import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from app.database import get_db, get_events_collection
from app.services.elastic import index_events_bulk
from app.services.geoip import lookup as geoip_lookup
from app.services.threat_feed import is_malicious
from app.services.rules import classify_event
from app.ws_manager import broadcast
from app.config import TRUSTED_PROXY_IPS

router = APIRouter(prefix="/ingest", tags=["ingest"])

# ---------------------------------------------------------------------------
# Sensitive-field redaction (defense in depth).
#
# The website tracker already refuses to send values for password-like
# fields, but this denylist is the real safety net: it runs on EVERY website
# event before anything is persisted to Mongo/Elasticsearch, so even a
# modified/maliciously crafted tracker payload can never store these values.
# Passwords, API tokens, card numbers etc. stay out of the SOC platform
# entirely — there is no legitimate case for persisting them.
# ---------------------------------------------------------------------------
_SENSITIVE_FIELD_RE = re.compile(
    r"(password|passwd|pass|pwd|token|secret|card|cvv|ssn|otp|api[_-]?key|authorization)",
    re.IGNORECASE,
)

REDACTED = "[REDACTED]"


def redact_sensitive_fields(value):
    """Recursively replace values of sensitive keys with [REDACTED]."""
    if isinstance(value, dict):
        redacted = {}
        name_hint = ""
        is_sensitive = False
        for k, v in value.items():
            key = str(k)
            if key.lower() in ("name", "field") and not name_hint:
                name_hint = str(v or "")
            if key.lower() == "sensitive":
                is_sensitive = bool(v)
        for k, v in value.items():
            key = str(k)
            redact_value = bool(_SENSITIVE_FIELD_RE.search(key)) or (
                is_sensitive and key.lower() == "value"
            ) or (
                bool(_SENSITIVE_FIELD_RE.search(name_hint)) and key.lower() == "value"
            )
            redacted[k] = REDACTED if redact_value else redact_sensitive_fields(v)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive_fields(item) for item in value]
    return value


def _cap(value, n: int = 2000) -> str:
    return str(value or "")[:n]


def _website_summary(event_type: str, raw: dict, user: dict | None, page: dict | None) -> str:
    """Readable one-liner for the Events list — generic event, rich properties."""
    who = ""
    if user:
        who = f" by {user.get('email') or user.get('name') or user.get('id') or ''}"
    raw = raw or {}
    t = str(event_type or "generic").lower()
    if t == "page_view":
        return f"Page view{who}: {_cap((page or {}).get('path') or raw.get('url') or 'unknown', 200)}"
    if t == "click":
        target = raw.get("text") or raw.get("id") or raw.get("href") or raw.get("tag") or "element"
        return f"Click{who}: {_cap(target, 120)}"
    if t == "input":
        return f"Input{who}: {_cap(raw.get('field', '?'), 60)} ({raw.get('length', 0)} chars)"
    if t == "form_submit":
        form_raw = raw.get("form")
        if isinstance(form_raw, dict):
            form = form_raw.get("id") or form_raw.get("name") or form_raw.get("action") or "form"
        elif isinstance(form_raw, str) and form_raw:
            form = form_raw
        else:
            form = "form"
        fields = raw.get("fields")
        try:
            if isinstance(fields, str):
                fields = json.loads(fields)
        except Exception:
            fields = fields or []
        n = len(fields) if isinstance(fields, (list, dict)) else 0
        return f"Form submitted{who}: {_cap(form, 120)} ({n} fields)"
    if t == "fetch":
        return f"{raw.get('method', 'GET')} {_cap(raw.get('url', ''), 200)} → {raw.get('status', '?')}{who}"
    if t == "api_error":
        return f"API error{who}: {_cap(raw.get('method', 'GET'), 10)} {_cap(raw.get('url', ''), 150)} ({_cap(raw.get('error', ''), 100)})"
    if t == "js_error":
        return f"JS error{who}: {_cap(raw.get('message', ''), 150)}"
    if t == "identify":
        u = user or {}
        return f"User identified: {u.get('email') or u.get('name') or u.get('id') or '?'}"
    if t == "user_logout":
        return f"User logged out{(' (' + who.strip(' by ') + ')') if who else ''}"
    return f"Website event{who}: {_cap(event_type or 'generic', 80)}"


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _resolve_project_from_request(request: Request, body_data: dict, db) -> tuple[int, str]:
    api_key = (
        request.headers.get("X-API-Key")
        or request.query_params.get("api_key")
        or (body_data.get("api_key") if isinstance(body_data, dict) else None)
    )
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key in header, query, or body")
    key_hash = _hash_key(api_key)
    key = db.api_keys.find_one({"key_hash": key_hash, "revoked": False})
    if not key:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    db.api_keys.update_one({"id": key["id"]}, {"$set": {"last_used_at": datetime.now(timezone.utc)}})
    return key["project_id"], api_key


def _is_trusted_proxy(ip: str) -> bool:
    """True if the direct peer is a reverse proxy we allow to set forwarded
    headers. Direct clients (browsers, agents) are never trusted, so a forged
    X-Forwarded-For from them is ignored and cannot spoof the recorded IP."""
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    for entry in TRUSTED_PROXY_IPS:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if addr in ip_network(entry, strict=False):
                    return True
            elif ip_address(entry) == addr:
                return True
        except ValueError:
            continue
    return False


def _real_client_ip(request: Request) -> str:
    """Real source IP, in priority order:

    1. X-Forwarded-For first entry — but ONLY when the direct peer is a
       known/trusted proxy (see TRUSTED_PROXY_IPS). The first entry is the
       original client when the request has passed through a reverse proxy.
    2. X-Real-IP (set by our nginx) — same trust requirement.
    3. request.client.host — the direct connection peer; the only correct
       answer when there is no proxy in front.

    Forwards from untrusted peers are ignored entirely (IP spoofing guard).
    """
    peer = request.client.host if request.client else ""
    if peer and _is_trusted_proxy(peer):
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
        x_real = request.headers.get("X-Real-IP", "").strip()
        if x_real:
            return x_real
    return peer


def _enrich(event: dict, request: Request) -> dict:
    enriched = event.get("enriched", {})
    ip = _real_client_ip(request)
    if ip:
        enriched["ip"] = ip
        geo = geoip_lookup(ip)
        if geo:
            enriched["geo"] = geo
        if is_malicious(ip, project_id=event.get("project_id")):
            enriched["threat_match"] = True
    if "user_agent_parsed" not in enriched and "user_agent" in event.get("raw", {}):
        enriched["user_agent_parsed"] = str(event["raw"]["user_agent"])

    # Form interaction context (already redacted in raw) — surfaced the same
    # way user_agent is, so the Events view can show it without touching raw.
    raw = event.get("raw") or {}
    form_raw = raw.get("form")
    fields = raw.get("fields")
    if isinstance(fields, str):
        try:
            parsed_fields = json.loads(fields)
        except Exception:
            parsed_fields = []
    else:
        parsed_fields = fields or []
    if isinstance(parsed_fields, dict):
        parsed_fields = [
            {"name": k, "filled": bool(v), "length": (len(v) if isinstance(v, str) else None)}
            for k, v in parsed_fields.items()
        ]

    if isinstance(form_raw, dict) or isinstance(parsed_fields, list) and parsed_fields or raw.get("timing_ms") is not None:
        form_label = ""
        if isinstance(form_raw, dict):
            for key in ("id", "name"):
                if form_raw.get(key):
                    form_label = str(form_raw[key])
                    break
            if not form_label and form_raw.get("action"):
                form_label = str(form_raw["action"])[:120]
        elif isinstance(form_raw, str):
            form_label = _cap(form_raw, 200)
        enriched["form"] = {
            "name": _cap(form_label, 200),
            "action": _cap(form_raw.get("action"), 300) if isinstance(form_raw, dict) else "",
            "timing_ms": int(raw["timing_ms"]) if isinstance(raw.get("timing_ms"), (int, float)) and raw["timing_ms"] >= 0 else None,
            "validation_errors": [
                _cap(er.get("message") if isinstance(er, dict) else er, 200)
                for er in (raw.get("validation_errors") or [])[:10]
            ],
            "fields": [
                {
                    "name": _cap(f.get("name"), 100),
                    "type": _cap(f.get("type"), 30),
                    "filled": bool(f.get("filled")),
                    "length": f.get("length"),
                }
                for f in (parsed_fields or [])
                if isinstance(f, dict) and f.get("name")
            ][:50],
        }

    enriched["risk_score"] = max(enriched.get("risk_score", 0), 80) if enriched.get("threat_match") else enriched.get("risk_score", 0)

    detections = classify_event(raw)
    if detections:
        labels, seen = [], set()
        for m in detections:
            label = m["category"].replace("_", " ").upper()
            if label not in seen:
                seen.add(label)
                labels.append(label)
        enriched["detected_attacks"] = ", ".join(labels)
        enriched["detections"] = detections
        enriched["risk_score"] = max(enriched.get("risk_score", 0), detections[0]["score"])

    score = float(enriched.get("risk_score") or 0)
    if score >= 80:
        enriched["severity"] = "critical"
    elif score >= 60:
        enriched["severity"] = "high"
    elif score >= 30:
        enriched["severity"] = "medium"
    elif score > 0 or detections:
        enriched["severity"] = "low"
    else:
        enriched["severity"] = "info"

    event["enriched"] = enriched
    # All stored timestamps are offset-form ISO (+00:00), matching the agent
    # pipeline (_normalize_ts) — cleanup cutoffs compare these strings
    # lexicographically, and a Z suffix sorts AFTER +00:00 at equal instants.
    ts = event.get("timestamp")
    if not ts:
        event["timestamp"] = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    else:
        ts = str(ts)
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        elif "+" not in ts:
            ts = ts + "+00:00"
        event["timestamp"] = ts
    return event


MAX_INGEST_BATCH = 200


@router.post("/event", summary="Ingest website events (snippet → POST /ingest/event)")
@router.post("/{project_id}/event", summary="Ingest website events for a specific project")
async def ingest_event(
    request: Request,
    project_id: int | None = None,
    db=Depends(get_db),
):
    raw_bytes = await request.body()
    if not raw_bytes:
        body = {}
    else:
        try:
            body = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Payload must be a JSON object")

    resolved_id, _ = await run_in_threadpool(_resolve_project_from_request, request, body, db)
    if project_id is not None and resolved_id != project_id:
        raise HTTPException(status_code=403, detail="API key does not belong to specified project")

    target_project_id = resolved_id
    if "events" in body:
        if not isinstance(body["events"], list):
            raise HTTPException(status_code=400, detail="'events' must be an array")
        if len(body["events"]) > MAX_INGEST_BATCH:
            raise HTTPException(status_code=400, detail=f"Batch too large (max {MAX_INGEST_BATCH} events)")
        events_list = body["events"]
    else:
        events_list = [body]

    ingested = []
    es_docs = []
    mongo_docs = []
    for evt in events_list:
        if not isinstance(evt, dict):
            continue
        user = evt.get("user") if isinstance(evt.get("user"), dict) else None
        session = evt.get("session") if isinstance(evt.get("session"), dict) else None
        page = evt.get("page") if isinstance(evt.get("page"), dict) else None

        parsed: dict = {}
        if user:
            parsed["user"] = {k: _cap(v, 200) for k, v in user.items() if k in ("id", "email", "name", "role") and v is not None}
        if session:
            parsed["session"] = {k: _cap(v, 100) for k, v in session.items() if k in ("session_id", "visit_id")}
            if isinstance(session.get("seq"), int):
                parsed["session"]["seq"] = min(session["seq"], 10 ** 9)
        if page:
            parsed["page"] = {k: _cap(v, 2000) for k, v in page.items()}
        if isinstance(evt.get("parsed"), dict):
            parsed.update({k: (_cap(v, 500) if isinstance(v, str) else v) for k, v in evt["parsed"].items()})
        parsed = redact_sensitive_fields(parsed)

        raw_data = redact_sensitive_fields(evt.get("raw", evt) if isinstance(evt.get("raw"), dict) else evt)
        raw_tags = evt.get("tags", [])
        safe_tags = [str(t)[:64] for t in raw_tags[:20]] if isinstance(raw_tags, list) else []

        event = {
            "project_id": str(target_project_id),
            # /ingest/event IS the website integration path — anything without
            # an explicit source is a website event (never "unknown", which no
            # feed filter understands).
            "source": evt.get("source", "website"),
            "event_type": _cap(evt.get("event_type", "generic"), 80),
            "raw": raw_data,
            "tags": safe_tags,
            "summary": _website_summary(evt.get("event_type", "generic"), raw_data, parsed.get("user"), page),
            "parsed": parsed,
        }
        event = _enrich(event, request)
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        event["id"] = event_id
        es_docs.append(event)

        # Save copy in Mongo for reliable fallback
        mongo_docs.append({
            "id": event_id,
            "project_id": target_project_id,
            "source": event["source"],
            "event_type": event["event_type"],
            "summary": event["summary"],
            "raw": event["raw"],
            "parsed": event["parsed"],
            "enriched": event["enriched"],
            "tags": event["tags"],
            "timestamp": event["timestamp"],
        })
        ingested.append(event)

    # Batched writes off the event loop — one bulk round trip per store
    if es_docs:
        await run_in_threadpool(index_events_bulk, es_docs)
    if mongo_docs:
        await run_in_threadpool(get_events_collection("website").insert_many, mongo_docs)

    for evt_data in ingested:
        _id = evt_data.get("id")
        evt_copy = {k: v for k, v in evt_data.items() if k != "_id"}
        try:
            await broadcast(target_project_id, evt_copy)
        except Exception:
            pass

    return {"status": "ok", "count": len(ingested)}

