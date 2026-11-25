import asyncio
import hashlib
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool
from app.database import (
    get_db, get_next_id, NO_ID, get_events_collection,
    agent_events_collections, RAW_AGENT_COND,
)
from app.models.agent_key import (
    AgentKeyCreate, AgentKeyCreated,
    EnrollRequest, EnrollResponse, AgentLogEntry, AgentLogBulk,
    generate_raw_key, hash_raw_key,
)
from app.auth import get_current_user, get_current_agent, create_agent_token
from app.dependencies import get_owned_project
from app.models.cleanup import CleanupFilters, CleanupExecute
from app.routers.ingest import _real_client_ip
from app.services.elastic import index_agent_log, index_event, index_events_bulk, index_agent_logs_bulk, delete_agent_logs_by_query
from app.services.geoip import lookup as geoip_lookup
from app.services.log_parser import parse_log
from app.services.threat_feed import is_malicious
from app.services.event_filter import is_relevant_entry
from app.services.severity import classify_severity
from app.services.risk_engine import compute_risk_score
from app.services.mitre import get_mitre
from app.services.audit import record_cleanup
from app.ws_manager import broadcast

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agents", tags=["agents"])
cleanup_router = APIRouter(tags=["agent-logs"])

_usp_js_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "usp.js")


def _parse_and_enrich(message: str, meta: dict | None, project_id: int | None = None) -> tuple[str, dict, dict]:
    """Normalize a raw log line → (summary, parsed, enriched).

    enriched carries real source-IP intelligence: geo lookup + known-bad match.
    """
    meta = meta or {}
    result = parse_log(message, meta)
    summary = result["summary"]
    parsed = result["parsed"]

    enriched = {}
    ip = parsed.get("ip") or ""
    if ip:
        enriched["ip"] = ip
        geo = geoip_lookup(ip)
        if geo:
            enriched["geo"] = geo
        if is_malicious(ip, project_id=project_id):
            enriched["threat_match"] = True
    return summary, parsed, enriched


def _agent_events_source(os_type) -> str:
    """Map an agent's os_type to the per-source collection name."""
    _os = str(os_type or "").lower()
    return "windows" if ("windows" in _os or "win32" in _os or _os.startswith("win")) else "linux"


def _normalize_ts(value) -> str:
    """Normalize any entry timestamp to offset-form ISO (schema default).

    ``+00:00`` (isoformat) is used instead of ``Z`` so the ``$lt`` string
    comparisons in the cleanup cutoffs behave identically for every document.
    """
    ts = str(value or "")
    if not ts:
        ts = datetime.now(timezone.utc).isoformat()
    elif ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    elif "+" not in ts:
        ts = ts + "+00:00"
    return ts


def _build_agent_doc(agent, source, category, event_type, summary, parsed,
                     enriched, raw_message, meta, trace_id, ts, level="info",
                     stage="") -> dict:
    """One unified document per agent entry — the ONLY shape stored in
    events_windows / events_linux (lifecycle, heartbeat AND security events)."""
    return {
        "id": f"agent_{uuid.uuid4().hex[:12]}",
        "project_id": agent.get("project_id"),
        "agent_id": agent["id"],
        "hostname": agent.get("hostname") or "",
        "source": source,
        "category": category,
        "event_type": event_type,
        "summary": summary,
        "parsed": parsed,
        "raw": {
            **meta,
            "level": level,
            "stage": stage,
            "message": raw_message,
            "agent_id": agent["id"],
            "hostname": agent.get("hostname") or "",
        },
        "enriched": enriched,
        "timestamp": ts,
    }


def _entry_category(stage: str, is_security: bool) -> str:
    """Classify an agent entry: heartbeat / lifecycle / security_event.

    ``stage`` values like enroll_done, config_saved and install_complete are
    lifecycle noise; heartbeats are their own bucket; anything promoted to the
    Events surface is a security_event.
    """
    if stage == "heartbeat":
        return "heartbeat"
    if is_security:
        return "security_event"
    return "lifecycle"


@router.get("/usp.js", summary="Website snippet script (embedded via script tag)")
def serve_usp_js():
    if not os.path.exists(_usp_js_path):
        raise HTTPException(status_code=404, detail="usp.js not found")
    with open(_usp_js_path, "r", encoding="utf-8") as f:
        content = f.read()
    return Response(content=content, media_type="application/javascript")


@router.delete("/keys", summary="Delete all of the user's agent keys")
def delete_all_agent_keys(user=Depends(get_current_user), db=Depends(get_db)):
    result = db.agent_keys.delete_many({"created_by": user["id"]})
    return {"message": f"Deleted {result.deleted_count} agent keys"}


@router.delete("/keys/{key_id}", summary="Revoke an agent key")
def revoke_agent_key(key_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    key = db.agent_keys.find_one({"id": key_id}, NO_ID)
    if not key or key["created_by"] != user["id"]:
        raise HTTPException(status_code=404, detail="Key not found")
    db.agent_keys.update_one({"id": key_id}, {"$set": {"status": "revoked", "revoked_at": datetime.now(timezone.utc)}})
    return {"message": "Key revoked"}


@router.post("/keys", summary="Create an agent key (one-time reveal)")
def create_agent_key(body: AgentKeyCreate, user=Depends(get_current_user), db=Depends(get_db)):
    project = db.projects.find_one({"id": body.project_id, "owner_id": user["id"]}, {"id": 1})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    raw = generate_raw_key()
    prefix = raw[:12]
    hashed = hash_raw_key(raw)
    key = {
        "id": get_next_id("agent_keys"),
        "label": body.label.strip(),
        "key_prefix": prefix,
        "key_hash": hashed,
        "status": "pending",
        "system_fingerprint": None,
        "hostname": None,
        "os_type": None,
        "ip_address": None,
        "created_by": user["id"],
        "project_id": body.project_id,
        "created_at": datetime.now(timezone.utc),
        "enrolled_at": None,
        "last_seen_at": None,
        "revoked_at": None,
    }
    db.agent_keys.insert_one(key)
    return AgentKeyCreated(id=key["id"], label=key["label"], api_key=raw, status=key["status"])


@router.get("/keys", summary="List the user's agent keys")
def list_agent_keys(project_id: int | None = Query(None), user=Depends(get_current_user), db=Depends(get_db)):
    q: dict = {"created_by": user["id"]}
    if project_id is not None:
        q["project_id"] = project_id
    keys = list(db.agent_keys.find(q, {"_id": 0, "key_hash": 0}).sort("created_at", -1))
    return keys


@router.get("/status", summary="Agent enrollment/liveness status across the user's projects")
def agent_status(user=Depends(get_current_user), db=Depends(get_db)):
    project_ids = [p["id"] for p in db.projects.find({"owner_id": user["id"]}, {"id": 1})]
    if not project_ids:
        return {"agents": []}
    keys = list(db.agent_keys.find(
        {"project_id": {"$in": project_ids}},
        {"_id": 0, "key_hash": 0},
    ))
    agents = []
    for k in keys:
        last = k.get("last_seen_at")
        agents.append({
            "id": k.get("id"),
            "label": k.get("label"),
            "hostname": k.get("hostname"),
            "os_type": k.get("os_type"),
            "ip_address": k.get("ip_address"),
            "status": k.get("status"),
            "project_id": k.get("project_id"),
            "last_seen_at": last.isoformat() if isinstance(last, datetime) else last,
            "enrolled_at": k.get("enrolled_at").isoformat() if isinstance(k.get("enrolled_at"), datetime) else k.get("enrolled_at"),
            "created_at": k.get("created_at").isoformat() if isinstance(k.get("created_at"), datetime) else k.get("created_at"),
        })
    return {"agents": agents}


def _clean_ip(value: str | None, request: Request) -> str | None:
    """Reject junk IPs ("0", "unknown", ...) and fall back to the caller IP."""
    val = str(value or "").strip()
    if val in ("0", "unknown", "0.0.0.0", ""):
        return _real_client_ip(request) or None
    return val


def _junk_ip(value) -> bool:
    return str(value or "").strip() in ("0", "", "unknown", "0.0.0.0")


def _refresh_agent_ip(db, agent_id: int, request: Request) -> str | None:
    """If the stored agent IP is junk, return the caller IP as seen by the
    server (every log/beat request originates from the agent itself)."""
    caller = _real_client_ip(request)
    if not caller:
        return None
    key = db.agent_keys.find_one({"id": agent_id}, {"ip_address": 1})
    if key and _junk_ip(key.get("ip_address")):
        return caller
    return None


@router.post("/enroll", summary="Enroll an agent with its one-time key (called by install scripts)")
def enroll(body: EnrollRequest, request: Request, db=Depends(get_db)):
    hashed = hash_raw_key(body.api_key)
    key = db.agent_keys.find_one({"key_hash": hashed})
    if not key:
        raise HTTPException(status_code=404, detail="Invalid API key")
    if key["status"] == "revoked":
        raise HTTPException(status_code=403, detail="API key is revoked")
    fingerprint = hashlib.sha256(
        f"{body.hostname}|{body.os_type}|{body.fingerprint_seed}".encode()
    ).hexdigest()
    ip_value = _clean_ip(body.ip_address, request)
    now = datetime.now(timezone.utc)
    if key["status"] == "pending":
        update = {
            "status": "active",
            "system_fingerprint": fingerprint,
            "hostname": body.hostname,
            "os_type": body.os_type,
            "ip_address": ip_value,
            "enrolled_at": now,
            "last_seen_at": now,
        }
        db.agent_keys.update_one({"id": key["id"]}, {"$set": update})
    elif key["status"] == "active":
        # Re-enroll requires an exact fingerprint match. Hostname alone is
        # attacker-controlled input and must never rebind a key, and the
        # stored binding is never overwritten by a mismatched caller.
        # Legacy keys without a stored fingerprint adopt the caller's on
        # first re-enroll, then behave like all other bound keys.
        stored = key.get("system_fingerprint")
        if stored and stored != fingerprint:
            raise HTTPException(
                status_code=409,
                detail=f"This API key is already enrolled to a different system ({key.get('hostname')}). Generate a new key for this machine.",
            )
        update_active: dict = {
            "last_seen_at": now,
            "ip_address": ip_value,
        }
        if not stored:
            update_active["system_fingerprint"] = fingerprint
            update_active["hostname"] = body.hostname
            update_active["os_type"] = body.os_type
        db.agent_keys.update_one({"id": key["id"]}, {"$set": update_active})
    token = create_agent_token(key["id"])
    return EnrollResponse(agent_token=token, agent_id=key["id"], log_endpoint="/agents/logs")


@router.get("/logs", summary="List raw agent logs for the user's agents")
def list_agent_logs(
    limit: int = Query(50),
    offset: int = Query(0),
    hostname: str | None = Query(None),
    category: str | None = Query(None),
    project_id: int | None = Query(None),
    query: str | None = Query(None),
    user=Depends(get_current_user),
    db=Depends(get_db),
):
    """Agent Logs view: every entry for the user's agents across
    events_windows + events_linux, newest first.

    All categories are returned (heartbeat, lifecycle and security_event) —
    this is the raw stream Live Events deliberately hides. Server-side
    filters: exact hostname, category, project_id, and a case-insensitive
    substring match over summary + raw message.
    """
    agent_ids = [a["id"] for a in db.agent_keys.find({"created_by": user["id"]}, {"id": 1})]
    if not agent_ids:
        return {"logs": [], "total": 0}
    q: dict = {"agent_id": {"$in": agent_ids}}
    if hostname:
        q["hostname"] = hostname
    if category:
        q["category"] = category
    if project_id is not None:
        q["project_id"] = {"$in": [project_id, str(project_id)]}
    if query:
        rx = {"$regex": re.escape(query), "$options": "i"}
        q["$or"] = [{"summary": rx}, {"raw.message": rx}]
    docs = []
    total = 0
    for col in agent_events_collections():
        total += col.count_documents(q)
        # Fetch through the requested page per collection, then slice once in
        # Python — skipping in both places drops rows across collections.
        docs.extend(
            col.find(q, NO_ID)
            .sort([("timestamp", -1), ("_id", -1)])
            .limit(offset + limit)
        )
    docs.sort(
        key=lambda d: (str(d.get("timestamp", "")), str(d.get("id", ""))),
        reverse=True,
    )
    result = []
    for log in docs[offset: offset + limit]:
        parsed = log.get("parsed") or {}
        raw = log.get("raw") or {}
        level = raw.get("level") or parsed.get("level") or parsed.get("severity") or "info"
        result.append({
            "id": log["id"],
            "agent_id": log["agent_id"],
            "source": log.get("source", ""),
            "category": log.get("category", ""),
            "level": level,
            "stage": raw.get("stage", ""),
            "message": raw.get("message", ""),
            "hostname": log.get("hostname", ""),
            "project_id": log.get("project_id"),
            "meta": raw,
            "summary": log.get("summary", ""),
            "parsed": parsed,
            "enriched": log.get("enriched", {}),
            "timestamp": log["timestamp"].isoformat() if hasattr(log["timestamp"], 'isoformat') else log["timestamp"],
        })
    return {"logs": result, "total": total}


@router.post("/logs", summary="Single agent log entry (heartbeat, lifecycle or security event)", include_in_schema=True)
async def agent_log(body: AgentLogEntry, request: Request, agent=Depends(get_current_agent), db=Depends(get_db)):
    trace_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    proj_id = agent.get("project_id")
    source = _agent_events_source(agent.get("os_type"))
    events_col = get_events_collection(source)

    summary, parsed, enriched = await run_in_threadpool(
        _parse_and_enrich, body.message, dict(body.meta) if body.meta else None, proj_id
    )

    is_security = body.stage != "heartbeat" and is_relevant_entry(body.meta, parsed)
    category = _entry_category(body.stage, is_security)
    event_type = classify_severity(
        (body.meta or {}).get("log_name", "") or parsed.get("log_name", ""),
        (body.meta or {}).get("event_id", "") or parsed.get("event_id", ""),
        parsed.get("action"),
        parsed,
    )
    meta = {**body.meta, "trace_id": trace_id} if body.meta else {"trace_id": trace_id}
    doc = _build_agent_doc(
        agent, source, category, event_type, summary, parsed, enriched,
        body.message, meta, trace_id, now.isoformat(timespec="microseconds"), level=body.level,
        stage=body.stage,
    )
    doc["mitre"] = get_mitre(
        (body.meta or {}).get("log_name", "") or parsed.get("log_name", ""),
        (body.meta or {}).get("event_id", "") or parsed.get("event_id", ""),
        parsed.get("action"),
    )

    # Risk score is computed against the EXISTING documents (burst windows must
    # not count the entry being written right now), then stored on the doc.
    if is_security:
        doc["enriched"]["risk_score"] = await run_in_threadpool(compute_risk_score, doc, db)

    await run_in_threadpool(events_col.insert_one, doc)
    await run_in_threadpool(index_agent_log, doc)

    agent_update = {"last_seen_at": now}
    ip_refresh = _refresh_agent_ip(db, agent["id"], request)
    if ip_refresh:
        agent_update["ip_address"] = ip_refresh
    await run_in_threadpool(db.agent_keys.update_one, {"id": agent["id"]}, {"$set": agent_update})

    if is_security:
        es_doc = {**doc, "project_id": str(proj_id) if proj_id else ""}
        await run_in_threadpool(index_event, es_doc)
        if proj_id:
            try:
                await broadcast(proj_id, {k: v for k, v in es_doc.items() if k != "_id"})
            except Exception:
                pass

    return {"status": "logged", "trace_id": trace_id}


@router.post("/logs/bulk", summary="Batched agent log entries from a running agent")
async def agent_log_bulk(body: AgentLogBulk, request: Request, agent=Depends(get_current_agent), db=Depends(get_db)):
    now = datetime.now(timezone.utc)
    proj_id = agent.get("project_id")
    agent_id = agent["id"]
    source = _agent_events_source(agent.get("os_type"))
    events_col = get_events_collection(source)

    log_docs = []
    es_docs = []
    broadcast_events = []

    for entry in body.entries:
        trace_id = str(uuid.uuid4())
        ts = _normalize_ts(entry.event_time or now.isoformat())
        meta = {**entry.meta, "trace_id": trace_id} if entry.meta else {"trace_id": trace_id}

        summary, parsed, enriched = _parse_and_enrich(entry.message, dict(entry.meta) if entry.meta else None, proj_id)

        is_security = entry.stage != "heartbeat" and is_relevant_entry(entry.meta, parsed)
        category = _entry_category(entry.stage, is_security)
        event_type = classify_severity(
            (entry.meta or {}).get("log_name", "") or parsed.get("log_name", ""),
            (entry.meta or {}).get("event_id", "") or parsed.get("event_id", ""),
            parsed.get("action"),
            parsed,
        )

        doc = _build_agent_doc(
            agent, source, category, event_type, summary, parsed, enriched,
            entry.message, meta, trace_id, ts, level=entry.level, stage=entry.stage,
        )
        doc["mitre"] = get_mitre(
            (entry.meta or {}).get("log_name", "") or parsed.get("log_name", ""),
            (entry.meta or {}).get("event_id", "") or parsed.get("event_id", ""),
            parsed.get("action"),
        )
        if is_security:
            doc["enriched"]["risk_score"] = await run_in_threadpool(compute_risk_score, doc, db)

        log_docs.append(doc)
        if is_security:
            es_docs.append({**doc, "project_id": str(proj_id) if proj_id else ""})
            broadcast_events.append(doc)

    # All blocking store writes run in the threadpool — the event loop stays free
    if log_docs:
        await run_in_threadpool(events_col.insert_many, log_docs)
    if log_docs:
        await run_in_threadpool(index_agent_logs_bulk, log_docs)
    if es_docs:
        await run_in_threadpool(index_events_bulk, es_docs)
    agent_update = {"last_seen_at": now}
    ip_refresh = _refresh_agent_ip(db, agent_id, request)
    if ip_refresh:
        agent_update["ip_address"] = ip_refresh
    await run_in_threadpool(db.agent_keys.update_one, {"id": agent_id}, {"$set": agent_update})

    if broadcast_events and proj_id:
        await asyncio.gather(
            *[broadcast(proj_id, {k: v for k, v in evt.items() if k != "_id"}) for evt in broadcast_events],
            return_exceptions=True,
        )

    return {"status": "logged", "count": len(body.entries)}


# ---------------------------------------------------------------------------
# Raw agent-log cleanup (same preview/delete contract as the events cleanup).
# Raw agent entries now live IN events_windows / events_linux (category
# heartbeat|lifecycle), so this scope targets category != "security_event"
# across both agent collections — the security-event docs are handled by the
# events cleanup scope instead. Same expected_count guard + audit trail.
# ---------------------------------------------------------------------------

def _agent_log_cutoff(before: str) -> datetime:
    if not before:
        raise HTTPException(status_code=400, detail="The 'before' cutoff timestamp is required")
    try:
        dt = datetime.fromisoformat(str(before).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid 'before' timestamp; use ISO 8601 format")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _agent_log_cleanup_query(project_id: int, hostname: str | None, before_dt: datetime) -> dict:
    q = {
        "project_id": {"$in": [project_id, str(project_id)]},
        "category": RAW_AGENT_COND["category"],
        "timestamp": {"$lt": before_dt.isoformat()},
    }
    if hostname:
        q["hostname"] = hostname
    return q


def _agent_log_docs(db, q, size: int, offset: int = 0):
    """Newest-first sample + total count across both agent collections."""
    docs = []
    total = 0
    for col in agent_events_collections():
        total += col.count_documents(q)
        docs.extend(
            col.find(q, NO_ID)
            .sort([("timestamp", -1), ("_id", -1)])
            .limit(offset + size)
        )
    docs.sort(key=lambda d: (str(d.get("timestamp", "")), str(d.get("id", ""))), reverse=True)
    return docs[offset: offset + size], total


def _oldest_newest_agent_logs(db, q: dict):
    oldest = None
    newest = None
    for col in agent_events_collections():
        first = col.find_one(q, {"timestamp": 1}, sort=[("timestamp", 1), ("_id", 1)])
        last = col.find_one(q, {"timestamp": 1}, sort=[("timestamp", -1), ("_id", -1)])
        if first and (oldest is None or str(first.get("timestamp", "")) < oldest):
            oldest = str(first.get("timestamp", ""))
        if last and (newest is None or str(last.get("timestamp", "")) > newest):
            newest = str(last.get("timestamp", ""))
    return oldest, newest


def _agent_log_row(d) -> dict:
    ts = d["timestamp"]
    parsed = d.get("parsed") or {}
    raw = d.get("raw") or {}
    return {
        "id": d.get("id"),
        "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
        "hostname": d.get("hostname", ""),
        "category": d.get("category", ""),
        "level": raw.get("level") or parsed.get("level") or parsed.get("severity") or "info",
        "stage": raw.get("stage", ""),
        "message": raw.get("message", ""),
        "summary": d.get("summary", ""),
    }


@cleanup_router.post("/projects/{project_id}/agent-logs/cleanup/preview",
                     summary="Preview which raw agent logs a cleanup would delete (read-only)")
def agent_logs_cleanup_preview(project_id: int, body: CleanupFilters,
                               _project=Depends(get_owned_project), db=Depends(get_db)):
    """Newest-first sample + count of matching raw agent logs. Deletes nothing."""
    before_dt = _agent_log_cutoff(body.before)
    q = _agent_log_cleanup_query(project_id, body.hostname, before_dt)

    docs, total = _agent_log_docs(db, q, size=20)
    oldest, newest = _oldest_newest_agent_logs(db, q)

    return {
        "count": total,
        "sample": [_agent_log_row(d) for d in docs],
        "oldest_match": oldest,
        "newest_match": newest,
    }


@cleanup_router.delete("/projects/{project_id}/agent-logs/cleanup",
                       summary="Delete raw agent logs matching the previewed filters (audit-logged)")
def agent_logs_cleanup(project_id: int, body: CleanupExecute,
                       user=Depends(get_current_user),
                       _project=Depends(get_owned_project), db=Depends(get_db)):
    """Delete raw agent logs; re-validates expected_count (409 on drift),
    syncs Elasticsearch, and appends an immutable audit entry.

    ``es_synced`` is false when ES was unreachable (Mongo is the source of
    truth, so the delete itself still holds)."""
    before_dt = _agent_log_cutoff(body.before)
    q = _agent_log_cleanup_query(project_id, body.hostname, before_dt)

    total = 0
    for col in agent_events_collections():
        total += col.count_documents(q)
    if total != body.expected_count:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Data changed since the preview was run: {total} raw log(s) now match, "
                f"not {body.expected_count}. Please preview again before deleting."
            ),
        )

    deleted = 0
    for col in agent_events_collections():
        deleted += col.delete_many(q).deleted_count
    before_iso = before_dt.isoformat()
    es_deleted = delete_agent_logs_by_query(project_id, before_iso, body.hostname)

    record_cleanup(db, user=user, project_id=project_id,
                   source="agent_logs", hostname=body.hostname, before=before_iso,
                   deleted_count=deleted, scope="agent_logs")
    return {"deleted_count": deleted, "es_synced": es_deleted >= 0}

