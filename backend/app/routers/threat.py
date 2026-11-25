"""Threat intelligence endpoints.

Known-bad matches (``threat_match`` flag set at ingest), per-project
indicator management (feed-derived + manually added, persisted in Mongo) and
feed refresh control. All project-scoped routes go through
``get_owned_project`` so a tampered project_id cannot read another user's
data.

Analyst-facing surfaces (MITRE tactics, attack timeline, correlated
narratives, top risk hosts, browsable multi-feed indicator list, false
positive feedback) live alongside the legacy match/indicator views.
"""

import ipaddress
import json as jsonlib
import re
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.auth import get_current_user
from app.database import get_db, NO_ID, all_events_collections, agent_events_collections, EVENTS_VIEW_COND
from app.dependencies import get_owned_project
from app.services import threat_feed
from app.services.elastic import _es_up, es, ELASTICSEARCH_INDEX

router = APIRouter(dependencies=[Depends(get_current_user)])

MAX_MATCHES = 200


class FeedbackBody(BaseModel):
    is_false_positive: bool = True


class TriageBody(BaseModel):
    status: str | None = None
    severity: str | None = None
    assigned_to: str | None = None
    analyst_notes: str | None = None


class AllowlistBody(BaseModel):
    indicator: str
    type: str = "ip"
    reason: str = ""


# ---------------------------------------------------------------------------
# Event triage + cross-panel filtering helpers
# ---------------------------------------------------------------------------

_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_MIN_RISK = {"low": 0, "medium": 30, "high": 60, "critical": 80}
_TRIAGE_STATUSES = ("new", "acknowledged", "investigating", "resolved", "false_positive")
_ALLOWLIST_TYPES = ("ip", "domain", "hash")


def _severity_bucket(risk) -> str:
    """Bucket a numeric risk score to critical|high|medium|low."""
    try:
        r = float(risk or 0)
    except (TypeError, ValueError):
        r = 0
    if r >= 80:
        return "critical"
    if r >= 60:
        return "high"
    if r >= 30:
        return "medium"
    return "low"


def _effective_severity(e: dict) -> str:
    """Stored severity override wins; otherwise bucket the risk score."""
    tri = e.get("triage") or {}
    if tri.get("severity") in _SEV_RANK:
        return tri["severity"]
    return _severity_bucket((e.get("enriched") or {}).get("risk_score", 0))


def _triage_dict(e: dict) -> dict:
    tri = e.get("triage") or {}
    return {
        "status": tri.get("status", "new"),
        "severity": _effective_severity(e),
        "severity_override": tri.get("severity"),
        "assigned_to": tri.get("assigned_to"),
        "analyst_notes": tri.get("analyst_notes", ""),
        "updated_at": tri.get("updated_at"),
    }


def _passes_threat_filters(e: dict, host: str | None = None,
                           technique_id: str | None = None,
                           min_severity: str | None = None) -> bool:
    """Shared cross-panel filter: host, MITRE technique, minimum severity."""
    if host:
        eh = e.get("hostname") or (e.get("raw") or {}).get("hostname") or ""
        if eh != host:
            return False
    if technique_id:
        # Stored techniques look like "T1110 - Brute Force"; a filter of
        # "T1110" (or "T1070" for sub-techniques like T1070.001) matches by prefix.
        tech = ((e.get("mitre") or {}).get("technique") or "")
        if tech != technique_id and not tech.startswith(technique_id):
            return False
    if min_severity and min_severity in _SEV_RANK:
        if _SEV_RANK.get(_effective_severity(e), 0) < _SEV_RANK[min_severity]:
            return False
    return True


def _event_ip(e: dict) -> str:
    """Normalized source IP (same precedence the risk engine reads)."""
    for field in ("enriched", "parsed", "raw"):
        v = (e.get(field) or {}).get("ip") or ""
        if v and v != "unknown":
            return v
    return ""


def _event_user(e: dict) -> str:
    """Authenticated/target user when the parser extracted one."""
    u = ((e.get("parsed") or {}).get("user")) or ((e.get("raw") or {}).get("user")) or ""
    u = str(u).strip()
    if not u or u.lower() in ("unknown", "-", "n/a", "none", "null"):
        return ""
    return u


def _allowlisted_values(project_id: int, db) -> set[str]:
    """Indicators this project allowlisted as known-good infrastructure."""
    return {
        str(d.get("indicator"))
        for d in db.ioc_allowlist.find({"project_id": project_id}, {"indicator": 1})
    }


def _ts_iso(value) -> str:
    """Normalize a stored timestamp to an ISO string."""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _parse_ts(v):
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


def _window_start(window: str) -> datetime:
    """Start of the aggregation window for 24h / 7d / 30d."""
    now = datetime.now(timezone.utc)
    if window.endswith("d"):
        return now - timedelta(days=int(window[:-1]))
    return now - timedelta(hours=int(window[:-1]))


def _view_events_in_window(project_id: int, db, start: datetime, collections=None, projection=None):
    """Security-view events for a project since `start` (index-backed + exact ts filter)."""
    pid_q = {"$in": [project_id, str(project_id)]}
    start_hint = (start - timedelta(seconds=1)).isoformat()
    cols = collections or all_events_collections()
    out = []
    for col in cols:
        q = {
            "project_id": pid_q,
            "$and": [
                EVENTS_VIEW_COND,
                {"$or": [{"timestamp": {"$gte": start_hint}}, {"timestamp": {"$gte": start}}]},
            ],
        }
        for e in col.find(q, projection or NO_ID):
            ts = _parse_ts(e.get("timestamp"))
            if ts and ts >= start:
                out.append((e, ts))
    return out


def _suppressed_values(project_id: int, db) -> set[str]:
    """Indicator values this project has marked as false positives."""
    return {
        str(d.get("value"))
        for d in db.threat_suppressions.find({"project_id": project_id, "is_false_positive": True}, {"value": 1})
    }


def _value_hits_ip(value: str, ip: str) -> bool:
    """Exact IP match or CIDR containment (feed entries may be netblocks)."""
    if value == ip:
        return True
    try:
        if "/" in value:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False)
    except ValueError:
        pass
    return False


def _indicator_hits(project_id: int, values: list[str], db) -> dict:
    """Per-indicator event stats for this project: {value: {count, first, last}}.

    Matches against the IPs already normalized at ingest time (enriched.ip /
    parsed.ip / raw.ip) — the same fields the risk engine and event filter
    read, so no re-extraction from raw messages happens here.
    """
    if not values:
        return {}
    suppressed = _suppressed_values(project_id, db)
    pid_q = {"$in": [project_id, str(project_id)]}
    or_clause = [
        {"enriched.ip": {"$in": values}},
        {"parsed.ip": {"$in": values}},
        {"raw.ip": {"$in": values}},
    ]
    base = {"project_id": pid_q, "$and": [EVENTS_VIEW_COND, {"$or": or_clause}]}
    stats: dict = {}
    for col in all_events_collections():
        for e in col.find(base, NO_ID).sort("timestamp", -1).limit(5000):
            ts = e.get("timestamp")
            ts = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
            matched_here: set[str] = set()
            for field in ("enriched", "parsed", "raw"):
                v = ((e.get(field) or {}).get("ip")) or ""
                if v in values and v not in suppressed:
                    matched_here.add(v)
            for v in matched_here:
                entry = stats.setdefault(v, {"count": 0, "first": None, "last": None})
                entry["count"] += 1
                if entry["last"] is None or ts > entry["last"]:
                    entry["last"] = ts
                if entry["first"] is None or ts < entry["first"]:
                    entry["first"] = ts
    return stats


def _events_matching(project_id: int, db) -> list[dict]:
    """Events in this project that match the current indicator list.

    Returns raw event docs (view-filtered), newest first, capped per source.
    """
    feed_ips = sorted(threat_feed.get_feed_ips())
    manual = list(db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID))
    manual_ips = sorted(v for v, t in ((m.get("value"), m.get("type")) for m in manual) if t == "ip")
    manual_domains = sorted(v for v, t in ((m.get("value"), m.get("type")) for m in manual) if t == "domain")

    all_ips = feed_ips + manual_ips
    or_clause = []
    if all_ips:
        or_clause += [
            {"enriched.ip": {"$in": all_ips}},
            {"parsed.ip": {"$in": all_ips}},
            {"raw.ip": {"$in": all_ips}},
        ]
    for domain in manual_domains:
        rx = re.compile(re.escape(domain), re.IGNORECASE)
        or_clause += [
            {"raw.url": rx},
            {"raw.hostname": rx},
            {"summary": rx},
            {"raw.message": rx},
        ]
    if not or_clause:
        return []

    q = {
        "project_id": {"$in": [project_id, str(project_id)]},
        "$and": [EVENTS_VIEW_COND, {"$or": or_clause}],
    }
    docs: list[dict] = []
    for col in all_events_collections():
        docs.extend(col.find(q, NO_ID).sort("timestamp", -1).limit(MAX_MATCHES))
    docs.sort(key=lambda d: str(d.get("timestamp", "")), reverse=True)
    return docs[:MAX_MATCHES]


def _match_indicator(event: dict, manual: list[dict]) -> dict | None:
    """Pick which indicator explains a matched event (manual preferred)."""
    ip = ""
    for field in ("enriched", "parsed", "raw"):
        ip = (event.get(field) or {}).get("ip") or ""
        if ip:
            break
    if ip and threat_feed.is_malicious(ip, project_id=event.get("project_id")):
        for m in manual:
            if m.get("type") == "ip" and str(m.get("value")) == ip:
                return {"value": ip, "type": "ip", "category": m.get("category", "manual"), "source": "manual"}
        return {"value": ip, "type": "ip", "category": "feed", "source": "feed"}
    hay = " ".join(
        str(v) for v in (
            (event.get("raw") or {}).get("url", ""),
            (event.get("raw") or {}).get("hostname", ""),
            event.get("summary", ""),
            (event.get("raw") or {}).get("message", ""),
        ) if v
    ).lower()
    for m in manual:
        if m.get("type") != "domain":
            continue
        if str(m.get("value")) in hay:
            return {"value": m["value"], "type": "domain", "category": m.get("category", "manual"), "source": "manual"}
    return None


def _match_to_dict(e: dict, matched: dict) -> dict:
    ts = e.get("timestamp")
    return {
        "id": e.get("id"),
        "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
        "source": e.get("source", "unknown"),
        "event_type": e.get("event_type", "generic"),
        "summary": e.get("summary", ""),
        "ip": (e.get("enriched") or {}).get("ip", ""),
        "risk_score": (e.get("enriched") or {}).get("risk_score", 0),
        "matched": matched,
        "severity": _effective_severity(e),
        "triage": _triage_dict(e),
    }


@router.get("/projects/{project_id}/threat-intel/flagged")
def list_flagged_events(
    project_id: int,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Recent events that matched a known-malicious indicator (threat_match)."""
    query = {
        "project_id": {"$in": [project_id, str(project_id)]},
        "enriched.threat_match": True,
        "$and": [EVENTS_VIEW_COND],
    }
    suppressed = _suppressed_values(project_id, db)
    excluded = set(suppressed) | _allowlisted_values(project_id, db)
    if excluded:
        query["enriched.ip"] = {"$nin": list(excluded)}
    docs = []
    for col in all_events_collections():
        docs.extend(col.find(query, NO_ID).sort("timestamp", -1).limit(offset + limit))
    docs.sort(key=lambda d: str(d.get("timestamp", "")), reverse=True)
    docs = docs[offset: offset + limit]
    result = []
    for e in docs:
        enriched = e.get("enriched", {}) or {}
        ip = enriched.get("ip", "")
        result.append({
            "id": e.get("id"),
            "timestamp": e.get("timestamp"),
            "source": e.get("source", "unknown"),
            "event_type": e.get("event_type", "generic"),
            "summary": e.get("summary") or (e.get("raw", {}) or {}).get("message", ""),
            "ip": enriched.get("ip", ""),
            "country": (enriched.get("geo", {}) or {}).get("country", ""),
            "city": (enriched.get("geo", {}) or {}).get("city", ""),
            "risk_score": enriched.get("risk_score", 0),
            "raw": e.get("raw", {}),
            "severity": _effective_severity(e),
            "triage": _triage_dict(e),
        })
    return {
        "events": result,
        "total": sum(col.count_documents(query) for col in all_events_collections()),
    }


@router.get("/projects/{project_id}/threat/indicators")
def list_indicators(
    project_id: int,
    source: str = Query("all", pattern="^(all|feed|manual)$"),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Known threat indicators for a project.

    ``manual``: the project's persisted manual indicators (always returned,
    even with zero event hits). ``feed``: feed IPs that actually hit this
    project's events. ``all``: both, merged by value (manual wins).
    """
    manual_docs = list(
        db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID)
        .sort("added_at", -1)
    )
    manual_map = {str(d["value"]): d for d in manual_docs}

    if source == "manual":
        manual_only = manual_docs
        feed_only: list[dict] = []
    else:
        excluded = set(_suppressed_values(project_id, db)) | _allowlisted_values(project_id, db)
        feed_ips = [v for v in threat_feed.get_feed_ips() if v not in excluded]
        hits = _indicator_hits(project_id, sorted(feed_ips), db)
        feed_only = [
            {
                "id": f"feed:{ip}",
                "value": ip,
                "type": "ip",
                "category": "feed",
                "source": "feed",
                "first_seen": h["first"],
                "last_seen": h["last"],
                "hit_count": h["count"],
            }
            for ip, h in hits.items()
        ]

    result = []
    if source in ("all", "manual"):
        hits_manual = _indicator_hits(project_id, [str(d["value"]) for d in manual_docs], db)
        for d in manual_docs:
            h = hits_manual.get(str(d["value"]), {"count": 0, "first": None, "last": None})
            result.append({
                "id": d["id"],
                "value": d["value"],
                "type": d.get("type", "ip"),
                "category": d.get("category", "manual"),
                "source": "manual",
                "notes": d.get("notes", ""),
                "added_by": d.get("added_by"),
                "added_at": d.get("added_at"),
                "first_seen": h["first"],
                "last_seen": h["last"],
                "hit_count": h["count"],
            })
    if source in ("all", "feed"):
        seen = {r["value"] for r in result}
        for item in feed_only:
            if item["value"] not in seen:
                result.append(item)

    return {
        "indicators": result,
        "total": len(result),
        "feed": {
            "source": threat_feed.FEED_SOURCE_NAME,
            "last_sync": threat_feed.get_last_sync(),
            "count": threat_feed.get_feed_count(),
            "error": threat_feed.get_last_error(),
            "project_hits": len(feed_only),
        },
        "manual_total": len(manual_docs),
    }


@router.get("/projects/{project_id}/threat/correlation")
def ip_correlation(
    project_id: int,
    limit: int = Query(500, ge=1, le=1000),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """IP × event-type correlation matrix for this project.

    Groups events by (source IP, event_type), resolved through the same
    normalized fields the risk engine and event filter read (enriched.ip →
    parsed.ip → raw.ip), so no second IP-extraction convention is introduced.
    "unknown" rows are excluded outright — a single dominant unknown bucket
    can never drown out real address data.
    """
    ip_expr = {
        "$ifNull": [
            "$enriched.ip",
            {"$ifNull": ["$parsed.ip", {"$ifNull": ["$raw.ip", "unknown"]}]},
        ]
    }
    pipeline = [
        {
            "$match": {
                "project_id": {"$in": [project_id, str(project_id)]},
                "$and": [EVENTS_VIEW_COND],
            }
        },
        {
            "$project": {
                "_ip": ip_expr,
                "event_type": {"$ifNull": ["$event_type", "generic"]},
                "timestamp": 1,
                "enriched.risk_score": 1,
            }
        },
        {"$match": {"_ip": {"$nin": ["unknown", ""]}}},
        {
            "$group": {
                "_id": {"ip": "$_ip", "event_type": "$event_type"},
                "count": {"$sum": 1},
                "avg_risk": {"$avg": "$enriched.risk_score"},
                "last_seen": {"$max": "$timestamp"},
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]

    rows: list[dict] = []
    for col in all_events_collections():
        for doc in col.aggregate(pipeline):
            rows.append({
                "ip": doc["_id"]["ip"],
                "event_type": doc["_id"]["event_type"],
                "count": doc["count"],
                "avg_risk": round(float(doc.get("avg_risk") or 0), 1),
                "last_seen": _ts_iso(doc["last_seen"]) if doc.get("last_seen") else "",
            })
    rows.sort(key=lambda r: r["count"], reverse=True)
    return rows[:limit]


@router.get("/projects/{project_id}/threat/matches")
def list_matches(
    project_id: int,
    limit: int = Query(MAX_MATCHES, ge=1, le=MAX_MATCHES),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Actual events in this project matching the current indicator list.

    Events whose indicator was suppressed via the feedback endpoint are
    excluded (project-scoped; the global feed is untouched).
    """
    docs = _events_matching(project_id, db)[:limit]
    manual = list(db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID))
    excluded = set(_suppressed_values(project_id, db)) | _allowlisted_values(project_id, db)
    result = []
    for e in docs:
        matched = _match_indicator(e, manual)
        if matched and matched.get("value") not in excluded:
            result.append(_match_to_dict(e, matched))
    return {"events": result, "total": len(result)}


@router.post("/projects/{project_id}/threat/refresh")
def refresh_feed(
    project_id: int,
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Re-pull the threat feed now (feed is global; manual indicators survive)."""
    threat_feed.refresh()
    return {
        "source": ", ".join(threat_feed.get_feed_names()),
        "last_sync": threat_feed.get_last_sync(),
        "count": threat_feed.get_feed_count(),
        "error": threat_feed.get_last_error(),
    }


# ---------------------------------------------------------------------------
# Analyst surfaces (Parts A–G): tactics, timeline, narratives, top hosts,
# browsable indicators, false-positive feedback
# ---------------------------------------------------------------------------


@router.get("/projects/{project_id}/threat-intel/tactics")
def threat_tactics(
    project_id: int,
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    host: str | None = Query(None),
    technique_id: str | None = Query(None),
    min_severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """MITRE ATT&CK tactic counts for the window (replaces the severity donut).

    Aggregate by ``mitre.tactic`` across agent events — Credential Access vs
    Persistence vs Defense Evasion, with the concrete techniques behind each
    and a couple of example summaries. Events without a mapping are skipped.
    Accepts the shared cross-panel filters (host, technique_id, min_severity).
    """
    start = _window_start(window)
    tactic_agg: dict[str, dict] = {}
    for e, _ in _view_events_in_window(project_id, db, start, agent_events_collections()):
        if not _passes_threat_filters(e, host, technique_id, min_severity):
            continue
        m = e.get("mitre") or {}
        tactic = m.get("tactic")
        technique = m.get("technique")
        if not tactic:
            continue
        bucket = tactic_agg.setdefault(tactic, {"count": 0, "techniques": Counter(), "examples": []})
        bucket["count"] += 1
        if technique:
            bucket["techniques"][technique] += 1
        if len(bucket["examples"]) < 3:
            bucket["examples"].append(e.get("summary") or (e.get("raw") or {}).get("message", "")[:160])
    return {
        "window": window,
        "tactics": [
            {
                "tactic": tactic,
                "count": agg["count"],
                "techniques": [{"technique": t, "count": c} for t, c in agg["techniques"].most_common()],
                "examples": agg["examples"],
            }
            for tactic, agg in sorted(tactic_agg.items(), key=lambda kv: kv[1]["count"], reverse=True)
        ],
    }


@router.get("/projects/{project_id}/threat-intel/timeline")
def threat_timeline(
    project_id: int,
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    host: str | None = Query(None),
    technique_id: str | None = Query(None),
    min_severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Event volume + risk over time, hourly (24h) or daily (7d/30d).

    Prefers Elasticsearch's date_histogram (fast, already running) and falls
    back to a Mongo scan + Python bucketing when ES is down so the chart is
    never empty. Buckets are returned oldest-first. Accepts the shared
    cross-panel filters (host, technique_id, min_severity — the latter as a
    risk_score range in the ES path).
    """
    start = _window_start(window)
    hourly = window == "24h"
    interval = "hour" if hourly else "day"
    pid_str = str(project_id)

    if _es_up():
        try:
            must = [
                {"term": {"project_id": pid_str}},
                {"terms": {"source": ["windows", "linux"]}},
                {"range": {"timestamp": {"gte": start.isoformat()}}},
            ]
            if host:
                must.append({
                    "bool": {
                        "should": [
                            {"term": {"hostname": host}},
                            {"term": {"hostname.keyword": host}},
                            {"term": {"raw.hostname.keyword": host}},
                        ],
                        "minimum_should_match": 1,
                    }
                })
            if technique_id:
                must.append({"wildcard": {"mitre.technique": f"{technique_id}*"}})
            if min_severity and min_severity in _SEV_MIN_RISK:
                must.append({"range": {"enriched.risk_score": {"gte": _SEV_MIN_RISK[min_severity]}}})
            body = {
                "query": {"bool": {"must": must}},
                "size": 0,
                "aggs": {
                    "hist": {
                        "date_histogram": {"field": "timestamp", "calendar_interval": interval},
                        "aggs": {
                            "avg_risk": {"avg": {"field": "enriched.risk_score"}},
                            "max_risk": {"max": {"field": "enriched.risk_score"}},
                        },
                    }
                },
            }
            resp = es.search(index=ELASTICSEARCH_INDEX, body=body)
            buckets = [
                {
                    "bucket_start": b["key_as_string"],
                    "event_count": b["doc_count"],
                    "avg_risk_score": round(float(b.get("avg_risk", {}).get("value") or 0), 1),
                    "max_risk_score": round(float(b.get("max_risk", {}).get("value") or 0), 1),
                }
                for b in resp["aggregations"]["hist"]["buckets"]
            ]
            return {"window": window, "source": "elasticsearch", "buckets": buckets}
        except Exception:
            pass  # fall through to Mongo — never show an empty timeline

    fmt = "%Y-%m-%dT%H:00:00+00:00" if hourly else "%Y-%m-%dT00:00:00+00:00"
    buckets: dict[str, dict] = {}
    for e, ts in _view_events_in_window(project_id, db, start, agent_events_collections()):
        if not _passes_threat_filters(e, host, technique_id, min_severity):
            continue
        key = ts.strftime(fmt)
        bucket = buckets.setdefault(key, {"bucket_start": key, "event_count": 0, "risk_sum": 0.0, "avg_risk_score": 0, "max_risk_score": 0})
        risk = float((e.get("enriched") or {}).get("risk_score") or 0)
        bucket["event_count"] += 1
        bucket["risk_sum"] += risk
        bucket["max_risk_score"] = max(bucket["max_risk_score"], risk)
    for key, bucket in buckets.items():
        if bucket["event_count"]:
            bucket["avg_risk_score"] = round(bucket["risk_sum"] / bucket["event_count"], 1)
        else:
            bucket["avg_risk_score"] = 0
        bucket.pop("risk_sum", None)
    return {
        "window": window,
        "source": "mongo",
        "buckets": [buckets[k] for k in sorted(buckets.keys())],
    }


@router.get("/projects/{project_id}/threat-intel/narratives")
def threat_narratives(
    project_id: int,
    hours: int = Query(24, ge=1, le=168),
    host: str | None = Query(None),
    technique_id: str | None = Query(None),
    min_severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Rule-based correlated attack narratives (kill-chain view).

    Groups recent security events by hostname; where 3+ events from the same
    host fall within a sliding 2h window AND show escalation (2+ distinct
    MITRE tactics, or a high/critical severity, or risk >= 70), the run is
    returned as one ordered chain the UI can render as a story. Accepts the
    shared cross-panel filters (host, technique_id, min_severity).
    """
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    CHAIN_GAP = timedelta(hours=2)
    by_host: dict[str, list] = {}
    for e, ts in _view_events_in_window(project_id, db, start, agent_events_collections()):
        ev_host = e.get("hostname") or (e.get("raw") or {}).get("hostname") or ""
        if not ev_host:
            continue
        if not _passes_threat_filters(e, host, technique_id, min_severity):
            continue
        m = e.get("mitre") or {}
        by_host.setdefault(ev_host, []).append({
            "ts": ts,
            "tactic": m.get("tactic"),
            "technique": m.get("technique"),
            "summary": e.get("summary") or (e.get("raw") or {}).get("message", ""),
            "event_type": e.get("event_type", "info"),
            "risk_score": float((e.get("enriched") or {}).get("risk_score") or 0),
            "id": e.get("id"),
        })

    narratives = []
    for ev_host, steps in by_host.items():
        steps.sort(key=lambda s: s["ts"])
        run: list[dict] = []
        for step in steps:
            if run and step["ts"] - run[-1]["ts"] > CHAIN_GAP:
                if _is_chain(run):
                    narratives.append(_chain_to_dict(ev_host, run))
                run = []
            run.append(step)
        if _is_chain(run):
            narratives.append(_chain_to_dict(ev_host, run))

    narratives.sort(key=lambda n: n["start_time"], reverse=True)
    return {"hours": hours, "narratives": narratives}


def _is_chain(steps: list[dict]) -> bool:
    """3+ steps from one host with escalating or notable tactics."""
    if len(steps) < 3:
        return False
    tactics = {s["tactic"] for s in steps if s["tactic"]}
    if len(tactics) >= 2:
        return True
    if any(s["event_type"] in ("high", "critical") for s in steps):
        return True
    return any(s["risk_score"] >= 70 for s in steps)


def _chain_to_dict(host: str, run: list[dict]) -> dict:
    """Chain dict with a severity = highest stage reached in the run."""
    severities = []
    for s in run:
        sev = s.get("severity") or _severity_bucket(s.get("risk_score", 0))
        severities.append(sev)
        s["severity"] = sev
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    top = max(severities, key=lambda v: order.get(v, 0)) if severities else "medium"
    return {
        "hostname": host,
        "start_time": run[0]["ts"].isoformat(),
        "end_time": run[-1]["ts"].isoformat(),
        "event_count": len(run),
        "severity": top,
        "chain": [
            {
                "time": s["ts"].isoformat(),
                "tactic": s["tactic"],
                "technique": s["technique"],
                "summary": s["summary"],
                "event_type": s["event_type"],
                "event_id": s["id"],
                "severity": s.get("severity", "medium"),
                "risk_score": s.get("risk_score", 0),
            }
            for s in run
        ],
    }


@router.get("/projects/{project_id}/threat-intel/top-hosts")
def threat_top_hosts(
    project_id: int,
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    host: str | None = Query(None),
    technique_id: str | None = Query(None),
    min_severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Ranked per-host risk accumulation for the window (works today, no IP).

    SUM(risk_score) + COUNT + last-seen grouped by hostname across agent
    events — hostname is populated by every agent entry, so this is the
    page's primary "where do I look first" triage list even before IP
    enrichment lands. Accepts the shared cross-panel filters plus an OS
    lookup from the project's enrolled agents.
    """
    start = _window_start(window)
    os_by_host = {
        k.get("hostname"): k.get("os_type")
        for k in db.agent_keys.find(
            {"project_id": {"$in": [project_id, str(project_id)]}, "hostname": {"$ne": None}},
            {"hostname": 1, "os_type": 1},
        )
        if k.get("hostname")
    }
    hosts: dict[str, dict] = {}
    for e, ts in _view_events_in_window(project_id, db, start, agent_events_collections()):
        ev_host = e.get("hostname") or (e.get("raw") or {}).get("hostname") or ""
        if not ev_host:
            continue
        if not _passes_threat_filters(e, host, technique_id, min_severity):
            continue
        entry = hosts.setdefault(ev_host, {"risk_total": 0, "event_count": 0, "last_seen": None})
        entry["risk_total"] += float((e.get("enriched") or {}).get("risk_score") or 0)
        entry["event_count"] += 1
        if entry["last_seen"] is None or ts > _parse_ts(entry["last_seen"]):
            entry["last_seen"] = ts.isoformat()
    ranked = [
        {
            "hostname": h,
            "risk_total": round(v["risk_total"], 1),
            "event_count": v["event_count"],
            "last_seen": v["last_seen"],
            "os_type": os_by_host.get(h, ""),
        }
        for h, v in hosts.items()
    ]
    ranked.sort(key=lambda h: h["risk_total"], reverse=True)
    return {"window": window, "hosts": ranked[:100]}


@router.get("/projects/{project_id}/threat-intel/indicators")
def list_feed_indicators(
    project_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    source_feed: str | None = Query(None),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Browsable list of every currently-loaded indicator with provenance.

    Global feed entries (Part D, tagged with source_feed) plus this project's
    manual indicators (source_feed="manual"), filterable by source_feed and
    paginated. Unlike /threat/indicators this shows ALL loaded indicators, not
    just the ones that hit this project's events.
    """
    items: list[dict] = []
    for item in threat_feed.get_feed_items():
        items.append({
            "value": item["value"],
            "category": item["category"],
            "source_feed": item["source_feed"],
            "loaded_at": item["loaded_at"],
        })
    for d in db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID).sort("added_at", -1):
        items.append({
            "value": str(d.get("value", "")),
            "category": d.get("category", "manual"),
            "source_feed": "manual",
            "loaded_at": d.get("added_at"),
        })
    if source_feed:
        items = [i for i in items if i["source_feed"] == source_feed]
    items.sort(key=lambda i: (i["loaded_at"] or ""), reverse=True)
    total = len(items)
    start = (page - 1) * page_size
    return {
        "indicators": items[start:start + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
        "source_feed": source_feed,
        "feeds": threat_feed.get_feed_status(),
        "last_sync": threat_feed.get_last_sync(),
        "error": threat_feed.get_last_error(),
    }


@router.post("/projects/{project_id}/threat-intel/matches/{match_id}/feedback")
def match_feedback(
    project_id: int,
    match_id: str,
    body: FeedbackBody,
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Mark a matched indicator as a false positive for THIS project.

    The indicator value (resolved from the event that produced the match) is
    stored in the project-scoped suppression list; future matches against it
    are excluded from Known Threat IPs, Matched Events and flagged events for
    this project only. The global feed and other projects are untouched.
    """
    pid_q = {"$in": [project_id, str(project_id)]}
    event = None
    for col in all_events_collections():
        event = col.find_one({"id": match_id, "project_id": pid_q}, NO_ID)
        if event:
            break
    if not event:
        raise HTTPException(status_code=404, detail="Match not found")
    matched = _match_indicator(event, list(db.threat_indicators.find({"project_id": project_id, "source": "manual"}, NO_ID)))
    if not matched:
        raise HTTPException(status_code=404, detail="No indicator match found for this event")
    value = matched["value"]
    db.threat_suppressions.update_one(
        {"project_id": project_id, "value": value},
        {"$set": {"is_false_positive": body.is_false_positive, "updated_at": datetime.now(timezone.utc).isoformat()},
         "$setOnInsert": {"created_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    return {"status": "ok", "value": value, "suppressed": body.is_false_positive}


# ---------------------------------------------------------------------------
# Known Threat IPs + Geo Breakdown (Phase 1)
# ---------------------------------------------------------------------------


@router.get("/projects/{project_id}/threat-intel/known-ips")
def threat_known_ips(
    project_id: int,
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    host: str | None = Query(None),
    technique_id: str | None = Query(None),
    min_severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    limit: int = Query(200, ge=1, le=500),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Per-IP rollup for the window: volume, risk, hosts, enrichment.

    Groups view-filtered events by normalized source IP (the same
    enriched→parsed→raw precedence the risk engine reads). Allowlisted and
    suppressed values are excluded outright — known-good infrastructure must
    never appear as a threat. ``is_known_bad`` is true when the IP is on the
    threat feed or was flagged at ingest (``threat_match``). Works with zero
    enrichment (geo fields are empty strings) and lights up once the GeoIP
    DB is configured.
    """
    start = _window_start(window)
    excluded = set(_suppressed_values(project_id, db)) | _allowlisted_values(project_id, db)
    feed_ips = set(threat_feed.get_feed_ips())
    agg: dict[str, dict] = {}
    for e, ts in _view_events_in_window(project_id, db, start):
        if not _passes_threat_filters(e, host, technique_id, min_severity):
            continue
        ip = _event_ip(e)
        if not ip or ip in excluded:
            continue
        enriched = e.get("enriched") or {}
        geo = enriched.get("geo") or {}
        entry = agg.setdefault(ip, {
            "count": 0, "risk_sum": 0.0, "max_risk": 0.0,
            "first_seen": None, "last_seen": None,
            "hosts": set(), "country": "", "city": "",
            "threat_matches": 0,
        })
        risk = float(enriched.get("risk_score") or 0)
        ts_iso = ts.isoformat()
        entry["count"] += 1
        entry["risk_sum"] += risk
        entry["max_risk"] = max(entry["max_risk"], risk)
        if entry["first_seen"] is None or ts_iso < entry["first_seen"]:
            entry["first_seen"] = ts_iso
        if entry["last_seen"] is None or ts_iso > entry["last_seen"]:
            entry["last_seen"] = ts_iso
        ev_host = e.get("hostname") or (e.get("raw") or {}).get("hostname") or ""
        if ev_host:
            entry["hosts"].add(ev_host)
        if not entry["country"] and geo.get("country"):
            entry["country"] = geo.get("country", "")
            entry["city"] = geo.get("city", "")
        if enriched.get("threat_match"):
            entry["threat_matches"] += 1
    rows = [
        {
            "ip": ip,
            "event_count": v["count"],
            "avg_risk": round(v["risk_sum"] / v["count"], 1) if v["count"] else 0,
            "max_risk": round(v["max_risk"], 1),
            "first_seen": v["first_seen"],
            "last_seen": v["last_seen"],
            "hosts": sorted(v["hosts"]),
            "country": v["country"],
            "city": v["city"],
            "is_known_bad": ip in feed_ips or v["threat_matches"] > 0,
            "threat_matches": v["threat_matches"],
        }
        for ip, v in agg.items()
    ]
    rows.sort(key=lambda r: (r["is_known_bad"], r["event_count"]), reverse=True)
    return {"window": window, "ips": rows[:limit], "total": len(rows)}


@router.get("/projects/{project_id}/threat-intel/geo")
def threat_geo(
    project_id: int,
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    host: str | None = Query(None),
    technique_id: str | None = Query(None),
    min_severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Event/IP counts grouped by country (simple sorted list, v1).

    Reads ``enriched.geo.country`` already stored at ingest — no GeoIP lookup
    happens here, so this stays cheap and correct when the DB is absent
    (then every event is "Unknown" and the UI says so honestly).
    """
    start = _window_start(window)
    by_country: dict[str, dict] = {}
    unknown = 0
    for e, _ in _view_events_in_window(project_id, db, start):
        if not _passes_threat_filters(e, host, technique_id, min_severity):
            continue
        country = ((e.get("enriched") or {}).get("geo") or {}).get("country") or ""
        if not country:
            unknown += 1
            continue
        entry = by_country.setdefault(country, {"event_count": 0, "ips": set()})
        entry["event_count"] += 1
        ip = _event_ip(e)
        if ip:
            entry["ips"].add(ip)
    rows = [
        {"country": c, "event_count": v["event_count"], "ip_count": len(v["ips"])}
        for c, v in by_country.items()
    ]
    rows.sort(key=lambda r: r["event_count"], reverse=True)
    return {"window": window, "countries": rows[:10], "unknown_country_events": unknown}


# ---------------------------------------------------------------------------
# Event triage: status / severity / assignee / notes (Phase 2)
# ---------------------------------------------------------------------------


@router.patch("/projects/{project_id}/threat-intel/events/{event_id}/triage")
def triage_event(
    project_id: int,
    event_id: str,
    body: TriageBody,
    user=Depends(get_current_user),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Set triage state on one event (any events_* collection, by string id).

    Only the fields present in the body are touched; everything lives under
    the ``triage`` subdocument so ingest mappings and cleanup queries are
    unaffected. ``severity`` is an analyst override — when absent the API
    keeps bucketing the live risk score.
    """
    if body.status is not None and body.status not in _TRIAGE_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status; expected one of {', '.join(_TRIAGE_STATUSES)}")
    if body.severity is not None and body.severity not in _SEV_RANK and body.severity != "auto":
        raise HTTPException(status_code=400, detail="Invalid severity; expected critical|high|medium|low|auto")
    pid_q = {"$in": [project_id, str(project_id)]}
    target = None
    target_col = None
    for col in all_events_collections():
        doc = col.find_one({"id": event_id, "project_id": pid_q}, NO_ID)
        if doc:
            target, target_col = doc, col
            break
    if target is None:
        raise HTTPException(status_code=404, detail="Event not found")
    update: dict = {"triage.updated_at": datetime.now(timezone.utc).isoformat()}
    unset: dict = {}
    if body.status is not None:
        update["triage.status"] = body.status
    if body.severity is not None:
        if body.severity == "auto":
            unset["triage.severity"] = ""
        else:
            update["triage.severity"] = body.severity
    if body.assigned_to is not None:
        update["triage.assigned_to"] = body.assigned_to
    if body.analyst_notes is not None:
        update["triage.analyst_notes"] = body.analyst_notes
    op: dict = {"$set": update}
    if unset:
        op["$unset"] = unset
    target_col.update_one({"id": event_id, "project_id": pid_q}, op)
    refreshed = target_col.find_one({"id": event_id, "project_id": pid_q}, NO_ID)
    return {"status": "ok", "event_id": event_id, "triage": _triage_dict(refreshed or {})}


# ---------------------------------------------------------------------------
# IOC allowlist: known-good infrastructure (Phase 3)
# ---------------------------------------------------------------------------


@router.get("/projects/{project_id}/threat-intel/allowlist")
def list_allowlist(
    project_id: int,
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Known-good indicators for this project (never flagged as threats)."""
    rows = list(db.ioc_allowlist.find({"project_id": project_id}, {"_id": 0}).sort("created_at", -1))
    return {"allowlist": rows, "total": len(rows)}


@router.post("/projects/{project_id}/threat-intel/allowlist")
def add_allowlist(
    project_id: int,
    body: AllowlistBody,
    user=Depends(get_current_user),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Allowlist one indicator value for this project only."""
    indicator = (body.indicator or "").strip()
    if not indicator:
        raise HTTPException(status_code=400, detail="indicator is required")
    if body.type not in _ALLOWLIST_TYPES:
        raise HTTPException(status_code=400, detail="Invalid type; expected ip|domain|hash")
    db.ioc_allowlist.update_one(
        {"project_id": project_id, "indicator": indicator},
        {"$set": {
            "type": body.type,
            "reason": body.reason or "",
            "added_by": user.get("name") or user.get("email") or str(user.get("id")),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }},
        upsert=True,
    )
    return {"status": "ok", "indicator": indicator}


@router.delete("/projects/{project_id}/threat-intel/allowlist/{indicator}")
def remove_allowlist(
    project_id: int,
    indicator: str,
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Remove an allowlist entry (values flag as threats again)."""
    res = db.ioc_allowlist.delete_one({"project_id": project_id, "indicator": indicator})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Allowlist entry not found")
    return {"status": "ok", "indicator": indicator}


# ---------------------------------------------------------------------------
# Timeline bucket drill-down (Phase 6 drawer data)
# ---------------------------------------------------------------------------


@router.get("/projects/{project_id}/threat-intel/timeline/bucket")
def threat_bucket(
    project_id: int,
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    bucket_start: str = Query(...),
    host: str | None = Query(None),
    technique_id: str | None = Query(None),
    min_severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    limit: int = Query(50, ge=1, le=200),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Raw events inside one timeline bucket (click a bar → drawer).

    Bucket boundaries use the same hourly/daily format the timeline endpoint
    emits, so the UI can pass ``bucket_start`` straight through.
    """
    try:
        bstart = datetime.fromisoformat(str(bucket_start).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid bucket_start; use ISO 8601 format")
    if bstart.tzinfo is None:
        bstart = bstart.replace(tzinfo=timezone.utc)
    bend = bstart + (timedelta(hours=1) if window == "24h" else timedelta(days=1))
    start = _window_start(window)
    rows = []
    for e, ts in _view_events_in_window(project_id, db, start, agent_events_collections()):
        if ts < bstart or ts >= bend:
            continue
        if not _passes_threat_filters(e, host, technique_id, min_severity):
            continue
        ets = e.get("timestamp")
        rows.append({
            "id": e.get("id"),
            "timestamp": ets.isoformat() if hasattr(ets, "isoformat") else str(ets),
            "source": e.get("source", "unknown"),
            "hostname": e.get("hostname") or (e.get("raw") or {}).get("hostname") or "",
            "event_type": e.get("event_type", "generic"),
            "summary": e.get("summary", ""),
            "ip": _event_ip(e),
            "risk_score": (e.get("enriched") or {}).get("risk_score", 0),
            "technique": (e.get("mitre") or {}).get("technique"),
            "tactic": (e.get("mitre") or {}).get("tactic"),
            "severity": _effective_severity(e),
            "triage": _triage_dict(e),
        })
    rows.sort(key=lambda r: str(r["timestamp"]), reverse=True)
    return {"window": window, "bucket_start": bucket_start, "events": rows[:limit], "total": len(rows)}


# ---------------------------------------------------------------------------
# Correlation graph (Phase 4)
# ---------------------------------------------------------------------------

_graph_cache: dict = {}
_GRAPH_TTL = 300
_GRAPH_NODE_CAP = 150
_EDGE_EVENT_IDS_CAP = 50


def _graph_edges_for_window(project_id: int, db, start: datetime,
                            host: str | None, technique_id: str | None,
                            min_severity: str | None) -> tuple[dict, dict]:
    """Build edge + node accumulators from window events and evidence.

    Edges: ip→host (originated_from), host→user (authenticated_as),
    user→event_type (executed), event_type→technique (mapped_to),
    technique→incident (grouped_into, via incident evidence snapshots).
    """
    edges: dict[tuple, dict] = {}
    nodes: dict[str, dict] = {}

    def node(nid: str, ntype: str, label: str):
        entry = nodes.setdefault(nid, {
            "id": nid, "type": ntype, "label": label,
            "risk_sum": 0.0, "touch_count": 0, "meta": {},
        })
        return entry

    def edge(src: str, dst: str, rel: str, event_id: str | None, risk: float):
        key = (src, dst, rel)
        acc = edges.setdefault(key, {"weight": 0, "event_ids": [], "risk_sum": 0.0})
        acc["weight"] += 1
        acc["risk_sum"] += risk
        if event_id and len(acc["event_ids"]) < _EDGE_EVENT_IDS_CAP and event_id not in acc["event_ids"]:
            acc["event_ids"].append(event_id)

    os_by_host = {
        k.get("hostname"): k.get("os_type")
        for k in db.agent_keys.find(
            {"project_id": {"$in": [project_id, str(project_id)]}, "hostname": {"$ne": None}},
            {"hostname": 1, "os_type": 1},
        )
        if k.get("hostname")
    }
    feed_ips = set(threat_feed.get_feed_ips())

    for e, _ in _view_events_in_window(project_id, db, start, agent_events_collections()):
        if not _passes_threat_filters(e, host, technique_id, min_severity):
            continue
        risk = float((e.get("enriched") or {}).get("risk_score") or 0)
        eid = e.get("id")
        ip = _event_ip(e)
        ev_host = e.get("hostname") or (e.get("raw") or {}).get("hostname") or ""
        user = _event_user(e)
        etype = e.get("event_type") or "generic"
        m = e.get("mitre") or {}
        technique = m.get("technique") or ""
        tactic = m.get("tactic") or ""
        geo = (e.get("enriched") or {}).get("geo") or {}

        host_id = f"host:{ev_host}" if ev_host else None
        if ip and host_id:
            ip_id = f"ip:{ip}"
            n = node(ip_id, "ip", ip)
            n["meta"].setdefault("country", geo.get("country", ""))
            n["meta"].setdefault("city", geo.get("city", ""))
            n["meta"]["is_known_bad"] = ip in feed_ips or bool((e.get("enriched") or {}).get("threat_match"))
            node(host_id, "host", ev_host)["meta"].setdefault("os", os_by_host.get(ev_host, ""))
            edge(ip_id, host_id, "originated_from", eid, risk)
        if host_id and user:
            user_id = f"user:{user}"
            node(user_id, "user", user)
            node(host_id, "host", ev_host)
            edge(host_id, user_id, "authenticated_as", eid, risk)
        if user:
            user_id = f"user:{user}"
            type_id = f"type:{etype}"
            node(user_id, "user", user)
            node(type_id, "event_type", etype)
            edge(user_id, type_id, "executed", eid, risk)
        if technique:
            type_id = f"type:{etype}"
            tech_id = f"technique:{technique}"
            node(type_id, "event_type", etype)
            tnode = node(tech_id, "technique", technique)
            if tactic:
                tnode["meta"].setdefault("tactic", tactic)
            edge(type_id, tech_id, "mapped_to", eid, risk)

    # technique → incident via evidence snapshots of this project's incidents
    for inc in db.incidents.find({"project_id": project_id}, NO_ID):
        for ev in db.incident_evidence.find({"incident_id": inc.get("id")}, {"event_snapshot": 1}):
            snap = ev.get("event_snapshot")
            try:
                snap = jsonlib.loads(snap) if isinstance(snap, str) else (snap or {})
            except (TypeError, ValueError):
                continue
            tech = ((snap.get("mitre") or {}).get("technique")) or ""
            if not tech:
                continue
            if technique_id and not (tech == technique_id or tech.startswith(technique_id)):
                continue
            tech_id = f"technique:{tech}"
            inc_id = f"incident:{inc.get('id')}"
            node(tech_id, "technique", tech)
            inode = node(inc_id, "incident", inc.get("title") or f"Incident #{inc.get('id')}")
            inode["meta"]["status"] = inc.get("status", "")
            inode["meta"]["severity"] = inc.get("severity", "")
            edge(tech_id, inc_id, "grouped_into", snap.get("id"), 0.0)

    # Fold edge risk into node risk_contribution inputs
    for (src, dst, _rel), acc in edges.items():
        for nid in (src, dst):
            if nid in nodes:
                nodes[nid]["risk_sum"] += acc["risk_sum"]
                nodes[nid]["touch_count"] += acc["weight"]
    return edges, nodes


@router.get("/projects/{project_id}/threat-intel/graph")
def threat_graph(
    project_id: int,
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    host: str | None = Query(None),
    technique_id: str | None = Query(None),
    min_severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    min_weight: int = Query(1, ge=1),
    limit: int = Query(_GRAPH_NODE_CAP, ge=10, le=500),
    _project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """Force-directed correlation graph data for the window.

    Nodes: ip / host / user / event_type / technique / incident with degree
    and avg-risk contribution. Edges carry co-occurrence weight + capped
    event ids for drill-down. Nodes are capped (top by degree) with a
    ``truncated`` flag so the layout never chokes on dense windows. The
    unfiltered aggregation is cached briefly per project+window+filters.
    """
    start = _window_start(window)
    cache_key = (project_id, window, host, technique_id, min_severity)
    now = time.monotonic()
    cached = _graph_cache.get(cache_key)
    if cached and cached[0] > now:
        edges, nodes = cached[1], cached[2]
    else:
        edges, nodes = _graph_edges_for_window(project_id, db, start, host, technique_id, min_severity)
        _graph_cache[cache_key] = (now + _GRAPH_TTL, edges, nodes)

    for nid in nodes:
        nodes[nid]["degree"] = 0
    for (src, dst, _rel) in edges:
        if src in nodes:
            nodes[src]["degree"] += 1
        if dst in nodes:
            nodes[dst]["degree"] += 1
    ranked = sorted(
        nodes.values(),
        key=lambda n: (n["degree"], n["risk_sum"] / max(n["touch_count"], 1)),
        reverse=True,
    )
    total_nodes = len(ranked)
    kept = ranked[:limit]
    truncated = total_nodes > limit
    keep_ids = {n["id"] for n in kept}
    out_edges = [
        {
            "source_id": src,
            "target_id": dst,
            "relationship": rel,
            "weight": acc["weight"],
            "event_ids": acc["event_ids"],
        }
        for (src, dst, rel), acc in edges.items()
        if acc["weight"] >= min_weight and src in keep_ids and dst in keep_ids
    ]
    out_nodes = [
        {
            "id": n["id"],
            "type": n["type"],
            "label": n["label"],
            "degree": n["degree"],
            "risk_contribution": round(n["risk_sum"] / max(n["touch_count"], 1), 1),
            "meta": n["meta"],
        }
        for n in kept
    ]
    return {
        "window": window,
        "nodes": out_nodes,
        "edges": out_edges,
        "truncated": truncated,
        "totals": {"nodes": total_nodes, "edges": len(edges)},
        "showing": {"nodes": len(out_nodes), "edges": len(out_edges)},
    }
