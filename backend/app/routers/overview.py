from collections import Counter
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Query
from app.database import get_db, all_events_collections, agent_events_collections, EVENTS_VIEW_COND
from app.auth import get_current_user
from app.dependencies import get_owned_project
from app.services.elastic import _es_up

router = APIRouter(dependencies=[Depends(get_current_user)])


def _parse_ts(v):
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception:
            return None
    return None


@router.get("/projects/{project_id}/overview", summary="Dashboard overview stats for a project")
def project_overview(
    hours: int = Query(24),
    project=Depends(get_owned_project),
    db=Depends(get_db),
):
    project_id = project["id"]
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    start_hint = (start - timedelta(seconds=1)).isoformat()
    pid_q = {"$in": [project_id, str(project_id)]}

    events = []
    total_events = 0
    for col in all_events_collections():
        total_events += col.count_documents({"project_id": pid_q, "$and": [EVENTS_VIEW_COND]})
        events.extend(col.find(
            {
                "project_id": pid_q,
                "$and": [
                    EVENTS_VIEW_COND,
                    {"$or": [{"timestamp": {"$gte": start_hint}}, {"timestamp": {"$gte": start}}]},
                ],
            },
            {"timestamp": 1, "event_type": 1, "source": 1, "enriched.ip": 1, "enriched.severity": 1, "summary": 1, "raw.hostname": 1},
        ))

    in_range = []
    for e in events:
        ts = _parse_ts(e.get("timestamp"))
        if ts and ts >= start:
            in_range.append((e, ts))
    in_range.sort(key=lambda x: x[1], reverse=True)

    def _sev(ev):
        s = (ev.get("enriched") or {}).get("severity")
        if s in ("critical", "high", "medium", "low", "info"):
            return s
        return ev.get("event_type", "unknown")

    event_count = len(in_range)
    alert_count = sum(1 for e, _ in in_range if _sev(e) in ("critical", "high"))

    top_ips = Counter()
    top_types = Counter()
    for e, _ in in_range:
        ip = (e.get("enriched") or {}).get("ip")
        if ip:
            top_ips[ip] += 1
        top_types[_sev(e)] += 1

    if hours <= 48:
        fmt = "%Y-%m-%d %H:00"
    else:
        fmt = "%Y-%m-%d"
    buckets = {}
    for _, ts in in_range:
        key = ts.strftime(fmt)
        buckets[key] = buckets.get(key, 0) + 1
    chart = [{"date": k, "count": buckets[k]} for k in sorted(buckets.keys())]

    last_event_ts = max((ts for _, ts in in_range), default=None)
    last_heartbeat = None
    for col in agent_events_collections():
        hb = col.find_one(
            {"project_id": pid_q, "category": "heartbeat"}, {"timestamp": 1},
            sort=[("timestamp", -1)],
        )
        if hb and (last_heartbeat is None or str(hb.get("timestamp", "")) > str(last_heartbeat.get("timestamp", ""))):
            last_heartbeat = hb
    last_heartbeat_ts = _parse_ts(last_heartbeat.get("timestamp")) if last_heartbeat else None

    es_up = bool(_es_up())
    if event_count > 0 and es_up:
        health = "healthy"
    elif event_count > 0:
        health = "degraded"
    else:
        health = "no_data"

    agents = []
    for k in db.agent_keys.find({"project_id": pid_q}, {"_id": 0, "key_hash": 0}):
        last = _parse_ts(k.get("last_seen_at"))
        agents.append({
            "id": k.get("id"),
            "label": k.get("label"),
            "hostname": k.get("hostname"),
            "os_type": k.get("os_type"),
            "ip_address": k.get("ip_address"),
            "status": k.get("status"),
            "last_seen_at": last.isoformat() if last else None,
        })

    open_incidents = db.incidents.count_documents({"project_id": project_id, "status": {"$nin": ["resolved", "false_positive"]}})

    return {
        "hours": hours,
        "events_in_range": event_count,
        "alerts_in_range": alert_count,
        "open_incidents": open_incidents,
        "ingest_health": {
            "status": health,
            "elasticsearch_up": es_up,
            "last_event_at": last_event_ts.isoformat() if last_event_ts else None,
            "last_heartbeat_at": last_heartbeat_ts.isoformat() if last_heartbeat_ts else None,
        },
        "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_ips.most_common(5)],
        "top_event_types": [{"event_type": t, "count": c} for t, c in top_types.most_common(5)],
        "severity_distribution": {t: c for t, c in top_types.items()},
        "chart": chart,
        "agents": agents,
        "total_events": total_events,
    }
