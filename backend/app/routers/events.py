from fastapi import APIRouter, Depends, HTTPException, Query
import re
from datetime import datetime, timezone
from app.database import get_db, NO_ID, get_events_collection, EVENTS_SOURCES, all_events_collections, EVENTS_VIEW_COND
from app.auth import get_current_user
from app.dependencies import get_owned_project
from app.models.cleanup import CleanupFilters, CleanupExecute
from app.services.elastic import search_events, get_event_by_id, delete_events_by_query
from app.services.audit import record_cleanup, list_cleanups

router = APIRouter(dependencies=[Depends(get_current_user)])


def _event_to_dict(e: dict) -> dict:
    ts = e.get("timestamp")
    return {
        "id": e.get("id"),
        "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
        "source": e.get("source", "unknown"),
        "category": e.get("category", ""),
        "event_type": e.get("event_type", "generic"),
        "summary": e.get("summary", ""),
        "parsed": e.get("parsed", {}),
        "raw": e.get("raw", {}),
        "enriched": e.get("enriched", {}),
        "tags": e.get("tags", []),
    }


RAW_CATEGORIES = ("heartbeat", "lifecycle")
NAMED_CATEGORIES = (*RAW_CATEGORIES, "security_event")


def _ts_sort_key(doc: dict):
    ts = doc.get("timestamp")
    if isinstance(ts, datetime):
        return (ts.timestamp(), str(doc.get("id", "")))
    if isinstance(ts, str):
        try:
            return (datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp(), str(doc.get("id", "")))
        except ValueError:
            pass
    return (0.0, str(doc.get("id", "")))


def _base_mongo_q(project_id: int, event_type: str | None, severity: str | None,
                  query: str | None, host: str | None, category: str | None = None) -> dict:
    mongo_q = {"project_id": {"$in": [project_id, str(project_id)]}}
    # A named category narrows to exactly that bucket (so "security only"
    # excludes uncategorized website docs); unset keeps the curated surface.
    conds = [{"category": category}] if category in NAMED_CATEGORIES else [EVENTS_VIEW_COND]
    if event_type:
        conds.append({"$or": [{"event_type": event_type}, {"enriched.severity": event_type}]})
    if severity:
        conds.append({"$or": [{"event_type": severity}, {"enriched.severity": severity}]})
    if query:
        rx = re.compile(re.escape(query), re.IGNORECASE)
        conds.append({"$or": [{"summary": rx}, {"raw.message": rx}, {"raw.url": rx}, {"enriched.ip": rx}, {"id": rx}]})
    if host:
        hrx = re.compile(re.escape(host), re.IGNORECASE)
        conds.append({"$or": [{"hostname": hrx}, {"raw.hostname": hrx}]})
    mongo_q["$and"] = conds
    return mongo_q


@router.get("/projects/{project_id}/events")
def list_events(
    query: str = Query(None),
    severity: str = Query(None),
    source: str = Query(None, description="Filter to one source: website | windows | linux | all"),
    event_type: str = Query(None),
    host: str = Query(None),
    category: str = Query(None, description="Raw agent bucket: heartbeat | lifecycle | security_event | all"),
    time_from: str = Query(None),
    time_to: str = Query(None),
    size: int = Query(50),
    offset: int = Query(0),
    project=Depends(get_owned_project),
    db=Depends(get_db),
):
    """List events for a project.

    With ``source`` set to one of website/windows/linux, events come only
    from that source's collection. Without it (or with ``source=all``) the
    three collections are merged into one time-sorted feed (Elasticsearch
    first, MongoDB as fallback) so the Live Events view stays unified.

    ``category=heartbeat|lifecycle`` opens the raw agent stream (bypassing
    Elasticsearch, which only indexes the security surface); anything else
    keeps the curated security-event feed.
    """
    project_id = project["id"]

    if source == "all":
        source = None
    if category == "all":
        category = None
    if category and category not in (*RAW_CATEGORIES, "security_event"):
        raise HTTPException(status_code=400, detail="Invalid category; expected one of heartbeat, lifecycle, security_event, all")

    if source:
        if source not in EVENTS_SOURCES:
            raise HTTPException(status_code=400, detail=f"Invalid source; expected one of {', '.join(EVENTS_SOURCES)}")
        col = get_events_collection(source)
        q = _base_mongo_q(project_id, event_type, severity, query, host, category)
        docs = list(col.find(q, NO_ID).sort([("timestamp", -1), ("_id", -1)]).skip(offset).limit(size))
        return {"events": [_event_to_dict(d) for d in docs], "total": col.count_documents(q)}

    if category not in NAMED_CATEGORIES:
        events_list, total = search_events(
            project_id, query, severity, source, event_type,
            time_from, time_to, size, offset, host=host,
        )
        if events_list:
            return {"events": events_list, "total": total}

    # Merge the three per-source collections and re-sort in Python — Mongo
    # cannot sort across collections natively.
    q = _base_mongo_q(project_id, event_type, severity, query, host, category)
    merged = []
    for src in EVENTS_SOURCES:
        merged.extend(
            get_events_collection(src).find(q, NO_ID)
            .sort([("timestamp", -1), ("_id", -1)])
            .limit(offset + size)
        )
    merged.sort(key=_ts_sort_key, reverse=True)
    total_merged = sum(get_events_collection(src).count_documents(q) for src in EVENTS_SOURCES)
    if merged:
        return {
            "events": [_event_to_dict(d) for d in merged[offset: offset + size]],
            "total": total_merged,
        }

    # No events at all: return the empty feed. Raw agent entries (heartbeat /
    # lifecycle) are deliberately excluded by EVENTS_VIEW_COND and are browsed
    # through GET /agents/logs and the "raw agent logs" cleanup instead.
    return {"events": [], "total": 0}


def _cleanup_cutoff(before: str | None) -> str:
    """Validate + normalize an ISO cutoff to the stored format (isoformat with offset).

    Events store timestamps as ``now.isoformat()`` strings (``+00:00`` suffix,
    variable microseconds); the frontend sends ``toISOString()`` (``Z`` suffix).
    Normalizing both to offset-form ISO keeps the ``$lt`` string comparison exact.
    """
    if not before:
        raise HTTPException(status_code=400, detail="The 'before' cutoff timestamp is required")
    try:
        dt = datetime.fromisoformat(str(before).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid 'before' timestamp; use ISO 8601 format")
    return dt.isoformat()


def _cleanup_query(project_id: int, source: str, hostname: str | None, before_iso: str) -> dict:
    q = {
        "project_id": {"$in": [project_id, str(project_id)]},
        "timestamp": {"$lt": before_iso},
        "$and": [EVENTS_VIEW_COND],
    }
    if source != "all":
        q["source"] = source
    if hostname:
        q["raw.hostname"] = hostname
    return q


def _matched_events(db, project_id: int, source: str, hostname: str | None,
                    before_iso: str, size: int = 20, offset: int = 0):
    """Count + newest-first sample of the events a cleanup would remove.

    One and the same query builder is used here and in the delete endpoint, so
    the preview count is exactly the count the delete re-validates against.
    """
    q = _cleanup_query(project_id, source, hostname, before_iso)
    cols = [get_events_collection(source)] if source != "all" else list(all_events_collections())
    total = 0
    if size <= 0:
        # count-only path (the delete endpoint re-validates against this)
        for col in cols:
            total += col.count_documents(q)
        return [], total
    docs = []
    for col in cols:
        total += col.count_documents(q)
        # Fetch through the requested page per collection, slice once below —
        # skipping in both places would drop rows across collections.
        docs.extend(
            col.find(q, NO_ID)
            .sort([("timestamp", -1), ("_id", -1)])
            .limit(offset + size)
        )
    docs.sort(key=lambda d: (str(d.get("timestamp", "")), str(d.get("id", ""))), reverse=True)
    return docs[offset: offset + size], total


def _oldest_newest(db, project_id: int, source: str, hostname: str | None, before_iso: str):
    """Oldest/newest timestamps of the matched set (string compare is safe:
    every stored timestamp is offset-form isoformat)."""
    q = _cleanup_query(project_id, source, hostname, before_iso)
    cols = [get_events_collection(source)] if source != "all" else list(all_events_collections())
    oldest = None
    newest = None
    for col in cols:
        first = col.find_one(q, {"timestamp": 1}, sort=[("timestamp", 1), ("_id", 1)])
        last = col.find_one(q, {"timestamp": 1}, sort=[("timestamp", -1), ("_id", -1)])
        if first and (oldest is None or str(first.get("timestamp", "")) < oldest):
            oldest = str(first.get("timestamp", ""))
        if last and (newest is None or str(last.get("timestamp", "")) > newest):
            newest = str(last.get("timestamp", ""))
    return oldest, newest


def _sample_event(e: dict) -> dict:
    ts = e.get("timestamp")
    return {
        "id": e.get("id"),
        "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
        "source": e.get("source", "unknown"),
        "event_type": e.get("event_type", "generic"),
        "summary": e.get("summary", ""),
        "raw_message": (e.get("raw") or {}).get("message", ""),
        "raw_url": (e.get("raw") or {}).get("url", ""),
        "hostname": (e.get("raw") or {}).get("hostname", ""),
    }


@router.post("/projects/{project_id}/events/cleanup/preview",
             summary="Preview which events a cleanup would delete (read-only)")
def cleanup_preview(project_id: int, body: CleanupFilters,
                    _project=Depends(get_owned_project), db=Depends(get_db)):
    """Show exactly what a DELETE with the same body would remove.

    Returns the total count, the newest 20 matching events (full timestamp /
    source / summary so the user recognizes real rows), and the oldest/newest
    matched timestamps. Deletes nothing — the UI calls this on every filter
    change so the count shown is always live.
    """
    if body.source not in EVENTS_SOURCES and body.source != "all":
        raise HTTPException(status_code=400, detail=f"Invalid source; expected one of all, {', '.join(EVENTS_SOURCES)}")
    before_iso = _cleanup_cutoff(body.before)

    docs, total = _matched_events(db, project_id, body.source, body.hostname, before_iso, size=20)
    oldest, newest = _oldest_newest(db, project_id, body.source, body.hostname, before_iso)
    return {
        "count": total,
        "sample": [_sample_event(d) for d in docs],
        "oldest_match": oldest,
        "newest_match": newest,
    }


@router.delete("/projects/{project_id}/events/cleanup",
               summary="Delete events matching the previewed filters (audit-logged)")
def cleanup_events(project_id: int, body: CleanupExecute,
                   user=Depends(get_current_user),
                   _project=Depends(get_owned_project), db=Depends(get_db)):
    """Execute the cleanup shown by the preview.

    Re-validates ``expected_count`` against a fresh server-side count first:
    if the matching set changed between preview and confirm, the request is
    rejected with 409. (Standalone Mongo has no multi-document transactions,
    so rows arriving between the re-count and the delete still match the same
    cutoff query — the guard catches drift, not same-millisecond races.)
    Deletes from the relevant events_* collections AND issues the matching
    Elasticsearch delete_by_query, then records the action in the immutable
    ``audit_log`` collection. ``es_synced`` is false when ES was unreachable;
    Mongo stays the source of truth either way.
    """
    if body.source not in EVENTS_SOURCES and body.source != "all":
        raise HTTPException(status_code=400, detail=f"Invalid source; expected one of all, {', '.join(EVENTS_SOURCES)}")
    before_iso = _cleanup_cutoff(body.before)

    _, total = _matched_events(db, project_id, body.source, body.hostname, before_iso, size=0)
    if total != body.expected_count:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Data changed since the preview was run: {total} event(s) now match, "
                f"not {body.expected_count}. Please preview again before deleting."
            ),
        )

    q = _cleanup_query(project_id, body.source, body.hostname, before_iso)
    cols = [get_events_collection(body.source)] if body.source != "all" else list(all_events_collections())
    deleted = 0
    for col in cols:
        deleted += col.delete_many(q).deleted_count

    es_deleted = delete_events_by_query(project_id, None if body.source == "all" else body.source, before_iso, body.hostname)

    record_cleanup(db, user, project_id, body.source, body.hostname, before_iso, deleted, scope="events")
    return {"deleted_count": deleted, "es_synced": es_deleted >= 0}


@router.get("/events/{event_id}", summary="Get a single event by id")
def get_event(event_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    """Return one event — but only to the owner of its project.

    Event ids are unpredictable, but that is not an access control: the owning
    project is resolved first (Mongo, then ES fallback) and the standard
    ownership check runs before any event data is returned, so a cross-project
    id guess gets a 404 rather than the event.
    """
    for col in all_events_collections():
        e = col.find_one({"id": event_id}, NO_ID)
        if e:
            try:
                get_owned_project(int(e.get("project_id")), user, db)
            except (TypeError, ValueError):
                raise HTTPException(status_code=404, detail="Event not found")
            return e
    event = get_event_by_id(event_id)
    if event:
        try:
            get_owned_project(int(event.get("project_id")), user, db)
        except (TypeError, ValueError):
            raise HTTPException(status_code=404, detail="Event not found")
        return event
    raise HTTPException(status_code=404, detail="Event not found")


@router.get("/projects/{project_id}/cleanup-history",
            summary="Cleanup audit trail for a project (read-only, never cleanable)")
def cleanup_history(project_id: int, limit: int = Query(50), offset: int = Query(0),
                    _project=Depends(get_owned_project), db=Depends(get_db)):
    """List every executed cleanup for this project.

    Rows live in the ``audit_log`` collection, which the product can never
    delete or edit — there is deliberately no endpoint to remove them. This
    list is the durable record of what was deleted, by whom, and when.
    """
    rows, total = list_cleanups(db, project_id, limit=limit, offset=offset)
    return {"cleanups": rows, "total": total}

