from datetime import datetime, timezone
from app.database import get_next_id, NO_ID

AUDIT_LOG_COLLECTION = "audit_log"


def record_cleanup(db, user, project_id: int, source: str, hostname: str | None,
                   before: str, deleted_count: int, scope: str = "events"):
    """Append one immutable audit entry for an executed cleanup.

    The ``audit_log`` collection is write-only from the product's perspective:
    there is deliberately NO endpoint that can delete or edit these rows, and
    the cleanup code paths never touch it with delete_many/update — a cleanup
    of security logs is itself a security-sensitive action and must leave a
    durable, non-destructible record (user, filters, count, when).
    """
    db.audit_log.insert_one({
        "id": get_next_id(AUDIT_LOG_COLLECTION),
        "user_id": user["id"],
        "username": user.get("name") or user.get("email") or user.get("username") or "",
        "project_id": project_id,
        "scope": scope,
        "source": source,
        "hostname_filter": hostname or "",
        "before_timestamp": before,
        "deleted_count": deleted_count,
        "executed_at": datetime.now(timezone.utc),
    })


def list_cleanups(db, project_id: int, limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
    """Newest-first cleanup history for a project (read-only audit trail).

    Must exclude incident activity rows, which share the audit_log
    collection but carry no deleted_count/scope fields.
    """
    q = {"project_id": project_id, "entity_type": {"$ne": "incident"}}
    total = db.audit_log.count_documents(q)
    docs = list(
        db.audit_log.find(q, NO_ID)
        .sort("executed_at", -1)
        .skip(offset)
        .limit(limit)
    )
    rows = []
    for d in docs:
        ts = d.get("executed_at")
        rows.append({
            "id": d.get("id"),
            "user_id": d.get("user_id"),
            "username": d.get("username", ""),
            "scope": d.get("scope", "events"),
            "source": d.get("source"),
            "hostname_filter": d.get("hostname_filter", ""),
            "before_timestamp": d.get("before_timestamp"),
            "deleted_count": d.get("deleted_count"),
            "executed_at": ts.isoformat() if isinstance(ts, datetime) else str(ts),
        })
    return rows, total


def log_incident_action(db, user, project_id: int, incident_id: int,
                        action: str, detail: str,
                        from_value: str | None = None,
                        to_value: str | None = None) -> dict:
    """Append one immutable entry to the incident activity log.

    Lives in the same write-only ``audit_log`` collection as cleanups (the
    product has no delete/edit endpoint for these rows); entries are tagged
    ``entity_type: "incident"`` so the two audit streams never collide.
    ``from_value``/``to_value`` capture field transitions (status, severity,
    assignee) for the activity feed.
    """
    row = {
        "id": get_next_id(AUDIT_LOG_COLLECTION),
        "entity_type": "incident",
        "incident_id": incident_id,
        "project_id": project_id,
        "user_id": user["id"],
        "username": user.get("name") or user.get("email") or user.get("username") or "",
        "action": action,
        "detail": detail,
        "from_value": from_value,
        "to_value": to_value,
        "timestamp": datetime.now(timezone.utc),
    }
    db.audit_log.insert_one(row)
    return row


def list_incident_activity(db, incident_id: int, limit: int = 500) -> list[dict]:
    """Chronological activity for one incident, authors resolved by user id.

    The username snapshot written at log time is used when the user record
    no longer exists (e.g. account deleted); live join wins otherwise.
    Capped so a chatty incident can't dump unbounded history into one response.
    """
    users = {u["id"]: u for u in db.users.find({}, NO_ID)}
    docs = list(
        db.audit_log.find({"entity_type": "incident", "incident_id": incident_id}, NO_ID)
        .sort("timestamp", 1)
        .limit(limit)
    )
    rows = []
    for d in docs:
        uid = d.get("user_id")
        user = users.get(uid)
        name = ""
        if user:
            name = user.get("name") or user.get("email") or ""
        if not name:
            name = d.get("username", "")
        if not name:
            name = f"User #{uid}"
        ts = d.get("timestamp")
        rows.append({
            "id": d.get("id"),
            "user_id": uid,
            "user_name": name,
            "action": d.get("action"),
            "detail": d.get("detail", ""),
            "from_value": d.get("from_value"),
            "to_value": d.get("to_value"),
            "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
        })
    return rows
