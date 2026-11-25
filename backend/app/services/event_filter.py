"""Gate the Events pipeline: only security-relevant entries are promoted.

Every agent entry is still written verbatim into its per-source collection
(events_windows / events_linux, category heartbeat|lifecycle) — nothing is
lost. This module decides which entries ALSO get category ``security_event``
and surface on the Events surface / Elasticsearch / Live Events. Severity
here is a security assessment, NOT a passthrough of the OS's own
Level/Error/Warning label.
"""

from app.services.log_parser import detect_log_type

# Windows: log_name -> {event_id: security severity}
# NOTE: 4624 stays "medium" for now; escalation for logon type 3/10 combined
# with a new/unfamiliar source IP can be layered on top of this table later.
ALLOWED_WINDOWS_EVENTS = {
    "Security": {
        4624: "medium",   # successful logon (escalate below if type 3/10 + new IP)
        4625: "high",     # failed logon
        4634: "info",     # logoff
        4648: "medium",   # explicit credential logon
        4672: "medium",   # privileged/special logon
        4688: "info",     # new process created
        4698: "medium",   # scheduled task created
        4720: "medium",   # account created
        4722: "medium",   # account enabled
        4724: "high",     # password reset attempt
        4732: "high",     # member added to security-enabled local group
        4740: "medium",   # user account locked out
        4756: "high",     # member added to security-enabled universal group
        4768: "info",     # Kerberos TGT requested
        4769: "info",     # Kerberos service ticket requested
        4771: "medium",   # Kerberos pre-auth failed
        4776: "medium",   # credential validation
        1102: "critical", # audit log cleared — classic anti-forensics move
    },
    "System": {
        7045: "medium",   # new service installed — common persistence technique
        104:  "high",     # event log cleared
    },
    # Application: nothing by default — licensing/app crash noise lives here.
    # Add specific provider+event_id pairs only if you find a genuine security
    # signal in Application (e.g. a specific AV product's detection event ID).
}

# Linux: parsed action -> security severity
ALLOWED_LINUX_ACTIONS = {
    "failed_login": "medium",     # escalates on repetition, see risk_engine
    "successful_login": "info",   # escalates if from an unfamiliar/flagged IP
    "sudo_command": "info",       # escalate only for specific sensitive commands
    "process_exec": "info",       # every command run in a real user session
    "account_added": "high",
}


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_log_name(log_name) -> str:
    name = (log_name or "").strip()
    if name in ALLOWED_WINDOWS_EVENTS:
        return name
    title = name.title()
    return title if title in ALLOWED_WINDOWS_EVENTS else name


def is_security_relevant(log_name: str, event_id) -> bool:
    """Windows: is this (log, event_id) pair worth promoting to Events?"""
    key = _normalize_log_name(log_name)
    eid = _to_int(event_id)
    return eid is not None and eid in ALLOWED_WINDOWS_EVENTS.get(key, {})


def is_security_relevant_linux(parsed: dict) -> bool:
    """Linux: is this parsed action worth promoting to Events?"""
    return (parsed or {}).get("action") in ALLOWED_LINUX_ACTIONS


def base_severity(log_name: str, event_id) -> str:
    """Security severity for a Windows (log, event_id) pair; "info" if unlisted."""
    key = _normalize_log_name(log_name)
    eid = _to_int(event_id)
    if eid is None:
        return "info"
    return ALLOWED_WINDOWS_EVENTS.get(key, {}).get(eid, "info")


def is_relevant_entry(meta: dict | None, parsed: dict) -> bool:
    """Decide whether a raw log entry should be promoted to the Events pipeline."""
    meta = meta or {}
    parsed = parsed or {}
    if detect_log_type(meta) == "linux":
        return is_security_relevant_linux(parsed)
    return is_security_relevant(meta.get("log_name", ""), meta.get("event_id", 0))
