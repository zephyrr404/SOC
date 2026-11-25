"""Normalize raw agent log lines into structured summaries.

Every function returns {"summary": str, "parsed": dict} and NEVER mutates or
discards the original raw text — callers keep the raw message verbatim for
forensics and store summary/parsed alongside it.
"""

import ipaddress
import re

# ── Windows: well-known Security/System event IDs → action + summary template ──

WINDOWS_EVENT_TEMPLATES = {
    4625: ("failed_logon", "Failed logon for {user} from {ip}"),
    4624: ("successful_logon", "Successful logon for {user} from {ip}"),
    4648: ("explicit_credential_logon", "Explicit credential logon for {user} from {ip}"),
    5156: ("connection_allowed", "WFP permitted a connection from {ip}"),
    4634: ("logoff", "Logoff for {user}"),
    4647: ("logoff", "User initiated logoff for {user}"),
    4720: ("account_created", "User account created: {user}"),
    4722: ("account_enabled", "User account enabled: {user}"),
    4723: ("password_changed", "Password changed for {user}"),
    4724: ("password_reset", "Password reset attempted for {user}"),
    4725: ("account_disabled", "User account disabled: {user}"),
    4726: ("account_deleted", "User account deleted: {user}"),
    4740: ("account_locked", "User account locked out: {user}"),
    4756: ("group_member_added", "Member added to a security-enabled universal group"),
    4768: ("kerberos_tgt_requested", "Kerberos TGT requested for {user} from {ip}"),
    4769: ("kerberos_service_ticket", "Kerberos service ticket requested for {user} from {ip}"),
    4771: ("kerberos_preauth_failed", "Kerberos pre-authentication failed for {user} from {ip}"),
    4776: ("credential_validation", "Credential validation attempted for {user}"),
    4688: ("process_created", "New process created: {process}"),
    4732: ("group_member_added", "Member added to a security-enabled local group"),
    1102: ("audit_log_cleared", "Security audit log was cleared"),
    7045: ("service_installed", "A service was installed in the system"),
    4698: ("scheduled_task_created", "A scheduled task was created"),
    6005: ("service_started", "Event log service started"),
    6006: ("service_stopped", "Event log service stopped"),
}

_FIELD_PATTERNS = {
    "ip": [
        r"Source Network Address:\s*(\S+)",
        r"Source Address:\s*(\S+)",
        r"IP Address:\s*(\S+)",
        r"Client Address:\s*(\S+)",
    ],
    "process": [
        r"New Process Name:\s*(\\?[^:\r\n]+)",
        r"Process Name:\s*(\S+)",
    ],
}

_LINE_LIMIT = 200


def _first_line(text: str) -> str:
    line = (text or "").strip().splitlines()
    return (line[0].strip() if line else (text or "")).strip()[: _LINE_LIMIT]


def _valid_user(value: str) -> bool:
    v = value.strip()
    return bool(v) and v.lower() not in ("-", "n/a")


def _lookup_ip(value: str) -> str | None:
    """Accept only genuinely useful source IPs; drop placeholders and loopback.

    ``-``, ``n/a`` and loopback addresses (127.0.0.0/8, ::1, IPv4-mapped
    variants) carry no attacker signal — e.g. 4624/4625 Type 2 console logons
    report "-" and RDP sessions land on ::1 for localhost connections.
    """
    v = value.strip()
    if not v or v.lower() in ("-", "n/a"):
        return None
    try:
        addr = ipaddress.ip_address(v)
    except ValueError:
        return None
    if addr.is_loopback or addr.is_multicast:
        return None
    return v


def _extract_ip(message: str) -> str | None:
    for pattern in _FIELD_PATTERNS["ip"]:
        m = re.search(pattern, message, re.IGNORECASE | re.MULTILINE)
        if m:
            ip = _lookup_ip(m.group(1))
            if ip:
                return ip
    return None


def _extract(message: str, key: str) -> str | None:
    if key == "user":
        m = re.search(
            r"Account For Which Logon Failed:.*?Security ID:.*?Account Name:\s*(\S+)",
            message,
            re.IGNORECASE | re.DOTALL,
        )
        if m and _valid_user(m.group(1)):
            return m.group(1).strip()
        m = re.search(r"Target Account:.*?Account Name:\s*(\S+)", message, re.IGNORECASE | re.DOTALL)
        if m and _valid_user(m.group(1)):
            return m.group(1).strip()
        m = re.search(r"New User Name:\s*(\S+)", message)
        if m and _valid_user(m.group(1)):
            return m.group(1).strip()
        for m in re.finditer(r"Account Name:\s*(\S+)", message):
            if _valid_user(m.group(1)):
                return m.group(1).strip()
        return None
    for pattern in _FIELD_PATTERNS.get(key, []):
        m = re.search(pattern, message, re.IGNORECASE | re.MULTILINE)
        if m and _valid_user(m.group(1)):
            return m.group(1).strip()
    return None


def parse_windows_event(raw_message: str, meta: dict | None = None) -> dict:
    """Parse a Windows Event Log entry into a readable summary + fields.

    Known Security event IDs (4625 failed logon, 4624 successful logon, 4720
    account created, ...) get template summaries with extracted user/IP;
    everything else falls back to the first line of the message.
    """
    meta = meta or {}
    message = (raw_message or "").strip()
    result = {"summary": _first_line(message) or (raw_message or "")[: _LINE_LIMIT], "parsed": {}}

    try:
        event_id = int(meta.get("event_id") or 0)
    except (TypeError, ValueError):
        event_id = 0

    parsed = {
        "event_id": str(event_id) if event_id else meta.get("event_id", ""),
        "provider": meta.get("provider", ""),
        "level": meta.get("level_name", ""),
    }
    if meta.get("log_name"):
        parsed["log_name"] = meta["log_name"]

    if event_id and event_id in WINDOWS_EVENT_TEMPLATES:
        action, template = WINDOWS_EVENT_TEMPLATES[event_id]
        parsed["action"] = action
        user = _extract(message, "user")
        ip = _extract_ip(message)
        process = _extract(message, "process")
        logon_type_m = re.search(r"Logon Type:\s*(\d+)", message)
        if logon_type_m:
            parsed["logon_type"] = logon_type_m.group(1)
        if event_id == 4624 and parsed.get("logon_type", "") not in ("3", "10"):
            # Only network (3) / RDP (10) logons carry an external source;
            # console and service logons report "-" or the local host.
            ip = None
        if user:
            parsed["user"] = user
        if ip:
            parsed["ip"] = ip
        if process:
            parsed["process"] = process
        result["summary"] = template.format(
            user=user or "unknown", ip=ip or "unknown", process=process or "unknown"
        )[: _LINE_LIMIT]

    result["parsed"] = parsed
    return result


# ── Linux: journald structured entries ──

_JOURNALD_SEVERITY = {
    "0": "critical", "1": "critical", "2": "critical",
    "3": "high",
    "4": "medium",
    "5": "info", "6": "info", "7": "info",
}


def _match_linux_patterns(line: str) -> dict | None:
    """Run the auth/sudo regexes against a message; return parsed fields + action."""
    for pattern, action, extract in _LINUX_PATTERNS:
        m = re.search(pattern, line)
        if not m:
            continue
        parsed = extract(m)
        parsed["action"] = action
        if "ip" in parsed and _lookup_ip(parsed["ip"]) is None:
            parsed["ip"] = "local"
        if parsed.get("ip") == "local":
            del parsed["ip"]
        return parsed
    return None


def parse_journal_entry(raw_message: str, meta: dict | None = None) -> dict:
    """Parse a journald JSON entry whose fields arrive in ``meta``.

    journald gives us well-defined fields (service, process, pid, host,
    PRIORITY, message) instead of free text, so the summary is built from
    them directly — ``[service or process] message[:150]`` — while the
    auth/sudo regexes still run on top of the message to pull out
    user/ip/action for security events. journald PRIORITY (0-7 syslog levels)
    maps to the existing severity system: 0-2 → critical, 3 → high,
    4 → medium, 5-7 → info; the raw value is kept for analysts.
    """
    meta = meta or {}
    message = (raw_message or "").strip()
    service = (meta.get("service") or "").strip()
    process = (meta.get("process") or "").strip()
    priority = str(meta.get("severity") or meta.get("priority") or "").strip()

    parsed = {
        "log_name": "system",
        "provider": service,
        "service": service,
        "severity": _JOURNALD_SEVERITY.get(priority, "info"),
        "priority": priority,
    }
    if process:
        parsed["process"] = process
    if meta.get("pid") not in (None, ""):
        parsed["pid"] = str(meta["pid"])
    if meta.get("host"):
        parsed["host"] = str(meta["host"])
    if meta.get("time"):
        parsed["time"] = str(meta["time"])

    matched = _match_linux_patterns(message)
    source = service or process or "system"
    if matched:
        parsed.update(matched)
        template = _LINUX_SUMMARY_TEMPLATES.get(matched["action"], "")
        if template:
            summary = template.format(**matched)[: _LINE_LIMIT]
        else:
            summary = f"[{source}] {message[:150]}"
    else:
        summary = f"[{source}] {message[:150]}"

    return {"summary": summary, "parsed": parsed}


# ── Linux: common syslog / auth.log patterns ──

_LINUX_PATTERNS = [
    (
        r"Failed password for (\S+) from (\S+) port (\d+)",
        "failed_login",
        lambda m: {"user": m.group(1), "ip": m.group(2), "port": m.group(3)},
    ),
    (
        r"Failed publickey for (\S+) from (\S+) port (\d+)",
        "failed_login",
        lambda m: {"user": m.group(1), "ip": m.group(2), "port": m.group(3)},
    ),
    (
        r"Accepted (password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port (\d+)",
        "successful_login",
        lambda m: {"method": m.group(1), "user": m.group(2), "ip": m.group(3), "port": m.group(4)},
    ),
    (
        r"authentication failure; logname=(\S*) uid=\d+ euid=\d+ tty=\S+ ruser=(\S*) rhost=(\S+)",
        "failed_login",
        lambda m: {"user": m.group(2) or m.group(1) or "unknown", "ip": m.group(3)},
    ),
    (
        r"Invalid user (\S+) from (\S+)",
        "invalid_user",
        lambda m: {"user": m.group(1), "ip": m.group(2)},
    ),
    (
        r"sudo:\s+(\S+)\s*:\s*TTY=.*?\s*COMMAND=(.*)$",
        "sudo_command",
        lambda m: {"user": m.group(1), "cmd": m.group(2).strip()},
    ),
    (
        r"sudo:\s+(\S+)\s*:\s+COMMAND=(.*)$",
        "sudo_command",
        lambda m: {"user": m.group(1), "cmd": m.group(2).strip()},
    ),
    (
        # journald sudo messages carry no "sudo:" prefix — rsyslog adds it.
        r"^(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=\S+\s*;\s*COMMAND=(.*)$",
        "sudo_command",
        lambda m: {"user": m.group(1), "cmd": m.group(2).strip()},
    ),
    (
        r"session opened for user (\S+) by (\S+)",
        "session_open",
        lambda m: {"user": m.group(1), "by": m.group(2)},
    ),
    (
        r"session closed for user (\S+)",
        "session_closed",
        lambda m: {"user": m.group(1)},
    ),
    (
        r"New session (\d+) of user (\S+)\.",
        "session_open",
        lambda m: {"user": m.group(2)},
    ),
    (
        # auditd execve records forwarded by the journal watcher.
        r"^Command executed by (\S+): (.+)$",
        "process_exec",
        lambda m: {"user": m.group(1), "cmd": m.group(2).strip()},
    ),
    (
        r"new user:\s*name=([^,\s]+)",
        "account_added",
        lambda m: {"user": m.group(1)},
    ),
]

_LINUX_SUMMARY_TEMPLATES = {
    "failed_login": "Failed login for {user} from {ip}",
    "successful_login": "Successful login for {user} from {ip} ({method})",
    "invalid_user": "Login attempt with invalid user {user} from {ip}",
    "sudo_command": "Sudo command by {user}: {cmd}",
    "process_exec": "Command executed by {user}: {cmd}",
    "account_added": "User account created: {user}",
    "session_open": "Session opened for {user}",
    "session_closed": "Session closed for {user}",
}


def parse_linux_line(raw_line: str) -> dict:
    """Parse a single syslog/auth.log line into a structured summary.

    Falls back to { summary: first 200 chars } when nothing matches — a raw
    line is never dropped just because it doesn't fit a known shape.
    """
    line = (raw_line or "").strip()
    result = {"summary": line[: _LINE_LIMIT], "parsed": {}}

    parsed = _match_linux_patterns(line)
    if parsed:
        template = _LINUX_SUMMARY_TEMPLATES.get(parsed["action"], "")
        if template:
            result["summary"] = template.format(**parsed)[: _LINE_LIMIT]
        result["parsed"] = parsed

    return result


def detect_log_type(meta: dict | None) -> str:
    """Decide windows vs linux from meta hints; defaults to windows."""
    meta = meta or {}
    log_type = str(meta.get("log_type") or "").lower()
    if log_type in ("windows", "linux"):
        return log_type
    if meta.get("service") is not None or meta.get("cursor") is not None:
        # journald watcher meta — never a Windows event.
        return "linux"
    log_name = str(meta.get("log_name") or "").lower()
    provider = str(meta.get("provider") or "").lower()
    if provider.startswith("microsoft-windows"):
        return "windows"
    if log_name in ("security", "application", "powershell"):
        return "windows"
    if log_name in ("syslog", "auth", "authpriv", "systemd", "journald", "audit"):
        return "linux"
    if log_name == "system":
        # Windows "System" log entries carry real event IDs; the Linux
        # journald agent sends event_id "0" for everything.
        event_id = str(meta.get("event_id") or "")
        if event_id.isdigit() and int(event_id) > 0:
            return "windows"
        return "linux"
    return "windows"


def parse_log(raw_text: str, meta: dict | None = None) -> dict:
    """Dispatch to the right parser based on meta.log_type / heuristics."""
    meta = meta or {}
    if meta.get("service") is not None or meta.get("cursor") is not None:
        return parse_journal_entry(raw_text, meta)
    if detect_log_type(meta) == "linux":
        return parse_linux_line(raw_text)
    return parse_windows_event(raw_text, meta)
