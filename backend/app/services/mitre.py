"""MITRE ATT&CK technique mapping.

Maps the platform's allow-listed event surface (the same (log_name, event_id)
and Linux action keys used by ``event_filter`` / ``severity``) to ATT&CK
tactics and techniques. Wired into the agent ingest bridge in agents.py
alongside severity/risk_score, so every new security event carries a
``mitre`` object and the threat-intel page can aggregate tactics without
re-deriving anything.
"""

MITRE_MAP = {
    ("Security", 4625): {"tactic": "Credential Access", "technique": "T1110 - Brute Force"},
    ("Security", 4624): {"tactic": "Initial Access", "technique": "T1078 - Valid Accounts"},
    ("Security", 4648): {"tactic": "Lateral Movement", "technique": "T1550 - Use Alternate Authentication Material"},
    ("Security", 4672): {"tactic": "Privilege Escalation", "technique": "T1078.003 - Valid Accounts: Local Accounts"},
    ("Security", 4688): {"tactic": "Execution", "technique": "T1059 - Command and Scripting Interpreter"},
    ("Security", 4698): {"tactic": "Persistence", "technique": "T1053.005 - Scheduled Task"},
    ("Security", 4720): {"tactic": "Persistence", "technique": "T1136 - Create Account"},
    ("Security", 4722): {"tactic": "Persistence", "technique": "T1098 - Account Manipulation"},
    ("Security", 4724): {"tactic": "Credential Access", "technique": "T1098 - Account Manipulation"},
    ("Security", 4732): {"tactic": "Persistence", "technique": "T1098 - Account Manipulation"},
    ("Security", 4740): {"tactic": "Credential Access", "technique": "T1110 - Brute Force"},
    ("Security", 4756): {"tactic": "Persistence", "technique": "T1098 - Account Manipulation"},
    ("Security", 4768): {"tactic": "Credential Access", "technique": "T1558 - Steal or Forge Kerberos Tickets"},
    ("Security", 4769): {"tactic": "Credential Access", "technique": "T1558.003 - Kerberoasting"},
    ("Security", 4771): {"tactic": "Credential Access", "technique": "T1110 - Brute Force"},
    ("Security", 4776): {"tactic": "Credential Access", "technique": "T1110 - Brute Force"},
    ("Security", 1102): {"tactic": "Defense Evasion", "technique": "T1070.001 - Clear Windows Event Logs"},
    ("System", 7045): {"tactic": "Persistence", "technique": "T1543.003 - Create or Modify System Process"},
    ("System", 104): {"tactic": "Defense Evasion", "technique": "T1070.001 - Clear Windows Event Logs"},
}

LINUX_MITRE_MAP = {
    "failed_login": {"tactic": "Credential Access", "technique": "T1110 - Brute Force"},
    "sudo_command": {"tactic": "Privilege Escalation", "technique": "T1548.003 - Sudo and Sudo Caching"},
    "account_added": {"tactic": "Persistence", "technique": "T1136 - Create Account"},
}


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_mitre(log_name: str, event_id, action: str | None = None) -> dict | None:
    """ATT&CK mapping for a Windows (log, event_id) pair or a Linux action.

    Returns {"tactic": ..., "technique": ...} or None when unmapped. The
    log_name normalization mirrors event_filter so both systems agree.
    """
    name = (log_name or "").strip()
    if name not in MITRE_MAP:
        title = name.title()
        if title in MITRE_MAP:
            name = title
    if name:
        eid = _to_int(event_id)
        if eid is not None and (name, eid) in MITRE_MAP:
            return dict(MITRE_MAP[(name, eid)])
    if action:
        hit = LINUX_MITRE_MAP.get(action)
        if hit:
            return dict(hit)
    return None