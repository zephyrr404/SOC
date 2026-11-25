"""Unit & setup-script verification tests for the SOC platform."""

import importlib
import json
import os
import re
import subprocess
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def _ensure_stub_modules():
    """Provide lightweight stubs for optional/infra packages absent locally."""
    if "pymongo" not in sys.modules:
        pymongo = types.ModuleType("pymongo")

        class _DummyCol:
            def __getattr__(self, _):
                return lambda *a, **kw: None

        class _DummyDB:
            def __getitem__(self, _):
                return _DummyCol()

            def __getattr__(self, _):
                return _DummyCol()

        class _DummyClient:
            def __init__(self, *a, **kw):
                pass

            def __getitem__(self, _):
                return _DummyDB()

        pymongo.MongoClient = _DummyClient
        sys.modules["pymongo"] = pymongo


_ensure_stub_modules()

from app.services import event_filter, log_parser, mitre, reachable, rules, severity, threat_feed
from app.services.incident_metrics import linked_entities, mitigation_suggestions, parse_snapshot


# ---------------------------------------------------------------------------
# Website attack-detection rules
# ---------------------------------------------------------------------------

def test_rules_detect_real_attacks_and_avoid_benign_false_positives():
    sqli = rules.classify_event({"comment": "' OR '1'='1"})
    assert any(m["category"] == "sqli" for m in sqli)

    xss = rules.classify_event({"bio": "<script>alert(1)</script>"})
    assert any(m["category"] == "xss" for m in xss)

    scanner = rules.classify_event({"ua": "sqlmap"})
    assert any(m["rule"] == "scanner_dork" for m in scanner)

    # Benign SPA navigation & form submit on localhost must NOT flag SSRF
    benign_nav = rules.classify_event({
        "entry_page": True,
        "navigation": True,
        "from": "http://localhost:5173/workspace",
        "to": "http://localhost:5173/overview",
    })
    assert not any(m["category"] == "ssrf" for m in benign_nav)

    benign_form = rules.classify_event({
        "form": {"id": "login", "action": "http://localhost:5173/login"},
        "fields": [{"name": "email", "value": "user@example.com"}],
    })
    assert not any(m["category"] == "ssrf" for m in benign_form)

    # Benign numeric UI/session metadata must NOT flag IDOR
    benign_click = rules.classify_event({"id": "42", "seq": "1", "x": "120", "y": "240"})
    assert not any(m["category"] == "idor" for m in benign_click)


# ---------------------------------------------------------------------------
# Windows & Linux log parser / filter / MITRE consistency
# ---------------------------------------------------------------------------

def test_windows_4625_extracts_target_user_both_multiline_and_flattened():
    multiline = (
        "An account failed to log on.\r\n"
        "Subject:\r\n"
        "\tSecurity ID:\t\tS-1-5-18\r\n"
        "\tAccount Name:\t\tSYSTEM\r\n"
        "Account For Which Logon Failed:\r\n"
        "\tSecurity ID:\t\tNULL SID\r\n"
        "\tAccount Name:\t\talice\r\n"
        "Network Information:\r\n"
        "\tSource Network Address:\t203.0.113.10\r\n"
    )
    flattened = multiline.replace("\r\n", " ")

    for msg in (multiline, flattened):
        res = log_parser.parse_windows_event(msg, {"log_name": "Security", "event_id": "4625"})
        assert res["parsed"]["user"] == "alice"
        assert res["parsed"]["ip"] == "203.0.113.10"
        assert res["parsed"]["action"] == "failed_logon"


def test_linux_useradd_and_execve_parsed_and_promoted():
    added = log_parser.parse_journal_entry(
        "new user: name=backdoor, UID=1005, GID=1005",
        {"service": "useradd", "cursor": "s=1"},
    )
    assert added["parsed"]["action"] == "account_added"
    assert added["parsed"]["user"] == "backdoor"
    assert event_filter.is_relevant_entry({"service": "useradd", "cursor": "s=1"}, added["parsed"])
    assert severity.classify_severity("system", 0, added["parsed"]["action"], added["parsed"]) == "high"
    assert mitre.get_mitre("system", 0, added["parsed"]["action"])["technique"].startswith("T1136")


def test_allowed_windows_events_have_mitre_mappings():
    for log_name, events in event_filter.ALLOWED_WINDOWS_EVENTS.items():
        for eid in events:
            if eid == 4634:
                continue  # benign logoff
            assert mitre.get_mitre(log_name, eid) is not None, f"Missing MITRE mapping for {(log_name, eid)}"


# ---------------------------------------------------------------------------
# Reachable URL helper
# ---------------------------------------------------------------------------

def test_reachable_backend_url_preserves_scheme_slashes(monkeypatch):
    monkeypatch.setattr(reachable, "PUBLIC_BACKEND_URL", "https://soc.example.com/")
    assert reachable.reachable_backend_url() == "https://soc.example.com"


# ---------------------------------------------------------------------------
# Threat feed project-scoped manual IPs
# ---------------------------------------------------------------------------

def test_threat_feed_manual_ips_are_project_scoped():
    threat_feed.add_ip("198.51.100.77", project_id=10)
    try:
        assert threat_feed.is_malicious("198.51.100.77", project_id=10) is True
        assert threat_feed.is_malicious("198.51.100.77", project_id=20) is False
    finally:
        threat_feed.remove_ip("198.51.100.77", project_id=10)


# ---------------------------------------------------------------------------
# Incident metrics
# ---------------------------------------------------------------------------

def test_incident_metrics_extracts_entities():
    ev = {
        "event_snapshot": json.dumps({
            "source": "windows",
            "hostname": "WIN-SRV-01",
            "parsed": {"user": "bob"},
            "enriched": {"ip": "203.0.113.5", "risk_score": 70},
            "mitre": {"tactic": "Credential Access", "technique": "T1110 - Brute Force"},
        })
    }
    snap = parse_snapshot(ev)
    assert snap["hostname"] == "WIN-SRV-01"
    entities = linked_entities([ev])
    assert entities["hosts"] == ["WIN-SRV-01"]
    assert entities["ips"] == ["203.0.113.5"]
    assert entities["users"] == ["bob"]
    assert entities["technique_ids"] == ["T1110"]
    assert mitigation_suggestions([ev])[0]["tactic"] == "Credential Access"


# ---------------------------------------------------------------------------
# Setup scripts (Windows / Linux / Web) validation
# ---------------------------------------------------------------------------

def test_linux_install_sh_syntax_and_no_jq_or_cli_token():
    sh_path = ROOT / "agents" / "install.sh"
    res = subprocess.run(["bash", "-n", str(sh_path)], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr
    text = sh_path.read_text(encoding="utf-8")
    assert "jq" not in text
    assert "--config /etc/soc-agent/config.json" in text
    assert "chmod 600 /etc/soc-agent/config.json" in text


def test_windows_install_ps1_uses_oldest_and_global_timer_helpers():
    ps_text = (ROOT / "agents" / "install.ps1").read_text(encoding="utf-8")
    assert "-Oldest" in ps_text
    assert ps_text.count("-Oldest") >= 2
    assert "function global:Get-SocConfig" in ps_text
    assert "function global:Send-SocBulk" in ps_text
    assert "function global:Save-SocCursors" in ps_text
    assert "function global:Invoke-SocReEnroll" in ps_text


def test_web_usp_js_syntax_and_redaction():
    usp_path = ROOT / "backend" / "app" / "static" / "usp.js"
    res = subprocess.run(["node", "--check", str(usp_path)], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr
    text = usp_path.read_text(encoding="utf-8")
    assert "redactValue" in text
    assert "queue.length >= 500" in text
