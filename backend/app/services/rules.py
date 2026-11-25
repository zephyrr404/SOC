"""Generic rule-based attack detection for website events.

One rule table covering the common web attack classes (SQLi, XSS, IDOR,
LFI/RFI, SSRF, command injection, path traversal, open redirect, NoSQL/LDAP
injection, CRLF/header injection, scanner probes). Every string inside the
already-redacted raw payload is checked against every rule's patterns.

Key-aware design:
  * Fields that describe *navigation/session context* — the page ``url``,
    ``referrer``, ``user_agent``, ``hostname`` and anything under ``page`` —
    are exempt from rules that look for *outbound attack targets* (SSRF,
    open redirect). Otherwise a normal visit to ``http://localhost:5174/...``
    would false-positive as an SSRF loopback.
  * Everything else (form fields, request bodies, comments, custom raw) is
    attacker-controlled input and is scored normally.

Severity → score mapping (kept in one place so the UI badge tier and the
stored score never drift):
  critical 90  command injection, stacked SQL, /etc/passwd, SSRF metadata
  high     80  SQLi boolean/UNION, LFI, SSRF private, XSS script/event
  medium   60  IDOR numeric refs, path traversal, OR/AND probes, NoSQL, CRLF
  low      30  open redirect, scanner noise, admin-path probes

classify_event() returns every match sorted by descending score; max_risk_score()
returns the single highest contribution.
"""

import re
from typing import Iterable

SEVERITY_TO_SCORE = {"critical": 90, "high": 80, "medium": 60, "low": 30}

# Raw keys that describe navigation/session context, never attack input.
_CONTEXT_LEAF_KEYS = {"url", "referrer", "user_agent", "hostname", "page_url", "href", "from", "to"}
# Metadata keys whose bare numeric values should not synthesize key=value IDOR probes.
_BENIGN_KV_KEYS = {"id", "seq", "num", "index", "length", "status", "duration_ms", "timing_ms", "x", "y"}
_SCANNER_HINTS = ("acunetix", "nikto", "nessus", "sqlmap", "dirbuster", "awscan", "fuzz", "xsser")


class Rule:
    __slots__ = ("rule_id", "category", "name", "severity", "patterns", "context_aware")

    def __init__(self, rule_id: str, category: str, name: str, severity: str, patterns,
                 context_aware: bool = False):
        self.rule_id = rule_id
        self.category = category
        self.name = name
        self.severity = severity if severity in SEVERITY_TO_SCORE else "low"
        self.patterns = [p if isinstance(p, re.Pattern) else re.compile(p, re.IGNORECASE) for p in patterns]
        # context_aware=True → excluded from context (navigational) fields.
        self.context_aware = context_aware

    @property
    def score(self) -> int:
        return SEVERITY_TO_SCORE[self.severity]

    def match(self, value: str):
        for p in self.patterns:
            if p.search(value):
                return p
        return None


def _sql_boolean():
    return [
        # ' OR '1'='1   " OR "1"="1   ' OR 1=1   OR 1=1
        r"""['"]\s*(?:or|and)\s*['"]?\s*\d+\s*['"]?\s*=\s*['"]?\s*\d+\s*['"]?""",
        r"""\b(?:or|and)\s+1\s*=\s*1\b""",
        r"""['"]\s*(?:or|and)\s*['"]?\s*\d+\s*['"]?\s*=\s*\d+""",
    ]


RULES: list[Rule] = [
    # ─── SQL injection ───────────────────────────────────────────────────────
    Rule("sqli_union", "sqli", "SQL injection (UNION SELECT)", "high",
         [r"""\bunion\s+(?:all\s+)?select\b"""]),
    Rule("sqli_boolean", "sqli", "SQL injection (boolean bypass)", "high",
         _sql_boolean()),
    Rule("sqli_stacked", "sqli", "SQL injection (stacked statement)", "critical",
         [r""";\s*(?:drop|insert|update|delete|truncate|alter|create)\s+\w+"""]),
    Rule("sqli_comment", "sqli", "SQL injection (comment termination)", "high",
         [r"""['"]\s*(?:or|and)[^'"]{0,30}?--\s*$""",
          r"""\b(?:select|union|or|and)\b[\s\S]{0,80}?--\s*$"""]),
    Rule("sqli_sleep", "sqli", "SQL injection (SLEEP time-based)", "critical",
         [r"""\bsleep\s*\("""]),
    Rule("sqli_waitfor", "sqli", "SQL injection (WAITFOR DELAY)", "critical",
         [r"""\bwaitfor\s+delay\b"""]),
    Rule("sqli_cast", "sqli", "SQL injection (CAST/CONVERT)", "high",
         [r"""\b(?:cast|convert|char|nchar)\s*\(\s*\d+"""]),
    Rule("sqli_mysql", "sqli", "SQL injection (MySQL vector)", "high",
         [r"""\b(?:load_file|benchmark|information_schema)\b"""]),
    Rule("sqli_quote", "sqli", "SQL injection (quote probe)", "medium",
         [r"""\b\d+\s*['"]\s*[+\-]\s*['"]?\s*\d+\b""",
          r"""\\x27\s*(?:or|and)"""]),

    # ─── Cross-site scripting ────────────────────────────────────────────────
    Rule("xss_script", "xss", "XSS (<script> tag)", "high",
         [r"""<script[^>]*>""", r"""%3cscript%3e""", r"""&lt;script&gt;"""]),
    Rule("xss_event", "xss", "XSS (event handler)", "high",
         [r"""\bon(?:load|error|click|mouseover|focus|submit|change|keydown|keyup|hashchange|mouseenter|drag)\s*=\s*['"]?(?:alert|confirm|prompt|document\.|fetch|eval|atob)""",
          r"""<img[^>]*\bonerror\s*=""", r"""<svg[^>]*\bonload\s*="""]),
    Rule("xss_javascript", "xss", "XSS (javascript: URI)", "high",
         [r"""\bjavascript\s*:\s*""", r"""\bjavascript\s*%3a"""]),
    Rule("xss_alert", "xss", "XSS (alert/confirm/prompt)", "medium",
         [r"""\b(?:alert|confirm|prompt)\s*\("""]),
    Rule("xss_eval", "xss", "XSS (eval/Function)", "high",
         [r"""\beval\s*\(""", r"""\bnew\s+Function\s*\(""", r"""\batob\s*\("""]),
    Rule("xss_img", "xss", "XSS (img/src onerror)", "high",
         [r"""<img[^>]*\bonerror\s*=""", r"""<img[^>]*src\s*=\s*['"]?x"""]),
    Rule("xss_dom", "xss", "XSS (DOM sink)", "high",
         [r"""document\.(?:cookie|location|referrer|write|writeln)\s*="""]),
    Rule("xss_encoded", "xss", "XSS (HTML-encoded)", "medium",
         [r"""&#x?0*[0-9a-f]+\s*;""", r"""%3c%2f?script%3e""", r"""\\u003c"""]),
    Rule("xss_danger_prop", "xss", "XSS (dangerous attribute probe)", "low",
         [r"""<iframe""", r"""expression\s*\(""", r"""behavior\s*:"""]),

    # ─── IDOR ────────────────────────────────────────────────────────────────
    Rule("idor_numeric", "idor", "IDOR (numeric object reference)", "medium",
         [r"""\b(?:id|uid|user_id|account(?:s|_id)?|order[:_-]?id|invoice|profile|object_id)\s*["']?\s*[:=]\s*["']?\s*\d+\b"""]),
    Rule("idor_path", "idor", "IDOR (numeric path reference)", "medium",
         [r"""/(?:users?|accounts?|orders?|invoices?|profiles?|items?|documents?|messages?)/\d{1,10}(?:[/?#]|$)"""]),
    Rule("idor_range", "idor", "IDOR (sequential range probe)", "medium",
         [r"""\b\d{1,6}\s*,\s*\d{1,6}\s*,\s*\d{1,6}\b"""]),
    Rule("idor_hidden_idx", "idor", "IDOR (hidden index probe)", "medium",
         [r"""\b(?:index|seq|num)\s*[:=]\s*\d+\b"""]),

    # ─── Local / remote file inclusion ───────────────────────────────────────
    Rule("lfi_traversal", "lfi", "LFI (path traversal)", "high",
         [r"""\.\.(/|\\)""", r"""%2e%2e%2f|%2e%2e%5c|\.\.%2f|\.\.%5c"""]),
    Rule("lfi_etc", "lfi", "LFI (/etc/passwd style)", "critical",
         [r"""/etc/passwd""", r"""c:\\windows\\win\.ini""", r"""/proc/self/environ"""]),
    Rule("lfi_php", "lfi", "LFI (PHP wrappers)", "high",
         [r"""php://(?:filter|input|temp)"""]),
    Rule("rfi_remote", "rfi", "RFI (remote file load)", "high",
         [r"""\b(?:include|require|page|file|path|dir|doc|load|open|src)\s*[:=]\s*(?:https?://|file://)"""]),

    # ─── SSRF ────────────────────────────────────────────────────────────────
    Rule("ssrf_loopback", "ssrf", "SSRF (loopback target)", "critical",
         [r"""https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])"""],
         context_aware=True),
    Rule("ssrf_cloud_meta", "ssrf", "SSRF (cloud metadata)", "critical",
         [r"""169\.254\.169\.254""", r"""metadata\.google\.internal"""],
         context_aware=True),
    Rule("ssrf_private", "ssrf", "SSRF (private network)", "high",
         [r"""https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"""],
         context_aware=True),
    Rule("ssrf_file", "ssrf", "SSRF (file:// scheme)", "high",
         [r"""file:///""", r"""gopher://"""],
         context_aware=True),

    # ─── Command injection ───────────────────────────────────────────────────
    Rule("cmd_exec", "cmd_injection", "Command injection (execution)", "critical",
         [r"""[;&|`$]\s*(?:ls|cat|whoami|id|pwd|nc|ncat|netcat|wget|curl|bash|sh|python|perl|ruby|php|rm|kill|chmod|chown|env|ifconfig|ipconfig|net\s+user|dir|type|mkdir|mv|cp)\b"""]),
    Rule("cmd_subshell", "cmd_injection", "Command injection (subshell)", "critical",
         [r"""\$\([^)]*\)""", r"""`[^`]+`""", r"""\|\s*(?:sh|bash)\b"""]),
    Rule("cmd_pipe_in", "cmd_injection", "Command injection (pipe)", "high",
         [r"""(?:\||;|&&)\s*(?:cat\s+[^;|&]+\s*\||echo\s|nc\s|wget\s|curl\s)"""]),

    # ─── Path traversal (standalone, outside LFI) ────────────────────────────
    Rule("traversal_encoded", "path_traversal", "Path traversal (encoded)", "medium",
         [r"""%2e%2e%2f|%2e%2e%5c|\.\.%2f|\.\.%5c|%252e%252e%252f"""]),
    Rule("traversal_null", "path_traversal", "Path traversal (NULL byte)", "high",
         [r"""%00""", r"""\\x00"""]),

    # ─── Open redirect ───────────────────────────────────────────────────────
    Rule("redirect_open", "open_redirect", "Open redirect", "low",
         [r"""\b(?:url|redirect|next|return|returnurl|dest|destination|target|redirect_uri|goto|out)\s*["']?\s*[:=]\s*["']?\s*(?:https?://|//)"""],
         context_aware=True),

    # ─── NoSQL / LDAP injection ──────────────────────────────────────────────
    Rule("nosql_operator", "nosql_injection", "NoSQL injection ($ne/$gt/$where)", "medium",
         [r"""["']?\$(?:ne|gt|gte|lt|lte|nin|in|exists|where|regex|not)\b"""]),
    Rule("nosql_where", "nosql_injection", "NoSQL injection ($where)", "high",
         [r"""\$\s*where\s*[:=]"""]),
    Rule("ldap_injection", "ldap_injection", "LDAP injection", "medium",
         [r"""\(\s*\)\s*\(\s*\)""", r"""\)\s*\\\s*\("""]),

    # ─── Header / CRLF injection ─────────────────────────────────────────────
    Rule("crlf_header", "header_injection", "CRLF / header injection", "medium",
         [r"""%0d%0a|%0D%0A|\r\n\r\n"""]),

    # ─── Generic / scanner probes ────────────────────────────────────────────
    Rule("scanner_sql_keyword", "scanner", "SQL keyword scanner probe", "medium",
         [r"""\b(?:select\s+from|insert\s+into|union\s+all\s+select|order\s+by)\b"""]),
    Rule("scanner_xss_keyword", "scanner", "XSS keyword scanner probe", "medium",
         [r"""<(?:\/)?(?:script|img|svg|iframe|object|embed|style)(?=\s|>)"""]),
    Rule("scanner_admin", "scanner", "Admin/discovery path probe", "low",
         [r"""/(?:admin|administrator|wp-admin|phpmyadmin|\.git/|\.env|\.htaccess|\.aws)(?:[/?#]|$)"""]),
    Rule("scanner_dork", "scanner", "Scanner dork keyword", "low",
         [r"""(?:acunetix|nikto|nessus|sqlmap|dirbuster|awscan|fuzz|xsser)"""]),
]


def _fast_miss(value: str) -> bool:
    if len(value) < 3:
        return True
    if any(c in value for c in ("'", '"', "<", ">", "/", "\\", ";", "|", "&", "$", "%", "=", ":", "(", ")", "`", ",")):
        return False
    low = value.lower()
    return not any(h in low for h in _SCANNER_HINTS)


def _is_context(path: tuple) -> bool:
    """True when the field describes navigation/session context."""
    if not path:
        return False
    if path == ("form", "action"):
        return True
    return path[0] == "page" or path[-1] in _CONTEXT_LEAF_KEYS


def _iter_strs(value, path=()) -> Iterable[tuple]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _iter_strs(v, path + (str(k),))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _iter_strs(v, path + (str(i),))


def classify_event(payload) -> list[dict]:
    """Run a raw payload through every rule (key-aware).

    Returns a sorted, deduplicated list:
        [{"rule", "category", "name", "severity", "score"}]
    Empty list means nothing matched.
    """
    matches: list[dict] = []
    for path, value in _iter_strs(payload):
        if not isinstance(value, str) or _fast_miss(value):
            continue
        ctx = _is_context(path)
        candidates = [value]
        if path and path[-1].lower() not in _BENIGN_KV_KEYS:
            candidates.append(f"{path[-1]}={value}")
        for candidate in candidates:
            for rule in RULES:
                if rule.context_aware and ctx:
                    continue
                if rule.match(candidate):
                    matches.append({
                        "rule": rule.rule_id,
                        "category": rule.category,
                        "name": rule.name,
                        "severity": rule.severity,
                        "score": rule.score,
                    })

    if not matches:
        return []

    seen = set()
    uniq: list[dict] = []
    for m in matches:
        if m["rule"] not in seen:
            seen.add(m["rule"])
            uniq.append(m)

    uniq.sort(key=lambda m: (-m["score"], m["category"], m["rule"]))
    return uniq


def max_risk_score(payload) -> int:
    matches = classify_event(payload)
    return max((m["score"] for m in matches), default=0)


def attack_label(payload) -> str:
    cats: list[str] = []
    for m in classify_event(payload):
        label = m["category"].replace("_", " ").upper()
        if label not in cats:
            cats.append(label)
    return ", ".join(cats)


def scan_event(raw: dict) -> list[dict]:
    """Convenience wrapper for the ingest path."""
    return classify_event(raw)