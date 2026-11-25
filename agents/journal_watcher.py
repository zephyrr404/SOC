#!/usr/bin/env python3
"""journald → SOC agent log watcher.

Reads the systemd journal as structured JSON (journalctl -o json -f), maps
each entry to the field set the SOC backend understands (time, host, process,
pid, service, severity/PRIORITY, message) and flushes buffered entries in
~1s batches to POST /agents/logs/bulk.

Reliability contract (mirrors the Windows agent):
- a cursor file holds the __CURSOR of the last entry that was successfully
  acknowledged by the backend; on restart, journalctl resumes from it with
  --after-cursor, so no entry is sent twice
- the cursor is persisted only after a successful flush; on network errors
  the batch is re-queued at the front of the buffer and retried
- journalctl itself is the persistent feed (no poll loop); if the process
  dies, systemd restarts this unit and journalctl resumes from the cursor
"""

import json
import os
import re
import subprocess
import sys
import threading
import time

import requests

CONFIG_FILE = "/etc/soc-agent/config.json"
CURSOR_FILE = "/etc/soc-agent/journal_cursor"
FLUSH_INTERVAL = 1.0
HEARTBEAT_INTERVAL = 30.0

_stop = threading.Event()
_buffer = []
_lock = threading.Lock()
_token_lock = threading.Lock()
_runtime_cfg = {"api_base": "", "agent_token": "", "config_path": CONFIG_FILE}


def load_cursor():
    """Return the last acknowledged journald __CURSOR, or None."""
    try:
        with open(CURSOR_FILE, "r", encoding="utf-8") as f:
            cursor = f.read().strip()
        return cursor or None
    except OSError:
        return None


def save_cursor(cursor):
    """Persist the acknowledged cursor so restarts resume without duplicates."""
    try:
        parent = os.path.dirname(CURSOR_FILE)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(CURSOR_FILE, "w", encoding="utf-8") as f:
            f.write(cursor + "\n")
    except OSError as exc:
        print(f"[journal_watcher] failed to persist cursor: {exc}", file=sys.stderr)


def _get_token():
    with _token_lock:
        return _runtime_cfg.get("agent_token", "")


def _re_enroll(api_base):
    """Attempt to re-enroll using config.json when the agent token expires."""
    cfg_path = _runtime_cfg.get("config_path") or CONFIG_FILE
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return None
    api_key = cfg.get("api_key")
    if not api_key:
        return None
    body = {
        "api_key": api_key,
        "hostname": cfg.get("hostname") or os.uname().nodename,
        "os_type": cfg.get("os_type") or "Linux",
        "ip_address": "unknown",
        "fingerprint_seed": cfg.get("fingerprint_seed") or "unknown",
    }
    try:
        resp = requests.post(f"{api_base}/agents/enroll", json=body, timeout=10)
        resp.raise_for_status()
        new_token = resp.json().get("agent_token")
        if new_token:
            with _token_lock:
                _runtime_cfg["agent_token"] = new_token
            cfg["agent_token"] = new_token
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            return new_token
    except requests.RequestException as exc:
        print(f"[journal_watcher] re-enroll failed: {exc}", file=sys.stderr)
    return None


def map_entry(obj):
    """Map a journald JSON object to the SOC meta field set."""
    return {
        "time": obj.get("__REALTIME_TIMESTAMP") or obj.get("SYSLOG_TIMESTAMP") or "",
        "host": obj.get("_HOSTNAME") or "",
        "process": obj.get("_COMM") or "",
        "pid": obj.get("_PID") or "",
        "service": obj.get("SYSLOG_IDENTIFIER") or "",
        "severity": obj.get("PRIORITY") or "",
        "message": obj.get("MESSAGE") or "",
        "cursor": obj.get("__CURSOR") or "",
    }


def stream_journal(meta_base):
    """Follow the journal from the persisted cursor, appending to the buffer."""
    while not _stop.is_set():
        cursor = load_cursor()
        cmd = ["journalctl", "-o", "json", "-f", "--no-pager"]
        if cursor:
            cmd.append("--after-cursor=" + cursor)
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            print(f"[journal_watcher] cannot start journalctl: {exc}", file=sys.stderr)
            time.sleep(2)
            continue

        while not _stop.is_set():
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                # Non-JSON noise on the stream — skip, never abort the feed.
                continue
            entry = map_entry(obj)
            if not entry["cursor"] or not entry["message"]:
                continue
            with _lock:
                _buffer.append(
                    {
                        "level": "info",
                        "stage": "event_log",
                        "message": entry["message"],
                        "meta": {**meta_base, **entry},
                    }
                )

        try:
            proc.terminate()
        except OSError:
            pass

        if not _stop.is_set():
            time.sleep(1)


def flush_loop(bulk_url, api_base):
    """Flush buffered entries every ~1s; persist the cursor only on success."""
    while not _stop.is_set():
        with _lock:
            batch = _buffer[:]
            del _buffer[:]
        if batch:
            token = _get_token()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            try:
                resp = requests.post(bulk_url, json={"entries": batch}, headers=headers, timeout=10)
                if resp.status_code == 401:
                    new_tok = _re_enroll(api_base)
                    if new_tok:
                        headers["Authorization"] = f"Bearer {new_tok}"
                        resp = requests.post(bulk_url, json={"entries": batch}, headers=headers, timeout=10)
                resp.raise_for_status()
                last_cursor = batch[-1]["meta"].get("cursor") or ""
                if last_cursor:
                    save_cursor(last_cursor)
            except requests.RequestException as exc:
                with _lock:
                    _buffer[:0] = batch
                print(
                    f"[journal_watcher] flush failed ({exc}); "
                    f"{len(batch)} entries re-queued",
                    file=sys.stderr,
                )
        _stop.wait(FLUSH_INTERVAL)


def heartbeat_loop(bulk_url, api_base):
    """Keep the agent's last_seen_at fresh while the journal feed is silent."""
    while not _stop.is_set():
        token = _get_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        try:
            resp = requests.post(
                bulk_url,
                json={
                    "entries": [
                        {
                            "level": "info",
                            "stage": "heartbeat",
                            "message": "Agent heartbeat",
                            "meta": {"log_name": "system", "log_type": "linux"},
                        }
                    ]
                },
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 401:
                _re_enroll(api_base)
        except requests.RequestException as exc:
            print(f"[journal_watcher] heartbeat failed: {exc}", file=sys.stderr)
        _stop.wait(HEARTBEAT_INTERVAL)


_AUDIT_RECORD_RE = re.compile(r'^type=(\w+) msg=audit\((\d+(?:\.\d+)?):(\d+)\): (.*)$')
_AUDIT_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def _audit_kv(text):
    out = {}
    for key, quoted, plain in _AUDIT_KV_RE.findall(text):
        out[key] = quoted if quoted else plain
    return out


def _collect_argv(kv):
    args = []
    for i in range(16):
        v = kv.get(f"a{i}")
        if v is None or v == "NULL" or v.startswith("0x"):
            break
        args.append(v)
    return args


def _load_uid_names(path="/etc/passwd"):
    names = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[2].isdigit():
                    names[parts[2]] = parts[0]
    except OSError:
        pass
    return names


def audit_stream_loop(meta_base):
    """Tail auditd's execve records — every command executed, with the real
    (audit) user who ran it. auditd writes each execve as a set of correlated
    records sharing one msg id: SYSCALL (exe/comm/auid) → EXECVE (argv chunks)
    → ... → PROCTITLE. Entries with auid=-1 (system daemons, cron, kernel
    spawns) carry no user session and are skipped. The file is read from its
    current end on start, so a service restart never replays old records.
    """
    path = "/var/log/audit/audit.log"
    if not os.path.exists(path):
        print(
            "[journal_watcher] auditd log not found; process-exec auditing disabled",
            file=sys.stderr,
        )
        return
    uid_names = _load_uid_names()
    pending = {}

    def handle(line):
        m = _AUDIT_RECORD_RE.match(line)
        if not m:
            return
        rec_type, _ts, rec_id, rest = m.groups()
        kv = _audit_kv(rest)
        if rec_type == "SYSCALL" and kv.get("key") == "soc_exec" and kv.get("auid", "-1") != "-1":
            pending[rec_id] = {
                "auid": kv.get("auid"),
                "comm": kv.get("comm", ""),
                "exe": kv.get("exe", ""),
                "pid": kv.get("pid", ""),
                "argv": [],
                "created": time.time(),
            }
            return
        if rec_type == "EXECVE" and rec_id in pending:
            pending[rec_id]["argv"].extend(_collect_argv(kv))
            return
        if rec_type == "PROCTITLE" and rec_id in pending:
            emit(pending.pop(rec_id))

    def emit(rec):
        argv = [a for a in rec["argv"] if a and a != "NULL"]
        cmd = " ".join(argv) or rec["exe"] or rec["comm"]
        if rec["auid"] not in uid_names:
            uid_names.update(_load_uid_names())
        name = uid_names.get(rec["auid"], rec["auid"])
        with _lock:
            _buffer.append(
                {
                    "level": "info",
                    "stage": "execve",
                    "message": f"Command executed by {name}: {cmd}",
                    "meta": {
                        **meta_base,
                        "process": rec["comm"],
                        "pid": rec["pid"],
                        "user": name,
                        "uid": rec["auid"],
                        "exec": rec["exe"],
                        "cmd": cmd,
                    },
                }
            )

    try:
        f = open(path, "r", encoding="utf-8", errors="replace")
        f.seek(0, 2)
    except OSError as exc:
        print(f"[journal_watcher] cannot open audit log: {exc}", file=sys.stderr)
        return

    while not _stop.is_set():
        for rid in [k for k, r in pending.items() if time.time() - r["created"] > 5]:
            emit(pending.pop(rid))
        try:
            fstat_ino = os.fstat(f.fileno()).st_ino
            stat_ino = os.stat(path).st_ino
            if fstat_ino != stat_ino:
                f.close()
                f = open(path, "r", encoding="utf-8", errors="replace")
                f.seek(0, 2)
        except OSError:
            pass
        line = f.readline()
        if not line:
            _stop.wait(0.2)
            continue
        handle(line.strip())

    try:
        f.close()
    except OSError:
        pass


def main():
    api_base = ""
    agent_token = ""
    config_path = CONFIG_FILE
    if len(sys.argv) == 3 and sys.argv[1] == "--config":
        config_path = sys.argv[2]
    elif len(sys.argv) == 3:
        api_base = sys.argv[1].rstrip("/")
        agent_token = sys.argv[2]
    elif len(sys.argv) != 1:
        print(f"usage: {sys.argv[0]} [--config <path> | <api_base> <agent_token>]", file=sys.stderr)
        return 1

    if not api_base or not agent_token:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            api_base = str(cfg.get("api_base") or "").rstrip("/")
            agent_token = str(cfg.get("agent_token") or "")
        except (OSError, ValueError) as exc:
            print(f"[journal_watcher] failed to load config {config_path}: {exc}", file=sys.stderr)
            return 1

    if not api_base or not agent_token:
        print("[journal_watcher] api_base and agent_token are required", file=sys.stderr)
        return 1

    _runtime_cfg["api_base"] = api_base
    _runtime_cfg["agent_token"] = agent_token
    _runtime_cfg["config_path"] = config_path

    bulk_url = f"{api_base}/agents/logs/bulk"
    meta_base = {"log_name": "system", "log_type": "linux"}

    threads = [
        threading.Thread(target=stream_journal, args=(meta_base,), daemon=True),
        threading.Thread(target=flush_loop, args=(bulk_url, api_base), daemon=True),
        threading.Thread(target=heartbeat_loop, args=(bulk_url, api_base), daemon=True),
        threading.Thread(target=audit_stream_loop, args=(meta_base,), daemon=True),
    ]
    for thread in threads:
        thread.start()

    try:
        _stop.wait()
    except KeyboardInterrupt:
        _stop.set()
    for thread in threads:
        thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
