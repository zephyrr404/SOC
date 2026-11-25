#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: install.sh must run as root (sudo)"
    exit 1
fi

API_KEY=""
API_BASE="http://localhost:8000"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-key) API_KEY="$2"; shift 2 ;;
        --api-base) API_BASE="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$API_KEY" ]]; then
    echo "Error: --api-key is required"
    exit 1
fi
API_BASE="${API_BASE%/}"

if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is required"
    exit 1
fi

HOSTNAME=$(hostname)
OS=$(grep -m1 PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || uname -s)
IP=$(ip -4 route get 1 2>/dev/null | awk '{
        for (i = 1; i <= NF; i++)
            if ($i == "src") { print $(i + 1); exit }
    }')
if [[ -z "$IP" ]] || [[ "$IP" == "0.0.0.0" ]]; then
    IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
FINGERPRINT=$(cat /etc/machine-id 2>/dev/null || echo "unknown")

ENROLL_BODY=$(python3 -c '
import json, sys
print(json.dumps({
    "api_key": sys.argv[1],
    "hostname": sys.argv[2],
    "os_type": sys.argv[3],
    "ip_address": sys.argv[4],
    "fingerprint_seed": sys.argv[5],
}))
' "$API_KEY" "$HOSTNAME" "$OS" "$IP" "$FINGERPRINT")

ENROLL_RESP=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/agents/enroll" \
  -H "Content-Type: application/json" \
  -d "$ENROLL_BODY")

HTTP_CODE=$(echo "$ENROLL_RESP" | tail -1)
BODY=$(echo "$ENROLL_RESP" | sed '$d')

if [[ "$HTTP_CODE" == "409" ]]; then
    DETAIL=$(python3 -c 'import json, sys; print(json.loads(sys.stdin.read()).get("detail", ""))' <<< "$BODY" 2>/dev/null || echo "$BODY")
    echo "Already enrolled to a different system: $DETAIL"
    exit 1
elif [[ "$HTTP_CODE" == "200" ]]; then
    AGENT_TOKEN=$(python3 -c 'import json, sys; print(json.loads(sys.stdin.read())["agent_token"])' <<< "$BODY")
    AGENT_ID=$(python3 -c 'import json, sys; print(json.loads(sys.stdin.read())["agent_id"])' <<< "$BODY")
else
    echo "Enrollment failed (HTTP $HTTP_CODE): $BODY"
    exit 1
fi

mkdir -p /etc/soc-agent
chmod 700 /etc/soc-agent
mkdir -p /opt/soc-agent

python3 -c '
import json, sys
cfg = {
    "api_key": sys.argv[1],
    "api_base": sys.argv[2],
    "agent_token": sys.argv[3],
    "agent_id": int(sys.argv[4]),
    "hostname": sys.argv[5],
    "os_type": sys.argv[6],
    "fingerprint_seed": sys.argv[7],
    "flush_interval_seconds": 1,
    "heartbeat_interval_seconds": 30,
}
with open("/etc/soc-agent/config.json", "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
' "$API_KEY" "$API_BASE" "$AGENT_TOKEN" "$AGENT_ID" "$HOSTNAME" "$OS" "$FINGERPRINT"
chmod 600 /etc/soc-agent/config.json

# -- Remove the legacy bash agent (heartbeat + journalctl loops) --
systemctl disable --now soc-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/soc-agent.service /etc/soc-agent/agent.sh

# -- Carry the acknowledged cursor across the upgrade so nothing is resent --
if [[ -f /etc/soc-agent/cursor ]] && [[ ! -f /etc/soc-agent/journal_cursor ]]; then
    mv /etc/soc-agent/cursor /etc/soc-agent/journal_cursor
fi

# -- Install the Python journal watcher --
echo "Downloading journal watcher..."
curl -fsSL "$API_BASE/agents/journal_watcher.py" -o /opt/soc-agent/journal_watcher.py
chmod +x /opt/soc-agent/journal_watcher.py

if ! python3 -c "import requests" 2>/dev/null; then
    echo "Installing python requests..."
    python3 -m pip install --break-system-packages requests 2>/dev/null \
        || python3 -m pip install requests
fi

# -- Enable process-execution auditing (auditd) --
# Every command executed by a real user session is recorded as an execve
# audit record; the journal watcher tails /var/log/audit/audit.log for them.
if ! command -v auditctl &> /dev/null; then
    echo "Installing auditd..."
    apt-get install -y auditd 2>/dev/null || yum install -y auditd 2>/dev/null || true
fi
if command -v auditctl &> /dev/null; then
    mkdir -p /etc/audit/rules.d
    cat > /etc/audit/rules.d/soc-exec.rules <<'EOF'
-a always,exit -F arch=b64 -S execve -k soc_exec
-a always,exit -F arch=b32 -S execve -k soc_exec
EOF
    auditctl -R /etc/audit/rules.d/soc-exec.rules 2>/dev/null || true
    systemctl enable auditd 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
fi

# -- Register the journal watcher service --
if command -v systemctl &> /dev/null && systemctl show-environment &> /dev/null; then
    cat > /etc/systemd/system/soc-agent-journal.service <<EOF
[Unit]
Description=SOC Agent Journal Watcher
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/soc-agent/journal_watcher.py --config /etc/soc-agent/config.json
Restart=always
RestartSec=5
SupplementaryGroups=systemd-journal
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload && systemctl enable --now soc-agent-journal.service
else
    echo "systemd not active — starting background watcher with @reboot cron fallback..."
    if command -v crontab &> /dev/null; then
        (crontab -l 2>/dev/null | grep -v '/opt/soc-agent/journal_watcher.py'; echo "@reboot /usr/bin/python3 /opt/soc-agent/journal_watcher.py --config /etc/soc-agent/config.json >/var/log/soc-agent.log 2>&1") | crontab -
    fi
    pkill -f '/opt/soc-agent/journal_watcher.py' 2>/dev/null || true
    nohup /usr/bin/python3 /opt/soc-agent/journal_watcher.py --config /etc/soc-agent/config.json >/var/log/soc-agent.log 2>&1 &
fi

echo "SOC Agent installed successfully on $HOSTNAME"
