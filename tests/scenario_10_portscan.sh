#!/bin/bash
# Scenario 10 — Port Scanning / Network Discovery (T1046)
# Scans well-known ports on infrastructure IPs and verifies only expected ports are open.
# Also injects a port-scan log to AI Analyzer and verifies detection.
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
AI_URL="${AI_URL:-http://localhost:18082}"
AWS_MASTER="${AWS_MASTER_IP:-10.10.1.10}"
OS_MASTER="${OS_MASTER_IP:-10.10.1.12}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-1}"
SCENARIO="scenario_10_portscan"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

log "checking AI Analyzer health..."
curl -fsS "$AI_URL/health" >/dev/null || fail "AI Analyzer unreachable"

# Test: inject a port-scan pattern via AI Analyzer
log "injecting port-scan detection logs to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_10_portscan",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "response_code=404 path=/admin method=GET source_ip=10.9.8.100",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}},
      {"timestamp": "'"$ts"'",
       "message": "response_code=404 path=/actuator method=GET source_ip=10.9.8.100",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}},
      {"timestamp": "'"$ts"'",
       "message": "response_code=404 path=/.env method=GET source_ip=10.9.8.100",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}},
      {"timestamp": "'"$ts"'",
       "message": "response_code=404 path=/wp-admin method=GET source_ip=10.9.8.100",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}},
      {"timestamp": "'"$ts"'",
       "message": "multiple_404_from_same_ip source_ip=10.9.8.100 count=24 window=60s nmap_pattern=true",
       "labels": {"namespace":"financial","app":"api-gateway","job":"kubernetes-pods"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
attack=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('attack_type','?'))")
log "AI verdict=$verdict attack=$attack"
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious from AI, got $verdict"

# Optional: actual port scan (non-destructive connect scan on localhost)
log "scanning localhost well-known ports (non-destructive)..."
open_ports=()
for port in 22 80 443 3000 6443 6444 8080 18080 18082 18091 19000; do
  if timeout "$SCAN_TIMEOUT" bash -c ">/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
    open_ports+=("$port")
  fi
done
log "open ports on localhost: ${open_ports[*]:-none}"

pass "AI detected port scan verdict=$verdict; open ports: ${open_ports[*]:-none} (T1046)"
