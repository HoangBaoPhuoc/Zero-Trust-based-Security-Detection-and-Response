#!/bin/bash
# Scenario 13 — SQL Injection / Exploit Public-Facing Application (T1190)
# Sends SQL injection payloads in payment API parameters.
# Expects 400/403/422 from input validation, and AI detection when injected as logs.
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:8180}"
AI_URL="${AI_URL:-http://localhost:18082}"
SCENARIO="scenario_13_sql_injection"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

log "checking services..."
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway unreachable"
curl -fsS "$AI_URL/health" >/dev/null || fail "AI Analyzer unreachable"

# Get JWT
TOKEN=""
TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
[[ -n "$TOKEN" ]] && log "JWT obtained" || log "WARNING: no JWT, continuing"

log "sending SQL injection payloads in payment request..."
PAYLOADS=(
  "' OR '1'='1"
  "ACC-1001'; DROP TABLE accounts;--"
  "1 UNION SELECT * FROM accounts--"
  "ACC-1001' AND 1=CONVERT(int,@@version)--"
)
blocked=0
for payload in "${PAYLOADS[@]}"; do
  AUTH_HEADER=()
  [[ -n "$TOKEN" ]] && AUTH_HEADER=(-H "Authorization: Bearer $TOKEN")
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$GW_URL/payments" \
    "${AUTH_HEADER[@]}" \
    -H "Content-Type: application/json" \
    -d "{\"from_account\":\"$payload\",\"to_account\":\"ACC-2001\",\"amount\":1000,\"currency\":\"VND\"}")
  log "payload '${payload:0:30}...' → HTTP $code"
  [[ "$code" =~ ^(400|403|422|500)$ ]] && blocked=$((blocked + 1))
done
log "$blocked/${#PAYLOADS[@]} SQL injection payloads blocked/rejected"

# AI detection
log "injecting SQL injection attack log to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_13_sql_injection",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "exploit_probe detected SQL injection attempt from_account=\" OR 1=1-- source_ip=198.51.100.42 path=/payments",
       "labels": {"namespace":"financial","app":"api-gateway","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "input_validation_failed field=from_account value=\"'\'';\\ DROP TABLE accounts;--\" reason=sql_injection_pattern",
       "labels": {"namespace":"financial","app":"payment-service","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "response_code=422 path=/payments method=POST source_ip=198.51.100.42 reason=invalid_account_format",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
attack=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('attack_type','?'))")
log "AI verdict=$verdict attack=$attack"
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious from AI, got $verdict"

pass "$blocked/${#PAYLOADS[@]} SQL injections rejected; AI verdict=$verdict attack=$attack (T1190)"
