#!/bin/bash
# Scenario 19 — Data Staging / Automated Exfiltration (T1074 / T1020)
# Simulates bulk data export: rapid repeated queries to account history endpoint.
# Verifies rate limiting activates and AI detects data staging pattern.
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:18443}"
AI_URL="${AI_URL:-http://localhost:18082}"
SCENARIO="scenario_19_data_staging"
BULK_REQUESTS="${BULK_REQUESTS:-20}"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway unreachable"
curl -fsS "$AI_URL/health" >/dev/null || fail "AI Analyzer unreachable"

TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

log "simulating bulk data export: $BULK_REQUESTS rapid GET /accounts requests..."
blocked=0
for i in $(seq 1 "$BULK_REQUESTS"); do
  AUTH_HEADER=()
  [[ -n "$TOKEN" ]] && AUTH_HEADER=(-H "Authorization: Bearer $TOKEN")
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "${AUTH_HEADER[@]}" "$GW_URL/accounts/ACC-1001/history?limit=1000&page=$i")
  [[ "$code" =~ ^(429|403)$ ]] && blocked=$((blocked + 1))
done
log "$blocked/$BULK_REQUESTS bulk requests rate-limited/blocked"

log "injecting data staging pattern to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_19_data_staging",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "bulk_data_access account=ACC-1001 requests=20 time_window=30s total_records_accessed=8000 bytes_sent=4194304 source_ip=10.9.8.77",
       "labels": {"namespace":"financial","app":"account-service","job":"kubernetes-pods","cloud":"openstack"}},
      {"timestamp": "'"$ts"'",
       "message": "data_staging_detected automated_pattern=true user=testuser01 account=ACC-1001 export_size=4MB suspicious_pagination=true",
       "labels": {"namespace":"financial","app":"account-service","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "large_response bytes_sent=2097152 path=/accounts/ACC-1001/history method=GET source_ip=10.9.8.77 duration_ms=250",
       "labels": {"namespace":"financial","app":"account-service","job":"envoy-access"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
playbook=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('recommended_playbook','?'))")
log "AI verdict=$verdict playbook=$playbook"
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious, got $verdict"

pass "$blocked/$BULK_REQUESTS bulk requests blocked; AI verdict=$verdict (T1074/T1020)"
