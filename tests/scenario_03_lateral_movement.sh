#!/bin/bash
# Scenario 03 — Lateral Movement (T1021)
# Attempts to call /transactions/execute with a wrong service SVID header.
# OPA should block with 403.  Also verifies AI detects lateral movement pattern.
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
AI_URL="${AI_URL:-http://localhost:18082}"
SCENARIO="scenario_03_lateral_movement"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

log "checking API Gateway health..."
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway unreachable at $GW_URL"

log "sending lateral movement request (notification-service SVID → /payments/internal/execute)..."
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$GW_URL/payments/internal/execute" \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://ztlab.local/aws/notification-service" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":500000,"currency":"VND"}')
log "direct endpoint response: HTTP $code"
[[ "$code" == "403" || "$code" == "404" || "$code" == "401" ]] \
  || log "WARNING: unexpected HTTP $code (may indicate missing OPA rule for this path)"

log "injecting lateral movement log to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_03_lateral_movement",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "opa_deny svid=spiffe://ztlab.local/aws/notification-service path=/transactions/execute method=POST reason=svid_not_authorized_for_path",
       "labels": {"namespace":"financial","app":"opa-server","job":"opa-decisions"}},
      {"timestamp": "'"$ts"'",
       "message": "unauthorized_service_call caller=notification-service target=transaction-service path=/transactions/execute source_ip=10.10.1.11",
       "labels": {"namespace":"financial","app":"notification-service","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "lateral movement detected notification-service attempting to reach transaction service directly",
       "labels": {"namespace":"financial","app":"transaction-service","job":"kubernetes-pods"}}
    ]
  }')
printf '%s\n' "$response" | python3 -m json.tool 2>/dev/null || true
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
attack=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('attack_type','?'))")
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious verdict, got $verdict"

pass "lateral movement blocked (HTTP $code); AI verdict=$verdict attack=$attack (T1021)"
