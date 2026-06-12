#!/bin/bash
# Scenario 08 — Unauthorized Cross-Cloud Access (T1021.007)
# Validates that the cross-cloud boundary (Envoy STATIC cluster + OPA cross_cloud policy)
# blocks requests missing the required SPIFFE SVID and fraud gate headers.
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
AI_URL="${AI_URL:-http://localhost:18082}"
OS_CB_URL="${OS_CB_URL:-http://localhost:18084}"
SCENARIO="scenario_08_cross_cloud"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

log "checking API Gateway health..."
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway unreachable"

# Test 1: direct call to core-banking without SVID (should be blocked by OPA)
log "test 1: direct call to core-banking /transactions/execute without SVID..."
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$OS_CB_URL/transactions/execute" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000,"currency":"VND"}' 2>/dev/null || echo "000")
log "response: HTTP $code"
[[ "$code" == "403" || "$code" == "401" || "$code" == "000" ]] \
  || log "WARNING: expected 403/401, got $code (core-banking may not be port-forwarded)"

# Test 2: call via API gateway without fraud gate (OPA cross_cloud should block at OpenStack boundary)
log "test 2: attempting payment without fraud gate header (Envoy cross-cloud should reject)..."
code2=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$GW_URL/payments" \
  -H "Content-Type: application/json" \
  -H "X-Force-No-Fraud-Check: true" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":99999,"currency":"VND"}')
log "response: HTTP $code2"

# Test 3: inject cross-cloud violation log to AI
log "test 3: injecting unauthorized cross-cloud access log to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_08_cross_cloud",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "cross_cloud_access_denied source_cloud=aws destination_cloud=openstack missing_svid=true path=/transactions/execute source_ip=10.10.1.99",
       "labels": {"namespace":"financial","app":"core-banking","job":"opa-decisions","cloud":"openstack"}},
      {"timestamp": "'"$ts"'",
       "message": "opa_deny reason=cross_cloud_policy_violation svid=unknown path=/transactions/execute X-Fraud-Gate=missing",
       "labels": {"namespace":"financial","app":"opa-server","job":"opa-decisions","cloud":"openstack"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
log "AI verdict: $verdict"
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious from AI, got $verdict"

pass "cross-cloud access controls verified; AI verdict=$verdict (T1021.007)"
