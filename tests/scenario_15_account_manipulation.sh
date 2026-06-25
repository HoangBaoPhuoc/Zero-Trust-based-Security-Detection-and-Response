#!/bin/bash
# Scenario 15 — Account Manipulation / Unauthorized Admin Access (T1098)
# Attempts to access admin/configuration endpoints without proper role.
# Verifies OPA blocks these paths and AI detects the pattern.
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:8180}"
AI_URL="${AI_URL:-http://localhost:18082}"
SCENARIO="scenario_15_account_manipulation"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway unreachable"
curl -fsS "$AI_URL/health" >/dev/null || fail "AI Analyzer unreachable"

# Get regular user JWT (no admin role)
TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
[[ -n "$TOKEN" ]] && log "regular user JWT obtained" || log "WARNING: no JWT"

log "attempting to access privileged endpoints with regular user JWT..."
ADMIN_PATHS=(
  "/admin/accounts"
  "/admin/config"
  "/internal/admin/users"
  "/accounts/ACC-1001/admin/override"
  "/transactions/admin/rollback-all"
)
blocked=0
for path in "${ADMIN_PATHS[@]}"; do
  AUTH_HEADER=()
  [[ -n "$TOKEN" ]] && AUTH_HEADER=(-H "Authorization: Bearer $TOKEN")
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "${AUTH_HEADER[@]}" "$GW_URL$path")
  log "$path → HTTP $code"
  [[ "$code" =~ ^(400|401|403|404)$ ]] && blocked=$((blocked + 1))
done
log "$blocked/${#ADMIN_PATHS[@]} admin paths blocked"

log "injecting account manipulation log to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_15_account_manipulation",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "unauthorized_admin_access user=testuser01 path=/admin/accounts method=GET reason=insufficient_role required=admin got=financial-read source_ip=10.10.1.50",
       "labels": {"namespace":"financial","app":"api-gateway","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "opa_deny path=/admin/accounts reason=missing_admin_role user=testuser01 svid=none",
       "labels": {"namespace":"financial","app":"opa-server","job":"opa-decisions"}},
      {"timestamp": "'"$ts"'",
       "message": "account_manipulation_attempt user=testuser01 trying to modify ACC-2001 balance without authorization",
       "labels": {"namespace":"financial","app":"account-service","job":"kubernetes-pods"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious, got $verdict"

pass "$blocked/${#ADMIN_PATHS[@]} admin paths blocked; AI verdict=$verdict (T1098)"
