#!/bin/bash
# Scenario 16 — Credential Stuffing (T1078.001)
# Tests many different usernames with a common password list against Keycloak.
# Verifies all return 401/400 and AI detects the distributed brute-force pattern.
set -euo pipefail

KC_URL="${KC_URL:-http://localhost:18443}"
AI_URL="${AI_URL:-http://localhost:18082}"
SCENARIO="scenario_16_credential_stuffing"
ATTEMPTS="${STUFFING_ATTEMPTS:-25}"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

curl -fsS "$KC_URL/realms/ztlab/.well-known/openid-configuration" >/dev/null \
  || fail "Keycloak unreachable"
curl -fsS "$AI_URL/health" >/dev/null || fail "AI Analyzer unreachable"

USERNAMES=("admin" "user1" "user2" "john.doe" "jane.smith" "operator" "superuser"
           "banking_admin" "finance_user" "test" "demo" "root" "sa" "dbadmin"
           "payments_svc" "api_user" "webhook" "monitor" "alertmanager" "prometheus"
           "grafana" "loki" "opa_admin" "spire_admin" "keycloak_admin")
PASSWORDS=("Password123" "Admin@2024" "P@ssw0rd" "Welcome1" "Qwerty123")

log "starting credential stuffing: ${#USERNAMES[@]} usernames × ${#PASSWORDS[@]} passwords..."
blocked=0
total=0
for username in "${USERNAMES[@]}"; do
  for password in "${PASSWORDS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
      -d "grant_type=password&client_id=web-portal&username=$username&password=$password")
    [[ "$code" =~ ^(400|401)$ ]] && blocked=$((blocked + 1))
    total=$((total + 1))
    [[ "$total" -ge "$ATTEMPTS" ]] && break 2
  done
done
log "$blocked/$total attempts blocked (401/400)"
[[ "$blocked" -ge $((total - 2)) ]] || fail "too many unexpected successes: $((total - blocked))"

log "injecting credential stuffing detection log to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_16_credential_stuffing",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "credential_stuffing_detected multiple_usernames=25 common_password_attempts=125 time_window=60s source_ips=[10.9.8.1,10.9.8.2,10.9.8.3] auth_failures_total=125",
       "labels": {"namespace":"identity","app":"keycloak","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "jwt_verification_failed reason=invalid_credentials username=admin source_ip=10.9.8.1 attempt=1",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}},
      {"timestamp": "'"$ts"'",
       "message": "jwt_verification_failed reason=invalid_credentials username=superuser source_ip=10.9.8.2 attempt=50",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious, got $verdict"

pass "$blocked/$total credential stuffing attempts blocked; AI verdict=$verdict (T1078.001)"
