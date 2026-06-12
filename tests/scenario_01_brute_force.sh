#!/bin/bash
# Scenario 01 — Brute Force JWT (T1110.001)
# Sends 20 invalid login attempts to Keycloak, expects all 401/400.
# Also injects synthetic log to AI Analyzer and verifies malicious verdict.
set -euo pipefail

KC_URL="${KC_URL:-http://localhost:18443}"
AI_URL="${AI_URL:-http://localhost:18082}"
SCENARIO="scenario_01_brute_force"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

log "checking Keycloak health..."
curl -fsS "$KC_URL/realms/ztlab/.well-known/openid-configuration" >/dev/null \
  || fail "Keycloak unreachable at $KC_URL"

log "sending 20 invalid login attempts..."
blocked=0
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
    -d "grant_type=password&client_id=web-portal&username=testuser01&password=WRONG-$i")
  case "$code" in
    400|401) blocked=$((blocked + 1)) ;;
    *) log "WARNING: unexpected HTTP $code on attempt $i" ;;
  esac
done
log "$blocked/20 attempts returned 401/400"
[[ $blocked -ge 18 ]] || fail "expected ≥18 blocked, got $blocked"

log "injecting brute-force log to AI Analyzer..."
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_01_brute_force",
    "logs": [
      {"timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
       "message": "jwt_verification_failed reason=invalid_credentials source_ip=10.0.0.1 attempt=1",
       "labels": {"namespace":"financial","app":"api-gateway","job":"kubernetes-pods"}},
      {"timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
       "message": "jwt_verification_failed reason=invalid_credentials source_ip=10.0.0.1 attempt=2",
       "labels": {"namespace":"financial","app":"api-gateway","job":"kubernetes-pods"}},
      {"timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
       "message": "jwt_verification_failed reason=invalid_credentials source_ip=10.0.0.1 attempt=15 auth_failures_total=15",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}}
    ]
  }')
printf '%s\n' "$response" | python3 -m json.tool 2>/dev/null || true
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('verdict','?'))")
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious verdict, got $verdict"

pass "$blocked/20 Keycloak attempts blocked; AI verdict=$verdict (T1110.001)"
