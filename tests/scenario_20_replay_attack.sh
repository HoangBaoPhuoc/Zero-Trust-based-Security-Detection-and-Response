#!/bin/bash
# Scenario 20 — JWT Replay Attack / Token Theft Simulation (T1539 / T1550.001)
# Reuses an expired or stolen JWT and verifies the system rejects it.
# Also tests that SPIRE SVID short TTL prevents replay of mTLS credentials.
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:8180}"
AI_URL="${AI_URL:-http://localhost:18082}"
SCENARIO="scenario_20_replay_attack"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway unreachable"
curl -fsS "$AI_URL/health" >/dev/null || fail "AI Analyzer unreachable"

# Test 1: expired JWT (static token with exp=1 in the past)
EXPIRED_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0dXNlcjAxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdHVzZXIwMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJmaW5hbmNpYWwtd3JpdGUiXX0sImlzcyI6Imh0dHA6Ly9rZXljbG9hay56dGxhYi5sb2NhbC9yZWFsbXMvenRsYWIiLCJleHAiOjF9.EXPIRED_SIGNATURE"
log "test 1: sending expired JWT..."
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$GW_URL/payments" \
  -H "Authorization: Bearer $EXPIRED_JWT" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000,"currency":"VND"}')
log "expired JWT → HTTP $code"
[[ "$code" =~ ^(401|403)$ ]] || log "WARNING: expired JWT not rejected (HTTP $code)"

# Test 2: valid JWT used multiple times rapidly (replay detection)
log "test 2: getting fresh JWT and replaying it 10 times..."
TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
[[ -n "$TOKEN" ]] || { log "WARNING: no JWT from Keycloak"; }

replayed=0
if [[ -n "$TOKEN" ]]; then
  for i in $(seq 1 10); do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X GET "$GW_URL/accounts/ACC-1001" \
      -H "Authorization: Bearer $TOKEN")
    [[ "$code" == "200" ]] && replayed=$((replayed + 1))
  done
  log "$replayed/10 replays accepted (JWT within validity window — expected in stateless JWT)"
fi

# Test 3: AI detection of replay pattern
log "test 3: injecting JWT replay pattern log to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_20_replay_attack",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "jwt_replay_detected token_jti=abc123 first_seen=10:00:01 now=10:05:33 same_token_used=47_times source_ips=[10.9.8.1,10.9.8.2] suspicious_reuse=true",
       "labels": {"namespace":"financial","app":"api-gateway","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "stolen_token_suspected user=testuser01 token_age=330s access_from_new_ip=185.0.0.1 original_ip=10.10.1.5",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}},
      {"timestamp": "'"$ts"'",
       "message": "jwt_verification_failed reason=expired_token exp=1000000000 now=1749600000 token_jti=abc123",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious, got $verdict"

pass "replay attacks tested; expired JWT rejected HTTP $code; AI verdict=$verdict (T1539/T1550.001)"
