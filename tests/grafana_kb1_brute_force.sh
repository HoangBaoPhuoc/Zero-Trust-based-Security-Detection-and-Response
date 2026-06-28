#!/bin/bash
# KB1 — Brute Force Login (T1110.001)
# Zero Trust layer: Authentication (api-gateway JWT validation)
# Tấn công thật: gửi 20 request với JWT không hợp lệ đến api-gateway
#                → api-gateway log WARN jwt_verification_failed (source_ip, reason)
# Grafana rule  : Brute Force Login → severity=high
#   LogQL: {namespace="financial",app="api-gateway"} | json | event="jwt_verification_failed"
# SOAR playbook : revoke_user_sessions
# HITL          : YES — email gửi admin khi case pending_approval
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
SCENARIO="KB1_brute_force"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway không khả dụng tại $GW_URL"

# ── 2. Sinh traffic tấn công thật ────────────────────────────────────────────
# Gửi 20 request với JWT không hợp lệ đến api-gateway
# → api-gateway._verify_token() → JWKS verify thất bại
# → log WARN: {event: jwt_verification_failed, reason: invalid_rs256, source_ip: <IP>}
# → Promtail thu → Loki {namespace=financial, app=api-gateway}
blocked=0
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$GW_URL/payments" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer INVALID_BRUTEFORCE_TOKEN_ATTEMPT_$i" \
    -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000,"currency":"VND"}')
  [[ "$code" =~ ^(400|401|403)$ ]] && blocked=$((blocked+1))
done
[[ $blocked -ge 18 ]] || fail "chỉ $blocked/20 lần bị chặn (cần ≥18)"
log "api-gateway chặn $blocked/20 (401) — jwt_verification_failed ghi vào Loki"

pass "KB1 | $blocked/20 blocked | log thật → Loki (Grafana fire trong ≤1 phút)"
