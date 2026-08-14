#!/bin/bash
# KB2 — Fraud Gate (T1078.004)
# Zero Trust layer: Fraud detection (fraud-detection service + payment-service)
# Tấn công thật: gửi giao dịch amount=500M qua channel=tor qua api-gateway
#                → payment-service gọi fraud-detection
#                → fraud score ≥ 75 (critical_amount + risky_channel) → verdict=block
#                → payment-service log AUDIT payment_blocked_fraud (log thật)
# Grafana rule  : Fraud Gate Bypass → severity=critical
#   LogQL: {namespace="financial",app="payment-service"} | json | level="AUDIT" | event="payment_blocked_fraud"
# SOAR playbook : isolate_workload
# HITL          : YES — email gửi admin (critical severity)
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:8180}"
SCENARIO="KB2_fraud_gate"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway không khả dụng"

# ── 2. Lấy JWT hợp lệ ───────────────────────────────────────────────────────
TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
[[ -n "$TOKEN" ]] || fail "Không lấy được JWT"

# ── 3. Gửi giao dịch gian lận qua api-gateway ────────────────────────────────
# Scoring: base(5) + critical_amount_500M(+55) + risky_channel_tor(+15) = 75 → block
# payment-service nhận verdict=block → log AUDIT payment_blocked_fraud
# → Promtail thu → Loki {namespace=financial, app=payment-service}
blocked=0
for i in $(seq 1 3); do
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$GW_URL/payments" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -H "X-Channel: tor" \
    -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":500000000,"currency":"VND","channel":"tor"}')
  [[ "$http_code" == "403" ]] && blocked=$((blocked+1))
  log "  Attempt $i → HTTP $http_code"
done

[[ $blocked -ge 2 ]] || fail "Chỉ $blocked/3 bị chặn (cần ≥2)"
log "payment-service chặn $blocked/3 → AUDIT payment_blocked_fraud → Loki"

pass "KB2 | $blocked/3 blocked | log AUDIT thật → Loki (Grafana fire trong ≤1 phút)"
