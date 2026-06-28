#!/bin/bash
# KB5 — Access Denied Spike (T1078) — OPA RBAC Enforcement
# Zero Trust layer: Authorization (OPA RBAC — least-privilege, deny by default)
# Tấn công thật: merchant01 (role=financial-read) thử POST /payments
#                → OPA: role_permits_action=false (financial-read thiếu POST permission)
#                → OPA deny → Envoy 403 → OPA decision log thật
# Grafana rule  : Access Denied Spike → severity=high
#   LogQL: {job="opa-decisions", opa_result="false", request_path="/payments"}
# SOAR playbook : block_source_ip
# HITL          : YES — email gửi admin
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:8180}"
SCENARIO="KB5_access_denied"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway không khả dụng"

# ── 2. Lấy JWT merchant01 (role=financial-read only) ─────────────────────────
MERCHANT_TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=merchant01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
[[ -n "$MERCHANT_TOKEN" ]] || fail "Không lấy được JWT merchant01"

# ── 3. merchant01 thử POST /payments → OPA RBAC deny thật ──────────────────
# OPA: external_api_request requires role_permits_action → financial-read không có POST
# → allow=false → Envoy 403 → OPA decision log (job=opa-decisions, opa_result=false)
# → Promtail thu OPA container log → Loki
denied=0
amounts=(100000 50000 200000 75000 1000000 5000)
for amount in "${amounts[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GW_URL/payments" \
    -H "Authorization: Bearer $MERCHANT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"from_account\":\"ACC-4001\",\"to_account\":\"ACC-2001\",\"amount\":$amount}" \
    2>/dev/null || echo "000")
  [[ "$code" == "403" ]] && denied=$((denied+1))
  log "  POST /payments $amount → HTTP $code"
done

[[ $denied -ge 4 ]] || fail "Chỉ $denied/${#amounts[@]} bị từ chối (cần ≥4)"
log "OPA RBAC từ chối $denied/${#amounts[@]} (403) → decision log → Loki {job=opa-decisions, request_path=/payments}"
log "→ Grafana alert 'Kịch bản 5 — Access Denied Spike' sẽ fire trong ≤1 phút → SOAR tạo case access_denied"

pass "KB5 DONE | OPA RBAC từ chối $denied/${#amounts[@]} (403) | Log thật từ OPA decision log → Grafana fire trong ≤1 phút"
