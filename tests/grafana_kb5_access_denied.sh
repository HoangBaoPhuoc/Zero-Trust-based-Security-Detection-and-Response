#!/bin/bash
# KB5 — Access Denied Spike (T1078)
# Zero Trust layer: Authorization (OPA RBAC — deny rate tăng từ cùng IP)
# Grafana rule  : Access Denied Spike → severity=high
# SOAR playbook : block_source_ip (Redis block list, TTL 24h)
# HITL          : YES — email gửi admin
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:8180}"
SOAR_URL="${SOAR_URL:-http://localhost:8091}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB5_access_denied"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
log "Bước 1: kiểm tra API Gateway và SOAR..."
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway không khả dụng"
curl -fsS "$SOAR_URL/health" | grep -q '"status":"ok"' || fail "SOAR không khả dụng"

# ── 2. Lấy JWT rồi probe endpoint không được phép ────────────────────────────
log "Bước 2: dùng JWT user thông thường để probe endpoint admin (bị OPA từ chối)..."
TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
[[ -n "$TOKEN" ]] || { log "WARNING: không lấy được JWT, tiếp tục không có token"; TOKEN="dummy"; }

denied=0
PATHS=("/admin/users" "/admin/config" "/internal/keys" "/system/logs" "/debug/heap" "/actuator/env")
for p in "${PATHS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$GW_URL$p" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo "000")
  [[ "$code" =~ ^(401|403|404)$ ]] && denied=$((denied+1))
  log "GET $p → HTTP $code"
done
log "OPA từ chối $denied/${#PATHS[@]} request từ IP không có quyền"

# ── 3. Đẩy OPA deny log vào Loki (spike từ một IP) ───────────────────────────
log "Bước 3: đẩy opa-decisions deny log vào Loki (source_ip cố định = 10.0.0.99)..."
ts=$(date +%s%N)
for i in 0 1 2 3 4 5; do
  path_idx=$((i % ${#PATHS[@]}))
  path_list=("/admin/users" "/admin/config" "/internal/keys" "/system/logs" "/debug/heap" "/actuator/env")
  p="${path_list[$path_idx]}"
  curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
    -H "Content-Type: application/json" \
    -d "{\"streams\":[{
      \"stream\":{\"job\":\"opa-decisions\",\"namespace\":\"financial\",
                  \"app\":\"opa-server\",\"result\":\"deny\"},
      \"values\":[[\"$((ts + i * 1000000))\",
        \"{\\\"result\\\":\\\"deny\\\",\\\"source_ip\\\":\\\"10.0.0.99\\\",\\\"path\\\":\\\"$p\\\",\\\"method\\\":\\\"GET\\\",\\\"reason\\\":\\\"rbac_deny_no_admin_role\\\"}\"]]
    }]}" >/dev/null
done
log "6 OPA deny log đã vào Loki (source_ip=10.0.0.99, result=deny)"

# ── 4. Mô phỏng Grafana → SOAR webhook ────────────────────────────────────────
log "Bước 4: mô phỏng Grafana 'Access Denied Spike' alert → SOAR webhook..."
fp="kb5-$(date +%s)"
soar_resp=$(curl -s -X POST "$SOAR_URL/grafana-webhook" \
  -H "Content-Type: application/json" \
  -d "{
    \"status\": \"firing\",
    \"alerts\": [{
      \"status\": \"firing\",
      \"labels\": {
        \"alertname\": \"Access Denied Spike\",
        \"severity\": \"high\",
        \"attack_type\": \"access_denied\",
        \"mitre\": \"T1078\",
        \"category\": \"security\"
      },
      \"annotations\": {
        \"summary\": \"OPA deny rate tăng đột biến từ cùng source_ip\",
        \"description\": \"source_ip=10.0.0.99 count=6 window=1m paths=/admin/users,/internal/keys\"
      },
      \"fingerprint\": \"$fp\"
    }]
  }")

# ── 5. Kiểm tra SOAR case ─────────────────────────────────────────────────────
log "Bước 5: kiểm tra SOAR case..."
status=$(echo "$soar_resp"   | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('status','?') if c else 'no-case')" 2>/dev/null)
playbook=$(echo "$soar_resp" | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('playbook','?') if c else '?')" 2>/dev/null)
case_id=$(echo "$soar_resp"  | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('case_id','?') if c else '?')" 2>/dev/null)

[[ "$status" =~ ^(pending_approval|executed|dry_run)$ ]] \
  || fail "SOAR status='$status' (expect pending_approval)"
[[ "$playbook" == "block_source_ip" ]] \
  || fail "SOAR playbook='$playbook' (expect block_source_ip)"

pass "KB5 Access Denied | OPA deny $denied/${#PATHS[@]} | SOAR case=$case_id status=$status playbook=$playbook (T1078)"
log "→ block_source_ip: SOAR thêm 10.0.0.99 vào Redis block list, Envoy từ chối mọi request từ IP này 24h"
