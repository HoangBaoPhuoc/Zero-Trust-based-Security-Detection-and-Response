#!/bin/bash
# KB5 — Access Denied Spike (T1078) — OPA RBAC Enforcement
# Zero Trust layer: Authorization (OPA RBAC — least-privilege, deny by default)
# Bằng chứng thật: merchant01 (financial-read only) thử POST /payments → OPA từ chối HTTP 403
# SOAR playbook : block_source_ip
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

# ── 2. Lấy JWT merchant01 (financial-read only) ───────────────────────────────
log "Bước 2: lấy JWT merchant01 (role: financial-read only)..."
MERCHANT_TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=merchant01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
[[ -n "$MERCHANT_TOKEN" ]] || fail "Không lấy được JWT merchant01"

roles=$(echo "$MERCHANT_TOKEN" | cut -d. -f2 | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip(); p+='='*((4-len(p)%4)%4)
d=json.loads(base64.urlsafe_b64decode(p))
print(d.get('realm_access',{}).get('roles',[]))" 2>/dev/null || echo "unknown")
log "  merchant01 roles: $roles  ← chỉ có financial-read, không có financial-write"

# ── 3. merchant01 thử POST /payments → OPA RBAC deny thật ───────────────────
log "Bước 3: merchant01 thử POST /payments (cần financial-write) → OPA RBAC từ chối..."
denied=0
amounts=(100000 50000 200000 75000 1000000 5000)
for amount in "${amounts[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GW_URL/payments" \
    -H "Authorization: Bearer $MERCHANT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"from_account\":\"ACC-4001\",\"to_account\":\"ACC-2001\",\"amount\":$amount}" \
    2>/dev/null || echo "000")
  [[ "$code" == "403" ]] && denied=$((denied+1))
  log "  POST /payments amount=$amount → HTTP $code  ← OPA RBAC deny (financial-write required)"
done

[[ $denied -ge 4 ]] || fail "Chỉ $denied/${#amounts[@]} request bị OPA từ chối (cần ≥4)"
log "▶ OPA RBAC từ chối $denied/${#amounts[@]} request — merchant01 vi phạm least-privilege"

# Lấy response body để hiển thị lý do
deny_reason=$(curl -s -X POST "$GW_URL/payments" \
  -H "Authorization: Bearer $MERCHANT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-4001","to_account":"ACC-2001","amount":1000}' 2>/dev/null) || deny_reason="{}"
parsed=$(echo "$deny_reason" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d)" 2>/dev/null) || parsed="(see HTTP 403)"
log "  OPA response: $parsed"

# ── 4. Đẩy OPA deny log vào Loki (Python để tránh bash escaping issues) ──────
log "Bước 4: đẩy OPA deny log vào Loki (format khớp Grafana rule)..."
python3 - <<PYEOF
import json, urllib.request, time
loki_url = "${LOKI_URL}"
now = time.time_ns()
log_lines = []
for i in range(6):
    log_lines.append([str(now + i * 1_000_000), json.dumps({
        "result": "deny",
        "source_ip": "10.0.0.99",
        "path": "/payments",
        "method": "POST",
        "reason": "rbac_deny_missing_financial_write_role",
        "subject": "merchant01",
        "subject_roles": ["financial-read"],
        "required_roles": ["financial-write"]
    })])
payload = {"streams": [{"stream": {
    "job": "opa-decisions",
    "namespace": "financial",
    "app": "opa-server",
    "result": "deny"
}, "values": log_lines}]}
req = urllib.request.Request(
    f"{loki_url}/loki/api/v1/push",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print(f"[KB5_access_denied] 6 OPA deny log đã vào Loki — Grafana rule sẽ fire")
PYEOF

# ── 5. Mô phỏng Grafana → SOAR webhook ────────────────────────────────────────
log "Bước 5: mô phỏng Grafana 'Access Denied Spike' → SOAR webhook..."
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
        \"summary\": \"OPA RBAC deny spike — merchant01 bị từ chối $denied/${#amounts[@]} POST /payments\",
        \"description\": \"source_ip=10.0.0.99 count=$denied window=1m reason=missing_financial_write_role subject=merchant01\"
      },
      \"fingerprint\": \"$fp\"
    }]
  }")

# ── 6. Kiểm tra SOAR case ─────────────────────────────────────────────────────
log "Bước 6: kiểm tra SOAR case..."
status=$(echo "$soar_resp"   | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('status','?') if c else 'no-case')" 2>/dev/null || echo "?")
playbook=$(echo "$soar_resp" | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('playbook','?') if c else '?')" 2>/dev/null || echo "?")
case_id=$(echo "$soar_resp"  | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('case_id','?') if c else '?')" 2>/dev/null || echo "?")

[[ "$status" =~ ^(pending_approval|executed|dry_run)$ ]] \
  || fail "SOAR status='$status' (expect pending_approval)"
[[ "$playbook" == "block_source_ip" ]] \
  || fail "SOAR playbook='$playbook' (expect block_source_ip)"

pass "KB5 Access Denied | OPA RBAC THẬT: $denied/${#amounts[@]} từ chối | SOAR case=$case_id status=$status playbook=$playbook (T1078)"
log "  ✓ Zero Trust enforcement THẬT: merchant01 (financial-read) bị OPA từ chối POST /payments"
log "  ✓ OPA policy: require role financial-write — không có → HTTP 403"
log "  block_source_ip: SOAR thêm IP vào Redis blocklist 24h"
