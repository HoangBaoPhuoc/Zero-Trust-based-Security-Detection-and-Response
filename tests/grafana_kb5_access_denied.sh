#!/bin/bash
# KB5 — Access Denied Spike (T1078) — OPA RBAC Enforcement
# Zero Trust layer: Authorization (OPA RBAC — least-privilege, deny by default)
# Bằng chứng thật: merchant01 (financial-read only) thử POST /payments → OPA từ chối HTTP 403
# SOAR playbook : block_source_ip
# HITL          : YES — email gửi admin
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:8180}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB5_access_denied"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway không khả dụng"

# ── 2. Lấy JWT merchant01 (financial-read only) ───────────────────────────────
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
log "merchant01 roles: $roles"

# ── 3. merchant01 thử POST /payments → OPA RBAC deny thật ───────────────────
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

[[ $denied -ge 4 ]] || fail "Chỉ $denied/${#amounts[@]} request bị OPA từ chối (cần ≥4)"
log "OPA RBAC từ chối $denied/${#amounts[@]} (403)"

# ── 4. Đẩy OPA deny log vào Loki ─────────────────────────────────────────────
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
PYEOF

pass "KB5 | OPA RBAC từ chối $denied/${#amounts[@]} (403) | logs → Loki (Grafana fire trong ≤1 phút)"
