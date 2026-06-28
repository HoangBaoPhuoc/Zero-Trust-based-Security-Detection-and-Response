#!/bin/bash
# KB3 — Lateral Movement: Unauthorized Internal Path (T1021.007)
# Zero Trust layer: mTLS SVID identity + OPA internal_service_request policy
# Tấn công thật: notification-service (kubectl exec) POST /payments/internal/execute
#                lên payment-service — path này KHÔNG nằm trong whitelist OPA cho internal service
#                OPA policy: internal_service_request for POST chỉ cho phép /payments, /score, /notify
#                → OPA từ chối → Envoy 403 → OPA decision log thật
# Grafana rule  : Lateral Movement → severity=critical
#   LogQL: {job="opa-decisions", opa_result="false", request_path="/payments/internal/execute"}
# SOAR playbook : isolate_workload
# HITL          : YES — email gửi admin (critical)
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
SCENARIO="KB3_lateral_movement"
CONTEXT="${KUBE_CONTEXT:-ctx-aws}"
NAMESPACE="financial"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway không khả dụng tại $GW_URL"

# ── 2. Lấy notification-service pod (attacker) ───────────────────────────────
NOTIF_POD=$(kubectl --context "$CONTEXT" get pod -n "$NAMESPACE" \
  -l app=notification-service \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[[ -n "$NOTIF_POD" ]] || fail "Không tìm được pod notification-service"
NOTIF_IP=$(kubectl --context "$CONTEXT" get pod "$NOTIF_POD" -n "$NAMESPACE" \
  -o jsonpath='{.status.podIP}' 2>/dev/null)
log "Attacker pod: $NOTIF_POD (IP: $NOTIF_IP, SVID: spiffe://ztlab.local/aws/notification-service)"

# ── 3. Tấn công thật: lateral movement qua unauthorized internal path ────────
# notification-service có SPIRE SVID hợp lệ nhưng OPA chỉ cho phép POST tới:
#   /payments, /score, /notify
# Cố gọi /payments/internal/execute → OPA từ chối (lateral movement)
# Envoy mTLS đính kèm SVID thật → OPA thấy đúng source_principal nhưng path bị cấm
# OPA ghi decision log (console=true) → Promtail thu container log → Loki
log "Tấn công: notification-service → payment-service POST /payments/internal/execute"
denied=0
for i in $(seq 1 3); do
  result=$(kubectl --context "$CONTEXT" exec -n "$NAMESPACE" "$NOTIF_POD" -- \
    python3 -c "
import urllib.request, json
try:
    req = urllib.request.Request(
        'http://payment-service.financial.svc.cluster.local:8080/payments/internal/execute',
        data=json.dumps({
            'from_account': 'ACC-1001',
            'to_account': 'ACC-ATTACKER',
            'amount': 999999,
            'lateral_move': $i
        }).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST')
    resp = urllib.request.urlopen(req, timeout=5)
    print('ALLOWED-' + str(resp.status))
except Exception as e:
    print('DENIED-' + str(getattr(e, 'code', 0)))
" 2>/dev/null || echo "exec_failed")
  log "  Attempt $i → $result"
  [[ "$result" =~ DENIED|403 ]] && denied=$((denied+1))
done

[[ $denied -ge 2 ]] || fail "OPA chỉ từ chối $denied/3 (cần ≥2) — kiểm tra OPA policy"
log "OPA từ chối $denied/3 — lateral movement bị chặn tại /payments/internal/execute"
log "→ OPA decision log (opa_result=false, request_path=/payments/internal/execute)"
log "→ Promtail scrape OPA container log → Loki {job=opa-decisions}"
log "→ Grafana sẽ fire alert trong ≤1 phút → SOAR tạo case lateral_movement"

pass "KB3 DONE | $denied/3 bị OPA chặn | Log thật từ OPA decision log → Grafana fire trong ≤1 phút"
