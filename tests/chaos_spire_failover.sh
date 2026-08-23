#!/bin/bash
# Chaos test — SPIRE server failover
# Zero Trust layer: kiểm chứng thật rằng SVID đã cấp vẫn hoạt động khi
# spire-server tạm thời không sẵn sàng (SPIRE agent cache SVID cục bộ, không
# cần gọi lại server cho mỗi request) — nhưng KHÔNG cấp/renew được SVID mới
# trong lúc server down. Đây là thuộc tính "graceful degradation" quan trọng:
# spire-server là single point of registration nhưng KHÔNG phải single point
# of failure cho traffic đang chạy — nếu ngược lại (traffic chết ngay khi
# spire-server down) thì kiến trúc này quá mong manh cho production.
set -euo pipefail

CONTEXT="${KUBE_CONTEXT:-ctx-aws}"
NAMESPACE="spire"
SCENARIO="CHAOS_spire_failover"
# /health is a public_path in zta_policy.rego — it never required a
# SPIRE-issued SVID/mTLS cert in the first place, so hitting it (even via
# api-gateway's real Service, not just port-forward) never actually
# exercised "does mTLS traffic survive spire-server being down". Testing
# payment-service → fraud-detection instead: real pod-to-pod call, real
# Istio ISTIO_MUTUAL using a SPIRE-issued cert already cached by spire-agent
# — this is what "SVID caching survives spire-server downtime" actually
# means. Run from inside a live pod, not through port-forward (which
# bypasses Istio's own sidecar interception entirely — see the identical
# fix + full writeup in chaos_opa_failover.sh).
CALLER_POD_LABEL="app=payment-service"
TARGET_URL="http://fraud-detection.financial.svc.cluster.local:8080/health"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

ORIGINAL_REPLICAS=$(kubectl --context "$CONTEXT" get deployment spire-server -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
log "spire-server hiện có $ORIGINAL_REPLICAS replica"

CALLER_POD=$(kubectl --context "$CONTEXT" get pods -n financial -l "$CALLER_POD_LABEL" -o jsonpath='{.items[0].metadata.name}')
[[ -n "$CALLER_POD" ]] || fail "Không tìm thấy pod $CALLER_POD_LABEL"
call_target() {
  kubectl --context "$CONTEXT" exec -n financial "$CALLER_POD" -c payment-service -- python3 -c "
import urllib.request
try:
    r = urllib.request.urlopen('$TARGET_URL', timeout=5)
    print(r.status)
except Exception as e:
    print('000')
" 2>/dev/null
}

restore_spire() {
  log "Khôi phục spire-server về $ORIGINAL_REPLICAS replica..."
  kubectl --context "$CONTEXT" scale deployment spire-server -n "$NAMESPACE" --replicas="$ORIGINAL_REPLICAS" >/dev/null
  kubectl --context "$CONTEXT" rollout status deployment/spire-server -n "$NAMESPACE" --timeout=90s >/dev/null 2>&1 || true
}
trap restore_spire EXIT

log "Baseline — payment-service gọi fraud-detection qua mTLS thật trước khi tắt SPIRE"
baseline_code=$(call_target)
[[ "$baseline_code" == "200" ]] || fail "Baseline lỗi ($baseline_code) — dừng test"

log "Scale spire-server → 0 replica (giữ nguyên spire-agent — SVID đã cấp vẫn nằm trong cache agent)..."
kubectl --context "$CONTEXT" scale deployment spire-server -n "$NAMESPACE" --replicas=0 >/dev/null
kubectl --context "$CONTEXT" wait --for=delete pod -n "$NAMESPACE" -l app=spire-server --timeout=60s >/dev/null 2>&1 || true
log "spire-server đã tắt"

log "Traffic service-to-service (Istio ISTIO_MUTUAL dùng SVID SPIRE đã cấp từ trước) — kỳ vọng VẪN hoạt động"
still_working=0
for i in 1 2 3; do
  code=$(call_target)
  log "  Attempt $i (SPIRE server down) → HTTP $code"
  [[ "$code" == "200" ]] && still_working=$((still_working+1))
done

[[ $still_working -ge 2 ]] || fail "Traffic KHÔNG hoạt động khi spire-server down ($still_working/3) — SVID cache của agent có thể không đủ TTL, hoặc kiến trúc phụ thuộc server nhiều hơn dự kiến"
log "$still_working/3 request vẫn thành công dù spire-server down — SVID cache tại agent hoạt động đúng thiết kế"

restore_spire
trap - EXIT
recovered_code=$(call_target)
[[ "$recovered_code" == "200" ]] || fail "Sau khi phục hồi spire-server, traffic vẫn lỗi ($recovered_code)"

pass "CHAOS DONE | $still_working/3 traffic vẫn chạy khi SPIRE server down (SVID cache) | Phục hồi thành công"
