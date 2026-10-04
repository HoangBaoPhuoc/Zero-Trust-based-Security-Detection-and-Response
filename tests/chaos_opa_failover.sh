#!/usr/bin/env bash
# Chaos test — OPA PDP fail-closed (Policy Decision Point availability)
#
# Kiểm chứng THẬT (không chỉ đọc config rồi tin): Istio CUSTOM AuthorizationPolicy
# → `opa-ext-authz` extensionProvider thật sự **fail-closed** khi OPA không phản
# hồi — traffic nội mesh bị chặn (503) chứ KHÔNG lọt qua (fail-open = lỗ hổng
# nghiêm trọng).
#
# Gọi từ TRONG pod (kubectl exec) — KHÔNG qua port-forward: port-forward nối
# thẳng loopback của pod, BỎ QUA iptables interception của Istio → request
# không hề chạm Istio/OPA (test tự lừa chính nó).
set -uo pipefail
SCENARIO="chaos_opa_failover"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"

CTX="$KUBE_AWS"
CALLER="$(crapi_pod bff "$CTX")"           # bff có edge tới crapi-web trong service_acl
TARGET="http://crapi-web.crapi.svc.cluster.local:80/"
[[ -n "$CALLER" ]] || fail "không tìm được pod bff"

call() {
  kubectl --context "$CTX" -n "$NS" exec "$CALLER" -c bff -- python3 -c "
import urllib.request
try:
    r = urllib.request.urlopen('$TARGET', timeout=6); print(r.status)
except urllib.error.HTTPError as e: print(e.code)
except Exception as e: print('ERR', type(e).__name__)" 2>/dev/null || echo "exec_fail"
}

ORIG="$(kubectl --context "$CTX" -n "$NS" get deploy opa-server -o jsonpath='{.spec.replicas}')"
restore() {
  log "khôi phục opa-server → $ORIG replica"
  kubectl --context "$CTX" -n "$NS" scale deploy opa-server --replicas="$ORIG" >/dev/null
  kubectl --context "$CTX" -n "$NS" rollout status deploy/opa-server --timeout=120s >/dev/null 2>&1 || true
}
trap restore EXIT

log "Baseline — bff → crapi-web (qua mesh + OPA)"
b="$(call)"; [[ "$b" == "200" ]] || fail "baseline lỗi ($b) — hệ thống không ổn định trước test"

log "Scale opa-server → 0 (cả $ORIG replica)"
kubectl --context "$CTX" -n "$NS" scale deploy opa-server --replicas=0 >/dev/null
kubectl --context "$CTX" -n "$NS" wait --for=delete pod -l app=opa --timeout=60s >/dev/null 2>&1 || true

denied=0
for i in 1 2 3; do
  c="$(call)"; log "  attempt $i (OPA down) → $c"
  [[ "$c" == "503" ]] && denied=$((denied + 1))
done
[[ $denied -ge 2 ]] || fail "chỉ $denied/3 bị chặn khi OPA down — nghi fail-OPEN (kiểm istio-operator opa-ext-authz + AuthorizationPolicy crapi-web)"
log "$denied/3 request → 503 khi OPA down — xác nhận **fail-closed** thật"

restore
r="$(call)"; [[ "$r" == "200" ]] || fail "sau khi phục hồi OPA, bff→crapi-web vẫn lỗi ($r)"
pass "$SCENARIO — $denied/3 fail-closed khi OPA down; phục hồi OK"
