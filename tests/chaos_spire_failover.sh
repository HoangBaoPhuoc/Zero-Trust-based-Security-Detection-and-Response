#!/usr/bin/env bash
# Chaos test — SPIRE server failover (graceful degradation)
#
# Kiểm chứng THẬT: SVID đã cấp vẫn hoạt động khi spire-server tạm thời down
# (spire-agent cache SVID cục bộ) — spire-server là single point of
# *registration* nhưng KHÔNG phải single point of *failure* cho traffic đang
# chạy. (SVID mới sẽ không cấp/renew được trong lúc server down — đó là đánh đổi
# chấp nhận được, KHÁC với "traffic chết ngay".)
#
# Gọi từ TRONG pod (kubectl exec) qua đường mТLS thật (crapi-workshop →
# crapi-identity /identity/health_check — nằm trong service_acl).
set -uo pipefail
SCENARIO="chaos_spire_failover"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"

CTX_APP="$KUBE_AWS"
CTX_SPIRE="$KUBE_AWS"     # spire-server AWS (SVID của caller crapi-workshop do agent AWS cấp)
CALLER="$(crapi_pod crapi-workshop "$CTX_APP")"
TARGET="http://crapi-identity-openstack.crapi.svc.cluster.local:30090/identity/health_check"
[[ -n "$CALLER" ]] || fail "không tìm được pod crapi-workshop"

call() {
  kubectl --context "$CTX_APP" -n "$NS" exec "$CALLER" -c crapi-workshop -- sh -c \
    "wget -q -O /dev/null -T6 -S $TARGET 2>&1 | grep -oE 'HTTP/[0-9.]+ [0-9]{3}' | tail -1 | grep -oE '[0-9]{3}\$'" 2>/dev/null || echo "ERR"
}

ORIG="$(kubectl --context "$CTX_SPIRE" -n spire get deploy spire-server -o jsonpath='{.spec.replicas}')"
restore() {
  log "khôi phục spire-server → $ORIG replica"
  kubectl --context "$CTX_SPIRE" -n spire scale deploy spire-server --replicas="$ORIG" >/dev/null
  kubectl --context "$CTX_SPIRE" -n spire rollout status deploy/spire-server --timeout=120s >/dev/null 2>&1 || true
}
trap restore EXIT

log "Baseline — crapi-workshop → crapi-identity (mТLS SVID, cross-cloud)"
b="$(call)"; [[ "$b" == "200" ]] || fail "baseline lỗi ($b)"

log "Scale spire-server (AWS) → 0"
kubectl --context "$CTX_SPIRE" -n spire scale deploy spire-server --replicas=0 >/dev/null
kubectl --context "$CTX_SPIRE" -n spire wait --for=delete pod -l app=spire-server --timeout=60s >/dev/null 2>&1 || true
sleep 10

ok_count=0
for i in 1 2 3 4 5; do
  c="$(call)"; log "  attempt $i (spire-server down) → $c"
  [[ "$c" == "200" ]] && ok_count=$((ok_count + 1))
  sleep 2
done
[[ $ok_count -ge 4 ]] || fail "chỉ $ok_count/5 thành công khi spire-server down — SVID cache KHÔNG graceful (kiến trúc quá mong manh)"
log "$ok_count/5 request thành công khi spire-server down — SVID cache của agent hoạt động (graceful degradation)"

restore
r="$(call)"; [[ "$r" == "200" ]] || fail "sau khi phục hồi spire-server, hop vẫn lỗi ($r)"
pass "$SCENARIO — $ok_count/5 sống sót khi spire-server down; phục hồi OK"
