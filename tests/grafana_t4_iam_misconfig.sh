#!/bin/bash
# T4 — Privilege escalation via misconfigured security group / network ACL
# Zero Trust layer: tenet 2 (micro-segmentation) — NetworkPolicy đóng vai trò
# tương đương "security group" trong kiến trúc K8s-native của ZTLab. Test này
# xác nhận đúng những gì file tham khảo T4 mô tả ("misconfigured SG cho phép
# truy cập trái phép") KHÔNG xảy ra: pod ở namespace không nằm trong allow-list
# của k8s/financial/network-policies/aws-allow-list.yaml không kết nối được
# vào service nội bộ financial (redis), dù cùng cluster, cùng resolve DNS được.
#
# Khác KB3/T3 (đều test ở tầng OPA/identity): T4 test đúng tầng network layer
# (NetworkPolicy/CNI), KHÔNG qua OPA — chứng minh phòng thủ nhiều lớp độc lập
# (defense in depth), không chỉ dựa vào 1 điểm kiểm soát duy nhất.
set -euo pipefail

CONTEXT="${KUBE_CONTEXT:-ctx-aws}"
SCENARIO="T4_iam_misconfig"
TEST_POD="t4-network-segmentation-test"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

cleanup() {
  kubectl --context "$CONTEXT" delete pod "$TEST_POD" -n default --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "Tạo pod thử nghiệm trong namespace 'default' — KHÔNG nằm trong allow-list của aws-allow-list.yaml (chỉ cho kube-system/monitoring/financial/plg-stack)"
kubectl --context "$CONTEXT" run "$TEST_POD" -n default --image=busybox:1.36 --restart=Never \
  --command -- sleep 300 >/dev/null
kubectl --context "$CONTEXT" wait --for=condition=Ready pod/"$TEST_POD" -n default --timeout=30s >/dev/null

log "Tấn công: pod ở 'default' thử kết nối redis.financial.svc.cluster.local:6379 (đáng lẽ chỉ financial/plg-stack mới được phép)"
blocked=0
for i in 1 2 3; do
  if kubectl --context "$CONTEXT" exec "$TEST_POD" -n default -- \
       timeout 3 nc -zv redis.financial.svc.cluster.local 6379 2>&1 | grep -qi "open\|succeeded"; then
    result="CONNECTED (không nên xảy ra)"
  else
    result="BLOCKED/TIMEOUT"
    blocked=$((blocked+1))
  fi
  log "  Attempt $i → $result"
done

[[ $blocked -ge 2 ]] || fail "Pod ở 'default' namespace kết nối được vào redis financial ($blocked/3 blocked) — NetworkPolicy có lỗ hổng, cần kiểm tra lại aws-allow-list.yaml"
log "$blocked/3 lần kết nối bị chặn — NetworkPolicy đúng vai trò 'security group', namespace ngoài allow-list không truy cập được"

log "Đối chứng: pod trong namespace 'financial' (nằm trong chính allow-list) PHẢI kết nối được"
CONTROL_POD=$(kubectl --context "$CONTEXT" get pod -n financial -l app=fraud-detection -o jsonpath='{.items[0].metadata.name}')
control_result=$(kubectl --context "$CONTEXT" exec "$CONTROL_POD" -n financial -c fraud-detection -- \
  python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(('redis.financial.svc.cluster.local', 6379))
    print('CONNECTED')
except Exception as e:
    print('FAILED:', e)
" 2>&1 || echo "FAILED")
log "  Pod trong financial namespace → $control_result"
[[ "$control_result" == *"CONNECTED"* ]] || fail "Đối chứng FAIL — pod hợp lệ trong financial cũng không kết nối được redis, NetworkPolicy có thể quá chặt (false positive)"

pass "T4 DONE | $blocked/3 pod ngoài allow-list bị NetworkPolicy chặn | Đối chứng pod hợp lệ trong financial vẫn kết nối được"
