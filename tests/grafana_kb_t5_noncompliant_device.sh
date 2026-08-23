#!/bin/bash
# T5 — Insider with valid credentials but non-compliant device posture
# Zero Trust layer: Dynamic policy (NIST SP 800-207 tenet 4) — posture_compliant
#                    trong opa/policies/zta_policy.rego VÀ opa/policies/cross_cloud.rego
#
# Cập nhật 2026-08-23: phát hiện path /transactions/execute thật (payment-service
# AWS -> core-banking OpenStack) được xét bởi opa-config.yaml's
# `path: zta/crosscloud/allow` — KHÔNG phải zta/authz/allow. Rule
# posture_compliant viết đầu tiên trong zta_policy.rego (core_transaction_with_
# fraud_gate) không hề chạy trên đường thật này — header X-Device-Posture
# payment-service gắn (shared/posture.py) tới nơi nhưng bị bỏ qua. Đã thêm rule
# posture_compliant tương ứng vào cross_cloud.rego. Script này giờ test CẢ 2
# policy: zta/authz (rule gốc, vẫn đúng logic, dùng nếu 1 caller nào khác gọi
# qua đường đó) và zta/crosscloud (đường thật service này thực sự đi qua).
#
# Cách kiểm thử: port-forward opa-service:8181 (REST API OPA) rồi POST input
# đúng shape Envoy ext_authz gửi tới cả 2 path — cô lập đúng logic Rego cần
# kiểm chứng, không đi qua Envoy/app thật.
#
# Lý do không test qua app thật (đã thử, bỏ): core-banking có lớp validate
# HMAC signature riêng (services/core-banking/main.py) — request thiếu chữ ký
# hợp lệ bị app tự chặn 403 ở CẢ 2 trường hợp (có/không posture), che mất kết
# quả OPA thật. Lý do không exec thẳng vào pod gọi opa-service:8181 nội bộ:
# NetworkPolicy (k8s/financial/network-policies/os-allow-list.yaml) chỉ cho
# phép port 9191 (gRPC ext_authz) tới OPA, chặn đúng 8181 (REST) — micro-
# segmentation hoạt động đúng thiết kế, không phải lỗi. port-forward qua API
# server không đi qua đường CNI mà NetworkPolicy kiểm soát nên vẫn gọi được.
#
# Attack: input có valid_svid + fraud_gate_valid hợp lệ (score=5<75, gate=passed)
#         NHƯNG x-device-posture=non-compliant → kỳ vọng allow=false.
# Đối chứng: input giống hệt nhưng KHÔNG có header x-device-posture (giống toàn
#         bộ traffic thật hiện tại, chưa service nào gửi header này) → kỳ vọng
#         allow=true, chứng minh thay đổi Rego là additive, không phá traffic cũ.
set -euo pipefail

CONTEXT="${KUBE_CONTEXT:-ctx-openstack}"
NAMESPACE="financial"
SCENARIO="T5_noncompliant_device"
LOCAL_PORT=18181

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

cleanup() { [[ -n "${PF_PID:-}" ]] && kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT

kubectl --context "$CONTEXT" port-forward -n "$NAMESPACE" svc/opa-service "${LOCAL_PORT}:8181" \
  > /tmp/ztlab-t5-opa-pf.log 2>&1 &
PF_PID=$!
for i in $(seq 1 10); do
  curl -s -o /dev/null "http://localhost:${LOCAL_PORT}/health" 2>/dev/null && break
  sleep 1
done

query_opa_authz() {
  local headers_json="$1"
  curl -s -X POST "http://localhost:${LOCAL_PORT}/v1/data/zta/authz/allow" \
    -H "Content-Type: application/json" \
    -d "{\"input\":{\"attributes\":{\"source\":{\"principal\":\"spiffe://ztlab.local/openstack/account-service\"},\"request\":{\"http\":{\"method\":\"POST\",\"path\":\"/transactions/execute\",\"headers\":${headers_json}}}}}}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('result'))" 2>/dev/null || echo "request_failed"
}

query_opa_crosscloud() {
  local headers_json="$1"
  curl -s -X POST "http://localhost:${LOCAL_PORT}/v1/data/zta/crosscloud/allow" \
    -H "Content-Type: application/json" \
    -d "{\"input\":{\"attributes\":{\"source\":{\"principal\":\"spiffe://ztlab.local/aws/payment-service\"},\"destination\":{\"principal\":\"spiffe://ztlab.local/openstack/core-banking\"},\"request\":{\"http\":{\"method\":\"POST\",\"path\":\"/transactions/execute\",\"headers\":${headers_json}}}}}}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('result'))" 2>/dev/null || echo "request_failed"
}

run_check() {
  local label="$1" query_fn="$2"
  log "[$label] Đối chứng: input KHÔNG có x-device-posture (giống traffic thật hiện tại)"
  local control
  control=$("$query_fn" '{"x-fraud-gate":"passed","x-fraud-score":"5"}')
  log "[$label]   OPA allow = $control (kỳ vọng True)"
  [[ "$control" == "True" ]] || fail "[$label] Đối chứng FAIL — thay đổi Rego đã phá traffic hiện có (allow phải =True khi thiếu header)"

  log "[$label] Tấn công: input GIỐNG HỆT + x-device-posture=non-compliant"
  local denied=0 result
  for i in 1 2 3; do
    result=$("$query_fn" '{"x-fraud-gate":"passed","x-fraud-score":"5","x-device-posture":"non-compliant"}')
    log "[$label]   Attempt $i → OPA allow = $result"
    [[ "$result" == "False" ]] && denied=$((denied+1))
  done
  [[ $denied -ge 2 ]] || fail "[$label] OPA chỉ deny $denied/3 (cần ≥2) — posture_compliant chưa hoạt động đúng"
  log "[$label] OPA từ chối $denied/3 dù fraud_gate_valid + valid_svid đều đúng"
}

# zta/authz — rule gốc trong zta_policy.rego, đúng logic nhưng KHÔNG phải
# đường thật payment-service->core-banking đi qua (xem ghi chú đầu file).
run_check "zta.authz" query_opa_authz

# zta/crosscloud — đường thật request /transactions/execute thực sự đi qua
# trên cluster OpenStack (opa-config.yaml: path: zta/crosscloud/allow).
run_check "zta.crosscloud" query_opa_crosscloud

log "→ Chứng minh Zero Trust tenet 4 (dynamic policy): credential hợp lệ + fraud-gate hợp lệ vẫn KHÔNG đủ nếu posture không đạt — đúng trên CẢ policy thật đang enforce"
pass "T5 DONE | zta.authz + zta.crosscloud đều deny khi posture non-compliant, đều allow khi thiếu header — không phá traffic hiện có"
