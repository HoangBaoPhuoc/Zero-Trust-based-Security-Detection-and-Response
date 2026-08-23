#!/bin/bash
# T3 — Unauthorized cross-cloud access (attacker ngoài trust domain thử truy
# cập tài nguyên OpenStack, dù dùng đúng service DNS/network path thật)
# Zero Trust layer: tenet 1+2 — mọi resource yêu cầu xác thực bất kể vị trí
# mạng; identity phải thuộc đúng trust domain ztlab.local, không phải chỉ cần
# "gọi đúng địa chỉ" là được coi là hợp lệ.
#
# Khác KB3 (lateral movement — SVID hợp lệ THẬT của ztlab.local, chỉ sai
# quyền path nội bộ): T3 test identity HOÀN TOÀN NGOÀI trust domain (kiểu
# "spiffe://external.attacker/..." — một attacker giả mạo SVID nhưng không
# được SPIRE của ztlab.local ký) cố truy cập core-banking trên OpenStack.
set -euo pipefail

CONTEXT="${KUBE_CONTEXT:-ctx-openstack}"
NAMESPACE="financial"
SCENARIO="T3_cross_cloud_bypass"
LOCAL_PORT=18183

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

cleanup() { [[ -n "${PF_PID:-}" ]] && kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT

kubectl --context "$CONTEXT" port-forward -n "$NAMESPACE" svc/opa-service "${LOCAL_PORT}:8181" \
  > /tmp/ztlab-t3-opa-pf.log 2>&1 &
PF_PID=$!
for i in $(seq 1 10); do
  curl -s -o /dev/null "http://localhost:${LOCAL_PORT}/health" 2>/dev/null && break
  sleep 1
done

query_opa() {
  local principal="$1"
  curl -s -X POST "http://localhost:${LOCAL_PORT}/v1/data/zta/authz/allow" \
    -H "Content-Type: application/json" \
    -d "{\"input\":{\"attributes\":{\"source\":{\"principal\":\"${principal}\"},\"request\":{\"http\":{\"method\":\"POST\",\"path\":\"/transactions/execute\",\"headers\":{\"x-fraud-gate\":\"passed\",\"x-fraud-score\":\"5\"}}}}}}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('result'))" 2>/dev/null || echo "request_failed"
}

log "Đối chứng: SVID thật trong trust domain ztlab.local (spiffe://ztlab.local/openstack/account-service)"
control=$(query_opa "spiffe://ztlab.local/openstack/account-service")
log "  OPA allow = $control (kỳ vọng True)"
[[ "$control" == "True" ]] || fail "Đối chứng FAIL — SVID hợp lệ trong trust domain mà vẫn bị deny"

log "Tấn công: SVID giả mạo NGOÀI trust domain (spiffe://external.attacker/fake-service) — network path/DNS giống hệt, chỉ khác identity"
denied=0
for fake_principal in \
  "spiffe://external.attacker/malicious-service" \
  "spiffe://evil.corp/fake-account-service" \
  ""
do
  result=$(query_opa "$fake_principal")
  log "  principal='$fake_principal' → OPA allow = $result"
  [[ "$result" == "False" ]] && denied=$((denied+1))
done

[[ $denied -ge 2 ]] || fail "OPA chỉ deny $denied/3 (cần ≥2) — valid_svid có thể đang chấp nhận identity ngoài trust domain"
log "OPA từ chối $denied/3 identity ngoài trust domain ztlab.local"
log "→ Chứng minh: 'gọi đúng địa chỉ mạng' không đủ — phải có SVID hợp lệ do đúng root CA của ztlab.local ký"

pass "T3 DONE | $denied/3 OPA deny do SVID ngoài trust domain | Đối chứng SVID thật vẫn allow=True"
