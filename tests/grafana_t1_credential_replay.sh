#!/bin/bash
# T1 — Compromised/stolen credential replay (long-lived/expired token reuse)
# Zero Trust layer: tenet 3 (per-session, không cấp vĩnh viễn) — OPA kiểm tra
# valid_jwt = iss đúng VÀ exp còn hạn cho MỌI request, không có khái niệm
# "đã login thì tin trong cả phiên dài".
#
# Cách kiểm thử: gọi thẳng OPA REST API (giống T5 — tách khỏi tầng app để đo
# đúng logic Rego, không nhiễu bởi lớp khác). Không dùng token thật hết hạn
# (accessTokenLifespan=300s, đợi thật quá lâu cho 1 bài test) — tự dựng 1 JWT
# đúng cấu trúc 3 phần base64 (header.payload.signature) với claim exp trong
# quá khứ. Hợp lệ để test vì OPA dùng io.jwt.decode() (chỉ decode, không verify
# chữ ký — xem comment trong opa/policies/zta_policy.rego) nên không cần chữ ký
# thật hợp lệ để kiểm tra riêng nhánh "exp hết hạn" của valid_jwt.
set -euo pipefail

CONTEXT="${KUBE_CONTEXT:-ctx-aws}"
NAMESPACE="financial"
SCENARIO="T1_credential_replay"
LOCAL_PORT=18182
ISSUER="http://keycloak.ztlab.local:8180/realms/ztlab"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

cleanup() { [[ -n "${PF_PID:-}" ]] && kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT

kubectl --context "$CONTEXT" port-forward -n "$NAMESPACE" svc/opa-service "${LOCAL_PORT}:8181" \
  > /tmp/ztlab-t1-opa-pf.log 2>&1 &
PF_PID=$!
for i in $(seq 1 10); do
  curl -s -o /dev/null "http://localhost:${LOCAL_PORT}/health" 2>/dev/null && break
  sleep 1
done

build_jwt() {
  local exp="$1"
  python3 -c "
import base64, json
def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
header = {'alg': 'RS256', 'typ': 'JWT'}
payload = {'iss': '$ISSUER', 'exp': $exp, 'realm_access': {'roles': ['financial-write']}}
print(b64(header) + '.' + b64(payload) + '.forged-signature-not-verified-by-opa')
"
}

query_opa_with_jwt() {
  local jwt="$1"
  curl -s -X POST "http://localhost:${LOCAL_PORT}/v1/data/zta/authz/allow" \
    -H "Content-Type: application/json" \
    -d "{\"input\":{\"attributes\":{\"request\":{\"http\":{\"method\":\"POST\",\"path\":\"/payments\",\"headers\":{\"authorization\":\"Bearer ${jwt}\"}}}}}}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('result'))" 2>/dev/null || echo "request_failed"
}

NOW=$(date +%s)
FUTURE=$((NOW + 3600))
PAST=$((NOW - 3600))

log "Đối chứng: JWT với exp còn hạn (tương lai +1h), issuer đúng, role financial-write"
valid_jwt=$(build_jwt "$FUTURE")
control=$(query_opa_with_jwt "$valid_jwt")
log "  OPA allow = $control (kỳ vọng True)"
[[ "$control" == "True" ]] || fail "Đối chứng FAIL — JWT hợp lệ mà vẫn bị deny, kiểm tra lại issuer/policy"

log "Tấn công (replay): JWT GIỐNG HỆT nhưng exp đã hết hạn (quá khứ -1h) — mô phỏng credential cũ bị đánh cắp/replay"
denied=0
for i in 1 2 3; do
  expired_jwt=$(build_jwt "$PAST")
  result=$(query_opa_with_jwt "$expired_jwt")
  log "  Attempt $i (exp=hết hạn) → OPA allow = $result"
  [[ "$result" == "False" ]] && denied=$((denied+1))
done

[[ $denied -ge 2 ]] || fail "OPA chỉ deny $denied/3 (cần ≥2) — kiểm tra lại điều kiện exp trong valid_jwt"
log "OPA từ chối $denied/3 request dùng JWT hết hạn — replay credential cũ không dùng được"
log "→ Chứng minh Zero Trust tenet 3: không có 'đã login là tin mãi', mọi request re-check exp độc lập"

pass "T1 DONE | $denied/3 OPA deny do JWT hết hạn (replay) | Đối chứng JWT còn hạn vẫn allow=True"
