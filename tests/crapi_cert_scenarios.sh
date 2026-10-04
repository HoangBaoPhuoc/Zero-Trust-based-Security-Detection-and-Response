#!/usr/bin/env bash
# KỊCH BẢN — 4 kịch bản certificate thiết bị qua Istio IngressGateway (mТLS biên).
#
# Phần 1.3 remediation (2026-09-18): đợt trước (BAOCAO-SUA-GOC-2026-09-13.md,
# KET-QUA-CRAPI.md) verify 3 kịch bản đầu bằng curl THỦ CÔNG (không tái lặp
# được tự động): cert hợp lệ+compliant→200, không cert→TLS fail, CA lạ→TLS
# fail. Bảng nghiệm thu ghi "3 kịch bản certificate PASS" nhưng THIẾU đúng
# kịch bản duy nhất chứng minh POSTURE thật sự tham gia quyết định (không chỉ
# nằm trong cert cho có): cert HỢP LỆ (ký đúng Device CA, TLS handshake OK)
# nhưng posture:non-compliant, thử một hành động GHI → phải bị từ chối VÀ có
# decision log ghi rõ lý do là posture (không phải suy diễn từ "request bị
# chặn" chung chung — 2 lần độc lập trong task này đã gặp đúng bẫy "trông
# giống hệt bị chặn nhưng do lý do khác").
#
# Endpoint dùng cho kịch bản 4: POST /community/api/v2/community/posts —
# CỐ Ý không dùng /workshop/api/shop/orders (như crapi_access_denied.sh) vì
# endpoint đó còn nằm trong sensitive_crapi_action (opa/crapi-policies/
# zta_crapi.rego dòng 136-145) → cũng bị step_up_ok chặn (acr != high), nên
# một 403 ở đó KHÔNG chứng minh được cụ thể posture là nguyên nhân (có thể là
# thiếu step-up). community/posts KHÔNG nằm trong sensitive_crapi_action →
# step_up_ok luôn true (nhánh "not sensitive_crapi_action") → 403 ở đây CHỈ
# có thể do posture_ok/device_trust_ok — cô lập đúng biến cần chứng minh.
set -uo pipefail
SCENARIO="crapi_cert_scenarios"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"

pass_n=0; fail_n=0
ok()  { echo "  PASS: $1"; pass_n=$((pass_n + 1)); }
bad() { echo "  FAIL: $1"; fail_n=$((fail_n + 1)); }

_ensure_device_cert test-compliant compliant
_ensure_device_cert test-noncompliant non-compliant

RESOLVE="--resolve ${CRAPI_HOST}:${_BFF_TUNNEL_PORT}:127.0.0.1"

echo "== Kịch bản 1/4: cert hợp lệ (Device CA thật) + posture:compliant =="
code="$(curl -s -o /dev/null -w '%{http_code}' -m8 --cacert "$CRAPI_CA_CERT" \
  --cert "$CA_DIR/issued/test-compliant/device.crt" --key "$CA_DIR/issued/test-compliant/device.key" \
  $RESOLVE "$BFF_URL/health")"
echo "  GET /health -> $code"
[[ "$code" == "200" ]] && ok "cert hợp lệ + compliant -> 200" || bad "kỳ vọng 200, được $code"

echo "== Kịch bản 2/4: không cert =="
code="$(curl -s -o /dev/null -w '%{http_code}' -m8 --cacert "$CRAPI_CA_CERT" $RESOLVE "$BFF_URL/health" 2>/dev/null)"
curl_exit=$?
echo "  GET /health (không cert) -> http=${code:-000} curl_exit=$curl_exit"
[[ "$curl_exit" != "0" || "$code" != "200" ]] && ok "không cert -> TLS/kết nối fail (không phải 200)" \
  || bad "KHÔNG cert nhưng vẫn nhận 200 — lỗ hổng thật"

echo "== Kịch bản 3/4: cert ký bởi CA lạ (không phải Device CA) =="
ROGUE_DIR="$(mktemp -d)"
trap 'rm -rf "$ROGUE_DIR"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$ROGUE_DIR/rogue-ca.key" 2>/dev/null
openssl req -x509 -new -key "$ROGUE_DIR/rogue-ca.key" -days 1 -out "$ROGUE_DIR/rogue-ca.crt" \
  -subj "/C=VN/O=Attacker/CN=Rogue Device CA" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$ROGUE_DIR/rogue.key" 2>/dev/null
openssl req -new -key "$ROGUE_DIR/rogue.key" -out "$ROGUE_DIR/rogue.csr" \
  -subj "/C=VN/O=Attacker/OU=posture:compliant/CN=rogue-device" 2>/dev/null
openssl x509 -req -in "$ROGUE_DIR/rogue.csr" -CA "$ROGUE_DIR/rogue-ca.crt" -CAkey "$ROGUE_DIR/rogue-ca.key" \
  -CAcreateserial -days 1 -out "$ROGUE_DIR/rogue.crt" \
  -extfile <(printf 'subjectAltName=URI:spiffe://ztlab.local/device/rogue-device\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n') 2>/dev/null
code="$(curl -s -o /dev/null -w '%{http_code}' -m8 --cacert "$CRAPI_CA_CERT" \
  --cert "$ROGUE_DIR/rogue.crt" --key "$ROGUE_DIR/rogue.key" $RESOLVE "$BFF_URL/health" 2>/dev/null)"
curl_exit=$?
echo "  GET /health (cert CA lạ) -> http=${code:-000} curl_exit=$curl_exit"
[[ "$curl_exit" != "0" || "$code" != "200" ]] && ok "CA lạ -> TLS handshake fail (không phải 200)" \
  || bad "cert ký bởi CA lạ nhưng vẫn nhận 200 — lỗ hổng thật"

echo "== Kịch bản 4/4: cert hợp lệ + posture:non-compliant, hành động GHI (không phải sensitive_crapi_action) =="
_orig_cert="$CRAPI_CLIENT_CERT"; _orig_key="$CRAPI_CLIENT_KEY"
CRAPI_CLIENT_CERT="$CA_DIR/issued/test-noncompliant/device.crt"
CRAPI_CLIENT_KEY="$CA_DIR/issued/test-noncompliant/device.key"
T0="$(date +%s)"
Jnc="$(crapi_login testuser01 'Test1234!')"
code="$(crapi_call "$Jnc" POST /community/api/v2/community/posts '{"content":"posture-scenario-probe","author":"testuser01"}')"
rm -f "$Jnc"
# +1: `date +%s` làm tròn XUỐNG — sự kiện audit của BFF mang timestamp phần lẻ giây SAU T1 (đo 2026-10-04:
# event 11:52:00.59, T1 = 11:52:00) nên cửa sổ (T0,T1] bỏ sót nó → FAIL giả "không thấy device_trust_denied".
T1="$(( $(date +%s) + 1 ))"
CRAPI_CLIENT_CERT="$_orig_cert"; CRAPI_CLIENT_KEY="$_orig_key"
echo "  POST /community/api/v2/community/posts (cert hợp lệ, posture:non-compliant) -> $code"
[[ "$code" == "403" ]] && ok "posture:non-compliant + hành động ghi -> 403" \
  || bad "kỳ vọng 403, được $code — device_trust_compliant/posture_compliant có đang chặn thật không?"

sleep 6
# Bằng chứng ĐÚNG cho kịch bản này là bff-audit, KHÔNG PHẢI opa-decisions —
# phát hiện khi viết script này: `services/bff/main.py` dòng 572-576 chặn
# device_trust=suspicious NGAY TẠI BFF (PEP, "gương OPA" — comment gốc trong
# code) TRƯỚC KHI proxy tới crapi-community, nên OPA KHÔNG BAO GIỜ được gọi
# cho request này — 1 opa_result=false log sẽ KHÔNG BAO GIỜ xuất hiện dù
# enforcement hoàn toàn đúng. event=device_trust_denied chỉ có thể sinh ra từ
# nhánh code này (device_trust=="suspicious", tức posture != "compliant") nên
# tự nó đã là bằng chứng posture-specific, không mập mờ với lý do khác.
n="$(loki_count '{job="bff-audit"} | json | event="device_trust_denied"' "$T0" "$T1")"
echo "  bff-audit event=device_trust_denied trong [T0,T1]: $n dòng"
[[ "$n" -ge 1 ]] && ok "decision log (bff-audit device_trust_denied) xác nhận POSTURE là căn cứ từ chối" \
  || bad "KHÔNG thấy bff-audit device_trust_denied — không chứng minh được posture thực sự tham gia (có thể log chưa kịp ingest, hoặc từ chối vì lý do khác)"

echo
echo "== KẾT QUẢ: PASS=$pass_n FAIL=$fail_n =="
[[ $fail_n -eq 0 ]] && pass "$SCENARIO — 4/4 kịch bản certificate đúng kỳ vọng, kể cả posture:non-compliant có decision log" \
  || fail "$SCENARIO — $fail_n/4 kịch bản KHÔNG đúng kỳ vọng (xem chi tiết ở trên)"
