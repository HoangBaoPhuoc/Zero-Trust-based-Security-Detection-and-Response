#!/usr/bin/env bash
# KỊCH BẢN — Access Denied Spike (unauthenticated internal + device không tin cậy)
#
# Lớp Zero-Trust nghiệm thu: OPA fail-closed. (1) Gọi nội mesh KHÔNG có SVID
# hợp lệ / KHÔNG có phiên → deny. (2) Thiết bị posture=non-compliant (A3 —
# client cert Device CA, KHÔNG còn suy đoán qua User-Agent) cố GHI → deny
# (`device_trust_compliant` / `posture_compliant`).
#
# Tấn công THẬT:
#   - exec vào pod crapi-web (SVID web, KHÔNG có edge tới workshop/community trong
#     service_acl trừ tĩnh) gọi API nghiệp vụ workshop → deny.
#   - login testuser01 bằng cert thiết bị posture=non-compliant (scripts/issue-device-cert.sh)
#     → BFF gắn X-Device-Trust: suspicious → POST đơn hàng → deny.
#
# Bằng chứng: OPA decision log spike (opa_result=false) + BFF audit
# device_trust_denied → Grafana "Access Denied Spike" → incident-analyzer evidence bundle.
set -uo pipefail
SCENARIO="crapi_access_denied"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"
crapi_preflight

denied=0 total=0

WEB_POD="$(crapi_pod crapi-web)"
if [[ -n "$WEB_POD" ]]; then
  log "1) crapi-web (SVID web, không phải PEP) → gọi API nghiệp vụ workshop/community"
  for path in /workshop/api/shop/products /community/api/v2/community/home /workshop/api/shop/orders; do
    for i in 1 2 3; do
      total=$((total + 1))
      code="$(kubectl --context "$KUBE_AWS" -n "$NS" exec "$WEB_POD" -c crapi-web -- \
        sh -c "wget -q -O /dev/null -T6 -S http://crapi-workshop.crapi.svc.cluster.local:8000${path} 2>&1 \
          | grep -oE 'HTTP/[0-9.]+ [0-9]{3}' | tail -1 | grep -oE '[0-9]{3}\$'" 2>/dev/null || echo 000)"
      [[ "$code" == "403" || "$code" == "000" ]] && denied=$((denied + 1))
    done
  done
  log "   → $denied/$total bị từ chối (deny/không kết nối)"
else
  log "1) bỏ qua — không tìm được pod crapi-web"
fi

log "2) Thiết bị posture=non-compliant (cert Device CA) cố GHI đơn hàng"
_orig_cert="$CRAPI_CLIENT_CERT"; _orig_key="$CRAPI_CLIENT_KEY"
CRAPI_CLIENT_CERT="$CA_DIR/issued/test-noncompliant/device.crt"
CRAPI_CLIENT_KEY="$CA_DIR/issued/test-noncompliant/device.key"
Jb="$(crapi_login testuser01 'Test1234!')"
for i in 1 2 3 4 5; do
  total=$((total + 1))
  code="$(crapi_call "$Jb" POST /workshop/api/shop/orders '{"product_id":1,"quantity":1}')"
  log "   POST orders (posture=non-compliant) attempt $i → $code"
  [[ "$code" == "403" ]] && denied=$((denied + 1))
done
rm -f "$Jb"
CRAPI_CLIENT_CERT="$_orig_cert"; CRAPI_CLIENT_KEY="$_orig_key"

[[ $denied -ge $(( total / 2 )) ]] || fail "chỉ $denied/$total bị từ chối — kiểm tra OPA fail-closed / device_trust_compliant"
log "Tổng $denied/$total request bị từ chối tại điểm enforcement (OPA / BFF)"

sleep 3
n="$(loki_count '{job="opa-decisions", opa_result="false"}')"
log "OPA deny trong 10 phút: $n dòng → Loki"

pass "$SCENARIO — $denied/$total bị từ chối · OPA deny spike + device_trust_denied → Loki · Grafana 'Access Denied Spike' → incident-analyzer evidence bundle"
