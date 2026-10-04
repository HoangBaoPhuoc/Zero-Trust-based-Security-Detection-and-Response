#!/usr/bin/env bash
# KỊCH BẢN 5 — thu hồi cert thiết bị (Phần 2.2/3.5, vòng cuối 2026-09-26).
#
# Cơ chế (scripts/revoke-device-cert.sh + services/bff/main.py): denylist tầng ứng
# dụng trong ConfigMap `device-revocation-list`, mount thư mục vào pod bff (KHÔNG
# subPath) và bff đọc TƯƠI mỗi request GHI. Thiết kế có chủ đích: thiết bị bị thu hồi
# bị chặn HÀNH ĐỘNG GHI (POST/PUT/PATCH/DELETE), còn hành động ĐỌC vẫn đi qua — giống
# `device_trust=suspicious` (posture non-compliant); đây KHÔNG phải cắt hẳn kết nối
# như CRL ở tầng TLS. Kịch bản đo đúng hành vi đó, không tuyên bố hơn.
#
# Các bước (mọi cấu hình đổi đều hoàn nguyên trong trap, kể cả khi lỗi giữa chừng):
#   0. bảo đảm test-compliant KHÔNG bị thu hồi; đăng nhập -> phiên S1
#   1. S1 ghi (POST community/posts) -> KHÔNG 403  (đối chứng: thiết bị chưa thu hồi)
#   2. thu hồi test-compliant; đo số giây tới khi file trong pod bff cập nhật
#   3. S1 (phiên ĐÃ ĐĂNG NHẬP trước khi thu hồi) ghi -> 403 device_revoked  (live check)
#   4. S1 đọc (GET workshop/shop/products) -> 200                         (đọc vẫn qua)
#   5. đăng nhập MỚI sau thu hồi (S2) ghi -> 403
#   6. bff-audit có device_trust_denied reason=revoked trong [T0,T1]
#   7. gỡ thu hồi; sau khi file cập nhật, phiên mới ghi -> KHÔNG 403 (hoàn nguyên được)
set -uo pipefail
SCENARIO="crapi_cert_revocation"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

DEVICE=test-compliant
CM_PATH=/app/device-revocation/revoked.json
POST_PATH=/community/api/v2/community/posts
POST_BODY='{"title":"revocation-probe","content":"revocation-probe"}'
pass_n=0; fail_n=0
ok()  { echo "  PASS: $1"; pass_n=$((pass_n + 1)); }
bad() { echo "  FAIL: $1"; fail_n=$((fail_n + 1)); }

restore() { bash "$REPO_ROOT/scripts/revoke-device-cert.sh" "$DEVICE" --unrevoke >/dev/null 2>&1; }
trap 'restore; rm -f "${S1:-}" "${S2:-}" "${S3:-}"' EXIT

pod_file() { kubectl --context "$KUBE_AWS" -n "$NS" exec deploy/bff -c bff -- cat "$CM_PATH" 2>/dev/null; }
# wait_file <chuỗi> <present|absent> → in số giây (tối đa 180s)
wait_file() {
  local needle="$1" mode="$2" t0; t0="$(date +%s)"
  while [[ $(( $(date +%s) - t0 )) -lt 180 ]]; do
    if pod_file | grep -q "$needle"; then [[ "$mode" == present ]] && { echo $(( $(date +%s) - t0 )); return 0; }
    else [[ "$mode" == absent ]] && { echo $(( $(date +%s) - t0 )); return 0; }
    fi
  done
  echo ">180"; return 1
}

crapi_preflight
restore
wait_file "$DEVICE" absent >/dev/null

echo "== 0/7 đăng nhập (thiết bị chưa thu hồi) =="
S1="$(crapi_login testuser01 'Test1234!')"
c="$(crapi_call "$S1" POST "$POST_PATH" "$POST_BODY")"
echo "  POST posts (chưa thu hồi) -> $c"
[[ "$c" != "403" && "$c" != "000" ]] && ok "đối chứng: chưa thu hồi thì ghi không bị 403 (được $c)" \
  || bad "đối chứng hỏng: chưa thu hồi mà ghi trả $c — kịch bản không kết luận được"

echo "== 2/7 thu hồi $DEVICE và đo độ trễ tới pod bff =="
T0="$(date +%s)"
bash "$REPO_ROOT/scripts/revoke-device-cert.sh" "$DEVICE" >/dev/null 2>&1
lag="$(wait_file "$DEVICE" present)"; rc=$?
echo "  file trong pod bff cập nhật sau: ${lag}s"
[[ $rc -eq 0 ]] && ok "ConfigMap tới pod bff sau ${lag}s (không cần restart)" || bad "file trong pod KHÔNG cập nhật sau 180s"

echo "== 3/7 phiên ĐÃ ĐĂNG NHẬP trước thu hồi: hành động GHI =="
c="$(crapi_call "$S1" POST "$POST_PATH" "$POST_BODY")"
echo "  POST posts (phiên cũ, cert đã thu hồi) -> $c"
[[ "$c" == "403" ]] && ok "phiên cũ bị chặn ghi ngay (403)" || bad "phiên cũ ghi trả $c, kỳ vọng 403 — thu hồi KHÔNG có hiệu lực với phiên đang hoạt động"

echo "== 4/7 cùng phiên: hành động ĐỌC =="
c="$(crapi_call "$S1" GET /workshop/api/shop/products)"
echo "  GET products (cert đã thu hồi) -> $c"
[[ "$c" == "200" ]] && ok "đọc vẫn 200 (đúng thiết kế: thu hồi chặn GHI, không cắt kết nối)" \
  || bad "đọc trả $c (kỳ vọng 200 theo thiết kế hiện tại)"

echo "== 5/7 đăng nhập MỚI sau thu hồi: hành động GHI =="
S2="$(crapi_login testuser01 'Test1234!')"
c="$(crapi_call "$S2" POST "$POST_PATH" "$POST_BODY")"
echo "  POST posts (phiên mới, cert đã thu hồi) -> $c"
[[ "$c" == "403" ]] && ok "phiên mới sau thu hồi cũng bị chặn ghi (403)" || bad "phiên mới ghi trả $c, kỳ vọng 403"

T1="$(( $(date +%s) + 1 ))"; sleep 8   # +1: date +%s làm tròn xuống (xem crapi_bola.sh)
echo "== 6/7 bằng chứng bff-audit =="
n="$(loki_count '{job="bff-audit"} | json | event="device_trust_denied" | reason="revoked"' "$T0" "$T1")"
echo "  bff-audit device_trust_denied reason=revoked trong [T0,T1]: $n dòng"
[[ "$n" -ge 1 ]] && ok "audit ghi rõ lý do 'revoked' (không mập mờ với posture)" \
  || bad "không thấy bff-audit reason=revoked (log chưa ingest hoặc lý do khác)"

echo "== 7/7 gỡ thu hồi (hoàn nguyên) =="
restore
lag2="$(wait_file "$DEVICE" absent)"; echo "  file cập nhật sau: ${lag2}s"
S3="$(crapi_login testuser01 'Test1234!')"
c="$(crapi_call "$S3" POST "$POST_PATH" "$POST_BODY")"
echo "  POST posts (sau gỡ thu hồi) -> $c"
[[ "$c" != "403" && "$c" != "000" ]] && ok "gỡ thu hồi thì ghi lại được (không 403, được $c)" || bad "sau gỡ thu hồi ghi vẫn trả $c"

echo
echo "== KẾT QUẢ: PASS=$pass_n FAIL=$fail_n =="
[[ $fail_n -eq 0 ]] && pass "$SCENARIO — thu hồi có hiệu lực với ghi (phiên cũ + phiên mới), độ trễ file ${lag}s, hoàn nguyên được" \
  || fail "$SCENARIO — $fail_n bước KHÔNG đúng (xem chi tiết ở trên)"
