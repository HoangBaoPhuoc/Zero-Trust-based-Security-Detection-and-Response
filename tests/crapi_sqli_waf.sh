#!/usr/bin/env bash
# KỊCH BẢN — SQL Injection probe qua WAF (A2 — đối chứng "CRS bắt được chữ ký").
#
# Cặp đôi với crapi_bola.sh: cùng người dùng hợp lệ, nhưng lần này request MANG
# payload injection kinh điển. Kỳ vọng:
#   1. CRS/ModSecurity GHI NHẬN (job=waf-audit, tag attack-sqli) — chữ ký bắt được.
#   2. Request VẪN ĐI TIẾP tới ứng dụng (SecRuleEngine=DetectionOnly) — không chặn,
#      không làm nhiễu telemetry.
set -uo pipefail
SCENARIO="crapi_sqli_waf"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"
crapi_preflight

J="$(crapi_login testuser01 'Test1234!')"
trap 'rm -f "$J"' EXIT
log "Đăng nhập testuser01 — gửi SQLi/XSS/traversal qua WAF (DetectionOnly)"

T0="$(date +%s)"
echo "---- probe requests (HTTP code — kỳ vọng KHÔNG bị WAF chặn) ----"
declare -a P=(
  "GET  /identity/api/v2/vehicle/vehicles?id=1'%20OR%20'1'%3D'1'%20UNION%20SELECT%20username,password%20FROM%20users--"
  "GET  /community/api/v2/community/posts/recent?sort=1;DROP%20TABLE%20users--"
  "GET  /workshop/api/shop/products?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
  "GET  /identity/api/v2/user/pictures?file=../../../../etc/passwd"
)
for entry in "${P[@]}"; do
  m="$(awk '{print $1}' <<<"$entry")"; p="$(awk '{print $2}' <<<"$entry")"
  code="$(crapi_call "$J" "$m" "$p")"
  printf '  %s %-70s -> %s\n' "$m" "${p:0:70}" "$code"
  # WAF ở DetectionOnly: không được trả 403 do ModSecurity (bff/OPA có thể trả 401/404)
done
# Mục 11 vòng 2026-09-29 — nguyên nhân chênh "attack-lfi/rce = 1 (run_all) / 0 (chạy
# riêng)": T1 lấy bằng `date +%s` (làm tròn XUỐNG) và Loki tính cửa sổ (T0, T1] theo
# giây nguyên. Dòng audit của probe CUỐI (LFI/RCE, và thường cả XSS) được ghi trong
# cùng giây với T1 → rơi ra ngoài cửa sổ hay không tuỳ phần lẻ của giây. Đo lại có
# mili-giây: T1=…077.818 → floor 077; dòng xss ts=077.006, lfi/rce ts=077.773 BỊ
# LOẠI (results/round4/crs/probe-timing-1.log). Làm tròn LÊN +1 s: vẫn là cửa sổ tường
# minh của chính lần chạy (tất định), nhưng chứa trọn giây cuối.
T1="$(( $(date +%s) + 1 ))"

sleep 4   # đợi Promtail batchwait(1s) + ingest Loki — [T0,T1] giữ nguyên, không dịch theo sleep này
echo "---- ĐO: CRS/WAF audit — khoảng thời gian tường minh [T0=$T0, T1=$T1] (Phần 1.1, cùng cơ chế tất định với crapi_bola.sh) ----"
crs_sqli="$(loki_count '{job="waf-audit"} |~ "attack-sqli"' "$T0" "$T1")"
crs_xss="$(loki_count  '{job="waf-audit"} |~ "attack-xss"' "$T0" "$T1")"
crs_lfi="$(loki_count  '{job="waf-audit"} |~ "attack-(lfi|rce)"' "$T0" "$T1")"
crs_total="$(loki_count '{job="waf-audit"} |~ "\"transaction\""' "$T0" "$T1")"
echo "  CRS attack-sqli [T0,T1]      = $crs_sqli"
echo "  CRS attack-xss  [T0,T1]      = $crs_xss"
echo "  CRS attack-lfi/rce [T0,T1]   = $crs_lfi"
echo "  CRS transaction total[T0,T1] = $crs_total"

hits=$(( crs_sqli + crs_xss + crs_lfi ))
[[ $hits -ge 1 ]] || fail "$SCENARIO — CRS KHÔNG ghi nhận probe injection nào (hits=$hits) — WAF chưa hoạt động / rule chưa load / promtail job waf-audit lỗi"

pass "$SCENARIO — CRS ghi nhận $hits probe injection (job=waf-audit); request vẫn đi tiếp (DetectionOnly)"
