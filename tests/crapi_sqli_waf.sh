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

sleep 4
echo "---- ĐO: CRS/WAF audit ----"
crs_sqli="$(loki_count '{job="waf-audit"} |~ "attack-sqli"')"
crs_xss="$(loki_count  '{job="waf-audit"} |~ "attack-xss"')"
crs_lfi="$(loki_count  '{job="waf-audit"} |~ "attack-(lfi|rce)"')"
crs_total="$(loki_count '{job="waf-audit"} |~ "\"transaction\""')"
echo "  CRS attack-sqli (10m)      = $crs_sqli"
echo "  CRS attack-xss  (10m)      = $crs_xss"
echo "  CRS attack-lfi/rce (10m)   = $crs_lfi"
echo "  CRS transaction total(10m) = $crs_total"

hits=$(( crs_sqli + crs_xss + crs_lfi ))
[[ $hits -ge 1 ]] || fail "$SCENARIO — CRS KHÔNG ghi nhận probe injection nào (hits=$hits) — WAF chưa hoạt động / rule chưa load / promtail job waf-audit lỗi"

pass "$SCENARIO — CRS ghi nhận $hits probe injection (job=waf-audit); request vẫn đi tiếp (DetectionOnly)"
