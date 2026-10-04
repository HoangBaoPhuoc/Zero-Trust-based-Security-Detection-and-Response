#!/usr/bin/env bash
# Chạy toàn bộ kịch bản tấn công crAPI → sinh log thật → Grafana → incident-analyzer.
#
# Yêu cầu: cụm chạy + port-forward (bash scripts/open-admin-uis.sh).
# Sau khi chạy: xem Grafana (http://localhost:3000, Alerting → ZTLab) fire,
# rồi evidence bundles (http://localhost:8091/evidence) và mail (MailHog SOC :8026).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SCRIPTS=(
  "Lateral Movement (T1021)      crapi_lateral_movement.sh"
  "BFLA (API5:2023)              crapi_bfla.sh"
  "Step-up Auth (dynamic policy) crapi_step_up.sh"
  "Access Denied Spike           crapi_access_denied.sh"
  "Brute Force (T1110)           crapi_brute_force.sh"
  "SQLi/XSS/LFI qua WAF (CRS bắt) crapi_sqli_waf.sh"
  "BOLA (API1:2023, CRS mù)      crapi_bola.sh"
  # vòng 2026-09-29: 3 kịch bản trước chỉ làm tay/chưa từng chạy trọn
  "Step-up OTP đầu-cuối          crapi_step_up_otp.sh"
  "Large Response (T1041)        crapi_large_response.sh"
  "Privilege Escalation (T1068)  crapi_privilege_escalation.sh"
)

pass=0; failc=0; results=()
for entry in "${SCRIPTS[@]}"; do
  name="${entry%% *}"; script="${entry##* }"
  echo; echo "════════════════════════════════════════════════════════"
  echo " $entry"
  echo "════════════════════════════════════════════════════════"
  if bash "$HERE/$script"; then results+=("PASS  $entry"); pass=$((pass+1))
  else results+=("FAIL  $entry"); failc=$((failc+1)); fi
  sleep 3
done

echo; echo "════════════════════════════════════════════════════════"
echo " KẾT QUẢ"
echo "════════════════════════════════════════════════════════"
printf '  %s\n' "${results[@]}"
echo; echo "  PASS=$pass  FAIL=$failc"
echo
echo "Tiếp theo (≤2 phút):"
echo "  1. Grafana  http://localhost:3000  → Alerting → Alert rules → folder ZTLab (xem rule chuyển Firing)"
echo "  2. Evidence http://localhost:8091/evidence  (bundle mới theo attack_type)"
echo "  3. MailHog  http://localhost:8025  (mail signup/reset crAPI)"
echo
echo "Đối chứng BOLA (Phần 1.1): 3 lần chạy liên tiếp tests/crapi_bola.sh phải cho CÙNG kết quả"
echo "  (khoảng thời gian Loki tường minh [T0,T1] của mỗi lần chạy — không dùng cửa sổ trượt)."
[[ $failc -eq 0 ]] || exit 1
