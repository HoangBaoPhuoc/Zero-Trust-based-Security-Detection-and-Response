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
echo "  3. MailHog  http://localhost:8025  (mail HITL cho case severity cao)"
[[ $failc -eq 0 ]] || exit 1
