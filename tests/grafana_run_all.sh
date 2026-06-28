#!/bin/bash
# Chạy toàn bộ 4 kịch bản Grafana → SOAR
# KB1: Brute Force T1110.001       | KB3: Lateral Movement T1021.007
# KB2: Fraud Gate Bypass T1078.004 | KB5: Access Denied Spike T1078
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0; SKIP=0
RESULTS=()

run_kb() {
  local name="$1" script="$2"
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo " Chạy $name"
  echo "════════════════════════════════════════════════════════"
  if [[ ! -f "$SCRIPT_DIR/$script" ]]; then
    echo "[SKIP] $script không tồn tại"
    RESULTS+=("SKIP  $name")
    SKIP=$((SKIP+1))
    return
  fi
  chmod +x "$SCRIPT_DIR/$script"
  if bash "$SCRIPT_DIR/$script"; then
    RESULTS+=("PASS  $name")
    PASS=$((PASS+1))
  else
    RESULTS+=("FAIL  $name  ← xem log bên trên")
    FAIL=$((FAIL+1))
  fi
  sleep 2
}

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   ZTLab — Chạy 4 kịch bản Grafana → SOAR           ║"
echo "╚══════════════════════════════════════════════════════╝"

run_kb "KB1  Brute Force (T1110.001)"          grafana_kb1_brute_force.sh
run_kb "KB2  Fraud Gate Bypass (T1078.004)"    grafana_kb2_fraud_gate.sh
run_kb "KB3  Lateral Movement (T1021.007)"     grafana_kb3_lateral_movement.sh
run_kb "KB5  Access Denied Spike (T1078)"      grafana_kb5_access_denied.sh

echo ""
echo "════════════════════════════════════════════════════════"
echo " KẾT QUẢ"
echo "════════════════════════════════════════════════════════"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo ""
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo ""

if [[ $FAIL -gt 0 ]]; then
  echo "⚠  Có $FAIL kịch bản thất bại — xem log bên trên để debug"
  exit 1
fi
echo "✓  Tất cả $PASS kịch bản đã PASS"
echo ""
echo "Bước tiếp theo:"
echo "  1. Mở Web Portal  → http://localhost:18081/security  (đăng nhập analyst01 / Test1234!)"
echo "  2. Xem SOAR cases đã tạo → phê duyệt hoặc từ chối từng playbook"
echo "  3. Kiểm tra hộp thư  voha2005@gmail.com  → email HITL với log evidence"
echo "  4. Mở Grafana        → http://localhost:3000  (admin / ZTALab2026!)"
echo "     Alerting → Alert rules → folder ZTLab → xem 4 rule đang inactive/firing"
