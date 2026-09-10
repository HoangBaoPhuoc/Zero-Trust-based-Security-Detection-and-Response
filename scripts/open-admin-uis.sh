#!/usr/bin/env bash
# Mở port-forward cho tất cả admin/monitoring UI của ZTLab
#
# Dùng:
#   bash scripts/open-admin-uis.sh          # bật tất cả (chạy nền, tự restart)
#   bash scripts/open-admin-uis.sh stop     # dừng tất cả
#   bash scripts/open-admin-uis.sh status   # kiểm tra
#
# UI sau khi bật:
#   Keycloak     → http://localhost:8180   (admin / ztlab-admin-2026)
#   crAPI        → http://localhost:18081   (WAF→BFF — entry point; SPA + login OIDC)
#   crAPI BFF bypass → http://localhost:18083   (bỏ qua WAF, debug)
#   Grafana      → http://localhost:3000   (admin / ZTALab2026!)
#   Loki         → http://localhost:13100
#   Incident Analyzer → http://localhost:8091   (evidence bundles — /evidence, /health)
#   Prometheus   → http://localhost:9090
#   MailHog (crAPI)  → http://localhost:8025   (mail signup/reset crAPI — cluster OpenStack)
#   MailHog (SOC)    → http://localhost:8026   (incident-analyzer evidence emails — plg-stack)

set -euo pipefail

AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"
PID_DIR="/tmp/ztlab-pf"
LOG_FILE="/tmp/ztlab-pf.log"

mkdir -p "$PID_DIR"

# Mỗi port-forward chạy trong vòng lặp auto-restart, tách hẳn khỏi terminal (setsid)
start_pf_daemon() {
  local label="$1"
  local ns="$2"
  local svc="$3"
  local local_port="$4"
  local remote_port="$5"
  local ctx="${6:-$AWS_CONTEXT}"
  local pid_file="$PID_DIR/${local_port}.pid"

  # Đã có daemon cho port này rồi
  if [[ -f "$pid_file" ]]; then
    local old_pid
    old_pid=$(cat "$pid_file")
    if kill -0 "$old_pid" 2>/dev/null; then
      echo "[SKIP] $label — daemon PID $old_pid đang chạy"
      return
    fi
    rm -f "$pid_file"
  fi

  # Port đang bị chiếm bởi process khác
  if ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${local_port}$"; then
    echo "[SKIP] $label — port $local_port đã được dùng (process khác)"
    return
  fi

  # Chạy vòng lặp auto-restart trong session mới (setsid) → tồn tại sau khi terminal đóng
  setsid bash -c "
    while true; do
      kubectl --context '$ctx' port-forward 'svc/$svc' -n '$ns' \
        '${local_port}:${remote_port}' --address=127.0.0.1 \
        >>'$LOG_FILE' 2>&1
      sleep 3
    done
  " &
  local daemon_pid=$!
  echo "$daemon_pid" > "$pid_file"

  # Chờ tối đa 8s cho port listen
  local i
  for ((i = 0; i < 8; i++)); do
    sleep 1
    if ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${local_port}$"; then
      echo "[ OK ] $label → http://localhost:${local_port}  (PID $daemon_pid)"
      return
    fi
  done
  echo "[FAIL] $label — không thể mở port $local_port (xem $LOG_FILE)"
}

stop_all() {
  echo "=== ZTLab — Dừng port-forwards ==="
  for pid_file in "$PID_DIR"/*.pid; do
    [[ -f "$pid_file" ]] || continue
    local port
    port=$(basename "$pid_file" .pid)
    local pid
    pid=$(cat "$pid_file")
    # Kill cả process group (daemon + kubectl con)
    if kill -0 "$pid" 2>/dev/null; then
      kill -- -"$(ps -o pgid= -p "$pid" | tr -d ' ')" 2>/dev/null || kill "$pid" 2>/dev/null || true
      echo "  Stopped port $port (PID $pid)"
    else
      echo "  Port $port — đã dừng rồi"
    fi
    rm -f "$pid_file"
  done
  # Kill socat Loki proxy
  pkill -f "socat.*13099" 2>/dev/null || true
  # Kill bất kỳ kubectl port-forward nào còn sót
  pkill -f "kubectl.*port-forward" 2>/dev/null || true
  echo "Done."
}

show_status() {
  echo "=== ZTLab — Port-forward status ==="
  declare -A PORT_NAMES=(
    [8180]="Keycloak"
    [18081]="crAPI (WAF→BFF)"
    [18083]="crAPI BFF (bypass)"
    [3000]="Grafana"
    [13100]="Loki"
    [8091]="Incident Analyzer"
    [9090]="Prometheus"
    [8025]="MailHog (crAPI)"
    [8026]="MailHog (SOC)"
  )
  for port in 8180 18081 18083 3000 13100 8091 9090 8025 8026; do
    local name="${PORT_NAMES[$port]}"
    local pid_file="$PID_DIR/${port}.pid"
    local daemon_alive="no"
    local port_open="no"
    if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      daemon_alive="yes (PID $(cat "$pid_file"))"
    fi
    if ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${port}$"; then
      port_open="yes"
    fi
    printf "  %-22s port %-6s daemon=%-20s listen=%s\n" "$name" "$port" "$daemon_alive" "$port_open"
  done
}

case "${1:-start}" in
  stop)
    stop_all
    exit 0
    ;;
  status)
    show_status
    exit 0
    ;;
  start|"")
    ;;
  *)
    echo "Usage: $0 [start|stop|status]"
    exit 1
    ;;
esac

echo "=== ZTLab — Mở port-forwards (auto-restart daemons) ==="
echo "Yêu cầu: K8s tunnel đang chạy (bash scripts/k8s-tunnel.sh up aws)"
echo ""

# Identity — A1: Keycloak nay ở cụm OpenStack
start_pf_daemon "Keycloak"            identity   keycloak          8180  8080  "$OS_CONTEXT"
# crAPI (ứng dụng mục tiêu) — điểm vào là WAF (ModSecurity/CRS DetectionOnly, A2)
# đứng trước BFF. Cổng 18081 khớp redirectUri client crapi-bff. WAF proxy trong
# suốt tới bff:8080. 18083 = bypass thẳng bff để debug (bỏ qua WAF).
start_pf_daemon "crAPI (WAF→BFF)"     crapi      waf              18081  8080
start_pf_daemon "crAPI BFF (bypass)"  crapi      bff              18083  8080
# PLG Stack
start_pf_daemon "Grafana"             plg-stack  grafana           3000  3000
start_pf_daemon "Loki"                plg-stack  loki             13100  3100
# Loki proxy cho OpenStack promtail: 10.10.10.1:13099 → localhost:13100
# OpenStack nodes không reach được localhost trực tiếp nên cần socat bridge
if ! ss -lnt | awk '{print $4}' | grep -Eq ":13099$"; then
  pkill -f "socat.*13099" 2>/dev/null || true
  setsid socat TCP-LISTEN:13099,bind=10.10.10.1,fork,reuseaddr TCP:127.0.0.1:13100 &
  echo $! > "$PID_DIR/loki-proxy.pid"
  echo "[ OK ] Loki-proxy → 10.10.10.1:13099 → localhost:13100 (for OpenStack promtail)"
fi
start_pf_daemon "Incident Analyzer"   plg-stack  incident-analyzer 8091  8080
# Monitoring
start_pf_daemon "Prometheus"          monitoring prometheus        9090  9090
# Mail — mailhog nằm ở cluster OpenStack (cạnh crapi-identity)
start_pf_daemon "MailHog (crAPI)"     crapi      mailhog           8025  8025  "$OS_CONTEXT"
start_pf_daemon "MailHog (SOC)"       plg-stack  mailhog           8026  8025

echo ""
echo "Credentials:"
echo "  Keycloak:   admin / ztlab-admin-2026"
echo "  Grafana:    admin / ZTALab2026!"
echo "  crAPI login (qua BFF, Keycloak OIDC): testuser01 / Test1234!  (demoadmin / Test1234! cho admin)"
echo ""
echo "Daemon tự restart nếu kubectl port-forward chết."
echo "Dừng tất cả: bash scripts/open-admin-uis.sh stop"
echo "Kiểm tra:    bash scripts/open-admin-uis.sh status"
