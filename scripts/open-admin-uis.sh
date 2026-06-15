#!/usr/bin/env bash
# Mở port-forward cho tất cả admin UI của ZTLab
# Chạy: ./scripts/open-admin-uis.sh
# Sau đó truy cập:
#   pgAdmin     → http://localhost:5050  (email: admin@ztlab.com / pass: ztlab2026)
#   RedisInsight→ http://localhost:5540
#   Grafana     → http://localhost:3000
#   SOAR Engine → http://localhost:8081
#   Web Portal  → http://localhost:8082

set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/ztlab/aws-tunnel.yaml}"

cleanup() {
  echo ""
  echo "Stopping all port-forwards..."
  kill "${PF_PIDS[@]}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

PF_PIDS=()

start_pf() {
  local label="$1"
  local ns="$2"
  local svc="$3"
  local local_port="$4"
  local remote_port="$5"

  if ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${local_port}$"; then
    echo "[SKIP] $label — port $local_port đã được dùng"
    return
  fi

  kubectl port-forward "svc/$svc" -n "$ns" "${local_port}:${remote_port}" >/dev/null 2>&1 &
  PF_PIDS+=($!)
  sleep 1
  if ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${local_port}$"; then
    echo "[ OK ] $label → http://localhost:${local_port}"
  else
    echo "[FAIL] $label — không thể mở port $local_port"
  fi
}

echo "=== ZTLab Admin UIs ==="
start_pf "pgAdmin (PostgreSQL)"  financial  pgadmin       5050  80
start_pf "RedisInsight (Redis)"  financial  redisinsight  5540  5540
start_pf "Grafana"               plg-stack  grafana       3000  3000
start_pf "SOAR Engine"           plg-stack  soar-engine   8081  8080
start_pf "Web Portal"            financial  web-portal    8082  8080

echo ""
echo "Đăng nhập pgAdmin: admin@ztlab.com / ztlab2026"
echo "Redis DB0=fraud, DB1=scorer, DB2=blocklist"
echo ""
echo "Nhấn Ctrl+C để thoát..."
wait
