#!/usr/bin/env bash
# Mở port-forward cho tất cả admin/monitoring UI của ZTLab
# Chạy: ./scripts/open-admin-uis.sh
# Sau đó truy cập:
#   Keycloak    → http://localhost:8180   (admin / ztlab-admin-2026)
#   API Gateway → http://localhost:18080
#   Web Portal  → http://localhost:18081
#   Grafana     → http://localhost:3000   (admin / ZTALab2026!)
#   Loki        → http://localhost:13100
#   SOAR Engine → http://localhost:8091
#   Scorer      → http://localhost:18092
#   Prometheus  → http://localhost:9090
#   pgAdmin     → http://localhost:5050   (admin@ztlab.com / ztlab2026)
#   RedisInsight→ http://localhost:5540

set -euo pipefail

AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"

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
  local ctx="${6:-$AWS_CONTEXT}"

  if ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${local_port}$"; then
    echo "[SKIP] $label — port $local_port đã được dùng"
    return
  fi

  kubectl --context "$ctx" port-forward "svc/$svc" -n "$ns" \
    "${local_port}:${remote_port}" --address=127.0.0.1 >/dev/null 2>&1 &
  PF_PIDS+=($!)
  sleep 1
  if ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${local_port}$"; then
    echo "[ OK ] $label → http://localhost:${local_port}"
  else
    echo "[FAIL] $label — không thể mở port $local_port"
  fi
}

echo "=== ZTLab — Mở port-forwards ==="
echo ""
echo "Yêu cầu: K8s tunnel đang chạy (bash scripts/k8s-tunnel.sh up all)"
echo ""

# Identity
start_pf "Keycloak"               identity   keycloak       8180  8080

# Financial
start_pf "API Gateway"            financial  api-gateway   18080  8080
start_pf "Web Portal"             financial  web-portal    18081  8080

# PLG Stack
start_pf "Grafana"                plg-stack  grafana        3000  3000
start_pf "Loki"                   plg-stack  loki          13100  3100
start_pf "SOAR Engine"            plg-stack  soar-engine    8091  8080
start_pf "Security Scorer"        plg-stack  security-scorer 18092 8080

# Monitoring
start_pf "Prometheus"             monitoring prometheus      9090  9090

# DB Admin
# pgAdmin chạy trên OpenStack (cùng cluster với Postgres)
start_pf "pgAdmin (PostgreSQL)"   financial  pgadmin        5050  80   "$OS_CONTEXT"
# RedisInsight chạy trên AWS (cùng cluster với Redis)
start_pf "RedisInsight (Redis)"   financial  redisinsight   5540  5540 "$AWS_CONTEXT"

echo ""
echo "Credentials:"
echo "  Keycloak:  admin / ztlab-admin-2026"
echo "  Grafana:   admin / ZTALab2026!"
echo "  pgAdmin:   admin@ztlab.com / ztlab2026"
echo "  Redis DB0=fraud+blocklist+soar  DB1=scorer"
echo ""
echo "Nhấn Ctrl+C để thoát..."
wait
