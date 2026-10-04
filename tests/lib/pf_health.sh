#!/usr/bin/env bash
# Kiểm + dựng lại port-forward của scripts/open-admin-uis.sh theo CHỨC NĂNG (HTTP thật),
# không chỉ "cổng đang listen" — port-forward treo (listen nhưng không chuyển tiếp,
# vd sau khi pod đích restart) là dạng hỏng hay gặp nhất khi chạy nhiều giờ.
# Dùng bởi results/round4/after-deploy-chain.sh (watchdog 60 s + kiểm trước mỗi bước).
source "$(dirname "${BASH_SOURCE[0]}")/crapi_common.sh"
PF_PID_DIR="/tmp/ztlab-pf"

# pf_check <port> → 0 nếu dịch vụ sau port trả lời đúng
pf_check() {
  local p="$1" code
  case "$p" in
    18444) local -a o; mapfile -t o < <(crapi_curl_tls_opts)
           code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' "${o[@]}" "$BFF_URL/health")" ;;
    13100) code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' http://127.0.0.1:13100/ready)" ;;
    3000)  code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/api/health)" ;;
    8026)  code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' 'http://127.0.0.1:8026/api/v2/messages?limit=1')" ;;
    9090)  code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' http://127.0.0.1:9090/-/ready)" ;;
    8091)  code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' http://127.0.0.1:8091/evidence)" ;;
    *) return 1 ;;
  esac
  [[ "$code" == 200 ]]
}

# pf_restart <port>: giết daemon + port-forward của port đó rồi chạy lại open-admin-uis.sh
# (script bỏ qua port còn sống, chỉ dựng cái thiếu).
pf_restart() {
  local p="$1" pid
  if [[ -f "$PF_PID_DIR/$p.pid" ]]; then
    pid="$(cat "$PF_PID_DIR/$p.pid")"
    kill -- -"$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')" 2>/dev/null || kill "$pid" 2>/dev/null || true
    rm -f "$PF_PID_DIR/$p.pid"
  fi
  pkill -f "port-forward .* ${p}:" 2>/dev/null || true
  sleep 2
  bash "$REPO_ROOT/scripts/open-admin-uis.sh" >/dev/null 2>&1 || true
}

PF_PORTS=(18444 13100 3000 8026 9090 8091)

# Tầng DƯỚI port-forward: tunnel SSH tới API k3s (127.0.0.1:6444 AWS / 6445 OpenStack,
# scripts/k8s-tunnel.sh). Lần chạy chuỗi đầu (2026-09-30 01:11–01:49) tunnel AWS chết sau
# deploy → mọi port-forward không dựng lại được, watchdog chỉ dựng lại port-forward nên
# 18 bước liền bị SKIP. Kiểm và dựng lại tunnel TRƯỚC.
k8s_api_ok() { kubectl --context "$KUBE_AWS" --request-timeout=8s get --raw /readyz >/dev/null 2>&1 \
               && kubectl --context "$KUBE_OS" --request-timeout=8s get --raw /readyz >/dev/null 2>&1; }

# pf_heal_all → in danh sách thứ đã phải dựng lại (rỗng nếu tất cả khỏe)
pf_heal_all() {
  local p healed=()
  if ! k8s_api_ok; then
    bash "$REPO_ROOT/scripts/k8s-tunnel.sh" up all >/dev/null 2>&1 || true
    sleep 3; healed+=("k8s-tunnel")
  fi
  for p in "${PF_PORTS[@]}"; do
    pf_check "$p" || { pf_restart "$p"; healed+=("$p"); }
  done
  echo "${healed[*]}"
}
