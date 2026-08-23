#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY_FILE="${INVENTORY_FILE:-$ROOT_DIR/ansible/inventory/hosts.yml}"
SSH_USER="${SSH_USER:-ubuntu}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/ztlab-key}"
SSH_CONNECT_TIMEOUT="${SSH_CONNECT_TIMEOUT:-10}"
SSH_COMMAND_TIMEOUT="${SSH_COMMAND_TIMEOUT:-30}"
SYNC_KUBECONFIG_ON_UP="${SYNC_KUBECONFIG_ON_UP:-false}"
AWS_LOCAL_PORT="${AWS_K8S_LOCAL_PORT:-6444}"
OS_LOCAL_PORT="${OS_K8S_LOCAL_PORT:-6445}"

AWS_CONTEXT="ctx-aws"
OS_CONTEXT="ctx-openstack"
AWS_KEY_PAIR_NAME="${AWS_KEY_PAIR_NAME:-ztlab-key}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/${AWS_KEY_PAIR_NAME}}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

local_port_open() {
  local port="$1"
  ss -lnt | awk '{print $4}' | grep -Eq "(^|:)${port}$"
}

wait_for_local_port() {
  local port="$1"
  local attempts="${2:-10}"
  local i
  for ((i = 0; i < attempts; i++)); do
    if local_port_open "$port"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_local_port_closed() {
  local port="$1"
  local attempts="${2:-10}"
  local i
  for ((i = 0; i < attempts; i++)); do
    if ! local_port_open "$port"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

inventory_host_var() {
  local host="$1"
  local key="$2"
  ansible-inventory -i "$INVENTORY_FILE" --host "$host" --yaml \
    | awk -F': ' -v k="$key" '$1 == k {print $2; exit}'
}

resolve_targets() {
  AWS_BASTION_IP="$(inventory_host_var aws_bastion ansible_host)"
  AWS_MASTER_IP="$(inventory_host_var aws_k3s_master ansible_host)"
  OS_GATEWAY_IP="$(inventory_host_var os_gateway ansible_host)"
  OS_MASTER_IP="$(inventory_host_var os_k3s_master ansible_host)"

  if [[ -z "$AWS_BASTION_IP" || -z "$AWS_MASTER_IP" || -z "$OS_GATEWAY_IP" || -z "$OS_MASTER_IP" ]]; then
    echo "Unable to resolve tunnel targets from inventory: $INVENTORY_FILE" >&2
    exit 1
  fi
}

start_tunnels() {
  local scope="${1:-all}"
  resolve_targets

  if [[ "$scope" == "all" || "$scope" == "aws" ]]; then
    if local_port_open "$AWS_LOCAL_PORT"; then
      echo "AWS tunnel already listening on 127.0.0.1:${AWS_LOCAL_PORT}; skipping."
    else
      local aws_log="/tmp/ztlab-aws-k8s-tunnel.log"
      setsid ssh -N         -i "$SSH_KEY"         -o ExitOnForwardFailure=yes         -o BatchMode=yes         -o ConnectTimeout="$SSH_CONNECT_TIMEOUT"         -o ConnectionAttempts=1         -o ServerAliveInterval=30         -o ServerAliveCountMax=3         -o UserKnownHostsFile=/dev/null         -o StrictHostKeyChecking=no         -L "127.0.0.1:${AWS_LOCAL_PORT}:127.0.0.1:6443"         -J "${SSH_USER}@${AWS_BASTION_IP}"         "${SSH_USER}@${AWS_MASTER_IP}" >"$aws_log" 2>&1 < /dev/null &
      if ! wait_for_local_port "$AWS_LOCAL_PORT" 20; then
        cat "$aws_log" >&2 2>/dev/null || true
        echo "Failed to start AWS tunnel on 127.0.0.1:${AWS_LOCAL_PORT}" >&2
        exit 1
      fi
    fi
  fi

  if [[ "$scope" == "all" || "$scope" == "openstack" ]]; then
    if local_port_open "$OS_LOCAL_PORT"; then
      echo "OpenStack tunnel already listening on 127.0.0.1:${OS_LOCAL_PORT}; skipping."
    else
      local os_log="/tmp/ztlab-openstack-k8s-tunnel.log"
      setsid ssh -N         -i "$SSH_KEY"         -o ExitOnForwardFailure=yes         -o BatchMode=yes         -o ConnectTimeout="$SSH_CONNECT_TIMEOUT"         -o ConnectionAttempts=1         -o ServerAliveInterval=30         -o ServerAliveCountMax=3         -o UserKnownHostsFile=/dev/null         -o StrictHostKeyChecking=no         -o ProxyCommand="ssh -i ${SSH_KEY} -o BatchMode=yes -o ConnectTimeout=${SSH_CONNECT_TIMEOUT} -o ConnectionAttempts=1 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p ${SSH_USER}@${OS_GATEWAY_IP}"         -L "127.0.0.1:${OS_LOCAL_PORT}:127.0.0.1:6443"         "${SSH_USER}@${OS_MASTER_IP}" >"$os_log" 2>&1 < /dev/null &
      if ! wait_for_local_port "$OS_LOCAL_PORT" 20; then
        cat "$os_log" >&2 2>/dev/null || true
        echo "Failed to start OpenStack tunnel on 127.0.0.1:${OS_LOCAL_PORT}" >&2
        exit 1
      fi
    fi
  fi

  echo "Tunnels started (${scope}):"
  if [[ "$scope" == "all" || "$scope" == "aws" ]]; then
    echo "  AWS       127.0.0.1:${AWS_LOCAL_PORT} -> ${AWS_MASTER_IP}:6443 via ${AWS_BASTION_IP}"
  fi
  if [[ "$scope" == "all" || "$scope" == "openstack" ]]; then
    echo "  OpenStack 127.0.0.1:${OS_LOCAL_PORT} -> ${OS_MASTER_IP}:6443 via ${OS_GATEWAY_IP}"
  fi
}
pull_remote_kubeconfig() {
  local cloud="$1"
  local output_file="$2"

  resolve_targets

  if [[ "$cloud" == "aws" ]]; then
    timeout "$SSH_COMMAND_TIMEOUT" ssh \
      -i "$SSH_KEY" \
      -o UserKnownHostsFile=/dev/null \
      -o StrictHostKeyChecking=no \
      -o BatchMode=yes \
      -o ConnectTimeout="$SSH_CONNECT_TIMEOUT" \
      -o ConnectionAttempts=1 \
      -J "${SSH_USER}@${AWS_BASTION_IP}" \
      "${SSH_USER}@${AWS_MASTER_IP}" \
      "sudo cat /etc/rancher/k3s/k3s.yaml" > "$output_file"
    return
  fi

  if [[ "$cloud" == "openstack" ]]; then
    timeout "$SSH_COMMAND_TIMEOUT" ssh \
      -i "$SSH_KEY" \
      -o UserKnownHostsFile=/dev/null \
      -o StrictHostKeyChecking=no \
      -o BatchMode=yes \
      -o ConnectTimeout="$SSH_CONNECT_TIMEOUT" \
      -o ConnectionAttempts=1 \
      -o ProxyCommand="ssh -i ${SSH_KEY} -o BatchMode=yes -o ConnectTimeout=${SSH_CONNECT_TIMEOUT} -o ConnectionAttempts=1 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -W %h:%p ${SSH_USER}@${OS_GATEWAY_IP}" \
      "${SSH_USER}@${OS_MASTER_IP}" \
      "sudo cat /etc/rancher/k3s/k3s.yaml" > "$output_file"
    return
  fi

  echo "Unsupported cloud value: $cloud" >&2
  exit 1
}

configure_context_from_kubeconfig() {
  local source_kubeconfig="$1"
  local context_name="$2"
  local local_port="$3"
  local tmp_dir="$4"

  local ca_data
  local client_cert_data
  local client_key_data

  ca_data="$(kubectl --kubeconfig "$source_kubeconfig" config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
  client_cert_data="$(kubectl --kubeconfig "$source_kubeconfig" config view --raw -o jsonpath='{.users[0].user.client-certificate-data}')"
  client_key_data="$(kubectl --kubeconfig "$source_kubeconfig" config view --raw -o jsonpath='{.users[0].user.client-key-data}')"

  if [[ -z "$ca_data" || -z "$client_cert_data" || -z "$client_key_data" ]]; then
    echo "Failed to extract kubeconfig certificates for context: $context_name" >&2
    exit 1
  fi

  local ca_file="$tmp_dir/${context_name}-ca.crt"
  local cert_file="$tmp_dir/${context_name}-client.crt"
  local key_file="$tmp_dir/${context_name}-client.key"

  printf '%s' "$ca_data" | base64 -d > "$ca_file"
  printf '%s' "$client_cert_data" | base64 -d > "$cert_file"
  printf '%s' "$client_key_data" | base64 -d > "$key_file"

  kubectl config set-cluster "$context_name" \
    --server="https://127.0.0.1:${local_port}" \
    --certificate-authority="$ca_file" \
    --embed-certs=true >/dev/null

  kubectl config set-credentials "$context_name" \
    --client-certificate="$cert_file" \
    --client-key="$key_file" \
    --embed-certs=true >/dev/null

  kubectl config set-context "$context_name" \
    --cluster="$context_name" \
    --user="$context_name" >/dev/null
}

sync_kubeconfig() {
  local scope="${1:-all}"
  local tmp_dir
  tmp_dir="$(mktemp -d)"

  local aws_source="$tmp_dir/aws-k3s.yaml"
  local os_source="$tmp_dir/openstack-k3s.yaml"

  if [[ "$scope" == "all" || "$scope" == "aws" ]]; then
    pull_remote_kubeconfig aws "$aws_source"
    configure_context_from_kubeconfig "$aws_source" "$AWS_CONTEXT" "$AWS_LOCAL_PORT" "$tmp_dir"
  fi

  if [[ "$scope" == "all" || "$scope" == "openstack" ]]; then
    pull_remote_kubeconfig openstack "$os_source"
    configure_context_from_kubeconfig "$os_source" "$OS_CONTEXT" "$OS_LOCAL_PORT" "$tmp_dir"
  fi

  rm -rf "$tmp_dir"

  echo "Kubeconfig contexts synchronized (${scope})."
}

stop_cloud_tunnel() {
  local cloud="$1"
  resolve_targets

  case "$cloud" in
    aws)
      pkill -f "127.0.0.1:${AWS_LOCAL_PORT}:127.0.0.1:6443" || true
      pkill -f "${AWS_LOCAL_PORT}:${AWS_MASTER_IP}:6443" || true
      pkill -f "127.0.0.1:${AWS_LOCAL_PORT}:${AWS_MASTER_IP}:6443" || true
      wait_for_local_port_closed "$AWS_LOCAL_PORT" 10 || {
        echo "AWS tunnel on port ${AWS_LOCAL_PORT} is still listening after stop attempt." >&2
        return 1
      }
      ;;
    openstack)
      pkill -f "127.0.0.1:${OS_LOCAL_PORT}:127.0.0.1:6443" || true
      pkill -f "${OS_LOCAL_PORT}:${OS_MASTER_IP}:6443" || true
      pkill -f "127.0.0.1:${OS_LOCAL_PORT}:${OS_MASTER_IP}:6443" || true
      wait_for_local_port_closed "$OS_LOCAL_PORT" 10 || {
        echo "OpenStack tunnel on port ${OS_LOCAL_PORT} is still listening after stop attempt." >&2
        return 1
      }
      ;;
    *)
      echo "Unsupported cloud value: $cloud" >&2
      return 1
      ;;
  esac
}

stop_tunnels() {
  local scope="${1:-all}"
  if [[ "$scope" == "all" || "$scope" == "aws" ]]; then
    stop_cloud_tunnel aws || true
  fi
  if [[ "$scope" == "all" || "$scope" == "openstack" ]]; then
    stop_cloud_tunnel openstack || true
  fi
  echo "Tunnels stopped (${scope}, if existed)."
}

kubectl_context_healthy() {
  local context="$1"
  kubectl --context "$context" get --raw=/readyz --request-timeout=10s >/dev/null 2>&1
}

ensure_kubectl_healthy() {
  local scope="${1:-all}"

  if [[ "$scope" == "all" || "$scope" == "aws" ]]; then
    if ! kubectl_context_healthy "$AWS_CONTEXT"; then
      echo "AWS Kubernetes tunnel is not responding; restarting it."
      stop_cloud_tunnel aws
      start_tunnels aws
      if ! kubectl_context_healthy "$AWS_CONTEXT"; then
        sync_kubeconfig aws
        kubectl_context_healthy "$AWS_CONTEXT" || {
          echo "AWS Kubernetes context is still unhealthy after tunnel restart." >&2
          return 1
        }
      fi
    fi
  fi

  if [[ "$scope" == "all" || "$scope" == "openstack" ]]; then
    if ! kubectl_context_healthy "$OS_CONTEXT"; then
      echo "OpenStack Kubernetes tunnel is not responding; restarting it."
      stop_cloud_tunnel openstack
      start_tunnels openstack
      if ! kubectl_context_healthy "$OS_CONTEXT"; then
        sync_kubeconfig openstack
        kubectl_context_healthy "$OS_CONTEXT" || {
          echo "OpenStack Kubernetes context is still unhealthy after tunnel restart." >&2
          return 1
        }
      fi
    fi
  fi
}

show_status() {
  ss -lntp | grep -E ":${AWS_LOCAL_PORT}|:${OS_LOCAL_PORT}" || echo "No active k8s API tunnels found."
}

verify_kubectl() {
  local scope="${1:-all}"
  sync_kubeconfig "$scope"

  if [[ "$scope" == "all" || "$scope" == "aws" ]]; then
    kubectl --context "$AWS_CONTEXT" cluster-info
    kubectl --context "$AWS_CONTEXT" get nodes -o wide
  fi

  if [[ "$scope" == "all" || "$scope" == "openstack" ]]; then
    kubectl --context "$OS_CONTEXT" cluster-info
    kubectl --context "$OS_CONTEXT" get nodes -o wide
  fi
}

usage() {
  cat <<EOF
Usage: $(basename "$0") <up|down|status|verify|sync> [all|aws|openstack]

Env overrides:
  INVENTORY_FILE       Path to Ansible inventory (default: ansible/inventory/hosts.yml)
  SSH_KEY              SSH private key path (default: ~/.ssh/ztlab-key)
  SSH_USER             SSH username (default: ubuntu)
  SSH_CONNECT_TIMEOUT  SSH connect timeout in seconds (default: 10)
  SSH_COMMAND_TIMEOUT  SSH command timeout in seconds (default: 30)
  SYNC_KUBECONFIG_ON_UP Sync kubeconfig during up when true (default: false)
  AWS_K8S_LOCAL_PORT   Local AWS API tunnel port (default: 6444)
  OS_K8S_LOCAL_PORT    Local OpenStack API tunnel port (default: 6445)

Examples:
  $(basename "$0") up openstack
  $(basename "$0") verify openstack
EOF
}

main() {
  need_cmd ansible-inventory
  need_cmd ssh
  need_cmd ss
  need_cmd timeout

  local scope="${2:-all}"
  if [[ "$scope" != "all" && "$scope" != "aws" && "$scope" != "openstack" ]]; then
    echo "Unsupported scope: $scope" >&2
    usage
    exit 1
  fi

  case "${1:-}" in
    up)
      start_tunnels "$scope"
      need_cmd kubectl
      ensure_kubectl_healthy "$scope"
      if [[ "$SYNC_KUBECONFIG_ON_UP" == "true" ]]; then
        sync_kubeconfig "$scope"
        ensure_kubectl_healthy "$scope"
      fi
      ;;
    down)
      stop_tunnels "$scope"
      ;;
    status)
      show_status
      ;;
    verify)
      need_cmd kubectl
      verify_kubectl "$scope"
      ;;
    sync)
      need_cmd kubectl
      sync_kubeconfig "$scope"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
