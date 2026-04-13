#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY_FILE="${INVENTORY_FILE:-$ROOT_DIR/ansible/inventory/hosts.yml}"
SSH_USER="${SSH_USER:-ubuntu}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/zta-siem-soar-key}"
AWS_LOCAL_PORT="${AWS_K8S_LOCAL_PORT:-6444}"
OS_LOCAL_PORT="${OS_K8S_LOCAL_PORT:-6443}"

AWS_CONTEXT="ctx-aws"
OS_CONTEXT="ctx-openstack"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
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
  resolve_targets

  ssh -fN \
    -i "$SSH_KEY" \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -o StrictHostKeyChecking=no \
    -L "127.0.0.1:${AWS_LOCAL_PORT}:127.0.0.1:6443" \
    -J "${SSH_USER}@${AWS_BASTION_IP}" \
    "${SSH_USER}@${AWS_MASTER_IP}"

  ssh -fN \
    -i "$SSH_KEY" \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -o UserKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=no \
    -L "127.0.0.1:${OS_LOCAL_PORT}:127.0.0.1:6443" \
    -J "${SSH_USER}@${OS_GATEWAY_IP}" \
    "${SSH_USER}@${OS_MASTER_IP}"

  echo "Tunnels started:"
  echo "  AWS       127.0.0.1:${AWS_LOCAL_PORT} -> ${AWS_MASTER_IP}:6443 via ${AWS_BASTION_IP}"
  echo "  OpenStack 127.0.0.1:${OS_LOCAL_PORT} -> ${OS_MASTER_IP}:6443 via ${OS_GATEWAY_IP}"
}

pull_remote_kubeconfig() {
  local cloud="$1"
  local output_file="$2"

  resolve_targets

  if [[ "$cloud" == "aws" ]]; then
    ssh \
      -i "$SSH_KEY" \
      -o StrictHostKeyChecking=no \
      -J "${SSH_USER}@${AWS_BASTION_IP}" \
      "${SSH_USER}@${AWS_MASTER_IP}" \
      "sudo cat /etc/rancher/k3s/k3s.yaml" > "$output_file"
    return
  fi

  if [[ "$cloud" == "openstack" ]]; then
    ssh \
      -i "$SSH_KEY" \
      -o UserKnownHostsFile=/dev/null \
      -o StrictHostKeyChecking=no \
      -J "${SSH_USER}@${OS_GATEWAY_IP}" \
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
  local tmp_dir
  tmp_dir="$(mktemp -d)"

  local aws_source="$tmp_dir/aws-k3s.yaml"
  local os_source="$tmp_dir/openstack-k3s.yaml"

  pull_remote_kubeconfig aws "$aws_source"
  pull_remote_kubeconfig openstack "$os_source"

  configure_context_from_kubeconfig "$aws_source" "$AWS_CONTEXT" "$AWS_LOCAL_PORT" "$tmp_dir"
  configure_context_from_kubeconfig "$os_source" "$OS_CONTEXT" "$OS_LOCAL_PORT" "$tmp_dir"

  rm -rf "$tmp_dir"

  echo "Kubeconfig contexts synchronized: ${AWS_CONTEXT}, ${OS_CONTEXT}"
}

stop_tunnels() {
  pkill -f "127.0.0.1:${AWS_LOCAL_PORT}:127.0.0.1:6443" || true
  pkill -f "127.0.0.1:${OS_LOCAL_PORT}:127.0.0.1:6443" || true
  echo "Tunnels stopped (if existed)."
}

show_status() {
  ss -lntp | grep -E ":${AWS_LOCAL_PORT}|:${OS_LOCAL_PORT}" || echo "No active k8s API tunnels found."
}

verify_kubectl() {
  sync_kubeconfig
  kubectl --context "$AWS_CONTEXT" cluster-info
  kubectl --context "$OS_CONTEXT" cluster-info
  kubectl --context "$AWS_CONTEXT" get nodes -o wide
  kubectl --context "$OS_CONTEXT" get nodes -o wide
}

usage() {
  cat <<EOF
Usage: $(basename "$0") <up|down|status|verify|sync>

Env overrides:
  INVENTORY_FILE       Path to Ansible inventory (default: ansible/inventory/hosts.yml)
  SSH_KEY              SSH private key path (default: ~/.ssh/zta-siem-soar-key)
  SSH_USER             SSH username (default: ubuntu)
  AWS_K8S_LOCAL_PORT   Local AWS API tunnel port (default: 6444)
  OS_K8S_LOCAL_PORT    Local OpenStack API tunnel port (default: 6443)
EOF
}

main() {
  need_cmd ansible-inventory
  need_cmd ssh
  need_cmd ss

  case "${1:-}" in
    up)
      start_tunnels
      need_cmd kubectl
      sync_kubeconfig
      ;;
    down)
      stop_tunnels
      ;;
    status)
      show_status
      ;;
    verify)
      need_cmd kubectl
      verify_kubectl
      ;;
    sync)
      need_cmd kubectl
      sync_kubeconfig
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
