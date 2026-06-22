#!/usr/bin/env bash
# Build and sync financial service images to all K3s nodes (AWS + OpenStack)
# so redeploy/recreate does not depend on external registry availability.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INVENTORY_FILE="$REPO_ROOT/ansible/inventory/hosts.yml"
ARCHIVE_PATH="${ARCHIVE_PATH:-/tmp/ztlab-financial-images.tar}"
IMAGE_TAG="${IMAGE_TAG:-1.0.0}"
SKIP_BUILD="${SKIP_BUILD:-false}"
BUILD_PAUSE_SECONDS="${BUILD_PAUSE_SECONDS:-5}"
GROUP_PAUSE_SECONDS="${GROUP_PAUSE_SECONDS:-10}"
MIN_SWAP_SIZE_GB="${MIN_SWAP_SIZE_GB:-8}"
AUTO_INCREASE_SWAP="${AUTO_INCREASE_SWAP:-false}"

SKIP_PUSH_OPENSTACK=false

for arg in "$@"; do
  case "$arg" in
    --skip-push-openstack|--aws-only)
      SKIP_PUSH_OPENSTACK=true
      ;;
    --help|-h)
      echo "Usage: $0 [--skip-push-openstack|--aws-only]"
      exit 0
      ;;
  esac
done

AWS_K3S_TARGETS="aws_k3s_master:aws_k3s_worker_1:aws_k3s_worker_2"
OPENSTACK_K3S_TARGETS="os_k3s_master:os_k3s_worker_1:os_k3s_worker_2"
K3S_TARGETS="$AWS_K3S_TARGETS"
if [[ "$SKIP_PUSH_OPENSTACK" != "true" ]]; then
  K3S_TARGETS="$AWS_K3S_TARGETS:$OPENSTACK_K3S_TARGETS"
fi

BATCHES=()
BATCHES+=("api-gateway payment-service fraud-detection")
BATCHES+=("notification-service core-banking account-service")
BATCHES+=("transaction-service ai-analyzer soar-engine")
BATCHES+=("web-portal security-scorer")

log() {
  echo "[INFO] $*"
}

err() {
  echo "[ERROR] $*" >&2
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Missing required command: $1"
    exit 1
  fi
}

current_swap_gb() {
  local total_kb
  total_kb="$(swapon --show=SIZE --noheadings 2>/dev/null | awk '{gsub(/[^0-9]/, "", $1); sum += $1} END {print sum+0}')"
  awk -v kb="$total_kb" 'BEGIN { printf "%d", kb / 1024 / 1024 }'
}

ensure_swap() {
  local current_swap
  current_swap="$(current_swap_gb)"
  if [[ "$current_swap" -ge "$MIN_SWAP_SIZE_GB" ]]; then
    log "Swap already sufficient (${current_swap}G >= ${MIN_SWAP_SIZE_GB}G)"
    return 0
  fi

  if [[ "$AUTO_INCREASE_SWAP" != "true" ]]; then
    log "Swap is low (${current_swap}G). Run ./scripts/increase-swap.sh to raise it to at least ${MIN_SWAP_SIZE_GB}G."
    return 0
  fi

  log "Swap is low (${current_swap}G). Increasing swap before image sync..."
  "$REPO_ROOT/scripts/increase-swap.sh"
}

build_images() {
  log "Building ztlab/*:${IMAGE_TAG} images in small batches"
  local batch_index=1

  for batch in "${BATCHES[@]}"; do
    log "Starting build batch ${batch_index}: ${batch}"
    for image in $batch; do
      log "Building ztlab/${image}:${IMAGE_TAG}"
      docker build --network host \
        -t "ztlab/${image}:${IMAGE_TAG}" \
        --build-arg SERVICE_NAME="$image" \
        -f "$REPO_ROOT/services/Dockerfile" \
        "$REPO_ROOT"
      sleep "$BUILD_PAUSE_SECONDS"
    done
    batch_index=$((batch_index + 1))
    sleep "$GROUP_PAUSE_SECONDS"
  done
}

save_archive() {
  local batch_index=1

  log "Saving image archives by batch"
  for batch in "${BATCHES[@]}"; do
    local batch_archive="${ARCHIVE_PATH%.tar}.batch${batch_index}.tar"
    local refs=()

    for image in $batch; do
      refs+=("ztlab/${image}:${IMAGE_TAG}")
    done

    log "Saving batch ${batch_index} to ${batch_archive}"
    docker save -o "$batch_archive" "${refs[@]}"
    ls -lh "$batch_archive"
    batch_index=$((batch_index + 1))
    sleep "$GROUP_PAUSE_SECONDS"
  done
}

copy_archive_to_nodes() {
  local batch_index=1

  log "Copying batch archives to K3s nodes"
  for batch in "${BATCHES[@]}"; do
    local batch_archive="${ARCHIVE_PATH%.tar}.batch${batch_index}.tar"
    log "Copying ${batch_archive} to K3s nodes"
    ansible "$K3S_TARGETS" -i "$INVENTORY_FILE" -m copy \
      -a "src=$batch_archive dest=/tmp/$(basename "$batch_archive") mode=0644"
    batch_index=$((batch_index + 1))
  done
}

import_archive_on_nodes() {
  local batch_index=1

  log "Importing batch archives into containerd on all K3s nodes"
  for batch in "${BATCHES[@]}"; do
    local batch_archive="/tmp/$(basename "${ARCHIVE_PATH%.tar}.batch${batch_index}.tar")"
    log "Importing ${batch_archive}"
    ansible "$K3S_TARGETS" -i "$INVENTORY_FILE" -m shell \
      -a "sudo -n ctr -n k8s.io images import ${batch_archive}"
    batch_index=$((batch_index + 1))
    sleep "$GROUP_PAUSE_SECONDS"
  done
}

restart_financial_deployments() {
  log "Restarting financial deployments on ctx-aws"
  kubectl --context ctx-aws -n financial rollout restart deployment || true

  if [[ "$SKIP_PUSH_OPENSTACK" != "true" ]]; then
    log "Restarting financial deployments on ctx-openstack"
    kubectl --context ctx-openstack -n financial rollout restart deployment || true
  else
    log "Skipping ctx-openstack restart (--skip-push-openstack)"
  fi
}

verify_quick() {
  log "Quick check (financial pods)"
  kubectl --context ctx-aws get pods -n financial

  if [[ "$SKIP_PUSH_OPENSTACK" != "true" ]]; then
    echo "---"
    kubectl --context ctx-openstack get pods -n financial
  else
    log "Skipping ctx-openstack pod check (--skip-push-openstack)"
  fi
}

main() {
  require_cmd docker
  require_cmd ansible
  require_cmd kubectl

  if [[ ! -f "$INVENTORY_FILE" ]]; then
    err "Inventory not found: $INVENTORY_FILE"
    exit 1
  fi

  ensure_swap

  if [[ "$SKIP_BUILD" != "true" ]]; then
    build_images
  else
    log "Skipping build step (SKIP_BUILD=true)"
  fi

  save_archive
  copy_archive_to_nodes
  import_archive_on_nodes
  restart_financial_deployments
  verify_quick

  log "Image sync completed"
}

main "$@"
