#!/usr/bin/env bash
# Build and sync financial service images to all K3s nodes (AWS + OpenStack)
# so redeploy/recreate does not depend on external registry availability.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INVENTORY_FILE="$REPO_ROOT/ansible/inventory/hosts.yml"
ARCHIVE_PATH="${ARCHIVE_PATH:-/tmp/ztlab-financial-images.tar}"
IMAGE_TAG="${IMAGE_TAG:-1.0.0}"
SKIP_BUILD="${SKIP_BUILD:-false}"
SKIP_PULL="${SKIP_PULL:-false}"
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
BATCHES+=("transaction-service soar-engine")
BATCHES+=("web-portal security-scorer")
BATCHES+=("ai-analyzer")
# bff (crAPI edge PEP) — chỉ build nếu thư mục tồn tại (thêm ở Phase 2).
if [[ -d "$REPO_ROOT/services/bff" ]]; then
  BATCHES+=("bff")
fi

# Ảnh bên thứ 3 cho crAPI — PULL từ Docker Hub, ghim digest để tái tạo được
# (KE-HOACH-CRAPI.md trục D). Import y hệt luồng save→copy→ctr import.
# Cập nhật digest: chạy scripts/sync-app-images.sh --print-digests
PULL_IMAGES=(
  "crapi/crapi-identity:latest@sha256:5d1db5b3ba8e02bc68711ec6fc4e35ed7cd8b87e63785ece9e7ff5b5e36c5260"
  "crapi/crapi-community:latest@sha256:8ba0c7eda86ae065a673f1fa554d0109a24f25c5a8d65097ae024e5ee715c54e"
  "crapi/crapi-workshop:latest@sha256:d4d2d94d35a31e211b04d5a771881f5ae13e358e8fa0804463ae3bace05dd815"
  "crapi/crapi-web:latest@sha256:b27d246c646bd33898e7d1d2095b6e7576c0993a7b81a73aa7386929493d7151"
  "crapi/mailhog:latest@sha256:015c23f79d40c9dc1800cd0a458503b89aeda3b585a12c37d53829d6c7d61fdd"
  "postgres:14@sha256:156f0b253fd61366d5fc2107ad45955027d5612f695a8436ce20167f3fa79bff"
  "mongo:4.4@sha256:4be76f674fc4b27859816811b8baa3c51830eb1dbf4ca81a51e26b79edd662ef"
)
PULL_ARCHIVE="${PULL_ARCHIVE:-/tmp/ztlab-pull-images.tar}"

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

pull_images() {
  log "Pulling 3rd-party images (crAPI + postgres + mongo), pinned by digest"
  local pulled=()
  for spec in "${PULL_IMAGES[@]}"; do
    local tagref="${spec%@*}"          # crapi/crapi-web:latest  |  postgres:14
    local repo="${tagref%:*}"          # crapi/crapi-web         |  postgres
    local digestref="${repo}@${spec#*@}"   # crapi/crapi-web@sha256:...
    log "docker pull ${digestref}"
    docker pull --platform linux/amd64 "$digestref"
    # Re-tag về :latest để manifest K8s (imagePullPolicy: IfNotPresent) khớp.
    docker tag "$digestref" "$tagref"
    pulled+=("$tagref")
    sleep "$BUILD_PAUSE_SECONDS"
  done
  log "Saving pulled images to ${PULL_ARCHIVE}"
  docker save -o "$PULL_ARCHIVE" "${pulled[@]}"
  ls -lh "$PULL_ARCHIVE"
}

copy_pull_archive_to_nodes() {
  log "Copying ${PULL_ARCHIVE} to K3s nodes"
  ansible "$K3S_TARGETS" -i "$INVENTORY_FILE" -m copy \
    -a "src=$PULL_ARCHIVE dest=/tmp/$(basename "$PULL_ARCHIVE") mode=0644"
}

import_pull_archive_on_nodes() {
  log "Importing ${PULL_ARCHIVE} into containerd on all K3s nodes"
  ansible "$K3S_TARGETS" -i "$INVENTORY_FILE" -m shell \
    -a "sudo -n ctr -n k8s.io images import /tmp/$(basename "$PULL_ARCHIVE")"
}

print_digests() {
  for spec in "${PULL_IMAGES[@]}"; do
    local repo tag; repo="${spec%%:*}"; tag="${spec#*:}"; tag="${tag%@*}"
    local scope="repository:${repo}:pull"
    [[ "$repo" != */* ]] && scope="repository:library/${repo}:pull" && repo="library/${repo}"
    local tok dig
    tok=$(curl -sSL "https://auth.docker.io/token?service=registry.docker.io&scope=${scope}" | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")
    dig=$(curl -sSL -o /dev/null -D - -H "Authorization: Bearer $tok" \
      -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.v2+json" \
      "https://registry-1.docker.io/v2/${repo}/manifests/${tag}" | grep -i '^docker-content-digest:' | awk '{print $2}' | tr -d '\r')
    echo "  \"${spec%@*}@${dig}\""
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

ensure_tunnels_up() {
  log "Ensuring K8s API tunnels are up before restarting deployments"
  local scope="all"
  if [[ "$SKIP_PUSH_OPENSTACK" == "true" ]]; then
    scope="aws"
  fi
  "$REPO_ROOT/scripts/k8s-tunnel.sh" up "$scope"
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
  if [[ "${1:-}" == "--print-digests" ]]; then
    require_cmd curl
    print_digests
    exit 0
  fi

  require_cmd docker
  require_cmd ansible
  require_cmd kubectl

  # --pull-only: bỏ qua build/save/import ảnh finance (đã có sẵn trên node),
  # chỉ pull + import ảnh crAPI/postgres/mongo. Dùng khi thêm crAPI vào cụm
  # đang chạy mà không muốn đụng lại toàn bộ finance images.
  if [[ "${1:-}" == "--pull-only" ]]; then
    if [[ ! -f "$INVENTORY_FILE" ]]; then err "Inventory not found: $INVENTORY_FILE"; exit 1; fi
    pull_images
    copy_pull_archive_to_nodes
    import_pull_archive_on_nodes
    log "Pull-only sync completed"
    exit 0
  fi

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

  if [[ "$SKIP_PULL" != "true" ]]; then
    pull_images
    copy_pull_archive_to_nodes
    import_pull_archive_on_nodes
  else
    log "Skipping 3rd-party image pull (SKIP_PULL=true)"
  fi

  ensure_tunnels_up
  restart_financial_deployments
  verify_quick

  log "Image sync completed"
}

main "$@"
