#!/usr/bin/env bash
# Create or resize a swapfile on the local machine.
# Default size is 8G, configurable with SWAP_SIZE.

set -euo pipefail

SWAP_SIZE="${SWAP_SIZE:-8G}"
SWAP_FILE="${SWAP_FILE:-/swapfile}"

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

current_swap_total() {
  if command -v swapon >/dev/null 2>&1; then
    swapon --show=SIZE --noheadings 2>/dev/null | awk 'BEGIN{sum=0} {gsub(/[^0-9]/, "", $1); if ($1 ~ /^[0-9]+$/) sum += $1} END{print sum}'
  else
    echo 0
  fi
}

size_to_bytes() {
  local value="$1"
  python3 - <<'PY' "$value"
import re, sys
value = sys.argv[1].strip().upper()
match = re.fullmatch(r"([0-9]+)([KMGTP]?)", value)
if not match:
    raise SystemExit(f"Invalid size: {value}")
number = int(match.group(1))
unit = match.group(2)
multiplier = {
    '': 1,
    'K': 1024,
    'M': 1024**2,
    'G': 1024**3,
    'T': 1024**4,
    'P': 1024**5,
}[unit]
print(number * multiplier)
PY
}

ensure_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      exec sudo -E "$0" "$@"
    fi
    err "This script must be run as root or with sudo"
    exit 1
  fi
}

main() {
  require_cmd fallocate
  require_cmd chmod
  require_cmd mkswap
  require_cmd swapon
  require_cmd awk

  if [[ "${EUID}" -ne 0 ]]; then
    ensure_root "$@"
  fi

  local target_bytes current_bytes
  target_bytes="$(size_to_bytes "$SWAP_SIZE")"
  current_bytes="$(current_swap_total)"

  if [[ -f "$SWAP_FILE" ]]; then
    local existing_bytes
    existing_bytes="$(stat -c%s "$SWAP_FILE")"
    if [[ "$existing_bytes" -ge "$target_bytes" ]]; then
      log "Swapfile already exists at ${SWAP_FILE} with size >= ${SWAP_SIZE}"
      swapon --show
      exit 0
    fi
    log "Resizing existing swapfile ${SWAP_FILE} to ${SWAP_SIZE}"
    swapoff "$SWAP_FILE" || true
    rm -f "$SWAP_FILE"
  else
    log "Creating swapfile ${SWAP_FILE} with size ${SWAP_SIZE}"
  fi

  fallocate -l "$SWAP_SIZE" "$SWAP_FILE"
  chmod 600 "$SWAP_FILE"
  mkswap "$SWAP_FILE" >/dev/null
  swapon "$SWAP_FILE"
  log "Swap enabled"
  swapon --show
}

main "$@"
