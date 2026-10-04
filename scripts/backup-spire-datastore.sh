#!/usr/bin/env bash
# Sao lưu SPIRE server datastore (Phần 3.3, remediation 2026-09-19).
#
# SPIRE server: sqlite3 trên hostPath (/opt/spire/data/server/datastore.sqlite3),
# 1 bản duy nhất, strategy: Recreate (spire/k8s/server-deployment.yaml) — mất
# node đó là mất TOÀN BỘ registry danh tính (mọi SPIRE entry: workload SVID
# nào được cấp cho ai). Không có backup/restore trước bản sửa này.
#
# Dùng sqlite3 CLI TRÊN HOST (không phải trong container spire-server — ảnh
# đó tối giản, không có shell/sqlite3) chạy lệnh `.backup` chính thức của
# SQLite (an toàn với DB đang ghi — khác hẳn `cp` thô có thể chụp giữa lúc
# transaction dở dang) trực tiếp lên file hostPath.
#
# Dùng:
#   scripts/backup-spire-datastore.sh [aws|openstack|all]   (mặc định: all)
#
# Ghi ra: deploy/backups/spire/<cluster>/spire-<cluster>-<UTC timestamp>.sqlite3
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="$REPO_ROOT/ansible/inventory/hosts.yml"
BACKUP_ROOT="$REPO_ROOT/deploy/backups/spire"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${1:-all}"

REMOTE_DB="/opt/spire/data/server/datastore.sqlite3"
REMOTE_TMP="/tmp/spire-backup-${TS}.sqlite3"

backup_one() {
  local cluster="$1" host_group="$2"
  echo "[backup-spire] $cluster ($host_group) — sqlite3 .backup..."
  ansible "$host_group" -i "$INVENTORY" -m shell -a "
    command -v sqlite3 >/dev/null 2>&1 || sudo apt-get install -y -qq sqlite3 >/dev/null
    sudo sqlite3 '$REMOTE_DB' '.backup $REMOTE_TMP'
    sudo chmod 644 '$REMOTE_TMP'
  " --become-user=root 2>&1 | grep -v "^$" || { echo "[backup-spire] LỖI khi backup $cluster trên node — bỏ qua cluster này"; return 1; }

  mkdir -p "$BACKUP_ROOT/$cluster"
  local dest="$BACKUP_ROOT/$cluster/spire-${cluster}-${TS}.sqlite3"
  ansible "$host_group" -i "$INVENTORY" -m fetch \
    -a "src=$REMOTE_TMP dest=$dest flat=yes" >/dev/null
  ansible "$host_group" -i "$INVENTORY" -m file -a "path=$REMOTE_TMP state=absent" --become >/dev/null 2>&1 || true

  if [[ -f "$dest" ]]; then
    local size
    size="$(du -h "$dest" | cut -f1)"
    echo "[backup-spire] OK: $dest ($size)"
  else
    echo "[backup-spire] LỖI: không thấy file backup sau khi fetch ($cluster)" >&2
    return 1
  fi
}

case "$TARGET" in
  aws) backup_one aws aws_k3s_master ;;
  openstack) backup_one openstack os_k3s_worker_1 ;;
  all)
    backup_one aws aws_k3s_master
    backup_one openstack os_k3s_worker_1
    ;;
  *) echo "Dùng: $0 [aws|openstack|all]" >&2; exit 1 ;;
esac

echo "[backup-spire] Xong. Danh sách backup hiện có:"
find "$BACKUP_ROOT" -name '*.sqlite3' -newer /dev/null 2>/dev/null | sort | tail -10
