#!/usr/bin/env bash
# Khôi phục SPIRE server datastore từ backup (Phần 3.3, remediation 2026-09-19).
#
# Dùng:
#   scripts/restore-spire-datastore.sh <aws|openstack> <path-to-backup.sqlite3>
#
# Quy trình: scale spire-server về 0 (tránh ghi đè trong lúc copy — SPIRE
# server là NGUỒN GỐC mọi SVID, dừng phát hành tạm thời trong vài giây chấp
# nhận được, tốt hơn nhiều so với khôi phục nhầm 1 DB đang bị ghi), copy file
# backup đè lên datastore.sqlite3 trên host, scale lại 1, verify bằng chính
# `spire-server entry show` (nguồn sự thật thật, không suy đoán từ log).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="$REPO_ROOT/ansible/inventory/hosts.yml"

CLUSTER="${1:-}"
BACKUP_FILE="${2:-}"
if [[ -z "$CLUSTER" || -z "$BACKUP_FILE" ]]; then
  echo "Dùng: $0 <aws|openstack> <path-to-backup.sqlite3>" >&2
  exit 1
fi
[[ -f "$BACKUP_FILE" ]] || { echo "Không tìm thấy file backup: $BACKUP_FILE" >&2; exit 1; }

case "$CLUSTER" in
  aws) HOST_GROUP="aws_k3s_master"; KCTX="ctx-aws" ;;
  openstack) HOST_GROUP="os_k3s_worker_1"; KCTX="ctx-openstack" ;;
  *) echo "cluster phải là 'aws' hoặc 'openstack'" >&2; exit 1 ;;
esac
REMOTE_DB="/opt/spire/data/server/datastore.sqlite3"
REMOTE_TMP="/tmp/spire-restore-$(date -u +%s).sqlite3"

echo "[restore-spire] Trước khi khôi phục — entry hiện có (để đối chiếu sau):"
BEFORE_COUNT=$(kubectl --context "$KCTX" -n spire exec deploy/spire-server -- \
  /opt/spire/bin/spire-server entry show -socketPath /tmp/spire-server/private/api.sock 2>/dev/null \
  | grep -c '^SPIFFE ID' || echo 0)
echo "  entry hiện tại: $BEFORE_COUNT"

echo "[restore-spire] Scale spire-server ($CLUSTER) về 0..."
kubectl --context "$KCTX" -n spire scale deployment/spire-server --replicas=0
kubectl --context "$KCTX" -n spire wait --for=delete pod -l app=spire-server --timeout=60s 2>/dev/null || true

echo "[restore-spire] Copy file backup lên host + ghi đè datastore..."
ansible "$HOST_GROUP" -i "$INVENTORY" -m copy \
  -a "src=$BACKUP_FILE dest=$REMOTE_TMP mode=0644" >/dev/null
ansible "$HOST_GROUP" -i "$INVENTORY" -m shell -a "
  sudo cp '$REMOTE_DB' '${REMOTE_DB}.pre-restore-$(date -u +%s)'
  sudo cp '$REMOTE_TMP' '$REMOTE_DB'
  sudo rm -f '$REMOTE_TMP'
" --become >/dev/null

echo "[restore-spire] Scale spire-server ($CLUSTER) về 1..."
kubectl --context "$KCTX" -n spire scale deployment/spire-server --replicas=1
kubectl --context "$KCTX" -n spire wait --for=condition=Ready pod -l app=spire-server --timeout=90s

echo "[restore-spire] Verify — entry sau khi khôi phục:"
AFTER_COUNT=$(kubectl --context "$KCTX" -n spire exec deploy/spire-server -- \
  /opt/spire/bin/spire-server entry show -socketPath /tmp/spire-server/private/api.sock 2>/dev/null \
  | grep -c '^SPIFFE ID' || echo 0)
echo "  entry sau khôi phục: $AFTER_COUNT (trước khi khôi phục: $BEFORE_COUNT)"

if [[ "$AFTER_COUNT" -ge 1 ]]; then
  echo "[restore-spire] OK — datastore khôi phục thành công, $AFTER_COUNT entry đọc được."
else
  echo "[restore-spire] CẢNH BÁO — 0 entry sau khôi phục, kiểm tra lại file backup/kết nối." >&2
  exit 1
fi
