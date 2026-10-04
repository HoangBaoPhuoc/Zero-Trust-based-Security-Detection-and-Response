#!/usr/bin/env bash
# Khôi phục Postgres/Vault từ backup (Phần 3.4, remediation 2026-09-19).
#
# Dùng:
#   scripts/restore-databases.sh postgres <path-to-dump.sql.gz>
#   scripts/restore-databases.sh vault    <path-to-vault.tar.gz>
set -euo pipefail
WHAT="${1:-}"
FILE="${2:-}"
[[ -n "$WHAT" && -n "$FILE" && -f "$FILE" ]] || {
  echo "Dùng: $0 postgres|vault <backup-file>" >&2; exit 1
}

case "$WHAT" in
  postgres)
    echo "[restore-databases] Postgres — DROP + tạo lại schema từ dump..."
    gunzip -c "$FILE" | kubectl --context ctx-openstack -n crapi exec -i postgresdb-0 -- \
      sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
    echo "[restore-databases] OK — verify nhanh: đếm bảng"
    kubectl --context ctx-openstack -n crapi exec postgresdb-0 -- \
      sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\dt" -t' | grep -c . || true
    ;;
  vault)
    echo "[restore-databases] Vault — GHI ĐÈ /vault/data (cần seal lại + unseal sau khi khôi phục)"
    kubectl --context ctx-aws -n vault scale statefulset/vault --replicas=0
    kubectl --context ctx-aws -n vault wait --for=delete pod/vault-0 --timeout=60s 2>/dev/null || true
    # Dùng 1 pod tạm mount cùng PVC để ghi đè (vault-0 đã bị xoá, PVC còn nguyên)
    kubectl --context ctx-aws -n vault run vault-restore-helper --image=busybox:1.36 --restart=Never \
      --overrides='{"spec":{"containers":[{"name":"vault-restore-helper","image":"busybox:1.36","command":["sleep","120"],"volumeMounts":[{"name":"data","mountPath":"/vault/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-vault-0"}}]}}'
    kubectl --context ctx-aws -n vault wait --for=condition=Ready pod/vault-restore-helper --timeout=60s
    kubectl --context ctx-aws -n vault exec vault-restore-helper -- sh -c 'rm -rf /vault/data/* /vault/data/.[!.]*' 2>/dev/null || true
    kubectl --context ctx-aws -n vault cp "$FILE" vault-restore-helper:/tmp/restore.tar.gz
    kubectl --context ctx-aws -n vault exec vault-restore-helper -- tar xzf /tmp/restore.tar.gz -C /vault/data
    kubectl --context ctx-aws -n vault delete pod vault-restore-helper --wait=true
    kubectl --context ctx-aws -n vault scale statefulset/vault --replicas=1
    kubectl --context ctx-aws -n vault wait --for=condition=Ready pod/vault-0 --timeout=90s
    echo "[restore-databases] Vault pod sẵn sàng — postStart lifecycle hook tự unseal bằng"
    echo "  vault-unseal-keys Secret (xem k8s/vault/vault.yaml). Verify:"
    echo "  kubectl -n vault exec vault-0 -- sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status'"
    ;;
  *) echo "Dùng: $0 postgres|vault <backup-file>" >&2; exit 1 ;;
esac
