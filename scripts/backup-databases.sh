#!/usr/bin/env bash
# Sao lưu Postgres (dữ liệu người dùng crAPI, OpenStack) + Vault (secret,
# AWS) — Phần 3.4, remediation 2026-09-19. Trước bản sửa này KHÔNG có quy
# trình sao lưu nào cho 2 kho dữ liệu này.
#
# Postgres: pg_dump qua kubectl exec (image postgres chính thức có sẵn
# pg_dump) — dump logic, khôi phục bằng psql, không phụ thuộc PV/node cụ thể.
# Vault: `vault operator raft snapshot` KHÔNG áp dụng (storage backend là
# "file", không phải "raft") — sao lưu bằng cách nén /vault/data trong
# container rồi kubectl cp ra ngoài (Vault image có tar).
#
# Dùng:
#   scripts/backup-databases.sh [postgres|vault|all]   (mặc định: all)
# Ghi ra: deploy/backups/{postgres,vault}/<timestamp>.{sql.gz,tar.gz}
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="$REPO_ROOT/deploy/backups"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${1:-all}"

backup_postgres() {
  echo "[backup-databases] Postgres (OpenStack, crapi/postgresdb-0)..."
  mkdir -p "$BACKUP_ROOT/postgres"
  local dest="$BACKUP_ROOT/postgres/postgres-${TS}.sql.gz"
  # --clean --if-exists: dump tự chứa lệnh DROP trước khi CREATE lại — khôi
  # phục ĐÈ LÊN một DB đã có dữ liệu (rollback) hoặc DB rỗng (disaster
  # recovery) đều chạy sạch, không lỗi "already exists" hàng loạt (đã gặp
  # thật khi test restore lần đầu không có 2 cờ này).
  kubectl --context ctx-openstack -n crapi exec postgresdb-0 -- \
    sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' \
    | gzip > "$dest"
  local size; size="$(du -h "$dest" | cut -f1)"
  echo "[backup-databases] OK: $dest ($size)"
}

backup_vault() {
  echo "[backup-databases] Vault (AWS, vault/vault-0, file storage backend)..."
  mkdir -p "$BACKUP_ROOT/vault"
  local dest="$BACKUP_ROOT/vault/vault-${TS}.tar.gz"
  kubectl --context ctx-aws -n vault exec vault-0 -- \
    tar czf - -C /vault/data . > "$dest"
  local size; size="$(du -h "$dest" | cut -f1)"
  echo "[backup-databases] OK: $dest ($size)"
  echo "[backup-databases] LƯU Ý: file này chứa secret đã MÃ HOÁ bằng khoá Vault"
  echo "  (không phải plaintext) — nhưng unseal key (Secret vault-unseal-keys, K8s)"
  echo "  mới là thứ THẬT SỰ mở được nó. Backup 2 thứ CÙNG NHAU (xem 3.7)."
}

case "$TARGET" in
  postgres) backup_postgres ;;
  vault) backup_vault ;;
  all) backup_postgres; backup_vault ;;
  *) echo "Dùng: $0 [postgres|vault|all]" >&2; exit 1 ;;
esac
