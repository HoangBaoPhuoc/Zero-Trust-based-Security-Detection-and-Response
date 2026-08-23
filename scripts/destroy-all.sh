#!/usr/bin/env bash
# All-in-one destroy — gỡ toàn bộ hạ tầng AWS + OpenStack (Phần 3 của DEPLOY.md) bằng 1 lệnh.
#
# Mặc định GIỮ LẠI: SSH key-pair (ztlab-key / zta-siem-soar-key) và image/flavor
# OpenStack — để lần `deploy-all.sh` kế tiếp không phải tạo/upload lại từ đầu.
# Dùng --purge-all (hoặc từng cờ riêng) nếu muốn dọn sạch hẳn.
#
# Dùng:
#   bash scripts/destroy-all.sh                # destroy hạ tầng, giữ key-pair + image/flavor
#   bash scripts/destroy-all.sh --yes           # bỏ qua xác nhận (dùng trong tự động hoá)
#   bash scripts/destroy-all.sh --only aws      # chỉ destroy AWS
#   bash scripts/destroy-all.sh --only openstack
#   bash scripts/destroy-all.sh --purge-keys    # xoá luôn SSH key-pair trên AWS/OpenStack
#   bash scripts/destroy-all.sh --purge-image   # xoá luôn OpenStack image ubuntu-22.04 + flavor
#   bash scripts/destroy-all.sh --purge-all     # xoá sạch (key-pair + image/flavor)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ASSUME_YES=false
ONLY="all"
PURGE_KEYS=false
PURGE_IMAGE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)      ASSUME_YES=true; shift ;;
    --only)        ONLY="$2"; shift 2 ;;
    --purge-keys)  PURGE_KEYS=true; shift ;;
    --purge-image) PURGE_IMAGE=true; shift ;;
    --purge-all)   PURGE_KEYS=true; PURGE_IMAGE=true; shift ;;
    *) echo "Tham số không hợp lệ: $1"; exit 1 ;;
  esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[DESTROY]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }

[[ -f .env ]] || fail "Không thấy file .env"
set -a; source <(grep -v '^#' .env | grep '='); set +a
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-southeast-1}"
AWS_KEY_PAIR_NAME="${AWS_KEY_PAIR_NAME:-ztlab-key}"

if ! $ASSUME_YES; then
  echo -e "${RED}Sắp destroy hạ tầng ($ONLY) — KHÔNG thể hoàn tác. Toàn bộ VM/dữ liệu trên cluster sẽ mất.${NC}"
  read -rp "Gõ 'destroy' để xác nhận: " CONFIRM
  [[ "$CONFIRM" == "destroy" ]] || fail "Huỷ — không khớp xác nhận"
fi

log "Dừng tunnel/port-forward đang chạy"
pkill -f "kubectl.*port-forward" 2>/dev/null || true
bash scripts/k8s-tunnel.sh down all 2>/dev/null || true
ok "Đã dừng tunnel"

if [[ "$ONLY" == "all" || "$ONLY" == "aws" ]]; then
  log "Destroy AWS"
  terraform -chdir=terraform/aws destroy --auto-approve
  ok "AWS destroy xong"
fi

if [[ "$ONLY" == "all" || "$ONLY" == "openstack" ]]; then
  log "Destroy OpenStack"
  terraform -chdir=terraform/openstack destroy --auto-approve
  ok "OpenStack destroy xong"
fi

if $PURGE_KEYS; then
  log "Xoá SSH key-pair (--purge-keys)"
  aws ec2 delete-key-pair --key-name "$AWS_KEY_PAIR_NAME" --region "$AWS_DEFAULT_REGION" 2>/dev/null \
    && ok "Đã xoá AWS key-pair '$AWS_KEY_PAIR_NAME'" \
    || warn "AWS key-pair '$AWS_KEY_PAIR_NAME' không tồn tại hoặc đã xoá"
  openstack keypair delete zta-siem-soar-key 2>/dev/null \
    && ok "Đã xoá OpenStack key-pair 'zta-siem-soar-key'" \
    || warn "OpenStack key-pair 'zta-siem-soar-key' không tồn tại hoặc đã xoá"
else
  log "Giữ lại SSH key-pair (dùng --purge-keys để xoá) — deploy-all.sh lần sau sẽ tái dùng, không phải import lại"
fi

if $PURGE_IMAGE; then
  log "Xoá OpenStack image/flavor (--purge-image)"
  openstack image delete ubuntu-22.04 2>/dev/null && ok "Đã xoá image ubuntu-22.04" || warn "Image không tồn tại"
  openstack flavor delete nano-plus m1.medium 2>/dev/null && ok "Đã xoá flavor" || warn "Flavor không tồn tại"
else
  log "Giữ lại OpenStack image/flavor (dùng --purge-image để xoá) — deploy-all.sh lần sau khỏi upload lại ~600MB"
fi

echo -e "\n${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN} Destroy hoàn tất ($ONLY)${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
terraform -chdir=terraform/aws output 2>&1 | head -3 || true
terraform -chdir=terraform/openstack output 2>&1 | head -3 || true
echo "Chạy 'bash scripts/deploy-all.sh' khi muốn dựng lại."
