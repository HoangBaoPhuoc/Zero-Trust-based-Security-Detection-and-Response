#!/usr/bin/env bash
# All-in-one deploy — chạy toàn bộ Bước 1 → 14 của DEPLOY.md (Phần 1) bằng 1 lệnh,
# từ hạ tầng trống (sau `terraform destroy`) tới cluster chạy đầy đủ ứng dụng.
# Tầng hạ tầng (SSH key, Terraform, Ansible, inventory, tunnel) do script này lo;
# tầng ứng dụng K8s được uỷ quyền cho scripts/deploy-app.sh ở bước cuối.
#
# Idempotent theo thiết kế: chạy lại an toàn sau mỗi lần `terraform destroy` —
# tự bỏ qua các bước đã ở trạng thái đúng (tool đã cài, key-pair đã import,
# image/flavor OpenStack đã tồn tại...) thay vì làm lại từ đầu mỗi lần.
#
# Dùng:
#   bash scripts/deploy-all.sh
#   bash scripts/deploy-all.sh --skip-tools     # bỏ Bước 1 (apt install) — máy đã cài đủ
#   bash scripts/deploy-all.sh --from-step 9    # chạy lại từ 1 bước cụ thể (debug)
#
# Xem DEPLOY.md để biết chi tiết từng bước tương ứng.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SKIP_TOOLS=false
FROM_STEP=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-tools) SKIP_TOOLS=true; shift ;;
    --from-step)  FROM_STEP="$2"; shift 2 ;;
    *) echo "Tham số không hợp lệ: $1"; exit 1 ;;
  esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[FIRST-DEPLOY]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }
step() {
  echo -e "\n${BLUE}══════════════════════════════════════════${NC}"
  echo -e "${BLUE} Bước $1 — $2${NC}"
  echo -e "${BLUE}══════════════════════════════════════════${NC}"
}
run_step() { [[ "$FROM_STEP" -le "$1" ]]; }

START_TS=$(date +%s)

# ─────────────────────────────────────────────────────────
step 1 "Cài công cụ cần thiết"
if run_step 1; then
  if $SKIP_TOOLS; then
    warn "Bỏ qua (--skip-tools)"
  else
    MISSING=()
    for c in ansible ssh ssh-keygen socat curl jq openssl; do
      command -v "$c" >/dev/null || MISSING+=("$c")
    done
    if [[ ${#MISSING[@]} -gt 0 ]]; then
      log "Thiếu: ${MISSING[*]} — cài qua apt"
      sudo apt update
      sudo apt install -y ansible python3-pip python3-venv openssh-client openssh-server \
                          iproute2 coreutils curl jq openssl socat
    else
      ok "Tool cơ bản đã đủ"
    fi

    command -v kubectl >/dev/null || { log "Cài kubectl"; sudo snap install kubectl --classic; }
    command -v terraform >/dev/null || fail "Chưa có terraform — cài thủ công trước (không có trong apt mặc định), xem https://developer.hashicorp.com/terraform/install"
    command -v aws >/dev/null || fail "Chưa có AWS CLI — cài thủ công trước"
    command -v openstack >/dev/null || fail "Chưa có OpenStack CLI — cài thủ công trước (thường qua venv riêng)"

    if ! command -v docker >/dev/null; then
      fail "Chưa có Docker — cài Docker CE trước khi tiếp tục (xem DEPLOY.md Bước 1)"
    fi
    sudo systemctl enable --now docker
    if ! groups "$USER" | grep -q docker; then
      sudo usermod -aG docker "$USER"
      warn "Vừa thêm $USER vào group docker — nếu lệnh docker bên dưới lỗi quyền, đăng xuất/đăng nhập lại rồi chạy lại script với --from-step 2"
    fi
    ok "Bước 1 xong"
  fi
fi

# ─────────────────────────────────────────────────────────
step 2 "Credentials .env"
if run_step 2; then
  [[ -f .env ]] || fail "Không thấy file .env — copy từ .env.template trước"
  set -a; source <(grep -v '^#' .env | grep '='); set +a

  if [[ -z "${AWS_ACCESS_KEY_ID:-}" || -z "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
    warn "Thiếu AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY trong .env"
    read -rp "AWS_ACCESS_KEY_ID: " _akid
    read -rsp "AWS_SECRET_ACCESS_KEY: " _asec; echo
    [[ -n "$_akid" && -n "$_asec" ]] || fail "Không được để trống"
    sed -i "s|^AWS_ACCESS_KEY_ID=.*|AWS_ACCESS_KEY_ID=$_akid|" .env
    sed -i "s|^AWS_SECRET_ACCESS_KEY=.*|AWS_SECRET_ACCESS_KEY=$_asec|" .env
    export AWS_ACCESS_KEY_ID="$_akid" AWS_SECRET_ACCESS_KEY="$_asec"
  fi
  export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-southeast-1}"
  ok "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:0:6}...  region=$AWS_DEFAULT_REGION"

  [[ -n "${OS_AUTH_URL:-}" ]] || fail "Thiếu OS_AUTH_URL trong .env"
  ok "OS_AUTH_URL=$OS_AUTH_URL"
fi

# ─────────────────────────────────────────────────────────
step 3 "SSH key AWS"
if run_step 3; then
  export AWS_KEY_PAIR_NAME="ztlab-key"
  export SSH_KEY="$HOME/.ssh/$AWS_KEY_PAIR_NAME"
  export TF_VAR_key_pair_name="$AWS_KEY_PAIR_NAME"

  [[ -f "$SSH_KEY" ]] || ssh-keygen -t ed25519 -f "$SSH_KEY" -N ""

  if aws ec2 describe-key-pairs --key-names "$AWS_KEY_PAIR_NAME" --region "$AWS_DEFAULT_REGION" >/dev/null 2>&1; then
    ok "Key-pair '$AWS_KEY_PAIR_NAME' đã tồn tại trên AWS — bỏ qua import"
  else
    log "Import key-pair '$AWS_KEY_PAIR_NAME' lên AWS"
    aws ec2 import-key-pair \
      --key-name "$AWS_KEY_PAIR_NAME" \
      --public-key-material fileb://"$SSH_KEY.pub" \
      --region "$AWS_DEFAULT_REGION"
  fi
fi

# ─────────────────────────────────────────────────────────
step 4 "SSH key OpenStack"
if run_step 4; then
  OS_KEY="$HOME/.ssh/zta-siem-soar-key"
  [[ -f "$OS_KEY" ]] || ssh-keygen -t ed25519 -f "$OS_KEY" -N ""

  if openstack keypair show zta-siem-soar-key >/dev/null 2>&1; then
    ok "Key-pair 'zta-siem-soar-key' đã tồn tại trên OpenStack — bỏ qua"
  else
    log "Tạo key-pair 'zta-siem-soar-key' trên OpenStack"
    openstack keypair create --public-key "$OS_KEY.pub" zta-siem-soar-key
  fi
fi

# ─────────────────────────────────────────────────────────
step 5 "Provision AWS (Terraform)"
if run_step 5; then
  terraform -chdir=terraform/aws init -input=false
  terraform -chdir=terraform/aws apply --auto-approve
  ok "AWS apply xong"
fi

# ─────────────────────────────────────────────────────────
step 6 "Image Ubuntu OpenStack"
if run_step 6; then
  if openstack image list -f value -c Name | grep -qx "ubuntu-22.04"; then
    ok "Image 'ubuntu-22.04' đã tồn tại — bỏ qua"
  else
    IMG_FILE="$HOME/ubuntu-22.04.img"
    [[ -f "$IMG_FILE" ]] || wget -O "$IMG_FILE" \
      https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
    openstack image create "ubuntu-22.04" \
      --file "$IMG_FILE" --disk-format qcow2 --container-format bare --public
    ok "Image tạo xong"
  fi
fi

# ─────────────────────────────────────────────────────────
step 7 "Flavor OpenStack"
if run_step 7; then
  EXISTING_FLAVORS=$(openstack flavor list -f value -c Name)
  grep -qx "nano-plus" <<<"$EXISTING_FLAVORS" \
    || openstack flavor create nano-plus --vcpus 1 --ram 1024 --disk 20 --public
  grep -qx "m1.medium" <<<"$EXISTING_FLAVORS" \
    || openstack flavor create m1.medium --vcpus 2 --ram 4096 --disk 40 --public
  ok "Flavor sẵn sàng"
fi

# ─────────────────────────────────────────────────────────
step 8 "Provision OpenStack (Terraform)"
if run_step 8; then
  terraform -chdir=terraform/openstack init -input=false
  terraform -chdir=terraform/openstack apply --auto-approve
  ok "OpenStack apply xong"
fi

# ─────────────────────────────────────────────────────────
step 9 "Cập nhật IP vào Ansible inventory (tự động)"
if run_step 9; then
  AWS_BASTION_IP=$(terraform -chdir=terraform/aws output -raw aws_bastion_pip)
  AWS_GATEWAY_IP=$(terraform -chdir=terraform/aws output -raw aws_gateway_eip)
  OS_GATEWAY_IP=$(terraform -chdir=terraform/openstack output -raw os_gateway_floating_ip)

  [[ -n "$AWS_BASTION_IP" && -n "$AWS_GATEWAY_IP" && -n "$OS_GATEWAY_IP" ]] \
    || fail "Thiếu output Terraform — kiểm tra Bước 5/8 đã apply thành công chưa"

  log "aws_bastion=$AWS_BASTION_IP  aws_gateway=$AWS_GATEWAY_IP  os_gateway=$OS_GATEWAY_IP"

  HOSTS_YML="ansible/inventory/hosts.yml"
  cp "$HOSTS_YML" "$HOSTS_YML.bak"

  python3 - "$HOSTS_YML" "$AWS_BASTION_IP" "$AWS_GATEWAY_IP" "$OS_GATEWAY_IP" <<'PYEOF'
import re, sys

path, bastion_ip, gateway_ip, os_gw_ip = sys.argv[1:5]
content = open(path).read()

content = re.sub(
    r'(aws_bastion:\n\s+ansible_host: )\S+',
    lambda m: m.group(1) + bastion_ip, content, count=1)
content = re.sub(
    r'(aws_gateway:\n\s+ansible_host: )\S+',
    lambda m: m.group(1) + gateway_ip, content, count=1)

marker = '    openstack:\n'
before, _, after = content.partition(marker)
if not _:
    sys.exit("Không tìm thấy marker 'openstack:' trong hosts.yml — cấu trúc file đã thay đổi, sửa tay")

# aws_private / aws_monitoring ProxyJump đều trỏ tới bastion — nằm trước marker openstack:
before = re.sub(r'(-o ProxyJump=ubuntu@)\S+', lambda m: m.group(1) + bastion_ip, before)

# os_gateway ansible_host + os_private ProxyJump — nằm sau marker openstack:
after = re.sub(
    r'(os_gateway:\n\s+ansible_host: )\S+',
    lambda m: m.group(1) + os_gw_ip, after, count=1)
after = re.sub(r'(-o ProxyJump=ubuntu@)\S+', lambda m: m.group(1) + os_gw_ip, after)

open(path, 'w').write(before + marker + after)
print("hosts.yml patched OK")
PYEOF

  ansible-inventory -i "$HOSTS_YML" --host aws_bastion | grep ansible_host
  ansible-inventory -i "$HOSTS_YML" --host os_gateway  | grep ansible_host
  ok "Inventory đã cập nhật (backup: $HOSTS_YML.bak)"
fi

# ─────────────────────────────────────────────────────────
step 10 "Kiểm tra kết nối SSH + Ansible ping"
if run_step 10; then
  log "Chờ SSH sẵn sàng trên toàn bộ node (tối đa 5 phút)..."
  DEADLINE=$(( $(date +%s) + 300 ))
  until ansible -i ansible/inventory/hosts.yml all -m ping >/tmp/ansible-ping.log 2>&1; do
    if [[ $(date +%s) -ge $DEADLINE ]]; then
      cat /tmp/ansible-ping.log
      fail "SSH/ping không thành công sau 5 phút — kiểm tra security group / TF_VAR_key_pair_name (xem bảng lỗi thường gặp trong DEPLOY.md)"
    fi
    sleep 10
  done
  ok "Toàn bộ node phản hồi ping"
fi

# ─────────────────────────────────────────────────────────
step 11 "Ansible provisioning"
if run_step 11; then
  ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/baseline.yml
  ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/wireguard.yml
  ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/k3s.yml
  ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/promtail.yml
  ok "Ansible xong"
fi

# ─────────────────────────────────────────────────────────
step 12 "Tunnel Kubernetes"
if run_step 12; then
  bash scripts/k8s-tunnel.sh up all

  log "Chờ node Ready trên cả 2 cluster (tối đa 3 phút)..."
  DEADLINE=$(( $(date +%s) + 180 ))
  for CTX in ctx-aws ctx-openstack; do
    until kubectl --context "$CTX" get nodes >/dev/null 2>&1; do
      [[ $(date +%s) -lt $DEADLINE ]] || fail "Không kết nối được $CTX — kiểm tra k8s-tunnel.sh status"
      sleep 5
    done
  done
  kubectl config get-contexts
  kubectl --context ctx-aws get nodes
  kubectl --context ctx-openstack get nodes
  ok "Cluster sẵn sàng"
fi

# ─────────────────────────────────────────────────────────
step 13 "Deploy ứng dụng"
if run_step 13; then
  [[ -f "$HOME/kolla-venv/bin/activate" ]] && source "$HOME/kolla-venv/bin/activate"

  IMAGE_TAG=1.0.0 bash scripts/sync-financial-images.sh
  export KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-ztlab-admin-2026}"
  bash scripts/deploy-app.sh

  kubectl --context ctx-aws get pods -A
  kubectl --context ctx-openstack get pods -A
  ok "Deploy ứng dụng xong"
fi

# ─────────────────────────────────────────────────────────
step 14 "Seed data + mở UI"
if run_step 14; then
  python3 tests/seed_db.py
  bash scripts/open-admin-uis.sh
  ss -lnt | grep -E ':(18080|18081|3000|13100|8091|18082|18092|9090|5050|5540)\b' || true
  ok "Seed + UI xong"
fi

ELAPSED=$(( $(date +%s) - START_TS ))
echo -e "\n${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN} First deploy hoàn tất trong $((ELAPSED/60))m $((ELAPSED%60))s${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo "Xem DEPLOY.md Phần 2 cho vận hành hàng ngày (redeploy code, demo, health check)."
