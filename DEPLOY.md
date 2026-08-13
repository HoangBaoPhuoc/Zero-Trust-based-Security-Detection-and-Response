# Hướng dẫn Deploy Lần Đầu

Làm theo thứ tự từ trên xuống. Mỗi bước phải hoàn thành trước khi sang bước tiếp theo.

---

## Bước 1 — Cài công cụ cần thiết

```bash
sudo apt update
sudo apt install -y ansible python3-pip python3-venv openssh-client openssh-server \
                    iproute2 coreutils curl jq openssl socat

# Cài kubectl
sudo snap install kubectl --classic

# Cài Docker nếu chưa có
command -v docker >/dev/null || echo "Chưa có Docker — cài Docker CE trước khi tiếp tục"
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
newgrp docker   # nạp group ngay, không cần đăng xuất
```

---

## Bước 2 — Điền credentials vào file .env

Mở file `.env` và điền các giá trị còn trống:

```
AWS_ACCESS_KEY_ID=<Access Key từ AWS IAM>
AWS_SECRET_ACCESS_KEY=<Secret Key từ AWS IAM>
```

> Lấy key tại: AWS Console → IAM → Security credentials → Create access key → chọn CLI

Sau khi điền xong, load file .env vào terminal:

```bash
export $(grep -v '^#' .env | xargs)
```

Kiểm tra đã load đúng chưa:

```bash
echo $AWS_ACCESS_KEY_ID   # phải hiện key, không được trống
```

---

## Bước 3 — Tạo SSH key cho AWS

Mỗi người deploy tạo key riêng với tên theo format `ztlab-key-<tháng><năm>`:

```bash
# Đặt tên key (thay 0726 bằng tháng/năm của bạn)
export AWS_KEY_PAIR_NAME="ztlab-key-0726"
export SSH_KEY="$HOME/.ssh/$AWS_KEY_PAIR_NAME"
export TF_VAR_key_pair_name="$AWS_KEY_PAIR_NAME"

# Tạo key trên máy
ssh-keygen -t ed25519 -f "$SSH_KEY" -N ""

# Kiểm tra
ls -l "$SSH_KEY" "$SSH_KEY.pub"
```

Upload public key lên AWS:

```bash
aws ec2 import-key-pair \
  --key-name "$AWS_KEY_PAIR_NAME" \
  --public-key-material fileb://"$SSH_KEY.pub" \
  --region ap-southeast-1

# Kiểm tra đã upload chưa
aws ec2 describe-key-pairs --key-names "$AWS_KEY_PAIR_NAME" --region ap-southeast-1
```

---

## Bước 4 — Tạo SSH key cho OpenStack

```bash
# Tạo key trên máy (nếu chưa có)
[[ -f ~/.ssh/zta-siem-soar-key ]] || ssh-keygen -t ed25519 -f ~/.ssh/zta-siem-soar-key -N ""

# Kiểm tra OpenStack có kết nối được không
echo $OS_AUTH_URL   # phải là http://192.168.1.254:5000/v3

# Upload lên OpenStack
openstack keypair create --public-key ~/.ssh/zta-siem-soar-key.pub zta-siem-soar-key
```

---

## Bước 5 — Provision hạ tầng AWS bằng Terraform

```bash
# Khởi tạo Terraform (tải provider)
terraform -chdir=terraform/aws init

# Tạo hạ tầng
terraform -chdir=terraform/aws apply --auto-approve

# Kiểm tra output sau khi xong
terraform -chdir=terraform/aws output -json | jq '.aws_instances, .aws_k3s_api_tunnel'
```

---

## Bước 6 — Upload image Ubuntu vào OpenStack

Terraform cần image `ubuntu-22.04` có sẵn trong OpenStack. Kiểm tra trước:

```bash
openstack image list
```

Nếu trống, upload image:

```bash
# Tải image Ubuntu 22.04 (khoảng 600MB) — openstack snap không đọc được /tmp nên lưu về ~
wget -O ~/ubuntu-22.04.img \
  https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img

# Upload lên OpenStack
openstack image create "ubuntu-22.04" \
  --file ~/ubuntu-22.04.img \
  --disk-format qcow2 \
  --container-format bare \
  --public

# Kiểm tra đã có chưa
openstack image list
```

---

## Bước 6.1 — Tạo flavor cho OpenStack

Terraform cần 2 flavor: `nano-plus` và `m1.medium`. Kiểm tra trước:

```bash
openstack flavor list
```

Nếu trống, tạo mới:

```bash
# nano-plus: dùng cho gateway và identity (1 vCPU, 1GB RAM, 20GB disk)
openstack flavor create nano-plus \
  --vcpus 1 --ram 1024 --disk 20 --public

# m1.medium: dùng cho k3s master và worker (2 vCPU, 4GB RAM, 40GB disk)
openstack flavor create m1.medium \
  --vcpus 2 --ram 4096 --disk 40 --public

# Kiểm tra
openstack flavor list
```

---

## Bước 7 — Provision hạ tầng OpenStack bằng Terraform

```bash
terraform -chdir=terraform/openstack init
terraform -chdir=terraform/openstack apply --auto-approve

terraform -chdir=terraform/openstack output -json | jq '.openstack_instances, .openstack_k3s_api_tunnel'
```

---

## Bước 8 — Cập nhật IP vào Ansible inventory

Sau mỗi lần terraform apply, IP của các máy thay đổi — phải cập nhật thủ công vào `ansible/inventory/hosts.yml`.

Lấy IP mới từ terraform output:

```bash
terraform -chdir=terraform/aws output aws_bastion_pip        # IP bastion AWS
terraform -chdir=terraform/aws output aws_gateway_eip        # EIP gateway AWS
terraform -chdir=terraform/openstack output os_gateway_floating_ip  # Floating IP gateway OpenStack
```

Mở file `ansible/inventory/hosts.yml` và cập nhật các dòng sau:

```yaml
aws_bastion:
  ansible_host: <aws_bastion_pip>       # thay bằng IP mới

aws_gateway:
  ansible_host: <aws_gateway_eip>       # thay bằng EIP mới

# ProxyJump AWS (xuất hiện 2 lần trong file)
-o ProxyJump=ubuntu@<aws_bastion_pip>

os_gateway:
  ansible_host: <os_gateway_floating_ip>  # thay bằng floating IP mới

# ProxyJump OpenStack
-o ProxyJump=ubuntu@<os_gateway_floating_ip>
```

Kiểm tra inventory đã đúng chưa:

```bash
ansible-inventory -i ansible/inventory/hosts.yml --host aws_bastion | grep ansible_host
ansible-inventory -i ansible/inventory/hosts.yml --host os_gateway  | grep ansible_host
```

---

## Bước 9 — Kiểm tra kết nối SSH

```bash
AWS_BASTION_IP=$(terraform -chdir=terraform/aws output -raw aws_bastion_pip)
OS_GATEWAY_IP=$(terraform -chdir=terraform/openstack output -raw os_gateway_floating_ip)

# SSH thử từng node
ssh -i "$SSH_KEY" -o ConnectTimeout=10 ubuntu@$AWS_BASTION_IP echo "bastion OK"
ssh -i ~/.ssh/zta-siem-soar-key -o ConnectTimeout=10 ubuntu@$OS_GATEWAY_IP echo "os_gateway OK"
ssh -i "$SSH_KEY" -o ProxyJump=ubuntu@$AWS_BASTION_IP ubuntu@10.10.1.10 echo "k3s-master OK"

# Kiểm tra toàn bộ inventory
ansible -i ansible/inventory/hosts.yml all -m ping
```

---

## Bước 10 — Chạy Ansible provisioning

Thứ tự chạy các playbook:

```bash
# 1. Cài gói cơ bản trên tất cả các node
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/baseline.yml

# 2. Cài WireGuard VPN giữa AWS gateway và OpenStack gateway
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/wireguard.yml

# 3. Cài k3s lên các node Kubernetes
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/k3s.yml

# 4. Cài Promtail (log shipping)
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/promtail.yml
```

---

## Bước 11 — Tạo tunnel Kubernetes và kiểm tra cluster

```bash
# Tạo tunnel SSH đến k3s API server
bash scripts/k8s-tunnel.sh up all

# Kiểm tra 2 cluster đã kết nối chưa
kubectl config get-contexts
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

---

## Bước 8 — Deploy ứng dụng

```bash
# Bật venv
source ~/kolla-venv/bin/activate

# Build và copy image vào các node
IMAGE_TAG=1.0.0 bash scripts/sync-financial-images.sh

# Kiểm tra image
docker images | grep '^ztlab/'

# Deploy toàn bộ hệ thống
export KEYCLOAK_ADMIN_PASSWORD=ztlab-admin-2026
bash scripts/deploy-all.sh

# Kiểm tra pods trên 2 cluster
kubectl --context ctx-aws get pods -A
kubectl --context ctx-openstack get pods -A
```

---

## Bước 9 — Seed data và mở UI

```bash
# Nạp dữ liệu mẫu
python3 tests/seed_db.py

# Mở port-forward cho các UI
bash scripts/open-admin-uis.sh

# Kiểm tra các port đã mở
ss -lnt | grep -E ':(18080|18081|3000|13100|8091|18082|18092|9090|5050|5540)\b'
```

---

## Xử lý lỗi thường gặp

| Lỗi | Nguyên nhân | Cách fix |
|-----|-------------|----------|
| `No valid credential sources found` | Chưa load .env hoặc key trống | Chạy lại `export $(grep -v '^#' .env | xargs)` |
| `terraform output` ra `null` | Chưa `terraform apply` hoặc sai thư mục | Chạy đúng `-chdir=terraform/aws` hoặc `openstack` |
| `kubectl config get-contexts` trống | Chưa chạy tunnel | Chạy `bash scripts/k8s-tunnel.sh up all` |
| `docker ps` báo lỗi quyền | Chưa thêm user vào group docker | Chạy `sudo usermod -aG docker $USER && newgrp docker` |
| SSH timeout | Security group chưa mở port 22 | Kiểm tra `admin_ip` trong terraform variables |
