# ZTLab — Deploy Handbook

Một file duy nhất cho cả 2 tình huống:

- **[Phần 1 — First Deploy](#phần-1--first-deploy-từ-số-0)**: máy hoàn toàn mới, chưa có gì, dựng hạ tầng từ đầu.
- **[Phần 2 — Redeploy / Vận hành hàng ngày](#phần-2--redeploy--vận-hành-hàng-ngày)**: hạ tầng đã tồn tại, chỉ cần bật lại sau khi tắt máy, hoặc đẩy 1 thay đổi code lên cluster đang chạy.
- **[Phần 3 — Destroy](#phần-3--destroy--gỡ-bỏ-hoàn-toàn)**: gỡ bỏ hoàn toàn hạ tầng (khác với "tắt máy" ở Phần 2 — destroy xoá hẳn, không bật lại được, phải First Deploy lại từ đầu).

Nếu không chắc mình ở tình huống nào: chạy `kubectl config get-contexts` — nếu có `ctx-aws`/`ctx-openstack` và `kubectl --context ctx-aws get nodes` trả về node thật, bạn đang ở Phần 2.

---

## Phần 1 — First Deploy (từ số 0)

> **Rút gọn:** `bash scripts/deploy-all.sh` chạy tự động toàn bộ Bước 1→14 bên dưới (idempotent — chạy lại an toàn sau mỗi lần destroy, tự bỏ qua phần đã đúng trạng thái như tool đã cài, key-pair/image/flavor đã tồn tại). Dùng `--skip-tools` nếu máy đã cài đủ công cụ, `--from-step N` để chạy lại từ 1 bước cụ thể khi debug. Các bước dưới đây vẫn giữ để tham khảo/debug khi script dừng giữa chừng.
>
> Lưu ý phân biệt: `deploy-all.sh` = hạ tầng (Terraform/Ansible) + ứng dụng, dùng khi bắt đầu từ hạ tầng trống. `scripts/deploy-app.sh` (Bước 13 bên dưới) chỉ deploy lại tầng ứng dụng K8s, dùng khi VM/cluster đã có sẵn — `deploy-all.sh` tự gọi nó ở bước cuối.

Làm theo thứ tự từ trên xuống. Mỗi bước phải hoàn thành trước khi sang bước tiếp theo.

### Bước 1 — Cài công cụ cần thiết

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

### Bước 2 — Điền credentials vào file .env

Mở file `.env` và điền các giá trị còn trống:

```
AWS_ACCESS_KEY_ID=<Access Key từ AWS IAM>
AWS_SECRET_ACCESS_KEY=<Secret Key từ AWS IAM>
```

> Lấy key tại: AWS Console → IAM → Security credentials → Create access key → chọn CLI

```bash
export $(grep -v '^#' .env | xargs)
echo $AWS_ACCESS_KEY_ID   # phải hiện key, không được trống
```

### Bước 3 — Tạo SSH key cho AWS

```bash
export AWS_KEY_PAIR_NAME="ztlab-key-0726"   # thay 0726 bằng tháng/năm của bạn
export SSH_KEY="$HOME/.ssh/$AWS_KEY_PAIR_NAME"
export TF_VAR_key_pair_name="$AWS_KEY_PAIR_NAME"

ssh-keygen -t ed25519 -f "$SSH_KEY" -N ""
ls -l "$SSH_KEY" "$SSH_KEY.pub"

aws ec2 import-key-pair \
  --key-name "$AWS_KEY_PAIR_NAME" \
  --public-key-material fileb://"$SSH_KEY.pub" \
  --region ap-southeast-1

aws ec2 describe-key-pairs --key-names "$AWS_KEY_PAIR_NAME" --region ap-southeast-1
```

> **Gotcha đã gặp:** `TF_VAR_key_pair_name` PHẢI khớp đúng key vừa import — Terraform không tự phát hiện key-pair sai tên, nó sẽ tạo instance nhưng SSH sẽ timeout ở Bước 9 mà không có lỗi rõ ràng.

### Bước 4 — Tạo SSH key cho OpenStack

```bash
[[ -f ~/.ssh/zta-siem-soar-key ]] || ssh-keygen -t ed25519 -f ~/.ssh/zta-siem-soar-key -N ""

echo $OS_AUTH_URL   # phải là http://192.168.1.254:5000/v3
openstack keypair create --public-key ~/.ssh/zta-siem-soar-key.pub zta-siem-soar-key
```

### Bước 5 — Provision hạ tầng AWS bằng Terraform

```bash
terraform -chdir=terraform/aws init
terraform -chdir=terraform/aws apply --auto-approve
terraform -chdir=terraform/aws output -json | jq '.aws_instances, .aws_k3s_api_tunnel'
```

### Bước 6 — Upload image Ubuntu vào OpenStack

```bash
openstack image list   # kiểm tra trước, nếu đã có ubuntu-22.04 thì bỏ qua bước này

wget -O ~/ubuntu-22.04.img \
  https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img

openstack image create "ubuntu-22.04" \
  --file ~/ubuntu-22.04.img \
  --disk-format qcow2 \
  --container-format bare \
  --public

openstack image list
```

### Bước 7 — Tạo flavor cho OpenStack

```bash
openstack flavor list   # kiểm tra trước

# nano-plus: gateway + identity (1 vCPU, 1GB RAM, 20GB disk)
openstack flavor create nano-plus --vcpus 1 --ram 1024 --disk 20 --public

# m1.medium: k3s master + worker (2 vCPU, 4GB RAM, 40GB disk)
openstack flavor create m1.medium --vcpus 2 --ram 4096 --disk 40 --public

openstack flavor list
```

### Bước 8 — Provision hạ tầng OpenStack bằng Terraform

```bash
terraform -chdir=terraform/openstack init
terraform -chdir=terraform/openstack apply --auto-approve
terraform -chdir=terraform/openstack output -json | jq '.openstack_instances, .openstack_k3s_api_tunnel'
```

### Bước 9 — Cập nhật IP vào Ansible inventory

Sau mỗi lần `terraform apply`, IP của các máy thay đổi — cập nhật thủ công vào `ansible/inventory/hosts.yml`.

```bash
terraform -chdir=terraform/aws output aws_bastion_pip
terraform -chdir=terraform/aws output aws_gateway_eip
terraform -chdir=terraform/openstack output os_gateway_floating_ip
```

Cập nhật các dòng sau trong `ansible/inventory/hosts.yml`:

```yaml
aws_bastion:
  ansible_host: <aws_bastion_pip>

aws_gateway:
  ansible_host: <aws_gateway_eip>

# ProxyJump AWS (xuất hiện 2 lần trong file)
-o ProxyJump=ubuntu@<aws_bastion_pip>

os_gateway:
  ansible_host: <os_gateway_floating_ip>

# ProxyJump OpenStack
-o ProxyJump=ubuntu@<os_gateway_floating_ip>
```

```bash
ansible-inventory -i ansible/inventory/hosts.yml --host aws_bastion | grep ansible_host
ansible-inventory -i ansible/inventory/hosts.yml --host os_gateway  | grep ansible_host
```

### Bước 10 — Kiểm tra kết nối SSH

```bash
AWS_BASTION_IP=$(terraform -chdir=terraform/aws output -raw aws_bastion_pip)
OS_GATEWAY_IP=$(terraform -chdir=terraform/openstack output -raw os_gateway_floating_ip)

ssh -i "$SSH_KEY" -o ConnectTimeout=10 ubuntu@$AWS_BASTION_IP echo "bastion OK"
ssh -i ~/.ssh/zta-siem-soar-key -o ConnectTimeout=10 ubuntu@$OS_GATEWAY_IP echo "os_gateway OK"
ssh -i "$SSH_KEY" -o ProxyJump=ubuntu@$AWS_BASTION_IP ubuntu@10.10.1.10 echo "k3s-master OK"

ansible -i ansible/inventory/hosts.yml all -m ping
```

### Bước 11 — Chạy Ansible provisioning

```bash
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/baseline.yml    # gói cơ bản
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/wireguard.yml   # VPN AWS↔OpenStack
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/k3s.yml         # K3s
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/promtail.yml    # log shipping
```

### Bước 12 — Tạo tunnel Kubernetes và kiểm tra cluster

```bash
bash scripts/k8s-tunnel.sh up all

kubectl config get-contexts
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

### Bước 13 — Deploy ứng dụng

```bash
source ~/kolla-venv/bin/activate   # nếu dùng venv riêng cho openstack CLI

IMAGE_TAG=1.0.0 bash scripts/sync-financial-images.sh   # build + copy image vào mọi node
docker images | grep '^ztlab/'                          # kiểm tra image đã build

export KEYCLOAK_ADMIN_PASSWORD=ztlab-admin-2026
bash scripts/deploy-app.sh

kubectl --context ctx-aws get pods -A
kubectl --context ctx-openstack get pods -A
```

### Bước 14 — Seed data và mở UI

```bash
python3 tests/seed_db.py
bash scripts/open-admin-uis.sh

ss -lnt | grep -E ':(18080|18081|3000|13100|8091|18082|18092|9090|5050|5540)\b'
```

Sau bước này, hệ thống đã sẵn sàng — chuyển sang **Phần 2** cho các lần khởi động/redeploy tiếp theo.

---

## Phần 2 — Redeploy / Vận hành hàng ngày

Áp dụng khi hạ tầng (Terraform/Ansible) đã tồn tại — chỉ cần bật lại sau khi tắt máy, hoặc đẩy code mới lên.

### 2.1 Bật lại sau khi tắt máy / reboot host

OpenStack VM tắt theo host vật lý; AWS EC2 vẫn chạy nếu không stop thủ công.

```bash
# 1. Bật OpenStack VMs
source /etc/kolla/admin-openrc.sh
openstack server list
openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2
sleep 30

# 2. Mở K8s tunnels (SSH tunnel tới k3s API server, cả 2 cluster)
bash scripts/k8s-tunnel.sh up all
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes

# 3. Mở toàn bộ port-forward — daemon tự-restart, KHÔNG cần lệnh nohup thủ công
bash scripts/open-admin-uis.sh

# 4. Restore services về trạng thái sạch (gỡ isolation/NetworkPolicy còn sót từ demo trước)
bash scripts/run-demo.sh --restore
```

> `scripts/open-admin-uis.sh` mở toàn bộ port-forward cần thiết (web-portal, api-gateway, grafana, loki, soar-engine, ai-analyzer, security-scorer, keycloak, prometheus, pgadmin, redisinsight) và tự kết nối lại nếu 1 tunnel bị rớt — không cần chạy `kubectl port-forward` tay từng lệnh.

### 2.2 Kiểm tra sức khoẻ hệ thống

```bash
curl -s http://localhost:18080/health | python3 -m json.tool

curl -s http://localhost:8180/realms/ztlab/.well-known/openid-configuration \
  | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['issuer'])"

curl -s "http://localhost:13100/loki/api/v1/label/job/values" \
  | python3 -c "import sys,json; print('Loki jobs:', json.load(sys.stdin)['data'])"
# Phải thấy: envoy-access, opa-decisions, kubernetes-pods, security-healthcheck, system

curl -s http://localhost:8091/health \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('SOAR:', d['status'], '| cases:', d.get('total_cases',0))"

curl -s -u admin:ZTALab2026! http://localhost:3000/api/health \
  | python3 -c "import sys,json; print('Grafana:', json.load(sys.stdin)['database'])"
```

Pods phải `Running`; các microservice có Istio sidecar (istio-proxy) phải `2/2`:

```bash
kubectl --context ctx-aws get pods -n financial
kubectl --context ctx-aws get pods -n identity
kubectl --context ctx-aws get pods -n plg-stack
```

### 2.3 Redeploy sau khi sửa code

Có 2 đường, chọn theo loại thay đổi:

**(A) Sửa logic Python (`main.py`) của 1 service — nhanh, không rebuild image**

```bash
bash scripts/patch-services.sh                    # patch tất cả 5 service hỗ trợ
bash scripts/patch-services.sh fraud-detection     # hoặc chỉ 1 service
```

Cách hoạt động: mount 1 ConfigMap chứa `main.py` hiện tại đè lên `/app/main.py` trong container, rồi `rollout restart`. Danh sách service hỗ trợ nằm trong `scripts/patch-services.sh` (`SERVICE_NS` map) — hiện có `web-portal`, `api-gateway`, `fraud-detection`, `payment-service`, `soar-engine`. Thêm service mới vào map đó nếu cần patch nhanh 1 service khác.

> **Giới hạn quan trọng:** cách này CHỈ đè `main.py`. Nếu sửa file khác trong service đó (vd. `services/web-portal/templates/*.html`, file tĩnh, hoặc thêm dependency mới vào `requirements.txt`) — ConfigMap patch sẽ KHÔNG áp dụng, phải rebuild image (đường B).

**(B) Sửa template/static/requirements, hoặc thêm service mới — rebuild image**

```bash
docker build --network host -t "ztlab/<service>:1.0.0" \
  --build-arg SERVICE_NAME="<service>" -f services/Dockerfile .

docker save "ztlab/<service>:1.0.0" -o /tmp/<service>.tar

ansible aws_private -i ansible/inventory/hosts.yml -m copy \
  -a "src=/tmp/<service>.tar dest=/tmp/<service>.tar" \
  --limit "aws_k3s_master,aws_k3s_worker_1,aws_k3s_worker_2"

ansible aws_private -i ansible/inventory/hosts.yml -m shell \
  -a "sudo -n ctr -n k8s.io images import /tmp/<service>.tar && rm -f /tmp/<service>.tar" \
  --limit "aws_k3s_master,aws_k3s_worker_1,aws_k3s_worker_2"

kubectl --context ctx-aws rollout restart deployment/<service> -n financial
kubectl --context ctx-aws rollout status  deployment/<service> -n financial --timeout=90s
```

> **Nếu service đó CŨNG có ConfigMap patch mount (đường A) từ trước** — image mới sẽ bị đè lại bởi ConfigMap cũ. Chạy lại `bash scripts/patch-services.sh <service>` sau khi rebuild để đồng bộ ConfigMap với `main.py` mới nhất trong repo, hoặc gỡ volumeMount nếu không cần patch nhanh nữa.
>
> Để deploy lại toàn bộ service tài chính cùng lúc (không chỉ 1 cái), dùng `IMAGE_TAG=1.0.0 bash scripts/sync-financial-images.sh` thay vì lặp tay từng service.

### 2.4 Chạy demo / kịch bản tấn công

```bash
# Normal traffic + kịch bản tấn công (xem README.md để biết danh sách kịch bản hiện hành)
bash scripts/run-demo.sh

# Chỉ 1 kịch bản cụ thể
bash scripts/run-demo.sh --kb1   # brute force
bash scripts/run-demo.sh --kb2   # lateral movement
bash scripts/run-demo.sh --kb3   # fraud gate bypass
bash scripts/run-demo.sh --kb4   # data exfiltration

# Restore về trạng thái sạch sau demo (bắt buộc trước khi demo lại)
bash scripts/run-demo.sh --restore
```

> Web Portal cũng có bộ kịch bản demo trực quan tại `/scenarios` (yêu cầu đăng nhập role `security-admin`/`security-analyst`, ví dụ tài khoản `soc01`) — 12 kịch bản, dùng để demo trực tiếp trên UI thay vì terminal.

### 2.5 Sinh dataset ML/DL thật (cho nhóm nghiên cứu mô hình)

```bash
python3 ml-dataset/generate_dataset.py --normal-count 24
```

Xem `ml-dataset/README.md` để biết schema đầy đủ, cách mở rộng, và ý nghĩa từng cột.

### 2.6 Tắt máy an toàn (nếu cần dừng để tiết kiệm chi phí)

```bash
# OpenStack: tắt VM
source /etc/kolla/admin-openrc.sh
openstack server stop os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2

# AWS: chỉ stop nếu chủ động muốn dừng (mặc định vẫn chạy, tính phí theo giờ)
# aws ec2 stop-instances --instance-ids <id> --region ap-southeast-1
```

Trạng thái cluster/dữ liệu vẫn còn nguyên khi bật lại (không phải chạy lại Phần 1) — quay lại **2.1** ở lần khởi động kế tiếp.

---

## Phần 3 — Destroy (gỡ bỏ hoàn toàn)

Khác với **2.6 Tắt máy** (chỉ stop VM, bật lại được ngay, dữ liệu/cluster giữ nguyên) — destroy xoá hẳn toàn bộ VM, network, volume do Terraform tạo. Muốn dùng lại phải chạy lại **Phần 1** từ đầu (kể cả Bước 6/7 upload lại image/flavor OpenStack nếu chúng cũng bị xoá thủ công).

Dùng khi: dừng hẳn dự án, đổi region/tài khoản cloud, hoặc hạ tầng bị lỗi nặng cần dựng lại sạch từ số 0.

> **Rút gọn:** `bash scripts/destroy-all.sh` gộp toàn bộ 3.1→3.3 bên dưới. Mặc định giữ lại SSH key-pair và image/flavor OpenStack (để `deploy-all.sh` lần sau nhanh hơn, khỏi tạo/upload lại) — dùng `--purge-keys`/`--purge-image`/`--purge-all` nếu muốn xoá sạch. `--yes` để bỏ qua bước xác nhận gõ `destroy` (dùng khi tự động hoá). `--only aws` hoặc `--only openstack` để destroy 1 bên.

### 3.1 Trước khi destroy

```bash
# Đảm bảo không còn tunnel/port-forward đang chạy (tránh log lỗi vô hại nhưng gây nhiễu)
pkill -f "kubectl.*port-forward"
bash scripts/k8s-tunnel.sh down all

# Load lại credentials nếu terminal mới
export $(grep -v '^#' .env | xargs)
export AWS_KEY_PAIR_NAME="<tên key đã dùng lúc deploy>"
```

### 3.2 Destroy hạ tầng — 2 cloud độc lập, không phụ thuộc lẫn nhau về mặt Terraform

```bash
terraform -chdir=terraform/aws destroy --auto-approve
terraform -chdir=terraform/openstack destroy --auto-approve
```

> Chạy song song hoặc tuần tự đều được (2 thư mục Terraform độc lập, không có `depends_on` xuyên cloud — chỉ liên kết nhau qua WireGuard cấu hình bởi Ansible, không phải Terraform state).

Kiểm tra đã sạch:

```bash
terraform -chdir=terraform/aws output          # phải rỗng/lỗi "no outputs"
terraform -chdir=terraform/openstack output    # tương tự
aws ec2 describe-instances --region ap-southeast-1 \
  --filters "Name=tag:Project,Values=ztlab" --query 'Reservations[].Instances[].State.Name'
openstack server list   # không còn os-gateway/os-k3s-*
```

### 3.3 Dọn dẹp thủ công (Terraform không tự xoá)

```bash
# SSH key-pair đã import lên AWS (Terraform KHÔNG quản lý key-pair đã import bằng import-key-pair)
aws ec2 delete-key-pair --key-name "$AWS_KEY_PAIR_NAME" --region ap-southeast-1

# SSH keypair trên OpenStack
openstack keypair delete zta-siem-soar-key

# (Tuỳ chọn) Image/flavor OpenStack tạo ở Bước 6/7 — thường GIỮ LẠI để lần deploy sau
# không phải upload lại image ~600MB. Chỉ xoá nếu chắc chắn không deploy lại:
# openstack image delete ubuntu-22.04
# openstack flavor delete nano-plus m1.medium

# Local: docker images build cho ztlab (không bắt buộc, chỉ để giải phóng dung lượng máy)
docker images | grep '^ztlab/' | awk '{print $1":"$2}' | xargs -r docker rmi
```

> **Terraform state** (`terraform/*/terraform.tfstate*`) tự động phản ánh đã destroy — không cần xoá tay. Nếu muốn dọn sạch hẳn thư mục làm việc Terraform: `rm -rf terraform/*/.terraform` (an toàn, chỉ là cache provider, `terraform init` sẽ tải lại khi cần).

### 3.4 Destroy một phần (chỉ 1 cloud)

Nếu chỉ muốn gỡ 1 bên (vd. giữ AWS, xoá OpenStack để tiết kiệm chi phí VM riêng):

```bash
terraform -chdir=terraform/openstack destroy --auto-approve
```

Lưu ý: `payment-service`/`core-banking` phụ thuộc kết nối cross-cloud qua WireGuard — nếu xoá OpenStack mà giữ AWS chạy, các health-check liên quan `core-banking`/`account-service`/`transaction-service` (OpenStack) sẽ báo down, đây là hành vi đúng, không phải lỗi.

---

## Xử lý lỗi thường gặp

| Lỗi | Nguyên nhân | Cách fix |
|-----|-------------|----------|
| `No valid credential sources found` | Chưa load `.env` hoặc key trống | Chạy lại `export $(grep -v '^#' .env | xargs)` |
| `terraform output` ra `null` | Chưa `terraform apply` hoặc sai thư mục | Chạy đúng `-chdir=terraform/aws` hoặc `openstack` |
| `kubectl config get-contexts` trống | Chưa chạy tunnel | `bash scripts/k8s-tunnel.sh up all` |
| `docker ps` báo lỗi quyền | Chưa thêm user vào group docker | `sudo usermod -aG docker $USER && newgrp docker` |
| SSH timeout khi provision | Security group chưa mở port 22, hoặc `TF_VAR_key_pair_name` sai | Kiểm tra `admin_ip` trong terraform variables + đúng tên key-pair đã import |
| `curl http://localhost:XXXXX` trả `HTTP:000` | Port-forward bị rớt (thường sau khi `rollout restart` pod) | `bash scripts/open-admin-uis.sh` — daemon tự kết nối lại, không cần restart tay |
| Sửa `main.py` xong nhưng chạy vẫn thấy code cũ | Service đó đang có ConfigMap patch (`patch-<service>`) đè `/app/main.py`, patch cũ chưa refresh | `bash scripts/patch-services.sh <service>` |
| Sửa template/HTML xong nhưng web không đổi | Template được bake cứng vào image lúc build, ConfigMap patch chỉ đè `main.py` | Rebuild image — xem mục 2.3(B) |
| `payment-service`/`fraud-detection` báo lỗi thiếu field khi gọi trực tiếp qua `curl` | Field mới (vd. `device_trust`) có default nên không bắt buộc — kiểm tra đang gọi đúng field name, không phải lỗi thiếu field | Xem `class PaymentRequest`/`FraudRequest` trong `main.py` tương ứng |
