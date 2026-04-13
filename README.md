# ZTLab — Zero Trust Security Detection & Response System

ZTLab hiện đã chuyển sang kiến trúc gọn nhẹ hơn: **PLG Stack** gồm Promtail, Loki và Grafana cho SIEM, chạy song song với hạ tầng Zero Trust, WireGuard, SPIRE, OPA, Envoy và Keycloak. ELK, Wazuh, Kafka, SOAR và AI Engine không còn nằm trong luồng deploy hiện tại.

## Kiến trúc hiện tại

```text
Internet
  -> DMZ: WireGuard gateway, API gateway, Keycloak
  -> Private: K3s workloads, SPIRE, OPA, Envoy sidecars
  -> Restricted: Loki + Grafana
  -> Management: Bastion, Terraform, Ansible

OpenStack <-> AWS qua WireGuard tunnel
Promtail chạy trên mọi node và đẩy log về Loki
```

## Repo Layout

| Path | Mục đích |
|------|----------|
| [terraform/](terraform/) | Provision AWS và OpenStack |
| [ansible/](ansible/) | Baseline, WireGuard, K3s, Promtail |
| [k8s/](k8s/) | Kubernetes manifests |
| [spire/](spire/) | SPIRE server, agent, registration |
| [envoy/](envoy/) | Envoy sidecar config |
| [opa/](opa/) | Policy engine config và Rego policies |
| [plg-stack/](plg-stack/) | Docker Compose cho Loki, Grafana, Promtail |
| [scripts/](scripts/) | Hỗ trợ deploy, tunnel, health check |
| [services/](services/) | Microservices tài chính |
| [shared/](shared/) | Shared Python modules |

## Deploy Flow Hiện Tại

### 1. Chuẩn bị biến môi trường

```bash
git clone 
cp .env.template .env
set -a && source .env && set +a

# If conflict version
source .venv/bin/activate
export PYTHONNOUSERSITE=1
```

### 2. Provision hạ tầng

```bash
cd /etc/zta-siem-soar/terraform/aws
terraform init
terraform apply --auto-approve

cd ../openstack
terraform init
terraform apply --auto-approve
```

### 3. Cập nhật inventory Ansible

Điều chỉnh [ansible/inventory/hosts.yml](ansible/inventory/hosts.yml) theo output Terraform, tối thiểu phải có:
- `aws_gateway`
- `aws_bastion`
- `aws_k3s_master`
- `aws_k3s_worker_1`
- `aws_k3s_worker_2`
- `aws_security`
- `aws_siem`
- `os_gateway`
- `os_k3s_master`
- `os_k3s_worker_1`
- `os_k3s_worker_2`
- `os_identity`

#### Trích output để sửa IP cho lần đầu deploy

```bash
cd /etc/zta-siem-soar/terraform

# AWS
terraform -chdir=aws output aws_gateway_eip
terraform -chdir=aws output aws_bastion_pip
terraform -chdir=aws output aws_instances

# OpenStack
terraform -chdir=openstack output os_gateway_floating_ip
terraform -chdir=openstack output openstack_instances
```

Map output -> host trong [ansible/inventory/hosts.yml](ansible/inventory/hosts.yml):

| Host trong inventory | Nguồn output |
|---|---|
| `aws_gateway.ansible_host` | `aws_gateway_eip` hoặc `aws_instances.aws_gateway.elastic_ip` |
| `aws_bastion.ansible_host` | `aws_bastion_pip` hoặc `aws_instances.aws_bastion.public_ip` |
| `aws_k3s_master.ansible_host` | `aws_instances.aws_k3s_master.private_ip` |
| `aws_k3s_worker_1.ansible_host` | `aws_instances.aws_k3s_worker_1.private_ip` |
| `aws_k3s_worker_2.ansible_host` | `aws_instances.aws_k3s_worker_2.private_ip` |
| `aws_security.ansible_host` | `aws_instances.aws_security.private_ip` |
| `aws_siem.ansible_host` | `aws_instances.aws_siem.private_ip` |
| `os_gateway.ansible_host` | `os_gateway_floating_ip` hoặc `openstack_instances.os_gateway.public_ip` |
| `openstack.vars.os_gateway_floating_ip` | `os_gateway_floating_ip` |
| `os_k3s_master.ansible_host` | `openstack_instances.os_k3s_master.private_ip` |
| `os_k3s_worker_1.ansible_host` | `openstack_instances.os_k3s_worker_1.private_ip` |
| `os_k3s_worker_2.ansible_host` | `openstack_instances.os_k3s_worker_2.private_ip` |
| `os_identity.ansible_host` | `openstack_instances.os_identity.identity_ip` |

Sau khi sửa IP, chạy kiểm tra nhanh:

```bash
cd /etc/zta-siem-soar/ansible
ansible ssh_entrypoints -i inventory/hosts.yml -m ping
ansible aws_private -i inventory/hosts.yml -m ping
ansible openstack -i inventory/hosts.yml -m ping
```

### 4. Baseline và WireGuard

```bash
cd /etc/zta-siem-soar/ansible
ansible-playbook -i inventory/hosts.yml playbooks/baseline.yml
ansible-playbook -i inventory/hosts.yml playbooks/wireguard.yml
```

### 5. Triển khai K3s

```bash
ansible-playbook -i inventory/hosts.yml playbooks/k3s.yml
```

### 6. Mở tunnel kubectl

```bash
cd /etc/zta-siem-soar
./scripts/k8s-tunnel.sh up
./scripts/k8s-tunnel.sh verify
```

### 7. Deploy security stack

```bash
./scripts/deploy-security-stack.sh
```

Script này deploy SPIRE, Keycloak, OPA và Envoy ConfigMap cho cả hai cluster.

### 8. Deploy financial workloads

```bash
# AWS cluster
kubectl --context ctx-aws apply -f k8s/financial/aws-services.yaml

# OpenStack cluster
kubectl --context ctx-openstack apply -f k8s/financial/os-services.yaml
```

Lưu ý: hiện các file trong `k8s/financial/*.yaml` vẫn là placeholder TODO. Nếu chưa điền manifest thật, `kubectl apply` sẽ báo `error: no objects passed to apply`.

Nếu bạn dùng bộ manifest tổng hợp, có thể chạy:

```bash
kubectl --context ctx-aws apply -f k8s/financial/
kubectl --context ctx-openstack apply -f k8s/financial/
```

### 9. Deploy PLG Stack

```bash
./scripts/deploy-plg-stack.sh
```

Hoặc chạy trực tiếp:

```bash
cd /etc/zta-siem-soar
docker compose -f plg-stack/docker-compose.plg.yml up -d
```

## Verify Sau Deploy

```bash
cd /etc/zta-siem-soar/ansible
ansible ssh_entrypoints -i inventory/hosts.yml -m ping
ansible aws_private -i inventory/hosts.yml -m ping
ansible openstack -i inventory/hosts.yml -m ping

cd /etc/zta-siem-soar
./scripts/k8s-tunnel.sh status
kubectl --context ctx-aws get pods -A
kubectl --context ctx-openstack get pods -A
```

## Ghi chú

- SIEM hiện dùng Loki làm backend log trung tâm, Grafana cho dashboard và alerting, Promtail làm collector trên mọi node.
- Các file và thư mục cũ của ELK, Wazuh, Kafka, SOAR và AI Engine đã được loại bỏ khỏi luồng deploy hiện tại.
- Nếu đổi IP sau khi `terraform apply`, cập nhật lại [ansible/inventory/hosts.yml](ansible/inventory/hosts.yml) trước khi chạy Ansible.

## Tài liệu tham khảo

- [IMPLEMENTATION.md](IMPLEMENTATION.md)
- [MAP.md](MAP.md)