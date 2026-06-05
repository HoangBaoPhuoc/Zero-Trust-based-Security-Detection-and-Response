# Hướng dẫn khởi động lại / Redeploy ZTLab

> Dành cho trường hợp tắt máy, mất phiên làm việc, hoặc cần deploy lại từ đầu.

---

## Thông tin cơ sở hạ tầng

| Node | IP Public | IP Private | Vai trò |
|------|-----------|------------|---------|
| `aws-bastion` | **54.254.145.86** | 10.10.4.10 | SSH jump host |
| `aws-gateway` | 18.143.173.245 | 10.10.0.10 | WireGuard VPN server |
| `aws-k3s-master` | *(không có)* | **10.10.1.10** | K3s control plane |
| `aws-k3s-worker-1` | *(không có)* | 10.10.1.11 | K3s worker |
| `aws-k3s-worker-2` | *(không có)* | 10.10.1.12 | K3s worker |
| `aws-security` | *(không có)* | 10.10.1.20 | Keycloak, SPIRE |
| `aws-siem` | *(không có)* | 10.10.2.10 | *(dự phòng)* |

```
SSH Key : ~/.ssh/zta-siem-soar-key
Kubeconfig (tunnel) : ~/.kube/ztlab/aws-tunnel.yaml
Kubeconfig (direct) : ~/.kube/ztlab/aws.yaml
```

> **Lưu ý:** Bastion IP `54.254.145.86` là địa chỉ tĩnh (EIP) — không đổi khi restart instance.

---

## Tình huống 1 — Chỉ cần kết nối lại (AWS vẫn đang chạy)

Đây là trường hợp thường gặp nhất: máy deployer bị tắt hoặc đóng terminal.

```bash
# Bước 1: Kiểm tra AWS instances còn running không
cd ~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
ssh -i ~/.ssh/zta-siem-soar-key -o ConnectTimeout=10 ubuntu@54.254.145.86 "echo bastion OK"

# Bước 2: Mở SSH tunnel cho kubectl
ssh -f -N \
  -i ~/.ssh/zta-siem-soar-key \
  -o StrictHostKeyChecking=no \
  -o ServerAliveInterval=30 \
  -L 6444:10.10.1.10:6443 \
  -J ubuntu@54.254.145.86 \
  ubuntu@10.10.1.10

# Bước 3: Kiểm tra pods
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml
kubectl get pods -A --no-headers | grep -v kube-system

# Nếu tất cả Running → hệ thống đang chạy bình thường, không cần làm gì thêm
```

**Mở tunnel truy cập UI (cần chạy riêng 1 terminal):**

```bash
ssh -N \
  -i ~/.ssh/zta-siem-soar-key \
  -o StrictHostKeyChecking=no \
  -L 8080:10.10.1.10:80 \
  -J ubuntu@54.254.145.86 \
  ubuntu@10.10.1.10

# Sau đó thêm vào /etc/hosts (1 lần duy nhất):
# 127.0.0.1  api.ztlab.local grafana.ztlab.local keycloak.ztlab.local
# 127.0.0.1  ai.ztlab.local soar.ztlab.local prometheus.ztlab.local
```

| URL | Service | Credentials |
|-----|---------|-------------|
| http://grafana.ztlab.local:8080 | Grafana | `admin` / `ZTALab2026!` |
| http://keycloak.ztlab.local:8080 | Keycloak | `admin` / `ztlab-admin-2026` |
| http://api.ztlab.local:8080/health | API Gateway | — |
| http://prometheus.ztlab.local:8080 | Prometheus | — |
| http://ai.ztlab.local:8080/health | AI Analyzer | — |
| http://soar.ztlab.local:8080/cases | SOAR Engine | — |

---

## Tình huống 2 — AWS instances bị dừng rồi khởi động lại

Khi start lại EC2 instances từ AWS Console:

```bash
# Bước 1: Đợi instances running (~2 phút sau khi start)
# Bước 2: SSH vào bastion để kiểm tra
ssh -i ~/.ssh/zta-siem-soar-key ubuntu@54.254.145.86

# Bước 3: K3s tự khởi động (đã cấu hình systemd enabled)
# Kiểm tra từ máy deployer:
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.10 \
  "systemctl status k3s --no-pager | head -5 && kubectl get nodes"

# Bước 4: Đợi pods Running (~3-5 phút)
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml
# Mở tunnel trước (Tình huống 1 - Bước 2)
watch kubectl get pods -A --no-headers | grep -v kube-system
```

> K3s đã được cấu hình `systemctl enable k3s` → **tất cả pods tự khởi động lại** sau khi node reboot.
> PVC data (Grafana, SOAR cases, Prometheus, PostgreSQL, Redis) được giữ nguyên trên local-path storage.

**Nếu có pod không tự lên:**

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

# Kiểm tra pod bị lỗi
kubectl get pods -A | grep -v Running | grep -v Completed | grep -v kube-system

# Xem log pod lỗi
kubectl logs -n <namespace> <pod-name> --tail=30

# Restart một deployment cụ thể
kubectl rollout restart deployment/<name> -n <namespace>

# Hoặc restart toàn bộ namespace
kubectl rollout restart deployment -n financial
kubectl rollout restart deployment -n plg-stack
kubectl rollout restart deployment -n identity
kubectl rollout restart deployment -n monitoring
```

---

## Tình huống 3 — Deploy lại toàn bộ từ đầu

Dùng khi cần setup lại hoàn toàn (cluster mới, node mới, v.v.).

### 3.1 Prerequisites

```bash
# Cài kubectl nếu chưa có
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -m 0755 kubectl /usr/local/bin/kubectl

# Clone repo
git clone <repo-url> ~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
cd ~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
```

### 3.2 Chuẩn bị biến môi trường

```bash
# Tạo file .env từ template
cp .env.template .env

# Điền các giá trị bắt buộc:
# GEMINI_API_KEY=<key từ Google AI Studio>
# OPENAI_API_KEY=<key nếu dùng OpenAI>
# GRAFANA_ADMIN_PASSWORD=ZTALab2026!
# AI_PROVIDER=gemini

nano .env   # hoặc vim / code
```

### 3.3 Cài K3s trên các nodes (nếu chưa có)

```bash
# Chạy từ máy deployer — cài K3s master
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.10 \
  "curl -sfL https://get.k3s.io | sh -"

# Lấy join token
JOIN_TOKEN=$(ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.10 \
  "sudo cat /var/lib/rancher/k3s/server/node-token")

# Cài K3s trên từng worker
for WORKER_IP in 10.10.1.11 10.10.1.12; do
  ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@$WORKER_IP \
    "curl -sfL https://get.k3s.io | K3S_URL=https://10.10.1.10:6443 K3S_TOKEN=$JOIN_TOKEN sh -"
done

# Lấy kubeconfig
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.10 \
  "sudo cat /etc/rancher/k3s/k3s.yaml" \
  | sed 's|https://127.0.0.1:6443|https://127.0.0.1:6444|g' \
  > ~/.kube/ztlab/aws-tunnel.yaml

chmod 600 ~/.kube/ztlab/aws-tunnel.yaml
```

### 3.4 Build và sync images lên nodes

```bash
# Build images tất cả services
cd ~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud

bash scripts/sync-financial-images.sh
# Script sẽ:
#   1. Build docker images (ztlab/api-gateway:1.0.0, v.v.)
#   2. Export thành .tar
#   3. SCP lên từng K3s node
#   4. Import vào containerd (k3s ctr images import)
```

> **Nếu images đã có sẵn trên nodes** (không build lại), bỏ qua bước này.
> Kiểm tra: `ssh ... ubuntu@10.10.1.10 "sudo k3s ctr images ls | grep ztlab"`

### 3.5 Deploy toàn bộ

```bash
# Mở tunnel trước
ssh -f -N -i ~/.ssh/zta-siem-soar-key -o StrictHostKeyChecking=no \
  -L 6444:10.10.1.10:6443 -J ubuntu@54.254.145.86 ubuntu@10.10.1.10

# Chạy deploy script (14 bước tự động)
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml
export GEMINI_API_KEY=$(grep GEMINI_API_KEY .env | cut -d= -f2)

bash scripts/deploy-full.sh --skip-images
```

Script sẽ tự động:
1. Tạo namespaces (`financial`, `identity`, `plg-stack`, `monitoring`)
2. Tạo secrets (Keycloak, AI)
3. Deploy PostgreSQL × 2 + Redis
4. Deploy Keycloak + import realm `ztlab`
5. Deploy 7 financial microservices
6. Deploy PLG Stack: Loki + Grafana (với 4 dashboards, 6 alert rules) + Promtail DaemonSet
7. Deploy AI Analyzer + SOAR Engine (với RBAC)
8. Deploy Prometheus (9 scrape targets)
9. Apply NetworkPolicies
10. Apply Traefik Ingress routes
11. Tạo Keycloak test users
12. Chạy health check + test payment end-to-end

**Thời gian**: ~10–15 phút (chủ yếu chờ Keycloak import realm ~60s).

---

## Tình huống 4 — Chỉ redeploy một phần

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

# Chỉ deploy lại AI + SOAR
kubectl apply -f k8s/rbac/soar-rbac.yaml
kubectl apply -f k8s/plg-stack/ai-soar.yaml
kubectl rollout restart deployment/ai-analyzer deployment/soar-engine -n plg-stack

# Chỉ deploy lại Grafana (cập nhật dashboards/alerts)
kubectl delete configmap grafana-datasources grafana-dashboard-provider \
  grafana-dashboards grafana-alerting -n plg-stack 2>/dev/null || true

kubectl create configmap grafana-datasources -n plg-stack \
  --from-file=loki-datasource.yml=plg-stack/grafana/datasources/loki-datasource.yml
kubectl create configmap grafana-dashboard-provider -n plg-stack \
  --from-file=dashboard-provider.yml=plg-stack/grafana/dashboards/dashboard-provider.yml
kubectl create configmap grafana-dashboards -n plg-stack \
  --from-file=plg-stack/grafana/dashboards/zta-security-overview.json \
  --from-file=plg-stack/grafana/dashboards/envoy-access-logs.json \
  --from-file=plg-stack/grafana/dashboards/opa-decision-log.json \
  --from-file=plg-stack/grafana/dashboards/ai-siem-soar.json
kubectl create configmap grafana-alerting -n plg-stack \
  --from-file=plg-stack/grafana/alerting/brute-force-alert.yml \
  --from-file=plg-stack/grafana/alerting/fraud-gate-bypass-alert.yml \
  --from-file=plg-stack/grafana/alerting/large-response-alert.yml \
  --from-file=plg-stack/grafana/alerting/lateral-movement-alert.yml \
  --from-file=plg-stack/grafana/alerting/ai-analyzer-alert.yml \
  --from-file=plg-stack/grafana/alerting/soar-engine-alert.yml
kubectl rollout restart deployment/grafana -n plg-stack

# Chỉ deploy lại financial services
kubectl apply -f k8s/financial/
kubectl rollout restart deployment -n financial

# Chỉ deploy lại Prometheus
kubectl apply -f k8s/monitoring/prometheus.yaml
```

---

## Kiểm tra nhanh sau khi khởi động

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

# 1. Pods OK?
kubectl get pods -A --no-headers | grep -v kube-system | grep -v Running
# (phải rỗng — không có pod nào không Running)

# 2. AI hoạt động?
kubectl port-forward -n plg-stack svc/ai-analyzer 18090:8080 &
sleep 2 && curl -s http://localhost:18090/health | python3 -m json.tool
# Mong đợi: provider=gemini, provider_backoff_remaining_seconds=0

# 3. Payment flow OK?
TOKEN=$(bash scripts/gen-dev-token.sh testuser01 financial-write | head -1)
kubectl exec -n financial deploy/api-gateway -- python3 -c "
import urllib.request, json
req = urllib.request.Request(
    'http://localhost:8080/payments',
    data=json.dumps({'from_account':'acc001','to_account':'acc002','amount':50000}).encode(),
    headers={'Content-Type':'application/json','Authorization':'Bearer $TOKEN'},
    method='POST')
r=urllib.request.urlopen(req, timeout=10)
d=json.loads(r.read().decode())
print('Payment:', d.get('status'), '| Fraud score:', d['fraud']['score'], '| TxID:', d['core_banking']['transaction_id'][:8])
"

# 4. Prometheus targets OK?
kubectl port-forward -n monitoring svc/prometheus 19090:9090 &
sleep 2 && curl -s http://localhost:19090/api/v1/targets | \
  python3 -c "import json,sys; d=json.load(sys.stdin)['data']['activeTargets']; print(f'{sum(t[\"health\"]==\"up\" for t in d)}/{len(d)} targets UP')"

# 5. Demo tấn công (AI → SOAR pipeline)
kubectl port-forward -n plg-stack svc/ai-analyzer 18090:8080 &
kubectl port-forward -n plg-stack svc/soar-engine 18091:8080 &
kubectl port-forward -n plg-stack svc/loki 13100:3100 &
sleep 2
AI_URL=http://127.0.0.1:18090 SOAR_URL=http://127.0.0.1:18091 LOKI_URL=http://127.0.0.1:13100 \
  bash scripts/demo-ai-soar.sh
```

---

## Đổi AI provider

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

# Xem provider hiện tại
kubectl exec -n plg-stack deploy/ai-analyzer -- env | grep AI_PROVIDER

# Đổi sang gemini (mặc định)
kubectl patch secret ai-secrets -n plg-stack --type=json \
  -p='[{"op":"replace","path":"/data/AI_PROVIDER","value":"'$(echo -n 'gemini' | base64)'"}]'

# Đổi sang openai
kubectl patch secret ai-secrets -n plg-stack --type=json \
  -p='[{"op":"replace","path":"/data/AI_PROVIDER","value":"'$(echo -n 'openai' | base64)'"}]'

# Đổi sang heuristic (không dùng AI, chỉ rule-based)
kubectl patch secret ai-secrets -n plg-stack --type=json \
  -p='[{"op":"replace","path":"/data/AI_PROVIDER","value":"'$(echo -n 'heuristic' | base64)'"}]'

# Áp dụng
kubectl rollout restart deployment/ai-analyzer -n plg-stack
```

---

## Bật SOAR live mode (thực sự execute K8s actions)

> ⚠️ Khi `SOAR_DRY_RUN=false`, SOAR sẽ **thực sự** scale down / isolate pods khi phát hiện tấn công.

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

# Bật live mode
kubectl patch secret ai-secrets -n plg-stack --type=json \
  -p='[{"op":"replace","path":"/data/SOAR_DRY_RUN","value":"'$(echo -n 'false' | base64)'"}]'
kubectl rollout restart deployment/soar-engine -n plg-stack

# Tắt lại về dry-run
kubectl patch secret ai-secrets -n plg-stack --type=json \
  -p='[{"op":"replace","path":"/data/SOAR_DRY_RUN","value":"'$(echo -n 'true' | base64)'"}]'
kubectl rollout restart deployment/soar-engine -n plg-stack
```

---

## Thông tin tài khoản

| Service | Username | Password |
|---------|----------|----------|
| Grafana | `admin` | `ZTALab2026!` |
| Keycloak Admin | `admin` | `ztlab-admin-2026` |
| Keycloak testuser01 | `testuser01` | `Test@1234` |
| Keycloak testuser02 | `testuser02` | `Test@1234` |

**JWT dev token** (cho test api-gateway trực tiếp):
```bash
TOKEN=$(bash scripts/gen-dev-token.sh testuser01 financial-write | head -1)
echo $TOKEN
```

---

## Files quan trọng

```
scripts/
  deploy-full.sh          ← Deploy toàn bộ từ đầu
  gen-dev-token.sh        ← Tạo JWT test token
  demo-ai-soar.sh         ← Chạy 5 attack scenarios
  health-check.sh         ← Kiểm tra toàn hệ thống
  k8s-tunnel.sh           ← Quản lý SSH tunnels

k8s/
  namespaces.yaml         ← Tất cả namespaces
  ingress.yaml            ← Traefik routes
  financial/              ← Microservices
  keycloak/               ← Identity
  plg-stack/              ← Loki, Grafana, AI, SOAR
  monitoring/             ← Prometheus
  rbac/                   ← SOAR permissions

plg-stack/grafana/
  datasources/            ← Loki datasource (uid: Loki)
  dashboards/             ← 4 dashboards JSON
  alerting/               ← 6 alert rules YAML

~/.kube/ztlab/
  aws-tunnel.yaml         ← Kubeconfig qua SSH tunnel (port 6444)
  aws.yaml                ← Kubeconfig direct (port 6443, cần ở cùng mạng)
```
