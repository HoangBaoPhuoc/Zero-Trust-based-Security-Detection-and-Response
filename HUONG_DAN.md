# ZTLab — Hướng Dẫn Vận Hành & Demo

> **Đồ án:** Triển khai Hệ thống Phát hiện và Phản ứng Sự cố Bảo mật Dựa trên Zero Trust cho Microservices trong Multi-Cloud  
> **Sinh viên:** Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)

---

## Thông tin hạ tầng

### EC2 Instances (AWS Console → EC2 → Instances)

| Tên instance | Instance ID | IP Private | IP Public | Dùng cho |
|---|---|---|---|---|
| **aws-bastion** | `i-06d2382ad780bda8c` | 10.10.4.10 | **54.254.145.86** (EIP tĩnh) | SSH jump host |
| **aws-k3s-master** | `i-0293f9568b3c0762b` | 10.10.1.10 | — | AWS K3s control plane |
| **aws-k3s-worker-1** | `i-00001195627942100` | 10.10.1.11 | — | AWS K3s worker |
| **os-k3s-master** | `i-08f1cf418461cca62` | 10.10.1.12 | — | OpenStack K3s control plane |

Các instance khác (`aws-gateway`, `aws-security`, `aws-siem`) **không cần** thiết cho lab — có thể bỏ qua.

### Credentials

| Dịch vụ | Tài khoản | Mật khẩu |
|---------|-----------|---------|
| Grafana | admin | ZTALab2026! |
| Keycloak Admin | admin | ztlab-admin-2026 |
| Keycloak testuser01 | testuser01 | Test@1234 |
| Keycloak testuser02 | testuser02 | Test@1234 |

### Kubectl contexts

| Context | Tunnel port | Trỏ đến | Cluster |
|---------|------------|---------|---------|
| `ctx-aws` | localhost:6444 | 10.10.1.10:6443 | AWS K3s (master + worker-1) |
| `ctx-openstack` | localhost:6445 | 10.10.1.12:6443 | OpenStack K3s (os-master) |

### NodePorts quan trọng trên OpenStack (10.10.1.12)

| Port | Dùng cho | Giao thức |
|------|----------|-----------|
| 30081 | core-banking **Envoy inbound** (mTLS) | TLS — chỉ dành cho mTLS |
| 30084 | core-banking app (plain HTTP) | HTTP — Prometheus scrape, health check |
| 30082 | account-service | HTTP |
| 30083 | transaction-service | HTTP |
| 30900 | SPIRE Server API (trên 10.10.1.10) | gRPC |

---

## Phần 1 — Khởi động hệ thống từ đầu

> Dùng khi vừa bật máy local lên, hoặc sau khi EC2 bị stop. Làm theo thứ tự từ trên xuống.

---

### Bước 1 — Bật EC2 instances

Kiểm tra trạng thái hiện tại trước:

```bash
aws ec2 describe-instances --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62 \
  --query 'Reservations[].Instances[].[InstanceId, Tags[?Key==`Name`].Value|[0], State.Name]' \
  --output table
```

Nếu tất cả đã `running` → bỏ qua lệnh start bên dưới, chuyển thẳng sang Bước 2.

Nếu có instance đang `stopped` → bật lên:

```bash
aws ec2 start-instances --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62
```

Chờ ~3–5 phút rồi kiểm tra tất cả đã `running`:

```bash
aws ec2 describe-instance-status --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62 \
  --query 'InstanceStatuses[].[InstanceId, InstanceState.Name, InstanceStatus.Status, SystemStatus.Status]' \
  --output table
```

Kết quả mong đợi — tất cả 4 dòng phải là `running | ok | ok`:
```
----------------------------------------------------------------------
|                     DescribeInstanceStatus                         |
+----------------------+---------+--------+--------+
|  i-06d2382ad780bda8c | running | ok     | ok     |
|  i-0293f9568b3c0762b | running | ok     | ok     |
|  i-00001195627942100 | running | ok     | ok     |
|  i-08f1cf418461cca62 | running | ok     | ok     |
+----------------------+---------+--------+--------+
```

Nếu chưa thấy đủ 4 dòng (instance đang khởi động chưa có status) → chạy lại lệnh sau 1–2 phút.

> **Lưu ý:** `aws-bastion` có Elastic IP tĩnh `54.254.145.86` — IP này không thay đổi dù restart.

---

### Bước 2 — Xác nhận bastion đang sống

```bash
ssh -i ~/.ssh/zta-siem-soar-key \
  -o ConnectTimeout=10 \
  -o StrictHostKeyChecking=no \
  ubuntu@54.254.145.86 "echo bastion OK && uptime"
```

Nếu vẫn timeout sau 5 phút → chạy lại lệnh check status ở Bước 1.

---

### Bước 3 — Mở kubectl tunnels cho cả hai cluster

```bash
cd ~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
bash scripts/k8s-tunnel.sh up all
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml
```

Kiểm tra:

```bash
kubectl --context ctx-aws get nodes
# NAME             STATUS   ROLES                  AGE
# ip-10-10-1-10    Ready    control-plane,master   ...
# ip-10-10-1-11    Ready    <none>                 ...

kubectl --context ctx-openstack get nodes
# NAME        STATUS   ROLES                  AGE
# os-master   Ready    control-plane,master   ...
```

Nếu tunnel không mở được:
```bash
bash scripts/k8s-tunnel.sh status          # xem port nào đang mở
bash scripts/k8s-tunnel.sh down            # đóng hết
bash scripts/k8s-tunnel.sh up all          # mở lại
```

---

### Bước 4 — Thêm /etc/hosts (chỉ cần làm 1 lần)

```bash
grep -q "api.ztlab.local" /etc/hosts || sudo tee -a /etc/hosts <<'EOF'
127.0.0.1  api.ztlab.local grafana.ztlab.local keycloak.ztlab.local
127.0.0.1  ai.ztlab.local soar.ztlab.local prometheus.ztlab.local
EOF
```

---

### Bước 5 — Mở UI tunnel (mở terminal riêng, để block)

Terminal này cần giữ nguyên trong suốt buổi demo.

```bash
ssh -N \
  -i ~/.ssh/zta-siem-soar-key \
  -o StrictHostKeyChecking=no \
  -L 8080:10.10.1.10:80 \
  -J ubuntu@54.254.145.86 \
  ubuntu@10.10.1.10
```

> Terminal này không có output — đó là đúng. Mở terminal mới để tiếp tục.

Xác nhận UI tunnel hoạt động:

```bash
curl -v -H "Host: api.ztlab.local" http://127.0.0.1:8080/health
# Expect: HTTP/1.1 200 OK và JSON {"status":"ok","service":"api-gateway",...}
```

**Nếu không hoạt động:**

```bash
# 1. Kiểm tra port 8080 có đang bị chiếm không
ss -tlnp | grep 8080
# Nếu có process khác dùng → kill trước
kill $(lsof -ti tcp:8080) 2>/dev/null

# 2. Kiểm tra bastion còn reachable không
ssh -i ~/.ssh/zta-siem-soar-key -o ConnectTimeout=8 ubuntu@54.254.145.86 "echo OK"

# 3. Kiểm tra Traefik (ingress) trên AWS master đang chạy không
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.10 \
  "kubectl get pods -n kube-system | grep traefik"

# 4. Thử mở lại tunnel (terminal mới)
ssh -N -i ~/.ssh/zta-siem-soar-key -o StrictHostKeyChecking=no \
  -L 8080:10.10.1.10:80 -J ubuntu@54.254.145.86 ubuntu@10.10.1.10
```

> Nếu Traefik không chạy → `kubectl --context ctx-aws rollout restart deployment/traefik -n kube-system`

---

### Bước 6 — Mở port-forward và kiểm tra các UI

Hệ thống có **6 UI** truy cập được — chia làm 2 nhóm:

**Nhóm 1 — Qua UI tunnel (Bước 5, cần tunnel đang chạy):**

| URL | Đăng nhập | Vào thẳng trang |
|-----|-----------|-----------------|
| http://grafana.ztlab.local:8080 | admin / ZTALab2026! | `/d/ztlab-overview` — Security Overview |
| http://prometheus.ztlab.local:8080 | Không cần | `/targets` — xem 9/9 targets; `/graph` — query |
| http://keycloak.ztlab.local:8080 | admin / ztlab-admin-2026 | `/admin` — quản lý users/realms |
| http://ai.ztlab.local:8080 | Không cần | `/health` — trạng thái AI; `/cases` — xem cases |
| http://soar.ztlab.local:8080 | Không cần | `/cases` — danh sách SOAR cases |
| http://api.ztlab.local:8080 | JWT Bearer token | `/health` — kiểm tra; `/payments` — demo |

> **Prometheus `/graph` hiện ra blank** là bình thường — đó là query box rỗng. Vào thẳng `/targets` để thấy 9/9 scrape targets, hoặc `/graph` rồi nhập query như `ztlab_txn_total`.

**Nhóm 2 — Qua port-forward (truy cập trực tiếp, không cần Host header):**

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

kubectl --context ctx-aws port-forward -n plg-stack  svc/grafana      3000:3000  --address=127.0.0.1 >/tmp/pf-grafana.log  2>&1 &
kubectl --context ctx-aws port-forward -n plg-stack  svc/loki         3100:3100  --address=127.0.0.1 >/tmp/pf-loki.log     2>&1 &
kubectl --context ctx-aws port-forward -n plg-stack  svc/ai-analyzer  8090:8080  --address=127.0.0.1 >/tmp/pf-ai.log      2>&1 &
kubectl --context ctx-aws port-forward -n plg-stack  svc/soar-engine  8091:8080  --address=127.0.0.1 >/tmp/pf-soar.log    2>&1 &
kubectl --context ctx-aws port-forward -n monitoring svc/prometheus   9090:9090  --address=127.0.0.1 >/tmp/pf-prom.log    2>&1 &

sleep 4

# Xác nhận tất cả đang chạy
echo "Grafana:    $(curl -sf http://127.0.0.1:3000/api/health | python3 -c 'import json,sys; print(json.load(sys.stdin)["database"])')"
echo "Loki:       $(curl -sf http://127.0.0.1:3100/ready)"
echo "Prometheus: $(curl -sf http://127.0.0.1:9090/-/healthy)"
echo "AI:         $(curl -sf http://127.0.0.1:8090/health | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["status"], "|", d["provider"])')"
echo "SOAR:       $(curl -sf http://127.0.0.1:8091/health | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["status"], "| cases:", d["case_count"])')"
```

Kết quả mong đợi:
```
Grafana:    ok
Loki:       ready
Prometheus: Prometheus Server is Healthy.
AI:         ok | openai
SOAR:       ok | cases: <số case hiện tại>
```

> `AI_PROVIDER` phụ thuộc `.env.ai`/secret đang deploy; hệ thống live hiện dùng `openai`. Số SOAR cases tăng dần theo số lần chạy demo, nên chỉ cần endpoint trả về `ok`.

Khi xong buổi demo, tắt port-forward:
```bash
kill $(pgrep -f "kubectl port-forward") 2>/dev/null
```

---

### Bước 7 — Kiểm tra toàn bộ pods đang chạy

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

echo "=== AWS Cluster ==="
kubectl --context ctx-aws get pods -A --no-headers \
  | grep -v kube-system | grep -v Completed \
  | awk '{printf "%-20s %-35s %s\n", $1, $2, $3}'

echo ""
echo "=== OpenStack Cluster ==="
kubectl --context ctx-openstack get pods -n financial --no-headers \
  | awk '{printf "%-35s %s\n", $1, $2}'
```

Tất cả phải ở trạng thái `Running`. Pods trên OpenStack với 2 containers (`2/2`) là bình thường — container thứ hai là Envoy sidecar (core-banking). Nếu có pod lỗi:

```bash
# Xem lý do
kubectl --context ctx-aws describe pod -n <namespace> <pod-name>
kubectl --context ctx-aws logs -n <namespace> <pod-name> --tail=30

# Restart
kubectl --context ctx-aws rollout restart deployment/<tên> -n <namespace>
```

---

### Bước 8 — Kiểm tra toàn bộ hệ thống trước khi demo

Chạy từng mục theo thứ tự. Tất cả phải pass mới demo được.

#### 8.1 — Health cơ bản

```bash
# API Gateway (AWS)
curl -s -H "Host: api.ztlab.local" http://127.0.0.1:8080/health | python3 -m json.tool
# Expect: {"status":"ok","service":"api-gateway","cloud":"aws"}

# Core Banking (OpenStack) — dùng port 30084 (plain HTTP, KHÔNG dùng 30081 là mTLS)
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.10 \
  "curl -sf http://10.10.1.12:30084/health"
# Expect: {"status":"ok","service":"core-banking","cloud":"openstack"}
```

#### 8.2 — Pods tất cả Running

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

# AWS — phải thấy: api-gateway, payment-service, fraud-detection,
#   notification-service, opa-server, redis, promtail, loki, grafana,
#   ai-analyzer, soar-engine, prometheus, keycloak, spire (tất cả Running)
kubectl --context ctx-aws get pods -A --no-headers | grep -v kube-system | grep -v Completed

# OpenStack — phải thấy: core-banking (2/2), account-service, transaction-service,
#   opa-server, postgres-accounts, postgres-txn, promtail, spire-agent (tất cả Running)
kubectl --context ctx-openstack get pods -n financial --no-headers
kubectl --context ctx-openstack get pods -n plg-stack --no-headers
kubectl --context ctx-openstack get pods -n spire --no-headers
```

#### 8.3 — SPIRE: workload đã được cấp SVID

```bash
# SPIRE server đang chạy và có đủ entries
kubectl --context ctx-aws exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server entry show 2>/dev/null | grep -c "Entry ID"
# Expect: 16 (hoặc hơn)

# SPIRE agent OpenStack đang nhận SVID (phải thấy "SVID" hoặc "issued")
kubectl --context ctx-openstack logs -n spire daemonset/spire-agent --tail=10 \
  | grep -E "SVID|issued|attestation|error" | tail -5
```

#### 8.4 — Prometheus: 9/9 targets UP

```bash
kubectl --context ctx-aws port-forward -n monitoring svc/prometheus 19090:9090 \
  --address=127.0.0.1 >/tmp/pf-prom.log 2>&1 &
sleep 3
curl -s "http://localhost:19090/api/v1/targets?state=active" | python3 -c "
import json,sys
tgts = json.load(sys.stdin)['data']['activeTargets']
up = [t for t in tgts if t['health']=='up']
down = [t for t in tgts if t['health']!='up']
print(f'Targets: {len(up)} UP / {len(tgts)} total')
for t in down:
    print('  DOWN:', t['scrapeUrl'], '-', t.get('lastError','')[:60])
"
kill %1 2>/dev/null; wait %1 2>/dev/null
# Expect: 9 UP / 9 total
```

#### 8.5 — Loki: xác nhận nhận log từ cả AWS và OpenStack

> Yêu cầu: đã chạy port-forward Loki từ Bước 6.

##### Kiểm tra Loki hoạt động

```bash
curl -s http://127.0.0.1:3100/ready
```

Kết quả mong đợi:

```text
ready
```

##### Kiểm tra các labels trong Loki

```bash
curl -s http://127.0.0.1:3100/loki/api/v1/labels \
| python3 -c 'import json,sys; print("Labels:", json.load(sys.stdin)["data"])'
```

Kết quả mong đợi:

```text
Labels: [..., 'cloud', 'namespace', 'job', 'container', ...]
```

##### Xác nhận có log từ AWS

```bash
curl -sG "http://127.0.0.1:3100/loki/api/v1/query" \
  --data-urlencode 'query=count_over_time({cloud="aws"}[1h])' \
| python3 -c 'import json,sys; d=json.load(sys.stdin); print("AWS logs:", "OK" if d["data"]["result"] else "KHÔNG CÓ LOG")'
```

Kết quả mong đợi:

```text
AWS logs: OK
```

##### Xác nhận có log từ OpenStack

```bash
curl -sG "http://127.0.0.1:3100/loki/api/v1/query" \
  --data-urlencode 'query=count_over_time({cloud="openstack"}[1h])' \
| python3 -c 'import json,sys; d=json.load(sys.stdin); print("OpenStack logs:", "OK" if d["data"]["result"] else "KHÔNG CÓ LOG — kiểm tra Promtail hoặc Loki Proxy")'
```

Kết quả mong đợi:

```text
OpenStack logs: OK
```

##### Kiểm tra trực tiếp log đang được ingest

```bash
curl -sG "http://127.0.0.1:3100/loki/api/v1/query" \
  --data-urlencode 'query={cloud=~"aws|openstack"}' \
| python3 -m json.tool | head -50
```

Nếu có dữ liệu trả về, chứng tỏ Loki đang nhận log từ các node trong hệ thống.

#### 8.6 — Loki Proxy (socat relay cho OpenStack → AWS Loki)

##### Kiểm tra socat đang listen

```bash
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.11 \
  "ss -tlnp | grep 31100 && echo 'socat OK — port 31100 đang listen' || echo 'STOPPED — chạy: sudo systemctl start loki-proxy.service'"
```

Kết quả mong đợi:

```text
socat OK — port 31100 đang listen
```

##### Kiểm tra relay thực sự truy cập được Loki

```bash
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.11 \
  "curl -s http://127.0.0.1:31100/ready"
```

Kết quả mong đợi:

```text
ready
```

Nếu nhận được `ready`, chứng tỏ:

```text
OpenStack Promtail
    ↓
localhost:31100 (socat)
    ↓
AWS Loki :3100
```

đang hoạt động bình thường.

##### Nếu không hoạt động

Kiểm tra log:

```bash
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.11 \
  "sudo journalctl -u loki-proxy.service -n 50 --no-pager"
```

Khởi động lại:

```bash
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.11 \
  "sudo systemctl restart loki-proxy.service"
```

> **Lưu ý:** Kiểm tra port `31100` là cách đáng tin cậy hơn `systemctl is-active`, vì trong quá trình demo socat có thể được chạy thủ công ngoài systemd nhưng vẫn hoạt động bình thường.

#### 8.7 — Cross-cloud mTLS end-to-end (quan trọng nhất)

```bash
TOKEN=$(bash scripts/gen-dev-token.sh 2>/dev/null | head -1)
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Host: api.ztlab.local" \
  -d '{"from_account":"acc001","to_account":"acc002","amount":100000,"currency":"VND"}' \
  -X POST http://127.0.0.1:8080/payments | python3 -c "
import json,sys
d=json.load(sys.stdin)
status = d.get('status','?')
fraud  = d.get('fraud',{})
txn    = d.get('core_banking',{})
print(f'Payment status : {status}')
print(f'Fraud score    : {fraud.get(\"score\",\"?\")} — gate: {fraud.get(\"gate\",\"?\")}')
print(f'Transaction ID : {txn.get(\"transaction_id\",\"FAILED\")}')
if status == 'completed':
    print('✓ Cross-cloud mTLS + OPA hoạt động bình thường')
else:
    print('✗ Có lỗi — xem Phần 5 Xử lý sự cố')
"
```

**Hệ thống sẵn sàng demo** khi tất cả 7 mục trên đều pass, đặc biệt Bước 8.7 trả về `status: completed`.

---

## Phần 2 — Demo đồ án (thứ tự khuyến nghị)

> Thực hiện sau khi đã hoàn thành Phần 1.

### Chuẩn bị trước khi demo

```bash
cd ~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

# Lấy JWT token dùng cho toàn bộ buổi demo
TOKEN=$(bash scripts/gen-dev-token.sh testuser01 financial-write 2>/dev/null | head -1)
echo "Token (60 ký tự đầu): ${TOKEN:0:60}..."
```

**Mở Grafana trước khi demo:**
- URL: **http://grafana.ztlab.local:8080** (qua UI tunnel) hoặc **http://127.0.0.1:3000** (qua port-forward)
- Đăng nhập: admin / ZTALab2026!
- Bật **Auto Refresh 10s** (góc trên bên phải)
- Mở tab **Security Overview** và **AI SIEM SOAR** để theo dõi realtime

---

### Demo 1 — Chứng minh kiến trúc 2 cloud

Mở 2 terminal song song để thấy rõ 2 cluster độc lập:

```bash
# Terminal 1 — AWS cluster
kubectl --context ctx-aws get pods -n financial
# api-gateway, payment-service, fraud-detection, notification-service, opa-server, redis

# Terminal 2 — OpenStack cluster
kubectl --context ctx-openstack get pods -n financial
# core-banking (2/2 — có Envoy sidecar), account-service, transaction-service, opa-server, postgres-*
```

**Điểm nhấn khi trình bày:** Hai context khác nhau, hai K3s cluster hoàn toàn tách biệt, phân chia workload theo nguyên tắc Data Classification (public-facing → AWS, core banking → OpenStack). Core-banking có 2 containers vì chạy thêm Envoy sidecar để thực thi mTLS và OPA.

---

### Demo 2 — Giao dịch bình thường (Zero Trust cho phép, cross-cloud mTLS)

```bash
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Host: api.ztlab.local" \
  -d '{"from_account":"acc001","to_account":"acc002","amount":100000,"currency":"VND"}' \
  -X POST http://127.0.0.1:8080/payments | python3 -m json.tool
```

Kết quả mong đợi:
```json
{
    "status": "completed",
    "trace_id": "362097f1-...",
    "fraud": {
        "score": 5,
        "verdict": "allow",
        "gate": "passed"
    },
    "core_banking": {
        "transaction_id": "0d8e75cd-...",
        "status": "completed",
        "trace_id": "362097f1-..."
    }
}
```

**Điểm nhấn — flow Zero Trust đầy đủ:**

1. API Gateway (AWS) xác thực JWT qua OPA (`zta/authz/allow`)
2. payment-service (AWS) gọi fraud-detection → score=5 → passed
3. payment-service Envoy **gọi core-banking qua mTLS** với SVID `spiffe://ztlab.local/aws/payment-service`
4. core-banking Envoy (OpenStack) xác thực SVID + OPA (`zta/crosscloud/allow`) → cho phép
5. core-banking xử lý giao dịch → transaction_id trả về

Kiểm tra cross-cloud mTLS log trực tiếp:
```bash
# Log Envoy trên core-banking xác nhận SVID payment-service
kubectl --context ctx-openstack logs -n financial deployment/core-banking -c envoy --tail=3 | grep -v warning

# Log OPA OpenStack xác nhận policy allow
kubectl --context ctx-openstack logs -n financial deployment/opa-server --tail=5 \
  | python3 -c "import json,sys; [print('OPA result:', json.loads(l).get('result'), '| src:', json.loads(l).get('input',{}).get('source_principal','?')) for l in sys.stdin if 'Decision Log' in l]" 2>/dev/null
```

Kiểm tra trace_id xuyên suốt cả 2 cloud trong Grafana → Explore → Loki:
```logql
{job="kubernetes-pods", namespace="financial"} | json | trace_id="362097f1-..."
```

---

### Demo 3 — Không có JWT Token (OPA từ chối)

**Kịch bản:** Kẻ tấn công gọi API không có token.

```bash
curl -s \
  -H "Content-Type: application/json" \
  -H "Host: api.ztlab.local" \
  -d '{"from_account":"acc001","to_account":"acc002","amount":100000}' \
  -X POST http://127.0.0.1:8080/payments
```

**Kết quả:** HTTP 403 — OPA chặn tại Envoy sidecar, request không chạm đến application.

```bash
# Kiểm tra log OPA AWS từ Loki
curl -sG http://127.0.0.1:3100/loki/api/v1/query \
  --data-urlencode 'query={job="opa-decisions"} | json | opa_result="false"' \
  --data-urlencode 'limit=3' | python3 -c "
import json,sys
r = json.load(sys.stdin)['data']['result']
for stream in r:
    for ts,msg in stream['values'][:1]:
        d = json.loads(msg)
        print('result:', d.get('result'), '| path:', d.get('path'), '| cloud:', d.get('labels',{}).get('cloud','?'))
"
```

---

### Demo 4 — Brute Force JWT (T1110.001)

**Kịch bản:** Kẻ tấn công thử liên tiếp nhiều token sai.

```bash
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "req$i → HTTP %{http_code}\n" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.fake.signature" \
    -H "Host: api.ztlab.local" \
    -H "Content-Type: application/json" \
    -d '{"from_account":"acc001","to_account":"acc002","amount":100}' \
    -X POST http://127.0.0.1:8080/payments
done
```

**Kết quả:** 15× HTTP 401.

**Trên Grafana:** Tab **Alerting** → alert `brute-force-alert` chuyển sang **Firing** sau khi đếm ≥ 5 lần trong 60 giây.

---

### Demo 5 — Fraud Gate Block: kênh rủi ro + số tiền lớn (T1078)

**Kịch bản:** Giao dịch 500 triệu VND từ kênh TOR.

```bash
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Host: api.ztlab.local" \
  -d '{"from_account":"acc001","to_account":"acc002","amount":500000000,"currency":"VND","channel":"tor"}' \
  -X POST http://127.0.0.1:8080/payments | python3 -m json.tool
```

**Kết quả:** HTTP 403, `fraud.score=75`, `gate=blocked`.

Scoring: `5 (base) + 55 (critical_amount ≥500M) + 15 (risky_channel=tor) = 75` → block.

---

### Demo 6 — Velocity Attack: lũ giao dịch từ 1 account (T1496)

**Kịch bản:** Flood 35 giao dịch liên tiếp từ cùng một account.

```bash
for i in $(seq 1 35); do
  RES=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -H "Host: api.ztlab.local" \
    -d "{\"from_account\":\"flood001\",\"to_account\":\"acc002\",\"amount\":150000000}" \
    -X POST http://127.0.0.1:8080/payments)
  SCORE=$(echo "$RES" | python3 -c "
import json,sys
d=json.load(sys.stdin)
f=d.get('fraud',{})
print(f\"score={f.get('score','?')} gate={f.get('gate','?')}\")" 2>/dev/null || echo "blocked")
  echo "req$i: $SCORE"
done
```

**Kết quả:** Từ request ~31 trở đi: `score=75, gate=blocked` → HTTP 403.

---

### Demo 7 — JWT token giả mạo (T1550.001)

**Kịch bản:** Token có cấu trúc hợp lệ nhưng ký bằng secret sai.

```bash
FAKE_TOKEN=$(python3 - <<'PY'
import time, json, base64, hmac, hashlib
secret = "wrong-secret-key"
now = int(time.time())
def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
header  = b64url(json.dumps({"alg":"HS256","typ":"JWT"}))
payload = b64url(json.dumps({"sub":"attacker","iss":"https://evil.com/realms/ztlab",
    "aud":"api-gateway","iat":now,"exp":now+3600,
    "realm_access":{"roles":["financial-write"]}}))
sig = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
print(f"{header}.{payload}.{b64url(sig)}")
PY
)

curl -s \
  -H "Authorization: Bearer $FAKE_TOKEN" \
  -H "Host: api.ztlab.local" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"acc001","to_account":"acc002","amount":100000}' \
  -X POST http://127.0.0.1:8080/payments
```

**Kết quả:** HTTP 401 — `jwt_verification_failed, reason=invalid_jwt`.

---

### Demo 8 — AI phát hiện và SOAR phản ứng

Sau các demo tấn công ở trên, AI Analyzer tự động poll Loki mỗi 120 giây. Để trigger ngay mà không cần đợi:

```bash
# Trigger AI analyze ngay lập tức
curl -s -X POST http://127.0.0.1:8090/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "source": "demo-manual",
    "logs": [
      {"message": "jwt_verification_failed source_ip=10.10.1.55 service=api-gateway count=15", "labels": {"job": "kubernetes-pods", "namespace": "financial"}},
      {"message": "payment_blocked_fraud fraud_score=75 source_ip=10.10.1.55 channel=tor amount=500000000", "labels": {"job": "kubernetes-pods", "service": "payment-service"}}
    ]
  }' | python3 -m json.tool
```

Kết quả mong đợi:
```json
{
    "verdict": "malicious",
    "severity": "high",
    "confidence": 0.78,
    "attack_type": "access_denied",
    "recommended_playbook": "isolate_workload",
    "provider_used": "gemini"
}
```

Kiểm tra SOAR cases được tạo tự động:

```bash
curl -s http://127.0.0.1:8091/cases | python3 -c "
import json, sys
cases = json.load(sys.stdin)
print(f'Tổng cases: {len(cases)}')
print('--- 5 cases gần nhất ---')
for c in cases[-5:]:
    print(f\"  [{c['status']:8}] {c['attack_type']:20} → {c['playbook']:22} sev={c['severity']}\")
"
```

**Trên Grafana:** Tab **AI SIEM SOAR** → thấy alert count và case count tăng lên.

---

### Demo 9 — Xem log cross-cloud trong Grafana

Vào **Grafana → Explore → datasource: Loki**:

```logql
# Xem tất cả log từ cả hai cloud
{job="kubernetes-pods", namespace="financial"} | json | line_format "{{.cloud}} | {{.service}} | {{.event}}"

# Chỉ log từ OpenStack
{job="kubernetes-pods", namespace="financial", cloud="openstack"}

# Giao dịch hoàn thành (cross-cloud)
{job="kubernetes-pods", namespace="financial"} |= "core_transaction_completed"

# OPA AWS cho phép (JWT validation)
{job="opa-decisions", cloud="aws"} | json | opa_result="true"

# OPA OpenStack cho phép (cross-cloud mTLS)
{job="opa-decisions", cloud="openstack"} | json | opa_result="true"

# OPA từ chối
{job="opa-decisions"} | json | opa_result="false"
```

---

## Phần 3 — Thứ tự demo gợi ý (15–20 phút)

```
┌─────────────────────────────────────────────────────────────────┐
│  THỨ TỰ DEMO TRƯỚC HỘI ĐỒNG                                     │
├─────────┬───────────────────────────────────────────────────────┤
│  1 phút │ Mở Grafana, bật auto-refresh 10s                      │
│         │ Giới thiệu 2 cluster (ctx-aws + ctx-openstack)        │
├─────────┼───────────────────────────────────────────────────────┤
│  2 phút │ Demo 1: kubectl get pods cả 2 cluster                 │
│         │ → core-banking 2/2 (Envoy sidecar mTLS)               │
│         │ → Chứng minh 2 K3s cluster thực sự tách biệt          │
├─────────┼───────────────────────────────────────────────────────┤
│  3 phút │ Demo 2: Giao dịch bình thường 100k VND                │
│         │ → SVID payment-service → OPA crosscloud → allow       │
│         │ → trace_id xuyên suốt AWS → OpenStack                 │
│         │ → Grafana Security Overview: OPA allow tăng           │
├─────────┼───────────────────────────────────────────────────────┤
│  2 phút │ Demo 3: Không có JWT → HTTP 403                       │
│         │ Demo 7: JWT giả mạo → HTTP 401                        │
├─────────┼───────────────────────────────────────────────────────┤
│  3 phút │ Demo 4: Brute force 15 lần → Alert Firing             │
│         │ → Grafana Alerting chuyển sang Firing                 │
├─────────┼───────────────────────────────────────────────────────┤
│  2 phút │ Demo 5: Fraud gate block (tor + 500M VND)             │
│         │ → score=75, gate=blocked                              │
├─────────┼───────────────────────────────────────────────────────┤
│  4 phút │ Demo 8: Trigger AI analyze                            │
│         │ → verdict=malicious, SOAR case tạo ra                 │
│         │ → Grafana AI SIEM SOAR: cases tăng lên                │
├─────────┼───────────────────────────────────────────────────────┤
│  2 phút │ Demo 9: Grafana Explore → LogQL                       │
│         │ → Log từ aws và openstack cùng trace_id               │
│         │ → OPA decisions từ cả 2 cluster                       │
└─────────┴───────────────────────────────────────────────────────┘
```

---

## Phần 4 — Restart sau khi tắt máy

### Tình huống A: Chỉ máy local tắt, EC2 vẫn đang chạy

Kiểm tra EC2 còn sống không:
```bash
ssh -i ~/.ssh/zta-siem-soar-key -o ConnectTimeout=8 ubuntu@54.254.145.86 "echo OK"
```

Nếu OK → làm lại **Bước 3 → 8** ở Phần 1 (bỏ qua Bước 1 và 2).

---

### Tình huống B: EC2 đã bị stop (hết giờ lab, hoặc chủ động tắt)

**Bước B1 — Bật EC2 trên AWS Console** (xem Bước 1, Phần 1)

Bật 4 instances, chờ status `2/2 checks passed`.

**Bước B2 — Kiểm tra bastion**

```bash
ssh -i ~/.ssh/zta-siem-soar-key -o ConnectTimeout=10 ubuntu@54.254.145.86 "echo OK && uptime"
```

**Bước B3 — Kiểm tra K3s đã tự lên chưa**

K3s tự khởi động khi EC2 boot. Kiểm tra sau ~2 phút:

```bash
# AWS cluster
ssh -i ~/.ssh/zta-siem-soar-key \
  -J ubuntu@54.254.145.86 ubuntu@10.10.1.10 \
  "kubectl get nodes --no-headers 2>/dev/null | awk '{print \$1, \$2}'"

# OpenStack cluster
ssh -i ~/.ssh/zta-siem-soar-key \
  -o StrictHostKeyChecking=no \
  -o ProxyCommand="ssh -i ~/.ssh/zta-siem-soar-key -o StrictHostKeyChecking=no -W %h:%p ubuntu@54.254.145.86" \
  ubuntu@10.10.1.12 \
  "kubectl get nodes --no-headers 2>/dev/null | awk '{print \$1, \$2}'"
```

Kết quả mong đợi:
```
ip-10-10-1-10   Ready     ← AWS master
ip-10-10-1-11   Ready     ← AWS worker
---
os-master   Ready         ← OpenStack node
```

Nếu `NotReady` → đợi thêm 1–2 phút, K3s sẽ tự recover.

**Bước B4 — Mở tunnels và chờ pods**

```bash
cd ~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
bash scripts/k8s-tunnel.sh up all
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml
```

Theo dõi pods đang khởi động (Ctrl+C khi tất cả Running):

```bash
watch -n 5 'kubectl --context ctx-aws get pods -A --no-headers | grep -v kube-system | grep -v Completed | awk "{printf \"%-20s %-35s %s\\n\", \$1, \$2, \$3}"'
```

Thường mất 3–5 phút để tất cả pods Running sau khi EC2 boot.

**Bước B5 — Tiếp tục từ Bước 4 (Phần 1)**

Mở UI tunnel, port-forward, và kiểm tra health như bình thường.

---

## Phần 5 — Xử lý sự cố thường gặp

### API trả về 405 Method Not Allowed

Nguyên nhân: gọi đúng path nhưng sai HTTP method. Bảng method đúng:

| Endpoint | Method đúng | Method sai → 405 |
|----------|-------------|------------------|
| `/health` | GET | POST, PUT, DELETE |
| `/payments` | POST | GET, PUT |
| `/metrics` | GET | POST |

Kiểm tra nhanh method đang dùng:

```bash
# Xem response header để biết lỗi từ đâu
curl -sv -X POST \
  -H "Host: api.ztlab.local" \
  http://127.0.0.1:8080/health 2>&1 | grep -E "< HTTP|detail|Allow"
# Nếu thấy "Method Not Allowed" → sai method
# Header "Allow: GET" sẽ cho biết method nào mới đúng
```

Lỗi hay gặp:

```bash
# SAI — POST vào /health
curl -X POST http://127.0.0.1:8080/health -H "Host: api.ztlab.local"
# → 405

# ĐÚNG — GET vào /health
curl http://127.0.0.1:8080/health -H "Host: api.ztlab.local"
# → 200

# SAI — GET vào /payments
curl http://127.0.0.1:8080/payments -H "Host: api.ztlab.local"
# → 403 (OPA chặn trước) hoặc 405 nếu OPA pass

# ĐÚNG — POST vào /payments
curl -X POST http://127.0.0.1:8080/payments \
  -H "Host: api.ztlab.local" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"acc001","to_account":"acc002","amount":100000,"currency":"VND"}'
```

---

### Tunnel kubectl không kết nối được

```bash
bash scripts/k8s-tunnel.sh status
# Nếu rỗng → tunnel chưa mở

bash scripts/k8s-tunnel.sh down
bash scripts/k8s-tunnel.sh up all
```

### Port-forward bị ngắt giữa chừng

```bash
kill $(pgrep -f "kubectl port-forward") 2>/dev/null
sleep 1
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml
kubectl --context ctx-aws port-forward -n plg-stack svc/grafana      3000:3000  --address=127.0.0.1 >/tmp/pf-grafana.log 2>&1 &
kubectl --context ctx-aws port-forward -n plg-stack svc/loki         3100:3100  --address=127.0.0.1 >/tmp/pf-loki.log    2>&1 &
kubectl --context ctx-aws port-forward -n plg-stack svc/ai-analyzer  8090:8080  --address=127.0.0.1 >/tmp/pf-ai.log     2>&1 &
kubectl --context ctx-aws port-forward -n plg-stack svc/soar-engine  8091:8080  --address=127.0.0.1 >/tmp/pf-soar.log   2>&1 &
```

### Promtail OS không push được log về Loki

```bash
# Kiểm tra socat proxy trên worker-1 còn chạy không
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.11 \
  "sudo systemctl status loki-proxy.service | head -5"

# Nếu stopped → start lại
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.11 \
  "sudo systemctl start loki-proxy.service"

# Xác nhận Promtail OS có push được không
kubectl --context ctx-openstack logs -n plg-stack daemonset/promtail --tail=5 | grep -E "error|ready|sending"
```

> **Lưu ý hạ tầng:** K3s NodePort không forward được traffic từ ngoài cluster vào pod trên node khác (flannel hairpin issue). Workaround đã dùng: `socat` chạy trên `ip-10-10-1-11` (node đang host Loki pod) lắng nghe `0.0.0.0:31100` và forward vào Loki ClusterIP. Service `loki-proxy.service` đã được enable để tự khởi động khi reboot.

### Cross-cloud payment trả về 503

```bash
# Kiểm tra core-banking có running không (2/2 = Envoy sidecar OK)
kubectl --context ctx-openstack get pods -n financial -l app=core-banking

# Kiểm tra Envoy inbound trên core-banking (mTLS, port 30081)
kubectl --context ctx-openstack logs -n financial deployment/core-banking -c envoy --tail=5

# Kiểm tra core-banking app health (port 30084 = plain HTTP)
ssh -i ~/.ssh/zta-siem-soar-key -J ubuntu@54.254.145.86 ubuntu@10.10.1.10 \
  "curl -sf --max-time 5 http://10.10.1.12:30084/health"

# Nếu NetworkPolicy bị mất → apply lại
kubectl --context ctx-aws apply -f k8s/financial/network-policies/aws-allow-list.yaml
kubectl --context ctx-openstack apply -f k8s/financial/network-policies/os-allow-list.yaml
```

### Cross-cloud payment trả về 403 (OPA ext_authz từ chối)

OPA trên OpenStack block request mTLS từ payment-service. Nguyên nhân thường gặp:

```bash
# Xem OPA decision log trên OpenStack
kubectl --context ctx-openstack logs -n financial deployment/opa-server --since=5m \
  | grep "Decision Log" | python3 -c "
import json,sys
for l in sys.stdin:
    try:
        d=json.loads(l)
        if 'Decision Log' in d.get('msg',''):
            print('result:', d.get('result'), '| src:', d.get('input',{}).get('source_principal','?'))
    except: pass
"

# Kiểm tra NetworkPolicy (port 9191 phải cho phép intra-namespace)
kubectl --context ctx-openstack get networkpolicy -n financial os-financial-allow-baseline -o yaml | grep -A5 "9191"

# Kiểm tra SPIRE agent đang cấp SVID cho Envoy core-banking không
kubectl --context ctx-openstack logs -n spire daemonset/spire-agent --tail=10 | grep -E "SVID|error|issued"
```

Nếu NetworkPolicy thiếu port 9191:
```bash
kubectl --context ctx-openstack apply -f k8s/financial/network-policies/os-allow-list.yaml
```

### SPIRE SVID không được cấp cho OpenStack workloads

SPIRE agent trên OpenStack kết nối về SPIRE server AWS qua NodePort 30900.

```bash
# Kiểm tra SPIRE agent log
kubectl --context ctx-openstack logs -n spire daemonset/spire-agent --tail=20 | grep -E "attestation|token|error|SVID"

# Kiểm tra entries đã đăng ký
kubectl --context ctx-aws exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server entry show | grep -E "openstack|SPIFFE ID" | head -10

# Nếu SPIRE agent không connect được server → kiểm tra NodePort 30900
kubectl --context ctx-aws get svc -n spire spire-server
```

> **Lưu ý:** SPIRE agent OpenStack dùng `join_token` attestation. Token hiện tại có thể hết hạn sau 10 phút nếu agent restart và chưa hoàn thành attestation. Kiểm tra trạng thái trong log agent.

### Pod đang Pending hoặc CrashLoopBackOff

```bash
kubectl --context ctx-aws describe pod -n <namespace> <pod-name>
kubectl --context ctx-aws logs -n <namespace> <pod-name> --previous --tail=50
kubectl --context ctx-aws rollout restart deployment/<tên> -n <namespace>
```

### AI đang backoff (quota hết)

```bash
curl -s http://127.0.0.1:8090/health | python3 -c "
import json,sys; d=json.load(sys.stdin)
print('Provider:', d['provider'])
print('Backoff còn:', d['provider_backoff_remaining_seconds'], 'giây')
"
```

Nếu backoff > 0 giây → đổi sang heuristic để demo offline:

```bash
kubectl --context ctx-aws patch secret ai-secrets -n plg-stack --type=json \
  -p='[{"op":"replace","path":"/data/AI_PROVIDER","value":"'$(echo -n 'heuristic' | base64)'"}]'
kubectl --context ctx-aws rollout restart deployment/ai-analyzer -n plg-stack
sleep 30
curl -s http://127.0.0.1:8090/health | python3 -c "import json,sys; print(json.load(sys.stdin)['provider'])"
# heuristic
```

### Prometheus targets DOWN

```bash
# Kiểm tra targets (9/9 phải UP)
kubectl --context ctx-aws port-forward -n monitoring svc/prometheus 19090:9090 &
sleep 3
curl -s "http://localhost:19090/api/v1/targets?state=active" | python3 -c "
import json,sys
tgts = json.load(sys.stdin)['data']['activeTargets']
up = sum(1 for t in tgts if t['health']=='up')
print(f'{up}/{len(tgts)} UP')
for t in tgts:
    if t['health'] != 'up':
        print('DOWN:', t['scrapeUrl'], '—', t.get('lastError',''))
"
kill %1 2>/dev/null
```

> **Lưu ý:** Core-banking scrape qua port `30084` (plain HTTP). Port `30081` là mTLS Envoy và KHÔNG dùng được cho Prometheus.

---

## Phần 6 — Tùy chỉnh nâng cao

### Bật SOAR live mode (thực thi thật)

> ⚠️ Khi `DRY_RUN=false`, SOAR **thực sự** scale down / isolate pods trong cluster.

```bash
# Bật live mode
kubectl --context ctx-aws patch secret ai-secrets -n plg-stack --type=json \
  -p='[{"op":"replace","path":"/data/SOAR_DRY_RUN","value":"'$(echo -n 'false' | base64)'"}]'
kubectl --context ctx-aws rollout restart deployment/soar-engine -n plg-stack

# Tắt lại về dry-run (an toàn)
kubectl --context ctx-aws patch secret ai-secrets -n plg-stack --type=json \
  -p='[{"op":"replace","path":"/data/SOAR_DRY_RUN","value":"'$(echo -n 'true' | base64)'"}]'
kubectl --context ctx-aws rollout restart deployment/soar-engine -n plg-stack
```

### Rollback case sau khi SOAR thực thi

```bash
CASE_ID=$(curl -s http://127.0.0.1:8091/cases | python3 -c "
import json,sys; cases=json.load(sys.stdin)
if cases: print(cases[-1]['case_id'])
")
echo "Case ID: $CASE_ID"
curl -s http://127.0.0.1:8091/cases/$CASE_ID | python3 -m json.tool
curl -s -X POST http://127.0.0.1:8091/cases/$CASE_ID/rollback | python3 -m json.tool
```

### Redeploy một phần sau khi sửa code

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

# AWS services
kubectl --context ctx-aws apply -f k8s/financial/aws-services.yaml
kubectl --context ctx-aws rollout restart deployment -n financial

# OpenStack services (bao gồm Envoy sidecar core-banking)
kubectl --context ctx-openstack apply -f k8s/financial/os-services.yaml
kubectl --context ctx-openstack apply -f k8s/financial/os-security.yaml
kubectl --context ctx-openstack rollout restart deployment -n financial

# Envoy configmap AWS (cross-cloud routing + mTLS upstream)
kubectl --context ctx-aws apply -f envoy/configmap.yaml
kubectl --context ctx-aws rollout restart deployment/payment-service deployment/api-gateway -n financial

# NetworkPolicy (cả 2 cluster)
kubectl --context ctx-aws apply -f k8s/financial/network-policies/aws-allow-list.yaml
kubectl --context ctx-openstack apply -f k8s/financial/network-policies/os-allow-list.yaml

# OPA policies AWS
kubectl --context ctx-aws apply -f opa/deployment.yaml
kubectl --context ctx-aws rollout restart deployment/opa-server -n financial
```

### Redeploy toàn bộ từ đầu

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml
bash scripts/deploy-all.sh --skip-images
# ~20–30 phút
```

---

## Phần 7 — Thông tin tham chiếu nhanh

### LogQL queries hay dùng trong Grafana Explore

```logql
# Toàn bộ traffic tài chính theo cloud
{job="kubernetes-pods", namespace="financial"} | json | line_format "{{.cloud}} | {{.service}} | {{.event}}"

# Chỉ OpenStack logs
{job="kubernetes-pods", namespace="financial", cloud="openstack"}

# OPA AWS từ chối (JWT không hợp lệ)
{job="opa-decisions", cloud="aws"} | json | opa_result="false"

# OPA OpenStack cho phép (cross-cloud mTLS)
{job="opa-decisions", cloud="openstack"} | json | opa_result="true"

# Brute force indicator
{job="kubernetes-pods", namespace="financial"} |= "jwt_verification_failed"

# Fraud block
{job="kubernetes-pods", namespace="financial"} |= "payment_blocked_fraud"

# Cross-cloud giao dịch hoàn thành
{job="kubernetes-pods"} |= "core_transaction_completed"

# AI phát hiện tấn công
{job="ai-analyzer"} |= "ai_security_alert"

# SOAR đã tạo case
{job="soar-engine"} |= "soar_action"
```

### Prometheus PromQL hay dùng

```promql
ztlab_auth_failures_total                   # Lỗi xác thực theo service
ztlab_txn_total{status="completed"}         # Giao dịch thành công
ztlab_txn_total{status="blocked_fraud"}     # Giao dịch bị chặn do fraud
ztlab_fraud_score_sum / ztlab_fraud_score_count  # Fraud score trung bình
ztlab_cross_cloud_latency_seconds           # Latency AWS → OpenStack (mTLS)
ztlab_service_up                            # Health các service
```

### Kiểm tra SPIRE

```bash
# Xem tất cả workload entries đã đăng ký
kubectl --context ctx-aws exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server entry show | grep -E "SPIFFE ID|Entry ID"
# Kết quả: ~16 entries (AWS + OpenStack workloads)

# Xem SVID đang được cấp cho Envoy core-banking
kubectl --context ctx-openstack logs -n spire daemonset/spire-agent --tail=20 \
  | grep -E "SVID|issued|attestation"
```

### Kiểm tra cross-cloud mTLS

```bash
# Xem Envoy core-banking access log (xác nhận SVID payment-service)
kubectl --context ctx-openstack logs -n financial deployment/core-banking -c envoy --tail=5

# Kết quả expect:
# {"svid":"spiffe://ztlab.local/aws/payment-service","response_code":200,...}

# Xem OPA OpenStack decision log (xác nhận policy allow)
kubectl --context ctx-openstack logs -n financial deployment/opa-server --since=2m \
  | grep "Decision Log"
```

### Scripts có sẵn

| Script | Mục đích |
|--------|----------|
| `scripts/deploy-all.sh` | Deploy toàn bộ hệ thống từ đầu |
| `scripts/deploy-security-stack.sh` | Deploy riêng SPIRE / OPA / Envoy |
| `scripts/k8s-tunnel.sh up all` | Mở kubectl tunnel 2 cluster |
| `scripts/gen-dev-token.sh` | Tạo JWT token để test |
| `scripts/health-check.sh` | Kiểm tra health toàn bộ hệ thống |
| `scripts/run-demo.sh` | Chạy kịch bản demo tự động |
| `scripts/sync-financial-images.sh` | Sync Docker images sang K3s nodes |

---

*Xem báo cáo đầy đủ tại [BAOCAO.md](BAOCAO.md)*
