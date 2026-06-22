# ZTLab — Hướng Dẫn Vận Hành & Demo

**Zero Trust Security Detection and Response for Microservices in Multi-Cloud**  
Sinh viên: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
Hệ thống: AWS K3s + OpenStack K3s · SPIRE mTLS · Envoy + OPA · Keycloak OIDC · PLG Stack · AI Analyzer · SOAR Engine

---

## Mục lục

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Bật EC2 instances](#2-bật-ec2-instances)
3. [Mở tunnel & port-forward](#3-mở-tunnel--port-forward)
4. [Health check toàn hệ thống](#4-health-check-toàn-hệ-thống)
5. [Tài khoản & credentials](#5-tài-khoản--credentials)
6. [Test end-to-end: Payment flow](#6-test-end-to-end-payment-flow)
7. [Web Portal (banking UI)](#7-web-portal-banking-ui)
8. [Grafana — Dashboards & Alerts](#8-grafana--dashboards--alerts)
9. [AI Analyzer & SOAR Engine](#9-ai-analyzer--soar-engine)
10. [Phản ứng sự cố thủ công](#10-phản-ứng-sự-cố-thủ-công)
11. [Database admin UIs (pgAdmin & RedisInsight)](#11-database-admin-uis-pgadmin--redisinsight)
12. [Chạy kịch bản tấn công](#12-chạy-kịch-bản-tấn-công)
13. [Các lỗi thường gặp & fix](#13-các-lỗi-thường-gặp--fix)

---

## 1. Tổng quan kiến trúc

```
Internet
   |  HTTPS/PKCE
   v
+---------------------------- AWS K3s (10.10.1.10/11) ----------------------------+
|  identity ns:  Keycloak (OIDC realm=ztlab)                                      |
|  financial ns: api-gateway <--Envoy(15006)--OPA ext_authz(9191)                 |
|                web-portal --PKCE--> Keycloak                                    |
|                payment-service --SPIRE mTLS--> fraud-detection                  |
|                notification-service                                              |
|                Redis (DB0=fraud+blocklist, DB1=scorer, DB2=soar)                |
|  plg-stack ns: Promtail --> Loki --> Grafana (5 dashboards, 6 alert rules)      |
|                AI Analyzer (poll Loki 30s) --> SOAR Engine                      |
|                Security Scorer · TheHive                                         |
|  monitoring ns: Prometheus                                                       |
|  spire ns:     SPIRE server + agent                                             |
|                                                                                  |
|  WireGuard VPN (10.200.0.0/30) <---------------------------------------------  |
+---------------------------------------------------------------------------------+
                                              |
+----------------------- OpenStack K3s (10.10.1.12) ------------------------------+
|  financial ns: core-banking <--Envoy(15006)--OPA cross_cloud                   |
|                account-service --> postgres-accounts (accounts_db)               |
|                transaction-service --> postgres-txn (transactions_db)            |
|  spire ns:     SPIRE agent (join_token attestation)                             |
+---------------------------------------------------------------------------------+
```

**Payment flow:**

```
User JWT --> api-gateway
  |-- Envoy sidecar --> OPA zta_policy.rego (valid JWT + role financial-write --> allow)
  |-- api-gateway: verify JWT RS256 via Keycloak JWKS, rate-limit, Redis IP-blocklist
  --> payment-service (SPIRE mTLS)
        |-- fraud-detection: Redis velocity --> fraud_score (gate < 75 = passed)
        --> core-banking (SPIRE mTLS cross-cloud, OPA cross_cloud.rego)
              |-- account-service --> postgres-accounts (debit/credit)
              --> transaction-service --> postgres-txn (ledger)
```

**Namespace layout:**

| Namespace | Cluster | Services |
|-----------|---------|----------|
| `identity` | AWS | Keycloak |
| `financial` | AWS | api-gateway, payment-service, fraud-detection, notification-service, web-portal, Redis, pgAdmin, RedisInsight |
| `financial` | OpenStack | core-banking, account-service, transaction-service, postgres-accounts, postgres-txn, OPA |
| `plg-stack` | AWS | Loki, Grafana, Promtail, AI Analyzer, SOAR Engine, Security Scorer, TheHive |
| `monitoring` | AWS | Prometheus |
| `spire` | both | SPIRE server (AWS) + agents |

---

## 2. Bật EC2 instances

Instances tắt khi không dùng. Sau khi bật, **IP bastion sẽ thay đổi** — phải cập nhật inventory.

```bash
# Bật tất cả instances
aws ec2 start-instances --region ap-southeast-1 --instance-ids \
  i-BASTION i-GATEWAY i-MASTER i-WORKER1 i-SECURITY i-OS_MASTER

# Đợi running (~2 phút)
aws ec2 wait instance-running --region ap-southeast-1 --instance-ids \
  i-BASTION i-GATEWAY i-MASTER i-WORKER1 i-SECURITY i-OS_MASTER

# Lấy IP mới của bastion
NEW_BASTION_IP=$(aws ec2 describe-instances --region ap-southeast-1 \
  --instance-ids i-BASTION \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "Bastion IP moi: $NEW_BASTION_IP"
```

Cập nhật `ansible/inventory/hosts.yml`: thay `ansible_host` của `aws_bastion` và tất cả `ProxyJump` bằng IP mới.

> **IP hiện tại:** bastion = `52.221.255.36` (thay đổi sau mỗi lần restart)

---

## 3. Mở tunnel & port-forward

### 3.1 K8s API tunnels

```bash
# Mở cả hai cluster (AWS + OpenStack)
bash scripts/k8s-tunnel.sh up all

# Kiểm tra
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

Nếu kubeconfig chưa có context hoặc certs hết hạn:

```bash
SYNC_KUBECONFIG_ON_UP=true bash scripts/k8s-tunnel.sh up all
```

### 3.2 Port-forwards — dùng script (khuyên dùng)

```bash
bash scripts/open-admin-uis.sh
```

Script này mở tất cả port-forwards và in URL/credentials. Nhấn `Ctrl+C` để tắt tất cả khi xong.

**Các port được mở:**

| Service | Port local | Namespace |
|---------|-----------|-----------|
| Keycloak | 8180 | identity |
| API Gateway | 18080 | financial |
| Web Portal | 18081 | financial |
| Grafana | 3000 | plg-stack |
| Loki | 13100 | plg-stack |
| SOAR Engine | 8091 | plg-stack |
| AI Analyzer | 8090 | plg-stack |
| Security Scorer | 18092 | plg-stack |
| Prometheus | 9090 | monitoring |
| pgAdmin | 5050 | financial |
| RedisInsight | 5540 | financial |

### 3.3 Tắt tunnel khi xong

```bash
bash scripts/k8s-tunnel.sh down all
# Port-forwards tắt tự động khi Ctrl+C thoát scripts/open-admin-uis.sh
```

---

## 4. Health check toàn hệ thống

```bash
bash scripts/health-check.sh
```

Điều kiện tối thiểu trước demo: `FAIL=0`. Các `WARN` về SSH/Ansible có thể bỏ qua nếu không chạy `--full`.

```bash
# Kiểm tra nhanh từng thành phần
curl -s http://127.0.0.1:13100/ready                               # Loki
curl -s http://127.0.0.1:3000/api/health                           # Grafana
curl -s http://127.0.0.1:18080/health | python3 -m json.tool       # API Gateway (jwks_keys_loaded=1)
curl -s http://127.0.0.1:8090/health                               # AI Analyzer
curl -s http://127.0.0.1:8091/health                               # SOAR Engine
curl -s http://127.0.0.1:18092/health                              # Security Scorer
```

### Kiểm tra pods

```bash
kubectl --context ctx-aws -n financial get pods        # api-gateway, payment-service, ...
kubectl --context ctx-aws -n plg-stack get pods        # loki, grafana, ai-analyzer, soar-engine, ...
kubectl --context ctx-aws -n identity get pods         # keycloak
kubectl --context ctx-aws -n spire get pods            # spire-server, spire-agent
kubectl --context ctx-openstack -n financial get pods  # core-banking, account-service, transaction-service
kubectl --context ctx-openstack -n spire get pods      # spire-agent
```

Pods `2/2 Running` = có Envoy sidecar. `1/1 Running` = không có sidecar (bình thường với scorer/thehive).

### Kiểm tra Redis

```bash
kubectl --context ctx-aws -n financial exec deploy/redis -- \
  sh -c 'redis-cli -a $REDIS_PASSWORD --no-auth-warning ping'
# --> PONG
```

### Kiểm tra OPA

```bash
kubectl --context ctx-aws -n financial port-forward svc/opa-service 18083:8181 --address=127.0.0.1 &
sleep 2
curl -s http://127.0.0.1:18083/v1/policies \
  | python3 -c "import json,sys; [print(x['id']) for x in json.load(sys.stdin)['result']]"
kill %1
```

---

## 5. Tài khoản & credentials

### Service URLs

| Service | URL | Credential |
|---------|-----|------------|
| **Web Portal** | http://127.0.0.1:18081 | Đăng nhập OIDC → Keycloak |
| **API Gateway** | http://127.0.0.1:18080 | JWT Bearer token |
| **Keycloak Admin** | http://127.0.0.1:8180 | `admin` / `ztlab-admin-2026` |
| **Grafana** | http://127.0.0.1:3000 | `admin` / `ZTALab2026!` |
| **Loki** | http://127.0.0.1:13100 | — |
| **Prometheus** | http://127.0.0.1:9090 | — |
| **AI Analyzer** | http://127.0.0.1:8090 | — (Bearer `SOAR_API_TOKEN` cho approve/dismiss) |
| **SOAR Engine** | http://127.0.0.1:8091 | Bearer `SOAR_API_TOKEN` |
| **Security Scorer** | http://127.0.0.1:18092 | — |
| **pgAdmin** | http://127.0.0.1:5050 | `admin@ztlab.com` / `ztlab2026` |
| **RedisInsight** | http://127.0.0.1:5540 | — (add connection thủ công, xem mục 11) |

### Tài khoản người dùng (Keycloak realm: ztlab)

| Username | Password | Roles | Account số |
|----------|----------|-------|------------|
| `testuser01` | `Test1234!` | financial-read, financial-write | ACC-1001 |
| `testuser02` | `Test1234!` | financial-read, financial-write | ACC-2001 |
| `demoadmin` | `DemoAdmin2026!` | financial-read, financial-write, security-analyst, security-admin | ACC-3001 |
| `merchant01` | `Test1234!` | financial-read, financial-write | ACC-4001 |
| `analyst01` | `Analyst1234!` | security-analyst | — |

### Database credentials

| Database | Host (OpenStack cluster-internal) | DB | User | Pass |
|----------|----------------------------------|-----|------|------|
| Accounts | `postgres-accounts.financial.svc.cluster.local:5432` | `accounts_db` | `accounts_user` | `accounts_pass` |
| Transactions | `postgres-txn.financial.svc.cluster.local:5432` | `transactions_db` | `txn_user` | `txn_pass` |

pgAdmin được pre-configured sẵn với cả hai server — xem mục 11.

### Redis

Redis chạy trên AWS cluster, namespace `financial`, port 6379.  
Password: `ZTALab-Redis-2026!` (Secret `redis-auth`, key `password`).

| DB index | Dùng cho |
|----------|----------|
| DB0 | fraud-detection velocity cache + IP blocklist (`ztlab:blocked_ip:*`) |
| DB1 | security-scorer anomaly score cache |
| DB2 | SOAR engine case store |

---

## 6. Test end-to-end: Payment flow

### Bước 1 — Lấy JWT token

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8180/realms/ztlab/protocol/openid-connect/token \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=web-portal" \
  --data-urlencode "username=testuser01" \
  --data-urlencode "password=Test1234!" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

echo "Token: ${TOKEN:0:40}..."
```

> `web-portal` là public PKCE client — không cần client secret.  
> Token issuer phải là `http://keycloak.ztlab.local:8180/realms/ztlab` (OPA kiểm tra chính xác chuỗi này, bao gồm port `:8180`).

### Bước 2 — Gửi payment

```bash
curl -s -X POST http://127.0.0.1:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "from_account": "ACC-1001",
    "to_account":   "ACC-2001",
    "amount":       500000,
    "currency":     "VND",
    "memo":         "test payment"
  }' | python3 -m json.tool
```

**Kết quả thành công:**
```json
{
  "status": "completed",
  "fraud": { "score": 5, "verdict": "allow", "gate": "passed" },
  "core_banking": {
    "transaction_id": "...",
    "status": "completed",
    "from_balance": 9500000
  }
}
```

### Bước 3 — Kiểm tra tài khoản

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18080/accounts | python3 -m json.tool
```

### Debug JWT payload

```bash
echo "$TOKEN" | python3 -c "
import sys, base64, json
t = sys.stdin.read().strip().split('.')
p = t[1] + '=' * (-len(t[1]) % 4)
d = json.loads(base64.urlsafe_b64decode(p))
print('iss:', d.get('iss'))
print('exp:', d.get('exp'))
print('roles:', d.get('realm_access', {}).get('roles', []))
"
```

---

## 7. Web Portal (banking UI)

Truy cập `http://127.0.0.1:18081` trong browser.

**Flow đăng nhập (PKCE):**
1. Click "Đăng nhập" → redirect tới Keycloak (`http://127.0.0.1:8180`)
2. Nhập username/password (vd: `testuser01` / `Test1234!`)
3. Keycloak redirect về `/auth/callback` với code
4. Web Portal exchange code → RS256 access token (lưu phía server trong session cookie, không trong browser)
5. Dashboard hiển thị bank card, balance, transaction history

**Các trang:**

| Path | Mô tả | Quyền tối thiểu |
|------|-------|-----------------|
| `/login` | Đăng nhập OIDC redirect | — |
| `/dashboard` | Tổng quan tài khoản | financial-read |
| `/transfer` | Chuyển tiền | financial-write |
| `/profile` | Thông tin tài khoản | financial-read |
| `/security` | SOAR cases, HITL approval, block IP | security-analyst |
| `/admin` | Tất cả accounts + giao dịch (join Keycloak) | security-admin |
| `/scenarios` | Chạy demo kịch bản tấn công | security-analyst |
| `/register` | Tự đăng ký tài khoản (rate-limit 5/giờ/IP) | — |

**Trang `/security`** (role `security-analyst` hoặc `security-admin`):
- Xem SOAR cases với trạng thái (pending/executed/rolled_back)
- Xem danh sách pending AI alerts cần HITL approval
- Approve hoặc dismiss từng alert
- Xem và quản lý IPs đang bị block
- Rollback SOAR case đã thực thi

---

## 8. Grafana — Dashboards & Alerts

URL: `http://127.0.0.1:3000` | `admin` / `ZTALab2026!`

### 5 Dashboards (provisioned qua ConfigMap)

| Tên dashboard | File | UID |
|---------------|------|-----|
| ZTLab Security Overview | `zta-security-overview.json` | `ztlab-security-overview` |
| Envoy Access Logs | `envoy-access-logs.json` | `ztlab-envoy-access-logs` |
| OPA Decision Log | `opa-decision-log.json` | `ztlab-opa-decision-log` |
| ZTLab AI SIEM SOAR | `ai-siem-soar.json` | `ztlab-ai-siem-soar` |
| Threat Intelligence Feed | `threat-intel-feed.json` | `ztlab-threat-intel` |

### 6 Alert rules + 1 Notification policy

| Alert | Kịch bản | MITRE | Severity |
|-------|----------|-------|----------|
| Brute Force Login | SC-1 | T1110.001 | high |
| Lateral Movement (Invalid SVID) | SC-2 | T1021.007 | critical |
| Fraud Gate Bypass | SC-3 | T1078.004 | critical |
| Data Exfiltration (Large Response) | SC-4 | T1041 | high |
| AI Anomaly Score >= 70 | SC-5 | T1059 | critical |
| SOAR Action Recorded | — | — | info |

Alert rules dùng **LogQL** (query Loki trực tiếp), evaluate every 1 minute.

**Notification routing:**
- Contact point `ztlab-security-admin` → email `voha2005@gmail.com`
- Webhook receiver `ztlab-soar-webhook` → `http://soar-engine.plg-stack.svc.cluster.local:8080/grafana-webhook`

Grafana alerts kích hoạt SOAR Engine qua webhook. AI Analyzer cũng có pipeline song song riêng (xem mục 9).

### Test notification email

```bash
curl -s -X POST -u admin:ZTALab2026! \
  "http://127.0.0.1:3000/api/alertmanager/grafana/config/api/v1/receivers/test" \
  -H "Content-Type: application/json" \
  -d '{"receivers":[{"name":"ztlab-security-admin","grafana_managed_receiver_configs":[{"name":"ztlab-security-admin","type":"email","settings":{"addresses":"voha2005@gmail.com"}}]}]}'
```

### Xem alert state

```bash
curl -s -u admin:ZTALab2026! http://127.0.0.1:3000/api/v1/provisioning/alert-rules \
  | python3 -c "import json,sys; [print(r['title'], '|', r.get('noDataState','')) for r in json.load(sys.stdin)]"
```

---

## 9. AI Analyzer & SOAR Engine

### Luồng tự động

```
Promtail (DaemonSet) --> Loki
                           | (poll moi 30s)
                        AI Analyzer (port 8090)
                        |  severity: low/medium  --> SOAR Engine POST /alerts (auto)
                        |  severity: high/critical --> pending_alerts[], email admin (HITL)
                        v
                     SOAR Engine (port 8091)
                        | thuc thi playbook
                        +--> Kubernetes API (scale/patch/NetworkPolicy)
                        +--> Keycloak Admin API (revoke sessions)
                        +--> Redis (block IP)
```

**AI detection rules (heuristic, không cần API key):**

| Pattern | Attack type | Severity |
|---------|-------------|----------|
| 5+ lần 401 từ cùng IP trong 1 phút | brute_force | high |
| OPA deny với SVID không hợp lệ | lateral_movement | critical |
| Payment thiếu header `x-fraud-gate: passed` | fraud_gate_bypass | critical |
| Response body >1MB từ OpenStack | data_exfiltration | high |
| Security scorer score ≥ 70 | anomaly | critical |

Nếu dùng OpenAI/Gemini: đặt `AI_PROVIDER=openai` hoặc `gemini` trong Secret `ai-secrets`, chain: GPT-4o-mini → Gemini 1.5 Flash → Heuristic fallback.

### HITL approval flow

```
1. AI Analyzer detect severity >= high
2. Alert lưu vào pending_alerts[] (state=pending), gửi email admin
3. Admin vào Web Portal /security --> Approve
   hoặc gọi API trực tiếp:
   POST http://127.0.0.1:8090/pending/{alert_id}/approve
4. AI Analyzer gọi SOAR Engine POST /alerts
5. SOAR Engine thực thi playbook, lưu case, trả về case_id
```

### API AI Analyzer (port 8090)

```bash
# Danh sách pending alerts
curl -s http://127.0.0.1:8090/pending | python3 -m json.tool

# Approve (HITL)
curl -s -X POST http://127.0.0.1:8090/pending/{alert_id}/approve | python3 -m json.tool

# Dismiss
curl -s -X POST http://127.0.0.1:8090/pending/{alert_id}/dismiss | python3 -m json.tool

# Phân tích log trực tiếp (test)
curl -s -X POST http://127.0.0.1:8090/analyze \
  -H "Content-Type: application/json" \
  -d '{"log_line":"{\"response_code\":401,\"source_ip\":\"10.0.0.99\",\"path\":\"/payments\"}","labels":{"job":"envoy-access","cloud":"aws"}}' \
  | python3 -m json.tool
```

### API SOAR Engine (port 8091)

```bash
# Danh sách cases
curl -s http://127.0.0.1:8091/cases | python3 -m json.tool

# Playbooks có sẵn
curl -s http://127.0.0.1:8091/playbooks | python3 -m json.tool

# IPs đang bị block
curl -s http://127.0.0.1:8091/blocked-ips | python3 -m json.tool

# Rollback case
curl -s -X POST http://127.0.0.1:8091/cases/{case_id}/rollback | python3 -m json.tool
```

**6 playbooks của SOAR Engine:**

| Playbook | Hành động | Áp dụng cho |
|----------|-----------|-------------|
| `block_source_ip` | Redis SET `ztlab:blocked_ip:{ip}` TTL 24h | Brute force |
| `revoke_user_sessions` | Keycloak Admin API logout all sessions | Brute force |
| `isolate_workload` | Patch K8s Service selector → không có endpoint | Lateral movement |
| `restrict_egress` | Tạo NetworkPolicy egress deny | Data exfiltration |
| `quarantine_workload` | Scale deployment xuống 0 replicas | Fraud gate bypass |
| `monitor_only` | Log alert, không hành động | Low severity |

### Inject test log để kích hoạt AI Analyzer

```bash
LOKI_URL="http://127.0.0.1:13100"
NOW=$(python3 -c "import time; print(int(time.time()*1e9))")

curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
  -H "Content-Type: application/json" \
  -d "{\"streams\":[{\"stream\":{\"job\":\"envoy-access\",\"namespace\":\"financial\",\"cloud\":\"aws\"},\"values\":[[\"$NOW\",\"{\\\"response_code\\\":401,\\\"source_ip\\\":\\\"10.0.0.99\\\",\\\"path\\\":\\\"/payments\\\",\\\"method\\\":\\\"POST\\\"}\"]]}]}"

# Đợi ~35 giây rồi kiểm tra
sleep 35
curl -s http://127.0.0.1:8090/pending | python3 -m json.tool
```

---

## 10. Phản ứng sự cố thủ công

### Block/unblock IP (Redis CLI)

```bash
# Block IP (TTL 24h)
kubectl --context ctx-aws -n financial exec deploy/redis -- \
  sh -c 'redis-cli -a $REDIS_PASSWORD --no-auth-warning \
    SET "ztlab:blocked_ip:10.0.0.99" \
    "{\"reason\":\"manual\",\"by\":\"admin\"}" EX 86400'

# Liệt kê IPs bị block
kubectl --context ctx-aws -n financial exec deploy/redis -- \
  sh -c 'redis-cli -a $REDIS_PASSWORD --no-auth-warning KEYS "ztlab:blocked_ip:*"'

# Unblock
kubectl --context ctx-aws -n financial exec deploy/redis -- \
  sh -c 'redis-cli -a $REDIS_PASSWORD --no-auth-warning DEL "ztlab:blocked_ip:10.0.0.99"'
```

### Revoke tất cả sessions Keycloak

```bash
ADMIN_TOKEN=$(curl -s -X POST http://127.0.0.1:8180/realms/master/protocol/openid-connect/token \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=ztlab-admin-2026" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://127.0.0.1:8180/admin/realms/ztlab/logout-all"
```

### Isolate service (ngăn traffic)

```bash
# Isolate payment-service (Service selector không match pod nào)
kubectl --context ctx-aws -n financial patch svc payment-service --type='json' \
  -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service","isolated":"true"}}]'

# Rollback
kubectl --context ctx-aws -n financial patch svc payment-service --type='json' \
  -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

### Scale down / restore service

```bash
kubectl --context ctx-aws -n financial scale deployment/payment-service --replicas=0
kubectl --context ctx-aws -n financial scale deployment/payment-service --replicas=1
```

---

## 11. Database admin UIs (pgAdmin & RedisInsight)

### pgAdmin — quản lý PostgreSQL

URL: `http://127.0.0.1:5050` | `admin@ztlab.com` / `ztlab2026`

pgAdmin được **pre-configured** với 2 server (xem `k8s/financial/db-admin-ui.yaml`):
- **ZTLab Accounts DB** → `postgres-accounts.financial.svc.cluster.local:5432` — `accounts_db / accounts_user`
- **ZTLab Transactions DB** → `postgres-txn.financial.svc.cluster.local:5432` — `transactions_db / txn_user`

Mở pgAdmin → click server trong tree → **Connect** (điền password khi được hỏi: `accounts_pass` hoặc `txn_pass`).

**Demo queries:**
```sql
-- Tất cả tài khoản và số dư
SELECT account_number, owner_username, balance FROM accounts ORDER BY account_number;

-- 20 giao dịch gần nhất
SELECT * FROM transactions ORDER BY created_at DESC LIMIT 20;

-- Tổng giao dịch theo từng tài khoản
SELECT from_account, count(*) as total, sum(amount) as total_amount
FROM transactions GROUP BY from_account ORDER BY total DESC;
```

### RedisInsight — quản lý Redis

URL: `http://127.0.0.1:5540`

Lần đầu mở → **"+ Add Redis Database"** → điền:

| Field | Giá trị |
|-------|---------|
| Host | `redis.financial.svc.cluster.local` |
| Port | `6379` |
| Password | `ZTALab-Redis-2026!` |
| Alias | `ZTLab Redis` |

> Host `redis.financial.svc.cluster.local` resolve được vì RedisInsight chạy trong K8s cluster.

**Demo queries (dùng CLI tab trong RedisInsight):**
```
# DB0 — IPs bị block
KEYS ztlab:blocked_ip:*

# DB0 — Fraud velocity counter của một IP
KEYS ztlab:fraud:velocity:*

# DB1 — Security scorer
SELECT 1
KEYS *

# DB2 — SOAR cases
SELECT 2
KEYS *
```

---

## 12. Chạy kịch bản tấn công

```bash
# Full demo: normal traffic + attacks
bash scripts/run-demo.sh

# Chỉ traffic bình thường
bash scripts/run-demo.sh --traffic-only

# Chỉ attack scenarios
bash scripts/run-demo.sh --attack-only

# Loop liên tục (Ctrl+C để dừng)
bash scripts/run-demo.sh --continuous
```

### 7 kịch bản riêng lẻ

| Script | Mô tả | MITRE | Alert kích hoạt |
|--------|-------|-------|-----------------|
| `tests/scenario_01_brute_force.sh` | 10+ lần login thất bại | T1110.001 | Brute Force Login |
| `tests/scenario_02_jwt_forgery.py` | JWT giả mạo HS256 | T1078.004 | OPA deny (403) |
| `tests/scenario_03_lateral_movement.sh` | SVID không hợp lệ giữa services | T1021.007 | Lateral Movement |
| `tests/scenario_04_fraud_gate_bypass.py` | Payment bypass fraud gate | T1078.004 | Fraud Gate Bypass |
| `tests/scenario_05_high_velocity.py` | 100 giao dịch/phút | T1499 | AI Anomaly Score |
| `tests/scenario_06_exfiltration.py` | Response body >1MB | T1041 | Data Exfiltration |
| `tests/scenario_11_cryptomining.sh` | CPU spike bất thường | T1496 | AI Anomaly Score |

### Thu thập metrics demo

```bash
python3 tests/collect_metrics.py
# Đo: MTTD (inject log -> AI verdict), MTTR (approve -> SOAR execute), FPR, FNR
```

---

## 13. Các lỗi thường gặp & fix

### EC2 restart → Bastion IP đổi → tunnel không kết nối

```bash
NEW_IP=$(aws ec2 describe-instances --region ap-southeast-1 \
  --instance-ids i-BASTION_ID \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
sed -i "s/IP_CU/$NEW_IP/g" ansible/inventory/hosts.yml
```

### API Gateway trả 401 "invalid token" dù token Keycloak đúng

Nguyên nhân: api-gateway chưa load JWKS (Keycloak chưa sẵn sàng khi pod start).

```bash
curl -s http://127.0.0.1:18080/health \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['jwks_keys_loaded'])"
# Phai = 1. Neu = 0:
kubectl --context ctx-aws -n financial rollout restart deployment/api-gateway
```

### Payment trả 403 "OPA deny"

Kiểm tra 3 điều kiện:
1. Token issuer phải là `http://keycloak.ztlab.local:8180/realms/ztlab` (có port `:8180`)
2. Token chưa hết hạn (`exp` > thời điểm hiện tại)
3. Roles phải có `financial-write`

```bash
echo "$TOKEN" | python3 -c "
import sys, base64, json
t = sys.stdin.read().strip().split('.')
p = t[1] + '=' * (-len(t[1]) % 4)
d = json.loads(base64.urlsafe_b64decode(p))
print('iss:', d.get('iss'))
print('roles:', d.get('realm_access', {}).get('roles', []))
"
```

### Payment trả 403 "fraud gate integrity validation failed"

Secret `CORE_BANKING_SHARED_SECRET` không được mount vào core-banking pod.

```bash
kubectl -n financial exec deploy/core-banking -c core-banking -- \
  python3 -c "import os; print('len:', len(os.getenv('CORE_BANKING_SHARED_SECRET','')))"
# Phai = 64. Neu = 0:
kubectl -n financial patch deployment core-banking --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/env/-","value":{"name":"CORE_BANKING_SHARED_SECRET","valueFrom":{"secretKeyRef":{"name":"core-banking-integrity-secret","key":"shared-secret"}}}}]'
kubectl -n financial rollout restart deployment/core-banking
```

### Cross-cloud (core-banking OpenStack) TLS error / connection reset

SPIRE agent OpenStack bị CrashLoopBackOff do join token đã dùng rồi.

```bash
# 1. Generate join token moi
NEW_TOKEN=$(kubectl --context ctx-aws -n spire exec deploy/spire-server -- \
  /opt/spire/bin/spire-server token generate -ttl 3600 \
  | grep "Token:" | awk '{print $2}')

# 2. Patch SPIRE agent DaemonSet tren OpenStack
kubectl --context ctx-openstack -n spire patch daemonset spire-agent \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args/3\",\"value\":\"$NEW_TOKEN\"}]"

# 3. Dang ky lai SPIRE entries cho OpenStack workloads
bash spire/scripts/register-os-workloads.sh
```

### Payment trả 503 "upstream payment service error"

Service đang bị isolate (selector bị thêm label phụ). Fix:

```bash
kubectl --context ctx-aws -n financial patch svc payment-service --type='json' \
  -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

### Port-forward chết sau rollout restart

```bash
pkill -f "kubectl.*port-forward" 2>/dev/null || true
sleep 2
bash scripts/open-admin-uis.sh
```

### AI Analyzer không detect / không có pending alerts

```bash
# Kiem tra health
curl -s http://127.0.0.1:8090/health | python3 -m json.tool

# Xem log
kubectl --context ctx-aws -n plg-stack logs deploy/ai-analyzer --tail=50

# Test phan tich truc tiep
curl -s -X POST http://127.0.0.1:8090/analyze \
  -H "Content-Type: application/json" \
  -d '{"log_line":"{\"response_code\":401,\"source_ip\":\"1.2.3.4\",\"count\":6}","labels":{"job":"envoy-access"}}' \
  | python3 -m json.tool
```

### SOAR Engine không thực thi playbook

```bash
kubectl --context ctx-aws -n plg-stack logs deploy/soar-engine --tail=50

# Kiem tra SOAR_DRY_RUN (phai = "false" trong production)
kubectl --context ctx-aws -n plg-stack get deployment soar-engine \
  -o jsonpath='{.spec.template.spec.containers[0].env}' \
  | python3 -m json.tool | grep -A2 "DRY_RUN"
```

---

## Quick Reference

```
Tunnel:         bash scripts/k8s-tunnel.sh up all
Port-forwards:  bash scripts/open-admin-uis.sh
Health:         bash scripts/health-check.sh
Demo:           bash scripts/run-demo.sh

Web Portal:     http://127.0.0.1:18081
API Gateway:    http://127.0.0.1:18080
Keycloak:       http://127.0.0.1:8180    admin / ztlab-admin-2026
Grafana:        http://127.0.0.1:3000    admin / ZTALab2026!
AI Analyzer:    http://127.0.0.1:8090
SOAR Engine:    http://127.0.0.1:8091
Loki:           http://127.0.0.1:13100
Prometheus:     http://127.0.0.1:9090
pgAdmin:        http://127.0.0.1:5050    admin@ztlab.com / ztlab2026
RedisInsight:   http://127.0.0.1:5540
```
