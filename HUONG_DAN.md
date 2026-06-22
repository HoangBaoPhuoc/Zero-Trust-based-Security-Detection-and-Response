# ZTLab — Hướng Dẫn Vận Hành & Demo

**Zero Trust Security Detection and Response for Microservices in Multi-Cloud**  
Sinh viên: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
Hệ thống: AWS K3s + OpenStack K3s · SPIRE mTLS · Envoy+OPA · Keycloak OIDC · PLG Stack · WireGuard

---

## Mục lục

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Bật EC2 instances](#2-bật-ec2-instances)
3. [Mở tunnel & port-forward](#3-mở-tunnel--port-forward)
4. [Health check toàn hệ thống](#4-health-check-toàn-hệ-thống)
5. [Tài khoản & credentials](#5-tài-khoản--credentials)
6. [Test end-to-end: Payment flow](#6-test-end-to-end-payment-flow)
7. [Web Portal (banking UI)](#7-web-portal-banking-ui)
8. [Grafana — Dashboards & Alert](#8-grafana--dashboards--alert)
9. [Phản ứng thủ công khi có alert](#9-phản-ứng-thủ-công-khi-có-alert)
10. [Chạy kịch bản tấn công](#10-chạy-kịch-bản-tấn-công)
11. [Các lỗi thường gặp & fix](#11-các-lỗi-thường-gặp--fix)

---

## 1. Tổng quan kiến trúc

```
                     ┌─────────────────── AWS K3s ───────────────────────────┐
User (browser)       │                                                         │
    │  HTTPS PKCE    │  web-portal ──OIDC──► Keycloak                         │
    ├──────────────► │  api-gateway ◄── Envoy sidecar ◄── OPA ext_authz       │
    │                │      │                                                  │
    │                │  payment-service ──SPIRE mTLS──► fraud-detection        │
    │                │      │                                                  │
    │                │      └──────────────────────────────────────────────────┼──► OpenStack K3s
    │                │                                                         │        │
    │                │  Promtail ──► Loki ──► Grafana (5 dashboards)           │   core-banking
    │                │                  │                                      │   account-service
    │                │          4 alert rules ──email──► admin (thủ công)      │   transaction-service
    │                │
    │                │  WireGuard VPN (10.200.0.0/30) ◄──────────────────────►│ OpenStack gateway
    │                └─────────────────────────────────────────────────────────┘
```

**Namespace layout AWS:**
- `identity` — Keycloak
- `financial` — api-gateway, web-portal, payment-service, fraud-detection, core-banking (AWS replica), account-service, transaction-service, notification-service, OPA, Redis, PostgreSQL
- `plg-stack` — Loki, Grafana, Promtail
- `monitoring` — Prometheus
- `spire` — SPIRE server + agents

**Cross-cloud:** payment-service → core-banking (OpenStack `10.10.1.12:30081`) qua SPIRE mTLS với join_token attestation.

---

## 2. Bật EC2 instances

Instances đang dừng (sau khi không dùng) cần bật lại. Sau khi bật, **IP public của bastion sẽ đổi** — phải cập nhật inventory.

```bash
# Bật tất cả instances (AWS CLI)
aws ec2 start-instances --region ap-southeast-1 --instance-ids \
  i-BASTION i-GATEWAY i-MASTER i-WORKER1 i-SECURITY i-OS_MASTER

# Đợi running (~2 phút)
aws ec2 wait instance-running --region ap-southeast-1 --instance-ids \
  i-BASTION i-GATEWAY i-MASTER i-WORKER1 i-SECURITY i-OS_MASTER

# Lấy IP mới của bastion
NEW_BASTION_IP=$(aws ec2 describe-instances --region ap-southeast-1 \
  --instance-ids i-BASTION \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "Bastion IP mới: $NEW_BASTION_IP"
```

Cập nhật `ansible/inventory/hosts.yml`: thay IP cũ của `aws_bastion.ansible_host` và tất cả `ProxyJump` bằng IP mới.

> **IP hiện tại (2026-06-21):** bastion = `52.221.255.36`  
> IP thay đổi mỗi lần restart. Luôn kiểm tra trước khi mở tunnel.

---

## 3. Mở tunnel & port-forward

### 3.1 K8s API tunnels

```bash
# Mở cả hai cluster (AWS + OpenStack)
bash scripts/k8s-tunnel.sh up all

# Kiểm tra
ss -lntp | grep -E ':6444|:6445'
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

Nếu kubeconfig chưa có context hoặc certs hết hạn:
```bash
SYNC_KUBECONFIG_ON_UP=true bash scripts/k8s-tunnel.sh up all
```

### 3.2 Port-forwards (chạy một lần, giữ nền)

```bash
# Identity
nohup kubectl --context ctx-aws -n identity \
  port-forward svc/keycloak 8180:8080 --address=127.0.0.1 >/tmp/pf-kc.log 2>&1 &

# Financial
nohup kubectl --context ctx-aws -n financial \
  port-forward svc/api-gateway 18080:8080 --address=127.0.0.1 >/tmp/pf-gw.log 2>&1 &
nohup kubectl --context ctx-aws -n financial \
  port-forward svc/web-portal 18081:8080 --address=127.0.0.1 >/tmp/pf-web.log 2>&1 &

# PLG Stack
nohup kubectl --context ctx-aws -n plg-stack \
  port-forward svc/grafana 3000:3000 --address=127.0.0.1 >/tmp/pf-grafana.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack \
  port-forward svc/loki 13100:3100 --address=127.0.0.1 >/tmp/pf-loki.log 2>&1 &
# Prometheus (namespace: monitoring)
nohup kubectl --context ctx-aws -n monitoring \
  port-forward svc/prometheus 9090:9090 --address=127.0.0.1 >/tmp/pf-prom.log 2>&1 &
```

Kiểm tra tất cả đang listen:
```bash
ss -lntp | grep "127.0.0.1" | grep -E ":(3000|8180|18080|18081|13100|9090)"
```

### 3.3 Tắt tunnel khi xong

```bash
bash scripts/k8s-tunnel.sh down all
pkill -f "kubectl.*port-forward"
```

---

## 4. Health check toàn hệ thống

```bash
bash scripts/health-check.sh
```

Điều kiện tối thiểu trước demo: `FAIL=0`.

### Kiểm tra nhanh từng thành phần

```bash
# Redis (cần auth từ Secret redis-auth)
kubectl --context ctx-aws -n financial exec deploy/redis -- \
  sh -c 'redis-cli -a $REDIS_PASSWORD --no-auth-warning ping'
# → PONG

# OPA (3 policies: zta_policy, fraud_gate, cross_cloud)
kubectl --context ctx-aws -n financial port-forward svc/opa-service 18083:8181 --address=127.0.0.1 &
curl -s http://127.0.0.1:18083/v1/policies | python3 -c \
  "import json,sys; p=json.load(sys.stdin)['result']; print(f'{len(p)} policies: {[x[\"id\"] for x in p]}')"

# Keycloak issuer
curl -s http://127.0.0.1:8180/realms/ztlab/.well-known/openid-configuration \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['issuer'])"
# → http://keycloak.ztlab.local:8180/realms/ztlab

# Loki
curl -s http://127.0.0.1:13100/ready

# Grafana
curl -s -u admin:ZTALab2026! http://127.0.0.1:3000/api/health | python3 -m json.tool

# Prometheus
curl -s http://127.0.0.1:9090/-/healthy

# API Gateway (jwks_keys_loaded phải = 1)
curl -s http://127.0.0.1:18080/health | python3 -m json.tool
```

### Kiểm tra pods

```bash
kubectl --context ctx-aws -n financial get pods
kubectl --context ctx-aws -n plg-stack get pods
kubectl --context ctx-aws -n identity get pods
kubectl --context ctx-aws -n spire get pods
kubectl --context ctx-openstack -n financial get pods
kubectl --context ctx-openstack -n spire get pods
```

Tất cả phải ở trạng thái `Running`. Pods 2/2 là có Envoy sidecar đi kèm.

---

## 5. Tài khoản & credentials

### Service URLs

| Service | URL | Credential |
|---------|-----|------------|
| **Web Portal** | http://127.0.0.1:18081 | Đăng nhập qua Keycloak OIDC |
| **Keycloak Admin** | http://127.0.0.1:8180 | `admin` / `ztlab-admin-2026` |
| **Grafana** | http://127.0.0.1:3000 | `admin` / `ZTALab2026!` |
| **API Gateway** | http://127.0.0.1:18080 | JWT Bearer token |
| **Loki** | http://127.0.0.1:13100 | — |
| **Prometheus** | http://127.0.0.1:9090 | — |

### Tài khoản người dùng (Keycloak realm: ztlab)

| Username | Password | Roles | Account số |
|----------|----------|-------|------------|
| `testuser01` | `Test1234!` | financial-read, financial-write | ACC-1001 |
| `testuser02` | `Test1234!` | financial-read, financial-write | ACC-2001 |
| `demoadmin` | `DemoAdmin2026!` | financial-read, financial-write, security-analyst, security-admin | ACC-3001 |
| `merchant01` | `Test1234!` | financial-read, financial-write | ACC-4001 |
| `analyst01` | `Analyst1234!` | security-analyst | ACC-5001 |

### Keycloak client secrets

`api-gateway` client secret: lấy động vì thay đổi sau mỗi lần Keycloak restart:

```bash
ADMIN_TOKEN=$(curl -s -X POST http://127.0.0.1:8180/realms/master/protocol/openid-connect/token \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=ztlab-admin-2026" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://127.0.0.1:8180/admin/realms/ztlab/clients?clientId=api-gateway" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['secret'])"
```

---

## 6. Test end-to-end: Payment flow

### Bước 1 — Lấy JWT token

Client `web-portal` là public PKCE client — không cần secret:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8180/realms/ztlab/protocol/openid-connect/token \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=web-portal" \
  --data-urlencode "username=testuser01" \
  --data-urlencode "password=Test1234!" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

echo "Token: ${TOKEN:0:40}..."
```

> Lưu ý: `api-gateway` client (confidential) cũng hoạt động nhưng cần fetch secret động sau mỗi lần Keycloak restart. Dùng `web-portal` đơn giản hơn cho demo.

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
    "from_balance": ...
  }
}
```

### Bước 3 — Kiểm tra accounts

```bash
# Xem balance tài khoản
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18080/accounts | python3 -m json.tool
```

### Luồng đầy đủ

```
User JWT → api-gateway
  ├─ Envoy inbound (port 15006) → OPA HTTP /v1/data/zta/authz/allow (port 8181)
  │       OPA zta_policy.rego: valid_jwt (iss=keycloak.ztlab.local:8180) + role_permits → allow
  ├─ api-gateway: verify JWT RS256 via Keycloak JWKS, rate limit, IP block (Redis)
  └─ forward → payment-service (Envoy SPIRE mTLS)
       │
       ├─ fraud-detection: Redis velocity check → fraud score
       │      score < 75 → gate=passed; HMAC-SHA256 sign (trace_id|from|to|amount|currency|score)
       │
       └─ core-banking (AWS K3s, path /transactions/execute via Envoy outbound)
              SPIRE mTLS: spiffe://ztlab.local/aws/payment-service → spiffe://ztlab.local/aws/core-banking
              OPA internal_service_request: payment-service POST /transactions/* → allow
              core-banking verify HMAC signature + fraud score < 74
              → account-service (debit/credit PostgreSQL, AWS K3s)
              → transaction-service (ledger PostgreSQL, AWS K3s)
              Return {transaction_id, status, from_balance, to_balance}
→ Response trở về user với transaction_id
```

---

## 7. Web Portal (banking UI)

Truy cập `http://127.0.0.1:18081` trong browser.

**Flow đăng nhập (PKCE):**
1. Click "Đăng nhập" → redirect tới Keycloak (`http://127.0.0.1:8180`)
2. Nhập username/password (vd: `testuser01` / `Test1234!`)
3. Keycloak redirect về `/auth/callback` với code
4. Web Portal exchange code → RS256 access token (stored server-side)
5. Dashboard hiển thị: bank card, balance, transaction history

**Các trang:**
- `/login` — Trang đăng nhập (OIDC redirect)
- `/dashboard` — Tổng quan tài khoản, link tới Grafana Alerting
- `/transfer` — Chuyển tiền
- `/profile` — Thông tin tài khoản
- `/security` — Quản lý incidents bảo mật: block IP, revoke sessions, scale down/restore service; chỉ role `security-analyst` hoặc `security-admin`
- `/admin` — Xem tất cả accounts + giao dịch với thông tin user (join từ Keycloak); chỉ role `security-admin`
- `/scenarios` — Chạy demo kịch bản tấn công; chỉ role `security-analyst` hoặc `security-admin`
- `/register` — Tự đăng ký tài khoản (rate-limit 5 lần/giờ/IP)

> Lưu ý: Web Portal dùng PKCE (public client `web-portal`), không dùng client secret.  
> Token được lưu phía server (session cookie), không lưu trong browser storage.

---

## 8. Grafana — Dashboards & Alert

URL: `http://127.0.0.1:3000` | `admin` / `ZTALab2026!`

### Dashboards (5 dashboards)

| Dashboard | UID | Nội dung |
|-----------|-----|----------|
| Security Overview | `ztlab-security-v2` | Zero Trust controls, multi-cloud status |
| Envoy Access Logs | `ztlab-envoy-access` | HTTP request logs từ Envoy sidecar |
| OPA Decision Log | `ztlab-opa-decisions` | Allow/deny decisions từ OPA |
| Full System Logs | `ztlab-system-logs` | Tất cả logs từ Loki |
| Financial Transactions | `ztlab-financial` | Giao dịch, fraud events |

### Alert rules (4 rules — LogQL)

| Alert | LogQL trigger | MITRE | Severity |
|-------|---------------|-------|----------|
| Brute Force Login | `{job="envoy-access"} \| json \| response_code=401` — >5 trong 1m | T1110.001 | high |
| Lateral Movement | `{job="opa-decisions", opa_result="false"}` | T1021.007 | critical |
| Fraud Gate Bypass | `{job="opa-decisions", opa_result="false", request_path="/transactions/execute"}` | T1078.004 | critical |
| Large Response / Exfiltration | `{job="envoy-access", cloud="openstack"} \| json \| bytes_sent > 1048576` | T1041 | high |

Tất cả 4 rules: evaluate every 1 minute, for=0s. Contact point: email → `voha2005@gmail.com`.

### Contact point & routing

- **Email:** `voha2005@gmail.com` (SMTP: `smtp.gmail.com:587`, MandatoryStartTLS)
- Tất cả alerts → route tới contact point `ztlab-security-admin` (email)
- Phản ứng: admin nhận email → vào Web Portal `/security` → block IP thủ công hoặc xử lý K8s

### Test email thủ công

```bash
# Gửi test notification tới tất cả receivers của ztlab-security-admin
curl -s -X POST -u admin:ZTALab2026! \
  -H "Content-Type: application/json" \
  -d '{"receivers": [{"name": "ztlab-security-admin", "grafana_managed_receiver_configs": [{"name": "ztlab-security-admin", "type": "email", "settings": {"addresses": "voha2005@gmail.com"}}]}]}' \
  http://127.0.0.1:3000/api/alertmanager/grafana/config/api/v1/receivers/test
```

---

## 9. Phản ứng thủ công khi có alert

Khi Grafana alert rule kích hoạt, email được gửi tới `voha2005@gmail.com`. Admin xử lý thủ công:

### Phản ứng sự cố qua Web Portal

1. Đăng nhập Web Portal với tài khoản role `security-admin` (vd: `demoadmin`) hoặc `security-analyst` (analyst01)
2. Vào trang **Security** (`/security`)
3. Xem danh sách incidents đang pending
4. Chọn action phù hợp với loại tấn công:
   - **Block IP** → ghi `ztlab:blocked_ip:{ip}` vào Redis TTL 24h, api-gateway chặn ngay
   - **Revoke All Sessions** → Keycloak logout toàn bộ user sessions đang hoạt động
   - **Scale Down Payment** → dừng payment-service tạm thời (replicas=0) để ngăn giao dịch mới
   - **Scale Down Banking** → dừng core-banking tạm thời (replicas=0)
   - **Restore** → khôi phục service về replicas=1 sau khi điều tra xong
   - **Acknowledge** → đánh dấu incident đã xử lý và đóng lại

### Block IP qua Redis CLI

```bash
# Block IP thủ công (TTL 24h) — Redis có auth
kubectl --context ctx-aws -n financial exec deploy/redis -- \
  sh -c 'redis-cli -a $REDIS_PASSWORD --no-auth-warning SET "ztlab:blocked_ip:10.0.0.99" \
  "{\"reason\":\"manual_block\",\"by\":\"admin\",\"ts\":\"2026-06-21T10:00:00Z\"}" EX 86400'

# Xem danh sách IPs bị block
kubectl --context ctx-aws -n financial exec deploy/redis -- \
  sh -c 'redis-cli -a $REDIS_PASSWORD --no-auth-warning KEYS "ztlab:blocked_ip:*"'

# Unblock IP
kubectl --context ctx-aws -n financial exec deploy/redis -- \
  sh -c 'redis-cli -a $REDIS_PASSWORD --no-auth-warning DEL "ztlab:blocked_ip:10.0.0.99"'
```

### Isolate service K8s (khi lateral movement / fraud bypass)

```bash
# Isolate payment-service (selector không khớp → service trở nên không có endpoint)
kubectl --context ctx-aws -n financial patch svc payment-service --type='json' \
  -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service","isolated":"true"}}]'

# Rollback
kubectl --context ctx-aws -n financial patch svc payment-service --type='json' \
  -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

### Kiểm tra alert rules trong Grafana

```bash
# Xem trạng thái alert rules qua API
curl -s -u admin:ZTALab2026! http://127.0.0.1:3000/api/v1/provisioning/alert-rules \
  | python3 -c "import json,sys; [print(r['title'], r.get('noDataState','')) for r in json.load(sys.stdin)]"
```

---

## 10. Chạy kịch bản tấn công

```bash
# Full demo: normal traffic + attacks
bash scripts/run-demo.sh

# Chỉ gửi traffic bình thường
bash scripts/run-demo.sh --traffic-only

# Chỉ chạy attack scenarios
bash scripts/run-demo.sh --attack-only

# Loop liên tục (Ctrl+C để dừng)
bash scripts/run-demo.sh --continuous
```

### Kịch bản riêng lẻ

| Script | Mô tả | MITRE |
|--------|-------|-------|
| `tests/scenario_01_brute_force.sh` | 10+ lần login thất bại | T1110.001 |
| `tests/scenario_02_jwt_forgery.py` | JWT giả mạo với HS256 | T1078.004 |
| `tests/scenario_03_lateral_movement.sh` | SVID không hợp lệ giữa services | T1021.007 |
| `tests/scenario_04_fraud_gate_bypass.py` | Bypass fraud gate header | T1078.004 |
| `tests/scenario_05_high_velocity.py` | 100 giao dịch/phút | T1499 |
| `tests/scenario_06_exfiltration.py` | Response body > 1MB | T1041 |
| `tests/scenario_11_cryptomining.sh` | CPU spike bất thường | T1496 |

### Inject logs test vào Loki (không cần chạy attack thật)

```bash
LOKI_URL="http://127.0.0.1:13100"
NOW=$(python3 -c "import time; print(int(time.time()*1e9))")

# Ví dụ: brute force attack log
curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
  -H "Content-Type: application/json" \
  -d "{\"streams\":[{\"stream\":{\"job\":\"envoy-access\",\"cloud\":\"aws\",\"namespace\":\"financial\"},\"values\":[[\"$NOW\",\"{\\\"response_code\\\":401,\\\"source_ip\\\":\\\"10.0.0.99\\\",\\\"path\\\":\\\"/payments\\\",\\\"scenario\\\":\\\"brute-force\\\"}\"]]}]}"
```

---

## 11. Các lỗi thường gặp & fix

### EC2 restart → Bastion IP đổi → tunnel không kết nối được

```bash
# Lấy IP mới
NEW_IP=$(aws ec2 describe-instances --region ap-southeast-1 \
  --instance-ids i-BASTION_ID \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

# Sửa inventory (thay IP cũ bằng IP mới)
sed -i "s/IP_CU/$NEW_IP/g" ansible/inventory/hosts.yml
```

### API Gateway trả 401 "invalid token" dù token Keycloak đúng

Nguyên nhân: api-gateway chưa load JWKS (Keycloak chưa sẵn sàng khi pod start).

```bash
# Kiểm tra
curl -s http://127.0.0.1:18080/health | python3 -c "import json,sys; print(json.load(sys.stdin)['jwks_keys_loaded'])"
# → phải = 1

# Nếu = 0: restart pod
kubectl --context ctx-aws -n financial rollout restart deployment/api-gateway
```

### Keycloak client secret thay đổi sau restart → 401 Unauthorized khi lấy token

```bash
# Lấy secret mới
ADMIN_TOKEN=$(curl -s -X POST http://127.0.0.1:8180/realms/master/protocol/openid-connect/token \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=ztlab-admin-2026" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://127.0.0.1:8180/admin/realms/ztlab/clients?clientId=api-gateway" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['secret'])"
```

### Payment trả 403 Forbidden

OPA từ chối. Kiểm tra:
1. Token issuer phải là `http://keycloak.ztlab.local:8180/realms/ztlab` (http, bao gồm port 8180 — OPA kiểm tra chính xác chuỗi này)
2. Token chưa hết hạn (`exp` > now)
3. Roles phải có `financial-write` (testuser01 có đủ)

```bash
# Debug JWT payload
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

### Payment trả 503 "upstream payment service error"

Service bị isolate thủ công (selector bị thêm label isolation). Fix:

```bash
kubectl --context ctx-aws -n financial patch svc payment-service --type='json' \
  -p='[{"op": "replace", "path": "/spec/selector", "value": {"app": "payment-service"}}]'
```

### Cross-cloud (core-banking OpenStack) connection reset / TLS error

SPIRE agent OpenStack bị CrashLoopBackOff do join token đã dùng rồi. Fix:

```bash
# 1. Generate token mới
NEW_TOKEN=$(kubectl --context ctx-aws -n spire exec deploy/spire-server -- \
  /opt/spire/bin/spire-server token generate -ttl 3600 \
  | grep "Token:" | awk '{print $2}')

# 2. Patch SPIRE agent DaemonSet trên OpenStack
kubectl --context ctx-openstack -n spire patch daemonset spire-agent \
  --type='json' \
  -p="[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args/3\",\"value\":\"$NEW_TOKEN\"}]"

# 3. Đăng ký SPIRE entries cho OpenStack workloads
PARENT_ID="spiffe://ztlab.local/spire/agent/join_token/$NEW_TOKEN"

for svc in core-banking account-service transaction-service; do
  kubectl --context ctx-aws -n spire exec deploy/spire-server -- \
    /opt/spire/bin/spire-server entry create \
    -parentID "$PARENT_ID" \
    -spiffeID "spiffe://ztlab.local/openstack/$svc" \
    -selector "unix:uid:0"
done
```

### Service bị isolate thủ công → rollback

```bash
# Restore payment-service selector
kubectl --context ctx-aws -n financial patch svc payment-service --type='json' \
  -p='[{"op": "replace", "path": "/spec/selector", "value": {"app": "payment-service"}}]'

# Restore bất kỳ service nào khác
kubectl --context ctx-aws -n financial patch svc SERVICE_NAME --type='json' \
  -p='[{"op": "replace", "path": "/spec/selector", "value": {"app": "SERVICE_NAME"}}]'
```

### Port-forward chết (sau rollout restart)

```bash
# Restart tất cả
pkill -f "kubectl.*port-forward" 2>/dev/null || true
sleep 2
# Chạy lại các lệnh port-forward ở mục 3.2
# Hoặc dùng script:
bash scripts/open-admin-uis.sh
```

### Payment trả 403 "fraud gate integrity validation failed"

Nguyên nhân phổ biến: `CORE_BANKING_SHARED_SECRET` không có trong core-banking pod.

```bash
# Kiểm tra
kubectl -n financial exec deploy/core-banking -c core-banking -- \
  python3 -c "import os; print('Secret len:', len(os.getenv('CORE_BANKING_SHARED_SECRET','')))"
# Phải trả về: Secret len: 64
```

Nếu len=0: secret chưa được mount. Fix bằng patch deployment:
```bash
kubectl -n financial patch deployment core-banking --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/env/-","value":{"name":"CORE_BANKING_SHARED_SECRET","valueFrom":{"secretKeyRef":{"name":"core-banking-integrity-secret","key":"shared-secret"}}}}]'
kubectl -n financial rollout restart deployment/core-banking
```

### GET /accounts trả 403 dù có token hợp lệ (OPA deny)

Nguyên nhân: OPA policy dùng issuer sai (không có port `:8180`).

```bash
# Kiểm tra issuer trong token
echo $TOKEN | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip().split('.')[1]
p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p))['iss'])
"
# Phải ra: http://keycloak.ztlab.local:8180/realms/ztlab

# Kiểm tra OPA policy
kubectl -n financial exec deploy/opa-server -c opa -o yaml 2>/dev/null -- ls / || \
kubectl get configmap -n financial opa-policies -o jsonpath='{.data.zta_policy\.rego}' | \
  grep "keycloak.ztlab.local"
# Phải có ":8180" trong dòng jwt_payload.iss
```

---

## Quick Reference

```
Tunnel:        bash scripts/k8s-tunnel.sh up all
Health:        bash scripts/health-check.sh
Demo:          bash scripts/run-demo.sh
Grafana:       http://127.0.0.1:3000  (admin/ZTALab2026!)
Keycloak:      http://127.0.0.1:8180  (admin/ztlab-admin-2026)
Web Portal:    http://127.0.0.1:18081
API Gateway:   http://127.0.0.1:18080
Loki:          http://127.0.0.1:13100
```
