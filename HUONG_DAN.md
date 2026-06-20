# ZTLab — Hướng Dẫn Vận Hành & Demo

**Zero Trust Security Detection and Response for Microservices in Multi-Cloud**  
Sinh viên: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
Hệ thống: AWS K3s + OpenStack K3s · SPIRE mTLS · Envoy+OPA · Keycloak OIDC · PLG Stack · SOAR

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
9. [SOAR — Incident workflow](#9-soar--incident-workflow)
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
    │                │  Promtail ──► Loki ──► Grafana                          │   core-banking
    │                │                  │                                      │   account-service
    │                │                  └──► Alert ──► SOAR engine ──email──► │   transaction-service
    │                │                                     │
    │                │  security-scorer (Redis anomaly)     └──► K8s playbooks
    │                │  ai-analyzer (heuristic/OpenAI)
    │                └─────────────────────────────────────────────────────────┘
```

**Namespace layout AWS:**
- `identity` — Keycloak
- `financial` — api-gateway, web-portal, payment-service, fraud-detection, core-banking (AWS replica), account-service, transaction-service, notification-service, OPA, Redis, PostgreSQL
- `plg-stack` — Loki, Grafana, Promtail, SOAR engine, AI Analyzer, Security Scorer
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
nohup kubectl --context ctx-aws -n plg-stack \
  port-forward svc/soar-engine 8091:8080 --address=127.0.0.1 >/tmp/pf-soar.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack \
  port-forward svc/ai-analyzer 8090:8080 --address=127.0.0.1 >/tmp/pf-ai.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack \
  port-forward svc/security-scorer 18092:8080 --address=127.0.0.1 >/tmp/pf-scorer.log 2>&1 &

# Prometheus (namespace: monitoring)
nohup kubectl --context ctx-aws -n monitoring \
  port-forward svc/prometheus 9090:9090 --address=127.0.0.1 >/tmp/pf-prom.log 2>&1 &
```

Kiểm tra tất cả đang listen:
```bash
ss -lntp | grep "127.0.0.1" | grep -E ":(3000|8180|18080|18081|13100|8091|8090|18092|9090)"
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
# Redis
kubectl --context ctx-aws -n financial exec deploy/redis -- redis-cli ping
# → PONG

# OPA (3 policies: zta_policy, fraud_gate, cross_cloud)
kubectl --context ctx-aws -n financial port-forward svc/opa-service 18083:8181 --address=127.0.0.1 &
curl -s http://127.0.0.1:18083/v1/policies | python3 -c \
  "import json,sys; p=json.load(sys.stdin)['result']; print(f'{len(p)} policies: {[x[\"id\"] for x in p]}')"

# Keycloak issuer
curl -s http://127.0.0.1:8180/realms/ztlab/.well-known/openid-configuration \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['issuer'])"
# → http://keycloak.ztlab.local/realms/ztlab

# Loki
curl -s http://127.0.0.1:13100/ready

# Grafana
curl -s -u admin:ZTALab2026! http://127.0.0.1:3000/api/health | python3 -m json.tool

# Prometheus
curl -s http://127.0.0.1:9090/-/healthy

# SOAR
curl -s http://127.0.0.1:8091/health | python3 -m json.tool

# AI Analyzer
curl -s http://127.0.0.1:8090/health | python3 -m json.tool

# Security Scorer
curl -s http://127.0.0.1:18092/health | python3 -m json.tool

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
| **SOAR Engine** | http://127.0.0.1:8091 | — |
| **AI Analyzer** | http://127.0.0.1:8090 | — |
| **Security Scorer** | http://127.0.0.1:18092 | — |
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

```bash
# Lấy client secret
ADMIN_TOKEN=$(curl -s -X POST http://127.0.0.1:8180/realms/master/protocol/openid-connect/token \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=ztlab-admin-2026" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

SECRET=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://127.0.0.1:8180/admin/realms/ztlab/clients?clientId=api-gateway" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['secret'])")

# Lấy token người dùng (ROPC)
TOKEN=$(curl -s -X POST http://127.0.0.1:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=api-gateway&client_secret=$SECRET&username=testuser01&password=Test1234!" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

echo "Token: ${TOKEN:0:30}..."
```

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
User JWT → Envoy (port 15006) → OPA ext_authz (port 9191)
       OPA: external_api_request? method=POST path=/payments valid_jwt role_permits_action not valid_svid → allow
→ api-gateway (verify JWT RS256 via Keycloak JWKS)
→ payment-service (Envoy SPIRE mTLS) → fraud-detection (Redis velocity check)
       fraud score < 75 → X-Fraud-Gate=passed header
→ core-banking AWS replica gọi core-banking OpenStack (10.10.1.12:30081)
       SPIRE mTLS: spiffe://ztlab.local/aws/core-banking → spiffe://ztlab.local/openstack/core-banking
→ account-service (OpenStack) → transaction-service (OpenStack) → PostgreSQL
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
- `/dashboard` — Tổng quan tài khoản, anomaly score widget
- `/transfer` — Chuyển tiền
- `/profile` — Thông tin tài khoản

> Lưu ý: Web Portal dùng PKCE (public client `web-portal`), không dùng client secret.  
> Không có `/logs` hay `/alerts` trong nav — chỉ roles security-analyst+ mới thấy `/scenarios`.

---

## 8. Grafana — Dashboards & Alert

URL: `http://127.0.0.1:3000` | `admin` / `ZTALab2026!`

### Dashboards

| Dashboard | UID | Nội dung |
|-----------|-----|----------|
| ZTLab AI SIEM+SOAR | `ztlab-ai-siem-soar` | Tổng hợp: anomaly score, fraud, SOAR incidents |
| ZTLab SOAR | `ztlab-soar` | Incident timeline, SOAR actions |
| Security Overview | `ztlab-security-v2` | Zero Trust controls, multi-cloud status |
| Envoy Access Logs | — | HTTP request logs từ Envoy sidecar |
| OPA Decision Log | — | Allow/deny decisions từ OPA |
| Full System Logs | — | Tất cả logs từ Loki |

### Alert rules (10 rules)

| Alert | Trigger | Severity |
|-------|---------|----------|
| Brute Force Login | 5+ lỗi 401 trong 1 phút | high |
| Lateral Movement SVID | OPA từ chối cross-service | critical |
| Fraud Gate Bypass | bypass `/transactions/execute` | critical |
| Large Response Exfiltration | response > 1MB | high |
| AI Anomaly Score ≥ 70 | Prometheus metric | high |
| AI Malicious Activity | log `verdict:malicious` trong Loki | high |
| SOAR Action Recorded | log `soar_action` trong Loki | high |
| Security Alert Requires Admin Approval | pending approval | high |

### Contact point & routing

- **Email:** `voha2005@gmail.com` (SMTP: `smtp.gmail.com:587`, MandatoryStartTLS)
- **Webhook:** SOAR engine nhận alert qua `/grafana-webhook` → tạo incident → gửi email thêm
- Tất cả alerts với label `category: security` → route tới `ztlab-security-admin`

### Test email thủ công

```bash
# Gửi test notification tới tất cả receivers của ztlab-security-admin
curl -s -X POST -u admin:ZTALab2026! \
  -H "Content-Type: application/json" \
  -d '{"receivers": [{"name": "ztlab-security-admin", "grafana_managed_receiver_configs": [{"name": "ztlab-security-admin", "type": "email", "settings": {"addresses": "voha2005@gmail.com"}}]}]}' \
  http://127.0.0.1:3000/api/alertmanager/grafana/config/api/v1/receivers/test
```

---

## 9. SOAR — Incident workflow

URL: `http://127.0.0.1:8091`

### Endpoints

| Endpoint | Mô tả |
|----------|-------|
| `GET /health` | Health check |
| `GET /incidents` | Tất cả incidents (40+ entries) |
| `GET /pending` | Alerts chờ admin duyệt |
| `POST /incidents/{id}/approve` | Duyệt → thực thi playbook |
| `POST /incidents/{id}/dismiss` | Bỏ qua |
| `GET /analyze` | Phân tích Loki logs mới nhất |

### Xem incidents

```bash
# Tất cả incidents
curl -s http://127.0.0.1:8091/incidents | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'Total: {len(d)}')
for i in d[-5:]:
    print(f'  [{i[\"status\"]}] {i[\"alert_name\"]} (sev={i[\"severity\"]})')
"

# Pending approval
curl -s http://127.0.0.1:8091/pending | python3 -m json.tool
```

### Playbooks SOAR có thể chạy

| Playbook | Kích hoạt bởi |
|----------|---------------|
| `isolate_service` | Lateral movement / fraud bypass |
| `block_ip` | Brute force (TTL 86400s, lưu Redis) |
| `revoke_user_sessions` | Credential stuffing |
| `rate_limit_user` | High velocity transactions |
| `notify_admin` | Tất cả high/critical alerts |

> **Cảnh báo:** Approve incident sẽ thực thi playbook thật trên K8s (vd: thay selector của service).  
> Sau khi demo, rollback bằng: `kubectl patch svc payment-service -n financial --type='json' -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'`

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
1. Token issuer phải là `http://keycloak.ztlab.local/realms/ztlab` (http, không phải https)
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

SOAR đã isolate payment-service (selector bị thêm label isolation). Fix:

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

### SOAR isolate service → rollback

```bash
# Restore payment-service selector
kubectl --context ctx-aws -n financial patch svc payment-service --type='json' \
  -p='[{"op": "replace", "path": "/spec/selector", "value": {"app": "payment-service"}}]'

# Restore bất kỳ service nào khác
kubectl --context ctx-aws -n financial patch svc SERVICE_NAME --type='json' \
  -p='[{"op": "replace", "path": "/spec/selector", "value": {"app": "SERVICE_NAME"}}]'
```

### Port-forward chết

```bash
# Restart tất cả
pkill -f "kubectl.*port-forward" 2>/dev/null || true
sleep 2
# Chạy lại các lệnh port-forward ở mục 3.2
```

---

## Quick Reference

```
Tunnel:        bash scripts/k8s-tunnel.sh up all
Health:        bash scripts/health-check.sh
Demo:          bash scripts/run-demo.sh
SOAR UI:       http://127.0.0.1:8091/incidents
Grafana:       http://127.0.0.1:3000  (admin/ZTALab2026!)
Keycloak:      http://127.0.0.1:8180  (admin/ztlab-admin-2026)
Web Portal:    http://127.0.0.1:18081
API Gateway:   http://127.0.0.1:18080
```
