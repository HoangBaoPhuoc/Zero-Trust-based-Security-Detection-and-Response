# ZTLab — Hướng Dẫn Vận Hành & Demo

**Zero Trust Security Detection and Response for Microservices in Multi-Cloud**  
Sinh viên: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
GVHD: ThS. Đỗ Thị Phương Uyên · Môn: NT114.Q21.ANTT

---

## Mục lục

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Hạ tầng & địa chỉ IP](#2-hạ-tầng--địa-chỉ-ip)
3. [Khởi động hệ thống (mỗi lần bật máy)](#3-khởi-động-hệ-thống-mỗi-lần-bật-máy)
4. [Deploy lần đầu](#4-deploy-lần-đầu)
5. [Tài khoản & credentials](#5-tài-khoản--credentials)
6. [Truy cập các UI](#6-truy-cập-các-ui)
7. [Health check nhanh](#7-health-check-nhanh)
8. [Kịch bản demo & tấn công](#8-kịch-bản-demo--tấn-công)
9. [SOAR Engine](#9-soar-engine)
10. [Grafana — Dashboards & Alerts](#10-grafana--dashboards--alerts)
11. [OPA — Chính sách bảo mật](#11-opa--chính-sách-bảo-mật)
12. [Xử lý sự cố thường gặp](#12-xử-lý-sự-cố-thường-gặp)

---

## 1. Tổng quan kiến trúc

```
                        Internet / Browser
                               │
                               ▼
┌──────────────────── AWS K3s (ctx-aws) ─────────────────────────────────┐
│                                                                         │
│  namespace: identity                                                    │
│    Keycloak (realm=ztlab, port 8080)                                   │
│    SPIRE Server (trust domain=ztlab.local, SVID TTL=1h)               │
│                                                                         │
│  namespace: financial                                                   │
│    api-gateway       spiffe://ztlab.local/aws/api-gateway              │
│    payment-service   spiffe://ztlab.local/aws/payment-service          │
│    fraud-detection   spiffe://ztlab.local/aws/fraud-detection          │
│    notification-svc  spiffe://ztlab.local/aws/notification-service     │
│    web-portal, OPA, Redis, PostgreSQL                                  │
│                                                                         │
│  namespace: plg-stack                                                   │
│    Promtail → Loki (90 ngày) → Grafana                                 │
│    SOAR Engine  (Grafana webhook → K8s playbook)                       │
│    Security Scorer                                                      │
│                                                                         │
│  namespace: monitoring                                                  │
│    Prometheus (10 targets)                                              │
│                                                                         │
└────────────────────────┬───────────────────────────────────────────────┘
                         │  WireGuard (10.200.0.1 ↔ 10.200.0.2)
                         │  Envoy mTLS SPIFFE SVID
                         ▼
┌───────────── OpenStack K3s (ctx-openstack) ────────────────────────────┐
│  namespace: financial                                                   │
│    core-banking     spiffe://ztlab.local/openstack/core-banking        │
│      NodePort 30080 (Envoy mTLS) · 30084 (HTTP /metrics)              │
│    account-service  spiffe://ztlab.local/openstack/account-service     │
│      NodePort 30082 (Envoy mTLS) · 30086 (HTTP /metrics)              │
│    transaction-svc  spiffe://ztlab.local/openstack/transaction-service │
│      NodePort 30083 (Envoy mTLS) · 30087 (HTTP /metrics)              │
│    OPA, Redis, PostgreSQL, pgAdmin, RedisInsight                       │
│                                                                         │
│  namespace: plg-stack                                                   │
│    Promtail → socat proxy (deployer:13099) → Loki (AWS)                │
└────────────────────────────────────────────────────────────────────────┘
```

### Luồng payment chính (Gap 2 — cross-cloud)

```
Browser → web-portal (JWT PKCE)
  → api-gateway (verify JWT + OPA authz)
  → payment-service (HMAC sign + fraud score)
  → fraud-detection (Redis velocity, score=5 → gate=passed)
  → core-banking [OpenStack] (mTLS SPIFFE, OPA: x-fraud-gate + x-fraud-score)
  → account-service [OpenStack] (debit/credit)
  → transaction-service [OpenStack] (ledger)
```

### Luồng phát hiện & phản ứng tự động

```
Grafana alert rule fire (Loki count_over_time query)
  → POST soar-engine/grafana-webhook
  → SOAR parse attack_type từ label Grafana
  → severity >= medium AND auto_execute=true
  → chạy playbook ngay: isolate_workload / block_source_ip / revoke_user_sessions / restrict_egress
  → ghi case vào Redis + file
```

---

## 2. Hạ tầng & địa chỉ IP

| Node | IP Private | IP Public | Vai trò |
|------|-----------|-----------|---------|
| aws_bastion | — | 52.221.255.36 | SSH jump host |
| aws_gateway | 10.10.0.x / WG 10.200.0.1 | 13.213.245.227 | NAT + WireGuard |
| aws_k3s_master | 10.10.1.10 | — | K8s control plane AWS |
| aws_k3s_worker_1 | 10.10.1.11 | — | K8s worker AWS |
| os_gateway | — / WG 10.200.0.2 | 10.10.10.188 | WireGuard client OpenStack |
| os_k3s_master | 192.168.101.11 | — | K8s master OpenStack |
| deployer (máy này) | 10.10.10.1 (br-exnat) | — | SSH bastion + Loki proxy |

**K8s contexts:**
- `ctx-aws` → API server `127.0.0.1:6444` (SSH tunnel qua bastion)
- `ctx-openstack` → API server `127.0.0.1:6445` (SSH tunnel qua os_gateway)

**WireGuard tunnel:**
- aws_gateway `10.200.0.1` ↔ os_gateway `10.200.0.2`
- MASQUERADE trên AWS K3s nodes: `10.42.0.0/16 → 192.168.101.0/24`

**Cross-cloud Envoy upstreams (đang active):**
- payment-service → `192.168.101.11:30080` (core-banking mTLS)
- api-gateway → `192.168.101.11:30082` (account-service mTLS)
- api-gateway → `192.168.101.11:30083` (transaction-service mTLS)

**Loki log pipeline OpenStack:**
- OpenStack promtail → `10.10.10.1:13099` (socat trên deployer)
- socat → `localhost:13100` (kubectl port-forward → Loki AWS)

---

## 3. Khởi động hệ thống (mỗi lần bật máy)

> Làm đúng thứ tự sau mỗi khi reboot máy deployer hoặc mở session mới.

### Bước 1 — Bật OpenStack VMs

```bash
source /etc/kolla/admin-openrc.sh
openstack server list
# Nếu SHUTOFF → bật lại
openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2
```

Đợi ~30 giây để VMs boot xong.

### Bước 2 — Mở K8s API tunnels

```bash
bash scripts/k8s-tunnel.sh up all
```

Kiểm tra:
```bash
kubectl --context ctx-aws get nodes
# ip-10-10-1-10 Ready, ip-10-10-1-11 Ready

kubectl --context ctx-openstack get nodes
# os-k3s-master Ready, os-k3s-worker-1 Ready, os-k3s-worker-2 Ready
```

### Bước 3 — Kiểm tra pods

```bash
# AWS
kubectl --context ctx-aws get pods -A | grep -v "Running\|Completed"
# OpenStack
kubectl --context ctx-openstack get pods -A | grep -v "Running\|Completed"
```

Nếu pod nào không Running:
```bash
kubectl --context ctx-aws rollout restart deployment/<tên> -n <namespace>
kubectl --context ctx-openstack rollout restart deployment/<tên> -n financial
```

### Bước 4 — Mở port-forwards & Loki proxy

```bash
bash scripts/open-admin-uis.sh
```

Script khởi động toàn bộ dưới dạng daemon tự-restart (không cần giữ terminal). Bao gồm:
- 10 port-forwards cho các UI
- socat proxy `10.10.10.1:13099 → localhost:13100` (Loki pipeline OpenStack)

Kiểm tra: `bash scripts/open-admin-uis.sh status`  
Dừng: `bash scripts/open-admin-uis.sh stop`

### Bước 5 — Kiểm tra SOAR không isolate service từ demo trước

```bash
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.spec.selector}'
# Phải là: {"app":"payment-service"}
# Nếu có "soar.ztlab.io/isolated":"true" → restore:
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

### Checklist nhanh

```bash
# 1. OpenStack VMs
source /etc/kolla/admin-openrc.sh && openstack server list
# Nếu SHUTOFF: openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2

# 2. Tunnels
bash scripts/k8s-tunnel.sh up all

# 3. Nodes
kubectl --context ctx-aws get nodes && kubectl --context ctx-openstack get nodes

# 4. Pods (chỉ show cái không Running)
kubectl --context ctx-aws get pods -A | grep -v "Running\|Completed"
kubectl --context ctx-openstack get pods -A | grep -v "Running\|Completed"

# 5. Port-forwards
bash scripts/open-admin-uis.sh

# 6. Kiểm tra payment-service không bị isolate
kubectl --context ctx-aws get svc payment-service -n financial -o jsonpath='{.spec.selector}'
```

> **Sau reboot AWS VM:** pods tự restart theo K3s systemd, chỉ cần bước 2 + 4.  
> **Sau reboot OpenStack VM:** VMs tắt — phải bật lại (bước 1) trước khi mở tunnel.

---

## 4. Deploy lần đầu

Chỉ làm một lần khi cluster chưa có gì. K8s tunnel phải đang chạy.

### Bước 1 — Build & sync images

```bash
IMAGE_TAG=1.0.0 bash scripts/sync-financial-images.sh
```

Build 10 service images và copy vào containerd trên tất cả K3s nodes.

### Bước 2 — Deploy toàn bộ

```bash
export KEYCLOAK_ADMIN_PASSWORD=ztlab-admin-2026
bash scripts/deploy-all.sh
```

Deploy theo thứ tự: Namespaces → Security stack (SPIRE/SPIFFE, OPA, Keycloak realm `ztlab`) → Financial infra → Financial workloads → PLG + SOAR → NetworkPolicies → Status check.

### Bước 3 — Seed database

```bash
python3 tests/seed_db.py
```

Reset số dư: ACC-1001 = 1,000,000,000 VND · ACC-2001 = 250,000,000 VND.

### Bước 4 — Mở port-forwards

```bash
bash scripts/open-admin-uis.sh
```

---

## 5. Tài khoản & credentials

### Keycloak (realm: ztlab)

| Username | Password | Role | Tài khoản ngân hàng |
|----------|----------|------|---------------------|
| admin | ztlab-admin-2026 | Keycloak superadmin | — |
| testuser01 | Test1234! | financial-read, financial-write | ACC-1001 |
| testuser02 | Test1234! | financial-read, financial-write | ACC-2001 |
| merchant01 | Test1234! | financial-read | ACC-4001 |
| analyst01 | Test1234! | security-analyst | ACC-5001 |

> **merchant01**: chỉ `financial-read` → POST /payments → HTTP 403 (demo RBAC).  
> **analyst01**: xem `/security`, `/monitor` nhưng không chuyển tiền được.

### Roles OPA

| Role | Phương thức được phép |
|------|----------------------|
| `financial-read` | GET, OPTIONS |
| `financial-write` | GET, OPTIONS, POST, PUT |
| `security-analyst` | GET, OPTIONS |
| `security-admin` | GET, OPTIONS, POST, PUT, DELETE |

### Grafana

- Login: `admin` / `ZTALab2026!`

### Database

| Thành phần | Host nội bộ | DB | User | Password |
|-----------|------------|-----|------|---------|
| PostgreSQL accounts (AWS) | postgres-accounts.financial:5432 | accounts_db | accounts_user | accounts_pass |
| PostgreSQL transactions (AWS) | postgres-txn.financial:5432 | transactions_db | txn_user | txn_pass |
| Redis (AWS) | redis.financial:6379 | DB0/DB1 | — | ZTALab-Redis-2026! |
| pgAdmin | http://localhost:5050 | — | admin@ztlab.com | ztlab2026 |

**Redis DB mapping:**
- **DB0** — fraud velocity keys + IP blocklist + SOAR IP blocking
- **DB1** — anomaly scorer 15 phút window (security-scorer)

### SPIRE

- Trust domain: `ztlab.local` · SVID TTL: 1h · CA TTL: 168h
- AWS: `spiffe://ztlab.local/aws/{api-gateway,payment-service,fraud-detection,notification-service}`
- OpenStack: `spiffe://ztlab.local/openstack/{core-banking,account-service,transaction-service}`

---

## 6. Truy cập các UI

```bash
bash scripts/open-admin-uis.sh   # khởi động tất cả
```

| Service | URL | Thông tin đăng nhập |
|---------|-----|---------------------|
| Web Portal | http://localhost:18081 | testuser01 / Test1234! |
| API Gateway | http://localhost:18080 | — (cần JWT) |
| Keycloak | http://localhost:8180 | admin / ztlab-admin-2026 |
| Grafana | http://localhost:3000 | admin / ZTALab2026! |
| Prometheus | http://localhost:9090 | — |
| SOAR Engine | http://localhost:8091 | — |
| Security Scorer | http://localhost:18092 | — |
| Loki | http://localhost:13100 | — |
| pgAdmin | http://localhost:5050 | admin@ztlab.com / ztlab2026 |
| RedisInsight | http://localhost:5540 | — |

### Web Portal — các trang chính

| Đường dẫn | Mô tả | Role |
|-----------|-------|------|
| `/login` | Đăng nhập OIDC/PKCE qua Keycloak | — |
| `/dashboard` | Số dư, lịch sử giao dịch | Đăng nhập |
| `/transfer` | Chuyển tiền | financial-write |
| `/scenarios` | Trigger kịch bản attack từ UI | Đăng nhập |
| `/security` | SOAR cases, blocked IPs | security-analyst |
| `/monitor` | System health | security-analyst |
| `/admin` | Quản lý users & accounts | security-admin |

---

## 7. Health check nhanh

```bash
# API Gateway
curl http://localhost:18080/health
# → {"status":"ok","jwks_keys_loaded":2,...}

# SOAR Engine
curl http://localhost:8091/health
# → {"status":"ok","auto_execute":true,"dry_run":false,"min_severity":"medium","case_count":N}

# Loki
curl http://localhost:13100/ready
# → ready

# Grafana
curl http://localhost:3000/api/health
# → {"database":"ok"}

# Prometheus targets
curl -s http://localhost:9090/api/v1/targets | python3 -c "
import sys,json; d=json.load(sys.stdin)
t=d['data']['activeTargets']
up=sum(1 for x in t if x['health']=='up')
print(f'UP: {up}/{len(t)}')
"
# → UP: 10/10

# OPA policy (test fraud gate)
kubectl --context ctx-aws exec -n financial deploy/opa-server -- \
  curl -s -X POST localhost:8181/v1/data/zta/authz/allow \
  -d '{"input":{"attributes":{"request":{"http":{"method":"POST","path":"/transactions/execute","headers":{}}},"source":{"principal":"spiffe://ztlab.local/aws/payment-service"}}}}' \
  -H "Content-Type: application/json"
# → {"result":false}  ← ĐÚNG: không có fraud gate thì bị deny

# E2E payment test
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234!&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1}'
# → {"status":"completed","fraud":{"score":5,"gate":"passed"},...}
```

---

## 8. Kịch bản demo & tấn công

### Chuẩn bị trước demo

```bash
# Reset số dư
python3 tests/seed_db.py

# Kiểm tra payment-service không bị isolate
kubectl --context ctx-aws get svc payment-service -n financial -o jsonpath='{.spec.selector}'
# Phải là: {"app":"payment-service"}
```

Mở 4 tab trình duyệt:

| Tab | URL |
|-----|-----|
| 1 | http://localhost:18081 — Web Portal (testuser01) |
| 2 | http://localhost:3000/d/siem-soar-ztlab — Grafana SIEM SOAR |
| 3 | http://localhost:3000/alerting/list — Grafana Alerts |
| 4 | http://localhost:18081/security — SOAR cases (analyst01) |

---

### Kịch bản 1 — Brute Force (T1110.001)

**Mô tả:** Nhiều lần đăng nhập sai → OPA deny rate tăng → Grafana alert → SOAR revoke sessions.

```bash
bash tests/scenario_01_brute_force.sh
# Hoặc từ Web Portal: /scenarios → "Brute Force"
```

**Chuỗi sự kiện:**
1. 20 lần login sai với testuser01 → Keycloak trả 401
2. Promtail đọc Envoy access log → Loki stream `job=envoy-access`
3. Grafana alert "Kịch bản 1 — Brute Force" fire (count_over_time của 401 [1m] > ngưỡng)
4. SOAR nhận webhook → attack_type=`brute_force` → playbook `revoke_user_sessions`
5. Keycloak Admin API xóa tất cả session của user vi phạm
6. Xem case tại http://localhost:18081/security hoặc `curl http://localhost:8091/cases`

---

### Kịch bản 2 — Lateral Movement (T1021.007)

**Mô tả:** Service dùng SPIFFE ID ngoài allowlist → OPA deny → SOAR isolate workload.

```bash
bash tests/scenario_03_lateral_movement.sh
# Hoặc từ Web Portal: /scenarios → "Lateral Movement"
```

**Chuỗi sự kiện:**
1. Request đến Envoy với source.principal không thuộc `spiffe://ztlab.local/`
2. OPA: `valid_svid = false` → `internal_service_request = false` → `allow = false`
3. OPA decision log: `result=false` → Promtail → Loki label `opa_result=false`
4. Grafana alert "Kịch bản 2 — Lateral Movement" fire
5. SOAR: attack_type=`lateral_movement` → playbook `isolate_workload` → patch Service selector
6. payment-service tạm ngưng nhận traffic

**Restore sau demo:**
```bash
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

---

### Kịch bản 3 — Fraud Gate Bypass (T1078.004) — Gap 2

**Mô tả:** Bỏ qua fraud-detection, gọi trực tiếp core-banking không có fraud gate header → OPA deny → SOAR isolate.

```bash
python3 tests/scenario_04_fraud_gate_bypass.py
# Hoặc từ Web Portal: /scenarios → "Fraud Gate Bypass"
```

**Chuỗi sự kiện:**
1. POST `/transactions/execute` đến core-banking (OpenStack) không có header `x-fraud-gate: passed`
2. OPA (OpenStack): path = `/transactions/execute` → yêu cầu `core_transaction_with_fraud_gate` → `fraud_gate_valid = false` → deny
3. OPA log: `result=false` với `":path":"/transactions/execute"` → Promtail extract `request_path=/transactions/execute`
4. Loki stream: `{job="opa-decisions", opa_result="false", request_path="/transactions/execute"}`
5. Grafana alert "Kịch bản 3 — Fraud Gate Bypass" fire
6. SOAR: attack_type=`fraud_gate_bypass` → playbook `isolate_workload`

**OPA policy kiểm tra (Gap 2):**

| Request | Kết quả |
|---------|---------|
| POST /transactions/execute, không có fraud gate | **DENY** ← cơ chế bảo vệ |
| POST /transactions/execute, x-fraud-gate=passed, x-fraud-score=5 | ALLOW |
| POST /transactions/execute, x-fraud-gate=passed, x-fraud-score=80 | **DENY** (score ≥ 75) |
| POST /transactions (không phải /execute), có SVID | ALLOW |

**Restore:**
```bash
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

---

### Kịch bản 4 — Data Exfiltration (T1041) — Gap 1

**Mô tả:** Response từ core-banking vượt 1MB → Grafana alert → SOAR restrict egress.

```bash
python3 tests/scenario_06_exfiltration.py
# Hoặc từ Web Portal: /scenarios → "Data Exfiltration"
```

**Chuỗi sự kiện:**
1. Request tải lượng dữ liệu lớn → Envoy access log `bytes_sent > 1048576`
2. Loki stream `job=envoy-access`, label `gap=gap1`
3. Grafana alert "Kịch bản 4 — Data Exfiltration Suspect" fire
4. SOAR: attack_type=`large_response` → playbook `restrict_egress` → scale api-gateway xuống 0

**Restore:**
```bash
kubectl --context ctx-aws scale deployment api-gateway -n financial --replicas=1
```

---

### Kịch bản 5 — JWT Forgery (T1606)

**Mô tả:** JWT tự ký với key giả, algorithm=none → API Gateway từ chối.

```bash
python3 tests/scenario_02_jwt_forgery.py
```

**Kết quả mong đợi:** HTTP 401/403, không vào được API Gateway. OPA `valid_jwt = false`.

---

### Kịch bản 6 — High Velocity (T1190)

**Mô tả:** 50 payment liên tiếp → fraud score tăng theo velocity (Redis DB0) → gate block.

```bash
python3 tests/scenario_05_high_velocity.py
```

---

### Restore toàn bộ sau demo

```bash
# Restore payment-service nếu bị isolate
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'

# Restore api-gateway nếu bị restrict_egress (scale=0)
kubectl --context ctx-aws scale deployment api-gateway -n financial --replicas=1

# Unblock IPs
for ip in $(curl -s http://localhost:8091/blocked-ips | python3 -c \
  "import sys,json; [print(x.get('ip','')) for x in json.load(sys.stdin)]"); do
  curl -s -X DELETE "http://localhost:8091/blocked-ips/$ip"
done

# Reset số dư
python3 tests/seed_db.py
```

---

## 9. SOAR Engine

**URL:** http://localhost:8091  
**Cấu hình hiện tại:** `auto_execute=true`, `min_severity=medium`, `dry_run=false`

SOAR nhận webhook từ Grafana → phân tích alert → chạy playbook tự động nếu `severity >= medium`.

### Playbooks

| Playbook | Trigger | Hành động K8s |
|----------|---------|--------------|
| `isolate_workload` | lateral_movement, fraud_gate_bypass | Patch Service selector → pod không nhận traffic (vẫn còn để forensics) |
| `restrict_egress` | large_response | Scale Deployment → 0 replica |
| `quarantine_workload` | cryptomining | Scale Deployment → 0 replica |
| `block_source_ip` | port_scan, exploit_probe, access_denied | Tạo NetworkPolicy chặn source IP/32 + ghi Redis DB0 (24h) |
| `revoke_user_sessions` | brute_force, jwt_replay, credential_stuffing | Keycloak Admin API xóa session user |

### Attack type routing

| attack_type (Grafana label) | Playbook | Target |
|-----------------------------|---------|--------|
| fraud_gate_bypass | isolate_workload | payment-service |
| lateral_movement | isolate_workload | payment-service |
| large_response | restrict_egress | api-gateway |
| brute_force | revoke_user_sessions | api-gateway |
| access_denied | block_source_ip | api-gateway |
| port_scan | block_source_ip | api-gateway |
| jwt_replay | revoke_user_sessions | api-gateway |

### API endpoints

```bash
# Trạng thái SOAR
curl http://localhost:8091/health

# Tất cả cases
curl http://localhost:8091/cases | python3 -m json.tool

# Chi tiết case
curl http://localhost:8091/cases/{case_id}

# Rollback case (restore workload bị isolate)
curl -X POST http://localhost:8091/cases/{case_id}/rollback

# IPs đang bị block
curl http://localhost:8091/blocked-ips

# Block IP thủ công
curl -X POST http://localhost:8091/blocked-ips/1.2.3.4

# Unblock IP
curl -X DELETE http://localhost:8091/blocked-ips/1.2.3.4

# Danh sách playbooks
curl http://localhost:8091/playbooks
```

### Lưu ý về repeat_interval

Grafana notification policy có `repeat_interval=1h` — cùng một alert sẽ không gửi lại SOAR trong 1 giờ. Nếu cần test lại cùng kịch bản trước 1 giờ, xóa silence/silence expire rồi chờ alert re-evaluate.

---

## 10. Grafana — Dashboards & Alerts

**URL:** http://localhost:3000 · Login: admin / ZTALab2026!  
**Log retention: 90 ngày**

### 6 Dashboards (folder: ZTLab)

| Dashboard | Mô tả |
|-----------|-------|
| ZTLab — Zero Trust Security Overview | Tổng quan OPA allow/deny, JWT failures, fraud |
| ZTLab Security Overview | Panels tóm tắt nhanh |
| ZTLab Full Logs | Toàn bộ Envoy access logs |
| Envoy Access Logs | HTTP matrix, latency P50/P95/P99 |
| OPA Decision Log | Allow/deny rate, top denied paths |
| SIEM SOAR — Security Incidents & Response | Cases, playbooks, IPs blocked, log stream |

### 6 Alert Rules (folder: ZTLab)

| Alert | Severity | Query Loki | attack_type | SOAR Playbook |
|-------|----------|-----------|-------------|---------------|
| Kịch bản 1 — Brute Force Login | high | count_over_time 401 [1m] | brute_force | revoke_user_sessions |
| Kịch bản 2 — Lateral Movement | critical | count_over_time opa_result=false [5m] | lateral_movement | isolate_workload |
| Kịch bản 3 — Fraud Gate Bypass | critical | count_over_time opa_result=false, request_path=/transactions/execute [5m] | fraud_gate_bypass | isolate_workload |
| Kịch bản 4 — Data Exfiltration | high | count_over_time bytes_sent > 1MB [5m] | large_response | restrict_egress |
| Access Denied Spike | high | count_over_time OPA deny [1m] | access_denied | block_source_ip |
| SOAR Engine Health | warning | count SOAR logs [5m] < 1 | — | — (monitor only) |

> **Tất cả** alert `category=security` → webhook SOAR Engine (`/grafana-webhook`).  
> Alert SOAR Engine Health chỉ fire khi SOAR pod DOWN (không có log > 5 phút).

### Contact points

- `ztlab-security-admin` (webhook): `http://soar-engine.plg-stack.svc.cluster.local:8080/grafana-webhook`

### Notification policy

- `category="security"` → `ztlab-security-admin`
- `group_wait=10s` · `group_interval=5m` · `repeat_interval=1h`

---

## 11. OPA — Chính sách bảo mật

**File:** `opa/policies/zta_policy.rego`  
**ConfigMap:** `opa-policies` (namespace: financial, cả AWS lẫn OpenStack)

### Các rule chính

```
allow = true khi:
  public_path           → GET /health, /ready, /metrics*
  external_api_request  → JWT hợp lệ + role_permits_action + không có SVID
  internal_service_request → SVID hợp lệ + method/path phù hợp
  core_transaction_with_fraud_gate → SVID + POST /transactions/execute + fraud gate đã xác nhận
```

### Fraud gate enforcement (Gap 2)

```rego
# POST /transactions/execute YÊU CẦU fraud gate — không thể bypass qua internal_service_request
internal_service_request if {
  valid_svid
  method == "POST"
  startswith(path, "/transactions")
  not startswith(path, "/transactions/execute")   ← exclusion bảo vệ
}

core_transaction_with_fraud_gate if {
  valid_svid
  method == "POST"
  startswith(path, "/transactions/execute")
  fraud_gate_valid                                 ← x-fraud-gate=passed + x-fraud-score<75
}
```

### Cập nhật OPA policy

```bash
# Sửa file opa/policies/zta_policy.rego, sau đó:
kubectl --context ctx-aws create configmap opa-policies \
  -n financial \
  --from-file=zta_policy.rego=opa/policies/zta_policy.rego \
  --from-file=fraud_gate.rego=opa/policies/fraud_gate.rego \
  --from-file=cross_cloud.rego=opa/policies/cross_cloud.rego \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -

kubectl --context ctx-aws rollout restart deployment/opa-server -n financial

# Tương tự cho OpenStack nếu cần
kubectl --context ctx-openstack create configmap opa-policies \
  -n financial \
  --from-file=zta_policy.rego=opa/policies/zta_policy.rego \
  --from-file=fraud_gate.rego=opa/policies/fraud_gate.rego \
  --from-file=cross_cloud.rego=opa/policies/cross_cloud.rego \
  --dry-run=client -o yaml | kubectl --context ctx-openstack apply -f -

kubectl --context ctx-openstack rollout restart deployment/opa-server -n financial
```

---

## 12. Xử lý sự cố thường gặp

### Payment trả 503 — SOAR đã auto-isolate service

```bash
# Kiểm tra selector
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.spec.selector}'
# Nếu có "soar.ztlab.io/isolated":"true" → restore:
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'

# Xem SOAR case để hiểu nguyên nhân
curl http://localhost:8091/cases | python3 -c "
import sys,json
for c in sorted(json.load(sys.stdin), key=lambda x:x.get('ts',''), reverse=True)[:5]:
    print(c['ts'][11:19], c['attack_type'], c['playbook'], c['status'])"
```

### Lateral Movement alert fire khi đang test OPA trực tiếp

Khi test OPA qua `curl localhost:XXXX/v1/data/...` (không qua Envoy), request không có SPIFFE SVID → OPA deny → Promtail pick up → Grafana alert fire → SOAR isolate payment-service. Đây là **behavior đúng**.

Restore payment-service và dừng test OPA direct để alert tự về inactive sau ~5 phút.

### Payment trả 503 — cross-cloud không hoạt động

```bash
# 1. Kiểm tra OpenStack VMs
source /etc/kolla/admin-openrc.sh && openstack server list
# Nếu SHUTOFF: openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2

# 2. Kiểm tra WireGuard
ssh -i ~/.ssh/ztlab-key ubuntu@52.221.255.36 "sudo wg show wg0"

# 3. Kiểm tra OpenStack pods
kubectl --context ctx-openstack get pods -n financial | grep -v Running

# 4. Test TCP từ payment-service đến core-banking
kubectl --context ctx-aws exec -n financial deployment/payment-service \
  -c payment-service -- python3 -c "
import socket; s=socket.socket(); s.settimeout(5)
try: s.connect(('192.168.101.11',30080)); print('30080 OK')
except Exception as e: print('FAIL:', e)"
```

### Payment trả 403 — HMAC fail

```bash
# Kiểm tra secret trên cả hai cluster
kubectl --context ctx-aws get secret core-banking-integrity-secret -n financial
kubectl --context ctx-openstack get secret core-banking-integrity-secret -n financial

# Nếu thiếu trên OpenStack, sync từ AWS:
SECRET=$(kubectl --context ctx-aws get secret core-banking-integrity-secret \
  -n financial -o jsonpath='{.data.CORE_BANKING_SHARED_SECRET}')
kubectl --context ctx-openstack create secret generic core-banking-integrity-secret \
  -n financial --from-literal=CORE_BANKING_SHARED_SECRET=$(echo $SECRET | base64 -d) \
  --dry-run=client -o yaml | kubectl --context ctx-openstack apply -f -
```

### API Gateway trả 403 — JWT invalid issuer

OPA kiểm tra `jwt_payload.iss == "http://keycloak.ztlab.local:8180/realms/ztlab"`. Nếu Keycloak chạy URL khác → 403. Kiểm tra issuer trong token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234!&scope=openid" \
  -H "Content-Type: application/x-www-form-urlencoded" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Decode payload (base64)
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool | grep iss
```

### API Gateway trả jwks_keys_loaded=0

Keycloak chưa sẵn sàng khi api-gateway start. Restart:
```bash
kubectl --context ctx-aws -n financial rollout restart deployment/api-gateway
```

### Không đăng nhập được Web Portal — invalid_redirect_uri

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=ztlab-admin-2026" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

CLIENT_ID=$(curl -s "http://localhost:8180/admin/realms/ztlab/clients?clientId=web-portal" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

curl -s -X PUT "http://localhost:8180/admin/realms/ztlab/clients/$CLIENT_ID" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "clientId":"web-portal","publicClient":true,"standardFlowEnabled":true,
    "attributes":{"pkce.code.challenge.method":"S256"},
    "redirectUris":["http://localhost:18081/*","http://127.0.0.1:18081/*"],
    "webOrigins":["+"]
  }'
```

### Loki không nhận log từ OpenStack

```bash
# Kiểm tra socat proxy đang chạy
ss -lnt | grep 13099
# Phải có: 10.10.10.1:13099

# Nếu không có → khởi động lại port-forwards
bash scripts/open-admin-uis.sh stop
bash scripts/open-admin-uis.sh

# Kiểm tra OpenStack promtail LOKI_PUSH_URL
kubectl --context ctx-openstack get daemonset promtail -n plg-stack \
  -o jsonpath='{.spec.template.spec.containers[0].env}' | python3 -c "
import sys,json
for e in json.load(sys.stdin):
    if 'LOKI' in e.get('name',''):
        print(e['name'], '=', e.get('value','?'))"
# Phải là: LOKI_PUSH_URL = http://10.10.10.1:13099/loki/api/v1/push
```

### SPIRE SVID hết hạn (lỗi mTLS sau ~1h)

```bash
kubectl --context ctx-aws rollout restart daemonset/spire-agent -n spire
# Đợi SVID renew xong
kubectl --context ctx-aws -n financial rollout restart deployment
kubectl --context ctx-openstack -n financial rollout restart deployment
```

### K8s tunnel mất kết nối

```bash
bash scripts/k8s-tunnel.sh down all
bash scripts/k8s-tunnel.sh up all
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

### Grafana alert bị firing liên tục (false positive)

```bash
# Kiểm tra trạng thái các alert
curl -s -u admin:ZTALab2026! \
  "http://localhost:3000/api/prometheus/grafana/api/v1/rules" | python3 -c "
import sys,json; d=json.load(sys.stdin)
for g in d.get('data',{}).get('groups',[]):
    for r in g.get('rules',[]):
        if r.get('state')=='firing':
            for a in r.get('alerts',[]):
                print(r['name'], '→', a.get('state'), 'value:', a.get('value'))"

# Nếu state="Alerting (Error)" → query lỗi → check execErrState
# Nếu có OPA deny không mong muốn → kiểm tra xem có test OPA trực tiếp không
# Alert tự về inactive sau 5 phút khi không còn trigger
```

### SOAR pod không start

```bash
kubectl --context ctx-aws -n plg-stack describe pod -l app=soar-engine | tail -20
# Thường do secret redis-auth thiếu → chạy lại deploy
bash scripts/deploy-all.sh
```

### Token test API nhanh

```bash
# Lấy token testuser01
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234!&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo $TOKEN

# Dùng token
curl -H "Authorization: Bearer $TOKEN" http://localhost:18080/accounts/ACC-1001
```

---

*Hệ thống implement Zero Trust Architecture theo NIST SP 800-207: không có implicit trust, mọi request đều xác thực identity (JWT + SPIFFE SVID) và policy (OPA) trước khi được phép truy cập tài nguyên.*
