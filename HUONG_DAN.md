# ZTLab — Hướng Dẫn Vận Hành & Demo

**Zero Trust Security Detection and Response for Microservices in Multi-Cloud**  
Sinh viên: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
GVHD: ThS. Đỗ Thị Phương Uyên · Môn: NT114.Q21.ANTT

---

## Mục lục

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Hạ tầng & IP](#2-hạ-tầng--ip)
3. [Kết nối vào hệ thống](#3-kết-nối-vào-hệ-thống)
4. [**Khởi động lại sau restart máy**](#4-khởi-động-lại-sau-restart-máy)
5. [Deploy lần đầu](#5-deploy-lần-đầu)
6. [Mở port-forwards (mỗi lần demo)](#6-mở-port-forwards-mỗi-lần-demo)
7. [Health check](#7-health-check)
8. [Tài khoản & credentials](#8-tài-khoản--credentials)
9. [Web Portal](#9-web-portal)
10. [Grafana — Dashboards & Alert Rules](#10-grafana--dashboards--alert-rules)
11. [SOAR Engine & HITL](#11-soar-engine--hitl)
12. [Grafana → SOAR tự động](#12-grafana--soar-tự-động)
13. [Chạy demo & quay video](#13-chạy-demo--quay-video)
14. [Kịch bản tấn công chi tiết](#14-kịch-bản-tấn-công-chi-tiết)
15. [Database Admin UIs](#15-database-admin-uis)
16. [Hạn chế đã biết](#16-hạn-chế-đã-biết)
17. [Xử lý lỗi thường gặp](#17-xử-lý-lỗi-thường-gặp)

---

## 1. Tổng quan kiến trúc

```
Internet  (HTTPS / PKCE OIDC)
    │
    ▼
┌─────────────────────── AWS K3s (ctx-aws) ──────────────────────────────┐
│  namespace: identity                                                    │
│    Keycloak  (realm=ztlab · port 8080)                                 │
│    SPIRE Server (trust domain=ztlab.local · SVID TTL=1h · CA=168h)    │
│                                                                         │
│  namespace: financial                                                   │
│    api-gateway       SVID: spiffe://ztlab.local/aws/api-gateway        │
│    payment-service   SVID: spiffe://ztlab.local/aws/payment-service    │
│    fraud-detection   SVID: spiffe://ztlab.local/aws/fraud-detection    │
│    notification-svc  SVID: spiffe://ztlab.local/aws/notification-svc   │
│    web-portal        ──PKCE──► Keycloak                                │
│                                                                         │
│  namespace: plg-stack                                                   │
│    Promtail (DaemonSet) → Loki (retention 90 ngày) → Grafana           │
│    SOAR Engine  (Grafana webhook trigger · K8s SDK · Keycloak API)     │
│    Security Scorer  (anomaly score 15min window)                       │
│                                                                         │
│  namespace: monitoring                                                  │
│    Prometheus                                                           │
└───────────────────────┬─────────────────────────────────────────────────┘
                        │  WireGuard mTLS (Envoy SPIFFE SVID)
                        │  payment-service Envoy → 192.168.101.11:30080
                        ▼
┌────────────── OpenStack K3s (ctx-openstack) ────────────────────────────┐
│  namespace: financial                                                    │
│    core-banking      SVID: spiffe://ztlab.local/openstack/core-banking  │
│      NodePort 30080 (mTLS·Envoy) · 30084 (HTTP)                        │
│    account-service   SVID: spiffe://ztlab.local/openstack/account-svc   │
│      NodePort 30082 (mTLS·Envoy) · 30086 (HTTP)                        │
│    transaction-svc   SVID: spiffe://ztlab.local/openstack/txn-svc       │
│      NodePort 30083 (mTLS·Envoy) · 30087 (HTTP)                        │
│    PostgreSQL accounts + txn · Redis · pgAdmin · RedisInsight            │
│    OPA Server (authz policy cho inbound mTLS)                           │
└─────────────────────────────────────────────────────────────────────────┘
```

> **Kiến trúc cross-cloud thực tế:** AWS K3s và OpenStack K3s kết nối qua WireGuard (`10.200.0.1 ↔ 10.200.0.2`). AWS pods tới OpenStack NodePorts qua MASQUERADE rule. 3 services core banking deploy trên **OpenStack** theo đúng Bảng 4.2 NT114.

**Luồng payment chính:**
```
web-portal → api-gateway (JWT verify + OPA) → payment-service (HMAC sign)
  → fraud-detection (Redis velocity check 15 phút)
  → core-banking (SPIRE mTLS) → account-service (debit/credit)
  → transaction-service (ledger)
```

**Luồng phát hiện & phản ứng:**
```
Grafana alert rule (Loki query) fires
  → POST soar-engine/grafana-webhook
  → severity low/medium  → execute playbook ngay
  → severity high/critical → pending_approval → email admin
       └─ Admin click [PHÊ DUYỆT] → playbook thực thi
       └─ Admin click [TỪ CHỐI]   → case skipped
```

---

## 2. Hạ tầng & IP

| Node | Private IP | Public IP | Vai trò |
|------|-----------|-----------|---------|
| aws_bastion | — | 52.221.255.36 | SSH jump host |
| aws_gateway | 10.10.0.x / WG 10.200.0.1 | 13.213.245.227 | NAT + WireGuard server |
| aws_k3s_master | 10.10.1.10 | — | K8s control plane (AWS) · Traefik |
| aws_k3s_worker_1 | 10.10.1.11 | — | K8s worker (AWS) · Loki relay |
| os_gateway | — | 10.10.10.188 | WireGuard client (OpenStack) |
| os_k3s_master | 192.168.101.11 | — | K8s standalone (OpenStack) |

**WireGuard:**
- aws_gateway: `10.200.0.1` · os_gateway: `10.200.0.2`
- Subnet tunnel: `10.200.0.0/24` · Port: UDP 51820
- MASQUERADE rule trên aws nodes: `10.42.0.0/16 → 192.168.101.0/24`

**Cross-cloud Envoy upstream (đang active):**
- payment-service Envoy → `192.168.101.11:30080` → core-banking (OpenStack mTLS)
- api-gateway Envoy → `192.168.101.11:30082` → account-service (OpenStack mTLS)
- api-gateway Envoy → `192.168.101.11:30083` → transaction-service (OpenStack mTLS)
- core-banking app → `account-service.financial.svc.cluster.local:8080` (internal HTTP trên OS cluster)

**K8s contexts:**
- `ctx-aws` → API server `127.0.0.1:6444` (qua SSH tunnel)
- `ctx-openstack` → API server `127.0.0.1:6445` (qua SSH tunnel)

**SSH key:** `~/.ssh/ztlab-key`

---

## 3. Kết nối vào hệ thống

### Bước 0 — Bật WireGuard VPN (nếu chưa chạy)

```bash
# Cấu hình lần đầu
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/wireguard.yml

# Kiểm tra tunnel
ansible aws_gateway,os_gateway -i ansible/inventory/hosts.yml -m shell -a "wg show wg0"

# Restart nếu cần
ansible aws_gateway,os_gateway -i ansible/inventory/hosts.yml \
  -m shell -a "systemctl restart wg-quick@wg0"
```

### Bước 1 — Mở K8s API tunnel

```bash
bash scripts/k8s-tunnel.sh up all
```

Tunnel forward (qua SSH bastion):
- `127.0.0.1:6444` → `aws_k3s_master:6443` qua bastion 52.221.255.36
- `127.0.0.1:6445` → `os_k3s_master:6443` qua os_gateway 10.10.10.188

Kiểm tra:
```bash
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

Dừng tunnel:
```bash
bash scripts/k8s-tunnel.sh down all
```

---

## 4. Khởi động lại sau restart máy

> Làm theo thứ tự này mỗi khi reboot máy deployer hoặc mở lại session mới.

### Bước 1 — Kiểm tra OpenStack containers (nếu dùng OpenStack local)

```bash
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "horizon|keystone|nova|neutron"
```

Nếu containers chưa chạy:
```bash
cd /etc/kolla && docker compose up -d    # hoặc: kolla-ansible deploy
```

### Bước 2 — Kiểm tra K8s tunnel hiện tại

```bash
bash scripts/k8s-tunnel.sh status
```

Nếu không thấy port nào đang listen → mở tunnel:

```bash
# Chỉ cần AWS (thường dùng nhất):
bash scripts/k8s-tunnel.sh up aws

# Cả hai cloud (nếu OpenStack VM đang bật):
bash scripts/k8s-tunnel.sh up all
```

Xác nhận đã kết nối:
```bash
kubectl --context ctx-aws get nodes
# Kỳ vọng: ip-10-10-1-10 Ready, ip-10-10-1-11 Ready
```

### Bước 3 — Kiểm tra OpenStack VMs (bắt buộc cho cross-cloud)

```bash
source /etc/kolla/admin-openrc.sh
openstack server list
# Tất cả phải ở trạng thái ACTIVE
```

Nếu VMs bị SHUTOFF:
```bash
openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2
# Đợi 30 giây rồi mở tunnel
bash scripts/k8s-tunnel.sh up all
```

### Bước 4 — Kiểm tra pods quan trọng

```bash
# AWS: 4 financial services + PLG + identity
kubectl --context ctx-aws get pods -n financial
kubectl --context ctx-aws get pods -n plg-stack
kubectl --context ctx-aws get pods -n identity

# OpenStack: 3 core banking services
kubectl --context ctx-openstack get pods -n financial
```

Pod nào không `Running` — restart:
```bash
kubectl --context ctx-aws rollout restart deployment/<tên-pod> -n <namespace>
kubectl --context ctx-openstack rollout restart deployment/<tên-pod> -n financial
```

Nếu hầu hết pods đều crash → re-deploy toàn bộ:
```bash
export KEYCLOAK_ADMIN_PASSWORD=ztlab-admin-2026
bash scripts/deploy-all.sh
```

### Bước 5 — Mở port-forwards

```bash
bash scripts/open-admin-uis.sh
```

Script thoát ngay (không cần giữ terminal), mỗi port-forward chạy nền tự restart. Tất cả 10 UI sẽ hiện `[ OK ]`. Kiểm tra lại bất cứ lúc nào: `bash scripts/open-admin-uis.sh status`. Nếu có `[FAIL]` → xem mục [Xử lý lỗi](#17-xử-lý-lỗi-thường-gặp).

### Bước 6 — Quick health check

```bash
curl -s http://localhost:18081/health | python3 -m json.tool   # web-portal
curl -s http://localhost:18080/health | python3 -m json.tool   # api-gateway
curl -s http://localhost:8091/health  | python3 -m json.tool   # soar-engine
curl -s http://localhost:3000/api/health                        # grafana
```

Kiểm tra thêm SOAR cases (phòng SOAR isolate service từ demo trước):
```bash
# Xem services có bị SOAR isolate không
kubectl --context ctx-aws get svc -n financial \
  -o jsonpath='{range .items[*]}{.metadata.name}{": "}{.spec.selector}{"\n"}{end}' | \
  python3 -c "import sys; [print('⚠ ISOLATED:', l) for l in sys.stdin if 'isolated' in l]"

# Nếu có service bị isolate → rollback
curl http://localhost:8091/cases | python3 -c "
import sys,json
[print(c['case_id'], c['target_workload'], c['status'])
 for c in json.load(sys.stdin) if c['playbook']=='isolate_workload']"
# curl -X POST http://localhost:8091/cases/{case_id}/rollback
```

### Checklist tóm tắt (copy & paste)

```bash
# 1. Kiểm tra/bật OpenStack VMs
source /etc/kolla/admin-openrc.sh
openstack server list
# Nếu SHUTOFF: openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2

# 2. Tunnel (cả 2 cloud)
bash scripts/k8s-tunnel.sh up all

# 3. Xác nhận nodes OK
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes

# 4. Xác nhận pods OK
kubectl --context ctx-aws get pods -n financial
kubectl --context ctx-openstack get pods -n financial
kubectl --context ctx-aws get pods -n plg-stack
kubectl --context ctx-aws get pods -n identity

# 5. Port-forwards
bash scripts/open-admin-uis.sh

# 6. Kiểm tra SOAR không isolate service
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.spec.selector}'
# Phải là: {"app":"payment-service"} — không có "soar.ztlab.io/isolated"
```

> **Sau khi reboot AWS VM**: pods tự restart (K3s systemd). Chỉ cần làm lại bước 2 và 5 ở trên.

> **Sau khi reboot OpenStack VM**: VMs tắt — phải `openstack server start` lại (bước 1 ở trên). WireGuard trên os-gateway tự khởi cùng systemd.

---

## 5. Deploy lần đầu

Chỉ làm một lần khi hệ thống chưa có gì. Tunnel phải đang chạy.

### Bước 1 — Build & sync images

```bash
IMAGE_TAG=1.0.0 bash scripts/sync-financial-images.sh
```

Build 10 service images và copy vào containerd trên tất cả K3s nodes.

Services: `api-gateway`, `payment-service`, `fraud-detection`, `notification-service`, `core-banking`, `account-service`, `transaction-service`, `soar-engine`, `web-portal`, `security-scorer`

### Bước 2 — Deploy toàn bộ

```bash
export KEYCLOAK_ADMIN_PASSWORD=ztlab-admin-2026
bash scripts/deploy-all.sh
```

8 steps theo thứ tự: Namespaces → Images → Security stack (SPIRE/SPIFFE · OPA · Keycloak realm `ztlab`) → Financial infra → Financial workloads → PLG + SOAR → Network policies + Ingress → Status check.

> Nếu muốn chạy riêng security stack: `KEYCLOAK_ADMIN_PASSWORD=ztlab-admin-2026 bash scripts/deploy-security-stack.sh`

### Bước 3 — Seed database (chạy sau deploy)

```bash
python3 tests/seed_db.py
```

Reset balances về baseline NT114: ACC-1001 = 1,000,000,000 VND · ACC-2001 = 250,000,000 VND.

---

## 6. Mở port-forwards (mỗi lần demo)

Script chạy mỗi port-forward như một **daemon tự restart** — không cần giữ terminal mở, không bị kill khi đóng cửa sổ.

```bash
bash scripts/open-admin-uis.sh          # bật tất cả
bash scripts/open-admin-uis.sh status   # kiểm tra daemon còn chạy không
bash scripts/open-admin-uis.sh stop     # dừng tất cả
```

| Service | URL | Credentials |
|---------|-----|-------------|
| Keycloak | http://localhost:8180 | admin / ztlab-admin-2026 |
| API Gateway | http://localhost:18080 | — |
| Web Portal | http://localhost:18081 | testuser01 / Test1234! |
| Grafana | http://localhost:3000 | admin / ZTALab2026! |
| Loki | http://localhost:13100 | — |
| SOAR Engine | http://localhost:8091 | — |
| Security Scorer | http://localhost:18092 | — |
| Prometheus | http://localhost:9090 | — |
| pgAdmin | http://localhost:5050 | admin@ztlab.com / ztlab2026 |
| RedisInsight | http://localhost:5540 | — |

> Tất cả port-forward đều từ cluster **AWS**. Nếu một port-forward chết (mất kết nối K8s thoáng qua), daemon tự restart sau 3 giây.

---

## 7. Health check

```bash
bash scripts/health-check.sh
```

Kiểm tra nhanh từng service:

```bash
curl http://localhost:18080/health    # api-gateway: {"jwks_keys_loaded": 2}
curl http://localhost:8091/health     # soar-engine: {"dry_run": false, "hitl_severity": "high", ...}
curl http://localhost:13100/ready     # loki: ready
curl http://localhost:3000/api/health # grafana: {"database": "ok"}
```

---

## 8. Tài khoản & credentials

### Keycloak — realm: ztlab

| Username | Password | Roles | Tài khoản ngân hàng |
|----------|----------|-------|---------------------|
| admin *(Keycloak)* | ztlab-admin-2026 | Keycloak superadmin | — |
| testuser01 | Test1234! | financial-read, financial-write | ACC-1001 (1,000,000,000 VND) |
| testuser02 | Test1234! | financial-read, financial-write | ACC-2001 (250,000,000 VND) |
| merchant01 | Test1234! | financial-read | ACC-4001 (26,750,000 VND) |
| analyst01  | Test1234! | security-analyst | ACC-5001 (10,000,000 VND) |

> **merchant01** chỉ có `financial-read` → POST /payments → HTTP 403 (dùng để demo RBAC).  
> **analyst01** có `security-analyst` → xem được `/security` và `/monitor` nhưng không chuyển tiền được.

**Roles:**

| Role | Quyền |
|------|-------|
| `financial-read` | GET /accounts, GET /transactions |
| `financial-write` | + POST /payments |
| `security-analyst` | Xem SOAR cases, security monitor |
| `security-admin` | + Block IP, rollback playbook, approve HITL |

### Reset DB trước mỗi bộ test

```bash
python3 tests/seed_db.py
```

Reset balances về baseline (ACC-1001=1B, ACC-2001=250M) và xóa ledger transactions.

### Grafana

- **Login:** admin / ZTALab2026!

### Database

| DB | Internal host | DB name | User | Password |
|----|--------------|---------|------|---------|
| PostgreSQL accounts | postgres-accounts.financial:5432 | accounts_db | accounts_user | accounts_pass |
| PostgreSQL transactions | postgres-txn.financial:5432 | transactions_db | txn_user | txn_pass |
| Redis | redis.financial:6379 | DB0/DB1 | — | ZTALab-Redis-2026! |

**Redis DB mapping:**
- **DB0** — fraud velocity keys + IP blocklist + SOAR IP blocking
- **DB1** — anomaly scorer 15 phút window (security-scorer)

### SPIRE

- Trust domain: `ztlab.local`
- SVID TTL: 1h · CA TTL: 168h
- SPIFFE IDs: `spiffe://ztlab.local/aws/{service}` · `spiffe://ztlab.local/openstack/{service}`

---

## 9. Web Portal

**URL:** http://localhost:18081

### Trang & quyền

| Đường dẫn | Mô tả | Role yêu cầu |
|-----------|-------|-------------|
| `/login` | Đăng nhập OIDC/PKCE | Không |
| `/register` | Tạo tài khoản mới | Không |
| `/dashboard` | Số dư, lịch sử giao dịch | Đăng nhập |
| `/transfer` | Chuyển tiền | financial-write |
| `/profile` | Thông tin tài khoản | Đăng nhập |
| `/scenarios` | Chạy kịch bản attack demo | Đăng nhập |
| `/security` | SOAR cases, blocked IPs | security-analyst / security-admin |
| `/monitor` | System health tất cả services | security-analyst / security-admin |
| `/admin` | Quản lý users & accounts | security-admin |

### Login flow PKCE

1. `/login` → click "Đăng nhập với Keycloak" → redirect Keycloak
2. Keycloak xác thực → authorization code → web-portal exchange code → JWT
3. Session lưu trong HMAC-signed cookie (TTL 1h)

### Scenarios page

Trang `/scenarios` cho phép trigger các kịch bản demo trực tiếp từ UI (không cần terminal):
- No JWT · JWT Forgery · Lateral Movement · Fraud Gate Bypass
- High Velocity · Rate Limit · Inject events (brute force, port scan, exfiltration...)

---

## 10. Grafana — Dashboards & Alert Rules

**URL:** http://localhost:3000 · **Login:** admin / ZTALab2026!

**Log retention: 90 ngày** (2160h) — đủ cho yêu cầu audit bảo mật.

### 6 Dashboards (folder: ZTLab)

| Dashboard | UID | Mô tả |
|-----------|-----|-------|
| ZTLab — Zero Trust Security Overview | `ztlab-security-v2` | Tổng quan OPA, JWT failures, fraud blocks |
| ZTLab Security Overview | `ztlab-security-overview` | Panels tóm tắt nhanh |
| ZTLab Full Logs | `ztlab-full-logs` | Toàn bộ Envoy access logs |
| Envoy Access Logs | `ztlab-envoy-access-logs` | HTTP matrix, latency P50/P95/P99 |
| OPA Decision Log | `ztlab-opa-decision-log` | Allow/deny rate, top denied paths |
| SIEM SOAR — Security Incidents & Response | `siem-soar-ztlab` | Cases, HITL pending, playbooks executed, IPs blocked, log stream |

### 6 Alert Rules (folder: ZTLab)

| Alert | Severity | Trigger | SOAR playbook |
|-------|----------|---------|---------------|
| Kịch bản 1 — Brute Force Login Detected | high | 401 count by IP [1m] | revoke_user_sessions |
| Kịch bản 2 — Lateral Movement: Invalid SVID | critical | OPA deny invalid svid [5m] | isolate_workload |
| Kịch bản 3 — Fraud Gate Bypass | critical | OPA deny path=/transactions/execute | isolate_workload |
| Kịch bản 4 — Data Exfiltration Suspect | high | bytes_sent > 1MB từ Envoy access log | restrict_egress |
| SOAR Engine Health | warning | soar-engine pod down > 2m | — (notify only) |
| Access Denied Spike | high | OPA deny rate tăng đột biến | block_source_ip |

> Tất cả alert `category=security` → webhook **SOAR Engine** (`/grafana-webhook`) qua contact point `ztlab-soar-webhook`.  
> Alert `severity=high` hoặc `critical` → SOAR giữ lại → **gửi email admin** chờ phê duyệt.  
> Alert `severity=low/medium` → SOAR thực thi tự động ngay (không cần approve).

> **Lưu ý:** Sau khi SOAR chạy playbook `isolate_workload`, service đó sẽ tạm ngưng nhận traffic. Restore bằng: `curl -X POST http://localhost:8091/cases/{case_id}/rollback`

---

## 11. SOAR Engine & HITL

**URL:** http://localhost:8091

### 5 Playbooks (`SOAR_DRY_RUN=false` — thực thi thật)

| Playbook | Trigger | Hành động |
|----------|---------|-----------|
| `isolate_workload` | lateral_movement, fraud_gate_bypass | Patch Service selector → traffic dừng |
| `restrict_egress` | large_response | Scale Deployment → 0 replica |
| `quarantine_workload` | cryptomining | Scale Deployment → 0 replica |
| `block_source_ip` | port_scan, exploit_probe, access_denied | Tạo NetworkPolicy chặn IP/32 + Redis DB0 blocklist 24h |
| `revoke_user_sessions` | brute_force, jwt_replay, credential_stuffing | Keycloak Admin API xóa session user |

### HITL — Human In The Loop

Khi Grafana gửi alert severity **high** hoặc **critical**, SOAR **không thực thi ngay** mà:

1. Lưu case với status `pending_approval`
2. Gửi email HTML đến admin (`voha2005@gmail.com`) với:
   - Chi tiết alert, severity, MITRE ATT&CK
   - Tên playbook sẽ thực thi, target workload
   - Log evidence từ Grafana
   - Hai nút bấm: **PHÊ DUYỆT & THỰC THI** / **TỪ CHỐI**
3. Admin click nút trong email → SOAR thực thi hoặc bỏ qua

```
Grafana alert (high/critical)
  → SOAR pending_approval
  → Email → admin click [✅ PHÊ DUYỆT] → http://localhost:8091/cases/{id}/approve?token=...
                                        → playbook execute
                        [❌ TỪ CHỐI]  → http://localhost:8091/cases/{id}/deny?token=...
                                        → case skipped
```

> Alert severity **low/medium** vẫn thực thi tự động không cần approve.

**Cấu hình SMTP** (Secret `grafana-smtp-secret`):
```bash
# Tạo/update secret
kubectl --context ctx-aws create secret generic grafana-smtp-secret \
  -n plg-stack --from-literal=password="<gmail-app-password>" \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -
kubectl --context ctx-aws rollout restart deployment/soar-engine -n plg-stack
```

### Endpoints

```bash
curl http://localhost:8091/health                          # status, pending_hitl count
curl http://localhost:8091/cases                           # tất cả cases
curl http://localhost:8091/cases/{case_id}                # chi tiết
curl -X POST http://localhost:8091/cases/{id}/rollback    # restore workload
curl http://localhost:8091/blocked-ips                    # IPs bị block
curl -X POST http://localhost:8091/blocked-ips/1.2.3.4   # block thủ công
curl -X DELETE http://localhost:8091/blocked-ips/1.2.3.4 # unblock
curl http://localhost:8091/playbooks                      # danh sách playbooks
```

---

## 12. Grafana → SOAR tự động

```
Grafana alert rule fire (Loki query, eval interval 1m)
  │
  ├─► POST soar-engine.plg-stack:8080/grafana-webhook
  │      │
  │      ├── severity low/medium → _run_steps() ngay → status: executed
  │      │
  │      └── severity high/critical → pending_approval → email admin
  │                                          │
  │                                    Admin click approve
  │                                          │
  │                                    GET /cases/{id}/approve?token=...
  │                                          │
  │                                    _run_steps() → status: executed
  │
  └─► Email thông báo (voha2005@gmail.com) — dù low/medium hay HITL
```

**IP blocking enforcement:**
Khi SOAR thực thi `block_source_ip`, key `ztlab:blocked_ip:{ip}` được ghi vào **Redis DB0**.  
api-gateway đọc cùng key này để từ chối request 403 ngay tại cổng vào.

---

## 13. Chạy demo & quay video

### Chuẩn bị

```bash
# Terminal 1 — giữ mở
bash scripts/k8s-tunnel.sh up all

# Terminal 2 — giữ mở
bash scripts/open-admin-uis.sh

# Reset DB về baseline NT114
python3 tests/seed_db.py
```

Mở sẵn 5 tab trình duyệt:

| Tab | URL | Mục đích |
|-----|-----|---------|
| 1 | http://localhost:18081 | Web Portal (đăng nhập testuser01 / Test1234!) |
| 2 | http://localhost:3000/d/ztlab-security-v2 | Grafana Zero Trust Security Overview |
| 3 | http://localhost:3000/alerting/list | Grafana Alert Rules |
| 4 | http://localhost:18081/security | SOAR cases + blocked IPs (analyst01 / Test1234!) |
| 5 | http://localhost:18081/monitor | System health |

### Chạy demo

```bash
# Full demo: normal traffic + tất cả attack scenarios
bash scripts/run-demo.sh

# Chỉ tấn công
bash scripts/run-demo.sh --attack-only

# Chỉ brute force (thấy Grafana alert → SOAR live)
bash scripts/run-demo.sh --brute-force --attack-only

# Loop liên tục (traffic chạy trong khi quay)
bash scripts/run-demo.sh --continuous
```

### Kịch bản quay video đề xuất

| Thời điểm | Màn hình | Nội dung |
|-----------|----------|---------|
| 0:00 | Web Portal /dashboard | testuser01 xem số dư ACC-1001 = 1,000,000,000 VND |
| 0:30 | Web Portal /transfer | Chuyển 100,000 VND sang ACC-2001 → completed, score=5 |
| 1:00 | Grafana Full Logs | Envoy access logs xuất hiện real-time |
| 1:30 | Terminal | Chạy `bash tests/scenario_01_brute_force.sh` |
| 2:00 | Grafana Alerting | Alert "Brute Force" chuyển → Firing |
| 2:30 | Email admin | SOAR gửi email HITL — admin click PHÊ DUYỆT |
| 3:00 | Web Portal /security (analyst01) | Cases list → status: executed |
| 3:30 | Grafana SIEM SOAR dashboard | Panels: Cases, Pending HITL, IPs Blocked, log stream |
| 4:00 | Terminal | `python3 tests/scenario_04_fraud_gate_bypass.py` |

### Sau demo — restore

```bash
# Xem cases
curl http://localhost:8091/cases | python3 -m json.tool

# Rollback workload bị isolate (thay {case_id} bằng case thực tế)
curl -X POST http://localhost:8091/cases/{case_id}/rollback

# Unblock IPs bị SOAR block
curl -X DELETE http://localhost:8091/blocked-ips/{ip_address}

# Restart toàn bộ financial services (single-cloud mode)
kubectl --context ctx-aws -n financial rollout restart deployment

# Reset DB
python3 tests/seed_db.py
```

---

## 14. Kịch bản tấn công chi tiết

### Kịch bản 1 — Brute Force (T1110.001)

```bash
KC_URL=http://localhost:8180 bash tests/scenario_01_brute_force.sh
```

20 lần login sai → Grafana alert (severity=high) → SOAR HITL email → admin approve → `revoke_user_sessions`

### Kịch bản 2 — JWT Forgery (T1606)

```bash
KC_URL=http://localhost:8180 GW_URL=http://localhost:18080 python3 tests/scenario_02_jwt_forgery.py
```

JWT tự ký với algorithm=none → API Gateway từ chối (issuer sai)

### Kịch bản 3 — Lateral Movement (T1021.007)

```bash
GW_URL=http://localhost:18080 bash tests/scenario_03_lateral_movement.sh
```

Service dùng SPIFFE ID ngoài trust domain `ztlab.local` → Envoy/OPA deny → SOAR HITL → `isolate_workload`

### Kịch bản 4 — Fraud Gate Bypass (T1078)

```bash
KC_URL=http://localhost:8180 GW_URL=http://localhost:18080 python3 tests/scenario_04_fraud_gate_bypass.py
```

Gọi core-banking với `X-Fraud-Gate: passed` giả mạo → OPA deny → SOAR HITL → `isolate_workload`

### Kịch bản 5 — High Velocity (T1190)

```bash
KC_URL=http://localhost:8180 GW_URL=http://localhost:18080 python3 tests/scenario_05_high_velocity.py
```

50 payment liên tiếp trong 15 phút → fraud score tăng theo velocity (Redis DB0) → `review` → `block`

### Kịch bản 6 — Data Exfiltration (T1041)

```bash
KC_URL=http://localhost:8180 GW_URL=http://localhost:18080 python3 tests/scenario_06_exfiltration.py
```

Response bytes_sent lớn bất thường → Grafana alert `large_response` → SOAR → `restrict_egress`

### Chạy toàn bộ test suite

```bash
KC_URL=http://localhost:8180 GW_URL=http://localhost:18080 python3 tests/scenario_00_full_suite.py
```

---

## 15. Database Admin UIs

### pgAdmin (http://localhost:5050)

> pgAdmin chạy trên cluster **AWS** — port-forward qua ctx-aws. Để xem dữ liệu OpenStack postgres, port-forward thêm: `kubectl --context ctx-openstack port-forward -n financial svc/pgadmin 5051:80`

Login: `admin@ztlab.com` / `ztlab2026`

Hai server pre-configured:
- **ZTLab Accounts** → postgres-accounts.financial:5432 · DB: accounts_db · accounts_user/accounts_pass
- **ZTLab Transactions** → postgres-txn.financial:5432 · DB: transactions_db · txn_user/txn_pass

### RedisInsight (http://localhost:5540)

> RedisInsight chạy trên cluster **AWS** — cùng cluster với Redis.

Thêm connection lần đầu:
1. Click **Add Redis Database**
2. Host: `redis.financial.svc.cluster.local` · Port: `6379`
3. Password: `ZTALab-Redis-2026!`

Hoặc mở port-forward Redis rồi dùng `127.0.0.1:6379`:
```bash
kubectl --context ctx-aws port-forward -n financial svc/redis 6379:6379 --address=127.0.0.1 &
```

### Token nhanh để test API

```bash
bash scripts/gen-dev-token.sh testuser01    # financial-write
bash scripts/gen-dev-token.sh analyst01     # security-analyst
```

---

## 16. Hạn chế đã biết

### OpenStack VMs tắt khi reboot máy deployer

KVM VMs (os-gateway, os-k3s-master, os-k3s-worker-1, os-k3s-worker-2) không tự bật khi máy host khởi động lại. Cần bật thủ công:

```bash
source /etc/kolla/admin-openrc.sh
openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2
sleep 30
bash scripts/k8s-tunnel.sh up all
kubectl --context ctx-openstack get pods -n financial
```

### Phân chia services giữa 2 cluster

| Cluster | Services | Kết nối từ AWS |
|---------|----------|----------------|
| AWS K3s | api-gateway, payment-service, fraud-detection, notification-service, web-portal | — |
| OpenStack K3s | core-banking, account-service, transaction-service | WireGuard + Envoy mTLS NodePorts 30080/30082/30083 |

> `k8s/financial/aws-backend-services.yaml` là file dự phòng cho chế độ single-cloud (NOT apply lên production cluster).

### SPIRE Agent trên OpenStack dùng join_token

Khi migrate lên OpenStack, cần tạo join token:

```bash
kubectl --context ctx-aws exec -n spire deploy/spire-server -- \
  /opt/spire/bin/spire-server token generate \
  -spiffeID spiffe://ztlab.local/openstack-agent
```

### HITL email chỉ hoạt động khi cấu hình SMTP

Nếu `SMTP_PASS` chưa được set trong secret `grafana-smtp-secret`, email sẽ bị skip (log `hitl_email_skip`). SOAR case vẫn lưu với status `pending_approval`, có thể approve thủ công qua API:

```bash
# Lấy case_id đang pending
curl http://localhost:8091/cases | python3 -c "
import sys,json
[print(c['case_id'], c['status'], c['severity']) for c in json.load(sys.stdin)
 if c['status']=='pending_approval']"

# Approve thủ công (cần token)
TOKEN=$(curl -s http://localhost:8091/health | python3 -c "import sys,json; print('no-token')")
curl "http://localhost:8091/cases/{case_id}/approve?token={hitl_token}"
```

---

## 17. Xử lý lỗi thường gặp

### Không đăng nhập được Web Portal — `invalid_redirect_uri`

Keycloak live thiếu `localhost:18081` trong redirectUris. Fix qua Admin API:

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=ztlab-admin-2026" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

CLIENT_ID=$(curl -s "http://localhost:8180/admin/realms/ztlab/clients?clientId=web-portal" \
  -H "Authorization: Bearer $TOKEN" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

curl -s -X PUT "http://localhost:8180/admin/realms/ztlab/clients/$CLIENT_ID" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"clientId":"web-portal","publicClient":true,"standardFlowEnabled":true,
       "attributes":{"pkce.code.challenge.method":"S256"},
       "redirectUris":["http://localhost:18081/*","http://127.0.0.1:18081/*",
                       "http://portal.ztlab.local/*","http://localhost:8080/*"],
       "webOrigins":["+"]}'
```

### Reset password user trong Keycloak

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=ztlab-admin-2026" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Lấy user ID
USER_ID=$(curl -s "http://localhost:8180/admin/realms/ztlab/users?username=testuser01" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

# Reset password
curl -X PUT "http://localhost:8180/admin/realms/ztlab/users/$USER_ID/reset-password" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"type":"password","value":"Test1234!","temporary":false}'
```

### API Gateway trả 403 cho mọi request dù token hợp lệ

OPA `valid_jwt` false do issuer URL sai. Kiểm tra `opa/policies/zta_policy.rego`:
```
jwt_payload.iss == "http://keycloak.ztlab.local:8180/realms/ztlab"
```
Sau khi sửa:
```bash
kubectl --context ctx-aws create configmap opa-policies \
  --from-file=opa/policies/ -n financial --dry-run=client -o yaml | \
  kubectl --context ctx-aws apply -f -
kubectl --context ctx-aws -n financial rollout restart deployment/api-gateway
```

### API Gateway trả `jwks_keys_loaded=0`

Keycloak chưa sẵn sàng khi api-gateway start. Restart:
```bash
kubectl --context ctx-aws -n financial rollout restart deployment/api-gateway
```

### Payment trả 503 — cross-cloud không hoạt động

1. Kiểm tra OpenStack VMs đang chạy:
```bash
source /etc/kolla/admin-openrc.sh && openstack server list
# Tất cả phải ACTIVE
```

2. Kiểm tra WireGuard tunnel:
```bash
ansible aws_gateway,os_gateway -i ansible/inventory/hosts.yml -m shell -a "wg show wg0"
# Hoặc: ssh -i ~/.ssh/ztlab-key ubuntu@52.221.255.36 "wg show"
```

3. Kiểm tra NodePorts OpenStack:
```bash
kubectl --context ctx-openstack get svc -n financial | grep -E "core-banking|account|transaction"
# Phải có: 15006:30080, 15006:30082, 15006:30083
```

4. Test TCP từ AWS pod đến OpenStack:
```bash
kubectl --context ctx-aws exec -n financial deployment/payment-service \
  -c payment-service -- python3 -c "
import socket
s=socket.socket(); s.settimeout(5)
try: s.connect(('192.168.101.11',30080)); print('30080 OK')
except Exception as e: print('30080 FAIL:', e)
"
```

### Payment trả 503 — SOAR đã auto-isolate service

SOAR có thể tự động chạy playbook `isolate_workload` khi phát hiện `lateral_movement` hoặc `fraud_gate_bypass`. Service bị isolate sẽ trả 503 (K8s Service selector không match pod nào).

Kiểm tra:
```bash
# Xem service bị isolate không
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.spec.selector}'
# Nếu có "soar.ztlab.io/isolated":"true" → bị isolate

# Xem SOAR case để hiểu lý do
curl http://localhost:8091/cases | python3 -c "
import sys,json
[print(c['case_id'], c['playbook'], c['target_workload'], c['status']) 
 for c in json.load(sys.stdin)]"

# Rollback (restore service)
curl -X POST http://localhost:8091/cases/{case_id}/rollback

# Hoặc patch thủ công nếu không có case_id
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

### Payment trả 403 — HMAC fail

```bash
# Kiểm tra secret tồn tại cả hai cluster
kubectl --context ctx-aws get secret core-banking-integrity-secret -n financial
kubectl --context ctx-openstack get secret core-banking-integrity-secret -n financial

# Nếu thiếu trên OpenStack:
SECRET=$(kubectl --context ctx-aws get secret core-banking-integrity-secret \
  -n financial -o jsonpath='{.data.CORE_BANKING_SHARED_SECRET}')
kubectl --context ctx-openstack create secret generic core-banking-integrity-secret \
  -n financial --from-literal=CORE_BANKING_SHARED_SECRET=$(echo $SECRET | base64 -d)
```

### SOAR pod không start (CrashLoopBackOff)

```bash
kubectl --context ctx-aws -n plg-stack describe pod -l app=soar-engine | tail -20
# Thường do secret redis-auth thiếu. Chạy lại:
bash scripts/deploy-all.sh   # idempotent
```

### K8s tunnel mất kết nối

```bash
bash scripts/k8s-tunnel.sh status
bash scripts/k8s-tunnel.sh down all && bash scripts/k8s-tunnel.sh up all
```

### SPIRE SVID hết hạn (lỗi mTLS sau ~1h)

```bash
# Restart SPIRE agent để renew SVIDs
kubectl --context ctx-aws rollout restart daemonset/spire-agent -n spire

# Sau đó restart các services để Envoy re-fetch SVID mới
kubectl --context ctx-aws -n financial rollout restart deployment
```

### SPIFFE_ID sai trong Envoy (lỗi "workload not authorized")

Nếu Envoy log báo "workload is not authorized for the requested identities":
```bash
# Kiểm tra SPIFFE_ID env var trong container envoy
kubectl --context ctx-aws exec -n financial <pod> -c envoy -- \
  cat /tmp/envoy.yaml | python3 -c "
import sys
for l in sys.stdin:
    if 'name: spiffe://' in l and 'ROOTCA' not in l:
        print(l.strip()); break"

# Nếu sai, sửa bằng:
kubectl --context ctx-aws set env deployment/<service> -n financial \
  "SPIFFE_ID=spiffe://ztlab.local/<prefix>/<service>"
```

SPIFFE IDs đúng theo NT114 Bảng 4.2:
- `aws/api-gateway` · `aws/payment-service` · `aws/fraud-detection` · `aws/notification-service`
- `openstack/core-banking` · `openstack/account-service` · `openstack/transaction-service`

---

*Hệ thống implement Zero Trust Architecture theo NIST SP 800-207: không có implicit trust, mọi request đều verify identity (JWT + SPIFFE SVID) và policy (OPA) trước khi được phép.*
