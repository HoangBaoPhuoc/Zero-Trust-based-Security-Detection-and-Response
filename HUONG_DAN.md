# ZTLab — Hướng Dẫn Vận Hành & Demo

**Zero Trust Security Detection and Response for Microservices in Multi-Cloud**  
Sinh viên: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
GVHD: ThS. Đỗ Thị Phương Uyên · Môn: NT114.Q21.ANTT

---

## Mục lục

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Hạ tầng & IP](#2-hạ-tầng--ip)
3. [Kết nối vào hệ thống](#3-kết-nối-vào-hệ-thống)
4. [Deploy lần đầu](#4-deploy-lần-đầu)
5. [Mở port-forwards (mỗi lần demo)](#5-mở-port-forwards-mỗi-lần-demo)
6. [Health check](#6-health-check)
7. [Tài khoản & credentials](#7-tài-khoản--credentials)
8. [Web Portal](#8-web-portal)
9. [Grafana — Dashboards & Alert Rules](#9-grafana--dashboards--alert-rules)
10. [AI Analyzer & SOAR Engine](#10-ai-analyzer--soar-engine)
11. [Grafana → SOAR tự động](#11-grafana--soar-tự-động)
12. [Chạy demo & quay video](#12-chạy-demo--quay-video)
13. [Kịch bản tấn công chi tiết](#13-kịch-bản-tấn-công-chi-tiết)
14. [Database Admin UIs](#14-database-admin-uis)
15. [Hạn chế đã biết](#15-hạn-chế-đã-biết)
16. [Xử lý lỗi thường gặp](#16-xử-lý-lỗi-thường-gặp)

---

## 1. Tổng quan kiến trúc

```
Internet  (HTTPS / PKCE OIDC)
    │
    ▼
┌─────────────────────────── AWS K3s ────────────────────────────────────┐
│  namespace: identity                                                    │
│    Keycloak  (realm=ztlab · port 8080)                                 │
│    SPIRE Server (trust domain=ztlab.local · SVID TTL=1h · CA=168h)    │
│                                                                         │
│  namespace: financial                                                   │
│    api-gateway  ──Envoy sidecar──► OPA ext_authz (gRPC 9191)          │
│    web-portal   ──PKCE──► Keycloak                                     │
│    payment-service ──SPIRE mTLS──► fraud-detection                    │
│    notification-service                                                 │
│    Redis  (DB0=fraud+blocklist · DB1=scorer · DB2=soar)                │
│                                                                         │
│  namespace: plg-stack                                                   │
│    Promtail (DaemonSet) → Loki → Grafana                               │
│    AI Analyzer  (poll Loki 30s → heuristic/OpenAI/Gemini)             │
│    SOAR Engine  (K8s SDK + Keycloak Admin API + Redis)                 │
│    Security Scorer  (anomaly score 15min window)                       │
│                                                                         │
│  namespace: monitoring                                                  │
│    Prometheus                                                           │
└────────────────────────────────────────────────────────────────────────┘
           │  WireGuard VPN (UDP 51820) · 10.200.0.0/24
           │  aws-gateway (10.200.0.1) ←→ os-gateway (10.200.0.2)
           │  cross-cloud NodePort 192.168.101.11:30080 đi qua WireGuard
           ▼
┌─────────────────── OpenStack K3s ──────────────────────────────────────┐
│  namespace: financial                                                   │
│    core-banking ──Envoy──► OPA   (xử lý transaction thực tế)          │
│    account-service  (PostgreSQL accounts_db · debit/credit)            │
│    transaction-service  (PostgreSQL transactions_db · ledger)          │
│    SPIRE Agent  (join_token attestor)                                  │
│                                                                         │
│  Lưu ý: core-banking, account-service, transaction-service             │
│  được buộc chạy trên os-k3s-master (nodeName) — xem mục 15            │
└────────────────────────────────────────────────────────────────────────┘
```

**Luồng payment chính:**
```
web-portal → api-gateway (JWT verify + OPA) → payment-service (HMAC sign)
  → fraud-detection (Redis velocity check)
  → core-banking/OpenStack (SPIRE mTLS, NodePort 192.168.101.11:30080)
  → account-service (debit/credit) → transaction-service (ledger)
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
- MASQUERADE rule trên aws nodes: `10.42.0.0/16 → 192.168.101.0/24` (pods AWS có thể route sang OS)

**Cross-cloud Envoy upstream:**
- payment-service Envoy → `192.168.101.11:30080` → core-banking pod (OS)

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

# Kiểm tra connectivity AWS → OpenStack
ansible aws_gateway -i ansible/inventory/hosts.yml -m shell \
  -a "ping -c 3 10.200.0.2"

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

## 4. Deploy lần đầu

Chỉ làm một lần khi hệ thống chưa có gì. Tunnel phải đang chạy.

### Bước 1 — Build & sync images

```bash
IMAGE_TAG=1.0.0 bash scripts/sync-financial-images.sh
```

Build 11 service images và copy vào containerd trên tất cả K3s nodes.

Services: `api-gateway`, `payment-service`, `fraud-detection`, `notification-service`, `core-banking`, `account-service`, `transaction-service`, `ai-analyzer`, `soar-engine`, `web-portal`, `security-scorer`

### Bước 2 — Deploy toàn bộ

```bash
export KEYCLOAK_ADMIN_PASSWORD=ztlab-admin-2026
bash scripts/deploy-all.sh
```

8 steps theo thứ tự: Namespaces → Images → Security stack (SPIRE/SPIFFE · OPA · Keycloak realm `ztlab`) → Financial infra → Financial workloads → PLG + AI/SOAR → Network policies + Ingress → Status check.

> Nếu muốn chạy riêng security stack trước: `KEYCLOAK_ADMIN_PASSWORD=ztlab-admin-2026 bash scripts/deploy-security-stack.sh`

### Bước 3 — Seed database (chạy sau deploy)

```bash
python3 tests/seed_db.py
```

Reset balances về baseline NT114: ACC-1001 = 1,000,000,000 VND · ACC-2001 = 250,000,000 VND.

---

## 5. Mở port-forwards (mỗi lần demo)

Chạy trong terminal riêng — **giữ terminal này mở suốt demo:**

```bash
bash scripts/open-admin-uis.sh
```

| Service | URL | Credentials |
|---------|-----|-------------|
| Keycloak | http://localhost:8180 | admin / ztlab-admin-2026 |
| API Gateway | http://localhost:18080 | — |
| Web Portal | http://localhost:18081 | xem mục 7 |
| Grafana | http://localhost:3000 | admin / ZTALab2026! |
| Loki | http://localhost:13100 | — |
| SOAR Engine | http://localhost:8091 | — |
| AI Analyzer | http://localhost:8090 | — |
| Security Scorer | http://localhost:18092 | — |
| Prometheus | http://localhost:9090 | — |
| pgAdmin | http://localhost:5050 | admin@ztlab.com / ztlab2026 |
| RedisInsight | http://localhost:5540 | xem mục 14 |

Nhấn **Ctrl+C** để đóng tất cả.

---

## 6. Health check

```bash
bash scripts/health-check.sh
```

Kiểm tra nhanh từng service:

```bash
curl http://localhost:18080/health    # api-gateway: {"jwks_keys_loaded": 2}
curl http://localhost:8090/health     # ai-analyzer: {"provider": "heuristic", "poll_enabled": true}
curl http://localhost:8091/health     # soar-engine: {"dry_run": false, "playbooks": [...]}
curl http://localhost:13100/ready     # loki: ready
curl http://localhost:3000/api/health # grafana: {"database": "ok"}
```

---

## 7. Tài khoản & credentials

### Keycloak — realm: ztlab

| Username | Password | Roles | Tài khoản ngân hàng |
|----------|----------|-------|---------------------|
| admin *(Keycloak)* | ztlab-admin-2026 | Keycloak superadmin | — |
| testuser01 | Test1234! | financial-read, financial-write | ACC-1001 (1,000,000,000 VND) |
| testuser02 | Test1234! | financial-read, financial-write | ACC-2001 (250,000,000 VND) |
| merchant01 | Test1234! | financial-read | ACC-4001 (26,750,000 VND) |
| analyst01 | Test1234! | security-analyst | ACC-5001 (10,000,000 VND) |

> **Lưu ý:** merchant01 chỉ có `financial-read` → POST /payments → HTTP 403 (dùng để demo RBAC).  
> analyst01 có `security-analyst` → xem được `/security` và `/monitor` nhưng không xem được accounts.

**Roles:**

| Role | Quyền |
|------|-------|
| `financial-read` | GET /accounts, GET /transactions |
| `financial-write` | + POST /payments |
| `security-analyst` | Xem SOAR cases, security monitor |
| `security-admin` | + Block IP, rollback playbook, approve HITL alerts |

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
| Redis | redis.financial:6379 | DB0/DB1/DB2 | — | ZTALab-Redis-2026! |

**Redis DB mapping:**
- DB0 — fraud velocity keys + IP blocklist
- DB1 — anomaly scorer 15min window
- DB2 — SOAR IP blocklist + case buffer

### SPIRE

- Trust domain: `ztlab.local`
- SVID TTL: 1h · CA TTL: 168h
- SPIFFE IDs: `spiffe://ztlab.local/aws/{service}` · `spiffe://ztlab.local/openstack/{service}`

---

## 8. Web Portal

**URL:** http://localhost:18081

### Trang & quyền

| Đường dẫn | Mô tả | Role yêu cầu |
|-----------|-------|-------------|
| `/login` | Đăng nhập OIDC/PKCE | Không |
| `/register` | Tạo tài khoản mới | Không |
| `/dashboard` | Số dư, lịch sử giao dịch | Đăng nhập |
| `/transfer` | Chuyển tiền | Đăng nhập |
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

## 9. Grafana — Dashboards & Alert Rules

**URL:** http://localhost:3000 · **Login:** admin / ZTALab2026!

### 6 Dashboards (folder: ZTLab)

| Dashboard | Mô tả |
|-----------|-------|
| ZTLab — Zero Trust Security Overview | Tổng quan OPA, JWT failures, fraud blocks |
| ZTLab Security Overview | Panels tóm tắt nhanh |
| ZTLab Full Logs | Toàn bộ Envoy access logs |
| Envoy Access Logs | HTTP matrix, latency P50/P95/P99 |
| OPA Decision Log | Allow/deny rate, top denied paths |
| ZTLab — Threat Intelligence Feed | IP blocklist, threat scoring timeline |

### 6 Alert Rules (folder: ZTLab)

| Alert | Severity | Trigger | SOAR playbook |
|-------|----------|---------|---------------|
| Kịch bản 1 — Brute Force Login Detected | high | 401 count by IP [1m] | revoke_user_sessions |
| Kịch bản 2 — Lateral Movement: Invalid SVID | critical | OPA deny invalid svid [5m] | isolate_workload |
| Kịch bản 3 — Fraud Gate Bypass | critical | OPA deny path=/transactions/execute | isolate_workload |
| Kịch bản 4 — Data Exfiltration Suspect | high | bytes_sent > 1MB từ OpenStack | restrict_egress |
| AI Analyzer Health | warning | ai-analyzer pod down > 2m | — (notify only) |
| SOAR Engine Health | warning | soar-engine pod down > 2m | — (notify only) |

**Notification:** tất cả alert `category=security` → webhook SOAR Engine (`/grafana-webhook`).

---

## 10. AI Analyzer & SOAR Engine

### AI Analyzer (http://localhost:8090)

```
Poll Loki mỗi 30s (lookback 90s)
  → Phân tích logs: heuristic → OpenAI GPT-4o-mini → Gemini 1.5 Flash (fallback)
  → severity ≥ high  → PendingAlert (HITL) → chờ admin approve
  → severity < high  → forward thẳng sang SOAR Engine
  → Sau khi approve → forward sang SOAR Engine
```

**Cấu hình AI provider** (Secret `ai-secrets`):
- `AI_PROVIDER=heuristic` — mặc định, không cần API key
- `AI_PROVIDER=gemini` + `GEMINI_API_KEY=...`
- `AI_PROVIDER=openai` + `OPENAI_API_KEY=...`

**HITL endpoints:**
```bash
curl http://localhost:8090/pending                          # xem pending alerts
curl -X POST http://localhost:8090/pending/{id}/approve    # approve
curl -X POST http://localhost:8090/pending/{id}/dismiss    # dismiss
```

### SOAR Engine (http://localhost:8091)

**5 Playbooks** (`SOAR_DRY_RUN=false` — thực thi thật):

| Playbook | Trigger | Hành động |
|----------|---------|-----------|
| `isolate_workload` | lateral_movement, fraud_gate_bypass | Patch Service selector → traffic dừng |
| `restrict_egress` | large_response | Scale Deployment → 0 replica |
| `quarantine_workload` | cryptomining | Scale Deployment → 0 replica |
| `block_source_ip` | port_scan, exploit_probe | Tạo NetworkPolicy chặn IP/32 + Redis blocklist 24h |
| `revoke_user_sessions` | brute_force, jwt_replay | Keycloak Admin API xóa session user |

**Endpoints:**
```bash
curl http://localhost:8091/cases                           # tất cả cases
curl http://localhost:8091/cases/{case_id}                # chi tiết
curl -X POST http://localhost:8091/cases/{id}/rollback    # restore workload
curl http://localhost:8091/blocked-ips                    # IPs bị block
curl -X POST http://localhost:8091/blocked-ips/1.2.3.4   # block thủ công
curl -X DELETE http://localhost:8091/blocked-ips/1.2.3.4 # unblock
curl http://localhost:8091/playbooks                      # danh sách playbooks
```

---

## 11. Grafana → SOAR tự động

Grafana alert fire → gọi trực tiếp SOAR Engine, không qua AI Analyzer:

```
Grafana alert rule fire (Loki query, interval 1m)
  → POST http://soar-engine.plg-stack:8080/grafana-webhook
  → SOAR đọc label attack_type từ payload
  → map sang playbook → thực thi
  → ghi SOAR case + log event grafana_soar_triggered
```

---

## 12. Chạy demo & quay video

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
| 2:30 | Web Portal /security (analyst01) | Cases list + SOAR action |
| 3:00 | Terminal | `python3 tests/scenario_04_fraud_gate_bypass.py` |
| 3:30 | Web Portal /monitor | All services UP |

### Sau demo — restore

```bash
# Xem cases
curl http://localhost:8091/cases | python3 -m json.tool

# Rollback workload bị isolate
curl -X POST http://localhost:8091/cases/{case_id}/rollback

# Restart toàn bộ financial services
kubectl --context ctx-aws -n financial rollout restart deployment
kubectl --context ctx-openstack -n financial rollout restart deployment

# Reset DB
python3 tests/seed_db.py
```

---

## 13. Kịch bản tấn công chi tiết

> Các scenario script dùng KC_URL mặc định là `http://localhost:18443`. Phải set đúng port `8180` khi chạy tay.

### Kịch bản 1 — Brute Force (T1110.001)

```bash
KC_URL=http://localhost:8180 bash tests/scenario_01_brute_force.sh
```

20 lần login sai → Grafana alert → SOAR `revoke_user_sessions`

### Kịch bản 2 — JWT Forgery (T1606)

```bash
KC_URL=http://localhost:8180 GW_URL=http://localhost:18080 python3 tests/scenario_02_jwt_forgery.py
```

JWT tự ký với algorithm=none → API Gateway từ chối (issuer sai)

### Kịch bản 3 — Lateral Movement (T1021.007)

```bash
GW_URL=http://localhost:18080 bash tests/scenario_03_lateral_movement.sh
```

Service dùng SPIFFE ID ngoài trust domain `ztlab.local` → Envoy/OPA deny → SOAR `isolate_workload`

### Kịch bản 4 — Fraud Gate Bypass (T1078)

```bash
KC_URL=http://localhost:8180 GW_URL=http://localhost:18080 python3 tests/scenario_04_fraud_gate_bypass.py
```

Gọi core-banking với `X-Fraud-Gate: passed` giả mạo (không qua fraud-detection) → OPA deny + Core Banking validate lại header

### Kịch bản 5 — High Velocity (T1190)

```bash
KC_URL=http://localhost:8180 GW_URL=http://localhost:18080 python3 tests/scenario_05_high_velocity.py
```

50 payment liên tiếp → fraud score tăng theo velocity → `review` → `block`

### Kịch bản 6 — Data Exfiltration (T1041)

```bash
KC_URL=http://localhost:8180 GW_URL=http://localhost:18080 python3 tests/scenario_06_exfiltration.py
```

Response bytes_sent lớn bất thường → AI Analyzer phát hiện `large_response` → SOAR `restrict_egress`

### Chạy toàn bộ test suite

```bash
KC_URL=http://localhost:8180 GW_URL=http://localhost:18080 python3 tests/scenario_00_full_suite.py
```

---

## 14. Database Admin UIs

### pgAdmin (http://localhost:5050)

Login: `admin@ztlab.com` / `ztlab2026`

Hai server pre-configured:
- **ZTLab Accounts** → postgres-accounts.financial:5432 · DB: accounts_db · accounts_user/accounts_pass
- **ZTLab Transactions** → postgres-txn.financial:5432 · DB: transactions_db · txn_user/txn_pass

### RedisInsight (http://localhost:5540)

Thêm connection lần đầu:
1. Click **Add Redis Database**
2. Host: `127.0.0.1` · Port: `6379`
3. Password: `ZTALab-Redis-2026!`

Mở thêm port-forward Redis:
```bash
kubectl --context ctx-aws port-forward -n financial svc/redis 6379:6379 --address=127.0.0.1 &
```

### Token nhanh để test API

```bash
bash scripts/gen-dev-token.sh testuser01    # financial-write
bash scripts/gen-dev-token.sh analyst01     # security-analyst
```

---

## 15. Hạn chế đã biết

### OS cross-node pod networking (kube-router)

Trên OpenStack K3s, kube-router ngăn cross-node pod-to-pod TCP dù đã mở UDP 8472 (Flannel VXLAN).

**Workaround áp dụng:** `core-banking`, `account-service`, `transaction-service` buộc chạy trên `os-k3s-master` via `spec.nodeName`.

```bash
# Kiểm tra pods chạy đúng node
kubectl --context ctx-openstack get pods -n financial -o wide | grep -E "core-banking|account-service|transaction-service"
# Tất cả phải trên NODE = os-k3s-master
```

Nếu pod di chuyển sang node khác sau restart (không có `nodeName`):
```bash
kubectl --context ctx-openstack patch deployment core-banking -n financial \
  --type='json' -p='[{"op":"add","path":"/spec/template/spec/nodeName","value":"os-k3s-master"}]'
```

### OS services dùng targetPort: 8080 (bypass Envoy/OPA)

Các service `account-service`, `transaction-service`, `core-banking` trên OpenStack có `targetPort: 8080` (trực tiếp tới app, không qua Envoy port 15006). Điều này là do OPA chặn plain HTTP call nội bộ giữa các services trong cluster OS (thiếu SVID cho intra-cluster calls).

Đây là hạn chế đã được ghi nhận trong báo cáo (§1.3.2): *"Account-service và transaction-service trên OpenStack chưa tích hợp Envoy sidecar do hạn chế tài nguyên."*

### SPIRE Agent trên OpenStack dùng join_token

SPIRE Agent phía OS dùng `join_token` attestation thay vì `k8s_psat`. Token cần được tạo lại nếu VM reboot:

```bash
# Tạo join token mới
kubectl --context ctx-aws exec -n spire statefulset/spire-server -- \
  /opt/spire/bin/spire-server token generate -spiffeID spiffe://ztlab.local/openstack-agent

# Apply token mới vào SPIRE Agent config trên OpenStack (xem spire/scripts/)
```

---

## 16. Xử lý lỗi thường gặp

### API Gateway trả 403 cho mọi request dù token hợp lệ

OPA `valid_jwt` false do issuer URL sai. Kiểm tra `opa/policies/zta_policy.rego`:
```
jwt_payload.iss == "http://keycloak.ztlab.local:8180/realms/ztlab"
```
Phải có `:8180`. Sau khi sửa, update ConfigMap:
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

1. Kiểm tra WireGuard:
```bash
ansible aws_gateway,os_gateway -i ansible/inventory/hosts.yml -m shell -a "wg show wg0"
```

2. Kiểm tra core-banking pod chạy đúng node:
```bash
kubectl --context ctx-openstack get pods -n financial -o wide | grep core-banking
# Cột NODE phải là os-k3s-master
```

3. Kiểm tra NodePort:
```bash
kubectl --context ctx-openstack get svc core-banking -n financial
# PORT(S) phải có 30080
```

### Payment trả 403 — fraud gate / HMAC fail

Kiểm tra secret `core-banking-integrity-secret` tồn tại trên cả hai cluster:
```bash
kubectl --context ctx-aws get secret core-banking-integrity-secret -n financial
kubectl --context ctx-openstack get secret core-banking-integrity-secret -n financial
```

Nếu thiếu trên OpenStack:
```bash
SECRET=$(kubectl --context ctx-aws get secret core-banking-integrity-secret \
  -n financial -o jsonpath='{.data.CORE_BANKING_SHARED_SECRET}')
kubectl --context ctx-openstack create secret generic core-banking-integrity-secret \
  -n financial --from-literal=CORE_BANKING_SHARED_SECRET=$(echo $SECRET | base64 -d)
```

### AI Analyzer không tạo alerts

Kiểm tra provider:
```bash
kubectl --context ctx-aws -n plg-stack get secret ai-secrets \
  -o jsonpath='{.data.AI_PROVIDER}' | base64 -d
```
Mặc định `heuristic` — hoạt động không cần API key. Nếu `gemini`/`openai` — kiểm tra API key.

### SOAR / AI Analyzer pod không start (CrashLoopBackOff)

```bash
kubectl --context ctx-aws -n plg-stack describe pod -l app=soar-engine | tail -20
```
Thường do secret thiếu. Chạy lại:
```bash
bash scripts/deploy-all.sh   # idempotent
```

### K8s tunnel mất kết nối

```bash
bash scripts/k8s-tunnel.sh status
bash scripts/k8s-tunnel.sh down all && bash scripts/k8s-tunnel.sh up all
```

### SPIRE SVID hết hạn (lỗi mTLS sau ~1h)

SPIRE Agent tự renew nếu đang chạy. Nếu agent bị restart:
```bash
kubectl --context ctx-aws rollout restart daemonset/spire-agent -n spire
kubectl --context ctx-openstack rollout restart daemonset/spire-agent -n spire
```

---

*Hệ thống implement Zero Trust Architecture theo NIST SP 800-207: không có implicit trust, mọi request đều verify identity (JWT + SPIFFE SVID) và policy (OPA) trước khi được phép.*
