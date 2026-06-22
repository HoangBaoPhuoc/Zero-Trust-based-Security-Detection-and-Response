# ZTLab — Hướng Dẫn Vận Hành & Demo

**Zero Trust Security Detection and Response for Microservices in Multi-Cloud**  
Sinh viên: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)

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
15. [Xử lý lỗi thường gặp](#15-xử-lý-lỗi-thường-gặp)

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
           │  cross-cloud (NodePort 30081)
           ▼
┌─────────────────── OpenStack K3s ──────────────────────────────────────┐
│  namespace: financial                                                   │
│    core-banking ──Envoy──► OPA   (xử lý transaction thực tế)          │
│    account-service  (PostgreSQL accounts_db · debit/credit)            │
│    transaction-service  (PostgreSQL transactions_db · ledger)          │
│    SPIRE Agent  (join_token attestor)                                  │
└────────────────────────────────────────────────────────────────────────┘
```

**Luồng payment chính:**
```
web-portal → api-gateway (JWT verify + OPA) → payment-service (HMAC sign)
  → fraud-detection (Redis velocity check) → core-banking/OpenStack (SPIRE mTLS + OPA)
  → account-service (debit/credit) → transaction-service (ledger)
```

---

## 2. Hạ tầng & IP

| Node | Private IP | Public IP | Vai trò |
|------|-----------|-----------|---------|
| aws_bastion | — | 52.221.255.36 | SSH jump host |
| aws_gateway | — | 13.213.245.227 | NAT gateway |
| aws_k3s_master | 10.10.1.10 | — | K8s control plane (AWS) |
| aws_k3s_worker_1 | 10.10.1.11 | — | K8s worker (AWS) |
| os_gateway | — | 10.10.10.188 | OpenStack floating IP |
| os_k3s_master | 10.10.1.12 | — | K8s control plane + worker (OpenStack) |

**K8s contexts:**
- `ctx-aws` → API server `127.0.0.1:6444` (qua SSH tunnel)
- `ctx-openstack` → API server `127.0.0.1:6445` (qua SSH tunnel)

**SSH key:** `~/.ssh/ztlab-key`

---

## 3. Kết nối vào hệ thống

### Bước 1 — Mở K8s API tunnel

```bash
bash scripts/k8s-tunnel.sh up all
```

Tunnel forward:
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

Build 11 service images (`ztlab/*:1.0.0`) và copy vào containerd trên tất cả K3s nodes qua Ansible.

Services: `api-gateway`, `payment-service`, `fraud-detection`, `notification-service`, `core-banking`, `account-service`, `transaction-service`, `ai-analyzer`, `soar-engine`, `web-portal`, `security-scorer`

### Bước 2 — Deploy security stack

```bash
KEYCLOAK_ADMIN_PASSWORD=ztlab-admin-2026 bash scripts/deploy-security-stack.sh
```

Deploy: SPIRE Server/Agent · OPA config · Keycloak realm `ztlab` với users/roles/clients · Envoy config.

### Bước 3 — Deploy toàn bộ

```bash
bash scripts/deploy-all.sh
```

8 steps theo thứ tự:
1. Namespaces (identity, financial, plg-stack, monitoring, spire)
2. Images (verify sync đã xong)
3. Security stack
4. Financial infrastructure (PostgreSQL, Redis, Secrets, pgAdmin, RedisInsight)
5. Financial workloads (api-gateway, payment, fraud-detection, notification, web-portal, security-scorer)
6. PLG + AI/SOAR (Loki, Grafana, Promtail, AI Analyzer, SOAR Engine, Prometheus)
7. Network policies + Ingress
8. Final status check

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
curl http://localhost:18080/health   # api-gateway: {"jwks_keys_loaded": 2}
curl http://localhost:8090/health    # ai-analyzer: {"provider": "heuristic", "poll_enabled": true}
curl http://localhost:8091/health    # soar-engine: {"dry_run": false, "playbooks": [...]}
curl http://localhost:13100/ready    # loki: ready
curl http://localhost:3000/api/health # grafana: {"database": "ok"}
```

---

## 7. Tài khoản & credentials

### Keycloak — realm: ztlab

| Username | Password | Roles | Dùng cho |
|----------|----------|-------|---------|
| admin *(Keycloak)* | ztlab-admin-2026 | Keycloak superadmin | Admin console |
| testuser01 | Test1234! | financial-read, financial-write | Demo payment chính |
| testuser02 | Test1234! | financial-read, financial-write | Demo multi-user |
| merchant01 | Merchant1234! | financial-read | Demo read-only |
| analyst01 | Analyst1234! | security-analyst | Demo monitoring |
| demoadmin | DemoAdmin2026! | tất cả 4 roles | Demo full access |

**Roles:**
| Role | Quyền |
|------|-------|
| `financial-read` | GET /accounts, GET /transactions |
| `financial-write` | + POST /payments, PUT |
| `security-analyst` | xem SOAR cases, Security Monitor |
| `security-admin` | + block IP, rollback playbook, approve HITL alerts |

**Tài khoản ngân hàng mặc định:** `ACC-1001` (testuser01) · `ACC-2001` (testuser02)

### Grafana
- **Login:** admin / ZTALab2026!

### Database

| DB | Internal host | DB name | User | Password |
|----|--------------|---------|------|---------|
| PostgreSQL accounts | postgres-accounts.financial:5432 | accounts_db | accounts_user | accounts_pass |
| PostgreSQL transactions | postgres-txn.financial:5432 | transactions_db | txn_user | txn_pass |
| Redis | redis.financial:6379 | DB0/DB1/DB2 | — | ZTALab-Redis-2026! |

**Redis DB mapping:**
- DB0 — fraud velocity keys + IP blocklist (fraud-detection, api-gateway)
- DB1 — anomaly scorer 15min window (security-scorer)
- DB2 — SOAR IP blocklist + case buffer (soar-engine)

### SPIRE
- Trust domain: `ztlab.local`
- SVID TTL: 1h · JWT SVID TTL: 5m · CA TTL: 168h
- SPIFFE IDs: `spiffe://ztlab.local/aws/{service}` · `spiffe://ztlab.local/openstack/{service}`

---

## 8. Web Portal

**URL:** http://localhost:18081

### Trang & quyền

| Đường dẫn | Mô tả | Role yêu cầu |
|-----------|-------|-------------|
| `/` | Landing page | Không |
| `/login` | Đăng nhập PKCE | Không |
| `/register` | Tạo tài khoản mới | Không |
| `/dashboard` | Số dư, lịch sử giao dịch | Đăng nhập |
| `/transfer` | Chuyển tiền | Đăng nhập |
| `/profile` | Thông tin tài khoản | Đăng nhập |
| `/admin` | Quản lý users & accounts | security-admin |
| `/scenarios` | Chạy kịch bản attack | security-analyst/admin |
| `/security` | SOAR cases, blocked IPs | security-analyst/admin |
| `/monitor` | System health tất cả services | security-analyst/admin |

### Login flow PKCE
1. `/login` → redirect Keycloak → đăng nhập → authorization code
2. web-portal exchange code → JWT token
3. Session lưu trong HMAC-signed cookie (stateless)

---

## 9. Grafana — Dashboards & Alert Rules

**URL:** http://localhost:3000 · **Login:** admin / ZTALab2026!

### 8 Dashboards (folder: ZTLab)

| Dashboard | UID | Panels |
|-----------|-----|--------|
| ZTLab AI SIEM SOAR | ztlab-ai-siem-soar | 9 |
| ZTLab SOAR Dashboard | ztlab-soar | 16 |
| ZTLab — Zero Trust Security Overview | ztlab-security-v2 | 19 |
| ZTLab — Threat Intelligence Feed | ztlab-threat-intel | 10 |
| ZTLab Full Logs | ztlab-full-logs | 11 |
| ZTLab Security Overview | ztlab-security-overview | 5 |
| Envoy Access Logs | ztlab-envoy-access-logs | 4 |
| OPA Decision Log | ztlab-opa-decision-log | 3 |

### 8 Alert Rules (folder: ZTLab)

| Alert | Severity | Loki query | SOAR playbook |
|-------|----------|-----------|---------------|
| Kịch bản 1 — Brute Force | high | 401 count by source_ip [1m] | revoke_user_sessions |
| Kịch bản 2 — Lateral Movement | critical | opa_result=false [5m] | isolate_workload |
| Kịch bản 3 — Fraud Gate Bypass | critical | opa_result=false, path=/transactions/execute | isolate_workload |
| Kịch bản 4 — Data Exfiltration | high | bytes_sent > 1MB, cloud=openstack | restrict_egress |
| Anomaly Score ≥ 70 | critical | ztlab_anomaly_score metric | monitor_only |
| Anomaly Score ≥ 40 | high | ztlab_anomaly_score metric | monitor_only |
| Nhiều Fraud Block | high | fraud block count | monitor_only |
| SOAR Action Recorded | info | soar_action log | — |

**Notification:** tất cả alert `category=security` → webhook SOAR Engine + email admin.

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

**5 Playbooks** (thực thi thật, `SOAR_DRY_RUN=false`):

| Playbook | Trigger | Hành động K8s/Keycloak |
|----------|---------|----------------------|
| `isolate_workload` | lateral_movement, fraud_gate_bypass | Patch Service selector → traffic dừng, pod giữ nguyên |
| `restrict_egress` | large_response | Scale Deployment → 0 replica |
| `quarantine_workload` | cryptomining | Scale Deployment → 0 replica |
| `block_source_ip` | port_scan, exploit_probe, access_denied | Tạo NetworkPolicy chặn IP/32 + Redis blocklist 24h |
| `revoke_user_sessions` | brute_force, jwt_replay | Keycloak Admin API xóa session user |

**4-phase execution:** `contain → investigate → eradicate → recover`

**Endpoints:**
```bash
curl http://localhost:8091/cases                          # tất cả cases
curl http://localhost:8091/cases/{case_id}               # chi tiết
curl -X POST http://localhost:8091/cases/{id}/rollback   # restore workload
curl http://localhost:8091/blocked-ips                   # danh sách IPs bị block
curl -X POST http://localhost:8091/blocked-ips/1.2.3.4  # block thủ công
curl -X DELETE http://localhost:8091/blocked-ips/1.2.3.4 # unblock
curl http://localhost:8091/playbooks                     # danh sách playbooks
```

---

## 11. Grafana → SOAR tự động

Grafana alert fire → gọi trực tiếp SOAR Engine, không qua AI Analyzer:

```
Grafana alert rule fire (Loki query, interval 1m)
  → POST http://soar-engine.plg-stack:8080/grafana-webhook
  → SOAR đọc label attack_type từ payload
  → map sang playbook → thực thi 4 phases
  → ghi SOAR case + log event grafana_soar_triggered
  → (song song) gửi email cho admin
```

Mapping labels trong alert rules:

| Alert | Label `attack_type` | Playbook |
|-------|---------------------|---------|
| Brute Force | brute_force | revoke_user_sessions |
| Lateral Movement | lateral_movement | isolate_workload |
| Fraud Gate Bypass | fraud_gate_bypass | isolate_workload |
| Data Exfiltration | large_response | restrict_egress |

---

## 12. Chạy demo & quay video

### Chuẩn bị

```bash
# Terminal 1 — giữ mở
bash scripts/k8s-tunnel.sh up all

# Terminal 2 — giữ mở
bash scripts/open-admin-uis.sh
```

Mở sẵn 5 tab trình duyệt:

| Tab | URL | Mục đích |
|-----|-----|---------|
| 1 | http://localhost:18081 | Web Portal (đăng nhập demoadmin / DemoAdmin2026!) |
| 2 | http://localhost:3000/d/ztlab-ai-siem-soar | Grafana AI SIEM SOAR |
| 3 | http://localhost:3000/d/ztlab-soar | Grafana SOAR Dashboard |
| 4 | http://localhost:18081/security | SOAR cases + blocked IPs |
| 5 | http://localhost:18081/monitor | System health |

### Chạy demo

```bash
# Full demo: normal traffic + 5 attack scenarios
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
| 0:00 | Web Portal /dashboard | testuser01 chuyển tiền bình thường |
| 0:30 | Grafana Full Logs | Envoy access logs xuất hiện real-time |
| 1:00 | Terminal | Chạy `--brute-force --attack-only` |
| 1:30 | Grafana Alerting | Alert "Brute Force" chuyển → Firing |
| 2:00 | Grafana SOAR Dashboard | SOAR case mới, playbook=revoke_user_sessions |
| 2:30 | Web Portal /security | Cases list + blocked IPs |
| 3:00 | Web Portal /monitor | All services UP |
| 3:30 | SOAR Engine API | `curl localhost:8091/cases` |

### Sau demo — restore

```bash
# Xem cases để lấy case_id
curl http://localhost:8091/cases | python3 -m json.tool

# Rollback workload bị isolate
curl -X POST http://localhost:8091/cases/{case_id}/rollback

# Hoặc restart toàn bộ
kubectl --context ctx-aws -n financial rollout restart deployment
kubectl --context ctx-openstack -n financial rollout restart deployment
```

---

## 13. Kịch bản tấn công chi tiết

### Kịch bản 1 — Brute Force (T1110.001)

```bash
bash scripts/run-demo.sh --brute-force --attack-only
# hoặc
bash tests/scenario_01_brute_force.sh
```

10 lần login sai → Grafana alert (1min) → SOAR `revoke_user_sessions`

### Kịch bản 2 — JWT Forgery (T1606)

```bash
python3 tests/scenario_02_jwt_forgery.py
```

Tạo JWT tự ký để bypass OPA → OPA từ chối do issuer sai

### Kịch bản 3 — Lateral Movement (T1021.007)

```bash
bash tests/scenario_03_lateral_movement.sh
```

Service dùng SPIFFE ID không đúng → Envoy/OPA deny → Grafana alert → SOAR `isolate_workload`

### Kịch bản 4 — Fraud Gate Bypass (T1078.004) — Gap 2

```bash
python3 tests/scenario_04_fraud_gate_bypass.py
```

payment-service gọi core-banking thiếu header `X-Fraud-Score` → OPA deny → SOAR `isolate_workload`

### Kịch bản 5 — High Velocity (T1190)

```bash
python3 tests/scenario_05_high_velocity.py
```

Nhiều payment liên tiếp → Security Scorer tăng anomaly score → Grafana alert

### Kịch bản 4b — Data Exfiltration (T1041) — Gap 1

```bash
bash scripts/run-demo.sh --attack-only
# (script push synthetic log: bytes_sent=2.5MB từ core-banking)
```

Response > 1MB từ OpenStack Envoy → Grafana alert → SOAR `restrict_egress`

### Chạy toàn bộ test suite

```bash
python3 tests/scenario_00_full_suite.py
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

Cần mở thêm port-forward Redis:
```bash
kubectl --context ctx-aws port-forward -n financial svc/redis 6379:6379 --address=127.0.0.1 &
```

### Token nhanh để test API

```bash
bash scripts/gen-dev-token.sh testuser01        # financial-write
bash scripts/gen-dev-token.sh demoadmin         # tất cả roles
```

---

## 15. Xử lý lỗi thường gặp

### API Gateway trả 403 cho mọi request dù token hợp lệ

OPA `valid_jwt` luôn false do issuer URL sai. Kiểm tra `opa/policies/zta_policy.rego`:
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

### SOAR / AI Analyzer pod không start (CrashLoopBackOff)

Kiểm tra events:
```bash
kubectl --context ctx-aws -n plg-stack describe pod -l app=soar-engine | tail -20
```
Thường do secret thiếu. Chạy lại deploy:
```bash
bash scripts/deploy-all.sh   # idempotent
```

### AI Analyzer không tạo alerts

Kiểm tra provider:
```bash
kubectl --context ctx-aws -n plg-stack get secret ai-secrets \
  -o jsonpath='{.data.AI_PROVIDER}' | base64 -d
```
Mặc định `heuristic` — hoạt động không cần API key. Nếu `gemini`/`openai` — kiểm tra API key.

### K8s tunnel mất kết nối

```bash
bash scripts/k8s-tunnel.sh status
bash scripts/k8s-tunnel.sh down all
bash scripts/k8s-tunnel.sh up all
```

### SPIRE SVID hết hạn (lỗi mTLS sau ~1h)

SPIRE Agent tự renew nếu đang chạy. Nếu agent bị restart:
```bash
kubectl --context ctx-aws rollout restart daemonset/spire-agent -n spire
kubectl --context ctx-openstack rollout restart daemonset/spire-agent -n spire
```

### Port-forward bị ngắt

```bash
bash scripts/open-admin-uis.sh
```

---

*Hệ thống implement Zero Trust Architecture theo NIST SP 800-207: không có implicit trust, mọi request đều verify identity (JWT + SPIFFE SVID) và policy (OPA) trước khi được phép.*
