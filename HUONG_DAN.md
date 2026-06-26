# ZTLab — Hướng Dẫn Vận Hành & Demo

**Zero Trust Security Detection and Response for Microservices in Multi-Cloud**  
Sinh viên: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
GVHD: ThS. Đỗ Thị Phương Uyên · Môn: NT114.Q21.ANTT

---

## Mục lục

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Hạ tầng & địa chỉ IP](#2-hạ-tầng--địa-chỉ-ip)
3. [Khởi động hệ thống](#3-khởi-động-hệ-thống)
4. [Deploy lần đầu](#4-deploy-lần-đầu)
5. [Tài khoản & credentials](#5-tài-khoản--credentials)
6. [Truy cập các UI](#6-truy-cập-các-ui)
7. [Health check nhanh](#7-health-check-nhanh)
8. [Demo 4 kịch bản tấn công](#8-demo-4-kịch-bản-tấn-công)
9. [SOAR Engine](#9-soar-engine)
10. [Grafana — Dashboards & Alerts](#10-grafana--dashboards--alerts)
11. [OPA — Chính sách Zero Trust](#11-opa--chính-sách-zero-trust)
12. [Xử lý sự cố](#12-xử-lý-sự-cố)

---

## 1. Tổng quan kiến trúc

```
                           Browser / Client
                                  │
                                  ▼
┌─────────────────── AWS K3s  (ctx-aws) ──────────────────────────────────┐
│ namespace: identity                                                      │
│   Keycloak   realm=ztlab · PKCE/OIDC · port 8080                       │
│   SPIRE Server   trust domain=ztlab.local · SVID TTL=1h                │
│                                                                          │
│ namespace: financial                                                     │
│   web-portal      (Jinja2 UI + Keycloak SSO proxy)                     │
│   api-gateway     spiffe://ztlab.local/aws/api-gateway                  │
│   payment-service spiffe://ztlab.local/aws/payment-service              │
│   fraud-detection spiffe://ztlab.local/aws/fraud-detection              │
│   OPA             ext_authz gRPC port 9191                              │
│   Redis · PostgreSQL accounts · PostgreSQL transactions                 │
│                                                                          │
│ namespace: plg-stack                                                     │
│   Promtail (DaemonSet) → Loki (90 ngày) → Grafana                      │
│   SOAR Engine   (Grafana webhook → K8s playbook tự động)               │
│   Security Scorer   (anomaly window 15 phút · Redis)                   │
│                                                                          │
│ namespace: monitoring                                                    │
│   Prometheus  (10 targets: AWS + OpenStack)                             │
└─────────────────────────┬───────────────────────────────────────────────┘
                          │  WireGuard VPN  10.200.0.1 ↔ 10.200.0.2
                          │  Envoy mTLS · SPIFFE SVID
                          ▼
┌──────────── OpenStack K3s  (ctx-openstack) ─────────────────────────────┐
│ namespace: financial                                                     │
│   core-banking      spiffe://ztlab.local/openstack/core-banking         │
│     NodePort mTLS=30080 · HTTP=30084                                    │
│   account-service   spiffe://ztlab.local/openstack/account-service      │
│     NodePort mTLS=30082 · HTTP=30086                                    │
│   transaction-svc   spiffe://ztlab.local/openstack/transaction-service  │
│     NodePort mTLS=30083 · HTTP=30087                                    │
│   OPA · Redis · PostgreSQL · pgAdmin · RedisInsight                     │
│                                                                          │
│ namespace: plg-stack                                                     │
│   Promtail → socat 10.10.10.1:13099 → Loki (AWS)                       │
└─────────────────────────────────────────────────────────────────────────┘
```

### Luồng thanh toán (cross-cloud, Gap 2)

```
Browser
  → web-portal (PKCE session)
  → api-gateway (JWT verify + OPA authz)
  → payment-service (HMAC sign + gọi fraud-detection)
  → fraud-detection (Redis velocity → score=5 → gate=passed)
  → core-banking [OpenStack] (SPIFFE mTLS + OPA: yêu cầu x-fraud-gate)
  → account-service [OpenStack] (debit/credit)
  → transaction-service [OpenStack] (ghi ledger)
```

### Luồng phát hiện & phản ứng tự động

```
Grafana alert fire (Loki count_over_time query, eval 1 phút)
  → POST soar-engine/grafana-webhook
  → SOAR parse attack_type từ label alert
  → severity ≥ medium + auto_execute=true
  → chạy playbook ngay (isolate / block / restrict / revoke)
  → ghi case vào Redis + file
```

---

## 2. Hạ tầng & địa chỉ IP

| Node | IP Private | IP Public | Vai trò |
|------|-----------|-----------|---------|
| aws_bastion | — | 52.221.255.36 | SSH jump host |
| aws_gateway | 10.10.0.x · WG 10.200.0.1 | 13.213.245.227 | NAT + WireGuard |
| aws_k3s_master | 10.10.1.10 | — | K8s control plane AWS |
| aws_k3s_worker_1 | 10.10.1.11 | — | K8s worker AWS |
| os_gateway | — · WG 10.200.0.2 | 10.10.10.188 | WireGuard client |
| os_k3s_master | 192.168.101.11 | — | K8s master OpenStack |
| deployer (máy này) | 10.10.10.1 (br-exnat) | — | Bastion + Loki proxy |

**K8s contexts:**
- `ctx-aws` → `127.0.0.1:6444` (SSH tunnel qua bastion)
- `ctx-openstack` → `127.0.0.1:6445` (SSH tunnel qua os_gateway)

**SSH key:** `~/.ssh/ztlab-key`

---

## 3. Khởi động hệ thống

> Làm đúng thứ tự này sau mỗi khi reboot máy deployer hoặc mở session mới.

### Bước 1 — Bật OpenStack VMs

```bash
source /etc/kolla/admin-openrc.sh
openstack server list
```

Nếu có VM nào `SHUTOFF`:
```bash
openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2
# Đợi ~30 giây để VMs boot
```

### Bước 2 — Mở K8s tunnels

```bash
bash scripts/k8s-tunnel.sh up all
```

Kiểm tra:
```bash
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

### Bước 3 — Kiểm tra pods

```bash
# Chỉ show pod không Running
kubectl --context ctx-aws get pods -A | grep -v "Running\|Completed"
kubectl --context ctx-openstack get pods -A | grep -v "Running\|Completed"
```

Nếu có pod CrashLoop/Error:
```bash
kubectl --context ctx-aws rollout restart deployment/<tên> -n <namespace>
```

### Bước 4 — Mở port-forwards

```bash
bash scripts/open-admin-uis.sh
```

Chạy daemon tự-restart, không cần giữ terminal. Kiểm tra: `bash scripts/open-admin-uis.sh status`

### Bước 5 — Kiểm tra payment-service chưa bị SOAR isolate

```bash
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.spec.selector}' && echo
# Phải là: {"app":"payment-service"}
```

Nếu có `soar.ztlab.io/isolated`:
```bash
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

### Checklist nhanh (copy-paste)

```bash
# 1. OpenStack VMs
source /etc/kolla/admin-openrc.sh && openstack server list
# Nếu SHUTOFF: openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2

# 2. Tunnels
bash scripts/k8s-tunnel.sh up all

# 3. Xác nhận nodes
kubectl --context ctx-aws get nodes && kubectl --context ctx-openstack get nodes

# 4. Port-forwards
bash scripts/open-admin-uis.sh

# 5. Kiểm tra payment-service
kubectl --context ctx-aws get svc payment-service -n financial -o jsonpath='{.spec.selector}'
# Phải là: {"app":"payment-service"}
```

> **Sau reboot AWS VM:** pods tự restart theo K3s/systemd, chỉ làm lại bước 2 + 4.  
> **Sau reboot OpenStack VM:** VMs tắt — phải bật lại (bước 1) trước khi mở tunnel.

---

## 4. Deploy lần đầu

Chỉ làm một lần khi cluster chưa có gì. Tunnel phải đang chạy trước.

```bash
# Build và sync tất cả images vào K3s nodes
IMAGE_TAG=1.0.0 bash scripts/sync-financial-images.sh

# Deploy toàn bộ hệ thống (idempotent)
export KEYCLOAK_ADMIN_PASSWORD=ztlab-admin-2026
bash scripts/deploy-all.sh

# Seed dữ liệu database
python3 tests/seed_db.py
# ACC-1001 = 1,000,000,000 VND · ACC-2001 = 250,000,000 VND

# Mở port-forwards
bash scripts/open-admin-uis.sh
```

---

## 5. Tài khoản & credentials

### Keycloak — realm: ztlab

| Username | Password | Role | Tài khoản ngân hàng |
|----------|----------|------|---------------------|
| admin | ztlab-admin-2026 | Keycloak superadmin | — |
| testuser01 | Test1234! | financial-read, financial-write | ACC-1001 (1,000,000,000 VND) |
| testuser02 | Test1234! | financial-read, financial-write | ACC-2001 (250,000,000 VND) |
| merchant01 | Test1234! | financial-read | ACC-4001 |
| analyst01 | Test1234! | security-analyst | ACC-5001 |

> **merchant01** chỉ có `financial-read` → POST /payments → 403 (demo RBAC).  
> **analyst01** xem được `/security` và `/monitor` nhưng không chuyển tiền.

### Grafana

| URL | Login |
|-----|-------|
| http://localhost:3000 | admin / ZTALab2026! |

### Database

| Thành phần | Internal host | User / Pass |
|-----------|--------------|-------------|
| PostgreSQL accounts | postgres-accounts.financial:5432 | accounts_user / accounts_pass |
| PostgreSQL transactions | postgres-txn.financial:5432 | txn_user / txn_pass |
| Redis | redis.financial:6379 | — / ZTALab-Redis-2026! |
| pgAdmin | http://localhost:5050 | admin@ztlab.com / ztlab2026 |

**Redis DB mapping:**
- **DB0** — fraud velocity + IP blocklist (SOAR `block_source_ip`)
- **DB1** — security-scorer anomaly window 15 phút

### SPIRE

- Trust domain: `ztlab.local` · SVID TTL: 1h · CA TTL: 168h
- AWS: `spiffe://ztlab.local/aws/{api-gateway · payment-service · fraud-detection · notification-service}`
- OpenStack: `spiffe://ztlab.local/openstack/{core-banking · account-service · transaction-service}`

---

## 6. Truy cập các UI

```bash
bash scripts/open-admin-uis.sh   # khởi động tất cả daemon
```

| Service | URL | Đăng nhập |
|---------|-----|-----------|
| Web Portal | http://localhost:18081 | testuser01 / Test1234! (qua Keycloak SSO) |
| API Gateway | http://localhost:18080 | — (cần Bearer JWT) |
| Keycloak Admin | http://localhost:8180 | admin / ztlab-admin-2026 |
| Grafana | http://localhost:3000 | admin / ZTALab2026! |
| Prometheus | http://localhost:9090 | — |
| SOAR Engine | http://localhost:8091 | — |
| Security Scorer | http://localhost:18092 | — |
| Loki | http://localhost:13100 | — |
| pgAdmin | http://localhost:5050 | admin@ztlab.com / ztlab2026 |
| RedisInsight | http://localhost:5540 | — |

### Web Portal — các trang chính

| Trang | Mô tả | Role yêu cầu |
|-------|-------|-------------|
| `/login` | Đăng nhập OIDC/PKCE qua Keycloak | — |
| `/dashboard` | Số dư, lịch sử giao dịch | Đăng nhập |
| `/transfer` | Chuyển tiền | financial-write |
| `/scenarios` | Trigger kịch bản attack từ UI | Đăng nhập |
| `/security` | SOAR cases, blocked IPs | security-analyst |
| `/monitor` | System health | security-analyst |
| `/admin` | Quản lý users & accounts | security-admin |

**Login flow:** `/login` → click "Đăng nhập với Keycloak SSO" → Keycloak (proxied qua `/kc/`) → callback → `/dashboard`.

---

## 7. Health check nhanh

```bash
# Tất cả services
curl -s http://localhost:18081/health   # web-portal
curl -s http://localhost:18080/health   # api-gateway: jwks_keys_loaded≥1
curl -s http://localhost:8091/health    # soar-engine: dry_run=false, auto_execute=true
curl -s http://localhost:3000/api/health  # grafana: database=ok
curl -s http://localhost:13100/ready    # loki: ready
curl -s http://localhost:9090/-/healthy # prometheus

# Prometheus targets (phải 10/10 UP)
curl -s http://localhost:9090/api/v1/targets | python3 -c "
import sys,json; d=json.load(sys.stdin)
t=d['data']['activeTargets']
print('Targets UP:', sum(1 for x in t if x['health']=='up'), '/', len(t))"

# E2E payment test
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234!&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1}' \
  | python3 -m json.tool
# Kỳ vọng: status=completed, fraud.gate=passed
```

---

## 8. Demo 4 kịch bản tấn công

### Chuẩn bị trước mỗi lần demo

```bash
# 1. Reset số dư về baseline
python3 tests/seed_db.py

# 2. Xác nhận payment-service không bị isolate
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.spec.selector}' && echo
# Phải là: {"app":"payment-service"}

# 3. Xác nhận không có service nào bị scale=0
kubectl --context ctx-aws get deployment -n financial \
  --no-headers | awk '{print $1, $2, $3}'
```

Mở sẵn 4 tab trình duyệt:

| Tab | URL | Mục đích |
|-----|-----|---------|
| 1 | http://localhost:18081 | Web Portal — testuser01 |
| 2 | http://localhost:3000/d/siem-soar-ztlab | Grafana SIEM SOAR dashboard |
| 3 | http://localhost:3000/alerting/list | Grafana Alert Rules |
| 4 | http://localhost:18081/security | SOAR Cases — analyst01 |

---

### Kịch bản 1 — Brute Force Login (T1110.001)

```bash
bash tests/scenario_01_brute_force.sh
# Hoặc Web Portal: /scenarios → "Brute Force"
```

**Chuỗi sự kiện:**
1. 20 lần login sai liên tiếp với testuser01 → Keycloak trả 401
2. Envoy access log: 401 tích lũy trong Loki `job=envoy-access`
3. Grafana alert "Kịch bản 1 — Brute Force" → FIRING (count 401 [1m] > ngưỡng)
4. SOAR: `attack_type=brute_force` → playbook `revoke_user_sessions`
5. Keycloak Admin API xóa tất cả session của testuser01
6. Xem case: http://localhost:18081/security hoặc `curl http://localhost:8091/cases`

**Verify:** `curl http://localhost:8091/cases | python3 -c "import sys,json; [print(c['ts'][:19], c['playbook'], c['status']) for c in json.load(sys.stdin) if c.get('attack_type')=='brute_force']"`

---

### Kịch bản 2 — Lateral Movement (T1021.007)

```bash
bash tests/scenario_03_lateral_movement.sh
# Hoặc Web Portal: /scenarios → "Lateral Movement"
```

**Chuỗi sự kiện:**
1. Request đến Envoy không có SPIFFE SVID hợp lệ (ngoài trust domain `ztlab.local`)
2. OPA: `valid_svid=false` → `allow=false` → ghi decision log
3. Promtail extract `opa_result=false` → Loki
4. Grafana alert "Kịch bản 2 — Lateral Movement" → FIRING
5. SOAR: `attack_type=lateral_movement` → playbook `isolate_workload`
6. K8s Service selector của payment-service bị patch → pod không nhận traffic

**Restore sau demo:**
```bash
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
# Hoặc: curl -X POST http://localhost:8091/cases/{case_id}/rollback
```

---

### Kịch bản 3 — Fraud Gate Bypass (T1078.004) — Gap 2

```bash
python3 tests/scenario_04_fraud_gate_bypass.py
# Hoặc Web Portal: /scenarios → "Fraud Gate Bypass"
```

**Chuỗi sự kiện:**
1. Gọi trực tiếp `POST /transactions/execute` trên core-banking không có `x-fraud-gate: passed`
2. OPA (OpenStack): path `/transactions/execute` → yêu cầu `fraud_gate_valid` → header thiếu → DENY
3. Promtail: `opa_result=false`, `request_path=/transactions/execute` → Loki
4. Grafana alert "Kịch bản 3 — Fraud Gate Bypass" → FIRING
5. SOAR: `attack_type=fraud_gate_bypass` → playbook `isolate_workload` trên payment-service

**OPA fraud gate logic (Gap 2):**

| Request | Kết quả |
|---------|---------|
| POST /transactions/execute, không có header | **DENY** |
| POST /transactions/execute, x-fraud-gate=passed, x-fraud-score=5 | ALLOW |
| POST /transactions/execute, x-fraud-gate=passed, x-fraud-score=80 | **DENY** (score ≥ 75) |
| POST /transactions/* (không phải /execute), có SVID | ALLOW |

**Restore sau demo:**
```bash
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

---

### Kịch bản 4 — Data Exfiltration (T1041) — Gap 1

```bash
python3 tests/scenario_06_exfiltration.py
# Hoặc Web Portal: /scenarios → "Data Exfiltration"
```

**Chuỗi sự kiện:**
1. Response từ core-banking có `bytes_sent > 1,048,576` (1 MB)
2. Envoy access log → Loki `job=envoy-access`
3. Grafana alert "Kịch bản 4 — Data Exfiltration Suspect" → FIRING
4. SOAR: `attack_type=large_response` → playbook `restrict_egress`
5. Deployment api-gateway scale xuống 0 replica

**Restore sau demo:**
```bash
kubectl --context ctx-aws scale deployment api-gateway -n financial --replicas=1
```

---

### Restore toàn bộ sau demo

```bash
# Restore payment-service nếu bị isolate
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'

# Restore api-gateway nếu bị scale=0
kubectl --context ctx-aws scale deployment api-gateway -n financial --replicas=1

# Xóa blocked IPs (nếu có)
curl -s http://localhost:8091/blocked-ips | python3 -c "
import sys,json
d=json.load(sys.stdin)
for ip in d.get('blocked_ips',[]):
    print('unblocking:', ip)"
# curl -X DELETE http://localhost:8091/blocked-ips/{ip}

# Reset số dư
python3 tests/seed_db.py
```

---

## 9. SOAR Engine

**URL:** http://localhost:8091  
**Config hiện tại:** `auto_execute=true` · `min_severity=medium` · `dry_run=false`

### 5 Playbooks

| Playbook | Trigger (attack_type) | Hành động K8s |
|----------|----------------------|--------------|
| `isolate_workload` | lateral_movement, fraud_gate_bypass | Patch Service selector → pod không nhận traffic |
| `restrict_egress` | large_response | Scale Deployment → 0 replica |
| `quarantine_workload` | cryptomining | Scale Deployment → 0 replica |
| `block_source_ip` | port_scan, exploit_probe, access_denied | Tạo NetworkPolicy + Redis DB0 blocklist 24h |
| `revoke_user_sessions` | brute_force, jwt_replay, credential_stuffing | Keycloak Admin API xóa session |

### Attack type → Playbook → Target

| attack_type | Playbook | Target |
|-------------|---------|--------|
| fraud_gate_bypass | isolate_workload | payment-service |
| lateral_movement | isolate_workload | payment-service |
| large_response | restrict_egress | api-gateway |
| brute_force | revoke_user_sessions | api-gateway |
| access_denied | block_source_ip | api-gateway |
| port_scan | block_source_ip | api-gateway |
| jwt_replay | revoke_user_sessions | api-gateway |

### API endpoints

```bash
curl http://localhost:8091/health                           # trạng thái + case count
curl http://localhost:8091/cases                            # tất cả cases
curl http://localhost:8091/cases/{case_id}                 # chi tiết 1 case
curl -X POST http://localhost:8091/cases/{case_id}/rollback  # restore workload
curl http://localhost:8091/blocked-ips                      # IPs đang bị block
curl -X POST http://localhost:8091/blocked-ips/1.2.3.4     # block thủ công
curl -X DELETE http://localhost:8091/blocked-ips/1.2.3.4   # unblock
curl http://localhost:8091/playbooks                        # danh sách playbooks
```

### Lưu ý

- Grafana `repeat_interval=1h` — cùng 1 alert không gửi lại SOAR trong 1 giờ
- Sau khi `isolate_workload` chạy, payment-service trả **503** → phải restore trước khi test tiếp
- SOAR lưu cases vào `/data/cases.jsonl` (PersistentVolume) và Redis — không mất khi pod restart

---

## 10. Grafana — Dashboards & Alerts

**URL:** http://localhost:3000 · Login: admin / ZTALab2026!  
**Log retention:** 90 ngày (Loki)

### 6 Dashboards (folder: ZTLab)

| Dashboard | UID | Mô tả |
|-----------|-----|-------|
| ZTLab — Zero Trust Security Overview | ztlab-security-v2 | OPA allow/deny rate, JWT failures, fraud |
| ZTLab Security Overview | ztlab-security-overview | Panels tóm tắt |
| ZTLab Full Logs | ztlab-full-logs | Envoy access logs toàn bộ |
| Envoy Access Logs | ztlab-envoy-access-logs | HTTP matrix, latency P50/P95/P99 |
| OPA Decision Log | ztlab-opa-decision-log | Allow/deny rate, top denied paths |
| SIEM SOAR | siem-soar-ztlab | Cases, playbooks, IPs blocked, log stream |

### 6 Alert Rules (folder: ZTLab)

| Alert | Severity | Loki query | attack_type | Playbook |
|-------|----------|-----------|-------------|---------|
| Kịch bản 1 — Brute Force Login | high | count_over_time 401 [1m] | brute_force | revoke_user_sessions |
| Kịch bản 2 — Lateral Movement | critical | count_over_time opa_result=false [5m] | lateral_movement | isolate_workload |
| Kịch bản 3 — Fraud Gate Bypass | critical | count_over_time opa_result=false, request_path=/transactions/execute [5m] | fraud_gate_bypass | isolate_workload |
| Kịch bản 4 — Data Exfiltration | high | count_over_time bytes_sent>1MB [5m] | large_response | restrict_egress |
| Access Denied Spike | high | count_over_time OPA deny [1m] | access_denied | block_source_ip |
| SOAR Engine Health | warning | count SOAR logs [5m] < 1 → DOWN | — | — (monitor only) |

**Tất cả** alert `category=security` → webhook SOAR `/grafana-webhook`.

### Cập nhật Grafana alerts

```bash
# Sửa file yaml
vim k8s/plg-stack/grafana-alerting-configmap.yaml

# Apply ConfigMap
kubectl --context ctx-aws apply -f k8s/plg-stack/grafana-alerting-configmap.yaml

# Reload Grafana provisioning (không cần restart pod)
curl -s -X POST -u admin:ZTALab2026! \
  http://localhost:3000/api/admin/provisioning/alerting/reload
```

---

## 11. OPA — Chính sách Zero Trust

**File:** `opa/policies/zta_policy.rego`  
**Áp dụng:** ConfigMap `opa-policies` (cả AWS lẫn OpenStack cluster, namespace `financial`)

### Các luồng được phép

| Loại request | Điều kiện | Phép |
|-------------|-----------|------|
| Health/metrics | GET `/health`, `/ready`, `/metrics*` | Luôn cho phép |
| External API | JWT hợp lệ + role khớp method + không có SVID | Cho phép |
| Internal service | SVID `spiffe://ztlab.local/*` + method/path hợp lệ | Cho phép |
| Transaction execute | SVID + `x-fraud-gate: passed` + `x-fraud-score < 75` | Cho phép |
| Transaction execute | SVID nhưng thiếu/sai fraud gate | **DENY (Gap 2)** |

### Cập nhật OPA policy

```bash
# Sửa opa/policies/zta_policy.rego rồi apply:
kubectl --context ctx-aws create configmap opa-policies \
  -n financial \
  --from-file=opa/policies/ \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -
kubectl --context ctx-aws rollout restart deployment/opa-server -n financial

# Tương tự cho OpenStack
kubectl --context ctx-openstack create configmap opa-policies \
  -n financial \
  --from-file=opa/policies/ \
  --dry-run=client -o yaml | kubectl --context ctx-openstack apply -f -
kubectl --context ctx-openstack rollout restart deployment/opa-server -n financial
```

---

## 12. Xử lý sự cố

### Payment trả 503 — SOAR isolate payment-service

```bash
# Kiểm tra
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.spec.selector}' && echo
# Nếu có "soar.ztlab.io/isolated":"true":

# Cách 1 — rollback qua SOAR API
curl http://localhost:8091/cases | python3 -c "
import sys,json
[print(c['case_id'], c['ts'][:19], c['status'])
 for c in json.load(sys.stdin) if 'payment' in c.get('target_workload','')]"
curl -X POST http://localhost:8091/cases/{case_id}/rollback

# Cách 2 — patch trực tiếp
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

### Payment trả 503 — cross-cloud không hoạt động

```bash
# 1. Kiểm tra OpenStack VMs
source /etc/kolla/admin-openrc.sh && openstack server list

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

### API Gateway trả 403 — JWT issuer sai

OPA kiểm tra `jwt_payload.iss == "http://keycloak.ztlab.local:8180/realms/ztlab"`. Kiểm tra issuer trong token thực tế:

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234!&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo $TOKEN | cut -d. -f2 | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip()
p+='=='*((4-len(p)%4)%4)
print(json.loads(base64.urlsafe_b64decode(p)).get('iss'))"
```

Nếu issuer không khớp → sửa `opa/policies/zta_policy.rego` → apply lại ConfigMap.

### API Gateway jwks_keys_loaded=0

Keycloak chưa sẵn sàng khi api-gateway start → restart:
```bash
kubectl --context ctx-aws rollout restart deployment/api-gateway -n financial
```

### Web Portal redirect sai sau Keycloak login

Kiểm tra client `web-portal` trong Keycloak có đủ redirectUris chưa:
```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8180/realms/master/protocol/openid-connect/token \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=ztlab-admin-2026" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

CLIENT_ID=$(curl -s "http://localhost:8180/admin/realms/ztlab/clients?clientId=web-portal" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

curl -s -X PUT "http://localhost:8180/admin/realms/ztlab/clients/$CLIENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"clientId":"web-portal","publicClient":true,"standardFlowEnabled":true,
       "attributes":{"pkce.code.challenge.method":"S256"},
       "redirectUris":["http://localhost:18081/*","http://127.0.0.1:18081/*"],
       "webOrigins":["+"]}'
```

### Loki không nhận log từ OpenStack

```bash
# Kiểm tra socat proxy đang listen
ss -lnt | grep 13099
# Phải có: 10.10.10.1:13099

# Nếu không có → restart port-forwards
bash scripts/open-admin-uis.sh stop && bash scripts/open-admin-uis.sh
```

### SOAR pod không start (CrashLoopBackOff)

```bash
kubectl --context ctx-aws logs -n plg-stack deployment/soar-engine | tail -20
# Thường do redis-auth secret thiếu → redeploy:
bash scripts/deploy-all.sh
```

### SPIRE SVID hết hạn (mTLS fail sau ~1h)

```bash
kubectl --context ctx-aws rollout restart daemonset/spire-agent -n spire
# Đợi SVID renew xong (~30s), rồi restart services
kubectl --context ctx-aws rollout restart deployment -n financial
kubectl --context ctx-openstack rollout restart deployment -n financial
```

### K8s tunnel mất kết nối

```bash
bash scripts/k8s-tunnel.sh down all
bash scripts/k8s-tunnel.sh up all
```

### Grafana alert firing liên tục (false positive)

```bash
# Xem alert nào đang firing và giá trị
curl -s -u admin:ZTALab2026! \
  "http://localhost:3000/api/prometheus/grafana/api/v1/rules" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for g in d.get('data',{}).get('groups',[]):
    for r in g.get('rules',[]):
        if r.get('state')=='firing':
            print('FIRING:', r['name'])"
# Alert tự về inactive sau 5 phút khi không còn trigger
# Nếu vừa test OPA direct qua port-forward → đó là trigger hợp lệ, đợi 5 phút
```

### Lấy JWT token nhanh để test API

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234!&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo $TOKEN

# Dùng token
curl -H "Authorization: Bearer $TOKEN" http://localhost:18080/accounts/ACC-1001
curl -H "Authorization: Bearer $TOKEN" http://localhost:18080/transactions?account_id=ACC-1001
```

---

*Hệ thống implement Zero Trust Architecture theo NIST SP 800-207: không có implicit trust, mọi request đều xác thực identity (JWT + SPIFFE SVID) và policy (OPA) trước khi được phép truy cập tài nguyên.*
