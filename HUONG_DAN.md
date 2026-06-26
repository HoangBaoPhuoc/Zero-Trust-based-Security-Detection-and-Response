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
8. [Test kịch bản demo](#8-test-kịch-bản-demo)
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

### Luồng thanh toán (cross-cloud)

```
Browser
  → web-portal (PKCE session)
  → api-gateway (JWT verify + OPA authz)
  → payment-service (HMAC sign + gọi fraud-detection)
  → fraud-detection (Redis velocity → score → gate=passed/blocked)
  → core-banking [OpenStack] (SPIFFE mTLS + OPA: yêu cầu x-fraud-gate)
  → account-service [OpenStack] (debit/credit số dư)
  → transaction-service [OpenStack] (ghi ledger)
```

### Luồng phát hiện & phản ứng tự động

```
Log event (Envoy/OPA/app) → Promtail → Loki
  → Grafana alert fire (count_over_time query, eval 1 phút)
  → POST soar-engine/grafana-webhook
  → SOAR parse attack_type từ label alert
  → severity ≥ medium + auto_execute=true
  → chạy playbook ngay (isolate / block / restrict / revoke)
  → ghi case vào Redis + SOAR log
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

Chạy daemon tự-restart, không cần giữ terminal.  
Kiểm tra: `bash scripts/open-admin-uis.sh status`

### Bước 5 — Kiểm tra payment-service chưa bị SOAR isolate

```bash
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.spec.selector}' && echo
# Kết quả đúng: {"app":"payment-service"}
```

Nếu có `soar.ztlab.io/isolated`:
```bash
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

### Checklist nhanh (copy-paste toàn bộ)

```bash
# 1. OpenStack VMs
source /etc/kolla/admin-openrc.sh && openstack server list
# Nếu SHUTOFF: openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2

# 2. K8s tunnels
bash scripts/k8s-tunnel.sh up all

# 3. Xác nhận nodes
kubectl --context ctx-aws get nodes && kubectl --context ctx-openstack get nodes

# 4. Port-forwards
bash scripts/open-admin-uis.sh

# 5. Kiểm tra payment-service không bị isolate
kubectl --context ctx-aws get svc payment-service -n financial -o jsonpath='{.spec.selector}'
# Kết quả đúng: {"app":"payment-service"}
# Nếu sai: kubectl --context ctx-aws patch svc payment-service -n financial \
#   --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
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

# Mở port-forwards
bash scripts/open-admin-uis.sh
```

---

## 5. Tài khoản & credentials

### Keycloak — realm: ztlab

| Username | Password | Role | Tài khoản ngân hàng |
|----------|----------|------|---------------------|
| admin | ztlab-admin-2026 | Keycloak superadmin | — |
| testuser01 | Test@123! | financial-read, financial-write | ACC-1001 (1,000,000,000 VND) |
| testuser02 | Test@123! | financial-read, financial-write | ACC-2001 (250,000,000 VND) |
| merchant01 | Merchant@123! | financial-read | ACC-4001 |
| analyst01 | Analyst@123! | security-analyst | ACC-5001 |

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
| Web Portal | http://localhost:18081 | testuser01 / Test@123! (qua Keycloak SSO) |
| API Gateway | http://localhost:18080 | — (cần Bearer JWT) |
| Keycloak Admin | http://localhost:8180 | admin / ztlab-admin-2026 |
| Grafana | http://localhost:3000 | admin / ZTALab2026! |
| Prometheus | http://localhost:9090 | — |
| SOAR Engine API | http://localhost:8091 | — |
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
```

```bash
# Prometheus targets (phải 10/10 UP)
curl -s http://localhost:9090/api/v1/targets | python3 -c "
import sys,json; d=json.load(sys.stdin)
t=d['data']['activeTargets']
print('Targets UP:', sum(1 for x in t if x['health']=='up'), '/', len(t))"
```

```bash
# E2E payment test — lấy JWT rồi gửi payment
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test%40123%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000,"currency":"VND","description":"health-check"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('status:', d.get('status'), '| gate:', d.get('fraud',{}).get('gate'))"
# Kỳ vọng: status: completed | gate: passed
```

---

## 8. Test kịch bản demo

### Chuẩn bị trước mỗi lần demo

```bash
# 1. Reset số dư về baseline
python3 tests/seed_db.py
# ACC-1001 testuser01 = 1,000,000,000 VND
# ACC-2001 testuser02 = 250,000,000 VND

# 2. Restore payment-service nếu đang bị SOAR isolate
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'

# 3. Restore api-gateway nếu bị scale xuống 0
kubectl --context ctx-aws scale deployment api-gateway -n financial --replicas=1

# 4. Kiểm tra tất cả pods đang Running
kubectl --context ctx-aws get pods -n financial | grep -v "Running\|Completed"
# (không có output = tốt)
```

Mở sẵn 4 tab trình duyệt:

| Tab | URL | Mục đích |
|-----|-----|---------|
| 1 | http://localhost:18081 | Web Portal — đăng nhập testuser01 |
| 2 | http://localhost:3000/d/siem-soar-ztlab | Grafana SIEM SOAR dashboard |
| 3 | http://localhost:3000/alerting/list | Grafana Alert Rules (theo dõi FIRING) |
| 4 | http://localhost:18081/security | SOAR Cases — đăng nhập analyst01 |

---

### Cách chạy demo

Có 2 cách:

**Cách 1 — Script tự động (khuyến nghị)**

```bash
# Chạy toàn bộ: normal traffic + tất cả attack scenarios
bash scripts/run-demo.sh

# Chỉ normal traffic (4 payment hợp lệ)
bash scripts/run-demo.sh --traffic-only

# Chỉ attack scenarios (5 kịch bản + SOAR)
bash scripts/run-demo.sh --attack-only

# Thêm brute force (10 request JWT sai)
bash scripts/run-demo.sh --brute-force

# Loop liên tục (Ctrl+C để dừng)
bash scripts/run-demo.sh --continuous
```

**Cách 2 — Thủ công từng kịch bản** (xem mục 8.1–8.4 bên dưới)

---

### 8.1 — Kịch bản 1: Brute Force Login (T1110.001)

**Mô tả:** Kẻ tấn công thử đăng nhập sai nhiều lần → Keycloak 401 → Grafana detect → SOAR revoke session.

```bash
# Gửi 10 request JWT sai liên tiếp
for i in $(seq 1 10); do
  curl -s -X POST http://localhost:18080/payments \
    -H "Authorization: Bearer invalid.jwt.token.$i" \
    -H "Content-Type: application/json" \
    -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1}' > /dev/null
  echo -n "."
done
echo " done"
# Hoặc dùng script: bash scripts/run-demo.sh --brute-force --attack-only
```

**Chuỗi sự kiện:**
1. api-gateway Envoy trả 401 → access log → Promtail → Loki
2. Grafana alert "Kịch bản 1 — Brute Force Login" → FIRING (count 401 [1m] > ngưỡng)
3. SOAR: `attack_type=brute_force` → playbook `revoke_user_sessions`
4. Keycloak Admin API xóa tất cả active session của testuser01

**Verify kết quả:**
```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=[c for c in json.load(sys.stdin) if c.get('attack_type')=='brute_force']
for c in cases[-3:]:
    print(c['ts'][:19], '|', c['playbook'], '|', c['status'])"
```

**Không cần restore** — chỉ session bị xóa, service không bị tác động.

---

### 8.2 — Kịch bản 2: Lateral Movement (T1021.007)

**Mô tả:** Service bên ngoài trust domain cố gắng gọi vào core-banking → Envoy từ chối SVID không hợp lệ → SOAR isolate payment-service.

```bash
# Push log lateral movement vào Loki
python3 - <<'EOF'
import json, urllib.request, time
payload = {"streams":[{"stream":{
    "job":"envoy-access","service":"payment-service","namespace":"financial","attack_type":"lateral_movement"
  },"values":[[str(time.time_ns()), json.dumps({
    "event_type":"lateral_movement_attempt",
    "source_ip":"10.10.1.99",
    "svid":"spiffe://external.attacker/malicious-service",
    "destination":"core-banking",
    "response_code":403,
    "message":"SVID outside trust domain ztlab.local — denied by Envoy"
  })]]}]}
req = urllib.request.Request("http://localhost:13100/loki/api/v1/push",
    data=json.dumps(payload).encode(), headers={"Content-Type":"application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print("Loki push OK — chờ Grafana alert ~1 phút")
EOF
```

**Chuỗi sự kiện:**
1. Log với `attack_type=lateral_movement` vào Loki
2. Grafana alert "Kịch bản 2 — Lateral Movement" → FIRING
3. SOAR: `attack_type=lateral_movement` → playbook `isolate_workload`
4. K8s Service selector của payment-service bị patch → pod không nhận traffic → payment trả 503

**Verify:**
```bash
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.spec.selector}' && echo
# Kết quả sau isolate: {"app":"payment-service","soar.ztlab.io/isolated":"true"}
```

**Restore sau demo:**
```bash
# Cách 1 — rollback qua SOAR API
CASE_ID=$(curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=[c for c in json.load(sys.stdin) if c.get('attack_type')=='lateral_movement']
print(cases[-1]['case_id']) if cases else print('')")
curl -s -X POST http://localhost:8091/cases/${CASE_ID}/rollback

# Cách 2 — patch trực tiếp
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

---

### 8.3 — Kịch bản 3: Fraud Gate Bypass (T1078.004)

**Mô tả:** Kẻ tấn công cố gọi thẳng `/transactions/execute` trên core-banking mà không có header `x-fraud-gate: passed` → OPA từ chối → SOAR phản ứng.

```bash
# Gọi trực tiếp core-banking không qua fraud gate
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test%40123%21" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Thử bypass fraud gate — sẽ bị OPA deny
curl -s -X POST http://localhost:18080/transactions/execute \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":50000000}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d)"
# Kỳ vọng: 403 Forbidden từ OPA
```

**OPA fraud gate logic (Gap 2):**

| Request đến core-banking | Kết quả |
|--------------------------|---------|
| POST /transactions/execute, không có `x-fraud-gate` | **DENY 403** |
| POST /transactions/execute, `x-fraud-gate=passed`, score=5 | ALLOW |
| POST /transactions/execute, `x-fraud-gate=passed`, score=80 | **DENY** (score ≥ 75) |
| POST /transactions/* (không phải /execute) | ALLOW |

**Chuỗi sự kiện:**
1. OPA: `fraud_gate_valid=false` → DENY → ghi decision log
2. Promtail: `opa_result=false`, `request_path=/transactions/execute` → Loki
3. Grafana alert "Kịch bản 3 — Fraud Gate Bypass" → FIRING
4. SOAR: `attack_type=fraud_gate_bypass` → playbook `isolate_workload` trên payment-service

**Restore sau demo:**
```bash
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

---

### 8.4 — Kịch bản 4: Data Exfiltration (T1041)

**Mô tả:** Response có kích thước bất thường (>1 MB) từ core-banking → Envoy log → Grafana detect → SOAR scale api-gateway xuống 0.

```bash
# Push log data exfiltration vào Loki
python3 - <<'EOF'
import json, urllib.request, time
payload = {"streams":[{"stream":{
    "job":"envoy-access","service":"core-banking","namespace":"financial","attack_type":"large_response"
  },"values":[[str(time.time_ns()), json.dumps({
    "event_type":"large_response_detected",
    "source_ip":"10.10.4.22",
    "path":"/accounts/export",
    "response_code":200,
    "bytes_sent":2500000,
    "message":"Abnormal response size 2.5MB — possible data exfiltration"
  })]]}]}
req = urllib.request.Request("http://localhost:13100/loki/api/v1/push",
    data=json.dumps(payload).encode(), headers={"Content-Type":"application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print("Loki push OK — chờ Grafana alert ~1 phút")
EOF
```

**Chuỗi sự kiện:**
1. Log với `bytes_sent=2500000` vào Loki
2. Grafana alert "Kịch bản 4 — Data Exfiltration Suspect" → FIRING
3. SOAR: `attack_type=large_response` → playbook `restrict_egress`
4. Deployment `api-gateway` scale xuống 0 replica → toàn bộ API ngừng hoạt động

**Verify:**
```bash
kubectl --context ctx-aws get deployment api-gateway -n financial \
  -o jsonpath='{.spec.replicas}' && echo
# Kết quả sau restrict: 0
```

**Restore sau demo:**
```bash
kubectl --context ctx-aws scale deployment api-gateway -n financial --replicas=1
# Đợi pod ready
kubectl --context ctx-aws rollout status deployment api-gateway -n financial
```

---

### Restore toàn bộ sau demo

```bash
# Restore payment-service nếu bị isolate
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'

# Restore api-gateway nếu bị scale=0
kubectl --context ctx-aws scale deployment api-gateway -n financial --replicas=1

# Reset số dư
python3 tests/seed_db.py

# Xóa blocked IPs nếu có
curl -s http://localhost:8091/blocked-ips | python3 -c "
import sys,json
for ip in json.load(sys.stdin).get('blocked_ips',[]):
    print('blocked:', ip)
    # curl -X DELETE http://localhost:8091/blocked-ips/' + ip"
```

---

### Lưu ý quan trọng khi demo

> **SOAR auto-isolate payment-service định kỳ** — Nếu hệ thống đang có logs `lateral_movement` cũ trong Loki từ các session trước, Grafana alert có thể fire liên tục và SOAR sẽ tự isolate payment-service. Đây là hành vi đúng của hệ thống.
>
> Dấu hiệu: `GET /payments` → 503, và `kubectl get svc payment-service` thấy selector có `soar.ztlab.io/isolated`.
>
> Trước khi demo payment, luôn chạy lệnh restore ở trên.

---

## 9. SOAR Engine

**URL:** http://localhost:8091  
**Config hiện tại:** `auto_execute=true` · `min_severity=medium` · `dry_run=false` · `hitl_severity=high`

### 5 Playbooks

| Playbook | Trigger (attack_type) | Hành động K8s |
|----------|----------------------|--------------|
| `isolate_workload` | lateral_movement, fraud_gate_bypass | Patch Service selector → pod không nhận traffic |
| `restrict_egress` | large_response | Scale Deployment → 0 replica |
| `quarantine_workload` | cryptomining | Scale Deployment → 0 replica |
| `block_source_ip` | port_scan, exploit_probe, access_denied | Tạo NetworkPolicy + Redis DB0 blocklist 24h |
| `revoke_user_sessions` | brute_force, jwt_replay, credential_stuffing | Keycloak Admin API xóa session |

### Attack type → Playbook mapping

| attack_type | Playbook | Target workload |
|-------------|---------|----------------|
| fraud_gate_bypass | isolate_workload | payment-service |
| lateral_movement | isolate_workload | payment-service |
| large_response | restrict_egress | api-gateway |
| cryptomining | quarantine_workload | transaction-service |
| brute_force | revoke_user_sessions | api-gateway |
| access_denied | block_source_ip | api-gateway |
| port_scan | block_source_ip | api-gateway |

### API endpoints

```bash
curl http://localhost:8091/health                             # trạng thái + case count
curl http://localhost:8091/cases                              # tất cả cases
curl http://localhost:8091/cases/{case_id}                   # chi tiết 1 case
curl -X POST http://localhost:8091/cases/{case_id}/rollback  # restore workload
curl http://localhost:8091/blocked-ips                        # IPs đang bị block
curl -X POST http://localhost:8091/blocked-ips/1.2.3.4       # block thủ công
curl -X DELETE http://localhost:8091/blocked-ips/1.2.3.4     # unblock
curl http://localhost:8091/playbooks                          # danh sách playbooks
```

### Xem recent cases

```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=json.load(sys.stdin)
print(f'Total: {len(cases)} cases')
for c in cases[-10:]:
    print(c['ts'][:19], '|', c['attack_type'][:20].ljust(20),
          '|', c['severity'][:8].ljust(8), '|', c['playbook'][:25].ljust(25),
          '|', c['status'])"
```

### Lưu ý

- Grafana `repeat_interval=1h` — cùng 1 alert không gửi lại SOAR trong 1 giờ
- Sau `isolate_workload`: payment-service trả 503 cho đến khi restore
- Sau `restrict_egress`: api-gateway scale=0, toàn bộ API ngừng
- SOAR lưu cases vào Redis — không mất khi pod restart

---

## 10. Grafana — Dashboards & Alerts

**URL:** http://localhost:3000 · Login: admin / ZTALab2026!  
**Log retention:** 90 ngày (Loki)

### 6 Dashboards (folder: ZTLab)

| Dashboard | Mô tả |
|-----------|-------|
| ZTLab — Zero Trust Security Overview | OPA allow/deny rate, JWT failures, fraud score |
| ZTLab Security Overview | Panels tóm tắt cross-cloud |
| ZTLab Full Logs | Envoy access logs toàn bộ hệ thống |
| Envoy Access Logs | HTTP matrix, latency P50/P95/P99 |
| OPA Decision Log | Allow/deny rate, top denied paths |
| SIEM SOAR | Cases, playbooks, IPs blocked, live log stream |

### 6 Alert Rules (folder: ZTLab)

| Alert | Severity | attack_type | Playbook |
|-------|----------|-------------|---------|
| Kịch bản 1 — Brute Force Login | high | brute_force | revoke_user_sessions |
| Kịch bản 2 — Lateral Movement | critical | lateral_movement | isolate_workload |
| Kịch bản 3 — Fraud Gate Bypass | critical | fraud_gate_bypass | isolate_workload |
| Kịch bản 4 — Data Exfiltration | high | large_response | restrict_egress |
| Access Denied Spike | high | access_denied | block_source_ip |
| SOAR Engine Health | warning | — | monitor only |

Tất cả alert `category=security` → webhook SOAR `POST /grafana-webhook`.

### Reload Grafana alerts (sau khi sửa ConfigMap)

```bash
kubectl --context ctx-aws apply -f k8s/plg-stack/grafana-alerting-configmap.yaml
curl -s -X POST -u admin:ZTALab2026! \
  http://localhost:3000/api/admin/provisioning/alerting/reload
```

---

## 11. OPA — Chính sách Zero Trust

**File:** `opa/policies/zta_policy.rego`  
**Áp dụng:** ConfigMap `opa-policies` (cả AWS lẫn OpenStack cluster, namespace `financial`)

### Các luồng được phép

| Loại request | Điều kiện | Kết quả |
|-------------|-----------|---------|
| Health/metrics | GET `/health`, `/ready`, `/metrics*` | ALLOW |
| External API | JWT hợp lệ + role khớp method + không có SVID | ALLOW |
| Internal service | SVID `spiffe://ztlab.local/*` + method/path hợp lệ | ALLOW |
| Transaction execute | SVID + `x-fraud-gate: passed` + score < 75 | ALLOW |
| Transaction execute | Thiếu SVID hoặc thiếu/sai fraud gate | **DENY** |

### Cập nhật OPA policy

```bash
# Sửa opa/policies/zta_policy.rego rồi apply:
kubectl --context ctx-aws create configmap opa-policies \
  -n financial --from-file=opa/policies/ \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -
kubectl --context ctx-aws rollout restart deployment/opa-server -n financial

# Tương tự cho OpenStack
kubectl --context ctx-openstack create configmap opa-policies \
  -n financial --from-file=opa/policies/ \
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
CASE_ID=$(curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=[c for c in json.load(sys.stdin)
       if 'payment' in c.get('target_workload','') and c['status']=='executed']
print(cases[-1]['case_id']) if cases else print('')")
[ -n "$CASE_ID" ] && curl -X POST http://localhost:8091/cases/${CASE_ID}/rollback

# Cách 2 — patch trực tiếp (nhanh hơn)
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

### Payment trả 503 — cross-cloud không hoạt động

```bash
# 1. Kiểm tra OpenStack VMs
source /etc/kolla/admin-openrc.sh && openstack server list

# 2. Kiểm tra kết nối TCP từ AWS pod đến OpenStack NodePorts
kubectl --context ctx-aws exec -n financial deployment/payment-service \
  -c payment-service -- python3 -c "
import socket
for port, name in [(30080,'core-banking'),(30082,'account-svc'),(30083,'txn-svc')]:
    s=socket.socket(); s.settimeout(3)
    try: s.connect(('192.168.101.11',port)); print('OK', name)
    except Exception as e: print('FAIL', name, str(e)[:40])
    finally: s.close()"
# Phải OK cả 3

# 3. Kiểm tra WireGuard
kubectl --context ctx-aws exec -n financial deployment/payment-service \
  -c payment-service -- python3 -c "
import socket; s=socket.socket(socket.AF_INET, socket.SOCK_ICMP if hasattr(socket,'ICMP') else socket.SOCK_STREAM)
# Ping thay thế bằng TCP test ở trên"
```

### JWT invalid token — 401 từ api-gateway

```bash
# Lấy token mới từ Keycloak
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test%40123%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token','ERR'))")
echo "${TOKEN:0:30}..."

# Kiểm tra issuer trong token (phải là http://keycloak.ztlab.local:8180/realms/ztlab)
echo $TOKEN | cut -d. -f2 | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip()
p+='='*((4-len(p)%4)%4)
d=json.loads(base64.urlsafe_b64decode(p))
print('iss:', d.get('iss'))
print('roles:', d.get('realm_access',{}).get('roles',[]))"
```

### API Gateway jwks_keys_loaded=0

Keycloak chưa sẵn sàng khi api-gateway start → restart api-gateway:
```bash
kubectl --context ctx-aws rollout restart deployment/api-gateway -n financial
kubectl --context ctx-aws rollout status deployment/api-gateway -n financial
```

### Web Portal redirect sai sau Keycloak login

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

### Grafana alert firing liên tục (false positive)

```bash
# Xem alert nào đang firing
curl -s -u admin:ZTALab2026! \
  "http://localhost:3000/api/prometheus/grafana/api/v1/rules" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for g in d.get('data',{}).get('groups',[]):
    for r in g.get('rules',[]):
        if r.get('state')=='firing':
            print('FIRING:', r['name'])"
# Alert tự về inactive sau 5 phút khi không còn log trigger
```

### SPIRE SVID hết hạn (mTLS fail sau ~1h idle)

```bash
kubectl --context ctx-aws rollout restart daemonset/spire-agent -n spire
# Đợi ~30 giây
kubectl --context ctx-aws rollout restart deployment -n financial
kubectl --context ctx-openstack rollout restart deployment -n financial
```

### K8s tunnel mất kết nối

```bash
bash scripts/k8s-tunnel.sh down all
bash scripts/k8s-tunnel.sh up all
```

### Lấy JWT token nhanh để test API

```bash
# testuser01
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test%40123%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Dùng token
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:18080/accounts/ACC-1001
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:18080/accounts?owner=testuser01
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:18080/transactions?account_id=ACC-1001&limit=5
```

---

*Hệ thống implement Zero Trust Architecture theo NIST SP 800-207: không có implicit trust, mọi request đều xác thực identity (JWT + SPIFFE SVID) và policy (OPA) trước khi được phép truy cập tài nguyên.*
