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
9. [SOAR Engine & HITL](#9-soar-engine--hitl)
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
│   web-portal      (Jinja2 UI + Keycloak SSO + Security dashboard)      │
│   api-gateway     spiffe://ztlab.local/aws/api-gateway                  │
│   payment-service spiffe://ztlab.local/aws/payment-service              │
│   fraud-detection spiffe://ztlab.local/aws/fraud-detection              │
│   notification-service spiffe://ztlab.local/aws/notification-service   │
│   OPA             ext_authz gRPC port 9191                              │
│   Redis · PostgreSQL accounts · PostgreSQL transactions                 │
│                                                                          │
│ namespace: plg-stack                                                     │
│   Promtail (DaemonSet) → Loki (90 ngày) → Grafana                      │
│   SOAR Engine   (heuristic + Grafana webhook → HITL email → K8s)       │
│   Security Scorer   (anomaly score 0-100 · window 15 phút · Redis)     │
│                                                                          │
│ namespace: monitoring                                                    │
│   Prometheus  (scrape AWS + OpenStack targets)                          │
└─────────────────────────┬───────────────────────────────────────────────┘
                          │  WireGuard VPN  10.200.200.1 ↔ 10.200.200.2
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
  → notification-service [AWS] (fire-and-forget)
```

### Luồng phát hiện & phản ứng bảo mật (HITL)

```
Log event (Envoy/OPA/app) → Promtail → Loki
  ├─ Heuristic Poller (poll Loki mỗi 60s, 9 regex rules)
  │    └─ phát hiện anomaly → tạo SOAR case
  └─ Grafana alert fire (count_over_time query, eval 1 phút)
       └─ POST soar-engine/grafana-webhook → tạo SOAR case

SOAR case tạo xong:
  ├─ severity < high (medium/low): auto-execute playbook ngay
  └─ severity ≥ high: pending_approval → gửi email HITL cho admin
       └─ Admin mở email → thấy các nút hành động (block IP / isolate / revoke...)
          → click nút HOẶC vào web-portal /security → chọn hành động
          → SOAR thực thi playbook đã chọn → ghi case thành "executed"
```

---

## 2. Hạ tầng & địa chỉ IP

| Node | IP Private | IP Public | Vai trò |
|------|-----------|-----------|---------|
| aws_bastion | — | 52.221.255.36 | SSH jump host |
| aws_gateway | 10.10.0.10 · WG 10.200.200.1 | 13.213.245.227 | NAT + WireGuard |
| aws_k3s_master | 10.10.1.10 | — | K8s control plane AWS |
| aws_k3s_worker_1 | 10.10.1.11 | — | K8s worker AWS |
| os_gateway | 192.168.100.10 · WG 10.200.200.2 | 10.10.10.188 (floating) | WireGuard client |
| os_k3s_master | 192.168.101.11 | — | K8s master OpenStack |
| deployer (máy này) | 10.10.10.1 (br-exnat) | — | Bastion + Loki proxy |

**K8s contexts:**
- `ctx-aws` → `127.0.0.1:6444` (SSH tunnel qua 52.221.255.36 → 10.10.1.10:6443)
- `ctx-openstack` → `127.0.0.1:6445` (SSH tunnel qua 10.10.10.188 → 192.168.101.11:6443)

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
sleep 30
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

### Bước 5 — Restore về trạng thái sạch

```bash
bash scripts/run-demo.sh --restore
```

Lệnh này restore payment-service (nếu bị SOAR isolate), api-gateway (nếu bị scale=0) và core-banking trên OpenStack (nếu bị scale=0).

### Checklist nhanh (copy-paste toàn bộ)

```bash
# 1. OpenStack VMs
source /etc/kolla/admin-openrc.sh && openstack server list
# Nếu SHUTOFF:
openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2 && sleep 30

# 2. K8s tunnels
bash scripts/k8s-tunnel.sh up all

# 3. Xác nhận nodes
kubectl --context ctx-aws get nodes && kubectl --context ctx-openstack get nodes

# 4. Port-forwards
bash scripts/open-admin-uis.sh

# 5. Restore về trạng thái sạch
bash scripts/run-demo.sh --restore
```

> **Sau reboot AWS VM:** pods tự restart theo K3s/systemd, chỉ làm lại bước 2 + 4 + 5.  
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
| testuser01 | Test1234! | financial-read, financial-write | ACC-1001 (1,000,000,000 VND) |
| testuser02 | Test1234! | financial-read, financial-write | ACC-2001 (250,000,000 VND) |
| merchant01 | Test1234! | financial-read | ACC-4001 |
| analyst01 | Test1234! | security-analyst, security-admin | — |

> **merchant01** chỉ có `financial-read` → POST /payments → 403 (demo RBAC).  
> **analyst01** có cả `security-analyst` + `security-admin` → xem được `/security`, `/monitor`, duyệt HITL và thực thi playbook.

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
| `/security` | SOAR cases + blocked IPs + duyệt HITL | security-analyst (xem), security-admin (duyệt) |
| `/monitor` | System health | security-analyst |

**Login flow:** `/login` → click "Đăng nhập với Keycloak SSO" → Keycloak (proxied qua `/kc/`) → callback → `/dashboard`.

> **Phân quyền trang `/security`:**
> - **analyst01** (`security-analyst` + `security-admin`): xem SOAR Cases, duyệt HITL, thực thi playbook, quản lý blocked IPs, rollback case.
> - Người dùng chỉ có `security-analyst` (không có `security-admin`): chỉ đọc — không thể execute playbook.

---

## 7. Health check nhanh

```bash
# Tất cả services
curl -s http://localhost:18081/health   # web-portal: {"status":"ok"}
curl -s http://localhost:18080/health   # api-gateway: jwks_keys_loaded≥1
curl -s http://localhost:8091/health    # soar-engine: dry_run=false, case_count=N
curl -s http://localhost:3000/api/health  # grafana: database=ok
curl -s http://localhost:13100/ready    # loki: ready
curl -s http://localhost:9090/-/healthy # prometheus: Prometheus Server is Healthy.
```

```bash
# E2E payment test — lấy JWT rồi gửi payment
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":50000,"currency":"VND"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('status:', d.get('status'), '| gate:', d.get('fraud',{}).get('gate'))"
# Kỳ vọng: status: completed | gate: passed
```

---

## 8. Test kịch bản demo

### Chuẩn bị trước mỗi lần demo

```bash
# 1. Restore tất cả services về trạng thái bình thường
bash scripts/run-demo.sh --restore

# 2. Reset số dư về baseline
python3 tests/seed_db.py
# ACC-1001 testuser01 = 1,000,000,000 VND
# ACC-2001 testuser02 = 250,000,000 VND

# 3. Kiểm tra tất cả pods đang Running
kubectl --context ctx-aws get pods -n financial | grep -v "Running\|Completed"
kubectl --context ctx-openstack get pods -n financial | grep -v "Running\|Completed"
# (không có output = tốt)
```

Mở sẵn các tab trình duyệt:

| Tab | URL | Mục đích |
|-----|-----|---------|
| 1 | http://localhost:18081 | Web Portal — đăng nhập testuser01 |
| 2 | http://localhost:3000/d/ztlab-ai-siem-soar | Grafana SIEM SOAR dashboard |
| 3 | http://localhost:3000/alerting/list | Grafana Alert Rules (theo dõi FIRING) |
| 4 | http://localhost:18081/security | SOAR Cases — đăng nhập analyst01 |

---

### Luồng demo đầy đủ (HITL)

> Hệ thống theo mô hình **Human-in-the-Loop**: SOAR phát hiện tấn công, tạo case và gửi email cho admin với các nút hành động. Admin xem xét rồi chọn hành động phù hợp — SOAR thực thi. Không tự động execute cho severity ≥ high để đảm bảo oversight.

**Bước 1 — Push log tấn công (inject Loki)**  
**Bước 2 — Chờ Grafana alert fire (~60s) → SOAR tạo case `pending_approval`**  
**Bước 3 — Admin nhận email với nút hành động (revoke / block / isolate...)**  
**Bước 4 — Admin vào http://localhost:18081/security → tìm case "⏳ Chờ duyệt" → click "⚡ Xử lý"**  
**Bước 5 — Chọn playbook → SOAR thực thi → case chuyển sang "executed"**

---

### Cách chạy demo

> **Về "tấn công thực" vs "inject log":**
> - **KB1** có thể tấn công thực bằng cách craft JWT giả → api-gateway xác thực signature thất bại → trả 401 → Envoy ghi log thật → Grafana alert fire.
> - **KB2, KB3, KB4** không thể tấn công thực từ bên ngoài → inject log vào Loki để trigger Grafana alert.
> - Script `run-demo.sh` dùng inject log cho tất cả 4 kịch bản để đảm bảo tính đồng nhất khi demo.

**Cách 1 — Script tự động (khuyến nghị)**

```bash
# Chạy toàn bộ: normal traffic + tất cả 4 kịch bản tấn công
bash scripts/run-demo.sh

# Chỉ normal traffic (4 payment hợp lệ)
bash scripts/run-demo.sh --traffic-only

# Chỉ tất cả 4 kịch bản tấn công (không gửi normal traffic)
bash scripts/run-demo.sh --attack-only

# Chạy từng kịch bản riêng lẻ
bash scripts/run-demo.sh --kb1   # KB1: Brute Force
bash scripts/run-demo.sh --kb2   # KB2: Lateral Movement
bash scripts/run-demo.sh --kb3   # KB3: Fraud Gate Bypass
bash scripts/run-demo.sh --kb4   # KB4: Data Exfiltration

# Restore tất cả services sau demo
bash scripts/run-demo.sh --restore
```

> Script sẽ báo PASS khi SOAR tạo case (kể cả `pending_approval`). Admin vẫn cần vào web portal để duyệt.

**Cách 2 — Thủ công từng kịch bản** (copy-paste nhanh bên dưới)

---

### Lệnh tấn công thủ công (copy-paste nhanh)

> Mở Grafana `http://localhost:3000/alerting/list` theo dõi alert FIRING và `http://localhost:18081/security` để duyệt case.

#### Chuẩn bị

```bash
bash scripts/run-demo.sh --restore
curl -s http://localhost:18080/health | python3 -c "import sys,json; d=json.load(sys.stdin); print('GW OK, jwks='+str(d['jwks_keys_loaded']))"
```

#### KB1 — Brute Force Login

```bash
# Craft JWT: payload hợp lệ nhưng signature giả
FUTURE_EXP=$(($(date +%s) + 3600))
HEADER=$(python3 -c "import base64,json; h=json.dumps({'alg':'RS256','typ':'JWT'}).encode(); print(base64.urlsafe_b64encode(h).rstrip(b'=').decode())")
PAYLOAD=$(python3 -c "
import base64,json
p={'sub':'attacker','iss':'http://keycloak.ztlab.local:8180/realms/ztlab',
   'exp':$FUTURE_EXP,'realm_access':{'roles':['financial-write','financial-read']}}
print(base64.urlsafe_b64encode(json.dumps(p).encode()).rstrip(b'=').decode())")
FAKE_JWT="${HEADER}.${PAYLOAD}.FAKESIGNATUREFAKESIGNATUREFAKESIG"

echo "Gửi 20 request với JWT giả..."
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:18080/payments \
    -H "Authorization: Bearer $FAKE_JWT" \
    -H "Content-Type: application/json" \
    -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1}'
done
echo ""
echo "Xong! Chờ ~60s Grafana alert → SOAR case → email admin..."
sleep 65
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
c=[x for x in json.load(sys.stdin) if x.get('attack_type')=='brute_force']
x=c[-1] if c else {}
print('KB1:', x.get('status','CHƯA CÓ'), '|', x.get('playbook','?'))"
```

#### KB2 — Lateral Movement

```bash
python3 - <<'PY'
import json, urllib.request, time
now = time.time_ns()
values = [[str(now + i*1_000_000), json.dumps({
    "event_type": "lateral_movement_attempt", "opa_result": "false",
    "svid": "spiffe://external.attacker/malicious-service",
    "destination": "core-banking", "source_ip": "10.10.1.99",
    "message": f"SVID ngoài trust domain ztlab.local — OPA deny #{i+1}"
})] for i in range(5)]
payload = {"streams":[{"stream":{
    "job":"opa-decisions","opa_result":"false",
    "attack_scenario":"lateral_movement",
    "service":"payment-service","namespace":"financial"
},"values":values}]}
urllib.request.urlopen(urllib.request.Request(
    "http://127.0.0.1:13100/loki/api/v1/push",
    data=json.dumps(payload).encode(),
    headers={"Content-Type":"application/json"}, method="POST"), timeout=5)
print("Inject OK — chờ ~60s...")
PY
sleep 65
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
c=[x for x in json.load(sys.stdin) if x.get('attack_type')=='lateral_movement']
x=c[-1] if c else {}
print('KB2:', x.get('status','CHƯA CÓ'), '|', x.get('playbook','?'))"
# Sau khi admin duyệt tại web portal:
# kubectl --context ctx-aws get svc payment-service -n financial -o jsonpath='{.spec.selector}' && echo
# bash scripts/run-demo.sh --restore
```

#### KB3 — Fraud Gate Bypass

```bash
python3 - <<'PY'
import json, urllib.request, time
now = time.time_ns()
values = [[str(now + i*1_000_000), json.dumps({
    "event_type": "opa_deny", "opa_result": "false",
    "request_path": "/transactions/execute", "source_ip": "10.10.1.77",
    "reason": "fraud_gate header missing or tampered",
    "message": f"OPA DENY fraud_gate_bypass #{i+1}"
})] for i in range(5)]
payload = {"streams":[{"stream":{
    "job":"opa-decisions","opa_result":"false",
    "attack_scenario":"fraud_gate_bypass",
    "request_path":"/transactions/execute",
    "service":"payment-service","namespace":"financial"
},"values":values}]}
urllib.request.urlopen(urllib.request.Request(
    "http://127.0.0.1:13100/loki/api/v1/push",
    data=json.dumps(payload).encode(),
    headers={"Content-Type":"application/json"}, method="POST"), timeout=5)
print("Inject OK — chờ ~60s...")
PY
sleep 65
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
c=[x for x in json.load(sys.stdin) if x.get('attack_type')=='fraud_gate_bypass']
x=c[-1] if c else {}
print('KB3:', x.get('status','CHƯA CÓ'), '|', x.get('playbook','?'))"
# bash scripts/run-demo.sh --restore
```

#### KB4 — Data Exfiltration

```bash
# Ghi lại replicas trước
echo -n "core-banking trước: " && kubectl --context ctx-openstack get deploy core-banking -n financial -o jsonpath='{.spec.replicas}' && echo

python3 - <<'PY'
import json, urllib.request, time
now = time.time_ns()
values = [[str(now + i*1_000_000), json.dumps({
    "bytes_sent": 3100000, "response_code": 200,
    "path": "/accounts/export", "source_ip": "10.10.4.88",
    "message": f"Response size 3.1MB — possible data exfiltration #{i+1}"
})] for i in range(5)]
payload = {"streams":[{"stream":{
    "job":"envoy-access","service":"core-banking","namespace":"financial"
},"values":values}]}
urllib.request.urlopen(urllib.request.Request(
    "http://127.0.0.1:13100/loki/api/v1/push",
    data=json.dumps(payload).encode(),
    headers={"Content-Type":"application/json"}, method="POST"), timeout=5)
print("Inject OK — chờ ~60s...")
PY
sleep 65
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
c=[x for x in json.load(sys.stdin) if x.get('attack_type')=='large_response']
x=c[-1] if c else {}
print('KB4:', x.get('status','CHƯA CÓ'), '|', x.get('playbook','?'), '|', x.get('target_context','?'))"
# Sau khi admin duyệt "Hạn chế lưu lượng ra":
# echo -n "core-banking sau: " && kubectl --context ctx-openstack get deploy core-banking -n financial -o jsonpath='{.spec.replicas}' && echo
# bash scripts/run-demo.sh --restore
```

#### Xem kết quả tổng hợp

```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=json.load(sys.stdin)
print(f'Tổng {len(cases)} cases. 6 mới nhất:')
for c in cases[-6:]:
    icon='✓' if c.get('status') in ('executed','dry_run') else ('⏳' if c.get('status')=='pending_approval' else '✗')
    print(f'  {icon} {c[\"attack_type\"]:25} → {c[\"playbook\"]:22} [{c[\"status\"]}]')"
```

---

### 8.1 — Kịch bản 1: Brute Force Login (T1110.001)

**Mô tả:** Kẻ tấn công gửi nhiều request JWT giả → api-gateway xác thực signature thất bại → trả 401 → Envoy ghi log → Grafana detect → SOAR tạo case `pending_approval` → email admin → admin chọn `revoke_user_sessions` hoặc `block_source_ip`.

**Grafana query:** `{job="envoy-access"} | json | response_code=401 [1m]`

#### Cách A — Tấn công thực (real traffic)

```bash
FUTURE_EXP=$(($(date +%s) + 3600))

HEADER=$(python3 -c "
import base64,json
h=json.dumps({'alg':'RS256','typ':'JWT'}).encode()
print(base64.urlsafe_b64encode(h).rstrip(b'=').decode())")

PAYLOAD=$(python3 -c "
import base64,json
exp=$FUTURE_EXP
p={'sub':'attacker-uid','iss':'http://keycloak.ztlab.local:8180/realms/ztlab',
   'exp':exp,'realm_access':{'roles':['financial-write','financial-read']}}
d=json.dumps(p).encode()
print(base64.urlsafe_b64encode(d).rstrip(b'=').decode())")

FAKE_JWT="${HEADER}.${PAYLOAD}.FAKESIGNATUREFAKESIGNATUREFAKESIG"

echo "Gửi 20 request brute force với JWT giả signature..."
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:18080/payments \
    -H "Authorization: Bearer $FAKE_JWT" \
    -H "Content-Type: application/json" \
    -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1}'
done
echo ""
echo "Xong — 20 × 401 được ghi vào Envoy access log → Promtail → Loki → Grafana alert ~60s"
```

#### Cách B — Inject log vào Loki (đáng tin cậy hơn cho demo)

```bash
python3 - <<'PY'
import json, urllib.request, time
loki_url = "http://127.0.0.1:13100"
now = time.time_ns()
values = [[str(now + i * 1_000_000), json.dumps({
    "response_code": 401, "source_ip": "10.10.0.99",
    "method": "POST", "path": "/payments",
    "message": f"JWT invalid — brute force attempt #{i+1}"
})] for i in range(20)]
payload = {"streams": [{"stream": {
    "job": "envoy-access", "service": "api-gateway",
    "namespace": "financial", "response_code": "401", "source_ip": "10.10.0.99"
}, "values": values}]}
req = urllib.request.Request(f"{loki_url}/loki/api/v1/push",
    data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print("OK — 20 logs pushed, đợi Grafana alert ~60s")
PY
```

**Chuỗi sự kiện:**
1. 20 log `response_code=401` vào Loki
2. Grafana alert "Brute Force Login (T1110.001)" → FIRING
3. SOAR webhook: `attack_type=brute_force, severity=high` → case `pending_approval`
4. Email gửi admin với tên alert **"Brute Force Login (T1110.001)"** và 4 nút: `Thu hồi phiên`, `Chặn IP nguồn`, `Cô lập dịch vụ`, `Chỉ theo dõi`
5. Admin chọn hành động tại email hoặc web portal `/security`

**Verify kết quả:**
```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=[c for c in json.load(sys.stdin) if c.get('attack_type')=='brute_force']
for c in cases[-3:]:
    print(c['ts'][:19], '|', c['status'], '|', c['playbook'])"
```

**Không cần restore** nếu chỉ chọn `revoke_user_sessions` — chỉ session bị xóa, service không bị tác động.

---

### 8.2 — Kịch bản 2: Lateral Movement (T1021.007)

**Mô tả:** Service bên ngoài trust domain dùng SVID không hợp lệ → OPA từ chối → SOAR tạo case `pending_approval, critical` → email admin → admin chọn `isolate_workload` (cô lập payment-service).

**Grafana query:** `{job="opa-decisions", opa_result="false", attack_scenario="lateral_movement"} [5m]`

> **Tại sao không thể tấn công thực:** Cần service chạy với SPIFFE SVID ngoài trust domain — đòi hỏi kiểm soát SPIRE agent. Inject log mô phỏng hành vi này.

```bash
python3 - <<'PY'
import json, urllib.request, time
loki_url = "http://127.0.0.1:13100"
now = time.time_ns()
values = [[str(now + i * 1_000_000), json.dumps({
    "event_type": "lateral_movement_attempt",
    "opa_result": "false",
    "svid": "spiffe://external.attacker/malicious-service",
    "destination": "core-banking",
    "source_ip": "10.10.1.99",
    "message": f"SVID outside trust domain ztlab.local — OPA deny #{i+1}"
})] for i in range(5)]
payload = {"streams": [{"stream": {
    "job": "opa-decisions", "opa_result": "false",
    "attack_scenario": "lateral_movement",
    "service": "payment-service", "namespace": "financial"
}, "values": values}]}
req = urllib.request.Request(f"{loki_url}/loki/api/v1/push",
    data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print("OK — 5 logs pushed, đợi Grafana alert ~60s")
PY
```

**Chuỗi sự kiện:**
1. 5 log `opa_result=false, attack_scenario=lateral_movement` push vào Loki
2. Grafana alert "Lateral Movement — Invalid SVID (T1021.007)" → FIRING (phân biệt với KB3 nhờ stream label)
3. SOAR: `attack_type=lateral_movement, severity=critical` → case `pending_approval`
4. Email admin với tên alert **"Lateral Movement — Invalid SVID (T1021.007)"** và 5 nút: `Cô lập dịch vụ`, `Hạn chế lưu lượng ra`, `Chặn IP nguồn`, `Thu hồi phiên`, `Chỉ theo dõi`
5. Admin chọn → nếu `Cô lập dịch vụ`: payment-service selector bị patch → 503

**Verify sau khi admin chọn isolate:**
```bash
kubectl --context ctx-aws get svc payment-service -n financial \
  -o jsonpath='{.spec.selector}' && echo
# Kết quả sau isolate: {"app":"payment-service","soar.ztlab.io/isolated":"true"}
```

**Restore:**
```bash
bash scripts/run-demo.sh --restore
```

---

### 8.3 — Kịch bản 3: Fraud Gate Bypass (T1078.004)

**Mô tả:** Cố gọi `/transactions/execute` không có `x-fraud-gate: passed` → OPA từ chối → SOAR tạo case `pending_approval, critical` → email admin → admin chọn `isolate_workload`.

**Grafana query:** `{job="opa-decisions", opa_result="false", attack_scenario="fraud_gate_bypass"} [5m]`

```bash
python3 - <<'PY'
import json, urllib.request, time
loki_url = "http://127.0.0.1:13100"
now = time.time_ns()
values = [[str(now + i * 1_000_000), json.dumps({
    "event_type": "opa_deny",
    "opa_result": "false",
    "request_path": "/transactions/execute",
    "source_ip": "10.10.1.77",
    "reason": "fraud_gate header missing or tampered",
    "message": f"OPA DENY fraud_gate_bypass path=/transactions/execute #{i+1}"
})] for i in range(5)]
payload = {"streams": [{"stream": {
    "job": "opa-decisions", "opa_result": "false",
    "attack_scenario": "fraud_gate_bypass",
    "request_path": "/transactions/execute",
    "service": "payment-service", "namespace": "financial"
}, "values": values}]}
req = urllib.request.Request(f"{loki_url}/loki/api/v1/push",
    data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print("OK — 5 logs pushed, đợi Grafana alert ~60s")
PY
```

**Chuỗi sự kiện:**
1. 5 log `opa_result=false, attack_scenario=fraud_gate_bypass` push vào Loki
2. Grafana alert "Fraud Gate Bypass (T1078.004)" → FIRING (phân biệt với KB2 nhờ stream label `attack_scenario`)
3. SOAR: `attack_type=fraud_gate_bypass, severity=critical` → case `pending_approval`
4. Email admin với tên alert **"Fraud Gate Bypass (T1078.004)"** và 5 nút: `Cô lập dịch vụ`, `Hạn chế lưu lượng ra`, `Chặn IP nguồn`, `Thu hồi phiên`, `Chỉ theo dõi`
5. Admin chọn → nếu `Cô lập dịch vụ`: payment-service selector bị patch → 503

**OPA fraud gate logic:**

| Request đến core-banking | Kết quả |
|--------------------------|---------|
| POST /transactions/execute, không có `x-fraud-gate` | **DENY 403** |
| POST /transactions/execute, `x-fraud-gate=passed`, score < 75 | ALLOW |
| POST /transactions/execute, `x-fraud-gate=passed`, score ≥ 75 | **DENY** |
| GET /transactions/* (không phải /execute) | ALLOW |

**Restore:**
```bash
bash scripts/run-demo.sh --restore
```

---

### 8.4 — Kịch bản 4: Data Exfiltration (T1041)

**Mô tả:** Response kích thước bất thường (>1 MB) từ core-banking → Grafana detect → SOAR tạo case `pending_approval, high` → admin chọn `restrict_egress` → scale core-banking xuống 0 replica.

**Grafana query:** `{job="envoy-access"} | json | bytes_sent > 1048576 [5m]`

```bash
python3 - <<'PY'
import json, urllib.request, time
loki_url = "http://127.0.0.1:13100"
now = time.time_ns()
values = [[str(now + i * 1_000_000), json.dumps({
    "bytes_sent": 3100000,
    "response_code": 200,
    "path": "/accounts/export",
    "source_ip": "10.10.4.88",
    "message": f"Abnormal response size 3.1MB — possible data exfiltration #{i+1}"
})] for i in range(5)]
payload = {"streams": [{"stream": {
    "job": "envoy-access",
    "service": "core-banking", "namespace": "financial"
}, "values": values}]}
req = urllib.request.Request(f"{loki_url}/loki/api/v1/push",
    data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print("OK — 5 logs pushed (bytes_sent=3100000), đợi Grafana alert ~60s")
PY
```

**Chuỗi sự kiện:**
1. 5 log `bytes_sent=3100000` (JSON body) push vào Loki
2. Grafana alert "Data Exfiltration — Large Response (T1041)" → FIRING
3. SOAR: `attack_type=large_response, severity=high` → case `pending_approval`
4. Email admin với tên alert **"Data Exfiltration — Large Response (T1041)"** và 5 nút: `Hạn chế lưu lượng ra`, `Cách ly workload`, `Cô lập dịch vụ`, `Chặn IP nguồn`, `Chỉ theo dõi`
5. Admin chọn `Hạn chế lưu lượng ra` → core-banking (OpenStack) scale xuống 0 replicas

**Verify sau khi admin duyệt:**
```bash
kubectl --context ctx-openstack get deployment core-banking -n financial \
  -o jsonpath='{.spec.replicas}' && echo
# Kết quả sau restrict_egress: 0
```

**Restore:**
```bash
bash scripts/run-demo.sh --restore
```

---

### Restore toàn bộ sau demo

```bash
# Cách nhanh nhất
bash scripts/run-demo.sh --restore

# Hoặc thủ công:
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
kubectl --context ctx-aws scale deployment api-gateway -n financial --replicas=1
kubectl --context ctx-openstack scale deployment core-banking -n financial --replicas=1
python3 tests/seed_db.py
```

---

### Lưu ý quan trọng khi demo

> **SOAR tạo case pending_approval, KHÔNG tự execute:** Với `SOAR_HITL_SEVERITY=high`, tất cả KB1-KB4 (severity high/critical) đều yêu cầu admin duyệt. Admin nhận email hoặc vào `http://localhost:18081/security` để chọn hành động.

> **Grafana eval interval:** Alert rules eval mỗi 1 phút — sau khi push log vào Loki, chờ tối đa 60-90 giây để alert fire và SOAR tạo case.

> **Dedup:** SOAR dedup theo fingerprint 10 phút. Nếu inject nhiều lần trong 10 phút, chỉ tạo 1 case.

---

## 9. SOAR Engine & HITL

**URL:** http://localhost:8091  
**Config hiện tại:** `auto_execute=true` · `min_severity=medium` · `hitl_severity=high` · `dry_run=false`

### Cơ chế hoạt động

| Nguồn phát hiện | Cơ chế |
|-----------------|--------|
| **Heuristic Poller** | Poll Loki mỗi 60s, 9 regex rules (brute_force, lateral_movement, fraud_gate_bypass, cryptomining...) |
| **Grafana Webhook** | Grafana alert fire → POST `/grafana-webhook` → SOAR parse `attack_type` từ alert label |

| Severity | Hành động SOAR |
|----------|----------------|
| low, medium | Auto-execute playbook ngay |
| high, critical | Tạo case `pending_approval` → gửi email HITL → đợi admin |

### HITL Email & Web Portal

Khi SOAR tạo case `pending_approval`, admin nhận email tại voha2005@gmail.com với:
- Tên alert rõ ràng (VD: "Brute Force Login (T1110.001)") — không hiển thị "Kịch bản N" hay "Heuristic:"
- Thông tin case (attack_type, severity, source_ip, log evidence)
- Các nút hành động tùy theo loại tấn công (4-5 nút, màu khác nhau theo mức độ nguy hiểm) — admin tự chọn
- Click nút → link xác thực HMAC → SOAR thực thi playbook đã chọn

Admin cũng có thể duyệt qua **web portal**:
1. Đăng nhập `http://localhost:18081` bằng account có role `security-admin`
2. Vào `/security` → tab **SOAR Cases** → lọc "Chờ duyệt"
3. Click **⚡ Xử lý** trên case → chọn playbook → SOAR thực thi

### Playbooks & Attack type mapping

| attack_type | Tên alert hiển thị | Playbooks cho admin chọn | Target | Context |
|-------------|-------------------|--------------------------|--------|---------|
| `brute_force` | Brute Force Login (T1110.001) | revoke_user_sessions, block_source_ip, isolate_workload, monitor_only | api-gateway | ctx-aws |
| `credential_stuffing` | Credential Stuffing (T1110.004) | revoke_user_sessions, block_source_ip, isolate_workload, monitor_only | api-gateway | ctx-aws |
| `jwt_replay` | JWT Token Replay (T1539) | revoke_user_sessions, block_source_ip, isolate_workload, monitor_only | api-gateway | ctx-aws |
| `fraud_gate_bypass` | Fraud Gate Bypass (T1078.004) | isolate_workload, restrict_egress, block_source_ip, revoke_user_sessions, monitor_only | payment-service | ctx-aws |
| `lateral_movement` | Lateral Movement — Invalid SVID (T1021.007) | isolate_workload, restrict_egress, block_source_ip, revoke_user_sessions, monitor_only | payment-service | ctx-aws |
| `cryptomining` | Cryptomining Detected (T1496) | quarantine_workload, isolate_workload, block_source_ip, monitor_only | transaction-service | ctx-openstack |
| `port_scan` | Port Scan Detected (T1046) | block_source_ip, isolate_workload, monitor_only | api-gateway | ctx-aws |
| `exploit_probe` | Exploit Probe / Injection (T1203) | block_source_ip, isolate_workload, restrict_egress, monitor_only | api-gateway | ctx-aws |
| `large_response` | Data Exfiltration — Large Response (T1041) | restrict_egress, quarantine_workload, isolate_workload, block_source_ip, monitor_only | core-banking | ctx-openstack |
| `access_denied` | Access Denied Spike (T1078) | block_source_ip, isolate_workload, monitor_only | api-gateway | ctx-aws |

### Mô tả playbook

| Playbook | Hành động K8s |
|----------|--------------|
| `isolate_workload` | Patch Service selector → pod không nhận traffic (Service vẫn tồn tại, pod vẫn chạy) |
| `restrict_egress` | Scale Deployment → 0 replica (toàn bộ pod dừng) |
| `quarantine_workload` | Scale Deployment → 0 replica |
| `block_source_ip` | Tạo NetworkPolicy + Redis DB0 blocklist 24h |
| `revoke_user_sessions` | Gọi Keycloak Admin API xóa session của user |
| `monitor_only` | Không thực thi — chỉ ghi nhận |

### API endpoints

```bash
curl http://localhost:8091/health                                     # trạng thái + case count
curl http://localhost:8091/cases                                      # tất cả cases
curl http://localhost:8091/cases/{case_id}                           # chi tiết 1 case
curl -X POST http://localhost:8091/cases/{case_id}/rollback          # restore workload
curl -X POST http://localhost:8091/cases/{case_id}/execute-playbook \
  -H "Content-Type: application/json" -d '{"playbook":"block_source_ip"}'  # admin chọn playbook
curl http://localhost:8091/blocked-ips                                # IPs đang bị block
curl -X POST http://localhost:8091/blocked-ips/1.2.3.4               # block thủ công
curl -X DELETE http://localhost:8091/blocked-ips/1.2.3.4             # unblock
```

### Xem recent cases

```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=json.load(sys.stdin)
print(f'Total: {len(cases)} cases')
for c in cases[-10:]:
    icon='✓' if c['status'] in ('executed','dry_run') else ('⏳' if c['status']=='pending_approval' else '✗')
    print(icon, c['ts'][:19], '|', c['attack_type'][:20].ljust(20),
          '|', c['severity'][:8].ljust(8), '|', c['playbook'][:25].ljust(25),
          '|', c['status'])"
```

### Lưu ý

- Grafana `repeat_interval=1h` — cùng 1 alert không gửi lại SOAR trong 1 giờ
- Sau `isolate_workload` (payment-service): trả 503 đến khi restore
- Sau `restrict_egress` (core-banking OpenStack): payment flow lỗi ở bước ghi sổ cái
- SOAR lưu cases vào file `/data/cases.jsonl` trong pod — không mất khi pod restart nếu có PersistentVolume

---

## 10. Grafana — Dashboards & Alerts

**URL:** http://localhost:3000 · Login: admin / ZTALab2026!  
**Log retention:** 90 ngày (Loki)

### Dashboards (folder: ZTLab)

| Dashboard | Mô tả |
|-----------|-------|
| ZTLab — Zero Trust Security Overview | OPA allow/deny rate, JWT failures, fraud score |
| ZTLab Security Overview | Panels tóm tắt cross-cloud |
| ZTLab Full Logs | Envoy access logs toàn bộ hệ thống |
| Envoy Access Logs | HTTP matrix, latency P50/P95/P99 |
| OPA Decision Log | Allow/deny rate, top denied paths |
| ZTLab AI SIEM SOAR | Cases, playbooks, IPs blocked, live log stream |

### Alert Rules (folder: ZTLab)

| Alert | Severity | attack_type → Playbook đề xuất |
|-------|----------|-------------------------------|
| Brute Force Login (T1110.001) | high | brute_force → revoke_user_sessions |
| Lateral Movement — Invalid SVID (T1021.007) | critical | lateral_movement → isolate_workload |
| Fraud Gate Bypass (T1078.004) | critical | fraud_gate_bypass → isolate_workload |
| Data Exfiltration — Large Response (T1041) | high | large_response → restrict_egress |
| Access Denied Spike | high | access_denied → block_source_ip |
| SOAR Engine Health | warning | — (monitor only) |

Tất cả alert `category=security` → webhook `POST soar-engine/grafana-webhook` → SOAR tạo case `pending_approval`.

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

# Restore nhanh
bash scripts/run-demo.sh --restore

# Hoặc patch trực tiếp
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

### Payment trả lỗi — core-banking trên OpenStack bị scale=0 (sau KB4)

```bash
# Kiểm tra
kubectl --context ctx-openstack get deployment core-banking -n financial \
  -o jsonpath='{.spec.replicas}' && echo
# Nếu 0:

bash scripts/run-demo.sh --restore
# Hoặc:
kubectl --context ctx-openstack scale deployment core-banking -n financial --replicas=1
kubectl --context ctx-openstack rollout status deployment core-banking -n financial
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
# Phải OK cả 3 — nếu FAIL: kiểm tra OpenStack VMs đã ACTIVE và WireGuard đang chạy

# 3. Kiểm tra WireGuard trên os-gateway
ssh -i ~/.ssh/ztlab-key ubuntu@10.10.10.188 'sudo wg show wg0'
```

### JWT invalid token — 401 từ api-gateway

```bash
# Lấy token mới từ Keycloak
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token','ERR'))")
echo "${TOKEN:0:30}..."

# Kiểm tra issuer trong token
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

### Grafana alert firing liên tục (false positive từ logs cũ)

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

### SOAR case mắc kẹt ở pending_approval sau pod restart

Sau khi soar-engine pod restart, in-memory HITL queue bị xóa nhưng case file vẫn còn. Case vẫn hiển thị `pending_approval`. Admin có thể vào web portal chọn hành động bình thường — endpoint `execute-playbook` đọc từ `CASES` dict (loaded từ disk), không cần HITL queue.

```bash
# Xem pending cases
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
for c in json.load(sys.stdin):
    if c.get('status')=='pending_approval':
        print(c['case_id'], '|', c['attack_type'], '|', c['severity'])"

# Thực thi playbook thủ công cho 1 case
curl -s -X POST "http://localhost:8091/cases/<CASE_ID>/execute-playbook" \
  -H "Content-Type: application/json" \
  -d '{"playbook":"block_source_ip"}'
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
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Dùng token
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:18080/accounts/ACC-1001
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:18080/transactions?account_id=ACC-1001&limit=5"
```

### Cập nhật code SOAR/web-portal (hot-patch qua ConfigMap)

Hệ thống dùng ConfigMap để mount code vào pod, không cần rebuild Docker image:

```bash
# Cập nhật soar-engine main.py
kubectl --context ctx-aws create configmap soar-main-patch \
  -n plg-stack --from-file=main.py=services/soar-engine/main.py \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -
kubectl --context ctx-aws rollout restart deployment/soar-engine -n plg-stack

# Cập nhật web-portal main.py
kubectl --context ctx-aws create configmap patch-web-portal \
  -n financial --from-file=main.py=services/web-portal/main.py \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -

# Cập nhật web-portal security.html
kubectl --context ctx-aws create configmap patch-web-portal-tmpl \
  -n financial --from-file=security.html=services/web-portal/templates/security.html \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -

kubectl --context ctx-aws rollout restart deployment/web-portal -n financial
```

---

*Hệ thống implement Zero Trust Architecture theo NIST SP 800-207: không có implicit trust, mọi request đều xác thực identity (JWT + SPIFFE SVID) và policy (OPA) trước khi được phép truy cập tài nguyên. Phát hiện bất thường kết hợp heuristic log analysis + Grafana alerting, phản ứng qua SOAR với vòng lặp Human-in-the-Loop để đảm bảo oversight.*
