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
│   notification-service spiffe://ztlab.local/aws/notification-service   │
│   OPA             ext_authz gRPC port 9191                              │
│   Redis · PostgreSQL accounts · PostgreSQL transactions                 │
│                                                                          │
│ namespace: plg-stack                                                     │
│   Promtail (DaemonSet) → Loki (90 ngày) → Grafana                      │
│   SOAR Engine   (Grafana webhook → K8s playbook tự động)               │
│   Security Scorer   (anomaly window 15 phút · Redis)                   │
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

### Luồng phát hiện & phản ứng tự động

```
Log event (Envoy/OPA/app) → Promtail → Loki
  → Grafana alert fire (count_over_time query, eval 1 phút)
  → POST soar-engine/grafana-webhook
  → SOAR parse attack_type từ label alert
  → severity ≥ medium + auto_execute=true
  → chạy playbook ngay (isolate / block / restrict / revoke)
  → ghi case vào file /data/cases.jsonl
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
curl -s http://localhost:18081/health   # web-portal: {"status":"ok"}
curl -s http://localhost:18080/health   # api-gateway: jwks_keys_loaded≥1
curl -s http://localhost:8091/health    # soar-engine: dry_run=false, auto_execute=true
curl -s http://localhost:3000/api/health  # grafana: database=ok
curl -s http://localhost:13100/ready    # loki: ready
curl -s http://localhost:9090/-/healthy # prometheus: Prometheus Server is Healthy.
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

### Cách chạy demo

> **Về "tấn công thực" vs "inject log":**
> - **KB1** có thể tấn công thực bằng cách craft JWT giả → api-gateway xác thực signature thất bại → trả 401 → Envoy ghi log thật → Grafana alert fire.
> - **KB2, KB3, KB4** không thể tấn công thực từ bên ngoài (cần giả mạo SPIFFE SVID hoặc gọi trực tiếp internal service) → dùng inject log vào Loki để trigger Grafana alert.
> - Script `run-demo.sh` dùng inject log cho tất cả 4 kịch bản để đảm bảo tính đồng nhất và đáng tin cậy khi demo.

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

# Loop liên tục (Ctrl+C để dừng)
bash scripts/run-demo.sh --continuous
```

**Cách 2 — Thủ công từng kịch bản** (copy-paste nhanh bên dưới, không cần script)

---

### Lệnh tấn công thủ công (copy-paste nhanh)

> Mở Grafana `http://localhost:3000/alerting/list` để theo dõi alert FIRING và `http://localhost:8091/cases` để xem SOAR xử lý.

#### Chuẩn bị

```bash
bash scripts/run-demo.sh --restore
curl -s http://localhost:18080/health | python3 -c "import sys,json; d=json.load(sys.stdin); print('GW OK, jwks='+str(d['jwks_keys_loaded']))"
```

#### KB1 — Brute Force Login

```bash
# Craft JWT: payload hợp lệ nhưng signature giả
# OPA chỉ decode payload (không verify chữ ký) → cho qua → app kiểm tra chữ ký → 401
# Envoy ghi log response_code=401 → Promtail → Loki → Grafana alert
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
echo "Xong! Chờ ~60s rồi kiểm tra SOAR..."
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
kubectl --context ctx-aws get svc payment-service -n financial -o jsonpath='{.spec.selector}' && echo
bash scripts/run-demo.sh --restore
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
bash scripts/run-demo.sh --restore
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
echo -n "core-banking sau: " && kubectl --context ctx-openstack get deploy core-banking -n financial -o jsonpath='{.spec.replicas}' && echo
bash scripts/run-demo.sh --restore
```

#### Xem kết quả tổng hợp

```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=json.load(sys.stdin)
print(f'Tổng {len(cases)} cases. 4 mới nhất:')
for c in cases[-4:]:
    icon='✓' if c.get('status') in ('executed','dry_run') else '✗'
    print(f'  {icon} {c[\"attack_type\"]:25} → {c[\"playbook\"]:22} [{c[\"status\"]}]')"
```

---

### 8.1 — Kịch bản 1: Brute Force Login (T1110.001)

**Mô tả:** Kẻ tấn công gửi nhiều request JWT giả → OPA cho qua (chỉ decode payload, không verify signature) → api-gateway xác thực signature thất bại → trả 401 → Envoy ghi log thật → Grafana detect → SOAR revoke sessions.

**Grafana query:** `{job="envoy-access"} | json | response_code=401 [1m]`

#### Cách A — Tấn công thực (real traffic, tạo log thật trong Envoy)

```bash
# Craft JWT: payload hợp lệ nhưng signature giả
# OPA chỉ io.jwt.decode() không verify signature → cho qua
# App kiểm tra signature thật → trả 401 → Envoy log response_code=401
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

FAKE_JWT="\${HEADER}.\${PAYLOAD}.FAKESIGNATUREFAKESIGNATUREFAKESIG"

echo "Gửi 20 request brute force với JWT giả signature..."
for i in \$(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:18080/payments \
    -H "Authorization: Bearer \$FAKE_JWT" \
    -H "Content-Type: application/json" \
    -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1}'
done
echo ""
echo "Xong — 20 × 401 được ghi vào Envoy access log, Promtail sẽ đẩy vào Loki"
echo "Chờ Grafana eval interval ~60s để alert fire..."
```

> **Lưu ý:** Envoy ghi log với `"response_code":401` trong JSON body. Promtail scrape log này và đẩy vào Loki. Grafana alert query lọc `| json | response_code=401` sẽ detect sau tối đa 60s.

#### Cách B — Inject log vào Loki (đáng tin cậy hơn cho demo, không cần chờ Promtail)

```bash
# Push 20 log 401 vào Loki (response_code là stream label)
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
1. 20 log `response_code=401` vào Loki (từ Envoy thật hoặc inject trực tiếp)
2. Grafana alert "Kịch bản 1 — Brute Force Login" → FIRING (count 401 [1m] ≥ ngưỡng)
3. SOAR webhook: `attack_type=brute_force` → playbook `revoke_user_sessions`
4. SOAR gọi Keycloak Admin API xóa tất cả active session

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

**Mô tả:** Service bên ngoài trust domain dùng SVID không hợp lệ → OPA từ chối → SOAR isolate payment-service.

**Grafana query:** `{job="opa-decisions", opa_result="false", attack_scenario="lateral_movement"} [5m]`

> **Tại sao không thể tấn công thực từ bên ngoài:** Để trigger KB2 thật sự, kẻ tấn công cần có một service đang chạy với SPIFFE SVID từ trust domain ngoài (`spiffe://external.attacker/...`). Điều này đòi hỏi kiểm soát SPIRE agent nội bộ — không thể làm từ client bên ngoài. Thay vào đó, inject log mô phỏng hành vi này vào Loki để trigger alert. Label `attack_scenario=lateral_movement` phân biệt KB2 với các OPA deny thông thường từ KB1.

```bash
# Push 5 log OPA deny vào Loki (attack_scenario=lateral_movement là stream label phân biệt)
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
1. 5 log với stream labels `opa_result=false` + `attack_scenario=lateral_movement` push vào Loki
2. Grafana alert "Kịch bản 2 — Lateral Movement" → FIRING (chỉ match log KB2, không nhầm KB1)
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
bash scripts/run-demo.sh --restore
# Hoặc patch trực tiếp:
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'
```

---

### 8.3 — Kịch bản 3: Fraud Gate Bypass (T1078.004)

**Mô tả:** Kẻ tấn công cố gọi `/transactions/execute` mà không có header `x-fraud-gate: passed` → OPA từ chối → SOAR isolate payment-service.

**Grafana query:** `{job="opa-decisions", opa_result="false", attack_scenario="fraud_gate_bypass"} [5m]`

> **Tại sao không thể tấn công thực từ bên ngoài:** Endpoint `/transactions/execute` nằm trên core-banking (OpenStack), không được expose qua api-gateway (chỉ có `/payments`, `/accounts`, `/transactions`). Kẻ tấn công từ ngoài không có đường gọi trực tiếp vào core-banking. Thực tế, fraud gate bypass xảy ra khi service nội bộ bị compromise và cố bypass payment-service. Label `attack_scenario=fraud_gate_bypass` phân biệt KB3 với KB2.

```bash
# Push 5 log OPA deny vào Loki (attack_scenario=fraud_gate_bypass là stream label phân biệt)
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

**OPA fraud gate logic (kiểm soát request đến core-banking):**

| Request đến core-banking | Kết quả |
|--------------------------|---------|
| POST /transactions/execute, không có `x-fraud-gate` | **DENY 403** |
| POST /transactions/execute, `x-fraud-gate=passed`, score < 75 | ALLOW |
| POST /transactions/execute, `x-fraud-gate=passed`, score ≥ 75 | **DENY** |
| GET /transactions/* (không phải /execute) | ALLOW |

**Chuỗi sự kiện:**
1. 5 log với stream labels `opa_result=false` + `attack_scenario=fraud_gate_bypass` push vào Loki
2. Grafana alert "Kịch bản 3 — Fraud Gate Bypass" → FIRING (chỉ match log KB3, không nhầm KB2)
3. SOAR: `attack_type=fraud_gate_bypass` → playbook `isolate_workload` (severity=critical)
4. K8s Service selector của payment-service bị patch → 503

**Restore sau demo:**
```bash
bash scripts/run-demo.sh --restore
```

---

### 8.4 — Kịch bản 4: Data Exfiltration (T1041)

**Mô tả:** Response có kích thước bất thường (>1 MB) từ core-banking bị Envoy ghi log → Grafana detect → SOAR scale core-banking (OpenStack) xuống 0 replica.

**Grafana query:** `{job="envoy-access"} | json | bytes_sent > 1048576 [5m]`

> **Tại sao không thể tấn công thực:** Để trigger KB4 thật, cần có endpoint trả response ≥ 1MB (core-banking `/accounts/export` trả toàn bộ dữ liệu). Trong môi trường demo với dữ liệu seed nhỏ, response thực tế chỉ vài KB — không đủ để trigger alert. Dùng inject log để mô phỏng scenario thực tế khi có lượng dữ liệu lớn.

```bash
# Push 5 log envoy-access với bytes_sent lớn vào Loki
# bytes_sent nằm trong JSON body (parsed bởi | json), KHÔNG phải stream label
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
1. 5 log với `bytes_sent=3100000` (trong JSON body) push vào Loki
2. Grafana alert "Kịch bản 4 — Data Exfiltration Suspect" → FIRING
3. SOAR: `attack_type=large_response` → playbook `restrict_egress`
4. SOAR scale Deployment `core-banking` trên **ctx-openstack** xuống **0 replica** — dịch vụ ngân hàng cốt lõi ngừng hoạt động

**Verify:**
```bash
kubectl --context ctx-openstack get deployment core-banking -n financial \
  -o jsonpath='{.spec.replicas}' && echo
# Kết quả sau restrict_egress: 0
```

**Restore sau demo:**
```bash
bash scripts/run-demo.sh --restore
# Hoặc scale trực tiếp:
kubectl --context ctx-openstack scale deployment core-banking -n financial --replicas=1
kubectl --context ctx-openstack rollout status deployment core-banking -n financial
```

---

### Restore toàn bộ sau demo

```bash
# Cách nhanh nhất — restore tất cả bằng script
bash scripts/run-demo.sh --restore

# Hoặc thủ công từng bước:

# Restore payment-service (KB2, KB3)
kubectl --context ctx-aws patch svc payment-service -n financial \
  --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]'

# Restore api-gateway (nếu bị scale=0)
kubectl --context ctx-aws scale deployment api-gateway -n financial --replicas=1

# Restore core-banking trên OpenStack (KB4)
kubectl --context ctx-openstack scale deployment core-banking -n financial --replicas=1

# Reset số dư
python3 tests/seed_db.py
```

---

### Lưu ý quan trọng khi demo

> **SOAR auto-isolate payment-service:** Nếu hệ thống đang có logs cũ trong Loki từ session trước, Grafana alert có thể fire và SOAR sẽ tự isolate payment-service. Dấu hiệu: `GET /payments` → 503, và `kubectl get svc payment-service` thấy selector có `soar.ztlab.io/isolated`. Trước khi demo, luôn chạy `bash scripts/run-demo.sh --restore`.

> **Grafana eval interval:** Alert rules eval mỗi 1 phút — sau khi push log vào Loki, chờ tối đa 60-90 giây để alert fire và SOAR tạo case.

---

## 9. SOAR Engine

**URL:** http://localhost:8091  
**Config hiện tại:** `auto_execute=true` · `min_severity=medium` · `dry_run=false`

### Playbooks & Attack type mapping

| attack_type | Playbook | Target | Context |
|-------------|---------|--------|---------|
| `brute_force` | `revoke_user_sessions` | api-gateway | ctx-aws |
| `lateral_movement` | `isolate_workload` | payment-service | ctx-aws |
| `fraud_gate_bypass` | `isolate_workload` | payment-service | ctx-aws |
| `large_response` | `restrict_egress` | core-banking | ctx-openstack |
| `access_denied` | `block_source_ip` | api-gateway | ctx-aws |
| `port_scan` | `block_source_ip` | api-gateway | ctx-aws |
| `cryptomining` | `quarantine_workload` | transaction-service | ctx-openstack |

### Mô tả playbook

| Playbook | Hành động K8s |
|----------|--------------|
| `isolate_workload` | Patch Service selector → pod không nhận traffic (Service vẫn tồn tại, pod vẫn chạy) |
| `restrict_egress` | Scale Deployment → 0 replica (toàn bộ pod dừng) |
| `quarantine_workload` | Scale Deployment → 0 replica |
| `block_source_ip` | Tạo NetworkPolicy + Redis DB0 blocklist 24h |
| `revoke_user_sessions` | Gọi Keycloak Admin API xóa session của user |

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

| Alert | Severity | attack_type → Playbook |
|-------|----------|------------------------|
| Kịch bản 1 — Brute Force Login | high | brute_force → revoke_user_sessions |
| Kịch bản 2 — Lateral Movement | critical | lateral_movement → isolate_workload |
| Kịch bản 3 — Fraud Gate Bypass | critical | fraud_gate_bypass → isolate_workload |
| Kịch bản 4 — Data Exfiltration | high | large_response → restrict_egress |
| Access Denied Spike | high | access_denied → block_source_ip |
| SOAR Engine Health | warning | — (monitor only) |

Tất cả alert `category=security` → webhook `POST soar-engine/grafana-webhook`.

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
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test%40123%21&scope=openid" \
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
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:18080/transactions?account_id=ACC-1001&limit=5"
```

---

*Hệ thống implement Zero Trust Architecture theo NIST SP 800-207: không có implicit trust, mọi request đều xác thực identity (JWT + SPIFFE SVID) và policy (OPA) trước khi được phép truy cập tài nguyên.*
