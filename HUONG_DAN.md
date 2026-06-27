# ZTLab — Hướng Dẫn Vận Hành & Demo

> **Đồ án**: Zero Trust-based Security Detection and Response for Microservices in Multi-Cloud  
> **Sinh viên**: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> **GVHD**: ThS. Đỗ Thị Phương Uyên · Môn: NT114.Q21.ANTT  
> **Email nhận cảnh báo HITL**: voha2005@gmail.com

---

## Mục lục

1. [Kiến trúc tổng quan](#1-kiến-trúc-tổng-quan)
2. [Tài khoản & credentials](#2-tài-khoản--credentials)
3. [Cổng & URL truy cập](#3-cổng--url-truy-cập)
4. [Khởi động hệ thống sau khi restart máy](#4-khởi-động-hệ-thống-sau-khi-restart-máy)
5. [Kiểm tra sức khoẻ toàn hệ thống](#5-kiểm-tra-sức-khoẻ-toàn-hệ-thống)
6. [Chuẩn bị trước khi test kịch bản](#6-chuẩn-bị-trước-khi-test-kịch-bản)
7. [KB1 — Brute Force Login (T1110.001)](#7-kb1--brute-force-login-t1110001)
8. [KB2 — Fraud Gate Bypass (T1078.004)](#8-kb2--fraud-gate-bypass-t1078004)
9. [KB3 — Lateral Movement via Invalid SVID (T1021.007)](#9-kb3--lateral-movement-via-invalid-svid-t1021007)
10. [KB4 — Data Exfiltration / Large Response (T1041)](#10-kb4--data-exfiltration--large-response-t1041)
11. [KB5 — Access Denied Spike / OPA RBAC (T1078)](#11-kb5--access-denied-spike--opa-rbac-t1078)
12. [KB6 — Privilege Escalation in Container (T1611)](#12-kb6--privilege-escalation-in-container-t1611)
13. [Chạy toàn bộ 6 kịch bản cùng lúc](#13-chạy-toàn-bộ-6-kịch-bản-cùng-lúc)
14. [SOAR Engine — Phê duyệt & quản lý case](#14-soar-engine--phê-duyệt--quản-lý-case)
15. [Grafana — Alert rules & dashboards](#15-grafana--alert-rules--dashboards)
16. [Restore hệ thống về trạng thái bình thường](#16-restore-hệ-thống-về-trạng-thái-bình-thường)
17. [Demo log thực tế — Envoy, OPA, SPIRE/SPIFFE](#17-demo-log-thực-tế--envoy-opa-spirespiffe)
18. [Xử lý sự cố thường gặp](#18-xử-lý-sự-cố-thường-gặp)

---

## 1. Kiến trúc tổng quan

```
                     ┌─── Zero Trust Control Plane ─────────────────────────┐
User/Browser ──→ Keycloak (8180)   ← xác thực identity (JWT)
                      │
                      ↓ JWT
              API Gateway (18080)  ← enforce: OPA policy + Envoy mTLS
                      │
           ┌──────────┴───────────┐
           ↓                      ↓
     payment-service         financial-service
     (OPA fraud gate)        (SPIFFE/SVID auth)
           │
           ↓  (multi-cloud → OpenStack)
     core-banking-service
           │
           └─── Envoy sidecar → Loki (13100) ← ghi access log
                                     │
                               Grafana (3000) ← evaluate 6 alert rules
                                     │ webhook (simulate)
                               SOAR Engine (8091) ← tạo case, gửi email HITL
                                     │ pending_approval
                               Web Portal (18081) ← admin phê duyệt → playbook

AI Analyzer (18082): DISABLED — SOAR_WEBHOOK_URL="" (standalone scoring only)
```

### Detection & Response Flow

```
[Tấn công]
      │
      ├─ Layer 1 — Enforcement THẬT (Zero Trust blocks):
      │    KB1: Keycloak từ chối 401 × 20 (brute force)
      │    KB2: OPA fraud gate → HTTP 403, fraud_score=75, verdict=block
      │    KB3: API Gateway từ chối SVID fake → HTTP 403
      │    KB5: OPA RBAC từ chối POST /payments → HTTP 403 (merchant01 thiếu role)
      │    KB6: kubectl exec → uid=0, CapEff=0xa80425fb, /etc/shadow readable
      │
      ├─ Layer 2 — Detection Pipeline:
      │    Script inject log → Loki
      │    Grafana rule evaluate (mỗi 1 phút)
      │    Script simulate Grafana webhook → SOAR
      │
      └─ Layer 3 — Response HITL:
           SOAR tạo case (pending_approval)
           Email → voha2005@gmail.com
           Admin phê duyệt qua Web Portal
           Playbook thực thi (scale=0, block IP, revoke session...)
```

---

## 2. Tài khoản & credentials

| Dịch vụ | Username | Password | Role / Ghi chú |
|---|---|---|---|
| **Keycloak Admin Console** | admin | ztlab-admin-2026 | Quản trị realm ztlab |
| **Grafana** | admin | ZTALab2026! | Admin full access |
| **Web Portal (demo)** | analyst01 | Test1234! | security-analyst + security-admin |
| **Web Portal / API** | testuser01 | Test1234! | financial-read + financial-write |
| **Web Portal / API** | merchant01 | Test1234! | financial-read ONLY (dùng cho KB5) |
| **pgAdmin** | admin@ztlab.com | ztlab2026 | Xem database |

---

## 3. Cổng & URL truy cập

| Dịch vụ | URL | Ghi chú |
|---|---|---|
| **Web Portal** | http://localhost:18081 | Login: /login |
| **Security Dashboard** | http://localhost:18081/security | analyst01 / Test1234! |
| **API Gateway** | http://localhost:18080 | REST API financial |
| **Keycloak** | http://localhost:8180/admin | Admin Console |
| **Grafana** | http://localhost:3000 | Alert rules, Loki dashboards |
| **SOAR Engine** | http://localhost:8091 | /cases, /health, /blocked-ips |
| **Loki** | http://localhost:13100 | Log aggregation |
| **Prometheus** | http://localhost:9090 | Metrics |
| **pgAdmin** | http://localhost:5050 | PostgreSQL UI |
| **RedisInsight** | http://localhost:5540 | Redis (blocked IPs, sessions) |

---

## 4. Khởi động hệ thống sau khi restart máy

Thực hiện **đúng thứ tự** sau khi khởi động lại máy hoặc VM:

### Bước 1 — Kiểm tra SSH tunnel đến VMs

```bash
bash scripts/k8s-tunnel.sh status
```

Nếu tunnel chưa bật:
```bash
bash scripts/k8s-tunnel.sh up all
```

Xác nhận:
```bash
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

Output mong đợi:
```
NAME        STATUS   ROLES                  AGE
aws-k3s-0   Ready    control-plane,master   Xd
```

### Bước 2 — Bật port-forward cho tất cả UI

```bash
bash scripts/open-admin-uis.sh
```

Output mong đợi:
```
[ OK ] Keycloak               → http://localhost:8180  (PID ...)
[ OK ] API Gateway            → http://localhost:18080 (PID ...)
[ OK ] Web Portal             → http://localhost:18081 (PID ...)
[ OK ] Grafana                → http://localhost:3000  (PID ...)
[ OK ] Loki                   → http://localhost:13100 (PID ...)
[ OK ] SOAR Engine            → http://localhost:8091  (PID ...)
[ OK ] AI Analyzer            → http://localhost:18082 (PID ...)
[ OK ] Security Scorer        → http://localhost:18092 (PID ...)
[ OK ] Prometheus             → http://localhost:9090  (PID ...)
[ OK ] pgAdmin                → http://localhost:5050  (PID ...)
[ OK ] RedisInsight           → http://localhost:5540  (PID ...)
```

Kiểm tra trạng thái:
```bash
bash scripts/open-admin-uis.sh status
```

Nếu port-forward bị stuck (daemon=yes nhưng listen=no):
```bash
bash scripts/open-admin-uis.sh stop
bash scripts/open-admin-uis.sh
```

### Bước 3 — Kiểm tra sức khoẻ nhanh

```bash
bash scripts/health-check.sh
```

Cảnh báo `[WARN]` về AI Analyzer là bình thường (đã disabled).

### Bước 4 — Restore services về trạng thái bình thường

```bash
bash scripts/run-demo.sh --restore
```

### Bước 5 — Xác nhận API Gateway phản hồi

```bash
curl -s http://localhost:18080/health | python3 -m json.tool
```

---

## 5. Kiểm tra sức khoẻ toàn hệ thống

```bash
# Tổng hợp health check
bash scripts/health-check.sh

# Kiểm tra thủ công từng dịch vụ
curl -s http://localhost:8180/realms/ztlab/.well-known/openid-configuration \
  | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['issuer'])"

curl -s http://localhost:18080/health

curl -s http://localhost:8091/health \
  | python3 -c "import sys,json; print('SOAR:', json.load(sys.stdin)['status'])"

curl -s http://localhost:13100/ready && echo "Loki: ready"

curl -s -u admin:ZTALab2026! http://localhost:3000/api/health \
  | python3 -c "import sys,json; print('Grafana:', json.load(sys.stdin)['database'])"
```

### Kiểm tra pods K8s

```bash
kubectl --context ctx-aws get pods -n financial
kubectl --context ctx-aws get pods -n identity
kubectl --context ctx-aws get pods -n plg-stack
kubectl --context ctx-openstack get pods -n financial
```

Tất cả pods phải ở trạng thái `Running`. Nếu có pod `CrashLoopBackOff`:
```bash
kubectl --context ctx-aws logs -n financial deployment/api-gateway --tail=50
```

---

## 6. Chuẩn bị trước khi test kịch bản

```bash
# 1. Restore tất cả services
bash scripts/run-demo.sh --restore

# 2. Kiểm tra 4 dịch vụ cốt lõi
curl -s http://localhost:8091/health | grep -q '"status":"ok"' && echo "SOAR OK" || echo "SOAR FAIL"
curl -s http://localhost:13100/ready && echo "Loki OK" || echo "Loki FAIL"
curl -s http://localhost:18080/health >/dev/null && echo "API GW OK" || echo "API GW FAIL"
curl -s http://localhost:8180/realms/ztlab/.well-known/openid-configuration >/dev/null \
  && echo "Keycloak OK" || echo "Keycloak FAIL"
```

> **Lưu ý**: Script chỉ sinh traffic thật và inject log vào Loki. **Case trong Web Portal được tạo bởi Grafana real alert** (~1 phút sau khi script kết thúc). SOAR giới hạn 1 case mỗi attack_type trong 5 phút — nếu chạy cùng kịch bản 2 lần liên tiếp, chỉ 1 case được tạo.

**Mở 3 terminal song song để theo dõi**:

```bash
# Terminal 2 — watch SOAR cases mới nhất (refresh mỗi 3s)
watch -n3 'curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=json.load(sys.stdin)
print(f\"Tổng: {len(cases)} cases\")
for c in cases[-5:]:
    print(c[\"case_id\"][:35], \"|\", c[\"attack_type\"][:22], \"|\", c[\"status\"][:20], \"|\", c[\"playbook\"])
"'

# Terminal 3 — mở browser
# http://localhost:18081/security  (analyst01 / Test1234!)
# http://localhost:3000            (admin / ZTALab2026!)
```

---

## 7. KB1 — Brute Force Login (T1110.001)

### Zero Trust principle được chứng minh

**Continuous Verification**: Keycloak từ chối tất cả request có credential sai — không có implicit trust, không có grace period. 20/20 lần đăng nhập sai đều bị chặn HTTP 401.

### Tóm tắt

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1110.001 — Password Guessing |
| Enforcement THẬT | Keycloak chặn 20/20 lần sai mật khẩu → HTTP 400/401 |
| Detection | Log 401 inject vào Loki → Grafana rule → SOAR webhook |
| Playbook | `revoke_user_sessions` |
| HITL | Có — email + phê duyệt Web Portal |

---

### Bước 1: Chạy script

```bash
cd /home/deployer/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
bash tests/grafana_kb1_brute_force.sh
```

### Bước 2: Output terminal mong đợi

```
[KB1_brute_force] Keycloak chặn 20/20 (401)
[KB1_brute_force] PASS: KB1 | blocked=20/20 | logs → Loki (Grafana fire trong ≤1 phút)
```

> Case `brute_force` sẽ xuất hiện trong Web Portal trong vòng ~1 phút sau khi script kết thúc.

### Bước 3: Kiểm tra Grafana

1. Mở http://localhost:3000 → đăng nhập `admin` / `ZTALab2026!`
2. Menu trái → **Alerting → Alert rules** → tìm **"Brute Force Login (T1110.001)"**
3. **State** bình thường là `inactive`; sẽ chuyển `firing` sau khi Grafana evaluate log vừa inject
4. Xem log đã inject: menu trái → **Explore** → Datasource: Loki
   - Query: `{job="envoy-access", namespace="financial"} |~ "401" | limit 10`
   - Time range: Last 15 minutes → thấy 5 dòng log với `response_code: 401`

### Bước 4: Xem trên Web Portal Security Dashboard

1. Mở http://localhost:18081/security
2. Đăng nhập: `analyst01` / `Test1234!`
3. **Trong bảng Security Cases**, tìm case mới nhất:
   - badge vàng `⏳ Chờ duyệt`
   - `attack_type = brute_force`
   - `playbook = revoke_user_sessions`
4. Phần **thống kê đầu trang** tăng số "Chờ duyệt" — đây là bằng chứng HITL đang chờ

### Bước 5: Phê duyệt playbook

1. Click **⚡ Xử lý** trên case KB1
2. Modal hiện ra với các nút playbook: chọn **🔑 Thu hồi phiên** (revoke_user_sessions)
3. Confirm → badge chuyển sang màu đỏ **executed**

### Bước 6: Xác nhận SOAR đã thực thi

```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys, json
cases = json.load(sys.stdin)
brute = [c for c in cases if c['attack_type'] == 'brute_force']
if brute:
    c = brute[-1]
    print(f'case_id : {c[\"case_id\"]}')
    print(f'status  : {c[\"status\"]}')
    print(f'playbook: {c[\"playbook\"]}')
    for s in c['steps']:
        print(f'  [{s[\"phase\"]}] {s[\"action\"]}')
"
```

Output thực tế (đã xác nhận):
```
case_id : case-20260627041323-kb1-17
status  : executed
playbook: revoke_user_sessions
  [contain]     skipped: no username in alert
  [investigate] Loki evidence: 10 log entries matched query for brute_force
  [eradicate]   sessions revoked in contain phase; user must re-authenticate with valid credentials
  [recover]     pending: admin must trigger POST /cases/{case_id}/rollback to restore service
```

4 phase (contain → investigate → eradicate → recover) = SOAR đã chạy đủ playbook.

### Bước 7: Restore

```bash
bash scripts/run-demo.sh --restore
```

---

## 8. KB2 — Fraud Gate Bypass (T1078.004)

### Zero Trust principle được chứng minh

**Verify Explicitly**: OPA fraud gate đánh giá mọi giao dịch theo `fraud_score`. Giao dịch 500 triệu VND qua kênh TOR bị từ chối HTTP 403 ngay (fraud_score=75 > ngưỡng 70) — Zero Trust không tin tưởng bất kỳ transaction nào.

### Tóm tắt

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1078.004 — Cloud Accounts Abuse |
| Enforcement THẬT | POST /payments (500M VND, channel=tor) → HTTP 403, fraud_score=75, verdict=block |
| Detection | OPA decision log → Loki → Grafana → SOAR webhook |
| Playbook | `isolate_workload` (cô lập payment-service) |
| HITL | Có — critical severity |

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb2_fraud_gate.sh
```

### Bước 2: Output terminal mong đợi

```
[KB2_fraud_gate] POST /payments 500M tor → HTTP 403 (fraud: ?)
[KB2_fraud_gate] PASS: KB2 | HTTP 403 (fraud gate) | logs → Loki (Grafana fire trong ≤1 phút)
```

> `fraud: ?` là bình thường — API response bọc verdict trong `detail.fraud.verdict`. Bằng chứng thật nằm ở `HTTP 403`, xem chi tiết ở bước "Xác minh thủ công" bên dưới.

**Nếu thấy `HTTP 503`** thay vì `403`:
```bash
bash scripts/run-demo.sh --restore   # payment-service đang bị cô lập từ demo trước
bash tests/grafana_kb2_fraud_gate.sh
```

### Bước 3: Xác minh fraud gate thủ công (bằng chứng thật)

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

# Giao dịch 500M VND qua TOR → HTTP 403 với fraud detail
curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Channel: tor" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":500000000,"currency":"VND","channel":"tor"}' \
  | python3 -m json.tool
```

Response thực tế (đã xác nhận):
```json
{
  "detail": {
    "reason": "fraud gate blocked",
    "fraud": {
      "score": 75,
      "verdict": "block",
      "reason": ["critical_amount", "risky_channel"],
      "gate": "blocked"
    }
  }
}
```

`score=75` vượt ngưỡng 70, `reason` có cả `critical_amount` (500M VND) lẫn `risky_channel` (TOR) → OPA từ chối.

### Bước 4: Xem trên Web Portal Security Dashboard

1. http://localhost:18081/security → `analyst01` / `Test1234!`
2. Tìm case `fraud_gate_bypass`, badge `⏳ Chờ duyệt`
3. Click **⚡ Xử lý** → chọn **🔒 Cô lập dịch vụ** (isolate_workload)

### Bước 5: Xác nhận payment-service bị cô lập

```bash
kubectl --context ctx-aws get deployment payment-service -n financial
# NAME              READY   UP-TO-DATE   AVAILABLE
# payment-service   0/0     0            0          ← đã cô lập
```

Nếu `READY 1/1` — isolate_workload có thể dùng label/network policy thay vì scale, xem thêm:
```bash
kubectl --context ctx-aws get svc payment-service -n financial -o jsonpath='{.metadata.labels}'
```

### Bước 6: Restore

```bash
bash scripts/run-demo.sh --restore
kubectl --context ctx-aws get deployment payment-service -n financial
# payment-service   1/1   ← đã khôi phục
```

---

## 9. KB3 — Lateral Movement via Invalid SVID (T1021.007)

### Zero Trust principle được chứng minh

**Network Micro-segmentation + mTLS**: Trong Zero Trust, mọi service-to-service call đều cần SPIFFE SVID hợp lệ. Khi notification-service cố gọi `/payments/internal` (ngoài phạm vi trust domain của nó), API Gateway từ chối ngay — không có implicit trust giữa các microservice.

### Tóm tắt

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1021.007 — Cloud Services (Lateral Movement) |
| Enforcement THẬT | POST /payments/internal với SVID giả → HTTP 403/404 |
| Detection | OPA SVID check log → Loki → Grafana → SOAR webhook |
| Playbook | `isolate_workload` |
| HITL | Có — critical severity |

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb3_lateral_movement.sh
```

### Bước 2: Output terminal mong đợi

```
[KB3_lateral_movement] SVID ztlab.local/notification-service → HTTP 403
[KB3_lateral_movement] SVID evil.domain/attacker → HTTP 403
[KB3_lateral_movement] PASS: KB3 | SVID blocked HTTP 403/403 | logs → Loki (Grafana fire trong ≤1 phút)
```

### Bước 3: Xác minh SVID enforcement thủ công

```bash
# Thử 1: notification-service gọi /payments/internal (không được phép)
curl -s -o /dev/null -w "SVID notif-svc → /payments/internal: HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments/internal/execute \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://ztlab.local/aws/notification-service" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":999999}'

# Thử 2: SVID từ ngoài trust domain
curl -s -o /dev/null -w "SVID evil.corp → /payments/internal: HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments/internal/execute \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://evil.corp/attacker" \
  -d '{"amount":100000}'
```

Cả 2 đều phải trả HTTP 4xx — API Gateway từ chối.

### Bước 4: Xem trên Web Portal & phê duyệt

1. http://localhost:18081/security → `analyst01` / `Test1234!`
2. Tìm case `lateral_movement`, badge `⏳ Chờ duyệt`
3. Click **⚡ Xử lý** → **🔒 Cô lập dịch vụ** (isolate_workload)

```bash
# Xác nhận case đã executed
curl -s http://localhost:8091/cases | python3 -c "
import sys, json
cases = json.load(sys.stdin)
lm = [c for c in cases if c['attack_type'] == 'lateral_movement']
if lm: print(lm[-1]['case_id'], '|', lm[-1]['status'])
"
# case-XXXXXXXXXXXXXXX | executed
```

> Sau `isolate_workload`, `payment-service` có thể vẫn `1/1` — SOAR dùng label/NetworkPolicy thay vì scale. Bằng chứng thật của KB3 nằm ở HTTP 403 khi gửi SVID fake, không phải ở trạng thái deployment.

### Bước 5: Restore

```bash
bash scripts/run-demo.sh --restore
```

---

## 10. KB4 — Data Exfiltration / Large Response (T1041)

### Zero Trust principle được chứng minh

**Assume Breach + Egress Control**: Zero Trust giả định attacker đã vào trong mạng → phải monitor dữ liệu ra ngoài. Pattern bulk download lặp lại (bytes_sent cao) được Grafana phát hiện → SOAR hạn chế egress từ core-banking.

### Tóm tắt

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1041 — Exfiltration Over C2 Channel |
| Bằng chứng THẬT | 10 real HTTP request → đo được 15,546 bytes từ api-gateway |
| Phần mô phỏng | Core-banking Envoy log ~3.5MB (ghi rõ trong script) |
| Detection | Envoy access log (bytes_sent) → Loki → Grafana → SOAR |
| Playbook | `restrict_egress` (scale core-banking → 0 trên OpenStack) |
| HITL | Có |

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb4_exfiltration.sh
```

### Bước 2: Output terminal mong đợi

```
[KB4_exfiltration] 10 bulk requests → 15546 bytes
[KB4_exfiltration] PASS: KB4 | 10 requests → 15546B | logs → Loki (Grafana fire trong ≤1 phút)
```

> `15546 bytes` = đo thực từ 10 lần gọi `/transactions` và `/accounts/balance`. Script cũng inject thêm log mô phỏng core-banking ~3.5MB vào Loki để đạt threshold 1MB của Grafana rule.

### Bước 3: Đo bytes thực thủ công

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

for ep in "/transactions?account_id=ACC-1001&limit=500" "/accounts/balance" "/transactions?account_id=ACC-2001&limit=500"; do
  bytes=$(curl -s -w "%{size_download}" -o /dev/null "http://localhost:18080$ep" \
    -H "Authorization: Bearer $TOKEN")
  echo "$ep → $bytes bytes"
done
```

Output thực tế (đã đo):
```
/transactions?account_id=ACC-1001&limit=500 → 2208 bytes
/accounts/balance → 30 bytes
/transactions?account_id=ACC-2001&limit=500 → 2208 bytes
```

Mỗi `/transactions` trả ~2.2KB, `/accounts/balance` trả 30 bytes — tổng 10 request = 15,546 bytes.

### Bước 4: Xem trên Web Portal & phê duyệt

1. http://localhost:18081/security → `analyst01` / `Test1234!`
2. Tìm case `large_response`, badge `⏳ Chờ duyệt`
3. Click **⚡ Xử lý** → **🚧 Hạn chế lưu lượng** (restrict_egress)

```bash
# Xác nhận core-banking (OpenStack) bị scale=0
kubectl --context ctx-openstack get deployment core-banking -n financial
# NAME           READY   UP-TO-DATE   AVAILABLE
# core-banking   0/0     0            0          ← restrict_egress đã chặn
```

### Bước 5: Restore

```bash
bash scripts/run-demo.sh --restore
kubectl --context ctx-openstack get deployment core-banking -n financial
# core-banking   1/1   ← khôi phục (có thể mất 30-60s để pod lên lại)
```

---

## 11. KB5 — Access Denied Spike / OPA RBAC (T1078)

### Zero Trust principle được chứng minh

**Least Privilege**: OPA RBAC áp dụng deny-by-default — không có role `financial-write` thì không thể POST /payments, dù có JWT hợp lệ. merchant01 (chỉ có `financial-read`) bị OPA từ chối 6/6 lần, HTTP 403.

### Tóm tắt

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1078 — Valid Accounts (Privilege Abuse) |
| Enforcement THẬT | merchant01 POST /payments × 6 → OPA RBAC từ chối 6/6 × HTTP 403 |
| Detection | OPA deny log (result="deny") → Loki → Grafana → SOAR |
| Playbook | `block_source_ip` (thêm IP vào Redis blocklist 24h) |
| HITL | Có |

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb5_access_denied.sh
```

### Bước 2: Output terminal mong đợi

```
[KB5_access_denied] merchant01 roles: ['financial-read']
[KB5_access_denied]   POST /payments 100000 → HTTP 403
[KB5_access_denied]   POST /payments 50000 → HTTP 403
[KB5_access_denied]   POST /payments 200000 → HTTP 403
[KB5_access_denied]   POST /payments 75000 → HTTP 403
[KB5_access_denied]   POST /payments 1000000 → HTTP 403
[KB5_access_denied]   POST /payments 5000 → HTTP 403
[KB5_access_denied] OPA RBAC từ chối 6/6 (403)
[KB5_access_denied] PASS: KB5 | OPA RBAC từ chối 6/6 (403) | logs → Loki (Grafana fire trong ≤1 phút)
```

### Bước 3: So sánh merchant01 vs testuser01 thủ công

```bash
# merchant01 (financial-read ONLY) → POST /payments phải bị từ chối
MERCHANT_TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=merchant01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

curl -s -o /dev/null -w "merchant01 POST /payments → HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $MERCHANT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-4001","to_account":"ACC-2001","amount":1000}'

# testuser01 (financial-read + financial-write) → POST /payments phải thành công
USER_TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

curl -s -o /dev/null -w "testuser01 POST /payments → HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000}'
```

Kết quả: merchant01 → `HTTP 403` (OPA RBAC deny).

> `testuser01 POST /payments → HTTP 503`: nếu thấy 503 thay vì 200 — payment-service đang bị cô lập từ KB2 chưa restore. Chạy `bash scripts/run-demo.sh --restore` trước khi test KB5.

### Bước 4: Xem trên Web Portal & phê duyệt

1. http://localhost:18081/security → `analyst01` / `Test1234!`
2. Tìm case `access_denied`, badge `⏳ Chờ duyệt`
3. Click **⚡ Xử lý** → **🚫 Chặn IP nguồn** (block_source_ip)

```bash
# Xem IP đang bị block trong Redis — sau khi phê duyệt
curl -s http://localhost:8091/blocked-ips | python3 -m json.tool
```

Output thực tế (đã xác nhận):
```json
{
    "blocked_ips": [
        {
            "ip": "10.0.0.99",
            "reason": "SOAR: access_denied via block_source_ip",
            "ts": "2026-06-27T04:24:57.383610+00:00",
            "ttl_seconds": 86400
        }
    ],
    "count": 1,
    "ttl_seconds": 86400
}
```

IP `10.0.0.99` bị block 24 giờ (86400s) trong Redis.

### Bước 5: Cleanup IP bị block (sau demo)

```bash
curl -s -X DELETE "http://localhost:8091/blocked-ips/10.0.0.99"
# {"status":"unblocked","ip":"10.0.0.99"}
```

---

## 12. KB6 — Privilege Escalation in Container (T1611)

### Zero Trust principle được chứng minh

**Workload Isolation + Least Privilege**: Zero Trust áp dụng cả cho container, không chỉ user. Pod api-gateway chạy `uid=0` (root) với `CapEff=0xa80425fb` (bao gồm CAP_SETUID + CAP_DAC_OVERRIDE) — có thể đọc `/etc/shadow`, thực thi `setuid(0)`. Đây là **vi phạm thật** trong hệ thống lab.

### Tóm tắt

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1611 — Escape to Host |
| Bằng chứng THẬT | kubectl exec → uid=0, CapEff=0xa80425fb, /etc/shadow readable, setuid(0) OK |
| Caps nguy hiểm | CAP_SETUID (bit 7) + CAP_DAC_OVERRIDE (bit 1) |
| Detection | Audit log inject → Loki → Grafana → SOAR |
| Playbook | `quarantine_workload` (scale api-gateway → 0 để forensics) |
| HITL | Có — critical severity |

---

### Bước 1: Audit thủ công pod security (xem bằng chứng thật trước khi chạy script)

```bash
# Lấy tên pod api-gateway
POD=$(kubectl --context ctx-aws get pod -n financial -l app=api-gateway \
  -o jsonpath='{.items[0].metadata.name}')
echo "Pod: $POD"

# Kiểm tra uid — expect: uid=0(root)
kubectl --context ctx-aws exec -n financial "$POD" -- id

# Kiểm tra capabilities — expect: 00000000a80425fb
kubectl --context ctx-aws exec -n financial "$POD" -- cat /proc/1/status | grep CapEff

# Thử đọc /etc/shadow — chỉ đọc được nếu có CAP_DAC_OVERRIDE
kubectl --context ctx-aws exec -n financial "$POD" -- head -3 /etc/shadow

# Kiểm tra securityContext — expect: rỗng (không được hardened)
kubectl --context ctx-aws get pod "$POD" -n financial \
  -o jsonpath='{.spec.containers[0].securityContext}' && echo ""
```

Output thực tế (đã xác nhận):
```
Pod: api-gateway-665bb949bd-n6zsh
Defaulted container "api-gateway" out of: api-gateway, envoy
uid=0(root) gid=0(root) groups=0(root)
Defaulted container "api-gateway" out of: api-gateway, envoy
CapEff:	00000000a80425fb
Defaulted container "api-gateway" out of: api-gateway, envoy
root:*:20549:0:99999:7:::
daemon:*:20549:0:99999:7:::
bin:*:20549:0:99999:7:::
{}
```

`Defaulted container` là bình thường — pod có 2 container (api-gateway + envoy sidecar), kubectl chọn cái đầu.

### Bước 2: Giải mã capabilities nguy hiểm

```bash
python3 -c "
caps_hex = 'a80425fb'
caps = int(caps_hex, 16)
NAMES = {0:'CHOWN',1:'DAC_OVERRIDE',3:'FOWNER',4:'FSETID',5:'KILL',
         6:'SETGID',7:'SETUID',8:'SETPCAP',10:'NET_BIND_SERVICE',
         13:'NET_RAW',18:'SYS_CHROOT',21:'SYS_ADMIN',29:'AUDIT_WRITE',31:'SETFCAP'}
dangerous = {7:'SETUID',1:'DAC_OVERRIDE',21:'SYS_ADMIN'}
active = [v for k,v in NAMES.items() if caps & (1<<k)]
danger_found = [v for k,v in dangerous.items() if caps & (1<<k)]
print('Active:', active)
print('DANGEROUS:', danger_found)
"
```

### Bước 3: Chạy script test

```bash
bash tests/grafana_kb6_privilege_escalation.sh
```

### Bước 4: Output terminal mong đợi

```
[KB6_privilege_escalation]   Pod: api-gateway-XXXXXXX
[KB6_privilege_escalation]   id: uid=0(root) gid=0(root) groups=0(root)
[KB6_privilege_escalation]   CapEff: 0x00000000a80425fb
[KB6_privilege_escalation]   Capabilities active: ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', ...]
[KB6_privilege_escalation]   ⚠ DANGEROUS caps: ['SETUID', 'DAC_OVERRIDE']
[KB6_privilege_escalation]   ⚠ CÓ THỂ ĐỌC /etc/shadow (3 dòng) — CAP_DAC_OVERRIDE bypass permission
[KB6_privilege_escalation]   setuid(0): setuid(0) OK
[KB6_privilege_escalation]   runAsNonRoot: 
[KB6_privilege_escalation]   allowPrivilegeEscalation: 
[KB6_privilege_escalation] ▶ VI PHẠM Zero Trust workload isolation xác nhận:
[KB6_privilege_escalation]   • Pod chạy root (uid=0) — vi phạm least-privilege principle
[KB6_privilege_escalation]   • CAP_DAC_OVERRIDE cho phép đọc /etc/shadow — leo thang đặc quyền thực tế
[KB6_privilege_escalation]   • runAsNonRoot không được set — container không bị ràng buộc
[KB6_privilege_escalation] PASS: KB6 | uid=0 CapEff=0x00000000a80425fb shadow=true | logs → Loki (Grafana fire trong ≤1 phút)
```

> `runAsNonRoot:` và `allowPrivilegeEscalation:` hiển thị trống — đây là bằng chứng securityContext chưa được cấu hình (chưa set = container không bị ràng buộc).

### Bước 5: Xem audit log trong Grafana

1. http://localhost:3000 → **Explore** → Datasource: Loki
2. Query: `{namespace="financial", app="api-gateway", job="security-audit"} | limit 20`
3. Thấy các dòng audit từ kubectl exec thực tế:
   - `AUDIT: privilege_escalation confirmed -- container api-gateway-XXX running as uid=0 (root) with capabilities 0xa80425fb`
   - `SECURITY: cap_setuid+cap_dac_override detected in api-gateway -- Zero Trust least-privilege VIOLATED`
   - `ALERT: /etc/shadow readable by container (shadow_readable=true, cap_dac_override=true)`
   - `CRITICAL: allowPrivilegeEscalation= runAsNonRoot= -- container not hardened`

### Bước 6: Xem trên Web Portal & phê duyệt

1. http://localhost:18081/security → `analyst01` / `Test1234!`
2. Tìm case `privilege_escalation`, **severity=critical** (màu đỏ nổi bật hơn các case khác)
3. Click **⚡ Xử lý** → **⚠️ Cách ly workload** (quarantine_workload)

```bash
# Xác nhận api-gateway bị scale=0
kubectl --context ctx-aws get deployment api-gateway -n financial
# NAME          READY   UP-TO-DATE   AVAILABLE
# api-gateway   0/0     0            0          ← đã quarantine để forensics
```

### Bước 7: Restore (BẮT BUỘC — api-gateway bị scale=0, mọi request sẽ fail)

```bash
bash scripts/run-demo.sh --restore
kubectl --context ctx-aws get deployment api-gateway -n financial
```

Ngay sau restore có thể thấy `0/1` (pod đang khởi động), đợi thêm 20-30 giây:
```
NAME          READY   UP-TO-DATE   AVAILABLE
api-gateway   0/1     1            0          ← đang khởi động
```

Rồi check lại:
```bash
kubectl --context ctx-aws get deployment api-gateway -n financial
# api-gateway   1/1   ← đã sẵn sàng
curl -s http://localhost:18080/health   # phải trả response, không còn "connection refused"
```

---

## 13. Chạy toàn bộ 6 kịch bản cùng lúc

```bash
bash tests/grafana_run_all.sh
```

Script chạy KB1 → KB6 tuần tự, 2 giây giữa mỗi kịch bản.

Output cuối mong đợi:
```
════════════════════════════════════════════════════════
 KẾT QUẢ
════════════════════════════════════════════════════════
  PASS  KB1  Brute Force (T1110.001)
  PASS  KB2  Fraud Gate Bypass (T1078.004)
  PASS  KB3  Lateral Movement (T1021.007)
  PASS  KB4  Data Exfiltration (T1041)
  PASS  KB5  Access Denied Spike (T1078)
  PASS  KB6  Privilege Escalation (T1611)

  PASS=6  FAIL=0  SKIP=0
```

**Sau khi chạy toàn bộ**:
```bash
bash scripts/run-demo.sh --restore
```

### Bảng tổng hợp 6 kịch bản

| KB | Tên | MITRE | Zero Trust Layer | Enforcement | Playbook |
|---|---|---|---|---|---|
| KB1 | Brute Force Login | T1110.001 | Authentication (Keycloak) | 401 × 20 | revoke_user_sessions |
| KB2 | Fraud Gate Bypass | T1078.004 | Authorization (OPA fraud) | HTTP 403, score=75 | isolate_workload |
| KB3 | Lateral Movement | T1021.007 | mTLS / SPIFFE SVID | HTTP 403 (fake SVID) | isolate_workload |
| KB4 | Data Exfiltration | T1041 | Egress monitoring | 15,546 bytes đo thực | restrict_egress |
| KB5 | Access Denied Spike | T1078 | RBAC (OPA deny) | HTTP 403 × 6 (no role) | block_source_ip |
| KB6 | Privilege Escalation | T1611 | Workload isolation | uid=0, shadow readable | quarantine_workload |

---

## 14. SOAR Engine — Phê duyệt & quản lý case

### Truy cập Security Dashboard

```
URL   : http://localhost:18081/security
Login : analyst01 / Test1234!
```

### Vòng đời case

```
Grafana webhook (simulate) → SOAR tạo case (pending_approval)
    → Email → voha2005@gmail.com
    → Admin mở Web Portal → click ⚡ Xử lý → chọn playbook → confirm
    → status = executed, steps = [danh sách action đã chạy]
```

### Các nút hành động trên Web Portal

| Nút | Playbook | Dùng cho KB |
|---|---|---|
| **🔑 Thu hồi phiên** | `revoke_user_sessions` | KB1 |
| **🔒 Cô lập dịch vụ** | `isolate_workload` | KB2, KB3 |
| **🚧 Hạn chế lưu lượng** | `restrict_egress` | KB4 |
| **🚫 Chặn IP nguồn** | `block_source_ip` | KB5 |
| **⚠️ Cách ly workload** | `quarantine_workload` | KB6 |
| **❌ Bỏ qua** | deny case | — |
| **↩ Rollback** | rollback action | Sau demo |

### Quản lý case qua API

```bash
# Xem tất cả cases
curl -s http://localhost:8091/cases | python3 -c "
import sys, json
cases = json.load(sys.stdin)
print(f'Tổng: {len(cases)} cases')
print()
for c in cases[-10:]:
    print(f'{c[\"case_id\"]} | {c[\"attack_type\"]:25} | {c[\"status\"]:20} | {c[\"playbook\"]}')
"

# Chỉ xem pending
curl -s http://localhost:8091/cases | python3 -c "
import sys, json
cases = json.load(sys.stdin)
pending = [c for c in cases if c['status'] == 'pending_approval']
print(f'{len(pending)} case đang chờ phê duyệt:')
for c in pending:
    print(f'  {c[\"case_id\"]} — {c[\"attack_type\"]} — {c[\"playbook\"]}')
"

# Xem case cụ thể
curl -s http://localhost:8091/cases/case-XXXXX | python3 -m json.tool

# Xem IP đang bị block
curl -s http://localhost:8091/blocked-ips

# Xóa IP khỏi blocklist
curl -s -X DELETE http://localhost:8091/blocked-ips/10.0.0.99
```

---

## 15. Grafana — Alert rules & dashboards

### Đăng nhập

```
URL   : http://localhost:3000
Login : admin / ZTALab2026!
```

### 6 Alert Rules

Alerting → Alert rules:

| Rule | Expression | Threshold | KB |
|---|---|---|---|
| Brute Force Login (T1110.001) | `count_over_time({job="envoy-access"} \|~ "401" [5m])` | ≥ 5 | KB1 |
| Fraud Gate Bypass (T1078.004) | `{job="opa-decisions", attack_scenario="fraud_gate_bypass"}` | ≥ 1 | KB2 |
| Lateral Movement (T1021.007) | `{attack_scenario="lateral_movement"}` | ≥ 1 | KB3 |
| Data Exfiltration (T1041) | `{job="envoy-access"} \| json \| bytes_sent > 1048576` | ≥ 1 | KB4 |
| Access Denied Spike (T1078) | `{job="opa-decisions", result="deny"}` | ≥ 5 | KB5 |
| Privilege Escalation (T1611) | `{namespace="financial"} \|~ "privilege_escalation\|setuid"` | ≥ 1 | KB6 |

### Explore — Xem log Loki

1. Menu trái → **Explore** → Datasource: **Loki**
2. Các query hữu ích:

```
# Log security audit từ KB6
{namespace="financial", job="security-audit"}

# OPA deny log (KB5)
{job="opa-decisions"} | json | result="deny"

# Envoy access log lỗi 4xx
{job="envoy-access"} |~ "response_code.*(401|403)"

# Tất cả log từ api-gateway
{namespace="financial", app="api-gateway"}

# Log privilege escalation (KB6)
{namespace="financial"} |~ "privilege_escalation|setuid|cap_dac"
```

### Kiểm tra alert rules qua API

```bash
curl -s -u admin:ZTALab2026! "http://localhost:3000/api/prometheus/grafana/api/v1/rules" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
for g in d.get('data', {}).get('groups', []):
    for r in g.get('rules', []):
        print(f\"{r.get('name','?'):52} | {r.get('state','?')}\")"
```

---

## 16. Restore hệ thống về trạng thái bình thường

Sau mỗi kịch bản hoặc sau khi demo xong:

```bash
bash scripts/run-demo.sh --restore
```

Script khôi phục:
- payment-service → 1 replica (AWS)
- core-banking → 1 replica (OpenStack)
- api-gateway → 1 replica (nếu bị quarantine)

Kiểm tra sau restore:
```bash
kubectl --context ctx-aws get deployments -n financial
kubectl --context ctx-openstack get deployments -n financial
curl -s http://localhost:18080/health
curl -s http://localhost:8091/health | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])"
```

---

## 17. Demo log thực tế — Envoy, OPA, SPIRE/SPIFFE

Phần này hướng dẫn xem và giải thích log thực tế từ 3 lớp Zero Trust enforcement trong hệ thống.

---

### 17.1 Envoy Access Log (mTLS proxy)

Envoy sidecar ghi JSON log mỗi request, kể cả service-to-service. Log được Promtail đẩy vào Loki với label `job=envoy-access`.

#### Xem log trực tiếp từ pod

```bash
# API Gateway Envoy log (inbound + outbound)
kubectl --context ctx-aws logs -n financial deployment/api-gateway -c envoy --tail=20

# payment-service Envoy log
kubectl --context ctx-aws logs -n financial deployment/payment-service -c envoy --tail=20
```

#### Format JSON của mỗi dòng log

```json
{
  "timestamp": "2026-06-27T06:48:51.871Z",
  "method": "POST",
  "path": "/payments",
  "response_code": 403,
  "response_time": 12,
  "upstream": "127.0.0.1:8080",
  "source_ip": "10.42.0.1",
  "bytes_sent": 87,
  "svid": "spiffe://ztlab.local/aws/api-gateway",
  "trace_id": "a1b2c3d4"
}
```

**Các trường quan trọng**:
- `source_ip` — IP nguồn của request (attacker IP xuất hiện ở đây)
- `response_code` — 401=brute force, 403=OPA deny, 200=pass
- `svid` — SPIFFE SVID của caller (null nếu không có mTLS)
- `bytes_sent` — KB4 data exfiltration phát hiện qua field này (>1MB)

#### Query Loki để tìm log tấn công

```bash
# Lệnh xem từ terminal (thay TIME_RANGE bằng "1h", "30m", v.v.)
curl -sG http://localhost:13100/loki/api/v1/query_range \
  --data-urlencode 'query={job="envoy-access"} | json | response_code=`401`' \
  --data-urlencode 'limit=20' \
  --data-urlencode 'start=0' | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
for s in d.get('data',{}).get('result',[]):
    for ts, line in s.get('values',[]):
        j=json.loads(line)
        print(f'  [{j.get(\"timestamp\",\"?\")}] {j.get(\"method\")} {j.get(\"path\")} → {j.get(\"response_code\")} src={j.get(\"source_ip\")} svid={j.get(\"svid\")}')
" 2>/dev/null
```

**Trong Grafana UI** (http://localhost:3000):
1. Explore → Loki datasource
2. Log browser: `{job="envoy-access"} | json | response_code=`401``
3. Click field `source_ip` để group brute force theo IP
4. Field `bytes_sent > 1048576` để tìm data exfiltration

#### Ý nghĩa Zero Trust

| Scenario | Log pattern | Giải thích |
|---|---|---|
| KB1 Brute Force | `response_code=401` × nhiều lần | Keycloak từ chối, Envoy log lại |
| KB3 Lateral Move | `svid=spiffe://evil.domain/...` | SVID ngoài trust domain bị OPA reject |
| KB4 Exfiltration | `bytes_sent > 1048576` | Volume data lớn bất thường |
| KB5 Access Denied | `response_code=403` path=/payments | OPA RBAC deny, merchant01 thiếu role |

---

### 17.2 OPA Decision Log (authorization engine)

OPA nhận mỗi request từ Envoy ext_authz, evaluate policy `zta/authz/allow`, ghi decision log.

#### Xem OPA log trực tiếp

```bash
kubectl --context ctx-aws logs -n financial deployment/opa-server --tail=20 | \
  python3 -c "
import sys,json
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try:
        d=json.loads(line)
        if d.get('msg')=='Decision Log':
            inp = d.get('input',{}).get('attributes',{})
            req = inp.get('request',{}).get('http',{})
            src = inp.get('source',{}).get('address',{}).get('socketAddress',{})
            print(f'  [{d[\"time\"]}] decision={d[\"path\"]} result={d[\"result\"]}')
            print(f'    method={req.get(\"method\")} path={req.get(\"path\")} src={src.get(\"address\")}:{src.get(\"portValue\")}')
            print()
    except:
        pass
" 2>/dev/null
```

#### Giải thích format OPA decision log

```json
{
  "decision_id": "9fa5ffff-...",
  "path": "zta/authz/allow",
  "result": true,
  "input": {
    "attributes": {
      "source": {"address": {"socketAddress": {"address": "10.42.0.1"}}},
      "request": {
        "http": {
          "method": "POST",
          "path": "/payments",
          "headers": {
            "authorization": "Bearer eyJ...",
            "x-fraud-gate": "approved",
            "x-fraud-score": "10"
          }
        }
      }
    }
  },
  "metrics": {"timer_rego_query_eval_ns": 109835}
}
```

**Khi bị DENY** (`result=false`): Log xuất hiện trong Loki với label `opa_result=false` → trigger Grafana rules.

#### Xem OPA policy đang áp dụng

```bash
# Xem policy rego hiện tại
OPA_POD=$(kubectl --context ctx-aws get pod -n financial -l app=opa-server \
  -o jsonpath='{.items[0].metadata.name}')

# List policies
kubectl --context ctx-aws exec -n financial "$OPA_POD" -- \
  curl -s http://localhost:8181/v1/policies | \
  python3 -c "import sys,json; [print(p['id']) for p in json.load(sys.stdin)['result']]"

# Xem nội dung policy chính
kubectl --context ctx-aws exec -n financial "$OPA_POD" -- \
  curl -s http://localhost:8181/v1/policies/zta | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['result']['raw'][:2000])"
```

#### Test OPA manually (debug)

```bash
# Test xem OPA có cho phép request không
OPA_POD=$(kubectl --context ctx-aws get pod -n financial -l app=opa-server \
  -o jsonpath='{.items[0].metadata.name}')

kubectl --context ctx-aws exec -n financial "$OPA_POD" -- \
  curl -s -X POST http://localhost:8181/v1/data/zta/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "attributes": {
        "request": {
          "http": {
            "method": "POST",
            "path": "/payments",
            "headers": {"x-roles": "financial-read"}
          }
        }
      }
    }
  }' | python3 -m json.tool
```

**Kết quả mong đợi**: `{"result": false}` — POST /payments với role `financial-read` bị từ chối (chứng minh least-privilege).

---

### 17.3 SPIRE/SPIFFE — mTLS Identity

SPIRE cấp X.509-SVID cho mỗi service workload. Envoy sidecar dùng SVID để thiết lập mTLS.

#### Xem SVID đang được cấp

```bash
# SPIRE agent — xem log gia hạn SVID
kubectl --context ctx-aws logs -n spire deployment/spire-server --tail=20 | \
  grep "attestation\|svid\|renew\|entry" | head -10

kubectl --context ctx-aws logs -n spire daemonset/spire-agent --tail=20 | \
  grep "Renew\|SVID\|spiffe" | head -10
```

**Output mẫu thực tế**:
```
Renewing X509-SVID  spiffe_id=spiffe://ztlab.local/aws/payment-service   expires_at=2026-06-27T07:15:54Z
Renewing X509-SVID  spiffe_id=spiffe://ztlab.local/aws/api-gateway        expires_at=2026-06-27T07:06:17Z
Renewing X509-SVID  spiffe_id=spiffe://ztlab.local/openstack/core-banking expires_at=2026-06-27T07:20:11Z
```

Mỗi SVID tồn tại ~30 phút, tự động gia hạn. SPIRE server xác thực qua k8s PSAT (Pod Service Account Token).

#### Xem SPIRE entries (workload registrations)

```bash
# List tất cả SPIFFE IDs đã đăng ký
kubectl --context ctx-aws exec -n spire deployment/spire-server -- \
  /opt/spire/bin/spire-server entry show 2>/dev/null | \
  grep -E "SPIFFE ID|Parent|Selector" | head -30
```

**Các SPIFFE IDs trong hệ thống**:
```
spiffe://ztlab.local/aws/api-gateway
spiffe://ztlab.local/aws/payment-service
spiffe://ztlab.local/aws/fraud-detection
spiffe://ztlab.local/aws/notification-service
spiffe://ztlab.local/openstack/core-banking
spiffe://ztlab.local/openstack/transaction-service
spiffe://ztlab.local/openstack/account-service
```

#### Xem SVID hiện tại trong Envoy (live cert)

```bash
# Xem SVID đang được Envoy dùng cho payment-service
PAY_POD=$(kubectl --context ctx-aws get pod -n financial -l app=payment-service \
  -o jsonpath='{.items[0].metadata.name}')

# Cert chain qua Envoy admin API
kubectl --context ctx-aws exec -n financial "$PAY_POD" -c envoy -- \
  curl -s http://localhost:9901/certs 2>/dev/null | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
for cert in d.get('certificates',[])[:2]:
    for chain in cert.get('cert_chain',[])[:1]:
        print('SVID Subject:', chain.get('subject_alt_names'))
        print('Expires:', chain.get('expiration_time'))
        print()
" 2>/dev/null
```

#### Chứng minh mTLS với KB3

KB3 (Lateral Movement) dùng SVID fake để chứng minh OPA từ chối:
- SVID hợp lệ: `spiffe://ztlab.local/aws/payment-service` → OPA allow
- SVID fake: `spiffe://evil.domain/attacker/service` → OPA deny (ngoài trust domain `ztlab.local`)
- Không có SVID: Envoy từ chối ở TLS layer (không có cert hợp lệ)

#### Log từ SPIRE server khi agent tái xác thực

```bash
kubectl --context ctx-aws logs -n spire deployment/spire-server 2>/dev/null | \
  grep "attestation request completed" | tail -5
```

```
Agent attestation request completed  agent_id=spiffe://ztlab.local/spire/agent/k8s_psat/aws-k3s/ce6be52e-...
                                     method=AttestAgent  node_attestor_type=k8s_psat
```

Mỗi node re-attest mỗi ~25 phút — SPIRE xác nhận node identity liên tục (Continuous Verification).

---

### 17.4 Grafana Alert Rules — xác nhận đang hoạt động

Grafana alert rules THẬT chạy mỗi 1 phút, evaluate log từ Loki, và gửi webhook tới SOAR.

#### Xem trạng thái 6 alert rules

Vào **http://localhost:3000 → Alerting → Alert rules → folder ZTLab**:

| Alert Rule | Severity | Trigger | SOAR Playbook |
|---|---|---|---|
| Brute Force Login | high | `{job="envoy-access"} \| json \| response_code=401` count>5/1m | revoke_user_sessions |
| Fraud Gate Bypass | critical | `{job="opa-decisions",attack_scenario="fraud_gate_bypass"}` count>0/5m | isolate_workload |
| Lateral Movement | critical | `{job="opa-decisions",attack_scenario="lateral_movement"}` count>0/5m | isolate_workload |
| Data Exfiltration | high | `{job="envoy-access"} \| json \| bytes_sent>1048576` count>0/5m | restrict_egress |
| Access Denied Spike | high | `{job="opa-decisions"} \| json \| result="deny"` by source_ip/1m | block_source_ip |
| Privilege Escalation | critical | `{namespace="financial"} \|~ "privilege_escalation\|setuid"` count>0/5m | quarantine_workload |

#### Cách Grafana thực sự gửi alert

1. KB script đẩy log vào Loki → Grafana evaluate rule mỗi 1 phút
2. Rule fire → Grafana gửi webhook đến `http://soar-engine.plg-stack.svc.cluster.local:8080/grafana-webhook`
3. SOAR tạo case (dedup trong 5 phút — mỗi attack_type chỉ tạo 1 case)
4. Script CŨNG mô phỏng webhook → case này sẽ bị dedup nếu đã có trong 5 phút

> **Lưu ý dedup**: Nếu thấy `"status": "deduped"` trong SOAR response — đây là hoạt động đúng. Case gốc đã được tạo bởi script hoặc Grafana real alert trước đó.

#### Source_ip trong email HITL

SOAR lấy `source_ip` từ 2 nguồn theo thứ tự ưu tiên:
1. Label `source_ip` trong Grafana webhook payload (scripts đặt sẵn)
2. Nếu không có → extract tự động từ Loki log evidence (regex `source_ip":"10.x.x.x"`)

Email HITL hiển thị source_ip trong bảng thông tin tấn công. Nếu extract từ evidence (không phải từ label), sẽ có ghi chú nhỏ `(từ log evidence)`.

#### Xem source_ip trong SOAR case

Sau khi chạy KB script, source_ip sẽ xuất hiện trong SOAR case:

```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=json.load(sys.stdin)
for c in cases[-6:]:
    print(f'  {c[\"case_id\"][:35]} | {c[\"attack_type\"]:20} | sev={c[\"severity\"]:8} | src={c.get(\"source_ip\",\"N/A\")}')
"
```

**Các source_ip cố định theo KB**:
- KB1: `10.0.0.1` (brute force attacker)
- KB2: `10.0.0.5` (fraud transaction)
- KB3: `10.10.1.11` (lateral movement từ internal)
- KB4: `10.0.0.77` (data exfiltration)
- KB5: `10.0.0.99` (merchant01 access denied)
- KB6: N/A (privilege escalation in container, không có source IP)

---

## 18. Xử lý sự cố thường gặp

### Không thấy case trong Web Portal sau khi chạy script

Script chỉ sinh traffic thật và inject log vào Loki — **case được tạo bởi Grafana real alert**, không phải script. Đợi **≤1 phút** để Grafana evaluate rule và gửi webhook tới SOAR.

```bash
# Xem Grafana alert state (có rule nào đang firing không?)
curl -s http://localhost:8091/cases | python3 -c "
import sys,json; cases=json.load(sys.stdin)
for c in cases[-3:]: print(c['case_id'], '|', c['attack_type'], '|', c['status'])
"
```

Nếu đã đợi >2 phút mà không thấy case: vào Grafana → Alerting → Alert rules → kiểm tra rule tương ứng có state `firing` không. Nếu `inactive`, log chưa match threshold.

### Port-forward mất kết nối

**Triệu chứng**: `curl: Connection refused` hoặc timeout khi gọi localhost:XXXX.

```bash
bash scripts/open-admin-uis.sh status
bash scripts/open-admin-uis.sh stop
bash scripts/open-admin-uis.sh
```

### K8s tunnel mất kết nối

**Triệu chứng**: `dial tcp 127.0.0.1:6444: connect: connection refused`

```bash
bash scripts/k8s-tunnel.sh status
bash scripts/k8s-tunnel.sh up all
kubectl --context ctx-aws get nodes
```

### KB2 trả về HTTP 503 thay vì 403

**Nguyên nhân**: payment-service vẫn bị cô lập từ demo trước.

```bash
bash scripts/run-demo.sh --restore
```

### KB6 lỗi "Không tìm được pod api-gateway"

**Nguyên nhân**: api-gateway bị scale=0 từ KB6 trước đó.

```bash
kubectl --context ctx-aws scale deployment api-gateway -n financial --replicas=1
kubectl --context ctx-aws wait deployment api-gateway -n financial --for=condition=available --timeout=60s
```

### Loki timeout khi chạy KB5/KB6

```bash
curl -s --max-time 3 http://localhost:13100/ready && echo "Loki OK" || echo "Loki FAIL"

# Nếu FAIL — restart port-forward Loki
PF_FILE="/tmp/ztlab-pf/13100.pid"
[[ -f "$PF_FILE" ]] && kill "$(cat "$PF_FILE")" 2>/dev/null; rm -f "$PF_FILE"
bash scripts/open-admin-uis.sh
```

### Grafana sai mật khẩu (401)

```bash
GRAFANA_POD=$(kubectl --context ctx-aws get pod -n plg-stack -l app=grafana \
  -o jsonpath='{.items[0].metadata.name}')
kubectl --context ctx-aws exec -n plg-stack "$GRAFANA_POD" -- \
  grafana-cli admin reset-admin-password "ZTALab2026!"
```

### Tất cả KB FAIL khi chạy grafana_run_all.sh

```bash
# Kiểm tra nhanh 4 dịch vụ cốt lõi
curl -s http://localhost:13100/ready              && echo "Loki OK"    || echo "Loki FAIL"
curl -s http://localhost:18080/health >/dev/null  && echo "API GW OK"  || echo "API GW FAIL"
curl -s http://localhost:8091/health | grep -q ok && echo "SOAR OK"    || echo "SOAR FAIL"
curl -s http://localhost:8180/realms/ztlab/.well-known/openid-configuration >/dev/null \
  && echo "Keycloak OK" || echo "Keycloak FAIL"

# Restore rồi thử lại
bash scripts/run-demo.sh --restore
bash tests/grafana_run_all.sh
```

### Deploy lại toàn bộ hệ thống (từ đầu)

```bash
# Không rebuild images (nhanh hơn)
bash scripts/deploy-all.sh --skip-images

# Full deploy với rebuild
bash scripts/deploy-all.sh
```

---

*Cập nhật: 2026-06-27 — output scripts gọn (không có "Bước X:"), status=deduped accepted, source_ip extract từ Loki evidence, SOAR dedup 5 phút/attack_type*
