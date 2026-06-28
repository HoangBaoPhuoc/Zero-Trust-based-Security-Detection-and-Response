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
      │    KB1: api-gateway từ chối 20 JWT không hợp lệ → jwt_verification_failed (log thật)
      │    KB2: fraud-detection score=75 → payment-service AUDIT payment_blocked_fraud (log thật)
      │    KB3: notification-service pod gọi api-gateway không có auth → missing_bearer (log thật)
      │    KB4: bulk download → api-gateway trace_middleware ghi bytes_sent thật
      │    KB5: api-gateway RBAC từ chối POST /payments → authz_denied × 6 (log thật)
      │    KB6: security-scanner Job → uid=0, CAP_DAC_OVERRIDE → privilege_escalation (log thật)
      │
      ├─ Layer 2 — Detection Pipeline (tất cả log thật, không inject):
      │    Service ghi JSON log → stdout → Promtail DaemonSet → Loki
      │    Grafana rule evaluate (mỗi 1 phút) → alert FIRING
      │    Grafana gửi webhook thật đến SOAR Engine
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

> **Lưu ý**: Script sinh traffic thật, không inject log giả. **Log thật từ service → Promtail → Loki → Grafana alert → SOAR** (~1 phút sau khi script kết thúc). SOAR giới hạn 1 case mỗi attack_type trong 5 phút — nếu chạy cùng kịch bản 2 lần liên tiếp, chỉ 1 case được tạo.

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

**Continuous Verification**: api-gateway từ chối tất cả request có JWT không hợp lệ — không có implicit trust, không có grace period. 20/20 request với JWT sai đều bị chặn HTTP 401 và ghi log `jwt_verification_failed` thật vào Loki qua Promtail.

### Tóm tắt

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1110.001 — Password Guessing |
| Enforcement THẬT | api-gateway chặn 20/20 JWT không hợp lệ → HTTP 401 (log thật) |
| Detection | jwt_verification_failed log thật → Promtail → Loki → Grafana → SOAR |
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
[KB1_brute_force] api-gateway chặn 1/1 (401) — jwt_verification_failed
[KB1_brute_force] api-gateway chặn 2/2 (401) — jwt_verification_failed
...
[KB1_brute_force] api-gateway chặn 20/20 (401) — jwt_verification_failed
[KB1_brute_force] PASS: KB1 | 20/20 blocked | log thật → Loki (Grafana fire trong ≤1 phút)
```

> Case `brute_force` sẽ xuất hiện trong Web Portal trong vòng ~1 phút sau khi script kết thúc (Promtail scrape mỗi 5s → Loki → Grafana evaluate).

### Bước 3: Kiểm tra Grafana

1. Mở http://localhost:3000 → đăng nhập `admin` / `ZTALab2026!`
2. Menu trái → **Alerting → Alert rules** → tìm **"Brute Force Login (T1110.001)"**
3. **State** bình thường là `inactive`; sẽ chuyển `firing` sau khi api-gateway log được Promtail đưa vào Loki
4. Xem log thật: menu trái → **Explore** → Datasource: Loki
   - Query: `{namespace="financial",app="api-gateway"} | json | event="jwt_verification_failed"`
   - Time range: Last 15 minutes → thấy 20 dòng log với `event: jwt_verification_failed`

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
| Detection | AUDIT payment_blocked_fraud log thật từ payment-service → Promtail → Loki → Grafana → SOAR |
| Playbook | `isolate_workload` (cô lập payment-service) |
| HITL | Có — critical severity |

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb2_fraud_gate.sh
```

### Bước 2: Output terminal mong đợi

```
[KB2_fraud_gate] Attempt 1 → HTTP 403 (fraud_score=75, verdict=block)
[KB2_fraud_gate] Attempt 2 → HTTP 403 (fraud_score=75, verdict=block)
[KB2_fraud_gate] Attempt 3 → HTTP 403 (fraud_score=75, verdict=block)
[KB2_fraud_gate] payment-service chặn 3/3 → AUDIT payment_blocked_fraud → Loki
[KB2_fraud_gate] PASS: KB2 | 3/3 blocked | log AUDIT thật → Loki (Grafana fire trong ≤1 phút)
```

> Bằng chứng thật nằm ở `HTTP 403` và log AUDIT `payment_blocked_fraud` từ payment-service được Promtail thu vào Loki. Xem chi tiết ở bước "Xác minh thủ công" bên dưới.

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

**Network Micro-segmentation**: Trong Zero Trust, mọi service-to-service call đều phải được xác thực. Khi notification-service pod cố gọi api-gateway mà không có Authorization header (mô phỏng service bị compromise gọi lateral), api-gateway từ chối ngay với `jwt_verification_failed, reason=missing_bearer` — không có implicit trust giữa các microservice.

### Tóm tắt

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1021.007 — Cloud Services (Lateral Movement) |
| Enforcement THẬT | kubectl exec notification-service → curl api-gateway không có auth → HTTP 401 |
| Detection | jwt_verification_failed (reason=missing_bearer) log thật từ api-gateway → Promtail → Loki → Grafana → SOAR |
| Playbook | `isolate_workload` |
| HITL | Có — critical severity |

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb3_lateral_movement.sh
```

### Bước 2: Output terminal mong đợi

```
[KB3_lateral_movement] Gọi http://api-gateway.financial.svc.cluster.local:8080/payments không có auth → HTTP 401
[KB3_lateral_movement] Gọi http://api-gateway.financial.svc.cluster.local:8080/transactions không có auth → HTTP 401
...
[KB3_lateral_movement] api-gateway từ chối 5/5 (missing_bearer) → WARN jwt_verification_failed → Loki
[KB3_lateral_movement] PASS: KB3 | 5/5 blocked (missing_bearer) | log thật → Loki (Grafana fire trong ≤1 phút)
```

### Bước 3: Xác minh lateral movement thủ công

```bash
# Lấy tên pod notification-service
NOTIF_POD=$(kubectl --context ctx-aws get pod -n financial -l app=notification-service \
  -o jsonpath='{.items[0].metadata.name}')

# Từ bên trong notification-service pod, gọi api-gateway không có auth
# → mô phỏng service bị compromise đang lateral move
kubectl --context ctx-aws exec -n financial "$NOTIF_POD" -- \
  wget -qO- "http://api-gateway.financial.svc.cluster.local:8080/health" 2>&1 || true

kubectl --context ctx-aws exec -n financial "$NOTIF_POD" -- \
  wget --server-response -O /dev/null \
  "http://api-gateway.financial.svc.cluster.local:8080/payments" 2>&1 | grep "HTTP/"
```

Kết quả: HTTP 401 — api-gateway ghi log `jwt_verification_failed, reason=missing_bearer` với source_ip = pod IP notification-service.

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

> Sau `isolate_workload`, `payment-service` có thể vẫn `1/1` — SOAR dùng label/NetworkPolicy thay vì scale. Bằng chứng thật của KB3 nằm ở `HTTP 401 missing_bearer` từ api-gateway khi notification-service pod gọi không có auth, không phải ở trạng thái deployment.

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
| Bằng chứng THẬT | 10 bulk HTTP request → api-gateway trace_middleware ghi bytes_sent thật → Loki |
| Nguồn log | http_request log từ api-gateway (bytes_sent từ Content-Length header) |
| Detection | http_request log (bytes_sent > 5000) thật → Promtail → Loki → Grafana → SOAR |
| Playbook | `restrict_egress` (scale core-banking → 0 trên OpenStack) |
| HITL | Có |

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb4_exfiltration.sh
```

### Bước 2: Output terminal mong đợi

```
[KB4_exfiltration] GET /transactions → HTTP 200, bytes_sent=2208
[KB4_exfiltration] GET /accounts/balance → HTTP 200, bytes_sent=30
...
[KB4_exfiltration] 10 bulk requests → tổng bytes đo thực
[KB4_exfiltration] api-gateway ghi http_request log với bytes_sent → Promtail → Loki
[KB4_exfiltration] PASS: KB4 | 10 bulk requests | log bytes_sent thật → Loki (Grafana fire trong ≤1 phút)
```

> `bytes_sent` được api-gateway trace_middleware đọc từ `Content-Length` response header và ghi vào log JSON. Grafana alert query lọc `bytes_sent > 5000` trên log thật từ `{namespace="financial",app="api-gateway"}`.

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

**Least Privilege**: api-gateway RBAC áp dụng deny-by-default — không có role `financial-write` thì không thể POST /payments, dù có JWT hợp lệ. merchant01 (chỉ có `financial-read`) bị api-gateway từ chối 6/6 lần, HTTP 403, ghi log `authz_denied` thật vào Loki.

### Tóm tắt

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1078 — Valid Accounts (Privilege Abuse) |
| Enforcement THẬT | merchant01 POST /payments × 6 → api-gateway RBAC từ chối 6/6 × HTTP 403 |
| Detection | WARN authz_denied log thật từ api-gateway → Promtail → Loki → Grafana → SOAR |
| Playbook | `block_source_ip` (thêm IP vào Redis blocklist 24h) |
| HITL | Có |

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb5_access_denied.sh
```

### Bước 2: Output terminal mong đợi

```
[KB5_access_denied]   POST /payments 100000 → HTTP 403
[KB5_access_denied]   POST /payments 50000 → HTTP 403
[KB5_access_denied]   POST /payments 200000 → HTTP 403
[KB5_access_denied]   POST /payments 75000 → HTTP 403
[KB5_access_denied]   POST /payments 1000000 → HTTP 403
[KB5_access_denied]   POST /payments 5000 → HTTP 403
[KB5_access_denied] api-gateway từ chối 6/6 (403) → WARN authz_denied → Loki
[KB5_access_denied] PASS: KB5 | 6/6 denied | log thật → Loki (Grafana fire trong ≤1 phút)
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

Kết quả: merchant01 → `HTTP 403` (api-gateway RBAC deny: `authz_denied`, required_role=financial-write).

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

**Workload Isolation + Least Privilege**: Zero Trust áp dụng cả cho container, không chỉ user. Hệ thống lab không enforce `runAsNonRoot` — security-scanner Job chạy như root (uid=0) với `CAP_DAC_OVERRIDE`, có thể đọc `/etc/shadow`. Job tự kiểm tra security context thật của mình và ghi log `privilege_escalation` (AUDIT level) ra stdout → Promtail → Loki → Grafana alert.

### Tóm tắt

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1611 — Escape to Host |
| Cơ chế | k8s Job `security-scanner` chạy trong namespace `financial`, tự kiểm tra uid/caps/shadow |
| Bằng chứng THẬT | uid=0, CAP_DAC_OVERRIDE active, /etc/shadow readable → log AUDIT thật |
| Detection | privilege_escalation log thật → Promtail → Loki → Grafana → SOAR |
| Playbook | `quarantine_workload` (scale api-gateway → 0 để forensics) |
| HITL | Có — critical severity |

---

### Bước 1: Xem bằng chứng vi phạm trực tiếp (tùy chọn trước khi chạy script)

```bash
# Xác nhận namespace financial không enforce runAsNonRoot
POD=$(kubectl --context ctx-aws get pod -n financial -l app=api-gateway \
  -o jsonpath='{.items[0].metadata.name}')

kubectl --context ctx-aws exec -n financial "$POD" -- id
# uid=0(root) gid=0(root) groups=0(root)

kubectl --context ctx-aws exec -n financial "$POD" -- cat /proc/1/status | grep CapEff
# CapEff: 00000000a80425fb  (CAP_DAC_OVERRIDE + CAP_SETUID active)
```

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

Script tự động:
1. Xóa Job security-scanner cũ (nếu còn tồn tại)
2. Apply `k8s/financial/security-scanner-job.yaml` vào namespace `financial`
3. Chờ Job hoàn thành (timeout 90s)
4. Hiển thị log thật từ Job

### Bước 4: Output terminal mong đợi

```
[KB6_privilege_escalation] Deploy security-scanner Job vào namespace financial
[KB6_privilege_escalation] Chờ security-scanner Job hoàn thành (timeout 90s)...
[KB6_privilege_escalation] Kết quả từ security-scanner (log thật):
  event=privilege_escalation uid=0 caps=['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID',
       'SETGID', 'SETUID', 'NET_BIND_SERVICE', 'AUDIT_WRITE'] shadow=True violation=True
[KB6_privilege_escalation] Log thật từ security-scanner → Promtail → Loki {namespace=financial, app=security-scanner}
[KB6_privilege_escalation] PASS: KB6 | security-scanner Job completed | log AUDIT thật → Loki (Grafana fire trong ≤2 phút)
```

### Bước 5: Xem log AUDIT trong Grafana

1. http://localhost:3000 → **Explore** → Datasource: Loki
2. Query: `{namespace="financial",app="security-scanner"} | json | event="privilege_escalation"`
3. Thấy record JSON thật từ security-scanner Job:
   ```json
   {
     "level": "AUDIT",
     "service": "security-scanner",
     "event": "privilege_escalation",
     "uid": 0,
     "cap_eff": "00000000a80425fb",
     "dangerous_capabilities": ["CHOWN","DAC_OVERRIDE","SETUID"],
     "shadow_readable": true,
     "violation": true
   }
   ```

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

| KB | Tên | MITRE | Zero Trust Layer | Enforcement | Log nguồn | Playbook |
|---|---|---|---|---|---|---|
| KB1 | Brute Force Login | T1110.001 | Authentication | 401 × 20 (JWT invalid) | api-gateway: jwt_verification_failed | revoke_user_sessions |
| KB2 | Fraud Gate Bypass | T1078.004 | Authorization (fraud) | HTTP 403, score=75 | payment-service: payment_blocked_fraud (AUDIT) | isolate_workload |
| KB3 | Lateral Movement | T1021.007 | mTLS / auth | HTTP 401 × 5 (no auth) | api-gateway: jwt_verification_failed (missing_bearer) | isolate_workload |
| KB4 | Data Exfiltration | T1041 | Egress monitoring | bytes_sent log thật | api-gateway: http_request (bytes_sent) | restrict_egress |
| KB5 | Access Denied Spike | T1078 | RBAC | HTTP 403 × 6 (no role) | api-gateway: authz_denied (WARN) | block_source_ip |
| KB6 | Privilege Escalation | T1611 | Workload isolation | uid=0, shadow readable | security-scanner Job: privilege_escalation (AUDIT) | quarantine_workload |

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

| Rule | LogQL (log thật) | Threshold | KB |
|---|---|---|---|
| Brute Force Login (T1110.001) | `sum by (source_ip) (count_over_time({namespace="financial",app="api-gateway"} \| json \| event="jwt_verification_failed" [1m]))` | ≥ 1 | KB1 |
| Fraud Gate Bypass (T1078.004) | `sum(count_over_time({namespace="financial",app="payment-service"} \| json \| level="AUDIT" \| event="payment_blocked_fraud" [5m]))` | ≥ 1 | KB2 |
| Lateral Movement (T1021.007) | `sum(count_over_time({namespace="financial",app="api-gateway"} \| json \| event="jwt_verification_failed" \| reason="missing_bearer" [5m]))` | ≥ 1 | KB3 |
| Data Exfiltration (T1041) | `sum(count_over_time({namespace="financial",app="api-gateway"} \| json \| event="http_request" \| path=~"/transactions.*\|/accounts.*" \| bytes_sent > 5000 [5m]))` | ≥ 1 | KB4 |
| Access Denied Spike (T1078) | `sum by (source_ip) (count_over_time({namespace="financial",app="api-gateway"} \| json \| event="authz_denied" [1m]))` | ≥ 1 | KB5 |
| Privilege Escalation (T1611) | `sum(count_over_time({namespace="financial",app="security-scanner"} \| json \| event="privilege_escalation" [5m]))` | ≥ 1 | KB6 |

> Tất cả LogQL query trên đều là log **thật** từ service. Không có log inject giả — Promtail thu log từ pod stdout → Loki với label `{namespace="financial", app="<service>"}`.

### Explore — Xem log Loki

1. Menu trái → **Explore** → Datasource: **Loki**
2. Các query hữu ích:

```
# KB1 — Brute force: JWT không hợp lệ
{namespace="financial",app="api-gateway"} | json | event="jwt_verification_failed"

# KB2 — Fraud gate: giao dịch bị chặn
{namespace="financial",app="payment-service"} | json | level="AUDIT" | event="payment_blocked_fraud"

# KB3 — Lateral movement: gọi không có auth
{namespace="financial",app="api-gateway"} | json | event="jwt_verification_failed" | reason="missing_bearer"

# KB4 — Data exfiltration: response bytes lớn
{namespace="financial",app="api-gateway"} | json | event="http_request" | bytes_sent > 5000

# KB5 — Access denied: thiếu role
{namespace="financial",app="api-gateway"} | json | event="authz_denied"

# KB6 — Privilege escalation: security-scanner Job
{namespace="financial",app="security-scanner"} | json | event="privilege_escalation"

# Tất cả log AUDIT level
{namespace="financial"} | json | level="AUDIT"
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

## 17. Demo log thực tế — api-gateway, payment-service, SPIRE/SPIFFE

Phần này hướng dẫn xem và giải thích log thực tế từ các lớp Zero Trust enforcement trong hệ thống. Tất cả log đến từ **service thật** qua pipeline: stdout → Promtail DaemonSet → Loki.

---

### 17.1 api-gateway Log (enforcement chính)

api-gateway ghi JSON log mỗi request qua `trace_middleware` và `ZTLabLogger`. Log được Promtail đẩy vào Loki với label `{namespace="financial", app="api-gateway"}`.

#### Xem log trực tiếp từ pod

```bash
# api-gateway log (tất cả event)
kubectl --context ctx-aws logs -n financial deployment/api-gateway --tail=30

# Chỉ lấy dòng có event security
kubectl --context ctx-aws logs -n financial deployment/api-gateway --tail=100 | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('event') in ('jwt_verification_failed','authz_denied','http_request'):
            print(f'  [{d.get(\"event\")}] status={d.get(\"status_code\")} path={d.get(\"path\")} src={d.get(\"source_ip\")} reason={d.get(\"reason\",\"-\")} bytes={d.get(\"bytes_sent\",\"-\")}')
    except: pass
"
```

#### Format JSON của mỗi dòng log bảo mật

```json
{
  "timestamp": "2026-06-27T06:48:51.871Z",
  "level": "WARN",
  "service": "api-gateway",
  "cloud": "aws",
  "event": "jwt_verification_failed",
  "method": "POST",
  "path": "/payments",
  "status_code": 401,
  "source_ip": "10.42.0.1",
  "reason": "invalid_rs256",
  "trace_id": "a1b2c3d4"
}
```

```json
{
  "timestamp": "2026-06-27T07:10:22.301Z",
  "level": "WARN",
  "service": "api-gateway",
  "event": "authz_denied",
  "path": "/payments",
  "status_code": 403,
  "source_ip": "10.42.0.5",
  "required_role": "financial-write",
  "user": "merchant01",
  "trace_id": "b5c6d7e8"
}
```

```json
{
  "timestamp": "2026-06-27T07:15:00.100Z",
  "level": "INFO",
  "service": "api-gateway",
  "event": "http_request",
  "method": "GET",
  "path": "/transactions",
  "status_code": 200,
  "duration_ms": 45,
  "bytes_sent": 2208,
  "trace_id": "c9d0e1f2"
}
```

**Các event quan trọng**:
- `jwt_verification_failed` — JWT sai hoặc thiếu (KB1: invalid_rs256, KB3: missing_bearer)
- `authz_denied` — đủ auth nhưng thiếu role (KB5: financial-write required)
- `http_request` — mọi request thành công, có field `bytes_sent` (KB4)

#### Query Loki để tìm log tấn công

```bash
# KB1 — brute force: JWT không hợp lệ
curl -sG http://localhost:13100/loki/api/v1/query_range \
  --data-urlencode 'query={namespace="financial",app="api-gateway"} | json | event="jwt_verification_failed"' \
  --data-urlencode 'limit=20' --data-urlencode 'start=0' | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
for s in d.get('data',{}).get('result',[]):
    for ts, line in s.get('values',[]):
        j=json.loads(line)
        print(f'  [{j.get(\"timestamp\",\"?\")}] {j.get(\"method\")} {j.get(\"path\")} reason={j.get(\"reason\")} src={j.get(\"source_ip\")}')
" 2>/dev/null
```

**Trong Grafana UI** (http://localhost:3000):
1. Explore → Loki datasource
2. Log browser: `{namespace="financial",app="api-gateway"} | json | event="jwt_verification_failed"`
3. Click field `source_ip` để group brute force theo IP
4. Filter `bytes_sent > 5000` để tìm data exfiltration

#### Ý nghĩa Zero Trust

| Scenario | Event | Reason | Giải thích |
|---|---|---|---|
| KB1 Brute Force | jwt_verification_failed | invalid_rs256 | JWT không hợp lệ, api-gateway từ chối |
| KB3 Lateral Move | jwt_verification_failed | missing_bearer | Service call không có auth header |
| KB4 Exfiltration | http_request | — | bytes_sent cao từ bulk download |
| KB5 Access Denied | authz_denied | — | JWT hợp lệ nhưng thiếu role financial-write |

---

### 17.2 payment-service AUDIT Log (fraud detection)

payment-service ghi log AUDIT level khi chặn giao dịch nghi ngờ. Log đến Loki với label `{namespace="financial", app="payment-service"}`.

#### Xem log fraud blocking

```bash
# payment-service AUDIT log
kubectl --context ctx-aws logs -n financial deployment/payment-service --tail=50 | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('event') == 'payment_blocked_fraud':
            print(f'  AUDIT fraud_block: amount={d.get(\"amount\")} channel={d.get(\"channel\")} score={d.get(\"fraud_score\")} verdict={d.get(\"verdict\")}')
    except: pass
"
```

#### Format JSON log AUDIT payment_blocked_fraud

```json
{
  "timestamp": "2026-06-27T07:20:11.500Z",
  "level": "AUDIT",
  "service": "payment-service",
  "event": "payment_blocked_fraud",
  "account": "ACC-1001",
  "amount": 500000000,
  "channel": "tor",
  "fraud_score": 75,
  "verdict": "block",
  "reasons": ["critical_amount", "risky_channel"],
  "trace_id": "d4e5f6g7"
}
```

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

| Alert Rule | Severity | LogQL (log thật) | SOAR Playbook |
|---|---|---|---|
| Brute Force Login | high | `{namespace="financial",app="api-gateway"} \| json \| event="jwt_verification_failed"` | revoke_user_sessions |
| Fraud Gate Bypass | critical | `{namespace="financial",app="payment-service"} \| json \| level="AUDIT" \| event="payment_blocked_fraud"` | isolate_workload |
| Lateral Movement | critical | `{namespace="financial",app="api-gateway"} \| json \| event="jwt_verification_failed" \| reason="missing_bearer"` | isolate_workload |
| Data Exfiltration | high | `{namespace="financial",app="api-gateway"} \| json \| event="http_request" \| bytes_sent > 5000` | restrict_egress |
| Access Denied Spike | high | `{namespace="financial",app="api-gateway"} \| json \| event="authz_denied"` | block_source_ip |
| Privilege Escalation | critical | `{namespace="financial",app="security-scanner"} \| json \| event="privilege_escalation"` | quarantine_workload |

#### Cách Grafana gửi alert (flow thật)

1. Service ghi JSON log → stdout → Promtail DaemonSet scrape (mỗi 5s) → Loki
2. Grafana evaluate rule mỗi 1 phút → so sánh với LogQL threshold
3. Rule fire → Grafana gửi webhook thật đến `http://soar-engine.plg-stack.svc.cluster.local:8080/grafana-webhook`
4. SOAR tạo case (dedup 5 phút — mỗi attack_type chỉ tạo 1 case)

> **Lưu ý dedup**: Nếu thấy `"status": "deduped"` trong SOAR response — đây là hoạt động đúng. Case gốc đã được tạo bởi Grafana alert trước đó.

#### Xem source_ip trong SOAR case

Sau khi chạy KB script, source_ip sẽ xuất hiện trong SOAR case (extract từ log evidence):

```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=json.load(sys.stdin)
for c in cases[-6:]:
    print(f'  {c[\"case_id\"][:35]} | {c[\"attack_type\"]:20} | sev={c[\"severity\"]:8} | src={c.get(\"source_ip\",\"N/A\")}')
"
```

`source_ip` trong log thật là IP thực của pod/client gửi request — không còn dùng IP cố định giả.

---

## 18. Xử lý sự cố thường gặp

### Không thấy case trong Web Portal sau khi chạy script

Script sinh traffic thật → service ghi log → Promtail → Loki. **Case được tạo bởi Grafana real alert** sau khi evaluate log, không phải script. Đợi **≤1 phút** để Grafana evaluate rule và gửi webhook tới SOAR.

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

### KB6 lỗi "security-scanner Job không hoàn thành trong 90s"

**Nguyên nhân**: image `python:3.12-alpine` chưa được pull về node lần đầu tiên.

```bash
# Kiểm tra trạng thái Job
kubectl --context ctx-aws get job security-scanner -n financial
kubectl --context ctx-aws describe job security-scanner -n financial | grep -A5 Events

# Nếu lỗi ImagePullBackOff → đợi pull image (1-2 phút lần đầu)
kubectl --context ctx-aws get pods -n financial -l app=security-scanner

# Xóa Job cũ và chạy lại
kubectl --context ctx-aws delete job security-scanner -n financial --ignore-not-found
bash tests/grafana_kb6_privilege_escalation.sh
```

### KB6 quarantine_workload scale api-gateway về 0

**Sau khi approve KB6**: api-gateway bị scale=0, cần restore:

```bash
bash scripts/run-demo.sh --restore
kubectl --context ctx-aws get deployment api-gateway -n financial
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

*Cập nhật: 2026-06-28 — tất cả 6 KB dùng log thật (không inject giả), Grafana alert rules query log thật từ service pod, KB6 dùng security-scanner Job thay vì kubectl exec + inject audit log*
