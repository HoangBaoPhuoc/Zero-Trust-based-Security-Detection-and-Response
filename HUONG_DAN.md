# ZTLab — Hướng Dẫn Vận Hành & Demo

> **Đồ án**: Zero Trust-based Security Detection and Response for Microservices in Multi-Cloud  
> **Sinh viên**: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> **GVHD**: ThS. Đỗ Thị Phương Uyên · Môn: NT114.Q21.ANTT  
> **Email nhận cảnh báo HITL**: voha2005@gmail.com

---

## Mục lục

1. [Kiến trúc hệ thống](#1-kiến-trúc-hệ-thống)
2. [Các dịch vụ trên Kubernetes](#2-các-dịch-vụ-trên-kubernetes)
3. [Tài khoản & credentials](#3-tài-khoản--credentials)
4. [URL truy cập qua port-forward](#4-url-truy-cập-qua-port-forward)
5. [Khởi động sau khi restart máy](#5-khởi-động-sau-khi-restart-máy)
6. [Kiểm tra sức khoẻ hệ thống](#6-kiểm-tra-sức-khoẻ-hệ-thống)
7. [Chuẩn bị trước khi demo](#7-chuẩn-bị-trước-khi-demo)
8. [KB1 — Brute Force Login (T1110.001)](#8-kb1--brute-force-login-t1110001)
9. [KB2 — Fraud Gate Bypass (T1078.004)](#9-kb2--fraud-gate-bypass-t1078004)
10. [KB3 — Lateral Movement (T1021.007)](#10-kb3--lateral-movement-t1021007)
11. [KB5 — Access Denied Spike / OPA RBAC (T1078)](#11-kb5--access-denied-spike--opa-rbac-t1078)
12. [Chạy 4 kịch bản cùng lúc](#12-chạy-4-kịch-bản-cùng-lúc)
13. [SOAR — Phê duyệt case & Web Portal](#13-soar--phê-duyệt-case--web-portal)
14. [Xử lý sự cố thường gặp](#14-xử-lý-sự-cố-thường-gặp)

---

## 1. Kiến trúc hệ thống

### Luồng Zero Trust (request flow)

```
Người dùng / Script tấn công
      │  HTTP + JWT Bearer Token
      ▼
[API Gateway]  ← port 18080 (qua port-forward)
      │
      │  Envoy sidecar gọi OPA ext_authz (gRPC) TRƯỚC khi forward
      ▼
[OPA Server]   ← pod opa-server trong namespace financial
      │
      ├─ allow=true  → Envoy forward request → API Gateway Python app → service
      └─ allow=false → Envoy trả HTTP 403 NGAY (app Python KHÔNG chạy)
                         │
                         ▼
                  OPA ghi decision log ra stdout
                         │
                         ▼
                  Promtail DaemonSet scrape log
                         │
                         ▼
                  Loki (3100) — stream labels: {job="opa-decisions", opa_result="false", ...}
```

### Luồng detection & response

```
Loki (log store)
      │
      │  Grafana evaluate LogQL mỗi 1 phút
      ▼
[Grafana Alert] — FIRING nếu query > 0
      │
      │  webhook POST /grafana-webhook
      ▼
[SOAR Engine]  — tạo CaseRecord
      │
      ├─ severity < high → skipped (ghi log)
      └─ severity >= high → pending_approval
                              │
                              │  gửi email HITL → voha2005@gmail.com
                              │  (có log evidence + nút phê duyệt)
                              ▼
                     Admin xem Web Portal → approve/reject playbook
```

### Tại sao svid=null trong log KB5 là đúng

- **SVID** (SPIFFE Verifiable Identity Document) = chứng chỉ TLS của service trong mesh (mTLS)
- KB3 (Lateral Movement): notification-service → payment-service **nội bộ** dùng mTLS → có SVID
- KB5 (Access Denied): merchant01 là **người dùng bên ngoài** gọi API Gateway bằng JWT Bearer token → **không có mTLS SVID**, svid=null là ĐÚNG
- OPA vẫn từ chối vì JWT hợp lệ nhưng **role financial-read không có quyền POST /payments**

---

## 2. Các dịch vụ trên Kubernetes

### Namespace `financial` — Microservices

| Pod / Deployment | READY | Mô tả | Cluster IP |
|---|---|---|---|
| `api-gateway` | 2/2 | API gateway + Envoy sidecar | 10.43.11.23:8080 |
| `payment-service` | 2/2 | Xử lý thanh toán + Envoy sidecar | 10.43.75.232:8080 |
| `fraud-detection` | 2/2 | Chấm điểm fraud + Envoy sidecar | 10.43.190.34:8080 |
| `notification-service` | 2/2 | Gửi thông báo + Envoy sidecar | 10.43.247.146:8080 |
| `web-portal` | 2/2 | Security dashboard analyst01 + Envoy | 10.43.185.112:8080 |
| `opa-server` | 1/1 | OPA centralized ext_authz server | 10.43.55.170:8181/9191 |
| `redis` | 1/1 | Redis cache (blocked IPs, sessions) | 10.43.172.79:6379 |
| `postgres-txn` | 1/1 | PostgreSQL transaction DB | 10.43.242.69:5432 |
| `postgres-accounts` | 1/1 | PostgreSQL accounts DB | 10.43.170.180:5432 |
| `pgadmin` | 1/1 | pgAdmin web UI | 10.43.96.61:80 |
| `redisinsight` | 1/1 | RedisInsight web UI | 10.43.109.94:5540 |

> Pods có `READY 2/2` = container ứng dụng + Envoy sidecar. Envoy được inject tự động bởi Istio/SPIRE.

### Namespace `identity` — Keycloak

| Pod | READY | Mô tả | Cluster IP |
|---|---|---|---|
| `keycloak` | 1/1 | Identity Provider, phát JWT, quản lý users | 10.43.67.170:8080 |
| `keycloak-db` | 1/1 | PostgreSQL cho Keycloak | 10.43.108.226:5432 |

Realm **ztlab** chứa users: testuser01, merchant01, analyst01, admin.

### Namespace `plg-stack` — Monitoring & Security

| Pod / Deployment | READY | Mô tả | Cluster IP |
|---|---|---|---|
| `grafana` | 1/1 | Alert rules, Loki Explore, dashboards | 10.43.27.74:3000 |
| `loki` | 1/1 | Log aggregation (NodePort 31000) | 10.43.186.251:3100 |
| `promtail` (DaemonSet) | 1/1×2 | Log collector trên mỗi node K3s | — |
| `soar-engine` | 1/1 | SOAR: case management, email HITL, playbooks | 10.43.117.45:8080 |
| `ai-analyzer` | 1/1 | AI log analyzer (phụ trợ) | 10.43.25.182:8080 |
| `security-scorer` | 1/1 | Heuristic scoring | 10.43.105.208:8080 |

### Kiến trúc OPA (centralized ext_authz)

```
Tất cả service trong namespace financial:
api-gateway    ──(gRPC ext_authz)──┐
payment-service ─(gRPC ext_authz)──┤──→ opa-server (pod duy nhất)
notification-svc ─(gRPC ext_authz)─┘       │
fraud-detection ──(gRPC ext_authz)──┘       │ decision_logs → stdout
                                            │ → Promtail → Loki
                                            │ {job="opa-decisions"}
```

OPA Server đọc policy Rego → kiểm tra mọi request → ghi quyết định ra stdout.  
Promtail scrape stdout của pod opa-server → đẩy vào Loki với labels trích xuất bằng regex.

### Promtail — 3 job scrape

| Job | Source | Labels chính |
|---|---|---|
| `kubernetes-pods` | stdout tất cả pods | `{namespace, app, pod, container}` |
| `envoy-access-k8s` | container `envoy` trong ns `financial` | `{job="envoy-access", response_code, source_ip, method, path}` |
| `opa-decisions-k8s` | container `opa` trong ns `financial` | `{job="opa-decisions", opa_result, request_path}` |

---

## 3. Tài khoản & credentials

| Dịch vụ | Username | Password | Ghi chú |
|---|---|---|---|
| **Keycloak Admin** | admin | ztlab-admin-2026 | Trang /admin/master → quản lý realm |
| **Grafana** | admin | ZTALab2026! | Alert rules, Loki Explore |
| **Web Portal** | analyst01 | Test1234! | Security dashboard, phê duyệt SOAR case |
| **API (testuser01)** | testuser01 | Test1234! | financial-read + financial-write |
| **API (merchant01)** | merchant01 | Test1234! | financial-read ONLY — dùng cho KB5 |
| **pgAdmin** | admin@ztlab.com | ztlab2026 | Xem database |

---

## 4. URL truy cập qua port-forward

Tất cả service đều trong cluster K3s, KHÔNG có external IP. Truy cập qua `kubectl port-forward`:

| URL | Service trong K8s | Namespace | Ghi chú |
|---|---|---|---|
| http://localhost:18080 | `svc/api-gateway:8080` | financial | REST API gateway |
| http://localhost:18081 | `svc/web-portal:8080` | financial | Security dashboard |
| http://localhost:18081/security | — | — | Trang phê duyệt SOAR (analyst01) |
| http://localhost:8180 | `svc/keycloak:8080` | identity | Keycloak UI & token endpoint |
| http://localhost:3000 | `svc/grafana:3000` | plg-stack | Grafana (alerts, explore) |
| http://localhost:8091 | `svc/soar-engine:8080` | plg-stack | SOAR API (/health, /cases) |
| http://localhost:13100 | `svc/loki:3100` | plg-stack | Loki query API |

> **Lưu ý**: Port-forward phải được bật trước khi dùng. Xem mục 5 bên dưới.

---

## 5. Khởi động sau khi restart máy

### Bước 1 — Kiểm tra pods

```bash
kubectl --context ctx-aws get pods -n financial
kubectl --context ctx-aws get pods -n identity
kubectl --context ctx-aws get pods -n plg-stack
```

Tất cả phải `Running`. Microservice phải `2/2` (app + Envoy sidecar).

### Bước 2 — Bật port-forward (chạy từng lệnh riêng biệt)

```bash
nohup kubectl --context ctx-aws port-forward svc/grafana       3000:3000  -n plg-stack >/tmp/pf-grafana.log 2>&1 &
nohup kubectl --context ctx-aws port-forward svc/loki          13100:3100 -n plg-stack >/tmp/pf-loki.log    2>&1 &
nohup kubectl --context ctx-aws port-forward svc/api-gateway   18080:8080 -n financial >/tmp/pf-gw.log      2>&1 &
nohup kubectl --context ctx-aws port-forward svc/keycloak      8180:8080  -n identity  >/tmp/pf-kc.log      2>&1 &
nohup kubectl --context ctx-aws port-forward svc/web-portal    18081:8080 -n financial >/tmp/pf-wp.log      2>&1 &
nohup kubectl --context ctx-aws port-forward svc/soar-engine   8091:8080  -n plg-stack >/tmp/pf-soar.log    2>&1 &
```

> **Quan trọng**: KHÔNG dùng `&&` giữa các lệnh port-forward (gây exit 144). Chạy từng lệnh một với `nohup ... &`.

### Bước 3 — Kiểm tra nhanh

```bash
curl -s http://localhost:18080/health | python3 -m json.tool
curl -s http://localhost:13100/ready && echo "Loki OK"
curl -s -u admin:ZTALab2026! http://localhost:3000/api/health \
  | python3 -c "import sys,json; print('Grafana:', json.load(sys.stdin)['database'])"
curl -s http://localhost:8091/health \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('SOAR:', d['status'], '| cases:', d.get('total_cases',0))"
```

---

## 6. Kiểm tra sức khoẻ hệ thống

```bash
# Keycloak
curl -s http://localhost:8180/realms/ztlab/.well-known/openid-configuration \
  | python3 -c "import sys,json; print('Keycloak OK:', json.load(sys.stdin)['issuer'])"

# Loki — kiểm tra có log không
curl -s "http://localhost:13100/loki/api/v1/label/job/values" \
  | python3 -c "import sys,json; print('Loki jobs:', json.load(sys.stdin)['data'])"
# Phải thấy: envoy-access, opa-decisions, kubernetes-pods, soar-engine

# Grafana alert rules
curl -s -u admin:ZTALab2026! http://localhost:3000/api/ruler/grafana/api/v1/rules \
  | python3 -c "
import json,sys
data=json.load(sys.stdin)
for folder, groups in data.items():
    for group in groups:
        for rule in group.get('rules', []):
            labels = rule.get('labels', {})
            ga = rule.get('grafana_alert', {})
            if labels.get('category') == 'security':
                print(f\"  [{labels.get('severity')}] {labels.get('attack_type')} | {ga.get('title','')[:50]}\")
"
# Phải thấy 4 rules: brute_force, fraud_gate_bypass, lateral_movement, access_denied
```

---

## 7. Chuẩn bị trước khi demo

> **Đọc kỹ trước khi chạy**:
> - Scripts chạy **tấn công thật** → **log thật** → Promtail scrape → Loki → Grafana alert **~1 phút sau**
> - SOAR dedup **5 phút**: cùng kịch bản trong 5 phút chỉ tạo 1 case
> - Không cần chờ giữa các kịch bản (KB1→KB2→KB3→KB5 chạy liên tiếp được)
> - Sau khi chạy script, mở email voha2005@gmail.com và Web Portal để nhận alert

### Mở 2 terminal song song

```bash
# Terminal 2 — theo dõi SOAR cases (refresh 5s)
watch -n5 'curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=json.load(sys.stdin)
print(f\"Tổng: {len(cases)} cases\")
for c in sorted(cases, key=lambda x: x[\"ts\"], reverse=True)[:5]:
    print(c[\"case_id\"][:33], \"|\", c[\"attack_type\"][:22], \"|\", c[\"status\"])
"'

# Terminal 3 — theo dõi SOAR logs real-time
kubectl --context ctx-aws logs -n plg-stack -l app=soar-engine -f 2>/dev/null \
  | grep --line-buffered -E "hitl_email|pending_approval|soar_action|grafana_soar"
```

### Lấy token testuser01 (dùng để test thủ công)

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")
echo "Token: ${TOKEN:0:30}..."
```

---

## 8. KB1 — Brute Force Login (T1110.001)

### Zero Trust principle được chứng minh

**Continuous Verification** — Mọi request PHẢI có JWT hợp lệ. Script gửi 20 request với Bearer token giả → OPA ext_authz từ chối → Envoy trả **HTTP 403**. OPA ghi quyết định ra stdout → Promtail → Loki.

### Thông tin kỹ thuật

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1110.001 — Password Guessing |
| Tấn công | 20 request POST /payments với JWT không hợp lệ |
| Layer từ chối | OPA ext_authz → Envoy HTTP 403 (app Python KHÔNG chạy) |
| Log nguồn | **Envoy access log** → `{job="envoy-access", response_code="403"}` |
| Grafana LogQL | `sum by (source_ip) (count_over_time({job="envoy-access", response_code="403"}[1m])) > 10` |
| Ngưỡng fire | > 10 lần 403 từ cùng source_ip trong 1 phút |
| Severity | high |
| Playbook | `revoke_user_sessions` |
| HITL | Có — email voha2005@gmail.com + phê duyệt Web Portal |

### Chạy test

```bash
cd /home/deployer/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
bash tests/grafana_kb1_brute_force.sh
```

### Output mong đợi

```
[KB1_brute_force] api-gateway chặn 20/20 (401) — jwt_verification_failed ghi vào Loki
[KB1_brute_force] PASS: KB1 | 20/20 blocked | log thật → Loki (Grafana fire trong ≤1 phút)
```

> Lưu ý: script in "(401)" nhưng thực tế Envoy log **403** vào Loki — đây là response code OPA trả về qua Envoy.

### Verify log trong Loki (Grafana Explore)

1. Mở http://localhost:3000 → **Explore** → Datasource: **Loki**
2. Query:
   ```
   {job="envoy-access", response_code="403"}
   ```
3. Phải thấy log JSON: `response_code: 403, path: /payments, source_ip: 127.0.0.1`

### Sau ~1 phút — Alert FIRING

- **Grafana**: Alerting → Alert rules → folder ZTLab → `Kịch bản 1 — Brute Force` → **Firing**
- **SOAR log**: `hitl_email_sent` → voha2005@gmail.com
- **Email**: tiêu đề "⚠ SOAR HITL: Brute Force Login (T1110.001)" + log evidence (403 từ Loki) + nút Web Portal

---

## 9. KB2 — Fraud Gate Bypass (T1078.004)

### Zero Trust principle được chứng minh

**Assume Breach** — Ngay cả khi có token hợp lệ và được authorized, business logic layer (fraud-detection) vẫn chặn giao dịch bất thường. Payment-service ghi audit log `payment_blocked_fraud` → Loki.

### Thông tin kỹ thuật

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1078.004 — Cloud Accounts |
| Tấn công | testuser01 POST /payments với amount rất lớn hoặc velocity cao → fraud score ≥ 75 |
| Layer từ chối | fraud-detection service (business logic) → payment-service trả 403 |
| Log nguồn | **payment-service stdout** → `{namespace="financial", app="payment-service"} \| json \| event="payment_blocked_fraud"` |
| Grafana LogQL | `sum(count_over_time({namespace="financial",app="payment-service"} \| json \| level="AUDIT" \| event="payment_blocked_fraud" [10m]))` |
| Ngưỡng fire | > 0 lần trong 10 phút |
| Severity | critical |
| Playbook | `isolate_workload` |
| HITL | Có — email voha2005@gmail.com + phê duyệt Web Portal |

### Chạy test

```bash
bash tests/grafana_kb2_fraud_gate.sh
```

### Output mong đợi

```
[KB2_fraud_gate] PASS: ...payment_blocked_fraud events → Loki
```

### Verify log trong Loki

```
{namespace="financial", app="payment-service"} | json | event="payment_blocked_fraud"
```

Phải thấy: `level=AUDIT, event=payment_blocked_fraud, fraud_score=<số>, transaction_id=...`

### Sau ~1 phút — Alert FIRING

- **Grafana**: `Kịch bản 2 — Fraud Gate Bypass` → **Firing**
- **Email**: "Fraud Gate Bypass (T1078.004)" + log evidence từ payment-service

---

## 10. KB3 — Lateral Movement (T1021.007)

### Zero Trust principle được chứng minh

**Least Privilege / Micro-segmentation** — Dù notification-service CÓ SVID hợp lệ (mTLS certificate), nó vẫn KHÔNG được phép gọi `/payments/internal/execute` vì OPA policy chỉ cho phép payment-service gọi endpoint nội bộ này. OPA ghi decision log với `opa_result=false`.

### Thông tin kỹ thuật

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1021.007 — Cloud Services |
| Tấn công | notification-service giả mạo gọi payment-service:8080/payments/internal/execute |
| Layer từ chối | OPA ext_authz (kiểm tra SVID caller + path whitelist) → Envoy HTTP 403 |
| Log nguồn | **OPA decision log** → `{job="opa-decisions", opa_result="false", request_path="/payments/internal/execute"}` |
| Grafana LogQL | `sum(count_over_time({job="opa-decisions",opa_result="false",request_path="/payments/internal/execute"}[10m]))` |
| Ngưỡng fire | > 0 lần trong 10 phút |
| Severity | critical |
| Playbook | `isolate_workload` |
| HITL | Có — email voha2005@gmail.com + phê duyệt Web Portal |

### Chạy test

```bash
bash tests/grafana_kb3_lateral_movement.sh
```

### Output mong đợi

```
[KB3_lateral_movement] notification-service → /payments/internal/execute: HTTP 403 (OPA deny)
[KB3_lateral_movement] PASS: 3/3 bị OPA từ chối | log thật → Loki {job=opa-decisions}
```

### Verify log trong Loki

```
{job="opa-decisions", opa_result="false", request_path="/payments/internal/execute"}
```

Phải thấy JSON quyết định OPA: `result: false, ":path": "/payments/internal/execute"`.

### Sau ~1 phút — Alert FIRING

- **Grafana**: `Kịch bản 3 — Lateral Movement` → **Firing**
- **Email**: "Lateral Movement — Invalid SVID (T1021.007)" + log evidence từ OPA decision log

---

## 11. KB5 — Access Denied Spike / OPA RBAC (T1078)

### Zero Trust principle được chứng minh

**Least Privilege** — merchant01 có JWT hợp lệ (authenticated) nhưng role `financial-read` không có quyền POST /payments (chỉ `financial-write` mới được). OPA RBAC từ chối → Envoy 403. Đây là enforcement **authorization** (sau khi đã authenticated).

### Tại sao svid=null là đúng

merchant01 là **người dùng bên ngoài** gọi API qua HTTP với JWT Bearer token — không dùng mTLS nên không có SVID. `svid=null` trong log là bình thường. Điều quan trọng là OPA vẫn từ chối vì thiếu role phù hợp.

### Thông tin kỹ thuật

| | Chi tiết |
|---|---|
| MITRE ATT&CK | T1078 — Valid Accounts |
| Tấn công | merchant01 (financial-read) thử POST /payments nhiều lần |
| Layer từ chối | OPA RBAC: `role_permits_action=false` → Envoy HTTP 403 |
| Log nguồn | **OPA decision log** → `{job="opa-decisions", opa_result="false", request_path="/payments"}` |
| Grafana LogQL | `sum(count_over_time({job="opa-decisions", opa_result="false", request_path="/payments"}[10m]))` |
| Ngưỡng fire | > 0 lần trong 10 phút |
| Severity | high |
| Playbook | `block_source_ip` |
| HITL | Có — email voha2005@gmail.com + phê duyệt Web Portal |

### Chạy test

```bash
bash tests/grafana_kb5_access_denied.sh
```

### Output mong đợi

```
[KB5_access_denied]   POST /payments 100000 → HTTP 403
...
[KB5_access_denied] OPA RBAC từ chối 6/6 (403) → decision log → Loki {job=opa-decisions, request_path=/payments}
[KB5_access_denied] PASS: KB5 DONE | OPA RBAC từ chối 6/6 (403) | Log thật từ OPA decision log
```

### Verify log trong Loki

```
{job="opa-decisions", opa_result="false", request_path="/payments"}
```

Phải thấy: OPA decision với `result: false`, `authorization: Bearer eyJ...` (JWT có nhưng role sai), `svid: null` (external user, không có mTLS).

### Sau ~1 phút — Alert FIRING

- **Grafana**: `Kịch bản 5 — Access Denied Spike` → **Firing**
- **Email**: "Access Denied Spike (T1078)" + log evidence từ OPA decision log

---

## 12. Chạy 4 kịch bản cùng lúc

```bash
cd /home/deployer/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud
bash tests/grafana_run_all.sh
```

Script chạy tuần tự KB1→KB2→KB3→KB5. Sau ~1-2 phút Grafana evaluate và SOAR gửi 4 email HITL.

### Kết quả mong đợi

```
╔══════════════════════════════════════════════════════╗
║   ZTLab — Chạy 4 kịch bản Grafana → SOAR           ║
╚══════════════════════════════════════════════════════╝
...
  PASS  KB1  Brute Force (T1110.001)
  PASS  KB2  Fraud Gate Bypass (T1078.004)
  PASS  KB3  Lateral Movement (T1021.007)
  PASS  KB5  Access Denied Spike (T1078)

  PASS=4  FAIL=0  SKIP=0
✓  Tất cả 4 kịch bản đã PASS
```

### Kiểm tra SOAR cases sau khi chạy

```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys, json
cases = json.load(sys.stdin)
print(f'Tổng: {len(cases)} cases')
for c in sorted(cases, key=lambda x: x['ts'], reverse=True):
    print(f\"  {c['case_id'][:33]} | {c['attack_type']:<22} | {c['status']:<20} | email={c.get('email_sent',False)}\")
"
```

---

## 13. SOAR — Phê duyệt case & Web Portal

### Web Portal — http://localhost:18081/security

1. Mở trình duyệt: **http://localhost:18081/security**
2. Đăng nhập: `analyst01` / `Test1234!`
3. Danh sách SOAR cases sẽ hiện ra với nút **Approve** / **Reject**
4. Click **Approve** → SOAR thực thi playbook (dry-run mode — mô phỏng)

### API trực tiếp (nếu cần)

```bash
# Xem tất cả cases
curl -s http://localhost:8091/cases | python3 -m json.tool

# Xem case cụ thể
CASE_ID="case-20260628xxxxxx-xxxxxx"
curl -s "http://localhost:8091/cases/$CASE_ID" | python3 -m json.tool

# Phê duyệt case (approve playbook)
TOKEN_SOAR=$(curl -s "http://localhost:8091/cases/$CASE_ID" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('hitl_token',''))")
curl -s -X POST "http://localhost:8091/approve/$CASE_ID?token=$TOKEN_SOAR" | python3 -m json.tool

# Xem blocked IPs
curl -s http://localhost:8091/blocked-ips | python3 -m json.tool
```

### Grafana — Alert rules

- **URL**: http://localhost:3000 (admin / ZTALab2026!)
- Alerting → Alert rules → Folder **ZTLab**
- 4 security rules: KB1 (brute_force), KB2 (fraud_gate_bypass), KB3 (lateral_movement), KB5 (access_denied)
- State: **Normal** (khi không có tấn công) / **Firing** (1 phút sau khi chạy script)

### Grafana — Loki Explore (xem log thật)

| Kịch bản | LogQL |
|---|---|
| KB1 Brute Force | `{job="envoy-access", response_code="403"}` |
| KB2 Fraud Gate | `{namespace="financial", app="payment-service"} \| json \| event="payment_blocked_fraud"` |
| KB3 Lateral Movement | `{job="opa-decisions", opa_result="false", request_path="/payments/internal/execute"}` |
| KB5 Access Denied | `{job="opa-decisions", opa_result="false", request_path="/payments"}` |
| Tất cả OPA deny | `{job="opa-decisions", opa_result="false"}` |
| SOAR action logs | `{job="soar-engine"} \|= "soar_action"` |

---

## 14. Xử lý sự cố thường gặp

### Port-forward bị ngắt (ERR_CONNECTION_REFUSED)

```bash
# Kiểm tra port-forward nào còn sống
ps aux | grep port-forward | grep -v grep

# Khởi động lại tất cả
nohup kubectl --context ctx-aws port-forward svc/grafana       3000:3000  -n plg-stack >/tmp/pf-grafana.log 2>&1 &
nohup kubectl --context ctx-aws port-forward svc/loki          13100:3100 -n plg-stack >/tmp/pf-loki.log    2>&1 &
nohup kubectl --context ctx-aws port-forward svc/api-gateway   18080:8080 -n financial >/tmp/pf-gw.log      2>&1 &
nohup kubectl --context ctx-aws port-forward svc/keycloak      8180:8080  -n identity  >/tmp/pf-kc.log      2>&1 &
nohup kubectl --context ctx-aws port-forward svc/web-portal    18081:8080 -n financial >/tmp/pf-wp.log      2>&1 &
nohup kubectl --context ctx-aws port-forward svc/soar-engine   8091:8080  -n plg-stack >/tmp/pf-soar.log    2>&1 &
```

### Grafana alert không fire sau 2 phút

```bash
# Kiểm tra log có trong Loki không
curl -s "http://localhost:13100/loki/api/v1/query" \
  --data-urlencode 'query={job="envoy-access", response_code="403"}' \
  --data-urlencode "time=$(date +%s)" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('403 logs:', sum(len(r['values']) for r in d['data']['result']))"

# Nếu = 0 → chạy lại script
# Nếu > 0 → đợi thêm 1 chu kỳ Grafana (1 phút)
```

### SOAR không nhận được webhook từ Grafana

```bash
# Kiểm tra Grafana contact point
curl -s -u admin:ZTALab2026! http://localhost:3000/api/v1/provisioning/contact-points \
  | python3 -c "import sys,json; [print(cp['name'], cp['type'], cp['settings'].get('url','')) for cp in json.load(sys.stdin)]"
# Phải thấy URL trỏ đến soar-engine service (cluster-internal URL)

# Xem SOAR log gần nhất
kubectl --context ctx-aws logs -n plg-stack -l app=soar-engine --tail=20 2>/dev/null
```

### SOAR tạo case nhưng không gửi email

```bash
# Kiểm tra SMTP config
kubectl --context ctx-aws get deployment soar-engine -n plg-stack \
  -o jsonpath='{.spec.template.spec.containers[0].env}' \
  | python3 -c "
import json,sys
envs=json.load(sys.stdin)
for e in envs:
    if 'SMTP' in e['name'] or 'EMAIL' in e['name'] or 'ADMIN' in e['name']:
        val = e.get('value','')
        print(f\"{e['name']}={val[:30] if 'PASS' not in e['name'] else '***'}\")
"
```

### Grafana pod crash / restart

```bash
kubectl --context ctx-aws rollout restart deployment/grafana -n plg-stack
kubectl --context ctx-aws rollout status deployment/grafana -n plg-stack --timeout=60s

# Khởi động lại port-forward Grafana
kill $(ps aux | grep "port-forward svc/grafana" | grep -v grep | awk '{print $2}') 2>/dev/null; true
nohup kubectl --context ctx-aws port-forward svc/grafana 3000:3000 -n plg-stack >/tmp/pf-grafana.log 2>&1 &
```

### Xem tất cả pods hiện tại

```bash
kubectl --context ctx-aws get pods -A | grep -v "Running\|Completed" # pods có vấn đề
kubectl --context ctx-aws get pods -n financial                       # microservices
kubectl --context ctx-aws get pods -n identity                        # keycloak
kubectl --context ctx-aws get pods -n plg-stack                       # monitoring & soar
```
