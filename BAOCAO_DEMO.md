# Báo Cáo Demo Hệ Thống ZTLab
## Zero Trust Security Detection & Response for Microservices in Multi-Cloud

> **Môn học:** NT114.Q21.ANTT — Đồ án chuyên ngành  
> **Sinh viên:** Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> **Giảng viên hướng dẫn:** ThS. Đỗ Thị Phương Uyên  
> **Ngày thực hiện demo:** 2026-06-28

---

## I. Tổng Quan Hệ Thống

ZTLab là hệ thống ngân hàng vi dịch vụ được xây dựng theo mô hình **Zero Trust** — mọi request đều phải được xác minh danh tính và kiểm tra quyền hạn, bất kể đến từ đâu, không có "vùng tin tưởng" bên trong.

Hệ thống vừa là ứng dụng thực tế (chuyển tiền, tra số dư) vừa là **nền tảng thực nghiệm bảo mật**: tự phát hiện tấn công qua Grafana, tự phân tích và phản ứng qua SOAR Engine, yêu cầu admin phê duyệt trước khi cô lập workload (Human-in-the-Loop).

### Topology

```
┌──────────────── AWS (ap-southeast-1) ────────────────────────┐     WireGuard      ┌─── OpenStack (Local) ─────┐
│                                                               │ ←────────────────→ │                           │
│  api-gateway          ← cổng vào duy nhất (port 18080)       │                    │  core-banking             │
│  payment-service      ← điều phối giao dịch + fraud gate     │                    │  account-service          │
│  fraud-detection      ← chấm điểm rủi ro mỗi giao dịch      │                    │  transaction-service      │
│  notification-service ← gửi email thông báo                  │                    │                           │
│                                                               │                    │  (lưu ledger, tài khoản)  │
│  Keycloak             ← OIDC Identity Provider                │                    └───────────────────────────┘
│  SPIRE Server         ← cấp SVID (X.509 workload cert)       │
│  OPA Server           ← Policy Decision Point (ext_authz)    │
│                                                               │
│  Loki                 ← log aggregation                      │
│  Promtail             ← scrape pod logs → Loki               │
│  Grafana              ← alert rules + SOAR webhook            │
│  SOAR Engine          ← case management + HITL playbook      │
└───────────────────────────────────────────────────────────────┘
```

Mỗi pod microservice chạy **2 container** (`READY 2/2`): container ứng dụng + container Envoy sidecar. Mọi traffic vào/ra đều đi qua Envoy — ứng dụng không bao giờ nhận request trực tiếp.

---

## II. Bốn Lớp Kiểm Soát Zero Trust

Mỗi request đi qua hệ thống phải vượt qua 4 lớp kiểm soát nối tiếp. Không lớp nào tin tưởng lớp trước — mỗi lớp xác minh độc lập.

---

### Lớp 1 — Keycloak: Xác Thực Danh Tính Người Dùng

**Vai trò:** Là Identity Provider duy nhất. Người dùng POST username/password đến Keycloak và nhận lại một **JWT (JSON Web Token)** có chữ ký RSA. JWT này chứa thông tin định danh và danh sách role, được ký bằng private key của Keycloak — không ai có thể tự tạo JWT giả mạo mà không có private key đó.

**Cấu hình thực tế:**

| Tài khoản | Roles | Ý nghĩa trong hệ thống |
|---|---|---|
| `testuser01` | `financial-read`, `financial-write` | Người dùng thông thường, được giao dịch |
| `merchant01` | `financial-read` | Đối tác đọc-only, không được POST |
| `analyst01` | `security-analyst`, `security-admin` | Nhân viên bảo mật, phê duyệt SOAR cases |

**JWT payload sau khi decode:**

```json
{
  "preferred_username": "testuser01",
  "realm_access": { "roles": ["financial-read", "financial-write"] },
  "iss": "http://keycloak.ztlab.local:8180/realms/ztlab",
  "exp": 1782601630
}
```

Trường `realm_access.roles` được OPA đọc để quyết định user được phép làm gì.

**Lấy JWT thủ công:**

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

**Decode để xem roles:**

```bash
echo $TOKEN | cut -d. -f2 | python3 -c "
import sys, base64, json
p = sys.stdin.read().strip(); p += '=' * ((4-len(p)%4)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p))['realm_access'], indent=2))
"
```

```json
{
  "roles": ["financial-read", "financial-write"]
}
```

> **Ý nghĩa:** `financial-write` ↔ được phép POST. Không có role này → OPA từ chối ngay, dù JWT hoàn toàn hợp lệ.

---

### Lớp 2 — SPIRE/SPIFFE: Định Danh Workload

**Vai trò:** Trong khi Keycloak định danh *người dùng*, SPIRE định danh *dịch vụ*. Mỗi microservice được cấp một **SVID (SPIFFE Verifiable Identity Document)** — chứng chỉ X.509 tự động gia hạn, ký bởi SPIRE CA. Khi payment-service gọi fraud-detection, fraud-detection xác minh chứng chỉ của caller và biết chính xác đó là `spiffe://ztlab.local/aws/payment-service`.

**7 định danh SPIFFE trong hệ thống (từ SPIRE Server):**

```bash
kubectl --context ctx-aws exec -n spire \
  $(kubectl --context ctx-aws get pod -n spire -l app=spire-server -o jsonpath='{.items[0].metadata.name}') \
  -- /opt/spire/bin/spire-server entry show 2>/dev/null | grep "SPIFFE ID"
```

```
SPIFFE ID : spiffe://ztlab.local/aws/api-gateway
SPIFFE ID : spiffe://ztlab.local/aws/payment-service
SPIFFE ID : spiffe://ztlab.local/aws/fraud-detection
SPIFFE ID : spiffe://ztlab.local/aws/notification-service
SPIFFE ID : spiffe://ztlab.local/openstack/core-banking
SPIFFE ID : spiffe://ztlab.local/openstack/account-service
SPIFFE ID : spiffe://ztlab.local/openstack/transaction-service
```

**Cách SPIRE xác minh danh tính node:** Không dùng password cứng. SPIRE dùng `k8s_psat` (Kubernetes Projected Service Account Token) — mỗi pod có token do K8s cấp theo ServiceAccount. SPIRE Server gọi K8s API để xác minh token đó thật sự thuộc về đúng namespace + serviceaccount → mới cấp SVID.

```
SPIFFE ID        : spiffe://ztlab.local/aws/api-gateway
Selector         : k8s:ns:financial       ← phải đang chạy trong namespace financial
Selector         : k8s:sa:api-gateway     ← phải dùng ServiceAccount có tên api-gateway
```

> **Ý nghĩa:** Không thể tự khai `"Tôi là payment-service"` — phải chứng minh qua K8s API. Pod giả mạo sẽ không có đúng namespace + serviceaccount → không được cấp SVID.

**SVID được gia hạn tự động mỗi giờ:**

```bash
kubectl --context ctx-aws logs -n spire \
  $(kubectl --context ctx-aws get pod -n spire -l app=spire-server -o jsonpath='{.items[0].metadata.name}') \
  | grep "Renewing X509-SVID" | tail -3
```

```
msg="Renewing X509-SVID"  spiffe_id="spiffe://ztlab.local/aws/api-gateway"     expires_at="2026-06-28T12:43:16Z"
msg="Renewing X509-SVID"  spiffe_id="spiffe://ztlab.local/aws/payment-service"  expires_at="2026-06-28T12:43:19Z"
msg="Renewing X509-SVID"  spiffe_id="spiffe://ztlab.local/aws/fraud-detection"  expires_at="2026-06-28T12:43:22Z"
```

> **Ý nghĩa:** Log này chứng minh nguyên tắc *Continuous Verification* — SPIRE không chỉ cấp một lần rồi thôi, mà liên tục xác minh lại và gia hạn. SVID hết hạn → Envoy không còn có cert hợp lệ → kết nối mTLS bị từ chối.

---

### Lớp 3 — Envoy Sidecar: mTLS và Policy Enforcement Point

**Vai trò:** Mỗi pod chạy một Envoy sidecar nằm trước ứng dụng, xử lý toàn bộ traffic. Envoy làm 3 việc:

**3a. Enforce mTLS — buộc caller phải trình SVID**

Khi service khác kết nối vào, Envoy yêu cầu caller phải trình chứng chỉ X.509. Envoy tự lấy cert của mình từ SPIRE Agent qua Unix socket `/run/spire/sockets/agent.sock` — không có password hay private key nào nằm trong config hay biến môi trường.

```yaml
# envoy/envoy-sidecar.yaml — block transport_socket → downstream_tls_context
require_client_certificate: true   # buộc caller phải có cert hợp lệ
```

Trường `%DOWNSTREAM_PEER_URI_SAN%` trong access log format sẽ chứa SPIFFE URI của caller — đây là giá trị được đọc trực tiếp từ chứng chỉ TLS, không thể giả mạo qua HTTP header.

**3b. Gọi OPA kiểm tra quyền trước khi forward**

Sau khi xác thực TLS xong, Envoy gọi OPA qua gRPC (ext_authz) với toàn bộ thông tin request. OPA trả `allow=true/false`. Nếu false → Envoy trả 403, ứng dụng không bao giờ nhận được request.

```yaml
# envoy/envoy-sidecar.yaml — block http_filters → envoy.filters.http.ext_authz
failure_mode_allow: false   # nếu OPA timeout/lỗi → TỪ CHỐI (không phải cho qua)
timeout: 2s
```

`failure_mode_allow: false` là cấu hình Zero Trust quan trọng: khi OPA không trả lời trong 2 giây, Envoy **từ chối** thay vì cho qua. Thà chặn nhầm còn hơn để lọt khi chính sách đang bị lỗi.

**3c. Ghi access log JSON chi tiết**

Mỗi request → một dòng JSON với đầy đủ thông tin:

```bash
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=payment-service -o jsonpath='{.items[0].metadata.name}') \
  -c envoy --tail=3
```

```json
{"timestamp":"2026-06-28T07:04:57Z","method":"POST","path":"/payments/internal/execute","response_code":403,"response_time":6,"source_ip":"10.42.1.149","bytes_sent":0,"svid":"spiffe://ztlab.local/aws/notification-service"}
```

| Trường | Giá trị | Ý nghĩa |
|---|---|---|
| `svid` | `spiffe://...notification-service` | Caller là notification-service — xác thực qua mTLS cert, không thể giả |
| `response_code` | `403` | OPA từ chối — notification-service không được phép gọi `/payments/internal/execute` |
| `source_ip` | `10.42.1.149` | IP của pod notification-service trong cluster |
| `bytes_sent` | `0` | Response body trống — request bị chặn trước khi vào app |
| `response_time` | `6ms` | OPA xử lý quyết định trong 6ms — không ảnh hưởng performance |

Log này được **Promtail** thu thập và đẩy vào Loki với labels `{app="payment-service", job="envoy-access"}`.

---

### Lớp 4 — OPA: Kiểm Tra Quyền Hạn (Policy Decision Point)

**Vai trò:** OPA nhận request từ Envoy, đánh giá policy Rego, trả lời `allow: true/false`.

**Nguyên tắc cốt lõi:**

```rego
# opa/policies/zta_policy.rego
package zta.authz

default allow = false    # deny-by-default — từ chối trừ khi có rule tường minh cho phép
```

**4 loại request được phép (exhaustive):**

```rego
allow if { public_path }                    # GET /health, GET /metrics
allow if { external_api_request }           # user gọi từ ngoài với JWT hợp lệ
allow if { internal_service_request }       # service gọi service với SVID hợp lệ
allow if { core_transaction_with_fraud_gate } # execute tại core-banking có fraud gate passed
```

Ngoài 4 loại trên, mọi request đều bị từ chối.

**Bảng phân quyền theo role:**

```rego
permissions := {
  "financial-read":   {"GET": true, "OPTIONS": true},
  "financial-write":  {"GET": true, "OPTIONS": true, "POST": true, "PUT": true},
  "security-admin":   {"GET": true, "OPTIONS": true, "POST": true, "PUT": true, "DELETE": true},
}
```

> Khi merchant01 (`financial-read`) thử `POST /payments`, OPA tra bảng: `permissions["financial-read"]["POST"]` không tồn tại → `allow = false` → HTTP 403.

**Kiểm tra SVID:**

```rego
# source_principal được Envoy đọc từ cert của caller qua mTLS
valid_svid if {
  startswith(source_principal, "spiffe://ztlab.local/")
}
```

SVID `spiffe://evil.corp/attacker` → `startswith("spiffe://ztlab.local/")` = false → `valid_svid = false` → `allow = false`.

**Kiểm tra Fraud Gate tại core-banking:**

```rego
fraud_gate_valid if {
  headers["x-fraud-gate"] == "passed"
  to_number(headers["x-fraud-score"]) < 75
}
```

payment-service muốn gọi `/transactions/execute` tại core-banking phải gắn `X-Fraud-Gate: passed` và `X-Fraud-Score < 75`. Thiếu header hoặc score cao → OPA từ chối.

**OPA Decision Log — Promtail tự động gắn nhãn:**

Promtail scrape `/var/log/opa/decisions.json` và dùng pipeline stage để extract:

```yaml
# plg-stack/promtail/promtail-aws.yml
pipeline_stages:
  - json:
      expressions:
        opa_result: result.allow     # extract true/false từ OPA decision
  - labels:
      opa_result:                    # gắn thành stream label trong Loki
```

Khi OPA từ chối (`allow=false`), Loki nhận log với label `{opa_result="false"}` → Grafana dùng label này để detect tấn công.

---

## III. Luồng Giám Sát: Loki → Grafana → SOAR

### Promtail thu thập log thực tế

Promtail chạy như DaemonSet trên mỗi node K8s, scrape log từ container (`/var/log/containers/`) và đẩy vào Loki. Nó thêm labels dựa trên pod metadata:

| Nguồn log | Stream labels trong Loki |
|---|---|
| Envoy sidecar (mọi pod) | `job="envoy-access"`, `app=<tên pod>`, `namespace="financial"` |
| OPA decisions file | `job="opa-decisions"`, `opa_result="true/false"` |
| Application log | `job="kubernetes-pods"`, `app=<tên pod>` |

### Grafana Alert Rules

4 alert rule chạy trên Grafana, evaluate **mỗi 1 phút**, query Loki:

| Rule | Loki Query | Trigger khi |
|---|---|---|
| Brute Force (KB1) | `{job="envoy-access"} \| json \| response_code=401` | Có response 401 trong vòng 1 phút |
| Lateral Movement (KB3) | `{job="opa-decisions", opa_result="false"}` | OPA deny bất kỳ |
| Fraud Gate Bypass (KB2) | `{job="opa-decisions", opa_result="false", request_path="/transactions/execute"}` | OPA deny tại endpoint execute |
| Data Exfiltration (KB4) | `{job="envoy-access", cloud="openstack"} \| json \| bytes_sent > 1048576` | Response > 1MB từ OpenStack |

Khi rule fire → Grafana gửi POST webhook đến `http://soar-engine.plg-stack.svc.cluster.local:8080/grafana-webhook`.

### SOAR Engine xử lý webhook

SOAR nhận alert, map sang attack type, tạo case:

```
Grafana label: attack_type=lateral_movement
→ SOAR playbook: isolate_workload
→ SOAR target: payment-service (từ TARGETS_BY_ATTACK map)
→ severity >= high → status = pending_approval
→ Gửi email HITL đến voha2005@gmail.com
→ Chờ admin phê duyệt trên http://localhost:18081/security
```

---

## IV. Luồng Giao Dịch Bình Thường (Baseline)

Trước khi demo tấn công, cần chứng minh hệ thống hoạt động đúng với giao dịch hợp lệ.

**Tình huống:** testuser01 chuyển 10,000 VND sang ACC-2001.

```bash
# Bước 1: Lấy JWT
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Bước 2: Gửi giao dịch
curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":10000,"currency":"VND"}'
```

```json
{"status":"completed","trace_id":"abc-123","fraud":{"score":5,"verdict":"allow"}}
```

**Điều gì vừa xảy ra bên trong:**

```
[1] testuser01 → Keycloak POST token → JWT (roles: financial-read, financial-write)
[2] curl → Envoy inbound api-gateway (:15006) → Envoy gọi OPA:
      - JWT hợp lệ? → RSA signature đúng, chưa hết hạn ✓
      - Role financial-write? → có ✓
      - external_api_request → allow = true
[3] Envoy forward → api-gateway app → verify JWT lần 2 → check Redis blocked IP → OK
[4] api-gateway → Envoy outbound (127.0.0.1:15001) → mTLS → payment-service
      SVID: spiffe://ztlab.local/aws/api-gateway (cert từ SPIRE Agent)
[5] payment-service → fraud-detection /score:
      amount=10000 VND → bình thường (< 500M critical threshold)
      channel="api" → kênh an toàn
      velocity=1 → bình thường
      → score = 5, verdict = "allow", gate = "passed"
[6] payment-service → core-banking /transactions/execute
      header X-Fraud-Gate: passed, X-Fraud-Score: 5
      OPA check tại core-banking: SVID payment-service hợp lệ + fraud gate passed → allow
[7] core-banking ghi ledger → HTTP 200 → trả về chuỗi
[8] Tất cả Envoy ghi access log → Promtail → Loki
      Grafana không thấy pattern bất thường → alert không fire
```

Xác nhận giao dịch xong trong Envoy access log:

```bash
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=api-gateway -o jsonpath='{.items[0].metadata.name}') \
  -c envoy --tail=3 | python3 -c "import sys,json; [print(json.dumps({k:v for k,v in json.loads(l).items() if k in ['path','response_code','bytes_sent','svid']},ensure_ascii=False)) for l in sys.stdin if '/payments' in l and 'metrics' not in l]"
```

```json
{"path": "/payments", "response_code": 200, "bytes_sent": 74, "svid": "spiffe://ztlab.local/aws/api-gateway"}
```

---

## V. Demo 6 Kịch Bản Tấn Công

**Chuẩn bị trước khi demo mỗi kịch bản:**

```bash
# Restore toàn bộ về trạng thái ban đầu (scale deployments lên 1, xóa NetworkPolicy cũ)
bash scripts/run-demo.sh --restore

# Confirm tất cả service đang READY
kubectl --context ctx-aws get deployment -n financial
```

```
NAME                   READY   UP-TO-DATE   AVAILABLE
api-gateway            1/1     1            1
payment-service        1/1     1            1
fraud-detection        1/1     1            1
notification-service   1/1     1            1
```

---

### KB1 — Brute Force Login (T1110.001)

**Bối cảnh tấn công:** Kẻ tấn công không biết mật khẩu của `testuser01`, thử đoán liên tục bằng cách gửi 20 request đăng nhập với mật khẩu sai khác nhau.

**Zero Trust ngăn chặn bằng cách nào:** Keycloak không có "grace period" hay "lockout sau X lần". Mỗi request đăng nhập là một xác thực độc lập — sai là từ chối ngay, không có ngoại lệ.

**Chạy kịch bản:**

```bash
bash tests/grafana_kb1_brute_force.sh
```

**Diễn giải từng bước:**

**① Health check Keycloak (dòng 18–19 trong script)**

```bash
curl -fsS http://localhost:8180/realms/ztlab/.well-known/openid-configuration >/dev/null
```

Script gọi OpenID Configuration endpoint để xác nhận Keycloak đang chạy. Nếu fail → script dừng ngay với thông báo lỗi rõ ràng thay vì chạy tiếp với kết quả sai.

**② Tấn công thật: 20 lần đăng nhập sai (dòng 22–30)**

```bash
for i in $(seq 1 20); do
  curl -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
    -d "grant_type=password&client_id=web-portal&username=testuser01&password=WRONG_PASS_$i"
done
```

Mỗi vòng lặp gửi một POST đến Keycloak token endpoint với `password=WRONG_PASS_1`, `WRONG_PASS_2`, ... `WRONG_PASS_20`. Đây là traffic tấn công *thật* — không phải inject hay giả lập. Keycloak trả `HTTP 401` cho mỗi lần.

```
[KB1_brute_force] Keycloak chặn 20/20 (401)
```

> **Ý nghĩa output:** `20/20` — tất cả 20 request đều bị từ chối. Không có "1 lần thử thành công" nào dù mật khẩu của attacker gần đúng. Keycloak xác minh từng request độc lập.

**③ Inject log vào Loki để Grafana detect (dòng 33–41)**

```bash
ts=$(date +%s%N)
curl -X POST http://localhost:13100/loki/api/v1/push \
  -d '{"streams":[{"stream":{"job":"envoy-access","namespace":"financial","app":"api-gateway"},
    "values":[["'$ts'","{"response_code":401,"source_ip":"10.0.0.1","path":"/api/login"}"]]}]}'
```

Script đẩy 5 dòng log (format JSON của Envoy) vào Loki với labels `{job="envoy-access", app="api-gateway"}`. Nội dung mỗi dòng là `response_code: 401`.

> **Tại sao inject?** Keycloak từ chối tại identity layer — request không đến Envoy của api-gateway, nên Envoy không có log. Script inject log Envoy format để Grafana rule `{job="envoy-access"} | json | response_code=401` có thể match.

**④ Grafana phát hiện (khoảng 1 phút sau)**

Grafana evaluate rule mỗi 1 phút. Rule `sum by (source_ip) (count_over_time({job="envoy-access"} | json | response_code=\`401\` [1m]))` tìm thấy 5 log `401` từ `10.0.0.1` → giá trị > 0 → **alert fire**.

Grafana gửi POST webhook đến SOAR:

```json
{
  "alerts": [{
    "labels": {"attack_type": "brute_force", "severity": "high"},
    "annotations": {"summary": "Brute Force Login Detected"}
  }]
}
```

**⑤ SOAR tạo case và gửi email HITL**

```bash
curl -s http://localhost:18082/cases | python3 -c "
import sys,json
for c in json.load(sys.stdin)[-3:]:
    print(c['case_id'], '|', c['attack_type'], '|', c['status'], '|', c.get('playbook',''))
"
```

```
case-20260628041323-brute | brute_force | pending_approval | revoke_user_sessions
```

> **Ý nghĩa:** `pending_approval` — SOAR tạo case nhưng chưa làm gì. Playbook `revoke_user_sessions` đang chờ admin phê duyệt. Email HITL đã gửi đến `voha2005@gmail.com` với log evidence là 5 dòng 401 từ Loki.

**Log demo live — chạy khi trình bày:**

```bash
# [1] Xem Keycloak ghi nhận 20 lần thất bại
kubectl --context ctx-aws logs -n identity \
  $(kubectl --context ctx-aws get pod -n identity -l app=keycloak -o jsonpath='{.items[0].metadata.name}') \
  | grep LOGIN_ERROR | tail -5
```

```
WARN [org.keycloak.events] type="LOGIN_ERROR" error="invalid_user_credentials" username="testuser01"
WARN [org.keycloak.events] type="LOGIN_ERROR" error="invalid_user_credentials" username="testuser01"
WARN [org.keycloak.events] type="LOGIN_ERROR" error="invalid_user_credentials" username="testuser01"
WARN [org.keycloak.events] type="LOGIN_ERROR" error="invalid_user_credentials" username="testuser01"
WARN [org.keycloak.events] type="LOGIN_ERROR" error="invalid_user_credentials" username="testuser01"
```

> 20 lần sai = 20 dòng log liên tiếp trong vài giây — dấu hiệu brute force điển hình.

```bash
# [2] Xem Keycloak từ chối — không có dòng LOGIN nào (chỉ LOGIN_ERROR)
kubectl --context ctx-aws logs -n identity \
  $(kubectl --context ctx-aws get pod -n identity -l app=keycloak -o jsonpath='{.items[0].metadata.name}') \
  | grep '"type":"LOGIN"' | tail -3
# → (không có output) — không có lần nào thành công
```

```bash
# [3] Xem SOAR case vừa tạo
curl -s http://localhost:18082/cases | python3 -c "
import sys,json
cases=[c for c in json.load(sys.stdin) if c.get('attack_type')=='brute_force']
if cases: print(json.dumps(cases[-1], indent=2, ensure_ascii=False))"
```

```json
{
  "case_id": "case-20260628041323-brute",
  "attack_type": "brute_force",
  "status": "pending_approval",
  "playbook": "revoke_user_sessions",
  "email_sent": true
}
```

**⑥ Admin phê duyệt trên Web Portal → SOAR thực thi**

Vào `http://localhost:18081/security` (analyst01 / Test1234!) → thấy case `brute_force` đang `⏳ Chờ duyệt` → click **⚡ Xử lý** → chọn **🔑 Thu hồi phiên** → Confirm.

SOAR thực thi 4 phase playbook:

```bash
# Xem log playbook sau khi phê duyệt
CASE_ID=$(curl -s http://localhost:18082/cases | python3 -c "
import sys,json
cases=[c for c in json.load(sys.stdin) if c.get('attack_type')=='brute_force']
print(cases[-1]['case_id'] if cases else '')")

curl -s http://localhost:18082/cases/$CASE_ID | python3 -c "
import sys,json; c=json.load(sys.stdin)
print('status:', c.get('status'))
for s in c.get('steps',[]):
    print(f'[{s[\"phase\"]}] {s[\"result\"] or s.get(\"error\",\"\")}')
"
```

```
status: executed
[contain   ] revoked 0 sessions for user (alert không có username field — skip)
[investigate] Loki evidence: 5 log entries matched query for brute_force from 10.0.0.1
[eradicate ] brute_force patterns noted — user must re-authenticate
[recover   ] pending manual restore
```

> **Ý nghĩa từng phase:**
> - `contain`: Cố gắng thu hồi Keycloak sessions. Bị skip vì alert không có `username` field — đây là giới hạn của kịch bản brute force khi chưa có user nào đăng nhập thành công.
> - `investigate`: Query Loki tìm thấy 5 entries 401 làm bằng chứng — đây là dữ liệu trong email HITL.
> - `eradicate`: Ghi nhận pattern, user cần auth lại.
> - `recover`: Chờ admin quyết định rollback (restore lại nếu false positive).

**Kết quả:** 20/20 request brute force bị chặn. Không có request nào đến được Envoy hay OPA — Keycloak là tuyến phòng thủ đầu tiên.

---

### KB2 — Fraud Gate Bypass (T1078.004)

**Bối cảnh tấn công:** Kẻ tấn công đã có tài khoản hợp lệ (`testuser01` / `Test1234!`) — JWT hoàn toàn đúng. Chúng cố thực hiện giao dịch khổng lồ (500 triệu VND) qua kênh ẩn danh TOR để chuyển tiền ra ngoài.

**Zero Trust ngăn chặn bằng cách nào:** Có JWT hợp lệ chưa đủ — nguyên tắc *Verify Explicitly* yêu cầu mỗi giao dịch phải được đánh giá riêng theo ngữ cảnh. Fraud Detection chấm điểm rủi ro theo: số tiền, kênh giao dịch, tần suất. Điểm vượt ngưỡng → payment-service chặn ngay, không gọi core-banking.

**Chạy kịch bản:**

```bash
bash tests/grafana_kb2_fraud_gate.sh
```

**Diễn giải từng bước:**

**① Lấy JWT hợp lệ (dòng 22–26)**

```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")
```

testuser01 đăng nhập thành công — JWT hợp lệ, có `financial-write`. Đến đây không có gì bất thường.

**② Gửi tấn công: 500M VND qua kênh TOR (dòng 29–40)**

```bash
curl -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":500000000,"currency":"VND","channel":"tor"}'
```

```
[KB2_fraud_gate] POST /payments 500M tor → HTTP 403 (fraud: block)
```

> **Ý nghĩa:** `HTTP 403` mặc dù JWT hoàn toàn hợp lệ. Zero Trust không chỉ hỏi "người này là ai" mà còn hỏi "hành động này có bình thường không". Cùng user, cùng endpoint — nhưng ngữ cảnh (500M + TOR) làm thay đổi quyết định.

**③ Fraud Detection tính điểm (thực tế bên trong)**

payment-service nhận request, gọi fraud-detection `/score` để chấm điểm:

```
Base score:                      5 điểm  (mọi giao dịch đều có)
+ amount = 500,000,000 ≥ 500M:  +55 điểm  (critical_amount threshold)
+ channel = "tor":              +15 điểm  (kênh ẩn danh, rủi ro cao)
─────────────────────────────────────────
Tổng:                           75 điểm  ≥ ngưỡng block (70) → verdict = "block"
```

```bash
# Xem fraud-detection log tính điểm thực tế
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=fraud-detection -o jsonpath='{.items[0].metadata.name}') \
  -c fraud-detection --tail=20 | python3 -c "
import sys,json
for line in sys.stdin:
    try:
        j=json.loads(line)
        if j.get('event')=='fraud_score_computed':
            print(json.dumps({k:j[k] for k in ['event','fraud_score','verdict','reason','amount'] if k in j},ensure_ascii=False))
    except: pass
" | tail -3
```

```json
{"event": "fraud_score_computed", "fraud_score": 75, "verdict": "block", "reason": ["critical_amount", "risky_channel"], "amount": 500000000}
```

> **Ý nghĩa:** `fraud_score=75` vượt ngưỡng 70. `reason` liệt kê chính xác nguyên nhân. Log này là **bằng chứng audit** của quyết định từ chối.

**④ payment-service KHÔNG gọi core-banking**

```bash
# Xem payment-service log xác nhận chặn trước khi gọi core-banking
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=payment-service -o jsonpath='{.items[0].metadata.name}') \
  -c payment-service --tail=10 | python3 -c "
import sys,json
for line in sys.stdin:
    try:
        j=json.loads(line)
        if j.get('event')=='payment_blocked_fraud':
            print(json.dumps({k:j[k] for k in ['event','fraud_score','trace_id'] if k in j},ensure_ascii=False))
    except: pass
" | tail -3
```

```json
{"event": "payment_blocked_fraud", "fraud_score": 75, "trace_id": "7f3a-bc12-..."}
```

> **Ý nghĩa:** Event `payment_blocked_fraud` — payment-service tự quyết định không gọi tiếp. Core-banking không bao giờ nhận được request này. Attacker không thể thực hiện giao dịch dù có JWT hợp lệ.

**⑤ Inject OPA decision log vào Loki để Grafana detect (dòng 43–53)**

```bash
curl -X POST http://localhost:13100/loki/api/v1/push \
  -d '{"streams":[{"stream":{"job":"opa-decisions","opa_result":"false","attack_scenario":"fraud_gate_bypass"},
    "values":[["'$ts'","{"result":false,"fraud_score":75,"source_ip":"10.0.0.5","path":"/transactions/execute"}"]]}]}'
```

Script inject 2 OPA decision log với labels `{opa_result="false", attack_scenario="fraud_gate_bypass"}`. Grafana rule `{job="opa-decisions", opa_result="false", request_path="/transactions/execute"}` match → alert fire → SOAR webhook.

**⑥ SOAR — isolate_workload**

Sau khi admin phê duyệt:

```bash
# Verify payment-service đã scale=0
kubectl --context ctx-aws get deployment payment-service -n financial
```

```
NAME              READY   UP-TO-DATE   AVAILABLE
payment-service   0/0     0            0
```

```bash
# Mọi request tiếp theo bị 503
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount":1000}'
```

```
HTTP 503
```

> **Ý nghĩa:** `scale=0` — payment-service không còn replica nào. K8s không có pod để route traffic → 503. Attacker không thể thử bất kỳ giao dịch nào khác. Cô lập hoàn toàn mà không cần shutdown toàn hệ thống.

**Restore sau demo:**

```bash
kubectl --context ctx-aws scale deployment payment-service -n financial --replicas=1
```

---

### KB3 — Lateral Movement via Invalid SVID (T1021.007)

**Bối cảnh tấn công:** Kẻ tấn công đã vào được bên trong cluster (giả sử đã compromise notification-service). Chúng cố gọi trực tiếp API nội bộ nhạy cảm `/payments/internal/execute` để thực hiện giao dịch, bỏ qua mọi lớp kiểm tra bên ngoài.

**Zero Trust ngăn chặn bằng cách nào:** Trong Zero Trust, "đã vào trong mạng" không có nghĩa gì. Mỗi service-to-service call phải có SVID hợp lệ **và** SVID đó phải được phép gọi path đó. Notification-service có SVID hợp lệ trong trust domain nhưng không có quyền gọi `/payments/internal/execute` — OPA từ chối.

Kịch bản này có **2 cách demo**, bổ sung nhau:

**Cách A — `grafana_kb3_lateral_movement.sh`:** Demo tấn công từ bên ngoài qua API Gateway với header SVID giả. Trigger Grafana alert.

**Cách B — `scenario_03_lateral_movement.sh`:** Demo tấn công từ *bên trong* notification-service pod thông qua Envoy outbound proxy. Chứng minh SVID thật được Envoy gắn vào — OPA vẫn từ chối dù SVID đúng trust domain.

---

#### Cách A — Từ bên ngoài (trigger Grafana)

```bash
bash tests/grafana_kb3_lateral_movement.sh
```

**① Thử 1: SVID từ đúng trust domain nhưng sai path (dòng 21–27)**

```bash
curl -X POST http://localhost:18080/payments/internal/execute \
  -H "X-SPIFFE-ID: spiffe://ztlab.local/aws/notification-service" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":999999}'
```

```
[KB3_lateral_movement] SVID ztlab.local/notification-service → HTTP 403
```

OPA nhận request, thấy `spiffe://ztlab.local/aws/notification-service` — valid_svid=true (đúng trust domain). Nhưng không có rule nào cho phép notification-service gọi `/payments/internal/execute` → `allow = false`.

> **Lưu ý kỹ thuật:** Request này đến từ localhost qua port-forward, đi qua API Gateway Envoy. Envoy không có mTLS với caller ngoài → `source_principal` rỗng. OPA từ chối vì không match `internal_service_request` (không có SVID). Header `X-SPIFFE-ID` chỉ là HTTP header bình thường — OPA không đọc HTTP header để quyết định SVID, chỉ đọc `source_principal` từ TLS cert.

**② Thử 2: SVID từ ngoài trust domain (dòng 29–33)**

```bash
curl -X POST http://localhost:18080/transactions/execute \
  -H "X-SPIFFE-ID: spiffe://evil.domain/attacker/service" \
  -d '{"amount":100000}'
```

```
[KB3_lateral_movement] SVID evil.domain/attacker → HTTP 403
```

OPA kiểm tra: `startswith("spiffe://evil.domain/...", "spiffe://ztlab.local/")` = false → `valid_svid = false` → `allow = false`.

**③ Inject OPA decision log (dòng 36–47)**

Script inject 2 log vào Loki với `opa_result="false"` và path `/payments/internal/execute`. Grafana `lateral-movement-alert` match → SOAR webhook.

---

#### Cách B — Từ bên trong (chứng minh mTLS thật)

```bash
bash tests/scenario_03_lateral_movement.sh
```

Đây là kịch bản kỹ thuật chứng minh Envoy mTLS hoạt động đúng với SVID thật. Script `kubectl exec` vào notification-service và gọi payment-service qua Envoy outbound proxy bên trong pod.

**① Resolve pods (dòng 17–27)**

```bash
NOTIF_POD=$(kubectl --context ctx-aws get pods -n financial -l app=notification-service -o jsonpath='{.items[0].metadata.name}')
PAYMENT_POD=$(kubectl --context ctx-aws get pods -n financial -l app=payment-service -o jsonpath='{.items[0].metadata.name}')
OPA_POD=$(kubectl --context ctx-aws get pods -n financial -l app=opa -o jsonpath='{.items[0].metadata.name}')
```

```
[scenario_03_lateral_movement] notification-service pod: notification-service-8689ffd588-jnghq
[scenario_03_lateral_movement] payment-service pod:      payment-service-79b8886786-p78ts
```

> **Ý nghĩa:** Lấy tên pod thật để exec vào — pod name thay đổi mỗi lần restart, lệnh này tự động resolve.

**② Exec vào notification-service → gọi qua Envoy outbound (dòng 39–63)**

```python
# Lệnh Python được chạy BÊN TRONG container notification-service
req = urllib.request.Request(
  'http://127.0.0.1:15001/payments/internal/execute',   # 15001 = Envoy outbound proxy
  data=data, method='POST',
  headers={
    'Content-Type': 'application/json',
    'Host': 'payment-service.financial.svc.cluster.local'   # Envoy cần Host header để route
  })
```

```
[scenario_03_lateral_movement] Envoy response: HTTP 403
```

> **Kỹ thuật quan trọng:** Port `127.0.0.1:15001` là **Envoy outbound proxy** trong pod. Khi ứng dụng gọi đến đây, Envoy:
> 1. Đọc `Host` header để biết destination là payment-service
> 2. Lấy SVID của notification-service từ SPIRE Agent qua Unix socket
> 3. Mở kết nối mTLS đến payment-service Envoy inbound (port 15006) với SVID đó làm client cert
>
> Đây là SVID *thật* — không phải header giả. Envoy tự lấy từ SPIRE, không ai override được.

**③ Thu thập Envoy access log của payment-service (dòng 71–92)**

```bash
kubectl --context ctx-aws logs -n financial $PAYMENT_POD -c envoy --tail=500 \
  | python3 -c "
import sys, json
entries = []
for line in sys.stdin:
    try:
        j = json.loads(line.strip())
        if 'payments' in j.get('path','') and 'metrics' not in j.get('path',''):
            entries.append(j)
    except: pass
if entries:
    e = entries[-1]
    print('response_code={} path={} svid={} source_ip={} bytes_sent={}'.format(
        e.get('response_code'), e.get('path'), e.get('svid'), e.get('source_ip'), e.get('bytes_sent')))
"
```

```
response_code=403 path=/payments/internal/execute svid=spiffe://ztlab.local/aws/notification-service source_ip=10.42.1.149 bytes_sent=0
```

> **Ý nghĩa từng trường:**
> - `svid=spiffe://ztlab.local/aws/notification-service` — đây là SVID thật được Envoy đọc từ TLS client cert. Không thể giả mạo.
> - `response_code=403` — OPA từ chối dù SVID đúng trust domain — notification-service không được phép gọi `/payments/internal/execute`.
> - `source_ip=10.42.1.149` — IP thật của notification-service pod trong cluster.
> - `bytes_sent=0` — request bị chặn trước khi app nhận, không có dữ liệu nào bị lộ.

**④ Thu thập OPA decision log (dòng 94–114)**

```bash
kubectl --context ctx-aws logs -n financial $OPA_POD --tail=300 \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        j = json.loads(line.strip())
        path = j.get('input',{}).get('attributes',{}).get('request',{}).get('http',{}).get('path','')
        if 'payments' in path and 'metrics' not in path and j.get('result') is False:
            src = j.get('input',{}).get('attributes',{}).get('source',{})
            print(f'time={j.get(\"time\",\"\")} path={path} principal={src.get(\"principal\",\"\")} result=False')
    except: pass
"
```

```
time=2026-06-28T07:04:57Z path=/payments/internal/execute principal=spiffe://ztlab.local/aws/notification-service result=False
```

> **Ý nghĩa:** `principal=spiffe://ztlab.local/aws/notification-service` — OPA thấy đúng SVID của notification-service (lấy từ mTLS cert qua Envoy). Nhưng policy không có rule nào cho phép notification-service gọi `/payments/internal/execute` → `result=False`.
>
> Đây chứng minh OPA đọc `source_principal` từ mTLS cert (thông qua Envoy `include_peer_certificate: true`), không phải từ HTTP header. Attacker không thể gửi header giả `X-SPIFFE-ID` để bypass.

**⑤ Assert SVID trong cả hai log (dòng 120–123)**

```bash
echo "$ENVOY_ENTRY" | grep -q "spiffe://ztlab.local/aws/notification-service" || fail "..."
echo "$OPA_ENTRY"   | grep -q "spiffe://ztlab.local/aws/notification-service" || fail "..."
```

```
[scenario_03_lateral_movement] PASS: lateral movement blocked HTTP 403; SVID verified in Envoy + OPA logs (T1021.007)
```

**Kết quả tổng hợp:**

| Thử nghiệm | SVID | Kết quả | Lý do |
|---|---|---|---|
| Từ ngoài với header giả `evil.domain` | `spiffe://evil.domain/attacker` | HTTP 403 | Ngoài trust domain |
| Từ ngoài với header giả `notification-service` | (chỉ là HTTP header) | HTTP 403 | Không có mTLS cert thật |
| Từ trong pod qua Envoy outbound 15001 | `spiffe://ztlab.local/aws/notification-service` | HTTP 403 | Đúng trust domain nhưng sai path — OPA deny |

---

### KB4 — Data Exfiltration / Large Response (T1041)

**Bối cảnh tấn công:** Kẻ tấn công có JWT hợp lệ, không làm gì "bất hợp pháp" về mặt hành động — chỉ liên tục gọi API lấy lịch sử giao dịch với `limit=500`, nhiều lần, để dần dần kéo hết dữ liệu ra ngoài. Mỗi request riêng lẻ đều hợp lệ.

**Zero Trust ngăn chặn bằng cách nào:** *Assume Breach + Egress Monitoring* — Zero Trust giám sát cả traffic *ra ngoài*. Envoy ghi `bytes_sent` cho mỗi response. Pattern lặp lại nhiều request lấy dữ liệu lớn → Grafana phát hiện → SOAR cô lập nguồn dữ liệu.

**Chạy kịch bản:**

```bash
bash tests/grafana_kb4_exfiltration.sh
```

**Diễn giải từng bước:**

**① Lấy JWT và thực hiện bulk download (dòng 22–46)**

Script lấy JWT của testuser01, sau đó gọi 10 request đến các endpoint dữ liệu:

```bash
endpoints=(
  "/transactions?account_id=ACC-1001&limit=500"
  "/transactions?account_id=ACC-2001&limit=500"
  "/accounts/balance"
  # ... 7 endpoint nữa
)
for ep in "${endpoints[@]}"; do
  sz=$(curl -s -w "%{size_download}" -o /dev/null "$GW_URL$ep" -H "Authorization: Bearer $TOKEN")
  total_bytes=$((total_bytes + sz))
done
```

```
[KB4_exfiltration] 10 bulk requests → 15546 bytes
```

> **Ý nghĩa:** `15546 bytes` là số byte thực sự nhận về được đo bằng `curl -w "%{size_download}"`. Không phải giả lập — đây là data thật từ hệ thống. 10 request × ~1554 bytes/request trung bình.

**② Inject log vào Loki (dòng 48–68)**

Script inject **2 loại log**:

**Log 1 — api-gateway (bytes thực đo):**

```bash
curl -X POST http://localhost:13100/loki/api/v1/push \
  -d '{"streams":[{"stream":{"job":"envoy-access","app":"api-gateway"},
    "values":[["'$ts'","{"bytes_sent":15546,"source_ip":"10.0.0.77","path":"/transactions","request_count":10}"]]}]}'
```

**Log 2 — core-banking (giả lập, > 1MB):**

```bash
curl -X POST http://localhost:13100/loki/api/v1/push \
  -d '{"streams":[{"stream":{"job":"envoy-access","app":"core-banking","cloud":"openstack"},
    "values":[
      ["...","{"bytes_sent":2097152,"source_ip":"10.0.0.77","path":"/accounts/export"}"],
      ["...","{"bytes_sent":1572864,"source_ip":"10.0.0.77","path":"/transactions/dump"}"]
    ]}]}'
```

> **Tại sao inject log core-banking?** Grafana rule cần `bytes_sent > 1,048,576` (1MB). 15KB từ api-gateway không đủ trigger. Trong thực tế, attacker bulk-download từ core-banking sẽ sinh ra response hàng MB — lab inject 2MB+1.5MB để demo được detection này. Promtail trên OpenStack node sẽ tự thu thập nếu tunnel sống.

**③ Grafana detect và SOAR phản ứng**

Grafana rule `{job="envoy-access", cloud="openstack"} | json | bytes_sent > 1048576` match log core-banking 2MB → alert fire → SOAR webhook.

```bash
# Sau khi admin phê duyệt — xem playbook restrict_egress
CASE_ID=$(curl -s http://localhost:18082/cases | python3 -c "
import sys,json; cases=[c for c in json.load(sys.stdin) if c.get('attack_type')=='large_response']
print(cases[-1]['case_id'] if cases else '')")

curl -s http://localhost:18082/cases/$CASE_ID | python3 -c "
import sys,json; c=json.load(sys.stdin)
for s in c.get('steps',[]): print(f'[{s[\"phase\"]}] {s[\"result\"] or \"\"}')
"
```

```
[contain   ] scaled Deployment/core-banking from 1 → 0 replicas (suspected exfiltration)
[investigate] Loki evidence: 2 log entries matched query for large_response from 10.0.0.77
[eradicate ] created NetworkPolicy/soar-block-f425eca1 — blocked 10.0.0.77/32 in financial
[recover   ] pending manual restore
```

> **Ý nghĩa từng phase:**
> - `contain`: Scale core-banking về 0 — cắt nguồn dữ liệu. Mọi request đến core-banking trả 503 ngay lập tức.
> - `investigate`: Query Loki với term `bytes_sent|data.exfil|large.response` → tìm được 2 log entries > 1MB làm bằng chứng.
> - `eradicate`: Tạo K8s NetworkPolicy chặn IP `10.0.0.77` khỏi namespace financial.
> - `recover`: Chờ admin trigger rollback sau khi điều tra xong.

```bash
# Xem NetworkPolicy vừa được tạo
kubectl --context ctx-aws get networkpolicy -n financial
```

```
NAME                  POD-SELECTOR   AGE
soar-block-f425eca1   <none>         2m
```

```bash
# Xem chi tiết — IP nào bị block
kubectl --context ctx-aws describe networkpolicy soar-block-f425eca1 -n financial | grep -A5 "From\|CIDR"
```

```
From:
  IPBlock:
    CIDR:   0.0.0.0/0
    Except: 10.0.0.77/32   ← IP attacker bị loại trừ
```

```bash
# Xem Envoy access log tại api-gateway — bytes thực từ 10 request
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=api-gateway -o jsonpath='{.items[0].metadata.name}') \
  -c envoy --tail=20 | python3 -c "
import sys,json
for line in sys.stdin:
    try:
        j=json.loads(line)
        if 'transactions' in j.get('path','') and j.get('bytes_sent',0) > 0:
            print(f'path={j[\"path\"]} bytes_sent={j[\"bytes_sent\"]} src={j.get(\"source_ip\")}')
    except: pass
" | tail -5
```

```
path=/transactions?account_id=ACC-1001&limit=500 bytes_sent=2208 src=127.0.0.1
path=/transactions?account_id=ACC-2001&limit=500 bytes_sent=2208 src=127.0.0.1
path=/transactions?account_id=ACC-1001&limit=500 bytes_sent=2208 src=127.0.0.1
```

---

### KB5 — Access Denied Spike / OPA RBAC (T1078)

**Bối cảnh tấn công:** Kẻ tấn công có tài khoản đối tác `merchant01` (chỉ có `financial-read`). Biết endpoint `/payments`, chúng cố thực hiện giao dịch — "privilege abuse" hay "role escalation".

**Zero Trust ngăn chặn bằng cách nào:** *Least Privilege* — OPA deny-by-default RBAC. `permissions["financial-read"]["POST"]` không tồn tại trong policy table → từ chối. Không phải "có tài khoản là làm được mọi thứ".

**Chạy kịch bản:**

```bash
bash tests/grafana_kb5_access_denied.sh
```

**Diễn giải từng bước:**

**① Lấy JWT merchant01 và decode xem roles (dòng 22–32)**

```bash
MERCHANT_TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "grant_type=password&client_id=web-portal&username=merchant01&password=Test1234%21" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

roles=$(echo "$MERCHANT_TOKEN" | cut -d. -f2 | python3 -c "
import sys,base64,json; p=sys.stdin.read().strip(); p+='='*((4-len(p)%4)%4)
d=json.loads(base64.urlsafe_b64decode(p))
print(d.get('realm_access',{}).get('roles',[]))")
```

```
[KB5_access_denied] merchant01 roles: ['financial-read']
```

> **Ý nghĩa:** Script decode phần payload của JWT (giữa 2 dấu `.`) và lấy trường `realm_access.roles`. `['financial-read']` — chỉ có quyền đọc, không có `financial-write`. Script in ra để chứng minh JWT thật sự chứa role này — không phải server tự quyết định.

**② merchant01 cố gọi POST /payments 6 lần (dòng 36–49)**

```bash
amounts=(100000 50000 200000 75000 1000000 5000)
for amount in "${amounts[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GW_URL/payments" \
    -H "Authorization: Bearer $MERCHANT_TOKEN" \
    -d "{\"amount\":$amount}")
  echo "POST /payments $amount → HTTP $code"
done
```

```
[KB5_access_denied]   POST /payments 100000  → HTTP 403
[KB5_access_denied]   POST /payments 50000   → HTTP 403
[KB5_access_denied]   POST /payments 200000  → HTTP 403
[KB5_access_denied]   POST /payments 75000   → HTTP 403
[KB5_access_denied]   POST /payments 1000000 → HTTP 403
[KB5_access_denied]   POST /payments 5000    → HTTP 403
[KB5_access_denied] OPA RBAC từ chối 6/6 (403)
```

> **Ý nghĩa:** 6 amounts khác nhau để chứng minh không phải "số tiền sai" — mà là role không đủ. OPA đánh giá mỗi request: `permissions["financial-read"]["POST"]` → không tồn tại → `role_permits_action = false` → `allow = false`. Không có exception nào.

**③ So sánh trực tiếp: merchant01 vs testuser01**

```bash
# merchant01 (financial-read) → 403
curl -s -o /dev/null -w "merchant01: HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $MERCHANT_TOKEN" \
  -d '{"from_account":"ACC-4001","to_account":"ACC-2001","amount":10000}'

# testuser01 (financial-read + financial-write) → 200
TOKEN_USER=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -o /dev/null -w "testuser01: HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN_USER" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":10000}'
```

```
merchant01: HTTP 403
testuser01: HTTP 200
```

> **Ý nghĩa:** Cùng endpoint, cùng body, cùng thời điểm — kết quả hoàn toàn khác chỉ vì khác role trong JWT. OPA không nhìn vào IP, không nhìn vào "ai gọi từ đâu" — chỉ nhìn vào token và path.

**④ OPA ghi nhận decision (từ Promtail scrape)**

```bash
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=opa -o jsonpath='{.items[0].metadata.name}') \
  --tail=10 | python3 -c "
import sys,json
for line in sys.stdin:
    try:
        j=json.loads(line)
        if j.get('result') is False:
            path=j.get('input',{}).get('attributes',{}).get('request',{}).get('http',{}).get('path','')
            if '/payments' in path:
                roles=j.get('input',{}).get('attributes',{}).get('request',{}).get('http',{}).get('headers',{}).get('x-jwt-roles','?')
                print(f'path={path} result=False metrics={j.get(\"metrics\",{}).get(\"timer_rego_query_eval_ns\",0)//1000}us')
    except: pass
" | tail -5
```

```
path=/payments result=False metrics=189us
path=/payments result=False metrics=201us
path=/payments result=False metrics=194us
```

> **Ý nghĩa:** OPA xử lý mỗi quyết định trong ~200 microseconds (0.2ms). Đủ nhanh để không ảnh hưởng performance, đủ chắc để không có request nào lọt.

**⑤ Inject log để Grafana detect + SOAR block IP**

Script inject 6 OPA deny log vào Loki. Grafana broad lateral-movement rule `{job="opa-decisions", opa_result="false"}` match → SOAR webhook → case `access_denied` → playbook `block_source_ip`.

Sau khi phê duyệt:

```bash
# Xem IP bị block trong Redis (TTL 24h)
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=redis -o jsonpath='{.items[0].metadata.name}') \
  -- redis-cli KEYS "ztlab:blocked_ip:*"
```

```
1) "ztlab:blocked_ip:10.0.0.99"
```

```bash
# Xem TTL còn lại
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=redis -o jsonpath='{.items[0].metadata.name}') \
  -- redis-cli TTL "ztlab:blocked_ip:10.0.0.99"
```

```
(integer) 86352
```

> **Ý nghĩa:** `86352` giây ≈ 23.98 giờ còn lại. api-gateway kiểm tra Redis key `ztlab:blocked_ip:10.0.0.99` trước khi xử lý mỗi request — nếu key tồn tại → trả 429 ngay, không cần OPA hay Keycloak.

---

### KB6 — Privilege Escalation in Container (T1611)

**Bối cảnh tấn công:** Kẻ tấn công đã vào được bên trong container api-gateway (ví dụ qua code injection hay supply chain attack). Container đang chạy với quyền root và có capabilities nguy hiểm — có thể đọc file nhạy cảm, setuid, thậm chí thoát ra host.

**Zero Trust ngăn chặn bằng cách nào:** *Workload Isolation + Least Privilege cho container* — Zero Trust không chỉ áp dụng cho network. Container phải chạy non-root, không có capabilities dư thừa. Đây là vi phạm cấu hình thật trong lab — được phát hiện qua audit và cách ly.

**Chạy kịch bản:**

```bash
bash tests/grafana_kb6_privilege_escalation.sh
```

**Diễn giải từng bước:**

**① Audit thực tế — kiểm tra uid đang chạy (dòng 27–28)**

```bash
POD=$(kubectl --context ctx-aws get pod -n financial -l app=api-gateway \
  -o jsonpath='{.items[0].metadata.name}')
kubectl --context ctx-aws exec -n financial "$POD" -- id
```

```
[KB6_privilege_escalation]   id: uid=0(root) gid=0(root) groups=0(root)
```

> **Ý nghĩa:** `uid=0(root)` — container đang chạy với user root. Theo best practice Zero Trust (NIST SP 800-190), container phải chạy với UID ≥ 1000. uid=0 nghĩa là nếu attacker có code execution trong container, họ đã là root ngay lập tức.

**② Audit capabilities hex (dòng 31–33)**

```bash
kubectl --context ctx-aws exec -n financial "$POD" -- \
  cat /proc/1/status | grep '^CapEff'
```

```
[KB6_privilege_escalation]   CapEff: 0xa80425fb
```

> **Ý nghĩa:** `0xa80425fb` là bitmask capabilities của tiến trình root trong container. Script giải mã hex này:

```bash
# Script decode (dòng 36–54)
python3 -c "
caps = int('a80425fb', 16)
dangerous = {7:'SETUID', 1:'DAC_OVERRIDE', 21:'SYS_ADMIN'}
active = [v for k,v in dangerous.items() if caps & (1<<k)]
print('DANGEROUS caps:', active)
"
```

```
[KB6_privilege_escalation]   Capabilities active: ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'KILL', 'SETGID', 'SETUID', 'SETPCAP', 'NET_BIND_SERVICE', 'NET_RAW', 'SYS_CHROOT', 'MKNOD', 'AUDIT_WRITE', 'SETFCAP']
[KB6_privilege_escalation]   ⚠ DANGEROUS caps: ['DAC_OVERRIDE', 'SETUID']
```

> **Ý nghĩa từng capability nguy hiểm:**
> - `CAP_DAC_OVERRIDE` — bypass mọi permission check của filesystem → đọc/ghi bất kỳ file nào dù permission là `000`.
> - `CAP_SETUID` — có thể thay đổi UID của tiến trình bất kỳ lúc nào → leo thang lên root bất cứ khi nào muốn.
> - `CAP_SYS_ADMIN` (nếu có) — gần như full root, có thể mount filesystem, thay đổi kernel param.

**③ Chứng minh leo thang thật: đọc /etc/shadow (dòng 57–65)**

```bash
kubectl --context ctx-aws exec -n financial "$POD" -- head -2 /etc/shadow
```

```
[KB6_privilege_escalation]   ⚠ CÓ THỂ ĐỌC /etc/shadow (3 dòng) — CAP_DAC_OVERRIDE bypass permission
```

```
root:*:20549:0:99999:7:::
daemon:*:20549:0:99999:7:::
```

> **Ý nghĩa:** `/etc/shadow` chứa password hash của tất cả user trong container. Permission mặc định là `640` (chỉ root đọc được) — nhưng `CAP_DAC_OVERRIDE` bypass permission check → đọc được. Trong container production thật, file này có thể chứa credentials của service account.
>
> Đây là **bằng chứng leo thang đặc quyền thực tế** — không phải lý thuyết.

**④ Thử setuid(0) (dòng 67–70)**

```bash
kubectl --context ctx-aws exec -n financial "$POD" -- \
  python3 -c "import os; os.setuid(0); print('setuid(0) OK')"
```

```
[KB6_privilege_escalation]   setuid(0): setuid(0) OK
```

> **Ý nghĩa:** `setuid(0) OK` — process có thể tự đặt UID về 0 (root) bất cứ lúc nào. Đây là cơ sở của nhiều kỹ thuật container escape.

**⑤ Kiểm tra securityContext (dòng 73–78)**

```bash
kubectl --context ctx-aws get pod "$POD" -n financial \
  -o jsonpath='{.spec.containers[0].securityContext}'
```

```
[KB6_privilege_escalation]   runAsNonRoot: null
[KB6_privilege_escalation]   allowPrivilegeEscalation: null
```

> **Ý nghĩa:** `null` / rỗng — không có cấu hình hardening nào. Pod spec không có `securityContext.runAsNonRoot: true` hay `allowPrivilegeEscalation: false`. K8s không ép buộc gì → container chạy theo mặc định của Docker image (thường là root).
>
> Container đúng chuẩn Zero Trust phải có:
> ```yaml
> securityContext:
>   runAsNonRoot: true
>   runAsUser: 1000
>   allowPrivilegeEscalation: false
>   capabilities:
>     drop: ["ALL"]
> ```

**⑥ Tổng hợp vi phạm**

```
[KB6_privilege_escalation] ▶ VI PHẠM Zero Trust workload isolation xác nhận:
[KB6_privilege_escalation]   • Pod chạy root (uid=0) — vi phạm least-privilege principle
[KB6_privilege_escalation]   • CAP_DAC_OVERRIDE cho phép đọc /etc/shadow — leo thang đặc quyền thực tế
[KB6_privilege_escalation]   • runAsNonRoot không được set — container không bị ràng buộc
```

**⑦ Inject log audit vào Loki và SOAR phản ứng**

Script inject 5 dòng audit text vào Loki với labels `{job="security-audit", app="api-gateway"}`. Sau khi admin phê duyệt:

```bash
# api-gateway bị scale=0 để forensics
kubectl --context ctx-aws get deployment api-gateway -n financial
```

```
NAME          READY   UP-TO-DATE   AVAILABLE
api-gateway   0/0     0            0
```

> **Ý nghĩa:** `quarantine_workload` là playbook cứng nhất — scale api-gateway về 0 để forensics. Toàn bộ traffic ngừng nhận. Không giống `isolate_workload` (chỉ cô lập service bị attack), quarantine ngăn api-gateway (cổng vào) để attacker không thể tiếp tục thao túng hệ thống.

**Restore bắt buộc sau KB6:**

```bash
bash scripts/run-demo.sh --restore
kubectl --context ctx-aws get deployment -n financial
```

```
NAME                   READY   UP-TO-DATE   AVAILABLE
api-gateway            1/1     1            1
payment-service        1/1     1            1
fraud-detection        1/1     1            1
notification-service   1/1     1            1
```

---

## VI. Luồng SOAR Human-in-the-Loop (HITL)

HITL đảm bảo không có hành động cứng nào (scale=0, block IP, NetworkPolicy) được tự động thực thi mà không có con người phê duyệt.

### Vòng đời đầy đủ của một case

```
① Script chạy → traffic tấn công thật → log vào Loki
② Grafana evaluate rule (mỗi 1 phút) → alert fire
③ Grafana POST webhook → SOAR /grafana-webhook
④ SOAR tạo case: status=pending_approval
⑤ SOAR query Loki lấy log evidence (30 phút gần nhất)
⑥ SOAR gửi email HITL đến voha2005@gmail.com
     → Email chứa: severity, MITRE ID, log evidence, nút chọn playbook
⑦ Admin vào Web Portal http://localhost:18081/security
     → Đăng nhập analyst01 / Test1234!
     → Thấy case đang ⏳ Chờ duyệt
     → Click ⚡ Xử lý → chọn playbook → Confirm
⑧ SOAR thực thi 4 phase:
     contain    → hành động cô lập ngay
     investigate → query Loki thêm evidence
     eradicate  → xử lý triệt để
     recover    → chờ manual rollback
⑨ Case status → executed
⑩ Sau demo: bash scripts/run-demo.sh --restore
```

### 5 Playbook có sẵn

| Playbook | Hành động K8s thực tế | Dùng cho |
|---|---|---|
| `revoke_user_sessions` | Gọi Keycloak Admin API DELETE `/sessions/{id}` | KB1 Brute Force |
| `isolate_workload` | `kubectl scale deployment $workload --replicas=0` | KB2 Fraud, KB3 Lateral |
| `restrict_egress` | Scale core-banking=0 + tạo `NetworkPolicy` chặn IP | KB4 Exfiltration |
| `block_source_ip` | Ghi key Redis `ztlab:blocked_ip:$ip` TTL 86400s + `NetworkPolicy` | KB5 Access Denied |
| `quarantine_workload` | Scale api-gateway=0 (cứng, cần restore thủ công) | KB6 Privilege Escalation |

### Trạng thái case trên Web Portal

| Trạng thái | Badge | Ý nghĩa |
|---|---|---|
| `pending_approval` | ⏳ Vàng | Chờ admin phê duyệt |
| `executing` | 🔄 Xanh nhấp | SOAR đang chạy playbook |
| `executed` | ✓ Đỏ | Playbook đã hoàn thành |
| `denied` | ✗ Xám | Admin quyết định không can thiệp |
| `rolled_back` | ↩ Tím | Đã restore về trạng thái ban đầu |

### Xem log evidence trong email

Email HITL chứa log evidence từ Loki. Với KB3 (lateral movement), evidence trông như sau:

```
[?] {"svid":"spiffe://ztlab.local/aws/notification-service","source_ip":"10.42.1.149",
     "path":"/payments/internal/execute","response_code":403,"response_time":6}

[?] {"decision_id":"52b30605-...","result":false,
     "input":{"attributes":{"source":{"principal":"spiffe://ztlab.local/aws/notification-service"},
     "request":{"http":{"path":"/payments/internal/execute"}}}}}

[payment-service] {"svid":"spiffe://ztlab.local/aws/notification-service","source_ip":"10.42.1.149",
                   "path":"/payments/internal/execute","response_code":403}
```

Cả Envoy access log và OPA decision log đều chứa SVID thật của notification-service — bằng chứng không thể bác bỏ rằng notification-service đã cố truy cập endpoint không được phép.

---

## VII. Chạy Tất Cả 6 Kịch Bản Liên Tiếp

```bash
# Restore trước
bash scripts/run-demo.sh --restore

# Chạy tất cả
bash tests/grafana_run_all.sh
```

```
╔══════════════════════════════════════════════════════╗
║   ZTLab — Chạy 6 kịch bản Grafana → SOAR           ║
╚══════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════
 Chạy KB1  Brute Force (T1110.001)
════════════════════════════════════════════════════════
[KB1_brute_force] Keycloak chặn 20/20 (401)
[KB1_brute_force] PASS: KB1 | blocked=20/20 | logs → Loki (Grafana fire trong ≤1 phút)

════════════════════════════════════════════════════════
 Chạy KB2  Fraud Gate Bypass (T1078.004)
════════════════════════════════════════════════════════
[KB2_fraud_gate] POST /payments 500M tor → HTTP 403 (fraud: block)
[KB2_fraud_gate] PASS: KB2 | HTTP 403 (fraud gate) | logs → Loki

════════════════════════════════════════════════════════
 Chạy KB3  Lateral Movement (T1021.007)
════════════════════════════════════════════════════════
[KB3_lateral_movement] SVID ztlab.local/notification-service → HTTP 403
[KB3_lateral_movement] SVID evil.domain/attacker → HTTP 403
[KB3_lateral_movement] PASS: KB3 | SVID blocked HTTP 403/403 | logs → Loki

════════════════════════════════════════════════════════
 Chạy KB4  Data Exfiltration (T1041)
════════════════════════════════════════════════════════
[KB4_exfiltration] 10 bulk requests → 15546 bytes
[KB4_exfiltration] PASS: KB4 | 10 requests → 15546B | logs → Loki

════════════════════════════════════════════════════════
 Chạy KB5  Access Denied Spike (T1078)
════════════════════════════════════════════════════════
[KB5_access_denied] merchant01 roles: ['financial-read']
[KB5_access_denied]   POST /payments 100000 → HTTP 403
[KB5_access_denied]   POST /payments 50000  → HTTP 403
[KB5_access_denied]   POST /payments 200000 → HTTP 403
[KB5_access_denied]   POST /payments 75000  → HTTP 403
[KB5_access_denied]   POST /payments 1000000 → HTTP 403
[KB5_access_denied]   POST /payments 5000   → HTTP 403
[KB5_access_denied] OPA RBAC từ chối 6/6 (403)
[KB5_access_denied] PASS: KB5 | OPA RBAC từ chối 6/6 | logs → Loki

════════════════════════════════════════════════════════
 Chạy KB6  Privilege Escalation (T1611)
════════════════════════════════════════════════════════
[KB6_privilege_escalation]   id: uid=0(root) gid=0(root) groups=0(root)
[KB6_privilege_escalation]   CapEff: 0xa80425fb
[KB6_privilege_escalation]   ⚠ DANGEROUS caps: ['DAC_OVERRIDE', 'SETUID']
[KB6_privilege_escalation]   ⚠ CÓ THỂ ĐỌC /etc/shadow (3 dòng)
[KB6_privilege_escalation] ▶ VI PHẠM Zero Trust workload isolation xác nhận
[KB6_privilege_escalation] PASS: KB6 | uid=0 CapEff=0xa80425fb shadow=true | logs → Loki

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

**Sau khi chạy xong — Grafana fire trong vòng 1 phút:**

- Vào `http://localhost:3000` (admin / ZTLab2024!) → Alerting → Alert rules → folder ZTLab → thấy các rule đang `Firing`.
- Vào `http://localhost:18081/security` (analyst01 / Test1234!) → thấy 4–6 case `⏳ Chờ duyệt`.
- Kiểm tra `voha2005@gmail.com` → email HITL với log evidence.

---

## VIII. Tổng Hợp Kết Quả

| KB | Tên | MITRE | Lớp Zero Trust | Bằng chứng thật | Phản ứng SOAR |
|---|---|---|---|---|---|
| KB1 | Brute Force Login | T1110.001 | Authentication (Keycloak) | 20 HTTP 401 thực từ Keycloak | revoke_user_sessions |
| KB2 | Fraud Gate Bypass | T1078.004 | Authorization (fraud policy) | fraud_score=75, verdict=block, reason=[critical_amount, risky_channel] | isolate_workload → payment-service scale=0 |
| KB3 | Lateral Movement | T1021.007 | mTLS identity (SPIRE + Envoy) | SVID=spiffe://ztlab.local/aws/notification-service trong Envoy + OPA log | isolate_workload |
| KB4 | Data Exfiltration | T1041 | Egress monitoring (Envoy bytes_sent) | 15,546 bytes đo thực từ 10 bulk request | restrict_egress → core-banking scale=0 + NetworkPolicy |
| KB5 | Access Denied Spike | T1078 | RBAC least privilege (OPA) | merchant01 HTTP 403 × 6 lần với 6 amounts khác nhau | block_source_ip → Redis TTL 24h + NetworkPolicy |
| KB6 | Privilege Escalation | T1611 | Workload isolation (container security) | uid=0, CapEff=0xa80425fb, /etc/shadow readable, setuid(0) OK | quarantine_workload → api-gateway scale=0 |

---

## IX. Lưu Ý Khi Demo

**1. Restore bắt buộc trước mỗi kịch bản:**

```bash
bash scripts/run-demo.sh --restore
```

Đặc biệt sau KB6 — api-gateway bị scale=0, toàn bộ hệ thống không nhận request nào.

**2. Dedup 5 phút:** Nếu chạy cùng kịch bản 2 lần trong 5 phút, SOAR báo case đã `deduped` — đây là hoạt động đúng, tránh flood email. Chờ 5 phút hoặc dùng fingerprint khác.

**3. Fraud score tăng sau nhiều lần chạy KB2:** Redis velocity counter cộng dồn. Score có thể là 85+ thay vì 75 — vẫn bị chặn vì vượt ngưỡng 70, nhưng số hiển thị khác. Reset bằng:

```bash
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=redis -o jsonpath='{.items[0].metadata.name}') \
  -- redis-cli FLUSHDB
```

**4. Grafana fire sau 1 phút:** Script chạy xong → Grafana evaluate sau tối đa 1 phút → case xuất hiện trên Web Portal. Không cần refresh thủ công, chỉ cần chờ.

**5. OpenStack tunnel down:** Nếu payment trả timeout khi gọi core-banking:

```bash
bash scripts/k8s-tunnel.sh up all
```

**6. Thứ tự demo đề xuất:**

```
1. Chứng minh hệ thống hoạt động bình thường (giao dịch testuser01 → HTTP 200)
2. KB5 (RBAC) → ngắn, trực quan nhất: merchant01 vs testuser01
3. KB1 (Brute Force) → đơn giản, dễ hiểu
4. KB2 (Fraud Gate) → thấy fraud score breakdown
5. KB3 (Lateral Movement) → kỹ thuật nhất, chạy scenario_03 để thấy SVID thật
6. KB4 (Exfiltration) → thấy bytes_sent trong log
7. KB6 (Privilege Escalation) → dramatic nhất, chạy cuối cùng
```
