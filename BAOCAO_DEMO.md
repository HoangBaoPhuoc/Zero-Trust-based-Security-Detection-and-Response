# Báo Cáo Demo Hệ Thống ZTLab
## Zero Trust Security Detection & Response for Microservices in Multi-Cloud

> **Môn học:** NT114.Q21.ANTT — Đồ án chuyên ngành  
> **Sinh viên:** Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> **Giảng viên hướng dẫn:** ThS. Đỗ Thị Phương Uyên  
> **Ngày thực hiện demo:** 2026-06-27

---

## I. Giới Thiệu Hệ Thống

### Hệ thống làm gì?

ZTLab là một hệ thống ngân hàng vi dịch vụ (microservices) được xây dựng theo mô hình **Zero Trust** — tức là không tin tưởng mặc định bất kỳ ai, dù người dùng hay dịch vụ đang ở bên trong hay bên ngoài hệ thống. Mọi request đều phải được xác minh, mọi hành động đều phải được kiểm tra quyền hạn.

Ngoài chức năng ngân hàng, hệ thống còn có khả năng **tự phát hiện tấn công** (detection) và **tự động phản ứng** (response) thông qua chuỗi: Grafana → SOAR Engine → Human-in-the-Loop.

### Hệ thống chạy ở đâu?

Hệ thống triển khai trên **hai cloud khác nhau**, kết nối với nhau qua đường hầm WireGuard mã hoá:

```
┌──────────── AWS (Singapore) ────────────┐      WireGuard       ┌──── OpenStack (Local) ────┐
│                                         │  ←————————————————→  │                           │
│  api-gateway        ← cổng vào duy nhất │                       │  core-banking             │
│  payment-service    ← điều phối giao dịch│                       │  account-service          │
│  fraud-detection    ← tính điểm rủi ro  │                       │  transaction-service      │
│  notification-svc   ← gửi email         │                       │                           │
│                                         │                       │  (lưu trữ dữ liệu        │
│  Keycloak           ← đăng nhập         │                       │   tài chính cốt lõi)      │
│  OPA Server         ← phân quyền        │                       └───────────────────────────┘
│  SPIRE              ← định danh service │
│                                         │
│  Grafana + Loki     ← giám sát, cảnh báo│
│  SOAR Engine        ← phản ứng sự cố    │
└─────────────────────────────────────────┘
```

---

## II. Các Thành Phần Zero Trust — Cấu Hình Và Vai Trò

Hệ thống Zero Trust được xây dựng từ 4 lớp kiểm soát chính, hoạt động nối tiếp nhau với mỗi request.

---

### Lớp 1: Keycloak — Xác Thực Người Dùng

**Vai trò:** Là "cổng đăng nhập" duy nhất. Người dùng xác thực tại đây và nhận về một **JWT (JSON Web Token)** — một thẻ điện tử có chữ ký mã hoá, chứa thông tin định danh và quyền hạn.

**Cấu hình thực tế:** Keycloak quản lý realm `ztlab` với các tài khoản:

| Tài khoản | Quyền hạn | Ý nghĩa |
|---|---|---|
| testuser01 | financial-read + financial-write | Người dùng thông thường, được phép giao dịch |
| merchant02 | financial-read | Đối tác, chỉ được xem thông tin, không được giao dịch |
| analyst01 | security-analyst + security-admin | Nhân viên bảo mật, phê duyệt sự cố |

**JWT trông như thế nào?** Khi đăng nhập thành công, server trả về một chuỗi dài. Trong đó, phần payload sau khi giải mã có dạng:

```json
{
  "preferred_username": "testuser01",
  "realm_access": {
    "roles": ["financial-read", "financial-write"]
  },
  "iss": "http://keycloak.ztlab.local:8180/realms/ztlab",
  "exp": 1782555600
}
```
> 📁 **Nguồn:** Giải mã JWT bằng lệnh `echo $TOKEN | cut -d. -f2 | base64 -d | python3 -m json.tool` — lấy token từ bước đăng nhập Keycloak (POST `/realms/ztlab/protocol/openid-connect/token`)

Trường `roles` này được OPA (lớp tiếp theo) dùng để quyết định người dùng được làm gì.

**Khi đăng nhập thất bại,** Keycloak ghi ngay vào event log:

```
WARN [org.keycloak.events]
  type="LOGIN_ERROR"
  error="invalid_user_credentials"
  username="testuser01"
  ipAddress="127.0.0.1"
```
> 📁 **Nguồn:** `kubectl --context ctx-aws logs -n identity <keycloak-pod> | grep LOGIN_ERROR`

Đây là bằng chứng của mỗi lần thử brute force — 20 lần thất bại sẽ có 20 dòng log như vậy.

---

### Lớp 2: SPIRE/SPIFFE — Định Danh Dịch Vụ

**Vai trò:** Trong khi Keycloak lo việc "người dùng là ai", SPIRE lo việc "dịch vụ là ai". Mỗi microservice được cấp một **chứng chỉ định danh duy nhất (SVID)** — tương tự như CMND của từng dịch vụ.

**Tại sao cần?** Trong môi trường microservices, các dịch vụ liên tục gọi nhau. Nếu chỉ dùng địa chỉ IP để xác định "ai đang gọi", attacker có thể giả mạo IP rất dễ. SPIRE giải quyết bằng cách cấp chứng chỉ mật mã — không thể giả mạo.

**Cấu hình thực tế:**

```
trust_domain = "ztlab.local"    ← ranh giới tin cậy
default_x509_svid_ttl = "1h"   ← mỗi chứng chỉ chỉ sống 1 giờ, tự động gia hạn
```
> 📁 **Nguồn:** file `spire/server/server.conf`

SPIRE xác thực node thông qua Kubernetes API (k8s_psat) — không có password cứng nào trong config.

**7 định danh SPIFFE trong hệ thống:**

```
spiffe://ztlab.local/aws/api-gateway
spiffe://ztlab.local/aws/payment-service
spiffe://ztlab.local/aws/fraud-detection
spiffe://ztlab.local/aws/notification-service
spiffe://ztlab.local/openstack/core-banking
spiffe://ztlab.local/openstack/account-service
spiffe://ztlab.local/openstack/transaction-service
```
> 📁 **Nguồn:** file `spire/server/server.conf` (registration entries) — xác minh live bằng `kubectl --context ctx-aws exec -n spire <spire-agent-pod> -- /opt/spire/bin/spire-agent api fetch x509 -socketPath /run/spire/sockets/agent.sock`

Mỗi ID này được gắn vào một chứng chỉ X.509 thực sự. Khi payment-service gọi core-banking, core-banking đọc chứng chỉ của caller và biết chính xác đó là `spiffe://ztlab.local/aws/payment-service` — không thể giả mạo.

**Log SPIRE đang hoạt động (gia hạn chứng chỉ mỗi ~30 phút):**

```
msg="Renewing X509-SVID"
  spiffe_id="spiffe://ztlab.local/aws/api-gateway"
  expires_at="2026-06-27T11:43:16Z"

msg="Successfully reattested node"
  agent_id="spiffe://ztlab.local/spire/agent/k8s_psat/aws-k3s/ce6be52e-..."
  node_attestor_type=k8s_psat
```
> 📁 **Nguồn:** `kubectl --context ctx-aws logs -n spire <spire-server-pod> | grep -E "Renewing|reattested"`

Node re-attest mỗi ~25 phút — SPIRE **liên tục** xác minh identity, đây là bằng chứng của nguyên tắc *Continuous Verification*.

---

### Lớp 3: Envoy Sidecar — Proxy Bảo Mật

**Vai trò:** Mỗi microservice chạy kèm một **Envoy Sidecar** — một proxy nhỏ nằm trong cùng pod, đứng chắn trước ứng dụng. Mọi traffic vào/ra đều qua Envoy, ứng dụng không bao giờ nhận request trực tiếp.

Điều này thể hiện qua trạng thái pod: các service quan trọng đều `READY 2/2` (2 container: app + envoy), không phải `1/1`.

**Envoy làm 3 việc quan trọng:**

**1. Xử lý mTLS** — khi nhận kết nối từ service khác, Envoy yêu cầu caller trình chứng chỉ SVID. Envoy tự lấy cert của mình từ SPIRE Agent qua Unix socket `/run/spire/sockets/agent.sock`. Nhờ vậy không có password hay key nào cứng trong code.

```yaml
require_client_certificate: true   ← bắt buộc caller phải trình cert
```
> 📁 **Nguồn:** file `envoy/envoy-sidecar.yaml` — block `transport_socket` → `downstream_tls_context`

**2. Gọi OPA kiểm tra quyền** — sau khi xác thực TLS, Envoy gọi OPA qua gRPC trước khi forward request vào app:

```yaml
failure_mode_allow: false   ← nếu OPA lỗi/timeout → TỪ CHỐI, không bao giờ để qua
timeout: 2s
```
> 📁 **Nguồn:** file `envoy/envoy-sidecar.yaml` — block `http_filters` → `envoy.filters.http.ext_authz`

`failure_mode_allow: false` là một quyết định quan trọng: thà từ chối nhầm còn hơn để lọt request khi hệ thống kiểm soát đang có vấn đề.

**3. Ghi access log chi tiết** — mỗi request đều được ghi thành một dòng JSON:

```json
{
  "timestamp": "2026-06-27T11:43:37Z",
  "method": "POST",
  "path": "/payments",
  "response_code": 200,
  "response_time": 3,
  "source_ip": "10.42.0.1",
  "bytes_sent": 74,
  "svid": "spiffe://ztlab.local/aws/api-gateway"
}
```
> 📁 **Nguồn:** `kubectl --context ctx-aws logs -n financial <pod-name> -c envoy` — format JSON được định nghĩa trong `envoy/envoy-sidecar.yaml` → block `access_log`

Trường `svid` cho biết chính xác caller là ai (identity mật mã, không thể giả). Trường `bytes_sent` được dùng để phát hiện data exfiltration. Log này được Promtail thu thập và đẩy vào Loki.

**Routing outbound** — khi service cần gọi service khác, nó luôn đi qua `127.0.0.1:15001` (Envoy outbound), không bao giờ gọi thẳng. Envoy routing theo path:

```
/score              → fraud-detection service
/transactions/execute → core-banking (OpenStack, qua WireGuard)
/notify             → notification-service
```
> 📁 **Nguồn:** file `envoy/envoy-sidecar.yaml` — listener `:15001` (outbound) → block `route_config` → `virtual_hosts`

---

### Lớp 4: OPA — Kiểm Tra Quyền Hạn

**Vai trò:** OPA (Open Policy Agent) là "thẩm phán" của hệ thống. Nó nhận mọi request từ Envoy, đọc policy Rego, và trả lời một câu hỏi duy nhất: **"request này có được phép không?"**

**Nguyên tắc cơ bản của policy:**

```rego
default allow = false    ← mặc định từ chối tất cả
```
> 📁 **Nguồn:** file `opa/policies/zta_policy.rego` — dòng đầu tiên của package `zta.authz`

Có nghĩa là: trừ khi có rule nào đó chủ động cho phép, mọi request đều bị từ chối. Đây là *deny-by-default* — nguyên tắc cốt lõi của Zero Trust.

**4 loại request được phép (và điều kiện):**

| Loại | Điều kiện | Ví dụ |
|---|---|---|
| Public path | Không cần gì | GET /health |
| Từ người dùng | JWT hợp lệ + đúng role + không có SVID | POST /payments từ testuser01 |
| Từ service khác | SVID hợp lệ trong trust domain | payment-service gọi fraud-detection |
| Giao dịch tài chính | SVID hợp lệ + fraud gate passed | core-banking nhận execute |

**Phân quyền theo role:** OPA có một bảng tra cứu rõ ràng:

```
financial-read  → chỉ GET, OPTIONS
financial-write → GET, OPTIONS, POST, PUT
security-admin  → GET, OPTIONS, POST, PUT, DELETE
```
> 📁 **Nguồn:** file `opa/policies/zta_policy.rego` — object `permissions` → xem bằng `cat opa/policies/zta_policy.rego | grep -A10 "permissions :="`

Khi merchant01 (chỉ có `financial-read`) thử POST /payments, OPA tra bảng: `permissions["financial-read"]["POST"]` không tồn tại → `role_permits_action = false` → `allow = false` → HTTP 403.

**Kiểm tra SVID:** OPA kiểm tra xem SVID của caller có bắt đầu bằng `spiffe://ztlab.local/` không. Nếu ai đó gửi `spiffe://evil.corp/attacker` — không qua được.

**Kiểm tra Fraud Gate:** Khi payment-service gọi `/transactions/execute` tới core-banking, OPA yêu cầu phải có 2 header: `X-Fraud-Gate: passed` VÀ `X-Fraud-Score < 75`. Không có header hoặc score cao → từ chối.

---

### Detection & Response: Grafana → SOAR

**Grafana** chạy 6 alert rule, evaluate mỗi **1 phút**, query log từ Loki:

| Kịch bản | Query Loki | Trigger khi |
|---|---|---|
| Brute Force (KB1) | `{job="envoy-access"} \| json \| response_code=401` | Có log 401 trong 1 phút |
| Fraud Gate (KB2) | `{job="opa-decisions",opa_result="false",request_path="/transactions/execute"}` | Có OPA deny tại /transactions/execute |
| Lateral Movement (KB3) | `{job="opa-decisions",opa_result="false"}` | Có OPA deny bất kỳ |
| Data Exfiltration (KB4) | `{job="envoy-access",cloud="openstack"} \| json \| bytes_sent > 1048576` | Response > 1MB từ OpenStack |
| Access Denied (KB5) | `{job="opa-decisions"} \| json \| result="deny"` | Có OPA deny |
| Privilege Escalation (KB6) | `{namespace="financial"} \|~ "privilege_escalation\|setuid"` | Log chứa keyword nguy hiểm |

Khi rule fire → Grafana gửi webhook đến SOAR Engine.

**SOAR Engine** nhận alert và:
1. Tạo case với `status = pending_approval` (vì KB1–KB6 đều severity ≥ high)
2. Gửi email cảnh báo đến voha2005@gmail.com
3. Chờ admin phê duyệt trên Web Portal (http://localhost:18081/security)
4. Khi phê duyệt → thực thi playbook K8s (scale deployment, tạo NetworkPolicy, block IP Redis)

---

## III. Luồng Giao Dịch Bình Thường

Trước khi xem các kịch bản tấn công, cần hiểu một giao dịch hợp lệ trải qua bao nhiêu lớp kiểm soát.

**Tình huống:** testuser01 chuyển 10,000 VND sang ACC-2001.

**Bước 1 — Đăng nhập lấy JWT:**

testuser01 POST đến Keycloak với username/password. Keycloak xác minh, trả về JWT có `roles: ["financial-read","financial-write"]`. Client lưu JWT này để dùng cho các request tiếp theo.

**Bước 2 — Gửi lệnh chuyển tiền:**

```
POST http://localhost:18080/payments
Authorization: Bearer <JWT>
{"from_account":"ACC-1001","to_account":"ACC-2001","amount":10000}
```

**Bước 3 — API Gateway + Envoy kiểm tra:**

Request đến Envoy inbound (`:15006`). Envoy gọi OPA:
- JWT có hợp lệ không? → có (chữ ký RSA đúng, chưa hết hạn, issuer đúng)
- Role có `financial-write` không? → có
- Không có SVID? → đúng, đây là request từ user → `external_api_request` match → **cho phép**

Envoy forward vào api-gateway app. api-gateway lại verify JWT một lần nữa (double-check), kiểm tra IP có bị block trong Redis không → không → forward sang payment-service qua Envoy outbound (mTLS).

**Bước 4 — Fraud Detection:**

payment-service gọi fraud-detection `/score`:
- amount = 10,000 VND → bình thường (không phải critical_amount ≥ 500M)
- channel = "api" → không phải kênh rủi ro
- velocity = lần đầu giao dịch → 0 điểm thêm
- **Tổng score = 5** (chỉ base score), ngưỡng block là 70 → `gate = "passed"`

**Bước 5 — Gọi Core Banking:**

payment-service gắn headers `X-Fraud-Gate: passed`, `X-Fraud-Score: 5`, và **HMAC signature** (để core-banking xác minh header không bị giả mạo trên đường đi). Gọi qua WireGuard tunnel đến core-banking trên OpenStack.

Core-banking Envoy nhận → OPA check: SVID của payment-service hợp lệ, `X-Fraud-Gate: passed`, score < 75 → cho phép → thực hiện debit/credit → ghi ledger.

**Bước 6 — Trả kết quả:**

```json
{"status":"completed","trace_id":"abc-123","fraud":{"score":5,"verdict":"allow"}}
```

**Bước 7 — Ghi log:**

Tất cả Envoy trong chuỗi ghi access log → Promtail thu thập → Loki. Grafana evaluate rule → không thấy pattern bất thường → alert vẫn `inactive`.

---

## IV. Demo 6 Kịch Bản Tấn Công

---

### KB1 — Brute Force Login (T1110.001)

**Ý tưởng tấn công:** Kẻ tấn công không biết mật khẩu, thử đoán liên tục.

**Zero Trust ngăn chặn bằng cách nào:** *Continuous Verification* — Keycloak không có "grace period", không có cơ chế "thử sai 3 lần mới block". Mỗi lần thử là một lần xác minh độc lập, sai là từ chối ngay.

**Chạy kịch bản:**

```bash
bash tests/grafana_kb1_brute_force.sh
```

**Diễn biến từng bước:**

**① Script gửi 20 lần đăng nhập với password sai:**

Script lặp 20 lần, mỗi lần POST đến Keycloak token endpoint với `password=wrong_password_X`. Mỗi lần Keycloak trả HTTP 401. Không có lần nào được qua.

```
[KB1_brute_force] Keycloak chặn 20/20 — xác thực Zero Trust hoạt động đúng
```

Trong Keycloak, mỗi lần thất bại ghi một dòng log:

```
type="LOGIN_ERROR"  error="invalid_user_credentials"  username="testuser01"
```
> 📁 **Nguồn:** `kubectl --context ctx-aws logs -n identity <keycloak-pod> | grep LOGIN_ERROR | tail -25` — mỗi lần sai password → 1 dòng như thế này

20 lần thất bại = 20 dòng log trong vòng 5 giây — dấu hiệu rõ ràng của brute force.

**② Script đẩy log 401 vào Loki:**

5 dòng JSON access log (format Envoy) với `response_code: 401` được đẩy vào Loki Push API. Grafana rule `{job="envoy-access"} | json | response_code=401` sẽ tìm thấy chúng khi evaluate.

**③ Grafana webhook → SOAR tạo case:**

Script simulate webhook Grafana đến SOAR. SOAR tạo case:
- `attack_type = brute_force`
- `severity = high`
- `status = pending_approval` (cần admin duyệt)
- Gửi email HITL đến voha2005@gmail.com

```
SOAR case=case-20260627041323-kb1-17  status=pending_approval  playbook=revoke_user_sessions
```
> 📁 **Nguồn:** output trực tiếp từ `bash tests/grafana_kb1_brute_force.sh` — hoặc xem qua `curl -s http://localhost:18082/cases | python3 -m json.tool`

**④ Admin phê duyệt trên Web Portal:**

Vào http://localhost:18081/security → analyst01/Test1234! → thấy badge **⏳ Chờ duyệt** → click **⚡ Xử lý** → chọn **🔑 Thu hồi phiên** → Confirm.

**⑤ SOAR thực thi playbook — 4 phase:**

```
[contain    ] → thử revoke Keycloak session theo username (bị skip vì alert không có username field)
[investigate] → query Loki: tìm được 10 log entry 401 làm bằng chứng
[eradicate  ] → ghi nhận sessions đã được xử lý, user phải re-authenticate
[recover    ] → pending, chờ admin trigger rollback
```
> 📁 **Nguồn:** `curl -s http://localhost:18082/cases/<case-id>/log | python3 -m json.tool` — log từng phase playbook của SOAR Engine

**Kết quả chứng minh:**

```
case_id : case-20260627072514-kb1-17
status  : executed
[investigate] Loki evidence: 10 log entries matched query for brute_force from 10.0.0.1
```
> 📁 **Nguồn:** `curl -s http://localhost:18082/cases/case-20260627072514-kb1-17 | python3 -m json.tool`

Hệ thống phát hiện, tạo case, thực thi response hoàn chỉnh. Cuộc tấn công brute force không vào được bất kỳ service nào phía trong — bị chặn ngay tại Identity Provider.

**📋 Log demo live — chạy theo thứ tự khi trình bày:**

**[1] Xem Keycloak ghi nhận 20 lần thất bại:**
```bash
kubectl --context ctx-aws logs -n identity \
  $(kubectl --context ctx-aws get pod -n identity -l app=keycloak -o jsonpath='{.items[0].metadata.name}') \
  | grep LOGIN_ERROR | tail -5
```
```
WARN [org.keycloak.events] type="LOGIN_ERROR" error="invalid_user_credentials" username="testuser01" ipAddress="127.0.0.1"
WARN [org.keycloak.events] type="LOGIN_ERROR" error="invalid_user_credentials" username="testuser01" ipAddress="127.0.0.1"
WARN [org.keycloak.events] type="LOGIN_ERROR" error="invalid_user_credentials" username="testuser01" ipAddress="127.0.0.1"
WARN [org.keycloak.events] type="LOGIN_ERROR" error="invalid_user_credentials" username="testuser01" ipAddress="127.0.0.1"
WARN [org.keycloak.events] type="LOGIN_ERROR" error="invalid_user_credentials" username="testuser01" ipAddress="127.0.0.1"
```

**[2] Xem Envoy ghi log 401 (bằng chứng Grafana dùng để alert):**
```bash
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=api-gateway -o jsonpath='{.items[0].metadata.name}') \
  -c envoy | grep '"response_code":"401"' | tail -3
```
```json
{"timestamp":"2026-06-27T11:42:01Z","method":"POST","path":"/realms/ztlab/protocol/openid-connect/token","response_code":"401","source_ip":"10.0.0.1","bytes_sent":44}
{"timestamp":"2026-06-27T11:42:02Z","method":"POST","path":"/realms/ztlab/protocol/openid-connect/token","response_code":"401","source_ip":"10.0.0.1","bytes_sent":44}
{"timestamp":"2026-06-27T11:42:03Z","method":"POST","path":"/realms/ztlab/protocol/openid-connect/token","response_code":"401","source_ip":"10.0.0.1","bytes_sent":44}
```

**[3] Xem SOAR đã tạo case (ngay sau khi script chạy xong):**
```bash
curl -s http://localhost:18082/cases | python3 -c "
import sys, json
cases = json.load(sys.stdin)
for c in cases[-3:]:
    print(c['case_id'], '|', c['attack_type'], '|', c['status'], '|', c.get('playbook',''))
"
```
```
case-20260627072514-kb1-17 | brute_force | pending_approval | revoke_user_sessions
```

**[4] Sau khi phê duyệt trên Web Portal — xem playbook thực thi:**
```bash
curl -s http://localhost:18082/cases/case-20260627072514-kb1-17 | python3 -m json.tool | grep -E '"status"|"phase"|"result"'
```
```json
"status": "executed",
"phase": "investigate",
"result": "Loki evidence: 10 log entries matched query for brute_force from 10.0.0.1"
```

---

### KB2 — Fraud Gate Bypass (T1078.004)

**Ý tưởng tấn công:** Kẻ tấn công đã có tài khoản hợp lệ (JWT đúng), cố thực hiện giao dịch số tiền cực lớn qua kênh ẩn danh (TOR).

**Zero Trust ngăn chặn bằng cách nào:** *Verify Explicitly* — có JWT hợp lệ chưa đủ. Mỗi giao dịch phải được đánh giá riêng theo ngữ cảnh: số tiền bao nhiêu, kênh nào, lịch sử giao dịch ra sao. OPA không chỉ hỏi "người này là ai" mà còn hỏi "hành động này có đáng tin không".

**Chạy kịch bản:**

```bash
bash tests/grafana_kb2_fraud_gate.sh
```

**Diễn biến từng bước:**

**① Kẻ tấn công đăng nhập thành công:**

testuser01 đăng nhập với đúng password → Keycloak cấp JWT hợp lệ. Đến đây mọi thứ bình thường.

**② Gửi giao dịch 500 triệu VND qua kênh TOR:**

```
POST /payments
{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":500000000,"channel":"tor"}
```

**③ Fraud Detection tính điểm rủi ro:**

fraud-detection nhận request từ payment-service, tính:
- Base score: 5 điểm
- `amount = 500,000,000 VND` ≥ ngưỡng critical (500M) → **+55 điểm**
- `channel = "tor"` thuộc danh sách kênh rủi ro → **+15 điểm**
- **Tổng score = 75**, ngưỡng block là 70 → **verdict = "block"**

**④ Payment-service trả về 403 ngay, KHÔNG gọi core-banking:**

Đây là điểm quan trọng: giao dịch bị chặn *trước khi* chạm đến lớp banking. Core-banking không bao giờ nhận được request này.

**Response thực tế:**

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
> 📁 **Nguồn:** output của `bash tests/grafana_kb2_fraud_gate.sh` — hoặc test thủ công bằng `curl -s -X POST http://localhost:18080/payments -H "Authorization: Bearer $TOKEN" -d '{"amount":500000000,"channel":"tor",...}'`

**⑤ SOAR tạo case, phê duyệt → isolate_workload:**

Sau khi admin phê duyệt, SOAR scale payment-service về 0 replica:

```
[contain] scaled Deployment/payment-service from 1 → 0 replicas
```
> 📁 **Nguồn:** `curl -s http://localhost:18082/cases/<case-id>/log` — dòng phase `contain` trong playbook `isolate_workload`

Xác nhận:
```bash
kubectl --context ctx-aws get deployment payment-service -n financial
# payment-service   0/0     0            0     ← đã cô lập hoàn toàn
```

Mọi request đến payment-service đều nhận HTTP 503. Kẻ tấn công không thể tiếp tục thử bất kỳ giao dịch nào khác.

**📋 Log demo live — chạy theo thứ tự khi trình bày:**

**[1] Gọi thủ công để thấy 403 ngay lập tức:**
```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-9999","amount":500000000,"channel":"tor"}' \
  | python3 -m json.tool
```
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

**[2] Xem fraud-detection log tính điểm:**
```bash
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=fraud-detection -o jsonpath='{.items[0].metadata.name}') \
  | grep -E "score|verdict|reason" | tail -5
```
```
INFO score=75 verdict=block reason=['critical_amount', 'risky_channel'] gate=blocked amount=500000000 channel=tor
```

**[3] Xem payment-service log xác nhận KHÔNG gọi core-banking:**
```bash
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=payment-service -o jsonpath='{.items[0].metadata.name}') \
  | grep -E "fraud gate|core.banking|blocked" | tail -5
```
```
INFO fraud gate blocked — score=75, reason=['critical_amount','risky_channel'] — NOT calling core-banking
INFO returning HTTP 403 to caller
```

**[4] Sau khi SOAR thực thi — xem payment-service đã scale=0:**
```bash
kubectl --context ctx-aws get deployment payment-service -n financial
```
```
NAME              READY   UP-TO-DATE   AVAILABLE
payment-service   0/0     0            0
```

**[5] Xác nhận attack không thể tiếp tục (503):**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-9999","amount":1000}'
```
```
HTTP 503
```

---

### KB3 — Lateral Movement via Invalid SVID (T1021.007)

**Ý tưởng tấn công:** Kẻ tấn công đã vào được bên trong mạng nội bộ (giả sử đã compromise notification-service hoặc tự tạo SVID giả). Cố gọi API nội bộ nhạy cảm `/payments/internal/execute` để thực hiện giao dịch trực tiếp, bỏ qua mọi kiểm tra bên ngoài.

**Zero Trust ngăn chặn bằng cách nào:** *Network Micro-segmentation* — trong Zero Trust, việc "đã vào trong mạng" không có ý nghĩa gì. Mỗi service-to-service call đều phải có định danh hợp lệ (SVID) và đúng quyền hạn. Không có "trusted zone" bên trong.

**Chạy kịch bản:**

```bash
bash tests/grafana_kb3_lateral_movement.sh
```

**Diễn biến từng bước:**

**① Thử 1: Dùng SVID của notification-service gọi sang /payments/internal:**

notification-service có SVID hợp lệ trong trust domain `ztlab.local`. Nhưng OPA policy chỉ cho phép notification-service gọi `/notify` — không phải `/payments/internal/execute`.

```
X-SPIFFE-ID: spiffe://ztlab.local/aws/notification-service
→ OPA: valid_svid=true, nhưng path không match rule nào → allow=false → HTTP 403
```

**② Thử 2: Dùng SVID từ ngoài trust domain:**

```
X-SPIFFE-ID: spiffe://evil.corp/attacker
→ OPA: valid_svid = startswith("spiffe://ztlab.local/") = FALSE → allow=false → HTTP 403
```

**Xác minh thủ công:**

```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments/internal/execute \
  -H "X-SPIFFE-ID: spiffe://evil.corp/attacker" \
  -d '{"amount":100000}'

→ HTTP 403   ← bị chặn hoàn toàn
```

**Log OPA thực tế ghi nhận:**

```json
{
  "result": false,
  "path": "zta/authz/allow",
  "input": {
    "request": {"http": {"path": "/payments/internal/execute"}},
    "x-spiffe-id": "spiffe://evil.corp/attacker"
  },
  "metrics": {"timer_rego_query_eval_ns": 251982}
}
```
> 📁 **Nguồn:** `kubectl --context ctx-aws logs -n opa <opa-pod> | grep '"result":false'` — OPA ghi decision log cho mọi request bị từ chối

OPA xử lý mỗi request trong ~252 microseconds. Đủ nhanh để không ảnh hưởng performance, đủ chắc để không có request nào lọt.

**③ SOAR case:**

```
case-20260627042140-bf5e09 | lateral_movement | executed | isolate_workload
```
> 📁 **Nguồn:** `curl -s http://localhost:18082/cases | python3 -c "import sys,json; [print(c['case_id'],'|',c['attack_type'],'|',c['status'],'|',c.get('playbook','')) for c in json.load(sys.stdin)]"`

**📋 Log demo live — chạy theo thứ tự khi trình bày:**

**[1] Thử gọi API nội bộ với SVID giả — xem bị chặn ngay:**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments/internal/execute \
  -H "X-SPIFFE-ID: spiffe://evil.corp/attacker" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-9999","amount":999999}'
```
```
HTTP 403
```

**[2] Thử với SVID của notification-service (đúng trust domain nhưng sai path):**
```bash
curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments/internal/execute \
  -H "X-SPIFFE-ID: spiffe://ztlab.local/aws/notification-service" \
  -d '{"amount":999999}'
```
```
HTTP 403
```

**[3] Xem OPA decision log — thấy 2 request vừa bị deny:**
```bash
kubectl --context ctx-aws logs -n opa \
  $(kubectl --context ctx-aws get pod -n opa -l app=opa -o jsonpath='{.items[0].metadata.name}') \
  | grep '"result":false' | tail -3
```
```json
{"result":false,"path":"zta/authz/allow","input":{"request":{"http":{"path":"/payments/internal/execute"}},"x-spiffe-id":"spiffe://evil.corp/attacker"},"metrics":{"timer_rego_query_eval_ns":251982}}
{"result":false,"path":"zta/authz/allow","input":{"request":{"http":{"path":"/payments/internal/execute"}},"x-spiffe-id":"spiffe://ztlab.local/aws/notification-service"},"metrics":{"timer_rego_query_eval_ns":198341}}
```

**[4] Xem Envoy access log ghi nhận cả 2 lần deny:**
```bash
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=payment-service -o jsonpath='{.items[0].metadata.name}') \
  -c envoy | grep '"response_code":"403"' | tail -3
```
```json
{"timestamp":"2026-06-27T11:55:01Z","method":"POST","path":"/payments/internal/execute","response_code":"403","source_ip":"10.0.0.1","svid":""}
{"timestamp":"2026-06-27T11:55:04Z","method":"POST","path":"/payments/internal/execute","response_code":"403","source_ip":"10.0.0.1","svid":"spiffe://ztlab.local/aws/notification-service"}
```

**[5] Xem SOAR case sau khi phê duyệt — notification-service bị cô lập:**
```bash
curl -s http://localhost:18082/cases | python3 -c "
import sys, json
for c in json.load(sys.stdin)[-2:]:
    print(c['case_id'], '|', c['attack_type'], '|', c['status'])
"
```
```
case-20260627042140-bf5e09 | lateral_movement | executed
```

---

### KB4 — Data Exfiltration / Large Response (T1041)

**Ý tưởng tấn công:** Kẻ tấn công có JWT hợp lệ, không cố làm gì bất thường — chỉ liên tục gọi API lấy lịch sử giao dịch với `limit=500`, nhiều lần, để dần dần kéo hết dữ liệu ra ngoài.

**Zero Trust ngăn chặn bằng cách nào:** *Assume Breach + Egress Control* — Zero Trust giả định kẻ tấn công có thể đã vào bên trong rồi, nên phải giám sát cả traffic *ra ngoài*. Envoy ghi `bytes_sent` cho mỗi response, Grafana phát hiện pattern dữ liệu lớn bất thường.

**Chạy kịch bản:**

```bash
bash tests/grafana_kb4_exfiltration.sh
```

**Diễn biến từng bước:**

**① 10 request bulk download thực tế:**

Script gọi 10 lần liên tiếp các endpoint trả dữ liệu lớn. Đo được:

```
/transactions?account_id=ACC-1001&limit=500 → 2,208 bytes
/accounts/balance → 30 bytes
/transactions?account_id=ACC-2001&limit=500 → 2,208 bytes
... (10 request)
Tổng = 15,546 bytes thực đo từ api-gateway
```

```
[KB4] ▶ 10 request bulk data — tổng bytes nhận: 15546 bytes
```
> 📁 **Nguồn:** output của `bash tests/grafana_kb4_exfiltration.sh` — script đo `bytes_received` thực từ từng curl call

**② Inject log giả lập core-banking (3.5MB) vào Loki:**

Grafana rule cần `bytes_sent > 1,048,576` (1MB). 15KB từ api-gateway không đủ trigger. Script inject log giả lập core-banking với `bytes_sent = 3,670,016` (~3.5MB) để Grafana phát hiện.

*Lý do giả lập:* core-banking chạy trên OpenStack, khi tunnel bị down Promtail không capture được log. Trong production thực, Promtail sẽ tự thu thập.

**③ SOAR — restrict_egress:**

```
[contain    ] scaled Deployment/core-banking from 1 → 0 replicas (suspected exfiltration)
[investigate] Loki evidence: 2 log entries matched query for large_response from 10.0.0.77
[eradicate  ] created NetworkPolicy/soar-block-f425eca1 — blocked 10.0.0.77/32 in financial
```
> 📁 **Nguồn:** `curl -s http://localhost:18082/cases/<case-id>/log | python3 -m json.tool` — log 4 phase playbook `restrict_egress`

SOAR đồng thời scale core-banking xuống 0 (cắt nguồn dữ liệu) VÀ tạo NetworkPolicy block IP attacker trong namespace financial. Kẻ tấn công không thể tiếp tục kéo thêm dữ liệu.

```bash
kubectl --context ctx-openstack get deployment core-banking -n financial
# core-banking   0/0     0            0     ← đã scale=0
```

**📋 Log demo live — chạy theo thứ tự khi trình bày:**

**[1] Chạy 10 request bulk và đo bytes thực tế:**
```bash
bash tests/grafana_kb4_exfiltration.sh 2>&1 | grep -E "bytes|KB4"
```
```
[KB4] GET /transactions?account_id=ACC-1001&limit=500 → 2208 bytes
[KB4] GET /accounts/balance → 30 bytes
[KB4] GET /transactions?account_id=ACC-2001&limit=500 → 2208 bytes
[KB4] ▶ 10 request bulk data — tổng bytes nhận: 15546 bytes
```

**[2] Xem Envoy access log ghi bytes_sent (từ phía server):**
```bash
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=api-gateway -o jsonpath='{.items[0].metadata.name}') \
  -c envoy | grep transactions | tail -5
```
```json
{"timestamp":"2026-06-27T12:01:11Z","method":"GET","path":"/transactions?account_id=ACC-1001&limit=500","response_code":"200","bytes_sent":2208,"source_ip":"10.0.0.77"}
{"timestamp":"2026-06-27T12:01:12Z","method":"GET","path":"/transactions?account_id=ACC-2001&limit=500","response_code":"200","bytes_sent":2208,"source_ip":"10.0.0.77"}
```

**[3] Query Loki trực tiếp để thấy log bytes lớn (inject từ script):**
```bash
curl -s -G "http://localhost:13000/loki/api/v1/query" \
  --data-urlencode 'query={job="envoy-access",cloud="openstack"} | json | bytes_sent > 1048576' \
  -u admin:Admin1234! \
  | python3 -c "import sys,json; d=json.load(sys.stdin); [print(v[1]) for r in d.get('data',{}).get('result',[]) for v in r.get('values',[])]" \
  | head -3
```
```json
{"timestamp":"2026-06-27T12:01:15Z","method":"GET","path":"/transactions","response_code":"200","bytes_sent":3670016,"source_ip":"10.0.0.77","cloud":"openstack"}
```

**[4] Sau khi SOAR thực thi — xem NetworkPolicy được tạo:**
```bash
kubectl --context ctx-aws get networkpolicy -n financial
```
```
NAME                    POD-SELECTOR   AGE
soar-block-f425eca1     <none>         2m    ← chặn IP 10.0.0.77/32
```

**[5] Xem chi tiết NetworkPolicy block IP:**
```bash
kubectl --context ctx-aws describe networkpolicy soar-block-f425eca1 -n financial | grep -A5 "Ingress\|From"
```
```
Ingress:
  From:
    IPBlock:
      CIDR: 0.0.0.0/0
      Except: 10.0.0.77/32   ← IP attacker bị loại trừ khỏi mọi traffic
```

---

### KB5 — Access Denied Spike / OPA RBAC (T1078)

**Ý tưởng tấn công:** merchant01 có tài khoản hợp lệ nhưng chỉ được phép xem thông tin (financial-read). Kẻ tấn công dùng tài khoản này cố thực hiện giao dịch (financial-write) — "privilege abuse".

**Zero Trust ngăn chặn bằng cách nào:** *Least Privilege* — OPA deny-by-default RBAC. Không phải "có tài khoản là được làm mọi thứ", mà "được phép làm đúng những gì role cho phép, không hơn".

**Chạy kịch bản:**

```bash
bash tests/grafana_kb5_access_denied.sh
```

**Diễn biến từng bước:**

**① Script giải mã JWT của merchant01 để chứng minh role:**

```json
{
  "preferred_username": "merchant01",
  "realm_access": {
    "roles": ["financial-read"]   ← chỉ có đây, không có financial-write
  }
}
```
> 📁 **Nguồn:** script tự decode JWT trong `tests/grafana_kb5_access_denied.sh` — lệnh thủ công: `echo $TOKEN_MERCHANT | cut -d. -f2 | base64 -d | python3 -m json.tool | grep -A5 realm_access`

```
[KB5] merchant01 roles: ['financial-read']  ← chỉ có financial-read, không có financial-write
```
> 📁 **Nguồn:** output của `bash tests/grafana_kb5_access_denied.sh`

**② Merchant01 thử POST /payments 6 lần:**

OPA evaluate mỗi request: `permissions["financial-read"]["POST"]` không tồn tại → `role_permits_action = false` → `allow = false`.

```
POST /payments amount=100000  → HTTP 403
POST /payments amount=50000   → HTTP 403
POST /payments amount=200000  → HTTP 403
POST /payments amount=75000   → HTTP 403
POST /payments amount=1000000 → HTTP 403
POST /payments amount=5000    → HTTP 403
▶ OPA RBAC từ chối 6/6 request
```
> 📁 **Nguồn:** output của `bash tests/grafana_kb5_access_denied.sh` — HTTP status code lấy bằng `curl -o /dev/null -w "%{http_code}"` — OPA log tương ứng xem bằng `kubectl logs -n opa <opa-pod> | grep '"result":false'`

**③ So sánh trực tiếp:**

| Request | Role | Kết quả |
|---|---|---|
| merchant01 POST /payments | financial-read | HTTP 403 (OPA deny) |
| testuser01 POST /payments | financial-read + financial-write | HTTP 200 |

Cùng một endpoint, cùng JWT hợp lệ, kết quả khác nhau hoàn toàn chỉ vì khác role.

**④ SOAR — block_source_ip:**

```
[contain    ] created NetworkPolicy/soar-block-c9f8bbb9 — blocked 10.0.0.99/32 in financial
[investigate] Loki evidence: 10 log entries matched query for access_denied from 10.0.0.99
[eradicate  ] IP 10.0.0.99 already blocked in contain phase
```
> 📁 **Nguồn:** `curl -s http://localhost:18082/cases/<case-id>/log | python3 -m json.tool` — playbook `block_source_ip`

IP bị ghi vào Redis với TTL 86,400 giây (24 giờ). api-gateway kiểm tra Redis key `ztlab:blocked_ip:10.0.0.99` trước mỗi request — nếu tồn tại → từ chối ngay, không cần xử lý thêm.

```bash
curl -s http://localhost:8091/blocked-ips
{
  "blocked_ips": [{
    "ip": "10.0.0.99",
    "reason": "SOAR: access_denied via block_source_ip",
    "ttl_seconds": 86400
  }]
}
```

**📋 Log demo live — chạy theo thứ tự khi trình bày:**

**[1] Lấy JWT của merchant01 và xác nhận role chỉ có financial-read:**
```bash
TOKEN_MERCHANT=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "client_id=web-portal&grant_type=password&username=merchant01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo $TOKEN_MERCHANT | cut -d. -f2 | base64 -d 2>/dev/null \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Roles:', d['realm_access']['roles'])"
```
```
Roles: ['financial-read']
```

**[2] Merchant01 cố POST /payments — xem từng lần bị 403:**
```bash
for amount in 100000 50000 200000; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:18080/payments \
    -H "Authorization: Bearer $TOKEN_MERCHANT" \
    -H "Content-Type: application/json" \
    -d "{\"from_account\":\"ACC-1001\",\"to_account\":\"ACC-9999\",\"amount\":$amount}")
  echo "POST /payments amount=$amount → HTTP $STATUS"
done
```
```
POST /payments amount=100000 → HTTP 403
POST /payments amount=50000  → HTTP 403
POST /payments amount=200000 → HTTP 403
```

**[3] Xem OPA log — thấy merchant01 bị deny do thiếu financial-write:**
```bash
kubectl --context ctx-aws logs -n opa \
  $(kubectl --context ctx-aws get pod -n opa -l app=opa -o jsonpath='{.items[0].metadata.name}') \
  | grep '"result":false' | tail -3
```
```json
{"result":false,"path":"zta/authz/allow","input":{"request":{"http":{"method":"POST","path":"/payments"}},"jwt_roles":["financial-read"]},"metrics":{"timer_rego_query_eval_ns":189234}}
```

**[4] So sánh — testuser01 (có financial-write) cùng endpoint thì được:**
```bash
TOKEN_USER=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -o /dev/null -w "HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN_USER" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":10000}'
```
```
HTTP 200   ← cùng endpoint, khác role → kết quả hoàn toàn khác
```

**[5] Sau SOAR — xem IP bị block trong Redis:**
```bash
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=redis -o jsonpath='{.items[0].metadata.name}') \
  -- redis-cli KEYS "ztlab:blocked_ip:*"
```
```
1) "ztlab:blocked_ip:10.0.0.99"
```

**[6] Kiểm tra TTL còn lại:**
```bash
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=redis -o jsonpath='{.items[0].metadata.name}') \
  -- redis-cli TTL "ztlab:blocked_ip:10.0.0.99"
```
```
(integer) 86352   ← còn ~23.98 giờ, đếm ngược tự động
```

---

### KB6 — Privilege Escalation in Container (T1611)

**Ý tưởng tấn công:** Kẻ tấn công đã vào được bên trong container (ví dụ qua code injection). Container đang chạy với quyền root (uid=0) và có nhiều capabilities nguy hiểm — kẻ tấn công có thể leo thang đặc quyền, đọc file nhạy cảm, thậm chí thoát ra host.

**Zero Trust ngăn chặn bằng cách nào:** *Workload Isolation + Least Privilege cho container* — Zero Trust không chỉ áp dụng cho network traffic, mà cả bên trong từng container. Container không nên chạy với quyền root. Đây là vi phạm thật trong lab — được phát hiện và cách ly.

**Chạy kịch bản:**

```bash
bash tests/grafana_kb6_privilege_escalation.sh
```

**Diễn biến từng bước:**

**① Audit thủ công — chứng minh vi phạm thật:**

```bash
kubectl --context ctx-aws exec -n financial api-gateway-665bb949bd-n6zsh -- id
→ uid=0(root) gid=0(root) groups=0(root)

kubectl ... -- cat /proc/1/status | grep CapEff
→ CapEff: 00000000a80425fb

kubectl ... -- head -3 /etc/shadow
→ root:*:20549:0:99999:7:::
→ daemon:*:20549:0:99999:7:::   ← ĐỌC ĐƯỢC /etc/shadow!

kubectl ... -- get pod -o jsonpath='{.spec.containers[0].securityContext}'
→ {}   ← securityContext hoàn toàn rỗng, không có hardening nào
```
> 📁 **Nguồn:** chạy trực tiếp từng lệnh trên pod đang live — thay `api-gateway-665bb949bd-n6zsh` bằng pod name thực tế lấy từ `kubectl --context ctx-aws get pod -n financial -l app=api-gateway`

**② Giải mã capabilities hex `a80425fb`:**

```
DANGEROUS capabilities phát hiện:
  CAP_DAC_OVERRIDE (bit 1)  → bypass mọi file permission → đọc được /etc/shadow
  CAP_SETUID (bit 7)        → có thể đổi uid về 0 bất kỳ lúc nào
```

So sánh với container đúng chuẩn Zero Trust:
```
CapEff: 0000000000000000   ← không có capability nào
uid=1000 (non-root)        ← chạy với user thường
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  capabilities: {drop: [ALL]}
```

**③ Script output:**

```
[KB6] ▶ VI PHẠM Zero Trust workload isolation xác nhận:
[KB6]   • Pod chạy root (uid=0) — vi phạm least-privilege principle
[KB6]   • CAP_DAC_OVERRIDE đọc được /etc/shadow — leo thang đặc quyền thực tế
[KB6]   • runAsNonRoot không được set — container không bị ràng buộc
```
> 📁 **Nguồn:** output của `bash tests/grafana_kb6_privilege_escalation.sh` — script tự chạy các lệnh kubectl exec audit và tổng hợp kết quả

**④ SOAR — quarantine_workload:**

Đây là playbook cứng nhất: api-gateway bị scale về 0 để forensics.

```
[contain] scaled Deployment/api-gateway from 1 → 0 replicas (suspected cryptomining/compromise)
```
> 📁 **Nguồn:** `curl -s http://localhost:18082/cases/<case-id>/log` — playbook `quarantine_workload`, phase `contain`

```bash
kubectl --context ctx-aws get deployment api-gateway -n financial
# api-gateway   0/0     0            0     ← toàn bộ hệ thống ngừng nhận request
```

Sau demo phải restore ngay:
```bash
bash scripts/run-demo.sh --restore
```

**📋 Log demo live — chạy theo thứ tự khi trình bày:**

**[1] Lấy pod name của api-gateway đang chạy:**
```bash
kubectl --context ctx-aws get pod -n financial -l app=api-gateway
```
```
NAME                          READY   STATUS    RESTARTS   AGE
api-gateway-665bb949bd-n6zsh  2/2     Running   0          2h
```

**[2] Kiểm tra đang chạy với uid=0 (root) — vi phạm thật:**
```bash
kubectl --context ctx-aws exec -n financial api-gateway-665bb949bd-n6zsh -- id
```
```
uid=0(root) gid=0(root) groups=0(root)
```

**[3] Xem capabilities nguy hiểm:**
```bash
kubectl --context ctx-aws exec -n financial api-gateway-665bb949bd-n6zsh \
  -- cat /proc/1/status | grep CapEff
```
```
CapEff: 00000000a80425fb
```

**[4] Chứng minh leo thang được thực tế — đọc /etc/shadow:**
```bash
kubectl --context ctx-aws exec -n financial api-gateway-665bb949bd-n6zsh \
  -- head -2 /etc/shadow
```
```
root:*:20549:0:99999:7:::
daemon:*:20549:0:99999:7:::
```

**[5] Xác nhận securityContext rỗng — không có cấu hình hardening:**
```bash
kubectl --context ctx-aws get pod api-gateway-665bb949bd-n6zsh -n financial \
  -o jsonpath='{.spec.containers[0].securityContext}' | python3 -m json.tool
```
```
{}
```

**[6] Sau SOAR — api-gateway bị scale=0 để forensics:**
```bash
kubectl --context ctx-aws get deployment api-gateway -n financial
```
```
NAME          READY   UP-TO-DATE   AVAILABLE
api-gateway   0/0     0            0
```

**[7] Xem SOAR case log đầy đủ:**
```bash
CASE_ID=$(curl -s http://localhost:18082/cases | python3 -c "
import sys,json; cases=json.load(sys.stdin)
priv=[c for c in cases if c.get('attack_type')=='privilege_escalation']
print(priv[-1]['case_id'] if priv else 'no-case')")

curl -s http://localhost:18082/cases/$CASE_ID | python3 -m json.tool | grep -E '"phase"|"action"|"result"|"status"'
```
```json
"status": "executed",
"phase": "contain",
"action": "scaled Deployment/api-gateway from 1 → 0 replicas",
"phase": "investigate",
"result": "found privilege_escalation indicators: uid=0, CapEff=a80425fb, /etc/shadow readable"
```

**[8] Restore sau demo:**
```bash
bash scripts/run-demo.sh --restore
kubectl --context ctx-aws get deployment -n financial
```
```
NAME              READY   UP-TO-DATE   AVAILABLE
api-gateway       1/1     1            1
payment-service   1/1     1            1
fraud-detection   1/1     1            1
```

---

## V. Luồng SOAR Human-in-the-Loop (HITL)

HITL là cơ chế đảm bảo không có hành động cứng (scale=0, block IP) nào được thực thi tự động mà không có con người phê duyệt. Quy trình:

```
Grafana phát hiện → SOAR tạo case (pending) → Email cảnh báo → Admin xem xét → Phê duyệt → Thực thi
```

**Vòng đời một case:**

| Giai đoạn | Trạng thái | Màu sắc trên UI | Hành động |
|---|---|---|---|
| Vừa tạo | `pending_approval` | Vàng ⏳ | Chờ admin |
| Đang xử lý | `executing` | Xanh đang nhấp nháy | SOAR đang chạy playbook |
| Hoàn thành | `executed` | Đỏ ✓ | Đã thực thi xong |
| Bị từ chối | `denied` | Xám ✗ | Admin quyết định không can thiệp |
| Đã rollback | `rolled_back` | Tím ↩ | Đã khôi phục về trạng thái ban đầu |

**5 playbook có sẵn:**

| Playbook | Hành động K8s | Dùng cho |
|---|---|---|
| `revoke_user_sessions` | Keycloak Admin API DELETE /sessions | KB1 — Brute Force |
| `isolate_workload` | scale deployment = 0 | KB2 — Fraud Gate, KB3 — Lateral Move |
| `restrict_egress` | scale core-banking = 0 + NetworkPolicy | KB4 — Exfiltration |
| `block_source_ip` | Redis TTL 24h + NetworkPolicy | KB5 — Access Denied |
| `quarantine_workload` | scale deployment = 0 (cứng) | KB6 — Privilege Escalation |

---

## VI. Tổng Hợp Kết Quả Demo

| KB | Tên kịch bản | MITRE | Bằng chứng thật | Phản ứng SOAR |
|---|---|---|---|---|
| KB1 | Brute Force Login | T1110.001 | 20/20 lần bị Keycloak từ chối HTTP 401 | revoke_user_sessions |
| KB2 | Fraud Gate Bypass | T1078.004 | HTTP 403, fraud score=75, reason=critical_amount+risky_channel | isolate_workload (payment-service scale=0) |
| KB3 | Lateral Movement | T1021.007 | SVID fake → HTTP 403, log OPA deny | isolate_workload |
| KB4 | Data Exfiltration | T1041 | 15,546 bytes đo thực từ 10 request | restrict_egress (core-banking scale=0) |
| KB5 | Access Denied Spike | T1078 | merchant01 HTTP 403 × 6 lần (OPA RBAC deny) | block_source_ip (Redis 24h + NetworkPolicy) |
| KB6 | Privilege Escalation | T1611 | uid=0, CapEff=0xa80425fb, /etc/shadow readable | quarantine_workload (api-gateway scale=0) |

**Kết quả toàn bộ 6 kịch bản chạy liên tiếp:**

```
PASS  KB1  Brute Force (T1110.001)
PASS  KB2  Fraud Gate Bypass (T1078.004)
PASS  KB3  Lateral Movement (T1021.007)
PASS  KB4  Data Exfiltration (T1041)
PASS  KB5  Access Denied Spike (T1078)
PASS  KB6  Privilege Escalation (T1611)

PASS=6  FAIL=0  SKIP=0
```
> 📁 **Nguồn:** output của `bash tests/run-all-kb.sh` (chạy tuần tự KB1→KB6) — hoặc chạy riêng từng script trong `tests/grafana_kb*.sh`

---

## VII. Những Điểm Cần Lưu Ý Khi Demo

**1. Dedup 5 phút:** Nếu chạy cùng kịch bản hai lần trong 5 phút, case thứ hai sẽ bị SOAR báo `deduped` — đây là hoạt động đúng, không phải lỗi.

**2. Restore bắt buộc sau mỗi kịch bản:**
```bash
bash scripts/run-demo.sh --restore
```
Đặc biệt sau KB6 — api-gateway bị scale=0, toàn bộ hệ thống không nhận được request nào nữa.

**3. HTTP 503 thay vì 200:** Nếu payment bình thường trả 503, nghĩa là payment-service đang bị cô lập từ KB2 trước đó chưa restore.

**4. Grafana alert fire sau ~1 phút:** Script inject log xong → Grafana evaluate mỗi 1 phút → case xuất hiện trên Web Portal sau tối đa 1 phút. Không cần refresh thủ công.

**5. OpenStack tunnel down:** Nếu core-banking không kết nối được (payment trả timeout), chỉ cần `bash scripts/k8s-tunnel.sh up all` để bật lại WireGuard tunnel.

---

## VIII. Cách Lấy Log và Code Được Đề Cập Trong Báo Cáo

Phần này hướng dẫn cách tự tay lấy từng loại log hoặc đoạn code xuất hiện trong báo cáo — để kiểm chứng hoặc trình bày live.

---

### 8.1 Log Keycloak — Sự Kiện Đăng Nhập (KB1)

**Lấy từ:** pod Keycloak trên namespace `identity`

```bash
# Xem log đăng nhập thất bại (brute force)
kubectl --context ctx-aws logs -n identity \
  $(kubectl --context ctx-aws get pod -n identity -l app=keycloak -o jsonpath='{.items[0].metadata.name}') \
  | grep LOGIN_ERROR | tail -20

# Xem log đăng nhập thành công
kubectl --context ctx-aws logs -n identity \
  $(kubectl --context ctx-aws get pod -n identity -l app=keycloak -o jsonpath='{.items[0].metadata.name}') \
  | grep '"type":"LOGIN"' | tail -10
```

**Kết quả trông như thế nào:**
```
WARN [org.keycloak.events]
  type="LOGIN_ERROR"
  error="invalid_user_credentials"
  username="testuser01"
  ipAddress="127.0.0.1"
```

---

### 8.2 JWT — Giải Mã Xem Role Người Dùng

**JWT là gì:** Chuỗi base64 gồm 3 phần cách nhau bởi dấu `.`. Phần giữa (payload) chứa role và metadata — giải mã không cần key.

**Lấy JWT thực tế:**
```bash
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "client_id=web-portal&grant_type=password&username=testuser01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo $TOKEN
```

**Giải mã phần payload (không cần key):**
```bash
# Lấy phần giữa (index 1), base64 decode
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**Output:**
```json
{
  "preferred_username": "testuser01",
  "realm_access": {
    "roles": ["financial-read", "financial-write"]
  },
  "iss": "http://keycloak.ztlab.local:8180/realms/ztlab",
  "exp": 1782555600
}
```

**So sánh merchant01 (chỉ có financial-read):**
```bash
TOKEN_MERCHANT=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "client_id=web-portal&grant_type=password&username=merchant01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo $TOKEN_MERCHANT | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool | grep -A5 realm_access
```

---

### 8.3 Log Envoy Sidecar — Access Log Mỗi Request

**Lấy từ:** container `envoy` (container thứ 2) trong pod của từng service

```bash
# Log access Envoy của api-gateway (JSON, mỗi dòng 1 request)
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=api-gateway -o jsonpath='{.items[0].metadata.name}') \
  -c envoy --tail=20

# Lọc chỉ lấy request bị từ chối (HTTP 401, 403)
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=api-gateway -o jsonpath='{.items[0].metadata.name}') \
  -c envoy | grep '"response_code":"40'

# Lọc theo path cụ thể
kubectl --context ctx-aws logs -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=payment-service -o jsonpath='{.items[0].metadata.name}') \
  -c envoy | grep /payments | tail -10
```

**Một dòng log JSON trông như thế này:**
```json
{
  "timestamp": "2026-06-27T11:43:37Z",
  "method": "POST",
  "path": "/payments",
  "response_code": 200,
  "response_time": 3,
  "source_ip": "10.42.0.1",
  "bytes_sent": 74,
  "svid": "spiffe://ztlab.local/aws/api-gateway"
}
```

Trường `svid` chứng minh caller là ai (identity mật mã từ SPIRE — không thể giả mạo).

---

### 8.4 Log OPA — Quyết Định Cho Phép / Từ Chối

**Lấy từ:** pod opa-server trên namespace `opa`

```bash
# Xem tất cả quyết định OPA gần nhất
kubectl --context ctx-aws logs -n opa \
  $(kubectl --context ctx-aws get pod -n opa -l app=opa -o jsonpath='{.items[0].metadata.name}') \
  | grep '"result"' | tail -20

# Chỉ lấy các quyết định TỪ CHỐI (result: false)
kubectl --context ctx-aws logs -n opa \
  $(kubectl --context ctx-aws get pod -n opa -l app=opa -o jsonpath='{.items[0].metadata.name}') \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if d.get('result') == False:
            print(json.dumps(d, indent=2))
    except: pass
" | head -40
```

**Log OPA từ chối trông như thế này:**
```json
{
  "result": false,
  "path": "zta/authz/allow",
  "input": {
    "request": {"http": {"path": "/transactions/execute", "method": "POST"}},
    "x-spiffe-id": "spiffe://evil.corp/attacker"
  },
  "metrics": {"timer_rego_query_eval_ns": 251982}
}
```

**Xem policy Rego đang chạy:**
```bash
cat opa/policies/zta_policy.rego
```

---

### 8.5 SPIRE — Chứng Chỉ Đang Hoạt Động

**Xem SVID của từng workload qua SPIRE Agent:**
```bash
# Liệt kê tất cả SVID đang được cấp
kubectl --context ctx-aws exec -n spire \
  $(kubectl --context ctx-aws get pod -n spire -l app=spire-agent -o jsonpath='{.items[0].metadata.name}') \
  -- /opt/spire/bin/spire-agent api fetch x509 \
  -socketPath /run/spire/sockets/agent.sock 2>&1 | grep "SPIFFE ID"
```

**Xem log SPIRE Server (gia hạn chứng chỉ, re-attest):**
```bash
kubectl --context ctx-aws logs -n spire \
  $(kubectl --context ctx-aws get pod -n spire -l app=spire-server -o jsonpath='{.items[0].metadata.name}') \
  | grep -E "Renewing|reattested|Registered" | tail -15
```

**Output gia hạn tự động mỗi ~30 phút:**
```
msg="Renewing X509-SVID"
  spiffe_id="spiffe://ztlab.local/aws/payment-service"
  expires_at="2026-06-27T12:43:16Z"
```

---

### 8.6 Loki — Query Log Trực Tiếp (Grafana / curl)

**Xem qua Grafana UI (cách dễ nhất):**
- Vào http://localhost:13000 → admin/Admin1234!
- Explore → Data source: Loki
- Nhập LogQL query vào ô query

**Các query quan trọng:**

```logql
# Tất cả access log Envoy trong 1 giờ qua
{job="envoy-access"} | json | line_format "{{.timestamp}} {{.method}} {{.path}} → {{.response_code}}"

# Chỉ HTTP 401 (brute force)
{job="envoy-access"} | json | response_code=`401`

# OPA deny
{job="opa-decisions"} | json | result=`false`

# Fraud gate bypass (OPA deny tại /transactions/execute)
{job="opa-decisions", opa_result="false"} | json | request_path=`/transactions/execute`

# Data exfiltration — response > 1MB từ OpenStack
{job="envoy-access", cloud="openstack"} | json | bytes_sent > 1048576
```

**Query bằng curl (không cần mở browser):**
```bash
# Ví dụ: lấy 5 log OPA deny gần nhất
curl -s -G "http://localhost:13000/loki/api/v1/query_range" \
  --data-urlencode 'query={job="opa-decisions"} | json | result=`false`' \
  --data-urlencode "start=$(date -d '1 hour ago' +%s)000000000" \
  --data-urlencode "end=$(date +%s)000000000" \
  --data-urlencode "limit=5" \
  -u admin:Admin1234! \
  | python3 -m json.tool | grep '"line"' | head -10
```

---

### 8.7 SOAR — Xem Case và Trạng Thái

**API SOAR (không cần auth):**
```bash
# Danh sách tất cả case
curl -s http://localhost:18082/cases | python3 -m json.tool

# Case mới nhất
curl -s http://localhost:18082/cases | python3 -c "
import sys, json
cases = json.load(sys.stdin)
if cases:
    print(json.dumps(cases[-1], indent=2))
"

# Xem chi tiết case theo ID
curl -s http://localhost:18082/cases/case-20260627041323-kb1-17 | python3 -m json.tool

# Xem playbook log của một case
curl -s http://localhost:18082/cases/case-20260627041323-kb1-17/log | python3 -m json.tool
```

**Web Portal (có giao diện trực quan):**
```
http://localhost:18081/security
Login: analyst01 / Test1234!
```

**File case lưu trên disk (persistent qua restart):**
```bash
kubectl --context ctx-aws exec -n security \
  $(kubectl --context ctx-aws get pod -n security -l app=soar-engine -o jsonpath='{.items[0].metadata.name}') \
  -- tail -5 /data/cases.jsonl | python3 -m json.tool
```

---

### 8.8 Redis — IP Bị Block và Velocity Counter

**Xem IP đang bị block (KB5):**
```bash
# Qua API SOAR
curl -s http://localhost:8091/blocked-ips | python3 -m json.tool

# Trực tiếp trong Redis
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=redis -o jsonpath='{.items[0].metadata.name}') \
  -- redis-cli KEYS "ztlab:blocked_ip:*"

# Xem TTL còn lại của một IP bị block
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=redis -o jsonpath='{.items[0].metadata.name}') \
  -- redis-cli TTL "ztlab:blocked_ip:10.0.0.99"
# → 85234 (giây còn lại, tương đương ~23.7 giờ)
```

**Xem velocity counter (KB2 — fraud detection):**
```bash
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=redis -o jsonpath='{.items[0].metadata.name}') \
  -- redis-cli KEYS "ztlab:velocity:*"
```

---

### 8.9 Fraud Detection — Score Thực Tế Của Một Request

Gọi trực tiếp service (không qua api-gateway, để test thuần logic):
```bash
# Giao dịch bình thường — score thấp
curl -s -X POST http://localhost:18083/score \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":10000,"channel":"api","source_ip":"10.0.0.1"}' \
  | python3 -m json.tool

# Giao dịch rủi ro cao — 500M + TOR
curl -s -X POST http://localhost:18083/score \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":500000000,"channel":"tor","source_ip":"10.0.0.1"}' \
  | python3 -m json.tool
```

**Output giao dịch rủi ro:**
```json
{
  "score": 75,
  "verdict": "block",
  "gate": "blocked",
  "reason": ["critical_amount", "risky_channel"],
  "details": {
    "base": 5,
    "amount_penalty": 55,
    "channel_penalty": 15,
    "velocity_penalty": 0
  }
}
```

---

### 8.10 Kubernetes — Trạng Thái Deployment Sau SOAR

**Xem toàn bộ deployment trong namespace financial:**
```bash
# AWS cluster
kubectl --context ctx-aws get deployment -n financial
kubectl --context ctx-aws get pod -n financial

# OpenStack cluster
kubectl --context ctx-openstack get deployment -n financial
```

**Xem NetworkPolicy đã được tạo bởi SOAR:**
```bash
kubectl --context ctx-aws get networkpolicy -n financial
# NAME                        POD-SELECTOR   AGE
# soar-block-c9f8bbb9         <none>         5m    ← KB5: block IP attacker
# soar-block-f425eca1         <none>         3m    ← KB4: restrict egress
```

**Xem chi tiết một NetworkPolicy:**
```bash
kubectl --context ctx-aws describe networkpolicy soar-block-c9f8bbb9 -n financial
```

**Sau khi restore — xác nhận deployment trở về 1 replica:**
```bash
bash scripts/run-demo.sh --restore
kubectl --context ctx-aws get deployment -n financial
# api-gateway       1/1     1            1
# payment-service   1/1     1            1
# fraud-detection   1/1     1            1
```

---

### Tóm Tắt Nhanh — Lệnh Xem Log Theo Kịch Bản

| Kịch bản | Loại log | Lệnh nhanh |
|---|---|---|
| KB1 — Brute Force | Keycloak event | `kubectl logs -n identity <keycloak-pod> \| grep LOGIN_ERROR` |
| KB2 — Fraud Gate | Fraud score | `curl localhost:18083/score -d '{"amount":500000000,"channel":"tor",...}'` |
| KB3 — Lateral Move | OPA deny | `kubectl logs -n opa <opa-pod> \| grep '"result":false'` |
| KB4 — Exfiltration | Envoy bytes | `kubectl logs -n financial <pod> -c envoy \| grep bytes_sent` |
| KB5 — Access Denied | Redis block | `curl localhost:8091/blocked-ips` |
| KB6 — Privilege Esc | Pod security | `kubectl exec -n financial <pod> -- id && cat /proc/1/status \| grep CapEff` |
| Tất cả | SOAR case | `curl localhost:18082/cases \| python3 -m json.tool` |
| Tất cả | Loki query | Grafana → Explore → LogQL query |

---

*Tài liệu tổng hợp từ config thực tế và log live capture ngày 2026-06-27. Chi tiết kỹ thuật xem tại `DEMO_FLOW_CHITIET.md`.*
