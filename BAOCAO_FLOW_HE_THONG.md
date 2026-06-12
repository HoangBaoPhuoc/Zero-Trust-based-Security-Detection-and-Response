# Báo cáo flow hệ thống ZTLab hiện tại

Tài liệu này mô tả theo đúng code và manifest hiện tại trong repo. Trọng tâm là giải thích rõ **gateway là gì**, **input/output tại từng điểm**, request đi qua đâu, và luồng log - phát hiện - phản ứng hoạt động như thế nào.

Trong hệ thống này có 3 lớp "gateway" cần phân biệt:

- **Infrastructure Gateway**: lớp hạ tầng đưa traffic từ người dùng vào cluster AWS và nối AWS với OpenStack.
- **API Gateway**: service `api-gateway` trong namespace `financial`, là cửa vào nghiệp vụ cho các API tài chính.
- **Envoy Gateway/Sidecar**: proxy nằm cạnh workload, là điểm chặn và kiểm soát request bằng OPA + mTLS/SPIRE.

## 1. Tổng quan kiến trúc hiện tại

Hệ thống chạy trên mô hình multi-cloud:

- **AWS K3s cluster**: chạy các service phía ngoài và các thành phần quan sát/phản ứng:
  - `web-portal`
  - `api-gateway`
  - `payment-service`
  - `fraud-detection`
  - `notification-service`
  - `keycloak`
  - `opa-service`
  - `loki`, `grafana`, `ai-analyzer`, `soar-engine`, `thehive`
- **OpenStack K3s cluster**: chạy các service lõi nội bộ:
  - `core-banking`
  - `account-service`
  - `transaction-service`
  - `postgres-accounts`
  - `postgres-txn`
- **Kết nối AWS - OpenStack**:
  - AWS gọi sang OpenStack qua IP `10.10.1.12`.
  - `core-banking` trên OpenStack expose NodePort `30081` vào Envoy inbound `15006`.
  - Envoy phía AWS route các path `/transactions` và `/accounts` đến cluster `core_banking` tại `10.10.1.12:30081`.

Sơ đồ rút gọn:

```text
Browser
  -> Traefik Ingress AWS
  -> web-portal hoặc api-gateway
  -> api-gateway
  -> Envoy sidecar + OPA
  -> payment-service
  -> Envoy sidecar + OPA
  -> fraud-detection
  -> payment-service
  -> Envoy mTLS cross-cloud
  -> core-banking trên OpenStack
  -> account-service + transaction-service
  -> response quay ngược về Browser
```

## 2. Gateway là gì trong hệ thống này

### 2.1 Infrastructure Gateway

Đây là lớp hạ tầng đưa traffic vào hệ thống.

**Thành phần chính:**

- **Bastion/SSH tunnel**: người vận hành mở tunnel về AWS, sau đó truy cập các domain nội bộ như `api.ztlab.local`, `portal.ztlab.local`, `grafana.ztlab.local`.
- **Traefik Ingress**: route theo Host header:
  - `api.ztlab.local` -> service `api-gateway:8080`
  - `portal.ztlab.local` -> service `web-portal:8080`
  - `grafana.ztlab.local` -> service `grafana:3000`
  - `keycloak.ztlab.local` -> service `keycloak:8080`
  - `ai.ztlab.local` -> service `ai-analyzer:8080`
  - `soar.ztlab.local` -> service `soar-engine:8080`
- **WireGuard/private network**: tạo đường nối AWS - OpenStack để AWS có thể gọi `10.10.1.12:30081`.

**Input:** HTTP từ browser/curl hoặc traffic nội bộ đi qua VPN.

**Output:** request đã được route vào đúng Kubernetes Service/namespace.

### 2.2 API Gateway

`api-gateway` là gateway nghiệp vụ của ứng dụng tài chính. Nó không chỉ forward request, mà còn thực hiện các bước kiểm soát ở mức người dùng:

- Nhận request từ Web Portal hoặc client trực tiếp.
- Kiểm tra rate limit theo source IP, mặc định `60 request/phút`.
- Kiểm tra JWT:
  - Ưu tiên verify RS256 bằng JWKS của Keycloak.
  - Có fallback HS256 dev token bằng `JWT_DEV_SECRET`.
- Kiểm tra role:
  - `POST /payments` cần role `financial-write`.
  - `GET /accounts/{account_id}` và `GET /transactions` cần role `financial-read`.
- Tạo hoặc truyền tiếp `X-Trace-ID`.
- Forward sang `payment-service` thông qua Envoy local outbound `127.0.0.1:15001`.

**Input mẫu vào API Gateway:**

```http
POST /payments
Authorization: Bearer <access_token>
Content-Type: application/json
X-Trace-ID: <optional>

{
  "from_account": "ACC-1001",
  "to_account": "ACC-2001",
  "amount": 100000,
  "currency": "VND",
  "channel": "api",
  "country": "VN"
}
```

**Output thành công:**

```json
{
  "status": "completed",
  "trace_id": "<uuid>",
  "fraud": {
    "score": 5,
    "verdict": "allow",
    "reason": ["baseline"],
    "gate": "passed"
  },
  "core_banking": {
    "transaction_id": "<uuid>",
    "status": "completed",
    "trace_id": "<uuid>",
    "from_balance": 999900000,
    "to_balance": 250100000
  }
}
```

**Output lỗi có thể gặp:**

- `401 missing bearer token`: không có `Authorization: Bearer`.
- `401 invalid token`: token sai chữ ký, sai issuer hoặc hết hạn.
- `403 role 'financial-write' required`: token hợp lệ nhưng không có quyền ghi.
- `429 rate limit exceeded`: vượt giới hạn theo source IP.
- `503 payment service unavailable`: gateway không gọi được downstream.

### 2.3 Envoy Gateway/Sidecar

Envoy là gateway cục bộ của từng workload có sidecar. Đây là **Policy Enforcement Point** trong kiến trúc Zero Trust.

Trong manifest Kubernetes, các service có sidecar thường expose service port `8080` nhưng `targetPort` là `15006`. Nghĩa là request đi vào pod sẽ vào Envoy trước, không đi thẳng vào app.

Envoy làm các việc chính:

- Nhận request inbound ở port `15006`.
- Gọi OPA ext_authz qua gRPC đến `opa-service.financial.svc.cluster.local:9191`.
- Nếu OPA allow, forward request vào app local `127.0.0.1:8080`.
- Nếu app cần gọi service khác, app gọi `127.0.0.1:15001`; Envoy outbound route theo path:
  - `/payments` -> `payment-service`
  - `/score` -> `fraud-detection`
  - `/notify` -> `notification-service`
  - `/transactions` -> `core-banking`
  - `/accounts` -> `core-banking`
- Dùng SPIRE SDS lấy certificate SVID để thực hiện mTLS service-to-service.

**Input của Envoy inbound:**

- HTTP plain từ Ingress hoặc service nội bộ.
- Hoặc HTTP qua mTLS từ Envoy sidecar khác.
- Header quan trọng: `Authorization`, `X-Trace-ID`, `X-Fraud-Gate`, `X-Fraud-Score`.
- Peer principal nếu có mTLS: `spiffe://ztlab.local/...`.

**Output của Envoy inbound:**

- Allow -> forward vào app local port `8080`.
- Deny -> trả HTTP deny từ ext_authz, không cho request vào app.
- Ghi access log JSON gồm method, path, response_code, duration, upstream, source_ip, trace_id, svid.

## 3. Flow đăng nhập Web Portal

Mục đích của flow này là lấy JWT hợp lệ từ Keycloak để gọi API Gateway.

```text
Browser
  -> GET /login trên web-portal
  -> POST /auth/login username/password
  -> web-portal POST Keycloak token endpoint
  -> Keycloak trả access_token + refresh_token
  -> web-portal tạo session cookie ztlab_session
  -> Browser vào /dashboard, /transfer, /logs, /alerts
```

**Input tại `web-portal /auth/login`:**

```http
POST /auth/login
Content-Type: application/x-www-form-urlencoded

username=testuser01&password=Test1234!
```

**Web Portal gọi Keycloak:**

```text
POST /realms/ztlab/protocol/openid-connect/token
grant_type=password
client_id=web-portal
username=<user>
password=<password>
```

**Output thành công:**

- Keycloak trả JSON token.
- Web Portal decode access token để lấy:
  - `preferred_username`
  - `realm_access.roles`
- Web Portal lưu cookie `ztlab_session` có:
  - username
  - access_token
  - refresh_token
  - roles
  - account_id map theo user

Các user/role chính đang có trong Keycloak:

- `testuser01`: `financial-read`, `financial-write`
- `merchant01`: `financial-read`
- `analyst01`: `security-analyst`

## 4. Flow chuyển tiền chuẩn

Đây là flow nghiệp vụ quan trọng nhất của hệ thống.

### 4.1 Bước 1: Browser/Web Portal gửi yêu cầu chuyển tiền

Người dùng thao tác trên trang `/transfer`. Frontend gọi:

```http
POST /api/transfer
Cookie: ztlab_session=<signed-session>
Content-Type: application/json

{
  "from_account": "ACC-1001",
  "to_account": "ACC-2001",
  "amount": 100000,
  "currency": "VND",
  "channel": "api"
}
```

Web Portal lấy `access_token` trong session và gọi API Gateway:

```http
POST http://api-gateway.financial.svc.cluster.local:8080/payments
Authorization: Bearer <access_token>
Content-Type: application/json

{ payment body }
```

Output của Web Portal là JSON từ API Gateway, giữ nguyên status code downstream.

### 4.2 Bước 2: API Gateway kiểm tra request

API Gateway nhận `POST /payments` và thực hiện:

1. Lấy source IP từ `X-Forwarded-For` hoặc client socket.
2. Kiểm tra rate limit.
3. Verify JWT.
4. Kiểm tra role `financial-write`.
5. Tạo `trace_id` nếu request chưa có `X-Trace-ID`.
6. Forward sang `PAYMENT_SERVICE_URL`, trong deployment hiện tại là `http://127.0.0.1:15001`.

Request API Gateway forward vào Payment Service:

```http
POST /payments
Authorization: Bearer <access_token>
X-Trace-ID: <uuid>
X-User-ID: <jwt-sub>
Content-Type: application/json

{ payment body }
```

Tại đây API Gateway là điểm chuyển request người dùng thành request nội bộ có trace và user context.

### 4.3 Bước 3: Envoy của API Gateway route sang Payment

`api-gateway` không gọi thẳng Kubernetes DNS của payment. Nó gọi local Envoy outbound:

```text
api-gateway app
  -> 127.0.0.1:15001/payments
  -> Envoy outbound
  -> payment-service.financial.svc.cluster.local:8080
  -> Kubernetes Service payment-service targetPort 15006
  -> Envoy inbound của payment-service
  -> OPA ext_authz
  -> app payment-service:8080
```

OPA allow vì request có SVID hợp lệ từ `spiffe://ztlab.local/aws/api-gateway` hoặc có Bearer token với path hợp lệ. Sau đó request mới đi vào app `payment-service`.

### 4.4 Bước 4: Payment Service kiểm tra giới hạn và gọi Fraud Detection

Payment Service nhận body:

```json
{
  "from_account": "ACC-1001",
  "to_account": "ACC-2001",
  "amount": 100000,
  "currency": "VND",
  "channel": "api",
  "country": "VN"
}
```

Payment xử lý:

1. Lấy `X-Trace-ID`.
2. Nếu `amount > MAX_SINGLE_TXN_VND` thì reject. Hiện tại `MAX_SINGLE_TXN_VND=500000000`.
3. Gọi Fraud Detection:

```http
POST /score
X-Trace-ID: <uuid>
Authorization: Bearer <access_token>
Content-Type: application/json

{ payment body }
```

Fraud Detection tính điểm:

- Điểm nền: `5`.
- Velocity theo Redis key `fraud:velocity:<from_account>`.
- `amount >= 100000000` cộng 30.
- `amount >= 500000000` cộng 55.
- Channel `tor`, `unknown`, `script` cộng 15.
- Country không thuộc `VN`, `SG`, `TH` cộng 10.

Output Fraud Detection khi giao dịch bình thường:

```json
{
  "score": 5,
  "verdict": "allow",
  "reason": ["baseline"],
  "gate": "passed"
}
```

Output khi bị chặn:

```json
{
  "score": 75,
  "verdict": "block",
  "reason": ["critical_amount", "risky_channel"],
  "gate": "blocked"
}
```

Payment Service chỉ đi tiếp nếu `gate == "passed"`. Nếu `gate == "blocked"`, Payment trả `403` với lý do fraud gate blocked.

### 4.5 Bước 5: Payment Service gọi Core Banking cross-cloud

Nếu fraud gate passed, Payment gọi Core Banking:

```http
POST /transactions/execute
X-Trace-ID: <uuid>
Authorization: Bearer <access_token>
X-Fraud-Gate: passed
X-Fraud-Score: <score>
Content-Type: application/json

{
  "from_account": "ACC-1001",
  "to_account": "ACC-2001",
  "amount": 100000,
  "currency": "VND",
  "trace_id": "<uuid>"
}
```

Đường đi mạng:

```text
payment-service app
  -> 127.0.0.1:15001/transactions/execute
  -> Envoy outbound route prefix /transactions
  -> core_banking cluster
  -> 10.10.1.12:30081
  -> OpenStack Service core-banking NodePort 30081
  -> Envoy inbound core-banking port 15006
  -> OPA ext_authz
  -> core-banking app port 8080
```

OPA/Core Banking chỉ chấp nhận khi:

- SVID hợp lệ bắt đầu bằng `spiffe://ztlab.local/`.
- Method là `POST`.
- Path bắt đầu `/transactions/execute`.
- Header `X-Fraud-Gate` bằng `passed`.
- Header `X-Fraud-Score` nhỏ hơn `75`.

Core Banking có thêm kiểm tra trong code:

- `fraud_gate != "passed"` -> reject.
- `fraud_score > MAX_ALLOWED_FRAUD_SCORE` -> reject.
- Hiện tại `MAX_ALLOWED_FRAUD_SCORE=74`.

Vì vậy fraud gate có 2 lớp: OPA chặn ở proxy và Core Banking tự kiểm lại ở tầng nghiệp vụ.

### 4.6 Bước 6: Core Banking cập nhật account và ledger

Core Banking không tự ghi DB trực tiếp. Nó điều phối 2 service nội bộ OpenStack.

**1. Gọi Account Service:**

```http
POST /accounts/transfer
X-Trace-ID: <uuid>
Content-Type: application/json

{
  "from_account": "ACC-1001",
  "to_account": "ACC-2001",
  "amount": 100000,
  "currency": "VND"
}
```

Account Service xử lý:

- Khóa 2 row account bằng `SELECT ... FOR UPDATE`.
- Kiểm tra account nguồn và account đích tồn tại.
- Kiểm tra currency.
- Kiểm tra số dư.
- Trừ tiền account nguồn, cộng tiền account đích.

Output:

```json
{
  "status": "applied",
  "from_balance": 999900000,
  "to_balance": 250100000
}
```

**2. Gọi Transaction Service:**

```http
POST /transactions
X-Trace-ID: <uuid>
Content-Type: application/json

{
  "from_account": "ACC-1001",
  "to_account": "ACC-2001",
  "amount": 100000,
  "currency": "VND",
  "status": "completed",
  "trace_id": "<uuid>"
}
```

Transaction Service ghi vào bảng `ledger` và trả record transaction. Trong Core Banking, ghi ledger là best-effort: nếu ghi ledger lỗi thì Core Banking log warning, nhưng giao dịch account đã áp dụng vẫn có thể trả `completed`.

Output cuối của Core Banking:

```json
{
  "transaction_id": "<uuid>",
  "status": "completed",
  "trace_id": "<uuid>",
  "from_balance": 999900000,
  "to_balance": 250100000
}
```

### 4.7 Bước 7: Payment gửi notification và trả về API Gateway

Sau khi Core Banking thành công, Payment:

1. Tăng metric `TXN_TOTAL{status="completed"}`.
2. Log audit `payment_completed`.
3. Gọi Notification Service:

```http
POST /notify
X-Trace-ID: <uuid>
Content-Type: application/json

{
  "trace_id": "<uuid>",
  "event": "payment_completed",
  "transaction": { core_banking_result }
}
```

Notification Service trả:

```json
{
  "status": "queued",
  "service": "notification-service",
  "trace_id": "<uuid>"
}
```

Payment không fail giao dịch nếu notification lỗi; nó chỉ log warning `notification_send_failed`.

Output cuối trả về API Gateway/Web Portal:

```json
{
  "status": "completed",
  "trace_id": "<uuid>",
  "fraud": { "...": "..." },
  "core_banking": { "...": "..." }
}
```

## 5. Flow xem số dư và lịch sử giao dịch

### 5.1 Xem số dư account

Browser gọi Web Portal:

```http
GET /api/balance/ACC-1001
Cookie: ztlab_session=<session>
```

Web Portal gọi API Gateway:

```http
GET /accounts/ACC-1001
Authorization: Bearer <access_token>
```

API Gateway:

- Verify JWT.
- Cần role `financial-read`.
- Gọi `PAYMENT_SERVICE_URL/accounts/ACC-1001`.

Payment Service:

- Proxy sang `CORE_BANKING_URL/accounts/ACC-1001`.

Core Banking:

- Proxy sang `ACCOUNT_SERVICE_URL/accounts/ACC-1001`.

Account Service trả:

```json
{
  "account_id": "ACC-1001",
  "owner": "testuser01",
  "balance": 1000000000,
  "currency": "VND"
}
```

### 5.2 Xem lịch sử giao dịch

Browser gọi:

```http
GET /api/transactions?account_id=ACC-1001&limit=20
```

Đường đi:

```text
web-portal
  -> api-gateway GET /transactions?account_id=ACC-1001&limit=20
  -> payment-service
  -> core-banking
  -> transaction-service
  -> postgres-txn
```

Output là danh sách ledger:

```json
[
  {
    "transaction_id": "<uuid>",
    "from_account": "ACC-1001",
    "to_account": "ACC-2001",
    "amount": 100000,
    "currency": "VND",
    "status": "completed",
    "trace_id": "<uuid>",
    "created_at": 1760000000.0
  }
]
```

## 6. Flow Zero Trust enforcement

Mỗi request đi qua nhiều lớp kiểm soát, không có thành phần nào được tin mặc định.

### 6.1 Kiểm soát tại API Gateway

API Gateway kiểm soát ở mức người dùng:

- Có Bearer token không?
- Token có đúng issuer/JWKS hoặc dev secret không?
- User có role phù hợp không?
- Source IP có vượt rate limit không?

Đây là authorization theo user identity.

### 6.2 Kiểm soát tại Envoy + OPA

Envoy + OPA kiểm soát ở mức workload/service:

- Public path `/health`, `/ready`, `/metrics` được allow.
- External request có Bearer token chỉ được vào các edge path hợp lệ.
- Internal service request cần SVID hợp lệ trong trust domain `spiffe://ztlab.local/`.
- Core transaction cần fraud gate header hợp lệ.

Kết quả OPA:

- `allow=true`: Envoy forward request vào app.
- `allow=false`: request bị chặn trước khi đến app.

### 6.3 Kiểm soát tại Core Banking

Core Banking là lớp kiểm soát nghiệp vụ cuối cùng:

- Không tin riêng OPA.
- Tự validate lại `X-Fraud-Gate` và `X-Fraud-Score`.
- Nếu bypass gateway/OPA nhưng thiếu header hoặc score cao thì vẫn bị `403 fraud gate validation failed`.

## 7. Flow log, SIEM, AI và SOAR

### 7.1 Log được tạo ở đâu

Các service dùng `ZTLabLogger` và `trace_middleware`:

- Mỗi request có `trace_id`.
- Response có header `X-Trace-ID`.
- Log dạng JSON gồm timestamp, level, service, cloud, event, method/path/status/duration và các field audit như amount, fraud_score, transaction_id.

Envoy cũng ghi access log JSON gồm method, path, response_code, duration, upstream, source_ip, trace_id và svid.

### 7.2 Promtail -> Loki -> Grafana

Promtail thu log từ pod/container trên cả AWS và OpenStack, gán label `cloud`, `namespace`, `app`, `job`, sau đó đẩy về Loki. OpenStack đẩy log về Loki AWS qua đường private/WireGuard và proxy port đã cấu hình.

Grafana dùng Loki datasource để xem log theo service/cloud, alert khi có label `pending_approval="true"`, và hiển thị SIEM dashboard.

### 7.3 AI Analyzer

AI Analyzer có 2 kiểu input.

**1. Tự động poll Loki:**

```text
AI Analyzer -> Loki query_range
query={job=~"envoy-access|opa-decisions|kubernetes-pods"} |~ "(?i)(403|401|denied|fraud_gate_bypass|...)"
```

**2. Gọi trực tiếp API:**

```http
POST /analyze
Content-Type: application/json

{
  "source": "web_scenario",
  "logs": [
    {
      "timestamp": "2026-06-12T00:00:00Z",
      "message": "jwt_verification_failed reason=invalid_jwt source_ip=10.9.8.55",
      "labels": {
        "namespace": "financial",
        "app": "api-gateway"
      }
    }
  ]
}
```

Output AI:

```json
{
  "verdict": "malicious",
  "severity": "high",
  "confidence": 0.86,
  "attack_type": "access_denied",
  "summary": "Detected suspicious security indicators...",
  "evidence": ["..."],
  "recommended_action": "investigate source identity, affected workload, and related OPA/Envoy decisions",
  "recommended_playbook": "isolate_workload",
  "affected_service": "api-gateway",
  "source_ip": "10.9.8.55",
  "provider_used": "openai|gemini|heuristic",
  "model_used": "..."
}
```

Nếu severity dưới ngưỡng approve, AI chỉ push alert vào Loki. Nếu severity là `high` hoặc `critical`, AI tạo pending alert:

- Lưu trong memory `PENDING_ALERTS`.
- Push Loki với label `pending_approval="true"`.
- Tạo TheHive alert nếu có cấu hình.
- Chờ admin approve/dismiss qua `GET /pending`, `POST /pending/{alert_id}/approve`, `POST /pending/{alert_id}/dismiss`.

### 7.4 SOAR Engine

SOAR chỉ chạy khi AI forward alert sau khi admin approve.

Input vào SOAR:

```http
POST /alerts
Content-Type: application/json

{
  "verdict": "malicious",
  "severity": "high",
  "confidence": 0.86,
  "attack_type": "port_scan",
  "recommended_playbook": "block_source_ip",
  "affected_service": "api-gateway",
  "source_ip": "10.9.8.55",
  "summary": "...",
  "evidence": ["..."]
}
```

SOAR quyết định có execute hay không dựa trên:

- `verdict != normal`
- severity >= `SOAR_MIN_SEVERITY`
- confidence >= `SOAR_MIN_CONFIDENCE`
- `SOAR_AUTO_EXECUTE=true`

Mapping attack type sang playbook:

| Attack type | Playbook |
|---|---|
| `fraud_gate_bypass`, `lateral_movement` | `isolate_workload` |
| `large_response` | `restrict_egress` |
| `cryptomining` | `quarantine_workload` |
| `port_scan`, `exploit_probe`, `access_denied` | `block_source_ip` |
| `brute_force`, `credential_stuffing`, `jwt_replay` | `revoke_user_sessions` |

Output SOAR là case:

```json
{
  "case_id": "case-<timestamp>-<hash>",
  "status": "executed",
  "attack_type": "port_scan",
  "severity": "high",
  "confidence": 0.86,
  "playbook": "block_source_ip",
  "target_context": "ctx-aws",
  "target_namespace": "financial",
  "target_workload": "api-gateway",
  "source_ip": "10.9.8.55",
  "action": "executed block_source_ip (...)"
}
```

Case được lưu vào `/data/cases.jsonl`, push lại vào Loki với `event_type=soar_action`, và có thể rollback qua `POST /cases/{case_id}/rollback` nếu playbook hỗ trợ.

## 8. Bảng input/output theo từng thành phần

| Thành phần | Input | Xử lý chính | Output |
|---|---|---|---|
| Web Portal | Form login hoặc API call từ browser + cookie session | Lấy token Keycloak, giữ session, gọi API Gateway/AI/Loki | HTML page hoặc JSON cho frontend |
| Keycloak | Username/password hoặc admin API | Cấp JWT, quản lý role/session | access_token, refresh_token, JWKS |
| API Gateway | HTTP `/payments`, `/accounts`, `/transactions` + Bearer token | Rate limit, JWT verify, role check, tạo trace | Forward sang Payment hoặc trả 401/403/429/503 |
| Envoy inbound | Request vào service port 15006 | Gọi OPA ext_authz, log access, forward local app | Allow vào app port 8080 hoặc deny |
| OPA | Envoy CheckRequest gồm method/path/header/source principal | Rego policy: public path, bearer path, SVID, fraud gate | allow/deny |
| Payment Service | Payment JSON + trace/user headers | Amount limit, fraud score, core banking call, notification | Completed JSON hoặc fraud/core error |
| Fraud Detection | Payment JSON | Redis velocity + amount/channel/country scoring | score, verdict, reason, gate |
| Core Banking | `/transactions/execute` + fraud headers | Validate fraud gate, gọi account transfer và ledger | transaction_id, status, balances |
| Account Service | Account query hoặc transfer JSON | Đọc/ghi PostgreSQL accounts, atomic transfer | account record hoặc balance mới |
| Transaction Service | Ledger JSON hoặc query | Ghi/đọc PostgreSQL ledger | transaction record/list |
| Notification Service | Event JSON | Log/audit notification queued | queued status |
| Promtail/Loki | Container/app/Envoy logs | Label và tập trung log | Log queryable cho Grafana/AI |
| AI Analyzer | Log batch từ Loki/API | LLM/heuristic classify threat | alert, pending alert, TheHive alert |
| SOAR Engine | Approved security alert | Chọn playbook, patch K8s/Keycloak, ghi case | case record, Loki audit, rollback endpoint |

## 9. Các điểm cần nhấn mạnh khi thuyết trình

1. **API Gateway không phải là nơi bảo mật duy nhất.** Nó kiểm user/JWT/role, còn Envoy + OPA là lớp enforcement cho service-to-service.
2. **Core Banking nằm ở OpenStack** để mô phỏng private cloud. AWS chỉ gọi vào qua NodePort `30081` và mTLS Envoy.
3. **Fraud gate có 2 lớp**: OPA chặn request `/transactions/execute` nếu thiếu `X-Fraud-Gate=passed` hoặc score >= 75; Core Banking validate lại trong code để tránh bypass policy.
4. **Trace ID là dây nối toàn flow.** Cùng một `trace_id` xuất hiện từ API Gateway, Payment, Fraud, Core Banking, Account, Transaction và Notification.
5. **AI/SOAR có HITL.** High/critical alert không tự động chạy SOAR ngay; AI tạo pending alert, admin approve thì mới forward sang SOAR.
6. **NetworkPolicy giới hạn đường đi.** AWS chỉ được egress sang OpenStack core banking NodePort `30081`; OpenStack chỉ allow traffic cần thiết từ AWS và nội bộ namespace.
7. **SOAR action có audit và rollback.** Mọi case ghi vào PVC `/data/cases.jsonl` và Loki; một số playbook có rollback để khôi phục selector/replica/network policy.

## 10. Tóm tắt một câu về flow

Người dùng đăng nhập Web Portal để lấy JWT từ Keycloak, gửi giao dịch vào API Gateway; Gateway verify token và role rồi đưa request qua Envoy/OPA sang Payment Service; Payment chấm Fraud Detection, nếu gate passed thì qua Envoy mTLS cross-cloud sang Core Banking trên OpenStack; Core Banking cập nhật account và ledger; toàn bộ log được đẩy về Loki để AI Analyzer phát hiện bất thường và sau khi admin approve thì SOAR Engine thực thi playbook phản ứng trên Kubernetes.
