# Báo Cáo Flow Hệ Thống ZTLab

Tài liệu này mô tả flow theo source hiện tại: gateway nào xử lý gì, input/output ở từng bước, log đi đâu, AI/SOAR phản ứng thế nào. Dùng cùng với [HUONG_DAN.md](HUONG_DAN.md) để test.

## 1. Các lớp gateway

| Lớp | Thành phần | Vai trò |
|---|---|---|
| Infrastructure gateway | SSH tunnel, bastion, Traefik/port-forward, WireGuard/private route | Đưa người dùng/operator vào cluster và nối AWS với OpenStack |
| API Gateway | `services/api-gateway` | Verify JWT thật bằng JWKS, rate limit, role check, tạo/truyền `X-Trace-ID` |
| Envoy sidecar gateway | Envoy `15006/15001` + OPA ext_authz + SPIRE SDS | Policy enforcement cho service-to-service, access log, mTLS workload |
| Core Banking guard | `services/core-banking` | Lớp nghiệp vụ cuối: verify fraud gate, fraud score và HMAC signature |

## 2. Luồng tổng quát

```text
User Browser / curl
  -> Web Portal hoặc API Gateway
  -> Keycloak OIDC token endpoint
  -> API Gateway
  -> Envoy outbound/inbound + OPA
  -> Payment Service
  -> Fraud Detection
  -> Payment ký fraud gate bằng HMAC
  -> Envoy mTLS/SPIRE sang OpenStack
  -> Core Banking verify gate + HMAC
  -> Account Service transfer
  -> Transaction Service ledger
  -> Notification Service
  -> response quay lại user
```

## 3. Login Web Portal — OIDC Authorization Code + PKCE (S256)

```text
Browser GET /login
  -> Web Portal render trang login (nút "Đăng nhập qua Keycloak")

Browser GET /auth/start
  -> Web Portal sinh code_verifier (random 32 bytes) + code_challenge (SHA-256 base64url)
  -> Lưu {state, code_verifier, redirect_uri} vào signed cookie ztlab_pkce (max_age=300s)
  -> Redirect browser đến Keycloak auth endpoint qua /kc/ proxy:
       /kc/realms/ztlab/protocol/openid-connect/auth
         ?client_id=web-portal
         &response_type=code
         &scope=openid profile email
         &redirect_uri=http://portal/auth/callback
         &state=<random>
         &code_challenge=<S256>
         &code_challenge_method=S256

User đăng nhập trên Keycloak
  -> Keycloak redirect về /auth/callback?code=<auth_code>&state=<state>

Browser GET /auth/callback
  -> Web Portal verify CSRF state khớp cookie ztlab_pkce
  -> Gọi Keycloak token endpoint với code + code_verifier (PKCE exchange)
  -> Keycloak trả {access_token, refresh_token, id_token}
  -> Web Portal decode JWT payload (unverified, chỉ lấy claims)
  -> Gọi API Gateway /accounts để lấy account_id của user
  -> Tạo server-side session {username, roles, access_token, refresh_token, account_id}
  -> Xóa cookie ztlab_pkce, set cookie ztlab_session (opaque sid)
  -> Redirect -> /dashboard
```

Điểm bảo mật:

- Cookie `ztlab_session` chứa opaque signed sid, **không** chứa access_token/refresh_token.
- Session data lưu trong memory `_sessions`; pod restart mất session.
- Cookie: `HttpOnly`, `SameSite=Lax`; `Secure` bật khi `HTTPS_ENABLED=true`.
- PKCE S256 chống authorization code interception attack.
- CSRF state khớp bằng signed cookie (không dùng server-side state store).
- PKCE cookie TTL 300s — hết hạn nếu user chậm đăng nhập.

## 4. API Gateway input/output

### Input payment

```http
POST /payments
Authorization: Bearer <keycloak_access_token>
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

### Xử lý

1. Rate limit theo source IP: **60 request/phút**, sliding window bằng `deque`. Vượt ngưỡng → 429.
2. Verify JWT:
   - Primary: RS256/JWKS từ Keycloak.
   - Fail-closed nếu JWKS unavailable.
   - HS256 dev token chỉ khi `ALLOW_DEV_TOKENS=true` và `JWT_DEV_SECRET` có giá trị.
3. Kiểm role:
   - `POST /payments`: `financial-write`.
   - `GET /accounts`, `GET /transactions`: `financial-read`.
4. Tạo hoặc forward `X-Trace-ID`.
5. Forward sang `PAYMENT_SERVICE_URL`, thường là Envoy outbound `http://127.0.0.1:15001`.

### Output lỗi chính

| HTTP | Lý do |
|---:|---|
| 401 | Missing/invalid bearer token |
| 403 | Thiếu role cần thiết |
| 429 | Rate limit exceeded |
| 503 | JWKS/dev verifier hoặc payment downstream unavailable |

## 5. Envoy + OPA flow

**Inbound (nhận request từ bên ngoài service):**

```text
Kubernetes Service targetPort 15006
  -> Envoy inbound listener :15006
  -> OPA ext_authz gRPC (policy check)
  -> allow → forward đến app :8080
  -> deny  → trả lỗi 403 ngay, app không nhìn thấy request
```

**Outbound (service gọi ra ngoài):**

```text
App gọi http://127.0.0.1:15001/<path>
  -> Envoy outbound listener :15001
  -> Route theo prefix: /transactions → upstream 10.10.1.12:30081 (core-banking OpenStack)
  -> Bọc mTLS bằng SVID X.509 từ SPIRE SDS socket (/run/spire/sockets)
  -> OpenStack Envoy inbound verify peer SVID → forward core-banking :8080
```

OPA policy hiện tập trung vào:

- Allow public path: `/health`, `/ready`, `/metrics`.
- Edge bearer path (API Gateway): cho đi qua, API Gateway tự verify JWT RS256.
- SVID workload: kiểm peer certificate thuộc `spiffe://ztlab.local/`.
- Fraud gate header: kiểm `X-Fraud-Gate` tại proxy layer trước core-banking.

OPA không decode JWT chưa verify để cấp quyền — đó là trách nhiệm của API Gateway.

**SPIFFE ID các workload:**

| Service | SPIFFE ID |
|---|---|
| api-gateway | `spiffe://ztlab.local/aws/api-gateway` |
| payment-service | `spiffe://ztlab.local/aws/payment-service` |
| fraud-detection | `spiffe://ztlab.local/aws/fraud-detection` |
| notification-service | `spiffe://ztlab.local/aws/notification-service` |
| core-banking | `spiffe://ztlab.local/openstack/core-banking` |

## 6. Payment và Fraud Detection

Payment Service nhận request đã qua API Gateway/Envoy:

1. Reject nếu `amount > MAX_SINGLE_TXN_VND`, mặc định `500_000_000` VND.
2. Gọi Fraud Detection `/score`.
3. Fraud Detection tính điểm (cộng dồn, cap ở 100):

| Yếu tố | Điều kiện | Cộng điểm |
|---|---|---|
| Baseline | luôn | +5 |
| Velocity | 6–10 tx trong 60s | +10 |
| Velocity | 11–30 tx | +25 |
| Velocity | >30 tx | +40 |
| High amount | `amount >= 100_000_000` VND | +30 |
| Critical amount | `amount >= 500_000_000` VND | +55 (thay thế high) |
| Risky channel | `tor`, `unknown`, `script` | +15 |
| Unusual country | ngoài VN, SG, TH | +10 |

4. Verdict theo score:

| Score | Verdict | Gate | HTTP |
|---|---|---|---|
| < 40 | `allow` | `passed` | 200 |
| 40–74 | `review` | `passed` | 200 (nhưng flagged) |
| ≥ 75 | `block` | `blocked` | 403 |

5. Nếu `gate=blocked`, Payment trả 403 ngay.
6. Nếu `gate=passed`, Payment ký HMAC và gọi Core Banking.

Output Fraud Detection bình thường:

```json
{"score": 5, "verdict": "allow", "reason": ["baseline"], "gate": "passed"}
```

**Redis Velocity Tracking:**

Mỗi giao dịch ghi một timestamp vào ZSET `fraud:velocity:{account_id}` (TTL 120s). Sliding window 60s: đếm số entry trong cửa sổ và cộng điểm tương ứng. Debug endpoint:

```bash
# Trong pod fraud-detection
GET /debug/velocity
```

Web Portal proxy endpoint này tại `/api/velocity`, hiển thị trong panel **Redis Velocity** tại trang `/logs`.

## 7. Fraud gate integrity HMAC

Trước khi gọi Core Banking, Payment ký:

```text
canonical = timestamp|trace_id|from_account|to_account|amount_2decimal|currency|fraud_score
signature = HMAC_SHA256(CORE_BANKING_SHARED_SECRET, canonical)
```

> **timestamp** là Unix epoch integer (giây), đứng **đầu** canonical. Đây là replay protection: Core Banking reject nếu `|now - timestamp| > 60s`.

Header gửi sang Core Banking:

```http
X-Trace-ID: <uuid>
X-Fraud-Gate: passed
X-Fraud-Score: <score>
X-Fraud-Timestamp: <unix_epoch>
X-Fraud-Gate-Signature: <hmac_sha256_hex>
```

Core Banking chỉ execute khi **tất cả** điều kiện đúng:

| Điều kiện | Giá trị |
|---|---|
| `X-Fraud-Gate == "passed"` | gate phải là passed |
| `X-Fraud-Score <= MAX_FRAUD_SCORE` | mặc định 74 |
| `abs(now - X-Fraud-Timestamp) <= 60s` | anti-replay window |
| HMAC khớp | tính lại và so sánh constant-time |

Nếu bất kỳ điều kiện nào sai → 403 + log `event=fraud_gate_bypass` với `fraud_signature_valid`, `fraud_timestamp_valid`.

**Tác dụng bảo mật:** kẻ tấn công không thể tự gọi `/transactions/execute` với header fraud giả vì không có `CORE_BANKING_SHARED_SECRET`, và không thể replay request cũ vì timestamp window 60s.

## 8. Cross-cloud Core Banking

Đường đi:

```text
payment-service app
  -> 127.0.0.1:15001/transactions/execute
  -> Envoy outbound route /transactions
  -> 10.10.1.12:30081
  -> OpenStack core-banking Service targetPort 15006
  -> Envoy inbound + OPA
  -> core-banking app 8080
```

Core Banking gọi tiếp:

```text
core-banking
  -> account-service /accounts/transfer   (atomic DB transfer — bước quyết định số dư)
  -> transaction-service /transactions    (ghi ledger best-effort, không rollback nếu fail)
```

Sau khi Account Service trả `completed`, Payment Service gọi Notification Service (qua Envoy outbound `127.0.0.1:15001`, best-effort — lỗi chỉ ghi warn, không fail payment):

```text
payment-service
  -> POST http://127.0.0.1:15001/notify
       {trace_id, event="payment_completed", transaction: {...}}
  -> notification-service ghi log sự kiện
```

Transaction Service ghi ledger audit-only. Account Service transfer là bước quyết định số dư cuối cùng.

## 9. Output payment thành công

```json
{
  "status": "completed",
  "trace_id": "<uuid>",
  "fraud": {
    "score": 5,
    "verdict": "allow",
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

## 10. SIEM log flow

**Lý do chọn PLG thay ELK:** Loki chỉ index label (không full-text index), RAM ~512 MB–1 GB thay vì 4–8 GB của Elasticsearch — phù hợp tài nguyên lab. Query bằng LogQL tương tự PromQL.

```text
AWS cluster
  App logs + Envoy access logs + OPA decision logs
    -> Promtail DaemonSet (label cloud=aws)
    -> Loki :3100 (in-cluster) / :3101 (port-forward local)
    -> Grafana :3000 (in-cluster) / :3001 (port-forward local)
    -> AI Analyzer (poll Loki + nhận push từ SOAR/AI)

OpenStack cluster
  App logs + Envoy + OPA
    -> Promtail DaemonSet (label cloud=openstack)
    -> socat relay :31100 (AWS worker 10.10.1.11, systemd loki-relay.service)
    -> Loki ClusterIP 10.43.186.251:3100 (AWS in-cluster)
```

`trace_id` là khóa truy vết xuyên cloud. Một giao dịch chuẩn phải thấy cùng `trace_id` ở API Gateway, Payment, Fraud, Core Banking, Account/Transaction và Notification.

**Cross-cloud relay — thực tế vs đề xuất:**

| | Đề xuất ban đầu | Thực tế triển khai |
|---|---|---|
| Kênh truyền log OS→AWS | WireGuard tunnel (OpenStack → aws-siem 10.10.2.10:3100) | socat relay trên AWS worker 10.10.1.11:31100 → Loki ClusterIP |
| Loki/Grafana deployment | Dedicated node `aws-siem` (Docker Compose) | K8s namespace `plg-stack` (cùng cluster AWS) |
| Lý do thay đổi | WireGuard giữa các cluster chưa setup trong lab thực tế | socat relay đủ dùng cho lab; K8s deployment đơn giản hơn |

**Port conflict local:** Port 3000 và 3100 bị Docker PLG stack local chiếm → K8s port-forward dùng 3001 (Grafana) và 3101 (Loki).

**OPA Rego — đề xuất vs thực tế:**
- Đề xuất ban đầu có `io.jwt.decode` trong Rego để đọc JWT claim.
- Thực tế sửa: API Gateway verify JWT RS256 trước, OPA chỉ nhận metadata đã tin cậy từ Envoy/Gateway — không decode JWT chưa verify trong OPA.

## 11. AI Analyzer flow

AI Analyzer nhận log qua hai đường:

- Poll Loki theo query security trong background (interval cấu hình).
- API trực tiếp `POST /analyze` từ demo/scenario (Web Portal `/api/scenarios/{id}/run`).

**AI Provider — thiết kế và triển khai thực tế:**

**Theo đề xuất ban đầu**, AI Analyzer được thiết kế để gọi **LLM API bên ngoài** (OpenAI hoặc Gemini) để phân tích log bảo mật theo ngữ nghĩa. Heuristic regex chỉ là lớp fallback khi không có API key.

| Provider | Cấu hình | Hành vi | Endpoint |
|---|---|---|---|
| `openai` | `OPENAI_API_KEY` + `OPENAI_MODEL=gpt-4o-mini` | Gọi LLM API, merge với heuristic | `https://api.openai.com/v1/chat/completions` |
| `gemini` | `GEMINI_API_KEY` + `GEMINI_MODEL=gemini-1.5-flash` | Gọi LLM API, merge với heuristic | `https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent` |
| `heuristic` **(fallback lab)** | Không cần API key | Chỉ dùng MALICIOUS_PATTERNS regex | — |

**Trong môi trường lab hiện tại:** `AI_PROVIDER=heuristic` vì không cấu hình API key thật. Khi deploy với key thật, đặt `AI_PROVIDER=openai` hoặc `AI_PROVIDER=gemini`.

Khi LLM lỗi → backoff 900s, fallback tự động về `heuristic_analyze()`. Merge rule: heuristic thắng nếu LLM kết luận `normal` nhưng heuristic phát hiện pattern; severity chọn cao hơn.

**MALICIOUS_PATTERNS** (heuristic, 12 loại — khớp regex case-insensitive trên toàn bộ log text):

| Regex pattern | attack_type |
|---|---|
| `\b(401\|403\|denied\|deny\|unauthorized\|forbidden)\b` | `access_denied` |
| `fraud_gate_bypass` | `fraud_gate_bypass` |
| `brute.?force\|account.?locked\|too.?many.?attempt\|login.?attempt.*\b([5-9]\d\|\d{3,})\b` | `brute_force` |
| `lateral\|invalid.*svid\|spiffe.*den` | `lateral_movement` |
| `port scan\|nmap\|masscan\|syn scan` | `port_scan` |
| `privilege escalation\|setuid\|cap_sys_admin` | `privilege_escalation` |
| `credential[_ -]?stuffing\|multiple_usernames\|common_password_attempts` | `credential_stuffing` |
| `jwt[_ -]?replay\|stolen_token\|suspicious_reuse\|expired_token` | `jwt_replay` |
| `container[_ -]?escape\|host_filesystem\|suspicious_syscall\|ptrace\|seccomp\|169\.254\.169\.254` | `container_escape` |
| `xmrig\|cryptomin\|stratum\+tcp` | `cryptomining` |
| `sqlmap\|union select\|/etc/passwd\|cmd=\|powershell\|curl .*http` | `exploit_probe` |
| `bytes_sent[=: ]([1-9]\d{6,})` | `large_response` (bytes ≥ 1 MB) |

**Severity logic (heuristic):**

```python
# Tất cả patterns khớp → tập unique_reasons
severity = "critical" if {"fraud_gate_bypass", "lateral_movement", "cryptomining"} & set(unique_reasons) \
           else "high"
if len(reasons) == 1 and unique_reasons == ["access_denied"]:
    severity = "medium"
```

Tóm lại:
- Chỉ `access_denied` → **medium** → `event_type=ai_alert_logged_only` (không tạo pending alert).
- Bất kỳ attack type khác → **high** → pending alert.
- Có `fraud_gate_bypass`, `lateral_movement`, hoặc `cryptomining` → **critical** → pending alert.

**Polling config mặc định:**

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `AI_ANALYZER_POLL_INTERVAL_SECONDS` | 30 | Tần suất query Loki |
| `AI_ANALYZER_LOOKBACK_SECONDS` | 90 | Cửa sổ log nhìn lại |
| `AI_ANALYZER_MAX_LOGS_PER_BATCH` | 25 | Số log tối đa/batch |
| `AI_ANALYZER_PENDING_TTL_SECONDS` | 3600 | Pending alert tự hết sau 1h |

**Ignored namespaces/apps (không tạo alert từ):** `plg-stack`, `monitoring`, `identity`, `kube-system`; app `grafana`, `loki`, `promtail`, `ai-analyzer`, `soar-engine`, `prometheus`, `keycloak`.

Output chuẩn:

```json
{
  "verdict": "malicious",
  "severity": "high",
  "confidence": 0.95,
  "attack_type": "brute_force",
  "recommended_playbook": "quarantine_workload",
  "affected_service": "api-gateway",
  "source_ip": "10.9.8.55"
}
```

## 12. SOAR HITL flow

```text
AI high/critical alert
  -> pending alert lưu trong PENDING_ALERTS (in-memory + Loki)
  -> Web Portal /alerts tab "Chờ duyệt"
  -> admin investigate (xem verdict/severity/attack_type/source_ip)
  -> Dismiss → ghi audit Loki, không tác động workload
  -> Approve → Web Portal forward sang SOAR Engine /execute
  -> SOAR chọn playbook (từ AI recommendation hoặc PLAYBOOK_MAP)
  -> thực thi: patch K8s Service/NetworkPolicy/Deployment hoặc Keycloak API
  -> ghi case vào /data/cases.jsonl + push Loki event_type=soar_action
  -> nếu cần undo: POST /cases/{case_id}/rollback
```

**Chú ý quan trọng:** `SOAR_DRY_RUN=true` là mặc định — SOAR log hành động nhưng **không thực thi thật**. Đặt `SOAR_DRY_RUN=false` để chạy playbook thật trên cluster.

**Playbook và attack_type mapping:**

| attack_type | Playbook được chọn | Tác động thực |
|---|---|---|
| `fraud_gate_bypass` | `isolate_workload` | Patch Service selector cô lập traffic |
| `lateral_movement` | `isolate_workload` | Patch Service selector cô lập traffic |
| `large_response` | `restrict_egress` | Patch NetworkPolicy hạn chế egress |
| `cryptomining` | `quarantine_workload` | Scale deployment về 0 replica |
| `port_scan` | `block_source_ip` | Tạo/patch NetworkPolicy chặn source IP |
| `exploit_probe` | `block_source_ip` | Tạo/patch NetworkPolicy chặn source IP |
| `access_denied` | `block_source_ip` | Tạo/patch NetworkPolicy chặn source IP |
| `brute_force` | `revoke_user_sessions` | Revoke session qua Keycloak admin API |
| `credential_stuffing` | `revoke_user_sessions` | Revoke session qua Keycloak admin API |
| `jwt_replay` | `revoke_user_sessions` | Revoke session qua Keycloak admin API |
| khác / không map | `monitor_only` | Chỉ ghi audit, không tác động |

**Rollback:** `isolate_workload`, `restrict_egress`, `quarantine_workload`, `block_source_ip` hỗ trợ rollback tự động qua `POST /cases/{case_id}/rollback`. `revoke_user_sessions` không rollback tự động — admin phải unlock user trong Keycloak thủ công.

**Case status lifecycle:** `dry_run` → `executed` → `rolled_back` | `rollback_failed`. Hoặc `failed` nếu playbook lỗi.

## 13. SPIFFE/SPIRE — Workload Identity

SPIRE cấp X.509 SVID (SPIFFE Verifiable Identity Document) cho mỗi workload, dùng cho mTLS cross-cloud.

```text
SPIRE Server (AWS, ns: spire)
  -> RegistrationEntry: spiffe://ztlab.local/aws/payment-service
       selector: k8s:pod-label:spiffe.io/spiffeid=aws/payment-service

SPIRE Agent (DaemonSet, mỗi node)
  -> attestation: k8s_psat (Projected Service Account Token)
  -> cấp SVID qua Workload API socket /run/spire/sockets/agent.sock

Envoy SDS (Secret Discovery Service)
  -> mount /run/spire/sockets vào pod
  -> Envoy gọi Workload API lấy SVID + trust bundle
  -> Dùng SVID cho outbound mTLS (payment → core-banking)
  -> Verify peer SVID cho inbound mTLS (core-banking Envoy verify payment)
```

**OpenStack SPIRE Agent:**

- Dùng join token (manual) thay vì k8s_psat vì OpenStack K3s không có Projected SA Token mặc định.
- Join token có thể hết hạn sau restart lâu → cần tạo lại từ SPIRE Server AWS và patch DaemonSet.

**Cross-cloud trust:** SPIRE Server AWS là root of trust duy nhất; OpenStack agent join vào cùng trust domain `spiffe://ztlab.local/`. Core Banking Envoy verify peer cert phải thuộc trust domain này.

## 14. Self-registration — Tạo user và tài khoản ngân hàng

Web Portal cho phép user tự đăng ký. Flow gồm hai bước tuần tự:

```text
Browser POST /auth/register {username, password, confirm_password, email}

Bước 1: Tạo Keycloak user
  -> Web Portal gọi Keycloak Admin REST API
       POST /admin/realms/ztlab/users
         {username, email, credentials: [{type:password, value:password}], enabled:true}
  -> Gán role financial-read, financial-write

Bước 2: Tạo tài khoản ngân hàng
  -> Web Portal lấy token của user vừa tạo (Resource Owner Password Grant)
  -> Gọi API Gateway POST /accounts
       {account_id: <random ACC-XXXXXX>, owner: username, balance: INITIAL_BALANCE, currency: VND}
  -> API Gateway forward qua Envoy → Core Banking (OpenStack)
  -> Core Banking gọi Account Service tạo bản ghi trong PostgreSQL
```

Admin token để tạo user: Web Portal gọi Keycloak master realm bằng `KEYCLOAK_ADMIN_USER/PASS` (Resource Owner Password Grant → `/realms/master/protocol/openid-connect/token`), lấy token có quyền admin realm `ztlab`.

`INITIAL_BALANCE` mặc định = **10,000,000 VND** (10 triệu).

Điểm bảo mật:

- Rate limit đăng ký: `REGISTER_LIMIT_PER_HOUR` per source IP (sliding window bằng `deque`).
- Validation: username ≥ 3 ký tự `[a-z0-9_]`; password ≥ 12 ký tự + ít nhất 1 hoa + 1 số + 1 ký tự đặc biệt.
- Keycloak 409 trả generic error (không tiết lộ username/email đã tồn tại — chống enumeration).
- Nếu tạo Keycloak thành công nhưng tạo account ngân hàng fail → user tồn tại trong Keycloak nhưng không có account, cần xử lý manual.
- Account ID collision: retry tối đa 5 lần với ID ngẫu nhiên mới.

## 15. Test flow tối thiểu

1. `bash scripts/health-check.sh` phải `FAIL=0`.
2. Lấy JWT Keycloak từ `testuser01`.
3. `POST /payments` hợp lệ phải trả `completed`.
4. JWT giả phải trả `401`.
5. Direct Core Banking với signature giả phải trả `403`.
6. Inject AI alert critical phải tạo pending alert.
7. Dismiss hoặc approve + rollback SOAR case.


## 16. Flow demo Web UI

Web Portal không chỉ là màn hình đăng nhập/chuyển tiền, mà còn là console demo cho hệ thống.

```text
Browser
  -> /login        (OIDC PKCE start)
  -> /register     (tự đăng ký)
  -> /dashboard    (sau khi login)
  -> /transfer
  -> /scenarios
  -> /alerts
  -> /logs
```

Các trang chính:

| Trang | Backend route | Vai trò demo |
|---|---|---|
| `/login` | `GET /auth/start` → Keycloak | OIDC PKCE login |
| `/register` | `POST /auth/register` | Tạo Keycloak user + bank account |
| `/dashboard` | `/api/balance`, `/api/transactions` | Xem số dư và lịch sử giao dịch |
| `/transfer` | `/api/transfer` | Chạy flow payment thật qua API Gateway |
| `/scenarios` | `/api/scenarios/{id}/run` | Chạy kịch bản bảo mật từ UI |
| `/alerts` | `/api/alerts`, approve/dismiss | HITL cho AI/SOAR |
| `/logs` | `/api/logs`, `/api/velocity` | Log Loki + Redis Velocity panel |

Khi bấm một kịch bản trên `/scenarios`:

```text
Browser button
  -> Web Portal /api/scenarios/{scenario_id}/run
  -> tùy scenario:
       gọi API Gateway
       hoặc inject log vào AI Analyzer
  -> Web Portal trả JSON kết quả
  -> UI render status_code/verdict/playbook/expected
```

Nhóm scenario UI:

- **Zero Trust enforcement:** không JWT, JWT giả, lateral movement path, fraud gate block.
- **Velocity/rate limit:** high velocity, rate limit.
- **AI Detection:** brute force, port scan, exfiltration, cryptomining, SQLi probe, credential stuffing.
- **HITL:** các inject high/critical tạo pending alert; admin xử lý trên `/alerts`.

Flow HITL trên UI:

```text
/scenarios inject alert
  -> AI Analyzer verdict malicious/high-critical
  -> pending alert
  -> /alerts tab Chờ duyệt
  -> Dismiss: audit only
  -> Approve: forward SOAR
  -> SOAR case + Loki audit
```

## 17. Redis Velocity UI

Web Portal `/logs` (`http://127.0.0.1:8080/logs`) hiển thị panel **"Redis — Fraud Velocity Tracking"** ở đầu trang, tự refresh 15s.

Flow dữ liệu:

```text
Fraud Detection /debug/velocity
  -> Web Portal /api/velocity (proxy, cần session)
  -> logs.html JavaScript loadVelocity()
  -> bảng account / tx-in-window / risk / TTL
```

| Rủi ro | Tx / 60s | Badge | Cộng fraud score |
|---|---|---|---|
| NORMAL | ≤ 5 | xanh | 0 |
| LOW | 6–10 | xanh đậm | +10 |
| ELEVATED | 11–30 | vàng | +25 |
| HIGH | > 30 | đỏ | +40 |

Key Redis: `fraud:velocity:{account_id}` (ZSET timestamps, TTL=120s). Panel trống khi không có giao dịch trong 120s là bình thường.

## 18. Tóm tắt

ZTLab buộc mọi giao dịch đi qua user identity (Keycloak JWT RS256), workload identity (SPIFFE/SPIRE SVID), policy enforcement (Envoy/OPA), fraud scoring (Redis velocity + rule-based) và HMAC integrity gate trước khi Core Banking ghi số dư; log từ cả AWS và OpenStack được tập trung về Loki qua socat relay; AI Analyzer nhận diện 12 loại tấn công và chỉ sau khi admin duyệt HITL thì SOAR mới thực thi playbook trên hạ tầng thật.

## 19. So sánh với đề xuất ban đầu

### 19.1 Những điểm đúng với đề xuất

| Thành phần | Đề xuất | Thực tế |
|---|---|---|
| Log stack | PLG (Promtail + Loki + Grafana) | PLG ✓ |
| Lý do chọn PLG | ELK cần 4–8 GB RAM; PLG 512 MB–1 GB | Triển khai thành công trên lab ✓ |
| Fraud Detection | Rule-based score + Redis velocity | Triển khai đầy đủ ✓ |
| HMAC fraud gate | Payment ký, Core Banking verify | Triển khai đầy đủ ✓ |
| SPIFFE/SPIRE | SVID X.509 workload identity | Triển khai đầy đủ ✓ |
| Envoy mTLS | Outbound payment → core banking | Triển khai đầy đủ ✓ |
| OPA ext_authz | Envoy sidecar gọi OPA | Triển khai đầy đủ ✓ |
| SOAR HITL | Admin approve trước khi execute playbook | Triển khai đầy đủ ✓ |
| Keycloak OIDC RS256 | JWKS endpoint, fail-closed | Triển khai đầy đủ ✓ |

### 19.2 Thay đổi so với đề xuất và lý do

| Điểm | Đề xuất ban đầu | Thực tế triển khai | Lý do |
|---|---|---|---|
| **AI phân tích log** | Gọi LLM API bên ngoài (mô hình phân loại) | Heuristic regex (fallback); openai/gemini khi có API key | Lab không cấu hình API key thật; thiết kế vẫn hỗ trợ API call |
| **Cross-cloud relay** | WireGuard tunnel (OpenStack → aws-siem:3100) | socat relay (AWS worker:31100 → Loki ClusterIP) | WireGuard chưa setup giữa hai cluster trong lab |
| **SIEM deployment** | Dedicated `aws-siem` node (Docker Compose, 10.10.2.10) | K8s namespace `plg-stack` (cùng cluster AWS) | K8s deployment đơn giản hơn, tận dụng cluster sẵn có |
| **Ingress gateway** | Traefik Ingress Controller (Bước 1 Flow.md) | Không triển khai; dùng kubectl port-forward | Đủ cho lab; Traefik thêm độ phức tạp không cần thiết |
| **OPA JWT decode** | `io.jwt.decode` trong Rego để đọc claim | API Gateway verify JWT RS256; OPA nhận metadata đã tin cậy | Loại bỏ lỗ hổng verify JWT chưa kiểm tra chữ ký trong OPA |
| **SPIRE OpenStack** | `k8s_psat` attestor cho cả hai cluster | AWS: `k8s_psat`; OpenStack: `join_token` | OpenStack SPIRE node attestation với k8s_psat phức tạp hơn trong single-node lab |

### 19.3 Lưu ý về ELK và AI API

**ELK không dùng:** IMPLEMENTATION.md (Version 2.0.0) xác nhận "PLG Stack replaces ELK+Wazuh+Kafka" vì lý do RAM. Toàn bộ hệ thống dùng PLG.

**AI gọi external API là thiết kế chính:** Proposal mô tả AI Analyzer dùng "tập luật và mô hình phân loại" — nghĩa là kết hợp heuristic rules (MALICIOUS_PATTERNS) với LLM classification (OpenAI/Gemini API). Trong lab, `AI_PROVIDER=heuristic` vì thiếu API key. Khi demo với key thật, đặt `AI_PROVIDER=openai` hoặc `AI_PROVIDER=gemini` để AI gọi API bên ngoài.
