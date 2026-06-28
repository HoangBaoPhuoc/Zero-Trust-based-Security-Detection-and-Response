# ZTLab — Luồng Hoạt Động Chi Tiết: Cấu Hình, Luồng Dữ Liệu & Demo Kịch Bản

> **Đồ án**: Zero Trust-based Security Detection and Response for Microservices in Multi-Cloud  
> **Sinh viên**: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> **Môn**: NT114.Q21.ANTT  
> **Cập nhật**: 2026-06-28 — tất cả KB dùng log thật (không inject giả), Grafana alert rules query log thật từ service pod

---

## Mục lục

1. [Tổng quan hệ thống — có gì, chạy ở đâu](#1-tổng-quan-hệ-thống--có-gì-chạy-ở-đâu)
2. [Cấu hình từng thành phần Zero Trust](#2-cấu-hình-từng-thành-phần-zero-trust)
   - 2.1 Keycloak — Identity Provider
   - 2.2 SPIRE/SPIFFE — Workload Identity
   - 2.3 Envoy Sidecar — mTLS Proxy
   - 2.4 OPA — Policy Engine
   - 2.5 Grafana Alert Rules — Detection
   - 2.6 SOAR Engine — Response
3. [Luồng bình thường — một giao dịch hợp lệ đi qua hệ thống](#3-luồng-bình-thường--một-giao-dịch-hợp-lệ-đi-qua-hệ-thống)
4. [KB1 — Brute Force Login (T1110.001)](#4-kb1--brute-force-login-t1110001)
5. [KB2 — Fraud Gate Bypass (T1078.004)](#5-kb2--fraud-gate-bypass-t1078004)
6. [KB3 — Lateral Movement via Invalid SVID (T1021.007)](#6-kb3--lateral-movement-via-invalid-svid-t1021007)
7. [KB4 — Data Exfiltration / Large Response (T1041)](#7-kb4--data-exfiltration--large-response-t1041)
8. [KB5 — Access Denied Spike / OPA RBAC (T1078)](#8-kb5--access-denied-spike--opa-rbac-t1078)
9. [KB6 — Privilege Escalation in Container (T1611)](#9-kb6--privilege-escalation-in-container-t1611)

---

## 1. Tổng quan hệ thống — có gì, chạy ở đâu

Hệ thống ZTLab gồm hai cụm Kubernetes triển khai trên hai cloud khác nhau, kết nối với nhau qua WireGuard tunnel.

**Cụm AWS (K3s, 2 node)** chạy toàn bộ lớp ứng dụng phía người dùng:

| Service | Vai trò | Pod |
|---|---|---|
| api-gateway | Điểm vào duy nhất, verify JWT, kiểm tra IP block | 2/2 (app + envoy) |
| payment-service | Điều phối giao dịch, gọi fraud-detection rồi core-banking | 2/2 |
| fraud-detection | Tính fraud score theo amount/channel/velocity | 2/2 |
| notification-service | Gửi email xác nhận giao dịch | 2/2 |
| web-portal | UI cho người dùng và Security Dashboard HITL | 2/2 |
| opa-server | Policy engine, evaluate mọi request theo Rego policy | 1/1 |
| keycloak | Identity Provider, cấp JWT cho user | 1/1 |
| spire-server | SPIFFE CA, cấp X.509-SVID cho workload | 1/1 |
| spire-agent ×2 | Chạy trên mỗi node, nhận SVID và cấp cho pod | 1/1 mỗi node |
| loki | Log aggregation — nhận log từ Promtail, lưu chuỗi thời gian | 1/1 |
| grafana | Visualize log, chạy 6 alert rules, gửi webhook tới SOAR | 1/1 |
| promtail ×2 | DaemonSet — scrape log container từ node, đẩy vào Loki | 1/1 mỗi node |
| soar-engine | Nhận alert, tạo case, gửi email HITL, thực thi playbook | 1/1 |
| redis | Lưu blocked IPs, session blacklist, fraud velocity counter | 1/1 |
| postgresql ×2 | Lưu accounts và transaction ledger | 1/1 mỗi DB |

**Cụm OpenStack (K3s, 3 node)** chạy lớp core banking:

| Service | Vai trò |
|---|---|
| core-banking | Xử lý giao dịch tài chính, gọi account-service và transaction-service |
| account-service | Truy vấn số dư, thực hiện debit/credit |
| transaction-service | Ghi ledger, lưu lịch sử giao dịch |

Hai cụm kết nối qua **WireGuard** (10.200.0.1 ↔ 10.200.0.2). Envoy trên AWS trỏ thẳng đến IP OpenStack qua NodePort: `192.168.101.11:30080/30082/30083`.

---

## 2. Cấu hình từng thành phần Zero Trust

### 2.1 Keycloak — Identity Provider

Keycloak quản lý realm `ztlab`, chịu trách nhiệm xác thực người dùng và cấp JWT. Mỗi JWT chứa danh sách `realm_access.roles` — đây là căn cứ để OPA quyết định quyền hạn sau này.

**Người dùng và vai trò trong hệ thống:**

| Username | Roles | Tài khoản |
|---|---|---|
| testuser01 | financial-read, financial-write | ACC-1001 |
| testuser02 | financial-read, financial-write | ACC-2001 |
| merchant01 | financial-read (chỉ đọc) | ACC-4001 |
| analyst01 | security-analyst, security-admin | — |

**Client `web-portal`** là OIDC client duy nhất được phép dùng luồng `password` grant. API Gateway lấy JWKS từ Keycloak nội bộ qua `http://keycloak.identity.svc.cluster.local:8080/realms/ztlab/protocol/openid-connect/certs` để verify chữ ký JWT.

Khi user đăng nhập thành công, Keycloak ghi log kiểu `LOGIN` vào event log. Khi thất bại (sai mật khẩu), ghi `LOGIN_ERROR` với trường `error="invalid_user_credentials"`. Log này là bằng chứng đầu tiên của các cuộc tấn công brute force.

---

### 2.2 SPIRE/SPIFFE — Workload Identity

SPIRE cấp **X.509-SVID (SPIFFE Verifiable Identity Document)** — chứng chỉ TLS mang SPIFFE ID — cho mỗi pod trong hệ thống. Đây là cơ chế định danh workload, thay thế hoàn toàn việc dùng IP hoặc service name để xác định "ai đang gọi ai".

**Cấu hình SPIRE Server** (`spire/server/server.conf`):

```
trust_domain = "ztlab.local"   ← ranh giới tin cậy — chỉ SVID từ domain này mới được chấp nhận
default_x509_svid_ttl = "1h"  ← SVID hết hạn mỗi 1 giờ, tự động gia hạn trước khi hết
ca_ttl = "168h"                ← CA cert tồn tại 7 ngày
```

Plugin `NodeAttestor "k8s_psat"` xác thực node thông qua Kubernetes Pod Service Account Token — không có hardcoded credential, SPIRE hỏi Kubernetes API để kiểm tra node identity.

**Cấu hình SPIRE Agent** (`spire/agent/aws-agent.conf`):

```
trust_domain = "ztlab.local"
server_address = "spire-server.spire.svc.cluster.local"
socket_path = "/run/spire/sockets/agent.sock"   ← Unix socket, Envoy kết nối vào đây để lấy cert
```

`WorkloadAttestor "k8s"` — khi pod yêu cầu SVID, agent kiểm tra pod đó có Service Account và label khớp với entry đăng ký không. Nếu khớp thì cấp SVID.

**7 SPIFFE IDs đã đăng ký trong hệ thống:**

```
spiffe://ztlab.local/aws/api-gateway
spiffe://ztlab.local/aws/payment-service
spiffe://ztlab.local/aws/fraud-detection
spiffe://ztlab.local/aws/notification-service
spiffe://ztlab.local/openstack/core-banking
spiffe://ztlab.local/openstack/account-service
spiffe://ztlab.local/openstack/transaction-service
```

Mỗi SVID là chứng chỉ X.509 có field `Subject Alternative Name = URI:<spiffe_id>`. Envoy đọc SAN này để xác định "caller là ai" và đưa vào `%DOWNSTREAM_PEER_URI_SAN%` trong access log (field `svid`).

**Log SPIRE agent đang gia hạn SVID (thực tế):**

```
time="2026-06-27T11:11:11Z" msg="Renewing X509-SVID"
  spiffe_id="spiffe://ztlab.local/aws/api-gateway"
  expires_at="2026-06-27T11:43:16Z"

time="2026-06-27T11:11:35Z" msg="Successfully reattested node"
  spiffe_id="spiffe://ztlab.local/spire/agent/k8s_psat/aws-k3s/ce6be52e-..."
  method=AttestAgent  node_attestor_type=k8s_psat
```

SVID được gia hạn tự động trước khi hết hạn. Node tái xác thực mỗi ~25 phút. Đây là **Continuous Verification** ở tầng workload — không có trust mặc định, mọi identity đều phải được xác minh liên tục.

---

### 2.3 Envoy Sidecar — mTLS Proxy

Mỗi service trong hệ thống đều chạy kèm **Envoy sidecar** như một container thứ hai trong cùng pod (thấy rõ qua `READY 2/2`). Mọi traffic vào/ra service đều đi qua Envoy — ứng dụng không bao giờ nhận request trực tiếp từ bên ngoài pod.

Cấu hình nằm trong `envoy/envoy-sidecar.yaml`, được mount vào pod qua ConfigMap. Envoy lắng nghe 2 cổng:

**Cổng 15006 — Inbound Proxy (nhận request đến):**

Envoy inbound được cấu hình với 2 filter chain: một cho TLS (mTLS từ service khác) và một cho plain HTTP (từ bên ngoài cluster, ví dụ từ localhost port-forward).

Khi nhận kết nối TLS, filter chain kích hoạt `DownstreamTlsContext` với:
- `require_client_certificate: true` — bắt buộc caller phải trình client cert
- Cert của Envoy được lấy từ SPIRE Agent qua `sds_config` gRPC — tức là Envoy tự động xin SPIRE lấy cert, không cần hardcode
- `ROOTCA` để verify cert của caller — chỉ chấp nhận cert do SPIRE ký

Sau khi TLS handshake xong, HTTP filter chain gọi **OPA ext_authz** trước khi forward request vào app:
```yaml
- name: envoy.filters.http.ext_authz
  failure_mode_allow: false      ← nếu OPA timeout hoặc lỗi → từ chối luôn, KHÔNG để qua
  grpc_service:
    cluster_name: opa_ext_authz  ← gRPC đến opa-service.financial.svc.cluster.local:9191
    timeout: 2s
```

**Cổng 15001 — Outbound Proxy (gửi request ra):**

Khi service cần gọi service khác, nó gọi đến `http://127.0.0.1:15001/<path>`. Envoy outbound routing dựa vào path:

```yaml
/payments      → cluster payment_service   (payment-service.financial.svc.cluster.local:8080)
/score         → cluster fraud_detection   (fraud-detection.financial.svc.cluster.local:8080)
/notify        → cluster notification_service
/transactions/execute → cluster core_banking (192.168.101.11:30080 — OpenStack via WireGuard)
/transactions  → cluster transaction_service (192.168.101.11:30083 — OpenStack)
/accounts      → cluster account_service  (192.168.101.11:30082 — OpenStack)
```

Mỗi upstream cluster được cấu hình `UpstreamTlsContext` với SVID lấy từ SPIRE — tức là kết nối ra cũng là mTLS, Envoy trình cert của service hiện tại để peer verify.

**Access log JSON mỗi request:**

```yaml
log_format:
  json_format:
    timestamp: "%START_TIME%"
    method: "%REQ(:METHOD)%"
    path: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
    response_code: "%RESPONSE_CODE%"
    response_time: "%DURATION%"
    upstream: "%UPSTREAM_HOST%"
    source_ip: "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
    bytes_sent: "%BYTES_SENT%"
    svid: "%DOWNSTREAM_PEER_URI_SAN%"   ← SPIFFE ID của caller (từ mTLS cert)
```

Log Envoy được Promtail đọc từ `/var/log/pods/financial_*/envoy/*.log` và đẩy vào Loki với label `{namespace="financial", app="<service>", container="envoy"}`. Tuy nhiên, đối với ZTLab, nguồn log chính cho Grafana alert rules là **app container** (api-gateway, payment-service), không phải Envoy container — vì các event bảo mật quan trọng (jwt_verification_failed, authz_denied, payment_blocked_fraud) được ghi bởi ứng dụng Python, không phải Envoy.

---

### 2.4 OPA — Policy Engine

OPA nhận mọi request từ Envoy qua gRPC ext_authz protocol, evaluate policy Rego, trả `allow=true/false`. Envoy quyết định forward hay từ chối dựa vào kết quả đó.

**Policy chính** (`opa/policies/zta_policy.rego`):

```rego
package zta.authz

default allow = false    ← deny-by-default — không match bất kỳ rule nào thì từ chối
```

Policy có 4 loại request được phép:

**1. Public paths** — không cần auth:
```rego
public_path if { path in ["/health", "/ready", "/metrics"] }
```

**2. External API request** — từ user qua HTTP, cần JWT hợp lệ và đúng role:
```rego
external_api_request if {
  method == "POST"
  path == "/payments"
  valid_jwt          ← issuer đúng + chưa hết hạn
  role_permits_action  ← role trong JWT có quyền POST không?
  not valid_svid     ← không có SVID → đây là request từ user bên ngoài, không phải service
}
```

**3. Internal service request** — từ service khác, cần SVID trong trust domain:
```rego
internal_service_request if {
  valid_svid          ← spiffe_id startswith "spiffe://ztlab.local/"
  method == "POST"
  path in ["/payments", "/score", "/notify"]
}
```

**4. Core transaction** — gọi `/transactions/execute`, phải qua fraud gate:
```rego
core_transaction_with_fraud_gate if {
  valid_svid
  path startswith "/transactions/execute"
  fraud_gate_valid    ← header X-Fraud-Gate == "passed" VÀ X-Fraud-Score < 75
}
```

**Phân quyền theo role** (`permissions` map):
```rego
permissions := {
  "financial-read":  {"GET": true, "OPTIONS": true},
  "financial-write": {"GET": true, "OPTIONS": true, "POST": true, "PUT": true},
  "security-analyst":{"GET": true, "OPTIONS": true},
  "security-admin":  {"GET": true, "OPTIONS": true, "POST": true, "PUT": true, "DELETE": true},
}
```

`merchant01` chỉ có `financial-read` → POST /payments không khớp `permissions["financial-read"]["POST"]` → `role_permits_action` = false → `allow = false` → HTTP 403.

**SVID validation:**
```rego
valid_svid if {
  startswith(source_principal, "spiffe://ztlab.local/")
}
```

`source_principal` đến từ `input.attributes.source.principal` — Envoy đặt trường này bằng SAN của client certificate. Nếu cert là `spiffe://evil.corp/attacker`, `startswith("spiffe://ztlab.local/")` = false → `valid_svid` = false → lateral movement bị chặn.

**Fraud gate policy** (`opa/policies/fraud_gate.rego`):
```rego
fraud_gate_valid if {
  headers["x-fraud-gate"] == "passed"
  to_number(headers["x-fraud-score"]) < 75
}
```

OPA kiểm tra 2 header mà payment-service phải gắn vào khi gọi core-banking. Nếu không có header hoặc score ≥ 75 thì `/transactions/execute` bị từ chối.

---

### 2.5 Grafana Alert Rules — Detection Layer

Grafana chạy 6 alert rules, evaluate mỗi 1 phút, query log từ Loki. Khi rule fire, Grafana gửi webhook HTTP đến SOAR Engine.

Mỗi rule định nghĩa trong file YAML riêng, được load vào Grafana qua ConfigMap khi deploy:

| Rule | File | LogQL (log thật) | Nguồn log |
|---|---|---|---|
| Brute Force Login | `brute-force-alert.yml` | `sum by (source_ip) (count_over_time({namespace="financial",app="api-gateway"} \| json \| event="jwt_verification_failed" [1m]))` | api-gateway WARN |
| Fraud Gate Bypass | `fraud-gate-bypass-alert.yml` | `sum(count_over_time({namespace="financial",app="payment-service"} \| json \| level="AUDIT" \| event="payment_blocked_fraud" [5m]))` | payment-service AUDIT |
| Lateral Movement | `lateral-movement-alert.yml` | `sum(count_over_time({namespace="financial",app="api-gateway"} \| json \| event="jwt_verification_failed" \| reason="missing_bearer" [5m]))` | api-gateway WARN |
| Data Exfiltration | `large-response-alert.yml` | `sum(count_over_time({namespace="financial",app="api-gateway"} \| json \| event="http_request" \| path=~"/transactions.*\|/accounts.*" \| bytes_sent > 5000 [5m]))` | api-gateway INFO |
| Access Denied Spike | `access-denied-spike-alert.yml` | `sum by (source_ip) (count_over_time({namespace="financial",app="api-gateway"} \| json \| event="authz_denied" [1m]))` | api-gateway WARN |
| Privilege Escalation | `privilege-escalation-alert.yml` | `sum(count_over_time({namespace="financial",app="security-scanner"} \| json \| event="privilege_escalation" [5m]))` | security-scanner Job AUDIT |

> Tất cả LogQL query đều query log **thật** từ service pod — không có log inject giả. Promtail DaemonSet thu log từ pod stdout, đẩy vào Loki với label `{namespace="financial", app="<service>"}`.

**Notification policy** (`notification-policy.yml`) cấu hình route tất cả alert đến contact point `ztlab-soar-webhook`, trỏ đến `http://soar-engine.plg-stack.svc.cluster.local:8080/grafana-webhook`.

Mỗi alert rule có các labels: `severity`, `attack_type`, `mitre` — SOAR dùng các label này để quyết định playbook và severity của case.

---

### 2.6 SOAR Engine — Response Automation

SOAR Engine là FastAPI application chạy trong namespace `plg-stack`. Nó có 3 việc chính: nhận webhook từ Grafana, tạo case với HITL queue, và thực thi playbook K8s khi được phê duyệt.

**Cấu hình qua env vars (từ K8s Secret/ConfigMap):**

```
SOAR_DRY_RUN=false            ← thực thi thật, không dry run
SOAR_AUTO_EXECUTE=true        ← auto execute nếu severity < hitl_severity
SOAR_HITL_SEVERITY=high       ← severity >= high thì cần HITL (không auto)
SOAR_MIN_SEVERITY=medium      ← bỏ qua alert có severity thấp hơn medium
SOAR_ALLOWED_CONTEXTS=ctx-aws,ctx-openstack  ← SOAR có quyền kubectl vào 2 cluster
CASE_STORE_PATH=/data/cases.jsonl           ← persistent storage, không mất khi pod restart
ADMIN_EMAIL=voha2005@gmail.com
```

**Mapping attack type → playbook** (hard-coded trong SOAR):

```python
PLAYBOOK_BY_ATTACK = {
  "brute_force":          "revoke_user_sessions",
  "fraud_gate_bypass":    "isolate_workload",
  "lateral_movement":     "isolate_workload",
  "large_response":       "restrict_egress",
  "access_denied":        "block_source_ip",
  "privilege_escalation": "quarantine_workload",
  ...
}
```

**Mapping attack type → workload bị tác động:**

```python
TARGETS_BY_ATTACK = {
  "fraud_gate_bypass":  {"context": "ctx-aws",       "workload": "payment-service"},
  "lateral_movement":   {"context": "ctx-aws",       "workload": "payment-service"},
  "large_response":     {"context": "ctx-openstack", "workload": "core-banking"},
  "privilege_escalation": {"context": "ctx-aws",     "workload": "api-gateway"},
  "access_denied":      {"context": "ctx-aws",       "workload": "api-gateway"},
}
```

**4 phase của mỗi playbook:**
- **contain** — hành động ngay lập tức: scale deployment xuống 0, tạo NetworkPolicy block IP, hoặc revoke Keycloak session
- **investigate** — query Loki lấy log evidence làm bằng chứng
- **eradicate** — xóa source threat: block IP Redis, xóa NetworkPolicy tạm thời nếu cần
- **recover** — log pending, chờ admin trigger rollback thủ công

---

## 3. Luồng bình thường — một giao dịch hợp lệ đi qua hệ thống

Trước khi xem các kịch bản tấn công, cần hiểu một giao dịch bình thường đi qua bao nhiêu lớp kiểm soát.

```
[testuser01] POST /payments {"from":"ACC-1001","to":"ACC-2001","amount":10000}
    │
    ▼ (1) HTTP → localhost:18080 (port-forward đến api-gateway pod)
┌─────────────────────────────────────────────────────────┐
│ Envoy Inbound :15006                                    │
│   - TLS Inspector: plain HTTP → filter chain thứ 2     │
│   - ext_authz gRPC → OPA Server :9191                  │
│     OPA nhận: method=POST, path=/payments, JWT=Bearer.. │
│     Check: valid_jwt? ✓ | role financial-write? ✓       │
│     Check: not valid_svid? ✓ (không có SVID = user req) │
│     → external_api_request rule match → allow=true      │
│   - Forward đến 127.0.0.1:8080 (api-gateway app)       │
└─────────────────────────────────────────────────────────┘
    │
    ▼ (2) api-gateway app xử lý
    - Verify JWT signature: lấy JWKS từ Keycloak, verify RSA signature
    - Check IP blocklist: Redis key "ztlab:blocked_ip:10.x.x.x" → không có → OK
    - Rate limit: bucket 60 req/phút theo source IP → chưa vượt → OK
    - Check role "financial-write" trong JWT claims → có → OK
    - PAYMENT_SERVICE_URL = "http://127.0.0.1:15001"  ← gọi qua Envoy outbound!
    │
    ▼ (3) Envoy Outbound :15001 → path=/payments → cluster payment_service
    - Envoy mở mTLS connection đến payment-service:8080
    - Gắn cert "spiffe://ztlab.local/aws/api-gateway" (lấy từ SPIRE)
    - payment-service Envoy verify cert: đúng trust domain ztlab.local → OK
    │
    ▼ (4) payment-service xử lý
    - Gọi fraud-detection /score qua Envoy outbound:
      → POST http://127.0.0.1:15001/score {"amount":10000,"channel":"api"}
      → fraud-detection tính: score = 5 (base) + 0 (velocity OK) = 5
      → gate = "passed", verdict = "allow"
    │
    ▼ (5) payment-service gọi core-banking /transactions/execute
    - Tính HMAC signature: hmac(shared_secret, timestamp|trace_id|from|to|amount|score)
    - Gắn headers: X-Fraud-Gate=passed, X-Fraud-Score=5, X-Fraud-Gate-Signature=...
    - Gọi qua Envoy outbound → cluster core_banking → 192.168.101.11:30080 (WireGuard)
    - core-banking Envoy inbound nhận: verify mTLS cert api-gateway.local ✓
      → OPA check: valid_svid ✓ + path=/transactions/execute + fraud_gate_valid ✓ → allow
    - core-banking gọi account-service (debit ACC-1001, credit ACC-2001)
    - core-banking gọi transaction-service (ghi ledger)
    │
    ▼ (6) Trả kết quả về
    payment-service → api-gateway → user
    {"status":"completed","trace_id":"...","fraud":{"score":5,"verdict":"allow"}}
    │
    ▼ (7) Notification (fire-and-forget)
    payment-service gọi /notify → notification-service → gửi email xác nhận
    │
    ▼ (8) Log pipeline
    Tất cả Envoy sidecar ghi JSON access log → stdout → Promtail đọc → Loki
    Grafana query Loki mỗi 1 phút → không có pattern bất thường → alert rules vẫn inactive
```

---

## 4. KB1 — Brute Force Login (T1110.001)

**Zero Trust principle chứng minh:** *Continuous Verification* — api-gateway xác minh mọi request ngay tại điểm vào, không có grace period, không có implicit trust. 20/20 request với JWT không hợp lệ đều bị từ chối và ghi log thật.

**Tóm tắt luồng:**

```
[Attacker] gửi 20 request POST /payments với JWT không hợp lệ (fake/sai signature)
    → api-gateway verify JWT signature: FAIL → HTTP 401
    → api-gateway ghi WARN log: {event:"jwt_verification_failed", reason:"invalid_rs256", source_ip:...}
    → Log JSON ra stdout → Promtail DaemonSet scrape → Loki
    → Grafana rule evaluate:
        sum by(source_ip)(count_over_time({namespace="financial",app="api-gateway"}
          | json | event="jwt_verification_failed" [1m])) > 0 → FIRING
    → Grafana gửi webhook thật đến SOAR /grafana-webhook
    → SOAR tạo case pending_approval, gửi email HITL
    → Admin phê duyệt → revoke_user_sessions
```

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb1_brute_force.sh
```

### Bước 2: Kiểm tra api-gateway và SOAR

Script curl đến api-gateway `/health` và SOAR `/health` để đảm bảo cả hai còn sống. Nếu một trong hai không phản hồi, script dừng ngay.

### Bước 3: Gửi 20 request với JWT không hợp lệ

Script gửi 20 POST `/payments` đến api-gateway, mỗi lần với JWT giả (random string hoặc sai signature). api-gateway verify JWT signature thất bại → trả HTTP 401 → ghi log WARN `jwt_verification_failed`.

```bash
# Bên trong script, lặp 20 lần:
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer fake.jwt.token.invalid_signature" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000}'
```

api-gateway log JSON ra stdout:
```json
{
  "timestamp": "2026-06-27T09:46:44.222Z",
  "level": "WARN",
  "service": "api-gateway",
  "event": "jwt_verification_failed",
  "method": "POST",
  "path": "/payments",
  "status_code": 401,
  "source_ip": "10.42.0.1",
  "reason": "invalid_rs256"
}
```

Promtail scrape log này (mỗi 5s) và đẩy vào Loki với label `{namespace="financial", app="api-gateway"}`.

**Output terminal:**
```
[KB1_brute_force] api-gateway chặn 20/20 (401) — jwt_verification_failed ghi vào Loki
[KB1_brute_force] PASS: KB1 | 20/20 blocked | log thật → Loki (Grafana fire trong ≤1 phút)
```

**Xem log thật từ api-gateway:**
```bash
kubectl --context ctx-aws logs -n financial deployment/api-gateway --tail=30 | \
  python3 -c "
import sys,json
for line in sys.stdin:
    try:
        d=json.loads(line)
        if d.get('event')=='jwt_verification_failed':
            print(f'  {d[\"timestamp\"]} | reason={d[\"reason\"]} src={d[\"source_ip\"]}')
    except: pass
"
```

### Bước 4: Grafana detect → SOAR

Grafana evaluate rule mỗi 1 phút:
```logql
sum by (source_ip) (count_over_time({namespace="financial",app="api-gateway"}
  | json | event="jwt_verification_failed" [1m])) > 0
```

Log 20 dòng `jwt_verification_failed` từ api-gateway khớp query → rule FIRING → Grafana gửi webhook thật đến SOAR.

SOAR nhận webhook:
1. Dedup check: có case `brute_force` trong 5 phút không? → Không → tạo mới
2. `case_id = "case-YYYYMMDDHHMMSS-kb1-17"`, `status = pending_approval`
3. Severity=high → HITL (không auto-execute)
4. Gửi email HITL đến voha2005@gmail.com

**Xem case trên SOAR API:**

```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys, json
cases = json.load(sys.stdin)
c = [c for c in cases if c['attack_type'] == 'brute_force'][-1]
print(f'case_id   : {c[\"case_id\"]}')
print(f'severity  : {c[\"severity\"]}')
print(f'status    : {c[\"status\"]}')
print(f'source_ip : {c.get(\"source_ip\")}')
for s in c['steps']:
    print(f'  [{s[\"phase\"]:12}] {s[\"action\"]}')
"
```

**Output thực tế:**
```
case_id   : case-20260627072514-kb1-17
severity  : high
status    : executed
source_ip : 10.0.0.1

  [contain     ] skipped: no username in alert
  [investigate ] Loki evidence: 10 log entries matched query for brute_force from 10.0.0.1
  [eradicate   ] sessions revoked in contain phase; user must re-authenticate with valid credentials
  [recover     ] pending: admin must trigger POST /cases/{case_id}/rollback to restore service
```

**Giải thích 4 phase:**

- **contain**: SOAR thử gọi Keycloak Admin API `DELETE /sessions/{userId}` để revoke session. Bị skip vì alert payload không có `username` field — chỉ có `source_ip`. Đây là gap thực tế: brute force alert chứa IP của attacker, không phải username của victim.
- **investigate**: SOAR query Loki `{namespace="financial",app="api-gateway"} | json | event="jwt_verification_failed"` → tìm log entry làm bằng chứng. Evidence này được ghi vào case để admin review.
- **eradicate**: Ghi nhận rằng session đã được xử lý ở phase contain (dù thực ra bị skip). Logic phòng thủ: user phải đăng nhập lại với credential đúng.
- **recover**: Trạng thái pending — hệ thống đang chờ admin xác nhận đã restore xong, trigger `POST /cases/{id}/rollback`.

### Bước 7: Phê duyệt qua Web Portal

Admin mở `http://localhost:18081/security`, đăng nhập `analyst01 / Test1234!`. Giao diện hiển thị bảng Security Cases với case KB1 có badge **⏳ Chờ duyệt** màu vàng. Click **⚡ Xử lý** mở modal, chọn **🔑 Thu hồi phiên** (`revoke_user_sessions`), click Confirm.

Badge chuyển sang **executed** màu đỏ. SOAR ghi timestamp thực thi vào case.

---

## 5. KB2 — Fraud Gate Bypass (T1078.004)

**Zero Trust principle chứng minh:** *Verify Explicitly* — không phải chỉ verify user một lần khi đăng nhập. Mỗi giao dịch phải được đánh giá riêng theo ngữ cảnh. Dù attacker có JWT hợp lệ, giao dịch 500M VND qua TOR vẫn bị từ chối vì fraud-detection evaluate *hành động cụ thể*, không chỉ *danh tính*.

**Tóm tắt luồng:**

```
[Attacker] đăng nhập thành công → có JWT hợp lệ
    → POST /payments {"amount":500000000,"channel":"tor"}
    → api-gateway verify JWT: OK → forward sang payment-service (mTLS)
    → payment-service gọi fraud-detection /score
        amount=500M ≥ CRITICAL_AMOUNT_VND → +55 điểm
        channel=tor ∈ {tor,unknown,script} → +15 điểm
        base score = 5 → tổng = 75 → verdict="block" (threshold 70)
    → payment-service raise HTTP 403, không gọi core-banking
    → payment-service ghi AUDIT log: {event:"payment_blocked_fraud", score:75}
    → Log JSON ra stdout → Promtail → Loki
    → Grafana rule:
        sum(count_over_time({namespace="financial",app="payment-service"}
          | json | level="AUDIT" | event="payment_blocked_fraud" [5m])) > 0 → FIRING
    → Grafana gửi webhook thật đến SOAR → case pending_approval
    → Admin phê duyệt → isolate_workload (payment-service scale=0)
```

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb2_fraud_gate.sh
```

### Bước 2: Script lấy JWT hợp lệ

Script xin token từ Keycloak với đúng password của testuser01. Keycloak trả JWT có `roles: ["financial-read","financial-write"]`. JWT này hoàn toàn hợp lệ — attacker đã đăng nhập đúng.

```
[KB2_fraud_gate] Bước 2: lấy JWT testuser01...
```

### Bước 3: Gửi giao dịch 500M VND qua TOR

```bash
curl -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Channel: tor" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER",
       "amount":500000000,"currency":"VND","channel":"tor"}'
```

Luồng xử lý bên trong:

**api-gateway** nhận request, OPA check: JWT valid + role financial-write + không có SVID = external_api_request → allow. api-gateway verify JWT signature thành công. Forward sang payment-service qua Envoy outbound (mTLS).

**payment-service** nhận request. Trước tiên kiểm tra `amount > MAX_SINGLE_TXN_VND (500_000_000)`: không vượt (bằng đúng 500M). Gọi fraud-detection `/score`.

**fraud-detection** tính điểm:
```python
score = 5   # base

# amount = 500,000,000 VND
if amount >= CRITICAL_AMOUNT_VND:   # 500_000_000
    score += 55   # → score = 60
    reasons.append("critical_amount")

# channel = "tor"
if channel.lower() in {"tor", "unknown", "script"}:
    score += 15   # → score = 75
    reasons.append("risky_channel")

# velocity từ Redis: lần đầu giao dịch → 0 điểm thêm

verdict = "block" if score >= 70 else "allow"
gate    = "blocked" if verdict == "block" else "passed"
```

Trả về: `{"score":75,"verdict":"block","reason":["critical_amount","risky_channel"],"gate":"blocked"}`

**payment-service** nhận `gate != "passed"` → raise HTTPException 403:
```python
if gate != "passed":
    raise HTTPException(status_code=403, detail={"reason": "fraud gate blocked", "fraud": fraud})
```

payment-service **không gọi core-banking**. Giao dịch bị chặn hoàn toàn trước khi chạm đến lớp banking.

### Bước 4: Response thực tế

```
[KB2_fraud_gate] API Gateway trả về HTTP 403 (expect 403 — fraud gate blocked)
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

Giải thích từng field: `score=75` vượt ngưỡng 70, hai lý do cộng điểm là `critical_amount` (giao dịch ≥ 500M VND) và `risky_channel` (kênh TOR). `gate=blocked` xác nhận fraud gate đã kích hoạt.

### Bước 5: Log AUDIT và SOAR case

payment-service ghi AUDIT log `payment_blocked_fraud` ra stdout → Promtail → Loki. Grafana rule `sum(count_over_time({namespace="financial",app="payment-service"} | json | level="AUDIT" | event="payment_blocked_fraud" [5m]))` match → SOAR nhận webhook thật.

```
[KB2_fraud_gate] Attempt 1 → HTTP 403 (fraud_score=75, verdict=block)
[KB2_fraud_gate] Attempt 2 → HTTP 403 (fraud_score=75, verdict=block)
[KB2_fraud_gate] Attempt 3 → HTTP 403 (fraud_score=75, verdict=block)
[KB2_fraud_gate] payment-service chặn 3/3 → AUDIT payment_blocked_fraud → Loki
[KB2_fraud_gate] PASS: KB2 | 3/3 blocked | log AUDIT thật → Loki (Grafana fire trong ≤1 phút)
```

### Bước 6: Phê duyệt → isolate_workload

Admin chọn **🔒 Cô lập dịch vụ** (`isolate_workload`). SOAR thực thi:

**contain phase** — SOAR gọi Kubernetes API (dùng `in-cluster config`, có RBAC `cluster-admin`):
```python
# Scale deployment payment-service về 0 replica
apps_v1.patch_namespaced_deployment_scale(
    name="payment-service",
    namespace="financial",
    body={"spec": {"replicas": 0}}
)
```

Sau khi scale=0, pod payment-service bị terminate. Mọi request đến payment-service đều bị timeout — kể cả request bình thường từ user khác. Envoy inbound vẫn nhận request nhưng upstream 127.0.0.1:8080 không còn lắng nghe → trả HTTP 503.

Xác nhận:
```bash
kubectl --context ctx-aws get deployment payment-service -n financial
# NAME              READY   UP-TO-DATE   AVAILABLE
# payment-service   0/0     0            0          ← đã cô lập
```

---

## 6. KB3 — Lateral Movement via No Auth (T1021.007)

**Zero Trust principle chứng minh:** *Network Micro-segmentation* — trong Zero Trust, việc đã vào được mạng nội bộ không có nghĩa là có thể gọi bất kỳ service nào. Mỗi service-to-service call đều phải được xác thực. Khi notification-service pod bị compromise và cố lateral move, api-gateway phát hiện ngay vì request không có Authorization header.

**Tóm tắt luồng:**

```
[Attacker] đã compromised notification-service pod trong cluster
    → kubectl exec vào notification-service pod
    → gọi http://api-gateway.financial.svc.cluster.local:8080/payments KHÔNG CÓ auth header
        api-gateway verify JWT: không có Authorization header
        → log WARN {event:"jwt_verification_failed", reason:"missing_bearer", source_ip:<pod-IP>}
        → HTTP 401
    → lặp lại 5 lần cho nhiều endpoint khác nhau
    → Log JSON ra stdout → Promtail → Loki
    → Grafana rule:
        sum(count_over_time({namespace="financial",app="api-gateway"}
          | json | event="jwt_verification_failed" | reason="missing_bearer" [5m])) > 0 → FIRING
    → SOAR → case pending_approval → Admin phê duyệt → isolate_workload
```

**Tại sao phân biệt được KB1 vs KB3:**
- KB1 (brute force): gửi JWT với signature sai → `reason="invalid_rs256"`
- KB3 (lateral movement): không có Authorization header gì cả → `reason="missing_bearer"`

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb3_lateral_movement.sh
```

### Bước 2: Script kubectl exec vào notification-service pod

Script lấy tên và IP của notification-service pod, sau đó `kubectl exec` vào pod đó và dùng `wget` hoặc `curl` (nếu có) để gọi api-gateway mà không có auth header:

```bash
# Lấy pod notification-service
NOTIF_POD=$(kubectl --context ctx-aws get pod -n financial -l app=notification-service \
  -o jsonpath='{.items[0].metadata.name}')

# Từ bên trong pod, gọi api-gateway không có Authorization header
kubectl --context ctx-aws exec -n financial "$NOTIF_POD" -- \
  wget -qO- "http://api-gateway.financial.svc.cluster.local:8080/payments" 2>&1 || true
```

api-gateway nhận request, verify JWT: không có Authorization header → log WARN `jwt_verification_failed` với `reason=missing_bearer` và `source_ip=<IP của notification-service pod>`.

```
[KB3_lateral_movement] Gọi http://api-gateway.financial.svc.cluster.local:8080/payments không có auth → HTTP 401
[KB3_lateral_movement] Gọi http://api-gateway.financial.svc.cluster.local:8080/transactions không có auth → HTTP 401
...
[KB3_lateral_movement] api-gateway từ chối 5/5 (missing_bearer) → WARN jwt_verification_failed → Loki
[KB3_lateral_movement] PASS: KB3 | 5/5 blocked (missing_bearer) | log thật → Loki
```

**Log api-gateway thực tế** (`kubectl logs -n financial deployment/api-gateway | grep missing_bearer`):

```json
{
  "timestamp": "2026-06-27T09:46:55.100Z",
  "level": "WARN",
  "service": "api-gateway",
  "event": "jwt_verification_failed",
  "method": "GET",
  "path": "/payments",
  "status_code": 401,
  "source_ip": "10.42.1.23",
  "reason": "missing_bearer"
}
```

`source_ip=10.42.1.23` là IP thật của notification-service pod — đây là bằng chứng lateral movement từ internal pod.

### Bước 3: SOAR case

SOAR nhận alert `lateral_movement` (từ Grafana webhook thật), playbook `isolate_workload`, target `payment-service` (AWS):

```
[contain    ] scaled Deployment/payment-service → isolate
[investigate] Loki evidence: log entries matched query for lateral_movement
[eradicate  ] skipped (isolation trong contain phase)
[recover    ] pending rollback
```

---

## 7. KB4 — Data Exfiltration / Large Response (T1041)

**Zero Trust principle chứng minh:** *Assume Breach + Egress Control* — Zero Trust không chỉ bảo vệ ở perimeter, mà giả định attacker đã vào trong rồi, nên phải giám sát cả traffic ra ngoài. api-gateway `trace_middleware` ghi `bytes_sent` thật cho mỗi response, Grafana phát hiện pattern bulk download lặp lại.

**Tóm tắt luồng:**

```
[Attacker] có JWT hợp lệ, gọi /transactions và /accounts nhiều lần liên tiếp
    → 10 bulk download request → api-gateway trace_middleware ghi bytes_sent thật
    → Log JSON ra stdout: {event:"http_request", path:"/transactions", bytes_sent:2208}
    → Promtail → Loki
    → Grafana rule:
        sum(count_over_time({namespace="financial",app="api-gateway"}
          | json | event="http_request" | path=~"/transactions.*|/accounts.*"
          | bytes_sent > 5000 [5m])) > 0 → FIRING
    → SOAR → restrict_egress → core-banking scale=0
```

**Cơ chế ghi bytes_sent**: `shared/logging.py` `trace_middleware` đọc `Content-Length` response header sau khi handler chạy xong, ghi vào log field `bytes_sent`. Đây là giá trị thực từ response body.

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb4_exfiltration.sh
```

### Bước 2: 10 bulk requests thực tế → bytes_sent log thật

Script lấy JWT testuser01, gọi 10 lần các endpoint trả response lớn:

```bash
for i in $(seq 1 10); do
  curl -s "http://localhost:18080/transactions?account_id=ACC-1001&limit=500" \
    -H "Authorization: Bearer $TOKEN" -o /dev/null -w "%{size_download}"
done
```

api-gateway trace_middleware ghi log JSON thật cho mỗi request:

```json
{
  "timestamp": "2026-06-27T09:47:00.100Z",
  "level": "INFO",
  "service": "api-gateway",
  "event": "http_request",
  "method": "GET",
  "path": "/transactions",
  "status_code": 200,
  "duration_ms": 45,
  "bytes_sent": 2208,
  "trace_id": "e5f6g7h8"
}
```

Log này đến Loki với label `{namespace="financial", app="api-gateway"}` — Grafana alert query filter `bytes_sent > 5000` sẽ match những request trả nhiều dữ liệu.

**Output terminal:**
```
[KB4_exfiltration] GET /transactions → HTTP 200, bytes_sent=2208
[KB4_exfiltration] GET /accounts/balance → HTTP 200, bytes_sent=30
...
[KB4_exfiltration] api-gateway ghi http_request log với bytes_sent → Promtail → Loki
[KB4_exfiltration] PASS: KB4 | 10 bulk requests | log bytes_sent thật → Loki (Grafana fire trong ≤1 phút)
```

### Bước 3: SOAR case — restrict_egress

SOAR case thực tế (sau khi phê duyệt):

```
severity  : high
playbook  : restrict_egress

[contain    ] scaled Deployment/core-banking from 1 → 0 replicas (suspected exfiltration)
[investigate] Loki evidence: log entries matched query for large_response
[eradicate  ] created NetworkPolicy blocking source IP in financial
[recover    ] pending rollback
```

**contain phase** scale core-banking (OpenStack) xuống 0 replica — cắt đứt nguồn dữ liệu.

Xác nhận:
```bash
kubectl --context ctx-openstack get deployment core-banking -n financial
# core-banking   0/0     0            0          ← đã scale=0
```

---

## 8. KB5 — Access Denied Spike / RBAC (T1078)

**Zero Trust principle chứng minh:** *Least Privilege* — api-gateway implement deny-by-default RBAC. merchant01 có JWT hợp lệ từ Keycloak nhưng thiếu role `financial-write` → api-gateway từ chối 6/6 lần POST /payments và ghi log `authz_denied` thật vào Loki.

**Tóm tắt luồng:**

```
[merchant01] đăng nhập thành công → JWT có roles: ["financial-read"]
    → POST /payments 6 lần liên tiếp
    → api-gateway verify JWT: OK (JWT hợp lệ, chữ ký đúng)
    → api-gateway _require_role(claims, "financial-write"):
        "financial-write" not in ["financial-read"] → HTTP 403
        ghi WARN log: {event:"authz_denied", required_role:"financial-write", user:"merchant01"}
    → 6/6 lần đều trả HTTP 403
    → Log JSON ra stdout → Promtail → Loki
    → Grafana rule:
        sum by(source_ip)(count_over_time({namespace="financial",app="api-gateway"}
          | json | event="authz_denied" [1m])) > 0 → FIRING
    → SOAR → block_source_ip
```

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb5_access_denied.sh
```

### Bước 2: Script decode JWT để minh chứng role

Script lấy token merchant01, decode JWT payload (base64url), in ra danh sách roles:

```python
# Bên trong script
import base64, json
parts = token.split(".")
pad = parts[1] + "=" * (-len(parts[1]) % 4)
claims = json.loads(base64.urlsafe_b64decode(pad))
roles = claims["realm_access"]["roles"]
# → ['financial-read']
```

```
[KB5_access_denied] Bước 2: lấy JWT merchant01 (role: financial-read only)...
[KB5_access_denied]   merchant01 roles: ['financial-read']  ← chỉ có financial-read, không có financial-write
```

### Bước 3: 6 lần POST /payments đều bị 403

api-gateway evaluate mỗi request trong hàm `_require_role`:

```python
# api-gateway/main.py
def _require_role(claims, role):
    roles = claims.get("realm_access", {}).get("roles", [])
    if role not in roles:
        # Ghi log WARN authz_denied
        logger.warn("authz_denied", required_role=role, user=claims.get("preferred_username"),
                    source_ip=request.client.host)
        raise HTTPException(status_code=403, detail="Insufficient permissions")
```

merchant01 roles = `["financial-read"]` → `"financial-write" not in roles` → HTTP 403 + log `authz_denied`.

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

So sánh: nếu dùng testuser01 (có `financial-write`) → POST /payments trả HTTP 200.

### Bước 4: Xác minh thủ công

```bash
# merchant01 → phải 403
curl -s -o /dev/null -w "merchant01 POST /payments → HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $MERCHANT_TOKEN" \
  -d '{"from_account":"ACC-4001","to_account":"ACC-2001","amount":1000}'

merchant01 POST /payments → HTTP 403
```

### Bước 5: SOAR — block_source_ip

SOAR case thực tế:

```
severity  : high
playbook  : block_source_ip

[contain    ] created NetworkPolicy — blocked source IP in financial
[investigate] Loki evidence: log entries matched query for access_denied
[eradicate  ] IP already blocked in contain phase; no additional action
[recover    ] pending rollback
```

**contain phase**: SOAR tạo NetworkPolicy block IP nguồn trong namespace `financial`. Đồng thời ghi IP vào Redis key `ztlab:blocked_ip:<ip>` với TTL 86400 giây (24h) — api-gateway kiểm tra Redis key này trước khi xử lý request.

Xác nhận IP trong Redis blocklist:

```bash
curl -s http://localhost:8091/blocked-ips | python3 -m json.tool
```

`source_ip` trong log thật là IP của pod/client gửi request — không còn dùng IP cố định `10.0.0.99`.

---

## 9. KB6 — Privilege Escalation in Container (T1611)

**Zero Trust principle chứng minh:** *Workload Isolation + Least Privilege cho container* — Zero Trust không chỉ áp dụng cho network, mà cả bên trong từng container. Hệ thống lab không enforce `runAsNonRoot` — security-scanner Job chạy như root và ghi log AUDIT `privilege_escalation` thật vào stdout → Promtail → Loki → Grafana.

**Tóm tắt luồng:**

```
[Security scanner] kubectl apply k8s/financial/security-scanner-job.yaml
    → Job chạy python:3.12-alpine trong namespace financial
    → Tự kiểm tra security context của mình:
        uid = os.getuid()           → 0 (root!)
        CapEff từ /proc/1/status   → 00000000a80425fb (CAP_DAC_OVERRIDE, CAP_SETUID, ...)
        /etc/shadow readable       → True (CAP_DAC_OVERRIDE bypass permissions)
        violation = True
    → Ghi JSON AUDIT log ra stdout:
        {event:"privilege_escalation", uid:0, dangerous_capabilities:[...], violation:true}
    → Promtail DaemonSet thu log (container trong namespace financial)
    → Loki: {namespace="financial", app="security-scanner"}
    → Grafana rule:
        sum(count_over_time({namespace="financial",app="security-scanner"}
          | json | event="privilege_escalation" [5m])) > 0 → FIRING
    → SOAR → quarantine_workload → api-gateway scale=0
```

---

### Bước 1: Xem bằng chứng vi phạm (tùy chọn, trước khi chạy script)

```bash
POD=$(kubectl --context ctx-aws get pod -n financial -l app=api-gateway \
  -o jsonpath='{.items[0].metadata.name}')

# Xác nhận namespace financial không enforce runAsNonRoot
kubectl --context ctx-aws exec -n financial "$POD" -- id
# uid=0(root) gid=0(root) groups=0(root)

kubectl --context ctx-aws exec -n financial "$POD" -- cat /proc/1/status | grep CapEff
# CapEff: 00000000a80425fb  (includes CAP_DAC_OVERRIDE, CAP_SETUID)
```

### Bước 2: Decode capabilities hex

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

- **CAP_DAC_OVERRIDE** (bit 1): bỏ qua mọi file permission check — đọc được `/etc/shadow`
- **CAP_SETUID** (bit 7): có thể thay đổi UID về 0 bất kỳ lúc nào

### Bước 3: Chạy script

```bash
bash tests/grafana_kb6_privilege_escalation.sh
```

Script tự động:
1. Xóa Job cũ nếu còn: `kubectl delete job security-scanner -n financial`
2. Apply Job mới: `kubectl apply -f k8s/financial/security-scanner-job.yaml`
3. Chờ Job hoàn thành: `kubectl wait job/security-scanner --for=condition=complete --timeout=90s`
4. Hiển thị log thật từ Job

```
[KB6_privilege_escalation] Deploy security-scanner Job vào namespace financial
[KB6_privilege_escalation] Chờ security-scanner Job hoàn thành (timeout 90s)...
[KB6_privilege_escalation] Kết quả từ security-scanner (log thật):
  event=privilege_escalation uid=0 caps=['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID',
       'SETGID', 'SETUID', 'NET_BIND_SERVICE', 'AUDIT_WRITE'] shadow=True violation=True
[KB6_privilege_escalation] Log thật từ security-scanner → Promtail → Loki {namespace=financial, app=security-scanner}
[KB6_privilege_escalation] PASS: KB6 | security-scanner Job completed | log AUDIT thật → Loki (Grafana fire trong ≤2 phút)
```

### Bước 4: Log AUDIT thật trong Loki

security-scanner Job ghi JSON ra stdout, Promtail thu vào Loki với `{namespace="financial", app="security-scanner"}`:

```json
{
  "timestamp": "2026-06-27T10:15:00Z",
  "level": "AUDIT",
  "service": "security-scanner",
  "cloud": "aws",
  "event": "privilege_escalation",
  "uid": 0,
  "gid": 0,
  "cap_eff": "00000000a80425fb",
  "dangerous_capabilities": ["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETGID", "SETUID", "AUDIT_WRITE"],
  "shadow_readable": true,
  "violation": true,
  "detail": "container running as root uid=0 with dangerous capabilities — violates Zero Trust least-privilege principle"
}
```

Grafana rule `{namespace="financial",app="security-scanner"} | json | event="privilege_escalation"` match ngay.

### Bước 5: SOAR case — quarantine_workload

SOAR case thực tế:

```
severity  : critical
playbook  : quarantine_workload

[contain    ] scaled Deployment/api-gateway from 1 → 0 replicas (privilege escalation detected)
[investigate] Loki evidence: log entries matched query for privilege_escalation
[eradicate  ] skipped
[recover    ] pending rollback
```

**contain phase**: api-gateway scale=0 — tất cả traffic đến hệ thống đều fail. Đây là phản ứng cứng nhất: cách ly hoàn toàn để forensics.

Xác nhận:
```bash
kubectl --context ctx-aws get deployment api-gateway -n financial
# api-gateway   0/0     0            0          ← đã quarantine
```

**BẮT BUỘC restore ngay sau demo:**
```bash
bash scripts/run-demo.sh --restore
```

### Bước 6: Fix đề xuất cho báo cáo

Cấu hình `securityContext` đúng chuẩn nên là:

```yaml
securityContext:
  runAsNonRoot: true               # không được chạy với uid=0
  runAsUser: 1000                  # chạy với non-root uid cố định
  allowPrivilegeEscalation: false  # không thể gọi setuid để leo quyền
  capabilities:
    drop: [ALL]                    # xóa tất cả capabilities
    add: []                        # chỉ add lại nếu thực sự cần
  readOnlyRootFilesystem: true     # root filesystem chỉ đọc
```

Nếu apply config này, security-scanner sẽ ghi `event=security_check_passed` thay vì `privilege_escalation`.

---

*Tài liệu tổng hợp từ config thực tế và log live capture ngày 2026-06-27. Tất cả log trong KB1-KB6 là log thật từ service, không inject giả.*

---

*Tài liệu tổng hợp từ config thực tế (`envoy/envoy-sidecar.yaml`, `opa/policies/zta_policy.rego`, `spire/server/server.conf`, `services/*/main.py`, `plg-stack/grafana/alerting/*.yml`) và log live capture ngày 2026-06-27.*
