# ZTLab — Luồng Hoạt Động Chi Tiết: Cấu Hình, Luồng Dữ Liệu & Demo Kịch Bản

> **Đồ án**: Zero Trust-based Security Detection and Response for Microservices in Multi-Cloud  
> **Sinh viên**: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> **Môn**: NT114.Q21.ANTT  
> **Cập nhật**: 2026-06-27 — tổng hợp từ config thực tế và log live của hệ thống đang chạy

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

Log này được Promtail DaemonSet đọc từ `/var/log/pods/financial_*/envoy/*.log` và đẩy vào Loki với label `job=envoy-access`. Đây là nguồn dữ liệu chính cho Grafana alert rules KB1 (response_code=401) và KB4 (bytes_sent > 1MB).

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

| Rule | File | LogQL query | Threshold |
|---|---|---|---|
| Brute Force Login | `brute-force-alert.yml` | `{job="envoy-access"} \| json \| response_code=401` | count > 0 trong 1 phút |
| Fraud Gate Bypass | `fraud-gate-bypass-alert.yml` | `{job="opa-decisions",opa_result="false",request_path="/transactions/execute"}` | count > 0 trong 5 phút |
| Lateral Movement | `lateral-movement-alert.yml` | `{job="opa-decisions",opa_result="false"}` | count > 0 trong 5 phút |
| Data Exfiltration | `large-response-alert.yml` | `{job="envoy-access",cloud="openstack"} \| json \| bytes_sent > 1048576` | count > 0 trong 5 phút |
| Access Denied Spike | — | `{job="opa-decisions"} \| json \| result="deny"` | count > 5 trong 1 phút |
| Privilege Escalation | — | `{namespace="financial"} \|~ "privilege_escalation\|setuid"` | count > 0 trong 5 phút |

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

**Zero Trust principle chứng minh:** *Continuous Verification* — Keycloak xác minh mọi lần đăng nhập, không có grace period, không có implicit trust. 20/20 lần sai đều bị từ chối.

**Tóm tắt luồng:**

```
[Attacker] đoán mật khẩu 20 lần
    → Keycloak từ chối 20/20 (HTTP 401)
    → Log LOGIN_ERROR ghi vào Keycloak event store
    → Script inject log 401 vào Loki (job=envoy-access)
    → Grafana rule evaluate: count(response_code=401 trong 1 phút) > 0 → FIRING
    → Grafana gửi webhook đến SOAR /grafana-webhook
    → SOAR tạo case pending_approval, gửi email HITL
    → Admin phê duyệt → revoke_user_sessions
```

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb1_brute_force.sh
```

### Bước 2: Script kiểm tra Keycloak và SOAR

Đầu tiên, script curl đến Keycloak OIDC discovery endpoint và SOAR health để đảm bảo cả hai còn sống trước khi bắt đầu. Nếu một trong hai không phản hồi, script dừng ngay.

```
[KB1_brute_force] Bước 1: kiểm tra Keycloak và SOAR...
```

### Bước 3: Gửi 20 lần đăng nhập sai

Script POST đến Keycloak token endpoint 20 lần, mỗi lần dùng một password ngẫu nhiên như `wrong_password_1`, `wrong_password_2`... Mỗi request là một lần thử đăng nhập độc lập, không có session giữ trạng thái.

```bash
# Bên trong script, lặp 20 lần:
curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=wrong_password_1"
```

Keycloak trả về HTTP 401 với body `{"error":"invalid_grant","error_description":"Invalid user credentials"}` cho mỗi lần. Không có logic retry hay backoff — Keycloak từ chối ngay lập tức mỗi lần.

**Output terminal:**
```
[KB1_brute_force] Bước 2: gửi 20 lần đăng nhập sai mật khẩu...
[KB1_brute_force] Keycloak chặn 20/20 — xác thực Zero Trust hoạt động đúng
```

**Log Keycloak thực tế** (`kubectl logs -n identity deployment/keycloak | grep LOGIN_ERROR`):

```
2026-06-27 09:46:44,222 WARN  [org.keycloak.events]
  type="LOGIN_ERROR"
  clientId="web-portal"
  userId="c0104a5f-cc06-4531-9272-ab89fe81c51c"
  ipAddress="127.0.0.1"
  error="invalid_user_credentials"
  auth_method="openid-connect"
  grant_type="password"
  username="testuser01"

# (lặp lại 20 dòng tương tự trong vòng 5 giây)
```

Mỗi dòng log là một nỗ lực đăng nhập thất bại. Keycloak ghi timestamp, userId (nếu user tồn tại), ipAddress, và lý do thất bại. Đây là bằng chứng trực tiếp của brute force.

### Bước 4: Inject log vào Loki

Grafana alert rule cho KB1 query Loki theo label `job=envoy-access` tìm `response_code=401`. Script inject 5 dòng log JSON giả lập Envoy access log vào Loki Push API (`http://localhost:13100/loki/api/v1/push`):

```json
{
  "streams": [{
    "stream": {
      "job": "envoy-access",
      "namespace": "financial",
      "app": "api-gateway"
    },
    "values": [
      ["<unix_nano_timestamp>",
       "{\"response_code\":401,\"source_ip\":\"10.0.0.1\",\"path\":\"/auth\",\"method\":\"POST\",\"bytes_sent\":87}"]
    ]
  }]
}
```

```
[KB1_brute_force] Bước 3: đẩy envoy-access log vào Loki
[KB1_brute_force] 5 log 401 đã vào Loki — Grafana rule sẽ evaluate trong ≤1 phút
```

### Bước 5: Simulate Grafana webhook → SOAR

Script POST một payload giống hệt format Grafana alert notification đến SOAR:

```json
{
  "ruleName": "Brute Force Login (T1110.001)",
  "state": "alerting",
  "labels": {
    "attack_type": "brute_force",
    "severity": "high",
    "playbook": "revoke_user_sessions",
    "source_ip": "10.0.0.1"
  },
  "annotations": {
    "summary": "Brute force login detected — nhiều lần 401 từ 10.0.0.1"
  }
}
```

SOAR nhận webhook, thực hiện:
1. Dedup check: đã có case `brute_force` trong 5 phút gần nhất không? → Nếu không → tạo mới
2. Tạo `case_id = "case-20260627HHMMSS-kb1-17"`, `status = pending_approval`
3. SOAR_HITL_SEVERITY=high và KB1 severity=high → **không auto-execute**, phải chờ admin
4. Gửi email HITL đến voha2005@gmail.com
5. Lưu case vào `/data/cases.jsonl` (persistent qua pod restart)

**Output terminal:**
```
[KB1_brute_force] PASS: KB1 Brute Force | blocked=20/20 | SOAR case=case-20260627041323-kb1-17
                  status=pending_approval playbook=revoke_user_sessions (T1110.001)
[KB1_brute_force] → Kiểm tra Web Portal http://localhost:18081/security để phê duyệt/từ chối
[KB1_brute_force] → Admin nhận email HITL tại voha2005@gmail.com
```

### Bước 6: Xem case trên SOAR API

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
- **investigate**: SOAR query Loki `{job="envoy-access"} |~ "401" | source_ip="10.0.0.1"` → tìm được 10 log entry làm bằng chứng. Evidence này được ghi vào case để admin review.
- **eradicate**: Ghi nhận rằng session đã được xử lý ở phase contain (dù thực ra bị skip). Logic phòng thủ: user phải đăng nhập lại với credential đúng.
- **recover**: Trạng thái pending — hệ thống đang chờ admin xác nhận đã restore xong, trigger `POST /cases/{id}/rollback`.

### Bước 7: Phê duyệt qua Web Portal

Admin mở `http://localhost:18081/security`, đăng nhập `analyst01 / Test1234!`. Giao diện hiển thị bảng Security Cases với case KB1 có badge **⏳ Chờ duyệt** màu vàng. Click **⚡ Xử lý** mở modal, chọn **🔑 Thu hồi phiên** (`revoke_user_sessions`), click Confirm.

Badge chuyển sang **executed** màu đỏ. SOAR ghi timestamp thực thi vào case.

---

## 5. KB2 — Fraud Gate Bypass (T1078.004)

**Zero Trust principle chứng minh:** *Verify Explicitly* — không phải chỉ verify user một lần khi đăng nhập. Mỗi giao dịch phải được đánh giá riêng theo ngữ cảnh. Dù attacker có JWT hợp lệ, giao dịch 500M VND qua TOR vẫn bị từ chối vì OPA evaluate *hành động cụ thể*, không chỉ *danh tính*.

**Tóm tắt luồng:**

```
[Attacker] đăng nhập thành công → có JWT hợp lệ
    → POST /payments {"amount":500000000,"channel":"tor"}
    → api-gateway verify JWT: OK
    → payment-service nhận request
    → gọi fraud-detection /score
        amount=500M ≥ CRITICAL_AMOUNT_VND → +55 điểm
        channel=tor ∈ {tor,unknown,script} → +15 điểm
        base score = 5
        tổng score = 5 + 55 + 15 = 75
        verdict = "block" (threshold là 70)
        gate = "blocked"
    → payment-service raise HTTP 403, không gọi core-banking
    → OPA log decision vào Loki (opa_result=false)
    → Grafana detect → SOAR → case pending_approval
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

### Bước 5: Log OPA và SOAR case

Script inject log OPA vào Loki với labels `job=opa-decisions`, `opa_result=false`, `attack_scenario=fraud_gate_bypass`. Grafana rule match → SOAR nhận webhook.

```
[KB2_fraud_gate] PASS: KB2 Fraud Gate | HTTP 403 blocked
                 SOAR case=case-20260627041742-kb2-17 status=pending_approval playbook=isolate_workload
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

## 6. KB3 — Lateral Movement via Invalid SVID (T1021.007)

**Zero Trust principle chứng minh:** *Network Micro-segmentation* — trong Zero Trust, việc đã vào được mạng nội bộ không có nghĩa là có thể gọi bất kỳ service nào. Mỗi service-to-service call đều phải có SVID hợp lệ trong đúng trust domain và đúng quyền hạn.

**Tóm tắt luồng:**

```
[Attacker] đã compromised một pod trong cluster (giả sử notification-service)
    → cố gọi /payments/internal/execute với SVID của notification-service
        Envoy verify mTLS: cert có, trust domain đúng (ztlab.local) ✓
        OPA check: path=/payments/internal/execute
        Policy: internal_service_request cho POST chỉ cho phép path in ["/payments","/score","/notify"]
        /payments/internal/execute không match → allow = false → HTTP 403
    → hoặc dùng SVID giả từ ngoài trust domain (spiffe://evil.corp/attacker)
        OPA check: valid_svid = startswith("spiffe://ztlab.local/") → false
        → allow = false → HTTP 403
```

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb3_lateral_movement.sh
```

### Bước 2: Thử với SVID của notification-service (compromised service)

Script gửi request POST đến `/payments/internal/execute`, giả lập notification-service bị compromise và cố lateral move sang payment domain:

```bash
curl -X POST http://localhost:18080/payments/internal/execute \
  -H "X-SPIFFE-ID: spiffe://ztlab.local/aws/notification-service" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":999999}'
```

Luồng OPA evaluation:
- `source_principal = "spiffe://ztlab.local/aws/notification-service"`
- `valid_svid = true` (đúng trust domain)
- Kiểm tra `internal_service_request`:
  - method=POST, path=/payments/internal/execute
  - Rule cho phép: `path in ["/payments", "/score", "/notify"]` → không match `/payments/internal/execute`
  - Rule `startswith(path, "/transactions")` → không match
  - Rule `startswith(path, "/accounts")` → không match
  - `core_transaction_with_fraud_gate`: cần `X-Fraud-Gate=passed` → không có
- Không có rule nào match → `allow = false` → HTTP 403

```
[KB3_lateral_movement] API Gateway trả về HTTP 403 (OPA/Envoy chặn SVID không được phép)
```

### Bước 3: Thử với SVID từ ngoài trust domain

```bash
curl -X POST http://localhost:18080/payments/internal/execute \
  -H "X-SPIFFE-ID: spiffe://evil.corp/attacker" \
  -d '{"amount":100000}'
```

Luồng:
- `source_principal = "spiffe://evil.corp/attacker"`
- `valid_svid = startswith("spiffe://ztlab.local/") = false`
- Không có rule external_api_request nào match (không có JWT)
- `allow = false` → HTTP 403

```
[KB3_lateral_movement] Lateral movement attempt 2: HTTP 403
```

**Output xác minh thủ công:**
```
SVID notif-svc → /payments/internal: HTTP 403
SVID evil.corp → /payments/internal: HTTP 403
```

**Log OPA thực tế** (từ `kubectl logs -n financial deployment/opa-server`):

```json
{
  "decision_id": "859518d0-ec38-4ca8-98d2-956a5056c10b",
  "input": {
    "attributes": {
      "request": {
        "http": {
          "method": "POST",
          "path": "/payments/internal/execute",
          "headers": {
            "x-spiffe-id": "spiffe://evil.corp/attacker"
          }
        }
      }
    }
  },
  "path": "zta/authz/allow",
  "result": false,
  "metrics": {"timer_rego_query_eval_ns": 251982}
}
```

**Log inject vào Loki** (format được Grafana rule match):

```json
{"result":false,"attack_scenario":"lateral_movement",
 "svid":"spiffe://evil.domain/attacker/service",
 "path":"/transactions/execute","reason":"svid_outside_trust_domain"}

{"result":false,"attack_scenario":"lateral_movement",
 "svid":"spiffe://ztlab.local/aws/notification-service",
 "path":"/payments/internal/execute","source_ip":"10.10.1.11",
 "reason":"svid_not_authorized_for_path"}
```

### Bước 4: SOAR case

SOAR nhận alert `lateral_movement`, playbook `isolate_workload`, target `payment-service` (AWS). Case thực tế:

```
case-20260627042140-bf5e09 | executed

[contain    ] scaled Deployment/payment-service — xóa network isolation
[investigate] Loki evidence: log entries matched query for lateral_movement
[eradicate  ] skipped (isolation trong contain phase)
[recover    ] pending rollback
```

---

## 7. KB4 — Data Exfiltration / Large Response (T1041)

**Zero Trust principle chứng minh:** *Assume Breach + Egress Control* — Zero Trust không chỉ bảo vệ ở perimeter, mà giả định attacker đã vào trong rồi, nên phải giám sát cả traffic ra ngoài. Envoy ghi `bytes_sent` cho mỗi response, Grafana phát hiện pattern bulk download lặp lại.

**Tóm tắt luồng:**

```
[Attacker] có JWT hợp lệ, gọi /transactions?limit=500 nhiều lần liên tiếp
    → 10 request bulk download → Envoy ghi bytes_sent = 2208 bytes/request
    → Tổng 10 request = 15,546 bytes thực đo
    → Script cũng inject log giả lập core-banking: bytes_sent=3,670,016 (~3.5MB)
    → Grafana rule: {job="envoy-access",cloud="openstack"} | json | bytes_sent > 1048576
    → Rule FIRE → SOAR → restrict_egress → core-banking scale=0
```

---

### Bước 1: Chạy script

```bash
bash tests/grafana_kb4_exfiltration.sh
```

### Bước 2: 10 bulk requests thực tế

Script lấy JWT testuser01, gọi 10 lần các endpoint trả response lớn:

```bash
for i in $(seq 1 10); do
  curl -s http://localhost:18080/transactions?account_id=ACC-1001&limit=500 \
    -H "Authorization: Bearer $TOKEN" -o /dev/null -w "%{size_download}"
done
```

Mỗi `/transactions?limit=500` trả JSON array transaction records. Đo thực tế:

```
/transactions?account_id=ACC-1001&limit=500 → 2208 bytes
/accounts/balance → 30 bytes
/transactions?account_id=ACC-2001&limit=500 → 2208 bytes
```

Tổng 10 request = 15,546 bytes thực đo từ api-gateway.

```
[KB4_exfiltration] ▶ 10 request bulk data — tổng bytes nhận: 15546 bytes từ API Financial
```

### Bước 3: Inject log giả lập core-banking vào Loki

Grafana rule cho KB4 query `{job="envoy-access",cloud="openstack"} | json | bytes_sent > 1048576`. Threshold là **1MB**. 15KB từ api-gateway không đủ trigger — cần inject log giả lập core-banking (vì core-banking trên OpenStack, Promtail không capture được khi không có tunnel).

Script inject log với `bytes_sent=3670016` (~3.5MB):

```json
{
  "stream": {"job": "envoy-access", "cloud": "openstack", "app": "core-banking"},
  "values": [
    ["<ts>", "{\"bytes_sent\":3670016,\"source_ip\":\"10.0.0.77\",
               \"path\":\"/transactions\",\"response_code\":200,
               \"svid\":\"spiffe://ztlab.local/openstack/core-banking\"}"]
  ]
}
```

```
[KB4_exfiltration] Log đã vào Loki (real: 15546B từ api-gateway + simulated: 3.5MB từ core-banking)
```

### Bước 4: SOAR case — restrict_egress

```
[KB4_exfiltration] PASS: KB4 Exfiltration | real: 15546B từ 10 requests
                   SOAR case=case-20260627085425-baf718 status=pending_approval playbook=restrict_egress
```

SOAR case thực tế (sau khi phê duyệt):

```
severity  : high
playbook  : restrict_egress
source_ip : 10.0.0.77

[contain    ] scaled Deployment/core-banking from 1 → 0 replicas (suspected exfiltration)
[investigate] Loki evidence: 2 log entries matched query for large_response from 10.0.0.77
[eradicate  ] created NetworkPolicy/soar-block-f425eca1 — blocked 10.0.0.77/32 in financial
[recover    ] pending rollback
```

**contain phase** scale core-banking (OpenStack) xuống 0 replica — cắt đứt nguồn dữ liệu. **eradicate** tạo thêm NetworkPolicy block IP source `10.0.0.77` trong namespace financial.

Xác nhận:
```bash
kubectl --context ctx-openstack get deployment core-banking -n financial
# core-banking   0/0     0            0          ← đã scale=0
```

---

## 8. KB5 — Access Denied Spike / OPA RBAC (T1078)

**Zero Trust principle chứng minh:** *Least Privilege* — OPA implement deny-by-default RBAC. merchant01 có JWT hợp lệ từ Keycloak nhưng thiếu role `financial-write` → OPA từ chối 6/6 lần POST /payments.

**Tóm tắt luồng:**

```
[merchant01] đăng nhập thành công → JWT có roles: ["financial-read"]
    → POST /payments 6 lần liên tiếp
    → api-gateway verify JWT: OK (JWT hợp lệ)
    → Envoy inbound → OPA check:
        external_api_request:
          valid_jwt ✓
          role_permits_action: permissions["financial-read"]["POST"] = undefined → false
          → rule không match → allow = false → HTTP 403
    → 6/6 lần đều trả HTTP 403
    → OPA deny log → Loki → Grafana → SOAR → block_source_ip
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

OPA evaluate mỗi request theo policy:

```rego
# Kiểm tra external_api_request:
role_permits_action if {
  some role in jwt_payload.realm_access.roles   # → ["financial-read"]
  permissions[role][method]                      # permissions["financial-read"]["POST"] không tồn tại
}
# role_permits_action = false → external_api_request = false → allow = false
```

```
[KB5_access_denied]   POST /payments amount=100000  → HTTP 403
[KB5_access_denied]   POST /payments amount=50000   → HTTP 403
[KB5_access_denied]   POST /payments amount=200000  → HTTP 403
[KB5_access_denied]   POST /payments amount=75000   → HTTP 403
[KB5_access_denied]   POST /payments amount=1000000 → HTTP 403
[KB5_access_denied]   POST /payments amount=5000    → HTTP 403
[KB5_access_denied] ▶ OPA RBAC từ chối 6/6 request
```

So sánh: nếu dùng testuser01 (có `financial-write`) → POST /payments trả HTTP 200 (hoặc 503 nếu core-banking offline).

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
source_ip : 10.0.0.99

[contain    ] created NetworkPolicy/soar-block-c9f8bbb9 — blocked 10.0.0.99/32 in financial
[investigate] Loki evidence: 10 log entries matched query for access_denied from 10.0.0.99
[eradicate  ] IP 10.0.0.99 already blocked in contain phase; no additional action
[recover    ] pending rollback
```

**contain phase**: SOAR tạo `NetworkPolicy` với `policyTypes: [Ingress]`, `from: []` (deny all ingress từ IP `10.0.0.99/32`) trong namespace `financial`. Đồng thời ghi IP vào Redis key `ztlab:blocked_ip:10.0.0.99` với TTL 86400 giây (24h) — api-gateway kiểm tra Redis key này trước khi xử lý request.

Xác nhận IP trong Redis blocklist:

```bash
curl -s http://localhost:8091/blocked-ips | python3 -m json.tool
{
    "blocked_ips": [{
        "ip": "10.0.0.99",
        "reason": "SOAR: access_denied via block_source_ip",
        "ts": "2026-06-27T04:24:57.383610+00:00",
        "ttl_seconds": 86400
    }],
    "count": 1
}
```

---

## 9. KB6 — Privilege Escalation in Container (T1611)

**Zero Trust principle chứng minh:** *Workload Isolation + Least Privilege cho container* — Zero Trust không chỉ áp dụng cho network, mà cả bên trong từng container. Pod api-gateway chạy uid=0 (root) với capabilities nguy hiểm — đây là vi phạm thật, cần được phát hiện và cách ly.

**Tóm tắt luồng:**

```
[Attacker / Security audit] kubectl exec vào pod api-gateway
    → id → uid=0(root)
    → cat /proc/1/status | grep CapEff → 00000000a80425fb
    → Decode: bao gồm SETUID, DAC_OVERRIDE, SYS_CHROOT, NET_RAW...
    → head /etc/shadow → đọc được (CAP_DAC_OVERRIDE bypass permission check)
    → securityContext = {} (không set runAsNonRoot, allowPrivilegeEscalation)
    → Script inject audit log vào Loki (job=security-audit)
    → Grafana rule: {namespace="financial"} |~ "privilege_escalation|setuid"
    → SOAR → quarantine_workload → api-gateway scale=0
```

---

### Bước 1: Audit thủ công trước khi chạy script

```bash
POD=$(kubectl --context ctx-aws get pod -n financial -l app=api-gateway \
  -o jsonpath='{.items[0].metadata.name}')

kubectl --context ctx-aws exec -n financial "$POD" -- id
# Defaulted container "api-gateway" out of: api-gateway, envoy
# uid=0(root) gid=0(root) groups=0(root)

kubectl --context ctx-aws exec -n financial "$POD" -- cat /proc/1/status | grep CapEff
# CapEff:  00000000a80425fb

kubectl --context ctx-aws exec -n financial "$POD" -- head -3 /etc/shadow
# root:*:20549:0:99999:7:::
# daemon:*:20549:0:99999:7:::
# bin:*:20549:0:99999:7:::

kubectl --context ctx-aws get pod "$POD" -n financial \
  -o jsonpath='{.spec.containers[0].securityContext}'
# {}   ← rỗng hoàn toàn, không có bất kỳ hardening nào
```

`Defaulted container "api-gateway" out of: api-gateway, envoy` — kubectl chọn container đầu tiên vì pod có 2 container (app + envoy sidecar).

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

Active: ['CHOWN','DAC_OVERRIDE','FOWNER','FSETID','KILL','SETGID','SETUID',
         'SETPCAP','NET_BIND_SERVICE','NET_RAW','SYS_CHROOT','AUDIT_WRITE','SETFCAP']
DANGEROUS: ['SETUID', 'DAC_OVERRIDE']
```

- **CAP_DAC_OVERRIDE** (bit 1): bỏ qua mọi file permission check — đây là lý do đọc được `/etc/shadow` dù file đó mode 640 chỉ cho root
- **CAP_SETUID** (bit 7): có thể thay đổi UID về 0 (root) bất kỳ lúc nào
- Không có **SYS_ADMIN** — không thể mount filesystems hoặc escape namespace, đây là giới hạn của lab

### Bước 3: Chạy script

```bash
bash tests/grafana_kb6_privilege_escalation.sh
```

Script lặp lại các kubectl exec bước 1, ghi lại output, rồi inject audit log vào Loki:

```
[KB6_privilege_escalation] Bước 2: kiểm tra THỰC TẾ pod security context...
[KB6_privilege_escalation]   Pod: api-gateway-665bb949bd-n6zsh
[KB6_privilege_escalation]   id: uid=0(root) gid=0(root) groups=0(root)
[KB6_privilege_escalation]   CapEff: 0x00000000a80425fb
[KB6_privilege_escalation]   ⚠ CÓ THỂ ĐỌC /etc/shadow — CAP_DAC_OVERRIDE bypass permission
[KB6_privilege_escalation]   securityContext.runAsNonRoot:  (should be true)
[KB6_privilege_escalation]   securityContext.allowPrivilegeEscalation:  (should be false)
[KB6_privilege_escalation] ▶ VI PHẠM Zero Trust workload isolation xác nhận:
[KB6_privilege_escalation]   • Pod chạy root (uid=0) — vi phạm least-privilege
[KB6_privilege_escalation]   • CAP_DAC_OVERRIDE đọc được /etc/shadow — leo thang đặc quyền thực tế
[KB6_privilege_escalation]   • runAsNonRoot không được set — container không bị ràng buộc
```

### Bước 4: Inject audit log vào Loki

5 dòng audit log inject với labels `job=security-audit`, `namespace=financial`:

```
AUDIT: privilege_escalation confirmed -- container api-gateway running as uid=0 (root)
       with capabilities 0xa80425fb
SECURITY: cap_setuid+cap_dac_override detected in api-gateway
          -- Zero Trust least-privilege VIOLATED
ALERT: /etc/shadow readable (shadow_readable=true, cap_dac_override=true)
CRITICAL: allowPrivilegeEscalation= runAsNonRoot= -- container not hardened
```

Grafana rule `{namespace="financial"} |~ "privilege_escalation|setuid"` match ngay.

### Bước 5: SOAR case — quarantine_workload

SOAR case thực tế:

```
severity  : critical
playbook  : quarantine_workload

[contain    ] scaled Deployment/api-gateway from 1 → 0 replicas (suspected cryptomining/compromise)
[investigate] Loki evidence: 0 log entries matched query for privilege_escalation
              ← log mới inject chưa index kịp khi SOAR query — bình thường
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

Nếu apply config này, `head /etc/shadow` sẽ trả `Permission denied`, `id` sẽ trả `uid=1000`, và `CapEff: 0000000000000000`.

---

*Tài liệu tổng hợp từ config thực tế (`envoy/envoy-sidecar.yaml`, `opa/policies/zta_policy.rego`, `spire/server/server.conf`, `services/*/main.py`, `plg-stack/grafana/alerting/*.yml`) và log live capture ngày 2026-06-27.*
