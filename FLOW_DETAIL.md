# ZTLab — Luồng Hoạt Động Chi Tiết: Cấu Hình, Luồng Dữ Liệu & Demo Kịch Bản

> **Đồ án**: Zero Trust-based Security Detection and Response for Microservices in Multi-Cloud
> **Sinh viên**: Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)
> **Môn**: NT114.Q21.ANTT
> **Viết lần đầu**: 2026-06-28 — **Viết lại toàn bộ, đối chiếu source + log thật**: 2026-08-20

## Về lần viết lại này

Bản 28/06 mô tả một phiên bản cũ của hệ thống. Sau nhiều lần destroy/redeploy và chỉnh sửa code (đặc biệt là script `tests/grafana_kb3_lateral_movement.sh` viết lại hoàn toàn cơ chế tấn công, và Keycloak client `web-portal` bị khoá direct-access-grant vì lý do hardening), bản cũ còn nhiều chỗ mô tả sai — không phải lệch số liệu nhỏ mà lệch cả **cơ chế kỹ thuật** (ví dụ KB1, KB3 thực tế chặn ở tầng OPA/Envoy chứ không phải ở tầng ứng dụng như bản cũ mô tả). Toàn bộ nội dung dưới đây được viết lại bằng cách đọc trực tiếp source code hiện tại (`opa/policies/*.rego`, `services/*/main.py`, `k8s/plg-stack/grafana.../*.yml`, `spire/*.conf`, `k8s/keycloak/realm-config.json`) và đối chiếu với log thật truy vấn từ Loki trong lần chạy demo ngày 2026-08-20 (xem [SYSTEM_EVALUATION.md](SYSTEM_EVALUATION.md) để biết số liệu tổng hợp/so sánh mô hình).

**Lưu ý về số hiệu KB:** số KB trong tài liệu này khớp tên file `tests/grafana_kb*.sh` (KB1=brute force, KB2=fraud gate, KB3=lateral movement, KB5=access denied); KB4 (data exfiltration) chạy qua `scripts/run-demo.sh --kb4`, không có file `tests/grafana_kb4_*.sh` riêng. Số KB trong `scripts/run-demo.sh --kbN` **lệch thứ tự** so với tài liệu này (ở đó KB2=Lateral Movement, KB3=Fraud Gate Bypass) — luôn đối chiếu theo **tên kịch bản**, không đối chiếu chéo bằng số.

---

## Mục lục

1. [Tổng quan hệ thống](#1-tổng-quan-hệ-thống)
2. [Cấu hình từng thành phần Zero Trust](#2-cấu-hình-từng-thành-phần-zero-trust)
   - 2.1 Keycloak — Identity Provider
   - 2.2 SPIRE/SPIFFE — Workload Identity
   - 2.3 Istio Sidecar (istio-proxy) — mTLS Proxy
   - 2.4 OPA — Policy Engine
   - 2.5 Grafana Alert Rules — Detection
   - 2.6 SOAR Engine — Response
3. [Luồng bình thường — một giao dịch hợp lệ](#3-luồng-bình-thường--một-giao-dịch-hợp-lệ)
4. [KB1 — Brute Force Login (T1110.001)](#4-kb1--brute-force-login-t1110001)
5. [KB2 — Fraud Gate Bypass (T1078.004)](#5-kb2--fraud-gate-bypass-t1078004)
6. [KB3 — Lateral Movement via Unauthorized Internal Path (T1021.007)](#6-kb3--lateral-movement-via-unauthorized-internal-path-t1021007)
7. [KB4 — Data Exfiltration / Large Response (T1041)](#7-kb4--data-exfiltration--large-response-t1041)
8. [KB5 — Access Denied Spike / OPA RBAC (T1078)](#8-kb5--access-denied-spike--opa-rbac-t1078)
9. [KB6 — Container Privilege Escalation (T1068)](#9-kb6--container-privilege-escalation-t1068)

---

## 1. Tổng quan hệ thống

Hai cụm Kubernetes trên hai cloud, nối qua WireGuard tunnel.

**Cụm AWS (K3s, 3 node)** — lớp ứng dụng người dùng, identity, policy, observability, response:

| Service | Vai trò | Namespace |
|---|---|---|
| api-gateway | Điểm vào duy nhất — verify JWT (chữ ký), IP blocklist, rate limit, forward tới payment-service | financial |
| payment-service | Điều phối giao dịch — gọi fraud-detection rồi core-banking (cross-cloud) | financial |
| fraud-detection | Chấm điểm rủi ro theo amount/channel/velocity | financial |
| notification-service | Gửi email xác nhận giao dịch | financial |
| web-portal | UI người dùng + Security Dashboard HITL | financial |
| opa-server | Policy engine — istio-proxy gọi qua ext_authz gRPC (CUSTOM AuthorizationPolicy) trước khi forward mọi request | financial |
| keycloak + keycloak-db | Identity Provider, cấp JWT | identity |
| spire-server / spire-agent (DaemonSet) | SPIFFE CA + cấp X.509-SVID cho mỗi pod | spire |
| loki, grafana, promtail (DaemonSet) | Log aggregation, 6 alert rule thật, log shipping | plg-stack |
| soar-engine | Nhận webhook Grafana, tạo case HITL, thực thi playbook K8s | plg-stack |
| ai-analyzer, security-scorer | Phân tích log bổ sung (heuristic/LLM), chấm điểm bảo mật tổng | plg-stack |
| redis | Blocked IPs, session blacklist, fraud velocity counter | financial |
| postgresql (accounts, txn) | Số dư và ledger giao dịch | financial (AWS chỉ có Redis — Postgres thật nằm bên OpenStack, xem bên dưới) |

**Cụm OpenStack (K3s, 3 node)** — lớp core banking:

| Service | Vai trò |
|---|---|
| core-banking | Xử lý giao dịch, gọi account-service + transaction-service |
| account-service | Truy vấn số dư, debit/credit (Postgres) |
| transaction-service | Ghi ledger, lịch sử giao dịch (Postgres) |

Hai cụm kết nối qua WireGuard. `payment-service` gọi `core-banking` qua istio-proxy (Service+Endpoints thủ công trỏ NodePort, `k8s/financial/istio-policies.yaml`) → private IP của `os_k3s_master` trên WireGuard tunnel, ISTIO_MUTUAL bằng SPIRE SVID xuyên cloud.

---

## 2. Cấu hình từng thành phần Zero Trust

### 2.1 Keycloak — Identity Provider

Keycloak quản lý realm `ztlab`. Mỗi JWT chứa `realm_access.roles` — căn cứ để OPA/api-gateway quyết định quyền hạn.

**Người dùng và vai trò thật** (`k8s/keycloak/realm-config.json`):

| Username | Roles |
|---|---|
| testuser01 | financial-read, financial-write |
| testuser02 | financial-read, financial-write |
| merchant01 | financial-read (chỉ đọc) |
| analyst01 | security-analyst |
| demoadmin | financial-read, financial-write, security-analyst, security-admin |

**3 OIDC client đã cấu hình, chỉ 1 client được phép `password` grant (direct access):**

| clientId | `directAccessGrantsEnabled` | Dùng để |
|---|---|---|
| `web-portal` | **false** | Chỉ luồng OIDC/PKCE qua browser — đây là hardening Zero Trust có chủ đích, không phải thiếu sót |
| `api-gateway` | **true** | Duy nhất client được phép lấy token qua `grant_type=password` — dùng cho traffic thật của user (qua web-portal backend) **và cho mọi script test/demo** (cần thêm `client_secret`, lấy qua Keycloak admin API) |
| `siem-backend` | false | — |

> Bản tài liệu 28/06 viết ngược lại (nói `web-portal` là client được phép password grant) — đã sửa. Tất cả script trong `tests/grafana_kb2_fraud_gate.sh`, `grafana_kb5_access_denied.sh`, `tests/collect_metrics.py`, `tests/perf_overhead.py` từng gọi sai `client_id=web-portal` và bị Keycloak từ chối (`unauthorized_client`) — đã sửa sang `api-gateway` + secret ngày 2026-08-20.

api-gateway verify chữ ký JWT bằng JWKS lấy từ `http://keycloak.identity.svc.cluster.local:8080/realms/ztlab/protocol/openid-connect/certs`.

---

### 2.2 SPIRE/SPIFFE — Workload Identity

SPIRE cấp X.509-SVID cho mỗi pod. Cấu hình thật (`spire/server/server.conf`, `spire/server/aws-server.conf`, `spire/server/os-server.conf` — đồng nhất cả 2 cloud):

```
trust_domain           = "ztlab.local"
default_x509_svid_ttl  = "1h"     ← SVID hết hạn mỗi 1 giờ, tự động gia hạn
ca_ttl                 = "168h"   ← Root CA tồn tại 7 ngày
```

`NodeAttestor "k8s_psat"` xác thực node qua Kubernetes Pod Service Account Token. SPIFFE ID theo mẫu `spiffe://ztlab.local/aws/<service>` hoặc `spiffe://ztlab.local/openstack/<service>`.

Mỗi SVID là chứng chỉ X.509 có `SAN = URI:<spiffe_id>`. istio-proxy đọc SAN này qua mTLS handshake, đặt vào `input.attributes.source.principal` khi gọi OPA ext_authz — đây là căn cứ để OPA phân biệt "request từ service thật trong hệ thống" (`valid_svid`) với request từ bên ngoài.

---

### 2.3 Istio Sidecar (istio-proxy) — mTLS Proxy

> **Cập nhật 2026-08-23**: bản trước mô tả hand-rolled Envoy sidecar (ConfigMap
> `envoy/envoy-sidecar.yaml`, cổng 15006/15001/9901 tự cấu hình tay). Toàn bộ
> 8 service financial (cả 2 cloud) đã migrate sang **Istio service mesh** —
> container `envoy` bị gỡ hoàn toàn, thay bằng `istio-proxy` do Istio tự
> inject và quản lý qua xDS (không còn ConfigMap envoy tay). Nội dung dưới
> đây mô tả kiến trúc THẬT hiện tại, xác nhận qua test trực tiếp (không suy
> đoán từ config) ngày 2026-08-23.

Mỗi service application chạy kèm `istio-proxy` sidecar (pod `READY 2/2`), inject tự động qua label `istio-injection=enabled` trên namespace `financial` (cả 2 cluster). Cấu hình cài đặt tập trung tại `k8s/istio/istio-operator.yaml`:

- **`trustDomain: ztlab.local`** — khớp với SPIRE, không dùng mặc định `cluster.local` của Istio (nếu lệch, Istio tự từ chối cert do SPIRE cấp với lỗi `CERTIFICATE_UNKNOWN`, đã xác nhận qua repro thật).
- **SPIRE vẫn là nguồn cấp cert**, KHÔNG dùng Citadel CA mặc định của Istio: mỗi pod migrate có annotation `sidecar.istio.io/userVolume`/`userVolumeMount` mount socket SPIRE Workload API (`/run/spire/sockets/agent.sock`) vào đúng đường dẫn quy ước `/var/run/secrets/workload-spiffe-uds/socket` — pilot-agent (bên trong istio-proxy) tự phát hiện socket này lúc khởi động và dùng làm nguồn SDS thay vì tự cấp cert nội bộ (log xác nhận: `"Workload SDS socket found. Istio SDS Server won't be started"`).
- **`PeerAuthentication mode: STRICT`** cho toàn namespace (cả 2 cloud) — mọi kết nối service-to-service bắt buộc mTLS thật bằng cert SPIRE. Riêng `api-gateway` và `web-portal` có override `PERMISSIVE` (`k8s/financial/istio-policies.yaml`) vì đây là 2 điểm nhận traffic công khai qua Traefik — trình duyệt/Traefik không có client cert SPIFFE.
- **`opa-ext-authz` extensionProvider** (gRPC, trỏ `opa-service.financial.svc.cluster.local:9191`) — thay thế đúng chức năng ext_authz cũ. 6/8 service migrate có `AuthorizationPolicy action: CUSTOM` trỏ provider này (api-gateway, payment-service, fraud-detection, core-banking, account-service, transaction-service — những service có Rego logic thật, không thể biểu diễn bằng rule ALLOW/DENY tĩnh). 2 service còn lại (notification-service, web-portal) dùng `action: ALLOW`/không policy vì luật OPA cho chúng chỉ là "SVID hợp lệ" — Istio's native principal check đã đủ, không cần round-trip OPA.
- **Cross-cloud (payment-service AWS → core-banking OpenStack)**: dùng Service+Endpoints K8s thường (không dùng ServiceEntry — Istio validation webhook từ chối IP thô làm `hosts`, và DNS-capture của ServiceEntry không hoạt động ổn định trong lần thử) trỏ tới NodePort `192.168.101.11:30080` qua WireGuard, kèm `DestinationRule` `ISTIO_MUTUAL` + `subjectAltNames` khớp SPIFFE ID thật của core-banking.

**⚠️ Giới hạn quan trọng khi tự test (phát hiện 2026-08-23):** `kubectl port-forward svc/api-gateway` (chính cơ chế `$GW_URL=http://localhost:18080` mà mọi script `tests/grafana_kb*.sh` dùng) **kết nối thẳng vào pod qua loopback bên trong network namespace, bỏ qua hoàn toàn iptables interception của Istio**. Nghĩa là test qua port-forward chỉ kiểm tra được lớp bảo mật **application-level** của api-gateway (JWT decode, fraud gate, business logic) — KHÔNG đi qua STRICT mTLS/CUSTOM AuthorizationPolicy của Istio. Muốn verify đúng lớp Istio phải test qua Traefik thật (`kubectl port-forward svc/traefik -n kube-system` + header `Host: api.ztlab.local`) — response `Server: istio-envoy` (khác `uvicorn`) mới xác nhận request đã qua đúng lớp Istio. Đã dùng cách này để verify OPA fail-closed thật (xem `tests/chaos_opa_failover.sh`) — KHÔNG dùng port-forward tới Service như bản cũ.

Truy cập internal (service gọi service) qua Service DNS thường (`http://<service>.financial.svc.cluster.local:8080/<path>`) — Istio tự động chặn traffic bằng iptables và áp mTLS trong suốt, ứng dụng không cần biết gì về TLS/SDS.

Access log JSON của istio-proxy (bật qua `meshConfig.accessLogFormat`, khớp field tên cũ để không cần sửa Grafana LogQL) có: `timestamp`, `method`, `path`, `response_code`, `response_time`, `upstream`, `source_ip`, `bytes_sent`, `svid` (từ `%DOWNSTREAM_PEER_URI_SAN%`), `trace_id` — vẫn label `job="envoy-access"` trong Loki (Promtail scrape theo container `istio-proxy` thay vì `envoy` cũ). **Lưu ý xác nhận thật:** Envoy/istio-proxy **không ghi access log cho request bị CUSTOM AuthorizationPolicy (ext_authz) từ chối** — chỉ ghi log cho request đã hoàn tất vòng đời HTTP bình thường (allowed, hoặc bị app tự chối). Vì vậy `brute-force-alert.yml` (KB1) dùng log app-level `jwt_verification_failed` chứ không dùng `job="envoy-access"` (xem 2.5).

---

### 2.4 OPA — Policy Engine

OPA nhận request qua ext_authz gRPC (istio-proxy gọi thay cho Envoy hand-rolled cũ — cùng 1 giao thức, cùng OPA), evaluate `opa/policies/zta_policy.rego`, trả `allow=true/false`.

**Điểm quan trọng hay bị hiểu nhầm:** OPA **không tự verify chữ ký JWT**. Policy dùng `io.jwt.decode()` (chỉ decode, không check signature) — verify chữ ký là việc của api-gateway (python-jose + JWKS). Comment thật trong file giải thích lý do: *"OPA's role: claims-based authorization — issuer, expiry, realm roles. Using io.jwt.decode (no signature check) is correct here because the upstream api-gateway already rejected any request with an invalid signature before it reaches downstream services with OPA sidecars."*

```rego
package zta.authz
default allow = false          ← deny-by-default

# Issuer lấy qua OIDC discovery document của chính Keycloak (cache 5 phút),
# không hardcode chuỗi cố định — một chuỗi hardcode từng gây toàn bộ JWT
# bị từ chối ngày 2026-08-13 (lệch KC_HOSTNAME_PORT giữa 3 nơi cấu hình độc lập).
expected_issuer := discovery_response.body.issuer if { ... Keycloak OIDC discovery ... }

valid_jwt if {
  jwt_payload.iss == expected_issuer
  jwt_payload.exp > time.now_ns() / 1000000000
}

permissions := {
  "financial-read":   {"GET": true, "OPTIONS": true},
  "financial-write":  {"GET": true, "OPTIONS": true, "POST": true, "PUT": true},
  "security-analyst": {"GET": true, "OPTIONS": true},
  "security-admin":   {"GET": true, "OPTIONS": true, "POST": true, "PUT": true, "DELETE": true},
}
role_permits_action if { some role in jwt_payload.realm_access.roles; permissions[role][method] }

allow if { public_path }
allow if { external_api_request }       # user thật, có JWT hợp lệ, KHÔNG có SVID
allow if { internal_service_request }   # service-to-service, có SVID hợp lệ
allow if { core_transaction_with_fraud_gate }

external_api_request if {   # POST /payments hoặc /accounts, hoặc bất kỳ GET/OPTIONS
  valid_jwt; role_permits_action; not valid_svid
}

internal_service_request if { valid_svid; method in ["GET","OPTIONS"] }
internal_service_request if { valid_svid; method=="POST"; path in ["/payments","/score","/notify"] }
internal_service_request if { valid_svid; method=="POST"; startswith(path,"/accounts") }
internal_service_request if { valid_svid; method=="POST"; startswith(path,"/transactions"); not startswith(path,"/transactions/execute") }

core_transaction_with_fraud_gate if {
  valid_svid; startswith(path,"/transactions/execute"); fraud_gate_valid
}

valid_svid if { startswith(source_principal, "spiffe://ztlab.local/") }
fraud_gate_valid if { headers["x-fraud-gate"]=="passed"; to_number(headers["x-fraud-score"]) < 75 }
```

**Vì sao request với JWT giả bị chặn ở tầng nào phụ thuộc ĐƯỜNG VÀO (xem cảnh báo port-forward ở §2.3 và chi tiết đầy đủ ở Mục 4/KB1):** nếu request tới qua Traefik thật, `io.jwt.decode()` trong OPA thất bại với input không đúng cấu trúc JWT → `valid_jwt=false` → `allow=false` → istio-proxy trả **403 ngay tại lớp CUSTOM AuthorizationPolicy** (`server: istio-envoy`), không chạm app. Nếu request tới qua `kubectl port-forward` (như cách toàn bộ `tests/grafana_kb*.sh` gọi `$GW_URL`), request bỏ qua lớp Istio hoàn toàn và chạm thẳng app — `services/api-gateway/main.py` tự bắt lỗi decode, trả 401 `event=jwt_verification_failed`. Cả 2 đường đều CHẶN được request (không lọt qua), chỉ khác tầng nào thực hiện việc chặn.

`internal_service_request` **không** whitelist `/payments/internal/execute` — đây chính là lỗ hổng KB3 khai thác (xem Mục 6).

**Fraud gate** (`opa/policies/fraud_gate.rego`, package riêng — cùng logic được lặp lại inline trong `zta_policy.rego`):
```rego
package zta.fraud_gate
default fraud_gate_valid = false
fraud_gate_valid if {
  input.attributes.request.http.headers["x-fraud-gate"] == "passed"
  to_number(input.attributes.request.http.headers["x-fraud-score"]) < 75
}
```

**Cross-cloud policy** (`opa/policies/cross_cloud.rego`, package `zta.crosscloud` — OPA trên OpenStack dùng path này cho ext_authz, KHÔNG dùng `zta.authz` ở trên; xem `opa-config.yaml` trong `k8s/financial/os-security.yaml`: `path: zta/crosscloud/allow`). Policy này allow-list theo cặp `source.principal`/`destination.principal` SPIFFE ID cụ thể — chặt hơn `zta_policy.rego` (không chỉ dựa vào `valid_svid` chung chung):
```rego
package zta.crosscloud
default allow = false

allow if {   # payment-service (AWS) -> core-banking (OpenStack)
  input.attributes.source.principal == "spiffe://ztlab.local/aws/payment-service"
  input.attributes.destination.principal == "spiffe://ztlab.local/openstack/core-banking"
  input.attributes.request.http.method in ["GET", "POST"]
  startswith(input.attributes.request.http.path, "/transactions")
}
allow if {   # (thêm 2026-08-23) cùng cặp principal, path /accounts
  input.attributes.source.principal == "spiffe://ztlab.local/aws/payment-service"
  input.attributes.destination.principal == "spiffe://ztlab.local/openstack/core-banking"
  input.attributes.request.http.method in ["GET", "POST"]
  startswith(input.attributes.request.http.path, "/accounts")
}
```

> **Bug thật đã tìm và vá 2026-08-23 (nguyên nhân "chuyển khoản không thành công"):**
> Rule gốc chỉ cho phép `payment-service → core-banking` với path bắt đầu bằng
> `/transactions`. Nhưng `services/payment-service/main.py` còn proxy CẢ
> `POST /accounts` (tạo tài khoản ngân hàng lần đăng nhập đầu) và
> `GET /accounts`/`GET /accounts/{id}` (tra số dư) sang `core-banking` — hai
> path này KHÔNG khớp rule, nên bị istio-proxy trên core-banking từ chối
> 403 ngay tại lớp CUSTOM AuthorizationPolicy, thân rỗng, `response_time`
> chỉ 1-4ms, `upstream: null` (không hề chạm tới ứng dụng core-banking thật).
> Hệ quả dây chuyền: `auth_callback` trong web-portal gọi
> `_create_bank_account_with_token` → api-gateway → payment-service →
> core-banking bị 403 → log `first_login_account_create_failed` → user không
> có tài khoản nào → dashboard/transfer không có gì để chọn/chuyển từ đó.
> Phát hiện bằng cách gọi trực tiếp từ payment-service pod
> (`kubectl exec ... curl core-banking-openstack.../accounts`, thấy
> `HTTPError 403` thân rỗng, `server: envoy`) — không suy đoán từ đọc code.
> Đã sửa: thêm rule `allow` thứ 2 cho path `/accounts` (cùng cặp principal ở
> trên), apply lại ConfigMap `opa-policies` + restart `opa-server` trên cả 2
> cluster, verify lại bằng phiên đăng nhập PKCE thật (tạo tài khoản, tra số
> dư, chuyển khoản — cả 3 bước đều `200`).

---

### 2.5 Grafana Alert Rules — Detection Layer

**6 rule tấn công thật** trong `plg-stack/grafana/alerting/` (đọc trực tiếp từ file + xác nhận trên ConfigMap live của cluster, không phải suy đoán), evaluate `for: 0s` (fire ngay khi query > 0, không chờ cửa sổ ổn định):

| Rule (file) | LogQL thật | severity / mitre / attack_type |
|---|---|---|
| `brute-force-alert.yml` | `sum by (source_ip)(count_over_time({namespace="financial",app="api-gateway"}\|json\|event="jwt_verification_failed"[5m])) > 10` | high / T1110.001 / brute_force |
| `fraud-gate-bypass-alert.yml` | `sum(count_over_time({namespace="financial",app="payment-service"}\|json\|level="AUDIT"\|event="payment_blocked_fraud"[10m]))` | critical / T1078.004 / fraud_gate_bypass |
| `lateral-movement-alert.yml` | `sum(count_over_time({job="opa-decisions",opa_result="false",request_path="/payments/internal/execute"}[10m]))` | critical / T1021.007 / lateral_movement |
| `large-response-alert.yml` | `sum(count_over_time({job="envoy-access"}\|json\|bytes_sent > 1048576[5m]))` | high / T1041 / large_response |
| `access-denied-alert.yml` | `sum(count_over_time({job="opa-decisions", opa_result="false", request_path="/payments"}[10m]))` | high / T1078 / access_denied |
| `privilege-escalation-alert.yml` | `sum(count_over_time({namespace="financial",app="security-scanner"}\|json\|event="privilege_escalation"[5m]))` | critical / T1068 / privilege_escalation |

Ngoài ra còn 2 file **không phải rule tấn công** (`soar-engine-alert.yml`, `security-control-plane-alert.yml` — cảnh báo vận hành nội bộ SOAR/control-plane) và `notification-policy.yml` (route mọi alert tới contact point webhook SOAR: `http://soar-engine.plg-stack.svc.cluster.local:8080/grafana-webhook`).

> **Cập nhật 2026-08-20 (2 bug đã vá):** (1) `access-denied-alert.yml` — dù file tồn tại từ trước, `provision_grafana_configmaps()` trong `scripts/deploy-app.sh` thiếu dòng `--from-file` tương ứng nên **chưa từng được nạp vào Grafana thật** trên cluster đang chạy (verify trực tiếp qua `kubectl get configmap grafana-alerting` — file vắng mặt) — bản viết lại 20/08 trước đó của tài liệu này lỡ ghi nhầm là đã hoạt động. (2) `privilege-escalation-alert.yml` — trước đây không tồn tại trong thư mục thật (có 1 bản nháp trong file cũ `k8s/plg-stack/grafana-alerting-configmap.yaml`, chưa từng apply), và SOAR (`services/soar-engine/main.py`) thiếu hẳn key `privilege_escalation` trong `TARGETS_BY_ATTACK`/`PLAYBOOK_BY_ATTACK`/`MITRE_BY_ATTACK`. Cả 2 giờ đã vá tận gốc và **xác nhận end-to-end thật**: chạy `tests/grafana_kb5_access_denied.sh` + `kubectl apply -f k8s/financial/security-scanner-job.yaml` → cả 2 rule fire → SOAR tạo case `access_denied` (severity=high, playbook=block_source_ip) và `privilege_escalation` (severity=critical, playbook=quarantine_workload) thật, `pending_approval`.

> **Cập nhật 2026-08-23 (sau migrate Istio, `brute-force-alert.yml` sửa lần 2):** LogQL cũ của `brute-force-alert.yml` (`job="envoy-access", response_code="403"`) đã sai từ TRƯỚC cả migration Istio — chưa từng được verify khớp traffic thật của kịch bản KB1 (JWT giả bị app tự bắt, không qua Envoy/OPA — xem giải thích ở §2.4 và Mục 4). Đã sửa sang query log app-level `jwt_verification_failed`, verify trực tiếp trên Loki: count tăng đúng lên 20 khớp 20 request KB1 gửi.

> **Cập nhật 2026-08-23 (`access-denied-alert.yml` sửa cùng đợt):** cùng lý do như brute-force — request tấn công thật của `tests/grafana_kb5_access_denied.sh` cũng đi qua `$GW_URL` port-forward, bỏ qua Istio/OPA. Đã sửa sang query log app-level `authz_denied` (`services/api-gateway/main.py:_require_role`), verify trực tiếp trên Loki. Xem Mục 8 (KB5) để biết chi tiết.

Còn lại: 1/6 rule query `job="opa-decisions"` (`lateral-movement` — request tấn công thật đi qua `kubectl exec` service-to-service, KHÔNG qua port-forward, nên thật sự chạm Istio/OPA; log quyết định của OPA không đổi khi migrate Istio vì OPA vẫn là cùng 1 tiến trình, chỉ khác caller là istio-proxy thay vì Envoy hand-rolled), 4/6 query log tầng ứng dụng (`brute-force`, `access-denied`, `fraud-gate-bypass`, `privilege-escalation` — event do code Python tự ghi), 1/6 (`large-response-alert.yml`) query `job="envoy-access"` — nay là log của istio-proxy (Promtail scrape theo tên container `istio-proxy`, xem §2.3), format JSON giữ nguyên tên field cũ nên không cần sửa LogQL này.

**Bài học chung rút ra 2026-08-23:** 3/6 rule tấn công qua `api-gateway` (`brute-force`, `access-denied`, và trước đó `fraud-gate-bypass` vốn đã là app-level) hoá ra đều dựa vào log app-level, không phải vì THIẾT KẾ cố ý muốn vậy, mà vì **toàn bộ test suite `tests/grafana_kb*.sh` gọi `api-gateway` qua `kubectl port-forward`**, một con đường vô tình bỏ qua lớp Istio/OPA phía trước nó. Chỉ 2 rule có request tấn công đi qua `kubectl exec` thật (`lateral-movement`, và KB6 privilege-escalation qua Job riêng) mới thật sự chạm được lớp hạ tầng (Istio/OPA hoặc kernel capabilities). Đây là giới hạn về PHƯƠNG PHÁP TEST cần cải thiện nếu muốn demo đúng toàn bộ defense-in-depth (xem §2.3 để biết cách test đúng qua Traefik).

---

### 2.6 SOAR Engine — Response Automation

FastAPI app trong namespace `plg-stack`. Đọc trực tiếp `services/soar-engine/main.py`:

```
SOAR_DRY_RUN=false             SOAR_AUTO_EXECUTE=true
SOAR_HITL_SEVERITY=high        SOAR_MIN_SEVERITY=medium
SOAR_ALLOWED_CONTEXTS=ctx-aws,ctx-openstack
SOAR_CASE_STORE_PATH=/data/cases.jsonl   ADMIN_EMAIL=voha2005@gmail.com
```

**Mapping attack_type → playbook/target thật** (trích, đủ cho 6 kịch bản trong tài liệu này — dict đầy đủ có 14 attack_type):

| attack_type | playbook | target context/workload |
|---|---|---|
| `brute_force` | revoke_user_sessions | ctx-aws / api-gateway |
| `fraud_gate_bypass` | isolate_workload | ctx-aws / payment-service |
| `lateral_movement` | isolate_workload | ctx-aws / payment-service |
| `large_response` | restrict_egress | ctx-openstack / core-banking |
| `access_denied` | block_source_ip | ctx-aws / api-gateway |
| `privilege_escalation` | quarantine_workload | ctx-aws / api-gateway |

> **Đính chính cho Mục 9 (KB6):** bản viết lại 20/08 trước đó của tài liệu này ghi nhầm là SOAR chỉ có key `container_escape` (T1611) và cần map `privilege_escalation` sang key đó — **sai**. `container_escape`/T1611 (Escape to Host — thoát ra host) và `privilege_escalation`/T1068 (Exploitation for Privilege Escalation — leo thang đặc quyền trong container) là **2 kỹ thuật MITRE khác nhau**, `ai-analyzer.yaml` vốn đã phân biệt đúng 2 pattern này từ trước (dòng regex riêng cho từng cái). `security-scanner-job.yaml` phát hiện đúng `privilege_escalation` (uid=0 + dangerous capabilities), không phải container escape. Vá đúng gốc rễ: thêm hẳn key `privilege_escalation` vào 5 dict taxonomy của SOAR (trước đó bị thiếu, dù `SUGGESTED_PLAYBOOKS` đã có sẵn 1 dòng cho key này — dấu hiệu việc wire từng bị làm dở rồi bỏ), không phải gán nhầm sang `container_escape`.

**4 phase mỗi playbook** (`_execute_playbook`, xác nhận đúng như code):
- **contain** — hành động ngay: scale deployment về 0 (`isolate_workload`/`quarantine_workload`), tạo NetworkPolicy block IP (`block_source_ip`/`restrict_egress`), hoặc revoke Keycloak session (`revoke_user_sessions`)
- **investigate** — query Loki lấy log evidence (`_investigate_loki`)
- **eradicate** — dọn dẹp bổ sung tuỳ playbook
- **recover** — ghi `pending`, chờ admin gọi `POST /cases/{case_id}/rollback` thủ công

Nếu `severity >= SOAR_HITL_SEVERITY (high)` → case ở trạng thái `pending_approval`, gửi email HITL, **không tự thực thi** — chờ admin duyệt qua Web Portal `/security` hoặc link trong email. Nếu severity thấp hơn → tự thực thi ngay (`SOAR_AUTO_EXECUTE=true`).

---

## 3. Luồng bình thường — một giao dịch hợp lệ

> Cập nhật 2026-08-23: thay `Envoy Inbound/Outbound :15006/:15001` (hand-rolled) bằng
> `istio-proxy` (Istio tự inject, transparent — app gọi thẳng Service DNS, không qua
> `127.0.0.1:15001` nữa). Xác nhận qua giao dịch thật chạy end-to-end dưới STRICT mTLS
> (HTTP 200, fraud gate PASS, core-banking cập nhật balance thật) ngày 2026-08-23.

```
[testuser01] POST /payments {"from":"ACC-1001","to":"ACC-2001","amount":10000}
    │
    ▼ istio-proxy inbound (api-gateway pod, PeerAuthentication PERMISSIVE — Traefik không có client cert)
    - AuthorizationPolicy action=CUSTOM → ext_authz gRPC → OPA :9191
      OPA: valid_jwt ✓, role financial-write permits POST ✓, not valid_svid ✓ (user request)
      → external_api_request match → allow=true → forward tới app :8080
    │
    ▼ api-gateway app (services/api-gateway/main.py)
    - Verify chữ ký JWT qua JWKS Keycloak (python-jose)
    - Check Redis blocklist IP, rate limit
    - Check role "financial-write" trong claims
    - Gọi payment-service qua Service DNS thẳng (http://payment-service.financial.svc.cluster.local:8080) — istio-proxy tự chặn + áp ISTIO_MUTUAL, app không biết gì về TLS
    │
    ▼ payment-service (PeerAuthentication STRICT)
    - Gọi fraud-detection /score qua Service DNS (istio-proxy mTLS trong suốt) → score=5 (base, không velocity/critical/risky) → verdict=allow, gate=passed
    - Gắn header X-Fraud-Gate=passed, X-Fraud-Score=5, X-Fraud-Gate-Signature=hmac(...)
    - Gọi core-banking /transactions/execute qua Service+Endpoints thủ công (core-banking-openstack.financial.svc.cluster.local) → istio-proxy áp ISTIO_MUTUAL → WireGuard → OpenStack
      core-banking istio-proxy inbound: verify mTLS SVID ✓ (cert SPIRE thật, cùng trust domain 2 cloud) → OPA CUSTOM: valid_svid + path + fraud_gate_valid + posture_compliant ✓ → allow
    - core-banking gọi account-service (debit/credit) + transaction-service (ghi ledger) — cùng cơ chế istio-proxy mTLS
    │
    ▼ Trả kết quả → payment-service → api-gateway → user
    │
    ▼ (fire-and-forget) payment-service gọi notification-service → gửi email
    │
    ▼ Log pipeline: istio-proxy access log (JSON, format khớp field tên cũ) → stdout → Promtail (scrape container istio-proxy) → Loki
      Grafana evaluate mỗi rule liên tục — không match pattern bất thường → không alert nào fire
```

---

## 4. KB1 — Brute Force Login (T1110.001)

**Zero Trust principle:** *Continuous Verification, deny-by-default* — 20 request với JWT không hợp lệ đều bị từ chối trước khi chạm business logic.

**Script thật:** `tests/grafana_kb1_brute_force.sh` — gửi 20 `POST /payments` qua `$GW_URL=http://localhost:18080` (`kubectl port-forward svc/api-gateway`) với header `Authorization: Bearer INVALID_BRUTEFORCE_TOKEN_ATTEMPT_<i>` (chuỗi giả, không phải JWT hợp lệ về cấu trúc).

**Cập nhật 2026-08-23 (viết lại lần 2, sau khi Istio thay Envoy hand-rolled):** cơ chế chặn thật cho kịch bản test cụ thể này ĐÃ THAY ĐỔI so với bản 2026-08-20 — không phải do lỗi ghi chép, mà do một phát hiện thật về cách `kubectl port-forward` hoạt động:

> **`kubectl port-forward svc/<name>` kết nối thẳng vào pod qua loopback bên trong network namespace của chính pod đó — bỏ qua hoàn toàn iptables interception mà Istio dùng để chèn mTLS/CUSTOM AuthorizationPolicy vào traffic.** Đây không phải bug của ZTLab — đây là cách `kubectl port-forward` hoạt động với BẤT KỲ service mesh dùng iptables-redirect nào. Ở kiến trúc CŨ (hand-rolled Envoy lắng nghe trực tiếp trên port Service trỏ tới, ví dụ 15006), port-forward vô tình vẫn chạm được Envoy vì Envoy CHÍNH LÀ tiến trình nhận kết nối ở port đó. Ở kiến trúc MỚI (Istio dùng transparent iptables redirect trên CÙNG port app lắng nghe), port-forward's loopback connection không kích hoạt redirect này — nên **request qua port-forward giờ chạm thẳng app, bỏ qua toàn bộ lớp Istio/OPA CUSTOM AuthorizationPolicy.**

Đã xác nhận bằng thực nghiệm (không suy đoán): gửi CÙNG MỘT request (garbage token, `POST /accounts` hoặc `/payments`) qua 2 đường —
- **Qua port-forward** (`$GW_URL`, cách KB1-KB5 test): response `server: uvicorn`, `401 {"detail":"invalid token"}` — **app tự bắt** (`services/api-gateway/main.py`), OPA hoàn toàn không được gọi (0 decision-log entry trong Loki dù retry nhiều lần với timing khác nhau).
- **Qua Traefik thật** (production ingress — `kubectl port-forward svc/traefik -n kube-system` + header `Host: api.ztlab.local`): response `server: istio-envoy`, `403` rỗng thân — **Istio/OPA CUSTOM AuthorizationPolicy chặn TRƯỚC khi tới app**, xác nhận cả khi tắt hẳn `opa-server` (fail-closed thật, xem `tests/chaos_opa_failover.sh`).

Nghĩa là: **KB1 (và toàn bộ `tests/grafana_kb*.sh`, dùng chung `$GW_URL` port-forward) chỉ verify được lớp bảo mật application-level của api-gateway** (JWT decode, xem `services/api-gateway/main.py`) — không verify được lớp Istio/OPA phía trước nó. Đây KHÔNG phải lỗ hổng bảo mật thật (traffic thật qua Traefik vẫn được Istio/OPA bảo vệ đầy đủ, đã verify), mà là **giới hạn của phương pháp test hiện tại** cần lưu ý khi đọc kết quả PASS của các script KB.

**Cơ chế chặn thật của KB1 (qua port-forward, đúng như test đang chạy):** garbage token → `jose.jwt.decode()` trong Python throw exception → api-gateway trả 401, ghi log:

```json
{"timestamp":"2026-08-23T14:00:17Z","level":"WARN","service":"api-gateway","event":"jwt_verification_failed","reason":"invalid_rs256","source_ip":"127.0.0.6"}
```

Xác nhận thật qua Loki: `{namespace="financial",app="api-gateway"} | json | event="jwt_verification_failed"` trả về đúng 20 entry cho 1 lần chạy KB1 (`source_ip=127.0.0.1`, count tăng dần lên 20 rồi giữ nguyên trong cửa sổ 5 phút).

**Kết quả chạy thật:**
```
[KB1_brute_force] api-gateway chặn 20/20  — jwt_verification_failed ghi vào Loki
[KB1_brute_force] PASS: KB1 | 20/20 blocked | log thật → Loki (Grafana fire trong ≤1 phút)
```

**Grafana rule fire:** `brute-force-alert.yml` (đã sửa 2026-08-23, LogQL cũ dùng `job="envoy-access"` là sai từ TRƯỚC migration Istio — không ai từng verify thật) — `sum by(source_ip)(count_over_time({namespace="financial",app="api-gateway"} | json | event="jwt_verification_failed" [5m])) > 10` — 20 > 10 → **FIRING** → webhook tới SOAR → case `brute_force`, severity=high → HITL, playbook `revoke_user_sessions`.

**Xem case:**
```bash
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases=[c for c in json.load(sys.stdin) if c['attack_type']=='brute_force']
c=cases[-1]; print(c['case_id'], c['status'], c['playbook'])"
```

---

## 5. KB2 — Fraud Gate Bypass (T1078.004)

**Zero Trust principle:** *Verify Explicitly per-action* — JWT hợp lệ (đăng nhập đúng) không đủ; mỗi giao dịch được đánh giá riêng theo ngữ cảnh (amount, channel).

**Script thật:** `tests/grafana_kb2_fraud_gate.sh` — lấy JWT `testuser01` qua client `api-gateway` (+ secret, xem 2.1), gửi 3 lần `POST /payments` với `amount=500000000, channel=tor`.

**Công thức chấm điểm thật** (`services/fraud-detection/main.py`, hàm `_score`):
```python
score = 5                                    # base
if amount >= CRITICAL_AMOUNT_VND (500_000_000): score += 55   # → 60, reason="critical_amount"
if channel in {"tor","unknown","script"}:        score += 15   # → 75, reason="risky_channel"
score = min(score, 100)
verdict = "block" if score >= 75 else "review" if score >= 40 else "allow"
gate = "blocked" if verdict=="block" else "passed"
```
`500_000_000` đúng bằng ngưỡng `CRITICAL_AMOUNT_VND` (`>=`) nên vẫn cộng điểm. Ngưỡng block thật là **`score >= 75`** (bản 28/06 ghi nhầm 70).

payment-service nhận `gate != "passed"` → `HTTPException(403, {"reason":"fraud gate blocked","fraud":{...}})`, **không gọi core-banking** — giao dịch chặn hoàn toàn trước khi chạm banking layer.

**Kết quả chạy thật (2026-08-20, sau khi sửa client_id):**
```
[KB2_fraud_gate]   Attempt 1 → HTTP 403
[KB2_fraud_gate]   Attempt 2 → HTTP 403
[KB2_fraud_gate]   Attempt 3 → HTTP 403
[KB2_fraud_gate] payment-service chặn 3/3 → AUDIT payment_blocked_fraud → Loki
[KB2_fraud_gate] PASS: KB2 | 3/3 blocked | log AUDIT thật → Loki (Grafana fire trong ≤1 phút)
```

**Grafana rule:** `fraud-gate-bypass-alert.yml` — query log **tầng ứng dụng** (khác KB1/KB3/KB5): `{namespace="financial",app="payment-service"} | json | level="AUDIT" | event="payment_blocked_fraud"` → case severity=critical, playbook `isolate_workload` (scale `payment-service` về 0).

---

## 6. KB3 — Lateral Movement via Unauthorized Internal Path (T1021.007)

**Zero Trust principle:** *Least Privilege ở tầng service-to-service* — có SVID hợp lệ (đã "ở trong mạng nội bộ", mTLS thành công) **không** có nghĩa được gọi bất kỳ endpoint nào của service khác. OPA whitelist đúng path/method cho từng service, deny phần còn lại.

> Kịch bản này **khác hoàn toàn** so với bản tài liệu 28/06 (bản cũ mô tả `kubectl exec` gọi `api-gateway` không kèm Authorization header → 401 `missing_bearer`). Script thật hiện tại (`tests/grafana_kb3_lateral_movement.sh`) đã được viết lại — dùng SVID mTLS thật, gọi thẳng `payment-service`, bị **OPA** (không phải api-gateway) từ chối vì sai path, trả **403** (không phải 401).

**Script thật:**
1. Lấy pod `notification-service` (đóng vai attacker đã compromise pod này) — pod có SVID hợp lệ `spiffe://ztlab.local/aws/notification-service` do SPIRE agent tự động cấp (không cần làm gì thêm để "có" SVID — mọi pod trong mesh đều có).
2. `kubectl exec` vào pod đó, chạy Python `urllib.request` gọi thẳng `http://payment-service.financial.svc.cluster.local:8080/payments/internal/execute` (service-to-service qua istio-proxy sidecar của payment-service, ISTIO_MUTUAL tự động).
3. `zta_policy.rego`'s `internal_service_request` chỉ whitelist POST tới `/payments`, `/score`, `/notify`, hoặc path bắt đầu bằng `/accounts`/`/transactions` (trừ `/transactions/execute`) — **`/payments/internal/execute` không khớp bất kỳ rule nào** → `allow=false` → istio-proxy trả 403 (request này đi qua `kubectl exec` service-to-service thật, KHÔNG qua port-forward — xác nhận đúng qua Istio/OPA, không phải app code, xem §2.3).

**Kết quả chạy thật (2026-08-19):**
```
[KB3_lateral_movement] Attacker pod: notification-service-774cbc8d58-fcchr (IP: 10.42.2.8, SVID: spiffe://ztlab.local/aws/notification-service)
[KB3_lateral_movement] Tấn công: notification-service → payment-service POST /payments/internal/execute
[KB3_lateral_movement]   Attempt 1 → DENIED-403
[KB3_lateral_movement]   Attempt 2 → DENIED-403
[KB3_lateral_movement]   Attempt 3 → DENIED-403
[KB3_lateral_movement] OPA từ chối 3/3 — lateral movement bị chặn tại /payments/internal/execute
```

**Grafana rule:** `lateral-movement-alert.yml` — `{job="opa-decisions",opa_result="false",request_path="/payments/internal/execute"}` → case severity=critical, playbook `isolate_workload` (target `payment-service`, cùng workload mà attacker cố với tới — cô lập chính nó).

---

## 7. KB4 — Data Exfiltration / Large Response (T1041)

**Zero Trust principle:** *Assume Breach + Egress Monitoring* — giám sát cả traffic ra, không chỉ chặn ở lối vào.

> Khác với bản 28/06 (mô tả 10 request HTTP thật lấy `bytes_sent` từ response thật, ngưỡng 5000 byte), cơ chế thật **không tạo traffic HTTP thật** — script đẩy thẳng **5 dòng log giả lập** vào Loki qua API push, mô phỏng đúng shape log mà istio-proxy sẽ tạo ra nếu có response lớn thật. Không có file `tests/grafana_kb4_exfiltration.sh` — kịch bản này chạy qua `bash scripts/run-demo.sh --kb4` (hàm `run_kb4`).

**Cơ chế thật** (`scripts/run-demo.sh`, hàm `run_kb4`):
```python
# Đẩy 5 log entry vào Loki, label job="envoy-access", mỗi entry:
{"bytes_sent": 3100000, "response_code": 200, "path": "/accounts/export",
 "source_ip": "10.10.4.88", "message": "Abnormal response size 3.1MB — possible data exfiltration #<i>"}
```
Ngưỡng rule thật là **1.048.576 byte (1 MiB)**, không phải 5000 như bản cũ — `3.100.000 > 1.048.576` nên fire ngay.

**Kết quả chạy thật (2026-08-19):**
```
▶ Push 5 log vào Loki (job=envoy-access + JSON bytes_sent=3100000 > 1048576)...
▶ Grafana query: {job=envoy-access} | json | bytes_sent > 1048576 [5m]
OK — 5 logs pushed (bytes_sent=3100000)
▶ Đợi Grafana alert fire + SOAR xử lý (90s max)...
▶ SOAR đề xuất restrict_egress — admin phải duyệt tại web portal
FOUND_HITL
  case_id  : case-20260819172850-3ce4f5
  status   : pending_approval
  playbook : restrict_egress | severity: high
  context  : ctx-openstack | workload: core-banking
```

**Grafana rule:** `large-response-alert.yml` → case severity=high, playbook `restrict_egress`, **target `ctx-openstack`/`core-banking`** — xác nhận pipeline phát hiện (AWS) → phản ứng (OpenStack) hoạt động xuyên cloud thật.

---

## 8. KB5 — Access Denied Spike / OPA RBAC (T1078)

**Zero Trust principle:** *Least Privilege* — `merchant01` (role `financial-read` only) có JWT hợp lệ (đăng nhập thành công), nhưng OPA `permissions["financial-read"]` không có quyền `POST` → deny-by-default áp dụng dù danh tính đã xác thực đúng.

**Script thật:** `tests/grafana_kb5_access_denied.sh` — lấy JWT `merchant01` qua client `api-gateway` (+ secret), gửi 6 lần `POST /payments` với số tiền khác nhau.

**Cập nhật 2026-08-23:** cũng như KB1 (xem cảnh báo port-forward ở §2.3/Mục 4), request tấn công thật của script này đi qua `$GW_URL` (`kubectl port-forward svc/api-gateway`) — **bỏ qua lớp Istio/OPA hoàn toàn**. Đã xác nhận bằng thực nghiệm: response có `server: uvicorn` (không phải `istio-envoy`), OPA **không hề được gọi** (0 decision-log entry cho path `/payments` trong cửa sổ test). Cơ chế chặn thật là app code (`services/api-gateway/main.py:_require_role`): `role not in roles` → log `{event:"authz_denied", required_role:"financial-write", user:"merchant01", source_ip}` → trả 403 `{"detail":"role 'financial-write' required"}`.

(OPA **cũng có** rule tương đương — `role_permits_action` kiểm `permissions["financial-read"]["POST"]` không tồn tại → `allow=false` — nhưng rule này của OPA không được thực thi cho đường đi qua port-forward vì OPA không hề nằm trên đường đi đó. Nếu test qua Traefik thật, OPA MỚI là tầng chặn thật — chưa verify riêng KB5 qua đường này, chỉ verify KB1 qua Traefik trong Mục 4.)

**Kết quả chạy thật:**
```
[KB5_access_denied]   POST /payments 100000 → HTTP 403
[KB5_access_denied]   POST /payments 50000 → HTTP 403
[KB5_access_denied]   POST /payments 200000 → HTTP 403
[KB5_access_denied]   POST /payments 75000 → HTTP 403
[KB5_access_denied]   POST /payments 1000000 → HTTP 403
[KB5_access_denied]   POST /payments 5000 → HTTP 403
[KB5_access_denied] OPA RBAC từ chối 6/6 (403) → decision log → Loki {job=opa-decisions, request_path=/payments}
```
(dòng log của chính script ghi "OPA RBAC" mang tính mô tả chung/lịch sử — tầng chặn thật đã xác nhận là app-level, xem giải thích ở trên)

**Grafana rule:** `access-denied-alert.yml` (đã sửa 2026-08-23, LogQL cũ `job="opa-decisions"` chưa từng khớp traffic thật của test này) — `sum(count_over_time({namespace="financial",app="api-gateway"} | json | event="authz_denied" [10m]))` → case severity=high, playbook `block_source_ip`. Verify trực tiếp trên Loki: count tăng đúng theo số lần chạy KB5 (6 request/lần).

---

## 9. KB6 — Container Privilege Escalation (T1068)

**Trạng thái thật, xác nhận end-to-end ngày 2026-08-20:** `k8s/financial/security-scanner-job.yaml` phát hiện vi phạm → `privilege-escalation-alert.yml` (Grafana) fire → webhook thật tới SOAR → case `privilege_escalation` tạo thành công (`severity=critical`, `playbook=quarantine_workload`, `status=pending_approval`). Trước đây pipeline này chưa từng chạy được (thiếu rule Grafana thật + SOAR thiếu key taxonomy) — đã vá tận gốc, không còn là "hướng phát triển tiếp theo" nữa.

**Cách chạy để tái hiện:**
```bash
kubectl --context ctx-aws delete job security-scanner -n financial --ignore-not-found=true
kubectl --context ctx-aws apply -f k8s/financial/security-scanner-job.yaml
kubectl --context ctx-aws logs -n financial job/security-scanner
# Chờ ≤60s (interval Grafana 1m) rồi kiểm tra case:
curl -s http://localhost:8091/cases | python3 -c "import json,sys; print([c for c in json.load(sys.stdin) if c['attack_type']=='privilege_escalation'][-1])"
```

**Cơ chế Job thật** (`k8s/financial/security-scanner-job.yaml`, chạy `python:3.12-alpine`, namespace `financial`):
```python
uid = os.getuid()                     # 0 nếu namespace không enforce runAsNonRoot
cap_eff = <đọc CapEff từ /proc/1/status>
shadow_readable = <thử đọc /etc/shadow>
dangerous = <decode CapEff hex thành tên capability: DAC_OVERRIDE, SETUID, ...>
violation = uid == 0 or shadow_readable or bool(dangerous)
# Ghi JSON: {"level":"AUDIT","service":"security-scanner","event":"privilege_escalation" if violation else "security_check_passed",
#            "uid":uid,"cap_eff":cap_eff,"dangerous_capabilities":dangerous,"shadow_readable":shadow_readable,"violation":violation}
```

**Chạy thủ công để xem bằng chứng:**
```bash
kubectl --context ctx-aws apply -f k8s/financial/security-scanner-job.yaml
kubectl --context ctx-aws logs -n financial job/security-scanner
```

---

*Đối chiếu 2026-08-20 với: `opa/policies/zta_policy.rego`, `opa/policies/fraud_gate.rego`, `services/api-gateway/main.py`, `services/fraud-detection/main.py`, `services/soar-engine/main.py`, `k8s/keycloak/realm-config.json`, `spire/server/*.conf`, `envoy/*.yaml`, `plg-stack/grafana/alerting/*.yml`, `k8s/financial/security-scanner-job.yaml`, và log Loki thật từ lần chạy demo cùng ngày.*
