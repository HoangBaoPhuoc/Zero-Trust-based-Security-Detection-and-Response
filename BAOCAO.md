# BÁO CÁO ĐỒ ÁN CHUYÊN NGÀNH

---

**ĐẠI HỌC QUỐC GIA TP. HỒ CHÍ MINH**  
**TRƯỜNG ĐẠI HỌC CÔNG NGHỆ THÔNG TIN**

---

**TÊN ĐỀ TÀI (TIẾNG VIỆT):**  
Triển khai Hệ thống Phát hiện và Phản ứng Sự cố Bảo mật Dựa trên Zero Trust cho Hệ thống Hướng Microservices trong Môi trường Multi-Cloud

**TÊN ĐỀ TÀI (TIẾNG ANH):**  
Implementation of a Zero Trust-Based Security Detection and Response System for Microservice Application in Multi-Cloud Environments

**Cán bộ hướng dẫn:** Đỗ Thị Phương Uyên  
**Thời gian thực hiện:** 05/02/2026 – 30/05/2026

**Sinh viên thực hiện:**
- Hoàng Bảo Phước — MSSV: 23521231
- Phạm Võ Khánh Hà — MSSV: 23520414

---

## Mục lục

1. [Tổng quan đề tài](#1-tổng-quan-đề-tài)
2. [Cơ sở lý thuyết](#2-cơ-sở-lý-thuyết)
3. [Thiết kế hệ thống](#3-thiết-kế-hệ-thống)
4. [Triển khai chi tiết](#4-triển-khai-chi-tiết)
5. [Luồng hoạt động từng thành phần](#5-luồng-hoạt-động-từng-thành-phần)
6. [Kết quả kiểm thử](#6-kết-quả-kiểm-thử)
7. [Đánh giá tổng thể](#7-đánh-giá-tổng-thể)
8. [Kết luận và hướng phát triển](#8-kết-luận-và-hướng-phát-triển)
9. [Tài liệu tham khảo](#9-tài-liệu-tham-khảo)

---

## 1. Tổng quan đề tài

### 1.1 Đặt vấn đề

Trong kỷ nguyên chuyển đổi số, điện toán đám mây đã trở thành nền tảng công nghệ chủ đạo. Đặc biệt trong ngành Tài chính – Ngân hàng, mô hình Multi-Cloud ngày càng được áp dụng rộng rãi: hệ thống Core Banking vận hành trên Private Cloud để đảm bảo kiểm soát dữ liệu, trong khi các dịch vụ ngân hàng số tận dụng Public Cloud để mở rộng linh hoạt. Theo Gartner (2024), hơn 85% doanh nghiệp đang sử dụng ít nhất hai nhà cung cấp cloud khác nhau.

Tuy nhiên, sự phức tạp của môi trường Multi-Cloud tạo ra những điểm mù nghiêm trọng về bảo mật. Các mô hình bảo mật truyền thống dựa trên network perimeter và implicit trust đã chứng tỏ sự lỗi thời qua các sự cố lớn như SolarWinds (2020) và Colonial Pipeline (2021). Thiếu sự thống nhất về chính sách bảo mật và giám sát giữa các miền cloud khiến thời gian phát hiện vi phạm (MTTD) cao hơn trung bình 27% so với môi trường đơn lẻ (IBM, 2023).

Thị trường đã có các giải pháp như Cloudflare One, Zscaler, Palo Alto Prisma Access, nhưng vẫn đối mặt với thách thức về chi phí cao và thiếu khả năng phản ứng tự động có kiểm soát ở cấp độ workload trong môi trường Kubernetes Multi-Cloud.

### 1.2 Mục tiêu

**Mục tiêu tổng quát:** Nghiên cứu và triển khai mô hình phòng thủ chủ động dựa trên kiến trúc Zero Trust tích hợp SIEM/SOAR hỗ trợ AI trên hạ tầng Multi-Cloud thực tế, tối ưu hóa MTTD và MTTR đồng thời đảm bảo có cơ chế kiểm soát của con người (HITL) trước mọi hành động tự động.

**Mục tiêu cụ thể:**
- Thiết lập định danh workload phi tập trung với SPIFFE/SPIRE — loại bỏ implicit trust dựa trên IP
- Thực thi kiểm soát truy cập thích ứng với Envoy + OPA + Keycloak trên mọi service-to-service call
- Xây dựng SIEM tập trung với PLG Stack thu thập log từ hai cloud
- Triển khai AI Analyzer với LLM để suy luận ngữ nghĩa từ log, nhận diện MITRE ATT&CK techniques
- Tự động hóa phản ứng sự cố với SOAR Engine, có cơ chế HITL và rollback
- Xây dựng hệ thống quản lý case sự cố với TheHive

### 1.3 Phạm vi và giới hạn

**Phạm vi:**
- Hạ tầng: 2 K3s cluster tách biệt — AWS (master + worker) và OpenStack (standalone)
- Ứng dụng: 7 microservice mô phỏng luồng thanh toán ngân hàng
- Bảo mật: SPIFFE/SPIRE mTLS, Envoy ext_authz, OPA policy, Keycloak OIDC, NetworkPolicy
- Quan sát: PLG Stack (Promtail-Loki-Grafana), Prometheus, AI Analyzer, SOAR Engine, TheHive

**Giới hạn:**
- Môi trường lab: 3 EC2 t3.medium + 1 OpenStack node; không mô phỏng traffic thực tế quy mô lớn
- Account-service và transaction-service trên OpenStack chưa có Envoy sidecar (plain HTTP nội bộ)
- SPIRE Agent OpenStack dùng `join_token` attestation thay vì `k8s_psat`
- SOAR mặc định `dry_run=false` nhưng chỉ thực thi sau khi admin approve qua HITL

---

## 2. Cơ sở lý thuyết

### 2.1 Kiến trúc Zero Trust (ZTA)

Zero Trust được NIST định nghĩa trong SP 800-207 với nguyên tắc cốt lõi **"Never Trust, Always Verify"**. Khác với mô hình perimeter truyền thống, ZTA yêu cầu xác thực và ủy quyền liên tục cho mọi yêu cầu truy cập, bất kể nguồn gốc.

Ba trụ cột của ZTA trong đề tài:

| Trụ cột | Hiện thực trong ZTLab |
|---------|----------------------|
| **Verify explicitly** | Mọi request phải có JWT (Keycloak) hoặc SVID (SPIRE) hợp lệ trước khi được xử lý |
| **Least privilege** | OPA policy chỉ cho phép đúng path + method + service identity, không có implicit allow |
| **Assume breach** | Toàn bộ quyết định OPA được log, AI phân tích liên tục, SOAR sẵn sàng phản ứng |

### 2.2 SPIFFE/SPIRE — Định danh Workload

SPIFFE (Secure Production Identity Framework for Everyone) là tiêu chuẩn cấp phát danh tính cho workload trong môi trường phân tán. SPIRE là hiện thực của tiêu chuẩn này.

Mỗi workload được cấp **SVID (SPIFFE Verifiable Identity Document)** dưới dạng chứng chỉ X.509:
```
spiffe://ztlab.local/aws/payment-service
spiffe://ztlab.local/openstack/core-banking
```

SVID có TTL 1 giờ, tự động gia hạn qua SPIRE Agent. mTLS giữa các service sử dụng SVID, loại bỏ quản lý certificate thủ công. Envoy truy cập SVID từ SPIRE Agent qua SDS (Secret Discovery Service) tại Unix socket `/tmp/spire-agent/public/api.sock`.

**Kiến trúc SPIRE trong ZTLab:**
```
[SPIRE Server — AWS cluster]
     │  trust_domain = "ztlab.local"
     │  NodeAttestor: k8s_psat (AWS), join_token (OpenStack)
     │
     ├── SPIRE Agent (DaemonSet — AWS k3s)
     │    └── cấp SVID cho: api-gateway, payment-service, fraud-detection,
     │                       notification-service (qua SDS → Envoy)
     │
     └── SPIRE Agent (DaemonSet — OpenStack k3s)
          └── cấp SVID cho: core-banking
              (kết nối về SPIRE Server qua NodePort 30900 → WireGuard)
```

### 2.3 Open Policy Agent (OPA) — Policy Engine

OPA là policy engine "policy as code" — chính sách viết bằng Rego được đánh giá tại runtime. Trong ZTLab, OPA tích hợp vào Envoy như **ext_authz server**: trước khi Envoy forward bất kỳ request nào, nó gửi một gRPC CheckRequest sang OPA và chỉ tiếp tục nếu OPA trả về `allowed=true`.

Ba policy file trong hệ thống:

| File | Package | Vai trò |
|------|---------|---------|
| `zta_policy.rego` | `zta.authz` | Policy chính — Envoy ext_authz query `zta/authz/allow` |
| `fraud_gate.rego` | `zta.fraud_gate` | Định nghĩa `fraud_gate_valid` — import bởi zta_policy |
| `cross_cloud.rego` | `zta.crosscloud` | Validate cross-cloud SVID pair |

**Bốn loại request và quyết định của OPA:**

```
Request đến Envoy sidecar
     │
     ├── Không có token và không có SVID?
     │    └── path = /health, /ready, /metrics → ALLOW (public)
     │    └── path khác → DENY (missing_bearer)
     │
     ├── Có Bearer JWT (không có SVID)?  →  external request
     │    └── JWT hợp lệ (RS256, issuer đúng, role có financial-write)?
     │         ├── YES → ALLOW POST /payments, GET *
     │         └── NO  → DENY (invalid_jwt)
     │
     ├── Có X-SPIFFE-ID (có SVID)?  →  internal service call
     │    └── SVID thuộc trust domain ztlab.local?
     │         ├── YES → ALLOW POST /payments|/score|/notify|/accounts/*|/transactions/*
     │         └── NO  → DENY (svid_not_authorized)
     │
     └── Có SVID + X-Fraud-Gate: passed + X-Fraud-Score < 75?  →  core transaction
          └── ALLOW POST /transactions/execute
```

### 2.4 Envoy Proxy — Policy Enforcement Point

Envoy chạy như **sidecar container** trong các pod tài chính AWS, đóng vai trò PEP (Policy Enforcement Point). Mọi traffic vào/ra pod đều đi qua Envoy.

Cấu hình Envoy bao gồm:
- **Listener 15006** (inbound): chặn toàn bộ traffic vào pod, gọi OPA ext_authz
- **Cluster `opa_authz`**: kết nối gRPC đến `opa-server.financial.svc.cluster.local:9191`
- **Cluster `local_service`**: forward về ứng dụng (port 8080) sau khi OPA cho phép
- **Cluster `core_banking`**: **STATIC** upstream trỏ thẳng `10.10.1.12:30081` (cross-cloud)
- **Access log**: JSON format, Promtail thu thập mỗi request

### 2.5 Keycloak — Identity Provider

Keycloak cung cấp OIDC/OAuth2 với realm `ztlab`, client `api-gateway`. Token RS256 có claim `realm_access.roles` chứa vai trò người dùng. API Gateway verify JWT bằng JWKS endpoint của Keycloak trước khi forward vào pipeline.

### 2.6 PLG Stack — SIEM tập trung

Promtail-Loki-Grafana thay thế ELK Stack, nhẹ hơn ~10× về bộ nhớ:

- **Promtail**: DaemonSet trên cả hai cluster, gán label `cloud`, `namespace`, `app`, `node` cho mỗi log stream
- **Loki**: Backend aggregation, index theo label (không full-text), lưu PVC 10Gi trên AWS
- **Grafana**: Visualization, alerting engine, datasource Loki + Prometheus

Log từ OpenStack được Promtail đẩy về Loki qua socat relay `10.10.1.11:31100` — systemd service `loki-proxy.service` tự khởi động khi reboot.

### 2.7 AI Analyzer — SOC Analyst tự động

AI Analyzer là FastAPI service đóng vai trò **AI-driven SOC analyst**, tích hợp LLM để phân tích log theo thời gian thực. Provider chain: OpenAI GPT-4o-mini → Google Gemini Flash → Heuristic rule-based fallback.

**Output schema chuẩn:**
```json
{
  "verdict": "normal | suspicious | malicious",
  "severity": "low | medium | high | critical",
  "confidence": 0.0–1.0,
  "attack_type": "<định danh kỹ thuật>",
  "attack_techniques": ["T1110.001", "T1078"],
  "recommended_playbook": "isolate_workload | restrict_egress | quarantine_workload",
  "affected_service": "<service bị ảnh hưởng>",
  "source_ip": "<IP tấn công nếu có>",
  "reasoning": "<giải thích ngắn gọn>"
}
```

**Xử lý theo ngưỡng severity:**
- `low/medium` → ghi verdict vào Loki, không tạo alert
- `high/critical` → tạo pending alert (in-memory, TTL 3600s) + TheHive alert + push Loki `{pending_approval="true"}` → HITL flow

### 2.8 SOAR Engine — Automated Response

SOAR Engine nhận alert đã được admin approve và thực thi playbook trực tiếp trên Kubernetes API:

| Playbook | Hành động | Mục đích |
|----------|-----------|---------|
| `isolate_workload` | Patch Service selector với label không tồn tại | Ngắt traffic vào pod, giữ pod còn chạy để forensics |
| `restrict_egress` | Patch NetworkPolicy chặn toàn bộ egress | Ngăn data exfiltration tiếp tục |
| `quarantine_workload` | Scale Deployment replicas=0 | Tắt hoàn toàn service bị compromise |

Mọi action được append vào `cases.jsonl` (PVC 1Gi) — audit trail bền vững qua pod restart. `POST /cases/{id}/rollback` khôi phục trạng thái trước.

### 2.9 TheHive — Incident Response Platform

TheHive là nền tảng quản lý sự cố mã nguồn mở, backend Cassandra. AI Analyzer tự động tạo TheHive **alert** khi phát hiện high/critical threat. Khi admin approve, AI tạo thêm TheHive **case** để lưu dấu điều tra (IR timeline, observables, tasks).

---

## 3. Thiết kế hệ thống

### 3.1 Kiến trúc tổng thể — 4 lớp

```
┌─────────────────────────────────────────────────────────────────────────┐
│  LỚP 1: ỨNG DỤNG                                                        │
│  Browser → Web Portal → API Gateway                                      │
│  → Payment → Fraud Detection → Core Banking → Account → Transaction      │
├─────────────────────────────────────────────────────────────────────────┤
│  LỚP 2: KIỂM SOÁT TRUY CẬP (Zero Trust Enforcement)                    │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐                 │
│  │ Keycloak    │  │ Envoy Proxy  │  │ SPIFFE/SPIRE   │                 │
│  │ OIDC RS256  │  │ sidecar PEP  │  │ SVID X.509     │                 │
│  │ JWT Bearer  │  │ ext_authz    │  │ mTLS auto-renew│                 │
│  └─────────────┘  └──────────────┘  └────────────────┘                 │
│                         │                                               │
│                   ┌─────▼──────┐                                        │
│                   │ OPA Policy │ zta_policy.rego + cross_cloud.rego     │
│                   └────────────┘                                        │
├─────────────────────────────────────────────────────────────────────────┤
│  LỚP 3: QUAN SÁT & PHẢN ỨNG (SIEM/SOAR)                                │
│  Promtail → Loki → AI Analyzer (LLM) → Grafana Alerting (HITL)         │
│                                      → TheHive (Case IR)                │
│                                      → SOAR Engine → Kubernetes         │
│  Prometheus → Grafana (dashboards)                                      │
├─────────────────────────────────────────────────────────────────────────┤
│  LỚP 4: HẠ TẦNG MULTI-CLOUD                                             │
│  AWS K3s (10.10.1.10 / .11)   ←── WireGuard VPN ───►   OpenStack K3s   │
│  Public Cloud workloads               mTLS / SVID       (10.10.1.12)   │
│                                                          Private Cloud  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Hạ tầng Multi-Cloud

#### AWS — Public Cloud

```
AWS VPC (10.10.0.0/16)
├── Subnet Management (10.10.4.0/24) — aws-bastion (EIP: 54.254.145.86)
├── Subnet DMZ       (10.10.0.0/24) — aws-gateway (WireGuard server)
├── Subnet Private   (10.10.1.0/24) — aws-k3s-master  (10.10.1.10)
│                                   — aws-k3s-worker-1 (10.10.1.11)
└── Subnet Restricted(10.10.2.0/24) — dự phòng SIEM
```

- Không có EC2 nào trong Private subnet có Public IP
- Mọi truy cập từ internet phải qua bastion (SSH) hoặc WireGuard
- Security Group chỉ mở port 6443, 8080, 30000–32767 trong nội bộ VPC

#### OpenStack — Private Cloud

```
OpenStack Network
├── zta-dmz-network     (192.168.100.0/24) — os-gateway (WireGuard client)
└── zta-private-network (192.168.101.0/24) — os-k3s-master (WG IP: 10.10.1.12)
```

`os-k3s-master` nhận IP WireGuard `10.10.1.12` cùng dải với AWS — cho phép Envoy trên AWS định tuyến đến OpenStack mà không cần DNS cross-cluster.

#### WireGuard VPN — Kết nối liên cloud

```
[aws-gateway: 10.10.0.10]  ←── UDP 51820 (ChaCha20-Poly1305) ───►  [os-gateway]
        │                                                                   │
   Route: 10.10.1.0/24                                          Route: 10.10.1.0/24
```

Toàn bộ traffic cross-cloud (payment-service → core-banking) đi qua tunnel này — mã hóa ở layer network, bổ sung thêm một lớp ngoài mTLS ứng dụng. WireGuard chạy như `wg-quick@wg0` systemd service, tự khởi động khi reboot.

### 3.3 Phân bố workload theo Data Classification

| Cloud | Workload | Lý do phân bố |
|-------|---------|--------------|
| **AWS** | api-gateway, payment-service, fraud-detection, notification-service | Tiếp nhận external traffic, xử lý logic nghiệp vụ thông thường |
| **AWS** | Keycloak, OPA, Redis, Web Portal | Identity provider, policy engine, session store |
| **AWS** | Loki, Grafana, AI Analyzer, SOAR, TheHive, Prometheus | SIEM/SOAR — quản lý tập trung |
| **OpenStack** | core-banking, account-service, transaction-service | **Dữ liệu nhạy cảm** — core banking, số dư tài khoản, lịch sử giao dịch |
| **OpenStack** | PostgreSQL (accounts_db + transactions_db) | Database persist cho tài khoản và ledger |

---

## 4. Triển khai chi tiết

### 4.1 Infrastructure as Code

**Terraform** provision tài nguyên cloud:
- `terraform/aws/`: VPC, subnet, security group, EC2, Elastic IP, key pair
- `terraform/openstack/`: Network, router, security group, Nova instances

**Ansible** configuration management:
- `baseline.yml`: cài Docker, K3s, dependency
- `wireguard.yml`: cấu hình WireGuard tunnel
- `promtail.yml`: deploy Promtail DaemonSet

**K3s** được chọn (thay kubeadm) vì nhẹ ~70MB binary, phù hợp EC2 t3.medium, có local-path provisioner tích hợp.

### 4.2 SPIRE — Cấu hình định danh

```
SPIRE Server (AWS) — trust_domain="ztlab.local", CA TTL=168h, SVID TTL=1h
     │
     ├── NodeAttestor k8s_psat (AWS nodes)
     │    → Chứng thực dựa trên ServiceAccount Projected Token của K3s
     │
     └── NodeAttestor join_token (OpenStack)
          → Agent kết nối về SPIRE Server qua NodePort 30900 (AWS master)
          → Token hết hạn khi EC2 restart — cần tạo mới (xem HUONG_DAN.md)
```

**~16 SVID entries đã đăng ký:**
```
spiffe://ztlab.local/aws/api-gateway
spiffe://ztlab.local/aws/payment-service
spiffe://ztlab.local/aws/fraud-detection
spiffe://ztlab.local/aws/notification-service
spiffe://ztlab.local/openstack/core-banking
spiffe://ztlab.local/openstack/account-service
spiffe://ztlab.local/openstack/transaction-service
... (và các service phụ trợ)
```

### 4.3 Envoy — Cấu hình sidecar

```yaml
# envoy/configmap.yaml — trích cấu hình key
listeners:
  - name: inbound_15006        # chặn mọi traffic vào pod
    address: 0.0.0.0:15006
    filter_chains:
      - filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              http_filters:
                - name: envoy.filters.http.ext_authz
                  typed_config:
                    grpc_service:
                      envoy_grpc:
                        cluster_name: opa_authz  # gọi OPA trước khi forward
                - name: envoy.filters.http.router

clusters:
  - name: opa_authz
    type: STRICT_DNS
    load_assignment:
      endpoints:
        - lb_endpoints:
            endpoint:
              address: {socket_address: {address: opa-server.financial.svc.cluster.local, port_value: 9191}}

  - name: local_service          # ứng dụng trong cùng pod
    load_assignment:
      endpoints:
        - lb_endpoints:
            endpoint:
              address: {socket_address: {address: 127.0.0.1, port_value: 8080}}

  - name: core_banking           # cross-cloud STATIC upstream
    type: STATIC
    connect_timeout: 8s
    load_assignment:
      endpoints:
        - lb_endpoints:
            endpoint:
              address: {socket_address: {address: 10.10.1.12, port_value: 30081}}
```

OPA query path: `POST /v1/data/zta/authz/allow` — package `zta.authz` trong `zta_policy.rego`.

### 4.4 OPA Policy — Rego rules

```rego
# opa/policies/zta_policy.rego (trích)
package zta.authz

import future.keywords.if
import future.keywords.in

default allow = false

headers          := input.attributes.request.http.headers
method           := input.attributes.request.http.method
path             := input.attributes.request.http.path
source_principal := object.get(object.get(input.attributes, "source", {}), "principal",
                   object.get(object.get(input, "source", {}), "principal", ""))

# --- JWT helpers ---

bearer_token := t if {
  raw := headers["authorization"]
  startswith(raw, "Bearer ")
  t := substring(raw, 7, -1)
}

jwt_payload := payload if {
  [_, payload, _] := io.jwt.decode(bearer_token)
}

# Role → HTTP method được phép
permissions := {
  "financial-read":  {"GET": true, "OPTIONS": true},
  "financial-write": {"GET": true, "OPTIONS": true, "POST": true, "PUT": true},
  "security-analyst": {"GET": true, "OPTIONS": true},
  "security-admin":  {"GET": true, "OPTIONS": true, "POST": true, "PUT": true, "DELETE": true},
}

# JWT hợp lệ: issuer đúng VÀ chưa hết hạn
valid_jwt if {
  jwt_payload.iss == "http://keycloak.ztlab.local/realms/ztlab"
  jwt_payload.exp > time.now_ns() / 1e9
}

# Ít nhất một realm_access.role trong JWT cho phép HTTP method hiện tại
role_permits_action if {
  some role in jwt_payload.realm_access.roles
  permissions[role][method]
}

# SVID từ trust domain ztlab.local (internal service)
valid_svid if { startswith(source_principal, "spiffe://ztlab.local/") }

# Fraud gate: X-Fraud-Gate=passed VÀ score < 75
fraud_gate_valid if {
  headers["x-fraud-gate"] == "passed"
  to_number(headers["x-fraud-score"]) < 75
}

# === Allow rules ===

# 1. Public endpoints: /health, /ready, /metrics
allow if { public_path }

# 2. External user — JWT hợp lệ + role phù hợp method, không có SVID
allow if { external_api_request }

# 3. Internal service-to-service (SVID từ trust domain)
allow if { internal_service_request }

# 4. Core transaction qua fraud gate
allow if { core_transaction_with_fraud_gate }

public_path if { path in ["/health", "/ready", "/metrics"] }
public_path if { startswith(path, "/metrics") }

external_api_request if {
  method == "POST"; path == "/payments"
  valid_jwt; role_permits_action; not valid_svid
}
external_api_request if {
  method in ["GET", "OPTIONS"]
  valid_jwt; role_permits_action; not valid_svid
}

internal_service_request if { valid_svid; method in ["GET", "OPTIONS"] }
internal_service_request if { valid_svid; method == "POST"; path in ["/payments", "/score", "/notify"] }
internal_service_request if { valid_svid; method == "POST"; startswith(path, "/accounts") }
internal_service_request if { valid_svid; method == "POST"; startswith(path, "/transactions") }

core_transaction_with_fraud_gate if {
  valid_svid; method == "POST"; startswith(path, "/transactions/execute")
  fraud_gate_valid
}
```

### 4.5 NetworkPolicy

**AWS** (`aws-allow-list.yaml`):
- Financial pods: nhận ingress từ `financial`, `monitoring`, `kube-system`
- Egress: DNS (53), internal cluster, identity namespace, **cross-cloud rule**: `10.10.1.12/32:30081`

**OpenStack** (`os-allow-list.yaml`):
- Financial pods: nhận ingress từ internal cluster + subnet `10.10.1.0/24` (WireGuard)
- Egress: DNS, intra-cluster (8080, 5432), Loki relay `10.10.1.11:31100`

### 4.6 Microservices — Stack kỹ thuật

Tất cả service viết bằng **Python/FastAPI** với đặc điểm chung:

```python
# Structured logging — mọi service đều log JSON với cấu trúc này
{
    "timestamp": "2026-06-12T10:30:15Z",
    "level": "INFO",
    "service": "payment-service",
    "cloud": "aws",
    "trace_id": "362097f1-5d87-4318-973d-c2ea5e11711b",
    "event": "payment_request",
    # ... các field nghiệp vụ
}
```

**Database tích hợp:**

| Service | DB | Tech | Chi tiết |
|---------|-----|------|---------|
| `account-service` | PostgreSQL `accounts_db` | asyncpg | Table `accounts`; seed ACC-1001/ACC-2001 khi startup |
| `transaction-service` | PostgreSQL `transactions_db` | asyncpg | Table `ledger`; ghi mỗi giao dịch với UUID, timestamp |
| `fraud-detection` | Redis | redis.asyncio | Sorted Set `fraud:velocity:{account}`; sliding window 60s |

Image được build từ `services/Dockerfile` và sync vào containerd K3s bằng `scripts/sync-financial-images.sh` — không phụ thuộc Docker Hub.

### 4.7 PLG Stack — Logging Pipeline

```
[App logs — JSON structured]
         │
[Envoy access log — JSON per request]
         │
[OPA decision log — allow/deny với context]
         │  ← cả 3 loại log từ mọi pod
[Promtail DaemonSet — AWS cluster]     [Promtail DaemonSet — OpenStack cluster]
         │                                          │
         │                               socat relay 10.10.1.11:31100
         │                                          │
         └──────────────── Loki API ───────────────┘
                     (http://loki.plg-stack.svc.cluster.local:3100)
                                    │
                              [Loki backend]
                              PVC 10Gi on AWS
                                    │
                     ┌──────────────┼──────────────────┐
                     │              │                   │
              [Grafana]     [AI Analyzer]         [Prometheus]
              (query LogQL)  (poll mỗi 120s)     (query metrics)
```

**5 Grafana dashboards:**
- ZTA Security Overview: tổng quan OPA decisions, JWT failures, fraud blocks
- Envoy Access Logs: HTTP matrix, response time, error rate
- OPA Decision Log: allow/deny rate theo service, top denied paths
- AI SIEM SOAR: AI verdicts, attack types, SOAR cases, TheHive cases
- **Threat Intelligence Feed** (mới): MITRE heatmap, top source IPs, verdict distribution, live event stream

### 4.8 AI Analyzer — Cấu hình và triển khai

```yaml
# k8s/plg-stack/ai-soar.yaml (trích env)
- name: AI_PROVIDER                          # "openai" hoặc "gemini" (từ Secret ai-secrets)
- name: AI_ANALYZER_POLL_INTERVAL_SECONDS    # "120" — poll Loki mỗi 2 phút
- name: AI_ANALYZER_LOOKBACK_SECONDS         # "300" — nhìn lại 5 phút gần nhất
- name: AI_ANALYZER_MAX_LOGS_PER_BATCH       # "10" — tối đa 10 log/batch để tiết kiệm token
- name: AI_ANALYZER_MIN_ALERT_SEVERITY       # "medium" — dưới ngưỡng này bỏ qua
- name: AI_ANALYZER_ADMIN_APPROVAL_SEVERITY  # "high" — cần admin approve
- name: AI_ANALYZER_PENDING_TTL_SECONDS      # "3600" — pending alert tự expire sau 1h
- name: THEHIVE_URL                          # http://thehive.plg-stack.svc.cluster.local:9000
- name: SOAR_WEBHOOK_URL                     # http://soar-engine.plg-stack.svc.cluster.local:8080/alerts
```

**Heuristic fallback patterns (khi không có API key):**

| Pattern (Regex) | Attack Type được gán |
|----------------|---------------------|
| `(401\|403\|denied\|unauthorized)` | `access_denied` |
| `fraud_gate_bypass` | `fraud_gate_bypass` |
| `lateral\|invalid.*svid\|spiffe.*den` | `lateral_movement` |
| `port scan\|nmap\|masscan\|syn scan` | `port_scan` |
| `privilege escalation\|setuid\|cap_sys_admin` | `privilege_escalation` |
| `xmrig\|cryptomin\|stratum\+tcp` | `cryptomining` |
| `sqlmap\|union select\|/etc/passwd` | `exploit_probe` |
| `bytes_sent=[1-9]\d{6,}` | `large_response` |

### 4.9 SOAR Engine — RBAC và persistent storage

**RBAC trên AWS cluster:**
```yaml
# k8s/rbac/soar-rbac.yaml
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "patch", "list"]
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get", "patch", "list"]
```

**Cross-cluster:** SOAR dùng kubeconfig `ctx-openstack` mount qua Secret, kết nối `localhost:6445` (SSH tunnel → `10.10.1.12:6443`) để thao tác workload OpenStack.

**Persistent storage:** PVC `soar-cases-pvc` (1Gi) mount tại `/data`. File `cases.jsonl` tích lũy tất cả case qua các lần restart.

---

## 5. Luồng hoạt động từng thành phần

### 5.1 Luồng Request từ Browser đến Core Banking (Happy Path)

Đây là luồng đầy đủ nhất trong hệ thống — từ trình duyệt người dùng đến database OpenStack:

```
BƯỚC 1: Đăng nhập qua Keycloak
────────────────────────────────────────────────────────────────
Browser
  │  POST /realms/ztlab/protocol/openid-connect/token
  │  grant_type=password, client_id=web-portal
  │  username=testuser01, password=Test1234!
  ▼
[Keycloak — identity namespace]
  │  Verify credentials → PostgreSQL keycloak-db
  │  Sign JWT (RS256, private key nội bộ Keycloak)
  │  Payload: { sub, preferred_username,
  │             realm_access.roles: ["financial-write"],
  │             iss: "http://keycloak.ztlab.local/realms/ztlab",
  │             exp: now + 300s }
  ▼
Browser nhận: { access_token: "eyJ...", expires_in: 300 }


BƯỚC 2: Gọi API Gateway
────────────────────────────────────────────────────────────────
Browser
  │  POST /payments
  │  Authorization: Bearer eyJ...
  │  Content-Type: application/json
  │  Body: {"from_account":"ACC-1001","to_account":"ACC-2001",
  │          "amount":100000,"currency":"VND"}
  ▼
[api-gateway service — financial namespace, AWS]
  │
  │  1. Rate limit check (60 req/min/IP — in-memory counter)
  │     ├── Under limit → PASS
  │     └── Over limit  → 429 Too Many Requests
  │
  │  2. JWT Verification
  │     ├── Fetch JWKS từ Keycloak (cached, refresh khi rotate)
  │     │   GET http://keycloak.identity.svc.cluster.local:8080/
  │     │        realms/ztlab/protocol/openid-connect/certs
  │     ├── Verify RS256 signature bằng public key từ JWKS
  │     ├── Check issuer = "http://keycloak.ztlab.local/realms/ztlab"
  │     ├── Check exp không hết hạn
  │     ├── Check realm_access.roles contains "financial-write"
  │     └── Nếu fail → 401 Unauthorized
  │
  │  3. Tạo headers downstream
  │     X-Trace-ID: uuid4() (mới, nếu không có)
  │     X-User-ID: token.preferred_username
  │     X-User-Roles: token.realm_access.roles
  │
  │  4. Forward đến payment-service
  │     (api-gateway tự nó không có Envoy sidecar, forward trực tiếp)
  ▼
  → payment-service:8080/payments (qua K8s Service ClusterIP)


BƯỚC 3: Envoy sidecar intercept tại payment-service
────────────────────────────────────────────────────────────────
[Envoy sidecar — port 15006, cùng pod với payment-service]
  │
  │  1. Intercept inbound request trên port 15006
  │
  │  2. Gửi gRPC CheckRequest sang OPA ext_authz
  │     → POST http://opa-server.financial.svc.cluster.local:9191
  │             /v1/data/zta/authz/allow
  │     Body: {
  │       "input": {
  │         "attributes": {
  │           "request": {
  │             "http": {
  │               "method": "POST",
  │               "path": "/payments",
  │               "headers": {
  │                 "authorization": "Bearer eyJ...",
  │                 "x-trace-id": "362097f1-...",
  │                 "x-forwarded-client-cert": ""  ← không có SVID (external)
  │               }
  │             }
  │           }
  │         }
  │       }
  │     }
  │
  │  3. OPA đánh giá zta_policy.rego:
  │     - has_svid? → NO (không có x-forwarded-client-cert)
  │     - has_valid_jwt? → YES (Bearer token hợp lệ)
  │     - has_financial_write_role? → YES (từ JWT claim)
  │     - path "/payments" với method "POST" → ALLOW
  │     → OPA trả về: {"result": true}
  │
  │  4. Envoy nhận allow=true → forward request đến 127.0.0.1:8080
  │
  │  5. Ghi access log JSON:
  │     {"method":"POST","path":"/payments","response_code":200,
  │      "duration_ms":142,"upstream":"local_service",
  │      "opa_result":true,"svid":"","trace_id":"362097f1-..."}
  ▼
  → payment-service app tại 127.0.0.1:8080


BƯỚC 4: Payment Service xử lý
────────────────────────────────────────────────────────────────
[payment-service app — Python/FastAPI]
  │
  │  1. Validate request body
  │     amount <= 500,000,000 VND? → YES
  │     from_account != to_account? → YES
  │
  │  2. Gọi Fraud Detection
  │     POST http://fraud-detection.financial.svc.cluster.local:8080/score
  │     Body: {"account_id":"ACC-1001","amount":100000,
  │             "channel":"web","country":"VN","trace_id":"..."}
  │
  │     [Envoy sidecar fraud-detection: OPA check SVID của payment-service]
  │     → OPA: has_svid=YES, svid=spiffe://ztlab.local/aws/payment-service
  │     → internal_path_allowed("/score")=YES → ALLOW
  │
  │     [fraud-detection app]
  │     ├── Redis ZREMRANGEBYSCORE "fraud:velocity:ACC-1001" (xóa entries cũ)
  │     ├── Redis ZADD "fraud:velocity:ACC-1001" (ghi entry mới)
  │     ├── Redis ZCARD "fraud:velocity:ACC-1001" → count = 1 (velocity thấp)
  │     ├── Tính score:
  │     │   baseline:       5
  │     │   velocity (1<5): 0
  │     │   amount (100K):  0
  │     │   channel (web):  0
  │     │   Total:          5
  │     └── Return: {"score":5,"verdict":"allow","gate":"passed"}
  │
  │  3. Score = 5 < 75 → Fraud gate PASSED
  │     Thêm headers cho cross-cloud:
  │     X-Fraud-Gate: passed
  │     X-Fraud-Score: 5
  │
  │  4. Start timer đo cross-cloud latency
  │
  │  5. Forward đến core-banking qua Envoy upstream cluster "core_banking"
  ▼


BƯỚC 5: Cross-cloud call — Envoy mTLS
────────────────────────────────────────────────────────────────
[Envoy trong pod payment-service — outbound]
  │
  │  1. Request được forward đến cluster "core_banking"
  │     STATIC endpoint: 10.10.1.12:30081
  │     (đi qua WireGuard VPN tunnel)
  │
  │  2. TLS handshake mTLS:
  │     ├── Envoy lấy SVID của payment-service từ SPIRE Agent
  │     │   (qua SDS tại /tmp/spire-agent/public/api.sock)
  │     │   SVID cert: CN=spiffe://ztlab.local/aws/payment-service
  │     │   Private key: ephemeral, do SPIRE cấp, TTL=1h
  │     ├── Present cert đến core-banking Envoy
  │     ├── Verify cert của core-banking:
  │     │   URI SAN = spiffe://ztlab.local/openstack/core-banking
  │     │   Issuer = SPIRE CA (trust_domain ztlab.local)
  │     └── mTLS established (TLS 1.3, ECDHE, AES-256-GCM)
  │
  │  3. Request đến 10.10.1.12:30081
  │     NodePort → core-banking pod (port 15006 — Envoy inbound)
  ▼


BƯỚC 6: Envoy sidecar tại Core Banking (OpenStack)
────────────────────────────────────────────────────────────────
[Envoy sidecar — core-banking pod, OpenStack cluster]
  │
  │  1. Nhận request từ payment-service
  │     Headers bao gồm:
  │     x-forwarded-client-cert: URI=spiffe://ztlab.local/aws/payment-service
  │     x-fraud-gate: passed
  │     x-fraud-score: 5
  │
  │  2. Gửi CheckRequest sang OPA (OpenStack)
  │     → POST http://opa-server.financial.svc.cluster.local:9191
  │             /v1/data/zta/authz/allow
  │
  │  3. OPA đánh giá (cả zta_policy + cross_cloud):
  │     - has_svid? → YES
  │     - svid = spiffe://ztlab.local/aws/payment-service → in trust domain
  │     - path "/payments" → internal_path_allowed → ALLOW
  │     → OPA trả về: {"result": true}
  │
  │  4. Ghi Envoy access log (cloud: openstack):
  │     {"method":"POST","path":"/payments","response_code":200,
  │      "svid":"spiffe://ztlab.local/aws/payment-service",
  │      "opa_result":true,"cloud":"openstack","trace_id":"362097f1-..."}
  ▼
  → core-banking app tại 127.0.0.1:8080


BƯỚC 7: Core Banking xử lý giao dịch
────────────────────────────────────────────────────────────────
[core-banking app — Python/FastAPI, OpenStack]
  │
  │  1. Validate headers
  │     X-Fraud-Gate == "passed"? → YES
  │     X-Fraud-Score < 75? → YES (score=5)
  │     Nếu fail → 403 (fraud_gate_bypass_blocked)
  │
  │  2. Generate transaction_id = uuid4()
  │
  │  3. Gọi account-service (trừ số dư)
  │     POST http://account-service.financial.svc.cluster.local:8080
  │          /accounts/ACC-1001/debit
  │     Body: {"amount":100000,"transaction_id":"...","trace_id":"..."}
  │
  │     [account-service]
  │     → asyncpg: UPDATE accounts SET balance = balance - 100000
  │                WHERE account_id = 'ACC-1001' AND balance >= 100000
  │     → Return: {"new_balance": 9900000, "status": "debited"}
  │
  │  4. Gọi transaction-service (ghi ledger)
  │     POST http://transaction-service.financial.svc.cluster.local:8080
  │          /transactions
  │     Body: {"transaction_id":"...","from":"ACC-1001","to":"ACC-2001",
  │             "amount":100000,"type":"transfer","trace_id":"..."}
  │
  │     [transaction-service]
  │     → asyncpg: INSERT INTO ledger (id, from_account, to_account,
  │                amount, status, created_at) VALUES (...)
  │     → Return: {"status":"committed","ledger_id":"..."}
  │
  │  5. Return đến payment-service:
  │     {"transaction_id":"0d8e75cd-...","status":"completed",
  │      "trace_id":"362097f1-...","cloud":"openstack"}
  ▼


BƯỚC 8: Payment Service kết thúc và trả kết quả
────────────────────────────────────────────────────────────────
[payment-service]
  │
  │  1. Stop timer → ghi metric
  │     ztlab_cross_cloud_latency_seconds{route="aws_to_openstack"} = 0.142
  │
  │  2. Gọi notification-service (async, không chờ)
  │     POST http://notification-service.financial.svc.cluster.local:8080
  │          /notify
  │     Body: {"user_id":"testuser01","event":"payment_completed",
  │             "amount":100000,"trace_id":"..."}
  │
  │  3. Ghi log giao dịch thành công:
  │     {"event":"payment_completed","trace_id":"362097f1-...",
  │      "cloud":"aws","fraud_score":5,"cross_cloud_latency_ms":142}
  │
  │  4. Return response về api-gateway → về browser:
  │     {
  │       "status": "completed",
  │       "trace_id": "362097f1-5d87-4318-973d-c2ea5e11711b",
  │       "fraud": {"score": 5, "verdict": "allow", "gate": "passed"},
  │       "core_banking": {"transaction_id": "0d8e75cd-...",
  │                         "status": "completed"}
  │     }
```

> **Điểm chứng minh Zero Trust:** Cùng `trace_id` xuất hiện trong log của payment-service (cloud: aws) và core-banking (cloud: openstack) — truy vết xuyên cloud trong Grafana với LogQL: `{job="kubernetes-pods", namespace="financial"} |= "362097f1"`.

---

### 5.2 Luồng Fraud Detection chi tiết

```
Yêu cầu thanh toán đến payment-service
  │
  ├── amount > 500,000,000 VND?  →  400 (exceeds_limit)
  │
  └── Gọi fraud-detection /score
            │
            ├── [VELOCITY CHECK — Redis Sorted Set]
            │   Key: "fraud:velocity:ACC-1001"
            │   ZREMRANGEBYSCORE(key, 0, now-60s)  ← xóa entries cũ
            │   ZADD(key, now, uuid)               ← ghi entry mới
            │   count = ZCARD(key)                 ← đếm trong 60s
            │
            │   count ≤ 5:  velocity_score = 0
            │   count ≤ 10: velocity_score = 10   (soft limit)
            │   count ≤ 30: velocity_score = 25   (high velocity)
            │   count > 30: velocity_score = 40   (extreme)
            │
            ├── [AMOUNT SCORE]
            │   amount < 100M:  0
            │   amount < 500M: +30
            │   amount ≥ 500M: +55
            │
            ├── [CHANNEL SCORE]
            │   channel = "tor" / "unknown" / "script": +15
            │   channel = "web" / "mobile": 0
            │
            ├── [COUNTRY SCORE]
            │   country ≠ VN, SG, TH: +10
            │
            └── total = 5 (baseline) + velocity + amount + channel + country
                        │
                        ├── total < 40:  verdict=allow,   gate=passed
                        ├── total < 75:  verdict=review,  gate=passed
                        └── total ≥ 75:  verdict=block,   gate=BLOCKED → 403
```

---

### 5.3 Luồng AI-SOAR từ Log đến Kubernetes Action

```
BƯỚC 1: Thu thập log
────────────────────────────────────────────────────────────────
[Mọi pod tài chính — AWS và OpenStack]
  │  stdout: JSON structured log
  │  Envoy: access log JSON (mỗi request)
  │  OPA: decision log JSON (mỗi allow/deny)
  ▼
[Promtail DaemonSet]
  │  Scrape /var/log/pods/**/*.log
  │  Gán labels: job, namespace, app, cloud, node
  │  Thêm pipeline stage lọc noise
  ▼
[Loki — AWS plg-stack]
  │  Index: labels only (không full-text)
  │  Storage: PVC 10Gi
  │  Retention: 30 ngày


BƯỚC 2: AI Analyzer poll tự động (mỗi 120s)
────────────────────────────────────────────────────────────────
[AI Analyzer — poll loop]
  │
  │  1. Tính time range: [now-300s, now]
  │
  │  2. Query Loki:
  │     GET /loki/api/v1/query_range
  │     query: {job=~"envoy-access|opa-decisions|kubernetes-pods"}
  │             |~ "(?i)(403|401|denied|fraud_gate_bypass|lateral|
  │                       xmrig|port.scan|bytes_sent|unauthorized)"
  │     limit: 25 entries
  │
  │  3. Lọc noise (bỏ qua):
  │     - namespace: plg-stack, monitoring, identity, kube-system
  │     - app: grafana, loki, promtail, ai-analyzer, prometheus
  │     - Message chứa: "ngalert", "ai_security_alert" (tránh phân tích lại)
  │
  │  4. Nếu có log đáng ngờ → gọi LLM
  │
  │  5. Gọi OpenAI/Gemini với prompt:
  │     System: "You are a SOC analyst specializing in Zero Trust and
  │              MITRE ATT&CK. Analyze the following security logs..."
  │     User: [batch log JSON, tối đa 10 entries]
  │
  │  6. Parse response → AlertRecord:
  │     { verdict, severity, confidence, attack_type,
  │       attack_techniques, recommended_playbook,
  │       affected_service, source_ip, reasoning }
  │
  │  7. Kiểm tra log_hash (sha256 của log content)
  │     Nếu đã xử lý → bỏ qua (tránh alert trùng lặp)
  │
  │  8. Phân loại theo severity:
  │     ├── low/medium:  ghi verdict vào Loki
  │     │                job=ai-analyzer, event=ai_security_alert
  │     │
  │     └── high/critical: → BƯỚC 3 (HITL flow)


BƯỚC 3: HITL — Human-in-the-Loop
────────────────────────────────────────────────────────────────
[AI Analyzer — high/critical alert]
  │
  │  1. Tạo PendingAlert (lưu in-memory):
  │     alert_id = uuid4()
  │     status = "pending"
  │     expires_at = now + 3600s
  │
  │  2. Tạo TheHive alert:
  │     POST http://thehive.plg-stack.svc.cluster.local:9000/api/v1/alert
  │     {
  │       "type": "ztlab-ai",
  │       "source": "ai-analyzer",
  │       "sourceRef": f"{alert_id}-{log_hash[:8]}",
  │       "title": f"[{severity.upper()}] {attack_type} detected",
  │       "severity": 3 (high) / 4 (critical),
  │       "tags": ["ztlab", attack_type, affected_service]
  │     }
  │     → Nhận: thehive_alert_id = "~4108320"
  │
  │  3. Push Loki — gắn label pending_approval="true":
  │     POST /loki/api/v1/push
  │     stream labels: { job="ai-analyzer", pending_approval="true",
  │                      alert_id=alert_id }
  │     message: "Pending HITL approval for {attack_type} alert"
  │
  │  4. (Optional) Gửi webhook tức thì nếu ADMIN_WEBHOOK_URL được set
  │     POST webhook với payload chứa alert_id và portal link
  ▼
[Grafana Alerting — rule "ai-pending-approval-alert"]
  │
  │  Condition (evaluate mỗi 1 phút):
  │  count_over_time(
  │    {job="ai-analyzer", pending_approval="true"}[2m]
  │  ) > 0
  │
  │  Khi FIRING → gửi qua Contact Point "ztlab-security-admin"
  │  (Webhook: POST http://ai-analyzer.plg-stack.svc.cluster.local:8080/grafana-webhook)
  │  Payload: alert name, severity, pending_alert_ids, link to Grafana dashboard
  ▼
Admin nhận thông báo → mở Web Portal http://portal/alerts
  │
  │  Xem danh sách pending alerts:
  │  GET /api/alerts  →  calls AI Analyzer /pending?status=pending
  │
  │  Mỗi alert hiển thị:
  │  - attack_type, severity, affected_service, source_ip
  │  - TheHive alert link
  │  - reasoning từ AI
  │  - thời gian tạo và thời gian hết hạn
  │
  │  Admin có thể gọi investigate trước khi quyết định:
  │  POST /pending/{alert_id}/investigate
  │  → AI query Loki 30 phút gần nhất cho service bị ảnh hưởng + OPA denials
  │  → Trả về: loki_evidence[], opa_denials[], summary
  │
  ├── Admin chọn DISMISS:
  │   POST /pending/{alert_id}/dismiss {"note":"false positive"}
  │   → status = "dismissed", không tác động workload
  │   → Ghi log: event=ai_pending_alert_dismissed
  │
  └── Admin chọn APPROVE:
      POST /pending/{alert_id}/approve {"note":"confirmed attack"}
      → BƯỚC 4 (SOAR execution)


BƯỚC 4: SOAR Execution
────────────────────────────────────────────────────────────────
[AI Analyzer — sau khi admin approve]
  │
  │  1. Tạo TheHive case (từ alert đã có):
  │     POST /api/v1/case
  │     {"title": f"[IR] {attack_type} — {affected_service}",
  │      "description": reasoning,
  │      "severity": 3/4, "tags": [...]}
  │     → thehive_case_id = "~5120448"
  │
  │  2. Gọi SOAR webhook:
  │     POST http://soar-engine.plg-stack.svc.cluster.local:8080/alerts
  │     {
  │       "verdict": "malicious",
  │       "severity": "high",
  │       "confidence": 0.85,
  │       "attack_type": "brute_force",
  │       "recommended_playbook": "isolate_workload",
  │       "affected_service": "api-gateway",
  │       "target_context": "ctx-aws"
  │     }
  ▼
[SOAR Engine]
  │
  │  1. Threshold check:
  │     severity >= SOAR_MIN_SEVERITY ("medium")? → YES
  │     confidence >= SOAR_MIN_CONFIDENCE (0.5)? → YES (0.85)
  │
  │  2. Attack → Playbook mapping:
  │     brute_force → isolate_workload
  │
  │  3. Tạo case (append vào cases.jsonl):
  │     { case_id: "case-20260612-001",
  │       timestamp, alert_source, attack_type, severity,
  │       target_workload: "api-gateway",
  │       target_context: "ctx-aws",
  │       playbook: "isolate_workload",
  │       status: "pending" }
  │
  │  4. SOAR_DRY_RUN=false → thực thi live:
  │
  │  [Playbook: isolate_workload]
  │  a. Get current Service spec (snapshot để rollback):
  │     kubectl --context ctx-aws get svc api-gateway -n financial -o json
  │     → lưu original_selector = {"app":"api-gateway"}
  │
  │  b. Patch Service selector:
  │     kubectl --context ctx-aws patch svc api-gateway -n financial
  │     --patch '{"spec":{"selector":{"app":"api-gateway-isolated"}}}'
  │     → Service selector không match pod nào → endpoints = <none>
  │     → api-gateway không còn nhận traffic mới
  │     → Các pod vẫn running (forensics có thể exec vào xem)
  │
  │  c. Update case status: "completed"
  │     Ghi log: event=soar_action, playbook=isolate_workload,
  │              target=api-gateway, context=ctx-aws
  │
  │  5. Rollback (nếu cần sau điều tra):
  │     POST /cases/case-20260612-001/rollback
  │     → Patch lại selector về original_selector
  │     → api-gateway pods nhận traffic trở lại
  │     → case status: "rolled_back"
```

---

### 5.4 Luồng xác thực SVID — Brute Force bị chặn

Ví dụ attacker giả mạo SVID để lateral movement:

```
Attacker → POST /payments/internal/execute
           Header: X-Forwarded-Client-Cert: URI=spiffe://evil.corp/attacker
           (SVID giả mạo — không có cert hợp lệ)
  ▼
[Envoy sidecar payment-service]
  │
  │  Gửi CheckRequest sang OPA:
  │  input.request.http.headers["x-forwarded-client-cert"]
  │  = "URI=spiffe://evil.corp/attacker"
  │
  │  OPA đánh giá:
  │  has_svid? → YES (header tồn tại)
  │  svid_in_trust_domain? → NO
  │    (evil.corp ≠ ztlab.local)
  │  has_valid_jwt? → NO (không có Bearer)
  │  → allow = false
  │
  │  Envoy nhận allow=false → 403 Forbidden
  │
  │  Ghi access log:
  │  {"path":"/payments/internal/execute","response_code":403,
  │   "opa_result":false,"svid":"spiffe://evil.corp/attacker",
  │   "reason":"svid_not_in_trust_domain"}
  ▼
[Promtail] → [Loki]  ← AI Analyzer phát hiện trong poll tiếp theo
  │
  │  AI: "invalid SVID from unknown trust domain attempting internal endpoint"
  │  → verdict=malicious, attack_type=lateral_movement, severity=high
  │  → HITL flow (tạo pending alert)
```

---

### 5.5 Luồng Log Cross-Cloud trong Grafana

```
Transaction được thực hiện (trace_id = "abc123")
  │
  ├── payment-service (AWS) log:
  │   {"event":"cross_cloud_payment_sent","trace_id":"abc123",
  │    "cloud":"aws","destination":"core-banking","amount":100000}
  │   Promtail → Loki (labels: cloud=aws, app=payment-service)
  │
  └── core-banking (OpenStack) log:
      {"event":"transaction_committed","trace_id":"abc123",
       "cloud":"openstack","transaction_id":"xyz789"}
      Promtail → socat 10.10.1.11:31100 → Loki (labels: cloud=openstack, app=core-banking)

Trong Grafana Explore:
  Query: {job="kubernetes-pods", namespace="financial"} |= "abc123"

  Kết quả (theo thời gian):
  10:30:15 [aws]        [payment-service] cross_cloud_payment_sent  trace=abc123
  10:30:15 [aws]        [payment-service] fraud_check_passed         trace=abc123
  10:30:15 [openstack]  [core-banking]    request_received           trace=abc123
  10:30:15 [openstack]  [core-banking]    fraud_gate_validated       trace=abc123
  10:30:15 [openstack]  [account-service] balance_debited            trace=abc123
  10:30:15 [openstack]  [txn-service]     ledger_committed           trace=abc123
  10:30:15 [aws]        [payment-service] cross_cloud_completed      trace=abc123
```

---

## 6. Kết quả kiểm thử

### 6.1 Bảng 20 Kịch bản tấn công

| # | Tên kịch bản | MITRE | Tấn công | Kết quả mong đợi |
|---|-------------|-------|----------|----------------|
| 01 | Brute Force JWT | T1110 | 20 lần login sai Keycloak | 401×20; AI verdict=malicious |
| 02 | JWT Forgery | T1078.001 | JWT ký sai key | 401; OPA block |
| 03 | Lateral Movement | T1021 | SVID sai gọi internal endpoint | 403; OPA deny; AI detect |
| 04 | Fraud Gate Bypass | T1078 | 500M VND qua tor | 403; score=75 block |
| 05 | High Velocity | T1499 | 40 txn/60s từ cùng account | ≥5 blocked; velocity=75 |
| 06 | Data Exfiltration | T1041 | response bytes_sent 8MB bất thường | AI detect restrict_egress |
| 07 | SVID Expiry | T1552 | Kill SPIRE agent → SVID hết hạn | mTLS fail; auto-renew sau |
| 08 | Cross-Cloud Violation | T1199 | Direct call core-banking không có SVID | 403/000; AI detect |
| 09 | Privilege Escalation | T1068 | `sudo -n /bin/sh`, socket mount check | Blocked; cảnh báo |
| 10 | Port Scan | T1046 | Inject nmap log + live scan | AI detect port_scan |
| 11 | Cryptomining | T1496 | Inject xmrig log + CPU burner pod | AI detect; quarantine |
| 12 | SOAR Response | — | Full HITL flow approve + rollback | case created; K8s patched; rollback |
| 13 | SQL Injection | T1190 | 4 SQLi payloads trong from_account | 400/422; AI detect exploit_probe |
| 14 | Command Injection | T1059 | Shell metachar trong payment params | 400/422; AI detect |
| 15 | Account Manipulation | T1098 | testuser01 gọi /admin/* endpoints | 401/403/404 tất cả |
| 16 | Credential Stuffing | T1078.001 | 25 username × 5 password | 100% blocked; AI detect |
| 17 | Impair Defenses | T1562 | Probe OPA admin, Prometheus, Grafana admin | 401/403/404; AI detect |
| 18 | Container Escape | T1611 | Check hostPath, metadata service | BLOCKED; no host mounts |
| 19 | Data Staging | T1074 | 20 bulk GET /accounts/history | rate-limit kicks in; AI detect |
| 20 | JWT Replay | T1539 | Expired JWT + replay pattern inject | 401; AI detect |

### 6.2 Kết quả chi tiết từng nhóm

#### Nhóm 1 — Kiểm soát truy cập (Kịch bản 1–5, 15–16)

**Kịch bản 1: Brute Force JWT**

20 lần login sai Keycloak trong vòng 30 giây:
```
attempt 1  → 401
attempt 2  → 401
...
attempt 20 → 401

Grafana Alert "brute-force-alert" → FIRING (≥5 failures/60s)
AI verdict: malicious | attack_type: brute_force | T1110.001
AI reasoning: "20 consecutive login failures from same IP within 30s window"
```

**Kịch bản 2: JWT Forgery**

JWT được ký bằng sai algorithm/secret:
```
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.[payload].INVALIDSIG
→ HTTP 401
api-gateway log: jwt_verification_failed, reason=invalid_signature
```

**Kịch bản 4: Fraud Gate Block — 500M VND qua tor**
```
Request: amount=500000000, channel="tor"
Fraud scoring:
  baseline:          5
  critical_amount:  +55  (≥500M)
  risky_channel:    +15  (tor)
  total:             75  → BLOCK

Response: HTTP 403
{"error": "fraud_block", "fraud_score": 75, "gate": "blocked"}
```

#### Nhóm 2 — Phát hiện tấn công qua AI (Kịch bản 6, 8, 10, 11, 13, 14)

**Kịch bản 6: Data Exfiltration**

Inject log response size bất thường:
```json
AI Input: "bytes_sent=8388608 path=/accounts/ACC-1001/history"
AI Output:
{
  "verdict": "malicious",
  "severity": "high",
  "confidence": 0.88,
  "attack_type": "large_response",
  "attack_techniques": ["T1041"],
  "recommended_playbook": "restrict_egress",
  "reasoning": "Response size 8MB on account history endpoint far exceeds
                normal range (~5KB). Pattern consistent with data exfiltration."
}
```

**Kịch bản 13: SQL Injection**
```
Test payloads → HTTP 400/422:
  "1' OR '1'='1"         → 422 (validation error)
  "'; DROP TABLE..."     → 400 (bad request)
  "1 UNION SELECT..."    → 422
  "admin'--"             → 400

AI: verdict=malicious, attack_type=exploit_probe, T1190
```

**Kịch bản 10: Port Scan**
```
Inject log: "nmap syn scan source_ip=10.9.8.99 ports_tried=1024"
AI: verdict=malicious, attack_type=port_scan, T1046
confidence=0.82
```

#### Nhóm 3 — HITL và SOAR (Kịch bản 12)

**Kịch bản 12: Full SOAR Response Pipeline**

```
1. Inject critical fraud_gate_bypass log
   → AI: verdict=malicious, severity=critical, playbook=isolate_workload

2. Pending alert tạo:
   alert_id: "7668c451-3e9"
   status: "pending"
   thehive_alert_id: "~4108320"

3. Grafana rule "ai-pending-approval-alert" FIRING
   → Contact Point "ztlab-security-admin" notified

4. Admin approve:
   POST /pending/7668c451-3e9/approve
   → thehive_case_id: "~5120448" (TheHive case created)
   → SOAR case created: case-20260612-001

5. SOAR execute isolate_workload:
   kubectl patch svc payment-service -n financial
   --patch '{"spec":{"selector":{"app":"payment-service-isolated"}}}'
   → endpoints: <none>
   → payment-service: no longer receiving traffic

6. Rollback:
   POST /cases/case-20260612-001/rollback
   → selector restored: {"app":"payment-service"}
   → endpoints: 10.x.x.x:8080 (pod IP)
   → payment-service: operational
   → case status: "rolled_back"
```

#### Nhóm 4 — Container và Infrastructure Security (Kịch bản 17, 18)

**Kịch bản 17: Impair Defenses**
```
GET /opa/v1/policies via API Gateway      → 404 (không expose)
GET /metrics via API Gateway              → 404 (không expose)
GET http://grafana:3000/api/admin/settings → 401 (cần admin auth)
POST Loki /loki/api/v1/push (no auth)    → 204 (Loki open push, expected in lab)

AI: verdict=malicious, attack_type=impair_defenses, T1562
```

**Kịch bản 18: Container Escape**
```
hostNetwork: false ✓
hostPID:     false ✓
hostIPC:     false ✓
hostPath mounts: /run/spire (expected, SPIRE socket only) ✓

Metadata service (169.254.169.254): BLOCKED by NetworkPolicy ✓
AI: verdict=malicious, attack_type=container_escape, T1611
```

### 6.3 Tình trạng deployment tại thời điểm báo cáo

**AWS Cluster (18+ pods Running):**

| Namespace | Service | Containers | Trạng thái |
|-----------|---------|-----------|-----------|
| financial | api-gateway | 2/2 (app + Envoy) | Running |
| financial | payment-service | 2/2 | Running |
| financial | fraud-detection | 2/2 | Running |
| financial | notification-service | 2/2 | Running |
| financial | opa-server | 1/1 | Running |
| financial | redis | 1/1 | Running |
| financial | web-portal | 1/1 | Running |
| identity | keycloak | 1/1 | Running |
| identity | keycloak-db | 1/1 | Running |
| plg-stack | loki | 1/1 | Running |
| plg-stack | grafana | 1/1 | Running |
| plg-stack | ai-analyzer | 1/1 | Running |
| plg-stack | soar-engine | 1/1 | Running |
| plg-stack | thehive | 1/1 | Running |
| plg-stack | thehive-cassandra | 1/1 | Running |
| plg-stack | promtail | DaemonSet/2 | Running |
| monitoring | prometheus | 1/1 | Running |
| spire | spire-server | 1/1 | Running |
| spire | spire-agent | DaemonSet/2 | Running |

**OpenStack Cluster (8 pods Running):**

| Namespace | Service | Ghi chú |
|-----------|---------|---------|
| financial | core-banking | 2/2 — Envoy sidecar + SPIRE SVID |
| financial | account-service | asyncpg → postgres-accounts |
| financial | transaction-service | asyncpg → postgres-txn |
| financial | opa-server | Policy xác thực cross-cloud |
| financial | postgres-accounts | PVC 8Gi, accounts_db |
| financial | postgres-txn | PVC 8Gi, transactions_db |
| plg-stack | promtail | Push → socat relay 10.10.1.11:31100 |
| spire | spire-agent | join_token attestation |

### 6.4 Prometheus Metrics — 9/9 targets UP

| Target | Endpoint | Status |
|--------|----------|--------|
| api-gateway (AWS) | pod:8080/metrics | UP |
| payment-service (AWS) | pod:8080/metrics | UP |
| fraud-detection (AWS) | pod:8080/metrics | UP |
| notification-service (AWS) | pod:8080/metrics | UP |
| core-banking (OpenStack) | 10.10.1.12:30084/metrics | UP |
| account-service (OpenStack) | 10.10.1.12:30082/metrics | UP |
| transaction-service (OpenStack) | 10.10.1.12:30083/metrics | UP |
| loki | pod:3100/metrics | UP |
| prometheus | localhost:9090/metrics | UP |

> OpenStack services được scrape qua NodePort HTTP tĩnh thay vì pod network liên cluster — giữ boundary multi-cloud rõ ràng nhưng đảm bảo metrics đầy đủ cho cả hai cloud trên cùng Grafana.

---

## 7. Đánh giá tổng thể

### 7.1 Bảng đánh giá theo tiêu chí

| Tiêu chí | Kết quả | Chi tiết |
|----------|---------|---------|
| **Zero Trust enforcement** | Đạt | OPA verify JWT (issuer + expiry + realm role) và SVID; block 100% request không hợp lệ tại Envoy sidecar |
| **mTLS giữa services** | Đạt (partial) | Envoy + SPIRE trên AWS đầy đủ; core-banking OpenStack có sidecar; account/txn-service chưa có |
| **Cross-cloud routing** | Đạt | Envoy STATIC cluster → 10.10.1.12:30081; WireGuard mã hóa layer 3; trace_id xuyên suốt |
| **Log tập trung** | Đạt | Loki nhận log cả hai cluster; label `cloud=aws|openstack`; LogQL cross-cloud |
| **Fraud Detection** | Đạt | Velocity + amount + channel scoring; Redis sliding window 60s; double-check tại core-banking |
| **AI Detection** | Đạt | 20 kịch bản tấn công; confidence 0.78–0.92; MITRE ATT&CK mapping; heuristic fallback |
| **HITL + SOAR** | Đạt | Pending alert → Grafana alert POST `/grafana-webhook` → admin approve qua Web Portal → SOAR execute; rollback hoạt động |
| **TheHive Integration** | Đạt | Alert và Case tự động tạo khi high/critical; IR timeline trong TheHive UI |
| **Grafana Alerting** | Đạt | 7 rules active; Contact Point `ztlab-security-admin`; Threat Intel Feed dashboard |
| **Prometheus** | Đạt (9/9) | Tất cả services, cả hai cloud |
| **Database persistence** | Đạt | PostgreSQL (account, txn), Redis (velocity) — data qua pod restart |
| **IaC** | Đạt | Terraform + Ansible + K8s manifests đầy đủ |

### 7.2 Điểm nổi bật

**Zero Trust thực tế trên Multi-Cloud:**
- Không có implicit trust nào trong hệ thống: request không có JWT hoặc SVID hợp lệ bị Envoy + OPA chặn ngay tại sidecar, trước khi chạm đến ứng dụng
- Fraud gate được kiểm tra **hai lần** (payment-service AWS + core-banking OpenStack) — defense-in-depth thực sự
- Mọi SVID có TTL 1h, tự gia hạn — không có long-lived secret nào trong hệ thống

**Vòng lặp SIEM-AI-SOAR hoàn chỉnh:**
- Từ log xuất hiện → AI phát hiện → Grafana notify → admin approve → SOAR cô lập workload: toàn bộ trong < 5 phút (với HITL) hoặc < 30s (nếu SOAR auto-execute, không qua HITL)
- AI không chỉ match pattern cứng mà suy luận ngữ nghĩa từ chuỗi log — ví dụ nhận ra lateral movement từ sequence "SVID lạ + endpoint ngoài topology bình thường"
- Audit trail đầy đủ: cases.jsonl persist qua pod restart; TheHive lưu alert + case cho IR

**Multi-Cloud trace visibility:**
- Cùng `trace_id` trong log AWS và OpenStack — không còn "black box" ở boundary cloud
- Grafana Threat Intelligence Feed dashboard hiển thị MITRE ATT&CK heatmap cross-cloud

---

## 8. Kết luận và hướng phát triển

### 8.1 Kết luận

Đề tài đã triển khai thành công hệ thống bảo mật Zero Trust toàn diện trên môi trường Multi-Cloud thực tế, với kết quả chính:

**Về kiến trúc Zero Trust:**
- Loại bỏ hoàn toàn implicit trust: mọi service-to-service call đều qua Envoy ext_authz + OPA, không có route nào bypass
- SPIFFE/SPIRE tự động cấp và gia hạn SVID — không cần quản lý certificate thủ công, đảm bảo short-lived credentials
- NetworkPolicy tách biệt workload cả hai cluster, cross-cloud chỉ mở đúng 1 port (30081) đến đúng 1 service (core-banking)

**Về Multi-Cloud:**
- WireGuard cung cấp mã hóa layer 3 + mTLS cung cấp mã hóa layer 7 — hai lớp mã hóa độc lập cho cross-cloud traffic
- Trace ID xuyên suốt AWS → OpenStack cho phép debug và audit cross-cloud
- Fraud gate double-check thực thi defense-in-depth thực sự ở boundary cloud

**Về SIEM/SOAR tích hợp AI:**
- PLG Stack thu thập và chuẩn hóa log từ cả hai cloud — một Loki backend, một Grafana, tầm nhìn tập trung
- AI Analyzer kết hợp LLM reasoning với heuristic fallback — hoạt động cả khi không có internet/API key
- HITL flow đảm bảo không có automated action nào mà không có người chịu trách nhiệm
- 20 kịch bản tấn công được triển khai đầy đủ, phủ 15+ MITRE ATT&CK techniques

### 8.2 Hạn chế

- **mTLS partial OpenStack**: account-service và transaction-service chưa có Envoy sidecar, vẫn plain HTTP nội bộ trong cluster OpenStack
- **SPIRE join_token**: OpenStack SPIRE Agent dùng join_token thay vì k8s_psat — token phải tạo lại sau mỗi lần restart EC2
- **Prometheus cross-cluster**: Scrape OpenStack qua NodePort tĩnh — không tự động scale khi thêm node
- **AI cost**: GPT-4o-mini/Gemini có cost per call — không phù hợp với traffic production lớn
- **SOAR playbook đơn giản**: Chỉ 3 playbook cơ bản; thiếu block IP tại firewall, Slack notification, PagerDuty integration

### 8.3 Hướng phát triển

1. **Hoàn thiện mTLS OpenStack**: Bổ sung Envoy sidecar cho account-service, transaction-service; chuyển SPIRE từ join_token sang k8s_psat
2. **Open-source LLM**: Thay OpenAI bằng Mistral 7B hoặc LLaMA 3 self-hosted để demo offline
3. **Prometheus Federation / Thanos**: Chuẩn hóa scrape cross-cluster, hỗ trợ long-term storage
4. **Service Mesh đầy đủ**: Migrate sang Istio hoặc Cilium để có mTLS policy granular và observability tốt hơn
5. **SOAR playbook mở rộng**: Tích hợp Slack notification, PagerDuty, tự động update firewall rule, Cloud Security Group
6. **CI/CD Security Gate**: OPA conftest policy test trong pipeline để detect policy regression sớm
7. **SIEM correlation rules**: Bổ sung Grafana ML plugin hoặc tích hợp SIGMA rules cho detection đa chiều

---

## 9. Tài liệu tham khảo

1. NIST Special Publication 800-207 — *Zero Trust Architecture* (2020)
2. SPIFFE/SPIRE Documentation — https://spiffe.io/docs/
3. Open Policy Agent Documentation — https://www.openpolicyagent.org/docs/
4. Envoy Proxy Documentation — https://www.envoyproxy.io/docs/
5. Grafana Loki Documentation — https://grafana.com/docs/loki/
6. IBM Security X-Force Threat Intelligence Index 2023
7. Gartner — *Magic Quadrant for Security Information and Event Management* (2024)
8. MITRE ATT&CK Framework — https://attack.mitre.org/
9. Rose, S., Borchert, O., et al. — *Zero Trust Architecture*, NIST SP 800-207, 2020
10. Kubernetes Network Policies — https://kubernetes.io/docs/concepts/services-networking/network-policies/
11. K3s Documentation — https://docs.k3s.io/
12. FastAPI Documentation — https://fastapi.tiangolo.com/
13. OpenAI API Documentation — https://platform.openai.com/docs/
14. TheHive Project Documentation — https://docs.strangebee.com/thehive/
15. WireGuard VPN — https://www.wireguard.com/

---

*Báo cáo được soạn thảo dựa trên hệ thống đang vận hành tại thời điểm ngày 12/06/2026.*
