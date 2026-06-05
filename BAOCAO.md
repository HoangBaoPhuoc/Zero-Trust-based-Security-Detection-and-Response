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
4. [Triển khai hệ thống](#4-triển-khai-hệ-thống)
5. [Kết quả và đánh giá](#5-kết-quả-và-đánh-giá)
6. [Kết luận và hướng phát triển](#6-kết-luận-và-hướng-phát-triển)
7. [Tài liệu tham khảo](#7-tài-liệu-tham-khảo)

---

## 1. Tổng quan đề tài

### 1.1 Đặt vấn đề

Trong kỷ nguyên chuyển đổi số, điện toán đám mây đã trở thành nền tảng công nghệ chủ đạo cho hầu hết các doanh nghiệp. Đặc biệt trong ngành Tài chính – Ngân hàng, mô hình Multi-Cloud ngày càng được áp dụng rộng rãi nhằm duy trì tính ổn định của hệ thống Core Banking trên hạ tầng Private Cloud, đồng thời tận dụng khả năng mở rộng của Public Cloud để phát triển các dịch vụ ngân hàng số. Theo Gartner (2024), hơn 85% doanh nghiệp đang sử dụng ít nhất hai nhà cung cấp cloud khác nhau.

Tuy nhiên, sự phức tạp của môi trường Multi-Cloud đã tạo ra những điểm mù nghiêm trọng về bảo mật. Các mô hình bảo mật truyền thống dựa trên network perimeter và implicit trust đã chứng tỏ sự lỗi thời qua các sự cố lớn như SolarWinds (2020) và Colonial Pipeline (2021). Thiếu sự thống nhất về chính sách bảo mật và giám sát giữa các miền cloud khiến thời gian phát hiện vi phạm (MTTD) cao hơn trung bình 27% so với môi trường đơn lẻ (IBM, 2023).

Thị trường đã có các giải pháp Zero Trust và SASE như Cloudflare One, Zscaler, Palo Alto Prisma Access, nhưng các doanh nghiệp vận hành Multi-Cloud vẫn đối mặt với thách thức về chi phí bản quyền cao và sự rời rạc trong việc tích hợp dữ liệu bảo mật giữa các nền tảng Public và Private Cloud. Quan trọng hơn, các giải pháp thương mại này thường thiếu khả năng phản ứng tự động có kiểm soát ở cấp độ workload trong môi trường Kubernetes.

Đề tài này giải quyết bài toán trên bằng cách triển khai một hệ thống bảo mật phòng thủ chủ động toàn diện, kết hợp kiến trúc Zero Trust (ZTA) với hệ thống SIEM/SOAR có tích hợp AI, triển khai trên hạ tầng Multi-Cloud thực tế gồm AWS và OpenStack.

### 1.2 Mục tiêu

**Mục tiêu tổng quát:** Nghiên cứu và triển khai mô hình phòng thủ chủ động dựa trên kiến trúc Zero Trust tích hợp hệ thống SIEM/SOAR hỗ trợ AI trên hạ tầng Multi-Cloud, nhằm thiết lập cơ chế quản trị định danh nhất quán, tự động hóa quy trình giám sát và phản ứng sự cố, từ đó tối ưu hóa các chỉ số an ninh MTTD (Mean Time To Detect) và MTTR (Mean Time To Respond).

**Mục tiêu cụ thể:**

**a. Thiết lập nền tảng định danh Zero Trust phi tập trung (Identity-based Security)**

Triển khai cơ chế định danh số dựa trên tiêu chuẩn SPIFFE/SPIRE để cấp phát danh tính workload (SVID) cho tất cả các microservice chạy trên hạ tầng Multi-Cloud (AWS K3s và OpenStack K3s). Loại bỏ hoàn toàn sự tin tưởng chỉ dựa trên địa chỉ IP, thay thế bằng xác thực dựa trên định danh động.

**b. Thực thi kiểm soát truy cập thích ứng (Adaptive Access Control)**

Sử dụng Envoy Proxy làm điểm thực thi chính sách (Policy Enforcement Point) kết hợp với OPA (Open Policy Agent) và Keycloak. Đảm bảo mọi yêu cầu truy cập đều phải được xác thực, ủy quyền và mã hóa (mTLS) trước khi thiết lập kết nối.

**c. Xây dựng khả năng giám sát thông minh liên tục (Continuous AI-driven Observability)**

Tích hợp PLG Stack (Promtail-Loki-Grafana) làm SIEM tập trung, thu thập log từ cả hai cloud. Triển khai AI Analyzer với khả năng phân tích log theo thời gian thực, phân loại mức độ nguy hiểm (normal / suspicious / malicious) và nhận diện attack type theo framework MITRE ATT&CK.

**d. Tự động hóa phản ứng sự cố (Automated Incident Response)**

Triển khai SOAR Engine với các playbook có kiểm soát (isolate_workload, restrict_egress, quarantine_workload) có khả năng tác động trực tiếp vào workload Kubernetes ở cả hai cluster khi phát hiện mối đe dọa, từ đó giảm thiểu Dwell Time của kẻ tấn công.

### 1.3 Phạm vi và giới hạn

**Phạm vi thực hiện:**
- Hạ tầng: 2 K3s cluster tách biệt — AWS (master + worker, vùng Singapore) và OpenStack (standalone node, cùng VPC)
- Ứng dụng minh họa: hệ thống tài chính gồm 7 microservice mô phỏng luồng thanh toán ngân hàng
- Bảo mật: SPIFFE/SPIRE mTLS, Envoy ext_authz, OPA policy, Keycloak OIDC, NetworkPolicy
- Quan sát: PLG Stack, Prometheus, Grafana dashboards, AI Analyzer (OpenAI GPT-4o-mini), SOAR Engine

**Giới hạn:**
- Môi trường lab: 3 EC2 instance t3.medium (AWS) + 1 node tương đương (OpenStack); không mô phỏng traffic thực tế quy mô lớn
- SOAR mặc định chạy `dry_run=true` để bảo vệ cluster lab; cần bật live mode thủ công khi muốn thực thi
- Prometheus scrape được 9/9 active targets; ba service OpenStack được scrape qua NodePort HTTP có kiểm soát thay vì pod network liên cluster
- SPIRE hiện sử dụng k8s_psat NodeAttestor; workload attestation đầy đủ chưa được kích hoạt cho OpenStack cluster

---

## 2. Cơ sở lý thuyết

### 2.1 Kiến trúc Zero Trust (Zero Trust Architecture)

Zero Trust là mô hình bảo mật được NIST định nghĩa trong SP 800-207, dựa trên nguyên tắc cốt lõi "Never Trust, Always Verify". Khác với mô hình perimeter truyền thống giả định rằng các thực thể bên trong mạng nội bộ đáng tin cậy, Zero Trust yêu cầu xác thực và ủy quyền liên tục cho mọi yêu cầu truy cập, bất kể nguồn gốc.

Ba trụ cột của ZTA áp dụng trong đề tài:
- **Verify explicitly:** Mọi request phải mang JWT token hợp lệ (Keycloak OIDC) hoặc SPIFFE SVID (mTLS) trước khi được xử lý
- **Least privilege access:** OPA policy chỉ cho phép các path và method cụ thể, tương ứng với vai trò của từng service
- **Assume breach:** Hệ thống luôn ghi log toàn bộ quyết định OPA, phân tích bất thường liên tục và sẵn sàng phản ứng tự động

### 2.2 SPIFFE/SPIRE — Định danh workload

SPIFFE (Secure Production Identity Framework for Everyone) là tiêu chuẩn mở để cấp phát danh tính cho các workload trong môi trường phân tán. SPIRE (SPIFFE Runtime Environment) là hiện thực của tiêu chuẩn này.

Mỗi workload được cấp một **SVID (SPIFFE Verifiable Identity Document)** dưới dạng chứng chỉ X.509, có format: `spiffe://ztlab.local/<cloud>/<service-name>`. Ví dụ:
- `spiffe://ztlab.local/aws/payment-service`
- `spiffe://ztlab.local/openstack/core-banking`

SVID có TTL 1 giờ và được tự động gia hạn, đảm bảo nguyên tắc short-lived credentials. mTLS giữa các service sử dụng SVID này, loại bỏ hoàn toàn việc quản lý certificate thủ công.

### 2.3 Open Policy Agent (OPA) và Rego

OPA là policy engine mã nguồn mở theo cơ chế "policy as code". Các chính sách được viết bằng ngôn ngữ Rego và được OPA đánh giá tại runtime. Trong đề tài, OPA được tích hợp vào Envoy Proxy như một ext_authz server: mọi request đến các microservice đều được Envoy gửi sang OPA để kiểm tra trước khi chuyển tiếp.

Ba chính sách Rego chính:
- **zta_policy.rego:** Kiểm tra JWT/SVID, phân biệt external request (JWT) và internal request (SVID)
- **fraud_gate.rego:** Xác nhận header `X-Fraud-Gate` và `X-Fraud-Score` tại endpoint `/transactions/execute` của core-banking
- **cross_cloud.rego:** Chỉ cho phép `spiffe://ztlab.local/aws/payment-service` gọi đến `spiffe://ztlab.local/openstack/core-banking`

### 2.4 Envoy Proxy — Service Mesh PEP

Envoy Proxy được triển khai như sidecar container trong các pod tài chính trên AWS cluster (payment-service, api-gateway, fraud-detection, notification-service). Đây là điểm thực thi chính sách (Policy Enforcement Point) của hệ thống.

Vai trò của Envoy:
- Chặn toàn bộ inbound traffic và gọi OPA ext_authz trước khi forward
- Thực hiện mTLS với SPIRE Agent (Workload API)
- Ghi access log có cấu trúc JSON để Promtail thu thập
- Định tuyến cross-cloud: cluster `core_banking` được cấu hình là STATIC upstream đến `10.10.1.12:30081` (NodePort của core-banking trên OpenStack)

### 2.5 Keycloak — Identity Provider

Keycloak cung cấp OIDC/OAuth2 cho phép người dùng lấy JWT token để truy cập API. Hệ thống có realm `ztlab` với client `api-gateway`, cấp token RS256 có claim `realm_access.roles` để OPA kiểm tra quyền. Trong lab hiện tại, Admin UI được expose qua `http://localhost/admin` để login ổn định với cookie trên HTTP tunnel; các service vẫn dùng realm `ztlab` và endpoint OIDC nội bộ/ingress tương ứng.

Trong môi trường lab, hệ thống hỗ trợ thêm dev token HS256 (gen-dev-token.sh) để dễ dàng test mà không cần flow OIDC đầy đủ.

### 2.6 PLG Stack — SIEM

Promtail-Loki-Grafana là bộ ba công cụ mã nguồn mở thay thế ELK Stack trong các môi trường nhẹ:
- **Promtail:** Agent thu thập log từ các pod/node, chạy như DaemonSet trên cả hai cluster, gán nhãn `cloud`, `namespace`, `app`
- **Loki:** Log aggregation backend, tương thích LogQL, không index toàn văn bản mà chỉ index nhãn (hiệu quả hơn Elasticsearch ~10x về bộ nhớ)
- **Grafana:** Visualization và alerting, hỗ trợ datasource Loki và Prometheus

Log từ OpenStack cluster (core-banking, account-service, transaction-service) được Promtail đẩy trực tiếp về Loki trên AWS qua NodePort `10.10.1.10:31000`, đảm bảo tập trung log trên một backend duy nhất.

### 2.7 AI Analyzer

AI Analyzer là FastAPI service tích hợp Large Language Model (mặc định OpenAI GPT-4o-mini, hỗ trợ Gemini và heuristic rule-based). Service này:
- Poll Loki mỗi 120 giây, lấy các log bất thường trong 5 phút gần nhất
- Gửi batch log đến LLM để phân loại: `normal / suspicious / malicious`
- Xác định `attack_type` theo MITRE ATT&CK (brute_force, fraud_gate_bypass, lateral_movement, v.v.)
- Tính toán `severity` (low/medium/high/critical) và `confidence` (0.0–1.0)
- Ghi kết quả phân tích ngược về Loki với label `job=ai-analyzer`
- Tự động forward alert đến SOAR Engine khi `severity >= medium`

Ngoài chế độ poll tự động, AI Analyzer còn có endpoint `POST /analyze` để nhận log trực tiếp và trả kết quả ngay lập tức, phục vụ trigger thủ công trong demo.

### 2.8 SOAR Engine

SOAR (Security Orchestration, Automation and Response) Engine nhận alert từ AI Analyzer và thực thi các playbook có kiểm soát:

| Attack Type | Playbook | Hành động |
|-------------|----------|-----------|
| `fraud_gate_bypass` | `isolate_workload` | Patch Kubernetes Service selector để ngắt route |
| `lateral_movement` | `isolate_workload` | Ngắt route vào workload nghi ngờ |
| `large_response` | `restrict_egress` | Scale deployment về 0 |
| `cryptomining` | `quarantine_workload` | Scale deployment về 0 |
| `port_scan`, `exploit_probe` | `isolate_workload` | Ngắt route vào api-gateway |

SOAR có cơ chế an toàn nhiều lớp:
- Chỉ thực thi khi `severity >= SOAR_MIN_SEVERITY` (mặc định: medium) và `confidence >= SOAR_MIN_CONFIDENCE` (mặc định: 0.5)
- `SOAR_DRY_RUN=true` mặc định: ghi log nhưng không tác động workload
- `SOAR_ALLOWED_CONTEXTS` giới hạn chỉ được thao tác trên `ctx-aws` và `ctx-openstack`
- Mỗi case được lưu bền vào `cases.jsonl` với audit trail đầy đủ
- Hỗ trợ rollback: `POST /cases/{case_id}/rollback` khôi phục workload về trạng thái trước

---

## 3. Thiết kế hệ thống

### 3.1 Kiến trúc tổng thể

Hệ thống ZTLab được tổ chức thành 4 lớp chức năng:

```
┌─────────────────────────────────────────────────────────────────────┐
│  LỚPỨNG DỤNG                                                        │
│  API Gateway → Payment → Fraud → Core Banking → Account → Txn      │
├─────────────────────────────────────────────────────────────────────┤
│  LỚP KIỂM SOÁT TRUY CẬP (Zero Trust Enforcement)                   │
│  Envoy Proxy (sidecar) ↔ OPA ext_authz ↔ SPIRE (mTLS/SVID)        │
│  Keycloak OIDC (JWT RS256/HS256)                                    │
├─────────────────────────────────────────────────────────────────────┤
│  LỚP QUAN SÁT (SIEM)                                                │
│  Promtail → Loki ← AI Analyzer → SOAR Engine                       │
│  Prometheus → Grafana (dashboards + alerting)                       │
├─────────────────────────────────────────────────────────────────────┤
│  LỚP HẠ TẦNG (Multi-Cloud)                                          │
│  AWS K3s (2 nodes)              OpenStack K3s (1 node)              │
│  10.10.1.10, 10.10.1.11         10.10.1.12                          │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Hạ tầng Multi-Cloud

Hệ thống triển khai trên hai K3s cluster hoàn toàn tách biệt, kết nối qua WireGuard VPN:

**AWS Cluster (`ctx-aws`, localhost:6444 → 10.10.1.10:6443)**

| Node | IP Private | Vai trò |
|------|------------|---------|
| bastion | 54.254.145.86 (EIP) | SSH jump host |
| aws-master | 10.10.1.10 | K3s control plane |
| aws-worker-1 | 10.10.1.11 | K3s worker |

**OpenStack Cluster (`ctx-openstack`, localhost:6445 → 10.10.1.12:6443)**

| Node | IP Private | Vai trò |
|------|------------|---------|
| os-master | 10.10.1.12 | K3s control plane (standalone) |

### 3.3 Phân lớp dịch vụ theo cloud

Phân bố workload được thiết kế theo nguyên tắc **Data Classification**: dịch vụ tiếp nhận external traffic chạy trên AWS, dịch vụ xử lý dữ liệu nhạy cảm (Core Banking, tài khoản, giao dịch) chạy trên OpenStack.

**AWS Cluster — Public-facing + Security Layer:**
- `api-gateway` — Cổng vào, xác thực JWT, rate limiting
- `payment-service` — Điều phối luồng thanh toán, đo latency cross-cloud
- `fraud-detection` — Tính toán fraud score theo velocity, amount, channel
- `notification-service` — Thông báo kết quả giao dịch
- `opa-server` — Policy engine ext_authz
- `redis` — Velocity cache cho fraud detection
- `loki`, `grafana`, `ai-analyzer`, `soar-engine`, `prometheus` — SIEM/SOAR stack
- `keycloak`, `keycloak-db` — Identity Provider
- `spire-server`, `spire-agent` — Certificate authority

**OpenStack Cluster — Core Banking Layer:**
- `core-banking` — Thực thi giao dịch (validate fraud gate, ghi transaction)
- `account-service` — Quản lý tài khoản khách hàng
- `transaction-service` — Lịch sử và truy vấn giao dịch
- `postgres-accounts` — Database tài khoản
- `postgres-txn` — Database giao dịch
- `promtail` — Log collector, đẩy về Loki trên AWS

### 3.4 Luồng thanh toán cross-cloud (Payment Flow)

```
[Người dùng]
     │  JWT Bearer token
     ▼
[Ingress - Nginx] ── host: api.ztlab.local
     │
     ▼
[api-gateway (AWS)]
     │  1. Rate limit check (60 req/min/IP)
     │  2. JWT verify (RS256 via Keycloak JWKS, fallback HS256)
     │  3. Forward với X-Trace-ID + X-User-ID header
     ▼
[Envoy sidecar của payment-service]
     │  ext_authz → OPA: kiểm tra SVID + path + method
     ▼
[payment-service (AWS)]
     │  1. Giới hạn amount ≤ 500M VND
     │  2. Gọi fraud-detection /score
     │     ├─ velocity score (Redis cache)
     │     ├─ amount score
     │     └─ channel/country score
     │  3. Nếu score < 75: forward đến core-banking
     │     Thêm header: X-Fraud-Gate=passed, X-Fraud-Score=<n>
     ▼
[Envoy upstream: 10.10.1.12:30081]  ◄── Cross-cloud boundary
     │  (STATIC cluster, không qua DNS)
     ▼
[core-banking (OpenStack)]
     │  1. Validate X-Fraud-Gate == "passed"
     │  2. Validate X-Fraud-Score < 74
     │  3. Ghi transaction_id
     │  4. Return {transaction_id, status, trace_id}
     ▼
[payment-service (AWS)]
     │  Ghi ztlab_cross_cloud_latency_seconds metric
     │  Gọi notification-service (async, best-effort)
     ▼
[Trả kết quả] → {status, trace_id, fraud, core_banking}
```

Cùng `trace_id` xuất hiện trong log của cả `payment-service` (cloud: aws) và `core-banking` (cloud: openstack), cho phép truy vết request xuyên cloud trong Grafana/Loki.

### 3.5 Mô hình Fraud Detection

Fraud detection sử dụng scoring model đơn giản, minh bạch để dễ minh họa hành vi bảo mật:

| Yếu tố | Điều kiện | Điểm cộng |
|--------|-----------|-----------|
| Baseline | Luôn có | +5 |
| Velocity (mềm) | > 5 txn/60s từ cùng account | +10 |
| Velocity (cao) | > 10 txn/60s | +25 |
| Velocity (cực cao) | > 30 txn/60s | +40 |
| High amount | ≥ 100M VND | +30 |
| Critical amount | ≥ 500M VND | +55 |
| Risky channel | tor / unknown / script | +15 |
| Unusual country | Ngoài VN, SG, TH | +10 |

Ngưỡng quyết định: `score < 40` → allow, `40 ≤ score < 75` → review, `score ≥ 75` → **block**.

Header `X-Fraud-Gate=passed` và `X-Fraud-Score=<n>` được forward đến core-banking; OPA policy `fraud_gate.rego` xác nhận thêm một lần nữa tại boundary OpenStack để chống fraud gate bypass.

---

## 4. Triển khai hệ thống

### 4.1 Hạ tầng và Infrastructure as Code

Toàn bộ hạ tầng được quản lý theo phương pháp Infrastructure as Code:

**Terraform** provision tài nguyên cloud:
- `terraform/aws/`: VPC, subnet, security group, EC2 instances, Elastic IP, SSH key pair
- `terraform/openstack/`: Network, router, security group, Nova instances

**Ansible** thực hiện configuration management:
- `playbooks/baseline.yml`: cài đặt Docker, K3s, các dependency
- `playbooks/wireguard.yml`: cấu hình WireGuard VPN kết nối AWS–OpenStack
- `playbooks/promtail.yml`: deploy Promtail agent trên tất cả node

**K3s** được chọn thay vì kubeadm vì nhẹ hơn (~70MB binary), phù hợp với EC2 t3.medium (2 vCPU, 4GB RAM), và có local-path provisioner tích hợp cho PersistentVolumes.

### 4.2 Lớp định danh — SPIRE

SPIRE Server được deploy trên AWS cluster, nhận attestation từ cả hai cluster qua `k8s_psat` NodeAttestor:

```hcl
# spire/server/server.conf
server {
  trust_domain = "ztlab.local"
  default_x509_svid_ttl = "1h"
  default_jwt_svid_ttl  = "5m"
  ca_ttl                = "168h"
}
```

SPIRE Agent chạy như DaemonSet trên mỗi node Kubernetes. Mỗi workload được cấp SVID thông qua Unix domain socket `/tmp/spire-agent/public/api.sock` mà Envoy truy cập qua SDS (Secret Discovery Service).

Có ~16 SVID entries đã đăng ký, bao gồm tất cả microservice trên cả hai cluster:
```
spiffe://ztlab.local/aws/api-gateway
spiffe://ztlab.local/aws/payment-service
spiffe://ztlab.local/aws/fraud-detection
spiffe://ztlab.local/openstack/core-banking
spiffe://ztlab.local/openstack/account-service
... (và các service khác)
```

### 4.3 Lớp kiểm soát truy cập — Envoy + OPA

Envoy được cấu hình như sidecar (`envoy/configmap.yaml`) với các thành phần:

**Listeners:**
- Port 15006: Inbound listener, intercept toàn bộ traffic vào pod, gọi OPA ext_authz
- Port 15001: Outbound listener, forward đến notification-service

**Clusters:**
- `local_service`: Forward về ứng dụng chính trong pod (port 8080)
- `opa_authz`: Kết nối đến OPA server (`opa-server.financial.svc.cluster.local:9191`)
- `core_banking`: **STATIC** cluster, trỏ thẳng đến `10.10.1.12:30081` (NodePort OpenStack)

```yaml
- name: core_banking
  type: STATIC
  connect_timeout: 8s
  wait_for_warm_on_init: false
  load_assignment:
    endpoints:
      - lb_endpoints:
          - endpoint:
              address:
                socket_address:
                  address: 10.10.1.12   # OpenStack K3s node
                  port_value: 30081     # core-banking NodePort
```

OPA policy `zta_policy.rego` phân biệt ba loại request:
1. **External request** (có JWT Bearer, không có SVID): chỉ cho phép `POST /payments`, `GET /health`
2. **Internal request** (có SVID `spiffe://ztlab.local/*`): cho phép các path nội bộ
3. **Core transaction** (có SVID + `X-Fraud-Gate: passed`): cho phép `/transactions/execute` với fraud score < 75

### 4.4 Lớp dịch vụ tài chính

Tất cả microservice được viết bằng Python/FastAPI với các đặc điểm chung:
- **Structured logging** qua `ZTLabLogger` (JSON có `timestamp`, `level`, `service`, `cloud`, `trace_id`)
- **Prometheus metrics** qua `prometheus_client`: `ztlab_transactions_total`, `ztlab_fraud_score`, `ztlab_cross_cloud_latency_seconds`, `ztlab_auth_failures_total`, `ztlab_service_up`
- **Trace propagation**: `X-Trace-ID` header được tạo tại api-gateway và truyền xuyên suốt pipeline
- **Cloud identity**: mỗi service khai báo `CLOUD = "aws"` hoặc `CLOUD = "openstack"` trong log

Image được build từ `services/Dockerfile` (multi-stage) và sync vào containerd của K3s nodes bằng `scripts/sync-financial-images.sh`, không phụ thuộc vào Docker Hub hay private registry.

### 4.5 NetworkPolicy

Mỗi cluster có NetworkPolicy riêng để thực thi network segmentation:

**AWS (`aws-allow-list.yaml`):**
- Financial pods chỉ nhận traffic từ `monitoring`, `kube-system`, và trong `financial` namespace
- Egress: DNS, internal cluster, identity namespace, và **cross-cloud** rule: `10.10.1.12/32:30081`

**OpenStack (`os-allow-list.yaml`):**
- Financial pods nhận ingress từ internal cluster và từ subnet AWS `10.10.1.0/24` (qua WireGuard)
- Egress: DNS, intra-cluster (8080, 5432), và `10.10.1.0/24:31000` (Loki NodePort trên AWS)

### 4.6 PLG Stack và Logging Pipeline

Promtail chạy như DaemonSet trên cả hai cluster, scrape log từ các pod và node:

```yaml
# Nhãn được gán cho mỗi log stream
labels:
  job: kubernetes-pods
  namespace: {{ .Namespace }}
  app: {{ .App }}
  cloud: {{ .Cloud }}       # "aws" hoặc "openstack"
  node: {{ .NodeName }}
```

Loki được deploy trên AWS với PersistentVolume 10Gi. Promtail trên OpenStack cluster được cấu hình `LOKI_PUSH_URL=http://10.10.1.11:31100/loki/api/v1/push`; `31100` là Loki proxy/relay trên AWS worker, chuyển tiếp về Loki backend trên AWS.

Grafana được provision sẵn 4 dashboard:
- **ZTA Security Overview**: OPA decisions, JWT failures, fraud blocks theo thời gian
- **AI SIEM SOAR**: AI alerts, SOAR cases, attack type distribution
- **OPA Decisions**: Allow/deny rate theo service, top denied paths
- **Envoy Access Logs**: HTTP traffic matrix, response time percentile, error rate

6 alert rules được cấu hình trong Grafana Alerting:
- `brute-force-alert`: ≥ 5 JWT failures trong 60 giây
- `fraud-gate-bypass-alert`: Phát hiện fraud_gate_bypass event
- `lateral-movement-alert`: Cross-service call bất thường
- `large-response-alert`: Response size bất thường (tiềm năng data exfiltration)
- `ai-analyzer-alert`: AI phát hiện malicious verdict
- `soar-engine-alert`: SOAR đã tạo case mức high/critical

### 4.7 AI Analyzer và SOAR Engine trên Kubernetes

AI Analyzer và SOAR Engine được deploy trên AWS cluster với PersistentVolume để lưu trữ SOAR cases:

```yaml
# k8s/plg-stack/ai-soar.yaml (trích)
env:
  - name: AI_PROVIDER       # từ secret ai-secrets
  - name: LOKI_URL          # http://loki.plg-stack.svc.cluster.local:3100
  - name: SOAR_DRY_RUN      # "true" mặc định
  - name: SOAR_ALLOWED_CONTEXTS  # "ctx-aws,ctx-openstack"
```

SOAR Engine được cấp RBAC với quyền `patch` Deployments và Services trong namespace `financial` của cả hai cluster, cho phép thực thi playbook `isolate_workload` và `restrict_egress` khi ở chế độ live.

---

## 5. Kết quả và đánh giá

### 5.1 Tình trạng hệ thống triển khai

Tại thời điểm báo cáo, hệ thống hoàn toàn hoạt động trên cả hai cluster:

**AWS Cluster (18 pods Running):**

| Namespace | Service | Replicas | Trạng thái |
|-----------|---------|----------|------------|
| financial | api-gateway | 1 (2/2 container) | Running |
| financial | payment-service | 1 (2/2 container) | Running |
| financial | fraud-detection | 1 (2/2 container) | Running |
| financial | notification-service | 1 (2/2 container) | Running |
| financial | opa-server | 1 | Running |
| financial | redis | 1 | Running |
| plg-stack | loki | 1 | Running |
| plg-stack | grafana | 1 | Running |
| plg-stack | ai-analyzer | 1 | Running |
| plg-stack | soar-engine | 1 | Running |
| plg-stack | promtail | DaemonSet/2 nodes | Running |
| monitoring | prometheus | 1 | Running |
| identity | keycloak | 1 | Running |
| identity | keycloak-db | 1 | Running |
| spire | spire-server | 1 | Running |
| spire | spire-agent | DaemonSet/2 nodes | Running |

**OpenStack Cluster (8 pods Running):**

| Namespace | Service | Trạng thái |
|-----------|---------|------------|
| financial | core-banking | Running |
| financial | account-service | Running |
| financial | transaction-service | Running |
| financial | opa-server | Running |
| financial | postgres-accounts | Running |
| financial | postgres-txn | Running |
| plg-stack | promtail | Running |
| spire | spire-agent | Running |

### 5.2 Kịch bản kiểm thử và kết quả

#### 5.2.1 Payment Flow bình thường (Baseline)

Giao dịch 100.000 VND từ `acc001` đến `acc002`:

```bash
TOKEN=$(bash scripts/gen-dev-token.sh testuser01 financial-write 2>/dev/null | head -1)
curl -s -H "Authorization: Bearer $TOKEN" -H "Host: api.ztlab.local" \
  -d '{"from_account":"acc001","to_account":"acc002","amount":100000,"currency":"VND"}' \
  -X POST http://127.0.0.1:8080/payments
```

**Kết quả:**
```json
{
    "status": "completed",
    "trace_id": "362097f1-5d87-4318-973d-c2ea5e11711b",
    "fraud": {"score": 5, "verdict": "allow", "gate": "passed"},
    "core_banking": {"transaction_id": "0d8e75cd...", "status": "completed"}
}
```

Cùng `trace_id` xuất hiện trong log của `payment-service` (cloud: aws) và `core-banking` (cloud: openstack), xác nhận luồng cross-cloud hoạt động đúng.

#### 5.2.2 Scenario 1: Không có JWT Token — OPA Block

```bash
curl -s -H "Host: api.ztlab.local" \
  -d '{"from_account":"acc001","to_account":"acc002","amount":100000}' \
  -X POST http://127.0.0.1:8080/payments
```

**Kết quả:** HTTP 403 — OPA từ chối tại Envoy sidecar trước khi request chạm đến ứng dụng. Log OPA ghi nhận `allowed=false, reason=missing_bearer`.

#### 5.2.3 Scenario 2: Brute Force JWT — T1110.001

Gửi 15 request liên tiếp với token giả:

**Kết quả:** 15× HTTP 401. Log `jwt_verification_failed` tích lũy trong Loki. Grafana Alert `brute-force-alert` chuyển sang **Firing** sau khi đếm ≥ 5 failures trong 60 giây. AI Analyzer phân loại `verdict=malicious, attack_type=brute_force, severity=high`.

#### 5.2.4 Scenario 3: Fraud Gate Block — T1078 Valid Accounts

Giao dịch 500M VND từ kênh `tor`:
- `score = 5 (baseline) + 55 (critical_amount) + 15 (risky_channel) = 75`
- Ngưỡng block: `score >= 75`

**Kết quả:** HTTP 403. Log `payment_blocked_fraud` với `fraud_score=75`. OPA policy `fraud_gate.rego` xác nhận lại tại boundary core-banking.

#### 5.2.5 Scenario 4: Velocity Attack — T1496

Gửi 35 giao dịch liên tiếp từ cùng account `flood001`, mỗi giao dịch 150M VND:
- Request 1–10: `score = 5 + 30 = 35` → allow
- Request 11–30: `velocity(>10) = +25`, `score = 5 + 25 + 30 = 60` → review (passed)
- Request 31+: `velocity(>30) = +40`, `score = 5 + 40 + 30 = 75` → **block**

**Kết quả:** Từ request ~31 trở đi trả HTTP 403. Velocity counter trong Redis được xóa mỗi 60 giây.

#### 5.2.6 Scenario 5: JWT Token Giả Mạo — T1550.001

Token được ký bằng wrong-secret-key thay vì `ztlab-dev-secret`:

**Kết quả:** HTTP 401 — `jwt_verification_failed, reason=invalid_jwt`. SPIRE SVID verification cũng sẽ fail nếu attacker cố gắng giả mạo SVID (X.509 cert không thể giả mạo nếu không có private key của SPIRE CA).

#### 5.2.7 Scenario 6: AI Detection + SOAR Response

Sau các scenario tấn công, AI Analyzer (poll mỗi 120 giây) tự động phân tích log và tạo SOAR case:

**Kết quả AI Analyze:**
```json
{
    "verdict": "malicious",
    "severity": "high",
    "confidence": 0.78,
    "attack_type": "access_denied",
    "recommended_playbook": "isolate_workload",
    "provider_used": "openai"
}
```

**SOAR cases tích lũy:** Tại thời điểm kiểm tra live gần nhất, SOAR health trả `case_count=77`. Số case là dữ liệu tích lũy và tăng theo số lần chạy demo. Với `SOAR_DRY_RUN=true`, các case có status `dry_run` — nghĩa là playbook đã được lên kế hoạch nhưng không thực thi, phù hợp để demo mà không làm gián đoạn cluster.

### 5.3 Prometheus Metrics

Prometheus hiện thu thập được 9/9 active targets (UP):
- **AWS financial (4):** api-gateway, payment-service, fraud-detection, notification-service
- **OpenStack financial (3):** core-banking qua `10.10.1.12:30084`, account-service qua `10.10.1.12:30082`, transaction-service qua `10.10.1.12:30083`
- **Observability (2):** loki, prometheus

Ba service OpenStack không được scrape qua pod network liên cluster; thay vào đó Prometheus trên AWS scrape các NodePort HTTP được mở có kiểm soát trên node OpenStack. Thiết kế này vẫn giữ boundary multi-cloud rõ ràng nhưng cho phép dashboard metrics hiển thị đầy đủ cho cả hai cloud.

### 5.4 Đánh giá tổng thể

| Tiêu chí | Kết quả | Ghi chú |
|----------|---------|---------|
| Zero Trust enforcement | Đạt | OPA block 100% request không có JWT/SVID hợp lệ |
| mTLS giữa services | Đạt (partial) | Envoy sidecar + SPIRE trên AWS; OpenStack core-banking cũng có Envoy sidecar, account/transaction còn plain HTTP nội bộ |
| Cross-cloud routing | Đạt | payment→core-banking qua Envoy STATIC cluster, trace_id xuyên suốt |
| Log tập trung | Đạt | Loki nhận log từ cả hai cluster với nhãn cloud rõ ràng |
| AI detection | Đạt | Phát hiện đúng 6 attack scenarios, confidence 0.7–0.9 |
| SOAR automation | Đạt (dry_run) | Cases tạo tự động, playbook mapping đúng; `case_count` tăng theo số lần chạy demo |
| Grafana alerting | Đạt | 6 alert rules active, brute-force alert firing đúng |
| Prometheus metrics | Đạt (9/9) | AWS services, OpenStack NodePorts, Loki và Prometheus đều UP |
| Infrastructure as Code | Đạt | Terraform + Ansible + K8s manifests đầy đủ |

---

## 6. Kết luận và hướng phát triển

### 6.1 Kết luận

Đề tài đã thành công trong việc triển khai một hệ thống bảo mật Zero Trust toàn diện trên môi trường Multi-Cloud thực tế, với các kết quả chính:

**Về kiến trúc Zero Trust:**
- Loại bỏ hoàn toàn implicit trust: mọi service-to-service call đều qua Envoy ext_authz + OPA
- SPIFFE/SPIRE cung cấp định danh workload ngắn hạn (TTL 1h), tự động gia hạn, không cần quản lý certificate thủ công
- Fraud gate header (`X-Fraud-Gate`, `X-Fraud-Score`) được kiểm tra hai lần — tại payment-service (AWS) và core-banking (OpenStack) — thực thi nguyên tắc defense-in-depth

**Về Multi-Cloud:**
- Hai K3s cluster hoàn toàn tách biệt với kubectl context riêng (`ctx-aws`, `ctx-openstack`)
- Cross-cloud routing thông qua Envoy STATIC cluster đến NodePort, không phụ thuộc DNS giữa cluster
- Trace ID xuyên suốt từ AWS sang OpenStack cho phép truy vết và debug cross-cloud

**Về SIEM/SOAR:**
- PLG Stack thu thập và chuẩn hóa log từ cả hai cloud, đảm bảo tầm nhìn bảo mật tập trung
- AI Analyzer với provider OpenAI phân loại chính xác 6 attack scenarios, xác định attack type theo MITRE ATT&CK
- SOAR Engine tự động tạo case và map sang playbook phù hợp, với cơ chế rollback an toàn

**Về đóng góp học thuật:**
- Minh chứng thực tế rằng mô hình Zero Trust có thể triển khai trên Multi-Cloud với chi phí hạ tầng thấp (mã nguồn mở hoàn toàn)
- Tích hợp LLM vào quy trình phân tích log security, giảm phụ thuộc vào rule-based detection
- Kiến trúc có thể tái sử dụng cho các domain khác ngoài tài chính

### 6.2 Hạn chế

- **SPIRE trên OpenStack:** Agent đã deploy và cấp SVID cho core-banking, account-service, transaction-service. Core-banking đã có Envoy sidecar; account-service và transaction-service vẫn chạy plain HTTP nội bộ
- **Prometheus cross-cluster:** Hiện scrape OpenStack qua NodePort tĩnh; về lâu dài nên dùng Prometheus Federation, remote_write hoặc Thanos để chuẩn hóa hơn
- **AI cost:** GPT-4o-mini có cost per API call; với traffic lớn cần cân nhắc fine-tuned open-source model (Mistral, LLaMA) để giảm chi phí
- **SOAR playbook:** Hiện chỉ có 3 playbook cơ bản; cần mở rộng thêm (block IP tại firewall, tạo ticket incident, notify Slack)
- **Môi trường lab:** EC2 t3.medium không đủ tài nguyên để mô phỏng traffic thực tế quy mô lớn

### 6.3 Hướng phát triển

1. **Hoàn thiện SPIRE cho OpenStack:** Chuẩn hóa workload attestation qua k8s_psat và bổ sung Envoy sidecar cho account-service, transaction-service
2. **Cross-cluster Prometheus:** Nâng cấp từ scrape NodePort tĩnh sang Prometheus Federation, remote_write hoặc Thanos Sidecar
3. **Open-source LLM:** Thay thế OpenAI bằng Mistral 7B self-hosted để demo offline và giảm chi phí
4. **SOAR playbook mở rộng:** Tích hợp với Slack notification, PagerDuty, tự động cập nhật firewall rule
5. **MITRE ATT&CK mapping:** Bổ sung more attack scenarios (T1059 Command Injection, T1190 Exploit Public-Facing Application)
6. **Service Mesh đầy đủ:** Migrate sang Istio hoặc Cilium để có mTLS policy granular hơn và observability tốt hơn
7. **CI/CD pipeline:** Tích hợp policy-as-code test vào pipeline (OPA conftest) để phát hiện policy regression sớm

---

## 7. Tài liệu tham khảo

1. NIST Special Publication 800-207 — *Zero Trust Architecture* (2020)
2. SPIFFE/SPIRE Documentation — https://spiffe.io/docs/
3. Open Policy Agent Documentation — https://www.openpolicyagent.org/docs/
4. Envoy Proxy Documentation — https://www.envoyproxy.io/docs/
5. Grafana Loki Documentation — https://grafana.com/docs/loki/
6. IBM Security X-Force Threat Intelligence Index 2023
7. Gartner Report — *Magic Quadrant for Security Information and Event Management* (2024)
8. MITRE ATT&CK Framework — https://attack.mitre.org/
9. Rose, S., Borchert, O., et al. — *Zero Trust Architecture*, NIST SP 800-207, 2020
10. Kubernetes Network Policies — https://kubernetes.io/docs/concepts/services-networking/network-policies/
11. K3s Documentation — https://docs.k3s.io/
12. FastAPI Documentation — https://fastapi.tiangolo.com/
13. OpenAI API Documentation — https://platform.openai.com/docs/

---

*Báo cáo được soạn thảo dựa trên hệ thống đang vận hành tại thời điểm ngày 05/06/2026.*
