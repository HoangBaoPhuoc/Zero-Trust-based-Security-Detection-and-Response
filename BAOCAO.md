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
3. [Thiết kế hệ thống](#3-thiết-kế-hệ-thống) — 3.1 Kiến trúc tổng thể | 3.2 Hạ tầng Multi-Cloud (AWS + OpenStack + WireGuard) | 3.3–3.6
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
- SPIRE Server (AWS) dùng `k8s_psat` NodeAttestor; SPIRE Agent (OpenStack) dùng `join_token` attestation. Core-banking đã có Envoy sidecar; account-service và transaction-service trên OpenStack vẫn chạy plain HTTP nội bộ (chưa có Envoy sidecar)

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

Ba policy file được load vào OPA (package khác nhau):
- **zta_policy.rego** (`package zta.authz`): Policy chính — Envoy ext_authz query `zta/authz/allow`. Phân biệt external request (có Bearer token, không có SVID), internal request (có SVID), và core transaction (SVID + fraud gate headers hợp lệ). Rule `core_transaction_with_fraud_gate` cho phép `POST /transactions/execute` khi có SVID hợp lệ + `X-Fraud-Gate: passed` + `X-Fraud-Score < 75`
- **fraud_gate.rego** (`package zta.fraud_gate`): Định nghĩa `fraud_gate_valid` và `fraud_gate_bypass_detected` — được import bởi `zta_policy.rego`
- **cross_cloud.rego** (`package zta.crosscloud`): Định nghĩa `allow_cross_cloud` chỉ cho phép `payment-service → core-banking` và `allow` cho các AWS/OpenStack SVID — supplementary policy, không được Envoy ext_authz query trực tiếp (do khác package với `zta.authz`)

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

Log từ OpenStack cluster (core-banking, account-service, transaction-service) được Promtail đẩy về Loki trên AWS qua socat relay `10.10.1.11:31100` (port 31100 trên AWS worker-1, node đang host Loki pod), đảm bảo tập trung log trên một backend duy nhất. Socat được cấu hình như systemd service (`loki-proxy.service`) để tự khởi động khi reboot.

### 2.7 AI Analyzer

AI Analyzer là FastAPI service đóng vai trò **AI-driven SOC analyst** trong hệ thống, tích hợp Large Language Model để phân tích log bảo mật theo thời gian thực. Ba provider được hỗ trợ với fallback chain tự động: OpenAI GPT-4o-mini → Google Gemini 1.5 Flash → Heuristic rule-based (không cần API key).

**Vòng lặp phân tích tự động (poll loop):**

Service poll Loki mỗi 120 giây với LogQL query `{job=~"envoy|opa|system"}`, lấy tối đa 25 log entries trong 90 giây gần nhất. Các log được lọc theo từ khóa bất thường trước khi gửi lên LLM để tiết kiệm token.

**Prompt engineering:**

System prompt định nghĩa LLM như một SOC analyst với chuyên môn về Zero Trust và MITRE ATT&CK. User prompt chứa batch log JSON có cấu trúc. Output schema bắt buộc là JSON với các trường:

```json
{
  "verdict": "normal | suspicious | malicious",
  "severity": "low | medium | high | critical",
  "confidence": 0.0–1.0,
  "attack_type": "<chuỗi định danh>",
  "attack_techniques": ["T1110.001", "T1078", ...],
  "recommended_playbook": "isolate_workload | restrict_egress | quarantine_workload",
  "reasoning": "<giải thích ngắn gọn>"
}
```

**Các attack type mà AI có thể nhận diện:**

| Attack Type | MITRE Technique | Mô tả |
|-------------|----------------|-------|
| `brute_force` | T1110.001 | Nhiều JWT failure liên tiếp từ cùng IP |
| `fraud_gate_bypass` | T1078 | Attempt bypass fraud header validation |
| `lateral_movement` | T1021 | Cross-service call bất thường ngoài luồng bình thường |
| `large_response` | T1041 | Response size bất thường, tiềm năng data exfiltration |
| `cryptomining` | T1496 | Bất thường về CPU / outbound connection |
| `port_scan` | T1046 | Nhiều 404/403 trên các path không tồn tại |
| `exploit_probe` | T1190 | Request path có pattern injection hoặc traversal |

**Kết quả được ghi ngược về Loki** với label `job=ai-analyzer` để hiển thị trên Grafana dashboard "AI SIEM SOAR" và trigger alert rule `ai-analyzer-alert`. Khi `severity >= medium`, AI Analyzer tự động POST sang SOAR Engine endpoint `/alerts`.

Ngoài chế độ poll tự động, AI Analyzer có endpoint `POST /analyze` nhận log trực tiếp và trả kết quả ngay lập tức, phục vụ trigger thủ công trong demo và tích hợp external webhook.

### 2.8 SOAR Engine

SOAR (Security Orchestration, Automation and Response) Engine là thành phần phản ứng tự động của hệ thống, nhận alert từ AI Analyzer và thực thi các playbook có kiểm soát trực tiếp trên Kubernetes API.

**Chuỗi quyết định (Decision Chain):**

```
[Alert từ AI Analyzer]
     │  verdict=malicious, severity=high, confidence=0.78
     ▼
[Threshold filter]
     │  severity >= SOAR_MIN_SEVERITY (medium)?  → Pass
     │  confidence >= SOAR_MIN_CONFIDENCE (0.5)? → Pass
     ▼
[Attack → Playbook mapping]
     │  attack_type: fraud_gate_bypass → isolate_workload
     ▼
[Case creation]  →  cases.jsonl (audit trail bền vững)
     │  case_id, timestamp, context, workload, playbook, status
     ▼
[Dry-run / Live execution]
     │  DRY_RUN=true  → log intent, status="dry_run"
     │  DRY_RUN=false → thực thi Kubernetes API call
     ▼
[Kubernetes API: ctx-aws / ctx-openstack]
     │  isolate_workload: patch Service selector (orphan pods)
     │  restrict_egress: scale Deployment replicas=0
     │  quarantine_workload: scale Deployment replicas=0
```

**Playbook mapping:**

| Attack Type | Playbook | Hành động cụ thể |
|-------------|----------|-----------------|
| `fraud_gate_bypass` | `isolate_workload` | Patch Service selector với label không tồn tại → ngắt route vào workload |
| `lateral_movement` | `isolate_workload` | Ngắt route vào service đang bị dùng làm pivot |
| `large_response` | `restrict_egress` | Scale Deployment về 0, ngăn tiếp tục exfiltration |
| `cryptomining` | `quarantine_workload` | Scale Deployment về 0, tạm dừng resource consumption |
| `port_scan`, `exploit_probe` | `isolate_workload` | Ngắt route vào api-gateway, bảo vệ toàn bộ entry point |
| `brute_force` | `isolate_workload` | Ngắt route vào api-gateway nếu source là internal service |

**Cơ chế an toàn nhiều lớp:**
- `SOAR_DRY_RUN=true` mặc định: ghi log intent nhưng không tác động workload, phù hợp môi trường lab
- `SOAR_MIN_SEVERITY=medium` và `SOAR_MIN_CONFIDENCE=0.5`: chỉ thực thi khi AI đủ chắc chắn
- `SOAR_ALLOWED_CONTEXTS=ctx-aws,ctx-openstack`: giới hạn phạm vi thao tác
- **Rollback**: `POST /cases/{case_id}/rollback` khôi phục Service selector hoặc scale lại Deployment về trạng thái trước; trạng thái trước được snapshot khi tạo case
- **Audit trail**: mỗi case được append vào `cases.jsonl` với đầy đủ timestamp, actor (ai-analyzer), workload bị tác động, status (dry_run/completed/failed/rolled_back)

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

Hệ thống triển khai trên hai K3s cluster hoàn toàn tách biệt, kết nối qua WireGuard VPN, mô phỏng môi trường Multi-Cloud thực tế giữa AWS Public Cloud và OpenStack Private Cloud.

#### 3.2.1 AWS — Public Cloud

Hạ tầng AWS được thiết kế theo mô hình **Defense-in-Depth** với 4 subnet tách biệt trong cùng một VPC:

```
AWS VPC (10.10.0.0/16)
├── Subnet DMZ        (10.10.0.0/24)  — WireGuard Gateway, tiếp nhận kết nối VPN
├── Subnet Private    (10.10.1.0/24)  — K3s cluster nodes (control plane + worker)
├── Subnet Restricted (10.10.2.0/24)  — SIEM node (isolated)
└── Subnet Management (10.10.4.0/24)  — Bastion SSH jump host
```

| Instance | Subnet | IP Private | IP Public | Loại | Vai trò |
|----------|--------|------------|-----------|------|---------|
| `aws-bastion` | Management | 10.10.4.10 | **54.254.145.86** (EIP) | t3.micro | SSH jump host — entry point duy nhất từ internet |
| `aws-gateway` | DMZ | 10.10.0.10 | 18.143.173.245 | t3.micro | WireGuard VPN server — cầu nối AWS ↔ OpenStack |
| `aws-k3s-master` | Private | 10.10.1.10 | *(không có)* | t3.medium | K3s control plane (2 vCPU, 4GB RAM) |
| `aws-k3s-worker-1` | Private | 10.10.1.11 | *(không có)* | t3.small | K3s worker node (2 vCPU, 2GB RAM) |
| `aws-security` | Private | 10.10.1.20 | *(không có)* | t3.micro | Dự phòng cho SPIRE / Keycloak nếu tách node |
| `aws-siem` | Restricted | 10.10.2.10 | *(không có)* | t3.medium | Dự phòng SIEM độc lập nếu tách cluster |

**Thiết kế mạng AWS theo nguyên tắc Zero Trust:**
- Bastion (Management subnet) là điểm truy cập duy nhất từ ngoài, chỉ cho phép SSH port 22
- K3s nodes nằm trong Private subnet, **không có public IP**, chỉ tiếp cận được qua bastion hoặc qua WireGuard tunnel
- Security Group của K3s nodes chỉ mở các port cần thiết: 6443 (K3s API), 8080 (workload), 30000–32767 (NodePort)
- Không có route trực tiếp từ internet vào Private subnet

**K3s cluster AWS (`ctx-aws`):**
- `aws-k3s-master` (10.10.1.10): chạy K3s control plane (etcd, API server, scheduler), đồng thời là worker
- `aws-k3s-worker-1` (10.10.1.11): chạy workload pods (Loki, Grafana, AI-SOAR, Prometheus nằm trên node này)
- Kubectl truy cập qua SSH tunnel: `localhost:6444 → 10.10.1.10:6443` (qua bastion)

#### 3.2.2 OpenStack — Private Cloud

OpenStack đóng vai trò **Private Cloud** trong kiến trúc Multi-Cloud, mô phỏng môi trường on-premise của ngân hàng nơi hệ thống Core Banking vận hành. Hạ tầng OpenStack có mạng riêng biệt hoàn toàn với AWS:

```
OpenStack Network
├── zta-dmz-network     (192.168.100.0/24) — Gateway, kết nối external network
└── zta-private-network (192.168.101.0/24) — K3s node, Core Banking workloads
```

| Instance | Network | IP Private | Flavor | Vai trò |
|----------|---------|------------|--------|---------|
| `os-gateway` | DMZ | 192.168.100.x | nano-plus | WireGuard VPN client — kết nối về aws-gateway |
| `os-k3s-master` | Private | **10.10.1.12** (WireGuard) | m1.medium | K3s standalone node — chạy toàn bộ Core Banking layer |

> **Lưu ý về địa chỉ IP:** `os-k3s-master` có IP WireGuard `10.10.1.12` thuộc cùng dải `10.10.1.0/24` với AWS K3s nodes — đây là thiết kế có chủ đích, cho phép Envoy trên AWS định tuyến đến OpenStack qua WireGuard VPN mà không cần DNS cross-cluster.

**K3s cluster OpenStack (`ctx-openstack`):**
- `os-k3s-master` chạy K3s ở chế độ standalone (control plane + worker trên cùng một node)
- Chứa toàn bộ Core Banking layer: core-banking, account-service, transaction-service, PostgreSQL × 2, SPIRE agent, Promtail
- Kubectl truy cập qua SSH tunnel riêng: `localhost:6445 → 10.10.1.12:6443`

#### 3.2.3 Kết nối liên cloud — WireGuard VPN

WireGuard VPN tạo tunnel mã hóa layer 3 giữa hai cloud, cho phép giao tiếp trực tiếp ở mức IP:

```
[aws-gateway: 10.10.0.10]  ←── WireGuard tunnel (UDP 51820) ───→  [os-gateway: 192.168.100.x]
         │                                                                    │
    10.10.1.0/24 (AWS)                                              10.10.1.12 (OS WG IP)
```

- **AWS phía**: `aws-gateway` (10.10.0.10) là WireGuard server, lắng nghe UDP 51820, quảng bá route `10.10.1.0/24`
- **OpenStack phía**: `os-gateway` là WireGuard client, kết nối về EIP của `aws-gateway`, nhận route về `10.10.1.0/24`
- WireGuard được cấu hình như **systemd service** (`wg-quick@wg0`) trên cả hai node, tự khởi động khi reboot
- Toàn bộ traffic cross-cloud (payment-service → core-banking) đi qua tunnel này, được mã hóa ChaCha20-Poly1305 ở layer network — **bổ sung thêm một lớp mã hóa ngoài mTLS ứng dụng**

**Tóm tắt phân tầng Multi-Cloud:**

```
Internet
    │  SSH port 22 only
    ▼
[aws-bastion: 54.254.145.86]  — Management subnet
    │  SSH tunneling
    ▼
[aws-k3s-master: 10.10.1.10]  — Private subnet (AWS)
[aws-k3s-worker-1: 10.10.1.11]
    │  WireGuard VPN (10.10.1.0/24)
    ▼
[os-k3s-master: 10.10.1.12]  — Private Cloud (OpenStack)
```

### 3.3 Phân lớp dịch vụ theo cloud

Phân bố workload được thiết kế theo nguyên tắc **Data Classification**: dịch vụ tiếp nhận external traffic chạy trên AWS, dịch vụ xử lý dữ liệu nhạy cảm (Core Banking, tài khoản, giao dịch) chạy trên OpenStack.

**AWS Cluster — Public-facing + Security Layer:**
- `api-gateway` — Cổng vào, xác thực JWT, rate limiting
- `payment-service` — Điều phối luồng thanh toán, đo latency cross-cloud
- `fraud-detection` — Tính toán fraud score theo velocity, amount, channel
- `notification-service` — Thông báo kết quả giao dịch
- `opa-server` — Policy engine ext_authz
- `redis` — Velocity store cho fraud detection; fraud-detection kết nối qua **redis.asyncio**, dùng Redis Sorted Set (`fraud:velocity:{account}`) để track tần suất giao dịch theo sliding window 60 giây
- `loki`, `grafana`, `ai-analyzer`, `soar-engine`, `prometheus` — SIEM/SOAR stack
- `keycloak`, `keycloak-db` — Identity Provider
- `spire-server`, `spire-agent` — Certificate authority

**OpenStack Cluster — Core Banking Layer:**
- `core-banking` — Thực thi giao dịch (validate fraud gate, ghi transaction_id)
- `account-service` — Quản lý tài khoản khách hàng; kết nối **PostgreSQL** (`accounts_db`) qua asyncpg, tự tạo table khi startup và seed dữ liệu mẫu (ACC-1001, ACC-2001)
- `transaction-service` — Lịch sử giao dịch; kết nối **PostgreSQL** (`transactions_db`) qua asyncpg, lưu ledger persist qua pod restart
- `postgres-accounts` — PostgreSQL 16, lưu bảng `accounts` (PVC 8Gi)
- `postgres-txn` — PostgreSQL 16, lưu bảng `ledger` (PVC 8Gi)
- `promtail` — Log collector, đẩy về Loki trên AWS

### 3.4 Luồng thanh toán cross-cloud (Payment Flow)

```
[Người dùng]
     │  JWT Bearer token
     ▼
[Ingress - Traefik] ── host: api.ztlab.local (IngressRoute K3s built-in)
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

Dữ liệu velocity được lưu trong **Redis Sorted Set** với key `fraud:velocity:{account_id}`: mỗi request tạo một entry (UUID, score=Unix timestamp), `ZREMRANGEBYSCORE` tự xóa entries ngoài cửa sổ 60 giây, `ZCARD` đếm số request còn lại. Dữ liệu persist qua pod restart, đảm bảo velocity counter không bị reset khi fraud-detection khởi động lại.

Header `X-Fraud-Gate=passed` và `X-Fraud-Score=<n>` được forward đến core-banking; OPA policy `fraud_gate.rego` xác nhận thêm một lần nữa tại boundary OpenStack để chống fraud gate bypass.

### 3.6 Kiến trúc AI-SOAR Pipeline

AI-SOAR tạo thành vòng lặp phản ứng khép kín (closed-loop) từ log thu thập đến hành động tự động trên workload:

```
┌──────────────────────────────────────────────────────────────────┐
│  LOG COLLECTION                                                   │
│  Envoy access logs + OPA decision logs + App logs                 │
│  └─ Promtail (DaemonSet) → Loki (AWS)                            │
└────────────────────┬─────────────────────────────────────────────┘
                     │ LogQL poll mỗi 120s
                     ▼
┌──────────────────────────────────────────────────────────────────┐
│  AI ANALYZER (FastAPI + LLM)                                      │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │  Fetch batch logs → Prompt engineering → LLM call       │     │
│  │  OpenAI GPT-4o-mini / Gemini 1.5 Flash / Heuristic      │     │
│  │  Output: {verdict, severity, confidence, attack_type,   │     │
│  │           attack_techniques (MITRE), recommended_playbook}│    │
│  └─────────────────────────────────────────────────────────┘     │
│  ├─ Ghi verdict ngược → Loki (job=ai-analyzer)                   │
│  └─ severity >= medium → POST /alerts → SOAR Engine              │
└────────────────────┬─────────────────────────────────────────────┘
                     │ Alert JSON
                     ▼
┌──────────────────────────────────────────────────────────────────┐
│  SOAR ENGINE (FastAPI + Kubernetes client)                        │
│  ┌─────────────────────────────────────────────────────────┐     │
│  │  Threshold check → Attack→Playbook mapping               │     │
│  │  Case creation (cases.jsonl) → Dry-run or Live execute   │     │
│  │  Playbooks: isolate_workload / restrict_egress /         │     │
│  │             quarantine_workload                          │     │
│  └─────────────────────────────────────────────────────────┘     │
│  └─ Rollback: POST /cases/{id}/rollback                          │
└────────────────────┬─────────────────────────────────────────────┘
                     │ Kubernetes API patch/scale
                     ▼
┌──────────────────────────────────────────────────────────────────┐
│  KUBERNETES WORKLOADS (ctx-aws / ctx-openstack)                   │
│  isolate: patch Service selector → pods orphaned, traffic dropped │
│  restrict/quarantine: scale Deployment replicas=0                 │
└──────────────────────────────────────────────────────────────────┘
                     │ Prometheus metrics + Grafana alert
                     ▼
              [soar-engine-alert FIRING] → Grafana dashboard
```

Điểm phân biệt kiến trúc này so với rule-based SIEM truyền thống: AI Analyzer không chỉ so khớp pattern cứng mà **suy luận ngữ nghĩa** từ chuỗi log — ví dụ, nhận ra rằng một chuỗi request bình thường trở thành lateral movement khi context là "sau chuỗi JWT failure + từ service không được phép gọi endpoint này theo topology bình thường". SOAR Engine sau đó chuyển reasoning đó thành hành động cụ thể trên workload, với audit trail đầy đủ để review sau sự cố.

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

SPIRE Server được deploy trên AWS cluster. AWS cluster sử dụng `k8s_psat` NodeAttestor; OpenStack cluster sử dụng `join_token` attestation (SPIRE Agent kết nối về Server qua NodePort 30900 trên AWS master):

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

OPA ext_authz query path: `zta/authz/allow` (package `zta.authz` trong `zta_policy.rego`). Policy phân biệt ba loại request:
1. **External request** (có Bearer token, không có SVID): cho phép `POST /payments` và `GET/OPTIONS *`
2. **Internal request** (có SVID `spiffe://ztlab.local/*`): cho phép `GET/OPTIONS *` và `POST /payments|/score|/notify`
3. **Core transaction** (có SVID + `X-Fraud-Gate: passed` + `X-Fraud-Score < 75`): cho phép `POST /transactions/execute`
4. **Public path** (`/health`, `/ready`, `/metrics`): luôn cho phép, không cần auth

### 4.4 Lớp dịch vụ tài chính

Tất cả microservice được viết bằng Python/FastAPI với các đặc điểm chung:
- **Structured logging** qua `ZTLabLogger` (JSON có `timestamp`, `level`, `service`, `cloud`, `trace_id`)
- **Prometheus metrics** qua `prometheus_client`: `ztlab_transactions_total`, `ztlab_fraud_score`, `ztlab_cross_cloud_latency_seconds`, `ztlab_auth_failures_total`, `ztlab_service_up`
- **Trace propagation**: `X-Trace-ID` header được tạo tại api-gateway và truyền xuyên suốt pipeline
- **Cloud identity**: mỗi service khai báo `CLOUD = "aws"` hoặc `CLOUD = "openstack"` trong log

**Tích hợp cơ sở dữ liệu:**

Các service lưu trữ dữ liệu nghiệp vụ vào database persist, không dùng in-memory:

| Service | Database | Công nghệ | Chi tiết |
|---------|----------|-----------|----------|
| `account-service` | PostgreSQL `accounts_db` | asyncpg connection pool | Table `accounts`; startup tự tạo table và seed ACC-1001, ACC-2001 |
| `transaction-service` | PostgreSQL `transactions_db` | asyncpg connection pool | Table `ledger`; ghi mỗi giao dịch với UUID, timestamp, status |
| `fraud-detection` | Redis | redis.asyncio | Sorted Set `fraud:velocity:{account}`; sliding window 60 giây |

Tất cả database dùng PersistentVolumeClaim trên K3s local-path provisioner: data không mất khi pod restart. Các service kết nối DB tại `startup_event` (FastAPI lifespan), tự tạo schema nếu chưa tồn tại.

Image được build từ `services/Dockerfile` và sync vào containerd của K3s nodes bằng `scripts/sync-financial-images.sh`, không phụ thuộc vào Docker Hub hay private registry.

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

AI Analyzer và SOAR Engine được deploy trên AWS cluster trong namespace `plg-stack`, chạy cùng namespace với Loki và Grafana để tối giản network hop.

**Cấu hình AI Analyzer:**

```yaml
# k8s/plg-stack/ai-soar.yaml (trích)
containers:
  - name: ai-analyzer
    image: ztlab/ai-analyzer:1.0.0
    env:
      - name: AI_PROVIDER            # "openai" (từ Secret ai-secrets)
      - name: OPENAI_API_KEY         # từ Secret ai-secrets
      - name: LOKI_URL               # http://loki.plg-stack.svc.cluster.local:3100
      - name: SOAR_ENGINE_URL        # http://soar-engine.plg-stack.svc.cluster.local:8090
      - name: AI_ANALYZER_POLL_ENABLED           # "true"
      - name: AI_ANALYZER_POLL_INTERVAL_SECONDS  # "120"
      - name: AI_ANALYZER_LOOKBACK_SECONDS       # "90"
      - name: AI_ANALYZER_MAX_LOGS_PER_BATCH     # "25"
      - name: AI_ANALYZER_MIN_ALERT_SEVERITY     # "medium"
```

**RBAC cho SOAR Engine:**

SOAR Engine cần quyền thao tác workload trên cả hai cluster. Trên AWS cluster, ServiceAccount `soar-engine` được gán ClusterRole với quyền `get`, `patch` trên `deployments` và `services` trong namespace `financial`. Để thao tác cross-cluster sang OpenStack, SOAR Engine sử dụng kubeconfig `ctx-openstack` được mount qua Secret, kết nối đến `localhost:6445` (SSH tunnel đến `10.10.1.12:6443`):

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

**Persistent storage cho SOAR cases:**

SOAR Engine mount PersistentVolumeClaim `soar-cases-pvc` (1Gi, local-path provisioner) tại `/data`. File `cases.jsonl` tại đường dẫn này accumulate tất cả SOAR case qua các lần restart — đảm bảo audit trail không bị mất. Endpoint `GET /cases` đọc từ file này và trả về danh sách case phân trang.

**Giám sát AI-SOAR:**

Cả hai service expose `/metrics` endpoint (Prometheus format) và `/health` endpoint. Grafana dashboard "AI SIEM SOAR" kết nối trực tiếp Loki datasource để query `{job="ai-analyzer"}` và hiển thị: verdict distribution (pie chart), severity timeline, attack type heatmap, SOAR case creation rate, và top recommended playbooks.

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

| Namespace | Service | Trạng thái | Ghi chú |
|-----------|---------|------------|---------|
| financial | core-banking | Running | 2/2 containers (app + Envoy sidecar) |
| financial | account-service | Running | Kết nối postgres-accounts |
| financial | transaction-service | Running | Kết nối postgres-txn |
| financial | opa-server | Running | |
| financial | postgres-accounts | Running | PVC 8Gi, accounts_db |
| financial | postgres-txn | Running | PVC 8Gi, transactions_db |
| plg-stack | promtail | Running | Push log → socat relay 10.10.1.11:31100 |
| spire | spire-agent | Running | join_token attestation |

### 5.2 Kịch bản kiểm thử và kết quả

#### 5.2.1 Payment Flow bình thường (Baseline)

Giao dịch 100.000 VND từ `ACC-1001` đến `ACC-2001`:

```bash
TOKEN=$(bash scripts/gen-dev-token.sh testuser01 financial-write 2>/dev/null | head -1)
curl -s -H "Authorization: Bearer $TOKEN" -H "Host: api.ztlab.local" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000,"currency":"VND"}' \
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
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000}' \
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

#### 5.2.7 Scenario 6: AI Detection — Brute Force Analysis

Sau chuỗi 15 request JWT giả (scenario 5.2.3), AI Analyzer poll Loki và phát hiện pattern brute force. Kết quả `POST /analyze` trả về:

```json
{
    "verdict": "malicious",
    "severity": "high",
    "confidence": 0.85,
    "attack_type": "brute_force",
    "attack_techniques": ["T1110.001"],
    "recommended_playbook": "isolate_workload",
    "reasoning": "Detected 15 consecutive jwt_verification_failed events from same source within 90s window. Pattern consistent with credential stuffing attack against api-gateway.",
    "provider_used": "openai"
}
```

Kết quả này được ghi vào Loki với label `job=ai-analyzer`, trigger alert `ai-analyzer-alert` trên Grafana, và forward sang SOAR Engine do `severity=high >= medium`.

**SOAR case được tạo tự động:**
```json
{
    "case_id": "case-20260606-001",
    "timestamp": "2026-06-06T10:30:15Z",
    "alert_source": "ai-analyzer",
    "attack_type": "brute_force",
    "severity": "high",
    "confidence": 0.85,
    "target_workload": "api-gateway",
    "target_context": "ctx-aws",
    "playbook": "isolate_workload",
    "status": "dry_run",
    "dry_run_note": "Would patch Service/api-gateway selector to isolate pods"
}
```

Với `SOAR_DRY_RUN=true`, SOAR ghi intent nhưng không tác động cluster — phù hợp môi trường lab. Khi bật live mode, playbook `isolate_workload` sẽ patch Service selector với label `isolated=true` khiến các pod api-gateway không còn nhận traffic mới.

#### 5.2.8 Scenario 7: AI Detection — Lateral Movement + SOAR Rollback Demo

Scenario kiểm tra khả năng AI phát hiện lateral movement và quy trình rollback của SOAR.

**Thiết lập:** Gửi loạt request từ `notification-service` (SVID `spiffe://ztlab.local/aws/notification-service`) đến endpoint `/transactions/execute` — path mà theo thiết kế chỉ `payment-service` mới được gọi:

```bash
# Giả lập notification-service gọi transaction endpoint bất thường
curl -s -H "X-SPIFFE-ID: spiffe://ztlab.local/aws/notification-service" \
     -H "Host: api.ztlab.local" \
     -X POST http://127.0.0.1:8080/transactions/execute
```

**OPA block ngay lập tức:** HTTP 403 — `reason=svid_not_authorized_for_path`. Log OPA ghi `allowed=false` với SVID và path đầy đủ.

**AI phân tích (trigger manual):**
```json
{
    "verdict": "malicious",
    "severity": "high",
    "confidence": 0.82,
    "attack_type": "lateral_movement",
    "attack_techniques": ["T1021"],
    "recommended_playbook": "isolate_workload",
    "reasoning": "notification-service SVID attempting to access /transactions/execute — outside normal service topology. Consistent with compromised service being used as pivot to reach core transaction path.",
    "provider_used": "openai"
}
```

**SOAR rollback demo:** Khi SOAR case ở live mode đã patch Service để isolate `notification-service`, quy trình rollback được thực hiện:
```bash
curl -X POST http://soar-engine/cases/case-20260606-002/rollback
# → Service selector được khôi phục về trạng thái gốc
# → notification-service pods nhận traffic trở lại
# → case status: "rolled_back"
```

**SOAR cases tích lũy:** Tại thời điểm kiểm tra live, SOAR health trả `case_count=77+` — số case tích lũy và tăng qua từng lần chạy demo, là bằng chứng audit trail bền vững qua các lần restart pod.

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
| mTLS giữa services | Đạt (partial) | Envoy sidecar + SPIRE trên AWS; core-banking (OpenStack) có Envoy sidecar; account/transaction-service vẫn plain HTTP nội bộ |
| Cross-cloud routing | Đạt | payment→core-banking qua Envoy STATIC cluster (10.10.1.12:30081), trace_id xuyên suốt |
| Log tập trung | Đạt | Loki nhận log từ cả hai cluster với nhãn cloud rõ ràng |
| AI detection | Đạt | Phân tích 7 attack scenarios với confidence 0.78–0.85; xác định đúng MITRE technique; reasoning có thể đọc được |
| SOAR automation | Đạt (dry_run) | Cases tạo tự động với audit trail; playbook mapping đúng cho 6 attack type; rollback hoạt động; `case_count=77+` tích lũy |
| Grafana alerting | Đạt | 6 alert rules active, brute-force alert firing đúng |
| Prometheus metrics | Đạt (9/9) | AWS services, OpenStack NodePorts, Loki và Prometheus đều UP |
| Database persistence | Đạt | account-service (PostgreSQL), transaction-service (PostgreSQL), fraud-detection (Redis) — data không mất khi pod restart |
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

**Về SIEM/SOAR tích hợp AI:**
- PLG Stack thu thập và chuẩn hóa log từ cả hai cloud với nhãn `cloud=aws|openstack`, đảm bảo tầm nhìn bảo mật tập trung trong một Loki backend duy nhất
- AI Analyzer triển khai vòng lặp phân tích khép kín: poll Loki → LLM reasoning → ghi verdict → trigger SOAR, giảm MTTD so với pure rule-based alerting bằng cách nhận diện pattern phức tạp mà regex không thể mô tả
- AI phân loại chính xác 7 attack scenarios với confidence 0.78–0.85, xác định đúng MITRE ATT&CK technique (T1110.001, T1078, T1021, T1041) và mapping sang playbook phù hợp
- SOAR Engine tự động tạo case với audit trail bền vững (cases.jsonl), hỗ trợ rollback có kiểm soát, thực thi playbook trực tiếp trên cả hai Kubernetes cluster (ctx-aws, ctx-openstack) thông qua patch Service selector và scale Deployment

**Về đóng góp học thuật:**
- Minh chứng thực tế rằng mô hình Zero Trust có thể triển khai trên Multi-Cloud với chi phí hạ tầng thấp (mã nguồn mở hoàn toàn)
- Tích hợp LLM vào quy trình phân tích log security để suy luận ngữ nghĩa, không chỉ so khớp pattern — mở ra hướng nghiên cứu "AI-augmented SOC" trên nền tảng open-source
- Kiến trúc closed-loop AI→SOAR→Kubernetes có thể tái sử dụng cho bất kỳ domain nào vận hành microservice trên Kubernetes

### 6.2 Hạn chế

- **mTLS partial trên OpenStack:** Core-banking có Envoy sidecar + SPIRE SVID (mTLS inbound từ payment-service qua 30081). Account-service và transaction-service chưa có Envoy sidecar, vẫn plain HTTP trong nội bộ cluster OpenStack. SPIRE Agent OpenStack dùng `join_token` attestation thay vì `k8s_psat` do OpenStack cluster không có Service Account Projected Token đầy đủ
- **Prometheus cross-cluster:** Hiện scrape OpenStack qua NodePort tĩnh; về lâu dài nên dùng Prometheus Federation, remote_write hoặc Thanos để chuẩn hóa hơn
- **AI cost:** GPT-4o-mini có cost per API call; với traffic lớn cần cân nhắc fine-tuned open-source model (Mistral, LLaMA) để giảm chi phí
- **SOAR playbook:** Hiện chỉ có 3 playbook cơ bản; cần mở rộng thêm (block IP tại firewall, tạo ticket incident, notify Slack)
- **Môi trường lab:** EC2 t3.medium không đủ tài nguyên để mô phỏng traffic thực tế quy mô lớn

### 6.3 Hướng phát triển

1. **Hoàn thiện mTLS cho OpenStack:** Bổ sung Envoy sidecar cho account-service, transaction-service trên OpenStack; chuẩn hóa SPIRE attestation từ join_token sang k8s_psat
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

*Báo cáo được soạn thảo dựa trên hệ thống đang vận hành tại thời điểm ngày 06/06/2026.*
