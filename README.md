# ZTLab — Zero Trust Security Detection & Response

> **Đồ án chuyên ngành** | Trường Đại học Công nghệ Thông tin — ĐHQG TP.HCM  
> Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> GVHD: Đỗ Thị Phương Uyên

Hệ thống triển khai kiến trúc **Zero Trust** kết hợp **SIEM/SOAR tích hợp AI** trên môi trường **Multi-Cloud thực tế** (AWS + OpenStack), minh họa bằng ứng dụng tài chính microservices.

---

## Kiến trúc

```
Internet
  └─▶ Nginx Ingress (api.ztlab.local)
        └─▶ [AWS K3s Cluster — ctx-aws]
              ├─ api-gateway   (JWT verify, rate limit)
              ├─ payment-service ─── Envoy ──▶ OPA ext_authz
              │    └─────────────────────────────────────────▶ 10.10.1.12:30081
              ├─ fraud-detection  (velocity + amount scoring)         │
              ├─ notification-service                                  │
              ├─ opa-server / redis / keycloak                        │
              └─ loki / grafana / ai-analyzer / soar-engine           │
                                                                      │
                              [OpenStack K3s Cluster — ctx-openstack] │
                               └─ core-banking ◀────────────────────-─┘
                               └─ account-service
                               └─ transaction-service
                               └─ postgres-accounts / postgres-txn
                               └─ promtail ──▶ Loki (AWS:31000)
```

**Luồng thanh toán cross-cloud:**  
`API Gateway → JWT verify → OPA allow → payment-service → Fraud score → Envoy STATIC 10.10.1.12:30081 → core-banking (OpenStack)`

Cùng `trace_id` xuất hiện trong log của cả hai cloud để đảm bảo khả năng truy vết xuyên suốt.

---

## Thành phần bảo mật

| Tầng | Công nghệ | Vai trò |
|------|-----------|---------|
| Định danh workload | SPIFFE/SPIRE | Cấp X.509 SVID cho mỗi microservice, TTL 1h |
| Kiểm soát truy cập | OPA + Envoy ext_authz | Policy as code, chặn request tại Envoy sidecar |
| Xác thực người dùng | Keycloak OIDC | JWT RS256, claim-based authorization |
| mTLS | Envoy + SPIRE SDS | Service-to-service encryption |
| Network segmentation | Kubernetes NetworkPolicy | Phân tách traffic AWS↔OpenStack |
| SIEM | PLG Stack (Promtail + Loki + Grafana) | Log tập trung từ cả hai cloud |
| AI Detection | OpenAI GPT-4o-mini / Gemini / Heuristic | Phân loại log theo MITRE ATT&CK |
| SOAR | SOAR Engine (FastAPI + Kubernetes SDK) | Playbook tự động: isolate, restrict, quarantine |
| Metrics | Prometheus + Grafana | 6/9 services (3 OS services — expected) |

---

## Hạ tầng

### AWS Cluster (`ctx-aws`, port 6444)

| Node | IP | Vai trò |
|------|----|---------|
| bastion | 54.254.145.86 (EIP) | SSH jump host |
| aws-master | 10.10.1.10 | K3s control plane |
| aws-worker-1 | 10.10.1.11 | K3s worker |

### OpenStack Cluster (`ctx-openstack`, port 6445)

| Node | IP | Vai trò |
|------|----|---------|
| os-master | 10.10.1.12 | K3s control plane (standalone) |

```
SSH Key    : ~/.ssh/zta-siem-soar-key
Kubeconfig : ~/.kube/ztlab/aws-tunnel.yaml
```

---

## Cấu trúc repo

```
.
├── terraform/               # IaC — provision AWS và OpenStack
├── ansible/                 # Configuration management (K3s, WireGuard, Promtail)
├── k8s/
│   ├── financial/           # Kubernetes manifests dịch vụ tài chính
│   │   ├── aws-services.yaml      # api-gateway, payment, fraud, notification
│   │   ├── os-services.yaml       # core-banking, account, transaction (OpenStack)
│   │   ├── redis.yaml / postgres-*.yaml
│   │   └── network-policies/      # aws-allow-list.yaml, os-allow-list.yaml
│   ├── plg-stack/           # Loki, Grafana, Promtail, AI Analyzer, SOAR Engine
│   ├── monitoring/          # Prometheus
│   ├── ingress.yaml / namespaces.yaml
│   └── rbac/                # SOAR RBAC (patch deployments/services)
├── envoy/
│   └── configmap.yaml       # Envoy sidecar config (ext_authz, cross-cloud upstream)
├── opa/
│   ├── policies/
│   │   ├── zta_policy.rego        # JWT + SVID verification
│   │   ├── fraud_gate.rego        # Fraud gate header validation
│   │   └── cross_cloud.rego       # AWS→OpenStack identity policy
│   └── deployment.yaml
├── spire/
│   ├── server/              # SPIRE Server config (trust_domain: ztlab.local)
│   ├── agent/               # SPIRE Agent config (aws + openstack)
│   ├── k8s/                 # SPIRE Kubernetes manifests
│   └── scripts/             # register-aws-workloads.sh, register-os-workloads.sh
├── services/
│   ├── api-gateway/         # FastAPI — JWT verify, rate limit, forward
│   ├── payment-service/     # FastAPI — Điều phối thanh toán, cross-cloud latency metric
│   ├── fraud-detection/     # FastAPI — Velocity + amount + channel scoring
│   ├── core-banking/        # FastAPI — Thực thi giao dịch, validate fraud gate
│   ├── account-service/     # FastAPI — Quản lý tài khoản
│   ├── transaction-service/ # FastAPI — Lịch sử giao dịch
│   ├── notification-service/# FastAPI — Thông báo sự kiện
│   ├── soar-engine/         # FastAPI — SOAR playbook execution
│   └── Dockerfile           # Multi-stage build, shared base
├── shared/
│   ├── logging.py           # ZTLabLogger (JSON structured, cloud-aware)
│   └── metrics.py           # Prometheus metrics definitions
├── plg-stack/
│   ├── grafana/
│   │   ├── dashboards/      # ZTA Overview, AI SIEM SOAR, OPA, Envoy Access
│   │   └── alerting/        # 6 alert rules (brute-force, fraud, lateral-movement, ...)
│   └── loki/loki-config.yml
├── scripts/
│   ├── deploy-all.sh        # Deploy toàn bộ (cả hai cluster)
│   ├── deploy-security-stack.sh  # SPIRE + OPA + Envoy + Keycloak
│   ├── setup-os-cluster.sh  # Khởi tạo OpenStack K3s cluster từ đầu
│   ├── k8s-tunnel.sh        # Quản lý SSH tunnel (up/down/status/verify)
│   ├── sync-financial-images.sh  # Build + sync images vào K3s nodes
│   ├── gen-dev-token.sh     # Tạo JWT dev token (HS256)
│   ├── health-check.sh      # Kiểm tra sức khỏe toàn hệ thống
│   └── run-demo.sh          # Script demo tự động
├── tests/                   # 12 test scenarios (brute force, JWT forgery, SOAR, ...)
├── BAOCAO.md                # Báo cáo đồ án đầy đủ
└── HUONG_DAN.md             # Hướng dẫn vận hành và demo
```

---

## Khởi động nhanh

### Yêu cầu

- SSH key tại `~/.ssh/zta-siem-soar-key`
- `kubectl`, `ansible`, `ssh` đã cài sẵn
- EC2 instances đang running (AWS Console)

### 1. Mở tunnels

```bash
bash scripts/k8s-tunnel.sh up all
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

kubectl --context ctx-aws get nodes        # 2 nodes Ready
kubectl --context ctx-openstack get nodes  # 1 node Ready (os-master)
```

### 2. Mở UI tunnel (terminal riêng, để block)

```bash
ssh -N -i ~/.ssh/zta-siem-soar-key -o StrictHostKeyChecking=no \
  -L 8080:10.10.1.10:80 -J ubuntu@54.254.145.86 ubuntu@10.10.1.10
```

### 3. Mở port-forward AI / SOAR / Loki

```bash
kubectl --context ctx-aws port-forward -n plg-stack svc/ai-analyzer 8090:8080 --address=127.0.0.1 &
kubectl --context ctx-aws port-forward -n plg-stack svc/soar-engine 8091:8080 --address=127.0.0.1 &
kubectl --context ctx-aws port-forward -n plg-stack svc/loki 3100:3100 --address=127.0.0.1 &
```

### 4. Thêm /etc/hosts (1 lần)

```bash
grep -q "api.ztlab.local" /etc/hosts || sudo tee -a /etc/hosts <<'EOF'
127.0.0.1  api.ztlab.local grafana.ztlab.local keycloak.ztlab.local prometheus.ztlab.local
EOF
```

### 5. Kiểm tra sức khỏe

```bash
curl -s -H "Host: api.ztlab.local" http://127.0.0.1:8080/health
# {"status":"ok","service":"api-gateway","cloud":"aws"}

curl -s http://127.0.0.1:8090/health | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['status'], d['provider'])"
# ok openai
```

---

## URLs sau khi mở tunnel

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://grafana.ztlab.local:8080 | admin / ZTALab2026! |
| Keycloak | http://keycloak.ztlab.local:8080 | admin / ztlab-admin-2026 |
| API Gateway | http://api.ztlab.local:8080/health | — |
| Prometheus | http://prometheus.ztlab.local:8080/targets | — |
| AI Analyzer | http://127.0.0.1:8090/health | port-forward |
| SOAR Engine | http://127.0.0.1:8091/cases | port-forward |
| Loki | http://127.0.0.1:3100/ready | port-forward |

---

## Test payment flow

```bash
TOKEN=$(bash scripts/gen-dev-token.sh testuser01 financial-write 2>/dev/null | head -1)

curl -s \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Host: api.ztlab.local" \
  -d '{"from_account":"acc001","to_account":"acc002","amount":100000,"currency":"VND"}' \
  -X POST http://127.0.0.1:8080/payments | python3 -m json.tool
```

Kết quả mong đợi: `status=completed`, `fraud.score=5`, `core_banking.status=completed`

---

## Fraud scoring model

| Yếu tố | Ngưỡng | Điểm |
|--------|--------|------|
| Baseline | Luôn có | +5 |
| Velocity cao | > 30 txn/60s | +40 |
| Critical amount | ≥ 500M VND | +55 |
| High amount | ≥ 100M VND | +30 |
| Risky channel | tor / unknown / script | +15 |
| Unusual country | Ngoài VN, SG, TH | +10 |

`score < 40` → allow · `40–74` → review (passed) · `≥ 75` → **block**

---

## Attack scenarios

Xem chi tiết tại [HUONG_DAN.md — Section 4](HUONG_DAN.md#4-demo-attack-scenarios-hành-vi-thật--log-thật):

| Scenario | Kỹ thuật MITRE | Kết quả |
|----------|----------------|---------|
| Không có JWT | — | HTTP 403, OPA deny |
| Brute force JWT sai | T1110.001 | HTTP 401×15, Alert Firing |
| channel=tor + 500M VND | T1078 | HTTP 403, fraud.score=75 |
| Vượt giới hạn 500M+ | — | HTTP 400, amount limit |
| Velocity 35 txn/60s | T1496 | Block từ txn thứ 31 |
| JWT sai secret | T1550.001 | HTTP 401, sig fail |

---

## Deploy từ đầu

```bash
# Sau khi có hạ tầng + K3s sẵn trên cả hai cluster:
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml
bash scripts/deploy-all.sh --skip-images

# Nếu cần setup OpenStack cluster từ đầu:
bash scripts/setup-os-cluster.sh
```

---

## Prometheus metrics tự định nghĩa

```promql
ztlab_transactions_total{service, cloud, type, status}
ztlab_fraud_score{service, cloud, verdict}
ztlab_cross_cloud_latency_seconds{source, target, status}
ztlab_auth_failures_total{service, cloud, reason}
ztlab_service_up{service, cloud}
```

---

## Tài liệu

- [HUONG_DAN.md](HUONG_DAN.md) — Hướng dẫn vận hành, khởi động, troubleshooting, demo step-by-step
- [BAOCAO.md](BAOCAO.md) — Báo cáo đồ án đầy đủ (tổng quan, thiết kế, triển khai, kết quả)
