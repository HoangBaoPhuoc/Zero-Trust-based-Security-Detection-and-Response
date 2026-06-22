# ZTLab — Zero Trust Security Detection & Response

**Đồ án chuyên ngành UIT** · Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)

Hệ thống lab multi-cloud minh họa Zero Trust Security cho microservices tài chính: user đăng nhập Keycloak OIDC/PKCE, gọi API Gateway qua Envoy+OPA, xử lý payment qua fraud detection, rồi thực hiện giao dịch tại Core Banking trên OpenStack bằng SPIRE mTLS. Log từ hai cloud được đưa về PLG Stack (Promtail → Loki → Grafana), Grafana alert rules phát hiện tấn công và gửi email cảnh báo admin.

---

## Kiến trúc

```
                    ── AWS K3s (ap-southeast-1) ─────────────────────────┐
User (browser)      │                                                      │
  │  OIDC/PKCE      │  web-portal → Keycloak (RS256 JWT)                  │
  ├───────────────► │  api-gateway ← Envoy sidecar + OPA ext_authz        │
  │                 │      │ SPIRE mTLS                                    │
  │                 │  payment-service → fraud-detection (Redis velocity)  │
  │                 │      │ cross-cloud SPIRE mTLS                        │
  │                 │      └──────────────────────────────────────────────►│── OpenStack K3s
  │                 │                                                       │      core-banking
  │                 │  Promtail → Loki → Grafana (5 dashboards)            │      account-service
  │                 │                       │ 4 alert rules → email admin  │      transaction-service
  │                 │                       │ (phản ứng thủ công bởi admin)│
  │                 └──────────────────────────────────────────────────────┘
```

**Stack:**
- **Identity:** Keycloak OIDC, SPIFFE/SPIRE X.509 SVIDs
- **Policy:** Envoy sidecar + OPA (ext_authz gRPC, 3 policies: zta, fraud_gate, cross_cloud)
- **Services:** FastAPI microservices (K3s K8s), Redis, PostgreSQL
- **Observability:** Promtail → Loki → Grafana (4 alert rules, email SMTP)
- **Security Ops:** Grafana Alerting (LogQL), email contact point, phản ứng thủ công bởi admin

---

## Cấu trúc repo

```
terraform/          Provisioning AWS + OpenStack (IaC)
ansible/            Inventory + playbooks cấu hình nodes
k8s/                Kubernetes manifests (financial, keycloak, plg-stack, monitoring)
opa/policies/       Rego: zta_policy, fraud_gate, cross_cloud
spire/              SPIRE server/agent configs + K8s manifests
envoy/              Envoy sidecar configmap
services/           FastAPI microservices source code
shared/             Python shared modules (logging, metrics)
plg-stack/grafana/  Dashboard JSON + alert YAML + datasource
monitoring/         Prometheus scrape config
scripts/            k8s-tunnel, health-check, run-demo, deploy, sync-images
tests/              scenario_01..20 (brute force, JWT forgery, lateral movement, ...)
```

---

## Bắt đầu nhanh

```bash
# 1. Bật EC2 instances (sau khi dừng, IP bastion sẽ đổi — cập nhật inventory)
aws ec2 start-instances --region ap-southeast-1 --instance-ids i-... i-...

# 2. Mở K8s tunnel
bash scripts/k8s-tunnel.sh up all
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes

# 3. Mở port-forwards (xem HUONG_DAN.md mục 3.2)

# 4. Health check
bash scripts/health-check.sh    # FAIL=0 là điều kiện tối thiểu

# 5. Demo
bash scripts/run-demo.sh
```

**Hướng dẫn đầy đủ:** [HUONG_DAN.md](HUONG_DAN.md)

---

## URLs khi đang chạy

| Service | URL | Credential |
|---------|-----|------------|
| Web Portal | http://127.0.0.1:18081 | OIDC login |
| API Gateway | http://127.0.0.1:18080 | JWT Bearer |
| Keycloak Admin | http://127.0.0.1:8180 | admin / ztlab-admin-2026 |
| Grafana | http://127.0.0.1:3000 | admin / ZTALab2026! |
| Loki | http://127.0.0.1:13100 | — |
| Prometheus | http://127.0.0.1:9090 | — |

## Tài khoản demo

| User | Password | Roles | Account |
|------|----------|-------|---------|
| `testuser01` | `Test1234!` | financial-read, financial-write | ACC-1001 |
| `testuser02` | `Test1234!` | financial-read, financial-write | ACC-2001 |
| `demoadmin` | `DemoAdmin2026!` | all 4 roles | ACC-3001 |
| `analyst01` | `Analyst1234!` | security-analyst | ACC-5001 |
