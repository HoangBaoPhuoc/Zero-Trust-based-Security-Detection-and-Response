# ZTLab — Zero Trust Security Detection & Response

**Đồ án chuyên ngành UIT · NT114.Q21.ANTT**  
Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
GVHD: ThS. Đỗ Thị Phương Uyên

Hệ thống lab multi-cloud minh họa Zero Trust Security cho microservices tài chính: user đăng nhập qua Keycloak OIDC/PKCE, gọi API Gateway được bảo vệ bởi Envoy sidecar + OPA ext_authz, xử lý payment qua fraud detection, rồi ghi giao dịch tại Core Banking trên OpenStack qua SPIRE mTLS. Log từ cả hai cloud được đưa về PLG Stack (Promtail → Loki → Grafana), Grafana alert rules phát hiện 4 loại tấn công và tự động kích hoạt SOAR Engine thực hiện playbook K8s (isolate, restrict, revoke).

---

## Kiến trúc

```
                    ── AWS K3s (ap-southeast-1) ──────────────────────────────┐
User (browser)      │                                                          │
  │  OIDC/PKCE      │  web-portal ──► Keycloak (RS256 JWT · PKCE)             │
  ├──────────────►  │  api-gateway ← Envoy sidecar + OPA ext_authz            │
  │                 │      │ SPIRE mTLS  (spiffe://ztlab.local/aws/*)          │
  │                 │  payment-service → fraud-detection (Redis velocity)      │
  │                 │      │ WireGuard + SPIRE mTLS cross-cloud                │
  │                 │      └──────────────────────────────────────────────────►│── OpenStack K3s
  │                 │                                                           │  core-banking
  │                 │  Promtail → Loki → Grafana (6 dashboards, 6 alerts)      │  account-service
  │                 │                       │ 4 attack types detected           │  transaction-service
  │                 │                       ▼                                   │  (spiffe://ztlab.local/openstack/*)
  │                 │               SOAR Engine                                 │
  │                 │          (auto_execute, 5 playbooks)                      │
  │                 │    isolate · restrict · revoke · block · quarantine       │
  │                 └───────────────────────────────────────────────────────────┘
```

**Stack:**
- **Identity:** Keycloak OIDC/PKCE, SPIFFE/SPIRE X.509 SVIDs (trust domain `ztlab.local`)
- **Policy:** Envoy sidecar + OPA ext_authz gRPC — JWT verify, RBAC, fraud gate, SVID check
- **Services:** FastAPI microservices trên K3s (AWS + OpenStack), Redis, PostgreSQL
- **Observability:** Promtail → Loki (90 ngày) → Grafana (6 dashboards, 6 alert rules)
- **Security Ops:** SOAR Engine — nhận Grafana webhook, chạy playbook K8s tự động (`auto_execute=true`)

---

## Cấu trúc repo

```
terraform/          Provisioning AWS + OpenStack (IaC)
ansible/            Inventory + playbooks cấu hình nodes
k8s/                Kubernetes manifests (financial, identity, plg-stack, monitoring)
opa/policies/       Rego: zta_policy (JWT, RBAC, fraud gate, SVID)
spire/              SPIRE server/agent configs + K8s manifests
envoy/              Envoy sidecar configmap (mTLS, OPA ext_authz)
services/           FastAPI microservices source code
shared/             Python shared modules (logging, metrics)
monitoring/         Prometheus scrape config
scripts/            k8s-tunnel, open-admin-uis, run-demo, deploy, sync-images
tests/              seed_db, scenario tests
```

---

## Bắt đầu nhanh

```bash
# 1. Bật OpenStack VMs (sau reboot host, VMs tắt)
source /etc/kolla/admin-openrc.sh
openstack server list
openstack server start os-gateway os-k3s-master os-k3s-worker-1 os-k3s-worker-2
sleep 30

# 2. Mở K8s tunnels
bash scripts/k8s-tunnel.sh up all
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes

# 3. Mở port-forwards (daemon tự-restart)
bash scripts/open-admin-uis.sh

# 4. Restore services về trạng thái sạch
bash scripts/run-demo.sh --restore

# 5. Chạy demo đầy đủ (normal traffic + 4 kịch bản tấn công)
bash scripts/run-demo.sh
```

**Hướng dẫn đầy đủ:** [HUONG_DAN.md](HUONG_DAN.md)

---

## URLs khi đang chạy

| Service | URL | Credential |
|---------|-----|------------|
| Web Portal | http://localhost:18081 | testuser01 / Test@123! (Keycloak SSO) |
| API Gateway | http://localhost:18080 | JWT Bearer |
| Keycloak Admin | http://localhost:8180 | admin / ztlab-admin-2026 |
| Grafana | http://localhost:3000 | admin / ZTALab2026! |
| SOAR Engine | http://localhost:8091 | — |
| Prometheus | http://localhost:9090 | — |
| Loki | http://localhost:13100 | — |
| pgAdmin | http://localhost:5050 | admin@ztlab.com / ztlab2026 |

---

## Tài khoản demo

| User | Password | Role | Tài khoản |
|------|----------|------|-----------|
| `testuser01` | `Test@123!` | financial-read, financial-write | ACC-1001 |
| `testuser02` | `Test@123!` | financial-read, financial-write | ACC-2001 |
| `merchant01` | `Merchant@123!` | financial-read (chỉ đọc, demo RBAC 403) | ACC-4001 |
| `analyst01` | `Analyst@123!` | security-analyst (xem /security, /monitor) | ACC-5001 |

---

## 4 Kịch bản tấn công

| # | Tên | ATT&CK | Phát hiện | SOAR phản ứng |
|---|-----|--------|-----------|--------------|
| KB1 | Brute Force Login | T1110.001 | Envoy 401 count > ngưỡng / 1m | `revoke_user_sessions` |
| KB2 | Lateral Movement | T1021.007 | OPA deny SVID ngoài trust domain | `isolate_workload` (payment-service) |
| KB3 | Fraud Gate Bypass | T1078.004 | OPA deny `/transactions/execute` | `isolate_workload` (payment-service) |
| KB4 | Data Exfiltration | T1041 | Envoy response `bytes_sent > 1MB` | `restrict_egress` (core-banking, OpenStack) |

```bash
# Chạy từng kịch bản:
bash scripts/run-demo.sh --kb1
bash scripts/run-demo.sh --kb2
bash scripts/run-demo.sh --kb3
bash scripts/run-demo.sh --kb4
# Restore sau demo:
bash scripts/run-demo.sh --restore
```
