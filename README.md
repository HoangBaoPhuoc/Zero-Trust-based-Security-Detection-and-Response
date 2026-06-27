# ZTLab — Zero Trust Security Detection & Response

**Đồ án chuyên ngành UIT · NT114.Q21.ANTT**  
Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
GVHD: ThS. Đỗ Thị Phương Uyên

Hệ thống lab multi-cloud minh họa Zero Trust Security cho microservices tài chính: user đăng nhập qua Keycloak OIDC/PKCE, gọi API Gateway được bảo vệ bởi Envoy sidecar + OPA ext_authz, xử lý payment qua fraud detection, rồi ghi giao dịch tại Core Banking trên OpenStack qua SPIRE mTLS. Log từ cả hai cloud được đưa về PLG Stack (Promtail → Loki → Grafana), Grafana phát hiện 4 loại tấn công và kích hoạt SOAR Engine theo mô hình Human-in-the-Loop (HITL) — admin nhận email với nút hành động, chọn playbook, SOAR thực thi trên K8s.

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
  │                 │  Promtail → Loki → Grafana (6 alert rules)               │  account-service
  │                 │                       │ attack detected (webhook thật)    │  transaction-service
  │                 │                       ▼                                   │  (spiffe://ztlab.local/openstack/*)
  │                 │               SOAR Engine (HITL · dedup 5min)             │
  │                 │        pending_approval → email admin                     │
  │                 │    isolate · restrict · revoke · block · quarantine       │
  │                 └───────────────────────────────────────────────────────────┘
```

**Stack:**
- **Identity:** Keycloak OIDC/PKCE, SPIFFE/SPIRE X.509 SVIDs (trust domain `ztlab.local`, gia hạn ~30 phút)
- **Policy:** Envoy sidecar + OPA ext_authz gRPC — JWT verify, RBAC, fraud gate, SVID check
- **Services:** FastAPI microservices trên K3s (AWS + OpenStack), Redis, PostgreSQL
- **Observability:** Promtail → Loki → Grafana (6 alert rules thật, gửi webhook mỗi 1 phút khi fire)
- **Security Ops:** SOAR Engine — HITL, 6 playbooks, email HITL với action buttons, dedup 5 phút/attack_type

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

# 5. Chạy demo đầy đủ (normal traffic + 4 attack scenarios)
bash scripts/run-demo.sh
```

**Hướng dẫn đầy đủ:** [HUONG_DAN.md](HUONG_DAN.md)

---

## URLs khi đang chạy

| Service | URL | Credential |
|---------|-----|------------|
| Web Portal | http://localhost:18081 | testuser01 / Test1234! (Keycloak SSO) |
| API Gateway | http://localhost:18080 | JWT Bearer |
| Keycloak Admin | http://localhost:8180 | admin / ztlab-admin-2026 |
| Grafana | http://localhost:3000 | admin / ZTALab2026! |
| SOAR Engine | http://localhost:8091 | — |
| AI Analyzer | http://localhost:18082 | — |
| Prometheus | http://localhost:9090 | — |
| Loki | http://localhost:13100 | — |
| pgAdmin | http://localhost:5050 | admin@ztlab.com / ztlab2026 |

---

## Tài khoản demo

| User | Password | Role | Tài khoản |
|------|----------|------|-----------|
| `testuser01` | `Test1234!` | financial-read, financial-write | ACC-1001 |
| `testuser02` | `Test1234!` | financial-read, financial-write | ACC-2001 |
| `merchant01` | `Test1234!` | financial-read (chỉ đọc — demo RBAC 403) | ACC-4001 |
| `analyst01` | `Test1234!` | security-analyst + security-admin (HITL approval) | — |

---

## 6 Kịch bản tấn công Zero Trust (Grafana → SOAR)

Mỗi kịch bản chứng minh 1 lớp Zero Trust enforcement thật, detection qua Grafana alert rules, phản ứng qua SOAR HITL.

| # | Tên | ATT&CK | Enforcement THẬT | Phát hiện Grafana | SOAR Playbook |
|---|-----|--------|------------------|-------------------|---------------|
| KB1 | Brute Force Login | T1110.001 | Keycloak từ chối 20/20 sai pass (401) | Envoy 401 count/1m by source_ip | revoke_user_sessions |
| KB2 | Fraud Gate Bypass | T1078.004 | OPA fraud gate block amount=500M (503) | OPA deny: attack_scenario=fraud_gate_bypass | isolate_workload |
| KB3 | Lateral Movement | T1021.007 | API GW từ chối SVID fake (403) | OPA deny: attack_scenario=lateral_movement | isolate_workload |
| KB4 | Data Exfiltration | T1041 | Envoy đo bytes_sent thật từ 10 bulk req | Envoy bytes_sent>1MB count/5m | restrict_egress |
| KB5 | Access Denied Spike | T1078 | OPA RBAC từ chối merchant01 POST /payments (403) | OPA deny: result=deny by source_ip | block_source_ip |
| KB6 | Privilege Escalation | T1611 | kubectl exec xác nhận uid=0, /etc/shadow readable | Log audit: privilege_escalation keyword | quarantine_workload |

> **HITL Flow:** severity ≥ high → SOAR tạo case `pending_approval` → email voha2005@gmail.com → admin duyệt tại Web Portal /security → playbook thực thi trên K8s.

> **Dedup:** SOAR giới hạn 1 case/attack_type/5 phút. Grafana real alert fire ~1 phút sau khi log vào Loki — nếu case đã có từ script, alert của Grafana sẽ bị dedup (status=deduped).

```bash
# Chạy 1 kịch bản:
bash tests/grafana_kb1_brute_force.sh
bash tests/grafana_kb2_fraud_gate.sh
# ... kb3, kb4, kb5, kb6

# Chạy tất cả 6 kịch bản:
bash tests/grafana_run_all.sh

# Restore sau demo (xóa cả soar-block NetworkPolicies):
bash scripts/run-demo.sh --restore
```

## Demo log hệ thống

| Log | Lệnh xem | Ý nghĩa |
|-----|----------|---------|
| Envoy access | `kubectl logs -n financial deploy/api-gateway -c envoy` | source_ip, response_code, bytes_sent, svid |
| OPA decision | `kubectl logs -n financial deploy/opa-server` | result=true/false, path, input attributes |
| SPIRE agent | `kubectl logs -n spire daemonset/spire-agent` | SVID renewal mỗi ~30 phút |
| SOAR cases | `curl http://localhost:8091/cases` | attack_type, severity, source_ip, status |
| Grafana Loki | http://localhost:3000 → Explore | Query: `{job="envoy-access"} \| json \| response_code=401` |
