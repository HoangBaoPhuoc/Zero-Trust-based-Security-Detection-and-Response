# ZTLab — Zero Trust Security Detection & Response

**Đồ án chuyên ngành UIT · NT114.Q21.ANTT**  
Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
GVHD: ThS. Đỗ Thị Phương Uyên

Hệ thống lab multi-cloud minh họa Zero Trust Security cho microservices tài chính: user đăng nhập qua Keycloak OIDC/PKCE, gọi API Gateway được bảo vệ bởi Envoy sidecar + OPA ext_authz, xử lý payment qua fraud detection (bao gồm tín hiệu device trust), rồi ghi giao dịch tại Core Banking trên OpenStack qua SPIRE mTLS. Log từ cả hai cloud được đưa về PLG Stack (Promtail → Loki → Grafana), Grafana phát hiện 5 loại tấn công và kích hoạt SOAR Engine theo mô hình Human-in-the-Loop (HITL) — admin nhận email với nút hành động, chọn playbook, SOAR thực thi trên K8s.

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
  │                 │  Promtail → Loki → Grafana (5 alert rules)               │  account-service
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
- **Observability:** Promtail → Loki → Grafana (5 alert rules thật, gửi webhook mỗi 1 phút khi fire)
- **Security Ops:** SOAR Engine — HITL, 5 playbooks, email HITL với action buttons, dedup 5 phút/attack_type

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
scripts/            k8s-tunnel, open-admin-uis, run-demo, deploy, patch-services, sync-images
tests/              seed_db, scenario tests
ml-dataset/         Script + tài liệu sinh dataset train/test cho nhóm ML/DL (xem ml-dataset/README.md)
```

---

## Bắt đầu nhanh

Toàn bộ hướng dẫn deploy (lần đầu từ số 0, hoặc bật lại/redeploy hệ thống đã có sẵn) nằm ở **[DEPLOY.md](DEPLOY.md)** — không lặp lại ở đây để tránh 2 nơi lệch nhau. Tóm tắt siêu ngắn cho người đã quen hệ thống:

```bash
bash scripts/k8s-tunnel.sh up all      # mở tunnel tới 2 cluster
bash scripts/open-admin-uis.sh         # mở toàn bộ port-forward (tự-restart)
bash scripts/run-demo.sh --restore     # đưa hệ thống về trạng thái sạch
bash scripts/run-demo.sh               # normal traffic + 4 kịch bản tấn công
```

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
| `demoadmin` | `Test1234!` | security-admin + security-analyst (full quyền: `/admin`, `/security`, `/scenarios`, `/monitor`, phê duyệt HITL) | — |
| `soc01` | `Test1234!` | security-analyst — dùng để chạy `/scenarios` trên Web Portal (role-gated) | — |
| `analyst01` | `Test1234!` | security-analyst — **login qua Keycloak hiện bị lỗi** (redirect loop ở login-actions/authenticate, chưa rõ nguyên nhân); dùng `demoadmin` hoặc `soc01` thay thế | — |

---

## 5 kịch bản tấn công Zero Trust (Grafana → SOAR)

Mỗi kịch bản chứng minh 1 lớp Zero Trust enforcement thật, detection qua Grafana alert rules (`plg-stack/grafana/alerting/*.yml`), phản ứng qua SOAR HITL.

| Tên | ATT&CK | Enforcement THẬT | Phát hiện Grafana | SOAR Playbook | Chạy bằng |
|-----|--------|------------------|-------------------|----------------|-----------|
| Brute Force Login | T1110.001 | Keycloak từ chối 20/20 sai pass (401) | `brute-force-alert.yml` | revoke_user_sessions | `run-demo.sh --kb1` |
| Lateral Movement | T1021.007 | API GW từ chối SVID fake (403) | `lateral-movement-alert.yml` | isolate_workload | `run-demo.sh --kb2` |
| Fraud Gate Bypass | T1078.004 | OPA fraud gate block amount=500M (403) | `fraud-gate-bypass-alert.yml` | isolate_workload | `run-demo.sh --kb3` |
| Data Exfiltration | T1041 | Envoy đo bytes_sent thật (bulk response) | `large-response-alert.yml` | restrict_egress | `run-demo.sh --kb4` |
| Access Denied Spike | T1078 | OPA RBAC từ chối merchant01 POST /payments (403) | `access-denied-alert.yml` | block_source_ip | `tests/grafana_kb5_access_denied.sh` |

> **Số hiệu KB chỉ có ý nghĩa bên trong `scripts/run-demo.sh --kbN`** (dùng cho lệnh ở cột cuối). Không dùng số KB để tham chiếu chéo sang nơi khác — tránh nhầm với thứ tự liệt kê trong tài liệu khác.
>
> **Privilege Escalation (T1611)**: có manifest `k8s/financial/security-scanner-job.yaml` nhưng **chưa có Grafana alert rule tương ứng** — chưa nằm trong pipeline detection→SOAR tự động, chỉ verify thủ công qua `kubectl exec`. Xem đây là hướng phát triển tiếp theo, không phải kịch bản demo-được.

> **HITL Flow:** severity ≥ high → SOAR tạo case `pending_approval` → email voha2005@gmail.com → admin duyệt tại Web Portal /security → playbook thực thi trên K8s.

> **Dedup:** SOAR giới hạn 1 case/attack_type/5 phút. Grafana real alert fire ~1 phút sau khi log vào Loki — nếu case đã có từ script, alert của Grafana sẽ bị dedup (status=deduped).

```bash
# Chạy từng kịch bản (KB1-KB4 qua run-demo.sh, KB5 là script riêng):
bash scripts/run-demo.sh --kb1   # brute force
bash scripts/run-demo.sh --kb2   # lateral movement
bash scripts/run-demo.sh --kb3   # fraud gate bypass
bash scripts/run-demo.sh --kb4   # data exfiltration
bash tests/grafana_kb5_access_denied.sh

# Restore sau demo (xóa cả soar-block NetworkPolicies):
bash scripts/run-demo.sh --restore
```

Chi tiết vận hành/redeploy: xem **[DEPLOY.md](DEPLOY.md)**.

## Demo log hệ thống

| Log | Lệnh xem | Ý nghĩa |
|-----|----------|---------|
| Envoy access | `kubectl logs -n financial deploy/api-gateway -c envoy` | source_ip, response_code, bytes_sent, svid |
| OPA decision | `kubectl logs -n financial deploy/opa-server` | result=true/false, path, input attributes |
| SPIRE agent | `kubectl logs -n spire daemonset/spire-agent` | SVID renewal mỗi ~30 phút |
| SOAR cases | `curl http://localhost:8091/cases` | attack_type, severity, source_ip, status |
| Grafana Loki | http://localhost:3000 → Explore | Query: `{job="envoy-access"} \| json \| response_code=401` |
