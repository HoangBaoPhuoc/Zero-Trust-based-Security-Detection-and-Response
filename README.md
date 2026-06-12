# ZTLab — Zero Trust Security Detection & Response

> **Đồ án chuyên ngành** | Trường Đại học Công nghệ Thông tin — ĐHQG TP.HCM  
> Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> GVHD: Đỗ Thị Phương Uyên

ZTLab triển khai kiến trúc **Zero Trust** kết hợp **SIEM/SOAR tích hợp AI** trên môi trường **multi-cloud thực tế** gồm AWS và OpenStack. Ứng dụng minh họa là hệ thống tài chính microservices có luồng thanh toán cross-cloud, định danh workload bằng SPIFFE/SPIRE, policy enforcement bằng Envoy + OPA, log tập trung bằng Promtail/Loki/Grafana, phát hiện bằng AI Analyzer và phản ứng bằng SOAR Engine.

---

## Kiến trúc

```text
Browser / curl
  └─▶ SSH tunnel / Traefik Ingress (AWS)
        ├─▶ portal.ztlab.local  ──▶ web-portal
        ├─▶ api.ztlab.local     ──▶ api-gateway
        ├─▶ grafana.ztlab.local ──▶ Grafana
        ├─▶ keycloak.ztlab.local──▶ Keycloak
        ├─▶ ai.ztlab.local      ──▶ AI Analyzer
        └─▶ soar.ztlab.local    ──▶ SOAR Engine

[AWS K3s Cluster — ctx-aws]
  ├─ web-portal
  ├─ api-gateway        (JWT verify, role check, rate limit)
  ├─ payment-service    (payment orchestration)
  ├─ fraud-detection    (Redis velocity + amount/channel/country scoring)
  ├─ notification-service
  ├─ Keycloak / OPA / SPIRE / Redis
  └─ Loki / Grafana / Prometheus / AI Analyzer / SOAR Engine / TheHive
             │
             │ Envoy mTLS + SPIRE SVID
             ▼
        10.10.1.12:30081
             │
[OpenStack K3s Cluster — ctx-openstack]
  ├─ core-banking       (fraud gate validation, transaction execution)
  ├─ account-service    (PostgreSQL accounts)
  ├─ transaction-service(PostgreSQL ledger)
  └─ promtail           (push log về Loki trên AWS)
```

**Luồng thanh toán chính:**

```text
Web Portal/API client
  -> API Gateway
  -> Envoy + OPA
  -> Payment Service
  -> Fraud Detection
  -> Envoy mTLS cross-cloud
  -> Core Banking trên OpenStack
  -> Account Service + Transaction Service
  -> Notification Service
```

Cùng một `trace_id` được truyền qua toàn bộ chain để truy vết log từ AWS sang OpenStack.

---

## Gateway trong hệ thống

Hệ thống có 3 lớp gateway khác nhau:

| Lớp | Thành phần | Vai trò |
|---|---|---|
| Infrastructure Gateway | SSH tunnel, WireGuard, Traefik Ingress | Đưa traffic vào AWS cluster và nối AWS với OpenStack |
| API Gateway | `services/api-gateway` | Verify JWT, kiểm role, rate limit, tạo/truyền `X-Trace-ID`, forward sang payment |
| Envoy Sidecar Gateway | `envoy/configmap.yaml` | Policy Enforcement Point, gọi OPA ext_authz, mTLS bằng SPIRE SVID, route service-to-service |

Chi tiết input/output từng điểm được mô tả trong [BAOCAO_FLOW_HE_THONG.md](BAOCAO_FLOW_HE_THONG.md).

---

## Thành phần bảo mật

| Tầng | Công nghệ | Vai trò |
|---|---|---|
| Định danh workload | SPIFFE/SPIRE | Cấp X.509 SVID cho workload, trust domain `ztlab.local` |
| Kiểm soát truy cập | OPA + Envoy ext_authz | Policy-as-code: verify JWT issuer + expiry + realm role, chặn request tại sidecar |
| Xác thực người dùng | Keycloak OIDC | JWT RS256, issuer `keycloak.ztlab.local/realms/ztlab`, roles `financial-read/write`, `security-analyst/admin` |
| mTLS | Envoy + SPIRE SDS | Mã hóa và xác thực service-to-service |
| Network segmentation | Kubernetes NetworkPolicy | Giới hạn đường đi AWS -> OpenStack và traffic nội bộ namespace |
| SIEM | Promtail + Loki + Grafana | Log tập trung từ cả hai cloud |
| AI Detection | OpenAI/Gemini/Heuristic | Phân loại log, suy luận attack type, đề xuất playbook |
| HITL | Grafana alert → AI Analyzer webhook → Web Portal | Severity ≥ high tạo PendingAlert, Grafana POST `/grafana-webhook`, admin approve/reject trước khi SOAR chạy |
| SOAR | FastAPI + Kubernetes SDK | `isolate_workload`, `restrict_egress`, `quarantine_workload`, `block_source_ip`, `revoke_user_sessions` |
| Case management | TheHive | Tạo alert/case điều tra sự cố |

---

## Hạ tầng

### AWS Cluster (`ctx-aws`, tunnel port 6444)

| Node | IP | Vai trò |
|---|---|---|
| bastion | `54.254.252.106` | SSH jump host — EIP tĩnh |
| aws-master | `10.10.1.10` | K3s control plane, Traefik ingress |
| aws-worker-1 | `10.10.1.11` | K3s worker, Loki relay/proxy |

### OpenStack Cluster (`ctx-openstack`, tunnel port 6445)

| Node | IP | Vai trò |
|---|---|---|
| os-master | `10.10.1.12` | K3s standalone, core banking workloads |

```text
SSH key    : ~/.ssh/zta-siem-soar-key
Kubeconfig : ~/.kube/ztlab/aws-tunnel.yaml
```

---

## Cấu trúc repo

```text
.
├── terraform/                    # IaC provision AWS và OpenStack
├── ansible/                      # Baseline, WireGuard, K3s, Promtail
├── k8s/
│   ├── financial/
│   │   ├── aws-services.yaml             # api-gateway, payment, fraud, notification
│   │   ├── os-services.yaml              # core-banking, account, transaction trên OpenStack
│   │   ├── web-portal.yaml               # portal.ztlab.local
│   │   ├── aws-backend-services.yaml     # manifest hỗ trợ local/single-cluster
│   │   ├── redis.yaml
│   │   ├── postgres-accounts.yaml
│   │   ├── postgres-txn.yaml
│   │   └── network-policies/
│   ├── keycloak/                 # Realm ztlab, users, roles, clients
│   ├── plg-stack/                # Loki, Grafana, Promtail, AI, SOAR, TheHive
│   ├── monitoring/               # Prometheus
│   ├── ingress.yaml
│   └── rbac/
├── envoy/
│   └── configmap.yaml            # Envoy inbound/outbound, ext_authz, mTLS, cross-cloud upstream
├── opa/
│   ├── policies/
│   │   ├── zta_policy.rego       # Main allow/deny policy
│   │   ├── fraud_gate.rego       # Fraud gate validation
│   │   └── cross_cloud.rego      # AWS/OpenStack identity policy
│   └── deployment.yaml
├── spire/                        # SPIRE server/agent config và workload registration
├── services/
│   ├── web-portal/               # FastAPI + Jinja UI: dashboard, transfer, logs, alerts, scenarios
│   ├── api-gateway/              # JWT verify, role check, rate limit
│   ├── payment-service/          # Điều phối thanh toán
│   ├── fraud-detection/          # Fraud scoring
│   ├── core-banking/             # Execute transaction + fraud gate check
│   ├── account-service/          # Account DB + transfer
│   ├── transaction-service/      # Ledger DB
│   ├── notification-service/     # Notification event queue/log
│   ├── ai-analyzer/              # AI SOC analyst
│   ├── soar-engine/              # SOAR playbook runner
│   └── Dockerfile
├── shared/                       # Logging và Prometheus metrics dùng chung
├── plg-stack/                    # Grafana dashboard/alerting, Loki config
├── scripts/                      # Deploy, tunnel, health-check, demo, image sync
├── tests/                        # scenario_00 đến scenario_20 + metrics/perf
├── BAOCAO.md                     # Báo cáo đồ án đầy đủ
├── BAOCAO_FLOW_HE_THONG.md       # Báo cáo flow/gateway/input-output
└── HUONG_DAN.md                  # Hướng dẫn vận hành và demo
```

---

## Khởi động nhanh

### Yêu cầu

- SSH key tại `~/.ssh/zta-siem-soar-key`
- `kubectl`, `ssh`, `ansible`, `docker` đã cài sẵn
- Các VM/EC2 đang chạy
- Kubeconfig dùng tunnel: `~/.kube/ztlab/aws-tunnel.yaml`

### 1. Mở tunnel Kubernetes

```bash
bash scripts/k8s-tunnel.sh up all
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

### 2. Mở UI tunnel

Chạy ở terminal riêng và để lệnh này giữ kết nối:

```bash
ssh -N -i ~/.ssh/zta-siem-soar-key -o StrictHostKeyChecking=no   -L 18080:10.10.1.10:80 -J ubuntu@54.254.252.106 ubuntu@10.10.1.10
```

### 3. Mở port-forward cho API nội bộ cần debug

```bash
kubectl --context ctx-aws port-forward -n plg-stack svc/ai-analyzer 8090:8080 --address=127.0.0.1 &
kubectl --context ctx-aws port-forward -n plg-stack svc/soar-engine 8091:8080 --address=127.0.0.1 &
kubectl --context ctx-aws port-forward -n plg-stack svc/loki 3100:3100 --address=127.0.0.1 &
kubectl --context ctx-aws port-forward -n plg-stack svc/thehive 19000:9000 --address=127.0.0.1 &
```

### 4. Thêm `/etc/hosts`

```bash
grep -q "api.ztlab.local" /etc/hosts || sudo tee -a /etc/hosts <<'EOF'
127.0.0.1  api.ztlab.local portal.ztlab.local grafana.ztlab.local keycloak.ztlab.local prometheus.ztlab.local ai.ztlab.local soar.ztlab.local
EOF
```

### 5. Kiểm tra sức khỏe

```bash
curl -s -H "Host: api.ztlab.local" http://127.0.0.1:18080/health
curl -s -H "Host: portal.ztlab.local" http://127.0.0.1:18080/health
curl -s http://127.0.0.1:8090/health | python3 -m json.tool
curl -s http://127.0.0.1:8091/health | python3 -m json.tool
```

---

## URL sau khi mở tunnel

| Thành phần | URL | Ghi chú |
|---|---|---|
| Web Portal | http://portal.ztlab.local:18080 | Đăng nhập, chuyển tiền, logs, alerts, scenarios |
| API Gateway | http://api.ztlab.local:18080/health | API tài chính |
| Grafana | http://grafana.ztlab.local:18080 | `admin / ZTALab2026!` |
| Keycloak | http://keycloak.ztlab.local:18080 | `admin / ztlab-admin-2026` |
| Prometheus | http://prometheus.ztlab.local:18080/targets | Monitoring |
| AI Analyzer | http://127.0.0.1:8090/health | Port-forward |
| SOAR Engine | http://127.0.0.1:8091/cases | Port-forward |
| Loki | http://127.0.0.1:3100/ready | Port-forward |
| TheHive | http://127.0.0.1:19000 | Port-forward |

Tài khoản demo trong Keycloak:

| User | Password | Role |
|---|---|---|
| `testuser01` | `Test1234!` | `financial-read`, `financial-write` |
| `testuser02` | `Test1234!` | `financial-read`, `financial-write` |
| `merchant01` | `Merchant1234!` | `financial-read` |
| `analyst01` | `Analyst1234!` | `security-analyst` |

---

## Test payment flow

Tạo token dev HS256:

```bash
TOKEN=$(bash scripts/gen-dev-token.sh testuser01 financial-write 2>/dev/null | head -1)
```

Gửi giao dịch qua API Gateway:

```bash
curl -s   -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json"   -H "Host: api.ztlab.local"   -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000,"currency":"VND","channel":"api"}'   -X POST http://127.0.0.1:8080/payments | python3 -m json.tool
```

Kết quả mong đợi:

```json
{
  "status": "completed",
  "trace_id": "<uuid>",
  "fraud": {
    "score": 5,
    "verdict": "allow",
    "gate": "passed"
  },
  "core_banking": {
    "status": "completed"
  }
}
```

---

## Fraud scoring model

| Yếu tố | Ngưỡng | Điểm |
|---|---|---|
| Baseline | Luôn có | +5 |
| Velocity trung bình | Count > `FRAUD_VELOCITY_SOFT_LIMIT / 2` | +10 |
| Velocity cao | Count > `FRAUD_VELOCITY_SOFT_LIMIT` | +25 |
| Velocity rất cao | Count > `FRAUD_VELOCITY_SOFT_LIMIT * 3` | +40 |
| High amount | `amount >= 100000000` | +30 |
| Critical amount | `amount >= 500000000` | +55 |
| Risky channel | `tor`, `unknown`, `script` | +15 |
| Unusual country | Ngoài `VN`, `SG`, `TH` | +10 |

Kết quả:

- `score < 40`: `allow`, gate `passed`
- `40 <= score < 75`: `review`, gate `passed`
- `score >= 75`: `block`, gate `blocked`

Core Banking chỉ nhận `/transactions/execute` khi có `X-Fraud-Gate: passed` và `X-Fraud-Score < 75`; service này vẫn tự validate lại trong code để chống bypass.

---

## AI/SOAR/HITL flow

```text
Service/Envoy logs
  -> Promtail
  -> Loki
  -> AI Analyzer (poll mỗi 120s, lookback 300s)
  -> Nếu severity >= high: tạo PendingAlert, push log pending_approval=true lên Loki
  -> Grafana alert rule detect log pending_approval=true
  -> Grafana Contact Point "ztlab-security-admin" POST /grafana-webhook trên AI Analyzer
  -> Admin nhận thông báo, review tại Web Portal (GET /pending)
  -> Admin approve: POST /approve/{alert_id}
  -> SOAR Engine thực thi playbook (isolate/restrict/quarantine/block/revoke)
  -> Kubernetes/Keycloak action
  -> cases.jsonl + Loki audit log
```

Playbook hiện có:

| Playbook | Hành động |
|---|---|
| `isolate_workload` | Patch Service selector để ngắt traffic vào workload |
| `restrict_egress` | Scale deployment xuống 0 cho tình huống exfiltration |
| `quarantine_workload` | Scale deployment xuống 0 cho workload bị compromise |
| `block_source_ip` | Tạo NetworkPolicy chặn source IP |
| `revoke_user_sessions` | Revoke session user qua Keycloak Admin API |
| `monitor_only` | Chỉ ghi nhận và giám sát |

---

## Attack scenarios

Repo hiện có bộ scenario từ `scenario_00` đến `scenario_20`.

| File | Nội dung |
|---|---|
| `scenario_00_full_suite.py` | Chạy full suite |
| `scenario_01_brute_force.sh` | Brute force/JWT failure |
| `scenario_02_jwt_forgery.py` | JWT forgery |
| `scenario_03_lateral_movement.sh` | Lateral movement/SVID sai |
| `scenario_04_fraud_gate_bypass.py` | Bypass fraud gate |
| `scenario_05_high_velocity.py` | High-velocity transaction |
| `scenario_06_exfiltration.py` | Data exfiltration/large response |
| `scenario_07_svid_expiry.sh` | SPIRE/SVID expiry/impair identity |
| `scenario_08_cross_cloud.sh` | Cross-cloud policy test |
| `scenario_09_privesc.sh` | Privilege escalation |
| `scenario_10_portscan.sh` | Port scan |
| `scenario_11_cryptomining.sh` | Cryptomining |
| `scenario_12_soar_response.sh` | SOAR response validation |
| `scenario_13_sql_injection.sh` | SQL injection probe |
| `scenario_14_command_injection.sh` | Command injection probe |
| `scenario_15_account_manipulation.sh` | Account manipulation |
| `scenario_16_credential_stuffing.sh` | Credential stuffing |
| `scenario_17_impair_defenses.sh` | Impair defenses |
| `scenario_18_container_escape.sh` | Container escape signal |
| `scenario_19_data_staging.sh` | Data staging |
| `scenario_20_replay_attack.sh` | Replay attack |

Chạy full suite:

```bash
python3 tests/scenario_00_full_suite.py
```

Hoặc chạy demo script:

```bash
LOKI_URL=http://127.0.0.1:3100 bash scripts/run-demo.sh
```

---

## Deploy từ đầu

```bash
export KUBECONFIG=~/.kube/ztlab/aws-tunnel.yaml

# Mở tunnel nếu chưa có
bash scripts/k8s-tunnel.sh up all

# Deploy toàn bộ stack
bash scripts/deploy-all.sh

# Nếu image đã sync/build rồi
bash scripts/deploy-all.sh --skip-images
```

Các option chính:

```text
--skip-images
--skip-tunnel
--skip-security-stack
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

- [BAOCAO_FLOW_HE_THONG.md](BAOCAO_FLOW_HE_THONG.md) — Flow hệ thống, gateway, input/output từng điểm
- [BAOCAO.md](BAOCAO.md) — Báo cáo đồ án đầy đủ
- [HUONG_DAN.md](HUONG_DAN.md) — Hướng dẫn vận hành, demo và troubleshooting
- [MAP.md](MAP.md) — Bản đồ file và logic hệ thống
