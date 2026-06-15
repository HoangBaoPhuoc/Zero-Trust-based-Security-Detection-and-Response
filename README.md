# ZTLab - Zero Trust Security Detection & Response

ZTLab là hệ thống lab multi-cloud cho đề tài **Zero Trust Security Detection and Response for Microservices**. Ứng dụng minh họa là hệ thống tài chính microservices: user đăng nhập Keycloak, gọi API Gateway, đi qua Envoy/OPA, Payment Service, Fraud Detection, rồi thực hiện giao dịch ở Core Banking trên OpenStack. Log từ hai cloud được đưa về Loki/Grafana, AI Analyzer phát hiện bất thường, admin duyệt HITL, SOAR Engine mới thực thi phản ứng.

## Trạng thái hiện tại

Các điểm bảo mật quan trọng đã được đồng bộ trong source hiện tại:

- API Gateway verify JWT bằng Keycloak JWKS/RS256 và fail-closed nếu JWKS không dùng được. HS256 dev token chỉ hoạt động khi bật `ALLOW_DEV_TOKENS=true` và có `JWT_DEV_SECRET`.
- Web Portal dùng cookie `ztlab_session` dạng opaque `sid`; access token/refresh token nằm trong server-side session, không nhét thẳng vào cookie.
- Keycloak admin password và session secret không còn mặc định hard-code trong code path production.
- Payment Service ký fraud gate bằng `CORE_BANKING_SHARED_SECRET`; Core Banking bắt buộc verify `X-Fraud-Gate-Signature` ngoài `X-Fraud-Gate=passed` và `X-Fraud-Score <= 74`.
- OPA không còn dựa vào JWT decode chưa verify để cấp quyền. User-level JWT được verify tại API Gateway; Envoy/OPA tập trung vào public path, edge bearer path, SVID workload và fraud gate.
- TheHive/Cassandra đã gỡ khỏi runtime để giảm RAM; case management hiện qua SOAR `/cases` và Loki audit.

Health-check gần nhất sau khi sửa tài liệu/flow: `PASS=35 WARN=4 FAIL=0`. Các warning còn lại liên quan remote AWS Kubernetes tunnel/API khi hạ tầng AWS master hoặc bastion không phản hồi đúng; OpenStack, local PLG, AI, SOAR, Loki đều pass.

## Kiến trúc nhanh

```text
Browser / curl
  -> Web Portal hoặc API Gateway trên AWS
  -> Keycloak JWT RS256
  -> API Gateway: rate limit + JWT verify + role check + trace_id
  -> Envoy sidecar + OPA ext_authz
  -> Payment Service
  -> Fraud Detection
  -> Envoy mTLS/SPIRE cross-cloud
  -> Core Banking trên OpenStack
  -> Account Service + Transaction Service
  -> Notification Service

Logs: app/Envoy/OPA -> Promtail -> Loki -> Grafana
Detection: Loki -> AI Analyzer -> pending alert -> admin approve/dismiss
Response: approved alert -> SOAR Engine -> K8s/Keycloak action -> case audit
```

## Hạ tầng và context

| Thành phần | Giá trị hiện tại | Ghi chú |
|---|---:|---|
| AWS K3s context | `ctx-aws` | API qua tunnel local `127.0.0.1:6444` |
| OpenStack K3s context | `ctx-openstack` | API qua tunnel local `127.0.0.1:6445` |
| AWS master | `10.10.1.10` | K3s control plane AWS |
| AWS worker | `10.10.1.11` | K3s worker AWS |
| OpenStack node | `10.10.1.12` | K3s single node, core banking |
| AWS bastion | lấy từ `terraform -chdir=terraform/aws output aws_bastion_pip` | Đồng bộ vào `ansible/inventory/hosts.yml` |
| SSH key | `~/.ssh/zta-siem-soar-key` | Dùng cho tunnel/Ansible |

Nếu `ctx-aws` bị `TLS handshake timeout` hoặc SSH báo `banner exchange timeout`, xem phần troubleshooting trong [HUONG_DAN.md](HUONG_DAN.md).

## Cấu trúc repo

```text
terraform/              IaC AWS/OpenStack
ansible/                inventory, playbooks, templates
k8s/financial/          manifest service tài chính AWS/OpenStack
k8s/keycloak/           realm, user, role, secret example
k8s/plg-stack/          Loki, Grafana, AI Analyzer, SOAR
opa/policies/           Rego policy cho Envoy ext_authz
spire/                  SPIRE server/agent/workload entries
envoy/                  Envoy sidecar config
services/               FastAPI microservices
scripts/                deploy, tunnel, health-check, demo, image sync
tests/                  scenario_00 full suite và scenario_01..20
```

## Bắt đầu test nhanh

### 1. Kiểm tra cấu hình và tunnel

```bash
terraform -chdir=terraform/aws output aws_bastion_pip
sed -n '1,80p' ansible/inventory/hosts.yml

bash scripts/k8s-tunnel.sh up all
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

`k8s-tunnel.sh up` mặc định kiểm tra tunnel Kubernetes thật sự bằng `/readyz`. Nếu cần kéo lại kubeconfig từ node, chạy:

```bash
SYNC_KUBECONFIG_ON_UP=true bash scripts/k8s-tunnel.sh up all
```

### 2. Chạy health-check tổng

```bash
bash scripts/health-check.sh
```

Kết quả đạt yêu cầu: `FAIL=0`. Warning remote SSH có thể bỏ qua nếu không bật `RUN_REMOTE=1`. Warning `ctx-aws` cần xử lý trước khi chạy full suite vì các scenario cần AWS K8s.

### 3. Nếu vừa sửa code, rebuild/sync image và deploy

```bash
IMAGE_TAG=1.1.0 BUILD_PAUSE_SECONDS=1 GROUP_PAUSE_SECONDS=2 bash scripts/sync-financial-images.sh
SKIP_BUILD=true bash scripts/deploy-all.sh --skip-images --skip-tunnel --skip-security-stack
```

Các image trong manifest hiện đang dùng tag `ztlab/*:1.1.0`.

### 4. Mở port-forward phục vụ test CLI

```bash
pkill -f 'kubectl.*port-forward' 2>/dev/null || true

nohup kubectl --context ctx-aws -n identity   port-forward svc/keycloak    8180:8080 --address=127.0.0.1 >/tmp/pf-kc.log 2>&1 &
nohup kubectl --context ctx-aws -n financial  port-forward svc/api-gateway 18080:8080 --address=127.0.0.1 >/tmp/pf-gw.log 2>&1 &
nohup kubectl --context ctx-aws -n financial  port-forward svc/web-portal  8080:8080 --address=127.0.0.1 >/tmp/pf-web.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack  port-forward svc/grafana     3001:3000 --address=127.0.0.1 >/tmp/pf-grafana.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack  port-forward svc/ai-analyzer 8090:8080 --address=127.0.0.1 >/tmp/pf-ai.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack  port-forward svc/soar-engine 8091:8080 --address=127.0.0.1 >/tmp/pf-soar.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack  port-forward svc/loki        3101:3100 --address=127.0.0.1 >/tmp/pf-loki.log 2>&1 &
```

### 5. Test payment baseline

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8180/realms/ztlab/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -s -X POST http://127.0.0.1:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000,"currency":"VND","channel":"api","country":"VN"}' \
  | python3 -m json.tool
```

Kết quả mong đợi:

```json
{
  "status": "completed",
  "trace_id": "...",
  "fraud": {"score": 5, "verdict": "allow", "gate": "passed"},
  "core_banking": {"status": "completed"}
}
```

### 6. Chạy full security scenario suite

```bash
BASELINE_SECONDS=30 \
LOKI_URL=http://127.0.0.1:3101 \
AI_URL=http://127.0.0.1:8090 \
SOAR_URL=http://127.0.0.1:8091 \
python3 tests/scenario_00_full_suite.py
```

Suite tự mở port-forward riêng trên dải `19180-19187`, fail sớm nếu port đã bị chiếm, và chạy các scenario từ brute force, JWT forgery, lateral movement, fraud gate bypass, high velocity tới SOAR response.


### 7. Demo bằng Web UI

Có tương tác Web UI. Sau khi mở port-forward ở bước 4:

1. Mở `http://127.0.0.1:8080`.
2. Bấm **"Đăng nhập qua Keycloak"**; dùng `demoadmin / DemoAdmin2026!` (đủ 4 roles) hoặc `testuser01 / Test1234!`.
3. Vào **Dashboard** để xem số dư và lịch sử giao dịch.
4. Vào **Chuyển tiền**:
   - Tài khoản nguồn: `ACC-1001`.
   - Tài khoản đích: `ACC-2001`.
   - Số tiền demo bình thường: `100000`.
   - Kết quả đúng: UI hiện `completed`, có `trace_id`, các bước JWT/OPA/Fraud/mTLS/Account/Ledger hoàn tất.
5. Vào **Kịch bản** để chạy các scenario tương tác:
   - `Không có JWT`: kỳ vọng bị chặn.
   - `JWT giả mạo`: kỳ vọng `401`.
   - `Fraud Gate Block`: kỳ vọng fraud block.
   - `High Velocity`: thấy score tăng theo số lần giao dịch.
   - Nhóm `AI Detection`: inject log và tạo pending alert.
6. Vào **AI Alerts**:
   - Chọn tab `Chờ duyệt`.
   - Với demo an toàn, bấm `Dismiss`.
   - Nếu muốn chứng minh SOAR, bấm `Approve -> SOAR`, sau đó kiểm tra case ở `http://127.0.0.1:8091/cases` và rollback nếu cần.
7. Vào **Logs** (`http://127.0.0.1:8080/logs`) để xem log gần nhất và panel **Redis Velocity** theo account, hoặc mở Grafana `http://127.0.0.1:3001` để query theo `trace_id`.

Flow demo đề xuất cho buổi trình bày:

```text
Login Web UI
  -> chuyển tiền bình thường
  -> copy trace_id, xem log/Grafana
  -> chạy JWT giả mạo trên trang Kịch bản
  -> chạy Fraud Gate Block
  -> chạy Brute Force/Port Scan inject
  -> vào AI Alerts dismiss/approve
  -> xem SOAR case/audit
```

## URL hay dùng

| Dịch vụ | URL local | Ghi chú |
|---|---|---|
| Web Portal | http://127.0.0.1:8080 | `testuser01 / Test1234!` |
| API Gateway | http://127.0.0.1:18080/health | Payment API |
| Keycloak | http://127.0.0.1:8180 | OIDC/admin |
| Grafana | http://127.0.0.1:3001 | `admin / ZTALab2026!` |
| Loki | http://127.0.0.1:3101/ready | SIEM log store |
| AI Analyzer | http://127.0.0.1:8090/health | Detection API |
| SOAR Engine | http://127.0.0.1:8091/health | Response/cases API |

## Tài khoản demo

| User | Password | Role | Tài khoản ngân hàng |
|---|---|---|---|
| `demoadmin` | `DemoAdmin2026!` | financial-read, financial-write, security-analyst, security-admin | `ACC-9LVGYX` (10M VND) |
| `testuser01` | `Test1234!` | `financial-read`, `financial-write` | `ACC-1001` |
| `testuser02` | `Test1234!` | `financial-read`, `financial-write` | `ACC-PVNP61` (10M VND) |
| `merchant01` | `Merchant1234!` | `financial-read` | `ACC-2001` |
| `analyst01` | `Analyst1234!` | `security-analyst` | — |

## Tài liệu tiếp theo

- [HUONG_DAN.md](HUONG_DAN.md): checklist vận hành/test từ đầu.
- [BAOCAO_FLOW_HE_THONG.md](BAOCAO_FLOW_HE_THONG.md): flow input/output từng thành phần.
- [BAOCAO.md](BAOCAO.md): báo cáo kỹ thuật/tổng kết đồ án.
- [MAP.md](MAP.md): bản đồ file và logic trong repo.
