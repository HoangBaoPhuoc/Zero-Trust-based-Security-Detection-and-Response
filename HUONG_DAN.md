# ZTLab - Hướng Dẫn Vận Hành Và Test Hệ Thống

Tài liệu này là đường đọc chính khi bắt đầu test hệ thống. Làm theo thứ tự từ trên xuống: kiểm tra hạ tầng, mở tunnel, health-check, deploy nếu cần, rồi chạy payment baseline và security scenarios.

## 0. Nguyên tắc đọc nhanh

- Mọi lệnh chạy tại root repo.
- Không dùng dev token trong test mặc định. Lấy JWT thật từ Keycloak.
- `FAIL=0` trong `scripts/health-check.sh` là điều kiện tối thiểu trước khi demo.
- Nếu vừa sửa code service, phải build/sync image và rollout lại trước khi kết luận test.
- SOAR có thể tác động Kubernetes thật khi approve alert. Với demo an toàn, dùng `dismiss` hoặc rollback case sau khi approve.

## 1. Kiểm tra hạ tầng hiện tại

```bash
pwd
git status --short
terraform -chdir=terraform/aws output aws_bastion_pip
terraform -chdir=terraform/aws output aws_instances
sed -n '1,90p' ansible/inventory/hosts.yml
```

Đối chiếu `aws_bastion` trong `ansible/inventory/hosts.yml` với `terraform -chdir=terraform/aws output aws_bastion_pip`. Nếu khác, sửa inventory trước khi mở tunnel AWS.

Context và port chuẩn:

| Context | Local API | Remote |
|---|---:|---|
| `ctx-aws` | `127.0.0.1:6444` | `10.10.1.10:6443` qua AWS bastion |
| `ctx-openstack` | `127.0.0.1:6445` | `10.10.1.12:6443` qua jump host |

## 2. Mở Kubernetes tunnel

```bash
bash scripts/k8s-tunnel.sh up all
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
```

Nếu cần sync lại kubeconfig từ node:

```bash
SYNC_KUBECONFIG_ON_UP=true bash scripts/k8s-tunnel.sh up all
```

Kiểm tra port tunnel:

```bash
ss -lntp | grep -E ':6444|:6445'
kubectl --context ctx-aws get --raw=/readyz --request-timeout=15s
kubectl --context ctx-openstack get --raw=/readyz --request-timeout=15s
```

## 3. Health-check tổng

```bash
bash scripts/health-check.sh
```

Kết quả mong đợi:

```text
FAIL=0
```

Warning thường gặp:

| Warning | Ý nghĩa | Cách xử lý |
|---|---|---|
| `remote SSH checks skipped` | Bình thường khi `RUN_REMOTE=0` | Bỏ qua hoặc chạy `RUN_REMOTE=1 bash scripts/health-check.sh` |
| `ctx-aws TLS handshake timeout` | Tunnel/socket có nhưng AWS API không trả lời | Xem mục 12.1 |
| `Loki raw demo stream missing` | Chưa có log demo raw | Chạy `LOKI_URL=http://127.0.0.1:3101 bash scripts/run-demo.sh --traffic-only` hoặc seed log demo |

## 4. Deploy khi code hoặc manifest thay đổi

Nếu chỉ kiểm tra hệ thống đang chạy, bỏ qua mục này. Nếu vừa sửa source service hoặc manifest:

```bash
IMAGE_TAG=1.1.0 BUILD_PAUSE_SECONDS=1 GROUP_PAUSE_SECONDS=2 bash scripts/sync-financial-images.sh
SKIP_BUILD=true bash scripts/deploy-all.sh --skip-images --skip-tunnel --skip-security-stack
```

Chờ rollout:

```bash
kubectl --context ctx-aws -n financial rollout status deployment/api-gateway --timeout=120s
kubectl --context ctx-aws -n financial rollout status deployment/payment-service --timeout=120s
kubectl --context ctx-openstack -n financial rollout status deployment/core-banking --timeout=120s
kubectl --context ctx-aws -n plg-stack rollout status deployment/ai-analyzer --timeout=120s
kubectl --context ctx-aws -n plg-stack rollout status deployment/soar-engine --timeout=120s
```

## 5. Mở port-forward để test thủ công

```bash
pkill -f 'kubectl.*port-forward' 2>/dev/null || true

nohup kubectl --context ctx-aws -n financial  port-forward svc/api-gateway 18080:8080 --address=127.0.0.1 >/tmp/pf-gw.log 2>&1 &
nohup kubectl --context ctx-aws -n financial  port-forward svc/web-portal  8080:8080 --address=127.0.0.1 >/tmp/pf-web.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack  port-forward svc/grafana     3001:3000 --address=127.0.0.1 >/tmp/pf-grafana.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack  port-forward svc/ai-analyzer 8090:8080 --address=127.0.0.1 >/tmp/pf-ai.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack  port-forward svc/soar-engine 8091:8080 --address=127.0.0.1 >/tmp/pf-soar.log 2>&1 &
nohup kubectl --context ctx-aws -n plg-stack  port-forward svc/loki        3101:3100 --address=127.0.0.1 >/tmp/pf-loki.log 2>&1 &

sleep 4
for url in \
  http://127.0.0.1:8080/health \
  http://127.0.0.1:18080/health \
  http://127.0.0.1:8080/kc/realms/ztlab/.well-known/openid-configuration \
  http://127.0.0.1:3001/api/health \
  http://127.0.0.1:8090/health \
  http://127.0.0.1:8091/health \
  http://127.0.0.1:3101/ready; do
  printf '%-80s ' "$url"
  curl -fsS --max-time 5 "$url" >/dev/null && echo OK || echo FAIL
done
```

## 6. Test payment baseline

Lấy JWT từ Keycloak (qua `/kc/` proxy — chỉ cần port 8080):

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/kc/realms/ztlab/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
```

Gửi giao dịch hợp lệ:

```bash
curl -s -X POST http://127.0.0.1:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000,"currency":"VND","channel":"api","country":"VN"}' \
  | python3 -m json.tool
```

Kỳ vọng:

- HTTP 200.
- `status=completed`.
- `fraud.gate=passed`.
- `core_banking.status=completed`.
- Log có cùng `trace_id` trên AWS và OpenStack.

Tra cứu trace trong Loki:

```bash
TRACE=<trace_id_from_response>
curl -G 'http://127.0.0.1:3101/loki/api/v1/query' \
  --data-urlencode 'query={namespace="financial"} |= "'"$TRACE"'"' \
  | python3 -m json.tool
```

## 7. Test các lớp bảo mật chính

### 7.1 Không có JWT phải bị chặn

```bash
curl -s -o /tmp/no-jwt.out -w '%{http_code}\n' \
  -X POST http://127.0.0.1:18080/payments \
  -H 'Content-Type: application/json' \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":100000}'
cat /tmp/no-jwt.out
```

Kỳ vọng: `401` hoặc `403` tùy request bị chặn ở API Gateway hay Envoy/OPA.

### 7.2 JWT giả phải bị chặn

```bash
FAKE_JWT='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZXIiLCJleHAiOjk5OTk5OTk5OTl9.INVALID'

curl -s -o /tmp/fake-jwt.out -w '%{http_code}\n' \
  -X POST http://127.0.0.1:18080/payments \
  -H "Authorization: Bearer $FAKE_JWT" \
  -H 'Content-Type: application/json' \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000}'
cat /tmp/fake-jwt.out
```

Kỳ vọng: `401`.

### 7.3 Fraud gate block

```bash
curl -s -X POST http://127.0.0.1:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":500000000,"currency":"VND","channel":"tor","country":"RU"}' \
  | python3 -m json.tool
```

Kỳ vọng: HTTP 403 với body:

```json
{
  "detail": {
    "reason": "fraud gate blocked",
    "fraud": { "score": 85, "verdict": "block", "gate": "blocked",
                "reason": ["critical_amount","risky_channel","unusual_country"] }
  }
}
```

### 7.4 Direct Core Banking bypass phải bị chặn

Full suite đã test tự động scenario này. Test thủ công:

```bash
nohup kubectl --context ctx-openstack -n financial port-forward svc/core-banking 19184:8080 --address=127.0.0.1 >/tmp/pf-core.log 2>&1 &
sleep 2
curl -s -o /tmp/direct-core.out -w '%{http_code}\n' \
  -X POST http://127.0.0.1:19184/transactions/execute \
  -H 'Content-Type: application/json' \
  -H 'X-Fraud-Gate: passed' \
  -H 'X-Fraud-Score: 1' \
  -H "X-Fraud-Timestamp: $(date +%s)" \
  -H 'X-Fraud-Gate-Signature: deadbeef_forged' \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000,"currency":"VND","trace_id":"manual-bypass"}'
cat /tmp/direct-core.out
pkill -f 'kubectl --context ctx-openstack -n financial port-forward svc/core-banking 19184:8080' || true
```

Kỳ vọng: `403`. Timestamp hợp lệ nhưng HMAC signature sai → Core Banking reject. Log audit ghi `fraud_signature_valid: false`.

## 8. Test AI/SOAR HITL

Inject alert critical:

```bash
curl -s -X POST http://127.0.0.1:8090/analyze \
  -H 'Content-Type: application/json' \
  -d '{
    "source":"manual-hitl-test",
    "logs":[{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","message":"fraud_gate_bypass detected service=payment-service source_ip=10.9.8.9 critical unauthorized transfer","labels":{"namespace":"financial","app":"payment-service","job":"envoy-access"}}]
  }' | python3 -m json.tool
```

Xem pending alert:

```bash
curl -s 'http://127.0.0.1:8090/pending?status=pending' | python3 -m json.tool
```

Dismiss để demo an toàn:

```bash
ALERT_ID=$(curl -s 'http://127.0.0.1:8090/pending?status=pending' \
  | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a[0]["alert_id"] if a else "")')

curl -s -X POST "http://127.0.0.1:8090/pending/${ALERT_ID}/dismiss" \
  -H 'Content-Type: application/json' \
  -d '{"note":"manual demo, no real incident"}' | python3 -m json.tool
```

Approve chỉ khi muốn SOAR tác động thật:

```bash
curl -s -X POST "http://127.0.0.1:8090/pending/${ALERT_ID}/approve" \
  -H 'Content-Type: application/json' \
  -d '{"note":"confirmed, execute playbook"}' | python3 -m json.tool

curl -s http://127.0.0.1:8091/cases | python3 -m json.tool
```

Rollback case nếu playbook hỗ trợ:

```bash
CASE_ID=<case_id>
curl -s -X POST "http://127.0.0.1:8091/cases/${CASE_ID}/rollback" | python3 -m json.tool
```

## 9. Chạy full scenario suite

```bash
BASELINE_SECONDS=30 \
LOKI_URL=http://127.0.0.1:3101 \
AI_URL=http://127.0.0.1:8090 \
SOAR_URL=http://127.0.0.1:8091 \
python3 tests/scenario_00_full_suite.py
```

Suite kiểm tra các nhóm chính:

| Nhóm | Scenario |
|---|---|
| Auth/JWT | brute force, JWT forgery, JWT replay, credential stuffing |
| Zero Trust | lateral movement, SVID/cross-cloud policy, privilege escalation |
| Fraud/Core | fraud gate bypass, high velocity, account manipulation |
| AppSec | SQL injection, command injection, data staging |
| Runtime | port scan, cryptomining, container escape, impair defenses |
| Response | SOAR response validation |


## 10. Demo bằng Web UI

Web Portal là màn hình chính để demo cho người xem. Không bắt buộc thao tác bằng CLI.

### 10.1 Mở UI và đăng nhập

Sau khi đã chạy port-forward ở mục 5, mở:

```text
http://127.0.0.1:8080
```

Web portal dùng **OIDC Authorization Code + PKCE (S256)** — không nhập username/password trực tiếp vào portal. Bấm nút **"Đăng nhập qua Keycloak"**, trình duyệt chuyển sang trang đăng nhập Keycloak (phục vụ tại `/kc/` qua web portal — cùng port 8080), đăng nhập tại đó, sau đó tự redirect về dashboard.

> **Không cần** port-forward Keycloak riêng. Web portal tự proxy Keycloak qua `/kc/` — chỉ cần port 8080 là đủ.

Tài khoản có sẵn:

| User | Password | Roles | Tài khoản ngân hàng | Mục đích |
|---|---|---|---|---|
| `demoadmin` | `DemoAdmin2026!` | financial-read, financial-write, security-analyst, security-admin | `ACC-9LVGYX` (10M VND) | **Full quyền — dùng cho test/demo** |
| `testuser01` | `Test1234!` | financial-read, financial-write | `ACC-1001` | User nghiệp vụ bình thường |
| `testuser02` | `Test1234!` | financial-read, financial-write | `ACC-PVNP61` (10M VND) | User nghiệp vụ thứ 2 |
| `merchant01` | `Merchant1234!` | financial-read | `ACC-2001` | Chỉ đọc, demo thiếu quyền ghi |
| `analyst01` | `Analyst1234!` | security-analyst | — (không cần) | Phân tích bảo mật, không có quyền tài chính |

### 10.2 Demo giao dịch bình thường

Đăng nhập bằng `demoadmin` (hoặc `testuser01`), sau đó:

1. Vào **Dashboard**: kiểm tra số dư account hiện tại.
2. Vào **Chuyển tiền**.
3. Nhập:
   - From: account của user đang đăng nhập (hiển thị trên dashboard).
   - To: `ACC-2001`.
   - Amount: `100000`.
   - Currency: `VND`.
4. Bấm xác nhận.
5. Kết quả đúng:
   - UI trả `status=completed`.
   - Có `trace_id`.
   - Các bước kiểm soát: JWT → OPA/Envoy → Fraud → HMAC → mTLS → Account → Ledger.

Sau đó vào **Logs** hoặc Grafana để tìm `trace_id` vừa nhận.

### 10.3 Demo kịch bản bảo mật trên UI

Vào **Kịch bản**. Các nút trên trang này gọi `/api/scenarios/{scenario_id}/run` từ Web Portal, nên người demo không cần tự gõ curl.

Nên chạy theo thứ tự sau:

| Thứ tự | Kịch bản UI | Điều cần nói khi demo | Kỳ vọng |
|---:|---|---|---|
| 1 | `Không có JWT` | API không chấp nhận request thiếu bearer token | 401/403 |
| 2 | `JWT giả mạo` | API Gateway verify JWKS, chữ ký sai bị reject | 401 |
| 3 | `Fraud Gate Block` | Fraud score cao nên Payment không gọi Core Banking | 403, `gate=blocked, score=85` |
| 4 | `High Velocity` | Redis velocity làm score tăng theo số lần chuyển | score tăng |
| 5 | `Brute Force Login (inject)` | Inject log cho AI Analyzer phân tích | malicious/high, pending alert |
| 6 | `Port Scan (inject)` | AI gợi ý playbook `block_source_ip` | pending alert |
| 7 | `Credential Stuffing (inject)` | AI nhận diện nhiều username/password | `revoke_user_sessions` |

Sau mỗi kịch bản inject high/critical, bấm link **AI Alerts** để sang trang duyệt.

### 10.4 Demo HITL: approve hoặc dismiss

Vào **AI Alerts**:

- Tab `Chờ duyệt`: các alert mới tạo từ trang Kịch bản.
- Bấm `Dismiss`: demo an toàn, không tác động Kubernetes.
- Bấm `Approve -> SOAR`: SOAR thực thi playbook thật.

Nếu approve, kiểm tra case:

```bash
curl -s http://127.0.0.1:8091/cases | python3 -m json.tool
```

Rollback nếu playbook hỗ trợ:

```bash
CASE_ID=<case_id>
curl -s -X POST "http://127.0.0.1:8091/cases/${CASE_ID}/rollback" | python3 -m json.tool
```

### 10.5 Kịch bản demo hoàn chỉnh trong 7 phút

```text
1. Mở Web Portal → bấm "Đăng nhập qua Keycloak" → login demoadmin / DemoAdmin2026!
2. Dashboard: giới thiệu account và balance (demoadmin có đủ 4 roles hiển thị).
3. Chuyển tiền 100000 VND: chứng minh flow nghiệp vụ completed.
4. Copy trace_id, mở Logs/Grafana: chứng minh observability xuyên cloud.
5. Sang Kịch bản → chạy JWT giả mạo: chứng minh authentication fail-closed.
6. Chạy Fraud Gate Block: chứng minh fraud control tầng payment-service.
7. Chạy Port Scan inject: AI tạo pending alert.
8. Sang AI Alerts (demoadmin có security-admin nên thấy approve/dismiss).
9. Dismiss để demo an toàn, hoặc approve để SOAR chạy playbook thật.
10. Nếu approve → kiểm tra SOAR cases → rollback.
```

### 10.6 Demo tấn công trực tiếp qua CLI

Các lệnh tấn công thủ công bổ sung — dùng khi cần chứng minh sâu hơn ngoài UI:

**Lấy token demoadmin (dùng cho CLI — qua `/kc/` proxy, chỉ cần port 8080):**

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/kc/realms/ztlab/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=web-portal&username=demoadmin&password=DemoAdmin2026!' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
```

**A1 — Không có JWT (lớp OPA/Envoy):**

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:18080/payments \
  -H 'Content-Type: application/json' \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000}'
# Kỳ vọng: 401 hoặc 403
```

**A2 — JWT giả mạo (chữ ký sai):**

```bash
FAKE='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZXIiLCJleHAiOjk5OTk5OTk5OTl9.INVALID'
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:18080/payments \
  -H "Authorization: Bearer $FAKE" \
  -H 'Content-Type: application/json' \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000}'
# Kỳ vọng: 401
```

**A3 — Fraud gate block (số tiền lớn + kênh tor):**

```bash
curl -s -X POST http://127.0.0.1:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":500000000,"currency":"VND","channel":"tor","country":"RU"}' \
  | python3 -m json.tool
# Kỳ vọng: 403
# {"detail":{"reason":"fraud gate blocked","fraud":{"score":85,"gate":"blocked","reason":["critical_amount","risky_channel","unusual_country"]}}}
```

**A4 — Bypass Core Banking trực tiếp (HMAC giả):**

```bash
nohup kubectl --context ctx-openstack -n financial port-forward svc/core-banking 19184:8080 \
  --address=127.0.0.1 >/tmp/pf-core.log 2>&1 &
sleep 2

curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:19184/transactions/execute \
  -H 'Content-Type: application/json' \
  -H 'X-Fraud-Gate: passed' \
  -H 'X-Fraud-Score: 1' \
  -H "X-Fraud-Timestamp: $(date +%s)" \
  -H 'X-Fraud-Gate-Signature: deadbeef_forged_signature' \
  -d '{"from_account":"ACC-1001","to_account":"ACC-9999","amount":999999999,"currency":"VND","trace_id":"bypass-test"}'
# Kỳ vọng: 403 — timestamp hợp lệ nhưng HMAC sai → fraud_signature_valid: false

pkill -f 'kubectl --context ctx-openstack.*core-banking.*19184' || true
```

**A5 — High velocity (10 giao dịch nhanh, đẩy fraud score):**

```bash
for i in $(seq 1 10); do
  echo -n "req $i: "
  curl -s -X POST http://127.0.0.1:18080/payments \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000,"currency":"VND"}' \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); f=d.get("detail",{}).get("fraud",d.get("fraud",{})); print(f"score={f.get(\"score\",\"?\")} gate={f.get(\"gate\",\"?\")}")'
done
```

**A6 — SQL Injection payload:**

```bash
curl -s -X POST http://127.0.0.1:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"from_account":"1'"'"' OR '"'"'1'"'"'='"'"'1","to_account":"ACC-2001","amount":100,"currency":"VND"}' \
  | python3 -m json.tool
# Kỳ vọng: 422 Unprocessable Entity (Pydantic validation)
```

**A7 — Inject brute force log cho AI Analyzer:**

```bash
curl -s -X POST http://127.0.0.1:8090/analyze \
  -H 'Content-Type: application/json' \
  -d "{
    \"source\": \"manual-attack-demo\",
    \"logs\": [{
      \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"message\": \"jwt_verification_failed reason=invalid_jwt attempt=20 username=demoadmin source_ip=10.9.8.55 brute_force_detected within_30s\",
      \"labels\": {\"namespace\": \"financial\", \"app\": \"api-gateway\", \"job\": \"kubernetes-pods\", \"cloud\": \"aws\"}
    }]
  }" | python3 -m json.tool
# Kỳ vọng: verdict=malicious, attack_type=brute_force, severity=high
```

**A8 — Xem và duyệt pending alert (cần demoadmin):**

```bash
# Xem alert
curl -s 'http://127.0.0.1:8090/pending?status=pending' | python3 -m json.tool

# Lấy alert_id và dismiss an toàn
ALERT_ID=$(curl -s 'http://127.0.0.1:8090/pending?status=pending' \
  | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a[0]["alert_id"] if a else "")')

curl -s -X POST "http://127.0.0.1:8090/pending/${ALERT_ID}/dismiss" \
  -H 'Content-Type: application/json' \
  -d '{"note":"manual demo - no real incident"}' | python3 -m json.tool
```

### 10.7 Khi nào dùng CLI thay UI

Dùng CLI khi cần chứng minh sâu hơn:

- Direct Core Banking bypass với signature giả.
- Full `tests/scenario_00_full_suite.py`.
- Kiểm log Loki/Grafana bằng LogQL.
- Kiểm pod/rollout/network policy bằng `kubectl`.

## 11. Đọc log và dashboard

### 11.1 Truy cập Grafana

```
URL:      http://127.0.0.1:3001
Username: admin
Password: ZTALab2026!
```

> **Lưu ý port**: Port 3000 và 3100 đang bị Docker PLG stack chiếm. K8s Grafana dùng 3001, K8s Loki dùng 3101.

### 11.2 4 Dashboard có sẵn

Vào **Dashboards** trong sidebar:

| Dashboard | Nội dung chính |
|---|---|
| **ZTLab Security Overview** | Tổng quan sự kiện bảo mật theo thời gian, fraud alert count |
| **OPA Decision Log** | Quyết định allow/deny của OPA theo từng request, trace_id |
| **Envoy Access Logs** | HTTP traffic qua sidecar proxy: method, path, status, latency |
| **ZTLab AI SIEM SOAR** | Alert từ AI Analyzer, SOAR HITL actions, threat intel |

### 11.3 Xem log thô qua Explore (LogQL)

Vào **Explore** → datasource **Loki** → nhập query:

#### OPA — quyết định phân quyền
```logql
{app="opa", namespace="financial"}
```
Chỉ lấy decision log có cấu trúc JSON (`decision_id`, `input`, `result.allow`):
```logql
{job="opa-decisions"}
```

#### Keycloak — sự kiện xác thực
```logql
{app="keycloak"}
```
Lọc theo loại event:
```logql
{app="keycloak"} |~ "LOGIN|LOGOUT|TOKEN_ISSUED|LOGIN_ERROR|REFRESH_TOKEN"
```

#### Redis
```logql
{app="redis", namespace="financial"}
```
> Redis log level mặc định là `notice` — chỉ ghi startup, shutdown, RDB/AOF save. Bình thường rất thưa.
> Để xem fraud velocity tracking theo account, dùng **Redis Velocity UI trong Web Portal** (xem mục 11.6).
> Để debug ở cấp lệnh:
> ```bash
> # Stream stdout log
> kubectl --context ctx-aws -n financial logs deployment/redis -f
>
> # Xem tất cả commands đang chạy (ZADD, ZCARD của fraud detection...)
> kubectl --context ctx-aws -n financial exec deployment/redis -- redis-cli MONITOR
> ```

#### Prometheus (container log, không phải metrics)
```logql
{app="prometheus", namespace="monitoring"}
```

#### Envoy sidecar — HTTP access log có trace_id
```logql
{job="envoy-access"} | json | namespace="financial"
```
Lọc theo service cụ thể:
```logql
{job="envoy-access"} | json | upstream=~".*core-banking.*"
```

#### Lọc log theo cloud (cross-cloud)
```logql
# Chỉ logs từ OpenStack cluster
{namespace="financial"} | json | cloud="openstack"

# Chỉ logs từ AWS cluster
{namespace="financial"} | json | cloud="aws"
```

#### Tìm log theo trace_id xuyên service
```logql
{namespace="financial"} |= "<trace_id>"
```

### 11.4 Luồng đi của log

```
┌──────────────────── AWS cluster ──────────────────────────────┐
│  Pods (stdout/stderr)                                          │
│    │ /var/log/pods/ (hostPath mount)                          │
│    ▼                                                           │
│  Promtail DaemonSet (cloud=aws)                                │
│    ├── job: kubernetes-pods  → tất cả pod logs                 │
│    ├── job: envoy-access     → /var/log/envoy/*.log (JSON)     │
│    └── job: opa-decisions    → /var/log/opa/*.log (JSON)       │
│    │ HTTP POST /loki/api/v1/push                               │
│    ▼                                                           │
│  Loki :3100 ◄── AI Analyzer (direct push, job=ai-analyzer)    │
│               ◄── SOAR Engine (direct push, job=soar-engine)  │
│    │                                                           │
│    ▼                                                           │
│  Grafana :3000 (port-forward → 3001)                          │
│    ├── datasource: Loki (in-cluster http://loki:3100)          │
│    └── datasource: Prometheus                                  │
└────────────────────────────────────────────────────────────────┘
              ▲
┌──────────────── OpenStack cluster ────────────────────────────┐
│  Pods (core-banking, opa, account-service, envoy...)           │
│    │ /var/log/pods/                                            │
│    ▼                                                           │
│  Promtail DaemonSet (cloud=openstack)                          │
│    │ HTTP POST /loki/api/v1/push                               │
│    ▼                                                           │
│  socat relay :31100 (AWS worker, systemd loki-relay.service)   │
│    └──► Loki ClusterIP 10.43.186.251:3100 (AWS)               │
└────────────────────────────────────────────────────────────────┘
```

**Phân biệt log nguồn**: Dùng label `cloud=aws` hoặc `cloud=openstack` trong Grafana Explore để tách log theo cluster.

### 11.5 Loki query nhanh từ terminal

```bash
# Kiểm tra cloud labels đã có
curl -s 'http://127.0.0.1:3101/loki/api/v1/label/cloud/values'

# Fraud events gần nhất
curl -G 'http://127.0.0.1:3101/loki/api/v1/query' \
  --data-urlencode 'query={namespace="financial"} |= "fraud_gate_bypass"' \
  | python3 -m json.tool

# Tất cả log từ OpenStack 5 phút qua
curl -G 'http://127.0.0.1:3101/loki/api/v1/query_range' \
  --data-urlencode 'query={cloud="openstack"}' \
  --data-urlencode "start=$(( $(date +%s) - 300 ))000000000" \
  --data-urlencode "end=$(date +%s)000000000" \
  --data-urlencode 'limit=20' \
  | python3 -m json.tool
```

### 11.6 Redis Velocity UI trong Web Portal

Trang **Logs** (`http://127.0.0.1:8080/logs`) có panel **"Redis — Fraud Velocity Tracking"** ở đầu trang, hiển thị trạng thái velocity theo từng account đang hoạt động, tự refresh mỗi 15 giây.

| Cột | Ý nghĩa |
|---|---|
| **Account** | Mã tài khoản nguồn |
| **Tx / 60s** | Số giao dịch trong cửa sổ trượt 60 giây hiện tại |
| **Tải** | Progress bar — so sánh với ngưỡng (`soft_limit × 3 = 30`) |
| **Rủi ro** | NORMAL / LOW / ELEVATED / HIGH |
| **TTL Redis** | Số giây trước khi key tự xóa khỏi Redis |

**Quy tắc tính rủi ro:**

| Mức | Tx / 60s | Cộng fraud score | Badge |
|---|---|---|---|
| NORMAL | ≤ 5 | +0 | xanh |
| LOW | 6–10 | +10 | xanh đậm |
| ELEVATED | 11–30 | +25 | vàng |
| HIGH | > 30 | +40 | đỏ |

> Key Redis có format `fraud:velocity:{account_id}` (ZSET timestamp), TTL = 120s. Panel trống khi không có giao dịch nào trong 120s gần nhất — đây là bình thường.

**Kiểm tra velocity API trực tiếp:**

```bash
# Gọi fraud-detection debug endpoint (trong cluster)
kubectl --context ctx-aws -n financial exec deployment/fraud-detection -- \
  python3 -c "
import urllib.request, json
r = urllib.request.urlopen('http://127.0.0.1:8080/debug/velocity', timeout=5)
print(json.dumps(json.loads(r.read()), indent=2))
"

# Gọi qua web portal (cần session cookie từ trình duyệt)
# GET http://127.0.0.1:8080/api/velocity
```

**Tạo traffic để thấy velocity tăng (demo):**

Chạy scenario `high_velocity` trong Web UI → Scenarios, hoặc gửi nhiều payment nhanh liên tiếp. Sau 6 tx trong 60s sẽ thấy mức LOW xuất hiện, > 10 tx sẽ chuyển ELEVATED và fraud score tự động tăng trong response.

## 12. Troubleshooting

### 12.1 `ctx-aws` TLS handshake timeout hoặc SSH banner timeout

1. Kiểm tra bastion từ Terraform và inventory:

```bash
terraform -chdir=terraform/aws output aws_bastion_pip
rg -n 'aws_bastion|ansible_host' ansible/inventory/hosts.yml
```

2. Kiểm tra bastion login:

```bash
AWS_BASTION=$(terraform -chdir=terraform/aws output -raw aws_bastion_pip)
timeout 15 ssh -i ~/.ssh/zta-siem-soar-key -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no ubuntu@$AWS_BASTION 'hostname; uptime'
```

3. Kiểm tra từ bastion vào master:

```bash
timeout 20 ssh -i ~/.ssh/zta-siem-soar-key -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=no ubuntu@$AWS_BASTION \
  'for p in 22 6443; do timeout 5 bash -lc "</dev/tcp/10.10.1.10/$p" >/dev/null 2>&1 && echo 10.10.1.10:$p open || echo 10.10.1.10:$p blocked; done'
```

4. Nếu port open nhưng SSH banner/API TLS vẫn timeout, master AWS có thể đang treo sâu. Cần restart instance `aws_k3s_master` hoặc kiểm tra console cloud trước khi chạy test tiếp.

### 12.2 Port-forward bị kẹt

```bash
pkill -f 'kubectl.*port-forward' || true
ss -lntp | grep -E ':8080|:18080|:3001|:3101|:8090|:8091'
```

### 12.3 Loki thiếu raw demo stream

```bash
LOKI_URL=http://127.0.0.1:3101 bash scripts/run-demo.sh --traffic-only
bash scripts/health-check.sh
```

### 12.4 SPIRE OpenStack crash sau restart

```bash
kubectl --context ctx-openstack -n spire get pods
kubectl --context ctx-openstack -n spire logs daemonset/spire-agent --tail=50
```

Nếu join token hết hạn, tạo token mới từ SPIRE server AWS, patch DaemonSet OpenStack, rồi restart `core-banking` để Envoy lấy SVID mới.

## 13. Tắt/mở lại hạ tầng tạm thời để tiết kiệm phí

Trạng thái đã tắt tạm thời ngày 2026-06-13:

- AWS EC2: đã chạy `stop-instances` cho 7 instance trong Terraform state.
- OpenStack: các VM lab `os-gateway`, `os-identity`, `os-k3s-master`, `os-k3s-worker-1`, `os-k3s-worker-2` đang `SHUTOFF`. `test-vm` cũng đang `SHUTOFF`.

AWS instance cần bật lại:

| Terraform key | Instance ID | IP | Vai trò |
|---|---|---:|---|
| `aws_bastion` | `i-06d2382ad780bda8c` | `10.10.4.10` | SSH bastion |
| `aws_gateway` | `i-059694c4d1affdb2f` | `10.10.0.10` | WireGuard/NAT gateway |
| `aws_k3s_master` | `i-0293f9568b3c0762b` | `10.10.1.10` | K3s control plane |
| `aws_k3s_worker_1` | `i-00001195627942100` | `10.10.1.11` | K3s worker |
| `aws_k3s_worker_2` | `i-08f1cf418461cca62` | `10.10.1.12` | K3s worker |
| `aws_security` | `i-0b0ec5f99d896bf65` | `10.10.1.20` | Security services |
| `aws_siem` | `i-0de79b221be7358cf` | `10.10.2.10` | SIEM |

Kiểm tra trạng thái AWS:

```bash
/snap/bin/aws ec2 describe-instances --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-059694c4d1affdb2f \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62 \
    i-0b0ec5f99d896bf65 \
    i-0de79b221be7358cf \
  --query 'Reservations[].Instances[].{Name:Tags[?Key==`Name`]|[0].Value,InstanceId:InstanceId,State:State.Name,PrivateIp:PrivateIpAddress,PublicIp:PublicIpAddress}' \
  --output table
```

Bật lại AWS ngày mai:

```bash
/snap/bin/aws ec2 start-instances --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-059694c4d1affdb2f \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62 \
    i-0b0ec5f99d896bf65 \
    i-0de79b221be7358cf

/snap/bin/aws ec2 wait instance-running --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-059694c4d1affdb2f \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62 \
    i-0b0ec5f99d896bf65 \
    i-0de79b221be7358cf
```

Bật lại OpenStack:

```bash
source /etc/kolla/admin-openrc.sh
openstack server start os-gateway os-identity os-k3s-master os-k3s-worker-1 os-k3s-worker-2
openstack server list --long
```

Sau khi bật lại, đợi 2-3 phút cho K3s và service nền lên lại rồi chạy:

```bash
bash scripts/k8s-tunnel.sh up all
bash scripts/health-check.sh
```

Nếu `ctx-openstack` lỗi SPIRE sau restart, xử lý theo mục 12.4.

Để tắt lại lần sau:

```bash
/snap/bin/aws ec2 stop-instances --region ap-southeast-1 \
  --instance-ids \
    i-06d2382ad780bda8c \
    i-059694c4d1affdb2f \
    i-0293f9568b3c0762b \
    i-00001195627942100 \
    i-08f1cf418461cca62 \
    i-0b0ec5f99d896bf65 \
    i-0de79b221be7358cf

source /etc/kolla/admin-openrc.sh
openstack server stop os-gateway os-identity os-k3s-master os-k3s-worker-1 os-k3s-worker-2
```

## 14. Cleanup sau test

```bash
pkill -f 'kubectl.*port-forward' || true
bash scripts/k8s-tunnel.sh status
bash scripts/health-check.sh
```
