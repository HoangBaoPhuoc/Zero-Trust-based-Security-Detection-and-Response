# Script Trình Bày Demo — ZTLab Zero Trust Security
## Lời nói theo từng bước thực thi kịch bản

> Dùng khi demo trực tiếp. Mỗi phần **[SHOW]** = mở tab terminal/trình duyệt tương ứng.  
> Mỗi phần **[SAY]** = đọc hoặc paraphrase — không cần đọc nguyên từng chữ.  
> Phần `> ` in nghiêng là giải thích output terminal xuất hiện trên màn hình.

---

## Trước khi bắt đầu — Checklist

```bash
# Kiểm tra services đang chạy
bash scripts/run-demo.sh --restore          # restore mọi thứ về trạng thái bình thường
curl -s http://localhost:18080/health        # API Gateway phải trả về JSON có jwks_keys_loaded > 0
curl -s http://localhost:8091/health         # SOAR phải trả về {"status":"ok","dry_run":false}
curl -s http://localhost:13100/ready         # Loki phải trả "ready"
```

---

## Phần 0 — Giới thiệu hệ thống (2–3 phút)

**[SAY]**

> "Hệ thống chúng tôi triển khai là một nền tảng ngân hàng microservice chạy trên 2 cloud song song: AWS Singapore và OpenStack nội bộ. Điểm đặc biệt là toàn bộ communication giữa các service đều được bảo vệ theo mô hình Zero Trust — không service nào được tin tưởng mặc định dù ở trong cùng cluster.

> Có 4 lớp bảo vệ xếp chồng:

> Lớp 1 — Keycloak xác thực người dùng và cấp JWT. Token này sống tối đa 5 phút, buộc client phải refresh liên tục.

> Lớp 2 — SPIRE cấp SVID, tức là certificate chứa SPIFFE ID cho từng workload. Certificate này được ký bởi CA nội bộ của chúng tôi, sống 1 giờ, tự gia hạn, không có password nào trong code hay config.

> Lớp 3 — Envoy sidecar chạy song song với mỗi service. Mọi request vào pod đều phải đi qua Envoy inbound tại port 15006, Envoy yêu cầu mTLS — caller phải trình cert SPIRE, không có cert thì không nói chuyện được.

> Lớp 4 — OPA policy engine. Envoy gửi mỗi request lên OPA qua gRPC ext_authz. OPA quyết định allow hay deny dựa trên SVID, JWT role, path, và fraud gate header. Default là deny — không có rule tường minh nào match thì request bị chặn."

**[SHOW]** Sơ đồ topology (BAOCAO_DEMO.md Section I) hoặc Grafana dashboard `ZTA Security Overview`.

---

## Phần 1 — Normal Traffic Baseline (1 phút)

**[SHOW]** Terminal 1 — chạy:

```bash
bash scripts/run-demo.sh --traffic-only
```

**[SAY khi script chạy]**

> "Đây là traffic bình thường. Script lấy JWT từ Keycloak cho user `testuser01`, rồi gọi `/payments` 4 lần với số tiền khác nhau."

**[Output trên màn hình]**

```
[NORMAL] payment ACC-1001→ACC-2001 50000VND  →  completed fraud_score=12 gate=passed tx=TXN-a3f7...
[NORMAL] payment ACC-1001→ACC-2001 2500000VND →  completed fraud_score=23 gate=passed tx=TXN-b9c2...
[NORMAL] payment ACC-1001→ACC-2001 15000000VND→  completed fraud_score=45 gate=passed tx=TXN-d1e8...
[NORMAL] payment ACC-2001→ACC-1001 100000VND  →  completed fraud_score=8  gate=passed tx=TXN-f2a4...
```

**[SAY giải thích từng field]**

> "`fraud_score` do fraud-detection service tính — điểm này dựa trên số tiền, tần suất giao dịch trong 15 phút (velocity counter lưu ở Redis), và channel. Giao dịch nhỏ tần suất thấp thì score thấp.

> `gate=passed` nghĩa là OPA đã check header `x-fraud-gate: passed` và `x-fraud-score < 75` — đây là điều kiện bắt buộc để lệnh gọi `/transactions/execute` sang core-banking được phép.

> `tx=TXN-...` là transaction ID từ core-banking chạy trên OpenStack — qua WireGuard tunnel 10.200.0.1 → 10.200.0.2."

---

## Phần 2 — KB1: Brute Force Login (T1110.001)

### Bước 2.1 — Chạy kịch bản

**[SHOW]** Terminal 1 — chạy:

```bash
bash scripts/run-demo.sh --kb1
```

**[SAY khi thấy dòng "Push 20 log vào Loki"]**

> "Script push 20 log vào Loki với label `job=envoy-access`, `response_code=401`, `source_ip=10.10.0.99`. Đây mô phỏng kẻ tấn công gửi 20 request login sai liên tiếp. Trong thực tế, log này đến từ Envoy access log của api-gateway — Promtail thu thập từ `/var/log/envoy/access.log` trên node và extract `response_code` thành stream label."

**[Output trên màn hình]**

```
  ▶ Push 20 log vào Loki (job=envoy-access, response_code=401 — stream label)...
  ▶ Grafana query: {job=envoy-access} | json | response_code=`401` [1m]
OK — 20 logs pushed (response_code=401)

  ▶ Đợi Grafana alert fire + SOAR xử lý (90s max)...
  ▶ Grafana eval mỗi 1 phút — có thể chờ tới 60s trước khi alert fire
..............
```

**[SAY khi thấy dấu chấm chờ]**

> "Grafana đang đợi chu kỳ evaluate tiếp theo. Alert rule KB1 cấu hình `interval: 1m` — tức là Grafana chạy query mỗi 1 phút. Query là `sum by (source_ip) (count_over_time({job="envoy-access"} | json | response_code=401 [1m]))` — đếm số 401 trong 1 phút nhóm theo source IP. Ngưỡng là 10."

### Bước 2.2 — SOAR nhận alert

**[Output khi SOAR tạo case]**

```
FOUND_HITL
  case_id  : case-20260628-kb1-a3f7
  status   : pending_approval
  playbook : revoke_user_sessions | severity: high
  context  : ctx-aws | workload: api-gateway
  >>> Admin phải chọn hành động tại: http://localhost:18081/security
[ OK ] KB1 PASS — SOAR tạo case brute_force | playbook đề xuất: revoke_user_sessions
```

**[SAY]**

> "SOAR tạo case với status `pending_approval` — tức là đây là tấn công severity `high` nên phải có người duyệt, không tự động thực thi. SOAR đã gửi email đến `voha2005@gmail.com` với log evidence và 2 nút: Approve hoặc Deny.

> Playbook đề xuất là `revoke_user_sessions` — thu hồi tất cả session của user bị brute force trong Keycloak bằng cách gọi Keycloak Admin API.

> `context: ctx-aws` — SOAR sẽ thực thi trên cluster AWS. `workload: api-gateway` — target là api-gateway vì đây là điểm nhận request login."

**[SHOW]** Email vừa nhận được / Web portal `http://localhost:18081/security`.

**[SAY]**

> "Trong email có phần log evidence — SOAR query Loki với `{namespace="financial"}` tìm các log chứa từ khóa liên quan đến brute force, lấy tối đa 10 dòng để admin có đủ context trước khi quyết định."

### Bước 2.3 — Admin Approve (demo trực tiếp)

**[SHOW]** Mở link approve từ email hoặc web portal, click Approve.

**[SAY]**

> "Khi admin approve, SOAR chạy 4 phase của playbook:
> Phase 1 — Collect: SOAR lấy thêm evidence từ Loki.
> Phase 2 — Contain: gọi Keycloak Admin API thu hồi session.
> Phase 3 — Eradicate: patch NetworkPolicy hoặc rate limit.
> Phase 4 — Recover: log lại, update case status thành `executed`."

---

## Phần 3 — KB2: Lateral Movement — Invalid SVID (T1021.007)

### Bước 3.1 — Giải thích trước khi chạy

**[SAY]**

> "Kịch bản này mô phỏng một service cố gắng gọi sang service khác mà không có SVID hợp lệ trong trust domain của chúng tôi. Trong mô hình Zero Trust, mọi service-to-service call đều phải có mTLS với cert do SPIRE cấp. Nếu cert không thuộc `spiffe://ztlab.local/` thì OPA deny ngay.

> Để thấy rõ cơ chế thật, có thể chạy kịch bản thực tế thay vì push log giả."

**[SHOW]** Terminal 2 — chạy kịch bản thực:

```bash
bash tests/scenario_03_lateral_movement.sh
```

**[Output]**

```
[scenario_03_lateral_movement] resolving pods...
[scenario_03_lateral_movement] notification-service pod: notification-service-7d4b9c-xxxxx
[scenario_03_lateral_movement] payment-service pod:      payment-service-6f8d2a-yyyyy
[scenario_03_lateral_movement] checking API Gateway health...
[scenario_03_lateral_movement] executing lateral movement from notification-service via Envoy outbound (15001)...
[scenario_03_lateral_movement] Envoy response: HTTP 403
```

**[SAY khi thấy "executing lateral movement"]**

> "Script dùng `kubectl exec` để chui vào bên trong container `notification-service`, rồi từ đó gọi `http://127.0.0.1:15001/payments/internal/execute` — đây là Envoy outbound proxy chạy trong cùng pod, không phải gọi thẳng ra ngoài.

> Tại sao dùng `127.0.0.1:15001`? Vì Envoy outbound là thứ gắn SPIRE SVID thật của notification-service vào kết nối mTLS. Nếu gọi thẳng bằng curl ra payment-service sẽ không có cert, kết nối bị từ chối ngay ở tầng TCP. Bằng cách gọi qua Envoy outbound, chúng tôi mô phỏng đúng cách một service bị compromise cố dùng identity thật của nó để lateral move."

**[SAY khi thấy "Envoy response: HTTP 403"]**

> "OPA trả 403. Lý do: path `/payments/internal/execute` chỉ được phép với SVID `spiffe://ztlab.local/aws/payment-service` tự gọi chính mình, hoặc từ `api-gateway`. `notification-service` không có quyền đó trong policy `zta_policy.rego`."

**[Output tiếp theo]**

```
[scenario_03_lateral_movement] Envoy evidence: response_code=403 path=/payments/internal/execute svid=spiffe://ztlab.local/aws/notification-service source_ip=127.0.0.1 upstream=127.0.0.1:8080 bytes_sent=0
[scenario_03_lateral_movement] OPA evidence:   time=2026-06-28T... path=/payments/internal/execute principal=spiffe://ztlab.local/aws/notification-service result=False
[scenario_03_lateral_movement] PASS: lateral movement blocked HTTP 403; SVID verified in Envoy + OPA logs (T1021.007)
```

**[SAY giải thích evidence]**

> "Quan trọng nhất là field `svid=spiffe://ztlab.local/aws/notification-service` trong Envoy log. Field này đến từ Envoy format string `%DOWNSTREAM_PEER_URI_SAN%` — Envoy tự đọc Subject Alternative Name từ TLS client certificate của caller. Không thể forge bằng HTTP header.

> OPA log cũng ghi lại `principal=spiffe://ztlab.local/aws/notification-service` — đây là input OPA nhận từ Envoy qua `include_peer_certificate: true` trong cấu hình ext_authz. `result=False` xác nhận OPA đã deny."

### Bước 3.2 — Grafana trigger và SOAR

**[SHOW]** Chạy demo script KB2:

```bash
bash scripts/run-demo.sh --kb2
```

**[SAY khi thấy dòng Push log]**

> "Script push 5 log OPA deny vào Loki với labels `opa_result=false`, `attack_scenario=lateral_movement`. Grafana query `{job="opa-decisions", opa_result="false", attack_scenario="lateral_movement"}` đếm trong 5 phút."

**[Output khi SOAR tạo case]**

```
FOUND_HITL
  case_id  : case-20260628-kb2-b9c1
  status   : pending_approval
  playbook : isolate_workload | severity: critical
  context  : ctx-aws | workload: payment-service
  >>> Admin phải chọn hành động tại: http://localhost:18081/security
```

**[SAY]**

> "Severity `critical` nên phải có người duyệt. Playbook `isolate_workload` sẽ scale deployment `payment-service` xuống 0 replica — dừng hoàn toàn service này. SOAR có quyền làm điều này vì RBAC `soar-financial-responder` trong file `k8s/rbac/soar-rbac.yaml` cấp quyền `patch deployments` trong namespace `financial`."

---

## Phần 4 — KB3: Fraud Gate Bypass (T1078.004)

### Bước 4.1 — Giải thích cơ chế

**[SAY trước khi chạy]**

> "Kịch bản này về fraud gate — cơ chế đặc biệt của hệ thống chúng tôi. Khi payment-service muốn gọi core-banking để thực thi lệnh chuyển tiền, OPA yêu cầu 2 điều kiện: có SVID hợp lệ, VÀ header `x-fraud-gate: passed` với `x-fraud-score` phải nhỏ hơn 75.

> Kẻ tấn công cố bỏ qua fraud detection bằng cách giả header này. Nhưng SVID thật từ payment-service mà gắn header fake thì OPA vẫn deny — vì fraud-detection service phải set header đó dựa trên tính toán thực, không ai tự set được."

**[SHOW]** Terminal — chạy kịch bản fraud gate bypass thực tế:

```bash
python3 tests/scenario_04_fraud_gate_bypass.py
```

**[Output]**

```
[scenario_04_fraud_gate_bypass] resolving pods...
[scenario_04_fraud_gate_bypass] api-gateway pod: api-gateway-8d7b9c-zzzzz
[scenario_04_fraud_gate_bypass] checking API Gateway health...
[scenario_04_fraud_gate_bypass] sending 500M VND via tor channel (expected: fraud score=75 → 403 block)...
[scenario_04_fraud_gate_bypass] response HTTP 403: {"error": "payment blocked", "reason": "fraud_score_too_high", "fraud_score": 75}
```

**[SAY]**

> "Giao dịch 500 triệu VND qua kênh `tor` — fraud-detection tính score = 75. Ngưỡng block là 70. Score 75 > 70 → payment-service không gọi tiếp sang core-banking mà trả 403 ngay. Không cần OPA can thiệp ở bước này vì fraud-detection đã chặn trước.

> Điểm quan trọng: nếu attacker cố tự set `x-fraud-gate: passed` và `x-fraud-score: 10` trong header rồi gọi thẳng payment-service nội bộ — OPA vẫn cho qua vì header đúng format. Nhưng OPA chặn ở chỗ khác: SVID của caller phải là `spiffe://ztlab.local/aws/payment-service`, không ai bên ngoài có SVID đó."

**[Output evidence]**

```
[scenario_04_fraud_gate_bypass] fraud-detection evidence: event=fraud_score_computed amount=500000000 fraud_score=75 verdict=block reason=high_amount_tor_channel
[scenario_04_fraud_gate_bypass] payment-service evidence: event=payment_blocked_fraud fraud_score=75 trace_id=TRC-... gate=blocked
[scenario_04_fraud_gate_bypass] Envoy evidence: response_code=403 path=/payments source_ip=... bytes_sent=89 response_time=23ms
[scenario_04_fraud_gate_bypass] PASS: fraud gate blocked HTTP 403; fraud_score=75 (>= block threshold 70) verified in fraud-detection + payment-service logs (T1078.004)
```

**[SAY giải thích fraud-detection evidence]**

> "Script đọc log trực tiếp từ pod fraud-detection tìm event `fraud_score_computed`. `reason=high_amount_tor_channel` — rule tính điểm trong fraud-detection service kết hợp amount > ngưỡng với channel rủi ro cao.

> `payment-service evidence` lấy từ log audit của payment-service — event `payment_blocked_fraud` xác nhận chính service này đã từ chối, không phải Envoy hay OPA.

> `Envoy evidence` — Envoy access log ghi lại cuối cùng: 403, 23ms response time."

### Bước 4.2 — Grafana và SOAR

**[SHOW]** Chạy KB3:

```bash
bash scripts/run-demo.sh --kb3
```

**[SAY khi thấy case SOAR]**

> "Lần này SOAR cũng đề xuất `isolate_workload` với `payment-service` — cùng playbook với lateral movement. Lý do: cả 2 loại tấn công đều nhắm vào payment-service và đều nghiêm trọng ở mức critical. SOAR map attack type sang playbook qua dictionary `PLAYBOOK_BY_ATTACK` trong `services/soar-engine/main.py`."

---

## Phần 5 — KB4: Data Exfiltration — Large Response (T1041)

### Bước 5.1 — Giải thích

**[SAY trước khi chạy]**

> "Kịch bản này phát hiện exfiltration qua response size bất thường. Core-banking trên OpenStack trả về response > 1MB — bình thường một API call không bao giờ trả nhiều data đến vậy. Grafana query Envoy access log tìm `bytes_sent > 1048576`."

**[SHOW]** Chạy KB4:

```bash
bash scripts/run-demo.sh --kb4
```

**[Output khi push log]**

```
  ▶ Push 5 log vào Loki (job=envoy-access + JSON bytes_sent=3100000 > 1048576)...
  ▶ Grafana query: {job=envoy-access} | json | bytes_sent > 1048576 [5m]
OK — 5 logs pushed (bytes_sent=3100000)
```

**[SAY]**

> "Script push log với `bytes_sent=3100000` — 3.1MB. Để query `bytes_sent > 1048576` hoạt động trong Grafana, field này phải là số trong JSON body, không phải string. Promtail extract qua pipeline stage `json: expressions: bytes_sent: bytes_sent`.

> Loki Logql: `{job="envoy-access"} | json | bytes_sent > 1048576` — pipe `| json` parse JSON body của log line, sau đó filter numeric field."

**[Output khi SOAR tạo case]**

```
  ▶ core-banking (OpenStack) trước: 1 replicas
FOUND_HITL
  case_id  : case-20260628-kb4-c7d3
  status   : pending_approval
  playbook : restrict_egress | severity: high
  context  : ctx-openstack | workload: core-banking
```

**[SAY]**

> "Đây là kịch bản cross-cloud. `context: ctx-openstack` — SOAR sẽ thực thi lệnh kubectl trên cluster OpenStack, không phải AWS. Target là `core-banking`.

> Playbook `restrict_egress` scale deployment core-banking xuống 0 replica trên OpenStack. SOAR có quyền này vì trong `ai-soar.yaml`, pod SOAR được mount kubeconfig của cả 2 cluster."

**[SHOW]** Sau khi admin approve, kiểm tra:

```bash
kubectl --context ctx-openstack get deploy core-banking -n financial
```

**[Output]**

```
NAME           READY   UP-TO-DATE   AVAILABLE   AGE
core-banking   0/0     0            0           26d
```

**[SAY]**

> "Core-banking đã scale xuống 0. Không còn pod nào chạy — mọi lệnh chuyển tiền mới đều không thể hoàn tất. Đây là biện pháp contain nhanh nhất khi nghi ngờ exfiltration từ core-banking."

---

## Phần 6 — Restore và Kiểm Tra SOAR Dashboard (1 phút)

**[SHOW]** Terminal:

```bash
bash scripts/run-demo.sh --restore
```

**[Output]**

```
  ▶ Restore payment-service deployment (replicas=1, xóa SOAR isolation)...
    payment-service deployment: OK
    payment-service svc selector: OK
  ▶ Restore api-gateway (replicas=1)...
    api-gateway: OK
  ▶ Restore core-banking trên OpenStack (replicas=1)...
    core-banking: OK
  ▶ Xóa soar-block NetworkPolicies tích lũy (AWS + OpenStack)...
    AWS: không có soar-block NP
    OpenStack: không có soar-block NP
[ OK ] Restore hoàn tất
```

**[SAY]**

> "Restore khôi phục tất cả service về trạng thái bình thường: scale lại deployment, xóa NetworkPolicy mà SOAR đã tạo, restore Service selector về đúng app label. Sau restore, hệ thống tiếp tục nhận traffic mới."

**[SHOW]** Grafana → `http://127.0.0.1:3000` → dashboard `ZTLab AI SIEM SOAR`.

**[SAY]**

> "Dashboard Grafana cho thấy toàn bộ alert đã fire, case status, và playbook đã thực thi. Datasource là Loki — tất cả log từ Envoy và OPA đều được Promtail push vào đây theo real-time."

**[SHOW]** SOAR API — cases summary:

```bash
curl -s http://localhost:8091/cases | python3 -c "
import json,sys
cases=json.load(sys.stdin)
for c in cases[-6:]:
    s=c.get('status','?')
    print(f'{s:18} {c.get(\"attack_type\",\"?\":25} → {c.get(\"playbook\",\"?\")}')
"
```

**[SAY]**

> "SOAR lưu tất cả case trong file `/data/cases.jsonl` — JSON Lines, mỗi dòng 1 case. Mỗi case có đủ thông tin: evidence, playbook, các step đã thực thi, timestamp, kết quả approve/deny."

---

## Phần 7 — Điểm Kỹ Thuật Nổi Bật (2 phút)

**[SAY — chọn 3–4 điểm tùy thời gian còn lại]**

### Về SPIRE SVID

> "SVID là X.509 certificate, không phải API key hay password. Nó được SPIRE Agent cấp dựa trên Kubernetes Service Account của pod — attestation xảy ra khi SPIRE Server gọi K8s API xác minh pod đang chạy đúng namespace và ServiceAccount. Không có human-in-the-loop, không có secret nào được distribute thủ công."

### Về OPA deny-by-default

> "Default rule trong `zta_policy.rego` là `default allow = false`. Nghĩa là nếu OPA crash hay timeout, Envoy sẽ từ chối request — vì cấu hình là `failure_mode_allow: false`. Không có degraded mode nào mà security bị bỏ qua."

### Về Grafana provisioning

> "Toàn bộ alert rules, datasource, và notification policy được load từ ConfigMap khi Grafana khởi động. Không có gì được config thủ công qua UI. File nằm ở `plg-stack/grafana/alerting/`. Điều này đảm bảo mọi thay đổi đều qua git."

### Về SOAR HITL

> "SOAR không tự động với severity high và critical — phải có admin approve. Email HITL chứa log evidence thật lấy từ Loki, không phải synthetic. Link approve/deny là HTTP GET đến SOAR API — admin click từ điện thoại cũng được."

### Về cross-cloud

> "Hai cluster AWS và OpenStack nối với nhau qua WireGuard tunnel 10.200.0.1 ↔ 10.200.0.2. Microservice trên AWS gọi core-banking trên OpenStack qua NodePort 30080, K3s routing đến pod qua tunnel. SOAR có kubeconfig của cả 2 cluster nên có thể thực thi playbook ở bất kỳ cloud nào."

---

## Phần 8 — Q&A Hints

**Câu hỏi: "Nếu SPIRE Server down thì sao?"**

> "SVID đã được cache trong SPIRE Agent memory. Trong 1 giờ (TTL mặc định), các service vẫn có SVID hợp lệ và hoạt động bình thường. Sau 1 giờ SVID hết hạn, Envoy sẽ không thể verify cert → connection refused. Đây là trade-off giữa availability và security."

**Câu hỏi: "OPA có bottleneck không?"**

> "OPA chạy in-process trong cùng pod với Envoy — không có network hop. Timeout cấu hình là 2 giây, nhưng thực tế dưới 5ms cho policy đơn giản. OPA là stateless nên scale horizontal được."

**Câu hỏi: "Tại sao dùng Loki thay vì Elasticsearch?"**

> "Loki không index full-text content — chỉ index labels. Điều này giảm đáng kể storage và memory. Đổi lại query phải filter qua label trước rồi mới parse JSON content. Cho workload log của chúng tôi với số lượng labels cố định, Loki phù hợp hơn."

**Câu hỏi: "Email HITL có bị miss không nếu attacker spam alert?"**

> "SOAR có dedup window 5 phút — cùng attack type + source IP + workload trong 5 phút chỉ tạo 1 case. Nên dù Grafana fire nhiều alert cho cùng 1 attack, admin chỉ nhận 1 email."

---

## Checklist cuối demo

- [ ] `bash scripts/run-demo.sh --restore` — restore tất cả service
- [ ] Verify `kubectl --context ctx-aws get deploy payment-service -n financial` → `1/1`
- [ ] Verify `kubectl --context ctx-openstack get deploy core-banking -n financial` → `1/1`
- [ ] Verify `curl -s http://localhost:8091/health | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])"`  → `ok`
