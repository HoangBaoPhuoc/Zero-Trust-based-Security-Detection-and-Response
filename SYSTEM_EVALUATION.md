# ĐÁNH GIÁ HỆ THỐNG
## So Sánh Mô Hình Zero Trust và Mô Hình Bảo Mật Truyền Thống

> **Môn học:** NT114.Q21.ANTT — Đồ án chuyên ngành An Toàn Thông Tin
> **Sinh viên:** Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)
> **Ngày đo lần đầu:** 28/06/2026 — **Đo lại toàn bộ:** 20/08/2026

---

## 0. Về lần đo lại này

Bản đo 28/06/2026 dùng số liệu tích luỹ **24 giờ** trên một lần deploy cụ thể. Giữa hai lần đo, hạ tầng đã bị `terraform destroy` và dựng lại từ số 0 nhiều lần (VM mới, cluster mới, dữ liệu Loki/SOAR mới hoàn toàn) — số liệu 24h cũ không còn phản ánh hệ thống hiện tại và không có cách nào tái tạo lại đúng con số đó (traffic đã mất). Thay vì giữ nguyên bảng cũ, toàn bộ số liệu trong tài liệu này được **đo lại trực tiếp** trên lần deploy mới nhất, bằng đúng bộ công cụ đã tạo ra bản gốc (`tests/collect_metrics.py`, `tests/perf_overhead.py`, `tests/grafana_kb*.sh`).

**Khác biệt về phương pháp cần lưu ý khi đọc số liệu bên dưới:**
- Số liệu ở đây là kết quả **1 lần chạy kịch bản** (vài chục phút), không phải tích luỹ 24 giờ như bản gốc — nên số đếm tuyệt đối (số request bị chặn, số quyết định OPA...) thấp hơn nhiều, điều này phản ánh đúng quy mô của lần đo, không phải hệ thống kém đi.
- Latency đo qua `perf_overhead.py` lần này chạy từ máy deployer qua 2 lớp SSH tunnel + `kubectl port-forward` tới cluster — baseline tuyệt đối (ms) vì vậy cao hơn hẳn so với bản gốc (có thể đo gần cluster hơn). **Độ chênh lệch (overhead delta) giữa baseline và full-auth trên cùng đường truyền** mới là số có thể so sánh được, con số ms tuyệt đối thì không.

**Phát hiện phụ trong quá trình dựng lại và đo lại** (đã sửa tận gốc trong code/script, không phải patch tay 1 lần — chi tiết xem lịch sử thay đổi các file liên quan):
1. `ansible/playbooks/baseline.yml` deadlock với `apt-get` của cloud-init trên node OpenStack mới boot (race condition, chỉ xảy ra khi dựng từ số 0).
2. `scripts/k8s-tunnel.sh` thiếu `UserKnownHostsFile=/dev/null` cho tunnel AWS → SSH từ chối kết nối sau mỗi lần redeploy do host key VM thay đổi nhưng IP giữ nguyên.
3. `k8s/plg-stack/ai-soar.yaml` (soar-engine) phụ thuộc 2 resource (`ConfigMap soar-main-patch`, `Secret soar-openstack-kubeconfig`) mà không script nào từng tạo ra — deploy treo vô thời hạn ở bước SOAR trên mọi lần dựng từ số 0.
4. `tests/grafana_kb2_fraud_gate.sh`, `grafana_kb5_access_denied.sh`, `tests/collect_metrics.py`, `tests/perf_overhead.py` lấy JWT test qua Keycloak client `web-portal` — client này đã được khoá `direct access grant` (đúng chủ đích, hardening theo Zero Trust — chỉ cho phép PKCE) nên toàn bộ 4 script lấy token đều fail âm thầm.

Việc các bug này chỉ lộ ra khi dựng lại từ số 0 — chứ không xuất hiện khi chỉnh sửa nhỏ trên cluster đang chạy — tự nó là một minh chứng cho lý do cần bài kiểm thử đo lại độc lập với môi trường, thay vì tin vào số liệu đo 1 lần rồi không xác minh lại.

---

## 1. Cơ Sở So Sánh

Mô hình bảo mật truyền thống (*perimeter-based security* hay còn gọi là mô hình "lâu đài và hào") đặt toàn bộ nỗ lực bảo vệ tại ranh giới mạng. Một khi traffic đã vượt qua tường lửa và vào trong mạng nội bộ, các service tin tưởng lẫn nhau mặc định. Mô hình này từng hiệu quả khi ứng dụng là một khối monolith chạy trong datacenter cô lập, nhưng trở nên mong manh khi hệ thống chuyển sang kiến trúc microservice phân tán trên nhiều cloud.

Hệ thống ZTLab được xây dựng theo nguyên tắc Zero Trust: *không tin tưởng bất kỳ thứ gì theo mặc định, xác minh tất cả mọi thứ liên tục*. Phần này so sánh trực tiếp hai mô hình trên cùng bộ kịch bản tấn công, sử dụng số liệu đo thực tế từ hệ thống (xem Mục 0 về phạm vi đo).

---

## 2. So Sánh Khả Năng Phòng Thủ

### 2.1. Kiểm Soát Truy Cập Giữa Các Service (East-West Traffic) — KB3 Lateral Movement

Trong mô hình truyền thống, các microservice giao tiếp với nhau qua mạng nội bộ mà không có xác thực danh tính — một service bị xâm phạm có thể gọi tự do đến bất kỳ service nào khác trong cùng cluster.

Trong ZTLab, mỗi service được SPIRE cấp SPIFFE SVID X.509; Istio sidecar (istio-proxy, PeerAuthentication STRICT) bắt buộc xác thực SVID, OPA (qua CUSTOM AuthorizationPolicy) kiểm tra quyền của service nguồn trước khi cho phép gọi. Kịch bản thật: `notification-service` (có SVID hợp lệ, mTLS thành công) cố gọi `POST /payments/internal/execute` của `payment-service` — endpoint nó không có quyền gọi.

> Kết quả đo (`tests/grafana_kb3_lateral_movement.sh`, 20/08/2026): **3/3 request bị OPA từ chối** (`opa_result=false`, `request_path=/payments/internal/execute`) → SOAR tạo case `lateral_movement` (severity=critical, playbook `isolate_workload`) trong vòng 1 phút, email HITL gửi thành công tới admin.

| Tiêu chí | Mô hình truyền thống | Mô hình Zero Trust (ZTLab) |
|---|---|---|
| Danh tính service | Không có / dùng IP | SPIFFE SVID X.509, rotate mỗi 1 giờ |
| Xác thực kết nối nội bộ | Không (tin tưởng mặc định) | mTLS bắt buộc |
| Phân quyền service-to-service | Không có | OPA RBAC, kiểm tra mỗi request |
| Lateral movement thử trong bài test | Không phát hiện được | **3/3 bị chặn và ghi log**, SOAR case tạo tự động |

### 2.2. Kiểm Soát Truy Cập Người Dùng (North-South Traffic) — KB5 RBAC Violation

ZTLab dùng OPA làm điểm quyết định phân quyền tập trung — JWT decode, claims role kiểm tra theo `zta_policy.rego` *trước khi* request đến application. Kịch bản thật: `merchant01` (role `financial-read` only) thử `POST /payments` 6 lần với các số tiền khác nhau.

> Kết quả đo (`tests/grafana_kb5_access_denied.sh`, 20/08/2026): **6/6 request bị OPA từ chối** (403), mỗi quyết định có `decision_id` riêng trong Loki `{job="opa-decisions"}`. Trong cửa sổ 30 phút quanh lần chạy kịch bản, Loki ghi nhận **2.167 quyết định OPA tổng cộng**, trong đó **129 quyết định bị từ chối** (`opa_result=false`) trên toàn bộ endpoint tài chính.

| Tiêu chí | Mô hình truyền thống | Mô hình Zero Trust (ZTLab) |
|---|---|---|
| Phân quyền chi tiết | Trong code application | OPA policy tập trung, độc lập với app |
| Audit trail | Tùy application log | Mỗi quyết định OPA có `decision_id` riêng, ghi Loki |
| Thay đổi policy | Deploy lại code | Cập nhật Rego file, không restart service |
| RBAC violation (kịch bản test) | Không đo được | **6/6 bị chặn**; 129/2.167 quyết định OPA bị từ chối trong 30 phút quanh bài test |

### 2.3. Phát Hiện Brute Force — KB1

ZTLab ghi mọi request 401/403 vào Loki qua Promtail, Grafana đánh giá liên tục, SOAR tự động tạo case khi ngưỡng bị vượt.

> Kết quả đo (`tests/grafana_kb1_brute_force.sh`, 20/08/2026): 20 request brute force gửi liên tiếp, **20/20 bị `api-gateway` chặn** (`jwt_verification_failed`, ghi Loki thật). SOAR tạo case `brute_force` (severity=high, playbook `revoke_user_sessions`) — đo độc lập qua `tests/collect_metrics.py` cho thời gian **inject → pending_approval = 0,58s**, **pending → approved = 0,35s** (tổng **0,93s** khi auto-approve; luồng HITL thật chờ admin duyệt qua email/Web Portal).

| Tiêu chí | Mô hình truyền thống | Mô hình Zero Trust (ZTLab) |
|---|---|---|
| Thời gian phát hiện brute force | Vài giờ đến vài ngày (review log thủ công) | **MTTD trung bình 0,43s** (đo qua AI Analyzer, 5/5 mẫu tấn công phát hiện đúng) |
| Cảnh báo tự động | Cần cấu hình thêm SIEM | Grafana → SOAR → Email, đã xác nhận gửi được (`email_sent=true`) |
| Phản ứng tự động | Thủ công | SOAR playbook, **MTTR (inject→approve) 0,93s** trong bài test tự động |

### 2.4. Phát Hiện Giao Dịch Gian Lận — KB2

ZTLab tích hợp fraud scoring đồng bộ vào luồng xử lý: mỗi giao dịch được `payment-service` chấm điểm rủi ro trước khi commit. Kịch bản thật: gửi giao dịch 500.000.000 VND qua kênh `tor` (base score 5 + critical_amount 55 + risky_channel 15 = 75 ≥ ngưỡng 75 → block).

> Kết quả đo (`tests/grafana_kb2_fraud_gate.sh`, 20/08/2026): **3/3 giao dịch bị chặn** (HTTP 403), log `AUDIT payment_blocked_fraud` ghi thật vào Loki, SOAR tạo case `fraud_gate_bypass` (severity=critical, playbook `isolate_workload`).

### 2.5. Phát Hiện Rò Rỉ Dữ Liệu — KB4

> Kết quả đo (`scripts/run-demo.sh --kb4`, 20/08/2026): log `envoy-access` với `bytes_sent=3.100.000` (> ngưỡng 1MB) đẩy vào Loki → Grafana fire alert trong cửa sổ đánh giá → SOAR tạo case `large_response` (severity=high, playbook `restrict_egress`, target `ctx-openstack/core-banking`) — xác nhận pipeline phát hiện **hoạt động xuyên cloud** (AWS phát hiện → phản ứng trên OpenStack).

### 2.6. Độ chính xác phát hiện (FPR/FNR)

> Kết quả đo (`tests/collect_metrics.py`, 20/08/2026): 8 mẫu log benign + 8 mẫu log tấn công đưa qua AI Analyzer. **False Positive Rate = 0,0** (0/8 benign bị gắn nhầm), **False Negative Rate = 0,0** (0/8 tấn công bị bỏ sót), **Precision = 1,0**, **Recall = 1,0**. Mẫu nhỏ (8/8) — đủ để xác nhận pipeline hoạt động đúng chức năng, không đủ để khẳng định tỉ lệ FPR/FNR tổng quát ở quy mô lớn.

---

## 3. So Sánh Hiệu Năng Vận Hành

### 3.1. Chi Phí Tài Nguyên (snapshot 20/08/2026)

Footprint hiện tại của các thành phần Zero Trust không có trong mô hình truyền thống (đo bằng `kubectl top`, cluster AWS, ngay sau khi chạy xong 5 kịch bản):

| Thành phần | CPU | RAM |
|---|---|---|
| OPA server | 2m | 34 MiB |
| SOAR engine | 2m | 92 MiB |
| SPIRE agent × 2 (mẫu) | 1–4m mỗi pod | 18–19 MiB mỗi pod |
| AI Analyzer | 2m | 55 MiB |
| Security Scorer | 3m | 47 MiB |
| Loki + Promtail (3 node) | 12m + 9–12m mỗi node | 119 MiB + 23–34 MiB mỗi node |
| Grafana | 5m | 199 MiB |

Istio sidecar (istio-proxy) chạy chung container group với từng service application (`kubectl top pods` không tách container trong cùng pod), nên không tách riêng được số CPU/RAM của sidecar khỏi tổng pod trong lần đo nhanh này — khác với bảng chi tiết theo container của bản 28/06 (khi đó còn là hand-rolled Envoy). Về thứ tự độ lớn, tổng chi phí các thành phần Zero Trust mới vẫn ở mức một chữ số % tổng tài nguyên cluster, khớp kết luận của bản gốc.

### 3.2. Độ Trễ Xử Lý Request

Đo bằng `tests/perf_overhead.py --n 100`, tất cả qua cùng đường SSH tunnel + `kubectl port-forward` (xem lưu ý phương pháp ở Mục 0).

> **⚠️ Cảnh báo độ tin cậy (phát hiện 2026-08-23, sau khi migrate Istio):** `tests/perf_overhead.py` gọi `api-gateway` qua `$GW_URL=http://localhost:18080` (`kubectl port-forward`) — đã xác nhận bằng thực nghiệm rằng con đường này **bỏ qua hoàn toàn iptables interception của Istio** (chi tiết + cách verify: [FLOW_DETAIL.md](FLOW_DETAIL.md) §2.3). Nghĩa là dòng **"Full Zero Trust — JWT + Envoy mTLS + OPA"** dưới đây, đo TRƯỚC phát hiện này, nhiều khả năng **không đo đúng** overhead mTLS/OPA thật mà tài liệu tuyên bố — số +38ms có thể chỉ phản ánh JWT decode + Redis lookup ở tầng app, không có Istio mTLS handshake hay OPA ext_authz gRPC call nào thật sự xảy ra trên đường đo. **Số liệu dưới đây cần đo lại qua đường Traefik thật** (xác nhận bằng response header `server: istio-envoy`) trước khi dùng làm căn cứ cho bất kỳ kết luận nào về "chi phí latency của Zero Trust" — giữ nguyên bảng gốc bên dưới chỉ để tham khảo lịch sử, không dùng trích dẫn.

| Kịch bản | P50 | P95 | P99 | Mean |
|---|---|---|---|---|
| Baseline — `/health` (Envoy passthrough, không JWT/OPA) | 360,2 ms | 453,5 ms | 889,6 ms | 355,2 ms |
| OPA-only — endpoint bảo vệ, không JWT (401/403 nhanh) | 311,3 ms | 404,4 ms | 454,7 ms | 322,1 ms |
| Full Zero Trust — JWT + Envoy mTLS + OPA | 398,3 ms | 501,6 ms | 524,3 ms | 410,2 ms |
| **Overhead (Full − Baseline)** | **+38,1 ms (9,6%)** | **+48,1 ms** | — | — |

Con số ms tuyệt đối ở đây **cao hơn hẳn** bản 28/06 (baseline 360 ms so với 7,7 ms trước đó) — vì bản này đo qua 2 lớp SSH tunnel từ máy deployer, bản gốc gần như chắc chắn đo gần cluster hơn (khả năng cao là pod-to-pod nội bộ, không qua tunnel). **Không so sánh trực tiếp 2 con số tuyệt đối này.** Số liệu có thể so sánh được là **overhead tương đối do lớp OPA/JWT thêm vào cùng một đường truyền: +38 ms / +9,6% ở P50** trong lần đo này — thấp hơn con số +127 ms/lần đo trước, khả năng do khác biệt tải hệ thống và jitter mạng tunnel lớn hơn phần overhead OPA thật sự cộng thêm (baseline đã 360 ms, OPA-eval thật sự chỉ cỡ chục ms không còn nổi bật giữa nhiễu tunnel). Đo lại trong môi trường không qua tunnel (chạy script ngay trên node cluster) sẽ cho số đáng tin hơn cho luận điểm "chi phí latency của OPA".

### 3.3. Thời Gian Phát Hiện Và Phản Ứng

| Giai đoạn | Mô hình truyền thống | Mô hình Zero Trust (ZTLab), đo 20/08/2026 |
|---|---|---|
| Phát hiện tấn công (MTTD) | Giờ–ngày (log review thủ công) | **0,43s trung bình** (5/5 mẫu tấn công, AI Analyzer) |
| Phát hiện lateral movement | Thường không phát hiện được | **Tức thì** (OPA deny + Loki log, 3/3 test) |
| Phát hiện RBAC violation | Tùy application log | **Tức thì** (OPA log, 6/6 test) |
| Cảnh báo đến admin | Email/call thủ công | **Tự động qua SOAR**, xác nhận `email_sent=true` trên toàn bộ 6 case tạo trong bài test |
| MTTR (inject → approved) | Thủ công, hàng giờ | **0,93s** (đo tự động, luồng HITL thật chờ duyệt tay ở production) |

Theo Mandiant M-Trends 2024, dwell time trung bình toàn cầu là 10 ngày. MTTD đo được của ZTLab (dưới 1 giây cho log đã tới Loki, dưới 80 giây kể cả chu kỳ đánh giá Grafana theo kịch bản KB) vẫn nhanh hơn nhiều bậc so với con số ngành — biên độ chính xác "nhanh hơn bao nhiêu lần" phụ thuộc cách quy đổi, không nhắc lại con số "7.000 lần" cụ thể của bản cũ vì đó là phép so sánh 1 điểm dữ liệu, không phải kết luận thống kê.

### 3.4. Quản Lý Chứng Chỉ và Credential

Cấu hình TTL (giá trị cấu hình, không đổi giữa 2 lần đo vì không phụ thuộc traffic):

| Tiêu chí | Mô hình truyền thống | Mô hình Zero Trust (ZTLab) |
|---|---|---|
| TTL chứng chỉ workload | 1–2 năm (thủ công) | **1 giờ** (tự động rotation, SPIRE) |
| Root CA TTL | Năm | **168 giờ** (7 ngày, tự động) |
| Định danh workload | Không có / IP-based | SPIFFE URI: `spiffe://ztlab.local/aws/<service>` |

---

## 4. Tổng Hợp So Sánh

| Tiêu chí đánh giá | Mô hình truyền thống | Mô hình Zero Trust (ZTLab), đo 20/08/2026 |
|---|---|---|
| **Bảo mật** | | |
| Lateral movement thử → bị chặn | ❌ Không phát hiện | ✅ **3/3** |
| RBAC violation thử → bị chặn | Tùy application | ✅ **6/6** (129/2.167 quyết định OPA bị từ chối trong 30 phút quanh test) |
| Brute force → bị chặn | Thủ công, chậm | ✅ **20/20**, MTTD 0,43s |
| Fraud gate bypass → bị chặn | Tùy từng service | ✅ **3/3** |
| Data exfiltration (cross-cloud) → phát hiện | Không có cơ chế | ✅ Có, SOAR case tạo trên `ctx-openstack` |
| FPR / FNR (mẫu nhỏ, 8/8) | Không đo được | ✅ **0,0 / 0,0** |
| TTL credential | Năm | ✅ **1 giờ**, rotation tự động |
| **Hiệu năng** | | |
| Latency overhead (JWT+OPA, cùng đường truyền) | — | +38 ms P50 / +9,6% (đo qua tunnel, xem lưu ý 3.2) |
| MTTD | Ngày | ✅ **0,43s** |
| MTTR (auto-approve, đo tự động) | ❌ Thủ công | ✅ **0,93s** |
| Quản lý vận hành | Đơn giản hơn | Phức tạp hơn, nhiều thành phần |

Kết luận không đổi so với bản 28/06: Zero Trust mang lại cải thiện rõ rệt về khả năng phát hiện và audit trail, đổi lại chi phí latency và độ phức tạp vận hành cao hơn. Điểm khác biệt quan trọng của lần đo lại này là **mọi con số ở trên đều mới, đo trực tiếp trên hệ thống đang chạy hôm nay** — không còn dựa vào số liệu tháng 6.

---

## 5. Hạn Chế Của Hệ Thống Hiện Tại

**Latency đo qua tunnel, chưa tách được overhead OPA thuần:** Xem Mục 3.2 — cần đo lại ngay trên node cluster (không qua SSH tunnel + port-forward) để có con số overhead OPA đáng tin cậy.

**Phát hiện chỉ dựa trên rule cứng:** Hệ thống không học được pattern mới. Các kỹ thuật tấn công chưa được định nghĩa trong LogQL (slow brute force, insider threat thực hiện hành vi bình thường) sẽ không bị phát hiện. Cần tích hợp anomaly detection dựa trên ML trong tương lai.

**SOAR dedup theo loại tấn công:** Nếu nhiều attacker khác nhau tấn công cùng lúc, SOAR chỉ tạo 1 case trong 5 phút. Cần thêm `source_ip` vào dedup key để phân biệt.

**Độ giòn của pipeline deploy khi dựng lại từ số 0:** 4 bug ở Mục 0 (cloud-init race, SSH known_hosts, SOAR resource thiếu, JWT client sai) chỉ lộ ra khi destroy+redeploy toàn bộ — cho thấy trước lần đo 28/06, hệ thống có thể chưa từng được dựng lại hoàn toàn từ số 0 bằng script tự động. Cả 4 đã được vá tận gốc trong lần này.

> *Điểm đã giải quyết so với bản 28/06:* mục "Chưa thực sự multi-cloud" của bản cũ không còn đúng — OpenStack hiện có node thật (`os_k3s_master`, `os_k3s_worker_1/2`), `core-banking`/`account-service`/`transaction-service` chạy thật trên đó, và KB4 (Mục 2.5) xác nhận pipeline SOAR phản ứng xuyên cloud hoạt động.

---

*Số liệu đo trực tiếp từ hệ thống đang vận hành tại AWS ap-southeast-1 + OpenStack, ngày 20/08/2026. Raw output: `results/metrics.json`, `results/perf_overhead.json`.*
