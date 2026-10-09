# HẠN CHẾ VÀ HƯỚNG PHÁT TRIỂN

> Viết để dùng thẳng cho chương Hạn chế của khoá luận. Mỗi mục: **hiện tượng**,
> **nguyên nhân đã xác định tới đâu**, **đã loại trừ bằng thực nghiệm**, **vì sao
> không xử lý trong phạm vi khoá luận**, **hướng khắc phục đúng nếu làm tiếp**.
> Nguồn số liệu: `SAN-SANG-GIAI-DOAN-B.md` (bảng đóng sổ 2026-10-04) và các file thô trong `results/closeout/` (`results/round3/` cho số đo 2026-09-26 còn hợp lệ).
> File này được viết TĂNG DẦN; mục nào chưa có số đo thật ghi rõ "chưa đo".

## H1. Không có metrics cấp ứng dụng cho `bff` — panel metric cũ ĐÃ XOÁ (2026-10-04)

- **Hiện tượng:** `bff` không có route `/metrics` (request rơi xuống proxy catch-all tới `crapi-web`, trả 404). Job
  Prometheus `crapi-services-aws` đã gỡ (Q6). Dashboard từng có 23 panel luôn rỗng: metric `ztlab_*` của ứng dụng finance cũ
  (`ztlab_anomaly_score`, `ztlab_fraud_*`, `ztlab_transactions_total`, `ztlab_auth_failures_total`) và truy vấn Loki vào
  `namespace="financial"` / `app=fraud-detection|api-gateway|core-banking|notification-service` — những thứ không còn tồn tại.
- **Đã làm (2026-10-04):** xoá các panel đó khỏi `incident-evidence-dashboard.json`, `ztlab-security-overview.json`,
  `ztlab-full-logs.json` (row rỗng xoá theo); 4 truy vấn regex `namespace=~"financial|…"` đổi `financial` → `crapi`.
- **Vì sao không thêm instrumentation:** quan sát của hệ thống dựa trên **log** (Loki: OPA decision log, access log Envoy,
  audit BFF, CRS audit); MTTD, alert và evidence bundle không dùng metric của bff. Prometheus chỉ còn 3 target (Q6) và
  **không phải trụ cột quan sát** — luận văn không được mô tả nó như nguồn phát hiện.
- **Hướng đúng nếu làm tiếp:** thêm `prometheus-client` vào `bff`, khai lại job, dựng panel RED (rate/error/duration) theo route.

## H2. Rule `Mesh Integrity` báo giả — ĐÃ SỬA 2026-09-29

- **Hiện tượng (trước):** rule "request tới crapi không có SVID" `firing` liên tục khi hệ thống khỏe.
- **Nguyên nhân (đã đo):** trường `svid` = `%DOWNSTREAM_PEER_URI_SAN%` chỉ có nghĩa ở dòng log **phía server** (inbound) của sidecar;
  dòng **phía client** (outbound: push Loki, token Keycloak, bff→workshop…) luôn `svid=null`. Cùng cửa sổ 5 phút: rule cũ khớp 52 dòng,
  đều là báo giả. Tệ hơn: kết nối plaintext thật vào cổng STRICT bị từ chối ở tầng listener với `response_flags=NR`, **không có HTTP
  method** — rule cũ (`method != ""`) không bao giờ bắt được đúng thứ nó định bắt.
- **Sửa (trong code):** access log Envoy thêm `upstream_cluster`/`response_flags`/`transport_failure`; Promtail suy nhãn `direction`;
  rule = (A) dòng inbound có HTTP mà không SVID + (B) dòng NR không upstream_cluster không method.
- **Nghiệm thu:** `tests/mesh_integrity_fp_check.sh` — 10 phút tải thường (405 request) → 0 lần khác `inactive`; 1 kết nối plaintext →
  Firing sau 119 s.
- **Còn lại:** request qua `kubectl port-forward` thẳng vào app không đi qua sidecar inbound nên không bị rule thấy (và không cần: đó là
  đường debug nằm ngoài mesh, không phải bypass từ workload).

## H3. Phân đoạn L4 trong namespace `crapi` KHÔNG hiệu lực (lỗi của kube-router) — NÂNG THÀNH PHÁT HIỆN

> Trạng thái cuối 2026-10-04: **HẠN CHẾ có chủ đích + phát hiện có tên riêng** — xem `PHAT-HIEN-PHAN-DOAN-L4.md` (mục riêng cho luận văn,
> tái hiện lại trên cụm dựng từ trống cả hai cloud). Không sửa. Phần dưới giữ chi tiết kỹ thuật.

- **Hiện tượng:** `tests/netpol_matrix.sh` (22 ô): 14 MATCH / 8 MISMATCH. Cả 8 ô "kỳ vọng bị chặn" đều là nguồn TRONG ns `crapi`
  (crapi-web → bff/workshop/redis/mongodb, community → bff/redis, bff → mongodb) hoặc `monitoring → redis`, và vẫn kết nối
  được. Nguồn ngoài ns (`default` → bff/opa) và egress cross-cloud (community → k3s-API/ssh của node OpenStack) bị chặn đúng.
- **Nguyên nhân đã xác định:** baseline `podSelector: {}` Ingress+Egress có rule egress "cùng ns :<cổng>"; kube-router áp
  rule đó như "cho phép" ở phía ingress của pod đích, làm thủng default-deny ingress đúng cho các cổng nằm trong danh sách
  egress. Tái hiện cô lập (`tests/netpol_podselector_probe.sh`, biến thể `egress-shadow`, ns tạm): policy chỉ cho `a` vào
  `srv` nhưng `c → srv:80` vẫn thông, cả cùng node lẫn khác node, ở cả 2 cụm chạy được.
- **Đã loại trừ bằng thực nghiệm:** (i) thiếu `ipset` — sai (k3s tự có `ipset`, PATH đặt trước host; policy `podSelector` đơn
  lẻ chạy đúng 8/8); (ii) do sidecar/uid 1337 — sai (pod không sidecar trong ns `crapi` cũng vượt); (iii) lỗi đồng bộ thoáng
  qua — sai (lặp lại nhiều lần, ổn định).
- **Vì sao không xử lý:** sửa đúng đòi hỏi tách egress theo từng pod nguồn (policy egress riêng cho mỗi nguồn theo edge) và
  rà lại egress ngoài đồ thị (posture-agent, seed job, sidecar); rủi ro làm gãy deploy ở vòng cuối là cao, trong khi L7
  (mТLS STRICT + OPA `service_acl`) đã phân đoạn được nội ns (7/7 kịch bản tấn công PASS).
- **Hướng đúng:** (1) sinh policy egress theo từng pod nguồn từ edge của service-graph, baseline chỉ giữ DNS/istiod/Loki/cross-cloud;
  hoặc (2) đổi bộ điều khiển NetworkPolicy (Calico/Cilium) và chạy lại đúng ma trận này; (3) giữ `tests/netpol_matrix.sh` làm cổng
  nghiệm thu.
- **Tác động tới luận văn:** L4 CÓ hiệu lực với nguồn ngoài namespace và egress cross-cloud; KHÔNG được tuyên bố là lớp phân đoạn
  giữa các pod cùng namespace. `redis --requirepass` và `mongod --auth` là lớp bù cho đích không sidecar.

## H4. Thu hồi cert thiết bị chỉ chặn hành động GHI, không phải CRL tầng TLS

- **Hiện tượng:** sau khi thu hồi, thiết bị vẫn kết nối TLS được và vẫn ĐỌC được (200); chỉ POST/PUT/PATCH/DELETE bị chặn (403,
  `reason=revoked`), cả phiên đã đăng nhập trước thu hồi lẫn phiên mới. Độ trễ từ lúc thu hồi tới lúc bff thấy: 16–64 giây.
- **Nguyên nhân:** thiết kế có chủ đích — denylist tầng ứng dụng trong ConfigMap, bff đọc tươi trên mỗi request GHI; không vá
  CRL/OCSP của Istio Gateway (đường vào duy nhất, rủi ro cấu hình sai cao).
- **Đã loại trừ:** giả thuyết "ConfigMap `subPath` không bao giờ cập nhật" — sai (mount cả thư mục, không `subPath`); hiện tượng
  "file vẫn rỗng sau >3 phút" của vòng trước không tái hiện (7/7 PASS, `tests/crapi_cert_revocation.sh`).
- **Vì sao không xử lý:** thu hồi cắt-hẳn-kết-nối đòi hỏi CRL/OCSP ở Gateway.
- **Hướng đúng:** CRL thật (Envoy `crl` trong `validation_context`) hoặc TTL cert ngắn + cấp lại; thu hẹp độ trễ bằng watch thay vì mount.
  Tài liệu/luận văn phải nói "chặn thao tác ghi", không nói "không tới được ứng dụng".

## H5. Xung đột iptables-legacy / nf_tables trên k3s và hệ quả với phân đoạn L4

Đây là câu chuyện điều tra có giá trị học thuật, giữ lại kể cả khi lỗi cụ thể đã sửa.

- **Hiện tượng:** trên cả 6 node (Ubuntu 22.04, k3s), `update-alternatives` trỏ `iptables-nft`; kube-router ghi rule vào
  nftables. `iptables-legacy -S FORWARD` chỉ thấy `-P FORWARD ACCEPT`, trong khi `iptables -S FORWARD` (backend nft) và `nft list
  ruleset` thấy đủ chain `KUBE-ROUTER-FORWARD`/`KUBE-POD-FW-*`. Istio-init dùng `iptables-legacy` trong netns của pod. Công cụ nhìn
  nhầm backend thấy "không có rule", hoặc báo `chain … is incompatible, use 'nft' tool`.
- **Hệ quả thực tế:** hai lần chẩn đoán sai liên tiếp — "kube-router không enforce đáng tin cậy" rồi "node thiếu ipset" — đều
  bắt nguồn từ đọc sai lớp: shell SSH tương tác không có PATH của k3s (nên `ipset: command not found`) và dòng
  `# match-set` do `nft` hiển thị match `xt_set` bị hiểu là "rule chết". Bằng chứng đúng lớp là **bộ đếm gói trong chain
  `KUBE-POD-FW-*` (`nft -a list ruleset`)** và các ipset thật (`ipset list`).
- **Đã loại trừ:** thiếu `ipset` (xem H3); xung đột legacy/nft làm rule không được thực thi (rule THỰC SỰ thực thi: counter
  `reject` tăng đúng theo lưu lượng bị từ chối).
- **CHƯA KIỂM LẠI — độ tin cậy THẤP (trạng thái cuối 2026-10-04: HẠN CHẾ):** ghi chú 2026-09-13 rằng `ipBlock` CIDR chính xác
  (`/24`, `/32`) không khớp cho traffic ingress đã NAT qua gateway (chỉ `0.0.0.0/0` hoạt động). Chỉ có một quan sát, không có dữ liệu thô
  giữ lại, chưa tái hiện trên cụm nào sau đó. Egress `ipBlock 192.168.101.0/24` từ pod hoạt động đúng (ma trận A3). Không được trích như
  một kết quả; nếu cần: tái hiện bằng một policy ingress `ipBlock` = IP private của `aws_gateway` (nguồn sau MASQUERADE, xem H11) trên một
  pod thử trong ns tạm, so với `0.0.0.0/0`.
- **Hướng đúng:** thống nhất một backend (nft) trên node, ghi rõ trong runbook "đọc rule bằng `nft -a list ruleset`, không
  bằng `iptables-legacy`"; hoặc đổi CNI/netpol controller.

## H6. Độ trễ overhead Zero-Trust: thành phần PDP đạt; overhead đầu-cuối 20 ms p99 CHƯA được chứng minh (trạng thái cuối 2026-10-04)

- **Số hợp lệ duy nhất hiện có — thành phần PDP**, đo từ `metrics.timer_server_handler_ns` của từng decision OPA trong 60 phút lưu lượng
  lành tính (`tests/opa_pdp_latency.py`, `results/closeout/perf/pdp-benign-window.json`): AWS n = 5277, p50 0,50 / p95 2,02 / **p99 4,37 ms**
  (p99 từ 53 mẫu), max 409,6 ms; OpenStack n = 2129, p99 1,45 ms. Đây là **cận dưới** của overhead ext_authz (không gồm gRPC Envoy↔OPA, bắt tay
  mТLS, hai chặng Envoy, ghi decision log).
- **Nguồn đuôi đã xác định:** phân phối AWS lưỡng đỉnh — 35/5277 (0,66 %) mẫu ≥ 100 ms, không mẫu nào 20–100 ms; 98 % mẫu ≥ p99 trùng lần OPA
  tải lại JWKS/discovery **cross-cloud** từ Keycloak OpenStack (`http.send` `force_cache_duration_seconds: 300`). Ở tải thấp hơn, tỉ lệ này > 1 %
  và p99 nhảy 100–400 ms. Giả thuyết cũ "decision log console" không phải nguồn đuôi của PDP (log ghi SAU khi trả lời, ngoài timer); lượt chẩn
  đoán phía client tắt decision log **chưa chạy** (`tests/perf_opa_decision_log_diag.sh` đã sẵn sàng, có xác nhận khôi phục sống).
- **Vì sao chưa có số đầu-cuối:** request đi trọn tới crapi-workshop (cặp duy nhất trong `service_acl` vừa có JWT RS256 vừa trả 200) gọi identity
  + Postgres **bên kia WireGuard** mỗi lần: ~1–1,8 s/request. n ≥ 2000 × 3 cấu hình × 3 lượt ≈ 5 giờ, và nhiễu WAN lớn hơn ngưỡng 20 ms nhiều
  lần — hiệu hai phân phối WAN ở p99 không đo được overhead vài ms. (Toàn bộ số độ trễ của vòng 3 đã bị xoá: đo trên request 401.)
- **Không đo được "không mesh" thật:** `crapi-workshop` crash nếu thiếu sidecar (cần mТLS tới `crapi-identity` STRICT).
- **Trạng thái cuối: CHUYỂN SANG GIAI ĐOẠN B** — đo dưới tải nền thật trong một cửa sổ riêng không có kịch bản tấn công, bằng `tests/perf_overhead.py`
  (đã sửa: làm mới JWT theo lô ≤ 150 s). Kết luận thẳng cho luận văn: *ngưỡng 20 ms p99 cho toàn bộ overhead Zero-Trust chưa được chứng minh đạt;
  thành phần PDP đạt với p99 4,37 ms trên lưu lượng thật.*
- **Hướng đúng:** (1) JWKS cục bộ mỗi cloud (bundle OPA / mirror) để bỏ `http.send` qua WAN trên đường quyết định; (2) thêm
  `%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%` vào access log Envoy để tách thời gian ở sidecar khỏi thời gian ứng dụng trên từng request (n lớn, không
  cần cửa sổ đo riêng); (3) workload đo không phụ thuộc cross-cloud.

## H7. "Chính sách tồn tại nhưng không bao giờ được thực thi" — sáu trường hợp độc lập (trạng thái cuối 2026-10-04)

Cùng một lớp lỗi xuất hiện sáu lần, mỗi lần qua một cơ chế khác nhau; bài học chung quan trọng hơn từng lỗi. Trạng thái hiện tại
của từng ca:

| # | Ca | Cơ chế | Trạng thái 2026-10-04 |
|---|---|---|---|
| 1 | PassthroughCluster (WAF) | `proxy_set_header Host $host` làm Envoy outbound của waf rơi vào `PassthroughCluster`, bỏ qua mТLS và OPA, **không có decision log nào** | ĐÃ SỬA (Phần 1); `waf → bff` có decision OPA cho từng request |
| 2 | `waf-opa-authz` | AuthorizationPolicy CUSTOM tồn tại nhưng Envoy chưa từng gọi nó cho traffic PERMISSIVE/plaintext | **ĐÃ THỰC THI** từ khi waf STRICT + biên là Istio IngressGateway (Phần 1.3); chứng minh nhân quả bằng request gắn marker → decision `edge-gateway → waf` 7 ms trước `waf → bff` (`results/round4/waf-opa-authz/`). Giữ, không xoá |
| 3 | Gatekeeper | hai constraint nhắm ns `financial` đã xoá — 0 violation vì không có gì để kiểm | ĐÃ SỬA: retarget `crapi`, `deny` cho workload tự viết, `dryrun` cho ảnh bên thứ 3 (H13) |
| 4 | NetworkPolicy nội ns + rule Control-Plane | pod-segmentation apply nhưng không chặn nguồn cùng ns; rule `Security Control-Plane Down` firing đảo ngược (NoData = báo động) | NetworkPolicy: **KHÔNG sửa — nâng thành phát hiện** (`PHAT-HIEN-PHAN-DOAN-L4.md`, tái hiện 2026-10-04 trên cụm mới); rule: ĐÃ SỬA 2026-09-26 (`or vector(0)`, `noDataState: OK`) |
| 5 | Rule `Mesh Integrity` + step-up OTP | rule bắt nhầm dòng phía client và không thể bắt kết nối plaintext (NR, không method); step-up thiếu `acr.loa.map` → chưa từng thành công | ĐÃ SỬA 2026-09-29 (H2, H15.2); kiểm lại trên cụm 2026-10-04 (bảng đóng sổ) |
| 6 | **(Mới, 2026-10-04) Kênh email của Grafana** | receiver `ztlab-infra-admin` + email của `ztlab-security-admin` cấu hình đủ, rule Firing đúng, nhưng SMTP trỏ Gmail với mật khẩu rỗng → mọi lần gửi `535 Username and Password not accepted` (API receivers). Alert hạ tầng (Mesh Integrity, Control-Plane Down, Log Pipeline Silent, Health-Check Silent) **chưa từng báo tới ai**; chỉ phát hiện vì phép thử 3.4 đòi vế bằng chứng thứ hai (email thật tới hộp thư) | ĐÃ SỬA: SMTP Grafana → MailHog `plg-stack` (`k8s/plg-stack/grafana.yaml`); kiểm sống: `SAN-SANG` 3.4 |

**Bài học phương pháp (cho chương Bàn luận): chính sách tồn tại không đồng nghĩa với chính sách thực thi; mọi control phải có bằng
chứng thực thi sống.** Các trường hợp trên có chung một hình dạng: đối tượng cấu hình tồn tại, deploy báo thành công, `kubectl get`
thấy, kiểm tra tĩnh (lint, test sinh file, so khớp nguồn) đều qua — nhưng đường traffic thật hoặc không đi qua điểm thực thi
(PassthroughCluster, PERMISSIVE), hoặc điểm thực thi đánh giá trên tập rỗng (Gatekeeper trỏ ns đã xoá), hoặc ngữ nghĩa bị đảo
(NoData = báo động, rule egress làm thủng ingress, `acr` sai kiểu). Không trường hợp nào được phát hiện bằng đọc cấu hình; tất cả
được phát hiện bằng **một phép thử sống có hai vế**: (1) đường *đáng lẽ bị từ chối* thật sự bị từ chối, và (2) *việc đánh giá thật sự
xảy ra* — có decision log / counter / evidence gắn với đúng request thử (marker duy nhất, trace id). Vế (2) quan trọng không kém vế
(1): một policy "cho qua" và một policy "không bao giờ được gọi" cho cùng kết quả HTTP 200. Hệ quả cho phương pháp nghiệm thu: tiêu
chí "Ready"/"applied"/"0 violation" không phải bằng chứng; bảng `AUDIT-THUC-THI.md` chỉ ghi ✅ khi có bằng chứng thực thi sống kèm
nguồn dữ liệu thô.

**Bài học (kỹ thuật):** fail-closed ở tầng chính sách vô nghĩa nếu traffic không tới được tầng chính sách. Mọi chính sách phải kèm một phép
thử "đường bị từ chối thật sự từ chối" **và** "việc đánh giá thật sự xảy ra" (decision log / counter), không chỉ kiểm tra đối
tượng tồn tại. `AUDIT-THUC-THI.md` là bảng ghi điều đó cho từng chính sách.

## H8. `kubectl get pods` Ready không đủ làm tiêu chí nghiệm thu — nghiệm thu đã TÁCH khỏi đường deploy (2026-10-04)

Bằng chứng trong dự án: (i) vòng 2 — mọi pod `2/2 Running` nhưng `waf → bff` trả 503; (ii) 2026-09-26 — Prometheus `1/1 Running` nhưng
không có sidecar và target `down`; (iii) rule cảnh báo hiển thị `firing` khi hệ thống khỏe; (iv) 2026-10-04 — pod OPA OpenStack `1/1
Ready` nhưng KHÔNG có `istio-proxy` (tạo trong lúc istiod đang cài) → mọi request tới Keycloak 403 UAEX. Biện pháp: `verify_mesh_connectivity`
(request thật giữa các cặp `service_acl`), kiểm sidecar OPA tường minh, `tests/verify_telemetry_pipeline.py`, `tests/netpol_matrix.sh`.

**Đã sửa:** `verify_mesh_connectivity` từng `fail` ngay giữa `deploy_crapi` và `deploy_observability_response` — một lỗi tầng app làm
stack quan sát không bao giờ được dựng (sự cố vòng 2026-09-19/26). Nay trong đường deploy đầy đủ (`deploy-app.sh` đặt
`ZTLAB_DEFER_ACCEPTANCE=1`) nó chỉ cảnh báo; nghiệm thu thật chạy ở `verify_final` → "Step 8c" (`deploy-crapi.sh --verify-only`), SAU khi
mọi thứ đã dựng, và vẫn `fail` nếu mesh không thông. Chạy `deploy-crapi.sh` độc lập giữ hành vi cũ (fail ở cuối, không có gì đứng sau).
**Còn lại:** nghiệm thu mesh chỉ kiểm 2 cặp (waf→bff, community→identity cross-cloud).

## H9. Các thành phần cố ý giữ ở mức test double

- **MailHog** (SMTP demo, `MH_STORAGE=memory`): hộp thư SOC và mail signup crAPI; không phải relay thật, không TLS/auth.
- **OpenLDAP** (`identity-directory`): "SCIM demo directory" READ_ONLY federate vào Keycloak — minh hoạ nguồn danh tính doanh nghiệp,
  không phải directory thật; bind DN/mật khẩu là giá trị lab trong script deploy.
- **Vault:** storage `file` + PVC + auto-unseal, nhưng unseal key và root token nằm trong K8s Secret (`vault-unseal-keys`) — giản lược có
  chủ đích cho lab, không phải mô hình vận hành thật (nên dùng auto-unseal KMS/HSM).
- **incident-analyzer:** chỉ phát hiện + đóng gói bằng chứng + email; KHÔNG có hành động phản ứng (cam kết của khoá luận, A4).
- **Cross-cloud:** hai "cloud" là AWS thật và một OpenStack AIO trên máy đơn; uplink của host `aio` (điện thoại) từng mất mạng
  giữa phiên (vòng 2).
- **Hướng đúng:** thay bằng dịch vụ thật (SMTP relay, LDAP/AD, Vault HA + KMS) khi đưa vào sản xuất.

## H10. Bằng chứng tái lập (deploy) — destroy + dựng từ trống trên mã hiện tại (2026-10-04)

- **Đã chạy:** `terraform plan` không target cả 2 cloud trước destroy → `No changes` (0 destroy ngoài ý muốn); `destroy-all.sh` rồi
  `deploy-all.sh` từ trống, hai cloud, tài khoản AWS mới. Lần 1 hỏng ở Terraform OpenStack (VM kẹt BUILD 30 phút — đồng hồ host AIO bị
  chỉnh lùi 7 h sau khi Kolla khởi động; sửa trong code: `scripts/openstack-aio-preflight.sh`); lần 2 hỏng ở chính bước tiền kiểm mới
  (CLI snap 5.8 không tạo được VM không NIC; sửa); lần 3 xanh: 0 FAIL, nghiệm thu Step 8b (stack quan sát + log OpenStack qua WireGuard)
  và Step 8c (mesh) đều OK. Chi tiết, thời gian và các WARN: `SAN-SANG-GIAI-DOAN-B.md` mục 3.6; log `results/closeout/rebuild/`.
- **Giới hạn còn lại:** lần 3 bị Claude Code dừng giữa bước 11 vì máy thiếu RAM (5 VM OpenStack ≈ 7,6 GB / 15 GB) và được chạy tiếp
  bằng `--from-step 11` trên đúng các VM vừa tạo — vẫn là hạ tầng từ trống, nhưng không phải một lệnh liền mạch. Lần chạy tiếp làm lộ lỗi
  thứ ba (`--from-step > 2` không nạp `.env` → SAML bị bỏ qua mà deploy vẫn báo xanh; đã sửa). Bước 3c thực hiện `terraform apply
  -target` lên tài nguyên AWS IAM thật (SAML provider + role).

## H11. Điểm đơn lỗi của đường log OpenStack → Loki — ĐÃ SỬA 2026-09-29

- **Trước:** Promtail OpenStack → `socat` trên máy deployer (172.10.10.1:13099) → `kubectl port-forward` → Loki. Máy ngủ/đổi mạng = mất log
  âm thầm (positions ở `emptyDir`, retry mặc định ~10 phút).
- **Vì sao chưa từng đi thẳng WireGuard:** `aws_gateway` MASQUERADE mọi gói ra `ens5` (kể cả từ `wg0`) nên nguồn tới node AWS là IP private
  của gateway, trong khi SG chỉ mở NodePort cho subnet OpenStack → bị chặn. Cùng lý do, relay `loki-relay` (socat trên worker AWS) chưa
  bao giờ dùng được.
- **Sửa:** SG mở NodePort cho `${gateway_private_ip}/32` (Terraform); Promtail OpenStack đẩy thẳng `http://10.10.1.10:31000` (NodePort Loki);
  positions trên hostPath `/var/lib/promtail`; backoff 0,5→30 s × 300 lần (~2,5 giờ); deploy `fail` nếu Loki không có log `cloud=openstack`
  trong 3 phút; alert `Log Pipeline Silent` (không có log OpenStack 10 phút). Bỏ cả hai relay socat.
- **Nghiệm thu:** ngắt `wg-quick@wg0` 61 s → 519/519 dòng tuần tự tới Loki, 0 mất (`tests/log_pipeline_outage.sh`).
- **Còn lại (trạng thái cuối: HẠN CHẾ):** ngưỡng chịu đựng của đường log OpenStack ≈ **2,5 giờ** gián đoạn (backoff 0,5→30 s × 300 lần);
  dài hơn, hoặc pod Promtail bị xoá/đổi node trong lúc đang retry, phần batch giữ trong bộ nhớ có thể mất (Promtail không có WAL bền).
  Host `aio` tắt thì cả cụm OpenStack dừng — log không mất nhưng cũng không sinh. Với TTL SVID 4 h (H17), đường log và mТLS nay chịu
  được cùng cỡ gián đoạn. **Lưới an toàn cho đợt 150 giờ:** bộ thu chia khúc (`tests/collect_chunked.py`) đánh `gap` mọi khúc có khoảng
  > 60 s không tươi ở một cloud — nghiệm thu 2026-10-04: ngắt WireGuard 134 s giữa khúc 2 → khúc 2 `gap`, khúc 1/3 `valid`. Đáng chú ý:
  hậu kiểm Loki của khúc 2 thấy log OpenStack **đầy đủ** (Promtail gửi bù) — một mình hậu kiểm sẽ đánh nhầm `valid`; tiêu chí độ tươi
  trực tiếp mới bắt được. Alert `Log Pipeline Silent` (10 phút) là lưới thứ hai.

## H12. Bí mật mức lab được commit trong repo

Một số giá trị mẫu nằm trong manifest/script để tái lập dễ (`session-secret` của bff, mật khẩu seed `crapi-seed`, mật khẩu admin LDAP,
mật khẩu user demo trong `realm-config.json`, mật khẩu admin Keycloak mặc định trong script). Đây là dữ liệu demo, không phải bí mật
sản xuất. **Hướng đúng:** đưa hết vào Vault + External Secrets, quét bí mật trong CI, và đổi toàn bộ trước khi dùng ngoài lab.

## H13. Ranh giới của khoá luận (không phải lỗi)

- Lỗ hổng tầng ứng dụng của crAPI (BOLA, BFLA, JWT confusion, SSRF, mass assignment…) được **giữ nguyên có chủ đích** làm đối tượng bao
  quanh; CRS ở chế độ `DetectionOnly` (không chặn) để không làm nhiễu telemetry — nên WAF chỉ chứng minh "CRS bắt SQLi nhưng không bắt
  BOLA" (phép đo đối chứng), không phải bảo vệ.
- Gatekeeper `ZTLabRequireNonRoot` chỉ `deny` cho 4 workload tự viết; ảnh crAPI/bên thứ 3 giữ `dryrun` (không sửa ảnh đích để giữ tính
  tái lập thực nghiệm).

## H14. MTTD phụ thuộc chính sách thông báo và nhịp eval — đo lại 10 lượt/kịch bản (trạng thái cuối 2026-10-04)

- **Chính sách đã đổi (trong code, kiểm bản sống trước khi đo):** route `category=security` `group_by: ['...']` (mỗi alert instance một nhóm),
  `group_wait 5s`, `group_interval 30s` — trước đây `group_by [grafana_folder, alertname]` + `group_interval 5m` làm MTTD phản ánh nhịp flush
  và mất bundle khi hai kịch bản chạy chồng.
- **Kết quả (tuần tự, không chồng kịch bản; `results/closeout/mttd/`):** Lateral Movement trung vị 19,26 s [10,38–50,90], Brute Force trung vị
  80,68 s [42,37–82,72], n = 10 mỗi kịch bản, 0 lượt mất bundle. Phần do hệ thống ≈ 2 s (tấn công → deny trong Loki) + 0,01 s (bundle → email);
  phần còn lại do cấu hình (eval 60 s, ngưỡng tích luỹ, `group_wait`).
- **Hạn chế còn lại (trạng thái cuối: HẠN CHẾ):** các lượt khoá pha với nhịp eval (bundle luôn ở cùng một giây trong phút) vì bộ chạy bắt đầu ngay
  khi rule về inactive; trung vị Brute Force nghiêng về pha xấu. Chu kỳ eval 1 phút là chặn dưới của độ phân giải MTTD.
- **Hướng đúng:** chèn độ trễ ngẫu nhiên 0–60 s trước mỗi lượt; nếu cần MTTD thấp hơn, giảm `interval` của nhóm rule (đánh đổi tải truy vấn Loki).

## H16. PHÁT HIỆN CHÍNH — BFF không làm mới token: hệ thống "đúng" trong mọi phép thử ngắn, sai có hệ thống trong phép thử dài

- **Hiện tượng:** access token Keycloak sống 300 s; BFF lưu `refresh_token` nhưng chưa từng dùng. Mọi phiên người dùng dài hơn 5 phút
  gửi tiếp token hết hạn trong `X-Access-Token` → OPA (`io.jwt.decode_verify` kiểm `exp`) **từ chối đúng** → 403. Đo sống: phiên 10 phút
  lưu lượng hoàn toàn hợp lệ → 75/405 request (18,5 %) bị 403, và **một evidence bundle "Lateral Movement" được sinh ra khi không có
  tấn công nào** (rule Lateral đếm mọi OPA deny trên API nghiệp vụ).
- **Vì sao nghiêm trọng hơn mọi lỗi khác của chuỗi vòng hạ tầng:** tỉ lệ deny lành tính này **tương quan với độ dài phiên** — 0 % trong 5
  phút đầu, tăng dần sau đó. 150 giờ dữ liệu nền của Giai đoạn B sẽ mang nhãn "tấn công" sai một cách *có hệ thống*, không ngẫu nhiên.
  Mô hình Giai đoạn C sẽ học "phiên dài ⇒ tấn công": recall cao trên tập test (cùng phân phối, cùng lỗi) và sụp trên biến thể — đúng
  dạng thất bại mà tiêu chí đề cương "giữ ≥ 70 % recall trên biến thể chưa xuất hiện trong tập huấn luyện" được đặt ra để bắt, nhưng khi
  đó đã quá muộn để thu lại dữ liệu.
- **Vì sao chưa vòng nào thấy:** mọi kịch bản, mọi phép đo trước đây chạy xong trong < 5 phút kể từ lúc đăng nhập. Không một phép thử
  nào có thời lượng vượt TTL của token. Phát hiện được là nhờ lần đầu chạy trọn một luồng người dùng thật **dài hơn TTL** (nghiệm thu
  mục 4, 10 phút tải thường) — và nhìn vào mã HTTP của chính lưu lượng "nền", thứ trước đó chỉ được coi là phông.
- **Sửa (code):** `services/bff/main.py::_ensure_fresh_access_token` — làm mới bằng `refresh_token` của đúng client đã cấp (`crapi-bff` /
  `crapi-bff-stepup`), cập nhật `acr` theo token mới, giữ nguyên tuổi phiên (không kéo dài `SESSION_MAX_AGE`), refresh thất bại → 401
  `token_expired` (buộc đăng nhập lại, không để request đi với token chết). Audit `token_refreshed` / `token_refresh_failed`.
  Nghiệm thu `tests/bff_token_refresh.sh`: 200 ở t = 0 và t = 330 s, 1 lần `token_refreshed`.
- **Bài học cho chương Bàn luận (cùng họ H7):** *một hệ thống có thể chạy đúng trong mọi phép thử ngắn và sai có hệ thống trong phép thử
  dài.* Mọi trạng thái có thời hạn (token 300 s, SVID 1 h, cert thiết bị 7 ngày — H15.3 là cùng lớp lỗi ở thang ngày) phải có ít nhất
  một phép thử dài hơn thời hạn đó. Với một đề tài mà sản phẩm cuối là *dữ liệu*, lỗi kiểu này nguy hiểm hơn lỗi làm hệ thống sập, vì
  nó không làm gì sập — nó chỉ gán nhãn sai.
- **Còn lại:** ngữ nghĩa rule Lateral ("mọi deny") không đổi — mọi nguồn deny lành tính khác vẫn sinh bundle; đo ở mục 13
  (`SAN-SANG-GIAI-DOAN-B.md`).

## H15. Phát hiện vòng 2026-09-29 — lỗi thật lộ ra khi chạy trọn luồng (đã sửa trong code)

Mỗi lỗi dưới đây nằm im vì chưa từng có phép thử chạy trọn luồng trong thời gian đủ dài — cùng họ với H7.

1. **BFF không làm mới access token Keycloak** — phát hiện chính của vòng, xem riêng **H16**.
2. **Step-up OTP chưa bao giờ có thể thành công:** thiếu `acr.loa.map` (token `acr="2"`, BFF/OPA so `"high"`); flow `browser-stepup` hỏi OTP
   hai lần; `stepup-demo` không có user crAPI. Sửa trong deploy/realm/seed; `tests/crapi_step_up_otp.sh`.
3. **Cert thiết bị test hết hạn (TTL 7 ngày) mà không ai phát hành lại** → mọi kịch bản chết ở Gateway. `_ensure_device_cert` nay phát
   hành lại khi còn < 24 h. **Rủi ro Giai đoạn B:** bộ sinh tải phải gọi `crapi_preflight` (hoặc tương đương) ít nhất mỗi ngày.
4. **Công cụ đo `loki_count` sai** (căn cửa sổ theo `step`, chỉ đọc series đầu) → chênh CRS `attack-lfi/rce` 1↔0 và "transaction total"
   2 thay vì 3. Không phải hành vi CRS. Mọi số đếm Loki của vòng 3 lấy qua hàm này (BOLA, SQLi) phải đo lại bằng bản đã sửa.
5. `security-scanner` Job không bao giờ complete (sidecar); `sync-app-images.sh --aws-only` thoát 1 dù thành công.

## H17. TTL X.509-SVID nâng 1 h → 4 h (2026-10-04) — đánh đổi có chủ đích

- **Vì sao:** chuỗi sự cố số một (`HE-THONG-CHI-TIET.md` §10.2): uplink host `aio` mất → WireGuard/DNS chết → SPIRE agent không làm mới
  SVID → SVID hết hạn → mТLS STRICT sập dây chuyền. Thời gian cụm chịu được gián đoạn trước khi sập ≈ phần đời còn lại của SVID (agent
  làm mới ở ~½ TTL), nên TTL 1 h cho biên ~30–60 phút; 4 h cho ~2–4 giờ — cùng cỡ với độ bền của đường log (H11, retry ~2,5 h). Với đợt
  thu 150 giờ cộng dồn, đây là khác biệt giữa "một lần rớt mạng mất một khúc" và "một lần rớt mạng làm sập cả cụm".
- **Phát hiện khi sửa:** `default_x509_svid_ttl` trong `spire/server/*.conf` **không có tác dụng** — `scripts/ensure-spire-entries.sh` tạo
  mọi entry với `-ttl 3600`, giá trị trên entry ghi đè default của server (đo sống: 9/9 entry AWS mang `x509_svid_ttl=3600`). Sửa cả hai
  chỗ; entry dùng `-x509SVIDTTL $SPIRE_X509_SVID_TTL` (14400) và khi entry đã tồn tại với TTL khác thì `entry update` (chạy lại trên cụm
  có sẵn cũng hội tụ). Cờ `-ttl` cũ đồng thời đặt TTL JWT-SVID = 1 h; nay JWT-SVID theo default server 5 phút (hệ thống không dùng
  JWT-SVID — Istio dùng X.509 qua SDS).
- **Đánh đổi:** một khoá riêng workload bị lộ dùng được lâu hơn (tối đa 4 h thay vì 1 h) — trong mô hình này không có thu hồi SVID,
  nên TTL là cơ chế giới hạn duy nhất. Chấp nhận vì mối đe doạ thực nghiệm đo được (sập dây chuyền) lớn hơn rủi ro lộ khoá trong lab.
- **Hướng đúng nếu làm tiếp:** giữ TTL ngắn nhưng làm SPIRE agent sống sót qua gián đoạn (agent cache SVID + upstream server cục bộ mỗi
  cloud đã có; vấn đề là đường attest/sync), hoặc federation hai trust domain để mỗi cloud tự cấp SVID khi WAN đứt.


## H18. Phép đo đối chứng "CRS không bắt BOLA" chưa từng được đo trên một vụ BOLA thành công — ĐÃ SỬA (2026-10-04)

- **Hiện tượng:** `tests/crapi_bola.sh` thử các UUID xe "đoán" (`649acfac-…0001`, `…0002`, `0000…0001`, `1111…`) và tính MỌI mã HTTP
  từ ứng dụng — kể cả **404** — là "BOLA tới được ứng dụng". Log thô 2026-09-13, 2026-09-26 và lần chạy đầu 2026-10-04: **mọi request BOLA
  đều 404** (UUID không tồn tại; `testuser01` không có xe nên cũng không có UUID thật). Kết luận cũ "request tới được ứng dụng và thực sự
  đọc dữ liệu xe của người khác — CRS = 0" là **sai ở vế đầu**: CRS = 0 trên request 404, không phải trên BOLA.
- **Lỗi đi kèm:** `T1="$(date +%s)"` làm tròn xuống → dòng audit CRS của request cuối (phần lẻ giây sau T1) rơi khỏi cửa sổ (T0,T1] —
  lỗi đã sửa ở `crapi_sqli_waf.sh` vòng 4 nhưng sót ở BOLA, và với BOLA nó thiên về đúng kết quả kỳ vọng (0). Cùng lỗi làm
  `crapi_cert_scenarios.sh` FAIL giả (không thấy `device_trust_denied` có timestamp 0,59 s sau T1).
- **Sửa:** đi đúng chuỗi BOLA của crAPI — (1) vehicleid của người khác lộ qua `community/posts/recent` (trường `author.vehicleid`),
  (2) `GET /identity/api/v2/vehicle/{id}/location`; chỉ tính là BOLA khi **200 và email chủ xe ≠ kẻ tấn công**, FAIL nếu không có vụ nào;
  T1 làm tròn lên +1 s ở cả ba script.
- **Kết quả mới (3 lượt):** mỗi lượt 3/3 nạn nhân (`adam007`, `pogba006`, `robot001`) bị đọc vị trí xe thành công; CRS = 0 hit trên path
  BOLA, 0 tag `attack-*`; vế "đánh giá thật sự xảy ra": cả 3 request mỗi lượt có dòng inbound + outbound ở sidecar của WAF (đi qua
  nginx/ModSecurity). Đối chiếu SQLi/XSS/LFI: 3/3 lượt `attack-sqli`=1, `attack-xss`=1, `attack-lfi/rce`=1, tổng 3. Dữ liệu
  `results/closeout/crs-bola/`.
- **Bài học (cùng họ H7):** một phép đo đối chứng có thể "PASS" mãi mãi nếu điều kiện tiên quyết của nó (cuộc tấn công thực sự thành công)
  không được kiểm. Kết quả âm (0 hit) chỉ có nghĩa khi đã chứng minh có thứ để bắt.
