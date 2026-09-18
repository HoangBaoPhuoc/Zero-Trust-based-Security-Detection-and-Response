# BÁO CÁO SỬA TẬN GỐC — 2026-09-13

> Nhánh: `feat/root-cause-remediation` (từ `feat/kehoach-thaydoi`). Snapshot từng
> Phần: `snapshots/diff-phan{1,2,3}.patch`. Kiểm kê hop đầy đủ: `KIEM-KE-HOP.md`.
> Bảng SPIFFE/edge sinh tự động: `docs/GENERATED-SERVICE-GRAPH.md`.

## RÀNG BUỘC MÔI TRƯỜNG — ĐỌC TRƯỚC KHI ĐỌC PHẦN CÒN LẠI

Cụm OpenStack (`os-gateway`, floating IP `172.10.10.191`) **không truy cập được
trong SUỐT phiên làm việc này** — `ping`/SSH đều "No route to host", xác nhận
lại nhiều lần kể cả cuối phiên. Đây là sự cố hạ tầng đã biết trước (uplink
hotspot điện thoại của host `aio` — xem `project_ztlab_openstack_uplink_fragility`
trong bộ nhớ dài hạn), **không phải do các thay đổi trong báo cáo này gây ra**.

Hệ quả trực tiếp, quan trọng nhất của báo cáo này:
- **Không destroy+redeploy được** — nghiệm thu cuối theo yêu cầu **KHÔNG thực
  hiện được**. Toàn bộ kiểm chứng sống nằm trên cụm AWS đang chạy hiện tại (đã
  chạy 12+ giờ, KHÔNG phải "trống rồi deploy lại"), cộng với soát mã nguồn kỹ
  cho phần không verify sống được.
- Toàn bộ đổi liên quan Keycloak/OpenStack (Phần 1.2) viết đúng theo pattern đã
  verify sống của `crapi-identity`, và cơ chế lõi (sidecar+SPIRE cho một
  workload trước đây không có) đã **verify sống hệt vậy trên AWS** (opa-server,
  istio-ingressgateway) — nhưng bản thân hop Keycloak thật thì chưa chạy thử.
- Không đăng nhập được (Keycloak là IdP duy nhất) → không kịch bản tấn công nào
  trong `tests/crapi_*.sh` chạy được (tất cả gọi `crapi_login`) → không đo được
  full_auth trong `perf_overhead.py`.

Việc đầu tiên cần làm khi uplink phục hồi: xem mục "VIỆC CÒN LẠI CHO BẠN" cuối
báo cáo — có danh sách lệnh cụ thể để hoàn tất nghiệm thu.

---

## PHẦN 1 — CÓ HOP KHÔNG CÓ DANH TÍNH

### 1.1 Kiểm kê (đầy đủ trong `KIEM-KE-HOP.md`)

Kiểm kê không chỉ đọc source mà đối chiếu **log thật** trên cụm AWS (Loki). Phát
hiện quan trọng nhất của cả đợt sửa: **`AuthorizationPolicy waf-opa-authz` (gate
`X-Edge-Marker` cho hop Traefik→waf) CHƯA BAO GIỜ được Envoy gọi** — xác nhận
bằng cách vét toàn bộ log giữ lại trong Loki: nhãn `source_principal` chỉ từng
có đúng 1 giá trị (`aws/waf`), nhãn `opa_result` chỉ từng có `true`, không một
dòng nào chứa `x-edge-marker`. Tức là hop biên hoàn toàn không có enforcement ở
tầng mesh/PDP suốt thời gian hệ thống chạy — tệ hơn cả những gì tài liệu mô tả
("có gate nhưng dùng marker" hoá ra là "gate không hề chạy").

Nguyên nhân kỹ thuật (không chắc 100%, ghi rõ để không mạo nhận): PeerAuthentication
`PERMISSIVE` trên Istio 1.22.3 dường như dựng 2 filter chain (mTLS-inspected và
plaintext-passthrough) và filter ext_authz/EnvoyFilter tuỳ biến chỉ được gắn vào
nhánh mТLS — traffic plaintext (từ Traefik, không sidecar) đi thẳng qua, bỏ qua
mọi HTTP filter tuỳ biến. Việc này áp dụng ĐỒNG NHẤT cho mọi workload PERMISSIVE
khác đứng trước một hop không-mesh — không phải bug riêng của app này.

### 1.2 Keycloak vào mesh

**Việc đã làm** (toàn bộ trong `diff-phan1.patch`):
- Ns `identity` bật `istio-injection: enabled`.
- Keycloak: ServiceAccount riêng, sidecar + SPIRE socket, SPIFFE
  `spiffe://ztlab.local/openstack/keycloak`.
- `keycloak-db` (Postgres) **tường minh tắt injection** — giữ ở nhóm (b), không
  vào mesh (đúng chủ đích, không phải bỏ sót).
- 2 `DestinationRule` (`keycloak.identity.svc.cluster.local` nội cụm +
  `keycloak-openstack.crapi.svc.cluster.local:30091` cross-cloud) đổi
  `DISABLE` → `ISTIO_MUTUAL`, SAN đúng.
- `PeerAuthentication STRICT` cho Keycloak — **không PERMISSIVE**, khác đề xuất
  "làm như waf" trong đề bài.
- `AuthorizationPolicy keycloak-opa-authz` (CUSTOM → opa-ext-authz).
- 2 edge L7 mới trong `service-graph-crapi.yaml`: `aws/bff -> openstack/keycloak`
  (`GET/POST /realms, /resources, /js` — đúng `_KC_PROXY_ALLOWED` trong
  `services/bff/main.py`) và `aws/opa -> openstack/keycloak` (`GET /realms`).

**Quyết định BẪY 1 (5 pod bootstrap Admin API)**: task cho 2 lựa chọn (PERMISSIVE
kiểu waf, hoặc đưa hẳn vào mesh). Đã đọc source và thấy cả 5 pod
(`kc-crapi-setup`, `kc-ldap-federation-setup`, `kc-audience-mapper-setup`,
`kc-stepup-flow-setup`, `kc-saml-meta`) đều dùng CHUNG một khuôn
(`kubectl run ... --restart=Never` rồi `kubectl exec`) — **chọn đưa hẳn vào
mesh**: ServiceAccount `kc-admin-setup` riêng (đã có SPIRE entry qua generator),
edge L7 catch-all `openstack/kc-admin-setup -> openstack/keycloak`. Lý do chọn
nhánh này thay vì PERMISSIVE: các pod này đã cầm sẵn mật khẩu admin Keycloak
thật qua Secret — mở PERMISSIVE cho Keycloak để chúng gọi plaintext nghĩa là
giữ lại đúng loại "cơ chế thay thế tạm bợ" mà cả đợt sửa này đang xoá; đưa vào
mesh không tốn thêm gì (ns đã inject sẵn) và đóng gap triệt để hơn.

**Quyết định BẪY 2 (opa-server không sidecar)**: bật sidecar cho **cả 2 cluster**
(file `k8s/crapi/opa.yaml` dùng chung, không parametrize theo cluster được một
cách an toàn) — `openstack/opa` được sidecar dù không thực sự cần cho hop nào
hiện tại (harmless, đối xứng, tránh 1 workload có sidecar/1 không cùng file).
Giữ **`PeerAuthentication PERMISSIVE`** cho opa's OWN INBOUND (ext_authz gRPC
từ mọi workload khác) + **KHÔNG đổi** `DestinationRule opa-service-plaintext`
— tức là mọi consumer OPA hiện tại (bff/waf/web/community/workshop/identity)
tiếp tục gọi plaintext y hệt trước, **không hồi quy**. Chỉ EGRESS của opa (gọi
Keycloak) có SVID thật.

**Đã verify sống trên AWS** (không thể verify trên OpenStack — cụm không truy
cập được): áp `opa.yaml` mới lên AWS, opa-server 3/3 kẹt ở `1/2` đúng như dự
đoán (thiếu SPIRE entry) → đăng ký entry → cả 3 pod lên `2/2` trong vài giây →
gửi lại request qua Gateway mới, **vẫn HTTP 200**; kiểm trực tiếp qua bypass
port `/workshop/api/shop/products` **vẫn HTTP 401 (không phải 503)** — chứng
minh `ext_authz` vẫn `allow=true` cho MỌI hop cũ, không một workload nào hồi
quy khi opa được cấp SVID. Đây là bằng chứng mạnh nhất có thể thu thập mà
không đụng tới hop Keycloak thật (chỉ có ở OpenStack).

**Việc còn treo cho Phần 1.2**: chạy lại toàn bộ khi OpenStack lên, verify (a)
Keycloak pod lên `2/2` sau khi có SPIRE entry — dự đoán rất tin cậy vì đã thấy
đúng pattern này 2 lần độc lập trên AWS (gateway, opa); (b) login thật qua BFF
→ Keycloak; (c) `opa(AWS) → keycloak` lấy JWKS qua mТLS mới — kiểm bằng
`counter_rego_builtin_http_send_network_requests: 2` trong decision log OPA
như tài liệu cũ mô tả.

### 1.3 Biên vào mesh — xoá X-Edge-Marker

**Đã verify sống ĐẦY ĐỦ trên AWS**, cắt hẳn đường cũ theo đúng "chạy song song
rồi mới cắt":

1. `profile: minimal` trong `istio-operator.yaml` không có ingressgateway —
   thêm `components.ingressGateways`. Thử annotation
   `sidecar.istio.io/userVolume` (dùng được cho bff/waf) **KHÔNG có tác dụng**
   cho gateway pod (log: "Workload SDS socket not found. Starting Istio SDS
   Server" — rơi về cert tự ký của istiod, không phải SPIRE) — phải dùng
   `k8s.overlays` patch thẳng vào Deployment sinh ra.
2. `Gateway` (ns crapi, cổng **8443 MỚI**, `tls.mode: MUTUAL`,
   `credentialName: edge-gateway-tls` — bí mật ở **ns istio-system**, không
   phải ns của Gateway CR, theo đúng quy ước SDS của Istio) + `VirtualService`
   → `waf:8080`.
3. Đăng ký SPIRE `spiffe://ztlab.local/aws/edge-gateway` — pod `0/1` (SDS "not
   authorized") → `1/1` ngay sau khi có entry, cùng pattern với opa.
4. Header cert thiết bị: THAY vì dùng `x-forwarded-client-cert` chuẩn của Envoy
   (đã thử — **không dùng được**: mỗi hop mТLS tự SANITIZE_SET đè bằng peer
   CỦA CHÍNH NÓ, tới bff chỉ còn thấy `aws/waf`, thông tin cert thiết bị mất
   ngay ở hop kế — đổi hành vi này toàn mesh để sửa thì rủi ro vượt xa lợi
   ích), dùng 1 header ứng dụng riêng `x-device-cert-info` do **Lua EnvoyFilter
   ở chính Gateway** gắn (trích `Subject`/`URI` từ cert đã verify).
5. **Vấn đề giả mạo header** (tương đương RÀNG BUỘC #5 cũ): một Lua EnvoyFilter
   THỨ HAI ở **waf's inbound** xoá header đó trừ khi mТLS peer đúng
   `spiffe://.../aws/edge-gateway`. Đây là cách thay X-Edge-Marker bằng
   "kiểm source_principal đúng là biên" như đề bài yêu cầu, không dùng bí mật
   chia sẻ nào.
6. `waf` PeerAuthentication `PERMISSIVE` → `STRICT` (Traefik không còn lý do
   gửi plaintext).
7. **Verify cả 3 kịch bản qua cổng MỚI (`:18444`) TRƯỚC KHI xoá đường cũ**:
   - Cert hợp lệ + client cert đúng CA → **200**, header
     `x-device-cert-info` đúng nội dung cert (`Subject`, posture).
   - Không cert → TLS handshake fail (`exit 56`, không tới được waf/bff).
   - Cert ký bởi CA lạ → TLS handshake fail.
   - Cert hết hạn (sinh bằng `cryptography`, ký thật bởi Device CA, hết hạn
     30 ngày trước) → TLS handshake fail.
8. Sau khi cả 3 pass: **xoá hẳn** `k8s/crapi/edge-tls.yaml`,
   `k8s/crapi/ingress-aws.yaml`; xoá `EDGE_MARKER`/`X-Edge-Marker`/2 k8s Secret
   liên quan khỏi BFF, OPA rego, manifest. Grep toàn repo cuối cùng: **0 kết
   quả chức năng** (chỉ còn comment lịch sử giải thích đã xoá cái gì).
9. Rebuild + redeploy image `bff` với code đã dọn — chạy lại cả 3 kịch bản +
   `tests/lib/crapi_common.sh::crapi_preflight` — **vẫn PASS** sau khi dọn.

### 1.4 Đóng bypass port

**Thực nghiệm** (yêu cầu bắt buộc của đề bài): `:18081`/`:18083`
(`kubectl port-forward` thẳng tới Service `waf`/`bff`) **VẪN vào được**, kể cả
sau khi `waf`/`bff` đã `STRICT` — verify bằng cách gửi request không mang cert
gì, không mang header gì, tới `bff` (đã `STRICT` từ trước cả đợt sửa này, không
liên quan gì tới thay đổi hôm nay) qua port-forward: **vẫn 200**.

**Nguyên nhân**: `kubectl port-forward` tunnel trực tiếp vào network namespace
của pod và kết nối `localhost:<port>` BÊN TRONG namespace đó — traffic này
không đi qua các rule iptables REDIRECT mà Istio's init container cài để chặn
traffic vào Envoy sidecar (những rule đó áp cho traffic tới TỪ interface mạng
thật của pod, không áp cho traffic loopback sinh ra ngay trong netns). Đây là
tính chất chung của `kubectl port-forward` + Istio, không phải lỗ hổng riêng
của app này, và **không sửa được bằng cấu hình OPA/Istio ở phía server** — thử
cả PERMISSIVE→STRICT cũng không đóng được.

**Quyết định**: **GIỮ** 2 cổng debug này (xoá không đóng thêm rủi ro thật nào —
ai có được chúng đã có kubeconfig của cụm, tức đã có quyền tương đương
`kubectl exec` vào bất kỳ pod nào, đọc bất kỳ Secret nào — mất mát thêm từ 2
cổng này là biên rất nhỏ). Đã sửa **tài liệu/comment cho đúng bản chất**: trước
đây mô tả "bỏ qua Traefik/WAF" (đúng nhưng thiếu), nay ghi rõ "bỏ qua TOÀN BỘ
TLS + mТLS + OPA, đòi kubeconfig của cụm — không phải đường vào thứ hai cho
thiết bị/người dùng thật" (`scripts/open-admin-uis.sh`, `KIEM-KE-HOP.md`).

---

## PHẦN 2 — MỘT NGUỒN SỰ THẬT DUY NHẤT

- `scripts/gen-spire-entries.py` (mới): sinh `scripts/spire-entries.generated.sh`
  (danh sách workload + số lượng kỳ vọng) từ `service-graph-crapi.yaml`.
  `ensure-spire-entries.sh` source file này thay vì hardcode 3 nơi từng lệch
  nhau (comment "AWS 5", log "expect 6", check thật `-lt 5` — cả 3 con số khác
  nhau, chỉ tình cờ chưa vỡ vì `-lt 5` vẫn pass khi thực tế là 6).
- `scripts/gen-networkpolicy.py` mở rộng sinh thêm `{aws,os}-allow-list.yaml`:
  phần hạ tầng tĩnh (Traefik/Prometheus/DNS/istiod/Loki) khai trong
  `netpol_baseline:` của graph; phần **ipBlock cross-cloud — chỗ đã trôi thật
  sự (bug Keycloak A1 đổi cloud)** — nay TÍNH từ mọi edge `cross_cluster: true`,
  không khai tay nữa. Hệ quả phụ: phát hiện và tự sửa luôn 1 gap có sẵn (thiếu
  egress `openstack→aws:31025` cho `identity→mailhog`).
- `scripts/gen-docs-tables.py` (mới, Phần 2.3): sinh
  `docs/GENERATED-SERVICE-GRAPH.md` — thay 3 bảng viết tay đã trôi trong
  `HE-THONG-CHI-TIET.md` (§4.1 ghi "AWS (4)", thực tế generator cho ra 8; §4.3
  thiếu `waf→bff`; §4.4 thiếu Keycloak).
- `tests/test_service_graph_consistency.py`: từ 2 bài mở rộng thành 3 — bài
  mới canh **mọi workload tham gia edge L7 phải có SPIRE entry thật và không
  tự mâu thuẫn khai `spiffe: false`**. **Tự chứng minh test có thể FAIL**: thêm
  1 edge vào graph mà không chạy lại generator → test đỏ đúng dòng mong đợi →
  hoàn tác, xanh lại — làm 2 lần cho 2 loại lỗi khác nhau (file generated lệch,
  và workload thiếu SPIRE entry).

**Nghiệm thu "một workload mới chỉ cần sửa MỘT chỗ"**: đã tự chứng minh trong
lúc làm Phần 1 — mọi workload mới (`edge-gateway`, `kc-admin-setup`, `keycloak`
chuyển sang mesh, `opa` cả 2 cluster) chỉ cần thêm vào `service-graph-crapi.yaml`
rồi chạy 4 generator, không sửa tay bất kỳ file generated nào.

---

## PHẦN 3 — CÁC ĐIỂM YẾU HẠ TẦNG CÒN LẠI

### 3.1 Alert toàn vẹn mesh — **verify sống, tự tái hiện lỗi rồi hoàn tác**

`plg-stack/grafana/alerting/mesh-integrity-alert.yml`: LogQL
`sum(count_over_time({job="envoy-access", namespace="crapi"} | json | method != "" | svid = "" [5m]))`
— request HTTP thật (có `method`) mà `svid` rỗng. `category: infrastructure` →
route thẳng `ztlab-infra-admin` (email), không qua incident-analyzer, theo đúng
`notification-policy.yml` đã có sẵn (không cần sửa policy routing).

**Verify sống**: tạm thời revert `waf-proxy-backend-conf` về đúng bug gốc đã
tìm thấy ở A2/A3 (`proxy_set_header Host $host;` thay vì `$proxy_host`) → gửi 1
request qua Gateway mới → log `envoy-access` ghi đúng
`{"method":"GET","svid":null,"upstream":"10.43.245.35:8080"}` (upstream là
ClusterIP — dấu hiệu PassthroughCluster) → xác nhận **0 decision log** khớp
`trace_id` đó (đúng mô tả gốc: bỏ qua mТLS/OPA mà không để lại dấu vết) → chờ 1
phút, gọi Grafana API xác nhận rule chuyển `state: firing` → **revert ngay lập
tức** ConfigMap về bản đã fix → gửi lại request, **200 OK**, `diff` xác nhận
cấu hình sống khớp 100% với source đã commit (không để sót state).

### 3.2 Vault — verify sống

`crapi-jwt-key` và `grafana-smtp-secret` nay seed vào Vault
(`secret/crapi-jwt-key`, `secret/grafana-smtp`) 1 lần, đọc lại các lần deploy
sau — cùng mẫu `_device_ca_from_vault` đã dùng cho Device CA. k8s Secret vẫn là
cơ chế phân phối runtime (không đổi cách bff/Grafana đọc).

**Phát hiện cần sửa lại nhận định trong đề bài**: `crapi-jwt-key` **không phải
"bí mật nhạy cảm nhất hệ thống"** như mô tả — `deploy/vendor/crapi-keys/README.md`
ghi rõ đây là khoá RSA **công khai của chính OWASP crAPI upstream**, vendored
trực tiếp từ repo của họ, **đã commit trong git** từ trước. Mọi bản cài crAPI
trên thế giới dùng chung khoá này để demo. Đưa vào Vault vẫn làm (được yêu cầu
tường minh, không tốn gì, nhất quán với Device CA), nhưng giá trị bảo mật thực
tế của bước này thấp — nên sửa câu mô tả này trong luận văn nếu có dùng lại.

**Verify sống trên AWS**: seed cả 2 giá trị vào Vault, đọc lại đúng, tạo lại k8s
Secret từ giá trị Vault, restart Grafana — rollout thành công, không hồi quy.

### 3.3 Công cụ đo

- `tests/perf_overhead.py`: sửa xong, chạy được. Baseline (`/health`) P50≈2069ms,
  no-session (`/workshop/api/shop/products` không cookie) P50≈1746ms — **số
  này KHÔNG phản ánh overhead Zero-Trust thật**, bị chi phối bởi chi phí mỗi
  request là 1 tiến trình `curl` mới (TLS handshake mới hoàn toàn, không
  connection pooling) — đã ghi rõ `methodology_note` ngay trong
  `results/perf_overhead.json`. Phép đo B4 thật (tách overhead mТLS+OPA khỏi độ
  trễ cross-cloud bằng keep-alive) thuộc Giai đoạn B, ngoài phạm vi lần này.
  `full_auth` skip đúng thiết kế (Keycloak không tới được).
- `tests/collect_metrics.py`: **KHÔNG sửa được bằng đổi tên**. Gọi thẳng API
  `ai-analyzer`/`soar-engine` (`/analyze`, `/pending`, `/pending/{id}/approve`)
  để đo MTTR bằng cách tự approve 1 playbook — nhưng A4 đã xoá hoàn toàn 3
  service đó, gộp thành `incident-analyzer` với API khác hẳn và **không còn
  khái niệm approve playbook** (đúng cam kết A4: không thực thi tự động). Cần
  thiết kế lại MTTD/MTTR trước khi sửa, không phải việc của lần remediation
  này — đã ghi rõ trong docstring, không giả vờ đã xong.

---

## QUYẾT ĐỊNH TỰ CHỌN — TÓM TẮT

| # | Điểm mơ hồ | Quyết định | Lý do |
|---|---|---|---|
| 1 | Ordering Phần 1 vs Phần 2 | Làm Phần 2 (generator) TRƯỚC Phần 1's Keycloak/Gateway edges | Thêm workload mới cho Phần 1 dùng ngay được generator, tránh làm 2 lần |
| 2 | BẪY 1 (Keycloak Admin API) | Đưa vào mesh (SA riêng), không PERMISSIVE | Không tái tạo anti-pattern đang bị xoá; chi phí gần bằng 0 vì ns đã inject sẵn |
| 3 | BẪY 2 (opa không sidecar) | Bật sidecar CẢ 2 cluster, PERMISSIVE cho inbound, giữ nguyên DestinationRule plaintext | File dùng chung 2 cluster, không parametrize an toàn được; PERMISSIVE+DR cũ = zero regression cho consumer hiện tại (đã verify sống) |
| 4 | Biên mới: Istio Gateway hay tiêm sidecar Traefik | Istio IngressGateway (khuyến nghị chính của đề bài) | Không vướng gì khi đọc repo (chỉ thiếu component, thêm được sạch); native trong mesh, không cần duy trì 1 loại proxy thứ 3 (Traefik) làm mesh boundary |
| 5 | Cert thiết bị truyền qua nhiều hop | Header ứng dụng riêng (`x-device-cert-info`) + Lua strip-if-untrusted-peer, không dùng XFCC chuẩn | XFCC bị mỗi hop tự SANITIZE_SET đè, đổi hành vi đó ảnh hưởng toàn mesh; giải pháp chọn chỉ chạm 2 EnvoyFilter có phạm vi hẹp |
| 6 | Bypass port :18081/:18083 | GIỮ, sửa tài liệu | Không đóng được bằng policy (bản chất kubectl port-forward); đóng cũng không giảm rủi ro thật vì đã cần kubeconfig cụm |
| 7 | crapi-jwt-key có thật sự "nhạy cảm nhất" | Vẫn đưa vào Vault, nhưng ghi rõ đây là khoá public crAPI upstream | Làm đúng yêu cầu tường minh; không được im lặng sửa mô tả sai trong đề bài mà không nói ra |
| 8 | collect_metrics.py | KHÔNG sửa (chỉ ghi rõ lý do) | Cần thiết kế lại MTTD/MTTR sau A4, không phải rename — sửa nửa vời sẽ tạo ảo giác "đã chạy được" |

---

## KẾT QUẢ KIỂM TRA (chỉ AWS — không destroy/redeploy được)

| Kiểm tra | Kết quả |
|---|---|
| `health-check.sh` | `PASS=20 WARN=15 FAIL=0`. Toàn bộ WARN là do OpenStack không tới được + port-forward local chưa bật lúc chạy — không có FAIL nào. |
| `test_service_graph_consistency.py` | `3/3 PASS` (mở rộng từ 2 bài, tự chứng minh có thể FAIL 2 lần rồi hoàn tác). |
| `tests/crapi_*.sh` (toàn bộ script tấn công) | **KHÔNG chạy được** — mọi script gọi `crapi_login`, cần Keycloak (OpenStack down). Chưa từng chạy trong phiên này, không phải hồi quy do thay đổi. |
| Login qua đường vào MỚI + gọi API nghiệp vụ | **Không test được** (cần Keycloak thật). Đã test đầy đủ lớp TLS/mТLS/header bên dưới login (xem 1.3). |
| OPA lấy JWKS + verify JWT | **Không test được trực tiếp** (cần Keycloak). Cơ chế sidecar cho phép opa gọi mТLS đã verify tổng quát trên AWS (xem 1.2). |
| SQLi qua WAF (DetectionOnly) | **Không chạy được kịch bản chính thức** (cần login). WAF audit pipeline không đổi bởi lần sửa này. |
| BOLA — CRS không ghi nhận | **Không chạy được kịch bản chính thức** (cần login). |
| 3 kịch bản certificate (đường MỚI) | **PASS cả 3**, verify sống nhiều lần trên AWS (xem 1.3). |
| Grep `X-Edge-Marker`/`EDGE_MARKER` | **0 kết quả chức năng** trong toàn repo — chỉ còn comment lịch sử. |
| Kiểm kê hop nhóm (c) | Không còn hop nào cố ý ở nhóm (c) theo source; 1.2 chưa verify sống (OpenStack down) — xem `KIEM-KE-HOP.md` mục "Trạng thái cuối". |

Không có chẩn đoán lỗi nào cần thu thập (không có test nào FAIL trên phần chạy
được) — các mục "không chạy được" đều do OpenStack/Keycloak không tới được,
không phải do thay đổi trong lần sửa này gây lỗi.

---

## CÁCH TRUY CẬP HỆ THỐNG QUA ĐƯỜNG VÀO MỚI

```bash
bash scripts/open-admin-uis.sh          # bật port-forward, gồm "crAPI (Gateway mTLS)" :18444
bash scripts/issue-device-cert.sh myuser compliant   # nếu chưa có cert

curl -sk --resolve crapi.ztlab.local:18444:127.0.0.1 \
  --cert deploy/vendor/device-ca/issued/myuser/device.crt \
  --key  deploy/vendor/device-ca/issued/myuser/device.key \
  --cacert deploy/vendor/device-ca/device-ca.crt \
  https://crapi.ztlab.local:18444/login   # (cần Keycloak sống để login thật)
```

`tests/lib/crapi_common.sh` đã trỏ `BFF_URL` mặc định sang `:18444` — mọi
`tests/crapi_*.sh` dùng đúng đường mới không cần sửa gì thêm khi Keycloak sống
lại. Cổng `:18443`/Traefik **không còn tồn tại** — đã xoá hẳn.

Cổng debug `:18081`/`:18083` (`kubectl port-forward` thẳng waf/bff) vẫn còn,
nhưng **không phải đường Zero-Trust** — đòi kubeconfig của cụm, bỏ qua toàn bộ
TLS/mТLS/OPA (xem 1.4).

---

## CẬP NHẬT — NGHIỆM THU ĐẦY ĐỦ TRÊN DESTROY+REDEPLOY SẠCH (2026-09-13, phiên chiều/tối)

OpenStack uplink phục hồi trong phiên này. Chạy đúng quy trình nghiệm thu cuối
mà báo cáo trên còn treo: `terraform destroy` cả 2 cloud → `scripts/
deploy-all.sh` từ trống. Snapshot riêng: `snapshots/diff-verify-song-
2026-09-13.patch`.

### 4 bug hạ tầng MỚI phát lộ (không do Phần 1.2 thiết kế sai — do lần đầu chạy
trên hạ tầng thật-sạch, xem `KIEM-KE-HOP.md` mục "CẬP NHẬT" để biết chi tiết
đầy đủ từng bug), đã sửa tận gốc trong source:

1. **SPIRE agent/server restart vô điều kiện làm hỏng socket của mọi pod đã
   chạy trước đó** (kể cả Keycloak, istio-ingressgateway) — sửa bằng
   config-hash annotation, chỉ restart khi config thật đổi
   (`scripts/deploy-security-stack.sh`).
2. **Istio cài `ingressgateway` cả trên OpenStack** (không cần, không SPIRE
   entry) — thêm `k8s/istio/istio-operator-os-overlay.yaml` tắt component
   này khi cài lên OS (áp dụng ở cả `deploy-app.sh` và `deploy-crapi.sh`, 2
   nơi gọi `istioctl install`).
3. **5 pod bootstrap `kubectl run kc-*-setup` thiếu SPIRE socket annotation
   VÀ thiếu label `app=kc-admin-setup`** → rơi về CA riêng của Istio (mTLS
   luôn CERTIFICATE_VERIFY_FAILED) và bị NetworkPolicy chặn (label không
   khớp) — sửa cả 2 trong biến `KC_ADMIN_SETUP_OVERRIDES` dùng chung.
4. **`gen-networkpolicy.py` hardcode `namespace: crapi`** cho mọi policy sinh
   ra, không xử lý workload khác namespace (Keycloak ở `identity`) và không
   có ngoại lệ cho traffic cross-cluster hợp lệ khi workload đó cũng có
   policy pod-segmentation — sửa generator dùng đúng namespace từ
   `workloads.<id>.namespace` + tự thêm ipBlock ngoại lệ. CIDR ngoại lệ dùng
   `0.0.0.0/0` (giới hạn đúng port) vì kube-router trên node
   (`iptables v1.8.7 nf_tables`) xác nhận qua thực nghiệm không match được
   ipBlock CIDR cụ thể (`/24` lẫn `/32` chính xác đều fail, chỉ `/0` chạy) —
   **đã hỏi và được người dùng duyệt quyết định này**; bảo vệ thật cho hop
   vẫn là L7 (STRICT mTLS + OPA ext_authz).

### 2 phát hiện thêm ngoài SPIRE/mTLS

5. **WAF gửi `Host: $proxy_host` cho BFF** (đúng fix A2/A3 cũ) nhưng thiếu
   `X-Forwarded-Host` → `_external_base()` trong BFF build sai redirect OIDC
   (dùng hostname nội bộ cluster thay vì host thật) → login qua Gateway mới
   không hoạt động. Thêm `proxy_set_header X-Forwarded-Host $http_host;`
   (`k8s/crapi/waf.yaml`) — dùng `$http_host` (giữ port) chứ không phải
   `$host` (nginx tự bỏ port).
6. **CRS rule 921140 false-positive trên header `x-forwarded-client-cert`**
   (Envoy tự gắn, chứa cert PEM URL-encoded — CRS decode `%0A` thành newline
   thật rồi coi là CRLF injection) — gây nhiễu số đo đối chứng BOLA của luận
   văn (WAF vẫn báo CRS "bắt" trên request BOLA dù payload hoàn toàn sạch).
   Thêm CRS exclusion đúng 1 rule/1 header
   (`k8s/crapi/waf.yaml::waf-crs-exclusions`) — verify không làm yếu phát
   hiện SQLi/XSS/LFI thật (`crapi_sqli_waf.sh` vẫn PASS sau fix).

### KẾT QUẢ NGHIỆM THU (destroy+redeploy sạch — lần đầu chạy được đầy đủ)

| Kiểm tra | Kết quả |
|---|---|
| `health-check.sh` | **PASS=31 WARN=4 FAIL=0** (4 WARN đều vô hại: .env.ai/A4, remote SSH cần RUN_REMOTE=1, port debug 18081, evidence stream rỗng vì chưa có attack) |
| `test_service_graph_consistency.py` | **3/3 PASS** (chạy lại sau khi thêm edge + sửa generator) |
| `tests/crapi_run_all.sh` | **PASS=5 FAIL=0** (Lateral Movement, BFLA, Step-up, Access Denied Spike, Brute Force) |
| Login qua đường vào MỚI (`:18444`) + gọi API nghiệp vụ | **200** — `crapi_login` thật qua Keycloak OIDC thành công LẦN ĐẦU TIÊN, `GET /workshop/api/shop/products` và `GET /community/api/v2/community/posts/recent` đều 200 |
| OPA lấy JWKS + verify JWT qua mТLS | **Xác nhận** — `counter_rego_builtin_http_send_network_requests: 2` trên cả 3 replica opa-server (AWS) |
| SQLi qua WAF (DetectionOnly) | **PASS** — CRS ghi `attack-sqli/xss/lfi`, request vẫn đi tiếp |
| BOLA — CRS không ghi nhận | **Xác nhận qua log thô** (0 hit từ pod WAF hiện tại, toàn bộ vòng đời) — script `crapi_bola.sh` báo FAIL=4 do `loki_count()` dính stale/cache của Loki khi gọi lặp lại quá nhanh trong phiên debug (bằng chứng đầy đủ trong `results/bola-output-2026-09-13.txt`), không phải CRS bắt nhầm thật |
| 3 kịch bản certificate qua Gateway mới | **PASS cả 3** — hợp lệ+compliant → 200; không cert → TLS fail; CA lạ → TLS fail (verify lại sau các restart gateway/waf trong phiên) |
| Grep `X-Edge-Marker`/`EDGE_MARKER` | **0 kết quả chức năng** (không đổi so với báo cáo trước) |
| Kiểm kê hop nhóm (c) | **Không còn mục nào chưa verify sống** — (c)-2/(c)-3/(c)-4 nay đã verify đầy đủ, xem `KIEM-KE-HOP.md` |

Không có bug an ninh nào bị bỏ sót/che giấu qua các fix trên — mọi thay đổi là
sửa lỗi hạ tầng làm request KHÔNG TỚI ĐƯỢC đích (fail-closed do stale
socket/NetworkPolicy/redirect sai), không phải nới lỏng bất kỳ policy nghiệp
vụ nào. Ngoại lệ duy nhất cần lưu ý minh bạch: ipBlock `0.0.0.0/0` ở mục 4
(giới hạn đúng port, lớp bảo vệ thật vẫn là L7) — đã trình bày lý do và được
duyệt.

## VIỆC CÒN LẠI CHO BẠN

**Mục 1 và 2 gốc (chờ OpenStack + nghiệm thu destroy/redeploy) đã HOÀN TẤT**
trong phiên cập nhật 2026-09-13 ở trên — xem bảng kết quả. Còn lại:

1. **HE-THONG-CHI-TIET.md** chỉ mới sửa đúng 3 bảng bị trôi (§4.1/4.3/4.4, Phần
   2.3). Phần còn lại (kiến trúc §2.1, WAF §4.7, Device CA §4.8, luồng đăng
   nhập §8.2, bảng cấu hình §9, trạng thái §11) **CHƯA được viết lại** theo
   Phần 1 (Keycloak mesh, Gateway mới, waf STRICT, xoá marker) — vẫn mô tả
   kiến trúc CŨ. Cần một lượt rewrite riêng trước khi dùng tài liệu này cho
   luận văn.

2. Sửa 4 điểm "SỬA ĐỀ CƯƠNG (v9)" trong `KEHOACH-THAYDOI-HETHONG.md` (việc viết
   văn bản của bạn, không phải infra) — vẫn treo từ trước, không thuộc phạm vi
   lần này.

3. `tests/collect_metrics.py` cần thiết kế lại MTTD/MTTR cho kiến trúc
   post-A4 (xem 3.3) — không phải việc rename.

4. Enroll OTP một lần cho `stepup-demo` (việc thủ công cũ, vẫn treo).

5. Nếu muốn số đo BOLA/CRS "sạch" trực tiếp từ `tests/crapi_bola.sh` (không
   cần tự tra Loki thủ công như phiên này) — chạy lại kịch bản đó một lần,
   CÁCH xa lần chạy gần nhất ít nhất ~15 phút (để cache/kết quả cũ của Loki
   trôi khỏi cửa sổ 10 phút của `loki_count()`), thay vì gọi lặp lại nhanh.
