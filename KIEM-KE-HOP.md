# KIỂM KÊ HOP — trước khi sửa (Phần 1.1, KEHOACH-THAYDOI-HETHONG.md remediation)

> Chốt ngày 2026-09-13. Đối chiếu `policy/service-graph-crapi.yaml`, `k8s/crapi/istio-policies.yaml`,
> `k8s/crapi/waf.yaml`, `k8s/crapi/network-policies/*`, `scripts/ensure-spire-entries.sh`,
> `services/bff/main.py`, `opa/crapi-policies/*.rego` — **và** log thật lấy từ Loki trên cụm AWS
> đang chạy (`kubectl --context ctx-aws -n plg-stack port-forward svc/loki 13100:3100`), cụm
> OpenStack **không truy cập được lúc kiểm kê** (`172.10.10.191` no route to host — uplink host
> `aio` sập, xem `project_ztlab_openstack_uplink_fragility` trong memory; không phải regression
> của lần sửa này). Mọi khẳng định "đã verify sống" dưới đây chỉ áp dụng cho phía AWS; phía
> OpenStack dựa trên đọc source + tài liệu, ghi rõ ràng buộc này ở từng dòng liên quan.

## Nhóm (a) — mTLS + SPIFFE principal + qua OPA (đã đúng, không đụng)

| Hop | Ghi chú |
|---|---|
| Traefik→waf **KHÔNG thuộc nhóm này** — xem nhóm (c) #1, đây là phát hiện chính của kiểm kê. |
| `waf → bff` | mTLS thật, `source_principal=spiffe://ztlab.local/aws/waf`, qua OPA (`bff-opa-authz`). **Verify sống 2026-09-13**: `kubectl -n crapi port-forward svc/waf 18081:8080` rồi `curl /health` và `curl /workshop/api/shop/products` → cả hai đều sinh `Decision Log` với `source_principal=aws/waf`, `destination_principal=aws/bff`, `opa_result=true` (xem log Loki thu thập lúc 06:11–06:15 UTC). |
| `bff → crapi-community` | Đúng theo service-graph, mТLS + `crapi-community-opa-authz`. |
| `bff → crapi-workshop` | idem, `crapi-workshop-opa-authz`. |
| `bff → crapi-web` | idem, path GET static only. |
| `bff → crapi-identity` (cross-cloud) | mТLS ISTIO_MUTUAL (`crapi-identity-openstack-mtls` DestinationRule) + `crapi-identity-opa-authz` (OPA OpenStack). Không verify sống được hôm nay (OS down) — dựa trên source + lần verify trước (KET-QUA-CRAPI.md). |
| `crapi-community/-workshop → crapi-identity /verify` (cross-cloud) | idem. |

## Nhóm (b) — L4 dữ liệu, cố ý không qua mesh (ngoại lệ có chủ đích, GIỮ NGUYÊN)

Liệt kê tường minh theo yêu cầu — đây LÀ ngoại lệ đã được cân nhắc (không sidecar ở phía không
Istio, hoặc là kết nối dữ liệu thuần không mang chính sách nghiệp vụ per-request):

| Hop | Lý do giữ L4 |
|---|---|
| `bff → redis:6379` | Session store nội bộ AWS, không sidecar phía redis (`spiffe: false` trong service-graph); mất mТLS chấp nhận được vì cùng ns, cùng cluster, netpol L4 chặn nguồn. |
| `crapi-community/-workshop → mongodb:27017` | idem, dữ liệu community/workshop, không sidecar. |
| `crapi-community/-workshop → postgresdb-openstack:30432` (cross-cloud) | Postgres OpenStack không sidecar (`DestinationRule mode: DISABLE`) — WireGuard mã hoá tunnel thay mТLS. |
| `crapi-identity → postgresdb:5432` (nội OpenStack) | idem, cùng cluster. |
| `crapi-identity → mailhog:1025` (nội OpenStack, SMTP) | Test double không cần chính sách. |
| `* → opa:9191/8181` (ext_authz gRPC/HTTP, cả 2 cluster) | **Cố ý L4** — đây là hop gọi TỚI PDP; bọc nó bằng chính PDP là vòng lặp logic (circular dependency). `opa-service-plaintext` DestinationRule `mode: DISABLE` giữ nguyên, xem BẪY 2 dưới. |

## Nhóm (c) — KHÔNG có danh tính / cơ chế thay thế tạm bợ → PHẢI SỬA

### (c)-1. Traefik → waf — **X-Edge-Marker là cơ chế thay thế tạm bợ, và ĐÃ ĐƯỢC CHỨNG MINH KHÔNG HOẠT ĐỘNG**

`k8s/crapi/waf.yaml` có `AuthorizationPolicy waf-opa-authz` (`selector: app=waf`, `action: CUSTOM`,
`provider: opa-ext-authz`, `rules: [{}]`) — theo thiết kế, hop này gọi OPA với
`source_principal=""` (Traefik ngoài mesh) và OPA có rule `public_path` gated bởi
`headers["x-edge-marker"] == opa.runtime().env.EDGE_MARKER` (`opa/crapi-policies/zta_crapi.rego`
dòng 206-211).

**Thực nghiệm 2026-09-13 (cụm AWS đang chạy, không đụng gì trước khi test):**
```
kubectl --context ctx-aws -n plg-stack port-forward svc/loki 13100:3100 &
curl -s -G http://localhost:13100/loki/api/v1/label/source_principal/values
  → ["spiffe://ztlab.local/aws/waf"]        # CHỈ MỘT giá trị, suốt cửa sổ lưu log hiện có
curl -s -G http://localhost:13100/loki/api/v1/label/opa_result/values
  → ["true"]                                 # CHƯA BAO GIỜ có opa_result=false
curl -s -G ... --data-urlencode 'query={job="opa-decisions"} |= "x-edge-marker"'
  → 0 kết quả                                # rule marker CHƯA BAO GIỜ được match/log
curl -s -G ... --data-urlencode 'query={job="opa-decisions", source_principal=""}'
  → 0 kết quả decision log (chỉ có log truy cập /health không liên quan ext_authz)
```
Kết luận: **`waf-opa-authz` không hề được Envoy gọi cho traffic PERMISSIVE/plaintext vào `waf`**
(rất có thể do cách Istio dựng filter chain HTTP cho PeerAuthentication PERMISSIVE không gắn
ext_authz filter vào nhánh plaintext trên bản Istio 1.22.3 đang dùng — chưa xác định chính xác
lý do lõi Envoy, nhưng bằng chứng thực nghiệm là dứt khoát: **rule marker là dead code**, hop
Traefik→waf hiện **không có bất kỳ enforcement nào ở tầng mesh/PDP**, chỉ còn lại việc Traefik tự
verify TLS client-cert (thật, đã verify ở A3) làm hàng rào duy nhất còn hoạt động cho hop này.

Đây chính xác là mẫu hình Nguyên nhân 1 mô tả: một cơ chế thay thế tạm bợ (shared secret) được
dựng lên để bù cho hop thiếu danh tính, và bản thân cơ chế thay thế đó cũng không đáng tin (ở
đây còn tệ hơn: nó im lặng không chạy). **Xử lý ở Phần 1.3.**

### (c)-2. `bff → keycloak-openstack:30091` — plaintext qua WireGuard, không SPIFFE, không OPA
`k8s/crapi/cross-cloud-aws.yaml`: `DestinationRule keycloak-openstack-plaintext` → `mode: DISABLE`.
Namespace `identity` (nơi Keycloak chạy) **không có nhãn `istio-injection`** (`k8s/namespaces.yaml`
dòng 17-23) → Keycloak pod không sidecar → không SPIFFE, không mТLS, không SVID cho OPA kiểm.
Đây là luồng OIDC (mật khẩu + token) đi trần qua WireGuard. **Xử lý ở Phần 1.2.**

### (c)-3. `opa(AWS) → keycloak-openstack:30091` (http.send JWKS + OIDC discovery) — cùng vấn đề (c)-2
Thêm ràng buộc riêng: `kubectl --context ctx-aws get pods -n crapi opa-server-* ` cho READY `1/1`
(so với `bff`/`waf`/`crapi-web`/`crapi-community`/`crapi-workshop` đều `2/2`) — **xác nhận
opa-server AWS không có Istio sidecar**, đúng như BẪY 2 cảnh báo: dù Keycloak vào mesh, hop này
vẫn không mТLS được nếu không tự cho opa-server một sidecar. **Xử lý ở Phần 1.2.**

### (c)-4. 5 pod bootstrap Keycloak Admin API — chạy hoàn toàn ngoài mesh
`kc-crapi-setup`, `kc-ldap-federation-setup`, `kc-audience-mapper-setup`, `kc-stepup-flow-setup`
(`scripts/deploy-crapi.sh`, `scripts/deploy-app.sh`) và `kc-saml-meta` — tất cả tạo bằng
`kubectl run --image=... -n identity` KHÔNG sidecar, gọi thẳng
`http://keycloak.identity.svc.cluster.local:8080` bằng mật khẩu admin Keycloak lấy từ Secret.
Đây chính là BẪY 1: nếu Keycloak lên STRICT mà các pod này không vào mesh, chúng chết hết ngay
lần deploy kế tiếp. **Xử lý ở Phần 1.2** (đưa vào mesh, KHÔNG dùng PERMISSIVE tạm bợ).

## Nguồn không SPIFFE cố ý (không phải nhóm (c), liệt kê để không nhầm)
`aws/mongodb`, `aws/redis`, `aws/mailhog`, `aws/opa` (inbound), `openstack/postgresdb`,
`openstack/opa` (inbound) — khai `spiffe: false` trong `service-graph-crapi.yaml`, khớp nhóm (b).

## Sự kiện phụ phát hiện khi kiểm kê (không phải nhóm (c), ghi lại vì ảnh hưởng báo cáo/report cuối)
- `ensure-spire-entries.sh`: comment nói "AWS 5 (waf+bff+web+community+workshop)" nhưng code check
  `-lt 5` còn log lại in "expect 6" — 3 con số không khớp nhau dù hành vi (gate ở 5, thực tế đăng
  ký 6 vì có thêm `prometheus`) vẫn đúng. Sửa nhân tiện khi làm Phần 2 (sinh danh sách này từ
  service-graph nên số lượng luôn tự khớp, không còn hardcode 3 chỗ lệch nhau).
- `HE-THONG-CHI-TIET.md` §4.1 bảng SPIFFE ghi "AWS (4)" — trôi so với thực tế đăng ký là 6
  (thiếu `waf`, `prometheus`). §4.3 ma trận L7 không liệt kê `waf → bff` (vì nó được diễn giải
  riêng ở §4.7 dưới dạng "waf's own inbound hop", dễ gây hiểu lầm đây là edge không tồn tại).
  §4.4 mô tả netpol bằng tay: "Traefik→bff:8080" (thực tế `aws-allow-list.yaml` đã sửa thành
  "Traefik→waf:8080" từ A2), "bff→identity(Keycloak 8080)" (đã bị xoá từ A1, thay bằng ipBlock
  cross-cloud), thiếu cổng 30091 trong danh sách ipBlock (thực tế `aws-allow-list.yaml` ĐÃ có).
  → **Các file YAML thực tế đã đúng, chỉ có bảng tường thuật tay trong tài liệu bị trôi** — bằng
  chứng sống cho chính vấn đề Nguyên nhân 2 (nguồn sự thật chỉ phủ một nửa: ai đó sửa netpol khi
  cần, nhưng bảng mô tả trong tài liệu không ai cập nhật theo). **Xử lý ở Phần 2.3.**

## Trạng thái cuối (sau Phần 1, 2026-09-13)

Nhóm (c) đã đóng hết theo source code (chưa verify sống hết — xem ràng buộc dưới):
- (c)-1 Traefik→waf: **THÁO HẲN đường Traefik**, thay bằng Istio IngressGateway
  (`spiffe://ztlab.local/aws/edge-gateway`) → waf, mТLS thật, qua OPA thật (edge
  `aws/edge-gateway -> aws/waf`). **Verify sống đầy đủ trên AWS** (3 kịch bản
  cert + xác nhận X-Edge-Marker/EDGE_MARKER xoá sạch khỏi codebase).
- (c)-2/(c)-3 bff/opa → keycloak: DestinationRule đổi DISABLE → ISTIO_MUTUAL,
  opa (2 cluster) nay có sidecar. **Verify sống cơ chế sidecar+SPIRE trên AWS**
  (áp dụng y hệt cho opa) nhưng **CHƯA verify được hop thật opa→keycloak** (cần
  OpenStack).
- (c)-4 5 pod bootstrap Admin API: đưa vào mesh bằng ServiceAccount
  `kc-admin-setup` riêng. **CHƯA verify sống** (cần OpenStack).

Không còn hop nào cố ý ở nhóm (c) theo source; nhóm (b) (L4 dữ liệu) giữ nguyên,
liệt kê đầy đủ ở trên.

## Ràng buộc môi trường lúc thực hiện remediation này
Cụm OpenStack (`172.10.10.191`, os-gateway) không truy cập được trong suốt phiên làm việc này
("No route to host" cả ping lẫn SSH) — sự cố hạ tầng đã biết trước (uplink hotspot điện thoại
của host `aio`, xem `project_ztlab_openstack_uplink_fragility`), không phải do các thay đổi ở
đây gây ra. Hệ quả:
- Mọi thay đổi chạm tới phía OpenStack (Keycloak mesh injection, SPIRE entry cho Keycloak/
  kc-admin-setup, AuthorizationPolicy trên Keycloak) được viết đúng theo source + đối chiếu pattern
  đã verify sống của `crapi-identity`, nhưng **KHÔNG verify sống được trong phiên này** — cần
  chạy lại trên cụm khi uplink phục hồi trước khi coi Phần 1.2 là "đã nghiệm thu", không chỉ
  "đã viết đúng".
- Nghiệm thu cuối (destroy toàn bộ + deploy lại từ đầu) **không thực hiện được** vì cần
  `terraform apply` + Ansible SSH tới OpenStack. Xem BAOCAO-SUA-GOC-2026-09-13.md phần "Việc còn
  lại" cho quy trình nghiệm thu khi uplink phục hồi.
