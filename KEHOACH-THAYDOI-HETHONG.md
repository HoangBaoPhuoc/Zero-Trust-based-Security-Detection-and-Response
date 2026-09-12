# KẾ HOẠCH THAY ĐỔI & TỐI ƯU HỆ THỐNG — sau rà soát đề cương v8 ↔ hiện trạng `feat/crapi-target`

> Chốt ngày 2026-09-10. Căn cứ: `DeCuongChiTiet_KLTN_ZTA_v8.docx` ↔ `HETHONGCHITIET.md` (branch `feat/crapi-target`), đối chiếu bài mẫu KLTN Trần Thị Mỹ Huyền – Ngô Tuấn Kiệt (2025).

---

## 0. CÁC QUYẾT ĐỊNH ĐÃ CHỐT

| # | Vấn đề | Quyết định | Lý do |
|---|---|---|---|
| 1 | Keycloak (+ db, openldap) đang ở AWS, ngược lập luận Nghị định 53 | **Chuyển toàn bộ sang OpenStack** | NĐ53 Điều 26 bắt buộc thông tin cá nhân người dùng lưu trong nước; pattern *selective residency* của Slack/OpenAI dựa trên GDPR (quy định về *chuyển* dữ liệu, có SCC/adequacy) nên không áp dụng được. Bài mẫu cùng khoa đặt `API gateway, Keycloak, PostgreSQL` trên OpenStack (Bảng 4.1, tr.70), AWS chỉ chạy ứng dụng đích. Chi phí thấp vì Keycloak không nằm trên đường xử lý mỗi request. |
| 2 | SOAR có playbook thực thi thật, mâu thuẫn cam kết "chỉ báo" | **Xoá toàn bộ phần thực thi**; gộp `soar-engine` + `ai-analyzer` + `security-scorer` thành một `incident-analyzer` | Khoá luận dừng ở phát hiện + phân tích bằng chứng + thông báo. Ba service đang làm cùng một việc bằng regex, tách ba khó biện minh. |
| 3 | Đề cương nói "chứng chỉ thiết bị kèm posture", thực tế là heuristic User-Agent + posture của pod BFF | **Triển khai client certificate mTLS thật**, posture nhúng trong cert | Bỏ được điểm yếu "đoán thiết bị bằng User-Agent"; giữ nguyên câu chữ đề cương, không phải sửa. |
| 4 | Đề cương hứa OWASP CRS nhưng hệ thống chưa có WAF | **Thêm ModSecurity3 + CRS trước BFF, chế độ DetectionOnly** | Khớp đề cương, và cho phép đo đối chứng: CRS bắt SQLi nhưng **không bắt được request BOLA nào** — biến luận điểm trung tâm thành số đo. DetectionOnly để không chặn nhầm luồng crAPI và không làm nhiễu dữ liệu huấn luyện. |
| 5 | Thứ tự thực hiện | **Đóng băng kiến trúc trước, rồi mới sinh dataset thật** | Cả 4 thay đổi trên đều làm đổi telemetry (đường request, header, số hop, `http.send` của OPA). Sinh dữ liệu trước là sinh đi sinh lại. |
| 6 | Mục tiêu 150 giờ lưu lượng nền | **Giữ 150h, cộng dồn nhiều phiên**, đánh dấu phiên hợp lệ | Hạ tầng có tiền sử sập khi uplink hotspot rớt. Không đòi chạy liên tục, nhưng phải loại được window bị cắt giữa chừng. |
| 7 | Ngưỡng độ trễ 20ms p99 | **Tách overhead Zero Trust khỏi độ trễ cross-cloud** | 20ms áp cho overhead mTLS+OPA đo trên cùng một hop nội cụm; độ trễ cross-cloud báo cáo riêng như đặc tính kiến trúc hybrid. |
| 8 | Rate limiting ở BFF | **Không thêm** | Ngoài phạm vi; và chặn bớt lưu lượng tấn công có thể làm loãng chính tín hiệu mô hình cần học. |

---

## GIAI ĐOẠN A — ĐÓNG BĂNG KIẾN TRÚC

Toàn bộ giai đoạn này phải xong và verify được **trước khi** sinh một giờ dữ liệu thật nào. Nguyên tắc chung: mọi thay đổi nằm ở **source IaC** (Terraform / Helm / manifest / script deploy), verify bằng `terraform destroy` → `deploy-all.sh` chạy sạch — không tiêm live bằng `kubectl apply`.

### A1. Chuyển Keycloak sang OpenStack

**Việc:**
- Chuyển `k8s/keycloak/` (keycloak + keycloak-db) và `k8s/openldap/` từ context `ctx-aws` sang `ctx-openstack`, ns `identity` / `identity-directory` trên cụm OpenStack.
- Mở NodePort mới trên `os-k3s-master` cho Keycloak (đề xuất **30091**), theo đúng mẫu `crapi-identity` 30090.
- Thêm vào `k8s/crapi/cross-cloud-aws.yaml`: Service selectorless `keycloak-openstack` + Endpoints `192.168.101.11:30091` + DestinationRule (`mode: DISABLE` — Keycloak không sidecar, WireGuard lo mã hoá; hoặc `ISTIO_MUTUAL` nếu cho Keycloak chạy sidecar).
- Đổi hai điểm tiêu thụ:
  - OPA `opa/crapi-policies/zta_crapi.rego` — JWKS + OIDC discovery từ `keycloak.identity.svc.cluster.local:8080` → `keycloak-openstack.crapi.svc.cluster.local:30091`. Giữ `force_cache` 300s.
  - BFF `services/bff/main.py` — target proxy `/kc/*` và endpoint token/authorize.
- Cập nhật `policy/service-graph-crapi.yaml`: thêm edge `aws/bff → openstack/keycloak` và `aws/opa → openstack/keycloak`, rồi chạy lại `scripts/gen-rego-acl.py` + `scripts/gen-networkpolicy.py`.
- NetworkPolicy: sửa `{aws,os}-allow-list.yaml` — egress `crapi`→ipBlock `192.168.101.0/24`:**30091**; bỏ egress bff→`identity`(8080) cũ trên AWS.
- Security group OpenStack (`terraform/openstack/security_groups.tf`): `neutron-sg-os-private` hiện chỉ mở NodePort **từ chính dải** — phải mở thêm cho nguồn đến từ WireGuard/os-gateway SNAT. **Kiểm tra kỹ điểm này, đây là chỗ dễ gãy nhất.**
- Các bước Keycloak Admin API trong `deploy-app.sh` (`deploy_openldap_and_federation`, `deploy_audience_mapper`, `deploy_stepup_flow`, `deploy_aws_saml_federation`) phải đổi sang trỏ context OpenStack.

**Verify:**
- `kubectl --context ctx-openstack -n identity get pods` — keycloak Running.
- Login `testuser01/Test1234!` tại `/login` thành công; step-up OTP vẫn ép được.
- Decision log OPA vẫn có `counter_rego_builtin_http_send_network_requests: 2` (JWKS + discovery) — chứng minh OPA vẫn tự verify chữ ký.
- `terraform destroy` + `deploy-all.sh` chạy sạch từ hạ tầng trống.

**Gate A1:** không login được, hoặc OPA không lấy được JWKS → dừng, không đi tiếp.

---

### A2. Thêm WAF ModSecurity3 + CRS (DetectionOnly)

**Việc:**
- Deployment mới `waf` trong ns `crapi` cụm AWS: nginx + ModSecurity3 + OWASP CRS, `SecRuleEngine DetectionOnly`, audit log ra stdout dạng JSON.
- Đổi `k8s/ingress.yaml` (Traefik IngressRoute): `bff:8080` → `waf:8080`; `waf` forward tới `bff:8080`.
- SPIFFE: thêm entry `spiffe://ztlab.local/aws/waf` vào `scripts/ensure-spire-entries.sh`.
- Istio: DestinationRule custom-SAN cho `waf`; AuthorizationPolicy CUSTOM → `opa-ext-authz`. PeerAuthentication: chuyển `waf` sang PERMISSIVE (nhận từ Traefik), **siết `bff` về STRICT** — hiện `bff` đang PERMISSIVE, sau khi có WAF đứng trước thì không cần nữa. Đây là một cải thiện phụ đáng giá.
- `policy/service-graph-crapi.yaml`: thêm edge `aws/waf → aws/bff` (mọi method, mọi path), regenerate.
- Promtail: job mới `waf-audit` scrape container `waf` ns `crapi`.
- Grafana: panel đối chứng trong `crapi-attack-surface.json` — **số CRS hit theo loại tấn công** đặt cạnh **số OPA deny**, và một panel riêng đếm CRS hit trên các request BOLA (kỳ vọng = 0).

**Verify:**
- Gửi SQLi vào một endpoint crAPI → CRS ghi nhận trong `waf-audit`, request **vẫn đi tiếp** (DetectionOnly), OPA vẫn quyết định bình thường.
- Chạy `tests/crapi_*.sh` kịch bản BOLA → CRS **không ghi nhận gì**, OPA/BFF vẫn xử lý như trước. Đây là số đo đối chứng cần cho luận văn — lưu lại ngay lần này.
- `tests/test_service_graph_consistency.py` vẫn 2/2 PASS.

**Gate A2:** WAF làm hỏng bất kỳ luồng nghiệp vụ crAPI nào → sửa hoặc rollback, không để tồn tại ở trạng thái nửa vời.

---

### A3. Client certificate + posture trong cert

**Tiền đề bắt buộc:** hiện hệ thống truy cập bằng **HTTP** (`http://crapi.ztlab.local`, port-forward `:18081`). Client certificate yêu cầu TLS — nên **phải bật HTTPS ở Traefik trước**. Đây là việc phát sinh chưa có trong `HETHONGCHITIET.md`, cần tính vào khối lượng.

**Việc:**
- Tạo **Device CA** riêng (không dùng chung `spire/root-ca` để giữ tách bạch device identity và workload identity). Lưu key trong Vault.
- Script `scripts/issue-device-cert.sh <user> <posture>`: phát hành client cert, xuất PKCS#12 để import vào trình duyệt. Thuộc tính posture nhúng vào cert — đề xuất dùng SAN URI `spiffe://ztlab.local/device/<device-id>` cho định danh, và một OID mở rộng hoặc trường Subject OU (`OU=posture:compliant`) cho trạng thái tuân thủ. TTL ngắn (đề xuất 7 ngày) để demo được kịch bản cert hết hạn.
- Traefik: bật TLS + `TLSOption` với `clientAuth.clientAuthType: RequireAndVerifyClientCert`, `caFiles` trỏ Device CA. Traefik forward `X-Forwarded-Tls-Client-Cert-Info`.
- WAF phải **pass-through** các header cert này (không strip).
- BFF `services/bff/main.py`:
  - Bỏ `_evaluate_device_trust` dựa User-Agent; thay bằng đọc cert đã verify → `device_id`, `posture`.
  - **Strip cứng** header `X-Forwarded-Tls-Client-Cert*` đến từ client trước khi tin — chỉ chấp nhận giá trị do Traefik gắn (giống cách đang strip `X-Device-*`).
  - Gắn `X-Device-Posture` / `X-Device-Trust` từ nội dung cert.
- OPA: giữ nguyên `posture_ok` / `device_trust_ok`. Vì không có cert hợp lệ thì **không thiết lập được kết nối TLS**, câu "toàn bộ truy cập từ thiết bị không đạt posture đều bị chặn" trong Kết quả mong đợi trở thành đúng ở tầng kết nối — không cần nới `strong_control_required`.

**Verify (3 kịch bản demo):**
1. Cert hợp lệ + `posture:compliant` → truy cập bình thường.
2. Cert hợp lệ + `posture:non-compliant` → OPA deny ở hành động ghi, có decision log.
3. Không cert / cert hết hạn / cert do CA khác ký → **TLS handshake fail**, không vào được tới BFF.

**Gate A3:** cả 3 kịch bản tái lập được sau `destroy` + `apply`.

---

### A4. Xoá phần thực thi SOAR → `incident-analyzer`

**Xoá hẳn:**
- Toàn bộ `ALLOWED_PLAYBOOKS` và code thực thi trong `services/soar-engine/main.py`: `isolate_workload`, `restrict_egress`, `block_source_ip`, `revoke_user_sessions`, `quarantine_workload`, `scale_deployment`.
- Biến `SOAR_AUTO_EXECUTE`, `SOAR_DRY_RUN`, `SOAR_ALLOWED_CONTEXTS`.
- Secret `soar-openstack-kubeconfig` (SOAR không còn cần kubeconfig cụm nào).
- `k8s/rbac/soar-rbac.yaml`, `k8s/rbac/web-portal-response-rbac.yaml` — bỏ quyền `patch deployments/services`. ServiceAccount mới chỉ cần quyền đọc.
- Endpoint `/cases/{id}/approve|deny|choose-action`.

**Gộp thành `services/incident-analyzer/`:**
- Giữ `POST /grafana-webhook` → tạo bản ghi **evidence** (thay cho `CaseRecord`).
- Kéo về từ `ai-analyzer`: map log → kỹ thuật ATT&CK.
- Kéo về từ `security-scorer`: chấm điểm ưu tiên theo RULES.
- **Bổ sung mới:** truy vấn Loki lấy log quanh thời điểm cảnh báo (±5 phút, các job `opa-decisions`, `envoy-access`, `bff-audit`, `waf-audit`) → đóng gói thành bundle bằng chứng.
- Gửi email qua SMTP MailHog (secret từ Vault) kèm bundle. Không có nút phê duyệt, không có hành động.
- Chừa sẵn một endpoint để **module ML ở Giai đoạn C cắm điểm rủi ro vào** — đây là lý do không xoá sạch cả ba service.

**Cập nhật kèm:** `notification-policy.yml` → `incident-analyzer.plg-stack:8080/grafana-webhook`; Promtail job `soar-engine` → `incident-analyzer`; dashboard `ztlab-soar-dashboard` đổi tên; các panel "SOAR actions" trong `crapi-attack-surface.json` đổi thành "evidence bundles".

**Verify:** chạy `tests/crapi_run_all.sh` → Grafana Firing → `incident-analyzer` tạo evidence bundle + gửi email, và **không có bất kỳ thay đổi nào trên cụm** (`kubectl get svc,deploy -n crapi` không đổi trước/sau).

---

### A5. Hai việc bắt buộc, không cần quyết định

**A5.1 — Kiểm tra `destination_principal` có trong decision log.**
Nhóm đặc trưng B của đề cương cần "số danh tính đích khác nhau". OPA input có `destination_principal` (§8.3) nhưng pipeline Promtail hiện chỉ parse `request_path` thành label. Nếu trường này bị rơi, phải sinh lại toàn bộ dataset.

```bash
logcli query '{job="opa-decisions"}' --limit=1 -o raw | jq '.input.attributes.destination'
```

Nếu thiếu → sửa `decision_logs` config của OPA và pipeline Promtail **ngay trong Giai đoạn A**.

**A5.2 — Cơ chế gắn nhãn theo lần chạy.**
Wrapper `tests/crapi_run_campaign.sh`, mỗi lần chạy ghi một dòng vào `runs.jsonl`:

```json
{"run_id":"<uuid>","scenario":"bola_vehicle_location","t_start":"...","t_end":"...","target_entity":"<user|svid>"}
```

**Tuyệt đối không tiêm header đánh dấu vào lưu lượng tấn công.** Một header như `X-Campaign-Id` sẽ trở thành đặc trưng rò rỉ hoàn hảo — mô hình học đúng cái header đó thay vì học hành vi, đúng loại lỗi mà Arp và cộng sự [17] cảnh báo và chính đề cương đã cam kết kiểm tra bằng shortcut learning test. Gán nhãn **offline**, join theo cặp (entity, khoảng thời gian).

---

## GIAI ĐOẠN B — SINH DỮ LIỆU

Chỉ bắt đầu khi tất cả gate của Giai đoạn A đã qua và kiến trúc được đóng băng (tag một commit làm mốc).

### B1. Load generator lưu lượng nền
Chưa tồn tại — phải viết. Yêu cầu: mô phỏng nhiều người dùng crAPI với hành vi đa dạng (duyệt sản phẩm, đăng bài community, đặt lịch workshop, xem xe), kèm vài kịch bản hành vi khác thường lành tính để dữ liệu không quá đơn điệu (đúng như Bước 3 đề cương). Mỗi phiên người dùng phải đăng nhập thật qua Keycloak để sinh telemetry đầy đủ.

### B2. Đánh dấu phiên thu thập hợp lệ
Vì 150 giờ được cộng dồn: `scripts/capture-session.sh start|stop` đẩy marker vào Loki (job `capture-session`). Script gán nhãn chỉ giữ window **nằm trọn trong một phiên hợp lệ**, loại bỏ window bị cắt do sập tunnel. Ghi lại tổng số giờ hợp lệ tích luỹ và các khoảng gián đoạn — số này đưa vào luận văn.

### B3. Sinh lưu lượng tấn công
Mở rộng 5 script hiện có thành ≥100 lần chạy độc lập, có biến thể tham số. **Giữ riêng một nhóm biến thể chỉ dùng cho tập test** để phục vụ tiêu chí "giữ ≥70% recall trên biến thể chưa từng thấy".

### B4. Đo độ trễ (làm ngay đầu Giai đoạn B, đừng để cuối)
Hai phép đo tách biệt:
- **Overhead Zero Trust** — so p99 của cùng một hop nội cụm AWS có và không có sidecar+PDP. Đây là con số áp ngưỡng 20ms.
- **Độ trễ cross-cloud** — lấy từ `response_time` trong `envoy-access` trên các hop đi OpenStack. Báo cáo riêng như đặc tính kiến trúc hybrid.

Đo sớm vì nếu overhead thật vượt 20ms thì phải sửa đề cương trước khi bảo vệ, không phải sau.

---

## GIAI ĐOẠN C — MÔ HÌNH MACHINE LEARNING

Chạy song song từ Giai đoạn A: SV2 phát triển bộ trích xuất đặc trưng trên dữ liệu mô phỏng theo lược đồ log đã thống nhất (đúng như phần Kế hoạch thực hiện của đề cương đã viết), không chờ hạ tầng.

Nội dung giữ nguyên như Bước 4 đề cương: XGBoost, ba cấu hình (baseline ngưỡng / nhóm A / A+B), chia dữ liệu theo thời gian có buffer, đánh giá PR-AUC + recall tại FPR 1%, kiểm tra shortcut learning, SHAP. Kết quả chấm điểm cắm vào endpoint đã chừa sẵn ở `incident-analyzer`.

---

## SỬA ĐỀ CƯƠNG (v9)

Sau các quyết định trên, **ba trong bốn điểm lệch tự hết** — không cần sửa câu chữ:
- Keycloak chuyển sang OpenStack → lập luận Nghị định 53 lành lại.
- Chứng chỉ thiết bị thật → câu "chứng chỉ thiết bị kèm posture" (Bước 1) và "toàn bộ … thiết bị không đạt posture đều bị chặn" (Kết quả mong đợi) trở thành đúng.
- Thêm CRS → câu ở mục Ngoài phạm vi trở thành đúng.

Còn lại cần sửa:

1. **Kết quả mong đợi, gạch đầu dòng "Ảnh hưởng vận hành"** — tách phép đo: ngưỡng 20ms áp cho overhead mTLS + ủy quyền tập trung đo trên hop nội cụm; độ trễ do kiến trúc hybrid cross-cloud báo cáo như chỉ số độc lập.
2. **Mục tiêu bullet 1 và Bước 1** — nói rõ Keycloak đặt trên OpenStack cùng dịch vụ định danh. Câu này biến việc chuyển Keycloak từ "chi tiết kỹ thuật" thành "quyết định thiết kế có căn cứ pháp lý", củng cố hẳn phần Phạm vi.
3. **Mục tiêu bullet 5 và Bước 5** — nói rõ đầu ra là cảnh báo kèm **bằng chứng đã được phân tích và chấm mức ưu tiên**, gửi tới người vận hành; hệ thống không có cơ chế thực thi hành động. Diễn đạt hiện tại hơi mơ hồ, dễ bị hiểu là có SOAR.
4. **Mục Ngoài phạm vi** — thêm một câu: CRS chạy ở chế độ ghi nhận, dùng làm đối chứng cho thấy phương pháp dựa trên chữ ký không phát hiện được lớp tấn công vượt quyền. Câu này biến WAF từ "thành phần phụ" thành "thành phần phục vụ luận điểm".

---

## RỦI RO CẦN THEO DÕI

| Rủi ro | Ảnh hưởng | Giảm thiểu |
|---|---|---|
| Security group OpenStack chưa mở NodePort cho nguồn từ WireGuard | Chuyển Keycloak xong không login được | Kiểm tra `neutron-sg-os-private` **trước** khi chuyển, không phải sau |
| Bật HTTPS ở Traefik là việc phát sinh chưa lường trong A3 | Trượt tiến độ Giai đoạn A | Làm A3 sau A1/A2/A4; nếu kẹt, tách riêng phần TLS làm bước độc lập |
| Uplink hotspot rớt giữa đợt thu thập dài | Mất giờ dữ liệu | `capture-session` marker + `wg-watchdog` đã có; chấp nhận cộng dồn |
| Overhead Zero Trust thực đo vượt 20ms | Sai tiêu chí nghiệm thu | Đo ở B4 (sớm), còn kịp sửa đề cương |
| Thêm WAF + client cert làm đổi đường request | Dataset sinh trước vô giá trị | Đã xử lý bằng nguyên tắc đóng băng kiến trúc trước |
| `destination_principal` không có trong decision log | Mất nhóm đặc trưng B, phải sinh lại toàn bộ | Kiểm tra ở A5.1, trước mọi việc thu thập |

---

*Nguồn đối chiếu: `DeCuongChiTiet_KLTN_ZTA_v8.docx`; `HETHONGCHITIET.md` (2026-09-10); KLTN "Tăng cường bảo mật cho các hệ thống ứng dụng hướng service và microservice sử dụng học sâu và Zero Trust", Trần Thị Mỹ Huyền – Ngô Tuấn Kiệt, UIT 2025 (Bảng 4.1 tr.70, §4.2.1.5 tr.72).*
