# AUDIT THỰC THI — mọi chính sách có thật sự chạy?

> Phần 2 của nhiệm vụ "hoàn thiện hệ thống" (2026-09-18/19). Lý do tồn tại
> file này: hệ thống đã có HAI trường hợp độc lập của cùng một lớp lỗi —
> chính sách tồn tại trong manifest, deploy thành công, hiện diện khi
> `kubectl get`, nhưng KHÔNG BAO GIỜ được thực thi (bug WAF Host-header rơi
> vào PassthroughCluster bỏ qua mТLS+OPA không log; `waf-opa-authz` chưa
> từng được Envoy gọi — cả hai đã sửa ở Phần 1.3 trước đó). Vì vậy KHÔNG
> chính sách nào dưới đây được coi là "đang hoạt động" chỉ vì nó tồn tại —
> mỗi dòng có bằng chứng thực nghiệm (đường từ chối thật sự từ chối + việc
> đánh giá thật sự xảy ra). Ngày đo ghi ở từng mục: §3 đo 2026-09-26 và lặp lại 2026-10-04; **§6 viết lại hoàn toàn
> 2026-10-04 trên cụm dựng từ trống** (bản §6 cũ dựa trên một phiên mà cụm chưa từng có Loki/Grafana —
> nên khẳng định "9/9 verify sống" của nó không có cơ sở và đã bị xoá).
>
> Quy ước cột **Thực thi**: ✅ THẬT (có bằng chứng cả 2 chiều — deny thật +
> evaluate thật) · ⚠️ MỘT PHẦN (deny/evaluate thật nhưng có giới hạn/ngoại lệ
> đã biết, ghi rõ) · ❌ CHỈ TÀI LIỆU/DEAD (tồn tại nhưng không chặn gì thật).

## 1. AuthorizationPolicy (Istio)

| Tên | File | Selector/Provider | Thực thi | Bằng chứng |
|---|---|---|---|---|
| `bff-opa-authz` | istio-policies.yaml | app=bff, CUSTOM opa-ext-authz | ✅ THẬT | `tests/crapi_run_all.sh` 7/7 PASS dùng hop này liên tục; RBAC/service_acl deny xác nhận qua crapi_bfla.sh (403 khi crapi-user gọi endpoint admin); decision log `job=opa-decisions,source_principal=aws/waf,destination_principal=aws/bff` có thật với `opa_result` cả true/false. |
| `crapi-community-opa-authz` | istio-policies.yaml | app=crapi-community | ✅ THẬT | `crapi_lateral_movement.sh`: exec vào community gọi thẳng workshop → OPA chặn 5/5 (403), decision log deny thật. Đường allow: BOLA/business traffic qua bff→community 200 bình thường. |
| `crapi-workshop-opa-authz` | istio-policies.yaml | app=crapi-workshop | ✅ THẬT | Đối chứng trực tiếp 2026-09-18: `nc`/`curl` thẳng từ crapi-web (ngoài service_acl) tới workshop → OPA trả 403; cùng request từ waf/bff qua đường hợp lệ → 200/401 tuỳ session. |
| `crapi-identity-opa-authz` | istio-policies.yaml | app=crapi-identity (OpenStack) | ✅ THẬT | Login OIDC thật qua Gateway → BFF → identity (OpenStack) → 200, đồng thời cross-cloud decision log opa_result=true xuất hiện trên OS opa. |
| `waf-opa-authz` | waf.yaml | app=waf | ✅ THẬT (đã sửa Phần 1.3, xem lịch sử) | Trước đây DEAD (Traefik→waf không SPIFFE, marker không hoạt động). Sau khi thay bằng Istio IngressGateway: decision log `source_principal=aws/edge-gateway,destination_principal=aws/waf` có thật, liên tục, cho mọi request qua Gateway (xác nhận lại 2026-09-18 khi chạy crapi_bola.sh/crapi_sqli_waf.sh). |
| `keycloak-opa-authz` | keycloak-mesh-policies.yaml | app=keycloak (OpenStack) | ✅ THẬT | **Suýt bị bỏ sót khi chỉ đọc istio-policies.yaml/waf.yaml** (Phần 1.2 audit) — xác nhận bằng đo trực tiếp Loki `job=envoy-access, path="/envoy.service.auth.v3.Authorization/Check"`, đối chiếu `source_ip` → pod Keycloak (10.42.1.4) thật sự gọi opa-service:9191. Login OIDC thật (BFF→Keycloak) phụ thuộc hop này — nếu dead thì login đã hỏng hoàn toàn (không hỏng). |
| `opa-inbound-allow` (MỚI, Phần 1.2) | opa.yaml | app=opa, action: ALLOW | ✅ THẬT | Xem mục 2 (PeerAuthentication) — cùng một cụm bằng chứng: RBAC allowed=151/denied=4→0 sau khi sửa bug double-prefix `spiffe://spiffe://`; test tiêu cực trực tiếp: crapi-web (không trong allow-list) gọi opa-service:9191 → 403; GET 8181/health → 200 (đúng thiết kế permissive có chủ đích); PUT 8181/v1/policies → 403 (chặn ghi). |

**Kết luận nhóm AuthorizationPolicy: 7/7 THẬT, không có object dead.** Đây là
nhóm được audit kỹ nhất — 2 case dead trước đó (waf-opa-authz, PassthroughCluster)
đã đóng ở Phần 1 trước, và Phần 1.2 lần này tự phát hiện 1 bug tương tự lúc
mới thêm chính sách (double `spiffe://` prefix khiến `opa-inbound-allow` bị
Envoy RBAC deny toàn bộ ngay khi mới bật — vá trong vài phút nhờ đo trực tiếp
`pilot-agent request GET stats | grep rbac`, không phải đoán).

## 2. PeerAuthentication (Istio)

| Tên | File | Scope | Thực thi | Bằng chứng |
|---|---|---|---|---|
| `default` (STRICT) | istio-policies.yaml | ns crapi, toàn bộ | ✅ THẬT | Mọi test không-mТLS trực tiếp (curl HTTP trần) tới workload có sidecar đều fail; xác nhận qua `istioctl proxy-config` + hàng trăm request test suốt Phần 1/2 đều đi qua mТLS. |
| `crapi-web-permissive` | istio-policies.yaml | app=crapi-web | ⚠️ MỘT PHẦN (có chủ đích) | PERMISSIVE vì crapi-web phục vụ cả traffic mesh (bff) và debug port-forward — không phải điểm enforce authz thật (crapi-web không có business logic nhạy cảm, chỉ static). Không phải dead, đúng lý do tồn tại từ A1/A2. |
| `bff-strict` | bff.yaml | app=bff | ✅ THẬT | mọi request trực tiếp (không qua waf, không mТLS) tới bff bị từ chối; chỉ waf (đúng service_acl) vào được (xem mục 1.6 dưới, verify sống 2026-09-18: crapi-web/crapi-community gọi thẳng bff:8080 → OPA 403 trên path nghiệp vụ). |
| `waf-strict` | waf.yaml | app=waf | ✅ THẬT | Traefik/plaintext không còn tồn tại; chỉ Istio Gateway (mТLS client-cert) reach được — 4/4 kịch bản certificate (`tests/crapi_cert_scenarios.sh`) verify sống PASS. |
| `keycloak-strict` | keycloak-mesh-policies.yaml | app=keycloak | ✅ THẬT | Không có ngoại lệ PERMISSIVE nào; login OIDC thật hoạt động (mọi caller — bff, opa AWS, 5 pod kc-admin-setup — đều trong mesh). |
| `opa-strict` (MỚI, Phần 1.2) | opa.yaml | app=opa, portLevelMtls 8181→PERMISSIVE | ✅ THẬT (9191) / ⚠️ MỘT PHẦN CÓ CHỦ Ý (8181) | 9191 (kênh ext_authz thật): STRICT xác nhận qua `istioctl proxy-config listener` — CHỈ 1 filter chain `transport_protocol: tls`, không có raw_buffer fallback. 8181: PERMISSIVE có chủ đích (security-healthcheck CronJob ns=spire không vào mesh) nhưng bù bằng AuthorizationPolicy giới hạn CHỈ GET /health — verify: PUT /v1/policies → 403 dù không cần SPIFFE. |

**Kết luận nhóm PeerAuthentication: 6/6 THẬT hoặc có ngoại lệ tài liệu hoá rõ
ràng, không có dead.**

## 3. NetworkPolicy (kube-router, k3s embedded) — VIẾT LẠI 2026-09-26

> **Mục này thay hoàn toàn bản 2026-09-18/19.** Hai kết luận cũ đều đã bị đo bác bỏ:
> (a) "kube-router không enforce đáng tin cậy nói chung" (2026-09-18) và (b) "rule
> podSelector/namespaceSelector vô hiệu vì node thiếu `ipset`, nên ngừng apply
> pod-segmentation" (2026-09-19). Bằng chứng thô: `results/round3/` (mỗi mệnh đề bên
> dưới có file/lệnh kèm theo). Lịch sử điều tra: `HAN-CHE-VA-HUONG-PHAT-TRIEN.md` H3, H5.

### 3.1 Giả thuyết ipset — SAI (3 bằng chứng độc lập)

1. **Cơ chế:** `PATH` của tiến trình k3s = `/var/lib/rancher/k3s/data/<hash>/bin:/usr/local/sbin:…`
   (đọc từ `/proc/<pid>/environ`); thư mục bin của k3s có sẵn binary `ipset` (198 KB)
   và đứng TRƯỚC `/usr/sbin`. `command not found` của vòng 2 là do shell SSH tương tác,
   không phải môi trường của kube-router. Các ipset `KUBE-SRC-*`/`KUBE-DST-*` có đủ IP pod.
2. **A/B thực nghiệm:** cài `ipset` lên host (16:40) KHÔNG đổi kết quả `waf → bff` (vẫn
   503); thêm cổng 8080 vào egress baseline (không đổi ipset) đổi 503 → 200.
3. **Probe cô lập** (`tests/netpol_podselector_probe.sh`, ns tạm, 1 policy `podSelector`):
   cả 2 cụm, cùng node và khác node **8/8 MATCH** — trước policy cả 2 nguồn tới được,
   sau policy nguồn được phép tới được, nguồn không được phép bị `reject` (curl exit 7).
   (`results/round3/podselector_probe_{aws,openstack}.txt`)

*Giới hạn thành thật:* không có phép thử trực tiếp trên node đã gỡ `ipset` (thao tác gỡ
gói bị hệ thống từ chối trong phiên này); phần đó được chứng minh bằng cơ chế PATH.

### 3.2 Nguyên nhân thật của sự cố `waf → bff` 503 ("mesh-connectivity")

Baseline `{aws,os}-crapi-allow-baseline` có `podSelector: {}` + `policyTypes: [Ingress,
Egress]` ⇒ MỌI pod ns `crapi` bị default-deny cả 2 chiều. Danh sách cổng egress
"nội bộ crapi" viết tay thiếu **8080** (cổng của bff/waf) ⇒ SYN của waf bị `reject` tại
chain firewall của **pod nguồn** (đo: counter `reject` trong `KUBE-POD-FW-*` của waf tăng
đúng theo số request). Sửa: cổng egress nội ns được **tính ra từ edge service-graph**
(`scripts/gen-networkpolicy.py::_intra_ns_egress_ports`) + test hồi quy
`test_baseline_egress_covers_every_intra_namespace_edge_port`.

### 3.3 Ma trận thực nghiệm đầy đủ (`tests/netpol_matrix.sh`, 22 ô — 14 MATCH / 8 MISMATCH)

Đo L4 sạch: từ container `istio-proxy` của pod nguồn tới POD IP đích (curl exit 7 =
reject, 28 = drop, còn lại = TCP connect thành công). Kỳ vọng rút từ service-graph.

| Dạng rule | Ô | Kết quả |
|---|---|---|
| **A2** namespaceSelector KHÁC ns | `default/probe → bff:8080`, `→ opa:8181` (không được phép) | **BỊ CHẶN đúng** (exit 7) — 2/2 |
| **A2** | `monitoring/probe → bff:8080`, `→ opa:8181` (được phép) | tới được đúng — 2/2 |
| **A3** ipBlock cross-cloud | community → OpenStack NodePort 30090 (được phép) | tới được đúng |
| **A3** | community → OpenStack k3s-API :6443, ssh :22 (không được phép) | **BỊ CHẶN đúng** (exit 7); ô đối chứng từ pod ngoài policy tới được ⇒ cổng đích tự nó mở, chính policy chặn |
| **A1** podSelector cùng ns — được phép | waf→bff, bff→workshop, bff→redis, community→mongodb, crapi-web→opa:9191 | tới được đúng — 5/5 |
| **A1** — KHÔNG được phép | crapi-web→bff, community→bff, crapi-web→workshop, crapi-web→redis, community→redis, crapi-web→mongodb, bff→mongodb, monitoring→redis | **VẪN TỚI ĐƯỢC — 8/8 MISMATCH** |

### 3.4 Phát hiện mới: rule egress của baseline làm thủng ingress default-deny cùng ns

Tất cả 8 MISMATCH có chung đặc điểm: nguồn nằm TRONG ns `crapi` (hoặc `monitoring → redis`)
và cổng đích nằm trong danh sách egress của baseline (80, 6379, 8000, 8080, 8087, 8181,
9191, 27017). Nguồn nằm ngoài ns bị chặn đúng. Thí nghiệm cô lập (biến thể
`egress-shadow` của `tests/netpol_podselector_probe.sh`, ns tạm, 2 policy: một
"baseline-like" `podSelector: {}` Ingress+Egress với egress "cùng ns :80" và không có
rule ingress, một policy chỉ cho `a` vào `srv`): `a → srv` thông (đúng) nhưng **`c → srv:80`
cũng thông (SAI theo đặc tả NetworkPolicy)**, cả cùng-node lẫn khác-node. Kết luận: kube-router
đang áp rule egress của policy chọn mọi pod thành "cho phép" ở phía ingress của pod đích.
Điều này giải thích quan sát cũ ở §3.2 gốc ("crapi-web → redis vẫn OPEN dù ipset đúng") mà
trước đây bị quy cho "nf_tables nói chung".

**Chưa sửa** (rủi ro làm gãy deploy ở vòng cuối; xem `HAN-CHE-VA-HUONG-PHAT-TRIEN.md` H3):
hướng đúng là tách egress theo từng pod nguồn theo edge, kèm rà lại egress của
posture-agent/seed job/sidecar.

### 3.5 Bảng hiệu lực THẬT (thay bảng compensating control cũ)

| Lớp | Hiệu lực | Ghi chú |
|---|---|---|
| L4, nguồn NGOÀI ns `crapi` → pod `crapi` | ✅ THẬT | đo: default/monitoring chỉ vào đúng cổng baseline cho phép |
| L4, egress cross-cloud (ipBlock) | ✅ THẬT | đo: chặn k3s-API/ssh của node OpenStack |
| L4, phân đoạn TRONG ns `crapi` (pod-segmentation) | ❌ KHÔNG hiệu lực ở các cổng nằm trong egress baseline | §3.4 |
| L7 mTLS STRICT + OPA `service_acl` | ✅ THẬT — lớp phân đoạn nội ns duy nhất đáng tin | 7/7 kịch bản PASS (`results/round3/crapi_run_all-1.log`) |
| redis `--requirepass`, mongod `--auth` | ✅ compensating control cho đích không sidecar | vì L4 nội ns không chặn được crapi-web → redis/mongodb |
| postgresdb | ⚠️ suy từ hành vi image chuẩn, chưa tự thử không mật khẩu | ghi rõ mức tin cậy thấp hơn |
| mailhog | ❌ không có | test double có chủ đích |

### 3.6 Hành động tài liệu/IaC

- `deploy-crapi.sh::apply_network_policies` apply lại `{aws,os}-pod-segmentation.yaml`
  (đảo ngược quyết định 2026-09-19); baseline + pod-segmentation cùng được apply.
- KHÔNG đưa task cài `ipset` vào Ansible (không giải quyết gì).
- Header trong các file YAML sinh ra và `HE-THONG-CHI-TIET.md` §4.4/§8.1/§10 đã sửa theo.

## 4. Gatekeeper (OPA admission control)

| Constraint | Trước | Sau | Thực thi |
|---|---|---|---|
| `ZTLabRequireNonRoot` | `financial-require-nonroot`, namespace `financial` (**namespace đã bị xoá từ migration crAPI, không còn pod nào**) | `crapi-require-nonroot`, namespace `crapi`, enforcementAction: **dryrun** (có chủ đích) | ❌→⚠️ Trước: DEAD (0 violations vì không có gì để kiểm, không phải vì tuân thủ — case thứ 3 của "chính sách tồn tại, deploy OK, không hề thực thi"). Sau: THẬT ĐANG AUDIT — `kubectl get constraint` xác nhận **12 violation thật** (bff/waf/opa/crapi-web/community/workshop/identity/mongodb/redis/postgresdb/mailhog/posture-agent đều thiếu `runAsNonRoot`). Giữ dryrun có chủ đích: bật `deny` ngay chặn TOÀN BỘ pod hệ thống (không workload nào đã hardening) — đúng bài học cũ (payment-service làm gãy Envoy sidecar). |
| `ZTLabRequireImagePolicy` | `financial-require-image-policy`, namespace `financial` (dead, lý do như trên) | `crapi-require-image-policy`, namespace `crapi`, enforcementAction: **deny** | ✅ THẬT — 0 violation thật (hầu hết image ghim `@sha256`, số còn lại ghim tag cụ thể, không dùng `:latest`). **Verify enforcement thật**: `kubectl run --image=alpine:latest -n crapi --dry-run=server` → admission webhook denied thật (không phải suy đoán). |

**Kết luận: 2/2 constraint TỪNG DEAD (case thứ 3, đúng như task dự đoán), đã
retarget về namespace thật đang chạy. 1/2 nay enforce thật (deny), 1/2 giữ
audit-only có chủ đích với lý do kỹ thuật cụ thể (không phải bỏ quên).**

## 5. WAF — ModSecurity3 + OWASP CRS (DetectionOnly)

| Khía cạnh | Thực thi | Bằng chứng |
|---|---|---|
| CRS bắt được chữ ký tấn công (SQLi/XSS/LFI) | ✅ THẬT | `tests/crapi_sqli_waf.sh`: 3 probe injection → CRS ghi nhận (`attack-sqli`, `attack-xss`, `attack-lfi/rce`), request vẫn đi tiếp (DetectionOnly, không chặn — đúng thiết kế). |
| CRS KHÔNG bắt lỗ hổng vượt quyền (BOLA) — phép đo đối chứng trung tâm của khoá luận | ✅ THẬT, TẤT ĐỊNH (Phần 1.1) | `tests/crapi_bola.sh` 3 lần liên tiếp cùng kết quả (CRS hit = 0 cả 3 lần) sau khi sửa `loki_count()` dùng khoảng thời gian tường minh [T0,T1] thay vì cửa sổ trượt 10 phút (nguyên nhân gốc của FAIL=4 giả trước đây). |
| CRS exclusion (`waf-crs-exclusions`, rule 921140 trên `x-forwarded-client-cert`) không làm yếu phát hiện thật | ✅ THẬT | `crapi_sqli_waf.sh` vẫn PASS đầy đủ sau khi có exclusion — chỉ 1 rule/1 header bị loại trừ, không ảnh hưởng SQLi/XSS/LFI thật. |

## 6. Grafana Alert Rules (folder ZTLab, eval 1m) — VIẾT LẠI 2026-10-04

Phương pháp (`tests/alerts_verify_all.sh`, chạy tuần tự, mỗi rule một kịch bản kích hoạt thật): đợi rule về không-Firing → ghi T0 →
kích hoạt → (vế 1) rule chuyển **Firing** theo API ruler của Grafana → (vế 2) **bằng chứng thông báo thật** sau T0: evidence bundle ở
incident-analyzer (rule `category=security`, đường webhook) hoặc email trong hộp thư SOC MailHog (rule `category=infrastructure`/`health`,
đường email của Grafana). Dữ liệu thô: `results/closeout/alerts/verify-all-*.log`, `run.log`, `run2-infra.log`.

| # | Rule | Kích hoạt | Firing (giây sau kích hoạt) | Bằng chứng thông báo | Thực thi |
|---|---|---|---|---|---|
| 1 | crAPI — Lateral Movement | `crapi_lateral_movement.sh` | 18 s | bundle `ev-20261004050655-de1034` (`lateral_movement`), email gửi | ✅ THẬT |
| 2 | crAPI — Access Denied Spike | `crapi_access_denied.sh` | 25 s | bundle `ev-20261004051805-6b05ba` (`access_denied`) | ✅ THẬT |
| 3 | crAPI — Brute Force | `crapi_brute_force.sh` | 13 s | bundle `ev-20261004051925-31ad2b` (`brute_force`) | ✅ THẬT |
| 4 | crAPI — BFLA | `crapi_bfla.sh` | 43 s | bundle `ev-20261004052055-31d3f7` — **`attack_type=access_denied`** dù tên alert là BFLA (nhãn cho Giai đoạn C cần lấy theo `alert_name`) | ✅ THẬT |
| 5 | Data Exfiltration — Large Response (T1041) | `crapi_large_response.sh` (response > 1 MB) | ≤ 5 s | bundle `ev-20261004052235-645354` (`large_response`) | ✅ THẬT |
| 6 | Privilege Escalation in Container (T1068) | `crapi_privilege_escalation.sh` (security-scanner Job) | ≤ 5 s | bundle `ev-20261004052415-efce5a` (`privilege_escalation`) | ✅ THẬT |
| 7 | Mesh Integrity | 1 kết nối plaintext thật vào cổng STRICT (uid 1337 của bff → crapi-workshop:8000) | 90 s | email `[ZTLab INFRA] Mesh Integrity …` 05:36:07Z (17 s sau Firing) | ✅ THẬT — **sau khi sửa SMTP** (xem dưới) |
| 8 | Security Control-Plane Down | tiêm lỗi phía bộ kiểm: Job sao chép CronJob `security-healthcheck` với `OPA_URL` trỏ cổng không tồn tại → `status=critical` thật trong log (OPA thật không bị tắt — PDP fail-closed) | ≤ 60 s | email `[ZTLab INFRA] Security Control-Plane Down …` 05:34:23Z và 05:44:40Z | ✅ THẬT — lần kiểm thứ hai email tới 4 s sau cửa sổ chờ 240 s do `group_interval 5m` của route hạ tầng (nhóm đã gửi lúc 05:34:23) |
| 9 | Incident Analyzer — Health Check | tự Firing khi có bundle trong 10 phút | Firing 05:49:50Z sau một bundle mới | email `[ZTLab SECURITY] Incident Analyzer — Health Check …` 05:33:52Z, 05:39:40Z | ✅ THẬT (email lấy từ lần Firing trước trong cùng 15 phút) |

**Kết luận: 9/9 rule có bằng chứng sống hai vế trên cụm 2026-10-04.** Hai rule mới ngoài danh sách 9 (`Log Pipeline Silent`, `Health-Check
Silent`) dùng cùng đường email hạ tầng nay đã thông, nhưng **chưa được kích hoạt thử** trong vòng này (cần ≥ 10 phút im lặng nhân tạo).

**Phát hiện khi viết lại mục này (H7 ca 6):** lần chạy đầu, rule Mesh Integrity Firing đúng nhưng không có email nào: API receivers của
Grafana cho thấy MỌI integration email đều thất bại `535 Username and Password not accepted` — SMTP trỏ Gmail với mật khẩu rỗng. Các rule
`category=infrastructure` chỉ có đường email nên **chưa từng báo tới ai**; rule bảo mật vẫn tới SOC nhờ webhook. Sửa trong code:
`k8s/plg-stack/grafana.yaml` trỏ SMTP vào MailHog `plg-stack`, người nhận `soc-admin@ztlab.local`. Ngoài ra script kiểm phải giải mã tiêu đề
MIME (`=?utf-8?…`) — bản đầu so chuỗi trên tiêu đề đã mã hoá.

## 7. Tóm tắt phát hiện + xử lý

| # | Phát hiện | Loại lỗi | Xử lý |
|---|---|---|---|
| 1 | `opa-inbound-allow` mới thêm bị double-prefix `spiffe://spiffe://` → RBAC deny toàn bộ PDP | Bug thật, phát hiện NGAY khi verify (không phải sau này) | Sửa tại chỗ, verify lại — xem Phần 1.2 |
| 2 | Gatekeeper 2 constraint trỏ namespace `financial` đã xoá | Dead policy (case thứ 3) | Retarget `crapi`, xác nhận compliance thật trước khi chọn enforcementAction |
| 3 | NetworkPolicy baseline rule rỗng cổng nuốt phân đoạn per-destination | Bug thiết kế policy | Xoá rule, verify — nhưng phát hiện thêm #4 |
| 4 | ~~Kube-router/nf_tables không enforce đáng tin cậy~~ rồi ~~thiếu ipset~~ — **SỬA LẠI 2026-09-26**: cả hai chẩn đoán đều sai. Nguyên nhân thật: egress baseline thiếu 8080 (503) + rule egress baseline làm thủng ingress cùng ns (§3.3–3.4) | Bug thật, đã đo | Sửa cổng egress (sinh từ edge); apply lại pod-segmentation; lỗ ingress nội ns của kube-router ghi vào Hạn chế H3, chưa sửa |
| 5 | Nghi vấn ban đầu "MongoDB không --auth" | Nhận định sai của chính audit này | Kiểm lại trước khi sửa — phát hiện auth đã chạy đúng, KHÔNG đổi gì (tránh phá vỡ cái đang đúng) |
| 6 | Mesh Integrity alert báo giả + không bắt được kết nối plaintext | Bug alert rule | Sửa 2026-09-29 (H2): lọc `direction=inbound` + vế NR |
| 7 | Kênh email của Grafana chết (SMTP Gmail mật khẩu rỗng) — alert hạ tầng không báo tới ai | Dead channel (H7 ca 6) | SMTP → MailHog; 9/9 rule kiểm sống hai vế 2026-10-04 (§6) |

Không có mục nào trong Phần 2 còn ở trạng thái "chưa rõ" — mọi phát hiện đều
đã sửa (nếu có thể trong phạm vi hợp lý) hoặc ghi rõ giới hạn có chủ đích kèm
lý do kỹ thuật cụ thể.
