# KẾT QUẢ THỰC THI — thay finance app → crAPI

> Log từng Phase. Mẫu như `KET-QUA-KIEM-TRA.md`: lệnh + output thật, không tóm tắt bằng trí nhớ.

---

## GATE 0 — Đọc source crAPI (2026-09-09)

### Giả định vs Thực tế

| # | Giả định (KE-HOACH §1) | Thực tế (đọc source) | Hệ quả |
|---|---|---|---|
| 1 | Port identity/community/workshop/web = 8080/8087/8000/80 | ✅ đúng (`*/config.yaml SERVER_PORT`, `*/deployment.yaml containerPort`) | — |
| 2 | community/workshop có DB riêng | ❌ **SAI** — `services/workshop/crapi/user/models.py`: `class User … Meta.db_table = "user_login"`, `managed = settings.IS_TESTING` (=False); `UserDetails→user_details`, `Vehicle→vehicle_details`. community `seeder.go`: `models.FindAuthorByEmail()` query Postgres. **community + workshop đọc THẲNG bảng của identity trong Postgres dùng chung.** | **DB-1 (tách Postgres) BẤT KHẢ THI nếu không fork crAPI.** → chuyển **DB-2**: 1 Postgres `crapi` duy nhất, đặt ở **OpenStack** (Nghị định 53 — toàn bộ dữ liệu ở OpenStack). MongoDB ở AWS. |
| 3 | community/workshop verify JWT bằng pubkey local | ❌ — cả 2 gọi `POST http://<IDENTITY_SERVICE>/identity/api/auth/verify` **mỗi request** (`services/community/api/auth/token.go`, `services/workshop/utils/jwt.py`), rồi `jwt.decode(..., verify_signature=False)` lấy `sub`, `User.objects.get(email=sub)` / `CheckTokenInDB`. | Edge `service_acl`: `community→identity` + `workshop→identity` phải allow `POST /identity/api/auth/verify`. Thêm 2 hop cross-cloud HTTP mỗi request. |
| 4 | Khoá ký JWT của crAPI dùng được để mint | ✅ `deploy/k8s/keys/jwks.json` = **RSA private key đầy đủ** (`d,p,q,dp,dq,qi`), `alg RS256`, `kid MKMZkDenUfuDF2byYowDj7tW5Ox6XG4Y1THTEGScRg8`, `use sig`. identity `JwtProvider.generateJwtToken`: claims `sub`(email), `iat`, `exp`, `role`(string, `user.getRole().getName()`); KHÔNG có `aud`/`iss`. `validateJwtToken`: nhánh RS256 verify bằng pubkey nhúng. | **bff mint RS256** `{sub, role, iat, exp}` bằng key này, `kid` như trên. identity chấp nhận. (crAPI có sẵn lỗ hổng HS256-confusion + JKU injection — giữ nguyên, đó là challenge crAPI.) |
| 5 | Seed phức tạp | ✅ đơn giản — `POST /identity/api/auth/signup` ghi `user_login`/`user_details` vào Postgres dùng chung → community + workshop thấy ngay. `POST /identity/api/auth/reset-test-users` + `/unlock` cũng có. `GET /identity/api/auth/jwks.json` identity tự publish JWKS. | seed Job = loạt signup + add_vehicle + tạo product/coupon. |
| 6 | Ảnh gốc chịu istio-proxy sidecar | ⚠️ CHƯA test — Phase 1 test `crapi-identity` trước (Java Spring, chỉ TCP 8080, không có lý do kỹ thuật để fail). | — |
| 7 | `JWKS` vào identity qua file `/.keys` | ⚠️ `application.properties`: `app.jwksJson=${JWKS}` (env, không phải đọc file trực tiếp). Deployment gốc mount secret ở `/.keys`. → entrypoint ảnh có thể tự `export JWKS=$(cat /.keys/jwks.json)`. Phase 1: mount `/.keys` **và** set env `JWKS` = nội dung file, kiểm log identity. | — |

### Quyết định GATE 0 (agent tự quyết, người dùng đã uỷ quyền)

1. **DB-2**: 1 Postgres `crapi` (image `postgres:14`, `-c max_connections=500`) trên **OpenStack**. MongoDB (`mongo:4.4`) + mailhog trên **AWS** (mailhog cần Mongo: `MH_MONGO_URI=…@mongodb:27017`).
   - Nghị định 53: khớp **tốt hơn** DB-1 (toàn bộ dữ liệu — cả định danh lẫn shop — nằm trên hạ tầng chủ quyền OpenStack).
   - Cross-cloud tăng lên **6 hop**: bff→identity(HTTP), community→identity(HTTP/req), workshop→identity(HTTP/req), community→postgres(5432), workshop→postgres(5432), identity→mailhog(SMTP 1025). Mạnh hơn cho tenet 2 + số liệu overhead.
   - **mТLS hop Postgres:** Postgres KHÔNG có sidecar (như finance app) → hop cross-cloud Postgres = **plain TCP qua WireGuard** (WireGuard mã hoá tunnel — vẫn thoả "secured regardless of location", cơ chế khác mТLS). Hop HTTP identity vẫn mТLS ISTIO_MUTUAL đầy đủ (2 đầu đều có sidecar). Ghi rõ khác biệt này trong luận văn.
2. **Topology cuối:** OpenStack ns `crapi` = `crapi-identity` + `postgresdb` + `opa`. AWS ns `crapi` = `bff` + `crapi-web` + `crapi-community` + `crapi-workshop` + `mongodb` + `mailhog` + `redis` + `opa`.
3. **Realm role** rename: `crapi-user` / `crapi-mechanic` / `crapi-admin` / `soc-analyst`. bff map Keycloak role → claim `role` của token crAPI (`"user"`/`"mechanic"`/`"admin"` — xác nhận giá trị chính xác khi thấy token thật Phase 1).
4. **sensitive_crapi_action** (step-up + posture + device-trust): `POST /workshop/api/shop/orders`, `POST /workshop/api/shop/orders/return_order`, `POST /identity/api/v2/user/reset-password`, `POST /identity/api/v2/user/change-email`.
5. **Branch:** `feat/crapi-target` (off `fix/zta-remediation` HEAD).

**→ TARGET-CRAPI.md + KE-HOACH-CRAPI.md đã cập nhật cho DB-2. Tiếp Phase 1.**

---

## PHASE 1 — crAPI + PLG + mТLS

### 1.1 Ảnh — chuyển từ air-gap import → digest-pin + node tự pull

**Phát hiện:** `docker save` gộp nhiều ảnh multi-arch (Docker 29 + containerd image store) → `ctr images import` trên node lỗi `content digest sha256:de74616... not found` (blob thiếu trong OCI archive).

**Kiểm chứng:** node K3s **có internet** — `crictl pull crapi/crapi-web:latest` OK trên cả `aws_k3s_master` và `os_k3s_master` (giống istio/gatekeeper images vốn pull thẳng từ docker.io khi deploy).

**Quyết định:** manifest `k8s/crapi/*` ghim ảnh bằng **digest** (`crapi/crapi-identity@sha256:5d1db5b…` v.v.), `imagePullPolicy: IfNotPresent` → node tự pull, tái tạo được (digest cố định), bỏ phụ thuộc `docker save/ctr import`. `scripts/sync-app-images.sh --pull-only` giữ làm đường offline tùy chọn (chưa sửa lỗi save-per-image — không chặn). Air-gap thực sự vốn đã không có (istio/gatekeeper cũng pull từ internet).

Digest (2026-09-09): identity `5d1db5b3ba8e…`, community `8ba0c7eda86a…`, workshop `d4d2d94d35a3…`, web `b27d246c646b…`, mailhog `015c23f79d40…`, postgres:14 `156f0b253fd6…`, mongo:4.4 `4be76f674fc4…`.

### 1.2 Deploy + nghiệm thu Phase 1 + 2 (2026-09-09) — ✅ ĐẠT

**Khoá JWT identity:** entrypoint ảnh đọc `/app/keys/jwks.json` (KHÔNG phải `/.keys` như k8s base crAPI ghi — base sai, thực tế fallback `default_jwks.json`). `deploy/vendor/crapi-keys/jwks.json` == `default_jwks.json` nhúng trong ảnh (cùng `kid MKMZkDenUfuDF2byYowDj7tW5Ox6XG4Y1THTEGScRg8`). → mount `/app/keys`, bff mint bằng cùng key.

**crAPI role claim:** `ERole` → `user` / `mechanic` / `admin` (không phải `ROLE_*`). bff ROLE_MAP đúng.

**Trạng thái pod:** cả 2 cluster Running 2/2 — OS: `crapi-identity`, `postgresdb`. AWS: `bff`, `crapi-web`, `crapi-community`, `crapi-workshop`, `mongodb`, `mailhog`, `redis`. `crapi-community` crash-loop 1 lần lúc khởi động (chờ identity qua `/identity/health_check`, identity restart do đăng ký SPIRE sau) rồi tự phục hồi — cần thêm initContainer wait ở Phase 5 cho fresh deploy sạch.

**mТLS + SPIRE (verified qua istio access log của crapi-identity):**
```
"svid":"spiffe://ztlab.local/aws/bff"        — bff → identity cross-cloud
"svid":"spiffe://ztlab.local/aws/crapi-community"
"svid":"spiffe://ztlab.local/aws/crapi-workshop"
```
Định dạng access log JSON khớp finance app (path/method/response_code/svid/trace_id) → LogQL Grafana tái dùng được.

**Cross-cloud:** `crapi-workshop → crapi-identity-openstack:30090/identity/health_check` = **200** (WireGuard + Istio ISTIO_MUTUAL, DR subjectAltNames `spiffe://ztlab.local/openstack/crapi-identity`). Postgres cross-cloud (community/workshop → `postgresdb-openstack:30432`, plain TCP/WireGuard) — community/workshop kết nối DB OK.
> ⚠️ Bài học test: `kubectl exec -c istio-proxy -- curl` BỎ QUA mesh (traffic của uid 1337 không bị iptables intercept) → luôn thấy "connection reset" giả. Phải test từ **app container**.

**Token-exchange (bff mint → crAPI chấp nhận):**
| Gọi | Kết quả |
|---|---|
| identity `/identity/api/v2/user/dashboard` (bff token) | 200 + user data |
| identity `/identity/api/auth/verify` (bff token) | 200 "valid JWT token" → community/workshop sẽ chấp nhận |
| workshop `/workshop/api/shop/products` | 200 (Wheel, Seat — có seed data) |
| community `/community/api/v2/community/posts/recent` | 200 (posts thật) |

**crAPI login native:** `POST /identity/api/auth/login {test@example.com / Test!123}` = 200 + JWT `{sub, iat, exp, role:"user"}` — cùng format bff mint.

**BOLA còn nguyên (đúng chủ đích — ranh giới ZTA vs app-layer authz):**
`test@example.com` đọc được vehicle location của `adam007@example.com` (`GET /identity/api/v2/vehicle/{adam-uuid}/location` → 200, trả lat/long + họ tên + email). ZTA network/identity KHÔNG chặn — sẽ dùng làm minh chứng luận văn.

**BFF OIDC/PKCE:** `crapi.ztlab.local/health` qua Traefik = 200; `/auth/start` = 302 → `/kc/realms/ztlab/protocol/openid-connect/auth?client_id=crapi-bff&code_challenge=…S256`. Luồng browser đầy đủ (login Keycloak → callback → mint) cần test bằng browser thật (Phase 6).

**Keycloak (Admin API, `configure_crapi_keycloak`):** role `crapi-user/mechanic/admin`, `soc-analyst`; client `crapi-bff` + `crapi-bff-stepup` (aud mapper `crapi-bff`); gán role user demo. realm-config.json cũng cập nhật cho fresh import.

**PLG:** promtail regex `+crapi` — apply + restart DS → Loki có namespace `crapi` (`bff`, `mongodb`, … streams) + istio access log job `envoy-access`.

**Còn nợ Phase 1/2 (làm ở phase sau):** initContainer wait cho crapi-community/workshop; test browser OIDC đầy đủ; bff audit → Loki (job `bff-audit`) chưa thấy stream (LOKI_URL có set — kiểm lại Phase 3).



### PHASE 3 — OPA enforcement (2026-09-09) — ✅ ĐẠT

**Kiến trúc:** OPA riêng ns `crapi` (3 replica + PDB, tách hẳn OPA finance). Istio
`extensionProvider opa-ext-authz-crapi` → `opa-service.crapi:9191`. CUSTOM
AuthorizationPolicy trên `bff`, `crapi-community`, `crapi-workshop` (AWS, path
`zta/crapi/authz/allow`), `crapi-identity` (OpenStack, path `zta/crapi/crosscloud/allow`).

**Phát hiện kiến trúc:** hop `bff → crapi-identity` là cross-cloud TRỰC TIẾP → đi
qua OPA **OpenStack** (`crosscloud_crapi.rego`) chỉ kiểm `service_acl` + posture,
KHÔNG kiểm token Keycloak/RBAC (Keycloak ở AWS, OS OPA không resolve được). →
**bff tự enforce RBAC + step-up + device-trust** (`_rbac_ok()`, gương của
`zta_crapi.rego`) — defense-in-depth như finance app (api-gateway app + OPA).
Hop `bff → community/workshop` (cùng cluster AWS) OPA vẫn kiểm đầy đủ RBAC.

**OPA REST eval (deterministic):**
| input | result |
|---|---|
| `community → workshop GET /workshop/api/shop/products` (lateral movement) | **false** ✓ |
| `bff → workshop GET /workshop/api/shop/products` (+ Keycloak token) | **true** ✓ |

**BFF end-to-end (session Redis, gọi qua `http://localhost:8080`):**
| # | Test | KQ | Kỳ vọng |
|---|---|---|---|
| 1 | crapi-user GET `/workshop/api/shop/products` | 200 | 200 ✓ |
| 2 | crapi-user DELETE `/identity/api/v2/admin/videos/1` | 403 | 403 (RBAC) ✓ |
| 3 | crapi-admin DELETE `/identity/api/v2/admin/videos/999` | 404 | authz pass, video ko tồn tại ✓ |
| 4 | soc-analyst POST `/community/api/v2/community/posts` | 403 | 403 (ko ghi) ✓ |
| 5 | POST `/workshop/api/shop/orders` acr=1 | 401 | 401 step_up ✓ |
| 6 | POST orders acr=high (session giả) | 403 | OPA từ chối token acr=1 thật — **đúng** (defense in depth; test thật cần OTP) |
| 7 | POST community/posts, device_trust=suspicious | 403 | 403 ✓ |
| 8 | không session | 401 | 401 ✓ |
| 9 | BOLA: user đọc vehicle location user khác | **200** | vuln crAPI còn nguyên ✓ |

**Decision log → Loki** (job `opa-decisions`): `result:true/false`, `source_principal`,
`counter_rego_builtin_http_send_network_requests:2` (OPA gọi Keycloak JWKS+discovery).

**Sửa phát sinh Phase 3:**
- **mailhog: AWS → OpenStack.** AWS SG `ztlab-sg-private` không cho inbound NodePort
  từ dải OpenStack (`192.168.101.0/24`) → `identity(OS) → mailhog(AWS):31025` treo
  → signup treo (identity block trên SMTP send sau khi tạo user thành công).
  → mailhog về OpenStack, `MH_STORAGE=memory` (bỏ dep Mongo), SMTP nội cluster.
  Thêm rule SG vào `terraform/aws/security_groups.tf` (root-cause) — cần AWS creds +
  `terraform apply`; khi có, chuyển mailhog về AWS được (thêm 1 hop cross-cloud SMTP).
- **identity `traffic.sidecar.istio.io/excludeOutboundPorts: "1025"`** — SMTP là
  server-first protocol, istio-proxy sniffing làm hỏng handshake ("220 ESMTP" rồi
  connection close). Loại 1025 khỏi interception → plain TCP → OK.
- **bff session → Redis** (`bff:session:<sid>`, TTL, fallback in-proc) — cần cho
  scale + test; cookie chỉ mang `{sid}` ký.

**Cross-cloud hops thực tế (verified):**
| Hop | Giao thức | Bảo vệ |
|---|---|---|
| bff → identity | HTTP | Istio mТLS ISTIO_MUTUAL (SVID) + WireGuard |
| community → identity `/verify` | HTTP | như trên |
| workshop → identity `/verify` | HTTP | như trên |
| community/workshop → postgresdb :30432 | TCP 5432 | WireGuard (Postgres ko sidecar) |
| identity → mailhog | SMTP 1025 | nội cluster OpenStack (ko còn cross-cloud) |

### PHASE 4 — NetworkPolicy L4 (2026-09-09) — ✅ ĐẠT
`k8s/crapi/network-policies/{aws,os}-allow-list.yaml` (baseline podSelector {}) +
`{aws,os}-pod-segmentation.yaml` (generated). Applied 2 cluster, crapi verified
vẫn chạy (bff→identity 200). Như finance: k3s netpol không enforce đầy đủ cho
traffic có sidecar — L7 (service_acl) là lớp phân đoạn thật.

### PHASE 5 — Tích hợp deploy + gỡ finance (2026-09-09) — ✅ ĐẠT (live)
- `deploy-app.sh`: `deploy_financial_infra+services` → `deploy_crapi` (gọi
  `deploy-crapi.sh`). `apply_network_policies`/`deploy_istio`/`regenerate_policy_files`/
  `deploy_stepup_flow`/`deploy_audience_mapper` → crapi. `namespaces.yaml` financial→crapi.
- `deploy-security-stack.sh`: `deploy_step_4_opa` no-op (OPA ở deploy-crapi).
- `sync-app-images.sh`: BATCHES = bff + soar-engine + ai-analyzer + security-scorer
  (finance services đã xoá). `k8s/ingress.yaml`: bỏ api-gateway route.
- `realm-config.json`: crapi-only (client crapi-bff/-stepup, role crapi-*, +stepup-demo).
- gen-rego-acl.py / gen-networkpolicy.py: crapi-only.
- istio-operator: `extensionProvider opa-ext-authz` → `opa-service.crapi` (bỏ finance).
- soar-engine `TARGETS_BY_ATTACK` + ai-analyzer `known_services`/`service_map` → crapi.
- **GỠ (live + repo):** namespace `financial` (2 cluster), `services/{api-gateway,
  payment-service,web-portal,core-banking,account-service,transaction-service,
  fraud-detection,notification-service}/`, `shared/svid_sign.py`, `k8s/financial/`,
  `opa/{policies,config,deployment.yaml}`, `policy/service-graph.yaml`,
  8 SPIRE entry finance (live).
- **GIỮ:** `posture-agent-cronjob` + `security-scanner-job` (move `k8s/crapi/`),
  redis (databases-aws.yaml), device-posture/trust (bff), step-up, PLG, SOAR/ai/scorer engine.

**Nghiệm thu Phase 5 (running system):**
```
legit GET workshop/community/identity  → 200
RBAC user DELETE admin video            → 403 ; admin → 404 (authz pass)
RBAC soc-analyst POST                   → 403
step-up order acr=1                     → 401
BOLA (vuln crAPI)                       → 200 (còn nguyên)
lateral movement (OPA REST eval)        → result:false
health-check.sh                         → FAIL=0
SPIRE entries                           → AWS 4 / OS 2 (chỉ crapi)
namespace financial                    → NotFound (đã xoá 2 cluster)
```

### PHASE 7 — Detection (LIGHT, 2026-09-09) — một phần
Đã làm: alert rule `access-denied` (OPA deny spike), `lateral-movement` (deny +
`request_path` API nghiệp vụ), `brute-force` (login/OTP crapi-identity),
`bfla` (bff `rbac_denied`, thay fraud-gate-bypass), `large-response`+`privilege-escalation`
(ns→crapi). `security-control-plane`+`soar-engine` alert: infra, không đổi.
promtail `opa-decisions` regex `:path`→`[:]?path`. Verified qua Loki: access-denied
query = 50/10m, lateral-movement = 32/10m sau khi sinh deny thật.

**CÒN LẠI Phase 7 (việc tương lai — không chặn target):** script tấn công crAPI
thật (`tests/crapi_*.sh` thay `grafana_kb*.sh`), dashboard Grafana theo attack
surface crAPI, verify end-to-end Grafana alert → webhook → SOAR case → playbook,
tinh chỉnh ngưỡng, `tests/test_service_graph_consistency.py` cho crapi.

### PHASE 6 — Reproducibility — ⏳ CẦN NGƯỜI DÙNG
Agent KHÔNG chạy được `terraform destroy`/`apply` (classifier chặn). Đường
fresh-deploy đã review + sửa các điểm gãy (BATCHES, ingress, realm-config,
namespaces, generators, provider). Cần người dùng chạy:
```
bash scripts/destroy-all.sh          # hoặc terraform destroy 2 chiều
export $(grep -v '^#' .env | xargs)  # AWS creds (cho SG rule mới + SAML)
bash scripts/deploy-all.sh           # fresh — kỳ vọng ra crapi + ZTA
```
Nghiệm thu: xem TARGET-CRAPI.md §7.
