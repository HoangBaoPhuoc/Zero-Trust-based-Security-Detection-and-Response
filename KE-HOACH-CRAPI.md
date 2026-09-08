# KẾ HOẠCH — Thay ứng dụng mục tiêu: finance app → OWASP crAPI

> **File này dành cho agent (Claude CLI) thực thi.** Cùng quy ước `KE-HOACH-SUA-HE-THONG.md`.
> Đích đã duyệt: xem **`TARGET-CRAPI.md`**. File này là các bước để đạt đích đó.
>
> **Nguồn sự thật hiện trạng:** đọc trực tiếp source (2026-09-09). **Nguồn crAPI:** github.com/OWASP/crAPI@develop.
>
> **Mô hình thực thi (chốt 2026-09-09):** sau khi người dùng duyệt `TARGET-CRAPI.md`, agent **tự thực thi toàn bộ
> Phase 1→7, tự sửa/tự fix, KHÔNG cần người dùng action thêm**. Ngoại lệ bắt buộc phải nhờ người dùng:
> (1) `terraform destroy` / `terraform apply` (bị classifier chặn — Phase 6);
> (2) enroll OTP step-up qua browser thật (1 lần, như `VIEC-CON-TON-DONG.md` mục 1).
> Mọi thứ khác (sửa source, `kubectl apply`, build/sync ảnh, rollout, verify) agent tự làm và tự ghi kết quả
> vào `KET-QUA-CRAPI.md`.

---

## 0. QUYẾT ĐỊNH ĐÃ CHỐT

| Trục | Chọn |
|---|---|
| **A — Phạm vi** | Core: `crapi-identity`, `crapi-community`, `crapi-workshop`, `crapi-web`, `mailhog`, Postgres×2, MongoDB. KHÔNG lấy `crapi-chatbot`/`chromadb`/`gateway-service`. |
| **B — Hybrid** | **AWS:** `bff`(mới), `crapi-web`, `crapi-community`, `crapi-workshop`, `postgres-shop`, `mongodb`, `redis`, `mailhog`, `opa`. **OpenStack:** `crapi-identity`, `postgres-identity`, `opa`. Biên = "ai cần xác thực" (AWS) vs "nơi cấp danh tính + dữ liệu định danh" (OpenStack) — khớp Nghị định 53. |
| **C — Danh tính user** | C2b: `bff` (FastAPI) là điểm vào duy nhất. User login **Keycloak OIDC/PKCE** ở bff. bff **mint token crAPI-native** (RS256, khoá RSA của crAPI) `sub=email` cho hop Đông–Tây (`Authorization`), forward token Keycloak ở `X-Access-Token` cho OPA (realm role + step-up `acr`). crAPI **giữ ảnh gốc**. |
| **D — Ảnh** | Pull `crapi/*` + `postgres:14` + `mongo:4.4` từ Docker Hub (ghim `@sha256:`) → air-gap import. `sync-financial-images.sh` → `sync-app-images.sh` (crAPI = pull, `bff` = build). |
| **Namespace** | `crapi` (cả 2 cluster), thay hẳn `financial`. |
| **Bỏ hẳn (đặc thù ngân hàng, không liên quan crAPI)** | `fraud-detection`, `notification-service`, verdict ký SVID (T-1.5), fraud-gate score (`X-Fraud-Gate`/`X-Fraud-Score` + rule `fraud_gate_valid`), ngưỡng VND, luỹ kế ngày. |
| **Device posture / device trust** | **GIỮ — do `bff` tự tính, không cần service scoring riêng.** bff gắn `X-Device-Posture` (posture của chính bff, `shared/posture.py`) + `X-Device-Trust` (phân tích User-Agent browser, bê từ `web-portal` cũ). OPA giữ `posture_compliant` + `device_trust_compliant`. `posture-agent` CronJob + `security-scanner-job` audit pod ns `crapi` — giữ. |
| **PLG pipeline** | **GIỮ HOẠT ĐỘNG TỪ PHASE 1.** Promtail→Loki→Grafana, istio-proxy access log (job `envoy-access`), OPA decision log (job `opa-decisions`), Loki relay cross-cloud, bff đẩy audit log lên Loki. Chỉ đổi regex namespace `financial`→`crapi`. **Nội dung** alert rule / SOAR target map / security-scorer regex = Phase 7 (vì hardcode theo endpoint finance) — tới lúc đó lớp *phát hiện* chưa khớp attack surface crAPI, nhưng *đường ống* vẫn chạy. |

### Cơ chế bảo mật finance-app GIỮ NGUYÊN (không đổi cơ chế, chỉ đổi dữ liệu/đích)
mTLS STRICT (Istio PeerAuth) · SPIRE SVID scheme riêng `spiffe://ztlab.local/<cloud>/<svc>` · OPA ext_authz fail-closed, 2 cluster 2 path (`zta/authz/allow`, `zta/crosscloud/allow`) · `service_acl` L7 sinh từ `policy/service-graph.yaml` · NetworkPolicy L4 allow-list + pod-segmentation · Keycloak OIDC/PKCE + RBAC realm role · step-up OTP (`acr=high`, Conditional-OTP flow) · OPA tự verify chữ ký JWT (Keycloak JWKS + OIDC discovery) + kiểm `aud` · device posture (workload) + device trust (browser) qua header `X-Device-Posture`/`X-Device-Trust` (do `bff` tính) · `posture-agent` CronJob + `security-scanner-job` · Gatekeeper admission · Vault · audit log OPA (`decision_id`) · PLG + Prometheus + SOAR HITL + ai-analyzer + security-scorer (engine giữ nguyên) · cross-cloud NodePort+WireGuard+selectorless-Svc+DR ISTIO_MUTUAL · Istio install + `opa-ext-authz` provider + trustDomain `ztlab.local`.

> **Không port (đặc thù ngân hàng — làm rõ ranh giới đóng góp trong luận văn):** `fraud-detection` (chấm điểm rủi ro giao dịch theo amount/velocity), `notification-service`, verdict ký SVID T-1.5, `fraud_gate_valid`, ngưỡng VND, `daily_cumulative`, `core_transaction_with_fraud_gate`. Trục "dynamic policy" (tenet 4) của crAPI được thể hiện bằng device-trust + device-posture + step-up + RBAC + trạng thái SVID — không còn trục amount/velocity.

### Hạ tầng KHÔNG đụng
Terraform, Ansible (baseline/k3s/wireguard/promtail), SPIRE server/agent + root CA, Keycloak deployment + Postgres của nó, Vault, Gatekeeper, PLG stack deployment, Prometheus, `gen-rego-acl.py`/`gen-networkpolicy.py` (data-driven).

### Xoá ở Phase 5
`services/{api-gateway,payment-service,web-portal,core-banking,account-service,transaction-service,fraud-detection,notification-service}/`, `shared/svid_sign.py`, `k8s/financial/{aws-services,os-services,web-portal,postgres-accounts,postgres-txn,services,db-admin-ui}.yaml`, `opa/policies/fraud_gate.rego`. **GIỮ:** `services/Dockerfile`, `shared/posture.py`, `k8s/financial/{redis,posture-agent-cronjob,security-scanner-job}.yaml` (move sang `k8s/crapi/`, đổi ns).

---

## 1. GIẢ ĐỊNH CẦN KIỂM CHỨNG — GATE 0 (đọc source crAPI kỹ)

Đọc `deploy/k8s/base/{identity,community,workshop,web,mailhog}/*` + Dockerfile + code auth từng service. Xác nhận:

1. Port: identity 8080, community 8087, workshop 8000, web 80. (đã đọc config ✅)
2. **DB:** identity = Postgres only. community/workshop = Postgres + Mongo. ⚠️ community ghi bảng gì vào Postgres — nếu Mongo-only, bỏ edge `community→postgres-shop`.
3. **JWT liên service:** endpoint/cách community & workshop lấy pubkey từ identity (`IDENTITY_SERVICE`). ⚠️ cần path chính xác cho `service_acl`.
4. **Khoá ký:** `deploy/*/keys/jwks.json` có RSA private key dùng được để mint token identity chấp nhận? Alg RS256 hay HS256 (`JWT_SECRET: crapi`)? ⚠️ quyết cách bff mint.
5. **Filter verify token của crapi-identity** (`JwtAuthTokenFilter` Spring): claim bắt buộc (`sub`, `role`, `iat`, `exp`, `aud`?). ⚠️ bff phải mint đúng bộ claim.
6. **Seed:** identity tự tạo user/vehicle mẫu lúc boot? biến điều khiển? user "victim" cho BOLA có sẵn không?
7. **Sidecar:** ảnh gốc chịu istio-proxy + mount SPIRE socket — test 1 service ở Phase 1.
8. Health endpoint mỗi service → dùng `tcpSocket` cho chắc.
9. `crapi-web` tách được static để bff proxy phần API không.

**🛑 GATE 0 — trình bày "giả định vs thực tế" + `service-graph.yaml` nháp + danh sách file. (Agent tự tiếp nếu không có mâu thuẫn chặn; chỉ DỪNG nếu phát hiện điều làm sai lệch `TARGET-CRAPI.md`.)**

---

## 2. TOPOLOGY & DANH TÍNH — xem `TARGET-CRAPI.md` §2, §3

SPIFFE entries mới (`ensure-spire-entries.sh`), gate đếm AWS=4 / OpenStack=1:
`aws/{bff, crapi-web, crapi-community, crapi-workshop}` · `openstack/crapi-identity`.

---

## 3. PHASE 1 — crAPI + PLG + mТLS chạy, CHƯA có OPA/BFF

### 1.1 Ảnh — `scripts/sync-app-images.sh`
Pull+ghim digest: `crapi/crapi-identity`, `crapi/crapi-community`, `crapi/crapi-workshop`, `crapi/crapi-web`, `crapi/mailhog`, `postgres:14`, `mongo:4.4`. Build: `bff` (qua `services/Dockerfile`). Import 6 node như cũ. `deploy-app.sh` gọi tên script mới.

### 1.2 Manifest `k8s/crapi/`
- `namespace.yaml` — ns `crapi`.
- `aws-workloads.yaml` — `crapi-web`, `crapi-community`, `crapi-workshop` (copy nguyên block SPIRE `userVolume`/sidecar từ `aws-services.yaml`). Override env crAPI: `IDENTITY_SERVICE=crapi-identity-openstack.crapi.svc.cluster.local:30090`, `DB_HOST=postgres-shop`, `MONGO_DB_HOST=mongodb`.
- `os-workloads.yaml` — `crapi-identity` Deployment + Service **NodePort 30090**→8080 + SA + mount Secret `crapi-jwt-key` `/.keys`. Override: `DB_HOST=postgres-identity`, `MAILHOG_HOST=mailhog-aws.crapi.svc.cluster.local`, `MAILHOG_PORT=31025`.
- `databases.yaml` — `postgres-shop`+`mongodb`+`redis` (AWS), `postgres-identity` (OpenStack). PVC. `inject:"false"`.
- `mailhog.yaml` — AWS, NodePort 31025→1025 (SMTP) + ClusterIP 8025 (UI). `inject:"true"` (mТLS SMTP cross-cloud — giữ tenet 2; fallback `"false"` nếu handshake TCP fail).
- `configmaps.yaml` — `crapi-*-configmap` từ `deploy/k8s/base/*/config.yaml`, sửa host theo split.
- `cross-cloud.yaml` — selectorless Svc+Endpoints `crapi-identity-openstack` (AWS, `192.168.101.11:30090`) + `mailhog-aws` (OpenStack, `<aws-worker>:31025`) — mẫu `core-banking-openstack`.
- Move `k8s/financial/{redis,posture-agent-cronjob,security-scanner-job}.yaml` → `k8s/crapi/`, đổi ns. `redis`: bff dùng cho rate-limit + PKCE state (không phục vụ crAPI).

### 1.3 Secret khoá crAPI
`deploy/vendor/crapi-keys/jwks.json` (commit — key upstream công khai của crAPI, không phải bí mật thật). `deploy-crapi.sh` tạo Secret `crapi-jwt-key` **cả 2 cluster**.

### 1.4 Mesh Phase 1
`k8s/crapi/istio-policies.yaml`: PeerAuth STRICT ns `crapi` + PERMISSIVE tạm `crapi-web` + DestinationRule custom-SAN mỗi service + `crapi-identity-openstack` + `mailhog-aws`. **Chưa** AuthorizationPolicy CUSTOM. Label ns `crapi` `istio-injection=enabled` cả 2 (thêm `deploy_istio()`).

### 1.5 PLG — nối lại ngay
`k8s/plg-stack/promtail-daemonset.yaml`: regex namespace `financial|identity|plg-stack` → `crapi|identity|plg-stack`. Container regex `istio-proxy` giữ. OPA decision-log scrape giữ. Loki relay cross-cloud giữ. Xác nhận log crAPI + istio-proxy vào Loki.

### 1.6 SPIRE — `ensure-spire-entries.sh` thay 8→5 entry (AWS=4, OpenStack=1).

### Kiểm chứng Phase 1
1. `kubectl -n crapi get pods` 2 cluster: Running 2/2.
2. mТLS `crapi-community`→`crapi-identity-openstack`: SVID trong peer cert (istio-proxy log).
3. Luồng crAPI gốc chạy: signup→login→list vehicles.
4. BOLA còn nguyên: user A đọc vehicle location user B.
5. OTP mail: `crapi-identity`(OS)→`mailhog`(AWS) — thấy mail ở mailhog UI.
6. Loki có log `{namespace="crapi"}` + `{job="envoy-access"}` + `{job="opa-decisions"}`.

**🛑 GATE 1**

---

## 4. PHASE 2 — BFF (edge PEP + Keycloak + token-exchange + device trust)

### 2.1 `services/bff/main.py` (FastAPI, tái dùng nhiều từ `web-portal/main.py`)
- Keycloak OIDC/PKCE: `/auth/start`, `/auth/callback`, `/auth/logout`. Session cookie ký (`itsdangerous`), state PKCE ở Redis.
- **Device trust** (bê từ `web-portal/main.py`): phân tích User-Agent/ASN/ lịch sử → `X-Device-Trust: trusted|new_device|suspicious`.
- **Token-exchange mỗi request proxy:**
  - `Authorization: Bearer <crapi_jwt>` — bff mint RS256 (`sub=email`, `role`, `iat`, `exp`, + claim theo GATE 0 #5), khoá từ Secret `crapi-jwt-key`.
  - `X-Access-Token: <keycloak_access_token>`.
  - `X-Device-Trust`, `X-Device-Posture` (posture của chính bff, `shared/posture.py`).
- Reverse proxy: `/identity/*`→`crapi-identity-openstack:30090`; `/community/*`→`crapi-community:8087`; `/workshop/*`→`crapi-workshop:8000`; `/`+`/static/*`→`crapi-web:80`.
- Đẩy audit log (ai làm gì, decision) lên Loki (`LOKI_URL`).

### 2.2 Manifest
- `bff` vào `aws-workloads.yaml`: SA `bff`, SPIFFE `aws/bff`, sidecar, mount `crapi-jwt-key` + `bff-secret`.
- `k8s/crapi/ingress.yaml` — Traefik `Host(crapi.ztlab.local)`→`bff:8080`.
- `crapi-web` PeerAuth về STRICT; chỉ `bff` PERMISSIVE.

### 2.3 Keycloak — `k8s/keycloak/realm-config.json`
- Client `web-portal`→`crapi-bff` (public/PKCE, redirect `http://crapi.ztlab.local/*`). `web-portal-stepup`→`crapi-bff-stepup`.
- Realm role: rename `financial-read/-write, security-analyst, security-admin` → `crapi-user, crapi-admin, soc-analyst` (+ `crapi-mechanic` nếu cần cho BFLA demo). Cập nhật users demo + `zta_policy.rego`.
- `deploy_stepup_flow()`: bind client mới.

### Kiểm chứng Phase 2
1. `crapi.ztlab.local`→Keycloak login `testuser01`→UI crAPI.
2. `GET /workshop/api/shop/products` qua bff OK.
3. `X-Access-Token` + `X-Device-Trust` + `X-Device-Posture` ở request bff→crapi-* (istio access log).
4. Logout → 401.

**🛑 GATE 2**

---

## 5. PHASE 3 — OPA (Zero Trust authz + posture + step-up)

### 3.1 `policy/service-graph.yaml` — viết lại (xem `TARGET-CRAPI.md` §4 bảng đầy đủ)
Workloads: 5 SPIFFE + infra. Edges L7 (method+path từ `crapi-openapi-spec.json`): `bff→{crapi-identity(cross), crapi-community, crapi-workshop, crapi-web}`, `crapi-community→crapi-identity(cross)`, `crapi-workshop→crapi-identity(cross)`, + L4: `bff/crapi-*→redis/postgres-shop/mongodb/postgres-identity/opa`, `crapi-identity→mailhog(cross,1025)`.
Chạy lại `gen-rego-acl.py` + `gen-networkpolicy.py`.

### 3.2 `opa/policies/zta_policy.rego` (AWS, `zta/authz/allow`)
- Giữ: verify JWT Keycloak JWKS + `expected_issuer` OIDC discovery + kiểm `exp`.
- Đổi: đọc token từ `headers["x-access-token"]` (fallback `authorization`). `aud`→`crapi-bff`.
- `permissions`/`role_permits_action`: map `crapi-user/crapi-admin/soc-analyst` → (method, path-prefix crAPI).
- **Giữ `posture_compliant`** (`x-device-posture == compliant` hoặc header vắng) + **`device_trust_compliant`** (`x-device-trust != suspicious`) — áp cho `sensitive_crapi_action` (danh sách ở `TARGET` §4).
- **Giữ step-up**: `sensitive_crapi_action` + `requires_step_up` (theo *loại* action) → `step_up_satisfied` (`acr=="high"`).
- **Bỏ:** `fraud_gate_valid`, `daily_cumulative`, ngưỡng VND, `/transactions/execute` cụ thể, `core_transaction_with_fraud_gate`, `sensitive_payment_request`. `includeRequestBodyInCheck` gỡ khỏi `istio-operator.yaml` trừ khi step-up cần đọc body.
- Giữ nguyên: `internal_service_request` (valid_svid + `allowed_by_acl` — lõi chống lateral movement), `external_api_request`, `audit_log`.

### 3.3 `opa/policies/cross_cloud.rego` (OpenStack, `zta/crosscloud/allow`)
Giữ `service_acl` + `allowed_by_acl` + `posture_compliant`. Bỏ `fraud_gate_valid` + `device_trust_compliant`. Guard `crapi-identity`: chỉ `bff`/`crapi-community`/`crapi-workshop`.

### 3.4 `k8s/crapi/istio-policies.yaml`
CUSTOM→`opa-ext-authz`: `bff`, `crapi-web`, `crapi-community`, `crapi-workshop` (AWS), `crapi-identity` (OpenStack). Giữ DestinationRule custom-SAN + `opa-service-plaintext`.

### Kiểm chứng Phase 3
1. Chức năng crAPI qua bff vẫn chạy (OPA không chặn nhầm).
2. Lateral movement chặn: `crapi-community` gọi `crapi-workshop` path ngoài `service_acl` → 403 (decision log false).
3. Unauthenticated internal → deny.
4. step-up: action nhạy cảm với `acr!=high` → 401 `step_up_required`; sau OTP `acr=high` → 200.
5. posture: `x-device-posture: non-compliant` (giả qua OPA REST) → deny; `x-device-trust: suspicious` → deny.
6. `health-check.sh` FAIL=0; `test_service_graph_consistency.py` PASS.

**🛑 GATE 3**

---

## 6. PHASE 4 — NetworkPolicy L4

`k8s/crapi/network-policies/{aws,os}-allow-list.yaml` — rewrite ns `crapi`: ingress Traefik→bff, monitoring→metrics, spire→opa:8181, nội bộ theo `service_acl`; egress DNS, `crapi`→`crapi`, `crapi`→`identity`(Keycloak), `crapi`→`plg-stack`(Loki 3100), cross-cloud ipBlock `192.168.101.0/24`:30090 + `10.42.0.0/16`, istio-system:15012. `{aws,os}-pod-segmentation.yaml` generated. Cập nhật `apply_network_policies()`.

Kiểm chứng: `health-check.sh` FAIL=0; hop hợp lệ thông; `security-healthcheck` cronjob green.

**🛑 GATE 4**

---

## 7. PHASE 5 — Deploy script + dọn finance

### 5.1 `scripts/deploy-crapi.sh` (thay `deploy_financial_infra`+`deploy_financial_services`)
Secret `crapi-jwt-key`/`bff-secret`/`crapi-seed` → databases → wait → configmaps → workloads 2 cluster → wait → cross-cloud.yaml → istio-policies → `ensure-spire-entries.sh` → ingress → **seed Job** (§5.3). `deploy-app.sh main()`: thay lời gọi. `deploy-security-stack.sh` `deploy_step_4_opa`/`financial_manifests_ready`: `financial`→`crapi`.

### 5.2 Sửa mọi tham chiếu `financial`
`k8s/namespaces.yaml`, `deploy-app.sh`, `deploy-security-stack.sh`, `ensure-spire-entries.sh`, `promtail-daemonset.yaml`, `k8s/rbac/*.yaml`, `k8s/security-monitoring/healthcheck-cronjob.yaml`, `services/soar-engine/main.py` (`SOAR_NAMESPACE`, `ALERT_TARGET`), `services/ai-analyzer/main.py` (`SERVICES`), `services/security-scorer/main.py` (`REDIS_URL`), `tests/*`, `opa/config` (ns configmap).

### 5.3 Seed (TÁCH RIÊNG — dữ liệu ứng dụng, KHÔNG phải hạ tầng)
`k8s/crapi/seed-job.yaml` — Job idempotent chạy sau deploy: đợi identity ready → `POST /identity/api/auth/signup` cho từng user demo Keycloak (cùng email, password ở Secret `crapi-seed`) → tạo vehicle/product/mechanic/coupon mẫu → tạo cặp victim/attacker cho BOLA. Ghi rõ trong `DEPLOY.md`: reproducible, idempotent, nhưng là *seed app* không phải *provision hạ tầng*.

### 5.4 Xoá finance (§0). Cập nhật `README.md`, `FLOW_DETAIL.md`, `docs/` (kiến trúc + mermaid).

**🛑 GATE 5 — review diff trước commit.**

---

## 8. PHASE 6 — Reproducibility (cần người dùng chạy terraform)

1. Người dùng: `bash scripts/destroy-all.sh` (hoặc `terraform destroy` 2 chiều).
2. Người dùng: `bash scripts/deploy-all.sh` từ 0.
3. Agent nghiệm thu: pods Running 2 cluster + seed Job Completed · login `crapi.ztlab.local` qua Keycloak · `istioctl proxy-config secret` = SVID SPIRE · lateral-movement deny · posture/device-trust/step-up hoạt động · BOLA vẫn tái hiện (crAPI còn lỗ hổng app-layer — đúng chủ đích) · `health-check.sh` FAIL=0 · `test_service_graph_consistency.py` PASS · Loki có log crAPI · **không `kubectl apply` tay nào ngoài `deploy-all.sh`**.

**🛑 GATE 6 — mốc "đã thay xong".**

---

## 9. PHASE 7 — Detection khớp attack surface crAPI

- `plg-stack/grafana/alerting/` (9 rule → BOLA spike, BFLA admin-endpoint, SSRF egress, injection 5xx, brute-force OTP `/auth/v3/check-otp`, JWT anomaly, priv-esc container, access-denied spike, control-plane-down).
- `services/soar-engine/main.py` `ALERT_TARGET` → `crapi-community`/`crapi-workshop`/`crapi-identity`; playbook giữ tên.
- `services/ai-analyzer/main.py` `SERVICES`; `services/security-scorer/main.py` RULES regex.
- `tests/grafana_kb*.sh` → `tests/crapi_kb*.sh` (script tấn công thật khớp rule).
- `posture-agent-cronjob.yaml`/`security-scanner-job.yaml` → ns `crapi` (đã move Phase 1).

**🛑 GATE 7 — mốc hoàn tất toàn bộ.**

---

## 10. RỦI RO / ROLLBACK

- Branch `feat/crapi-target` (base: hỏi người dùng — `khanhha` hay `fix/zta-remediation`).
- Mỗi Phase ≥ 1 commit; nghiệm thu xong mới sang Phase sau. Ghi mọi kết quả vào `KET-QUA-CRAPI.md`.
- Finance app chỉ `git rm` ở Phase 5.
- Rủi ro cao: (a) ảnh crAPI không chịu sidecar → `inject:false` service đó + ghi rõ mất mТLS hop; (b) crАPI verify JWT liên service theo cách khó mở path → rule `service_acl` rộng hơn cho `community/workshop→identity`; (c) bff mint token sai claim → đọc `JwtAuthTokenFilter` crapi-identity; (d) SMTP qua Istio mТLS fail → mailhog `inject:false`.

*Cập nhật: 2026-09-09. Chờ duyệt `TARGET-CRAPI.md`.*
