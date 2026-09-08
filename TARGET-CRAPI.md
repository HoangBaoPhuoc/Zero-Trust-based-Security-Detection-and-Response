# TARGET — Trạng thái đích sau khi thay finance app → OWASP crAPI

> **File này để người dùng DUYỆT.**

> **TRẠNG THÁI 2026-09-09:** Phase 1–5 XONG + verified (branch `feat/crapi-target`). Phase 7 làm LIGHT. Phase 6 (fresh destroy+deploy-all) CẦN NGƯỜI DÙNG chạy terraform. Xem `KET-QUA-CRAPI.md`.
 Sau khi duyệt, agent tự thực thi `KE-HOACH-CRAPI.md` Phase 1→7,
> tự sửa/tự fix, không cần action thêm (trừ `terraform destroy/apply` ở Phase 6 và enroll OTP 1 lần).
>
> Nguyên tắc: **giữ tối đa cơ chế bảo mật của finance app**. Chỉ đổi (1) ứng dụng mục tiêu,
> (2) ma trận phân quyền L7, (3) nội dung alert/SOAR (Phase 7). Mọi lớp ZTA còn lại giữ nguyên cơ chế.

---

## 1. THÀNH PHẦN — trạng thái đích

### 1.1 Ứng dụng mục tiêu (crAPI Core — ảnh gốc Docker Hub, ghim digest)

| Workload | Cloud | ns | Port | Sidecar | SPIFFE ID | DB |
|---|---|---|---|---|---|---|
| `crapi-identity` (Java/Spring) | **OpenStack** | crapi | 8080 (+NodePort 30090) | istio + SPIRE | `spiffe://ztlab.local/openstack/crapi-identity` | postgres-identity |
| `crapi-community` (Go) | AWS | crapi | 8087 | istio + SPIRE | `…/aws/crapi-community` | postgres-shop + mongodb |
| `crapi-workshop` (Django) | AWS | crapi | 8000 | istio + SPIRE | `…/aws/crapi-workshop` | postgres-shop + mongodb |
| `crapi-web` (React/nginx, static) | AWS | crapi | 80 | istio + SPIRE | `…/aws/crapi-web` | — |
| `mailhog` | AWS | crapi | 1025 SMTP (+NodePort 31025) / 8025 UI | none | — | mongodb |
| `postgresdb` (`postgres:14`, **1 DB `crapi` dùng chung**) | **OpenStack** | crapi | 5432 (+NodePort 30432) | none | — | — |
| `mongodb` (`mongo:4.4`) | AWS | crapi | 27017 | none | — | — |

> **DB-2 (bắt buộc — phát hiện GATE 0):** `crapi-workshop`/`crapi-community` đọc thẳng bảng `user_login`/`user_details`/`vehicle_details` của identity trong Postgres dùng chung (`db_table` hardcode, `managed=False`) — **không tách Postgres được nếu không fork crAPI**. → 1 Postgres duy nhất, đặt ở OpenStack (toàn bộ dữ liệu trên hạ tầng chủ quyền — khớp Nghị định 53 tốt hơn DB-1). MongoDB ở AWS (chỉ community/workshop/mailhog dùng; identity không). Hop cross-cloud Postgres = plain TCP qua WireGuard (Postgres không có sidecar); hop HTTP identity vẫn mТLS ISTIO_MUTUAL đầy đủ.

### 1.2 Lớp Zero Trust / edge

| Workload | Cloud | Vai trò | SPIFFE ID |
|---|---|---|---|
| `bff` (FastAPI — **mới**) | AWS | Điểm vào duy nhất. Keycloak OIDC/PKCE. Mint token crAPI-native (RS256). Reverse-proxy theo path. Tính device-trust (browser) + device-posture (workload). Đẩy audit log Loki. | `…/aws/bff` |
| `redis` (**giữ**) | AWS | rate-limit + PKCE state cho bff (không phục vụ crAPI). | — |
| `opa` ×3 replica + PDB | AWS | PDP ext_authz path `zta/authz/allow` | — |
| `opa` ×3 replica + PDB | OpenStack | PDP ext_authz path `zta/crosscloud/allow` | — |

> **Bỏ hẳn:** `fraud-detection`, `notification-service` (chấm điểm rủi ro giao dịch + verdict ký SVID T-1.5 — đặc thù ngân hàng, không liên quan crAPI).

### 1.3 Hạ tầng bảo mật & quan sát — **GIỮ NGUYÊN**
SPIRE server/agent + root CA (`ztlab.local`) · Keycloak + Postgres · Vault · Gatekeeper (admission) · Istio (`opa-ext-authz` provider, trustDomain `ztlab.local`, access log JSON) · PLG (Promtail→Loki→Grafana) + Loki relay cross-cloud · Prometheus · SOAR engine (HITL) · ai-analyzer · security-scorer · `posture-agent` CronJob · `security-scanner-job` · Traefik ingress.

### 1.4 Danh sách đầy đủ workload ns `crapi`
**AWS (8):** `bff`, `crapi-web`, `crapi-community`, `crapi-workshop`, `mongodb`, `redis`, `mailhog`, `opa`.
**OpenStack (3):** `crapi-identity`, `postgresdb`, `opa`.
**SPIFFE (5):** `aws/bff`, `aws/crapi-web`, `aws/crapi-community`, `aws/crapi-workshop`, `openstack/crapi-identity`.

---

## 2. TOPOLOGY ĐÍCH

```
 Browser ──HTTPS──▶ Traefik(crapi.ztlab.local)
                      │
        ┌─────────────▼──────────────────── AWS K3s · ns crapi ──────────────────────────────┐
        │  bff  ── Keycloak OIDC/PKCE (ns identity) ──▶ Keycloak                              │
        │   │   ── mint crAPI JWT (khoá RSA crAPI) ; device-trust + device-posture ; audit→Loki│
        │   │   ── rate-limit / PKCE state ──▶ redis                                          │
        │   ├──▶ crapi-web        (static React, :80)                                        │
        │   ├──▶ crapi-community  (:8087) ──▶ mongodb(:27017)  [Postgres + verify JWT: cross-cloud ▼] │
        │   └──▶ crapi-workshop   (:8000) ──▶ mongodb(:27017)  [Postgres + verify JWT: cross-cloud ▼] │
        │  opa (:9191 ext_authz zta/authz/allow, :8181)                                      │
        └────────────────────┼───────────────────────────────────────────────────────────────┘
       cross-cloud (WireGuard):│ identity NodePort 30090 (HTTP, +mTLS ISTIO_MUTUAL)
                               │ postgresdb NodePort 30432 (TCP 5432, WireGuard only)
        ┌──────────────────────▼──────────── OpenStack K3s · ns crapi ───────────────────────┐
        │  crapi-identity (:8080)  ◀── bff, crapi-community, crapi-workshop (verify JWT/req)  │
        │  crapi-identity + crapi-community + crapi-workshop ──▶ postgresdb (:5432, 1 DB crapi)│
        │  crapi-identity ──SMTP :1025──▶ mailhog (AWS, NodePort 31025 + WG)                  │
        │  opa (:9191 ext_authz zta/crosscloud/allow, :8181)                                 │
        └───────────────────────────────────────────────────────────────────────────────────┘
```

**Hop cross-cloud:** HTTP (mТLS ISTIO_MUTUAL + WireGuard): `bff→identity`, `community→identity`, `workshop→identity`. TCP (WireGuard): `community→postgresdb`, `workshop→postgresdb`, `identity→mailhog` (SMTP).

---

## 3. LUỒNG REQUEST ĐÍCH (một hành động nhạy cảm: `POST /workshop/api/shop/orders`)

```
1. Browser → bff : có session Keycloak (đã PKCE login)
2. bff:
   - device-trust  = analyse(User-Agent, ASN, lịch sử) → "trusted"|"new_device"|"suspicious"
   - device-posture = shared/posture.py (posture của chính bff) → "compliant"
   - mint crapi_jwt = RS256({sub: user@email, role, exp}, crapi_priv_key)
   - proxy → crapi-workshop:8000  headers:
        Authorization: Bearer <crapi_jwt>          (crAPI cần)
        X-Access-Token: <keycloak_access_token>    (OPA cần)
        X-Device-Trust: trusted
        X-Device-Posture: compliant
3. istio-proxy(crapi-workshop) → OPA ext_authz (zta/authz/allow):
   - source_principal = spiffe://ztlab.local/aws/bff        → valid_svid ✓
   - allowed_by_acl[bff][crapi-workshop][POST] ⊇ /workshop/api/shop/orders ✓
   - sensitive_crapi_action ✓ → posture_compliant ✓ , device_trust_compliant (≠ suspicious) ✓
                              → requires_step_up (theo loại action) → step_up_satisfied (acr=high)
   - JWT (X-Access-Token): sig(Keycloak JWKS) ✓ , iss ✓ , aud=crapi-bff ✓ , exp ✓
                           role_permits_action[crapi-user][POST] ✓
   → allow=true , audit_log{decision_id, svid, resource, posture}
4. crapi-workshop xử lý đơn hàng (KHÔNG sửa gì — crAPI gốc)
5. Toàn bộ: istio access log (job=envoy-access) + OPA decision log (job=opa-decisions)
   + bff audit log → Loki → Grafana
```

**Lateral movement bị chặn:** nếu `crapi-community` bị chiếm và gọi `crapi-workshop` một path không có trong `service_acl[crapi-community][crapi-workshop]` → OPA `allow=false` → 403 → alert (Phase 7).

---

## 4. MA TRẬN PHÂN QUYỀN L7 ĐÍCH (`policy/service-graph.yaml`)

> Path chính xác chốt ở GATE 0 sau khi đọc `crapi-openapi-spec.json`. Bảng dưới là hình dạng.

| from | to | method: path-prefix | cross-cloud |
|---|---|---|---|
| `aws/bff` | `openstack/crapi-identity` | GET/POST/PUT/DELETE: `/identity/api` | ✓ |
| `aws/bff` | `aws/crapi-community` | GET/POST: `/community/api` | |
| `aws/bff` | `aws/crapi-workshop` | GET/POST/PUT: `/workshop/api` | |
| `aws/bff` | `aws/crapi-web` | GET: `/`, `/static` | |
| `aws/bff` | `aws/redis` | L4 6379 | |
| `aws/crapi-community` | `openstack/crapi-identity` | POST: `/identity/api/auth/verify` | ✓ |
| `aws/crapi-workshop` | `openstack/crapi-identity` | POST: `/identity/api/auth/verify` | ✓ |
| `aws/crapi-community` | `openstack/postgresdb` · `aws/mongodb` | L4 5432 (cross) · 27017 | ✓/— |
| `aws/crapi-workshop` | `openstack/postgresdb` · `aws/mongodb` | L4 5432 (cross) · 27017 | ✓/— |
| `openstack/crapi-identity` | `openstack/postgresdb` | L4 5432 | |
| `openstack/crapi-identity` | `aws/mailhog` | L4 1025 (SMTP) | ✓ |
| (mỗi service) | (opa cùng cluster) | L4 9191, 8181 | |

**Hành động nhạy cảm (`sensitive_crapi_action` — posture + device-trust + step-up):** — chốt ở GATE 3, đề xuất:
`POST /workshop/api/shop/orders`, `POST /workshop/api/shop/orders/return_order`, `POST /identity/api/v2/user/reset-password`, `POST /identity/api/v2/user/change-email`, `DELETE /identity/api/v2/admin/videos/*`.

---

## 5. ÁNH XẠ CƠ CHẾ BẢO MẬT FINANCE → CRAPI

| # | Cơ chế (finance) | Trạng thái đích (crAPI) |
|---|---|---|
| 1 | mТLS STRICT (Istio PeerAuth ns) | **Giữ nguyên** — ns `crapi` STRICT, PERMISSIVE chỉ `bff` |
| 2 | SPIRE SVID scheme riêng + DestinationRule custom-SAN | **Giữ nguyên** — 7 entry mới, 1 DR/service |
| 3 | OPA ext_authz fail-closed, 2 cluster 2 path | **Giữ nguyên** — `zta_policy.rego` + `cross_cloud.rego` viết lại dữ liệu |
| 4 | `service_acl` L7 sinh từ `service-graph.yaml` | **Giữ nguyên cơ chế** — `service-graph.yaml` mới, generator không đổi |
| 5 | NetworkPolicy L4 allow-list + pod-segmentation | **Giữ nguyên** — rewrite ns `crapi` |
| 6 | Keycloak OIDC/PKCE + RBAC realm role | **Giữ nguyên** — ở `bff`; role rename `crapi-user/crapi-admin/soc-analyst` |
| 7 | OPA tự verify chữ ký JWT (JWKS + OIDC discovery) + `aud` | **Giữ nguyên** — token Keycloak ở `X-Access-Token`, `aud=crapi-bff` |
| 8 | Step-up OTP `acr=high` (Conditional-OTP flow) | **Giữ nguyên** — map sang hành động crAPI nhạy cảm (theo *loại* action) |
| 9 | Device posture workload (`X-Device-Posture`, `shared/posture.py`) | **Giữ nguyên** — `bff` tự kiểm posture, gắn header; OPA `posture_compliant` |
| 10 | Device trust browser (`X-Device-Trust`) | **Giữ nguyên** — `bff` tính (bê từ `web-portal`); OPA `device_trust_compliant` |
| 11 | ~~Fraud gate + verdict ký SVID (T-1.5)~~ | **BỎ** — đặc thù ngân hàng (rủi ro theo amount/velocity), không có tương đương crAPI |
| 12 | `posture-agent` CronJob + `security-scanner-job` | **Giữ nguyên** — move ns `crapi` |
| 13 | Gatekeeper admission (nonroot dryrun, image-policy deny) | **Giữ nguyên** — cluster-level, không đổi |
| 14 | Vault (KV, kubernetes auth, soar-engine) | **Giữ nguyên** |
| 15 | Audit log OPA (`decision_id` mỗi decision) | **Giữ nguyên** |
| 16 | PLG pipeline (Promtail→Loki→Grafana), istio access log, OPA decision log, Loki relay cross-cloud | **Giữ nguyên, chạy từ Phase 1** — chỉ đổi regex ns `financial`→`crapi` |
| 17 | SOAR HITL engine + playbook (isolate/quarantine/block_ip/restrict_egress) | **Giữ engine** — `ALERT_TARGET` map lại (Phase 7) |
| 18 | ai-analyzer (LLM log analysis) + security-scorer | **Giữ** — `SERVICES`/RULES cập nhật (Phase 7) |
| 19 | Cross-cloud NodePort + WireGuard + selectorless Svc + DR ISTIO_MUTUAL | **Giữ nguyên** — `crapi-identity-openstack`, `mailhog-aws` |
| 20 | Grafana alert rules (9) — nội dung theo endpoint finance | **Viết lại Phase 7** — BOLA/BFLA/SSRF/injection/brute-force-OTP/JWT-anomaly/priv-esc. Tới lúc đó lớp *phát hiện* chưa khớp crAPI (đường ống vẫn chạy) |

**Không port (đặc thù ngân hàng, không có tương đương crAPI):** `fraud-detection` (chấm điểm rủi ro amount/velocity), `notification-service`, verdict ký SVID (T-1.5), `fraud_gate_valid`, ngưỡng giao dịch VND (`STEP_UP_SINGLE_VND`…), luỹ kế ngày (`daily_cumulative`), `core_transaction_with_fraud_gate` cho `/transactions/execute`. → step-up/posture/device-trust vẫn gate hành động nhạy cảm crAPI, chỉ theo *loại hành động* thay vì theo số tiền. Trục "dynamic policy" (tenet 4) thu hẹp: còn device-trust + device-posture + step-up + RBAC + trạng thái SVID; mất trục amount/velocity — ghi rõ trong luận văn như một khác biệt có chủ đích.

---

## 6. CÂY FILE ĐÍCH (khác biệt so với hiện trạng)

```
services/
  bff/                      ← MỚI (FastAPI: Keycloak OIDC/PKCE, mint crAPI token, reverse-proxy, device-trust + device-posture, audit→Loki)
  {api-gateway,payment-service,web-portal,core-banking,account-service,transaction-service,fraud-detection,notification-service}/  ← XOÁ (Phase 5)
  Dockerfile ← GIỮ ; shared/posture.py ← GIỮ ; shared/svid_sign.py ← XOÁ
k8s/crapi/                  ← MỚI (thay k8s/financial/)
  namespace.yaml aws-workloads.yaml os-workloads.yaml databases.yaml mailhog.yaml
  configmaps.yaml cross-cloud.yaml istio-policies.yaml ingress.yaml seed-job.yaml
  redis.yaml posture-agent-cronjob.yaml security-scanner-job.yaml   ← move từ k8s/financial/
  network-policies/{aws,os}-allow-list.yaml  {aws,os}-pod-segmentation.yaml(generated)
k8s/financial/             ← XOÁ (Phase 5)
opa/policies/
  zta_policy.rego cross_cloud.rego  ← viết lại (dữ liệu)
  service_acl.rego                  ← generated từ service-graph mới
  fraud_gate.rego                   ← XOÁ (không port)
policy/service-graph.yaml  ← viết lại toàn bộ
deploy/vendor/crapi-keys/jwks.json  ← MỚI (khoá RSA crAPI upstream, để bff mint token)
scripts/
  deploy-crapi.sh          ← MỚI (thay deploy_financial_* trong deploy-app.sh)
  sync-app-images.sh       ← đổi tên từ sync-financial-images.sh, +nhánh pull crapi/*
k8s/keycloak/realm-config.json  ← client crapi-bff/-stepup, role rename
KET-QUA-CRAPI.md           ← MỚI (log kết quả từng Phase — như KET-QUA-KIEM-TRA.md)
```

---

## 7. TIÊU CHÍ NGHIỆM THU CUỐI (Phase 6)

1. `terraform destroy` + `deploy-all.sh` từ 0 → toàn bộ pod `ns crapi` Running 2 cluster, seed Job Completed, **không `kubectl apply` tay nào**.
2. Login `crapi.ztlab.local` qua Keycloak (PKCE) → dùng được crAPI (vehicles, shop, community).
3. `istioctl proxy-config secret <pod>` → SVID `spiffe://ztlab.local/...` (SPIRE, không phải Citadel).
4. mТLS mọi hop service-to-service kể cả cross-cloud (peer cert có URI SAN SPIFFE).
5. Lateral movement (`crapi-community`→`crapi-workshop` path lạ) → OPA deny, decision log ghi.
6. posture `non-compliant` → deny; device-trust `suspicious` → deny; step-up: `acr!=high` trên hành động nhạy cảm → 401, sau OTP → 200.
7. BOLA/BFLA/mass-assignment của crAPI **vẫn tái hiện được** (ZTA network/identity không chặn app-layer authz — đúng chủ đích, làm rõ ranh giới đóng góp).
8. Loki: `{namespace="crapi"}`, `{job="envoy-access"}`, `{job="opa-decisions"}`, audit log bff — đều có dữ liệu; Grafana Explore query được.
9. `scripts/health-check.sh` FAIL=0 · `python3 tests/test_service_graph_consistency.py` PASS.
10. Phase 7: ≥1 kịch bản tấn công crAPI (vd BOLA spike) kích hoạt alert Grafana → SOAR tạo case HITL → admin chọn playbook → thực thi.

---

## 8. ĐIỂM CẦN NGƯỜI DÙNG (ngoài luồng tự động)

| Khi nào | Việc | Vì sao |
|---|---|---|
| Phase 6 | Chạy `scripts/destroy-all.sh` + `scripts/deploy-all.sh` (nếu classifier chặn agent) | Live-infra terraform |
| Phase 6 | Enroll OTP step-up qua browser 1 lần | Không tự động hoá được (QR thật) |

**Cập nhật 2026-09-09:** người dùng uỷ quyền agent chạy xuyên suốt Phase 0→7 **không cần duyệt thêm**. Các quyết định nhỏ (rename role, `sensitive_crapi_action`, branch, DB-2) agent đã tự quyết — xem `KET-QUA-CRAPI.md` GATE 0. Sau khi target đạt: agent tự chạy `destroy-all.sh` rồi `systemctl suspend` (nếu quyền cho phép; nếu không, báo người dùng chạy tay). Mọi GATE 🛑 = agent tự đi tiếp sau khi ghi nghiệm thu vào `KET-QUA-CRAPI.md`.

---

*Chờ người dùng duyệt. Duyệt = "OK target" / góp ý sửa. Sau đó agent chạy `KE-HOACH-CRAPI.md` từ Phase 0.*
