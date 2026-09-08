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
