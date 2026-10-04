# Service graph — bảng sinh tự động

> **GENERATED FILE — KHÔNG SỬA TAY.** Nguồn: `policy/service-graph-crapi.yaml`.
> Sinh lại: `python3 scripts/gen-docs-tables.py`. Tham chiếu từ `HE-THONG-CHI-TIET.md`
> thay vì lặp lại nội dung — sửa graph rồi chạy lại generator, đừng sửa file này.

## 1. Danh sách SPIFFE entry

**aws (8):**

- `spiffe://ztlab.local/aws/bff`
- `spiffe://ztlab.local/aws/crapi-community`
- `spiffe://ztlab.local/aws/crapi-web`
- `spiffe://ztlab.local/aws/crapi-workshop`
- `spiffe://ztlab.local/aws/edge-gateway`
- `spiffe://ztlab.local/aws/opa`
- `spiffe://ztlab.local/aws/prometheus` _(spire_only — không tham gia service_acl)_
- `spiffe://ztlab.local/aws/waf`

**openstack (5):**

- `spiffe://ztlab.local/openstack/crapi-identity`
- `spiffe://ztlab.local/openstack/crapi-seed` _(spire_only — không tham gia service_acl)_
- `spiffe://ztlab.local/openstack/kc-admin-setup`
- `spiffe://ztlab.local/openstack/keycloak`
- `spiffe://ztlab.local/openstack/opa`

## 2. Ma trận edge L7 (qua OPA service_acl)

| Nguồn (SPIFFE) | Đích | Method + path prefix |
|---|---|---|
| `spiffe://ztlab.local/aws/edge-gateway` | `spiffe://ztlab.local/aws/waf` | GET `/`; POST `/`; PUT `/`; DELETE `/`; PATCH `/`; HEAD `/`; OPTIONS `/` |
| `spiffe://ztlab.local/aws/waf` | `spiffe://ztlab.local/aws/bff` | GET `/`; POST `/`; PUT `/`; DELETE `/`; PATCH `/`; HEAD `/`; OPTIONS `/` |
| `spiffe://ztlab.local/aws/bff` | `spiffe://ztlab.local/openstack/crapi-identity` _(cross-cloud)_ | GET `/identity/api, /identity/health_check`; POST `/identity/api`; PUT `/identity/api`; DELETE `/identity/api` |
| `spiffe://ztlab.local/aws/bff` | `spiffe://ztlab.local/aws/crapi-community` | GET `/community/api`; POST `/community/api` |
| `spiffe://ztlab.local/aws/bff` | `spiffe://ztlab.local/aws/crapi-workshop` | GET `/workshop/api`; POST `/workshop/api`; PUT `/workshop/api` |
| `spiffe://ztlab.local/aws/bff` | `spiffe://ztlab.local/aws/crapi-web` | GET `/, /static, /images, /index.html, /favicon` |
| `spiffe://ztlab.local/aws/crapi-community` | `spiffe://ztlab.local/openstack/crapi-identity` _(cross-cloud)_ | POST `/identity/api/auth/verify`; GET `/identity/health_check` |
| `spiffe://ztlab.local/aws/crapi-workshop` | `spiffe://ztlab.local/openstack/crapi-identity` _(cross-cloud)_ | POST `/identity/api/auth/verify`; GET `/identity/health_check` |
| `spiffe://ztlab.local/aws/bff` | `spiffe://ztlab.local/openstack/keycloak` _(cross-cloud)_ | GET `/realms, /resources, /js`; POST `/realms` |
| `spiffe://ztlab.local/aws/opa` | `spiffe://ztlab.local/openstack/keycloak` _(cross-cloud)_ | GET `/realms` |
| `spiffe://ztlab.local/openstack/kc-admin-setup` | `spiffe://ztlab.local/openstack/keycloak` | GET `/`; POST `/`; PUT `/`; DELETE `/` |

## 3. Edge L4 thuần (không qua OPA service_acl)

| Nguồn | Đích | Port(s) | Cross-cloud |
|---|---|---|---|
| `aws/bff` | `aws/redis` | 6379 |  |
| `aws/crapi-community` | `aws/mongodb` | 27017 |  |
| `aws/crapi-workshop` | `aws/mongodb` | 27017 |  |
| `aws/crapi-community` | `openstack/postgresdb` | 30432 | có |
| `aws/crapi-workshop` | `openstack/postgresdb` | 30432 | có |
| `openstack/crapi-identity` | `openstack/postgresdb` | 5432 |  |
| `openstack/crapi-identity` | `aws/mailhog` | 31025 | có |
| `aws/bff` | `aws/opa` | 9191, 8181 |  |
| `aws/waf` | `aws/opa` | 9191, 8181 |  |
| `aws/crapi-web` | `aws/opa` | 9191, 8181 |  |
| `aws/crapi-community` | `aws/opa` | 9191, 8181 |  |
| `aws/crapi-workshop` | `aws/opa` | 9191, 8181 |  |
| `openstack/crapi-identity` | `openstack/opa` | 9191, 8181 |  |
| `openstack/keycloak` | `openstack/opa` | 9191, 8181 |  |

