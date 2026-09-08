# crAPI JWT signing key (vendored from OWASP/crAPI @ develop)

`jwks.json` là khoá RSA (RS256) **của chính OWASP crAPI upstream**, công khai trong
repo của họ (`deploy/k8s/keys/jwks.json`) — không phải bí mật thật của hệ thống này.

Dùng để:
- `crapi-identity` ký/verify JWT nội bộ crAPI (mount `/.keys`, env `JWKS`).
- `bff` mint token crAPI-native cho từng user sau khi user đã đăng nhập Keycloak
  (token-exchange, xem `services/bff/`).

`scripts/deploy-crapi.sh` tạo Secret `crapi-jwt-key` từ file này trên cả 2 cluster.
