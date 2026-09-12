package zta.crapi.authz

# PDP cho ứng dụng mục tiêu crAPI (cluster AWS). Envoy ext_authz path
# `zta/crapi/authz/allow`. Xem KE-HOACH-CRAPI.md Phase 3 + TARGET-CRAPI.md §5.
#
# Khác opa/policies/zta_policy.rego (finance):
#   - Token Keycloak người dùng đọc từ header `X-Access-Token` (bff đặt); header
#     `Authorization` mang token crAPI-native (crAPI cần) nên KHÔNG dùng để authz.
#   - `aud` = "crapi-bff".
#   - RBAC map sang path crAPI (crapi-user/mechanic/admin/soc-analyst).
#   - GIỮ: device posture + device trust + step-up (theo LOẠI hành động).
#   - BỎ: fraud-gate score, ngưỡng VND, daily_cumulative, /transactions/execute.
#   - `internal_service_request` (chống lateral movement) — GIỮ nguyên cơ chế,
#     dữ liệu từ data.zta.crapi.generated.service_acl.

import future.keywords.if
import future.keywords.in

default allow := false

headers          := input.attributes.request.http.headers
method           := input.attributes.request.http.method
path             := input.attributes.request.http.path
source_principal := object.get(
  object.get(input.attributes, "source", {}), "principal",
  object.get(object.get(input, "source", {}), "principal", ""))

# ── JWT Keycloak (X-Access-Token; fallback Authorization cho client test) ────
bearer_token := t if {
  raw := headers["x-access-token"]
  raw != ""
  t := raw
}

bearer_token := t if {
  not headers["x-access-token"]
  raw := headers["authorization"]
  startswith(raw, "Bearer ")
  t := substring(raw, 7, -1)
}

# A1: Keycloak moved to OpenStack — OPA (AWS) reaches it via the cross-cloud
# selectorless Service keycloak-openstack:30091 (→ os-k3s-master NodePort → WG).
# Only the AWS PDP (zta/crapi/authz/allow) evaluates this; the OpenStack PDP
# (crosscloud) never does, so the name not resolving there is harmless.
jwks_response := http.send({
  "method": "GET",
  "url": "http://keycloak-openstack.crapi.svc.cluster.local:30091/realms/ztlab/protocol/openid-connect/certs",
  "force_cache": true,
  "force_cache_duration_seconds": 300,
  "raise_error": false,
})

discovery_response := http.send({
  "method": "GET",
  "url": "http://keycloak-openstack.crapi.svc.cluster.local:30091/realms/ztlab/.well-known/openid-configuration",
  "force_cache": true,
  "force_cache_duration_seconds": 300,
  "raise_error": false,
})

default expected_issuer := "http://keycloak.ztlab.local:8180/realms/ztlab"

expected_issuer := discovery_response.body.issuer if {
  not discovery_response.error
  discovery_response.status_code == 200
  discovery_response.body.issuer
}

jwt_verify_result := io.jwt.decode_verify(bearer_token, {
  "cert": jwks_response.raw_body,
  "iss": expected_issuer,
  "aud": "crapi-bff",
}) if {
  not jwks_response.error
  jwks_response.status_code == 200
}

jwt_signature_valid if { jwt_verify_result[0] == true }

jwt_payload := jwt_verify_result[2] if { jwt_signature_valid }

valid_jwt if {
  jwt_signature_valid
  jwt_payload.iss == expected_issuer
  jwt_payload.exp > time.now_ns() / 1000000000
}

realm_roles := jwt_payload.realm_access.roles if { jwt_signature_valid }
default realm_roles := []

# ── RBAC: role Keycloak → (method, path-prefix crAPI) ───────────────────────
# soc-analyst: chỉ đọc. crapi-user: đọc + hành động cơ bản. crapi-mechanic:
# thêm mechanic endpoints. crapi-admin: thêm admin/management.
role_read_ok if {
  some r in realm_roles
  r in {"crapi-user", "crapi-mechanic", "crapi-admin", "soc-analyst"}
  method in ["GET", "OPTIONS", "HEAD"]
}

role_write_ok if {
  some r in realm_roles
  r in {"crapi-user", "crapi-mechanic", "crapi-admin"}
  method in ["POST", "PUT", "PATCH", "DELETE"]
  not admin_path
  not mechanic_only_path
}

role_write_ok if {
  some r in realm_roles
  r in {"crapi-mechanic", "crapi-admin"}
  mechanic_only_path
}

role_write_ok if {
  "crapi-admin" in realm_roles
  method in ["POST", "PUT", "PATCH", "DELETE"]
}

admin_path if { startswith(path, "/identity/api/v2/admin") }
admin_path if { startswith(path, "/workshop/api/management") }
mechanic_only_path if { startswith(path, "/workshop/api/mechanic/service_requests") }
mechanic_only_path if { startswith(path, "/workshop/api/mechanic/mechanic_report") }

role_permits_action if { role_read_ok }
role_permits_action if { role_write_ok }

# ── Device posture / trust (bff đặt header) ─────────────────────────────────
posture_compliant if { not headers["x-device-posture"] }
posture_compliant if { headers["x-device-posture"] == "compliant" }

device_trust_compliant if { not headers["x-device-trust"] }
device_trust_compliant if { headers["x-device-trust"] != "suspicious" }

# ── Step-up: hành động nhạy cảm cần acr=high (theo LOẠI, không theo số tiền) ─
sensitive_crapi_action if {
  method == "POST"
  some p in [
    "/workshop/api/shop/orders",
    "/workshop/api/shop/orders/return_order",
    "/identity/api/v2/user/reset-password",
    "/identity/api/v2/user/change-email",
  ]
  startswith(path, p)
}

step_up_satisfied if { jwt_payload.acr == "high" }

# ── service_acl (chống lateral movement — GIỮ cơ chế finance) ───────────────
service_acl := data.zta.crapi.generated.service_acl

allowed_by_acl if {
  allowed_paths := service_acl[source_principal][destination_principal][method]
  some p in allowed_paths
  startswith(path, p)
}

destination_principal := object.get(
  object.get(input.attributes, "destination", {}), "principal",
  object.get(object.get(input, "destination", {}), "principal", ""))

valid_svid if { startswith(source_principal, "spiffe://ztlab.local/") }

# ── Quyết định ─────────────────────────────────────────────────────────────
allow if { public_path }
allow if { internal_service_request }

public_path if { path in ["/health", "/ready", "/metrics", "/identity/health_check"] }
public_path if { startswith(path, "/metrics") }
# crAPI public auth endpoints (signup/login/OTP) — không cần Keycloak token
public_path if {
  method == "POST"
  some p in [
    "/identity/api/auth/signup",
    "/identity/api/auth/login",
    "/identity/api/auth/forget-password",
    "/identity/api/auth/v2/check-otp",
    "/identity/api/auth/v3/check-otp",
    "/identity/api/auth/v2.7/user/login-with-token",
    "/identity/api/auth/v4.0/user/login-with-token",
    "/identity/api/auth/verify",
    "/workshop/api/mechanic/signup",
  ]
  startswith(path, p)
}
public_path if { method == "GET"; startswith(path, "/identity/api/auth/jwks.json") }
# BFF OIDC bootstrap (services/bff/main.py) — điểm vào DUY NHẤT của crAPI, phải
# vào được TRƯỚC KHI có session/token. Áp cho cả hop Traefik→waf (A3 — không có
# source_principal vì Traefik không trong mesh) lẫn waf→bff — thiếu rule này thì
# public_path/internal_service_request đều fail (không SVID) và OPA chặn luôn
# bước đăng nhập đầu tiên, trước khi có cơ hội kiểm token/device/RBAC.
public_path if {
  method in ["GET", "POST"]
  some p in ["/auth/start", "/auth/callback", "/auth/logout", "/login", "/kc"]
  startswith(path, p)
}
# waf's OWN inbound hop (Traefik -> waf) can NEVER have a SPIFFE source_principal
# — Traefik sits outside the mesh by design, so internal_service_request/valid_svid
# is structurally unreachable here regardless of path. Real authz for these
# requests happens one hop later (waf -> bff, real mTLS SVID both sides) via
# internal_service_request; this rule only lets waf itself pass the request on.
# Gated on the same shared edge-marker secret Traefik stamps and BFF already
# trusts (RÀNG BUỘC #5) so a pod calling waf directly (no marker) still can't
# forge this — without it, every non-public_path request would 403 at waf
# before ever reaching bff's real check.
public_path if {
  source_principal == ""
  destination_principal == ""
  headers["x-edge-marker"] == opa.runtime().env.EDGE_MARKER
  opa.runtime().env.EDGE_MARKER != ""
}
# crapi-web static — bff → crapi-web GET
public_path if {
  method in ["GET", "HEAD"]
  startswith(source_principal, "spiffe://ztlab.local/aws/bff")
  destination_principal == "spiffe://ztlab.local/aws/crapi-web"
}

internal_service_request if {
  valid_svid
  allowed_by_acl
  keycloak_gate
}

# Với hop bff→backend, Keycloak token của người dùng cuối (X-Access-Token) là
# lớp authz người-dùng thật; hop community/workshop→identity là service-to-
# service (không có token người dùng ở header đó) — cho qua theo service_acl.
keycloak_gate if {
  not startswith(source_principal, "spiffe://ztlab.local/aws/bff")
}

keycloak_gate if {
  startswith(source_principal, "spiffe://ztlab.local/aws/bff")
  valid_jwt
  role_permits_action
  posture_ok
  device_trust_ok
  step_up_ok
}

# Device posture + device trust là tín hiệu "dynamic policy" (tenet 7) — áp cho
# hành động GHI và hành động nhạy cảm, KHỚP với BFF `_rbac_ok` (chỉ chặn
# suspicious device ở POST/PUT/PATCH/DELETE) và KE-HOACH-CRAPI.md §3.2
# ("áp cho sensitive_crapi_action"). Đọc thường (GET/HEAD, không nhạy cảm) vẫn
# đủ mạnh bằng valid_jwt + RBAC + valid_svid + mТLS.
strong_control_required if { method in ["POST", "PUT", "PATCH", "DELETE"] }
strong_control_required if { sensitive_crapi_action }

posture_ok if { not strong_control_required }
posture_ok if { strong_control_required; posture_compliant }

device_trust_ok if { not strong_control_required }
device_trust_ok if { strong_control_required; device_trust_compliant }

step_up_ok if { not sensitive_crapi_action }
step_up_ok if { sensitive_crapi_action; step_up_satisfied }

# ── Audit ──────────────────────────────────────────────────────────────────
audit_log := {
  "timestamp":      time.now_ns(),
  "action":         method,
  "resource":       path,
  "decision":       allow,
  "svid":           source_principal,
  "device_posture": object.get(headers, "x-device-posture", "not_reported"),
  "device_trust":   object.get(headers, "x-device-trust", "not_reported"),
  "step_up":        object.get(jwt_payload, "acr", "none"),
}
