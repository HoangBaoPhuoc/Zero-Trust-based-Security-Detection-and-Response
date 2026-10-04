package zta.crapi.crosscloud

# PDP cho crapi-identity (cluster OpenStack). Envoy ext_authz path
# `zta/crapi/crosscloud/allow`. Guard: chỉ bff / crapi-community / crapi-workshop
# (theo service_acl) được gọi identity. Không có fraud-gate / device-trust
# (identity không phải đích hành động nhạy cảm — step-up gate ở tầng bff/AWS OPA).

import future.keywords.if
import future.keywords.in

default allow := false

headers := object.get(input.attributes.request.http, "headers", {})
method  := input.attributes.request.http.method
path    := input.attributes.request.http.path
source_principal      := object.get(input.attributes.source, "principal", "")
destination_principal := object.get(input.attributes.destination, "principal", "")

service_acl := data.zta.crapi.generated.service_acl

allowed_by_acl if {
  allowed_paths := service_acl[source_principal][destination_principal][method]
  some p in allowed_paths
  startswith(path, p)
}

posture_compliant if { not headers["x-device-posture"] }
posture_compliant if { headers["x-device-posture"] == "compliant" }

allow if { public_path }
allow if {
  startswith(source_principal, "spiffe://ztlab.local/")
  allowed_by_acl
  posture_compliant
}

public_path if { path in ["/health", "/ready", "/metrics", "/identity/health_check"] }
public_path if { startswith(path, "/metrics") }
public_path if {
  method == "POST"
  some p in [
    "/identity/api/auth/signup", "/identity/api/auth/login",
    "/identity/api/auth/forget-password", "/identity/api/auth/v2/check-otp",
    "/identity/api/auth/v3/check-otp", "/identity/api/auth/verify",
    "/identity/api/auth/v2.7/user/login-with-token",
    "/identity/api/auth/v4.0/user/login-with-token",
    "/identity/api/auth/reset-test-users",
  ]
  startswith(path, p)
}
public_path if { method == "GET"; startswith(path, "/identity/api/auth/jwks.json") }

audit_log := {
  "timestamp": time.now_ns(), "action": method, "resource": path,
  "decision": allow, "svid": source_principal,
}
