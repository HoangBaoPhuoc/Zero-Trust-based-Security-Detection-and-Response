package zta.authz

import future.keywords.if
import future.keywords.in

default allow = false

headers          := input.attributes.request.http.headers
method           := input.attributes.request.http.method
path             := input.attributes.request.http.path
source_principal := object.get(
  object.get(input.attributes, "source", {}), "principal",
  object.get(object.get(input, "source", {}), "principal", ""))

# JWT signature verification is done by api-gateway (python-jose + Keycloak JWKS).
# OPA's role: claims-based authorization — issuer, expiry, realm roles.
# Using io.jwt.decode (no signature check) is correct here because the upstream
# api-gateway already rejected any request with an invalid signature before it
# reaches downstream services with OPA sidecars.

bearer_token := t if {
  raw := headers["authorization"]
  startswith(raw, "Bearer ")
  t := substring(raw, 7, -1)
}

jwt_payload := payload if {
  [_, payload, _] := io.jwt.decode(bearer_token)
}

valid_jwt if {
  jwt_payload.iss == "http://keycloak.ztlab.local/realms/ztlab"
  jwt_payload.exp > time.now_ns() / 1000000000
}

permissions := {
  "financial-read":   {"GET": true, "OPTIONS": true},
  "financial-write":  {"GET": true, "OPTIONS": true, "POST": true, "PUT": true},
  "security-analyst": {"GET": true, "OPTIONS": true},
  "security-admin":   {"GET": true, "OPTIONS": true, "POST": true, "PUT": true, "DELETE": true},
}

role_permits_action if {
  some role in jwt_payload.realm_access.roles
  permissions[role][method]
}

allow if { public_path }
allow if { external_api_request }
allow if { internal_service_request }
allow if { core_transaction_with_fraud_gate }

public_path if { path in ["/health", "/ready", "/metrics"] }
public_path if { startswith(path, "/metrics") }

external_api_request if {
  method == "POST"
  path == "/payments"
  valid_jwt
  role_permits_action
  not valid_svid
}

external_api_request if {
  method == "POST"
  path == "/accounts"
  valid_jwt
  role_permits_action
  not valid_svid
}

external_api_request if {
  method in ["GET", "OPTIONS"]
  valid_jwt
  role_permits_action
  not valid_svid
}

internal_service_request if {
  valid_svid
  method in ["GET", "OPTIONS"]
}

internal_service_request if {
  valid_svid
  method == "POST"
  path in ["/payments", "/score", "/notify"]
}

internal_service_request if {
  valid_svid
  method == "POST"
  startswith(path, "/accounts")
}

internal_service_request if {
  valid_svid
  method == "POST"
  startswith(path, "/transactions")
}

core_transaction_with_fraud_gate if {
  valid_svid
  method == "POST"
  startswith(path, "/transactions/execute")
  fraud_gate_valid
}

valid_svid if {
  startswith(source_principal, "spiffe://ztlab.local/")
}

fraud_gate_valid if {
  headers["x-fraud-gate"] == "passed"
  to_number(headers["x-fraud-score"]) < 75
}

audit_log := {
  "timestamp": time.now_ns(),
  "action":    method,
  "resource":  path,
  "decision":  allow,
  "svid":      source_principal,
}
