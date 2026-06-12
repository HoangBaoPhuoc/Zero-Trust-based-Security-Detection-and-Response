package zta.authz

import future.keywords.if
import future.keywords.in

default allow = false

headers := input.attributes.request.http.headers
method := input.attributes.request.http.method
path := input.attributes.request.http.path
source_principal := object.get(object.get(input.attributes, "source", {}), "principal", object.get(object.get(input, "source", {}), "principal", ""))

has_bearer_token if {
  token := headers["authorization"]
  startswith(token, "Bearer ")
}

allow if {
  public_path
}

# External user requests are allowed only on edge API paths and only when a
# bearer token is present. JWT signature, issuer, expiry, audience, and roles
# are enforced by api-gateway with Keycloak JWKS; OPA must not authorize based
# on decoded-but-unverified JWT claims.
allow if {
  external_api_request
}

# Internal service calls are identity based. A plain in-cluster request with only
# an Authorization header must not reach sensitive financial services.
allow if {
  internal_service_request
}

allow if {
  core_transaction_with_fraud_gate
}

public_path if {
  path in ["/health", "/ready", "/metrics"]
}

public_path if {
  startswith(path, "/metrics")
}

external_api_request if {
  method == "POST"
  path == "/payments"
  has_bearer_token
  not valid_svid
}

# Allow external users to create bank accounts via api-gateway with JWT
external_api_request if {
  method == "POST"
  path == "/accounts"
  has_bearer_token
  not valid_svid
}

external_api_request if {
  method in ["GET", "OPTIONS"]
  has_bearer_token
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

# core-banking → account-service: POST /accounts/transfer and POST /accounts
internal_service_request if {
  valid_svid
  method == "POST"
  startswith(path, "/accounts")
}

# core-banking → transaction-service: POST /transactions (ledger write)
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
  "action": method,
  "resource": path,
  "decision": allow,
  "svid": source_principal,
}
