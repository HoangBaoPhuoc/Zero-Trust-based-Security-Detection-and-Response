package zta.crosscloud

import future.keywords.if
import future.keywords.in

default allow = false
default allow_cross_cloud = false

# Specific cross-cloud relationship: payment-service (AWS) -> core-banking (OpenStack)
allow_cross_cloud if {
  input.attributes.source.principal == "spiffe://ztlab.local/aws/payment-service"
  input.attributes.destination.principal == "spiffe://ztlab.local/openstack/core-banking"
}

# Cross-cloud ingress: payment-service (AWS) proxies both transaction execution
# AND account management to core-banking (see services/payment-service/main.py:
# POST/GET /accounts, GET /accounts/{id}, GET /transactions, POST
# /transactions/execute — all forwarded to CORE_BANKING_URL). Originally this
# rule only covered "/transactions", which silently 403'd every account
# lookup/creation call (empty-body ext_authz deny, response_time ~1-4ms,
# upstream: null in istio-proxy access log) — found 2026-08-23 while
# investigating "chuyển khoản không thành công": first-login auto account
# creation always failed, so users had 0 accounts and transfer had nothing
# to transfer from.
# /transactions/execute is real money movement — the one path Device
# Posture (T5) is meant to gate. Found 2026-08-23: this path is reached via
# THIS package (zta.crosscloud), not zta.authz — the `posture_compliant`
# rule already written in zta_policy.rego's core_transaction_with_fraud_gate
# never actually ran for this real call, so the X-Device-Posture header
# payment-service now attaches (shared/posture.py) was arriving at OPA but
# not being checked by whichever rule actually decides this request. Split
# out so posture only gates the execute path, not account/history lookups.
allow if {
  input.attributes.source.principal == "spiffe://ztlab.local/aws/payment-service"
  input.attributes.destination.principal == "spiffe://ztlab.local/openstack/core-banking"
  input.attributes.request.http.method == "POST"
  input.attributes.request.http.path == "/transactions/execute"
  posture_compliant
}

allow if {
  input.attributes.source.principal == "spiffe://ztlab.local/aws/payment-service"
  input.attributes.destination.principal == "spiffe://ztlab.local/openstack/core-banking"
  input.attributes.request.http.method in ["GET", "POST"]
  startswith(input.attributes.request.http.path, "/transactions")
  input.attributes.request.http.path != "/transactions/execute"
}

# Additive: caller not yet updated to send the header (any other internal
# hop) is unaffected — only an explicit "non-compliant" value denies.
posture_compliant if {
  not input.attributes.request.http.headers["x-device-posture"]
}

posture_compliant if {
  input.attributes.request.http.headers["x-device-posture"] == "compliant"
}

allow if {
  input.attributes.source.principal == "spiffe://ztlab.local/aws/payment-service"
  input.attributes.destination.principal == "spiffe://ztlab.local/openstack/core-banking"
  input.attributes.request.http.method in ["GET", "POST"]
  startswith(input.attributes.request.http.path, "/accounts")
}

# Cross-cloud: api-gateway (AWS) manages accounts and reads transaction
# history on OpenStack (account lookup/creation at login, balance, history).
allow if {
  input.attributes.source.principal == "spiffe://ztlab.local/aws/api-gateway"
  input.attributes.destination.principal in {
    "spiffe://ztlab.local/openstack/account-service",
    "spiffe://ztlab.local/openstack/transaction-service",
  }
  input.attributes.request.http.method in ["GET", "POST"]
  not denied_path
}

# OpenStack-internal: any OS workload may call another OS service (no /admin)
allow if {
  startswith(input.attributes.source.principal, "spiffe://ztlab.local/openstack/")
  input.attributes.request.http.method in ["GET", "POST", "PUT", "OPTIONS"]
  not denied_path
}

denied_path if {
  startswith(input.attributes.request.http.path, "/admin")
}
