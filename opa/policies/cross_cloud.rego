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

# Cross-cloud ingress: only payment-service may POST to /transactions on core-banking
allow if {
  input.attributes.source.principal == "spiffe://ztlab.local/aws/payment-service"
  input.attributes.destination.principal == "spiffe://ztlab.local/openstack/core-banking"
  input.attributes.request.http.method == "POST"
  startswith(input.attributes.request.http.path, "/transactions")
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
