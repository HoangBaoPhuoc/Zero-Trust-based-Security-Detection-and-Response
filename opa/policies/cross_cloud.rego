package zta.crosscloud

import future.keywords.if
import future.keywords.in

default allow = false
default allow_cross_cloud = false

allow_cross_cloud if {
  input.attributes.source.principal == "spiffe://ztlab.local/aws/payment-service"
  input.attributes.destination.principal == "spiffe://ztlab.local/openstack/core-banking"
}

allow if {
  startswith(input.attributes.source.principal, "spiffe://ztlab.local/aws/")
  input.attributes.request.http.method in ["GET", "POST"]
  not denied_path
}

allow if {
  startswith(input.attributes.source.principal, "spiffe://ztlab.local/openstack/")
  input.attributes.request.http.method in ["GET", "OPTIONS"]
}

denied_path if {
  startswith(input.attributes.request.http.path, "/admin")
}
