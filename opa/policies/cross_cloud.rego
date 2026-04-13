package zta.cross_cloud

default allow_cross_cloud = false

allow_cross_cloud {
  input.source.principal == "spiffe://ztlab.local/aws/payment-service"
  input.destination.principal == "spiffe://ztlab.local/os/core-banking"
}

package zta.crosscloud

import future.keywords.if
import future.keywords.in

default allow = false

allow if {
  startswith(input.source.principal, "spiffe://ztlab.local/aws/")
  input.attributes.request.http.method in ["GET", "POST"]
  not denied_path
}

allow if {
  startswith(input.source.principal, "spiffe://ztlab.local/os/")
  input.attributes.request.http.method in ["GET", "OPTIONS"]
}

denied_path if {
  startswith(input.attributes.request.http.path, "/admin")
}
