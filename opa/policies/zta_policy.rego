package zta.authz

import future.keywords.if
import future.keywords.in

default allow = false

valid_jwt if {
  token := input.attributes.request.http.headers["authorization"]
  token != ""
}

valid_svid if {
  svid := input.source.principal
  startswith(svid, "spiffe://ztlab.local/")
}

role_permits_action if {
  method := input.attributes.request.http.method
  method in ["GET", "POST", "OPTIONS"]
}

allow if {
  valid_jwt
  valid_svid
  role_permits_action
}

# TODO: populate from IMPLEMENTATION.md §5.2
