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

package zta.authz

import future.keywords.if
import future.keywords.in

default allow = false

allow if {
  valid_jwt
  valid_svid
  role_permits_action
}

valid_jwt if {
  token := input.attributes.request.http.headers["authorization"]
  startswith(token, "Bearer ")
  [_, payload, _] := io.jwt.decode(token)
  payload.iss == "https://keycloak.ztlab.local/realms/ztlab"
  payload.exp > time.now_ns() / 1000000000
  input.parsed_body.subject = payload.sub
}

valid_svid if {
  svid := input.source.principal
  startswith(svid, "spiffe://ztlab.local/")
}

role_permits_action if {
  [_, payload, _] := io.jwt.decode(input.attributes.request.http.headers["authorization"])
  roles := payload.realm_access.roles
  input.attributes.request.http.method == "POST"
  startswith(input.attributes.request.http.path, "/transactions")
  "financial-write" in roles
}

role_permits_action if {
  [_, _payload, _] := io.jwt.decode(input.attributes.request.http.headers["authorization"])
  input.attributes.request.http.method in ["GET", "OPTIONS"]
}

audit_log := {
  "timestamp": time.now_ns(),
  "subject": input.parsed_body.subject,
  "action": input.attributes.request.http.method,
  "resource": input.attributes.request.http.path,
  "decision": allow,
  "svid": input.source.principal,
}
