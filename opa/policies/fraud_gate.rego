package zta.fraud_gate

import future.keywords.if

default fraud_gate_valid = false

fraud_gate_valid if {
  input.attributes.request.http.headers["x-fraud-gate"] == "passed"
  to_number(input.attributes.request.http.headers["x-fraud-score"]) < 75
}

fraud_gate_bypass_detected if {
  input.attributes.request.http.path == "/transactions/execute"
  not fraud_gate_valid
}

deny_reason := "fraud_gate_bypass" if {
  fraud_gate_bypass_detected
}
