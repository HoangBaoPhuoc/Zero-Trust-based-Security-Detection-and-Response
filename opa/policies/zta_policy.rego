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

# Issuer trước đây hardcode 1 chuỗi cố định tại đây, PHẢI khớp tuyệt đối với
# cấu hình Keycloak thật (KC_HOSTNAME/KC_HOSTNAME_PORT) và với JWT_ISSUER của
# api-gateway ở một file khác — 3 nơi độc lập cùng phải đồng bộ tay. Lệch 1
# ký tự (đã xảy ra ngày 2026-08-13, thiếu KC_HOSTNAME_PORT) làm toàn bộ JWT
# bị OPA từ chối. Giờ tự hỏi OIDC discovery document — nguồn sự thật do
# chính Keycloak công bố — cache 5 phút để không tốn round-trip mỗi request.
discovery_response := http.send({
  "method": "GET",
  "url": "http://keycloak.identity.svc.cluster.local:8080/realms/ztlab/.well-known/openid-configuration",
  "force_cache": true,
  "force_cache_duration_seconds": 300,
  "raise_error": false,
})

# Fallback nếu discovery lỗi (Keycloak chưa lên, mạng lỗi...) — không để
# toàn bộ policy sập theo kiểu fail-closed tệ hơn cả lỗi cũ.
default expected_issuer := "http://keycloak.ztlab.local:8180/realms/ztlab"

expected_issuer := discovery_response.body.issuer if {
  not discovery_response.error
  discovery_response.status_code == 200
  discovery_response.body.issuer
}

valid_jwt if {
  jwt_payload.iss == expected_issuer
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
  not startswith(path, "/transactions/execute")
}

core_transaction_with_fraud_gate if {
  valid_svid
  method == "POST"
  startswith(path, "/transactions/execute")
  fraud_gate_valid
  posture_compliant
}

valid_svid if {
  startswith(source_principal, "spiffe://ztlab.local/")
}

fraud_gate_valid if {
  headers["x-fraud-gate"] == "passed"
  to_number(headers["x-fraud-score"]) < 75
}

# Device/workload posture (T5 — insider với credential hợp lệ nhưng posture fail).
# Cập nhật 2026-08-23: payment-service giờ tự tính posture thật (in-process,
# shared/posture.py, không gọi mạng) và gắn header X-Device-Posture thật khi
# gọi core-banking /transactions/execute — hoàn thiện phần còn thiếu của kế
# hoạch cũ (trước đó chỉ có rule Rego + test cô lập, chưa có nguồn tín hiệu
# thật). Chuẩn "compliant" cố ý lỏng hơn "phải chạy non-root": kiểm tra thật
# ngày 2026-08-23 cho thấy MỌI service ở đây đều chạy uid=0, đọc được
# /etc/shadow, không có securityContext nào — đúng dấu hiệu "vi phạm" mà
# k8s/financial/security-scanner-job.yaml dùng để giả lập KB6. Enforce đúng
# chuẩn đó sẽ chặn luôn mọi giao dịch thật hiện tại. Nên compliant chỉ fail
# khi có dấu hiệu thật sự nguy hiểm: capability vượt quá tập mặc định của
# Docker (SYS_ADMIN/SYS_PTRACE/NET_ADMIN/SYS_MODULE/ALL) hoặc image không ghim
# tag (`:latest`/không tag) — khớp đúng chuẩn k8s/financial/posture-agent-
# cronjob.yaml dùng để audit định kỳ toàn bộ pod trong namespace.
# Vẫn giữ thiết kế cộng thêm: nếu caller không gửi header (service cũ/khác
# chưa cập nhật) thì coi như không áp dụng, cho qua — không phá traffic khác.
# tests/grafana_kb_t5_noncompliant_device.sh vẫn giả lập trực tiếp giá trị
# "non-compliant" qua REST API của OPA để kiểm chứng nhánh deny độc lập với
# payment-service thật.
posture_compliant if {
  not headers["x-device-posture"]
}

posture_compliant if {
  headers["x-device-posture"] == "compliant"
}

audit_log := {
  "timestamp":         time.now_ns(),
  "action":            method,
  "resource":          path,
  "decision":          allow,
  "svid":              source_principal,
  "device_posture":    object.get(headers, "x-device-posture", "not_reported"),
}
