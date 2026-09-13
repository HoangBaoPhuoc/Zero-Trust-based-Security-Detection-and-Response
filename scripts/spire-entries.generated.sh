# GENERATED FILE — KHÔNG SỬA TAY. Nguồn: policy/service-graph-crapi.yaml
# Sinh lại: python3 scripts/gen-spire-entries.py
#
# scripts/ensure-spire-entries.sh source file này thay vì hardcode danh sách
# workload + số lượng kỳ vọng riêng — không còn 2 nơi có thể lệch nhau.

AWS_SPIRE_WORKLOADS=(
  "spiffe://ztlab.local/aws/bff|crapi|bff"
  "spiffe://ztlab.local/aws/crapi-community|crapi|crapi-community"
  "spiffe://ztlab.local/aws/crapi-web|crapi|crapi-web"
  "spiffe://ztlab.local/aws/crapi-workshop|crapi|crapi-workshop"
  "spiffe://ztlab.local/aws/edge-gateway|istio-system|istio-ingressgateway-service-account"
  "spiffe://ztlab.local/aws/opa|crapi|opa"
  "spiffe://ztlab.local/aws/prometheus|monitoring|prometheus"
  "spiffe://ztlab.local/aws/waf|crapi|waf"
)
AWS_EXPECTED_COUNT=8

OPENSTACK_SPIRE_WORKLOADS=(
  "spiffe://ztlab.local/openstack/crapi-identity|crapi|crapi-identity"
  "spiffe://ztlab.local/openstack/crapi-seed|crapi|crapi-seed"
  "spiffe://ztlab.local/openstack/kc-admin-setup|identity|kc-admin-setup"
  "spiffe://ztlab.local/openstack/keycloak|identity|keycloak"
  "spiffe://ztlab.local/openstack/opa|crapi|opa"
)
OPENSTACK_EXPECTED_COUNT=5
