package zta.crapi.generated

# GENERATED FILE — KHÔNG SỬA TAY. Nguồn: policy/service-graph-crapi.yaml
# Sinh lại: python3 scripts/gen-rego-acl.py --crapi
#
# Ma trận phân quyền service-to-service (L7) cho ứng dụng mục tiêu crAPI —
# import bởi opa/crapi-policies/{zta_crapi,crosscloud_crapi}.rego qua
# `data.zta.crapi.generated`. Xem KE-HOACH-CRAPI.md Phase 3 + KET-QUA-CRAPI.md GATE 0.

service_acl := {
  "spiffe://ztlab.local/aws/bff": {
    "spiffe://ztlab.local/openstack/crapi-identity": {
      "GET": ["/identity/api", "/identity/health_check"],
      "POST": ["/identity/api"],
      "PUT": ["/identity/api"],
      "DELETE": ["/identity/api"],
    },
    "spiffe://ztlab.local/aws/crapi-community": {
      "GET": ["/community/api"],
      "POST": ["/community/api"],
    },
    "spiffe://ztlab.local/aws/crapi-workshop": {
      "GET": ["/workshop/api"],
      "POST": ["/workshop/api"],
      "PUT": ["/workshop/api"],
    },
    "spiffe://ztlab.local/aws/crapi-web": {
      "GET": ["/", "/static", "/images", "/index.html", "/favicon"],
    },
  },
  "spiffe://ztlab.local/aws/crapi-community": {
    "spiffe://ztlab.local/openstack/crapi-identity": {
      "POST": ["/identity/api/auth/verify"],
      "GET": ["/identity/health_check"],
    },
  },
  "spiffe://ztlab.local/aws/crapi-workshop": {
    "spiffe://ztlab.local/openstack/crapi-identity": {
      "POST": ["/identity/api/auth/verify"],
      "GET": ["/identity/health_check"],
    },
  },
}
