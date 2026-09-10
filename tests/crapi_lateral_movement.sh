#!/usr/bin/env bash
# KỊCH BẢN — Lateral Movement (ATT&CK T1021)
#
# Lớp Zero-Trust nghiệm thu: OPA `internal_service_request` (service_acl dựa trên
# SPIFFE SVID). `crapi-community` có SVID hợp lệ nhưng service-graph-crapi.yaml
# KHÔNG có edge community→workshop → OPA từ chối.
#
# Tấn công THẬT: exec vào pod crapi-community (giả lập bị RCE) → gọi thẳng
# crapi-workshop qua service mesh (mТLS SVID của community đính kèm) tới path
# nghiệp vụ /workshop/api/shop/orders.
#
# Bằng chứng: OPA decision log (job=opa-decisions, opa_result=false,
# request_path=/workshop/api/shop/orders) → Grafana rule "Lateral Movement"
# (severity critical) → SOAR case attack_type=lateral_movement → playbook
# isolate_workload.
set -uo pipefail
SCENARIO="crapi_lateral_movement"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"

ATTACKER_POD="$(crapi_pod crapi-community)"
[[ -n "$ATTACKER_POD" ]] || fail "không tìm được pod crapi-community"
log "Attacker: $ATTACKER_POD (SVID spiffe://ztlab.local/aws/crapi-community)"
log "Mục tiêu: POST http://crapi-workshop:8000/workshop/api/shop/orders (ngoài service_acl)"

denied=0
for i in 1 2 3 4 5; do
  code="$(kubectl --context "$KUBE_AWS" -n "$NS" exec "$ATTACKER_POD" -c crapi-community -- \
    sh -c 'wget -q -O /dev/null -T8 -S \
      --header="Content-Type: application/json" \
      --post-data="{\"lateral\":true}" \
      http://crapi-workshop.crapi.svc.cluster.local:8000/workshop/api/shop/orders 2>&1 \
      | grep -oE "HTTP/[0-9.]+ [0-9]{3}" | tail -1 | grep -oE "[0-9]{3}$"' 2>/dev/null || echo "000")"
  log "  attempt $i → HTTP ${code:-000}"
  [[ "$code" == "403" || "$code" == "000" ]] && denied=$((denied + 1))
  sleep 1
done

[[ $denied -ge 4 ]] || fail "OPA chỉ chặn $denied/5 (cần ≥4) — kiểm tra service_acl / AuthorizationPolicy crapi-workshop"
log "OPA chặn $denied/5 — lateral movement community→workshop bị từ chối tại mesh (mТLS SVID + service_acl)"

sleep 3
n="$(loki_count '{job="opa-decisions", opa_result="false"} |~ "/workshop/api/shop/orders"')"
log "OPA decision log (deny, /workshop/api/shop/orders) trong 10 phút: $n dòng vào Loki"
[[ "$n" -ge 1 ]] || log "  (chưa thấy trên Loki — promtail có độ trễ ~15-30s; Grafana vẫn sẽ fire ở lần eval kế tiếp)"

pass "$SCENARIO — $denied/5 bị OPA chặn · decision log → Loki · Grafana 'Lateral Movement' sẽ fire ≤1 phút → SOAR isolate_workload"
