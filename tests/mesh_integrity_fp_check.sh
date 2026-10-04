#!/usr/bin/env bash
# Mục 4 vòng 2026-09-29 — nghiệm thu rule Grafana "Mesh Integrity" (H2).
#
#  Pha 0: chờ rule về Normal (inactive).
#  Pha 1: NORMAL_MIN phút traffic người dùng bình thường qua Gateway (login +
#         GET dashboard/products/vehicles), lấy mẫu trạng thái rule mỗi 20 s.
#         Kỳ vọng: 0 mẫu firing/pending.
#  Pha 2: MỘT kết nối plaintext thật vào cổng STRICT (curl từ container
#         istio-proxy của bff, uid 1337 → iptables RETURN → không qua Envoy →
#         plaintext tới crapi-workshop:8000). Kỳ vọng: rule firing trong ≤ 4 phút.
#
# Cần: scripts/open-admin-uis.sh (Grafana :3000, Gateway :18444).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/crapi_common.sh"
NORMAL_MIN="${NORMAL_MIN:-10}"
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-closeout}/mesh-integrity"; mkdir -p "$OUT"
TAG="run$(date +%Y%m%d%H%M%S)"; LOG="$OUT/$TAG.log"
exec > >(tee "$LOG") 2>&1
GP="$(kubectl --context "$KUBE_AWS" -n plg-stack get secret grafana-admin-secret -o jsonpath='{.data.admin-password}' | base64 -d)"

rule_state() {
  curl -s -u "admin:$GP" http://localhost:3000/api/prometheus/grafana/api/v1/rules | python3 -c '
import json,sys
for g in json.load(sys.stdin)["data"]["groups"]:
  for r in g["rules"]:
    if r["name"].startswith("Mesh Integrity"): print(r["state"]); sys.exit()
print("missing")'
}

crapi_preflight
echo "[$(date -Is)] Pha 0: chờ rule về inactive"
for _ in $(seq 1 40); do [[ "$(rule_state)" == inactive ]] && break; sleep 15; done
s="$(rule_state)"; echo "  state=$s"; [[ "$s" == inactive ]] || fail "rule không về inactive trước khi bắt đầu"

echo "[$(date -Is)] Pha 1: ${NORMAL_MIN} phút traffic bình thường"
end=$(( $(date +%s) + NORMAL_MIN * 60 )); samples=0; bad=0; reqs=0; codes=""
J="$(crapi_login testuser01 'Test1234!')"
next_sample=0
while [[ $(date +%s) -lt $end ]]; do
  for p in /identity/api/v2/user/dashboard /workshop/api/shop/products /identity/api/v2/vehicle/vehicles; do
    c="$(crapi_call "$J" GET "$p")"; reqs=$((reqs+1)); codes+="$c "
  done
  if [[ $(date +%s) -ge $next_sample ]]; then
    st="$(rule_state)"; samples=$((samples+1))
    [[ "$st" != inactive ]] && bad=$((bad+1))
    echo "  [$(date +%T)] mesh-integrity=$st reqs=$reqs"
    next_sample=$(( $(date +%s) + 20 ))
  fi
  sleep 2
done
rm -f "$J"
echo "  mã HTTP: $(tr ' ' '\n' <<<"$codes" | sort | uniq -c | tr '\n' ' ')"
echo "PHA1: requests=$reqs samples=$samples non_inactive=$bad"

echo "[$(date -Is)] Pha 2: 1 kết nối plaintext vào crapi-workshop:8000 (STRICT)"
T2=$(date +%s)
kubectl --context "$KUBE_AWS" -n crapi exec deploy/bff -c istio-proxy -- \
  curl -s -m 5 -o /dev/null -w "  curl: %{http_code} %{errormsg}\n" http://crapi-workshop.crapi.svc.cluster.local:8000/workshop/api/shop/products || true
fired=""
for _ in $(seq 1 24); do
  st="$(rule_state)"
  if [[ "$st" == firing ]]; then fired=$(( $(date +%s) - T2 )); break; fi
  sleep 10
done
echo "PHA2: firing_after_s=${fired:-NONE}"
if [[ "$bad" -eq 0 && -n "$fired" ]]; then echo "PASS"; else echo "FAIL"; exit 1; fi
