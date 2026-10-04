#!/usr/bin/env bash
# Ma trận thực nghiệm NetworkPolicy — đo THẬT xem NetworkPolicy có chặn ở tầng L4
# hay không, theo 2 chiều: dạng rule × đường đi (Phần 3.3 vòng cuối 2026-09-26;
# thay bản v1 của BAOCAO-VONG-2026-09-19.md, bản đó lỗi ô A3 và test nhầm cổng).
#
# Dạng rule NetworkPolicy áp cho đích:
#   A1 = podSelector cùng ns (aws-pod-*, ingress theo edge service-graph)
#   A2 = namespaceSelector khác ns (baseline: monitoring/istio-system/kube-system)
#   A3 = ipBlock (baseline egress cross-cloud 192.168.101.0/24)
# Đường đi:
#   B1 = cùng node   B2 = khác node   (tự suy từ nodeName của nguồn/đích)
#   B3 = đích có sidecar   B4 = đích KHÔNG sidecar (redis/mongodb)
#
# Cách đo (L4 sạch, không lẫn L7): gọi TỪ container `istio-proxy` của pod nguồn
# (uid 1337 -> bỏ qua redirect outbound của Envoy nguồn) THẲNG tới POD IP đích.
# NetworkPolicy do kube-router thực thi ở host, trước khi gói tới pod đích:
#   curl exit 7  = "connection refused"  => kube-router `reject` (BỊ CHẶN ở L4)
#   curl exit 28 = timeout               => DROP (BỊ CHẶN ở L4)
#   curl exit 0/52/56/35/... = TCP connect thành công => LỌT QUA L4 (đích có
#     sidecar STRICT mTLS sẽ reset HTTP thường — đó là L7, không phải NetworkPolicy)
# Nguồn ngoài mesh (ns monitoring/default) dùng pod probe tạm curlimages/curl.
#
# Mỗi ô có KỲ VỌNG (allow|deny) rút từ policy/service-graph-crapi.yaml; verdict
# MATCH nếu quan sát khớp kỳ vọng, MISMATCH nếu không — MISMATCH KHÔNG bị che.
#
# Dùng: bash tests/netpol_matrix.sh [--out results/netpol_matrix.txt]
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS="${AWS_CONTEXT:-ctx-aws}"
OS="${OS_CONTEXT:-ctx-openstack}"
OUT="$REPO_ROOT/results/netpol_matrix.txt"
[[ "${1:-}" == "--out" ]] && OUT="$2"
mkdir -p "$(dirname "$OUT")"

ROWS=()
MATCH=0; MISMATCH=0
log() { echo "[netpol-matrix] $*"; }

# pod_of <ctx> <ns> <app> -> "name node ip"
pod_of() {
  kubectl --context "$1" -n "$2" get pod -l "app=$3" \
    -o jsonpath='{.items[0].metadata.name} {.items[0].spec.nodeName} {.items[0].status.podIP}' 2>/dev/null
}

classify() {  # <curl exit> -> BLOCKED_REFUSED|BLOCKED_TIMEOUT|REACHED
  case "$1" in
    7)  echo BLOCKED_REFUSED ;;
    28) echo BLOCKED_TIMEOUT ;;
    *)  echo REACHED ;;
  esac
}

# cell <id> <rule_form> <expect allow|deny> <src_desc> <src_ctx> <src_ns> <src_pod> <src_container> <src_node> <dst_desc> <dst_ip:port> <dst_node> <dst_sidecar yes|no>
cell() {
  local id="$1" form="$2" expect="$3" sdesc="$4" sctx="$5" sns="$6" spod="$7" scont="$8" snode="$9"
  local ddesc="${10}" target="${11}" dnode="${12}" dsc="${13}"
  local path="B2"; [[ "$snode" == "$dnode" ]] && path="B1"
  local side="B3"; [[ "$dsc" == "no" ]] && side="B4"
  local ec
  kubectl --context "$sctx" -n "$sns" exec "$spod" -c "$scont" -- \
    curl -s -o /dev/null -m 5 "http://$target/" >/dev/null 2>&1
  ec=$?
  local obs; obs="$(classify "$ec")"
  local verdict="MISMATCH"
  if [[ "$expect" == "allow" && "$obs" == "REACHED" ]] || [[ "$expect" == "deny" && "$obs" != "REACHED" ]]; then
    verdict="MATCH"; MATCH=$((MATCH+1))
  else
    MISMATCH=$((MISMATCH+1))
  fi
  ROWS+=("$id|$form|$path,$side|$sdesc -> $ddesc ($target)|$expect|curl_exit=$ec $obs|$verdict")
  log "$id [$form $path,$side] $sdesc -> $ddesc: kỳ vọng=$expect quan sát=$obs (exit $ec) => $verdict"
}

PROBE_NS=(monitoring default)
cleanup() {
  for n in "${PROBE_NS[@]}"; do
    kubectl --context "$AWS" -n "$n" delete pod netpol-probe --ignore-not-found --wait=false >/dev/null 2>&1
  done
}
trap cleanup EXIT

start_probes() {
  for n in "${PROBE_NS[@]}"; do
    kubectl --context "$AWS" -n "$n" delete pod netpol-probe --ignore-not-found --wait=true >/dev/null 2>&1
    kubectl --context "$AWS" -n "$n" run netpol-probe --image=curlimages/curl --restart=Never \
      --command -- sleep 600 >/dev/null 2>&1
  done
  for n in "${PROBE_NS[@]}"; do
    kubectl --context "$AWS" -n "$n" wait --for=condition=Ready pod/netpol-probe --timeout=90s >/dev/null 2>&1 \
      || log "CẢNH BÁO: probe pod ns $n chưa Ready — các ô dùng nó sẽ MISMATCH/ERROR"
  done
}

main() {
  local w b web com wk rd mg opa
  read -r WP WN WI <<<"$(pod_of "$AWS" crapi waf)"
  read -r BP BN BI <<<"$(pod_of "$AWS" crapi bff)"
  read -r XP XN XI <<<"$(pod_of "$AWS" crapi crapi-web)"
  read -r CP CN CI <<<"$(pod_of "$AWS" crapi crapi-community)"
  read -r KP KN KI <<<"$(pod_of "$AWS" crapi crapi-workshop)"
  read -r RP RN RI <<<"$(pod_of "$AWS" crapi redis)"
  read -r MP MN MI <<<"$(pod_of "$AWS" crapi mongodb)"
  read -r OP ON OI <<<"$(pod_of "$AWS" crapi opa)"
  [[ -z "$OP" ]] && read -r OP ON OI <<<"$(kubectl --context "$AWS" -n crapi get pod -l app=opa -o jsonpath='{.items[0].metadata.name} {.items[0].spec.nodeName} {.items[0].status.podIP}')"
  log "pods: waf=$WP($WN) bff=$BP($BN) web=$XP($XN) community=$CP($CN) workshop=$KP($KN) redis=$RP($RN) mongodb=$MP($MN) opa=$OP($ON)"

  start_probes
  local PMN PDN
  PMN="$(kubectl --context "$AWS" -n monitoring get pod netpol-probe -o jsonpath='{.spec.nodeName}' 2>/dev/null)"
  PDN="$(kubectl --context "$AWS" -n default get pod netpol-probe -o jsonpath='{.spec.nodeName}' 2>/dev/null)"

  # --- A1: podSelector cùng ns, đích có sidecar (bff: chỉ waf được phép, port 8080) ---
  cell A1-01 A1 allow "waf" "$AWS" crapi "$WP" istio-proxy "$WN" "bff" "$BI:8080" "$BN" yes
  cell A1-02 A1 deny  "crapi-web" "$AWS" crapi "$XP" istio-proxy "$XN" "bff" "$BI:8080" "$BN" yes
  cell A1-03 A1 deny  "crapi-community" "$AWS" crapi "$CP" istio-proxy "$CN" "bff" "$BI:8080" "$BN" yes
  # workshop (8000): chỉ bff được phép theo edge
  cell A1-04 A1 allow "bff" "$AWS" crapi "$BP" istio-proxy "$BN" "crapi-workshop" "$KI:8000" "$KN" yes
  cell A1-05 A1 deny  "crapi-web" "$AWS" crapi "$XP" istio-proxy "$XN" "crapi-workshop" "$KI:8000" "$KN" yes
  # opa 9191: mọi workload nghiệp vụ được phép (ext_authz)
  cell A1-06 A1 allow "crapi-web" "$AWS" crapi "$XP" istio-proxy "$XN" "opa" "$OI:9191" "$ON" yes

  # --- A1×B4: đích KHÔNG sidecar ---
  cell A1-07 A1 allow "bff" "$AWS" crapi "$BP" istio-proxy "$BN" "redis" "$RI:6379" "$RN" no
  cell A1-08 A1 deny  "crapi-web" "$AWS" crapi "$XP" istio-proxy "$XN" "redis" "$RI:6379" "$RN" no
  cell A1-09 A1 deny  "crapi-community" "$AWS" crapi "$CP" istio-proxy "$CN" "redis" "$RI:6379" "$RN" no
  cell A1-10 A1 allow "crapi-community" "$AWS" crapi "$CP" istio-proxy "$CN" "mongodb" "$MI:27017" "$MN" no
  cell A1-11 A1 deny  "crapi-web" "$AWS" crapi "$XP" istio-proxy "$XN" "mongodb" "$MI:27017" "$MN" no
  cell A1-12 A1 deny  "bff" "$AWS" crapi "$BP" istio-proxy "$BN" "mongodb" "$MI:27017" "$MN" no

  # --- A2: namespaceSelector khác ns (baseline: monitoring được vào 8080/15006/8181; default thì không) ---
  if [[ -n "$PMN" ]]; then
    cell A2-01 A2 allow "monitoring/probe" "$AWS" monitoring netpol-probe netpol-probe "$PMN" "bff" "$BI:8080" "$BN" yes
    cell A2-02 A2 allow "monitoring/probe" "$AWS" monitoring netpol-probe netpol-probe "$PMN" "opa" "$OI:8181" "$ON" yes
    cell A2-03 A2 deny  "monitoring/probe" "$AWS" monitoring netpol-probe netpol-probe "$PMN" "redis" "$RI:6379" "$RN" no
  fi
  if [[ -n "$PDN" ]]; then
    cell A2-04 A2 deny "default/probe" "$AWS" default netpol-probe netpol-probe "$PDN" "bff" "$BI:8080" "$BN" yes
    cell A2-05 A2 deny "default/probe" "$AWS" default netpol-probe netpol-probe "$PDN" "opa" "$OI:8181" "$ON" yes
  fi

  # --- A3: ipBlock (baseline egress cross-cloud 192.168.101.0/24: chỉ 30090/30091/30432) ---
  local OSN
  OSN="$(kubectl --context "$OS" get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null)"
  if [[ -n "$OSN" ]]; then
    cell A3-01 A3 allow "crapi-community" "$AWS" crapi "$CP" istio-proxy "$CN" "openstack-node:NodePort identity" "$OSN:30090" "openstack" yes
    cell A3-02 A3 deny  "crapi-community" "$AWS" crapi "$CP" istio-proxy "$CN" "openstack-node:k3s-API" "$OSN:6443" "openstack" no
    cell A3-03 A3 deny  "crapi-community" "$AWS" crapi "$CP" istio-proxy "$CN" "openstack-node:ssh" "$OSN:22" "openstack" no
    # Đối chứng: cùng đích từ pod ngoài phạm vi policy (ns default không có NetworkPolicy).
    # Nếu đối chứng KHÔNG tới được thì ô deny ở trên không chứng minh được gì (cổng đóng thật).
    if [[ -n "$PDN" ]]; then
      cell A3-c1 A3-ctl allow "default/probe(đối chứng)" "$AWS" default netpol-probe netpol-probe "$PDN" "openstack-node:ssh" "$OSN:22" "openstack" no
      cell A3-c2 A3-ctl allow "default/probe(đối chứng)" "$AWS" default netpol-probe netpol-probe "$PDN" "openstack-node:NodePort identity" "$OSN:30090" "openstack" no
    fi
  fi

  local total=$((MATCH+MISMATCH))
  {
    echo "# Ma trận NetworkPolicy — $(date -u +%FT%TZ) — $MATCH/$total MATCH, $MISMATCH MISMATCH"
    echo "# id|dạng-rule|đường-đi|nguồn -> đích|kỳ-vọng|quan-sát|verdict"
    printf '%s\n' "${ROWS[@]}"
  } | tee "$OUT"
  log "kết quả thô lưu ở $OUT"
  [[ $MISMATCH -eq 0 ]]
}

main "$@"
