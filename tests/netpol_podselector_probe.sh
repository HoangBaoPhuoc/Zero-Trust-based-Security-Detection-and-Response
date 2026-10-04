#!/usr/bin/env bash
# Thí nghiệm cô lập cho mục 2.1 (vòng cuối 2026-09-26): NetworkPolicy dạng
# podSelector (loại mà vòng 2 cho là "0% hiệu lực vì node không có ipset") CÓ
# thực thi được trên cụm này hay không — đo trong một namespace TẠM, không đụng
# tới bất kỳ policy/workload nào của hệ thống.
#
# Bố cục (ns `netpol-probe`, KHÔNG bật istio-injection, không sidecar):
#   srv  : nginx, label role=server        (đích)
#   a    : curl, label role=allowed        (nguồn ĐƯỢC PHÉP theo policy)
#   c    : curl, label role=denied         (nguồn KHÔNG được phép)
# Một policy duy nhất: ingress vào role=server chỉ từ podSelector role=allowed.
# Chạy 2 biến thể vị trí: (same) a,c cùng node với srv; (cross) a,c khác node.
#
# Kỳ vọng nếu podSelector/ipset hoạt động: a->srv REACHED, c->srv BLOCKED (curl
# exit 7 = reject, 28 = drop). Nếu "rule chết" như giả thuyết vòng 2 thì c->srv
# REACHED (không chặn) hoặc a->srv BLOCKED (chặn nhầm). Không suy đoán: in kết quả
# thô + verdict; kèm trạng thái `ipset` trên node (chỉ đọc qua SSH nếu truyền
# --ssh-nodes, mặc định bỏ qua).
#
# Dùng: bash tests/netpol_podselector_probe.sh <ctx> [--out file]
#   vd: bash tests/netpol_podselector_probe.sh ctx-aws
set -uo pipefail
CTX="${1:?Dùng: $0 <kube-context> [--out file]}"
OUT=""
[[ "${2:-}" == "--out" ]] && OUT="$3"
NS=netpol-probe
K() { kubectl --context "$CTX" "$@"; }
log() { echo "[podselector-probe:$CTX] $*"; }
ROWS=()

cleanup() { K delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1; }
trap cleanup EXIT

nodes=($(K get nodes -o jsonpath='{.items[*].metadata.name}'))
[[ ${#nodes[@]} -ge 2 ]] || { log "cần >=2 node để đo khác-node"; exit 2; }
N1="${nodes[0]}"; N2="${nodes[1]}"

K delete ns "$NS" --ignore-not-found --wait=true >/dev/null 2>&1
K create ns "$NS" >/dev/null

mkpod() { # name role image node cmd...
  local name="$1" role="$2" image="$3" node="$4"; shift 4
  K -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: { name: $name, labels: { role: $role } }
spec:
  nodeName: $node
  restartPolicy: Never
  containers:
    - name: c
      image: $image
      imagePullPolicy: IfNotPresent
      $( [[ $# -gt 0 ]] && printf 'command: [%s]' "$(printf '"%s",' "$@" | sed 's/,$//')" )
EOF
}

run_variant() { # <label> <client node>
  local label="$1" cnode="$2"
  K -n "$NS" delete pod srv a c netpol --ignore-not-found --wait=true >/dev/null 2>&1
  K -n "$NS" delete networkpolicy --all >/dev/null 2>&1
  mkpod srv server nginx:alpine "$N1"
  mkpod a allowed curlimages/curl "$cnode" sleep 600
  mkpod c denied curlimages/curl "$cnode" sleep 600
  K -n "$NS" wait --for=condition=Ready pod/srv pod/a pod/c --timeout=120s >/dev/null 2>&1 \
    || { log "[$label] pod chưa Ready — bỏ qua biến thể"; return; }
  local sip; sip="$(K -n "$NS" get pod srv -o jsonpath='{.status.podIP}')"

  probe() { # <tag> <pod> <expect reach|block>
    local ec; K -n "$NS" exec "$2" -- curl -s -o /dev/null -m 5 "http://$sip/" >/dev/null 2>&1; ec=$?
    local obs="REACHED"; [[ $ec -eq 7 || $ec -eq 28 ]] && obs="BLOCKED"
    local v="MISMATCH"; [[ ( "$3" == reach && "$obs" == REACHED ) || ( "$3" == block && "$obs" == BLOCKED ) ]] && v="MATCH"
    ROWS+=("$label|$1|kỳ vọng=$3|quan sát=$obs (curl exit $ec)|$v")
    log "[$label] $1: kỳ vọng $3, quan sát $obs (exit $ec) => $v"
  }

  # Đối chứng TRƯỚC policy: chưa có policy => cả a và c phải tới được (loại trừ lỗi mạng).
  probe "pre-policy a->srv" a reach
  probe "pre-policy c->srv" c reach

  K -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: allow-from-a-only }
spec:
  podSelector: { matchLabels: { role: server } }
  policyTypes: [Ingress]
  ingress:
    - from: [ { podSelector: { matchLabels: { role: allowed } } } ]
      ports: [ { port: 80, protocol: TCP } ]
EOF
  sleep 15   # kube-router sync
  probe "policy    a->srv (được phép)" a reach
  probe "policy    c->srv (không được phép)" c block
}

# Biến thể 3 (egress-shadow): mô phỏng đúng cấu trúc ns crapi — 1 policy "baseline"
# podSelector {} policyTypes [Ingress,Egress] với egress `to namespaceSelector(cùng ns) :80`
# (KHÔNG có rule ingress nào) + 1 policy per-destination cho phép ingress vào srv CHỈ
# từ role=allowed. Theo ĐẶC TẢ NetworkPolicy, egress rule KHÔNG cấp quyền ingress nên
# c->srv:80 phải BỊ CHẶN. Nếu c->srv REACHED thì rule egress của baseline đang làm
# "lủng" ingress default-deny (đã quan sát ở ns crapi: mọi nguồn cùng ns qua được đúng
# các cổng nằm trong danh sách egress).
run_shadow_variant() { # <label> <client node>
  local label="$1" cnode="$2"
  K -n "$NS" delete pod srv a c --ignore-not-found --wait=true >/dev/null 2>&1
  K -n "$NS" delete networkpolicy --all >/dev/null 2>&1
  mkpod srv server nginx:alpine "$N1"
  mkpod a allowed curlimages/curl "$cnode" sleep 600
  mkpod c denied curlimages/curl "$cnode" sleep 600
  K -n "$NS" wait --for=condition=Ready pod/srv pod/a pod/c --timeout=120s >/dev/null 2>&1 \
    || { log "[$label] pod chưa Ready — bỏ qua"; return; }
  local sip; sip="$(K -n "$NS" get pod srv -o jsonpath='{.status.podIP}')"
  K -n "$NS" apply -f - >/dev/null <<EOF2
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: baseline-like }
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  egress:
    - to: [ { namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: $NS } } } ]
      ports: [ { port: 80, protocol: TCP } ]
    - to: [ { namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } } } ]
      ports: [ { port: 53, protocol: UDP }, { port: 53, protocol: TCP } ]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: allow-from-a-only }
spec:
  podSelector: { matchLabels: { role: server } }
  policyTypes: [Ingress]
  ingress:
    - from: [ { podSelector: { matchLabels: { role: allowed } } } ]
      ports: [ { port: 80, protocol: TCP } ]
EOF2
  sleep 15
  probe2() { local ec; K -n "$NS" exec "$2" -- curl -s -o /dev/null -m 5 "http://$sip/" >/dev/null 2>&1; ec=$?
    local obs="REACHED"; [[ $ec -eq 7 || $ec -eq 28 ]] && obs="BLOCKED"
    local v="MISMATCH"; [[ ( "$3" == reach && "$obs" == REACHED ) || ( "$3" == block && "$obs" == BLOCKED ) ]] && v="MATCH"
    ROWS+=("$label|$1|kỳ vọng=$3|quan sát=$obs (curl exit $ec)|$v"); log "[$label] $1: kỳ vọng $3, quan sát $obs (exit $ec) => $v"; }
  probe2 "a->srv (được phép)" a reach
  probe2 "c->srv (KHÔNG được phép, nhưng cổng 80 nằm trong egress baseline)" c block
}

log "node1=$N1 node2=$N2"
run_variant same-node  "$N1"
run_variant cross-node "$N2"
run_shadow_variant egress-shadow-cross-node "$N2"
run_shadow_variant egress-shadow-same-node  "$N1"

M=$(printf '%s\n' "${ROWS[@]}" | grep -c '|MATCH$'); T=${#ROWS[@]}
{
  echo "# podSelector probe — ctx=$CTX — $(date -u +%FT%TZ) — $M/$T MATCH"
  echo "# biến-thể|phép-đo|kỳ-vọng|quan-sát|verdict"
  printf '%s\n' "${ROWS[@]}"
} | tee ${OUT:+"$OUT"}
[[ $M -eq $T ]]
