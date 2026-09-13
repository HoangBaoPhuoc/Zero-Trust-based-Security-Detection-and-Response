#!/bin/bash
# Idempotently ensure all SPIRE registration entries this app needs exist.
#
# Why this is a separate, standalone script (not just a function inside
# deploy-security-stack.sh): SPIRE's datastore (sqlite3 on a node-pinned
# hostPath — see k8s/spire/*.yaml) has no automatic backup. If the
# spire-server pod is ever recreated in a way that loses that hostPath
# content, every workload registration entry vanishes silently and stays
# gone until someone re-registers them — meanwhile istio-proxy's
# SPIRE-backed SDS keeps failing ("workload is not authorized for the
# requested identities [\"default\"]") for any pod created after the wipe,
# while pods created before it keep working off their already-cached SVID.
# This makes the failure look like an unrelated, delayed Istio/mTLS bug
# (observed once in practice: took over an hour to trace back to 0
# registration entries on spire-server).
#
# deploy-security-stack.sh calls this once as part of the full security
# stack pass, but deploy-app.sh's deploy_financial_services() ALSO calls it
# on every run, unconditionally (not gated behind --skip-security-stack) —
# so a wiped datastore self-heals on the very next `deploy-app.sh` run
# instead of silently breaking whatever pod happens to restart next.
#
# Usage: AWS_CONTEXT=ctx-aws OS_CONTEXT=ctx-openstack ./ensure-spire-entries.sh

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"
TIMEOUT_WAIT="${TIMEOUT_WAIT:-180}"

# Danh sách workload + số lượng kỳ vọng — sinh từ policy/service-graph-crapi.yaml
# (scripts/gen-spire-entries.py, Phần 2 remediation 2026-09). KHÔNG hardcode ở
# đây nữa — sửa graph rồi chạy lại generator, đừng sửa file .generated.sh.
# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/spire-entries.generated.sh"

log_info()  { echo "[SPIRE-ENTRIES] $*"; }
log_error() { echo "[SPIRE-ENTRIES][ERROR] $*" >&2; }

# Real failures must surface immediately (exit non-zero) — only "this exact
# entry already exists" is safe to treat as success on a re-run.
_spire_entry_create() {
  local ctx="$1"; shift
  local out
  if out=$(kubectl --context "$ctx" -n spire exec deploy/spire-server -- /opt/spire/bin/spire-server entry create \
    -socketPath /tmp/spire-server/private/api.sock "$@" 2>&1); then
    return 0
  fi
  if echo "$out" | grep -q "AlreadyExists\|similar entry already exists"; then
    return 0
  fi
  log_error "spire-server entry create failed (ctx=$ctx): $out"
  return 1
}

register_spire_entry() {
  local ctx="$1" spiffe_id="$2" parent_id="$3" ns="$4" sa="$5"
  _spire_entry_create "$ctx" \
    -spiffeID "$spiffe_id" -parentID "$parent_id" \
    -selector "k8s:ns:${ns}" -selector "k8s:sa:${sa}" -ttl 3600
}

# Đăng ký toàn bộ workload của một cluster từ mảng "<spiffe_id>:<ns>:<sa>" sinh
# bởi gen-spire-entries.py (xem spire-entries.generated.sh).
register_spire_entries_from_generated() {
  local ctx="$1" parent="$2"; shift 2
  local entry spiffe_id ns sa
  for entry in "$@"; do
    IFS='|' read -r spiffe_id ns sa <<<"$entry"
    register_spire_entry "$ctx" "$spiffe_id" "$parent" "$ns" "$sa"
  done
}

register_node_alias() {
  local ctx="$1" spiffe_id="$2" cluster="$3"
  # Parented to the SPIRE server itself (-node), matched via the
  # k8s_psat:cluster:<name> selector every agent in this cluster gets
  # regardless of its own per-node UUID — so workload entries (parented to
  # this alias) survive node/agent replacement without being redone.
  _spire_entry_create "$ctx" \
    -node -spiffeID "$spiffe_id" -selector "k8s_psat:cluster:${cluster}"
}

# Count entries whose SPIFFE ID contains the given substring — used both to
# confirm each register_spire_entry above actually landed, and as a final
# sanity gate so an empty/wiped datastore is caught at deploy time instead
# of surfacing later as an unrelated-looking pod readiness failure.
count_entries_matching() {
  local ctx="$1" pattern="$2"
  kubectl --context "$ctx" -n spire exec deploy/spire-server -- /opt/spire/bin/spire-server entry show \
    -socketPath /tmp/spire-server/private/api.sock 2>/dev/null | grep -c "$pattern" || true
}

# A single slow-to-attest spire-agent pod (lab nodes are resource-constrained
# and the OpenStack cluster's uplink is a phone hotspot — see docs on uplink
# fragility) can occasionally take longer than one TIMEOUT_WAIT window to go
# Ready even though the rollout is progressing normally, not stuck. Retrying
# the same wait once before failing absorbs that without masking a real hang
# (a truly stuck rollout still fails after both attempts).
wait_rollout() {
  local ctx="$1" kind="$2" name="$3" attempt
  for attempt in 1 2; do
    if kubectl --context "$ctx" -n spire rollout status "$kind/$name" --timeout="${TIMEOUT_WAIT}s"; then
      return 0
    fi
    log_error "rollout status $kind/$name timed out on $ctx (attempt $attempt/2)"
  done
  return 1
}

log_info "Waiting for spire-server/spire-agent on both clusters..."
wait_rollout "$AWS_CONTEXT" deployment spire-server
wait_rollout "$AWS_CONTEXT" daemonset spire-agent
wait_rollout "$OS_CONTEXT" deployment spire-server
wait_rollout "$OS_CONTEXT" daemonset spire-agent

AWS_PARENT="spiffe://ztlab.local/nodes/aws-k3s"
OS_PARENT="spiffe://ztlab.local/nodes/os-k3s"

log_info "Registering node aliases..."
register_node_alias "$AWS_CONTEXT" "$AWS_PARENT" "aws-k3s"
register_node_alias "$OS_CONTEXT" "$OS_PARENT" "os-k3s"

# crAPI target app — danh sách + số lượng kỳ vọng đều sinh từ
# policy/service-graph-crapi.yaml (scripts/gen-spire-entries.py). SA-based selector.
log_info "Registering crAPI workload SVID entries..."
register_spire_entries_from_generated "$AWS_CONTEXT" "$AWS_PARENT" "${AWS_SPIRE_WORKLOADS[@]}"
register_spire_entries_from_generated "$OS_CONTEXT" "$OS_PARENT" "${OPENSTACK_SPIRE_WORKLOADS[@]}"

# Deploy-time gate. Entry idempotent — an toàn khi pod chưa có. Số lượng kỳ
# vọng đến từ CÙNG file generated ở trên nên không thể lệch với danh sách vừa
# đăng ký (trước bản sửa Phần 2: comment/log/check gate là 3 con số hardcode
# khác nhau, từng lệch nhau mà không ai nhận ra vì gate vẫn pass tình cờ).
aws_count=$(count_entries_matching "$AWS_CONTEXT" "spiffe://ztlab.local/aws/")
os_count=$(count_entries_matching "$OS_CONTEXT" "spiffe://ztlab.local/openstack/")
log_info "Verified entries present: AWS=$aws_count (expect $AWS_EXPECTED_COUNT), OpenStack=$os_count (expect $OPENSTACK_EXPECTED_COUNT)"
if [ "$aws_count" -lt "$AWS_EXPECTED_COUNT" ] || [ "$os_count" -lt "$OPENSTACK_EXPECTED_COUNT" ]; then
  log_error "SPIRE registration entries missing after registration attempt — spire-server datastore may be empty/corrupted. Check 'kubectl -n spire exec deploy/spire-server -- /opt/spire/bin/spire-server entry show -socketPath /tmp/spire-server/private/api.sock' on both clusters."
  exit 1
fi

log_info "SPIRE workload registration verified OK"
