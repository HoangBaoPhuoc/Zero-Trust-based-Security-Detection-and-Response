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

AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"
TIMEOUT_WAIT="${TIMEOUT_WAIT:-180}"

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

log_info "Waiting for spire-server/spire-agent on both clusters..."
kubectl --context "$AWS_CONTEXT" -n spire rollout status deployment/spire-server --timeout="${TIMEOUT_WAIT}s"
kubectl --context "$AWS_CONTEXT" -n spire rollout status daemonset/spire-agent --timeout="${TIMEOUT_WAIT}s"
kubectl --context "$OS_CONTEXT" -n spire rollout status deployment/spire-server --timeout="${TIMEOUT_WAIT}s"
kubectl --context "$OS_CONTEXT" -n spire rollout status daemonset/spire-agent --timeout="${TIMEOUT_WAIT}s"

AWS_PARENT="spiffe://ztlab.local/nodes/aws-k3s"
OS_PARENT="spiffe://ztlab.local/nodes/os-k3s"

log_info "Registering node aliases..."
register_node_alias "$AWS_CONTEXT" "$AWS_PARENT" "aws-k3s"
register_node_alias "$OS_CONTEXT" "$OS_PARENT" "os-k3s"

log_info "Registering AWS workload SVID entries..."
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/api-gateway" "$AWS_PARENT" financial api-gateway
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/payment-service" "$AWS_PARENT" financial payment-service
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/fraud-detection" "$AWS_PARENT" financial fraud-detection
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/notification-service" "$AWS_PARENT" financial notification-service
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/web-portal" "$AWS_PARENT" financial web-portal

log_info "Registering OpenStack workload SVID entries..."
register_spire_entry "$OS_CONTEXT" "spiffe://ztlab.local/openstack/core-banking" "$OS_PARENT" financial core-banking
register_spire_entry "$OS_CONTEXT" "spiffe://ztlab.local/openstack/account-service" "$OS_PARENT" financial account-service
register_spire_entry "$OS_CONTEXT" "spiffe://ztlab.local/openstack/transaction-service" "$OS_PARENT" financial transaction-service

# Deploy-time gate: 5 AWS workload entries + 3 OpenStack workload entries
# expected. If this ever comes back low, spire-server's datastore is empty
# or partially wiped — fail now instead of leaving it for the next pod
# restart to discover.
aws_count=$(count_entries_matching "$AWS_CONTEXT" "spiffe://ztlab.local/aws/")
os_count=$(count_entries_matching "$OS_CONTEXT" "spiffe://ztlab.local/openstack/")
log_info "Verified entries present: AWS=$aws_count (expect 5), OpenStack=$os_count (expect 3)"
if [ "$aws_count" -lt 5 ] || [ "$os_count" -lt 3 ]; then
  log_error "SPIRE registration entries missing after registration attempt — spire-server datastore may be empty/corrupted. Check 'kubectl -n spire exec deploy/spire-server -- /opt/spire/bin/spire-server entry show -socketPath /tmp/spire-server/private/api.sock' on both clusters."
  exit 1
fi

log_info "SPIRE workload registration verified OK"
