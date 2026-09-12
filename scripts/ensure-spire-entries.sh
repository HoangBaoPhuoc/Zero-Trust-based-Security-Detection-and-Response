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

# crAPI target app (ns crapi) — KE-HOACH-CRAPI.md §2. SA-based selector.
log_info "Registering crAPI workload SVID entries..."
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/waf" "$AWS_PARENT" crapi waf
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/bff" "$AWS_PARENT" crapi bff
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/crapi-web" "$AWS_PARENT" crapi crapi-web
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/crapi-community" "$AWS_PARENT" crapi crapi-community
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/crapi-workshop" "$AWS_PARENT" crapi crapi-workshop
# A2: bff PeerAuthentication STRICT — Prometheus scrapes bff:8080/metrics directly,
# needs its own SVID or that scrape target goes down (k8s/monitoring/prometheus.yaml).
register_spire_entry "$AWS_CONTEXT" "spiffe://ztlab.local/aws/prometheus" "$AWS_PARENT" monitoring prometheus
register_spire_entry "$OS_CONTEXT" "spiffe://ztlab.local/openstack/crapi-identity" "$OS_PARENT" crapi crapi-identity
register_spire_entry "$OS_CONTEXT" "spiffe://ztlab.local/openstack/crapi-seed" "$OS_PARENT" crapi crapi-seed

# Deploy-time gate. crAPI: AWS 5 (waf+bff+web+community+workshop) + OS 2
# (identity+seed). Entry idempotent — an toàn khi pod chưa có.
aws_count=$(count_entries_matching "$AWS_CONTEXT" "spiffe://ztlab.local/aws/")
os_count=$(count_entries_matching "$OS_CONTEXT" "spiffe://ztlab.local/openstack/")
log_info "Verified entries present: AWS=$aws_count (expect 6), OpenStack=$os_count (expect 2)"
if [ "$aws_count" -lt 5 ] || [ "$os_count" -lt 2 ]; then
  log_error "SPIRE registration entries missing after registration attempt — spire-server datastore may be empty/corrupted. Check 'kubectl -n spire exec deploy/spire-server -- /opt/spire/bin/spire-server entry show -socketPath /tmp/spire-server/private/api.sock' on both clusters."
  exit 1
fi

log_info "SPIRE workload registration verified OK"
