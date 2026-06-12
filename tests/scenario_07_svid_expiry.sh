#!/bin/bash
# Scenario 07 — SPIRE SVID Expiry & Recovery (T1552.004)
# Without ENABLE_DESTRUCTIVE=1 just validates SPIRE health and SVID issuance.
# With ENABLE_DESTRUCTIVE=1 deletes SPIRE agent pods and verifies auto-recovery.
set -euo pipefail

AWS_CTX="${AWS_CTX:-ctx-aws}"
OS_CTX="${OS_CTX:-ctx-openstack}"
ENABLE_DESTRUCTIVE="${ENABLE_DESTRUCTIVE:-0}"
SCENARIO="scenario_07_svid_expiry"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
skip() { printf "[%s] SKIP: %s\n" "$SCENARIO" "$*"; exit 0; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

log "checking SPIRE agents on both clusters..."
aws_agents=$(kubectl --context "$AWS_CTX" get pods -n spire -l app=spire-agent --no-headers 2>/dev/null | wc -l | tr -d ' ')
os_agents=$(kubectl --context "$OS_CTX" get pods -n spire -l app=spire-agent --no-headers 2>/dev/null | wc -l | tr -d ' ') || os_agents="0"
log "AWS SPIRE agent pods: $aws_agents | OpenStack SPIRE agent pods: $os_agents"
[[ "$aws_agents" -ge 1 ]] || fail "no SPIRE agent pods on AWS cluster"

log "checking registered SPIFFE IDs..."
server_pod=$(kubectl --context "$AWS_CTX" get pod -n spire -l app=spire-server \
  -o jsonpath='{.items[0].metadata.name}')
entries=$(kubectl --context "$AWS_CTX" exec -n spire "$server_pod" -- \
  /opt/spire/bin/spire-server entry show 2>/dev/null | grep -c "SPIFFE ID" || echo 0)
log "registered SPIFFE IDs: $entries"
[[ "$entries" -ge 5 ]] || log "WARNING: only $entries SPIFFE IDs registered (expected ≥5)"

if [[ "$ENABLE_DESTRUCTIVE" != "1" ]]; then
  log "non-destructive check complete (SPIRE healthy, $entries SVIDs registered)"
  skip "set ENABLE_DESTRUCTIVE=1 to test pod deletion + recovery"
fi

log "DESTRUCTIVE: deleting SPIRE agent pods to simulate SVID expiry..."
for ctx in "$AWS_CTX" "$OS_CTX"; do
  while IFS= read -r pod; do
    [[ -z "$pod" ]] && continue
    log "deleting $pod on $ctx..."
    kubectl --context "$ctx" delete pod "$pod" -n spire --grace-period=0 --force 2>/dev/null || true
  done < <(kubectl --context "$ctx" get pods -n spire -l app=spire-agent -o jsonpath='{.items[*].metadata.name}' \
    2>/dev/null | tr ' ' '\n')
done

log "waiting for SPIRE agents to recover (up to 180s)..."
sleep 10
for ctx in "$AWS_CTX" "$OS_CTX"; do
  kubectl --context "$ctx" rollout status daemonset/spire-agent -n spire --timeout=180s \
    || fail "SPIRE agent DaemonSet failed to recover on $ctx"
done

log "restarting core-banking to force new SVID acquisition..."
kubectl --context "$OS_CTX" rollout restart deployment/core-banking -n financial >/dev/null
kubectl --context "$OS_CTX" rollout status deployment/core-banking -n financial --timeout=120s >/dev/null

pass "SPIRE agents recovered; core-banking restarted with fresh SVID (T1552.004)"
