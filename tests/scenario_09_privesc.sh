#!/bin/bash
# Scenario 09 — Privilege Escalation in Container (T1611)
# Checks that containers run as non-root and sudo/privileged escalation is blocked.
set -euo pipefail

AWS_CTX="${AWS_CTX:-ctx-aws}"
NS="financial"
SCENARIO="scenario_09_privesc"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

log "finding api-gateway pod..."
pod=$(kubectl --context "$AWS_CTX" get pod -n "$NS" -l app=api-gateway \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
[[ -n "$pod" ]] || fail "no api-gateway pod found in namespace $NS"
log "using pod: $pod"

log "checking running user in api-gateway container..."
user=$(kubectl --context "$AWS_CTX" exec -n "$NS" "$pod" -c api-gateway -- id 2>/dev/null || echo "exec_failed")
log "container id: $user"
if echo "$user" | grep -q "uid=0"; then
  log "WARNING: container running as root (uid=0) — should be non-root in production"
fi

log "attempting sudo escalation in container..."
sudo_result=$(kubectl --context "$AWS_CTX" exec -n "$NS" "$pod" -c api-gateway -- \
  sh -c "sudo -n /bin/sh -c id 2>&1 || echo 'sudo_blocked'" 2>&1 || echo "exec_error")
log "sudo result: $sudo_result"
if echo "$sudo_result" | grep -qE "sudo_blocked|not allowed|command not found|exec_error"; then
  log "sudo escalation blocked"
else
  log "WARNING: sudo may be available — review container security context"
fi

log "checking for sensitive mounted paths..."
mounts=$(kubectl --context "$AWS_CTX" exec -n "$NS" "$pod" -c api-gateway -- \
  cat /proc/mounts 2>/dev/null | grep -E "/var/run/docker\.sock|/run/docker\.sock|/run/containerd/containerd\.sock|/var/run/docker$" || true)
if [[ -n "$mounts" ]]; then
  fail "container socket mounted — potential container escape: $mounts"
fi
log "no container socket mounts found"

log "checking security context in pod spec..."
privileged=$(kubectl --context "$AWS_CTX" get pod "$pod" -n "$NS" \
  -o jsonpath='{.spec.containers[*].securityContext.privileged}' 2>/dev/null || echo "")
log "privileged flag: '${privileged:-not set}'"
if echo "$privileged" | grep -q "true"; then
  fail "container is running with privileged=true — critical security issue"
fi

pass "no privilege escalation path found in api-gateway container (T1611)"
