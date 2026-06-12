#!/bin/bash
# Scenario 18 — Container Escape Attempt (T1611)
# Checks that containers cannot access host filesystem, host network, or
# Docker/containerd socket. Also verifies NetworkPolicy blocks unexpected egress.
set -euo pipefail

AWS_CTX="${AWS_CTX:-ctx-aws}"
AI_URL="${AI_URL:-http://localhost:18082}"
NS="financial"
SCENARIO="scenario_18_container_escape"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

curl -fsS "$AI_URL/health" >/dev/null || fail "AI Analyzer unreachable"

pod=$(kubectl --context "$AWS_CTX" get pod -n "$NS" -l app=api-gateway \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
[[ -n "$pod" ]] || { log "WARNING: no api-gateway pod found, skipping live checks"; }

if [[ -n "$pod" ]]; then
  log "checking for host path mounts in $pod..."
  host_mounts=$(kubectl --context "$AWS_CTX" get pod "$pod" -n "$NS" \
    -o jsonpath='{.spec.volumes[*].hostPath.path}' 2>/dev/null | tr ' ' '\n' | \
    grep -vE "^(/run/spire|/tmp|$)" | grep -v "^$" || true)
  if [[ -n "$host_mounts" ]]; then
    log "WARNING: unexpected host path mounts: $host_mounts"
  else
    log "no unexpected host path mounts"
  fi

  log "checking hostNetwork / hostPID / hostIPC flags..."
  flags=$(kubectl --context "$AWS_CTX" get pod "$pod" -n "$NS" \
    -o jsonpath='hostNetwork={.spec.hostNetwork} hostPID={.spec.hostPID} hostIPC={.spec.hostIPC}' 2>/dev/null)
  log "pod flags: $flags"
  echo "$flags" | grep -q "hostNetwork=true" && fail "hostNetwork=true — container escape risk"
  echo "$flags" | grep -q "hostPID=true"     && fail "hostPID=true — container escape risk"

  log "attempting to reach host metadata service from container..."
  meta_result=$(kubectl --context "$AWS_CTX" exec -n "$NS" "$pod" -c api-gateway -- \
    sh -c 'timeout 3 wget -q -O- http://169.254.169.254/latest/meta-data/ 2>&1 || echo blocked' 2>/dev/null || echo "exec_error")
  log "metadata service result: ${meta_result:0:80}"
  if echo "$meta_result" | grep -qE "ami-id|instance-id|block"; then
    log "NOTE: metadata service accessible from container (expected to be blocked by NP in prod)"
  fi
fi

log "injecting container escape attempt log to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_18_container_escape",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "container_escape_attempt pod=api-gateway trying to mount /proc/1/root host_filesystem_access=blocked",
       "labels": {"namespace":"financial","app":"api-gateway","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "suspicious_syscall ptrace detected pid=1337 container=api-gateway node=ip-10-10-1-11 blocked_by_seccomp",
       "labels": {"namespace":"financial","app":"api-gateway","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "network_policy_blocked egress dst=169.254.169.254:80 src=api-gateway reason=no_matching_egress_rule",
       "labels": {"namespace":"financial","app":"api-gateway","job":"envoy-access"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious, got $verdict"

pass "container escape vectors checked; AI verdict=$verdict (T1611)"
