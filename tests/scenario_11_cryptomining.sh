#!/bin/bash
# Scenario 11 — Cryptomining / Resource Abuse (T1496)
# Injects cryptomining-pattern logs to AI Analyzer and verifies detection.
# Optionally deploys a CPU-burner pod (requires ENABLE_DESTRUCTIVE=1).
set -euo pipefail

AI_URL="${AI_URL:-http://localhost:18082}"
AWS_CTX="${AWS_CTX:-ctx-aws}"
ENABLE_DESTRUCTIVE="${ENABLE_DESTRUCTIVE:-0}"
SCENARIO="scenario_11_cryptomining"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
skip() { printf "[%s] SKIP: %s\n" "$SCENARIO" "$*"; exit 0; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

log "checking AI Analyzer health..."
curl -fsS "$AI_URL/health" >/dev/null || fail "AI Analyzer unreachable"

log "injecting cryptomining signature logs..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_11_cryptomining",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "cpu_usage_spike pod=payment-service cpu_percent=940 threshold=200 sustained=120s xmrig stratum+tcp pool.minexmr.com:443",
       "labels": {"namespace":"financial","app":"payment-service","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "outbound_connection_blocked dst=pool.minexmr.com:443 protocol=tcp reason=networkpolicy service=payment-service",
       "labels": {"namespace":"financial","app":"payment-service","job":"envoy-access"}},
      {"timestamp": "'"$ts"'",
       "message": "cryptomin process detected xmrig --url pool.minexmr.com:443 --user wallet pid=1337 cpu=940%",
       "labels": {"namespace":"financial","app":"payment-service","job":"kubernetes-pods"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
playbook=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('recommended_playbook','?'))")
log "AI verdict=$verdict playbook=$playbook"
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious from AI, got $verdict"

if [[ "$ENABLE_DESTRUCTIVE" == "1" ]]; then
  log "DESTRUCTIVE: deploying CPU-burner pod to simulate cryptomining..."
  kubectl --context "$AWS_CTX" run crypto-burner -n financial \
    --image=ztlab/api-gateway:1.1.0 --restart=Never \
    --overrides='{"spec":{"containers":[{"name":"crypto-burner","image":"ztlab/api-gateway:1.1.0","command":["sh","-c","while true; do :; done"],"resources":{"limits":{"cpu":"1000m"}}}]}}' \
    2>/dev/null || true
  sleep 8
  kubectl --context "$AWS_CTX" top pod crypto-burner -n financial 2>/dev/null || true
  kubectl --context "$AWS_CTX" delete pod crypto-burner -n financial --grace-period=0 2>/dev/null || true
  log "CPU-burner deployed, observed, and cleaned up"
fi

pass "AI detected cryptomining verdict=$verdict playbook=$playbook (T1496)"
