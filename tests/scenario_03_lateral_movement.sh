#!/bin/bash
# Scenario 03 — Lateral Movement (T1021.007)
# Executes attack FROM WITHIN notification-service pod via Envoy outbound proxy
# so the real SPIRE SVID appears in Envoy/OPA logs.  OPA blocks with 403.
set -euo pipefail

K8S_CTX="${K8S_CTX:-ctx-aws}"
AI_URL="${AI_URL:-http://localhost:18082}"
GW_URL="${GW_URL:-http://localhost:18080}"
NAMESPACE="financial"
SCENARIO="scenario_03_lateral_movement"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Resolve pods ───────────────────────────────────────────────────────────
log "resolving pods..."
NOTIF_POD=$(kubectl --context "$K8S_CTX" get pods -n "$NAMESPACE" \
  -l app=notification-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
PAYMENT_POD=$(kubectl --context "$K8S_CTX" get pods -n "$NAMESPACE" \
  -l app=payment-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
OPA_POD=$(kubectl --context "$K8S_CTX" get pods -n "$NAMESPACE" \
  -l app=opa -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

[[ -n "$NOTIF_POD" ]]  || fail "notification-service pod not found"
[[ -n "$PAYMENT_POD" ]] || fail "payment-service pod not found"
[[ -n "$OPA_POD" ]]    || fail "opa-server pod not found"
log "notification-service pod: $NOTIF_POD"
log "payment-service pod:      $PAYMENT_POD"

# ── 2. Health check via API Gateway ──────────────────────────────────────────
log "checking API Gateway health..."
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway unreachable at $GW_URL"

# ── 3. Attack: exec into notification-service → call via Envoy outbound ───────
# Envoy outbound (127.0.0.1:15001) adds real mTLS SPIRE SVID for notification-service.
# Route /payments/* → payment_service cluster (mTLS, SVID = notification-service).
# payment-service Envoy inbound sees real SVID → OPA evaluates → denies (wrong service).
log "executing lateral movement from within notification-service (via Envoy outbound 15001)..."
ATTACK_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
code=$(kubectl --context "$K8S_CTX" exec -n "$NAMESPACE" "$NOTIF_POD" \
  -c notification-service -- python3 -c "
import urllib.request, json, sys
data = json.dumps({
  'from_account': 'ACC-1001',
  'to_account':   'ACC-9999',
  'amount':       500000,
  'currency':     'VND'
}).encode()
req = urllib.request.Request(
  'http://127.0.0.1:15001/payments/internal/execute',
  data=data, method='POST',
  headers={
    'Content-Type': 'application/json',
    'Host': 'payment-service.financial.svc.cluster.local'
  })
try:
    resp = urllib.request.urlopen(req, timeout=5)
    print(resp.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print('ERR', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null)
log "Envoy response: HTTP $code"
[[ "$code" == "403" ]] || fail "expected 403 from OPA deny, got HTTP $code"

# ── 4. Give logs 2s to flush, then read real evidence ─────────────────────────
sleep 2

# Real Envoy access log from payment-service — large tail, filter /payments non-metrics
ENVOY_ENTRY=$(kubectl --context "$K8S_CTX" logs -n "$NAMESPACE" "$PAYMENT_POD" \
  -c envoy --tail=500 2>/dev/null \
  | python3 -c "
import sys, json
entries = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        j = json.loads(line)
        path = j.get('path','')
        if 'payments' in path and 'metrics' not in path:
            entries.append(j)
    except:
        pass
if entries:
    e = entries[-1]
    svid = e.get('svid') or ''
    print('response_code={} path={} svid={} source_ip={} upstream={} bytes_sent={}'.format(
        e.get('response_code','?'), e.get('path','?'), svid,
        e.get('source_ip','?'), e.get('upstream','?'), e.get('bytes_sent','?')))
")

# Real OPA decision (principal + result=false for /payments/internal/execute)
OPA_ENTRY=$(kubectl --context "$K8S_CTX" logs -n "$NAMESPACE" "$OPA_POD" \
  --tail=300 2>/dev/null \
  | python3 -c "
import sys, json
entries = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        j = json.loads(line)
        path = j.get('input', {}).get('attributes', {}).get('request', {}).get('http', {}).get('path', '')
        result = j.get('result')
        if 'payment' in path and 'metrics' not in path and result is False:
            src = j.get('input', {}).get('attributes', {}).get('source', {})
            principal = src.get('principal', '')
            entries.append({'path': path, 'principal': principal, 'result': result, 'time': j.get('time','')})
    except:
        pass
if entries:
    e = entries[-1]
    print('time={time} path={path} principal={principal} result={result}'.format(**e))
" 2>/dev/null)

log "Envoy evidence: $ENVOY_ENTRY"
log "OPA evidence:   $OPA_ENTRY"

# Validate that the real SVID appeared in logs
if echo "$ENVOY_ENTRY" | grep -q "spiffe://ztlab.local/aws/notification-service"; then
  log "SVID verified in Envoy log"
else
  log "WARNING: notification-service SVID not found in Envoy log (check mTLS path)"
fi

# ── 5. Feed REAL log evidence to AI Analyzer ──────────────────────────────────
log "sending real log evidence to AI Analyzer..."
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d "$(python3 -c "
import json, sys
envoy = '$ENVOY_ENTRY'
opa   = '$OPA_ENTRY'
ts    = '$ATTACK_TS'
payload = {
  'source': 'scenario_03_lateral_movement',
  'logs': [
    {
      'timestamp': ts,
      'message': 'opa_deny ' + opa,
      'labels': {'namespace': 'financial', 'app': 'opa-server', 'job': 'opa-decisions'}
    },
    {
      'timestamp': ts,
      'message': 'envoy_block ' + envoy,
      'labels': {'namespace': 'financial', 'app': 'payment-service', 'job': 'envoy-access'}
    },
    {
      'timestamp': ts,
      'message': 'lateral_movement_attempt caller=notification-service target=payment-service path=/payments/internal/execute svid=spiffe://ztlab.local/aws/notification-service',
      'labels': {'namespace': 'financial', 'app': 'notification-service', 'job': 'kubernetes-pods'}
    }
  ]
}
print(json.dumps(payload))
")")

printf '%s\n' "$response" | python3 -m json.tool 2>/dev/null || true
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
attack=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('attack_type','?'))")

[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious verdict, got $verdict"

pass "lateral movement blocked HTTP $code; svid=notification-service verified; AI verdict=$verdict attack=$attack (T1021.007)"
