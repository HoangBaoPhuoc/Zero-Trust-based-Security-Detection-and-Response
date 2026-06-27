#!/bin/bash
# Scenario 03 — Lateral Movement (T1021.007)
# Executes attack FROM WITHIN notification-service pod via Envoy outbound proxy
# so the real SPIRE SVID appears in Envoy/OPA logs.  OPA blocks with 403.
set -euo pipefail

K8S_CTX="${K8S_CTX:-ctx-aws}"
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
[[ -n "$OPA_POD" ]]    || fail "opa pod not found"
log "notification-service pod: $NOTIF_POD"
log "payment-service pod:      $PAYMENT_POD"

# ── 2. Health check ───────────────────────────────────────────────────────────
log "checking API Gateway health..."
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway unreachable at $GW_URL"

# ── 3. Attack: exec into notification-service → call via Envoy outbound ───────
# Envoy outbound (127.0.0.1:15001) attaches notification-service SPIRE SVID
# as mTLS client cert when connecting to payment-service.
log "executing lateral movement from notification-service via Envoy outbound (15001)..."
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

# ── 4. Collect real log evidence ──────────────────────────────────────────────
sleep 2

# Envoy access log — payment-service (last /payments non-metrics entry)
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
    print('response_code={} path={} svid={} source_ip={} upstream={} bytes_sent={}'.format(
        e.get('response_code','?'), e.get('path','?'),
        e.get('svid') or '',
        e.get('source_ip','?'), e.get('upstream','?'), e.get('bytes_sent','?')))
")

# OPA decision log — last deny on /payments/internal/execute
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
        if 'payments' in path and 'metrics' not in path and j.get('result') is False:
            src = j.get('input', {}).get('attributes', {}).get('source', {})
            entries.append({'path': path, 'principal': src.get('principal',''), 'time': j.get('time','')})
    except:
        pass
if entries:
    e = entries[-1]
    print('time={time} path={path} principal={principal} result=False'.format(**e))
")

log "Envoy evidence: $ENVOY_ENTRY"
log "OPA evidence:   $OPA_ENTRY"

# ── 5. Assert SVID in both logs ───────────────────────────────────────────────
echo "$ENVOY_ENTRY" | grep -q "spiffe://ztlab.local/aws/notification-service" \
  || fail "notification-service SVID missing from Envoy log — mTLS not enforced"
echo "$OPA_ENTRY" | grep -q "spiffe://ztlab.local/aws/notification-service" \
  || fail "notification-service principal missing from OPA deny log"

pass "lateral movement blocked HTTP $code; SVID verified in Envoy + OPA logs (T1021.007)"
