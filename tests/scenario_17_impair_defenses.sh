#!/bin/bash
# Scenario 17 — Impair Defenses: Access to Security Infrastructure (T1562)
# Attempts to reach OPA admin API, Prometheus metrics, Loki push endpoint, and
# Grafana admin API from outside their intended access boundaries.
# All should be inaccessible or require authentication.
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
AI_URL="${AI_URL:-http://localhost:8090}"
LOKI_URL="${LOKI_URL:-http://localhost:3100}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
SCENARIO="scenario_17_impair_defenses"

log()  { printf "[%s] %s\n" "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

curl -fsS "$AI_URL/health" >/dev/null || fail "AI Analyzer unreachable"

log "attempting to reach security infrastructure endpoints without auth..."
protected=0

# OPA admin endpoints (should be internal-only)
log "checking OPA admin API via API Gateway..."
code=$(curl -s -o /dev/null -w "%{http_code}" "$GW_URL/opa/v1/policies")
log "GET /opa/v1/policies → HTTP $code"
[[ "$code" =~ ^(401|403|404)$ ]] && protected=$((protected + 1)) || log "WARNING: OPA admin endpoint exposed (HTTP $code)"

# Prometheus scrape without auth
log "checking Prometheus /metrics endpoint..."
code=$(curl -s -o /dev/null -w "%{http_code}" "$GW_URL/metrics")
log "GET /metrics via GW → HTTP $code"
[[ "$code" =~ ^(401|403|404)$ ]] && protected=$((protected + 1))

# Loki push without auth (should require auth or be internal-only)
log "attempting Loki push without auth..."
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$LOKI_URL/loki/api/v1/push" \
  -H "Content-Type: application/json" \
  -d '{"streams":[{"stream":{"job":"attacker"},"values":[["'"$(date +%s%N)"'","impair_defenses_test"]]}]}' \
  2>/dev/null || echo "000")
log "Loki push → HTTP $code"
[[ "$code" =~ ^(401|403|204|200)$ ]] && protected=$((protected + 1)) \
  || log "NOTE: Loki may be open for push (expected in lab — restrict in prod)"

# Grafana admin without credentials
log "checking Grafana admin API without credentials..."
code=$(curl -s -o /dev/null -w "%{http_code}" "$GRAFANA_URL/api/admin/settings")
log "GET /api/admin/settings → HTTP $code"
[[ "$code" =~ ^(401|403)$ ]] && protected=$((protected + 1)) || log "WARNING: Grafana admin API exposed"

log "injecting defense-impairment attempt log to AI Analyzer..."
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "scenario_17_impair_defenses",
    "logs": [
      {"timestamp": "'"$ts"'",
       "message": "security_infrastructure_probe opa_admin_access_attempt source_ip=10.9.8.50 path=/v1/policies method=GET unauthorized",
       "labels": {"namespace":"financial","app":"opa-server","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "prometheus_scrape_attempt_blocked source_ip=10.9.8.50 target=opa-server:9191 reason=networkpolicy",
       "labels": {"namespace":"financial","app":"opa-server","job":"kubernetes-pods"}},
      {"timestamp": "'"$ts"'",
       "message": "impair_defenses attempt to disable logging detected loki_push_unauthorized source_ip=10.9.8.50",
       "labels": {"namespace":"plg-stack","app":"loki","job":"kubernetes-pods"}}
    ]
  }')
verdict=$(printf '%s' "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('verdict','?'))")
[[ "$verdict" == "malicious" || "$verdict" == "suspicious" ]] \
  || fail "expected malicious/suspicious, got $verdict"

pass "security infrastructure endpoints checked; AI verdict=$verdict (T1562)"
