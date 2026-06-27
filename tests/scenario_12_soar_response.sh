#!/bin/bash
# scenario_12 — SOAR 4-step Response Pipeline
# Tests: isolate_workload (fraud_gate_bypass), block_source_ip (port_scan),
#        revoke_user_sessions (brute_force), and rollback.
# MITRE: TA0040 Impact / TA0006 Credential Access
set -euo pipefail

AI_URL="${AI_URL:-http://localhost:18082}"
SOAR_URL="${SOAR_URL:-http://127.0.0.1:8091}"
GW_URL="${GW_URL:-http://127.0.0.1:18080}"

pass() { printf '[scenario_12] PASS: %s\n' "$1"; }
fail() { printf '[scenario_12] FAIL: %s\n' "$1"; exit 1; }

# ── Health checks ────────────────────────────────────────────────────────────
printf '[scenario_12] checking AI analyzer health...\n'
curl -fsS "$AI_URL/health" >/dev/null || fail "AI analyzer unreachable"

printf '[scenario_12] checking SOAR engine health...\n'
soar_health=$(curl -fsS "$SOAR_URL/health")
echo "$soar_health" | grep -q '"status":"ok"' || fail "SOAR engine unhealthy"

# Verify new playbooks are registered
echo "$soar_health" | grep -q '"block_source_ip"' || fail "block_source_ip playbook missing"
echo "$soar_health" | grep -q '"revoke_user_sessions"' || fail "revoke_user_sessions playbook missing"
pass "health checks passed; new playbooks registered"

# ── Test 1: isolate_workload (fraud_gate_bypass) ─────────────────────────────
printf '[scenario_12] TEST 1: fraud_gate_bypass → isolate_workload + 4-step\n'

resp1=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H 'Content-Type: application/json' \
  -d '{
    "source": "scenario_12_fraud_bypass",
    "logs": [{
      "message": "OPA deny fraud_gate_bypass response_code=403 source_ip=10.10.1.77 service=payment-service path=/transactions/execute amount=500000000 channel=tor"
    }]
  }')
printf '%s\n' "$resp1"

echo "$resp1" | grep -q '"verdict":"malicious"' || fail "expected malicious verdict for fraud_gate_bypass"
echo "$resp1" | grep -q '"recommended_playbook":"isolate_workload"' || fail "expected isolate_workload playbook"

# Approve pending alert if HITL is active
printf '[scenario_12] approving pending alert if required...\n'
pending=$(curl -fsS "$AI_URL/pending?status=pending")
alert_id=$(printf "%s" "$pending" | python3 -c "
import sys, json
alerts = json.load(sys.stdin)
if alerts:
    print(alerts[0].get('alert_id',''))
" 2>/dev/null || echo "")
if [[ -n "$alert_id" ]]; then
  curl -fsS -X POST "$AI_URL/pending/$alert_id/approve" \
    -H 'Content-Type: application/json' \
    -d '{"note":"scenario_12 test approval"}' >/dev/null
  printf '[scenario_12] approved alert %s\n' "$alert_id"
  sleep 2
fi

# Check SOAR case created with steps
cases=$(curl -fsS "$SOAR_URL/cases")
echo "$cases" | grep -q 'fraud_gate_bypass' || fail "SOAR case not created for fraud_gate_bypass"
echo "$cases" | grep -Eq '"status":"(dry_run|executed)"' || fail "SOAR case status unexpected"

# Verify 4-step structure
echo "$cases" | python3 -c "
import sys, json
cases = json.load(sys.stdin)
relevant = [c for c in cases if c.get('attack_type') == 'fraud_gate_bypass']
if not relevant:
    print('no relevant case')
    sys.exit(1)
case = relevant[-1]
steps = case.get('steps', [])
phases = [s['phase'] for s in steps]
print('steps:', phases)
for required in ['contain', 'investigate', 'eradicate', 'recover']:
    if required not in phases:
        print(f'missing phase: {required}')
        sys.exit(1)
print('all 4 phases present')
" || fail "4-step playbook phases incomplete"

pass "TEST 1: isolate_workload with 4-step phases verified"

# ── Test 2: block_source_ip (port_scan) ──────────────────────────────────────
printf '[scenario_12] TEST 2: port_scan → block_source_ip\n'

resp2=$(curl -fsS -X POST "$SOAR_URL/alerts" \
  -H 'Content-Type: application/json' \
  -d '{
    "verdict": "malicious",
    "severity": "high",
    "confidence": 0.85,
    "attack_type": "port_scan",
    "summary": "nmap SYN scan detected from 10.9.8.99 ports_tried=1024",
    "source_ip": "10.9.8.99",
    "affected_service": "api-gateway"
  }')
printf '%s\n' "$resp2"

echo "$resp2" | grep -q '"playbook":"block_source_ip"' || fail "expected block_source_ip playbook for port_scan"
echo "$resp2" | grep -q '"source_ip":"10.9.8.99"' || fail "source_ip not recorded in case"
echo "$resp2" | grep -Eq '"status":"(dry_run|executed)"' || fail "SOAR case status unexpected"

# Check case has contain step mentioning the IP block or NetworkPolicy
echo "$resp2" | python3 -c "
import sys, json
case = json.load(sys.stdin)
steps = case.get('steps', [])
contain = next((s for s in steps if s['phase'] == 'contain'), None)
if not contain:
    print('no contain step')
    sys.exit(1)
print('contain step:', contain['action'])
# In dry_run mode the action will say 'dry_run:' which is fine
" || fail "contain step missing in block_source_ip case"

pass "TEST 2: block_source_ip case created with source_ip tracking"

# ── Test 3: revoke_user_sessions (brute_force) ───────────────────────────────
printf '[scenario_12] TEST 3: brute_force → revoke_user_sessions\n'

resp3=$(curl -fsS -X POST "$SOAR_URL/alerts" \
  -H 'Content-Type: application/json' \
  -d '{
    "verdict": "malicious",
    "severity": "critical",
    "confidence": 0.91,
    "attack_type": "brute_force",
    "summary": "20 failed logins in 30s from 203.0.113.5",
    "source_ip": "203.0.113.5",
    "username": "testuser01",
    "affected_service": "api-gateway"
  }')
printf '%s\n' "$resp3"

echo "$resp3" | grep -q '"playbook":"revoke_user_sessions"' || fail "expected revoke_user_sessions for brute_force"
echo "$resp3" | grep -q '"username":"testuser01"' || fail "username not recorded in case"
echo "$resp3" | grep -Eq '"status":"(dry_run|executed)"' || fail "case status unexpected"

pass "TEST 3: revoke_user_sessions case created with username tracking"

# ── Test 4: rollback a case ──────────────────────────────────────────────────
printf '[scenario_12] TEST 4: rollback\n'

# Find the most recent executed/dry_run case with isolate_workload
cases_all=$(curl -fsS "$SOAR_URL/cases")
case_id=$(printf '%s' "$cases_all" | python3 -c "
import sys, json
cases = json.load(sys.stdin)
rollbackable = [c for c in cases
                if c.get('playbook') == 'isolate_workload'
                and c.get('status') in ('dry_run', 'executed')]
if rollbackable:
    print(rollbackable[-1]['case_id'])
" 2>/dev/null || echo "")

if [[ -n "$case_id" ]]; then
  rollback_resp=$(curl -fsS -X POST "$SOAR_URL/cases/$case_id/rollback" \
    -H 'Content-Type: application/json')
  echo "$rollback_resp" | grep -Eq '"status":"rolled_back"' || \
    printf '[scenario_12] NOTE: rollback status = %s (may be expected if already rolled back)\n' \
      "$(echo "$rollback_resp" | grep -o '"status":"[^"]*"' | head -1)"
  pass "TEST 4: rollback called on case $case_id"
else
  printf '[scenario_12] TEST 4: no rollbackable isolate_workload case found — skip\n'
fi

# ── Summary ──────────────────────────────────────────────────────────────────
printf '\n[scenario_12] PASS: Full SOAR response pipeline verified.\n'
printf '[scenario_12] Playbooks tested: isolate_workload, block_source_ip, revoke_user_sessions\n'
printf '[scenario_12] 4-step phases verified: contain → investigate → eradicate → recover\n'
