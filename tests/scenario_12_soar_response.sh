#!/bin/bash
set -euo pipefail

AI_URL="${AI_URL:-http://127.0.0.1:8090}"
SOAR_URL="${SOAR_URL:-http://127.0.0.1:8091}"

printf '[scenario_12] checking AI analyzer health...\n'
curl -fsS "$AI_URL/health" >/dev/null

printf '[scenario_12] checking SOAR engine health...\n'
curl -fsS "$SOAR_URL/health" >/dev/null

printf '[scenario_12] sending fraud_gate_bypass log to AI analyzer...\n'
response=$(curl -fsS -X POST "$AI_URL/analyze" \
  -H 'Content-Type: application/json' \
  -d '{"source":"scenario_12_soar_response","logs":[{"message":"OPA deny fraud_gate_bypass response_code=403 source_ip=10.10.1.77 service=payment-service path=/transactions/execute"}]}')

printf '%s\n' "$response"
echo "$response" | grep -q '"verdict":"malicious"'
echo "$response" | grep -q '"recommended_playbook":"isolate_workload"'

printf '[scenario_12] checking SOAR cases...\n'
cases=$(curl -fsS "$SOAR_URL/cases")
printf '%s\n' "$cases"
echo "$cases" | grep -q 'fraud_gate_bypass'
echo "$cases" | grep -Eq '"status":"(dry_run|executed)"'

printf '[scenario_12] PASS: AI alert produced a SOAR case/action.\n'
