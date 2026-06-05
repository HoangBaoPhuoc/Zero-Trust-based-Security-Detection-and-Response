#!/bin/bash
set -euo pipefail

AI_URL="${AI_URL:-http://127.0.0.1:8090}"
SOAR_URL="${SOAR_URL:-http://127.0.0.1:8091}"
LOKI_URL="${LOKI_URL:-http://127.0.0.1:3100}"
SLEEP_SECONDS="${SLEEP_SECONDS:-1}"
SOAR_API_TOKEN="${SOAR_API_TOKEN:-}"

soar_curl() {
  if [[ -n "$SOAR_API_TOKEN" ]]; then
    curl -fsS -H "Authorization: Bearer $SOAR_API_TOKEN" "$@"
  else
    curl -fsS "$@"
  fi
}

push_raw_log() {
  local scenario="$1"
  local severity="$2"
  local message="$3"
  local now_ns
  now_ns="$(date +%s%N)"
  python3 - "$LOKI_URL" "$scenario" "$severity" "$message" "$now_ns" <<'PY_PUSH'
import json
import sys
import urllib.request

loki_url, scenario, severity, message, now_ns = sys.argv[1:]
payload = {
    "streams": [
        {
            "stream": {
                "job": "demo-raw",
                "service": "ztlab-demo",
                "scenario": scenario,
                "severity": severity,
            },
            "values": [[now_ns, json.dumps({"event_type": "demo_raw_log", "scenario": scenario, "severity": severity, "message": message})]],
        }
    ]
}
req = urllib.request.Request(
    f"{loki_url.rstrip('/')}/loki/api/v1/push",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=10) as res:
    if res.status != 204:
        raise SystemExit(f"Loki push returned HTTP {res.status}")
PY_PUSH
}

analyze_log() {
  local scenario="$1"
  local message="$2"
  python3 - "$AI_URL" "$scenario" "$message" <<'PY_ANALYZE'
import json
import sys
import urllib.request

ai_url, scenario, message = sys.argv[1:]
payload = {"source": f"demo-{scenario}", "logs": [{"message": message, "labels": {"job": "demo-raw", "scenario": scenario}}]}
req = urllib.request.Request(
    f"{ai_url.rstrip('/')}/analyze",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=60) as res:
    print(res.read().decode())
PY_ANALYZE
}

run_case() {
  local scenario="$1"
  local severity="$2"
  local message="$3"
  printf '\n[demo] %s\n' "$scenario"
  push_raw_log "$scenario" "$severity" "$message"
  analyze_log "$scenario" "$message"
  sleep "$SLEEP_SECONDS"
}

printf '[demo] checking services...\n'
curl -fsS "$AI_URL/health" >/dev/null
curl -fsS "$SOAR_URL/health" >/dev/null
curl -fsS "$LOKI_URL/loki/api/v1/labels" >/dev/null

run_case "fraud-gate-bypass" "critical" "OPA deny fraud_gate_bypass response_code=403 source_ip=10.10.1.77 service=payment-service path=/transactions/execute"
run_case "lateral-movement" "critical" "Envoy denied lateral movement invalid SVID spiffe deny source_ip=10.10.1.88 service=core-banking destination=openstack/core-banking"
run_case "large-response" "high" "Envoy access log response_code=200 bytes_sent=2500000 source_ip=10.10.4.22 service=core-banking path=/accounts/export"
run_case "cryptomining" "critical" "system alert xmrig cryptomining stratum+tcp source_ip=10.10.4.33 service=transaction-service pod=transaction-service"
run_case "port-scan" "high" "network alert nmap port scan source_ip=10.10.0.44 service=api-gateway ports=22,80,443,8080"

printf '\n[demo] recent SOAR cases:\n'
soar_curl "$SOAR_URL/cases"
printf '\n\n[demo] open Grafana dashboard: http://127.0.0.1:3000/d/ztlab-ai-siem-soar/ztlab-ai-siem-soar\n'
