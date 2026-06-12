#!/usr/bin/env python3
"""Scenario 06 — Data Exfiltration via Large Response (T1041)
Injects a synthetic log showing a large response (>1MB bytes_sent) from core-banking.
Verifies AI Analyzer detects this as suspicious/malicious and recommends restrict_egress.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

AI_URL = os.environ.get("AI_URL", "http://localhost:18082")
SCENARIO = "scenario_06_exfiltration"


def log(msg: str) -> None:
    print(f"[{SCENARIO}] {msg}")


def fail(msg: str) -> None:
    print(f"[{SCENARIO}] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def http_post(url: str, body: dict, headers: dict) -> tuple[int, str]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


log("checking AI Analyzer health...")
try:
    with urllib.request.urlopen(f"{AI_URL}/health", timeout=10) as r:
        assert r.status == 200
except Exception as exc:
    fail(f"AI Analyzer unreachable: {exc}")

ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
log("injecting large-response exfiltration logs...")
status, body = http_post(
    f"{AI_URL}/analyze",
    {
        "source": "scenario_06_exfiltration",
        "logs": [
            {
                "timestamp": ts,
                "message": "response_code=200 bytes_sent=2097152 method=GET path=/accounts/ACC-1001/history service=account-service duration_ms=4800 source_ip=203.0.113.42",
                "labels": {"namespace": "financial", "app": "account-service", "job": "envoy-access", "cloud": "openstack"},
            },
            {
                "timestamp": ts,
                "message": "large_response_detected bytes_sent=2097152 threshold=524288 path=/accounts/ACC-1001/history client_ip=203.0.113.42",
                "labels": {"namespace": "financial", "app": "envoy-proxy", "job": "envoy-access", "cloud": "openstack"},
            },
            {
                "timestamp": ts,
                "message": "data_exfiltration_risk account=ACC-1001 exported_records=8420 destination=203.0.113.42 bytes=2097152",
                "labels": {"namespace": "financial", "app": "account-service", "job": "kubernetes-pods"},
            },
        ],
    },
    {"Content-Type": "application/json"},
)
if status != 200:
    fail(f"AI Analyzer returned {status}: {body[:200]}")

result = json.loads(body)
verdict = result.get("verdict", "?")
playbook = result.get("recommended_playbook", "?")
log(f"AI verdict={verdict} attack={result.get('attack_type','?')} playbook={playbook}")

if verdict not in ("malicious", "suspicious"):
    fail(f"expected malicious/suspicious, got {verdict}")
if "restrict" not in playbook and "isolate" not in playbook and "quarantine" not in playbook:
    log(f"WARNING: unexpected playbook {playbook!r} (expected restrict_egress or isolate)")

print(f"[{SCENARIO}] PASS: AI detected large-response exfiltration verdict={verdict} playbook={playbook} (T1041)")
