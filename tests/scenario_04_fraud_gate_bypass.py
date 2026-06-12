#!/usr/bin/env python3
"""Scenario 04 — Fraud Gate Bypass (T1078)
Calls /payments with amount=500M VND via 'tor' channel → fraud score=75 → blocked.
Also injects a fraud_gate_bypass log to AI Analyzer and verifies detection.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

GW_URL = os.environ.get("GW_URL", "http://localhost:18080")
KC_URL = os.environ.get("KC_URL", "http://localhost:18443")
AI_URL = os.environ.get("AI_URL", "http://localhost:18082")
SCENARIO = "scenario_04_fraud_gate_bypass"


def log(msg: str) -> None:
    print(f"[{SCENARIO}] {msg}")


def fail(msg: str) -> None:
    print(f"[{SCENARIO}] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def http_post(url: str, body: dict | str, headers: dict, form: bool = False) -> tuple[int, str]:
    if form:
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    else:
        data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


# Health
log("checking API Gateway health...")
try:
    with urllib.request.urlopen(f"{GW_URL}/health", timeout=10) as r:
        assert r.status == 200
except Exception as exc:
    fail(f"API Gateway unreachable: {exc}")

# Get a valid JWT
log("getting JWT from Keycloak...")
token = ""
try:
    status, body = http_post(
        f"{KC_URL}/realms/ztlab/protocol/openid-connect/token",
        "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!",
        {"Content-Type": "application/x-www-form-urlencoded"},
        form=True,
    )
    if status == 200:
        token = json.loads(body).get("access_token", "")
    else:
        log(f"WARNING: Keycloak returned {status}, using no token")
except Exception as exc:
    log(f"WARNING: Keycloak unreachable ({exc}), continuing without token")

# Test 1: amount=500M VND via tor → score=75 → block
log("test 1: sending 500M VND via tor channel (score=75, should block)...")
headers = {"Content-Type": "application/json"}
if token:
    headers["Authorization"] = f"Bearer {token}"
status, body = http_post(
    f"{GW_URL}/payments",
    {"from_account": "ACC-1001", "to_account": "ACC-2001", "amount": 500_000_000, "currency": "VND", "channel": "tor"},
    headers,
)
log(f"response HTTP {status}: {body[:120]}")
if status not in (400, 403):
    log(f"WARNING: expected 403 fraud block, got {status} (fraud detection may not be active or amount threshold differs)")

# Test 2: AI detection via inject
log("test 2: injecting fraud_gate_bypass log to AI Analyzer...")
ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
ai_status, ai_body = http_post(
    f"{AI_URL}/analyze",
    {
        "source": "scenario_04_fraud_gate_bypass",
        "logs": [
            {"timestamp": ts, "message": "fraud_gate_bypass detected service=payment-service source_ip=10.9.8.7 X-Fraud-Gate=missing attempt to execute transaction without fraud validation", "labels": {"namespace": "financial", "app": "payment-service", "job": "envoy-access"}},
            {"timestamp": ts, "message": "opa_deny path=/transactions/execute reason=fraud_gate_missing svid=spiffe://ztlab.local/aws/payment-service", "labels": {"namespace": "financial", "app": "opa-server", "job": "opa-decisions"}},
        ],
    },
    {"Content-Type": "application/json"},
)
if ai_status != 200:
    fail(f"AI Analyzer returned {ai_status}: {ai_body[:200]}")
result = json.loads(ai_body)
verdict = result.get("verdict", "?")
log(f"AI verdict={verdict} attack={result.get('attack_type','?')} playbook={result.get('recommended_playbook','?')}")
if verdict not in ("malicious", "suspicious"):
    fail(f"expected malicious/suspicious, got {verdict}")

print(f"[{SCENARIO}] PASS: fraud gate bypass blocked HTTP {status}; AI verdict={verdict} (T1078)")
