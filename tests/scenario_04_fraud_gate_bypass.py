#!/usr/bin/env python3
"""Scenario 04 — Fraud Gate Bypass (T1078.004)
Calls /payments with amount=500M VND via 'tor' channel → fraud score=75 → blocked.
Collects real evidence from fraud-detection AUDIT log, payment-service AUDIT log,
and API Gateway Envoy access log.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

GW_URL  = os.environ.get("GW_URL",  "http://localhost:18080")
KC_URL  = os.environ.get("KC_URL",  "http://localhost:8180")
K8S_CTX = os.environ.get("K8S_CTX", "ctx-aws")
NS      = "financial"
SCENARIO = "scenario_04_fraud_gate_bypass"


def log(msg: str) -> None:
    print(f"[{SCENARIO}] {msg}")


def fail(msg: str) -> None:
    print(f"[{SCENARIO}] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def http_post(url: str, body, headers: dict, form: bool = False) -> tuple[int, str]:
    data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    req  = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def kubectl_logs(pod: str, container: str, tail: int = 200) -> list[str]:
    result = subprocess.run(
        ["kubectl", "--context", K8S_CTX, "logs", "-n", NS, pod, "-c", container,
         f"--tail={tail}"],
        capture_output=True, text=True
    )
    return result.stdout.splitlines()


def get_pod(label: str) -> str:
    result = subprocess.run(
        ["kubectl", "--context", K8S_CTX, "get", "pods", "-n", NS,
         "-l", label, "-o", "jsonpath={.items[0].metadata.name}"],
        capture_output=True, text=True
    )
    return result.stdout.strip()


# ── 1. Resolve pods ───────────────────────────────────────────────────────────
log("resolving pods...")
gw_pod    = get_pod("app=api-gateway")
pay_pod   = get_pod("app=payment-service")
fraud_pod = get_pod("app=fraud-detection")

for name, pod in [("api-gateway", gw_pod), ("payment-service", pay_pod), ("fraud-detection", fraud_pod)]:
    if not pod:
        fail(f"{name} pod not found")
    log(f"{name} pod: {pod}")

# ── 2. Health check ───────────────────────────────────────────────────────────
log("checking API Gateway health...")
try:
    with urllib.request.urlopen(f"{GW_URL}/health", timeout=10) as r:
        assert r.status == 200
except Exception as exc:
    fail(f"API Gateway unreachable: {exc}")

# ── 3. Get JWT ────────────────────────────────────────────────────────────────
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
        log(f"WARNING: Keycloak returned {status}, proceeding without token")
except Exception as exc:
    log(f"WARNING: Keycloak unreachable ({exc}), proceeding without token")

# ── 4. Attack: amount=500M VND via tor channel ────────────────────────────────
log("sending 500M VND via tor channel (expected: fraud score=75 → 403 block)...")
headers = {"Content-Type": "application/json"}
if token:
    headers["Authorization"] = f"Bearer {token}"

status, body = http_post(
    f"{GW_URL}/payments",
    {"from_account": "ACC-1001", "to_account": "ACC-2001",
     "amount": 500_000_000, "currency": "VND", "channel": "tor"},
    headers,
)
log(f"response HTTP {status}: {body[:200]}")
if status not in (400, 403):
    fail(f"expected 403 fraud block, got {status}")

# ── 5. Collect real log evidence ──────────────────────────────────────────────
time.sleep(2)

# fraud-detection AUDIT: fraud_score_computed event
fraud_evidence = ""
for line in kubectl_logs(fraud_pod, "fraud-detection", tail=200):
    try:
        j = json.loads(line)
        if j.get("event") == "fraud_score_computed" and j.get("verdict") == "block":
            fraud_evidence = (
                f"event={j['event']} amount={j.get('amount')} "
                f"fraud_score={j.get('fraud_score')} verdict={j.get('verdict')} "
                f"reason={j.get('reason')}"
            )
    except Exception:
        pass

# payment-service AUDIT: payment_blocked_fraud event
pay_evidence = ""
for line in kubectl_logs(pay_pod, "payment-service", tail=100):
    try:
        j = json.loads(line)
        if j.get("event") == "payment_blocked_fraud":
            pay_evidence = (
                f"event={j['event']} fraud_score={j.get('fraud_score')} "
                f"trace_id={j.get('trace_id')} gate={j.get('fraud',{}).get('gate')}"
            )
    except Exception:
        pass

# API Gateway Envoy access log: last /payments 403 entry
envoy_evidence = ""
for line in kubectl_logs(gw_pod, "envoy", tail=500):
    try:
        j = json.loads(line)
        if j.get("path", "").startswith("/payments") and "metrics" not in j.get("path", ""):
            envoy_evidence = (
                f"response_code={j.get('response_code')} path={j.get('path')} "
                f"source_ip={j.get('source_ip')} bytes_sent={j.get('bytes_sent')} "
                f"response_time={j.get('response_time')}ms"
            )
    except Exception:
        pass

log(f"fraud-detection evidence: {fraud_evidence or 'NOT FOUND'}")
log(f"payment-service evidence: {pay_evidence or 'NOT FOUND'}")
log(f"Envoy evidence:           {envoy_evidence or 'NOT FOUND'}")

# ── 6. Assert evidence ────────────────────────────────────────────────────────
if not fraud_evidence:
    fail("fraud_score_computed AUDIT log not found in fraud-detection")
score_val = next((int(p.split("=")[1]) for p in fraud_evidence.split() if p.startswith("fraud_score=")), 0)
if score_val < 70:
    fail(f"expected fraud_score >= 70 (block threshold) in fraud-detection log, got: {fraud_evidence}")
if not pay_evidence:
    fail("payment_blocked_fraud AUDIT log not found in payment-service")

print(f"[{SCENARIO}] PASS: fraud gate blocked HTTP {status}; "
      f"fraud_score={score_val} (>= block threshold 70) verified in fraud-detection + payment-service logs (T1078.004)")
