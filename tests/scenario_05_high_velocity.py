#!/usr/bin/env python3
"""Scenario 05 — High-Velocity Transaction Flood (T1496 / T1110)
Sends 40 rapid payment requests from the same account.
Expects velocity-based blocking after ~30 requests (fraud score ≥ 75).
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error

GW_URL = os.environ.get("GW_URL", "http://localhost:18080")
KC_URL = os.environ.get("KC_URL", "http://localhost:18443")
SCENARIO = "scenario_05_high_velocity"
REQUESTS = int(os.environ.get("VELOCITY_REQUESTS", "40"))


def log(msg: str) -> None:
    print(f"[{SCENARIO}] {msg}")


def fail(msg: str) -> None:
    print(f"[{SCENARIO}] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def http_post(url: str, body: dict | str, headers: dict, form: bool = False) -> tuple[int, str]:
    data = (body.encode() if isinstance(body, str) else body) if form else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


# Health
try:
    with urllib.request.urlopen(f"{GW_URL}/health", timeout=10) as r:
        assert r.status == 200
except Exception as exc:
    fail(f"API Gateway unreachable: {exc}")

# Get JWT
log("getting JWT from Keycloak...")
token = ""
try:
    s, b = http_post(
        f"{KC_URL}/realms/ztlab/protocol/openid-connect/token",
        "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!",
        {"Content-Type": "application/x-www-form-urlencoded"},
        form=True,
    )
    if s == 200:
        token = json.loads(b).get("access_token", "")
    else:
        log(f"WARNING: Keycloak {s}")
except Exception as exc:
    log(f"WARNING: Keycloak unreachable ({exc})")

headers = {"Content-Type": "application/json"}
if token:
    headers["Authorization"] = f"Bearer {token}"

log(f"sending {REQUESTS} rapid payment requests from ACC-1001...")
statuses: list[int] = []
for i in range(REQUESTS):
    s, _ = http_post(
        f"{GW_URL}/payments",
        {"from_account": "ACC-1001", "to_account": "ACC-2001", "amount": 150_000_000 + i, "currency": "VND"},
        headers,
    )
    statuses.append(s)
    if (i + 1) % 10 == 0:
        log(f"  {i+1}/{REQUESTS} sent — last code: {s}")

blocked = sum(1 for s in statuses if s in (400, 403, 429))
allowed = sum(1 for s in statuses if s == 200)
log(f"results: {allowed} allowed, {blocked} blocked (400/403/429), total={REQUESTS}")

# Velocity blocking kicks in after ~10 requests in a 60s window (fraud score ≥ 75)
if blocked < 5:
    fail(f"expected ≥5 blocked by velocity/fraud, got {blocked}. statuses={statuses}")

print(f"[{SCENARIO}] PASS: {blocked}/{REQUESTS} requests blocked by velocity/fraud scoring (T1496)")
