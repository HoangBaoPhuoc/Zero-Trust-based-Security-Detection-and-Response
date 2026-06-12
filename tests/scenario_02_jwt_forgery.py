#!/usr/bin/env python3
"""Scenario 02 — JWT Token Forgery (T1550.001)
Sends a JWT signed with wrong secret to payment endpoint, expects 401/403.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.request
import urllib.error

GW_URL = os.environ.get("GW_URL", "http://localhost:18080")
SCENARIO = "scenario_02_jwt_forgery"


def log(msg: str) -> None:
    print(f"[{SCENARIO}] {msg}")


def fail(msg: str) -> None:
    print(f"[{SCENARIO}] FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_forged_jwt(subject: str = "testuser01") -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "sub": subject,
        "preferred_username": subject,
        "realm_access": {"roles": ["financial-read", "financial-write"]},
        "iss": "http://keycloak.ztlab.local/realms/ztlab",
        "exp": 9999999999,
        "iat": 1000000000,
    }).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(b"wrong-secret-key", signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(sig)}"


def http_post(url: str, body: dict, headers: dict) -> int:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


log("checking API Gateway health...")
try:
    with urllib.request.urlopen(f"{GW_URL}/health", timeout=10) as resp:
        assert resp.status == 200
except Exception as exc:
    fail(f"API Gateway unreachable: {exc}")

forged = make_forged_jwt()
log(f"forged JWT prefix: {forged[:40]}...")

status = http_post(
    f"{GW_URL}/payments",
    {"from_account": "ACC-1001", "to_account": "ACC-2001", "amount": 1000, "currency": "VND"},
    {"Authorization": f"Bearer {forged}", "Content-Type": "application/json"},
)
log(f"response HTTP {status}")

if status in (401, 403):
    print(f"[{SCENARIO}] PASS: forged JWT rejected with HTTP {status} (T1550.001)")
else:
    fail(f"forged JWT was NOT rejected — HTTP {status} (expected 401 or 403)")
