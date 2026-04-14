#!/usr/bin/env python3
"""Full ZTLab security test scenario suite.

Derived from IMPLEMENTATION.md §10 and MAP.md test matrix.
The suite is designed to be runnable from the deployer workstation against
both K3s clusters after the stack has been deployed.

It is intentionally self-contained:
- ports forward the required services locally
- performs a baseline warm-up
- exercises scenarios 1-11
- queries Loki for the main SIEM signals where available
- reports pass/fail/skipped per scenario

Environment variables:
  BASELINE_SECONDS        Baseline warm-up duration, default: 600
  KEYCLOAK_ADMIN_PASSWORD Keycloak admin password; if unset, read from k8s secret
  EXFIL_URL               Optional URL for scenario 6 large-response test
  ENABLE_DESTRUCTIVE      Set to 1 to allow scenario 7 agent deletion
  IMAGE_TAG               Optional tag for the local ztlab images, default: 1.0.0
  LOKI_URL                Loki base URL, default: http://10.10.2.10:3100
  STRICT                  If 1, fail fast on unexpected responses, default: 0
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import hmac
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = REPO_ROOT / "ansible" / "inventory" / "hosts.yml"
DEFAULT_LOKI_URL = os.environ.get("LOKI_URL", "http://10.10.2.10:3100")
DEFAULT_BASELINE_SECONDS = int(os.environ.get("BASELINE_SECONDS", "600"))
STRICT = os.environ.get("STRICT", "0") == "1"
ENABLE_DESTRUCTIVE = os.environ.get("ENABLE_DESTRUCTIVE", "0") == "1"
IMAGE_TAG = os.environ.get("IMAGE_TAG", "1.0.0")
EXFIL_URL = os.environ.get("EXFIL_URL", "")

AWS_CONTEXT = os.environ.get("AWS_CONTEXT", "ctx-aws")
OS_CONTEXT = os.environ.get("OS_CONTEXT", "ctx-openstack")
FINANCIAL_NAMESPACE = os.environ.get("FINANCIAL_NAMESPACE", "financial")
IDENTITY_NAMESPACE = os.environ.get("IDENTITY_NAMESPACE", "identity")
SPIRE_NAMESPACE = os.environ.get("SPIRE_NAMESPACE", "spire")

PORTS = {
    "keycloak": 18080,
    "aws_api_gateway": 18081,
    "aws_payment": 18082,
    "aws_fraud": 18083,
    "os_core_banking": 18084,
    "os_account": 18085,
    "os_txn": 18086,
    "aws_notification": 18087,
}

SERVICES = {
    "keycloak": (AWS_CONTEXT, IDENTITY_NAMESPACE, "svc/keycloak", 8080),
    "aws_api_gateway": (AWS_CONTEXT, FINANCIAL_NAMESPACE, "svc/api-gateway", 8080),
    "aws_payment": (AWS_CONTEXT, FINANCIAL_NAMESPACE, "svc/payment-service", 8080),
    "aws_fraud": (AWS_CONTEXT, FINANCIAL_NAMESPACE, "svc/fraud-detection", 8080),
    "aws_notification": (AWS_CONTEXT, FINANCIAL_NAMESPACE, "svc/notification-service", 8080),
    "os_core_banking": (OS_CONTEXT, FINANCIAL_NAMESPACE, "svc/core-banking", 8080),
    "os_account": (OS_CONTEXT, FINANCIAL_NAMESPACE, "svc/account-service", 8080),
    "os_txn": (OS_CONTEXT, FINANCIAL_NAMESPACE, "svc/transaction-service", 8080),
}

SCENARIO_ORDER = [
    "scenario_01_brute_force",
    "scenario_02_jwt_forgery",
    "scenario_03_lateral_movement",
    "scenario_04_fraud_gate_bypass",
    "scenario_05_high_velocity",
    "scenario_06_exfiltration",
    "scenario_07_svid_expiry",
    "scenario_08_cross_cloud",
    "scenario_09_privesc",
    "scenario_10_portscan",
    "scenario_11_cryptomining",
]


@dataclass
class ScenarioResult:
    name: str
    status: str
    details: str = ""
    metrics: Dict[str, object] = dataclasses.field(default_factory=dict)


class SuiteError(RuntimeError):
    pass


class CommandError(SuiteError):
    pass


class PortForward:
    def __init__(self, name: str, process: subprocess.Popen[str], local_port: int):
        self.name = name
        self.process = process
        self.local_port = local_port

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)


PORT_FORWARDS: List[PortForward] = []
SCENARIO_RESULTS: List[ScenarioResult] = []


def log(message: str) -> None:
    print(f"[INFO] {message}")


def warn(message: str) -> None:
    print(f"[WARN] {message}")


def fail(message: str) -> None:
    print(f"[ERROR] {message}", file=sys.stderr)


def run(cmd: List[str], check: bool = True, capture: bool = True, text: bool = True, input_data: Optional[str] = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        check=False,
        capture_output=capture,
        text=text,
        input=input_data,
    )
    if check and proc.returncode != 0:
        raise CommandError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def kubectl(context: str, *args: str, check: bool = True, capture: bool = True, input_data: Optional[str] = None) -> subprocess.CompletedProcess[str]:
    return run(["kubectl", "--context", context, *args], check=check, capture=capture, input_data=input_data)


def shell_output(cmd: List[str]) -> str:
    return run(cmd, check=True, capture=True).stdout.strip()


def ensure_command(name: str) -> None:
    if run(["bash", "-lc", f"command -v {name} >/dev/null 2>&1"], check=False, capture=False).returncode != 0:
        raise SuiteError(f"Missing required command: {name}")


def cleanup_port_forwards() -> None:
    for pf in PORT_FORWARDS:
        try:
            pf.stop()
        except Exception:
            pass


atexit_registered = False


def register_cleanup() -> None:
    global atexit_registered
    if atexit_registered:
        return
    import atexit

    atexit.register(cleanup_port_forwards)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: (cleanup_port_forwards(), sys.exit(130)))
    atexit_registered = True


def port_is_open(port: int, host: str = "127.0.0.1", timeout: float = 0.3) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False


def wait_for_port(port: int, timeout_seconds: int = 60) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if port_is_open(port):
            return
        time.sleep(0.5)
    raise SuiteError(f"Port {port} did not become ready in {timeout_seconds}s")


def start_port_forward(name: str, context: str, namespace: str, resource: str, local_port: int, remote_port: int) -> PortForward:
    log(f"Starting port-forward {name}: {context}/{namespace} {resource} -> 127.0.0.1:{local_port}")
    proc = subprocess.Popen(
        [
            "kubectl",
            "--context",
            context,
            "-n",
            namespace,
            "port-forward",
            resource,
            f"{local_port}:{remote_port}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    pf = PortForward(name=name, process=proc, local_port=local_port)
    PORT_FORWARDS.append(pf)
    wait_for_port(local_port, timeout_seconds=60)
    return pf


def http_request(method: str, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[bytes] = None, timeout: int = 20) -> Tuple[int, str, Dict[str, str]]:
    req = urllib.request.Request(url, method=method, headers=headers or {})
    if body is not None:
        req.data = body
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace"), dict(exc.headers)


def json_request(method: str, url: str, payload: Optional[dict] = None, headers: Optional[Dict[str, str]] = None, timeout: int = 20) -> Tuple[int, str, Dict[str, str]]:
    final_headers = {"Content-Type": "application/json"}
    if headers:
        final_headers.update(headers)
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    return http_request(method, url, headers=final_headers, body=body, timeout=timeout)


def form_request(method: str, url: str, data: Dict[str, str], headers: Optional[Dict[str, str]] = None, timeout: int = 20) -> Tuple[int, str, Dict[str, str]]:
    final_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        final_headers.update(headers)
    body = urllib.parse.urlencode(data).encode("utf-8")
    return http_request(method, url, headers=final_headers, body=body, timeout=timeout)


def get_secret_value(context: str, namespace: str, secret: str, key: str) -> str:
    proc = kubectl(context, "-n", namespace, "get", "secret", secret, "-o", f"jsonpath={{.data.{key}}}")
    encoded = proc.stdout.strip()
    if not encoded:
        raise SuiteError(f"Secret {secret}/{key} is empty in {context}/{namespace}")
    return base64.b64decode(encoded).decode("utf-8")


def read_inventory_ips() -> Dict[str, str]:
    text = INVENTORY_PATH.read_text(encoding="utf-8")
    patterns = {
        "aws_gateway": r"aws_gateway:\s*\n\s*ansible_host:\s*(\S+)",
        "os_gateway": r"os_gateway:\s*\n\s*ansible_host:\s*(\S+)",
    }
    ips: Dict[str, str] = {}
    for name, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            ips[name] = match.group(1)
    return ips


def query_loki(logql: str, start_ts: float, end_ts: Optional[float] = None, limit: int = 50) -> dict:
    if end_ts is None:
        end_ts = time.time()
    params = urllib.parse.urlencode(
        {
            "query": logql,
            "start": str(int(start_ts * 1e9)),
            "end": str(int(end_ts * 1e9)),
            "limit": str(limit),
            "direction": "forward",
        }
    )
    url = f"{DEFAULT_LOKI_URL}/loki/api/v1/query_range?{params}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def loki_count(logql: str, start_ts: float, end_ts: Optional[float] = None) -> int:
    payload = query_loki(logql, start_ts, end_ts=end_ts, limit=200)
    total = 0
    for result in payload.get("data", {}).get("result", []):
        total += len(result.get("values", []))
    return total


def scenario(name: str):
    def decorator(func):
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                details, metrics = func(start, *args, **kwargs)
                SCENARIO_RESULTS.append(ScenarioResult(name=name, status="PASS", details=details, metrics=metrics or {}))
                log(f"{name}: PASS - {details}")
            except SkipScenario as exc:
                SCENARIO_RESULTS.append(ScenarioResult(name=name, status="SKIP", details=str(exc)))
                warn(f"{name}: SKIP - {exc}")
            except Exception as exc:
                SCENARIO_RESULTS.append(ScenarioResult(name=name, status="FAIL", details=str(exc)))
                fail(f"{name}: FAIL - {exc}")
                if STRICT:
                    raise
        return wrapper
    return decorator


class SkipScenario(Exception):
    pass


def keycloak_admin_password() -> str:
    env_pwd = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "").strip()
    if env_pwd:
        return env_pwd
    return get_secret_value(AWS_CONTEXT, IDENTITY_NAMESPACE, "keycloak-secret", "admin-password")


def get_keycloak_admin_token(keycloak_base_url: str, password: str) -> str:
    url = f"{keycloak_base_url}/realms/master/protocol/openid-connect/token"
    status, body, _ = form_request(
        "POST",
        url,
        {
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": "admin",
            "password": password,
        },
    )
    if status != 200:
        raise SuiteError(f"Failed to get Keycloak admin token: HTTP {status}: {body}")
    token = json.loads(body).get("access_token")
    if not token:
        raise SuiteError("Keycloak admin token missing in response")
    return token


def create_test_user(keycloak_base_url: str, admin_token: str, username: str, password: str) -> None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    search_url = f"{keycloak_base_url}/admin/realms/master/users?username={urllib.parse.quote(username)}"
    status, body, _ = http_request("GET", search_url, headers=headers)
    if status != 200:
        raise SuiteError(f"Cannot query Keycloak users: HTTP {status}: {body}")
    users = json.loads(body)
    if users:
        return

    create_url = f"{keycloak_base_url}/admin/realms/master/users"
    payload = {
        "username": username,
        "enabled": True,
        "credentials": [
            {"type": "password", "value": password, "temporary": False}
        ],
    }
    status, body, _ = json_request("POST", create_url, payload, headers=headers)
    if status not in (201, 204):
        raise SuiteError(f"Cannot create Keycloak user: HTTP {status}: {body}")


def make_forged_jwt(subject: str = "testuser01") -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "iss": "https://keycloak.ztlab.local/realms/master",
        "aud": "ztlab-api",
        "scope": "admin",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    signing_input = f"{b64url(json.dumps(header, separators=(',', ':')).encode())}.{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = hmac.new(b"definitely-not-the-real-secret", signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(signature)}"


def baseline_traffic(keycloak_url: str, endpoints: Dict[str, str], seconds: int) -> None:
    log(f"Running baseline traffic for {seconds}s")
    started = time.time()
    i = 0
    while time.time() - started < seconds:
        for name in ("aws_api_gateway", "aws_payment", "aws_fraud", "aws_notification", "os_core_banking", "os_account", "os_txn"):
            if name not in endpoints:
                continue
            url = endpoints[name]
            if name == "os_core_banking":
                payload = {
                    "from_account": "A001",
                    "to_account": "A002",
                    "amount": 1000,
                    "currency": "VND",
                    "trace_id": f"baseline-{i}",
                }
                headers = {"X-Fraud-Gate": "passed", "X-Fraud-Score": "10", "X-Trace-ID": f"baseline-{i}"}
                json_request("POST", f"{url}/transactions/execute", payload, headers=headers)
            elif name == "aws_payment":
                payload = {
                    "from_account": "A001",
                    "to_account": "A002",
                    "amount": 1000,
                    "currency": "VND",
                    "channel": "baseline",
                }
                json_request("POST", f"{url}/payments", payload, headers={"X-Trace-ID": f"baseline-{i}"})
            else:
                http_request("GET", f"{url}/health")
        i += 1
        time.sleep(2)


@scenario("scenario_01_brute_force")
def run_brute_force(start_ts: float, keycloak_url: str, admin_password: str) -> Tuple[str, Dict[str, object]]:
    attempts = 20
    statuses = []
    token_url = f"{keycloak_url}/realms/master/protocol/openid-connect/token"
    for idx in range(attempts):
        status, body, _ = form_request(
            "POST",
            token_url,
            {
                "client_id": "admin-cli",
                "grant_type": "password",
                "username": "admin",
                "password": f"wrong-{idx}-{admin_password[:4]}",
            },
            timeout=15,
        )
        statuses.append(status)
    loki_matches = 0
    try:
        time.sleep(5)
        loki_matches = loki_count('{job="envoy-access"} | json | response_code="401"', start_ts)
    except Exception as exc:
        warn(f"Loki query skipped for brute force: {exc}")
    if all(status in (400, 401) for status in statuses):
        return f"20 invalid login attempts sent; Loki401={loki_matches}", {"statuses": statuses, "loki401": loki_matches}
    raise SuiteError(f"Unexpected Keycloak statuses: {statuses}")


@scenario("scenario_02_jwt_forgery")
def run_jwt_forgery(start_ts: float, endpoints: Dict[str, str]) -> Tuple[str, Dict[str, object]]:
    forged_jwt = make_forged_jwt()
    url = f"{endpoints['aws_payment']}/payments"
    payload = {
        "from_account": "A001",
        "to_account": "A002",
        "amount": 1000,
        "currency": "VND",
        "channel": "jwt-forgery",
    }
    status, body, _ = json_request(
        "POST",
        url,
        payload,
        headers={"Authorization": f"Bearer {forged_jwt}", "X-Trace-ID": "jwt-forgery"},
        timeout=15,
    )
    if status in (401, 403):
        return f"JWT forgery rejected with HTTP {status}", {"status": status}
    raise SuiteError(f"JWT forgery was not rejected (HTTP {status}): {body[:200]}")


@scenario("scenario_03_lateral_movement")
def run_lateral_movement(start_ts: float, endpoints: Dict[str, str]) -> Tuple[str, Dict[str, object]]:
    url = f"{endpoints['os_core_banking']}/transactions/execute"
    payload = {
        "from_account": "A001",
        "to_account": "A002",
        "amount": 100000,
        "currency": "VND",
        "trace_id": "lateral-movement",
    }
    headers = {
        "X-SPIFFE-ID": "spiffe://ztlab.local/aws/payment-service",
        "X-Destination-SPIFFE-ID": "spiffe://ztlab.local/openstack/core-banking",
        "X-Fraud-Gate": "passed",
        "X-Fraud-Score": "10",
        "X-Trace-ID": "lateral-movement",
    }
    status, body, _ = json_request("POST", url, payload, headers=headers, timeout=15)
    if status in (401, 403):
        return f"Wrong SVID call blocked with HTTP {status}", {"status": status}
    raise SuiteError(f"Wrong SVID call was not blocked (HTTP {status}): {body[:200]}")


@scenario("scenario_04_fraud_gate_bypass")
def run_fraud_gate_bypass(start_ts: float, endpoints: Dict[str, str]) -> Tuple[str, Dict[str, object]]:
    url = f"{endpoints['os_core_banking']}/transactions/execute"
    payload = {
        "from_account": "A001",
        "to_account": "A002",
        "amount": 100000,
        "currency": "VND",
        "trace_id": "fraud-gate-bypass",
    }
    status, body, _ = json_request("POST", url, payload, timeout=15)
    loki_matches = 0
    try:
        time.sleep(5)
        loki_matches = loki_count('{job="opa-decisions"} | json | deny_reason="fraud_gate_bypass"', start_ts)
    except Exception as exc:
        warn(f"Loki query skipped for fraud bypass: {exc}")
    if status == 403:
        return f"Fraud gate bypass denied; LokiDeny={loki_matches}", {"status": status, "loki_deny": loki_matches}
    raise SuiteError(f"Fraud gate bypass not denied (HTTP {status}): {body[:200]}")


@scenario("scenario_05_high_velocity")
def run_high_velocity(start_ts: float, endpoints: Dict[str, str]) -> Tuple[str, Dict[str, object]]:
    url = f"{endpoints['aws_payment']}/payments"
    statuses: List[int] = []
    for idx in range(60):
        payload = {
            "from_account": "A001",
            "to_account": "A002",
            "amount": 1000 + idx,
            "currency": "VND",
            "channel": "loadtest",
        }
        status, body, _ = json_request("POST", url, payload, headers={"X-Trace-ID": f"hv-{idx}"}, timeout=15)
        statuses.append(status)
        time.sleep(1)
    blocked = sum(1 for status in statuses if status in (429, 403))
    if blocked > 0:
        return f"Velocity flood produced {blocked} blocked responses", {"blocked": blocked, "statuses": statuses}
    raise SuiteError("High velocity flood did not trigger a block; fraud scorer/rate limiting may still be missing")


@scenario("scenario_06_exfiltration")
def run_exfiltration(start_ts: float) -> Tuple[str, Dict[str, object]]:
    if not EXFIL_URL:
        raise SkipScenario("EXFIL_URL not set; skipping large-response validation")
    status, body, headers = http_request("GET", EXFIL_URL, timeout=30)
    size = len(body.encode("utf-8", errors="ignore"))
    try:
        time.sleep(5)
        loki_matches = loki_count('{job="envoy-access", cloud="openstack"} | json | bytes_sent > 1048576', start_ts)
    except Exception as exc:
        warn(f"Loki query skipped for exfiltration: {exc}")
        loki_matches = -1
    if status == 200 and size > 1048576:
        return f"Large response observed ({size} bytes); LokiHits={loki_matches}", {"status": status, "size": size, "loki_hits": loki_matches}
    raise SuiteError(f"Exfiltration validation did not meet threshold (HTTP {status}, size={size})")


@scenario("scenario_07_svid_expiry")
def run_svid_expiry(start_ts: float) -> Tuple[str, Dict[str, object]]:
    if not ENABLE_DESTRUCTIVE:
        raise SkipScenario("Set ENABLE_DESTRUCTIVE=1 to allow deleting SPIRE agent pods")
    deleted = 0
    for context in (AWS_CONTEXT, OS_CONTEXT):
        pods = kubectl(context, "-n", SPIRE_NAMESPACE, "get", "pods", "-l", "app=spire-agent", "-o", "name").stdout.splitlines()
        if not pods:
            continue
        pod_name = pods[0].strip().split("/", 1)[-1]
        kubectl(context, "-n", SPIRE_NAMESPACE, "delete", "pod", pod_name, check=True)
        deleted += 1
    for context in (AWS_CONTEXT, OS_CONTEXT):
        try:
            kubectl(context, "-n", SPIRE_NAMESPACE, "rollout", "status", "daemonset/spire-agent", "--timeout=180s")
        except Exception as exc:
            raise SuiteError(f"SPIRE agent did not recover in {context}: {exc}")
    return f"Deleted {deleted} SPIRE agent pod(s) and confirmed recovery", {"deleted": deleted}


@scenario("scenario_08_cross_cloud")
def run_cross_cloud(start_ts: float, endpoints: Dict[str, str]) -> Tuple[str, Dict[str, object]]:
    url = f"{endpoints['os_core_banking']}/transactions/execute"
    payload = {
        "from_account": "A001",
        "to_account": "A002",
        "amount": 100000,
        "currency": "VND",
        "trace_id": "cross-cloud",
    }
    headers = {
        "X-Source-Cloud": "aws",
        "X-Source-SPIFFE-ID": "spiffe://ztlab.local/aws/payment-service",
        "X-Destination-SPIFFE-ID": "spiffe://ztlab.local/openstack/core-banking",
        "X-Fraud-Gate": "passed",
        "X-Fraud-Score": "10",
    }
    status, body, _ = json_request("POST", url, payload, headers=headers, timeout=15)
    if status in (401, 403):
        return f"Cross-cloud lateral movement blocked with HTTP {status}", {"status": status}
    raise SuiteError(f"Cross-cloud lateral movement was not blocked (HTTP {status}): {body[:200]}")


@scenario("scenario_09_privesc")
def run_privesc(start_ts: float, endpoints: Dict[str, str]) -> Tuple[str, Dict[str, object]]:
    pod_name = kubectl(AWS_CONTEXT, "-n", FINANCIAL_NAMESPACE, "get", "pod", "-l", "app=api-gateway", "-o", "jsonpath={.items[0].metadata.name}").stdout.strip()
    if not pod_name:
        raise SuiteError("Cannot find api-gateway pod for privesc check")
    proc = run(
        [
            "kubectl",
            "--context",
            AWS_CONTEXT,
            "-n",
            FINANCIAL_NAMESPACE,
            "exec",
            pod_name,
            "--",
            "sh",
            "-lc",
            "id && (sudo -n /bin/bash -lc id)",
        ],
        check=False,
        capture=True,
    )
    if proc.returncode != 0:
        return f"Privilege escalation blocked in pod {pod_name}", {"returncode": proc.returncode}
    raise SuiteError(f"Privilege escalation unexpectedly succeeded in pod {pod_name}")


@scenario("scenario_10_portscan")
def run_portscan(start_ts: float) -> Tuple[str, Dict[str, object]]:
    ips = read_inventory_ips()
    targets = {"aws_gateway": ips.get("aws_gateway", "127.0.0.1"), "os_gateway": ips.get("os_gateway", "127.0.0.1")}
    ports = [22, 80, 443, 51820, 6443, 8080, 3100]
    results: Dict[str, List[int]] = {}
    for host, ip in targets.items():
        open_ports = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        results[host] = open_ports
    return f"Port scan completed: {results}", {"results": results}


@scenario("scenario_11_cryptomining")
def run_cryptomining(start_ts: float) -> Tuple[str, Dict[str, object]]:
    name = "crypto-burner"
    manifest = textwrap.dedent(
        f"""
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: {name}
          namespace: {FINANCIAL_NAMESPACE}
          labels:
            app: {name}
        spec:
          replicas: 1
          selector:
            matchLabels:
              app: {name}
          template:
            metadata:
              labels:
                app: {name}
            spec:
              containers:
                - name: burner
                  image: ztlab/api-gateway:{IMAGE_TAG}
                  imagePullPolicy: IfNotPresent
                  command: ["sh", "-c", "while true; do :; done"]
                  resources:
                    requests:
                      cpu: "250m"
                      memory: "64Mi"
                    limits:
                      cpu: "1000m"
                      memory: "128Mi"
        """
    ).strip() + "\n"
    apply_proc = run(
        ["kubectl", "--context", AWS_CONTEXT, "apply", "-f", "-"],
        check=True,
        capture=True,
        input_data=manifest,
    )
    time.sleep(10)
    top = run(["kubectl", "--context", AWS_CONTEXT, "top", "pods", "-n", FINANCIAL_NAMESPACE, "--no-headers"], check=False, capture=True)
    delete_proc = run(["kubectl", "--context", AWS_CONTEXT, "-n", FINANCIAL_NAMESPACE, "delete", "deployment", name, "--ignore-not-found"], check=False, capture=True)
    if top.returncode == 0 and name in top.stdout:
        return f"Cryptomining-style CPU burner started and measured", {"kubectl_top": top.stdout.strip()}
    raise SuiteError(f"Could not observe CPU spike for {name}; top output: {top.stdout.strip()} {top.stderr.strip()}")


def wait_for_expected_health(endpoints: Dict[str, str]) -> None:
    checks = [
        ("Keycloak", f"{endpoints['keycloak']}/realms/master"),
        ("AWS api-gateway", f"{endpoints['aws_api_gateway']}/health"),
        ("AWS payment-service", f"{endpoints['aws_payment']}/health"),
        ("AWS fraud-detection", f"{endpoints['aws_fraud']}/health"),
        ("OS core-banking", f"{endpoints['os_core_banking']}/health"),
        ("OS account-service", f"{endpoints['os_account']}/health"),
        ("OS transaction-service", f"{endpoints['os_txn']}/health"),
    ]
    for label, url in checks:
        status, body, _ = http_request("GET", url, timeout=20)
        if status != 200:
            raise SuiteError(f"Health check failed for {label}: HTTP {status} - {body[:200]}")
        log(f"Health ok: {label}")


def ensure_port_forwards() -> Dict[str, str]:
    endpoints = {}
    for name, (context, namespace, resource, remote_port) in SERVICES.items():
        local_port = PORTS[name]
        start_port_forward(name, context, namespace, resource, local_port, remote_port)
        endpoints[name] = f"http://127.0.0.1:{local_port}"
    return endpoints


def baseline_and_seed(endpoints: Dict[str, str]) -> None:
    admin_password = keycloak_admin_password()
    admin_token = get_keycloak_admin_token(endpoints["keycloak"], admin_password)
    try:
        create_test_user(endpoints["keycloak"], admin_token, "testuser01", "Test@1234")
    except Exception as exc:
        warn(f"Keycloak test user setup skipped: {exc}")

    baseline_traffic(endpoints["keycloak"], endpoints, DEFAULT_BASELINE_SECONDS)


def run_all(endpoints: Dict[str, str]) -> None:
    admin_password = keycloak_admin_password()

    scenario_01 = run_brute_force(endpoints["keycloak"], admin_password)
    # run_brute_force is decorated; call through the wrapper below for consistent result handling.


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the full ZTLab scenario suite.")
    parser.add_argument("--baseline-seconds", type=int, default=DEFAULT_BASELINE_SECONDS)
    parser.add_argument("--skip-baseline", action="store_true")
    parser.add_argument("--skip-privesc", action="store_true")
    parser.add_argument("--skip-cryptomining", action="store_true")
    parser.add_argument("--skip-portscan", action="store_true")
    args = parser.parse_args()

    ensure_command("kubectl")
    ensure_command("python3")
    register_cleanup()

    baseline_seconds = args.baseline_seconds

    log("Starting port-forwards")
    endpoints = ensure_port_forwards()

    log("Validating health endpoints")
    wait_for_expected_health(endpoints)

    log("Seeding baseline data")
    admin_password = keycloak_admin_password()
    try:
        admin_token = get_keycloak_admin_token(endpoints["keycloak"], admin_password)
        create_test_user(endpoints["keycloak"], admin_token, "testuser01", "Test@1234")
    except Exception as exc:
        warn(f"Could not create Keycloak test user, continuing without it: {exc}")

    if not args.skip_baseline:
        baseline_traffic(endpoints["keycloak"], endpoints, baseline_seconds)
    else:
        warn("Baseline warm-up skipped")

    # Run scenarios in implementation order.
    run_brute_force(endpoints["keycloak"], admin_password)
    try:
        run_jwt_forgery(endpoints)
    except Exception as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_02_jwt_forgery", status="FAIL", details=str(exc)))
        fail(f"scenario_02_jwt_forgery: FAIL - {exc}")
    try:
        run_lateral_movement(endpoints)
    except Exception as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_03_lateral_movement", status="FAIL", details=str(exc)))
        fail(f"scenario_03_lateral_movement: FAIL - {exc}")
    run_fraud_gate_bypass(endpoints)
    try:
        run_high_velocity(endpoints)
    except Exception as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_05_high_velocity", status="FAIL", details=str(exc)))
        fail(f"scenario_05_high_velocity: FAIL - {exc}")
    try:
        run_exfiltration()
    except SkipScenario as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_06_exfiltration", status="SKIP", details=str(exc)))
        warn(f"scenario_06_exfiltration: SKIP - {exc}")
    except Exception as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_06_exfiltration", status="FAIL", details=str(exc)))
        fail(f"scenario_06_exfiltration: FAIL - {exc}")
    try:
        if args.skip_privesc:
            raise SkipScenario("Skipped by flag")
        run_svid_expiry()
    except SkipScenario as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_07_svid_expiry", status="SKIP", details=str(exc)))
        warn(f"scenario_07_svid_expiry: SKIP - {exc}")
    except Exception as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_07_svid_expiry", status="FAIL", details=str(exc)))
        fail(f"scenario_07_svid_expiry: FAIL - {exc}")
    try:
        run_cross_cloud(endpoints)
    except Exception as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_08_cross_cloud", status="FAIL", details=str(exc)))
        fail(f"scenario_08_cross_cloud: FAIL - {exc}")
    try:
        if args.skip_privesc:
            raise SkipScenario("Skipped by flag")
        run_privesc(endpoints)
    except SkipScenario as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_09_privesc", status="SKIP", details=str(exc)))
        warn(f"scenario_09_privesc: SKIP - {exc}")
    except Exception as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_09_privesc", status="FAIL", details=str(exc)))
        fail(f"scenario_09_privesc: FAIL - {exc}")
    try:
        if args.skip_portscan:
            raise SkipScenario("Skipped by flag")
        run_portscan()
    except SkipScenario as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_10_portscan", status="SKIP", details=str(exc)))
        warn(f"scenario_10_portscan: SKIP - {exc}")
    except Exception as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_10_portscan", status="FAIL", details=str(exc)))
        fail(f"scenario_10_portscan: FAIL - {exc}")
    try:
        if args.skip_cryptomining:
            raise SkipScenario("Skipped by flag")
        run_cryptomining()
    except SkipScenario as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_11_cryptomining", status="SKIP", details=str(exc)))
        warn(f"scenario_11_cryptomining: SKIP - {exc}")
    except Exception as exc:
        SCENARIO_RESULTS.append(ScenarioResult(name="scenario_11_cryptomining", status="FAIL", details=str(exc)))
        fail(f"scenario_11_cryptomining: FAIL - {exc}")

    print("\n=== SUMMARY ===")
    failed = 0
    for result in SCENARIO_RESULTS:
        print(f"{result.name}: {result.status} - {result.details}")
        if result.metrics:
            print(f"  metrics: {json.dumps(result.metrics, sort_keys=True)}")
        if result.status == "FAIL":
            failed += 1

    if failed:
        print(f"\nSuite completed with {failed} failure(s).", file=sys.stderr)
        return 1

    print("\nSuite completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
