#!/usr/bin/env python3
"""ZTLab Performance Overhead Benchmark.

Measures the latency overhead introduced by the Zero Trust security pipeline:
  - Envoy sidecar TLS termination + mTLS
  - OPA policy evaluation (ext_authz gRPC)
  - Keycloak JWT verification

Methodology:
  1. Baseline  : N direct requests to a simple health endpoint (minimal security path)
  2. Auth path : N requests to a protected endpoint with full JWT + OPA evaluation
  3. Delta     : P50/P95/P99 overhead attributed to the security pipeline

Usage:
  python3 tests/perf_overhead.py [--n 100] [--output results/perf_overhead.json]

Environment variables:
  GW_URL    API Gateway base URL   (default: http://localhost:18080)
  KC_URL    Keycloak base URL      (default: http://localhost:8180)
  BENCH_N   Number of requests     (default: 50)
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

GW_URL  = os.environ.get("GW_URL",  "http://localhost:18080").rstrip("/")
KC_URL  = os.environ.get("KC_URL",  "http://localhost:8180").rstrip("/")
BENCH_N = int(os.environ.get("BENCH_N", "50"))

OUTPUT_PATH = Path(os.environ.get("PERF_OUTPUT", "results/perf_overhead.json"))


def _get(url: str, headers: dict | None = None, timeout: float = 10.0) -> tuple[int, float]:
    req = urllib.request.Request(url, headers=headers or {})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            return resp.status, time.perf_counter() - t0
    except urllib.error.HTTPError as exc:
        return exc.code, time.perf_counter() - t0
    except Exception:
        return 0, time.perf_counter() - t0


KC_ADMIN_PASS = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "ztlab-admin-2026")
_api_gateway_secret_cache: str = ""


def _api_gateway_client_secret() -> str:
    # web-portal client has directAccessGrantsEnabled=false (Zero Trust hardening —
    # browser PKCE flow only), so scripted token grants must use api-gateway instead,
    # which requires its client secret fetched via the Keycloak admin API.
    global _api_gateway_secret_cache
    if _api_gateway_secret_cache:
        return _api_gateway_secret_cache
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": "admin",
        "password": KC_ADMIN_PASS,
    }).encode()
    req = urllib.request.Request(
        f"{KC_URL}/realms/master/protocol/openid-connect/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            admin_token = json.loads(resp.read()).get("access_token", "")
        if not admin_token:
            return ""
        req = urllib.request.Request(
            f"{KC_URL}/admin/realms/ztlab/clients?clientId=api-gateway",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            clients = json.loads(resp.read())
        _api_gateway_secret_cache = clients[0]["secret"] if clients else ""
    except Exception:
        return ""
    return _api_gateway_secret_cache


def _keycloak_token() -> str:
    secret = _api_gateway_client_secret()
    if not secret:
        return ""
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "api-gateway",
        "client_secret": secret,
        "username": "testuser01",
        "password": "Test1234!",
    }).encode()
    req = urllib.request.Request(
        f"{KC_URL}/realms/ztlab/protocol/openid-connect/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read()).get("access_token", "")
    except Exception:
        return ""


def percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(sorted_data) - 1)
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (k - lo)


def run_benchmark(label: str, url: str, headers: dict | None, n: int) -> dict:
    latencies: list[float] = []
    errors = 0
    print(f"  [{label}] {n} requests to {url}")
    for i in range(n):
        code, elapsed = _get(url, headers)
        if code in (200, 401, 403):
            latencies.append(elapsed * 1000)  # ms
        else:
            errors += 1
        if (i + 1) % 10 == 0:
            print(f"    ... {i+1}/{n} done", end="\r")
        time.sleep(0.01)  # avoid self-DoS
    print()
    if not latencies:
        return {"error": "no successful responses", "errors": errors}
    return {
        "n": len(latencies),
        "errors": errors,
        "p50_ms":  round(percentile(latencies, 50), 2),
        "p95_ms":  round(percentile(latencies, 95), 2),
        "p99_ms":  round(percentile(latencies, 99), 2),
        "mean_ms": round(statistics.mean(latencies), 2),
        "min_ms":  round(min(latencies), 2),
        "max_ms":  round(max(latencies), 2),
        "stdev_ms": round(statistics.stdev(latencies), 2) if len(latencies) > 1 else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="ZTLab perf overhead benchmark")
    parser.add_argument("--n", type=int, default=BENCH_N, help="requests per scenario")
    parser.add_argument("--output", default=str(OUTPUT_PATH), help="JSON output path")
    args = parser.parse_args()
    n = args.n
    output = Path(args.output)

    print("ZTLab Performance Overhead Benchmark")
    print(f"  GW_URL : {GW_URL}")
    print(f"  KC_URL : {KC_URL}")
    print(f"  N      : {n} requests per scenario")
    print()

    # Verify gateway is reachable
    code, _ = _get(f"{GW_URL}/health")
    if code == 0:
        print(f"ERROR: API Gateway unreachable at {GW_URL}", file=sys.stderr)
        return 1

    results: dict = {
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_per_scenario": n,
    }

    # 1. Baseline: health endpoint — just Envoy passthrough, no JWT/OPA
    print("[1/4] Baseline — health endpoint (Envoy passthrough only)")
    results["baseline"] = run_benchmark("baseline", f"{GW_URL}/health", None, n)

    # 2. No-auth request to protected endpoint — hits OPA → expect 401/403
    print("[2/4] OPA-only overhead — protected endpoint, no JWT")
    results["opa_only"] = run_benchmark("opa_only", f"{GW_URL}/accounts/ACC-1001", None, n)

    # 3. Full auth path — JWT + Envoy mTLS + OPA
    print("[3/4] Full auth path — JWT + Envoy mTLS + OPA")
    token = _keycloak_token()
    if token:
        headers = {"Authorization": f"Bearer {token}"}
        results["full_auth"] = run_benchmark("full_auth", f"{GW_URL}/accounts/ACC-1001", headers, n)
    else:
        print("  WARNING: Keycloak unavailable, skipping full-auth benchmark")
        results["full_auth"] = {"note": "skipped — Keycloak unavailable"}

    # 4. Keycloak token issuance latency
    print("[4/4] Keycloak token issuance latency")
    kc_latencies: list[float] = []
    for _ in range(min(n, 20)):
        t0 = time.perf_counter()
        tok = _keycloak_token()
        elapsed = (time.perf_counter() - t0) * 1000
        if tok:
            kc_latencies.append(elapsed)
        time.sleep(0.05)
    if kc_latencies:
        results["keycloak_token_issuance"] = {
            "n": len(kc_latencies),
            "p50_ms":  round(percentile(kc_latencies, 50), 2),
            "p95_ms":  round(percentile(kc_latencies, 95), 2),
            "mean_ms": round(statistics.mean(kc_latencies), 2),
        }
    else:
        results["keycloak_token_issuance"] = {"note": "skipped — Keycloak unavailable"}

    # Compute overhead delta
    baseline = results["baseline"]
    full_auth = results["full_auth"]
    if "p50_ms" in baseline and "p50_ms" in full_auth:
        results["overhead_delta"] = {
            "p50_ms":  round(full_auth["p50_ms"]  - baseline["p50_ms"],  2),
            "p95_ms":  round(full_auth["p95_ms"]  - baseline["p95_ms"],  2),
            "p99_ms":  round(full_auth["p99_ms"]  - baseline["p99_ms"],  2),
            "mean_ms": round(full_auth["mean_ms"] - baseline["mean_ms"], 2),
            "overhead_pct_p50": round(
                (full_auth["p50_ms"] - baseline["p50_ms"]) / full_auth["p50_ms"] * 100, 1
            ) if full_auth["p50_ms"] > 0 else 0.0,
        }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to {output}")

    # Summary table
    print("\n=== PERFORMANCE OVERHEAD SUMMARY ===")
    b = results.get("baseline", {})
    o = results.get("opa_only", {})
    f = results.get("full_auth", {})
    d = results.get("overhead_delta", {})

    def row(label: str, data: dict) -> None:
        if "p50_ms" in data:
            print(f"  {label:<30} P50={data['p50_ms']:>7.1f}ms  P95={data['p95_ms']:>7.1f}ms  P99={data.get('p99_ms',0):>7.1f}ms  mean={data['mean_ms']:>7.1f}ms")
        elif "note" in data:
            print(f"  {label:<30} {data['note']}")

    row("Baseline (health only)",     b)
    row("OPA-only (no JWT)",          o)
    row("Full ZT (JWT+Envoy+OPA)",    f)
    if d:
        print(f"  {'Security overhead (delta)':<30} P50=+{d['p50_ms']:>6.1f}ms  P95=+{d['p95_ms']:>6.1f}ms  ({d.get('overhead_pct_p50',0):.1f}% of request)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
