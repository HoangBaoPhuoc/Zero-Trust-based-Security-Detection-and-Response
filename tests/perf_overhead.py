#!/usr/bin/env python3
"""ZTLab Performance Overhead Benchmark — crAPI (Phần 3.3, remediation 2026-09).

Trước bản sửa này script này trỏ tới `api-gateway`/ns `financial` của app cũ
(chưa từng chạy được với crAPI). Sửa lại cho đúng kiến trúc hiện tại: điểm
vào DUY NHẤT là Istio IngressGateway + client-cert mТLS
(scripts/issue-device-cert.sh, tests/lib/crapi_common.sh), phiên đăng nhập là
cookie BFF (không phải Bearer token trực tiếp như api-gateway cũ) — login
thật qua `tests/lib/crapi_common.sh::crapi_login` (subprocess bash, tái dùng
logic OIDC/PKCE đã có thay vì viết lại bằng Python).

CHỈ LÀ CÔNG CỤ ĐO (không phải Giai đoạn B/B4) — đo kiểu health-vs-protected
đơn giản để có SỐ THẬT lần đầu tiên; KHÔNG tách overhead Zero-Trust khỏi độ
trễ cross-cloud (đó là B4 thật, có nhóm test-only riêng, ngoài phạm vi lần
sửa này).

Usage:
  python3 tests/perf_overhead.py [--n 50] [--output results/perf_overhead.json]

Environment variables:
  BFF_URL   Gateway/BFF base URL (default: https://crapi.ztlab.local:18444,
            giống tests/lib/crapi_common.sh — cần scripts/open-admin-uis.sh
            và Device CA client cert test-compliant đã issue).
  BENCH_N   Number of requests (default: 50)
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CA_DIR = REPO_ROOT / "deploy" / "vendor" / "device-ca"
CRAPI_HOST = os.environ.get("CRAPI_HOST", "crapi.ztlab.local")
BFF_URL = os.environ.get("BFF_URL", f"https://{CRAPI_HOST}:18444").rstrip("/")
BENCH_N = int(os.environ.get("BENCH_N", "50"))
OUTPUT_PATH = Path(os.environ.get("PERF_OUTPUT", "results/perf_overhead.json"))

CLIENT_CERT = CA_DIR / "issued" / "test-compliant" / "device.crt"
CLIENT_KEY = CA_DIR / "issued" / "test-compliant" / "device.key"
CA_CERT = CA_DIR / "device-ca.crt"


def _tls_args() -> list[str]:
    return [
        "--cacert", str(CA_CERT), "--cert", str(CLIENT_CERT), "--key", str(CLIENT_KEY),
        "--resolve", f"{CRAPI_HOST}:{BFF_URL.rsplit(':', 1)[-1]}:127.0.0.1",
    ]


def _curl(url: str, cookie_jar: str | None = None, timeout: float = 10.0) -> tuple[int, float]:
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", str(timeout), *_tls_args()]
    if cookie_jar:
        cmd += ["-b", cookie_jar]
    cmd.append(url)
    t0 = time.perf_counter()
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        elapsed = time.perf_counter() - t0
        code = int(out.stdout.strip() or "0")
        return code, elapsed
    except Exception:
        return 0, time.perf_counter() - t0


def _crapi_login() -> str | None:
    """Đăng nhập thật qua BFF OIDC/PKCE (tests/lib/crapi_common.sh::crapi_login),
    trả về đường dẫn cookie-jar hoặc None nếu Keycloak không tới được."""
    script = f'source "{REPO_ROOT}/tests/lib/crapi_common.sh"; crapi_login testuser01 "Test1234!"'
    try:
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        jar = out.stdout.strip()
        if out.returncode == 0 and jar and Path(jar).exists():
            return jar
    except Exception:
        pass
    return None


def percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(sorted_data) - 1)
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (k - lo)


def run_benchmark(label: str, url: str, cookie_jar: str | None, n: int) -> dict:
    latencies: list[float] = []
    errors = 0
    print(f"  [{label}] {n} requests to {url}")
    for i in range(n):
        code, elapsed = _curl(url, cookie_jar)
        if code in (200, 401, 403):
            latencies.append(elapsed * 1000)  # ms
        else:
            errors += 1
        if (i + 1) % 10 == 0:
            print(f"    ... {i + 1}/{n} done", end="\r")
        time.sleep(0.01)  # avoid self-DoS
    print()
    if not latencies:
        return {"error": "no successful responses", "errors": errors}
    return {
        "n": len(latencies),
        "errors": errors,
        "p50_ms": round(percentile(latencies, 50), 2),
        "p95_ms": round(percentile(latencies, 95), 2),
        "p99_ms": round(percentile(latencies, 99), 2),
        "mean_ms": round(statistics.mean(latencies), 2),
        "min_ms": round(min(latencies), 2),
        "max_ms": round(max(latencies), 2),
        "stdev_ms": round(statistics.stdev(latencies), 2) if len(latencies) > 1 else 0.0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="ZTLab perf overhead benchmark (crAPI)")
    parser.add_argument("--n", type=int, default=BENCH_N, help="requests per scenario")
    parser.add_argument("--output", default=str(OUTPUT_PATH), help="JSON output path")
    args = parser.parse_args()
    n = args.n
    output = Path(args.output)

    print("ZTLab Performance Overhead Benchmark (crAPI)")
    print(f"  BFF_URL : {BFF_URL}")
    print(f"  N       : {n} requests per scenario")
    print()

    code, _ = _curl(f"{BFF_URL}/health")
    if code == 0:
        print(f"ERROR: Gateway/BFF unreachable at {BFF_URL} — chạy scripts/open-admin-uis.sh trước", file=sys.stderr)
        return 1

    results: dict = {
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_per_scenario": n,
        "methodology_note": (
            "Mỗi request là 1 tiến trình curl mới (TLS handshake mới hoàn toàn, "
            "không reuse connection) — số đo bị chi phối bởi chi phí fork+TLS "
            "handshake per-request, KHÔNG phải overhead Zero-Trust thuần. Đây là "
            "công cụ đo lần đầu (Phần 3.3), không phải phép đo B4 thật (tách "
            "overhead mТLS+OPA khỏi độ trễ cross-cloud bằng keep-alive/connection "
            "pooling) — B4 thuộc Giai đoạn B, ngoài phạm vi lần sửa này."
        ),
    }

    print("[1/3] Baseline — /health (public_path, không qua RBAC/JWT)")
    results["baseline"] = run_benchmark("baseline", f"{BFF_URL}/health", None, n)

    print("[2/3] BFF-only overhead — protected endpoint, KHÔNG có session (401 tại BFF)")
    results["no_session"] = run_benchmark("no_session", f"{BFF_URL}/workshop/api/shop/products", None, n)

    print("[3/3] Full auth path — session thật (Keycloak OIDC + mТLS + OPA)")
    cookie_jar = _crapi_login()
    if cookie_jar:
        results["full_auth"] = run_benchmark(
            "full_auth", f"{BFF_URL}/workshop/api/shop/products", cookie_jar, n)
        Path(cookie_jar).unlink(missing_ok=True)
    else:
        print("  WARNING: Keycloak/BFF login không thành công, bỏ qua full-auth benchmark")
        results["full_auth"] = {"note": "skipped — Keycloak/BFF login unavailable"}

    baseline = results["baseline"]
    full_auth = results["full_auth"]
    if "p50_ms" in baseline and "p50_ms" in full_auth:
        results["overhead_delta"] = {
            "p50_ms": round(full_auth["p50_ms"] - baseline["p50_ms"], 2),
            "p95_ms": round(full_auth["p95_ms"] - baseline["p95_ms"], 2),
            "p99_ms": round(full_auth["p99_ms"] - baseline["p99_ms"], 2),
            "mean_ms": round(full_auth["mean_ms"] - baseline["mean_ms"], 2),
            "overhead_pct_p50": round(
                (full_auth["p50_ms"] - baseline["p50_ms"]) / full_auth["p50_ms"] * 100, 1
            ) if full_auth["p50_ms"] > 0 else 0.0,
        }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to {output}")

    print("\n=== PERFORMANCE OVERHEAD SUMMARY (crAPI) ===")
    b = results.get("baseline", {})
    ns = results.get("no_session", {})
    f = results.get("full_auth", {})
    d = results.get("overhead_delta", {})

    def row(label: str, data: dict) -> None:
        if "p50_ms" in data:
            print(f"  {label:<32} P50={data['p50_ms']:>7.1f}ms  P95={data['p95_ms']:>7.1f}ms  P99={data.get('p99_ms', 0):>7.1f}ms  mean={data['mean_ms']:>7.1f}ms")
        elif "note" in data:
            print(f"  {label:<32} {data['note']}")

    row("Baseline (health only)", b)
    row("BFF-only (no session, 401)", ns)
    row("Full ZT (session+mTLS+OPA)", f)
    if d:
        print(f"  {'Security overhead (delta)':<32} P50=+{d['p50_ms']:>6.1f}ms  P95=+{d['p95_ms']:>6.1f}ms  ({d.get('overhead_pct_p50', 0):.1f}% of request)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
