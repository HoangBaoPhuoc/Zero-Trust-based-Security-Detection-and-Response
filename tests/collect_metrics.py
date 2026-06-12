#!/usr/bin/env python3
"""ZTLab Security Metrics Collector.

Measures four key security performance indicators:
  MTTD  — Mean Time To Detect     (seconds from attack log injection to AI verdict)
  MTTR  — Mean Time To Respond    (seconds from AI verdict to SOAR playbook execution)
  FPR   — False Positive Rate     (benign logs flagged malicious / total benign logs)
  FNR   — False Negative Rate     (attack logs not detected / total attack logs)
  OVH   — Security Overhead       (extra latency introduced by Envoy+OPA mTLS pipeline)

Usage:
  python3 tests/collect_metrics.py [--output results/metrics.json]

Environment variables:
  GW_URL    API Gateway base URL       (default: http://localhost:18080)
  KC_URL    Keycloak base URL          (default: http://localhost:18443)
  AI_URL    AI Analyzer base URL       (default: http://localhost:18082)
  SOAR_URL  SOAR Engine base URL       (default: http://localhost:18091)
  LOKI_URL  Loki base URL              (default: http://localhost:13100)
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

GW_URL   = os.environ.get("GW_URL",   "http://localhost:18080").rstrip("/")
KC_URL   = os.environ.get("KC_URL",   "http://localhost:18443").rstrip("/")
AI_URL   = os.environ.get("AI_URL",   "http://localhost:18082").rstrip("/")
SOAR_URL = os.environ.get("SOAR_URL", "http://localhost:18091").rstrip("/")
LOKI_URL = os.environ.get("LOKI_URL", "http://localhost:13100").rstrip("/")

OUTPUT_PATH = Path(os.environ.get("METRICS_OUTPUT", "results/metrics.json"))


# ── helpers ──────────────────────────────────────────────────────────────────

def _post(url: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _keycloak_token(username: str = "testuser01", password: str = "Test1234!") -> str:
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "web-portal",
        "username": username,
        "password": password,
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


def _inject_attack_log(source: str, message: str) -> tuple[float, dict]:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t0 = time.time()
    result = _post(f"{AI_URL}/analyze", {
        "source": source,
        "logs": [{
            "timestamp": ts,
            "message": message,
            "labels": {"namespace": "financial", "app": "api-gateway", "job": "kubernetes-pods"},
        }],
    })
    elapsed = time.time() - t0
    return elapsed, result


# ── MTTD ─────────────────────────────────────────────────────────────────────

ATTACK_PROBES = [
    ("mttd_brute_force",
     "login_failed invalid_credentials attempt=21 username=admin source_ip=10.9.8.1"),
    ("mttd_lateral_movement",
     "lateral_movement invalid_svid spiffe://ztlab.local/ns/financial/sa/wrong source denied"),
    ("mttd_port_scan",
     "port scan nmap detected syn scan source_ip=10.9.8.99 ports_tried=1024"),
    ("mttd_fraud_bypass",
     "fraud_gate_bypass payment_blocked score=85 source_ip=10.9.8.50 amount=800000000"),
    ("mttd_exfiltration",
     "bytes_sent=8388608 path=/accounts/ACC-1001/history method=GET source_ip=10.9.8.77"),
]


def measure_mttd() -> dict:
    print("  [MTTD] injecting attack logs and timing AI detection...")
    times: list[float] = []
    detected = 0
    for source, msg in ATTACK_PROBES:
        elapsed, result = _inject_attack_log(source, msg)
        verdict = result.get("verdict", "clean")
        if verdict in ("malicious", "suspicious"):
            times.append(elapsed)
            detected += 1
        else:
            print(f"    WARNING: {source} not detected (verdict={verdict})")
    if not times:
        return {"error": "no attacks detected", "detected": 0, "total": len(ATTACK_PROBES)}
    return {
        "detected": detected,
        "total": len(ATTACK_PROBES),
        "mean_seconds": round(statistics.mean(times), 3),
        "median_seconds": round(statistics.median(times), 3),
        "min_seconds": round(min(times), 3),
        "max_seconds": round(max(times), 3),
    }


# ── MTTR ─────────────────────────────────────────────────────────────────────

def measure_mttr() -> dict:
    print("  [MTTR] checking SOAR pending→approval→execution cycle...")
    # Inject a high-severity attack to create a pending alert
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t_inject = time.time()
    result = _post(f"{AI_URL}/analyze", {
        "source": "mttr_probe",
        "logs": [{
            "timestamp": ts,
            "message": "critical lateral_movement invalid_svid spiffe://ztlab.local/ns/financial/sa/attacker blocked privilege escalation cap_sys_admin",
            "labels": {"namespace": "financial", "app": "api-gateway", "job": "kubernetes-pods"},
        }],
    })

    severity = result.get("severity", "")
    alert_id = result.get("alert_id", "")

    if not alert_id:
        # Check latest pending alert
        try:
            pending_list = _get(f"{AI_URL}/pending")
            if pending_list:
                alert_id = pending_list[0].get("alert_id", "")
        except Exception:
            pass

    if not alert_id:
        return {
            "note": "no pending alert created (severity may be below threshold or SOAR in dry-run)",
            "inject_to_verdict_seconds": round(time.time() - t_inject, 3),
        }

    t_pending = time.time()
    # Simulate admin approval
    try:
        approved = _post(f"{AI_URL}/pending/{alert_id}/approve", {"note": "mttr measurement"})
        t_approved = time.time()
        status = approved.get("status", "unknown")
        return {
            "alert_id": alert_id,
            "severity": severity,
            "inject_to_pending_seconds": round(t_pending - t_inject, 3),
            "pending_to_approved_seconds": round(t_approved - t_pending, 3),
            "inject_to_approved_seconds": round(t_approved - t_inject, 3),
            "final_status": status,
        }
    except Exception as exc:
        return {
            "alert_id": alert_id,
            "error": str(exc),
            "inject_to_pending_seconds": round(t_pending - t_inject, 3),
        }


# ── FPR / FNR ─────────────────────────────────────────────────────────────────

BENIGN_LOGS = [
    "payment processed amount=50000 from=ACC-1001 to=ACC-2001 status=ok",
    "health check GET /health 200 duration_ms=2",
    "jwt_verified user=testuser01 exp_in=3540s",
    "opa_allow path=/payments method=POST spiffe=payment-service",
    "transaction committed txn_id=TXN-9999 duration_ms=50",
    "prometheus_scrape /metrics 200 15k",
    "liveness_probe GET /health 200",
    "spire_svid_renewed ttl=3600 workload=core-banking",
]

ATTACK_LOGS = [
    ("attack_01", "login_failed attempt=25 username=admin brute_force source_ip=10.0.0.1"),
    ("attack_02", "fraud_gate_bypass score=90 amount=999000000 channel=tor"),
    ("attack_03", "lateral_movement invalid_svid denied spiffe://bad/path"),
    ("attack_04", "port scan nmap syn scan source_ip=10.9.8.2 ports=65535"),
    ("attack_05", "privilege escalation setuid /bin/sh cap_sys_admin"),
    ("attack_06", "bytes_sent=16777216 data_exfiltration path=/accounts/export"),
    ("attack_07", "xmrig cryptomining cpu=98% stratum+tcp://pool.example.com"),
    ("attack_08", "sqlmap union select * from accounts where 1=1 --"),
]


def measure_fpr_fnr() -> dict:
    print("  [FPR/FNR] testing detection accuracy on benign and attack samples...")
    false_positives = 0
    for msg in BENIGN_LOGS:
        try:
            _, result = _inject_attack_log("fpr_test", msg)
            if result.get("verdict") in ("malicious", "suspicious"):
                false_positives += 1
                print(f"    FP: benign log flagged: {msg[:60]}")
        except Exception:
            pass

    true_positives = 0
    false_negatives = 0
    for source, msg in ATTACK_LOGS:
        try:
            _, result = _inject_attack_log(source, msg)
            if result.get("verdict") in ("malicious", "suspicious"):
                true_positives += 1
            else:
                false_negatives += 1
                print(f"    FN: attack not detected: {msg[:60]}")
        except Exception:
            false_negatives += 1

    total_benign = len(BENIGN_LOGS)
    total_attack = len(ATTACK_LOGS)
    fpr = round(false_positives / total_benign, 4) if total_benign else 0.0
    fnr = round(false_negatives / total_attack, 4) if total_attack else 0.0

    return {
        "benign_tested": total_benign,
        "attack_tested": total_attack,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_positives": true_positives,
        "fpr": fpr,
        "fnr": fnr,
        "precision": round(true_positives / (true_positives + false_positives), 4) if (true_positives + false_positives) > 0 else 1.0,
        "recall": round(true_positives / total_attack, 4) if total_attack else 0.0,
    }


# ── Security Overhead ─────────────────────────────────────────────────────────

def measure_security_overhead() -> dict:
    print("  [OVH] measuring latency contribution of security pipeline...")
    token = _keycloak_token()
    if not token:
        return {"note": "Keycloak unavailable, skipping overhead measurement"}

    headers_with_auth = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    samples_auth: list[float] = []
    samples_noauth: list[float] = []

    # Authenticated path (goes through Envoy mTLS + OPA + JWT verification)
    for _ in range(10):
        req = urllib.request.Request(f"{GW_URL}/accounts/ACC-1001", headers=headers_with_auth)
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=5) as _:
                pass
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass
        samples_auth.append(time.time() - t0)
        time.sleep(0.05)

    # Health endpoint (minimal security path)
    for _ in range(10):
        req = urllib.request.Request(f"{GW_URL}/health")
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=5) as _:
                pass
        except Exception:
            pass
        samples_noauth.append(time.time() - t0)
        time.sleep(0.05)

    if not samples_auth or not samples_noauth:
        return {"note": "no samples collected"}

    mean_auth    = statistics.mean(samples_auth)
    mean_noauth  = statistics.mean(samples_noauth)
    overhead_ms  = round((mean_auth - mean_noauth) * 1000, 2)

    return {
        "samples": 10,
        "auth_path_mean_ms":    round(mean_auth * 1000, 2),
        "health_path_mean_ms":  round(mean_noauth * 1000, 2),
        "security_overhead_ms": overhead_ms,
        "overhead_pct": round((mean_auth - mean_noauth) / mean_auth * 100, 1) if mean_auth > 0 else 0.0,
    }


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    print("ZTLab Security Metrics Collection")
    print(f"  GW_URL  : {GW_URL}")
    print(f"  AI_URL  : {AI_URL}")
    print()

    # Verify AI Analyzer is reachable
    try:
        _get(f"{AI_URL}/health")
    except Exception as exc:
        print(f"ERROR: AI Analyzer unreachable at {AI_URL}: {exc}", file=sys.stderr)
        return 1

    results: dict = {"collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    print("[1/4] MTTD — Mean Time To Detect")
    results["mttd"] = measure_mttd()
    print(f"      → {results['mttd']}\n")

    print("[2/4] MTTR — Mean Time To Respond")
    results["mttr"] = measure_mttr()
    print(f"      → {results['mttr']}\n")

    print("[3/4] FPR/FNR — Detection Accuracy")
    results["detection_accuracy"] = measure_fpr_fnr()
    print(f"      → {results['detection_accuracy']}\n")

    print("[4/4] Security Overhead — Latency Impact")
    results["security_overhead"] = measure_security_overhead()
    print(f"      → {results['security_overhead']}\n")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(results, indent=2))
    print(f"Results written to {OUTPUT_PATH}")

    # Print summary table
    print("\n=== METRICS SUMMARY ===")
    mttd = results["mttd"]
    if "mean_seconds" in mttd:
        print(f"  MTTD          : {mttd['mean_seconds']}s mean  ({mttd['detected']}/{mttd['total']} detected)")
    mttr = results["mttr"]
    if "inject_to_approved_seconds" in mttr:
        print(f"  MTTR          : {mttr['inject_to_approved_seconds']}s (inject→approve)")
    acc = results["detection_accuracy"]
    print(f"  FPR           : {acc.get('fpr', 'n/a')} ({acc.get('false_positives',0)}/{acc.get('benign_tested',0)} benign flagged)")
    print(f"  FNR           : {acc.get('fnr', 'n/a')} ({acc.get('false_negatives',0)}/{acc.get('attack_tested',0)} attacks missed)")
    print(f"  Precision     : {acc.get('precision', 'n/a')}")
    print(f"  Recall        : {acc.get('recall', 'n/a')}")
    ovh = results["security_overhead"]
    if "security_overhead_ms" in ovh:
        print(f"  Sec Overhead  : +{ovh['security_overhead_ms']}ms ({ovh['overhead_pct']}%)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
