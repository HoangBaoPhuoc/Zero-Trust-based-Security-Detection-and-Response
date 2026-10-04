#!/usr/bin/env python3
"""Nghiệm thu pipeline telemetry THÔNG THẬT từ đầu tới cuối (Phần 1.3, vòng cuối
2026-09-26) — không dừng ở "pod Running".

Kiểm (mỗi mục in PASS/FAIL kèm số thô, exit 1 nếu có FAIL):
  1. Loki ready + có log trong cửa sổ cho TỪNG job: envoy-access, opa-decisions,
     bff-audit, waf-audit (bắt buộc); kubernetes-pods, incident-analyzer (tham khảo).
  2. Log tới từ CẢ HAI cloud (label `cloud`) cho envoy-access và opa-decisions —
     chứng minh đường relay OpenStack -> Loki (AWS) thông.
  3. Prometheus: mọi active target `up` (đọc qua kubectl exec, không phụ thuộc
     port-forward).
  4. Grafana: cả 2 datasource (Loki, Prometheus) trả health OK qua API.
  5. Grafana alert rule: liệt kê state; có ÍT NHẤT 1 rule `firing` gắn với một
     kịch bản tấn công VÀ một evidence bundle của incident-analyzer trong cửa sổ
     (alert -> webhook -> bundle thật, không chỉ state).

Yêu cầu: tunnel (scripts/open-admin-uis.sh) đã bật: Loki :13100, Grafana :3000,
Incident Analyzer :8091. Chạy SAU khi đã chạy kịch bản tấn công (tests/crapi_run_all.sh).

Dùng: python3 tests/verify_telemetry_pipeline.py [--window-min 60] [--output results/round3/telemetry.json]
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
AWS = "ctx-aws"
LOKI = "http://localhost:13100"
GRAFANA = "http://localhost:3000"
ANALYZER = "http://localhost:8091"

RESULTS: list[dict] = []


def record(name: str, ok: bool, detail: str, required: bool = True) -> None:
    RESULTS.append({"check": name, "pass": ok, "required": required, "detail": detail})
    tag = "PASS" if ok else ("FAIL" if required else "INFO")
    print(f"[{tag}] {name}: {detail}")


def http_json(url: str, auth: tuple[str, str] | None = None, timeout: int = 15):
    req = urllib.request.Request(url)
    if auth:
        tok = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {tok}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def loki_count(query: str, window_min: int) -> dict[str, float]:
    """sum by (cloud) hoặc tổng — trả {label_value: count}."""
    q = f"sum by (cloud) (count_over_time({query}[{window_min}m]))"
    url = f"{LOKI}/loki/api/v1/query?" + urllib.parse.urlencode({"query": q})
    res = http_json(url)["data"]["result"]
    return {r["metric"].get("cloud", ""): float(r["value"][1]) for r in res}


def kubectl(*args: str) -> str:
    return subprocess.run(["kubectl", "--context", AWS, *args], capture_output=True,
                          text=True, timeout=60).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-min", type=int, default=60)
    ap.add_argument("--output", default="results/round3/telemetry.json")
    args = ap.parse_args()
    w = args.window_min

    # 1. Loki ready
    try:
        with urllib.request.urlopen(f"{LOKI}/ready", timeout=10) as r:
            record("loki_ready", r.read().decode().strip() == "ready", "GET /ready")
    except Exception as e:  # noqa: BLE001
        record("loki_ready", False, f"không gọi được Loki: {e}")
        return _finish(args)

    per_job: dict[str, dict[str, float]] = {}
    for job, required in [("envoy-access", True), ("opa-decisions", True), ("bff-audit", True),
                          ("waf-audit", True), ("kubernetes-pods", False), ("incident-analyzer", False)]:
        try:
            c = loki_count(f'{{job="{job}"}}', w)
        except Exception as e:  # noqa: BLE001
            record(f"loki_job_{job}", False, f"query lỗi: {e}", required)
            continue
        per_job[job] = c
        total = sum(c.values())
        record(f"loki_job_{job}", total > 0, f"{int(total)} dòng trong {w}m, theo cloud={ {k or '-': int(v) for k, v in c.items()} }", required)

    # 2. cả 2 cloud
    for job in ("envoy-access", "opa-decisions"):
        clouds = {k for k, v in per_job.get(job, {}).items() if v > 0 and k}
        record(f"loki_two_clouds_{job}", {"aws", "openstack"} <= clouds,
               f"cloud có log: {sorted(clouds)} (cần aws + openstack)")

    # 3. Prometheus targets (qua exec)
    try:
        out = kubectl("-n", "monitoring", "exec", "deploy/prometheus", "-c", "prometheus", "--",
                      "wget", "-qO-", "localhost:9090/api/v1/targets")
        targets = json.loads(out)["data"]["activeTargets"]
        bad = [f"{t['labels'].get('job')}:{t['health']}" for t in targets if t["health"] != "up"]
        record("prometheus_targets", not bad and len(targets) > 0,
               f"{len(targets)} target, không-up={bad or 'không có'}")
    except Exception as e:  # noqa: BLE001
        record("prometheus_targets", False, f"không đọc được targets: {e}")

    # 4. Grafana datasource health
    try:
        pw = base64.b64decode(kubectl("-n", "plg-stack", "get", "secret", "grafana-admin-secret",
                                      "-o", "jsonpath={.data.admin-password}")).decode()
        us = base64.b64decode(kubectl("-n", "plg-stack", "get", "secret", "grafana-admin-secret",
                                      "-o", "jsonpath={.data.admin-user}")).decode()
        auth = (us, pw)
        for ds in http_json(f"{GRAFANA}/api/datasources", auth):
            h = http_json(f"{GRAFANA}/api/datasources/uid/{ds['uid']}/health", auth)
            record(f"grafana_datasource_{ds['name']}", h.get("status") == "OK", f"{h.get('status')}: {str(h.get('message'))[:80]}")
        # 5. rule states
        rules = http_json(f"{GRAFANA}/api/prometheus/grafana/api/v1/rules", auth)["data"]["groups"]
        states = {r["name"]: r["state"] for g in rules for r in g["rules"]}
        for n, s in sorted(states.items()):
            print(f"       rule: {s:9} {n}")
        firing = [n for n, s in states.items() if s == "firing"]
        bundles = http_json(f"{ANALYZER}/evidence")
        cutoff = time.time() - w * 60
        recent = [b for b in bundles if _ts(b["ts"]) >= cutoff]
        types = sorted({b["attack_type"] for b in recent})
        record("alert_firing_and_bundle", bool(firing) and bool(recent),
               f"{len(firing)} rule firing; {len(recent)} evidence bundle trong {w}m, attack_type={types}")
    except Exception as e:  # noqa: BLE001
        record("grafana_alerts", False, f"lỗi: {e}")

    return _finish(args)


def _ts(s: str) -> float:
    from datetime import datetime
    return datetime.fromisoformat(s).timestamp()


def _finish(args) -> int:
    failed = [r for r in RESULTS if r["required"] and not r["pass"]]
    out = REPO_ROOT / args.output
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"generated": time.strftime("%FT%TZ", time.gmtime()),
                               "window_min": args.window_min, "results": RESULTS,
                               "failed": [r["check"] for r in failed]}, ensure_ascii=False, indent=2))
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} kiểm tra đạt; FAIL bắt buộc: {[r['check'] for r in failed] or 'không'}")
    print(f"kết quả thô: {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
