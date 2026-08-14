#!/usr/bin/env python3
"""ZTLab ML/DL dataset generator.

Drives the live demo (web-portal -> api-gateway -> fraud-detection / OPA / Envoy)
through normal traffic + all 12 attack scenarios, then pulls the resulting logs
back out of Loki + security-scorer and joins them into two labeled CSVs:

  samples/tabular_dataset.csv  — one row per gateway request, features from
                                  Envoy access log + OPA decision log + fraud-
                                  detection/payment-service audit log, joined by
                                  trace_id (exact) or by time-window (approx).
  samples/text_dataset.csv     — one row per injected/log-line event pushed to
                                  security-scorer, exact event_type label.

Requires only the Python 3 standard library. Run with the usual local
port-forwards up (scripts/open-admin-uis.sh): web-portal:18081, loki:13100,
security-scorer:18092.

Usage:
    python3 ml-dataset/generate_dataset.py [--reps 5] [--skip-heavy]
"""

import argparse
import base64
import csv
import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

PORTAL = "http://127.0.0.1:18081"
LOKI = "http://127.0.0.1:13100"
SCORER = "http://127.0.0.1:18092"
OUT_DIR = Path(__file__).parent / "samples"

USERS = [("testuser01", "Test1234!"), ("testuser02", "Test1234!")]
# /api/scenarios/*/run is role-gated (security-admin/security-analyst only) —
# soc01 is a dedicated security-analyst test account for this (see ml-dataset/README.md).
SCENARIO_RUNNER_USER = ("soc01", "Test1234!")

# scenario_id -> (label / attack_type, mitre technique, reps)
GATEWAY_SCENARIOS = {
    "no_jwt": ("access_denied", "T1078", 5),
    "jwt_forgery": ("access_denied", "T1078", 5),
    "lateral_movement": ("lateral_movement", "T1021.007", 5),
    "fraud_gate": ("fraud_gate_bypass", "T1078.004", 5),
    "sqli_probe": ("exploit_probe", "T1203", 5),
    "high_velocity": ("brute_force", "T1110.001", 1),
    "rate_limit": ("port_scan", "T1046", 1),
}

INJECT_SCENARIOS = [
    "inject_brute_force", "inject_port_scan", "inject_exfiltration",
    "inject_cryptomining", "inject_cred_stuffing",
]


class Session:
    """Cookie-jar backed HTTP client emulating a real browser login."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def get(self, url, timeout=15):
        req = urllib.request.Request(url, method="GET")
        with self.opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), resp.geturl()

    def post_form(self, url, fields, timeout=15):
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                      headers={"Content-Type": "application/x-www-form-urlencoded"})
        with self.opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), resp.geturl()

    def post_json(self, url, payload, timeout=20):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                      headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
                return resp.status, _safe_json(body)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            return e.code, _safe_json(body)


def _safe_json(text):
    try:
        return json.loads(text)
    except Exception:
        return {"raw": text[:300]}


def login(username, password) -> Session:
    """Full OIDC Authorization Code + PKCE flow, exactly as the browser does it,
    through web-portal's /kc proxy so cookies stay same-origin."""
    sess = Session()
    # urllib's opener auto-follows the redirect chain: /auth/start -> /kc/realms/.../auth
    # (Keycloak login page, proxied through web-portal so cookies stay same-origin).
    status, html, final_url = sess.get(f"{PORTAL}/auth/start")
    if status != 200:
        raise RuntimeError(f"failed to load Keycloak login page: HTTP {status} at {final_url}")

    m = re.search(r'<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"', html)
    if not m:
        raise RuntimeError("could not find kc-form-login action in Keycloak login page")
    action_url = m.group(1).replace("&amp;", "&")

    status, body, final_url = sess.post_form(action_url, {"username": username, "password": password})
    if "/dashboard" not in final_url:
        raise RuntimeError(f"login did not reach /dashboard (landed on {final_url}) — check credentials")
    return sess


def decode_jwt_sub(token: str) -> str:
    try:
        parts = token.split(".")
        padding = 4 - len(parts[1]) % 4
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * padding))
        return payload.get("preferred_username", "")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Traffic generation
# ---------------------------------------------------------------------------

def run_normal_traffic(sess: Session, n: int, events: list):
    """Legit transfers with varied amount/channel/country to spread fraud
    scores across the 'normal' class (not all normal traffic scores 0)."""
    channels = ["web", "mobile", "api"]
    countries = ["VN", "VN", "VN", "SG", "TH"]
    pairs = [("ACC-1001", "ACC-2001"), ("ACC-2001", "ACC-1001")]
    amounts = [10_000, 50_000, 250_000, 1_000_000, 5_000_000, 20_000_000,
               80_000_000, 150_000_000, 400_000_000]
    for i in range(n):
        frm, to = pairs[i % 2]
        amount = amounts[i % len(amounts)]
        body = {
            "from_account": frm, "to_account": to, "amount": amount, "currency": "VND",
            "channel": channels[i % len(channels)], "country": countries[i % len(countries)],
        }
        t0 = time.time()
        status, result = sess.post_json(f"{PORTAL}/api/transfer", body)
        t1 = time.time()
        trace_id = result.get("trace_id") if isinstance(result, dict) else None
        events.append({
            "label": "normal", "mitre": "", "scenario": "normal_traffic",
            "start": t0, "end": t1, "trace_id": trace_id, "status_code": status,
        })
        print(f"  [normal] {frm}->{to} {amount:>12,} VND ch={body['channel']:6} "
              f"country={body['country']} -> HTTP {status} trace={trace_id}")
        time.sleep(0.4)


def run_gateway_scenarios(sess: Session, reps_override: int | None, skip_heavy: bool, events: list):
    for scenario_id, (label, mitre, default_reps) in GATEWAY_SCENARIOS.items():
        if skip_heavy and scenario_id in ("high_velocity", "rate_limit"):
            print(f"  [skip] {scenario_id} (--skip-heavy)")
            continue
        reps = reps_override if reps_override is not None else default_reps
        reps = 1 if scenario_id in ("high_velocity", "rate_limit") else reps
        for r in range(reps):
            t0 = time.time()
            status, result = sess.post_json(f"{PORTAL}/api/scenarios/{scenario_id}/run", {})
            t1 = time.time()
            trace_id = None
            if isinstance(result, dict):
                inner = result.get("result")
                if isinstance(inner, dict):
                    trace_id = inner.get("trace_id")
            events.append({
                "label": label, "mitre": mitre, "scenario": scenario_id,
                "start": t0, "end": t1, "trace_id": trace_id, "status_code": status,
            })
            print(f"  [{scenario_id}] rep {r+1}/{reps} -> HTTP {status} trace={trace_id}")
            time.sleep(0.6)


def run_inject_scenarios(sess: Session, reps: int):
    for scenario_id in INJECT_SCENARIOS:
        for r in range(reps):
            status, result = sess.post_json(f"{PORTAL}/api/scenarios/{scenario_id}/run", {})
            print(f"  [{scenario_id}] rep {r+1}/{reps} -> HTTP {status}")
            time.sleep(0.3)


# ---------------------------------------------------------------------------
# Loki querying
# ---------------------------------------------------------------------------

def loki_query_range(query: str, start_ns: int, end_ns: int, limit=5000):
    params = urllib.parse.urlencode({
        "query": query, "start": str(start_ns), "end": str(end_ns),
        "limit": str(limit), "direction": "forward",
    })
    url = f"{LOKI}/loki/api/v1/query_range?{params}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        print(f"  ! Loki query failed ({query}): {exc}", file=sys.stderr)
        return []
    lines = []
    for stream in data.get("data", {}).get("result", []):
        stream_labels = stream.get("stream", {})
        for ts_ns, line in stream.get("values", []):
            lines.append((int(ts_ns), stream_labels, line))
    return lines


def label_for_ts(ts_seconds: float, events: list, trace_id: str | None):
    """Exact trace_id match wins; else fall back to the time-window a
    recorded action was running in. Returns (label, mitre, confidence)."""
    if trace_id:
        for e in events:
            if e["trace_id"] and e["trace_id"] == trace_id:
                return e["label"], e["mitre"], "exact"
    for e in events:
        if e["start"] - 1.0 <= ts_seconds <= e["end"] + 3.0:
            return e["label"], e["mitre"], "window"
    return None, None, None


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def parse_envoy_line(line: str) -> dict:
    d = _safe_json(line)
    if not isinstance(d, dict):
        return {}
    return {
        "envoy_method": d.get("method"), "envoy_path": d.get("path"),
        "envoy_response_code": d.get("response_code"), "envoy_response_time_ms": d.get("response_time"),
        "envoy_bytes_sent": d.get("bytes_sent"), "envoy_source_ip": d.get("source_ip"),
        "envoy_upstream": d.get("upstream"), "envoy_svid": d.get("svid"),
        "envoy_trace_id": d.get("trace_id"),
    }


def parse_opa_line(line: str) -> dict:
    d = _safe_json(line)
    if not isinstance(d, dict):
        return {}
    attrs = (d.get("input") or {}).get("attributes", {})
    req = attrs.get("request", {}).get("http", {})
    headers = req.get("headers", {}) or {}
    dest = attrs.get("destination", {}) or {}
    src = attrs.get("source", {}) or {}
    result = d.get("result")
    return {
        "opa_decision_id": d.get("decision_id"),
        "opa_allow": result if isinstance(result, bool) else (result or {}).get("allow") if isinstance(result, dict) else None,
        "opa_dest_principal": dest.get("principal"),
        "opa_source_principal": src.get("principal"),
        "opa_req_method": req.get("method"), "opa_req_path": req.get("path"),
        "opa_req_host": req.get("host"),
        "opa_has_bearer": bool(headers.get("authorization")),
        "opa_x_trace_id": headers.get("x-trace-id"),
        "opa_x_user_id": headers.get("x-user-id"),
        "opa_content_length": headers.get("content-length"),
        "opa_user_agent": headers.get("user-agent"),
    }


def parse_pod_json_line(line: str) -> dict:
    d = _safe_json(line)
    if not isinstance(d, dict):
        return {}
    return {
        "app_event": d.get("event"), "app_level": d.get("level"), "app_service": d.get("service"),
        "app_trace_id": d.get("trace_id"), "app_fraud_score": d.get("fraud_score"),
        "app_verdict": d.get("verdict"), "app_reason": ";".join(d.get("reason", []) or []) if isinstance(d.get("reason"), list) else d.get("reason"),
        "app_amount": d.get("amount"), "app_channel": d.get("channel"), "app_country": d.get("country"),
        "app_status_code": d.get("status_code"), "app_duration_ms": d.get("duration_ms"),
    }


def build_tabular_dataset(events: list, start_ns: int, end_ns: int) -> list[dict]:
    print("\n[*] Querying Loki: envoy-access ...")
    envoy_lines = loki_query_range('{job="envoy-access"}', start_ns, end_ns)
    print(f"    {len(envoy_lines)} lines")

    print("[*] Querying Loki: opa-decisions ...")
    opa_lines = loki_query_range('{job="opa-decisions"} != `req_path\\":\\"/health`', start_ns, end_ns)
    print(f"    {len(opa_lines)} lines")

    print("[*] Querying Loki: kubernetes-pods (fraud-detection, payment-service, api-gateway) ...")
    pod_lines = loki_query_range(
        '{job="kubernetes-pods", app=~"fraud-detection|payment-service|api-gateway"}', start_ns, end_ns)
    print(f"    {len(pod_lines)} lines")

    rows = []
    for ts_ns, labels, line in envoy_lines:
        ts_s = ts_ns / 1e9
        feat = parse_envoy_line(line)
        if not feat:
            continue
        lbl, mitre, conf = label_for_ts(ts_s, events, feat.get("envoy_trace_id"))
        if lbl is None:
            continue
        row = {"source_layer": "envoy", "timestamp": ts_s, "label": lbl, "mitre": mitre,
               "label_confidence": conf, "stream_labels": json.dumps(labels)}
        row.update(feat)
        rows.append(row)

    for ts_ns, labels, line in opa_lines:
        ts_s = ts_ns / 1e9
        feat = parse_opa_line(line)
        if not feat:
            continue
        lbl, mitre, conf = label_for_ts(ts_s, events, feat.get("opa_x_trace_id"))
        if lbl is None:
            continue
        row = {"source_layer": "opa", "timestamp": ts_s, "label": lbl, "mitre": mitre,
               "label_confidence": conf, "stream_labels": json.dumps(labels)}
        row.update(feat)
        rows.append(row)

    for ts_ns, labels, line in pod_lines:
        ts_s = ts_ns / 1e9
        feat = parse_pod_json_line(line)
        if not feat or not feat.get("app_event"):
            continue
        lbl, mitre, conf = label_for_ts(ts_s, events, feat.get("app_trace_id"))
        if lbl is None:
            continue
        row = {"source_layer": "app", "timestamp": ts_s, "label": lbl, "mitre": mitre,
               "label_confidence": conf, "stream_labels": json.dumps(labels)}
        row.update(feat)
        rows.append(row)

    return rows


def fetch_text_dataset(events: list) -> list[dict]:
    """security-scorer stores exactly what was injected, with event_type as an
    exact label — no time-window guessing needed for this half of the dataset."""
    try:
        with urllib.request.urlopen(f"{SCORER}/events/recent?limit=1000", timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        print(f"  ! could not fetch security-scorer /events/recent: {exc}", file=sys.stderr)
        return []
    rows = []
    items = data if isinstance(data, list) else data.get("events", [])
    for ev in items:
        if not isinstance(ev, dict):
            continue
        rows.append({
            "event_type": ev.get("event_type") or ev.get("pattern") or ev.get("type"),
            "message": ev.get("message", ""),
            "service": ev.get("service", ""),
            "timestamp": ev.get("timestamp") or ev.get("ts"),
        })
    return rows


# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

TABULAR_FIELDS = [
    "source_layer", "timestamp", "label", "mitre", "label_confidence", "stream_labels",
    "envoy_method", "envoy_path", "envoy_response_code", "envoy_response_time_ms",
    "envoy_bytes_sent", "envoy_source_ip", "envoy_upstream", "envoy_svid", "envoy_trace_id",
    "opa_decision_id", "opa_allow", "opa_dest_principal", "opa_source_principal",
    "opa_req_method", "opa_req_path", "opa_req_host", "opa_has_bearer", "opa_x_trace_id",
    "opa_x_user_id", "opa_content_length", "opa_user_agent",
    "app_event", "app_level", "app_service", "app_trace_id", "app_fraud_score", "app_verdict",
    "app_reason", "app_amount", "app_channel", "app_country", "app_status_code", "app_duration_ms",
]

TEXT_FIELDS = ["event_type", "message", "service", "timestamp"]


def write_csv(path: Path, fields: list, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=None, help="override reps per gateway scenario")
    ap.add_argument("--inject-reps", type=int, default=5)
    ap.add_argument("--normal-count", type=int, default=20)
    ap.add_argument("--skip-heavy", action="store_true", help="skip high_velocity/rate_limit (slow)")
    args = ap.parse_args()

    run_start_ns = time.time_ns()
    events: list[dict] = []

    print(f"[*] Logging in as {USERS[0][0]} ...")
    sess1 = login(*USERS[0])
    print(f"[*] Logging in as {USERS[1][0]} ...")
    sess2 = login(*USERS[1])
    print(f"[*] Logging in as {SCENARIO_RUNNER_USER[0]} (security-analyst — /api/scenarios/*/run is role-gated) ...")
    sess_soc = login(*SCENARIO_RUNNER_USER)
    print("[+] All sessions authenticated via real OIDC PKCE flow.\n")

    print("[*] Generating normal traffic ...")
    run_normal_traffic(sess1, args.normal_count // 2, events)
    run_normal_traffic(sess2, args.normal_count - args.normal_count // 2, events)

    print("\n[*] Running gateway-routed attack scenarios (produce rich Envoy/OPA/app logs) ...")
    run_gateway_scenarios(sess_soc, args.reps, args.skip_heavy, events)

    print("\n[*] Running inject-only scenarios (text dataset, exact labels via security-scorer) ...")
    run_inject_scenarios(sess_soc, args.inject_reps)

    run_end_ns = time.time_ns()
    print(f"\n[*] Traffic generation window: {(run_end_ns - run_start_ns) / 1e9:.1f}s, "
          f"{len(events)} labeled actions recorded.")
    print("[*] Waiting 15s for logs to land in Loki (Promtail scrape lag) ...")
    time.sleep(15)

    tabular_rows = build_tabular_dataset(events, run_start_ns, run_end_ns + 15_000_000_000)
    text_rows = fetch_text_dataset(events)

    write_csv(OUT_DIR / "tabular_dataset.csv", TABULAR_FIELDS, tabular_rows)
    write_csv(OUT_DIR / "text_dataset.csv", TEXT_FIELDS, text_rows)

    print(f"\n[+] Wrote {len(tabular_rows)} rows -> {OUT_DIR / 'tabular_dataset.csv'}")
    print(f"[+] Wrote {len(text_rows)} rows -> {OUT_DIR / 'text_dataset.csv'}")

    print("\n[*] Tabular label distribution:")
    counts = {}
    for r in tabular_rows:
        counts[r["label"]] = counts.get(r["label"], 0) + 1
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {k:25} {v}")

    print("\n[*] Text label distribution:")
    counts = {}
    for r in text_rows:
        counts[r["event_type"]] = counts.get(r["event_type"], 0) + 1
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {str(k):25} {v}")


if __name__ == "__main__":
    main()
