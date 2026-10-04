#!/usr/bin/env python3
"""Mục 3.1 (đóng sổ 2026-10-04) — phân phối độ trễ PDP (OPA ext_authz) đo TỪ CHÍNH decision log.

Mỗi decision OPA ghi `metrics.timer_server_handler_ns` (OPA nhận → trả lời một quyết định) và
`timer_rego_builtin_http_send_ns` (lấy JWKS/discovery — cache 300 s). Đây là thành phần ext_authz của
overhead Zero-Trust, đo trên LƯU LƯỢNG THẬT với n lớn và KHÔNG bị nhiễu WAN (khác phép đo phía client,
nơi mỗi request tới crapi-workshop đi qua identity + Postgres cross-cloud ~1 s).
Không gồm: chặng gRPC Envoy↔OPA, bắt tay mТLS, hai chặng Envoy, và chi phí ghi decision log (ghi SAU
khi trả lời) — nên đây là CẬN DƯỚI của overhead ext_authz, không phải toàn bộ overhead ZT.

    python3 tests/opa_pdp_latency.py --start <epoch> --end <epoch> --output results/closeout/perf/pdp.json
"""
import argparse, json, statistics, sys, urllib.parse, urllib.request
from collections import Counter


Q = ('{job="opa-decisions"} |= "decision_id" | json srv="metrics.timer_server_handler_ns", '
     'hs="metrics.timer_rego_builtin_http_send_ns", dst="input.attributes.destination.principal", res="result" '
     '| line_format "{{.srv}} {{.hs}} {{.dst}} {{.res}}"')


def fetch(loki, start, end, window=300):
    """Đọc HẾT dòng trong [start,end]: chỉ lấy 4 trường (line_format) để giữ payload nhỏ; chia cửa sổ
    `window` giây và phân trang trong cửa sổ (bản đầu đọc nguyên dòng decision → port-forward rớt)."""
    out = []
    w0 = start
    while w0 < end:
        cur, w_end = int(w0 * 1e9), int(min(end, w0 + window) * 1e9)
        while cur < w_end:
            p = urllib.parse.urlencode({"query": Q, "start": cur, "end": w_end, "limit": 5000, "direction": "forward"})
            with urllib.request.urlopen(f"{loki}/loki/api/v1/query_range?{p}", timeout=120) as r:
                res = json.load(r)["data"]["result"]
            vals = sorted((int(ts), line, s["stream"]) for s in res for ts, line in s["values"])
            out += vals
            if len(vals) < 5000:
                break
            cur = vals[-1][0] + 1
        w0 += window
    return out


def pct(v, p):
    if not v:
        return None
    k = (len(v) - 1) * p / 100
    f = int(k)
    return v[f] + (v[min(f + 1, len(v) - 1)] - v[f]) * (k - f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loki", default="http://127.0.0.1:13100")
    ap.add_argument("--start", type=float, required=True)
    ap.add_argument("--end", type=float, required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    rows = fetch(a.loki, a.start, a.end)
    per = {}
    for ts, line, st in rows:
        f = line.split()
        # Loki in số ns lớn ở dạng mũ (vd 1.2e+07) — parse float, không isdigit (bản đầu loại mất ~3/4 mẫu)
        def num(x):
            try:
                return float(x)
            except ValueError:
                return None
        if len(f) < 3 or num(f[0]) is None:
            continue
        key = st.get("cloud", "?")
        per.setdefault(key, []).append({
            "ms": num(f[0]) / 1e6, "http_send_ms": (num(f[1]) or 0) / 1e6,
            "dst": f[2].rsplit("/", 1)[-1], "allow": f[3:4] == ["true"]})
    report = {"window": [a.start, a.end], "method": __doc__.strip().splitlines()[0], "clouds": {}}
    for cloud, xs in sorted(per.items()):
        v = sorted(x["ms"] for x in xs)
        n = len(v)
        p99 = pct(v, 99)
        tail = [x for x in xs if x["ms"] >= p99]
        report["clouds"][cloud] = {
            "n": n, "p50_ms": round(pct(v, 50), 3), "p95_ms": round(pct(v, 95), 3), "p99_ms": round(p99, 3),
            "max_ms": round(v[-1], 3), "mean_ms": round(statistics.mean(v), 3),
            "samples_at_or_above_p99": len(tail),
            "tail_http_send_share": round(sum(1 for x in tail if x["http_send_ms"] > 1) / max(1, len(tail)), 3),
            "tail_by_dst": Counter(x["dst"] for x in tail).most_common(5),
            "allow_ratio": round(sum(1 for x in xs if x["allow"]) / n, 4),
            "histogram_ms_0.25": dict(sorted(Counter(round(int(x // 0.25) * 0.25, 2) for x in v).items())),
        }
        r = report["clouds"][cloud]
        print(f"{cloud:10} n={n:6}  p50={r['p50_ms']:.2f}  p95={r['p95_ms']:.2f}  p99={r['p99_ms']:.2f}  max={r['max_ms']:.2f} ms"
              f"  (p99 từ {len(tail)} mẫu; đuôi có http.send>1ms: {r['tail_http_send_share']:.0%})")
    json.dump(report, open(a.output, "w"), ensure_ascii=False, indent=1)
    return 0 if per else 1


if __name__ == "__main__":
    sys.exit(main())
