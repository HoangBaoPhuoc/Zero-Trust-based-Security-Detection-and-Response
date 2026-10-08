#!/usr/bin/env python3
"""Giai đoạn B §B1 — NGHIỆM THU nhịp độ: chứng minh biến thể giữ riêng khác train
về HÀNH VI THẬT, không chỉ nhãn.

Quy trình (chạy SAU khi đã có ≥1 lượt burst + ≥1 lượt slow_drip của cùng một họ
trong tests/runs.jsonl):
  1. Lấy [t_start,t_end] của lượt burst và lượt slow_drip từ runs.jsonl
     (phân loại pace theo policy/variant-split.yaml ↔ variant_group).
  2. Trích timestamp THẬT các request của từng lượt từ Loki (lọc theo họ).
  3. Tính phân phối khoảng cách giữa các request (min/median/mean/max/stdev).
  4. KHẲNG ĐỊNH hai phân phối khác nhau rõ rệt:
        burst:     median < --burst-max (mặc 1.0s)
        slow_drip: median > --slow-min (mặc 5.0s) VÀ stdev > stdev(burst)
  5. Lưu bằng chứng (2 dãy timestamp + thống kê) vào --out.
  Không đạt (4) → biến thể giữ riêng CHƯA tồn tại thật → KHÔNG chạy cổng.

Thêm: VICTIMS (đếm thực thể đích riêng biệt trong Loki), SOURCE (source_principal
thật trong decision log).

Dùng:
  python3 tests/phaseb_pace_accept.py --family bola --runs tests/runs.jsonl \
      --loki http://localhost:13100 --out results/phaseb/pace
  python3 tests/phaseb_pace_accept.py --selftest
"""
from __future__ import annotations
import argparse, json, re, statistics, sys, urllib.parse, urllib.request
from datetime import datetime

def iso_e(s): return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()

# họ → (Loki selector, regex lọc dòng, regex rút thực thể đích, có dùng source_principal)
FAMILY = {
    "bola":                 ('{job="envoy-access"}',                 r'vehicle/[^/]+/location',  r'vehicle/([^/]+)/location', False),
    "lateral_movement":     ('{job="opa-decisions", opa_result="false"}', r'/workshop/api/shop/orders', None, True),
    "brute_force":          ('{namespace="identity",app="keycloak"}', r'(?i)login_error|invalid_user_credentials', r'username["=:\s]+([A-Za-z0-9_.-]+)', False),
    "access_denied_spike":  ('{job="opa-decisions", opa_result="false"}', r'.', None, True),
    "bfla":                 ('{job="bff-audit"}',                    r'rbac_denied', None, False),
    "large_response":       ('{job="envoy-access"}',                 r'posts/recent', None, False),
}

def load_variant_pace(split_file):
    """variant id (ví dụ bola_slowdrip) → pace."""
    import yaml
    doc = yaml.safe_load(open(split_file)); m = {}
    for fam in doc["families"]:
        for grp in ("train", "holdout"):
            for v in fam.get(grp) or []:
                m[v["id"]] = v.get("pace", "")
    return m

def pick_runs(runs_file, family, split_file):
    """Trả (burst_run, slow_run) mới nhất cho họ. Phân loại pace theo variant id."""
    pace_of = {}
    try: pace_of = load_variant_pace(split_file)
    except Exception: pass
    burst = slow = None
    for l in open(runs_file):
        l = l.strip()
        if not l: continue
        d = json.loads(l)
        if d.get("class") != "attack" or d.get("scenario") != family: continue
        if d.get("status") == "aborted": continue
        vg = d.get("variant_group", "")           # "group:variant_id"
        vid = vg.split(":", 1)[1] if ":" in vg else vg
        # pace lấy từ yaml; fallback CHỈ theo "slow|drip" (spray/many nay có thể là burst)
        pace = pace_of.get(vid) or ("slow_drip" if re.search(r'slow|drip', vid) else "burst")
        run = {"t0": iso_e(d["t_start"]), "t1": iso_e(d["t_end"]), "variant": vid, "pace": pace}
        if pace == "slow_drip": slow = run
        else: burst = run
    return burst, slow

def loki_lines(loki, selector, t0, t1):
    """Trả list (ts_seconds, line) trong [t0,t1], forward, phân trang."""
    out = []; cur = int(t0 * 1e9); end = int((t1 + 1) * 1e9)
    while cur < end:
        qs = urllib.parse.urlencode({"query": selector, "start": str(cur), "end": str(end),
                                     "limit": 5000, "direction": "forward"})
        data = json.load(urllib.request.urlopen(f"{loki}/loki/api/v1/query_range?{qs}", timeout=60))["data"]["result"]
        last = cur
        for s in data:
            for ts, line in s["values"]:
                out.append((int(ts) / 1e9, line)); last = max(last, int(ts))
        if not data or last <= cur: break
        cur = last + 1
    return sorted(out)

def gap_stats(ts):
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    if not gaps:
        return {"n_requests": len(ts), "n_gaps": 0}
    return {"n_requests": len(ts), "n_gaps": len(gaps),
            "min": round(min(gaps), 3), "median": round(statistics.median(gaps), 3),
            "mean": round(statistics.mean(gaps), 3), "max": round(max(gaps), 3),
            "stdev": round(statistics.pstdev(gaps), 3)}

def verdict(burst_stats, slow_stats, burst_max, slow_min):
    reasons = []
    ok = True
    if burst_stats.get("n_gaps", 0) < 2 or slow_stats.get("n_gaps", 0) < 2:
        return False, ["không đủ request (≥3 mỗi lượt) để tính phân phối khoảng cách"]
    if not burst_stats["median"] < burst_max:
        ok = False; reasons.append(f"burst median={burst_stats['median']}s KHÔNG < {burst_max}s")
    if not slow_stats["median"] > slow_min:
        ok = False; reasons.append(f"slow_drip median={slow_stats['median']}s KHÔNG > {slow_min}s")
    if not slow_stats["stdev"] > burst_stats["stdev"]:
        ok = False; reasons.append(f"slow_drip stdev={slow_stats['stdev']} KHÔNG > burst stdev={burst_stats['stdev']}")
    if ok: reasons.append("hai phân phối khác nhau rõ rệt → biến thể giữ riêng TỒN TẠI THẬT")
    return ok, reasons

def distinct_targets(lines, target_re):
    if not target_re: return None
    s = set()
    for _ts, line in lines:
        for m in re.findall(target_re, line): s.add(m)
    return sorted(s)

def distinct_sources(lines):
    s = set()
    for _ts, line in lines:
        try:
            d = json.loads(line)
            p = (((d.get("input") or {}).get("attributes") or {}).get("source") or {}).get("principal") or d.get("svid")
            if p: s.add(p)
        except Exception:
            m = re.search(r'spiffe://[^"\\ ]+', line)
            if m: s.add(m.group(0))
    return sorted(s)

def run(args):
    sel, line_re, target_re, use_src = FAMILY[args.family]
    burst, slow = pick_runs(args.runs, args.family, args.split)
    if not burst or not slow:
        print(f"[accept] CHƯA đủ lượt: burst={bool(burst)} slow_drip={bool(slow)} cho họ '{args.family}'.")
        print("         Chạy 1 lượt burst + 1 lượt slow_drip trước (crapi_campaign_phaseb.sh --families "
              f"{args.family} --groups train,holdout --repeat 1).")
        sys.exit(2)
    rx = re.compile(line_re)
    result = {"family": args.family, "burst_variant": burst["variant"], "slow_variant": slow["variant"]}
    series = {}
    for name, rrun in (("burst", burst), ("slow_drip", slow)):
        lines = [(ts, ln) for ts, ln in loki_lines(args.loki, sel, rrun["t0"], rrun["t1"]) if rx.search(ln)]
        ts = [t for t, _ in lines]
        series[name] = {"window": [rrun["t0"], rrun["t1"]], "timestamps": [round(t, 3) for t in ts],
                        "stats": gap_stats(ts)}
        if target_re: series[name]["distinct_targets"] = distinct_targets(lines, target_re)
        if use_src:   series[name]["distinct_source_principals"] = distinct_sources(lines)
    ok, reasons = verdict(series["burst"]["stats"], series["slow_drip"]["stats"], args.burst_max, args.slow_min)
    result["series"] = series; result["pass"] = ok; result["reasons"] = reasons
    import os; os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, f"pace-accept-{args.family}.json")
    json.dump(result, open(path, "w"), indent=2, ensure_ascii=False)
    print(f"[accept] họ={args.family}")
    print(f"  burst({burst['variant']}):     {series['burst']['stats']}")
    print(f"  slow_drip({slow['variant']}):  {series['slow_drip']['stats']}")
    if target_re:
        print(f"  VICTIMS riêng biệt: burst={len(series['burst'].get('distinct_targets') or [])} "
              f"slow={len(series['slow_drip'].get('distinct_targets') or [])}")
    if use_src:
        print(f"  SOURCE principals: burst={series['burst'].get('distinct_source_principals')} "
              f"slow={series['slow_drip'].get('distinct_source_principals')}")
    for r in reasons: print(f"  - {r}")
    print(f"[accept] {'PASS' if ok else 'FAIL'} — bằng chứng → {path}")
    sys.exit(0 if ok else 1)

def selftest():
    # burst: gaps ~0.2s; slow_drip: gaps ~tens of seconds với phương sai
    bt = [1000.0 + i * 0.2 for i in range(10)]
    st = [2000.0]
    for g in (12, 90, 30, 180, 45, 60, 25, 110, 70):
        st.append(st[-1] + g)
    bs, ss = gap_stats(bt), gap_stats(st)
    ok, reasons = verdict(bs, ss, 1.0, 5.0)
    print("[selftest] burst:", bs); print("[selftest] slow_drip:", ss)
    print("[selftest] verdict:", ok, reasons)
    assert ok, "selftest: burst/slow_drip phải PASS"
    # ca âm: slow_drip thật ra cũng burst → phải FAIL
    ok2, _ = verdict(bs, gap_stats([3000.0 + i * 0.2 for i in range(10)]), 1.0, 5.0)
    assert not ok2, "selftest: hai lượt cùng nhịp phải FAIL"
    print("[selftest] OK — logic thống kê + verdict đúng (PASS khi khác nhịp, FAIL khi cùng nhịp)")

def main():
    ap = argparse.ArgumentParser(description="§B1 nghiệm thu nhịp độ từ timestamp Loki")
    ap.add_argument("--family", choices=list(FAMILY))
    ap.add_argument("--runs", default="tests/runs.jsonl")
    ap.add_argument("--split", default="policy/variant-split.yaml")
    ap.add_argument("--loki", default="http://localhost:13100")
    ap.add_argument("--out", default="results/phaseb/pace")
    ap.add_argument("--burst-max", type=float, default=1.0)
    ap.add_argument("--slow-min", type=float, default=5.0)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest: selftest(); return
    if not a.family: ap.error("cần --family (hoặc --selftest)")
    run(a)

if __name__ == "__main__":
    main()
