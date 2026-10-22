#!/usr/bin/env python3
"""Giai đoạn C — bộ trích đặc trưng v2, bám đúng đề cương KLTN (mục 6, Bước 2).

Khác `tests/phaseb_gate.py featurize` (bảng Giai đoạn B) ở bốn điểm đề cương
yêu cầu mà bảng cũ không có:
  1. Cửa sổ 5 phút TRƯỢT mỗi 1 phút (bảng cũ: tumbling 15/30/60/300/600 s).
  2. Mã đối tượng lấy cả UUID trong path và id trong query (`report_id`...)
     — `_target_ids` cũ chỉ bắt số nguyên nên `n_target` = 0 trên mọi cửa sổ BOLA.
  3. Đặc trưng "chưa từng thấy" (đối tượng mới với user, cặp gọi mới,
     cặp cross-cloud mới) tính NHÂN QUẢ: chỉ dựa trên sự kiện trước cửa sổ.
  4. Gán user cho cả request mang JWT (Bearer / X-Access-Token), không chỉ
     request có cookie phiên BFF — BOLA burst trước đây mất nhãn vì lý do này.

Đọc log thô do `phaseb_gate.py export` ghi ({envoy,opa,bff}.jsonl[.gz] trong
mỗi thư mục khúc), tái dùng phần đọc luồng/sắp thứ tự/gán nhãn của nó.

  python3 ml/features_v2.py inspect --chunk results/b4/chunks/c0001-...
  python3 ml/features_v2.py build --chunks results/b4/chunks/c0001-...,c0002-... \\
          --runs tests/runs.jsonl --out results/c4/features_v2
  python3 ml/features_v2.py selftest

Các khúc phải truyền theo thứ tự thời gian: lịch sử "đã từng thấy" mang từ
khúc trước sang khúc sau.
"""
from __future__ import annotations

import argparse
import base64
import bisect
import csv
import gzip
import heapq
import importlib.util
import json
import math
import os
import re
import statistics
import sys
import tempfile
from collections import Counter, defaultdict, deque
from urllib.parse import parse_qsl, urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
_GATE_PATH = os.path.join(_HERE, "..", "tests", "phaseb_gate.py")
_spec = importlib.util.spec_from_file_location("phaseb_gate", _GATE_PATH)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

WINDOW = 300
STEP = 60

# ───────────────────── nhóm đặc trưng (đề cương mục 6, Bước 2) ─────────────
FEATURES_A = [  # HTTP thông thường + quan hệ người dùng–đối tượng
    "n_req", "pct_4xx", "pct_5xx", "n_path", "path_entropy", "rw_ratio",
    "gap_mean", "gap_cv", "bytes_sum", "bytes_max", "rt_p95",
    "n_obj", "n_obj_new", "frac_obj_new",
]
FEATURES_B = [  # chỉ có trong môi trường Zero Trust
    "n_dst", "n_pair", "n_pair_new", "deny_count", "deny_rate",
    "xcloud_ratio", "n_xcloud_pair_new", "stepup_present", "posture_bad",
]
META = ["chunk_id", "window_start", "window_end", "entity", "entity_type",
        "label", "run_id", "scenario", "variant_group", "hist_sec"]

_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_NUM_SEG_RE = re.compile(r"/([a-z_]+)/(\d+)(?=/|$)")
_ID_PARAM_RE = re.compile(r"(^id$|_id$|^vin$)", re.I)


# ───────────────────── trích xuất từ một request ───────────────────────────
def object_ids(path: str) -> set[str]:
    """Mã đối tượng trong request: UUID ở bất kỳ đâu, số nguyên đứng sau một
    tên tài nguyên trong path (`/orders/12`), và tham số query dạng `*_id`
    (`mechanic_report?report_id=6`). Gắn tiền tố loại để `orders/12` và
    `videos/12` không trùng nhau."""
    if not path:
        return set()
    parts = urlsplit(path)
    out = {"uuid:" + u.lower() for u in _UUID_RE.findall(parts.path)}
    out |= {f"{res}:{num}" for res, num in _NUM_SEG_RE.findall(parts.path)}
    for k, v in parse_qsl(parts.query, keep_blank_values=False):
        if _ID_PARAM_RE.search(k) and v:
            out.add(f"{k.lower()}:{v}")
    return out


def norm_path(path: str) -> str:
    return gate._norm_path(path or "")


def _b64json(seg: str) -> dict:
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def jwt_user(token: str) -> str:
    """Username từ payload JWT (không kiểm chữ ký — chỉ để gán nhãn offline;
    chữ ký đã được OPA kiểm lúc ra quyết định). Keycloak: preferred_username;
    token crAPI-native do BFF mint: sub/email dạng `<user>@ztlab.local`."""
    if not token:
        return ""
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) < 2:
        return ""
    try:
        claims = _b64json(parts[1])
    except Exception:
        return ""
    user = claims.get("preferred_username") or claims.get("email") or claims.get("sub") or ""
    return user.split("@")[0] if isinstance(user, str) else ""


def jwt_acr(token: str) -> str:
    try:
        t = token[7:] if token.lower().startswith("bearer ") else token
        return str(_b64json(t.split(".")[1]).get("acr", ""))
    except Exception:
        return ""


def spiffe_cloud(principal: str) -> str:
    # spiffe://ztlab.local/<cloud>/<svc>
    if principal and principal.startswith("spiffe://"):
        segs = principal.split("/")
        return segs[3] if len(segs) > 4 else ""
    return ""


# ───────────────────── bản đồ danh tính (đọc trước) ────────────────────────
def build_identity_maps(chunk_dir: str, sid_map: dict) -> tuple[dict, dict]:
    """Một lượt qua log OPA: x-request-id → username, lấy user từ cookie phiên
    (C1) HOẶC từ JWT trong header (mới — phủ request Bearer). Trả thêm thống
    kê độ phủ để `inspect` báo cáo."""
    trace_user, stats = {}, Counter()
    p = gate._stream_path(chunk_dir, "opa")
    if not p:
        return trace_user, stats
    with gate._open_any(p) as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                http = _opa_http(gate._body(json.loads(raw)))
            except Exception:
                stats["parse_error"] += 1
                continue
            h = http.get("headers") or {}
            user, how = _user_from_headers(h, sid_map)
            stats["opa_events"] += 1
            stats[f"user_from_{how}"] += 1
            tid = h.get("x-request-id", "")
            if tid and user:
                trace_user[tid] = user
    return trace_user, stats


def _opa_http(body: dict) -> dict:
    inp = (body.get("input") or {}).get("attributes") or {}
    return (inp.get("request") or {}).get("http") or {}


def _user_from_headers(h: dict, sid_map: dict) -> tuple[str, str]:
    sid = gate._decode_sid(h.get("cookie", "")) if h.get("cookie") else ""
    if sid and sid_map.get(sid):
        return sid_map[sid], "cookie"
    for key in ("x-access-token", "authorization"):
        u = jwt_user(h.get(key, ""))
        if u:
            return u, "jwt"
    return "", "none"


# ───────────────────── bộ đọc luồng (sự kiện giàu hơn bản Giai đoạn B) ─────
def _make_opa_parser(sid_map: dict):
    def parse(raw: str) -> dict:
        r = json.loads(raw); b = gate._body(r)
        attrs = (b.get("input") or {}).get("attributes") or {}
        http = (attrs.get("request") or {}).get("http") or {}
        h = http.get("headers") or {}
        src = (attrs.get("source") or {}).get("principal") or b.get("svid") \
            or r["labels"].get("source_principal", "")
        dst = (attrs.get("destination") or {}).get("principal") or ""
        dec = b.get("result")
        if dec is None and "opa_result" in r["labels"]:
            dec = r["labels"]["opa_result"] == "true"
        user, _ = _user_from_headers(h, sid_map)
        tok = h.get("x-access-token") or h.get("authorization") or ""
        return dict(ts=int(r["ts_ns"]) / 1e9, stream="opa",
                    entity=user or gate._princ(src), entity_type="user" if user else "workload",
                    req_id=h.get("x-request-id", ""), src=src, dst=dst,
                    method=http.get("method", ""), path=http.get("path", "")
                    or r["labels"].get("request_path", ""),
                    code=None, decision=dec if isinstance(dec, bool) else None,
                    bytes=None, rt=None, reason=None,
                    posture=h.get("x-device-posture"), acr=jwt_acr(tok) if tok else "")
    return parse


def _make_envoy_parser(trace_user: dict):
    def parse(raw: str) -> dict:
        r = json.loads(raw); b = gate._body(r)
        tid = b.get("trace_id", "")
        user = trace_user.get(tid, "") if tid else ""
        svid = b.get("svid") or ""
        return dict(ts=int(r["ts_ns"]) / 1e9, stream="envoy",
                    entity=user or gate._princ(svid or r["labels"].get("source_ip", "")),
                    entity_type="user" if user else "workload",
                    req_id=tid, src=svid, dst=b.get("upstream_cluster") or "",
                    method=b.get("method", r["labels"].get("method", "")),
                    path=b.get("path", r["labels"].get("path", "")),
                    code=str(b.get("response_code", r["labels"].get("response_code", ""))),
                    decision=None, bytes=gate._num(b.get("bytes_sent")),
                    rt=gate._num(b.get("response_time")), reason=None, posture=None, acr="")
    return parse


def _parse_bff(raw: str) -> dict:
    e = gate._parse_bff_line(raw)
    user = e["entity"] if e["entity"] != "?" else ""
    return dict(ts=e["ts"], stream="bff", entity=user or "?",
                entity_type="user" if user else "workload",
                req_id="", src="", dst="", method="", path=e.get("path") or "",
                code=e["code"], decision=e["decision"], bytes=None, rt=None,
                reason=e["reason"], posture=None, acr=e.get("stepup") or "")


def iter_events(chunk_dir: str, sid_map: dict, trace_user: dict):
    gens = [gate._stream_gen([chunk_dir], "envoy", _make_envoy_parser(trace_user)),
            gate._stream_gen([chunk_dir], "opa", _make_opa_parser(sid_map)),
            gate._stream_gen([chunk_dir], "bff", _parse_bff)]
    for e in gate._resort_bounded(heapq.merge(*gens, key=lambda e: e["ts"]), lag=300):
        e["objs"] = object_ids(e["path"])   # tính một lần, dùng lại ở mọi cửa sổ chứa sự kiện
        yield e


# ───────────────────── gán nhãn theo lượt ──────────────────────────────────
class RunIndex:
    """Lượt tấn công/nhiễu theo entity, tra theo khoảng thời gian."""

    def __init__(self, runs: list[dict]):
        self.by_ent = defaultdict(list)
        for r in runs:
            if r.get("entity"):
                self.by_ent[r["entity"]].append(r)
        for lst in self.by_ent.values():
            lst.sort(key=lambda r: r["t0"])
        self.t0s = {k: [r["t0"] for r in v] for k, v in self.by_ent.items()}
        self.max_len = max((r["t1"] - r["t0"] for r in runs), default=0)

    def overlapping(self, entity: str, a: float, b: float) -> list[dict]:
        lst = self.by_ent.get(entity)
        if not lst:
            return []
        hi = bisect.bisect_left(self.t0s[entity], b)
        lo = bisect.bisect_left(self.t0s[entity], a - self.max_len - 1)
        return [r for r in lst[lo:hi] if r["t1"] >= a]


def label_window(entity: str, a: float, b: float, events: list[dict], idx: RunIndex):
    """Đề cương: cửa sổ dương nếu chứa ≥1 lời gọi thuộc một lượt tấn công.
    Khớp entity CHÍNH XÁC (không khớp chuỗi con như `_entity_match`) và dùng
    chữ ký hành vi `is_attack_event` của Giai đoạn B. Cửa sổ nằm trong lượt
    tấn công nhưng không có lời gọi nào của lượt → `attack_idle` (loại khi
    đánh giá, không coi là âm)."""
    runs = idx.overlapping(entity, a, b)
    idle = None
    for r in (x for x in runs if x["class"] == "attack"):
        if any(r["t0"] <= e["ts"] <= r["t1"] and gate.is_attack_event(e, r) for e in events):
            return "attack", r
        idle = idle or r
    if idle:
        return "attack_idle", idle
    for r in runs:
        if r["class"] == "benign_noise":
            return "benign_noise", r
    return "benign", None


# ───────────────────── đặc trưng một cửa sổ ────────────────────────────────
def _entropy(items) -> float:
    c = Counter(items); n = sum(c.values())
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


def _p95(vals):
    if not vals:
        return 0.0
    s = sorted(vals)
    return s[min(len(s) - 1, int(0.95 * len(s)))]


def window_features(events: list[dict], a: float, obj_first: dict, pair_first: dict) -> dict:
    """`obj_first`: đối tượng → lần đầu entity này chạm tới; `pair_first`:
    (src,dst) → lần đầu thấy trên toàn hệ thống. Một đối tượng/cặp là "mới"
    nếu lần đầu xuất hiện của nó nằm TRONG cửa sổ (tức chưa từng có trước a)."""
    req_ids = {e["req_id"] for e in events if e["req_id"]}
    n_req = len(req_ids) or len(events)
    codes = [e["code"] for e in events if e["code"]]
    n_code = len(codes) or 1
    paths = [norm_path(e["path"]) for e in events if e["path"]]
    reads = sum(1 for e in events if e["method"] in ("GET", "HEAD", "OPTIONS"))
    writes = sum(1 for e in events if e["method"] in ("POST", "PUT", "PATCH", "DELETE"))
    ts = sorted(e["ts"] for e in events)
    gaps = [y - x for x, y in zip(ts, ts[1:])]
    gm = statistics.mean(gaps) if gaps else 0.0
    gcv = (statistics.pstdev(gaps) / gm) if len(gaps) > 1 and gm > 0 else 0.0
    byts = [e["bytes"] for e in events if e["bytes"] is not None]
    rts = [e["rt"] for e in events if e["rt"] is not None]
    objs = set().union(*(e["objs"] for e in events)) if events else set()
    n_obj_new = sum(1 for o in objs if obj_first.get(o, a) >= a)
    opa = [e for e in events if e["stream"] == "opa"]
    pairs = {(e["src"], e["dst"]) for e in opa if e["src"] and e["dst"]}
    xpairs = {p for p in pairs if spiffe_cloud(p[0]) and spiffe_cloud(p[1])
              and spiffe_cloud(p[0]) != spiffe_cloud(p[1])}
    n_x = sum(1 for e in opa if spiffe_cloud(e["src"]) and spiffe_cloud(e["dst"])
              and spiffe_cloud(e["src"]) != spiffe_cloud(e["dst"]))
    denies = [e for e in events if e["decision"] is False or e["code"] in ("401", "403")]
    return {
        "n_req": n_req,
        "pct_4xx": sum(1 for c in codes if c.startswith("4")) / n_code,
        "pct_5xx": sum(1 for c in codes if c.startswith("5")) / n_code,
        "n_path": len(set(paths)), "path_entropy": round(_entropy(paths), 4),
        "rw_ratio": reads / writes if writes else float(reads),
        "gap_mean": round(gm, 4), "gap_cv": round(gcv, 4),
        "bytes_sum": sum(byts), "bytes_max": max(byts) if byts else 0.0,
        "rt_p95": _p95(rts),
        "n_obj": len(objs), "n_obj_new": n_obj_new,
        "frac_obj_new": round(n_obj_new / len(objs), 4) if objs else 0.0,
        "n_dst": len({e["dst"] for e in opa if e["dst"]}),
        "n_pair": len(pairs), "n_pair_new": sum(1 for p in pairs if pair_first.get(p, a) >= a),
        "deny_count": len(denies), "deny_rate": round(len(denies) / len(events), 4) if events else 0.0,
        "xcloud_ratio": round(n_x / len(opa), 4) if opa else 0.0,
        "n_xcloud_pair_new": sum(1 for p in xpairs if pair_first.get(p, a) >= a),
        "stepup_present": int(any(e["acr"] in ("high", "2", "3") for e in events)),
        "posture_bad": int(any(e["posture"] not in (None, "", "compliant", "not_reported", "unknown")
                               for e in events)),
    }


# ───────────────────── trượt cửa sổ trên luồng sự kiện ─────────────────────
class History:
    """Trạng thái mang qua các khúc: lần đầu entity chạm đối tượng, lần đầu
    thấy cặp gọi, lần đầu thấy entity."""

    def __init__(self):
        self.obj_first = defaultdict(dict)
        self.pair_first = {}
        self.ent_first = {}

    def observe(self, e: dict):
        ent = e["entity"]
        self.ent_first.setdefault(ent, e["ts"])
        of = self.obj_first[ent]
        for o in e["objs"]:
            of.setdefault(o, e["ts"])
        if e["stream"] == "opa" and e["src"] and e["dst"]:
            self.pair_first.setdefault((e["src"], e["dst"]), e["ts"])


def build_chunk(chunk_dir: str, runs: list[dict], hist: History, out_path: str,
                window=WINDOW, step=STEP, users_only=False) -> dict:
    chunk_id = os.path.basename(os.path.normpath(chunk_dir))
    sid_map = gate.build_sid_map([chunk_dir])
    trace_user, id_stats = build_identity_maps(chunk_dir, sid_map)
    idx = RunIndex(runs)
    buf = defaultdict(deque)          # entity → sự kiện trong `window` giây gần nhất
    labels, n_rows = Counter(), 0
    next_b = None
    fh = gzip.open(out_path, "wt", newline="")
    w = csv.DictWriter(fh, fieldnames=META + FEATURES_A + FEATURES_B)
    w.writeheader()

    def emit(b):
        nonlocal n_rows
        a = b - window
        for ent in list(buf):
            q = buf[ent]
            while q and q[0]["ts"] < a:
                q.popleft()
            if not q:
                del buf[ent]
                continue
            evs = [e for e in q if e["ts"] < b]
            if not evs or ent in ("?", ""):
                continue
            etype = "user" if any(e["entity_type"] == "user" for e in evs) else "workload"
            if users_only and etype != "user":
                continue
            lab, run = label_window(ent, a, b, evs, idx)
            row = {"chunk_id": chunk_id, "window_start": a, "window_end": b, "entity": ent,
                   "entity_type": etype, "label": lab,
                   "run_id": (run or {}).get("run_id", ""),
                   "scenario": gate._norm_scenario((run or {}).get("scenario", "")),
                   "variant_group": (run or {}).get("variant_group", ""),
                   "hist_sec": round(a - hist.ent_first.get(ent, a), 1)}
            row.update(window_features(evs, a, hist.obj_first[ent], hist.pair_first))
            w.writerow(row)
            labels[lab] += 1
            n_rows += 1

    n_ev = 0
    for e in iter_events(chunk_dir, sid_map, trace_user):
        n_ev += 1
        if next_b is None:
            next_b = (math.floor(e["ts"] / step) + 1) * step
        while e["ts"] >= next_b:
            emit(next_b)
            next_b += step
        hist.observe(e)
        buf[e["entity"]].append(e)
    if next_b is not None:   # xả các cửa sổ còn mở ở cuối khúc
        end = next_b + window
        while next_b <= end and buf:
            emit(next_b)
            next_b += step
    fh.close()
    meta = {"chunk_id": chunk_id, "n_events": n_ev, "n_rows": n_rows,
            "labels": dict(labels), "identity": dict(id_stats),
            "sid_map": len(sid_map), "trace_user": len(trace_user),
            "window": window, "step": step, "table": out_path}
    return meta


# ───────────────────── CLI ─────────────────────────────────────────────────
def cmd_inspect(chunk_dir: str, n=2):
    """Kiểm nhanh trên máy thu trước khi chạy dài: khoá trường thật của từng
    luồng và độ phủ gán user (cookie / JWT / không gán được)."""
    for name in ("envoy", "opa", "bff"):
        p = gate._stream_path(chunk_dir, name)
        print(f"== {name}: {p}")
        if not p:
            continue
        with gate._open_any(p) as fh:
            for i, raw in enumerate(fh):
                if i >= n:
                    break
                r = json.loads(raw); b = gate._body(r)
                keys = sorted(b.keys())
                if name == "opa":
                    h = _opa_http(b).get("headers") or {}
                    keys += ["headers:" + ",".join(sorted(h.keys()))]
                print("   labels:", sorted(r.get("labels", {}).keys()))
                print("   body  :", keys)
    sid_map = gate.build_sid_map([chunk_dir])
    trace_user, st = build_identity_maps(chunk_dir, sid_map)
    tot = st.get("opa_events", 0) or 1
    print(f"== gán user cho OPA: cookie={st['user_from_cookie']/tot:.1%} "
          f"jwt={st['user_from_jwt']/tot:.1%} không={st['user_from_none']/tot:.1%} "
          f"(sid_map={len(sid_map)}, trace_user={len(trace_user)})")


def cmd_build(chunks: list[str], runs_file: str, out_dir: str, window: int, step: int, users_only: bool):
    os.makedirs(out_dir, exist_ok=True)
    runs = gate.load_runs(runs_file)
    hist = History()
    metas = []
    for d in chunks:
        cid = os.path.basename(os.path.normpath(d))
        out = os.path.join(out_dir, f"{cid}__features_v2_w{window}s{step}.csv.gz")
        m = build_chunk(d, runs, hist, out, window, step, users_only)
        metas.append(m)
        print(f"[v2] {cid}: events={m['n_events']} rows={m['n_rows']} labels={m['labels']} "
              f"identity={m['identity']}", flush=True)
    json.dump(metas, open(os.path.join(out_dir, "features_v2_meta.json"), "w"),
              indent=2, ensure_ascii=False)


def _jwt(claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


def cmd_selftest():
    """Sinh một khúc giả nhỏ đúng định dạng export (envoy/opa/bff.jsonl.gz),
    gồm một lượt BOLA bằng Bearer (không cookie) và lưu lượng nền, rồi kiểm:
    gán user qua JWT, đối tượng UUID, đặc trưng mới/cũ, nhãn attack."""
    d = tempfile.mkdtemp(prefix="fv2_")
    chunk = os.path.join(d, "c9999-test"); os.makedirs(chunk)
    t0 = 1_800_000_000.0
    own, victims = "11111111-1111-1111-1111-111111111111", [
        "22222222-2222-2222-2222-22222222222%d" % i for i in range(5)]
    sess = base64.urlsafe_b64encode(json.dumps({"sid": "S1"}).encode()).decode().rstrip("=")
    envoy, opa, bff = [], [], []

    def req(ts, user_hdr, path, rid, code="200"):
        opa.append({"ts_ns": str(int(ts * 1e9)), "labels": {"opa_result": "true"},
                    "line": json.dumps({"result": True, "input": {"attributes": {
                        "source": {"principal": "spiffe://ztlab.local/aws/waf"},
                        "destination": {"principal": "spiffe://ztlab.local/openstack/crapi-identity"},
                        "request": {"http": {"method": "GET", "path": path,
                                             "headers": dict(user_hdr, **{"x-request-id": rid})}}}}})})
        envoy.append({"ts_ns": str(int(ts * 1e9 + 1e6)), "labels": {},
                      "line": json.dumps({"trace_id": rid, "method": "GET", "path": path,
                                          "response_code": code, "bytes_sent": 300,
                                          "response_time": 20, "svid": "spiffe://ztlab.local/aws/bff"})})

    bff.append({"ts_ns": str(int(t0 * 1e9)), "labels": {},
                "line": json.dumps({"event": "token_refreshed", "sid": "S1", "username": "victim01", "ts": t0})})
    # nền: victim01 (cookie) đọc xe của chính mình mỗi 20 s trong 30 phút
    for i in range(90):
        req(t0 + 20 * i, {"cookie": f"ztlab_bff_session={sess}.mac"},
            f"/identity/api/v2/vehicle/{own}/location", f"n{i}")
    # nền của attacker01 (Bearer) trước khi tấn công: đọc xe của mình
    for i in range(20):
        req(t0 + 30 * i, {"authorization": "Bearer " + _jwt({"sub": "attacker01@ztlab.local"})},
            "/identity/api/v2/vehicle/33333333-3333-3333-3333-333333333333/location", f"m{i}")
    # BOLA burst lúc t0+900: attacker01 đọc 5 xe của người khác
    ta = t0 + 900
    for i, v in enumerate(victims):
        req(ta + i, {"authorization": "Bearer " + _jwt({"sub": "attacker01@ztlab.local"})},
            f"/identity/api/v2/vehicle/{v}/location", f"a{i}")
    for name, rows in (("envoy", envoy), ("opa", opa), ("bff", bff)):
        with gzip.open(os.path.join(chunk, name + ".jsonl.gz"), "wt") as fh:
            for r in sorted(rows, key=lambda r: int(r["ts_ns"])):
                fh.write(json.dumps(r) + "\n")
    from datetime import datetime, timezone
    iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    runs_file = os.path.join(d, "runs.jsonl")
    with open(runs_file, "w") as fh:
        fh.write(json.dumps({"run_id": "R1", "scenario": "bola", "class": "attack", "status": "attack",
                             "variant_group": "train:bola_burst_lo", "target_entity": "attacker01",
                             "victims_used": victims, "t_start": iso(ta - 1), "t_end": iso(ta + 6)}) + "\n")

    assert object_ids("/workshop/api/mechanic/mechanic_report?report_id=6") == {"report_id:6"}
    assert object_ids(f"/identity/api/v2/vehicle/{own.upper()}/location") == {"uuid:" + own}
    assert jwt_user("Bearer " + _jwt({"preferred_username": "testuser01"})) == "testuser01"
    out = os.path.join(d, "out")
    cmd_build([chunk], runs_file, out, WINDOW, STEP, users_only=False)
    rows = list(csv.DictReader(gzip.open(os.path.join(out, "c9999-test__features_v2_w300s60.csv.gz"), "rt")))
    atk = [r for r in rows if r["label"] == "attack"]
    assert atk, "phải có cửa sổ attack (BOLA bằng Bearer)"
    assert all(r["entity"] == "attacker01" and r["run_id"] == "R1" for r in atk)
    assert max(int(r["n_obj_new"]) for r in atk) == 5, [r["n_obj_new"] for r in atk]
    ben = [r for r in rows if r["entity"] == "victim01"]
    assert ben and all(r["label"] == "benign" for r in ben)
    assert max(int(r["n_obj_new"]) for r in ben if float(r["window_start"]) > t0 + 300) == 0
    print(f"[selftest] OK — {len(rows)} cửa sổ, {len(atk)} attack, "
          f"n_obj_new(attack)={sorted({r['n_obj_new'] for r in atk})}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("inspect"); i.add_argument("--chunk", required=True)
    b = sub.add_parser("build")
    b.add_argument("--chunks", required=True, help="thư mục khúc, phân cách bằng dấu phẩy, theo thứ tự thời gian")
    b.add_argument("--runs", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--window", type=int, default=WINDOW)
    b.add_argument("--step", type=int, default=STEP)
    b.add_argument("--users-only", action="store_true", help="chỉ ghi cửa sổ của entity là người dùng")
    sub.add_parser("selftest")
    a = ap.parse_args()
    if a.cmd == "inspect":
        cmd_inspect(a.chunk)
    elif a.cmd == "build":
        cmd_build([c for c in a.chunks.split(",") if c], a.runs, a.out, a.window, a.step, a.users_only)
    else:
        cmd_selftest()


if __name__ == "__main__":
    main()
