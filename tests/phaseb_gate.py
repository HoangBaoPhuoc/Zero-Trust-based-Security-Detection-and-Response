#!/usr/bin/env python3
"""Giai đoạn B §5 — PIPELINE CỔNG 2 GIỜ (export → gán nhãn offline → bảng đặc
trưng → mô hình vứt đi → 3 kiểm tra bắt buộc).

Mục đích của cổng KHÔNG phải ra một mô hình tốt, mà để xác nhận TRƯỚC khi thu
150 giờ:
  (a) mọi đặc trưng trong docs/FEATURES-GIAIDOAN-C.md tính được từ log THẬT;
  (b) không đặc trưng nào rò rỉ nhãn (label leakage) do cách sinh dữ liệu;
  (c) bài toán đủ KHÓ — mô hình phân biệt được nhưng không hoàn hảo, và TỐT HƠN
      luật đơn giản deny_count>0 (nếu không: vấn đề thiết kế dữ liệu, không phải mô hình).

Không phụ thuộc thư viện ngoài: dùng GradientBoosting của sklearn nếu có, nếu
không rơi về random forest thuần Python (vẫn khai thác được rò rỉ → vẫn bắt được
"quá dễ"). Chạy trên host thu, không cần cài gì.

Lệnh:
  export  --loki URL --start EPOCH --end EPOCH --out DIR
  run     --logs DIR --runs runs.jsonl [--window 60 --step 60] --out DIR
  synth   --out DIR            # sinh log + runs.jsonl giả để TỰ KIỂM pipeline
  selftest                     # synth + run, khẳng định pipeline chạy trọn
"""
from __future__ import annotations
import argparse, base64, csv, gzip, heapq, json, math, os, random, re, statistics, sys, time, urllib.parse, urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ───────────────────────── tiện ích thời gian ─────────────────────────
def iso_to_epoch(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()

# ───────────────────────── 1) EXPORT từ Loki ──────────────────────────
STREAMS = {
    "envoy":  '{job="envoy-access"}',
    "opa":    '{job="opa-decisions"}',
    "bff":    '{job="bff-audit"}',
}
def loki_export(loki_url: str, start_e: float, end_e: float, out_dir: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    counts = {}
    for name, sel in STREAMS.items():
        # §B6 mục 2: ghi .jsonl.gz thẳng lúc export — JSONL lặp cùng bộ khoá nén
        # 8-15 lần, 150h không nén ≈46GB vượt đĩa hiện có; nén ngay từ đầu để
        # đĩa không bao giờ đầy giữa đợt thu nữa.
        path = os.path.join(out_dir, f"{name}.jsonl.gz")
        n = 0
        # B3 mục 2.3 — ROOT CAUSE: Loki giới hạn gRPC frontend<->querier ở
        # 4 MiB/response (mặc định). Dòng log opa-decisions chứa nguyên input
        # chính sách (JWT, header, kết quả) nên nặng hơn envoy/bff nhiều —
        # limit=5000 vượt 4 MiB ngay cả trên cửa sổ vài phút, Loki trả về
        # lỗi "ResourceExhausted" ở tầng server (thấy trong log pod loki,
        # không thấy ở client) và chết dần do retry nội bộ rồi "context
        # canceled" — client Python chỉ thấy urlopen TIMEOUT. Lỗi KHÔNG bắt
        # (try/except) nên văng khỏi vòng for, "opa" dừng giữa trang ĐẦU
        # TIÊN (file rỗng) và "bff" (đến sau trong STREAMS) KHÔNG BAO GIỜ
        # được export — toàn bộ nhãn sau đó chỉ còn envoy (entity=principal
        # dịch vụ, không phải username) → is_attack_event không bao giờ khớp
        # entity "testuser01" → 100% attack_idle. Đã đo trực tiếp: limit=1000
        # còn chạy được (<4 MiB), limit=2000 đã treo. Dùng PAGE_SIZE nhỏ,
        # có margin rộng, và lùi (retry) với trang nhỏ hơn nếu vẫn lỗi, để
        # không phụ thuộc đúng ngưỡng 4 MiB (payload mỗi dòng có thể dao động).
        PAGE_SIZE = 400
        cur = int(start_e * 1e9); end_ns = int(end_e * 1e9)
        try:
            with gzip.open(path, "wt") as fh:
                while cur < end_ns:
                    page = PAGE_SIZE
                    while True:
                        qs = urllib.parse.urlencode({"query": sel, "start": str(cur), "end": str(end_ns),
                                                     "limit": page, "direction": "forward"})
                        url = f"{loki_url}/loki/api/v1/query_range?{qs}"
                        try:
                            data = json.load(urllib.request.urlopen(url, timeout=60))["data"]["result"]
                            break
                        except Exception as ex:
                            if page <= 25:
                                raise
                            page = max(25, page // 4)
                            print(f"[export] {name}: trang {PAGE_SIZE} lỗi ({ex}) — thử lại với limit={page}")
                    last = cur
                    for stream in data:
                        labels = stream["stream"]
                        for ts, line in stream["values"]:
                            fh.write(json.dumps({"ts_ns": ts, "labels": labels, "line": line}) + "\n")
                            n += 1; last = max(last, int(ts))
                    if not data or last <= cur:
                        break
                    cur = last + 1
        except Exception as ex:
            print(f"[export] {name}: THẤT BẠI sau khi thu {n} dòng — {ex} — các luồng còn lại VẪN export tiếp")
        counts[name] = n
        print(f"[export] {name}: {n} dòng → {path}")
    return counts

# ───────────────────── 2) CHUẨN HOÁ log → sự kiện ─────────────────────
def _norm_path(p: str) -> str:
    p = p.split("?")[0]
    # chuẩn hoá tham số số/uuid thành {id} để path-class ổn định
    import re
    p = re.sub(r"/\d+", "/{id}", p)
    p = re.sub(r"/[0-9a-fA-F-]{8,}", "/{id}", p)
    return p

def _target_ids(p: str):
    import re
    return set(re.findall(r"/(\d+)(?:/|$)", p.split("?")[0]))

def _make_envoy_parser(trace_map: dict):
    """§C1c mục 2 — trả hàm _parse_envoy_line đã đóng gói trace_map.
    trace_map: trace_id → username (xây từ build_trace_map()).
    Envoy không có cookie; quy danh tính qua trace_id = opa.x-request-id."""
    def _parse_envoy_line(raw: str) -> dict:
        r = json.loads(raw); b = _body(r)
        ts = int(r["ts_ns"]) / 1e9
        code = str(b.get("response_code", r["labels"].get("response_code", "")))
        tid = b.get("trace_id", "")
        entity = trace_map.get(tid) if tid else None
        if not entity:
            entity = _princ(b.get("svid") or r["labels"].get("source_ip", ""))
        return dict(ts=ts, stream="envoy", entity=entity,
            method=b.get("method", r["labels"].get("method", "")),
            path=b.get("path", r["labels"].get("path", "")),
            code=code, decision=None, dest=None,
            posture=None, stepup=None, reason=None, sid=None,
            bytes=_num(b.get("bytes_sent")), ust=_num(b.get("upstream_service_time")),
            rt=_num(b.get("response_time")))
    return _parse_envoy_line

def _parse_envoy_line(raw: str) -> dict:
    """Compat — không có trace_map → entity luôn là SVID dịch vụ.
    Chỉ dùng cho synth/selftest. Đường thật gọi _make_envoy_parser(trace_map)."""
    return _make_envoy_parser({})(raw)

def _decode_sid(cookie: str) -> str:
    """§C1 mục 5.1 — quy danh tính người dùng về OPA event.
    Giải mã session cookie ztlab_bff_session → trả sid (chuỗi) hoặc "" nếu lỗi.
    Cookie format: ztlab_bff_session=<base64url({"sid":"..."})>.<mac>.
    Chỉ dùng phần trước dấu chấm thứ nhất (payload Flask-session)."""
    if "ztlab_bff_session=" not in cookie:
        return ""
    enc = cookie.split("ztlab_bff_session=")[1].split(";")[0].split(".")[0]
    try:
        pad = len(enc) % 4
        if pad:
            enc += "=" * (4 - pad)
        return json.loads(base64.urlsafe_b64decode(enc)).get("sid", "")
    except Exception:
        return ""

def _make_opa_parser(sid_map: dict):
    """§C1 mục 5.1 — trả hàm _parse_opa_line đã đóng gói sid_map.
    Nếu OPA event mang session cookie của người dùng đã biết, ghi đè entity
    từ SVID dịch vụ (waf/bff) sang username thực — cho phép is_attack_event()
    khớp lượt tấn công thành công (BOLA, large_response, privilege_escalation)
    vốn không sinh deny và do đó không bao giờ xuất hiện trong BFF auth events."""
    def _parse_opa_line(raw: str) -> dict:
        r = json.loads(raw); b = _body(r)
        ts = int(r["ts_ns"]) / 1e9
        inp = (b.get("input") or {}).get("attributes") or {}
        http = (inp.get("request") or {}).get("http") or {}
        src = (inp.get("source") or {}).get("principal") or b.get("svid") or r["labels"].get("source_principal", "")
        dec = b.get("result")
        if dec is None and "opa_result" in r["labels"]:
            dec = (r["labels"]["opa_result"] == "true")
        # §C1 mục 5.1: quy username từ session cookie — ưu tiên user hơn SVID dịch vụ
        sid = _decode_sid(http.get("headers", {}).get("cookie", ""))
        entity = sid_map.get(sid) if sid else None
        if not entity:
            entity = _princ(src)
        return dict(ts=ts, stream="opa", entity=entity,
            method=http.get("method", b.get("action", "")),
            path=http.get("path", b.get("resource", r["labels"].get("request_path", ""))),
            code=None, decision=(dec if isinstance(dec, bool) else None),
            dest=(inp.get("destination") or {}).get("principal"),
            posture=b.get("device_posture"), stepup=b.get("step_up"),
            reason=None, sid=sid or None, bytes=None, ust=None, rt=None)
    return _parse_opa_line

def _parse_opa_line(raw: str) -> dict:
    """Hàm tương thích cũ — không có sid_map → entity luôn là SVID dịch vụ.
    Chỉ dùng cho synth/selftest. Đường thật gọi _make_opa_parser(sid_map)."""
    return _make_opa_parser({})(raw)

def _parse_bff_line(raw: str) -> dict:
    r = json.loads(raw); b = _body(r)
    ts = b.get("ts") or int(r["ts_ns"]) / 1e9
    ev = b.get("event", "")
    denied = ev in ("rbac_denied", "device_trust_denied", "step_up_required")
    return dict(ts=float(ts), stream="bff", entity=b.get("username") or "?",
        method=None, path=b.get("path"), code=("403" if denied else None),
        decision=(False if denied else None), dest=None,
        posture=None, stepup=b.get("acr"), reason=ev, sid=b.get("sid"),
        bytes=None, ust=None, rt=None)

_STREAM_PARSERS = {"envoy": _parse_envoy_line, "opa": _parse_opa_line, "bff": _parse_bff_line}

def _stream_path(chunk_dir: str, name: str):
    for ext in (".jsonl.gz", ".jsonl"):
        p = os.path.join(chunk_dir, name + ext)
        if os.path.exists(p):
            return p
    return None

def _open_any(path: str):
    return gzip.open(path, "rt") if path.endswith(".gz") else open(path, "r")

def _stream_gen(chunk_dirs, name, parser):
    """Sinh sự kiện của MỘT luồng qua N khúc, theo thứ tự khúc truyền vào. Mỗi
    file khúc đã sắp theo thời gian lúc export, và các khúc được gọi theo thứ
    tự thời gian (ID khúc tăng dần) → luồng nối ra vẫn đơn điệu theo ts, không
    cần sort lại."""
    for d in chunk_dirs:
        p = _stream_path(d, name)
        if not p:
            continue
        with _open_any(p) as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                yield parser(raw)

def _resort_bounded(events_iter, lag=300):
    """§B6 mục 1 — PHÁT HIỆN TRONG LÚC KIỂM (2026-10-16): giả định "mỗi file
    khúc đã sắp theo thời gian" SAI ở mức tiểu tiết — loki_export trả nhiều
    'stream' Loki (mỗi stream = một tổ hợp label, vd mỗi pod/replica) trong
    CÙNG một trang, rồi nối các stream đó TUẦN TỰ (hết stream này mới ghi
    stream khác); từng stream riêng tăng dần, nhưng NỐI CHÚNG LẠI không còn
    đơn điệu toàn cục — đo thực tế trên khúc 1: lệch tối đa ~28s (90% sự kiện
    lệch >1s). heapq.merge giả định MỖI nguồn đã sort nên chỉ sửa được lệch
    GIỮA 3 luồng, không sửa được lệch BÊN TRONG một luồng — kết quả: cùng một
    cửa sổ (entity, w0) bị mở/đóng lặp lại nhiều lần → hàng chục nghìn dòng
    đặc trưng TRÙNG (đã bắt được qua kiểm so khớp với bản nạp-hết-vào-RAM, xem
    ghi chú kiểm thử). Sửa: đệm TRỄ CÓ HẠN (heap, lag giây) — giữ sự kiện tới
    khi mốc max đã vượt (ts_max_đã_thấy - lag) mới PHÁT ra, đảm bảo thứ tự
    ĐÚNG tuyệt đối miễn lệch thật ≤ lag. lag=300s (margin ~10× lệch đo được)
    — bộ nhớ = O(số sự kiện trong lag giây) ≈ vài nghìn, KHÔNG O(tổng dữ
    liệu đã thu, bất kể 150h bao nhiêu khúc)."""
    heap = []
    seq = 0
    max_ts = float("-inf")
    for e in events_iter:
        ts = e["ts"]
        if ts > max_ts:
            max_ts = ts
        seq += 1
        heapq.heappush(heap, (ts, seq, e))
        while heap and heap[0][0] <= max_ts - lag:
            yield heapq.heappop(heap)[2]
    while heap:
        yield heapq.heappop(heap)[2]

def build_sid_map(chunk_dirs) -> dict:
    """§C1 mục 5.1 — đọc trước BFF audit log của các khúc để xây bản đồ
    sid→username. BFF ghi sid trong token_refreshed, rbac_denied,
    device_trust_denied, step_up_required (không ghi trong user_login).
    Gọi TRƯỚC iter_events() và truyền map vào qua sid_map."""
    m = {}
    for d in chunk_dirs:
        p = _stream_path(d, "bff")
        if not p:
            continue
        with _open_any(p) as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    r = json.loads(raw)
                    b = _body(r)
                    sid = b.get("sid"); user = b.get("username", "")
                    if sid and user:
                        m[sid] = user
                except Exception:
                    pass
    return m

def build_trace_map(chunk_dirs, sid_map: dict) -> dict:
    """§C1c mục 2 — đọc trước OPA log, trích x-request-id → username.
    x-request-id trong OPA = trace_id trong Envoy (UUID giống nhau).
    Cho phép _make_envoy_parser() quy bytes_sent về username,
    giải quyết bytes_max/bytes_sum = 0 cho large_response.
    Gọi SAU build_sid_map (cần sid_map đã xây), TRƯỚC iter_events()."""
    m = {}
    for d in chunk_dirs:
        p = _stream_path(d, "opa")
        if not p:
            continue
        with _open_any(p) as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    r = json.loads(raw)
                    b = _body(r)
                    inp = (b.get("input") or {}).get("attributes") or {}
                    http = (inp.get("request") or {}).get("http") or {}
                    tid = http.get("headers", {}).get("x-request-id", "")
                    if not tid:
                        continue
                    cookie = http.get("headers", {}).get("cookie", "")
                    sid = _decode_sid(cookie) if cookie else ""
                    user = sid_map.get(sid) if sid else None
                    if user:
                        m[tid] = user
                except Exception:
                    pass
    return m

def iter_events(chunk_dirs, resort_lag=300, sid_map=None, trace_map=None):
    """§B6 mục 1 — ROOT CAUSE: bản cũ nạp TOÀN BỘ sự kiện vào MỘT list Python
    rồi sort() — ở 150h (~24 khúc, ~28 triệu sự kiện) cần 10-20GB RAM, bị hệ
    thống OOM-kill. Hợp N khúc × 3 luồng bằng heapq.merge theo khoá ts (mỗi
    luồng gần-đơn-điệu, xem _stream_gen), rồi sắp lại có hạn (_resort_bounded)
    để sửa lệch nhỏ CÒN SÓT (xem _resort_bounded) — toàn bộ STREAMING, bộ nhớ
    O(số luồng + số sự kiện trong resort_lag giây), KHÔNG O(tổng số sự kiện),
    bất kể thu bao nhiêu khúc.
    §C1 mục 5.1: sid_map → OPA entity attribution.
    §C1c mục 2: trace_map → Envoy bytes/ust/rt attribution về username."""
    opa_parser = _make_opa_parser(sid_map or {})
    envoy_parser = _make_envoy_parser(trace_map or {})
    parsers = {"envoy": envoy_parser, "opa": opa_parser, "bff": _parse_bff_line}
    gens = [_stream_gen(chunk_dirs, name, parser) for name, parser in parsers.items()]
    merged = heapq.merge(*gens, key=lambda e: e["ts"])
    return _resort_bounded(merged, lag=resort_lag)

def parse_events(logs_dir: str) -> list[dict]:
    """Tương thích cũ — CHỈ dùng cho synth/selftest (dữ liệu nhỏ, nạp hết an
    toàn). Đường thu thật (run()) dùng iter_events()/events_factory, KHÔNG
    bao giờ gọi hàm này trên log thật."""
    return list(iter_events([logs_dir]))

def _body(r: dict) -> dict:
    try: return json.loads(r["line"])
    except Exception: return {}
def _num(x):
    try: return float(x)
    except (TypeError, ValueError): return None
def _princ(s: str) -> str:
    # spiffe://ztlab.local/aws/bff → bff ; giữ nguyên nếu không phải spiffe
    if not s: return "?"
    return s.rstrip("/").split("/")[-1] if "spiffe://" in s else s

# ───────────────────── 3) GÁN NHÃN offline từ runs.jsonl ───────────────
def load_runs(runs_file: str) -> list[dict]:
    runs = []
    for l in open(runs_file):
        l = l.strip()
        if not l: continue
        d = json.loads(l)
        if "t_start" not in d or "t_end" not in d: continue
        # runs.jsonl DÙNG CHUNG với sổ cái thu theo khúc (collect_chunked.py ghi
        # {chunk_id,t_start,t_end,status}). CHỈ nhận bản ghi tấn công/nhiễu —
        # nhận diện bằng class ∈ {attack, benign_noise}. Bản ghi chunk (không có
        # class đó, hoặc có chunk_id) bị bỏ qua.
        cls = d.get("class")
        if cls not in ("attack", "benign_noise") or "chunk_id" in d:
            continue
        # lượt attack aborted KHÔNG tính (H18)
        if cls == "attack" and d.get("status") == "aborted":
            continue
        runs.append({"class": d.get("class", "attack"),
                     "entity": str(d.get("target_entity", "")),
                     "variant_group": d.get("variant_group", ""),
                     "scenario": d.get("scenario", ""),
                     "run_id": d.get("run_id", ""),
                     "victims_used": d.get("victims_used") or [],   # §B1b
                     "t0": iso_to_epoch(d["t_start"]), "t1": iso_to_epoch(d["t_end"])})
    return runs

# §B7 mục 1 — BUG: is_attack_event() dispatch theo run["scenario"] nguyên văn.
# crapi_campaign_phaseb.sh ghi SCENARIO=<family name> (đúng), nhưng dữ liệu đã
# thu (chunk 1-9, một phần trước khi override family-name tồn tại/một số
# đường gọi khác) lẫn tên THÔ "crapi_<script>.sh" cho 6/7 họ — chỉ bola ghi
# đúng cả hai kiểu vì tên family == tên script (không có hậu tố _spike/
# _escalation...). CHUẨN HOÁ ở matcher (rẻ hơn sửa 6 script ghi, miễn nhiễm
# với dữ liệu đã thu): strip tiền tố "crapi_", strip đuôi ".sh". Một mismatch
# KHÁC đã lộ ra khi chuẩn hoá: family "access_denied_spike" dùng script
# "crapi_access_denied.sh" (KHÔNG có "_spike" trong tên script) → cần alias
# tường minh sau khi strip, không chỉ strip tiền tố/hậu tố.
_SCENARIO_ALIASES = {"access_denied": "access_denied_spike"}

def _norm_scenario(name: str) -> str:
    if not name:
        return name
    n = name.strip()
    if n.startswith("crapi_"):
        n = n[len("crapi_"):]
    if n.endswith(".sh"):
        n = n[:-3]
    return _SCENARIO_ALIASES.get(n, n)

# Các tên scenario CÓ xử lý tường minh trong is_attack_event(). Dùng để phát
# hiện tên lạ (§B7 mục 1 — rào chắn: nhánh mặc định không được âm thầm = True).
_KNOWN_SCENARIOS = {"bola", "lateral_movement", "access_denied_spike", "bfla",
                     "large_response", "brute_force", "privilege_escalation"}

def is_attack_event(e: dict, run: dict) -> bool:
    """§B1d: sự kiện này có PHẢI là một request của CHÍNH lượt tấn công không
    (không chỉ 'cùng entity, cùng khoảng thời gian'). Dùng CHỮ KÝ hành vi của
    kịch bản (không marker tiêm): bola khớp path vehicle/{id}/location với id
    thuộc victims_used đã ghi; các họ dựa-deny khớp deny; v.v.
    §B7 mục 1: `run["scenario"]` CHUẨN HOÁ qua _norm_scenario() (xem định nghĩa
    ở trên) nên cả "brute_force" và "crapi_brute_force.sh" cùng khớp. Mặc định
    (tên scenario KHÔNG nhận ra, dù đã chuẩn hoá) KHÔNG còn `return True` âm
    thầm (lỗi gốc: `return deny or True` luôn True bất kể deny, vô hiệu hoá
    attack_idle cho mọi event của họ lạ) — fallback AN TOÀN giống các họ
    dựa-deny: chỉ event bị deny mới tính là tấn công. run() đếm/báo riêng tên
    lạ vào `unknown_scenario_runs` (rào chắn phát hiện ca tiếp theo cùng loại,
    không im lặng như trước)."""
    sc = _norm_scenario(run.get("scenario", ""))
    p = e.get("path") or ""
    deny = (e.get("decision") is False) or (e.get("code") in ("401", "403"))
    if sc == "bola":
        if "/location" not in p:
            return False
        vu = set(run.get("victims_used") or [])
        ids = set(_target_ids(p)) | set(_UUID_RE.findall(p))
        return bool(ids & vu) if vu else True   # không có victims_used → mọi location coi là tấn công
    if sc in ("lateral_movement", "access_denied_spike", "bfla"):
        return deny
    if sc == "large_response":
        return ("posts/recent" in p) or ((e.get("bytes") or 0) > 500000)
    if sc in ("brute_force", "privilege_escalation"):
        return True
    return deny   # mặc định AN TOÀN (§B7 mục 1): KHÔNG còn `or True`

def label_for(entity: str, ts: float, runs: list[dict]) -> tuple[str, str]:
    """Trả (class, variant_group). Khớp theo (entity, [t0,t1]); entity so khớp lỏng
    (username == target, hoặc principal chứa target) để bắc cầu liên-stream."""
    best = ("benign", "")   # mặc định N1
    for r in runs:
        if r["t0"] <= ts <= r["t1"] and _entity_match(entity, r["entity"]):
            # attack ưu tiên hơn benign_noise nếu chồng lấn (hiếm)
            if r["class"] == "attack":
                return ("attack", r["variant_group"])
            best = ("benign_noise", r["variant_group"])
    return best

def _entity_match(ev_entity: str, run_entity: str) -> bool:
    if not run_entity: return True   # run không chỉ entity → khớp theo thời gian
    return ev_entity == run_entity or run_entity in ev_entity or ev_entity in run_entity

# ───────────────────── 4) BẢNG ĐẶC TRƯNG per (entity, window) ──────────
FEATURES = ["deny_count","deny_rate","n_dest","n_path","n_target","n_actionclass",
            "rw_ratio","gap_mean","gap_var","code_4xx","code_5xx","reason_kinds",
            "ust_p95","ust_max","rt_p95","n_actions","stepup_present","posture_bad",
            "bytes_max","bytes_sum"]

def _pct(vals, q):
    vals = sorted(v for v in vals if v is not None)
    if not vals: return 0.0
    k = min(len(vals) - 1, int(q * (len(vals) - 1)))
    return float(vals[k])

def featurize(events_factory, runs: list[dict], window: int, step: int):
    """§B6 mục 1: nếu window==step (TRƯỜNG HỢP DUY NHẤT dùng trong run() và
    recall_by_window_width — xem CLI defaults 60/60 và các widths 60/300/600
    trong recall_by_window_width, luôn w,w) → đường STREAMING, bộ nhớ bounded
    (_featurize_streaming). Nếu ai gọi với window!=step (sliding, KHÔNG dùng ở
    B6) → rơi về bản cũ nạp hết vào list (_featurize_inmemory), đúng-nhưng-nặng
    RAM, chỉ an toàn trên dữ liệu nhỏ; KHÔNG dùng trên log thật 150h."""
    if window != step:
        events = list(events_factory() if callable(events_factory) else events_factory)
        return _featurize_inmemory(events, runs, window, step)
    return _featurize_streaming(events_factory, runs, window, step)

def _featurize_inmemory(events: list[dict], runs: list[dict], window: int, step: int):
    """§B1d: nhãn cửa sổ THEO REQUEST THẬT, không theo khoảng thời gian.
      - attack: tile mỗi lượt attack trên lưới; cửa sổ CHỨA ≥1 request của lượt
        (is_attack_event) → 'attack'; cửa sổ trong [t0,t1] nhưng KHÔNG có request
        của lượt → 'attack_idle' (ĐẾM riêng, LOẠI khỏi train/test).
      - benign/benign_noise: cửa sổ per-entity NGOÀI mọi khoảng attack.
    Trả (rows, idle_by_group). CHỈ dùng khi window!=step (xem featurize())."""
    attack_runs = [r for r in runs if r["class"] == "attack"]
    noise_runs = [r for r in runs if r["class"] == "benign_noise"]
    rows = []; idle = Counter()

    def in_attack(ent, w0, we):
        for r in attack_runs:
            if _entity_match(ent, r["entity"]) and not (we <= r["t0"] or w0 > r["t1"]):
                return True
        return False

    # 1) ATTACK: tile từng lượt
    for i, r in enumerate(attack_runs):
        rid = r.get("run_id") or f"{r['variant_group']}#{i}"
        ent_evs = [e for e in events if _entity_match(e["entity"], r["entity"])]
        w0 = math.floor(r["t0"] / step) * step
        while w0 <= r["t1"]:
            we = w0 + window
            if we <= r["t0"]:
                w0 += step; continue
            win = [e for e in ent_evs if w0 <= e["ts"] < we and r["t0"] <= e["ts"] <= r["t1"]]
            if any(is_attack_event(e, r) for e in win):
                row = _feat(win)
                row.update(entity=r["entity"], wstart=w0, label="attack",
                           variant_group=r["variant_group"], run_id=rid,
                           run_t0=r["t0"], scenario=r.get("scenario", ""))   # §B1e: độ trễ
                rows.append(row)
            else:
                # §B7 mục 1: khoá kèm scenario ĐÃ CHUẨN HOÁ để báo cáo tách theo họ
                idle[(r["variant_group"] or "attack", _norm_scenario(r.get("scenario", "")))] += 1
            w0 += step

    # 2) BENIGN / BENIGN_NOISE: per-entity, cửa sổ NGOÀI mọi khoảng attack
    by_ent = defaultdict(list)
    for e in events: by_ent[e["entity"]].append(e)
    for ent, evs in by_ent.items():
        if ent in ("?", ""): continue
        evs.sort(key=lambda e: e["ts"])
        tmin = evs[0]["ts"]; tmax = evs[-1]["ts"]; w0 = math.floor(tmin / step) * step
        while w0 <= tmax:
            we = w0 + window
            if in_attack(ent, w0, we):
                w0 += step; continue
            win = [e for e in evs if w0 <= e["ts"] < we]
            if win:
                lab, vg = "benign", ""
                for e in win:
                    l, v = label_for(ent, e["ts"], noise_runs)
                    if l == "benign_noise":
                        lab, vg = "benign_noise", v; break
                row = _feat(win)
                row.update(entity=ent, wstart=w0, label=lab, variant_group=vg, run_id="")
                rows.append(row)
            w0 += step
    return rows, idle

def _window_count(t0: float, t1: float, step: int) -> int:
    """Số cửa sổ tumbling [w0,w0+step) phủ [t0,t1] — ĐÚNG công thức vòng lặp cũ
    `while w0<=t1: w0+=step`, không cần chạm sự kiện nào (window==step nên
    nhánh `we<=t0 → continue, không đếm` của bản cũ không bao giờ xảy ra: w0 ≤
    t0 < w0+step luôn đúng khi window==step, xem _featurize_streaming)."""
    w0 = math.floor(t0 / step) * step
    n = 0
    while w0 <= t1:
        n += 1
        w0 += step
    return n

def _featurize_streaming(events_factory, runs: list[dict], window: int, step: int):
    """§B6 mục 1 — đồng nghĩa chức năng với _featurize_inmemory KHI window==step
    (tumbling, trường hợp DUY NHẤT dùng ở B6), nhưng MỘT LƯỢT QUÉT duy nhất qua
    sự kiện (không nạp hết vào list): tích luỹ bộ đệm cho cửa sổ ĐANG MỞ của
    mỗi thực thể/lượt tấn công đang hoạt động; khi mốc thời gian vượt biên,
    PHÁT ra cửa sổ (ghi dòng đặc trưng hoặc cộng attack_idle) và GIẢI PHÓNG bộ
    đệm đó. Bộ nhớ = O(số thực thể/lượt ĐANG HOẠT ĐỘNG tại một thời điểm) —
    không phụ thuộc tổng số khúc/sự kiện đã thu.

    Đúng-tương-đương với bản cũ vì: (a) lưới cửa sổ w0=floor(ts/step)*step là
    LƯỚI GIỜ TOÀN CỤC, giống nhau cho mọi thực thể/lượt — không phải tương đối
    theo từng lượt; (b) luồng sự kiện hợp nhất (iter_events) đơn điệu không
    giảm theo ts, nên per-entity/per-run cũng đơn điệu không giảm theo ts →
    một khi mốc đã vượt biên cửa sổ/lượt, KHÔNG sự kiện nào tới sau còn thuộc
    về nó — an toàn để phát-và-giải-phóng ngay khi biên bị vượt."""
    assert window == step, "_featurize_streaming yêu cầu window==step (tumbling)"
    attack_runs = sorted([dict(r) for r in runs if r["class"] == "attack"], key=lambda r: r["t0"])
    noise_runs = [r for r in runs if r["class"] == "benign_noise"]
    rows = []; idle = Counter()
    n_runs = len(attack_runs)

    run_total = {}
    run_bufs = {}
    for i, r in enumerate(attack_runs):
        r["_rid"] = r.get("run_id") or f"{r['variant_group']}#{i}"
        run_total[i] = _window_count(r["t0"], r["t1"], step)
        run_bufs[i] = {}

    def finalize_run(i):
        r = attack_runs[i]
        buf = run_bufs.pop(i)
        hits = 0
        for w0, win in buf.items():
            if any(is_attack_event(e, r) for e in win):
                hits += 1
                row = _feat(win)
                row.update(entity=r["entity"], wstart=w0, label="attack",
                           variant_group=r["variant_group"], run_id=r["_rid"],
                           run_t0=r["t0"], scenario=r.get("scenario", ""))
                rows.append(row)
        idle[(r["variant_group"] or "attack", _norm_scenario(r.get("scenario", "")))] += run_total.pop(i) - hits

    benign_open = {}   # entity -> (w0, [events])

    def finalize_benign(ent):
        w0, win = benign_open.pop(ent)
        if not win:
            return
        lab, vg = "benign", ""
        for e in win:
            l, v = label_for(ent, e["ts"], noise_runs)
            if l == "benign_noise":
                lab, vg = "benign_noise", v; break
        row = _feat(win)
        row.update(entity=ent, wstart=w0, label=lab, variant_group=vg, run_id="")
        rows.append(row)

    active = []          # chỉ số (trong attack_runs) đang hoạt động
    next_run_idx = 0      # con trỏ nạp thêm runs mới vào active, theo t0 tăng dần

    for e in (events_factory() if callable(events_factory) else events_factory):
        ts = e["ts"]; ent = e["entity"]
        w0 = math.floor(ts / step) * step
        we = w0 + window

        while next_run_idx < n_runs and attack_runs[next_run_idx]["t0"] - window <= ts:
            active.append(next_run_idx); next_run_idx += 1

        # §B6 mục 1 — PHÁT HIỆN TRONG LÚC KIỂM: hoàn tất (finalize) theo `ts >
        # r.t1` là SỚM QUÁ — cửa sổ [w0,we) VẪN chồng lấn run khi w0<=r.t1 dù
        # một sự kiện KHÔNG LIÊN QUAN (entity khác) đã có ts>r.t1 (lưới cửa sổ
        # toàn cục, không theo từng entity). Dùng đúng mốc vòng lặp gốc
        # `while w0<=r.t1`: chỉ hoàn tất khi BIÊN CỬA SỔ hiện tại đã vượt —
        # nếu không, cửa sổ cuối (phần đuôi run nằm trong we>t1) bị tụt xuống
        # benign/benign_noise sai (đo được 15 dòng testuser01 lệch).
        still = []
        for i in active:
            if w0 > attack_runs[i]["t1"]:
                finalize_run(i)
            else:
                still.append(i)
        active = still

        matched = [i for i in active if _entity_match(ent, attack_runs[i]["entity"])
                   and not (we <= attack_runs[i]["t0"] or w0 > attack_runs[i]["t1"])]
        if matched:
            for i in matched:
                r = attack_runs[i]
                if r["t0"] <= ts <= r["t1"]:
                    run_bufs[i].setdefault(w0, []).append(e)
            continue   # cửa sổ chồng lượt tấn công → KHÔNG vào benign (giống in_attack cũ)

        if ent in ("?", ""):
            continue   # bản cũ: `if ent in ("?",""): continue` trong vòng benign — bỏ hẳn, không tính dòng nào

        cur = benign_open.get(ent)
        if cur is None or cur[0] != w0:
            if cur is not None:
                finalize_benign(ent)
            benign_open[ent] = (w0, [])
        benign_open[ent][1].append(e)

    for i in list(run_bufs.keys()):
        finalize_run(i)
    for ent in list(benign_open.keys()):
        finalize_benign(ent)
    return rows, idle

def _feat(win) -> dict:
    n = len(win)
    denies = [e for e in win if e.get("decision") is False or (e.get("code") in ("401", "403"))]
    dests = set(e["dest"] for e in win if e.get("dest"))
    paths = set(_norm_path(e["path"]) for e in win if e.get("path"))
    targets = set();
    for e in win:
        if e.get("path"): targets |= _target_ids(e["path"])
    actionclass = set((e.get("method"), _norm_path(e["path"] or "")) for e in win if e.get("path"))
    reads = sum(1 for e in win if e.get("method") in ("GET", "HEAD", "OPTIONS"))
    writes = sum(1 for e in win if e.get("method") in ("POST", "PUT", "PATCH", "DELETE"))
    ts_sorted = sorted(e["ts"] for e in win)
    gaps = [b - a for a, b in zip(ts_sorted, ts_sorted[1:])]
    codes = Counter(e["code"] for e in win if e.get("code"))
    c4 = sum(v for k, v in codes.items() if str(k).startswith("4"))
    c5 = sum(v for k, v in codes.items() if str(k).startswith("5"))
    reasons = set(e["reason"] for e in win if e.get("reason"))
    usts = [e["ust"] for e in win if e.get("ust") is not None]
    rts = [e["rt"] for e in win if e.get("rt") is not None]
    byts = [e["bytes"] for e in win if e.get("bytes") is not None]
    stepup = any((e.get("stepup") in ("high",)) for e in win)
    posture_bad = any(e.get("posture") not in (None, "compliant", "not_reported") for e in win)
    return {
        "deny_count": len(denies), "deny_rate": len(denies) / n if n else 0.0,
        "n_dest": len(dests), "n_path": len(paths), "n_target": len(targets),
        "n_actionclass": len(actionclass), "rw_ratio": reads / writes if writes else float(reads),
        "gap_mean": statistics.mean(gaps) if gaps else 0.0,
        "gap_var": statistics.pvariance(gaps) if len(gaps) > 1 else 0.0,
        "code_4xx": c4, "code_5xx": c5, "reason_kinds": len(reasons),
        "ust_p95": _pct(usts, 0.95), "ust_max": max(usts) if usts else 0.0,
        "rt_p95": _pct(rts, 0.95), "n_actions": n,
        "stepup_present": 1 if stepup else 0, "posture_bad": 1 if posture_bad else 0,
        "bytes_max": max(byts) if byts else 0.0, "bytes_sum": sum(byts) if byts else 0.0,
    }

# ───────────────────── 5) MÔ HÌNH (sklearn GB nếu có, else RF thuần) ────
def _try_sklearn():
    try:
        from sklearn.ensemble import GradientBoostingClassifier  # noqa
        return True
    except Exception:
        return False

class PyTree:
    """CART nhị phân đơn giản (Gini), giới hạn độ sâu — đủ khai thác rò rỉ."""
    def __init__(self, max_depth=4, min_leaf=3): self.max_depth=max_depth; self.min_leaf=min_leaf; self.root=None
    def fit(self, X, y):
        self.root = self._build(list(range(len(y))), X, y, 0); return self
    def _gini(self, ys):
        n=len(ys);
        if not n: return 0.0
        p=sum(ys)/n; return 1-p*p-(1-p)*(1-p)
    def _build(self, idx, X, y, depth):
        ys=[y[i] for i in idx]; node={"pred": sum(ys)/len(ys) if ys else 0.0}
        if depth>=self.max_depth or len(idx)<2*self.min_leaf or len(set(ys))<2: return node
        best=None
        nf=len(X[0]); feats=random.sample(range(nf), max(1,int(math.sqrt(nf))))
        for f in feats:
            vals=sorted(set(X[i][f] for i in idx))
            for a,b in zip(vals, vals[1:]):
                thr=(a+b)/2
                L=[i for i in idx if X[i][f]<=thr]; R=[i for i in idx if X[i][f]>thr]
                if len(L)<self.min_leaf or len(R)<self.min_leaf: continue
                g=(len(L)*self._gini([y[i] for i in L])+len(R)*self._gini([y[i] for i in R]))/len(idx)
                if best is None or g<best[0]: best=(g,f,thr,L,R)
        if not best: return node
        _,f,thr,L,R=best
        node.update({"f":f,"thr":thr,"L":self._build(L,X,y,depth+1),"R":self._build(R,X,y,depth+1)})
        return node
    def predict1(self, x):
        n=self.root
        while "f" in n: n=n["L"] if x[n["f"]]<=n["thr"] else n["R"]
        return n["pred"]

class PyForest:
    def __init__(self, n=25, max_depth=4): self.n=n; self.max_depth=max_depth; self.trees=[]
    def fit(self, X, y):
        self.trees=[]
        for _ in range(self.n):
            idx=[random.randrange(len(y)) for _ in range(len(y))]   # bootstrap
            self.trees.append(PyTree(self.max_depth).fit([X[i] for i in idx],[y[i] for i in idx]))
        return self
    def predict_proba(self, X):
        return [sum(t.predict1(x) for t in self.trees)/len(self.trees) for x in X]

def model_fit_predict(Xtr, ytr, Xte):
    if _try_sklearn():
        from sklearn.ensemble import GradientBoostingClassifier
        m=GradientBoostingClassifier(); m.fit(Xtr,ytr)
        return list(m.predict_proba(Xte)[:,1]), "sklearn.GradientBoostingClassifier(default)"
    random.seed(1337)
    m=PyForest().fit(Xtr,ytr)
    return m.predict_proba(Xte), "pure-python RandomForest(25×depth4) [sklearn vắng]"

# ───────────────────── 6) METRICS + 3 KIỂM TRA ────────────────────────
def metrics(y_true, prob, thr=0.5):
    tp=fp=tn=fn=0
    for yt,p in zip(y_true,prob):
        yp=1 if p>=thr else 0
        if yt==1 and yp==1: tp+=1
        elif yt==0 and yp==1: fp+=1
        elif yt==0 and yp==0: tn+=1
        else: fn+=1
    rec=tp/(tp+fn) if tp+fn else 0.0
    prec=tp/(tp+fp) if tp+fp else 0.0
    fpr=fp/(fp+tn) if fp+tn else 0.0
    return {"recall":round(rec,4),"precision":round(prec,4),"fpr":round(fpr,4),
            "tp":tp,"fp":fp,"tn":tn,"fn":fn}

def auc(y_true, prob):
    pos=[p for y,p in zip(y_true,prob) if y==1]; neg=[p for y,p in zip(y_true,prob) if y==0]
    if not pos or not neg: return None
    wins=sum(1 for a in pos for b in neg if a>b)+0.5*sum(1 for a in pos for b in neg if a==b)
    return round(wins/(len(pos)*len(neg)),4)

def split(rows, frac=0.5, seed=7):
    random.seed(seed); idx=list(range(len(rows))); random.shuffle(idx)
    k=int(len(rows)*frac); return set(idx[:k]), set(idx[k:])

def feature_computability(rows):
    """(a) đặc trưng nào KHÔNG tính được (toàn 0/thiếu trên mọi dòng)."""
    bad=[]
    for f in FEATURES:
        vals=[r[f] for r in rows]
        if all((v in (0, 0.0, None)) for v in vals):
            bad.append(f)
    return bad

def leakage_scan(rows):
    """(b) đặc trưng RÒ RỈ NHÃN do CÁCH SINH DỮ LIỆU, không phải tín hiệu thật.

    Phân biệt hai việc:
      - Tách attack khỏi N1 (benign) bằng deny/cường độ là tín hiệu HỢP LỆ — N2
        tồn tại chính vì thế; KHÔNG gắn cờ.
      - Rò rỉ thật: (i) giá trị đặc trưng XUẤT HIỆN RIÊNG ở attack vs toàn bộ
        non-attack (value disjoint — dấu hiệu path/id/user chỉ script tấn công
        tạo); HOẶC (ii) đặc trưng tách gần-hoàn-hảo attack khỏi BENIGN_NOISE
        (cặp khó) — nếu một feature một mình làm được thì mô hình học đường tắt.
    Gắn cờ = ứng viên để NGƯỜI ĐỌC quyết (nêu tên trong báo cáo), không tự loại.
    """
    y=[1 if r["label"]=="attack" else 0 for r in rows]
    # tập con attack vs benign_noise (cặp khó)
    hard=[(r, 1 if r["label"]=="attack" else 0) for r in rows if r["label"] in ("attack","benign_noise")]
    flagged=[]
    for f in FEATURES:
        vals=[r[f] for r in rows]
        a=set(v for v,yy in zip(vals,y) if yy==1)
        noa=set(v for v,yy in zip(vals,y) if yy==0)
        disjoint = bool(a and noa and a.isdisjoint(noa))
        hv=[r[f] for r,_ in hard]; hy=[yy for _,yy in hard]
        hard_auc=auc(hy, hv)
        near_perfect_vs_noise = hard_auc is not None and (hard_auc>=0.99 or hard_auc<=0.01)
        if disjoint or near_perfect_vs_noise:
            flagged.append({"feature":f,"value_disjoint":disjoint,
                            "auc_attack_vs_noise":hard_auc})
    return flagged

_UUID_RE = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
_EMAIL_RE = re.compile(r'[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+')

def identity_leakage_scan(events_factory, runs, min_occ=10, max_share=0.9):
    """events_factory: callable (gọi lại được nhiều lần, §B6 mục 1 — streaming)
    HOẶC list/iterable thường (tương thích selftest).
    §B1b (b'): RÒ RỈ DANH TÍNH — một vehicleid/id/email NÀO xuất hiện gần như
    CHỈ ở một lớp (>max_share) là đường tắt theo danh tính, không theo hành vi.
    Luân phiên nạn nhân (crapi_bola.sh) phải trải định danh qua nhiều lớp; check
    này XÁC NHẬN điều đó. Đặc trưng vi phạm phải ở dạng QUAN HỆ (n_target = SỐ
    uuid khác nhau) chứ KHÔNG phải dạng danh tính (uuid NÀO) — bảng đặc trưng
    hiện chỉ dùng n_target (quan hệ), không one-hot uuid, nên an toàn; check này
    canh nếu ai đó thêm đặc trưng danh tính hoặc nếu luân phiên hỏng.

    §B5 mục 2 (2026-10-13): khúc 1 gắn cờ 2392 định danh ở min_occ=3 — rác, vì
    với >1 triệu event, định danh xuất hiện 1-2 lần trivially có share=100%
    (1/1). Sàn min_occ=10 (mặc định MỚI, trước là 3) lọc rác tần suất thấp để
    rò rỉ THẬT (nếu có) không bị chìm trong vài nghìn dòng vô nghĩa. Số lượng
    đã xét/loại/gắn cờ được trả kèm để báo cáo minh bạch (không chỉ list)."""
    idclass = defaultdict(Counter)
    for e in (events_factory() if callable(events_factory) else events_factory):
        lab, _ = label_for(e["entity"], e["ts"], runs)
        p = e.get("path") or ""
        toks = set(_UUID_RE.findall(p)) | set(_target_ids(p))
        # email/username nếu có trong trường entity/reason
        for fld in (e.get("entity"),):
            if fld and "@" in str(fld):
                toks |= set(_EMAIL_RE.findall(str(fld)))
        for t in toks:
            idclass[t][lab] += 1
    flagged = []
    n_considered = len(idclass)
    n_below_floor = 0
    for val, cc in idclass.items():
        tot = sum(cc.values())
        if tot < min_occ:
            n_below_floor += 1
            continue
        top_class, top_n = cc.most_common(1)[0]
        share = top_n / tot
        if share > max_share:
            flagged.append({"identity": val, "total": tot, "dominant_class": top_class,
                            "share": round(share, 3), "by_class": dict(cc)})
    # ưu tiên các định danh lệch về attack lên đầu
    flagged.sort(key=lambda f: (f["dominant_class"] != "attack", -f["total"]))
    return {"min_occ": min_occ, "n_considered": n_considered,
            "n_below_floor": n_below_floor, "n_flagged": len(flagged),
            "flagged": flagged}

def path_leakage_scan(events_factory, runs, min_occ=10, max_share=0.9):
    """events_factory: callable hoặc iterable thường — xem identity_leakage_scan.
    §B1c (b''): RÒ RỈ TẦNG PATH — không đường dẫn (đã chuẩn hoá tham số) hay
    TIỀN TỐ nào được xuất hiện >max_share ở một lớp. Nếu N1 không bao giờ gọi
    /identity/api/v2/vehicle/{id}/location thì chính path đó là nhãn hoàn hảo
    (mô hình recall~1 bằng luật khớp path) mà kiểm uuid KHÔNG bắt được. §B1c sửa
    gốc: N1 gọi path đó với uuid của chính mình (crapi_load_n1.sh). Check này
    XÁC NHẬN không còn path/tiền tố lệch lớp; nếu còn, đặc trưng dạng PATH
    (one-hot path/prefix) phải BỎ — dùng dạng quan hệ n_path/n_actionclass.

    §B5 mục 2 (2026-10-13): sàn min_occ nâng lên 10 (trước là 5) — cùng lý do
    với identity_leakage_scan: path/tiền tố hiếm gặp trivially gắn cờ ở mẫu
    nhỏ. Trả kèm thống kê đã xét/loại/gắn cờ để không cần đoán qua độ dài list."""
    pathclass = defaultdict(Counter)
    for e in (events_factory() if callable(events_factory) else events_factory):
        p = _norm_path(e.get("path") or "")
        if not p or p == "/":
            continue
        lab, _ = label_for(e["entity"], e["ts"], runs)
        parts = [seg for seg in p.split("/") if seg]
        for k in range(1, len(parts) + 1):          # full path + mọi tiền tố
            pathclass["/" + "/".join(parts[:k])][lab] += 1
    flagged = []
    n_considered = len(pathclass)
    n_below_floor = 0
    for path, cc in pathclass.items():
        tot = sum(cc.values())
        if tot < min_occ:
            n_below_floor += 1
            continue
        top_class, top_n = cc.most_common(1)[0]
        share = top_n / tot
        if share > max_share:
            flagged.append({"path": path, "total": tot, "dominant_class": top_class,
                            "share": round(share, 3), "by_class": dict(cc)})
    flagged.sort(key=lambda f: (f["dominant_class"] != "attack", -f["total"]))
    return {"min_occ": min_occ, "n_considered": n_considered,
            "n_below_floor": n_below_floor, "n_flagged": len(flagged),
            "flagged": flagged}

def difficulty_verdict(model_m, rule_m, model_auc):
    if model_auc is None:
        return "INSUFFICIENT_DATA", "tập test thiếu lớp attack hoặc non-attack → không đánh giá được độ khó (cần nhiều lượt A hơn / cửa sổ nhỏ hơn)"
    too_easy = model_m["recall"]>=0.995 and model_m["precision"]>=0.995 and model_auc>=0.995
    near_random = model_auc<=0.6
    beats_rule = (model_m["recall"]+ (1-model_m["fpr"])) > (rule_m["recall"]+(1-rule_m["fpr"])) \
                 or model_m["precision"]>rule_m["precision"]
    if too_easy:
        return "NO_TOO_EASY", "mô hình recall≈precision≈1 quá dễ → N2 chưa đủ giống A, THIẾT KẾ LẠI N2"
    if near_random:
        return "NO_TOO_HARD", "mô hình ≈ ngẫu nhiên (AUC≤0.6) → đặc trưng chưa đủ HOẶC 2 giờ quá ít mẫu A"
    if not beats_rule:
        return "NO_RULE_TIE", "mô hình KHÔNG tốt hơn luật deny_count>0 → vấn đề THIẾT KẾ DỮ LIỆU, không phải mô hình"
    return "GO", "phân biệt được nhưng không hoàn hảo VÀ tốt hơn luật deny_count>0 → thiết kế đúng, MỞ CỔNG"

def rule_deny_gt0(rows_te):
    y=[1 if r["label"]=="attack" else 0 for r in rows_te]
    prob=[1.0 if r["deny_count"]>0 else 0.0 for r in rows_te]
    return metrics(y,prob), prob

def _grp(vg): return "train" if vg.startswith("train") else ("holdout" if vg.startswith("holdout") else "other")

def run_recall(rows_te, prob, predpos="model"):
    """RECALL theo LƯỢT: một lượt phát hiện nếu ≥1 cửa sổ attack của nó (trong
    test) được gắn cờ (prob≥0.5 cho mô hình, deny_count>0 cho luật). Tách nhóm."""
    seen=defaultdict(bool); grp={}
    for r,p in zip(rows_te,prob):
        if r["label"]!="attack": continue
        rid=r.get("run_id") or r.get("variant_group")
        hit=(p>=0.5) if predpos=="model" else (r["deny_count"]>0)
        seen[rid]=seen[rid] or hit; grp[rid]=_grp(r.get("variant_group",""))
    def rec(sel):
        ids=[rid for rid,g in grp.items() if sel(g)]
        return round(sum(1 for rid in ids if seen[rid])/len(ids),4) if ids else None
    return {"all":rec(lambda g:True),"train":rec(lambda g:g=="train"),
            "holdout":rec(lambda g:g=="holdout"),"n_runs_in_test":len(grp)}

def detection_latency(rows_te, prob):
    """§B1e: với mỗi lượt được gắn cờ, cửa sổ thứ mấy CỦA LƯỢT (1=cửa sổ đầu có
    request) và trễ bao lâu từ t_start. Trung vị + khoảng theo nhóm và theo họ."""
    byrun=defaultdict(list)
    for r,p in zip(rows_te,prob):
        if r["label"]!="attack": continue
        byrun[r.get("run_id")].append((r["wstart"],p,r.get("run_t0",r["wstart"]),
                                       r.get("variant_group",""),r.get("scenario","")))
    per=[]
    for rid,ws in byrun.items():
        ws.sort(key=lambda x:x[0])
        for i,(wstart,p,t0,vg,sc) in enumerate(ws):
            if p>=0.5:
                # cửa sổ căn lưới có thể bắt đầu TRƯỚC t0 → clamp 0 (= phát hiện
                # ngay trong cửa sổ bao trùm t_start).
                per.append({"run":rid,"group":_grp(vg),"scenario":sc,
                            "first_flag_window_index":i+1,
                            "first_flag_delay_sec":round(max(0.0,wstart-t0),1)}); break
    def summ(sel):
        xs=[l for l in per if sel(l)]
        if not xs: return None
        idxs=sorted(l["first_flag_window_index"] for l in xs)
        dls=sorted(l["first_flag_delay_sec"] for l in xs)
        return {"n":len(xs),"idx_median":statistics.median(idxs),"idx_range":[idxs[0],idxs[-1]],
                "delay_median_sec":statistics.median(dls),"delay_range_sec":[dls[0],dls[-1]]}
    scens=sorted(set(l["scenario"] for l in per if l["scenario"]))
    return {"by_group":{g:summ(lambda l,g=g:l["group"]==g) for g in ("train","holdout")},
            "by_scenario":{sc:summ(lambda l,sc=sc:l["scenario"]==sc) for sc in scens},
            "per_run":per}

def recall_by_window_width(events_factory, runs, widths=(60,300,600)):
    """§B1e: recall theo lượt ở các độ rộng cửa sổ (tumbling step=width), tách
    train/holdout — xác định độ rộng phù hợp với nhịp nào. attack_idle cao ở
    cửa sổ hẹp là tín hiệu CHỌN ĐỘ RỘNG, KHÔNG phải làm slow_drip dày lên.
    events_factory callable → mỗi width gọi lại từ đầu (§B6 mục 1: streaming,
    không giữ sự kiện trong RAM giữa các lượt quét)."""
    out={}
    for w in widths:
        rws,idle=featurize(events_factory,runs,w,w)
        na=sum(1 for r in rws if r["label"]=="attack")
        if na<3 or (len(rws)-na)<3:
            out[f"{w}s"]={"note":"thiếu dữ liệu"}; continue
        trw,tew=split(rws)
        Xtr=[[r[f] for f in FEATURES] for i,r in enumerate(rws) if i in trw]
        ytr=[1 if r["label"]=="attack" else 0 for i,r in enumerate(rws) if i in trw]
        Xte=[[r[f] for f in FEATURES] for i,r in enumerate(rws) if i in tew]
        rows_te=[r for i,r in enumerate(rws) if i in tew]
        if sum(ytr)<2 or len(set(ytr))<2: out[f"{w}s"]={"note":"train thiếu lớp"}; continue
        prob,_=model_fit_predict(Xtr,ytr,Xte)
        ho_idle=sum(c for (vg,sc),c in idle.items() if str(vg).startswith("holdout"))
        out[f"{w}s"]={"recall_by_run":run_recall(rows_te,prob),
                      "attack_idle_holdout":ho_idle}
    return out

# ───────────────────── RUN (gắn mọi thứ) ──────────────────────────────
def run(chunk_dirs, runs_file, window, step, out_dir):
    """§B6 mục 1: chunk_dirs là MỘT thư mục (str) hoặc danh sách thư mục khúc
    (cộng dồn N khúc). events_factory là CALLABLE gọi lại được nhiều lần —
    mỗi lần tạo generator mới (iter_events), KHÔNG giữ sự kiện trong RAM giữa
    các lượt quét (featurize / đếm / 2 kiểm rò rỉ / recall-theo-độ-rộng đều
    quét lại từ đầu — đổi vài lượt đọc đĩa để lấy bộ nhớ O(1) theo số khúc)."""
    if isinstance(chunk_dirs, str):
        chunk_dirs = [chunk_dirs]
    os.makedirs(out_dir, exist_ok=True)
    # §C1 mục 5.1: sid_map → OPA entity attribution
    # §C1c mục 2: trace_map → Envoy bytes/ust/rt attribution
    sid_map = build_sid_map(chunk_dirs)
    trace_map = build_trace_map(chunk_dirs, sid_map)
    events_factory = lambda: iter_events(chunk_dirs, sid_map=sid_map, trace_map=trace_map)
    runs=load_runs(runs_file)
    # §B7 mục 1 — rào chắn: scenario (ĐÃ CHUẨN HOÁ) không khớp họ nào đã biết
    # không được âm thầm coi là tấn công trong is_attack_event(); đếm/báo ở đây
    # một lần cho mỗi lượt (không spam theo event).
    unknown_runs=[r for r in runs if r["class"]=="attack" and _norm_scenario(r.get("scenario","")) not in _KNOWN_SCENARIOS]
    unknown_scenario_names=dict(Counter(_norm_scenario(r.get("scenario","")) or "(trống)" for r in unknown_runs))
    if unknown_runs:
        print(f"[run] ⚠ scenario KHÔNG NHẬN RA (fallback=deny, KHÔNG mặc định True): {unknown_scenario_names}")
    rows,idle=featurize(events_factory, runs, window, step)
    n_events=sum(1 for _ in events_factory())   # lượt quét riêng, chỉ đếm — không giữ gì
    labels=Counter(r["label"] for r in rows)
    # §B1d: attack_idle đã LOẠI; đếm theo nhóm biến thể + cảnh báo holdout thưa.
    # §B7 mục 1: khoá idle là (variant_group, scenario_chuẩn_hoá) — tách cả hai chiều.
    idle_total=sum(idle.values())
    idle_by_grp={"train":0,"holdout":0,"other":0}
    idle_by_vg=Counter(); idle_by_scenario=Counter()
    for (vg,sc),c in idle.items():
        k="train" if str(vg).startswith("train") else ("holdout" if str(vg).startswith("holdout") else "other")
        idle_by_grp[k]+=c
        idle_by_vg[vg]+=c
        idle_by_scenario[sc or "(trống)"]+=c
    atk_win_by_grp={"train":0,"holdout":0,"other":0}
    atk_win_by_scenario=Counter()
    for r in rows:
        if r["label"]!="attack": continue
        vg=r.get("variant_group",""); k="train" if vg.startswith("train") else ("holdout" if vg.startswith("holdout") else "other")
        atk_win_by_grp[k]+=1
        atk_win_by_scenario[_norm_scenario(r.get("scenario","")) or "(trống)"]+=1
    print(f"[run] sự kiện={n_events} runs={len(runs)} cửa_sổ={len(rows)} nhãn={dict(labels)}")
    print(f"[run] attack_idle LOẠI={idle_total} theo nhóm biến thể={dict(idle_by_vg)}")
    print(f"[run] attack_idle theo HỌ (scenario)={dict(idle_by_scenario)} · cửa_sổ_attack theo HỌ={dict(atk_win_by_scenario)}")
    result={"n_events":n_events,"n_runs":len(runs),"n_windows":len(rows),
            "label_counts":dict(labels),"window_s":window,"step_s":step,
            "attack_idle_total":idle_total,"attack_idle_by_variant":dict(idle_by_vg),
            "attack_idle_by_group":idle_by_grp,"attack_windows_by_group":atk_win_by_grp,
            "attack_idle_by_scenario":dict(idle_by_scenario),
            "attack_windows_by_scenario":dict(atk_win_by_scenario),
            "unknown_scenario_runs":len(unknown_runs),"unknown_scenario_names":unknown_scenario_names}
    # cảnh báo: holdout attack_idle quá cao so với cửa sổ attack → slow_drip quá thưa
    ho_idle=idle_by_grp["holdout"]; ho_atk=atk_win_by_grp["holdout"]
    if ho_idle+ho_atk>0 and ho_idle/(ho_idle+ho_atk)>0.5:
        result["warn_holdout_sparse"]=(f"attack_idle holdout {ho_idle}/{ho_idle+ho_atk} > 50% — "
            f"slow_drip có thể QUÁ THƯA so với cửa sổ {window}s; cân nhắc cửa sổ rộng hơn cho holdout")
        print(f"[run] ⚠ {result['warn_holdout_sparse']}")
    if labels.get("attack",0)<3 or (len(rows)-labels.get("attack",0))<3:
        result["verdict"]="INSUFFICIENT_DATA"
        result["note"]="quá ít cửa sổ attack hoặc non-attack để huấn luyện/kiểm tra"
        json.dump(result, open(os.path.join(out_dir,"gate_result.json"),"w"), indent=2, ensure_ascii=False)
        print(f"[run] VERDICT: INSUFFICIENT_DATA — {result['note']}"); return result
    # (a) computability
    result["features_not_computable"]=feature_computability(rows)
    # (b) leakage — đặc trưng tổng hợp
    result["leakage_flagged"]=leakage_scan(rows)
    # (b') leakage — DANH TÍNH (vehicleid/id/email lệch về một lớp)
    idl_scan=identity_leakage_scan(events_factory, runs)
    result["identity_leakage_flagged"]=idl_scan["flagged"]
    result["identity_leakage_scan_stats"]={k:v for k,v in idl_scan.items() if k!="flagged"}
    # (b'') leakage — TẦNG PATH (path/tiền tố lệch về một lớp)
    pl_scan=path_leakage_scan(events_factory, runs)
    result["path_leakage_flagged"]=pl_scan["flagged"]
    result["path_leakage_scan_stats"]={k:v for k,v in pl_scan.items() if k!="flagged"}
    # (c) difficulty — train/test split, bỏ cột leakage khỏi mô hình? KHÔNG: báo cáo
    #     cả hai để người đọc quyết; mô hình chính chạy trên TẤT CẢ đặc trưng để
    #     lộ ra "quá dễ" nếu có rò rỉ.
    tr,te=split(rows)
    X=lambda S:[[r[f] for f in FEATURES] for i,r in enumerate(rows) if i in S]
    Y=lambda S:[1 if r["label"]=="attack" else 0 for i,r in enumerate(rows) if i in S]
    Xtr,ytr,Xte=X(tr),Y(tr),X(te)
    rows_te=[r for i,r in enumerate(rows) if i in te]
    prob,model_name=model_fit_predict(Xtr,ytr,Xte)
    yte=Y(te)
    # ── §B1d ĐƠN VỊ ĐO (chốt trong docs/FEATURES-GIAIDOAN-C.md) ──────────────
    # FPR theo CỬA SỔ trên lành tính (N1+N2). Window-recall là SỐ PHỤ.
    wm=metrics(yte,prob); ma=auc(yte,prob)
    # RECALL theo LƯỢT: một lượt phát hiện nếu ≥1 cửa sổ của nó (trong test) được
    # gắn cờ (prob≥0.5). Đây là đơn vị cho tiêu chí ≥0.80 và ≥70% holdout.
    model_run_rec=run_recall(rows_te,prob,"model"); rule_run_rec=run_recall(rows_te,prob,"rule")
    rm,rprob=rule_deny_gt0(rows_te)
    # §B1e: độ trễ phát hiện (trên test) + recall theo độ rộng cửa sổ.
    result["detection_latency"]=detection_latency(rows_te,prob)
    result["recall_by_window_width"]=recall_by_window_width(events_factory,runs)
    # model_m dùng cho verdict: recall = recall THEO LƯỢT (đơn vị chốt), precision/fpr theo cửa sổ
    mm={"recall":model_run_rec["all"] if model_run_rec["all"] is not None else 0.0,
        "precision":wm["precision"],"fpr":wm["fpr"]}
    rmm={"recall":rule_run_rec["all"] if rule_run_rec["all"] is not None else 0.0,
         "precision":rm["precision"],"fpr":rm["fpr"]}
    verdict,why=difficulty_verdict(mm,rmm,ma)
    result.update({"model":model_name,
                   "recall_by_run":model_run_rec,"recall_by_run_rule":rule_run_rec,
                   "fpr_by_window":wm["fpr"],"precision_by_window":wm["precision"],
                   "window_recall_secondary":wm["recall"],"model_auc":ma,
                   "rule_deny_gt0_window":rm,"verdict":verdict,"why":why,
                   "train_n":len(ytr),"test_n":len(yte),
                   "test_attack_windows":sum(yte),"test_nonattack_windows":len(yte)-sum(yte)})
    json.dump(result, open(os.path.join(out_dir,"gate_result.json"),"w"), indent=2, ensure_ascii=False)
    # feature table ra CSV để soi tay
    with open(os.path.join(out_dir,"features.csv"),"w") as fh:
        fh.write("entity,wstart,label,variant_group,"+",".join(FEATURES)+"\n")
        for r in rows:
            fh.write(f"{r['entity']},{r['wstart']},{r['label']},{r['variant_group']},"+
                     ",".join(str(r[f]) for f in FEATURES)+"\n")
    print(f"[run] model={model_name}")
    print(f"[run] RECALL theo LƯỢT (đơn vị chốt ≥0.80 / holdout ≥0.70) — mô hình: {model_run_rec}")
    print(f"[run]   so luật deny>0 theo lượt: {rule_run_rec}")
    print(f"[run] FPR theo CỬA SỔ (lành tính N1+N2): mô hình={wm['fpr']} luật={rm['fpr']} · precision_window={wm['precision']}")
    print(f"[run] window-recall (SỐ PHỤ, đại lượng khác): {wm['recall']} AUC={ma}")
    print(f"[run] rò rỉ (đặc trưng): {[f['feature'] for f in result['leakage_flagged']]}")
    idl=result['identity_leakage_flagged']; idl_st=result['identity_leakage_scan_stats']
    print(f"[run] rò rỉ DANH TÍNH (>90% 1 lớp, sàn ≥{idl_st['min_occ']} lần): "
          f"{idl_st['n_considered']} định danh đã xét, {idl_st['n_below_floor']} loại vì dưới sàn, "
          f"{idl_st['n_flagged']} bị gắn cờ" +
          (f" — ví dụ {idl[0]['identity']} {idl[0]['by_class']}" if idl else " (không có — luân phiên OK)"))
    pl=result['path_leakage_flagged']; pl_st=result['path_leakage_scan_stats']
    print(f"[run] rò rỉ TẦNG PATH (>90% 1 lớp, sàn ≥{pl_st['min_occ']} lần): "
          f"{pl_st['n_considered']} path/tiền tố đã xét, {pl_st['n_below_floor']} loại vì dưới sàn, "
          f"{pl_st['n_flagged']} bị gắn cờ" +
          (f" — vd {pl[0]['path']} {pl[0]['by_class']} → BỎ đặc trưng dạng path" if pl else " (không có — N1 có gọi path tấn công hợp lệ)"))
    print(f"[run] không tính được: {result['features_not_computable']}")
    dl=result["detection_latency"]["by_group"]
    print(f"[run] ĐỘ TRỄ PHÁT HIỆN (§B1e) train={dl.get('train')} holdout={dl.get('holdout')}")
    print(f"[run] RECALL theo ĐỘ RỘNG CỬA SỔ (§B1e): " +
          " ".join(f"{w}={(v.get('recall_by_run') or {}).get('all')}/{(v.get('recall_by_run') or {}).get('holdout')}(all/holdout)"
                   for w,v in result['recall_by_window_width'].items()))
    print(f"[run] VERDICT: {verdict} — {why}")
    return result

# ───────────────────── §B7 mục 2 — FEATURIZE THEO KHÚC ─────────────────
# "MỘT LẦN ĐẮT, NHIỀU LẦN RẺ": đọc log (giải nén gzip + json.loads + resort)
# là phần tốn thời gian; sinh bảng đặc trưng Ở CẢ BA độ rộng cửa sổ trong
# cùng lượt chạy, ghi ra thư mục khúc. `run --features` sau đó chỉ ĐỌC các
# bảng này (ghép, huấn luyện, tính chỉ số) — không đọc lại log thô, không
# chạy lại _resort_bounded/iter_events. Không chọn độ rộng "tốt nhất" ở đây —
# sinh cả ba, để Giai đoạn C quyết (ngoài phạm vi B7).
def _feature_table_format():
    try:
        import pandas, pyarrow  # noqa
        return "parquet"
    except Exception:
        return "csvgz"   # mặc định thật tế trên host thu (không cài thêm thư viện)

_TABLE_COLS = ["chunk_id", "window_start", "window_width", "entity", "label",
               "variant_group", "run_id", "scenario"] + FEATURES

def _table_path(out_dir, width, fmt):
    ext = "parquet" if fmt == "parquet" else "csv.gz"
    return os.path.join(out_dir, f"features_w{width}.{ext}")

def write_feature_table(rows, chunk_id, width, out_dir, fmt=None):
    fmt = fmt or _feature_table_format()
    path = _table_path(out_dir, width, fmt)
    recs = [{"chunk_id": chunk_id, "window_start": r["wstart"], "window_width": width,
             "entity": r["entity"], "label": r["label"],
             "variant_group": r.get("variant_group", ""), "run_id": r.get("run_id", ""),
             "scenario": _norm_scenario(r.get("scenario", "")),
             **{f: r[f] for f in FEATURES}} for r in rows]
    if fmt == "parquet":
        import pandas as pd
        pd.DataFrame(recs, columns=_TABLE_COLS).to_parquet(path, index=False)
    else:
        with gzip.open(path, "wt", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=_TABLE_COLS)
            w.writeheader()
            w.writerows(recs)
    return path

def read_feature_table(out_dir, width):
    fmt = "parquet" if os.path.exists(_table_path(out_dir, width, "parquet")) else "csvgz"
    path = _table_path(out_dir, width, fmt)
    if fmt == "parquet":
        import pandas as pd
        df = pd.read_parquet(path)
        recs = df.to_dict("records")
    else:
        with gzip.open(path, "rt", newline="") as fh:
            recs = list(csv.DictReader(fh))
    rows = []
    for r in recs:
        row = {"wstart": float(r["window_start"]), "label": r["label"],
               "entity": r["entity"], "variant_group": r.get("variant_group", ""),
               "run_id": r.get("run_id", ""), "scenario": r.get("scenario", ""),
               "chunk_id": r.get("chunk_id", "")}
        for f in FEATURES:
            row[f] = float(r[f])
        rows.append(row)
    return rows

def featurize_chunk(chunk_dir, runs_file, out_dir=None, widths=(60, 300, 600), chunk_id=None):
    """§B7 mục 2: đọc log của MỘT khúc một lần, sinh + ghi bảng đặc trưng cho
    mỗi độ rộng trong `widths`. Trả metadata (n_events, thời gian, nhãn/
    attack_idle theo từng độ rộng — dùng để lắp lại gate_result.json ở chế độ
    --features mà KHÔNG cần đọc lại log thô)."""
    t0 = time.time()
    out_dir = out_dir or chunk_dir
    chunk_id = chunk_id or os.path.basename(os.path.normpath(chunk_dir))
    os.makedirs(out_dir, exist_ok=True)
    runs = load_runs(runs_file)
    # §C1 mục 5.1: sid_map → OPA entity attribution (username từ session cookie)
    # §C1c mục 2: trace_map → Envoy bytes/ust/rt attribution (trace_id → username)
    sid_map = build_sid_map([chunk_dir])
    trace_map = build_trace_map([chunk_dir], sid_map)
    events_factory = lambda: iter_events([chunk_dir], sid_map=sid_map, trace_map=trace_map)
    n_events = sum(1 for _ in events_factory())
    unknown_runs = [r for r in runs if r["class"] == "attack"
                    and _norm_scenario(r.get("scenario", "")) not in _KNOWN_SCENARIOS]
    unknown_names = dict(Counter(_norm_scenario(r.get("scenario", "")) or "(trống)" for r in unknown_runs))
    fmt = _feature_table_format()
    meta = {"chunk_id": chunk_id, "n_events": n_events, "format": fmt,
            "unknown_scenario_runs": len(unknown_runs), "unknown_scenario_names": unknown_names,
            "widths": {}}
    for w in widths:
        rows, idle = featurize(events_factory, runs, w, w)
        labels = Counter(r["label"] for r in rows)
        idle_by_grp = {"train": 0, "holdout": 0, "other": 0}; idle_by_scn = Counter()
        for (vg, sc), c in idle.items():
            k = "train" if str(vg).startswith("train") else ("holdout" if str(vg).startswith("holdout") else "other")
            idle_by_grp[k] += c; idle_by_scn[sc or "(trống)"] += c
        atk_win_by_scn = Counter()
        for r in rows:
            if r["label"] == "attack":
                atk_win_by_scn[_norm_scenario(r.get("scenario", "")) or "(trống)"] += 1
        meta["widths"][str(w)] = {
            "n_windows": len(rows), "label_counts": dict(labels),
            "attack_idle_total": sum(idle.values()), "attack_idle_by_group": idle_by_grp,
            "attack_idle_by_scenario": dict(idle_by_scn),
            "attack_windows_by_scenario": dict(atk_win_by_scn),
            "table": write_feature_table(rows, chunk_id, w, out_dir, fmt),
        }
    meta["elapsed_sec"] = round(time.time() - t0, 1)
    json.dump(meta, open(os.path.join(out_dir, "featurize_meta.json"), "w"), indent=2, ensure_ascii=False)
    print(f"[featurize] khúc={chunk_id} sự_kiện={n_events} widths={list(widths)} "
          f"định_dạng={fmt} elapsed={meta['elapsed_sec']}s unknown_scenario_runs={len(unknown_runs)} -> {out_dir}")
    return meta

def run_from_features(feature_dirs, out_dir, window=60):
    """§B7 mục 2 — nghiệm thu: đọc từ bảng đặc trưng đã sinh (featurize_chunk),
    KHÔNG đọc log thô, KHÔNG chạy iter_events/_resort_bounded. Ghép bảng của N
    khúc ở độ rộng `window`, huấn luyện, tính chỉ số — vài giây. identity/path
    leakage scan CẦN sự kiện thô theo path/entity, KHÔNG có ở đây → SKIPPED
    (ghi rõ trong kết quả, không giả vờ đã kiểm); đây là lý do chế độ
    --features chỉ nên dùng cho lặp nhanh ở Giai đoạn C, KHÔNG thay cho một
    lượt `run --logs` đầy đủ khi cần xác nhận lại rò rỉ."""
    t0 = time.time()
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    n_events = 0
    idle_total = 0; idle_by_grp = {"train": 0, "holdout": 0, "other": 0}
    idle_by_scn = Counter(); unknown_total = 0; unknown_names = Counter()
    for d in feature_dirs:
        meta = json.load(open(os.path.join(d, "featurize_meta.json")))
        n_events += meta["n_events"]
        unknown_total += meta.get("unknown_scenario_runs", 0)
        for k, v in meta.get("unknown_scenario_names", {}).items():
            unknown_names[k] += v
        wmeta = meta["widths"][str(window)]
        idle_total += wmeta["attack_idle_total"]
        for k in idle_by_grp: idle_by_grp[k] += wmeta["attack_idle_by_group"][k]
        for k, v in wmeta["attack_idle_by_scenario"].items(): idle_by_scn[k] += v
        rows.extend(read_feature_table(d, window))
    labels = Counter(r["label"] for r in rows)
    atk_win_by_grp = {"train": 0, "holdout": 0, "other": 0}
    for r in rows:
        if r["label"] != "attack": continue
        vg = r.get("variant_group", ""); k = "train" if vg.startswith("train") else ("holdout" if vg.startswith("holdout") else "other")
        atk_win_by_grp[k] += 1
    print(f"[run-features] khúc={len(feature_dirs)} sự_kiện={n_events} cửa_sổ={len(rows)} nhãn={dict(labels)}")
    result = {"n_events": n_events, "n_windows": len(rows), "label_counts": dict(labels),
              "window_s": window, "step_s": window, "source": "features",
              "attack_idle_total": idle_total, "attack_idle_by_group": idle_by_grp,
              "attack_idle_by_scenario": dict(idle_by_scn), "attack_windows_by_group": atk_win_by_grp,
              "unknown_scenario_runs": unknown_total, "unknown_scenario_names": dict(unknown_names),
              "identity_leakage_flagged": "SKIPPED (chế độ --features không có sự kiện thô)",
              "path_leakage_flagged": "SKIPPED (chế độ --features không có sự kiện thô)"}
    ho_idle = idle_by_grp["holdout"]; ho_atk = atk_win_by_grp["holdout"]
    if ho_idle + ho_atk > 0 and ho_idle / (ho_idle + ho_atk) > 0.5:
        result["warn_holdout_sparse"] = (f"attack_idle holdout {ho_idle}/{ho_idle+ho_atk} > 50% — "
            f"slow_drip có thể QUÁ THƯA so với cửa sổ {window}s")
    if labels.get("attack", 0) < 3 or (len(rows) - labels.get("attack", 0)) < 3:
        result["verdict"] = "INSUFFICIENT_DATA"
        json.dump(result, open(os.path.join(out_dir, "gate_result.json"), "w"), indent=2, ensure_ascii=False)
        return result
    result["features_not_computable"] = feature_computability(rows)
    result["leakage_flagged"] = leakage_scan(rows)   # không cần sự kiện thô — chạy trên bảng đặc trưng
    tr, te = split(rows)
    X = lambda S: [[r[f] for f in FEATURES] for i, r in enumerate(rows) if i in S]
    Y = lambda S: [1 if r["label"] == "attack" else 0 for i, r in enumerate(rows) if i in S]
    Xtr, ytr, Xte = X(tr), Y(tr), X(te)
    rows_te = [r for i, r in enumerate(rows) if i in te]
    prob, model_name = model_fit_predict(Xtr, ytr, Xte)
    yte = Y(te)
    wm = metrics(yte, prob); ma = auc(yte, prob)
    model_run_rec = run_recall(rows_te, prob, "model"); rule_run_rec = run_recall(rows_te, prob, "rule")
    rm, rprob = rule_deny_gt0(rows_te)
    result["detection_latency"] = detection_latency(rows_te, prob)
    # §B7 mục 2: recall theo độ rộng cửa sổ từ các bảng KHÁC (60/300/600) đã có
    # sẵn trong `feature_dirs` — KHÔNG đọc lại log thô cho 2 độ rộng còn lại.
    rbw = {}
    for w in (60, 300, 600):
        try:
            rws = []
            for d in feature_dirs:
                rws.extend(read_feature_table(d, w))
        except FileNotFoundError:
            rbw[f"{w}s"] = {"note": f"không có bảng width={w} trong feature_dirs"}; continue
        na = sum(1 for r in rws if r["label"] == "attack")
        if na < 3 or (len(rws) - na) < 3:
            rbw[f"{w}s"] = {"note": "thiếu dữ liệu"}; continue
        trw, tew = split(rws)
        Xtr2 = [[r[f] for f in FEATURES] for i, r in enumerate(rws) if i in trw]
        ytr2 = [1 if r["label"] == "attack" else 0 for i, r in enumerate(rws) if i in trw]
        Xte2 = [[r[f] for f in FEATURES] for i, r in enumerate(rws) if i in tew]
        rows_te2 = [r for i, r in enumerate(rws) if i in tew]
        if sum(ytr2) < 2 or len(set(ytr2)) < 2:
            rbw[f"{w}s"] = {"note": "train thiếu lớp"}; continue
        prob2, _ = model_fit_predict(Xtr2, ytr2, Xte2)
        rbw[f"{w}s"] = {"recall_by_run": run_recall(rows_te2, prob2)}
    result["recall_by_window_width"] = rbw
    mm = {"recall": model_run_rec["all"] if model_run_rec["all"] is not None else 0.0,
          "precision": wm["precision"], "fpr": wm["fpr"]}
    rmm = {"recall": rule_run_rec["all"] if rule_run_rec["all"] is not None else 0.0,
           "precision": rm["precision"], "fpr": rm["fpr"]}
    verdict, why = difficulty_verdict(mm, rmm, ma)
    result.update({"model": model_name, "recall_by_run": model_run_rec, "recall_by_run_rule": rule_run_rec,
                   "fpr_by_window": wm["fpr"], "precision_by_window": wm["precision"],
                   "window_recall_secondary": wm["recall"], "model_auc": ma,
                   "rule_deny_gt0_window": rm, "verdict": verdict, "why": why,
                   "train_n": len(ytr), "test_n": len(yte),
                   "test_attack_windows": sum(yte), "test_nonattack_windows": len(yte) - sum(yte)})
    result["elapsed_sec"] = round(time.time() - t0, 1)
    json.dump(result, open(os.path.join(out_dir, "gate_result.json"), "w"), indent=2, ensure_ascii=False)
    print(f"[run-features] model={model_name} VERDICT={verdict} — {why} (elapsed={result['elapsed_sec']}s)")
    print(f"[run-features] RECALL theo LƯỢT: mô hình={model_run_rec} luật={rule_run_rec}")
    print(f"[run-features] FPR theo cửa sổ: mô hình={wm['fpr']} luật={rm['fpr']}")
    return result

# ───────────────────── SYNTH (tự kiểm pipeline) ────────────────────────
def synth(out_dir, seed=7):
    """Sinh log + runs.jsonl giả, KHÔNG rò rỉ (attack khác benign bằng CƯỜNG ĐỘ,
    không bằng path/giá trị riêng), để chứng minh pipeline + 3 kiểm tra chạy."""
    random.seed(seed); os.makedirs(out_dir, exist_ok=True)
    base=1_700_000_000.0
    envoy=open(os.path.join(out_dir,"envoy.jsonl"),"w")
    opa=open(os.path.join(out_dir,"opa.jsonl"),"w")
    runs=open(os.path.join(out_dir,"runs.jsonl"),"w")
    paths_read=["/identity/api/v2/user/dashboard","/workshop/api/shop/products","/community/api/v2/community/posts/recent"]
    def emit_envoy(ts,ent,method,path,code,ust,byts):
        envoy.write(json.dumps({"ts_ns":str(int(ts*1e9)),"labels":{"job":"envoy-access"},
            "line":json.dumps({"method":method,"path":path,"response_code":code,
            "upstream_service_time":ust,"bytes_sent":byts,"response_time":ust+5,
            "svid":f"spiffe://ztlab.local/aws/{ent}"})})+"\n")
    def emit_opa(ts,ent,method,path,decision,dest,posture=None,stepup=None):
        opa.write(json.dumps({"ts_ns":str(int(ts*1e9)),"labels":{"job":"opa-decisions",
            "opa_result":str(decision).lower()},
            "line":json.dumps({"result":decision,"action":method,"resource":path,
            "svid":f"spiffe://ztlab.local/aws/{ent}","device_posture":posture,"step_up":stepup,
            "input":{"attributes":{"source":{"principal":f"spiffe://ztlab.local/aws/{ent}"},
            "destination":{"principal":"spiffe://ztlab.local/aws/crapi-workshop"},
            "request":{"http":{"method":method,"path":path}}}}})})+"\n")
    # N1: 60 cửa sổ lành tính, ~0 deny
    t=base
    for w in range(60):
        ent="bff"
        for _ in range(random.randint(8,15)):
            t+=random.uniform(0.5,4); p=random.choice(paths_read)
            emit_envoy(t,ent,"GET",p,"200",random.uniform(2,8),random.randint(200,2000))
            emit_opa(t,ent,"GET",p,True,None)
            if random.random()<0.02:  # hiếm deny lành tính ngẫu nhiên
                emit_envoy(t,ent,"POST","/community/api/v2/community/posts","403",random.uniform(2,8),100)
                emit_opa(t,ent,"POST","/community/api/v2/community/posts",False,None)
        t+=random.uniform(5,20)
    # N2: 16 phiên benign_noise — CÓ deny vừa phải (1–4), path GIỐNG A (không rò rỉ).
    # Thỉnh thoảng posture non-compliant / lý do step_up_required để các đặc trưng
    # posture_bad/reason/stepup tính được. Mỗi phiên cách ≥60s → nằm cửa sổ riêng.
    for s in range(16):
        t0=t; ent="bff"; ndeny=random.randint(1,8)   # chồng dải deny với attack → khó tách (GO)
        posture = "non-compliant" if s % 3 == 0 else None
        for _ in range(random.randint(5,10)):
            t+=random.uniform(0.5,5); p=random.choice(paths_read)
            emit_envoy(t,ent,"GET",p,"200",random.uniform(2,8),random.randint(200,1500)); emit_opa(t,ent,"GET",p,True,None,posture)
        for _ in range(ndeny):
            t+=random.uniform(0.5,5)
            emit_envoy(t,ent,"GET","/workshop/api/shop/orders/all","403",random.uniform(2,8),120)
            emit_opa(t,ent,"GET","/workshop/api/shop/orders/all",False,None,posture)
        runs.write(json.dumps({"class":"benign_noise","noise_type":"role_mismatch",
            "target_entity":"bff","t_start":_iso(t0),"t_end":_iso(t+1)})+"\n")
        t+=random.uniform(65,120)
    # A: 16 lượt attack — CƯỜNG ĐỘ cao hơn (nhiều deny, nhanh), path CHUNG với N2
    # (KHÔNG rò rỉ path/id riêng). Mỗi lượt cách ≥60s → cửa sổ riêng.
    for a in range(16):
        t0=t; ent="bff"; nd=random.randint(6,14)
        for _ in range(nd):
            t+=random.uniform(0.1,1.2)   # nhanh hơn N2 (nhịp độ là tín hiệu thật)
            code = "503" if random.random()<0.05 else "403"
            emit_envoy(t,ent,"GET","/workshop/api/shop/orders/all",code,random.uniform(2,8),120)
            emit_opa(t,ent,"GET","/workshop/api/shop/orders/all",False,None)
        runs.write(json.dumps({"run_id":f"r{a}","scenario":"lateral_movement","class":"attack",
            "variant_group":"train:lateral_community","status":"attack","target_entity":"bff",
            "t_start":_iso(t0),"t_end":_iso(t+1)})+"\n")
        t+=random.uniform(65,120)
    # A HOLDOUT (slow_drip THƯA) — kiểm §B1d: cửa sổ không có request tấn công →
    # attack_idle (loại); đủ thưa để tỉ lệ idle holdout >50% → cảnh báo.
    for a in range(6):
        t0=t; ent="bff"; end=t+600; nxt=t+40
        while t < end:
            t += random.uniform(8,14)
            if t >= nxt:
                emit_envoy(t,ent,"GET","/workshop/api/shop/orders/all","403",5,120)
                emit_opa(t,ent,"GET","/workshop/api/shop/orders/all",False,None)
                nxt = t + random.uniform(150,210)   # thưa → nhiều cửa sổ idle
            else:
                p=random.choice(paths_read)
                emit_envoy(t,ent,"GET",p,"200",5,500); emit_opa(t,ent,"GET",p,True,None)
        runs.write(json.dumps({"run_id":f"h{a}","scenario":"lateral_movement","class":"attack",
            "variant_group":"holdout:lateral_slow","status":"attack","target_entity":"bff",
            "t_start":_iso(t0),"t_end":_iso(t+1)})+"\n")
        t+=random.uniform(30,60)
    for fh in (envoy,opa,runs): fh.close()
    # bff rỗng (tuỳ chọn)
    open(os.path.join(out_dir,"bff.jsonl"),"w").close()
    print(f"[synth] đã sinh log + runs.jsonl → {out_dir}")

def _iso(e): return datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ───────────────────── CLI ─────────────────────────────────────────────
def main():
    ap=argparse.ArgumentParser(description="Giai đoạn B §5 — pipeline cổng 2 giờ")
    sub=ap.add_subparsers(dest="cmd", required=True)
    e=sub.add_parser("export"); e.add_argument("--loki",default="http://localhost:13100")
    e.add_argument("--start",type=float,required=True); e.add_argument("--end",type=float,required=True)
    e.add_argument("--out",required=True)
    # §B4 mục 0.1 — bài học B3 vế thứ hai: try/except cô lập lỗi là CHƯA đủ,
    # export còn phải KHẲNG ĐỊNH kết quả không rỗng, không chỉ không-crash.
    # envoy/opa KHÔNG BAO GIỜ được rỗng trong một khúc có lưu lượng; bff chỉ
    # rỗng hợp lệ khi khúc đó thật sự không có phiên đăng nhập nào (hiếm, cờ
    # --allow-empty-bff dành cho trường hợp đó, KHÔNG dùng mặc định).
    e.add_argument("--allow-empty-bff", action="store_true",
                    help="chấp nhận bff.jsonl rỗng (chỉ dùng khi khúc THẬT KHÔNG có phiên đăng nhập)")
    r=sub.add_parser("run"); r.add_argument("--logs",default=None,
        help="1 thư mục khúc, HOẶC nhiều thư mục nối bằng dấu phẩy (cộng dồn N khúc, "
             "§B6 mục 1 — streaming, bộ nhớ không tăng theo số khúc)")
    r.add_argument("--features",default=None,
        help="§B7 mục 2: thư mục (nối dấu phẩy) chứa bảng đặc trưng đã sinh bằng "
             "`featurize` — đọc bảng thay vì log thô, vài giây thay vì hàng giờ. "
             "Dùng --logs HOẶC --features, không cả hai.")
    r.add_argument("--runs",default=None,help="bắt buộc nếu dùng --logs; không cần nếu dùng --features")
    r.add_argument("--window",type=int,default=60); r.add_argument("--step",type=int,default=60); r.add_argument("--out",required=True)
    f=sub.add_parser("featurize",
        help="§B7 mục 2: đọc log MỘT khúc, sinh bảng đặc trưng cho cả 3 độ rộng cửa sổ")
    f.add_argument("--logs",required=True); f.add_argument("--runs",required=True)
    f.add_argument("--out",default=None,help="mặc định: ghi ngay trong --logs")
    f.add_argument("--widths",default="60,300,600")
    f.add_argument("--chunk-id",default=None)
    s=sub.add_parser("synth"); s.add_argument("--out",required=True)
    sub.add_parser("selftest")
    a=ap.parse_args()
    if a.cmd=="export":
        counts=loki_export(a.loki,a.start,a.end,a.out)
        json.dump({"counts":counts,"start":a.start,"end":a.end},
                  open(os.path.join(a.out,"export_counts.json"),"w"), indent=2, ensure_ascii=False)
        required=["envoy","opa"] + ([] if a.allow_empty_bff else ["bff"])
        empty=[name for name in required if counts.get(name,0)==0]
        if empty:
            for name in empty:
                print(f"[export] RỖNG: luồng '{name}' = 0 dòng trong [{a.start},{a.end}] "
                      f"(selector {STREAMS[name]!r}) — khúc KHÔNG hợp lệ, không ghi vào tổng giờ.",
                      file=sys.stderr)
            print(f"[export] KẾT QUẢ: {counts}", file=sys.stderr)
            sys.exit(1)
        print(f"[export] OK — mọi luồng bắt buộc đều >0 dòng: {counts}")
    elif a.cmd=="run":
        if a.features:
            feature_dirs=[d.strip() for d in a.features.split(",") if d.strip()]
            run_from_features(feature_dirs,a.out,a.window)
        else:
            if not a.logs or not a.runs:
                print("run: cần --logs VÀ --runs (hoặc dùng --features)", file=sys.stderr); sys.exit(1)
            chunk_dirs=[d.strip() for d in a.logs.split(",") if d.strip()]
            run(chunk_dirs,a.runs,a.window,a.step,a.out)
    elif a.cmd=="featurize":
        widths=tuple(int(x) for x in a.widths.split(",") if x.strip())
        featurize_chunk(a.logs,a.runs,a.out,widths,a.chunk_id)
    elif a.cmd=="synth": synth(a.out)
    elif a.cmd=="selftest":
        import tempfile; d=tempfile.mkdtemp(prefix="phaseb_gate_")
        synth(d); res=run(d,os.path.join(d,"runs.jsonl"),60,60,d)
        assert res["verdict"] in ("GO","NO_TOO_EASY","NO_TOO_HARD","NO_RULE_TIE","INSUFFICIENT_DATA")
        # unit: identity_leakage_scan — uuid chỉ ở attack bị gắn cờ; uuid trải
        # đều hai lớp thì KHÔNG.
        leaky="aaaaaaaa-1111-2222-3333-444444444444"; shared="bbbbbbbb-1111-2222-3333-555555555555"
        runs_u=[{"class":"attack","entity":"bff","variant_group":"","t0":0,"t1":100}]
        evs=[]
        for t in range(5): evs.append({"entity":"bff","ts":t*2,"path":f"/vehicle/{leaky}/location"})      # trong cửa sổ attack
        for t in range(5): evs.append({"entity":"bff","ts":200+t*2,"path":f"/vehicle/{shared}/location"}) # ngoài → benign
        for t in range(3): evs.append({"entity":"bff","ts":t*2,"path":f"/vehicle/{shared}/location"})     # cũng trong attack
        fl=identity_leakage_scan(evs,runs_u,min_occ=3)["flagged"]
        ids={f["identity"]:f["dominant_class"] for f in fl}
        assert leaky in ids and ids[leaky]=="attack", f"phải gắn cờ {leaky}: {fl}"
        assert shared not in ids, f"{shared} trải hai lớp — KHÔNG được gắn cờ: {fl}"
        print(f"[selftest] identity_leakage: gắn cờ {list(ids)} (đúng: chỉ uuid lệch-attack)")
        # unit: path_leakage_scan — path CHỈ ở attack bị gắn cờ; path trải hai lớp thì KHÔNG.
        evp=[]
        for t in range(8): evp.append({"entity":"bff","ts":t,"path":"/identity/api/v2/vehicle/zzz/location"})   # attack-only
        for t in range(8): evp.append({"entity":"bff","ts":t,"path":"/workshop/api/shop/products"})            # attack window
        for t in range(8): evp.append({"entity":"bff","ts":300+t,"path":"/workshop/api/shop/products"})        # benign window
        plf=path_leakage_scan(evp,runs_u,min_occ=3)["flagged"]
        paths={f["path"]:f["dominant_class"] for f in plf}
        assert any(p.endswith("/location") or p=="/identity" for p in paths), f"path attack-only phải bị cờ: {plf}"
        assert "/workshop/api/shop/products" not in paths, f"path trải hai lớp KHÔNG được cờ: {plf}"
        print(f"[selftest] path_leakage: gắn cờ {sorted(paths)} (đúng: path lệch-attack, bỏ qua path chung)")
        print(f"[selftest] OK — verdict={res['verdict']} (pipeline chạy trọn)")

if __name__=="__main__":
    main()
