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
import argparse, json, math, os, random, re, statistics, sys, urllib.parse, urllib.request
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
        path = os.path.join(out_dir, f"{name}.jsonl")
        n = 0
        with open(path, "w") as fh:
            # phân trang theo thời gian, forward, 5000 dòng/lần
            cur = int(start_e * 1e9); end_ns = int(end_e * 1e9)
            while cur < end_ns:
                qs = urllib.parse.urlencode({"query": sel, "start": str(cur), "end": str(end_ns),
                                             "limit": 5000, "direction": "forward"})
                url = f"{loki_url}/loki/api/v1/query_range?{qs}"
                data = json.load(urllib.request.urlopen(url, timeout=60))["data"]["result"]
                last = cur
                for stream in data:
                    labels = stream["stream"]
                    for ts, line in stream["values"]:
                        fh.write(json.dumps({"ts_ns": ts, "labels": labels, "line": line}) + "\n")
                        n += 1; last = max(last, int(ts))
                if not data or last <= cur:
                    break
                cur = last + 1
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

def parse_events(logs_dir: str) -> list[dict]:
    """Trả về list sự kiện chuẩn hoá từ 3 stream. entity = danh tính HÀNH ĐỘNG:
    bff → username; envoy/opa → source_principal (rút gọn service)."""
    events = []
    def add(**kw): events.append(kw)

    # envoy-access
    fp = os.path.join(logs_dir, "envoy.jsonl")
    if os.path.exists(fp):
        for raw in open(fp):
            r = json.loads(raw); b = _body(r)
            ts = int(r["ts_ns"]) / 1e9
            code = str(b.get("response_code", r["labels"].get("response_code", "")))
            add(ts=ts, stream="envoy",
                entity=_princ(b.get("svid") or r["labels"].get("source_ip", "")),
                method=b.get("method", r["labels"].get("method", "")),
                path=b.get("path", r["labels"].get("path", "")),
                code=code, decision=None, dest=None,
                posture=None, stepup=None, reason=None, sid=None,
                bytes=_num(b.get("bytes_sent")), ust=_num(b.get("upstream_service_time")),
                rt=_num(b.get("response_time")))
    # opa-decisions
    fp = os.path.join(logs_dir, "opa.jsonl")
    if os.path.exists(fp):
        for raw in open(fp):
            r = json.loads(raw); b = _body(r)
            ts = int(r["ts_ns"]) / 1e9
            inp = (b.get("input") or {}).get("attributes") or {}
            http = (inp.get("request") or {}).get("http") or {}
            src = (inp.get("source") or {}).get("principal") or b.get("svid") or r["labels"].get("source_principal", "")
            dec = b.get("result")
            if dec is None and "opa_result" in r["labels"]:
                dec = (r["labels"]["opa_result"] == "true")
            add(ts=ts, stream="opa", entity=_princ(src),
                method=http.get("method", b.get("action", "")),
                path=http.get("path", b.get("resource", "")),
                code=None, decision=(dec if isinstance(dec, bool) else None),
                dest=(inp.get("destination") or {}).get("principal"),
                posture=b.get("device_posture"), stepup=b.get("step_up"),
                reason=None, sid=None, bytes=None, ust=None, rt=None)
    # bff-audit
    fp = os.path.join(logs_dir, "bff.jsonl")
    if os.path.exists(fp):
        for raw in open(fp):
            r = json.loads(raw); b = _body(r)
            ts = b.get("ts") or int(r["ts_ns"]) / 1e9
            ev = b.get("event", "")
            denied = ev in ("rbac_denied", "device_trust_denied", "step_up_required")
            add(ts=float(ts), stream="bff", entity=b.get("username") or "?",
                method=None, path=b.get("path"), code=("403" if denied else None),
                decision=(False if denied else None), dest=None,
                posture=None, stepup=b.get("acr"), reason=ev, sid=b.get("sid"),
                bytes=None, ust=None, rt=None)
    events.sort(key=lambda e: e["ts"])
    return events

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

def is_attack_event(e: dict, run: dict) -> bool:
    """§B1d: sự kiện này có PHẢI là một request của CHÍNH lượt tấn công không
    (không chỉ 'cùng entity, cùng khoảng thời gian'). Dùng CHỮ KÝ hành vi của
    kịch bản (không marker tiêm): bola khớp path vehicle/{id}/location với id
    thuộc victims_used đã ghi; các họ dựa-deny khớp deny; v.v. Mặc định (họ lạ):
    coi mọi request trong khoảng là của lượt (giữ hành vi cũ)."""
    sc = run.get("scenario", "")
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
    return deny or True   # mặc định: mọi request trong khoảng

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

def featurize(events: list[dict], runs: list[dict], window: int, step: int):
    """§B1d: nhãn cửa sổ THEO REQUEST THẬT, không theo khoảng thời gian.
      - attack: tile mỗi lượt attack trên lưới; cửa sổ CHỨA ≥1 request của lượt
        (is_attack_event) → 'attack'; cửa sổ trong [t0,t1] nhưng KHÔNG có request
        của lượt → 'attack_idle' (ĐẾM riêng, LOẠI khỏi train/test).
      - benign/benign_noise: cửa sổ per-entity NGOÀI mọi khoảng attack.
    Trả (rows, idle_by_group)."""
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
                idle[r["variant_group"] or "attack"] += 1   # attack_idle — loại
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

def identity_leakage_scan(events, runs, min_occ=3, max_share=0.9):
    """§B1b (b'): RÒ RỈ DANH TÍNH — một vehicleid/id/email NÀO xuất hiện gần như
    CHỈ ở một lớp (>max_share) là đường tắt theo danh tính, không theo hành vi.
    Luân phiên nạn nhân (crapi_bola.sh) phải trải định danh qua nhiều lớp; check
    này XÁC NHẬN điều đó. Đặc trưng vi phạm phải ở dạng QUAN HỆ (n_target = SỐ
    uuid khác nhau) chứ KHÔNG phải dạng danh tính (uuid NÀO) — bảng đặc trưng
    hiện chỉ dùng n_target (quan hệ), không one-hot uuid, nên an toàn; check này
    canh nếu ai đó thêm đặc trưng danh tính hoặc nếu luân phiên hỏng."""
    import re as _re
    idclass = defaultdict(Counter)
    for e in events:
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
    for val, cc in idclass.items():
        tot = sum(cc.values())
        if tot < min_occ:
            continue
        top_class, top_n = cc.most_common(1)[0]
        share = top_n / tot
        if share > max_share:
            flagged.append({"identity": val, "total": tot, "dominant_class": top_class,
                            "share": round(share, 3), "by_class": dict(cc)})
    # ưu tiên các định danh lệch về attack lên đầu
    flagged.sort(key=lambda f: (f["dominant_class"] != "attack", -f["total"]))
    return flagged

def path_leakage_scan(events, runs, min_occ=5, max_share=0.9):
    """§B1c (b''): RÒ RỈ TẦNG PATH — không đường dẫn (đã chuẩn hoá tham số) hay
    TIỀN TỐ nào được xuất hiện >max_share ở một lớp. Nếu N1 không bao giờ gọi
    /identity/api/v2/vehicle/{id}/location thì chính path đó là nhãn hoàn hảo
    (mô hình recall~1 bằng luật khớp path) mà kiểm uuid KHÔNG bắt được. §B1c sửa
    gốc: N1 gọi path đó với uuid của chính mình (crapi_load_n1.sh). Check này
    XÁC NHẬN không còn path/tiền tố lệch lớp; nếu còn, đặc trưng dạng PATH
    (one-hot path/prefix) phải BỎ — dùng dạng quan hệ n_path/n_actionclass."""
    pathclass = defaultdict(Counter)
    for e in events:
        p = _norm_path(e.get("path") or "")
        if not p or p == "/":
            continue
        lab, _ = label_for(e["entity"], e["ts"], runs)
        parts = [seg for seg in p.split("/") if seg]
        for k in range(1, len(parts) + 1):          # full path + mọi tiền tố
            pathclass["/" + "/".join(parts[:k])][lab] += 1
    flagged = []
    for path, cc in pathclass.items():
        tot = sum(cc.values())
        if tot < min_occ:
            continue
        top_class, top_n = cc.most_common(1)[0]
        share = top_n / tot
        if share > max_share:
            flagged.append({"path": path, "total": tot, "dominant_class": top_class,
                            "share": round(share, 3), "by_class": dict(cc)})
    flagged.sort(key=lambda f: (f["dominant_class"] != "attack", -f["total"]))
    return flagged

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

def recall_by_window_width(events, runs, widths=(60,300,600)):
    """§B1e: recall theo lượt ở các độ rộng cửa sổ (tumbling step=width), tách
    train/holdout — xác định độ rộng phù hợp với nhịp nào. attack_idle cao ở
    cửa sổ hẹp là tín hiệu CHỌN ĐỘ RỘNG, KHÔNG phải làm slow_drip dày lên."""
    out={}
    for w in widths:
        rws,idle=featurize(events,runs,w,w)
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
        ho_idle=sum(c for vg,c in idle.items() if str(vg).startswith("holdout"))
        out[f"{w}s"]={"recall_by_run":run_recall(rows_te,prob),
                      "attack_idle_holdout":ho_idle}
    return out

# ───────────────────── RUN (gắn mọi thứ) ──────────────────────────────
def run(logs_dir, runs_file, window, step, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    events=parse_events(logs_dir)
    runs=load_runs(runs_file)
    rows,idle=featurize(events, runs, window, step)
    labels=Counter(r["label"] for r in rows)
    # §B1d: attack_idle đã LOẠI; đếm theo nhóm biến thể + cảnh báo holdout thưa.
    idle_total=sum(idle.values())
    idle_by_grp={"train":0,"holdout":0,"other":0}
    for vg,c in idle.items():
        k="train" if str(vg).startswith("train") else ("holdout" if str(vg).startswith("holdout") else "other")
        idle_by_grp[k]+=c
    atk_win_by_grp={"train":0,"holdout":0,"other":0}
    for r in rows:
        if r["label"]!="attack": continue
        vg=r.get("variant_group",""); k="train" if vg.startswith("train") else ("holdout" if vg.startswith("holdout") else "other")
        atk_win_by_grp[k]+=1
    print(f"[run] sự kiện={len(events)} runs={len(runs)} cửa_sổ={len(rows)} nhãn={dict(labels)}")
    print(f"[run] attack_idle LOẠI={idle_total} theo nhóm={dict(idle)}")
    result={"n_events":len(events),"n_runs":len(runs),"n_windows":len(rows),
            "label_counts":dict(labels),"window_s":window,"step_s":step,
            "attack_idle_total":idle_total,"attack_idle_by_variant":dict(idle),
            "attack_idle_by_group":idle_by_grp,"attack_windows_by_group":atk_win_by_grp}
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
    result["identity_leakage_flagged"]=identity_leakage_scan(events, runs)
    # (b'') leakage — TẦNG PATH (path/tiền tố lệch về một lớp)
    result["path_leakage_flagged"]=path_leakage_scan(events, runs)
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
    result["recall_by_window_width"]=recall_by_window_width(events,runs)
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
    idl=result['identity_leakage_flagged']
    print(f"[run] rò rỉ DANH TÍNH (>90% 1 lớp): {len(idl)} định danh" +
          (f" — ví dụ {idl[0]['identity']} {idl[0]['by_class']}" if idl else " (không có — luân phiên OK)"))
    pl=result['path_leakage_flagged']
    print(f"[run] rò rỉ TẦNG PATH (>90% 1 lớp): {len(pl)} path/tiền tố" +
          (f" — vd {pl[0]['path']} {pl[0]['by_class']} → BỎ đặc trưng dạng path" if pl else " (không có — N1 có gọi path tấn công hợp lệ)"))
    print(f"[run] không tính được: {result['features_not_computable']}")
    dl=result["detection_latency"]["by_group"]
    print(f"[run] ĐỘ TRỄ PHÁT HIỆN (§B1e) train={dl.get('train')} holdout={dl.get('holdout')}")
    print(f"[run] RECALL theo ĐỘ RỘNG CỬA SỔ (§B1e): " +
          " ".join(f"{w}={(v.get('recall_by_run') or {}).get('all')}/{(v.get('recall_by_run') or {}).get('holdout')}(all/holdout)"
                   for w,v in result['recall_by_window_width'].items()))
    print(f"[run] VERDICT: {verdict} — {why}")
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
    r=sub.add_parser("run"); r.add_argument("--logs",required=True); r.add_argument("--runs",required=True)
    r.add_argument("--window",type=int,default=60); r.add_argument("--step",type=int,default=60); r.add_argument("--out",required=True)
    s=sub.add_parser("synth"); s.add_argument("--out",required=True)
    sub.add_parser("selftest")
    a=ap.parse_args()
    if a.cmd=="export": loki_export(a.loki,a.start,a.end,a.out)
    elif a.cmd=="run": run(a.logs,a.runs,a.window,a.step,a.out)
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
        fl=identity_leakage_scan(evs,runs_u)
        ids={f["identity"]:f["dominant_class"] for f in fl}
        assert leaky in ids and ids[leaky]=="attack", f"phải gắn cờ {leaky}: {fl}"
        assert shared not in ids, f"{shared} trải hai lớp — KHÔNG được gắn cờ: {fl}"
        print(f"[selftest] identity_leakage: gắn cờ {list(ids)} (đúng: chỉ uuid lệch-attack)")
        # unit: path_leakage_scan — path CHỈ ở attack bị gắn cờ; path trải hai lớp thì KHÔNG.
        evp=[]
        for t in range(8): evp.append({"entity":"bff","ts":t,"path":"/identity/api/v2/vehicle/zzz/location"})   # attack-only
        for t in range(8): evp.append({"entity":"bff","ts":t,"path":"/workshop/api/shop/products"})            # attack window
        for t in range(8): evp.append({"entity":"bff","ts":300+t,"path":"/workshop/api/shop/products"})        # benign window
        plf=path_leakage_scan(evp,runs_u,min_occ=3)
        paths={f["path"]:f["dominant_class"] for f in plf}
        assert any(p.endswith("/location") or p=="/identity" for p in paths), f"path attack-only phải bị cờ: {plf}"
        assert "/workshop/api/shop/products" not in paths, f"path trải hai lớp KHÔNG được cờ: {plf}"
        print(f"[selftest] path_leakage: gắn cờ {sorted(paths)} (đúng: path lệch-attack, bỏ qua path chung)")
        print(f"[selftest] OK — verdict={res['verdict']} (pipeline chạy trọn)")

if __name__=="__main__":
    main()
