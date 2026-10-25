#!/usr/bin/env python3
"""Giai đoạn C — Bước 5: dịch vụ CHẤM ĐIỂM RỦI RO (shadow mode).

Đề cương mục 6 Bước 5 + mục 7: "Mô hình được đóng gói thành dịch vụ chấm điểm
rủi ro chạy SONG SONG, KHÔNG chặn giao dịch. Chạy ở shadow mode để đo false
positive thực tế, sau đó phát cảnh báo kèm bằng chứng ... cho người vận hành."

Mỗi chu kỳ (mặc 60 s): kéo log `--window` giây gần nhất từ Loki → tính đặc trưng
bằng ĐÚNG `ml/features_v2.py` (giống hệt lúc huấn luyện) → nạp mô hình đã đóng
gói (`ml/model/bola_detector.joblib` do `evaluate.py --save-model` xuất) → chấm
điểm → ghi nhật ký shadow; cửa sổ vượt ngưỡng thì (tùy chọn) phát cảnh báo.

KHÔNG nằm trên đường xử lý đồng bộ của request (chỉ đọc log sau khi đã ghi), nên
không làm tăng độ trễ giao dịch — đúng ràng buộc đề cương.

  python3 ml/score.py selftest                     # kiểm phần chấm điểm (không cần Loki)
  python3 ml/score.py once  --loki http://localhost:13100
  python3 ml/score.py loop  --loki http://localhost:13100 --interval 60
  python3 ml/score.py loop  --post --incident-url http://localhost:8091   # phát cảnh báo thật

CHÚ Ý: phần kéo-log + tính đặc trưng CHỈ chạy được khi có Loki sống; hãy xác
thực bằng `once` trên VM trước khi bật `loop`. `--post` là TẠM: endpoint
`POST /evidence/{id}/risk-score` của incident-analyzer gắn điểm vào MỘT evidence
ĐÃ CÓ; cảnh báo do ML tự phát hiện (chưa có evidence) cần endpoint tạo mới —
xem HUONG-DAN-TIEP-THEO-VM.md §5. Mặc định là shadow (chỉ ghi, không phát).
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import tempfile
import time
import urllib.request
from datetime import datetime, timezone

import pandas as pd

import features_v2 as fv  # dùng lại loki_export (qua fv.gate), build_chunk, History, FEATURES_*

MODEL_DEFAULT = os.path.join(os.path.dirname(__file__), "model", "bola_detector.joblib")


def load_bundle(path: str) -> dict:
    import joblib
    if not os.path.exists(path):
        raise SystemExit(f"!! chưa có mô hình {path} — chạy evaluate.py --save-model trước")
    b = joblib.load(path)
    for k in ("model", "feature_cols", "threshold"):
        if k not in b:
            raise SystemExit(f"!! artifact thiếu khoá '{k}' — mô hình đóng gói sai")
    return b


def featurize_recent(loki_url: str, window: int, step: int, now: float, margin: int = 60) -> pd.DataFrame:
    """Kéo [now-window-margin, now] từ Loki, tính đặc trưng, trả cửa sổ MỚI NHẤT
    của mỗi thực thể. Gán nhãn trống (runs=[]) vì chấm điểm không cần nhãn."""
    tmp = tempfile.mkdtemp(prefix="score_")
    chunk = os.path.join(tmp, "live"); os.makedirs(chunk)
    fv.gate.loki_export(loki_url, now - window - margin, now, chunk)
    out = os.path.join(tmp, "feat.csv.gz")
    fv.build_chunk(chunk, [], fv.History(), out, window=window, step=step, users_only=False)
    with gzip.open(out, "rt") as fh:
        df = pd.read_csv(fh)
    if df.empty:
        return df
    # cửa sổ mới nhất mỗi entity (một điểm rủi ro "hiện tại" cho mỗi thực thể)
    return df.sort_values("window_end").groupby("entity", as_index=False).tail(1)


def score(df: pd.DataFrame, bundle: dict, thr_override: float | None) -> pd.DataFrame:
    cols = bundle["feature_cols"]
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise SystemExit(f"!! bảng đặc trưng thiếu cột {missing} — mô hình và featurizer lệch phiên")
    thr = bundle["threshold"] if thr_override is None else thr_override
    df = df.copy()
    df["risk"] = bundle["model"].predict_proba(df[cols])[:, 1]
    df["alert"] = df["risk"] >= thr
    return df.sort_values("risk", ascending=False)


def emit(df: pd.DataFrame, bundle: dict, out_dir: str, post: bool, incident_url: str) -> int:
    os.makedirs(out_dir, exist_ok=True)
    log = os.path.join(out_dir, "shadow_scores.jsonl")
    n_alert = 0
    with open(log, "a") as fh:
        for _, r in df.iterrows():
            rec = {"ts": datetime.now(timezone.utc).isoformat(), "entity": r["entity"],
                   "window_start": float(r["window_start"]), "window_end": float(r["window_end"]),
                   "risk": round(float(r["risk"]), 4), "alert": bool(r["alert"]),
                   "model_scope": bundle.get("scope"), "threshold": float(bundle["threshold"])}
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            if r["alert"]:
                n_alert += 1
                if post:
                    _post_alert(incident_url, rec)
    return n_alert


def _post_alert(incident_url: str, rec: dict):
    """TẠM (xem chú thích đầu file): thử gửi cảnh báo do ML phát hiện. Best-effort,
    nuốt lỗi để shadow loop không chết vì incident-analyzer trục trặc."""
    try:
        body = json.dumps({"attack_type": "bola", "source": "ml-shadow",
                           "risk_score": rec["risk"], "entity": rec["entity"],
                           "window": [rec["window_start"], rec["window_end"]]}).encode()
        req = urllib.request.Request(incident_url.rstrip("/") + "/evidence/ml-alert/risk-score",
                                     data=body, headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=8).read()
    except Exception as e:
        print(f"[score] (cảnh báo không gửi được: {e})", flush=True)


def run_once(args, bundle) -> int:
    now = time.time()
    df = featurize_recent(args.loki, args.window, args.step, now)
    if df.empty:
        print(f"[score] {datetime.now().strftime('%H:%M:%S')} — không có cửa sổ nào trong {args.window}s gần nhất")
        return 0
    df = score(df, bundle, args.threshold)
    n_alert = emit(df, bundle, args.out, args.post, args.incident_url)
    top = df.iloc[0]
    print(f"[score] {datetime.now().strftime('%H:%M:%S')} — {len(df)} thực thể, "
          f"{n_alert} cảnh báo (ngưỡng {bundle['threshold']:.3f}); "
          f"cao nhất: {top['entity']} risk={top['risk']:.3f}", flush=True)
    return n_alert


def selftest():
    """Kiểm phần CHẤM ĐIỂM (không cần Loki): tạo bảng đặc trưng giả đúng cột của
    mô hình đã đóng gói, chấm điểm, kiểm risk∈[0,1] và cờ alert đúng theo ngưỡng.
    Cần một artifact mô hình — bỏ qua (SKIP) nếu chưa có, để selftest không
    'đỏ' chỉ vì chưa train."""
    import random
    path = os.environ.get("MODEL", MODEL_DEFAULT)
    if not os.path.exists(path):
        print(f"[selftest] SKIP — chưa có {path} (chạy evaluate.py --save-model trước)")
        return
    b = load_bundle(path)
    cols = b["feature_cols"]
    rows = [{**{c: random.random() for c in cols}, "entity": f"e{i}",
             "window_start": 0.0, "window_end": 300.0} for i in range(20)]
    df = score(pd.DataFrame(rows), b, None)
    assert df["risk"].between(0, 1).all(), "risk phải ∈ [0,1]"
    assert (df["alert"] == (df["risk"] >= b["threshold"])).all(), "cờ alert phải khớp ngưỡng"
    assert df["risk"].is_monotonic_decreasing, "phải sắp theo risk giảm dần"
    print(f"[selftest] OK — chấm {len(df)} cửa sổ, {int(df['alert'].sum())} vượt ngưỡng "
          f"{b['threshold']:.3f}, risk∈[{df['risk'].min():.3f},{df['risk'].max():.3f}]")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("once", "loop"):
        p = sub.add_parser(name)
        p.add_argument("--model", default=MODEL_DEFAULT)
        p.add_argument("--loki", default="http://localhost:13100")
        p.add_argument("--window", type=int, default=fv.WINDOW)
        p.add_argument("--step", type=int, default=fv.STEP)
        p.add_argument("--out", default="results/c4/shadow")
        p.add_argument("--threshold", type=float, default=None, help="ghi đè ngưỡng của mô hình")
        p.add_argument("--post", action="store_true", help="phát cảnh báo (mặc: chỉ shadow, không phát)")
        p.add_argument("--incident-url", default="http://localhost:8091")
        if name == "loop":
            p.add_argument("--interval", type=float, default=60)
    sub.add_parser("selftest")
    args = ap.parse_args()

    if args.cmd == "selftest":
        return selftest()
    bundle = load_bundle(args.model)
    print(f"[score] mô hình: {args.model} (scope={bundle.get('scope')}, ngưỡng={bundle['threshold']:.3f}, "
          f"{len(bundle['feature_cols'])} đặc trưng) — chế độ {'PHÁT cảnh báo' if args.post else 'SHADOW (chỉ ghi)'}")
    if args.cmd == "once":
        return run_once(args, bundle)
    while True:
        try:
            run_once(args, bundle)
        except SystemExit:
            raise
        except Exception as e:
            print(f"[score] lỗi chu kỳ (bỏ qua, chạy tiếp): {e}", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
