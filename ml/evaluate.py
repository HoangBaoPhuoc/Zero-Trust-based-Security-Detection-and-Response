#!/usr/bin/env python3
"""Giai đoạn C — đánh giá mô hình phát hiện BOLA theo đúng đề cương KLTN
(mục 6, Bước 4; mục 7 tiêu chí nghiệm thu).

  - Ba cấu hình: baseline luật ngưỡng, chỉ nhóm A, nhóm A+B (XGBoost).
  - Chia theo THỜI GIAN theo khúc, có khúc đệm (buffer) giữa train và test;
    ngưỡng FPR 1% chọn trên khúc validation (khúc train cuối), không trên test.
  - PR-AUC, recall tại FPR 1%; CI bootstrap 95% cho chênh lệch PR-AUC, lấy
    mẫu lại theo LƯỢT tấn công (dương) và theo khối entity×giờ (âm).
  - Đối chứng âm (xáo nhãn train), kiểm biến thể chưa thấy (bỏ dương
    `holdout:*` khỏi train), độ quan trọng đặc trưng (đóng góp SHAP của XGBoost).
  - Ba phạm vi âm: `all` (mọi entity), `user` (chỉ người dùng), `same-user`
    (chỉ entity từng là kẻ tấn công) — `same-user` là phép kiểm shortcut:
    nếu kết quả chỉ đẹp ở `all`, mô hình đang phân biệt LOẠI entity chứ
    không phải hành vi tấn công.

Đọc được cả bảng v2 (`ml/features_v2.py`) lẫn bảng Giai đoạn B
(`*__features_w{60,300,...}.csv.gz` trong c2-export/c3-export).

  python3 ml/evaluate.py --features "results/c4/features_v2/*.csv.gz" --out results/c4/eval
  python3 ml/evaluate.py --features "c2-export/*_w300.csv.gz" --out /tmp/eval_legacy
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_curve

try:
    from xgboost import XGBClassifier, DMatrix
    HAVE_XGB = True
except ImportError:          # máy chưa cài xgboost vẫn chạy được, ghi rõ trong kết quả
    from sklearn.ensemble import HistGradientBoostingClassifier
    HAVE_XGB = False

V2_A = ["n_req", "pct_4xx", "pct_5xx", "n_path", "path_entropy", "rw_ratio", "gap_mean", "gap_cv",
        "bytes_sum", "bytes_max", "rt_p95", "n_obj", "n_obj_new", "frac_obj_new"]
V2_B = ["n_dst", "n_pair", "n_pair_new", "deny_count", "deny_rate", "xcloud_ratio",
        "n_xcloud_pair_new", "stepup_present", "posture_bad"]
V2_BASELINES = ["deny_rate", "n_obj_new"]
LEGACY_A = ["n_path", "n_target", "n_actionclass", "rw_ratio", "gap_mean", "gap_var", "code_4xx",
            "code_5xx", "ust_p95", "ust_max", "rt_p95", "n_actions", "bytes_max", "bytes_sum"]
LEGACY_B = ["deny_count", "deny_rate", "n_dest", "reason_kinds", "stepup_present", "posture_bad"]
LEGACY_BASELINES = ["deny_rate", "n_target"]
USER_RE = re.compile(r"^(testuser|victim|merchant|stepup|operator|ghost|attacker|analyst|demo)")


def load(pattern: str) -> tuple[pd.DataFrame, str]:
    files = sorted(glob.glob(pattern))
    if not files:
        sys.exit(f"không có file nào khớp {pattern}")
    df = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    fmt = "v2" if "n_obj_new" in df.columns else "legacy"
    if "entity_type" not in df.columns:
        df["entity_type"] = np.where(df["entity"].astype(str).str.match(USER_RE), "user", "workload")
    for c in ("scenario", "variant_group", "run_id"):
        df[c] = df[c].fillna("").astype(str)
    df["chunk"] = df["chunk_id"].astype(str).str[:5]
    ws = "window_start" if "window_start" in df.columns else "wstart"
    df["hour_block"] = (df[ws] // 3600).astype(int)
    return df, fmt


def prepare(df: pd.DataFrame, target: str, scope: str, warmup_sec: float) -> pd.DataFrame:
    d = df[df["label"] != "attack_idle"]
    d = d[~((d["label"] == "attack") & (d["scenario"] != target))]   # họ khác: ngoài phạm vi ML
    if warmup_sec and "hist_sec" in d.columns:
        d = d[d["hist_sec"] >= warmup_sec]
    if scope == "user":
        d = d[d["entity_type"] == "user"]
    elif scope == "same-user":
        attackers = set(d.loc[d["label"] == "attack", "entity"])
        d = d[d["entity"].isin(attackers)]
    d = d.copy()
    d["y"] = (d["label"] == "attack").astype(int)
    return d


def split_by_chunk(d: pd.DataFrame, test_chunks: int, buffer_chunks: int):
    chunks = sorted(d["chunk"].unique())
    if len(chunks) < test_chunks + buffer_chunks + 2:
        sys.exit(f"cần ≥ {test_chunks + buffer_chunks + 2} khúc, chỉ có {chunks}")
    test = chunks[-test_chunks:]
    train = chunks[:-(test_chunks + buffer_chunks)]
    return d[d["chunk"].isin(train[:-1])], d[d["chunk"] == train[-1]], d[d["chunk"].isin(test)], \
        {"train": train[:-1], "val": train[-1:], "buffer": chunks[len(train):-test_chunks], "test": test}


def fit(X, y, seed=0):
    spw = (len(y) - y.sum()) / max(y.sum(), 1)
    if HAVE_XGB:
        m = XGBClassifier(n_estimators=400, max_depth=4, learning_rate=0.05, subsample=0.8,
                          colsample_bytree=0.8, scale_pos_weight=spw, eval_metric="aucpr",
                          random_state=seed, n_jobs=4)
    else:
        m = HistGradientBoostingClassifier(max_depth=4, learning_rate=0.05, max_iter=400,
                                           class_weight="balanced", random_state=seed)
    return m.fit(X, y)


def recall_at_fpr(y, s, fpr=0.01) -> float:
    f, t, _ = roc_curve(y, s)
    return float(np.interp(fpr, f, t))


def thr_at_fpr(y_neg_scores, fpr=0.01) -> float:
    return float(np.quantile(y_neg_scores, 1 - fpr)) if len(y_neg_scores) else 1.0


def block_bootstrap_diff(te: pd.DataFrame, s1, s2, n=1000, seed=0):
    """CI 95% của PR-AUC(s1) − PR-AUC(s2). Dương lấy lại theo run_id (các cửa
    sổ cùng một lượt không độc lập — đề cương: CI ở mức lần chạy tấn công);
    âm lấy lại theo khối (entity, giờ)."""
    rng = np.random.default_rng(seed)
    pos_groups = te[te["y"] == 1].groupby("run_id").indices
    neg_groups = te[te["y"] == 0].groupby(["entity", "hour_block"]).indices
    pos_keys, neg_keys = list(pos_groups), list(neg_groups)
    if len(pos_keys) < 2:
        return None
    pos_idx = te.index[te["y"] == 1]; neg_idx = te.index[te["y"] == 0]
    loc = {i: k for k, i in enumerate(te.index)}
    out = []
    for _ in range(n):
        rows = [loc[pos_idx[j]] for k in rng.choice(len(pos_keys), len(pos_keys))
                for j in pos_groups[pos_keys[k]]]
        rows += [loc[neg_idx[j]] for k in rng.choice(len(neg_keys), len(neg_keys))
                 for j in neg_groups[neg_keys[k]]]
        rows = np.array(rows); y = te["y"].values[rows]
        out.append(average_precision_score(y, s1[rows]) - average_precision_score(y, s2[rows]))
    lo, hi = np.percentile(out, [2.5, 97.5])
    return [round(float(lo), 4), round(float(hi), 4)]


def top_features(model, X: pd.DataFrame, k=8):
    if not HAVE_XGB:
        return {}
    contrib = model.get_booster().predict(DMatrix(X), pred_contribs=True)[:, :-1]
    imp = pd.Series(np.abs(contrib).mean(axis=0), index=X.columns).sort_values(ascending=False)
    return {f: round(float(v), 4) for f, v in imp.head(k).items()}


def evaluate_scope(df, fmt, scope, args) -> dict:
    A, B = (V2_A, V2_B) if fmt == "v2" else (LEGACY_A, LEGACY_B)
    baselines = V2_BASELINES if fmt == "v2" else LEGACY_BASELINES
    d = prepare(df, args.target, scope, args.warmup_sec)
    tr, va, te, chunks = split_by_chunk(d, args.test_chunks, args.buffer_chunks)
    res = {"scope": scope, "chunks": chunks,
           "n": {k: {"windows": int(len(x)), "pos": int(x["y"].sum()),
                     "pos_runs": int(x.loc[x["y"] == 1, "run_id"].nunique())}
                 for k, x in (("train", tr), ("val", va), ("test", te))},
           "base_rate_test": round(float(te["y"].mean()), 5)}
    if tr["y"].sum() < 3 or te["y"].sum() < 3 or (te["y"] == 0).sum() < 100:
        res["skipped"] = "quá ít dương/âm để đánh giá"
        return res
    scores, configs = {}, {}
    for b in baselines:
        scores[f"baseline:{b}"] = te[b].values.astype(float)
    for name, cols in (("A", A), ("A+B", A + B)):
        m = fit(tr[cols], tr["y"].values)
        thr = thr_at_fpr(m.predict_proba(va[cols])[:, 1][va["y"].values == 0], args.fpr)
        s = m.predict_proba(te[cols])[:, 1]
        scores[name] = s
        configs[name] = {"model": m, "cols": cols, "thr": thr}
    for name, s in scores.items():
        r = {"pr_auc": round(float(average_precision_score(te["y"], s)), 4),
             "recall_at_fpr_oracle": round(recall_at_fpr(te["y"].values, s, args.fpr), 4)}
        if name in configs:
            pred = s >= configs[name]["thr"]
            r["recall_at_val_thr"] = round(float(pred[te["y"].values == 1].mean()), 4)
            r["fpr_at_val_thr"] = round(float(pred[te["y"].values == 0].mean()), 4)
            pos_runs = te.loc[te["y"] == 1].assign(hit=pred[te["y"].values == 1]).groupby("run_id")["hit"].any()
            r["run_recall_at_val_thr"] = round(float(pos_runs.mean()), 4)
        res.setdefault("metrics", {})[name] = r
    best_base = max(baselines, key=lambda b: res["metrics"][f"baseline:{b}"]["pr_auc"])
    res["ci_pr_auc_AB_minus_A"] = block_bootstrap_diff(te, scores["A+B"], scores["A"], args.boot)
    res["ci_pr_auc_AB_minus_baseline"] = block_bootstrap_diff(
        te, scores["A+B"], scores[f"baseline:{best_base}"], args.boot)
    res["best_baseline"] = best_base
    # đối chứng âm: xáo nhãn train, chấm trên test thật
    yshuf = np.random.default_rng(1).permutation(tr["y"].values)
    nc = fit(tr[A + B], yshuf).predict_proba(te[A + B])[:, 1]
    res["negative_control_pr_auc"] = round(float(average_precision_score(te["y"], nc)), 4)
    # biến thể chưa thấy: bỏ dương holdout:* khỏi train, đo recall trên dương holdout:* của test
    tr_seen = tr[~((tr["y"] == 1) & tr["variant_group"].str.startswith("holdout:"))]
    te_unseen = te[(te["y"] == 0) | te["variant_group"].str.startswith("holdout:")]
    if tr_seen["y"].sum() >= 3 and te_unseen["y"].sum() >= 3:
        cols = A + B
        m = fit(tr_seen[cols], tr_seen["y"].values)
        thr = thr_at_fpr(m.predict_proba(va[cols])[:, 1][va["y"].values == 0], args.fpr)
        s = m.predict_proba(te_unseen[cols])[:, 1]
        res["unseen_variant"] = {
            "pos_test": int(te_unseen["y"].sum()),
            "recall_at_val_thr": round(float((s >= thr)[te_unseen["y"].values == 1].mean()), 4),
            "recall_at_fpr_oracle": round(recall_at_fpr(te_unseen["y"].values, s, args.fpr), 4)}
    else:
        res["unseen_variant"] = "không đủ dương để tách biến thể train/holdout"
    res["top_features_AB"] = top_features(configs["A+B"]["model"], te[A + B])
    return res


def verdict(r: dict, fpr: float) -> list[str]:
    """Đối chiếu mục 7 đề cương (chỉ phần đo được từ bảng đặc trưng)."""
    if "metrics" not in r:
        return [f"- {r.get('skipped')}"]
    m = r["metrics"]; ok = lambda b: "ĐẠT" if b else "CHƯA ĐẠT"
    ci1, ci2 = r["ci_pr_auc_AB_minus_A"], r["ci_pr_auc_AB_minus_baseline"]
    lines = [
        f"- recall A+B tại FPR {fpr:.0%} (ngưỡng chọn trên validation) ≥ 0,80: "
        f"{m['A+B']['recall_at_val_thr']} (FPR thực {m['A+B']['fpr_at_val_thr']}) → {ok(m['A+B']['recall_at_val_thr'] >= 0.8)}",
        f"- A+B vượt A, CI 95% chênh PR-AUC không chứa 0: {ci1} → {ok(bool(ci1) and ci1[0] > 0)}",
        f"- A+B vượt baseline ({r['best_baseline']}), CI không chứa 0: {ci2} → {ok(bool(ci2) and ci2[0] > 0)}",
        f"- đối chứng âm ≈ base rate: {r['negative_control_pr_auc']} vs {r['base_rate_test']} → "
        f"{ok(r['negative_control_pr_auc'] <= 2 * r['base_rate_test'] + 0.01)}",
    ]
    uv = r["unseen_variant"]
    lines.append(f"- recall biến thể chưa thấy ≥ 0,70: " + (
        f"{uv['recall_at_val_thr']} → {ok(uv['recall_at_val_thr'] >= 0.7)}" if isinstance(uv, dict) else uv))
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--features", required=True, help="glob tới bảng đặc trưng (một độ rộng cửa sổ)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--target", default="bola")
    ap.add_argument("--scopes", default="all,user,same-user")
    ap.add_argument("--test-chunks", type=int, default=3)
    ap.add_argument("--buffer-chunks", type=int, default=1)
    ap.add_argument("--warmup-sec", type=float, default=1800, help="bỏ cửa sổ khi lịch sử entity còn ngắn (chỉ bảng v2)")
    ap.add_argument("--fpr", type=float, default=0.01)
    ap.add_argument("--boot", type=int, default=1000)
    args = ap.parse_args()
    df, fmt = load(args.features)
    os.makedirs(args.out, exist_ok=True)
    results = {"format": fmt, "model": "xgboost" if HAVE_XGB else "sklearn-hgb (xgboost chưa cài)",
               "features": args.features, "scopes": {}}
    md = [f"# Kết quả đánh giá ({fmt}, mô hình {results['model']})", ""]
    for scope in args.scopes.split(","):
        r = evaluate_scope(df, fmt, scope, args)
        results["scopes"][scope] = r
        md += [f"## Phạm vi `{scope}`", "", f"Khúc: {r['chunks']}", f"Số mẫu: {r['n']}", ""]
        if scope != "same-user":
            md += ["> Phạm vi này còn chứa đường tắt theo LOẠI entity (kẻ tấn công so với service/"
                   "user khác). Chỉ dùng làm kết quả khi `same-user` cho kết luận tương tự.", ""]
        if "metrics" in r:
            md += ["| Cấu hình | PR-AUC | Recall@FPR (oracle) | Recall@ngưỡng val | FPR@ngưỡng val | Recall theo lượt |",
                   "|---|---|---|---|---|---|"]
            for k, v in r["metrics"].items():
                md.append(f"| {k} | {v['pr_auc']} | {v['recall_at_fpr_oracle']} | {v.get('recall_at_val_thr', '')} "
                          f"| {v.get('fpr_at_val_thr', '')} | {v.get('run_recall_at_val_thr', '')} |")
            md += ["", f"Đặc trưng quan trọng (A+B): {r['top_features_AB']}", ""]
        md += verdict(r, args.fpr) + [""]
    json.dump(results, open(os.path.join(args.out, "eval_result.json"), "w"), indent=2, ensure_ascii=False, default=str)
    open(os.path.join(args.out, "eval_report.md"), "w").write("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()
