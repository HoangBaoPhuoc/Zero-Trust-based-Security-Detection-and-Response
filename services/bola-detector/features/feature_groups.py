# services/bola-detector/features/feature_groups.py
"""Nhóm A (HTTP thường) và Nhóm B (đặc thù Zero Trust) — đây là ablation
3 cấu hình sẽ dùng ở Bước 4: baseline / A / A+B."""
import math
import pandas as pd

# baseline pairs "đã thấy" — trong thực tế build từ giai đoạn nền dài trước
# khi chạy tấn công; ở đây nhận vào như tham số để hàm test được độc lập.
def group_a_features(events: pd.DataFrame) -> dict:
    n = len(events)
    status = events["response_code"]
    path_lens = events["path"].str.len()
    return {
        "req_rate_per_min": n / 5.0,
        "pct_4xx": (status.between(400, 499)).mean() if n else 0.0,
        "pct_5xx": (status >= 500).mean() if n else 0.0,
        "avg_path_len": path_lens.mean() if n else 0.0,
        "path_entropy": _entropy(events["path"]) if n else 0.0,
    }


def group_b_features(events: pd.DataFrame, known_pairs: set[tuple[str, str]]) -> dict:
    n = len(events)
    distinct_callees = events["callee_identity"].nunique()
    pairs = set(zip(events["caller_identity"], events["callee_identity"]))
    unseen_pairs = len(pairs - known_pairs)
    deny_rate = (events["opa_decision"] == "deny").mean() if n else 0.0
    distinct_objects_per_session = (
        events.groupby("session_id")["object_id"].nunique().mean()
        if n and "session_id" in events else 0.0
    )
    return {
        "distinct_callee_count": distinct_callees,
        "unseen_identity_pair_count": unseen_pairs,
        "pdp_deny_rate": deny_rate,
        "distinct_objects_per_session": distinct_objects_per_session or 0.0,
    }


def _entropy(series: pd.Series) -> float:
    probs = series.value_counts(normalize=True)
    return float(-(probs * probs.apply(math.log2)).sum())
