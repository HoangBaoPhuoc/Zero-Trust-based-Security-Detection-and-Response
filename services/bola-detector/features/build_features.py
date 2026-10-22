# services/bola-detector/features/build_features.py
"""Ghép entity + windowing + feature_groups thành 1 pipeline chạy từ log
(thật hoặc giả lập) ra bảng feature sẵn sàng train."""
import json
import pandas as pd

from entities import add_entity_columns
from windowing import make_windows
from feature_groups import group_a_features, group_b_features


def load_events(jsonl_path: str) -> pd.DataFrame:
    rows = [json.loads(line) for line in open(jsonl_path)]
    return pd.DataFrame(rows)


def build_known_pairs(df: pd.DataFrame, before_ts) -> set[tuple[str, str]]:
    """Baseline 'cặp gọi đã từng thấy' — tính trên dữ liệu TRƯỚC mốc before_ts
    (giai đoạn nền), không được rò rỉ thông tin từ chính cửa sổ đang chấm điểm."""
    hist = df[pd.to_datetime(df["timestamp"]) < before_ts]
    return set(zip(hist["caller_identity"], hist["callee_identity"]))


def build_feature_table(jsonl_path: str) -> pd.DataFrame:
    df = load_events(jsonl_path)
    return build_feature_table_from_events(df)


def build_feature_table_from_events(df: pd.DataFrame) -> pd.DataFrame:
    """Như build_feature_table() nhưng nhận thẳng DataFrame events đã load sẵn
    (vd. ghép từ nhiều file log thô) thay vì 1 đường dẫn jsonl duy nhất —
    dùng bởi build_dataset.py ở GĐ3 khi có nhiều file log thật."""
    df = add_entity_columns(df)
    windows = make_windows(df)
    windows = windows[~windows["dropped_session_boundary"]]  # áp quy tắc gán nhãn

    rows = []
    for _, w in windows.iterrows():
        events = df.loc[w["event_idx"]]
        known_pairs = build_known_pairs(df, w["window_start"])
        feat = {"entity_id": w["entity_id"], "entity_type": w["entity_type"],
                "window_start": w["window_start"], "window_end": w["window_end"]}
        feat.update(group_a_features(events))
        feat.update(group_b_features(events, known_pairs))
        rows.append(feat)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    table = build_feature_table("dev/synth_events.jsonl")
    table.to_parquet("dev/synth_features.parquet", index=False)
    print(table.shape)
    print(table.head())
