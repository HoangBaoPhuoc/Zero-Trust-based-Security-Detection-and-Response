# services/bola-detector/features/windowing.py
"""Cửa sổ trượt 5 phút, bước trượt 1 phút — đúng đơn vị dự đoán trong đề cương:
(thực thể × cửa sổ thời gian)."""
import pandas as pd

WINDOW = pd.Timedelta(minutes=5)
STEP = pd.Timedelta(minutes=1)


def make_windows(df: pd.DataFrame) -> pd.DataFrame:
    """Trả về DataFrame các window: mỗi dòng là 1 (entity_id, window_start).
    events_in_window là list index để feature_groups.py dùng lại, tránh phải
    lọc lại toàn bộ log mỗi lần tính 1 đặc trưng."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    windows = []
    for entity_id, g in df.groupby("entity_id"):
        g = g.sort_values("timestamp")
        t_min, t_max = g["timestamp"].min(), g["timestamp"].max()
        w_start = t_min.floor(STEP)
        while w_start <= t_max:
            w_end = w_start + WINDOW
            mask = (g["timestamp"] >= w_start) & (g["timestamp"] < w_end)
            idx = g.index[mask]
            if len(idx) > 0:
                # loại cửa sổ vắt qua ranh giới session — quy tắc gán nhãn đã khoá
                sessions_in_window = g.loc[idx, "session_id"].unique()
                spans_boundary = len(sessions_in_window) > 1 and _crosses_boundary(g, idx)
                windows.append(dict(entity_id=entity_id, entity_type=g["entity_type"].iloc[0],
                                     window_start=w_start, window_end=w_end,
                                     event_idx=list(idx), dropped_session_boundary=spans_boundary))
            w_start += STEP
    return pd.DataFrame(windows)


def _crosses_boundary(g: pd.DataFrame, idx) -> bool:
    """True nếu cửa sổ chứa events từ >1 session VÀ khoảng cách thời gian giữa
    2 session đó lớn hơn nửa độ dài cửa sổ (tức thực sự là 2 phiên tách biệt,
    không phải trùng khớp session_id bị cấp lại nhanh)."""
    sub = g.loc[idx].sort_values("timestamp")
    if sub["session_id"].nunique() <= 1:
        return False
    boundaries = sub["session_id"].ne(sub["session_id"].shift()).cumsum()
    gap = sub.groupby(boundaries)["timestamp"].agg(["min", "max"])
    return len(gap) > 1
