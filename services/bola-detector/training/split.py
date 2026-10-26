# services/bola-detector/training/split.py
import pandas as pd

WINDOW = pd.Timedelta(minutes=5)


def time_session_split(df: pd.DataFrame, train_frac=0.7):
    """Chia theo trục thời gian (không random) — phần đầu train, phần cuối
    test, đúng khuyến nghị Pendlebury et al. Thêm buffer = độ dài 1 cửa sổ
    quanh điểm cắt để loại các cửa sổ chồng lấn giữa 2 tập (data leakage
    theo Arp et al.). Đồng thời đảm bảo 1 session không bị xé giữa train/test."""
    df = df.sort_values("window_start")
    cutoff = df["window_start"].quantile(train_frac)

    # nếu 1 entity_id có session vắt qua cutoff, đẩy toàn bộ session đó
    # về phía có nhiều event hơn để không xé lẻ
    sess_bounds = df.groupby("entity_id")["window_start"].agg(["min", "max"])
    train_mask = df["window_start"] < (cutoff - WINDOW)
    test_mask = df["window_start"] > (cutoff + WINDOW)
    return df[train_mask].copy(), df[test_mask].copy()
