# services/bola-detector/labeling/label_windows.py
import pandas as pd

# Đề cương KLTN: lớp tấn công ML nhắm tới CHỈ "BOLA + hành vi danh tính bị
# chiếm dụng" — BFLA/lateral movement bị OPA/policy tĩnh chặn, KHÔNG dùng ML
# cho 2 loại này. attack_runs_meta.jsonl vẫn có thể chứa attack_run BFLA (dùng
# làm negative cross-check chéo lớp, xem attacks/bfla_delete_video.py) nhưng
# TUYỆT ĐỐI không được gán label=1 cho cửa sổ chỉ giao với 1 attack_run BFLA,
# nếu không model sẽ bị dạy nhầm học cả pattern ngoài phạm vi ML của đề cương.
ML_IN_SCOPE_ATTACK_CLASSES = ("BOLA", "COMPROMISED_IDENTITY")


def label_windows(
    feature_table: pd.DataFrame,
    attack_runs: pd.DataFrame,
    ml_in_scope_classes: tuple[str, ...] = ML_IN_SCOPE_ATTACK_CLASSES,
) -> pd.DataFrame:
    """Cửa sổ dương <=> chứa ít nhất 1 event thuộc 1 attack_run đã đánh dấu VÀ
    có attack_class nằm trong phạm vi ML (mặc định BOLA + COMPROMISED_IDENTITY).
    So khớp thời gian bằng khoảng [window_start, window_end) giao với
    [run.start_ts, run.end_ts]. attack_class cũng được giữ lại trên từng dòng
    để sau này báo cáo detection rate tách riêng theo từng lớp tấn công
    (đề cương yêu cầu ablation/robustness không được gộp lẫn các lớp)."""
    feature_table = feature_table.copy()
    feature_table["label"] = 0
    feature_table["attack_run_id"] = None
    feature_table["attack_class"] = None
    for _, run in attack_runs.iterrows():
        if run["attack_class"] not in ml_in_scope_classes:
            continue  # vd. BFLA — ngoài phạm vi ML, không gán label=1
        mask = (feature_table["window_start"] < run["end_ts"]) & (
            feature_table["window_end"] > run["start_ts"]
        )
        feature_table.loc[mask, "label"] = 1
        feature_table.loc[mask, "attack_run_id"] = run["attack_run_id"]
        feature_table.loc[mask, "attack_class"] = run["attack_class"]
    return feature_table
