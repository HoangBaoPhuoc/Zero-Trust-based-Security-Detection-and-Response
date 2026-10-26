# services/bola-detector/dev/dryrun_gd4.py
"""DRY RUN pipeline GĐ4 (split -> train -> evaluate -> shap) trên dữ liệu
GIẢ LẬP của Bước 1.5 — MỤC ĐÍCH DUY NHẤT là kiểm tra code GĐ4 chạy hết không
lỗi, KHÔNG PHẢI để lấy số liệu đưa vào báo cáo (chỉ có 1 attack run giả lập,
không đạt điều kiện thống kê tối thiểu mà đề cương yêu cầu ở GĐ3: >=100 lần
chạy tấn công độc lập, >=150 giờ traffic nền). Khi có dữ liệu thật từ GĐ3,
chạy lại pipeline này với data/processed/features_labeled.parquet thật.
"""
import sys
import json
import pandas as pd

sys.path.insert(0, "features")
sys.path.insert(0, "labeling")
sys.path.insert(0, "training")

from build_features import build_feature_table
from label_windows import label_windows
from split import time_session_split
from train_xgboost import FEATURES_A, FEATURES_B, baseline_threshold_score, train_config
from sklearn.metrics import average_precision_score
from evaluate import recall_at_fpr, negative_control


def main():
    table = build_feature_table("dev/synth_events.jsonl")

    with open("dev/synth_attack_runs.jsonl") as f:
        runs = [json.loads(line) for line in f]
    attack_runs = pd.DataFrame(runs).rename(columns={"start": "start_ts", "end": "end_ts"})
    attack_runs["start_ts"] = pd.to_datetime(attack_runs["start_ts"])
    attack_runs["end_ts"] = pd.to_datetime(attack_runs["end_ts"])

    labeled = label_windows(table, attack_runs)
    labeled["is_test_only_variant"] = False  # dataset giả lập chỉ có 1 attack run cho train

    print(f"Tổng cửa sổ: {len(labeled)}, cửa sổ dương (label=1): {labeled['label'].sum()}")
    print(f"Số attack_run_id khác nhau: {labeled['attack_run_id'].nunique()}  <-- đề cương yêu cầu >=100 ở GĐ3")

    train_df, test_df = time_session_split(labeled)
    print(f"\ntrain: {len(train_df)} cửa sổ ({train_df['label'].sum()} dương)")
    print(f"test:  {len(test_df)} cửa sổ ({test_df['label'].sum()} dương)")

    if train_df["label"].sum() == 0 or test_df["label"].sum() == 0:
        print(
            "\n*** KẾT LUẬN QUAN TRỌNG ***\n"
            "Với chỉ 1 attack run, toàn bộ cửa sổ dương rơi hết vào 1 phía của "
            "split theo thời gian -> phía còn lại có 0 mẫu dương. Không thể "
            "train (nếu 0 mẫu dương ở train) hoặc không thể đánh giá PR-AUC có "
            "ý nghĩa (nếu 0 mẫu dương ở test). Đây CHÍNH XÁC là lý do đề cương "
            "yêu cầu >=100 lần chạy tấn công độc lập trải đều theo thời gian ở "
            "GĐ3 — để cả train và test đều có đủ mẫu dương phân bố qua nhiều "
            "mốc thời gian khác nhau."
        )
        return

    model_a = train_config(train_df, FEATURES_A)
    model_ab = train_config(train_df, FEATURES_A + FEATURES_B)

    baseline_scores = baseline_threshold_score(test_df)
    scores_a = model_a.predict_proba(test_df[FEATURES_A])[:, 1]
    scores_ab = model_ab.predict_proba(test_df[FEATURES_A + FEATURES_B])[:, 1]

    print("\n--- PR-AUC (chỉ mang tính kiểm tra code, KHÔNG dùng cho báo cáo) ---")
    for name, scores in [("baseline", baseline_scores), ("A", scores_a), ("A+B", scores_ab)]:
        pr_auc = average_precision_score(test_df["label"], scores)
        print(f"{name}: PR-AUC = {pr_auc:.4f}")

    recall, thr = recall_at_fpr(test_df["label"], scores_ab, target_fpr=0.01)
    print(f"\nrecall @ FPR=1% (A+B) = {recall:.4f} (threshold={thr:.4f})")

    neg_ctrl = negative_control(test_df["label"], test_df, FEATURES_A + FEATURES_B, train_config)
    print(f"Negative control PR-AUC (nhãn xáo trộn, kỳ vọng ~ base rate): {neg_ctrl:.4f}")


if __name__ == "__main__":
    main()
