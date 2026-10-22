# services/bola-detector/training/train_xgboost.py
import numpy as np
import xgboost as xgb
from sklearn.metrics import average_precision_score

FEATURES_A = ["req_rate_per_min", "pct_4xx", "pct_5xx", "avg_path_len", "path_entropy"]
FEATURES_B = ["distinct_callee_count", "unseen_identity_pair_count",
              "pdp_deny_rate", "distinct_objects_per_session"]


def baseline_threshold_score(df):
    """Cấu hình (i): baseline luật ngưỡng trên pdp_deny_rate — bắt buộc phải
    có để chứng minh model vượt trội, không phải chỉ nhìn có vẻ hay."""
    return df["pdp_deny_rate"].values


def train_config(train_df, feature_cols):
    pos = (train_df["label"] == 1).sum()
    neg = (train_df["label"] == 0).sum()
    scale_pos_weight = neg / max(pos, 1)   # xử lý mất cân bằng ở mức thuật toán

    model = xgb.XGBClassifier(
        n_estimators=300, max_depth=5, learning_rate=0.05,
        scale_pos_weight=scale_pos_weight, eval_metric="aucpr",
        n_jobs=4,
    )
    model.fit(train_df[feature_cols], train_df["label"])
    return model


if __name__ == "__main__":
    import pandas as pd
    from split import time_session_split

    df = pd.read_parquet("../data/processed/features_labeled.parquet")
    df = df[df["attack_run_id"].isna() | (~df["is_test_only_variant"])]  # loại biến thể test-only khỏi train
    train_df, test_df = time_session_split(df)

    model_a = train_config(train_df, FEATURES_A)
    model_ab = train_config(train_df, FEATURES_A + FEATURES_B)

    baseline_scores = baseline_threshold_score(test_df)
    scores_a = model_a.predict_proba(test_df[FEATURES_A])[:, 1]
    scores_ab = model_ab.predict_proba(test_df[FEATURES_A + FEATURES_B])[:, 1]

    for name, scores in [("baseline", baseline_scores), ("A", scores_a), ("A+B", scores_ab)]:
        pr_auc = average_precision_score(test_df["label"], scores)
        print(f"{name}: PR-AUC = {pr_auc:.4f}")

    model_ab.save_model("../model/bola_xgboost.json")
