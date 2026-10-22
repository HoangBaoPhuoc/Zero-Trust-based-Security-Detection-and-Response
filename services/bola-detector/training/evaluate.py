# services/bola-detector/training/evaluate.py
import numpy as np
from sklearn.metrics import precision_recall_curve, average_precision_score


def recall_at_fpr(y_true, scores, target_fpr=0.01):
    from sklearn.metrics import roc_curve
    fpr, tpr, thr = roc_curve(y_true, scores)
    idx = np.searchsorted(fpr, target_fpr)
    return tpr[min(idx, len(tpr) - 1)], thr[min(idx, len(thr) - 1)]


def bootstrap_ci_pr_auc_diff(y_true, scores_a, scores_b, attack_run_ids, n_boot=2000):
    """CI 95% cho chênh lệch PR-AUC giữa 2 cấu hình, resample theo attack_run_id
    (không phải theo dòng) — đúng yêu cầu 'CI ở mức lần chạy tấn công' của đề cương,
    vì các dòng cùng 1 attack run không độc lập với nhau."""
    runs = np.unique(attack_run_ids[attack_run_ids.notna()])
    diffs = []
    rng = np.random.default_rng(42)
    for _ in range(n_boot):
        sample_runs = rng.choice(runs, size=len(runs), replace=True)
        mask = attack_run_ids.isin(sample_runs) | (attack_run_ids.isna())
        if y_true[mask].sum() == 0:
            continue
        d = average_precision_score(y_true[mask], scores_b[mask]) - \
            average_precision_score(y_true[mask], scores_a[mask])
        diffs.append(d)
    lo, hi = np.percentile(diffs, [2.5, 97.5])
    return lo, hi   # đạt tiêu chí đề cương nếu khoảng này KHÔNG chứa 0


def negative_control(y_true, feature_df, feature_cols, train_fn, rng_seed=42):
    """Đối chứng âm: xáo trộn nhãn rồi train lại — PR-AUC phải xấp xỉ base rate,
    nếu vẫn cao là dấu hiệu leakage trong feature/pipeline."""
    import numpy as np
    rng = np.random.default_rng(rng_seed)
    shuffled = y_true.sample(frac=1, random_state=rng_seed).reset_index(drop=True)
    model = train_fn(feature_df.assign(label=shuffled), feature_cols)
    scores = model.predict_proba(feature_df[feature_cols])[:, 1]
    return average_precision_score(shuffled, scores)
