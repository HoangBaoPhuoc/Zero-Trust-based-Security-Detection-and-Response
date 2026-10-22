# services/bola-detector/labeling/attack_runs.py
"""Ghi lại metadata mọi lần chạy tấn công (kể cả benign 'hard negative' runs)
vào 1 file tập trung — nguồn sự thật duy nhất để gán nhãn ở build_features."""
import json
import time


def log_run(meta_path, attack_run_id, attack_class, start_ts, end_ts,
            is_test_only_variant=False, variant=None):
    """Field/tên tham số khớp đúng với những gì các script trong attacks/ tự
    ghi trực tiếp (is_test_only_variant, không phải is_test_only) — trước đây
    2 bên lệch tên field dù cùng ghi vào attack_runs_meta.jsonl."""
    record = dict(
        attack_run_id=attack_run_id,
        attack_class=attack_class,
        start_ts=start_ts,
        end_ts=end_ts,
        is_test_only_variant=is_test_only_variant,
    )
    if variant is not None:
        record["variant"] = variant
    with open(meta_path, "a") as f:
        f.write(json.dumps(record) + "\n")
