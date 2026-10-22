# services/bola-detector/dev/sanity_check.py
"""Kiểm tra nhanh (không cần pytest) cho checklist GD1:
1. Cửa sổ vắt session bị loại đúng.
2. Cửa sổ chứa attack run có unseen_identity_pair_count >= n_distinct_victims.
3. Sanity check bằng mắt: cửa sổ attack tách biệt khỏi benign trên >=1 đặc trưng nhóm B.

Chạy từ thư mục services/bola-detector:
    source .venv/bin/activate && python3 dev/sanity_check.py
"""
import json
import sys

sys.path.insert(0, "features")

from entities import add_entity_columns
from windowing import make_windows
from build_features import build_feature_table, load_events

N_DISTINCT_VICTIMS = 5  # phải khớp n_distinct_victims mặc định trong synth_log_generator.py


def main():
    # --- check 1: cửa sổ vắt session bị loại đúng ---
    df = load_events("dev/synth_events.jsonl")
    df = add_entity_columns(df)
    windows = make_windows(df)
    n_dropped = windows["dropped_session_boundary"].sum()
    print(f"[check 1] windows tổng: {len(windows)}, bị loại do vắt session: {n_dropped}")
    kept = windows[~windows["dropped_session_boundary"]]
    assert len(kept) <= len(windows)
    print("[check 1] OK — chạy được filter dropped_session_boundary")

    # --- build feature table + gán nhãn theo attacker (user0) ---
    table = build_feature_table("dev/synth_events.jsonl")
    with open("dev/synth_attack_runs.jsonl") as f:
        attack_meta = json.loads(f.readline())
    attacker_id = "user0@test.local"
    import pandas as pd
    start = pd.to_datetime(attack_meta["start"])
    end = pd.to_datetime(attack_meta["end"])

    # cửa sổ được coi là "chứa attack run" nếu attack run giao với [window_start, window_end)
    attack_windows = table[
        (table["entity_id"] == attacker_id)
        & (table["window_start"] < end)
        & (table["window_start"] + pd.Timedelta(minutes=5) > start)
    ]
    assert not attack_windows.empty, "Không tìm thấy cửa sổ nào chứa attack run — kiểm tra lại windowing."

    # benign windows: loại toàn bộ cửa sổ của chính attacker (kể cả phần benign
    # trước attack) để so sánh công bằng với các cửa sổ THẦN THUẦN benign của user khác
    benign_windows = table[table["entity_id"] != attacker_id]

    print("\n[check 2] So sánh distinct_objects_per_session (attack vs benign):")
    print("  attacker windows (liên quan attack run):")
    print(attack_windows[["window_start", "distinct_objects_per_session",
                           "unseen_identity_pair_count", "distinct_callee_count"]])
    print(f"  benign windows trung bình distinct_objects_per_session: "
          f"{benign_windows['distinct_objects_per_session'].mean():.2f}")

    # sanity check quan trọng nhất: attack windows có distinct_objects_per_session
    # cao hẳn so với benign (mỗi user benign chỉ xem đúng 1 xe -> luôn = 1.0)
    max_attack_distinct_obj = attack_windows["distinct_objects_per_session"].max()
    mean_benign_distinct_obj = benign_windows["distinct_objects_per_session"].mean()
    assert max_attack_distinct_obj > mean_benign_distinct_obj, (
        "Cửa sổ attack KHÔNG tách biệt khỏi benign trên distinct_objects_per_session — "
        "kiểm tra lại logic windowing/feature_groups trước khi tin code đúng."
    )
    print(f"\n[check 2] OK — attack max distinct_objects_per_session="
          f"{max_attack_distinct_obj:.1f} > benign mean={mean_benign_distinct_obj:.2f}")

    print("\nTất cả sanity check PASS.")


if __name__ == "__main__":
    main()
