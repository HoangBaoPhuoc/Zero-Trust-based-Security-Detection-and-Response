# services/bola-detector/build_dataset.py
"""GĐ3 — nối features/ (log thô -> bảng feature) với labeling/ (gắn nhãn)
thành 1 pipeline chạy trên dữ liệu THẬT, xuất ra đúng file mà
training/train_xgboost.py mong đợi: data/processed/features_labeled.parquet.

Trước script này, build_feature_table() (features/build_features.py) và
label_windows() (labeling/label_windows.py) là 2 khối tách rời, chưa có gì
gọi cả 2 theo đúng thứ tự rồi ghi ra data/processed/ — dev/dryrun_gd4.py có
làm việc này nhưng chỉ để kiểm tra code trên dữ liệu giả lập, không nhận
đường dẫn log thật/nhiều file.

Dùng khi đã có log thật (Envoy access log + OPA decision log, đúng schema
ZTLogEvent trong dev/log_schema.py) và attack_runs_meta.jsonl thật (ghi bởi
các script trong attacks/):

    python build_dataset.py \
        --events "data/raw/events_*.jsonl" \
        --attack-runs attacks/attack_runs_meta.jsonl \
        --out data/processed/features_labeled.parquet
"""
import argparse
import glob
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent / "features"))
sys.path.insert(0, str(Path(__file__).parent / "labeling"))

from build_features import build_feature_table_from_events  # noqa: E402
from label_windows import label_windows  # noqa: E402


def load_events(patterns: list[str]) -> pd.DataFrame:
    """Gộp nhiều file log thô (mỗi file 1 ngày/1 lần capture) thành 1 bảng.
    Dùng glob vì dữ liệu GĐ3 sinh trong ~5 tuần, khó gộp thủ công thành 1 file."""
    paths = sorted({p for pat in patterns for p in glob.glob(pat)})
    if not paths:
        raise FileNotFoundError(f"Không tìm thấy file log nào khớp: {patterns}")
    rows = []
    for p in paths:
        with open(p) as f:
            rows += [json.loads(line) for line in f if line.strip()]
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def load_attack_runs(path: str) -> pd.DataFrame:
    with open(path) as f:
        runs = [json.loads(line) for line in f if line.strip()]
    df = pd.DataFrame(runs)
    # start_ts/end_ts trong attack_runs_meta.jsonl là time.time() (unix float giây)
    # — xem attacks/bola_vehicle_scan.py — khác định dạng ISO của dev/synth_attack_runs.jsonl.
    df["start_ts"] = pd.to_datetime(df["start_ts"], unit="s", utc=True)
    df["end_ts"] = pd.to_datetime(df["end_ts"], unit="s", utc=True)
    if "is_test_only_variant" not in df.columns:
        df["is_test_only_variant"] = False
    return df


def build_dataset(event_patterns: list[str], attack_runs_path: str, out_path: str) -> pd.DataFrame:
    events = load_events(event_patterns)
    table = build_feature_table_from_events(events)

    attack_runs = load_attack_runs(attack_runs_path)
    labeled = label_windows(table, attack_runs)

    # gắn is_test_only_variant từ attack_runs vào từng cửa sổ theo attack_run_id.
    # Cửa sổ benign (attack_run_id=None) luôn False — train_xgboost.py chỉ cần
    # loại các cửa sổ DƯƠNG thuộc biến thể test-only khỏi tập train.
    variant_map = attack_runs.set_index("attack_run_id")["is_test_only_variant"]
    labeled["is_test_only_variant"] = (
        labeled["attack_run_id"].map(variant_map).astype("boolean").fillna(False).astype(bool)
    )

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    labeled.to_parquet(out, index=False)

    n_pos_runs = labeled.loc[labeled["label"] == 1, "attack_run_id"].nunique()
    print(f"Tổng cửa sổ: {len(labeled)}, cửa sổ dương (label=1): {int(labeled['label'].sum())}")
    print(f"Số attack_run_id khác nhau tạo ra nhãn dương: {n_pos_runs}"
          f"  <-- đề cương yêu cầu >=100 lần chạy tấn công độc lập ở GĐ3")
    print(f"Đã ghi: {out}")
    return labeled


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", nargs="+", default=["data/raw/events_*.jsonl"],
                     help="1 hoặc nhiều path/glob tới file log thô ZTLogEvent (.jsonl)")
    ap.add_argument("--attack-runs", default="attacks/attack_runs_meta.jsonl")
    ap.add_argument("--out", default="data/processed/features_labeled.parquet")
    args = ap.parse_args()
    build_dataset(args.events, args.attack_runs, args.out)


if __name__ == "__main__":
    main()
