#!/usr/bin/env bash
# Chạy trên MÁY THU (nơi có log thô results/b4/chunks/*): kiểm định dạng log,
# sinh bảng đặc trưng v2 cho các khúc hợp lệ, rồi đánh giá theo đề cương.
#
#   bash ml/run_collector.sh                 # mặc định: c0001..c0009
#   CHUNKS="c0001 c0002" bash ml/run_collector.sh
#   SKIP_BUILD=1 bash ml/run_collector.sh    # chỉ đánh giá lại bảng đã sinh
set -euo pipefail
cd "$(dirname "$0")/.."

CHUNK_ROOT="${CHUNK_ROOT:-results/b4/chunks}"
RUNS="${RUNS:-tests/runs.jsonl}"
OUT="${OUT:-results/c4}"
CHUNKS="${CHUNKS:-c0001 c0002 c0003 c0004 c0005 c0006 c0007 c0008 c0009}"
VENV="${VENV:-ml/.venv}"   # .venv/ đã có trong .gitignore

if [[ ! -x "$VENV/bin/python" ]]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r ml/requirements.txt
fi
PY="$VENV/bin/python"

dirs=()
for c in $CHUNKS; do
  d=$(ls -d "$CHUNK_ROOT/$c"-* 2>/dev/null | head -1 || true)
  [[ -n "$d" ]] || { echo "!! không thấy thư mục khúc $c trong $CHUNK_ROOT" >&2; exit 1; }
  dirs+=("$d")
done
mkdir -p "$OUT"

echo "== 1. selftest + kiểm định dạng log thật (khúc đầu)"
"$PY" ml/features_v2.py selftest
"$PY" ml/features_v2.py inspect --chunk "${dirs[0]}" | tee "$OUT/inspect.txt"

if [[ -z "${SKIP_BUILD:-}" ]]; then
  echo "== 2. sinh bảng đặc trưng v2 (cửa sổ 300 s trượt 60 s) — chạy lâu, ghi log ra $OUT/build.log"
  "$PY" ml/features_v2.py build --chunks "$(IFS=,; echo "${dirs[*]}")" --runs "$RUNS" \
        --out "$OUT/features_v2" 2>&1 | tee "$OUT/build.log"
fi

echo "== 3. đánh giá theo đề cương (all / user / same-user)"
"$PY" ml/evaluate.py --features "$OUT/features_v2/*.csv.gz" --out "$OUT/eval" | tee "$OUT/eval.log"

echo "== Xong. Gửi lại: $OUT/inspect.txt, $OUT/features_v2/features_v2_meta.json, $OUT/eval/eval_report.md, $OUT/eval/eval_result.json"
