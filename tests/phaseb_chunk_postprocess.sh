#!/usr/bin/env bash
# Giai đoạn B §4 (B4) mục 0.1 + mục 2 — HẬU KỲ một khúc: export dữ liệu ra file
# NGAY (Loki chỉ giữ 720h — không đợi), khẳng định không luồng nào rỗng, và
# ghi số dòng mỗi luồng vào CHÍNH bản ghi khúc trong runs.jsonl.
#
# Chạy SAU KHI tests/collect_chunked.py đã đóng một khúc (status valid/gap/
# aborted đã ghi). Nếu export rỗng (0.1), khúc bị HẠ xuống aborted ngay tại
# đây — không tính vào tổng giờ hợp lệ — bằng cách append một bản ghi "end"
# BỔ SUNG cùng chunk_id (Ledger.chunks() gộp theo thứ tự, bản ghi sau thắng
# field nào nó có mặt — xem tests/collect_chunked.py Ledger.chunks()).
#
# Dùng:
#   bash tests/phaseb_chunk_postprocess.sh <chunk_id>
#   bash tests/phaseb_chunk_postprocess.sh --last          # khúc mới nhất trong runs.jsonl
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
cd "$REPO_ROOT"

ARG="${1:?dùng: $0 <chunk_id> | --last}"
RUNS_FILE="${RUNS_FILE:-tests/runs.jsonl}"
RESULTS_ROUND="${RESULTS_ROUND:-b4}"

read -r CHUNK_ID T_START T_END STATUS <<<"$(python3 - "$RUNS_FILE" "$ARG" <<'PY'
import json, sys
runs_file, arg = sys.argv[1], sys.argv[2]
by = {}
for line in open(runs_file):
    line = line.strip()
    if not line: continue
    try: d = json.loads(line)
    except Exception: continue
    if "chunk_id" not in d or "event" not in d: continue
    c = by.setdefault(d["chunk_id"], {"chunk_id": d["chunk_id"]})
    c.update({k: v for k, v in d.items() if k != "event"})
if not by:
    print("__NONE__ 0 0 none"); sys.exit()
if arg == "--last":
    c = max(by.values(), key=lambda c: c.get("t_start", 0))
else:
    c = by.get(arg)
    if not c:
        print("__NONE__ 0 0 none"); sys.exit()
print(c["chunk_id"], c.get("t_start", 0), c.get("t_end", 0), c.get("status", "unknown"))
PY
)"

if [[ "$CHUNK_ID" == "__NONE__" ]]; then
  echo "[postprocess] không tìm thấy khúc '$ARG' trong $RUNS_FILE" >&2
  exit 1
fi
echo "[postprocess] khúc=$CHUNK_ID t_start=$T_START t_end=$T_END status_hiện_tại=$STATUS"

OUTDIR="results/$RESULTS_ROUND/chunks/$CHUNK_ID"
mkdir -p "$OUTDIR"
EXPORT_OK=1
python3 tests/phaseb_gate.py export --loki "${LOKI_URL:-http://localhost:13100}" \
  --start "$T_START" --end "$T_END" --out "$OUTDIR" || EXPORT_OK=0

COUNTS_JSON="{}"
[[ -f "$OUTDIR/export_counts.json" ]] && COUNTS_JSON="$(python3 -c "import json;print(json.dumps(json.load(open('$OUTDIR/export_counts.json'))['counts']))")"

NOW="$(date +%s.%N)"
if [[ "$EXPORT_OK" -eq 1 ]]; then
  # §B7 mục 2/5: FEATURIZE NGAY sau export (còn trong vòng chạy khúc này) —
  # chi phí dàn đều theo khúc, KHÔNG dồn thành một lượt gate cộng dồn cuối
  # (mục 3: cấm chạy lại gate cộng dồn giữa đường). Lỗi featurize KHÔNG hạ
  # khúc xuống aborted (dữ liệu thô đã export an toàn; thiếu bảng đặc trưng
  # có thể sinh lại sau bằng `featurize` — không mất giờ hợp lệ vì lý do này).
  FEAT_T0="$(date +%s.%N)"
  FEAT_OK=1
  python3 tests/phaseb_gate.py featurize --logs "$OUTDIR" --runs "$RUNS_FILE" \
    --chunk-id "$CHUNK_ID" --widths 60,300,600 || FEAT_OK=0
  FEAT_ELAPSED="$(python3 -c "print(round($(date +%s.%N)-$FEAT_T0,1))")"
  if [[ "$FEAT_OK" -eq 1 ]]; then
    echo "[postprocess] featurize OK — ${FEAT_ELAPSED}s -> $OUTDIR/features_w{60,300,600}.csv.gz"
  else
    echo "[postprocess] ⚠ featurize LỖI (${FEAT_ELAPSED}s) — khúc vẫn tính giờ hợp lệ, bảng đặc trưng thiếu, cần sinh lại sau" >&2
  fi
  # chỉ thêm line_counts/featurize — KHÔNG đụng status/hours gốc (giữ nguyên
  # valid/gap/aborted của collect_chunked.py, vốn đo bằng cơ chế khác: độ
  # tươi + hậu kiểm bucket).
  python3 -c "
import json
rec = {'event':'export','chunk_id':'$CHUNK_ID','t_start':$T_START,'t_end':$T_END,
       'line_counts':$COUNTS_JSON,'export_ok':True,'exported_at':$NOW,
       'featurize_ok':$([[ $FEAT_OK -eq 1 ]] && echo True || echo False),
       'featurize_elapsed_sec':$FEAT_ELAPSED,
       'featurize_dir':'$OUTDIR'}
open('$RUNS_FILE','a').write(json.dumps(rec, ensure_ascii=False)+'\n')
"
  echo "[postprocess] OK — line_counts=$COUNTS_JSON ghi vào $RUNS_FILE (chunk_id=$CHUNK_ID)"
else
  # §B4 mục 0.1: export rỗng → khúc bị HẠ xuống aborted, KHÔNG tính giờ, dù
  # collect_chunked.py từng đánh 'valid' theo độ tươi/hậu kiểm riêng của nó —
  # đây là một nguyên nhân KHÁC (file export rỗng dù Loki có dữ liệu, như B3).
  python3 -c "
import json
rec = {'event':'end','chunk_id':'$CHUNK_ID','t_start':$T_START,'t_end':$T_END,
       'status':'aborted','hours':0.0,
       'reason':'export rỗng (§B4 mục 0.1) — xem $OUTDIR/export_counts.json',
       'line_counts':$COUNTS_JSON,'export_ok':False,'exported_at':$NOW}
open('$RUNS_FILE','a').write(json.dumps(rec, ensure_ascii=False)+'\n')
"
  echo "[postprocess] RỖNG — khúc $CHUNK_ID hạ xuống aborted, không tính giờ. line_counts=$COUNTS_JSON" >&2
  exit 1
fi
