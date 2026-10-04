#!/usr/bin/env bash
# A5.2 (KEHOACH-THAYDOI-HETHONG.md) — wrapper ghi nhãn "lần chạy" cho mỗi kịch
# bản tấn công, dùng ở Giai đoạn B khi mở rộng crapi_*.sh thành ≥100 lần chạy
# độc lập có biến thể tham số.
#
# KHÔNG tiêm header đánh dấu (vd X-Campaign-Id) vào lưu lượng tấn công — một
# header như vậy sẽ là đặc trưng rò rỉ hoàn hảo: mô hình học đúng cái header
# đó thay vì học hành vi thật (shortcut learning, Arp và cộng sự [17], đề
# cương đã cam kết kiểm tra bằng shortcut learning test). Gán nhãn hoàn toàn
# OFFLINE: script này chỉ ghi lại (run_id, scenario, khoảng thời gian,
# target_entity) ra NGOÀI luồng traffic; join với log thật (Loki) sau, theo
# cặp (target_entity, [t_start, t_end]) — không phải theo một token lộ trong
# chính request.
#
# Dùng:
#   bash tests/crapi_run_campaign.sh <script.sh> [args...]
#   SCENARIO=bola_vehicle_location TARGET_ENTITY=testuser01 \
#     bash tests/crapi_run_campaign.sh crapi_bola.sh
#
# Ghi 1 dòng JSON vào tests/runs.jsonl mỗi lần chạy — không commit (xem .gitignore).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNS_FILE="${RUNS_FILE:-$HERE/runs.jsonl}"

if [[ $# -lt 1 ]]; then
  echo "Dùng: $0 <script.sh> [args...]" >&2
  echo "  (script.sh nằm trong $HERE — vd crapi_bola.sh, crapi_bfla.sh...)" >&2
  exit 1
fi
SCRIPT="$1"
shift

[[ -f "$HERE/$SCRIPT" ]] || { echo "Không tìm thấy $HERE/$SCRIPT" >&2; exit 1; }

SCENARIO="${SCENARIO:-${SCRIPT%.sh}}"
SCENARIO="${SCENARIO#crapi_}"
TARGET_ENTITY="${TARGET_ENTITY:-testuser01}"
RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"

T_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
bash "$HERE/$SCRIPT" "$@"
EXIT_CODE=$?
T_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

RUN_ID="$RUN_ID" SCENARIO="$SCENARIO" T_START="$T_START" T_END="$T_END" \
  TARGET_ENTITY="$TARGET_ENTITY" EXIT_CODE="$EXIT_CODE" python3 -c '
import json, os
rec = {
    "run_id": os.environ["RUN_ID"],
    "scenario": os.environ["SCENARIO"],
    "t_start": os.environ["T_START"],
    "t_end": os.environ["T_END"],
    "target_entity": os.environ["TARGET_ENTITY"],
    "exit_code": int(os.environ["EXIT_CODE"]),
}
print(json.dumps(rec))
' >> "$RUNS_FILE"

echo "[crapi_run_campaign] run_id=$RUN_ID scenario=$SCENARIO target_entity=$TARGET_ENTITY exit=$EXIT_CODE -> $RUNS_FILE"
exit "$EXIT_CODE"
