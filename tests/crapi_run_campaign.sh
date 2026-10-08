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
# Giai đoạn B §0.2/§4: nhóm biến thể (train|holdout|<id>) do orchestrator đặt
# khi đọc policy/variant-split.yaml. Mặc định "unspecified" khi chạy tay 1 lượt.
VARIANT_GROUP="${VARIANT_GROUP:-unspecified}"
CLASS="${CLASS:-attack}"
RUN_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"

T_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Bắt stderr để trích dòng FAIL (lý do không thoả tiền điều kiện — H18). tee để
# người chạy vẫn thấy log trực tiếp.
ERRLOG="$(mktemp)"
# §B1b: kênh meta để scenario ghi KEY=VALUE (vd victims_used, victim_pool_size)
# → gộp vào runs.jsonl. Chỉ nhận các khoá cho phép (an toàn).
export CRAPI_RUN_META="$(mktemp)"
bash "$HERE/$SCRIPT" "$@" 2> >(tee "$ERRLOG" >&2)
EXIT_CODE=$?
META_JSON="$(python3 -c '
import json, os, sys
allow = {"victims_used", "victim_pool_size", "source_used"}
out = {}
p = os.environ.get("CRAPI_RUN_META", "")
if p and os.path.exists(p):
    for line in open(p):
        if "=" not in line: continue
        k, v = line.rstrip("\n").split("=", 1)
        if k not in allow: continue
        out[k] = v.split(",") if k == "victims_used" else (int(v) if v.isdigit() else v)
print(json.dumps(out, ensure_ascii=False))
')"
rm -f "$CRAPI_RUN_META"; unset CRAPI_RUN_META
# §4 (H18): T1 làm tròn LÊN +1s — `date` làm tròn xuống, dòng audit của request
# cuối có phần lẻ giây SAU t_end và bị loại khỏi cửa sổ gán nhãn offline. Lỗi
# này từng sót ở 3 script scenario; đặt ở ĐÂY (nguồn sự thật của cửa sổ nhãn)
# để đúng cho MỌI scenario, không phải sửa từng script.
T_END="$(date -u -d '+1 second' +%Y-%m-%dT%H:%M:%SZ)"

# §4 — KIỂM TIỀN ĐIỀU KIỆN: mỗi scenario tự assert cuộc tấn công THỰC SỰ diễn ra
# (bola: 200 + email chủ xe ≠ attacker; lateral/access: deny decision log thật;
# brute: LOGIN_ERROR thật; bfla: rbac_denied thật; privesc: event + Firing;
# large: bytes_sent>1MiB) và fail (exit≠0) nếu không. Lượt không thoả → status
# "aborted", KHÔNG tính vào 100 lượt, ghi lý do. Chỉ exit==0 mới là "attack".
if [[ "$EXIT_CODE" -eq 0 ]]; then
  STATUS="attack"; REASON=""
else
  STATUS="aborted"
  REASON="$(grep -E 'FAIL:' "$ERRLOG" | tail -1 | sed -E 's/.*FAIL:[[:space:]]*//')"
  [[ -n "$REASON" ]] || REASON="exit=$EXIT_CODE (không bắt được dòng FAIL)"
fi
rm -f "$ERRLOG"

RUN_ID="$RUN_ID" SCENARIO="$SCENARIO" T_START="$T_START" T_END="$T_END" \
  TARGET_ENTITY="$TARGET_ENTITY" EXIT_CODE="$EXIT_CODE" \
  VARIANT_GROUP="$VARIANT_GROUP" CLASS="$CLASS" STATUS="$STATUS" REASON="$REASON" \
  META_JSON="$META_JSON" python3 -c '
import json, os
rec = {
    "run_id": os.environ["RUN_ID"],
    "scenario": os.environ["SCENARIO"],
    "variant_group": os.environ["VARIANT_GROUP"],
    "class": os.environ["CLASS"],
    "target_entity": os.environ["TARGET_ENTITY"],
    "t_start": os.environ["T_START"],
    "t_end": os.environ["T_END"],
    "status": os.environ["STATUS"],
    "exit_code": int(os.environ["EXIT_CODE"]),
}
reason = os.environ.get("REASON", "")
if reason:
    rec["reason"] = reason
try:
    meta = json.loads(os.environ.get("META_JSON", "{}"))
    rec.update(meta)   # §B1b: victims_used, victim_pool_size, ...
except Exception:
    pass
print(json.dumps(rec, ensure_ascii=False))
' >> "$RUNS_FILE"

echo "[crapi_run_campaign] run_id=$RUN_ID scenario=$SCENARIO variant=$VARIANT_GROUP status=$STATUS exit=$EXIT_CODE -> $RUNS_FILE"
exit "$EXIT_CODE"
