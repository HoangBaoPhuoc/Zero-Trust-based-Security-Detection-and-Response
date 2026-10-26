#!/usr/bin/env bash
# §B7 mục 5/6 — CHẠY TIẾP TỪ KHÚC 10 TỚI HẾT 150 GIỜ.
#
# Vòng ngoài giữ nguyên B5 §3 (một khúc = collect_chunked.py mở/đóng + export
# + kiểm không rỗng), cộng featurize (B7 mục 2, đã gắn vào
# tests/phaseb_chunk_postprocess.sh) và áp quy tắc dừng của B7 mục 6.
#
# KHÔNG chạy gate cộng dồn ở đây (B7 mục 3) — chỉ export → featurize → một
# dòng báo cáo mỗi khúc. Gate cộng dồn chạy MỘT LẦN DUY NHẤT khi đủ 150h,
# đọc từ bảng đặc trưng (`run --features`, vài giây).
#
# Dùng: nohup bash tests/phaseb_collect_loop.sh > <log> 2>&1 &
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
cd "$REPO_ROOT"

CHUNK_MINUTES="${CHUNK_MINUTES:-370}"             # 6,1667h — khớp khúc 1-9
TARGET_HOURS="${TARGET_HOURS:-150}"
RUNS_FILE="${RUNS_FILE:-tests/runs.jsonl}"
RESULTS_ROUND="${RESULTS_ROUND:-b4}"
GAP_STREAK_MAX=3
ABORT_STREAK_MAX=1   # §C2 mục 2.4: bff=0 → khúc vô dụng hoàn toàn (build_sid_map rỗng), dừng ngay
ABORTED_RATIO_MAX=0.20
# Giai đoạn C: collect_chunked.py đánh `low_quality` khi bff-audit câm (bff≈0,
# kiểu c0014/c0015 — WireGuard đứt) hoặc non-200 quá cao. Export của khúc như
# vậy KHÔNG rỗng (envoy vẫn có log) nên ABORT_STREAK_MAX ở trên không bắt được
# — phải đếm riêng, nếu không vòng thu sẽ thu mãi khúc hỏng mà không cộng giờ.
LOWQ_STREAK_MAX="${LOWQ_STREAK_MAX:-1}"

gap_streak=0
aborted_streak=0
lowq_streak=0
chunks_done=0

log() { echo "[collect-loop] $(date -u +%FT%TZ) $*"; }

valid_hours() {
  python3 tests/collect_chunked.py --report --ledger "$RUNS_FILE" 2>/dev/null \
    | grep "TỔNG GIỜ HỢP LỆ" | grep -oE '[0-9]+\.[0-9]+' | head -1
}

# §B7 mục 5 — xác nhận bốn variant mỏng đang đuổi, in cảnh báo nếu không
# (KHÔNG dừng pipeline vì chuyện này — chỉ báo, theo đúng yêu cầu "báo ngay").
check_thin_variants() {
  python3 - "$RUNS_FILE" <<'PY'
import json, collections
c = collections.Counter()
for l in open("tests/runs.jsonl"):
    l = l.strip()
    if not l: continue
    try: d = json.loads(l)
    except Exception: continue
    if d.get("class") != "attack" or d.get("status") == "aborted": continue
    vg = d.get("variant_group", "")
    c[vg] += 1
thin = ["train:exfil_burst_12", "holdout:exfil_slow_12", "train:exfil_burst_20",
        "holdout:exfil_slow_20", "holdout:denied_slowdrip", "train:denied_burst"]
print("[collect-loop] variant mỏng — lượt tới nay:", {k: c.get(k, 0) for k in thin})
if c.get("train:exfil_burst_12", 0) <= 3 and c.get("holdout:exfil_slow_12", 0) <= 3 and \
   c.get("train:exfil_burst_20", 0) <= 3 and c.get("holdout:exfil_slow_20", 0) <= 3:
    print("[collect-loop] ⚠ exfil_* vẫn ≤3 lượt — large_response có thể KHÔNG đánh giá được ở Giai đoạn C, báo ngay theo B7 mục 5/6.")
PY
}

# Tỉ lệ aborted trong campaign CỦA KHÚC VỪA ĐÓNG (theo khoảng [t_start,t_end]).
campaign_aborted_ratio() {
  local t_start="$1" t_end="$2"
  python3 - "$RUNS_FILE" "$t_start" "$t_end" <<'PY'
import json, sys
f, t0, t1 = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
tot = ab = 0
for l in open(f):
    l = l.strip()
    if not l: continue
    try: d = json.loads(l)
    except Exception: continue
    if d.get("class") != "attack" or "chunk_id" in d: continue
    ts = d.get("t_start", "")
    try:
        import datetime
        t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()
    except Exception:
        continue
    if not (t0 <= t <= t1): continue
    tot += 1
    if d.get("status") == "aborted": ab += 1
print(f"{ab}/{tot}" if tot else "0/0")
print(round(ab/tot, 3) if tot else 0.0)
PY
}

log "BẮT ĐẦU vòng thu — CHUNK_MINUTES=$CHUNK_MINUTES TARGET_HOURS=$TARGET_HOURS"

while true; do
  hrs="$(valid_hours)"
  log "giờ hợp lệ hiện tại: ${hrs:-?} / $TARGET_HOURS"
  if awk -v h="${hrs:-0}" -v t="$TARGET_HOURS" 'BEGIN{exit !(h>=t)}'; then
    log "ĐÃ ĐỦ $TARGET_HOURS GIỜ — dừng vòng thu, chạy gate cộng dồn MỘT LẦN từ bảng đặc trưng."
    break
  fi

  log "tiền kiểm (crapi_preflight + Loki + decision log đang chảy)..."
  if ! bash tests/phaseb_chunk_preflight.sh; then
    log "⚠ TIỀN KIỂM THẤT BẠI — dừng vòng thu, cần người can thiệp."
    exit 1
  fi

  log "mở khúc #$((chunks_done+1)) ($CHUNK_MINUTES phút)..."
  CHUNK_MINUTES="$CHUNK_MINUTES" N1_WORKERS="${N1_WORKERS:-8}" \
    CAMPAIGN_REPEAT="${CAMPAIGN_REPEAT:-2}" CAMPAIGN_GAP="${CAMPAIGN_GAP:-600}" \
    RESULTS_ROUND="$RESULTS_ROUND" \
    python3 tests/collect_chunked.py --chunk-minutes "$CHUNK_MINUTES" --chunks 1 \
      --ledger "$RUNS_FILE" \
      -- bash tests/phaseb_chunk_workload.sh
  chunks_done=$((chunks_done+1))

  # Đọc trạng thái khúc vừa đóng.
  read -r CID T0 T1 STATUS <<<"$(python3 - "$RUNS_FILE" <<'PY'
import json
by = {}
for l in open("tests/runs.jsonl"):
    l = l.strip()
    if not l: continue
    try: d = json.loads(l)
    except Exception: continue
    if "chunk_id" not in d or "event" not in d: continue
    c = by.setdefault(d["chunk_id"], {})
    c.update({k: v for k, v in d.items() if k != "event"})
c = max(by.values(), key=lambda c: c.get("t_start", 0))
print(c["chunk_id"], c.get("t_start", 0), c.get("t_end", 0), c.get("status", "unknown"))
PY
)"
  log "khúc đóng: $CID status=$STATUS [$T0,$T1]"

  if [[ "$STATUS" == "gap" ]]; then
    gap_streak=$((gap_streak+1))
    log "⚠ gap liên tiếp=$gap_streak/$GAP_STREAK_MAX"
    if [[ "$gap_streak" -ge "$GAP_STREAK_MAX" ]]; then
      log "BA KHÚC GAP LIÊN TIẾP — dừng, báo người dùng."; exit 1
    fi
    continue   # khúc gap: không export/featurize (không có dữ liệu hợp lệ)
  fi
  gap_streak=0

  if [[ "$STATUS" == "low_quality" ]]; then
    lowq_streak=$((lowq_streak+1))
    log "⚠ low_quality liên tiếp=$lowq_streak/$LOWQ_STREAK_MAX (xem cột reason/quality trong $RUNS_FILE)"
    if [[ "$lowq_streak" -ge "$LOWQ_STREAK_MAX" ]]; then
      log "KHÚC LOW_QUALITY — dừng, báo người dùng (kiểm WireGuard/bff-audit trước khi chạy tiếp)."; exit 1
    fi
    continue   # khúc low_quality: không export/featurize (dữ liệu không dùng được)
  fi
  lowq_streak=0

  log "hậu kỳ (export .gz → kiểm không rỗng → featurize 60/300/600)..."
  if ! bash tests/phaseb_chunk_postprocess.sh "$CID"; then
    aborted_streak=$((aborted_streak+1))
    log "⚠ export rỗng/hậu kỳ lỗi, liên tiếp=$aborted_streak/$ABORT_STREAK_MAX"
    if [[ "$aborted_streak" -ge "$ABORT_STREAK_MAX" ]]; then
      log "EXPORT RỖNG LIÊN TIẾP — dừng, báo người dùng."; exit 1
    fi
    continue
  fi
  aborted_streak=0

  ratio_line="$(campaign_aborted_ratio "$T0" "$T1")"
  ratio_frac="$(echo "$ratio_line" | sed -n '1p')"
  ratio_num="$(echo "$ratio_line" | sed -n '2p')"
  log "tỉ lệ aborted campaign khúc này: $ratio_frac ($ratio_num)"
  if awk -v r="${ratio_num:-0}" -v m="$ABORTED_RATIO_MAX" 'BEGIN{exit !(r>m)}'; then
    log "⚠ TỈ LỆ ABORTED VƯỢT ${ABORTED_RATIO_MAX} TRONG MỘT KHÚC — dừng, báo người dùng."; exit 1
  fi

  if [[ "$chunks_done" -ge 3 ]]; then
    check_thin_variants
  fi

  log "nghỉ 30s trước khúc kế..."
  sleep 30
done

log "HOÀN TẤT 150 GIỜ — chạy gate cộng dồn MỘT LẦN DUY NHẤT từ bảng đặc trưng (B7 mục 3)."
FEATURE_DIRS="$(python3 - "$RUNS_FILE" <<'PY'
import json
by = {}
for l in open("tests/runs.jsonl"):
    l = l.strip()
    if not l: continue
    try: d = json.loads(l)
    except Exception: continue
    if "chunk_id" not in d or "event" not in d: continue
    c = by.setdefault(d["chunk_id"], {})
    c.update({k: v for k, v in d.items() if k != "event"})
valid = [c["chunk_id"] for c in by.values() if c.get("status") == "valid"]
print(",".join(f"results/b4/chunks/{cid}" for cid in valid))
PY
)"
mkdir -p results/b4/cumulative_final
python3 tests/phaseb_gate.py run --features "$FEATURE_DIRS" --out results/b4/cumulative_final --window 60
log "GATE CỘNG DỒN XONG -> results/b4/cumulative_final/gate_result.json"
log "CHỜ XÁC NHẬN THỦ CÔNG trước khi coi Giai đoạn B là xong (B7 mục 6)."
