#!/usr/bin/env bash
# Giai đoạn B §4 (B4) — WORKLOAD của MỘT khúc, chạy dưới tests/collect_chunked.py.
#
# collect_chunked.py khởi tiến trình này với start_new_session=True (process
# group riêng) rồi SIGTERM cả group đúng lúc hết CHUNK_MINUTES — script này
# KHÔNG tự giới hạn thời gian, nó chỉ khởi N1+N2+chiến dịch A (cấu hình ĐỢT
# DÀI: gap 600, repeat≥2, KHÔNG --duration-min — xem §B4 mục 0.3) rồi `wait`
# tới khi bị giết. N1/N2 nhận DURATION hơi dài hơn khúc (đệm) để không tự tắt
# trước khi collect_chunked kết thúc khúc.
#
# Biến môi trường:
#   CHUNK_MINUTES   bắt buộc — PHẢI khớp --chunk-minutes truyền cho collect_chunked.py
#   N1_WORKERS      mặc định 8
#   CAMPAIGN_REPEAT mặc định 2 (đợt dài — §B4 mục 0.3)
#   CAMPAIGN_GAP    mặc định 600 (đợt dài — §B4 mục 0.3, KHÔNG rút ngắn)
#   SKIP_CHECKPOINT 1 = tắt mốc kiểm giờ 4-5 (chỉ dùng khi test khúc ngắn)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
cd "$REPO_ROOT"

CHUNK_MINUTES="${CHUNK_MINUTES:?cần CHUNK_MINUTES (khớp --chunk-minutes của collect_chunked.py)}"
N1_WORKERS="${N1_WORKERS:-8}"
CAMPAIGN_REPEAT="${CAMPAIGN_REPEAT:-2}"
CAMPAIGN_GAP="${CAMPAIGN_GAP:-600}"
SKIP_CHECKPOINT="${SKIP_CHECKPOINT:-0}"
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-phaseb}"; mkdir -p "$OUT"

CHUNK_SECONDS=$(( $(python3 -c "print(int(float('$CHUNK_MINUTES')*60))") ))
PAD_SECONDS=1200   # N1/N2 sống thêm 20' sau deadline dự kiến — collect_chunked giết, không tự tắt trước
LOADGEN_DURATION=$(( CHUNK_SECONDS + PAD_SECONDS ))
T_WORKLOAD_START="$(date +%s)"

# §B4 mục 1 kiểm #2 (SVID gia hạn qua 4h): chụp valid_from CỦA SVID BFF ngay
# lúc khúc bắt đầu để mốc kiểm giờ 4-5 so sánh — phải chụp Ở ĐÂY (đầu workload,
# gần đúng t_start thật của collect_chunked nhất) không phải lúc checkpoint.
mkdir -p "$OUT"
kubectl --context ctx-aws exec -n crapi deploy/bff -c istio-proxy -- curl -s localhost:15000/certs 2>/dev/null \
  | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print(""); sys.exit()
for c in d.get("certificates",[]):
    for cc in c.get("cert_chain",[]):
        for san in cc.get("subject_alt_names",[]):
            if san.get("uri","").endswith("/aws/bff"):
                print(cc.get("valid_from","")); sys.exit()
print("")
' > "$OUT/chunk1_initial_svid_valid_from.txt" 2>/dev/null || true

echo "[workload] bắt đầu $(date -u -d "@$T_WORKLOAD_START" +%FT%TZ) chunk_minutes=$CHUNK_MINUTES loadgen_duration=${LOADGEN_DURATION}s workers=$N1_WORKERS repeat=$CAMPAIGN_REPEAT gap=$CAMPAIGN_GAP"

# ── N1 (nền lành tính, có ultra_long nếu LOADGEN_DURATION đủ dài §B4 0.2) ──
DURATION="$LOADGEN_DURATION" WORKERS="$N1_WORKERS" bash tests/crapi_load_n1.sh &
N1_PID=$!

# ── N2 (nhiễu lành tính) ───────────────────────────────────────────────────
DURATION="$LOADGEN_DURATION" bash tests/crapi_noise_n2.sh &
N2_PID=$!

sleep 60   # warmup — nền sống trước khi chiến dịch A xen vào

# ── mốc kiểm giờ 4-5 (chỉ khúc 1 cần, nhưng chạy luôn nếu khúc đủ dài) ──────
if [[ "$SKIP_CHECKPOINT" != "1" && "$CHUNK_SECONDS" -ge 18000 ]]; then
  (
    CHECK_AT=$(( T_WORKLOAD_START + 4*3600 + 1800 ))  # giờ 4h30 — giữa mốc 4-5h yêu cầu
    now="$(date +%s)"
    sleep_s=$(( CHECK_AT - now )); [[ $sleep_s -gt 0 ]] && sleep "$sleep_s"
    bash tests/phaseb_chunk1_checkpoint.sh "$T_WORKLOAD_START" > "$OUT/chunk1_checkpoint.log" 2>&1
  ) &
  CHECKPOINT_PID=$!
  echo "[workload] mốc kiểm giờ 4h30 sẽ chạy lúc $(date -u -d "@$(( T_WORKLOAD_START + 4*3600 + 1800 ))" +%FT%TZ), log → $OUT/chunk1_checkpoint.log"
fi

# ── chiến dịch A — cấu hình ĐỢT DÀI (§B4 0.3): gap 600, repeat≥2, KHÔNG --duration-min ──
bash tests/crapi_campaign_phaseb.sh --repeat "$CAMPAIGN_REPEAT" --groups train,holdout --gap "$CAMPAIGN_GAP" &
CAMPAIGN_PID=$!

echo "[workload] N1=$N1_PID N2=$N2_PID campaign=$CAMPAIGN_PID — chờ bị collect_chunked.py kết thúc khúc"
# collect_chunked.py SIGTERM cả process group khi hết CHUNK_MINUTES — không tự
# thoát trước đó, để chiến dịch có thể chạy hết phần nó kịp làm trong khúc.
wait
