#!/usr/bin/env bash
# Giai đoạn B §2 — BỘ SINH LƯU LƯỢNG NỀN N1 (lành tính THƯỜNG, ~0 deny).
#
# 4 hồ sơ chạy đồng thời qua Gateway mTLS THẬT (cert compliant), KHÔNG port-forward
# đường debug. Mỗi "worker" lặp vô hạn: tạo phiên (login) → chạy một chuỗi hành
# động hợp lệ với nhịp NGẪU NHIÊN → nghỉ → phiên mới.
#
#   Khách xem   50%  đọc dashboard/sản phẩm/community           phiên 5–15'
#   Người mua   25%  + coupon + đặt đơn (step-up THẬT 1 lần/phiên) phiên 15–40'
#   Thợ máy     15%  (merchant01) + service request/report        phiên 10–30'
#   Phiên dài   10%  mọi hành động, thỉnh thoảng > 4h             phiên 60–120'
#
# Bắt buộc (§2):
#  - phiên > 300s (TTL access token — phép thử hồi quy sống H16: BFF phải refresh);
#    hồ sơ "phiên dài" vượt > 4h ít nhất 1 lần/khúc (TTL SVID — H17).
#  - nhịp request + nghỉ NGẪU NHIÊN (nền đều tăm tắp là đặc trưng giả).
#  - crapi_preflight đầu mỗi khúc (cert thiết bị TTL 7 ngày — H15.3).
#  - §1.2: người mua NẠP LẠI CREDIT qua coupon khi đơn trả 400 (stepup-demo hết
#    100 credit sau ~10 đơn → nguồn nhãn sai tương quan thời gian, cùng loại H16).
#  - giám sát non-200 THEO GIỜ; > 1% → cảnh báo + dừng khúc (không thu dữ liệu bẩn).
#
# Dùng (chạy ở TERMINAL RIÊNG ngoài Claude Code — RAM):
#   DURATION=7200 WORKERS=8 bash tests/crapi_load_n1.sh
#   bash tests/crapi_load_n1.sh --dry-run       # chỉ kiểm phân bổ hồ sơ, không gọi mạng
set -uo pipefail
SCENARIO="load_n1"
source "$(dirname "${BASH_SOURCE[0]}")/lib/crapi_common.sh"

DURATION="${DURATION:-7200}"          # tổng thời lượng khúc (giây); cổng 2h = 7200
WORKERS="${WORKERS:-8}"               # số worker đồng thời
NON200_LIMIT_PCT="${NON200_LIMIT_PCT:-1.0}"
LONG_OVER_4H="${LONG_OVER_4H:-0}"     # 1 = cho phép phiên dài vượt 4h (chỉ khúc ≥ ~5h)
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-phaseb}/n1"; mkdir -p "$OUT"
TAG="n1_$(date +%Y%m%d%H%M%S)"; REQLOG="$OUT/$TAG.requests.tsv"
DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1

# §1.2 credit top-up — endpoint/coupon cấu hình được (crAPI mặc định apply_coupon).
# Nếu deployment dùng code khác, đặt COUPON_CODE/COUPON_PATH qua env.
COUPON_PATH="${COUPON_PATH:-/workshop/api/shop/apply_coupon}"
COUPON_CODE="${COUPON_CODE:-TRAC075}"

READS=(/identity/api/v2/user/dashboard /identity/api/v2/vehicle/vehicles
       /workshop/api/shop/products /workshop/api/shop/orders/all
       /community/api/v2/community/home /community/api/v2/community/posts/recent)

# §B1b: pool nạn nhân (khớp seed-job.yaml + deploy-crapi.sh). N1 thỉnh thoảng đăng
# nhập các user này và ĐĂNG BÀI → vehicleid của họ lộ qua community/posts/recent,
# để crapi_bola.sh phát hiện ≥15 nạn nhân (luân phiên). Password Test1234!.
VICTIM_POOL=($(for k in $(seq -w 1 15); do echo "victim$k"; done))

# Phân bổ hồ sơ theo trọng số (50/25/15/10) cho N worker.
pick_profile() { # <worker_index>
  local r=$(( RANDOM % 100 ))
  if   (( r < 50 )); then echo viewer
  elif (( r < 75 )); then echo buyer
  elif (( r < 90 )); then echo mechanic
  else                    echo long; fi
}
# Thời lượng phiên (giây) theo hồ sơ — LUÔN > 300 (TTL access token).
session_len() { # <profile>
  case "$1" in
    viewer)   echo $(( 300 + RANDOM % 600 ))  ;;   # 5–15'
    buyer)    echo $(( 900 + RANDOM % 1500 )) ;;   # 15–40'
    mechanic) echo $(( 600 + RANDOM % 1200 )) ;;   # 10–30'
    long)
      if [[ "$LONG_OVER_4H" == "1" ]] && (( RANDOM % 4 == 0 )); then
        echo $(( 14400 + RANDOM % 3600 ))          # > 4h (H17 SVID TTL)
      else
        echo $(( 3600 + RANDOM % 3600 ))           # 60–120'
      fi ;;
  esac
}
rand_sleep() { sleep "$(python3 -c 'import random;print(round(random.uniform(0.4,4.0),2))')"; }

if [[ $DRY -eq 1 ]]; then
  echo "[n1] DRY — phân bổ 1000 mẫu hồ sơ:"
  declare -A cnt=()
  for _ in $(seq 1000); do p="$(pick_profile 0)"; cnt[$p]=$(( ${cnt[$p]:-0} + 1 )); done
  for p in viewer buyer mechanic long; do printf '   %-9s %4d (%.0f%%)  phiên mẫu=%ss\n' "$p" "${cnt[$p]:-0}" "${cnt[$p]:-0}" "$(session_len "$p")"; done
  echo "[n1] DRY ok (không gọi mạng)"; exit 0
fi

crapi_preflight
mapfile -t TLS < <(crapi_curl_tls_opts)
form_action() { grep -oE 'action="[^"]+"' | head -1 | sed -E 's/^action="//; s/"$//; s/&amp;/\&/g'; }

# step-up login cho người mua (acr=high 1 lần/phiên → mọi đơn sau qua, không OTP lại).
_STEPUP_SECRET=""
_load_stepup_secret() {
  [[ -n "$_STEPUP_SECRET" ]] && return 0
  _STEPUP_SECRET="$(kubectl --context "$KUBE_OS" -n identity get secret stepup-demo-otp -o jsonpath='{.data.secret}' 2>/dev/null | base64 -d)" || true
}
_totp() { python3 -c 'import hmac,hashlib,struct,time,sys
s=sys.argv[1].encode(); c=int(time.time()//30)
m=hmac.new(s,struct.pack(">Q",c),hashlib.sha1).digest(); o=m[-1]&15
print("%06d"%((struct.unpack(">I",m[o:o+4])[0]&0x7fffffff)%1000000))' "$1"; }
_LAST_WIN=""
login_stepup() { # <jar> → 0/1
  local jar="$1" page act win
  _load_stepup_secret; [[ -n "$_STEPUP_SECRET" ]] || return 1
  page="$(curl -s -A "$BROWSER_UA" "${TLS[@]}" -c "$jar" -b "$jar" -L "$BFF_URL/auth/start-stepup")"
  act="$(form_action <<<"$page")"; [[ -n "$act" ]] || return 1
  page="$(curl -s -A "$BROWSER_UA" "${TLS[@]}" -c "$jar" -b "$jar" -L \
    --data-urlencode "username=stepup-demo" --data-urlencode "password=StepupDemo123!" "$act")"
  win=$(( $(date +%s) / 30 )); while [[ "$win" == "$_LAST_WIN" ]]; do sleep 2; win=$(( $(date +%s) / 30 )); done
  _LAST_WIN="$win"; act="$(form_action <<<"$page")"; [[ -n "$act" ]] || return 1
  curl -s -A "$BROWSER_UA" "${TLS[@]}" -c "$jar" -b "$jar" -L -o /dev/null \
    --data-urlencode "otp=$(_totp "$_STEPUP_SECRET")" --data-urlencode "login=Sign In" "$act"
}

# §B1c: uuid xe CỦA CHÍNH requester. Xem vị trí xe của mình là chức năng BÌNH
# THƯỜNG — N1 phải gọi /identity/api/v2/vehicle/{id}/location một cách HỢP LỆ,
# nếu không chính path đó thành nhãn hoàn hảo (mô hình recall~1 bằng luật khớp
# path; kiểm rò rỉ uuid KHÔNG bắt được vì rò ở TẦNG PATH).
get_own_vehicle() { # <jar> → in uuid xe của mình (rỗng nếu user chưa có xe)
  curl -s -A "$BROWSER_UA" "${TLS[@]}" -b "$1" --max-time 20 \
    "$BFF_URL/identity/api/v2/vehicle/vehicles" 2>/dev/null \
    | grep -oE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' | head -1
}

req() { # <profile> <jar> <method> <path> [data]  → ghi dòng + in code
  local c; c="$(crapi_call "$2" "$3" "$4" "${5:-}")"
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date +%s.%N)" "$1" "$3" "$4" "$c" >> "$REQLOG"
  echo "$c"
}

# §1.2: đặt đơn, nếu 400 (hết credit) thì nạp coupon rồi thử lại 1 lần.
place_order() { # <profile> <jar>
  local code
  code="$(req "$1" "$2" POST /workshop/api/shop/orders '{"product_id":1,"quantity":1}')"
  if [[ "$code" == "400" ]]; then
    req "$1" "$2" POST "$COUPON_PATH" "{\"coupon_code\":\"$COUPON_CODE\",\"amount\":100}" >/dev/null
    req "$1" "$2" POST /workshop/api/shop/orders '{"product_id":1,"quantity":1}' >/dev/null
  fi
}

# Một phiên hoàn chỉnh của một hồ sơ (chạy nền trong worker).
run_session() { # <profile> <deadline_epoch>
  local profile="$1" hard_end="$2" jar slen s_end
  slen="$(session_len "$profile")"; s_end=$(( $(date +%s) + slen ))
  (( s_end > hard_end )) && s_end="$hard_end"
  case "$profile" in
    mechanic) jar="$(crapi_login merchant01 'Test1234!' 2>/dev/null)" || return 0 ;;
    buyer|long)
      jar="$(mktemp /tmp/crapi_cj.XXXXXX)"; login_stepup "$jar" >/dev/null 2>&1 || {
        # không step-up được → hạ xuống hành vi chỉ-đọc (vẫn lành tính, không deny)
        rm -f "$jar"; jar="$(crapi_login testuser01 'Test1234!' 2>/dev/null)" || return 0; profile="viewer"; } ;;
    *) # viewer — §B1b: ~1/4 phiên là một nạn nhân (đăng bài → vehicleid lộ ra)
      if (( RANDOM % 4 == 0 )) && [[ ${#VICTIM_POOL[@]} -gt 0 ]]; then
        vu="${VICTIM_POOL[RANDOM % ${#VICTIM_POOL[@]}]}"
        jar="$(crapi_login "$vu" 'Test1234!' 2>/dev/null)" || jar="$(crapi_login testuser01 'Test1234!' 2>/dev/null)" || return 0
      else
        jar="$(crapi_login testuser01 'Test1234!' 2>/dev/null)" || return 0
      fi ;;
  esac
  local own_uuid; own_uuid="$(get_own_vehicle "$jar")"   # §B1c: uuid xe của mình (nếu có)
  local i=0
  while [[ $(date +%s) -lt $s_end ]]; do
    i=$((i+1))
    req "$profile" "$jar" GET "${READS[RANDOM % ${#READS[@]}]}" >/dev/null
    # §B1c: xem vị trí xe CỦA CHÍNH MÌNH (hợp lệ) — tần suất tự nhiên ~1/5 vòng.
    [[ -n "$own_uuid" ]] && (( i % 5 == 0 )) && \
      req "$profile" "$jar" GET "/identity/api/v2/vehicle/$own_uuid/location" >/dev/null
    case "$profile" in
      buyer)    (( i % 8 == 0 ))  && place_order "$profile" "$jar" ;;
      long)     (( i % 12 == 0 )) && place_order "$profile" "$jar"
                (( i % 15 == 0 )) && req "$profile" "$jar" POST /community/api/v2/community/posts "{\"title\":\"n1-$i\",\"content\":\"bài viết thường $i\"}" >/dev/null ;;
      mechanic) (( i % 10 == 0 )) && req "$profile" "$jar" POST /workshop/api/mechanic/service_requests '{"vehicle_id":"1","problem_details":"định kỳ"}' >/dev/null ;;
      viewer)   (( i % 20 == 0 )) && req "$profile" "$jar" POST /community/api/v2/community/posts "{\"title\":\"n1-$i\",\"content\":\"bài viết thường $i\"}" >/dev/null ;;
    esac
    rand_sleep
  done
  rm -f "$jar"
}

# Worker: lặp phiên tới hard deadline, hồ sơ chọn ngẫu nhiên theo trọng số.
worker() { # <idx> <hard_end>
  local idx="$1" hard_end="$2"
  while [[ $(date +%s) -lt $hard_end ]]; do
    run_session "$(pick_profile "$idx")" "$hard_end"
    sleep $(( 2 + RANDOM % 8 ))   # nghỉ giữa 2 phiên
  done
}

# Giám sát non-200 theo giờ (chạy nền); > NON200_LIMIT_PCT → ghi cờ STOP.
STOPFLAG="$OUT/$TAG.STOP"
monitor() { # <hard_end>
  local hard_end="$1" last=0
  while [[ $(date +%s) -lt $hard_end ]]; do
    sleep 3600
    [[ -f "$REQLOG" ]] || continue
    python3 - "$REQLOG" "$last" "$NON200_LIMIT_PCT" "$STOPFLAG" <<'PY'
import sys
reqlog, last, limit, stopflag = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
rows = [l.split("\t") for l in open(reqlog) if l.strip()]
win = rows[last:]
if not win: sys.exit()
n = len(win); non200 = sum(1 for r in win if len(r) >= 5 and r[4].strip() != "200")
pct = 100 * non200 / n
print(f"[n1][monitor] giờ gần nhất: {n} req, non-200={non200} ({pct:.2f}%) ngưỡng={limit}%", flush=True)
if pct > limit:
    open(stopflag, "w").write(f"non200={pct:.2f}% > {limit}% ({non200}/{n})\n")
PY
    last="$(wc -l < "$REQLOG")"
    [[ -f "$STOPFLAG" ]] && { echo "[n1][monitor] non-200 vượt ngưỡng — DỪNG KHÚC: $(cat "$STOPFLAG")"; return; }
  done
}

HARD_END=$(( $(date +%s) + DURATION ))
# §B1f: nhịp tim để chiến dịch A (crapi_campaign_phaseb.sh) biết nền N1 CÒN
# SỐNG — nếu N1 tắt giữa chừng, các lượt tấn công sau đó không có nền (rác).
HEARTBEAT="$OUT/HEARTBEAT"; : > "$HEARTBEAT"
echo "[n1] bắt đầu khúc tag=$TAG DURATION=${DURATION}s WORKERS=$WORKERS long_over_4h=$LONG_OVER_4H → $REQLOG (heartbeat: $HEARTBEAT)"
monitor "$HARD_END" &  MON_PID=$!
PIDS=()
for ((w=1; w<=WORKERS; w++)); do worker "$w" "$HARD_END" & PIDS+=($!); done

# Nếu monitor dựng cờ STOP, giết worker sớm.
while kill -0 "$MON_PID" 2>/dev/null; do
  touch "$HEARTBEAT"   # §B1f: cập nhật mỗi 30s khi N1 còn chạy
  sleep 30
  if [[ -f "$STOPFLAG" ]]; then
    echo "[n1] nhận cờ STOP — kết thúc worker sớm"; kill "${PIDS[@]}" 2>/dev/null || true; break
  fi
  # còn worker nào sống không?
  alive=0; for p in "${PIDS[@]}"; do kill -0 "$p" 2>/dev/null && alive=1; done
  [[ $alive -eq 0 ]] && break
done
wait "${PIDS[@]}" 2>/dev/null || true
kill "$MON_PID" 2>/dev/null || true
rm -f "$HEARTBEAT"   # §B1f: N1 kết thúc → bỏ nhịp tim (chiến dịch biết nền đã tắt)

# Tổng kết non-200 cả khúc.
python3 - "$REQLOG" "$NON200_LIMIT_PCT" <<'PY' | tee "$OUT/$TAG.summary.txt"
import collections, sys
reqlog, limit = sys.argv[1], float(sys.argv[2])
rows = [l.split("\t") for l in open(reqlog) if l.strip()]
codes = collections.Counter(r[4].strip() for r in rows if len(r) >= 5)
n = sum(codes.values()); non200 = n - codes.get("200", 0)
pct = 100 * non200 / n if n else 0
by_prof = collections.Counter(r[1] for r in rows if len(r) >= 2)
print(f"[n1] KHÚC XONG: requests={n} codes={dict(codes)} non200={non200} ({pct:.2f}%) ngưỡng={limit}%")
print(f"[n1] theo hồ sơ: {dict(by_prof)}")
print(f"[n1] KẾT LUẬN: {'OK (<' + str(limit) + '%)' if pct < limit else 'BẨN (>=' + str(limit) + '%) — không dùng khúc này'}")
PY
[[ -f "$STOPFLAG" ]] && echo "[n1] (khúc bị cờ STOP giữa chừng — xem $STOPFLAG)"
exit 0
