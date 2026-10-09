#!/usr/bin/env bash
# Giai đoạn B §3 — BỘ SINH NHIỄU LÀNH TÍNH N2 (lành tính CÓ deny).
#
# N2 GIỐNG A về bề mặt (đều sinh deny) nhưng KHÁC A về bản chất (không có ý định,
# không mở rộng phạm vi). Nhiệm vụ thật của mô hình Giai đoạn C là phân biệt deny
# TẤN CÔNG với deny LÀNH TÍNH — nên N2 phải tồn tại và phải ĐA DẠNG: mỗi loại
# nhiễu tham số hoá (số lần, khoảng cách, có/không khôi phục) như biến thể tấn
# công. Nếu một loại có chữ ký quá dễ (vd session_expired luôn đúng 1×401→login),
# mô hình học chữ ký đó và bài toán lại thành tầm thường (§3.1).
#
# Mỗi PHIÊN N2 ghi 1 dòng runs.jsonl:
#   {class:"benign_noise", noise_type, target_entity, t_start, t_end}
# (gán nhãn OFFLINE như A — không tiêm marker vào traffic.)
#
# Dùng (terminal riêng, xen trong N1):
#   DURATION=7200 bash tests/crapi_noise_n2.sh
#   NOISE_TYPES=role_mismatch,client_retry bash tests/crapi_noise_n2.sh   # lọc loại
#   bash tests/crapi_noise_n2.sh --dry-run
set -uo pipefail
SCENARIO="noise_n2"
source "$(dirname "${BASH_SOURCE[0]}")/lib/crapi_common.sh"

DURATION="${DURATION:-7200}"
RUNS_FILE="${RUNS_FILE:-$REPO_ROOT/tests/runs.jsonl}"
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-phaseb}/n2"; mkdir -p "$OUT"
TAG="n2_$(date +%Y%m%d%H%M%S)"; REQLOG="$OUT/$TAG.requests.tsv"
ALL_TYPES=(role_mismatch session_expired posture_degraded stepup_abandoned client_retry)
IFS=',' read -ra NOISE_TYPES <<<"${NOISE_TYPES:-$(IFS=,; echo "${ALL_TYPES[*]}")}"
DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1

ADMIN_PATHS=(/workshop/api/management/users/all /identity/api/v2/admin/videos/1 /workshop/api/shop/orders/all)
READS=(/identity/api/v2/user/dashboard /workshop/api/shop/products /community/api/v2/community/posts/recent)
NONCOMPLIANT_CERT="$CA_DIR/issued/test-noncompliant/device.crt"
NONCOMPLIANT_KEY="$CA_DIR/issued/test-noncompliant/device.key"

rand()      { echo $(( $1 + RANDOM % ($2 - $1 + 1) )); }      # rand <min> <max>
rand_sleep(){ sleep "$(python3 -c "import random;print(round(random.uniform($1,$2),2))")"; }

record_run() { # <noise_type> <target> <t_start_iso> <t_end_iso>
  python3 -c '
import json,sys
print(json.dumps({"class":"benign_noise","noise_type":sys.argv[1],"target_entity":sys.argv[2],
                  "t_start":sys.argv[3],"t_end":sys.argv[4]},ensure_ascii=False))' "$@" >> "$RUNS_FILE"
}

if [[ $DRY -eq 1 ]]; then
  echo "[n2] DRY — loại nhiễu bật: ${NOISE_TYPES[*]}"
  echo "[n2] runs.jsonl: $RUNS_FILE"
  echo "[n2] tham số mẫu: role_mismatch hits=$(rand 1 3); session_expired actions=$(rand 1 4) recover=$(( RANDOM%2 )); posture writes=$(rand 1 3); retry=$(rand 3 8)"
  exit 0
fi

crapi_preflight
mapfile -t TLS < <(crapi_curl_tls_opts)
form_action() { grep -oE 'action="[^"]+"' | head -1 | sed -E 's/^action="//; s/"$//; s/&amp;/\&/g'; }

req() { # <noise_type> <jar> <method> <path> [data]  → in code
  local c; c="$(crapi_call "$2" "$3" "$4" "${5:-}")"
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date +%s.%N)" "$1" "$3" "$4" "$c" >> "$REQLOG"
  echo "$c"
}
login_user() { crapi_login "$1" 'Test1234!' 2>/dev/null; }

# 1) role_mismatch — user thường gọi path admin 1–3 lần RẢI RÁC (không liên tiếp)
#    xen hành vi bình thường. Deny vì RBAC, không phải ý định.
noise_role_mismatch() {
  local jar hits; jar="$(login_user testuser01)" || return 0
  hits="$(rand 1 3)"
  for ((h=0; h<hits; h++)); do
    req role_mismatch "$jar" GET "${READS[RANDOM % ${#READS[@]}]}" >/dev/null
    rand_sleep 1 4
    req role_mismatch "$jar" GET "${ADMIN_PATHS[RANDOM % ${#ADMIN_PATHS[@]}]}" >/dev/null
    rand_sleep 2 6
    req role_mismatch "$jar" GET "${READS[RANDOM % ${#READS[@]}]}" >/dev/null
  done
  rm -f "$jar"
}

# 2) session_expired — vài hành động, phiên "hết hạn" (xoá cookie-jar), nhận 401
#    trên 1–4 hành động; CÓ/KHÔNG đăng nhập lại (tham số hoá, không luôn 1×401→login).
noise_session_expired() {
  local jar acts recover; jar="$(login_user testuser01)" || return 0
  req session_expired "$jar" GET "${READS[RANDOM % ${#READS[@]}]}" >/dev/null
  rand_sleep 1 3
  : > "$jar"                               # phiên "hết" — cookie bay
  acts="$(rand 1 4)"
  for ((a=0; a<acts; a++)); do req session_expired "$jar" GET "${READS[RANDOM % ${#READS[@]}]}" >/dev/null; rand_sleep 1 5; done
  recover="$(( RANDOM % 2 ))"              # 50% khôi phục, 50% bỏ
  if [[ "$recover" == "1" ]]; then
    rm -f "$jar"; jar="$(login_user testuser01)" || return 0
    req session_expired "$jar" GET "${READS[RANDOM % ${#READS[@]}]}" >/dev/null
  fi
  rm -f "$jar"
}

# 3) posture_degraded — phiên dùng cert non-compliant: đọc bình thường, 1–3 ghi bị chặn.
noise_posture_degraded() {
  local jar writes
  CRAPI_CLIENT_CERT="$NONCOMPLIANT_CERT" CRAPI_CLIENT_KEY="$NONCOMPLIANT_KEY" \
    mapfile -t TLS < <(CRAPI_CLIENT_CERT="$NONCOMPLIANT_CERT" CRAPI_CLIENT_KEY="$NONCOMPLIANT_KEY" crapi_curl_tls_opts)
  # dùng cùng biến môi trường cho login + call (crapi_curl_tls_opts đọc tại gọi)
  export CRAPI_CLIENT_CERT="$NONCOMPLIANT_CERT" CRAPI_CLIENT_KEY="$NONCOMPLIANT_KEY"
  jar="$(login_user testuser01)" || { unset CRAPI_CLIENT_CERT CRAPI_CLIENT_KEY; mapfile -t TLS < <(crapi_curl_tls_opts); return 0; }
  req posture_degraded "$jar" GET "${READS[RANDOM % ${#READS[@]}]}" >/dev/null
  rand_sleep 1 3
  writes="$(rand 1 3)"
  for ((w=0; w<writes; w++)); do
    req posture_degraded "$jar" POST /community/api/v2/community/posts "{\"title\":\"nc-$w\",\"content\":\"ghi từ thiết bị non-compliant\"}" >/dev/null
    rand_sleep 2 5
  done
  rm -f "$jar"
  unset CRAPI_CLIENT_CERT CRAPI_CLIENT_KEY; mapfile -t TLS < <(crapi_curl_tls_opts)   # trả cert compliant
}

# 4) stepup_abandoned — login KHÔNG step-up, chạm hành động nhạy cảm → step_up_required,
#    KHÔNG step-up, chuyển việc khác.
noise_stepup_abandoned() {
  local jar; jar="$(login_user testuser01)" || return 0
  req stepup_abandoned "$jar" GET "${READS[RANDOM % ${#READS[@]}]}" >/dev/null
  rand_sleep 1 3
  req stepup_abandoned "$jar" POST /workshop/api/shop/orders '{"product_id":1,"quantity":1}' >/dev/null   # step_up_required
  rand_sleep 1 4
  # bỏ step-up, làm việc khác (đọc)
  local n; n="$(rand 2 4)"; for ((i=0;i<n;i++)); do req stepup_abandoned "$jar" GET "${READS[RANDOM % ${#READS[@]}]}" >/dev/null; rand_sleep 1 4; done
  rm -f "$jar"
}

# 5) client_retry — retry 3–8 lần một request bị từ chối, giãn cách KHÔNG đều.
noise_client_retry() {
  local jar tries path; jar="$(login_user testuser01)" || return 0
  path="${ADMIN_PATHS[RANDOM % ${#ADMIN_PATHS[@]}]}"   # bị RBAC deny
  tries="$(rand 3 8)"
  for ((t=0; t<tries; t++)); do req client_retry "$jar" GET "$path" >/dev/null; rand_sleep 0.5 6; done
  rm -f "$jar"
}

HARD_END=$(( $(date +%s) + DURATION ))
echo "[n2] bắt đầu khúc tag=$TAG DURATION=${DURATION}s loại=${NOISE_TYPES[*]} → $REQLOG + $RUNS_FILE"
declare -A DONE=()
while [[ $(date +%s) -lt $HARD_END ]]; do
  nt="${NOISE_TYPES[RANDOM % ${#NOISE_TYPES[@]}]}"
  t0="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  case "$nt" in
    role_mismatch)    noise_role_mismatch ;;
    session_expired)  noise_session_expired ;;
    posture_degraded) noise_posture_degraded ;;
    stepup_abandoned) noise_stepup_abandoned ;;
    client_retry)     noise_client_retry ;;
  esac
  t1="$(date -u -d '+1 second' +%Y-%m-%dT%H:%M:%SZ)"   # +1s như §4/H18
  record_run "$nt" "testuser01" "$t0" "$t1"
  DONE[$nt]=$(( ${DONE[$nt]:-0} + 1 ))
  rand_sleep 3 12
done
echo "[n2] KHÚC XONG — số phiên theo loại:"
for k in "${!DONE[@]}"; do printf '   %-18s %d\n' "$k" "${DONE[$k]}"; done
echo "[n2] runs.jsonl (benign_noise) đã ghi: $(grep -c benign_noise "$RUNS_FILE" 2>/dev/null || echo 0) dòng tổng"
