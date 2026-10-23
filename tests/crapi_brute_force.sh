#!/usr/bin/env bash
# KỊCH BẢN — Brute Force đăng nhập (ATT&CK T1110)
#
# Điểm vào xác thực người dùng crAPI là Keycloak (BFF OIDC/PKCE). Brute force =
# nhiều lần POST login-actions của Keycloak với mật khẩu sai → Keycloak ghi
# event LOGIN_ERROR / invalid_user_credentials.
#
# Tấn công THẬT: lặp luồng /auth/start → login-actions với password sai cho
# testuser01. (Keycloak có brute-force detection riêng — sau ngưỡng có thể tạm
# khoá tài khoản; script dừng ở 15 lần để không khoá vĩnh viễn tài khoản demo.)
#
# Bằng chứng: {namespace="identity",app="keycloak"} |~ "LOGIN_ERROR" → Grafana
# rule "Brute Force" → incident-analyzer evidence bundle (attack_type=brute_force)
# + block_source_ip.
set -uo pipefail
SCENARIO="crapi_brute_force"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"
crapi_preflight

ATTEMPTS="${ATTEMPTS:-15}"
UA="$BROWSER_UA"
# §B1: MODE=dense (train) → 1 username, nhiều mật khẩu sai, dồn dập (burst).
#      MODE=spray (holdout) → NHIỀU username, CÙNG một mật khẩu sai (password
#      spraying kinh điển), rải chậm (slow_drip). Nghiệm thu đếm số username
#      riêng biệt trong LOGIN_ERROR của Loki + phân phối khoảng cách.
MODE="${VP_MODE:-${MODE:-dense}}"
[[ "${VP_USERNAMES:-}" == "many" ]] && MODE="spray"
SPRAY_USERS=(testuser01 merchant01 stepup-demo ghost01 ghost02 ghost03 ghost04 operator01)
SPRAY_PASS="${SPRAY_PASS:-Winter2026!}"
log "Brute force Keycloak — MODE=$MODE ATTEMPTS=$ATTEMPTS PACE=${PACE:-burst}"

fail_count=0 ; err5xx=0
declare -a _tls_opts; mapfile -t _tls_opts < <(crapi_curl_tls_opts)
for i in $(seq 1 "$ATTEMPTS"); do
  [[ $i -gt 1 ]] && crapi_pace_sleep "$i" "$ATTEMPTS"
  if [[ "$MODE" == "spray" ]]; then
    user="${SPRAY_USERS[$(( (i - 1) % ${#SPRAY_USERS[@]} ))]}"; pass="$SPRAY_PASS"
  else
    user="testuser01"; pass="wrong-pass-$i"
  fi
  jar="$(mktemp)"
  page="$(curl -s -A "$UA" "${_tls_opts[@]}" -c "$jar" -b "$jar" -L "$BFF_URL/auth/start")"
  action="$(printf '%s' "$page" | grep -oE 'action="[^"]+"' | head -1 | sed -E 's/^action="//;s/"$//;s/&amp;/\&/g')"
  code="$(curl -s -A "$UA" "${_tls_opts[@]}" -c "$jar" -b "$jar" -L -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=$user" --data-urlencode "password=$pass" "$action")"
  # §B6 (sửa 2026-10): 503/5xx = Keycloak QUÁ TẢI/HỎNG, KHÔNG phải một lần đăng
  # nhập bị từ chối. Bản cũ đếm mọi mã ≠302 là "fail" → khi Keycloak trả 503,
  # fail_count vẫn đủ cao, assertion dưới PASS, lượt ghi status=attack dù cuộc
  # tấn công KHÔNG diễn ra (báo cáo đợt 150h §3 mục 6). Nay tách riêng 5xx và
  # abort nếu quá nhiều — một lần từ chối hợp lệ là 200 (render lại form lỗi)
  # hoặc 401, không bao giờ là 5xx.
  if [[ "$code" =~ ^5[0-9][0-9]$ ]]; then
    err5xx=$((err5xx + 1))
  elif [[ "$code" != "302" ]]; then
    fail_count=$((fail_count + 1))
  fi
  rm -f "$jar"
  printf '.'
done
echo
log "$fail_count/$ATTEMPTS lần đăng nhập bị từ chối (mật khẩu sai) · $err5xx lần Keycloak trả 5xx"
# Keycloak hỏng quá nửa số lần thử → cuộc brute-force không thực sự xảy ra: abort
# (exit≠0 → crapi_run_campaign.sh ghi status=aborted, KHÔNG tính vào lượt tấn công).
[[ $err5xx -gt $(( ATTEMPTS / 2 )) ]] && fail "Keycloak trả 5xx $err5xx/$ATTEMPTS lần — dịch vụ quá tải/hỏng, cuộc brute-force KHÔNG diễn ra (không ghi là attack)"
[[ $fail_count -ge $(( ATTEMPTS - 2 - err5xx )) ]] || fail "quá nhiều lần 'thành công' với mật khẩu sai — kiểm tra luồng Keycloak"

# xác nhận đăng nhập ĐÚNG vẫn được (không bị Keycloak lockout vĩnh viễn)
sleep 2
Jok="$(crapi_login testuser01 'Test1234!' || true)"
if [[ -n "${Jok:-}" && -f "$Jok" ]]; then log "mật khẩu đúng vẫn đăng nhập được (không bị khoá vĩnh viễn)"; rm -f "$Jok"; else
  log "⚠ testuser01 hiện không đăng nhập được — Keycloak brute-force detection đã tạm khoá; mở khoá: Keycloak admin → Users → testuser01 → Unlock, hoặc chờ hết waitIncrementSeconds"
fi

sleep 3
n="$(loki_count '{namespace="identity",app="keycloak"} |~ "(?i)login_error|invalid_user_credentials"')"
log "Keycloak LOGIN_ERROR trong 10 phút: $n dòng → Loki"
[[ "$n" -ge 1 ]] || log "  (nếu 0: bật event logging realm ztlab — Realm settings → Events → Save events; hoặc Keycloak log level)"

pass "$SCENARIO — $fail_count/$ATTEMPTS login sai · Keycloak LOGIN_ERROR → Loki · Grafana 'Brute Force' → incident-analyzer evidence bundle"
