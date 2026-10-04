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
log "Brute force Keycloak login testuser01 — $ATTEMPTS lần mật khẩu sai"

fail_count=0
declare -a _tls_opts; mapfile -t _tls_opts < <(crapi_curl_tls_opts)
for i in $(seq 1 "$ATTEMPTS"); do
  jar="$(mktemp)"
  page="$(curl -s -A "$UA" "${_tls_opts[@]}" -c "$jar" -b "$jar" -L "$BFF_URL/auth/start")"
  action="$(printf '%s' "$page" | grep -oE 'action="[^"]+"' | head -1 | sed -E 's/^action="//;s/"$//;s/&amp;/\&/g')"
  code="$(curl -s -A "$UA" "${_tls_opts[@]}" -c "$jar" -b "$jar" -L -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=testuser01" --data-urlencode "password=wrong-pass-$i" "$action")"
  # login sai → Keycloak render lại trang login (200) hoặc 401; KHÔNG có
  # /auth/callback?code=. Coi là "fail" nếu không đăng nhập được.
  [[ "$code" != "302" ]] && fail_count=$((fail_count + 1))
  rm -f "$jar"
  printf '.'
done
echo
log "$fail_count/$ATTEMPTS lần đăng nhập bị từ chối (mật khẩu sai)"
[[ $fail_count -ge $(( ATTEMPTS - 2 )) ]] || fail "quá nhiều lần 'thành công' với mật khẩu sai — kiểm tra luồng Keycloak"

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
