#!/usr/bin/env bash
# KỊCH BẢN — Step-up OTP đầu-cuối (mục 6 vòng 2026-09-29)
#
# crapi_step_up.sh chỉ chứng minh vế "bị đòi step-up" (401). Script này chạy
# TRỌN luồng cho user stepup-demo (OTP enroll bởi deploy, secret ở Secret k8s
# identity/stepup-demo-otp):
#   A. login thường (/auth/start, acr=1)  → POST /workshop/api/shop/orders → 401 step_up_required
#   B. /auth/start-stepup (acr_values=high) → mật khẩu → form OTP của Keycloak
#      → mã TOTP thật → callback → cùng hành động → KHÔNG còn 401/403
# Bằng chứng: BFF audit user_login acr=high stepup=true + OPA decision allow.
set -uo pipefail
SCENARIO="crapi_step_up_otp"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"
crapi_preflight
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-closeout}/step-up"; mkdir -p "$OUT"
T0=$(date +%s)

SECRET="$(kubectl --context "$KUBE_OS" -n identity get secret stepup-demo-otp -o jsonpath='{.data.secret}' | base64 -d)"
[[ -n "$SECRET" ]] || fail "thiếu Secret identity/stepup-demo-otp — deploy chưa enroll OTP (deploy-app.sh deploy_stepup_flow)"
totp() { python3 -c 'import hmac,hashlib,struct,time,sys
s=sys.argv[1].encode(); c=int(time.time()//30)
m=hmac.new(s,struct.pack(">Q",c),hashlib.sha1).digest(); o=m[-1]&15
print("%06d"%((struct.unpack(">I",m[o:o+4])[0]&0x7fffffff)%1000000))' "$SECRET"; }
mapfile -t TLS < <(crapi_curl_tls_opts)
form_action() { grep -oE 'action="[^"]+"' | head -1 | sed -E 's/^action="//; s/"$//; s/&amp;/\&/g'; }
ORDER='{"product_id":1,"quantity":1}'

LAST_WIN=""
# login_flow <jar> <start-path> → đặt LOGIN_RESULT = mã HTTP cuối (200 = về tới BFF)
# (biến toàn cục, KHÔNG gọi trong $(...) — LAST_WIN phải giữ giữa các lần). Nộp OTP nếu
# Keycloak hỏi; mỗi mã TOTP chỉ dùng một lần (Keycloak từ chối dùng lại mã
# trong cùng cửa sổ 30 s) → chờ sang cửa sổ mới nếu cần.
login_flow() {
  local jar="$1" start="$2" page act win
  page="$(curl -s -A "$BROWSER_UA" "${TLS[@]}" -c "$jar" -b "$jar" -L "$BFF_URL$start")"
  act="$(form_action <<<"$page")"; [[ -n "$act" ]] || { LOGIN_RESULT="noform"; return; }
  page="$(curl -s -A "$BROWSER_UA" "${TLS[@]}" -c "$jar" -b "$jar" -L -w '\n__CODE__%{http_code} %{url_effective}' \
    --data-urlencode "username=stepup-demo" --data-urlencode "password=StepupDemo123!" "$act")"
  if grep -q 'name="otp"' <<<"$page"; then
    win=$(( $(date +%s) / 30 )); while [[ "$win" == "$LAST_WIN" ]]; do sleep 2; win=$(( $(date +%s) / 30 )); done
    LAST_WIN="$win"; OTP_PROMPTS=$((OTP_PROMPTS+1))
    act="$(form_action <<<"$page")"
    page="$(curl -s -A "$BROWSER_UA" "${TLS[@]}" -c "$jar" -b "$jar" -L -w '\n__CODE__%{http_code} %{url_effective}' \
      --data-urlencode "otp=$(totp)" --data-urlencode "login=Sign In" "$act")"
    if grep -q 'name="otp"' <<<"$page"; then
      LOGIN_RESULT="otp_again: $(grep -oE 'input-error[^<]*<[^<]*|kc-feedback-text">[^<]*' <<<"$page" | head -1)"; return
    fi
  fi
  LOGIN_RESULT="$(sed -n 's/^__CODE__//p' <<<"$page" | tail -1)"
}

JA="$(mktemp /tmp/crapi_cj.XXXXXX)"; JB="$(mktemp /tmp/crapi_cj.XXXXXX)"; trap 'rm -f "$JA" "$JB"' EXIT

# A. login thường (client crapi-bff, flow browser mặc định: user có OTP nên
#    Keycloak hỏi OTP theo "Conditional OTP", nhưng KHÔNG yêu cầu LoA → acr=1)
OTP_PROMPTS=0; login_flow "$JA" /auth/start; lA="$LOGIN_RESULT"
rA="$(crapi_call "$JA" POST /workshop/api/shop/orders "$ORDER")"
log "A. login thường → [$lA] otp_prompts=$OTP_PROMPTS; POST orders → $rA"
[[ "$lA" == 200* ]] || fail "login thường thất bại ($lA)"
[[ "$rA" == "401" ]] || fail "phiên thường KHÔNG bị đòi step-up (mong 401, nhận $rA)"

# B. step-up (client crapi-bff-stepup, acr_values=high → Stepup-2fa hỏi OTP đúng 1 lần)
OTP_PROMPTS=0; login_flow "$JB" /auth/start-stepup; lB="$LOGIN_RESULT"
log "B. login step-up → [$lB] otp_prompts=$OTP_PROMPTS"
[[ "$lB" == 200* ]] || fail "đăng nhập step-up thất bại ($lB) — otp_again = Keycloak hỏi OTP lần 2 (flow browser-stepup)"
rB="$(crapi_call "$JB" POST /workshop/api/shop/orders "$ORDER")"
log "B. phiên step-up: POST orders → $rB"
[[ "$rB" != "401" && "$rB" != "403" && "$rB" != "000" ]] || fail "sau step-up vẫn bị chặn ($rB)"

sleep 8
T1=$(date +%s)
nlogin="$(loki_count '{job="bff-audit"} | json | event="user_login" | username="stepup-demo" | stepup="true"' "$T0" "$T1")"
log "BFF audit user_login stepup-demo stepup=true trong lần chạy: $nlogin"
[[ "$nlogin" -ge 1 ]] || fail "không thấy BFF audit user_login stepup=true của stepup-demo"
{ echo "ts=$(date -Is) phien_thuong=$rA phien_stepup=$rB bff_audit_login_stepup=$nlogin"; } >> "$OUT/step-up-otp.log"
pass "$SCENARIO — thường: $rA (step_up_required); sau OTP: $rB (không còn bị đòi step-up)"
