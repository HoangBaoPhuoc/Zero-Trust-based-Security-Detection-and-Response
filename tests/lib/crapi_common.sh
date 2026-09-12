#!/usr/bin/env bash
# Helper dùng chung cho các script tấn công crAPI (tests/crapi_*.sh).
#
# Mỗi kịch bản = tấn công THẬT vào lớp Zero-Trust đang chạy (mТLS SVID + OPA
# service_acl + RBAC + step-up + device-trust), sinh log THẬT (OPA decision log
# job=opa-decisions, istio access log job=envoy-access, BFF audit job=bff-audit,
# Keycloak event) → Promtail → Loki → Grafana alert → incident-analyzer evidence bundle.
#
# KHÔNG đẩy log giả vào Loki. KHÔNG phải bằng chứng "đã chặn" nếu chỉ chạy script
# này — enforcement được xác nhận riêng bằng chính assertion trong từng script
# (mã trả về 401/403 từ điểm enforcement thật).

set -uo pipefail

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LIB_DIR/../.." && pwd)"
CA_DIR="$REPO_ROOT/deploy/vendor/device-ca"

# A3 (KEHOACH-THAYDOI-HETHONG.md): điểm vào crAPI nay là Traefik biên với
# client-cert mTLS bắt buộc (k8s/crapi/edge-tls.yaml) — không còn cổng HTTP
# trần. Tunnel BFF_URL trỏ thẳng svc/traefik (entrypoint websecure, xem
# scripts/open-admin-uis.sh "crAPI (Traefik mTLS)"), --resolve để SNI/Host
# khớp Host(`crapi.ztlab.local`) dù cổng cục bộ khác nhau.
CRAPI_HOST="${CRAPI_HOST:-crapi.ztlab.local}"
BFF_URL="${BFF_URL:-https://$CRAPI_HOST:18443}"
_BFF_TUNNEL_PORT="${BFF_URL##*:}"
KUBE_AWS="${KUBE_AWS:-ctx-aws}"
KUBE_OS="${KUBE_OS:-ctx-openstack}"
NS="${CRAPI_NS:-crapi}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
BROWSER_UA="${BROWSER_UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36}"

# Cert thiết bị mặc định cho các kịch bản (posture=compliant) — tự phát hành
# nếu chưa có. Kịch bản device-trust dùng cert posture=non-compliant riêng
# (xem crapi_access_denied.sh) bằng cách gán đè CRAPI_CLIENT_CERT/_KEY.
CRAPI_CLIENT_CERT="${CRAPI_CLIENT_CERT:-$CA_DIR/issued/test-compliant/device.crt}"
CRAPI_CLIENT_KEY="${CRAPI_CLIENT_KEY:-$CA_DIR/issued/test-compliant/device.key}"
CRAPI_CA_CERT="${CRAPI_CA_CERT:-$CA_DIR/device-ca.crt}"

_ensure_device_cert() {
  local device_id="$1" posture="$2"
  [[ -f "$CA_DIR/issued/$device_id/device.crt" ]] && return 0
  bash "$REPO_ROOT/scripts/issue-device-cert.sh" "$device_id" "$posture" >/dev/null \
    || fail "không phát hành được cert thiết bị '$device_id' — kiểm tra Device CA ($CA_DIR)"
}

# Cờ curl TLS/mTLS dùng chung cho MỌI request tới BFF (login, call, preflight).
# Đọc CRAPI_CLIENT_CERT/_KEY tại thời điểm gọi (không cache) để
# crapi_access_denied.sh gán đè sang cert non-compliant cho kịch bản của nó.
crapi_curl_tls_opts() {
  printf '%s\n' --cacert "$CRAPI_CA_CERT" --cert "$CRAPI_CLIENT_CERT" --key "$CRAPI_CLIENT_KEY" \
    --resolve "${CRAPI_HOST}:${_BFF_TUNNEL_PORT}:127.0.0.1"
}

_SC="${SCENARIO:-crapi}"
log()  { printf '[%s] %s\n'       "$_SC" "$*"; }
pass() { printf '[%s] PASS: %s\n' "$_SC" "$*"; }
fail() { printf '[%s] FAIL: %s\n' "$_SC" "$*" >&2; exit 1; }

# preflight: Device CA fixtures + BFF reachable qua Traefik mTLS
crapi_preflight() {
  _ensure_device_cert test-compliant compliant
  _ensure_device_cert test-noncompliant non-compliant
  local -a tls_opts; mapfile -t tls_opts < <(crapi_curl_tls_opts)
  curl -fsS --max-time 5 "${tls_opts[@]}" "$BFF_URL/health" >/dev/null \
    || fail "BFF không phản hồi tại $BFF_URL (mTLS) — chạy: bash scripts/open-admin-uis.sh"
}

# crapi_login <user> <pass> [<user-agent>]  → in ra đường dẫn cookie-jar (stdout).
# Thực hiện đủ luồng Keycloak OIDC/PKCE qua BFF (/auth/start → login-actions →
# /auth/callback). Cookie-jar giữ session BFF (ztlab_bff_session).
crapi_login() {
  local user="$1" pass="$2" ua="${3:-$BROWSER_UA}"
  local jar; jar="$(mktemp /tmp/crapi_cj.XXXXXX)"
  local page action code
  local -a tls_opts; mapfile -t tls_opts < <(crapi_curl_tls_opts)
  page="$(curl -s -A "$ua" "${tls_opts[@]}" -c "$jar" -b "$jar" -L "$BFF_URL/auth/start")"
  action="$(printf '%s' "$page" | grep -oE 'action="[^"]+"' | head -1 | sed -E 's/^action="//; s/"$//; s/&amp;/\&/g')"
  [[ -n "$action" ]] || { rm -f "$jar"; fail "không lấy được form login Keycloak (BFF /auth/start)"; }
  code="$(curl -s -A "$ua" "${tls_opts[@]}" -c "$jar" -b "$jar" -L -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=$user" --data-urlencode "password=$pass" "$action")"
  [[ "$code" == "200" ]] || { rm -f "$jar"; fail "login $user thất bại (http $code)"; }
  printf '%s' "$jar"
}

# crapi_call <jar> <method> <path> [<data>] → in mã HTTP
crapi_call() {
  local jar="$1" method="$2" path="$3" data="${4:-}"
  local -a tls_opts; mapfile -t tls_opts < <(crapi_curl_tls_opts)
  if [[ -n "$data" ]]; then
    curl -s -A "$BROWSER_UA" "${tls_opts[@]}" -b "$jar" -X "$method" -H 'Content-Type: application/json' \
      -d "$data" -o /dev/null -w '%{http_code}' --max-time 25 "$BFF_URL$path"
  else
    curl -s -A "$BROWSER_UA" "${tls_opts[@]}" -b "$jar" -X "$method" -o /dev/null -w '%{http_code}' \
      --max-time 25 "$BFF_URL$path"
  fi
}

# loki_count '<logql>'  → số dòng khớp trong 10 phút gần nhất (0 nếu Loki không tới được)
loki_count() {
  local q="$1" end start
  end="$(date +%s)000000000"; start="$(( $(date +%s) - 600 ))000000000"
  curl -s --max-time 8 -G "$LOKI_URL/loki/api/v1/query_range" \
    --data-urlencode "query=count_over_time(($q)[10m])" \
    --data-urlencode "start=$start" --data-urlencode "end=$end" --data-urlencode "step=600" 2>/dev/null \
    | python3 -c "import json,sys
try:
    d=json.load(sys.stdin); r=d['data']['result']
    print(int(float(r[0]['values'][-1][1])) if r else 0)
except Exception:
    print(0)"
}

# pod nghiệp vụ đầu tiên của một app trong ns crapi (cluster AWS mặc định)
crapi_pod() {
  local app="$1" ctx="${2:-$KUBE_AWS}"
  kubectl --context "$ctx" -n "$NS" get pod -l "app=$app" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}
