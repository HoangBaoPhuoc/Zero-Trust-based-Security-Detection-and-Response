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

BFF_URL="${BFF_URL:-http://localhost:18081}"
KUBE_AWS="${KUBE_AWS:-ctx-aws}"
KUBE_OS="${KUBE_OS:-ctx-openstack}"
NS="${CRAPI_NS:-crapi}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
# UA "trình duyệt" → BFF đánh giá device_trust = new_device/trusted (không phải
# suspicious). Kịch bản device-trust sẽ tự đổi UA.
BROWSER_UA="${BROWSER_UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36}"

_SC="${SCENARIO:-crapi}"
log()  { printf '[%s] %s\n'       "$_SC" "$*"; }
pass() { printf '[%s] PASS: %s\n' "$_SC" "$*"; }
fail() { printf '[%s] FAIL: %s\n' "$_SC" "$*" >&2; exit 1; }

# preflight: BFF reachable
crapi_preflight() {
  curl -fsS --max-time 5 "$BFF_URL/health" >/dev/null \
    || fail "BFF không phản hồi tại $BFF_URL — chạy: bash scripts/open-admin-uis.sh"
}

# crapi_login <user> <pass> [<user-agent>]  → in ra đường dẫn cookie-jar (stdout).
# Thực hiện đủ luồng Keycloak OIDC/PKCE qua BFF (/auth/start → login-actions →
# /auth/callback). Cookie-jar giữ session BFF (ztlab_bff_session).
crapi_login() {
  local user="$1" pass="$2" ua="${3:-$BROWSER_UA}"
  local jar; jar="$(mktemp /tmp/crapi_cj.XXXXXX)"
  local page action code
  page="$(curl -s -A "$ua" -c "$jar" -b "$jar" -L "$BFF_URL/auth/start")"
  action="$(printf '%s' "$page" | grep -oE 'action="[^"]+"' | head -1 | sed -E 's/^action="//; s/"$//; s/&amp;/\&/g')"
  [[ -n "$action" ]] || { rm -f "$jar"; fail "không lấy được form login Keycloak (BFF /auth/start)"; }
  code="$(curl -s -A "$ua" -c "$jar" -b "$jar" -L -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=$user" --data-urlencode "password=$pass" "$action")"
  [[ "$code" == "200" ]] || { rm -f "$jar"; fail "login $user thất bại (http $code)"; }
  printf '%s' "$jar"
}

# crapi_call <jar> <method> <path> [<data>] → in mã HTTP
crapi_call() {
  local jar="$1" method="$2" path="$3" data="${4:-}"
  if [[ -n "$data" ]]; then
    curl -s -A "$BROWSER_UA" -b "$jar" -X "$method" -H 'Content-Type: application/json' \
      -d "$data" -o /dev/null -w '%{http_code}' --max-time 25 "$BFF_URL$path"
  else
    curl -s -A "$BROWSER_UA" -b "$jar" -X "$method" -o /dev/null -w '%{http_code}' \
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
