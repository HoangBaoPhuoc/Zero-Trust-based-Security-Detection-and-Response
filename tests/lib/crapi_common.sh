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

# Phần 1.3 (remediation 2026-09): điểm vào crAPI nay là Istio IngressGateway
# biên với client-cert mTLS bắt buộc (k8s/crapi/edge-gateway.yaml) — không
# còn Traefik/cổng HTTP trần. Tunnel BFF_URL trỏ thẳng
# svc/istio-ingressgateway (xem scripts/open-admin-uis.sh "crAPI (Gateway
# mTLS)"), --resolve để SNI/Host khớp Host(`crapi.ztlab.local`) dù cổng cục
# bộ khác nhau.
CRAPI_HOST="${CRAPI_HOST:-crapi.ztlab.local}"
BFF_URL="${BFF_URL:-https://$CRAPI_HOST:18444}"
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
  # Vòng 2026-09-29: trước chỉ kiểm file TỒN TẠI → cert fixture (TTL 7 ngày,
  # issue-device-cert.sh) hết hạn 2026-09-26 mà không ai phát hành lại; mọi
  # kịch bản chết ở Gateway với TLS alert "certificate expired" (curl 000).
  # Nay phát hành lại khi thiếu HOẶC còn < 24 giờ — đợt thu 150 giờ (Giai
  # đoạn B) dài gần bằng TTL nên việc này phải tự động.
  local crt="$CA_DIR/issued/$device_id/device.crt"
  [[ -f "$crt" ]] && openssl x509 -in "$crt" -noout -checkend 86400 >/dev/null 2>&1 && return 0
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

# preflight: Device CA fixtures + BFF reachable qua Istio Gateway mTLS
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

# ── Giai đoạn B §B1: THỰC THI nhịp độ (không chỉ ghi nhãn) ───────────────────
# Orchestrator crapi_campaign_phaseb.sh đặt (từ policy/variant-split.yaml):
#   PACE=burst|slow_drip ; DURATION_MIN = tổng phút rải cho slow_drip (mặc 30).
# crapi_pace_sleep <index> <total_N>: nghỉ TRƯỚC request kế.
#   burst     → 0–0.3s  (khoảng cách giữa request < 1s)
#   slow_drip → ~ DURATION_MIN*60/N mỗi request, jitter ±50% → tổng ≈ DURATION_MIN
#               phút, khoảng cách hàng chục giây tới vài phút CÓ phương sai (không
#               đều tăm tắp). Tối thiểu 1s để chắc chắn khác burst.
# Đây là phần THỰC THI mà nghiệm thu §B1 đo lại từ timestamp Loki (hai phân phối
# khoảng cách phải khác nhau rõ rệt) — nếu chỉ ghi nhãn, biến thể giữ riêng
# KHÔNG tồn tại thật (cùng hình dạng H18).
crapi_pace_sleep() {
  local idx="${1:-0}" n="${2:-10}"
  case "${PACE:-burst}" in
    slow_drip)
      sleep "$(python3 -c "import random
dur=float(${DURATION_MIN:-30})*60.0; n=max(1,int(${n})); base=dur/n
print(round(max(1.0, random.uniform(0.5*base, 1.5*base)),2))")" ;;
    *)
      sleep "$(python3 -c "import random;print(round(random.uniform(0.0,0.3),2))")" ;;
  esac
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

# loki_count '<logql>' [start_epoch_s] [end_epoch_s]
#   Không truyền start/end: cửa sổ TRƯỢT 10 phút gần nhất tính từ "now" — chỉ
#   dùng cho log THAM KHẢO (không gate pass/fail), vì kết quả phụ thuộc thời
#   điểm gọi và có thể ăn log của lần chạy trước/sau khi gọi script lặp lại
#   nhanh (Phần 1.1 remediation 2026-09: đây là nguyên nhân gốc khiến
#   crapi_bola.sh báo FAIL=4 giả — số CRS-hit không liên quan gì tới BOLA bị
#   tính vào vì rơi trong cùng cửa sổ 10 phút của một lần gọi debug trước đó).
#   Có start/end (epoch giây, TƯỜNG MINH — dùng mốc bắt đầu/kết thúc thật của
#   chính lần chạy, kiểu T_START/T_END của crapi_run_campaign.sh A5.2): khoảng
#   thời gian TẤT ĐỊNH, không phụ thuộc "now" → dùng cho MỌI phép đo gate
#   pass/fail (vd crapi_bola.sh, crapi_sqli_waf.sh).
loki_count() {
  local q="$1" start_s end_s dur start end
  if [[ $# -ge 3 ]]; then
    start_s="$2"; end_s="$3"
  else
    end_s="$(date +%s)"; start_s="$(( end_s - 600 ))"
  fi
  dur=$(( end_s - start_s )); [[ $dur -lt 1 ]] && dur=1
  # Mục 11 vòng 2026-09-29 — bản cũ dùng query_range(start,end,step=dur) rồi lấy
  # r[0].values[-1]: (1) Loki CĂN điểm đánh giá theo bội số của step (cửa sổ thật
  # bị lệch khỏi [T0,T1], vd (152,160] thay vì (148,156]); (2) không sum() nên chỉ
  # đếm SERIES ĐẦU TIÊN. Hệ quả đo được: "transaction total" = 2 dù có 3 dòng, và
  # attack-lfi/rce 1↔0 giữa các lần chạy. Instant query tại end với
  # sum(count_over_time(...[dur])) đếm đúng (end-dur, end] trên mọi series.
  curl -s --max-time 8 -G "$LOKI_URL/loki/api/v1/query" \
    --data-urlencode "query=sum(count_over_time(($q)[${dur}s]))" \
    --data-urlencode "time=${end_s}000000000" 2>/dev/null \
    | python3 -c "import json,sys
try:
    d=json.load(sys.stdin); r=d['data']['result']
    print(int(float(r[0]['value'][1])) if r else 0)
except Exception:
    print(0)"
}

# pod nghiệp vụ đầu tiên của một app trong ns crapi (cluster AWS mặc định)
crapi_pod() {
  local app="$1" ctx="${2:-$KUBE_AWS}"
  kubectl --context "$ctx" -n "$NS" get pod -l "app=$app" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# ── Vòng 2026-09-29: bằng chứng Firing THẬT cho một rule Grafana ────────────────
# (dùng cho crapi_large_response.sh, crapi_privilege_escalation.sh và
# tests/collect_metrics.py --runs). Cần port-forward Grafana :3000 + incident-analyzer :8091.
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
INCIDENT_ANALYZER_URL="${INCIDENT_ANALYZER_URL:-http://localhost:8091}"
_grafana_pass() { kubectl --context "$KUBE_AWS" -n plg-stack get secret grafana-admin-secret \
                    -o jsonpath='{.data.admin-password}' | base64 -d; }

# grafana_rule_state <title-prefix> → inactive|pending|firing|missing (+ activeAt nếu có)
grafana_rule_state() {
  curl -s -u "admin:$(_grafana_pass)" "$GRAFANA_URL/api/prometheus/grafana/api/v1/rules" | python3 -c '
import json,sys
pre=sys.argv[1]
for g in json.load(sys.stdin)["data"]["groups"]:
  for r in g["rules"]:
    if r["name"].startswith(pre):
      at=[a.get("activeAt","") for a in r.get("alerts",[]) if a.get("state","").lower().startswith("alert")]
      print(r["state"], (at or [""])[0]); sys.exit()
print("missing")' "$1"
}

# wait_rule_firing <title-prefix> <timeout_s> → in "firing <activeAt> <giây chờ>" hoặc "timeout"
wait_rule_firing() {
  local pre="$1" to="$2" t0 st; t0=$(date +%s)
  while (( $(date +%s) - t0 < to )); do
    st="$(grafana_rule_state "$pre")"
    [[ "$st" == firing* ]] && { echo "$st $(( $(date +%s) - t0 ))"; return 0; }
    sleep 5
  done
  echo "timeout"; return 1
}

# wait_evidence <attack_type> <after_epoch> <timeout_s> → in JSON evidence bundle đầu tiên khớp
wait_evidence() {
  local at="$1" after="$2" to="$3" t0 out; t0=$(date +%s)
  while (( $(date +%s) - t0 < to )); do
    out="$(curl -s "$INCIDENT_ANALYZER_URL/evidence" | python3 -c '
import json,sys,datetime
at,after=sys.argv[1],float(sys.argv[2])
for r in json.load(sys.stdin):
  ts=datetime.datetime.fromisoformat(r["ts"].replace("Z","+00:00")).timestamp()
  if ts>=after and at in r.get("attack_type",""):
    print(json.dumps({k:r.get(k) for k in ("evidence_id","ts","attack_type","alert_name","email_sent")},ensure_ascii=False)); break' "$at" "$after" 2>/dev/null)"
    [[ -n "$out" ]] && { echo "$out"; return 0; }
    sleep 5
  done
  return 1
}
