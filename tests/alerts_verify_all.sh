#!/usr/bin/env bash
# Mục 3.4 (đóng sổ 2026-10-04) — kiểm SỐNG cả 9 alert rule của AUDIT-THUC-THI.md §6 trên cụm hiện tại.
# Mỗi rule: chạy kịch bản kích hoạt THẬT → chờ rule Firing (Grafana ruler API) → chờ evidence bundle MỚI
# (ts ≥ T0) khớp alert_name ở incident-analyzer → ghi 1 dòng bằng chứng. TUẦN TỰ, không chồng kịch bản.
#
#   bash tests/alerts_verify_all.sh            # cả 9
#   ONLY="BFLA|Large" bash tests/alerts_verify_all.sh
#
# Kích hoạt:
#   Lateral Movement      tests/crapi_lateral_movement.sh
#   Access Denied Spike   tests/crapi_access_denied.sh
#   Brute Force           tests/crapi_brute_force.sh
#   BFLA                  tests/crapi_bfla.sh
#   Large Response        tests/crapi_large_response.sh (kịch bản tự kiểm Firing+bundle)
#   Privilege Escalation  tests/crapi_privilege_escalation.sh (kịch bản tự kiểm Firing+bundle)
#   Mesh Integrity        1 kết nối plaintext thật vào cổng STRICT (uid 1337 của bff → crapi-workshop:8000)
#   Control-Plane Down    TIÊM LỖI phía bộ kiểm: 1 Job sao chép CronJob security-healthcheck (AWS) với OPA_URL
#                         trỏ cổng không tồn tại → status=critical thật trong log (OPA thật vẫn chạy —
#                         không tắt PDP vì PDP fail-closed sẽ chặn toàn hệ thống)
#   Incident Analyzer Health  tự Firing khi có evidence bundle trong 10 phút (kiểm sau các rule trên)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/crapi_common.sh"
_SC="alerts_verify_all"
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-closeout}/alerts"; mkdir -p "$OUT"
EV="$OUT/verify-all-$(date +%Y%m%d%H%M%S).log"
ONLY="${ONLY:-.}"
PASSN=0; FAILN=0

record() { echo "$*" | tee -a "$EV"; }

# check <rule-title-prefix> <evidence-alert-name-substring> <firing_timeout> <evidence_timeout>
check() {
  local rule="$1" ev_sub="$2" ft="${3:-300}" et="${4:-240}" fired ev=""
  fired="$(wait_rule_firing "$rule" "$ft")" || { record "ts=$(date -Is) rule=\"$rule\" RESULT=FAIL firing=timeout(${ft}s)"; FAILN=$((FAILN+1)); return 1; }
  [[ "${EVIDENCE_KIND:-bundle}" == bundle ]] && ev="$(for _ in $(seq 1 $((et/5))); do
        o="$(curl -s "$INCIDENT_ANALYZER_URL/evidence" | python3 -c '
import json,sys,datetime
sub,after=sys.argv[1],float(sys.argv[2])
for r in json.load(sys.stdin):
  ts=datetime.datetime.fromisoformat(r["ts"].replace("Z","+00:00")).timestamp()
  if ts>=after and sub in (r.get("alert_name") or ""):
    print(json.dumps({k:r.get(k) for k in ("evidence_id","ts","attack_type","alert_name","email_sent")},ensure_ascii=False)); break' "$ev_sub" "$T0" 2>/dev/null)"
        [[ -n "$o" ]] && { echo "$o"; break; }; sleep 5; done)"
  if [[ -z "$ev" && "${EVIDENCE_KIND:-bundle}" == mail ]]; then
    # rule category=infrastructure/health → receiver ztlab-infra-admin (chỉ email, KHÔNG qua
    # incident-analyzer): bằng chứng là email tới MailHog SOC (:8026) có Subject chứa tên rule.
    for _ in $(seq 1 $((et/5))); do
      ev="$(curl -s 'http://127.0.0.1:8026/api/v2/messages?limit=100' | python3 -c '
import json,sys,datetime
sub,after=sys.argv[1],float(sys.argv[2])
for m in json.load(sys.stdin).get("items",[]):
  ts=datetime.datetime.fromisoformat(m["Created"][:26].rstrip("Z")+"+00:00").timestamp() if m["Created"].endswith("Z") else datetime.datetime.fromisoformat(m["Created"]).timestamp()
  from email.header import decode_header, make_header
  subj=str(make_header(decode_header(" ".join(m["Content"]["Headers"].get("Subject",[""])))))  # tiêu đề MIME =?utf-8?...
  if ts>=after and sub in subj:
    print(json.dumps({"mail_id":m["ID"],"created":m["Created"],"subject":subj[:160]},ensure_ascii=False)); break' "$ev_sub" "$T0" 2>/dev/null)"
      [[ -n "$ev" ]] && break; sleep 5
    done
  fi
  if [[ -z "$ev" ]]; then
    record "ts=$(date -Is) rule=\"$rule\" RESULT=FAIL firing=[$fired] evidence=none(${et}s)"; FAILN=$((FAILN+1)); return 1
  fi
  record "ts=$(date -Is) rule=\"$rule\" RESULT=PASS T0=$T0 firing=[$fired] evidence=$ev"; PASSN=$((PASSN+1))
}

# wait_rule_quiet <prefix> <timeout>: chờ rule rời Firing trước khi kích lại (tránh đếm Firing cũ)
wait_rule_quiet() {
  local t0; t0=$(date +%s)
  while (( $(date +%s) - t0 < ${2:-600} )); do
    [[ "$(grafana_rule_state "$1")" != firing* ]] && return 0; sleep 15
  done
  return 1
}

run() { # <rule-prefix> <evidence-substring> <cmd...>
  local rule="$1" sub="$2"; shift 2
  [[ "$rule" =~ $ONLY ]] || return 0
  log "════ $rule"
  wait_rule_quiet "$rule" 600 || log "CẢNH BÁO: rule vẫn Firing từ trước sau 10 phút — chỉ chấp nhận bundle có ts ≥ T0"
  T0=$(date +%s)
  "$@" > "$OUT/trigger-$(echo "$rule" | tr -c 'A-Za-z0-9' '_' | cut -c1-40).log" 2>&1
  check "$rule" "$sub" 300 240
  sleep 30
}

crapi_preflight

trigger_mesh() {
  kubectl --context "$KUBE_AWS" -n crapi exec deploy/bff -c istio-proxy -- \
    curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://crapi-workshop.crapi.svc.cluster.local:8000/workshop/api/shop/products || true
}

trigger_control_plane() {
  local job="hc-faultinject-$(date +%s)"
  kubectl --context "$KUBE_AWS" -n spire create job "$job" --from=cronjob/security-healthcheck --dry-run=client -o json \
    | python3 -c '
import json,sys
j=json.load(sys.stdin)
for c in j["spec"]["template"]["spec"]["containers"]:
  for e in c.get("env",[]):
    if e["name"]=="OPA_URL": e["value"]="http://opa-service.crapi.svc.cluster.local:1/health"
j["metadata"].setdefault("labels",{})["ztlab-faultinject"]="true"
print(json.dumps(j))' | kubectl --context "$KUBE_AWS" apply -f -
  kubectl --context "$KUBE_AWS" -n spire wait --for=condition=complete "job/$job" --timeout=180s \
    || kubectl --context "$KUBE_AWS" -n spire wait --for=condition=failed "job/$job" --timeout=10s
  kubectl --context "$KUBE_AWS" -n spire logs "job/$job" | tail -3
  kubectl --context "$KUBE_AWS" -n spire delete job "$job" --wait=false
}

run "crAPI — Lateral Movement"    "Lateral Movement"    bash "$REPO_ROOT/tests/crapi_lateral_movement.sh"
run "crAPI — Access Denied Spike" "Access Denied"       bash "$REPO_ROOT/tests/crapi_access_denied.sh"
run "crAPI — Brute Force"         "Brute Force"         bash "$REPO_ROOT/tests/crapi_brute_force.sh"
run "crAPI — BFLA"                "BFLA"                bash "$REPO_ROOT/tests/crapi_bfla.sh"
run "crAPI — Data Exfiltration"   "Large Response"      bash "$REPO_ROOT/tests/crapi_large_response.sh"
run "Kịch bản 6 — Privilege Escalation" "Privilege Escalation" bash "$REPO_ROOT/tests/crapi_privilege_escalation.sh"
EVIDENCE_KIND=mail run "Mesh Integrity"              "Mesh Integrity"      trigger_mesh
EVIDENCE_KIND=mail run "Security Control-Plane Down" "Control-Plane"       trigger_control_plane
if [[ "Incident Analyzer" =~ $ONLY ]]; then
  log "════ Incident Analyzer — Health Check (tự Firing khi có bundle trong 10 phút)"
  T0=$(( $(date +%s) - 900 ))
  EVIDENCE_KIND=mail check "Incident Analyzer — Health Check" "Incident Analyzer" 180 240
fi
record "TỔNG: PASS=$PASSN FAIL=$FAILN  (log: $EV)"
[[ $FAILN -eq 0 ]]
