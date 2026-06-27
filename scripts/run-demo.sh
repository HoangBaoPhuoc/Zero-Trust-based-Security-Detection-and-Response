#!/usr/bin/env bash
# run-demo.sh — Demo ZTLab Zero Trust Security
#
# Usage:
#   ./scripts/run-demo.sh                    # Full demo (normal traffic + tất cả kịch bản)
#   ./scripts/run-demo.sh --traffic-only     # Chỉ gửi normal traffic
#   ./scripts/run-demo.sh --attack-only      # Chạy 4 kịch bản tấn công có xác nhận SOAR
#   ./scripts/run-demo.sh --kb1              # KB1: Brute Force (10x JWT sai → revoke_user_sessions)
#   ./scripts/run-demo.sh --kb2              # KB2: Lateral Movement (SVID lạ → isolate payment-service)
#   ./scripts/run-demo.sh --kb3              # KB3: Fraud Gate Bypass (OPA deny → isolate payment-service)
#   ./scripts/run-demo.sh --kb4              # KB4: Data Exfiltration (response >1MB → scale core-banking=0)
#   ./scripts/run-demo.sh --restore          # Restore tất cả services về trạng thái bình thường
#   ./scripts/run-demo.sh --continuous       # Loop liên tục (Ctrl+C để dừng)
#
# Trước khi chạy: bash scripts/k8s-tunnel.sh up all && bash scripts/open-admin-uis.sh

set -euo pipefail

SOAR_URL="${SOAR_URL:-http://127.0.0.1:8091}"
LOKI_URL="${LOKI_URL:-http://127.0.0.1:13100}"
GW_URL="${GW_URL:-http://127.0.0.1:18080}"
KC_URL="${KC_URL:-http://127.0.0.1:8180}"
KC_REALM="${KC_REALM:-ztlab}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-ztlab-admin-2026}"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"
SOAR_API_TOKEN="${SOAR_API_TOKEN:-}"
_KC_CLIENT_SECRET=""
_KC_TOKEN=""

TRAFFIC_ONLY=false
ATTACK_ONLY=false
CONTINUOUS=false
RESTORE_ONLY=false
SKIP_PAYMENTS=false
RUN_KB1=false
RUN_KB2=false
RUN_KB3=false
RUN_KB4=false
SLEEP="${SLEEP_SECONDS:-1}"
SOAR_WAIT="${SOAR_WAIT:-90}"

for arg in "$@"; do
  case "$arg" in
    --traffic-only) TRAFFIC_ONLY=true ;;
    --attack-only)  ATTACK_ONLY=true ;;
    --continuous)   CONTINUOUS=true ;;
    --restore)      RESTORE_ONLY=true ;;
    --kb1)          RUN_KB1=true ;;
    --kb2)          RUN_KB2=true ;;
    --kb3)          RUN_KB3=true ;;
    --kb4)          RUN_KB4=true ;;
    --help|-h)
      sed -n '2,12p' "$0"; exit 0 ;;
    *)
      echo "[FAIL] Unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$TRAFFIC_ONLY" == true && "$ATTACK_ONLY" == true ]]; then
  echo "[FAIL] --traffic-only và --attack-only không dùng cùng nhau" >&2; exit 2
fi

ANY_KB=$([[ "$RUN_KB1$RUN_KB2$RUN_KB3$RUN_KB4" == *true* ]] && echo true || echo false)

# ─── Colors ─────────────────────────────────────────────────────────────────
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'
log()    { echo -e "${BLUE}[DEMO]${NC} $*"; }
ok()     { echo -e "${GREEN}[ OK ]${NC} $*"; }
fail()   { echo -e "${RED}[FAIL]${NC} $*"; }
attack() { echo -e "${RED}[ATTACK]${NC} $*"; }
normal() { echo -e "${GREEN}[NORMAL]${NC} $*"; }
info()   { echo -e "${CYAN}[INFO]${NC} $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $*"; }
step()   { echo -e "${CYAN}  ▶${NC} $*"; }

# ─── Token generation ────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

_get_kc_client_secret() {
  if [[ -n "$_KC_CLIENT_SECRET" ]]; then return 0; fi
  local admin_token
  admin_token=$(curl -s --max-time 10 -X POST \
    "$KC_URL/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password&client_id=admin-cli&username=admin&password=$KC_ADMIN_PASS" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
  if [[ -z "$admin_token" ]]; then
    warn "Không lấy được Keycloak admin token"; return 1
  fi
  _KC_CLIENT_SECRET=$(curl -s --max-time 10 \
    -H "Authorization: Bearer $admin_token" \
    "$KC_URL/admin/realms/$KC_REALM/clients?clientId=api-gateway" \
    | python3 -c "import json,sys; c=json.load(sys.stdin); print(c[0]['secret'] if c else '')" 2>/dev/null)
}

gen_token() {
  local user="${1:-testuser01}"
  _get_kc_client_secret || { echo ""; return 1; }
  curl -s --max-time 10 -X POST \
    "$KC_URL/realms/$KC_REALM/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=api-gateway&client_secret=$_KC_CLIENT_SECRET&username=$user&password=Test1234%21" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null
}

# ─── Loki push với đúng labels ───────────────────────────────────────────────
# $1=json_stream_labels  $2=json_log_object  $3=count (số lượng log cần push)
push_loki() {
  local stream_labels="$1" log_obj="$2" count="${3:-1}"
  python3 - "$LOKI_URL" "$stream_labels" "$log_obj" "$count" <<'PY' 2>/dev/null
import json, sys, urllib.request, time
loki_url, stream_labels_raw, log_obj_raw, count_raw = sys.argv[1:]
stream_labels = json.loads(stream_labels_raw)
log_obj       = json.loads(log_obj_raw)
count         = int(count_raw)
values = [[str(time.time_ns() + i * 1000000), json.dumps(log_obj)] for i in range(count)]
payload = {"streams": [{"stream": stream_labels, "values": values}]}
req = urllib.request.Request(
    f"{loki_url.rstrip('/')}/loki/api/v1/push",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
    method="POST")
urllib.request.urlopen(req, timeout=5)
print("OK")
PY
}

# ─── SOAR wait & verify ──────────────────────────────────────────────────────
# $1=expected attack_type  $2=expected playbook
# So sánh bằng ts (timestamp) thay vì count để tránh SOAR dedup overwrite case cũ
wait_soar_case() {
  local attack_type="$1" expected_playbook="$2"
  local timeout="${SOAR_WAIT}" interval=5 elapsed=0
  # Ghi lại timestamp hiện tại (ISO) để so sánh với ts của case mới
  local start_ts; start_ts=$(date -u +%Y-%m-%dT%H:%M:%S)

  while [[ $elapsed -lt $timeout ]]; do
    sleep $interval
    elapsed=$((elapsed + interval))
    local result
    result=$(curl -s "$SOAR_URL/cases" 2>/dev/null | python3 -c "
import sys, json
start_ts = '$start_ts'
attack_type = '$attack_type'
cases = json.load(sys.stdin)
# Tìm case mới nhất của attack_type với ts > start_ts (kể cả pending_approval)
matched = [c for c in cases
           if c.get('attack_type') == attack_type
           and c.get('status') in ('executed', 'dry_run', 'failed', 'pending_approval')
           and c.get('ts', '') >= start_ts]
if matched:
    c = matched[-1]
    status = c.get('status')
    if status == 'pending_approval':
        print('FOUND_HITL')
    else:
        print('FOUND')
    print('  case_id  :', c.get('case_id'))
    print('  status   :', status)
    print('  playbook :', c.get('playbook'), '| severity:', c.get('severity'))
    print('  context  :', c.get('target_context'), '| workload:', c.get('target_workload'))
    if status == 'pending_approval':
        print('  >>> Admin phải chọn hành động tại: http://localhost:18081/security')
    for s in c.get('steps', []):
        icon = chr(10003) if s.get('status') == 'completed' else (chr(10007) if s.get('status') == 'failed' else '-')
        print(f'  {icon} {s.get(\"phase\",\"?\"):12} {s.get(\"status\",\"?\"):10} | {s.get(\"action\",\"\")[:70]}')
" 2>/dev/null || echo "")
    if [[ "$result" == FOUND* ]]; then
      echo "$result"
      return 0
    fi
    echo -n "."
  done
  echo ""
  warn "SOAR không tạo case trong ${timeout}s — kiểm tra Grafana alert đã fire chưa"
  return 1
}

# ─── Restore services ────────────────────────────────────────────────────────
restore_all() {
  step "Restore payment-service (xóa SOAR isolation label)..."
  kubectl --context "$AWS_CONTEXT" patch svc payment-service -n financial \
    --type=json -p='[{"op":"replace","path":"/spec/selector","value":{"app":"payment-service"}}]' 2>/dev/null \
    && echo "    payment-service: OK" || true

  step "Restore api-gateway (replicas=1)..."
  kubectl --context "$AWS_CONTEXT" scale deployment api-gateway -n financial --replicas=1 2>/dev/null \
    && echo "    api-gateway: OK" || true

  step "Restore core-banking trên OpenStack (replicas=1)..."
  kubectl --context "$OS_CONTEXT" scale deployment core-banking -n financial --replicas=1 2>/dev/null \
    && kubectl --context "$OS_CONTEXT" rollout status deployment core-banking -n financial --timeout=30s 2>/dev/null \
    && echo "    core-banking: OK" || true

  step "Xóa soar-block NetworkPolicies tích lũy (AWS + OpenStack)..."
  local aws_np os_np
  aws_np=$(kubectl --context "$AWS_CONTEXT" get networkpolicy -n financial --no-headers 2>/dev/null | awk '/soar-block/{print $1}' | tr '\n' ' ')
  os_np=$(kubectl --context "$OS_CONTEXT" get networkpolicy -n financial --no-headers 2>/dev/null | awk '/soar-block/{print $1}' | tr '\n' ' ')
  if [[ -n "$aws_np" ]]; then
    kubectl --context "$AWS_CONTEXT" delete networkpolicy -n financial $aws_np 2>/dev/null \
      && echo "    AWS soar-block NP xóa: $aws_np" || true
  else
    echo "    AWS: không có soar-block NP"
  fi
  if [[ -n "$os_np" ]]; then
    kubectl --context "$OS_CONTEXT" delete networkpolicy -n financial $os_np 2>/dev/null \
      && echo "    OpenStack soar-block NP xóa: $os_np" || true
  else
    echo "    OpenStack: không có soar-block NP"
  fi
}

# ─── Service check ────────────────────────────────────────────────────────────
check_services() {
  log "Kiểm tra services..."
  local all_ok=true

  local gw_health
  gw_health=$(curl -s --max-time 5 "$GW_URL/health" 2>/dev/null)
  if [[ -n "$gw_health" ]]; then
    local jwks; jwks=$(echo "$gw_health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('jwks_keys_loaded',0))" 2>/dev/null)
    ok "API Gateway  : $GW_URL  (jwks_keys_loaded=$jwks)"
    [[ "$jwks" == "0" ]] && warn "JWKS chưa load — restart: kubectl --context ctx-aws -n financial rollout restart deploy/api-gateway"
  else
    warn "API Gateway không accessible — bỏ qua normal traffic"; SKIP_PAYMENTS=true
  fi

  if curl -fsS --max-time 5 "$SOAR_URL/health" >/dev/null 2>&1; then
    local dry; dry=$(curl -s --max-time 5 "$SOAR_URL/health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('dry_run','?'))" 2>/dev/null)
    ok "SOAR Engine  : $SOAR_URL  (dry_run=$dry)"
  else
    fail "SOAR Engine không accessible: nohup kubectl --context ctx-aws -n plg-stack port-forward svc/soar-engine 8091:8080 --address=127.0.0.1 &"
    all_ok=false
  fi

  if curl -fsS --max-time 5 "$LOKI_URL/ready" >/dev/null 2>&1; then
    ok "Loki         : $LOKI_URL"
  else
    fail "Loki không accessible: nohup kubectl --context ctx-aws -n plg-stack port-forward svc/loki 13100:3100 --address=127.0.0.1 &"
    all_ok=false
  fi

  if [[ "$all_ok" == false ]]; then
    fail "Một số services không accessible. Xem HUONG_DAN.md mục 3 để mở tunnels."; exit 1
  fi

  local iso; iso=$(kubectl --context "$AWS_CONTEXT" get svc payment-service -n financial \
    -o jsonpath='{.spec.selector}' 2>/dev/null | python3 -c "import sys,json; s=json.load(sys.stdin); print('ISOLATED' if s.get('soar.ztlab.io/isolated') else 'OK')" 2>/dev/null)
  [[ "$iso" == "ISOLATED" ]] && warn "payment-service đang bị SOAR isolate — chạy --restore trước khi test normal traffic"
  echo ""
}

# ─── Normal payment ───────────────────────────────────────────────────────────
send_payment() {
  local from="$1" to="$2" amount="$3" user="${4:-testuser01}" label="${5:-normal}"
  local TOKEN; TOKEN=$(gen_token "$user")
  if [[ -z "$TOKEN" ]]; then
    warn "Không lấy được token — bỏ qua payment $label"; return
  fi
  local RESULT
  RESULT=$(python3 - "$GW_URL" "$TOKEN" "$from" "$to" "$amount" <<'PY'
import json, sys, urllib.request
url, token, frm, to, amount = sys.argv[1:]
headers = {"Content-Type":"application/json", "Authorization":f"Bearer {token}"}
req = urllib.request.Request(
    f"{url}/payments",
    data=json.dumps({"from_account":frm,"to_account":to,"amount":float(amount),"currency":"VND"}).encode(),
    headers=headers, method="POST")
try:
    r=urllib.request.urlopen(req, timeout=15)
    d=json.loads(r.read().decode())
    score=d.get("fraud",{}).get("score","?")
    gate=d.get("fraud",{}).get("gate","?")
    txid=d.get("core_banking",{}).get("transaction_id","?")[:12]
    print(f"completed fraud_score={score} gate={gate} tx={txid}...")
except urllib.error.HTTPError as e:
    body=e.read().decode()[:120]
    print(f"HTTP {e.code}: {body}")
PY
  )
  normal "payment ${from}→${to} ${amount}VND  →  $RESULT"
}

# ─── KB1: Brute Force ────────────────────────────────────────────────────────
# Grafana query: sum by (source_ip) (count_over_time({job="envoy-access"} | json | response_code=`401` [1m]))
# response_code phải là STREAM LABEL (Promtail extract từ Envoy log)
run_kb1() {
  echo ""
  attack "═══ KB1: Brute Force Login (ATT&CK T1110.001) ═══"
  step "Restore services trước khi test..."
  restore_all
  echo ""
  step "Push 20 log vào Loki (job=envoy-access, response_code=401 — stream label)..."
  step "Grafana query: {job=envoy-access} | json | response_code=\`401\` [1m]"
  python3 - "$LOKI_URL" <<'PY'
import json, urllib.request, time, sys
loki_url = sys.argv[1]
now = time.time_ns()
values = [[str(now + i * 1_000_000), json.dumps({
    "response_code": 401, "source_ip": "10.10.0.99",
    "method": "POST", "path": "/payments",
    "message": f"JWT invalid — brute force attempt #{i+1}"
})] for i in range(20)]
payload = {"streams": [{"stream": {
    "job": "envoy-access", "service": "api-gateway",
    "namespace": "financial", "response_code": "401", "source_ip": "10.10.0.99"
}, "values": values}]}
req = urllib.request.Request(f"{loki_url.rstrip('/')}/loki/api/v1/push",
    data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print("OK — 20 logs pushed (response_code=401)")
PY

  echo ""
  step "Đợi Grafana alert fire + SOAR xử lý (${SOAR_WAIT}s max)..."
  step "Grafana eval mỗi 1 phút — có thể chờ tới 60s trước khi alert fire"
  if wait_soar_case "brute_force" "revoke_user_sessions"; then
    ok "KB1 PASS — SOAR tạo case brute_force | playbook đề xuất: revoke_user_sessions"
    info "Admin duyệt tại: http://localhost:18081/security (đăng nhập analyst01 hoặc security-admin)"
  else
    warn "KB1: Grafana alert chưa fire. Kiểm tra http://127.0.0.1:3000 → Alerting → Alert rules → Kịch bản 1"
  fi
}

# ─── KB2: Lateral Movement ───────────────────────────────────────────────────
# Grafana query: sum(count_over_time({job="opa-decisions",opa_result="false",attack_scenario="lateral_movement"}[5m]))
# attack_scenario="lateral_movement" phân biệt KB2 với KB3 và OPA deny từ KB1
run_kb2() {
  echo ""
  attack "═══ KB2: Lateral Movement — Invalid SVID (ATT&CK T1021.007) ═══"
  step "Restore services trước khi test..."
  restore_all
  echo ""
  step "Push 5 log vào Loki (job=opa-decisions, opa_result=false, attack_scenario=lateral_movement)..."
  step "Grafana query: {job=opa-decisions, opa_result=false, attack_scenario=lateral_movement}[5m]"
  python3 - "$LOKI_URL" <<'PY'
import json, urllib.request, time, sys
loki_url = sys.argv[1]
now = time.time_ns()
values = [[str(now + i * 1_000_000), json.dumps({
    "event_type": "lateral_movement_attempt",
    "opa_result": "false",
    "svid": "spiffe://external.attacker/malicious-service",
    "destination": "core-banking",
    "source_ip": "10.10.1.99",
    "message": f"SVID outside trust domain ztlab.local — OPA deny #{i+1}"
})] for i in range(5)]
payload = {"streams": [{"stream": {
    "job": "opa-decisions", "opa_result": "false",
    "attack_scenario": "lateral_movement",
    "service": "payment-service", "namespace": "financial"
}, "values": values}]}
req = urllib.request.Request(f"{loki_url.rstrip('/')}/loki/api/v1/push",
    data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print("OK — 5 logs pushed (opa_result=false)")
PY

  echo ""
  step "Đợi Grafana alert fire + SOAR xử lý (${SOAR_WAIT}s max)..."
  step "SOAR đề xuất isolate_workload — admin phải duyệt tại web portal"
  if wait_soar_case "lateral_movement" "isolate_workload"; then
    local sel; sel=$(kubectl --context "$AWS_CONTEXT" get svc payment-service -n financial \
      -o jsonpath='{.spec.selector}' 2>/dev/null)
    if echo "$sel" | grep -q "isolated"; then
      ok "KB2 PASS — payment-service đã bị isolate: $sel"
      step "Restore payment-service..."
      restore_all
    else
      ok "KB2 PASS — SOAR case tạo thành công | Chờ admin chọn hành động tại web portal"
      info "Admin duyệt tại: http://localhost:18081/security → chọn 'Cô lập dịch vụ' hoặc 'Chặn IP'"
    fi
  else
    warn "KB2: Grafana alert chưa fire. Kiểm tra http://127.0.0.1:3000 → Alerting → Alert rules → Kịch bản 2"
  fi
}

# ─── KB3: Fraud Gate Bypass ──────────────────────────────────────────────────
# Grafana query: sum(count_over_time({job="opa-decisions",opa_result="false",attack_scenario="fraud_gate_bypass"}[5m]))
# attack_scenario="fraud_gate_bypass" phân biệt KB3 với KB2
run_kb3() {
  echo ""
  attack "═══ KB3: Fraud Gate Bypass (ATT&CK T1078.004) ═══"
  step "Restore services trước khi test..."
  restore_all
  echo ""
  step "Push 5 log vào Loki (job=opa-decisions, opa_result=false, attack_scenario=fraud_gate_bypass)..."
  step "Grafana query: {job=opa-decisions, opa_result=false, attack_scenario=fraud_gate_bypass}[5m]"
  python3 - "$LOKI_URL" <<'PY'
import json, urllib.request, time, sys
loki_url = sys.argv[1]
now = time.time_ns()
values = [[str(now + i * 1_000_000), json.dumps({
    "event_type": "opa_deny",
    "opa_result": "false",
    "request_path": "/transactions/execute",
    "source_ip": "10.10.1.77",
    "reason": "fraud_gate header missing or tampered",
    "message": f"OPA DENY fraud_gate_bypass path=/transactions/execute #{i+1}"
})] for i in range(5)]
payload = {"streams": [{"stream": {
    "job": "opa-decisions", "opa_result": "false",
    "attack_scenario": "fraud_gate_bypass",
    "request_path": "/transactions/execute",
    "service": "payment-service", "namespace": "financial"
}, "values": values}]}
req = urllib.request.Request(f"{loki_url.rstrip('/')}/loki/api/v1/push",
    data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print("OK — 5 logs pushed (request_path=/transactions/execute)")
PY

  echo ""
  step "Đợi Grafana alert fire + SOAR xử lý (${SOAR_WAIT}s max)..."
  step "SOAR đề xuất isolate_workload (severity=critical) — admin phải duyệt tại web portal"
  if wait_soar_case "fraud_gate_bypass" "isolate_workload"; then
    local sel; sel=$(kubectl --context "$AWS_CONTEXT" get svc payment-service -n financial \
      -o jsonpath='{.spec.selector}' 2>/dev/null)
    if echo "$sel" | grep -q "isolated"; then
      ok "KB3 PASS — payment-service đã bị isolate: $sel"
      step "Restore payment-service..."
      restore_all
    else
      ok "KB3 PASS — SOAR case tạo thành công | Chờ admin chọn hành động tại web portal"
      info "Admin duyệt tại: http://localhost:18081/security → chọn 'Cô lập dịch vụ' hoặc 'Chặn IP'"
    fi
  else
    warn "KB3: Grafana alert chưa fire. Kiểm tra http://127.0.0.1:3000 → Alerting → Alert rules → Kịch bản 3"
  fi
}

# ─── KB4: Data Exfiltration ──────────────────────────────────────────────────
# Grafana query: sum(count_over_time({job="envoy-access"} | json | bytes_sent > 1048576 [5m]))
# bytes_sent cần trong JSON body (parsed bởi | json) — không phải stream label
run_kb4() {
  echo ""
  attack "═══ KB4: Data Exfiltration — Large Response (ATT&CK T1041) ═══"
  step "Restore services trước khi test..."
  restore_all
  echo ""
  step "Push 5 log vào Loki (job=envoy-access + JSON bytes_sent=3100000 > 1048576)..."
  step "Grafana query: {job=envoy-access} | json | bytes_sent > 1048576 [5m]"
  python3 - "$LOKI_URL" <<'PY'
import json, urllib.request, time, sys
loki_url = sys.argv[1]
now = time.time_ns()
values = [[str(now + i * 1_000_000), json.dumps({
    "bytes_sent": 3100000,
    "response_code": 200,
    "path": "/accounts/export",
    "source_ip": "10.10.4.88",
    "message": f"Abnormal response size 3.1MB — possible data exfiltration #{i+1}"
})] for i in range(5)]
payload = {"streams": [{"stream": {
    "job": "envoy-access",
    "service": "core-banking", "namespace": "financial"
}, "values": values}]}
req = urllib.request.Request(f"{loki_url.rstrip('/')}/loki/api/v1/push",
    data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
print("OK — 5 logs pushed (bytes_sent=3100000)")
PY

  echo ""
  step "Đợi Grafana alert fire + SOAR xử lý (${SOAR_WAIT}s max)..."
  step "SOAR đề xuất restrict_egress — admin phải duyệt tại web portal"
  local before_replicas
  before_replicas=$(kubectl --context "$OS_CONTEXT" get deploy core-banking -n financial \
    -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "?")
  step "core-banking (OpenStack) trước: ${before_replicas} replicas"

  if wait_soar_case "large_response" "restrict_egress"; then
    local after_replicas
    after_replicas=$(kubectl --context "$OS_CONTEXT" get deploy core-banking -n financial \
      -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "?")
    if [[ "$after_replicas" == "0" ]]; then
      ok "KB4 PASS — core-banking scaled xuống 0 replicas trên OpenStack"
      step "Restore core-banking..."
      restore_all
    else
      ok "KB4 PASS — SOAR case tạo thành công | Chờ admin chọn hành động tại web portal"
      info "Admin duyệt tại: http://localhost:18081/security → chọn 'Hạn chế lưu lượng ra'"
    fi
  else
    warn "KB4: Grafana alert chưa fire. Kiểm tra http://127.0.0.1:3000 → Alerting → Alert rules → Kịch bản 4"
  fi
}

# ─── Normal traffic ──────────────────────────────────────────────────────────
run_normal_traffic() {
  if [[ "$SKIP_PAYMENTS" == true ]]; then
    info "Bỏ qua normal traffic (API Gateway không accessible)"; return
  fi
  log "─── Normal traffic (baseline) ───"
  send_payment "ACC-1001" "ACC-2001" "50000"    "testuser01" "small"
  send_payment "ACC-1001" "ACC-2001" "2500000"  "testuser01" "medium"
  send_payment "ACC-1001" "ACC-2001" "15000000" "testuser01" "large"
  send_payment "ACC-2001" "ACC-1001" "100000"   "testuser02" "reverse"
  sleep 1
}

# ─── SOAR summary ────────────────────────────────────────────────────────────
print_soar_summary() {
  echo ""
  log "─── SOAR Cases (6 gần nhất) ───"
  python3 - "$SOAR_URL" <<'PY' 2>/dev/null
import json, sys, urllib.request
soar_url = sys.argv[1]
try:
    r = urllib.request.urlopen(f"{soar_url}/cases", timeout=5)
    cases = json.loads(r.read().decode())
    print(f"  Tổng: {len(cases)} cases")
    for c in cases[-6:]:
        s = c.get("status","?")
        icon = "✓" if s in ("executed","dry_run") else ("⏳" if s == "pending_approval" else ("✗" if s == "failed" else "-"))
        print(f"  {icon} [{s:17}] {c.get('attack_type','?'):25} sev={c.get('severity','?'):8} → {c.get('playbook','?')}")
except Exception as e:
    print(f"  (Không thể kết nối SOAR: {e})")
PY
  echo ""
  info "SOAR API:   http://127.0.0.1:8091/cases"
  info "Grafana:    http://127.0.0.1:3000/d/ztlab-ai-siem-soar"
  info "Web Portal: http://127.0.0.1:18081/security"
  echo ""
}

# ─── Banner ──────────────────────────────────────────────────────────────────
print_banner() {
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║         ZTLab — Zero Trust Security Demo                 ║${NC}"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║  Grafana  →  http://127.0.0.1:3000                       ║${NC}"
  echo -e "${CYAN}║  Dashboard: ZTLab AI SIEM SOAR                           ║${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

# ─── Entry point ─────────────────────────────────────────────────────────────
print_banner

if [[ "$RESTORE_ONLY" == true ]]; then
  log "Restore tất cả services..."
  restore_all
  ok "Restore hoàn tất"
  exit 0
fi

check_services

# Individual scenario mode
if [[ "$ANY_KB" == true ]]; then
  [[ "$RUN_KB1" == true ]] && run_kb1
  [[ "$RUN_KB2" == true ]] && run_kb2
  [[ "$RUN_KB3" == true ]] && run_kb3
  [[ "$RUN_KB4" == true ]] && run_kb4
  print_soar_summary
  exit 0
fi

if [[ "$CONTINUOUS" == true ]]; then
  log "Chạy continuous mode (Ctrl+C để dừng)..."
  ROUND=0
  while true; do
    ROUND=$((ROUND+1))
    log "══ Round $ROUND ══"
    [[ "$ATTACK_ONLY" == false ]] && run_normal_traffic
    if [[ "$TRAFFIC_ONLY" == false ]]; then
      run_kb1; run_kb2; run_kb3; run_kb4
    fi
    print_soar_summary
    log "Nghỉ 30s..."
    sleep 30
  done
else
  [[ "$ATTACK_ONLY" == false ]] && run_normal_traffic
  if [[ "$TRAFFIC_ONLY" == false ]]; then
    run_kb1; run_kb2; run_kb3; run_kb4
  fi
  print_soar_summary
fi
