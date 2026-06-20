#!/usr/bin/env bash
# run-demo.sh — Chạy toàn bộ demo ZTLab với traffic + attack scenarios
#
# Usage:
#   ./scripts/run-demo.sh                    # Full demo (normal traffic + attacks)
#   ./scripts/run-demo.sh --traffic-only     # Chỉ gửi normal traffic
#   ./scripts/run-demo.sh --attack-only      # Chỉ chạy attack scenarios
#   ./scripts/run-demo.sh --brute-force      # Demo brute force (10 lần 401)
#   ./scripts/run-demo.sh --continuous       # Loop liên tục (Ctrl+C để dừng)
#
# Trước khi chạy: phải mở tunnel (xem HUONG_DAN.md mục 3)

set -euo pipefail

AI_URL="${AI_URL:-http://127.0.0.1:8090}"
SOAR_URL="${SOAR_URL:-http://127.0.0.1:8091}"
LOKI_URL="${LOKI_URL:-http://127.0.0.1:13100}"
GW_URL="${GW_URL:-http://127.0.0.1:18080}"
KC_URL="${KC_URL:-http://127.0.0.1:8180}"
KC_REALM="${KC_REALM:-ztlab}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-ztlab-admin-2026}"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
SOAR_API_TOKEN="${SOAR_API_TOKEN:-}"
_KC_CLIENT_SECRET=""
_KC_TOKEN=""

TRAFFIC_ONLY=false
ATTACK_ONLY=false
BRUTE_FORCE=false
CONTINUOUS=false
SKIP_PAYMENTS=false
SLEEP="${SLEEP_SECONDS:-1}"

for arg in "$@"; do
  case "$arg" in
    --traffic-only) TRAFFIC_ONLY=true ;;
    --attack-only)  ATTACK_ONLY=true ;;
    --brute-force)  BRUTE_FORCE=true ;;
    --continuous)   CONTINUOUS=true ;;
    --help-tunnels) ;;
    --help|-h)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "[FAIL] Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

if [[ "$TRAFFIC_ONLY" == true && "$ATTACK_ONLY" == true ]]; then
  echo "[FAIL] --traffic-only and --attack-only cannot be used together" >&2
  exit 2
fi

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'
log()     { echo -e "${BLUE}[DEMO]${NC} $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC} $*"; }
attack()  { echo -e "${RED}[ATTACK]${NC} $*"; }
normal()  { echo -e "${GREEN}[NORMAL]${NC} $*"; }
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }

# ─── Token generation (Keycloak RS256 via ROPC) ───────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

_get_kc_client_secret() {
  if [[ -n "$_KC_CLIENT_SECRET" ]]; then return 0; fi
  local admin_token
  admin_token=$(curl -s --max-time 10 -X POST \
    "$KC_URL/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password&client_id=admin-cli&username=admin&password=$KC_ADMIN_PASS" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
  if [[ -z "$admin_token" ]]; then
    echo "[WARN] Không lấy được Keycloak admin token — kiểm tra port-forward 8180" >&2
    return 1
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
    -d "grant_type=password&client_id=api-gateway&client_secret=$_KC_CLIENT_SECRET&username=$user&password=Test1234!" \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null
}

# ─── Service check ────────────────────────────────────────────────────────────
check_services() {
  log "Kiểm tra services..."
  local ok=true

  if curl -fsS --max-time 5 "$GW_URL/health" >/dev/null 2>&1; then
    local jwks
    jwks=$(curl -s --max-time 5 "$GW_URL/health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('jwks_keys_loaded',0))" 2>/dev/null)
    ok "API Gateway  : $GW_URL  (jwks_keys_loaded=$jwks)"
    if [[ "$jwks" == "0" ]]; then
      echo -e "${YELLOW}[WARN]${NC} JWKS chưa load — restart api-gateway: kubectl --context ctx-aws -n financial rollout restart deploy/api-gateway"
    fi
  else
    # Fallback: auto port-forward
    if command -v kubectl >/dev/null 2>&1 && kubectl --context "$AWS_CONTEXT" get svc api-gateway -n financial >/dev/null 2>&1; then
      echo -e "${YELLOW}[WARN]${NC} Tự mở port-forward api-gateway:18080..."
      nohup kubectl --context "$AWS_CONTEXT" port-forward -n financial svc/api-gateway 18080:8080 --address=127.0.0.1 >/tmp/pf-gw.log 2>&1 &
      sleep 3
      if curl -fsS --max-time 3 "$GW_URL/health" >/dev/null 2>&1; then
        ok "API Gateway  : $GW_URL (via kubectl port-forward)"
      else
        echo -e "${YELLOW}[WARN]${NC} API Gateway không accessible — bỏ qua normal traffic test"
        SKIP_PAYMENTS=true
      fi
    else
      echo -e "${YELLOW}[WARN]${NC} API Gateway không accessible — bỏ qua normal traffic test"
      SKIP_PAYMENTS=true
    fi
  fi

  if curl -fsS --max-time 5 "$AI_URL/health" >/dev/null 2>&1; then
    PROVIDER=$(curl -s --max-time 5 "$AI_URL/health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('provider','?'))" 2>/dev/null)
    ok "AI Analyzer  : $AI_URL  (provider=$PROVIDER)"
  else
    echo -e "${YELLOW}[WARN]${NC} AI Analyzer không accessible:"
    echo "       nohup kubectl --context ctx-aws -n plg-stack port-forward svc/ai-analyzer 8090:8080 --address=127.0.0.1 &"
    ok=false
  fi

  if curl -fsS --max-time 5 "$SOAR_URL/health" >/dev/null 2>&1; then
    DRY=$(curl -s --max-time 5 "$SOAR_URL/health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('dry_run','?'))" 2>/dev/null)
    ok "SOAR Engine  : $SOAR_URL  (dry_run=$DRY)"
  else
    echo -e "${YELLOW}[WARN]${NC} SOAR Engine không accessible:"
    echo "       nohup kubectl --context ctx-aws -n plg-stack port-forward svc/soar-engine 8091:8080 --address=127.0.0.1 &"
    ok=false
  fi

  if curl -fsS --max-time 5 "$LOKI_URL/ready" >/dev/null 2>&1; then
    ok "Loki         : $LOKI_URL"
  else
    echo -e "${YELLOW}[WARN]${NC} Loki không accessible:"
    echo "       nohup kubectl --context ctx-aws -n plg-stack port-forward svc/loki 13100:3100 --address=127.0.0.1 &"
    ok=false
  fi

  if [[ "$ok" == false ]]; then
    echo ""
    echo -e "${RED}[FAIL]${NC} Một số services không accessible. Chạy lệnh này để xem hướng dẫn tunnel:"
    echo -e "${YELLOW}bash $REPO_ROOT/scripts/run-demo.sh --help-tunnels${NC}"
    echo ""
    exit 1
  fi
  echo ""
}

help_tunnels() {
  echo "Xem HUONG_DAN.md mục 3 để biết đầy đủ. Tóm tắt nhanh:"
  echo ""
  echo "Bước 1 — K8s tunnel (dùng script):"
  echo -e "  ${YELLOW}bash scripts/k8s-tunnel.sh up all${NC}"
  echo ""
  echo "Bước 2 — Port-forwards (copy & paste):"
  echo -e "  ${YELLOW}nohup kubectl --context ctx-aws -n identity port-forward svc/keycloak 8180:8080 --address=127.0.0.1 >/tmp/pf-kc.log 2>&1 &${NC}"
  echo -e "  ${YELLOW}nohup kubectl --context ctx-aws -n financial port-forward svc/api-gateway 18080:8080 --address=127.0.0.1 >/tmp/pf-gw.log 2>&1 &${NC}"
  echo -e "  ${YELLOW}nohup kubectl --context ctx-aws -n plg-stack port-forward svc/loki 13100:3100 --address=127.0.0.1 >/tmp/pf-loki.log 2>&1 &${NC}"
  echo -e "  ${YELLOW}nohup kubectl --context ctx-aws -n plg-stack port-forward svc/soar-engine 8091:8080 --address=127.0.0.1 >/tmp/pf-soar.log 2>&1 &${NC}"
  echo -e "  ${YELLOW}nohup kubectl --context ctx-aws -n plg-stack port-forward svc/ai-analyzer 8090:8080 --address=127.0.0.1 >/tmp/pf-ai.log 2>&1 &${NC}"
  echo -e "  ${YELLOW}nohup kubectl --context ctx-aws -n plg-stack port-forward svc/grafana 3000:3000 --address=127.0.0.1 >/tmp/pf-grafana.log 2>&1 &${NC}"
  exit 0
}

[[ "${1:-}" == "--help-tunnels" ]] && help_tunnels

# ─── Normal payment ───────────────────────────────────────────────────────────
send_payment() {
  local from="$1" to="$2" amount="$3" user="${4:-testuser01}" label="${5:-normal}"
  local TOKEN
  TOKEN=$(gen_token "$user")
  if [[ -z "$TOKEN" ]]; then
    echo -e "${YELLOW}[WARN]${NC} Không lấy được token Keycloak — bỏ qua payment $label"
    return
  fi
  local RESULT
  RESULT=$(python3 - "$GW_URL" "$TOKEN" "$from" "$to" "$amount" <<'PY'
import json, sys, urllib.request
url, token, frm, to, amount = sys.argv[1:]
headers = {"Content-Type":"application/json", "Authorization":f"Bearer {token}"}
req = urllib.request.Request(
    f"{url}/payments",
    data=json.dumps({"from_account":frm,"to_account":to,"amount":float(amount),"currency":"VND"}).encode(),
    headers=headers,
    method="POST")
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

# ─── Attack scenarios ─────────────────────────────────────────────────────────
push_loki_log() {
  local scenario="$1" severity="$2" message="$3"
  local now_ns
  now_ns="$(date +%s%N)"
  python3 - "$LOKI_URL" "$scenario" "$severity" "$message" "$now_ns" <<'PY' 2>/dev/null
import json, sys, urllib.request
loki_url, scenario, severity, message, now_ns = sys.argv[1:]
payload = {"streams":[{"stream":{"job":"demo-raw","service":"ztlab-demo","scenario":scenario,"severity":severity},"values":[[now_ns,json.dumps({"event_type":"demo_raw_log","scenario":scenario,"severity":severity,"message":message})]]}]}
req = urllib.request.Request(f"{loki_url.rstrip('/')}/loki/api/v1/push",data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"},method="POST")
urllib.request.urlopen(req, timeout=5)
PY
}

call_ai() {
  local scenario="$1" message="$2"
  python3 - "$AI_URL" "$scenario" "$message" <<'PY' 2>/dev/null
import json, sys, urllib.request
ai_url, scenario, message = sys.argv[1:]
payload = {"source":f"demo-{scenario}","logs":[{"message":message,"labels":{"job":"demo-raw","scenario":scenario}}]}
req = urllib.request.Request(f"{ai_url.rstrip('/')}/analyze",data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"},method="POST")
with urllib.request.urlopen(req, timeout=60) as r:
    d=json.loads(r.read().decode())
    print(f"verdict={d['verdict']} severity={d['severity']} attack={d['attack_type']} provider={d['provider_used']} confidence={d['confidence']}")
PY
}

run_attack() {
  local scenario="$1" severity="$2" message="$3"
  attack "[$scenario]"
  push_loki_log "$scenario" "$severity" "$message" && echo "  Loki push: OK" || echo "  Loki push: SKIP (no loki tunnel)"
  echo -n "  AI analyze: "
  call_ai "$scenario" "$message" || echo "SKIP (no AI tunnel)"
  sleep "$SLEEP"
}

brute_force_demo() {
  attack "Brute force — 10 invalid JWT requests"
  for i in $(seq 1 10); do
    python3 - "$GW_URL" "$GW_HOST" "$i" <<'PY' 2>/dev/null
import sys, urllib.request, json
url, host, i = sys.argv[1:]
headers = {"Content-Type":"application/json", "Authorization":"Bearer bad.token.here"}
if host:
    headers["Host"] = host
req = urllib.request.Request(f"{url}/payments",
    data=json.dumps({"from_account":"x","to_account":"y","amount":1}).encode(),
    headers=headers,
    method="POST")
try: urllib.request.urlopen(req, timeout=5)
except urllib.error.HTTPError as e: pass
PY
    echo -n "."
  done
  echo " 10x 401 sent → brute force alert sẽ fire trong Grafana"
}

# ─── Main demo ────────────────────────────────────────────────────────────────
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

run_normal_traffic() {
  if [[ "$SKIP_PAYMENTS" == true ]]; then
    info "Bỏ qua normal traffic (API Gateway không accessible)"
    return
  fi
  log "─── Normal traffic (baseline) ───"
  send_payment "ACC-1001" "ACC-2001" "50000"    "testuser01" "small-transfer"
  send_payment "ACC-1001" "ACC-2001" "2500000"  "testuser01" "medium-transfer"
  send_payment "ACC-1001" "ACC-2001" "15000000" "testuser01" "large-transfer"
  send_payment "ACC-2001" "ACC-1001" "100000"   "testuser02" "user02-transfer"
  sleep 1
}

run_attack_scenarios() {
  log "─── Attack scenarios (MITRE ATT&CK) ───"
  run_attack "fraud-gate-bypass"  "critical" "OPA deny fraud_gate_bypass response_code=403 source_ip=10.10.1.77 service=payment-service path=/transactions/execute"
  run_attack "lateral-movement"   "critical" "Envoy denied lateral movement invalid SVID spiffe deny source_ip=10.10.1.88 service=core-banking destination=openstack/core-banking"
  run_attack "large-response"     "high"     "Envoy access log response_code=200 bytes_sent=2500000 source_ip=10.10.4.22 service=core-banking path=/accounts/export"
  run_attack "cryptomining"       "critical" "system alert xmrig cryptomining stratum+tcp source_ip=10.10.4.33 pod=transaction-service"
  run_attack "port-scan"          "high"     "network alert nmap port scan source_ip=10.10.0.44 service=api-gateway ports=22,80,443,8080"
  if [[ "$BRUTE_FORCE" == true ]]; then
    brute_force_demo
  fi
}

print_soar_summary() {
  echo ""
  log "─── SOAR Incidents ───"
  python3 - "$SOAR_URL" "$SOAR_API_TOKEN" <<'PY' 2>/dev/null
import json, sys, urllib.request
soar_url, token = sys.argv[1:]
try:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = urllib.request.Request(f"{soar_url}/incidents", headers=headers)
    r = urllib.request.urlopen(req, timeout=5)
    incidents = json.loads(r.read().decode())
    print(f"  Total incidents: {len(incidents)}")
    for i in incidents[-6:]:
        status=i.get('status','?')
        name=i.get('alert_name','?')[:35]
        sev=i.get('severity','?')
        print(f"  [{status:8}] {name:35} sev={sev}")
except Exception as e:
    print(f"  (Cannot reach SOAR: {e})")
PY
  echo ""
  echo -e "  ${CYAN}SOAR incidents: http://127.0.0.1:8091/incidents${NC}"
  echo -e "  ${CYAN}Grafana AI SIEM SOAR: http://127.0.0.1:3000/d/ztlab-ai-siem-soar${NC}"
  echo ""
}

# ─── Entry point ──────────────────────────────────────────────────────────────
print_banner
check_services

if [[ "$CONTINUOUS" == true ]]; then
  log "Chạy continuous mode (Ctrl+C để dừng)..."
  ROUND=0
  while true; do
    ROUND=$((ROUND+1))
    log "══ Round $ROUND ══"
    [[ "$ATTACK_ONLY" == false ]] && run_normal_traffic
    [[ "$TRAFFIC_ONLY" == false ]] && run_attack_scenarios
    print_soar_summary
    log "Nghỉ 30s trước round tiếp theo..."
    sleep 30
  done
else
  [[ "$ATTACK_ONLY" == false ]] && run_normal_traffic
  [[ "$TRAFFIC_ONLY" == false ]] && run_attack_scenarios
  print_soar_summary
fi
