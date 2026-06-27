#!/bin/bash
# KB1 — Brute Force Login (T1110.001)
# Zero Trust layer: Authentication (Keycloak + Envoy)
# Grafana rule  : Brute Force Login (T1110.001) → severity=high
# SOAR playbook : revoke_user_sessions
# HITL          : YES — email gửi admin khi case pending_approval
set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8180}"
SOAR_URL="${SOAR_URL:-http://localhost:8091}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB1_brute_force"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
log "Bước 1: kiểm tra Keycloak và SOAR..."
curl -fsS "$KC_URL/realms/ztlab/.well-known/openid-configuration" >/dev/null \
  || fail "Keycloak không khả dụng tại $KC_URL"
curl -fsS "$SOAR_URL/health" | grep -q '"status":"ok"' \
  || fail "SOAR Engine không khả dụng tại $SOAR_URL"

# ── 2. Sinh traffic tấn công thật ────────────────────────────────────────────
log "Bước 2: gửi 20 lần đăng nhập sai mật khẩu..."
blocked=0
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=web-portal&username=testuser01&password=WRONG_PASS_$i")
  [[ "$code" =~ ^(400|401)$ ]] && blocked=$((blocked+1))
done
[[ $blocked -ge 18 ]] || fail "chỉ $blocked/20 lần bị chặn (cần ≥18)"
log "Keycloak chặn $blocked/20 — xác thực Zero Trust hoạt động đúng"

# ── 3. Đẩy log đặc trưng vào Loki ────────────────────────────────────────────
log "Bước 3: đẩy envoy-access log vào Loki (Grafana query: job=envoy-access, response_code=401)..."
ts=$(date +%s%N)
for seq in 0 1 2 3 4; do
  curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
    -H "Content-Type: application/json" \
    -d "{\"streams\":[{\"stream\":{\"job\":\"envoy-access\",\"namespace\":\"financial\",\"app\":\"api-gateway\"},
      \"values\":[[\"$((ts + seq * 1000000))\",
        \"{\\\"response_code\\\":401,\\\"source_ip\\\":\\\"10.0.0.1\\\",\\\"method\\\":\\\"POST\\\",\\\"path\\\":\\\"/api/login\\\",\\\"bytes_sent\\\":0}\"]]}]}" >/dev/null
done
log "5 log 401 đã vào Loki — Grafana rule sẽ evaluate trong ≤1 phút"

# ── 4. Mô phỏng Grafana → SOAR webhook ────────────────────────────────────────
log "Bước 4: mô phỏng Grafana 'Brute Force Login' alert → SOAR webhook..."
fp="kb1-$(date +%s)"
soar_resp=$(curl -s -X POST "$SOAR_URL/grafana-webhook" \
  -H "Content-Type: application/json" \
  -d "{
    \"status\": \"firing\",
    \"alerts\": [{
      \"status\": \"firing\",
      \"labels\": {
        \"alertname\": \"Brute Force Login (T1110.001)\",
        \"severity\": \"high\",
        \"attack_type\": \"brute_force\",
        \"mitre\": \"T1110.001\",
        \"category\": \"security\",
        \"source_ip\": \"10.0.0.1\"
      },
      \"annotations\": {
        \"summary\": \"$blocked failed logins from 10.0.0.1 in 60s\",
        \"description\": \"source_ip=10.0.0.1 count=$blocked window=60s target_user=testuser01\"
      },
      \"fingerprint\": \"$fp\"
    }]
  }")

# ── 5. Kiểm tra SOAR case ────────────────────────────────────────────────────
log "Bước 5: kiểm tra SOAR case được tạo..."
status=$(echo "$soar_resp"   | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('status','?') if c else 'no-case')" 2>/dev/null)
playbook=$(echo "$soar_resp" | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('playbook','?') if c else '?')" 2>/dev/null)
case_id=$(echo "$soar_resp"  | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('case_id','?') if c else '?')" 2>/dev/null)

[[ "$status" =~ ^(pending_approval|executed|dry_run)$ ]] \
  || fail "SOAR status='$status' (expect pending_approval)"
[[ "$playbook" == "revoke_user_sessions" ]] \
  || fail "SOAR playbook='$playbook' (expect revoke_user_sessions)"

pass "KB1 Brute Force | blocked=$blocked/20 | SOAR case=$case_id status=$status playbook=$playbook (T1110.001)"
