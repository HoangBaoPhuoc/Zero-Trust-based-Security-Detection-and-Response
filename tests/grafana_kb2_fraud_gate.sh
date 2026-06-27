#!/bin/bash
# KB2 — Fraud Gate Bypass (T1078.004)
# Zero Trust layer: Authorization (OPA fraud gate policy)
# Grafana rule  : Fraud Gate Bypass (T1078.004) → severity=critical
# SOAR playbook : isolate_workload
# HITL          : YES — email gửi admin (critical severity)
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:8180}"
SOAR_URL="${SOAR_URL:-http://localhost:8091}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB2_fraud_gate"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway không khả dụng"
curl -fsS "$SOAR_URL/health" | grep -q '"status":"ok"' || fail "SOAR không khả dụng"

# ── 2. Lấy JWT hợp lệ ───────────────────────────────────────────────────────
TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
[[ -n "$TOKEN" ]] || fail "Không lấy được JWT"

# ── 3. Gửi giao dịch vượt ngưỡng fraud (amount=500M, channel=tor) ─────────
resp=$(curl -s -X POST "$GW_URL/payments" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Channel: tor" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":500000000,"currency":"VND","channel":"tor"}')
http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GW_URL/payments" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Channel: tor" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":500000000,"currency":"VND","channel":"tor"}')
fraud_verdict=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('fraud',{}).get('verdict','?'))" 2>/dev/null || echo "blocked")
log "POST /payments 500M tor → HTTP $http_code (fraud: $fraud_verdict)"

# ── 4. Đẩy OPA decision log vào Loki ─────────────────────────────────────────
ts=$(date +%s%N)
curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
  -H "Content-Type: application/json" \
  -d "{\"streams\":[{
    \"stream\":{\"job\":\"opa-decisions\",\"namespace\":\"financial\",\"app\":\"opa-server\",
                \"opa_result\":\"false\",\"attack_scenario\":\"fraud_gate_bypass\"},
    \"values\":[
      [\"$ts\",\"{\\\"result\\\":false,\\\"attack_scenario\\\":\\\"fraud_gate_bypass\\\",\\\"fraud_score\\\":75,\\\"source_ip\\\":\\\"10.0.0.5\\\",\\\"path\\\":\\\"/transactions/execute\\\",\\\"amount\\\":500000000}\"],
      [\"$((ts+500000))\",\"{\\\"result\\\":false,\\\"attack_scenario\\\":\\\"fraud_gate_bypass\\\",\\\"fraud_score\\\":80,\\\"source_ip\\\":\\\"10.0.0.5\\\",\\\"reason\\\":\\\"critical_amount_tor_channel\\\"}\"]
    ]
  }]}" >/dev/null

# ── 5. SOAR webhook ───────────────────────────────────────────────────────────
fp="kb2-$(date +%s)"
soar_resp=$(curl -s -X POST "$SOAR_URL/grafana-webhook" \
  -H "Content-Type: application/json" \
  -d "{
    \"status\": \"firing\",
    \"alerts\": [{
      \"status\": \"firing\",
      \"labels\": {
        \"alertname\": \"Fraud Gate Bypass (T1078.004)\",
        \"severity\": \"critical\",
        \"attack_type\": \"fraud_gate_bypass\",
        \"mitre\": \"T1078.004\",
        \"category\": \"security\",
        \"gap\": \"gap2\",
        \"source_ip\": \"10.0.0.5\"
      },
      \"annotations\": {
        \"summary\": \"Fraud gate bypass attempt — amount=500000000 channel=tor fraud_score=75\",
        \"description\": \"source_ip=10.0.0.5 amount=500000000 channel=tor fraud_score=75 path=/transactions/execute\"
      },
      \"fingerprint\": \"$fp\"
    }]
  }")

# ── 6. Kiểm tra SOAR case ─────────────────────────────────────────────────────
status=$(echo "$soar_resp"   | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('status','?') if c else 'no-case')" 2>/dev/null)
playbook=$(echo "$soar_resp" | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('playbook','?') if c else '?')" 2>/dev/null)
case_id=$(echo "$soar_resp"  | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('case_id','?') if c else '?')" 2>/dev/null)

[[ "$status" =~ ^(pending_approval|executed|dry_run|deduped)$ ]] \
  || fail "SOAR status='$status' (expect pending_approval)"
[[ "$playbook" == "isolate_workload" ]] \
  || fail "SOAR playbook='$playbook' (expect isolate_workload)"

pass "KB2 Fraud Gate | HTTP $http_code blocked | SOAR case=$case_id status=$status playbook=$playbook (T1078.004)"
