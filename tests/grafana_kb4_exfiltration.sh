#!/bin/bash
# KB4 — Data Exfiltration / Large Response (T1041)
# Zero Trust layer: Egress monitoring (Envoy bytes_sent pattern)
# Bằng chứng thật: đo bytes thực từ các request bulk data lặp lại
# SOAR playbook : restrict_egress (scale core-banking → 0 trên OpenStack)
# HITL          : YES — email gửi admin
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:8180}"
SOAR_URL="${SOAR_URL:-http://localhost:8091}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB4_exfiltration"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
log "Bước 1: kiểm tra API Gateway và SOAR..."
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway không khả dụng"
curl -fsS "$SOAR_URL/health" | grep -q '"status":"ok"' || fail "SOAR không khả dụng"

# ── 2. Lấy JWT và thực hiện bulk data download ───────────────────────────────
log "Bước 2: lấy JWT testuser01 rồi kéo transaction history lặp lại nhiều lần..."
TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
[[ -n "$TOKEN" ]] || fail "Không lấy được JWT"

total_bytes=0
endpoints=(
  "/transactions?account_id=ACC-1001&limit=500"
  "/transactions?account_id=ACC-2001&limit=500"
  "/accounts/balance"
  "/transactions?account_id=ACC-1001&limit=500"
  "/accounts/balance"
  "/transactions?account_id=ACC-2001&limit=500"
  "/transactions?account_id=ACC-1001&limit=500"
  "/transactions?account_id=ACC-2001&limit=500"
  "/accounts/balance"
  "/transactions?account_id=ACC-1001&limit=500"
)
for ep in "${endpoints[@]}"; do
  sz=$(curl -s -w "%{size_download}" -o /dev/null "$GW_URL$ep" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo "0")
  total_bytes=$((total_bytes + sz))
done
log "▶ ${#endpoints[@]} request bulk data — tổng bytes nhận: $total_bytes bytes từ API Financial"
log "  (trong môi trường production, request tương tự tới core-banking sẽ trả response MB-level)"

# ── 3. Đẩy Envoy-format log vào Loki với bytes thực đo ────────────────────────
log "Bước 3: đẩy envoy-access log vào Loki (bytes_sent=$total_bytes đo thực + giả lập core-banking 2MB)..."
ts=$(date +%s%N)
# Log 1: bytes đo thực từ api-gateway
curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
  -H "Content-Type: application/json" \
  -d "{\"streams\":[{
    \"stream\":{\"job\":\"envoy-access\",\"namespace\":\"financial\",\"app\":\"api-gateway\"},
    \"values\":[
      [\"$ts\",\"{\\\"bytes_sent\\\":$total_bytes,\\\"source_ip\\\":\\\"10.0.0.77\\\",\\\"path\\\":\\\"/transactions\\\",\\\"method\\\":\\\"GET\\\",\\\"response_code\\\":200,\\\"request_count\\\":${#endpoints[@]}}\"]
    ]
  }]}" >/dev/null
# Log 2: giả lập Envoy của core-banking (OpenStack) — đây là target của restrict_egress
curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
  -H "Content-Type: application/json" \
  -d "{\"streams\":[{
    \"stream\":{\"job\":\"envoy-access\",\"namespace\":\"financial\",\"app\":\"core-banking\"},
    \"values\":[
      [\"$((ts+1000000))\",\"{\\\"bytes_sent\\\":2097152,\\\"source_ip\\\":\\\"10.0.0.77\\\",\\\"path\\\":\\\"/accounts/export\\\",\\\"method\\\":\\\"GET\\\",\\\"response_code\\\":200,\\\"note\\\":\\\"simulated_core_banking_response\\\"}\"],
      [\"$((ts+2000000))\",\"{\\\"bytes_sent\\\":1572864,\\\"source_ip\\\":\\\"10.0.0.77\\\",\\\"path\\\":\\\"/transactions/dump\\\",\\\"method\\\":\\\"GET\\\",\\\"response_code\\\":200,\\\"note\\\":\\\"simulated_core_banking_response\\\"}\"]
    ]
  }]}" >/dev/null
log "Log đã vào Loki (real: ${total_bytes}B từ api-gateway + simulated: 3.5MB từ core-banking)"

# ── 4. Mô phỏng Grafana → SOAR webhook ────────────────────────────────────────
log "Bước 4: mô phỏng Grafana 'Data Exfiltration — Large Response' → SOAR webhook..."
fp="kb4-$(date +%s)"
soar_resp=$(curl -s -X POST "$SOAR_URL/grafana-webhook" \
  -H "Content-Type: application/json" \
  -d "{
    \"status\": \"firing\",
    \"alerts\": [{
      \"status\": \"firing\",
      \"labels\": {
        \"alertname\": \"Data Exfiltration — Large Response (T1041)\",
        \"severity\": \"high\",
        \"attack_type\": \"large_response\",
        \"mitre\": \"T1041\",
        \"category\": \"security\",
        \"gap\": \"gap1\",
        \"source_ip\": \"10.0.0.77\"
      },
      \"annotations\": {
        \"summary\": \"${#endpoints[@]} bulk requests trong 5 phút — tổng $total_bytes bytes từ financial API\",
        \"description\": \"source_ip=10.0.0.77 request_count=${#endpoints[@]} total_bytes=$total_bytes target=core-banking (OpenStack)\"
      },
      \"fingerprint\": \"$fp\"
    }]
  }")

# ── 5. Kiểm tra SOAR case ─────────────────────────────────────────────────────
log "Bước 5: kiểm tra SOAR case..."
status=$(echo "$soar_resp"   | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('status','?') if c else 'no-case')" 2>/dev/null)
playbook=$(echo "$soar_resp" | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('playbook','?') if c else '?')" 2>/dev/null)
case_id=$(echo "$soar_resp"  | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('case_id','?') if c else '?')" 2>/dev/null)

[[ "$status" =~ ^(pending_approval|executed|dry_run)$ ]] \
  || fail "SOAR status='$status' (expect pending_approval)"
[[ "$playbook" == "restrict_egress" ]] \
  || fail "SOAR playbook='$playbook' (expect restrict_egress)"

pass "KB4 Exfiltration | real: ${total_bytes}B từ ${#endpoints[@]} requests | SOAR case=$case_id status=$status playbook=$playbook (T1041)"
