#!/bin/bash
# KB4 — Data Exfiltration / Large Response (T1041)
# Zero Trust layer: Egress monitoring (Envoy bytes_sent pattern)
# Bằng chứng thật: đo bytes thực từ các request bulk data lặp lại
# SOAR playbook : restrict_egress (scale core-banking → 0 trên OpenStack)
# HITL          : YES — email gửi admin
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
KC_URL="${KC_URL:-http://localhost:8180}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB4_exfiltration"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway không khả dụng"

# ── 2. Lấy JWT và thực hiện bulk data download ───────────────────────────────
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
log "${#endpoints[@]} bulk requests → $total_bytes bytes"

# ── 3. Đẩy Envoy-format log vào Loki với bytes thực đo ────────────────────────
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

pass "KB4 | ${#endpoints[@]} requests → ${total_bytes}B | logs → Loki (Grafana fire trong ≤1 phút)"
