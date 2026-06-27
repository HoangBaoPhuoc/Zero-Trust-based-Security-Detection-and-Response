#!/bin/bash
# KB4 — Data Exfiltration / Large Response (T1041)
# Zero Trust layer: Egress control (Envoy bytes_sent monitoring)
# Grafana rule  : Data Exfiltration — Large Response (T1041) → severity=high
# SOAR playbook : restrict_egress (scale core-banking → 0 replicas trên OpenStack)
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

# ── 2. Gửi nhiều request lấy data lớn ───────────────────────────────────────
log "Bước 2: gửi request bulk export (mô phỏng data exfiltration từ core-banking)..."
TOKEN=$(curl -s -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
total_bytes=0
for i in 1 2 3; do
  resp=$(curl -s -w "\n%{size_download}" "$GW_URL/accounts/balance" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo "0")
  sz=$(echo "$resp" | tail -1)
  total_bytes=$((total_bytes + sz))
  log "request $i: $sz bytes"
done
log "Tổng bytes tải về: $total_bytes"

# ── 3. Đẩy Envoy access log bytes_sent > 1MB vào Loki ────────────────────────
log "Bước 3: đẩy envoy-access log bytes_sent=2097152 vào Loki (mô phỏng dump DB lớn)..."
ts=$(date +%s%N)
curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
  -H "Content-Type: application/json" \
  -d "{\"streams\":[{
    \"stream\":{\"job\":\"envoy-access\",\"namespace\":\"financial\",\"app\":\"core-banking\"},
    \"values\":[
      [\"$ts\",\"{\\\"bytes_sent\\\":2097152,\\\"source_ip\\\":\\\"10.0.0.77\\\",\\\"path\\\":\\\"/accounts/export\\\",\\\"method\\\":\\\"GET\\\",\\\"response_code\\\":200,\\\"duration_ms\\\":3200}\"],
      [\"$((ts+2000000))\",\"{\\\"bytes_sent\\\":1572864,\\\"source_ip\\\":\\\"10.0.0.77\\\",\\\"path\\\":\\\"/transactions/dump\\\",\\\"method\\\":\\\"GET\\\",\\\"response_code\\\":200}\"]
    ]
  }]}" >/dev/null
log "Envoy bytes_sent >1MB log đã vào Loki"

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
        \"gap\": \"gap1\"
      },
      \"annotations\": {
        \"summary\": \"Phản hồi >1MB từ core-banking — nghi ngờ exfiltration\",
        \"description\": \"source_ip=10.0.0.77 bytes_sent=2097152 path=/accounts/export target=core-banking (OpenStack)\"
      },
      \"fingerprint\": \"$fp\"
    }]
  }")

# ── 5. Kiểm tra SOAR case ─────────────────────────────────────────────────────
log "Bước 5: kiểm tra SOAR case..."
status=$(echo "$soar_resp"   | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('status','?') if c else 'no-case')" 2>/dev/null)
playbook=$(echo "$soar_resp" | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('playbook','?') if c else '?')" 2>/dev/null)
target=$(echo "$soar_resp"   | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('target_workload','?') if c else '?')" 2>/dev/null)
case_id=$(echo "$soar_resp"  | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('case_id','?') if c else '?')" 2>/dev/null)

[[ "$status" =~ ^(pending_approval|executed|dry_run)$ ]] \
  || fail "SOAR status='$status' (expect pending_approval)"
[[ "$playbook" == "restrict_egress" ]] \
  || fail "SOAR playbook='$playbook' (expect restrict_egress)"

pass "KB4 Exfiltration | bytes>1MB detected | SOAR case=$case_id status=$status playbook=$playbook target=$target (T1041)"
log "→ restrict_egress: SOAR scale core-banking xuống 0 replica trên OpenStack cluster để chặn data ra"
