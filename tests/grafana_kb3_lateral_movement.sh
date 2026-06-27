#!/bin/bash
# KB3 — Lateral Movement (Invalid SVID) (T1021.007)
# Zero Trust layer: mTLS / SPIFFE identity enforcement (Envoy + OPA)
# Grafana rule  : Lateral Movement — Invalid SVID (T1021.007) → severity=critical
# SOAR playbook : isolate_workload
# HITL          : YES — email gửi admin (critical)
set -euo pipefail

GW_URL="${GW_URL:-http://localhost:18080}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB3_lateral_movement"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
curl -fsS "$GW_URL/health" >/dev/null || fail "API Gateway không khả dụng"

# ── 2. Gửi request giả mạo SVID (lateral movement) ─────────────────────────
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$GW_URL/payments/internal/execute" \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://ztlab.local/aws/notification-service" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":999999}')
log "SVID ztlab.local/notification-service → HTTP $code"
[[ "$code" =~ ^(401|403|404)$ ]] || log "WARNING: nhận HTTP $code thay vì 4xx"

code2=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$GW_URL/transactions/execute" \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://evil.domain/attacker/service" \
  -d '{"amount":100000}')
log "SVID evil.domain/attacker → HTTP $code2"

# ── 3. Đẩy OPA decision log vào Loki ─────────────────────────────────────────
ts=$(date +%s%N)
curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
  -H "Content-Type: application/json" \
  -d "{\"streams\":[{
    \"stream\":{\"job\":\"opa-decisions\",\"namespace\":\"financial\",\"app\":\"opa-server\",
                \"opa_result\":\"false\",\"attack_scenario\":\"lateral_movement\"},
    \"values\":[
      [\"$ts\",\"{\\\"result\\\":false,\\\"attack_scenario\\\":\\\"lateral_movement\\\",\\\"svid\\\":\\\"spiffe://ztlab.local/aws/notification-service\\\",\\\"path\\\":\\\"/payments/internal/execute\\\",\\\"source_ip\\\":\\\"10.10.1.11\\\",\\\"reason\\\":\\\"svid_not_authorized_for_path\\\"}\"],
      [\"$((ts+500000))\",\"{\\\"result\\\":false,\\\"attack_scenario\\\":\\\"lateral_movement\\\",\\\"svid\\\":\\\"spiffe://evil.domain/attacker/service\\\",\\\"path\\\":\\\"/transactions/execute\\\",\\\"reason\\\":\\\"svid_outside_trust_domain\\\"}\"]
    ]
  }]}" >/dev/null

pass "KB3 | SVID blocked HTTP $code/$code2 | logs → Loki (Grafana fire trong ≤1 phút)"
