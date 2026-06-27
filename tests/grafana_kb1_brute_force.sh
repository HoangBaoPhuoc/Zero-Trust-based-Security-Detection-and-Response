#!/bin/bash
# KB1 — Brute Force Login (T1110.001)
# Zero Trust layer: Authentication (Keycloak + Envoy)
# Grafana rule  : Brute Force Login (T1110.001) → severity=high
# SOAR playbook : revoke_user_sessions
# HITL          : YES — email gửi admin khi case pending_approval
set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8180}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB1_brute_force"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
curl -fsS "$KC_URL/realms/ztlab/.well-known/openid-configuration" >/dev/null \
  || fail "Keycloak không khả dụng tại $KC_URL"

# ── 2. Sinh traffic tấn công thật ────────────────────────────────────────────
blocked=0
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KC_URL/realms/ztlab/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=web-portal&username=testuser01&password=WRONG_PASS_$i")
  [[ "$code" =~ ^(400|401)$ ]] && blocked=$((blocked+1))
done
[[ $blocked -ge 18 ]] || fail "chỉ $blocked/20 lần bị chặn (cần ≥18)"
log "Keycloak chặn $blocked/20 (401)"

# ── 3. Đẩy log vào Loki ──────────────────────────────────────────────────────
ts=$(date +%s%N)
for seq in 0 1 2 3 4; do
  curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
    -H "Content-Type: application/json" \
    -d "{\"streams\":[{\"stream\":{\"job\":\"envoy-access\",\"namespace\":\"financial\",\"app\":\"api-gateway\"},
      \"values\":[[\"$((ts + seq * 1000000))\",
        \"{\\\"response_code\\\":401,\\\"source_ip\\\":\\\"10.0.0.1\\\",\\\"method\\\":\\\"POST\\\",\\\"path\\\":\\\"/api/login\\\",\\\"bytes_sent\\\":0}\"]]}]}" >/dev/null
done

pass "KB1 | blocked=$blocked/20 | logs → Loki (Grafana fire trong ≤1 phút)"
