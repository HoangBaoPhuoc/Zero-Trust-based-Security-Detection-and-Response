#!/usr/bin/env bash
# Vòng 2026-09-29: BFF phải làm mới access token Keycloak (TTL 300 s) cho phiên
# dài — trước bản sửa, mọi request sau phút thứ 5 bị OPA từ chối 403 (token hết hạn).
# Login → GET products (t=0) → chờ WAIT giây (> 300) → GET products lần nữa.
# PASS: cả 2 lần 200 và BFF audit có token_refreshed cho testuser01.
set -uo pipefail
SCENARIO="bff_token_refresh"
source "$(dirname "${BASH_SOURCE[0]}")/lib/crapi_common.sh"
WAIT="${WAIT:-330}"
crapi_preflight
T0=$(date +%s)
J="$(crapi_login testuser01 'Test1234!')"; trap 'rm -f "$J"' EXIT
c1="$(crapi_call "$J" GET /workshop/api/shop/products)"; log "t=0: GET products → $c1"
sleep "$WAIT"
c2="$(crapi_call "$J" GET /workshop/api/shop/products)"; log "t=${WAIT}s: GET products → $c2"
sleep 5
n="$(loki_count '{job="bff-audit"} | json | event="token_refreshed" | username="testuser01"' "$T0" "$(date +%s)")"
log "BFF audit token_refreshed: $n"
mkdir -p "$REPO_ROOT/results/${RESULTS_ROUND:-closeout}/bff-token-refresh"
echo "ts=$(date -Is) wait=$WAIT first=$c1 after=$c2 token_refreshed=$n" >> "$REPO_ROOT/results/${RESULTS_ROUND:-closeout}/bff-token-refresh/runs.log"
[[ "$c1" == 200 && "$c2" == 200 && "$n" -ge 1 ]] || fail "first=$c1 after=$c2 refreshed=$n"
pass "phiên ${WAIT}s: $c1 → $c2, token_refreshed=$n"
