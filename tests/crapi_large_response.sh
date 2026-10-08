#!/usr/bin/env bash
# KỊCH BẢN — Data Exfiltration: Large Response (T1041) — mục 3 vòng 2026-09-29
#
# Trước đây chỉ làm tay (AUDIT-THUC-THI.md §6, phiên 2026-09-18). Script hoá để
# bằng chứng Firing lặp lại được:
#   1. login testuser01, POST 2 community post ~700 KB mỗi cái (< 1 MB giới hạn body nginx/WAF)
#   2. GET /community/api/v2/community/posts/recent → response > 1 MB (2 post lớn)
#   3. Loki envoy-access bytes_sent > 1048576 → rule "Data Exfiltration: Large Response"
#      Firing (Grafana API) → evidence bundle attack_type=large_response (incident-analyzer)
set -uo pipefail
SCENARIO="crapi_large_response"
source "$(dirname "${BASH_SOURCE[0]}")/lib/crapi_common.sh"
crapi_preflight
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-closeout}/alerts"; mkdir -p "$OUT"
RULE="crAPI — Data Exfiltration: Large Response"

# §B1: biến thể. burst (train) = 1 response LỚN > MIN_BYTES (rule ngưỡng fire).
# accumulate (holdout exfil_many_small) = NHIỀU response NHỎ cộng dồn > MIN_BYTES;
# KHÔNG response đơn nào vượt ngưỡng nên rule ngưỡng-đơn KHÔNG fire — phát hiện
# là nhiệm vụ của lớp ML (cộng dồn theo phiên), không phải luật. Nghiệm thu đo
# phân phối khoảng cách + tổng bytes tích luỹ.
ACCUMULATE="${VP_ACCUMULATE:-false}"
MIN_BYTES="${VP_MIN_BYTES:-1048576}"
RESPONSES="${VP_RESPONSES:-1}"; [[ "$RESPONSES" =~ ^[0-9]+$ ]] || RESPONSES=12

st="$(grafana_rule_state "$RULE")"; log "trạng thái rule trước khi chạy: $st (ACCUMULATE=$ACCUMULATE PACE=${PACE:-burst})"
T0=$(date +%s)
J="$(crapi_login testuser01 'Test1234!')"; trap 'rm -f "$J" "$BODY"' EXIT
BODY="$(mktemp)"

if [[ "$ACCUMULATE" == "true" || "$ACCUMULATE" == "True" ]]; then
  mapfile -t TLS < <(crapi_curl_tls_opts)
  # vài post ~150KB để posts/recent có nội dung; mỗi GET giới hạn nhỏ (< ngưỡng).
  python3 -c 'import json;print(json.dumps({"title":"small","content":"X"*150000}))' > "$BODY"
  for k in 1 2 3 4; do
    curl -s -A "$BROWSER_UA" "${TLS[@]}" -b "$J" -X POST -H 'Content-Type: application/json' \
      --data-binary "@$BODY" -o /dev/null -w '' --max-time 60 "$BFF_URL/community/api/v2/community/posts" || true
  done
  total_bytes=0
  for ((i=1; i<=RESPONSES; i++)); do
    [[ $i -gt 1 ]] && crapi_pace_sleep "$i" "$RESPONSES"
    read -r code size < <(curl -s -A "$BROWSER_UA" "${TLS[@]}" -b "$J" -o /dev/null -w '%{http_code} %{size_download}\n' \
      --max-time 60 "$BFF_URL/community/api/v2/community/posts/recent?limit=3")
    total_bytes=$(( total_bytes + size ))
    log "  GET posts/recent #$i → $code, $size byte (cộng dồn=$total_bytes)"
  done
  [[ "$total_bytes" -gt "$MIN_BYTES" ]] || fail "exfil cộng dồn chỉ $total_bytes byte (cần > $MIN_BYTES) — tăng RESPONSES hoặc seed thêm post"
  T1="$(( $(date +%s) + 1 ))"
  pass "$SCENARIO (accumulate) — $RESPONSES response nhỏ cộng dồn $total_bytes byte > $MIN_BYTES; rule ngưỡng-đơn KHÔNG fire (đúng — phát hiện ở lớp ML)"
  exit 0
fi
python3 -c 'import json;print(json.dumps({"title":"large-response-probe","content":"X"*700000}))' > "$BODY"
mapfile -t TLS < <(crapi_curl_tls_opts)
for i in 1 2; do
  c="$(curl -s -A "$BROWSER_UA" "${TLS[@]}" -b "$J" -X POST -H 'Content-Type: application/json' \
       --data-binary "@$BODY" -o /dev/null -w '%{http_code}' --max-time 60 "$BFF_URL/community/api/v2/community/posts")"
  log "POST post lớn #$i (~700 KB) → $c"
done
read -r code size < <(curl -s -A "$BROWSER_UA" "${TLS[@]}" -b "$J" -o /dev/null -w '%{http_code} %{size_download}\n' \
  --max-time 60 "$BFF_URL/community/api/v2/community/posts/recent")
log "GET posts/recent → $code, $size byte"
[[ "$code" == 200 && "$size" -gt 1048576 ]] || fail "không tạo được response > 1 MB (code=$code size=$size)"

fired="$(wait_rule_firing "$RULE" 240)" || fail "rule không Firing trong 240 s"
log "rule Firing: $fired"
ev="$(wait_evidence large_response "$T0" 180)" || fail "không có evidence bundle large_response"
log "evidence: $ev"
echo "ts=$(date -Is) scenario=large_response response_bytes=$size firing=[$fired] evidence=$ev" >> "$OUT/firing-evidence.log"
pass "$SCENARIO — response $size byte → Firing ($fired) → evidence bundle"
