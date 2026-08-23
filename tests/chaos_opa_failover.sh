#!/bin/bash
# Chaos test — OPA PDP failover (Policy Decision Point availability)
# Zero Trust layer: kiểm chứng THẬT (không chỉ đọc config rồi tin) rằng
# Istio's CUSTOM AuthorizationPolicy → OPA ext_authz thật sự fail-closed khi
# OPA không phản hồi (k8s/istio/istio-operator.yaml's opa-ext-authz
# extensionProvider, k8s/financial/istio-policies.yaml's *-opa-authz
# policies). Đây là điểm khác biệt so với phần lớn tài liệu Zero Trust: chỉ
# nói "hệ thống có cấu hình X" không chứng minh gì — phải tắt thật OPA và
# quan sát traffic thật mới biết cấu hình đó có tác dụng hay không.
#
# QUAN TRỌNG (phát hiện 2026-08-23): `kubectl port-forward svc/api-gateway`
# kết nối thẳng vào pod qua loopback bên trong network namespace của pod —
# BỎ QUA HOÀN TOÀN iptables interception của Istio (istio-init's redirect
# rules loại trừ traffic nguồn loopback). Test qua port-forward luôn thấy
# HTTP 401 "missing bearer token" từ chính app (server: uvicorn) — GIỐNG HỆT
# nhau dù OPA up hay down — không phải vì fail-open, mà vì Istio/OPA không
# hề tham gia vào request đó. Test THẬT phải đi qua Traefik (production
# ingress thật) — xác nhận qua header `server: istio-envoy` (không phải
# `uvicorn`) mới chứng minh được request đã qua đúng lớp Istio.
set -euo pipefail

CONTEXT="${KUBE_CONTEXT:-ctx-aws}"
NAMESPACE="financial"
SCENARIO="CHAOS_opa_failover"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# Traefik ingress trực tiếp (KHÔNG dùng port-forward tới api-gateway Service
# — xem ghi chú ở trên tại sao điều đó vô hiệu hoá bài test này).
TRAEFIK_PF_PID=""
cleanup_traefik_pf() {
  [[ -n "$TRAEFIK_PF_PID" ]] && kill "$TRAEFIK_PF_PID" 2>/dev/null || true
}
kubectl --context "$CONTEXT" port-forward -n kube-system svc/traefik 18889:80 >/tmp/chaos-traefik-pf.log 2>&1 &
TRAEFIK_PF_PID=$!
sleep 3
GW_URL="http://localhost:18889"
CURL_HOST_HDR=(-H "Host: api.ztlab.local")

ORIGINAL_REPLICAS=$(kubectl --context "$CONTEXT" get deployment opa-server -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
log "opa-server hiện có $ORIGINAL_REPLICAS replica — sẽ scale về 0 rồi phục hồi khi xong (kể cả nếu script fail giữa chừng)"

restore_opa() {
  log "Khôi phục opa-server về $ORIGINAL_REPLICAS replica..."
  kubectl --context "$CONTEXT" scale deployment opa-server -n "$NAMESPACE" --replicas="$ORIGINAL_REPLICAS" >/dev/null
  kubectl --context "$CONTEXT" rollout status deployment/opa-server -n "$NAMESPACE" --timeout=90s >/dev/null 2>&1 || true
}
cleanup() {
  restore_opa
  cleanup_traefik_pf
}
trap cleanup EXIT

# ── 1. Baseline: request bình thường phải đi qua được (chưa tắt OPA) ────────
log "Baseline — kiểm tra request GET /health còn hoạt động trước khi tắt OPA (qua Traefik thật)"
baseline_code=$(curl -s -o /dev/null -w "%{http_code}" "${CURL_HOST_HDR[@]}" "$GW_URL/health")
[[ "$baseline_code" == "200" ]] || fail "Baseline lỗi ($baseline_code) — hệ thống không ổn định trước khi test, dừng lại"

# ── 2. Tắt OPA ───────────────────────────────────────────────────────────────
log "Scale opa-server → 0 replica..."
kubectl --context "$CONTEXT" scale deployment opa-server -n "$NAMESPACE" --replicas=0 >/dev/null
kubectl --context "$CONTEXT" wait --for=delete pod -n "$NAMESPACE" -l app=opa-server --timeout=60s >/dev/null 2>&1 || true
log "opa-server đã tắt (0 pod)"

# ── 3. Gửi request tới endpoint cần OPA ext_authz (không phải public_path) ──
# /accounts/ACC-1001 không nằm trong public_path — bắt buộc qua OPA.
# Kiểm tra CẢ status code (403/503) LẪN server header (istio-envoy) — nếu
# server header là "uvicorn" nghĩa là request đã lọt qua app mà không hề
# chạm Istio/OPA (fail-open thật sự, hoặc bài test đang tự lừa chính nó).
denied=0
for i in 1 2 3; do
  resp=$(curl -s -D - -o /dev/null -w "HTTPSTATUS:%{http_code}" "${CURL_HOST_HDR[@]}" "$GW_URL/accounts/ACC-1001" --max-time 5 || echo "HTTPSTATUS:000")
  code=$(echo "$resp" | grep -o 'HTTPSTATUS:[0-9]*' | cut -d: -f2)
  server=$(echo "$resp" | grep -i '^server:' | tr -d '\r' | awk '{print $2}')
  log "  Attempt $i (OPA down) → HTTP $code (server: ${server:-none})"
  if [[ "$code" =~ ^(403|503)$ && "$server" == "istio-envoy" ]]; then
    denied=$((denied+1))
  fi
done

[[ $denied -ge 2 ]] || fail "CHỈ $denied/3 bị từ chối THẬT (403/503 + server:istio-envoy) khi OPA down — có thể đang fail-open (lỗ hổng nghiêm trọng), hoặc request không chạm Istio (kiểm tra NetworkPolicy kube-system→financial:8080, k8s/istio/istio-operator.yaml opa-ext-authz)"
log "$denied/3 request bị từ chối bởi istio-envoy khi OPA down — xác nhận fail-closed thật qua đúng đường Traefik (không phải suy đoán từ config, không bị port-forward che giấu)"

# ── 4. Phục hồi và xác nhận traffic bình thường trở lại ─────────────────────
restore_opa
log "Xác nhận traffic bình thường sau khi phục hồi OPA..."
recovered_code=$(curl -s -o /dev/null -w "%{http_code}" "${CURL_HOST_HDR[@]}" "$GW_URL/health")
[[ "$recovered_code" == "200" ]] || fail "Sau khi phục hồi opa-server, /health vẫn lỗi ($recovered_code)"

pass "CHAOS DONE | $denied/3 fail-closed khi OPA down | Phục hồi thành công, traffic bình thường trở lại"
