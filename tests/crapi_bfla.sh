#!/usr/bin/env bash
# KỊCH BẢN — BFLA / Broken Function Level Authorization (OWASP API5:2023)
#
# Lớp Zero-Trust nghiệm thu: RBAC hai lớp — BFF `_rbac_ok` (đặt header token +
# gương OPA) VÀ OPA `zta/crapi/authz` `role_permits_action`. `crapi-user` cố
# GHI vào endpoint admin/management → cả hai từ chối.
#
# Tấn công THẬT: login testuser01 (crapi-user) qua Keycloak/BFF → POST
# /workshop/api/management/... và DELETE /identity/api/v2/admin/...
#
# Bằng chứng: BFF audit log (job=bff-audit, event=rbac_denied) → Grafana rule
# "BFLA" → Grafana alert → incident-analyzer evidence bundle (attack_type=access_denied).
set -uo pipefail
SCENARIO="crapi_bfla"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"
crapi_preflight

J="$(crapi_login testuser01 'Test1234!')"
trap 'rm -f "$J"' EXIT
log "Đăng nhập testuser01 (realm role: crapi-user) — thử thao tác admin/management"

declare -a TRIES=(
  "POST /workshop/api/management/users/all"
  "POST /identity/api/v2/admin/videos/1"
  "DELETE /identity/api/v2/admin/videos/1"
  "PUT /workshop/api/management/shop/orders/1"
)
# §B1: PACE + INTERLEAVE. Holdout bfla_slowdrip_interleaved = rải chậm, XEN giữa
# hành động hợp lệ (đọc) để lẫn vào phiên bình thường. Train = burst thuần.
INTERLEAVE="${VP_INTERLEAVE_WITH_VALID:-false}"
READS_OK=(/identity/api/v2/user/dashboard /workshop/api/shop/products /community/api/v2/community/posts/recent)
log "PACE=${PACE:-burst} INTERLEAVE=$INTERLEAVE"
denied=0; _i=0; _n=${#TRIES[@]}
for t in "${TRIES[@]}"; do
  _i=$((_i + 1))
  [[ $_i -gt 1 ]] && crapi_pace_sleep "$_i" "$_n"
  if [[ "$INTERLEAVE" == "true" || "$INTERLEAVE" == "True" ]]; then
    crapi_call "$J" GET "${READS_OK[RANDOM % ${#READS_OK[@]}]}" >/dev/null   # đọc hợp lệ xen vào
  fi
  m="${t% *}"; p="${t#* }"
  code="$(crapi_call "$J" "$m" "$p" '{"x":1}')"
  log "  $m $p → HTTP $code"
  [[ "$code" == "403" ]] && denied=$((denied + 1))
done

[[ $denied -ge 3 ]] || fail "chỉ $denied/4 bị chặn (cần ≥3) — kiểm tra BFF _rbac_ok / OPA role_permits_action"
log "BFF + OPA từ chối $denied/4 — crapi-user không leo thang lên function admin/management"

sleep 3
n="$(loki_count '{job="bff-audit"} | json | event="rbac_denied"')"
log "BFF audit rbac_denied trong 10 phút: $n dòng → Loki"

pass "$SCENARIO — $denied/4 BFLA bị chặn · bff-audit rbac_denied → Loki · Grafana 'BFLA' → incident-analyzer evidence bundle"
