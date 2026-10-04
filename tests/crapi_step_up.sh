#!/usr/bin/env bash
# KỊCH BẢN — Step-up Authentication (dynamic policy, tenet 7)
#
# Lớp Zero-Trust nghiệm thu: OPA `sensitive_crapi_action` + `step_up_ok`
# (`acr == "high"`) VÀ BFF `_is_sensitive`. Hành động nhạy cảm (đặt hàng, đổi
# email/mật khẩu) với phiên `acr=1` (login thường) → 401 `step_up_required`;
# chỉ qua sau khi xác thực lại OTP (`acr=high`).
#
# Tấn công THẬT: login testuser01 (KHÔNG step-up) → POST
# /workshop/api/shop/orders và /identity/api/v2/user/reset-password.
#
# Bằng chứng: BFF audit `event=step_up_required` + OPA decision result:false.
# Đây KHÔNG phải "tấn công bị chặn" mà là chốt kiểm soát động — đưa vào demo
# để cho thấy cùng token vẫn bị giới hạn theo mức đảm bảo xác thực.
set -uo pipefail
SCENARIO="crapi_step_up"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"
crapi_preflight

J="$(crapi_login testuser01 'Test1234!')"
trap 'rm -f "$J"' EXIT
log "Đăng nhập testuser01 — phiên acr=1 (không step-up)"

echo -n "  đọc thường  GET /workshop/api/shop/products : "; r1="$(crapi_call "$J" GET /workshop/api/shop/products)"; echo "$r1"
echo -n "  nhạy cảm   POST /workshop/api/shop/orders   : "; r2="$(crapi_call "$J" POST /workshop/api/shop/orders '{"product_id":1,"quantity":1}')"; echo "$r2"
echo -n "  nhạy cảm   POST /identity/api/v2/user/reset-password : "; r3="$(crapi_call "$J" POST /identity/api/v2/user/reset-password '{"password":"x","c_password":"x"}')"; echo "$r3"

[[ "$r1" =~ ^(200|404)$ ]] || fail "đọc thường bị chặn ($r1) — không mong đợi (device browser, RBAC ok)"
[[ "$r2" == "401" && "$r3" == "401" ]] || fail "hành động nhạy cảm KHÔNG bị đòi step-up (orders=$r2 reset-pw=$r3) — kiểm tra OPA sensitive_crapi_action / BFF _is_sensitive"
log "Đọc thường qua ($r1); 2/2 hành động nhạy cảm → 401 step_up_required (cần acr=high)"

sleep 3
n="$(loki_count '{job="bff-audit"} | json | event="step_up_required"')"
log "BFF audit step_up_required trong 10 phút: $n dòng → Loki"

pass "$SCENARIO — step-up bắt buộc cho hành động nhạy cảm (2/2), đọc thường không ảnh hưởng"
