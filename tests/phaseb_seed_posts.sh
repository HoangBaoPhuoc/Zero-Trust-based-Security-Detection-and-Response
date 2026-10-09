#!/usr/bin/env bash
# Giai đoạn B §B1f — mỗi victim đăng 1 bài community NGAY sau deploy để vehicleid
# phát hiện được qua community/posts/recent (crapi_bola.sh chọn nạn nhân) mà
# KHÔNG phụ thuộc N1 chạy bao lâu. Chạy trong PHA 0 (trước cổng).
#
# VÌ SAO KHÔNG làm trong seed-job.yaml (dù prompt đề nghị): seed-job chạy ở
# OpenStack (cạnh identity), còn crapi-community ở AWS. service-graph KHÔNG có
# edge cross-cloud openstack/crapi-seed → aws/crapi-community (crapi-seed là
# spire_only, không mô hình hoá egress tới community) → OPA/mesh CHẶN; cũng không
# có Service selectorless/NodePort community tới được từ OpenStack. Đường DUY
# NHẤT tới community là qua Istio IngressGateway mTLS (cần device cert) — nên
# phải chạy từ terminal như N1, không chạy được từ Job trong cụm OpenStack.
# (Đây là ràng buộc kiến trúc thật, không phải thiếu sót — xem service-graph-crapi.yaml.)
#
# Dùng: bash tests/phaseb_seed_posts.sh         # đăng cho victim01..15
set -uo pipefail
SCENARIO="seed_posts"
source "$(dirname "${BASH_SOURCE[0]}")/lib/crapi_common.sh"
VICTIM_POOL=($(for k in $(seq -w 1 15); do echo "victim$k"; done))
crapi_preflight

posted=0; nohave=0
for u in "${VICTIM_POOL[@]}"; do
  jar="$(crapi_login "$u" 'Test1234!' 2>/dev/null)" || { log "  $u: login lỗi"; continue; }
  # author.vehicleid trong bài chỉ có khi user ĐÃ claim xe (seed-job §B1b). Cảnh
  # báo nếu chưa có xe — vehicleid sẽ không lộ ra, bola không phát hiện được.
  own="$(curl -s -A "$BROWSER_UA" $(crapi_curl_tls_opts) -b "$jar" --max-time 20 \
        "$BFF_URL/identity/api/v2/vehicle/vehicles" 2>/dev/null \
        | grep -oE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' | head -1)"
  [[ -z "$own" ]] && { nohave=$((nohave+1)); log "  $u: CHƯA có xe (seed claim lỗi?) — bỏ"; rm -f "$jar"; continue; }
  code="$(crapi_call "$jar" POST /community/api/v2/community/posts \
        "{\"title\":\"xin chào từ $u\",\"content\":\"bài giới thiệu của $u\"}")"
  [[ "$code" == "200" || "$code" == "201" ]] && { posted=$((posted+1)); log "  $u: đăng bài OK ($code)"; } \
    || log "  $u: đăng bài lỗi ($code)"
  rm -f "$jar"
done
log "đăng bài: $posted/${#VICTIM_POOL[@]} (chưa có xe: $nohave)"
if [[ "$posted" -ge 15 ]]; then
  pass "$SCENARIO — $posted victim đã đăng bài; chạy phaseb_seed_verify.sh NEED=15 để xác nhận phát hiện"
else
  fail "$SCENARIO — chỉ $posted/15 đăng được (chưa có xe: $nohave). Kiểm seed-job claim xe (kubectl logs job/crapi-seed | grep '§B1b victims') + Keycloak victim (deploy-crapi.sh)."
fi
