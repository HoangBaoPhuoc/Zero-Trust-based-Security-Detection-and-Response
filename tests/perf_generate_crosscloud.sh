#!/usr/bin/env bash
# Sinh traffic THẬT qua Gateway mTLS để có mẫu cho phép đo độ trễ cross-cloud
# (tests/perf_overhead.py [b]). Mỗi request nghiệp vụ tới workshop/community khiến các
# service này gọi identity (OpenStack) `POST /identity/api/auth/verify` qua WireGuard
# (KIEM-KE-HOP.md nhóm (a)) — log Envoy của cả 2 phía có `response_time` thật.
# Dùng: bash tests/perf_generate_crosscloud.sh [số vòng, mặc định 30]
set -uo pipefail
SCENARIO="perf_generate_crosscloud"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/lib/crapi_common.sh"
N="${1:-30}"
crapi_preflight
J="$(crapi_login testuser01 'Test1234!')"
trap 'rm -f "$J"' EXIT
ok=0
for _ in $(seq 1 "$N"); do
  a="$(crapi_call "$J" GET /workshop/api/shop/products)"
  b="$(crapi_call "$J" GET /community/api/v2/community/posts/recent)"
  [[ "$a" == 200 && "$b" == 200 ]] && ok=$((ok+1))
done
echo "[perf_generate_crosscloud] $ok/$N vòng có cả 2 request = 200"
