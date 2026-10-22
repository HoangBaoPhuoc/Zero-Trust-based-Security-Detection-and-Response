#!/usr/bin/env bash
# §B7 mục 5 — TIỀN KIỂM trước MỖI khúc (150h, chunk 10+).
#
# Ba việc, đúng thứ tự nêu trong B7:
#   1) crapi_preflight (tests/lib/crapi_common.sh) — cert thiết bị Device CA
#      còn hạn (tự phát hành lại nếu thiếu/<24h, TTL gốc 7 ngày) + BFF mTLS
#      phản hồi.
#   2) port-forward/Loki sẵn sàng — ĐÃ tự kiểm + tự hồi phục trong
#      collect_chunked.py (wait_preconditions/heal_port_forward) mỗi khi mở
#      khúc; kiểm lại ở đây chỉ để FAIL NHANH trước khi tốn công chạy workload.
#   3) decision log OPA ĐANG CHẢY THẬT — CHƯA có tự động hoá nào trước B7.
#      Độ tươi (fresh_counts) chỉ xác nhận CÓ dòng log mới, không xác nhận
#      log đó phản ánh quyết định OPA còn SINH RA (mesh có thể "tươi" bằng
#      log cũ gửi bù trong khi OPA đã treo). Gửi MỘT request cố ý bị từ chối,
#      xác nhận nó XUẤT HIỆN trong Loki opa-decisions trong vài giây.
#
# Dùng: bash tests/phaseb_chunk_preflight.sh
# Thoát ≠0 → KHÔNG mở khúc (gọi script này TRƯỚC collect_chunked.py mỗi khúc).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/crapi_common.sh
source "$HERE/lib/crapi_common.sh"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"

echo "[preflight] 1/3 crapi_preflight (cert thiết bị + BFF mTLS reachable)..."
crapi_preflight
echo "[preflight] 1/3 OK"

echo "[preflight] 2/3 Loki /ready..."
curl -fsS --max-time 10 "$LOKI_URL/ready" >/dev/null \
  || { echo "[preflight] FAIL: Loki không /ready tại $LOKI_URL — chạy scripts/k8s-tunnel.sh trước." >&2; exit 1; }
echo "[preflight] 2/3 OK"

echo "[preflight] 3/3 decision log OPA đang chảy — gửi 1 request cố ý bị từ chối..."
T0="$(date -u +%s)"
WEB_POD="$(crapi_pod crapi-web)"
if [[ -z "$WEB_POD" ]]; then
  echo "[preflight] FAIL: không tìm được pod crapi-web để gửi request kiểm." >&2
  exit 1
fi
# crapi-web KHÔNG phải PEP cho workshop trong service_acl.rego → OPA deny.
# Không quan tâm mã HTTP cụ thể ở client (mesh có thể trả 403 hoặc đóng kết
# nối) — chỉ cần OPA ra MỘT quyết định mới để kiểm log có ghi nó không.
kubectl --context "$KUBE_AWS" -n "$NS" exec "$WEB_POD" -c crapi-web -- \
  sh -c 'wget -q -O /dev/null -T6 http://crapi-workshop.crapi.svc.cluster.local:8000/workshop/api/shop/products' \
  >/dev/null 2>&1 || true

sleep 8   # đợi batch Promtail bay tới Loki
NOW="$(date -u +%s)"
FOUND="$(curl -fsS --max-time 10 "$LOKI_URL/loki/api/v1/query_range" \
    --data-urlencode 'query={job="opa-decisions"} |= "false"' \
    --data-urlencode "start=${T0}000000000" \
    --data-urlencode "end=${NOW}000000000" \
  | python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: print(0); sys.exit()
print(sum(len(r.get("values") or []) for r in d.get("data",{}).get("result",[])))' 2>/dev/null)"
FOUND="${FOUND:-0}"

if [[ "$FOUND" -lt 1 ]]; then
  echo "[preflight] FAIL: KHÔNG thấy quyết định deny nào trong Loki opa-decisions sau request cố ý bị từ chối trong $((NOW-T0))s — decision log có thể đã NGỪNG CHẢY dù mesh/Loki vẫn 'tươi'. KHÔNG mở khúc." >&2
  exit 1
fi
echo "[preflight] 3/3 OK — $FOUND dòng opa deny thấy trong Loki — decision log đang chảy thật."
echo "[preflight] TẤT CẢ OK — an toàn để mở khúc."
