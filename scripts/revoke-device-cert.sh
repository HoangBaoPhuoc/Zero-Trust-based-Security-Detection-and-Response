#!/usr/bin/env bash
# Thu hồi cert thiết bị (Phần 3.2, remediation 2026-09-19).
#
# Device CA không hỗ trợ CRL thật (không muốn vá tầng TLS của Istio
# IngressGateway — đường vào DUY NHẤT của toàn hệ thống, rủi ro cấu hình sai
# cao hơn nhiều so với lợi ích). Thay vào đó: denylist ở tầng ứng dụng (bff
# đọc tươi mỗi request ghi, services/bff/main.py _revoked_device_ids) — có
# hiệu lực NGAY (không cần đợi hết TTL), kể cả cho phiên ĐANG hoạt động
# (không chỉ chặn lần đăng nhập tiếp theo).
#
# Dùng:
#   scripts/revoke-device-cert.sh <device-id>            # thu hồi
#   scripts/revoke-device-cert.sh <device-id> --unrevoke  # gỡ thu hồi
#   scripts/revoke-device-cert.sh --list                  # xem danh sách hiện tại
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
NS="crapi"
CM="device-revocation-list"

_current_json() {
  kubectl --context "$AWS_CONTEXT" -n "$NS" get configmap "$CM" \
    -o jsonpath='{.data.revoked\.json}' 2>/dev/null || echo '{"revoked_device_ids": []}'
}

if [[ "${1:-}" == "--list" ]]; then
  _current_json | python3 -m json.tool
  exit 0
fi

if [[ $# -lt 1 ]]; then
  echo "Dùng: $0 <device-id> [--unrevoke] | $0 --list" >&2
  exit 1
fi
DEVICE_ID="$1"
UNREVOKE="${2:-}"

NEW_JSON="$(_current_json | DEVICE_ID="$DEVICE_ID" UNREVOKE="$UNREVOKE" python3 -c '
import json, os, sys
d = json.load(sys.stdin)
ids = set(d.get("revoked_device_ids", []))
device_id = os.environ["DEVICE_ID"]
if os.environ.get("UNREVOKE") == "--unrevoke":
    ids.discard(device_id)
else:
    ids.add(device_id)
print(json.dumps({"revoked_device_ids": sorted(ids)}))
')"

kubectl --context "$AWS_CONTEXT" -n "$NS" create configmap "$CM" \
  --from-literal=revoked.json="$NEW_JSON" \
  --dry-run=client -o yaml | kubectl --context "$AWS_CONTEXT" apply -f -

if [[ "$UNREVOKE" == "--unrevoke" ]]; then
  echo "[revoke-device-cert] '$DEVICE_ID' đã GỠ khỏi danh sách thu hồi."
else
  echo "[revoke-device-cert] '$DEVICE_ID' đã bị THU HỒI — có hiệu lực trong ~60-90s"
  echo "  (kubelet đồng bộ ConfigMap volume vào pod bff, không cần restart)."
fi
echo "Danh sách hiện tại:"
echo "$NEW_JSON" | python3 -m json.tool
