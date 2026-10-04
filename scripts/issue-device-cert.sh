#!/usr/bin/env bash
# Phát hành client certificate ký bởi Device CA (A3 KEHOACH-THAYDOI-HETHONG.md)
# cho một thiết bị/demo-user — dùng để test client-cert mTLS ở Traefik biên
# (k8s/crapi/edge-tls.yaml) và posture/device_id BFF suy ra từ cert
# (services/bff/main.py: _evaluate_device_cert).
#
# Dùng:
#   scripts/issue-device-cert.sh <device-id> <compliant|non-compliant> [ttl-days]
#
# Định danh: SAN URI spiffe://ztlab.local/device/<device-id>.
# Posture:   Subject OU=posture:<compliant|non-compliant> (không dùng OID mở
#            rộng — Subject OU dễ debug bằng `openssl x509 -text` hơn).
# TTL mặc định 7 ngày (đề xuất KEHOACH — đủ ngắn để demo kịch bản cert hết hạn).
#
# Xuất ra $REPO_ROOT/deploy/vendor/device-ca/issued/<device-id>/:
#   device.crt device.key  — dùng trực tiếp với curl --cert/--key
#   device.p12             — import trình duyệt (Firefox/Chrome), passphrase rỗng
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_DIR="$REPO_ROOT/deploy/vendor/device-ca"

if [[ $# -lt 2 ]]; then
  echo "Dùng: $0 <device-id> <compliant|non-compliant> [ttl-days]" >&2
  exit 1
fi
DEVICE_ID="$1"
POSTURE="$2"
TTL_DAYS="${3:-7}"

case "$POSTURE" in
  compliant|non-compliant) ;;
  *) echo "posture phải là 'compliant' hoặc 'non-compliant', nhận: '$POSTURE'" >&2; exit 1 ;;
esac
if [[ ! "$DEVICE_ID" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "device-id chỉ được chứa chữ/số/-/_ , nhận: '$DEVICE_ID'" >&2
  exit 1
fi

if [[ ! -f "$CA_DIR/device-ca.key" || ! -f "$CA_DIR/device-ca.crt" ]]; then
  echo "Device CA chưa có tại $CA_DIR — chạy scripts/deploy-security-stack.sh (step 3.1) trước." >&2
  exit 1
fi

OUT_DIR="$CA_DIR/issued/$DEVICE_ID"
mkdir -p "$OUT_DIR"

openssl ecparam -name prime256v1 -genkey -noout -out "$OUT_DIR/device.key" 2>/dev/null
openssl req -new -key "$OUT_DIR/device.key" -out "$OUT_DIR/device.csr" \
  -subj "/C=VN/O=ZT-Lab/OU=posture:${POSTURE}/CN=${DEVICE_ID}" 2>/dev/null
openssl x509 -req -in "$OUT_DIR/device.csr" -CA "$CA_DIR/device-ca.crt" \
  -CAkey "$CA_DIR/device-ca.key" -CAcreateserial -days "$TTL_DAYS" \
  -out "$OUT_DIR/device.crt" \
  -extfile <(printf 'subjectAltName=URI:spiffe://ztlab.local/device/%s\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n' "$DEVICE_ID") 2>/dev/null
rm -f "$OUT_DIR/device.csr"

openssl pkcs12 -export -out "$OUT_DIR/device.p12" \
  -inkey "$OUT_DIR/device.key" -in "$OUT_DIR/device.crt" \
  -certfile "$CA_DIR/device-ca.crt" -passout pass: 2>/dev/null

chmod 600 "$OUT_DIR/device.key"
echo "[ OK ] Cert thiết bị '$DEVICE_ID' (posture=$POSTURE, TTL=${TTL_DAYS}d):"
echo "       $OUT_DIR/device.crt / device.key   (curl --cert/--key)"
echo "       $OUT_DIR/device.p12                (import trình duyệt — passphrase rỗng)"
echo "       CA cho --cacert / trình duyệt:      $CA_DIR/device-ca.crt"
