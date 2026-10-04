#!/usr/bin/env bash
# Mục 9 vòng 2026-09-29 — CHẨN ĐOÁN (không phải cấu hình vận hành): tắt TẠM decision
# log console của OPA AWS, đo lại 1 lượt tests/perf_overhead.py, rồi KHÔI PHỤC nguyên
# trạng (decision log là nguồn telemetry của khoá luận — không bao giờ để tắt).
# Khôi phục chạy trong trap EXIT, kể cả khi đo lỗi/Ctrl-C, và kiểm lại sau khi khôi phục.
#
# Dùng: tests/perf_opa_decision_log_diag.sh <output.json> [n]
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?output json}"; N="${2:-2000}"
CTX=ctx-aws
SAVED="$(mktemp)"
kubectl --context $CTX -n crapi get configmap opa-config -o jsonpath='{.data.opa-config\.yaml}' > "$SAVED"
grep -q "console: true" "$SAVED" || { echo "opa-config hiện KHÔNG có console: true — dừng (không rõ nguyên trạng)"; exit 1; }

restore() {
  echo "[restore] khôi phục opa-config nguyên trạng + restart opa-server"
  kubectl --context $CTX -n crapi create configmap opa-config --from-file=opa-config.yaml="$SAVED" \
    --dry-run=client -o yaml | kubectl --context $CTX apply -f -
  kubectl --context $CTX -n crapi rollout restart deploy/opa-server
  kubectl --context $CTX -n crapi rollout status deploy/opa-server --timeout=300s
  now="$(kubectl --context $CTX -n crapi get configmap opa-config -o jsonpath='{.data.opa-config\.yaml}')"
  if [[ "$now" == "$(cat "$SAVED")" ]]; then echo "[restore] OK — decision_logs.console: true đã trở lại"
  else echo "[restore] CẢNH BÁO: opa-config KHÁC nguyên trạng — kiểm tay!"; fi
  rm -f "$SAVED"
  # Xác nhận SỐNG (đóng sổ 2026-10-04): text ConfigMap đúng chưa đủ — phải thấy decision MỚI của OPA AWS
  # trong Loki job=opa-decisions sau thời điểm khôi phục. Tạo 1 decision bằng request bff → crapi-web.
  local t_restore; t_restore=$(date +%s); sleep 10
  kubectl --context $CTX -n crapi exec deploy/bff -c bff -- python -c \
    "import urllib.request;urllib.request.urlopen('http://crapi-web.crapi.svc.cluster.local/?dlprobe=$t_restore',timeout=10)" >/dev/null 2>&1
  local n=0 i
  for i in $(seq 1 12); do
    sleep 5
    n=$(curl -s -G http://127.0.0.1:13100/loki/api/v1/query_range \
          --data-urlencode 'query={job="opa-decisions",cloud="aws"}' --data-urlencode "start=${t_restore}000000000" \
          --data-urlencode "limit=5" | python3 -c 'import json,sys;print(sum(len(r["values"]) for r in json.load(sys.stdin)["data"]["result"]))' 2>/dev/null || echo 0)
    [[ "${n:-0}" -gt 0 ]] && break
  done
  if [[ "${n:-0}" -gt 0 ]]; then echo "[restore] XÁC NHẬN SỐNG: decision log OPA AWS đã chảy lại vào Loki (≥ $n dòng sau khôi phục)"
  else echo "[restore] LỖI: KHÔNG thấy decision log OPA AWS trong Loki 60 s sau khôi phục — kiểm tay NGAY (telemetry Giai đoạn C)"; return 1; fi
}
trap restore EXIT

sed 's/console: true/console: false/' "$SAVED" > "$SAVED.off"
kubectl --context $CTX -n crapi create configmap opa-config --from-file=opa-config.yaml="$SAVED.off" \
  --dry-run=client -o yaml | kubectl --context $CTX apply -f -
rm -f "$SAVED.off"
kubectl --context $CTX -n crapi rollout restart deploy/opa-server
kubectl --context $CTX -n crapi rollout status deploy/opa-server --timeout=300s
sleep 20
python3 "$REPO_ROOT/tests/perf_overhead.py" --n "$N" --skip-crosscloud --output "$OUT"
