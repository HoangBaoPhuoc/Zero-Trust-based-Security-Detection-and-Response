#!/usr/bin/env bash
# Mục 1 vòng 2026-09-29 — nghiệm thu đường log OpenStack → Loki (WireGuard → NodePort 31000).
#
# 1. Chạy pod `logseq` trên cụm OpenStack (ns plg-stack) in "logseq seq=N" mỗi 0,5 s.
# 2. Sau WARMUP giây: dừng wg-quick@wg0 trên os_gateway OUTAGE giây rồi bật lại.
# 3. Chờ DRAIN giây cho Promtail retry đẩy hết, rồi hỏi Loki toàn bộ seq đã nhận.
# 4. PASS nếu dãy seq liên tục (không thiếu số nào) từ đầu tới cuối cửa sổ.
#
# Dùng: tests/log_pipeline_outage.sh [OUTAGE=60] ; kết quả vào results/round4/log-pipeline/
set -euo pipefail
OUTAGE="${1:-60}"
WARMUP="${WARMUP:-60}"
DRAIN="${DRAIN:-120}"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"
OS_GW="${OS_GW:-$(ansible-inventory -i "$(dirname "${BASH_SOURCE[0]}")/../ansible/inventory/hosts.yml" --host os_gateway 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)[\"ansible_host\"])")}"
OS_KEY="${OS_KEY:-$HOME/.ssh/ztlab-key}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-closeout}/log-pipeline"
mkdir -p "$OUT"
TAG="run$(date +%Y%m%d%H%M%S)"
LOG="$OUT/$TAG.log"
exec > >(tee "$LOG") 2>&1

SSHO=(-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=10 -i "$OS_KEY")
P=/api/v1/namespaces/plg-stack/services/loki:3100/proxy

cleanup() { kubectl --context "$OS_CONTEXT" -n plg-stack delete pod logseq --ignore-not-found --wait=false >/dev/null 2>&1 || true
            ssh "${SSHO[@]}" "ubuntu@$OS_GW" 'sudo systemctl start wg-quick@wg0' >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[$(date -Is)] tag=$TAG outage=${OUTAGE}s warmup=${WARMUP}s drain=${DRAIN}s"
kubectl --context "$OS_CONTEXT" -n plg-stack delete pod logseq --ignore-not-found >/dev/null
kubectl --context "$OS_CONTEXT" -n plg-stack run logseq --image=busybox:1.36 --restart=Never \
  --labels=app=logseq -- sh -c "i=0; while true; do i=\$((i+1)); echo \"logseq $TAG seq=\$i\"; sleep 0.5; done"
kubectl --context "$OS_CONTEXT" -n plg-stack wait --for=condition=Ready pod/logseq --timeout=120s
T0=$(date +%s)
echo "[$(date -Is)] logseq running; warmup ${WARMUP}s"
sleep "$WARMUP"

echo "[$(date -Is)] STOP wg-quick@wg0 on os_gateway"
ssh "${SSHO[@]}" "ubuntu@$OS_GW" 'sudo systemctl stop wg-quick@wg0 && sudo wg show 2>&1 | head -1 || true'
TSTOP=$(date +%s)
sleep "$OUTAGE"
ssh "${SSHO[@]}" "ubuntu@$OS_GW" 'sudo systemctl start wg-quick@wg0 && sudo wg show wg0 | grep -E "latest handshake|endpoint" || true'
TSTART=$(date +%s)
echo "[$(date -Is)] START wg-quick@wg0 (down $((TSTART-TSTOP))s); drain ${DRAIN}s"
sleep "$DRAIN"

kubectl --context "$OS_CONTEXT" -n plg-stack delete pod logseq --wait=false >/dev/null
sleep 5
LAST_LOCAL=$(kubectl --context "$OS_CONTEXT" -n plg-stack logs logseq 2>/dev/null | tail -1 | sed -n 's/.*seq=//p' || true)
T1=$(date +%s)

Q=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "{cloud=\"openstack\", pod=\"logseq\"} |= \"$TAG\"")
kubectl --context "$AWS_CONTEXT" get --raw \
  "$P/loki/api/v1/query_range?limit=50000&direction=forward&start=$((T0-60))000000000&end=$((T1+60))000000000&query=$Q" \
  > "$OUT/$TAG.loki.json"

python3 - "$OUT/$TAG.loki.json" "$TSTOP" "$TSTART" "$TAG" <<'EOF'
import json, re, sys
d = json.load(open(sys.argv[1])); tstop, tstart, tag = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
seqs, in_outage = set(), set()
for s in d["data"]["result"]:
    for ts, line in s["values"]:
        m = re.search(r"seq=(\d+)", line)
        if not m: continue
        n = int(m.group(1)); seqs.add(n)
        if tstop <= int(ts) // 10**9 <= tstart: in_outage.add(n)
if not seqs:
    print("FAIL: Loki không có dòng logseq nào"); sys.exit(1)
lo, hi = min(seqs), max(seqs)
missing = sorted(set(range(lo, hi + 1)) - seqs)
print(f"received={len(seqs)} range={lo}..{hi} missing={len(missing)} "
      f"lines_timestamped_during_outage={len(in_outage)}")
if missing: print("missing seq (first 50):", missing[:50])
print("PASS" if not missing and lo == 1 and in_outage else "FAIL")
sys.exit(0 if not missing and lo == 1 and in_outage else 1)
EOF
