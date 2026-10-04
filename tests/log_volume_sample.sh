#!/usr/bin/env bash
# Mục 2.3 (đóng sổ 2026-10-04) — lấy mẫu tốc độ sinh log vào Loki để ngoại suy 150 giờ.
# Tổng quát hoá results/round4/log-volume/sample.sh (vốn viết cứng IP bastion + node Loki,
# cả hai đổi sau mỗi lần dựng lại): IP bastion lấy từ Terraform, node Loki/Prometheus lấy
# từ pod đang chạy, đường dẫn local-path lấy từ PV.
#
#   bash tests/log_volume_sample.sh <out.csv> [số_mẫu=13] [chu_kỳ_s=300]
#
# Mỗi dòng CSV: ts, bytes_received_total, lines_total, chunk_stored_total (metrics distributor/
# ingester của Loki), bytes5m_aws, bytes5m_openstack (LogQL bytes_over_time 5m — byte log THÔ),
# du_loki, du_prom (byte trên đĩa của thư mục PV), root_avail (byte trống / của node Loki).
# Phân tích: python3 tests/log_volume_analyze.py <out.csv>
set -uo pipefail
cd "$(dirname "$0")/.."
OUT="${1:?out.csv}"; N="${2:-13}"; PERIOD="${3:-300}"
P=/api/v1/namespaces/plg-stack/services/loki:3100/proxy
BASTION="$(terraform -chdir=terraform/aws output -raw aws_bastion_pip)"
SSHO="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=10 -i $HOME/.ssh/ztlab-key"
pv_path() { # <ns> <pvc> → đường dẫn local-path trên node
  local pv; pv="$(kubectl --context ctx-aws -n "$1" get pvc "$2" -o jsonpath='{.spec.volumeName}')"
  kubectl --context ctx-aws get pv "$pv" -o jsonpath='{.spec.local.path}{.spec.hostPath.path}'
}
node_ip() { # <ns> <selector>
  local n; n="$(kubectl --context ctx-aws -n "$1" get pod -l "$2" -o jsonpath='{.items[0].spec.nodeName}')"
  kubectl --context ctx-aws get node "$n" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'
}
LOKI_NODE="$(node_ip plg-stack app=loki)"; PROM_NODE="$(node_ip monitoring app=prometheus)"
LOKI_DIR="$(pv_path plg-stack loki-data-pvc)"; PROM_DIR="$(pv_path monitoring prometheus-data-pvc)"
echo "# loki=$LOKI_NODE:$LOKI_DIR prom=$PROM_NODE:$PROM_DIR bastion=$BASTION" >&2
du_on() { ssh $SSHO -J "ubuntu@$BASTION" "ubuntu@$1" "sudo du -s --block-size=1 '$2' | cut -f1; df --output=avail -B1 / | tail -1" 2>/dev/null | paste -sd,; }
Q=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("sum by (cloud) (bytes_over_time({cloud=~\".+\"}[5m]))"))')
[ -f "$OUT" ] || echo "ts,bytes_received_total,lines_total,chunk_stored_total,bytes5m_aws,bytes5m_openstack,du_loki,du_prom,root_avail" > "$OUT"
for i in $(seq 1 "$N"); do
  ts=$(date +%s)
  m=$(kubectl --context ctx-aws get --raw "$P/metrics" 2>/dev/null)
  br=$(awk '/^loki_distributor_bytes_received_total/{s+=$2} END{print s+0}' <<<"$m")
  lr=$(awk '/^loki_distributor_lines_received_total/{s+=$2} END{print s+0}' <<<"$m")
  cs=$(awk '/^loki_ingester_chunk_stored_bytes_total/{s+=$2} END{print s+0}' <<<"$m")
  q=$(kubectl --context ctx-aws get --raw "$P/loki/api/v1/query?query=$Q" 2>/dev/null)
  ba=$(python3 -c 'import json,sys;d=json.load(sys.stdin);print(next((r["value"][1] for r in d["data"]["result"] if r["metric"].get("cloud")=="aws"),0))' <<<"$q" 2>/dev/null)
  bo=$(python3 -c 'import json,sys;d=json.load(sys.stdin);print(next((r["value"][1] for r in d["data"]["result"] if r["metric"].get("cloud")=="openstack"),0))' <<<"$q" 2>/dev/null)
  l=$(du_on "$LOKI_NODE" "$LOKI_DIR"); p=$(du_on "$PROM_NODE" "$PROM_DIR")
  echo "$ts,$br,$lr,$cs,$ba,$bo,${l%%,*},${p%%,*},${l##*,}" >> "$OUT"
  [ "$i" -lt "$N" ] && sleep "$PERIOD"
done
