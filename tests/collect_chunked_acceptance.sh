#!/usr/bin/env bash
# Nghiệm thu mục 2.1 (đóng sổ 2026-10-04) — bộ thu chia khúc phải tự đánh dấu khúc bị gián đoạn.
# 3 khúc liên tiếp (mặc định 10 phút); giữa khúc 2 NGẮT WireGuard 120 s.
# Kỳ vọng: khúc 1 và 3 `valid`, khúc 2 `gap` và KHÔNG được cộng vào tổng giờ.
#
# Cách ngắt: iptables DROP UDP WireGuard (51820) trên os_gateway, CẢ hai chiều, 120 s. KHÔNG dùng
# `systemctl stop wg-quick@wg0`: wg-watchdog (mỗi phút) thấy `wg show` rỗng (hs=0) + ping peer lỗi
# → tự bật lại tunnel trong ≤ 60 s, nên "ngắt 2 phút" sẽ không thật sự kéo dài 2 phút. DROP gói giữ
# tunnel ở trạng thái "lên nhưng không có handshake" — 120 s < MAX_AGE 200 s của watchdog nên nó
# không can thiệp: đo đúng một sự cố mạng 2 phút.
#   bash tests/collect_chunked_acceptance.sh [phút_mỗi_khúc=10]
set -uo pipefail
cd "$(dirname "$0")/.."
MIN="${1:-10}"
OUT="results/${RESULTS_ROUND:-closeout}/chunked"; mkdir -p "$OUT"
TAG="acc$(date +%Y%m%d%H%M%S)"; LEDGER="$OUT/$TAG.ledger.jsonl"; LOG="$OUT/$TAG.log"
exec > >(tee "$LOG") 2>&1
INV=ansible/inventory/hosts.yml
RULE='-p udp --dport 51820'; RULE2='-p udp --sport 51820'
gw() { ansible -i "$INV" os_gateway -b -m shell -a "$1" 2>&1 | grep -v -E 'WARNING|^\s*$'; }
unblock() { gw "iptables -D INPUT $RULE -j DROP 2>/dev/null; iptables -D OUTPUT $RULE -j DROP 2>/dev/null; iptables -D INPUT $RULE2 -j DROP 2>/dev/null; iptables -D OUTPUT $RULE2 -j DROP 2>/dev/null; echo unblocked" >/dev/null; }
trap unblock EXIT

echo "[$(date -Is)] sổ cái: $LEDGER ; ${MIN} phút/khúc"
python3 tests/collect_chunked.py --ledger "$LEDGER" --chunks 3 --chunk-minutes "$MIN" --pause 5 &
COL=$!

# chờ khúc 2 bắt đầu, rồi ngắt ở khoảng 40 % thời lượng khúc
until grep -q '"event": "start", "chunk_id": "c0002' "$LEDGER" 2>/dev/null; do
  kill -0 $COL 2>/dev/null || { echo "bộ thu chết trước khúc 2"; exit 1; }; sleep 5
done
sleep $(( MIN * 60 * 4 / 10 ))
echo "[$(date -Is)] NGẮT WireGuard (DROP udp/51820 hai chiều trên os_gateway) 120 s"
T_CUT=$(date +%s)
gw "iptables -I INPUT 1 $RULE -j DROP; iptables -I OUTPUT 1 $RULE -j DROP; iptables -I INPUT 1 $RULE2 -j DROP; iptables -I OUTPUT 1 $RULE2 -j DROP; wg show wg0 latest-handshakes"
sleep 120
unblock
T_RESTORE=$(date +%s)
echo "[$(date -Is)] KHÔI PHỤC sau $((T_RESTORE - T_CUT)) s; handshake: $(gw 'sleep 15; wg show wg0 latest-handshakes' | tail -1)"
echo "cut_epoch=$T_CUT restore_epoch=$T_RESTORE" > "$OUT/$TAG.cut"

wait $COL
echo
python3 tests/collect_chunked.py --ledger "$LEDGER" --report
python3 - "$LEDGER" <<'EOF'
import json,sys
ends={}
for l in open(sys.argv[1]):
    r=json.loads(l)
    if r["event"]=="end": ends[r["chunk_id"][:5]]=r
st=[ends.get(k,{}).get("status") for k in ("c0001","c0002","c0003")]
ok = st==["valid","gap","valid"]
print(f"\nKẾT QUẢ NGHIỆM THU: trạng thái 3 khúc = {st} → {'PASS' if ok else 'FAIL'} (kỳ vọng ['valid','gap','valid'])")
sys.exit(0 if ok else 1)
EOF
