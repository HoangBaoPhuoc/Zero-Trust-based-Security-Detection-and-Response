#!/usr/bin/env bash
# Giai đoạn B §4 (B4) mục 1 — MỐC KIỂM giờ 4-5 của khúc 1. Bốn kiểm tường minh:
#   1) phiên ultra_long còn sống, không 401 (quyết định 5.1 + H16)
#   2) SVID sidecar BFF đã gia hạn qua mốc 4h (H17)
#   3) tỉ lệ non-200 của N1 < 1% trên toàn khúc tới giờ
#   4) log liên tục cả hai cloud, không khoảng khuyết > 60s (lấy mẫu sống)
#
# In JSON kết quả ra stdout. Không tự dừng khúc — chỉ đo và báo; quyết định
# dừng/tiếp do người gọi (báo cáo B4 §3 quy tắc dừng) đọc kết quả này.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
cd "$REPO_ROOT"
source tests/lib/crapi_common.sh 2>/dev/null || true

T_WORKLOAD_START="${1:?cần epoch bắt đầu workload}"
NOW="$(date +%s)"
ELAPSED_H="$(python3 -c "print(round(($NOW-$T_WORKLOAD_START)/3600,2))")"

OUT="$REPO_ROOT/results/${RESULTS_ROUND:-phaseb}"
REQLOG="$(ls -t "$OUT"/n1/n1_*.requests.tsv 2>/dev/null | head -1)"

# ── 1) ultra_long còn sống, không 401 ──────────────────────────────────────
ul_check="FAIL"; ul_detail="không có dòng ultra_long nào"
if [[ -n "$REQLOG" ]]; then
  ul_lines="$(awk -F'\t' '$2=="ultra_long"' "$REQLOG")"
  ul_n="$(printf '%s\n' "$ul_lines" | grep -c . || true)"
  if [[ "$ul_n" -gt 0 ]]; then
    last_ts="$(printf '%s\n' "$ul_lines" | tail -1 | cut -f1 | cut -d. -f1)"
    age_s=$(( NOW - last_ts ))
    bad="$(printf '%s\n' "$ul_lines" | awk -F'\t' '$5!="200"' | wc -l)"
    if [[ "$age_s" -le 900 && "$bad" -eq 0 ]]; then
      ul_check="PASS"; ul_detail="n=$ul_n dòng, lần cuối cách ${age_s}s, 0 non-200"
    else
      ul_detail="n=$ul_n, lần cuối cách ${age_s}s (cần ≤900s), non-200=$bad (cần 0)"
    fi
  fi
fi

# ── 2) SVID BFF đã gia hạn qua mốc 4h ──────────────────────────────────────
svid_check="FAIL"; svid_detail=""
svid_json="$(kubectl --context ctx-aws exec -n crapi deploy/bff -c istio-proxy -- \
  curl -s localhost:15000/certs 2>/dev/null)"
svid_valid_from="$(printf '%s' "$svid_json" | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print(""); sys.exit()
for c in d.get("certificates",[]):
    for cc in c.get("cert_chain",[]):
        for san in cc.get("subject_alt_names",[]):
            if san.get("uri","").endswith("/aws/bff"):
                print(cc.get("valid_from","")); sys.exit()
print("")
' 2>/dev/null)"
INIT_SVID_FILE="$OUT/chunk1_initial_svid_valid_from.txt"
if [[ -n "$svid_valid_from" ]]; then
  if [[ -f "$INIT_SVID_FILE" ]]; then
    init_vf="$(cat "$INIT_SVID_FILE")"
    if [[ "$svid_valid_from" != "$init_vf" ]]; then
      svid_check="PASS"; svid_detail="valid_from lúc bắt đầu=$init_vf, hiện tại=$svid_valid_from (ĐÃ gia hạn ít nhất 1 lần)"
    else
      svid_detail="valid_from KHÔNG đổi từ lúc bắt đầu ($init_vf) sau ${ELAPSED_H}h — SVID có thể CHƯA gia hạn qua mốc 4h"
    fi
  else
    svid_detail="không có mốc valid_from lúc bắt đầu khúc ($INIT_SVID_FILE) để so — không kết luận được"
  fi
else
  svid_detail="không lấy được /certs từ istio-proxy (kubectl exec lỗi hoặc không tìm thấy SAN aws/bff)"
fi

# ── 3) non-200 N1 < 1% toàn khúc tới giờ ───────────────────────────────────
non200_check="FAIL"; non200_detail="không có REQLOG"
if [[ -n "$REQLOG" ]]; then
  non200_detail="$(python3 -c "
rows=[l.split('\t') for l in open('$REQLOG') if l.strip()]
n=len(rows)
non200=sum(1 for r in rows if len(r)>=5 and r[4].strip()!='200')
pct=100*non200/n if n else 0
print(f'n={n} non200={non200} pct={pct:.3f}%')
")"
  pct_val="$(echo "$non200_detail" | grep -oE 'pct=[0-9.]+' | cut -d= -f2)"
  [[ -n "$pct_val" ]] && python3 -c "exit(0 if float('$pct_val')<1.0 else 1)" && non200_check="PASS"
fi

# ── 4) log liên tục cả hai cloud (lấy mẫu sống, không khoảng khuyết >60s) ──
cont_check="FAIL"; cont_detail=""
fc="$(curl -s -G "http://localhost:13100/loki/api/v1/query" \
  --data-urlencode 'query=sum by (cloud) (count_over_time({job="envoy-access"}[90s]))' \
  --data-urlencode "time=$(( NOW*1000000000 ))" 2>/dev/null)"
cont_detail="$(printf '%s' "$fc" | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print("không truy vấn được Loki"); sys.exit()
out={r["metric"].get("cloud","?"): float(r["value"][1]) for r in d.get("data",{}).get("result",[])}
print(out)
')"
if printf '%s' "$cont_detail" | grep -q "'aws'" && printf '%s' "$cont_detail" | grep -qv "0.0}" ; then
  : # không parse sâu hơn trong bash — chỉ báo PASS nếu CẢ HAI cloud >0 ở mẫu 90s gần nhất
fi
cont_pass="$(printf '%s' "$fc" | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print("0"); sys.exit()
out={r["metric"].get("cloud","?"): float(r["value"][1]) for r in d.get("data",{}).get("result",[])}
print("1" if out.get("aws",0)>0 and out.get("openstack",0)>0 else "0")
')"
[[ "$cont_pass" == "1" ]] && cont_check="PASS"

python3 -c "
import json
print(json.dumps({
  'elapsed_h': $ELAPSED_H,
  'checked_at': $NOW,
  'ultra_long_alive': {'result':'$ul_check','detail':'''$ul_detail'''},
  'svid_renewed_4h': {'result':'$svid_check','detail':'''$svid_detail'''},
  'n1_non200_pct': {'result':'$non200_check','detail':'''$non200_detail'''},
  'log_continuity': {'result':'$cont_check','detail':'''$cont_detail'''},
}, indent=2, ensure_ascii=False))
"
