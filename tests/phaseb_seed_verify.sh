#!/usr/bin/env bash
# Giai đoạn B §B1b — NGHIỆM THU seed nạn nhân: đếm được ≥N vehicleid RIÊNG BIỆT
# thuộc ≥N CHỦ khác nhau, PHÁT HIỆN ĐƯỢC qua community/posts/recent (đúng đường
# crapi_bola.sh dùng để chọn nạn nhân). Chạy SAU seed-job + sau khi N1 đã chạy
# một lúc (để các victim đăng bài, vehicleid lộ ra).
#
# Dùng: NEED=15 bash tests/phaseb_seed_verify.sh
set -uo pipefail
SCENARIO="seed_verify"
source "$(dirname "${BASH_SOURCE[0]}")/lib/crapi_common.sh"
NEED="${NEED:-15}"
ATTACKER="${ATTACKER:-testuser01}"
ATTACKER_EMAIL="${ATTACKER_EMAIL:-testuser01@ztlab.local}"
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-phaseb}/seed"; mkdir -p "$OUT"
crapi_preflight

J="$(crapi_login "$ATTACKER" 'Test1234!')"; trap 'rm -f "$J"' EXIT
mapfile -t TLS < <(crapi_curl_tls_opts)

# Quét nhiều trang community/posts/recent, gom (vehicleid, email) của NGƯỜI KHÁC.
OUTJSON="$OUT/seed-verify.json"
{ for off in $(seq 0 30 300); do
    curl -s -A "$BROWSER_UA" "${TLS[@]}" -b "$J" --max-time 20 \
      "$BFF_URL/community/api/v2/community/posts/recent?limit=30&offset=$off"; echo
  done; } | ATTACKER_EMAIL="$ATTACKER_EMAIL" OUTJSON="$OUTJSON" python3 -c '
import json, sys, os
seen = {}
atk = os.environ["ATTACKER_EMAIL"]
for line in sys.stdin:
    try: d = json.loads(line)
    except Exception: continue
    for p in d.get("posts", []):
        a = p.get("author") or {}
        vid, email = a.get("vehicleid"), a.get("email")
        if vid and email and email != atk:
            seen[vid] = email
owners = set(seen.values())
print(f"distinct_vehicleids={len(seen)} distinct_owners={len(owners)}")
for vid, em in sorted(seen.items()):
    print(f"  {vid}  {em}")
json.dump({"distinct_vehicleids": len(seen), "distinct_owners": len(owners),
           "pairs": seen}, open(os.environ["OUTJSON"], "w"), indent=2, ensure_ascii=False)
' 2>/dev/null || true
nv="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["distinct_vehicleids"])' "$OUTJSON" 2>/dev/null || echo 0)"
no="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["distinct_owners"])' "$OUTJSON" 2>/dev/null || echo 0)"
log "phát hiện $nv vehicleid / $no chủ (cần ≥ $NEED mỗi loại) → $OUTJSON"
if [[ "${nv:-0}" -ge "$NEED" && "${no:-0}" -ge "$NEED" ]]; then
  pass "$SCENARIO — đủ nạn nhân cho BOLA luân phiên ($nv vehicleid, $no chủ ≥ $NEED)"
else
  fail "$SCENARIO — THIẾU nạn nhân ($nv vehicleid, $no chủ < $NEED). Kiểm: seed-job claim xe (kubectl logs job/crapi-seed | grep '§B1b victims'); N1 đã chạy để victim đăng bài chưa?"
fi
