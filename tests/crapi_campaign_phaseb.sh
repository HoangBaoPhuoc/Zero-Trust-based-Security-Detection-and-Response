#!/usr/bin/env bash
# Giai đoạn B §4 — BỘ CHẠY CHIẾN DỊCH TẤN CÔNG A.
#
# Đọc nhóm biến thể từ policy/variant-split.yaml (§0.2, KHÔNG hardcode) và chạy
# từng lượt qua tests/crapi_run_campaign.sh (ghi runs.jsonl có variant_group +
# status attack/aborted + t_end làm tròn lên +1s). Mỗi lượt:
#   - run_id riêng (crapi_run_campaign.sh sinh)
#   - cách lượt trước ≥ --gap giây (mặc định 300s = 5' để KHÔNG chồng cửa sổ alert)
#   - tham số hoá: PACE + các param trong variant-split.yaml truyền thành biến môi
#     trường VP_<KEY> (scenario opt-in đọc) + PACE/DURATION_MIN (knob chung).
#
# CHẠY XEN trong lưu lượng nền: KHÔNG tự sinh N1/N2 — chạy bộ sinh nền
# (crapi_load_n1.sh + crapi_noise_n2.sh) ở TERMINAL KHÁC trước, rồi chạy file này.
# Nếu chạy trên hệ thống rảnh, mô hình học "có tải = bình thường" (§4).
#
# §B1c — QUY TẮC CHỒNG LƯỢT (thực thi, không chỉ tài liệu):
#   - Cửa sổ đặc trưng rộng nhất = 10 phút → GAP giữa hai lượt ≥ 600s. Mặc định
#     của file này là 600 (chế độ ĐỢT DÀI). Nếu một cửa sổ chứa cả lượt train
#     (burst) lẫn holdout (slow_drip) thì cửa sổ thuộc CẢ HAI nhóm → ranh giới
#     train/holdout rò, con số 70% mất nghĩa.
#   - Trong suốt một lượt slow_drip (DURATION_MIN thật 30'), KHÔNG lượt nào khác
#     khởi động: file này chạy các lượt TUẦN TỰ (crapi_run_campaign.sh chặn tới
#     khi scenario xong), nên điều này được BẢO ĐẢM về cấu trúc — cộng thêm GAP
#     ≥600 sau mỗi lượt. (Nền N1/N2 vẫn chạy song song — đó là chủ đích "xen".)
#   - CỔNG 2 GIỜ: được phép --gap 120 (gán nhãn OFFLINE theo runs.jsonl nên gap
#     ngắn KHÔNG sai nhãn; chỉ có thể chồng cửa sổ alert — chấp nhận ở cổng).
#
# Dùng:
#   ĐỢT DÀI (150h): bash tests/crapi_campaign_phaseb.sh --repeat N          # gap mặc định 600
#   CỔNG 2 GIỜ:     bash tests/crapi_campaign_phaseb.sh --repeat 1 --gap 120 --duration-min 3
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
SPLIT_FILE="${SPLIT_FILE:-$REPO_ROOT/policy/variant-split.yaml}"

REPEAT=2 ; GAP=600 ; SEL_GROUPS="train,holdout" ; FAMILIES="" ; DRY=0 ; DUR_CAP=""  # §B1c: gap mặc định 600 (10' cửa sổ)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repeat)   REPEAT="$2"; shift 2 ;;
    --gap)      GAP="$2"; shift 2 ;;
    --groups)   SEL_GROUPS="$2"; shift 2 ;;
    --families) FAMILIES="$2"; shift 2 ;;
    # §B1: giới hạn DURATION_MIN cho slow_drip. variant-split.yaml đặt 30' (giá
    # trị thật đợt 150h); cổng 2h KHÔNG đủ thời gian cho 30'×nhiều họ → dùng
    # --duration-min 3 để slow_drip ngắn mà VẪN khác burst rõ rệt (nghiệm thu
    # phaseb_pace_accept.py vẫn PASS). KHÔNG đặt cho đợt dài.
    --duration-min) DUR_CAP="$2"; shift 2 ;;
    --dry-run)  DRY=1; shift ;;
    *) echo "tham số lạ: $1" >&2; exit 1 ;;
  esac
done

[[ -f "$SPLIT_FILE" ]] || { echo "Không thấy $SPLIT_FILE" >&2; exit 1; }

# §B1c: chế độ. Có --duration-min = CỔNG (slow_drip rút ngắn, gap ngắn OK).
# Không có = ĐỢT DÀI → bắt buộc GAP ≥600 (cửa sổ đặc trưng 10') để không rò
# ranh giới train/holdout. Cảnh báo nếu vi phạm.
if [[ -z "$DUR_CAP" && "$GAP" -lt 600 ]]; then
  echo "[campaign] ⚠ ĐỢT DÀI nhưng --gap=$GAP < 600s: cửa sổ 10' có thể chứa cả burst lẫn slow_drip → RÒ ranh giới train/holdout. Dùng --gap 600 (hoặc --duration-min cho chế độ cổng)." >&2
fi

# Trích danh sách lượt từ YAML: mỗi dòng TSV = family scenario group variant_id pace params_json
#
# §B6 mục 3.3 — ROOT CAUSE (phân tích mốc 50h, 2026-10-16): thứ tự cũ là
# FAMILY-MAJOR (hết mọi lượt bola mới sang bfla, ... tới access_denied_spike,
# privilege_escalation, large_response ở CUỐI danh sách YAML), rồi lặp
# --repeat. Một khúc có hạn giờ (collect_chunked.py SIGTERM cả group đúng lúc
# hết CHUNK_MINUTES) CẮT Ở GẦN NHƯ CÙNG VỊ TRÍ trong thứ tự này mỗi lần →
# access_denied_spike/privilege_escalation/large_response (cuối danh sách)
# nhận ít lượt hơn hẳn KHÔNG PHẢI vì được cấp ít tấn công hơn mà vì CHƯA BAO
# GIỜ TỚI LƯỢT trước khi bị cắt (9 khúc: holdout:denied_slowdrip=2,
# exfil_*=1/1). Xếp ROUND-ROBIN qua các family (xen train/holdout trong từng
# family) để MỌI family có lượt SỚM trong hàng đợi bất kể cắt ở đâu — KHÔNG
# đổi policy/variant-split.yaml (đã đóng băng), chỉ đổi THỨ TỰ cấp lượt.
mapfile -t VARIANTS < <(python3 - "$SPLIT_FILE" "$SEL_GROUPS" "$FAMILIES" <<'PY'
import sys, json, yaml
split_file, groups_csv, fams_csv = sys.argv[1], sys.argv[2], sys.argv[3]
groups = set(g.strip() for g in groups_csv.split(",") if g.strip())
fams = set(f.strip() for f in fams_csv.split(",") if f.strip())
doc = yaml.safe_load(open(split_file))

fam_queues = []
for fam in doc["families"]:
    if fams and fam["name"] not in fams:
        continue
    tr = list(fam.get("train") or [])
    ho = list(fam.get("holdout") or [])
    seq = []
    for t, h in zip(tr, ho):
        if "train" in groups: seq.append(("train", t))
        if "holdout" in groups: seq.append(("holdout", h))
    if "train" in groups:
        seq += [("train", v) for v in tr[len(ho):]]
    if "holdout" in groups:
        seq += [("holdout", v) for v in ho[len(tr):]]
    if seq:
        fam_queues.append((fam["name"], fam["scenario"], seq))

maxlen = max((len(q) for _, _, q in fam_queues), default=0)
for idx in range(maxlen):
    for name, scenario, seq in fam_queues:
        if idx < len(seq):
            grp, v = seq[idx]
            print("\t".join([
                name, scenario, grp, v["id"],
                v.get("pace", ""), json.dumps(v.get("params") or {}, ensure_ascii=False),
            ]))
PY
)

[[ ${#VARIANTS[@]} -gt 0 ]] || { echo "Không có biến thể khớp --groups=$SEL_GROUPS --families=${FAMILIES:-*}" >&2; exit 1; }

# Giai đoạn C (sửa đường tắt entity): luân phiên kẻ tấn công BOLA qua pool —
# giữ ĐỒNG BỘ với CRAPI_ATTACKER_POOL trong tests/lib/crapi_common.sh. CHỈ áp
# cho họ bola: chỉ crapi_bola.sh đọc CRAPI_ATTACKER và đăng nhập bằng tài khoản
# đó; các họ khác vẫn đăng nhập testuser01 trong script của chúng, nên đặt
# CRAPI_ATTACKER cho chúng sẽ khiến target_entity (nhãn) LỆCH với entity thật
# trong log → gán nhãn sai. BOLA là mục tiêu ML của đề cương; các họ khác bị
# ml/evaluate.py prepare() loại khỏi tập đánh giá nên không cần luân phiên.
read -r -a ATTACKER_POOL <<<"${CRAPI_ATTACKER_POOL:-testuser01 testuser02 merchant01}"
bola_run_idx=0

RUNS_FILE_EFF="${RUNS_FILE:-$HERE/runs.jsonl}"
echo "[campaign] ${#VARIANTS[@]} biến thể × repeat=$REPEAT, gap=${GAP}s, groups=$SEL_GROUPS"
echo "[campaign] pool kẻ tấn công BOLA (luân phiên): ${ATTACKER_POOL[*]}"
echo "[campaign] runs.jsonl: $RUNS_FILE_EFF"

# §B1f: nền N1 phải CÒN SỐNG suốt chiến dịch (tấn công XEN trong nền). Theo dõi
# nhịp tim N1 (crapi_load_n1.sh ghi $OUT/HEARTBEAT mỗi 30s, xoá khi kết thúc).
N1_HEARTBEAT="${N1_HEARTBEAT:-$REPO_ROOT/results/${RESULTS_ROUND:-phaseb}/n1/HEARTBEAT}"
N1_STALE="${N1_STALE:-180}"
N1_WAS_UP=0; [[ -f "$N1_HEARTBEAT" ]] && N1_WAS_UP=1
[[ $DRY -eq 0 && "$N1_WAS_UP" -eq 0 ]] && echo "[campaign] ⚠ chưa thấy nhịp tim N1 ($N1_HEARTBEAT) — tấn công nên XEN trong nền; khởi động crapi_load_n1.sh trước."
n1_dead() {  # 0 = nền đã tắt (từng lên rồi mất/stale); 1 = còn sống / không theo dõi
  [[ "$N1_WAS_UP" -eq 1 ]] || return 1
  [[ -f "$N1_HEARTBEAT" ]] || return 0
  local age=$(( $(date +%s) - $(stat -c %Y "$N1_HEARTBEAT" 2>/dev/null || echo 0) ))
  [[ "$age" -gt "$N1_STALE" ]]
}
write_aborted() {  # <scenario> <variant_group>
  RUNS_FILE_EFF="$RUNS_FILE_EFF" SC="$1" VG="$2" python3 -c '
import json, os, uuid, datetime
now=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
rec={"run_id":str(uuid.uuid4()),"scenario":os.environ["SC"],"variant_group":os.environ["VG"],
     "class":"attack","target_entity":"testuser01","t_start":now,"t_end":now,
     "status":"aborted","exit_code":1,"reason":"nền N1 đã tắt — lượt KHÔNG chạy (§B1f)"}
open(os.environ["RUNS_FILE_EFF"],"a").write(json.dumps(rec,ensure_ascii=False)+"\n")'
}

TOTAL=0 ; ATTACK=0 ; ABORTED=0 ; FIRST=1
for ((i=1; i<=REPEAT; i++)); do
  for line in "${VARIANTS[@]}"; do
    IFS=$'\t' read -r family scenario group vid pace params <<<"$line"
    # §B1f: nền N1 tắt → lượt này + các lượt còn lại là aborted, KHÔNG chạy, KHÔNG chờ gap.
    if [[ $DRY -eq 0 ]] && n1_dead; then
      echo "[campaign] ⚠ nền N1 TẮT (heartbeat mất/stale > ${N1_STALE}s) — đánh $family/$vid = aborted (không chạy)"
      write_aborted "$scenario" "${group}:${vid}"; ABORTED=$((ABORTED+1)); continue
    fi
    # Giãn cách ≥GAP giữa các lượt (trừ lượt đầu) — không chồng cửa sổ alert.
    if [[ $FIRST -eq 0 ]]; then
      echo "[campaign] chờ ${GAP}s trước lượt kế..."
      [[ $DRY -eq 0 ]] && sleep "$GAP"
    fi
    FIRST=0
    TOTAL=$((TOTAL+1))

    # params_json → biến môi trường VP_<KEY> (scenario opt-in). Knob chung: PACE,
    # và DURATION_MIN nếu params có duration_min.
    declare -a ENVV=()
    ENVV+=("SCENARIO=${family}" "VARIANT_GROUP=${group}:${vid}" "CLASS=attack" "PACE=${pace}")
    # Luân phiên kẻ tấn công cho BOLA (xem chú thích ở đầu file). TARGET_ENTITY
    # và CRAPI_ATTACKER đặt CÙNG tài khoản để nhãn trùng entity đăng nhập thật.
    if [[ "$family" == "bola" ]]; then
      atk="${ATTACKER_POOL[$(( bola_run_idx % ${#ATTACKER_POOL[@]} ))]}"
      bola_run_idx=$((bola_run_idx + 1))
      ENVV+=("TARGET_ENTITY=$atk" "CRAPI_ATTACKER=$atk")
    fi
    while IFS=$'\t' read -r k v; do
      [[ -z "$k" ]] && continue
      KU="VP_$(echo "$k" | tr '[:lower:]' '[:upper:]')"
      ENVV+=("$KU=$v")
      [[ "$k" == "duration_min" ]] && ENVV+=("DURATION_MIN=$v")
    done < <(echo "$params" | python3 -c 'import json,sys
d=json.load(sys.stdin)
for k,v in d.items():
    print(f"{k}\t{v if not isinstance(v,(list,dict)) else json.dumps(v)}")')
    # §B1: cap DURATION_MIN (đặt SAU nên env lấy giá trị cuối → ghi đè params).
    [[ -n "$DUR_CAP" ]] && ENVV+=("DURATION_MIN=$DUR_CAP")

    echo "[campaign] #$TOTAL family=$family group=$group variant=$vid pace=$pace params=$params"
    if [[ $DRY -eq 1 ]]; then
      echo "   DRY: env ${ENVV[*]}  ->  crapi_run_campaign.sh $scenario"
      continue
    fi
    env "${ENVV[@]}" bash "$HERE/crapi_run_campaign.sh" "$scenario"
    rc=$?
    if [[ $rc -eq 0 ]]; then ATTACK=$((ATTACK+1)); else ABORTED=$((ABORTED+1)); fi
  done
done

echo "[campaign] XONG — tổng=$TOTAL  attack(tính)=$ATTACK  aborted(không tính)=$ABORTED"
echo "[campaign] Lượt aborted + lý do:"
"${PYTHON:-python3}" - "${RUNS_FILE:-$HERE/runs.jsonl}" <<'PY'
import json, sys
f = sys.argv[1]
try:
    rows = [json.loads(l) for l in open(f) if l.strip()]
except FileNotFoundError:
    sys.exit()
for r in rows:
    if r.get("status") == "aborted":
        print(f"   - {r.get('scenario')} [{r.get('variant_group')}]: {r.get('reason','?')}")
PY
