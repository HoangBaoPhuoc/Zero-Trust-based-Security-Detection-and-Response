# HƯỚNG DẪN TIẾP THEO — chạy trên VM thu dữ liệu (Giai đoạn C)

> Đọc kỹ toàn bộ trước khi chạy. File này viết cho **tác nhân AI làm việc trên VM
> `ztlab-os`** (nơi có cụm k8s, Loki, log thô). Mục tiêu: xác thực các sửa đổi
> vừa đẩy lên, rồi thu lại dữ liệu sạch cho mô hình BOLA theo đề cương KLTN.
>
> Cập nhật: 2026-10-23. Nhánh: `master`. Hai commit liên quan:
> `82746423` (đóng gói mô hình + khung SV2) và `b2ae6d61` (sửa đường tắt entity
> + lỗi 503). `git log --oneline -3` phải thấy hai commit này ở trên cùng.

---

## 0. Bối cảnh ngắn

- Hệ thống Zero Trust đa đám mây: **AWS thật** + **OpenStack trên VM Azure
  (`ztlab-os`)**, nối bằng WireGuard. Ứng dụng mục tiêu: OWASP crAPI.
- Mục tiêu ML (đề cương mục 5–6): phát hiện **BOLA** (truy cập trái quyền đối
  tượng của người khác) bằng XGBoost trên đặc trưng rút từ log Envoy + OPA.
- **Đơn vị quan sát:** cửa sổ trượt 5 phút (300 s), bước 60 s, theo từng thực
  thể (user/principal). Cửa sổ dương nếu chứa ≥1 request thuộc một lượt tấn công.
- **Gán nhãn offline** từ `tests/runs.jsonl` theo `(entity, [t_start, t_end])` —
  KHÔNG tiêm marker vào traffic.

### Tại sao phải thu lại (lỗi đã sửa ở commit `b2ae6d61`)

Bộ dữ liệu cũ (~49 giờ) **dính lỗi đường tắt (shortcut learning)**: mọi lượt
BOLA đều chạy bằng `testuser01`, nên mô hình học "nhận ra `testuser01`" thay vì
học hành vi BOLA. Phép kiểm `same-user` của đề cương (chỉ xét entity từng là kẻ
tấn công) không đủ mẫu âm để chạy. **Không sửa lại được dữ liệu cũ — phải thu
lại.** Các sửa đổi ở commit này CHỈ có tác dụng cho đợt thu mới:

| File | Thay đổi |
|---|---|
| `tests/lib/crapi_common.sh` | Thêm `CRAPI_ATTACKER_POOL=(testuser01 testuser02 merchant01)` — ba tài khoản đều có role `crapi-user`. |
| `tests/crapi_bola.sh` | Đăng nhập bằng `$CRAPI_ATTACKER` (orchestrator chỉ định), không cứng `testuser01`. |
| `tests/crapi_campaign_phaseb.sh` | Luân phiên kẻ tấn công qua pool, **chỉ cho họ `bola`**. Đặt `TARGET_ENTITY = CRAPI_ATTACKER`. |
| `tests/crapi_load_n1.sh` | Phiên viewer rải qua pool → `testuser02`/`merchant01` có lưu lượng nền. |
| `tests/crapi_noise_n2.sh` | Nhiễu N2 rải qua pool, `record_run` ghi đúng entity. |
| `tests/crapi_brute_force.sh` | 503/5xx của Keycloak → **abort**, không ghi `status=attack`. |

Và commit `82746423`: `ml/evaluate.py --save-model` đóng gói mô hình A+B (+ cột
đặc trưng + ngưỡng FPR 1%) ra `ml/model/bola_detector.joblib` cho Bước 5.

---

## 1. GIAI ĐOẠN 0 — Kiểm tra tiền đề trên VM

Chạy trên VM. **Dừng ngay nếu một bước thất bại**, đừng chạy bước sau.

```bash
cd ~/Zero-Trust-based-Security-Detection-and-Response   # đường dẫn repo trên VM
git fetch origin && git checkout master && git pull --ff-only origin master
git log --oneline -3            # phải thấy b2ae6d61 và 82746423
```

### 1.1 Cụm và cross-cloud sống

```bash
kubectl --context ctx-aws get nodes
kubectl --context ctx-openstack get nodes
# WireGuard os_gateway ↔ aws: handshake gần đây (< 3 phút)
ansible -i ansible/inventory/hosts.yml os_gateway -b -m shell -a 'wg show wg0 latest-handshakes'
```

### 1.2 crAPI + mặt phẳng chính sách sống

```bash
kubectl --context ctx-aws -n crapi get pods        # tất cả Running
kubectl --context ctx-openstack -n identity get pods
bash scripts/open-admin-uis.sh                     # port-forward Loki:13100 Grafana:3000 incident-analyzer:8091
bash tests/lib/../crapi_bola.sh 2>/dev/null; true  # chỉ để nạp preflight (sẽ fail ở bước sau nếu BFF chưa sẵn — OK)
```

### 1.3 **BẮT BUỘC: ba tài khoản pool phải đăng nhập được VÀ là crapi-user**

Đây là điểm mấu chốt của lần sửa này. `testuser02` và `merchant01` phải: (a)
tồn tại trong Keycloak với mật khẩu `Test1234!`; (b) có role `crapi-user`; (c)
đăng nhập được qua BFF. Nếu chưa, chạy lại seed:

```bash
# Seed tạo user + role (idempotent). Chỉ chạy nếu thiếu.
bash scripts/deploy-crapi.sh    # phần seed Keycloak + crAPI signup
kubectl --context ctx-aws -n crapi get job crapi-seed -o jsonpath='{.status.succeeded}'   # = 1
```

Kiểm nhanh từng tài khoản đăng nhập + đọc được endpoint crapi-user (phải 200):

```bash
source tests/lib/crapi_common.sh
crapi_preflight
for u in testuser01 testuser02 merchant01; do
  J="$(crapi_login "$u" 'Test1234!' 2>/dev/null)" || { echo "!! $u KHÔNG đăng nhập được"; continue; }
  code="$(crapi_call "$J" GET /identity/api/v2/user/dashboard)"
  echo "$u → dashboard http=$code (cần 200)"; rm -f "$J"
done
```

> **Nếu `testuser02` hoặc `merchant01` không 200:** đừng thu. Hoặc sửa seed cho
> đúng role `crapi-user`, HOẶC thu hẹp pool về các tài khoản 200 được bằng env
> `export CRAPI_ATTACKER_POOL="testuser01 testuser02"` (tối thiểu cần ≥2 tài
> khoản khác nhau, nếu không lỗi đường tắt vẫn còn). Ghi lại quyết định.

---

## 2. GIAI ĐOẠN 1 — Cổng 2 giờ (BẮT BUỘC trước đợt dài)

Mục đích: xác thực toàn pipeline trên dữ liệu sống TRƯỚC khi tốn 150 giờ. Đây
là runbook đã dùng ở các vòng trước (PHỤ LỤC B của `baocao-ml-dl/BAOCAO-CONG-2GIO.md`),
GIỮ NGUYÊN — các sửa đổi mới không đổi cách chạy, chỉ đổi tài khoản tấn công.

Chạy ở **terminal riêng**, RTC = UTC, đã port-forward (bước 1.2).

```bash
cd ~/Zero-Trust-based-Security-Detection-and-Response
export RESULTS_ROUND=phaseb

# ══ PHA 0 — KHỞI ĐỘNG (~30', NGOÀI cửa sổ cổng) ══════════════════════════════
DURATION=10800 WORKERS=8 bash tests/crapi_load_n1.sh &   # N1 nền 3h
N1_PID=$!
bash tests/phaseb_seed_posts.sh                          # victim đăng bài → lộ vehicleid
NEED=15 bash tests/phaseb_seed_verify.sh || { echo "BLOCKER 1b"; kill $N1_PID; exit 1; }
sleep 1800                                               # 30' N1 một mình
curl -s -G "http://localhost:13100/loki/api/v1/query" \
  --data-urlencode 'query=sum(count_over_time({job="envoy-access"} |~ `vehicle/[^/]+/location` [30m]))' \
  --data-urlencode "time=$(date +%s)000000000" | python3 -c 'import json,sys
r=json.load(sys.stdin)["data"]["result"]; n=int(float(r[0]["value"][1])) if r else 0
print(f"N1 gọi /vehicle/location 30 phút: {n} (cần >=20)"); sys.exit(0 if n>=20 else 1)' \
  || { echo "BLOCKER 1c"; kill $N1_PID; exit 1; }

# ══ PHA 1 — CỬA SỔ CỔNG (T0 .. T0+7200) ══════════════════════════════════════
T0=$(date +%s)
DURATION=10800 bash tests/crapi_noise_n2.sh &
sleep 60
bash tests/crapi_campaign_phaseb.sh --repeat 1 --groups train,holdout --gap 120 --duration-min 3

# nghiệm thu nhịp độ (burst vs slow_drip khác nhau thật)
for fam in bola brute_force access_denied_spike large_response bfla; do
  python3 tests/phaseb_pace_accept.py --family "$fam" --runs tests/runs.jsonl \
          --loki http://localhost:13100 --out results/phaseb/pace || echo "!! $fam chưa đạt nhịp"
done

while [ $(( $(date +%s) - T0 )) -lt 7200 ]; do sleep 30; done
T1=$(( $(date +%s) + 1 )); sleep 30
kill $N1_PID 2>/dev/null; pkill -f crapi_noise_n2 2>/dev/null || true

# PIPELINE CỔNG
mkdir -p results/phaseb/gate
python3 tests/opa_pdp_latency.py --start "$T0" --end "$T1" --output results/phaseb/gate/opa_pdp_latency.json
python3 tests/phaseb_gate.py export --loki http://localhost:13100 --start "$T0" --end "$T1" --out results/phaseb/gate
python3 tests/phaseb_gate.py run --logs results/phaseb/gate --runs tests/runs.jsonl --window 60 --step 60 --out results/phaseb/gate
cat results/phaseb/gate/gate_result.json
```

### 2.1 Tiêu chí ĐẠT của cổng (xem trong `gate_result.json`)

Cổng PASS mới được sang Giai đoạn 2. Kiểm các điểm sau; chú ý **điểm mới số 2**:

1. **`verdict` = `GO`**, cửa sổ attack > 0, non-200 của N1 < 1%.
2. **MỚI — luân phiên kẻ tấn công có thật:** `tests/runs.jsonl` phải có lượt
   `bola` với **≥2 `target_entity` khác nhau** (lý tưởng đủ ba: testuser01,
   testuser02, merchant01). Kiểm:
   ```bash
   grep '"scenario": "bola"' tests/runs.jsonl | grep '"status": "attack"' \
     | python3 -c 'import json,sys,collections
   c=collections.Counter(json.loads(l)["target_entity"] for l in sys.stdin)
   print("kẻ tấn công BOLA:", dict(c)); assert len(c)>=2, "VẪN chỉ 1 entity — luân phiên hỏng"'
   ```
3. **3 bộ soát rò rỉ sạch** (`feature_leakage`, `identity_leakage`,
   `path_leakage` trong `gate_result.json` không gắn cờ bất thường).
4. **Nghiệm thu nhịp độ (2b):** bola/brute/… PASS hoặc EXEMPT, không FAIL.
5. **`brute_force` không ghi attack giả khi 503:** nếu Keycloak từng 503 trong
   cửa sổ, lượt brute phải là `status=aborted reason=...5xx...`, không phải
   `attack`.

> Nếu điểm 2 vẫn chỉ 1 entity: kiểm lại bước 1.3 (tài khoản pool đăng nhập
> được không) và `crapi_campaign_phaseb.sh` dòng log "pool kẻ tấn công BOLA".

---

## 3. GIAI ĐOẠN 2 — Thu đợt dài

Chỉ chạy khi cổng PASS. Chi tiết nhịp/khúc nằm trong
`baocao-ml-dl/BAOCAO-THU-DULIEU-B.md` và `tests/phaseb_collect_loop.sh`.

Nguyên tắc:
- **Ưu tiên lấp biến thể mỏng trước** (các `holdout:*`, `exfil_*`, `privesc`,
  `denied_slowdrip` của đợt cũ chỉ 1–2 mẫu). Chạy `crapi_campaign_phaseb.sh`
  nhiều `--repeat` để mỗi biến thể đạt ≥2 lượt.
- **Nền N1/N2 phải sống suốt** mỗi khúc (orchestrator theo nhịp tim N1; N1 tắt
  giữa chừng → lượt còn lại đánh `aborted`).
- **GAP ≥ 600 s** giữa hai lượt cho đợt dài (không dùng `--duration-min`), để
  cửa sổ 10 phút không chứa cả lượt train lẫn holdout (rò ranh giới).
- Bộ thu chia khúc `tests/collect_chunked.py` tự đánh dấu khúc `gap` khi tunnel
  đứt — **không cộng khúc `gap` vào tổng giờ**.
- **MỚI — cổng chất lượng:** `collect_chunked.py` nay còn đánh trạng thái
  `low_quality` (không cộng giờ) khi luồng bff-audit câm (< `--min-bff-lines`,
  mặc 50) hoặc non-200 envoy quá cao (> `--max-non200-pct`, mặc 20%). Đây là
  cái bắt các khúc kiểu c0014/c0015/c0016 (bff≈0) và c0017 (non-200 43,6%) mà
  bản cũ đánh `valid` oan. Fail-open: query lỗi thì không đánh rớt. Xem cột
  `status` và `quality` trong sổ cái; chỉ `valid` mới dùng.
- Mục tiêu đề cương: **≥150 giờ nền** + **≥100 lượt tấn công độc lập**.

Sau mỗi vài khúc, chạy `inspect` (mục 4.1) để bắt sớm sự cố JWT/entity thay vì
phát hiện ở giờ thứ 150.

---

## 4. GIAI ĐOẠN 3 — Sinh đặc trưng v2 + đánh giá mô hình

Chạy trên VM (nơi có log thô `results/b4/chunks/*`). Quy trình gói trong
`ml/run_collector.sh`.

### 4.1 Kiểm định dạng log TRƯỚC (rẻ, bắt lỗi sớm)

```bash
python3 ml/features_v2.py selftest        # phải in [selftest] OK
# in khoá trường thật + tỉ lệ gán user cookie/jwt/none của khúc đầu:
python3 ml/features_v2.py inspect --chunk "$(ls -d results/b4/chunks/c0001-* | head -1)"
```

> **Nếu dòng "gán user cho OPA" có `jwt=0%`** trong khi có lượt BOLA chạy bằng
> Bearer: header token KHÔNG lọt vào OPA decision log → kiểm cấu hình mask của
> OPA (`k8s/crapi/opa.yaml`) trước khi để `build` chạy hết. Nếu attacker dùng
> cookie phiên BFF (mặc định của `crapi_bola.sh` hiện tại) thì `cookie%` cao là
> đúng, `jwt=0%` không sao.

### 4.2 Lọc runs.jsonl trước khi gán nhãn (MỚI)

`runs.jsonl` lẫn bản chạy thử + lượt thuộc khúc hỏng. Lọc còn lượt dùng được
(nằm trong khúc `valid` của sổ cái) trước khi build:

```bash
python3 tests/filter_runs.py --runs tests/runs.jsonl \
    --ledger results/b4/chunks/<tag>.ledger.jsonl --out tests/runs.filtered.jsonl
# xem báo cáo bỏ/giữ; rồi dùng tests/runs.filtered.jsonl cho bước build/evaluate.
```

### 4.3 Chạy cả quy trình

```bash
RUNS=tests/runs.filtered.jsonl bash ml/run_collector.sh   # selftest → inspect → build → evaluate
# hoặc chỉ định khúc:  CHUNKS="c0001 c0002 ..." RUNS=tests/runs.filtered.jsonl bash ml/run_collector.sh
```

### 4.4 Đánh giá + đóng gói mô hình cho Bước 5

```bash
python3 ml/evaluate.py --features "results/c4/features_v2/*.csv.gz" \
        --out results/c4/eval --save-model        # mặc định lưu phạm vi same-user
cat results/c4/eval/eval_report.md
```

### 4.5 Tiêu chí ĐẠT (đề cương mục 7 — đọc trong `eval_report.md`)

| Tiêu chí | Ngưỡng |
|---|---|
| **Phạm vi `same-user` CHẠY ĐƯỢC** (không còn "quá ít dương/âm") | bắt buộc — đây là cái lần sửa này nhắm tới |
| Recall A+B tại FPR 1% (ngưỡng chọn trên validation) | ≥ 0,80 |
| A+B vượt A: CI 95% chênh PR-AUC | không chứa 0 |
| A+B vượt baseline luật: CI 95% chênh PR-AUC | không chứa 0 |
| Đối chứng âm (xáo nhãn) PR-AUC | ≈ base rate |
| Recall trên biến thể chưa thấy (holdout) | ≥ 0,70 |
| Mô hình đã đóng gói | `ml/model/bola_detector.joblib` tồn tại |

> **Then chốt:** chỉ kết luận ĐẠT khi **phạm vi `same-user`** đạt, không phải
> `all`/`user` (hai phạm vi đó còn đường tắt theo LOẠI entity). Nếu `same-user`
> vẫn bị bỏ qua vì thiếu mẫu → thu thêm để các tài khoản pool có nhiều cửa sổ
> benign + attack hơn.

---

## 5. GIAI ĐOẠN 4 — Bước 5 đề cương (dịch vụ chấm điểm shadow mode)

Làm SAU khi mục 4 đạt. **CHƯA viết — cần thiết kế.** Yêu cầu đề cương (mục 6
Bước 5, mục 7 "Ảnh hưởng vận hành"):

- Dịch vụ chấm điểm chạy **song song, không chặn giao dịch** (không nằm trên
  đường xử lý đồng bộ).
- Mỗi chu kỳ (~1 phút): đọc log 5 phút gần nhất từ Loki → tính đặc trưng bằng
  **chính `ml/features_v2.py`** (phải giống hệt lúc train) → nạp
  `ml/model/bola_detector.joblib` → chấm điểm → cửa sổ vượt ngưỡng thì phát
  cảnh báo kèm mức ưu tiên.
- Dùng endpoint có sẵn `POST /evidence/{id}/risk-score` của
  `services/incident-analyzer` (có thể cần thêm endpoint tạo evidence mới cho
  cảnh báo do ML phát hiện mà chưa có bằng chứng từ rule Grafana).
- Chạy **shadow mode** một thời gian để đo false positive thực tế; đo và báo
  cáo **độ trễ phụ trội** riêng.

Trước khi code Bước 5, hỏi lại người hướng dẫn về: đặt service ở cloud nào,
có thêm endpoint tạo evidence không, cơ chế gửi cảnh báo (email/incident).

---

## 6. RÀO CHẮN — đừng làm

- **KHÔNG sửa dữ liệu 49h cũ để "chữa" đường tắt** — không chữa được, chỉ thu lại.
- **KHÔNG đặt `CRAPI_ATTACKER` cho các họ khác bola** — chỉ `crapi_bola.sh` đọc
  biến này; đặt cho họ khác làm nhãn lệch entity thật.
- **KHÔNG thêm `analyst01`/`demoadmin`/`stepup-demo` vào `CRAPI_ATTACKER_POOL`**
  — analyst01 là soc-analyst (BOLA bị RBAC chặn), stepup-demo thiếu user crAPI
  khớp (401). Chỉ dùng tài khoản role `crapi-user` đã 200 ở bước 1.3.
- **KHÔNG sửa `policy/variant-split.yaml`** (đã đóng băng, `frozen: true`).
- **KHÔNG bỏ qua cổng 2h** để chạy thẳng đợt dài — các script này rất nhạy, cổng
  là nơi bắt lỗi rẻ nhất.
- **KHÔNG tiêm marker** (header kiểu `X-Attack-Run-Id`) vào traffic tấn công —
  sẽ thành đặc trưng rò rỉ. Gán nhãn hoàn toàn offline qua `runs.jsonl`.

---

## 7. Nếu kẹt

| Triệu chứng | Hướng xử lý |
|---|---|
| VM/SSH không vào được | VM đang tắt hoặc NSG chặn — xem Azure Portal (Status=Running, IP, rule cổng 22). |
| `testuser02`/`merchant01` không 200 ở bước 1.3 | Chạy lại seed; nếu vẫn hỏng, thu hẹp pool bằng `export CRAPI_ATTACKER_POOL="testuser01 testuser02"`. |
| Cổng ra 0 cửa sổ attack | Kiểm blocker 1b/1c ở PHA 0; kiểm `crapi_bola.sh` có "BOLA thành công ≥1". |
| `same-user` vẫn bị bỏ qua | Thu thêm giờ để các tài khoản pool có nhiều cửa sổ benign hơn; kiểm điểm 2 ở mục 2.1. |
| `inspect` báo jwt=0% mà có BOLA Bearer | Kiểm mask header trong `k8s/crapi/opa.yaml`. |
| Tunnel WireGuard chập chờn | Khúc sẽ bị đánh `gap`, không cộng giờ — chấp nhận, thu bù. |

---

*Mọi lệnh trong file này giả định đang đứng ở thư mục gốc repo trên VM. Số liệu
tiêu chí lấy từ đề cương KLTN (mục 7) và `ml/README.md`.*
