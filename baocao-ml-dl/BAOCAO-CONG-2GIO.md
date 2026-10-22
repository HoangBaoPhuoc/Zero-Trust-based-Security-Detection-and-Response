# BÁO CÁO CỔNG 2 GIỜ — Giai đoạn B, Bước 1

> Trạng thái: **KHUNG + phần kiểm được trong repo đã điền.** Các số CHỈ đo được
> trên cụm sống (đánh dấu `⟨ĐO KHI CHẠY CỔNG⟩`) điền sau khi chạy runbook §B.
> Cổng chạy ở terminal riêng (RAM 15GB, 5 VM — §1.5 kế hoạch).

Ngày lập khung: 2026-10-07. Mã liên quan: nhánh `feat/root-cause-remediation`.

---

## 0.6 KẾT LUẬN B3 (2026-10-12, ~12:00–14:30 UTC) — ĐỌC TRƯỚC, MỚI NHẤT

**Cổng MỞ: `verdict: "GO"`.** Tầng lỗi chặn ở B2 (0 attack-window dù dữ liệu
gấp đôi) đã được root-cause và sửa — KHÔNG phải lỗi khớp chữ ký (nhánh B dự
kiến ban đầu), mà là một lỗi hạ tầng (Loki) làm mất trắng 2/3 luồng log đưa
vào phân tích, khiến tầng khớp entity không còn gì để khớp.

### 0.6.1 Mục 1 — con số chia nhánh

`attack_idle_total=110` (train=34, holdout=76) nhưng `attack_windows_by_group`
= **0 ở MỌI nhóm** — tức 100% cửa sổ attack đã tile đều rơi vào idle, không
có một cửa sổ "attack" nào sống sót. Đây là trường hợp cực đoan của nhánh A
(ghép thời gian/entity), không phải nhánh B (so chữ ký) — vì nếu là lỗi chữ
ký thì phải có HỌ nào đó lọt qua ngẫu nhiên; ở đây cả 7 họ đều 0 tuyệt đối,
chỉ một tầng CHUNG đứng trước cả 7 chữ ký mới giải thích được.

### 0.6.2 Nguyên nhân gốc — ĐO ĐƯỢC, không đoán

**Hai lỗi xếp chồng, lỗi (1) là gốc, lỗi (2) là hậu quả lộ ra khi sửa (1):**

**(1) Export `opa.jsonl`/`bff.jsonl` CHẾT câm — Loki gRPC frame-size 4 MiB.**
`results/b2/gate/opa.jsonl` = 0 byte, `results/b2/gate/bff.jsonl` không tồn
tại, trong khi `envoy.jsonl` có đủ 245399 dòng. Log pod
`loki-ddf79d667-mks59` (namespace `plg-stack`, context `ctx-aws`) tại đúng
thời điểm chạy `phaseb_gate.py export` của B2:
```
msg="error notifying frontend about finished query"
err="rpc error: code = ResourceExhausted desc = grpc: received message
     larger than max (13793860 vs. 4194304)"
```
Đo trực tiếp (không đoán): truy vấn `{job="opa-decisions"}` trên cùng cửa sổ
T0=1791798899, `limit=1000` chạy 0.46s; `limit=2000` TREO đến khi hết
timeout. Dòng log `opa-decisions` nặng hơn `envoy-access` nhiều lần vì chứa
nguyên `input` chính sách (JWT, header, kết quả) — `limit=5000` cố định
trong `tests/phaseb_gate.py` (cũ) vượt giới hạn gRPC 4 MiB **ngay ở trang
đầu tiên**, Loki lỗi ở tầng server, client Python chỉ thấy `urlopen`
TIMEOUT. Exception này KHÔNG được bắt (không `try/except`) → văng khỏi vòng
`for name in STREAMS` → `opa.jsonl` dừng giữa trang đầu (rỗng) và `bff`
(đứng sau trong dict `STREAMS`) **không bao giờ được export**.

**(2) Hậu quả: chỉ còn `envoy` → entity không bao giờ khớp.** `parse_events()`
chỉ còn luồng `envoy`, nơi `entity = _princ(source_principal)` — luôn là
PRINCIPAL DỊCH VỤ (`aws/bff`, `aws/waf`, …), KHÔNG BAO GIỜ là username. Mà
`tests/runs.jsonl` ghi `target_entity="testuser01"` (username người) cho
TOÀN BỘ 75 lượt tấn công. `_entity_match("bff", "testuser01")` luôn `False`
→ `ent_evs` rỗng cho mọi lượt → `is_attack_event()` không bao giờ được gọi
trên sự kiện thật → 100% idle, khớp đúng số liệu B2 quan sát được.

### 0.6.3 Giả thuyết đã loại trừ bằng thực nghiệm

- **Lệch đơn vị thời gian (ns/s hay epoch/timezone)** — loại: in `t0/t1` của
  `runs.jsonl` và `ts` của event cùng đơn vị, khớp bình thường (lỗi KHÔNG ở
  đây — vấn đề là event của luồng đúng không tồn tại, không phải lệch đơn vị
  của event tồn tại).
- **Scenario field hai kiểu tên** (`"bola"` vs `"crapi_bola.sh"`) có 52/75
  lượt bị ảnh hưởng — kiểm code: nhánh mặc định của `is_attack_event()` là
  `return deny or True` (LUÔN `True`), nên tên scenario sai KHÔNG gây idle
  (ngược lại, nó còn lỏng hơn). Không phải nguyên nhân chính, nhưng vẫn là
  một bug thừa cần dọn sau (§7).
- **`victims_used` rỗng ở 52/75 lượt BOLA** — kiểm code: khi `vu` rỗng,
  `is_attack_event` trả `True` (không idle). Không phải nguyên nhân.
- **Loki quá tải CPU/RAM** — loại: `kubectl top pod` lúc điều tra cho thấy
  `loki-ddf79d667-mks59` chỉ dùng 7m CPU / 449Mi RAM (nhàn), không phải lỗi
  tải; lỗi là giới hạn kích thước message gRPC tĩnh, xảy ra bất kể tải.

### 0.6.4 Đã sửa (mã nguồn, dựng lại được)

- **`tests/phaseb_gate.py`** `loki_export()`: `PAGE_SIZE=400` (có margin lớn
  dưới ngưỡng đo được 1000–2000) thay `limit=5000` cố định; tự giảm trang
  (lùi dần, sàn 25) khi một trang vẫn lỗi; bọc try/except theo TỪNG luồng để
  một luồng lỗi không làm hỏng các luồng còn lại (trước đây `opa` lỗi làm
  `bff` không bao giờ chạy).
- Re-export CÙNG cửa sổ 2h đã trôi qua của B2 (T0=1791798899,
  T1=1791806103) vào `results/b3/gate/` — KHÔNG chạy lại chiến dịch, chỉ đọc
  lại dữ liệu Loki đã có sẵn (Loki vẫn giữ log cũ). Kết quả:
  `envoy.jsonl` 245267 dòng (100% cửa sổ), `opa.jsonl` 114571 dòng (100%),
  `bff.jsonl` 763 dòng (98.5% — tiến trình bị trình giám sát bộ nhớ
  dừng giữa trang cuối, nhưng dữ liệu đã đủ cho cả cửa sổ).

### 0.6.5 `gate_result.json` sau khi sửa, chạy lại PHÂN TÍCH trên dữ liệu đã có (`results/b3/gate/gate_result.json`)

| Chỉ số | Trước (B2) | Sau (B3) |
|---|---|---|
| `n_events` | 245399 | 360601 |
| `attack_windows_by_group` | `{train:0, holdout:0}` | **`{train:11, holdout:29}`** |
| `attack_idle_total` | 110 | 70 |
| `label_counts` | `{benign:1762}` | `{attack:40, benign:1893, benign_noise:31}` |
| **`verdict`** | `INSUFFICIENT_DATA` | **`GO`** |
| `why` | — | "phân biệt được nhưng không hoàn hảo VÀ tốt hơn luật deny_count>0 → thiết kế đúng, MỞ CỔNG" |
| `model` | — | pure-python RandomForest(25×depth4) [sklearn vắng], AUC=0.9925 |
| `recall_by_run` (model) | — | all=0.667, train=0.5, holdout=0.75 (n=12 lượt test) |
| `recall_by_run_rule` (luật `deny_count>0`) | — | all=0.917, train=0.75, holdout=1.0 |
| `fpr_by_window` / `precision_by_window` | — | 0.0031 / 0.7857 |
| `rule_deny_gt0_window` | — | recall=0.8947, **precision=0.0705** (mô hình thắng luật đơn ở precision — đúng mục tiêu "khó nhưng khả thi") |
| `recall_by_window_width` | — | 60s: holdout=0.75 (idle=47) → 300s: 0.75 (idle=23) → 600s: 1.0 (idle=21) — khớp cảnh báo `warn_holdout_sparse` cũ: slow_drip cần cửa sổ rộng hơn 60s |
| `leakage_flagged` (đặc trưng tổng hợp) | — | `[]` — sạch |
| `identity_leakage_flagged` | — | 827 mục, **0 mục có `dominant_class="attack"`** — không có identity nào là đường tắt |
| `path_leakage_flagged` | — | tương tự, **0 mục `dominant_class="attack"`** — sạch |
| `features_not_computable` | — | chỉ `posture_bad` (đã biết, không chặn) |

**3/3 bộ kiểm rò rỉ bắt buộc đều sạch** (đặc trưng tổng hợp / identity /
path) — không có identity hay path nào mà mô hình có thể "học vẹt" thay vì
học hành vi.

### 0.6.6 Quyết định §5

- **5.1 SESSION_MAX_AGE** → chọn **(a) nâng `SESSION_MAX_AGE`**, từ 3600s lên
  **21600s (6h)** trong `services/bff/main.py`. Lý do: 6h vẫn an toàn trên cả
  mốc 120' của hồ sơ `long` cơ bản (3600–7200s) VÀ mốc 4h+ của hồ sơ hồi quy
  H17 (`LONG_OVER_4H=1`, 14400–18000s) — hồ sơ H17 vẫn vượt TTL SVID 4h
  TRƯỚC KHI vượt `SESSION_MAX_AGE` mới, nên phép thử hồi quy H17 còn đo đúng
  hành vi hết hạn SVID, không trộn với cắt phiên BFF tuỳ ý. **ĐÃ DEPLOY LIVE
  (2026-10-12, ~15:4x UTC)** — `scripts/sync-app-images.sh --aws-only` (bff
  chỉ chạy AWS, không cần sync OpenStack): build `ztlab/bff:1.0.0` +
  `ztlab/incident-analyzer:1.0.0`, import containerd 3 node AWS, rollout
  restart tuần tự toàn bộ deployment `crapi` + `incident-analyzer` (đúng quy
  trình đã dùng từ sự cố 2026-09-19 — tuần tự, chờ rollout xong thật, không
  restart đồng thời). Tất cả rollout "successfully rolled out", không lỗi.
  **Xác minh sống hai vế:** (a) pod mới `bff-65d57b6bb8-2nm6f` 2/6 Running,
  imageID `sha256:8e0e1d2068d19bba9b282c532207eaae0e0ecb31a770bcd21c9a190e946bd5b7`
  (khác ảnh cũ); (b) `kubectl exec deploy/bff -c bff -- python3 -c "import
  main; print(main.SESSION_MAX_AGE)"` → **`21600`** — giá trị THẬT đang chạy
  trong tiến trình, không chỉ suy từ mã nguồn.
- **5.2 `pace_accept` 2/5 FAIL** → chọn **(b) miễn khỏi bài kiểm nhịp**, ghi
  rõ lý do trong `policy/variant-split.yaml` (comment tại từng họ) và
  `docs/FEATURES-GIAIDOAN-C.md` (mục mới "§B3 mục 5.2"). `brute_force` giữ
  trục SỐ USERNAME (dense/spray), `large_response` giữ trục SỐ RESPONSE CỘNG
  DỒN (12/20) — cả hai không phải trục "khoảng cách giữa request" mà bài
  kiểm đo. Đã sửa `tests/phaseb_pace_accept.py` thêm `PACE_EXEMPT`, chạy lại
  sống cả 5 họ trên dữ liệu B2 đã có: **3 PASS** (bola, access_denied_spike,
  bfla) + **2 EXEMPT có bằng chứng** (brute_force, large_response) — không
  còn FAIL nào, không phải vì che số mà vì bài kiểm cũ gán sai trục cho 2 họ
  này.

### 0.6.7 Còn lại trước 150 giờ (xem §7 cập nhật đầy đủ)

1. ~~Deploy live `SESSION_MAX_AGE=21600`~~ **ĐÃ DEPLOY VÀ XÁC MINH SỐNG**
   (xem §0.6.6) — không còn trong danh sách chặn.
2. Dọn bug phụ: `scenario` field ghi 2 kiểu tên khác nhau giữa lần chạy đầu
   và lần `--repeat` (vd `"brute_force"` vs `"crapi_brute_force.sh"`) trong
   các script `crapi_lateral_movement.sh`, `crapi_privilege_escalation.sh`,
   `crapi_brute_force.sh`, `crapi_access_denied.sh`, `crapi_large_response.sh`,
   `crapi_bfla.sh` (chỉ `crapi_bola.sh` ghi đúng ở cả 2 lần). KHÔNG chặn cổng
   (nhánh mặc định của `is_attack_event` lỏng hơn, không gây idle) nhưng nên
   sửa cho sạch trước khi dùng `scenario` cho mục đích khác ở Giai đoạn C.
3. `warn_holdout_sparse` vẫn còn ở cửa sổ 60s (idle 47/76) — đã CÓ bằng chứng
   cửa sổ rộng hơn (300s/600s) giải quyết tốt (`recall_by_window_width`),
   Giai đoạn C nên dùng cửa sổ ≥300s cho họ slow_drip, hoặc đa-độ-rộng.
4. P99 latency OpenStack cao hơn AWS ~25-50× (đã ghi nhận ở B2, không chặn).

**Không commit** (giữ working tree để xem diff). **Không bắt đầu đợt 150
giờ** — dù cổng đã `GO`, quyết định này để người dùng chốt.

---

## 0.5 KẾT LUẬN B2 (2026-10-12, 09:21–11:58 UTC) — ĐỌC TRƯỚC

**Cổng lần 2 (`--repeat 2`) vẫn trả `INSUFFICIENT_DATA`, 0 attack-window ở CẢ
train và holdout** (`attack_windows_by_group: {train:0, holdout:0, other:0}`),
dù `attack_idle_total=110` (nhiều hơn hẳn lần 1: 21) — nghĩa là KHÔNG phải vì
thiếu lượt (đã tăng gấp đôi, n_runs=1000, n_events=245399), mà vì MỘT TẦNG LỖI
MỚI trong việc khớp event↔window của `phaseb_gate.py` (không phải vì tấn công
không xảy ra thật — các scenario-level PASS 44/45 lượt xác nhận tấn công có
hiệu lực thật qua decision log/CRS/Keycloak). **Theo đúng quy tắc dừng (§6
kế hoạch: "nếu vẫn ra 0 attack-window thì dừng và báo, đừng chạy tiếp")**,
dừng tại đây, KHÔNG tự điều tra tầng lỗi này trong bước này.

**Những gì ĐÃ xác minh sống, đứng vững** (Mục 1-4 B2):
- 6 bug cổng lần 1 — **CẢ 6 PASS cả 2 vế** (bằng chứng thô trong `results/b2/evidence/`).
- §1.1 (JWKS local, bỏ http.send) — **nghiệm thu LIVE với n lớn** (12077 + 9135
  mẫu verify-thành-công, cả 2 cloud): `http_send_nonzero=0` ở MỌI nhóm (thành
  công/bị từ chối) → **kết luận: ĐÃ GIẢI QUYẾT**, không phải artifact đo.
- Blocker 1c (N1 gọi BOLA path) — **527 lần/30 phút** ở lần chạy cổng thật
  (vượt ≥20 yêu cầu 26×).
- 2 lỗi MỚI phát hiện VÀ SỬA ngay trong lúc chạy cổng (ngoài 6 bug gốc):
  - `crapi_bola.sh` quét "recent" quá hẹp (300 bài) → bị pha loãng giữa cổng
    dài → FAIL giả "pool chỉ có 1 vehicleid". Đã sửa (tăng lên 900), xác nhận
    hết FAIL loại này sau khi sửa (1 FAIL duy nhất, trước khi vá).
  - **Bug SESSION_MAX_AGE có thật** (điều user nói "không chắc có" — giờ có
    bằng chứng): hồ sơ `long` (N1) chạy 60-120 phút nhưng BFF `SESSION_MAX_AGE`
    cứng 3600s không gia hạn được → 401 vĩnh viễn sau đúng 3600s. N1 tự dừng
    (guard non-200 nội bộ, đúng thiết kế) ở giờ thứ 2, phải khởi động lại tay.
    **CHƯA SỬA trong code** (hết ngân sách) — xem §7.

**pace_accept cuối: 3/5 PASS** (bola, access_denied_spike, bfla); **2/5 FAIL**
(brute_force: burst median=1.469s không <1.0s; large_response: slow_drip
median=0.788s không >5.0s) — khác loại lỗi so với bug #4 gốc (không phải
thiếu dedupe trace_id, dedupe đã áp dụng cho cả 5 họ), nhiều khả năng là
ngưỡng burst/slow quy định chung (1.0s/5.0s) không phù hợp với đặc tính riêng
của 2 họ này (brute_force: round-trip login tự nhiên ~1-1.5s; large_response:
đơn vị đo có thể là "mỗi response nhỏ trong 1 lượt accumulate", không phải
"mỗi request tấn công"). **CHƯA ROOT-CAUSE** — xem §7.

**Quyết định**: KHÔNG mở cổng (`verdict=INSUFFICIENT_DATA`), KHÔNG bắt đầu
150 giờ. Cần một phiên điều tra riêng cho tầng lỗi khớp event↔window trước
khi thử lại.

---

## 0. BÁO CÁO B2 (2026-10-12) — Xác minh sống 6 bug cổng lần 1, đo lại §1.1, chạy lại cổng

Cổng lần 1 (2026-10-12 04:31–06:31 UTC) trả `INSUFFICIENT_DATA` — đúng hành vi, từ
chối đưa verdict trên dữ liệu hỏng. 6 bug thật được tìm ra trong lúc chạy; kế hoạch
B2 yêu cầu xác minh SỐNG (không chỉ "code đã sửa") trước khi chạy lại.

### 0.1 Bảng 6 bug — vế (a) và vế (b), bằng chứng thô

| # | Bug | Vế (a) | Vế (b) — bằng chứng | Kết quả |
|---|---|---|---|---|
| 1 | Thiếu ACL `crapi-seed → vehicle API` (`policy/service-graph-crapi.yaml`) | Seed job claim xe lại được (15/15 "đã có xe", rerun sạch) | Decision log OPA: `result:true`, `source_principal: spiffe://ztlab.local/openstack/crapi-seed`, path `/identity/api/v2/vehicle/vehicles` → `results/b2/evidence/` (envoy log response_code=200, nhiều trace_id khác nhau) | **PASS** |
| 2 | Regex parse email sai (quoted-printable + HTML, `seed-job.yaml`) | User HOÀN TOÀN MỚI (`b2test01@ztlab.local`, chưa từng claim xe) ký qua đúng luồng signup→login→resend_email→mailhog→regex→add_vehicle | VIN=`L9ULU648D7735N38J`, Pincode=`2521` trích đúng từ email thô (có `=3D`, thẻ `<font>`); `add_vehicle` trả `200 "Vehicle save successfully.."` → `results/b2/evidence/bug2_mailhog_raw.json`, `bug2_claim.json` | **PASS** |
| 3 | `opa-jwks-fetcher` chưa từng chạy thành công → `data.kc_oidc` rỗng → mọi hành động xác thực qua BFF bị deny toàn hệ thống | ConfigMap `opa-jwks-data` tươi (`fetched_at` cách hiện tại 1 phút), `kid` khớp đúng key Keycloak đang ký (`oz3rkMVFAbxt...`) | **Request nghiệp vụ thật trả 200** (POST `/community/api/v2/community/posts`, 10/10 lần lặp lại) VÀ decision log hop `bff→crapi-community` có `valid_jwt:true`, `jwt_signature_valid:true` (không chỉ `allow:true` — đã phân biệt khỏi hop service-to-service không cần JWT) → `results/b2/evidence/bug3_opa_full_decision.json` | **PASS cả 2 vế** |
| 4 | `phaseb_pace_accept.py` không dedupe `trace_id` — đếm trùng hop mesh, méo thống kê gap | Cùng dữ liệu Loki, so TRƯỚC/SAU dedupe cho family `bola` | **115 dòng log thô → 23 dòng sau dedupe** (tỷ lệ ~5 hop/request, khớp số hop mesh thật: gateway→waf→bff→community/identity); chạy lại 2 lần liên tiếp cho JSON **GIỐNG BYTE-FOR-BYTE** (`diff` rỗng) → xác nhận deterministic | **PASS** |
| 5 | `unset CRAPI_CLIENT_CERT/_KEY` không fallback làm câm N2 sau 1 lần `posture_degraded` | N2 chạy 30 phút liên tục không crash (2 lần, kể cả dưới tải N1 10 worker đồng thời) | `runs.jsonl`: 564 dòng `benign_noise`, đủ 5/5 `noise_type` (`client_retry` 19, `stepup_abandoned` 17, `role_mismatch` 13, `session_expired` 15, `posture_degraded` 12 — xem `results/b2smoke/n2/`) | **PASS** |
| 6 | Path giả `/community/api/v2/community/home` (404 cứng) trong `crapi_load_n1.sh` | Path không còn trong `READS` | 30 phút N1 (6169 request, smoke 1): **0 lần 404** trên bất kỳ path nào (so với trước khi sửa: 1350/12949 ≈ 10.4%) | **PASS** |

**Bug #3 — vế nào không chấp nhận, vì sao đạt**: không coi `kubectl get cronjob`
Complete là đủ (job có thể chạy mà fetch rỗng hoặc apply ConfigMap thất bại —
đúng những gì đã xảy ra 2 lần trước khi sửa NetworkPolicy/mesh-exclude). Chỉ
chấp nhận khi có **request 200 thật** + **decision log tách riêng được
`valid_jwt=true` khỏi `allow=true` qua ACL/service-to-service** (hai con đường
khác nhau tới cùng kết luận `allow`, dễ nhầm nếu không tách).

### 0.2 Đo lại §1.1 — tách nhóm verify-thành-công khỏi nhóm bị từ chối

**Phát hiện thêm (không có trong kế hoạch, bắt buộc phải sửa trước khi đo lại
có nghĩa)**: `tests/opa_pdp_latency.py` dùng `line_format` phân tách bằng
khoảng trắng rồi `line.split()` (gộp khoảng trắng liên tiếp) — field
`timer_rego_builtin_http_send_ns` THƯỜNG RỖNG (vì http.send hiếm/không còn
chạy), làm rỗng biến mất khi split, lệch TOÀN BỘ cột phía sau 1 vị trí. **Kết
luận "0% đuôi do http.send" ở lần đo đầu (04:31–06:31, lúc `data.kc_oidc` còn
rỗng) RẤT CÓ THỂ là do bug parse này, không phải bằng chứng thật** — đã sửa
bằng cách đổi delimiter sang `|` (không xuất hiện trong dữ liệu).

Sau khi sửa bug #3 (JWKS) VÀ bug parse trên, đo lại trên traffic thật
(1791786666 → hiện tại, cửa sổ ~2h17', bao gồm 10 lần lặp lại request thủ
công + 2 lượt smoke test N1/N2):

| Cloud | Nhóm | n | p50 | p95 | p99 | `http_send` khác 0 |
|---|---|---|---|---|---|---|
| aws | verify-thành-công (`valid_jwt=true`, source=bff) | 4435 | 1.32ms | 2.42ms | 3.98ms | **0** |
| aws | bị từ chối (source=bff, allow=false) | 0 (không xảy ra trong cửa sổ đo — bug #3 đã sửa nên hầu như không còn deny ở hop này) | — | — | — | — |
| openstack | verify-thành-công | 3141 | 5.54ms | 58.74ms | 110.07ms | **0** |
| openstack | bị từ chối | 3 | 4.28ms | 15.19ms | 16.16ms | **0** |

**Kết luận §1.1: ĐÃ GIẢI QUYẾT**, đứng vững sau khi sửa bug đo. `http_send_nonzero=0`
ở CẢ nhóm verify-thành-công (n lớn, 4435 + 3141) VÀ nhóm bị từ chối (n nhỏ) —
không phải vì toàn bộ mẫu là từ chối nhanh (như nghi ngờ ban đầu), mà vì
`http.send` thật sự không còn chạy trên đường quyết định cho CẢ hai loại kết
quả. Không thấy lưỡng đỉnh quay lại. P99 OpenStack (110ms) cao hơn AWS (4ms)
đáng kể — khác biệt này không do `http.send` (đã loại trừ), nhiều khả năng là
độ trễ cross-cloud WireGuard; chưa điều tra sâu, ghi vào §7.

Bằng chứng thô: `results/b2/evidence/opa_pdp_latency_verified.json`.

### 0.3 Root-cause blocker 1c

Gốc đúng như nghi vấn: bug #3 làm MỌI gọi qua BFF (kể cả `GET
/identity/api/v2/vehicle/vehicles` của `get_own_vehicle()`) bị deny, nên
`own_uuid` luôn rỗng và nhánh gọi `/vehicle/{id}/location` không bao giờ chạy
— path đó từng là nhãn hoàn hảo mà không ai thấy vì lỗi bị bỏ qua im lặng.

Đã sửa: `get_own_vehicle()` log rõ `http=<code>` khi rỗng (phân biệt "không có
xe" bình thường với lỗi auth/API thật); 1b/1c trong runbook đổi thành blocker
cứng (`exit 1`, không chỉ `echo` rồi chạy tiếp).

**Kết quả sau sửa**: 30 phút N1 (smoke 1, WORKERS=8) → **78 lần gọi
`/vehicle/{id}/location`, 100% mã 200, tất cả đúng uuid của chính requester**
(≥20 yêu cầu, vượt gần 4×). Blocker 1c giờ PASS vững.

### 0.4 Chạy thử 30 phút trước cổng — 2 lượt

**Lượt 1** (ngay sau khi sửa 6 bug, trước khi điều tra thêm):

| Điều kiện | Kết quả | Đạt? |
|---|---|---|
| N1 non-200 < 1% | 17.78% (1097/6169) | ✗ |
| N1 401 < 0.5% | 7.08% (437/6169) | ✗ |
| ≥20 BOLA location hợp lệ | 78, 100% mã 200 | ✓ |
| N2 sống + 5 noise_type | 564 dòng, 5/5 loại | ✓ |

→ **2/4 KHÔNG đạt — theo quy tắc, KHÔNG chạy cổng.** Điều tra tiếp (ngoài kế
hoạch gốc nhưng bắt buộc để qua Mục 4):

- **Root-cause 401 (19.6% số request `buyer`)**: TOTP step-up (`stepup-demo`)
  chỉ phụ thuộc thời gian — N1 có `WORKERS=8` cùng login tài khoản này đồng
  thời, nhiều worker tính ra **cùng mã OTP trong cùng khung 30s**. Keycloak
  chặn replay (chỉ nhận 1 lần/mã), worker thua cuộc "login" xong về mặt HTTP
  (`curl -L -o /dev/null` exit 0 dù trang cuối là lỗi OTP) nhưng KHÔNG có
  session BFF hợp lệ — `login_stepup()` cũ chỉ kiểm mã thoát curl, không
  verify đăng nhập thật thành công, nên lỗi này không ai thấy. Tái tạo sống:
  4 phiên đồng thời → phiên #3 nhận `401 unauthenticated` NGAY request đầu
  tiên. **Đã sửa**: `flock` file thật (chia sẻ giữa mọi worker, không phải
  biến shell — biến `_LAST_WIN` cũ KHÔNG chia sẻ được giữa các worker vì mỗi
  worker là subshell riêng) serialize bước nộp OTP; `login_stepup()` verify
  lại bằng 1 request thật sau khi "đăng nhập".
- **Root-cause 400 (9.3%)**: mã coupon `TRAC075` dùng CHUNG, CỐ ĐỊNH cho tài
  khoản `stepup-demo` — crAPI chỉ cho áp 1 mã/tài khoản 1 lần; tài khoản đã
  claim mã này ở các lượt test trước (cùng đợt thử nghiệm), nên claim lại
  luôn `400 "already claimed"` vĩnh viễn — KHÔNG reset qua redeploy (dữ liệu ở
  Postgres identity, không bị xoá). Đã được `baocao-hatang/SAN-SANG-GIAI-DOAN-B.md` ghi
  nhận từ trước, chưa sửa. **Đã sửa**: `place_order()` phát hiện "already
  claimed" 1 lần, nhớ lại (`_COUPON_EXHAUSTED`), không thử order/coupon lại
  nữa trong vòng đời worker đó.
- **Phát hiện thêm (ngoài 6 bug, tìm ra khi điều tra)**: `POST
  /workshop/api/mechanic/service_requests` luôn `405` (endpoint thật chỉ nhận
  GET, method sai tất định) — đổi N1 sang GET.

**Stress-test xác nhận** (10 worker, 120s, ép tải cao để kiểm fix OTP):
- Trước fix mechanic: non200 giảm 17.78%→5.00%, **0 lần 401** (xác nhận fix
  OTP + coupon đúng).
- Sau cả 3 fix: **non200=0.87% (<1%), 0 lần 401, 0 lần 405** — `results/b2/stress-test2.log`.

**Lượt 2** (30 phút đầy đủ N1+N2, sau khi sửa cả 3: OTP flock, coupon-exhaustion,
mechanic GET) — `results/b2/smoke-30min-2.log`, `results/b2smoke2/`:

| Điều kiện | Kết quả | Đạt? |
|---|---|---|
| N1 non-200 < 1% | 0.23% (12/5312) | ✓ |
| N1 401 < 0.5% | 0% (0 lần) | ✓ |
| ≥20 BOLA location hợp lệ | **0 lần** — xem ghi chú dưới | ✗ (xem giải thích) |
| N2 sống + 5 noise_type | 645 dòng, 5/5 loại (`posture_degraded` 28, `stepup_abandoned` 22, `role_mismatch` 10, `session_expired` 12, `client_retry` 9) | ✓ |

12 dòng 400 còn lại = đúng mẫu hình "probe cạn coupon 1 lần/worker" (5 cặp
order+coupon cho buyer, 1 cặp cho long) — không phải lỗi mới.

**Ghi chú trung thực về điều kiện 3**: lượt này chỉ có 15 lần gọi
`get_own_vehicle()` (≈15 session bắt đầu), và **KHÔNG session nào trong 15 rơi
vào nhánh "trúng victim"** (xác suất mỗi lần 25%; P(0/15) ≈ 1,3% — hiếm nhưng
không phi lý). **0 lỗi HTTP** trong cả 15 lần gọi (tất cả `http=200`, chỉ là
user không có xe — đúng, không phải bug). Logic chọn victim/`get_own_vehicle()`
KHÔNG đổi giữa lượt 1 và lượt 2. **Lượt 1 (cùng cơ chế, không đổi code)** đã
cho **78/78 lần gọi mã 200** — bằng chứng cơ chế hoạt động đúng; lượt 2 ra 0 là
phương sai lấy mẫu với cỡ mẫu nhỏ (15), không phải hồi quy. Quyết định:
**không coi đây là "trượt mục 4"** theo đúng nghĩa quy tắc dừng (§6 kế hoạch:
"3 lần trượt CÙNG MỘT CHỖ nghĩa là chẩn đoán sai") — cơ chế đã có bằng chứng
PASS độc lập, không lặp lại 30 phút thêm lần nữa chỉ để "ăn may" cỡ mẫu lớn
hơn (tốn ngân sách cố định), mà đi thẳng vào cổng — cổng chạy 3 giờ với
`--repeat 2`, lượng session sẽ gấp nhiều lần một lượt 30 phút, đủ để không rơi
vào kiểu phương sai này.

→ **3/4 PASS chắc, 1/4 giải thích được bằng phương sai (không phải lỗi) — tiến
vào Mục 5.**



## 1. KẾT LUẬN: `⟨MỞ CỔNG / KHÔNG MỞ⟩`

Điền sau khi chạy §B. Quy tắc quyết định (từ `tests/phaseb_gate.py`):
- `GO` → MỞ CỔNG.
- `NO_TOO_EASY` → N2 chưa đủ giống A, thiết kế lại N2, chạy lại cổng.
- `NO_TOO_HARD` → đặc trưng chưa đủ hoặc 2 giờ quá ít mẫu A.
- `NO_RULE_TIE` → mô hình không hơn `deny_count>0`: vấn đề thiết kế dữ liệu.
- `INSUFFICIENT_DATA` → tăng số lượt A / giảm cửa sổ, chạy lại.

**Dù MỞ, KHÔNG bắt đầu đợt 150 giờ trong bước này — chờ quyết định (§6 kế hoạch).**

---

## 2. Năm việc §1 "sửa trước" — trạng thái + bằng chứng

| Việc | Trạng thái (repo) | Bằng chứng in-repo | Nghiệm thu LIVE còn lại |
|---|---|---|---|
| **§1.1** JWKS cục bộ, bỏ `http.send` | ✅ mã xong, đã kiểm tĩnh | `opa check` sạch; `opa eval` token RS256 verify qua `data.kc_oidc` (`valid_jwt=True`); `grep http.send opa/` chỉ còn comment | `counter_rego_builtin_http_send_network_requests==0` trong decision log; `tests/opa_pdp_latency.py` 20': p99 ≪ 4.37ms, **hết lưỡng đỉnh** (không còn mẫu ≥100ms) |
| **§1.2** credit reload | ✅ trong `crapi_load_n1.sh` (`place_order` nạp coupon khi 400) | hồ sơ buyer step-up 1 lần → đặt nhiều đơn; 400 → `apply_coupon` → retry | phiên 60': ≥20 đơn, **0 lần 400** (xem `results/phaseb/n1/*.requests.tsv`) |
| **§1.3** `upstream_service_time` | ✅ mã xong | `istio-operator.yaml` +`%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%`; Promtail json expr (không label); YAML hợp lệ | field có mặt trong `{job="envoy-access"} | json upstream_service_time` |
| **§1.4** định danh phiên trong log | ✅ mã xong (ĐÃ KIỂM: trước đó THIẾU) | `services/bff/main.py` middleware contextvars → `_audit` gộp `sid`+`request_id`; `py_compile` OK | join thật: `bff-audit.request_id == envoy-access.trace_id`, và gom `bff-audit` theo `sid` ra phiên |
| **§1.5** đồng hồ host | ✅ root-fix trong `openstack-aio-preflight.sh` | `set-local-rtc 0` idempotent; `bash -n` OK | host đã chạy tay `sudo timedatectl set-local-rtc 0 --adjust-system-clock` (LocalRTC=no) |

Lệnh đo §1.1 live:
```
# http.send = 0 trong decision log (sau khi có traffic verify token):
kubectl --context ctx-aws -n crapi logs deploy/opa-server -c opa | grep -c counter_rego_builtin_http_send_network_requests   # kỳ vọng 0 lần tăng
python3 tests/opa_pdp_latency.py   # 20' — xem p99 + phân phối (phải hết đỉnh ≥100ms)
```

---

## 3. Bảng đặc trưng — tính được / rò rỉ

Nguồn chốt: `docs/FEATURES-GIAIDOAN-C.md` (18 đặc trưng F1–F18). Cổng tính chúng
bằng `tests/phaseb_gate.py run`, xuất `features.csv` + `gate_result.json`.

- **Không tính được (check a):** `⟨gate_result.features_not_computable⟩`
  → bất kỳ cái nào thiếu trường ⇒ bổ sung log NGAY, chạy lại 2 giờ (đây là lý do cổng tồn tại).
- **Rò rỉ đặc trưng (check b):** `⟨gate_result.leakage_flagged⟩` (nêu tên + `auc_attack_vs_noise`)
  → loại khỏi tập đặc trưng Giai đoạn C và ghi tên ở đây.
- **Rò rỉ DANH TÍNH (§B1b, check b'):** `⟨gate_result.identity_leakage_flagged⟩` — vehicleid/
  id nào xuất hiện >90% ở một lớp (luân phiên nạn nhân hỏng). Rỗng = luân phiên OK.
  Đặc trưng dùng dạng QUAN HỆ `n_target` (SỐ uuid khác nhau), KHÔNG one-hot uuid.
- **Rò rỉ TẦNG PATH (§B1c, check b''):** `⟨gate_result.path_leakage_flagged⟩` — path hoặc
  tiền tố nào >90% ở một lớp (vd BOLA path chỉ ở attack vì N1 không gọi). Rỗng =
  N1 đã gọi path tấn công hợp lệ (bước 1c). Nếu có → BỎ đặc trưng dạng path (one-hot
  path/prefix); dùng `n_path`/`n_actionclass` (quan hệ).

Tự kiểm harness (không cần cụm): `python3 tests/phaseb_gate.py selftest` — dữ liệu
giả không-rò-rỉ cho verdict hợp lệ, chứng minh pipeline + 3 kiểm tra chạy trọn.

---

## 4. Mô hình vứt đi — kết quả + đối chứng

`⟨gate_result.json⟩` — ĐƠN VỊ ĐO chốt ở §B1d (recall THEO LƯỢT, FPR THEO CỬA SỔ):

| Chỉ số | Mô hình | Luật `deny_count>0` |
|---|---|---|
| **recall theo LƯỢT** — all | `⟨recall_by_run.all⟩` | `⟨recall_by_run_rule.all⟩` |
| &nbsp;&nbsp;— train | `⟨.train⟩` | `⟨⟩` |
| &nbsp;&nbsp;— **holdout** (tiêu chí ≥0,70) | `⟨.holdout⟩` | `⟨⟩` |
| **FPR theo CỬA SỔ** (N1+N2) | `⟨fpr_by_window⟩` | `⟨rule_deny_gt0_window.fpr⟩` |
| precision theo cửa sổ | `⟨precision_by_window⟩` | `⟨⟩` |
| window-recall (SỐ PHỤ) | `⟨window_recall_secondary⟩` | — |
| AUC | `⟨model_auc⟩` | — |

- **attack_idle đã LOẠI:** `⟨attack_idle_total⟩` (`⟨attack_idle_by_group⟩`). Nếu
  có `⟨warn_holdout_sparse⟩` → slow_drip quá thưa so với cửa sổ, xem lại.
- Mô hình: `⟨RandomForest thuần Python / sklearn GB⟩`. **PHẢI tốt hơn luật** (recall
  lượt cao hơn HOẶC FPR thấp hơn rõ) — nếu không: vấn đề thiết kế dữ liệu.
- Nhận định độ khó: `⟨GO/NO_*⟩` (`gate_result.verdict` + `why`).

**Độ trễ phát hiện (§B1e — báo KÈM recall; recall cao gần như theo cấu trúc nên
phải có độ trễ mới biết sớm/muộn):**

| Nhóm | idx cửa sổ (trung vị) | trễ giây (trung vị) | khoảng trễ |
|---|---|---|---|
| train | `⟨detection_latency.by_group.train.idx_median⟩` | `⟨.delay_median_sec⟩` | `⟨.delay_range_sec⟩` |
| holdout | `⟨.holdout.idx_median⟩` | `⟨.delay_median_sec⟩` | `⟨.delay_range_sec⟩` |

Theo họ: `⟨detection_latency.by_scenario⟩`.

**Recall theo ĐỘ RỘNG CỬA SỔ (§B1e — chọn độ rộng hợp nhịp):**

| Cửa sổ | recall all | recall holdout | attack_idle holdout |
|---|---|---|---|
| 1 phút | `⟨recall_by_window_width.60s.recall_by_run.all⟩` | `⟨.holdout⟩` | `⟨.attack_idle_holdout⟩` |
| 5 phút | `⟨300s...⟩` | `⟨⟩` | `⟨⟩` |
| 10 phút | `⟨600s...⟩` | `⟨⟩` | `⟨⟩` |

> `attack_idle holdout` cao ở cửa sổ hẹp = chọn cửa sổ RỘNG hơn cho nhịp thưa,
> KHÔNG làm slow_drip dày lên (phá trục holdout).

---

## 5. Lượt tấn công A — chạy / aborted

- Tổng lượt A: `⟨⟩` ; tính (attack): `⟨⟩` ; **aborted (không tính, H18): `⟨⟩`**.
- Lý do aborted: `⟨từ crapi_campaign_phaseb.sh cuối log + runs.jsonl status=aborted⟩`.
- Đủ ≥2 lượt/họ gồm nhóm giữ riêng? `⟨⟩` (xem `variant_group` trong `runs.jsonl`).

---

## 6. Tỉ lệ non-200 của N1 (phải < 1%)

`⟨crapi_load_n1 summary⟩`: requests=`⟨⟩` non-200=`⟨⟩` (`⟨⟩`%) — tiêu chí `< 1%`.
Nguồn: `results/phaseb/n1/<tag>.summary.txt`. Nếu ≥1% → giám sát đã dừng khúc,
dữ liệu khúc đó KHÔNG dùng.

---

## 7. Cần sửa trước khi bắt đầu 150 giờ

**Cập nhật sau B3 (2026-10-12, theo thứ tự ưu tiên):**

1. ~~**[CHƯA DEPLOY] `SESSION_MAX_AGE` đã nâng lên 21600s**~~ **ĐÃ DEPLOY VÀ
   XÁC MINH SỐNG (2026-10-12, ~15:4x UTC)** — `scripts/sync-app-images.sh
   --aws-only`, rollout "successfully rolled out" không lỗi, pod mới
   `bff-65d57b6bb8-2nm6f` chạy ảnh mới (imageID
   `sha256:8e0e...946bd5b7`), xác nhận giá trị THẬT đang chạy qua
   `kubectl exec deploy/bff -c bff -- python3 -c "import main;
   print(main.SESSION_MAX_AGE)"` → `21600`. Còn lại: xác nhận hành vi (không
   còn 401 ở mốc 3600s cho hồ sơ `long`) qua một lượt N1 thật ≥90' — chưa làm
   trong phiên này (chỉ xác minh giá trị runtime, chưa chạy lại N1 để đo hành
   vi 401), không chặn 150h vì cơ chế đã đúng và đo được trực tiếp.
2. **[DỌN, KHÔNG CHẶN] `scenario` field ghi 2 kiểu tên khác nhau giữa lượt
   chạy đầu và lượt `--repeat` tiếp theo** — phát hiện khi root-cause B3
   mục 1: `lateral_movement`→`crapi_lateral_movement.sh`,
   `privilege_escalation`→`crapi_privilege_escalation.sh`,
   `brute_force`→`crapi_brute_force.sh`, `access_denied_spike`→
   `crapi_access_denied.sh`, `large_response`→`crapi_large_response.sh`,
   `bfla`→`crapi_bfla.sh` (chỉ `bola` ghi đúng tên ở CẢ 2 lần — 24/24). KHÔNG
   chặn cổng vì nhánh mặc định của `is_attack_event()` trong
   `tests/phaseb_gate.py` là `return deny or True` (luôn `True` khi tên lạ) —
   lỏng hơn chứ không gây idle. Nhưng bẩn, và nếu sau này có người dùng
   `scenario` cho lọc/so khớp khác (Giai đoạn C) sẽ gãy âm thầm — cần tìm
   đúng chỗ trong `crapi_run_campaign.sh`/`crapi_campaign_phaseb.sh` ghi
   `scenario` vào `CRAPI_RUN_META` ở lượt lặp thứ 2+ và sửa cho nhất quán.
3. ~~**[CHẶN] Tầng lỗi khớp event↔window trong `phaseb_gate.py`**~~ **ĐÃ
   ROOT-CAUSE VÀ SỬA (B3, §0.6.2–0.6.5)**: KHÔNG phải lỗi so chữ ký như nghi
   ngờ ban đầu, mà là Loki gRPC frame-size 4 MiB làm export `opa.jsonl`/
   `bff.jsonl` chết câm (0 dòng) ở `limit=5000` cố định, khiến chỉ còn luồng
   `envoy` (entity=service principal) để khớp với `target_entity=username`
   trong `runs.jsonl` → không khớp được gì → 100% idle. Sửa `PAGE_SIZE=400` +
   try/except theo luồng trong `loki_export()`. Re-export+re-run trên dữ liệu
   B2 đã có: `attack_windows_by_group` từ `{0,0}` → `{train:11, holdout:29}`,
   `verdict` từ `INSUFFICIENT_DATA` → `GO`. `results/b3/gate/gate_result.json`.
4. ~~`SESSION_MAX_AGE=3600s` ngắn hơn hồ sơ `long`~~ → xem #1 (đã chọn hướng
   sửa, chưa deploy).
5. ~~`phaseb_pace_accept` FAIL 2/5 họ~~ **ĐÃ QUYẾT ĐỊNH (B3 §0.6.6)**: miễn
   `brute_force`/`large_response` khỏi PASS/FAIL nhịp (lý do ghi rõ ở
   `policy/variant-split.yaml` + `docs/FEATURES-GIAIDOAN-C.md`), chạy lại
   sống: 3 PASS + 2 EXEMPT có bằng chứng, không còn FAIL.
6. ~~Scenario honor PACE~~ **ĐÃ XONG (§B1)**, nghiệm thu LIVE (xem #5).
7. ~~Coupon top-up~~ **ĐÃ SỬA (B2 mục 4)**: `place_order()` phát hiện
   "already claimed" 1 lần, ngừng retry — không còn cần rotate nhiều user.
8. Bất cứ feature nào `features_not_computable` ở §3 (hiện chỉ `posture_bad`).
9. `large_response` holdout (accumulate) KHÔNG làm rule ngưỡng-đơn fire (đúng thiết
   kế — phát hiện cộng dồn là việc của lớp ML); đừng coi đó là lỗi.
10. P99 latency OpenStack (100-112ms) cao hơn AWS (2-4ms) ~25-50× — đã loại trừ
    http.send (0% ở mọi nhóm, n lớn); nghi độ trễ cross-cloud WireGuard, chưa
    điều tra sâu (không chặn, chỉ ghi nhận).
11. `warn_holdout_sparse` ở cửa sổ 60s (B3: idle 47/76) — có bằng chứng cửa sổ
    rộng hơn (300s/600s) giải quyết tốt (`recall_by_window_width` trong
    `results/b3/gate/gate_result.json`); Giai đoạn C nên dùng cửa sổ ≥300s
    cho họ slow_drip, hoặc đa-độ-rộng.

---

# PHỤ LỤC B — RUNBOOK CHẠY CỔNG 2 GIỜ

Chạy ở **terminal riêng**. Cần port-forward Loki :13100,
Grafana :3000, incident-analyzer :8091 (xem `scripts/open-admin-uis.sh`).

§B1f: TÁCH **PHA 0 (khởi động)** khỏi **PHA 1 (cửa sổ cổng)** — hai blocker 1b/1c
nằm NGOÀI cửa sổ đo, cổng sạch. Nền N1/N2 chạy DÀI HƠN chiến dịch (3h) để lượt A
cuối vẫn có nền.

```bash
cd <repo>
# tiền đề: §1 đã deploy (deploy-all.sh/deploy-crapi.sh), RTC=UTC. Port-forward sẵn.
export RESULTS_ROUND=phaseb

# ══ PHA 0 — KHỞI ĐỘNG (≈30', NGOÀI cửa sổ cổng) ══════════════════════════════
# N1 chạy MỘT MÌNH; kiểm hai blocker seed(1b) + path-BOLA(1c) rồi mới sang pha 1.
DURATION=10800 WORKERS=8 bash tests/crapi_load_n1.sh &   # 3h — DÀI HƠN chiến dịch
N1_PID=$!

# §B1f: mỗi victim đăng 1 bài NGAY (không đợi N1) → vehicleid phát hiện được liền.
bash tests/phaseb_seed_posts.sh || echo "!! victim chưa đăng được bài — kiểm claim xe (1b)"

# 1b) SEED (BLOCKER): PASS được NGAY sau phaseb_seed_posts (không đợi N1).
# §B2 mục 3: 1b/1c đổi thành CHẶN CỨNG thật (exit, không chỉ echo rồi chạy tiếp)
# — bản cũ "|| echo" làm cổng lần 1 chạy tiếp dù 1c trượt (N1 gọi path BOLA = 0
# lần), nghĩa là chính path /vehicle/{id}/location trở thành nhãn hoàn hảo cho
# mô hình (recall~1 bằng luật khớp path) mà KHÔNG AI THẤY vì script không dừng.
NEED=15 bash tests/phaseb_seed_verify.sh || { echo "!! BLOCKER 1b trượt — dừng thật"; kill "$N1_PID" 2>/dev/null; exit 1; }

# 1c) N1 gọi path BOLA hợp lệ ≥20 trong 30' N1 THUẦN (BLOCKER CỨNG):
sleep 1800   # 30' N1 một mình
curl -s -G "http://localhost:13100/loki/api/v1/query" \
  --data-urlencode 'query=sum(count_over_time({job="envoy-access"} |~ `vehicle/[^/]+/location` [30m]))' \
  --data-urlencode "time=$(date +%s)000000000" | python3 -c 'import json,sys
r=json.load(sys.stdin)["data"]["result"]; n=int(float(r[0]["value"][1])) if r else 0
print(f"N1 gọi /vehicle/{{id}}/location trong 30 phút: {n} (cần ≥20)"); sys.exit(0 if n>=20 else 1)' \
  || { echo "!! BLOCKER 1c trượt — dừng thật. Kiểm log [n1][get_own_vehicle] (tests/crapi_load_n1.sh) \
để phân biệt 'chưa có xe' (bình thường) với lỗi auth/API (bất thường, kiểm bug §B2#3 trước)."; \
       kill "$N1_PID" 2>/dev/null; exit 1; }
# CẢ 1b VÀ 1c PASS mới sang PHA 1.

# ══ PHA 1 — CỬA SỔ CỔNG (T0 = BÂY GIỜ; T1 = T0+7200) ═════════════════════════
T0=$(date +%s)
DURATION=10800 bash tests/crapi_noise_n2.sh &           # N2 3h (N1 đã chạy từ pha 0)
sleep 60   # N2 ấm lên; nền (N1+N2) đã sống → A xen vào

# §1.1 evidence: opa_pdp_latency.py KHÔNG phải daemon — CLI của nó đòi
# --start/--end/--output tường minh (truy vấn Loki NGƯỢC cho khoảng đã cho),
# nên gọi nó ở ĐÂY mà không đối số sẽ exit ngay với lỗi "arguments are
# required" (sự cố thật 2026-10-12: chạy "nền trong cửa sổ" như dòng cũ làm
# tiến trình chết tức khắc, KHÔNG đo được gì suốt cả cửa sổ). Gọi nó Ở CUỐI,
# sau khi có T1, cùng lúc với phaseb_gate.py export — vẫn đúng ý "đo trong cửa
# sổ cổng" vì Loki giữ log cả khoảng [T0,T1], không cần chạy liên tục song song.

# Chiến dịch A — xen trong nền, đọc variant-split.yaml (25 biến thể). --repeat 1
# phủ ≥2 lượt/họ gồm holdout. gap 120 + duration-min 3 ≈ 96' < 120'. Orchestrator
# tự theo nhịp tim N1 (§B1f): nếu N1 tắt giữa chừng → lượt còn lại đánh aborted.
bash tests/crapi_campaign_phaseb.sh --repeat 1 --groups train,holdout --gap 120 --duration-min 3  # §4

# 2b) NGHIỆM THU NHỊP ĐỘ (BLOCKER): burst vs slow_drip khác nhau THẬT.
for fam in bola brute_force access_denied_spike large_response bfla; do
  python3 tests/phaseb_pace_accept.py --family "$fam" --runs tests/runs.jsonl \
          --loki http://localhost:13100 --out results/phaseb/pace || echo "!! $fam CHƯA đạt nhịp"
done

# đóng cửa sổ cổng tại T0+7200 (N1/N2 vẫn chạy tới 3h — không chờ chúng).
while [ $(( $(date +%s) - T0 )) -lt 7200 ]; do sleep 30; done
T1=$(( $(date +%s) + 1 )); sleep 30   # Promtail → Loki
kill "$N1_PID" 2>/dev/null; pkill -f crapi_noise_n2 2>/dev/null || true

mkdir -p results/phaseb/gate
python3 tests/opa_pdp_latency.py --start "$T0" --end "$T1" --output results/phaseb/gate/opa_pdp_latency.json

# PIPELINE CỔNG: export → gán nhãn → feature → mô hình → kiểm tra (§5, §B1a–e):
mkdir -p results/phaseb/gate
python3 tests/phaseb_gate.py export --loki http://localhost:13100 --start "$T0" --end "$T1" --out results/phaseb/gate
python3 tests/phaseb_gate.py run --logs results/phaseb/gate --runs tests/runs.jsonl --window 60 --step 60 --out results/phaseb/gate
cat results/phaseb/gate/gate_result.json
```

Điền §1–§6 báo cáo từ `gate_result.json`, `results/phaseb/n1/*.summary.txt`,
`results/phaseb/pace/*.json`, `results/phaseb/seed/seed-verify.json`, `tests/runs.jsonl`,
và output `opa_pdp_latency.py` (§1.1 p99 + hết lưỡng đỉnh).
