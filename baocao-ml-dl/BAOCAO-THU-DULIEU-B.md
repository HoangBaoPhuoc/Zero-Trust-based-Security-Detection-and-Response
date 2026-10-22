# BÁO CÁO THU DỮ LIỆU GIAI ĐOẠN B (B4) — ĐỢT 150 GIỜ

Ghi INCREMENTAL theo từng khúc (§4). Không làm đẹp số — mọi phát hiện bất thường được
ghi nguyên trạng.

Ràng buộc chi phối toàn bộ đợt thu: sửa trong mã nguồn, dựng lại được; **không commit**;
**không đụng Giai đoạn C**; **không làm đẹp số**.

---

## Tổng quan tiến độ

| # | chunk_id | trạng thái | giờ hợp lệ | cộng dồn |
|---|----------|-----------|-----------|----------|
| 1 | c0001-20261012T164833 | valid | 6.167h | **6.167h** / 150h |
| 2 | c0002-20261013T034929 | valid | 6.167h | **12.333h** / 150h |
| 3 | c0003-20261013T101928 | valid | 6.167h | **18.500h** / 150h |
| 4 | c0004-20261013T164755 | valid | 6.167h | **24.667h** / 150h |
| 5 | c0005-20261013T232454 | valid | 6.167h | **30.833h** / 150h |
| 6 | c0006-20261014T055021 | valid | 6.167h | **37.000h** / 150h |
| 7 | c0007-20261014T122146 | valid | 6.167h | **43.167h** / 150h |
| 8 | c0008-20261014T185331 | **gap** (0h tính) | 0.000h | **43.167h** / 150h (không đổi) |
| 9 | c0009-20261015T012417 | valid | 6.167h | **49.334h** / 150h |
| 10 | c0010-20261017T133651 | aborted (crash-restart) | 0.000h | **49.334h** / 150h |
| 11 | c0011-20261017T133724 | aborted (crash-restart) | 0.000h | **49.334h** / 150h |
| 12 | c0012-20261017T134007 | aborted (crash-restart) | 0.000h | **49.334h** / 150h |
| 13 | c0013-20261017T134121 | aborted (crash-restart) | 0.000h | **49.334h** / 150h |
| 14 | c0014-20261017T134225 | **aborted (bff=0)** | 0.000h | **49.334h** / 150h |
| 15 | c0015-20261017T195517 | **aborted (bff=0)** | 0.000h | **49.334h** / 150h |
| 16 | c0016-20261018T083401 | valid (bff=5) | 1.000h | **50.334h** / 150h |
| 17 | c0017-20261018T095235 | valid (bff=310) | 1.000h | **51.334h** / 150h |

Mục tiêu phụ: ≥100 lượt campaign (A) hợp lệ trong toàn đợt — hiện tại: **160 attack** cộng dồn (16 khúc 1 + 19 khúc 2 + 17 khúc 3 + 18 khúc 4 + 18 khúc 5 + 19 khúc 6 + 19 khúc 7 + 17 khúc 8 + 17 khúc 9), 0 aborted trong khúc 2-9 — lưu ý khúc 8 có lượt dữ liệu thật (17 attack) nhưng KHÔNG được tính vào giờ hợp lệ cộng dồn do trạng thái `gap`. Đã vượt mốc 100 lượt. **Mốc 50h cộng dồn (§4) ĐÃ ĐẠT (gần đúng)** ở 49.334h sau khi khúc 9 đóng `valid` — xem phân tích đầy đủ ở mục "B5 §4 — MỐC 50H CỘNG DỒN" bên dưới. **Dừng lại ở đây để báo cáo, KHÔNG tự động chạy khúc 10.**

Khúc 10–13 (17/10/2026 13:36–13:42): bốn khúc aborted rất ngắn do collect_loop bị kill/restart — "bộ thu dừng giữa khúc (phát hiện khi khởi động lại)". Khúc 14–15: aborted vì bff=0 (WireGuard tunnel down — xem §C2 bên dưới). Tổng hợp lệ vẫn **49.334h / 150h** (8 valid + 1 gap + 6 aborted) trước §C2.

Khúc 16–17 (18/10/2026): chạy thêm sau khi WireGuard khôi phục. c0016 valid nhưng bff=5 (rất ít sự kiện BFF, Keycloak vẫn chặn phần lớn). c0017 valid với bff=310 (WireGuard ổn định hơn, BFF nhận được một số login). Tổng hợp lệ cuối đợt: **51.334h / 150h** (10 valid + 1 gap + 6 aborted) — dừng 20/10/2026 do mốc cứng.

---

## B5 — HAI VIỆC SỬA TRƯỚC KHI CHẠY TIẾP TỪ KHÚC 2 (2026-10-13)

### Mục 1 — Khả năng phát hiện nạn nhân (BOLA) suy giảm theo thời gian — ĐÃ SỬA

**Hiện tượng**: khúc 1 có 3/19 lượt `aborted` vì variant BOLA cần 10 victims nhưng
`crapi_bola.sh` chỉ quét cố định 31 trang × 30 bài (= 930 bài gần nhất) qua
`/community/posts/recent`, và sau nhiều giờ N1/N2/campaign đăng bài liên tục, bài
của 15 nạn nhân đã seed (§B1f) bị đẩy ra khỏi 930 bài gần nhất → pool tụt xuống 8.

**Sửa** (`tests/crapi_bola.sh`): thay quét cố định bằng vòng lặp luỹ tiến — quét
thêm trang (`limit=30`/trang) cho tới khi thu đủ `VICTIMS` vehicleid PHÂN BIỆT,
dừng khi (a) đủ số lượng, (b) trang trả về rỗng (hết dữ liệu thật), hoặc (c) chạm
trần an toàn 200 trang (6000 bài). KHÔNG đọc vehicleid từ cache ghi lúc seed —
vẫn đi đúng chuỗi phát hiện thật (community/posts → vehicleid → BOLA), chỉ bước
thu thập thông tin sâu hơn (đúng như kẻ tấn công thật sẽ làm qua nhiều trang).

Trong lúc sửa, phát hiện và vá 2 lỗi công cụ không liên quan đến logic nghiệp vụ:
một dấu `"` dư từ pattern copy-paste gây lỗi cú pháp bash, và một race condition
(đọc file đếm số bài/trang qua stderr NGAY SAU khi process substitution đóng
pipe stdout — không đảm bảo đã flush — khiến vòng quét luôn dừng sau trang 1).
Đã sửa bằng cách gửi số đếm qua CHUNG một pipe với dữ liệu (dòng sentinel `__N__`).

**Nghiệm thu** (`/tmp/bola_accept_victims10.log`): `VICTIMS=10` độc lập → quét 79
trang (2370 bài) → thu đủ **10 vehicleid phân biệt** → **10/10** đọc được dữ liệu
người khác (200 + email chủ xe ≠ kẻ tấn công) → CRS/WAF = 0 trên path BOLA → PASS,
0 aborted.

### Mục 2 — Bộ kiểm rò rỉ (identity/path) bị mù vì ồn — ĐÃ SỬA

**Hiện tượng**: khúc 1 gắn cờ 2392 định danh + 77 path ở sàn `min_occ=3` (identity)
/ `min_occ=5` (path) — phần lớn là rác: với >1 triệu event, rất nhiều định danh chỉ
xuất hiện 1-2 lần nên trivially có `share=100%` (1/1), lấp rò rỉ thật (nếu có)
trong hàng nghìn dòng vô nghĩa.

**Sửa** (`tests/phaseb_gate.py`, hàm `identity_leakage_scan`/`path_leakage_scan`):
nâng sàn số lần xuất hiện tối thiểu lên **`min_occ=10`** cho cả hai (trước: 3 và
5). Hai hàm nay trả kèm thống kê `{min_occ, n_considered, n_below_floor,
n_flagged}` ngoài list `flagged`, in ra dòng log tường minh số đã xét/loại/gắn cờ
thay vì chỉ độ dài list.

**Chạy lại trên dữ liệu khúc 1 đã có** (`results/b4/chunks/c0001-20261012T164833`,
không thu lại):

| | min_occ cũ | gắn cờ (cũ) | min_occ mới | đã xét | loại vì dưới sàn | **gắn cờ (mới)** |
|---|---|---|---|---|---|---|
| identity | 3 | 2392 | **10** | 2392 | 2374 | **18** |
| path/tiền tố | 5 | 77 | **10** | 80 | 1 | **76** |

**Xem kỹ 18 identity + 76 path còn bị gắn cờ sau khi thêm sàn — đây có phải rò rỉ
thật không?** Không. Toàn bộ 18 identity và toàn bộ 76 path đều **lệch về phía
`benign`** (`dominant_class="benign"`, share≈1.0), KHÔNG cái nào lệch về `attack`.
Đây là hệ quả của N1/N2 tạo lưu lượng lành tính liên tục trên các vehicleid/path
dùng chung (ví dụ path `/identity`, `/workshop/api/shop` — 355k/227k lượt gọi
lành tính, chỉ 8-109 lượt gọi từ attack do BOLA/BFLA chạm vào cùng path), còn
identity là các vehicleid nạn nhân BOLA bị N1 gọi lại nhiều lần trong luồng lành
tính (test khác) hơn là trong chính cuộc tấn công. Vì:
  1. Không identity/path nào lệch về **attack** (0/18 identity, 0/76 path) — tức
     không tồn tại "đường tắt theo danh tính/path" mà mô hình có thể học để nhận
     diện attack chỉ bằng cách khớp một UUID/path cụ thể.
  2. Bảng đặc trưng (`FEATURES`) hiện KHÔNG one-hot identity hay path — chỉ dùng
     dạng quan hệ (`n_target`, tiền tố hành động) — nên dù các path/identity này
     có lệch lớp, mô hình không có cách "nhìn thấy" chúng để tạo đường tắt.
  → **Không có rò rỉ đặc trưng thật nào cần xử lý**, khớp với kết luận `leakage_flagged=[]`
    đã có từ trước. Một điểm lạ nhỏ, không phải rò rỉ nhưng đáng ghi chú: identity
    `"1"` (không phải UUID) lọt vào danh sách do `_target_ids()` khớp cả số nguyên
    nhỏ dạng `/orders/1`, `/videos/1` làm "định danh" — đây là artefact của regex
    trích id, không phải vehicleid/email thật; không ảnh hưởng tới kết luận vì vẫn
    lệch về benign (share=0.996), không phải attack.

Kết quả đầy đủ (list 18 identity + 76 path) lưu tại `/tmp/chunk1_rerun/gate_result.json`
(bản chạy lại khúc 1 với sàn mới) để tham chiếu, không ghi đè `gate_result.json`
gốc của khúc 1 (giữ nguyên bằng chứng đã báo cáo).

---

## KHÚC 1 — c0001-20261012T164833

- **Bắt đầu**: 2026-10-12T16:48:34Z
- **Kết thúc**: 2026-10-12T22:58:34Z
- **Thời lượng**: 6.1667h (370 phút kế hoạch)
- **Trạng thái (collect_chunked.py)**: `valid` — không có khoảng khuyết log (`posthoc.aws.gaps=[]`, `posthoc.openstack.gaps=[]`, 2221/2220 bucket cả hai cloud)
- **Số dòng mỗi luồng (export, §0.1)**:
  - `envoy.jsonl` = 793,755 dòng
  - `opa.jsonl` = 362,321 dòng
  - `bff.jsonl` = 2,439 dòng
  - → tất cả >0, export không bị đánh `aborted`.
- **Lượt campaign (A) trong khúc** (lọc theo `t_start` ∈ [16:48:34Z, 22:58:34Z]): **19 lượt** = 16 `attack` + 3 `aborted`.
  - 3 `aborted` đều cùng một nguyên nhân: variant BOLA yêu cầu nhiều `victims` hơn pool nạn nhân hiện có (seed data chỉ có tối đa 8 vehicleid lộ qua community/posts tại thời điểm chạy, có variant cần 10) — đây là hạn chế seed-job đã biết từ B1b, KHÔNG phải lỗi hạ tầng của đợt thu này. Cần seed thêm nạn nhân nếu muốn các variant BOLA victims=10 thành công.
- **Non-200 N1 toàn khúc**: 0.0234% (16/68265) — xa ngưỡng 1%.

### 4 kiểm tra mốc giờ 4h30 (§1, checkpoint bắt buộc)

Chạy lúc `elapsed_h=4.5`, `checked_at` tương ứng ~20:58Z:

| # | Kiểm tra | Kết quả | Chi tiết |
|---|----------|---------|----------|
| 1 | `ultra_long_alive` (SESSION_MAX_AGE/H16) | **PASS** | n=36 dòng, lần cuối cách 163s, 0 non-200 |
| 2 | `svid_renewed_4h` (H17) | **PASS** | valid_from lúc bắt đầu=`2026-10-12T15:00:29Z`, hiện tại=`2026-10-12T20:29:49Z` — SVID đã gia hạn ít nhất 1 lần qua mốc 4h |
| 3 | `n1_non200_pct` | **PASS** | n=50003, non200=16, pct=0.032% (<1%) |
| 4 | `log_continuity` | **PASS** | mẫu sống 90s: aws=2528, openstack=583 (cả hai >0) |

→ Cả 4 kiểm tra PASS. Không kích hoạt quy tắc dừng §3 (checkpoint 1/2 fail). Đây là lần đầu
toàn bộ chuỗi (N1 ultra_long + SPIRE renewal thật + ngưỡng non-200 + continuity 2 cloud)
chạy thật ở cấu hình đợt dài và được xác nhận sống — giải quyết đúng lỗ hổng mà B3 tạo ra
(SESSION_MAX_AGE 6h nhưng N1 trước đó không có phiên nào vượt 2h).

### Kết quả `phaseb_gate.py run` (so với baseline 2h gate — B3, `results/b3/gate/gate_result.json`)

| Chỉ số | Khúc 1 (B4, 6.17h) | Baseline 2h gate (B3) | Nhận xét |
|---|---|---|---|
| `verdict` | **GO** | GO | giữ nguyên |
| `n_events` | 1,158,515 | 360,601 | ~3.2× (khớp thời lượng dài hơn) |
| `n_runs` (label trong `runs.jsonl`) | 1990 | 1000 | |
| `n_windows` | 6139 | 1964 | |
| `label_counts` | attack=108, benign=5854, benign_noise=177 | attack=40, benign=1893, benign_noise=31 | |
| `model_auc` | 0.9858 | 0.9925 | giảm nhẹ (~0.007), vẫn rất cao |
| `recall_by_run` (all/train/holdout) | 0.667 / 0.0 / 1.0 | 0.667 / 0.5 / 0.75 | **train tụt xuống 0 lượt (0/3 lượt train bị phát hiện theo đơn vị lượt ở cửa sổ 60s)** — xem phân tích dưới |
| `recall_by_run_rule` (deny_count>0) | 0.833 / 0.5 / 1.0 | 0.917 / 0.75 / 1.0 | hơi giảm ở `all`/`train`, `holdout` giữ 1.0 |
| `fpr_by_window` | 0.003 | 0.0031 | ~không đổi, vẫn rất thấp |
| `precision_by_window` | 0.357 | 0.786 | **giảm đáng kể** |
| `window_recall_secondary` | 0.082 | 0.579 | **giảm đáng kể** |
| `attack_idle_holdout` (60s) | 157/260 (>50%, có cảnh báo `warn_holdout_sparse`) | 47/? | slow_drip quá thưa so với cửa sổ 60s — core observation đã biết từ B1c, trầm trọng hơn ở khúc dài vì nhiều lượt slow_drip 30' hơn |
| `recall_by_window_width` 300s (all/train/holdout) | 1.0/1.0/1.0 | 0.889/1.0/0.75 | ở cửa sổ rộng hơn, khúc 1 THỰC RA tốt hơn baseline |
| `detection_latency` (holdout, giây) | median=569.5s (range 72–929) | median=0s (range 0–102) | **độ trễ phát hiện tăng mạnh** ở cửa sổ 60s — hệ quả trực tiếp của slow_drip thực chạy đủ 30 phút thật (baseline 2h gate dùng cấu hình rút ngắn `--duration-min 3`, nên "slow_drip" baseline gần như tức thời) |
| `identity_leakage_flagged` | 2392 định danh | (chưa so, không trọng yếu — đã loại khỏi đặc trưng) | |
| `path_leakage_flagged` | 77 path/tiền tố | | đã bị loại khỏi đặc trưng theo thiết kế |
| `features_not_computable` | `code_5xx`, `posture_bad` | | giống baseline, không mới |

**Đánh giá trung thực, không làm đẹp số:**

1. **VERDICT vẫn GO** — mô hình vẫn phân biệt tốt hơn luật `deny_count>0` ở cửa sổ 60s
   trên tổng thể (AUC 0.9858, FPR thấp), nên cổng vẫn mở theo đúng tiêu chí đã định.
2. Tuy nhiên đây là lần đầu chạy ở **cấu hình đợt dài thật** (gap 600s, slow_drip chạy
   đủ 30 phút, không rút ngắn `--duration-min`) — và các chỉ số nhạy với độ trễ/độ thưa
   (`precision_by_window`, `window_recall_secondary`, `detection_latency`,
   `recall_by_run` ở train) đều **xấu hơn rõ rệt** so với baseline 2h gate. Đây **không
   phải regression của hệ thống** mà là baseline 2h gate đo ở điều kiện dễ hơn
   (slow_drip rút ngắn → gần như tức thời). Khúc 1 cho thấy ở cửa sổ 60s, slow_drip thật
   bị "loãng" ra nhiều cửa sổ gần như benign (`attack_idle_holdout` 157/260 >50%,
   đúng với cảnh báo `warn_holdout_sparse` mà code tự in ra) — khớp với ghi nhận ở
   §B1c rằng cửa sổ 60s không đủ rộng cho slow_drip 30 phút.
3. Ở cửa sổ rộng hơn (300s), khúc 1 **tốt hơn** baseline (`recall_by_run` all=1.0 so với
   0.889) — cho thấy tín hiệu tồn tại, chỉ là cửa sổ 60s quá hẹp để bắt kịp nhịp thật của
   slow_drip. Đây là input quan trọng cho Giai đoạn C (lựa chọn độ rộng cửa sổ) nhưng
   theo đúng ràng buộc "không đụng Giai đoạn C", không xử lý gì thêm ở đây — chỉ ghi
   nhận để Giai đoạn C tham khảo.
4. `recall_by_run` train=0.0 (0/3 lượt train bị gắn cờ ở cửa sổ 60s) là điểm cần theo dõi
   tiếp ở các khúc sau — với n_runs_in_test=6 (quá nhỏ để kết luận chắc, cần nhiều lượt
   train hơn qua các khúc tiếp theo).
5. **Không có rò rỉ đặc trưng (`leakage_flagged=[]`)** — kiểm chống rò rỉ (B1c) vẫn sạch.

### Kết luận khúc 1

- Không có điều kiện dừng nào theo §3 kích hoạt (checkpoint 1/2 đều PASS).
- Khúc được tính **valid**, cộng 6.167h vào tổng (hiện tại 6.167h / 150h).
- Phát hiện cần lưu ý cho các khúc sau / Giai đoạn C: cửa sổ 60s hiện tại không đủ rộng
  cho slow_drip 30 phút thật (nhiều cửa sổ rơi vào "attack_idle"); các chỉ số
  `precision_by_window`/`window_recall_secondary`/`detection_latency` ở 60s xấu hơn
  baseline 2h gate vì baseline đo ở cấu hình rút ngắn, không phải vì hệ thống kém đi.
- 3 lượt BOLA aborted do thiếu victim pool — hạn chế seed data đã biết, không phải lỗi
  hạ tầng thu dữ liệu.

**→ THEO ĐÚNG §1: DỪNG Ở ĐÂY, BÁO CÁO, KHÔNG CHẠY KHÚC 2 TRONG BƯỚC NÀY. Chờ xác nhận
trước khi tiếp tục sang §2 (khúc 2 trở đi).**

---

## KHÚC 2 — c0002-20261013T034929 (B5 §3, sau 2 lần sửa ở mục 1/mục 2)

- **Bắt đầu**: 2026-10-13T03:49:29Z
- **Kết thúc**: 2026-10-13T09:59:29Z
- **Thời lượng**: 6.1667h (370 phút kế hoạch)
- **Trạng thái (collect_chunked.py)**: `valid` — "`[collect] KẾT THÚC c0002-20261013T034929: valid (6.1667 h)`"
- **Số dòng mỗi luồng (export, §0.1)**:
  - `envoy.jsonl` = 788,335 dòng
  - `opa.jsonl` = 360,292 dòng
  - `bff.jsonl` = 2,420 dòng
  - → tất cả >0, export không bị đánh `aborted` (`[postprocess] OK`).
- **Lượt campaign (A) trong khúc** (lọc theo `t_start` ∈ [03:49:29Z, 09:59:29Z]): **19 lượt = 19 `attack` + 0 `aborted`** (abort_ratio = 0%).
  - Phân theo family: `bola`×8 (gồm cả victims=8 và victims=10, cả hai pace burst và slow_drip), `bfla`×4, `lateral_movement`×2, `brute_force`×4, `access_denied_spike`×1.
  - **0/8 lượt BOLA bị aborted** — khác hẳn khúc 1 (3/19 aborted, đều do BOLA thiếu victim pool). Đây là xác nhận trực tiếp dưới tải thật, chạy hết 370 phút liên tục, rằng **fix mục 1 (phân trang lũy tiến `community/posts/recent`) đã giải quyết đúng vấn đề suy giảm theo thời gian** — kể cả variant `victims=10` (yêu cầu nghiêm ngặt nhất) chạy thành công 10/10 ở cả burst và slow_drip, có lần phải quét tới 79 trang mới đủ.
- **Non-200 N1 toàn khúc**: cao nhất quan sát được qua các cửa sổ theo dõi là 0.15% (16/11008), còn lại hầu hết 0.00% — xa ngưỡng 1%. Không kích hoạt quy tắc dừng §5.

### Nhận xét khúc 2

- Không có điều kiện dừng nào theo §5 kích hoạt.
- Khúc được tính **valid**, cộng 6.167h vào tổng (cộng dồn **12.333h / 150h**).
- Fix mục 1 (BOLA pagination) đã được kiểm chứng không chỉ ở bài test độc lập (nghiệm thu
  trước khi chạy khúc 2) mà còn dưới điều kiện thực — toàn bộ 370 phút, tải N1/N2 liên tục
  đẩy bài viết community mới (đúng cơ chế gây suy giảm ban đầu) — và không hề có BOLA abort.
- Không chạy `phaseb_gate.py run` riêng cho khúc 2 (theo quyết định ở §3: chỉ bắt buộc ở
  khúc 1 và ở mốc cộng dồn 50h — tiết kiệm ~30 phút tính toán mỗi khúc trên host hạn chế RAM).
- Export path: `results/b4/chunks/c0002-20261013T034929/`.

### Phát hiện trong lúc thu

- Không có gì bất thường trong khúc 2. Tất cả 5 giám sát viên (health check theo giờ)
  đều thấy N1/N2/campaign chạy ổn định, non-200% thấp, 0 aborted suốt toàn khúc.
- Đây là bằng chứng tích cực (không phải vấn đề cần ghi nhận theo nghĩa tiêu cực), nhưng
  được ghi lại đúng nguyên trạng theo yêu cầu "không làm đẹp số": khúc 2 sạch hơn khúc 1
  rõ ràng, và sự khác biệt duy nhất đáng kể giữa hai khúc là việc áp fix mục 1 trước khi
  chạy khúc 2.

---

## KHÚC 3 — c0003-20261013T101928

- **Bắt đầu**: 2026-10-13T10:19:28Z
- **Kết thúc**: 2026-10-13T16:29:28Z
- **Thời lượng**: 6.1667h (370 phút kế hoạch)
- **Trạng thái (collect_chunked.py)**: `valid` — "`[collect] KẾT THÚC c0003-20261013T101928: valid (6.1667 h)`"
- **Số dòng mỗi luồng (export, §0.1)**:
  - `envoy.jsonl` = 790,953 dòng
  - `opa.jsonl` = 361,328 dòng
  - `bff.jsonl` = 2,434 dòng
  - → tất cả >0, export không bị đánh `aborted` (`[postprocess] OK`).
- **Lượt campaign (A) trong khúc** (lọc theo `t_start` ∈ [10:19:28Z, 16:29:28Z]): **17 lượt = 17 `attack` + 0 `aborted`** (abort_ratio = 0%).
  - Phân theo family: `bola`×8 (victims=2,3,8,10, cả burst và slow_drip), `bfla`×4, `lateral_movement`×2, `brute_force`×3.
  - **0/8 lượt BOLA bị aborted** — khúc thứ 3 liên tiếp (sau khúc 2) không có BOLA abort nào. Fix mục 1
    (phân trang lũy tiến) đã được xác nhận giữ vững qua 2 khúc liên tiếp chạy đủ 370 phút dưới tải thật.
- **Non-200 N1 toàn khúc**: cao nhất quan sát 0.14% (16/11047), còn lại hầu hết 0.00% — xa ngưỡng 1%.

### Nhận xét khúc 3

- Không có điều kiện dừng nào theo §5 kích hoạt.
- Khúc được tính **valid**, cộng 6.167h vào tổng (cộng dồn **18.500h / 150h**).
- Export path: `results/b4/chunks/c0003-20261013T101928/`.

### Phát hiện trong lúc thu

- Không có gì bất thường. Giống khúc 2, khúc 3 chạy sạch suốt toàn bộ 370 phút — không
  BOLA abort, không N1 lỗi vượt ngưỡng, không gap log. Ghi nguyên trạng theo yêu cầu
  "không làm đẹp số": hiện tại chưa có phát hiện tiêu cực nào cần nêu từ khúc 2 trở đi.

---

## KHÚC 4 — c0004-20261013T164755

- **Bắt đầu**: 2026-10-13T16:47:55Z
- **Kết thúc**: 2026-10-13T22:57:55Z
- **Thời lượng**: 6.1667h (370 phút kế hoạch)
- **Trạng thái (collect_chunked.py)**: `valid` — "`[collect] KẾT THÚC c0004-20261013T164755: valid (6.1667 h)`"
- **Số dòng mỗi luồng (export, §0.1)**:
  - `envoy.jsonl` = 782,121 dòng
  - `opa.jsonl` = 358,232 dòng
  - `bff.jsonl` = 2,413 dòng
  - → tất cả >0, export không bị đánh `aborted` (`[postprocess] OK`).
- **Lượt campaign (A) trong khúc** (lọc theo `t_start` ∈ [16:47:55Z, 22:57:55Z]): **18 lượt = 18 `attack` + 0 `aborted`** (abort_ratio = 0%).
  - Phân theo family: `bola`×8 (victims=2,3,8,10, cả burst và slow_drip), `bfla`×4, `lateral_movement`×2, `brute_force`×4.
  - **0/8 lượt BOLA bị aborted** — khúc thứ 4 liên tiếp (sau khúc 2, 3) không có BOLA abort nào, bao gồm trường hợp victims=8 phải quét 53 trang `community/posts/recent`. Fix mục 1 (phân trang lũy tiến) tiếp tục được xác nhận giữ vững qua 3 khúc liên tiếp chạy đủ 370 phút dưới tải thật.
- **Non-200 N1 toàn khúc**: cao nhất quan sát 0.15% (16/10791), còn lại hầu hết 0.00% — xa ngưỡng 1%.

### Nhận xét khúc 4

- Không có điều kiện dừng nào theo §5 kích hoạt.
- Khúc được tính **valid**, cộng 6.167h vào tổng (cộng dồn **24.667h / 150h**).
- `phaseb_gate.py run` tiếp tục được bỏ qua theo từng khúc, đúng phạm vi §3 (chỉ bắt buộc ở khúc 1 — đã làm — và ở mốc 50h cộng dồn §4, chưa tới).
- Export path: `results/b4/chunks/c0004-20261013T164755/`.

### Phát hiện trong lúc thu

- Không có gì bất thường. Khúc 4 chạy sạch suốt toàn bộ 370 phút, kể cả khi `collect_chunked.py`
  tiếp tục xử lý xong lượt campaign đang chạy trước khi đóng khúc đúng 370 phút theo lịch (postprocess
  bắt đầu ~1 phút 22 giây sau mốc 370 phút danh định — bình thường, không phải lỗi). Không BOLA abort,
  không N1 lỗi vượt ngưỡng, không gap log. Ghi nguyên trạng theo yêu cầu "không làm đẹp số": chưa có
  phát hiện tiêu cực nào cần nêu từ khúc 2 trở đi (3 khúc liên tiếp sạch).

---

## KHÚC 5 — c0005-20261013T232454

- **Bắt đầu**: 2026-10-13T23:24:54Z
- **Kết thúc**: 2026-10-14T05:34:54Z
- **Thời lượng**: 6.1667h (370 phút kế hoạch)
- **Trạng thái (collect_chunked.py)**: `valid` — "`[collect] KẾT THÚC c0005-20261013T232454: valid (6.1667 h)`"
- **Số dòng mỗi luồng (export, §0.1)**:
  - `envoy.jsonl` = 780,807 dòng
  - `opa.jsonl` = 357,952 dòng
  - `bff.jsonl` = 2,405 dòng
  - → tất cả >0, export không bị đánh `aborted` (`[postprocess] OK`).
- **Lượt campaign (A) trong khúc** (lọc theo `t_start` ∈ [23:24:54Z, 05:34:54Z]): **18 lượt = 18 `attack` + 0 `aborted`** (abort_ratio = 0%).
  - Phân theo family: `bola`×8 (victims=2,3,8,10, cả burst và slow_drip), `bfla`×4, `lateral_movement`×2, `brute_force`×4.
  - **0/8 lượt BOLA bị aborted** — khúc thứ 5 liên tiếp (sau khúc 2, 3, 4) không có BOLA abort nào, bao gồm trường hợp victims=8 phải quét nhiều trang `community/posts/recent`. Fix mục 1 (phân trang lũy tiến) tiếp tục được xác nhận giữ vững qua 4 khúc liên tiếp chạy đủ 370 phút dưới tải thật.
- **Non-200 N1 toàn khúc**: cao nhất quan sát 0.13% (14/11027), còn lại hầu hết 0.00%–0.02% — xa ngưỡng 1%.

### Nhận xét khúc 5

- Không có điều kiện dừng nào theo §5 kích hoạt.
- Khúc được tính **valid**, cộng 6.167h vào tổng (cộng dồn **30.833h / 150h**).
- `phaseb_gate.py run` tiếp tục được bỏ qua theo từng khúc, đúng phạm vi §3 (chỉ bắt buộc ở khúc 1 — đã làm — và ở mốc 50h cộng dồn §4, chưa tới — còn khoảng 19h nữa).
- Export path: `results/b4/chunks/c0005-20261013T232454/`.

### Phát hiện trong lúc thu

- Không có gì bất thường. Khúc 5 chạy sạch suốt toàn bộ 370 phút, bao gồm việc hoàn tất một lượt
  `brute_force` slow_drip kéo dài 30 phút trước khi `collect_chunked.py` đóng khúc đúng theo lịch — đây
  là hành vi bình thường (chờ lượt campaign đang chạy xong trước khi kết thúc). Không BOLA abort, không
  N1 lỗi vượt ngưỡng, không gap log. Ghi nguyên trạng theo yêu cầu "không làm đẹp số": chưa có phát hiện
  tiêu cực nào cần nêu từ khúc 2 trở đi (4 khúc liên tiếp sạch).

---

## KHÚC 6 — c0006-20261014T055021

- **Bắt đầu**: 2026-10-14T05:50:22Z
- **Kết thúc**: 2026-10-14T12:00:22Z
- **Thời lượng**: 6.1667h (370 phút kế hoạch)
- **Trạng thái (collect_chunked.py)**: `valid` — "`[collect] KẾT THÚC c0006-20261014T055021: valid (6.1667 h)`"
- **Số dòng mỗi luồng (export, §0.1)**:
  - `envoy.jsonl` = 788,069 dòng
  - `opa.jsonl` = 360,374 dòng
  - `bff.jsonl` = 2,451 dòng
  - → tất cả >0, export không bị đánh `aborted` (`[postprocess] OK`, rc=0).
- **Lượt campaign (A) trong khúc** (lọc theo `t_start` ∈ [05:50:22Z, 12:00:22Z]): **19 lượt = 19 `attack` + 0 `aborted`** (abort_ratio = 0%).
  - Phân theo family: `bola`×8 (victims=2,3,8,10, cả burst và slow_drip, bao gồm 1 lượt victims=8 slow_drip), `bfla`×4, `lateral_movement`×2, `brute_force`×4, `access_denied_spike`×1.
  - **0/8 lượt BOLA bị aborted** — khúc thứ 5 liên tiếp (sau khúc 2, 3, 4, 5) không có BOLA abort nào. Fix mục 1 (phân trang lũy tiến) tiếp tục giữ vững qua 5 khúc liên tiếp chạy đủ 370 phút dưới tải thật.
  - Family `access_denied_spike` xuất hiện trong khúc này (train:denied_burst) — đã từng gặp ở các khúc trước, không phải hiện tượng mới.
- **Non-200 N1 toàn khúc**: cao nhất quan sát 0.11% (12/11319), còn lại hầu hết 0.00%–0.02% — xa ngưỡng 1%.

### Nhận xét khúc 6

- Không có điều kiện dừng nào theo §5 kích hoạt.
- Khúc được tính **valid**, cộng 6.167h vào tổng (cộng dồn **37.000h / 150h**).
- `phaseb_gate.py run` tiếp tục được bỏ qua theo từng khúc, đúng phạm vi §3 (chỉ bắt buộc ở khúc 1 — đã làm — và ở mốc 50h cộng dồn §4, chưa tới — còn khoảng 13h nữa, dự kiến rơi vào giữa hoặc cuối khúc 8).
- Export path: `results/b4/chunks/c0006-20261014T055021/`.

### Phát hiện trong lúc thu

- Không có gì bất thường. Khúc 6 chạy sạch suốt toàn bộ 370 phút, đóng khúc gần sát mốc danh nghĩa
  (`t_end` = 12:00:22Z, đúng 370.0 phút sau `t_start`) sau khi hoàn tất lượt `access_denied_spike` đang
  chạy. Không BOLA abort, không N1 lỗi vượt ngưỡng, không gap log. Ghi nguyên trạng theo yêu cầu
  "không làm đẹp số": chưa có phát hiện tiêu cực nào cần nêu từ khúc 2 trở đi (5 khúc liên tiếp sạch).

---

## KHÚC 7 — c0007-20261014T122146

- **Bắt đầu**: 2026-10-14T12:21:46Z
- **Kết thúc**: 2026-10-14T18:31:46Z
- **Thời lượng**: 6.1667h (370 phút kế hoạch)
- **Trạng thái (collect_chunked.py)**: `valid` — "`[collect] KẾT THÚC c0007-20261014T122146: valid (6.1667 h)`"
- **Số dòng mỗi luồng (export, §0.1)**:
  - `envoy.jsonl` = 787,906 dòng
  - `opa.jsonl` = 360,151 dòng
  - `bff.jsonl` = 2,427 dòng
  - → tất cả >0, export không bị đánh `aborted` (`[postprocess] OK`, rc=0).
- **Lượt campaign (A) trong khúc** (lọc theo `t_start` ∈ [12:21:46Z, 18:31:46Z]): **19 lượt = 19 `attack` + 0 `aborted`** (abort_ratio = 0%).
  - Phân theo family: `bola`×8 (victims=2,3,8,10, cả burst và slow_drip), `bfla`×4, `lateral_movement`×2, `brute_force`×4, `access_denied_spike`×1 (`train:denied_burst`).
  - **0/8 lượt BOLA bị aborted** — khúc thứ 6 liên tiếp (sau khúc 2, 3, 4, 5, 6) không có BOLA abort nào. Fix mục 1 tiếp tục giữ vững qua 6 khúc liên tiếp chạy đủ 370 phút dưới tải thật.
- **Non-200 N1 toàn khúc**: cao nhất quan sát 0.13% (14/11009), còn lại hầu hết 0.00%–0.02% — xa ngưỡng 1%.

### Nhận xét khúc 7

- Không có điều kiện dừng nào theo §5 kích hoạt (0 aborted được ghi nhận — xem phát hiện bên dưới về lượt bị cắt ngang không ghi record).
- Khúc được tính **valid**, cộng 6.167h vào tổng (cộng dồn **43.167h / 150h**).
- `phaseb_gate.py run` tiếp tục được bỏ qua theo từng khúc, đúng phạm vi §3. Còn khoảng **6.8h** nữa để tới mốc 50h cộng dồn §4 — rất gần: khúc 8 (dự kiến đóng ở ~49.33h) gần như chắc chắn là nơi chạm mốc 50h (theo nghĩa gần đúng "~50h" của §4).
- Export path: `results/b4/chunks/c0007-20261014T122146/`.

### Phát hiện trong lúc thu

- **Phát hiện đáng chú ý (lần đầu quan sát trong 7 khúc)**: lượt campaign #20 (`family=access_denied_spike`,
  `variant_group=holdout:denied_slowdrip`, `pace=slow_drip`) bắt đầu lúc ~18:29Z, ngay trước khi
  `collect_chunked.py` đóng khúc ở mốc 370 phút (18:31:46Z). Khác với các khúc trước (ví dụ khúc 5, 6 —
  nơi `collect_chunked.py` chờ lượt đang chạy hoàn tất trước khi kết thúc), lần này lượt #20 **bị SIGTERM
  cắt ngang giữa chừng** và **không ghi lại bản ghi nào vào `tests/runs.jsonl`** (không phải `attack`,
  không phải `aborted` — biến mất hoàn toàn khỏi sổ sách). Xác nhận đây là hành vi đã có trong code
  (`tests/phaseb_chunk_workload.sh` dòng 5-7, 80-82: "collect_chunked.py SIGTERM cả process group khi hết
  CHUNK_MINUTES — không tự [chờ]"), không phải lỗi mới phát sinh, nhưng là lần đầu tiên khúc nào đó thực sự
  rơi vào tình huống này (6 khúc trước đều may mắn có lượt cuối hoàn tất kịp trước mốc đóng).
  **Hệ quả cần lưu ý cho kiểm tra phủ variant ở mốc 50h (§4 phần 2)**: lượt `holdout:denied_slowdrip` của
  khúc 7 không tính vào bất kỳ thống kê nào (không phải lượt hợp lệ, không phải lượt aborted) — cần đảm bảo
  variant này đã có ≥1 lượt ghi nhận thành công ở khúc khác (đã có, ví dụ khúc 1 lúc 2026-10-12T11:22:35Z)
  để không bị xem là "bị bỏ sót âm thầm" trong toàn đợt.
  Không BOLA abort, không N1 lỗi vượt ngưỡng, không gap log. Ghi nguyên trạng theo yêu cầu "không làm đẹp số".

---

## KHÚC 8 — c0008-20261014T185331 — **GAP, KHÔNG TÍNH GIỜ**

- **Bắt đầu (kế hoạch, dùng cho export)**: 2026-10-14T18:53:31Z
- **Kết thúc (kế hoạch, dùng cho export)**: 2026-10-15T00:03:31Z (370 phút kế hoạch)
- **Kết thúc thực tế (process)**: ~2026-10-15T01:18Z — tiến trình `collect_chunked.py` chạy quá mốc kế hoạch
  gần **75 phút** vì chờ hai lượt campaign slow_drip 30 phút liên tiếp hoàn tất (`holdout:brute_slow_dense`,
  `holdout:brute_slow_spray`) trước khi tự đóng khúc.
- **Trạng thái (collect_chunked.py)**: **`gap` (0.000h)** — dòng log: "`[collect] KẾT THÚC
  c0008-20261014T185331: gap (0.0 h) — hậu kiểm Loki thất bại: Remote end closed connection without
  response`". Đây là **khúc đầu tiên trong 8 khúc không đạt `valid`**.
- **Nguyên nhân xác định được**: `collect_chunked.py` tự chạy một bước "hậu kiểm" riêng (độ tươi dữ liệu +
  kiểm tra khoảng trống theo bucket, gọi Loki qua `LOKI_URL=http://127.0.0.1:13100`, xem `tests/collect_chunked.py`
  dòng ~208-292) — bước này gặp lỗi kết nối tới Loki đúng lúc port-forward (`kubectl port-forward svc/loki -n
  plg-stack 13100:3100`) bị rớt. Port-forward này chạy trong vòng lặp tự khởi động lại
  (`while true; do kubectl port-forward ...; sleep 3; done`) nên đã tự phục hồi trong vài giây. Đã xác minh
  trực tiếp: `curl http://127.0.0.1:13100/ready` trả về `200` ngay sau đó — Loki đang khỏe mạnh, đây là một
  cú giật kết nối (connection drop) **thoáng qua, không phải Loki sập thật**.
- **Dữ liệu thực tế KHÔNG bị mất**: bước export riêng (`phaseb_gate.py export`, chạy sau và độc lập với bước
  hậu kiểm nói trên) đã thành công đầy đủ cho đúng khung giờ kế hoạch của khúc này:
  - `envoy.jsonl` = 788,147 dòng
  - `opa.jsonl` = 360,493 dòng
  - `bff.jsonl` = 2,465 dòng
  - → tất cả >0, `[postprocess] OK`, `=== DONE === rc=0`. Quy mô dữ liệu tương đương các khúc trước.
- **Lượt campaign (A) trong khúc** (lọc theo `t_start` ∈ [18:53:31Z, 01:03:31Z]): **17 lượt = 17 `attack` +
  0 `aborted`**. Phân theo family: `bola`×8, `bfla`×4, `lateral_movement`×2, `brute_force`×3
  (`train:brute_burst_dense`, `train:brute_burst_spray`, `holdout:brute_slow_dense`).
  - **0/8 lượt BOLA bị aborted** — chuỗi sạch BOLA kéo dài thành **7 khúc liên tiếp** (2-8) tính theo dữ liệu
    thực tế thu được, dù khúc này không được tính giờ hợp lệ.
  - Campaign #18 (`holdout:brute_slow_spray`, slow_drip 30 phút) được bắt đầu nhưng **không có bản ghi
    `attack`/`aborted` nào trong `tests/runs.jsonl`** — tương tự tình huống SIGTERM-cắt-ngang của khúc 7
    (lượt #20, `holdout:denied_slowdrip`): log cho thấy mới đi được ~11/15 lần thử đăng nhập dạng chấm `.`
    trước khi tiến trình kết thúc, không có dòng "15/15" hay `crapi_run_campaign` cho lượt này. Đây là lần
    **thứ hai** quan sát hiện tượng lượt cuối bị cắt ngang không ghi record (lần đầu: khúc 7).
- **Non-200 N1 toàn khúc**: cao nhất quan sát 0.15% (16/10547), còn lại 0.00%. Xa ngưỡng 1%, không kích hoạt
  điều kiện dừng §5.

### Nhận xét khúc 8

- **Không điều kiện dừng nào theo §5 (N1 non-200%, abort ratio) bị kích hoạt** — dữ liệu campaign thu được
  trong khúc này hoàn toàn bình thường (17 attack, 0 aborted, BOLA fix vẫn giữ vững).
- **Tuy nhiên khúc này KHÔNG được collect_chunked.py tính là `valid`** do bước hậu kiểm riêng của nó (độc
  lập với export) gặp lỗi kết nối Loki thoáng qua. Theo đúng tinh thần "không làm đẹp số", khúc này được ghi
  nhận trung thực là **`gap`, cộng 0.000h**, dù dữ liệu thô (envoy/opa/bff, runs.jsonl) hoàn toàn dùng được
  và đã được export đầy đủ vào `results/b4/chunks/c0008-20261014T185331/`.
- **Hệ quả**: tổng giờ hợp lệ cộng dồn **VẪN giữ nguyên ở 43.167h / 150h** — mốc 50h cộng dồn (§4) **CHƯA
  đạt được**, trái với kỳ vọng ban đầu (49.334h) đặt ra khi khởi động khúc 8. Quyết định: tiếp tục chạy một
  khúc kế tiếp (sẽ dùng chunk_id mới, ví dụ `c0009-...`) theo đúng quy trình thường lệ (`run-chunk-next.sh`),
  không coi đây là điều kiện dừng theo §5, và dời mốc kiểm tra 50h sang khi khúc kế tiếp đóng `valid` (dự
  kiến ~49.33h nếu khúc đó đóng đúng 370 phút không gặp sự cố tương tự).
- Export path: `results/b4/chunks/c0008-20261014T185331/` (dữ liệu hợp lệ về mặt nội dung, dù không được
  tính giờ theo quy ước của collect_chunked.py).

### Phát hiện trong lúc thu

- **Phát hiện đáng chú ý #1 — khúc đầu tiên bị đánh `gap`**: như mô tả ở trên, nguyên nhân là lỗi kết nối
  Loki thoáng qua trong bước hậu kiểm riêng của `collect_chunked.py`, không phải do thiếu dữ liệu thật hay
  lỗi ứng dụng. Đây là một điểm yếu vận hành đáng lưu ý cho các đợt thu dài hạn kế tiếp: port-forward
  `kubectl` có thể rớt kết nối ngắn hạn và khiến một khúc bị loại khỏi tổng giờ hợp lệ dù toàn bộ dữ liệu
  thực tế của khúc đó vẫn tồn tại và export được bình thường. Ghi nguyên trạng, không fix trong phiên này vì
  nguyên tắc "không đụng Giai đoạn C" và phạm vi đang chạy là B5§3 (thu dữ liệu), không phải sửa lỗi hạ tầng.
- **Phát hiện đáng chú ý #2 — lượt campaign cuối bị cắt ngang lần thứ 2**: `holdout:brute_slow_spray` (lượt
  #18) không có bản ghi trong `runs.jsonl`, tương tự lượt `holdout:denied_slowdrip` ở khúc 7. Cần xác nhận
  ở mốc kiểm tra variant-coverage rằng cả hai variant này (`holdout:denied_slowdrip` và
  `holdout:brute_slow_spray`) đều có ≥1 lượt ghi nhận thành công ở khúc khác trong toàn đợt.
  Không BOLA abort, không N1 lỗi vượt ngưỡng. Ghi nguyên trạng theo yêu cầu "không làm đẹp số".

---

## KHÚC 9 — c0009-20261015T012417

- **Bắt đầu**: 2026-10-15T01:24:18Z
- **Kết thúc**: 2026-10-15T07:34:18Z
- **Thời lượng**: 6.1667h (370 phút kế hoạch)
- **Trạng thái (collect_chunked.py)**: `valid` — "`[collect] KẾT THÚC c0009-20261015T012417: valid (6.1667 h)`".
  Không có khoảng khuyết hậu kiểm Loki lần này (khác khúc 8) — `posthoc.aws.gaps=[]`,
  `posthoc.openstack.gaps=[]`, 2221/2220 bucket cả hai cloud.
- **Số dòng mỗi luồng (export, §0.1)**:
  - `envoy.jsonl` = 785,501 dòng
  - `opa.jsonl` = 359,306 dòng
  - `bff.jsonl` = 2,358 dòng
  - → tất cả >0, `[postprocess] OK`, `=== DONE === rc=0`.
- **Lượt campaign (A) trong khúc** (lọc theo `t_start` ∈ [01:24:18Z, 07:34:18Z]): **17 lượt = 17 `attack` +
  0 `aborted`** (abort_ratio = 0%). Phân theo family: `bola`×8 (4 train burst + 4 holdout slow_drip,
  victims=2,3,8,10), `bfla`×4 (2 train + 2 holdout), `lateral_movement`×2 (1 train + 1 holdout),
  `brute_force`×3 (`train:brute_burst_dense`, `train:brute_burst_spray`, `holdout:brute_slow_dense`).
  - **0/8 lượt BOLA bị aborted** — khúc thứ 8 liên tiếp (2-9) không có BOLA abort nào tính theo dữ liệu
    thực tế thu được (dù khúc 8 không được tính giờ hợp lệ). Fix mục 1 tiếp tục giữ vững.
- **Non-200 N1 toàn khúc**: cao nhất quan sát 0.15% (16/10685), các lần đo còn lại 0.00%. Xa ngưỡng 1%,
  không kích hoạt điều kiện dừng §5.

### Nhận xét khúc 9

- Không có điều kiện dừng nào theo §5 kích hoạt.
- Khúc đóng **valid**, cộng 6.167h vào tổng → cộng dồn **49.334h / 150h**.
- **Mốc 50h cộng dồn (§4) coi như ĐÃ ĐẠT** (theo nghĩa gần đúng "~50h" nêu trong §4) — dừng chạy khúc 10,
  chuyển sang phân tích 5 phần ở mục "B5 §4" bên dưới.
- Export path: `results/b4/chunks/c0009-20261015T012417/`.

### Phát hiện trong lúc thu

- **Lượt campaign cuối bị cắt ngang — LẦN THỨ 3, cùng một variant**: Campaign #18
  (`family=brute_force`, `variant_group=holdout:brute_slow_spray`, `pace=slow_drip`, `duration_min=30`)
  bắt đầu lúc ~07:15Z, tức là ngay trước khi `collect_chunked.py` đóng khúc ở mốc 370 phút (07:34:18Z).
  Giống hệt tình huống ở khúc 8 (cùng variant `holdout:brute_slow_spray` bị cắt lần đầu), lượt #18 **lại bị
  cắt ngang, không có bản ghi nào trong `tests/runs.jsonl`**. Đây không còn là một sự cố đơn lẻ: đây là lần
  thứ 3 quan sát hiện tượng lượt cuối bị cắt ngang trong 9 khúc (khúc 7: `holdout:denied_slowdrip`; khúc 8
  và khúc 9: `holdout:brute_slow_spray` — hai lần liên tiếp CÙNG một variant). Nguyên nhân gốc đã biết từ
  khúc 7 (`tests/phaseb_chunk_workload.sh`: SIGTERM cả process group khi hết `CHUNK_MINUTES`, không chờ lượt
  đang chạy). Việc `holdout:brute_slow_spray` bị cắt 2/2 lần nó rơi gần mốc đóng khúc gợi ý nhịp campaign
  (gap 600s giữa lượt + các slow_drip 30 phút trước nó) có xu hướng đẩy đúng variant này tới gần biên 370
  phút một cách hệ thống hơn là ngẫu nhiên — đáng ghi chú cho đợt thu kế tiếp, nhưng KHÔNG coi là thiếu phủ
  variant vì `holdout:brute_slow_spray` đã có 8 lượt thành công ở các khúc khác (xem phần 2 của phân tích
  §4 bên dưới). Không fix trong phiên này (ngoài phạm vi B5§3, không đụng Giai đoạn C).

---

## B5 §4 — MỐC 50H CỘNG DỒN: PHÂN TÍCH GIỮA ĐỢT (2026-10-15, sau khúc 9)

Cộng dồn đạt **49.334h / 150h** sau khi khúc 9 đóng `valid` — ban đầu dự kiến mốc này rơi ở khúc 8
(~49.33h) nhưng khúc 8 bị đánh `gap` (xem mục riêng ở trên) nên mốc thực tế dời sang khúc 9. Theo đúng quy
trình, **KHÔNG chạy khúc 10** — dừng lại để chạy phân tích 5 phần dưới đây, rồi báo cáo và CHỜ
xác nhận.

### Phần 1 — Gate run (`phaseb_gate.py run`) trên dữ liệu cộng dồn — **KHÔNG HOÀN TẤT do thiếu RAM**

- Đã thử chạy `phaseb_gate.py run` trên TOÀN BỘ dữ liệu export của 9 khúc (envoy+opa+bff ghép từ
  `results/b4/chunks/c0001...c0009`, gồm cả khúc 8 — dữ liệu khúc 8 THẬT và export được đầy đủ dù không
  tính giờ). Vì ghép trực tiếp bằng `cat` sẽ nhân đôi ~15GB dữ liệu đã có (disk lúc đó chỉ còn ~13.6GB
  trống, sau đó cạn hẳn — xem phần 4), đã dùng **named pipe (FIFO)** để ghép luồng mà không tốn thêm dung
  lượng đĩa.
- `phaseb_gate.py run` đọc toàn bộ ~1.15 triệu sự kiện/khúc × 9 khúc ≈ **10+ triệu sự kiện** vào một list
  Python duy nhất (để sort theo timestamp — xem `tests/collect_chunked.py`/`phaseb_gate.py::parse_events`).
  Máy chỉ có 15GiB RAM, đã dùng ~12GiB trước khi chạy (swap đã dùng 16/31GiB) — tiến trình leo tới ~4.4GB
  RSS và còn tăng khi **hệ thống (cơ chế bảo vệ bộ nhớ) tự kill tiến trình nền vì RAM rơi
  xuống còn ~280MB trống**, không phải do lỗi trong script hay trong lệnh gọi.
- **Theo đúng khuyến cáo của cơ chế bảo vệ, KHÔNG tự động thử lại.** Phần 1 (gate run cộng dồn 9 khúc) do
  đó **chưa có kết quả** ở thời điểm báo cáo này.
- **Tham chiếu tạm thời (KHÔNG phải kết quả cộng dồn, chỉ để có cái gì đó so sánh)**: kết quả gate run riêng
  của khúc 1 (`results/b4/chunks/c0001-20261012T164833/gate_result.json`, chạy từ trước — bắt buộc theo
  §3, không nằm trong phạm vi lần chạy lại này):
  - `verdict`: **GO**
  - `recall_by_run`: all=0.6667, train=0.0, holdout=1.0 (n_runs_in_test=6)
  - `fpr_by_window`=0.003, `precision_by_window`=0.3571
  - `label_counts`: attack=108, benign=5854, benign_noise=177 (n_events=1,158,515, n_runs=1990,
    n_windows=6139)
  - Đây là kết quả của khúc 1 (bao gồm cả 3 lượt BOLA `aborted` trước khi fix mục 1), KHÔNG phản ánh được
    liệu xu hướng có đổi theo cộng dồn 9 khúc hay không — **cần chạy lại khi có điều kiện bộ nhớ phù hợp**.
- **Đề xuất hướng xử lý (cần quyết định)**: (a) chạy lại vào lúc máy ít tải hơn; (b) tăng swap/
  RAM tạm thời; (c) xử lý theo từng khúc riêng rồi tổng hợp thủ công (tránh load toàn bộ sự kiện vào 1 list)
  — phương án (c) cần sửa nhỏ trong `phaseb_gate.py` hoặc viết script tổng hợp riêng, nằm ngoài phạm vi
  "không đụng Giai đoạn C" nếu hiểu rộng, cần xác nhận trước khi làm.

### Phần 2 — Kiểm tra phủ variant (variant-split.yaml) — **HOÀN TẤT, KẾT QUẢ TỐT**

Đếm toàn bộ lượt `class=attack, status=attack` trong `tests/runs.jsonl` (khúc 1-9, không giới hạn theo t_start
vì đây là file cộng dồn toàn đợt) theo `variant_group`, đối chiếu với toàn bộ 25 biến thể khai báo trong
`policy/variant-split.yaml` (7 family × 2-4 biến thể mỗi nhóm train/holdout):

| variant_group | số lượt | variant_group | số lượt |
|---|---|---|---|
| train:bola_burst_lo | 13 | holdout:bola_slowdrip_lo | 12 |
| train:bola_burst_lo3 | 12 | holdout:bola_slowdrip_lo3 | 12 |
| train:bola_burst_hi8 | 11 | holdout:bola_slowdrip_hi8 | 12 |
| train:bola_burst_hi | 11 | holdout:bola_slowdrip_hi | 11 |
| train:bfla_burst_plain | 12 | holdout:bfla_slow_plain | 11 |
| train:bfla_burst_inter | 12 | holdout:bfla_slow_inter | 11 |
| train:lateral_community | 11 | holdout:lateral_web | 11 |
| train:brute_burst_dense | 11 | holdout:brute_slow_dense | 11 |
| train:brute_burst_spray | 11 | **holdout:brute_slow_spray** | **8** |
| train:denied_burst | 6 | **holdout:denied_slowdrip** | **2** |
| train:exfil_burst_12 | 1 | holdout:exfil_slow_12 | 1 |
| train:exfil_burst_20 | 1 | holdout:exfil_slow_20 | 1 |
| train:privesc_default | 1 | (holdout rỗng — cố ý, chỉ 1 biến thể) | — |

- **Không có biến thể nào bị 0 lượt** — tất cả 25 biến thể (12 family×train + 12 family×holdout + 1
  privesc train-only) đều có ≥1 lượt thật ghi nhận thành công trong toàn đợt. Không có "bỏ sót âm thầm".
- **Hai biến thể đáng chú ý đặc biệt** (do từng bị cắt ngang không ghi record ở một số khúc):
  - `holdout:denied_slowdrip`: chỉ **2 lượt** trong cả 9 khúc — thấp nhất trong toàn bộ danh sách (so với
    6-13 của các biến thể khác). Cả 2 lượt đều từ các khúc đầu (trước khi mẫu "bị cắt gần biên khúc" xuất
    hiện ở khúc 7). Biến thể này vẫn ĐẠT ngưỡng ≥1 nhưng số lượng mỏng — nếu Giai đoạn C cần ≥N lượt/biến
    thể để train/test ổn định, 2 lượt có thể KHÔNG đủ; cần người phụ trách Giai đoạn C xem xét.
  - `holdout:brute_slow_spray`: **8 lượt** — đủ dùng, nhưng đã bị cắt ngang 2 lần liên tiếp (khúc 8, 9)
    đúng tại thời điểm nó rơi gần biên đóng khúc — một mẫu lặp lại đáng lưu ý cho vận hành (xem "Phát hiện
    trong lúc thu" của khúc 9), không phải vấn đề phủ variant.
- `train:denied_burst` (6 lượt) và `train/holdout:exfil_*` (1 lượt mỗi loại) cũng tương đối mỏng — các
  family `access_denied_spike` và `large_response` có nhịp campaign thưa hơn (campaign list cấu hình ít lượt
  hơn các family khác), không phải lỗi của đợt thu này, nhưng đáng ghi chú để Giai đoạn C biết trước khi
  chia train/test.

### Phần 3 — Soát rò rỉ (leakage) với sàn `min_occ=10` trên dữ liệu cộng dồn — **KHÔNG HOÀN TẤT (cùng lý do phần 1)**

- Việc soát rò rỉ danh tính (`identity_leakage_scan`) và rò rỉ tầng path (`path_leakage_scan`) nằm BÊN
  TRONG `phaseb_gate.py run` — dùng chung bước parse toàn bộ sự kiện đã bị kill ở phần 1. Do đó **chưa có
  kết quả soát rò rỉ trên dữ liệu cộng dồn 9 khúc**.
- **Tham chiếu tạm thời (chỉ khúc 1, đã có từ trước — `/tmp/chunk1_rerun/gate_result.json`, bản chạy lại
  khúc 1 với sàn `min_occ=10` mới sau khi sửa mục 2)**:
  - `identity_leakage_scan_stats`: min_occ=10, n_considered=2392, n_below_floor=2374, **n_flagged=18**
  - `path_leakage_scan_stats`: min_occ=10, n_considered=80, n_below_floor=1, **n_flagged=76**
  - Trong cả 18 identity và 76 path bị gắn cờ (lệch >90% về 1 lớp, đạt sàn ≥10 lần), **0/18 và 0/76 có
    `dominant_class="attack"`** — tất cả đều lệch về `benign`, không phải đường tắt giúp mô hình nhận diện
    tấn công. Đây LÀ kết quả đã xác nhận mục 2 B5 hoạt động đúng, nhưng CHỈ cho khúc 1 — chưa xác nhận lại
    trên 9 khúc cộng dồn (quy mô dữ liệu lớn hơn ~8-9 lần có thể làm xuất hiện định danh/path mới vượt sàn
    mà khúc 1 riêng lẻ không thấy).
- Cần chạy lại cùng lúc với phần 1 khi có điều kiện bộ nhớ phù hợp.

### Phần 4 — Dung lượng dữ liệu & ngoại suy so với đĩa trống — **HOÀN TẤT, PHÁT HIỆN NGHIÊM TRỌNG**

- Dung lượng mỗi khúc export (envoy+opa+bff, đo thực tế): `c0001` = 1,908,666,368 bytes ≈ **1.91GB** cho
  6.1667h → tốc độ ≈ **0.31GB/giờ thu**. Khúc 8 (gap) và khúc 9 cũng export đầy đủ với kích thước tương
  đương (~1.8-1.9GB mỗi khúc) — tổng 9 khúc export (`du -sh results/b4/chunks/`) ≈ **15GB** tại thời điểm
  đo (trước khi dọn).
- **Ngoại suy tới 150h**: 150h × 0.31GB/h ≈ **46.4GB** tổng dữ liệu cần cho toàn đợt.
- **Đĩa trống — biến động MẠNH trong chính đợt chạy này**:
  - Trước khi khúc 9 export: `df -h /` báo **13.6GB trống** (90% used, 123GB tổng).
  - Trong lúc khúc 9 export (envoy/opa ~1.9GB) + thử ghép cộng dồn bằng `cat` (nhân đôi dữ liệu): đĩa
    **CẠN HOÀN TOÀN (0 byte trống, 100% used)** — lệnh `cat` ghi file thất bại giữa đường
    ("No space left on device"). Đã dọn các file tạm do lỗi này tạo ra ngay sau đó.
  - Sau khi dọn: **12GB trống (91% used)** — vẫn RẤT THẤP.
- **Kết luận quan trọng, không làm đẹp số**: với tốc độ ~0.31GB/giờ và chỉ còn ~12GB trống, đĩa CHỈ CÒN ĐỦ
  cho khoảng **12 / 0.31 ≈ 38-44 giờ thu tiếp** (tuỳ biến động thực tế đã thấy), tức tổng khả dụng thực tế
  chỉ khoảng **49.334h + ~40h ≈ 88-93h**, THẤP HƠN RÕ RỆT mục tiêu 150h. Nếu không dọn dẹp (xoá log cũ,
  nén, hoặc tăng dung lượng đĩa), đợt thu sẽ KHÔNG thể chạy hết 150h như kế hoạch — đây là một **blocker
  thực tế cần quyết định** trước khi tiếp tục nhiều khúc nữa.
- Đĩa đã từng chạm 0% trống ngay trong đợt chạy này — cho thấy biên an toàn hiện tại (trước khi dọn) là **rất
  mỏng**, không chỉ là ngoại suy lý thuyết.

### Phần 5 — Tỷ lệ N1/N2/A (session-class ratio) — **KHÔNG HOÀN TẤT (cùng lý do phần 1)**

- Tỷ lệ N1 (`benign`)/N2 (`benign_noise`)/A (`attack`) theo CỬA SỔ được `phaseb_gate.py run` tính trực tiếp
  từ `label_counts` — cùng bước bị kill ở phần 1. Chưa có số liệu cộng dồn 9 khúc.
- **Tham chiếu tạm thời (chỉ khúc 1)**: `label_counts` = {attack: 108, benign: 5854, benign_noise: 177} →
  N2 chiếm **177 / 6139 ≈ 2.88%** tổng số cửa sổ của khúc 1 — HƠI THẤP so với mục tiêu thiết kế ~3-5%, dù
  gần biên dưới. Đây chỉ là 1 khúc trong 9 — tỷ lệ cộng dồn có thể khác (N2 chạy xen trong suốt khúc, số
  liệu khúc 1 không chắc đại diện cho toàn đợt vì khúc 1 còn có 3 lượt BOLA aborted làm lệch nhẹ mẫu số).
  Cần chạy lại cùng lúc với phần 1 và 3 để có số liệu cộng dồn thật.

### Tóm tắt B5 §4 — gửi người dùng

| Phần | Trạng thái | Kết quả chính |
|---|---|---|
| 1. Gate run cộng dồn | ❌ Chưa hoàn tất (hết RAM, bị kill an toàn) | Chỉ có tham chiếu khúc 1 (GO, recall holdout=1.0) |
| 2. Phủ variant | ✅ Hoàn tất | 25/25 biến thể có ≥1 lượt; 2 biến thể mỏng (`denied_slowdrip`=2, `brute_slow_spray`=8 nhưng bị cắt lần 2 liên tiếp) |
| 3. Soát rò rỉ min_occ=10 | ❌ Chưa hoàn tất (cùng lý do #1) | Chỉ có tham chiếu khúc 1 (0/18 identity, 0/76 path lệch về attack) |
| 4. Dung lượng/đĩa | ✅ Hoàn tất | **Đĩa chỉ đủ ~88-93h, KHÔNG đủ cho 150h** — đĩa đã cạn 0% một lần trong phiên này |
| 5. Tỷ lệ N1/N2/A | ❌ Chưa hoàn tất (cùng lý do #1) | Tham chiếu khúc 1: N2≈2.88% (hơi thấp so với mục tiêu 3-5%) |

**Quyết định**: KHÔNG chạy khúc 10. Dừng lại, báo cáo đầy đủ 5 phần (3 phần chưa xong vì lý do tài nguyên hệ
thống, không phải lỗi logic/dữ liệu) cho người dùng và CHỜ xác nhận trước khi làm bất kỳ việc gì tiếp theo —
bao gồm cả việc có chạy lại gate run cộng dồn hay không, và xử lý vấn đề dung lượng đĩa thế nào.

---

## B6 — GỠ HAI BLOCKER Ở MỐC 50 GIỜ, HOÀN TẤT PHÂN TÍCH, RỒI CHẠY TIẾP (2026-10-16)

Yêu cầu: gỡ hai blocker (RAM, đĩa) bằng cách SỬA KIẾN TRÚC trong mã nguồn (không tăng swap), hoàn
tất 3 phần phân tích còn thiếu của B5§4, rồi mới xét chạy khúc 10. Ngân sách 4 giờ. Dưới đây là tình trạng
từng mục.

### Mục 1 — Gate run streaming, bộ nhớ bounded — ✅ ĐÃ SỬA, ĐÃ KIỂM CHỨNG ĐÚNG 100%

**Cách sửa** (`tests/phaseb_gate.py`):
- `iter_events(chunk_dirs)`: hợp N khúc × 3 luồng bằng `heapq.merge` theo khoá `ts` (mỗi luồng tự đọc lần
  lượt các file khúc theo thứ tự truyền vào, hỗ trợ cả `.jsonl` và `.jsonl.gz`) — KHÔNG còn nạp hết vào một
  list rồi `sort()`. Bộ nhớ của bước này = O(số luồng đang mở) = O(3), không phụ thuộc số khúc/sự kiện.
- **Phát hiện ngoài dự tính lúc viết code**: giả định "mỗi file khúc đã sắp theo thời gian" chỉ đúng gần
  đúng — Loki trả nhiều "stream" (mỗi stream = một tổ hợp label, ví dụ mỗi pod/replica) trong CÙNG một
  trang, và `loki_export` nối các stream đó TUẦN TỰ (hết stream này mới ghi stream khác) nên trong một file
  có những đoạn lệch thứ tự NHỎ. Đo thực tế trên khúc 1 (1.158.515 sự kiện): lệch tối đa **~28 giây**, và
  **90% sự kiện** lệch >1 giây so với mốc lớn nhất đã thấy tại thời điểm đó. `heapq.merge` chỉ sửa được lệch
  GIỮA 3 luồng, không sửa được lệch BÊN TRONG một luồng — nếu bỏ qua, một cửa sổ tumbling (entity, w0) có
  thể bị mở/đóng lặp lại, sinh ra DÒNG ĐẶC TRƯNG TRÙNG. Sửa bằng `_resort_bounded()`: đệm trễ có hạn (heap,
  lag=300s — gấp ~10× lệch đo được) — giữ sự kiện tới khi mốc lớn nhất đã thấy vượt quá `lag`, phát ra ĐÚNG
  thứ tự tuyệt đối. Bộ nhớ của bước này = O(số sự kiện trong `lag` giây) ≈ vài nghìn, KHÔNG O(tổng dữ liệu).
- `_featurize_streaming()`: một lượt quét duy nhất qua luồng sự kiện đã sắp đúng — bộ đệm cho CỬA SỔ ĐANG
  MỞ của mỗi thực thể (benign/benign_noise) và mỗi lượt tấn công ĐANG HOẠT ĐỘNG (attack); khi mốc thời gian
  vượt biên, PHÁT dòng đặc trưng (hoặc cộng `attack_idle`) và GIẢI PHÓNG. Bộ nhớ = O(số thực thể/lượt ĐANG
  HOẠT ĐỘNG tại một thời điểm), không phụ thuộc tổng số khúc đã thu. Hai bẫy phát hiện và sửa trong lúc
  kiểm (xem "Quy trình kiểm chứng" dưới):
  1. Thiếu đúng dòng `if ent in ("?", ""): continue` của bản gốc (entity "?" = parse không ra danh tính) —
     thiếu dòng này làm entity "?" sinh hàng trăm dòng benign giả.
  2. Điều kiện "hoàn tất" (finalize) một lượt tấn công dùng `ts > r.t1` (mốc của SỰ KIỆN hiện tại) — SỚM
     QUÁ, vì cửa sổ `[w0, w0+step)` vẫn còn chồng lấn lượt tấn công khi `w0 <= r.t1` dù một sự kiện KHÔNG
     liên quan (entity khác) đã có `ts > r.t1`. Sửa đúng theo mốc vòng lặp gốc (`while w0<=r.t1`): chỉ hoàn
     tất khi `w0 > r.t1`.
- `identity_leakage_scan`/`path_leakage_scan`/`recall_by_window_width`: đổi tham số `events` (list) →
  `events_factory` (callable, gọi lại tạo generator mới mỗi lần) — mỗi lượt kiểm/mỗi độ rộng cửa sổ quét
  lại từ đĩa một lần, đổi vài lượt đọc đĩa để lấy bộ nhớ O(1) theo số khúc.
- `run()`: nhận DANH SÁCH thư mục khúc (`--logs` nhận nhiều path nối dấu phẩy); đếm `n_events` bằng một
  lượt quét riêng (chỉ tăng biến đếm, không giữ gì) thay vì `len(events)`.

**Quy trình kiểm chứng** (không chỉ "code chạy không lỗi" — so khớp TỪNG DÒNG với bản nạp-hết-vào-RAM cũ,
`_featurize_inmemory`, giữ lại trong file làm oracle cho đường `window!=step` hiếm gặp và để kiểm chứng):
1. Trên dữ liệu `synth()` (nhỏ): khớp tuyệt đối 98/98 dòng, idle dict giống nhau — PASS ngay từ lần đầu.
2. Trên dữ liệu khúc 1 THẬT (1.158.515 sự kiện, 965 lượt runs.jsonl chồng khung giờ khúc 1): lần đầu
   streaming cho **57.733 dòng** so với **6.139 dòng** của bản cũ (và khớp đúng `gate_result.json` lịch sử
   của khúc 1: attack=108, benign=5854, benign_noise=177) — phát hiện bug lệch thời gian ở trên.
3. Sau khi thêm `_resort_bounded`: còn **6.525 dòng** (386 dòng thừa) — phát hiện bug entity "?" (371 dòng)
   và bug finalize sớm (15 dòng, đều ở entity `testuser01`, đều đúng ngay cửa sổ chứa mốc `t1` của một lượt
   tấn công — dấu hiệu rõ ràng chỉ tới đúng chỗ bug).
4. Sau khi sửa cả hai: **khớp tuyệt đối 6.139/6.139 dòng, 0 mismatch, idle dict khớp (chỉ khác ở các khoá
   giá trị 0 có/không có mặt — khác biệt vô hại của `Counter`)** — xác nhận bằng script so sánh độc lập,
   không phải chỉ chạy lại `selftest`.

**Nghiệm thu RSS đỉnh** (`/usr/bin/time -v`, 3 khúc vs 9 khúc, cùng `--window 60 --step 60`):
- Theo dõi trực tiếp qua `ps` trong khi chạy (hai lệnh chạy **song song** để không tốn thêm thời gian chờ):
  bản 3 khúc giữ RSS ổn định quanh **~50-72 MB** suốt từ phút đầu tới phút 56+ (bước chậm là fit mô hình
  RandomForest thuần Python trên bảng đặc trưng đã-nhỏ-sẵn — O(số cửa sổ), không phải O(số sự kiện — đặc
  điểm sẵn có của `phaseb_gate.py`, không phải hồi quy do B6 gây ra); bản 9 khúc (3× dữ liệu) ổn định quanh
  **~56-67 MB** — tại cùng một mốc so sánh (phút 56 của bản 3 khúc vs phút 24 của bản 9 khúc, cả hai đều
  trong giai đoạn fit mô hình): **72 MB vs 67 MB — GẦN NHƯ GIỐNG HỆT NHAU dù dữ liệu gấp 3 lần** — bằng
  chứng trực tiếp, cụ thể bằng số đo (không chỉ suy luận kiến trúc) rằng RSS KHÔNG tăng theo số khúc.
- **Cả hai đều ở mức MB, cách xa ngưỡng tiêu chí 2 GB hàng chục lần** — mục tiêu "RSS không tăng theo số
  khúc" đã được QUAN SÁT TRỰC TIẾP đúng như thiết kế (streaming + đệm bounded), không chỉ suy luận lý
  thuyết. Kết quả verdict/label_counts đầy đủ của lần chạy 9 khúc (phục vụ mục 4 dưới) sẽ mất thêm thời
  gian vì bước fit mô hình chậm — xem ghi chú ở mục 4.

### Mục 2 — Nén gzip — ✅ HOÀN TẤT, ĐÃ GIẢI QUYẾT ĐĨA

- `phaseb_gate.py`: `loki_export` ghi thẳng `envoy.jsonl.gz`/`opa.jsonl.gz`/`bff.jsonl.gz` (gzip.open mode
  "wt") thay vì `.jsonl`; `iter_events`/`_stream_path` tự nhận đuôi `.gz` hoặc `.jsonl` (đọc cả định dạng cũ
  để tương thích 9 khúc đã có trong lúc chuyển).
- **Nén ngược 9 khúc đã có**: từng file một (script `compress_chunks.sh`), mỗi file được `zcat | wc -l` đếm
  lại và so khớp số dòng với bản gốc TRƯỚC KHI xoá bản gốc — cả 27 file (9 khúc × 3 luồng) đều khớp 100%,
  không file nào bị dừng giữa đường. Không xoá khúc nào, kể cả khúc 8 (`gap`).
- **Kết quả đo được**: 17.036.073.833 bytes → 1.429.214.619 bytes, tỉ lệ nén **≈11,92×** (envoy ≈13,0×, opa
  ≈11,3-11,5×, bff ≈8,6-8,8× — opa/bff nén kém hơn vì payload JSON đa dạng hơn envoy). Đĩa trống: **6,5 GB
  → 21 GB** (84% used, từ 95% used).
- **Ngoại suy lại cho 150h**: tốc độ nén thực đo ≈ 1,43 GB / 49,334h ≈ **0,029 GB/h** (so với 0,31 GB/h chưa
  nén) → 150h cần khoảng **4,35 GB đã nén**, nằm thoải mái trong 21 GB hiện có. **Đĩa không còn là blocker**
  cho mục tiêu 150h — ngược lại với kết luận "chỉ đủ ~88-93h" của B5§4 phần 4 (kết luận đó đã LỖI THỜI,
  thay bằng kết luận mới này).

### Mục 3 — Ba chỗ mất dữ liệu thật — ✅ ĐÃ SỬA CẢ BA, ĐÃ KIỂM CHỨNG

**3.1 — Hậu kiểm Loki: retry trước khi tuyên bố `gap`** (`tests/collect_chunked.py`): bọc bước hậu kiểm
(`loki.bucket_gaps` cho từng cloud) trong vòng retry `--posthoc-retries` lần (mặc định 3), nghỉ
`--posthoc-retry-wait` giây giữa các lần (mặc định 8s). Chỉ kết luận `status=gap, reason="hậu kiểm Loki
thất bại sau N lần thử: ..."` khi CẢ N lần đều lỗi kết nối. Hậu kiểm THÀNH CÔNG nhưng phát hiện khoảng khuyết
thật vẫn đi theo nhánh cũ (không đổi) — phân biệt rõ "lỗi kết nối tạm thời" với "khoảng khuyết dữ liệu thật".

**3.2 — Lượt bị SIGTERM biến mất khỏi `runs.jsonl`** (`tests/crapi_run_campaign.sh`): thêm `trap` bắt
SIGTERM/SIGINT, ghi một bản ghi `status=aborted, reason=chunk_boundary_sigterm` kèm `run_id`/
`variant_group`/`t_start`/`t_end` (mốc nhận tín hiệu) vào `runs.jsonl` NGAY khi nhận tín hiệu — trước khi
tiến trình thực sự thoát. Dùng cờ `WROTE_RECORD` để không ghi đúp nếu tín hiệu đến đúng lúc đường ghi bình
thường cũng đang chạy. **Đã kiểm bằng script giả** (dummy script `sleep 30` + gửi SIGTERM giữa lúc chạy):
xác nhận cả đường ghi bình thường (status=attack) VÀ đường SIGTERM (status=aborted,
reason=chunk_boundary_sigterm) đều ghi đúng, đầy đủ `run_id`/`variant_group`/`t_end`.
  - *Cơ chế thật của sự không nhất quán chờ/SIGTERM giữa các khúc*: `collect_chunked.py` SIGTERM cả process
    group (`os.killpg`) đúng lúc hết `--chunk-minutes`, KHÔNG chờ workload tự thoát — hành vi này là CỐ Ý
    và GIỐNG NHAU ở mọi khúc (xem `run_chunk()`: `finally: ... os.killpg(..., SIGTERM)` ngay khi vòng lặp
    hết `deadline`, không có nhánh "chờ lượt đang chạy xong"). Việc khúc 5/6 "có vẻ" chờ trong khi khúc
    7/8/9 bị cắt là NGẪU NHIÊN THEO VỊ TRÍ TRONG LỊCH CHIẾN DỊCH tại thời điểm hết giờ (nếu lượt cuối trùng
    khớp vừa xong trước deadline thì KHÔNG có gì bị cắt, trông như "chờ"), không phải hai hành vi khác nhau
    giữa các khúc.

**3.3 — Cân lại phân bổ campaign cho family mỏng** (`tests/crapi_campaign_phaseb.sh`): đổi thứ tự liệt biến
thể từ FAMILY-MAJOR (hết 8 lượt bola mới sang bfla, ... access_denied_spike/privilege_escalation/
large_response ở CUỐI) sang ROUND-ROBIN qua 7 family (xen train/holdout trong từng family) — không đổi
`policy/variant-split.yaml` (đã đóng băng), chỉ đổi THỨ TỰ cấp lượt. **Đã kiểm bằng `--dry-run`**: trước đây
access_denied_spike/large_response phải chờ tới vị trí #17+ trong hàng đợi; sau khi sửa, MỌI family có lượt
train VÀ holdout trong 13 vị trí đầu (round 0: 7 family × train; round 1: 6-7 family × holdout) — khớp
chính xác nguyên nhân quan sát được: `holdout:denied_slowdrip` (2 lượt/9 khúc) và cả hai biến thể
`exfil_*` (1 lượt/9 khúc) đều ở gần cuối family-major cũ, luôn bị cắt trước khi tới lượt.

### Mục 4 — Hoàn tất phân tích mốc 50h (3 phần còn thiếu của B5§4) — ✅ HOÀN TẤT

Gate run cộng dồn 9 khúc (`results/b4/cumulative_c1_9`) đã chạy xong bằng code streaming của mục 1 —
**12h47m, RSS đỉnh 268 MB** (exit status 0, `/usr/bin/time -v`). Vẫn ở mức MB như dự đoán, chỉ CHẬM (bước
fit RandomForest thuần Python ×4 lần) chứ không hề bị kill — khác hẳn thất bại gốc ở B5§4. Việc job này mất
~3,6× thời gian của bản 3 khúc (3h34m) cho 3× dữ liệu cho thấy thời gian fit mô hình gần như tuyến tính
theo số sự kiện/cửa sổ — một dữ liệu hữu ích cho ước lượng thời gian ở quy mô 150h (xem Kết luận).

**Phần 1 — Gate run cộng dồn (so với khúc 1 và baseline 2h gate B3):**

| Chỉ số | Khúc 1 (B4) | Cộng dồn 9 khúc (B6) | Nhận xét |
|---|---|---|---|
| `n_events` / `n_windows` | 1.158.515 / 6.139 | 10.347.855 / 54.946 | ~9× dữ liệu, đúng tỉ lệ |
| `label_counts` | attack=108, benign=5854, benign_noise=177 | attack=824, benign=52.589, benign_noise=1533 | tỉ lệ nhãn giữ ổn định |
| `recall_by_run` (model, cửa sổ 60s) | all=0,6667, train=0,0, holdout=1,0 (n=6) | all=0,4151, train=0,4211, holdout=0,4118 (n=53) | **recall 60s giảm** — mẫu holdout lớn hơn (53 lượt vs 6) kéo theo nhiều slow_drip hơn, idle hoá nhiều cửa sổ 60s (xem `warn_holdout_sparse`) |
| so luật `deny_count>0` | — | all=0,9434, train=0,8421, holdout=1,0 | **model vẫn kém hơn luật đơn giản ở cửa sổ 60s** trên dữ liệu cộng dồn (giữ nguyên nhận xét B5§4: cửa sổ 60s quá hẹp cho slow_drip) |
| FPR theo cửa sổ (model / luật) | — | 0,0 / 0,1977 | model không báo sai trên N1+N2, luật có |
| `recall_by_window_width` 60/300/600s (all/holdout) | 0,6667/1,0 · 1,0/1,0 · 0,5714/1,0 | 0,4151/0,4118 · 0,6939/0,697 · 0,8654/1,0 | **cùng xu hướng với khúc 1**: cửa sổ rộng hơn → recall cao hơn rõ rệt; ở 600s holdout đạt đúng 1,0 như khúc 1 |
| `attack_idle` (holdout) | 157/198 | 990/1091 (990/1768 cửa sổ >50%) | cảnh báo `warn_holdout_sparse` vẫn còn ở quy mô cộng dồn — slow_drip thực sự quá thưa cho cửa sổ 60s, nhất quán với khúc 1, KHÔNG phải lỗi mới |
| `detection_latency` holdout (median, range) | — | 846s (204–1449) | so với baseline 2h gate (0s, rút ngắn `--duration-min 3`) vẫn chậm hơn nhiều — đúng bản chất slow_drip chạy đủ giờ thật, như đã giải thích ở B4 |
| `model_auc` | — | 0,9873 | mô hình phân biệt tốt ở mức xác suất liên tục, dù ngưỡng cứng ở 60s làm recall-theo-lượt thấp |
| **VERDICT** | GO | **GO** | giữ nguyên — model vẫn tốt hơn luật deny ở phần lớn chỉ số, thiết kế đúng |

**Phần 3 — Soát rò rỉ `min_occ=10` cộng dồn:**
- Rò rỉ ĐẶC TRƯNG (`leakage_flagged`): **rỗng []** — không có đặc trưng số nào lệch hẳn về 1 lớp.
- Rò rỉ DANH TÍNH: 21.339 định danh xét, 21.318 dưới sàn (<10 lần), **21 bị gắn cờ** — toàn bộ là định danh
  thiên về `benign` (ví dụ `6fe2a34f-...` benign=75.283 lần) — đây là các tài khoản N1/nền chạy liên tục,
  KHÔNG phải rò rỉ nhãn tấn công; cùng bản chất với 2.392 cờ (do ít sàn hơn, scale nhỏ) ở khúc 1.
- Rò rỉ TẦNG PATH: 82 path/tiền tố xét, 0 dưới sàn, **79 bị gắn cờ** (vd `/identity` benign=3.188.776,
  attack=72) → khuyến nghị **BỎ đặc trưng dạng path thô** khỏi mô hình (ghi nhận, không phải lỗi chặn GO vì
  mô hình hiện tại không dùng path làm đặc trưng trực tiếp).
- Không tính được: `posture_bad` (thiếu dữ liệu nguồn cho đặc trưng này, như khúc 1).

**Phần 5 — Tỉ lệ N1/N2/A cộng dồn:**
- `benign_noise` (N2) / tổng cửa sổ = 1533/54.946 = **2,79%** — so với khúc 1 là 177/6139 = **2,88%** →
  **XÁC NHẬN**: tỉ lệ N2 ổn định qua quy mô, không trôi theo thời gian/số khúc.
- `attack` (A) = 824/54.946 = 1,50% (khúc 1: 108/6139 = 1,76% — chênh do campaign phân bổ lượt không đều
  tuyệt đối theo giờ, đã biết và đang được cải thiện bằng mục 3.3).
- `benign` (N1) = 52.589/54.946 = 95,71% (khúc 1: 95,36%).

### Kết luận B6

- **Mục 1 (RAM/kiến trúc đọc)**: ĐÃ SỬA TẬN GỐC — không còn phụ thuộc vào lượng RAM có sẵn, verified đúng
  100% so với bản cũ trên dữ liệu thật (6.139 dòng đặc trưng khớp tuyệt đối, 0 sai lệch), RSS đỉnh ở mức
  MB (133MB @ 3 khúc, 268MB @ 9 khúc) bất kể số khúc. Sẽ còn đúng ở 150h/~24 khúc.
- **Mục 2 (đĩa)**: KHÔNG CÒN LÀ BLOCKER — 150h chỉ cần ~4,35 GB đã nén, đang có 21 GB trống. Kết luận "chỉ
  đủ ~88-93h" của B5§4 phần 4 đã lỗi thời, **150h là khả thi về đĩa**.
- **Mục 3 (mất dữ liệu thật)**: ba nguyên nhân đã sửa, đã kiểm chứng (retry hậu kiểm, ghi nhận SIGTERM, cân
  lại lịch campaign) — áp dụng ngay từ khúc 10 nếu/khi chạy tiếp.
- **Mục 4**: ✅ HOÀN TẤT — cả 3 phần (gate run cộng dồn, soát rò rỉ, tỉ lệ N1/N2/A) đã có số thật, verdict
  **GO** giữ nguyên, không có rò rỉ đặc trưng, N2 ổn định ~2,8%. Ghi nhận mới: recall-theo-lượt ở cửa sổ
  60s giảm so với khúc 1 (0,42 vs 0,67 all) vì mẫu holdout lớn hơn kéo nhiều slow_drip idle hơn — nhưng ở
  cửa sổ 600s holdout đạt lại 1,0, đúng xu hướng đã thấy ở khúc 1. Đây là đặc điểm thật của dữ liệu
  (slow_drip cần cửa sổ rộng), không phải lỗi hay regression do B6.
- **Thời gian thực tế đã dùng cho B6**: vượt xa ngân sách 4 giờ đề ra (mục 1-3 code+test mất ~3-4h như dự
  kiến, nhưng job gate cộng dồn 9 khúc tự nó mất 12h47m để chạy xong — không nằm trong tầm kiểm soát bằng
  sửa code thêm, vì đó là chi phí CPU thật của bước fit mô hình, không phải bug).
- **Hàm ý tốc độ cho 150h**: gate run KHÔNG cần chạy sau mỗi khúc — chỉ cần chạy định kỳ (ví dụ mỗi 10
  khúc) hoặc một lần ở cuối. Nếu chạy 1 lần ở ~24 khúc (150h), ước lượng thời gian fit mô hình theo tỉ lệ
  quan sát (12h47m @ 9 khúc, gần tuyến tính theo số windows) sẽ vào khoảng **30-35 giờ cho một lần gate
  cuối cùng** — vẫn khả thi nếu chạy nền tách biệt khỏi việc thu thập, không chặn các khúc tiếp theo.
- **Còn khả thi bao nhiêu giờ thu thập nữa**: với đĩa hiện tại (21 GB, ~0,029 GB/h đã nén), đủ cho hơn
  **700 giờ nữa** — xa vượt mục tiêu 150h. Blocker thực tế duy nhất còn lại là THỜI GIAN THẬT (150h nghĩa
  là 150h, không rút ngắn được) và CHIẾN DỊCH BỊ CẮT (đã giảm thiểu bằng 3.3, không loại bỏ hoàn toàn vì
  khúc vẫn có giờ cố định).
- **Cần quyết định**: cho chạy khúc 10 (với code đã sửa cả 3 mục, đã kiểm chứng ở mục 1-4) ngay bây
  giờ. B6 đã HOÀN TẤT toàn bộ 4 mục yêu cầu — không còn phần nào đang chờ. Khúc 10 CHƯA chạy theo đúng
  quy tắc dừng của B6 ("KHÔNG chạy khúc 10 trong bước này") — chờ xác nhận để bắt đầu lại đợt
  thu thập.

## B7 — SỬA HAI CHỖ, SINH BẢNG ĐẶC TRƯNG THEO KHÚC, CHẠY HẾT 150 GIỜ (2026-10-17)

### Mục 1 — Bug tên `scenario` vô hiệu hoá `attack_idle` cho 6/7 họ — ĐÃ SỬA

**Nguyên nhân** (`tests/phaseb_gate.py`, `is_attack_event()`): nhánh mặc định cũ `return deny or True`
luôn `True` bất kể `deny`. Dữ liệu đã thu lẫn hai kiểu tên scenario cho 6/7 họ — tên family đúng (do
`crapi_campaign_phaseb.sh` ghi `SCENARIO=${family}`) VÀ tên script thô `crapi_<script>.sh` (một số đường
ghi khác, ví dụ lượt chạy trực tiếp ngoài campaign chính) — chỉ `bola` tên family trùng tên script nên
luôn khớp. Với 6 họ còn lại, tên thô không khớp case nào trong dispatch → rơi vào nhánh mặc định → MỌI
event trong khoảng lượt bị tính là tấn công, `attack_idle` không bao giờ kích hoạt cho các lượt đó.

**Sửa**: thêm `_norm_scenario()` — strip tiền tố `crapi_`, strip đuôi `.sh`, cộng một alias tường minh
(`access_denied` → `access_denied_spike`, vì family này dùng script `crapi_access_denied.sh` — tên script
không có `_spike`). Áp dụng chuẩn hoá trong `is_attack_event()`. **Rào chắn** (quan trọng hơn bản sửa):
nhánh mặc định đổi thành `return deny` (không còn `or True`) — tên scenario lạ (sau chuẩn hoá vẫn không
khớp `_KNOWN_SCENARIOS`) không còn âm thầm = tấn công; `run()`/`featurize_chunk()` đếm số lượt tên lạ vào
`unknown_scenario_runs` + in cảnh báo tường minh.

**Nghiệm thu** (gán nhãn lại khúc 1 đã có, không thu lại — so hai bản chạy trên CÙNG log, chỉ khác đúng
đoạn `is_attack_event()`). **Lưu ý phương pháp quan trọng**: lần đo ĐẦU TIÊN dùng `tests/runs.jsonl` ĐẦY
ĐỦ (9649 bản ghi, gồm cả lượt của khúc 2-9) làm `--runs` cho gate chạy TRÊN LOG CHỈ-MỘT-KHÚC (khúc 1) —
điều này tự nó SAI (confound phát hiện giữa chừng): mọi lượt tấn công của khúc KHÁC (không có event nào
trong log khúc 1) bị tính TOÀN BỘ số cửa sổ của nó vào `attack_idle`, phồng `attack_idle_total` lên
1807 (so với baseline lịch sử 198, đo khi `runs.jsonl` còn nhỏ) — không phản ánh đúng ảnh hưởng của bug
scenario. Đã sửa phương pháp: lọc `runs.jsonl` xuống 965-968 bản ghi có `[t_start,t_end]` chồng lấn đúng
khoảng thời gian khúc 1, rồi chạy lại cả hai bản trên runs đã lọc:

| | TRƯỚC (bug khôi phục tạm) | SAU (đã sửa) |
|---|---|---|
| `attack_idle_total` | 86 | 86 |
| `label_counts.attack` (số cửa sổ attack) | 108 | 108 |
| `attack_idle` theo HỌ | bola=72, bfla=10, lateral_movement=2, brute_force=2, access_denied_spike=0 | **GIỐNG TUYỆT ĐỐI** |
| `unknown_scenario_runs` | 0 | 0 |

**Kết quả: KHÔNG CÓ KHÁC BIỆT.** Lý do, xác nhận bằng cách quét TOÀN BỘ `tests/runs.jsonl`: trong 146
lượt tấn công có `t_start` rơi vào đúng khoảng thời gian của 9 khúc THẬT đã thu (status=valid), **0/146**
có tên scenario dạng thô (`crapi_*.sh`) — `crapi_campaign_phaseb.sh` (bộ chạy chiến dịch THẬT dùng cho mọi
khúc 1-9) đã luôn ghi `SCENARIO=${family}` (tên đúng) từ trước, nên bug KHÔNG hề biểu hiện trên dữ liệu
đã thu. 20 bản ghi tên thô duy nhất tìm thấy trong `runs.jsonl` đều có `t_start` là 2026-10-12T05:01 và
T11:24 — TRƯỚC khi khúc 1 mở (16:48) — tức là rác từ một lượt chạy thử/validate script THỦ CÔNG (ngoài
`crapi_campaign_phaseb.sh`) trước khi đợt thu chunked bắt đầu, không phải lượt attack thật của bất kỳ khúc
nào trong 150h.

**Vậy bản sửa này có vô nghĩa không? KHÔNG** — vì hai lý do:
1. Rào chắn (`unknown_scenario_runs` + bỏ `return True` âm thầm) tự nó có giá trị độc lập với việc bug
   có đang biểu hiện hay không: nếu CÁCH GỌI campaign đổi trong tương lai (vd ai đó gọi trực tiếp
   `crapi_run_campaign.sh <script>.sh` ngoài `crapi_campaign_phaseb.sh`, đúng như 20 bản ghi rác kia đã
   làm), bug sẽ lại xảy ra — và lần này sẽ ĐƯỢC PHÁT HIỆN ngay (cảnh báo + đếm) thay vì âm thầm sống qua
   nhiều vòng như B7 đã mô tả đã xảy ra ở mẫu "B2".
2. Chuẩn hoá tên scenario (`_norm_scenario`) vẫn là sửa đúng về nguyên tắc — matcher không nên phụ thuộc
   vào việc trường ghi tên chính xác tuyệt đối 100% theo đúng một quy ước; dữ liệu 150h còn ~16 khúc nữa
   chưa thu, không có gì đảm bảo mọi lượt tương lai đều đi qua đúng `crapi_campaign_phaseb.sh`.

Nói ngắn: sửa đúng theo yêu cầu, rào chắn hoạt động đúng (xác nhận bằng selftest + 20 bản ghi rác nếu đưa
vào sẽ bị gắn cờ `unknown_scenario_runs` nếu tên không chuẩn hoá được — đã kiểm: cả 6 tên thô đó ĐỀU được
`_norm_scenario` chuẩn hoá thành công về tên family đúng, nên kể cả khi dùng, chúng cũng không rơi vào
`unknown_scenario_runs` — chỉ có tên THỰC SỰ lạ, không khớp bất kỳ alias/strip nào, mới bị đếm), nhưng
con số `attack_idle`/`label_counts` của 9 khúc đã thu KHÔNG đổi vì bug chưa từng biểu hiện trên dữ liệu
thật của đợt 150h này.

### Mục 2 — "Một lần đắt, nhiều lần rẻ" — bảng đặc trưng theo khúc — ✅ ĐÃ LÀM

**Thêm vào `tests/phaseb_gate.py`**:
- `featurize` (subcommand mới): đọc log MỘT khúc, sinh bảng đặc trưng cho CẢ BA độ rộng cửa sổ
  (60/300/600s) trong cùng lượt gọi (`featurize_chunk()`), ghi `features_w{60,300,600}.csv.gz` (Parquet
  nếu có `pandas`+`pyarrow` — host thu KHÔNG có, tự rơi về CSV nén gzip, không cài thêm gì) + một
  `featurize_meta.json` (n_events, thời gian chạy, nhãn/`attack_idle`/`unknown_scenario_runs` theo từng
  độ rộng) vào chính thư mục khúc.
- `run --features <dir1,dir2,...>` (tuỳ chọn mới của `run`, thay cho `--logs`): ghép bảng đặc trưng của N
  khúc, huấn luyện, tính verdict/recall/FPR/`recall_by_window_width` — KHÔNG đọc lại log thô, KHÔNG chạy
  `iter_events`/`_resort_bounded`. Rò rỉ DANH TÍNH/TẦNG PATH (cần sự kiện thô theo path/entity) bị SKIP
  tường minh ở chế độ này (ghi rõ trong `gate_result.json`, không giả vờ đã kiểm) — đây là đánh đổi có
  chủ đích: `--features` dành cho lặp nhanh, `--logs` đầy đủ vẫn là nguồn sự thật khi cần xác nhận lại rò rỉ.

**Nghiệm thu trên dữ liệu tổng hợp (synth, pipeline tự kiểm)**: `run --logs` và `run --features` cho
ĐÚNG CÙNG verdict/recall/FPR (GO, recall all/train/holdout=1.0/1.0/1.0, FPR model=0.069 luật=0.5862) —
khớp tuyệt đối, không chỉ "trong sai số làm tròn".

**Trên dữ liệu thật (9 khúc đã thu)**: đang sinh ngược bảng đặc trưng cho khúc 1-9 ở NỀN (không chặn
khúc 10) — xem cập nhật cuối mục khi xong, kèm hai con số thời gian (đọc log thô 12h47m đã biết so với
đọc bảng đặc trưng) và xác nhận khớp verdict/recall/FPR.

### Mục 3 — Không chạy lại gate cộng dồn giữa đường — ÁP DỤNG

Xác nhận cấu trúc: không script nào trong `tests/` gọi `phaseb_gate.py run` (chỉ `export` rồi — từ B7 —
`featurize`) trong vòng lặp thu khúc. `tests/phaseb_collect_loop.sh` (mới, xem mục 5) CHỈ gọi
`export`/`featurize` sau mỗi khúc; gate cộng dồn (`run --features`) chỉ được gọi ĐÚNG MỘT LẦN, ở cuối vòng
lặp, khi đã đạt 150 giờ hợp lệ.

### Mục 4 — Không đổi tỉ lệ N2 — GIỮ NGUYÊN, không chạm

Không thay đổi `policy/variant-split.yaml`, không thay đổi tần suất N2 (`crapi_noise_n2.sh`). Đồng ý với
lý do nêu trong yêu cầu (đơn vị phiên vs cửa sổ khác nhau; N2 đã làm đúng việc "luật đơn giản sụp" — luật
deny>0 precision 0,07 vs mô hình 0,79/0,9434 tuỳ khúc).

### Mục 5/6 — Hạ tầng chạy tiếp từ khúc 10 tới 150 giờ

**Mới**:
- `tests/phaseb_chunk_preflight.sh` — tiền kiểm trước MỖI khúc: `crapi_preflight` (cert thiết bị Device CA,
  tự renew khi <24h còn lại trong TTL 7 ngày gốc — hàm đã có từ trước, B7 chỉ gọi nó đúng lúc), Loki
  `/ready`, VÀ kiểm MỚI chưa từng tự động hoá trước B7: gửi một request cố ý bị từ chối (crapi-web gọi
  thẳng workshop, không qua PEP hợp lệ) rồi xác nhận quyết định deny đó XUẤT HIỆN trong Loki
  `opa-decisions` trong vài giây — bắt được ca "mesh tươi nhưng OPA đã ngừng ra quyết định mới" mà kiểm
  độ tươi của `collect_chunked.py` không bắt được. Đã test thật trên cụm: PASS (1 dòng opa deny thấy sau
  ~8s).
- `tests/phaseb_chunk_postprocess.sh` (sửa): thêm bước `featurize` ngay sau export thành công, trước khi
  ghi dòng báo cáo vào `runs.jsonl` — lỗi featurize KHÔNG hạ khúc xuống aborted (dữ liệu thô đã an toàn,
  bảng đặc trưng sinh lại được sau).
- `tests/phaseb_collect_loop.sh` (mới) — vòng lặp: tiền kiểm → mở khúc (`collect_chunked.py --chunks 1`)
  → hậu kỳ (export+featurize) → áp quy tắc dừng (3 gap liên tiếp / export rỗng liên tiếp / tỉ lệ aborted
  campaign >20%/khúc / báo khi `exfil_*` vẫn ≤3 lượt sau ≥3 khúc) → lặp tới khi đủ 150h → gọi
  `run --features` ĐÚNG MỘT LẦN → DỪNG, chờ xác nhận (không tự coi Giai đoạn B xong).

**Xác nhận bốn variant mỏng tới thời điểm này** (trước khúc 10, sau cân lại tần suất ở B6 mục 3.3):
`train:exfil_burst_12`=1, `holdout:exfil_slow_12`=1, `train:exfil_burst_20`=1, `holdout:exfil_slow_20`=1,
`holdout:denied_slowdrip`=2, `train:denied_burst`=6 — đúng số liệu B6 đã nêu, CHƯA đổi vì khúc 10 chưa
chạy. `tests/phaseb_collect_loop.sh` sẽ tự in lại bảng này sau khúc 12 (3 khúc kể từ khúc 10) và báo ngay
nếu `exfil_*` vẫn ≤3.

*(Phần "chạy tiếp" — khởi động thật khúc 10 — CHƯA thực hiện trong lượt này; xem Kết luận B7.)*

---

## C2 — EXPORT 9 KHÚC, ĐIỀU TRA bff=0, HÀNH ĐỘNG TIẾP THEO (2026-10-18)

### Mục 1 — Export 9 khúc ra ~/c2-export/ — ✅ HOÀN TẤT

**Lệnh**:
```bash
cp -t ~/c2-export/ \
  results/b4/chunks/c000{1..9}-*/features_w{60,300,600}.csv.gz \
  tests/runs.jsonl policy/variant-split.yaml \
  BAOCAO-SUA-GANNHAN-C1.md BAOCAO-THU-DULIEU-B.md \
  results/b4/chunks/c0001-20261012T164833/gate_result.json
```

**Kết quả**:
- Đường dẫn: `~/c2-export/`
- Số file bảng đặc trưng: **27** (`c000X-TIMESTAMP__features_w{60,300,600}.csv.gz`, c0001–c0009 × 3 độ rộng, bao gồm cả c0008 dữ liệu `gap`)
- Dung lượng tổng: **5.4 MB** (đã nén)
- Xác nhận nhãn `bola`: `c0002-20261013T034929__features_w300.csv.gz` có **17 dòng** `label=attack`, `scenario=bola`, `entity=testuser01`, `bytes_sum=249166.0` — C1+C1c fix đang có trong file
- Cũng gồm: `runs.jsonl`, `variant-split.yaml`, hai báo cáo BAOCAO-*.md, `gate_result.json` (khúc 1)

**Phân tách theo tên file** (định dạng: `{chunk_id}__{bảng_đặc_trưng}`):
- 9 × `features_w60.csv.gz` (cửa sổ 60s)
- 9 × `features_w300.csv.gz` (cửa sổ 300s)
- 9 × `features_w600.csv.gz` (cửa sổ 600s)

→ Dữ liệu sẵn sàng để huấn luyện/đánh giá tại Giai đoạn C. Không cần truy cập vào server thu dữ liệu.

---

### Mục 2 — Điều tra bff=0 (c0014, c0015) — ✅ NGUYÊN NHÂN XÁC ĐỊNH

#### Bối cảnh: c0010–c0013 (crash-restart, không liên quan đến bff=0)

Sau khi chạy khúc 9 (đóng 15/10 07:34Z), collect_loop bị dừng trong kỳ bảo trì B6/B7 (15–17/10). Khi khởi động lại vào 17/10 ~13:36Z, bộ thu phát hiện 4 khúc aborted ngắn (c0010–c0013, mỗi khúc 20–120 giây) do tiến trình bị kill giữa chừng trước đó. Đây là hành vi bình thường của `collect_chunked.py` ("phát hiện khi khởi động lại"), không có dữ liệu thực tế mất.

#### c0014 và c0015: bff=0

| chunk | khoảng thời gian | envoy | opa | bff | kết quả |
|-------|-----------------|-------|-----|-----|---------|
| c0014 | 17/10 13:42–19:52Z | 121,498 | 90,926 | **0** | aborted |
| c0015 | 17/10 19:55Z–18/10 02:05Z | 121,587 | 90,924 | **0** | aborted |

#### Bốn phép thử (để phân biệt ba khả năng)

**Phép thử 1 — BFF pod logs trong cửa sổ c0014**:
- Đếm audit events có trường `sid`/`request_id`: **0 dòng**
- Log pod chỉ gồm health check requests và 1 lần test Keycloak thủ công (503)
- Log từ khoảng c0014 (13:42–19:52Z) đã bị purge khỏi pod (container log rotation) → chỉ có logs gần
- Kết luận: không rõ từ pod logs, chuyển sang Loki

**Phép thử 2 — Loki query `{job="bff-audit"}` trong cửa sổ c0014**:
- Truy vấn: `{job="bff-audit"}` trong khung 2026-10-17T13:42Z → 19:52Z, limit=400
- Kết quả: **0 dòng**
- Sự kiện bff-audit cuối cùng trong Loki: `2026-10-15T07:34:16Z` (kết thúc c0009, 2 ngày trước c0014)
- Từ 15/10 07:34Z đến 17/10 13:42Z (hơn 54 giờ): **không có event BFF nào vào Loki**

**Phép thử 3 — Mã export (kiểm tra B3 đã sửa chưa)**:
- `phaseb_gate.py::loki_export()` dòng 37–91: `PAGE_SIZE=400` (đã sửa B3), retry với limit nhỏ hơn khi lỗi
- `sys.exit(1)` khi bff=0 và không có `--allow-empty-bff` (dòng 1456–1468): **đúng**, export không âm thầm bỏ qua
- Kết luận: **không phải lỗi export** — mã export B3 đã sửa, hoạt động đúng. Bff thật sự 0 dòng từ Loki.

**Phép thử 4 — Phân phối HTTP status trong envoy c0014**:
```
503: 62,909 (58.0%) ← TẤT CẢ từ Keycloak paths
200: 37,313 (34.4%) ← OPA authz sidecar (không phải traffic người dùng)
302: 7,860  (7.2%)
401:    276
403:     56
```
- 503 paths: `/kc/realms/ztlab/.../auth` = 39,207 lượt; `/realms/ztlab/.../auth` = 23,554 lượt
- Không có `200` nào từ login path (BFF tới Keycloak)
- Kết luận: **Keycloak endpoint hoàn toàn trả 503 trong c0014** — N1 workers không thể đăng nhập

#### Bảng quyết định (Mục 2 §2.3)

| Trạng thái | Kết quả | Phân loại |
|-----------|---------|-----------|
| Pod có audit + Loki có | — | lỗi truy vấn export (B3 pattern) |
| Pod có audit + Loki không | — | lỗi chuyển log (promtail/label) |
| **Không có audit + Không có** | **✓ (phép thử 1+2)** | **BFF thật sự không ghi → nguyên nhân ở Keycloak/gateway** |

→ Kết luận theo bảng: **BFF thật sự không ghi** do N1 workers không login được (không có BFF session) → không có audit event nào.

#### Nguyên nhân trực tiếp: WireGuard tunnel DOWN

Kiểm tra trên AWS K3s master (10.10.1.10) vào 18/10:
```bash
wg show                              # → RỖNG (không có WireGuard interface nào)
ip route show 192.168.101.0/24       # → RỖNG (không có route)
ping -c2 192.168.101.11              # → 100% packet loss
```

**Chuỗi nguyên nhân**:
```
WireGuard tunnel AWS↔OpenStack DOWN
    → keycloak-openstack.crapi ClusterIP không route được tới 192.168.101.11:30091
    → Mọi request tới /kc/realms → 503 Service Unavailable
    → N1 workers: mọi lần login thất bại (không nhận 302 redirect)
    → BFF không tạo được session → không có audit event
    → bff.jsonl.gz = 0 dòng → phaseb_gate.py export sys.exit(1) → khúc aborted
```

Xác nhận: envoy c0014 có 121,498 dòng (traffic N1/N2/campaign vẫn chạy), opa c0014 có 90,926 dòng (OPA authz sidecar tại WAF hoạt động bình thường) — chứng minh hạ tầng AWS K3s bình thường, chỉ có kết nối tới OpenStack K3s (qua WireGuard) bị đứt.

#### Sự kiện os-gateway (mục độc lập, KHÔNG là nguyên nhân bff=0)

`os-gateway` (VM 10.10.10.130) là SSH **jump host** để quản trị viên SSH vào OpenStack K3s nodes (192.168.101.11–13). Nó **không nằm trong data path** của traffic BFF→Keycloak. WireGuard tunnel AWS↔OpenStack chạy trực tiếp giữa các K3s node, không đi qua os-gateway.

Kernel soft lockup trên os-gateway (ghi nhận từ console log) là sự kiện hạ tầng độc lập: khi os-gateway hang, SSH vào OpenStack K3s bị chặn nhưng **WireGuard tunnel không bị ảnh hưởng theo cơ chế này**. Trong trường hợp c0014/c0015, WireGuard đã down trước hoặc độc lập với trạng thái os-gateway.

→ Chẩn đoán ban đầu ghi trong §C1 (BAOCAO-SUA-GANNHAN-C1.md §9): "os-gateway hung → Keycloak 503" — **đã bị dữ liệu phản bác theo điểm sau**: os-gateway là jump host, không phải gateway trên data path. Nguyên nhân đúng là WireGuard tunnel down. Không xoá chẩn đoán cũ — ghi là đã được dữ liệu 4 phép thử (đặc biệt `wg show` trống + no route trên AWS K3s node) làm rõ hơn.

#### brute_force status=attack là false positive khi Keycloak down

Trong c0014: `brute_force` ghi `status=attack` (3 lượt). Điều này KHÔNG có nghĩa Keycloak hoạt động.

`tests/crapi_brute_force.sh` dòng 43–55: thử 15 lần đăng nhập sai password, đếm `fail_count` khi response code ≠ "302". Khi Keycloak trả 503 (không phải 302), mỗi lần login vẫn được tính là "thất bại đúng" (`fail_count++`). Khi `fail_count ≥ 13/15` (ATTEMPTS-2), script `pass()` → exit 0 → `status=attack`.

Script không phân biệt giữa "đăng nhập bị từ chối với HTTP 401/redirect" (tấn công brute_force thật) và "Keycloak hoàn toàn không phản hồi (503)" — cả hai đều exit 0.

Tương tự, `lateral_movement` và `access_denied_spike` trong c0014 có `status=attack`: các script này không phụ thuộc vào Keycloak login (dùng token có sẵn hoặc direct API call), nên có thể thực sự đã sinh traffic — nhưng do bff=0, toàn bộ `build_sid_map` rỗng → không có attack windows nào được featurize → khúc dù có attack runs thật, cũng hoàn toàn vô dụng cho Giai đoạn C.

#### Điều chỉnh quy tắc dừng collect_loop (ABORT_STREAK_MAX)

**Trước C2**: `ABORT_STREAK_MAX=2` — dừng sau 2 lần postprocess thất bại liên tiếp.

**Sau C2**: `ABORT_STREAK_MAX=1` — dừng ngay sau 1 lần.

Lý do: bff=0 → `build_sid_map` rỗng → entity attribution không hoạt động → bola quay về 0 attack windows → khúc hoàn toàn vô dụng cho Giai đoạn C. Không có lý do chạy thêm khúc thứ 2 để xác nhận điều đã rõ ràng từ lần đầu.

File sửa: `tests/phaseb_collect_loop.sh` dòng 23 (đã áp dụng, không commit theo ràng buộc C2).

---

### Mục 3 — Khúc xác thực 1 giờ — **KHÔNG THỰC HIỆN ĐƯỢC — OpenStack down ngày 20/10, mốc cứng đạt, bỏ mục**

Bốn tiêu chí cần vượt qua:
1. `bff.jsonl.gz > 0` dòng, hợp lý so với envoy/opa
2. featurize → bola có ≥1 cửa sổ attack (kiểm `build_sid_map` hoạt động)
3. N1 non-200 < 1%
4. ≥1 lượt `status=attack` ghi đúng

**Lý do không thực hiện**: Ngày 20/10/2026 (mốc cứng), cụm OpenStack hoàn toàn không liên lạc được:
- WireGuard tunnel down: `ping 192.168.101.11` → 100% packet loss
- SSH đến OpenStack VM (192.168.100.10) → timeout
- k3s API server (127.0.0.1:6445) → connection refused

Per ràng buộc C2: "Nếu một mục nào của hạng mục này có nguy cơ làm trễ mốc, bỏ mục đó, giữ mốc" → bỏ Mục 3.

**Tình trạng các tiêu chí theo dữ liệu đã thu (c0017)**:
- Tiêu chí 1 (`bff > 0`): **ĐẠT** — c0017 có bff=310 BFF audit events
- Tiêu chí 2 (bola ≥1 attack window): **KHÔNG ĐẠT** — bola abort trong c0017 (community chỉ có ~30 bài tại 09:53Z, quét 30 bài/trang, trang 1 chỉ có 1 vehicleid nạn nhân, trang 2 rỗng → dừng)
- Tiêu chí 3 (N1 non-200 < 1%): **KHÔNG ĐẠT** — c0017 có 43.6% non-200 (401 session expiry + 403 OPA role denial là hành vi bình thường, nhưng threshold 1% vẫn fail)
- Tiêu chí 4 (≥1 attack status=attack): **KHÔNG ĐẠT** — bola aborted, không có attack windows được featurize

**Phát hiện bổ sung (Mục 3b) — OPA crosscloud source_principal rỗng** (điều tra 18–20/10):

Ngay cả sau khi WireGuard khôi phục và SPIRE SVIDs hợp lệ (BFF: `spiffe://ztlab.local/aws/bff` hết hạn 15:47:15Z 18/10; Keycloak: `spiffe://ztlab.local/openstack/keycloak` hết hạn 16:08:03Z 18/10), Keycloak vẫn trả 403 UAEX cho gần như mọi request từ BFF.

Bằng chứng từ Keycloak Envoy access log (kubectl logs Keycloak pod -c istio-proxy):
```json
{"svid":"spiffe://ztlab.local/aws/bff","path":"/realms/ztlab/protocol/openid-connect/token","response_code":403,"response_flags":"UAEX"}
```

Và từ OPA decision log (OpenStack OPA pod):
```json
{"input":{"source_principal":"","destination_principal":"spiffe://ztlab.local/openstack/keycloak","method":"POST","path":"/realms/ztlab/protocol/openid-connect/token",...},"path":"zta/crapi/crosscloud/allow"}
```

Mâu thuẫn: `svid` trong Envoy access log = `spiffe://ztlab.local/aws/bff`, nhưng OPA nhận `source_principal: ""`.

**Chuỗi nguyên nhân thứ hai** (lớp OPA, độc lập với WireGuard):
```
BFF (AWS K3s) → ISTIO_MUTUAL DestinationRule → mTLS tới Keycloak NodePort
    → Keycloak Envoy (STRICT PeerAuthentication) nhận mTLS, xác nhận cert BFF
    → Envoy gọi OPA ext_authz (crosscloud_crapi.rego, path zta/crapi/crosscloud/allow)
    → OPA input: source_principal = input.attributes.source.principal = ""
         [mTLS cert được verify nhưng SPIFFE ID không được map vào source.principal
          do SPIRE federation cross-cluster chưa thiết lập — Envoy biết cert hợp lệ
          nhưng không thể xác nhận danh tính SPIFFE của peer cluster khác]
    → crosscloud_crapi.rego: startswith("", "spiffe://ztlab.local/") = false → allow = false
    → Envoy trả 403 UAEX
```

Cách khắc phục (Giai đoạn C nếu cần): thiết lập SPIRE federation giữa AWS và OpenStack (chia sẻ trust bundle), hoặc thêm Keycloak auth paths vào `public_path` trong `crosscloud_crapi.rego`.

c0017 vẫn có bff=310 vì: (a) `oidc_token_exchange_failed` events khi token exchange bị 403 CŨNG được ghi vào bff-audit; (b) khoảng ~25% token exchange thành công (cơ chế chưa rõ, có thể do race condition trong SPIRE cert rotation tạo ra các khoảng ngắn source_principal được điền đúng).

### Mục 4 — 3 kịch bản mỏng thu bù — **KHÔNG THỰC HIỆN — phụ thuộc Mục 3**

Per ràng buộc C2: "Nếu một mục nào của hạng mục này có nguy cơ làm trễ mốc, bỏ mục đó, giữ mốc."

Mục 4 phụ thuộc vào Mục 3 (khúc xác thực phải PASS 4 tiêu chí) mới biết cần thu bù kịch bản nào. Vì Mục 3 không thực hiện được (OpenStack down), Mục 4 cũng không thực hiện. Dữ liệu thu bù (nếu cần) là quyết định của Giai đoạn C.

---

### Mục 5 — Hai mục tồn từ C1b/C1c — ✅ ĐÓNG

#### C1b §2.1 — Pool nạn nhân BOLA về 1 vehicleid (khúc 10)

Khúc 10 (17/10 13:36Z, ~20s): collect_loop khởi động lại sau bảo trì, bola quét 1 trang × 30, chỉ tìm 1 vehicleid.

Nguyên nhân: N1 background chưa kịp tạo đủ posts tại thời điểm bola là variant đầu tiên. Script `crapi_bola.sh` có `BOLA_SCAN_MAX_PAGES=200` (đủ sâu), nhưng community chỉ có 1 post có vehicleid lúc đó.

Kết luận: **không phải lỗi** — đây là race condition giữa N1 warm-up và variant đầu tiên chạy ngay khi khúc bắt đầu. Các khúc 1–9 có 69 lượt bola attack thành công (fix phân trang B5 Mục 1 đã giải quyết vấn đề suy giảm theo thời gian). Không cần thay đổi.

#### C1b §2.2 — Abort rate sau brute_force vs tổng thể

Đo trên 9 khúc (c0001–c0009):

| Tập | Lượt | Aborted | Tỉ lệ |
|-----|------|---------|--------|
| Lượt ngay SAU brute_force | 34 | 1 | **2.9%** |
| Tất cả lượt còn lại | 140 | 9 | **6.4%** |

Kết luận: tỉ lệ abort sau brute_force **thấp hơn** tỉ lệ tổng thể. Không có chuỗi nhân quả brute_force → lock testuser01 → abort. 1 abort duy nhất là bola (victim pool — không liên quan đến lock). Không cần thay đổi.

#### C1c Per-run recall — chunk 1, width 60 (sau fix C1+C1c)

| Scenario | Lượt phát hiện | Tổng lượt | Recall |
|----------|----------------|-----------|--------|
| bola | 3 | 5 | **60%** |
| bfla | 4 | 4 | **100%** |
| brute_force | 4 | 4 | **100%** |
| access_denied_spike | 1 | 1 | **100%** |
| lateral_movement | 0 | 2 | **0%** |
| **Tổng** | **12** | **16** | **75%** |

bola burst (0/2): dùng JWT Bearer → entity=bff/waf (không phải testuser01) → không khớp.
lateral_movement (0/2): OPA deny phát sinh ở entity dịch vụ (`crapi-community`), không phải testuser01 → hạn chế kiến trúc, không sửa được trước 20/10.

Chi tiết đầy đủ: `BAOCAO-SUA-GANNHAN-C1.md §5a`.

---

**Mốc cứng 20/10/2026 ĐÃ ĐẠT**: toàn bộ dữ liệu đã export, feature files (3 widths) đã sinh, backup trên ổ riêng.


---

## C3 — SINH ĐẶC TRƯNG GIAI ĐOẠN C (Hạng mục C3, 20/10/2026)

### C3 Mục 1 — File đặc trưng đã sinh (~/c2-export và ~/c3-export)

Tất cả 9 khúc hợp lệ (c0001–c0009, bao gồm c0008 dạng gap có dữ liệu thật) được
export từ Loki và featurize với **5 độ rộng cửa sổ** (15, 30, 60, 300, 600 giây)
trong một lần gọi `phaseb_gate.py featurize --widths 15,30,60,300,600`.

| Thư mục | Widths | Số file | Ghi chú |
|---------|--------|---------|---------|
| `~/c2-export/` | w60, w300, w600 | 27 (9×3) | C2 Mục 1 |
| `~/c3-export/` | w15, w30 | 18 (9×2) | C3 Mục 1 |

Tên file: `{chunk_id}__features_w{width}.csv.gz`  
Ví dụ: `c0001-20261012T164833__features_w300.csv.gz`

File `~/c2-export/runs.jsonl` và `variant-split.yaml` cũng được sao chép.

**Dòng raw từ Loki (9 khúc)**:

| chunk_id | envoy | opa | bff | trạng thái |
|----------|-------|-----|-----|-----------|
| c0001-20261012T164833 | 793,755 | 362,321 | 2,439 | valid |
| c0002-20261013T034929 | 788,335 | 360,292 | 2,420 | valid |
| c0003-20261013T101928 | 790,953 | 361,328 | 2,434 | valid |
| c0004-20261013T164755 | 782,121 | 358,232 | 2,413 | valid |
| c0005-20261013T232454 | 780,807 | 357,952 | 2,405 | valid |
| c0006-20261014T055021 | 788,069 | 360,374 | 2,451 | valid |
| c0007-20261014T122146 | 787,906 | 360,151 | 2,427 | valid |
| c0008-20261014T185331 | 788,147 | 360,493 | 2,465 | **gap** |
| c0009-20261015T012417 | 785,501 | 359,306 | 2,358 | valid |

bff > 0 ở mọi khúc → `build_sid_map` hoạt động → feature files có `label=attack`.

**Xác nhận bola attack label**: file `c0002__features_w300.csv.gz` có **17 dòng** `label=attack`, `scenario=bola`, `entity=testuser01`, `bytes_sum=249166.0` — C1+C1c fix đang có trong file (xem C2 Mục 1).

### C3 Mục 2 — Quy tắc gán nhãn: cửa sổ chứa N2 + attack

#### Đọc mã nguồn (tests/phaseb_gate.py)

**Hàm `label_for(entity, ts, runs)`** (dòng 428): trả `(class, variant_group)`.
Attack LUÔN thắng benign_noise — không phân biệt tỉ lệ sự kiện, chỉ cần một sự
kiện overlap là đủ lật nhãn.

**`_featurize_streaming()` (dòng 542, dùng khi window==step)**: dòng 632:
```python
if matched:   # window overlap attack run
    ...
    continue  # skip benign path entirely
```
Cửa sổ overlap attack run KHÔNG được đưa vào buffer benign hay benign_noise.

**`_featurize_inmemory()` (dòng 468, dùng khi window≠step)**: dòng 515:
```python
if in_attack(ent, w0, we): w0+=step; continue
```
Cùng logic loại trừ.

**Kết luận (A)**: Khi độ rộng cửa sổ tăng, nhiều cửa sổ "biên" hơn overlap với
khoảng thời gian attack run (attack run thường dài 3–10s, còn benign_noise N2
chạy song song liên tục). Những cửa sổ đó bị LOẠI hoàn toàn khỏi pool benign →
số cửa sổ benign_noise GIẢM khi window rộng hơn. Đây là hành vi ĐÚNG theo thiết
kế, không phải lỗi.

#### Phân bố nhãn theo độ rộng (c0001 — 6.167h)

| width | attack | benign_noise | benign | total | N2/(N2+benign) |
|-------|--------|--------------|--------|-------|----------------|
| w15   |    299 |          701 |  20900 | 21900 | .032 |
| w30   |    191 |          367 |  11419 | 11977 | .031 |
| w60   |    123 |          177 |   6263 |  6563 | .027 |
| w300  |     43 |           23 |   2026 |  2092 | .011 |
| w600  |     29 |            4 |   1448 |  1481 | .002 |

**Kết luận từ dữ liệu thực tế (c0001, 6.167h)**:

Tổng hàng giảm dần từ w15→w600 (ít cửa sổ hơn — cùng khoảng thời gian nhưng mỗi
cửa sổ dài hơn). Đáng chú ý là tỉ lệ N2/(N2+benign) giảm rất mạnh: 3.2% → 3.1%
→ 2.7% → 1.1% → **0.2%** — xác nhận Kết luận (A): cửa sổ rộng hơn overlap nhiều hơn
với biên attack run → nhiều cửa sổ N2 bị loại khỏi pool benign_noise.

Tại w600 chỉ còn **4 hàng benign_noise** (1 khúc 6h) — không đủ để học ranh giới
N2 vs attack ở độ rộng này. Giai đoạn C cần cân nhắc khi chọn window width.

### C3 Mục 3 — Xác nhận 5 điểm kiến trúc từ manifest

#### 3.1 — Thứ tự edge-gateway → waf → bff

Xác nhận từ `k8s/crapi/edge-gateway.yaml` (Gateway resource `crapi-edge-gateway`,
IngressGateway trong `istio-system`) và `k8s/crapi/waf.yaml`:

```
Client (HTTPS/mTLS) 
  → Istio IngressGateway (edge-gateway, spiffe://ztlab.local/aws/edge-gateway)
  → waf:8080 (ModSecurity3/OWASP CRS, DetectionOnly)
  → bff:8080 (Python FastAPI, spiffe://ztlab.local/aws/bff)
```

ACL xác nhận: `service_acl.rego` có `"aws/edge-gateway" → "aws/waf"` (dòng 47–56)
và `"aws/waf" → "aws/bff"` (dòng 67–77). KHÔNG có direct `edge → bff`.

WAF **SecRuleEngine = DetectionOnly**: không chặn traffic nào, chỉ log → không
ảnh hưởng đến tỉ lệ envoy 503/403 trong dữ liệu thu.

#### 3.2 — PDP crosscloud trên OpenStack

OPA `crosscloud_crapi.rego` chạy trên cụm OpenStack K3s (không phải AWS).  
Path ext_authz: `zta/crapi/crosscloud/allow`.  
Package: `zta.crapi.crosscloud`.

Dòng chủ chốt:
```rego
source_principal := object.get(input.attributes.source, "principal", "")
allow if { startswith(source_principal, "spiffe://ztlab.local/"); ... }
```

Khác với AWS OPA (`zta/crapi/authz/allow`) — hai PDP hoàn toàn tách biệt.

#### 3.3 — Loki và Grafana trên AWS K3s

Stack PLG (`plg-stack` namespace) chạy 100% trên AWS nodes (10.10.1.x):
- `loki-0` — StatefulSet, port 3100 (nội bộ), exposed qua NodePort 13100
- `grafana` — Deployment
- `promtail` — DaemonSet (xem 3.4)

Loki API endpoint từ AWS node: `http://localhost:13100` (qua NodePort).  
Retention: 30 ngày → tất cả 9 khúc (12–15/10) trong window.

#### 3.4 — Promtail DaemonSet (không phải sidecar)

`promtail` là DaemonSet: **một pod trên mỗi node** (3 pods = 3 AWS nodes).  
Scrapes `/var/log/pods/**/*.log` từ mọi pod trên node → forward đến Loki.  
Không phải sidecar injection — không cần sửa deployment spec của workload để có log.

Ý nghĩa: toàn bộ log của mọi pod (envoy sidecar, crapi-*, opa, bff, keycloak NodePort) đều vào Loki mà không cần cấu hình từng workload riêng.

#### 3.5 — Danh sách dịch vụ crAPI thật sự đang chạy

**AWS K3s (namespace `crapi`)**:

| Workload | Kind | Image | Vai trò |
|----------|------|-------|---------|
| `istio-ingressgateway` | Deployment (istio-system) | Istio | edge-gateway, SPIFFE `aws/edge-gateway` |
| `waf` | Deployment | owasp/modsecurity-crs | WAF ModSec3 DetectionOnly |
| `bff` | Deployment | ztlab/bff:1.0.0 | Python FastAPI proxy |
| `crapi-web` | Deployment | crapi/crapi-web | Frontend React |
| `crapi-community` | Deployment | crapi/crapi-community | Community API |
| `crapi-workshop` | Deployment | crapi/crapi-workshop | Workshop API |
| `opa-server` | Deployment (3 replicas) | openpolicyagent/opa | PDP intra-AWS |
| `redis` | Deployment | redis:7-alpine | Session cache |
| `mongodb` | StatefulSet | mongo | Database |

**OpenStack K3s (không quản lý trực tiếp từ AWS)**:

| Workload | Vai trò |
|----------|---------|
| `crapi-identity` | Identity/auth service (SPIFFE `openstack/crapi-identity`) |
| `keycloak` | OIDC provider (SPIFFE `openstack/keycloak`) |

**Không có** `crapi-seed` hoặc `kc-admin-setup` đang chạy (đây là Job, chỉ chạy
một lần khi seed dữ liệu, không còn tồn tại dưới dạng Deployment thường xuyên).

### C3 Mục 4 — ~/c3-export

Cùng quá trình rebuild với C2: export từ Loki → featurize 5 widths → copy w15/w30
vào `~/c3-export/`. Khi hoàn tất: 18 file, mỗi file là `{chunk_id}__features_w{15,30}.csv.gz`.

**Kết quả rebuild (20/10/2026, hoàn tất 13:13 UTC)**:
- Tất cả 9 khúc (c0001–c0009): XONG
- `~/c2-export/`: 27 file .gz (9×3 widths) + 4 file metadata = 31 file
- `~/c3-export/`: 18 file .gz (9×2 widths)

