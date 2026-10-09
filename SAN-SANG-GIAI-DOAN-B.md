# SẴN SÀNG GIAI ĐOẠN B — ĐÓNG SỔ GIAI ĐOẠN HẠ TẦNG (2026-10-03 → 2026-10-04)

> Văn bản bàn giao cuối của giai đoạn hạ tầng. Sau văn bản này giai đoạn hạ tầng được tuyên bố hoàn thành và không mở lại.
> Cụm đo: dựng **từ trống** ngày 2026-10-04 (AWS tài khoản 448079093506 + OpenStack AIO), mã nguồn hiện tại.
> Dữ liệu thô: `results/closeout/`. Bản bàn giao vòng 2026-09-29/30 trước đó: lịch sử git của file này.

## 1. KẾT LUẬN: **GO** cho Giai đoạn B

Lý do: (1) mục bắt buộc 2.1 — thu thập chia khúc có checkpoint, tự phát hiện khoảng trống, tiếp tục được — **ĐẠT** nghiệm thu sống
(valid / gap / valid với sự cố WireGuard 134 s giữa khúc 2); (2) tiêu chí GO/NO-GO 3.2 — deny lành tính **0/7406 quyết định (0,0 %), 0
evidence bundle** trong 60 phút lưu lượng hợp lệ, decision log được tự kiểm là đang chảy trước khi đếm; (3) 2.2 và 2.3 ĐẠT sau khi sửa
trong code (TTL SVID 4 h kiểm sống; đĩa node Loki đủ cho retention 720 h × 2); (4) hạ tầng tái lập được từ trống trên mã hiện tại.
Tiêu chí định lượng độ trễ (3.1) **không** chặn GO: thành phần PDP đo được trên lưu lượng thật, phép đo đầu-cuối chuyển sang B (lý do ở 3.1).

## 2. TRIAGE 2026-10-03 — cái gì đang là thật

### 2.1 Lần hỏng và nguyên nhân gốc

| Mốc (+07) | Sự kiện | Nguồn |
|---|---|---|
| 2026-09-30 00:04–01:07 | destroy + `deploy-all.sh` từ trống trên tài khoản AWS 213682563693: 0 FAIL | `results/round4/rebuild/attempt1.*` |
| 2026-09-30 02:07–03:16 | chuỗi đo tự động: `tfplan_aws` rc=0, `perf_run1` rc=1, `perf_run2` rc=1 | `results/round4/chain.status` |
| 2026-09-30 ~03:16 | tunnel API AWS chết; SSH bastion/gateway timeout; WireGuard 0 B nhận; `aws sts get-caller-identity` → `InvalidClientTokenId` (đồng hồ máy đúng) | transcript phiên 09-30 |
| 2026-10-03 22:30–01:16 | người dùng chuyển sang tài khoản AWS 448079093506 (`.env` mới; tfstate cũ lưu `snapshots/tfstate-acct-213682563693/`), dựng lại AWS, giữ OpenStack 09-30; sửa trong lúc dựng: OPA OpenStack thiếu `istio-proxy` (Keycloak 403 UAEX), route DNS hố đen trên `os_gateway` | mtime file, comment trong mã |
| 2026-10-04 01:30 → 09:46 | đóng sổ mục 3.6: plan sạch → destroy → `deploy-all.sh` từ trống (3 lần, xem 4.6) | `results/closeout/rebuild/` |

**Nguyên nhân gốc lần hỏng 09-30:** mất quyền truy cập **cấp tài khoản AWS** — khoá bị vô hiệu phía AWS và đồng thời mọi EC2 không tới được
(SSH lẫn WireGuard) trong khi Internet của máy người dùng bình thường. **Không** thuộc các sự cố trong cụm ở `HE-THONG-CHI-TIET.md` §10.2.
Lý do phía AWS không xác minh được từ repo. Đã loại trừ "khoá lộ qua git": `.env` không được track; khoá AWS duy nhất từng có trong lịch sử
git (`AKIAILNV…`, tháng 4–6/2026, xoá ở `789f0ad2`) không phải khoá của tài khoản vừa mất; khoá hiện tại không có trong lịch sử.
**Đã chặn được chưa:** không — rủi ro ngoài hệ thống. Giảm thiểu: thu chia khúc (một lần mất cụm = mất một khúc, không mất đợt thu).

**Sự cố thứ hai, lộ ra khi dựng lại (đã chặn bằng code):** máy AIO khởi động với đồng hồ lệch +7 h (RTC ghi giờ địa phương — dual-boot);
toàn bộ container Kolla khởi động trong lúc đó, rồi chrony bước lùi 25 199 s → nova-scheduler câm, VM kẹt BUILD 30 phút rồi `ERROR
MessagingTimeout` trong khi `compute service list` vẫn báo `up`. `scripts/openstack-aio-preflight.sh` (deploy-all bước 6) phát hiện
container có `StartedAt` ở tương lai, restart theo thứ tự phụ thuộc và tạo VM thử bắt buộc ACTIVE.

### 2.2 Phân loại từng bước của `results/round4/chain.status`

| Bước | Phân loại | Bằng chứng |
|---|---|---|
| `chờ deploy` / `deploy xanh` | HỢP LỆ (cụm 09-30, tài khoản cũ) | `attempt1.timing` rc=0, log 0 FAIL |
| `tfplan_aws` rc=0 | ĐÁNG NGỜ → `-INVALID` | plan của tài khoản đã mất; thay bằng plan 2026-10-04 |
| `perf_run1` rc=1 | CHƯA CHẠY (không ra số) → `-INVALID` | công cụ tự chặn: 2050/2050 = 401 |
| `perf_run2` rc=1 | CHƯA CHẠY (không ra số) → `-INVALID` | 320 × 200 rồi 1730 × 403 (JWT 300 s hết hạn giữa lượt); cụm mất 03:16 |
| `perf_run3`, `perf_crosscloud`, `perf_diag_nolog`, `benign403`, `postbuild`, `bola_*`, `sqli_*`, `mttd` | CHƯA CHẠY | không có dòng BEGIN |

Các thư mục đo **trước** chuỗi (cụm 2026-09-29 20:14): `log-pipeline/`, `mesh-integrity/`, `waf-opa-authz/`, `step-up/`, `bff-token-refresh/`,
`alerts/`, `crs/` — đúng phương pháp trên cụm có đủ stack quan sát; giữ làm lịch sử, **mọi mục được đo lại trên cụm 2026-10-04** (bảng 4).

### 2.3 File đã đổi tên `*-INVALID.*` (31 file)

- `results/round3/perf_overhead*`, `perf_runs.status` — mọi request 401 (client thiếu token crAPI).
- `results/round3/crapi_bola-{1,2,3}.log`, `crapi_sqli_waf-1.log`, `crapi_run_all-1.log` — đếm bằng `loki_count` đã chứng minh sai; **và**
  (phát hiện 2026-10-04, H18) mọi request BOLA trong đó đều 404.
- `results/round3/mttd_*`, `mttd_runner.log` — chính sách thông báo cũ, chạy chồng hai kịch bản, n = 1 sạch.
- `results/round4/chain-perf_run{1,2}.log`, `chain-tfplan_aws.log` — như bảng trên.
- `results/mttd.json`, `results/mttd_lateral_movement.json`, `results/bola-output-2026-09-13.txt` — phiên 09-13/18/19, trước khi stack quan
  sát được dựng đúng; BOLA trong đó cũng toàn 404.

Giữ nguyên (HỢP LỆ): `results/round3/netpol_matrix.txt`, `podselector_probe_*.txt`, `crapi_cert_revocation-1.log`, `crapi_cert_scenarios-1.log`,
`telemetry.json`, `deploy-full-2026-09-26.log`.

## 3. BẢNG ĐÓNG SỔ

Trạng thái cuối: **ĐẠT** / **ĐO ĐƯỢC KHÔNG ĐẠT** / **HẠN CHẾ** (có chủ đích, ghi ở `HAN-CHE-VA-HUONG-PHAT-TRIEN.md`) / **CHUYỂN SANG B**.

| Mục | Trạng thái cuối | Lý do (một câu) | Dữ liệu thô |
|---|---|---|---|
| 1 Triage | ĐẠT | nguyên nhân gốc xác định tới mức kiểm được; 31 file đáng ngờ đổi tên | mục 2 |
| 2.1 Thu thập chia khúc | **ĐẠT** | nghiệm thu valid/gap/valid, ngắt WG 134 s → khúc 2 `gap`, tổng 0,333 h hợp lệ; hậu kiểm một mình sẽ đánh nhầm `valid` (Promtail gửi bù) — tiêu chí độ tươi bắt được | `results/closeout/chunked/acc20261004095212.*` |
| 2.2 TTL SVID 1 h → 4 h | **ĐẠT** | sửa cả server.conf lẫn `-ttl` trên entry (entry ghi đè server); sống: 13/13 entry 14400 s, cert sidecar 4 h | `results/closeout/live-checks/svid-wg-dns-*.txt` |
| 2.2 wg-watchdog + CoreDNS override | **ĐẠT** | timer active 2 gateway, chạy mỗi phút; `coredns-custom` mount, DNS ngoài + nội cụm OK | như trên |
| 2.3 Dung lượng log 150 h | **ĐẠT (sau sửa code)** | 51,6 MB/h đĩa dưới tải lành tính; quyết định là retention 720 h: ≈ 37 GB × 2 = 74 GB > 21 GB trống → nâng EBS 30 → 100 GB (sửa tại chỗ) + growfs Ansible → 88 GB trống | `results/closeout/log-volume/` |
| 3.1 Độ trễ | **CHUYỂN SANG B** (thành phần PDP: ĐẠT) | đầu-cuối: mỗi request tới workshop ~1–1,8 s do identity + Postgres cross-cloud → n ≥ 2000×3×3 ≈ 5 h, nhiễu WAN ≫ 20 ms; PDP đo trên 7406 quyết định thật: p99 AWS 4,37 ms, OS 1,45 ms | `results/closeout/perf/pdp-benign-window.json` |
| 3.1 Chẩn đoán decision log | HẠN CHẾ | nguồn đuôi PDP xác định khác: 98 % mẫu ≥ p99 là tải lại JWKS/discovery cross-cloud (cache 300 s, 100–410 ms); decision log ghi SAU khi trả lời nên không nằm trong timer PDP; lượt client tắt-log chưa chạy | như trên |
| 3.2 Deny lành tính (GO/NO-GO) | **ĐẠT** | 3604 s, 2021 request, 7406 quyết định, 0 deny, 0 bundle; decision log tự kiểm PASS trước khi đếm | `results/closeout/benign-403/run20261004102533.*` (+ `.CORRECTION.txt`) |
| 3.3 CRS/BOLA | **ĐẠT** | 3/3 lượt: BOLA thật 3/3 nạn nhân → CRS 0; SQLi/XSS/LFI = 1/1/1 (tổng 3) giống hệt; phép đo BOLA cũ chưa từng chạm BOLA thành công (H18) | `results/closeout/crs-bola/` |
| 3.4 Chín alert rule | **ĐẠT** | 9/9 có Firing + thông báo thật sau kích hoạt; lần đầu lộ kênh email Grafana chết (SMTP Gmail mật khẩu rỗng — alert hạ tầng chưa từng báo tới ai, H7 ca 6) → sửa SMTP → MailHog, chạy lại 3 rule; `AUDIT-THUC-THI.md` §6 viết lại | `results/closeout/alerts/` |
| 3.5 MTTD | **ĐẠT** (đo xong, kèm hạn chế pha) | 10 lượt/kịch bản, tuần tự, chính sách mới (`group_by [...]`, 30 s): Lateral trung vị 19,26 s [10,38–50,90], Brute Force 80,68 s [42,37–82,72]; phần hệ thống ~2 s, phần cấu hình chi phối; các lượt khoá pha với nhịp eval (bundle luôn ở giây :55 / :25) | `results/closeout/mttd/summary.txt`, `lateral.json`, `brute.json` |
| 3.6 Tái lập hạ tầng | **ĐẠT** | plan trước destroy 0 thay đổi; dựng từ trống lần 3 xanh (0 FAIL, Step 8b + 8c OK); 3 lỗi lộ ra đều sửa trong code | `results/closeout/rebuild/` |
| H1 panel metric cũ | **ĐẠT** | xoá 23 panel nguồn chết, sửa 4 truy vấn; sống: 8 dashboard, 0 tham chiếu nguồn chết | `results/closeout/live-checks/readonly-*.txt` |
| H2 Mesh Integrity báo giả | **ĐẠT** | 60 phút lưu lượng lành tính: 0 khớp vế A, 0 khớp vế B trên 14 823 dòng inbound; plaintext thật → Firing 90 s + email | `results/closeout/mesh-integrity/fp-benign-window.txt` |
| H3 kube-router thủng ingress nội ns | **HẠN CHẾ + PHÁT HIỆN** | tái hiện y hệt trên cụm mới: ma trận 14/22 (đúng 8 ô cũ), probe `egress-shadow` 2/2 MISMATCH mỗi cloud | `PHAT-HIEN-PHAN-DOAN-L4.md`, `results/closeout/netpol/` |
| H4 thu hồi cert chặn ghi | **ĐẠT** | 7/7 PASS, độ trễ file 59 s | `results/closeout/crapi_cert_revocation-1.log` |
| H5 `ipBlock` CIDR với ingress đã NAT | HẠN CHẾ (độ tin cậy thấp) | một quan sát 09-13, không dữ liệu thô, chưa tái hiện — không trích | `HAN-CHE` H5 |
| H7 chính sách tồn tại ≠ thực thi | **ĐẠT** (nội dung Bàn luận) | 5 ca chốt trạng thái (ca 2 đã thực thi); bài học phương pháp hai vế viết xong | `HAN-CHE` H7 |
| H8 nghiệm thu chặn deploy | **ĐẠT** | `ZTLAB_DEFER_ACCEPTANCE` + Step 8c; lần dựng 2026-10-04 chạy đúng thứ tự (8b rồi 8c) | `attempt3b-deploy.log` |
| H11 đường log, gián đoạn > 2,5 h | HẠN CHẾ | ngưỡng chịu đựng ≈ 2,5 h, không WAL bền; 2.1 là lưới an toàn | `HAN-CHE` H11 |
| H15.1/H16 làm mới token | **ĐẠT** | phiên 330 s: 200 → 200, `token_refreshed=1` | `results/closeout/bff_token_refresh-1.log` |
| H15.2 step-up OTP | **ĐẠT** | enroll tự động trong deploy; thường → 401 `step_up_required`, sau OTP qua gate (`stepup=true`); hành động trả 400 vì `stepup-demo` cạn credit (xem 5) | `results/closeout/crapi_step_up_otp-1.log` |
| H15.3 cert thiết bị tự cấp lại | **ĐẠT** | 4 kịch bản cert 4/4 + bằng chứng `device_trust_denied` (sau sửa lỗi làm tròn T1) | `results/closeout/crapi_cert_scenarios-2.log` |
| H15.4 `loki_count` | **ĐẠT** | SQLi 3/3 lượt cùng một kết quả; cùng họ lỗi (T1 làm tròn xuống) còn sót ở 3 script — đã sửa | `results/closeout/crs-bola/` |
| H15.5 scanner Job / sync script | **ĐẠT** | Job Privilege Escalation chạy xong trong 3.4; `sync-app-images.sh` chạy trong deploy rc=0 | 3.4, deploy log |
| H9, H12, H13 | HẠN CHẾ (đã xong) | có chủ đích, không làm gì | `HAN-CHE` |
| Prometheus 3 target | **ĐẠT** | sống: 3 target (loki, plg-stack-services, prometheus) up; ghi rõ Prometheus không phải trụ cột quan sát | `HAN-CHE` H1 |
| Câu chữ tài liệu | **ĐẠT** | rà toàn repo: L4, thu hồi cert, xoá số bị bác bỏ (xem 7) | — |

## 4. SỐ LIỆU CHỐT CHO LUẬN VĂN

### 4.1 Độ trễ (3.1)

- **Thành phần PDP (OPA ext_authz), đo từ `metrics.timer_server_handler_ns` của từng decision trong 60 phút lưu lượng lành tính:**

  | Cloud | n | p50 | p95 | p99 | max | số mẫu tạo nên p99 |
  |---|---|---|---|---|---|---|
  | AWS (`zta/crapi/authz`, có JWT RS256 với request từ bff) | 5277 | 0,50 ms | 2,02 ms | 4,37 ms | 409,6 ms | 53 |
  | OpenStack (`zta/crapi/crosscloud`) | 2129 | 0,30 ms | 0,82 ms | 1,45 ms | 2,47 ms | 22 |

  Phân phối AWS **lưỡng đỉnh**: 35/5277 (0,66 %) mẫu ≥ 100 ms, không mẫu nào trong 20–100 ms; 98 % mẫu ≥ p99 trùng lúc OPA tải lại
  JWKS/discovery **cross-cloud** từ Keycloak OpenStack (`force_cache_duration_seconds: 300`). Ở tải thấp hơn, tỉ lệ này vượt 1 % và p99 của PDP
  nhảy lên 100–400 ms. Hướng đúng: JWKS cục bộ mỗi cloud (bundle OPA hoặc mirror), không gọi WAN trên đường quyết định.
- **Kết luận thẳng:** ngưỡng 20 ms p99 cho **toàn bộ** overhead Zero-Trust **chưa được chứng minh đạt**. Thành phần PDP đạt (p99 4,37 ms)
  nhưng đây là cận dưới (không gồm gRPC Envoy↔OPA, bắt tay mТLS, hai chặng Envoy). Phép đo đầu-cuối 3 cấu hình phía client **CHUYỂN SANG
  GIAI ĐOẠN B**: mỗi request đi trọn tới crapi-workshop tốn ~1–1,8 s vì identity + Postgres nằm bên kia WireGuard, nên n ≥ 2000 × 3 × 3 ≈ 5 h
  và nhiễu WAN lớn hơn ngưỡng nhiều lần. Trong B, đo dưới tải nền thật (đúng hướng H6) bằng công cụ đã sửa (`tests/perf_overhead.py` có làm
  mới JWT theo lô) trong một cửa sổ riêng không có kịch bản tấn công.

### 4.2 Deny lành tính (3.2)
0 deny / 7406 quyết định OPA (AWS 5277 + OpenStack 2129) = **0,0 %**; 0 evidence bundle; 2021 request phía client (2009 × 200, 11 × 400 — cạn
credit `stepup-demo`, 1 × 000). Tiêu chí < 1 % và 0 bundle: **ĐẠT**.

### 4.3 Dung lượng log (2.3)
Đo 1,02 h dưới tải lành tính: thô vào Loki 71,2 MB/h (AWS 49,3 + OpenStack 16,9), tăng trên đĩa Loki **51,6 MB/h**, Prometheus 3,7 MB/h.
150 h × 2 = 15,5 GB; **retention 720 h chạy 24/7 ≈ 37 GB × 2 = 74 GB** — con số quyết định. Đĩa node Loki nay 97 GB (88 GB trống).

### 4.4 CRS/BOLA (3.3)

| Lượt | BOLA thành công | CRS hit trên path BOLA | `attack-*` trong cửa sổ BOLA | SQLi `attack-sqli` | `attack-xss` | `attack-lfi/rce` | tổng transaction SQLi | OPA deny (BOLA) |
|---|---|---|---|---|---|---|---|---|
| 1 | 3/3 | 0 | 0 | 1 | 1 | 1 | 3 | 0 (BOLA hợp lệ theo `service_acl` + RBAC) |
| 2 | 3/3 | 0 | 0 | 1 | 1 | 1 | 3 | 0 |
| 3 | 3/3 | 0 | 0 | 1 | 1 | 1 | 3 | 0 |

### 4.5 Alert (3.4)
**9/9 rule kiểm chứng sống** trên cụm 2026-10-04 (bảng chi tiết: `AUDIT-THUC-THI.md` §6). Thời gian kích hoạt → Firing: 13–43 s với 4 rule
dựa trên đếm deny (Brute Force 13, Lateral 18, Access Denied 25, BFLA 43), ≤ 5 s với Large Response / Privilege Escalation, 90 s với Mesh
Integrity. Hai rule mới (`Log Pipeline Silent`, `Health-Check Silent`) chưa kích hoạt thử. Lưu ý cho nhãn Giai đoạn C: bundle của BFLA mang
`attack_type=access_denied`.

### 4.6 MTTD (3.5)

| Kịch bản | n | MTTD (T0 bắt đầu tấn công → evidence bundle) | thời lượng tấn công | tấn công → deny đầu tiên trong Loki (hệ thống) | deny → bundle (cấu hình chi phối) | bundle → email (hệ thống) |
|---|---|---|---|---|---|---|
| Lateral Movement | 10 | **trung vị 19,26 s**, khoảng 10,38–50,90 s | 17,15 s | 2,15 s [1,89–2,51] | 17,06 s [8,22–48,39] | 0,01 s |
| Brute Force | 10 | **trung vị 80,68 s**, khoảng 42,37–82,72 s | 31,71 s | 1,98 s [1,83–3,21] | 78,69 s [39,16–80,68] | 0,01 s |

- **Tách phần:** phần do **hệ thống** (Envoy → OPA → decision log → Promtail → Loki, rồi incident-analyzer dựng bundle + gửi email) ≈ **2 s**
  ở cả hai kịch bản. Phần còn lại do **cấu hình**: chu kỳ eval 60 s của Grafana, ngưỡng tích luỹ của rule (Brute Force > 10 lỗi/5 phút),
  `group_wait` 5 s.
- **Hạn chế phương pháp:** bộ chạy bắt đầu mỗi lượt ngay khi rule về inactive — thời điểm bám nhịp eval — nên các lượt **khoá pha**: mọi bundle
  Lateral tạo ở giây :55, mọi bundle Brute Force ở giây :25. Với Brute Force, tấn công bắt đầu ~15 s trước một nhịp eval, ngưỡng chưa vượt ở nhịp
  đó → bắt ở nhịp sau (~80 s); lượt 1 (pha khác) 42 s. Trung vị Brute Force vì thế nghiêng về pha xấu; khoảng 42–83 s mới là phạm vi thực. Lượt
  sau nên chèn độ trễ ngẫu nhiên 0–60 s trước mỗi lượt.
- Không có cam kết định lượng MTTD trong đề cương; không trích như một hằng số — trích trung vị + khoảng + n và phần hệ thống ≈ 2 s.

### 4.7 Tái lập (3.6)
- Trước destroy: `terraform plan` không target AWS + OpenStack: **No changes** (`results/closeout/rebuild/tfplan-*-pre-destroy.txt`).
- Lần 1: destroy 4 m 58 s; deploy hỏng ở Terraform OpenStack sau 31 phút (VM kẹt BUILD — đồng hồ host AIO, mục 2.1) → `openstack-aio-preflight.sh`.
- Lần 2: destroy 2 m 11 s; hỏng ngay ở tiền kiểm mới (CLI snap 5.8 không tạo được VM không NIC) → dùng CLI kolla-venv.
- Lần 3: destroy 55 s; bước 1–10 xanh, bị Claude Code dừng giữa bước 11 vì máy thiếu RAM; người dùng chạy tiếp `--from-step 11` trên đúng các VM
  vừa tạo: **34 m 31 s, 0 FAIL**, Step 8b (stack quan sát + 1652 dòng log OpenStack/5 phút qua WireGuard) và Step 8c (mesh) OK, **1 WARN**: SAML
  bị bỏ qua vì `--from-step 11` không nạp `.env` — lỗi thứ ba, đã sửa (`.env` luôn được nạp) và áp lại SAML (cert Keycloak cũ 09-29 → mới).
- Sau deploy: plan OpenStack `No changes`; plan AWS chỉ trôi giá trị output (`public_ip` gateway sau khi gắn EIP), 0 thay đổi tài nguyên.
  Sau đó áp có chủ đích 3 thay đổi tại chỗ (EBS 30 → 100 GB, mục 2.3).

## 5. CÒN HỞ KHI VÀO GIAI ĐOẠN B — và cái nào có thể làm hỏng đợt thu

| Hở | Có làm hỏng đợt thu? | Biện pháp |
|---|---|---|
| Mất tài khoản/quyền AWS (nguyên nhân 09-30) | **CÓ** — mất cụm | thu chia khúc; giữ snapshot tfstate; dựng lại từ trống đã chứng minh (~40–60 phút) |
| RAM máy AIO (15 GB; 5 VM ≈ 6,6 GB) — 2 lần tiến trình bị dừng vì thiếu RAM trong vòng này | **CÓ** — bộ thu/bộ sinh tải bị giết | chạy bộ thu ngoài Claude Code (terminal riêng) hoặc đặt `CLAUDE_CODE_DISABLE_BG_SHELL_PRESSURE_REAP=1`; đóng ứng dụng nặng |
| Đồng hồ host AIO lệch sau khởi động (dual-boot) | **CÓ** nếu host khởi động lại giữa đợt | `openstack-aio-preflight.sh` trước khi dựng/khôi phục; tận gốc: `timedatectl set-local-rtc 0` + Windows dùng RTC UTC |
| Gián đoạn WAN > ~2,5 h (Promtail) / > ~2–4 h (SVID) | CÓ — khúc bị `gap`, có thể mất log | bộ thu đánh `gap`; khôi phục theo §10.3 |
| **Trạng thái cạn dần trong phiên dài** (mới): `stepup-demo` hết 100 credit sau 10 đơn → mọi đơn sau trả 400 | **CÓ — gán nhãn sai có hệ thống** (cùng họ H16): tỉ lệ 400 tăng theo thời gian phiên | bộ sinh tải phải nạp lại credit (coupon) hoặc chọn hành động không tiêu hao; theo dõi tỉ lệ non-200 theo giờ |
| Cert thiết bị TTL 7 ngày | có, nếu không gọi `crapi_preflight` mỗi ngày | bộ sinh tải gọi `crapi_preflight` đầu mỗi khúc |
| Retention Loki 720 h | **CÓ** nếu 150 h trải dài > 30 ngày lịch | xuất dữ liệu sau mỗi khúc, hoặc hoàn tất trước 30 ngày kể từ khúc đầu |
| Đuôi PDP do tải JWKS cross-cloud mỗi 300 s | không làm hỏng, nhưng là đặc trưng có chu kỳ trong dữ liệu độ trễ | ghi chú cho Giai đoạn C (không coi là bất thường) |
| L4 không phân đoạn nội ns (H3) | không | L7 đảm nhiệm; phát hiện có tên |
| Độ trễ đầu-cuối chưa đo | không | đo trong B |

## 6. ĐỒNG BỘ TÀI LIỆU
`HE-THONG-CHI-TIET.md` (§4.1 TTL, §10.2 hai sự cố mới, §11 trạng thái), `HAN-CHE-VA-HUONG-PHAT-TRIEN.md` (H1, H3, H5, H7, H8, H10, H11 cập
nhật; H17 TTL, H18 BOLA mới), `PHAT-HIEN-PHAN-DOAN-L4.md` (mới), `AUDIT-THUC-THI.md` §6 (viết lại). Các báo cáo theo vòng cũ (`BAOCAO-*`, `KEHOACH-THAYDOI-HETHONG.md`, `KET-QUA-CRAPI.md`,
`KIEM-KE-HOP.md`, `docs/friction-survey.md`) đã bị xoá khỏi repo theo yêu cầu (bản đã commit còn trong lịch sử git).

## 7. MÃ ĐÃ SỬA TRONG VÒNG NÀY (đều nằm trong repo, dựng lại được)
- `spire/server/*.conf`, `scripts/ensure-spire-entries.sh` — TTL 4 h + hội tụ TTL entry có sẵn.
- `scripts/deploy-crapi.sh`, `scripts/deploy-app.sh` — H8 (`ZTLAB_DEFER_ACCEPTANCE`, `--verify-only`, Step 8c).
- `scripts/openstack-aio-preflight.sh` (mới), `scripts/deploy-all.sh` — tiền kiểm AIO; `.env` luôn nạp.
- `terraform/aws/main.tf` (EBS 100 GB), `ansible/playbooks/k3s.yml` (growfs), `k8s/plg-stack/loki.yaml` (ghi chú dung lượng).
- `plg-stack/grafana/dashboards/*.json` — H1.
- Công cụ: `tests/collect_chunked.py` + `tests/collect_chunked_acceptance.sh` (mới), `tests/log_volume_sample.sh` + `log_volume_analyze.py`
  (mới), `tests/opa_pdp_latency.py` (mới), `tests/alerts_verify_all.sh` (mới), `tests/perf_overhead.py` (JWT theo lô),
  `tests/perf_opa_decision_log_diag.sh` (xác nhận khôi phục sống), `tests/crapi_bola.sh` (BOLA thật), `tests/benign_traffic_403.sh` (mẫu số),
  `tests/crapi_cert_scenarios.sh` + `crapi_cert_revocation.sh` (T1), `tests/log_pipeline_outage.sh` (IP/key từ inventory), `RESULTS_ROUND`.
