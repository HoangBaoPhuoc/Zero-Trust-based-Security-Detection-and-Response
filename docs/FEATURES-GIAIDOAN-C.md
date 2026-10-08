# FEATURES-GIAIDOAN-C — danh sách đặc trưng CHỐT trước đợt thu

Giai đoạn B §5.1. Chốt **trước** khi thu để cổng 2 giờ kiểm được: (a) mọi đặc
trưng tính được từ log thật; (b) rà rò rỉ nhãn. Điều chỉnh được ở Giai đoạn C
nhưng mọi thay đổi phải chốt lại ở đây trước khi thu tiếp.

Đơn vị quan sát: **một phiên** (`sid`) — hoặc một **cửa sổ trượt** cho thực thể
(entity = user/principal/đối tượng). Nhãn gán ở Giai đoạn C từ `runs.jsonl` theo
`(entity, [t_start, t_end])`, **không** tiêm marker (A5.2).

## Nguồn log và trường (đã xác nhận trong mã, 2026-10-07)

| Stream (Loki) | Nhãn | Trường trong BODY (`| json ...`) |
|---|---|---|
| `envoy-access` | method, path, response_code, source_ip, direction | timestamp, response_time (`%DURATION%` ms), **upstream_service_time** (§1.3, ms), upstream, bytes_sent, trace_id, svid, upstream_cluster, response_flags, transport_failure |
| `bff-audit` | job, namespace, app, cloud | event, ts, **sid** (§1.4), **request_id** (§1.4 = X-Request-Id), username, email, roles, acr, path, reason/error, status |
| OPA decision log (`decision_logs.console`) | — | decision (bool), action (method), resource (path), svid (= source_principal), destination_principal, device_posture, device_trust, step_up (acr), decision_id |
| `posture-agent` | job, cloud | event=posture_check, workload, pod, image, compliant, reasons |
| crapi identity (login) | — | `LOGIN_ERROR` (nguồn brute-force / password-spray) |

### Khoá ghép (join)
- **Theo request:** `envoy-access.trace_id` == `bff-audit.request_id` (cùng
  `X-Request-Id` Envoy sinh ở ingress). OPA có `decision_id` riêng — ghép OPA↔
  envoy theo `(timestamp±, source_principal, method, path)`.
- **Theo phiên:** gom `bff-audit` theo `sid`; mỗi dòng có cả `sid` và
  `request_id` → bắc cầu sang `envoy-access` qua `request_id`.
- **Gán nhãn offline:** `runs.jsonl` `(entity, [t_start, t_end])` → lọc dòng log
  theo entity + cửa sổ thời gian (T1 làm tròn LÊN +1s — H18).

> Trước §1.4, `bff-audit` KHÔNG in `sid`/`request_id` → đặc trưng theo phiên và
> ghép liên-stream **không tính được**. Đây chính là loại thiếu trường mà cổng
> 2 giờ phải bắt ở giờ thứ 2, không phải giờ thứ 150. Đã sửa trong mã; cổng phải
> xác nhận join chạy thật trên dữ liệu sống.

## Bảng đặc trưng (chốt)

Cột **Tính được** = cổng 5.4(a) phải xác nhận trên log thật. Cột **Rủi ro rò rỉ**
= ứng viên cho rà soát 5.4(b) (loại nếu giá trị chỉ xuất hiện ở một lớp VÌ CÁCH
SINH DỮ LIỆU chứ không vì bản chất tấn công).

| # | Nhóm | Đặc trưng | Nguồn | Tính được | Rủi ro rò rỉ |
|---|---|---|---|---|---|
| F1 | đếm deny | `deny_count` trong cửa sổ 1/5/10 phút | OPA `decision=false` ∪ envoy `response_code∈{401,403}` | ✅ | — (đối chứng với luật `deny_count>0`) |
| F2 | đếm deny | tỉ lệ deny / tổng request trong cửa sổ | như F1 | ✅ | — |
| F3 | bề rộng | #`destination_principal` distinct / cửa sổ | OPA decision | ✅ | thấp |
| F4 | bề rộng | #`request_path` distinct (chuẩn hoá tham số) / cửa sổ | envoy path / OPA resource | ✅ | **path chỉ kịch bản tấn công gọi** → loại path đó |
| F5 | bề rộng | #thực thể đích distinct (vehicleId/userId/orderId từ path) | parse path | ✅ (cần parser param) | **id chỉ script tấn công chạm** → loại |
| F6 | trình tự | thứ tự loại hành động (n-gram method+resource-class) | envoy/OPA theo `sid` | ✅ (cần sid) | trung bình |
| F7 | trình tự | tỉ lệ đọc/ghi (GET:HEAD vs POST/PUT/PATCH/DELETE) | envoy method theo `sid` | ✅ | thấp |
| F8 | nhịp độ | khoảng cách trung bình giữa request | envoy timestamp theo `sid`/entity | ✅ | **nền đều tăm tắp = giả** → N1 phải nhịp ngẫu nhiên (§2) |
| F9 | nhịp độ | phương sai khoảng cách | như F8 | ✅ | như F8 |
| F10 | mã HTTP | phân bố response_code phía server | envoy `response_code` | ✅ | — |
| F11 | mã HTTP | mã phía client (bff trả) + lý do deny | bff-audit `event`/`reason` | ✅ | **event name là đường tắt** nếu N2 có chữ ký event cố định (§3) → giám sát |
| F12 | độ trễ | `upstream_service_time` (p50/p95/max cửa sổ) | envoy §1.3 | ✅ (sau §1.3) | **JWKS 300s skew** đã bỏ (§1.1) — nếu còn lưỡng đỉnh là lỗi khác |
| F13 | độ trễ | `response_time` tổng (so với F12 để thấy hàng đợi) | envoy | ✅ | — |
| F14 | phiên | độ dài phiên (t cuối − t đầu của `sid`) | bff-audit `sid`/`ts` | ✅ (cần sid) | **TTL 300s/4h** — phiên dài là hồi quy sống H16/H17, không phải nhãn |
| F15 | phiên | #hành động trong phiên | envoy theo `sid` | ✅ | — |
| F16 | phiên | có/không step-up (acr=high xuất hiện) | bff-audit `acr`/`step_up` | ✅ | **step_up_required luôn→login-lại** = đường tắt N2 (§3.1) → đa dạng hoá |
| F17 | tư thế | posture/device_trust của phiên | OPA `device_posture`/`device_trust`, bff event | ✅ | `posture_degraded` (N2.3) phải đa dạng, không 1 chữ ký |
| F18 | khối lượng | `bytes_sent` (max, tổng cửa sổ) | envoy | ✅ | large-response/exfil: ngưỡng 1MiB là ĐỊNH NGHĨA tấn công, không phải rò rỉ |

## Ứng viên rò rỉ phải rà ở cổng 5.4(b)
1. **Path/endpoint chỉ tấn công gọi** (F4) — ví dụ path privesc/admin không
   user thật nào chạm trong N1/N2.
2. **Thực thể đích chỉ script chạm** (F5) — vehicleId/orderId sinh riêng cho
   kịch bản tấn công.
3. **Username chỉ dùng cho tấn công** — tài khoản kẻ tấn công; brute-force phải
   nhắm user THẬT có trong N1.
4. **Chữ ký event cố định của N2** (F11/F16) — nếu `session_expired` luôn đúng
   1×401→login, mô hình học chữ ký đó → N2 phải tham số hoá (số lần, giãn cách,
   có/không khôi phục).
5. **Marker/UA của script** — KHÔNG được có (A5.2 gán nhãn offline). Rà
   `User-Agent`, header lạ, `source_ip` cố định của máy chạy campaign.
6. **Nhịp đều** (F8/F9) — nền N1 đều tăm tắp là đặc trưng giả; §2 bắt buộc nhịp
   ngẫu nhiên.

## ĐƠN VỊ ĐO — CHỐT (§B1d, không thương lượng lại)

Trộn đơn vị đo là nguồn kết luận sai. Chốt:

- **RECALL tính THEO LƯỢT TẤN CÔNG.** Một lượt được coi là PHÁT HIỆN nếu mô hình
  gắn cờ **≥1 cửa sổ thuộc lượt đó**. Đây là đơn vị cho **cả** tiêu chí đề cương
  **≥0,80** (tổng) **và ≥0,70 trên biến thể HOLDOUT**. `phaseb_gate.py` in
  `recall_by_run` {all, train, holdout}.
- **FPR tính THEO CỬA SỔ** trên lưu lượng LÀNH TÍNH (N1 + N2). `fpr_by_window`.
- **Window-recall là SỐ PHỤ** (`window_recall_secondary`) — đại lượng KHÁC, báo
  kèm để tham khảo, KHÔNG dùng cho tiêu chí.

### Gán nhãn cửa sổ (§B1d — theo REQUEST THẬT, không theo khoảng thời gian)
Một cửa sổ chỉ mang nhãn `attack` khi nó CHỨA ≥1 request **thuộc chính lượt đó**
(chữ ký hành vi của kịch bản: BOLA khớp `vehicle/{id}/location` với id ∈
`victims_used`; họ dựa-deny khớp deny; …). Cửa sổ nằm trong `[t_start,t_end]`
nhưng KHÔNG chứa request nào của lượt → nhãn riêng **`attack_idle`**, **LOẠI khỏi
cả train lẫn test** (không benign vì đang có tấn công; không attack vì không có
gì để thấy). Báo cáo `attack_idle_by_variant` + `attack_idle_by_group`.

> Vì sao: slow_drip (≈1 request/90s) rải 30 phút → phần lớn cửa sổ 1 phút trống
> request tấn công. Nếu gán attack theo KHOẢNG THỜI GIAN, các cửa sổ trống đó mang
> nhãn sai CHỈ ở nhóm holdout → recall holdout tụt vì lý do KHÔNG liên quan tổng
> quát hoá, kết luận 70% sai theo hướng bi quan. Nếu `attack_idle` holdout > 50%
> → `phaseb_gate.py` cảnh báo slow_drip quá thưa so với cửa sổ nhỏ nhất.

### Độ trễ phát hiện (§B1e — bắt buộc báo kèm recall)
Recall theo lượt cho một lượt 30 phút có tới ~20 cơ hội gắn cờ → cao gần như theo
CẤU TRÚC. Không có độ trễ kèm theo, recall không nói được phát hiện SỚM hay MUỘN.
`phaseb_gate.py` in, tách train/holdout và theo họ:
- **`first_flag_window_index`** — lượt bị gắn cờ ở cửa sổ thứ mấy CỦA NÓ (1 = cửa
  sổ đầu tiên có request).
- **`first_flag_delay_sec`** — giây từ `t_start` tới đầu cửa sổ gắn cờ đầu tiên
  (clamp 0 nếu cửa sổ căn lưới mở trước `t_start`).
- Báo **trung vị + khoảng** mỗi nhóm (`detection_latency.by_group`) và mỗi họ
  (`.by_scenario`).

### Recall theo ĐỘ RỘNG CỬA SỔ (§B1e)
`recall_by_window_width` in recall theo lượt (train/holdout) ở **1 / 5 / 10 phút**
để xác định độ rộng phù hợp với từng nhịp. **LƯU Ý QUAN TRỌNG:** cảnh báo
`attack_idle holdout > 50%` KHÔNG phải tín hiệu làm slow_drip DÀY lên (làm vậy phá
trục holdout) — nó là tín hiệu cửa sổ NHỎ NHẤT không hợp nhịp thưa; xử lý bằng
CHỌN ĐỘ RỘNG CỬA SỔ, không bằng sửa thiết kế tấn công.

## Đối chứng bắt buộc (5.4c)
Luật đơn giản **`deny_count > 0`** (F1). Mô hình vứt đi phải **tốt hơn** luật này
trên tập 2 giờ; nếu không → vấn đề THIẾT KẾ DỮ LIỆU (N2 chưa đủ giống A), không
phải vấn đề mô hình.
