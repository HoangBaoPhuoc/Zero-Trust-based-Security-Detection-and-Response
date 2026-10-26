# crAPI API Map (Bước 1.3)

> Bắt bằng cách gọi trực tiếp các API thật của crAPI (tương đương bắt gói tin qua DevTools — cùng
> endpoint, cùng request/response, chỉ khác công cụ capture) trên instance chạy tại `localhost:8888`
> ngày 2026-09-12. Đối chiếu path với source code thật trong `services/*/**` của repo crAPI
> (`VehicleController.java`, `merchant/urls.py` + `views.py`, `mechanic/urls.py` + `views.py`,
> `community/api/router/routes.go`) — không đoán path.
> Tài khoản test: `victim@test.local` (dùng để thực hiện cả 3 luồng) / `attacker@test.local` (dự phòng
> cho kịch bản BOLA ở GD2, chưa dùng ở bước này).

## Luồng 1 — Thêm xe (workshop / Add a Vehicle)

| # | Method | Path | Request body | Response (rút gọn) | Ghi chú |
|---|--------|------|---------------|---------------------|---------|
| 1 | GET | `/identity/api/v2/vehicle/vehicles` | — (Bearer token) | `[]` nếu user chưa "add vehicle" lần nào; sau khi add: `[{"id":7,"uuid":"036e3f33-...-b9","pincode":"9236","vin":"CL3G7E87AV3K8EKEN","year":2026,"status":"INACTIVE","model":{"model":"RS7","vehiclecompany":{"name":"Audi"}},"vehicleLocation":{"latitude":"37.746880","longitude":"-84.301460"}}]` | **Đính chính** (khác ghi chú lần trước): signup chỉ tạo 1 bản ghi xe ngẫu nhiên với `owner=null` trong DB + gửi vin/pincode qua email — CHƯA hiện trong `/vehicle/vehicles` của user. Chỉ sau khi user tự gọi `add_vehicle` với đúng vin+pincode thì backend mới set `owner=user`, lúc đó mới hiện ra (đã verify bằng cách tạo 5 tài khoản `sv2_victim{1..5}@test.local` mới — vehicles rỗng cho tới khi add_vehicle). |
| 2 | POST | `/identity/api/v2/vehicle/add_vehicle` | `{"vin":"C5JWPAEKWS8045YY3","pincode":"9436"}` | `{"message":"...","status":200}` lần đầu (set owner) → `{"message":"Sorry, This Vehicle is already added.","status":403}` nếu gọi lại | Endpoint "activate" xe bằng vin+pincode lấy từ email Mailhog (`Content.Body` là quoted-printable, cần decode bằng `quopri` trước khi regex trích VIN/Pincode). |
| 3 | POST | `/identity/api/v2/vehicle/resend_email` | — (Bearer token) | `CRAPIResponse` message | Gửi lại email chứa vin+pincode nếu người dùng làm mất. |
| 4 | GET | `/identity/api/v2/vehicle/{uuid}/location` | — (Bearer token) | `{"carId":"036e3f33-...-b9","vehicleLocation":{"latitude":"37.746880","longitude":"-84.301460"},"fullName":"victim","email":"victim@test.local"}` | **Đây là endpoint BOLA mục tiêu** (tên hàm trong source thật sự là `getLocationBOLA`) — không kiểm tra `{uuid}` có thuộc về user gọi hay không. `object_id` = uuid xe trong path. |

## Luồng 2 — Gửi báo cáo cho thợ (mechanic report)

| # | Method | Path | Request body | Response (rút gọn) | Ghi chú |
|---|--------|------|---------------|---------------------|---------|
| 1 | GET | `/workshop/api/mechanic/` | — (Bearer token) | `{"mechanics":[{"id":1,"mechanic_code":"TRAC_JHN","user":{"email":"jhon@example.com"}},{"id":2,"mechanic_code":"TRAC_JME", ...}]}` | Danh sách thợ để chọn khi "Contact Mechanic". |
| 2 | POST | `/workshop/api/merchant/contact_mechanic` | `{"mechanic_code":"TRAC_JHN","problem_details":"Xe keu la khi phanh gap","vin":"CL3G7E87AV3K8EKEN","mechanic_api":"https://<workshop-service>/workshop/api/mechanic/receive_report","repeat_request_if_failed":false,"number_of_repeats":1}` | `{"response_from_mechanic_api":{"id":6,"sent":true,"report_link":"http://localhost:8888/workshop/api/mechanic/mechanic_report?report_id=6"},"status":200}` | **SSRF theo thiết kế**: backend `workshop` tự làm proxy, gọi `GET` tới URL client cung cấp trong `mechanic_api` — client kiểm soát được đích gọi. `report_link` là endpoint ẩn (hidden API) chứa `report_id`. |
| 3 | GET | `/workshop/api/mechanic/mechanic_report?report_id=6` | — (Bearer token) | `{"id":6,"mechanic":{"mechanic_code":"TRAC_JHN"},"vehicle":{"vin":"CL3G7E87AV3K8EKEN","owner":{"email":"victim@test.local"}},"problem_details":"Xe keu la khi phanh gap","status":"pending","comments":[]}` | **`object_id` = `report_id`** (query param, không phải path segment — cần lưu ý cho Bước 1.4/1.7 khi trích `object_id` từ request). Đổi `report_id` sang số khác → BOLA (Challenge 2). |

## Luồng 3 — Đăng bài (community)

| # | Method | Path | Request body | Response (rút gọn) | Ghi chú |
|---|--------|------|---------------|---------------------|---------|
| 1 | POST | `/community/api/v2/community/posts` | `{"title":"Kinh nghiem bao duong Audi RS7","content":"Chia se video kiem tra phanh xe minh vua lam."}` | `{"id":"exn5MFYDPjvvRUjCvzKvpc","title":"...","content":"...","author":{"nickname":"victim","email":"victim@test.local","vehicleid":"036e3f33-...-b9"},"comments":[],"authorid":9}` | `author.vehicleid` được server tự gắn từ JWT (không phải field client gửi lên) — chính field này bị lộ và bị lợi dụng ở Challenge 1 (BOLA vehicle). |
| 2 | GET | `/community/api/v2/community/posts/recent` | — (Bearer token) | `{"posts":[{"id":"exn5MFYDPjvvRUjCvzKvpc",...,"author":{...,"vehicleid":"036e3f33-...-b9"}}, ...],"next_offset":null,"total":4}` | Trả về **`vehicleid` của MỌI tác giả bài viết**, kể cả người khác — đây chính là kênh để attacker lấy `vehicle_id` nạn nhân rồi ghép với Luồng 1 bước 4 (`/vehicle/{uuid}/location`) để hoàn thành Challenge 1. |

## Ghi chú chung
- `object_id` trích từ path: `vehicle uuid` (Luồng 1.4), còn `report_id` ở Luồng 2.3 lại nằm ở **query string**, không phải path — cần chuẩn hoá cách trích `object_id` ở Bước 1.4/1.7 để bắt được cả 2 dạng.
- Không endpoint nào trong 3 luồng trên trả path dạng template (`/vehicle/{id}`) — Envoy access log sẽ log path thật có ID cụ thể, không cần bật thêm header gì đặc biệt ngoài field đã đề xuất ở Bước 1.4.
- `contact_mechanic` (Luồng 2.2) là điểm SSRF — đáng chú ý thêm cho phần "công trình liên quan" / đặc trưng nhóm B sau này (caller gọi tới identity nội bộ theo tham số client kiểm soát).
