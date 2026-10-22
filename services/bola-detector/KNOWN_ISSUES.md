# bola-detector — trạng thái và lỗi đã biết

Khung ML do SV2 viết ở GĐ1–GĐ2 (09/2026), chạy dry-run trên log giả lập (`dev/`).
Khôi phục vào repo ngày 22/10/2026; trước đó thư mục chưa từng được commit.

Phần huấn luyện/đánh giá đã được viết lại thành `ml/` (đọc trực tiếp log
Giai đoạn B). Thư mục này giữ lại làm tham chiếu và để dùng lại `attacks/`,
`traffic/` khi thiết kế đợt thu mới.

| File | Lỗi | Xử lý trong `ml/` |
|---|---|---|
| `labeling/label_windows.py` | Gán nhãn chỉ theo khoảng thời gian, không so entity: mọi cửa sổ của mọi entity giao với lượt tấn công đều thành dương | `ml/features_v2.py::label_window` khớp entity chính xác + chữ ký `is_attack_event` |
| `training/evaluate.py::negative_control` | Chấm điểm trên chính tập train đã xáo nhãn, nên PR-AUC sẽ cao hơn base rate | `ml/evaluate.py` chấm trên tập test |
| `features/windowing.py`, `build_known_pairs` | O(n²) theo số sự kiện | `ml/features_v2.py` trượt cửa sổ dạng streaming |
| `training/split.py` | Biến `sess_bounds` không được dùng; chưa giữ nguyên session | chia theo khúc + khúc đệm |
| `features/feature_groups.py` | Đặc trưng đối tượng nằm ở nhóm B; thiếu "đối tượng chưa từng thuộc user" và nhóm cross-cloud (đề cương bản hiện tại) | `FEATURES_A` / `FEATURES_B` trong `ml/features_v2.py` |
| `attacks/*.py`, `traffic/*.py` | Gọi thẳng crAPI `localhost:8888` (không qua BFF/Keycloak/cert thiết bị); gắn header `X-Attack-Run-Id` (trái nguyên tắc không tiêm marker của Giai đoạn B) | Chưa chuyển — cần viết lại theo `tests/lib/crapi_common.sh` trước khi dùng cho đợt thu |
