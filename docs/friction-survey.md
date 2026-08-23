# Dev/Ops Friction Survey — Zero Trust Operational Cost

Bộ câu hỏi ngắn đo cảm nhận chi phí vận hành thật (không phải số liệu latency/CPU đã có trong SYSTEM_EVALUATION.md — đây là góc nhìn con người: người vận hành/phát triển tốn bao nhiêu công sức để làm việc *với* lớp Zero Trust này). Chạy `python3 tests/collect_friction_survey.py` để trả lời, hoặc điền tay theo mẫu dưới.

**Lưu ý quan trọng:** đây là **công cụ thu thập**, không phải kết quả — chỉ có giá trị khi có người thật (đã từng vận hành/phát triển trên ZTLab) trả lời. Không tự tạo số liệu giả cho mục này.

## Câu hỏi (thang 1–5, 1 = rất khó/tốn nhiều công, 5 = rất dễ/gần như không tốn công)

1. **Debug khi bị OPA/Istio chặn nhầm (403 không rõ lý do)** — mất bao lâu để tìm ra request bị chặn ở tầng nào (OPA policy? SVID sai? JWT hết hạn? NetworkPolicy?) và vì sao?
2. **Thêm 1 service mới vào hệ thống** — từ lúc có code tới lúc service đó có SVID, Istio sidecar (istio-proxy), OPA policy, NetworkPolicy đúng, chạy được trong luồng thật — so với thêm 1 service vào hệ thống không có các lớp này.
3. **Hiểu lỗi 403 lần đầu gặp** (không phải sau khi đã quen hệ thống) — độ khó đọc log/decision_id để suy ra nguyên nhân gốc.
4. **Redeploy/destroy toàn bộ hạ tầng** — độ tin cậy của `scripts/deploy-all.sh`/`destroy-all.sh` qua nhiều lần chạy (đã có log thật về việc phải vá 4+ bug mới chạy trơn tru — xem SYSTEM_EVALUATION.md Mục 0).
5. **Thêm 1 policy Rego mới hoặc sửa policy có sẵn** — độ khó test/verify policy không phá vỡ traffic hiện có trước khi apply lên cluster thật.
6. **Tổng thể** — nếu phải chọn lại, có chấp nhận đánh đổi (độ phức tạp vận hành) để lấy (khả năng phát hiện/audit trail) như SYSTEM_EVALUATION.md đã đo không?

## Mẫu điền tay (nếu không chạy script)

```
Người trả lời: _______________  Ngày: __________
Vai trò trong dự án (dev/ops/cả 2): __________

Q1 (debug 403): ___/5   — ghi chú:
Q2 (thêm service mới): ___/5   — ghi chú:
Q3 (hiểu lỗi 403 lần đầu): ___/5   — ghi chú:
Q4 (redeploy/destroy): ___/5   — ghi chú:
Q5 (sửa Rego policy): ___/5   — ghi chú:
Q6 (đánh đổi tổng thể, có đáng không): ___/5   — ghi chú:
```
