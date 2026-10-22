# ml/ — Giai đoạn C: phát hiện BOLA theo đề cương KLTN

Nguồn sự thật cho tiêu chí: **đề cương chi tiết** (mục 6 Bước 2–4, mục 7), không
phải `docs/FEATURES-GIAIDOAN-C.md` (tài liệu đó chốt recall theo lượt, đề cương
dùng recall theo cửa sổ 5 phút tại FPR 1%).

| File | Việc |
|---|---|
| `features_v2.py` | Log thô Giai đoạn B → bảng đặc trưng: cửa sổ 300 s trượt 60 s, nhóm A/B theo đề cương, nhãn theo lượt |
| `evaluate.py` | Baseline / A / A+B (XGBoost), chia theo khúc có khúc đệm, PR-AUC, recall@FPR 1%, CI bootstrap theo lượt, đối chứng âm, biến thể chưa thấy, 3 phạm vi âm |
| `run_collector.sh` | Chạy cả quy trình trên máy thu |

## Khác bảng đặc trưng Giai đoạn B ở đâu

| Điểm | Bảng B (`phaseb_gate.py featurize`) | v2 |
|---|---|---|
| Cửa sổ | tumbling 15/30/60/300/600 s | 300 s trượt 60 s (đề cương) |
| Mã đối tượng | `_target_ids`: chỉ số nguyên, nên **= 0 trên mọi cửa sổ BOLA** (vehicle ID là UUID) | UUID + `/<tài nguyên>/<số>` + query `*_id` |
| Gán user | cookie phiên BFF (C1) | cookie **hoặc JWT** (Bearer / X-Access-Token), nên BOLA burst có nhãn |
| Đặc trưng "mới" | không có | `n_obj_new`, `frac_obj_new` (A); `n_pair_new`, `n_xcloud_pair_new` (B), tính nhân quả |
| Cross-cloud | không có | `xcloud_ratio` từ SPIFFE `aws/` và `openstack/` |
| posture / step-up | đọc `device_posture` ở cấp cao nhất của decision log, nên luôn = 0 | header `x-device-posture`, `acr` trong JWT |
| Khớp entity khi gán nhãn | khớp chuỗi con hai chiều | khớp chính xác |

`features_v2.py` import `tests/phaseb_gate.py` để dùng lại phần đọc luồng,
sắp thứ tự (`_resort_bounded`), `load_runs`, `is_attack_event`. Không sửa file đó.

## Chạy trên máy thu

```bash
git fetch origin && git merge origin/feat/phase-c-ml   # chỉ thêm file mới, không đụng file đang có
bash ml/run_collector.sh          # selftest → inspect → build (lâu) → evaluate
```

Bước `inspect` in khoá trường thật của từng luồng và tỉ lệ sự kiện OPA gán
được user qua cookie / JWT / không gán được. **Xem kết quả này trước khi để
`build` chạy hết 9 khúc**: nếu tỉ lệ JWT = 0% trong khi BOLA burst dùng Bearer,
nghĩa là header token không có trong decision log (cần kiểm cấu hình mask của OPA).

Kết quả gửi lại: `results/c4/inspect.txt`, `results/c4/features_v2/features_v2_meta.json`,
`results/c4/eval/eval_report.md`, `results/c4/eval/eval_result.json`.

## Đánh giá bảng Giai đoạn B đã export (không cần log thô)

```bash
python3 ml/evaluate.py --features "c2-export/*_w300.csv.gz" --out /tmp/eval_b
```

Kết quả trên bảng cũ (22/10): phạm vi `all`/`user` cho recall@FPR1% khoảng 0,85–0,96,
**nhưng là đường tắt**. Mọi cửa sổ tấn công và nhiễu N2 đều thuộc `testuser01`,
user này không có cửa sổ benign nào, nên mô hình tách loại entity chứ không tách
hành vi. Phạm vi `same-user` ở cửa sổ 300 s chỉ có 65 cửa sổ âm trong tập test,
không đủ để đo FPR 1%. Đây là lý do cần sửa kịch bản thu (tài khoản tấn công
riêng, N2 rải trên nhiều user) trước khi thu tiếp.

## Phạm vi âm khi đọc kết quả

- `all`: mọi entity, gồm cả service/IP pod. Dễ đẹp giả.
- `user`: chỉ người dùng.
- `same-user`: chỉ những entity từng là kẻ tấn công. **Đây là phép kiểm shortcut
  mà đề cương yêu cầu.** Chỉ kết luận đạt khi phạm vi này cũng đạt.
