# BÁO CÁO CỔNG 2 GIỜ — Giai đoạn B, Bước 1

> Trạng thái: **KHUNG + phần kiểm được trong repo đã điền.** Các số CHỈ đo được
> trên cụm sống (đánh dấu `⟨ĐO KHI CHẠY CỔNG⟩`) điền sau khi chạy runbook §B.
> Cổng chạy NGOÀI Claude Code (RAM 15GB, 5 VM — §1.5 prompt).

Ngày lập khung: 2026-10-07. Mã liên quan: nhánh `feat/root-cause-remediation`.

---

## 1. KẾT LUẬN: `⟨MỞ CỔNG / KHÔNG MỞ⟩`

Điền sau khi chạy §B. Quy tắc quyết định (từ `tests/phaseb_gate.py`):
- `GO` → MỞ CỔNG.
- `NO_TOO_EASY` → N2 chưa đủ giống A, thiết kế lại N2, chạy lại cổng.
- `NO_TOO_HARD` → đặc trưng chưa đủ hoặc 2 giờ quá ít mẫu A.
- `NO_RULE_TIE` → mô hình không hơn `deny_count>0`: vấn đề thiết kế dữ liệu.
- `INSUFFICIENT_DATA` → tăng số lượt A / giảm cửa sổ, chạy lại.

**Dù MỞ, KHÔNG bắt đầu đợt 150 giờ trong bước này — báo để người dùng quyết (§6 prompt).**

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

`⟨điền từ kết quả cổng⟩`. Ứng viên đã biết:
- ~~Scenario honor PACE~~ **ĐÃ XONG (§B1)**: `crapi_*.sh` THỰC THI `PACE`/
  `DURATION_MIN`/`VICTIMS`/`SOURCE`; nghiệm thu `phaseb_pace_accept.py` phải PASS
  mỗi họ trước cổng (bằng chứng trong `results/phaseb/pace/`).
- Rotate nhiều user mua (OTP) nếu coupon top-up không đủ giữ 0×400.
- Bất cứ feature nào `features_not_computable` ở §3.
- `large_response` holdout (accumulate) KHÔNG làm rule ngưỡng-đơn fire (đúng thiết
  kế — phát hiện cộng dồn là việc của lớp ML); đừng coi đó là lỗi.

---

# PHỤ LỤC B — RUNBOOK CHẠY CỔNG 2 GIỜ

Chạy ở **terminal riêng NGOÀI Claude Code**. Cần port-forward Loki :13100,
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
NEED=15 bash tests/phaseb_seed_verify.sh || { echo "!! BLOCKER 1b trượt — dừng"; }

# 1c) N1 gọi path BOLA hợp lệ ≥20 trong 30' N1 THUẦN (BLOCKER):
sleep 1800   # 30' N1 một mình
curl -s -G "http://localhost:13100/loki/api/v1/query" \
  --data-urlencode 'query=sum(count_over_time({job="envoy-access"} |~ `vehicle/[^/]+/location` [30m]))' \
  --data-urlencode "time=$(date +%s)000000000" | python3 -c 'import json,sys
r=json.load(sys.stdin)["data"]["result"]; n=int(float(r[0]["value"][1])) if r else 0
print(f"N1 gọi /vehicle/{{id}}/location trong 30 phút: {n} (cần ≥20)"); sys.exit(0 if n>=20 else 1)' \
  || echo "!! BLOCKER 1c trượt — để N1 chạy thêm; nếu vẫn 0, kiểm victim có xe (1b)"
# CẢ 1b VÀ 1c PASS mới sang PHA 1.

# ══ PHA 1 — CỬA SỔ CỔNG (T0 = BÂY GIỜ; T1 = T0+7200) ═════════════════════════
T0=$(date +%s)
DURATION=10800 bash tests/crapi_noise_n2.sh &           # N2 3h (N1 đã chạy từ pha 0)
sleep 60   # N2 ấm lên; nền (N1+N2) đã sống → A xen vào

# §1.1 evidence: đo PDP latency TRONG cửa sổ (traffic sẵn có) — p99 + hết lưỡng đỉnh.
python3 tests/opa_pdp_latency.py &   # chạy nền trong cửa sổ, KHÔNG riêng lẻ
PDP_PID=$!

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
kill "$PDP_PID" "$N1_PID" 2>/dev/null; pkill -f crapi_noise_n2 2>/dev/null || true

# PIPELINE CỔNG: export → gán nhãn → feature → mô hình → kiểm tra (§5, §B1a–e):
mkdir -p results/phaseb/gate
python3 tests/phaseb_gate.py export --loki http://localhost:13100 --start "$T0" --end "$T1" --out results/phaseb/gate
python3 tests/phaseb_gate.py run --logs results/phaseb/gate --runs tests/runs.jsonl --window 60 --step 60 --out results/phaseb/gate
cat results/phaseb/gate/gate_result.json
```

Điền §1–§6 báo cáo từ `gate_result.json`, `results/phaseb/n1/*.summary.txt`,
`results/phaseb/pace/*.json`, `results/phaseb/seed/seed-verify.json`, `tests/runs.jsonl`,
và output `opa_pdp_latency.py` (§1.1 p99 + hết lưỡng đỉnh).
