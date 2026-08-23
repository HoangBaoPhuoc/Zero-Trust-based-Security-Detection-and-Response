# ZTLab — ML/DL Dataset Kit

Bộ công cụ này sinh dữ liệu **thật** (không phải log giả lập tĩnh) từ hệ thống demo
đang chạy, có nhãn (label) sẵn, để nhóm ML/DL dùng train/test mô hình phân loại
tấn công — mô hình đó sẽ được cắm vào chỗ trống hiện tại trong `services/ai-analyzer`
(`heuristic_analyze` / `openai_analyze` / `gemini_analyze` — phần này nhóm ML tự làm,
không đụng tới trong bộ kit này).

Không sửa bất kỳ logic phân loại nào trong `ai-analyzer`. Phạm vi ở đây chỉ là:
**bằng chứng dữ liệu thật** + **schema biến/feature** + **script sinh dataset lặp lại được**.

## 1. Vì sao dữ liệu "thật" chứ không phải log giả

Hệ thống có 3 lớp log độc lập, tất cả join được với nhau qua `trace_id`:

| Lớp | Nguồn (Loki `job=`) | Sinh ra bởi |
|---|---|---|
| Biên mạng (L4/L7 access log) | `envoy-access` (tên nhãn Loki giữ nguyên từ trước migration; nội dung là log của Istio sidecar) | Istio sidecar (istio-proxy) mỗi service |
| Quyết định uỷ quyền (authorization decision) | `opa-decisions` | OPA `ext_authz` (mỗi lần istio-proxy hỏi "cho qua không") |
| Ứng dụng (business logic) | `kubernetes-pods` (lọc theo `app=`) | `shared/logging.py::ZTLabLogger` trong từng service Python |

Một request thật (ví dụ 1 lệnh chuyển tiền) để lại dấu vết ở **cả 3 lớp cùng lúc**,
cùng một `trace_id` — đây chính là khóa join. `security-scorer` là lớp thứ 4, độc lập,
lưu trực tiếp các sự kiện injected (không qua Loki) — dùng cho bài toán phân loại văn bản.

**Phát hiện quan trọng khi khảo sát**: `services/fraud-detection/main.py` (endpoint
`/score`) trước đây audit-log **không có `trace_id`**, trong khi payment-service,
core-banking, account-service đều đã có. Đây là lỗ hổng join duy nhất còn sót —
đã vá tận gốc (thêm `request.state.trace_id` — middleware `trace_middleware` đã set
sẵn giá trị này, chỉ là fraud-detection quên đọc nó ra) và deploy lại (xem mục 6).
Đồng thời cũng thêm `channel`/`country` vào audit log này vì đó là 2 biến đầu vào
quan trọng của fraud-scoring mà trước đây không hề được ghi log — chỉ tồn tại
trong request body rồi mất.

## 2. Chạy script sinh dataset

```bash
# Cần các port-forward đang chạy (scripts/open-admin-uis.sh):
#   web-portal:18081, loki:13100, security-scorer:18092
python3 ml-dataset/generate_dataset.py --normal-count 24
```

Script tự động:
1. Đăng nhập thật qua OIDC Authorization Code + PKCE (giống hệt trình duyệt) bằng
   `testuser01`/`testuser02` (khách hàng, sinh traffic bình thường) và `soc01`
   (role `security-analyst`, dùng để gọi `/api/scenarios/*/run` — endpoint này đã
   được role-gate, khách hàng thường không gọi được nữa, xem mục 9) — không giả
   lập cookie, đăng nhập thật 100%.
2. Sinh **traffic bình thường** (chuyển tiền hợp lệ, biến thiên amount/channel/country).
3. Gọi tất cả **12 kịch bản tấn công** có sẵn ở `/scenarios` (chính là các nút bấm
   demo trên web UI) qua API `/api/scenarios/{id}/run`, mỗi kịch bản lặp N lần.
4. Đợi log trôi vào Loki (~15s), truy vấn lại 3 nguồn trên, join theo `trace_id`
   (khi có) hoặc theo cửa sổ thời gian (khi request bị chặn sớm, không có trace_id
   — xem mục 4).
5. Ghi ra 2 file CSV trong `ml-dataset/samples/`.

Cờ hữu ích: `--reps N` (số lần lặp mỗi kịch bản gateway), `--inject-reps N`,
`--normal-count N`, `--skip-heavy` (bỏ qua `high_velocity`/`rate_limit`, chạy nhanh
hơn để test). Chạy lại nhiều lần để tích lũy thêm dữ liệu — mỗi lần chạy **ghi đè**
file CSV, nên đổi tên file cũ trước nếu muốn giữ lại (hoặc gộp nhiều lần chạy bằng
`pandas.concat` khi tiền xử lý).

Dataset mẫu thật đã sinh sẵn: `ml-dataset/samples/tabular_dataset.csv` (839 dòng),
`ml-dataset/samples/text_dataset.csv` (301 dòng) — dùng ngay được, hoặc chạy lại
script để lấy bộ mới/lớn hơn.

## 3. `tabular_dataset.csv` — dataset dạng bảng (đa lớp)

Mỗi dòng = **một log line** ở một trong 3 lớp (`envoy` / `opa` / `app`), gắn nhãn.
Không pivot join thành 1-row-per-request vì lượng dữ liệu còn nhỏ — nhóm ML nên tự
pivot theo `trace_id`/`opa_x_trace_id`/`app_trace_id` khi cần feature vector đa lớp
cho 1 request (dùng `pandas.pivot_table` hoặc groupby).

### Cột nhãn (label columns)

| Cột | Ý nghĩa |
|---|---|
| `label` | **Biến mục tiêu (target)**. Giá trị = một trong các `attack_type` ở bảng taxonomy mục 5, hoặc `normal`. |
| `mitre` | MITRE ATT&CK technique ID tương ứng (rỗng nếu `normal`). |
| `label_confidence` | `exact` (join đúng theo `trace_id`) hoặc `window` (suy ra từ cửa sổ thời gian request đang chạy — xem mục 4, cẩn thận nhiễu). |
| `source_layer` | `envoy` / `opa` / `app` — lớp log của dòng này. |

### Cột đặc trưng (feature columns) theo lớp

**Lớp `envoy` (biên mạng — luôn có cho mọi HTTP request; tên cột giữ tiền tố `envoy_` từ trước migration Istio để không phải sửa `generate_dataset.py`/pipeline hiện có, nhưng dữ liệu nguồn thật là log của istio-proxy):**

| Cột | Kiểu | Ý nghĩa / giá trị ML |
|---|---|---|
| `envoy_method` | categorical | GET/POST/... |
| `envoy_path` | categorical/text | endpoint bị gọi — tín hiệu mạnh cho `exploit_probe`, `lateral_movement` |
| `envoy_response_code` | categorical | 200/401/403/409/422/429/500 — tín hiệu trực tiếp cho `access_denied`, `port_scan` (nhiều 429 dồn dập) |
| `envoy_response_time_ms` | numeric | độ trễ — bất thường có thể là dấu hiệu DoS/exfiltration |
| `envoy_bytes_sent` | numeric | kích thước response — dùng cho `large_response`/`data_staging` |
| `envoy_source_ip` | categorical | IP nguồn (velocity/frequency theo IP là feature engineering tốt) |
| `envoy_svid` | categorical | SPIFFE ID nếu có (thường null ở hop đầu từ browser) |
| `envoy_trace_id` | id | khóa join |

**Lớp `opa` (quyết định uỷ quyền — chỉ có khi request tới được service có sidecar OPA):**

| Cột | Kiểu | Ý nghĩa |
|---|---|---|
| `opa_allow` | boolean | **rất mạnh** — true/false quyết định của policy engine |
| `opa_dest_principal` | categorical | SPIFFE ID đích, dạng `spiffe://ztlab.local/<cloud>/<service>` |
| `opa_source_principal` | categorical | SPIFFE ID nguồn — null/lạ = dấu hiệu `lateral_movement` |
| `opa_req_method`, `opa_req_path`, `opa_req_host` | categorical | request thực tế OPA đang xét |
| `opa_has_bearer` | boolean | có Authorization header không — false = dấu hiệu `no_jwt`/`access_denied` |
| `opa_x_trace_id`, `opa_x_user_id` | id | khóa join + định danh người dùng |
| `opa_content_length` | numeric | kích thước request body |
| `opa_user_agent` | categorical/text | User-Agent — hữu ích phát hiện script/tool tấn công (`sqlmap`, `curl`, ...) |

**Lớp `app` (business logic — audit log của fraud-detection/payment-service/api-gateway):**

| Cột | Kiểu | Ý nghĩa |
|---|---|---|
| `app_event` | categorical | tên sự kiện (`fraud_score_computed`, `payment_blocked_fraud`, `payment_completed`, `http_request`, ...) |
| `app_fraud_score` | numeric **0-100** | điểm rule-based hiện tại của `fraud-detection` — dùng làm **1 feature đầu vào**, không phải nhãn — mô hình ML nên học để bổ sung/vượt qua rule-based này |
| `app_verdict` | categorical | `allow`/`review`/`block` theo ngưỡng rule-based hiện tại (75/40) |
| `app_reason` | text (multi-label, `;` phân cách) | lý do rule-based gắn: `critical_amount`, `high_amount`, `risky_channel`, `unusual_country`, `baseline` |
| `app_amount` | numeric | số tiền giao dịch (VND) |
| `app_channel` | categorical | `web`/`mobile`/`api`/`tor`/`unknown`/`script` |
| `app_country` | categorical | `VN`/`SG`/`TH`/khác (whitelist hiện tại chỉ 3 nước) |
| `app_status_code`, `app_duration_ms` | numeric | từ dòng `http_request` (mọi service đều có, kể cả không phải audit) |

### Feature engineering gợi ý (chưa có sẵn trong CSV, nhóm ML tự tính thêm)

- **Velocity theo `envoy_source_ip`**: số request trong cửa sổ trượt N giây — đúng
  bản chất `brute_force`/`port_scan`/`high_velocity`.
- **Entropy/độ đa dạng `envoy_path`** theo IP trong cửa sổ ngắn — cao bất thường =
  `port_scan`/`exploit_probe` (quét nhiều endpoint).
- **Tỷ lệ `opa_allow=false`** theo `opa_source_principal`/IP trong cửa sổ — cốt lõi
  của `lateral_movement`, `fraud_gate_bypass`.
- **Độ lệch `app_amount` so với lịch sử của `from_account`** (không có sẵn — cần
  join thêm dữ liệu account-service nếu muốn) — feature hành vi (behavioral),
  mạnh hơn ngưỡng tĩnh hiện tại của rule-based.
- **Giờ trong ngày / ngày trong tuần** từ `timestamp` — giao dịch giờ bất thường.

## 4. Về độ chính xác của nhãn (`label_confidence`)

Script gán nhãn theo 2 cách:

1. **`exact`**: response của request có `trace_id` (mọi request tới được
   `fraud-detection`/`core-banking`, tức là qua được lớp xác thực JWT) — join chính
   xác 100% qua `trace_id`/`x-trace-id`/`app_trace_id`.
2. **`window`**: request bị chặn **trước khi** có `trace_id` (ví dụ `no_jwt`,
   `jwt_forgery` — bị OPA/JWT-check từ chối ngay ở lớp xác thực, chưa kịp gọi tới
   fraud-detection) — script gán nhãn theo **cửa sổ thời gian** kịch bản đó đang
   chạy. Cách này có nhiễu: nếu có traffic nền khác (health-check định kỳ của K8s,
   ví dụ) trùng thời điểm, dòng log đó sẽ bị gán nhầm nhãn của kịch bản đang chạy.

**Khuyến nghị cho nhóm ML**: nếu cần một tập "sạch" tuyệt đối để đánh giá mô hình
(test set), lọc `label_confidence == "exact"`. Dùng cả tập `window` cho **train**
là hợp lý (nhiễu nhãn ở mức thấp, các mô hình tree-based/DL vẫn học tốt), nhưng nên
biết rõ đây là **weak label**, không phải ground truth tuyệt đối.

Cách khắc phục triệt để (không nằm trong phạm vi bộ kit này, đề xuất cho tương lai):
gắn `X-Trace-ID` ngay từ `web-portal` trước khi gọi `api-gateway`
(`services/web-portal/main.py::_call_gateway`) thay vì để mỗi service tự sinh —
khi đó **mọi** dòng log kể cả bị chặn sớm đều có cùng 1 trace_id xuyên suốt.

## 5. `text_dataset.csv` — dataset văn bản (đúng contract input/output của ai-analyzer)

Nguồn: `security-scorer`'s `/events/recent` — đây là nơi **duy nhất** hiện tại nhận
log dạng câu văn bản tự do (không phải JSON có cấu trúc), tương ứng đúng 1-1 với
input contract của `ai-analyzer`:

```python
# services/ai-analyzer/main.py — đây LÀ format input mà mô hình ML/DL cần tương thích
class LogEntry(BaseModel):
    timestamp: str | None = None
    message: str                        # <-- cột `message` trong text_dataset.csv
    labels: dict[str, str] = {}         # <-- suy ra một phần từ cột `service`
```

Nhãn ở đây là **chính xác tuyệt đối** (`exact`, không phải suy luận) vì
`security-scorer` lưu lại đúng những gì được bơm vào, kèm `event_type` gốc —
không cần join gì cả.

| Cột | Ý nghĩa |
|---|---|
| `event_type` | nhãn — 1-1 với `attack_type` trong bảng taxonomy mục 6 (map `data_exfil` → `large_response`, còn lại trùng tên) |
| `message` | câu log dạng text — input trực tiếp cho mô hình NLP/text-classification |
| `service` | service nguồn (context, không bắt buộc dùng làm feature) |
| `timestamp` | epoch seconds |

Đây là dataset phù hợp nếu nhóm ML muốn thử hướng **text classification** (TF-IDF +
classic ML, hoặc fine-tune một small transformer) thay vì/thêm vào hướng tabular.

## 6. Output contract mục tiêu — để mô hình "cắm vừa" vào `ai-analyzer`

`ai-analyzer` hiện định nghĩa sẵn schema output (`AnalyzeResult` trong
`services/ai-analyzer/main.py`) và toàn bộ hệ thống playbook/MITRE/HITL phía sau nó
(SOAR, `security.html`) đã được lập trình để tiêu thụ đúng schema này. Nhóm ML nên
huấn luyện mô hình để output khớp field-by-field:

```python
class AnalyzeResult(BaseModel):
    verdict: Literal["normal", "malicious", "suspicious"]
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float            # 0.0 - 1.0
    attack_type: str             # xem bảng taxonomy bên dưới — bắt buộc khớp 1 trong các giá trị này
    mitre: str                   # tự động điền theo attack_type nếu để trống (xem ATTACK_MITRE)
    summary: str
    evidence: list[str]
    recommended_action: str
    recommended_playbook: str | None   # tự động điền theo attack_type nếu để trống (xem ATTACK_PLAYBOOKS)
    affected_service: str | None
    source_ip: str | None
```

### Bảng taxonomy 15 lớp `attack_type` (đã dùng xuyên suốt hệ thống — playbook SOAR,
severity, MITRE — nhóm ML nên coi đây là tập nhãn cố định, KHÔNG tự đặt tên lớp mới
trừ khi cũng cập nhật 3 dict này trong `ai-analyzer/main.py`):

| `attack_type` | MITRE | Playbook SOAR | Severity |
|---|---|---|---|
| `fraud_gate_bypass` | T1078.004 | isolate_workload | critical |
| `container_escape` | T1611 | quarantine_workload | critical |
| `privilege_escalation` | T1068 | quarantine_workload | critical |
| `impair_defenses` | T1562 | quarantine_workload | critical |
| `large_response` (= `data_exfil` bên text_dataset) | T1041 | restrict_egress | high |
| `brute_force` | T1110.001 | revoke_user_sessions | high |
| `credential_stuffing` (= `cred_stuffing`) | T1110.004 | revoke_user_sessions | high |
| `data_staging` | T1074 | restrict_egress | high |
| `cryptomining` | T1496 | quarantine_workload | high |
| `account_manipulation` | T1531 | isolate_workload | high |
| `lateral_movement` | T1021.007 | isolate_workload | high |
| `port_scan` | T1046 | block_source_ip | medium |
| `access_denied` | T1078 | block_source_ip | medium |
| `exploit_probe` | T1203 | block_source_ip | high (fallback mặc định — không nằm trong 3 tập severity tường minh) |
| `jwt_replay` | T1550.001 | revoke_user_sessions | high (fallback mặc định) |
| *(không match gì)* | — | — | `normal`, severity=`low` |

Logic gốc (`services/ai-analyzer/main.py:389-402`): severity = `critical` nếu match
tập critical, `high` nếu match tập high, `medium` nếu match tập medium, **`high` nếu
không rơi vào tập nào** (mặc định thiên về cảnh báo, không phải bỏ sót) — áp dụng
đúng cho `exploit_probe` và `jwt_replay` ở trên.

Bảng gốc: `services/ai-analyzer/main.py` dòng 37-89 (`MALICIOUS_PATTERNS`,
`ATTACK_PLAYBOOKS`, `ATTACK_MITRE`) — đây cũng chính là baseline heuristic hiện tại
(regex-based), mô hình ML/DL cần **vượt qua** baseline này (đo bằng precision/recall
so với heuristic hiện có) mới có giá trị thay thế.

## 7. Hạn chế đã biết của bộ dataset mẫu đi kèm

- **Mất cân bằng lớp nặng**: `normal` (~344 dòng) và `brute_force` (~196, do
  `high_velocity` gọi 10 request liên tiếp) chiếm phần lớn; `port_scan` chỉ có 4
  dòng trong lần chạy mẫu. Cần oversampling (SMOTE) hoặc chạy script nhiều lần hơn
  cho các lớp hiếm (`--reps 15` cho riêng nhóm scenario ít mẫu).
- **1 cụm/1 phiên demo**: toàn bộ dữ liệu sinh trong một khoảng ~85 giây, cùng dải
  IP nội bộ cluster (`10.42.x.x`), cùng 2 user test. Không có sự đa dạng về nguồn
  gốc mạng/thời gian thật — mô hình train thuần trên bộ này có nguy cơ overfit vào
  đặc điểm của môi trường demo (ví dụ luôn học `source_ip` bắt đầu bằng `10.42`).
  Nên chạy script định kỳ (cron) qua nhiều ngày để đa dạng hoá, hoặc augment thêm.
- **2 dòng HTTP 409** xuất hiện trong lần chạy đầy đủ (transfer bình thường bị
  core-banking từ chối do trùng điều kiện idempotency) — không phải lỗi script,
  giữ nguyên trong dataset vì đó cũng là tín hiệu thật (nhãn vẫn là `normal`, chỉ là
  request bị từ chối vì lý do nghiệp vụ chứ không phải tấn công).
- **`rate_limit` scenario** tạo ra chủ yếu nhiễu `GET /health` lặp lại — tín hiệu
  cho `port_scan`/DoS yếu hơn so với brute_force/fraud_gate; cân nhắc bổ sung thêm
  kịch bản quét nhiều path khác nhau nếu cần dữ liệu `port_scan` chất lượng hơn.

## 9. Device Trust — trụ cột Zero Trust mới (bổ sung sau khi viết bộ kit này)

Hệ thống trước đây có Identity (Keycloak), Authorization (OPA), mTLS (SPIRE/Istio),
Fraud (rule-based) nhưng **thiếu tín hiệu Device Posture/Compliance** — một trụ cột
chuẩn của Zero Trust (NIST SP 800-207). Đã bổ sung một phiên bản thực tế, khả thi
với môi trường trình duyệt (không giả định có agent cài trên máy khách):

- **Device binding**: mỗi trình duyệt nhận 1 `device_id` bền vững (cookie 1 năm,
  `httponly`) ngay lần ghé thăm đầu tiên (`services/web-portal/main.py` middleware
  `security_headers`).
- **Device trust classification** (`_evaluate_device_trust`, tính tại thời điểm
  đăng nhập, lưu vào session): 
  - `suspicious` — User-Agent khớp dấu hiệu script/tool tự động (`curl`, `python-requests`,
    `sqlmap`, `nmap`, headless browser, ...) hoặc thiếu User-Agent hoàn toàn.
  - `new_device` — `device_id` chưa từng thấy cho tài khoản này (tra cứu Redis set
    `web-portal:known_devices:<username>`) — đăng ký lại luôn để lần sau được nhận
    diện là quen thuộc.
  - `trusted` — `device_id` đã có trong tập thiết bị quen thuộc của tài khoản.
- **Enforcement thật** (không chỉ hiển thị): `device_trust` được truyền xuyên suốt
  `web-portal → api-gateway → payment-service → fraud-detection` (field mới trong
  `PaymentRequest`/`FraudRequest`), cộng điểm vào fraud score giống hệt cách
  `channel`/`country` đang làm: `suspicious` → +20 điểm (`suspicious_device`),
  `new_device` → +10 điểm (`unrecognized_device`) — xem `fraud-detection/main.py::_score()`.
- **Cột mới trong dataset**: `app_reason` trong `tabular_dataset.csv` giờ có thể chứa
  `suspicious_device`/`unrecognized_device`; nên thêm cột `device_trust` khi tự mở
  rộng `parse_pod_json_line()` trong `generate_dataset.py` nếu muốn dùng làm feature
  riêng (hiện đang gộp chung vào `app_reason`).
- **Sự kiện đăng nhập thiết bị lạ** cũng được đẩy sang `security-scorer` với
  `event_type = "new_device_login"` / `"suspicious_device_login"` — đây là 1 nhãn
  **hoàn toàn mới**, chưa có trong 15-class taxonomy của `ai-analyzer` (mục 6) —
  nhóm ML có thể coi đây là class thứ 16 (`account_manipulation`-adjacent, gần với
  "unauthorized device access") nếu muốn mở rộng taxonomy, hoặc bỏ qua nếu chỉ tập
  trung vào 15 lớp gốc.

Lưu ý cho nhóm ML: đây là **behavioral/contextual signal**, không phải posture
"thật" theo nghĩa MDM (không kiểm tra mã hoá ổ đĩa, patch OS, EDR...) — vì trình
duyệt không cho phép truy cập các thông tin đó. Đây là kỹ thuật **device binding**
tiêu chuẩn (giống cách các ngân hàng thật làm — "thiết bị lạ đăng nhập"), phù hợp
với ràng buộc của một web app.

## 10. Tách luồng demo: Banking vs SOC Console

Nav/role đã được siết lại để 2 luồng demo tách bạch, không còn hiện lẫn:

- **Khách hàng thường** (không có role `security-admin`/`security-analyst`): chỉ
  thấy Tổng quan / Chuyển tiền / Hồ sơ. Không còn thấy — và không còn gọi được —
  `/scenarios`, `/monitor`, `/security`, `/admin` (đều trả 403 nếu cố truy cập
  trực tiếp bằng URL, kể cả gọi thẳng API).
- **security-admin / security-analyst**: thêm khu "Trung tâm An ninh (SOC)" với
  giao diện đổi tông màu riêng biệt khi vào các trang này.

File `generate_dataset.py` phản ánh đúng ranh giới này: `testuser01`/`testuser02`
(khách hàng) chỉ tạo traffic bình thường; `soc01` (security-analyst) mới gọi được
`/api/scenarios/*/run`.

## 11. File trong thư mục này

```
ml-dataset/
├── README.md              # tài liệu này
├── generate_dataset.py    # script sinh dataset (idempotent, chạy lại được nhiều lần)
└── samples/
    ├── tabular_dataset.csv    # 839 dòng — multi-layer, xem mục 3
    └── text_dataset.csv       # 301 dòng — text classification, xem mục 5
```
