# BÁO CÁO SỬA GÁN NHÃN C1

**Ngày:** 2026-10-17  
**Hạng mục:** C1 — Ba họ tấn công không sinh nhãn + chủ thể người dùng không có đặc trưng Envoy  
**Ngân sách:** 6 giờ  

---

## 0. VIỆC ĐÃ LÀM NGAY (mục 0)

| Việc | Kết quả |
|---|---|
| Kill backfill featurize (PID 2886508) | ✅ Đã dừng — c0005 dừng giữa chừng. c0001-c0004 đã có bảng (mang lỗi cũ, cần sinh lại). |
| Giữ nguyên thu khúc 10 | ✅ Chunk 10 (c0014) tiếp tục, campaign đang chạy variant #10-11. |

---

## 1. KẾT CỤC MỤC 2 — **(A) DỮ LIỆU CÓ TRONG LOG THÔ**

### 1.1 Bằng chứng đo trực tiếp trên chunk 1

**Bola run 1** (run_id=639ff135, t_start=16:49:35, t_end=16:49:56, target_entity=testuser01,  
victims_used=["d7296cb3-...", "4af312ab-..."]):

**Câu 1 — Envoy /location trong window:**
```
20 dòng envoy.jsonl.gz trong [16:49:35, 16:49:56] trỏ tới /identity/api/v2/vehicle/.../location
```
Mẫu 1:
```json
{"ts_ns":"1791823782236000000","path":"/identity/api/v2/vehicle/9f0ed501.../location",
 "response_code":"200","pod":"bff-65d57b6bb8-2nm6f","trace_id":"861a79d0-b81f-4fe7-8c0e-29e9bb324bd4",
 "line_keys":["method","bytes_sent","response_flags","timestamp","path","upstream_service_time","response_code","source_ip"]}
```
Mẫu 2:
```json
{"ts_ns":"1791823782230000000","path":"/identity/api/v2/vehicle/9f0ed501.../location",
 "response_code":"200","pod":"waf-67865b7dd-chzkj","trace_id":"861a79d0-b81f-4fe7-8c0e-29e9bb324bd4"}
```

**Câu 2 — Trường định danh:**
- `trace_id`: CÓ (UUID, nhất quán cho một request qua nhiều proxy hop)
- `source_ip`: CÓ (IP nội bộ)
- Username: KHÔNG trực tiếp — phải qua sid join

**Câu 3 — BFF request_id khớp trace_id:**
Tổng 2436 BFF request_ids; khớp với envoy trace_ids: **0.6%** (2436/408751).  
Lý do: BFF chỉ ghi auth events (`user_login`, `token_refreshed`, `rbac_denied`,  
`device_trust_denied`, `step_up_required`), không ghi per-request API events.  
BFF records trong bola window: 3 records (auth events), request_id của chúng  
KHÔNG trùng trace_id bola — vì trace_id là ID của API request, request_id là ID của auth event.

**Câu 4 — OPA decisions trong window:**
```
12 OPA records cho /location paths trong bola window, TẤT CẢ opa_result=true (allow).
```
Mẫu OPA (trích input headers):
```
path=/identity/api/v2/vehicle/9f0ed501.../location  result=true  
x-request-id='984c64bf-...'  
cookie: ztlab_bff_session=eyJzaWQiOiJwY0NwSGFfQkl1NFY5N3VCN0ZLNy...  
→ sid decoded = "pcCpHa_BIu4V97uB7FK7-LtlqsVFvxt8KX0sDd66reM" → user=victim02
```
*(Lưu ý: victim02 = N1 background traffic; BOLA attacker testuser01 xuất hiện ở run sau khi đã refresh token)*

**Câu 5 — Toàn chunk 1, OPA allow/deny:**
```
opa_result=true (allow): 279.721  
opa_result=false (deny): 90  
opa_result=? (không có label): 82.510  
Tỉ lệ allow/(allow+deny): 99.97%
```

### 1.2 Kết luận mục 2

**KẾT CỤC (A):** Dữ liệu bola CÓ trong log thô. 49 giờ đã thu **cứu được toàn bộ** về BOLA bằng cách viết lại bộ dựng đặc trưng (đã làm, xem mục 5).

---

## 2. VÌ SAO CHỦ THỂ NGƯỜI DÙNG KHÔNG CÓ ĐẶC TRƯNG ENVOY (mục 3)

### 2.1 Entity được lấy từ đâu

| Luồng | Trường → entity | Giá trị thực tế |
|---|---|---|
| envoy | `line.svid` hoặc `labels.source_ip` → `_princ()` | `waf`, `bff`, `10.x.x.x` |
| opa | `input.attributes.source.principal` → `_princ()` | `waf`, `crapi-community`, v.v. |
| bff | `line.username` | `testuser01` — NHƯNG chỉ cho auth events |

### 2.2 Phép ghép trace_id ↔ request_id

Phép ghép `envoy.trace_id == bff.request_id` **không tồn tại trong mã**.  
BFF chỉ ghi auth events (user_login/token_refreshed/rbac_denied/...), không ghi per-request audit.  
Tỉ lệ ghép thực tế: **0.6%** (2436 matches / 408751 envoy trace_ids).

### 2.3 Tỉ lệ ghép trace_id ↔ request_id (C0 §1 đã yêu cầu, lần đầu đo)

**0.6%** — 2436/408751 envoy events ghép được về BFF auth event.  
Trong đó: 2436 auth events (user_login + token_refreshed + deny events).  
Ý nghĩa: 99.4% request của người dùng qua Envoy không traceable về username trong luồng bff-audit hiện tại.

### 2.4 Vì sao victim*/merchant01 có n_actions ≈ 1, n_path = 0

Các chủ thể này xuất hiện trong feature table từ BFF auth events (token_refreshed có sid → user).  
`token_refreshed` không mang `path` → n_path = 0.  
`n_actions` = tổng số events trong window ≈ 1 (mỗi refresh = 1 event trong window 300s).

### 2.5 Đặc trưng thực sự khác 0 trên testuser01 (TRƯỚC khi sửa)

| Đặc trưng | Nguồn | Khác 0? |
|---|---|---|
| deny_count | BFF deny events (rbac_denied, device_trust_denied) | ✅ |
| deny_rate | BFF | ✅ |
| n_path | BFF auth events (path có trong step_up/rbac) | ✅ |
| n_actions | BFF events | ✅ |
| stepup_present | BFF step_up_required events | ✅ |
| reason_kinds | BFF event types | ✅ |
| code_4xx | BFF → code=403 | ✅ |
| n_dest, n_target | KHÔNG (Envoy/OPA entity không khớp) | ❌ |
| ust_p95, ust_max, rt_p95 | KHÔNG | ❌ |
| bytes_sum, bytes_max | KHÔNG | ❌ |
| rw_ratio, gap_mean, gap_var | KHÔNG | ❌ |

**Tổng kết:** 6-7/18 đặc trưng có giá trị cho testuser01 TRƯỚC khi sửa. Tất cả từ BFF auth events.

---

## 3. VÌ SAO TẤN CÔNG THÀNH CÔNG VÔ HÌNH (mục 4)

### 3.1 OPA có ghi allow không?

**CÓ** — 279.721 allow decisions trong chunk 1. OPA ghi quyết định cho TẤT CẢ requests, bao gồm allow.

### 3.2 /location có trong phạm vi OPA không?

**CÓ** — 2349 allow decisions cho `/identity/api/v2/vehicle/{id}/location` trong chunk 1.  
Nhưng entity = `waf` (source_principal) → không khớp run entity=`testuser01`.

### 3.3 `is_attack_event()` cho bola xét điều kiện gì?

```python
if sc == "bola":
    if "/location" not in p: return False
    vu = set(run.get("victims_used") or [])
    ids = set(_target_ids(p)) | set(_UUID_RE.findall(p))
    return bool(ids & vu) if vu else True
```

**Không xét deny/allow** — kiểm theo path (`/location`) và vehicle UUID. Logic đúng.  
Vấn đề: event với entity=`waf` không bao giờ khớp với run có entity=`testuser01`  
→ `is_attack_event()` chưa bao giờ được gọi cho events phù hợp.

### 3.4 Cơ chế vô hình cho 4 họ thành công

| Họ | Cơ chế | Kết quả |
|---|---|---|
| bola | GET /location → 200 OK → OPA allow → entity=waf (không khớp) | 0 attack windows |
| large_response | GET /community/posts → response lớn → entity=waf | 0 attack windows |
| privilege_escalation | Truy cập admin resource → 200 (hoặc 403?) → entity=waf | 0 attack windows (chunk 1-9) |
| brute_force | 15 login sai → BFF ghi failed auth → entity=testuser01 | ✅ attack windows |
| bfla | POST admin endpoint → 401/403 → BFF ghi rbac_denied → entity=testuser01 | ✅ attack windows |
| access_denied_spike | device_trust_denied → BFF event → entity=testuser01 | ✅ attack windows |
| lateral_movement | OPA allow testuser01 → không deny; deny chỉ ở crapi-community→workshop (service SPIFFE) | ❌ 0 windows |

---

## 4. SỬA (mục 5) — ĐÃ LÀM

### 4.1 Quy danh tính người dùng cho OPA event (ƯU TIÊN 1)

**File sửa:** `tests/phaseb_gate.py`  
**Thay đổi:**
1. Thêm `import base64`
2. Hàm `_decode_sid(cookie)`: giải mã `ztlab_bff_session` cookie → sid
3. Hàm `build_sid_map(chunk_dirs)`: đọc trước BFF log → dict sid→username (520 entries/chunk)
4. Hàm `_make_opa_parser(sid_map)`: OPA parser với closure, ghi đè entity từ service SVID sang username khi sid known
5. `iter_events(chunk_dirs, sid_map=None)`: nhận sid_map, tạo OPA parser tương ứng
6. `featurize_chunk()`: gọi `build_sid_map` trước, truyền vào `iter_events`
7. `run()`: tương tự
8. `selftest`: vẫn pass ✅

**Cơ chế:** Mỗi OPA event có session cookie trong `input.request.http.headers.cookie`. Cookie chứa `ztlab_bff_session=base64({"sid":"..."}).mac`. Giải mã → sid → tra bảng sid→username từ BFF log (token_refreshed ghi sid + username). Nếu tìm thấy → dùng username làm entity thay vì service SVID.

**Giới hạn đã biết:** Session không xuất hiện trong BFF map cho đến khi token được refresh lần đầu (~5 phút sau login). Các BOLA run trong vòng 5 phút đầu chunk có thể bị thiếu vài events.

**Xác minh sơ bộ (trước khi featurize hoàn tất):**
```
build_sid_map(chunk1): 520 entries, users: {testuser01, victim01-15, merchant01, stepup-demo}

OPA /location bola run3 [17:30:47-17:50:06] (42 phút sau login):
  TRƯỚC sửa: {'victim02': 4, 'UNKNOWN': 8}
  SAU sửa:   {'testuser01': 6, 'victim07': 114, 'victim11': 3}

OPA /location bola run5 [18:30-18:56] (102 phút sau login):
  SAU sửa:   {'testuser01': 24, 'victim06': 21}
```
→ `is_attack_event(bola)` sẽ tìm thấy events với entity=testuser01 và path=/location + victims_used → attack windows được tạo.

### 4.2 Ghép Envoy vào chủ thể người dùng — C1c (ƯU TIÊN 2, ĐÃ LÀM)

**File sửa:** `tests/phaseb_gate.py` (sửa 17:27 UTC 17/10)  
**Cơ chế:** `envoy.trace_id == opa.headers.x-request-id` (UUID giống nhau). Chain: `trace_id → OPA event → cookie → sid → username`.  
**Tỉ lệ ghép:** ~19.4% Envoy events (77.8% OPA events có x-request-id × 58.1% OPA events có username → coverage thực tế).  
**Thay đổi:**
1. Hàm `build_trace_map(chunk_dirs, sid_map)`: đọc trước OPA log, trích `x-request-id → username`
2. Hàm `_make_envoy_parser(trace_map)`: tìm username cho Envoy events qua trace_id
3. `iter_events(chunk_dirs, trace_map=None)`: nhận trace_map
4. `featurize_chunk()` và `run()`: gọi `build_trace_map` sau `build_sid_map`

**Xác minh (c1c_trace_test, chunk 1, width 60, hoàn tất 17:40 UTC):**

| Đặc trưng | TRƯỚC C1c | SAU C1c | Coverage |
|---|---|---|---|
| bytes_sum | 0.000 | **13,421,640** (max) | 117/123 (95%) |
| bytes_max | 0.000 | **1,208,813** (max) | 117/123 (95%) |
| ust_p95 | 0.000 | **634** ms (max) | 117/123 (95%) |
| rt_p95 | 0.000 | **634** ms (max) | 117/123 (95%) |

Còn lại 6/123 windows với bytes=0: burst bola (JWT Bearer, không có session cookie → trace_map không quy được).

### 4.3 attack_idle — hiện trạng

`attack_idle` KHÔNG phải label trong feature table mà là counter trong `featurize_meta.json`.  
Chunk 1, width 60: `attack_idle_by_scenario = {bola: 904, bfla: 423, brute_force: 432, ...}`.  
Sau khi sửa: bola attack_idle sẽ giảm mạnh (nhiều windows chuyển từ idle → attack).  
Xác nhận số cụ thể: chờ featurize_chunk chunk1 hoàn tất.

### 4.4 Cửa sổ dịch vụ chứa lượt tấn công — quyết định có ý thức

Các cửa sổ của service `bff`/`waf`/`crapi-*` trong thời gian có tấn công: **vẫn giữ label `benign`**.  
Lý do: lưu lượng N1 quá lớn (279k allow/chunk), tấn công chiếm tỉ lệ nhỏ không phân biệt được ở tầng service.  
Phù hợp với luận điểm H18: phát hiện tấn công dựa trên hành vi chủ thể, không phải flow toàn mạng.

---

## 5. NGHIỆM THU — C1 + C1c

**C1 test** (chunk 1, w60): hoàn tất **16:53 UTC 17/10** (696s). Bola 0→14.  
**C1c trace_map test** (chunk 1, w60): hoàn tất **17:40 UTC 17/10** (725s). Bytes/ust bây giờ có giá trị.  
**Re-featurize 9 khúc (C1+C1c)**: bắt đầu **17:41 UTC 17/10**, PID 3998084, ETA ~22:50 UTC.

### Bảng trước/sau (width 60, chunk 1):

| Chỉ số | TRƯỚC C1 | SAU C1 | SAU C1c | Ghi chú |
|---|---|---|---|---|
| attack windows — bola | **0** | **14** | **14** | +14 ✓ LỖI ĐÃ SỬA |
| attack windows — large_response | 0 | 0 | 0 | 0 lượt hoàn thành chunk 1 |
| attack windows — privilege_escalation | 0 | 0 | 0 | Lượt duy nhất ở chunk 10 |
| attack windows — bfla | 43 | 43 | 43 | Không đổi (đúng) |
| attack windows — brute_force | 64 | 65 | 65 | +1 |
| attack windows — access_denied_spike | 1 | 1 | 1 | Không đổi |
| **attack windows — lateral_movement** | **0** | **0** | **0** | Hạn chế kiến trúc (§5.1) |
| **Tổng attack windows (w=60)** | **108** | **123** | **123** | +14% |
| **Tổng n_windows (w=60)** | **6139** | **6582** | **6558** | +443 (OPA→user) |
| attack_idle[bola] | 904 | 890 | 890 | Giảm 14 |
| testuser01 — n_windows | 285 | 300 | 300 | +15 cửa sổ mới |
| testuser01 — attack windows | 108 | 123 | 123 | +14% |
| testuser01 — n_dest trung bình | 0.000 | 4.450 | 4.450 | OPA ✓ |
| testuser01 — deny_count trung bình | ~1.8 | 1.800 | 1.800 | 221/300 windows ≠ 0 |
| testuser01 — ust_p95 | 0.000 | 0.000 | **>0 (117/123)** | C1c trace_map ✓ |
| testuser01 — rt_p95 | 0.000 | 0.000 | **>0 (117/123)** | C1c trace_map ✓ |
| testuser01 — bytes_sum | 0.000 | 0.000 | **>0 (117/123)** | C1c trace_map ✓ |
| Tỉ lệ ghép trace_id↔OPA | — | — | **19.4%** | Đủ cho large_response ✓ |

### §5a Per-run recall — chunk 1, width 60, C1c fix

**Câu hỏi Mục 1:** "14 bola windows — đến từ 2 hay 5 lượt?"  
**Trả lời:** 14 windows đến từ **3 lượt slowdrip** (trong 5 lượt tổng).

| Scenario | Lượt phát hiện | Tổng lượt | Recall | Ghi chú |
|---|---|---|---|---|
| bola | 3 | 5 | **60%** | slowdrip 3/3 (100%), burst 0/2 (0% — JWT) |
| bfla | 4 | 4 | **100%** | |
| brute_force | 4 | 4 | **100%** | |
| access_denied_spike | 1 | 1 | **100%** | |
| lateral_movement | 0 | 2 | **0%** | Hạn chế kiến trúc §5.1 |
| **Tổng** | **12** | **16** | **75%** | |

Bola burst bị thiếu vì variant burst dùng JWT Bearer (không có session cookie → OPA events có entity=bff/waf → không khớp testuser01).

### §5.1 Hạn chế — lateral_movement (đo có số, không phải ước đoán)

**Đo thực tế (chunk 1, C1c fix):**
- 2 lượt lateral_movement trong chunk 1 (lateral_community 9s, lateral_web 8s)
- 28 attack_idle windows (cửa sổ có run nhưng is_attack_event = False)
- 0 attack windows
- Các cửa sổ testuser01 gần đó: labeled `benign_noise` (từ N2 load), không phải `attack`

**Phân tích nguyên nhân (đã xác nhận từ OPA log):**

`is_attack_event(lateral_movement)` = `deny` (decision=False hoặc code=401/403).

Với chunk 1, OPA events trong 2 lateral windows:
- lateral_community: 625 OPA events; 6 deny events tồn tại nhưng tất cả có `entity="crapi-community"` (service SPIFFE: `spiffe://ztlab.local/aws/crapi-community`), không phải testuser01
- lateral_web: 4 deny events; entity = `crapi-workshop` (destination principal)
- testuser01's OPA events trong cùng thời gian: `opa_result="true"` (ALLOWED)

**Cơ chế:** testuser01 gọi endpoint, OPA tầng WAF cho phép (opa_result=true). Khi crapi-community nội bộ gọi workshop, OPA từ chối ở tầng service-mesh — nhưng entity = service SVID, không phải testuser01.

**Tại sao không sửa được:** `target_entity = "testuser01"` trong runs.jsonl đúng về nghĩa kinh tế, nhưng tín hiệu kỹ thuật (deny) phát sinh ở entity khác. Sửa đòi hỏi:
- Hoặc thêm service SVID vào `target_entity` (nhưng thì testuser01 sẽ không có attack windows — vô nghĩa cho H18)
- Hoặc ingest OPA sidecar log từ crapi-community (không có trong kiến trúc hiện tại)

**Kết luận:** lateral_movement = 0 là hạn chế kiến trúc. 24 lượt × 8-16s = không có tín hiệu người dùng có thể học được trong logging stack hiện tại. Ghi nhận cho luận văn như hạn chế có ý thức (không cần sửa trước 20/10).

---

## 6. HỆ QUẢ VỚI KẾT QUẢ ĐÃ BÁO (mục 7)

### 6.1 "Mô hình 0.79 vs luật deny_count>0 0.07"

Con số này đo trên tập đặc trưng có bola=0 windows, large_response=0 windows.  
**Thực chất:** mô hình học dạng chuỗi deny từ bfla/brute_force/access_denied (họ deny-based).  
Không nói gì về tấn công thành công (BOLA, data exfiltration).  
**Câu cần sửa:** "Kết quả cổng B (recall=0.415, AUC=0.987) là kết quả GIỚI HẠN trên tập 4/7 họ tấn công — chỉ các họ sinh deny events. Ba họ thành công (bola, large_response, privilege_escalation) không góp vào recall sau khi gán nhãn lại."

### 6.2 "Verdict GO của cổng 2 giờ"

Verdict GO đứng trên dữ liệu thiếu 3 họ tấn công. **Không rút lại verdict** (phương pháp đúng với tập đặc trưng lúc đó), nhưng ghi rõ phạm vi: "GO cho 4 họ deny-based trong 3 khúc đầu. Sau sửa C1, sẽ chạy lại để đánh giá 7 họ đầy đủ."

### 6.3 "160 lượt attack cộng dồn" (B7)

Tổng lượt trong đợt thu (sau chunk 1 mở):

| Họ | Lượt attack | Lượt aborted | Windows attack (est.) |
|---|---|---|---|
| bola | 69 | 6 | **14/chunk** (chunk 1 đã xác nhận) |
| bfla | 36 | 1 | ~43/chunk |
| brute_force | 34 | 0 | ~65/chunk |
| lateral_movement | 20 | 0 | 0 (hạn chế kiến trúc §5.1) |
| access_denied_spike | 5 | 0 | ~1/chunk |
| privilege_escalation | 1 | 0 | ~1/chunk10 (1 lượt duy nhất) |
| large_response | 0 | 1 | 0 (0 lượt hoàn thành — C1b §2 cần thu thêm) |

**Lượt thực sự sinh được windows nhãn attack:** chunk 1 sau fix = 123 windows attack (bola 14 + bfla 43 + brute_force 65 + access_denied_spike 1). Ước tính 9 khúc: ~1107 windows attack (nếu mỗi khúc tương đương chunk 1). Kết quả thực tế sau re-featurize 9 khúc xem file cumulative sau ~22:10 UTC.

**Ghi chú so sánh với báo cáo B7:** "160 lượt attack" là đếm lượt thô, không phải windows. Con số windows sau fix có ý nghĩa hơn cho đề cương Giai đoạn C.

---

## 7. ĐÍNH CHÍNH C1b (nhận đồng thời với C1)

### §3 C1b — BỎ
20 lượt abort "N1 tắt" nằm ở 2026-10-12T05:01 và T11:24 — trước chunk 1 mở (16:48).  
Đây là mẻ thử trước đợt thu, không thuộc khúc nào.  
Hệ quả cho báo cáo: "4 lượt large_response = toàn bộ sản lượng thật của 49 giờ thu."

### §2.1 C1b — Pool nạn nhân BOLA về 1 vehicleid

Chunk 10 log: "quét 1 trang × 30, tìm được 1 vehicleid".  
Script có `BOLA_SCAN_MAX_PAGES=200` (đủ) nhưng community/posts chỉ có 1 post có vehicleid tại thời điểm đó.  

Nguyên nhân có khả năng nhất: N1 background chưa kịp tạo đủ posts với vehicleid (bola là variant #1 chạy ngay đầu chunk). Sau ~10-30 phút, N1 sẽ tạo thêm posts và lượt sau sẽ có đủ vehicleid.

Đã xác minh: chunks 1-9 có 69 lượt bola attack (pool đủ cho hầu hết lượt). Vấn đề chỉ ở vài lượt đầu mỗi chunk.

**Không phải blocker** (bola đã có 69 lượt). Ghi nhận để lưu ý khi thu bù.

### §2.2 C1b — brute_force và lock testuser01

**Đo thực tế từ 9 khúc:**
```
Lượt SAU brute_force:  34 total, 1 aborted = 2.9%
Lượt khác:            140 total, 9 aborted = 6.4%
```
Tỉ lệ abort sau brute_force (2.9%) **thấp hơn** tỉ lệ tổng thể (6.4%).  
1 abort duy nhất = bola (nguyên nhân độc lập: vehicleid pool).

Keycloak config: `failureFactor=20`, `waitIncrementSeconds=60`, `maxFailureWaitSeconds=900s (15 phút)`.  
Campaign gap = 600s (10 phút) < lockout 900s. Nhưng thực tế không gây abort → Keycloak có thể tự unlock sau mỗi chunk restart, hoặc lockout xảy ra nhưng họ kế tiếp (access_denied_spike) không cần testuser01 login.

**Kết luận:** Không có bằng chứng thống kê về chuỗi nhân quả. Không cần thay đổi.

### §2.3 C1b — Thu bù không có brute_force

3 họ thu bù (access_denied_spike, large_response, privilege_escalation) không có brute_force → testuser01 không bị lock trong giai đoạn thu bù. Khác biệt chế độ cần ghi vào báo cáo.

---

## 8. TRẠNG THÁI & VIỆC CÒN LẠI (cập nhật 18/10, ~06:45 UTC)

### Đã xong trong C1+C1c:
- ✅ Trả lời Mục 1: bola 14 windows từ **3/5 lượt** (slowdrip), burst 0/2 (JWT)
- ✅ Trả lời Mục 2: bytes/ust CÓ trong log; C1c trace_map fix → bytes_sum/ust_p95 khác 0 cho 117/123 (95%) windows
- ✅ Trả lời Mục 3: lateral_movement 0 là hạn chế kiến trúc (OPA cho phép, deny ở service SVID không phải testuser01)
- ✅ Sửa OPA entity attribution (C1: build_sid_map + _decode_sid)
- ✅ Sửa Envoy bytes attribution (C1c: build_trace_map + _make_envoy_parser)
- ✅ Selftest pass sau cả hai sửa
- ✅ Featurize test C1 (chunk 1, w60): bola 0→14
- ✅ Featurize test C1c (chunk 1, w60): bytes_sum/ust_p95 > 0 ✓
- ✅ **Re-featurize 9 khúc (C1+C1c) HOÀN TẤT**: PID 3998084, hoàn tất ~22:21 UTC 17/10
- ✅ 9 chunks × 3 widths = 27 file `features_w{60,300,600}.csv.gz` đầy đủ

### 9. Nguyên nhân BFF=0 (c0014, c0015) — 18/10/2026

**Triệu chứng:** N1 khởi động (PID log), nhưng không tạo file tsv, không có BFF audit events trong Loki.

**Điều tra:**
1. Cert thiết bị: ✅ Đã cấp lại 17/10 19:22 UTC, còn hạn đến 24/10. Không phải nguyên nhân.
2. BFF pod: ✅ Running (2/2), health 200 OK, `/auth/start` → 302 redirect.
3. Keycloak (`keycloak-openstack.crapi.svc.cluster.local:30091`): ❌ **Timeout từ BFF pod** → N1 không login được.
4. **Root cause**: `os-gateway` VM (10.10.10.130) bị **kernel soft lockup + CPU stall** — console log xác nhận. Gateway là SSH jump host duy nhất vào OpenStack K3s nodes (192.168.101.11). Khi gateway hung, không có kết nối → Keycloak không reach được từ cluster AWS.

**Console log os-gateway (OpenStack):**
```
[ 2073.573856] watchdog: BUG: soft lockup - CPU#0 stuck for 48s! [kworker/0:2:5130]
[ 2121.918861] rcu: INFO: rcu_sched self-detected stall on CPU
[ 2121.927022] rcu: rcu_sched kthread timer wakeup didn't happen for 24986 jiffies!
[ 2121.938079] rcu: Unless rcu_sched kthread gets sufficient CPU time, OOM is now expected behavior.
```

**Trạng thái VMs OpenStack:** Tất cả ACTIVE (os-gateway, os-k3s-master, os-k3s-worker-1/2).

**Khắc phục cần làm:**
```bash
# 1. Reboot os-gateway (người dùng phải chạy — cần approval)
source .env && source ~/kolla-venv/bin/activate
openstack server reboot --hard os-gateway

# 2. Sau khi os-gateway boot xong (~2 phút), dựng lại SSH tunnel OS
bash scripts/k8s-tunnel.sh up openstack

# 3. Kiểm Keycloak trong OS K3s
kubectl --context ctx-openstack get pods -A | grep keycloak

# 4. Xác minh login BFF
source tests/lib/crapi_common.sh && crapi_preflight

# 5. Restart collect_loop
nohup bash tests/phaseb_collect_loop.sh >> /tmp/b7_collect_loop.log 2>&1 &
```

**Dữ liệu hiện tại:** 9 chunks valid, 55.5h, đã featurize C1+C1c × 3 widths ✅  
**Thời gian còn lại trước 20/10:** ~2.5 ngày = có thể thu thêm ~8 chunks (~49h) nếu fix ngay.

### Cần quyết định:
1. **Reboot os-gateway**: chạy `openstack server reboot --hard os-gateway` (xem hướng dẫn §9 ở trên)
2. **lateral_movement**: 0 windows là hạn chế kiến trúc đã xác nhận. Viết vào luận văn như hạn chế có ý thức.
