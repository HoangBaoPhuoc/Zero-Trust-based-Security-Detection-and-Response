# ĐÁNH GIÁ HỆ THỐNG
## So Sánh Mô Hình Zero Trust và Mô Hình Bảo Mật Truyền Thống

> **Môn học:** NT114.Q21.ANTT — Đồ án chuyên ngành An Toàn Thông Tin  
> **Sinh viên:** Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> **Ngày đánh giá:** 28/06/2026

---

## 1. Cơ Sở So Sánh

Mô hình bảo mật truyền thống (*perimeter-based security* hay còn gọi là mô hình "lâu đài và hào") đặt toàn bộ nỗ lực bảo vệ tại ranh giới mạng. Một khi traffic đã vượt qua tường lửa và vào trong mạng nội bộ, các service tin tưởng lẫn nhau mặc định. Mô hình này từng hiệu quả khi ứng dụng là một khối monolith chạy trong datacenter cô lập, nhưng trở nên mong manh khi hệ thống chuyển sang kiến trúc microservice phân tán trên nhiều cloud.

Hệ thống ZTLab được xây dựng theo nguyên tắc Zero Trust: *không tin tưởng bất kỳ thứ gì theo mặc định, xác minh tất cả mọi thứ liên tục*. Phần này so sánh trực tiếp hai mô hình trên cùng bộ kịch bản tấn công, sử dụng số liệu đo thực tế từ hệ thống.

---

## 2. So Sánh Khả Năng Phòng Thủ

### 2.1. Kiểm Soát Truy Cập Giữa Các Service (East-West Traffic)

Trong mô hình truyền thống, các microservice giao tiếp với nhau qua mạng nội bộ mà không có xác thực danh tính. Một service bị xâm phạm có thể gọi tự do đến bất kỳ service nào khác trong cùng cluster — đây là điều kiện lý tưởng để kẻ tấn công thực hiện *lateral movement*.

Trong hệ thống ZTLab, mỗi service được SPIRE cấp một SPIFFE Verifiable Identity Document (SVID) dạng X.509. Envoy sidecar bắt buộc xác thực SVID trên mọi kết nối inbound, và OPA kiểm tra quyền của service nguồn trước khi cho phép gọi. Kết quả thực tế:

> Trong 24 giờ vận hành, **76 request lateral movement** bị OPA từ chối tại endpoint `/payments/internal/execute`. Toàn bộ các request này đến từ notification-service (IP `10.42.1.149`) — một service có SVID hợp lệ, kết nối mTLS thành công, nhưng không có quyền gọi endpoint nội bộ của payment-service. Trong mô hình truyền thống, 76 request này sẽ được thực thi mà không có bất kỳ cảnh báo nào.

| Tiêu chí | Mô hình truyền thống | Mô hình Zero Trust (ZTLab) |
|---|---|---|
| Danh tính service | Không có / dùng IP | SPIFFE SVID X.509, rotate mỗi 1 giờ |
| Xác thực kết nối nội bộ | Không (tin tưởng mặc định) | mTLS bắt buộc, ECDHE-ECDSA-AES128-GCM-SHA256 |
| Phân quyền service-to-service | Không có | OPA RBAC, kiểm tra mỗi request |
| Lateral movement trong 24h | Không phát hiện được | **76 request chặn và ghi log** |
| Lỗi xác thực mTLS | N/A | `ssl.fail_verify = 0` (100% handshake thành công) |

### 2.2. Kiểm Soát Truy Cập Người Dùng (North-South Traffic)

Mô hình truyền thống thường chỉ kiểm tra xác thực tại API Gateway (đúng token hay không), sau đó chuyển request vào hệ thống mà không kiểm tra thêm quyền hạn. Một tài khoản với token hợp lệ nhưng role thấp vẫn có thể thử gọi các endpoint không được phép.

ZTLab tích hợp OPA làm điểm quyết định phân quyền tập trung. JWT được decode, claims role được kiểm tra theo policy `zta_policy.rego` *trước khi* request đến application Python. Kết quả:

> Trong 24 giờ, **711 request** bị OPA từ chối tại `/payments` do vi phạm RBAC — phần lớn từ tài khoản có `role=financial-read` cố thực hiện thao tác ghi (`POST /payments`). OPA ghi log từng quyết định với `decision_id` riêng, kèm `subject`, `subject_roles`, `required_roles`, và `reason`. Trong mô hình truyền thống không có lớp phân quyền tập trung, các request này có thể đến được application và tùy logic code xử lý — rủi ro cao hơn và không có audit trail.

| Tiêu chí | Mô hình truyền thống | Mô hình Zero Trust (ZTLab) |
|---|---|---|
| Phân quyền chi tiết | Trong code application | OPA policy tập trung, độc lập với app |
| Audit trail | Tùy application log | 215.005 quyết định OPA/24h, mỗi cái có decision_id |
| Thay đổi policy | Deploy lại code | Cập nhật Rego file, không restart service |
| RBAC violation bị chặn 24h | Không đo được | **711 request** |

### 2.3. Phát Hiện Brute Force

Mô hình truyền thống thường phát hiện brute force qua rate limiting tại API Gateway hoặc phân tích log thủ công. Độ trễ từ khi tấn công xảy ra đến khi admin biết thường từ vài giờ đến vài ngày.

ZTLab ghi mọi request 403 vào Loki qua Promtail, Grafana đánh giá liên tục theo LogQL `count_over_time([5m]) > 10`, và SOAR tự động tạo case + gửi email khi ngưỡng bị vượt:

> Trong bài kiểm thử thực tế, 20 request brute force gửi trong vòng 1 giây, tất cả bị Envoy block (HTTP 403) trong **1–29 ms**. Grafana phát hiện pattern trong chu kỳ đánh giá tiếp theo, SOAR gửi email đến admin. Tổng thời gian từ tấn công đến email cảnh báo: **dưới 80 giây**. Trong 24 giờ qua, **1.145 request** với response code 403 đã được ghi nhận và phân tích.

| Tiêu chí | Mô hình truyền thống | Mô hình Zero Trust (ZTLab) |
|---|---|---|
| Thời gian phát hiện brute force | Vài giờ đến vài ngày | **≤ 80 giây** |
| Cảnh báo tự động | Cần cấu hình thêm SIEM | Tích hợp sẵn Grafana → SOAR → Email |
| Log có thể truy vấn | Tùy hệ thống | 90.326 envoy-access log/24h trong Loki |
| Phản ứng tự động | Thủ công | SOAR revoke session Keycloak, block IP Redis |

### 2.4. Phát Hiện Giao Dịch Gian Lận

Trong mô hình truyền thống, fraud detection thường là một bước kiểm tra thêm *sau* khi giao dịch được phép thực thi, thậm chí có thể chạy bất đồng bộ. Kẻ tấn công có thể gửi giao dịch và nhận kết quả trước khi hệ thống phát hiện gian lận.

ZTLab tích hợp fraud scoring vào luồng xử lý đồng bộ: mỗi giao dịch được payment-service chấm điểm rủi ro trước khi commit, và AUDIT log được ghi ngay khi từ chối. Grafana giám sát event `payment_blocked_fraud` liên tục.

> Trong 24 giờ, **124 giao dịch** bị chặn do fraud score vượt ngưỡng (≥ 75), với các lý do cụ thể được ghi vào log: `velocity=6/900s` (vượt tần suất), `critical_amount` (số tiền bất thường), `risky_channel` (kênh rủi ro). Mỗi giao dịch có `trace_id` để correlate với toàn bộ chuỗi xử lý.

---

## 3. So Sánh Hiệu Năng Vận Hành

### 3.1. Chi Phí Tài Nguyên

Mô hình Zero Trust yêu cầu thêm các thành phần hạ tầng (SPIRE, OPA, Envoy sidecar, PLG stack, SOAR) so với mô hình truyền thống chỉ cần API Gateway và ứng dụng. Đây là sự đánh đổi có chủ đích.

**Bảng — Tài nguyên tiêu thụ thực tế (đo 28/06/2026)**

| Thành phần | CPU | RAM | Có trong mô hình truyền thống? |
|---|---|---|---|
| OPA server | 3m | 23 MiB | ❌ Thêm mới |
| Envoy sidecar × 5 service | ~25m tổng | ~200 MiB tổng | ❌ Thêm mới |
| SPIRE server + agent | ~5m | ~60 MiB | ❌ Thêm mới |
| Loki + Promtail | 38m | 369 MiB | ✅ Có thể có SIEM tương đương |
| Grafana | 11m | 65 MiB | ✅ Có thể có dashboard |
| SOAR engine | 3m | 92 MiB | ❌ Thêm mới |
| **Overhead Zero Trust** | **~36m** | **~283 MiB** | |
| **Tổng cụm (2 node)** | **320m / 7,5%** | **3,9 GiB / 68%** | |

Chi phí thuần của các thành phần Zero Trust không có trong mô hình truyền thống (OPA + Envoy + SPIRE + SOAR) khoảng **36 millicore CPU và 283 MiB RAM** — tương đương khoảng 11% tổng tài nguyên đang dùng. Đây là mức overhead chấp nhận được.

### 3.2. Độ Trễ Xử Lý Request

Đây là điểm đánh đổi rõ ràng nhất. Mô hình Zero Trust thêm vào mỗi request một gRPC call từ Envoy đến OPA để đánh giá policy.

**Bảng — So sánh latency**

| Kịch bản | Latency avg | p95 | Ghi chú |
|---|---|---|---|
| Pod → Pod nội bộ (baseline, không Envoy, không OPA) | 7,7 ms | 22,1 ms | Tốc độ mạng Kubernetes thuần |
| Request qua Envoy + OPA (Zero Trust) | **134,7 ms** | 221,7 ms | Đo từ 20 mẫu thực tế |
| **Overhead của Zero Trust** | **≈ 127 ms** | | Chủ yếu là OPA eval time |

Mô hình truyền thống không có bước OPA ext_authz, do đó latency sẽ gần với baseline 7,7 ms. **Zero Trust thêm khoảng 127 ms trung bình mỗi request** — đây là chi phí thực sự phải trả cho việc xác minh liên tục.

Tuy nhiên, cần đặt con số này trong bối cảnh: OPA được triển khai dưới dạng pod độc lập giao tiếp qua gRPC trong môi trường lab tài nguyên hạn chế. Trong môi trường production với OPA tích hợp in-process vào Envoy (OPA-Envoy plugin), latency có thể giảm xuống **5–20 ms** — gần như ngang bằng mô hình truyền thống.

### 3.3. Thời Gian Phát Hiện Và Phản Ứng

Đây là lợi thế định lượng rõ ràng nhất của Zero Trust so với mô hình truyền thống.

**Bảng — So sánh thời gian phát hiện và phản ứng**

| Giai đoạn | Mô hình truyền thống | Mô hình Zero Trust (ZTLab) |
|---|---|---|
| Phát hiện brute force | Giờ–ngày (log review thủ công) | **≤ 80 giây** (Grafana tự động) |
| Phát hiện lateral movement | Thường không phát hiện được | **Tức thì** (OPA deny + Loki log) |
| Phát hiện RBAC violation | Tùy application log | **≤ 80 giây** (OPA log → Grafana) |
| Cảnh báo đến admin | Email/call thủ công | **Tự động qua SOAR** (53 email đã gửi) |
| Phản ứng (block IP, revoke session) | Thủ công, hàng giờ | **Tự động trong 5 giây** (SOAR playbook) |
| Audit trail | Không đồng nhất | **215.005 OPA decision/24h** với decision_id |

Theo báo cáo Mandiant M-Trends 2024, dwell time trung bình toàn cầu (thời gian kẻ tấn công tồn tại trong hệ thống trước khi bị phát hiện) là **10 ngày**. Hệ thống ZTLab rút ngắn con số này xuống còn **dưới 2 phút** đối với các loại tấn công đã được định nghĩa — tức là nhanh hơn hơn **7.000 lần**.

### 3.4. Quản Lý Chứng Chỉ và Credential

Mô hình truyền thống thường dùng chứng chỉ TLS tĩnh với TTL dài (1–2 năm), quản lý thủ công. Nếu private key bị lộ, kẻ tấn công có thể sử dụng trong nhiều năm mà không bị phát hiện.

ZTLab dùng SPIRE để phát hành và rotation tự động hoàn toàn:

| Tiêu chí | Mô hình truyền thống | Mô hình Zero Trust (ZTLab) |
|---|---|---|
| TTL chứng chỉ workload | 1–2 năm (thủ công) | **1 giờ** (tự động rotation) |
| Cửa sổ khai thác nếu key bị lộ | Lên đến 2 năm | **Tối đa 60 phút** |
| Rotation | Thủ công, cần downtime | **Tự động, zero-downtime** |
| Chứng chỉ hiện tại (đo thực tế) | — | Issued: 11:06Z, Expires: 12:06Z |
| Root CA TTL | Năm | **168 giờ** (7 ngày, tự động) |
| Định danh workload | Không có / IP-based | SPIFFE URI: `spiffe://ztlab.local/aws/payment-service` |

---

## 4. Tổng Hợp So Sánh

| Tiêu chí đánh giá | Mô hình truyền thống | Mô hình Zero Trust (ZTLab) |
|---|---|---|
| **Bảo mật** | | |
| Lateral movement bị chặn | ❌ Không phát hiện | ✅ **76 request/24h chặn và ghi log** |
| RBAC violation bị chặn | Tùy application | ✅ **711 request/24h** |
| Brute force phát hiện | Thủ công, chậm | ✅ **≤ 80 giây**, tự động |
| Fraud gate bypass | Tùy từng service | ✅ **124 giao dịch/24h** chặn |
| Audit trail | Không đồng nhất | ✅ **215.005 quyết định/24h** |
| TTL credential | Năm | ✅ **1 giờ**, rotation tự động |
| **Hiệu năng** | | |
| Latency mỗi request | ~8 ms | ~135 ms (+127 ms overhead) |
| Tài nguyên thêm | Không | +36m CPU, +283 MiB RAM |
| Thời gian phát hiện tấn công | Ngày | ✅ **≤ 80 giây** |
| Phản ứng tự động | ❌ Thủ công | ✅ SOAR playbook trong 5 giây |
| Quản lý vận hành | Đơn giản hơn | Phức tạp hơn, nhiều thành phần |

Zero Trust mang lại cải thiện đột phá về bảo mật với chi phí vận hành tăng vừa phải. Đánh đổi chính là **+127 ms latency và độ phức tạp vận hành cao hơn** để đổi lấy khả năng phát hiện tấn công nhanh hơn 7.000 lần, chặn các loại tấn công mà mô hình truyền thống không thể phát hiện (lateral movement, RBAC abuse), và audit trail đầy đủ cho toàn bộ traffic.

---

## 5. Hạn Chế Của Hệ Thống Hiện Tại

Dù vượt trội so với mô hình truyền thống trên phần lớn tiêu chí, hệ thống ZTLab trong phạm vi đồ án vẫn còn một số điểm chưa hoàn thiện:

**Latency OPA trong lab (~127 ms):** Do OPA chạy dưới dạng pod riêng biệt, giao tiếp qua gRPC. Trong triển khai production với OPA tích hợp in-process vào Envoy, con số này giảm xuống 5–20 ms. Đây là hạn chế của môi trường lab, không phải hạn chế của mô hình.

**Phát hiện chỉ dựa trên rule cứng:** Hệ thống không học được pattern mới. Các kỹ thuật tấn công chưa được định nghĩa trong LogQL (slow brute force, insider threat thực hiện hành vi bình thường) sẽ không bị phát hiện. Cần tích hợp anomaly detection dựa trên ML trong tương lai.

**Chưa thực sự multi-cloud:** WireGuard tunnel đến OpenStack đã cấu hình nhưng chưa có node thật phía OpenStack. Chính sách cross-cloud chưa được kiểm thử end-to-end với traffic thật.

**SOAR dedup theo loại tấn công:** Nếu nhiều attacker khác nhau tấn công cùng lúc, SOAR chỉ tạo 1 case trong 5 phút. Cần thêm `source_ip` vào dedup key để phân biệt.

---

*Số liệu được đo trực tiếp từ hệ thống đang vận hành tại AWS ap-southeast-1, ngày 28/06/2026.*
