# Ghi chú công trình liên quan (Bước 1.1)

> Ghi chú tóm tắt mỗi tài liệu 3-5 dòng, dùng thẳng cho chương "Công trình liên quan" của báo cáo.
> Đây là bản DRAFT tổng hợp để định hướng đọc — trước khi trích dẫn chính thức vào báo cáo, cần tự đọc
> lại bản gốc (link nêu ở mỗi mục) để xác nhận số liệu/cách diễn giải, tránh trích sai ý tác giả.

## 1. NIST SP 800-207 — Zero Trust Architecture
Định nghĩa kiến trúc Zero Trust dựa trên nguyên tắc "never trust, always verify": không còn khái niệm
mạng tin cậy ngầm định theo vị trí (perimeter-based), mọi request đều phải được xác thực/ủy quyền theo
từng phiên. Giới thiệu 2 thành phần lõi PDP (Policy Decision Point) và PEP (Policy Enforcement Point) —
PDP ra quyết định allow/deny dựa trên policy + tín hiệu ngữ cảnh (danh tính, thiết bị, hành vi), PEP là
nơi thực thi quyết định đó tại đường đi của traffic thật. Dùng cho phần đặt vấn đề: OPA đóng vai trò PDP,
Envoy `ext_authz` đóng vai trò PEP trong kiến trúc ZT của đề tài.

## 2. OWASP API Security Top 10 (2023)
Chuẩn hoá 10 rủi ro bảo mật API phổ biến nhất. Quan trọng nhất cho đề tài: phân định rõ **API1:2023
BOLA** (Broken Object Level Authorization — người dùng hợp lệ nhưng truy cập object KHÔNG thuộc quyền sở
hữu, ví dụ đổi ID trong URL) khác với **API5:2023 BFLA** (Broken Function Level Authorization — người
dùng truy cập được một CHỨC NĂNG/endpoint mà vai trò của họ không được phép gọi, bất kể object nào).
Đề cương yêu cầu trích đúng định nghĩa này vì 2 khái niệm hay bị nhầm lẫn trong tài liệu không chính thức.

## 3. Chen & Malin (2011) — Relational Analysis of Access Logs
"Detection of Anomalous Insiders in Collaborative Environments via Relational Analysis of Access Logs",
CODASPY 2011. Đề xuất CADS (Community-based Anomaly Detection System) — học không giám sát, dựa trên giả
thuyết người dùng hợp lệ có xu hướng hình thành "cộng đồng" hành vi truy cập tương tự nhau trong access
log; ai hành xử lệch khỏi cộng đồng của mình có xác suất là insider bất thường. Gần với hướng của đề tài
ở chỗ dùng đặc trưng quan hệ (ai truy cập gì) trên dữ liệu dạng bảng, không cần graph deep learning.
Nguồn: https://ptolemy.berkeley.edu/projects/truststc/pubs/887/codaspy_chen.pdf

## 4. Tuor et al. (2017) — Deep Learning for Unsupervised Insider Threat Detection
AAAI Workshop 2017. Coi log hệ thống như "câu" (chuỗi sự kiện) để huấn luyện mô hình ngôn ngữ mạng
neural hồi quy (RNN) theo kiểu online, không cần feature engineering thủ công theo domain. Đề xuất kiến
trúc RNN phân tầng (tiered) để mô hình hoá chuỗi hành động của user theo thời gian, đánh giá trên bộ dữ
liệu CERT Insider Threat v6.2. Tham khảo cách chia "cửa sổ hành vi theo thời gian" cho 1 entity, dù đề
tài không dùng RNN mà dùng đặc trưng tổng hợp trên cửa sổ trượt.
Nguồn: https://www.semanticscholar.org/paper/bac292286c7d12df6863c7ca8dec720ed6288302

## 5. TraceAnomaly / DeepTraLog — phát hiện bất thường trên trace microservice
- **TraceAnomaly** (ISSRE 2020): biểu diễn mỗi trace thành vector, dùng deep Bayesian network (VAE có
  posterior flow) học không giám sát để phát hiện trace bất thường, có thêm định vị nguyên nhân gốc dựa
  trên vector trace theo service.
- **DeepTraLog** (ICSE 2022): kết hợp CẢ trace lẫn log trong một đồ thị thống nhất (giữ cấu trúc lời gọi
  song song/bất đồng bộ mà cách biểu diễn "chuỗi tuần tự" bỏ sót), huấn luyện Gated Graph Neural Network
  theo deep SVDD, đạt precision 0.93/recall 0.97.
Tham khảo cách 2 công trình này định nghĩa "đơn vị phân tích" (1 trace / 1 cửa sổ lời gọi giữa các
service) và trích đặc trưng cấu trúc lời gọi — đề tài áp dụng ý tưởng "cửa sổ lời gọi" nhưng dùng đặc
trưng tổng hợp dạng bảng (XGBoost) thay vì graph neural network.
Nguồn: https://github.com/NetManAIOps/TraceAnomaly ; https://ieeexplore.ieee.org/document/9793918/

## 6. UNICORN / ProvDetector — provenance graph cho APT/malware ẩn danh
- **UNICORN** (NDSS 2020): dùng đồ thị provenance (quan hệ tiến trình–tài nguyên hệ điều hành theo thời
  gian) để phát hiện APT kiểu "low-and-slow", nén lịch sử thực thi dài thành "sketch" gọn bằng thuật toán
  kiểu Weisfeiler-Lehman, học không giám sát, không cần signature.
- **ProvDetector** ("You Are What You Do", NDSS): chọn lọc phần khả nghi trong provenance graph của 1
  tiến trình rồi dùng neural embedding + ML để phát hiện hành vi lệch chuẩn, đạt F1 ≈ 0.974 trên
  malware ẩn danh (impersonate tiến trình hợp lệ).
Chỉ cần nắm ý tưởng "quan hệ theo thời gian giữa các thực thể" để viết phần "công trình liên quan chưa
khai thác được gì": cả hai đều ở mức hệ điều hành/tiến trình, chưa áp dụng cho lớp API/service Zero
Trust như đề tài, và đều dùng graph learning nặng hơn nhiều so với đặc trưng bảng dự kiến của đề tài.
Nguồn: https://arxiv.org/abs/2001.01525 ; https://www.ndss-symposium.org/ndss-paper/you-are-what-you-do-hunting-stealthy-malware-via-data-provenance-analysis/

## 7. Arp et al. — "Dos and Don'ts of Machine Learning in Computer Security" (USENIX Security 2022)
Khảo sát 30 bài báo bảo mật hàng đầu trong 10 năm, chỉ ra 10 "pitfall" phổ biến khi làm ML cho bảo mật
(ví dụ: data leakage giữa train/test do chia ngẫu nhiên thay vì theo thời gian, spurious correlation,
đánh giá không thực tế với base rate...) — các pitfall này khiến hiệu năng công bố "ảo", không phản ánh
đúng khi triển khai thật. **Bắt buộc áp dụng trực tiếp ở Bước 4**: đề tài chia train/test theo trục thời
gian (không random) + có buffer quanh điểm cắt, đúng khuyến nghị chống leakage của bài này.
Nguồn: https://www.usenix.org/system/files/sec22summer_arp.pdf

## 8. Pendlebury et al. — TESSERACT (USENIX Security 2019)
Chỉ ra rằng đánh giá phân loại malware theo kiểu chia tập ngẫu nhiên (random split) tạo ra bias thử
nghiệm (spatial bias, temporal bias) khiến kết quả công bố cao giả tạo so với thực tế khi mô hình gặp
concept drift (malware/hành vi tấn công thay đổi theo thời gian). Đề xuất chia tập nghiêm ngặt theo trục
thời gian để mô phỏng đúng kịch bản triển khai thật (train trên quá khứ, test trên tương lai).
**Áp dụng trực tiếp**: đề tài dùng time-based split có buffer đúng tinh thần TESSERACT thay vì k-fold
ngẫu nhiên.
Nguồn: https://www.usenix.org/system/files/sec19fall_pendlebury_prepub.pdf

## 9. Axelsson — "The Base-Rate Fallacy and the Difficulty of Intrusion Detection" (2000)
Chứng minh bằng định lý Bayes rằng khi tỷ lệ tấn công thật (base rate) trong traffic rất thấp (như thực
tế phát hiện xâm nhập), thì để đạt được P(thật sự là tấn công | hệ thống báo động) cao, hệ thống bắt buộc
phải có tỷ lệ báo động giả (FAR) cực thấp — dù detection rate 99% vẫn có thể vô dụng nếu FAR chỉ 1-10%
trên traffic lớn. **Lý do đề tài không dùng accuracy** làm thước đo chính (vì nhãn dương cực hiếm — base
rate thấp, accuracy sẽ luôn cao giả tạo dù model vô dụng) mà chọn PR-AUC/recall tại FPR cố định.
Nguồn: https://dl.acm.org/doi/10.1145/357830.357849

## 10. Geirhos et al. — "Shortcut Learning in Deep Neural Networks" (Nature Machine Intelligence, 2020)
Nhiều thất bại tưởng như khác nhau của deep learning thực chất cùng một gốc: mô hình học "shortcut" —
quy tắc quyết định đạt điểm cao trên benchmark nhưng không phải bản chất vấn đề, nên fail khi gặp điều
kiện kiểm thử khác đi (ví dụ ví dụ kinh điển: mô hình phân biệt sao/trăng chỉ học VỊ TRÍ vật thể trong
ảnh vì dữ liệu train vô tình tương quan vị trí với nhãn, thay vì học hình dạng). **Áp dụng ở Bước 4**: lý
do đề tài bắt buộc phải test model trên biến thể tấn công CHƯA GẶP (viết script khác cách, không đưa vào
train) — để phân biệt model học "bản chất vượt quyền" hay chỉ học "dấu vết của 1 script cụ thể".
Nguồn: https://arxiv.org/abs/2004.07780

## 11. Lundberg & Lee — SHAP, "A Unified Approach to Interpreting Model Predictions" (NeurIPS 2017)
Thống nhất nhiều phương pháp giải thích mô hình (LIME, DeepLIFT, Shapley value cổ điển từ lý thuyết trò
chơi...) vào một khung chung: SHAP value đo đóng góp công bằng của từng đặc trưng vào một dự đoán cụ thể,
dựa trên trung bình có trọng số qua mọi tổ hợp con của tập đặc trưng. Cách đọc: SHAP value dương/âm cho
biết đặc trưng đó đẩy điểm dự đoán tăng/giảm so với baseline, |SHAP| lớn = đặc trưng quan trọng.
**Dùng ở Bước 4** (`shap_analysis.py`): kiểm tra đặc trưng nào chi phối top-1 SHAP — nếu là đặc trưng
gắn với bố trí thí nghiệm (ví dụ chỉ số liên quan cross-cloud) thay vì bản chất hành vi vượt quyền, đó là
dấu hiệu shortcut learning (liên hệ mục 10).
Nguồn: bài gốc NeurIPS 2017 (Lundberg & Lee), thư viện tham khảo: https://github.com/shap/shap

---

## Tổng hợp cho phần "Công trình liên quan chưa khai thác được gì"
Các công trình phát hiện bất thường trên microservice (mục 5) và trên provenance graph hệ điều hành
(mục 6) đều tập trung ở tầng hạ tầng/trace kỹ thuật (latency, cấu trúc lời gọi, tiến trình OS) — **chưa
khai thác tín hiệu đặc thù của lớp Zero Trust identity-aware** (SPIFFE ID, quyết định PDP, JWT subject)
để phân biệt BOLA/BFLA ở tầng ứng dụng API. Hướng insider-threat dựa trên access log quan hệ (mục 3, 4)
gần với bài toán của đề tài nhất về mặt dữ liệu (bảng, không phải đồ thị), nhưng chưa gắn với ngữ cảnh
Zero Trust (không có PDP decision, không phân biệt end-user JWT subject với workload SPIFFE ID) — đây là
khoảng trống đề tài lấp vào bằng Nhóm đặc trưng B.
