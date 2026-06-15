## **Bước 1\. Người dùng truy cập hệ thống**

Người dùng sử dụng trình duyệt web để truy cập hệ thống thông qua Internet. Request đầu tiên được gửi đến Traefik Ingress Controller, đây là thành phần đóng vai trò điểm vào tập trung của toàn bộ hệ thống. Traefik tiếp nhận request từ bên ngoài, thực hiện định tuyến dựa trên hostname và chuyển tiếp request đến Web Portal tương ứng. Tại thời điểm này hệ thống chưa xử lý bất kỳ nghiệp vụ nào mà chỉ cung cấp giao diện ban đầu cho người dùng.

**Input:** HTTP/HTTPS Request từ trình duyệt.

**Output:** Giao diện Web Portal hoặc Login Page.

**Generated Log:** Traefik Access Log ghi nhận địa chỉ IP nguồn, thời gian truy cập, đường dẫn truy cập và trạng thái phản hồi.

## **Bước 2\. Xác thực người dùng thông qua Keycloak**

Khi người dùng lựa chọn đăng nhập, Web Portal chuyển hướng đến Keycloak để thực hiện xác thực danh tính. Keycloak đóng vai trò Identity Provider trong kiến trúc Zero Trust, chịu trách nhiệm quản lý tài khoản, phân quyền và phát hành token. Người dùng nhập tên đăng nhập và mật khẩu, sau đó Keycloak kiểm tra thông tin này với Realm đã được cấu hình. Nếu xác thực thành công, Keycloak tạo JWT Access Token chứa thông tin định danh như User ID, Username, Role và thời gian hết hạn của phiên làm việc.

JWT Token là bằng chứng xác thực được sử dụng trong toàn bộ các request tiếp theo và giúp các thành phần phía sau có thể xác định được danh tính cũng như quyền hạn của người dùng mà không cần xác thực lại.

**Input:** Username và Password.

**Output:** JWT Access Token.

**Generated Log:** Authentication Log ghi nhận trạng thái đăng nhập, tài khoản sử dụng, thời gian đăng nhập và địa chỉ IP nguồn.

## **Bước 3\. Người dùng gửi yêu cầu nghiệp vụ**

Sau khi đăng nhập thành công, trình duyệt lưu trữ JWT Token và sử dụng token này trong các request nghiệp vụ tiếp theo. Khi người dùng thực hiện một thao tác như chuyển tiền, Browser gửi HTTP Request đến API Gateway và đính kèm JWT trong Authorization Header.

Dữ liệu gửi đi thường bao gồm thông tin tài khoản nguồn, tài khoản đích, số tiền giao dịch và các tham số nghiệp vụ liên quan. API Gateway đóng vai trò là điểm vào duy nhất của hệ thống, do đó mọi request từ bên ngoài đều phải đi qua thành phần này trước khi được phép truy cập các microservice nội bộ.

**Input:** HTTP Request chứa JWT Token và dữ liệu giao dịch.

**Output:** Request được chuyển đến API Gateway để kiểm tra bảo mật.

**Generated Log:** API Access Log ghi nhận Endpoint, User ID, Request Method và thời gian truy cập.

## **Bước 4\. API Gateway xác thực và kiểm soát truy cập**

API Gateway là lớp bảo vệ đầu tiên của hệ thống. Khi nhận request, Gateway sử dụng public key hoặc JWKS được cung cấp bởi Keycloak để xác thực chữ ký của JWT. Đồng thời Gateway kiểm tra thời gian hết hạn của token, vai trò của người dùng và các chính sách giới hạn tốc độ truy cập (Rate Limiting).

Nếu token không hợp lệ hoặc đã hết hạn, Gateway trả về lỗi 401 Unauthorized. Nếu token hợp lệ nhưng người dùng không có đủ quyền truy cập vào tài nguyên được yêu cầu, Gateway trả về lỗi 403 Forbidden. Chỉ những request vượt qua tất cả các bước kiểm tra mới được phép đi tiếp vào hệ thống nội bộ.

Ngoài chức năng bảo mật, Gateway còn sinh Trace ID để theo dõi giao dịch xuyên suốt toàn bộ hệ thống và ghi nhận các audit log phục vụ công tác điều tra sau này.

Trong implementation hiện tại, API Gateway là thành phần chịu trách nhiệm xác thực JWT trước khi request được chuyển đến OPA. Gateway kiểm tra chữ ký RS256 bằng public key/JWKS của Keycloak, kiểm tra thời gian hết hạn và trích xuất các claim đã được xác thực như user\_id, username, role và scope. Sau bước này, OPA không trực tiếp cấp quyền dựa trên JWT chưa được verify mà chỉ nhận các metadata đã đáng tin cậy từ Gateway hoặc Envoy để đánh giá chính sách truy cập. Cách thiết kế này giúp tách biệt rõ Authentication và Authorization, đồng thời tránh nguy cơ hệ thống đưa ra quyết định dựa trên JWT giả mạo.

**Input:** JWT Token, Request Path, HTTP Method và User Role.

**Output:** Authorized Request hoặc lỗi 401/403.

**Generated Log:** Authorization Log, Audit Log và Rate Limiting Log.

## **Bước 5\. Envoy Sidecar thu thập metadata và thực thi chính sách**

Sau khi vượt qua API Gateway, request được chuyển đến Payment Service thông qua Envoy Sidecar. Trong kiến trúc Zero Trust, Envoy đóng vai trò Policy Enforcement Point (PEP), chịu trách nhiệm thực thi các quyết định bảo mật trước khi request được phép tiếp cận logic nghiệp vụ của service.

Envoy thu thập các metadata liên quan đến request như nguồn gửi, đích đến, HTTP Method, Request Path, JWT Claims, Service Identity và Trace ID. Các thông tin này được sử dụng làm dữ liệu đầu vào cho quá trình đánh giá chính sách của OPA thông qua cơ chế ext\_authz. Việc kiểm tra này giúp bảo đảm chỉ những request đáp ứng đầy đủ các yêu cầu về danh tính, quyền truy cập và chính sách bảo mật mới được phép tiếp tục xử lý.

**Input:** Authorized Request từ API Gateway.

**Output:** Authorization Query gửi đến OPA.

**Generated Log:** Envoy Access Log, Metadata Collection Log và Authorization Request Log.

## **Bước 6\. OPA đánh giá chính sách truy cập**

OPA (Open Policy Agent) đóng vai trò Policy Decision Point (PDP) trong kiến trúc Zero Trust. OPA không thực hiện xác thực chữ ký JWT trực tiếp trong bước này. Thay vào đó, OPA nhận các thông tin đã được API Gateway xác thực trước đó, bao gồm role, user identity, request path, HTTP method và service identity. Dựa trên các dữ liệu này, OPA đánh giá policy Rego để quyết định request có được phép tiếp tục hay không.

Quá trình đánh giá có thể bao gồm nhiều điều kiện như vai trò của người dùng, loại dịch vụ được phép truy cập, API Path được yêu cầu, nguồn phát sinh request và các thuộc tính bảo mật khác. Sau khi hoàn tất quá trình đánh giá, OPA trả về kết quả Allow hoặc Deny cho Envoy.

Nếu quyết định là Deny, request sẽ bị chặn ngay lập tức. Nếu quyết định là Allow, request sẽ được chuyển tiếp đến Payment Service để xử lý nghiệp vụ.

**Input:** Request Metadata, JWT Claims, Service Identity.

**Output:** Policy Decision (Allow hoặc Deny).

**Generated Log:** Policy Decision Log ghi nhận policy được áp dụng, kết quả đánh giá và lý do cho phép hoặc từ chối truy cập.

## **Bước 7\. Envoy xử lý kết quả từ OPA và chuyển tiếp request**

Sau khi nhận được kết quả đánh giá chính sách từ OPA, Envoy tiến hành thực thi quyết định tương ứng. Nếu OPA trả về kết quả Deny, Envoy sẽ chặn request và phản hồi lỗi 403 Forbidden về phía API Gateway. Điều này giúp ngăn chặn các yêu cầu không được phép trước khi chúng tiếp cận các thành phần nghiệp vụ quan trọng.

Ngược lại, nếu OPA trả về kết quả Allow, Envoy sẽ forward request đến Payment Service. Tại thời điểm này request đã vượt qua hai lớp kiểm soát bảo mật gồm xác thực người dùng tại API Gateway và kiểm soát chính sách tại OPA. Request được xem là hợp lệ để bắt đầu xử lý nghiệp vụ tài chính.

**Input:** Policy Decision từ OPA.

**Output:** Forward Request hoặc Reject Response.

**Generated Log:** Envoy Authorization Log ghi nhận kết quả allow/deny, service đích và Trace ID của giao dịch.

## **Bước 8\. Payment Service tiếp nhận yêu cầu giao dịch**

Payment Service là thành phần trung tâm chịu trách nhiệm điều phối luồng xử lý giao dịch. Khi nhận request từ Envoy, service thực hiện kiểm tra cấu trúc dữ liệu, xác minh các trường bắt buộc và chuẩn hóa dữ liệu đầu vào. Các thông tin được tiếp nhận bao gồm tài khoản nguồn, tài khoản đích, số tiền giao dịch và thông tin người dùng đã được xác thực từ JWT Token.

Sau khi dữ liệu được xác nhận hợp lệ, Payment Service sinh Transaction ID và Trace ID để phục vụ việc theo dõi giao dịch xuyên suốt hệ thống. Tuy nhiên, giao dịch chưa được thực hiện ngay mà cần trải qua bước đánh giá rủi ro từ Fraud Detection Service.

**Input:** Transaction Request chứa thông tin giao dịch.

**Output:** Fraud Assessment Request.

**Generated Log:** Transaction Received Log chứa Transaction ID, User ID, Amount, Timestamp và trạng thái ban đầu của giao dịch.

## **Bước 9\. Fraud Detection Service đánh giá rủi ro giao dịch**

Payment Service gửi thông tin giao dịch sang Fraud Detection Service để đánh giá mức độ rủi ro. Thành phần này đóng vai trò lớp bảo vệ nghiệp vụ, giúp phát hiện các giao dịch bất thường trước khi chúng được chuyển đến hệ thống Core Banking.

Fraud Detection Service phân tích các thuộc tính của giao dịch như số tiền, tần suất giao dịch, tài khoản nguồn, tài khoản đích và các mẫu hành vi đã được định nghĩa trong hệ thống. Dựa trên các rule hiện có, hệ thống tính toán Risk Score và đưa ra Fraud Decision.

Kết quả trả về có thể là Allow nếu giao dịch được xem là an toàn hoặc Deny/Review nếu phát hiện dấu hiệu đáng ngờ.

**Input:** Transaction Information.

**Output:** Risk Score và Fraud Decision.

**Generated Log:** Fraud Assessment Log chứa Transaction ID, Risk Score, Fraud Decision và Rule Triggered.

## **Bước 10\. Payment Service xử lý kết quả Fraud Detection**

Sau khi nhận được kết quả đánh giá từ Fraud Detection Service, Payment Service quyết định có tiếp tục giao dịch hay không. Nếu Fraud Decision là Deny hoặc Risk Score vượt ngưỡng cho phép, giao dịch bị từ chối và kết quả được trả về người dùng.

Nếu giao dịch được chấp nhận, Payment Service bổ sung Fraud Metadata vào request bao gồm Fraud Score, Fraud Gate Status và Fraud Gate Signature. Fraud Gate Signature được tạo bằng thuật toán HMAC SHA-256 sử dụng khóa bí mật dùng chung giữa Payment Service và Core Banking Service. Chữ ký này được sinh trên dữ liệu giao dịch đã chuẩn hóa nhằm bảo đảm rằng thông tin Fraud Metadata không bị chỉnh sửa trong quá trình truyền qua môi trường liên đám mây.

Việc bổ sung Fraud Gate Signature giúp Core Banking có thể xác minh tính toàn vẹn của request trước khi thực hiện giao dịch, đồng thời ngăn chặn các trường hợp giả mạo header hoặc bypass lớp Fraud Detection.

**Input:** Risk Score và Fraud Decision.

**Output:** Validated Transaction Request chứa X-Fraud-Gate, X-Fraud-Score và X-Fraud-Gate-Signature.

**Generated Log:** Fraud Validation Log ghi nhận Risk Score, Fraud Decision, Signature Generation Status và Transaction ID.

## **Bước 11\. Thiết lập kết nối bảo mật giữa AWS và OpenStack**

Payment Service nằm trong cụm AWS trong khi Core Banking nằm trong cụm OpenStack. Do đó, request cần đi qua kết nối liên đám mây (Cross-Cloud Communication). Việc truyền dữ liệu được thực hiện thông qua WireGuard Tunnel nhằm tạo ra một kênh mạng riêng được mã hóa giữa hai môi trường.

Bên cạnh đó, Envoy Sidecar sử dụng SPIFFE/SPIRE để xác thực danh tính workload. Mỗi service được cấp một SPIFFE ID và SVID Certificate. Trước khi request được truyền sang OpenStack, hai phía thực hiện quá trình xác thực hai chiều bằng mTLS. Chỉ những workload có danh tính hợp lệ mới được phép thiết lập kết nối.

Cơ chế này giúp loại bỏ việc tin tưởng dựa trên địa chỉ IP và thay thế bằng mô hình xác thực dựa trên danh tính dịch vụ theo đúng nguyên tắc Zero Trust.

**Input:** Transaction Request và Workload Identity.

**Output:** Secure Cross-Cloud Request.

**Generated Log:** mTLS Connection Log, SPIFFE Authentication Log và WireGuard Tunnel Log.

## **Bước 12\. Core Banking Service tiếp nhận giao dịch**

Sau khi request đến cụm OpenStack, Core Banking Service là thành phần đầu tiên tiếp nhận giao dịch. Core Banking thực hiện kiểm tra Fraud Metadata được gửi từ Payment Service, bao gồm Fraud Gate Status, Fraud Score và Fraud Gate Signature.

Hệ thống sử dụng cùng khóa bí mật đã được cấu hình giữa hai phía để xác minh chữ ký HMAC SHA-256. Nếu chữ ký không hợp lệ, Fraud Gate không ở trạng thái "passed" hoặc Fraud Score vượt quá ngưỡng cho phép, Core Banking sẽ từ chối giao dịch và ghi nhận sự kiện bảo mật tương ứng.

Chỉ khi toàn bộ các điều kiện kiểm tra đều hợp lệ, Core Banking mới tiếp tục xử lý nghiệp vụ ngân hàng lõi. Sau đó Core Banking đóng vai trò điều phối các service phía sau như Account Service và Transaction Service để hoàn thành giao dịch.

**Input:** Validated Transaction Request, X-Fraud-Gate, X-Fraud-Score và X-Fraud-Gate-Signature.

**Output:** Internal Banking Processing Request.

**Generated Log:** Core Banking Validation Log, Fraud Verification Log, HMAC Verification Log và Business Policy Log.

## **Bước 13\. Core Banking gọi Account Service**

Để xác minh khả năng thực hiện giao dịch, Core Banking gửi yêu cầu đến Account Service. Thành phần này chịu trách nhiệm quản lý dữ liệu tài khoản và làm việc trực tiếp với PostgreSQL Account Database.

Khi nhận được Account ID và thông tin giao dịch, Account Service thực hiện truy vấn đến Postgres-Account để lấy thông tin tài khoản nguồn, số dư hiện tại và trạng thái tài khoản. Đây là cơ sở dữ liệu lưu trữ toàn bộ dữ liệu liên quan đến khách hàng và tài khoản ngân hàng trong hệ thống.

Nếu tài khoản không tồn tại, đang bị khóa hoặc số dư khả dụng không đủ để thực hiện giao dịch, Account Service trả về lỗi cho Core Banking và giao dịch bị dừng lại. Ngược lại, nếu tài khoản hợp lệ, Account Service thực hiện cập nhật số dư tài khoản nguồn và tài khoản đích trong cùng một transaction database nhằm bảo đảm tính nguyên tử (Atomicity). Điều này có nghĩa là hoặc toàn bộ thay đổi được ghi thành công, hoặc toàn bộ giao dịch bị rollback nếu xảy ra lỗi trong quá trình xử lý, từ đó tránh phát sinh trạng thái dữ liệu không nhất quán.

Sau khi cập nhật thành công, Account Service trả về thông tin số dư mới và trạng thái xử lý cho Core Banking để tiếp tục bước ghi nhận giao dịch.

**Input:** Account ID, Transaction Amount và Transaction Context.

**Output:** Account Information, Balance Validation Result và Updated Balance.

**Generated Log:** Account Lookup Log, Balance Validation Log và Balance Update Log.

**Database Interaction:**

* Đọc dữ liệu từ Postgres-Account để kiểm tra tài khoản.

* Cập nhật số dư tài khoản nguồn và tài khoản đích.

* Ghi nhận thời gian cập nhật và trạng thái giao dịch.

## **Bước 14\. Core Banking gọi Transaction Service**

Sau khi Account Service cập nhật số dư thành công, Core Banking gửi thông tin giao dịch đến Transaction Service. Thành phần này chịu trách nhiệm lưu trữ lịch sử giao dịch và làm việc trực tiếp với PostgreSQL Transaction Database.

Transaction Service tạo Transaction ID duy nhất, ghi nhận thời gian thực hiện, số tiền giao dịch, tài khoản nguồn, tài khoản đích và trạng thái xử lý. Tất cả thông tin này được lưu vào Postgres-Txn nhằm tạo ra transaction ledger phục vụ truy vết, kiểm toán và hiển thị lịch sử giao dịch trên Web Portal.

Khác với Account Service chịu trách nhiệm quản lý số dư, Transaction Service tập trung vào việc lưu trữ transaction record và audit trail. Điều này giúp tách biệt dữ liệu nghiệp vụ tài khoản và dữ liệu lịch sử giao dịch theo đúng kiến trúc Microservices.

Sau khi ghi dữ liệu thành công, Transaction Service trả về Transaction ID và trạng thái xử lý cho Core Banking.

**Input:** Transaction Detail, Updated Account Information và Transaction Context.

**Output:** Transaction ID và Transaction Status.

**Generated Log:** Transaction Commit Log, Ledger Log, Audit Log và Transaction Persistence Log.

**Database Interaction:**

* Ghi transaction record vào Postgres-Txn.

* Ghi audit trail phục vụ điều tra và kiểm toán.

* Lưu trạng thái giao dịch (pending, completed, failed).

* Cung cấp dữ liệu cho Dashboard và lịch sử giao dịch trên Web Portal.

## **Bước 15\. Core Banking tổng hợp kết quả giao dịch**

Core Banking nhận kết quả từ Transaction Service và tổng hợp phản hồi cuối cùng của giao dịch. Thông tin phản hồi bao gồm Transaction ID, trạng thái giao dịch và các thông báo lỗi nếu có.

Tại thời điểm này giao dịch đã được xử lý hoàn chỉnh trong hệ thống ngân hàng lõi và kết quả được gửi ngược trở lại Payment Service thông qua kênh kết nối bảo mật đã được thiết lập trước đó.

**Input:** Transaction Execution Result.

**Output:** Banking Response.

**Generated Log:** Transaction Completed Log.

## **Bước 16\. Payment Service gửi thông báo cho người dùng**

Khi giao dịch thành công, Payment Service gửi thông tin sang Notification Service để tạo thông báo cho người dùng. Notification Service có thể sinh Email Notification, SMS Notification hoặc System Notification tùy thuộc vào cấu hình của hệ thống.

Nội dung thông báo thường bao gồm Transaction ID, số tiền giao dịch, thời gian thực hiện và trạng thái giao dịch. Điều này giúp người dùng nhận biết ngay kết quả xử lý mà không cần thực hiện truy vấn lại hệ thống.

**Input:** Transaction Status và User Information.

**Output:** Notification Message.

**Generated Log:** Notification Log ghi nhận trạng thái gửi thông báo.

## **Bước 17\. Trả kết quả cuối cùng cho người dùng**

Sau khi hoàn tất toàn bộ quá trình xử lý, Payment Service trả kết quả về API Gateway. API Gateway tiếp tục chuyển response đến Web Portal và cuối cùng trình duyệt hiển thị kết quả cho người dùng.

Response cuối cùng thường chứa Transaction ID, trạng thái giao dịch và thông báo tương ứng. Đây là điểm kết thúc của luồng xử lý nghiệp vụ.

Toàn bộ quá trình từ khi người dùng gửi request cho đến khi nhận phản hồi đều được theo dõi bằng Trace ID và được ghi log tại các thành phần trung gian nhằm phục vụ giám sát, điều tra và kiểm toán.

Ngoài luồng chuyển tiền, khi người dùng truy cập Dashboard, Web Portal gửi yêu cầu truy vấn thông tin tài khoản và lịch sử giao dịch thông qua API Gateway. Các yêu cầu này được Core Banking điều phối đến Account Service và Transaction Service tương ứng. Account Service truy xuất dữ liệu từ Postgres-Account để lấy số dư hiện tại, trong khi Transaction Service truy xuất dữ liệu từ Postgres-Txn để lấy danh sách giao dịch gần nhất. Kết quả được trả về Web Portal và hiển thị trên Dashboard dưới dạng số dư tài khoản, trạng thái hệ thống và lịch sử giao dịch của người dùng.

**Input:** Final Transaction Result.

**Output:** Transaction Response hiển thị trên Web Portal.

**Generated Log:** Response Log, Audit Log và Transaction Summary Log.

# **Luồng giám sát và phản ứng bảo mật**

Trong quá trình vận hành hệ thống, tất cả các thành phần bao gồm Traefik, Keycloak, API Gateway, Envoy, OPA, Payment Service, Fraud Detection Service, Core Banking, Account Service và Transaction Service đều liên tục sinh log. Các log này chứa thông tin xác thực người dùng, quyết định phân quyền, hoạt động giao dịch, trạng thái hệ thống và các sự kiện bảo mật.

Promtail chịu trách nhiệm thu thập log từ các container và Kubernetes Pods trong cả môi trường AWS và OpenStack. Sau khi được chuẩn hóa và gắn nhãn, log được gửi đến Loki để lưu trữ tập trung. Grafana sử dụng Loki làm nguồn dữ liệu nhằm trực quan hóa log, xây dựng dashboard giám sát và hỗ trợ truy vấn sự kiện theo thời gian thực.

AI Analyzer định kỳ truy vấn Loki để lấy các sự kiện mới nhất. Hệ thống sử dụng tập luật và mô hình phân loại để nhận diện các hành vi bất thường như access denied, brute force, credential stuffing, JWT replay hoặc các dấu hiệu tấn công khác. Kết quả phân tích bao gồm loại tấn công, mức độ nghiêm trọng và độ tin cậy của cảnh báo.

Đối với các sự kiện có mức độ Low hoặc Medium, hệ thống chỉ ghi nhận và lưu trữ phục vụ theo dõi. Đối với các sự kiện High hoặc Critical, AI Analyzer tạo Pending Alert và chuyển đến giao diện Human-in-the-Loop. Security Analyst có thể xem chi tiết log liên quan, đánh giá cảnh báo và lựa chọn Approve hoặc Dismiss.

Nếu cảnh báo bị từ chối, hệ thống chỉ lưu lại lịch sử xử lý. Nếu cảnh báo được phê duyệt, SOAR Engine sẽ thực thi playbook tương ứng như khóa tài khoản, thu hồi phiên đăng nhập, chặn IP nguồn hoặc áp dụng các biện pháp phản ứng khác tùy theo loại sự kiện. Toàn bộ hành động của SOAR được ghi nhận vào Loki và lưu dưới dạng case audit nhằm phục vụ điều tra, truy vết và đánh giá hiệu quả phản ứng sự cố sau này.

**Input:** Security Log, Authentication Log, Authorization Log, Transaction Log và System Event.

**Output:** Security Alert, Pending Alert, SOAR Action và Audit Case.

**Generated Log:** AI Analysis Log, Alert Log, SOAR Action Log và Audit Log.

