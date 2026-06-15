# BÁO CÁO ĐỒ ÁN CHUYÊN NGÀNH - ZTLab

**Đề tài:** Triển khai hệ thống phát hiện và phản ứng sự cố bảo mật dựa trên Zero Trust cho microservices trong môi trường multi-cloud.

**Sinh viên:** Hoàng Bảo Phước (23521231), Phạm Võ Khánh Hà (23520414)  
**GVHD:** Đỗ Thị Phương Uyên

## 1. Mục tiêu

ZTLab xây dựng một lab multi-cloud thực tế để chứng minh ba năng lực:

1. **Zero Trust enforcement:** không tin IP/nội mạng mặc định; request phải qua JWT user identity, SPIFFE/SPIRE workload identity, Envoy/OPA policy và fraud integrity gate.
2. **Security detection:** log từ AWS/OpenStack được tập trung về Loki/Grafana; AI Analyzer phân loại log và nhận diện attack type.
3. **Controlled response:** high/critical alert đi qua HITL; admin approve thì SOAR Engine mới thực thi playbook trên Kubernetes/Keycloak.

## 2. Kiến trúc triển khai

```text
AWS K3s cluster
  web-portal, api-gateway, payment-service, fraud-detection,
  notification-service, Keycloak, OPA, SPIRE, Loki/Grafana,
  AI Analyzer, SOAR Engine

OpenStack K3s cluster
  core-banking, account-service, transaction-service,
  PostgreSQL accounts/ledger, OPA/SPIRE agent

Cross-cloud
  payment-service -> Envoy mTLS/SVID -> 10.10.1.12:30081 -> core-banking
```

Các context vận hành:

| Context | Vai trò | Tunnel local |
|---|---|---|
| `ctx-aws` | AWS K3s | `127.0.0.1:6444` |
| `ctx-openstack` | OpenStack K3s | `127.0.0.1:6445` |

## 3. Thành phần bảo mật

| Thành phần | Vai trò |
|---|---|
| Keycloak | OIDC/JWT RS256, user roles |
| API Gateway | JWKS verify, fail-closed, rate limit, role check |
| Envoy | Policy Enforcement Point, access log, mTLS outbound/inbound |
| OPA | Rego policy cho public path, bearer edge path, SVID và fraud gate |
| SPIFFE/SPIRE | Cấp SVID X.509 cho workload |
| Fraud Detection | Chấm điểm rủi ro giao dịch; Redis ZSET velocity tracking per-account |
| HMAC Fraud Gate | Payment ký gate; Core Banking verify signature để chống forged header |
| Promtail/Loki/Grafana | SIEM log tập trung và dashboard/alert |
| AI Analyzer | Phân tích log, tạo pending alert |
| SOAR Engine | Playbook response có audit/rollback |

## 4. Luồng thanh toán bảo mật

```text
User -> Web Portal/API Gateway
  -> Keycloak JWT
  -> API Gateway verify JWT + role financial-write
  -> Envoy/OPA kiểm policy
  -> Payment Service
  -> Fraud Detection score
  -> Payment ký X-Fraud-Gate-Signature bằng CORE_BANKING_SHARED_SECRET
  -> Envoy mTLS cross-cloud
  -> Core Banking verify gate + score + HMAC
  -> Account Service atomic transfer
  -> Transaction Service ledger
  -> Notification Service
```

Điều kiện Core Banking execute:

- `X-Fraud-Gate: passed`.
- `X-Fraud-Score <= 74`.
- `X-Fraud-Gate-Signature` khớp HMAC SHA-256 trên canonical payload.

## 5. Luồng phát hiện và phản ứng

```text
Logs -> Promtail -> Loki -> AI Analyzer
  -> severity low/medium: ghi nhận
  -> severity high/critical: pending alert
  -> admin approve/dismiss
  -> approve: SOAR Engine execute playbook
  -> case audit: /data/cases.jsonl + Loki
```

TheHive/Cassandra đã được loại khỏi runtime để giảm RAM; case management hiện nằm trong SOAR Engine.

## 6. Các cải tiến bảo mật đã hoàn thiện

- Bỏ fallback HS256 tự động ở API Gateway; dev token chỉ opt-in.
- Gateway fail-closed khi không verify được token.
- Web Portal không lưu token trong cookie client-side; dùng OIDC Authorization Code + PKCE (S256).
- Bỏ default password nhạy cảm ở code path admin Keycloak/SOAR.
- Chuyển secret Keycloak manifest sang example placeholder; deploy script tự tạo secret từ env hoặc random.
- Bổ sung HMAC fraud gate giữa Payment và Core Banking.
- OPA không cấp quyền dựa trên JWT decode chưa verify.
- Full-suite harness dùng port riêng `19180-19187` và fail nếu port bị chiếm.
- AI Analyzer nhận diện 12 attack type: `access_denied`, `fraud_gate_bypass`, `brute_force`, `lateral_movement`, `port_scan`, `privilege_escalation`, `credential_stuffing`, `jwt_replay`, `container_escape`, `cryptomining`, `exploit_probe`, `large_response`.
- Cross-cloud Loki relay: socat systemd service trên AWS worker chuyển tiếp push từ OpenStack Promtail → Loki ClusterIP; cả hai cloud đều có label `cloud=aws/openstack` trong Loki.
- Redis ZSET velocity tracking: mỗi account có key `fraud:velocity:{id}` (sliding window 60s, TTL 120s); Web Portal `/logs` có panel Redis Velocity tự refresh 15s.

## 7. Kết quả kiểm thử gần nhất

Health-check tổng:

```text
PASS=35 WARN=4 FAIL=0
```

Ý nghĩa:

- Local PLG, Loki, Grafana, AI Analyzer, SOAR: pass.
- OpenStack Kubernetes và financial workloads: pass.
- Loki có đủ stream AI alert, SOAR action, raw demo.
- Warning còn lại chủ yếu là remote SSH skipped và AWS Kubernetes API/tunnel timeout khi hạ tầng AWS master/bastion không phản hồi ổn định.

Các test bảo mật cần chạy sau khi AWS context ổn định:

```bash
BASELINE_SECONDS=30 \
LOKI_URL=http://127.0.0.1:3100 \
AI_URL=http://127.0.0.1:8090 \
SOAR_URL=http://127.0.0.1:8091 \
python3 tests/scenario_00_full_suite.py
```

## 8. Tiêu chí đạt khi demo

| Tiêu chí | Cách chứng minh |
|---|---|
| JWT thật hoạt động | Lấy token Keycloak và payment trả `completed` |
| JWT giả bị chặn | Scenario `JWT giả mạo` hoặc curl fake token trả 401 |
| Fraud gate block | Scenario `Fraud Gate Block` trả 403, `score=85, gate=blocked` |
| Direct core bypass bị chặn | curl core-banking với HMAC giả trả 403 |
| Cross-cloud trace | Loki thấy cùng `trace_id` ở `cloud=aws` và `cloud=openstack` |
| Velocity tracking | Chạy 10+ payment nhanh, xem Redis Velocity UI tại `/logs` |
| AI detection brute force | Scenario `Brute Force Login` → `verdict=malicious, severity=high` |
| AI detection đa dạng | Scenario Port Scan / Credential Stuffing / Cryptomining → pending alert |
| HITL | Tab `Chờ duyệt` tại `/alerts`, admin dismiss/approve được |
| SOAR audit | `/cases` có case và Loki có `event_type=soar_action` |

## 9. Giới hạn hiện tại

- Đây là lab, không phải production HA.
- Session Web Portal server-side đang lưu memory; pod restart sẽ mất session.
- Một số service nội bộ OpenStack vẫn plain HTTP trong namespace sau Core Banking.
- OpenStack SPIRE agent dùng join token, có thể cần refresh sau restart lâu.
- AWS tunnel/API phụ thuộc bastion và trạng thái EC2 master; khi `ctx-aws` timeout cần xử lý hạ tầng trước khi chạy full suite.
- Cross-cloud Loki relay dùng socat plain TCP (không TLS); đủ cho lab nhưng cần mTLS/TLS khi mở rộng production.

## 10. Hướng phát triển

- Dùng Redis/PostgreSQL cho Web Portal session store.
- Chuyển OpenStack SPIRE attestation sang cơ chế bền hơn join token.
- Tách secrets hoàn toàn sang external secret manager.
- Bổ sung mTLS nội bộ cho account-service và transaction-service.
- Chuẩn hóa CI chạy unit/security tests trước khi build image.
- Bổ sung dashboard SLA cho MTTD/MTTR và coverage MITRE.

## 11. Tài liệu vận hành

- `README.md`: tổng quan và quick start.
- `HUONG_DAN.md`: checklist vận hành/test từ đầu.
- `BAOCAO_FLOW_HE_THONG.md`: flow input/output chi tiết.
- `MAP.md`: bản đồ file trong repo.
