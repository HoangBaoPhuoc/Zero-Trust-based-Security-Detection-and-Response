mddeployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash tests/grafana_kb1_brute_force.sh
[KB1_brute_force] Bước 1: kiểm tra Keycloak và SOAR...
[KB1_brute_force] Bước 2: gửi 20 lần đăng nhập sai mật khẩu...
[KB1_brute_force] Keycloak chặn 20/20 — xác thực Zero Trust hoạt động đúng
[KB1_brute_force] Bước 3: đẩy envoy-access log vào Loki (Grafana query: job=envoy-access, response_code=401)...
[KB1_brute_force] 5 log 401 đã vào Loki — Grafana rule sẽ evaluate trong ≤1 phút
[KB1_brute_force] Bước 4: mô phỏng Grafana 'Brute Force Login' alert → SOAR webhook...
[KB1_brute_force] Bước 5: kiểm tra SOAR case được tạo...
[KB1_brute_force] PASS: KB1 Brute Force | blocked=20/20 | SOAR case=case-20260627041323-kb1-17 status=pending_approval playbook=revoke_user_sessions (T1110.001)
[KB1_brute_force] → Kiểm tra Web Portal http://localhost:18081/security để phê duyệt/từ chối
[KB1_brute_force] → Admin nhận email HITL tại voha2005@gmail.com nếu SMTP được cấu hình
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ curl -s http://localhost:8091/cases | python3 -c "
import sys, json
cases = json.load(sys.stdin)
brute = [c for c in cases if c['attack_type'] == 'brute_force']
if brute:
    c = brute[-1]
    print(f'case_id : {c[\"case_id\"]}')
    print(f'status  : {c[\"status\"]}')
    print(f'playbook: {c[\"playbook\"]}')
    print(f'steps   : {c[\"steps\"]}')
"
case_id : case-20260627041323-kb1-17
status  : executed
playbook: revoke_user_sessions
steps   : [{'phase': 'contain', 'status': 'completed', 'action': 'skipped: no username in alert', 'ts': '2026-06-27T04:16:30.403131+00:00', 'error': None}, {'phase': 'investigate', 'status': 'completed', 'action': 'Loki evidence: 10 log entries matched query for brute_force', 'ts': '2026-06-27T04:16:30.504747+00:00', 'error': None}, {'phase': 'eradicate', 'status': 'completed', 'action': 'sessions revoked in contain phase; user must re-authenticate with valid credentials', 'ts': '2026-06-27T04:16:30.504798+00:00', 'error': None}, {'phase': 'recover', 'status': 'completed', 'action': 'pending: admin must trigger POST /cases/{case_id}/rollback to restore service', 'ts': '2026-06-27T04:16:30.504806+00:00', 'error': None}]
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash scripts/run-demo.sh --restore

╔══════════════════════════════════════════════════════════╗
║         ZTLab — Zero Trust Security Demo                 ║
╠══════════════════════════════════════════════════════════╣
║  Grafana  →  http://127.0.0.1:3000                       ║
║  Dashboard: ZTLab AI SIEM SOAR                           ║
╚══════════════════════════════════════════════════════════╝

[DEMO] Restore tất cả services...
  ▶ Restore payment-service (xóa SOAR isolation label)...
service/payment-service patched (no change)
    payment-service: OK
  ▶ Restore api-gateway (replicas=1)...
deployment.apps/api-gateway scaled
    api-gateway: OK
  ▶ Restore core-banking trên OpenStack (replicas=1)...
deployment.apps/core-banking scaled
deployment "core-banking" successfully rolled out
    core-banking: OK
[ OK ] Restore hoàn tất
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash tests/grafana_kb2_fraud_gate.sh
[KB2_fraud_gate] Bước 1: kiểm tra API Gateway và SOAR...
[KB2_fraud_gate] Bước 2: lấy JWT testuser01...
[KB2_fraud_gate] Bước 3: gửi giao dịch 500,000,000 VND qua TOR channel (fraud_score sẽ ≥75)...
[KB2_fraud_gate] API Gateway trả về HTTP 403 (expect 403 — fraud gate blocked)
[KB2_fraud_gate] Fraud gate verdict: ?
[KB2_fraud_gate] Bước 4: đẩy opa-decisions log vào Loki (Grafana query: opa_result=false, attack_scenario=fraud_gate_bypass)...
[KB2_fraud_gate] OPA fraud_gate_bypass log đã vào Loki
[KB2_fraud_gate] Bước 5: mô phỏng Grafana 'Fraud Gate Bypass' alert → SOAR webhook...
[KB2_fraud_gate] Bước 6: kiểm tra SOAR case...
[KB2_fraud_gate] PASS: KB2 Fraud Gate | HTTP 403 blocked | SOAR case=case-20260627041742-kb2-17 status=pending_approval playbook=isolate_workload (T1078.004)
[KB2_fraud_gate] → OPA từ chối: giao dịch vượt ngưỡng fraud_score vì amount+channel vi phạm policy
[KB2_fraud_gate] → Admin nhận email HITL để phê duyệt isolate_workload
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ # Lấy JWT testuser01
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

# Giao dịch 500M VND qua TOR → expect HTTP 403 + fraud block
curl -v -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Channel: tor" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":500000000,"currency":"VND","channel":"tor"}' \
  2>&1 | grep -E "< HTTP|fraud|verdict|score"

# Giao dịch bình thường 10,000 VND → expect HTTP 200
curl -s -o /dev/null -w "Normal payment → HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":10000,"currency":"VND"}'
< HTTP/1.1 403 Forbidden
{"detail":{"reason":"fraud gate blocked","fraud":{"score":75,"verdict":"block","reason":["critical_amount","risky_channel"],"gate":"blocked"}}}
Normal payment → HTTP 503
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ kubectl --context ctx-aws get deployment payment-service -n financial
NAME              READY   UP-TO-DATE   AVAILABLE   AGE
payment-service   1/1     1            1           25d
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ kubectl --context ctx-aws get deployment payment-service -n financial
NAME              READY   UP-TO-DATE   AVAILABLE   AGE
payment-service   1/1     1            1           25d
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ kubectl --context ctx-aws get deployment payment-service -n financial
NAME              READY   UP-TO-DATE   AVAILABLE   AGE
payment-service   1/1     1            1           25d
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash scripts/run-demo.sh --restore
kubectl --context ctx-aws get deployment payment-service -n financial

╔══════════════════════════════════════════════════════════╗
║         ZTLab — Zero Trust Security Demo                 ║
╠══════════════════════════════════════════════════════════╣
║  Grafana  →  http://127.0.0.1:3000                       ║
║  Dashboard: ZTLab AI SIEM SOAR                           ║
╚══════════════════════════════════════════════════════════╝

[DEMO] Restore tất cả services...
  ▶ Restore payment-service (xóa SOAR isolation label)...
service/payment-service patched
    payment-service: OK
  ▶ Restore api-gateway (replicas=1)...
deployment.apps/api-gateway scaled
    api-gateway: OK
  ▶ Restore core-banking trên OpenStack (replicas=1)...
deployment.apps/core-banking scaled
deployment "core-banking" successfully rolled out
    core-banking: OK
[ OK ] Restore hoàn tất
NAME              READY   UP-TO-DATE   AVAILABLE   AGE
payment-service   1/1     1            1           25d
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash tests/grafana_kb3_lateral_movement.sh
[KB3_lateral_movement] Bước 1: kiểm tra API Gateway và SOAR...
[KB3_lateral_movement] Bước 2: gửi request với SVID giả — notification-service cố gọi /payments/internal...
[KB3_lateral_movement] API Gateway trả về HTTP 403 (expect 401/403/404 — OPA/Envoy chặn SVID không được phép)
[KB3_lateral_movement] Bước 2b: gửi thêm request không có SVID hợp lệ tới /transactions/execute...
[KB3_lateral_movement] Lateral movement attempt 2: HTTP 403
[KB3_lateral_movement] Bước 3: đẩy opa-decisions log vào Loki (Grafana query: attack_scenario=lateral_movement)...
[KB3_lateral_movement] OPA lateral_movement log đã vào Loki
[KB3_lateral_movement] Bước 4: mô phỏng Grafana 'Lateral Movement — Invalid SVID' → SOAR webhook...
[KB3_lateral_movement] Bước 5: kiểm tra SOAR case...
[KB3_lateral_movement] PASS: KB3 Lateral Movement | SVID blocked HTTP 403 | SOAR case=case-20260627042053-kb3-17 status=pending_approval playbook=isolate_workload (T1021.007)
[KB3_lateral_movement] → SPIFFE mTLS: chỉ SVID trong trust domain ztlab.local mới được phép giao tiếp service-to-service
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ # Thử 1: notification-service gọi /payments/internal (không được phép)
curl -s -o /dev/null -w "SVID notif-svc → /payments/internal: HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments/internal/execute \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://ztlab.local/aws/notification-service" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-ATTACKER","amount":999999}'

# Thử 2: SVID từ ngoài trust domain
curl -s -o /dev/null -w "SVID evil.corp → /payments/internal: HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments/internal/execute \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://evil.corp/attacker" \
  -d '{"amount":100000}'
SVID notif-svc → /payments/internal: HTTP 403
SVID evil.corp → /payments/internal: HTTP 403
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ curl -s http://localhost:8091/cases | python3 -c "
import sys, json
cases = json.load(sys.stdin)
lm = [c for c in cases if c['attack_type'] == 'lateral_movement']
if lm: print(lm[-1]['case_id'], '|', lm[-1]['status'])
"
case-20260627042140-bf5e09 | executed
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ kubectl --context ctx-aws get deployment payment-service -n financial
NAME              READY   UP-TO-DATE   AVAILABLE   AGE
payment-service   1/1     1            1           25d
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash scripts/run-demo.sh --restore

╔══════════════════════════════════════════════════════════╗
║         ZTLab — Zero Trust Security Demo                 ║
╠══════════════════════════════════════════════════════════╣
║  Grafana  →  http://127.0.0.1:3000                       ║
║  Dashboard: ZTLab AI SIEM SOAR                           ║
╚══════════════════════════════════════════════════════════╝

[DEMO] Restore tất cả services...
  ▶ Restore payment-service (xóa SOAR isolation label)...
service/payment-service patched
    payment-service: OK
  ▶ Restore api-gateway (replicas=1)...
deployment.apps/api-gateway scaled
    api-gateway: OK
  ▶ Restore core-banking trên OpenStack (replicas=1)...
deployment.apps/core-banking scaled
deployment "core-banking" successfully rolled out
    core-banking: OK
[ OK ] Restore hoàn tất
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash tests/grafana_kb4_exfiltration.sh
[KB4_exfiltration] Bước 1: kiểm tra API Gateway và SOAR...
[KB4_exfiltration] Bước 2: lấy JWT testuser01 rồi kéo transaction history lặp lại nhiều lần...
[KB4_exfiltration] ▶ 10 request bulk data — tổng bytes nhận: 15546 bytes từ API Financial
[KB4_exfiltration]   (trong môi trường production, request tương tự tới core-banking sẽ trả response MB-level)
[KB4_exfiltration] Bước 3: đẩy envoy-access log vào Loki (bytes_sent=15546 đo thực + giả lập core-banking 2MB)...
[KB4_exfiltration] Log đã vào Loki (real: 15546B từ api-gateway + simulated: 3.5MB từ core-banking)
[KB4_exfiltration] Bước 4: mô phỏng Grafana 'Data Exfiltration — Large Response' → SOAR webhook...
[KB4_exfiltration] Bước 5: kiểm tra SOAR case...
[KB4_exfiltration] PASS: KB4 Exfiltration | real: 15546B từ 10 requests | SOAR case=case-20260627042237-kb4-17 status=pending_approval playbook=restrict_egress (T1041)
[KB4_exfiltration]   Zero Trust: Envoy theo dõi bytes_sent — pattern trích xuất dữ liệu lớn lặp lại → alert
[KB4_exfiltration]   restrict_egress: SOAR scale core-banking (OpenStack) → 0 replica, chặn data ra ngoài
[KB4_exfiltration] 
[KB4_exfiltration]   Lưu ý: Tổng bytes thực đo từ api-gateway = 15546B.
[KB4_exfiltration]   Core-banking response (Envoy sidecar trên OpenStack) = simulated 3.5MB.
[KB4_exfiltration]   Trong production, Promtail sẽ tự capture Envoy log — không cần inject thủ công.
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

for ep in "/transactions?account_id=ACC-1001&limit=500" "/accounts/balance" "/transactions?account_id=ACC-2001&limit=500"; do
  bytes=$(curl -s -w "%{size_download}" -o /dev/null "http://localhost:18080$ep" \
    -H "Authorization: Bearer $TOKEN")
  echo "$ep → $bytes bytes"
done
/transactions?account_id=ACC-1001&limit=500 → 2208 bytes
/accounts/balance → 30 bytes
/transactions?account_id=ACC-2001&limit=500 → 2208 bytes
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ kubectl --context ctx-openstack get deployment core-banking -n financial
NAME           READY   UP-TO-DATE   AVAILABLE   AGE
core-banking   0/0     0            0           24d
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash scripts/run-demo.sh --restore
kubectl --context ctx-openstack get deployment core-banking -n financial

╔══════════════════════════════════════════════════════════╗
║         ZTLab — Zero Trust Security Demo                 ║
╠══════════════════════════════════════════════════════════╣
║  Grafana  →  http://127.0.0.1:3000                       ║
║  Dashboard: ZTLab AI SIEM SOAR                           ║
╚══════════════════════════════════════════════════════════╝

[DEMO] Restore tất cả services...
  ▶ Restore payment-service (xóa SOAR isolation label)...
service/payment-service patched (no change)
    payment-service: OK
  ▶ Restore api-gateway (replicas=1)...
deployment.apps/api-gateway scaled
    api-gateway: OK
  ▶ Restore core-banking trên OpenStack (replicas=1)...
deployment.apps/core-banking scaled
Waiting for deployment "core-banking" rollout to finish: 0 of 1 updated replicas are available...
deployment "core-banking" successfully rolled out
    core-banking: OK
[ OK ] Restore hoàn tất
NAME           READY   UP-TO-DATE   AVAILABLE   AGE
core-banking   1/1     1            1           24d
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash tests/grafana_kb5_access_denied.sh
[KB5_access_denied] Bước 1: kiểm tra API Gateway và SOAR...
[KB5_access_denied] Bước 2: lấy JWT merchant01 (role: financial-read only)...
[KB5_access_denied]   merchant01 roles: ['financial-read']  ← chỉ có financial-read, không có financial-write
[KB5_access_denied] Bước 3: merchant01 thử POST /payments (cần financial-write) → OPA RBAC từ chối...
[KB5_access_denied]   POST /payments amount=100000 → HTTP 403  ← OPA RBAC deny (financial-write required)
[KB5_access_denied]   POST /payments amount=50000 → HTTP 403  ← OPA RBAC deny (financial-write required)
[KB5_access_denied]   POST /payments amount=200000 → HTTP 403  ← OPA RBAC deny (financial-write required)
[KB5_access_denied]   POST /payments amount=75000 → HTTP 403  ← OPA RBAC deny (financial-write required)
[KB5_access_denied]   POST /payments amount=1000000 → HTTP 403  ← OPA RBAC deny (financial-write required)
[KB5_access_denied]   POST /payments amount=5000 → HTTP 403  ← OPA RBAC deny (financial-write required)
[KB5_access_denied] ▶ OPA RBAC từ chối 6/6 request — merchant01 vi phạm least-privilege
[KB5_access_denied]   OPA response: (see HTTP 403)
[KB5_access_denied] Bước 4: đẩy OPA deny log vào Loki (format khớp Grafana rule)...
[KB5_access_denied] 6 OPA deny log đã vào Loki — Grafana rule sẽ fire
[KB5_access_denied] Bước 5: mô phỏng Grafana 'Access Denied Spike' → SOAR webhook...
[KB5_access_denied] Bước 6: kiểm tra SOAR case...
[KB5_access_denied] PASS: KB5 Access Denied | OPA RBAC THẬT: 6/6 từ chối | SOAR case=case-20260627042341-kb5-17 status=pending_approval playbook=block_source_ip (T1078)
[KB5_access_denied]   ✓ Zero Trust enforcement THẬT: merchant01 (financial-read) bị OPA từ chối POST /payments
[KB5_access_denied]   ✓ OPA policy: require role financial-write — không có → HTTP 403
[KB5_access_denied]   block_source_ip: SOAR thêm IP vào Redis blocklist 24h
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ # merchant01 (financial-read ONLY) → POST /payments phải bị từ chối
MERCHANT_TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=merchant01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

curl -s -o /dev/null -w "merchant01 POST /payments → HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $MERCHANT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-4001","to_account":"ACC-2001","amount":1000}'

# testuser01 (financial-read + financial-write) → POST /payments phải thành công
USER_TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234%21&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

curl -s -o /dev/null -w "testuser01 POST /payments → HTTP %{http_code}\n" \
  -X POST http://localhost:18080/payments \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"from_account":"ACC-1001","to_account":"ACC-2001","amount":1000}'
merchant01 POST /payments → HTTP 403
testuser01 POST /payments → HTTP 503
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ curl -s http://localhost:8091/blocked-ips | python3 -m json.tool
{
    "blocked_ips": [],
    "count": 0,
    "ttl_seconds": 86400
}
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ curl -s http://localhost:8091/blocked-ips | python3 -m json.tool
{
    "blocked_ips": [
        {
            "ip": "10.0.0.99",
            "reason": "SOAR: access_denied via block_source_ip",
            "ts": "2026-06-27T04:24:57.383610+00:00",
            "ttl_seconds": 86400
        }
    ],
    "count": 1,
    "ttl_seconds": 86400
}
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ curl -s -X DELETE "http://localhost:8091/blocked-ips/10.0.0.99"
{"status":"unblocked","ip":"10.0.0.99"}deployer@aio:~/Zero-Trust-based-Security-Detection-and-Res# Lấy tên pod api-gateway-Multi-Cloud$ # Lấy tên pod api-gateway
POD=$(kubectl --context ctx-aws get pod -n financial -l app=api-gateway \
  -o jsonpath='{.items[0].metadata.name}')
echo "Pod: $POD"

# Kiểm tra uid — expect: uid=0(root)
kubectl --context ctx-aws exec -n financial "$POD" -- id

# Kiểm tra capabilities — expect: 00000000a80425fb
kubectl --context ctx-aws exec -n financial "$POD" -- cat /proc/1/status | grep CapEff

# Thử đọc /etc/shadow — chỉ đọc được nếu có CAP_DAC_OVERRIDE
kubectl --context ctx-aws exec -n financial "$POD" -- head -3 /etc/shadow

# Kiểm tra securityContext — expect: rỗng (không được hardened)
kubectl --context ctx-aws get pod "$POD" -n financial \
  -o jsonpath='{.spec.containers[0].securityContext}' && echo ""
Pod: api-gateway-665bb949bd-n6zsh
Defaulted container "api-gateway" out of: api-gateway, envoy
uid=0(root) gid=0(root) groups=0(root)
Defaulted container "api-gateway" out of: api-gateway, envoy
CapEff:	00000000a80425fb
Defaulted container "api-gateway" out of: api-gateway, envoy
root:*:20549:0:99999:7:::
daemon:*:20549:0:99999:7:::
bin:*:20549:0:99999:7:::

deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ python3 -c "
caps_hex = 'a80425fb'
caps = int(caps_hex, 16)
NAMES = {0:'CHOWN',1:'DAC_OVERRIDE',3:'FOWNER',4:'FSETID',5:'KILL',
         6:'SETGID',7:'SETUID',8:'SETPCAP',10:'NET_BIND_SERVICE',
         13:'NET_RAW',18:'SYS_CHROOT',21:'SYS_ADMIN',29:'AUDIT_WRITE',31:'SETFCAP'}
dangerous = {7:'SETUID',1:'DAC_OVERRIDE',21:'SYS_ADMIN'}
active = [v for k,v in NAMES.items() if caps & (1<<k)]
danger_found = [v for k,v in dangerous.items() if caps & (1<<k)]
print('Active:', active)
print('DANGEROUS:', danger_found)
"
Active: ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'KILL', 'SETGID', 'SETUID', 'SETPCAP', 'NET_BIND_SERVICE', 'NET_RAW', 'SYS_CHROOT', 'AUDIT_WRITE', 'SETFCAP']
DANGEROUS: ['SETUID', 'DAC_OVERRIDE']
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash tests/grafana_kb6_privilege_escalation.sh
[KB6_privilege_escalation] Bước 1: kiểm tra SOAR và Loki...
[KB6_privilege_escalation] Bước 2: kiểm tra THỰC TẾ pod security context của api-gateway (ctx-aws)...
[KB6_privilege_escalation]   Pod: api-gateway-665bb949bd-n6zsh
[KB6_privilege_escalation]   id: uid=0(root) gid=0(root) groups=0(root)
[KB6_privilege_escalation]   CapEff: 0x00000000a80425fb
[KB6_privilege_escalation]   ⚠ CÓ THỂ ĐỌC /etc/shadow (3 dòng) — CAP_DAC_OVERRIDE bypass permission
[KB6_privilege_escalation]   setuid(0): setuid(0) OK
[KB6_privilege_escalation]   securityContext.runAsNonRoot:  (should be true)
[KB6_privilege_escalation]   securityContext.allowPrivilegeEscalation:  (should be false)
[KB6_privilege_escalation] ▶ VI PHẠM Zero Trust workload isolation xác nhận:
[KB6_privilege_escalation]   • Pod chạy root (uid=0) — vi phạm least-privilege principle
[KB6_privilege_escalation]   • CAP_DAC_OVERRIDE cho phép đọc /etc/shadow — leo thang đặc quyền thực tế
[KB6_privilege_escalation]   • runAsNonRoot không được set — container không bị ràng buộc
[KB6_privilege_escalation] Bước 3: đẩy audit log thực tế (từ kết quả bước 2) vào Loki...
[KB6_privilege_escalation] 5 audit finding da vao Loki (du lieu tu kubectl exec thuc te)
[KB6_privilege_escalation] Bước 4: mô phỏng Grafana 'Privilege Escalation in Container' → SOAR webhook...
[KB6_privilege_escalation] Bước 5: kiểm tra SOAR case...
[KB6_privilege_escalation] PASS: KB6 Privilege Escalation | THẬT: uid=0 CapEff=0x00000000a80425fb shadow=true | SOAR case=case-20260627042548-kb6-17 status=pending_approval playbook=quarantine_workload (T1611)
[KB6_privilege_escalation]   ✓ Zero Trust violation THẬT: container không được hardened — root + dangerous capabilities
[KB6_privilege_escalation]   quarantine_workload: SOAR scale api-gateway → 0 để forensics (KHÔNG restore cho đến khi admin phê duyệt)
[KB6_privilege_escalation] 
[KB6_privilege_escalation]   Khuyến nghị fix (cho báo cáo):
[KB6_privilege_escalation]     securityContext:
[KB6_privilege_escalation]       runAsNonRoot: true
[KB6_privilege_escalation]       runAsUser: 1000
[KB6_privilege_escalation]       allowPrivilegeEscalation: false
[KB6_privilege_escalation]       capabilities: {drop: [ALL]}
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ kubectl --context ctx-aws get deployment api-gateway -n financial
NAME          READY   UP-TO-DATE   AVAILABLE   AGE
api-gateway   0/0     0            0           25d
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ bash scripts/run-demo.sh --restore
kubectl --context ctx-aws get deployment api-gateway -n financial

╔══════════════════════════════════════════════════════════╗
║         ZTLab — Zero Trust Security Demo                 ║
╠══════════════════════════════════════════════════════════╣
║  Grafana  →  http://127.0.0.1:3000                       ║
║  Dashboard: ZTLab AI SIEM SOAR                           ║
╚══════════════════════════════════════════════════════════╝

[DEMO] Restore tất cả services...
  ▶ Restore payment-service (xóa SOAR isolation label)...
service/payment-service patched (no change)
    payment-service: OK
  ▶ Restore api-gateway (replicas=1)...
deployment.apps/api-gateway scaled
    api-gateway: OK
  ▶ Restore core-banking trên OpenStack (replicas=1)...
deployment.apps/core-banking scaled
deployment "core-banking" successfully rolled out
    core-banking: OK
[ OK ] Restore hoàn tất
NAME          READY   UP-TO-DATE   AVAILABLE   AGE
api-gateway   0/1     1            0           25d
deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ curl -s http://localhost:18080/health
upstream connect error or disconnect/reset before headers. reset reason: remote connection failure, transport failure reason: delayed connect error: 111deployer@aio:~/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud$ 

LOG:
- app=keycloak: 2026-06-27 08:43:13,498 WARN  [org.keycloak.events] (executor-thread-2805) type="LOGIN_ERROR", realmId="871d7dd3-73e7-4160-be0e-af3a9ff45725", clientId="admin-cli", userId="0fa98b43-d7a5-4cd7-a33a-e27228101b73", ipAddress="127.0.0.1", error="invalid_user_credentials", auth_method="openid-connect", grant_type="password", client_auth_method="client-secret", username="admin"
2026-06-27 08:43:13,497 WARN  [org.keycloak.credential.PasswordCredentialProvider] (executor-thread-2805) Error when validating user password: java.lang.RuntimeException: java.lang.IllegalArgumentException: password empty
2026-06-27 08:43:06,905 WARN  [org.keycloak.events] (executor-thread-2805) type="LOGIN_ERROR", realmId="871d7dd3-73e7-4160-be0e-af3a9ff45725", clientId="admin-cli", userId="0fa98b43-d7a5-4cd7-a33a-e27228101b73", ipAddress="127.0.0.1", error="invalid_user_credentials", auth_method="openid-connect", grant_type="password", client_auth_method="client-secret", username="admin"

- job=opa_decision; opa_result=false: {"decision_id":"859518d0-ec38-4ca8-98d2-956a5056c10b","input":{"attributes":{"destination":{"address":{"socketAddress":{"address":"127.0.0.1","portValue":15006}}},"metadataContext":{},"request":{"http":{"headers":{":authority":"localhost:18080",":method":"POST",":path":"/payments/internal/execute",":scheme":"http","accept":"*/*","content-length":"17","content-type":"application/json","user-agent":"curl/8.5.0","x-forwarded-proto":"http","x-request-id":"f5ad8e1d-0a3b-4f07-b35b-4f4a686bce46","x-spiffe-id":"spiffe://evil.corp/attacker"},"host":"localhost:18080","id":"14745879109013931390","method":"POST","path":"/payments/internal/execute","protocol":"HTTP/1.1","scheme":"http"},"time":{"nanos":874409000,"seconds":1782551736}},"routeMetadataContext":{},"source":{"address":{"socketAddress":{"address":"127.0.0.1","portValue":47934}}}},"parsed_body":null,"parsed_path":["payments","internal","execute"],"parsed_query":{},"truncated_body":false,"version":[[{"type":"string","value":"encoding"},{"type":"string","value":"protojson"}],[{"type":"string","value":"ext_authz"},{"type":"string","value":"v3"}]]},"labels":{"id":"152f8352-6637-4367-b9ad-b993eb820d7a","version":"1.18.0"},"level":"info","metrics":{"timer_rego_query_eval_ns":251982,"timer_server_handler_ns":706069},"msg":"Decision Log","path":"zta/authz/allow","result":false,"time":"2026-06-27T09:15:36Z","timestamp":"2026-06-27T09:15:36.875682663Z","type":"openpolicyagent.org/decision_logs"}

- job=opa_decision; opa_result=false; attack_scenario=lateral_movement: {"result":false,"attack_scenario":"lateral_movement","svid":"spiffe://evil.domain/attacker/service","path":"/transactions/execute","reason":"svid_outside_trust_domain"}
{"result":false,"attack_scenario":"lateral_movement","svid":"spiffe://ztlab.local/aws/notification-service","path":"/payments/internal/execute","source_ip":"10.10.1.11","reason":"svid_not_authorized_for_path"}

- job=opa_decision; opa_result=false; attack_scenario=fraud_gate_bypass: {"result":false,"attack_scenario":"fraud_gate_bypass","fraud_score":80,"source_ip":"10.0.0.5","reason":"critical_amount_tor_channel"}
{"result":false,"attack_scenario":"fraud_gate_bypass","fraud_score":75,"source_ip":"10.0.0.5","path":"/transactions/execute","amount":500000000}
