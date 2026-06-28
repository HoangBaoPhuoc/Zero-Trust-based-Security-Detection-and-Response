# BÁO CÁO CẤU HÌNH CHI TIẾT HỆ THỐNG ZTLAB
## Triển Khai Zero Trust Security Detection and Response — NT114.Q21.ANTT

> **Môn học:** NT114.Q21.ANTT — Đồ án chuyên ngành An Toàn Thông Tin  
> **Sinh viên:** Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> **Giảng viên:** ThS. Đỗ Thị Phương Uyên  
> **Tài liệu này:** Báo cáo cấu hình chi tiết — mô tả từng tham số, file cấu hình, lý do chọn giá trị, lệnh apply và lệnh verify cho từng thành phần trong hệ thống.

---

## Mục Lục

1. [Kiến Trúc Tổng Thể và Luồng Dữ Liệu](#1-kiến-trúc-tổng-thể-và-luồng-dữ-liệu)
2. [Hạ Tầng Infrastructure as Code](#2-hạ-tầng-infrastructure-as-code)
3. [Keycloak — Identity Provider (Lớp 1)](#3-keycloak--identity-provider-lớp-1)
4. [SPIRE/SPIFFE — Workload Identity (Lớp 2)](#4-spirespiffe--workload-identity-lớp-2)
5. [Envoy Sidecar — mTLS và Policy Enforcement (Lớp 3)](#5-envoy-sidecar--mtls-và-policy-enforcement-lớp-3)
6. [OPA — Policy Decision Point (Lớp 4)](#6-opa--policy-decision-point-lớp-4)
7. [Microservices — Ứng Dụng Tài Chính](#7-microservices--ứng-dụng-tài-chính)
8. [PLG Stack — SIEM Thu Thập Log](#8-plg-stack--siem-thu-thập-log)
9. [Grafana Alerting — Phát Hiện Tấn Công](#9-grafana-alerting--phát-hiện-tấn-công)
10. [SOAR Engine — Phản Ứng Tự Động và HITL](#10-soar-engine--phản-ứng-tự-động-và-hitl)
11. [Redis — Velocity Cache và IP Blocklist](#11-redis--velocity-cache-và-ip-blocklist)
12. [WireGuard — Tunnel Cross-Cloud](#12-wireguard--tunnel-cross-cloud)
13. [Network Policy — Phân Vùng Namespace](#13-network-policy--phân-vùng-namespace)
14. [K8s RBAC — Quyền Hạn SOAR](#14-k8s-rbac--quyền-hạn-soar)
15. [Phụ Lục — Index File Cấu Hình và Lệnh Nhanh](#15-phụ-lục--index-file-cấu-hình-và-lệnh-nhanh)

---

## 1. Kiến Trúc Tổng Thể và Luồng Dữ Liệu

### 1.1. Topology Hạ Tầng

```
┌─────────────────────────── AWS ap-southeast-1 ───────────────────────────────┐
│                                                                               │
│  Bastion: 52.221.255.36 (SSH jump)    Gateway EIP: 13.213.245.227           │
│  K3s Master: 10.10.1.10  K3s Worker: 10.10.1.11  Loki Node: 10.10.2.10     │
│                                                                               │
│  Namespace: financial                  Namespace: identity                   │
│  ┌──────────────────────────────┐      ┌──────────────┐                     │
│  │ api-gateway     (2/2 Envoy)  │      │ Keycloak     │                     │
│  │ payment-service (2/2 Envoy)  │      │ Postgres-KC  │                     │
│  │ fraud-detection (2/2 Envoy)  │      └──────────────┘                     │
│  │ notification-svc(2/2 Envoy)  │                                            │
│  │ opa-server, redis, postgres  │      Namespace: spire                     │
│  └──────────────────────────────┘      ┌──────────────────────┐             │
│                                         │ spire-server         │             │
│  Namespace: plg-stack                   │ spire-agent (DS x2)  │             │
│  ┌───────────────────────────────┐      └──────────────────────┘             │
│  │ loki, grafana, soar-engine   │                                            │
│  │ promtail (DaemonSet x2)      │                                            │
│  └───────────────────────────────┘                                           │
│                          WireGuard: 10.200.0.1 ↔ 10.200.0.2                │
└───────────────────────────────────────────────────────────────────────────────┘
                                    │ UDP 51820 (WireGuard)
┌─────────────────── OpenStack (Local Lab) ────────────────────────────────────┐
│                                                                               │
│  os-gateway: 10.10.10.188 (floating)   K3s Master: 192.168.101.11           │
│                                                                               │
│  Namespace: financial                                                        │
│  ┌────────────────────────────────────────────────────────┐                 │
│  │ core-banking    (2/2 Envoy)  NodePort 30080→15006      │                 │
│  │ account-service (2/2 Envoy)  NodePort 30082→15006      │                 │
│  │ transaction-svc (2/2 Envoy)  NodePort 30083→15006      │                 │
│  │ opa-server, redis, postgres                             │                 │
│  └────────────────────────────────────────────────────────┘                 │
└───────────────────────────────────────────────────────────────────────────────┘
```

**Kubernetes Contexts:**
- `ctx-aws` → `~/.kube/ztlab/aws-tunnel.yaml` → API server 127.0.0.1:6444
- `ctx-openstack` → `~/.kube/ztlab/os-tunnel.yaml` → API server 127.0.0.1:6445

### 1.2. Bốn Lớp Zero Trust

```
Lớp 1 — KEYCLOAK (Identity Provider)
  Xác thực người dùng (username/password) → phát hành JWT (RS256, TTL 5 phút)
  Mọi request từ client PHẢI có JWT hợp lệ
  └─ File: k8s/keycloak/realm-config.json

Lớp 2 — SPIRE/SPIFFE (Workload Identity)
  Xác thực danh tính workload → phát hành SVID X.509 (TTL 1 giờ)
  Mọi service-to-service call PHẢI có SVID do SPIRE cấp
  └─ File: spire/server/server.conf, spire/agent/aws-agent.conf

Lớp 3 — ENVOY SIDECAR (Policy Enforcement Point)
  Thực thi mTLS (yêu cầu cert từ cả hai chiều)
  Gọi OPA để authorize từng request (ext_authz gRPC)
  └─ File: envoy/envoy-sidecar.yaml

Lớp 4 — OPA (Policy Decision Point)
  Kiểm tra JWT role, SVID trust domain, fraud gate header
  Deny-by-default: không có rule match → từ chối
  └─ File: opa/policies/zta_policy.rego
```

### 1.3. Luồng Request Bình Thường (POST /payments)

```
Bước 1: Client lấy JWT
  Browser/curl → POST /realms/ztlab/protocol/openid-connect/token
               → Keycloak (identity ns, port 8180)
               ← access_token (JWT RS256, TTL 300s)

Bước 2: Gọi API Gateway
  Client → POST http://api.ztlab.local/payments
           Authorization: Bearer <JWT>
           → api-gateway pod:15006 (Envoy INBOUND)

Bước 3: Envoy inbound api-gateway xử lý
  3a. TLS handshake (không cần mTLS với external client vì source_principal = "")
  3b. Envoy gọi OPA ext_authz:
      - input: method=POST, path=/payments, headers={authorization: Bearer JWT}
      - OPA verify JWT signature bằng JWKS từ Keycloak
      - OPA check role: financial-write có POST /payments → allow
  3c. Envoy forward → api-gateway app (127.0.0.1:8080)

Bước 4: api-gateway → payment-service (service-to-service)
  api-gateway app → 127.0.0.1:15001 (Envoy OUTBOUND)
  Envoy outbound:
    - Attach SVID: spiffe://ztlab.local/aws/api-gateway (từ SPIRE Agent)
    - Route /payments → cluster payment_service
    - mTLS handshake với payment-service:15006

Bước 5: Envoy inbound payment-service
  5a. mTLS verify cert của api-gateway (SVID từ trust domain ztlab.local) ✓
  5b. OPA ext_authz:
      - source_principal = spiffe://ztlab.local/aws/api-gateway
      - path = /payments, method = POST
      - Rule: api-gateway có SVID hợp lệ + path /payments → allow
  5c. Forward → payment-service app

Bước 6: payment-service → fraud-detection
  Tương tự bước 4-5 với SVID payment-service
  fraud-detection tính score, trả {score, gate, verdict}

Bước 7: payment-service → core-banking (CROSS-CLOUD)
  payment-service app → 127.0.0.1:15001 (Envoy outbound)
  Route: /transactions/execute → cluster core_banking
  Cluster endpoint: 192.168.101.11:30080 (OpenStack NodePort qua WireGuard)
  Headers: X-Fraud-Gate: passed, X-Fraud-Score: 23

Bước 8: Envoy inbound core-banking (OpenStack)
  8a. mTLS verify SVID payment-service ✓
  8b. OPA check fraud gate:
      - valid_svid ✓ AND x-fraud-gate=passed ✓ AND score < 75 ✓ → allow
  8c. core-banking → account-service (debit), transaction-service (ledger)

Bước 9: Logging
  Mỗi Envoy ghi access.log dạng JSON → /var/log/envoy/access.log
  Promtail DaemonSet đọc file → push Loki với labels (job, namespace, app)
  OPA ghi decision.log → /var/log/opa/decisions.json → Loki (job=opa-decisions)
```

### 1.4. Luồng Phát Hiện và Phản Ứng (Detection & Response)

```
[PHÁT HIỆN]
  Grafana evaluate alert rule mỗi 1 phút
  Query LogQL trên Loki:
    KB1: count_over_time({job="envoy-access"} | json | response_code=`401` [1m]) > 10
    KB2: count_over_time({job="opa-decisions", opa_result="false",
                          attack_scenario="lateral_movement"} [5m]) > 0
    KB3: count_over_time({job="opa-decisions", opa_result="false",
                          request_path="/transactions/execute"} [5m]) > 0
    KB4: count_over_time({job="envoy-access"} | json | bytes_sent > 1048576 [5m]) > 0

[ALERT FIRE]
  Grafana → POST http://soar-engine.plg-stack.svc:8080/grafana-webhook
  Body: {alerts: [{labels: {attack_type, severity, mitre}, ...}]}

[SOAR XỬ LÝ]
  SOAR nhận webhook → check dedup (5 phút)
  → _fetch_loki_lines(attack_type) → lấy ≤ 8 dòng log evidence
  → severity >= high → status = pending_approval
  → Gửi email HITL đến voha2005@gmail.com
  → Lưu case vào /data/cases.jsonl

[ADMIN DUYỆT]
  Admin nhận email hoặc vào http://localhost:18081/security
  Click "Xử lý" → chọn playbook → POST /cases/{id}/execute-playbook

[PLAYBOOK THỰC THI]
  Phase 1 Collect: query Loki thêm evidence
  Phase 2 Contain: kubectl scale/patch/create (K8s Python SDK)
  Phase 3 Eradicate: xóa NetworkPolicy cũ, xóa Redis blocklist cũ
  Phase 4 Recover: update case status → "executed", gửi confirmation email
```

---

## 2. Hạ Tầng Infrastructure as Code

### 2.1. Terraform — Provision AWS Resources

**File:** `terraform/main.tf`, `terraform/variables.tf`

Terraform provision toàn bộ hạ tầng AWS: VPC, subnets, security groups, EC2 instances cho K3s.

**Cấu hình chính:**

```hcl
# terraform/variables.tf
variable "region"         { default = "ap-southeast-1" }   # Singapore
variable "k3s_master_type"{ default = "t3.medium" }        # 2 vCPU, 4GB RAM
variable "k3s_worker_type"{ default = "t3.small" }         # 2 vCPU, 2GB RAM
variable "loki_node_type" { default = "t3.small" }         # node riêng cho Loki

# terraform/main.tf — Security Group K3s
resource "aws_security_group" "k3s" {
  ingress {
    from_port = 6443; to_port = 6443; protocol = "tcp"
    cidr_blocks = ["10.10.0.0/16"]    # K8s API chỉ trong VPC
  }
  ingress {
    from_port = 51820; to_port = 51820; protocol = "udp"
    cidr_blocks = ["0.0.0.0/0"]       # WireGuard UDP từ OpenStack
  }
}
```

**Cách apply:**

```bash
cd terraform/
terraform init
terraform plan -var="key_name=ztlab-key"
terraform apply -auto-approve
# Output: aws_k3s_master_ip, aws_gateway_public_ip
```

### 2.2. Ansible — Configuration Management

**File:** `ansible/playbooks/`, `ansible/inventory/hosts.yml`

Ansible cấu hình K3s cluster, WireGuard, và các thành phần host-level sau khi Terraform provision xong.

```yaml
# ansible/inventory/hosts.yml
all:
  children:
    aws:
      hosts:
        aws-master:
          ansible_host: 10.10.1.10
          ansible_ssh_common_args: "-J ubuntu@52.221.255.36"  # qua bastion
          ansible_user: ubuntu
          ansible_ssh_private_key_file: ~/.ssh/ztlab-key
        aws-worker:
          ansible_host: 10.10.1.11
          ansible_ssh_common_args: "-J ubuntu@52.221.255.36"
    openstack:
      hosts:
        os-master:
          ansible_host: 192.168.101.11
          ansible_ssh_common_args: "-J ubuntu@10.10.10.188"
```

**Playbooks quan trọng:**

| Playbook | File | Mục đích |
|---|---|---|
| K3s install | `ansible/playbooks/k3s.yml` | Cài K3s server + agent |
| WireGuard | `ansible/playbooks/wireguard.yml` | Cấu hình tunnel cross-cloud |
| SPIRE prep | `ansible/playbooks/spire-prep.yml` | Tạo thư mục data, copy config |
| Port forward | `ansible/playbooks/port-forward.yml` | Setup tunnel từ localhost |

**Cách chạy:**

```bash
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/k3s.yml
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/wireguard.yml
```

**Mở port-forward cho local access:**

```bash
bash scripts/k8s-tunnel.sh up all        # mở tunnel K8s API (6444, 6445)
bash scripts/open-admin-uis.sh           # mở port-forward UI (3000, 8091, ...)
```

Port-forward mặc định:
- `18080` → api-gateway (financial ns)
- `8180` → Keycloak (identity ns)
- `3000` → Grafana (plg-stack ns)
- `8091` → SOAR Engine (plg-stack ns)
- `13100` → Loki (plg-stack ns)
- `18081` → Web Portal (financial ns)

---

## 3. Keycloak — Identity Provider (Lớp 1)

**Vai trò trong ZTA:** Lớp 1 — Xác thực danh tính người dùng (end-user identity).  
**Namespace K8s:** `identity`

### 3.1. Cách Cấu Hình Deployment

**File:** `k8s/keycloak/deployment.yaml`

```yaml
spec:
  containers:
  - name: keycloak
    image: quay.io/keycloak/keycloak:24.0.3
    args:
      - start-dev          # Dev mode: bỏ qua HTTPS requirement
      - --import-realm     # Tự load realm-config.json khi start lần đầu
    env:
      - name: KEYCLOAK_ADMIN
        value: admin
      - name: KEYCLOAK_ADMIN_PASSWORD
        valueFrom:
          secretKeyRef:
            name: keycloak-secret
            key: admin-password    # = "ztlab-admin-2026"
      - name: KC_DB
        value: postgres
      - name: KC_DB_URL
        value: jdbc:postgresql://keycloak-db:5432/keycloak
      - name: KC_HOSTNAME
        value: keycloak.ztlab.local
      - name: KC_HTTP_ENABLED
        value: "true"
    volumeMounts:
      - name: realm-config
        mountPath: /opt/keycloak/data/import   # Keycloak đọc từ đây khi --import-realm
  volumes:
    - name: realm-config
      configMap:
        name: keycloak-realm-config            # chứa realm-config.json
```

**Tại sao PostgreSQL thay vì H2?** H2 in-memory mất data khi pod restart. PostgreSQL persist qua PVC.

**Tạo Secret:**

```bash
kubectl --context ctx-aws create secret generic keycloak-secret \
  -n identity --from-literal=admin-password='ztlab-admin-2026'
```

**Apply deployment:**

```bash
kubectl --context ctx-aws apply -f k8s/keycloak/deployment.yaml
kubectl --context ctx-aws apply -f k8s/keycloak/service.yaml
kubectl --context ctx-aws apply -f k8s/keycloak/postgres.yaml
```

### 3.2. Cấu Hình Realm — `k8s/keycloak/realm-config.json`

Realm là đơn vị định danh độc lập trong Keycloak. File JSON được import tự động khi Keycloak start lần đầu.

**Tham số Realm quan trọng:**

| Tham số | Giá trị | Lý do |
|---|---|---|
| `realm` | `ztlab` | Xuất hiện trong mọi URL `/realms/ztlab/` và `iss` claim của JWT |
| `accessTokenLifespan` | `300` (5 phút) | Ngắn → token bị đánh cắp chỉ dùng được 5 phút |
| `ssoSessionMaxLifespan` | `36000` (10 giờ) | Session không hết trong buổi làm việc |
| `refreshTokenLifespan` | `1800` (30 phút) | Refresh token sống lâu hơn access token |
| `defaultSignatureAlgorithm` | `RS256` | Asymmetric crypto — api-gateway verify offline bằng public key |

**Tại sao JWT không cần gọi Keycloak mỗi request?**  
RS256 dùng asymmetric key. Keycloak ký bằng private key, api-gateway verify bằng public key (JWKS endpoint). Public key được cache — chỉ fetch lại khi rotate. Không có network hop đến Keycloak cho mỗi request → không tạo bottleneck.

**Users và Roles được tạo trong realm-config.json:**

| Username | Password | Roles | Dùng để |
|---|---|---|---|
| `testuser01` | `Test1234!` | `financial-write` | Demo chuyển tiền (ACC-1001) |
| `testuser02` | `Test1234!` | `financial-write` | Demo chuyển tiền (ACC-2001) |
| `merchant01` | `Test1234!` | `financial-read` | Demo read-only access |
| `analyst01` | `Test1234!` | `security-analyst`, `security-admin` | Demo HITL approval |

**Clients trong realm:**

| Client ID | Loại | Dùng để |
|---|---|---|
| `web-portal` | Public | Frontend browser (không thể giữ secret) |
| `api-gateway` | Confidential | api-gateway verify JWT |
| `siem-backend` | Confidential | SOAR gọi Keycloak Admin API |

### 3.3. Luồng OIDC Đầy Đủ

```
1. Client → POST /realms/ztlab/protocol/openid-connect/token
   Body: grant_type=password, username=testuser01, password=Test1234!,
         client_id=web-portal
   
2. Keycloak xác thực user trong PostgreSQL keycloak-db

3. Keycloak trả:
   { "access_token": "<JWT>",      # RS256, TTL 300s
     "refresh_token": "<RT>",      # TTL 1800s
     "expires_in": 300,
     "token_type": "Bearer" }

4. JWT decode (không cần secret):
   Header: {"alg":"RS256","kid":"<key-id>"}
   Payload: {
     "iss": "http://keycloak.ztlab.local/realms/ztlab",
     "sub": "<user-uuid>",
     "exp": 1751234567,
     "realm_access": {"roles": ["financial-write"]},
     "preferred_username": "testuser01"
   }

5. api-gateway verify JWT:
   - Lấy JWKS: GET /realms/ztlab/protocol/openid-connect/certs
   - Tìm key với kid matching header
   - Verify chữ ký RSA bằng public key → nếu OK, JWT hợp lệ
   - Check exp → nếu quá hạn, trả 401
```

### 3.4. Cách Verify Keycloak Đang Chạy Đúng

```bash
# 1. Lấy token thủ công
TOKEN=$(curl -s -X POST http://localhost:8180/realms/ztlab/protocol/openid-connect/token \
  -d "grant_type=password&client_id=web-portal&username=testuser01&password=Test1234!" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token','ERROR'))")
echo "Token: ${TOKEN:0:60}..."

# 2. Decode JWT (không cần secret)
echo "$TOKEN" | python3 -c "
import sys, base64, json
t = sys.stdin.read().strip()
payload = t.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
d = json.loads(base64.b64decode(payload))
print(json.dumps(d, indent=2))
"

# 3. Test API với token
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:18080/health

# 4. Kiểm tra JWKS endpoint
curl -s http://localhost:8180/realms/ztlab/protocol/openid-connect/certs | python3 -c "
import sys,json; d=json.load(sys.stdin)
print(f'Keys: {len(d[\"keys\"])} | alg: {d[\"keys\"][0][\"alg\"]} | kid: {d[\"keys\"][0][\"kid\"][:20]}')
"
```

### 3.5. Cách Sửa Cấu Hình Keycloak

```bash
# Sửa realm-config.json (thêm user, sửa token TTL, v.v.)
vim k8s/keycloak/realm-config.json

# Update ConfigMap
kubectl --context ctx-aws create configmap keycloak-realm-config \
  -n identity --from-file=realm-config.json=k8s/keycloak/realm-config.json \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -

# Restart Keycloak để import lại realm
kubectl --context ctx-aws rollout restart deployment keycloak -n identity
kubectl --context ctx-aws rollout status deployment keycloak -n identity

# Reset password user thủ công (không cần restart)
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8180/realms/master/protocol/openid-connect/token \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=ztlab-admin-2026" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

USER_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8180/admin/realms/ztlab/users?username=testuser01 \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")

curl -s -X PUT http://localhost:8180/admin/realms/ztlab/users/$USER_ID/reset-password \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"type":"password","value":"Test1234!","temporary":false}'
```

---

## 4. SPIRE/SPIFFE — Workload Identity (Lớp 2)

**Vai trò trong ZTA:** Lớp 2 — Xác thực danh tính workload (service identity).  
**Namespace K8s:** `spire`

**Tại sao cần SVID khi đã có JWT?**  
JWT xác thực người dùng — nhưng không xác thực xem *service nào* đang gọi service nào. Một service bị compromise có thể tự gắn JWT của user và gọi sang service khác. SVID xác thực danh tính của container/process, độc lập với user, dựa trên Kubernetes identity (ServiceAccount + namespace).

### 4.1. SPIRE Server

**File cấu hình:** `spire/server/server.conf`  
**K8s manifest:** `spire/k8s/server-deployment.yaml`

```hcl
# spire/server/server.conf
server {
  bind_address = "0.0.0.0"
  bind_port    = "8081"
  trust_domain = "ztlab.local"          # Prefix cho mọi SPIFFE ID
  data_dir     = "/opt/spire/data/server"
  log_level    = "INFO"

  ca_subject {
    country      = ["VN"]
    organization = ["ZT-Lab"]
  }

  default_x509_svid_ttl = "1h"          # SVID hết hạn sau 1 giờ
  default_jwt_svid_ttl  = "5m"          # JWT SVID (ít dùng)
  ca_ttl                = "168h"        # CA cert sống 7 ngày, SPIRE tự rotate
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type     = "sqlite3"
      connection_string = "/opt/spire/data/server/datastore.sqlite3"
    }
  }

  KeyManager "disk" {
    plugin_data {
      keys_path = "/opt/spire/data/server/keys.json"
    }
  }

  NodeAttestor "k8s_psat" {        # PSAT = Projected Service Account Token
    plugin_data {
      clusters = {
        "aws-k3s" = {
          service_account_allow_list = ["spire:spire-agent"]
          kube_config_file           = "/root/.kube/aws-config"
        }
        "os-k3s" = {
          service_account_allow_list = ["spire:spire-agent"]
          kube_config_file           = "/root/.kube/os-config"
        }
      }
    }
  }
}
```

**Giải thích tham số:**

- **`trust_domain = "ztlab.local"`:** Mọi SVID dạng `spiffe://ztlab.local/<path>`. OPA check prefix này để xác nhận workload thuộc trust domain. SVID từ domain khác (ví dụ `spiffe://external.attacker/...`) bị từ chối.

- **`default_x509_svid_ttl = "1h"`:** SVID hết hạn 1 giờ. Envoy tự gia hạn ở ~30 phút (50% TTL). Nếu SPIRE Server down, SVID hiện tại vẫn dùng được đến hết hạn — tối đa 1 giờ grace period.

- **`ca_ttl = "168h"`:** CA certificate sống 7 ngày. SPIRE tự rotate và có overlap period để không gián đoạn service.

- **`k8s_psat` NodeAttestor:** SPIRE Agent gửi Kubernetes Projected Service Account Token lên Server. Server gọi K8s API `TokenReview` để xác minh token hợp lệ, pod đang chạy thật, đúng namespace và ServiceAccount. Không có password được truyền — attestation dựa hoàn toàn vào K8s identity.

**Apply SPIRE Server:**

```bash
# Apply K8s manifests
kubectl --context ctx-aws apply -f spire/k8s/server-deployment.yaml
kubectl --context ctx-aws apply -f spire/k8s/server-service.yaml

# Update ConfigMap nếu sửa server.conf
kubectl --context ctx-aws create configmap spire-server-config \
  -n spire --from-file=server.conf=spire/server/server.conf \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -
kubectl --context ctx-aws rollout restart deployment spire-server -n spire
```

### 4.2. SPIRE Agent

**File cấu hình:** `spire/agent/aws-agent.conf`  
**K8s manifest:** `spire/k8s/agent-daemonset.yaml`

```hcl
# spire/agent/aws-agent.conf
agent {
  data_dir         = "/run/spire"
  trust_domain     = "ztlab.local"
  server_address   = "spire-server.spire.svc.cluster.local"
  server_port      = "8081"
  socket_path      = "/run/spire/sockets/agent.sock"   # Envoy kết nối qua đây
  insecure_bootstrap = true
}

plugins {
  NodeAttestor "k8s_psat" {
    plugin_data { cluster = "aws-k3s" }
  }
  KeyManager "memory" { plugin_data {} }    # Key chỉ trong RAM
  WorkloadAttestor "k8s" {
    plugin_data { skip_kubelet_verification = true }
  }
}
```

**`socket_path` là giao tiếp Envoy ↔ SPIRE:**  
Envoy sidecar request SVID từ SPIRE Agent qua Unix domain socket `/run/spire/sockets/agent.sock` (gọi là SDS — Secret Discovery Service). Socket được mount vào mỗi pod qua `hostPath` volume. Không có network hop — agent cùng node với pod.

**`KeyManager "memory"`:** Private key Agent chỉ trong RAM. Khi Agent restart → key mới → SPIRE Server cấp SVID mới. Không persist key → giảm attack surface nếu node bị compromise.

**DaemonSet mount socket vào pod:**

```yaml
# spire/k8s/agent-daemonset.yaml
volumes:
  - name: spire-agent-socket
    hostPath:
      path: /run/spire/sockets
      type: DirectoryOrCreate

# Trong pod financial có thêm:
volumeMounts:
  - name: spire-agent-socket
    mountPath: /run/spire/sockets
    readOnly: true
```

### 4.3. Registration Entries — 7 Workload

Mỗi entry định nghĩa SPIFFE ID sẽ được cấp cho workload nào. Selector là **AND** — pod phải thỏa **cả hai** điều kiện.

```
SPIFFE ID                                    | Namespace  | ServiceAccount
─────────────────────────────────────────────┼────────────┼───────────────
spiffe://ztlab.local/aws/api-gateway         | financial  | api-gateway
spiffe://ztlab.local/aws/payment-service     | financial  | payment-service
spiffe://ztlab.local/aws/fraud-detection     | financial  | fraud-detection
spiffe://ztlab.local/aws/notification-service| financial  | notification-service
spiffe://ztlab.local/openstack/core-banking  | financial  | core-banking
spiffe://ztlab.local/openstack/account-service| financial | account-service
spiffe://ztlab.local/openstack/transaction-svc| financial | transaction-service
```

**Cách đăng ký entries:**

```bash
SPIRE_SERVER=$(kubectl --context ctx-aws get pod -n spire -l app=spire-server \
  -o jsonpath='{.items[0].metadata.name}')

# Đăng ký api-gateway
kubectl --context ctx-aws exec -n spire $SPIRE_SERVER -- \
  /opt/spire/bin/spire-server entry create \
  -parentID spiffe://ztlab.local/k8s-node/aws-master \
  -spiffeID spiffe://ztlab.local/aws/api-gateway \
  -selector k8s:ns:financial \
  -selector k8s:sa:api-gateway

# Xem tất cả entries
kubectl --context ctx-aws exec -n spire $SPIRE_SERVER -- \
  /opt/spire/bin/spire-server entry show

# Verify SVID của một workload
kubectl --context ctx-aws exec -n spire $SPIRE_SERVER -- \
  /opt/spire/bin/spire-server x509 validate \
  -spiffeID spiffe://ztlab.local/aws/api-gateway
```

**Cách Apply Thay Đổi SPIRE:**

```bash
# File entries được cấu hình trong: spire/k8s/entries.yaml (batch apply)
kubectl --context ctx-aws apply -f spire/k8s/entries.yaml

# Verify agent đang kết nối
kubectl --context ctx-aws logs -n spire -l app=spire-agent --tail=20 | grep "Node attestation"
```

---

## 5. Envoy Sidecar — mTLS và Policy Enforcement (Lớp 3)

**Vai trò trong ZTA:** Lớp 3 — Thực thi mTLS và gọi OPA cho mỗi request.  
**File cấu hình:** `envoy/envoy-sidecar.yaml`  
**Mount vào pod:** qua ConfigMap `envoy-sidecar-config` (namespace financial)

**Tại sao targetPort = 15006?**

```yaml
# k8s/financial/aws-services.yaml
kind: Service
spec:
  ports:
    - port: 8080
      targetPort: 15006    # Traffic đến pod đi vào Envoy INBOUND, không phải app
```

Khi service khác gọi `payment-service:8080`, K8s route đến port `15006` của pod — tức Envoy inbound. App (port 8080) chỉ nhận traffic từ Envoy localhost, không nhận từ bên ngoài pod.

### 5.1. Inbound Listener — Port 15006

```yaml
# envoy/envoy-sidecar.yaml — phần inbound
listeners:
  - name: inbound
    address:
      socket_address: { address: 0.0.0.0, port_value: 15006 }
    filter_chains:
      - transport_socket:
          name: envoy.transport_sockets.tls
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
            require_client_certificate: true    # mTLS bắt buộc — caller PHẢI có cert
            common_tls_context:
              tls_certificate_sds_secret_configs:
                - name: "spiffe://ztlab.local/aws/payment-service"  # cert của bản thân
                  sds_config:
                    api_config_source:
                      api_type: GRPC
                      grpc_services:
                        - envoy_grpc:
                            cluster_name: spire_agent    # lấy cert từ SPIRE Agent
              validation_context_sds_secret_config:
                name: ROOTCA     # CA cert để verify cert của caller
                sds_config:
                  api_config_source:
                    grpc_services:
                      - envoy_grpc: { cluster_name: spire_agent }
        filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              http_filters:
                - name: envoy.filters.http.ext_authz
                  typed_config:
                    failure_mode_allow: false    # OPA down → DENY (không phải allow)
                    include_peer_certificate: true  # gửi cert caller lên OPA
                    grpc_service:
                      envoy_grpc: { cluster_name: opa_ext_authz }
                      timeout: 2s
```

**`failure_mode_allow: false` cực kỳ quan trọng:** Nếu OPA crash/timeout, Envoy deny request — không phải allow. Đây là "fail closed" — an toàn hơn "fail open". Nếu cấu hình `true`, DoS vào OPA sẽ vô hiệu hóa toàn bộ access control.

**`include_peer_certificate: true`:** Envoy gửi TLS client certificate của caller (chứa SVID) lên OPA. OPA đọc `source_principal` = SPIFFE URI từ cert. Không thể giả mạo bằng HTTP header vì Envoy đọc từ TLS layer.

### 5.2. Outbound Listener — Port 15001

```yaml
# envoy/envoy-sidecar.yaml — phần outbound
listeners:
  - name: outbound
    address:
      socket_address: { address: 127.0.0.1, port_value: 15001 }
    filter_chains:
      - filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              route_config:
                virtual_hosts:
                  - routes:
                      - match: { prefix: "/payments" }
                        route: { cluster: payment_service }
                      - match: { prefix: "/score" }
                        route: { cluster: fraud_detection }
                      - match: { prefix: "/notify" }
                        route: { cluster: notification_service }
                      - match: { prefix: "/transactions/execute" }
                        route: { cluster: core_banking }      # → OpenStack
                      - match: { prefix: "/transactions" }
                        route: { cluster: transaction_service }
                      - match: { prefix: "/accounts" }
                        route: { cluster: account_service }
```

**Cluster definition cho mTLS outbound với SAN matching:**

```yaml
clusters:
  - name: payment_service
    load_assignment:
      endpoints:
        - lb_endpoints:
            - endpoint:
                address: { socket_address: { address: payment-service, port_value: 8080 } }
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        combined_validation_context:
          default_validation_context:
            match_typed_subject_alt_names:
              - san_type: URI
                matcher:
                  exact: "spiffe://ztlab.local/aws/payment-service"  # CHỈ chấp nhận SVID này
        tls_certificate_sds_secret_configs:
          - name: "spiffe://ztlab.local/aws/notification-service"    # SVID của bản thân

  # Cross-cloud cluster cho core-banking trên OpenStack
  - name: core_banking
    load_assignment:
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: 192.168.101.11    # OpenStack K3s master IP
                    port_value: 30080          # NodePort → Envoy inbound core-banking
```

**`match_typed_subject_alt_names`:** Envoy xác minh SVID phía server trước khi gửi data. Nếu `payment-service` bị replace bởi pod giả mạo có SVID khác → kết nối bị từ chối.

### 5.3. Access Log Format — JSON với SVID

```yaml
access_log:
  - name: envoy.access_loggers.file
    typed_config:
      path: "/var/log/envoy/access.log"
      json_format:
        timestamp:     "%START_TIME%"
        method:        "%REQ(:METHOD)%"
        path:          "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
        response_code: "%RESPONSE_CODE%"
        response_time: "%DURATION%"
        upstream:      "%UPSTREAM_HOST%"
        source_ip:     "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
        bytes_sent:    "%BYTES_SENT%"
        trace_id:      "%REQ(X-TRACE-ID)%"
        svid:          "%DOWNSTREAM_PEER_URI_SAN%"   # SPIFFE URI từ TLS cert
```

**`%DOWNSTREAM_PEER_URI_SAN%`:** Envoy đọc Subject Alternative Name URI từ TLS client certificate của caller. Field này không thể forge bằng HTTP header — Envoy đọc từ TLS cert layer. Đây là evidence quan trọng nhất trong KB2 (Lateral Movement detection).

### 5.4. Cluster SPIRE Agent — Lấy SVID qua SDS

```yaml
clusters:
  - name: spire_agent
    type: STATIC
    load_assignment:
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  pipe:
                    path: /run/spire/sockets/agent.sock    # Unix domain socket
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        explicit_http_config:
          http2_protocol_options: {}    # SDS API dùng gRPC/HTTP2
```

### 5.5. Cách Apply Thay Đổi Envoy

```bash
# Sửa envoy/envoy-sidecar.yaml
# Update ConfigMap cho tất cả pod
kubectl --context ctx-aws create configmap envoy-sidecar-config \
  -n financial --from-file=envoy-sidecar.yaml=envoy/envoy-sidecar.yaml \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -

# Restart tất cả pods để mount ConfigMap mới
kubectl --context ctx-aws rollout restart deployment \
  api-gateway payment-service fraud-detection notification-service -n financial

# Verify Envoy đang log
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=api-gateway \
    -o jsonpath='{.items[0].metadata.name}') \
  -c envoy -- tail -5 /var/log/envoy/access.log
```

---

## 6. OPA — Policy Decision Point (Lớp 4)

**Vai trò trong ZTA:** Lớp 4 — Quyết định allow/deny cho từng request.  
**Namespace K8s:** `financial` (chạy cùng namespace với microservices)  
**File policy:** `opa/policies/zta_policy.rego`  
**File config:** `opa/config/opa-config.yaml`

### 6.1. Cấu Hình OPA Server

**File:** `opa/config/opa-config.yaml`

```yaml
plugins:
  envoy_ext_authz_grpc:
    addr: :9191                    # gRPC endpoint cho Envoy
    path: zta/authz/allow          # package.rule trong .rego file

decision_logs:
  console: true                    # Ghi mỗi decision ra stdout dạng JSON
```

**`path: zta/authz/allow`:** OPA evaluate rule `allow` trong `package zta.authz`. Path phải khớp với `package zta.authz` ở đầu file Rego. Nếu sai path → OPA không evaluate được rule đúng → deny tất cả.

**`decision_logs.console: true`:** Mỗi decision được log ra stdout dạng JSON bao gồm toàn bộ input (path, method, headers, source principal) và kết quả. Promtail thu thập và push vào Loki với label `job=opa-decisions`.

**K8s Deployment:**

```yaml
# opa/deployment.yaml
containers:
  - name: opa
    image: openpolicyagent/opa:latest-envoy    # image có sẵn envoy ext_authz plugin
    args:
      - "run"
      - "--server"
      - "--addr=0.0.0.0:8181"        # REST API (debug)
      - "--config-file=/etc/opa/opa-config.yaml"
      - "/policies"                  # thư mục chứa .rego files
    ports:
      - containerPort: 8181    # REST API — debug, test policy
      - containerPort: 9191    # gRPC ext_authz — Envoy gọi vào
```

### 6.2. Policy — `opa/policies/zta_policy.rego`

**Nguyên tắc Deny-by-Default:**

```rego
package zta.authz

default allow = false    # TẤT CẢ request bị từ chối trừ khi có rule tường minh allow
```

**Input OPA nhận từ Envoy (qua CheckRequest gRPC):**

```rego
# Các field OPA extract từ input
headers          := input.attributes.request.http.headers
method           := input.attributes.request.http.method
path             := input.attributes.request.http.path
source_principal := object.get(
    object.get(input.attributes, "source", {}), "principal", "")
# source_principal = SVID của caller, lấy từ TLS cert qua include_peer_certificate:true
```

**Rule 1 — Public paths (health check, metrics):**

```rego
allow if {
    path_parts := split(path, "/")
    path_parts[1] in {"health", "metrics", "ready", "live"}
}
```

**Rule 2 — User request từ bên ngoài (có JWT, không có SVID):**

```rego
allow if { external_api_request }

external_api_request if {
    valid_jwt                     # JWT được ký bởi Keycloak (verify bằng JWKS)
    source_principal == ""        # Caller không có SVID = external client
    has_required_role             # JWT có role phù hợp với method + path
}

valid_jwt if {
    token := trim_prefix(object.get(headers, "authorization", ""), "Bearer ")
    [_, payload, _] := io.jwt.decode(token)
    payload.iss == "http://keycloak.ztlab.local/realms/ztlab"
    now := time.now_ns() / 1e9
    payload.exp > now
}

jwt_roles := roles if {
    token := trim_prefix(object.get(headers, "authorization", ""), "Bearer ")
    [_, payload, _] := io.jwt.decode(token)
    roles := payload.realm_access.roles
}

permissions := {
    "financial-read":   {"GET": true, "OPTIONS": true},
    "financial-write":  {"GET": true, "POST": true, "PUT": true, "OPTIONS": true},
    "security-analyst": {"GET": true, "OPTIONS": true},
    "security-admin":   {"GET": true, "POST": true, "PUT": true, "DELETE": true, "OPTIONS": true},
}

has_required_role if {
    some role in jwt_roles
    permissions[role][method]
}
```

**Rule 3 — Service-to-service với SVID hợp lệ:**

```rego
allow if { internal_service_request }

internal_service_request if {
    valid_svid
    has_service_permission
}

valid_svid if {
    startswith(source_principal, "spiffe://ztlab.local/")
}

service_permissions := {
    "spiffe://ztlab.local/aws/api-gateway":      {"/payments": {"POST","GET","PUT"}},
    "spiffe://ztlab.local/aws/payment-service":  {"/score": {"POST"}, "/notify": {"POST"}},
    "spiffe://ztlab.local/aws/fraud-detection":  {},
    "spiffe://ztlab.local/aws/notification-service": {},
}

has_service_permission if {
    perms := service_permissions[source_principal]
    path_perms := perms[path]
    method in path_perms
}
```

**Rule 4 — Core-banking transaction với fraud gate (đặc biệt quan trọng):**

```rego
allow if { core_transaction_with_fraud_gate }

core_transaction_with_fraud_gate if {
    startswith(path, "/transactions/execute")
    valid_svid
    fraud_gate_valid
}

fraud_gate_valid if {
    headers["x-fraud-gate"] == "passed"
    to_number(headers["x-fraud-score"]) < 75    # điểm fraud phải < ngưỡng 75
}
```

**Tại sao cần fraud gate OPA?** SVID chỉ xác nhận `payment-service` đang gọi `core-banking`. Nhưng payment-service có thể bị compromise và bỏ qua fraud-detection. Fraud gate buộc payment-service phải có header `x-fraud-gate: passed` do fraud-detection set — không thể tự set vì chỉ fraud-detection có logic tính score.

### 6.3. Cách Apply Policy Mới

```bash
# Sửa policy
vim opa/policies/zta_policy.rego

# Update ConfigMap
kubectl --context ctx-aws create configmap opa-policy -n financial \
  --from-file=zta_policy.rego=opa/policies/zta_policy.rego \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -

# OPA tự reload policy khi file thay đổi (watch mode) — không cần restart
# Nhưng nếu muốn restart để chắc chắn:
kubectl --context ctx-aws rollout restart deployment opa-server -n financial
```

### 6.4. Cách Test Policy Thủ Công

```bash
# Test policy trực tiếp qua OPA REST API (port-forward 8181)
kubectl --context ctx-aws port-forward -n financial svc/opa-server 8181:8181 &

# Test: api-gateway gọi payment-service → should allow
curl -s -X POST http://localhost:8181/v1/data/zta/authz/allow \
  -H "Content-Type: application/json" -d '{
    "input": {
      "attributes": {
        "request": {"http": {"method": "POST", "path": "/payments", "headers": {}}},
        "source": {"principal": "spiffe://ztlab.local/aws/api-gateway"}
      }
    }
  }' | python3 -m json.tool
# → {"result": true}

# Test: notification-service gọi /payments → should deny
curl -s -X POST http://localhost:8181/v1/data/zta/authz/allow \
  -H "Content-Type: application/json" -d '{
    "input": {
      "attributes": {
        "request": {"http": {"method": "POST", "path": "/payments/internal/execute", "headers": {}}},
        "source": {"principal": "spiffe://ztlab.local/aws/notification-service"}
      }
    }
  }' | python3 -m json.tool
# → {"result": false}  ← Lateral Movement bị chặn

# Test: fraud gate bypass → should deny
curl -s -X POST http://localhost:8181/v1/data/zta/authz/allow \
  -H "Content-Type: application/json" -d '{
    "input": {
      "attributes": {
        "request": {
          "http": {
            "method": "POST",
            "path": "/transactions/execute",
            "headers": {"x-fraud-gate": "passed", "x-fraud-score": "80"}
          }
        },
        "source": {"principal": "spiffe://ztlab.local/aws/payment-service"}
      }
    }
  }' | python3 -m json.tool
# → {"result": false}  ← score 80 >= 75, OPA deny
```

---

## 7. Microservices — Ứng Dụng Tài Chính

### 7.1. Stack Kỹ Thuật

Tất cả microservice viết bằng **Python 3.11** với **FastAPI**. Mỗi pod có 2 container: app (port 8080) và envoy (port 15006/15001).

| Service | Cloud | SVID | Chức năng |
|---|---|---|---|
| api-gateway | AWS | `aws/api-gateway` | JWT verify, rate limit, route |
| payment-service | AWS | `aws/payment-service` | Orchestrate thanh toán |
| fraud-detection | AWS | `aws/fraud-detection` | Tính fraud score |
| notification-service | AWS | `aws/notification-service` | Gửi thông báo |
| core-banking | OpenStack | `openstack/core-banking` | Thực thi lệnh tiền, gọi account + txn |
| account-service | OpenStack | `openstack/account-service` | Quản lý số dư |
| transaction-service | OpenStack | `openstack/transaction-service` | Ledger giao dịch |

### 7.2. api-gateway — Xác Thực và Rate Limiting

**File:** `services/api-gateway/main.py`  
**K8s manifest:** `k8s/financial/api-gateway-deployment.yaml`

```python
# services/api-gateway/main.py — các chức năng chính

# 1. JWT verification (KHÔNG gọi lại Keycloak mỗi request)
JWKS_URL = "http://keycloak.identity.svc.cluster.local:8080/realms/ztlab/protocol/openid-connect/certs"
_jwks_keys = {}

@app.on_event("startup")
async def load_jwks():
    resp = requests.get(JWKS_URL, timeout=10)
    for key_data in resp.json()["keys"]:
        kid = key_data["kid"]
        _jwks_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)

def verify_jwt(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    key = _jwks_keys[header["kid"]]
    return jwt.decode(token, key, algorithms=["RS256"],
                      audience="account", options={"verify_aud": False})

# 2. Rate limiting qua Redis (check IP blocklist)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis.financial.svc:6379")

async def check_ip_blocked(client_ip: str) -> bool:
    blocked = redis_client.get(f"ztlab:blocked_ip:{client_ip}")
    return blocked is not None

# 3. Route đến payment-service qua Envoy outbound
PAYMENT_URL = "http://127.0.0.1:15001/payments"  # qua Envoy outbound
```

### 7.3. fraud-detection — Mô Hình Điểm Số

**File:** `services/fraud-detection/main.py`

Fraud detection tính score dựa trên 4 yếu tố:

```python
def calculate_fraud_score(amount, account_id, channel, from_account):
    score = 0

    # Yếu tố 1: Số tiền (max 40 điểm)
    if amount > 500_000_000:   score += 40   # > 500M VND
    elif amount > 100_000_000: score += 30   # > 100M VND
    elif amount > 50_000_000:  score += 20   # > 50M VND
    elif amount > 10_000_000:  score += 10   # > 10M VND

    # Yếu tố 2: Velocity (max 40 điểm) — Redis counter
    key = f"ztlab:velocity:{account_id}:900"  # 15 phút window
    count = redis.incr(key)
    redis.expire(key, 900)
    score += min(count * 5, 40)

    # Yếu tố 3: Channel rủi ro (max 15 điểm)
    channel_risk = {"tor": 15, "vpn": 10, "mobile": 0, "web": 0, "api": 5}
    score += channel_risk.get(channel, 5)

    # Yếu tố 4: Giờ bất thường (max 5 điểm)
    hour = datetime.now().hour
    if hour < 6 or hour > 22: score += 5

    gate = "passed" if score < 70 else "blocked"
    verdict = "block" if score >= 70 else ("review" if score >= 40 else "allow")

    return {"score": min(score, 100), "gate": gate, "verdict": verdict}
```

**Ngưỡng OPA vs ngưỡng fraud-detection:**
- Fraud-detection: `score >= 70` → `gate=blocked` → payment-service không gọi core-banking
- OPA: `x-fraud-score >= 75` → deny — lớp thứ 2 nếu payment-service bị bypass

### 7.4. Cách Update Microservice

```bash
# Build image mới (nếu cần)
docker build -t ztlab/payment-service:latest services/payment-service/
# (hoặc chỉ sửa ConfigMap nếu code được mount qua ConfigMap)

# Rollout restart để apply code mới
kubectl --context ctx-aws rollout restart deployment payment-service -n financial
kubectl --context ctx-aws rollout status deployment payment-service -n financial --timeout=120s
```

---

## 8. PLG Stack — SIEM Thu Thập Log

**Namespace K8s:** `plg-stack`  
**Mục đích:** Thu thập toàn bộ log từ Envoy và OPA, lưu tập trung, cung cấp query interface cho Grafana và SOAR.

### 8.1. Loki — Log Aggregation Backend

**File:** `plg-stack/loki/loki-config.yml`  
**K8s ConfigMap:** `k8s/plg-stack/loki-configmap.yaml`

```yaml
# plg-stack/loki/loki-config.yml
auth_enabled: false    # Lab: không cần auth. Production: bật multi-tenancy

server:
  http_listen_port: 3100
  log_level: warn

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory:  /loki/rules
  replication_factor: 1
  ring:
    kvstore: { store: inmemory }   # Single-node: không cần etcd

schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb           # Loki v3: TSDB index engine, nhanh hơn boltdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h         # 1 index file/ngày → dễ xóa log cũ theo ngày

limits_config:
  reject_old_samples:          true
  reject_old_samples_max_age:  168h      # Từ chối PUSH log cũ hơn 7 ngày
  ingestion_rate_mb:           32
  ingestion_burst_size_mb:     64
  max_entries_limit_per_query: 50000

compactor:
  retention_enabled: true
  working_directory: /loki/compactor
  # Mặc định retention 90 ngày (2160h)
```

**Hai tham số retention khác nhau:**

| Tham số | Giá trị | Ý nghĩa |
|---|---|---|
| `reject_old_samples_max_age` | 7 ngày | Loki **từ chối nhận** log cũ hơn 7 ngày khi push |
| compactor `retention_period` | 90 ngày | Log được **giữ** 90 ngày rồi xóa |

**Apply Loki config:**

```bash
kubectl --context ctx-aws create configmap loki-config -n plg-stack \
  --from-file=loki-config.yml=plg-stack/loki/loki-config.yml \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -
kubectl --context ctx-aws rollout restart deployment loki -n plg-stack
```

**Verify Loki:**

```bash
curl -s http://localhost:13100/ready   # → "ready"
curl -s http://localhost:13100/config | python3 -c "
import sys,json; c=json.load(sys.stdin)
print('Schema:', c['schema_config']['configs'][0]['store'])
" 2>/dev/null || curl -s http://localhost:13100/config | grep -A2 "schema:"
```

### 8.2. Promtail — Log Collector DaemonSet

**File:** `plg-stack/promtail/promtail-aws.yml`  
**K8s manifest:** `k8s/plg-stack/promtail-daemonset.yaml`

Promtail chạy như DaemonSet — 1 pod trên mỗi node, tự động scale khi thêm node.

**3 nguồn log và pipeline:**

```yaml
# plg-stack/promtail/promtail-aws.yml
scrape_configs:

  # Nguồn 1: Envoy Access Log
  - job_name: envoy-access-aws
    static_configs:
      - targets: ["localhost"]
        labels:
          job: "envoy-access"
          cloud: "aws"
          __path__: /var/log/envoy/access.log
    pipeline_stages:
      - json:
          expressions:
            response_code: response_code   # extract field từ JSON log
            source_ip:     source_ip
            bytes_sent:    bytes_sent
            method:        method
            path:          path
            svid:          svid            # SPIFFE URI của caller
      - labels:
          response_code:   # promote thành Loki stream label → index
          source_ip:
          method:
          svid:

  # Nguồn 2: OPA Decision Log
  - job_name: opa-decisions-aws
    static_configs:
      - labels:
          job: "opa-decisions"
          __path__: /var/log/opa/decisions.json
    pipeline_stages:
      - json:
          expressions:
            opa_result:  result.allow      # nested: object result → key allow
            path:        input.attributes.request.http.path
            source_svid: input.source.principal
      - labels:
          opa_result:     # "true" hoặc "false"
          path:
          source_svid:

  # Nguồn 3: System Log
  - job_name: system-aws
    static_configs:
      - labels:
          job: "system"
          __path__: /var/log/syslog
```

**Tại sao cần labels?** Loki index theo labels, không index full-text. Label `response_code="401"` → query `{response_code="401"}` cực nhanh (lookup index). Không có label → phải scan toàn bộ log content.

**Volumes mount từ host:**

```yaml
# k8s/plg-stack/promtail-daemonset.yaml
volumes:
  - name: varlog
    hostPath: { path: /var/log }
  - name: envoy-logs
    hostPath:
      path: /var/log/envoy
      type: DirectoryOrCreate
  - name: opa-logs
    hostPath:
      path: /var/log/opa
      type: DirectoryOrCreate
```

**Apply Promtail:**

```bash
kubectl --context ctx-aws create configmap promtail-config -n plg-stack \
  --from-file=promtail-aws.yml=plg-stack/promtail/promtail-aws.yml \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -
kubectl --context ctx-aws rollout restart daemonset promtail -n plg-stack
```

**Verify Promtail đang push:**

```bash
# Xem targets
kubectl --context ctx-aws exec -n plg-stack \
  $(kubectl --context ctx-aws get pod -n plg-stack -l app=promtail \
    -o jsonpath='{.items[0].metadata.name}') \
  -- wget -qO- http://localhost:9080/targets 2>/dev/null | python3 -c "
import sys,json; d=json.load(sys.stdin)
for j in d: print(f'{j[\"labels\"].get(\"job\",\"?\")} → {j[\"health\"]}')
"

# Query Loki kiểm tra log đến
curl -sG http://localhost:13100/loki/api/v1/query_range \
  --data-urlencode 'query={job="envoy-access"}' \
  --data-urlencode "start=$(date -d '5 minutes ago' +%s%N)" \
  --data-urlencode "end=$(date +%s%N)" \
  --data-urlencode "limit=5" \
  | python3 -c "
import sys,json; d=json.load(sys.stdin)
streams = d['data']['result']
print(f'Streams: {len(streams)}')
for s in streams[:2]:
    print(f'  Labels: {s[\"stream\"]}')
    print(f'  Latest: {s[\"values\"][0][1][:100]}')
"
```

### 8.3. Grafana — Dashboard và Alerting

**File:** `plg-stack/grafana/grafana.ini`, K8s env vars override  
**K8s manifest:** `k8s/plg-stack/grafana.yaml`

```yaml
# k8s/plg-stack/grafana.yaml — environment variables
env:
  - name: GF_SECURITY_ADMIN_USER
    value: admin
  - name: GF_SECURITY_ADMIN_PASSWORD
    value: ZTALab2026!
  - name: GF_AUTH_ANONYMOUS_ENABLED
    value: "false"
  - name: GF_USERS_ALLOW_SIGN_UP
    value: "false"
  - name: GF_UNIFIED_ALERTING_ENABLED
    value: "true"          # Grafana Unified Alerting (v9+)
  - name: GF_SMTP_ENABLED
    value: "true"
  - name: GF_SMTP_HOST
    value: "smtp.gmail.com:587"
  - name: GF_SMTP_USER
    value: "voha2005@gmail.com"
  - name: GF_SMTP_PASSWORD
    valueFrom:
      secretKeyRef:
        name: grafana-smtp-secret
        key: password           # Gmail App Password 16 ký tự
  - name: GF_SMTP_STARTTLS_POLICY
    value: "MandatoryStartTLS"
```

**Provisioning — load cấu hình tự động từ ConfigMaps:**

| Mount path trong pod | ConfigMap | Nội dung |
|---|---|---|
| `/etc/grafana/provisioning/datasources` | `grafana-datasources` | Datasource Loki + Prometheus |
| `/etc/grafana/provisioning/dashboards` | `grafana-dashboard-provider` | Khai báo nơi load dashboard JSON |
| `/var/lib/grafana/dashboards` | `grafana-dashboards` | Dashboard JSON files |
| `/etc/grafana/provisioning/alerting` | `grafana-alerting` | Alert rules + notification policy |

**Datasource config:**

```yaml
# plg-stack/grafana/datasources/loki-datasource.yml
datasources:
  - name: Loki
    type: loki
    uid: Loki                # uid này được alert rules tham chiếu — không đổi
    url: http://loki:3100
    isDefault: true
    jsonData:
      maxLines: 1000
      timeout: 60
```

---

## 9. Grafana Alerting — Phát Hiện Tấn Công

**Thư mục:** `plg-stack/grafana/alerting/`  
**Áp dụng qua:** ConfigMap `grafana-alerting` (namespace plg-stack)

**Tại sao dùng `count_over_time()` thay vì log query trực tiếp?**

Grafana Unified Alerting dùng Server Side Expressions (SSE). SSE yêu cầu dữ liệu dạng `wide` (time series). Loki log query trả `long` (log entries) → lỗi SSE. `count_over_time()` convert log entries → metric → SSE hoạt động.

### 9.1. KB1 — Brute Force Login (T1110.001)

**File:** `plg-stack/grafana/alerting/brute-force-alert.yml`

```yaml
groups:
  - name: KB1-BruteForce
    interval: 1m        # evaluate mỗi 1 phút
    rules:
      - uid: brute-force-login
        title: "KB1 Brute Force Login"
        for: 0s         # fire ngay, không cần pending period
        condition: A
        data:
          - refId: A
            relativeTimeRange:
              from: 60   # xem 60 giây gần nhất
              to: 0
            datasourceUid: Loki
            model:
              expr: >
                sum by (source_ip) (
                  count_over_time(
                    {job="envoy-access"} | json | response_code=`401` [1m]
                  )
                )
              queryType: instant    # instant query → scalar (kiểu wide) → SSE OK
        noDataState: OK             # không có log 401 → alert inactive
        execErrState: Alerting      # query lỗi → vẫn alert (safe default)
        labels:
          severity: high
          attack_type: brute_force
          mitre: T1110.001
        annotations:
          summary: "Brute force login detected from {{ $labels.source_ip }}"
          threshold: "10 failed logins in 1 minute"
```

**LogQL giải thích:**
- `{job="envoy-access"}` — chọn stream với label job=envoy-access (Envoy access log)
- `| json` — parse JSON body của log line
- `| response_code=`401`` — filter chỉ lấy dòng có response_code = 401
- `count_over_time(...[1m])` — đếm số dòng trong 1 phút
- `sum by (source_ip)` — nhóm theo source IP

### 9.2. KB2 — Lateral Movement (T1021.007)

**File:** `plg-stack/grafana/alerting/lateral-movement-alert.yml`

```yaml
rules:
  - uid: lateral-movement-svid
    title: "KB2 Lateral Movement - Invalid SVID"
    for: 0s
    condition: A
    data:
      - refId: A
        relativeTimeRange: { from: 300, to: 0 }    # 5 phút
        datasourceUid: Loki
        model:
          expr: >
            sum(
              count_over_time(
                {job="opa-decisions",
                 opa_result="false",
                 attack_scenario="lateral_movement"}
                [5m]
              )
            )
          queryType: instant
    labels:
      severity: critical
      attack_type: lateral_movement
      mitre: T1021.007
```

**`attack_scenario="lateral_movement"` label:** Phân biệt KB2 với KB3 — cả hai đều có `opa_result=false`. Label này được set khi push log demo vào Loki. Trong thực tế, OPA decision log có thể thêm metadata qua custom label để Promtail extract.

### 9.3. KB3 — Fraud Gate Bypass (T1078.004)

**File:** `plg-stack/grafana/alerting/fraud-gate-bypass-alert.yml`

```yaml
rules:
  - uid: fraud-gate-bypass
    title: "KB3 Fraud Gate Bypass"
    for: 0s
    condition: A
    data:
      - refId: A
        relativeTimeRange: { from: 300, to: 0 }
        datasourceUid: Loki
        model:
          expr: >
            sum(
              count_over_time(
                {job="opa-decisions",
                 opa_result="false",
                 attack_scenario="fraud_gate_bypass"}
                [5m]
              )
            )
          queryType: instant
    labels:
      severity: critical
      attack_type: fraud_gate_bypass
      mitre: T1078.004
```

### 9.4. KB4 — Data Exfiltration (T1041)

**File:** `plg-stack/grafana/alerting/large-response-alert.yml`

```yaml
rules:
  - uid: large-response-exfiltration
    title: "KB4 Data Exfiltration - Large Response"
    for: 0s
    condition: A
    data:
      - refId: A
        relativeTimeRange: { from: 300, to: 0 }
        datasourceUid: Loki
        model:
          expr: >
            sum(
              count_over_time(
                {job="envoy-access"} | json | bytes_sent > 1048576
                [5m]
              )
            )
          queryType: instant
    labels:
      severity: high
      attack_type: large_response
      mitre: T1041
```

**`bytes_sent > 1048576`:** `1048576 = 1MB`. Bất kỳ response nào lớn hơn 1MB từ API là bất thường — giao dịch ngân hàng bình thường trả về < 10KB.

### 9.5. Notification Policy và Contact Points

**File:** `plg-stack/grafana/alerting/notification-policy.yml`

```yaml
contactPoints:
  - name: ztlab-security-admin
    receivers:
      - uid: ztlab-soar-webhook
        type: webhook
        settings:
          url: "http://soar-engine.plg-stack.svc.cluster.local:8080/grafana-webhook"
          httpMethod: POST
          maxAlerts: 10
      - uid: ztlab-admin-email
        type: email
        settings:
          addresses: "voha2005@gmail.com"
          singleEmail: true

policies:
  - receiver: ztlab-security-admin
    group_by: [grafana_folder, alertname]
    group_wait:     10s    # gom alerts trong 10s rồi gửi 1 lần
    group_interval: 5m     # sau khi gửi, chờ 5m trước khi gửi tiếp
    repeat_interval: 1h    # re-notify nếu alert vẫn firing sau 1h
```

**`group_wait: 10s`:** Khi alert fire, Grafana chờ 10 giây để gom các alert cùng folder/name lại thành 1 notification thay vì nhiều notification riêng lẻ.

### 9.6. Cách Apply Grafana Alerting

```bash
ALERTING_DIR=plg-stack/grafana/alerting

# Update ConfigMap với tất cả file alerting
kubectl --context ctx-aws create configmap grafana-alerting -n plg-stack \
  --from-file="$ALERTING_DIR/brute-force-alert.yml" \
  --from-file="$ALERTING_DIR/fraud-gate-bypass-alert.yml" \
  --from-file="$ALERTING_DIR/large-response-alert.yml" \
  --from-file="$ALERTING_DIR/lateral-movement-alert.yml" \
  --from-file="$ALERTING_DIR/notification-policy.yml" \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -

# Restart Grafana để load alerting mới
kubectl --context ctx-aws rollout restart deployment grafana -n plg-stack
kubectl --context ctx-aws rollout status deployment grafana -n plg-stack

# Verify alert rules
curl -s -u admin:ZTALab2026! http://localhost:3000/api/ruler/grafana/api/v1/rules \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
for folder,groups in d.items():
    for g in groups:
        for r in g['rules']:
            print(f'{r[\"grafana_alert\"][\"title\"]:40} state={r[\"grafana_alert\"][\"state\"]}')
"
```

---

## 10. SOAR Engine — Phản Ứng Tự Động và HITL

**File source:** `services/soar-engine/main.py`  
**Mount vào pod:** ConfigMap `soar-main-patch` (namespace plg-stack)  
**K8s manifest:** `k8s/plg-stack/ai-soar.yaml`

### 10.1. Environment Variables — Cấu Hình Hành Vi

```bash
# Từ k8s/plg-stack/ai-soar.yaml env section
LOKI_URL               = http://loki.plg-stack.svc.cluster.local:3100
SOAR_DRY_RUN           = false         # false = thực thi thật, không chỉ log
SOAR_AUTO_EXECUTE      = true          # auto-execute với severity thấp
SOAR_MIN_SEVERITY      = medium        # bỏ qua alert severity < medium
SOAR_HITL_SEVERITY     = high          # severity >= high → pending_approval
SOAR_MIN_CONFIDENCE    = 0.50          # confidence < 50% → bỏ qua
SOAR_NAMESPACE         = financial     # K8s namespace để thực thi playbook
SOAR_CASE_STORE_PATH   = /data/cases.jsonl
SOAR_BLOCK_IP_TTL_SECONDS = 86400      # IP block Redis: 24 giờ
ADMIN_EMAIL            = voha2005@gmail.com
SOAR_PUBLIC_URL        = http://127.0.0.1:8091
SMTP_HOST              = smtp.gmail.com
SMTP_PORT              = 587
SMTP_USER              = voha2005@gmail.com
SMTP_PASS              = <từ K8s Secret ai-secrets, key SMTP_PASS>
```

**Tạo Secret SMTP:**

```bash
kubectl --context ctx-aws create secret generic ai-secrets \
  -n plg-stack \
  --from-literal=SMTP_PASS='<gmail-app-password-16-chars>' \
  --from-literal=OPENAI_API_KEY='<nếu dùng AI Analyzer>'
```

### 10.2. Luồng Xử Lý Webhook từ Grafana

**Endpoint:** `POST /grafana-webhook`

```
Grafana POST body:
{
  "alerts": [{
    "labels": {
      "attack_type": "lateral_movement",
      "severity": "critical",
      "mitre": "T1021.007"
    },
    "annotations": {"summary": "..."},
    "startsAt": "2026-06-28T02:43:43Z"
  }]
}

SOAR xử lý:
  1. Extract attack_type, severity từ labels
  2. Check dedup: SHA256(attack_type + source_ip + workload) → Redis
     Nếu cùng fingerprint trong 5 phút → bỏ qua (dedup)
  3. Lookup TARGETS_BY_ATTACK → {context, workload, source_ip}
  4. Lookup PLAYBOOK_BY_ATTACK → playbook name
  5. _fetch_loki_lines(attack_type, source_ip, workload) → log evidence
  6. severity >= SOAR_HITL_SEVERITY (high) → status = pending_approval
  7. _smtp_send(email với evidence + approve/deny links)
  8. Lưu case vào /data/cases.jsonl
```

### 10.3. Map Attack Type → Playbook và Target

```python
# services/soar-engine/main.py
PLAYBOOK_BY_ATTACK = {
    "brute_force":       "revoke_user_sessions",  # Thu hồi session Keycloak
    "lateral_movement":  "isolate_workload",       # Scale deployment → 0
    "fraud_gate_bypass": "isolate_workload",       # Scale deployment → 0
    "large_response":    "restrict_egress",        # Scale core-banking → 0
    "access_denied":     "block_source_ip",        # Tạo NetworkPolicy block IP
    "privilege_escalation": "quarantine_workload", # Scale + network isolation
    "cryptomining":      "quarantine_workload",
}

TARGETS_BY_ATTACK = {
    "brute_force":       {"context": "ctx-aws",       "workload": "api-gateway"},
    "lateral_movement":  {"context": "ctx-aws",       "workload": "payment-service"},
    "fraud_gate_bypass": {"context": "ctx-aws",       "workload": "payment-service"},
    "large_response":    {"context": "ctx-openstack", "workload": "core-banking"},
}
```

**`ctx-openstack` cho `large_response`:** KB4 exfiltration từ core-banking trên OpenStack. SOAR thực thi playbook trên đúng cluster. Pod SOAR có kubeconfig của cả 2 cluster mount từ Secret.

### 10.4. Log Evidence — `_fetch_loki_lines()`

```python
# services/soar-engine/main.py
_LOKI_SEARCH_TERMS = {
    "brute_force":       "401|403|login.fail|authentication.fail|invalid.credentials",
    "lateral_movement":  "payments/internal/execute|transactions/execute|lateral_movement",
    "fraud_gate_bypass": "fraud_gate|fraud_score|bypass|gate=failed|fraud_gate_bypass",
    "large_response":    "bytes_sent|data.exfil|large.response|exfiltrat",
}

# Scope: namespace-wide hay per-workload
_EVIDENCE_NAMESPACE_WIDE = {"lateral_movement", "fraud_gate_bypass"}
# → query {namespace="financial"} thay vì {app="specific-service"}
# Lý do: OPA log có label app=opa, không phải app=payment-service
#         nếu query {app="payment-service"} sẽ miss OPA evidence

def _fetch_loki_lines(attack_type, source_ip=None, workload=None):
    term = _LOKI_SEARCH_TERMS.get(attack_type, "denied|error|attack|fail")
    if source_ip:
        term = f"{source_ip}|{term}"

    if attack_type in _EVIDENCE_NAMESPACE_WIDE:
        base = '{namespace="financial"}'
    else:
        base = f'{{app="{workload}"}}'

    query = f'{base} |~ "(?i)({term})"'
    # Lấy max 8 dòng, trong 30 phút gần nhất, mỗi dòng max 500 ký tự
```

### 10.5. Logic HITL — Phân Luồng Case

```python
# services/soar-engine/main.py
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SOAR_HITL_SEVERITY = os.getenv("SOAR_HITL_SEVERITY", "high")  # rank = 3

if SEVERITY_RANK[severity] >= SEVERITY_RANK[SOAR_HITL_SEVERITY]:
    # high (3) hoặc critical (4) → pending_approval
    status = "pending_approval"
    _send_hitl_email(case)           # email với log evidence
else:
    if SOAR_AUTO_EXECUTE:
        status = "executed"
        _run_playbook(case)          # thực thi ngay
    else:
        status = "pending_approval"
```

### 10.6. Playbook Implementation — 4 Phase

Mọi playbook thực thi theo 4 phase tuần tự:

```python
async def run_playbook(case: Case):
    # Phase 1: Collect
    extra_evidence = await _fetch_loki_lines(case.attack_type, ...)

    # Phase 2: Contain — hành động chính
    if case.playbook == "isolate_workload":
        k8s_client = get_k8s_client(case.context)  # ctx-aws hoặc ctx-openstack
        apps_v1 = client.AppsV1Api(k8s_client)
        apps_v1.patch_namespaced_deployment_scale(
            name=case.workload,
            namespace="financial",
            body={"spec": {"replicas": 0}}
        )

    elif case.playbook == "block_source_ip":
        # Tạo NetworkPolicy block source IP
        np = V1NetworkPolicy(
            metadata=V1ObjectMeta(
                name=f"soar-block-{hashlib.md5(source_ip.encode()).hexdigest()[:8]}",
                namespace="financial"
            ),
            spec=V1NetworkPolicySpec(
                pod_selector={},      # áp dụng cho TẤT CẢ pod
                policy_types=["Ingress"],
                ingress=[V1NetworkPolicyIngressRule(
                    _from=[V1NetworkPolicyPeer(
                        ip_block=V1IPBlock(
                            cidr="0.0.0.0/0",
                            except_=[f"{source_ip}/32"]
                        )
                    )]
                )]
            )
        )
        networking_v1.create_namespaced_network_policy("financial", np)

    elif case.playbook == "revoke_user_sessions":
        # Gọi Keycloak Admin API thu hồi session
        admin_token = get_keycloak_admin_token()
        requests.post(
            f"{KEYCLOAK_URL}/admin/realms/ztlab/users/{user_id}/logout",
            headers={"Authorization": f"Bearer {admin_token}"}
        )

    # Phase 3: Eradicate
    # Phase 4: Recover — update case status
    case.status = "executed"
    _save_case(case)
```

### 10.7. HITL Web Portal

**Web Portal:** `http://localhost:18081/security`  
**Login:** analyst01 / Test1234! (cần role security-admin để approve)

**API endpoints HITL:**

```bash
# Xem danh sách cases
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
for c in json.load(sys.stdin)[-5:]:
    print(f'{c[\"case_id\"]} | {c[\"attack_type\"]:20} | {c[\"status\"]:18}')
"

# Approve case và thực thi playbook mặc định
curl -s -X POST http://localhost:8091/cases/<case_id>/approve

# Chọn playbook cụ thể
curl -s -X POST http://localhost:8091/cases/<case_id>/execute-playbook \
  -H "Content-Type: application/json" \
  -d '{"playbook": "isolate_workload"}'

# Deny case
curl -s -X POST http://localhost:8091/cases/<case_id>/deny
```

### 10.8. Cách Apply Thay Đổi SOAR

```bash
# Sửa services/soar-engine/main.py
vim services/soar-engine/main.py

# Update ConfigMap
kubectl --context ctx-aws create configmap soar-main-patch -n plg-stack \
  --from-file=main.py=services/soar-engine/main.py \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -

# Restart SOAR
kubectl --context ctx-aws rollout restart deployment soar-engine -n plg-stack
kubectl --context ctx-aws rollout status deployment soar-engine -n plg-stack

# Verify SOAR health
curl -s http://localhost:8091/health | python3 -m json.tool
```

---

## 11. Redis — Velocity Cache và IP Blocklist

**File:** `k8s/financial/redis.yaml`  
**Namespace:** `financial` (cả AWS và OpenStack)

```yaml
# k8s/financial/redis.yaml
containers:
  - name: redis
    image: redis:7-alpine
    command: ["redis-server", "--requirepass", "$(REDIS_PASSWORD)"]
    env:
      - name: REDIS_PASSWORD
        valueFrom:
          secretKeyRef:
            name: redis-auth
            key: password    # = "ZTALab-Redis-2026!"
```

**3 loại dữ liệu trong Redis:**

**Loại 1 — Velocity Counter (fraud-detection):**
```
Key:   ztlab:velocity:{account_id}:{window_seconds}
Type:  String (integer)
TTL:   = window_seconds (900s = 15 phút)
Ops:   INCR (atomic) + EXPIRE
```

**Loại 2 — IP Blocklist (SOAR playbook):**
```
Key:   ztlab:blocked_ip:{ip_address}
Type:  String (reason string)
TTL:   86400s (24 giờ) = SOAR_BLOCK_IP_TTL_SECONDS
Ops:   SETEX (set + expire atomically)
```

**Loại 3 — SOAR Dedup Key:**
```
Key:   ztlab:soar:case:{attack_type}:{source_ip}:{workload}
Type:  String (case_id)
TTL:   300s (5 phút) = _WEBHOOK_DEDUP_S
```

**Commands verify Redis:**

```bash
REDIS_POD=$(kubectl --context ctx-aws get pod -n financial -l app=redis \
  -o jsonpath='{.items[0].metadata.name}')

# Xem tất cả keys
kubectl --context ctx-aws exec -n financial $REDIS_POD -- \
  redis-cli --pass ZTALab-Redis-2026! KEYS "ztlab:*"

# Kiểm tra IP bị block
kubectl --context ctx-aws exec -n financial $REDIS_POD -- \
  redis-cli --pass ZTALab-Redis-2026! \
  GET "ztlab:blocked_ip:10.10.0.99"

# Xem velocity counter của account
kubectl --context ctx-aws exec -n financial $REDIS_POD -- \
  redis-cli --pass ZTALab-Redis-2026! \
  GET "ztlab:velocity:ACC-1001:900"

# Xem TTL còn lại của một key
kubectl --context ctx-aws exec -n financial $REDIS_POD -- \
  redis-cli --pass ZTALab-Redis-2026! \
  TTL "ztlab:blocked_ip:10.10.0.99"

# Xóa IP block thủ công (rollback)
kubectl --context ctx-aws exec -n financial $REDIS_POD -- \
  redis-cli --pass ZTALab-Redis-2026! \
  DEL "ztlab:blocked_ip:10.10.0.99"
```

---

## 12. WireGuard — Tunnel Cross-Cloud

**Mục đích:** Kết nối AWS cluster (10.10.1.x) với OpenStack cluster (192.168.101.x) để microservice trên AWS gọi core-banking trên OpenStack như thể cùng mạng.

**Ansible playbook:** `ansible/playbooks/wireguard.yml`

### 12.1. Cấu Hình Tunnel

```ini
# /etc/wireguard/wg0.conf trên AWS gateway (13.213.245.227)
[Interface]
Address    = 10.200.0.1/24
PrivateKey = <aws-private-key>     # sinh bởi: wg genkey
ListenPort = 51820

[Peer]
PublicKey  = <os-public-key>
Endpoint   = 10.10.10.188:51820   # OpenStack floating IP
AllowedIPs = 192.168.100.0/24, 192.168.101.0/24, 192.168.102.0/24
PersistentKeepalive = 25           # giữ NAT mapping

# /etc/wireguard/wg0.conf trên OpenStack gateway
[Interface]
Address    = 10.200.0.2/24
PrivateKey = <os-private-key>
ListenPort = 51820

[Peer]
PublicKey  = <aws-public-key>
Endpoint   = 13.213.245.227:51820  # AWS EIP
AllowedIPs = 10.10.0.0/16, 10.200.0.0/24
PersistentKeepalive = 25
```

**`PersistentKeepalive = 25`:** AWS gateway ở sau NAT. Keepalive mỗi 25s giữ NAT mapping alive — nếu không có traffic 25s, NAT table bị xóa → mất kết nối.

**Cryptography:** WireGuard dùng Curve25519 (ECDH), ChaCha20-Poly1305 (encryption), BLAKE2s (hash). Session key rotate mỗi 3 phút.

### 12.2. Routing Cross-Cloud

```
payment-service (AWS 10.10.1.x)
  → Envoy outbound 127.0.0.1:15001
  → cluster core_banking (endpoint: 192.168.101.11:30080)
  → AWS K3s routing: 192.168.101.0/24 → wg0 interface
  → WireGuard encrypt → UDP 51820 → 13.213.245.227
  → OpenStack gateway nhận → WireGuard decrypt
  → → 192.168.101.11:30080 (NodePort)
  → K3s route → core-banking pod:15006 (Envoy inbound)
  → Envoy verify mTLS → OPA → core-banking app
```

### 12.3. Setup và Verify

```bash
# Setup WireGuard qua Ansible
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/wireguard.yml

# Verify tunnel từ AWS gateway node (SSH)
ssh -i ~/.ssh/ztlab-key -J ubuntu@52.221.255.36 ubuntu@10.10.1.10 "sudo wg show wg0"
# Output phải có: latest handshake: X seconds ago, transfer: X.XX KiB received

# Ping OpenStack từ payment-service pod
kubectl --context ctx-aws exec -n financial \
  $(kubectl --context ctx-aws get pod -n financial -l app=payment-service \
    -o jsonpath='{.items[0].metadata.name}') \
  -c app -- curl -s --max-time 3 http://192.168.101.11:30084/health
# Kỳ vọng: JSON response từ core-banking
```

---

## 13. Network Policy — Phân Vùng Namespace

**File:** `k8s/financial/network-policies/aws-allow-list.yaml`

NetworkPolicy chuyển K8s từ allow-all (mặc định) sang whitelist model. CNI plugin (Flannel+iptables trong K3s) translate rules thành iptables rules trên node.

### 13.1. financial namespace — Ingress Rules

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: financial-allow-list
  namespace: financial
spec:
  podSelector: {}    # áp dụng cho tất cả pod trong namespace
  policyTypes: [Ingress, Egress]
  ingress:
    # K8s health checks (kubelet)
    - from:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
      ports: [{ port: 15006 }]

    # Prometheus scrape metrics
    - from:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: monitoring }
      ports: [{ port: 8080 }, { port: 15006 }, { port: 8181 }]

    # Pod-to-pod trong namespace (service calls)
    - from:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: financial }
      ports:
        - port: 15006    # Envoy inbound
        - port: 9191     # OPA gRPC ext_authz
        - port: 5432     # PostgreSQL
        - port: 6379     # Redis

    # SOAR Engine query Redis, gọi API
    - from:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: plg-stack }
      ports: [{ port: 6379 }, { port: 15006 }]

    # External traffic qua Traefik Ingress (NodePort → 80)
    - from:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
      ports: [{ port: 15006 }]
```

### 13.2. financial namespace — Egress Rules

```yaml
  egress:
    # DNS resolution (bắt buộc — không có DNS thì không resolve service name)
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
      ports: [{ port: 53, protocol: UDP }, { port: 53, protocol: TCP }]

    # Pod-to-pod trong namespace
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: financial }
      ports:
        - port: 8080; port: 15006; port: 9191; port: 5432; port: 6379

    # Keycloak JWT verification (api-gateway fetch JWKS)
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: identity }
      ports: [{ port: 8080 }]

    # Push log đến Loki, gọi SOAR
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: plg-stack }
      ports: [{ port: 8080 }, { port: 3100 }]

    # Core-banking trên OpenStack qua WireGuard tunnel
    - to:
        - ipBlock: { cidr: "192.168.101.0/24" }
      ports:
        - { port: 30080 }    # core-banking Envoy NodePort
        - { port: 30082 }    # account-service Envoy NodePort
        - { port: 30083 }    # transaction-service Envoy NodePort
```

### 13.3. SOAR Tạo NetworkPolicy Động

Khi playbook `block_source_ip` chạy, SOAR tạo NetworkPolicy block IP attacker:

```yaml
# NetworkPolicy tự động tạo bởi SOAR
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: soar-block-f4eec49d    # hash của source IP
  namespace: financial
spec:
  podSelector: {}              # tất cả pod
  policyTypes: [Ingress]
  ingress:
    - from:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.10.0.99/32   # loại trừ IP attacker → traffic từ IP này bị drop
```

### 13.4. Verify và Apply Network Policy

```bash
# Apply
kubectl --context ctx-aws apply -f k8s/financial/network-policies/aws-allow-list.yaml

# Xem các NetworkPolicy đang active
kubectl --context ctx-aws get networkpolicy -n financial
kubectl --context ctx-aws describe networkpolicy financial-allow-list -n financial

# Xem NetworkPolicy SOAR đã tạo
kubectl --context ctx-aws get networkpolicy -n financial | grep soar-block

# Xóa NetworkPolicy SOAR (rollback)
kubectl --context ctx-aws delete networkpolicy -n financial \
  $(kubectl --context ctx-aws get networkpolicy -n financial \
    --no-headers | awk '/soar-block/{print $1}' | tr '\n' ' ')
```

---

## 14. K8s RBAC — Quyền Hạn SOAR

**File:** `k8s/rbac/soar-rbac.yaml`

SOAR cần quyền K8s để thực thi playbook nhưng không được có nhiều hơn mức cần thiết (Principle of Least Privilege).

```yaml
# Role — chỉ áp dụng trong namespace financial
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: soar-financial-responder
  namespace: financial
rules:
  - apiGroups: ["apps"]
    resources: ["deployments", "deployments/scale"]
    verbs: ["get", "list", "patch", "update"]    # scale deployment = patch replicas

  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get", "list", "patch", "update"]    # isolate = patch selector

  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]                        # chỉ đọc — không xóa pod

  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "create", "update", "patch", "delete"]  # block IP
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: soar-financial-responder
  namespace: financial    # binding có tác dụng tại financial namespace
subjects:
  - kind: ServiceAccount
    name: soar-engine       # ServiceAccount của SOAR pod
    namespace: plg-stack    # SOAR chạy ở plg-stack, nhưng có quyền ở financial
roleRef:
  kind: Role
  name: soar-financial-responder
  apiGroup: rbac.authorization.k8s.io
```

**Cross-namespace RoleBinding:** ServiceAccount từ namespace `plg-stack` có quyền trong namespace `financial`. K8s hỗ trợ cross-namespace trong `subjects`.

**Tại sao Role thay vì ClusterRole?** ClusterRole = quyền trên toàn cluster. Role = chỉ trong namespace `financial`. Nếu SOAR bị compromise, attacker chỉ thao túng được `financial` namespace — không phải cả cluster.

**Apply và verify:**

```bash
kubectl --context ctx-aws apply -f k8s/rbac/soar-rbac.yaml

# Verify SOAR có quyền scale deployment
kubectl --context ctx-aws auth can-i patch deployments \
  --as=system:serviceaccount:plg-stack:soar-engine -n financial
# → yes

# Verify SOAR KHÔNG có quyền xóa pod
kubectl --context ctx-aws auth can-i delete pods \
  --as=system:serviceaccount:plg-stack:soar-engine -n financial
# → no

# Verify SOAR KHÔNG có quyền ở identity namespace
kubectl --context ctx-aws auth can-i get secrets \
  --as=system:serviceaccount:plg-stack:soar-engine -n identity
# → no
```

---

## 15. Phụ Lục — Index File Cấu Hình và Lệnh Nhanh

### 15.1. Tổng Hợp File Cấu Hình

| Thành phần | File nguồn | K8s resource | Cách apply |
|---|---|---|---|
| Keycloak realm | `k8s/keycloak/realm-config.json` | ConfigMap `keycloak-realm-config` | `kubectl apply -f` → restart pod |
| Keycloak deployment | `k8s/keycloak/deployment.yaml` | Deployment `keycloak` | `kubectl apply -f` |
| SPIRE Server config | `spire/server/server.conf` | ConfigMap `spire-server-config` | Update CM → restart |
| SPIRE Agent config | `spire/agent/aws-agent.conf` | ConfigMap `spire-agent-config` | Update CM → rollout DaemonSet |
| SPIRE entries | `spire/k8s/entries.yaml` | SPIRE registration | `kubectl apply -f` |
| Envoy sidecar | `envoy/envoy-sidecar.yaml` | ConfigMap `envoy-sidecar-config` | Update CM → restart tất cả financial pods |
| OPA policy | `opa/policies/zta_policy.rego` | ConfigMap `opa-policy` | Update CM → OPA reload |
| OPA config | `opa/config/opa-config.yaml` | ConfigMap `opa-config` | Update CM → restart OPA |
| Loki config | `plg-stack/loki/loki-config.yml` | ConfigMap `loki-config` | Update CM → restart Loki |
| Promtail config | `plg-stack/promtail/promtail-aws.yml` | ConfigMap `promtail-config` | Update CM → rollout DaemonSet |
| Grafana alerting | `plg-stack/grafana/alerting/*.yml` | ConfigMap `grafana-alerting` | Update CM → restart Grafana |
| SOAR Engine | `services/soar-engine/main.py` | ConfigMap `soar-main-patch` | Update CM → restart SOAR |
| Redis | — | `k8s/financial/redis.yaml` | `kubectl apply -f` |
| NetworkPolicy | `k8s/financial/network-policies/aws-allow-list.yaml` | NetworkPolicy | `kubectl apply -f` |
| WireGuard | `ansible/playbooks/wireguard.yml` | host-level config | `ansible-playbook` |
| SOAR RBAC | `k8s/rbac/soar-rbac.yaml` | Role + RoleBinding | `kubectl apply -f` |

### 15.2. Lệnh Nhanh — Health Check

```bash
# Kiểm tra tất cả services trong 1 lệnh
echo "=== API Gateway ===" && curl -s http://localhost:18080/health | python3 -m json.tool
echo "=== SOAR ===" && curl -s http://localhost:8091/health | python3 -m json.tool
echo "=== Loki ===" && curl -s http://localhost:13100/ready
echo "=== Grafana ===" && curl -s http://localhost:3000/api/health | python3 -m json.tool
echo "=== Keycloak ===" && curl -s http://localhost:8180/realms/ztlab | python3 -c "
import sys,json; d=json.load(sys.stdin); print(f'Realm: {d[\"realm\"]} Token TTL: {d.get(\"accessTokenLifespan\",\"?\")}s')"

# Pod status nhanh
kubectl --context ctx-aws get pods -n financial -n plg-stack -n identity -n spire \
  --no-headers | awk '{print $1, $2, $3}' | column -t
```

### 15.3. Lệnh Nhanh — Demo KB2 (Lateral Movement)

```bash
# Bước 1: Restore về trạng thái bình thường
bash scripts/run-demo.sh --restore

# Bước 2: Chạy KB2
LOKI_URL=http://127.0.0.1:13100 SOAR_URL=http://127.0.0.1:8091 \
  bash scripts/run-demo.sh --kb2

# Bước 3: Kiểm tra case SOAR vừa tạo
curl -s http://localhost:8091/cases | python3 -c "
import sys,json
cases = [c for c in json.load(sys.stdin) if c.get('attack_type')=='lateral_movement']
if cases:
    c = cases[-1]
    print(f'Case: {c[\"case_id\"]}')
    print(f'Status: {c[\"status\"]}')
    print(f'Playbook: {c[\"playbook\"]}')
    print(f'Email sent: {c.get(\"email_sent\", False)}')
"

# Bước 4: Admin approve qua web portal
# → http://localhost:18081/security (analyst01 / Test1234!)
# Hoặc qua API:
CASE_ID="<case_id từ bước 3>"
curl -s -X POST http://localhost:8091/cases/$CASE_ID/execute-playbook \
  -H "Content-Type: application/json" \
  -d '{"playbook": "isolate_workload"}'

# Bước 5: Verify payment-service đã bị isolate
kubectl --context ctx-aws get deployment payment-service -n financial \
  -o jsonpath='{.spec.replicas}'
# → 0 (đã scale down)

# Bước 6: Restore lại sau khi demo
bash scripts/run-demo.sh --restore
```

### 15.4. Lệnh Nhanh — Update Cấu Hình

```bash
# Update Grafana alerting (KB1-KB4 alert rules)
ALERTING_DIR=plg-stack/grafana/alerting
kubectl --context ctx-aws create configmap grafana-alerting -n plg-stack \
  $(for f in $ALERTING_DIR/*.yml; do echo "--from-file=$f"; done) \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -
kubectl --context ctx-aws rollout restart deployment grafana -n plg-stack

# Update SOAR Engine code
kubectl --context ctx-aws create configmap soar-main-patch -n plg-stack \
  --from-file=main.py=services/soar-engine/main.py \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -
kubectl --context ctx-aws rollout restart deployment soar-engine -n plg-stack

# Update OPA policy (không cần restart — OPA watch file)
kubectl --context ctx-aws create configmap opa-policy -n financial \
  --from-file=zta_policy.rego=opa/policies/zta_policy.rego \
  --dry-run=client -o yaml | kubectl --context ctx-aws apply -f -

# Xem log SOAR real-time
kubectl --context ctx-aws logs -n plg-stack -l app=soar-engine -f --tail=50

# Xem log Grafana (kiểm tra alert evaluation)
kubectl --context ctx-aws logs -n plg-stack -l app=grafana -f --tail=50 | \
  grep -E "alert|firing|webhook"
```

### 15.5. Luồng Đầy Đủ — Từ Config Đến Detection

```
1. [IaC]      Terraform provision AWS VMs → Ansible install K3s + WireGuard
2. [Identity] Keycloak start → import realm-config.json → tạo users/roles/clients
3. [SPIRE]    SPIRE Server start → NodeAttestor k8s_psat cho 2 cluster
4. [SPIRE]    SPIRE Agent DaemonSet start → NodeAttestation → nhận Agent SVID
5. [SPIRE]    Entry registration → 7 workload entries (aws/..., openstack/...)
6. [Envoy]    Pod start → Envoy container mount spire-agent-socket
7. [Envoy]    Envoy connect SPIRE Agent SDS (grpc, /run/spire/sockets/agent.sock)
8. [Envoy]    Envoy nhận SVID X.509 cert từ SPIRE → cert sẵn sàng cho mTLS
9. [OPA]      OPA server start → load zta_policy.rego → listen :9191 gRPC
10.[PLG]      Promtail DaemonSet start → mount /var/log/envoy, /var/log/opa
11.[PLG]      Loki start → nhận log từ Promtail push
12.[PLG]      Grafana start → provisioning (datasource, alerts, dashboards) từ ConfigMap
13.[SOAR]     SOAR Engine start → kết nối Loki, SMTP ready
14.[TRAFFIC]  User request → Keycloak (JWT) → api-gateway (Envoy verify JWT + OPA)
              → payment-service (mTLS SVID) → fraud-detection → core-banking (WireGuard)
15.[LOG]      Mỗi request → Envoy access.log + OPA decision.log → Promtail → Loki
16.[DETECT]   Grafana evaluate LogQL mỗi 1 phút → count_over_time > threshold → fire
17.[ALERT]    Grafana → POST /grafana-webhook → SOAR tạo case
18.[HITL]     SOAR → email với log evidence → admin approve → playbook execute
19.[CONTAIN]  playbook: scale=0 hoặc NetworkPolicy block IP hoặc revoke session
20.[RECOVER]  bash scripts/run-demo.sh --restore → khôi phục về trạng thái ban đầu
```

---

*Tài liệu này mô tả cấu hình thực tế của hệ thống ZTLab tại thời điểm 2026-06-28.*  
*Mọi thay đổi cấu hình phải được commit vào git trước khi apply.*
