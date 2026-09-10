# HỆ THỐNG CHI TIẾT — Zero-Trust Security Detection & Response cho Microservice đa Cloud

> Tài liệu mô tả toàn bộ **kiến trúc, cấu hình, module và luồng hoạt động** của hệ thống ở trạng thái hiện tại (branch `feat/crapi-target`, 2026-09-10). Ứng dụng mục tiêu: **OWASP crAPI** (thay ứng dụng "finance" tự viết trước đây). Toàn bộ khung Zero-Trust được giữ nguyên cơ chế.
>
> Tài liệu đồng hành: `DEPLOY.md` (quy trình triển khai), `TARGET-CRAPI.md` / `KE-HOACH-CRAPI.md` / `KET-QUA-CRAPI.md` (kế hoạch + kết quả migration), `README.md`.

---

## 1. TỔNG QUAN & MỤC TIÊU

**Bài toán:** áp dụng mô hình **Zero Trust** (NIST SP 800-207) cho một hệ microservice **triển khai trên nhiều đám mây** (AWS + OpenStack), kèm lớp **phát hiện và phản ứng** (SIEM + SOAR) khớp với bề mặt tấn công thực tế.

**Nguyên tắc Zero Trust hiện thực hoá:**

| Tenet NIST 800-207 | Hiện thực trong hệ thống |
|---|---|
| 1. Mọi tài nguyên là "resource" | Mỗi microservice = một workload có danh tính SPIFFE riêng |
| 2. Bảo mật mọi liên lạc bất kể vị trí | mTLS STRICT (Istio PeerAuthentication) mọi hop trong mesh; hop cross-cloud không sidecar (Postgres) đi qua WireGuard |
| 3. Cấp quyền theo từng phiên | OPA đánh giá **từng request** (Envoy ext_authz), không có "vùng tin cậy" |
| 4. Chính sách động | RBAC realm-role + **step-up OTP** (theo *loại* hành động) + **device posture** + **device trust** |
| 5. Giám sát toàn vẹn tài sản | `posture-agent` CronJob + `security-scanner-job` (container isolation) + Gatekeeper admission |
| 6. Xác thực + cấp quyền động, nghiêm ngặt | Keycloak OIDC/PKCE ở BFF; OPA tự verify chữ ký JWT (Keycloak JWKS + OIDC discovery) + kiểm `aud`/`iss`/`exp` |
| 7. Thu thập tối đa dữ liệu để cải thiện | PLG (Promtail→Loki→Grafana) + Prometheus + OPA decision log + istio access log + BFF audit log → SOAR |

**Ranh giới đóng góp (làm rõ trong luận văn):** hệ thống **KHÔNG** vá lỗ hổng tầng ứng dụng của crAPI (BOLA, BFLA, JWT confusion, SSRF, mass assignment...). Đó là **chủ đích** — chúng là "challenge" của crAPI. Đóng góp là **lớp hạ tầng Zero-Trust + phát hiện/phản ứng** bao quanh: chặn *lateral movement*, *privilege escalation qua network*, *credential replay*, ép *step-up*, và phát hiện → tạo case SOAR khi lỗ hổng app bị khai thác.

---

## 2. KIẾN TRÚC TỔNG THỂ

### 2.1 Hai đám mây, biên phân chia theo "danh tính"

```
                    ┌─────────────────────────── Người dùng (trình duyệt) ───────────────────────────┐
                    │                         http://crapi.ztlab.local  (hoặc port-forward :18081)   │
                    ▼
         ╔══════════════════════ AWS (VPC 10.10.0.0/16) ══════════════════════╗   ╔════════ OpenStack (Kolla AIO trên host `aio`) ════════╗
         ║  k3s cluster "aws-k3s"  (master + 2 worker, subnet 10.10.1.0/24)   ║   ║  k3s cluster "os-k3s" (master + 2 worker,             ║
         ║                                                                    ║   ║                        subnet 192.168.101.0/24)      ║
         ║  ns crapi:                                                         ║   ║  ns crapi:                                            ║
         ║   • bff            (FastAPI — EDGE PEP, điểm vào DUY NHẤT)          ║   ║   • crapi-identity  (Java Spring — cấp JWT)          ║
         ║   • crapi-web      (React/nginx tĩnh, bff proxy tới)               ║   ║   • postgresdb      (Postgres 14 — DB DUY NHẤT)      ║
         ║   • crapi-community(Go)                                            ║   ║   • mailhog         (SMTP + UI, MH_STORAGE=memory)   ║
         ║   • crapi-workshop (Django)                                        ║   ║   • opa-server ×3   (PDP — path crosscloud)          ║
         ║   • mongodb, redis                                                 ║   ║                                                      ║
         ║   • opa-server ×3  (PDP — path authz)                              ║   ║  ns spire: spire-server + spire-agent (DaemonSet)    ║
         ║                                                                    ║   ║  ns istio-system: istiod                              ║
         ║  ns identity: keycloak + keycloak-db (Postgres)                    ║   ║                                                      ║
         ║  ns identity-directory: openldap (SCIM demo directory)             ║   ║  os-gateway VM (192.168.100.10 / .101.1 / .102.1)    ║
         ║  ns spire, istio-system, gatekeeper-system, vault                  ║   ║   — NAT private/identity → internet, WireGuard peer  ║
         ║  ns plg-stack: loki, grafana, promtail, soar-engine,               ║   ║                                                      ║
         ║                ai-analyzer, security-scorer                        ║   ║  edge-router (Neutron): DMZ 192.168.100.0/24 ↔ ext   ║
         ║  ns monitoring: prometheus                                         ║   ║                          (floating IP 172.10.10.169) ║
         ║  aws-gateway VM (WireGuard peer) · aws-bastion (SSH jump)          ║   ║                                                      ║
         ╚════════════════════════════════════╤═══════════════════════════════╝   ╚═══════════════════╤══════════════════════════════════╝
                                              │                                                       │
                                              └───────────── WireGuard (wg0, 10.200.0.0/24, UDP 51820) ┘
                                                    aws_gateway 10.200.0.1  ◄────►  os_gateway 10.200.0.2
                                    (định tuyến chéo: 10.42/10.43 ◄─► 192.168.101/102, PersistentKeepalive=25 + wg-watchdog)
```

**Vì sao chia như vậy** (khớp Nghị định 53/2022 về nội địa hoá dữ liệu):
- **OpenStack** = "nơi cấp danh tính + toàn bộ dữ liệu" → `crapi-identity` + `postgresdb` (DB **duy nhất**, chứa cả `user_login` lẫn dữ liệu shop) + `mailhog`.
- **AWS** = "nơi cần xác thực" → `bff` + các service tiêu thụ (`crapi-web/community/workshop`) + `mongodb` (chỉ community/workshop dùng) + `redis` (bff dùng cho session/rate-limit).

> **GATE 0 (đọc source crAPI):** `crapi-community` (Go) và `crapi-workshop` (Django) **đọc thẳng bảng `user_login` của identity** (`Meta.db_table = "user_login"`, `models.FindAuthorByEmail`) → **không tách được 2 Postgres**. Quyết định **DB-2**: 1 Postgres duy nhất đặt ở OpenStack; community/workshop (AWS) tới qua **NodePort 30432 + WireGuard** (plain TCP — Postgres không có sidecar).

### 2.2 Phiên bản thành phần

| Thành phần | Phiên bản |
|---|---|
| Kubernetes | k3s (2 cluster độc lập, `aws-k3s` / `os-k3s`) |
| Service mesh | Istio **1.22.3** (istioctl install, `istio-operator.yaml` là single source of truth) |
| Identity (SPIFFE) | SPIRE **1.9.4** (server + agent DaemonSet) |
| PDP | Open Policy Agent (image `openpolicyagent/opa@sha256:…`, plugin `envoy_ext_authz_grpc`) |
| IdP | Keycloak (realm `ztlab`, image trong `k8s/keycloak/`) |
| Admission | Gatekeeper (OPA Constraint Framework) |
| Secrets | HashiCorp Vault (dev mode, kubernetes auth) |
| SIEM | Grafana + Loki + Promtail (PLG) + Prometheus |
| Target app | OWASP crAPI Core (identity/community/workshop/web/mailhog), ảnh ghim `@sha256:` từ Docker Hub |

---

## 3. HẠ TẦNG (Terraform + Ansible)

### 3.1 Terraform

**`terraform/aws/`** — VPC `10.10.0.0/16`, subnet public (bastion + gateway), private `10.10.1.0/24` (3 node k3s + `aws-security`), monitoring `10.10.2.0/24` (`aws-loki`). Security group `ztlab-sg-private`:
- inbound 22 từ bastion, 6443/10250/8472(vxlan)/8081(spire) nội dải, **NodePort 30000–32767 từ dải OpenStack** (`192.168.101.0/24` — cho hop cross-cloud SNAT qua os-gateway; đã thêm rule này, cần AWS creds + `terraform apply`).
- `aws-gateway` EIP cố định (WireGuard endpoint mà os_gateway trỏ tới).
- `aws-bastion` public IP — **SSH jump host** cho mọi truy cập vào node private (ProxyJump).

**`terraform/openstack/`** — 3 network:
| Network | Subnet | Router | DNS |
|---|---|---|---|
| `zta-dmz` | 192.168.100.0/24 | gắn thẳng `zta-edge-router` (SNAT ra `public1`, floating IP) | `var.subnet_dns_nameservers` = **1.1.1.1 / 1.0.0.1** |
| `zta-private` | 192.168.101.0/24 | qua **os-gateway VM** (192.168.101.1) | như trên |
| `zta-identity` | 192.168.102.0/24 | qua os-gateway (192.168.102.1) | như trên |

> **DNS = 1.1.1.1 (không phải 8.8.8.8):** uplink internet của host `aio` là hotspot điện thoại (`172.20.10.x`) / CGNAT hay **chặn/timeout UDP/53 tới 8.8.8.8** → hỏng DNS toàn cụm → SPIRE agent không attest → mТLS sập dây chuyền. Biến `subnet_dns_nameservers` đổi được nếu mạng khác. Xem §10.

Security groups OpenStack (`terraform/openstack/security_groups.tf`): `neutron-sg-os-dmz` (443, 22-from-aio, WG 51820), `neutron-sg-os-private` (6443/10250/8472/8081/8181/9191 nội dải, 22 từ `192.168.101.1/32` = os-gateway, NodePort 30000-32767 từ chính dải), `neutron-sg-os-identity` (DNS 53 từ private, 22 từ os-gateway).

`cloud-init-gateway.yaml`: os-gateway bật `ip_forward`, MASQUERADE `-o ens3` (DMZ, đường ra internet), route tĩnh `1.1.1.1/1.0.0.1 via 192.168.100.1`.

### 3.2 Ansible (`ansible/playbooks/`)

| Playbook | Việc |
|---|---|
| `baseline.yml` | apt cơ bản, swap, `iptables-persistent`, tuning kernel |
| `k3s.yml` | cài k3s server/agent 2 cluster (node-token, `--flannel-iface`, disable traefik? không — giữ traefik cho ingress) |
| `wireguard.yml` | sinh keypair, render `wg0.conf` (`PersistentKeepalive = 25`), bật `wg-quick@wg0`; **`wg-watchdog.sh` + systemd timer 60s** trên cả 2 gateway (nếu handshake > 200s cũ + ping peer fail → `systemctl restart wg-quick@wg0`) |
| `promtail.yml` | (deploy Promtail — thực tế Promtail chạy như DaemonSet k8s, xem §7) |

**Inventory** (`ansible/inventory/hosts.yml`): các host AWS đi qua `ProxyJump=ubuntu@<bastion>`; các node OpenStack private đi qua `ProxyJump=ubuntu@<os_gateway_floating_ip>`. `deploy-all.sh` bước 9 tự vá IP + **`ssh-keygen -R`** các jump host (floating IP tái sử dụng qua các lần deploy → host key cũ trong `known_hosts` làm hop ProxyJump con chết: `Connection closed by UNKNOWN port 65535`).

---

## 4. LỚP ZERO-TRUST

### 4.1 SPIRE — danh tính workload (SPIFFE)

- **2 SPIRE server** (mỗi cluster 1), datastore `sqlite3` trên **hostPath `/opt/spire/data/server`** pin vào node `spire-server=true` (`strategy: Recreate`). UpstreamAuthority = `disk` (root CA `spire/root-ca/ca.crt`, `ca_ttl = 168h`).
- **SPIRE agent** = DaemonSet, `hostNetwork: true`, `dnsPolicy: ClusterFirstWithHostNet`. NodeAttestor `k8s_psat` (`cluster = "aws-k3s"` / `"os-k3s"`). Init container `wait-for-server` + `alias-socket-for-istio` (`ln -sfn agent.sock socket` — Istio SDS hardcode tên socket là `socket`). **`imagePullPolicy: IfNotPresent`** cả 3 container (tránh ImagePullBackOff khi node mất internet).
- **SVID TTL:** `default_x509_svid_ttl = "1h"`, `default_jwt_svid_ttl = "5m"`.
- **Scheme SPIFFE tuỳ biến (KHÔNG phải mặc định Istio):** `spiffe://ztlab.local/<cloud>/<service>`:

  | AWS (4) | OpenStack (1 + Job) |
  |---|---|
  | `spiffe://ztlab.local/aws/bff` | `spiffe://ztlab.local/openstack/crapi-identity` |
  | `spiffe://ztlab.local/aws/crapi-web` | `spiffe://ztlab.local/openstack/crapi-seed` (Job seed) |
  | `spiffe://ztlab.local/aws/crapi-community` | |
  | `spiffe://ztlab.local/aws/crapi-workshop` | |

  Node-alias: một entry `-node` parent vào `spire-server`, selector `k8s_psat:cluster:<x>` (mọi agent khớp, bất kể UUID) → workload entry parent vào alias `spiffe://ztlab.local/nodes/{aws,os}-k3s` thay vì UUID node. Hardcode trong **`scripts/ensure-spire-entries.sh`**, gọi vô điều kiện mỗi lần deploy.
- Vì scheme khác mặc định (`spiffe://<trustdomain>/ns/<ns>/sa/<sa>`), **mỗi Service cần một `DestinationRule` với `subjectAltNames` tường minh** (xem §4.2).

### 4.2 Istio service mesh

- Cài bằng `istioctl install -f k8s/istio/istio-operator.yaml` (2 cluster). `trustDomain: ztlab.local`. SPIRE là nguồn cert thật (Istio agent SDS ↔ spire-agent qua socket).
- **`meshConfig.extensionProviders`**: `opa-ext-authz` → `envoyExtAuthzGrpc` `opa-service.crapi.svc.cluster.local:9191`.
- **PeerAuthentication** ns `crapi`: `default` = **STRICT**; per-workload PERMISSIVE cho `bff` + `crapi-web` (nhận traffic từ ngoài mesh: BFF từ Traefik/port-forward; crapi-web static do BFF gọi).
- **DestinationRule custom-SAN** — mỗi service một cái (`k8s/crapi/istio-policies.yaml`), ví dụ:
  - `crapi-workshop.crapi.svc.cluster.local` → `subjectAltNames: ["spiffe://ztlab.local/aws/crapi-workshop"]`
  - `crapi-identity-openstack.crapi.svc.cluster.local` → `mode: ISTIO_MUTUAL`, SAN `spiffe://ztlab.local/openstack/crapi-identity` (hop cross-cloud, cả 2 đầu có sidecar).
  - `postgresdb-openstack.crapi.svc.cluster.local` → `mode: DISABLE` (Postgres OpenStack không sidecar → client istio-proxy đi plaintext, WireGuard lo mã hoá).
  - `opa-service` → `opa-service-plaintext` (`mode: DISABLE`, cổng 8181/9191 nội cụm).
- **AuthorizationPolicy CUSTOM → `opa-ext-authz`** cho `bff`, `crapi-web`, `crapi-community`, `crapi-workshop` (AWS) và `crapi-identity` (OpenStack). `rules: [{}]` (áp không điều kiện). Envoy gọi OPA gRPC ext_authz **mỗi request** → fail-closed (OPA không tới → 503).
- **Access log format tuỳ biến** (JSON, có field `svid` = SPIFFE của peer từ mТLS cert) → Promtail job `envoy-access`.

### 4.3 OPA — 2 PDP, 2 đường quyết định

| | AWS | OpenStack |
|---|---|---|
| Deployment | `opa-server` ×3 (ns crapi) | `opa-server` ×3 (ns crapi) |
| ext_authz path | `zta/crapi/authz/allow` | `zta/crapi/crosscloud/allow` |
| Policy file | `opa/crapi-policies/zta_crapi.rego` (package `zta.crapi.authz`) | `opa/crapi-policies/crosscloud_crapi.rego` (package `zta.crapi.crosscloud`) |
| ConfigMap | `opa-config` (per-cluster) + `opa-policies-crapi` (from-dir `opa/crapi-policies/`) | như AWS |

**`service_acl` — nguồn sự thật duy nhất** (`policy/service-graph-crapi.yaml`):
- Sinh ra `opa/crapi-policies/service_acl.rego` (package `zta.crapi.generated`) + `k8s/crapi/network-policies/{aws,os}-pod-segmentation.yaml` bằng `scripts/gen-rego-acl.py` + `scripts/gen-networkpolicy.py`.
- Test `tests/test_service_graph_consistency.py` (2 bài): (1) chạy generator xong file không đổi; (2) mọi edge nghiệp vụ có mặt ở CẢ L7 (rego) lẫn L4 (netpol).
- **Ma trận edge (L7 — qua OPA):**

  | Nguồn (SPIFFE) | Đích | Method + path prefix |
  |---|---|---|
  | `aws/bff` | `openstack/crapi-identity` (cross) | GET/POST/PUT/DELETE `/identity/api`, GET `/identity/health_check` |
  | `aws/bff` | `aws/crapi-community` | GET/POST `/community/api` |
  | `aws/bff` | `aws/crapi-workshop` | GET/POST/PUT `/workshop/api` |
  | `aws/bff` | `aws/crapi-web` | GET `/`, `/static`, `/images`, `/index.html`, `/favicon` |
  | `aws/crapi-community` | `openstack/crapi-identity` (cross) | POST `/identity/api/auth/verify`, GET `/identity/health_check` |
  | `aws/crapi-workshop` | `openstack/crapi-identity` (cross) | idem |

  Mọi cặp KHÔNG có trong bảng (vd `crapi-community → crapi-workshop`) → OPA `internal_service_request` = false → **deny (403)** = chống lateral movement.

- **Edge L4 thuần (không qua OPA service_acl):** `bff→redis:6379`, `community/workshop→mongodb:27017`, `community/workshop→postgresdb-openstack:30432` (cross), `crapi-identity→postgresdb:5432`, `crapi-identity→mailhog` (nội OpenStack), `*→opa:9191/8181`.

**`zta_crapi.rego` (AWS) — cấu trúc quyết định:**
```
allow if public_path                    # /health, /identity/health_check, POST /identity/api/auth/{signup,login,verify,check-otp,…}, GET jwks.json, bff→crapi-web static
allow if internal_service_request       # valid_svid ∧ allowed_by_acl ∧ keycloak_gate

keycloak_gate:
  • nếu nguồn KHÔNG phải bff  → chỉ cần service_acl (hop service-to-service, không có token người dùng)
  • nếu nguồn LÀ bff          → valid_jwt ∧ role_permits_action ∧ posture_ok ∧ device_trust_ok ∧ step_up_ok

valid_jwt        = io.jwt.decode_verify(X-Access-Token, {cert: <Keycloak JWKS>, iss: <OIDC discovery issuer>, aud: "crapi-bff"}) ∧ exp còn hạn
role_permits_action:
   GET/HEAD/OPTIONS  → role ∈ {crapi-user, crapi-mechanic, crapi-admin, soc-analyst}
   POST/PUT/PATCH/DELETE → không phải admin_path/mechanic_only_path, role ∈ {crapi-user, crapi-mechanic, crapi-admin}
   admin_path (/identity/api/v2/admin, /workshop/api/management) → chỉ crapi-admin
   mechanic_only_path → crapi-mechanic | crapi-admin
strong_control_required = (method là GHI) ∨ sensitive_crapi_action
posture_ok        = ¬strong_control_required ∨ (x-device-posture == "compliant" | vắng)
device_trust_ok   = ¬strong_control_required ∨ (x-device-trust ≠ "suspicious")
sensitive_crapi_action = POST {/workshop/api/shop/orders, …/return_order, /identity/api/v2/user/reset-password, …/change-email}
step_up_ok        = ¬sensitive_crapi_action ∨ jwt_payload.acr == "high"
```
> **Lưu ý thiết kế:** `posture`/`device_trust` chỉ gate **hành động GHI + nhạy cảm**, khớp BFF `_rbac_ok` (chỉ chặn suspicious device ở method GHI) và KE-HOACH §3.2. Đọc thường vẫn đủ mạnh bằng valid_jwt + RBAC + valid_svid + mТLS.

**`crosscloud_crapi.rego` (OpenStack)** — giữ `service_acl` + `allowed_by_acl` + `posture_compliant`; **bỏ** `device_trust_compliant` (BFF đã kiểm ở đầu vào; hop bff→identity cross-cloud chỉ tới OPA OpenStack). Guard `crapi-identity`: chỉ chấp nhận nguồn `bff` / `crapi-community` / `crapi-workshop`.

**JWT verify:** OPA gọi `http.send` tới `keycloak.identity.svc.cluster.local:8080/realms/ztlab/protocol/openid-connect/certs` + `.well-known/openid-configuration` (`force_cache` 300s). Xác nhận qua `counter_rego_builtin_http_send_network_requests: 2` trong decision log.

### 4.4 NetworkPolicy L4

`k8s/crapi/network-policies/`:
- `{aws,os}-allow-list.yaml` (podSelector `{}` — baseline): ingress Traefik→bff:8080, monitoring→:metrics, `spire`→opa:8181, `plg-stack`→redis:6379, nội `crapi`→`crapi` any; egress DNS, `crapi`→`crapi`, bff→`identity`(Keycloak 8080), `crapi`→`plg-stack`(Loki 3100), cross-cloud ipBlock `192.168.101.0/24`:30090/30432, `istio-system`:15012.
- `{aws,os}-pod-segmentation.yaml` (generated từ service-graph — podSelector `app=<x>`, ingress theo `service_acl`).

> **Giới hạn thực tế (ghi rõ trong luận văn):** trên k3s + kube-router, NetworkPolicy **không được enforce đầy đủ cho traffic có Istio sidecar** — **L7 (OPA `service_acl`) là lớp phân đoạn thật đang hoạt động**. NetworkPolicy L4 là defense-in-depth + tài liệu ý định + có hiệu lực cho đường không-sidecar (opa:8181, DNS, cross-cloud ipBlock).

### 4.5 Keycloak — IdP

- Realm `ztlab` (`k8s/keycloak/realm-config.json`, `--import-realm` lần boot đầu; các thiết lập không retrofit được thì `deploy-crapi.sh` / `deploy-app.sh` đăng ký live qua Admin API).
- **Client:** `crapi-bff` (public, PKCE S256, `standardFlowEnabled`, redirectUris `http://crapi.ztlab.local/*` + `http://localhost:18081/*` + `http://localhost:8080/*` + `127.0.0.1` tương ứng), `crapi-bff-stepup` (cùng cấu hình, dùng cho flow step-up). Protocol mapper `aud-crapi-bff` (oidc-audience-mapper → `aud=crapi-bff` trong access token, để OPA kiểm `aud`).
- **Realm role:** `crapi-user`, `crapi-mechanic`, `crapi-admin`, `soc-analyst`.
- **User demo** (khai trong realm-config.json, đồng thời seed vào crAPI Postgres qua Job):

  | username / email `@ztlab.local` | password | role |
  |---|---|---|
  | testuser01, testuser02 | `Test1234!` | crapi-user |
  | merchant01 | `Test1234!` | crapi-mechanic, crapi-user |
  | analyst01 | `Test1234!` | soc-analyst |
  | demoadmin | `DemoAdmin2026!` | crapi-admin + mechanic + user + soc-analyst |
  | stepup-demo | `StepupDemo123!` | crapi-user (demo enroll OTP) |

- **Step-up flow** (`deploy_stepup_flow`): browser authentication flow tuỳ biến với Conditional-OTP — khi client yêu cầu `acr_values=high` (BFF `/auth/start-stepup`), Keycloak ép nhập OTP → token có `acr: "high"`.
- **OpenLDAP federation** (`deploy_openldap_and_federation`): `openldap` (ns `identity-directory`) làm "SCIM demo directory" READ_ONLY federate vào Keycloak — minh hoạ nguồn danh tính doanh nghiệp, không phải directory thật.
- **Event logging** (bật 2026-09-10): `eventsEnabled: true`, `eventsListeners: ["jboss-logging"]`, `bruteForceProtected: true` (`failureFactor: 20`, `waitIncrementSeconds: 60`, `permanentLockout: false`) → failed login ghi `LOGIN_ERROR` ra stdout → Promtail → dùng cho alert brute-force.

### 4.6 BFF — Edge PEP (`services/bff/main.py`, FastAPI)

**Điểm vào DUY NHẤT của crAPI.** Tái dùng nhiều từ `web-portal` + `api-gateway` cũ.

| Chức năng | Chi tiết |
|---|---|
| **OIDC/PKCE** | `/login`, `/auth/start`, `/auth/start-stepup` (`acr_values=high`), `/auth/callback` (đổi code→token), `/auth/logout`. State + `code_verifier` ký (`itsdangerous`), lưu trong token tạm. Keycloak proxy dưới `/kc/*` (rewrite `/realms/` → `/kc/realms/` trong HTML + Location + Set-Cookie path) → luồng login self-contained trên cùng host. |
| **Session** | Cookie `ztlab_bff_session` = `{sid}` ký; state thật ở **Redis** `bff:session:<sid>` (TTL, fallback in-proc). Cookie `ztlab_bff_device` = device id ổn định (365 ngày). |
| **Device trust** | `_evaluate_device_trust`: phân tích User-Agent (`_parse_device_label`) + so với `bff:known_devices:<user>` trong Redis → `trusted` \| `new_device` \| `suspicious` (UA không phải trình duyệt). Gắn header `X-Device-Trust`. |
| **Device posture** | `shared/posture.py` — posture của chính pod bff (`DEVICE_POSTURE` = `compliant`/…). Gắn header `X-Device-Posture`. |
| **Token exchange (mỗi request proxy)** | `Authorization: Bearer <crapi_jwt>` — bff **mint RS256** `{sub: email, role: <"user"/"mechanic"/"admin">, iat, exp}` bằng **khoá RSA của chính crAPI** (`deploy/vendor/crapi-keys/jwks.json` == `default_jwks.json` nhúng trong ảnh identity, `kid = MKMZkDenUfuDF2byYowDj7tW5Ox6XG4Y1THTEGScRg8`). `X-Access-Token: <keycloak_access_token>` — cho OPA kiểm realm role + `acr`. Client KHÔNG được tự đặt các header này (bff strip trước khi forward). |
| **RBAC gương** (`_rbac_ok`) | Gương của `zta_crapi.rego` `role_permits_action` — cần vì hop bff→identity (cross-cloud) chỉ qua OPA OpenStack (không kiểm token người dùng). GET/HEAD/OPTIONS → OK cho mọi role hợp lệ; GHI vào `_ADMIN_PREFIXES` → cần `crapi-admin`; GHI mechanic prefix → mechanic/admin. → audit `event=rbac_denied` khi từ chối. |
| **Step-up gương** (`_is_sensitive`) | Danh sách `SENSITIVE_ACTIONS` → nếu `session.acr != "high"` → `401 {"error":"step_up_required","stepup_url":"/auth/start-stepup"}` + audit `event=step_up_required`. |
| **Device-trust gate** | `suspicious` + method GHI → `403 {"reason":"suspicious_device"}` + audit `event=device_trust_denied`. |
| **Reverse proxy** | `/identity/*` → `crapi-identity-openstack.crapi.svc:30090` (cross-cloud) · `/community/*` → `crapi-community:8087` · `/workshop/*` → `crapi-workshop:8000` · còn lại → `crapi-web:80`. `CHATBOT_SERVICE`/`MAILHOG_WEB_SERVICE` trỏ về `crapi-web:80` (không deploy — để nginx crapi-web resolve upstream, khỏi `[emerg] host not found`). |
| **Audit → Loki** | `_audit(event, …)` POST JSON tới `LOKI_URL` job `bff-audit` (`user_login`, `rbac_denied`, `step_up_required`, `device_trust_denied`, `sensitive_action_ok`, `proxy_error`). |

### 4.7 Gatekeeper + Vault

- **Gatekeeper** (`k8s/gatekeeper/`): constraint-templates + constraints — admission control (vd chặn container privileged, bắt buộc label/resource limit). Chạy `gatekeeper-system` ns trên AWS.
- **Vault** (`k8s/vault/vault.yaml`): dev mode, kubernetes auth. `soar-engine` role → đọc `secret/grafana-smtp-secret` (mật khẩu SMTP cho email HITL). `deploy-app.sh` unseal + config + seed secret.

---

## 5. ỨNG DỤNG MỤC TIÊU — OWASP crAPI Core

| Service | Ngôn ngữ | Cổng | Cluster | DB |
|---|---|---|---|---|
| `crapi-identity` | Java Spring | 8080 (NodePort 30090) | OpenStack | Postgres `user_login`, `user_details`, `vehicle_*` |
| `crapi-community` | Go | 8087 | AWS | Postgres (bảng của identity) + MongoDB (posts) |
| `crapi-workshop` | Django | 8000 | AWS | Postgres (bảng của identity) + MongoDB |
| `crapi-web` | React + nginx | 80 | AWS | — (SPA tĩnh) |
| `mailhog` | Go | 1025 (SMTP) / 8025 (UI) | OpenStack | — (`MH_STORAGE=memory`) |
| `postgresdb` | Postgres 14 | 5432 (NodePort 30432) | OpenStack | DB `crapi`, `-c max_connections=500` |
| `mongodb` | Mongo 4.4 | 27017 | AWS | |
| `redis` | Redis 7 | 6379 | AWS | (bff session/rate-limit) |

**Ảnh:** `crapi/*` + `postgres:14` + `mongo:4.4` ghim `@sha256:` (xem `scripts/sync-app-images.sh` `PULL_IMAGES`). **Node k3s tự pull** từ Docker Hub (giống ảnh istio/gatekeeper/opa) — `sync-app-images.sh` KHÔNG còn save/import ảnh bên thứ 3 (bug `docker save` gộp multi-arch → `ctr import: content digest not found`). Chỉ `bff` (+ engine detection) là ảnh tự build (`services/Dockerfile`, `ARG SERVICE_NAME`).

**JWT nội bộ crAPI:** community + workshop verify token bằng cách gọi `POST http://<identity>/identity/api/auth/verify` **mỗi request** rồi `jwt.decode(verify_signature=False)` lấy `sub`, `User.objects.get(email=sub)`. → thêm 2 hop cross-cloud HTTP mỗi request nghiệp vụ; edge `community/workshop → identity POST /identity/api/auth/verify` phải có trong `service_acl`.

**Lỗ hổng crAPI GIỮ NGUYÊN (chủ đích):** BOLA (`/identity/api/v2/vehicle/{id}/location`), BFLA, JWT HS256-confusion + JKU injection, mass assignment, SSRF (mechanic API)… Zero-Trust không vá tầng app — chỉ bao quanh.

**Seed** (`k8s/crapi/seed-job.yaml`, Job ns crapi OpenStack, có sidecar + SVID `openstack/crapi-seed`, cuối script `POST localhost:15020/quitquitquit`): `reset-test-users` (tạo `adam007/pogba006/robot001@example.com` + vehicles cho BOLA) + signup từng user demo Keycloak (`<user>@ztlab.local` / `CrapiSeed123!` → khớp email để token bff-minted resolve ở community/workshop).

---

## 6. CƠ CHẾ CROSS-CLOUD

**Mẫu "selectorless Service + Endpoints"** (bê từ `core-banking-openstack` của finance app):

```
# Áp trên AWS (k8s/crapi/cross-cloud-aws.yaml):
Service crapi-identity-openstack      (port 30090, KHÔNG selector)
Endpoints crapi-identity-openstack    → 192.168.101.11:30090   (os-k3s-master, NodePort)
DestinationRule crapi-identity-openstack-mtls  → ISTIO_MUTUAL, SAN spiffe://…/openstack/crapi-identity
Service postgresdb-openstack          (port 30432, KHÔNG selector)
Endpoints postgresdb-openstack        → 192.168.101.11:30432
DestinationRule postgresdb-openstack-plaintext → tls mode DISABLE   (Postgres không sidecar → WireGuard lo)

# Áp trên OpenStack (k8s/crapi/cross-cloud-os.yaml): TRỐNG (mailhog nằm cùng cluster identity, không có hop OS→AWS)
```

CoreDNS resolve tên `…svc.cluster.local` native → Istio auto-discover Endpoints như mọi Service → traffic đi `pod (10.42.x) → os-gateway/aws-gateway → WireGuard (10.200.0.x) → NodePort đích`. `deploy-crapi.sh::apply_manifest()` bỏ qua file cross-cloud rỗng (tránh `error: no objects passed to apply` giết script `set -e`).

**6 hop cross-cloud thực tế** (verified qua istio access log): `bff→identity` (HTTP mТLS), `community→identity /verify` (HTTP mТLS, mỗi request), `workshop→identity /verify` (idem), `community→postgresdb:30432` (TCP/WG), `workshop→postgresdb:30432` (TCP/WG), (`identity→mailhog` nay nội cụm OpenStack).

**WireGuard** (`ansible/templates/wg0-{aws,os}-gateway.j2`): `wg0` 10.200.0.0/24, UDP 51820, `PersistentKeepalive = 25`. `allowed_ips` os_gateway: `10.42.0.0/16, 10.43.0.0/16` (pod/svc AWS) ; aws_gateway: `192.168.101.0/24, 192.168.102.0/24`. **`wg-watchdog`** (systemd timer 60s): tunnel chết vì UDP drop kéo dài KHÔNG tự phục hồi → watchdog restart.

---

## 7. QUAN SÁT — PHÁT HIỆN — PHẢN ỨNG

### 7.1 PLG pipeline

**Promtail** (DaemonSet, `k8s/plg-stack/promtail-daemonset.yaml`, `CLOUD_PROVIDER` per-cluster). Loki chạy 1 nơi (AWS); OpenStack Promtail đẩy log qua **Loki-relay** (`socat 10.10.10.1:13099 → localhost:13100`, `open-admin-uis.sh`) qua WireGuard.

| Job | Scrape | Nội dung |
|---|---|---|
| `kubernetes-pods` | ns `crapi\|identity\|plg-stack`, mọi container | log ứng dụng (Keycloak `LOGIN_ERROR`, crapi-identity, bff…) |
| `envoy-access` | ns `crapi`, container `istio-proxy` | JSON access log (`svid`, `method`, `path`, `response_code`, `bytes_sent`, `upstream`) |
| `opa-decisions` | ns `crapi`, container `opa-server`, lọc `msg=="Decision Log"` | quyết định OPA (`opa_result`, `source_principal`, `request_path`, `decision_id`) — pipeline parse `request_path` thành label |
| `bff-audit` | (bff push trực tiếp qua Loki API) | `event`, `username`, `path`, `method`, `roles`, `acr` |
| `soar-engine` | ns `plg-stack` | `soar_action`, case, playbook |
| `security-healthcheck` | ns `spire` (CronJob mỗi phút) | `status`, `spire=<n>/<n>`, `opa=<code>`, `loki_push` |

### 7.2 Alert rules (`plg-stack/grafana/alerting/`, folder Grafana `ZTLab`, eval 1m)

| Rule | LogQL (rút gọn) | Severity | attack_type → SOAR playbook |
|---|---|---|---|
| **Lateral Movement** | `{job="opa-decisions", opa_result="false", request_path=~"/(workshop\|community)/api/.*\|/identity/api/v2/.*"} != "/identity/api/auth/verify"` | critical | `lateral_movement` → `isolate_workload` |
| **Access Denied Spike** | `{job="opa-decisions", opa_result="false"}` [10m] | high | `access_denied` → `block_source_ip` |
| **BFLA** | `{job="bff-audit"} \| json \| event="rbac_denied"` | high | `access_denied` → `block_source_ip` |
| **Brute Force** | `{namespace=~"identity\|crapi", app=~"keycloak\|crapi-identity"} \|~ "login_error\|invalid_user_credentials\|otp.*(invalid\|expired)"` > 10/5m | high | `brute_force` → `revoke_user_sessions` |
| **Data Exfil / Large Response** | `{job="envoy-access", namespace="crapi"} \| json \| bytes_sent > 1048576` | high | `large_response` → `restrict_egress` |
| **Privilege Escalation (container)** | `{namespace="crapi", app="security-scanner"} \| json \| event="privilege_escalation"` | critical | `privilege_escalation` → `quarantine_workload` |
| **Security Control-Plane Down** | SPIRE/OPA health (từ `security-healthcheck`) | critical | infra |
| **SOAR Engine Health** | `{job="soar-engine"}` action recorded | — | infra |

`notification-policy.yml` → contact point webhook `http://soar-engine.plg-stack:8080/grafana-webhook`.

### 7.3 SOAR engine (`services/soar-engine/main.py`, ns plg-stack)

- `POST /grafana-webhook` → parse alert → `attack_type` → tạo **case** (`CaseRecord`, lưu `/data/cases.jsonl`).
- `TARGETS_BY_ATTACK` (context + workload) + `PLAYBOOK_BY_ATTACK` + `SUGGESTED_PLAYBOOKS` (admin chọn).
- `SOAR_NAMESPACE = "crapi"`, `SOAR_DRY_RUN` / `SOAR_AUTO_EXECUTE` / `SOAR_MIN_SEVERITY` / `SOAR_MIN_CONFIDENCE` (secret `ai-secrets`).
- **Playbook** (`ALLOWED_PLAYBOOKS`): `isolate_workload` (patch Service selector → cô lập pod), `restrict_egress`, `block_source_ip` (NetworkPolicy chặn IP), `revoke_user_sessions` (Keycloak Admin API logout user), `quarantine_workload`, `scale_deployment`, `monitor_only`.
- **HITL:** case severity cao → email (SMTP MailHog qua Vault secret) + endpoint `/cases/{id}/approve|deny` (+ `-admin`). `SOAR_ALLOWED_CONTEXTS = ctx-aws,ctx-openstack` — SOAR có kubeconfig cả 2 cluster (`soar-openstack-kubeconfig` secret) → phản ứng xuyên cloud.
- **RBAC k8s** (`k8s/rbac/soar-rbac.yaml`, `web-portal-response-rbac.yaml`): SA `soar-engine` + `web-portal` (ns crapi) chỉ `get/patch deployments`, `get/patch services` — least privilege cho playbook.

### 7.4 ai-analyzer + security-scorer (ns plg-stack)

- `ai-analyzer` (`services/ai-analyzer/main.py`): làm giàu case — map log → kỹ thuật ATT&CK, `known_services`/`service_map` = crapi. Pattern riêng cho `container_escape`/T1611.
- `security-scorer` (`services/security-scorer/main.py`): chấm điểm rủi ro theo RULES regex, đọc `REDIS_URL = redis.crapi.svc…:6379/2`.

### 7.5 Dashboard Grafana

- `crapi-attack-surface.json` (mới) — **"crAPI — Attack Surface & Zero-Trust Enforcement"**: OPA allow/deny, deny theo path nghiệp vụ, 5 stat kịch bản (lateral / BFLA / step-up / brute-force / device-trust), SVID present vs `svid:null`, cross-cloud→identity HTTP code, SOAR actions, BFF audit theo event.
- Giữ: `zta-security-overview`, `ztlab-security-overview`, `ztlab-full-logs`, `envoy-access-logs`, `opa-decision-log`, `threat-intel-feed`, `ztlab-soar-dashboard`.

---

## 8. CÁC LUỒNG HOẠT ĐỘNG

### 8.1 Luồng triển khai (`scripts/deploy-all.sh`, hạ tầng trống → chạy đủ)

```
1  Cài công cụ (ansible, ssh, socat, jq, openssl, docker…)
2  Credentials .env (AWS creds, OS creds, KEYCLOAK_ADMIN_PASSWORD…)
3  SSH key AWS  (tạo/import key pair vào AWS)
4  SSH key OpenStack
5  terraform -chdir=terraform/aws apply         → VPC, SG, 5 EC2 (bastion, gateway, 3 k3s), aws-loki, aws-security
6  Ảnh Ubuntu OpenStack (glance import nếu thiếu)
7  Flavor OpenStack (m1.medium…)
8  terraform -chdir=terraform/openstack apply    → 3 network + edge-router, os-gateway, 3 k3s, SG
9  Vá IP vào ansible/inventory/hosts.yml  +  ssh-keygen -R <bastion,aws_gw,os_gw>
10 ansible all -m ping  (chờ SSH sẵn sàng ≤5 phút)
11 ansible-playbook baseline.yml → wireguard.yml → k3s.yml → promtail.yml
12 scripts/k8s-tunnel.sh up all   (SSH -L 6444→aws:6443 qua bastion, 6445→os:6443 qua os_gateway ProxyCommand)
13 scripts/sync-app-images.sh     (build+import bff/soar/ai/scorer; ảnh bên thứ 3 node tự pull)
   scripts/deploy-app.sh --skip-images:
     ├─ regenerate_policy_files  (gen-rego-acl.py + gen-networkpolicy.py)
     ├─ apply_namespaces  (+ k8s/dns/coredns-custom-openstack.yaml + rollout restart coredns OS)
     ├─ apply_network_policies (baseline)
     ├─ deploy_gatekeeper
     ├─ deploy_istio  (istioctl install 2 cluster, label ns crapi istio-injection=enabled)
     ├─ sync_images (skip)
     ├─ deploy_security_stack  (scripts/deploy-security-stack.sh: SPIRE server/agent + root CA + ensure-spire-entries.sh; OPA no-op — ở deploy-crapi)
     ├─ deploy_openldap_and_federation  (openldap + Keycloak LDAP provider live)
     ├─ deploy_audience_mapper  (Keycloak aud-crapi-bff mapper live)
     ├─ deploy_stepup_flow  (Keycloak browser-stepup flow)
     ├─ deploy_aws_saml_federation
     ├─ deploy_crapi  → scripts/deploy-crapi.sh:
     │    create_secrets (crapi-jwt-key 2 cluster) → apply_namespace_and_config → deploy_databases
     │    → deploy_crapi_workloads (mailhog+identity OS; web/community/workshop+cross-cloud-aws AWS)
     │    → configure_crapi_keycloak (role + client crapi-bff/-stepup + gán role user)
     │    → deploy_bff (+ ingress-aws/os) → register_spire → deploy_crapi_opa (opa-config + policies + opa.yaml)
     │    → reinstall_istio_for_crapi_provider → deploy_mesh_policies (istio-policies.yaml)
     │    → apply_network_policies (pod-segmentation) → restart_workloads_for_sds (bounce workload → istio-proxy tái lập SDS)
     │    → run_seed (Job crapi-seed)
     ├─ deploy_observability_response  (Loki, Grafana + datasources/dashboards/alerting, Promtail, Prometheus, soar/ai/scorer, Vault)
     ├─ apply_policies_and_ingress  (k8s/ingress.yaml — Traefik IngressRoute)
     └─ verify_final
14 Seed + mở UI  (scripts/open-admin-uis.sh — port-forward)
```

### 8.2 Luồng đăng nhập người dùng

```
Trình duyệt → http://localhost:18081/login  (BFF)
  → BFF /auth/start: sinh state + PKCE verifier/challenge → 302 tới BFF /kc/realms/ztlab/protocol/openid-connect/auth?client_id=crapi-bff&code_challenge=…
  → (BFF proxy) → Keycloak: render trang login "ZTLab"
  → POST username/password → /kc/realms/ztlab/login-actions/authenticate
  → Keycloak 302 → BFF /auth/callback?code=…&state=…
  → BFF: verify state → POST /kc/…/token (grant authorization_code + code_verifier) → nhận Keycloak access/id/refresh token
  → BFF: _evaluate_device_trust (UA + Redis known_devices) → trust
  → BFF: tạo session Redis {username, email, roles, acr, keycloak access_token, device_trust, crapi_token(mint RS256)} → Set-Cookie ztlab_bff_session
  → audit event=user_login → Loki (job=bff-audit)
  → 302 → BFF /  → proxy crapi-web (SPA crAPI load)
```

### 8.3 Luồng request Đông–Tây (bff → crapi-workshop, có mТLS + OPA + RBAC)

```
Trình duyệt: GET /workshop/api/shop/products  (cookie ztlab_bff_session)
  → BFF: _get_session → có phiên?  (không → 401 {"login_url":"/auth/start"})
  → BFF: device_trust=="suspicious" ∧ method GHI?  (GET → bỏ qua)
  → BFF: _rbac_ok(roles, GET, /workshop/api/shop/products)  → GET luôn OK cho role hợp lệ
  → BFF: _is_sensitive?  (GET không nhạy cảm → bỏ qua)
  → BFF: forward tới http://crapi-workshop.crapi.svc:8000/workshop/api/shop/products
       header inject: Authorization: Bearer <crapi_jwt RS256>, X-Access-Token: <keycloak>, X-Device-Trust, X-Device-Posture, X-Forwarded-For
  → istio-proxy (bff, client) — DestinationRule crapi-workshop-custom-san → mТLS handshake, present SVID spiffe://…/aws/bff
  → istio-proxy (crapi-workshop, server) — PeerAuth STRICT verify SVID; AuthorizationPolicy CUSTOM → gọi OPA ext_authz gRPC opa-service:9191
       OPA input: source_principal=aws/bff, destination_principal=aws/crapi-workshop, method=GET, path=/workshop/api/shop/products, headers{x-access-token, x-device-*}
       OPA: internal_service_request = valid_svid(✓) ∧ allowed_by_acl(bff→workshop GET /workshop/api ✓) ∧ keycloak_gate
            keycloak_gate: valid_jwt(io.jwt.decode_verify với Keycloak JWKS ✓) ∧ role_permits_action(GET, crapi-user ✓)
                           ∧ posture_ok(¬strong_control_required → ✓) ∧ device_trust_ok(✓) ∧ step_up_ok(¬sensitive → ✓)
       → allow=true  → decision log → Loki (job=opa-decisions, opa_result=true)
  → crapi-workshop (Django): verify token → POST http://crapi-identity-openstack:30090/identity/api/auth/verify  (hop cross-cloud, mТLS + OPA OpenStack)
  → 200 danh sách sản phẩm  → BFF trả về trình duyệt
```
Nếu là `crapi-community → crapi-workshop` (không có trong service_acl): OPA `allowed_by_acl=false` → `internal_service_request=false` → **403** (empty body — ext_authz deny) → decision log `opa_result=false` → alert Lateral Movement.

### 8.4 Luồng step-up

```
POST /workshop/api/shop/orders  (phiên acr=1)
  → BFF _is_sensitive(POST, /workshop/api/shop/orders) = true ∧ session.acr != "high"
    → 401 {"error":"step_up_required","stepup_url":"/auth/start-stepup"} + audit event=step_up_required
  (nếu client bỏ qua BFF không thể — mọi /workshop/* qua BFF)
  (nếu request tới được crapi-workshop: OPA sensitive_crapi_action ∧ ¬step_up_satisfied → deny)
→ Trình duyệt: /auth/start-stepup → Keycloak (client crapi-bff-stepup, acr_values=high) → nhập OTP → callback
  → session.acr = "high"  → POST orders lại → qua
```

### 8.5 Luồng phát hiện → phản ứng (end-to-end SOAR)

```
[Tấn công] vd exec crapi-community → POST crapi-workshop /workshop/api/shop/orders (ngoài service_acl)
  → istio-proxy crapi-workshop → OPA ext_authz → deny (403)
  → OPA decision log (opa_result=false, request_path=/workshop/api/shop/orders, source_principal=aws/crapi-community)
  → container log OPA → Promtail (job=opa-decisions) → Loki
[≤1 phút] Grafana eval rule "Lateral Movement": sum(count_over_time({job=opa-decisions, opa_result=false, request_path=~…}[10m])) > 0
  → Firing → notification-policy → webhook POST http://soar-engine.plg-stack:8080/grafana-webhook
  → SOAR: attack_type=lateral_movement → TARGETS_BY_ATTACK{ctx-aws, crapi-workshop} + PLAYBOOK{isolate_workload}
       → tạo CaseRecord (severity=critical, status=pending_approval) → /data/cases.jsonl
       → ai-analyzer làm giàu (ATT&CK T1021) → security-scorer chấm điểm
       → email HITL (SMTP MailHog, secret từ Vault) tới analyst
  → Admin: Grafana/SOAR UI → /cases/{id}/choose-action → approve playbook isolate_workload
       → SOAR patch Service crapi-workshop selector (ctx-aws) → cô lập pod → case status=executed
  → soar_action log → Loki (job=soar-engine) → dashboard cập nhật
```

### 8.6 Luồng cross-cloud (community → identity /verify)

```
crapi-community (AWS) cần verify token người dùng:
  → POST http://crapi-identity-openstack.crapi.svc.cluster.local:30090/identity/api/auth/verify
  → CoreDNS AWS resolve → ClusterIP selectorless Service → Endpoints 192.168.101.11:30090
  → istio-proxy community (client): DestinationRule crapi-identity-openstack-mtls (ISTIO_MUTUAL) → mТLS, present SVID aws/crapi-community
  → gói đi: pod 10.42.x → aws-gateway → WireGuard wg0 (10.200.0.1→10.200.0.2) → os-gateway → 192.168.101.11:30090 (NodePort)
  → istio-proxy crapi-identity (server): PeerAuth STRICT; AuthorizationPolicy CUSTOM → OPA OpenStack zta/crapi/crosscloud/allow
       service_acl[aws/crapi-community][openstack/crapi-identity][POST] ∋ "/identity/api/auth/verify" → allow
  → crapi-identity verify chữ ký RS256 (khoá của chính nó) → 200 {sub, role}
```

---

## 9. BẢNG CẤU HÌNH NHANH

| Hạng mục | Giá trị |
|---|---|
| Trust domain | `ztlab.local` |
| SVID scheme | `spiffe://ztlab.local/<cloud>/<service>` ; node alias `…/nodes/{aws,os}-k3s` |
| X509 SVID TTL | 1h (JWT SVID 5m, CA 168h) |
| OPA ext_authz path | AWS `zta/crapi/authz/allow` · OpenStack `zta/crapi/crosscloud/allow` |
| OPA JWKS source | `keycloak.identity.svc.cluster.local:8080/realms/ztlab/protocol/openid-connect/certs` |
| Keycloak realm / clients | `ztlab` / `crapi-bff`, `crapi-bff-stepup` (public PKCE) |
| Token audience (OPA kiểm) | `crapi-bff` |
| crAPI JWT kid (bff mint) | `MKMZkDenUfuDF2byYowDj7tW5Ox6XG4Y1THTEGScRg8` (RS256, khoá `deploy/vendor/crapi-keys/jwks.json`) |
| Namespace ứng dụng | `crapi` (thay `financial`) |
| NodePort cross-cloud | identity 30090, postgres 30432 (os-k3s-master 192.168.101.11) |
| WireGuard | wg0 10.200.0.0/24, UDP 51820, keepalive 25, watchdog 60s |
| Subnet DNS OpenStack | 1.1.1.1 / 1.0.0.1 |
| Port-forward (open-admin-uis.sh) | crAPI/BFF :18081 · Keycloak :8180 · Grafana :3000 · Loki :13100 · SOAR :8091 · AI :18082 · Scorer :18092 · Prometheus :9090 · MailHog :8025 |
| Sensitive actions (step-up) | POST `/workshop/api/shop/orders`, `…/return_order`, `/identity/api/v2/user/reset-password`, `…/change-email` |
| Admin paths (chỉ crapi-admin) | `/identity/api/v2/admin`, `/workshop/api/management` |

---

## 10. VẬN HÀNH & SỰ CỐ ĐÃ BIẾT

### 10.1 Kiểm tra sức khoẻ

- `bash scripts/health-check.sh` — kỳ vọng `FAIL=0` (WARN chấp nhận: `.env.ai missing`, remote SSH skipped).
- `python3 tests/test_service_graph_consistency.py` — `2/2 PASS` (service-graph = nguồn sự thật).
- `bash tests/crapi_run_all.sh` — 5 kịch bản tấn công, kỳ vọng `PASS=5 FAIL=0`; sau đó kiểm Grafana (Firing) + SOAR `/cases`.

### 10.2 Sự cố đã biết + cách xử lý

| Triệu chứng | Nguyên nhân | Xử lý |
|---|---|---|
| `security-healthcheck` CronJob nhấp nháy `opa=000/critical` | k3s kube-router chậm cập nhật ipset cho pod Job mới mỗi phút; OPA thật sự khoẻ | Flake đã biết — không phải regression. (Nâng cấp: đổi CronJob → Deployment IP ổn định.) |
| Toàn bộ crapi 2-cloud **503**, `svid:null` trong access log | Uplink host `aio` (hotspot điện thoại) drop NAT'd UDP → DNS(8.8.8.8) + WireGuard chết → SPIRE agent không attest → SVID hết hạn → mТLS STRICT sập | **Runbook §10.3**. Đã hạ rủi ro: DNS→1.1.1.1, coredns-custom, wg-watchdog, spire-agent `IfNotPresent`. |
| `bff → workshop` 502 `response_time=20000` | mТLS/SDS chưa settle sau restart (istio-proxy không tự tái lập SDS — Istio 1.22.3 + SPIRE 1.9.4) | `kubectl -n crapi rollout restart deploy` (thứ tự: identity OS → AWS). `deploy-crapi.sh::restart_workloads_for_sds` làm sẵn cuối deploy. |
| Login Keycloak báo "username phải là email" | Đang ở form login GỐC của crapi-web SPA (không dùng được — BFF chặn `/identity/*` chưa có phiên) | Vào thẳng `http://localhost:18081/login` (form Keycloak). Username hoặc email đều được. |
| `k8s-tunnel` chết giữa chừng | SSH qua bastion không ổn định / nhiều kết nối song song | `bash scripts/k8s-tunnel.sh down all && up all` |

### 10.3 Runbook khôi phục OpenStack (khi cross-cloud/mТLS 503)

```bash
# 0. Trên host aio: source /etc/kolla/admin-openrc.sh
# 1. DNS → 1.1.1.1
openstack subnet set --no-dns-nameservers --dns-nameserver 1.1.1.1 --dns-nameserver 1.0.0.1 zta-private-subnet   # + identity, dmz
ansible -i ansible/inventory/hosts.yml os_k3s_master:os_k3s_worker_1:os_k3s_worker_2:os_gateway -b -m shell \
  -a 'resolvectl dns $(ip route show default | awk "{print \$5;exit}") 1.1.1.1 1.0.0.1; resolvectl flush-caches'
# 2. CoreDNS override
kubectl --context ctx-openstack apply -f k8s/dns/coredns-custom-openstack.yaml
kubectl --context ctx-openstack -n kube-system rollout restart deploy/coredns
# 3. WireGuard
ansible -i ansible/inventory/hosts.yml aws_gateway:os_gateway -b -m shell -a 'systemctl restart wg-quick@wg0'
#    verify: ansible aws_gateway -m shell -a 'ping -I wg0 -c2 10.200.0.2; wg show'
# 4. SPIRE agent
kubectl --context ctx-openstack -n spire rollout restart daemonset/spire-agent
#    log kỳ vọng: "Node attestation was successful"
# 5. Workload (thứ tự phụ thuộc)
kubectl --context ctx-openstack -n crapi rollout restart deploy/opa-server deploy/crapi-identity deploy/mailhog
kubectl --context ctx-aws       -n crapi rollout restart deploy/opa-server deploy/bff deploy/crapi-web deploy/crapi-community deploy/crapi-workshop
# 6. Verify: login testuser01/Test1234! ở /login → GET /workshop/api/shop/products = 200
```

---

## 11. TRẠNG THÁI & VIỆC CÒN LẠI

**Đã hoàn tất (branch `feat/crapi-target`, verified trên cụm 2-cloud 2026-09-10):**
- Phase 1–5: crAPI Core 2-cloud + mТLS/SPIRE + BFF token-exchange + OPA 2-PDP + NetworkPolicy + dọn finance.
- Phase 6: fresh `destroy` → `deploy-all.sh` — 7 điểm gãy đã sửa (SSH known_hosts, sync-app-images, cross-cloud-os rỗng, crapi-web mailhog, seed_db, open-admin-uis, **OpenStack uplink hotspot**).
- Phase 7: 5 script tấn công `tests/crapi_*.sh` (PASS 5/5), alert rules crAPI, dashboard `crapi-attack-surface`, **e2e SOAR loop verified** (attack → Grafana Firing → SOAR case + playbook đúng).

**Việc người dùng:**
- `git add -A && git commit` branch `feat/crapi-target` (~30 file).
- Enroll OTP một lần cho `stepup-demo` qua trình duyệt (không tự động được).
- (Tuỳ chọn) `terraform apply` rule SG `ztlab-sg-private` NodePort-from-OpenStack (cần AWS creds) — hiện dùng đường SNAT qua os-gateway nên không bắt buộc.
- Cân nhắc nâng `default_x509_svid_ttl` 1h → 2–4h (giảm rủi ro sập dây chuyền khi SPIRE hiccup) — đánh đổi: cert sống lâu hơn.

---
*Cập nhật: 2026-09-10. Nguồn: đọc trực tiếp repo `feat/crapi-target` + nghiệm thu trên cụm đang chạy.*
