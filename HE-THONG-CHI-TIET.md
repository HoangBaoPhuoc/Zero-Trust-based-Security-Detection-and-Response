# HỆ THỐNG CHI TIẾT — Zero-Trust Security Detection & Response cho Microservice đa Cloud

> Tài liệu mô tả toàn bộ **kiến trúc, cấu hình, module và luồng hoạt động** của hệ thống ở trạng thái hiện tại (branch `feat/kehoach-thaydoi`, 2026-09-13, sau khi Giai đoạn A — A1 đến A5.2 của `KEHOACH-THAYDOI-HETHONG.md` — hoàn tất). Ứng dụng mục tiêu: **OWASP crAPI** (thay ứng dụng "finance" tự viết trước đây). Toàn bộ khung Zero-Trust được giữ nguyên cơ chế.
>
> Tài liệu đồng hành: `DEPLOY.md` (quy trình triển khai), `KET-QUA-CRAPI.md` (log kết quả migration finance→crAPI), `KEHOACH-THAYDOI-HETHONG.md` (kế hoạch A1-A5 + Giai đoạn B/C, A1-A5.2 nay đã DONE), `README.md`.
>
> **Đổi so với bản 2026-09-10 (Giai đoạn A):** Keycloak chuyển sang OpenStack (A1, §4.7); thêm WAF ModSecurity3+CRS trước BFF và siết `bff` PeerAuthentication về STRICT (A2, §4.2 + §4.7 mới); thêm Device CA + client-certificate mTLS với posture nhúng trong cert (A3, §4.8 mới); gộp `soar-engine`+`ai-analyzer`+`security-scorer` thành `incident-analyzer`, bỏ mọi khả năng thực thi (A4, §7.3); `destination_principal`/`source_principal` được promote thành Loki label (A5.1, §7.1); thêm `tests/crapi_run_campaign.sh` gắn nhãn theo lần chạy (A5.2, §10.1).

---

## 1. TỔNG QUAN & MỤC TIÊU

**Bài toán:** áp dụng mô hình **Zero Trust** (NIST SP 800-207) cho một hệ microservice **triển khai trên nhiều đám mây** (AWS + OpenStack), kèm lớp **phát hiện + phân tích bằng chứng + thông báo** (SIEM, **không** có thành phần thực thi phản ứng tự động — A4) khớp với bề mặt tấn công thực tế.

**Nguyên tắc Zero Trust hiện thực hoá:**

| Tenet NIST 800-207 | Hiện thực trong hệ thống |
|---|---|
| 1. Mọi tài nguyên là "resource" | Mỗi microservice = một workload có danh tính SPIFFE riêng |
| 2. Bảo mật mọi liên lạc bất kể vị trí | mTLS STRICT (Istio PeerAuthentication) mọi hop trong mesh; hop cross-cloud không sidecar (Postgres) đi qua WireGuard |
| 3. Cấp quyền theo từng phiên | OPA đánh giá **từng request** (Envoy ext_authz), không có "vùng tin cậy" |
| 4. Chính sách động | RBAC realm-role + **step-up OTP** (theo *loại* hành động) + **device posture** + **device trust** |
| 5. Giám sát toàn vẹn tài sản | `posture-agent` CronJob + `security-scanner-job` (container isolation) + Gatekeeper admission |
| 6. Xác thực + cấp quyền động, nghiêm ngặt | Keycloak OIDC/PKCE ở BFF; OPA tự verify chữ ký JWT (Keycloak JWKS + OIDC discovery) + kiểm `aud`/`iss`/`exp` |
| 7. Thu thập tối đa dữ liệu để cải thiện | PLG (Promtail→Loki→Grafana) + Prometheus + OPA decision log + istio access log + BFF audit log → `incident-analyzer` (evidence bundle, A4 — không còn SOAR thực thi) |

**Ranh giới đóng góp (làm rõ trong luận văn):** hệ thống **KHÔNG** vá lỗ hổng tầng ứng dụng của crAPI (BOLA, BFLA, JWT confusion, SSRF, mass assignment...). Đó là **chủ đích** — chúng là "challenge" của crAPI. Đóng góp là **lớp hạ tầng Zero-Trust + phát hiện/phản ứng** bao quanh: chặn *lateral movement*, *privilege escalation qua network*, *credential replay*, ép *step-up*, và phát hiện → đóng gói bằng chứng + thông báo người vận hành (§7.3) khi lỗ hổng app bị khai thác — **không** có hành động thực thi tự động nào (A4).

---

## 2. KIẾN TRÚC TỔNG THỂ

### 2.1 Hai đám mây, biên phân chia theo "danh tính"

```
                    ┌─────────────────────────── Người dùng (trình duyệt) ───────────────────────────┐
                    │        https://crapi.ztlab.local:18443  (Traefik, client-cert mTLS bắt buộc)   │
                    ▼
         ╔══════════════════════ AWS (VPC 10.10.0.0/16) ══════════════════════╗   ╔════════ OpenStack (Kolla AIO trên host `aio`) ════════╗
         ║  k3s cluster "aws-k3s"  (master + 2 worker, subnet 10.10.1.0/24)   ║   ║  k3s cluster "os-k3s" (master + 2 worker,             ║
         ║                                                                    ║   ║                        subnet 192.168.101.0/24)      ║
         ║  ns crapi:                                                         ║   ║  ns crapi:                                            ║
         ║   • waf            (nginx+ModSecurity3+CRS — DetectionOnly, A2)    ║   ║   • crapi-identity  (Java Spring — cấp JWT)          ║
         ║   • bff            (FastAPI — EDGE PEP, sau waf; PeerAuth STRICT)  ║   ║   • postgresdb      (Postgres 14 — DB DUY NHẤT)      ║
         ║   • crapi-web      (React/nginx tĩnh, bff proxy tới)               ║   ║   • mailhog         (SMTP + UI, MH_STORAGE=memory)   ║
         ║   • crapi-community(Go)                                            ║   ║   • opa-server ×3   (PDP — path crosscloud)          ║
         ║   • crapi-workshop (Django)                                        ║   ║                                                      ║
         ║   • mongodb, redis                                                 ║   ║  ns identity: keycloak + keycloak-db (Postgres, A1)  ║
         ║   • opa-server ×3  (PDP — path authz)                              ║   ║  ns identity-directory: openldap (SCIM demo)         ║
         ║                                                                    ║   ║  ns spire: spire-server + spire-agent (DaemonSet)    ║
         ║  ns spire, istio-system, gatekeeper-system, vault                  ║   ║  ns istio-system: istiod                              ║
         ║  ns plg-stack: loki, grafana, promtail, incident-analyzer,         ║   ║                                                      ║
         ║                mailhog (SMTP sink cho incident-analyzer)           ║   ║  os-gateway VM (192.168.100.10 / .101.1 / .102.1)    ║
         ║  ns monitoring: prometheus (mesh-injected, SVID aws/prometheus)    ║   ║   — NAT private/identity → internet, WireGuard peer  ║
         ║  aws-gateway VM (WireGuard peer) · aws-bastion (SSH jump)          ║   ║                                                      ║
         ║                                                                    ║   ║  edge-router (Neutron): DMZ 192.168.100.0/24 ↔ ext   ║
         ║                                                                    ║   ║                          (floating IP thay đổi mỗi   ║
         ║                                                                    ║   ║                           lần terraform apply)       ║
         ╚════════════════════════════════════╤═══════════════════════════════╝   ╚═══════════════════╤══════════════════════════════════╝
                                              │                                                       │
                                              └───────────── WireGuard (wg0, 10.200.0.0/24, UDP 51820) ┘
                                                    aws_gateway 10.200.0.1  ◄────►  os_gateway 10.200.0.2
                                    (định tuyến chéo: 10.42/10.43 ◄─► 192.168.101/102, PersistentKeepalive=25 + wg-watchdog)
```

**Đường request biên (sau A2+A3):** `trình duyệt --[TLS mTLS, Device CA]--> Traefik --[HTTP + X-Edge-Marker + X-Forwarded-Tls-Client-Cert-Info]--> waf (CRS DetectionOnly) --[mTLS SPIRE]--> bff`. Không TLS / cert sai CA / cert hết hạn → handshake fail ngay ở Traefik, không tới được waf/bff. Chi tiết: §4.7 (WAF), §4.8 (Device CA + client-cert mTLS).

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
| WAF (A2) | nginx + ModSecurity **v3** + OWASP CRS **v4** (`owasp/modsecurity-crs`, ghim `@sha256:`), `SecRuleEngine=DetectionOnly` |
| Device CA (A3) | CA riêng ECDSA P-256 tự sinh (`scripts/deploy-security-stack.sh::provision_device_ca`), tách bạch với SPIRE root CA; private key lưu Vault, không commit git |
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
- **PeerAuthentication** ns `crapi`: `default` = **STRICT**; per-workload PERMISSIVE chỉ còn `waf` (nhận HTTP trần từ Traefik — nằm ngoài mesh theo thiết kế) và `crapi-web` (static do BFF gọi). **`bff` đã siết về STRICT ở A2** — từ khi WAF đứng trước (Traefik→waf→bff mọi hop đều mТLS thật) BFF không còn nhận trực tiếp traffic không-cert nữa; xem §4.7. Hệ quả: mọi consumer khác của `bff:8080/metrics` (vd Prometheus) bắt buộc phải có SVID riêng, không được nương nhờ PERMISSIVE nữa (§4.9).
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
allow if public_path                    # /health, /identity/health_check, POST /identity/api/auth/{signup,login,verify,check-otp,…}, GET jwks.json,
                                         # BFF OIDC bootstrap (/auth/start, /auth/callback, /auth/logout, /login, /kc — A3), waf's own inbound hop
                                         # (Traefik→waf, gated on X-Edge-Marker == EDGE_MARKER, A3), bff→crapi-web static
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
> **Lưu ý thiết kế:** `posture`/`device_trust` chỉ gate **hành động GHI + nhạy cảm**, khớp BFF `_rbac_ok` (chỉ chặn suspicious device ở method GHI). Đọc thường vẫn đủ mạnh bằng valid_jwt + RBAC + valid_svid + mТLS. **Từ A3**, `posture`/`device_trust` không còn là heuristic User-Agent nữa mà đọc từ client certificate đã verify ở Traefik — xem §4.8.

**`crosscloud_crapi.rego` (OpenStack)** — giữ `service_acl` + `allowed_by_acl` + `posture_compliant`; **bỏ** `device_trust_compliant` (BFF đã kiểm ở đầu vào; hop bff→identity cross-cloud chỉ tới OPA OpenStack). Guard `crapi-identity`: chỉ chấp nhận nguồn `bff` / `crapi-community` / `crapi-workshop`.

**JWT verify:** OPA (AWS) gọi `http.send` tới `http://keycloak-openstack.crapi.svc.cluster.local:30091/realms/ztlab/protocol/openid-connect/certs` + `.../.well-known/openid-configuration` (`force_cache` 300s) — **kể từ A1**, đây là hop cross-cloud thật qua Service selectorless `keycloak-openstack` (NodePort 30091, xem §6), không còn nội cụm `keycloak.identity.svc:8080` như trước A1. Xác nhận qua `counter_rego_builtin_http_send_network_requests: 2` trong decision log.

### 4.4 NetworkPolicy L4

`k8s/crapi/network-policies/`:
- `{aws,os}-allow-list.yaml` (podSelector `{}` — baseline): ingress Traefik→bff:8080, monitoring→:metrics, `spire`→opa:8181, `plg-stack`→redis:6379, nội `crapi`→`crapi` any; egress DNS, `crapi`→`crapi`, bff→`identity`(Keycloak 8080), `crapi`→`plg-stack`(Loki 3100), cross-cloud ipBlock `192.168.101.0/24`:30090/30432, `istio-system`:15012.
- `{aws,os}-pod-segmentation.yaml` (generated từ service-graph — podSelector `app=<x>`, ingress theo `service_acl`).

> **Giới hạn thực tế (ghi rõ trong luận văn):** trên k3s + kube-router, NetworkPolicy **không được enforce đầy đủ cho traffic có Istio sidecar** — **L7 (OPA `service_acl`) là lớp phân đoạn thật đang hoạt động**. NetworkPolicy L4 là defense-in-depth + tài liệu ý định + có hiệu lực cho đường không-sidecar (opa:8181, DNS, cross-cloud ipBlock).

### 4.5 Keycloak — IdP

- **Từ A1 (2026-09-11): chạy trên OpenStack** (`ctx-openstack`, ns `identity`), không còn ở AWS. Lý do là pháp lý, không phải kỹ thuật: Nghị định 53/2022 Điều 26 buộc thông tin cá nhân người dùng lưu trong nước; OpenStack (host `aio`) là "nơi cấp danh tính + toàn bộ dữ liệu" của kiến trúc này (§2.1), nên IdP phải đứng cùng phía. Expose qua NodePort **30091** trên `os-k3s-master`; phía AWS (BFF, OPA) gọi qua Service selectorless `keycloak-openstack` (§6, §4.3) — không sidecar (`DestinationRule mode: DISABLE`, WireGuard lo mã hoá).
- Realm `ztlab` (`k8s/keycloak/realm-config.json`, `--import-realm` lần boot đầu; các thiết lập không retrofit được thì `deploy-crapi.sh` / `deploy-app.sh` đăng ký live qua Admin API — nay trỏ `ctx-openstack`). `redirectUris` của client `crapi-bff`/`crapi-bff-stepup` giờ **diff-and-PUT-update** ở mỗi lần deploy (trước A3 chỉ set lúc tạo mới lần đầu, nên thêm domain HTTPS mới không tự áp dụng cho client đã tồn tại).
- **Client:** `crapi-bff` (public, PKCE S256, `standardFlowEnabled`, redirectUris gồm cả HTTPS thật (`https://crapi.ztlab.local/*`, `https://crapi.ztlab.local:18443/*` — A3) lẫn HTTP dev/bypass (`http://crapi.ztlab.local/*`, `http://localhost:18081/*`, `http://localhost:8080/*`, `127.0.0.1` tương ứng)), `crapi-bff-stepup` (cùng cấu hình, dùng cho flow step-up). Protocol mapper `aud-crapi-bff` (oidc-audience-mapper → `aud=crapi-bff` trong access token, để OPA kiểm `aud`).
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
| **Device cert + posture (A3, thay heuristic UA cũ)** | `_evaluate_device_cert`: đọc `X-Forwarded-Tls-Client-Cert-Info` do Traefik gắn sau khi verify client cert bằng Device CA (`k8s/crapi/edge-tls.yaml`) — chỉ tin khi header `X-Edge-Marker` khớp `EDGE_MARKER` (bí mật chia sẻ, chặn pod trong cluster tự giả header cert khi gọi thẳng bff bỏ qua Traefik). `_parse_cert_info` decode URL-encoding rồi regex `key="value"` lấy `Subject`/`SAN`; `device_id` = SAN URI `spiffe://ztlab.local/device/<id>`, `posture` = `Subject OU=posture:<compliant\|non-compliant>`. Thiếu marker/cert/device_id → mặc định `posture:unknown, device_trust:suspicious`. Gắn header `X-Device-Trust`/`X-Device-Posture` cho hop đi tiếp. |
| **OIDC redirect scheme (A3)** | `_external_base`: WAF's nginx ghi đè `X-Forwarded-Proto` về scheme của chính nó (luôn `http`, vì TLS đã kết thúc ở Traefik) nên không tin được header chuẩn — đọc `X-Edge-Scheme` (header riêng do Middleware `edge-marker` gắn, nginx không biết tên này nên đi qua nguyên vẹn) để dựng đúng `redirect_uri` HTTPS cho OIDC. |
| **Token exchange (mỗi request proxy)** | `Authorization: Bearer <crapi_jwt>` — bff **mint RS256** `{sub: email, role: <"user"/"mechanic"/"admin">, iat, exp}` bằng **khoá RSA của chính crAPI** (`deploy/vendor/crapi-keys/jwks.json` == `default_jwks.json` nhúng trong ảnh identity, `kid = MKMZkDenUfuDF2byYowDj7tW5Ox6XG4Y1THTEGScRg8`). `X-Access-Token: <keycloak_access_token>` — cho OPA kiểm realm role + `acr`. Client KHÔNG được tự đặt các header này (bff strip trước khi forward). |
| **RBAC gương** (`_rbac_ok`) | Gương của `zta_crapi.rego` `role_permits_action` — cần vì hop bff→identity (cross-cloud) chỉ qua OPA OpenStack (không kiểm token người dùng). GET/HEAD/OPTIONS → OK cho mọi role hợp lệ; GHI vào `_ADMIN_PREFIXES` → cần `crapi-admin`; GHI mechanic prefix → mechanic/admin. → audit `event=rbac_denied` khi từ chối. |
| **Step-up gương** (`_is_sensitive`) | Danh sách `SENSITIVE_ACTIONS` → nếu `session.acr != "high"` → `401 {"error":"step_up_required","stepup_url":"/auth/start-stepup"}` + audit `event=step_up_required`. |
| **Device-trust gate** | `suspicious` + method GHI → `403 {"reason":"suspicious_device"}` + audit `event=device_trust_denied`. |
| **Reverse proxy** | `/identity/*` → `crapi-identity-openstack.crapi.svc:30090` (cross-cloud) · `/community/*` → `crapi-community:8087` · `/workshop/*` → `crapi-workshop:8000` · còn lại → `crapi-web:80`. `CHATBOT_SERVICE`/`MAILHOG_WEB_SERVICE` trỏ về `crapi-web:80` (không deploy — để nginx crapi-web resolve upstream, khỏi `[emerg] host not found`). |
| **Audit → Loki** | `_audit(event, …)` POST JSON tới `LOKI_URL` job `bff-audit` (`user_login`, `rbac_denied`, `step_up_required`, `device_trust_denied`, `sensitive_action_ok`, `proxy_error`). |

### 4.7 WAF — ModSecurity3 + OWASP CRS (A2, `k8s/crapi/waf.yaml`)

Đứng ngay sau Traefik, trước `bff`: `Traefik --HTTP--> waf:8080 --mTLS(Istio)--> bff:8080`. `SecRuleEngine=DetectionOnly` — CRS đánh giá **mọi** request và ghi audit JSON ra stdout khi khớp rule, nhưng **không bao giờ chặn** → không thể làm hỏng luồng nghiệp vụ crAPI, không làm nhiễu telemetry huấn luyện. Đây là phép đo đối chứng của luận văn: CRS bắt SQLi/XSS/path-traversal nhưng **không bắt được** request BOLA/BFLA nào — cho thấy phương pháp dựa trên chữ ký không phát hiện được lớp tấn công vượt quyền, biện minh cho lớp Zero-Trust authorization đứng sau.

- `waf` chạy Istio sidecar với SVID thật `spiffe://ztlab.local/aws/waf`; `PeerAuthentication` PERMISSIVE (nhận HTTP trần từ Traefik, ngoài mesh theo thiết kế); `DestinationRule waf-custom-san` (ISTIO_MUTUAL) + `AuthorizationPolicy CUSTOM → opa-ext-authz` cho hop **ra** (waf→bff) — parity với các workload khác.
- **Bug hạ tầng thật đã sửa (tồn tại từ A2, phát hiện khi verify sống A3):** ảnh gốc `owasp/modsecurity-crs` có `includes/proxy_backend.conf` dùng `proxy_set_header Host $host;` — nginx forward nguyên Host header của **client bên ngoài** (`crapi.ztlab.local`) sang bff thay vì host thật của bff. Envoy outbound router của waf chọn cluster đích theo Host/`:authority`; header đó không khớp alias nào của bff → rơi vào `allow_any` virtual host → **PassthroughCluster** (bỏ qua hẳn `DestinationRule`, không mТLS, không SPIFFE principal). Mọi check OPA cần `valid_svid` (tức mọi thứ ngoài `public_path`) fail-closed **mà không hề có decision log nào** — trông y hệt như "OPA chưa từng được gọi", rất khó chẩn đoán. Fix: `waf-proxy-backend-conf` ConfigMap override include đó bằng `proxy_set_header Host $proxy_host;`, mount lên **đường dẫn TEMPLATE** (`/etc/nginx/templates/includes/proxy_backend.conf.template`) chứ không phải file đã envsubst — mount thẳng lên file generated làm entrypoint tự regen fail (`Read-only file system`) và crash-loop.
- **Gate waf's own inbound hop:** vì Traefik nằm ngoài mesh, hop Traefik→waf không bao giờ có `source_principal` — `internal_service_request`/`valid_svid` không thể đúng ở đây dù path là gì. Thay vì nới lỏng chung chung, OPA chỉ cho qua khi request mang đúng `X-Edge-Marker` (bí mật chia sẻ do Middleware `edge-marker` gắn — xem §4.8) — pod nào gọi thẳng `waf` bỏ qua Traefik sẽ không có marker này nên vẫn bị chặn. Authorization theo user/role/posture thật sự diễn ra ở hop **kế tiếp** (waf→bff, mТLS thật cả 2 đầu).

### 4.8 Device CA — Client-certificate mTLS + posture nhúng trong cert (A3)

Thay heuristic User-Agent cũ (không đáng tin — client tự khai) bằng client-certificate mTLS thật ở biên Traefik, posture nhúng ngay trong cert nên **không có cert hợp lệ = không kết nối được**, không phải "OPA/BFF từ chối sau khi đã kết nối".

- **Device CA riêng** (`scripts/deploy-security-stack.sh::provision_device_ca`), tách bạch với SPIRE root CA (device identity ≠ workload identity): ECDSA P-256, tự sinh 10 năm nếu chưa có, hoặc phục hồi từ Vault (`_device_ca_from_vault`, để redeploy giữ nguyên CA thay vì phát hành lại toàn bộ cert thiết bị). **Private key KHÔNG commit git** (`deploy/vendor/device-ca/` trong `.gitignore`).
- **`k8s/crapi/edge-tls.yaml`:** `TLSOption device-mtls` (`clientAuthType: RequireAndVerifyClientCert`, `caFiles` = Device CA) trên `IngressRoute crapi-bff-mtls` (entrypoint `websecure`, tls secret `crapi-edge-tls` = cert server ký bởi Device CA). Không TLS / cert sai CA / cert hết hạn → **handshake fail ngay ở Traefik**, không tới được waf/bff.
- **`Middleware pass-client-cert`:** Traefik gắn `X-Forwarded-Tls-Client-Cert-Info` (Subject CN/OU + SAN của cert đã verify) cho BFF đọc.
- **`Middleware edge-marker`:** gắn 2 header riêng vào MỌI request qua Traefik — `X-Edge-Marker` (bí mật `bff-edge`, sinh ngẫu nhiên bởi `provision_device_ca`) để BFF/OPA chỉ tin cert-info/nới lỏng waf khi request thật sự đi qua Traefik (RÀNG BUỘC #5 — chỉ chấp nhận giá trị do reverse-proxy biên gắn, không phải client tự khai); và `X-Edge-Scheme: https` để BFF dựng đúng `redirect_uri` OIDC (§4.6) khi WAF ở giữa ghi đè `X-Forwarded-Proto`.
- **Posture nhúng ở Subject `OU=posture:<compliant|non-compliant>`**, device id ở SAN URI `spiffe://ztlab.local/device/<id>` — phát hành bằng `scripts/issue-device-cert.sh <device-id> <compliant|non-compliant>`. `tests/lib/crapi_common.sh::crapi_preflight` tự issue 2 cert cố định `test-compliant`/`test-noncompliant` cho test suite.
- **3 kịch bản đã verify sống qua `https://crapi.ztlab.local:18443` (không bypass):** (1) cert hợp lệ + `compliant` → truy cập bình thường; (2) cert hợp lệ + `non-compliant` → OPA/BFF deny ở hành động ghi, có decision log; (3) không cert / cert hết hạn / cert do CA khác ký → TLS handshake fail, không có decision log nào (chưa từng tới được BFF/OPA).

### 4.9 Gatekeeper + Vault

- **Gatekeeper** (`k8s/gatekeeper/`): constraint-templates + constraints — admission control (vd chặn container privileged, bắt buộc label/resource limit). Chạy `gatekeeper-system` ns trên AWS.
- **Vault** (`k8s/vault/vault.yaml`): dev mode, kubernetes auth — vẫn là thành phần Zero-Trust secrets chính (giữ private key Device CA, §4.8). **A4 đã bỏ** consumer cũ `soar-engine`/`SOAR_*`; hiện Vault không có consumer thực thi nào, chỉ giữ vai trò lưu trữ. `grafana-smtp-secret` (mật khẩu SMTP cho **Grafana's own alertmanager**, khác hẳn secret của incident-analyzer) là k8s Secret thường tạo trực tiếp trong `deploy-app.sh::deploy_observability_response`, **không** qua Vault.

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
Service keycloak-openstack            (port 30091, KHÔNG selector — A1)
Endpoints keycloak-openstack          → 192.168.101.11:30091
DestinationRule keycloak-openstack-plaintext   → tls mode DISABLE   (Keycloak không sidecar → WireGuard lo)

# Áp trên OpenStack (k8s/crapi/cross-cloud-os.yaml): TRỐNG (mailhog nằm cùng cluster identity, không có hop OS→AWS)
```

CoreDNS resolve tên `…svc.cluster.local` native → Istio auto-discover Endpoints như mọi Service → traffic đi `pod (10.42.x) → os-gateway/aws-gateway → WireGuard (10.200.0.x) → NodePort đích`. `deploy-crapi.sh::apply_manifest()` bỏ qua file cross-cloud rỗng (tránh `error: no objects passed to apply` giết script `set -e`).

**8 hop cross-cloud thực tế** (verified qua istio access log / OPA decision log): `bff→identity` (HTTP mТLS), `community→identity /verify` (HTTP mТLS, mỗi request), `workshop→identity /verify` (idem), `community→postgresdb:30432` (TCP/WG), `workshop→postgresdb:30432` (TCP/WG), (`identity→mailhog` nay nội cụm OpenStack); **thêm từ A1:** `bff→keycloak-openstack:30091` (OIDC token/authorize/userinfo, HTTP plaintext qua WireGuard — Keycloak không sidecar) và `opa(AWS)→keycloak-openstack:30091` (JWKS + OIDC discovery, `http.send`, §4.3).

**WireGuard** (`ansible/templates/wg0-{aws,os}-gateway.j2`): `wg0` 10.200.0.0/24, UDP 51820, `PersistentKeepalive = 25`. `allowed_ips` os_gateway: `10.42.0.0/16, 10.43.0.0/16` (pod/svc AWS) ; aws_gateway: `192.168.101.0/24, 192.168.102.0/24`. **`wg-watchdog`** (systemd timer 60s): tunnel chết vì UDP drop kéo dài KHÔNG tự phục hồi → watchdog restart.

---

## 7. QUAN SÁT — PHÁT HIỆN — PHẢN ỨNG

### 7.1 PLG pipeline

**Promtail** (DaemonSet, `k8s/plg-stack/promtail-daemonset.yaml`, `CLOUD_PROVIDER` per-cluster). Loki chạy 1 nơi (AWS); OpenStack Promtail đẩy log qua **Loki-relay** (`socat 10.10.10.1:13099 → localhost:13100`, `open-admin-uis.sh`) qua WireGuard.

| Job | Scrape | Nội dung |
|---|---|---|
| `kubernetes-pods` | ns `crapi\|identity\|plg-stack`, mọi container | log ứng dụng (Keycloak `LOGIN_ERROR`, crapi-identity, bff…) |
| `envoy-access` | ns `crapi`, container `istio-proxy` | JSON access log (`svid`, `method`, `path`, `response_code`, `bytes_sent`, `upstream`) |
| `opa-decisions` | ns `crapi`, container `opa-server`, lọc `msg=="Decision Log"` | quyết định OPA (`opa_result`, `request_path`, `decision_id`) — **A5.1:** `source_principal`/`destination_principal` cũng được promote thành **label** riêng (không chỉ nằm trong body JSON), phục vụ nhóm đặc trưng B của luận văn ("số danh tính đích khác nhau") mà không cần `\| json` mỗi query |
| `waf-audit` | ns `crapi`, container `waf` (A2) | ModSecurity audit JSON (`transaction.messages[]` = rule id khớp, `transaction.request.headers.host`…) |
| `bff-audit` | (bff push trực tiếp qua Loki API) | `event`, `username`, `path`, `method`, `roles`, `acr` |
| `incident-analyzer` | ns `plg-stack` (A4, thay `soar-engine`) | `event=evidence_bundle`, alert gốc, ATT&CK technique, priority score — **không** có `soar_action`/playbook nào (không còn khả năng thực thi) |
| `security-healthcheck` | ns `spire` (CronJob mỗi phút) | `status`, `spire=<n>/<n>`, `opa=<code>`, `loki_push` |

### 7.2 Alert rules (`plg-stack/grafana/alerting/`, folder Grafana `ZTLab`, eval 1m)

| Rule | LogQL (rút gọn) | Severity | attack_type → xử lý |
|---|---|---|---|
| **Lateral Movement** | `{job="opa-decisions", opa_result="false", request_path=~"/(workshop\|community)/api/.*\|/identity/api/v2/.*"} != "/identity/api/auth/verify"` | critical | `lateral_movement` → evidence bundle + email |
| **Access Denied Spike** | `{job="opa-decisions", opa_result="false"}` [10m] | high | `access_denied` → evidence bundle + email |
| **BFLA** | `{job="bff-audit"} \| json \| event="rbac_denied"` | high | `access_denied` → evidence bundle + email |
| **Brute Force** | `{namespace=~"identity\|crapi", app=~"keycloak\|crapi-identity"} \|~ "login_error\|invalid_user_credentials\|otp.*(invalid\|expired)"` > 10/5m | high | `brute_force` → evidence bundle + email |
| **Data Exfil / Large Response** | `{job="envoy-access", namespace="crapi"} \| json \| bytes_sent > 1048576` | high | `large_response` → evidence bundle + email |
| **Privilege Escalation (container)** | `{namespace="crapi", app="security-scanner"} \| json \| event="privilege_escalation"` | critical | `privilege_escalation` → evidence bundle + email |
| **Security Control-Plane Down** | SPIRE/OPA health (từ `security-healthcheck`) | critical | infra — **KHÔNG** qua incident-analyzer webhook, admin xử lý trực tiếp |
| **incident-analyzer Health** | `{job="incident-analyzer"} \|= "evidence_bundle"` được ghi nhận trong 10m | — | informational — chỉ xác nhận incident-analyzer còn sống, không phải cảnh báo tấn công |

**A4** đã bỏ hoàn toàn cột "→ SOAR playbook thực thi" — mọi `attack_type` giờ chỉ dẫn tới **một hành động duy nhất: đóng gói bằng chứng + gửi email cho người vận hành**, không có bất kỳ thay đổi nào trên cụm. `notification-policy.yml` → contact point webhook `http://incident-analyzer.plg-stack:8080/grafana-webhook` (đổi từ `soar-engine`).

### 7.3 incident-analyzer (`services/incident-analyzer/main.py`, ns plg-stack) — A4: gộp soar-engine + ai-analyzer + security-scorer

**Thay thế hoàn toàn bộ ba service cũ** (`soar-engine`, `ai-analyzer`, `security-scorer` — mã nguồn cũ vẫn còn trong `services/` như tham khảo lịch sử nhưng **không còn manifest k8s nào** deploy chúng, `k8s/plg-stack/incident-analyzer.yaml` là file duy nhất). Lý do gộp: khoá luận cam kết dừng ở **phát hiện + phân tích bằng chứng + thông báo**, không có "SOAR có playbook thực thi thật" (mâu thuẫn với chính cam kết đó ở bản cũ).

- `POST /grafana-webhook` (+ `POST /alerts` tổng quát) → map alert → kỹ thuật **MITRE ATT&CK** → chấm **priority score** rule-based (0-100, kế thừa logic cũ của `security-scorer`) → truy vấn **Loki** quanh thời điểm cảnh báo (±5 phút, job `opa-decisions`/`envoy-access`/`bff-audit`/`waf-audit`) → đóng gói thành **evidence bundle**.
- Gửi bundle qua email tới `MAIL_TO` (mặc định `soc@ztlab.local`) bằng SMTP **MailHog** trong cụm (không auth, không TLS) — không phải relay thật, chỉ demo HITL notification.
- Ghi lại evidence record (`EVIDENCE_STORE_PATH`, `/data/evidence.jsonl`) + mirror 1 dòng tóm tắt về Loki (`job=incident-analyzer`).
- **KHÔNG có khả năng phản ứng nào:** không Kubernetes client, không playbook, không chặn IP, không revoke session, không endpoint approve/deny. ServiceAccount chạy dưới đây **không gắn RBAC nào** (khác hẳn `soar-rbac.yaml`/`web-portal-response-rbac.yaml` cũ, đã xoá cùng quyền `patch deployments/services`).
- **Chừa sẵn** `POST /evidence/{id}/risk-score` — điểm cắm cho model ML của **Giai đoạn C** gắn risk score vào evidence record đã có, không cần sửa lại service này khi ML sẵn sàng.

### 7.4 Dashboard Grafana

- `crapi-attack-surface.json` — **"crAPI — Attack Surface & Zero-Trust Enforcement"**: OPA allow/deny, deny theo path nghiệp vụ, 5 stat kịch bản (lateral / BFLA / step-up / brute-force / device-trust), SVID present vs `svid:null`, cross-cloud→identity HTTP code, panel **evidence bundles** (đổi tên từ "SOAR actions" — A4, không còn hành động thực thi nào để đếm), BFF audit theo event. **A2** thêm hàng WAF/CRS control (số CRS hit theo loại tấn công cạnh số OPA deny; số CRS hit trên riêng request BOLA — kỳ vọng = 0).
- Giữ: `zta-security-overview`, `ztlab-security-overview`, `ztlab-full-logs`, `envoy-access-logs`, `opa-decision-log`, `threat-intel-feed`; `ztlab-soar-dashboard` **đổi tên** thành dashboard incident-analyzer (A4).

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
     ├─ deploy_security_stack  (scripts/deploy-security-stack.sh, thứ tự thật — xem log "STEP: N."):
     │    1. namespaces  →  2. Keycloak trên OpenStack (A1)  →  3.0 SPIRE root CA (shared)
     │    →  3.1 Device CA + edge server cert (A3, provision_device_ca — tự sinh hoặc phục hồi
     │       từ Vault, sinh bff-edge marker, render edge-tls.yaml)  →  3.1/3.2 SPIRE server+agent
     │       AWS/OpenStack  →  3.3 register_spire_workloads (ensure-spire-entries.sh, gate 6/2)
     │       →  3.4 security-healthcheck CronJob. OPA no-op ở đây — deploy ở deploy-crapi.
     ├─ deploy_openldap_and_federation  (openldap + Keycloak LDAP provider live)
     ├─ deploy_audience_mapper  (Keycloak aud-crapi-bff mapper live)
     ├─ deploy_stepup_flow  (Keycloak browser-stepup flow)
     ├─ deploy_aws_saml_federation
     ├─ deploy_crapi  → scripts/deploy-crapi.sh:
     │    create_secrets (crapi-jwt-key 2 cluster) → apply_namespace_and_config → deploy_databases
     │    → deploy_crapi_workloads (mailhog+identity OS; web/community/workshop+cross-cloud-aws AWS)
     │    → configure_crapi_keycloak (role + client crapi-bff/-stepup + gán role user)
     │    → deploy_bff (**+ waf.yaml, A2** + ingress-aws/os, ingress-aws.yaml nay redirect → HTTPS)
     │    → register_spire → deploy_crapi_opa (opa-config + policies + opa.yaml, gồm EDGE_MARKER env — A3)
     │    → reinstall_istio_for_crapi_provider → deploy_mesh_policies (istio-policies.yaml, + waf→bff edge)
     │    → apply_network_policies (pod-segmentation) → restart_workloads_for_sds (bounce workload → istio-proxy tái lập SDS)
     │    → run_seed (Job crapi-seed)
     ├─ deploy_observability_response  (Loki, Grafana + datasources/dashboards/alerting, Promtail,
     │    Prometheus **mesh-injected (A2, SVID aws/prometheus)**, incident-analyzer (A4, thay soar/ai/scorer), Vault, grafana-smtp-secret)
     ├─ apply_policies_and_ingress  (k8s/ingress.yaml — Traefik IngressRoute; edge-tls.yaml/crapi-bff-mtls đã apply sớm hơn ở provision_device_ca §3.1)
     └─ verify_final
14 Seed + mở UI  (scripts/open-admin-uis.sh — port-forward)
```

### 8.2 Luồng đăng nhập người dùng

```
Trình duyệt (client cert đã cài, vd scripts/issue-device-cert.sh testuser01 compliant)
  → https://crapi.ztlab.local:18443/login
  → Traefik: TLS handshake + RequireAndVerifyClientCert (device-mtls) → verify cert bằng Device CA
      (không cert/cert sai CA/hết hạn → handshake fail ngay, KHÔNG tới waf/bff)
  → Middleware pass-client-cert gắn X-Forwarded-Tls-Client-Cert-Info; edge-marker gắn X-Edge-Marker + X-Edge-Scheme:https
  → waf (ModSecurity CRS DetectionOnly — log nếu khớp rule, không chặn) → mTLS thật → bff
  → BFF /auth/start: sinh state + PKCE verifier/challenge → 302 tới BFF /kc/realms/ztlab/protocol/openid-connect/auth?client_id=crapi-bff&code_challenge=…
  → (BFF proxy) → Keycloak (OpenStack, qua keycloak-openstack:30091 — A1): render trang login "ZTLab"
  → POST username/password → /kc/realms/ztlab/login-actions/authenticate
  → Keycloak 302 → BFF /auth/callback?code=…&state=…  (redirect_uri dùng _external_base — X-Edge-Scheme:https, không phải scheme http nginx tự ghi đè)
  → BFF: verify state → POST /kc/…/token (grant authorization_code + code_verifier) → nhận Keycloak access/id/refresh token
  → BFF: _evaluate_device_cert (đọc X-Forwarded-Tls-Client-Cert-Info đã verify, chỉ tin khi X-Edge-Marker khớp) → device_id + posture:compliant → device_trust:trusted
  → BFF: tạo session Redis {username, email, roles, acr, keycloak access_token, device_trust, posture, crapi_token(mint RS256)} → Set-Cookie ztlab_bff_session
  → audit event=user_login → Loki (job=bff-audit)
  → 302 → BFF /  → proxy crapi-web (SPA crAPI load)
```
> Tunnel dev `http://localhost:18081` (`open-admin-uis.sh`, port-forward thẳng tới Service `waf`) vẫn tồn tại để test nhanh không cần cài client cert — nhưng đó là đường **bỏ qua Traefik**, không phải luồng Zero-Trust A3 thật; kịch bản demo/test chính thức (`tests/crapi_*.sh`) đi qua `:18443`.

### 8.3 Luồng request Đông–Tây (bff → crapi-workshop, có mТLS + OPA + RBAC)

```
Trình duyệt: GET /workshop/api/shop/products  (cookie ztlab_bff_session)
  → https://crapi.ztlab.local:18443 → Traefik (verify client cert lại — mỗi request, không chỉ lúc login)
    → waf (CRS DetectionOnly, không match rule nào cho request GET thường) → mТLS thật → bff
      (giống hệt hop biên ở §8.2 — chỉ viết tắt ở đây, xem §8.2 cho chi tiết Traefik/waf)
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

### 8.5 Luồng phát hiện → phân tích → thông báo (A4 — KHÔNG có phản ứng tự động)

```
[Tấn công] vd exec crapi-community → POST crapi-workshop /workshop/api/shop/orders (ngoài service_acl)
  → istio-proxy crapi-workshop → OPA ext_authz → deny (403)
  → OPA decision log (opa_result=false, request_path=/workshop/api/shop/orders,
    source_principal=aws/crapi-community — nay CŨNG là label riêng, không chỉ nằm trong body JSON, A5.1)
  → container log OPA → Promtail (job=opa-decisions) → Loki
[≤1 phút] Grafana eval rule "Lateral Movement": sum(count_over_time({job=opa-decisions, opa_result=false, request_path=~…}[10m])) > 0
  → Firing → notification-policy → webhook POST http://incident-analyzer.plg-stack:8080/grafana-webhook  (đổi từ soar-engine, A4)
  → incident-analyzer: attack_type=lateral_movement → map ATT&CK (T1021) → chấm priority score (rule-based)
       → truy vấn Loki ±5 phút quanh thời điểm alert (opa-decisions/envoy-access/bff-audit/waf-audit) → đóng gói evidence bundle
       → lưu evidence record (/data/evidence.jsonl) → mirror tóm tắt về Loki (job=incident-analyzer)
       → email evidence bundle (SMTP MailHog trong cụm) tới MAIL_TO (soc@ztlab.local)
  → DỪNG Ở ĐÂY. Không có bước "approve playbook", không patch Service/Deployment nào, không
    revoke session nào — incident-analyzer không có Kubernetes client, không RBAC. Admin đọc
    email + dashboard rồi tự quyết định, thủ công, ngoài phạm vi hệ thống này.
  → (Giai đoạn C, chưa triển khai) model ML có thể POST /evidence/{id}/risk-score để gắn thêm
    điểm rủi ro vào evidence record đã lưu — endpoint chừa sẵn, chưa có consumer thật.
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
| OPA JWKS source | `keycloak-openstack.crapi.svc.cluster.local:30091/realms/ztlab/protocol/openid-connect/certs` (A1 — cross-cloud, trước là nội cụm `keycloak.identity.svc:8080`) |
| Keycloak realm / clients | `ztlab` / `crapi-bff`, `crapi-bff-stepup` (public PKCE) — **chạy trên `ctx-openstack`, ns `identity` (A1)** |
| Token audience (OPA kiểm) | `crapi-bff` |
| crAPI JWT kid (bff mint) | `MKMZkDenUfuDF2byYowDj7tW5Ox6XG4Y1THTEGScRg8` (RS256, khoá `deploy/vendor/crapi-keys/jwks.json`) |
| Namespace ứng dụng | `crapi` (thay `financial`) |
| NodePort cross-cloud | keycloak 30091 (A1), identity 30090, postgres 30432 (os-k3s-master 192.168.101.11) |
| WireGuard | wg0 10.200.0.0/24, UDP 51820, keepalive 25, watchdog 60s |
| Subnet DNS OpenStack | 1.1.1.1 / 1.0.0.1 |
| WAF (A2) | `owasp/modsecurity-crs` (ghim sha256), `SecRuleEngine=DetectionOnly`, PARANOIA=1, ANOMALY_INBOUND=5/OUTBOUND=4 |
| Device CA / client-cert mTLS (A3) | ECDSA P-256, 10y; entrypoint `https://crapi.ztlab.local:18443` (Traefik, TLSOption `device-mtls`); posture ở `Subject OU=posture:<x>`; phát hành: `scripts/issue-device-cert.sh <id> <compliant\|non-compliant>` |
| Port-forward (open-admin-uis.sh) | crAPI (WAF→BFF) :18081 · crAPI bypass BFF :18083 · crAPI Traefik mTLS thật :18443 · Keycloak :8180 · Grafana :3000 · Loki :13100 · Incident Analyzer :8091 · Prometheus :9090 · MailHog crAPI :8025 · MailHog SOC :8026 |
| Sensitive actions (step-up) | POST `/workshop/api/shop/orders`, `…/return_order`, `/identity/api/v2/user/reset-password`, `…/change-email` |
| Admin paths (chỉ crapi-admin) | `/identity/api/v2/admin`, `/workshop/api/management` |

---

## 10. VẬN HÀNH & SỰ CỐ ĐÃ BIẾT

### 10.1 Kiểm tra sức khoẻ

- `bash scripts/health-check.sh` — kỳ vọng `FAIL=0` (WARN chấp nhận: `.env.ai missing`, remote SSH skipped).
- `python3 tests/test_service_graph_consistency.py` — `2/2 PASS` (service-graph = nguồn sự thật).
- `bash tests/crapi_run_all.sh` — 6 kịch bản tấn công (A3 thêm `crapi_step_up.sh`), kỳ vọng `PASS=6 FAIL=0`, chạy thật qua `https://crapi.ztlab.local:18443` (client cert `compliant`); sau đó kiểm Grafana (Firing) + email evidence bundle ở MailHog SOC (`:8026`) — **không** còn "SOAR `/cases`" (A4 đã bỏ endpoint đó).
- **A5.2:** `SCENARIO=... TARGET_ENTITY=... bash tests/crapi_run_campaign.sh crapi_bola.sh` — chạy 1 kịch bản có gắn nhãn, ghi 1 dòng JSON vào `tests/runs.jsonl` (gitignored) để join với Loki sau này theo `(target_entity, [t_start,t_end])`.

### 10.2 Sự cố đã biết + cách xử lý

| Triệu chứng | Nguyên nhân | Xử lý |
|---|---|---|
| `security-healthcheck` CronJob nhấp nháy `opa=000/critical` | k3s kube-router chậm cập nhật ipset cho pod Job mới mỗi phút; OPA thật sự khoẻ | **ĐÃ FIX (2026-09-13):** `k8s/security-monitoring/healthcheck-cronjob.yaml` retry curl OPA 3 lần (5s/lần) trước khi báo critical thật. Verified 2 lần chạy liên tiếp `status=healthy opa=200`. |
| Toàn bộ crapi 2-cloud **503**, `svid:null` trong access log | Uplink host `aio` (hotspot điện thoại) drop NAT'd UDP → DNS(8.8.8.8) + WireGuard chết → SPIRE agent không attest → SVID hết hạn → mТLS STRICT sập | **Runbook §10.3**. Đã hạ rủi ro: DNS→1.1.1.1, coredns-custom, wg-watchdog, spire-agent `IfNotPresent`. |
| `bff → workshop` 502 `response_time=20000` | mТLS/SDS chưa settle sau restart (istio-proxy không tự tái lập SDS — Istio 1.22.3 + SPIRE 1.9.4) | `kubectl -n crapi rollout restart deploy` (thứ tự: identity OS → AWS). `deploy-crapi.sh::restart_workloads_for_sds` làm sẵn cuối deploy. |
| `ensure-spire-entries.sh` timeout `error: timed out waiting for the condition` ở bước register SPIRE entries | Một `spire-agent` pod (thường OpenStack, node yếu/uplink hotspot) đôi khi cần hơn 180s để attest xong dù rollout vẫn tiến triển bình thường | **ĐÃ FIX (2026-09-13):** `wait_rollout()` retry lần 2 (tổng 2×180s) trước khi fail thật. |
| Login Keycloak báo "username phải là email" | Đang ở form login GỐC của crapi-web SPA (không dùng được — BFF chặn `/identity/*` chưa có phiên) | Vào `https://crapi.ztlab.local:18443/login` (form Keycloak, cần client cert — §4.8) hoặc tunnel dev `http://localhost:18081/login` (bỏ qua Traefik, không cần cert). Username hoặc email đều được. |
| `k8s-tunnel` chết giữa chừng | SSH qua bastion không ổn định / nhiều kết nối song song | `bash scripts/k8s-tunnel.sh down all && up all` |
| BFF trả `posture:unknown, device_trust:suspicious` dù cert hợp lệ | (Đã fix, để lại làm tham khảo) `X-Forwarded-Tls-Client-Cert-Info` bị URL-encode, `_parse_cert_info` cũ split `;`/`=` literal nên không khớp gì | Đã sửa: `urllib.parse.unquote()` trước khi parse bằng regex `key="value"` (§4.8). |

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

**Đã hoàn tất (branch `feat/kehoach-thaydoi`, verified trên cụm 2-cloud):**
- crAPI Core 2-cloud + mТLS/SPIRE + BFF token-exchange + OPA 2-PDP + NetworkPolicy (migration finance→crAPI, xem `KET-QUA-CRAPI.md` cho log chi tiết từng phase).
- **Giai đoạn A (`KEHOACH-THAYDOI-HETHONG.md`) — A1 đến A5.2, 100% xong, verify sống, đã commit (2026-09-13):**
  - **A1** — Keycloak + keycloak-db + openldap chuyển sang OpenStack (§4.5).
  - **A2** — WAF ModSecurity3+CRS DetectionOnly trước BFF; `bff` PeerAuthentication siết STRICT; Prometheus onboard vào mesh (§4.7, §4.2).
  - **A3** — Device CA riêng + client-certificate mTLS thật, posture nhúng trong cert, HTTPS bắt buộc ở Traefik biên (§4.8). 6 bug hạ tầng thật tìm và sửa tận gốc khi verify sống (WAF Host-header/PassthroughCluster, Keycloak redirectUris không update cho client cũ, OIDC redirect scheme sai do WAF ghi đè X-Forwarded-Proto, cert-info URL-encoded chưa decode, thiếu `grafana-smtp-secret`, thiếu `public_path` cho OIDC bootstrap).
  - **A4** — Gộp `soar-engine`+`ai-analyzer`+`security-scorer` thành `incident-analyzer`; bỏ hoàn toàn khả năng thực thi (§7.3).
  - **A5.1** — xác nhận `source_principal`/`destination_principal` không bị rơi trong pipeline Loki; promote thành label riêng (§7.1).
  - **A5.2** — `tests/crapi_run_campaign.sh`, gắn nhãn theo lần chạy offline, không tiêm marker vào traffic tấn công (§10.1).
- Sự cố hạ tầng phát hiện + sửa tận gốc trong lúc làm Giai đoạn A (không thuộc kế hoạch, phát sinh khi verify sống): promtail hardcode `api_server` AWS làm service-discovery chết trên OpenStack; `security-healthcheck` CronJob flake `opa=000` do k3s netpol ipset lag; `ensure-spire-entries.sh` rollout-status timeout quá sớm trên agent chậm attest (§10.2).

**Việc còn lại (`KEHOACH-THAYDOI-HETHONG.md`):**
- **"SỬA ĐỀ CƯƠNG (v9)"** — 4 điểm sửa câu chữ trong `DeCuongChiTiet_KLTN_ZTA_v8.docx` (không phải infra, việc viết của người dùng).
- **Giai đoạn B (sinh dữ liệu) — CHƯA BẮT ĐẦU:** B1 load generator hành vi người dùng thật (chưa tồn tại), B2 `scripts/capture-session.sh` đánh dấu phiên thu thập hợp lệ (chưa tồn tại), B3 mở rộng 6 script tấn công hiện có lên ≥100 lần chạy tham số hoá + giữ riêng nhóm biến thể test-only (chưa làm), B4 đo latency tách overhead Zero-Trust khỏi độ trễ cross-cloud — `tests/perf_overhead.py`/`collect_metrics.py` tồn tại nhưng còn trỏ tên service app "finance" cũ, chưa sửa cho crAPI, chưa từng chạy thử.
- **Giai đoạn C (ML)** — chưa bắt đầu, dự kiến chạy song song do thành viên khác nhóm phụ trách; endpoint `POST /evidence/{id}/risk-score` ở incident-analyzer đã chừa sẵn.

**Việc người dùng (còn treo):**
- Enroll OTP một lần cho `stepup-demo` qua trình duyệt (không tự động được).
- (Tuỳ chọn) `terraform apply` rule SG `ztlab-sg-private` NodePort-from-OpenStack (cần AWS creds) — hiện dùng đường SNAT qua os-gateway nên không bắt buộc.
- Cân nhắc nâng `default_x509_svid_ttl` 1h → 2–4h (giảm rủi ro sập dây chuyền khi SPIRE hiccup) — đánh đổi: cert sống lâu hơn.

---
*Cập nhật: 2026-09-13. Nguồn: đọc trực tiếp repo `feat/kehoach-thaydoi` (sau 6 commit A2-hoàn-tất/A3/A5.2/docs) + nghiệm thu trên cụm 2-cloud đang chạy.*
