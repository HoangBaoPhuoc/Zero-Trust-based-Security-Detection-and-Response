# HỆ THỐNG CHI TIẾT — Zero-Trust Security Detection & Response cho Microservice đa Cloud

> Tài liệu mô tả toàn bộ **kiến trúc, cấu hình, module và luồng hoạt động** của hệ thống **ĐANG CHẠY** (branch `feat/root-cause-remediation`, cập nhật **2026-10-04** theo cụm dựng từ trống + source). Trạng thái và số liệu chốt: `SAN-SANG-GIAI-DOAN-B.md`; hạn chế: `HAN-CHE-VA-HUONG-PHAT-TRIEN.md`; bằng chứng thực thi từng chính sách: `AUDIT-THUC-THI.md`. Phần chính không chứa số liệu chưa đo lại.
>
> Tài liệu đồng hành: `DEPLOY.md` (quy trình triển khai), `README.md`, `PHAT-HIEN-PHAN-DOAN-L4.md`.
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
                    ┌─────────────────────────── Người dùng / thiết bị ───────────────────────────┐
                    │  https://crapi.ztlab.local:8443 (NodePort) / :18444 (tunnel dev)             │
                    │  Istio IngressGateway — Gateway CR tls.mode: MUTUAL, client-cert Device CA   │
                    ▼
         ╔══════════════════════ AWS (VPC 10.10.0.0/16) ══════════════════════╗   ╔════════ OpenStack (Kolla AIO trên host `aio`) ════════╗
         ║  k3s cluster "aws-k3s"  (master + 2 worker, subnet 10.10.1.0/24)   ║   ║  k3s cluster "os-k3s" (master + 2 worker,             ║
         ║                                                                    ║   ║                        subnet 192.168.101.0/24)      ║
         ║  ns istio-system: istiod + istio-ingressgateway (SPIFFE           ║   ║  ns crapi:                                            ║
         ║   aws/edge-gateway — biên DUY NHẤT, không còn Traefik)             ║   ║   • crapi-identity  (Java Spring — cấp JWT)          ║
         ║  ns crapi:                                                         ║   ║   • postgresdb      (Postgres 14 — DB DUY NHẤT,      ║
         ║   • waf            (nginx+ModSecurity3+CRS DetectionOnly, STRICT   ║   ║     app-level auth, không sidecar; xem AUDIT §3.5)    ║
         ║     mТLS — chỉ edge-gateway gọi được)                              ║   ║                                                      ║
         ║   • bff            (FastAPI — EDGE PEP, sau waf; PeerAuth STRICT;  ║   ║   • mailhog [TEST DOUBLE] (SMTP + UI, memory)        ║
         ║     device-revocation ConfigMap đọc tươi mỗi request ghi)          ║   ║   • opa-server ×3   (PDP path crosscloud — STRICT    ║
         ║   • crapi-web      (React/nginx tĩnh, bff proxy tới)               ║   ║     mТLS cổng 9191, PERMISSIVE có kiểm soát 8181)    ║
         ║   • crapi-community(Go)                                            ║   ║                                                      ║
         ║   • crapi-workshop (Django)                                        ║   ║  ns identity (istio-injection=enabled): keycloak     ║
         ║   • mongodb (app-level auth), redis (--requirepass)               ║   ║   STRICT mТLS tuyệt đối + keycloak-db (Postgres, A1) ║
         ║   • opa-server ×3  (PDP path authz — cùng mô hình STRICT/PERMISSIVE║   ║  ns identity-directory: openldap [TEST DOUBLE]       ║
         ║     như OpenStack)                                                 ║   ║  ns spire: spire-server (sqlite, backup/restore có   ║
         ║                                                                    ║   ║   thật — scripts/backup-spire-datastore.sh) + agent  ║
         ║  ns spire, istio-system, gatekeeper-system                        ║   ║  ns istio-system: istiod (KHÔNG cài ingressgateway   ║
         ║  ns vault: Vault (storage: file, PVC bền + auto-unseal, backup/    ║   ║   trên OS — istio-operator-os-overlay.yaml)          ║
         ║   restore có thật — scripts/backup-databases.sh)                  ║   ║                                                      ║
         ║  ns plg-stack: loki (retention 30 ngày, đủ 150h Giai đoạn B),      ║   ║  os-gateway VM (192.168.100.10 / .101.1 / .102.1)    ║
         ║   grafana, promtail, incident-analyzer, mailhog [TEST DOUBLE]      ║   ║   — NAT private/identity → internet, WireGuard peer  ║
         ║  ns monitoring: prometheus (mesh-injected, SVID aws/prometheus)    ║   ║                                                      ║
         ║  aws-gateway VM (WireGuard peer) · aws-bastion (SSH jump)          ║   ║  edge-router (Neutron): DMZ 192.168.100.0/24 ↔ ext   ║
         ║                                                                    ║   ║                          (floating IP thay đổi mỗi   ║
         ║                                                                    ║   ║                           lần terraform apply)       ║
         ╚════════════════════════════════════╤═══════════════════════════════╝   ╚═══════════════════╤══════════════════════════════════╝
                                              │                                                       │
                                              └───────────── WireGuard (wg0, 10.200.0.0/24, UDP 51820) ┘
                                                    aws_gateway 10.200.0.1  ◄────►  os_gateway 10.200.0.2
                                    (định tuyến chéo: 10.42/10.43 ◄─► 192.168.101/102, PersistentKeepalive=25 + wg-watchdog)
```

**Đường request biên (sau Phần 1.3 remediation 2026-09):** `trình duyệt/thiết bị --[TLS mТLS, Device CA]--> Istio IngressGateway (Gateway CR, xác thực client-cert TẠI TẦNG TLS) --[mТLS SPIFFE thật, header x-device-cert-info do Lua filter ở chính Gateway gắn]--> waf (STRICT mТLS, CRS DetectionOnly, AuthorizationPolicy waf-opa-authz qua OPA thật) --[mТLS SPIRE]--> bff`. Không TLS / cert sai CA / cert hết hạn → không tới được ứng dụng; cert bị thu hồi (`scripts/revoke-device-cert.sh`) → vẫn kết nối được nhưng **bị chặn hành động GHI** ở BFF (không phải CRL ở tầng TLS; xem §4.8); cert hợp lệ nhưng posture:non-compliant → qua được TLS nhưng bị OPA/BFF từ chối ở hành động ghi (4 kịch bản, `tests/crapi_cert_scenarios.sh`). Traefik, cổng :18443 và X-Edge-Marker không còn nằm trên đường request của crAPI (không còn `X-Edge-Marker`/`EDGE_MARKER` ở đâu trong codebase; Traefik chỉ còn là ingress mặc định do k3s cài — pod vẫn chạy — và vài manifest cũ `k8s/ingress.yaml`, `k8s/monitoring/prometheus.yaml`, `k8s/identity/ingress-os.yaml` còn định nghĩa `IngressRoute` không dùng cho crAPI). Chi tiết: §4.7 (WAF), §4.8 (Device CA + thu hồi).

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
| Secrets | HashiCorp Vault (storage backend `file`, PVC bền, auto-unseal — KHÔNG phải dev mode; §4.9) |
| WAF (A2) | nginx + ModSecurity **v3** + OWASP CRS **v4** (`owasp/modsecurity-crs`, ghim `@sha256:`), `SecRuleEngine=DetectionOnly` |
| Device CA (A3) | CA riêng ECDSA P-256 tự sinh (`scripts/deploy-security-stack.sh::provision_device_ca`), tách bạch với SPIRE root CA; private key lưu Vault, không commit git |
| SIEM | Grafana + Loki + Promtail (PLG) + Prometheus |
| Target app | OWASP crAPI Core (identity/community/workshop/web/mailhog), ảnh ghim `@sha256:` từ Docker Hub |

---

## 3. HẠ TẦNG (Terraform + Ansible)

> *Mô tả theo source Terraform/Ansible; nghiệm thu bằng `terraform destroy` + `deploy-all.sh` từ trống ngày 2026-10-04 (`SAN-SANG-GIAI-DOAN-B.md` mục 4.7).*

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
| `k3s.yml` | cài k3s server/agent 2 cluster (node-token, `--flannel-iface`; giữ Traefik mặc định của k3s nhưng nó không nằm trên đường request crAPI). **Không** cài `ipset` lên host: k3s tự có `ipset` trong thư mục bin của nó (AUDIT §3.1) |
| `wireguard.yml` | sinh keypair, render `wg0.conf` (`PersistentKeepalive = 25`), bật `wg-quick@wg0`; **`wg-watchdog.sh` + systemd timer 60s** trên cả 2 gateway (nếu handshake > 200s cũ + ping peer fail → `systemctl restart wg-quick@wg0`) |
| `promtail.yml` | (deploy Promtail — thực tế Promtail chạy như DaemonSet k8s, xem §7) |

**Inventory** (`ansible/inventory/hosts.yml`): các host AWS đi qua `ProxyJump=ubuntu@<bastion>`; các node OpenStack private đi qua `ProxyJump=ubuntu@<os_gateway_floating_ip>`. `deploy-all.sh` bước 9 tự vá IP + **`ssh-keygen -R`** các jump host (floating IP tái sử dụng qua các lần deploy → host key cũ trong `known_hosts` làm hop ProxyJump con chết: `Connection closed by UNKNOWN port 65535`).

---

## 4. LỚP ZERO-TRUST

### 4.1 SPIRE — danh tính workload (SPIFFE)

- **2 SPIRE server** (mỗi cluster 1), datastore `sqlite3` trên **hostPath `/opt/spire/data/server`** pin vào node `spire-server=true` (`strategy: Recreate`). UpstreamAuthority = `disk` (root CA `spire/root-ca/ca.crt`, `ca_ttl = 168h`).
- **SPIRE agent** = DaemonSet, `hostNetwork: true`, `dnsPolicy: ClusterFirstWithHostNet`. NodeAttestor `k8s_psat` (`cluster = "aws-k3s"` / `"os-k3s"`). Init container `wait-for-server` + `alias-socket-for-istio` (`ln -sfn agent.sock socket` — Istio SDS hardcode tên socket là `socket`). **`imagePullPolicy: IfNotPresent`** cả 3 container (tránh ImagePullBackOff khi node mất internet).
- **SVID TTL:** X.509-SVID **4 h** (2026-10-04) — đặt trên từng entry (`ensure-spire-entries.sh`, `SPIRE_X509_SVID_TTL=14400`, giá trị trên entry ghi đè default server) và `default_x509_svid_ttl = "4h"` ở `spire/server/*.conf`; JWT-SVID 5 phút (không dùng). Kiểm sống: 13/13 entry 14400 s, cert sidecar `bff` hiệu lực đúng 4 h (`results/closeout/live-checks/`). Đánh đổi: H17.
- **Scheme SPIFFE tuỳ biến (KHÔNG phải mặc định Istio):** `spiffe://ztlab.local/<cloud>/<service>`. Danh sách đầy đủ (Phần 2, remediation 2026-09 — SINH TỰ ĐỘNG, không còn viết tay/hardcode): [`docs/GENERATED-SERVICE-GRAPH.md` §1](docs/GENERATED-SERVICE-GRAPH.md#1-danh-sách-spiffe-entry). Nguồn sự thật: `policy/service-graph-crapi.yaml` → `scripts/gen-spire-entries.py` → `scripts/spire-entries.generated.sh` (mà `scripts/ensure-spire-entries.sh` source, thay vì hardcode danh sách + số lượng kỳ vọng riêng như trước — 2 con số này từng lệch nhau mà gate deploy không phát hiện được).

  Node-alias: một entry `-node` parent vào `spire-server`, selector `k8s_psat:cluster:<x>` (mọi agent khớp, bất kể UUID) → workload entry parent vào alias `spiffe://ztlab.local/nodes/{aws,os}-k3s` thay vì UUID node.
- Vì scheme khác mặc định (`spiffe://<trustdomain>/ns/<ns>/sa/<sa>`), **mỗi Service cần một `DestinationRule` với `subjectAltNames` tường minh** (xem §4.2).

### 4.2 Istio service mesh

- Cài bằng `istioctl install -f k8s/istio/istio-operator.yaml` (2 cluster). `trustDomain: ztlab.local`. SPIRE là nguồn cert thật (Istio agent SDS ↔ spire-agent qua socket).
- **`meshConfig.extensionProviders`**: `opa-ext-authz` → `envoyExtAuthzGrpc` `opa-service.crapi.svc.cluster.local:9191`.
- **PeerAuthentication** ns `crapi`: `default` = **STRICT**; per-workload PERMISSIVE chỉ còn `crapi-web` (static do BFF gọi) và cổng `8181` của `opa` (REST/health, có AuthorizationPolicy chỉ cho `GET /health`). **`waf`, `bff`, `opa`(9191), `keycloak` đều STRICT tuyệt đối** — mọi hop `edge-gateway → waf → bff` là mТLS SPIFFE thật (§4.7). Mọi client vào workload STRICT phải có SVID (vd Prometheus có sidecar nhờ nhãn `istio-injection` khai ở `k8s/namespaces.yaml`). `bff` hiện KHÔNG có route `/metrics` (xem H1).
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
- Sinh ra `opa/crapi-policies/service_acl.rego` (package `zta.crapi.generated`) + `k8s/crapi/network-policies/{aws,os}-{pod-segmentation,allow-list}.yaml` + `scripts/spire-entries.generated.sh` + `docs/GENERATED-SERVICE-GRAPH.md` bằng `scripts/gen-{rego-acl,networkpolicy,spire-entries,docs-tables}.py` (Phần 2, remediation 2026-09 — mở rộng từ bản gốc chỉ sinh 2 file đầu).
- Test `tests/test_service_graph_consistency.py` (4 bài, 4/4 PASS 2026-09-26): (1) chạy TOÀN BỘ generator xong không file nào đổi; (2) mọi edge nghiệp vụ có mặt ở CẢ L7 (rego) lẫn L4 (netpol); (3) mọi workload tham gia edge L7 có entry SPIRE thật, không tự mâu thuẫn khai `spiffe: false`; (4) cổng egress nội ns của baseline NetworkPolicy phủ mọi cổng của edge nội cụm (bắt lỗi thiếu 8080 gây `waf→bff` 503).
- **Ma trận edge L7 + danh sách edge L4** (SINH TỰ ĐỘNG, không còn viết tay): [`docs/GENERATED-SERVICE-GRAPH.md` §2-3](docs/GENERATED-SERVICE-GRAPH.md#2-ma-trận-edge-l7-qua-opa-service_acl). Mọi cặp KHÔNG có trong ma trận L7 (vd `crapi-community → crapi-workshop`) → OPA `internal_service_request` = false → **deny (403)** = chống lateral movement.

**`zta_crapi.rego` (AWS) — cấu trúc quyết định:**
```
allow if public_path                    # /health, /identity/health_check, POST /identity/api/auth/{signup,login,verify,check-otp,…}, GET jwks.json,
                                         # BFF OIDC bootstrap (/auth/start, /auth/callback, /auth/logout, /login, /kc — A3),
                                         # bff→crapi-web static  (hop biên edge-gateway→waf đi qua service_acl thật, không còn rule marker)
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
> **Lưu ý thiết kế:** `posture`/`device_trust` chỉ gate **hành động GHI + nhạy cảm**, khớp BFF `_rbac_ok` (chỉ chặn suspicious device ở method GHI). Đọc thường vẫn đủ mạnh bằng valid_jwt + RBAC + valid_svid + mТLS. **Từ A3**, `posture`/`device_trust` không còn là heuristic User-Agent nữa mà đọc từ client certificate đã verify ở Istio IngressGateway — xem §4.8.

**`crosscloud_crapi.rego` (OpenStack)** — giữ `service_acl` + `allowed_by_acl` + `posture_compliant`; **bỏ** `device_trust_compliant` (BFF đã kiểm ở đầu vào; hop bff→identity cross-cloud chỉ tới OPA OpenStack). Guard `crapi-identity`: chỉ chấp nhận nguồn `bff` / `crapi-community` / `crapi-workshop`.

**JWT verify:** OPA (AWS) gọi `http.send` tới `http://keycloak-openstack.crapi.svc.cluster.local:30091/realms/ztlab/protocol/openid-connect/certs` + `.../.well-known/openid-configuration` (`force_cache` 300s) — **kể từ A1**, đây là hop cross-cloud thật qua Service selectorless `keycloak-openstack` (NodePort 30091, xem §6), không còn nội cụm `keycloak.identity.svc:8080` như trước A1. Xác nhận qua `counter_rego_builtin_http_send_network_requests: 2` trong decision log.

### 4.4 NetworkPolicy L4 — baseline + pod-segmentation, cả hai được apply (đo lại 2026-09-26)

`k8s/crapi/network-policies/` (SINH TỰ ĐỘNG từ `policy/service-graph-crapi.yaml` bằng `scripts/gen-networkpolicy.py`, **không sửa tay**):
- `{aws,os}-allow-list.yaml` — baseline `podSelector: {}` `policyTypes: [Ingress, Egress]` ⇒ **mọi pod ns `crapi` default-deny cả 2 chiều**, rồi mở: ingress từ `kube-system`/`istio-system`/`monitoring`/`spire` (đúng cổng), egress DNS + istiod + Loki + ipBlock cross-cloud (cổng NodePort 30090/30091/30432/31025 tính từ edge `cross_cluster`) + **egress nội ns `crapi` với danh sách cổng TÍNH RA từ edge nội cụm** (`_intra_ns_egress_ports`), hợp với danh sách nền viết tay.
- `{aws,os}-pod-segmentation.yaml` — mỗi policy `podSelector: app=<đích>`, ingress theo `service_acl` (edge nghiệp vụ + edge L4 như `bff→redis`, `→opa`).
- **Cả hai được `kubectl apply`** trong `scripts/deploy-crapi.sh::apply_network_policies` (bản 2026-09-19 từng ngừng apply pod-segmentation — đã đảo ngược, xem dưới).

**Hiệu lực THẬT đã đo** (ma trận 22 ô `tests/netpol_matrix.sh` + probe cô lập `tests/netpol_podselector_probe.sh`; số liệu và cách đo: `AUDIT-THUC-THI.md` §3, thô: `results/round3/`):

| Phạm vi | Kết luận đo |
|---|---|
| Nguồn NGOÀI ns `crapi` (`default`, `monitoring`) → pod `crapi` | ✅ chặn đúng, chỉ vào đúng cổng baseline mở |
| Egress cross-cloud (ipBlock) | ✅ chặn đúng (k3s-API, ssh của node OpenStack bị reject; cổng NodePort được phép tới được) |
| policy `podSelector` đơn lẻ (ns tạm, 2 cụm, cùng/khác node) | ✅ 8/8 đúng |
| **Phân đoạn TRONG ns `crapi` (pod-segmentation)** | ❌ **không hiệu lực ở các cổng nằm trong egress baseline** (8/8 ô "kỳ vọng chặn" vẫn thông) — rule egress của baseline làm thủng ingress default-deny của pod đích (thí nghiệm cô lập `egress-shadow` tái hiện được) |

> **Hai chẩn đoán cũ ĐÃ BỊ BÁC BỎ (không dùng cho luận văn):** (1) "kube-router không enforce đáng tin cậy" (2026-09-18); (2) "node không có `ipset` nên rule podSelector vô hiệu, ngừng apply pod-segmentation" (2026-09-19). Sự thật: k3s có `ipset` riêng, `PATH` của tiến trình k3s đặt nó trước `/usr/sbin`; `command not found` chỉ xuất hiện ở shell SSH. Sự cố "mesh-connectivity" (`waf→bff` 503) là **lỗi cấu hình**: egress baseline thiếu cổng 8080 — đã sửa (cổng nay được sinh từ edge) và có test hồi quy.
>
> **Câu chuẩn dùng cho luận văn (vòng 2026-09-29):** *"L4 chặn nguồn ngoài namespace và egress cross-cloud; phân đoạn nội namespace do L7 (mTLS + PDP) đảm nhiệm."* Không câu nào trong tài liệu được ngụ ý NetworkPolicy chặn được pod-to-pod trong ns `crapi`.
>
> **Hệ quả kiến trúc:** L4 KHÔNG được tuyên bố là lớp phân đoạn nội ns. **L7 (mТLS STRICT + OPA `service_acl`) là lớp phân đoạn nội ns duy nhất đáng tin**; redis (`--requirepass`) và mongodb (`--auth`) có xác thực tầng dữ liệu bù vì L4 nội ns không chặn được `crapi-web → redis/mongodb`. Chi tiết + hướng khắc phục: `HAN-CHE-VA-HUONG-PHAT-TRIEN.md` H3.

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
| **Device cert + posture (A3/Phần 1.3 — đọc từ Istio IngressGateway, KHÔNG còn Traefik)** | `_evaluate_device_cert` đọc header `x-device-cert-info` (`_DEVICE_CERT_HEADER_V2`, `services/bff/main.py`) — do **Lua EnvoyFilter ở chính Gateway** (`k8s/istio/edge-gateway-cert-header.yaml`) gắn SAU KHI verify client cert bằng Device CA ở tầng TLS của `k8s/crapi/edge-gateway.yaml` (`tls.mode: MUTUAL`). Không có bí mật chia sẻ kiểu `X-Edge-Marker` nữa — chuỗi tin cậy neo vào mТLS peer identity: một EnvoyFilter Lua THỨ HAI ở **waf's inbound** (`k8s/crapi/waf-strip-forged-cert-header.yaml`) xoá sạch header này trừ khi peer đúng `spiffe://ztlab.local/aws/edge-gateway` — pod khác trong mesh gọi thẳng `bff` không giả được header, và `service_acl` (chỉ `waf → bff`) là lớp chặn cuối. `_parse_cert_info` decode URL-encoding rồi regex `key="value"` lấy `Subject`/`SAN`; `device_id` = SAN URI `spiffe://ztlab.local/device/<id>`, `posture` = `Subject OU=posture:<compliant\|non-compliant>`. Thiếu header/cert/device_id → mặc định `posture:unknown, device_trust:suspicious`. Gắn header `X-Device-Trust`/`X-Device-Posture` cho hop đi tiếp. Chi tiết đầy đủ + verify sống: §4.8. |
| **OIDC redirect scheme (A3/Phần 1.3)** | `_external_base` (`services/bff/main.py`): waf's nginx ghi đè `X-Forwarded-Proto` về scheme của chính nó (`http`, vì TLS kết thúc ở Istio IngressGateway, hop waf→bff là mТLS nội mesh) nên không tin được header chuẩn — đọc `x-edge-scheme`, header riêng do **cùng Lua EnvoyFilter ở Gateway** gắn (không phải Traefik Middleware), để dựng đúng `redirect_uri` HTTPS cho OIDC. |
| **Token exchange (mỗi request proxy)** | `Authorization: Bearer <crapi_jwt>` — bff **mint RS256** `{sub: email, role: <"user"/"mechanic"/"admin">, iat, exp}` bằng **khoá RSA của chính crAPI** (`deploy/vendor/crapi-keys/jwks.json` == `default_jwks.json` nhúng trong ảnh identity, `kid = MKMZkDenUfuDF2byYowDj7tW5Ox6XG4Y1THTEGScRg8`). `X-Access-Token: <keycloak_access_token>` — cho OPA kiểm realm role + `acr`. Client KHÔNG được tự đặt các header này (bff strip trước khi forward). |
| **RBAC gương** (`_rbac_ok`) | Gương của `zta_crapi.rego` `role_permits_action` — cần vì hop bff→identity (cross-cloud) chỉ qua OPA OpenStack (không kiểm token người dùng). GET/HEAD/OPTIONS → OK cho mọi role hợp lệ; GHI vào `_ADMIN_PREFIXES` → cần `crapi-admin`; GHI mechanic prefix → mechanic/admin. → audit `event=rbac_denied` khi từ chối. |
| **Step-up gương** (`_is_sensitive`) | Danh sách `SENSITIVE_ACTIONS` → nếu `session.acr != "high"` → `401 {"error":"step_up_required","stepup_url":"/auth/start-stepup"}` + audit `event=step_up_required`. |
| **Device-trust gate** | `suspicious` + method GHI → `403 {"reason":"suspicious_device"}` + audit `event=device_trust_denied`. |
| **Reverse proxy** | `/identity/*` → `crapi-identity-openstack.crapi.svc:30090` (cross-cloud) · `/community/*` → `crapi-community:8087` · `/workshop/*` → `crapi-workshop:8000` · còn lại → `crapi-web:80`. `CHATBOT_SERVICE`/`MAILHOG_WEB_SERVICE` trỏ về `crapi-web:80` (không deploy — để nginx crapi-web resolve upstream, khỏi `[emerg] host not found`). |
| **Audit → Loki** | `_audit(event, …)` POST JSON tới `LOKI_URL` job `bff-audit` (`user_login`, `rbac_denied`, `step_up_required`, `device_trust_denied`, `sensitive_action_ok`, `proxy_error`). |

### 4.7 WAF — ModSecurity3 + OWASP CRS (A2, `k8s/crapi/waf.yaml`)

Đứng ngay sau Istio IngressGateway, trước `bff`: `edge-gateway --mТLS(Istio, STRICT)--> waf:8080 --mТLS(Istio)--> bff:8080`. `SecRuleEngine=DetectionOnly` — CRS đánh giá **mọi** request và ghi audit JSON ra stdout khi khớp rule, nhưng **không bao giờ chặn** → không thể làm hỏng luồng nghiệp vụ crAPI, không làm nhiễu telemetry huấn luyện. Đây là phép đo đối chứng trung tâm của luận văn: CRS bắt SQLi/XSS/path-traversal (`tests/crapi_sqli_waf.sh`) nhưng **không bắt được** request BOLA nào (`tests/crapi_bola.sh`, tất định qua 3 lần chạy liên tiếp — Phần 1.1 remediation 2026-09) — cho thấy phương pháp dựa trên chữ ký không phát hiện được lớp tấn công vượt quyền, biện minh cho lớp Zero-Trust authorization đứng sau.

- `waf` chạy Istio sidecar với SVID thật `spiffe://ztlab.local/aws/waf`; `PeerAuthentication waf-strict` (STRICT tuyệt đối — Traefik không còn tồn tại, không có lý do nhận plaintext); `DestinationRule waf-custom-san` (ISTIO_MUTUAL) + `AuthorizationPolicy CUSTOM waf-opa-authz → opa-ext-authz` cho **cả hai chiều** (inbound từ edge-gateway lẫn outbound tới bff) — parity với các workload khác trong mesh.
- **Bug hạ tầng thật đã sửa (tồn tại từ A2, phát hiện khi verify sống A3):** ảnh gốc `owasp/modsecurity-crs` có `includes/proxy_backend.conf` dùng `proxy_set_header Host $host;` — nginx forward nguyên Host header của **client bên ngoài** sang bff thay vì host thật của bff → Envoy outbound router của waf rơi vào `allow_any`/`PassthroughCluster` (bỏ qua hẳn mТLS/OPA, **không có decision log nào**). Fix: `waf-proxy-backend-conf` ConfigMap ghi `proxy_set_header Host $proxy_host;` **và** `X-Forwarded-Host: $http_host` (bug thứ hai phát hiện ở Phần 1.3 khi dựng biên mới — thiếu header này làm BFF build sai `redirect_uri` OIDC, login qua Gateway không hoạt động).
- **CRS exclusion đúng 1 rule/1 header** (`waf-crs-exclusions`): rule 921140 (CRLF injection) false-positive trên `x-forwarded-client-cert` — header Envoy tự gắn, chứa cert PEM URL-encoded, CRS decode `%0A` thành newline thật rồi báo nhầm. Verify: exclusion không làm yếu phát hiện SQLi/XSS/LFI thật.
- **Gate waf's own inbound hop (Phần 1.3, thay X-Edge-Marker cũ):** Traefik + `X-Edge-Marker` đã THÁO BỎ HOÀN TOÀN (0 kết quả chức năng khi grep). Biên mới là Istio IngressGateway (`spiffe://ztlab.local/aws/edge-gateway`) — hop này CÓ `source_principal` thật, qua `waf-opa-authz` (CUSTOM ext_authz, OPA thật) thay vì "nới lỏng chung chung". Authorization theo user/role/posture diễn ra tiếp ở hop kế (waf→bff).

### 4.8 Device CA — Client-certificate mTLS + posture nhúng trong cert + thu hồi (A3, Phần 1.3 + 3.2)

Client-certificate mTLS thật ở biên Istio IngressGateway, posture nhúng ngay trong cert nên **không cert / cert sai CA / cert hết hạn = không kết nối được** (từ chối ở bắt tay TLS), không phải "OPA/BFF từ chối sau khi đã kết nối". Cert bị lộ có thể thu hồi trước hạn qua denylist tầng ứng dụng — nhưng **chứng chỉ bị thu hồi thì bị chặn ở các thao tác ghi; thao tác đọc vẫn đi qua** (không phải CRL tầng TLS, xem gạch đầu dòng "Thu hồi" dưới).

- **Device CA riêng** (`scripts/deploy-security-stack.sh::provision_device_ca`), tách bạch với SPIRE root CA: ECDSA P-256, tự sinh 10 năm nếu chưa có, hoặc phục hồi từ Vault. **Private key KHÔNG commit git**.
- **`k8s/crapi/edge-gateway.yaml`:** `Gateway` CR (ns `crapi`, cổng **8443**, `tls.mode: MUTUAL`, `credentialName: edge-gateway-tls` — bí mật ở ns `istio-system` theo quy ước SDS của Istio) + `VirtualService` → `waf:8080`. Không TLS / cert sai CA / cert hết hạn → không tới được waf/bff. **Cert bị thu hồi vẫn qua TLS** (Gateway không kiểm CRL): chứng chỉ bị thu hồi thì bị chặn ở các thao tác ghi; thao tác đọc vẫn đi qua.
- **Header cert thiết bị:** KHÔNG dùng `x-forwarded-client-cert` chuẩn của Envoy (mỗi hop mТLS tự SANITIZE_SET đè — dùng chuẩn này thì thông tin cert thiết bị mất ngay ở hop kế). Dùng `x-device-cert-info` do **Lua EnvoyFilter ở chính Gateway** gắn (trích `Subject`/`URI` từ cert đã verify), và một Lua EnvoyFilter THỨ HAI ở **waf's inbound** (`waf-strip-forged-device-cert-header.yaml`) xoá header đó trừ khi mТLS peer đúng `spiffe://.../aws/edge-gateway` — chống giả mạo bằng kiểm `source_principal` đúng là biên, không dùng bí mật chia sẻ nào. **Verify thực nghiệm (không chỉ đọc file):** crapi-web/crapi-community (SPIFFE hợp lệ, KHÔNG phải edge-gateway) gọi thẳng `bff` trên path nghiệp vụ → OPA 403 (service_acl chỉ cho `waf → bff`); `/health` (public_path) thì 200 cho mọi nguồn — đúng kỳ vọng, không phải lỗ hổng.
- **Posture nhúng ở Subject `OU=posture:<compliant|non-compliant>`**, device id ở SAN URI `spiffe://ztlab.local/device/<id>` — phát hành bằng `scripts/issue-device-cert.sh <device-id> <compliant|non-compliant>`.
- **Thu hồi (Phần 3.2, remediation 2026-09-19):** KHÔNG vá CRL/OCSP thật ở tầng TLS của Istio Gateway (đường vào DUY NHẤT của toàn hệ thống — rủi ro cấu hình sai cao hơn nhiều so với lợi ích trong phạm vi khoá luận). Thay bằng **denylist tầng ứng dụng**: `scripts/revoke-device-cert.sh <device-id>` ghi vào ConfigMap `device-revocation-list` (ns crapi) mà `bff` đọc TƯƠI trên MỖI request ghi (không cache theo session — một phiên đã đăng nhập TRƯỚC KHI cert bị thu hồi vẫn bị chặn NGAY, không phải chỉ chặn lần đăng nhập tiếp theo). Kubelet tự đồng bộ ConfigMap volume (**đo 16–64 giây**, mount cả thư mục không `subPath`, không cần restart bff). **Phạm vi hiệu lực (đúng thiết kế, không phải CRL tầng TLS):** thiết bị bị thu hồi bị chặn hành động **GHI** (POST/PUT/PATCH/DELETE) — cả phiên đã đăng nhập trước lúc thu hồi lẫn phiên mới — còn hành động **ĐỌC vẫn 200**; kết nối TLS không bị cắt. Verify sống 2026-09-26: `tests/crapi_cert_revocation.sh` PASS=7 (phiên cũ ghi → 403, đọc → 200, phiên mới ghi → 403, `bff-audit event=device_trust_denied reason=revoked`, gỡ thu hồi ghi lại được).
- **4 kịch bản certificate + kịch bản thu hồi thứ 5** (`tests/crapi_cert_scenarios.sh` và `tests/crapi_cert_revocation.sh`) **đã verify sống qua Gateway mới** (`tests/crapi_cert_scenarios.sh`, tự động hoá — trước đây làm tay): (1) cert hợp lệ + `compliant` → 200; (2) không cert → TLS handshake fail; (3) cert ký bởi CA lạ → TLS handshake fail; (4) cert hợp lệ + `non-compliant`, hành động ghi (endpoint **không** thuộc `sensitive_crapi_action` để cô lập đúng biến posture, không lẫn với step-up) → 403 + bằng chứng `bff-audit event=device_trust_denied` (KHÔNG phải `opa-decisions` — BFF chặn ở PEP trước khi proxy tới OPA cho case này, "gương" của OPA).

### 4.9 Gatekeeper + Vault

- **Gatekeeper** (`k8s/gatekeeper/`): chạy `gatekeeper-system` ns trên AWS. **Phần 2 remediation (2026-09-19):** `ZTLabRequireNonRoot`/`ZTLabRequireImagePolicy` từng trỏ `namespace: financial` — namespace đã bị xoá từ lúc migration crAPI, tức DEAD (0 violation ghi nhận vì không có gì để kiểm, không phải vì tuân thủ). Đã retarget `namespace: crapi`: `ZTLabRequireImagePolicy` bật `deny` THẬT (0 violation thật, verify enforcement bằng `kubectl run --image=alpine:latest --dry-run=server` → admission denied thật). **Phần 1.2 remediation (2026-09-19):** `ZTLabRequireNonRoot` nay có **2 constraint** — `crapi-require-nonroot` (namespace `crapi`, `dryrun`, audit tổng quan — vẫn dryrun vì phủ cả image upstream OWASP crAPI/bên thứ 3 không tự sửa được) và `selfbuilt-require-nonroot-deny` (**`deny` THẬT**, `labelSelector: ztlab.io/nonroot-enforced=true`, phủ đúng 4 workload tự viết/tự quản lý manifest — `bff`, `waf`, `opa-server`, `incident-analyzer` — đã kiểm từng cái chạy non-root thật trước khi bật, verify sống bằng cách tạo 1 pod vi phạm và bị admission webhook chặn thật). Chi tiết + bằng chứng: `AUDIT-THUC-THI.md` mục 4.
- **Vault** (`k8s/vault/vault.yaml`): **storage backend `file`** (PVC bền, KHÔNG PHẢI dev mode — Phần 3.1 kiểm lại thấy đã đúng từ trước, không cần sửa), unseal key + root token lưu K8s Secret `vault-unseal-keys` (giản lược có chủ đích cho phạm vi lab, ghi rõ giới hạn ngay trong file), postStart lifecycle hook tự unseal khi pod restart. Vẫn là thành phần Zero-Trust secrets chính (giữ private key Device CA, §4.8). **A4 đã bỏ** consumer cũ `soar-engine`/`SOAR_*`; hiện Vault không có consumer thực thi nào, chỉ giữ vai trò lưu trữ. `grafana-smtp-secret` VÀ `grafana-admin-secret` (Phần 3.7 — trước đây admin password hardcode plaintext trong `grafana.yaml`) là k8s Secret thường tạo trực tiếp trong `deploy-app.sh::deploy_observability_response`, **không** qua Vault. **Backup/restore có thật** (Phần 3.4): `scripts/backup-databases.sh vault` + `scripts/restore-databases.sh vault` — verify sống một chu trình đầy đủ (xoá sạch `/vault/data`, khôi phục, auto-unseal, đọc lại được cả 3 secret).

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

**Promtail** (DaemonSet, `k8s/plg-stack/promtail-daemonset.yaml`, `CLOUD_PROVIDER` per-cluster). Loki chạy 1 nơi (AWS); OpenStack Promtail đẩy log qua **Loki-relay** (`socat 10.10.10.1:13099 → localhost:13100`, `open-admin-uis.sh`) qua WireGuard. **Verify đầu-cuối 2026-09-26** (`tests/verify_telemetry_pipeline.py`, 13/13 PASS): log tới Loki cho `envoy-access`/`opa-decisions` từ CẢ HAI cloud, `bff-audit`, `waf-audit`; Prometheus 3/3 target `up`; 2 datasource Grafana health OK; rule Firing → evidence bundle thật.

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
| **Security Control-Plane Down** | `sum(count_over_time({job="security-healthcheck"} \| json \| status="critical" [3m])) or vector(0)` | critical | infra — **KHÔNG** qua incident-analyzer webhook, admin xử lý trực tiếp. *Sửa 2026-09-26:* bản cũ để `noDataState: Alerting` nên firing vĩnh viễn khi hệ thống KHỎE (query rỗng = NoData); nay `or vector(0)` + `noDataState: OK` |
| **Security Health-Check Silent** (mới 2026-09-26) | `absent_over_time({job="security-healthcheck"}[5m])` | critical | infra — CronJob ngừng ghi log (mất tín hiệu = đáng ngờ); tách khỏi rule trên để giữ đúng ý định gốc |
| **Mesh Integrity** | `{job="envoy-access", namespace="crapi"} \| json \| method != "" \| svid = "" \| path != "/health"` | high | request không có SVID (khả năng bỏ qua mТLS/OPA). **Còn nhiễu (chưa sửa, H2):** đếm cả log phía client của sidecar (`svid` chỉ có ở inbound) và đường debug port-forward |
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
- **Giới hạn đã biết (H1):** `incident-evidence-dashboard.json` còn panel truy vấn metric `ztlab_*` của ứng dụng finance cũ (Prometheus hiện chỉ có 3 target: loki, incident-analyzer, prometheus; `bff` không có `/metrics`) — các panel đó luôn rỗng.

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
13 scripts/sync-app-images.sh     (build+import bff/incident-analyzer; ảnh bên thứ 3 node tự pull)
   scripts/deploy-app.sh --skip-images   — THỨ TỰ THẬT của main() (đã chạy sạch 2026-09-26: 17m56s, exit 0, 0 WARN/FAIL;
   log thô results/round3/deploy-full-2026-09-26.log):
     ├─ regenerate_policy_files  (gen-rego-acl.py + gen-networkpolicy.py)
     ├─ apply_namespaces  (k8s/namespaces.yaml — NGUỒN DUY NHẤT của nhãn istio-injection cho crapi/identity/monitoring)
     ├─ apply_network_policies (baseline sớm)      ├─ deploy_gatekeeper      ├─ deploy_spire_pre_istio
     ├─ deploy_istio  (istioctl install 2 cluster)  ├─ sync_images (skip)
     ├─ deploy_security_stack  (Keycloak OS + Device CA + SPIRE 2 cluster + entries + healthcheck + keycloak-mesh-policies)
     ├─ deploy_crapi  → scripts/deploy-crapi.sh, thứ tự thật:
     │    create_secrets → apply_namespace_and_config → deploy_databases → deploy_crapi_workloads
     │    → register_spire → deploy_crapi_opa (OPA 2 cluster)
     │    → apply_network_policies (**baseline + pod-segmentation**, cả hai)
     │    → configure_crapi_keycloak (role + client crapi-bff/-stepup — Admin API; cần OPA + netpol đã sẵn sàng, nếu không → 403 câm lặng)
     │    → deploy_bff (+ waf, ConfigMap device-revocation-list nếu chưa có)
     │    → reinstall_istio_for_crapi_provider → deploy_mesh_policies (istio-policies + edge-gateway)
     │    → restart_workloads_for_sds (bounce TUẦN TỰ) → run_seed (Job crapi-seed)
     │    → verify (gồm `verify_mesh_connectivity`: request THẬT giữa các cặp service, `fail` nếu không thông)
     ├─ deploy_openldap_and_federation → deploy_audience_mapper → deploy_stepup_flow → deploy_aws_saml_federation
     │    (**4 bước Keycloak Admin API/SAML nằm SAU deploy_crapi** vì `keycloak-opa-authz` fail-closed cần OPA OpenStack đã có;
     │     nếu chạy trước → Envoy Keycloak trả 403. Mỗi bước chỉ in OK khi thật sự thành công)
     ├─ deploy_observability_response  (Vault, Loki, Grafana + datasource/dashboard/alerting, Promtail 2 cluster,
     │    incident-analyzer + MailHog SOC, Prometheus mesh-injected)
     ├─ apply_policies_and_ingress  →  verify_final
     Lưu ý vận hành: `deploy-crapi.sh` đứng trước observability và `fail` khi mesh không thông ⇒ MỘT lỗi tầng app làm cả
     pipeline dừng và stack quan sát không được dựng — nguyên nhân cụm từng "thiếu Loki/Grafana/Prometheus" (H8).
14 Seed + mở UI  (scripts/open-admin-uis.sh — port-forward)
```

### 8.2 Luồng đăng nhập người dùng

```
Trình duyệt/curl (client cert đã cài, vd scripts/issue-device-cert.sh testuser01 compliant)
  → https://crapi.ztlab.local:8443/login  (NodePort thật; :18444 khi qua tunnel dev open-admin-uis.sh)
  → Istio IngressGateway: TLS handshake + Gateway CR tls.mode: MUTUAL → verify cert bằng Device CA
      (không cert/cert sai CA/hết hạn → không tới được waf/bff; cert BỊ THU HỒI vẫn qua TLS — BFF chặn thao tác GHI, đọc vẫn đi qua, xem dưới)
  → Lua EnvoyFilter ở Gateway gắn x-device-cert-info (Subject/URI cert đã verify) + x-edge-scheme:https
  → waf (STRICT mТLS, chỉ nhận từ edge-gateway; ModSecurity CRS DetectionOnly — log nếu khớp rule, không chặn;
      Lua EnvoyFilter thứ 2 xoá x-device-cert-info nếu peer KHÔNG phải edge-gateway) → mТLS thật (waf-opa-authz) → bff
  → BFF /auth/start: sinh state + PKCE verifier/challenge → 302 tới /kc/realms/ztlab/protocol/openid-connect/auth?client_id=crapi-bff&code_challenge=…
  → (BFF proxy) → Keycloak (OpenStack, STRICT mТLS trong mesh — Phần 1.2, qua keycloak-openstack:30091): render trang login "ZTLab"
  → POST username/password → /kc/realms/ztlab/login-actions/authenticate
  → Keycloak 302 → BFF /auth/callback?code=…&state=…  (redirect_uri dùng _external_base — x-edge-scheme:https)
  → BFF: verify state → POST /kc/…/token (grant authorization_code + code_verifier) → nhận Keycloak access/id/refresh token
  → BFF: _evaluate_device_cert (đọc x-device-cert-info đã verify — đáng tin vì Lua filter waf's inbound chỉ giữ header này
      khi mТLS peer đúng edge-gateway, KHÔNG dùng bí mật chia sẻ nào) → device_id + posture → KIỂM device_id có trong
      ConfigMap device-revocation-list không (Phần 3.2) → device_trust: trusted/suspicious
  → BFF: tạo session Redis {username, email, roles, acr, keycloak access_token, device_id, device_trust, posture,
      crapi_token(mint RS256)} → Set-Cookie ztlab_bff_session
  → audit event=user_login → Loki (job=bff-audit)
  → 302 → BFF /  → proxy crapi-web (SPA crAPI load)
```
> Cổng debug `kubectl port-forward` thẳng `waf`/`bff` (`scripts/open-admin-uis.sh`, mục "debug — bo qua TLS/OPA")
> vẫn tồn tại để test nhanh không cần cài client cert — đó là đường **bỏ qua toàn bộ mТLS/OPA HOÀN TOÀN** (đòi
> kubeconfig của cụm), không phải luồng Zero-Trust thật; kịch bản test chính thức (`tests/crapi_*.sh`) đi qua
> Gateway mТLS (`:18444` tunnel dev / `:8443` NodePort thật).

### 8.3 Luồng request Đông–Tây (bff → crapi-workshop, có mТLS + OPA + RBAC)

```
Trình duyệt: GET /workshop/api/shop/products  (cookie ztlab_bff_session)
  → https://crapi.ztlab.local:8443 (NodePort thật; :18444 tunnel dev) → Istio IngressGateway
    (verify client cert lại — mỗi request, không chỉ lúc login, Gateway CR tls.mode: MUTUAL)
    → waf (CRS DetectionOnly, không match rule nào cho request GET thường) → mТLS thật → bff
      (giống hệt hop biên ở §8.2 — chỉ viết tắt ở đây, xem §8.2 cho chi tiết Gateway/waf)
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
| Device CA / client-cert mTLS (Phần 1.3) | ECDSA P-256, 10y; entrypoint `https://crapi.ztlab.local:8443` NodePort thật (`k8s/crapi/edge-gateway.yaml`, Istio Gateway `tls.mode: MUTUAL`); posture ở `Subject OU=posture:<x>`; phát hành: `scripts/issue-device-cert.sh <id> <compliant\|non-compliant>`; thu hồi: `scripts/revoke-device-cert.sh <id>` (denylist ở BFF: chặn hành động GHI, đọc vẫn qua; hiệu lực sau 16–64s khi ConfigMap tới pod, không cần restart; verify `tests/crapi_cert_revocation.sh` PASS=7 — 2026-09-26) |
| OPA inbound (Phần 1.2) | Cổng 9191 (ext_authz thật): STRICT mТLS + `AuthorizationPolicy opa-inbound-allow` (action: ALLOW, 6 SPIFFE ID đo trực tiếp từ traffic thật). Cổng 8181 (REST/health): PERMISSIVE có chủ đích (security-healthcheck CronJob không vào mesh) nhưng chỉ GET /health, mọi method/path khác 403. |
| Port-forward (open-admin-uis.sh) | crAPI Gateway mТLS thật :18444 · debug bypass WAF :18081 · debug bypass BFF :18083 · Keycloak :8180 · Grafana :3000 · Loki :13100 · Incident Analyzer :8091 · Prometheus :9090 · MailHog crAPI :8025 · MailHog SOC :8026 |
| Sensitive actions (step-up) | POST `/workshop/api/shop/orders`, `…/return_order`, `/identity/api/v2/user/reset-password`, `…/change-email` |
| Admin paths (chỉ crapi-admin) | `/identity/api/v2/admin`, `/workshop/api/management` |

---

## 10. VẬN HÀNH & SỰ CỐ ĐÃ BIẾT

### 10.1 Kiểm tra sức khoẻ

- `bash scripts/health-check.sh` — kỳ vọng `FAIL=0` (WARN chấp nhận: `.env.ai missing`, remote SSH skipped).
- `python3 tests/test_service_graph_consistency.py` — `4/4 PASS` (service-graph = nguồn sự thật; gồm test cổng egress baseline).
- `python3 tests/verify_telemetry_pipeline.py` — nghiệm thu pipeline telemetry đầu-cuối (Loki theo job × cloud, Prometheus targets, Grafana datasource, rule Firing + evidence bundle); kỳ vọng 13/13.
- `bash tests/netpol_matrix.sh` (22 ô) và `bash tests/netpol_podselector_probe.sh <ctx>` — đo hiệu lực NetworkPolicy thật (kết quả thô `results/round3/`).
- `bash tests/crapi_cert_revocation.sh` — kịch bản thu hồi cert (tự hoàn nguyên trong `trap`).
- `python3 tests/perf_overhead.py` — overhead mТLS+OPA (client chạy TRONG container ứng dụng `bff`, KHÔNG phải curl trong `istio-proxy`; xem §10.2 và `HAN-CHE` H6).
- `bash tests/crapi_run_all.sh` — 7 kịch bản tấn công, kỳ vọng `PASS=7 FAIL=0` (đạt 2026-09-26 sau khi dựng đủ stack quan sát; `results/round3/crapi_run_all-1.log`), chạy thật qua `https://crapi.ztlab.local:18443` (client cert `compliant`); sau đó kiểm Grafana (Firing) + email evidence bundle ở MailHog SOC (`:8026`) — **không** còn "SOAR `/cases`" (A4 đã bỏ endpoint đó).
- **A5.2:** `SCENARIO=... TARGET_ENTITY=... bash tests/crapi_run_campaign.sh crapi_bola.sh` — chạy 1 kịch bản có gắn nhãn, ghi 1 dòng JSON vào `tests/runs.jsonl` (gitignored) để join với Loki sau này theo `(target_entity, [t_start,t_end])`.

### 10.2 Sự cố đã biết + cách xử lý

| Triệu chứng | Nguyên nhân | Xử lý |
|---|---|---|
| `security-healthcheck` CronJob `Error` ngay lúc cụm mới dựng (OPA/Loki chưa có → `status=critical opa=000000`) | Startup race: healthcheck chạy trước khi OPA/Loki được deploy; các pod `Error` cũ vẫn nằm trong danh sách vài chục phút | Vô hại về sau (log `healthy opa=200 loki_push=204` từ phút kế tiếp). CronJob retry curl OPA 3 lần (2026-09-13). *Nguyên nhân cũ "kube-router chậm cập nhật ipset" đã bị bác bỏ (AUDIT §3.1).* |
| Toàn bộ crapi 2-cloud **503**, `svid:null` trong access log | Uplink host `aio` (hotspot điện thoại) drop NAT'd UDP → DNS(8.8.8.8) + WireGuard chết → SPIRE agent không attest → SVID hết hạn → mТLS STRICT sập | **Runbook §10.3**. Đã hạ rủi ro: DNS→1.1.1.1, coredns-custom, wg-watchdog, spire-agent `IfNotPresent`. |
| `bff → workshop` 502 `response_time=20000` | mТLS/SDS chưa settle sau restart (istio-proxy không tự tái lập SDS — Istio 1.22.3 + SPIRE 1.9.4) | `kubectl -n crapi rollout restart deploy` (thứ tự: identity OS → AWS). `deploy-crapi.sh::restart_workloads_for_sds` làm sẵn cuối deploy. |
| `ensure-spire-entries.sh` timeout `error: timed out waiting for the condition` ở bước register SPIRE entries | Một `spire-agent` pod (thường OpenStack, node yếu/uplink hotspot) đôi khi cần hơn 180s để attest xong dù rollout vẫn tiến triển bình thường | **ĐÃ FIX (2026-09-13):** `wait_rollout()` retry lần 2 (tổng 2×180s) trước khi fail thật. |
| Login Keycloak báo "username phải là email" | Đang ở form login GỐC của crapi-web SPA (không dùng được — BFF chặn `/identity/*` chưa có phiên) | Vào `https://crapi.ztlab.local:18443/login` (form Keycloak, cần client cert — §4.8) hoặc tunnel dev `http://localhost:18081/login` (bỏ qua Traefik, không cần cert). Username hoặc email đều được. |
| `k8s-tunnel` chết giữa chừng | SSH qua bastion không ổn định / nhiều kết nối song song | `bash scripts/k8s-tunnel.sh down all && up all` |
| `waf → bff` 503 `delayed connect error: 111`, pod Ready 2/2, không có decision log OPA | NetworkPolicy: egress baseline `podSelector: {}` thiếu cổng đích (từng là 8080) ⇒ kube-router `reject` SYN ở chain firewall của POD NGUỒN | Đọc `sudo nft -a list ruleset \| grep reject` trên node, xem counter `reject` nào tăng và thuộc `KUBE-POD-FW-*` của pod nào; cổng egress nay sinh từ service-graph (`gen-networkpolicy.py`). **Không** cài `ipset`, không restart k3s. |
| Target Prometheus `connection reset by peer` | Prometheus không có sidecar (nhãn `istio-injection` bị ghi đè khi `apply` một object Namespace không nhãn) gọi workload STRICT bằng plaintext | Nhãn khai ở `k8s/namespaces.yaml`; Namespace không được khai lại ở file khác |
| Kiểm tra bằng `curl` trong container `istio-proxy` báo `connection reset by peer` tới workload STRICT | `istio-proxy` chạy uid 1337, iptables `-m owner --uid-owner 1337 -j RETURN` ⇒ traffic KHÔNG qua Envoy client ⇒ plaintext bị STRICT mTLS reset | Kiểm từ container ứng dụng (uid ≠ 1337). Chỉ dùng `istio-proxy` khi cố ý đo L4 |
| Terraform OpenStack: VM kẹt BUILD 30 phút rồi `ERROR` — fault `MessagingTimeout` ở `nova/conductor ... select_destinations` (2026-10-04) | Máy AIO khởi động với đồng hồ lệch +7 h (RTC bị ghi giờ địa phương — dual-boot — Linux đọc là UTC); toàn bộ container Kolla khởi động trong lúc đó, rồi chrony bước lùi 25 199 s → nova-scheduler câm. `compute service list` vẫn báo `up` (heartbeat chạy) nên không lộ ra | `scripts/openstack-aio-preflight.sh` (deploy-all bước 6): phát hiện container có `StartedAt` ở tương lai → restart theo thứ tự phụ thuộc (keepalived/haproxy → mariadb/rabbitmq → keystone → nova → neutron), rồi **tạo VM thử `--nic none`** và đòi ACTIVE. Phòng ngừa tận gốc trên host: `timedatectl set-local-rtc 0` ở cả hai OS hoặc đặt Windows dùng RTC UTC |
| Mất toàn bộ AWS: SSH bastion/gateway timeout, WireGuard 0 B, `aws sts` → `InvalidClientTokenId` (2026-09-30 03:16) | Mất quyền truy cập cấp tài khoản AWS (khoá bị vô hiệu phía AWS); nguyên nhân phía AWS không xác minh được từ repo; `.env` không bị track | Ngoài phạm vi kỹ thuật của repo: chuyển tài khoản, `deploy-all.sh` từ trống. Đợt thu Giai đoạn B chịu được nhờ thu chia khúc (`tests/collect_chunked.py`) |
| Rule Grafana `Security Control-Plane Down` firing dù healthcheck healthy | Query chỉ đếm `status="critical"` + `noDataState: Alerting` | Đã sửa 2026-09-26 (`or vector(0)`, `noDataState: OK`) |
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
# 5. Workload — TUẦN TỰ, KHÔNG restart nhiều deployment cùng lúc (Phần 1.1
#    remediation 2026-09-19): restart đồng thời
#    nhiều workload là đúng điều kiện đã kích hoạt sự cố mesh-connectivity
#    thật (bản chẩn đoán cũ "NetworkPolicy podSelector/ipset" đã bị bác bỏ,
#    xem §4.4 và AUDIT §3; restart tuần tự vẫn là thực hành tốt vì SDS/SVID). Dùng đúng vòng lặp tuần tự của
#    scripts/deploy-crapi.sh::restart_workloads_for_sds thay vì liệt kê
#    nhiều deployment trong 1 lệnh:
for d in opa-server crapi-identity mailhog; do
  kubectl --context ctx-openstack -n crapi rollout restart "deploy/$d"
  kubectl --context ctx-openstack -n crapi rollout status "deploy/$d" --timeout=240s
done
for d in opa-server bff crapi-web crapi-community crapi-workshop; do
  kubectl --context ctx-aws -n crapi rollout restart "deploy/$d"
  kubectl --context ctx-aws -n crapi rollout status "deploy/$d" --timeout=240s
done
# 6. Verify: login testuser01/Test1234! ở /login → GET /workshop/api/shop/products = 200
#    (KHÔNG chỉ tin `kubectl get pods` Ready — xác nhận sống 2026-09-19: pod
#    có thể Ready trong khi kết nối thật giữa 2 service vẫn đứt hoàn toàn,
#    xem verify_mesh_connectivity trong scripts/deploy-crapi.sh)
```

---

## 11. TRẠNG THÁI HIỆN TẠI (2026-10-04, đóng sổ giai đoạn hạ tầng) & VIỆC CÒN LẠI

**Nguồn duy nhất cho trạng thái và số liệu chốt: `SAN-SANG-GIAI-DOAN-B.md`** (bảng đóng sổ, dữ liệu thô `results/closeout/`). Tóm tắt:
- Hạ tầng dựng **từ trống** trên mã hiện tại (2026-10-04), 0 FAIL; nghiệm thu stack quan sát + mesh ở cuối deploy (H8).
- Thu thập chia khúc (`tests/collect_chunked.py`) nghiệm thu sống; deny lành tính 0/7406 quyết định trong 60 phút, 0 bundle → **GO Giai đoạn B**.
- TTL SVID 4 h; đĩa node Loki 100 GB (retention 720 h); CRS/BOLA đo lại trên BOLA thành công thật (H18).
- L4: *"L4 chặn nguồn ngoài namespace và egress cross-cloud; phân đoạn nội namespace do L7 (mTLS + PDP) đảm nhiệm"* — `PHAT-HIEN-PHAN-DOAN-L4.md`.
- Thu hồi cert: *"chặn thao tác ghi; thao tác đọc vẫn đi qua"* (H4).
- Quan sát của hệ thống dựa trên **log** (Loki); Prometheus còn 3 target và không phải trụ cột phát hiện.
- Độ trễ: thành phần PDP p99 4,37 ms (AWS) trên lưu lượng thật; overhead đầu-cuối chưa chứng minh đạt 20 ms p99 — đo trong Giai đoạn B.

**Còn hở / hạn chế:** `HAN-CHE-VA-HUONG-PHAT-TRIEN.md` (H1…H18) và `SAN-SANG-GIAI-DOAN-B.md` mục 5.

**Giai đoạn B (sinh dữ liệu) / C (ML):** bắt đầu từ trạng thái này; endpoint `POST /evidence/{id}/risk-score` ở incident-analyzer đã chừa sẵn.

---

---
*Cập nhật lần cuối: 2026-10-04 (đóng sổ giai đoạn hạ tầng). Nguồn: repo `feat/root-cause-remediation` + đo trên cụm dựng từ trống (`results/closeout/`).*
