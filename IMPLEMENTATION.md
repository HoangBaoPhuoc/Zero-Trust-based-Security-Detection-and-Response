# IMPLEMENTATION GUIDE
## Zero Trust-Based Security Detection and Response System for Microservices in Multi-Cloud Environments

> **Project:** Đồ án chuyên ngành — UIT  
> **Students:** Hoàng Bảo Phước (23521231) · Phạm Võ Khánh Hà (23520414)  
> **Supervisor:** Đỗ Thị Phương Uyên  
> **Timeline:** 05/02/2026 → 30/05/2026

---

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Infrastructure Layout — Multi-Cloud (AWS + OpenStack)](#2-infrastructure-layout--multi-cloud-aws--openstack)
3. [Phase 0 — WireGuard Site-to-Site VPN Setup](#3-phase-0--wireguard-site-to-site-vpn-setup)
4. [Phase 1 — Identity Foundation: SPIFFE/SPIRE](#4-phase-1--identity-foundation-spiffespire)
5. [Phase 2 — Policy Enforcement: Envoy Proxy + OPA + Keycloak](#5-phase-2--policy-enforcement-envoy-proxy--opa--keycloak)
6. [Phase 3 — Financial Microservices on K3s](#6-phase-3--financial-microservices-on-k3s)
7. [Phase 4 — Log Collection & SIEM (PLG Stack: Promtail + Loki + Grafana)](#7-phase-4--log-collection--siem-plg-stack-promtail--loki--grafana)
8. [Infrastructure as Code (Terraform + Ansible)](#8-infrastructure-as-code-terraform--ansible)
9. [Monitoring Dashboards & Grafana Configuration](#9-monitoring-dashboards--grafana-configuration)
10. [Security Testing Scenarios (MITRE ATT&CK)](#10-security-testing-scenarios-mitre-attck)
11. [Network & Port Reference](#11-network--port-reference)
12. [Environment Variables & Secrets Reference](#12-environment-variables--secrets-reference)

---

## 1. System Architecture Overview

### 1.1 Network Zone Model (4-Zone Architecture)

Toàn bộ hạ tầng được phân thành 4 vùng mạng cứng, áp dụng **tại cả AWS (Security Groups) lẫn OpenStack (Neutron Security Groups)**. Không có vùng nào được phép communicate trực tiếp với vùng không liền kề — traffic phải đi qua vùng trung gian.

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                                      INTERNET                                             │
└─────────────────────────────────┬─────────────────────────────────────────────────────────┘
                                  │ UDP 51820 (WireGuard) + TCP 443 only
                                  ▼
╔═══════════════════════════════════════════════════════════════════════════════════════════╗
║  [1] DMZ ZONE   ·  AWS Subnet 10.10.0.0/24  +  OpenStack os-gateway                     ║
║  ┌──────────────────┐  ┌───────────────────┐  ┌────────────────────────────────────┐    ║
║  │  aws-gateway     │  │  api-gateway pod  │  │  auth-portal / Keycloak            │    ║
║  │  WG Server · EIP │  │  Envoy entry point│  │  OIDC/OAuth2 · public HTTPS only   │    ║
║  └──────────────────┘  └───────────────────┘  └────────────────────────────────────┘    ║
║  ┌────────────────────────────────────────────────────────────────────────────────────┐  ║
║  │  os-gateway  (OpenStack)  ·  WG Client · NAT-only · no direct service             │  ║
║  └────────────────────────────────────────────────────────────────────────────────────┘  ║
╚═══════════════════════════════════════════════════════════════════════════════════════════╝
              │ inbound TCP 8080/443 from DMZ only · deny all else
              ▼
╔═══════════════════════════════════════════════════════════════════════════════════════════╗
║  [2] PRIVATE ZONE  ·  AWS 10.10.1.0/24  +  OpenStack 10.10.4.0/24, 10.10.5.0/24        ║
║                                                                                           ║
║  AWS K3s cluster                          OpenStack K3s cluster                          ║
║  ┌──────────────────────────────────┐    ┌────────────────────────────────────────────┐  ║
║  │ api-gateway-svc  payment-svc     │    │ core-banking  account-svc  txn-svc         │  ║
║  │ fraud-detection  notification    │    │ os-identity (SPIRE Agent)                  │  ║
║  │ Envoy+OPA sidecar on every pod   │◄──►│ Envoy+OPA sidecar on every pod             │  ║
║  └──────────────────────────────────┘    └────────────────────────────────────────────┘  ║
║  SPIRE Server · Prometheus · SPIRE Agents (all nodes, both clouds)                       ║
╚═══════════════════════════════════════════════════════════════════════════════════════════╝
              │ log traffic only — TCP 3100 (Loki) inbound to Restricted
              ▼
╔═══════════════════════════════════════════════════════════════════════════════════════════╗
║  [3] RESTRICTED ZONE  ·  AWS 10.10.2.0/24  (NO internet inbound)                        ║
║                                                                                           ║
║  ┌──────────────────────────────────────────────────────────────────────────────────┐    ║
║  │  aws-siem                                                                        │    ║
║  │  Loki    :3100  — nhận log từ tất cả Promtail agents (AWS + OpenStack qua WG)    │    ║
║  │  Grafana :3000  — dashboard, LogQL queries, alerting rules                       │    ║
║  └──────────────────────────────────────────────────────────────────────────────────┘    ║
╚═══════════════════════════════════════════════════════════════════════════════════════════╝
              │ SSH via bastion only · Ansible/Terraform API calls
              ▼
╔═══════════════════════════════════════════════════════════════════════════════════════════╗
║  [4] MANAGEMENT ZONE  ·  Bastion-gated  ·  No direct internet access                    ║
║  ┌──────────────────┐  ┌────────────────────────┐  ┌──────────────────────────────────┐ ║
║  │  Bastion host    │  │  Ansible runner         │  │  Terraform state (S3 + DynamoDB) │ ║
║  │  SSH jump host   │  │  Config management      │  │  IaC drift detection             │ ║
║  └──────────────────┘  └────────────────────────┘  └──────────────────────────────────┘ ║
╚═══════════════════════════════════════════════════════════════════════════════════════════╝

WireGuard Tunnel (10.10.0.0/24) spans DMZ ↔ OpenStack — encrypted at all times
Promtail trên OpenStack nodes push log qua WireGuard tunnel → Loki trên aws-siem
```

### 1.2 Log Collection Flow (PLG Stack)

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│  Log Sources (trên mọi node — AWS & OpenStack)                                      │
│                                                                                     │
│  /var/log/envoy/access.log      ← Envoy sidecar — JSON per request                 │
│  /var/log/opa/decisions.json    ← OPA sidecar  — JSON per policy decision          │
│  /var/log/syslog                ← System log  — auditd, kernel, auth               │
└──────────────────────────────────┬──────────────────────────────────────────────────┘
                                   │
                             Promtail agent
                    (cài trên từng node, đọc file log,
                     parse JSON, gán labels, push HTTP)
                                   │
                     (AWS nodes: local push)
                     (OS nodes: push qua WireGuard tunnel)
                                   │
                                   ▼
                    ┌──────────────────────────┐
                    │  Loki  (aws-siem:3100)    │
                    │  Kho lưu trữ log trung tâm│
                    │  Index bằng labels, không │
                    │  full-text index toàn bộ  │
                    └──────────────┬───────────┘
                                   │
                                   ▼
                    ┌──────────────────────────┐
                    │  Grafana (aws-siem:3000)  │
                    │  - Dashboard visualization│
                    │  - LogQL queries          │
                    │  - Alert rules            │
                    └──────────────────────────┘
```

### 1.3 Inter-Zone Traffic Rules

| From → To | Allowed Traffic | Denied |
|-----------|----------------|--------|
| Internet → DMZ | UDP 51820 (WG), TCP 443 | Everything else |
| DMZ → Private | TCP 8080, 443 (app traffic) | Direct DB, SIEM access |
| Private → Restricted | TCP 3100 (Promtail → Loki) | Inbound from Restricted to Private |
| Restricted → Private | TCP 6443 (K3s API — admin only) | General inbound |
| Management → All | SSH TCP 22 (from bastion only) | No inbound from other zones |
| OpenStack → Restricted | Via WG tunnel: 3100 (Loki) | Direct internet path |

### 1.4 Component Role Summary

| Component | Cloud | Role |
|-----------|-------|------|
| WireGuard Gateway AWS | AWS | VPN Server, Public IP/EIP |
| WireGuard Gateway OS | OpenStack | VPN Client, NAT-only |
| SPIRE Server | AWS | SVID issuance for all workloads |
| Keycloak | AWS | OIDC/OAuth2 Identity Provider |
| OPA | Both (sidecar) | Policy Decision Point |
| Envoy Proxy | Both (sidecar) | Policy Enforcement Point, mTLS |
| **Promtail** | **All nodes** | **Log collector — scrape & push to Loki** |
| **Loki** | **AWS** | **Log storage — label-based index, LogQL** |
| **Grafana** | **AWS** | **Dashboard, visualization, alerting** |

---

## 2. Infrastructure Layout — Multi-Cloud (AWS + OpenStack)

### 2.1 AWS Node Inventory (by Zone)

**[DMZ Zone] — Subnet: 10.10.0.0/24**

| Hostname | Instance Type | Private IP | Public IP | Services |
|----------|--------------|------------|-----------|----------|
| `aws-gateway` | t3.small | 10.10.0.1 | EIP (static) | WireGuard :51820, NAT gateway |

**[Private Zone] — Subnet: 10.10.1.0/24**

| Hostname | Instance Type | Private IP | Services |
|----------|--------------|------------|----------|
| `aws-k3s-master` | t3.medium | 10.10.1.10 | K3s control plane :6443 |
| `aws-k3s-worker-1` | t3.medium | 10.10.1.11 | K3s worker — Payment, Fraud |
| `aws-k3s-worker-2` | t3.medium | 10.10.1.12 | K3s worker — API GW, Notification |
| `aws-security` | t3.medium | 10.10.1.20 | SPIRE Server :8081, Keycloak :8080 |

**[Restricted Zone] — Subnet: 10.10.2.0/24**

| Hostname | Instance Type | Private IP | Services |
|----------|--------------|------------|----------|
| `aws-siem` | t3.medium | 10.10.2.10 | Loki :3100, Grafana :3000 |

> **Tại sao chỉ cần 1 node cho SIEM?** PLG Stack có footprint nhẹ hơn ELK rất nhiều. Loki không full-text index toàn bộ log content — chỉ index labels — nên RAM usage thấp hơn Elasticsearch từ 5–10×. Grafana và Loki trên cùng 1 node `t3.medium` là đủ cho workload lab.

**[Management Zone] — Bastion-gated**

| Hostname | Instance Type | Private IP | Services |
|----------|--------------|------------|----------|
| `aws-bastion` | t3.micro | 10.10.4.10 | SSH jump host — only node with port 22 open from internet |

> **Note:** IaC runner (Terraform + Ansible) chạy trực tiếp từ máy Ubuntu của deployer. Không cần instance riêng trong lab single-operator.

### 2.2 OpenStack Node Inventory (by Zone)

OpenStack sử dụng **3 provider networks tách biệt** theo zone. `os-gateway` là node duy nhất có interface trên cả 3 networks — đóng vai trò edge router, nhận internet traffic đầu tiên và route vào private/identity network bên trong.

```
Internet / AWS WireGuard
        │
        ▼
┌─────────────────────────────────────────────────┐
│  os-net-dmz  192.168.100.0/24                   │  ← provider network 1
│                                                  │
│  os-gateway (MULTI-HOMED)                        │
│    eth0: 192.168.100.10  (DMZ — internet-facing) │
│    eth1: 192.168.101.1   (gateway vào private)   │
│    eth2: 192.168.102.1   (gateway vào identity)  │
└─────────┬──────────────────────┬─────────────────┘
          │                      │
          ▼                      ▼
┌──────────────────┐   ┌──────────────────────────┐
│ os-net-private   │   │ os-net-identity           │
│ 192.168.101.0/24 │   │ 192.168.102.0/24          │
│                  │   │                            │
│ os-k3s-master    │   │ os-identity               │
│  .10             │   │  .10                       │
│ os-k3s-worker-1  │   │ (SPIRE Agent only)        │
│  .11             │   └──────────────────────────┘
│ os-k3s-worker-2  │
│  .12             │
└──────────────────┘
```

**[DMZ Zone] — os-net-dmz: 192.168.100.0/24**

| Hostname | Flavor | Interface | IP | WG Tunnel IP | Services |
|----------|--------|-----------|-----|--------------|----------|
| `os-gateway` | m1.medium | eth0 (DMZ) | 192.168.100.10 | 10.10.0.2 | WireGuard client, edge router, NAT |
| `os-gateway` | — | eth1 (Private GW) | 192.168.101.1 | — | Gateway cho private network |
| `os-gateway` | — | eth2 (Identity GW) | 192.168.102.1 | — | Gateway cho identity network |

> `os-gateway` được attach vào cả 3 networks. Trong OpenStack: tạo port trên từng network rồi attach vào instance.

**[Private Zone] — os-net-private: 192.168.101.0/24**

| Hostname | Flavor | Interface | IP | WG Tunnel IP | Services |
|----------|--------|-----------|-----|--------------|----------|
| `os-k3s-master` | m1.medium | eth0 | 192.168.101.10 | 10.10.4.10 | K3s control plane |
| `os-k3s-worker-1` | m1.medium | eth0 | 192.168.101.11 | 10.10.4.11 | Core Banking, Account Service |
| `os-k3s-worker-2` | m1.medium | eth0 | 192.168.101.12 | 10.10.4.12 | Transaction Service |

**[Identity Zone] — os-net-identity: 192.168.102.0/24**

| Hostname | Flavor | Interface | IP | WG Tunnel IP | Services |
|----------|--------|-----------|-----|--------------|----------|
| `os-identity` | m1.small | eth0 | 192.168.102.10 | 10.10.5.10 | SPIRE Agent — isolated network |

### 2.2.1 OpenStack Ansible Connectivity — Bootstrap Problem & Solution

**Vấn đề:** Không có floating IP, vòng tròn phụ thuộc:
- Ansible cần SSH vào VM để cài WireGuard
- WireGuard phải chạy trước thì tunnel mới up
- VM không có floating IP nên không reach từ ngoài

**Kiến trúc thực tế (Kolla AIO + 3 Provider networks):**

```
aio deployer machine
  │
  ├── br-provider ──── os-net-dmz (192.168.100.0/24)
  │     └── gán 192.168.100.1/24 vào br-provider → reach os-gateway eth0
  │
  │   os-gateway có 3 interfaces:
  │     eth0: 192.168.100.10 (DMZ)       ← reachable sau khi gán br-provider IP
  │     eth1: 192.168.101.1  (Private GW) ← route qua eth0 của os-gateway
  │     eth2: 192.168.102.1  (Identity GW)← route qua eth0 của os-gateway
  │
  ├── Sau khi có route:
  │     192.168.101.0/24 via 192.168.100.10 → reach private nodes
  │     192.168.102.0/24 via 192.168.100.10 → reach identity node
```

**Giải pháp từng bước:**

```bash
# ── Bước 1: Xác định bridge provider ─────────────────────────
sudo ovs-vsctl show | grep -A3 "br-provider\|br-ex"
# Hoặc Linux bridge:
brctl show | grep provider

# ── Bước 2: Gán IP vào br-provider (DMZ subnet) ──────────────
sudo ip addr add 192.168.100.1/24 dev br-provider
ip addr show br-provider   # verify

# ── Bước 3: Test ping os-gateway trước ───────────────────────
ping -c 2 192.168.100.10
# Nếu ping được → tiếp tục bước 4
# Nếu không → kiểm tra SG port 22 mở chưa (bước 5 trước)

# ── Bước 4: Thêm route đến private và identity qua os-gateway ─
sudo ip route add 192.168.101.0/24 via 192.168.100.10
sudo ip route add 192.168.102.0/24 via 192.168.100.10

# Verify
ip route get 192.168.101.10   # → via 192.168.100.10
ip route get 192.168.102.10   # → via 192.168.100.10

# ── Bước 5: Mở SSH trong OpenStack Security Groups ───────────
source /etc/kolla/zta-siem-soar-openrc.sh
AIO_IP="192.168.100.1"

openstack security group rule create neutron-sg-os-dmz \
  --protocol tcp --dst-port 22 \
  --remote-ip ${AIO_IP}/32 --direction ingress \
  --description "SSH from aio - bootstrap"

openstack security group rule create neutron-sg-os-private \
  --protocol tcp --dst-port 22 \
  --remote-ip ${AIO_IP}/32 --direction ingress \
  --description "SSH from aio - bootstrap"

openstack security group rule create neutron-sg-os-identity \
  --protocol tcp --dst-port 22 \
  --remote-ip ${AIO_IP}/32 --direction ingress \
  --description "SSH from aio - bootstrap"

# ── Bước 6: Test SSH vào từng node ───────────────────────────
ssh -i ~/.ssh/ztlab.pem ubuntu@192.168.100.10  # os-gateway (DMZ)
ssh -i ~/.ssh/ztlab.pem ubuntu@192.168.101.10  # os-k3s-master (Private)
ssh -i ~/.ssh/ztlab.pem ubuntu@192.168.102.10  # os-identity
```

---

## 3. Phase 0 — WireGuard Site-to-Site VPN Setup

*(Phần này giữ nguyên từ bản gốc — WireGuard config không thay đổi)*

### 3.1 Mục đích

WireGuard tạo tunnel layer-3 mã hóa giữa `aws-gateway` (EIP) và `os-gateway` (NAT). Tất cả cross-cloud traffic — bao gồm log Promtail từ OpenStack → Loki trên AWS — đều đi qua tunnel này.

### 3.2 AWS Gateway Config

**File:** `wireguard/aws-gateway.conf`

```ini
[Interface]
Address    = 10.10.0.1/24
ListenPort = 51820
PrivateKey = <AWS_GATEWAY_PRIVATE_KEY>
PostUp     = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown   = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# os-gateway
PublicKey  = <OS_GATEWAY_PUBLIC_KEY>
AllowedIPs = 10.10.0.2/32, 192.168.100.0/24, 192.168.101.0/24, 192.168.102.0/24
```

### 3.3 OpenStack Gateway Config

**File:** `wireguard/os-gateway.conf`

```ini
[Interface]
Address    = 10.10.0.2/24
PrivateKey = <OS_GATEWAY_PRIVATE_KEY>

[Peer]
# aws-gateway
PublicKey  = <AWS_GATEWAY_PUBLIC_KEY>
Endpoint   = <AWS_EIP>:51820
AllowedIPs = 10.10.0.1/32, 10.10.1.0/24, 10.10.2.0/24, 10.10.3.0/24
PersistentKeepalive = 25
```

### 3.4 Verify Tunnel

```bash
# Trên aws-gateway
sudo wg show

# Expected output:
# peer: <OS_PUBLIC_KEY>
#   endpoint: <OS_PUBLIC_IP>:XXXXX
#   allowed ips: 10.10.0.2/32, 192.168.100.0/24, ...
#   latest handshake: X seconds ago
#   transfer: Xmb received, Xmb sent

# Test connectivity
ping -c 3 10.10.0.2           # os-gateway WG IP
ping -c 3 192.168.101.10      # os-k3s-master (via os-gateway routing)
```

---

## 4. Phase 1 — Identity Foundation: SPIFFE/SPIRE

*(Phase này giữ nguyên — SPIRE không thay đổi)*

### 4.1 Mục đích

SPIRE cấp phát SPIFFE Verifiable Identity Documents (SVIDs) — X.509 certificates — cho mọi workload. OPA và Envoy dùng SVID để xác thực workload identity thay vì IP address.

### 4.2 SPIRE Server Config

**File:** `spire/server/server.conf`

```hcl
server {
  bind_address = "0.0.0.0"
  bind_port    = "8081"
  trust_domain = "ztlab.local"
  data_dir     = "/opt/spire/data/server"
  log_level    = "INFO"

  default_x509_svid_ttl = "1h"
  ca_ttl                = "168h"   # 7 days

  ca_subject {
    country      = ["VN"]
    organization = ["ZTLab"]
    common_name  = ""
  }
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type   = "sqlite3"
      connection_string = "/opt/spire/data/server/datastore.sqlite3"
    }
  }
  NodeAttestor "k8s_psat" {
    plugin_data {
      clusters = {
        "aws-k3s"  = { service_account_allow_list = ["spire:spire-agent"] }
        "os-k3s"   = { service_account_allow_list = ["spire:spire-agent"] }
      }
    }
  }
  KeyManager "memory" { plugin_data {} }
}
```

### 4.3 SPIRE Agent Config

**File:** `spire/agent/aws-agent.conf`

```hcl
agent {
  data_dir     = "/opt/spire/data/agent"
  log_level    = "INFO"
  trust_domain = "ztlab.local"
  server_address = "10.10.1.20"
  server_port  = "8081"
  socket_path  = "/run/spire/sockets/agent.sock"
}

plugins {
  NodeAttestor "k8s_psat" {
    plugin_data {
      cluster         = "aws-k3s"
      token_path      = "/var/run/secrets/tokens/spire-agent"
    }
  }
  KeyManager "memory" { plugin_data {} }
  WorkloadAttestor "k8s" {
    plugin_data {
      skip_kubelet_verification = true
    }
  }
}
```

### 4.4 Register Workload Entries

**File:** `spire/scripts/register-aws-workloads.sh`

```bash
#!/bin/bash
SPIRE_SERVER="spire-server"
NAMESPACE="spire"

# Register AWS services
kubectl exec -n $NAMESPACE $SPIRE_SERVER -- \
  spire-server entry create \
  -parentID spiffe://ztlab.local/spire/agent/k8s_psat/aws-k3s \
  -spiffeID spiffe://ztlab.local/aws/api-gateway \
  -selector k8s:ns:financial \
  -selector k8s:sa:api-gateway

kubectl exec -n $NAMESPACE $SPIRE_SERVER -- \
  spire-server entry create \
  -parentID spiffe://ztlab.local/spire/agent/k8s_psat/aws-k3s \
  -spiffeID spiffe://ztlab.local/aws/payment-service \
  -selector k8s:ns:financial \
  -selector k8s:sa:payment-service

kubectl exec -n $NAMESPACE $SPIRE_SERVER -- \
  spire-server entry create \
  -parentID spiffe://ztlab.local/spire/agent/k8s_psat/aws-k3s \
  -spiffeID spiffe://ztlab.local/aws/fraud-detection \
  -selector k8s:ns:financial \
  -selector k8s:sa:fraud-detection

kubectl exec -n $NAMESPACE $SPIRE_SERVER -- \
  spire-server entry create \
  -parentID spiffe://ztlab.local/spire/agent/k8s_psat/aws-k3s \
  -spiffeID spiffe://ztlab.local/aws/notification-service \
  -selector k8s:ns:financial \
  -selector k8s:sa:notification-service

echo "AWS workload entries registered."
```

---

## 5. Phase 2 — Policy Enforcement: Envoy Proxy + OPA + Keycloak

*(Phase này giữ nguyên — Zero Trust enforcement layer không thay đổi)*

### 5.1 Keycloak Realm Setup

```bash
# Deploy Keycloak trên aws-security node
kubectl apply -f k8s/keycloak/deployment.yaml
kubectl apply -f k8s/keycloak/service.yaml

# Import realm config
kubectl exec -n identity deploy/keycloak -- \
  /opt/keycloak/bin/kc.sh import --file /tmp/realm-config.json
```

**Realm config highlights** (`k8s/keycloak/realm-config.json`):
- Realm name: `ztlab`
- Clients: `api-gateway` (confidential), `payment-service` (service account)
- Roles: `financial-read`, `financial-write`, `security-admin`
- Access token TTL: 300s (5 min)
- Algorithm: RS256

### 5.2 OPA Policy

**File:** `opa/policies/zta_policy.rego`

```rego
package ztlab.authz

import future.keywords.if
import future.keywords.in

default allow := false

# ── Rule 1: Valid JWT from Keycloak ──────────────────────────
valid_jwt if {
    token := input.attributes.request.http.headers["authorization"]
    startswith(token, "Bearer ")
    jwt_payload := io.jwt.decode(substring(token, 7, -1))[1]
    jwt_payload.iss == "https://keycloak.ztlab.local/realms/ztlab"
    jwt_payload.exp > time.now_ns() / 1e9
}

# ── Rule 2: Valid SPIFFE SVID ────────────────────────────────
valid_svid if {
    input.source.principal != ""
    startswith(input.source.principal, "spiffe://ztlab.local/")
}

# ── Rule 3: Role-based action permission ─────────────────────
role_permits_action if {
    token := input.attributes.request.http.headers["authorization"]
    jwt_payload := io.jwt.decode(substring(token, 7, -1))[1]
    method := input.attributes.request.http.method
    some role in jwt_payload.realm_access.roles
    permissions[role][method]
}

permissions := {
    "financial-read":  {"GET": true},
    "financial-write": {"GET": true, "POST": true, "PUT": true},
    "security-admin":  {"GET": true, "POST": true, "PUT": true, "DELETE": true}
}

# ── Main allow rule ───────────────────────────────────────────
allow if {
    valid_jwt
    valid_svid
    role_permits_action
}
```

**File:** `opa/config/opa-config.yaml`

```yaml
services:
  - name: ztlab-bundle
    url: http://localhost:8888

bundles:
  ztlab:
    resource: /bundle.tar.gz
    polling:
      min_delay_seconds: 10
      max_delay_seconds: 20

decision_logs:
  plugin: file
  service: ""

plugins:
  file:
    path: /var/log/opa/decisions.json   # Promtail scrapes này
```

### 5.3 Envoy Sidecar Config

**File:** `envoy/envoy-sidecar.yaml`

```yaml
static_resources:
  listeners:
    - name: inbound
      address:
        socket_address: { address: 0.0.0.0, port_value: 15006 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: inbound_http
                access_log:
                  - name: envoy.access_loggers.file
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: /var/log/envoy/access.log     # Promtail scrapes này
                      log_format:
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
                          user_id:       "%REQ(X-USER-ID)%"
                          svid:          "%DOWNSTREAM_PEER_URI_SAN%"
                http_filters:
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      grpc_service:
                        envoy_grpc:
                          cluster_name: opa_authz
                      failure_mode_allow: false
                  - name: envoy.filters.http.jwt_authn
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
                      providers:
                        keycloak:
                          issuer: "https://keycloak.ztlab.local/realms/ztlab"
                          remote_jwks:
                            http_uri:
                              uri: "https://keycloak.ztlab.local/realms/ztlab/protocol/openid-connect/certs"
                              cluster: keycloak
                              timeout: 5s
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

### 5.4 Gap Fix — OPA: Enforce Fraud Gate Header (Gap 2)

**File:** `opa/policies/fraud_gate.rego`

```rego
package ztlab.authz

# ── Gap 2 Fix: Enforce mandatory fraud gate on Core Banking ──
# Any request from payment-service to core-banking MUST carry
# X-Fraud-Gate: passed AND X-Fraud-Score < 75

fraud_gate_valid if {
    input.source.principal == "spiffe://ztlab.local/aws/payment-service"
    input.attributes.request.http.path == "/transactions/execute"
    input.attributes.request.http.headers["x-fraud-gate"] == "passed"
    to_number(input.attributes.request.http.headers["x-fraud-score"]) < 75
}

allow if {
    input.attributes.request.http.path == "/transactions/execute"
    valid_svid
    fraud_gate_valid
}

fraud_gate_bypass_detected if {
    input.source.principal == "spiffe://ztlab.local/aws/payment-service"
    input.attributes.request.http.path == "/transactions/execute"
    not fraud_gate_valid
}

deny_reason := "fraud_gate_bypass" if {
    fraud_gate_bypass_detected
}
# deny_reason sẽ xuất hiện trong /var/log/opa/decisions.json
# → Promtail scrape → Loki → Grafana alert "fraud-gate-bypass-alert"
```

---

## 6. Phase 3 — Financial Microservices on K3s

*(Phase này giữ nguyên logic — chỉ thay đổi phần ghi chú về SIEM)*

### 6.1 Shared Modules

**File:** `shared/logging.py`

```python
import json, logging, sys, uuid, time
from typing import Any

class ZTLabLogger:
    """Structured JSON logger — emits log mà Promtail có thể parse."""

    LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40, "AUDIT": 50}

    def __init__(self, service: str, cloud: str):
        self.service = service
        self.cloud   = cloud

    def _emit(self, level: str, event: str, **kwargs):
        record = {
            "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level":      level,
            "service":    self.service,
            "cloud":      self.cloud,
            "event":      event,
            **kwargs
        }
        # Ghi ra stdout/stderr — container runtime collect và Promtail scrape
        # /var/log/containers/<pod>_<namespace>_<container>-*.log
        print(json.dumps(record), file=sys.stdout if level != "ERROR" else sys.stderr)

    def info(self,  event: str, **kw): self._emit("INFO",  event, **kw)
    def warn(self,  event: str, **kw): self._emit("WARN",  event, **kw)
    def error(self, event: str, **kw): self._emit("ERROR", event, **kw)
    def audit(self, event: str, **kw): self._emit("AUDIT", event, **kw)

def trace_middleware(service: str, cloud: str):
    """FastAPI middleware — inject X-Trace-ID vào mọi request."""
    from starlette.middleware.base import BaseHTTPMiddleware
    class _Middleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            trace_id = request.headers.get("X-Trace-ID", str(uuid.uuid4()))
            request.state.trace_id = trace_id
            response = await call_next(request)
            response.headers["X-Trace-ID"] = trace_id
            return response
    return _Middleware
```

### 6.2 AWS Microservices Deployment

**File:** `k8s/financial/aws-services.yaml`

```yaml
# ---- API Gateway Service ----
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: financial
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
      annotations:
        spiffe.io/spiffeid: "spiffe://ztlab.local/aws/api-gateway"
    spec:
      serviceAccountName: api-gateway
      containers:
        - name: api-gateway
          image: ztlab/api-gateway:1.0.0
          ports:
            - containerPort: 8080
          env:
            - name: KEYCLOAK_URL
              value: "https://keycloak.ztlab.local"
            - name: UPSTREAM_PAYMENT
              value: "http://payment-service:8080"
          resources:
            requests: { cpu: "100m", memory: "128Mi" }
            limits:   { cpu: "500m", memory: "256Mi" }
        - name: envoy
          image: envoyproxy/envoy:v1.29-latest
          args: ["-c", "/etc/envoy/envoy.yaml"]
          volumeMounts:
            - name: envoy-config
              mountPath: /etc/envoy
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
            - name: envoy-logs
              mountPath: /var/log/envoy
        - name: opa
          image: openpolicyagent/opa:0.63.0
          args:
            - "run"
            - "--server"
            - "--addr=localhost:9191"
            - "--config-file=/etc/opa/opa-config.yaml"
            - "/policies/zta_policy.rego"
            - "/policies/fraud_gate.rego"
            - "/policies/cross_cloud.rego"
          volumeMounts:
            - name: opa-policies
              mountPath: /policies
            - name: opa-config
              mountPath: /etc/opa
            - name: opa-logs
              mountPath: /var/log/opa
      volumes:
        - name: envoy-config
          configMap: { name: envoy-config }
        - name: opa-policies
          configMap: { name: opa-policies }
        - name: opa-config
          configMap: { name: opa-config }
        - name: spire-agent-socket
          hostPath: { path: /run/spire/sockets }
        - name: envoy-logs
          hostPath: { path: /var/log/envoy }    # Promtail scrapes từ host path này
        - name: opa-logs
          hostPath: { path: /var/log/opa }      # Promtail scrapes từ host path này
```

### 6.9 Gap Fix — OPA Policy: Fraud Header (Gap 2)

Xem §5.4 cho full OPA policy. Kết quả khi fraud gate bypass bị phát hiện:
1. OPA emit decision log vào `/var/log/opa/decisions.json` với `deny_reason: "fraud_gate_bypass"`
2. Promtail scrape file này và push vào Loki
3. Grafana alert rule `fraud-gate-bypass-alert.yml` fire khi detect pattern

### 6.10 Gap Fix — Large Response Detection (Gap 1)

Thay thế Logstash rule bằng LogQL trong Grafana:

**Grafana Alert:** `plg-stack/grafana/alerting/large-response-alert.yml`

```yaml
apiVersion: 1
groups:
  - name: gap1-exfiltration
    rules:
      - uid: gap1-large-response
        title: "Large Response — Exfiltration Suspect (Gap 1)"
        condition: C
        data:
          - refId: A
            queryType: range
            relativeTimeRange:
              from: 300
              to: 0
            datasourceUid: loki
            model:
              expr: |
                sum(count_over_time(
                  {job="envoy-access", cloud="openstack"}
                  | json
                  | bytes_sent > 1048576
                  [5m]
                ))
          - refId: C
            datasourceUid: __expr__
            model:
              conditions:
                - evaluator: { params: [0], type: gt }
                  operator:  { type: and }
                  query:     { params: [A] }
                  reducer:   { params: [], type: last }
                  type: query
        noDataState: OK
        execErrState: Alerting
        for: 0s
        annotations:
          summary: "Large response (>1MB) from OpenStack service — possible data exfiltration"
          description: "Envoy log từ OpenStack có bytes_sent > 1MB. Kiểm tra path và upstream."
        labels:
          severity: high
          gap: "gap1"
          mitre: "T1041"
```

---

## 7. Phase 4 — Log Collection & SIEM (PLG Stack: Promtail + Loki + Grafana)

### 7.1 Tổng quan PLG Stack

**Lý do chọn PLG thay vì ELK:**

| Tiêu chí | ELK (Elasticsearch + Logstash + Kibana) | PLG (Promtail + Loki + Grafana) |
|----------|----------------------------------------|--------------------------------|
| RAM usage | ~4–8 GB (Elasticsearch heap) | ~512 MB – 1 GB |
| Indexing strategy | Full-text index toàn bộ log content | Chỉ index labels, log content không index |
| Query language | Kibana Query Language / DSL | LogQL (giống PromQL) |
| Phù hợp | Log analytics phức tạp, full-text search | Label-based filtering, stream-oriented |
| Chi phí resource lab | Cần t3.large × 2 | Đủ với t3.medium × 1 |

**File:** `plg-stack/docker-compose.plg.yml`

```yaml
version: "3.8"

services:
  loki:
    image: grafana/loki:2.9.5
    container_name: loki
    ports:
      - "3100:3100"
    volumes:
      - ./loki/loki-config.yml:/etc/loki/local-config.yaml
      - loki-data:/loki
    command: -config.file=/etc/loki/local-config.yaml
    restart: unless-stopped
    networks:
      - plg

  grafana:
    image: grafana/grafana:10.3.1
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
      - GF_AUTH_ANONYMOUS_ENABLED=false
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - ./grafana/grafana.ini:/etc/grafana/grafana.ini
      - ./grafana/datasources:/etc/grafana/provisioning/datasources
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/alerting:/etc/grafana/provisioning/alerting
      - grafana-data:/var/lib/grafana
    depends_on:
      - loki
    restart: unless-stopped
    networks:
      - plg

volumes:
  loki-data:
  grafana-data:

networks:
  plg:
    driver: bridge
```

### 7.2 Loki Configuration

**File:** `plg-stack/loki/loki-config.yml`

```yaml
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096
  log_level: warn

common:
  instance_addr: 0.0.0.0
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory:  /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

# Giới hạn ingestion để tránh quá tải trong lab
limits_config:
  reject_old_samples:        true
  reject_old_samples_max_age: 168h   # 7 days
  ingestion_rate_mb:         32
  ingestion_burst_size_mb:   64
  max_streams_per_user:      10000
  max_entries_limit_per_query: 50000

# Retention — giữ log 30 ngày
compactor:
  working_directory: /loki/compactor
  retention_enabled: true

storage_config:
  tsdb_shipper:
    active_index_directory: /loki/tsdb-index
    cache_location: /loki/tsdb-cache
    cache_ttl: 24h

chunk_store_config:
  chunk_cache_config:
    embedded_cache:
      enabled: true
      max_size_mb: 256

table_manager:
  retention_deletes_enabled: true
  retention_period: 720h   # 30 days
```

### 7.3 Promtail Configuration

#### 7.3.1 Promtail — AWS Nodes

**File:** `plg-stack/promtail/promtail-aws.yml`

```yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions-aws.yaml

clients:
  - url: http://10.10.2.10:3100/loki/api/v1/push   # Loki trên aws-siem

scrape_configs:

  # ── 1. Envoy Access Log ───────────────────────────────────
  - job_name: envoy-access-aws
    static_configs:
      - targets: ["localhost"]
        labels:
          job:   "envoy-access"
          cloud: "aws"
          env:   "ztlab"
          __path__: /var/log/envoy/access.log
    pipeline_stages:
      - json:
          expressions:
            timestamp:     timestamp
            method:        method
            path:          path
            response_code: response_code
            response_time: response_time
            source_ip:     source_ip
            bytes_sent:    bytes_sent
            trace_id:      trace_id
            user_id:       user_id
            svid:          svid
      - labels:
          method:
          path:
      - timestamp:
          source: timestamp
          format: RFC3339
      - output:
          source: message

  # ── 2. OPA Decision Log ───────────────────────────────────
  - job_name: opa-decisions-aws
    static_configs:
      - targets: ["localhost"]
        labels:
          job:   "opa-decisions"
          cloud: "aws"
          env:   "ztlab"
          __path__: /var/log/opa/decisions.json
    pipeline_stages:
      - json:
          expressions:
            decision_id:  decision_id
            input:        input
            result:       result
            opa_result:   "result.allow"
            deny_reason:  "result.deny_reason"
            path:         "input.attributes.request.http.path"
            source_svid:  "input.source.principal"
      - labels:
          opa_result:
          deny_reason:
      - output:
          source: message

  # ── 3. System Log (syslog / auditd) ──────────────────────
  - job_name: system-aws
    static_configs:
      - targets: ["localhost"]
        labels:
          job:   "system"
          cloud: "aws"
          env:   "ztlab"
          __path__: /var/log/syslog
    pipeline_stages:
      - regex:
          expression: '^(?P<timestamp>\S+ \S+) (?P<hostname>\S+) (?P<program>[^\[:]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$'
      - labels:
          program:
      - output:
          source: message
```

#### 7.3.2 Promtail — OpenStack Nodes

**File:** `plg-stack/promtail/promtail-os.yml`

```yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions-os.yaml

clients:
  # Push qua WireGuard tunnel về Loki trên aws-siem
  - url: http://10.10.2.10:3100/loki/api/v1/push
    # Nếu tunnel down, Promtail sẽ buffer trong bộ nhớ và retry tự động
    batchwait: 1s
    batchsize: 1048576   # 1 MB

scrape_configs:

  # ── 1. Envoy Access Log ───────────────────────────────────
  - job_name: envoy-access-os
    static_configs:
      - targets: ["localhost"]
        labels:
          job:   "envoy-access"
          cloud: "openstack"
          env:   "ztlab"
          __path__: /var/log/envoy/access.log
    pipeline_stages:
      - json:
          expressions:
            timestamp:     timestamp
            method:        method
            path:          path
            response_code: response_code
            response_time: response_time
            source_ip:     source_ip
            bytes_sent:    bytes_sent
            trace_id:      trace_id
            user_id:       user_id
            svid:          svid
      - labels:
          method:
          path:
      - timestamp:
          source: timestamp
          format: RFC3339
      - output:
          source: message

  # ── 2. OPA Decision Log ───────────────────────────────────
  - job_name: opa-decisions-os
    static_configs:
      - targets: ["localhost"]
        labels:
          job:   "opa-decisions"
          cloud: "openstack"
          env:   "ztlab"
          __path__: /var/log/opa/decisions.json
    pipeline_stages:
      - json:
          expressions:
            decision_id:  decision_id
            opa_result:   "result.allow"
            deny_reason:  "result.deny_reason"
            path:         "input.attributes.request.http.path"
            source_svid:  "input.source.principal"
      - labels:
          opa_result:
          deny_reason:
      - output:
          source: message

  # ── 3. System Log ─────────────────────────────────────────
  - job_name: system-os
    static_configs:
      - targets: ["localhost"]
        labels:
          job:   "system"
          cloud: "openstack"
          env:   "ztlab"
          __path__: /var/log/syslog
    pipeline_stages:
      - regex:
          expression: '^(?P<timestamp>\S+ \S+) (?P<hostname>\S+) (?P<program>[^\[:]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$'
      - labels:
          program:
      - output:
          source: message
```

#### 7.3.3 Cài đặt Promtail bằng Ansible

**File:** `ansible/playbooks/promtail.yml`

```yaml
---
- name: Install and configure Promtail on all nodes
  hosts: all
  become: true
  vars:
    promtail_version: "2.9.5"
    promtail_binary_url: "https://github.com/grafana/loki/releases/download/v{{ promtail_version }}/promtail-linux-amd64.zip"

  tasks:
    - name: Create promtail user
      user:
        name: promtail
        system: yes
        shell: /sbin/nologin
        create_home: no

    - name: Create promtail directories
      file:
        path: "{{ item }}"
        state: directory
        owner: promtail
        group: promtail
        mode: "0755"
      loop:
        - /etc/promtail
        - /var/log/envoy
        - /var/log/opa
        - /tmp/promtail-positions

    - name: Download Promtail binary
      get_url:
        url: "{{ promtail_binary_url }}"
        dest: /tmp/promtail.zip
        mode: "0644"

    - name: Unzip Promtail
      unarchive:
        src: /tmp/promtail.zip
        dest: /usr/local/bin/
        remote_src: yes
        creates: /usr/local/bin/promtail-linux-amd64

    - name: Symlink promtail binary
      file:
        src: /usr/local/bin/promtail-linux-amd64
        dest: /usr/local/bin/promtail
        state: link

    - name: Deploy Promtail config from template
      template:
        src: templates/promtail-config.yml.j2
        dest: /etc/promtail/config.yml
        owner: promtail
        group: promtail
        mode: "0640"
      notify: restart promtail

    - name: Deploy Promtail systemd service
      copy:
        dest: /etc/systemd/system/promtail.service
        content: |
          [Unit]
          Description=Promtail log shipper
          After=network-online.target

          [Service]
          User=promtail
          ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/config.yml
          Restart=on-failure
          RestartSec=5s

          [Install]
          WantedBy=multi-user.target
      notify: restart promtail

    - name: Enable and start Promtail
      systemd:
        name: promtail
        enabled: yes
        state: started
        daemon_reload: yes

  handlers:
    - name: restart promtail
      systemd:
        name: promtail
        state: restarted
```

**File:** `ansible/templates/promtail-config.yml.j2`

```yaml
# Jinja2 template — rendered per node group
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/promtail-positions/positions.yaml

clients:
  - url: http://{{ loki_ip }}:3100/loki/api/v1/push
    batchwait: 1s
    batchsize: 1048576

scrape_configs:
  - job_name: envoy-access
    static_configs:
      - targets: ["localhost"]
        labels:
          job:   "envoy-access"
          cloud: "{{ cloud_provider }}"   # aws hoặc openstack (từ group_vars)
          node:  "{{ inventory_hostname }}"
          env:   "ztlab"
          __path__: /var/log/envoy/access.log
    pipeline_stages:
      - json:
          expressions:
            timestamp:     timestamp
            method:        method
            path:          path
            response_code: response_code
            response_time: response_time
            source_ip:     source_ip
            bytes_sent:    bytes_sent
      - labels:
          method:
          path:
      - timestamp:
          source: timestamp
          format: RFC3339

  - job_name: opa-decisions
    static_configs:
      - targets: ["localhost"]
        labels:
          job:   "opa-decisions"
          cloud: "{{ cloud_provider }}"
          node:  "{{ inventory_hostname }}"
          env:   "ztlab"
          __path__: /var/log/opa/decisions.json
    pipeline_stages:
      - json:
          expressions:
            opa_result:  "result.allow"
            deny_reason: "result.deny_reason"
            path:        "input.attributes.request.http.path"
      - labels:
          opa_result:
          deny_reason:

  - job_name: system
    static_configs:
      - targets: ["localhost"]
        labels:
          job:   "system"
          cloud: "{{ cloud_provider }}"
          node:  "{{ inventory_hostname }}"
          env:   "ztlab"
          __path__: /var/log/syslog
```

### 7.4 Grafana Configuration

**File:** `plg-stack/grafana/grafana.ini`

```ini
[server]
http_port = 3000
domain    = 10.10.2.10

[security]
admin_user     = admin
admin_password = ${GRAFANA_ADMIN_PASSWORD}

[auth]
disable_login_form = false

[users]
allow_sign_up = false
```

**File:** `plg-stack/grafana/datasources/loki-datasource.yml`

```yaml
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    uid: loki
    access: proxy
    url: http://loki:3100
    isDefault: true
    jsonData:
      maxLines: 1000
      timeout: 60
```

**File:** `plg-stack/grafana/dashboards/dashboard-provider.yml`

```yaml
apiVersion: 1
providers:
  - name: ztlab-dashboards
    orgId: 1
    folder: ZTLab
    folderUid: ztlab
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
      foldersFromFilesStructure: false
```

### 7.5 Grafana Dashboards — LogQL Queries

#### Dashboard: ZTA Security Overview

**File:** `plg-stack/grafana/dashboards/zta-security-overview.json`

Key panels và LogQL queries:

**Panel 1 — OPA Deny Count (24h)**
```logql
sum(count_over_time({job="opa-decisions"} | json | opa_result="false" [24h]))
```

**Panel 2 — JWT Failures (rate per minute)**
```logql
sum(rate({job="envoy-access"} | json | response_code="401" [1m]))
```

**Panel 3 — Top Denied SVID Pairs (table)**
```logql
topk(10,
  sum by (source_svid, path) (
    count_over_time(
      {job="opa-decisions"} | json | opa_result="false"
      [1h]
    )
  )
)
```

**Panel 4 — Fraud Gate Bypass Events (timeline)**
```logql
{job="opa-decisions"} | json | deny_reason="fraud_gate_bypass"
```

**Panel 5 — Large Responses from OpenStack (>1MB)**
```logql
{job="envoy-access", cloud="openstack"} | json | bytes_sent > 1048576
```

#### Dashboard: Envoy Access Logs

**File:** `plg-stack/grafana/dashboards/envoy-access-logs.json`

**Panel — Request Rate by Service**
```logql
sum by (path) (rate({job="envoy-access"} [1m]))
```

**Panel — Error Rate (4xx/5xx)**
```logql
sum(rate({job="envoy-access"} | json | response_code >= 400 [5m]))
/
sum(rate({job="envoy-access"} [5m]))
```

**Panel — P95 Response Time**
```logql
quantile_over_time(0.95,
  {job="envoy-access"} | json | unwrap response_time [5m]
) by (cloud)
```

#### Dashboard: OPA Decision Log

**File:** `plg-stack/grafana/dashboards/opa-decision-log.json`

**Panel — Allow vs Deny Rate**
```logql
sum by (opa_result) (
  rate({job="opa-decisions"} | json [5m])
)
```

**Panel — Denial Reasons Breakdown**
```logql
sum by (deny_reason) (
  count_over_time({job="opa-decisions"} | json | opa_result="false" [1h])
)
```

### 7.6 Grafana Alerting Rules

#### Alert 1 — Brute Force (T1110.001)

**File:** `plg-stack/grafana/alerting/brute-force-alert.yml`

```yaml
apiVersion: 1
groups:
  - name: brute-force
    rules:
      - uid: brute-force-login
        title: "Brute Force Login Attempt Detected"
        condition: C
        data:
          - refId: A
            queryType: range
            relativeTimeRange: { from: 60, to: 0 }
            datasourceUid: loki
            model:
              expr: |
                sum by (source_ip) (
                  count_over_time(
                    {job="envoy-access"} | json | response_code="401"
                    [1m]
                  )
                )
          - refId: C
            datasourceUid: __expr__
            model:
              conditions:
                - evaluator: { params: [5], type: gt }
                  operator:  { type: and }
                  query:     { params: [A] }
                  reducer:   { params: [], type: last }
                  type: query
        noDataState: OK
        execErrState: Alerting
        for: 0s
        annotations:
          summary: "{{ $labels.source_ip }} gây ra >5 lỗi 401 trong 1 phút"
          description: "Possible brute force attack. ATT&CK: T1110.001"
        labels:
          severity: high
          mitre: T1110.001
```

#### Alert 2 — Lateral Movement (T1021.007)

**File:** `plg-stack/grafana/alerting/lateral-movement-alert.yml`

```yaml
apiVersion: 1
groups:
  - name: lateral-movement
    rules:
      - uid: lateral-movement-svid
        title: "Lateral Movement — Invalid SVID Pair Detected"
        condition: C
        data:
          - refId: A
            queryType: range
            relativeTimeRange: { from: 300, to: 0 }
            datasourceUid: loki
            model:
              expr: |
                count_over_time(
                  {job="opa-decisions"} | json | opa_result="false"
                  | deny_reason="svid_mismatch"
                  [5m]
                )
          - refId: C
            datasourceUid: __expr__
            model:
              conditions:
                - evaluator: { params: [0], type: gt }
                  operator:  { type: and }
                  query:     { params: [A] }
                  reducer:   { params: [], type: last }
                  type: query
        noDataState: OK
        execErrState: Alerting
        for: 0s
        annotations:
          summary: "OPA denied request with SVID mismatch — possible lateral movement"
          description: "ATT&CK: T1021.007. Xem OPA Decision Log dashboard."
        labels:
          severity: critical
          mitre: T1021.007
```

#### Alert 3 — Fraud Gate Bypass (Gap 2, T1078.004)

**File:** `plg-stack/grafana/alerting/fraud-gate-bypass-alert.yml`

```yaml
apiVersion: 1
groups:
  - name: fraud-gate
    rules:
      - uid: fraud-gate-bypass
        title: "Fraud Gate Bypass Detected (Gap 2)"
        condition: C
        data:
          - refId: A
            queryType: range
            relativeTimeRange: { from: 300, to: 0 }
            datasourceUid: loki
            model:
              expr: |
                count_over_time(
                  {job="opa-decisions"} | json | deny_reason="fraud_gate_bypass"
                  [5m]
                )
          - refId: C
            datasourceUid: __expr__
            model:
              conditions:
                - evaluator: { params: [0], type: gt }
                  operator:  { type: and }
                  query:     { params: [A] }
                  reducer:   { params: [], type: last }
                  type: query
        noDataState: OK
        execErrState: Alerting
        for: 0s
        annotations:
          summary: "payment-service gọi core-banking mà không có fraud gate header"
          description: "Gap 2 validation triggered. ATT&CK: T1078.004."
        labels:
          severity: critical
          gap: gap2
          mitre: T1078.004
```

#### Alert 4 — Large Response / Exfiltration (Gap 1, T1041)

Xem §6.10 cho alert definition đầy đủ.

### 7.7 Deploy PLG Stack

```bash
# ── Bước 1: Deploy Loki + Grafana trên aws-siem ───────────────
ssh -J ubuntu@<BASTION_IP> ubuntu@10.10.2.10

cd /opt/ztlab
git clone <repo-url> .
cd plg-stack

# Tạo .env
cp ../../.env.template .env
# Điền GRAFANA_ADMIN_PASSWORD vào .env

docker compose -f docker-compose.plg.yml up -d

# Verify
curl http://localhost:3100/ready    # Loki → "ready"
curl http://localhost:3000/api/health  # Grafana → {"database":"ok"}

# ── Bước 2: Cài Promtail trên tất cả nodes ────────────────────
# Từ deployer machine
ansible-playbook -i ansible/inventory/hosts.yml \
  ansible/playbooks/promtail.yml

# ── Bước 3: Verify log đang chảy vào Loki ────────────────────
# Query Loki API trực tiếp
curl 'http://10.10.2.10:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="envoy-access"}' \
  --data-urlencode 'limit=5' \
  | jq '.data.result[].stream'

# ── Bước 4: Verify qua Grafana UI ────────────────────────────
# SSH tunnel để truy cập Grafana
ssh -L 3000:10.10.2.10:3000 -J ubuntu@<BASTION_IP> ubuntu@10.10.2.10
# Mở browser: http://localhost:3000
# Login: admin / <GRAFANA_ADMIN_PASSWORD>
# Explore → Loki → filter: {job="envoy-access", cloud="aws"}
```

---

## 8. Infrastructure as Code (Terraform + Ansible)

### 8.1 Terraform — AWS Resources

**File:** `terraform/aws/main.tf`

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_vpc" "ztlab" {
  cidr_block           = "172.31.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "ztlab-vpc", Project = "ztlab" }
}

resource "aws_subnet" "ztlab_main" {
  vpc_id            = aws_vpc.ztlab.id
  cidr_block        = "172.31.1.0/24"
  availability_zone = "${var.aws_region}a"
  tags = { Name = "ztlab-main-subnet" }
}

resource "aws_eip" "wg_gateway" {
  domain = "vpc"
  tags   = { Name = "ztlab-wg-gateway-eip" }
}

resource "aws_instance" "wg_gateway" {
  ami           = data.aws_ami.ubuntu22.id
  instance_type = "t3.small"
  subnet_id     = aws_subnet.ztlab_main.id
  key_name      = var.key_pair_name
  vpc_security_group_ids = [aws_security_group.wg_gateway.id]
  source_dest_check = false
  tags = { Name = "aws-gateway", Role = "wg-server" }
}

resource "aws_instance" "k3s_master" {
  ami           = data.aws_ami.ubuntu22.id
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.ztlab_main.id
  key_name      = var.key_pair_name
  vpc_security_group_ids = [aws_security_group.k3s.id]
  root_block_device { volume_size = 30 }
  tags = { Name = "aws-k3s-master", Role = "k3s-master" }
}

resource "aws_instance" "k3s_workers" {
  count         = 2
  ami           = data.aws_ami.ubuntu22.id
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.ztlab_main.id
  key_name      = var.key_pair_name
  vpc_security_group_ids = [aws_security_group.k3s.id]
  root_block_device { volume_size = 30 }
  tags = { Name = "aws-k3s-worker-${count.index + 1}", Role = "k3s-worker" }
}

# SIEM node — chạy Loki + Grafana (PLG Stack)
resource "aws_instance" "siem" {
  ami           = data.aws_ami.ubuntu22.id
  instance_type = "t3.medium"    # PLG nhẹ hơn ELK, t3.medium là đủ
  subnet_id     = aws_subnet.ztlab_main.id
  key_name      = var.key_pair_name
  vpc_security_group_ids = [aws_security_group.siem.id]
  root_block_device { volume_size = 50 }    # 50 GB cho Loki data
  tags = { Name = "aws-siem", Role = "siem-plg" }
}

data "aws_ami" "ubuntu22" {
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}
```

### 8.2 Terraform — Security Groups

**File:** `terraform/aws/security_groups.tf`

```hcl
# SIEM Security Group — Restricted Zone
resource "aws_security_group" "siem" {
  name   = "ztlab-siem-sg"
  vpc_id = aws_vpc.ztlab.id

  # Loki — nhận log từ Promtail agents (Private Zone + OpenStack qua WG tunnel)
  ingress {
    from_port   = 3100
    to_port     = 3100
    protocol    = "tcp"
    cidr_blocks = ["10.10.1.0/24", "10.10.0.0/24"]  # Private + WG subnet
    description = "Promtail → Loki"
  }

  # Grafana — chỉ từ Management Zone (bastion SSH tunnel)
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["10.10.4.0/24"]
    description = "Grafana dashboard — management zone only"
  }

  # SSH từ bastion
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.10.4.10/32"]
    description = "SSH from bastion"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ztlab-siem-sg" }
}
```

### 8.3 Ansible Deployment Order

**Không bao giờ chạy `ansible all` ngay từ đầu.** Phải bootstrap connectivity trước theo 4 giai đoạn.

#### Pre-flight: Verify connectivity

```bash
bash /tmp/check-os-connectivity.sh ~/.ssh/ztlab.pem
ansible ssh_entrypoints -i ansible/inventory/hosts.yml -m ping
```

#### Giai đoạn 1 — Baseline tất cả nodes có thể reach được

```bash
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/baseline.yml \
  --limit "ssh_entrypoints,aws_private,aws_restricted"

ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/baseline.yml \
  --limit "openstack"
```

#### Giai đoạn 2 — WireGuard (prerequisite cho mọi thứ)

```bash
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/wireguard.yml \
  --limit "aws_gateway,os_gateway"

# VERIFY TUNNEL — bắt buộc trước khi tiếp tục
ssh -J ubuntu@<BASTION_IP> ubuntu@<AWS_GATEWAY_IP> \
  "sudo wg show && ping -c 2 10.10.0.2"
```

#### Giai đoạn 3 — Baseline lại toàn bộ (sau khi tunnel up)

```bash
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/baseline.yml
ansible all -i ansible/inventory/hosts.yml -m ping  # tất cả phải trả về pong
```

#### Giai đoạn 4 — Deploy stack theo thứ tự dependency

```bash
# K3s (prerequisite cho SPIRE)
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/k3s.yml

# Promtail (cần Loki đã up trên aws-siem trước)
# Bước 4a: Deploy Loki + Grafana trên aws-siem trước
ssh -J ubuntu@<BASTION_IP> ubuntu@10.10.2.10 \
  "cd /opt/ztlab/plg-stack && docker compose -f docker-compose.plg.yml up -d"

# Bước 4b: Sau khi Loki ready, deploy Promtail lên tất cả nodes
ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/promtail.yml
```

#### hosts.yml — Cấu hình đúng cho từng zone

```yaml
# ansible/inventory/hosts.yml
all:
  vars:
    ansible_user: ubuntu
    ansible_ssh_private_key_file: ~/.ssh/ztlab.pem
    ansible_host_key_checking: false

  children:
    ssh_entrypoints:
      hosts:
        aws_bastion:
          ansible_host: 54.169.218.245
        aws_gateway:
          ansible_host: 52.221.9.50

    aws_private:
      vars:
        ansible_ssh_common_args: >-
          -o ProxyJump=ubuntu@54.169.218.245
          -o StrictHostKeyChecking=no
      hosts:
        aws_k3s_master:   { ansible_host: 10.10.1.10 }
        aws_k3s_worker_1: { ansible_host: 10.10.1.11 }
        aws_k3s_worker_2: { ansible_host: 10.10.1.12 }
        aws_security:     { ansible_host: 10.10.1.20 }

    aws_restricted:
      vars:
        ansible_ssh_common_args: >-
          -o ProxyJump=ubuntu@54.169.218.245
          -o StrictHostKeyChecking=no
      hosts:
        aws_siem: { ansible_host: 10.10.2.10 }

    openstack:
      vars:
        ansible_ssh_common_args: '-o StrictHostKeyChecking=no'
        cloud_provider: "openstack"    # dùng trong promtail-config.yml.j2
      children:
        os_dmz:
          hosts:
            os_gateway:
              ansible_host: 192.168.100.10
        os_private:
          hosts:
            os_k3s_master:   { ansible_host: 192.168.101.10 }
            os_k3s_worker_1: { ansible_host: 192.168.101.11 }
            os_k3s_worker_2: { ansible_host: 192.168.101.12 }
        os_identity:
          hosts:
            os_identity: { ansible_host: 192.168.102.10 }

    aws:
      vars:
        cloud_provider: "aws"    # dùng trong promtail-config.yml.j2
      children:
        ssh_entrypoints:
        aws_private:
        aws_restricted:
```

#### Tóm tắt thứ tự — cheatsheet

```
1. Setup br-provider trên aio (§2.2.1) ──────── một lần duy nhất
2. Mở SG port 22 từ aio IP (§2.2.1) ─────────── một lần duy nhất
3. ansible phase1 -m ping ────────────────────── verify connectivity
4. ansible-playbook baseline.yml --limit phase1
5. ansible-playbook wireguard.yml --limit aws_gateway,os_gateway
6. verify: wg show + ping 10.10.0.2 ──────────── bắt buộc trước bước 7
7. ansible-playbook baseline.yml ─────────────── lần này all reachable
8. ansible-playbook k3s.yml
9. Deploy Loki+Grafana trên aws-siem (docker compose up)
10. ansible-playbook promtail.yml ────────────── sau khi Loki ready
```

---

## 9. Monitoring Dashboards & Grafana Configuration

### 9.1 Dashboard Definitions

Xem §7.5 cho LogQL queries đầy đủ của từng dashboard.

**ZTA Security Overview** — Key panels:

| Panel | Visualization | LogQL source | Metric |
|-------|--------------|-------------|--------|
| Total OPA Denials (24h) | Stat | `{job="opa-decisions"}` | count where `opa_result=false` |
| JWT Failure Rate | Time series | `{job="envoy-access"}` | rate `response_code=401` |
| Top Attack Source IPs | Table | `{job="envoy-access"}` | topk by `source_ip` |
| Zero Trust Violations Timeline | Time series | `{job="opa-decisions"}` | count `opa_result=false` per minute |
| Fraud Gate Bypass Events | Logs panel | `{job="opa-decisions"}` | filter `deny_reason=fraud_gate_bypass` |

**Envoy Access Logs** — Key panels:

| Panel | Visualization | LogQL |
|-------|--------------|-------|
| Request Rate by Cloud | Time series | `sum by(cloud)(rate({job="envoy-access"}[1m]))` |
| Error Rate (4xx/5xx) | Gauge | ratio of error responses |
| Response Time P95 | Time series | `quantile_over_time(0.95, ...)` |
| Large Responses (>1MB) | Logs panel | `bytes_sent > 1048576` |

### 9.2 Alert Notification Channel

Grafana Alerting có thể gửi notification qua email, Slack, webhook. Trong lab, cấu hình đơn giản nhất:

```bash
# Grafana Contact Point — Email (nếu có SMTP)
# Hoặc Webhook để test
curl -X POST http://10.10.2.10:3000/api/v1/provisioning/contact-points \
  -H "Authorization: Basic $(echo -n admin:${GRAFANA_ADMIN_PASSWORD} | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ztlab-webhook",
    "type": "webhook",
    "settings": {
      "url": "http://localhost:8888/alerts"
    }
  }'
```

---

## 10. Security Testing Scenarios (MITRE ATT&CK)

### 10.1 Test Scenario Matrix

| # | Scenario | MITRE ATT&CK | ZTA Layer bị test | SIEM signal | Acceptance Criteria |
|---|----------|-------------|------------------|-------------|---------------------|
| 1 | Brute force login | T1110.001 | Keycloak 401 burst | Grafana Alert: brute-force | Alert fire ≤ 60s sau lần thứ 5 |
| 2 | JWT token forgery | T1550.001 | Envoy ext_authz | Envoy log `response_code=401` | 100% deny rate |
| 3 | Lateral movement — wrong SVID | T1021.007 | OPA SVID pair check | Grafana Alert: lateral-movement | OPA deny + alert ≤ 10s |
| 4 | Fraud gate bypass (Gap 2) | T1078.004 | OPA header check | Grafana Alert: fraud-gate-bypass | Deny 100%, alert immediate |
| 5 | High-velocity fraud (60 txn/min) | T1496 | Fraud scorer + Redis | Prometheus alert | Block sau txn thứ 10 |
| 6 | Data exfiltration >1MB (Gap 1) | T1041 | Promtail bytes_sent | Grafana Alert: large-response | Alert ≤ 30s |
| 7 | SVID not renewed | T1562.001 | SPIRE event log | System log Grafana query | Alert ≤ 5 min |
| 8 | Cross-cloud lateral movement | T1021 | OPA cross-cloud | Grafana OPA denial query | Alert từ cả 2 cloud |
| 9 | Privilege escalation on pod | T1068 | auditd | System log Grafana query | Alert ≤ 30s |
| 10 | Port scanning từ external | T1046 | System log | System log Grafana query | Alert ≤ 60s |
| 11 | Cryptomining container | T1496 | Prometheus CPU | Prometheus alert | Detect ≤ 5 min |

### 10.2 Baseline Setup

```bash
# Tạo test users trong Keycloak
export KEYCLOAK_URL="https://keycloak.ztlab.local"
export ADMIN_TOKEN=$(curl -s -X POST \
  "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=${KEYCLOAK_ADMIN_PASSWORD}" \
  | jq -r '.access_token')

curl -s -X POST "$KEYCLOAK_URL/admin/realms/ztlab/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser01","enabled":true,"credentials":[{"type":"password","value":"Test@1234","temporary":false}]}'

# Seed database
python tests/seed_db.py

# Chạy normal traffic 10 phút để Grafana có baseline
python tests/baseline_traffic.py &
sleep 600  # wait 10 min
```

### 10.3 Verify Detection bằng Loki/Grafana

Thay vì query Elasticsearch, dùng Loki API:

```bash
# Verify brute force detection
curl -G 'http://10.10.2.10:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="envoy-access"} | json | response_code="401"' \
  --data-urlencode 'limit=20' \
  | jq '.data.result[].values[]'

# Verify OPA fraud gate bypass detection
curl -G 'http://10.10.2.10:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="opa-decisions"} | json | deny_reason="fraud_gate_bypass"' \
  --data-urlencode 'limit=10' \
  | jq '.data.result[].values[]'

# Verify large response exfiltration detection
curl -G 'http://10.10.2.10:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="envoy-access", cloud="openstack"} | json | bytes_sent > 1048576' \
  --data-urlencode 'limit=10' \
  | jq '.data.result[].values[]'
```

### 10.4 Expected Results Summary

| Metric | Target | Ghi chú |
|--------|--------|---------|
| MTTD — ZTA-enforced scenarios (1–4) | ≤ 60s | OPA/Envoy deny ngay lập tức; Promtail push trong vài giây |
| MTTD — Volume-based (6) | ≤ 30s | Promtail scrape interval 5s; Grafana alert evaluate mỗi 1m |
| False Positive Rate | ≤ 5% | Grafana rules deterministic cho hard-gate scenarios |
| False Negative Rate | ≤ 10% | Gap 1 và Gap 2 đã được fix |
| Security Overhead at P95 | ≤ 20% | Envoy + OPA add ~5–15ms overhead |
| Fraud Gate Bypass Block Rate | 100% | OPA + application layer double-check |

### 10.5 Collect Metrics từ Loki

**File:** `tests/collect_metrics.py`

```python
#!/usr/bin/env python3
"""Collect MTTD và security metrics từ Loki API sau mỗi test scenario."""

import httpx, json, os, time
from datetime import datetime, timedelta, timezone

LOKI_URL = "http://10.10.2.10:3100"

def query_loki(logql: str, start: float, end: float = None) -> list:
    """Query Loki và trả về list of log entries."""
    if end is None:
        end = time.time()
    params = {
        "query": logql,
        "start": int(start * 1e9),   # nanoseconds
        "end":   int(end   * 1e9),
        "limit": 100,
        "direction": "forward"
    }
    r = httpx.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params, timeout=30)
    r.raise_for_status()
    results = r.json()
    entries = []
    for stream in results.get("data", {}).get("result", []):
        for ts, line in stream.get("values", []):
            entries.append({"timestamp_ns": int(ts), "line": line})
    return sorted(entries, key=lambda x: x["timestamp_ns"])

def collect_mttd(scenario_id: int, attack_start: float) -> float:
    """MTTD = thời gian từ lúc tấn công đến lúc log detection đầu tiên vào Loki."""
    queries = {
        1: '{job="envoy-access"} | json | response_code="401"',
        2: '{job="envoy-access"} | json | response_code="401"',
        3: '{job="opa-decisions"} | json | opa_result="false"',
        4: '{job="opa-decisions"} | json | deny_reason="fraud_gate_bypass"',
        6: '{job="envoy-access", cloud="openstack"} | json | bytes_sent > 1048576',
    }
    q = queries.get(scenario_id)
    if not q:
        return -1.0

    entries = query_loki(q, attack_start, attack_start + 300)  # look 5 min ahead
    if not entries:
        return -1.0

    detect_ns = entries[0]["timestamp_ns"]
    return (detect_ns / 1e9 - attack_start) * 1000  # ms

if __name__ == "__main__":
    import sys
    scenario_id = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    attack_start = float(sys.argv[2]) / 1000 if len(sys.argv) > 2 else time.time() - 60

    mttd = collect_mttd(scenario_id, attack_start)
    result = {
        "scenario":       scenario_id,
        "attack_start":   datetime.fromtimestamp(attack_start, tz=timezone.utc).isoformat(),
        "mttd_ms":        round(mttd, 1) if mttd > 0 else "NOT_DETECTED",
        "collected_at":   datetime.now(tz=timezone.utc).isoformat()
    }
    print(json.dumps(result, indent=2))
```

---

## 11. Network & Port Reference

**[DMZ Zone]**

| Service | Node | IP | Port | Protocol | Inbound from |
|---------|------|----|------|----------|--------------|
| WireGuard VPN | aws-gateway | 10.10.0.1 | 51820 | UDP | Internet (os-gateway dynamic IP) |
| Keycloak HTTPS | aws-security | 10.10.1.20 | 443 | TCP | DMZ (NLB) → Internet (OIDC flows) |
| SSH bastion | aws-bastion | 10.10.4.10 | 22 | TCP | Admin IP only |

**[Private Zone — AWS]**

| Service | Node | IP | Port | Protocol | Inbound from |
|---------|------|----|------|----------|--------------|
| K3s API | aws-k3s-master | 10.10.1.10 | 6443 | TCP | Private zone + Management |
| SPIRE Server | aws-security | 10.10.1.20 | 8081 | TCP | Private zone + OS via WG |
| Keycloak (internal) | aws-security | 10.10.1.20 | 8080 | TCP | Private zone only |
| Envoy inbound | all pods | — | 15006 | TCP | Envoy mesh intra-zone |
| OPA | all pods | — | 9191 | TCP | localhost only (sidecar) |
| Prometheus metrics | all pods | — | 9090 | TCP | Restricted zone (scrape) |

**[Private Zone — OpenStack]**

| Service | Node | Local IP | WG IP | Port | Inbound from |
|---------|------|----------|-------|------|--------------|
| K3s API | os-k3s-master | 192.168.101.10 | 10.10.4.10 | 6443 | OS Private + Management via WG |
| SPIRE Agent | os-identity | 192.168.101.20 | 10.10.5.10 | — | Connects out to SPIRE Server |

**[Restricted Zone — SIEM (PLG Stack)]**

| Service | Node | IP | Port | Protocol | Inbound from |
|---------|------|----|------|----------|--------------|
| Loki | aws-siem | 10.10.2.10 | 3100 | TCP | Private zone (Promtail) + OS via WG |
| Grafana | aws-siem | 10.10.2.10 | 3000 | TCP | Management zone (bastion SSH tunnel only) |

> **Grafana không expose ra internet.** Truy cập qua SSH local port forwarding: `ssh -L 3000:10.10.2.10:3000 -J ubuntu@<BASTION_IP> ubuntu@10.10.2.10`

---

## 12. Environment Variables & Secrets Reference

**File:** `.env.template` (never commit actual values)

```bash
# ========== WireGuard ==========
AWS_GATEWAY_PRIVATE_KEY=<generate with: wg genkey>
OS_GATEWAY_PRIVATE_KEY=<generate with: wg genkey>
AWS_EIP=<AWS Elastic IP address>

# ========== SPIRE ==========
SPIRE_JOIN_TOKEN=<generate with: spire-server token generate>
SPIRE_TRUST_DOMAIN=ztlab.local

# ========== Keycloak ==========
KEYCLOAK_ADMIN_PASSWORD=<min 16 chars, mixed case + special>
KEYCLOAK_DB_PASSWORD=<random 32 chars>

# ========== PLG Stack ==========
GRAFANA_ADMIN_PASSWORD=<min 16 chars>
# Loki không cần auth trong lab setup (internal network only)

# ========== AWS SDK (Terraform) ==========
AWS_ACCESS_KEY_ID=<IAM key with EC2 permissions>
AWS_SECRET_ACCESS_KEY=<IAM secret>
AWS_DEFAULT_REGION=ap-southeast-1

# ========== OpenStack SDK (Terraform) ==========
OS_AUTH_URL=http://<controller-ip>:5000/v3
OS_USERNAME=ztlab-admin
OS_PASSWORD=<openstack user password>
OS_PROJECT_NAME=ztlab
OS_REGION_NAME=RegionOne

# ========== Zone-specific notes ==========
# DMZ zone nodes:        no secrets stored — WireGuard keys only
# Private zone nodes:    SPIRE join token (short-lived, regenerate per deploy)
# Restricted zone nodes: Grafana admin password
# Management zone:       Terraform state S3 bucket name + DynamoDB table for locking
TERRAFORM_STATE_BUCKET=ztlab-terraform-state
TERRAFORM_LOCK_TABLE=ztlab-terraform-lock
```

**Secret Management:**

- Store all secrets in AWS Secrets Manager (production) hoặc Ansible Vault (lab)
- Rotate SPIRE SVIDs tự động (TTL = 1h, CA = 7d)
- Rotate Keycloak client secrets mỗi 90 ngày
- Grafana admin password nên rotate định kỳ; trong lab dùng Ansible Vault

---

> **Document maintained by:** Hoàng Bảo Phước · Phạm Võ Khánh Hà  
> **Last updated:** April 2026  
> **Version:** 2.0.0 (Simplified: PLG Stack replaces ELK+Wazuh+Kafka; AI Engine and SOAR removed)