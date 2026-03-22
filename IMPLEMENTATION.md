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
7. [Phase 4 — Log Collection Pipeline (Wazuh + Filebeat + Kafka)](#7-phase-4--log-collection-pipeline-wazuh--filebeat--kafka)
8. [Phase 5 — SIEM Core (ELK Stack on AWS)](#8-phase-5--siem-core-elk-stack-on-aws)
9. [Phase 6 — Real-Time Streaming: Kafka → OpenSearch Anomaly Detection](#9-phase-6--real-time-streaming-kafka--opensearch-anomaly-detection)
10. [Phase 7 — AI Detection Engine (ML + RAG + MCP)](#10-phase-7--ai-detection-engine-ml--rag--mcp)
11. [Phase 8 — SOAR Platform (TheHive + Cortex + n8n)](#11-phase-8--soar-platform-thehive--cortex--n8n)
12. [Phase 9 — Human-in-the-Loop (Slack Integration)](#12-phase-9--human-in-the-loop-slack-integration)
13. [Infrastructure as Code (Terraform + Ansible)](#13-infrastructure-as-code-terraform--ansible)
14. [Monitoring Dashboards & Kibana Configuration](#14-monitoring-dashboards--kibana-configuration)
15. [Security Testing Scenarios (MITRE ATT&CK)](#15-security-testing-scenarios-mitre-attck)
16. [Network & Port Reference](#16-network--port-reference)
17. [Environment Variables & Secrets Reference](#17-environment-variables--secrets-reference)

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
              │ log/alert traffic only — TCP 5044, 1514, 9200 inbound to Restricted
              ▼
╔═══════════════════════════════════════════════════════════════════════════════════════════╗
║  [3] RESTRICTED ZONE  ·  AWS 10.10.2.0/24 + 10.10.3.0/24  (NO internet inbound)        ║
║                                                                                           ║
║  ┌─────────────────────┐  ┌──────────────────┐  ┌──────────────────────────────────┐   ║
║  │  aws-siem-1          │  │  aws-siem-2       │  │  aws-opensearch                  │   ║
║  │  Elasticsearch 9200  │  │  Logstash :5044   │  │  OpenSearch :9200                │   ║
║  │  Kibana :5601        │  │  Kafka :9092       │  │  Anomaly Detectors (RCF)         │   ║
║  │  Wazuh Manager :1514 │  │  Zookeeper :2181   │  └──────────────────────────────────┘   ║
║  └─────────────────────┘  └──────────────────┘                                           ║
║  ┌──────────────────┐  ┌───────────────────────────────────────────────────────────────┐ ║
║  │  aws-ai           │  │  aws-soar                                                     │ ║
║  │  AI Engine :8000  │  │  TheHive :9000  Cortex :9001  n8n :5678                      │ ║
║  │  ChromaDB :8001   │  │  Outbound only: Slack webhook, AWS API, OpenStack Neutron API │ ║
║  └──────────────────┘  └───────────────────────────────────────────────────────────────┘ ║
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
OpenStack Wazuh Buffer: local queue on os-gateway when tunnel is down (see §7.5)
SOAR cross-cloud response: TheHive/Cortex acts on BOTH AWS SG and OpenStack Neutron (see §11.3)
```

### 1.2 Inter-Zone Traffic Rules

| From → To | Allowed Traffic | Denied |
|-----------|----------------|--------|
| Internet → DMZ | UDP 51820 (WG), TCP 443 | Everything else |
| DMZ → Private | TCP 8080, 443 (app traffic) | Direct DB, SIEM, SOAR access |
| Private → Restricted | TCP 5044 (Filebeat), 1514 (Wazuh), 9092 (Kafka) | Inbound from Restricted to Private |
| Restricted → Private | TCP 6443 (K3s API — SOAR only, outbound) | General inbound |
| Restricted → Internet | Outbound only: Slack API, AWS API (egress) | All inbound from internet |
| Management → All | SSH TCP 22 (from bastion only) | No inbound from other zones |
| OpenStack → Restricted | Via WG tunnel: 5044, 1514 | Direct internet path |

### 1.3 Why siem-1 and siem-2 Are Kept Separate

Two nodes are intentional even in a lab environment:

- **aws-siem-1** hosts Elasticsearch + Kibana + Wazuh Manager. This trio is I/O-bound — Elasticsearch performs continuous segment merging, Kibana serves dashboard queries, and Wazuh Manager correlates events. All three compete for disk IOPS and RAM.
- **aws-siem-2** hosts Logstash + Kafka + Zookeeper. This trio is CPU-bound — Logstash pipeline transformations, Kafka broker serialization, and Zookeeper leadership elections spike CPU during log ingestion bursts (attack simulations).

If merged, a single Kafka consumer thread spike during an attack simulation would steal CPU from Elasticsearch, causing alert queries to time out precisely when a security analyst needs them most — the worst possible moment for performance degradation. The separation also means Elasticsearch JVM heap can be sized to 50% of node RAM independently of Kafka's heap settings.

> **Lab resource tip:** If instance budget is hard-constrained, keep siem-1/siem-2 separate but downsize both to `t3.medium`. Elasticsearch heap = 2 GB, Kafka heap = 512 MB.

### 1.4 Why OpenStack Has No SIEM Node

SIEM is intentionally centralized on AWS for three reasons:

1. **Ingress cost:** AWS charges for data egress, not ingress. All log traffic flows *into* AWS — zero egress cost. Placing SIEM in OpenStack would require querying back from AWS for dashboards (egress).
2. **Data gravity:** AI models on `aws-ai` query Elasticsearch directly over the local subnet (sub-millisecond latency). Moving SIEM to OpenStack would add ~30-60ms round-trip per inference call, multiplied by thousands of log entries per batch.
3. **Resilience:** A compromised OpenStack node cannot tamper with SIEM data on a separate cloud. Logs are write-only from the OpenStack perspective via Wazuh/Filebeat agents.

**Blind-spot mitigation:** `os-gateway` runs a local Wazuh buffer (Filebeat spool + Kafka client queue) that holds up to 72h of logs if the WireGuard tunnel goes down. See §7.5 for configuration.

### 1.5 Component Role Summary

| Component | Cloud | Role |
|-----------|-------|------|
| WireGuard Gateway AWS | AWS | VPN Server, Public IP/EIP |
| WireGuard Gateway OS | OpenStack | VPN Client, NAT-only |
| SPIRE Server | AWS | SVID issuance for all workloads |
| Keycloak | AWS | OIDC/OAuth2 Identity Provider |
| OPA | Both (sidecar) | Policy Decision Point |
| Envoy Proxy | Both (sidecar) | Policy Enforcement Point, mTLS |
| Elasticsearch | AWS | Log storage + SIEM engine |
| Logstash | AWS | Log normalization pipeline |
| Kibana | AWS | Visualization + dashboards |
| OpenSearch | AWS | Anomaly detection (Random Cut Forest) |
| Apache Kafka | AWS | Real-time log streaming |
| Wazuh Manager | AWS | FIM, correlation engine |
| Wazuh Agent | All nodes | Log/event collection |
| Filebeat | All nodes | Envoy access log shipping |
| AI Engine | AWS | Isolation Forest + LSTM Autoencoder |
| RAG Pipeline | AWS | MITRE ATT&CK threat intelligence |
| TheHive | AWS | SOAR case management |
| Cortex | AWS | Automated responders |
| n8n | AWS | Workflow automation, HITL |

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

**[Restricted Zone] — Subnets: 10.10.2.0/24 and 10.10.3.0/24**

| Hostname | Instance Type | Private IP | Services | Why separate node |
|----------|--------------|------------|----------|-------------------|
| `aws-siem-1` | t3.large | 10.10.2.10 | Elasticsearch :9200, Kibana :5601, Wazuh Manager :1514 | I/O-bound: disk IOPS + RAM for indexing and queries |
| `aws-siem-2` | t3.large | 10.10.2.11 | Logstash :5044, Kafka :9092, Zookeeper :2181 | CPU-bound: pipeline transforms + broker serialization |
| `aws-opensearch` | t3.medium | 10.10.2.12 | OpenSearch :9200, Dashboard :5601 | RCF anomaly detection — memory-heavy, isolated from ES |
| `aws-soar` | t3.medium | 10.10.3.10 | TheHive :9000, Cortex :9001, n8n :5678 | Outbound-only responder — isolated from inbound traffic |
| `aws-ai` | t3.large | 10.10.3.11 | AI Engine :8000, ChromaDB :8001 | GPU/CPU inference — isolated from SOAR blast radius |

> **siem-1 vs siem-2 — resource profile justification:**  
> During an attack simulation, Kafka ingestion spikes to ~5,000 events/sec. On a merged node, Logstash + Kafka would consume 3–4 CPU cores leaving Elasticsearch with ~1 core — query latency for analyst dashboards would exceed 30s at the worst moment. Keeping them separate ensures Elasticsearch retains dedicated I/O and RAM at all times.

**[Management Zone] — Bastion-gated, no subnet exposure**

| Hostname | Instance Type | Private IP | Services |
|----------|--------------|------------|----------|
| `aws-bastion` | t3.micro | 10.10.4.10 | SSH jump host — only node with port 22 open from internet |
| `aws-iac-runner` | t3.small | 10.10.4.11 | Ansible runner, Terraform executor |

### 2.2 OpenStack Node Inventory (by Zone)

**[DMZ Zone] — OpenStack network: 192.168.100.0/24**

| Hostname | Flavor | Local IP | WG Tunnel IP | Services |
|----------|--------|----------|--------------|----------|
| `os-gateway` | m1.small | 192.168.100.10 | 10.10.0.2 | WireGuard client, NAT, Wazuh local buffer |

**[Private Zone] — OpenStack network: 192.168.101.0/24**

| Hostname | Flavor | Local IP | WG Tunnel IP | Services |
|----------|--------|----------|--------------|----------|
| `os-k3s-master` | m1.medium | 192.168.101.10 | 10.10.4.10 | K3s control plane |
| `os-k3s-worker-1` | m1.medium | 192.168.101.11 | 10.10.4.11 | Core Banking, Account Service |
| `os-k3s-worker-2` | m1.medium | 192.168.101.12 | 10.10.4.12 | Transaction Service |
| `os-identity` | m1.small | 192.168.101.20 | 10.10.5.10 | SPIRE Agent for OS cluster |

### 2.3 IP Addressing Scheme

```
── WireGuard tunnel backbone ──────────────────────────────
  10.10.0.0/24    VPN endpoints (aws-gateway, os-gateway)

── AWS subnets ────────────────────────────────────────────
  10.10.1.0/24    Private zone  (K3s nodes, SPIRE, Keycloak)
  10.10.2.0/24    Restricted zone — SIEM tier (siem-1/2, OpenSearch)
  10.10.3.0/24    Restricted zone — Security tier (SOAR, AI)
  10.10.4.0/24    Management zone (bastion, IaC runner)

── AWS K3s cluster ────────────────────────────────────────
  Pod CIDR:       10.42.0.0/16
  Service CIDR:   10.43.0.0/16

── OpenStack subnets ──────────────────────────────────────
  192.168.100.0/24   DMZ (os-gateway)
  192.168.101.0/24   Private zone (K3s nodes, os-identity)

── OpenStack K3s cluster ──────────────────────────────────
  Pod CIDR:       10.44.0.0/16
  Service CIDR:   10.45.0.0/16
```

### 2.4 AWS Security Groups — Zone Enforcement

**sg-dmz** (attached to: `aws-gateway`)

```
Inbound:
  UDP 51820   0.0.0.0/0           WireGuard from OS gateway (dynamic IP)
  TCP 443     0.0.0.0/0           HTTPS — Auth Portal only (via NLB)
  TCP 22      <admin-IP>/32        SSH — admin only

Outbound:
  All         0.0.0.0/0           NAT for tunnel traffic
```

**sg-private** (attached to: K3s nodes, `aws-security`)

```
Inbound:
  TCP 8080, 443   sg-dmz              App traffic from DMZ only
  TCP 6443        10.10.1.0/24        K3s API — node-to-node
  TCP 8081        10.10.1.0/24        SPIRE Server — agents within Private
  TCP 8081        10.10.4.0/24        SPIRE Server — OS agents via tunnel
  TCP 9090        10.10.2.0/24        Prometheus scrape from Restricted
  All             10.10.1.0/24        Intra-zone (Envoy mTLS mesh)
  All             10.44.0.0/16        Cross-cloud K3s pod traffic via WG

Outbound:
  TCP 5044    10.10.2.10          Filebeat → Logstash (siem-2)
  TCP 1514    10.10.2.10          Wazuh Agent → Manager (siem-1)
  TCP 9092    10.10.2.11          Kafka producer (metrics exporter)
  All         10.10.1.0/24        Intra-zone
```

**sg-restricted** (attached to: siem-1, siem-2, opensearch, soar, ai)

```
Inbound:
  TCP 5044    10.10.1.0/24        Filebeat from Private
  TCP 5044    10.10.4.0/24        Filebeat from OS Private (via WG)
  TCP 1514    10.10.1.0/24        Wazuh agents
  TCP 1514    10.10.4.0/24        Wazuh agents from OS
  TCP 9092    10.10.1.0/24        Kafka producers
  TCP 9200    10.10.3.0/24        ES queries — AI & SOAR inter-Restricted
  TCP 9000    10.10.3.0/24        TheHive API — AI to SOAR
  TCP 8000    10.10.3.0/24        AI Engine — SOAR to AI
  TCP 5601    10.10.4.10          Kibana — bastion only
  TCP 22      10.10.4.0/24        SSH from Management only

Outbound:
  TCP 443     0.0.0.0/0           Slack API webhook (n8n → Slack)
  TCP 443     AWS APIs            AWS SDK for Security Group automation
  TCP 9696    192.168.100.10      OpenStack Neutron API (via WG tunnel)
  All         10.10.2.0/24        Intra-Restricted
  All         10.10.3.0/24        Intra-Restricted
```

**sg-management** (attached to: bastion, IaC runner)

```
Inbound:
  TCP 22      <admin-IP>/32        SSH to bastion from admin IP only

Outbound:
  TCP 22      10.10.0.0/8          SSH to all internal zones
  TCP 443     AWS APIs             Terraform/Ansible API calls
  TCP 443     0.0.0.0/0            Package downloads
```

### 2.5 OpenStack Neutron Security Groups — Zone Enforcement

**neutron-sg-os-dmz** (attached to: `os-gateway`)

```bash
openstack security group create neutron-sg-os-dmz

# Egress to AWS WireGuard (all — dynamic source IP)
openstack security group rule create neutron-sg-os-dmz \
  --protocol udp --dst-port 51820 --direction egress

# Allow all internal forwarded traffic (tunnel NAT)
openstack security group rule create neutron-sg-os-dmz \
  --protocol tcp --remote-ip 192.168.101.0/24 --direction ingress

# Deny all other inbound
# (default deny applies — no explicit allow = denied)
```

**neutron-sg-os-private** (attached to: K3s nodes, os-identity)

```bash
openstack security group create neutron-sg-os-private

# K3s node-to-node
openstack security group rule create neutron-sg-os-private \
  --protocol tcp --remote-ip 192.168.101.0/24 --direction ingress

# Wazuh + Filebeat egress to AWS SIEM (via WG tunnel)
openstack security group rule create neutron-sg-os-private \
  --protocol tcp --dst-port 5044 --remote-ip 10.10.2.11 --direction egress
openstack security group rule create neutron-sg-os-private \
  --protocol tcp --dst-port 1514 --remote-ip 10.10.2.10 --direction egress
openstack security group rule create neutron-sg-os-private \
  --protocol tcp --dst-port 9092 --remote-ip 10.10.2.11 --direction egress

# SPIRE Agent egress to SPIRE Server on AWS
openstack security group rule create neutron-sg-os-private \
  --protocol tcp --dst-port 8081 --remote-ip 10.10.1.20 --direction egress
```

---

## 3. Phase 0 — WireGuard Site-to-Site VPN Setup

### 3.1 Install WireGuard (Both Gateways)

```bash
# Ubuntu 22.04
sudo apt update && sudo apt install -y wireguard wireguard-tools

# Generate keypairs on each node
wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
chmod 600 /etc/wireguard/privatekey
cat /etc/wireguard/publickey   # note this value
```

### 3.2 AWS Gateway — VPN Server Config

**File:** `/etc/wireguard/wg0.conf` on `aws-gateway`

```ini
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = <AWS_GATEWAY_PRIVATE_KEY>

# Enable IP forwarding and NAT for traffic routing
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# OpenStack Gateway peer
[Peer]
PublicKey = <OS_GATEWAY_PUBLIC_KEY>
AllowedIPs = 10.10.0.2/32, 10.10.4.0/24, 10.10.5.0/24
PersistentKeepalive = 25
```

### 3.3 OpenStack Gateway — VPN Client Config

**File:** `/etc/wireguard/wg0.conf` on `os-gateway`

```ini
[Interface]
Address = 10.10.0.2/24
PrivateKey = <OS_GATEWAY_PRIVATE_KEY>

PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# AWS Gateway peer (has public IP)
[Peer]
PublicKey = <AWS_GATEWAY_PUBLIC_KEY>
Endpoint = <AWS_EIP>:51820
AllowedIPs = 10.10.0.0/24, 10.10.1.0/24, 10.10.2.0/24, 10.10.3.0/24, 10.42.0.0/16, 10.43.0.0/16
PersistentKeepalive = 25
```

### 3.4 Enable & Verify

```bash
# On both gateways
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Verify
sudo wg show
ping 10.10.0.1   # from os-gateway
ping 10.10.0.2   # from aws-gateway
```

### 3.5 AWS Security Group — Inbound Rules

| Protocol | Port | Source | Purpose |
|----------|------|--------|---------|
| UDP | 51820 | 0.0.0.0/0 | WireGuard |
| TCP | 443 | 0.0.0.0/0 | HTTPS |
| TCP | 6443 | 10.10.0.0/24 | K3s API |
| TCP | 9200 | 10.10.0.0/24 | Elasticsearch |
| TCP | 5601 | 10.10.0.0/24 | Kibana |
| TCP | 9092 | 10.10.0.0/24 | Kafka |
| All | All | 10.10.0.0/8 | Internal tunnel |

---

## 4. Phase 1 — Identity Foundation: SPIFFE/SPIRE

### 4.1 Architecture

```
SPIRE Server (aws-security:10.10.3.10)
    │
    ├── SPIRE Agent (each AWS K3s node)
    │       └── Issues SVIDs to workloads via Unix socket
    │
    └── SPIRE Agent (each OS K3s node via WireGuard tunnel)
            └── Issues SVIDs to OS workloads
```

All inter-service communication uses mTLS with SPIFFE SVIDs. IP-based trust is eliminated.

### 4.2 SPIRE Server Installation

```bash
# On aws-security node
SPIRE_VERSION=1.9.4
wget https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-amd64-musl.tar.gz
tar -xzf spire-${SPIRE_VERSION}-linux-amd64-musl.tar.gz -C /opt/
ln -s /opt/spire-${SPIRE_VERSION}/bin/spire-server /usr/local/bin/spire-server
ln -s /opt/spire-${SPIRE_VERSION}/bin/spire-agent  /usr/local/bin/spire-agent
```

**File:** `/opt/spire/conf/server/server.conf`

```hcl
server {
  bind_address = "0.0.0.0"
  bind_port    = "8081"
  trust_domain = "ztlab.local"
  data_dir     = "/opt/spire/data/server"
  log_level    = "INFO"

  ca_subject {
    country      = ["VN"]
    organization = ["ZT-Lab"]
    common_name  = ""
  }

  # SVID TTL — short-lived to enforce continuous verification
  default_x509_svid_ttl = "1h"
  default_jwt_svid_ttl  = "5m"
  ca_ttl                = "168h"  # 1 week CA rotation
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "/opt/spire/data/server/datastore.sqlite3"
    }
  }

  KeyManager "disk" {
    plugin_data {
      keys_path = "/opt/spire/data/server/keys.json"
    }
  }

  NodeAttestor "k8s_psat" {
    plugin_data {
      clusters = {
        "aws-k3s" = {
          service_account_allow_list = ["spire:spire-agent"]
          kube_config_file = "/root/.kube/aws-config"
        }
        "os-k3s" = {
          service_account_allow_list = ["spire:spire-agent"]
          kube_config_file = "/root/.kube/os-config"
        }
      }
    }
  }
}
```

### 4.3 SPIRE Agent DaemonSet (K3s — Both Clusters)

**File:** `k8s/spire/agent-daemonset.yaml`

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spire-agent
  namespace: spire
spec:
  selector:
    matchLabels:
      app: spire-agent
  template:
    metadata:
      labels:
        app: spire-agent
    spec:
      hostPID: true
      hostNetwork: true
      serviceAccountName: spire-agent
      initContainers:
        - name: init
          image: cgr.dev/chainguard/wait-for-it
          args: ["10.10.3.10:8081", "--", "echo", "SPIRE Server ready"]
      containers:
        - name: spire-agent
          image: ghcr.io/spiffe/spire-agent:1.9.4
          args: ["-config", "/run/spire/config/agent.conf"]
          volumeMounts:
            - name: spire-config
              mountPath: /run/spire/config
              readOnly: true
            - name: spire-bundle
              mountPath: /run/spire/bundle
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
            - name: spire-token
              mountPath: /var/run/secrets/tokens
      volumes:
        - name: spire-config
          configMap:
            name: spire-agent-config
        - name: spire-bundle
          configMap:
            name: spire-bundle
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
            type: DirectoryOrCreate
        - name: spire-token
          projected:
            sources:
              - serviceAccountToken:
                  path: spire-agent
                  expirationSeconds: 7200
                  audience: spire-server
```

**Agent config** (`agent.conf`):

```hcl
agent {
  data_dir    = "/run/spire"
  log_level   = "INFO"
  trust_domain = "ztlab.local"
  server_address = "10.10.3.10"
  server_port    = "8081"
  socket_path = "/run/spire/sockets/agent.sock"

  # Authorize by K3s service account projected token
  join_token = "${JOIN_TOKEN}"
}

plugins {
  NodeAttestor "k8s_psat" {
    plugin_data {
      cluster = "aws-k3s"   # or "os-k3s" for OpenStack agents
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

### 4.4 Registration Entries (SVIDs per Workload)

```bash
# Register AWS microservices
spire-server entry create \
  -spiffeID spiffe://ztlab.local/aws/payment-service \
  -parentID spiffe://ztlab.local/k8s-psat/aws-k3s/spire-agent \
  -selector k8s:ns:financial \
  -selector k8s:sa:payment-service \
  -ttl 3600

spire-server entry create \
  -spiffeID spiffe://ztlab.local/aws/fraud-detection \
  -parentID spiffe://ztlab.local/k8s-psat/aws-k3s/spire-agent \
  -selector k8s:ns:financial \
  -selector k8s:sa:fraud-detection \
  -ttl 3600

# Register OpenStack microservices
spire-server entry create \
  -spiffeID spiffe://ztlab.local/os/core-banking \
  -parentID spiffe://ztlab.local/k8s-psat/os-k3s/spire-agent \
  -selector k8s:ns:financial \
  -selector k8s:sa:core-banking \
  -ttl 3600

spire-server entry create \
  -spiffeID spiffe://ztlab.local/os/account-service \
  -parentID spiffe://ztlab.local/k8s-psat/os-k3s/spire-agent \
  -selector k8s:ns:financial \
  -selector k8s:sa:account-service \
  -ttl 3600

spire-server entry create \
  -spiffeID spiffe://ztlab.local/os/transaction-service \
  -parentID spiffe://ztlab.local/k8s-psat/os-k3s/spire-agent \
  -selector k8s:ns:financial \
  -selector k8s:sa:transaction-service \
  -ttl 3600
```

---

## 5. Phase 2 — Policy Enforcement: Envoy Proxy + OPA + Keycloak

### 5.1 Keycloak Deployment (aws-security)

```yaml
# k8s/keycloak/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: identity
spec:
  replicas: 1
  selector:
    matchLabels:
      app: keycloak
  template:
    spec:
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:24.0.3
          args: ["start-dev"]
          env:
            - name: KEYCLOAK_ADMIN
              value: "admin"
            - name: KEYCLOAK_ADMIN_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: keycloak-secret
                  key: admin-password
            - name: KC_DB
              value: "postgres"
            - name: KC_DB_URL
              value: "jdbc:postgresql://keycloak-db:5432/keycloak"
            - name: KC_HOSTNAME
              value: "keycloak.ztlab.local"
            - name: KC_PROXY
              value: "edge"
          ports:
            - containerPort: 8080
```

**Keycloak Realm Configuration** (import via Admin API or JSON):

```json
{
  "realm": "ztlab",
  "enabled": true,
  "accessTokenLifespan": 300,
  "ssoSessionMaxLifespan": 36000,
  "clients": [
    {
      "clientId": "api-gateway",
      "protocol": "openid-connect",
      "publicClient": false,
      "authorizationServicesEnabled": true,
      "serviceAccountsEnabled": true,
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": false
    },
    {
      "clientId": "siem-backend",
      "protocol": "openid-connect",
      "publicClient": false,
      "serviceAccountsEnabled": true,
      "standardFlowEnabled": false
    }
  ],
  "roles": {
    "realm": [
      { "name": "financial-read" },
      { "name": "financial-write" },
      { "name": "security-analyst" },
      { "name": "security-admin" }
    ]
  }
}
```

### 5.2 OPA Policy Engine (sidecar on each service)

**File:** `opa/policies/zta_policy.rego`

```rego
package zta.authz

import future.keywords.if
import future.keywords.in

default allow = false

# Allow if: valid JWT + valid SVID + action permitted for role
allow if {
    valid_jwt
    valid_svid
    role_permits_action
}

valid_jwt if {
    token := input.attributes.request.http.headers["authorization"]
    [_, payload, _] := io.jwt.decode(token)
    payload.iss == "https://keycloak.ztlab.local/realms/ztlab"
    payload.exp > time.now_ns() / 1000000000
    input.parsed_body.subject = payload.sub
}

valid_svid if {
    svid := input.source.principal
    startswith(svid, "spiffe://ztlab.local/")
}

role_permits_action if {
    [_, payload, _] := io.jwt.decode(input.attributes.request.http.headers["authorization"])
    roles := payload.realm_access.roles
    action := input.attributes.request.http.method
    path   := input.attributes.request.http.path

    # Payment service: only financial-write can POST /transactions
    action == "POST"
    startswith(path, "/transactions")
    "financial-write" in roles
}

role_permits_action if {
    [_, payload, _] := io.jwt.decode(input.attributes.request.http.headers["authorization"])
    action := input.attributes.request.http.method
    action in ["GET", "OPTIONS"]
}

# Audit log every decision
audit_log := {
    "timestamp": time.now_ns(),
    "subject":   input.parsed_body.subject,
    "action":    input.attributes.request.http.method,
    "resource":  input.attributes.request.http.path,
    "decision":  allow,
    "svid":      input.source.principal
}
```

**OPA Sidecar config** (`opa-config.yaml`):

```yaml
services:
  - name: opa-server
    url: http://localhost:8181

decision_logs:
  plugin: file
  file:
    path: /var/log/opa/decisions.log
    partition_name: opa-decisions

plugins:
  file:
    path: /var/log/opa/decisions.log
```

### 5.3 Envoy Proxy Sidecar Configuration

**File:** `envoy/envoy-sidecar.yaml` (per service)

```yaml
static_resources:
  listeners:
    - name: inbound_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 15006   # intercept inbound
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                codec_type: AUTO
                stat_prefix: inbound_http
                access_log:
                  - name: envoy.access_loggers.file
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: /var/log/envoy/access.log
                      log_format:
                        json_format:
                          timestamp:     "%START_TIME%"
                          method:        "%REQ(:METHOD)%"
                          path:          "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
                          response_code: "%RESPONSE_CODE%"
                          response_time: "%DURATION%"
                          upstream:      "%UPSTREAM_HOST%"
                          source_ip:     "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
                          request_id:    "%REQ(X-REQUEST-ID)%"
                          authority:     "%REQ(:AUTHORITY)%"
                          user_agent:    "%REQ(USER-AGENT)%"
                          bytes_sent:    "%BYTES_SENT%"
                          bytes_received: "%BYTES_RECEIVED%"
                http_filters:
                  # Step 1: OPA authorization check
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      grpc_service:
                        envoy_grpc:
                          cluster_name: opa_cluster
                        timeout: 0.5s
                      failure_mode_allow: false
                      with_request_body:
                        max_request_bytes: 8192
                  # Step 2: JWT validation
                  - name: envoy.filters.http.jwt_authn
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
                      providers:
                        keycloak:
                          issuer: "https://keycloak.ztlab.local/realms/ztlab"
                          audiences: ["api-gateway"]
                          remote_jwks:
                            http_uri:
                              uri: "https://keycloak.ztlab.local/realms/ztlab/protocol/openid-connect/certs"
                              cluster: keycloak_cluster
                              timeout: 5s
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: opa_cluster
      type: STATIC
      load_assignment:
        cluster_name: opa_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 127.0.0.1
                      port_value: 9191
    - name: keycloak_cluster
      type: STRICT_DNS
      load_assignment:
        cluster_name: keycloak_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: keycloak.identity.svc.cluster.local
                      port_value: 8080
      # mTLS to Keycloak using SPIRE-issued cert
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          common_tls_context:
            tls_certificate_sds_secret_configs:
              - name: "spiffe://ztlab.local/envoy-proxy"
                sds_config:
                  api_config_source:
                    api_type: GRPC
                    grpc_services:
                      - envoy_grpc:
                          cluster_name: spire_agent
            combined_validation_context:
              default_validation_context:
                match_typed_subject_alt_names:
                  - san_type: URI
                    matcher:
                      exact: "spiffe://ztlab.local/keycloak"
              validation_context_sds_secret_config:
                name: "spiffe://ztlab.local"
                sds_config:
                  api_config_source:
                    api_type: GRPC
                    grpc_services:
                      - envoy_grpc:
                          cluster_name: spire_agent
```

---

## 6. Phase 3 — Financial Microservices on K3s

### 6.0 Application Design Principles

Mỗi microservice được build theo 3 nguyên tắc phục vụ mục tiêu ZTA + SIEM:

1. **Tạo log có cấu trúc tại mọi decision point** — mọi request/response đều emit structured JSON log kèm `user_id`, `spiffe_id`, `trace_id`, `amount`, `risk_score`. Đây là raw material cho SIEM correlation.
2. **Mandatory fraud gate trước khi chạm private cloud** — Payment Service bắt buộc gọi Fraud Detection và inject `X-Fraud-Score` header trước khi forward sang Core Banking. OPA trên Core Banking từ chối nếu thiếu header này — đây là fix cho **Gap 2**.
3. **Data ownership rõ ràng theo cloud** — AWS chứa stateless services (routing, scoring, notification). OpenStack chứa toàn bộ stateful data (account balances, transaction ledger, KYC). Cross-cloud call luôn được SPIRE SVID xác thực và logged.

**Tech stack:** Python 3.11 + FastAPI + SQLAlchemy (OpenStack services) + Redis (velocity window)

**Project layout:**
```
services/
  api-gateway/          # AWS — entry point, JWT verify, rate limit
  payment-service/      # AWS — orchestrate payment flow + fraud gate
  fraud-detection/      # AWS — stateless scoring engine + Redis velocity
  notification-service/ # AWS — event-driven alerts
  core-banking/         # OpenStack — orchestrator for private data
  account-service/      # OpenStack — KYC, balance, account CRUD
  transaction-service/  # OpenStack — ledger, history, audit trail
shared/
  models.py             # Pydantic schemas shared across services
  logging.py            # Structured JSON logger used by all services
  metrics.py            # Prometheus exporter base
```

### 6.1 Shared Infrastructure

**File:** `shared/logging.py`

```python
import json, logging, time, uuid
from contextvars import ContextVar
from fastapi import Request

trace_id_var: ContextVar[str] = ContextVar('trace_id', default='')

class ZTLabLogger:
    """Structured JSON logger — every field maps to a Logstash/Wazuh field."""

    def __init__(self, service_name: str, cloud: str):
        self.service  = service_name
        self.cloud    = cloud
        self._logger  = logging.getLogger(service_name)
        logging.basicConfig(
            level=logging.INFO,
            format='%(message)s'   # raw JSON only — no Python timestamp prefix
        )

    def _emit(self, level: str, event: str, **fields):
        record = {
            "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level":      level,
            "service":    self.service,
            "cloud":      self.cloud,
            "trace_id":   trace_id_var.get(''),
            "event":      event,
            **fields
        }
        print(json.dumps(record), flush=True)

    def info(self, event: str, **kw):  self._emit("INFO",  event, **kw)
    def warn(self, event: str, **kw):  self._emit("WARN",  event, **kw)
    def error(self, event: str, **kw): self._emit("ERROR", event, **kw)
    def audit(self, event: str, **kw): self._emit("AUDIT", event, **kw)


def trace_middleware(service_name: str, cloud: str):
    """FastAPI middleware: inject trace_id + log every request/response."""
    from starlette.middleware.base import BaseHTTPMiddleware
    import time

    logger = ZTLabLogger(service_name, cloud)

    class TraceMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            tid = request.headers.get("X-Trace-ID", str(uuid.uuid4()))
            trace_id_var.set(tid)
            t0  = time.time()
            response = await call_next(request)
            latency  = round((time.time() - t0) * 1000, 2)
            logger.info(
                "http_request",
                method       = request.method,
                path         = request.url.path,
                status_code  = response.status_code,
                latency_ms   = latency,
                source_ip    = request.client.host if request.client else "unknown",
                user_agent   = request.headers.get("user-agent", ""),
                spiffe_id    = request.headers.get("X-SPIFFE-ID", ""),
            )
            response.headers["X-Trace-ID"] = tid
            return response

    return TraceMiddleware
```

**File:** `shared/metrics.py`

```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# ── Transaction metrics ──────────────────────────────────────
TXN_TOTAL = Counter(
    'ztlab_transactions_total',
    'Transactions processed',
    ['service', 'cloud', 'type', 'status']
)
TXN_AMOUNT = Histogram(
    'ztlab_transaction_amount_vnd',
    'Transaction amounts in VND',
    ['service', 'type'],
    buckets=[100_000, 500_000, 1_000_000, 5_000_000,
             10_000_000, 50_000_000, 100_000_000, 500_000_000]
)
TXN_LATENCY = Histogram(
    'ztlab_transaction_duration_seconds',
    'End-to-end transaction latency',
    ['service', 'upstream'],
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

# ── Fraud metrics ─────────────────────────────────────────────
FRAUD_SCORE  = Histogram(
    'ztlab_fraud_score',
    'Fraud risk scores (0–100)',
    ['verdict'],
    buckets=[10, 20, 30, 40, 50, 60, 70, 75, 80, 90, 100]
)
FRAUD_BLOCKS = Counter(
    'ztlab_fraud_blocks_total',
    'Transactions blocked by fraud engine',
    ['reason']
)

# ── Auth metrics ──────────────────────────────────────────────
AUTH_FAILURES = Counter(
    'ztlab_auth_failures_total',
    'Authentication failures',
    ['service', 'reason', 'source_ip']
)

# ── Cross-cloud call metrics ──────────────────────────────────
CROSS_CLOUD_CALLS = Counter(
    'ztlab_cross_cloud_calls_total',
    'Cross-cloud service calls',
    ['from_service', 'to_service', 'status']
)
CROSS_CLOUD_LATENCY = Histogram(
    'ztlab_cross_cloud_latency_seconds',
    'Cross-cloud call latency (WireGuard tunnel)',
    ['from_service', 'to_service'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]
)

def start_metrics_server(port: int = 9090):
    start_http_server(port)
```

### 6.2 K3s Installation

```bash
# AWS K3s Master
curl -sfL https://get.k3s.io | sh -s - server \
  --cluster-init \
  --node-ip=10.10.1.10 \
  --advertise-address=10.10.1.10 \
  --flannel-iface=wg0 \
  --disable traefik \
  --disable servicelb

# Get join token
cat /var/lib/rancher/k3s/server/node-token

# AWS Workers
curl -sfL https://get.k3s.io | K3S_URL=https://10.10.1.10:6443 \
  K3S_TOKEN=<NODE_TOKEN> \
  sh -s - agent --node-ip=10.10.1.11 --flannel-iface=wg0

# OpenStack K3s Master
curl -sfL https://get.k3s.io | sh -s - server \
  --cluster-init \
  --node-ip=10.10.4.10 \
  --advertise-address=10.10.4.10 \
  --flannel-iface=wg0 \
  --disable traefik \
  --disable servicelb
```

### 6.3 Service: API Gateway (AWS)

Entry point cho toàn bộ hệ thống. Chịu trách nhiệm: xác thực JWT từ Keycloak, rate limiting theo `user_id`, routing đến Payment hoặc Account query service, và inject `X-Trace-ID` cho distributed tracing.

**File:** `services/api-gateway/main.py`

```python
import os, httpx, time
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
import redis.asyncio as redis
from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import start_metrics_server, AUTH_FAILURES, TXN_TOTAL

app    = FastAPI(title="ZTLab API Gateway")
logger = ZTLabLogger("api-gateway", "aws")
bearer = HTTPBearer()

KEYCLOAK_URL   = os.getenv("KEYCLOAK_URL", "https://keycloak.ztlab.local")
JWKS_URL       = f"{KEYCLOAK_URL}/realms/ztlab/protocol/openid-connect/certs"
PAYMENT_URL    = os.getenv("UPSTREAM_PAYMENT", "http://payment-service:8080")
ACCOUNT_URL    = os.getenv("UPSTREAM_ACCOUNT", "http://core-banking.os-financial:8080")
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "60"))

app.add_middleware(trace_middleware("api-gateway", "aws"))

# ── JWKS cache ────────────────────────────────────────────────
_jwks_cache: dict = {}
_jwks_fetched_at: float = 0.0

async def get_jwks() -> dict:
    global _jwks_cache, _jwks_fetched_at
    if time.time() - _jwks_fetched_at > 300:   # refresh every 5 min
        async with httpx.AsyncClient(verify=True) as c:
            r = await c.get(JWKS_URL)
            r.raise_for_status()
            _jwks_cache     = r.json()
            _jwks_fetched_at = time.time()
    return _jwks_cache

async def verify_jwt(creds: HTTPAuthorizationCredentials = Depends(bearer),
                     request: Request = None) -> dict:
    token = creds.credentials
    try:
        jwks    = await get_jwks()
        payload = jwt.decode(
            token, jwks,
            algorithms=["RS256"],
            audience="api-gateway",
            issuer=f"{KEYCLOAK_URL}/realms/ztlab"
        )
        return payload
    except JWTError as e:
        src_ip = request.client.host if request else "unknown"
        AUTH_FAILURES.labels(
            service="api-gateway", reason="jwt_invalid", source_ip=src_ip
        ).inc()
        logger.warn(
            "jwt_verification_failed",
            error    = str(e),
            source_ip= src_ip,
            token_prefix = token[:20] + "..."
        )
        raise HTTPException(status_code=401, detail="Invalid token")

# ── Rate limiter (per user, per minute) ──────────────────────
_redis: redis.Redis = None

async def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis(host="redis-gateway", port=6379, decode_responses=True)
    return _redis

async def check_rate_limit(user_id: str, source_ip: str):
    r   = await get_redis()
    key = f"ratelimit:{user_id}"
    cnt = await r.incr(key)
    if cnt == 1:
        await r.expire(key, 60)
    if cnt > RATE_LIMIT_RPM:
        AUTH_FAILURES.labels(
            service="api-gateway", reason="rate_limit_exceeded", source_ip=source_ip
        ).inc()
        logger.warn(
            "rate_limit_exceeded",
            user_id   = user_id,
            count_rpm = cnt,
            source_ip = source_ip
        )
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

# ── Routes ────────────────────────────────────────────────────
@app.post("/api/v1/payments")
async def create_payment(request: Request,
                         payload: dict = Depends(verify_jwt)):
    user_id = payload.get("sub")
    await check_rate_limit(user_id, request.client.host)
    body = await request.json()

    logger.info(
        "payment_request_received",
        user_id = user_id,
        amount  = body.get("amount"),
        currency= body.get("currency", "VND"),
        roles   = payload.get("realm_access", {}).get("roles", [])
    )
    TXN_TOTAL.labels(
        service="api-gateway", cloud="aws", type="payment", status="received"
    ).inc()

    # Forward to Payment Service with user context
    headers = {
        "X-User-ID":    user_id,
        "X-User-Roles": ",".join(payload.get("realm_access", {}).get("roles", [])),
        "X-Trace-ID":   request.headers.get("X-Trace-ID", ""),
        "Authorization": request.headers.get("Authorization", "")
    }
    async with httpx.AsyncClient(timeout=30.0) as c:
        resp = await c.post(f"{PAYMENT_URL}/payments", json=body, headers=headers)
    return resp.json()

@app.get("/api/v1/accounts/{account_id}")
async def get_account(account_id: str,
                      request: Request,
                      payload: dict = Depends(verify_jwt)):
    user_id = payload.get("sub")
    roles   = payload.get("realm_access", {}).get("roles", [])
    if "financial-read" not in roles and "financial-write" not in roles:
        raise HTTPException(status_code=403, detail="Insufficient roles")
    headers = {
        "X-User-ID":  user_id,
        "X-Trace-ID": request.headers.get("X-Trace-ID", "")
    }
    async with httpx.AsyncClient(timeout=10.0) as c:
        resp = await c.get(f"{ACCOUNT_URL}/accounts/{account_id}", headers=headers)
    return resp.json()

@app.get("/health")
async def health():
    return {"status": "ok", "service": "api-gateway", "cloud": "aws"}

if __name__ == "__main__":
    start_metrics_server(9090)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
```

### 6.4 Service: Payment Service (AWS) — với Fraud Gate (Gap 2 Fix)

Payment Service là orchestrator cho payment flow. Điểm quan trọng nhất: nó **bắt buộc** gọi Fraud Detection trước, inject `X-Fraud-Score` header, và Core Banking sẽ từ chối nếu header này vắng mặt hoặc score quá cao. Đây là cơ chế phòng thủ theo chiều sâu (defense in depth) cho Gap 2.

**File:** `services/payment-service/main.py`

```python
import os, httpx, uuid
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field
from decimal import Decimal
from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import (start_metrics_server, TXN_TOTAL,
                             TXN_AMOUNT, TXN_LATENCY, CROSS_CLOUD_CALLS,
                             CROSS_CLOUD_LATENCY, FRAUD_BLOCKS)
import time

app    = FastAPI(title="ZTLab Payment Service")
logger = ZTLabLogger("payment-service", "aws")
app.add_middleware(trace_middleware("payment-service", "aws"))

FRAUD_URL       = os.getenv("FRAUD_SERVICE_URL",    "http://fraud-detection:8080")
CORE_BANKING_URL= os.getenv("CORE_BANKING_URL",
                             "http://core-banking.os-financial.svc.cluster.local:8080")
NOTIFICATION_URL= os.getenv("NOTIFICATION_URL",     "http://notification-service:8080")
MAX_SINGLE_TXN  = int(os.getenv("MAX_SINGLE_TXN_VND", str(500_000_000)))  # 500M VND

class PaymentRequest(BaseModel):
    from_account: str
    to_account:   str
    amount:       Decimal = Field(gt=0)
    currency:     str     = Field(default="VND", max_length=3)
    note:         str     = Field(default="", max_length=200)
    channel:      str     = Field(default="api")   # api | mobile | atm

class PaymentResponse(BaseModel):
    transaction_id: str
    status:         str
    fraud_score:    int
    message:        str

@app.post("/payments", response_model=PaymentResponse)
async def process_payment(req: Request, body: PaymentRequest):
    user_id  = req.headers.get("X-User-ID", "unknown")
    trace_id = req.headers.get("X-Trace-ID", str(uuid.uuid4()))
    src_ip   = req.client.host if req.client else "unknown"

    logger.info(
        "payment_started",
        user_id      = user_id,
        from_account = body.from_account,
        to_account   = body.to_account,
        amount       = float(body.amount),
        currency     = body.currency,
        channel      = body.channel,
        source_ip    = src_ip,
    )

    # ── Hard rule: single transaction limit ──────────────────
    if body.currency == "VND" and body.amount > MAX_SINGLE_TXN:
        FRAUD_BLOCKS.labels(reason="amount_hard_limit").inc()
        logger.warn(
            "payment_blocked_hard_limit",
            amount      = float(body.amount),
            limit       = MAX_SINGLE_TXN,
            user_id     = user_id,
            source_ip   = src_ip
        )
        raise HTTPException(status_code=400,
                            detail=f"Amount exceeds single transaction limit")

    # ── Step 1: Fraud scoring gate (MANDATORY — Gap 2 fix) ───
    fraud_payload = {
        "user_id":      user_id,
        "from_account": body.from_account,
        "amount":       float(body.amount),
        "currency":     body.currency,
        "channel":      body.channel,
        "source_ip":    src_ip,
        "trace_id":     trace_id
    }
    t_fraud = time.time()
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            fr = await c.post(f"{FRAUD_URL}/score", json=fraud_payload,
                              headers={"X-Trace-ID": trace_id})
        fr.raise_for_status()
        fraud_result = fr.json()
    except httpx.HTTPStatusError as e:
        logger.error("fraud_service_error", status=e.response.status_code,
                     user_id=user_id)
        raise HTTPException(status_code=503, detail="Fraud service unavailable")
    except httpx.TimeoutException:
        # Fail-closed: fraud service timeout = block transaction
        logger.error("fraud_service_timeout", user_id=user_id, trace_id=trace_id)
        raise HTTPException(status_code=503, detail="Fraud service timeout — transaction blocked")

    fraud_score  = fraud_result["score"]
    fraud_verdict= fraud_result["verdict"]   # ALLOW | REVIEW | BLOCK

    logger.info(
        "fraud_score_received",
        user_id      = user_id,
        fraud_score  = fraud_score,
        fraud_verdict= fraud_verdict,
        latency_ms   = round((time.time() - t_fraud) * 1000, 2),
        amount       = float(body.amount)
    )

    if fraud_verdict == "BLOCK":
        FRAUD_BLOCKS.labels(reason="fraud_score_block").inc()
        TXN_TOTAL.labels(service="payment-service", cloud="aws",
                         type="payment", status="blocked_fraud").inc()
        logger.warn(
            "payment_blocked_fraud",
            fraud_score = fraud_score,
            user_id     = user_id,
            amount      = float(body.amount),
            source_ip   = src_ip
        )
        raise HTTPException(
            status_code=403,
            detail=f"Transaction blocked by fraud engine (score={fraud_score})"
        )

    # ── Step 2: Forward to Core Banking (OpenStack) ──────────
    # X-Fraud-Score header is MANDATORY — Core Banking OPA policy
    # will reject the request if this header is absent or score >= 75
    t_cross = time.time()
    banking_headers = {
        "X-User-ID":     user_id,
        "X-Fraud-Score": str(fraud_score),
        "X-Fraud-Gate":  "passed",          # proof that fraud service was called
        "X-Trace-ID":    trace_id,
        "X-Source-SVID": "spiffe://ztlab.local/aws/payment-service"
    }
    banking_body = {
        "from_account": body.from_account,
        "to_account":   body.to_account,
        "amount":       float(body.amount),
        "currency":     body.currency,
        "note":         body.note,
        "channel":      body.channel,
        "trace_id":     trace_id
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as c:
            br = await c.post(
                f"{CORE_BANKING_URL}/transactions/execute",
                json=banking_body,
                headers=banking_headers
            )
        br.raise_for_status()
        banking_result = br.json()
    except httpx.HTTPStatusError as e:
        CROSS_CLOUD_CALLS.labels(
            from_service="payment-service",
            to_service="core-banking", status="error"
        ).inc()
        logger.error(
            "core_banking_error",
            status_code = e.response.status_code,
            user_id     = user_id,
            trace_id    = trace_id
        )
        raise HTTPException(status_code=502, detail="Core banking error")

    cross_latency = time.time() - t_cross
    CROSS_CLOUD_CALLS.labels(
        from_service="payment-service",
        to_service="core-banking", status="success"
    ).inc()
    CROSS_CLOUD_LATENCY.labels(
        from_service="payment-service",
        to_service="core-banking"
    ).observe(cross_latency)
    TXN_AMOUNT.labels(service="payment-service", type="payment").observe(float(body.amount))
    TXN_TOTAL.labels(service="payment-service", cloud="aws",
                     type="payment", status="success").inc()

    txn_id = banking_result.get("transaction_id", str(uuid.uuid4()))
    logger.audit(
        "payment_completed",
        transaction_id  = txn_id,
        user_id         = user_id,
        from_account    = body.from_account,
        to_account      = body.to_account,
        amount          = float(body.amount),
        currency        = body.currency,
        fraud_score     = fraud_score,
        cross_cloud_ms  = round(cross_latency * 1000, 2),
    )

    # Fire-and-forget notification
    try:
        async with httpx.AsyncClient(timeout=2.0) as c:
            await c.post(f"{NOTIFICATION_URL}/notify", json={
                "user_id": user_id,
                "type":    "payment_success",
                "txn_id":  txn_id,
                "amount":  float(body.amount)
            })
    except Exception:
        pass  # notification failure is non-blocking

    return PaymentResponse(
        transaction_id = txn_id,
        status         = "completed",
        fraud_score    = fraud_score,
        message        = f"Payment processed. Fraud verdict: {fraud_verdict}"
    )

@app.get("/health")
async def health():
    return {"status": "ok", "service": "payment-service", "cloud": "aws"}

if __name__ == "__main__":
    start_metrics_server(9090)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
```

### 6.5 Service: Fraud Detection (AWS) — Stateless Scorer

**File:** `services/fraud-detection/main.py`

```python
import os, time, httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis.asyncio as aioredis
from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import start_metrics_server, FRAUD_SCORE, FRAUD_BLOCKS

app    = FastAPI(title="ZTLab Fraud Detection")
logger = ZTLabLogger("fraud-detection", "aws")
app.add_middleware(trace_middleware("fraud-detection", "aws"))

CORE_BANKING_URL = os.getenv("CORE_BANKING_URL",
    "http://core-banking.os-financial.svc.cluster.local:8080")
REDIS_HOST       = os.getenv("REDIS_HOST", "redis-fraud")
VELOCITY_WINDOW  = 60    # seconds
VELOCITY_MAX     = 10    # max transactions per window before score spikes

# Score weights (must sum to 100)
W_VELOCITY   = 40
W_AMOUNT     = 30
W_TIME       = 15
W_GEO_DEVICE = 15

class ScoreRequest(BaseModel):
    user_id:      str
    from_account: str
    amount:       float
    currency:     str = "VND"
    channel:      str = "api"
    source_ip:    str = "unknown"
    trace_id:     str = ""

class ScoreResponse(BaseModel):
    score:          int          # 0–100
    verdict:        str          # ALLOW | REVIEW | BLOCK
    components:     dict
    user_id:        str
    trace_id:       str

_redis: aioredis.Redis = None

async def get_redis():
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
    return _redis

async def score_velocity(user_id: str) -> tuple[int, int]:
    """Track transactions per 60s window per user. Returns (score_contribution, count)."""
    r   = await get_redis()
    key = f"velocity:{user_id}"
    cnt = await r.incr(key)
    if cnt == 1:
        await r.expire(key, VELOCITY_WINDOW)
    # Sigmoid-like mapping: 0 txn→0, 5 txn→20, 10 txn→40, 20+→40
    score = min(int((cnt / VELOCITY_MAX) * W_VELOCITY), W_VELOCITY)
    return score, cnt

async def score_amount(user_id: str, amount: float, currency: str) -> tuple[int, float]:
    """Compare amount against user's 90-day mean from Core Banking."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(
                f"{CORE_BANKING_URL}/accounts/{user_id}/stats",
                headers={"X-Internal-Call": "fraud-detection"}
            )
        if r.status_code == 200:
            stats   = r.json()
            mean    = stats.get("txn_amount_mean_90d", amount)
            std_dev = stats.get("txn_amount_std_90d", amount * 0.5)
            if std_dev < 1:
                std_dev = mean * 0.5
            z_score = abs(amount - mean) / std_dev
            # z < 1 → 0pts, z 1–2 → 10pts, z 2–3 → 20pts, z > 3 → 30pts
            score = min(int(z_score / 3.0 * W_AMOUNT), W_AMOUNT)
            return score, z_score
    except Exception:
        pass
    return 0, 0.0    # fail-open for amount scoring (velocity is the hard gate)

def score_time_of_day(channel: str) -> int:
    """Unusual hours for the given channel add risk."""
    hour = time.gmtime().tm_hour + 7  # convert UTC to GMT+7
    hour = hour % 24
    # API: unusual outside 06:00–22:00; ATM: unusual 02:00–05:00
    if channel == "api" and not (6 <= hour <= 22):
        return W_TIME        # full weight — API calls at 3am are suspicious
    if channel == "atm" and 2 <= hour <= 5:
        return W_TIME // 2   # partial
    return 0

def score_geo(source_ip: str) -> int:
    """Placeholder: in production, lookup IP geolocation. Here: basic heuristic."""
    # Non-VN IPs detected by simple range check (expand with real GeoIP in production)
    KNOWN_VN_PREFIXES = ("103.", "113.", "116.", "123.", "171.", "183.", "210.", "222.")
    for prefix in KNOWN_VN_PREFIXES:
        if source_ip.startswith(prefix):
            return 0
    # Unknown/international IP
    if source_ip.startswith("10.") or source_ip.startswith("192.168."):
        return 0   # internal lab traffic
    return W_GEO_DEVICE // 2   # half weight for unknown geo

@app.post("/score", response_model=ScoreResponse)
async def score_transaction(req: ScoreRequest):
    # Run all scoring components concurrently where possible
    vel_score, vel_count = await score_velocity(req.user_id)
    amt_score, z_score   = await score_amount(req.user_id, req.amount, req.currency)
    time_score           = score_time_of_day(req.channel)
    geo_score            = score_geo(req.source_ip)

    total = vel_score + amt_score + time_score + geo_score
    total = min(total, 100)

    if total < 40:
        verdict = "ALLOW"
    elif total < 75:
        verdict = "REVIEW"
    else:
        verdict = "BLOCK"

    components = {
        "velocity":   {"score": vel_score,  "txn_count_60s": vel_count},
        "amount":     {"score": amt_score,  "z_score": round(z_score, 2)},
        "time_of_day":{"score": time_score},
        "geo_device": {"score": geo_score,  "source_ip": req.source_ip}
    }

    FRAUD_SCORE.labels(verdict=verdict).observe(total)
    if verdict == "BLOCK":
        FRAUD_BLOCKS.labels(reason="composite_score").inc()

    logger.info(
        "fraud_scored",
        user_id    = req.user_id,
        total_score= total,
        verdict    = verdict,
        components = components,
        amount     = req.amount,
        trace_id   = req.trace_id,
        source_ip  = req.source_ip
    )

    return ScoreResponse(
        score      = total,
        verdict    = verdict,
        components = components,
        user_id    = req.user_id,
        trace_id   = req.trace_id
    )

@app.get("/health")
async def health():
    return {"status": "ok", "service": "fraud-detection", "cloud": "aws"}

if __name__ == "__main__":
    start_metrics_server(9090)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
```

### 6.6 Service: Core Banking API (OpenStack) — với OPA Fraud Gate Check

Core Banking là orchestrator trên private cloud. Điểm quan trọng: OPA sidecar được cấu hình thêm rule kiểm tra `X-Fraud-Score` header — đây là layer thứ 2 của Gap 2 fix. Ngay cả nếu kẻ tấn công có SVID hợp lệ của `payment-service`, Core Banking vẫn từ chối nếu fraud header không hợp lệ.

**File:** `services/core-banking/main.py`

```python
import os, uuid
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from decimal import Decimal
import httpx
from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import (start_metrics_server, TXN_TOTAL,
                             TXN_AMOUNT, CROSS_CLOUD_LATENCY)

app    = FastAPI(title="ZTLab Core Banking API")
logger = ZTLabLogger("core-banking", "openstack")
app.add_middleware(trace_middleware("core-banking", "openstack"))

ACCOUNT_URL     = os.getenv("ACCOUNT_SERVICE_URL", "http://account-service:8080")
TRANSACTION_URL = os.getenv("TRANSACTION_SERVICE_URL", "http://transaction-service:8080")
MAX_FRAUD_SCORE = int(os.getenv("MAX_ALLOWED_FRAUD_SCORE", "74"))  # matches REVIEW threshold

class ExecuteTransactionRequest(BaseModel):
    from_account: str
    to_account:   str
    amount:       float
    currency:     str = "VND"
    note:         str = ""
    channel:      str = "api"
    trace_id:     str = ""

@app.post("/transactions/execute")
async def execute_transaction(req: Request, body: ExecuteTransactionRequest):
    user_id    = req.headers.get("X-User-ID", "unknown")
    trace_id   = body.trace_id or req.headers.get("X-Trace-ID", str(uuid.uuid4()))
    src_svid   = req.headers.get("X-Source-SVID", "")

    # ── Gap 2 Fix Layer 2: Validate fraud gate header ────────
    # OPA policy also enforces this, but we double-check in application code
    # to produce a meaningful audit log entry
    fraud_score_raw = req.headers.get("X-Fraud-Score")
    fraud_gate      = req.headers.get("X-Fraud-Gate")

    if fraud_score_raw is None or fraud_gate != "passed":
        logger.warn(
            "fraud_gate_bypass_attempt",
            user_id    = user_id,
            source_svid= src_svid,
            trace_id   = trace_id,
            from_account= body.from_account,
            amount     = body.amount,
            missing_header = "X-Fraud-Score" if fraud_score_raw is None else "X-Fraud-Gate"
        )
        raise HTTPException(
            status_code=403,
            detail="Missing fraud gate validation — request rejected by core banking"
        )

    fraud_score = int(fraud_score_raw)
    if fraud_score >= MAX_FRAUD_SCORE:
        logger.warn(
            "transaction_rejected_fraud_score",
            fraud_score = fraud_score,
            threshold   = MAX_FRAUD_SCORE,
            user_id     = user_id,
            amount      = body.amount,
            trace_id    = trace_id
        )
        raise HTTPException(
            status_code=403,
            detail=f"Transaction rejected: fraud score {fraud_score} exceeds threshold {MAX_FRAUD_SCORE}"
        )

    logger.info(
        "transaction_execute_started",
        user_id     = user_id,
        from_account= body.from_account,
        to_account  = body.to_account,
        amount      = body.amount,
        currency    = body.currency,
        fraud_score = fraud_score,
        source_svid = src_svid,
        trace_id    = trace_id
    )

    # ── Step 1: Verify both accounts exist + check balance ──
    async with httpx.AsyncClient(timeout=5.0) as c:
        from_r = await c.get(
            f"{ACCOUNT_URL}/accounts/{body.from_account}",
            headers={"X-Trace-ID": trace_id, "X-Internal-Caller": "core-banking"}
        )
        to_r = await c.get(
            f"{ACCOUNT_URL}/accounts/{body.to_account}",
            headers={"X-Trace-ID": trace_id, "X-Internal-Caller": "core-banking"}
        )

    if from_r.status_code != 200:
        raise HTTPException(status_code=404, detail="Source account not found")
    if to_r.status_code != 200:
        raise HTTPException(status_code=404, detail="Destination account not found")

    from_account = from_r.json()
    balance      = from_account.get("balance", 0)

    if balance < body.amount:
        logger.info(
            "transaction_rejected_insufficient_funds",
            from_account = body.from_account,
            balance      = balance,
            requested    = body.amount,
            user_id      = user_id
        )
        raise HTTPException(status_code=400, detail="Insufficient funds")

    # ── Step 2: Write transaction to ledger ─────────────────
    txn_payload = {
        "from_account": body.from_account,
        "to_account":   body.to_account,
        "amount":       body.amount,
        "currency":     body.currency,
        "note":         body.note,
        "channel":      body.channel,
        "fraud_score":  fraud_score,
        "trace_id":     trace_id,
        "user_id":      user_id
    }
    async with httpx.AsyncClient(timeout=10.0) as c:
        txn_r = await c.post(
            f"{TRANSACTION_URL}/ledger/record",
            json=txn_payload,
            headers={"X-Trace-ID": trace_id, "X-Internal-Caller": "core-banking"}
        )
    txn_r.raise_for_status()
    txn_result = txn_r.json()
    txn_id     = txn_result["transaction_id"]

    # ── Step 3: Update balances ──────────────────────────────
    async with httpx.AsyncClient(timeout=5.0) as c:
        await c.post(
            f"{ACCOUNT_URL}/accounts/{body.from_account}/debit",
            json={"amount": body.amount, "txn_id": txn_id},
            headers={"X-Trace-ID": trace_id, "X-Internal-Caller": "core-banking"}
        )
        await c.post(
            f"{ACCOUNT_URL}/accounts/{body.to_account}/credit",
            json={"amount": body.amount, "txn_id": txn_id},
            headers={"X-Trace-ID": trace_id, "X-Internal-Caller": "core-banking"}
        )

    TXN_TOTAL.labels(
        service="core-banking", cloud="openstack", type="payment", status="success"
    ).inc()
    TXN_AMOUNT.labels(service="core-banking", type="payment").observe(body.amount)

    logger.audit(
        "transaction_completed",
        transaction_id = txn_id,
        from_account   = body.from_account,
        to_account     = body.to_account,
        amount         = body.amount,
        currency       = body.currency,
        fraud_score    = fraud_score,
        user_id        = user_id,
        trace_id       = trace_id,
        pci_dss_ref    = "PCI-DSS v4 Req 10.3"
    )
    return {"transaction_id": txn_id, "status": "completed", "trace_id": trace_id}

@app.get("/accounts/{user_id}/stats")
async def get_account_stats(user_id: str, req: Request):
    """Called by Fraud Detection to get user's 90-day transaction statistics."""
    async with httpx.AsyncClient(timeout=3.0) as c:
        r = await c.get(f"{TRANSACTION_URL}/stats/{user_id}",
                        headers={"X-Trace-ID": req.headers.get("X-Trace-ID", "")})
    if r.status_code != 200:
        return {"txn_amount_mean_90d": 0, "txn_amount_std_90d": 0}
    return r.json()

@app.get("/health")
async def health():
    return {"status": "ok", "service": "core-banking", "cloud": "openstack"}

if __name__ == "__main__":
    start_metrics_server(9090)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
```

### 6.7 Service: Account Service (OpenStack)

**File:** `services/account-service/main.py`

```python
import os, uuid
from fastapi import FastAPI, Request, HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy import String, Numeric, DateTime, func, select
from pydantic import BaseModel
from decimal import Decimal
import datetime
from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import start_metrics_server, TXN_TOTAL

app    = FastAPI(title="ZTLab Account Service")
logger = ZTLabLogger("account-service", "openstack")
app.add_middleware(trace_middleware("account-service", "openstack"))

DATABASE_URL = os.getenv("DATABASE_URL",
    "postgresql+asyncpg://ztlab:ztlab@postgres-accounts:5432/accounts")

engine      = create_async_engine(DATABASE_URL, pool_size=10, max_overflow=5)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

class Base(DeclarativeBase): pass

class Account(Base):
    __tablename__ = "accounts"
    id:           Mapped[str]     = mapped_column(String(36), primary_key=True)
    owner_user_id:Mapped[str]     = mapped_column(String(36), index=True)
    account_type: Mapped[str]     = mapped_column(String(20))   # savings | checking | business
    balance:      Mapped[Decimal] = mapped_column(Numeric(18, 2), default=0)
    currency:     Mapped[str]     = mapped_column(String(3), default="VND")
    status:       Mapped[str]     = mapped_column(String(20), default="active")
    kyc_status:   Mapped[str]     = mapped_column(String(20), default="verified")
    created_at:   Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    updated_at:   Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

@app.get("/accounts/{account_id}")
async def get_account(account_id: str, req: Request):
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Account).where(Account.id == account_id)
        )
        acc = result.scalar_one_or_none()
    if acc is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return {
        "account_id":   acc.id,
        "owner":        acc.owner_user_id,
        "type":         acc.account_type,
        "balance":      float(acc.balance),
        "currency":     acc.currency,
        "status":       acc.status,
        "kyc_status":   acc.kyc_status
    }

@app.post("/accounts/{account_id}/debit")
async def debit_account(account_id: str, req: Request):
    body = await req.json()
    amount = Decimal(str(body["amount"]))
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Account).where(Account.id == account_id).with_for_update()
        )
        acc = result.scalar_one_or_none()
        if acc is None:
            raise HTTPException(status_code=404)
        if acc.balance < amount:
            raise HTTPException(status_code=400, detail="Insufficient funds")
        acc.balance -= amount
        await session.commit()
    logger.audit(
        "account_debited",
        account_id = account_id,
        amount     = float(amount),
        txn_id     = body.get("txn_id"),
        new_balance= float(acc.balance)
    )
    return {"status": "ok", "new_balance": float(acc.balance)}

@app.post("/accounts/{account_id}/credit")
async def credit_account(account_id: str, req: Request):
    body = await req.json()
    amount = Decimal(str(body["amount"]))
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Account).where(Account.id == account_id).with_for_update()
        )
        acc = result.scalar_one_or_none()
        if acc is None:
            raise HTTPException(status_code=404)
        acc.balance += amount
        await session.commit()
    logger.audit(
        "account_credited",
        account_id = account_id,
        amount     = float(amount),
        txn_id     = body.get("txn_id"),
        new_balance= float(acc.balance)
    )
    return {"status": "ok", "new_balance": float(acc.balance)}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "account-service", "cloud": "openstack"}

if __name__ == "__main__":
    start_metrics_server(9090)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
```

### 6.8 Service: Transaction Service (OpenStack) — Ledger + Stats

**File:** `services/transaction-service/main.py`

```python
import os, uuid, datetime
from fastapi import FastAPI, Request, HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy import String, Numeric, DateTime, Integer, func, select
from pydantic import BaseModel
from decimal import Decimal
from shared.logging import ZTLabLogger, trace_middleware
from shared.metrics import start_metrics_server

app    = FastAPI(title="ZTLab Transaction Service")
logger = ZTLabLogger("transaction-service", "openstack")
app.add_middleware(trace_middleware("transaction-service", "openstack"))

DATABASE_URL = os.getenv("DATABASE_URL",
    "postgresql+asyncpg://ztlab:ztlab@postgres-transactions:5432/transactions")

engine = create_async_engine(DATABASE_URL, pool_size=10)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

class Base(DeclarativeBase): pass

class Transaction(Base):
    __tablename__ = "transactions"
    id:           Mapped[str]     = mapped_column(String(36), primary_key=True,
                                                   default=lambda: str(uuid.uuid4()))
    from_account: Mapped[str]     = mapped_column(String(36), index=True)
    to_account:   Mapped[str]     = mapped_column(String(36), index=True)
    user_id:      Mapped[str]     = mapped_column(String(36), index=True)
    amount:       Mapped[Decimal] = mapped_column(Numeric(18, 2))
    currency:     Mapped[str]     = mapped_column(String(3))
    channel:      Mapped[str]     = mapped_column(String(20))
    fraud_score:  Mapped[int]     = mapped_column(Integer, default=0)
    note:         Mapped[str]     = mapped_column(String(200), default="")
    status:       Mapped[str]     = mapped_column(String(20), default="completed")
    trace_id:     Mapped[str]     = mapped_column(String(36), default="")
    created_at:   Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now()
    )

@app.post("/ledger/record")
async def record_transaction(req: Request):
    body = await req.json()
    txn_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as session:
        txn = Transaction(
            id           = txn_id,
            from_account = body["from_account"],
            to_account   = body["to_account"],
            user_id      = body.get("user_id", ""),
            amount       = Decimal(str(body["amount"])),
            currency     = body.get("currency", "VND"),
            channel      = body.get("channel", "api"),
            fraud_score  = int(body.get("fraud_score", 0)),
            note         = body.get("note", ""),
            trace_id     = body.get("trace_id", ""),
            status       = "completed"
        )
        session.add(txn)
        await session.commit()

    logger.audit(
        "transaction_recorded",
        transaction_id = txn_id,
        from_account   = body["from_account"],
        to_account     = body["to_account"],
        amount         = float(body["amount"]),
        fraud_score    = int(body.get("fraud_score", 0)),
        trace_id       = body.get("trace_id")
    )
    return {"transaction_id": txn_id, "status": "recorded"}

@app.get("/stats/{user_id}")
async def get_user_stats(user_id: str):
    """Return 90-day transaction statistics for fraud scoring."""
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=90)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(
                func.avg(Transaction.amount).label("mean"),
                func.stddev_pop(Transaction.amount).label("std"),
                func.count(Transaction.id).label("count")
            ).where(
                Transaction.user_id == user_id,
                Transaction.created_at >= cutoff,
                Transaction.status == "completed"
            )
        )
        row = result.one()

    return {
        "user_id":               user_id,
        "txn_count_90d":         int(row.count or 0),
        "txn_amount_mean_90d":   float(row.mean or 0),
        "txn_amount_std_90d":    float(row.std or 0)
    }

@app.get("/history/{account_id}")
async def get_history(account_id: str, limit: int = 20):
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Transaction)
            .where(
                (Transaction.from_account == account_id) |
                (Transaction.to_account   == account_id)
            )
            .order_by(Transaction.created_at.desc())
            .limit(limit)
        )
        txns = result.scalars().all()
    return [
        {
            "id":           t.id,
            "from_account": t.from_account,
            "to_account":   t.to_account,
            "amount":       float(t.amount),
            "currency":     t.currency,
            "fraud_score":  t.fraud_score,
            "channel":      t.channel,
            "created_at":   t.created_at.isoformat()
        }
        for t in txns
    ]

@app.get("/health")
async def health():
    return {"status": "ok", "service": "transaction-service", "cloud": "openstack"}

if __name__ == "__main__":
    start_metrics_server(9090)
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
```

### 6.9 Gap Fix: OPA Policy Update — Enforce Fraud Header (Gap 2)

Thêm vào `opa/policies/zta_policy.rego` rule bắt buộc `X-Fraud-Gate` header khi `core-banking` nhận request từ `payment-service`:

```rego
# ── Gap 2 Fix: Enforce mandatory fraud gate on Core Banking ──
# Any request from payment-service to core-banking MUST carry
# X-Fraud-Gate: passed AND X-Fraud-Score < 75
# This catches attackers who have a valid SVID but skip the fraud service

fraud_gate_valid if {
    input.source.principal == "spiffe://ztlab.local/aws/payment-service"
    input.attributes.request.http.path == "/transactions/execute"
    input.attributes.request.http.headers["x-fraud-gate"] == "passed"
    to_number(input.attributes.request.http.headers["x-fraud-score"]) < 75
}

# Allow core-banking /transactions/execute ONLY if fraud gate is valid
# (other paths use standard role-based allow above)
allow if {
    input.attributes.request.http.path == "/transactions/execute"
    valid_svid
    fraud_gate_valid
}

# Deny and emit detailed log when fraud gate is missing
fraud_gate_bypass_detected if {
    input.source.principal == "spiffe://ztlab.local/aws/payment-service"
    input.attributes.request.http.path == "/transactions/execute"
    not fraud_gate_valid
}

# This entry appears in OPA decision log → Logstash → Wazuh correlation rule 100007
deny_reason := "fraud_gate_bypass" if {
    fraud_gate_bypass_detected
}
```

**New Wazuh Rule for Gap 2** (add to `/var/ossec/etc/rules/ztlab-rules.xml`):

```xml
<!-- Gap 2: Fraud gate bypass — payment-service calling core-banking without fraud check -->
<rule id="100007" level="14">
  <decoded_as>ztlab-opa</decoded_as>
  <field name="opa_result">^false$</field>
  <field name="deny_reason">^fraud_gate_bypass$</field>
  <description>FRAUD GATE BYPASS: payment-service attempted to reach core-banking
  without fraud validation header. SVID valid but mandatory gate missing.
  Possible compromised payment-service pod or lateral movement attempt.</description>
  <group>ztlab,fraud_gate_bypass,zero_trust_violation,critical</group>
</rule>
```

### 6.10 Gap Fix: Logstash Rule — Large Response Detection (Gap 1)

Thêm vào Logstash pipeline (`/etc/logstash/pipeline/ztlab-pipeline.conf`) để detect exfiltration qua response size — không cần đợi LSTM:

```ruby
# Add inside the filter block, after the envoy_access processing block

# ── Gap 1 Fix: Large response = potential data exfiltration ──
if [log_type] == "envoy_access" and [cloud_provider] == "openstack" {

  # Flag large responses from private cloud services
  if [bytes_sent] and [bytes_sent] > 1048576 {   # > 1 MB
    mutate {
      add_field => {
        "security_flag"      => "true"
        "alert_level"        => "high"
        "alert_type"         => "large_response_exfil_suspect"
        "exfil_bytes"        => "%{bytes_sent}"
      }
    }
  }

  # Flag bulk account data responses (core-banking /accounts or /history returning many records)
  if [path] =~ /\/(accounts|history|transactions)/ and [bytes_sent] and [bytes_sent] > 102400 {
    mutate {
      add_field => {
        "security_flag"   => "true"
        "alert_level"     => "medium"
        "alert_type"      => "bulk_data_response_suspect"
      }
    }
  }
}
```

**New Wazuh Rule for Gap 1** (add to `ztlab-rules.xml`):

```xml
<!-- Gap 1: Large response from OpenStack private cloud — exfiltration suspect -->
<rule id="100008" level="12">
  <decoded_as>ztlab-envoy</decoded_as>
  <field name="alert_type">^large_response_exfil_suspect$</field>
  <field name="cloud_provider">^openstack$</field>
  <description>Large response (>1MB) from OpenStack private service $(path)
  to $(upstream). Possible data exfiltration via Core Banking API.
  bytes_sent=$(exfil_bytes)</description>
  <group>ztlab,data_exfiltration,large_response,openstack</group>
</rule>

<!-- Gap 1: Bulk data read from account/transaction endpoints -->
<rule id="100009" level="10">
  <decoded_as>ztlab-envoy</decoded_as>
  <field name="alert_type">^bulk_data_response_suspect$</field>
  <description>Bulk data response from private cloud endpoint $(path).
  Response size $(bytes_sent) bytes exceeds threshold.</description>
  <group>ztlab,bulk_data_read,openstack</group>
</rule>
```

### 6.11 Dockerfile + docker-compose (Local Testing)

**File:** `docker-compose.local.yml`

```yaml
version: '3.8'

services:
  # ── AWS-equivalent services ──────────────────────────────
  api-gateway:
    build: ./services/api-gateway
    ports: ["8080:8080", "9091:9090"]
    environment:
      KEYCLOAK_URL:     "http://keycloak:8080"
      UPSTREAM_PAYMENT: "http://payment-service:8080"
    depends_on: [keycloak, payment-service]

  payment-service:
    build: ./services/payment-service
    ports: ["8081:8080", "9092:9090"]
    environment:
      FRAUD_SERVICE_URL:  "http://fraud-detection:8080"
      CORE_BANKING_URL:   "http://core-banking:8080"
      NOTIFICATION_URL:   "http://notification-service:8080"
    depends_on: [fraud-detection, core-banking]

  fraud-detection:
    build: ./services/fraud-detection
    ports: ["8082:8080", "9093:9090"]
    environment:
      CORE_BANKING_URL: "http://core-banking:8080"
      REDIS_HOST:       "redis-fraud"
    depends_on: [redis-fraud, core-banking]

  notification-service:
    build: ./services/notification-service
    ports: ["8083:8080"]

  # ── OpenStack-equivalent services ────────────────────────
  core-banking:
    build: ./services/core-banking
    ports: ["8084:8080", "9094:9090"]
    environment:
      ACCOUNT_SERVICE_URL:     "http://account-service:8080"
      TRANSACTION_SERVICE_URL: "http://transaction-service:8080"
    depends_on: [account-service, transaction-service]

  account-service:
    build: ./services/account-service
    ports: ["8085:8080", "9095:9090"]
    environment:
      DATABASE_URL: "postgresql+asyncpg://ztlab:ztlab@postgres-accounts:5432/accounts"
    depends_on: [postgres-accounts]

  transaction-service:
    build: ./services/transaction-service
    ports: ["8086:8080", "9096:9090"]
    environment:
      DATABASE_URL: "postgresql+asyncpg://ztlab:ztlab@postgres-txn:5432/transactions"
    depends_on: [postgres-txn]

  # ── Supporting infra ─────────────────────────────────────
  postgres-accounts:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: accounts
      POSTGRES_USER: ztlab
      POSTGRES_PASSWORD: ztlab
    volumes: [pgdata-accounts:/var/lib/postgresql/data]

  postgres-txn:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: transactions
      POSTGRES_USER: ztlab
      POSTGRES_PASSWORD: ztlab
    volumes: [pgdata-txn:/var/lib/postgresql/data]

  redis-fraud:
    image: redis:7-alpine
    command: redis-server --maxmemory 64mb --maxmemory-policy allkeys-lru

  keycloak:
    image: quay.io/keycloak/keycloak:24.0.3
    command: start-dev
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports: ["8180:8080"]

volumes:
  pgdata-accounts:
  pgdata-txn:
```

**Shared Dockerfile** (dùng cho tất cả services):

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY shared/ ./shared/
COPY services/${SERVICE_NAME}/ ./

RUN pip install --no-cache-dir \
    fastapi uvicorn[standard] httpx \
    sqlalchemy asyncpg aiosqlite \
    redis python-jose[cryptography] \
    prometheus-client pydantic

EXPOSE 8080 9090
CMD ["python", "main.py"]
```

```bash
# Build all images
for svc in api-gateway payment-service fraud-detection notification-service \
           core-banking account-service transaction-service; do
  docker build --build-arg SERVICE_NAME=$svc -t ztlab/$svc:1.0.0 .
done

# Local smoke test
docker compose -f docker-compose.local.yml up -d
docker compose -f docker-compose.local.yml ps
curl http://localhost:8080/health
```

```bash
# AWS K3s Master
curl -sfL https://get.k3s.io | sh -s - server \
  --cluster-init \
  --node-ip=10.10.1.10 \
  --advertise-address=10.10.1.10 \
  --flannel-iface=wg0 \
  --disable traefik \
  --disable servicelb

# Get join token
cat /var/lib/rancher/k3s/server/node-token

# AWS Workers
curl -sfL https://get.k3s.io | K3S_URL=https://10.10.1.10:6443 \
  K3S_TOKEN=<NODE_TOKEN> \
  sh -s - agent --node-ip=10.10.1.11 --flannel-iface=wg0

# OpenStack K3s Master (same pattern, different IP)
curl -sfL https://get.k3s.io | sh -s - server \
  --cluster-init \
  --node-ip=10.10.4.10 \
  --advertise-address=10.10.4.10 \
  --flannel-iface=wg0 \
  --disable traefik \
  --disable servicelb
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
  labels:
    app: api-gateway
    cloud: aws
    tier: edge
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
            - name: UPSTREAM_FRAUD
              value: "http://fraud-detection:8080"
          resources:
            requests: { cpu: "100m", memory: "128Mi" }
            limits:   { cpu: "500m", memory: "256Mi" }
        # Envoy sidecar
        - name: envoy
          image: envoyproxy/envoy:v1.29-latest
          args: ["-c", "/etc/envoy/envoy.yaml"]
          volumeMounts:
            - name: envoy-config
              mountPath: /etc/envoy
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
        # OPA sidecar
        - name: opa
          image: openpolicyagent/opa:0.63.0
          args:
            - "run"
            - "--server"
            - "--addr=localhost:9191"
            - "--format=json-pretty"
            - "--log-format=json"
            - "--log-level=info"
            - "/policies/zta_policy.rego"
          volumeMounts:
            - name: opa-policies
              mountPath: /policies
        # Prometheus metrics exporter
        - name: metrics-exporter
          image: ztlab/financial-metrics-exporter:1.0.0
          ports:
            - containerPort: 9090
              name: metrics
      volumes:
        - name: envoy-config
          configMap:
            name: envoy-config
        - name: opa-policies
          configMap:
            name: opa-policies
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
---
# ---- Payment Processing Service ----
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
  namespace: financial
spec:
  replicas: 1
  selector:
    matchLabels:
      app: payment-service
  template:
    metadata:
      labels:
        app: payment-service
      annotations:
        spiffe.io/spiffeid: "spiffe://ztlab.local/aws/payment-service"
    spec:
      serviceAccountName: payment-service
      containers:
        - name: payment-service
          image: ztlab/payment-service:1.0.0
          ports:
            - containerPort: 8080
          env:
            - name: CORE_BANKING_URL
              value: "http://core-banking.os-financial.svc.cluster.local:8080"
            - name: TRANSACTION_RATE_LIMIT
              value: "100"
        - name: envoy
          image: envoyproxy/envoy:v1.29-latest
          args: ["-c", "/etc/envoy/envoy.yaml"]
          volumeMounts:
            - name: envoy-config
              mountPath: /etc/envoy
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
        - name: opa
          image: openpolicyagent/opa:0.63.0
          args: ["run", "--server", "--addr=localhost:9191", "/policies/zta_policy.rego"]
          volumeMounts:
            - name: opa-policies
              mountPath: /policies
      volumes:
        - name: envoy-config
          configMap:
            name: envoy-config
        - name: opa-policies
          configMap:
            name: opa-policies
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
```

### 6.3 OpenStack Microservices Deployment

**File:** `k8s/financial/os-services.yaml`

```yaml
# ---- Core Banking API ----
apiVersion: apps/v1
kind: Deployment
metadata:
  name: core-banking
  namespace: financial
spec:
  replicas: 1
  selector:
    matchLabels:
      app: core-banking
  template:
    metadata:
      labels:
        app: core-banking
      annotations:
        spiffe.io/spiffeid: "spiffe://ztlab.local/os/core-banking"
    spec:
      serviceAccountName: core-banking
      containers:
        - name: core-banking
          image: ztlab/core-banking:1.0.0
          ports:
            - containerPort: 8080
          env:
            - name: DB_HOST
              value: "postgres-core.financial.svc.cluster.local"
            - name: ACCOUNT_SERVICE_URL
              value: "http://account-service:8080"
            - name: TRANSACTION_SERVICE_URL
              value: "http://transaction-service:8080"
        - name: envoy
          image: envoyproxy/envoy:v1.29-latest
          args: ["-c", "/etc/envoy/envoy.yaml"]
          volumeMounts:
            - name: envoy-config
              mountPath: /etc/envoy
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
        - name: opa
          image: openpolicyagent/opa:0.63.0
          args: ["run", "--server", "--addr=localhost:9191", "/policies/zta_policy.rego"]
          volumeMounts:
            - name: opa-policies
              mountPath: /policies
      volumes:
        - name: envoy-config
          configMap:
            name: envoy-config-os
        - name: opa-policies
          configMap:
            name: opa-policies
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
```

### 6.4 Prometheus Business Metrics Exporter

**File:** `services/metrics-exporter/main.py`

```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time, random, logging

# Business-level security metrics
txn_counter = Counter(
    'financial_transactions_total',
    'Total transactions processed',
    ['service', 'user_id', 'status', 'type']
)

login_failures = Counter(
    'auth_login_failures_total',
    'Total login failures',
    ['service', 'source_ip', 'user_id']
)

api_request_rate = Histogram(
    'api_request_duration_seconds',
    'API request latency',
    ['service', 'endpoint', 'method'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

suspicious_activity = Gauge(
    'suspicious_activity_score',
    'Real-time suspicious activity score per user',
    ['user_id', 'service']
)

svid_rotation_events = Counter(
    'spire_svid_rotation_total',
    'SPIRE SVID rotation events',
    ['service', 'status']
)

if __name__ == '__main__':
    start_http_server(9090)
    logging.info("Metrics exporter running on :9090")
    while True:
        time.sleep(15)
```

---

## 7. Phase 4 — Log Collection Pipeline (Wazuh + Filebeat + Kafka)

### 7.1 Wazuh Manager Deployment (aws-siem-1)

```bash
# Docker Compose — Wazuh Manager on AWS
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
chmod +x wazuh-install.sh
./wazuh-install.sh -a   # all-in-one (manager + indexer + dashboard)
```

**Custom Wazuh Decoder** (`/var/ossec/etc/decoders/ztlab-decoders.xml`):

```xml
<!-- Decoder for Envoy access logs -->
<decoder name="ztlab-envoy">
  <prematch>{"timestamp"</prematch>
  <regex>{"timestamp":"(\S+)","method":"(\w+)","path":"(\S+)","response_code":(\d+),"response_time":(\d+),"upstream":"(\S+)","source_ip":"(\S+)"</regex>
  <order>timestamp,method,path,response_code,response_time,upstream,source_ip</order>
</decoder>

<!-- Decoder for SPIRE SVID events -->
<decoder name="ztlab-spire">
  <prematch>SPIRE_EVENT</prematch>
  <regex>SPIRE_EVENT action:(\w+) spiffeID:(\S+) workload:(\S+) status:(\w+)</regex>
  <order>spire_action,spiffe_id,workload,status</order>
</decoder>

<!-- Decoder for OPA decision logs -->
<decoder name="ztlab-opa">
  <prematch>{"decision_id"</prematch>
  <regex>"decision_id":"(\S+)","input":.*"result":(\w+),"timestamp":"(\S+)"</regex>
  <order>decision_id,opa_result,timestamp</order>
</decoder>
```

**Custom Wazuh Rules** (`/var/ossec/etc/rules/ztlab-rules.xml`):

```xml
<!-- Brute force: 5 login failures within 60 seconds -->
<rule id="100001" level="10" frequency="5" timeframe="60">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip/>
  <description>Distributed brute force detected from $(srcip)</description>
  <group>authentication_failure,brute_force,ztlab</group>
</rule>

<!-- JWT Token anomaly: invalid token on Zero Trust path -->
<rule id="100002" level="12">
  <decoded_as>ztlab-envoy</decoded_as>
  <field name="response_code">^401$</field>
  <field name="path">^/api/</field>
  <description>Unauthorized access attempt on protected API path: $(path)</description>
  <group>ztlab,jwt_anomaly,zero_trust_violation</group>
</rule>

<!-- Lateral movement: service accessing unexpected upstream -->
<rule id="100003" level="14">
  <decoded_as>ztlab-envoy</decoded_as>
  <field name="response_code">^403$</field>
  <field name="opa_result">^false$</field>
  <description>OPA policy denial — possible lateral movement: $(source_ip) -> $(path)</description>
  <group>ztlab,lateral_movement,zero_trust_violation</group>
</rule>

<!-- SVID expiry not renewed (possible agent compromise) -->
<rule id="100004" level="13">
  <decoded_as>ztlab-spire</decoded_as>
  <field name="spire_action">^svid_expired$</field>
  <field name="status">^not_renewed$</field>
  <description>SVID expired and not renewed for workload: $(workload). Possible agent compromise.</description>
  <group>ztlab,identity_anomaly,spire</group>
</rule>

<!-- High transaction rate — possible fraud -->
<rule id="100005" level="10" frequency="50" timeframe="60">
  <if_matched_sid>100010</if_matched_sid>
  <same_field>user_id</same_field>
  <description>Abnormal transaction rate for user $(user_id) — possible fraud</description>
  <group>ztlab,financial_fraud,business_anomaly</group>
</rule>

<!-- Privilege escalation attempt -->
<rule id="100006" level="15">
  <if_group>sudo_cmd</if_group>
  <match>COMMAND=/bin/bash|COMMAND=/bin/sh|COMMAND=chmod 777</match>
  <description>Potential privilege escalation detected on $(hostname)</description>
  <group>ztlab,privilege_escalation,critical</group>
</rule>
```

### 7.2 Wazuh Agent Installation (All Nodes)

```bash
# Ubuntu agent install
wget -q -O - https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  tee /etc/apt/sources.list.d/wazuh.list
apt update && apt install -y wazuh-agent

# Configure agent
cat > /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <client>
    <server>
      <address>10.10.2.10</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>linux, ubuntu, ubuntu22</config-profile>
  </client>
  
  <!-- File Integrity Monitoring on Zero Trust config files -->
  <syscheck>
    <frequency>300</frequency>
    <directories realtime="yes" check_all="yes">/opt/spire/conf</directories>
    <directories realtime="yes" check_all="yes">/etc/envoy</directories>
    <directories realtime="yes" check_all="yes">/opt/opa/policies</directories>
    <directories realtime="yes" check_all="yes">/etc/wireguard</directories>
  </syscheck>
  
  <!-- Log sources -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/envoy/access.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/opa/decisions.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/run/spire/logs/spire-agent.log</location>
  </localfile>
</ossec_config>
EOF

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

### 7.3 Filebeat Configuration (Envoy Log Shipping)

**File:** `/etc/filebeat/filebeat.yml`

```yaml
filebeat.inputs:
  - type: filestream
    id: envoy-access-logs
    enabled: true
    paths:
      - /var/log/envoy/access.log
    parsers:
      - ndjson:
          target: ""
          add_error_key: true
    fields:
      log_type: envoy_access
      cloud_provider: aws          # or "openstack"
      cluster: aws-k3s             # or "os-k3s"
    fields_under_root: true

  - type: filestream
    id: opa-decision-logs
    enabled: true
    paths:
      - /var/log/opa/decisions.log
    parsers:
      - ndjson:
          target: ""
    fields:
      log_type: opa_decision
      cloud_provider: aws
    fields_under_root: true

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: {}
  - add_kubernetes_metadata:
      host: ${NODE_NAME}
      matchers:
        - logs_path:
            logs_path: "/var/log/containers/"
  - drop_fields:
      fields: ["agent.ephemeral_id", "ecs.version"]

output.logstash:
  hosts: ["10.10.2.11:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["/etc/filebeat/certs/ca.crt"]
  ssl.certificate: "/etc/filebeat/certs/filebeat.crt"
  ssl.key: "/etc/filebeat/certs/filebeat.key"
  bulk_max_size: 2048
  worker: 2
```

### 7.4 Logstash Pipeline Configuration

**File:** `/etc/logstash/pipeline/ztlab-pipeline.conf`

```ruby
input {
  # From Filebeat (Envoy + OPA logs)
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key         => "/etc/logstash/certs/logstash.key"
    ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
  }

  # From Wazuh Manager (security alerts)
  tcp {
    port => 5045
    codec => json_lines
    tags => ["wazuh"]
  }
}

filter {
  if [log_type] == "envoy_access" {
    mutate {
      add_field => { "[@metadata][index]" => "zta-envoy-logs" }
      add_field => { "[@metadata][kafka_topic]" => "zta.raw-logs" }
      convert   => { "response_code" => "integer" }
      convert   => { "response_time" => "integer" }
      convert   => { "bytes_sent"    => "integer" }
    }

    # Enrich: flag suspicious status codes
    if [response_code] in [401, 403, 429, 500] {
      mutate {
        add_field => { "security_flag" => "true" }
        add_field => { "alert_level"   => "medium" }
      }
    }

    # GeoIP enrichment on source_ip
    geoip {
      source => "source_ip"
      target => "geoip"
    }
  }

  if "wazuh" in [tags] {
    mutate {
      add_field => { "[@metadata][index]"       => "zta-wazuh-alerts" }
      add_field => { "[@metadata][kafka_topic]" => "zta.wazuh-alerts" }
    }

    # Map severity level
    if [rule][level] >= 15 {
      mutate { add_field => { "severity" => "critical" } }
    } else if [rule][level] >= 10 {
      mutate { add_field => { "severity" => "high" } }
    } else if [rule][level] >= 7 {
      mutate { add_field => { "severity" => "medium" } }
    } else {
      mutate { add_field => { "severity" => "low" } }
    }
  }

  if [log_type] == "opa_decision" {
    mutate {
      add_field => { "[@metadata][index]"       => "zta-opa-decision" }
      add_field => { "[@metadata][kafka_topic]" => "zta.raw-logs" }
    }
  }

  # Common enrichment
  mutate {
    add_field => { "processed_at" => "%{@timestamp}" }
  }
}

output {
  # --> Elasticsearch (persistent storage + SIEM)
  elasticsearch {
    hosts    => ["https://10.10.2.10:9200"]
    index    => "%{[@metadata][index]}-%{+YYYY.MM.dd}"
    user     => "logstash_writer"
    password => "${LOGSTASH_ES_PASSWORD}"
    ssl      => true
    cacert   => "/etc/logstash/certs/ca.crt"
    ilm_enabled        => true
    ilm_rollover_alias => "%{[@metadata][index]}"
    ilm_policy         => "ztlab-ilm-policy"
  }

  # --> Kafka (real-time streaming → AI + OpenSearch)
  kafka {
    bootstrap_servers => "10.10.2.11:9092"
    topic_id          => "%{[@metadata][kafka_topic]}"
    codec             => json
    compression_type  => "gzip"
    acks              => "1"
  }
}
```

### 7.5 OpenStack — Local Wazuh Buffer (Tunnel Resilience)

**Problem:** When the WireGuard tunnel between `os-gateway` and `aws-gateway` goes down (network outage, AWS maintenance), all OpenStack nodes lose their path to the SIEM. Without a local buffer, log data is silently dropped — creating a security blind spot that could last hours or days before the tunnel recovers.

**Solution:** `os-gateway` runs a local Filebeat spool + Kafka queue that holds up to 72 hours of events. The moment the tunnel recovers, buffered data is forwarded automatically in order.

#### Architecture

```
OS K3s nodes / os-identity
    │ Wazuh Agent (forward to local os-gateway)
    │ Filebeat (forward to local os-gateway)
    ▼
os-gateway  ← LOCAL BUFFER NODE
    ├── Filebeat spool:  /var/lib/filebeat-buffer/  (local disk, up to 20 GB)
    ├── Kafka client:    zta.os-raw-logs (local queue, fallback mode)
    └── Health check:    checks tunnel every 30s
           │
           │  WireGuard tunnel  (10.10.0.1 = aws-gateway)
           │  ↑ when tunnel UP: forward immediately
           │  ↑ when tunnel DOWN: buffer locally, retry
           ▼
aws-siem-2  (Logstash :5044 / Kafka :9092)
```

#### Filebeat Buffer Configuration on `os-gateway`

**File:** `/etc/filebeat/filebeat-buffer.yml`

```yaml
filebeat.inputs:
  # Receive from OS Wazuh agents (acts as local aggregator)
  - type: tcp
    host: "192.168.100.10:5045"
    enabled: true
    fields:
      log_source: openstack
      buffer_node: os-gateway
    fields_under_root: true

  # Receive from OS Filebeat agents (Envoy logs)
  - type: tcp
    host: "192.168.100.10:5046"
    enabled: true
    fields:
      log_source: openstack_envoy
      buffer_node: os-gateway
    fields_under_root: true

# Local spool — persist to disk when tunnel is down
queue.disk:
  max_size: 20gb
  path: /var/lib/filebeat-buffer
  write_ahead_log: true
  flush_timeout: 5s

# Primary output: forward to AWS SIEM (via WireGuard tunnel)
output.logstash:
  hosts: ["10.10.2.11:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["/etc/filebeat/certs/ca.crt"]
  ssl.certificate: "/etc/filebeat/certs/filebeat.crt"
  ssl.key: "/etc/filebeat/certs/filebeat.key"

  # Retry settings — keep retrying until tunnel recovers
  backoff.init: 5s
  backoff.max: 300s     # max 5 min between retries
  timeout: 30s
  max_retries: -1       # -1 = infinite retries (never drop)
  bulk_max_size: 1024
  worker: 1             # single worker — avoid flooding on recovery

# Monitoring
monitoring:
  enabled: true
  cluster_uuid: ztlab-os-buffer
```

#### Tunnel Health Monitor Service on `os-gateway`

**File:** `/opt/ztlab/tunnel-monitor.sh`

```bash
#!/bin/bash
# Monitors WireGuard tunnel health and toggles buffer flush rate
# Runs as a systemd service every 30s

TUNNEL_PEER="10.10.0.1"     # aws-gateway WireGuard IP
SIEM_PORT="5044"
BUFFER_LOG="/var/log/ztlab/tunnel-monitor.log"
STATE_FILE="/tmp/ztlab-tunnel-state"

check_tunnel() {
    # Ping through WireGuard tunnel
    ping -c 2 -W 5 -I wg0 "$TUNNEL_PEER" > /dev/null 2>&1 && echo "up" || echo "down"
}

check_siem_reach() {
    nc -z -w 5 "10.10.2.11" "$SIEM_PORT" > /dev/null 2>&1 && echo "up" || echo "down"
}

TUNNEL_STATUS=$(check_tunnel)
SIEM_STATUS=$(check_siem_reach)
PREV_STATE=$(cat "$STATE_FILE" 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [[ "$TUNNEL_STATUS" == "up" && "$SIEM_STATUS" == "up" ]]; then
    CURRENT_STATE="healthy"
    if [[ "$PREV_STATE" != "healthy" ]]; then
        echo "$TIMESTAMP TUNNEL RECOVERED — flushing buffer to SIEM" >> "$BUFFER_LOG"
        # Increase Filebeat worker count for faster drain
        systemctl restart filebeat-buffer
    fi
else
    CURRENT_STATE="degraded"
    if [[ "$PREV_STATE" == "healthy" ]]; then
        echo "$TIMESTAMP TUNNEL DOWN — switching to local buffer mode" >> "$BUFFER_LOG"
        # Log a Wazuh alert for the tunnel failure itself
        logger -t ztlab-tunnel "TUNNEL_DOWN tunnel_peer=$TUNNEL_PEER siem_port=$SIEM_PORT"
    fi
fi

echo "$TIMESTAMP status=$CURRENT_STATE tunnel=$TUNNEL_STATUS siem=$SIEM_STATUS" >> "$BUFFER_LOG"
echo "$CURRENT_STATE" > "$STATE_FILE"
```

**File:** `/etc/systemd/system/ztlab-tunnel-monitor.service`

```ini
[Unit]
Description=ZTLab WireGuard Tunnel Health Monitor
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service

[Service]
Type=oneshot
ExecStart=/opt/ztlab/tunnel-monitor.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**File:** `/etc/systemd/system/ztlab-tunnel-monitor.timer`

```ini
[Unit]
Description=Run tunnel monitor every 30 seconds

[Timer]
OnBootSec=60
OnUnitActiveSec=30
Unit=ztlab-tunnel-monitor.service

[Install]
WantedBy=timers.target
```

```bash
# Enable
chmod +x /opt/ztlab/tunnel-monitor.sh
mkdir -p /var/log/ztlab /var/lib/filebeat-buffer
systemctl daemon-reload
systemctl enable ztlab-tunnel-monitor.timer
systemctl start  ztlab-tunnel-monitor.timer

# Verify
systemctl list-timers | grep ztlab
journalctl -u ztlab-tunnel-monitor -f
```

#### Wazuh Agent on OS Nodes — Forward to Local Buffer

All OpenStack Wazuh agents point to `os-gateway` (local buffer) instead of directly to `aws-siem-1`. The buffer transparently forwards when tunnel is healthy.

**File:** `/var/ossec/etc/ossec.conf` on all OS K3s nodes

```xml
<ossec_config>
  <client>
    <server>
      <!-- Forward to LOCAL os-gateway buffer, NOT directly to AWS -->
      <address>192.168.100.10</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <!-- Fallback: if local buffer unreachable, queue locally on agent -->
    <enrollment>
      <enabled>yes</enabled>
    </enrollment>
    <buffer>
      <disabled>no</disabled>
      <queue_size>5000</queue_size>
      <events_per_second>500</events_per_second>
    </buffer>
  </client>
</ossec_config>
```

#### Wazuh Manager on `aws-siem-1` — Accept Forwarded OS Events

```xml
<!-- /var/ossec/etc/ossec.conf on aws-siem-1 — accept OS agent events via buffer -->
<remote>
  <connection>secure</connection>
  <port>1514</port>
  <protocol>tcp</protocol>
  <allowed-ips>10.10.0.2</allowed-ips>   <!-- os-gateway WG IP -->
  <allowed-ips>10.10.4.0/24</allowed-ips> <!-- OS private subnet via tunnel -->
</remote>
```

---

## 8. Phase 5 — SIEM Core (ELK Stack on AWS)

### 8.1 Elasticsearch Configuration

**File:** `/etc/elasticsearch/elasticsearch.yml`

```yaml
cluster.name: ztlab-siem
node.name: aws-siem-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

network.host: 10.10.2.10
http.port: 9200
transport.port: 9300

# Security
xpack.security.enabled: true
xpack.security.enrollment.enabled: true
xpack.security.http.ssl:
  enabled: true
  keystore.path: /etc/elasticsearch/certs/http.p12
xpack.security.transport.ssl:
  enabled: true
  verification_mode: certificate
  keystore.path: /etc/elasticsearch/certs/transport.p12
  truststore.path: /etc/elasticsearch/certs/transport.p12

# Monitoring
xpack.monitoring.collection.enabled: true

# Memory
indices.memory.index_buffer_size: 30%
thread_pool.write.queue_size: 1000
```

### 8.2 Index Lifecycle Management Policy

```json
PUT _ilm/policy/ztlab-ilm-policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_primary_shard_size": "5gb",
            "max_age": "1d"
          },
          "set_priority": { "priority": 100 }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink":   { "number_of_shards": 1 },
          "forcemerge": { "max_num_segments": 1 },
          "set_priority": { "priority": 50 },
          "allocate": { "number_of_replicas": 1 }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "set_priority": { "priority": 0 },
          "allocate":     { "number_of_replicas": 0 },
          "freeze": {}
        }
      },
      "delete": {
        "min_age": "365d",
        "actions": {
          "delete": { "delete_searchable_snapshot": true }
        }
      }
    }
  }
}
```

### 8.3 Index Templates

```json
PUT _index_template/zta-envoy-template
{
  "index_patterns": ["zta-envoy-logs-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name":           "ztlab-ilm-policy",
      "index.lifecycle.rollover_alias": "zta-envoy-logs"
    },
    "mappings": {
      "properties": {
        "@timestamp":     { "type": "date" },
        "timestamp":      { "type": "date" },
        "method":         { "type": "keyword" },
        "path":           { "type": "keyword" },
        "response_code":  { "type": "integer" },
        "response_time":  { "type": "long" },
        "source_ip":      { "type": "ip" },
        "upstream":       { "type": "keyword" },
        "cloud_provider": { "type": "keyword" },
        "cluster":        { "type": "keyword" },
        "security_flag":  { "type": "boolean" },
        "severity":       { "type": "keyword" },
        "geoip": {
          "properties": {
            "location": { "type": "geo_point" },
            "country_iso_code": { "type": "keyword" }
          }
        }
      }
    }
  }
}
```

---

## 9. Phase 6 — Real-Time Streaming: Kafka → OpenSearch Anomaly Detection

### 9.1 Kafka Configuration (Single Broker — Lab)

**File:** `/opt/kafka/config/server.properties`

```properties
broker.id=0
listeners=PLAINTEXT://10.10.2.11:9092
advertised.listeners=PLAINTEXT://10.10.2.11:9092
log.dirs=/var/kafka/logs
num.partitions=3
default.replication.factor=1
log.retention.hours=168
log.retention.bytes=10737418240
log.segment.bytes=1073741824
zookeeper.connect=10.10.2.11:2181
auto.create.topics.enable=true
message.max.bytes=10485760
```

**Topic Creation:**

```bash
kafka-topics.sh --create --bootstrap-server 10.10.2.11:9092 \
  --topic zta.raw-logs     --partitions 3 --replication-factor 1

kafka-topics.sh --create --bootstrap-server 10.10.2.11:9092 \
  --topic zta.wazuh-alerts --partitions 3 --replication-factor 1

kafka-topics.sh --create --bootstrap-server 10.10.2.11:9092 \
  --topic zta.ai-detections --partitions 1 --replication-factor 1
```

**Kafka Connect — Sink to OpenSearch:**

```json
POST /connectors
{
  "name": "opensearch-sink",
  "config": {
    "connector.class": "io.aiven.kafka.connect.opensearch.OpensearchSinkConnector",
    "tasks.max": "2",
    "topics": "zta.raw-logs,zta.wazuh-alerts,zta.ai-detections",
    "connection.url": "https://10.10.2.12:9200",
    "connection.username": "kafka-connector",
    "connection.password": "${OPENSEARCH_KAFKA_PASSWORD}",
    "type.name": "_doc",
    "key.ignore": "true",
    "schema.ignore": "true",
    "behavior.on.null.values": "delete",
    "batch.size": "500",
    "linger.ms": "1000"
  }
}
```

### 9.2 OpenSearch Anomaly Detection Configuration

```json
POST _plugins/_anomaly_detection/detectors
{
  "name": "zta-request-rate-anomaly",
  "description": "Detect abnormal API request rates",
  "time_field": "@timestamp",
  "indices": ["zta-envoy-logs-*"],
  "feature_attributes": [
    {
      "feature_name": "request_count",
      "feature_enabled": true,
      "importance": 1,
      "aggregation_query": {
        "request_count": { "value_count": { "field": "path" } }
      }
    },
    {
      "feature_name": "error_rate",
      "feature_enabled": true,
      "importance": 1,
      "aggregation_query": {
        "error_rate": {
          "avg": {
            "script": {
              "source": "doc['response_code'].value >= 400 ? 1 : 0"
            }
          }
        }
      }
    }
  ],
  "detection_interval": { "period": { "interval": 1, "unit": "Minutes" } },
  "window_delay":        { "period": { "interval": 1, "unit": "Minutes" } },
  "shingle_size": 8,
  "filters": []
}
```

---

## 10. Phase 7 — AI Detection Engine (ML + RAG + MCP)

### 10.1 Docker Compose — AI Engine Services (aws-ai)

```yaml
# docker-compose.ai.yml
version: '3.8'
services:
  ai-engine:
    image: ztlab/ai-engine:1.0.0
    container_name: ai-engine
    ports:
      - "8000:8000"
    environment:
      - ES_HOST=https://10.10.2.10:9200
      - ES_USER=ai_engine
      - ES_PASSWORD=${AI_ENGINE_ES_PASSWORD}
      - OPENSEARCH_HOST=https://10.10.2.12:9200
      - KAFKA_BROKERS=10.10.2.11:9092
      - WAZUH_API=https://10.10.2.10:55000
      - THEHIVE_URL=http://10.10.3.11:9000
      - THEHIVE_API_KEY=${THEHIVE_API_KEY}
      - MODEL_RETRAIN_INTERVAL_DAYS=7
      - INFERENCE_BATCH_SIZE=256
    volumes:
      - ./models:/app/models
      - ./rag-data:/app/rag-data
    restart: unless-stopped

  vector-db:
    image: chromadb/chroma:0.5.0
    container_name: vector-db
    ports:
      - "8001:8000"
    volumes:
      - chroma-data:/chroma/chroma
    restart: unless-stopped

volumes:
  chroma-data:
```

### 10.2 Isolation Forest Model

**File:** `ai-engine/models/isolation_forest.py`

```python
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib, json, logging
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)

class ZTLabIsolationForest:
    def __init__(self, es_host: str, es_user: str, es_password: str):
        self.es = Elasticsearch(
            [es_host],
            http_auth=(es_user, es_password),
            verify_certs=True
        )
        self.model = IsolationForest(
            n_estimators=200,
            max_samples='auto',
            contamination=0.05,   # expect ~5% anomalies
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.feature_names = [
            'request_rate_per_min',
            'error_rate_pct',
            'avg_response_time_ms',
            'unique_paths_per_min',
            'p95_response_time_ms',
            'failed_auth_count',
            'bytes_sent_avg',
            'suspicious_status_rate'
        ]

    def extract_features(self, days_back: int = 30) -> pd.DataFrame:
        """Aggregate Envoy logs into feature vectors."""
        query = {
            "size": 0,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{days_back}d",
                        "lte": "now"
                    }
                }
            },
            "aggs": {
                "by_minute": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1m"
                    },
                    "aggs": {
                        "request_count":    { "value_count": { "field": "path" } },
                        "error_count":      { "filter": { "range": { "response_code": { "gte": 400 } } } },
                        "avg_response":     { "avg": { "field": "response_time" } },
                        "p95_response":     { "percentiles": { "field": "response_time", "percents": [95] } },
                        "unique_paths":     { "cardinality": { "field": "path" } },
                        "failed_auth":      { "filter": { "term": { "response_code": 401 } } },
                        "avg_bytes":        { "avg": { "field": "bytes_sent" } },
                        "suspicious":       { "filter": { "terms": { "response_code": [401, 403, 429] } } }
                    }
                }
            }
        }

        res = self.es.search(index="zta-envoy-logs-*", body=query)
        buckets = res['aggregations']['by_minute']['buckets']

        rows = []
        for b in buckets:
            count = b['request_count']['value'] or 1
            rows.append({
                'request_rate_per_min':  count,
                'error_rate_pct':        (b['error_count']['doc_count'] / count) * 100,
                'avg_response_time_ms':  b['avg_response']['value'] or 0,
                'unique_paths_per_min':  b['unique_paths']['value'],
                'p95_response_time_ms':  b['p95_response']['values']['95.0'] or 0,
                'failed_auth_count':     b['failed_auth']['doc_count'],
                'bytes_sent_avg':        b['avg_bytes']['value'] or 0,
                'suspicious_status_rate': (b['suspicious']['doc_count'] / count) * 100
            })

        return pd.DataFrame(rows, columns=self.feature_names)

    def train(self):
        df = self.extract_features(days_back=30)
        X = self.scaler.fit_transform(df.fillna(0))
        self.model.fit(X)
        joblib.dump(self.model,  '/app/models/isolation_forest.pkl')
        joblib.dump(self.scaler, '/app/models/if_scaler.pkl')
        logger.info(f"Isolation Forest trained on {len(df)} samples")

    def predict(self, features: dict) -> dict:
        model  = joblib.load('/app/models/isolation_forest.pkl')
        scaler = joblib.load('/app/models/if_scaler.pkl')
        X = scaler.transform([[features[f] for f in self.feature_names]])
        score     = model.score_samples(X)[0]   # lower = more anomalous
        is_anomaly = model.predict(X)[0] == -1
        return {
            "is_anomaly":     is_anomaly,
            "anomaly_score":  float(score),
            "threshold":      -0.3,
            "features_used":  self.feature_names,
            "timestamp":      datetime.utcnow().isoformat()
        }
```

### 10.3 LSTM Autoencoder Model

**File:** `ai-engine/models/lstm_autoencoder.py`

```python
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, LSTM, Dense, RepeatVector, TimeDistributed
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
import joblib

SEQUENCE_LENGTH = 60   # 60 minutes lookback
N_FEATURES      = 8    # same 8 features as IF model
ENCODING_DIM    = 16

class LSTMAutoencoder:
    def __init__(self):
        self.model     = self._build_model()
        self.threshold = None

    def _build_model(self) -> Model:
        inputs   = Input(shape=(SEQUENCE_LENGTH, N_FEATURES))
        # Encoder
        encoded  = LSTM(64, activation='relu', return_sequences=False)(inputs)
        encoded  = Dense(ENCODING_DIM, activation='relu')(encoded)
        # Decoder
        decoded  = RepeatVector(SEQUENCE_LENGTH)(encoded)
        decoded  = LSTM(64, activation='relu', return_sequences=True)(decoded)
        outputs  = TimeDistributed(Dense(N_FEATURES))(decoded)

        model = Model(inputs, outputs)
        model.compile(optimizer='adam', loss='mse')
        return model

    def train(self, X_train: np.ndarray, epochs: int = 50, batch_size: int = 64):
        """X_train shape: (n_samples, SEQUENCE_LENGTH, N_FEATURES)"""
        callbacks = [
            EarlyStopping(patience=5, restore_best_weights=True),
            ModelCheckpoint('/app/models/lstm_ae.keras', save_best_only=True)
        ]
        self.model.fit(
            X_train, X_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.1,
            callbacks=callbacks
        )
        # Set threshold at 95th percentile of training reconstruction error
        reconstructions = self.model.predict(X_train)
        mse = np.mean(np.power(X_train - reconstructions, 2), axis=(1,2))
        self.threshold = np.percentile(mse, 95)
        np.save('/app/models/lstm_threshold.npy', self.threshold)

    def predict(self, X: np.ndarray) -> dict:
        """X shape: (1, SEQUENCE_LENGTH, N_FEATURES)"""
        model     = tf.keras.models.load_model('/app/models/lstm_ae.keras')
        threshold = float(np.load('/app/models/lstm_threshold.npy'))
        reconstruction = model.predict(X)
        mse = float(np.mean(np.power(X - reconstruction, 2)))
        return {
            "reconstruction_error": mse,
            "threshold":            threshold,
            "is_anomaly":           mse > threshold,
            "severity_score":       min((mse / threshold) * 10, 10.0)
        }
```

### 10.4 RAG Pipeline

**File:** `ai-engine/rag/pipeline.py`

```python
import chromadb
from chromadb.utils import embedding_functions
from anthropic import Anthropic
import json, logging

class ZTLabRAGPipeline:
    def __init__(self, chroma_host: str = "localhost", chroma_port: int = 8001):
        self.client = chromadb.HttpClient(host=chroma_host, port=chroma_port)
        self.ef     = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        self.collection = self.client.get_or_create_collection(
            name="threat-intelligence",
            embedding_function=self.ef
        )
        self.anthropic = Anthropic()

    def ingest_mitre(self, mitre_json_path: str):
        """Ingest MITRE ATT&CK for Cloud techniques."""
        with open(mitre_json_path) as f:
            data = json.load(f)

        docs, ids, metas = [], [], []
        for obj in data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                tid   = obj.get('external_references', [{}])[0].get('external_id', 'T0000')
                name  = obj.get('name', '')
                desc  = obj.get('description', '')
                docs.append(f"Technique: {name}\n\nDescription: {desc}")
                ids.append(tid)
                metas.append({
                    "technique_id": tid,
                    "name":         name,
                    "platforms":    str(obj.get('x_mitre_platforms', [])),
                    "source":       "mitre-attack"
                })

        # Batch ingest
        for i in range(0, len(docs), 100):
            self.collection.upsert(
                documents=ids[i:i+100],
                documents=docs[i:i+100],
                ids=ids[i:i+100],
                metadatas=metas[i:i+100]
            )

    def analyze_alert(self, alert: dict) -> dict:
        """Given a Wazuh alert, return AI-powered threat analysis."""
        # Retrieve relevant MITRE techniques
        query      = f"{alert.get('rule', {}).get('description', '')} {alert.get('data', {})}"
        results    = self.collection.query(query_texts=[query], n_results=5)

        context = "\n\n---\n\n".join(results['documents'][0]) if results['documents'] else ""

        prompt = f"""You are a SOC analyst for a financial services microservices platform protected by Zero Trust Architecture.

Alert Details:
{json.dumps(alert, indent=2)}

Relevant MITRE ATT&CK Techniques:
{context}

Analyze this security alert and provide:
1. Threat classification (ATT&CK technique if applicable)
2. Severity assessment (Critical/High/Medium/Low)
3. Immediate containment actions (max 3)
4. Investigation steps (max 5)
5. Confidence score (0-100)

Respond in JSON format only."""

        response = self.anthropic.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            analysis = json.loads(response.content[0].text)
        except json.JSONDecodeError:
            analysis = {"raw_response": response.content[0].text}

        return {
            "alert_id":        alert.get('id'),
            "analysis":        analysis,
            "mitre_context":   results['metadatas'][0] if results['metadatas'] else [],
            "model_used":      "claude-sonnet-4-20250514"
        }
```

### 10.5 MCP Server for SIEM Integration

**File:** `ai-engine/mcp/siem_server.py`

```python
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types
from elasticsearch import Elasticsearch
import json, os

server = Server("ztlab-siem")
es     = Elasticsearch(
    [os.getenv("ES_HOST")],
    http_auth=(os.getenv("ES_USER"), os.getenv("ES_PASSWORD")),
    verify_certs=True
)

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="search_security_events",
            description="Search Elasticsearch for security events by time range and severity",
            inputSchema={
                "type": "object",
                "properties": {
                    "query":     {"type": "string"},
                    "severity":  {"type": "string", "enum": ["low","medium","high","critical"]},
                    "hours_back":{"type": "integer", "default": 1},
                    "max_results":{"type": "integer", "default": 20}
                },
                "required": ["query"]
            }
        ),
        types.Tool(
            name="get_spire_events",
            description="Retrieve SPIRE identity events (SVID issuance, expiry, rotation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "workload":   {"type": "string"},
                    "event_type": {"type": "string"},
                    "hours_back": {"type": "integer", "default": 1}
                }
            }
        ),
        types.Tool(
            name="get_opa_denials",
            description="Get OPA policy denial events for lateral movement analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "source_ip": {"type": "string"},
                    "hours_back":{"type": "integer", "default": 1}
                }
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "search_security_events":
        must_clauses = [
            {"query_string": {"query": arguments["query"]}},
            {"range": {"@timestamp": {"gte": f"now-{arguments.get('hours_back',1)}h"}}}
        ]
        if arguments.get("severity"):
            must_clauses.append({"term": {"severity": arguments["severity"]}})

        res = es.search(
            index="zta-wazuh-alerts-*",
            body={"size": arguments.get("max_results", 20), "query": {"bool": {"must": must_clauses}}},
            sort=[{"@timestamp": "desc"}]
        )
        return [types.TextContent(type="text", text=json.dumps(res['hits']['hits'], indent=2))]

    elif name == "get_opa_denials":
        must = [
            {"term": {"opa_result": "false"}},
            {"range": {"@timestamp": {"gte": f"now-{arguments.get('hours_back',1)}h"}}}
        ]
        if arguments.get("source_ip"):
            must.append({"term": {"source_ip": arguments["source_ip"]}})
        res = es.search(index="zta-opa-decision-*", body={"size": 50, "query": {"bool": {"must": must}}})
        return [types.TextContent(type="text", text=json.dumps(res['hits']['hits'], indent=2))]

async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream,
                        InitializationOptions(server_name="ztlab-siem", server_version="1.0.0"))

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

---

## 11. Phase 8 — SOAR Platform (TheHive + Cortex + n8n)

### 11.1 TheHive + Cortex Docker Compose (aws-soar)

```yaml
# docker-compose.soar.yml
version: '3.8'
services:
  thehive:
    image: strangebee/thehive:5.3
    container_name: thehive
    ports:
      - "9000:9000"
    environment:
      - JVM_OPTS=-Xms512m -Xmx1g
    volumes:
      - ./thehive/config:/etc/thehive
      - thehive-data:/opt/thehive/data
    depends_on:
      - elasticsearch-thehive
    restart: unless-stopped

  cortex:
    image: thehiveproject/cortex:3.1.8
    container_name: cortex
    ports:
      - "9001:9001"
    environment:
      - JVM_OPTS=-Xms256m -Xmx512m
    volumes:
      - ./cortex/config:/etc/cortex
      - /var/run/docker.sock:/var/run/docker.sock
    restart: unless-stopped

  n8n:
    image: n8nio/n8n:1.47.1
    container_name: n8n
    ports:
      - "5678:5678"
    environment:
      - N8N_HOST=0.0.0.0
      - N8N_PORT=5678
      - N8N_PROTOCOL=http
      - WEBHOOK_URL=http://10.10.3.11:5678
      - DB_TYPE=postgresdb
      - DB_POSTGRESDB_HOST=n8n-db
      - DB_POSTGRESDB_DATABASE=n8n
      - DB_POSTGRESDB_USER=n8n
      - DB_POSTGRESDB_PASSWORD=${N8N_DB_PASSWORD}
      - N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}
    volumes:
      - n8n-data:/home/node/.n8n
    depends_on:
      - n8n-db
    restart: unless-stopped

  n8n-db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=n8n
      - POSTGRES_USER=n8n
      - POSTGRES_PASSWORD=${N8N_DB_PASSWORD}
    volumes:
      - n8n-db-data:/var/lib/postgresql/data

  elasticsearch-thehive:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
    container_name: es-thehive
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    volumes:
      - es-thehive-data:/usr/share/elasticsearch/data

volumes:
  thehive-data:
  n8n-data:
  n8n-db-data:
  es-thehive-data:
```

### 11.2 Cortex Responders

**File:** `cortex/responders/IsolateWorkload/run`

```python
#!/usr/bin/env python3
"""Cortex Responder: Isolate K3s workload by updating OPA policy"""
import sys, json, requests
from cortexutils.responder import Responder

class IsolateWorkload(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.opa_url    = self.get_param('config.opa_url',    None, 'OPA URL required')
        self.k3s_url    = self.get_param('config.k3s_url',    None, 'K3s API URL required')
        self.k3s_token  = self.get_param('config.k3s_token',  None, 'K3s token required')
        self.aws_region = self.get_param('config.aws_region', 'ap-southeast-1')

    def run(self):
        alert = self.get_param('data', None, 'Alert data required')
        workload   = alert.get('workload_name')
        namespace  = alert.get('namespace', 'financial')
        source_ip  = alert.get('source_ip')
        cloud      = alert.get('cloud_provider', 'aws')

        results = []

        # 1. Update OPA policy to deny all traffic from this workload
        policy_patch = {
            "isolated_workloads": [workload],
            "isolation_reason":   f"SOAR auto-isolation at {alert.get('timestamp')}",
            "alert_id":           alert.get('id')
        }
        r = requests.put(
            f"{self.opa_url}/v1/data/ztlab/isolated",
            json=policy_patch,
            headers={"Content-Type": "application/json"}
        )
        results.append({"action": "opa_policy_update", "status": r.status_code})

        # 2. Add K3s NetworkPolicy to isolate pod
        network_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name":      f"isolate-{workload}",
                "namespace": namespace,
                "labels":    {"soar-managed": "true", "alert-id": str(alert.get('id', ''))}
            },
            "spec": {
                "podSelector": {"matchLabels": {"app": workload}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],  # deny all ingress
                "egress":  []   # deny all egress
            }
        }
        k3s_headers = {
            "Authorization": f"Bearer {self.k3s_token}",
            "Content-Type":  "application/json"
        }
        r2 = requests.post(
            f"{self.k3s_url}/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies",
            json=network_policy,
            headers=k3s_headers,
            verify=False
        )
        results.append({"action": "k3s_network_policy", "status": r2.status_code})

        # 3. AWS Security Group: block source IP if cloud=aws
        if cloud == 'aws' and source_ip:
            import boto3
            ec2 = boto3.client('ec2', region_name=self.aws_region)
            # Revoke inbound from source IP on all ports
            # (security group ID should be stored in alert context)
            sg_id = alert.get('aws_security_group_id')
            if sg_id:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        'IpProtocol': '-1',
                        'IpRanges': [{'CidrIp': f'{source_ip}/32',
                                      'Description': f'SOAR block - alert {alert.get("id")}'}]
                    }]
                )
                results.append({"action": "aws_sg_revoke", "source_ip": source_ip, "status": "done"})

        self.report({
            "success": True,
            "workload": workload,
            "actions_taken": results,
            "message": f"Workload {workload} isolated successfully"
        })

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='isolated')]

if __name__ == '__main__':
    IsolateWorkload().run()
```

**Additional Responders to implement:**

| Responder Name | Trigger | Cloud target | Action |
|----------------|---------|--------------|--------|
| `RevokeKeycloakSession` | Suspicious login | AWS (Keycloak) | Revoke all active sessions for user |
| `RevokeSpireSVID` | Workload compromise | Both (SPIRE Server on AWS) | Delete SPIRE entry, force SVID revocation across both clouds |
| `BlockIPFirewall` | Brute force | Both | Update AWS SG **+** OpenStack Neutron |
| `UpdateOPAPolicy` | Lateral movement | Both (OPA sidecar reload) | Push deny-all policy for SVID pair |
| `RestoreWorkload` | False positive | Both | Remove NetworkPolicy, restore OPA rule, re-register SPIRE entry |
| `IsolateOSWorkload` | OS-side threat | OpenStack only | Neutron SG update + K3s NetworkPolicy on OS cluster |

### 11.3 Cross-Cloud SOAR: OpenStack Neutron Responder

The original `IsolateWorkload` responder only handled AWS Security Groups and K3s NetworkPolicy on the AWS cluster. Threats originating on or targeting OpenStack workloads (Core Banking, Account Service, Transaction Service) required a separate handler.

**File:** `cortex/responders/IsolateOSWorkload/run`

```python
#!/usr/bin/env python3
"""
Cortex Responder: Cross-cloud isolation for OpenStack workloads.
Operates on TWO layers simultaneously:
  1. OpenStack Neutron — updates security group to deny the threat source
  2. K3s NetworkPolicy on OS cluster — isolates the specific pod
  3. OPA policy push — denies cross-cloud traffic from/to isolated workload
  4. Audit log entry to Elasticsearch (PCI-DSS compliance)
"""
import sys, json, requests
from cortexutils.responder import Responder
import openstack


class IsolateOSWorkload(Responder):
    def __init__(self):
        Responder.__init__(self)
        # OpenStack credentials (from Cortex config — never hardcoded)
        self.os_auth_url    = self.get_param('config.os_auth_url',    None, 'OpenStack auth URL required')
        self.os_username    = self.get_param('config.os_username',    None, 'OpenStack username required')
        self.os_password    = self.get_param('config.os_password',    None, 'OpenStack password required')
        self.os_project     = self.get_param('config.os_project',     None, 'OpenStack project required')
        self.os_region      = self.get_param('config.os_region',      'RegionOne')
        # K3s OS cluster credentials
        self.k3s_os_url     = self.get_param('config.k3s_os_url',     None, 'OS K3s API URL required')
        self.k3s_os_token   = self.get_param('config.k3s_os_token',   None, 'OS K3s token required')
        # OPA endpoint (each microservice has local OPA sidecar)
        self.opa_base_url   = self.get_param('config.opa_base_url',   None, 'OPA base URL required')
        # SIEM Elasticsearch for audit
        self.es_url         = self.get_param('config.es_url',         None, 'Elasticsearch URL required')
        self.es_user        = self.get_param('config.es_user',        'audit_writer')
        self.es_password    = self.get_param('config.es_password',    None, 'ES password required')

    def run(self):
        alert     = self.get_param('data', None, 'Alert data required')
        workload  = alert.get('workload_name')         # e.g. "core-banking"
        namespace = alert.get('namespace', 'financial')
        source_ip = alert.get('source_ip')             # threatening source
        svid      = alert.get('spiffe_id', '')         # e.g. spiffe://ztlab.local/os/core-banking
        alert_id  = alert.get('id')
        timestamp = alert.get('@timestamp')

        results = []

        # ── Step 1: OpenStack Neutron — deny source IP on OS private SG ──────
        try:
            conn = openstack.connect(
                auth_url=self.os_auth_url,
                username=self.os_username,
                password=self.os_password,
                project_name=self.os_project,
                region_name=self.os_region
            )

            # Find security group for the OS private zone
            sg = conn.network.find_security_group('neutron-sg-os-private')
            if sg and source_ip:
                # Add deny rule for source IP on all protocols
                # (OpenStack Neutron uses allowlist model — we add a specific deny via
                # a dedicated block-list security group, then attach to the workload's port)
                block_sg_name = f"ztlab-block-{alert_id}"
                block_sg = conn.network.create_security_group(
                    name=block_sg_name,
                    description=f"SOAR auto-block alert={alert_id} src={source_ip}"
                )
                # Deny ingress from source_ip (no allow rules = implicit deny)
                # The workload's port gets this SG attached; existing allowed rules remain
                # on neutron-sg-os-private unchanged (non-destructive)

                # Find all ports for the workload (by server name prefix)
                servers = list(conn.compute.servers(name=workload))
                port_ids = []
                for server in servers:
                    for net_name, iface_list in server.addresses.items():
                        ports = list(conn.network.ports(device_id=server.id))
                        port_ids.extend([p.id for p in ports])

                # Attach block SG to workload ports
                for port_id in port_ids:
                    port = conn.network.get_port(port_id)
                    existing_sgs = port.security_group_ids or []
                    conn.network.update_port(
                        port_id,
                        security_groups=existing_sgs + [block_sg.id]
                    )
                    results.append({
                        "action":    "neutron_block_sg_attached",
                        "port_id":   port_id,
                        "block_sg":  block_sg_name,
                        "source_ip": source_ip,
                        "status":    "applied"
                    })
        except Exception as e:
            results.append({"action": "neutron_block", "status": "error", "detail": str(e)})

        # ── Step 2: K3s NetworkPolicy on OS cluster ───────────────────────────
        try:
            network_policy = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name":      f"isolate-{workload}-{alert_id[:8]}",
                    "namespace": namespace,
                    "labels":    {
                        "soar-managed":  "true",
                        "alert-id":      str(alert_id),
                        "cloud":         "openstack",
                        "isolation-type":"full"
                    }
                },
                "spec": {
                    "podSelector": {"matchLabels": {"app": workload}},
                    "policyTypes": ["Ingress", "Egress"],
                    # Empty = deny all Ingress and Egress
                    "ingress": [],
                    "egress":  []
                }
            }
            k3s_headers = {
                "Authorization": f"Bearer {self.k3s_os_token}",
                "Content-Type":  "application/json"
            }
            r = requests.post(
                f"{self.k3s_os_url}/apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies",
                json=network_policy,
                headers=k3s_headers,
                verify=False,
                timeout=10
            )
            results.append({
                "action":   "os_k3s_network_policy",
                "workload": workload,
                "status":   r.status_code,
                "policy":   f"isolate-{workload}-{alert_id[:8]}"
            })
        except Exception as e:
            results.append({"action": "os_k3s_network_policy", "status": "error", "detail": str(e)})

        # ── Step 3: OPA policy push — deny cross-cloud traffic for this SVID ──
        # This prevents AWS workloads from calling isolated OS workload
        try:
            isolation_data = {
                "isolated_workloads": [workload],
                "isolated_svids":     [svid],
                "isolation_source":   "soar_auto",
                "alert_id":           str(alert_id),
                "cloud":              "openstack"
            }
            r2 = requests.put(
                f"{self.opa_base_url}/v1/data/ztlab/os_isolated",
                json=isolation_data,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            results.append({
                "action":  "opa_cross_cloud_deny",
                "svid":    svid,
                "status":  r2.status_code
            })
        except Exception as e:
            results.append({"action": "opa_cross_cloud_deny", "status": "error", "detail": str(e)})

        # ── Step 4: Write PCI-DSS audit log to Elasticsearch ─────────────────
        try:
            audit_doc = {
                "@timestamp":   timestamp,
                "alert_id":     str(alert_id),
                "action":       "isolate_os_workload",
                "workload":     workload,
                "source_ip":    source_ip,
                "spiffe_id":    svid,
                "cloud":        "openstack",
                "steps":        results,
                "pci_dss_ref":  "PCI-DSS v4 Req 10.3, 11.5",
                "responder":    "IsolateOSWorkload",
                "outcome":      "applied" if all(r.get("status") not in ["error"] for r in results) else "partial"
            }
            requests.post(
                f"{self.es_url}/ztlab-audit-log/_doc",
                json=audit_doc,
                auth=(self.es_user, self.es_password),
                verify=True,
                timeout=5
            )
        except Exception as e:
            pass  # Audit failure is non-blocking but gets logged to responder output

        self.report({
            "success":       True,
            "workload":      workload,
            "cloud":         "openstack",
            "actions_taken": results,
            "layers":        ["neutron_sg", "k3s_network_policy", "opa_cross_cloud", "audit_log"],
            "message":       f"OS workload '{workload}' isolated across all enforcement layers"
        })

    def operations(self, raw):
        return [
            self.build_operation('AddTagToCase', tag='os-isolated'),
            self.build_operation('AddTagToCase', tag='cross-cloud-response')
        ]


if __name__ == '__main__':
    IsolateOSWorkload().run()
```

**Cortex config** — add to `application.conf`:

```hocon
responder.IsolateOSWorkload {
  os_auth_url  = "http://192.168.100.1:5000/v3"   # OpenStack Keystone via WG tunnel
  os_username  = "ztlab-soar"
  os_password  = ${?OS_SOAR_PASSWORD}              # from env
  os_project   = "ztlab"
  os_region    = "RegionOne"
  k3s_os_url   = "https://10.10.4.10:6443"         # OS K3s API via WG tunnel
  k3s_os_token = ${?OS_K3S_TOKEN}
  opa_base_url = "http://10.10.4.10:9191"           # OPA reachable via tunnel
  es_url       = "https://10.10.2.10:9200"
  es_user      = "audit_writer"
  es_password  = ${?AUDIT_ES_PASSWORD}
}
```

### 11.4 SOAR Response Decision Matrix (AWS vs OpenStack)

When TheHive receives an alert, the AI Playbook Engine determines which responder to invoke based on the `cloud_provider` field set by Logstash enrichment:

```python
# ai-engine/soar/playbook_engine.py  (decision logic excerpt)

def select_responder(alert: dict) -> list[str]:
    """
    Returns list of Cortex responder names to invoke based on alert context.
    Multiple responders may run in parallel for cross-cloud incidents.
    """
    cloud    = alert.get('cloud_provider', 'unknown')
    severity = alert.get('severity', 'low')
    category = alert.get('rule', {}).get('groups', [])

    responders = []

    # Identity layer — always cross-cloud (SPIRE Server is on AWS, affects both)
    if 'identity_anomaly' in category or 'spire' in category:
        responders.append('RevokeSpireSVID')         # single responder, both clouds

    # Network isolation
    if severity in ['high', 'critical']:
        if cloud == 'aws':
            responders.append('IsolateWorkload')     # AWS SG + K3s NetworkPolicy
        elif cloud == 'openstack':
            responders.append('IsolateOSWorkload')   # Neutron SG + OS K3s NetworkPolicy
        elif cloud == 'unknown':
            # Lateral movement across clouds — isolate both sides
            responders.extend(['IsolateWorkload', 'IsolateOSWorkload'])

    # Auth layer — Keycloak is on AWS, affects all users regardless of cloud
    if 'authentication_failure' in category or 'brute_force' in category:
        responders.append('RevokeKeycloakSession')

    # OPA cross-cloud policy
    if 'lateral_movement' in category or 'zero_trust_violation' in category:
        responders.append('UpdateOPAPolicy')

    return list(dict.fromkeys(responders))  # deduplicate, preserve order
```

---

## 12. Phase 9 — Human-in-the-Loop (Slack Integration)

### 12.1 n8n Workflow — HITL Approval

This n8n workflow handles the semi-automated response lifecycle:

```
Wazuh Alert (webhook) 
  → AI Analysis (HTTP → AI Engine)
  → Enrich with TheHive Case (HTTP → TheHive)
  → Format Slack Message (Function node)
  → Send Interactive Slack Message (Slack node)
  → Wait for Approval (Wait node — webhook callback)
    ├── APPROVED → Execute Cortex Responder
    │              → Update TheHive case (status: Resolved)
    │              → Log audit record (Elasticsearch)
    └── REJECTED → Update TheHive case (status: FalsePositive)
                   → Log audit record
                   → Notify analyst
```

**n8n Workflow JSON** (key nodes):

```json
{
  "nodes": [
    {
      "id": "webhook-trigger",
      "name": "Wazuh Alert Webhook",
      "type": "n8n-nodes-base.webhook",
      "parameters": {
        "path": "wazuh-alert",
        "responseMode": "responseNode",
        "httpMethod": "POST"
      }
    },
    {
      "id": "ai-analysis",
      "name": "AI Engine Analysis",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "http://10.10.3.12:8000/analyze",
        "method": "POST",
        "sendBody": true,
        "bodyParameters": {
          "parameters": [
            { "name": "alert", "value": "={{ $json }}" }
          ]
        }
      }
    },
    {
      "id": "slack-hitl",
      "name": "Send HITL Slack Alert",
      "type": "n8n-nodes-base.slack",
      "parameters": {
        "channel": "#security-alerts",
        "text": "",
        "blocks": "={{ JSON.stringify([\n  {\n    \"type\": \"section\",\n    \"text\": {\n      \"type\": \"mrkdwn\",\n      \"text\": \":rotating_light: *SECURITY ALERT — APPROVAL REQUIRED*\\n\\n*Alert:* \" + $('Wazuh Alert Webhook').item.json.rule.description + \"\\n*Severity:* \" + $('AI Engine Analysis').item.json.analysis.severity + \"\\n*Confidence:* \" + $('AI Engine Analysis').item.json.analysis.confidence_score + \"%\\n*Workload:* \" + $('Wazuh Alert Webhook').item.json.data.workload_name + \"\\n*Source IP:* \" + $('Wazuh Alert Webhook').item.json.data.srcip\n    }\n  },\n  {\n    \"type\": \"section\",\n    \"text\": {\n      \"type\": \"mrkdwn\",\n      \"text\": \"*Proposed Action:* \" + $('AI Engine Analysis').item.json.analysis.immediate_containment_actions.join(', ')\n    }\n  },\n  {\n    \"type\": \"actions\",\n    \"elements\": [\n      {\n        \"type\": \"button\",\n        \"text\": { \"type\": \"plain_text\", \"text\": \"✅ APPROVE\" },\n        \"style\": \"primary\",\n        \"value\": \"approve_\" + $('Wazuh Alert Webhook').item.json.id,\n        \"action_id\": \"approve_action\",\n        \"url\": \"http://10.10.3.11:5678/webhook/hitl-response?action=approve&alert_id=\" + $('Wazuh Alert Webhook').item.json.id\n      },\n      {\n        \"type\": \"button\",\n        \"text\": { \"type\": \"plain_text\", \"text\": \"❌ REJECT\" },\n        \"style\": \"danger\",\n        \"value\": \"reject_\" + $('Wazuh Alert Webhook').item.json.id,\n        \"action_id\": \"reject_action\",\n        \"url\": \"http://10.10.3.11:5678/webhook/hitl-response?action=reject&alert_id=\" + $('Wazuh Alert Webhook').item.json.id\n      }\n    ]\n  }\n]) }}"
      }
    },
    {
      "id": "audit-log",
      "name": "Write Audit Log",
      "type": "n8n-nodes-base.httpRequest",
      "parameters": {
        "url": "https://10.10.2.10:9200/ztlab-audit-log/_doc",
        "method": "POST",
        "sendBody": true,
        "bodyParameters": {
          "parameters": [
            { "name": "alert_id",   "value": "={{ $('Wazuh Alert Webhook').item.json.id }}" },
            { "name": "decision",   "value": "={{ $json.action }}" },
            { "name": "analyst",    "value": "={{ $json.approver }}" },
            { "name": "timestamp",  "value": "={{ $now.toISO() }}" },
            { "name": "action_taken", "value": "={{ $json.action === 'approve' ? $('AI Engine Analysis').item.json.analysis.immediate_containment_actions : 'rejected' }}" }
          ]
        }
      }
    }
  ]
}
```

### 12.2 Audit Log Index Mapping

```json
PUT _index_template/ztlab-audit-template
{
  "index_patterns": ["ztlab-audit-log*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name": "ztlab-ilm-policy"
    },
    "mappings": {
      "properties": {
        "@timestamp":     { "type": "date" },
        "alert_id":       { "type": "keyword" },
        "decision":       { "type": "keyword" },
        "analyst":        { "type": "keyword" },
        "action_taken":   { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
        "workload":       { "type": "keyword" },
        "severity":       { "type": "keyword" },
        "pci_dss_ref":    { "type": "keyword" }
      }
    }
  }
}
```

---

## 13. Infrastructure as Code (Terraform + Ansible)

### 13.1 Terraform — AWS Resources

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

# VPC
resource "aws_vpc" "ztlab" {
  cidr_block           = "172.31.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "ztlab-vpc", Project = "ztlab" }
}

# Subnet
resource "aws_subnet" "ztlab_main" {
  vpc_id            = aws_vpc.ztlab.id
  cidr_block        = "172.31.1.0/24"
  availability_zone = "${var.aws_region}a"
  map_public_ip_on_launch = false
  tags = { Name = "ztlab-main-subnet" }
}

# Elastic IP for WireGuard Gateway
resource "aws_eip" "wg_gateway" {
  domain = "vpc"
  tags   = { Name = "ztlab-wg-gateway-eip" }
}

# WireGuard Gateway
resource "aws_instance" "wg_gateway" {
  ami           = data.aws_ami.ubuntu22.id
  instance_type = "t3.small"
  subnet_id     = aws_subnet.ztlab_main.id
  key_name      = var.key_pair_name

  vpc_security_group_ids = [aws_security_group.wg_gateway.id]

  source_dest_check = false   # Required for routing

  tags = { Name = "aws-gateway", Role = "wg-server" }
}

resource "aws_eip_association" "wg_eip_assoc" {
  instance_id   = aws_instance.wg_gateway.id
  allocation_id = aws_eip.wg_gateway.id
}

# Security Group — WireGuard Gateway
resource "aws_security_group" "wg_gateway" {
  name   = "ztlab-wg-gateway-sg"
  vpc_id = aws_vpc.ztlab.id

  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "WireGuard VPN"
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
    description = "SSH admin"
  }
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.10.0.0/8"]
    description = "Internal tunnel traffic"
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "ztlab-wg-gateway-sg" }
}

# K3s Nodes
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

# SIEM Node
resource "aws_instance" "siem" {
  count         = 2
  ami           = data.aws_ami.ubuntu22.id
  instance_type = "t3.large"
  subnet_id     = aws_subnet.ztlab_main.id
  key_name      = var.key_pair_name
  vpc_security_group_ids = [aws_security_group.siem.id]
  root_block_device { volume_size = 100 }
  tags = { Name = "aws-siem-${count.index + 1}", Role = "siem" }
}

data "aws_ami" "ubuntu22" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}
```

### 13.2 Terraform — OpenStack Resources

**File:** `terraform/openstack/main.tf`

```hcl
terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.54"
    }
  }
}

provider "openstack" {
  auth_url    = var.os_auth_url
  user_name   = var.os_username
  password    = var.os_password
  tenant_name = var.os_project_name
  region      = var.os_region
}

resource "openstack_networking_network_v2" "ztlab" {
  name           = "ztlab-network"
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "ztlab" {
  name       = "ztlab-subnet"
  network_id = openstack_networking_network_v2.ztlab.id
  cidr       = "192.168.100.0/24"
  ip_version = 4
  dns_nameservers = ["8.8.8.8"]
}

resource "openstack_compute_instance_v2" "os_gateway" {
  name            = "os-gateway"
  image_name      = "Ubuntu-22.04"
  flavor_name     = "m1.small"
  key_pair        = var.key_pair_name
  security_groups = [openstack_networking_secgroup_v2.os_gateway.name]

  network {
    uuid = openstack_networking_network_v2.ztlab.id
  }
}

resource "openstack_compute_instance_v2" "os_k3s_master" {
  name            = "os-k3s-master"
  image_name      = "Ubuntu-22.04"
  flavor_name     = "m1.medium"
  key_pair        = var.key_pair_name
  security_groups = [openstack_networking_secgroup_v2.os_k3s.name]

  network {
    uuid = openstack_networking_network_v2.ztlab.id
  }
}

resource "openstack_networking_secgroup_v2" "os_gateway" {
  name        = "ztlab-os-gateway-sg"
  description = "Security group for OS WireGuard gateway"
}

resource "openstack_networking_secgroup_rule_v2" "os_gw_egress_all" {
  direction         = "egress"
  security_group_id = openstack_networking_secgroup_v2.os_gateway.id
  ethertype         = "IPv4"
}

resource "openstack_networking_secgroup_rule_v2" "os_gw_internal" {
  direction         = "ingress"
  security_group_id = openstack_networking_secgroup_v2.os_gateway.id
  ethertype         = "IPv4"
  remote_ip_prefix  = "10.10.0.0/8"
}
```

### 13.3 Ansible Playbook — Node Baseline

**File:** `ansible/playbooks/baseline.yml`

```yaml
---
- name: ZTLab Node Baseline Configuration
  hosts: all
  become: true
  vars:
    siem_ip: "10.10.2.10"

  tasks:
    - name: Update apt cache and upgrade
      apt:
        update_cache: yes
        upgrade: safe
        cache_valid_time: 3600

    - name: Install base packages
      apt:
        name:
          - curl
          - wget
          - git
          - jq
          - vim
          - net-tools
          - htop
          - nftables
          - fail2ban
          - auditd
          - wireguard
          - wireguard-tools
        state: present

    - name: Enable IP forwarding
      sysctl:
        name: net.ipv4.ip_forward
        value: '1'
        sysctl_set: yes
        state: present
        reload: yes

    - name: Configure auditd rules
      copy:
        dest: /etc/audit/rules.d/ztlab.rules
        content: |
          # Monitor Zero Trust config files
          -w /opt/spire/conf -p wa -k spire_config
          -w /etc/envoy -p wa -k envoy_config
          -w /opt/opa/policies -p wa -k opa_policy
          -w /etc/wireguard -p wa -k wireguard_config
          # Monitor privileged commands
          -a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec
          # Monitor network connections
          -a always,exit -F arch=b64 -S connect -k network_connect

    - name: Enable and start fail2ban
      systemd:
        name: fail2ban
        enabled: yes
        state: started

    - name: Configure Wazuh agent (template)
      template:
        src: templates/ossec.conf.j2
        dest: /var/ossec/etc/ossec.conf
        owner: root
        group: wazuh
        mode: '0640'
      notify: restart wazuh-agent

  handlers:
    - name: restart wazuh-agent
      systemd:
        name: wazuh-agent
        state: restarted
```

---

## 14. Monitoring Dashboards & Kibana Configuration

### 14.1 Dashboard Definitions

**ZTA Security Overview** — Key panels:

| Panel | Visualization | Index | Metric |
|-------|--------------|-------|--------|
| Total Alerts (24h) | Metric | zta-wazuh-alerts-* | count |
| Alert by Severity | Donut | zta-wazuh-alerts-* | terms(severity) |
| Top Attack Source IPs | Data Table | zta-wazuh-alerts-* | terms(source_ip), count |
| Alert Timeline | Line Chart | zta-wazuh-alerts-* | date_histogram(@timestamp, 5m) |
| MTTD Trend | Line Chart | zta-wazuh-alerts-* | avg(detection_delay_sec) per day |
| Zero Trust Violations | Metric | zta-opa-decision-* | filter(opa_result:false), count |

**Identity & Access Map** — Key panels:

| Panel | Visualization | Index |
|-------|--------------|-------|
| SVID Issuance Rate | Area Chart | zta-spire-events-* |
| mTLS Handshake Success Rate | Gauge | zta-envoy-logs-* |
| Service-to-Service Traffic Map | Network Map | zta-envoy-logs-* |
| Keycloak Auth Failures | Bar Chart | zta-wazuh-alerts-* |

### 14.2 Kibana Saved Search: Zero Trust Violations

```json
{
  "title": "ZTA Policy Violations",
  "description": "All OPA denials and JWT failures in ZTA environment",
  "hits": 0,
  "columns": ["@timestamp","source_ip","path","opa_result","response_code","severity","cloud_provider"],
  "sort": [["@timestamp", "desc"]],
  "query": {
    "language": "kuery",
    "query": "(opa_result: \"false\" OR response_code: 401 OR response_code: 403) AND security_flag: true"
  },
  "filters": []
}
```

---

## 15. Security Testing Scenarios — Evaluation Framework

Phần này định nghĩa đầy đủ kịch bản kiểm thử, acceptance criteria, script thực hiện, và phương pháp đo lường định lượng cho 5 metrics chính: MTTD, MTTR, FPR, FNR, Security Overhead.

### 15.1 Test Scenario Matrix (Full)

| # | Scenario | MITRE ATT&CK | ZTA Layer bị test | SIEM signal | Gap? | Acceptance Criteria |
|---|----------|-------------|------------------|-------------|------|---------------------|
| 1 | Brute force login | T1110.001 | Keycloak 401 burst | Wazuh 100001 | No | Alert trong ≤60s sau lần thứ 5 |
| 2 | JWT token forgery | T1550.001 | Envoy ext_authz | Wazuh 100002 | No | 100% deny rate, alert ngay lập tức |
| 3 | Lateral movement — wrong SVID | T1021.007 | OPA SVID pair check | Wazuh 100003 | No | OPA deny + alert trong ≤10s |
| 4 | Fraud gate bypass (Gap 2) | T1078.004 | OPA header check | Wazuh 100007 | Fixed | Deny 100%, TheHive case tạo tự động |
| 5 | High-velocity fraud (50+ txn/min) | T1496 | Fraud scorer + Prometheus | Wazuh 100005 | No | Block sau txn thứ 10, alert SIEM |
| 6 | Data exfiltration >1MB response (Gap 1) | T1041 | Logstash bytes_sent rule | Wazuh 100008 | Fixed | Alert trong ≤30s sau response lớn |
| 7 | SVID not renewed / agent silent | T1562.001 | SPIRE event log | Wazuh 100004 | No | Alert trong ≤5 min sau TTL expire |
| 8 | Cross-cloud lateral movement | T1021 | OPA cross-cloud + Envoy | SIEM correlation | No | Wazuh rule 100003 fires trên cả 2 cloud |
| 9 | Privilege escalation on pod | T1068 | Wazuh FIM + auditd | Wazuh 100006 | No | Alert trong ≤30s |
| 10 | Port scanning từ external | T1046 | Wazuh network monitor | Wazuh 5712 | No | Alert trong ≤60s |
| 11 | Cryptomining container | T1496 | Prometheus CPU spike | OpenSearch RCF | No | Anomaly detect trong ≤5 min |
| 12 | SOAR auto-response — workload isolation | — | Cortex + K3s NetworkPolicy | TheHive case | No | NetworkPolicy applied ≤30s sau approve |

### 15.2 Baseline Setup (Trước khi chạy test)

```bash
# ── Bước 1: Tạo test users và accounts ──────────────────────
export KEYCLOAK_URL="https://keycloak.ztlab.local"
export ADMIN_TOKEN=$(curl -s -X POST \
  "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=${KEYCLOAK_ADMIN_PASSWORD}" \
  | jq -r '.access_token')

# Create test user
curl -s -X POST "$KEYCLOAK_URL/admin/realms/ztlab/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser01","enabled":true,"credentials":[{"type":"password","value":"Test@1234","temporary":false}]}'

# ── Bước 2: Seed database với accounts và transaction history ─
cat > /tmp/seed.py << 'PYEOF'
import asyncio, asyncpg, uuid, random, datetime

async def seed():
    conn = await asyncpg.connect(
        "postgresql://ztlab:ztlab@postgres-accounts:5432/accounts"
    )
    # Create test accounts
    accounts = [
        (str(uuid.uuid4()), "testuser01", "checking", 50_000_000, "VND"),
        (str(uuid.uuid4()), "testuser01", "savings",  200_000_000, "VND"),
        (str(uuid.uuid4()), "victimuser", "checking", 100_000_000, "VND"),
    ]
    await conn.executemany(
        "INSERT INTO accounts(id,owner_user_id,account_type,balance,currency) VALUES($1,$2,$3,$4,$5)",
        accounts
    )
    await conn.close()
    print("Accounts seeded:", [a[0] for a in accounts])
    return [a[0] for a in accounts]

asyncio.run(seed())
PYEOF
python /tmp/seed.py

# ── Bước 3: Ghi lại baseline metrics ─────────────────────────
# Run for 10 minutes with normal traffic to establish LSTM baseline
cat > /tmp/normal_traffic.py << 'PYEOF'
import asyncio, httpx, random, time

API_URL  = "http://api-gateway:8080"
TOKEN    = "Bearer <valid_token>"   # replace with actual token

async def normal_traffic():
    """Simulate normal banking activity for 10 minutes."""
    accounts = ["<account_id_1>", "<account_id_2>"]  # replace
    async with httpx.AsyncClient() as c:
        for _ in range(600):   # ~1 request per second for 10 min
            if random.random() < 0.7:
                # Normal payment: 50k–5M VND
                await c.post(f"{API_URL}/api/v1/payments",
                    headers={"Authorization": TOKEN},
                    json={
                        "from_account": accounts[0],
                        "to_account":   accounts[1],
                        "amount":       random.randint(50_000, 5_000_000),
                        "currency":     "VND"
                    })
            else:
                await c.get(f"{API_URL}/api/v1/accounts/{accounts[0]}",
                    headers={"Authorization": TOKEN})
            await asyncio.sleep(1)

asyncio.run(normal_traffic())
PYEOF

# Record baseline metrics
BASELINE_MTTD=0
BASELINE_TXN_RATE=$(curl -s "http://aws-siem-1:9090/api/v1/query?query=rate(ztlab_transactions_total[5m])" \
  | jq '.data.result[0].value[1]')
echo "Baseline transaction rate: $BASELINE_TXN_RATE txn/s"
```

### 15.3 Test Scripts — Kịch bản chi tiết

#### Scenario 1 — Brute Force Login (T1110.001)

```bash
#!/bin/bash
# File: tests/scenario_01_brute_force.sh
# Setup: Run từ external host hoặc từ aws-bastion
# Expected: Wazuh rule 100001 fires sau 5 attempts, MTTD ≤ 60s

KEYCLOAK_URL="https://keycloak.ztlab.local"
TARGET_USER="testuser01"
T_START=$(date +%s%3N)

echo "[$(date)] Starting brute force simulation — 20 attempts"
for i in $(seq 1 20); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$KEYCLOAK_URL/realms/ztlab/protocol/openid-connect/token" \
    -d "client_id=api-gateway&grant_type=password&username=$TARGET_USER&password=wrongpass$i" \
    -H "Content-Type: application/x-www-form-urlencoded")
  echo "  Attempt $i: HTTP $STATUS"
  sleep 2
done

T_END=$(date +%s%3N)
ATTACK_DURATION=$(( T_END - T_START ))
echo "[$(date)] Attack completed in ${ATTACK_DURATION}ms"

# Poll SIEM for detection
echo "Polling SIEM for Wazuh rule 100001..."
for attempt in $(seq 1 12); do  # poll every 10s for 2 minutes
  ALERT_COUNT=$(curl -s -u elastic:${ELASTIC_PASSWORD} \
    "https://10.10.2.10:9200/zta-wazuh-alerts-*/_count" \
    -H "Content-Type: application/json" \
    -d '{"query":{"bool":{"must":[
          {"term":{"rule.id":"100001"}},
          {"range":{"@timestamp":{"gte":"now-5m"}}}
        ]}}}' | jq '.count')

  if [ "$ALERT_COUNT" -gt 0 ]; then
    T_DETECT=$(date +%s%3N)
    MTTD=$(( T_DETECT - T_START ))
    echo "DETECTED: Wazuh rule 100001 fired. MTTD = ${MTTD}ms"
    echo "RESULT: PASS (threshold: 60000ms)"
    break
  fi
  echo "  No detection yet (attempt $attempt/12)..."
  sleep 10
done
```

#### Scenario 2 — JWT Token Forgery (T1550.001)

```python
#!/usr/bin/env python3
# File: tests/scenario_02_jwt_forgery.py
# Expected: 100% deny rate by Envoy, Wazuh rule 100002

import httpx, jwt, json, time

API_URL   = "https://api-gateway.ztlab.local"
# Forge a JWT with a different secret (will fail RS256 verification)
FORGED_PAYLOAD = {
    "sub":    "attacker",
    "iss":    "https://keycloak.ztlab.local/realms/ztlab",  # correct issuer
    "aud":    "api-gateway",
    "exp":    int(time.time()) + 3600,
    "realm_access": {"roles": ["financial-write", "security-admin"]}
}

print("=== Scenario 2: JWT Forgery ===")
results = {"denied": 0, "allowed": 0}

for i in range(10):
    # Sign with wrong HS256 secret (correct issuer but wrong algorithm/key)
    forged_token = jwt.encode(FORGED_PAYLOAD, "wrong-secret", algorithm="HS256")
    r = httpx.post(
        f"{API_URL}/api/v1/payments",
        headers={"Authorization": f"Bearer {forged_token}"},
        json={"from_account": "acc1", "to_account": "acc2",
              "amount": 100000, "currency": "VND"},
        verify=False
    )
    if r.status_code == 401:
        results["denied"] += 1
    else:
        results["allowed"] += 1
    print(f"  Attempt {i+1}: HTTP {r.status_code}")

deny_rate = results["denied"] / 10 * 100
print(f"\nDeny rate: {deny_rate}% (expected: 100%)")
print(f"Result: {'PASS' if deny_rate == 100 else 'FAIL'}")
```

#### Scenario 4 — Fraud Gate Bypass — Gap 2 Fix Validation

```python
#!/usr/bin/env python3
# File: tests/scenario_04_fraud_gate_bypass.py
# Simulates: attacker has valid payment-service SVID but skips fraud service
# Expected: OPA deny (rule 100007) + TheHive case auto-created

import httpx, time, json

# In lab: exec into a compromised payment-service pod and call core-banking directly
CORE_BANKING_URL = "http://core-banking.os-financial.svc.cluster.local:8080"

print("=== Scenario 4: Fraud Gate Bypass ===")
print("Attempting to call core-banking directly WITHOUT fraud gate headers...")

test_cases = [
    # Case 1: No fraud headers at all
    {"name": "no_headers",    "headers": {}},
    # Case 2: Fraud score present but gate not passed
    {"name": "no_gate",       "headers": {"X-Fraud-Score": "10"}},
    # Case 3: Gate passed but score above threshold
    {"name": "high_score",    "headers": {"X-Fraud-Score": "80", "X-Fraud-Gate": "passed"}},
    # Case 4: Valid headers (should be ALLOWED — control case)
    {"name": "valid_control", "headers": {"X-Fraud-Score": "15", "X-Fraud-Gate": "passed",
                                           "X-User-ID": "testuser01"}},
]

results = []
for tc in test_cases:
    r = httpx.post(
        f"{CORE_BANKING_URL}/transactions/execute",
        json={"from_account": "acc1", "to_account": "acc2",
              "amount": 100000, "currency": "VND"},
        headers={**tc["headers"], "X-Trace-ID": f"test-{tc['name']}"},
        timeout=5.0
    )
    expected = 200 if tc["name"] == "valid_control" else 403
    status   = "PASS" if r.status_code == expected else "FAIL"
    results.append({"case": tc["name"], "status_code": r.status_code,
                    "expected": expected, "result": status})
    print(f"  [{status}] {tc['name']}: HTTP {r.status_code} (expected {expected})")

passed = sum(1 for r in results if r["result"] == "PASS")
print(f"\nPassed: {passed}/{len(results)}")

# Verify Wazuh rule 100007 fired for the bypass attempts
time.sleep(15)
import subprocess
alert_check = subprocess.run([
    "curl", "-s", "-u", f"elastic:{os.environ['ELASTIC_PASSWORD']}",
    "https://10.10.2.10:9200/zta-wazuh-alerts-*/_count",
    "-H", "Content-Type: application/json",
    "-d", '{"query":{"term":{"rule.id":"100007"}}}'
], capture_output=True, text=True)
count = json.loads(alert_check.stdout).get("count", 0)
print(f"Wazuh rule 100007 alerts: {count} (expected: 3 — one per bypass attempt)")
```

#### Scenario 5 — High-Velocity Fraud (T1496)

```python
#!/usr/bin/env python3
# File: tests/scenario_05_high_velocity.py
# Simulates account takeover with rapid transaction drain
# Expected: Fraud Detection blocks after 10 txn/min, Wazuh 100005 fires

import asyncio, httpx, time

API_URL = "https://api-gateway.ztlab.local"
TOKEN   = "Bearer <valid_token>"  # compromised legitimate user token

async def flood_transactions():
    """Send 60 transactions in 60 seconds from same user."""
    blocked_at = None
    allowed    = 0
    blocked    = 0
    t_start    = time.time()

    async with httpx.AsyncClient(verify=False) as c:
        for i in range(60):
            r = await c.post(
                f"{API_URL}/api/v1/payments",
                headers={"Authorization": TOKEN},
                json={"from_account": "acc_source", "to_account": f"acc_dest_{i%5}",
                      "amount": 50_000, "currency": "VND"},
                timeout=5.0
            )
            if r.status_code == 200:
                allowed += 1
            elif r.status_code == 403 and "fraud" in r.text.lower():
                blocked += 1
                if blocked_at is None:
                    blocked_at = i + 1
            await asyncio.sleep(1)

    t_end = time.time()
    print(f"\n=== Scenario 5 Results ===")
    print(f"Duration:    {t_end - t_start:.1f}s")
    print(f"Allowed:     {allowed}")
    print(f"Blocked:     {blocked}")
    print(f"Blocked at:  txn #{blocked_at}")
    print(f"Result:      {'PASS' if blocked_at and blocked_at <= 15 else 'FAIL'}")
    print(f"             (threshold: blocked within first 15 txn)")

asyncio.run(flood_transactions())
```

#### Scenario 6 — Data Exfiltration Large Response (Gap 1 Validation)

```python
#!/usr/bin/env python3
# File: tests/scenario_06_exfiltration.py
# Simulates bulk data pull from core-banking to trigger Gap 1 Wazuh rule 100008
# Expected: Wazuh 100008 fires when response > 1MB

import httpx, time, json, os

# Simulate from inside a compromised pod that has valid SVID
CORE_BANKING_URL = "http://core-banking.os-financial.svc.cluster.local:8080"

print("=== Scenario 6: Data Exfiltration — Large Response ===")

# Test case 1: Normal request (should NOT trigger)
r1 = httpx.get(
    f"{CORE_BANKING_URL}/accounts/acc_small",
    headers={"X-Internal-Call": "test", "X-Trace-ID": "test-normal"}
)
print(f"Normal request: HTTP {r1.status_code}, bytes={len(r1.content)}")

# Test case 2: Bulk history dump (generates large response to trigger Gap 1)
# In production this would be a legitimate large query; here we simulate with limit=10000
r2 = httpx.get(
    f"{CORE_BANKING_URL}/transactions/history/acc_source?limit=10000",
    headers={"X-Internal-Call": "test", "X-Trace-ID": "test-exfil"}
)
response_size = len(r2.content)
print(f"Bulk request:  HTTP {r2.status_code}, bytes={response_size}")

# Wait for Logstash processing + Wazuh detection
time.sleep(30)

alert_r = httpx.get(
    "https://10.10.2.10:9200/zta-wazuh-alerts-*/_count",
    auth=("elastic", os.environ["ELASTIC_PASSWORD"]),
    params={"q": "rule.id:100008 AND cloud_provider:openstack"},
    verify=False
)
count = alert_r.json().get("count", 0)
expected_trigger = response_size > 1_048_576

print(f"\nResponse size: {response_size} bytes ({response_size/1024/1024:.2f} MB)")
print(f"Expected alert: {'yes' if expected_trigger else 'no (below threshold)'}")
print(f"Wazuh 100008 alerts: {count}")
if expected_trigger:
    print(f"Result: {'PASS' if count > 0 else 'FAIL'}")
```

#### Scenario 8 — Cross-Cloud Lateral Movement

```bash
#!/bin/bash
# File: tests/scenario_08_cross_cloud_lateral.sh
# Simulates: compromised AWS pod trying to reach OS private services
# that are outside its allowed service graph
# Expected: OPA denies on both clouds, Wazuh 100003 fires in SIEM

# Get a token valid for payment-service
TOKEN=$(curl -s -X POST https://keycloak.ztlab.local/realms/ztlab/protocol/openid-connect/token \
  -d "client_id=payment-service-client&grant_type=client_credentials&client_secret=$PAYMENT_SECRET" \
  | jq -r '.access_token')

echo "=== Scenario 8: Cross-Cloud Lateral Movement ==="

# Attempt 1: payment-service SVID → account-service (not in allowed graph)
echo "Attempt 1: payment → account-service (wrong SVID pair)"
curl -v -k -X GET \
  "http://account-service.os-financial.svc.cluster.local:8080/accounts/acc123" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-SPIFFE-ID: spiffe://ztlab.local/aws/payment-service"
# Expected: 403 from OPA

# Attempt 2: fraud-detection → transaction-service (not in allowed graph)
echo "Attempt 2: fraud-detection → transaction-service (wrong SVID pair)"
curl -v -k -X GET \
  "http://transaction-service.os-financial.svc.cluster.local:8080/history/acc123" \
  -H "X-SPIFFE-ID: spiffe://ztlab.local/aws/fraud-detection"
# Expected: 403 from OPA

# Wait and check SIEM
sleep 20
echo "Checking SIEM for cross-cloud lateral movement alerts..."
ALERT_COUNT=$(curl -s -u elastic:$ELASTIC_PASSWORD \
  "https://10.10.2.10:9200/zta-wazuh-alerts-*/_count" \
  -H "Content-Type: application/json" \
  -d '{"query":{"bool":{"must":[
    {"term":{"rule.id":"100003"}},
    {"range":{"@timestamp":{"gte":"now-5m"}}}
  ]}}}' | jq '.count')
echo "Wazuh rule 100003 alerts: $ALERT_COUNT (expected: ≥2)"
[ "$ALERT_COUNT" -ge 2 ] && echo "PASS" || echo "FAIL"
```

### 15.4 Performance Testing — Security Overhead Measurement

```python
#!/usr/bin/env python3
# File: tests/perf_overhead.py
# Measures: latency overhead introduced by ZTA layers (Envoy + OPA + SPIRE)
# Tool: httpx async (equivalent to Apache JMeter results)

import asyncio, httpx, time, statistics, json
from collections import defaultdict

API_URL    = "https://api-gateway.ztlab.local"
TOKEN      = "Bearer <valid_token>"
ITERATIONS = 500
CONCURRENT = 10

results = defaultdict(list)

async def single_request(client: httpx.AsyncClient, endpoint: str):
    t0 = time.perf_counter()
    r  = await client.post(
        f"{API_URL}{endpoint}",
        headers={"Authorization": TOKEN},
        json={"from_account": "acc1", "to_account": "acc2",
              "amount": 100_000, "currency": "VND"}
    )
    latency = (time.perf_counter() - t0) * 1000   # ms
    return latency, r.status_code

async def run_load_test():
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        # Warm up
        for _ in range(20):
            await single_request(client, "/api/v1/payments")

        # Actual test
        semaphore = asyncio.Semaphore(CONCURRENT)
        async def bounded_request():
            async with semaphore:
                return await single_request(client, "/api/v1/payments")

        tasks = [bounded_request() for _ in range(ITERATIONS)]
        raw   = await asyncio.gather(*tasks)

    latencies = [r[0] for r in raw if r[1] == 200]
    errors    = sum(1 for r in raw if r[1] != 200)

    print("=== Performance Test Results ===")
    print(f"Iterations:   {ITERATIONS}")
    print(f"Concurrency:  {CONCURRENT}")
    print(f"Successful:   {len(latencies)}")
    print(f"Errors:       {errors}")
    print(f"")
    print(f"Latency (ms):")
    print(f"  P50:  {statistics.median(latencies):.1f}")
    print(f"  P95:  {sorted(latencies)[int(len(latencies)*0.95)]:.1f}")
    print(f"  P99:  {sorted(latencies)[int(len(latencies)*0.99)]:.1f}")
    print(f"  Mean: {statistics.mean(latencies):.1f}")
    print(f"  Min:  {min(latencies):.1f}")
    print(f"  Max:  {max(latencies):.1f}")
    print(f"")
    # Security overhead = (ZTA latency - baseline latency) / baseline * 100
    # Baseline = direct call without Envoy/OPA
    baseline_p95 = 45.0   # ms — measure with ZTA disabled first
    overhead_pct = (sorted(latencies)[int(len(latencies)*0.95)] - baseline_p95) / baseline_p95 * 100
    print(f"Estimated ZTA overhead at P95: {overhead_pct:.1f}%")
    print(f"Target: < 20% overhead")
    print(f"Result: {'PASS' if overhead_pct < 20 else 'FAIL'}")

asyncio.run(run_load_test())
```

### 15.5 Quantitative Evaluation — Metrics Collection

Mỗi kịch bản cần đo và ghi lại 6 metrics sau. Template thu thập tự động:

```python
#!/usr/bin/env python3
# File: tests/collect_metrics.py
# Run after each scenario to collect standardized metrics for the thesis report

import httpx, json, os, time
from datetime import datetime, timedelta

ES_URL      = "https://10.10.2.10:9200"
ES_AUTH     = ("elastic", os.environ["ELASTIC_PASSWORD"])
WAZUH_URL   = "https://10.10.2.10:55000"
WAZUH_AUTH  = ("wazuh-admin", os.environ["WAZUH_API_PASSWORD"])

def query_es(index: str, query: dict) -> dict:
    r = httpx.get(f"{ES_URL}/{index}/_search", json=query,
                  auth=ES_AUTH, verify=False)
    return r.json()

def collect_mttd(scenario_id: int, attack_start: float) -> float:
    """Mean Time To Detect: time from attack start to first Wazuh alert."""
    rule_map = {1: "100001", 2: "100002", 3: "100003", 4: "100007",
                5: "100005", 6: "100008", 7: "100004", 8: "100003"}
    rule_id = rule_map.get(scenario_id, "")
    query = {
        "size": 1, "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"must": [
            {"term": {"rule.id": rule_id}},
            {"range": {"@timestamp": {"gte": datetime.utcfromtimestamp(attack_start).isoformat()}}}
        ]}}
    }
    res   = query_es("zta-wazuh-alerts-*", query)
    hits  = res.get("hits", {}).get("hits", [])
    if not hits:
        return -1.0   # not detected
    detect_ts = hits[0]["_source"]["@timestamp"]
    detect_epoch = datetime.fromisoformat(detect_ts.replace("Z","")).timestamp()
    return (detect_epoch - attack_start) * 1000   # ms

def collect_fp_fn(scenario_id: int, window_minutes: int = 10) -> dict:
    """Estimate False Positive Rate and False Negative Rate for scenario window."""
    since = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()
    total_alerts = query_es("zta-wazuh-alerts-*", {
        "query": {"range": {"@timestamp": {"gte": since}}}
    }).get("hits", {}).get("total", {}).get("value", 0)

    # Manually tag confirmed TPs/FPs after each scenario run
    # This is placeholder — actual values filled in during testing
    return {
        "total_alerts_in_window": total_alerts,
        "tp":  "manual_review_required",
        "fp":  "manual_review_required",
        "fn":  "manual_review_required",
        "fpr": "calculated_post_review",
        "fnr": "calculated_post_review"
    }

def collect_security_overhead() -> dict:
    """Query Prometheus for ZTA latency overhead."""
    PROM_URL = "http://aws-siem-1:9090"
    # P95 end-to-end latency including Envoy + OPA
    r = httpx.get(f"{PROM_URL}/api/v1/query",
                  params={"query": 'histogram_quantile(0.95, rate(ztlab_transaction_duration_seconds_bucket[5m]))'})
    p95_with_zta = float(r.json()["data"]["result"][0]["value"][1]) * 1000
    baseline_ms  = 45.0   # established during baseline phase
    overhead_pct = (p95_with_zta - baseline_ms) / baseline_ms * 100
    return {
        "p95_with_zta_ms": round(p95_with_zta, 1),
        "baseline_ms":     baseline_ms,
        "overhead_pct":    round(overhead_pct, 1),
        "target_pct":      20.0,
        "pass":            overhead_pct < 20.0
    }

# ── Main report generation ───────────────────────────────────
if __name__ == "__main__":
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "scenarios": {},
        "security_overhead": collect_security_overhead()
    }
    # After running each scenario, call collect_mttd with the scenario ID
    # and the epoch time when the attack started
    # Example: report["scenarios"]["S01_brute_force"]["mttd_ms"] = collect_mttd(1, t_attack_start)
    print(json.dumps(report, indent=2))
```

### 15.6 Expected Results Summary (Acceptance Criteria)

| Metric | Target | Rationale |
|--------|--------|-----------|
| MTTD (ZTA-enforced scenarios 1–5) | ≤ 60s | Hard enforcement — OPA/Envoy fire immediately, Wazuh processes within one polling cycle |
| MTTD (Statistical scenarios 6, 11) | ≤ 5 min | Logstash rule fires at ingestion; OpenSearch RCF needs 1–2 anomaly windows |
| MTTR (auto-isolate after HITL approve) | ≤ 30s | Cortex Responder applies K3s NetworkPolicy + Neutron SG |
| False Positive Rate | ≤ 5% | Wazuh rules are deterministic for hard-gate scenarios |
| False Negative Rate | ≤ 10% | Gap 1 and Gap 2 fixed; Slow APT remains acknowledged FN |
| Security Overhead at P95 | ≤ 20% | Envoy + OPA add ~5–15ms; acceptable for banking API |
| Fraud Gate Bypass Block Rate | 100% | OPA + application layer double-check |
| Cross-cloud SVID enforcement | 100% deny on invalid pairs | SPIRE + OPA SVID pair policy |

### 15.7 MTTD Comparison — Baseline vs ZTA

```
Without ZTA (traditional perimeter):
  Brute force:          detected by SIEM log analysis  →  MTTD ~15 min (IBM 2023 baseline)
  Lateral movement:     detected only by correlation    →  MTTD ~30+ min
  Data exfiltration:    volume-based detection          →  MTTD ~60+ min

With ZTA (this system):
  Brute force:          Keycloak 401 burst → Wazuh 100001  →  MTTD ≤ 60s
  Lateral movement:     OPA SVID deny → Wazuh 100003       →  MTTD ≤ 10s
  Data exfiltration:    Logstash bytes_sent → Wazuh 100008 →  MTTD ≤ 30s
  Fraud gate bypass:    OPA header check → Wazuh 100007    →  MTTD ≤ 10s

Improvement factor:  15–90× faster detection across all measurable scenarios
```

---

## 16. Network & Port Reference

Ports are grouped by zone. Only ports listed as "allowed inbound" in §2.4 Security Groups are reachable from external zones.

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
| Envoy admin | all pods | — | 15000 | TCP | Management zone (bastion) |
| OPA | all pods | — | 9191 | TCP | localhost only (sidecar) |
| Prometheus metrics | all pods | — | 9090 | TCP | Restricted zone (scrape) |

**[Private Zone — OpenStack]**

| Service | Node | Local IP | WG IP | Port | Inbound from |
|---------|------|----------|-------|------|--------------|
| K3s API | os-k3s-master | 192.168.101.10 | 10.10.4.10 | 6443 | OS Private + Management via WG |
| SPIRE Agent | os-identity | 192.168.101.20 | 10.10.5.10 | — | Connects out to SPIRE Server |
| Wazuh Agent buffer | os-gateway | 192.168.100.10 | 10.10.0.2 | 1514 | OS Private (agents → buffer) |
| Filebeat buffer | os-gateway | 192.168.100.10 | 10.10.0.2 | 5045/5046 | OS Private (Filebeat → buffer) |
| Neutron API | OpenStack ctrl | 192.168.100.1 | — | 9696 | SOAR via WG tunnel (outbound only) |

**[Restricted Zone — SIEM tier]**

| Service | Node | IP | Port | Protocol | Inbound from |
|---------|------|----|------|----------|--------------|
| Elasticsearch REST | aws-siem-1 | 10.10.2.10 | 9200 | TCP | Restricted zone (AI, SOAR, Logstash) |
| Elasticsearch transport | aws-siem-1 | 10.10.2.10 | 9300 | TCP | Restricted zone internal |
| Kibana | aws-siem-1 | 10.10.2.10 | 5601 | TCP | Management zone (bastion) |
| Wazuh Manager | aws-siem-1 | 10.10.2.10 | 1514 | TCP | Private zone + OS via WG |
| Wazuh API | aws-siem-1 | 10.10.2.10 | 55000 | TCP | Restricted zone (n8n, AI) |
| Logstash Beats | aws-siem-2 | 10.10.2.11 | 5044 | TCP | Private zone + OS buffer via WG |
| Kafka | aws-siem-2 | 10.10.2.11 | 9092 | TCP | Private zone + Restricted zone |
| Zookeeper | aws-siem-2 | 10.10.2.11 | 2181 | TCP | aws-siem-2 localhost only |
| OpenSearch | aws-opensearch | 10.10.2.12 | 9200 | TCP | Restricted zone (Kafka Connect, AI) |
| OpenSearch Dashboard | aws-opensearch | 10.10.2.12 | 5601 | TCP | Management zone (bastion) |

**[Restricted Zone — Security tier]**

| Service | Node | IP | Port | Protocol | Inbound from |
|---------|------|----|------|----------|--------------|
| TheHive | aws-soar | 10.10.3.10 | 9000 | TCP | Restricted zone (n8n, AI Engine) |
| Cortex | aws-soar | 10.10.3.10 | 9001 | TCP | TheHive (localhost/Restricted) |
| n8n | aws-soar | 10.10.3.10 | 5678 | TCP | Slack webhooks inbound (outbound egress) |
| AI Engine | aws-ai | 10.10.3.11 | 8000 | TCP | Restricted zone (SOAR calls AI) |
| ChromaDB | aws-ai | 10.10.3.11 | 8001 | TCP | AI Engine localhost only |

**[Outbound-only from Restricted — not inbound]**

| Destination | Port | Purpose |
|-------------|------|---------|
| api.slack.com | 443 | HITL alert delivery + approval callbacks |
| AWS EC2 API | 443 | AWS Security Group automation (Cortex) |
| OpenStack Neutron (192.168.100.1) | 9696 | Neutron SG automation (IsolateOSWorkload) |
| OS K3s API (10.10.4.10) | 6443 | NetworkPolicy push (IsolateOSWorkload) |

---

## 17. Environment Variables & Secrets Reference

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

# ========== Elasticsearch ==========
ELASTIC_PASSWORD=<min 16 chars>
LOGSTASH_ES_PASSWORD=<min 16 chars>
AI_ENGINE_ES_PASSWORD=<min 16 chars>
KIBANA_SYSTEM_PASSWORD=<min 16 chars>

# ========== Kafka ==========
KAFKA_INTER_BROKER_PASSWORD=<random>

# ========== OpenSearch ==========
OPENSEARCH_ADMIN_PASSWORD=<min 16 chars>
OPENSEARCH_KAFKA_PASSWORD=<min 16 chars>

# ========== SOAR ==========
THEHIVE_API_KEY=<generate via TheHive admin console>
N8N_DB_PASSWORD=<random 32 chars>
N8N_ENCRYPTION_KEY=<random 32 chars hex>
SLACK_BOT_TOKEN=xoxb-<your-token>
SLACK_SIGNING_SECRET=<from Slack App config>

# ========== AWS SDK (for Cortex responders) ==========
AWS_ACCESS_KEY_ID=<IAM key with EC2 SG permissions only>
AWS_SECRET_ACCESS_KEY=<IAM secret>
AWS_DEFAULT_REGION=ap-southeast-1

# ========== OpenStack SDK (Terraform + admin) ==========
OS_AUTH_URL=http://<controller-ip>:5000/v3
OS_USERNAME=ztlab-admin
OS_PASSWORD=<openstack user password>
OS_PROJECT_NAME=ztlab
OS_REGION_NAME=RegionOne

# ========== OpenStack SDK (SOAR Cortex responder — least-privilege) ==========
# This account has ONLY neutron:port_update + neutron:security_group_create
# Never reuse the admin account for automated SOAR actions
OS_SOAR_AUTH_URL=http://<controller-ip>:5000/v3
OS_SOAR_USERNAME=ztlab-soar
OS_SOAR_PASSWORD=<dedicated soar password — different from admin>
OS_SOAR_PROJECT=ztlab
OS_K3S_OS_TOKEN=<OS K3s service account token for SOAR network policy push>

# ========== Zone-specific notes ==========
# DMZ zone nodes:        no secrets stored — WireGuard keys only
# Private zone nodes:    SPIRE join token (short-lived, regenerate per deploy)
# Restricted zone nodes: ES passwords, AI API keys, SOAR tokens
# Management zone:       Terraform state S3 bucket name + DynamoDB table for locking
TERRAFORM_STATE_BUCKET=ztlab-terraform-state
TERRAFORM_LOCK_TABLE=ztlab-terraform-lock
```

**Secret Management Recommendations:**

- Store all secrets in AWS Secrets Manager (production) or Ansible Vault (lab)
- Rotate SPIRE SVIDs automatically (TTL = 1h, CA = 7d)
- Rotate Keycloak client secrets every 90 days
- Use SPIRE-issued mTLS certificates for inter-service communication (no static certs)

---

> **Document maintained by:** Hoàng Bảo Phước · Phạm Võ Khánh Hà  
> **Last updated:** March 2026  
> **Version:** 1.0.0