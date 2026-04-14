# MAP.md — Bản đồ kiến trúc file và logic hệ thống ZTLab

> **Mục đích:** File này ánh xạ từng thư mục và file trong repo đến đúng section trong `IMPLEMENTATION.md`, giải thích ý nghĩa của từng thành phần, và hỗ trợ tìm đúng chỗ cần sửa khi có thay đổi.  
> **Quy tắc:** Khi thêm/sửa/xóa bất kỳ file nào, cập nhật MAP.md đồng thời.

---

## Mục lục

1. [Cây thư mục đầy đủ](#1-cây-thư-mục-đầy-đủ)
2. [terraform/ — Provisioning hạ tầng](#2-terraform--provisioning-hạ-tầng)
3. [ansible/ — Configuration management](#3-ansible--configuration-management)
4. [wireguard/ — VPN tunnel](#4-wireguard--vpn-tunnel)
5. [spire/ — Identity foundation](#5-spire--identity-foundation)
6. [k8s/ — Kubernetes manifests](#6-k8s--kubernetes-manifests)
7. [opa/ — Policy engine](#7-opa--policy-engine)
8. [envoy/ — Sidecar proxy](#8-envoy--sidecar-proxy)
9. [shared/ — Python shared modules](#9-shared--python-shared-modules)
10. [services/ — Financial microservices](#10-services--financial-microservices)
11. [plg-stack/ — Promtail + Loki + Grafana (SIEM)](#11-plg-stack--promtail--loki--grafana-siem)
12. [monitoring/ — Dashboards + alerts](#12-monitoring--dashboards--alerts)
13. [tests/ — Attack simulation + evaluation](#13-tests--attack-simulation--evaluation)
14. [scripts/ — Utilities](#14-scripts--utilities)
15. [Logic flow index — Tìm nhanh theo tính năng](#15-logic-flow-index--tìm-nhanh-theo-tính-năng)
16. [Quy tắc đặt tên và thêm file mới](#16-quy-tắc-đặt-tên-và-thêm-file-mới)

---

## 1. Cây thư mục đầy đủ

```
ztlab/                                  ← project root
│
├── README.md                           ← entry point, quick start
├── MAP.md                              ← file này
├── IMPLEMENTATION.md                   ← tài liệu kỹ thuật đầy đủ
├── .env.template                       ← template secrets (không commit .env thật)
├── .gitignore
│
├── terraform/
│   ├── aws/
│   │   ├── main.tf                     ← VPC, subnets, EC2 instances, EIP
│   │   ├── variables.tf                ← aws_region, key_pair_name, admin_ip
│   │   ├── outputs.tf                  ← public IPs, private IPs của các node
│   │   └── security_groups.tf          ← sg-dmz, sg-private, sg-restricted, sg-management
│   └── openstack/
│       ├── main.tf                     ← networks, subnets, instances
│       ├── variables.tf
│       ├── outputs.tf
│       └── security_groups.tf          ← neutron-sg-os-dmz, neutron-sg-os-private
│
├── ansible/
│   ├── inventory/
│   │   ├── hosts.yml                   ← tất cả nodes theo zone
│   │   └── group_vars/
│   │       ├── all.yml                 ← shared vars (loki_ip, wg_server_ip)
│   │       ├── aws.yml                 ← AWS-specific vars
│   │       └── openstack.yml           ← OS-specific vars
│   ├── playbooks/
│   │   ├── baseline.yml               ← packages, auditd, fail2ban, sysctl
│   │   ├── wireguard.yml              ← install + configure WG on gateways
│   │   ├── k3s.yml                    ← install K3s master + workers
│   │   └── promtail.yml               ← install + configure Promtail trên tất cả nodes
│   └── templates/
│       ├── promtail-config.yml.j2     ← Promtail config template (loki_ip từ group_vars)
│       └── wg0.conf.j2               ← WireGuard config template
│
├── wireguard/
│   ├── aws-gateway.conf               ← WG server config (VPN server, EIP)
│   └── os-gateway.conf                ← WG client config (initiates tunnel)
│
├── spire/
│   ├── server/
│   │   └── server.conf                ← SPIRE Server config (trust domain, CA TTL)
│   ├── agent/
│   │   ├── aws-agent.conf             ← SPIRE Agent config cho AWS K3s nodes
│   │   └── os-agent.conf              ← SPIRE Agent config cho OS K3s nodes
│   ├── k8s/
│   │   ├── namespace.yaml             ← namespace "spire"
│   │   ├── server-deployment.yaml     ← SPIRE Server Deployment
│   │   ├── agent-daemonset.yaml       ← SPIRE Agent DaemonSet
│   │   └── rbac.yaml                  ← ServiceAccount, ClusterRole
│   └── scripts/
│       ├── register-aws-workloads.sh  ← tạo SPIRE entries cho AWS services
│       ├── register-os-workloads.sh   ← tạo SPIRE entries cho OS services
│       └── verify-svids.sh            ← kiểm tra SVID issuance sau deploy
│
├── k8s/
│   ├── namespaces.yaml                ← financial, spire, identity, monitoring
│   ├── spire/                         ← (symlink → ../spire/k8s/)
│   ├── keycloak/
│   │   ├── deployment.yaml            ← Keycloak Deployment
│   │   ├── service.yaml               ← ClusterIP service
│   │   ├── secret.yaml                ← admin password (sealed secret)
│   │   └── realm-config.json          ← Keycloak realm "ztlab" import config
│   ├── financial/
│   │   ├── aws-services.yaml          ← Deployments: api-gateway, payment, fraud, notification
│   │   ├── os-services.yaml           ← Deployments: core-banking, account, transaction
│   │   ├── services.yaml              ← K8s Services cho tất cả microservices
│   │   ├── redis.yaml                 ← Redis cho fraud velocity window
│   │   ├── postgres-accounts.yaml     ← PostgreSQL cho account-service
│   │   ├── postgres-txn.yaml          ← PostgreSQL cho transaction-service
│   │   └── network-policies/
│   │       ├── aws-allow-list.yaml    ← whitelist service graph trên AWS
│   │       └── os-allow-list.yaml     ← whitelist service graph trên OpenStack
│   └── monitoring/
│       └── prometheus-scrape.yaml     ← ServiceMonitor cho Prometheus scrape
│
├── opa/
│   ├── policies/
│   │   ├── zta_policy.rego            ← main ZTA policy: JWT + SVID + role check
│   │   ├── fraud_gate.rego            ← Gap 2 fix: enforce X-Fraud-Gate header
│   │   └── cross_cloud.rego           ← cross-cloud SVID pair allow-list
│   └── config/
│       └── opa-config.yaml            ← OPA server config + decision log path
│
├── envoy/
│   ├── envoy-sidecar.yaml             ← base sidecar config (ext_authz + JWT + mTLS)
│   ├── envoy-aws.yaml                 ← AWS-specific overrides (upstream cluster IPs)
│   ├── envoy-os.yaml                  ← OS-specific overrides
│   └── configmap.yaml                 ← K8s ConfigMap wrapping envoy config
│
├── shared/                            ← Python modules dùng chung bởi tất cả services
│   ├── __init__.py
│   ├── logging.py                     ← ZTLabLogger: structured JSON + trace_id injection
│   └── metrics.py                     ← Prometheus metrics definitions (counters, histograms)
│
├── services/
│   ├── Dockerfile                     ← shared Dockerfile (ARG SERVICE_NAME)
│   ├── docker-compose.local.yml       ← local dev/test without cloud
│   ├── api-gateway/
│   │   ├── main.py                    ← FastAPI: JWT verify, rate limit, routing
│   │   └── requirements.txt
│   ├── payment-service/
│   │   ├── main.py                    ← FastAPI: fraud gate, cross-cloud call to core-banking
│   │   └── requirements.txt
│   ├── fraud-detection/
│   │   ├── main.py                    ← FastAPI: stateless scorer (velocity+amount+time+geo)
│   │   └── requirements.txt
│   ├── notification-service/
│   │   ├── main.py                    ← FastAPI: event consumer, send email/SMS alerts
│   │   └── requirements.txt
│   ├── core-banking/
│   │   ├── main.py                    ← FastAPI: transaction orchestrator, fraud header check
│   │   └── requirements.txt
│   ├── account-service/
│   │   ├── main.py                    ← FastAPI: account CRUD, balance debit/credit
│   │   ├── models.py                  ← SQLAlchemy Account model
│   │   └── requirements.txt
│   └── transaction-service/
│       ├── main.py                    ← FastAPI: ledger record, history, 90-day stats
│       ├── models.py                  ← SQLAlchemy Transaction model
│       └── requirements.txt
│
├── plg-stack/
│   ├── docker-compose.plg.yml         ← Loki + Grafana stack trên aws-siem
│   ├── promtail/
│   │   ├── promtail-aws.yml           ← Promtail config cho AWS nodes (Envoy + OPA + system log)
│   │   └── promtail-os.yml            ← Promtail config cho OpenStack nodes
│   ├── loki/
│   │   └── loki-config.yml            ← Loki server config (retention, storage, limits)
│   └── grafana/
│       ├── grafana.ini                ← Grafana server config (port, auth, datasource)
│       ├── datasources/
│       │   └── loki-datasource.yml    ← Loki datasource tự động provision vào Grafana
│       ├── dashboards/
│       │   ├── dashboard-provider.yml ← Grafana dashboard auto-provision config
│       │   ├── zta-security-overview.json  ← Dashboard: ZTA violations, OPA denials, JWT failures
│       │   ├── envoy-access-logs.json      ← Dashboard: HTTP traffic, response code, latency
│       │   └── opa-decision-log.json       ← Dashboard: OPA allow/deny rate per service
│       └── alerting/
│           ├── brute-force-alert.yml       ← Alert: 5+ HTTP 401 trong 60s từ cùng source_ip
│           ├── lateral-movement-alert.yml  ← Alert: OPA deny với path lateral movement
│           ├── fraud-gate-bypass-alert.yml ← Alert: OPA deny_reason=fraud_gate_bypass
│           └── large-response-alert.yml    ← Alert: bytes_sent > 1MB từ OpenStack services
│
├── monitoring/
│   └── prometheus/
│       └── alerts.yml                 ← Prometheus alerting rules (high fraud rate, etc.)
│
├── tests/
│   ├── baseline_traffic.py            ← normal traffic generator (10 min warm-up)
│   ├── seed_db.py                     ← seed PostgreSQL với accounts + history
│   ├── scenario_01_brute_force.sh     ← T1110.001: 20 failed logins
│   ├── scenario_02_jwt_forgery.py     ← T1550.001: HS256 forged token
│   ├── scenario_03_lateral_movement.sh← T1021.007: wrong SVID pair call
│   ├── scenario_04_fraud_gate_bypass.py← T1078.004: Gap 2 validation
│   ├── scenario_05_high_velocity.py   ← T1496: 60 txn/min flood
│   ├── scenario_06_exfiltration.py    ← T1041: Gap 1 large response
│   ├── scenario_07_svid_expiry.sh     ← T1562.001: kill SPIRE agent, watch alert
│   ├── scenario_08_cross_cloud.sh     ← T1021: wrong SVID cross-cloud call
│   ├── scenario_09_privesc.sh         ← T1068: privilege escalation on pod
│   ├── scenario_10_portscan.sh        ← T1046: nmap scan from external
│   ├── scenario_11_cryptomining.sh    ← T1496: XMRig container deploy
│   ├── perf_overhead.py               ← P50/P95/P99 latency + ZTA overhead %
│   └── collect_metrics.py             ← MTTD, FPR, FNR collection từ Loki sau mỗi scenario
│
└── scripts/
    ├── health-check.sh                ← ping all services, check SPIRE, WG tunnel, Loki
    ├── wg-status.sh                   ← WireGuard tunnel status + peer handshake age
    └── reset-lab.sh                   ← tear down + redeploy (dùng khi cần fresh env)
```

---

## 2. terraform/ — Provisioning hạ tầng

**Mục đích:** Tạo toàn bộ cloud resources từ code. Không tạo VM thủ công.

| File | Nội dung | IMPL.md section |
|------|----------|----------------|
| `terraform/aws/main.tf` | VPC, subnets, EC2 instances, EIP cho WG gateway, bastion | §13.1 |
| `terraform/aws/security_groups.tf` | `sg-dmz`, `sg-private`, `sg-restricted`, `sg-management` — rule từng zone | §2.4 |
| `terraform/aws/variables.tf` | `aws_region`, `key_pair_name`, `admin_ip`, instance types | §13.1 |
| `terraform/aws/outputs.tf` | Export IPs để Ansible dùng làm inventory | §13.1 |
| `terraform/openstack/main.tf` | Networks, subnets, flavor instances | §13.2 |
| `terraform/openstack/security_groups.tf` | `neutron-sg-os-dmz`, `neutron-sg-os-private` | §2.5 |

**Khi cần sửa:**
- Thêm node mới → `main.tf` + `outputs.tf` + cập nhật `ansible/inventory/hosts.yml`
- Thay đổi Security Group rule → `security_groups.tf` + cập nhật §2.4/§2.5 trong IMPL.md
- Thay đổi instance type → `variables.tf`

---

## 3. ansible/ — Configuration management

**Mục đích:** Cài đặt và cấu hình phần mềm trên các node sau khi Terraform tạo xong.

> **Quan trọng:** Phải đọc §2.2.1 trong IMPL.md trước khi chạy bất kỳ playbook nào — OpenStack nodes không có floating IP, cần setup `br-provider` trên aio trước. Thứ tự deploy: xem §13.4 trong IMPL.md.

| File | Nội dung | IMPL.md section |
|------|----------|----------------|
| `ansible/inventory/hosts.yml` | Danh sách tất cả nodes theo group; OpenStack group không có ProxyJump — connect thẳng từ aio qua br-provider | §13.4 |
| `ansible/inventory/group_vars/all.yml` | `loki_ip=10.10.2.10`, `wg_server_ip=10.10.0.1`, `trust_domain=ztlab.local` | §2.3 |
| `ansible/playbooks/baseline.yml` | Update packages, auditd rules, fail2ban, sysctl IP forward | §13.3 |
| `ansible/playbooks/wireguard.yml` | Install WireGuard, copy `wg0.conf`, enable service | §3 |
| `ansible/playbooks/k3s.yml` | Install K3s server/agent, set `--flannel-iface=wg0` | §6.2 |
| `ansible/playbooks/promtail.yml` | Install Promtail binary, deploy config từ template, start service | §7.2 |
| `ansible/templates/promtail-config.yml.j2` | Template Promtail config — loki_ip từ group_vars, scrape paths theo node role | §7.2 |

**Khi cần sửa:**
- Thêm node → `inventory/hosts.yml`
- Thay Loki IP → `group_vars/all.yml` (propagate tự động qua templates)
- Thay đổi auditd rules → `playbooks/baseline.yml`
- Thêm log source mới → `templates/promtail-config.yml.j2` thêm `scrape_config` block

---

## 4. wireguard/ — VPN tunnel

**Mục đích:** Kết nối AWS ↔ OpenStack qua encrypted tunnel. Nền tảng của toàn bộ cross-cloud communication.

| File | Nội dung | IMPL.md section |
|------|----------|----------------|
| `wireguard/aws-gateway.conf` | `[Interface]` 10.10.0.1, `ListenPort=51820`, `PostUp` iptables rules | §3.2 |
| `wireguard/os-gateway.conf` | `[Interface]` 10.10.0.2, `[Peer]` Endpoint=`<AWS_EIP>:51820` | §3.3 |

**Khi cần sửa:**
- Thêm peer (node mới cần WG access) → thêm `[Peer]` block vào `aws-gateway.conf`
- Thay AWS EIP → `os-gateway.conf` field `Endpoint`
- Thay đổi tunnel subnet → cả 2 file + cập nhật §2.3 trong IMPL.md

---

## 5. spire/ — Identity foundation

**Mục đích:** Cấp phát SPIFFE SVID cho mọi workload. Là nền tảng của Zero Trust — thay thế IP-based trust.

| File | Nội dung | IMPL.md section |
|------|----------|----------------|
| `spire/server/server.conf` | Trust domain `ztlab.local`, SVID TTL 1h, CA TTL 7d, K8s PSAT attestor | §4.2 |
| `spire/agent/aws-agent.conf` | Agent cho AWS nodes, cluster name `aws-k3s`, socket path | §4.3 |
| `spire/agent/os-agent.conf` | Agent cho OS nodes, cluster name `os-k3s`, SPIRE Server = 10.10.3.10 | §4.3 |
| `spire/k8s/agent-daemonset.yaml` | DaemonSet — deploy agent lên mọi K3s node | §4.3 |
| `spire/k8s/server-deployment.yaml` | Deployment SPIRE Server trên `aws-security` node | §4.2 |
| `spire/scripts/register-aws-workloads.sh` | `spire-server entry create` cho 4 AWS services | §4.4 |
| `spire/scripts/register-os-workloads.sh` | `spire-server entry create` cho 3 OS services | §4.4 |
| `spire/scripts/verify-svids.sh` | Kiểm tra SVID đã được issue chưa sau deploy | §4.4 |

**Khi cần sửa:**
- Thêm service mới → chạy `spire-server entry create` + thêm vào script tương ứng
- Thay đổi SVID TTL → `server.conf` field `default_x509_svid_ttl`
- Thêm OpenStack node mới → `os-agent.conf` + update DaemonSet

---

## 6. k8s/ — Kubernetes manifests

**Mục đích:** Deploy toàn bộ workloads lên K3s clusters.

| File | Nội dung | IMPL.md section |
|------|----------|----------------|
| `k8s/namespaces.yaml` | Tạo namespaces: `financial`, `spire`, `identity`, `monitoring` | §6.2 |
| `k8s/keycloak/deployment.yaml` | Keycloak Deployment với env vars | §5.1 |
| `k8s/keycloak/realm-config.json` | Realm `ztlab`: clients, roles, token TTL | §5.1 |
| `k8s/financial/aws-services.yaml` | Deployment: api-gateway, payment, fraud, notification — mỗi pod có 3 containers (app + envoy + opa) | §6.2 |
| `k8s/financial/os-services.yaml` | Deployment: core-banking, account, transaction — mỗi pod có 3 containers | §6.3 |
| `k8s/financial/redis.yaml` | Redis cho fraud velocity window (30s TTL keys) | §6.5 |
| `k8s/financial/postgres-accounts.yaml` | PostgreSQL cho Account Service — accounts table | §6.7 |
| `k8s/financial/postgres-txn.yaml` | PostgreSQL cho Transaction Service — transactions table | §6.8 |
| `k8s/financial/network-policies/aws-allow-list.yaml` | Whitelist service graph AWS: api-gw → payment, fraud; payment → notification | §2.4 |
| `k8s/financial/network-policies/os-allow-list.yaml` | Whitelist service graph OS: core-banking → account, transaction | §2.5 |

**Khi cần sửa:**
- Thêm service mới → tạo Deployment block trong file yaml tương ứng + thêm SPIRE entry
- Thay đổi service graph (ai được gọi ai) → `network-policies/*.yaml` + `opa/policies/zta_policy.rego`
- Scale service → thay `replicas` trong Deployment

---

## 7. opa/ — Policy engine

**Mục đích:** Enforce Zero Trust policy tại mọi service-to-service call. Chạy như sidecar trong mỗi pod.

| File | Nội dung | IMPL.md section |
|------|----------|----------------|
| `opa/policies/zta_policy.rego` | Main policy: `valid_jwt` + `valid_svid` + `role_permits_action` | §5.2 |
| `opa/policies/fraud_gate.rego` | **Gap 2 fix**: enforce `X-Fraud-Gate: passed` + score < 75 trước khi core-banking nhận request | §6.9 |
| `opa/policies/cross_cloud.rego` | Allow-list SVID pairs được phép cross-cloud (payment → core-banking only) | §5.2 |
| `opa/config/opa-config.yaml` | OPA server config: port 9191, decision log path `/var/log/opa/decisions.json`, bundle | §5.2 |

**Khi cần sửa:**
- Thêm rule mới → thêm vào `zta_policy.rego`; thêm Grafana alert tương ứng vào `plg-stack/grafana/alerting/`
- Thay đổi role permission → `role_permits_action` block trong `zta_policy.rego`
- Thêm cross-cloud route mới → `cross_cloud.rego`
- **Quan trọng:** OPA quyết định write ra file `/var/log/opa/decisions.json` — Promtail scrape file này theo config `promtail-os.yml`/`promtail-aws.yml`

---

## 8. envoy/ — Sidecar proxy

**Mục đích:** Policy Enforcement Point (PEP) — intercept mọi traffic, gọi OPA để check, verify JWT, enforce mTLS với SPIRE SVID.

| File | Nội dung | IMPL.md section |
|------|----------|----------------|
| `envoy/envoy-sidecar.yaml` | Base config: `ext_authz` (→ OPA :9191), `jwt_authn` (→ Keycloak JWKS), mTLS với SPIRE SDS | §5.3 |
| `envoy/envoy-aws.yaml` | AWS overrides: upstream cluster IPs trong AWS subnet | §5.3 |
| `envoy/envoy-os.yaml` | OS overrides: upstream cluster IPs trong OS subnet | §5.3 |
| `envoy/configmap.yaml` | K8s ConfigMap wrapping — mount vào pod tại `/etc/envoy/` | §6.2 |

**Access log format** (quan trọng cho PLG Stack):
Envoy emit JSON log tại `/var/log/envoy/access.log` với fields: `timestamp`, `method`, `path`, `response_code`, `response_time`, `upstream`, `source_ip`, `bytes_sent`. Đây là input cho Promtail → Loki → Grafana.

**Khi cần sửa:**
- Thêm filter mới (rate limit, CORS) → `envoy-sidecar.yaml` trong `http_filters` section
- Thêm upstream cluster → `envoy-aws.yaml` hoặc `envoy-os.yaml`
- Thay đổi log format → cập nhật cả `plg-stack/promtail/promtail-aws.yml` pipeline stages

---

## 9. shared/ — Python shared modules

**Mục đích:** Tránh duplicate code giữa 7 services. Mọi service import từ đây.

| File | Nội dung | IMPL.md section |
|------|----------|----------------|
| `shared/logging.py` | `ZTLabLogger`: emit structured JSON với `trace_id`, `spiffe_id`, `service`, `cloud` | §6.1 |
| `shared/metrics.py` | Prometheus metrics definitions: `TXN_TOTAL`, `FRAUD_SCORE`, `CROSS_CLOUD_LATENCY`, `AUTH_FAILURES` | §6.1 |

**Khi cần sửa:**
- Thêm field mới vào log → `logging.py` trong `_emit()` method
- Thêm metric mới → `metrics.py`, đặt tên theo convention `ztlab_<noun>_<unit>`
- **Quan trọng:** Mỗi thay đổi field log phải cập nhật pipeline stage `json` trong `plg-stack/promtail/promtail-aws.yml` và `promtail-os.yml`

---

## 10. services/ — Financial microservices

**Mục đích:** Business logic của hệ thống banking. Tạo ra traffic thực tế để SIEM detect.

### Phân công theo cloud

| Service | Cloud | File | Chức năng chính | IMPL.md |
|---------|-------|------|----------------|---------|
| `api-gateway` | AWS | `services/api-gateway/main.py` | JWT verify (Keycloak JWKS), rate limit (Redis 60 rpm), route request | §6.3 |
| `payment-service` | AWS | `services/payment-service/main.py` | **Fraud gate orchestrator**: call fraud → inject header → forward to core-banking | §6.4 |
| `fraud-detection` | AWS | `services/fraud-detection/main.py` | Stateless scorer: velocity (Redis) + amount z-score + time + geo | §6.5 |
| `notification-service` | AWS | `services/notification-service/main.py` | Fire-and-forget: email/SMS on txn events | — |
| `core-banking` | OpenStack | `services/core-banking/main.py` | Transaction orchestrator + **fraud header validation** (Gap 2 Layer 2) | §6.6 |
| `account-service` | OpenStack | `services/account-service/main.py` | Account CRUD, balance debit/credit với row-level lock | §6.7 |
| `transaction-service` | OpenStack | `services/transaction-service/main.py` | Ledger record, tx history, 90-day stats cho fraud scorer | §6.8 |

### Call graph (service → service)

```
[external user]
    │ HTTPS
    ▼
api-gateway  ──── JWT verify (Keycloak) ────────────────────────────────────
    │ HTTP (intra-cluster)
    ▼
payment-service
    │── POST /score ──────────► fraud-detection  (AWS → AWS, intra-cluster)
    │                               │── GET /accounts/{id}/stats ──► core-banking
    │◄── {score, verdict} ──────────┘
    │
    │── POST /transactions/execute ─────────────────────────────────────────
    │   + X-Fraud-Score + X-Fraud-Gate headers    (AWS → OpenStack, WireGuard)
    ▼
core-banking  (OpenStack)
    │── GET /accounts/{id} ──────────► account-service     (OS intra-cluster)
    │── POST /ledger/record ──────────► transaction-service (OS intra-cluster)
    │── POST /accounts/{id}/debit ───► account-service
    │── POST /accounts/{id}/credit ──► account-service
    │◄── {transaction_id} ────────────┘
    │◄────────────────────────────────────────────────────────────────────────
    ▼ (return to payment-service → api-gateway → user)

payment-service ──► notification-service  (fire-and-forget, non-blocking)
```

### SIEM-relevant events per service (Loki labels)

| Service | Event type | Log field | Grafana Alert |
|---------|-----------|-----------|--------------|
| api-gateway | auth failure | `event: jwt_verification_failed` | brute-force-alert |
| api-gateway | rate limit | `event: rate_limit_exceeded` | (Prometheus alert) |
| payment-service | fraud block | `event: payment_blocked_fraud` | (Prometheus alert) |
| payment-service | fraud gate missing | `event: fraud_gate_bypass_attempt` | fraud-gate-bypass-alert |
| fraud-detection | score computed | `fraud_score`, `verdict` | (Prometheus alert) |
| core-banking | fraud header reject | `event: fraud_gate_bypass_attempt` | fraud-gate-bypass-alert |
| core-banking | txn complete | `event: transaction_completed` (AUDIT level) | — |
| transaction-service | ledger record | `event: transaction_recorded` (AUDIT level) | — |

**Khi cần sửa:**
- Thêm endpoint mới → thêm route trong `main.py` service tương ứng + thêm SPIRE allowed path vào OPA policy
- Thay đổi fraud threshold → `services/fraud-detection/main.py` constants `W_*` và `services/core-banking/main.py` env `MAX_FRAUD_SCORE`
- Thay đổi amount limit → `services/payment-service/main.py` env `MAX_SINGLE_TXN_VND`

---

## 11. plg-stack/ — Promtail + Loki + Grafana (SIEM)

**Mục đích:** Thu thập, lưu trữ, truy vấn và cảnh báo dựa trên log từ cả 2 cloud. Đây là SIEM trung tâm của hệ thống, thay thế ELK Stack bằng stack nhẹ hơn phù hợp cho lab.

### Data flow (Log Pipeline)

```
[Tất cả nodes — AWS & OpenStack]
    │
    ├── Envoy sidecar  → /var/log/envoy/access.log     (JSON)
    ├── OPA sidecar    → /var/log/opa/decisions.json   (JSON)
    └── System logs    → /var/log/syslog               (text)
    │
    │  Promtail (cài trên từng node — push qua WireGuard tunnel)
    ▼
[aws-siem: 10.10.2.10]
    │
    └── Loki :3100  (kho lưu trữ log trung tâm)
            │
            └── Grafana :3000  (dashboard + alerting)
```

| File | Nội dung | IMPL.md section |
|------|----------|----------------|
| `plg-stack/docker-compose.plg.yml` | Loki + Grafana containers trên aws-siem (single node) | §7.1 |
| `plg-stack/loki/loki-config.yml` | Loki config: ingester, storage filesystem, retention 30d, port 3100 | §7.2 |
| `plg-stack/promtail/promtail-aws.yml` | Promtail cho AWS nodes: scrape Envoy log, OPA decision log, system log; pipeline JSON parse | §7.3 |
| `plg-stack/promtail/promtail-os.yml` | Promtail cho OpenStack nodes: scrape Envoy + OPA + syslog; push qua WireGuard 10.10.2.10:3100 | §7.3 |
| `plg-stack/grafana/grafana.ini` | Grafana port 3000, disable signup, admin password | §7.4 |
| `plg-stack/grafana/datasources/loki-datasource.yml` | Loki datasource URL `http://loki:3100`, provisioned tự động | §7.4 |
| `plg-stack/grafana/dashboards/dashboard-provider.yml` | Config để Grafana auto-load tất cả JSON trong thư mục dashboards/ | §7.4 |
| `plg-stack/grafana/dashboards/zta-security-overview.json` | Overview dashboard: OPA deny rate, JWT failure count, top source IPs | §7.5 |
| `plg-stack/grafana/dashboards/envoy-access-logs.json` | Envoy traffic dashboard: request rate, status code histogram, P95 latency | §7.5 |
| `plg-stack/grafana/dashboards/opa-decision-log.json` | OPA policy dashboard: allow/deny per service, denial reasons breakdown | §7.5 |
| `plg-stack/grafana/alerting/brute-force-alert.yml` | LogQL alert: `count_over_time({event="jwt_verification_failed"}[1m]) > 5` | §7.6 |
| `plg-stack/grafana/alerting/lateral-movement-alert.yml` | LogQL alert: `{opa_result="false", path=~".*transactions.*"}` | §7.6 |
| `plg-stack/grafana/alerting/fraud-gate-bypass-alert.yml` | LogQL alert: `{deny_reason="fraud_gate_bypass"}` | §7.6 |
| `plg-stack/grafana/alerting/large-response-alert.yml` | LogQL alert: `{cloud="openstack"} \| bytes_sent > 1048576` | §7.6 |

### Loki Label Schema

Promtail gán labels khi scrape log. Labels này được dùng để filter trong Grafana:

| Label | Giá trị mẫu | Mô tả |
|-------|------------|-------|
| `job` | `envoy-access`, `opa-decisions`, `system` | Loại log source |
| `cloud` | `aws`, `openstack` | Cloud nào phát sinh log |
| `node` | `aws-k3s-worker-1`, `os-gateway`, ... | Node cụ thể |
| `service` | `api-gateway`, `core-banking`, ... | Service (từ JSON field, extracted) |
| `env` | `ztlab` | Environment tag |

### Grafana Alert → Attack Mapping

| Alert file | Attack scenario | ATT&CK | LogQL trigger |
|------------|----------------|--------|---------------|
| `brute-force-alert.yml` | 20 failed logins | T1110.001 | `count_over_time` jwt_failed > 5/min |
| `lateral-movement-alert.yml` | Wrong SVID pair | T1021.007 | `opa_result=false` on transaction path |
| `fraud-gate-bypass-alert.yml` | Bypass fraud check (Gap 2) | T1078.004 | `deny_reason=fraud_gate_bypass` |
| `large-response-alert.yml` | Data exfiltration (Gap 1) | T1041 | `bytes_sent > 1MB` from openstack |

**Khi cần sửa:**
- Thêm log source mới → `promtail-aws.yml` hoặc `promtail-os.yml` thêm `scrape_config` block
- Thêm detection rule mới → tạo file mới trong `grafana/alerting/`, viết LogQL query
- Thay đổi retention → `loki-config.yml` field `retention_period`
- Thêm dashboard panel → edit JSON trong `grafana/dashboards/`, re-provision hoặc import thủ công

---

## 12. monitoring/ — Dashboards + alerts

**Mục đích:** Prometheus alerting cho business metrics (fraud rate, cross-cloud latency).

| File | Nội dung | IMPL.md section |
|------|----------|----------------|
| `monitoring/prometheus/alerts.yml` | Alert rules: `fraud_rate_high`, `cross_cloud_latency_high`, `auth_failure_spike` | §6.1 |

> **Lưu ý:** Security log-based alerting (OPA deny, JWT failure, brute force...) đã chuyển sang Grafana Alerting trong `plg-stack/grafana/alerting/`. File này chỉ còn Prometheus metrics alerts cho business/performance metrics.

---

## 13. tests/ — Attack simulation + evaluation

**Mục đích:** Kiểm thử có cấu trúc theo MITRE ATT&CK, đo lường metrics định lượng cho báo cáo.

| File | Scenario | ATT&CK | IMPL.md |
|------|----------|--------|---------|
| `tests/scenario_00_full_suite.py` | End-to-end runner for scenarios 1-11, baseline warm-up, Loki metrics | — | §10 |
| `tests/baseline_traffic.py` | Normal traffic generator — chạy 10 min trước khi test | — | §15.2 |
| `tests/seed_db.py` | Tạo test accounts + 90-day transaction history | — | §15.2 |
| `tests/scenario_01_brute_force.sh` | 20 failed logins, measure MTTD | T1110.001 | §15.3 |
| `tests/scenario_02_jwt_forgery.py` | Forged HS256 token, expect 100% deny | T1550.001 | §15.3 |
| `tests/scenario_03_lateral_movement.sh` | Wrong SVID pair call, expect OPA deny | T1021.007 | §15.3 |
| `tests/scenario_04_fraud_gate_bypass.py` | Call core-banking without fraud headers — **Gap 2 validation** | T1078.004 | §15.3 |
| `tests/scenario_05_high_velocity.py` | 60 txn/min flood, expect block after txn 10 | T1496 | §15.3 |
| `tests/scenario_06_exfiltration.py` | Bulk data pull >1MB — **Gap 1 validation** | T1041 | §15.3 |
| `tests/scenario_07_svid_expiry.sh` | Kill SPIRE Agent, watch Grafana alert | T1562.001 | §15.3 |
| `tests/scenario_08_cross_cloud.sh` | AWS pod → OS service wrong SVID | T1021 | §15.3 |
| `tests/scenario_09_privesc.sh` | `sudo /bin/bash` on pod | T1068 | §15.3 |
| `tests/scenario_10_portscan.sh` | nmap scan từ external | T1046 | §15.3 |
| `tests/scenario_11_cryptomining.sh` | XMRig container — Prometheus CPU spike | T1496 | §15.3 |
| `tests/perf_overhead.py` | 500 requests @ concurrency=10, measure P95 latency + ZTA overhead% | — | §15.4 |
| `tests/collect_metrics.py` | Auto-collect MTTD, FPR, FNR từ Loki API sau mỗi scenario | — | §15.5 |

**Chạy toàn bộ test suite:**

```bash
# 1. Seed và baseline
python tests/seed_db.py
python tests/baseline_traffic.py &   # chạy background 10 min

# 2. Chạy từng scenario và collect metrics
for s in 01 02 03 04 05 06 07 08 09 10 11; do
  echo "=== Running Scenario $s ==="
  T_START=$(date +%s%N)
  bash tests/scenario_${s}_*.sh 2>&1 | tee logs/scenario_${s}.log
  python tests/collect_metrics.py --scenario $s --start $T_START >> results/metrics.json
  sleep 120   # 2 min cooldown between scenarios
done

# 3. Performance test
python tests/perf_overhead.py | tee results/perf.txt
```

---

## 14. scripts/ — Utilities

| File | Nội dung | Khi nào dùng |
|------|----------|-------------|
| `scripts/health-check.sh` | Ping tất cả services, verify SPIRE SVID, check WG handshake < 5 min, check Loki /ready endpoint | Trước khi chạy test |
| `scripts/wg-status.sh` | `wg show` + parse last handshake age + alert nếu > 3 min | Debug tunnel issues |
| `scripts/reset-lab.sh` | `terraform destroy` + `terraform apply` + Ansible deploy lại từ đầu | Khi cần fresh environment |

---

## 15. Logic flow index — Tìm nhanh theo tính năng

### "Tôi muốn thêm một microservice mới"
1. `services/<new-service>/main.py` — viết FastAPI app, import từ `shared/`
2. `spire/scripts/register-aws-workloads.sh` hoặc `register-os-workloads.sh` — thêm `spire-server entry create`
3. `k8s/financial/aws-services.yaml` hoặc `os-services.yaml` — thêm Deployment block
4. `opa/policies/cross_cloud.rego` — nếu service cần gọi cross-cloud
5. `k8s/financial/network-policies/` — thêm NetworkPolicy allow rule
6. `plg-stack/promtail/promtail-aws.yml` hoặc `promtail-os.yml` — thêm scrape path nếu log ra file riêng
7. `MAP.md` §10 — cập nhật call graph và SIEM event table

### "Tôi muốn thêm detection rule (alert) mới"
1. Xác định log source: Envoy (`/var/log/envoy/access.log`) hay OPA (`/var/log/opa/decisions.json`) hay system log?
2. Kiểm tra Loki đã nhận log chưa: Grafana → Explore → chọn datasource Loki → filter theo label `job`
3. Viết LogQL query trong Grafana Explore để xác nhận pattern
4. Tạo file alert mới: `plg-stack/grafana/alerting/<tên-alert>.yml`
5. `tests/scenario_XX_*.sh` — viết test script tương ứng
6. `MAP.md` §11 Grafana Alert table — cập nhật

### "Tôi muốn thay đổi fraud threshold"
1. `services/fraud-detection/main.py` — constants `W_VELOCITY`, `W_AMOUNT` (weight) và verdicts thresholds (40/75)
2. `services/core-banking/main.py` — env `MAX_FRAUD_SCORE` (default 74)
3. `opa/policies/fraud_gate.rego` — `to_number(...) < 75` → thay giá trị mới
4. Test lại với `tests/scenario_05_high_velocity.py`

### "OpenStack nodes unreachable từ Ansible / aio không ping được VM"
1. `IMPLEMENTATION.md §2.2.1` — đọc toàn bộ section này trước
2. Chạy `sudo ovs-vsctl show` trên aio để xác định tên bridge provider (`br-provider` hoặc `br-ex`)
3. `sudo ip addr add 192.168.100.1/24 dev br-provider` — gán IP cho aio trên DMZ network
4. `sudo ip route add 192.168.101.0/24 via 192.168.100.10` — route đến os-net-private **qua os-gateway**
5. `sudo ip route add 192.168.102.0/24 via 192.168.100.10` — route đến os-net-identity qua os-gateway
6. Mở SG port 22 từ `192.168.100.1/32` trong **cả 3 SG**: `neutron-sg-os-dmz`, `neutron-sg-os-private`, `neutron-sg-os-identity`
7. Chạy `bash /tmp/check-os-connectivity.sh` để verify trước khi chạy Ansible
8. Persistent: netplan với routes via 192.168.100.10 (§2.2.1)

### "Thứ tự chạy Ansible playbook đúng là gì?"
1. `IMPLEMENTATION.md §13.4` — cheatsheet 9 bước đầy đủ
2. Không bao giờ chạy `ansible all` trước khi WireGuard tunnel up
3. Thứ tự cứng: `baseline (phase1)` → `wireguard (2 gateway)` → `verify tunnel` → `baseline (all)` → `k3s` → `promtail`

### "WireGuard tunnel down — debug"
1. `scripts/wg-status.sh` — check last handshake
2. `wireguard/aws-gateway.conf` và `wireguard/os-gateway.conf` — verify config
3. `ansible/inventory/group_vars/all.yml` — verify `wg_server_ip`
4. Loki sẽ không nhận log từ OS nodes khi tunnel down — check Grafana Explore, filter `cloud=openstack`, xem có log gần đây không

### "MTTD cao hơn expected — debug"
1. Kiểm tra Promtail → Loki connection trên node: `systemctl status promtail` + `journalctl -u promtail -n 50`
2. Kiểm tra Loki nhận log: `curl http://10.10.2.10:3100/ready` → phải trả về `ready`
3. Kiểm tra Loki ingestion: `curl http://10.10.2.10:3100/metrics | grep loki_ingester`
4. Kiểm tra Grafana alert đã fire chưa: Grafana → Alerting → Alert Rules
5. Xem `plg-stack/docker-compose.plg.yml` để restart Loki/Grafana nếu cần

---

## 16. Quy tắc đặt tên và thêm file mới

### Naming conventions

| Loại file | Convention | Ví dụ |
|-----------|-----------|-------|
| Terraform | lowercase-hyphen | `security_groups.tf`, `main.tf` |
| Ansible playbook | lowercase-hyphen | `promtail.yml` |
| K8s manifest | lowercase-hyphen | `aws-services.yaml` |
| Python service | `main.py` trong thư mục service | `services/api-gateway/main.py` |
| Test script | `scenario_NN_description.{sh,py}` | `scenario_04_fraud_gate_bypass.py` |
| Grafana alert | `<attack-type>-alert.yml` | `brute-force-alert.yml` |
| Grafana dashboard | `<component>-dashboard.json` hoặc `zta-<topic>.json` | `zta-security-overview.json` |
| Loki label key | `snake_case` | `source_ip`, `cloud`, `service` |
| Prometheus metric | `ztlab_<noun>_<unit>` | `ztlab_transactions_total` |

### Checklist khi thêm file mới

```
[ ] File đặt đúng thư mục theo MAP.md
[ ] Cập nhật MAP.md section tương ứng (thêm hàng vào bảng)
[ ] Nếu là Python service: import từ shared/, không copy-paste logger/metrics
[ ] Nếu là config file: thêm tham chiếu vào IMPLEMENTATION.md section tương ứng
[ ] Nếu là test script: đặt tên theo convention scenario_NN_*.{sh,py}
[ ] Nếu là Grafana alert: viết LogQL query, test trên Grafana Explore trước
[ ] .env.template: thêm env var mới nếu file cần secret
[ ] .gitignore: đảm bảo không commit .env, *.key, *.pem, *.p12
```

---

> **Cập nhật lần cuối:** Tháng 4/2026  
> **Phiên bản:** 2.0 (simplified: PLG Stack thay thế ELK+Wazuh+Kafka; loại bỏ AI Engine và SOAR)