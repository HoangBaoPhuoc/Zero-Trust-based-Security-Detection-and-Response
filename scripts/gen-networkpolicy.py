#!/usr/bin/env python3
"""Sinh NetworkPolicy pod-level (L4) từ policy/service-graph.yaml (T-3.2).

Sinh 4 file:
  k8s/crapi/network-policies/aws-pod-segmentation.yaml   (edge cluster=aws)
  k8s/crapi/network-policies/os-pod-segmentation.yaml    (edge cluster=openstack)
  k8s/crapi/network-policies/aws-allow-list.yaml         (Phần 2, 2026-09)
  k8s/crapi/network-policies/os-allow-list.yaml          (Phần 2, 2026-09)

Mỗi NetworkPolicy pod-segmentation chỉ siết chiều INGRESS của một workload đích
cụ thể, gộp tất cả nguồn được phép gọi tới nó (từ mọi edge có `to` trỏ vào
workload đó trong cùng cluster). Bỏ qua edge `cross_cluster: true` — cơ chế
cross-cloud dùng ipBlock (NodePort qua WireGuard), khai báo trong
{aws,os}-allow-list.yaml, không phải podSelector.

allow-list (baseline) gồm 2 phần: phần hạ tầng thuần (Traefik/Prometheus/
healthcheck/DNS/istiod/Loki — không phải edge service-to-service, khai tĩnh
trong `netpol_baseline:` của service-graph) + phần ipBlock cross-cloud, TÍNH
RA từ mọi edge `cross_cluster: true` (gộp l4_ports theo cặp cluster nguồn->
đích) — đây là phần đã trôi trong lịch sử (Keycloak A1 đổi cloud) nên không
còn cho khai tay nữa.

LƯU Ý (T-3.1, KET-QUA-KIEM-TRA.md): NetworkPolicy sinh ra đây hiện KHÔNG
được kube-router enforce cho traffic đi qua Istio sidecar trên hạ tầng đang
dùng. Vẫn sinh đúng theo ý định/khai báo — giá trị tài liệu hoá + sẵn sàng
nếu hạ tầng CNI thay đổi.

Usage: python3 scripts/gen-networkpolicy.py
Nghiệm thu: `git diff k8s/crapi/network-policies/*.yaml` rỗng nếu
service-graph-crapi.yaml không đổi.
"""
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAPH_FILE = REPO_ROOT / "policy" / "service-graph-crapi.yaml"
NETPOL_DIR = REPO_ROOT / "k8s" / "crapi" / "network-policies"
NS = "crapi"  # default/most-common namespace; gen_for_cluster now derives the
# real namespace per policy from the destination workload's own `namespace`
# field instead of assuming everything lives in NS — see bug note below.

HEADER = """# GENERATED FILE — KHÔNG SỬA TAY. Nguồn: policy/service-graph-crapi.yaml
# Sinh lại: python3 scripts/gen-networkpolicy.py
#
# T-3.1/T-3.2 — mỗi NetworkPolicy chỉ siết chiều INGRESS của một workload
# đích, khớp đúng traffic thật đã đo (T-1.1). Egress không đổi (xem
# {allow_list_file}). LƯU Ý: NetworkPolicy này hiện KHÔNG được kube-router
# enforce cho traffic có Istio sidecar trên hạ tầng đang dùng — xem
# KET-QUA-KIEM-TRA.md §T-3.1 trước khi coi đây là lớp bảo vệ đang hoạt động.
"""


def app_label(graph: dict, workload: str) -> str:
    w = graph["workloads"][workload]
    return w.get("app_label") or w.get("service_account") or workload.split("/")[-1]


def render_policy(
    name: str,
    namespace: str,
    dest_label: str,
    sources: list[tuple[str, list[int], str]],
    cross_cluster_ingress: list[tuple[str, list[int]]] | None = None,
) -> str:
    # Gộp theo (source, ports, source_namespace) — mỗi source có thể xuất
    # hiện ở nhiều edge (không xảy ra trong graph hiện tại nhưng generator
    # vẫn xử lý đúng nếu có).
    #
    # Bug tìm thấy sống 2026-09-13 (destroy+redeploy sạch): trước bản sửa
    # này, MỌI policy sinh ra namespace: crapi (hardcode) và MỌI `from` chỉ
    # có podSelector (giả định nguồn luôn cùng namespace với đích) — đúng cho
    # mọi workload cho tới khi Keycloak (Phần 1.2) chuyển sang ns `identity`.
    # Kết quả: NetworkPolicy os-pod-keycloak bị đặt SAI namespace (crapi thay
    # vì identity, nên không áp dụng cho pod Keycloak thật), và os-pod-opa
    # thiếu hẳn namespaceSelector cho nguồn `identity` — ext_authz từ Keycloak
    # bị NetworkPolicy chặn ở L4 trước khi tới OPA, Envoy fail-closed thành
    # 403 dù mTLS/OPA policy đều đúng. Namespace giờ lấy từ chính
    # workloads.<id>.namespace trong service-graph — nguồn đã đúng từ đầu,
    # generator chỉ là chưa dùng tới.
    from_blocks = []
    for src_label, ports, src_ns in sources:
        if src_ns == namespace:
            peer = f"""        - podSelector:
            matchLabels:
              app: {src_label}"""
        else:
            peer = f"""        - namespaceSelector:
            matchLabels: {{ kubernetes.io/metadata.name: {src_ns} }}
          podSelector:
            matchLabels:
              app: {src_label}"""
        from_blocks.append(
            f"""    - from:
{peer}
      ports:
{render_ports(ports)}"""
        )
    # Bug tìm thấy sống 2026-09-13, cùng buổi destroy+redeploy: defining ANY
    # Ingress NetworkPolicy for a pod switches it from k8s's default
    # allow-all to deny-except-listed — including traffic this generator
    # otherwise deliberately never models here (cross_cluster edges use the
    # ipBlock baseline instead, see gen_baseline). That's harmless for a
    # destination with NO other ingress source, but the moment a workload
    # gets BOTH an intra-cluster caller (so this function runs for it at
    # all) AND a legitimate cross-cluster caller (aws/bff, aws/opa ->
    # openstack/keycloak), the cross-cluster NodePort traffic is now
    # silently default-denied — confirmed live: `os-pod-keycloak` (added for
    # kc-admin-setup, Phần 1.2) blocked bff's login redirect to Keycloak with
    # a bare TCP refusal, even though mTLS/SPIRE/OPA were all already
    # correct. ns `crapi` never hit this because `{prefix}-crapi-allow-
    # baseline`'s podSelector: {{}} covers every pod there with its own
    # ipBlock rules; Keycloak's ns `identity` has no such baseline. Add the
    # missing ipBlock peer directly onto this policy instead — reuses the
    # ports already collected from this destination's intra-cluster edges,
    # since that's its real listening port (a NodePort's l4_ports value is
    # the externally-visible port, already rewritten by kube-proxy DNAT by
    # the time NetworkPolicy admission actually inspects the packet).
    for cidr, ports in cross_cluster_ingress or []:
        from_blocks.append(
            f"""    - from:
        - ipBlock:
            cidr: {cidr}
      ports:
{render_ports(ports)}"""
        )
    ingress = "\n".join(from_blocks)
    return f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {name}
  namespace: {namespace}
spec:
  podSelector:
    matchLabels:
      app: {dest_label}
  policyTypes:
    - Ingress
  ingress:
{ingress}
"""


def render_ports(ports: list[int]) -> str:
    lines = []
    for p in ports:
        lines.append(f"        - port: {p}")
        lines.append("          protocol: TCP")
    return "\n".join(lines)


def gen_for_cluster(graph: dict, cluster: str, prefix: str, allow_list_file: str) -> str:
    by_dest: dict[str, list[tuple[str, list[int], str]]] = {}
    for edge in graph["edges"]:
        if edge.get("cross_cluster"):
            continue
        src_workload = graph["workloads"].get(edge["from"])
        dst_workload = graph["workloads"].get(edge["to"])
        if not src_workload or not dst_workload:
            continue
        if src_workload["cluster"] != cluster or dst_workload["cluster"] != cluster:
            continue
        ports = edge.get("l4_ports")
        if not ports:
            continue
        by_dest.setdefault(edge["to"], []).append(
            (app_label(graph, edge["from"]), ports, src_workload["namespace"])
        )

    # See render_policy's bug note: only destinations that ALREADY got an
    # intra-cluster policy above need a cross-cluster ipBlock exemption too
    # (a destination with none stays in k8s's default-allow, nothing to fix).
    # Grouped by (dest, source cluster) so e.g. aws/bff and aws/opa both
    # calling openstack/keycloak produce ONE merged ipBlock rule, not two
    # identical ones.
    #
    # CIDR gotcha (found live 2026-09-13, same session): the ipBlock must be
    # the DESTINATION cluster's own private_cidr, NOT the source's — the
    # cross-cloud gateway (os_gateway/aws_gateway) SNATs this traffic to its
    # OWN address on the destination's private subnet before forwarding, so
    # by the time it reaches the destination node the packet's source IP is
    # already inside that subnet, never the caller's real cluster's CIDR.
    # Confirmed both empirically (iptables counters stayed at 0 with the
    # source-cluster CIDR, connection still refused) and by
    # terraform/openstack/security_groups.tf's own
    # os_private_ingress_nodeport_from_aws rule, which already documents
    # this ("source is os_gateway's SNAT'd IP, not the original AWS-side
    # IP") and allowlists the whole 192.168.101.0/24 (openstack's own
    # private_cidr) for exactly this reason — this generator now matches
    # that existing, already-correct precedent instead of the naive guess.
    cross_ingress_raw: dict[str, set[int]] = {}
    for edge in graph["edges"]:
        if not edge.get("cross_cluster") or edge["to"] not in by_dest:
            continue
        src_workload = graph["workloads"].get(edge["from"])
        dst_workload = graph["workloads"].get(edge["to"])
        if not src_workload or not dst_workload or dst_workload["cluster"] != cluster:
            continue
        real_ports = {p for _, ports, _ in by_dest[edge["to"]] for p in ports}
        cross_ingress_raw.setdefault(edge["to"], set()).update(real_ports)
    #
    # Second gotcha, same session: even with the CORRECT cidr above, kube-
    # router never actually admitted the traffic — confirmed via tcpdump on
    # the destination node that the real source IP (os_gateway's SNAT
    # address, 192.168.101.1) exactly matches 192.168.101.0/24, then proving
    # via a live-patched test that a specific ipBlock (/24 AND an exact /32
    # for that same address) both still got refused while 0.0.0.0/0 worked
    # immediately — on a fresh NetworkPolicy (deleted and recreated, ruling
    # out stale ipset state). The nodes run `iptables v1.8.7 (nf_tables)`;
    # `-m set --match-set` against a `hash:net` ipset is a known-flaky
    # combination under the nf_tables backend. This isn't fixable from the
    # manifest layer, so this uses 0.0.0.0/0 instead — still scoped to only
    # the exact ports of an already-mTLS-STRICT workload, and the real
    # authorization decision for this hop is L7 (PeerAuthentication STRICT +
    # AuthorizationPolicy CUSTOM -> OPA), matching every other pod-
    # segmentation policy's own documented caveat ("L7 là lớp phân đoạn
    # thật") — this is exactly that path, made explicit instead of silently
    # broken.
    cross_ingress: dict[str, list[tuple[str, list[int]]]] = {}
    for dest, ports in cross_ingress_raw.items():
        cross_ingress.setdefault(dest, []).append(("0.0.0.0/0", sorted(ports)))

    policies = [HEADER.format(allow_list_file=allow_list_file)]
    for dest in sorted(by_dest):
        dest_label = app_label(graph, dest)
        dest_ns = graph["workloads"][dest]["namespace"]
        policy_name = f"{prefix}-pod-{dest_label}"
        policies.append(
            render_policy(policy_name, dest_ns, dest_label, by_dest[dest], cross_ingress.get(dest))
        )
    return "---\n".join(policies)


BASELINE_HEADER = """# GENERATED FILE — KHÔNG SỬA TAY. Nguồn: policy/service-graph-crapi.yaml
# (netpol_baseline: + edge cross_cluster). Sinh lại: python3 scripts/gen-networkpolicy.py
#
# 2 phần: (1) hạ tầng thuần (Traefik/Prometheus/healthcheck/DNS/istiod/Loki) —
# khai tĩnh trong netpol_baseline: của service-graph, không phải edge service-
# to-service. (2) ipBlock cross-cloud — TÍNH RA từ mọi edge cross_cluster: true
# (gộp l4_ports theo cặp cluster nguồn->đích) để không còn trôi khi một
# workload đổi cloud (đúng bug đã xảy ra với Keycloak ở A1).
#
# LƯU Ý (như pod-segmentation): NetworkPolicy này hiện KHÔNG được kube-router
# enforce cho traffic có Istio sidecar trên hạ tầng đang dùng — L7 (OPA
# service_acl) là lớp phân đoạn thật. File này đúng về khai báo/ý định + có
# hiệu lực cho path không-sidecar (opa:8181, DNS, cross-cloud ipBlock).
"""


def _render_port_entry(p) -> list[str]:
    if isinstance(p, dict):
        return [f"        - {{ port: {p['port']}, protocol: {p.get('protocol', 'TCP')} }}"]
    return [f"        - {{ port: {p}, protocol: TCP }}"]


def _render_peer_rule(direction: str, rule: dict) -> str:
    """direction: 'ingress' (key 'from') hoặc 'egress' (key 'to')."""
    peer_key = "from" if direction == "ingress" else "to"
    peers = []
    if "from_ns" in rule or "to_ns" in rule:
        ns = rule.get("from_ns") or rule.get("to_ns")
        peers.append(f"        - namespaceSelector:\n            matchLabels: {{ kubernetes.io/metadata.name: {ns} }}")
    for cidr in rule.get("from_cidrs", []) or rule.get("to_cidrs", []):
        peers.append(f"        - ipBlock: {{ cidr: {cidr} }}")
    peer_block = "\n".join(peers)
    ports = rule.get("ports") or []
    lines = [f"    - {peer_key}:", peer_block]
    if ports:
        lines.append("      ports:")
        for p in ports:
            lines.extend(_render_port_entry(p))
    return "\n".join(lines)


def _cross_cloud_egress_rules(graph: dict, source_cluster: str) -> list[dict]:
    """Gộp l4_ports của mọi edge cross_cluster có from.cluster == source_cluster,
    theo cluster đích — sinh 1 rule egress ipBlock cho mỗi cluster đích khác
    nhau (thực tế hiện chỉ có 2 cluster nên luôn tối đa 1 rule)."""
    by_dest_cluster: dict[str, tuple[set[int], set[str]]] = {}
    for edge in graph["edges"]:
        if not edge.get("cross_cluster"):
            continue
        src = graph["workloads"].get(edge["from"])
        dst = graph["workloads"].get(edge["to"])
        if not src or not dst or src["cluster"] != source_cluster:
            continue
        ports, srcs = by_dest_cluster.setdefault(dst["cluster"], (set(), set()))
        ports.update(edge.get("l4_ports") or [])
        srcs.add(f"{edge['from']}->{edge['to']}")
    rules = []
    for dest_cluster, (ports, edge_names) in sorted(by_dest_cluster.items()):
        cidr = graph["clusters"][dest_cluster]["private_cidr"]
        rules.append({
            "to_cidrs": [cidr],
            "ports": sorted(ports),
            "comment": f"cross-cloud -> {dest_cluster} ({', '.join(sorted(edge_names))})",
        })
    return rules


def gen_baseline(graph: dict, cluster: str) -> str:
    baseline = graph["netpol_baseline"][cluster]
    name = "aws" if cluster == "aws" else "os"
    ingress_rules = list(baseline.get("ingress", []))
    egress_rules = list(baseline.get("egress", [])) + _cross_cloud_egress_rules(graph, cluster)

    parts = [BASELINE_HEADER, "---",
              "apiVersion: networking.k8s.io/v1",
              "kind: NetworkPolicy",
              "metadata:",
              f"  name: {name}-crapi-allow-baseline",
              f"  namespace: {NS}",
              "spec:",
              "  podSelector: {}",
              "  policyTypes: [Ingress, Egress]",
              "  ingress:"]
    for rule in ingress_rules:
        if rule.get("comment"):
            parts.append(f"    # {rule['comment']}")
        parts.append(_render_peer_rule("ingress", rule))
    parts.append("  egress:")
    for rule in egress_rules:
        if rule.get("comment"):
            parts.append(f"    # {rule['comment']}")
        parts.append(_render_peer_rule("egress", rule))
    return "\n".join(parts) + "\n"


def main() -> None:
    NETPOL_DIR.mkdir(parents=True, exist_ok=True)
    graph = yaml.safe_load(GRAPH_FILE.read_text())

    aws_content = gen_for_cluster(graph, "aws", "aws", "aws-allow-list.yaml")
    os_content = gen_for_cluster(graph, "openstack", "os", "os-allow-list.yaml")

    (NETPOL_DIR / "aws-pod-segmentation.yaml").write_text(aws_content)
    (NETPOL_DIR / "os-pod-segmentation.yaml").write_text(os_content)

    (NETPOL_DIR / "aws-allow-list.yaml").write_text(gen_baseline(graph, "aws"))
    (NETPOL_DIR / "os-allow-list.yaml").write_text(gen_baseline(graph, "openstack"))

    print(f"Sinh xong: {NETPOL_DIR.relative_to(REPO_ROOT)}/{{aws,os}}-{{pod-segmentation,allow-list}}.yaml")


if __name__ == "__main__":
    main()
