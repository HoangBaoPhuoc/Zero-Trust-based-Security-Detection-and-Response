"""Kiểm tra policy/service-graph-crapi.yaml là nguồn sự thật duy nhất thật sự
cho phân đoạn service-to-service của crAPI (L7 + L4 + danh tính SPIFFE).

Bài test (Phần 2, remediation 2026-09 mở rộng từ bản gốc 2 bài):
1. TOÀN BỘ artifact sinh ra (opa/crapi-policies/service_acl.rego,
   k8s/crapi/network-policies/{aws,os}-{pod-segmentation,allow-list}.yaml,
   scripts/spire-entries.generated.sh) khớp CHÍNH XÁC với những gì generator
   sinh ra từ service-graph-crapi.yaml ngay lúc này — nếu ai đó sửa tay 1
   trong 2 phía (graph hoặc file generated) mà quên chạy lại generator, test
   này FAIL ("chạy generator -> git diff không đổi").
2. Mọi edge nghiệp vụ (không phải l4_only, không phải cross_cluster) khai báo
   trong service-graph-crapi.yaml phải xuất hiện Ở CẢ HAI file sinh ra (L7 và
   L4) — không có cặp nào chỉ được khai báo ở 1 tầng mà quên tầng kia.
3. Mọi workload cần danh tính mesh (spiffe != false) phải có mặt trong
   scripts/spire-entries.generated.sh; mọi workload xuất hiện là from/to của
   1 edge KHÔNG l4_only (tức tham gia service_acl L7 — cần OPA kiểm SVID
   thật) không được khai `spiffe: false` — nếu không thì rego sinh ra sẽ đòi
   `valid_svid` cho một workload không hề có SVID, tự khoá chết chính nó.

LƯU Ý: test này chỉ xác nhận tính nhất quán giữa các FILE KHAI BÁO. NetworkPolicy
sinh ra CÓ hiệu lực thật ở kube-router (đo 2026-09-25: counter `reject` trong
chain KUBE-POD-FW-* tăng khi thiếu rule cho phép) — chẩn đoán cũ "không được
enforce"/"node thiếu ipset" là sai. Vì vậy thiếu 1 cổng ở baseline là làm
đứt traffic thật, xem test_baseline_egress_covers_every_intra_namespace_edge_port.

Chạy: python3 -m pytest tests/test_service_graph_consistency.py -v
      (hoặc: python3 tests/test_service_graph_consistency.py)
"""
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAPH_FILE = REPO_ROOT / "policy" / "service-graph-crapi.yaml"
REGO_OUT = REPO_ROOT / "opa" / "crapi-policies" / "service_acl.rego"
NETPOL_AWS = REPO_ROOT / "k8s" / "crapi" / "network-policies" / "aws-pod-segmentation.yaml"
NETPOL_OS = REPO_ROOT / "k8s" / "crapi" / "network-policies" / "os-pod-segmentation.yaml"
ALLOWLIST_AWS = REPO_ROOT / "k8s" / "crapi" / "network-policies" / "aws-allow-list.yaml"
ALLOWLIST_OS = REPO_ROOT / "k8s" / "crapi" / "network-policies" / "os-allow-list.yaml"
SPIRE_ENTRIES = REPO_ROOT / "scripts" / "spire-entries.generated.sh"
DOCS_TABLES = REPO_ROOT / "docs" / "GENERATED-SERVICE-GRAPH.md"


def _run_generator(script: str) -> None:
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / script)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert result.returncode == 0, f"{script} lỗi:\n{result.stdout}\n{result.stderr}"


def test_generated_files_match_source_of_truth():
    """Chạy generator xong, nội dung MỌI file generated không đổi."""
    before = {
        REGO_OUT: REGO_OUT.read_text(),
        NETPOL_AWS: NETPOL_AWS.read_text(),
        NETPOL_OS: NETPOL_OS.read_text(),
        ALLOWLIST_AWS: ALLOWLIST_AWS.read_text(),
        ALLOWLIST_OS: ALLOWLIST_OS.read_text(),
        SPIRE_ENTRIES: SPIRE_ENTRIES.read_text(),
        DOCS_TABLES: DOCS_TABLES.read_text(),
    }

    _run_generator("gen-rego-acl.py")
    _run_generator("gen-networkpolicy.py")
    _run_generator("gen-spire-entries.py")
    _run_generator("gen-docs-tables.py")

    for path, old_content in before.items():
        new_content = path.read_text()
        assert new_content == old_content, (
            f"{path.relative_to(REPO_ROOT)} lệch với policy/service-graph-crapi.yaml — "
            f"ai đó sửa tay file generated hoặc quên chạy lại generator sau khi sửa graph."
        )


def _business_edges(graph: dict) -> list[dict]:
    return [
        e for e in graph["edges"]
        if not e.get("l4_only") and not e.get("cross_cluster")
    ]


def _app_label(graph: dict, workload: str) -> str:
    w = graph["workloads"][workload]
    return w.get("app_label") or w.get("service_account") or workload.split("/")[-1]


def test_every_business_edge_present_in_both_layers():
    """Mọi cặp nguồn->đích nghiệp vụ (cùng cluster) phải có mặt ở CẢ L7 (rego)
    lẫn L4 (NetworkPolicy) — không cặp nào chỉ khai báo 1 tầng rồi quên tầng kia.

    KHÔNG kiểm tra enforcement thật — chỉ kiểm tra khai báo.
    """
    graph = yaml.safe_load(GRAPH_FILE.read_text())
    rego_text = REGO_OUT.read_text()
    netpol_aws = yaml.safe_load_all(NETPOL_AWS.read_text())
    netpol_os = yaml.safe_load_all(NETPOL_OS.read_text())
    netpol_docs = [d for d in list(netpol_aws) + list(netpol_os) if d]

    # L4: gom (dest podSelector app label) -> {source app labels được allow}
    l4_allowed: dict[str, set[str]] = {}
    for doc in netpol_docs:
        dest_label = doc["spec"]["podSelector"]["matchLabels"]["app"]
        sources = set()
        for rule in doc["spec"].get("ingress", []):
            for peer in rule.get("from", []):
                sel = peer.get("podSelector", {}).get("matchLabels", {})
                if "app" in sel:
                    sources.add(sel["app"])
        l4_allowed[dest_label] = sources

    missing_l4 = []
    missing_l7 = []
    for edge in _business_edges(graph):
        src_workload = graph["workloads"][edge["from"]]
        dst_workload = graph["workloads"][edge["to"]]
        if src_workload["cluster"] != dst_workload["cluster"]:
            continue  # cross-cluster đã lọc, nhưng phòng hờ dữ liệu graph sai

        dst_label = _app_label(graph, edge["to"])
        src_label = _app_label(graph, edge["from"])
        if src_label not in l4_allowed.get(dst_label, set()):
            missing_l4.append(f"{edge['from']} -> {edge['to']}")

        src_id = f'spiffe://{graph["trust_domain"]}/{edge["from"]}'
        dst_id = f'spiffe://{graph["trust_domain"]}/{edge["to"]}'
        if f'"{src_id}"' not in rego_text or f'"{dst_id}"' not in rego_text:
            missing_l7.append(f"{edge['from']} -> {edge['to']}")

    assert not missing_l4, f"Thiếu ở NetworkPolicy (L4): {missing_l4}"
    assert not missing_l7, f"Thiếu ở service_acl.rego (L7): {missing_l7}"


def _spire_registered_ids(graph: dict) -> set[str]:
    text = SPIRE_ENTRIES.read_text()
    ids = set()
    for line in text.splitlines():
        line = line.strip().strip('"')
        if line.startswith(f'spiffe://{graph["trust_domain"]}/'):
            ids.add(line.split("|")[0])
    return ids


def test_every_l7_workload_has_spire_entry_and_real_spiffe():
    """Mọi workload tham gia edge L7 (không l4_only — tức OPA sẽ đòi valid_svid
    cho nó) phải (a) có mặt trong scripts/spire-entries.generated.sh và (b)
    KHÔNG được khai `spiffe: false` trong service-graph-crapi.yaml — 2 điều
    kiện này lệch nhau nghĩa là một workload được rego yêu cầu SVID thật
    nhưng SPIRE không hề cấp, hoặc graph tự mâu thuẫn (spiffe:false nhưng vẫn
    đứng vai from/to của 1 edge L7)."""
    graph = yaml.safe_load(GRAPH_FILE.read_text())
    spire_ids = _spire_registered_ids(graph)
    trust_domain = graph["trust_domain"]

    l7_workloads = set()
    for edge in graph["edges"]:
        if edge.get("l4_only"):
            continue
        l7_workloads.add(edge["from"])
        l7_workloads.add(edge["to"])

    missing_spire = []
    marked_no_spiffe = []
    for w in sorted(l7_workloads):
        spiffe_id = f"spiffe://{trust_domain}/{w}"
        if graph["workloads"][w].get("spiffe") is False:
            marked_no_spiffe.append(w)
        if spiffe_id not in spire_ids:
            missing_spire.append(w)

    assert not marked_no_spiffe, (
        f"Workload tham gia edge L7 (OPA đòi valid_svid) nhưng khai `spiffe: false`: "
        f"{marked_no_spiffe} — service-graph-crapi.yaml tự mâu thuẫn."
    )
    assert not missing_spire, (
        f"Workload tham gia edge L7 nhưng KHÔNG có entry trong "
        f"scripts/spire-entries.generated.sh: {missing_spire} — chạy "
        f"python3 scripts/gen-spire-entries.py rồi kiểm lại workloads: có "
        f"'service_account' hay chưa."
    )


def _baseline_intra_ns_egress_ports(allowlist_path: Path) -> set:
    """Cổng của rule egress `namespaceSelector: crapi` trong baseline sinh ra."""
    ports = set()
    for doc in yaml.safe_load_all(allowlist_path.read_text()):
        if not doc or doc.get("kind") != "NetworkPolicy":
            continue
        for rule in doc["spec"].get("egress", []):
            for peer in rule.get("to", []):
                sel = peer.get("namespaceSelector", {}).get("matchLabels", {})
                if sel.get("kubernetes.io/metadata.name") == "crapi":
                    ports.update(p["port"] for p in rule.get("ports", []))
    return ports


def test_baseline_egress_covers_every_intra_namespace_edge_port():
    """Baseline có `podSelector: {}` + Egress => mọi pod ns crapi default-deny
    egress. Cổng đích của MỌI edge nội cụm (nguồn và đích cùng ns crapi) phải có
    trong rule egress `to_ns: crapi`, nếu không kube-router reject SYN tại chain
    firewall của pod nguồn (bug thật 2026-09-25: thiếu 8080 => waf->bff 503,
    'delayed connect error: 111' dù ingress/mTLS/OPA đều đúng)."""
    graph = yaml.safe_load(GRAPH_FILE.read_text())
    for cluster, allowlist in (("aws", ALLOWLIST_AWS), ("openstack", ALLOWLIST_OS)):
        needed = set()
        for edge in graph["edges"]:
            if edge.get("cross_cluster"):
                continue
            src, dst = graph["workloads"].get(edge["from"]), graph["workloads"].get(edge["to"])
            if not src or not dst:
                continue
            if src["cluster"] != cluster or dst["cluster"] != cluster:
                continue
            if src.get("namespace") != "crapi" or dst.get("namespace") != "crapi":
                continue
            needed.update(edge.get("l4_ports") or [])
        missing = needed - _baseline_intra_ns_egress_ports(allowlist)
        assert not missing, (
            f"{allowlist.name}: egress nội ns crapi thiếu cổng {sorted(missing)} mà "
            f"edge nội cụm ({cluster}) cần — chạy lại python3 scripts/gen-networkpolicy.py."
        )


if __name__ == "__main__":
    test_generated_files_match_source_of_truth()
    print("test_generated_files_match_source_of_truth: PASS")
    test_every_business_edge_present_in_both_layers()
    print("test_every_business_edge_present_in_both_layers: PASS")
    test_every_l7_workload_has_spire_entry_and_real_spiffe()
    print("test_every_l7_workload_has_spire_entry_and_real_spiffe: PASS")
    test_baseline_egress_covers_every_intra_namespace_edge_port()
    print("test_baseline_egress_covers_every_intra_namespace_edge_port: PASS")
