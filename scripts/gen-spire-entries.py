#!/usr/bin/env python3
"""Sinh scripts/spire-entries.generated.sh từ policy/service-graph-crapi.yaml
(Phần 2, remediation 2026-09).

TRƯỚC: danh sách workload SPIRE hardcode trong scripts/ensure-spire-entries.sh
(register_spire_entry gọi tay từng dòng) + số lượng kỳ vọng (gate) hardcode
riêng — 2 nơi này từng lệch nhau (comment nói "AWS 5", log nói "expect 6",
check thật `-lt 5`). Sau Phần 2: CẢ danh sách entry lẫn số lượng kỳ vọng đều
sinh từ CÙNG MỘT chỗ (service-graph-crapi.yaml `workloads:`), không còn cách
nào để 2 con số lệch nhau.

Một workload cần SPIRE entry khi trong `workloads:` có `spiffe` vắng mặt hoặc
`spiffe: true` (mặc định — mọi workload TRỪ khi khai `spiffe: false`, dùng cho
các đích L4 thuần như redis/mongodb/postgres/keycloak-chưa-vào-mesh/opa-inbound
không có sidecar riêng để SPIRE cấp SVID theo nghĩa "workload này gọi ra ngoài
qua sidecar của chính nó").

Usage: python3 scripts/gen-spire-entries.py
Nghiệm thu: `git diff scripts/spire-entries.generated.sh` rỗng nếu
service-graph-crapi.yaml không đổi.
"""
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAPH_FILE = REPO_ROOT / "policy" / "service-graph-crapi.yaml"
OUT_FILE = REPO_ROOT / "scripts" / "spire-entries.generated.sh"


def spiffe_id(trust_domain: str, workload: str) -> str:
    return f"spiffe://{trust_domain}/{workload}"


def main() -> None:
    graph = yaml.safe_load(GRAPH_FILE.read_text())
    trust_domain = graph["trust_domain"]

    by_cluster: dict[str, list[str]] = {c: [] for c in graph["clusters"]}
    for name, w in graph["workloads"].items():
        if w.get("spiffe") is False:
            continue
        if "service_account" not in w:
            continue  # entry app_label-only (vd redis) không có ServiceAccount rõ ràng để register
        # '|' làm delimiter (không phải ':') vì spiffe:// tự nó đã chứa ':'.
        entry = f"{spiffe_id(trust_domain, name)}|{w['namespace']}|{w['service_account']}"
        by_cluster[w["cluster"]].append(entry)

    lines = [
        "# GENERATED FILE — KHÔNG SỬA TAY. Nguồn: policy/service-graph-crapi.yaml",
        "# Sinh lại: python3 scripts/gen-spire-entries.py",
        "#",
        "# scripts/ensure-spire-entries.sh source file này thay vì hardcode danh sách",
        "# workload + số lượng kỳ vọng riêng — không còn 2 nơi có thể lệch nhau.",
        "",
    ]
    for cluster, entries in by_cluster.items():
        var_prefix = cluster.upper()
        lines.append(f"{var_prefix}_SPIRE_WORKLOADS=(")
        for e in sorted(entries):
            lines.append(f'  "{e}"')
        lines.append(")")
        lines.append(f"{var_prefix}_EXPECTED_COUNT={len(entries)}")
        lines.append("")

    OUT_FILE.write_text("\n".join(lines).rstrip() + "\n")
    print(f"Sinh xong: {OUT_FILE.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
