#!/usr/bin/env python3
"""Sinh docs/GENERATED-SERVICE-GRAPH.md từ policy/service-graph-crapi.yaml
(Phần 2.3, remediation 2026-09).

Trước bản sửa này, HE-THONG-CHI-TIET.md có 3 bảng viết tay (SPIFFE §4.1, ma
trận edge L7 §4.3, danh sách edge L4 §4.4) mô tả LẠI cùng dữ liệu đã có trong
service-graph-crapi.yaml — và đã trôi (§4.1 ghi AWS(4) trong khi gate thực tế
là 6, thiếu waf/prometheus; §4.3 thiếu waf→bff; §4.4 thiếu Keycloak). Sinh
thẳng từ graph thì không thể trôi nữa — sửa graph, chạy lại generator này.

Usage: python3 scripts/gen-docs-tables.py
Nghiệm thu: `git diff docs/GENERATED-SERVICE-GRAPH.md` rỗng nếu
service-graph-crapi.yaml không đổi.
"""
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAPH_FILE = REPO_ROOT / "policy" / "service-graph-crapi.yaml"
OUT_FILE = REPO_ROOT / "docs" / "GENERATED-SERVICE-GRAPH.md"


def spiffe_id(trust_domain: str, workload: str) -> str:
    return f"spiffe://{trust_domain}/{workload}"


def main() -> None:
    graph = yaml.safe_load(GRAPH_FILE.read_text())
    trust_domain = graph["trust_domain"]
    workloads = graph["workloads"]
    edges = graph["edges"]

    lines = [
        "# Service graph — bảng sinh tự động",
        "",
        "> **GENERATED FILE — KHÔNG SỬA TAY.** Nguồn: `policy/service-graph-crapi.yaml`.",
        "> Sinh lại: `python3 scripts/gen-docs-tables.py`. Tham chiếu từ `HE-THONG-CHI-TIET.md`",
        "> thay vì lặp lại nội dung — sửa graph rồi chạy lại generator, đừng sửa file này.",
        "",
        "## 1. Danh sách SPIFFE entry",
        "",
    ]

    by_cluster: dict[str, list[str]] = {}
    for name, w in sorted(workloads.items()):
        if w.get("spiffe") is False:
            continue
        by_cluster.setdefault(w["cluster"], []).append(name)

    for cluster in sorted(by_cluster):
        names = by_cluster[cluster]
        lines.append(f"**{cluster} ({len(names)}):**")
        lines.append("")
        for name in sorted(names):
            w = workloads[name]
            extra = " _(spire_only — không tham gia service_acl)_" if w.get("spire_only") else ""
            lines.append(f"- `{spiffe_id(trust_domain, name)}`{extra}")
        lines.append("")

    lines.append("## 2. Ma trận edge L7 (qua OPA service_acl)")
    lines.append("")
    lines.append("| Nguồn (SPIFFE) | Đích | Method + path prefix |")
    lines.append("|---|---|---|")
    for edge in edges:
        if edge.get("l4_only"):
            continue
        src = spiffe_id(trust_domain, edge["from"])
        dst = spiffe_id(trust_domain, edge["to"])
        rule_strs = []
        for r in edge["rules"]:
            paths = ", ".join(r["paths"])
            rule_strs.append(f"{r['method']} `{paths}`")
        cross = " _(cross-cloud)_" if edge.get("cross_cluster") else ""
        lines.append(f"| `{src}` | `{dst}`{cross} | {'; '.join(rule_strs)} |")
    lines.append("")

    lines.append("## 3. Edge L4 thuần (không qua OPA service_acl)")
    lines.append("")
    lines.append("| Nguồn | Đích | Port(s) | Cross-cloud |")
    lines.append("|---|---|---|---|")
    for edge in edges:
        if not edge.get("l4_only"):
            continue
        ports = ", ".join(str(p) for p in edge.get("l4_ports", []))
        cross = "có" if edge.get("cross_cluster") else ""
        lines.append(f"| `{edge['from']}` | `{edge['to']}` | {ports} | {cross} |")
    lines.append("")

    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text("\n".join(lines) + "\n")
    print(f"Sinh xong: {OUT_FILE.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
