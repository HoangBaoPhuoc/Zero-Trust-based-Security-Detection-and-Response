#!/usr/bin/env python3
"""Sinh opa/policies/service_acl.rego từ policy/service-graph.yaml (T-3.2).

Đây là NGUỒN SỰ THẬT DUY NHẤT cho ma trận phân quyền service-to-service (L7).
zta_policy.rego (cluster AWS) và cross_cloud.rego (cluster OpenStack) đều
`import data.zta.generated` và dùng `generated.service_acl` — không tự định
nghĩa service_acl riêng nữa (tránh lệch giữa 2 file như đã xảy ra trước T-3.2).

Chỉ sinh cho edge có `rules` (bỏ qua edge `l4_only: true` — Redis/Postgres/OPA
không đi qua OPA service_acl, đó là kết nối hạ tầng thuần L4).

Usage: python3 scripts/gen-rego-acl.py
Nghiệm thu: chạy xong, `git diff opa/policies/service_acl.rego` phải rỗng
(nếu service-graph.yaml không đổi) — nếu có diff, nghĩa là ai đó sửa tay
service_acl.rego hoặc service-graph.yaml, cần rà lại.
"""
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

# --crapi: sinh cho ứng dụng mục tiêu crAPI (package + file riêng, KHÔNG đụng
# service_acl.rego của finance app cho tới Phase 5 của KE-HOACH-CRAPI.md).
if "--crapi" in sys.argv:
    GRAPH_FILE = REPO_ROOT / "policy" / "service-graph-crapi.yaml"
    OUT_FILE = REPO_ROOT / "opa" / "crapi-policies" / "service_acl.rego"
    PACKAGE = "zta.crapi.generated"
    SRC_LABEL = "policy/service-graph-crapi.yaml (KE-HOACH-CRAPI.md)"
else:
    GRAPH_FILE = REPO_ROOT / "policy" / "service-graph.yaml"
    OUT_FILE = REPO_ROOT / "opa" / "policies" / "service_acl.rego"
    PACKAGE = "zta.generated"
    SRC_LABEL = "policy/service-graph.yaml (T-1.1, KET-QUA-KIEM-TRA.md)"


def spiffe_id(trust_domain: str, workload: str) -> str:
    return f"spiffe://{trust_domain}/{workload}"


def render_rules(rules: list[dict]) -> str:
    lines = []
    for r in rules:
        method = r["method"]
        paths = ", ".join(f'"{p}"' for p in r["paths"])
        lines.append(f'      "{method}": [{paths}],')
    return "\n".join(lines)


def main() -> None:
    graph = yaml.safe_load(GRAPH_FILE.read_text())
    trust_domain = graph["trust_domain"]

    by_source: dict[str, list[dict]] = {}
    for edge in graph["edges"]:
        if edge.get("l4_only"):
            continue
        by_source.setdefault(edge["from"], []).append(edge)

    blocks = []
    for source in sorted(by_source):
        dest_blocks = []
        for edge in by_source[source]:
            dest_id = spiffe_id(trust_domain, edge["to"])
            dest_blocks.append(
                f'    "{dest_id}": {{\n{render_rules(edge["rules"])}\n    }},'
            )
        source_id = spiffe_id(trust_domain, source)
        blocks.append(f'  "{source_id}": {{\n' + "\n".join(dest_blocks) + "\n  },")

    body = "\n".join(blocks)
    if "--crapi" in sys.argv:
        header = f"""# GENERATED FILE — KHÔNG SỬA TAY. Nguồn: policy/service-graph-crapi.yaml
# Sinh lại: python3 scripts/gen-rego-acl.py --crapi
#
# Ma trận phân quyền service-to-service (L7) cho ứng dụng mục tiêu crAPI —
# import bởi opa/crapi-policies/{{zta_crapi,crosscloud_crapi}}.rego qua
# `data.zta.crapi.generated`. Xem KE-HOACH-CRAPI.md Phase 3 + KET-QUA-CRAPI.md GATE 0."""
    else:
        header = """# GENERATED FILE — KHÔNG SỬA TAY. Nguồn: policy/service-graph.yaml
# Sinh lại: python3 scripts/gen-rego-acl.py
#
# Ma trận phân quyền service-to-service (L7) — nguồn sự thật duy nhất, dùng
# chung bởi zta_policy.rego (cluster AWS) và cross_cloud.rego (cluster
# OpenStack) qua `import data.zta.generated`. Xem policy/service-graph.yaml
# để biết dữ liệu gốc + traffic thật đã đo (T-1.1, KET-QUA-KIEM-TRA.md)."""
    content = f"""package {PACKAGE}

{header}

service_acl := {{
{body}
}}
"""
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(content)
    print(f"Sinh xong: {OUT_FILE.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
