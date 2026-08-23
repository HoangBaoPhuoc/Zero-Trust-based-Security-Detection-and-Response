#!/usr/bin/env python3
"""ZTLab — Dev/Ops Friction Survey collector.

Hỏi trực tiếp (CLI) bộ câu hỏi trong docs/friction-survey.md, ghi JSON vào
results/friction_survey_<timestamp>.json. Chạy `--summary` để tổng hợp thống
kê từ các file đã thu thập được (rỗng nếu chưa ai trả lời — không tự bịa).

Đây là công cụ thu thập, KHÔNG tự sinh dữ liệu mẫu — mỗi lần chạy không có
--summary sẽ hỏi người dùng thật đang ngồi trước máy trả lời từng câu.

Usage:
  python3 tests/collect_friction_survey.py            # hỏi và ghi 1 phản hồi mới
  python3 tests/collect_friction_survey.py --summary  # tổng hợp các phản hồi đã có
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"

QUESTIONS = [
    ("debug_403", "Debug khi bị OPA/Envoy chặn nhầm (403 không rõ lý do)"),
    ("add_new_service", "Thêm 1 service mới vào hệ thống (SVID + Envoy + OPA + NetworkPolicy)"),
    ("understand_403_first_time", "Hiểu lỗi 403 lần đầu gặp (chưa quen hệ thống)"),
    ("redeploy_destroy_reliability", "Redeploy/destroy toàn bộ hạ tầng — độ tin cậy"),
    ("edit_rego_policy", "Thêm/sửa 1 policy Rego mới, verify không phá traffic hiện có"),
    ("overall_tradeoff", "Tổng thể — đánh đổi độ phức tạp vận hành để lấy khả năng phát hiện/audit có đáng không"),
]


def collect_one() -> dict:
    print("ZTLab Dev/Ops Friction Survey — thang điểm 1-5 (1=rất khó/tốn công, 5=rất dễ)")
    print("Xem chi tiết từng câu hỏi tại docs/friction-survey.md\n")

    respondent = input("Tên/vai trò người trả lời (vd. 'dev', 'ops', để trống nếu ẩn danh): ").strip() or "anonymous"

    answers: dict[str, int] = {}
    notes: dict[str, str] = {}
    for key, question in QUESTIONS:
        while True:
            raw = input(f"{question} [1-5]: ").strip()
            if raw.isdigit() and 1 <= int(raw) <= 5:
                answers[key] = int(raw)
                break
            print("  → nhập số từ 1 đến 5")
        note = input("  Ghi chú (tuỳ chọn, Enter để bỏ qua): ").strip()
        if note:
            notes[key] = note

    record = {
        "respondent": respondent,
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "answers": answers,
        "notes": notes,
    }
    return record


def save(record: dict) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    path = RESULTS_DIR / f"friction_survey_{ts}.json"
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False))
    return path


def summarize() -> int:
    files = sorted(RESULTS_DIR.glob("friction_survey_*.json"))
    if not files:
        print("Chưa có phản hồi nào (không tự sinh dữ liệu mẫu) — chạy `python3 tests/collect_friction_survey.py` để thu thập trước.")
        return 0

    print(f"Tổng hợp {len(files)} phản hồi:\n")
    per_question: dict[str, list[int]] = {key: [] for key, _ in QUESTIONS}
    for f in files:
        data = json.loads(f.read_text())
        for key, val in data.get("answers", {}).items():
            per_question.setdefault(key, []).append(val)

    for key, question in QUESTIONS:
        vals = per_question.get(key, [])
        if not vals:
            print(f"  {question}: chưa có dữ liệu")
            continue
        print(f"  {question}: mean={statistics.mean(vals):.1f} (n={len(vals)}, values={vals})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="ZTLab dev/ops friction survey")
    parser.add_argument("--summary", action="store_true", help="Tổng hợp các phản hồi đã thu thập, không hỏi mới")
    args = parser.parse_args()

    if args.summary:
        return summarize()

    record = collect_one()
    path = save(record)
    print(f"\nĐã ghi phản hồi vào {path}")
    print("Chạy lại với --summary để xem tổng hợp khi đã có nhiều phản hồi.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
