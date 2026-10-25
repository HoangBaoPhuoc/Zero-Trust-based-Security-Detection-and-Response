#!/usr/bin/env python3
"""Lọc tests/runs.jsonl → chỉ giữ các lượt DÙNG ĐƯỢC cho Giai đoạn C.

Vấn đề (review đợt 150h §3.6): runs.jsonl lẫn rác — ~20 bản chạy thử, các lượt
thuộc khúc hỏng (c0010–c0017), và lượt attack `aborted`. Nếu nạp cả vào khi gán
nhãn/đánh giá, nhãn bị nhiễu. Script này GIỮ một lượt khi và chỉ khi:

  1. class ∈ {attack, benign_noise}  (bỏ bản ghi chunk của collect_chunked.py);
  2. KHÔNG phải attack `status=aborted` / `low_quality` (lượt không thực sự chạy);
  3. khoảng [t_start, t_end] của lượt NẰM TRONG một khúc `valid` của sổ cái thu
     (bỏ bản chạy thử và lượt thuộc khúc gap/aborted/low_quality tự động — chúng
     rơi ngoài mọi cửa sổ valid).

Không ghi đè file gốc: xuất ra --out (mặc định <runs>.filtered.jsonl) + in báo
cáo bỏ/giữ theo lý do. Sổ cái có thể truyền nhiều lần (--ledger a --ledger b).

  python3 tests/filter_runs.py --runs tests/runs.jsonl \\
      --ledger results/b4/chunks/<tag>.ledger.jsonl --out tests/runs.filtered.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone


def iso_to_epoch(s: str) -> float:
    s = s.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()


def valid_windows(ledger_paths: list[str]) -> list[tuple[float, float, str]]:
    """[(t_start, t_end, chunk_id)] của các khúc status=valid trong các sổ cái.

    Gộp mọi bản ghi theo chunk_id, bản ghi SAU ghi đè bản trước (giống
    phaseb_collect_loop.sh và collect_chunked.py --report): khúc collect_chunked
    đánh `valid` nhưng phaseb_chunk_postprocess.sh hạ xuống `aborted` (export
    rỗng) phải bị loại, không được giữ theo bản `end` đầu tiên."""
    by = {}
    for p in ledger_paths:
        for line in open(p):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "chunk_id" not in r or "event" not in r:
                continue
            by.setdefault(r["chunk_id"], {}).update({k: v for k, v in r.items() if k != "event"})
    wins = [(float(c["t_start"]), float(c["t_end"]), cid) for cid, c in by.items()
            if c.get("status") == "valid"]
    return sorted(wins)


def in_valid(t0: float, t1: float, wins: list[tuple[float, float, str]]) -> str | None:
    """chunk_id nếu [t0,t1] nằm GỌN trong một khúc valid; None nếu không."""
    for s, e, cid in wins:
        if t0 >= s and t1 <= e:
            return cid
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", default="tests/runs.jsonl")
    ap.add_argument("--ledger", action="append", required=True, help="sổ cái thu (lặp được)")
    ap.add_argument("--out", default=None, help="mặc định <runs>.filtered.jsonl")
    ap.add_argument("--require-valid-chunk", dest="require_valid", action="store_true", default=True,
                    help="(mặc định) bắt buộc lượt nằm trong khúc valid")
    ap.add_argument("--no-require-valid-chunk", dest="require_valid", action="store_false",
                    help="bỏ điều kiện 3 (chỉ lọc class + aborted) — dùng khi chưa có sổ cái đáng tin")
    args = ap.parse_args()

    out = args.out or (args.runs.rsplit(".", 1)[0] + ".filtered.jsonl")
    wins = valid_windows(args.ledger)
    if args.require_valid and not wins:
        sys.exit(f"!! không tìm thấy khúc valid nào trong {args.ledger} — "
                 f"kiểm lại sổ cái, hoặc chạy với --no-require-valid-chunk")

    kept, drop = [], {"not_class": 0, "aborted": 0, "outside_valid": 0, "bad_json": 0, "no_time": 0}
    per_chunk = {}
    for line in open(args.runs):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            drop["bad_json"] += 1
            continue
        if d.get("class") not in ("attack", "benign_noise") or "chunk_id" in d:
            drop["not_class"] += 1
            continue
        if d.get("class") == "attack" and d.get("status") in ("aborted", "low_quality"):
            drop["aborted"] += 1
            continue
        if "t_start" not in d or "t_end" not in d:
            drop["no_time"] += 1
            continue
        if args.require_valid:
            cid = in_valid(iso_to_epoch(d["t_start"]), iso_to_epoch(d["t_end"]), wins)
            if cid is None:
                drop["outside_valid"] += 1
                continue
            per_chunk[cid] = per_chunk.get(cid, 0) + 1
        kept.append(line)

    with open(out, "w") as fh:
        fh.write("\n".join(kept) + ("\n" if kept else ""))

    print(f"[filter_runs] khúc valid: {len(wins)} | giữ {len(kept)} lượt → {out}")
    print(f"[filter_runs] bỏ: {drop}")
    if per_chunk:
        print("[filter_runs] lượt giữ theo khúc: " +
              ", ".join(f"{k}={v}" for k, v in sorted(per_chunk.items())))
    # cảnh báo nếu lọc ra rỗng (sai sổ cái / sai múi giờ) để không âm thầm mất hết
    if args.require_valid and not kept:
        print("[filter_runs] ⚠ GIỮ 0 lượt — kiểm sổ cái có đúng đợt thu không, "
              "timestamp runs.jsonl và ledger có cùng múi giờ (UTC) không", file=sys.stderr)


if __name__ == "__main__":
    main()
