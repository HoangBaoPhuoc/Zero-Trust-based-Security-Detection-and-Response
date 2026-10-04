#!/usr/bin/env python3
"""Thu thập dữ liệu Giai đoạn B theo KHÚC, có sổ cái append-only và tự phát hiện khoảng trống.

Quyết định kiến trúc số 6: 150 giờ dữ liệu nền **cộng dồn nhiều phiên**. Cụm từng hỏng hai lần
trong một vòng, nên đợt thu phải sống sót qua sự cố thay vì giả định nó không xảy ra:

* Mỗi khúc ghi vào sổ cái append-only (cùng họ ``tests/runs.jsonl``) một bản ghi ``start`` và một
  bản ghi ``end`` mang ``{chunk_id, t_start, t_end, cloud, status}``. Không bao giờ ghi đè.
* ``status``:
    - ``valid``   — pipeline log của CẢ HAI cloud liên tục suốt ``[t_start, t_end]``;
    - ``gap``     — có khoảng > ``--max-gap`` giây (mặc định 60) không liên tục ở ít nhất một cloud;
    - ``aborted`` — khúc bị gián đoạn (Ctrl-C/SIGTERM, workload chết, bộ thu chết giữa khúc).
  Chỉ ``valid`` được cộng vào tổng giờ.
* Hai tiêu chí khoảng trống, vì một mình hậu kiểm là KHÔNG đủ:
    1. **Độ tươi (trực tiếp, mỗi ``--probe-interval`` s):** Loki có dòng log mới của từng cloud
       trong ``--fresh-window`` giây gần nhất không. Cần vì Promtail giữ batch và GỬI BÙ khi đường
       truyền nối lại (H11: ngắt WireGuard 61 s → 519/519 dòng vẫn tới, đúng timestamp gốc) — nên
       sau sự cố, dữ liệu trong Loki trông liên tục dù pipeline (và lưu lượng cross-cloud mà dữ
       liệu mô tả) đã đứt. Khoảng không tươi > max-gap → ``gap``.
    2. **Hậu kiểm đầy đủ (sau khúc):** ``count_over_time`` theo bucket ``--bucket`` giây trên
       ``[t_start, t_end]`` cho từng cloud; chuỗi bucket rỗng liên tiếp dài > max-gap → ``gap``
       (bắt trường hợp log mất hẳn, kể cả khi bộ thu bị mù trong lúc chạy).
  Khoảng bộ thu không hỏi được Loki (port-forward chết) được ghi ``probe_blind`` — không tự nó
  làm khúc ``gap``; hậu kiểm quyết định phần đó.
* Tiếp tục được: khởi động lại đọc sổ cái; khúc nào có ``start`` mà không có ``end`` (bộ thu chết
  giữa chừng) được đóng bằng một bản ghi ``end`` ``aborted`` (t_end = lần thăm dò cuối cùng, từ
  file ``<ledger>.progress``). Không mất lịch sử, không ghi đè, không cần người can thiệp.
* ``--report`` in tổng số giờ hợp lệ (con số dùng để biết đã đủ 150 giờ chưa — không cộng tay).

Ví dụ:
    python3 tests/collect_chunked.py --chunk-minutes 120 --target-hours 150 -- bash loadgen.sh
    python3 tests/collect_chunked.py --report
"""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CLOUDS = ("aws", "openstack")


def now():
    return time.time()


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t)) if t else None


# ── sổ cái ──────────────────────────────────────────────────────────────────
class Ledger:
    def __init__(self, path):
        self.path = path
        self.progress = path + ".progress"
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def records(self):
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass  # dòng cụt do chết giữa lúc ghi: bỏ qua, không sửa file
        return out

    def append(self, rec):
        with open(self.path, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def touch_progress(self, chunk_id, t):
        tmp = self.progress + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"chunk_id": chunk_id, "t_last_probe": t}, f)
        os.replace(tmp, self.progress)

    def last_progress(self, chunk_id):
        try:
            with open(self.progress) as f:
                p = json.load(f)
            return p["t_last_probe"] if p.get("chunk_id") == chunk_id else None
        except (OSError, ValueError, KeyError):
            return None

    def chunks(self):
        """Gộp start/end theo chunk_id (end sau cùng thắng — chỉ có một end mỗi khúc)."""
        by = {}
        for r in self.records():
            c = by.setdefault(r["chunk_id"], {"chunk_id": r["chunk_id"]})
            c.update({k: v for k, v in r.items() if k != "event"})
            c.setdefault("_events", []).append(r["event"])
        return list(by.values())

    def recover(self):
        """Đóng mọi khúc mồ côi (có start, không có end) bằng end=aborted."""
        closed = []
        for c in self.chunks():
            if "end" not in c["_events"]:
                t_end = self.last_progress(c["chunk_id"]) or c["t_start"]
                rec = {"event": "end", "chunk_id": c["chunk_id"], "t_start": c["t_start"], "t_end": t_end,
                       "t_start_iso": iso(c["t_start"]), "t_end_iso": iso(t_end), "cloud": c.get("cloud"),
                       "status": "aborted", "hours": 0.0,
                       "reason": "bộ thu dừng giữa khúc (phát hiện khi khởi động lại)", "recovered_at": now()}
                self.append(rec)
                closed.append(c["chunk_id"])
        return closed

    def valid_hours(self):
        return sum(c.get("hours", 0.0) for c in self.chunks() if c.get("status") == "valid")


# ── Loki ────────────────────────────────────────────────────────────────────
class Loki:
    def __init__(self, url, selector):
        self.url = url.rstrip("/")
        self.selector = selector  # vd '{cloud="%s"}'

    def _get(self, path, params, timeout=15):
        q = urllib.parse.urlencode(params)
        with urllib.request.urlopen(f"{self.url}{path}?{q}", timeout=timeout) as r:
            return json.load(r)

    def ready(self):
        try:
            with urllib.request.urlopen(self.url + "/ready", timeout=8) as r:
                return r.status == 200
        except Exception:
            return False

    def fresh_counts(self, window_s):
        """{cloud: số dòng có timestamp trong window_s giây gần nhất} hoặc None nếu không hỏi được."""
        sel = self.selector.replace('"%s"', '~"%s"' % "|".join(CLOUDS))
        query = f"sum by (cloud) (count_over_time({sel}[{int(window_s)}s]))"
        try:
            d = self._get("/loki/api/v1/query", {"query": query, "time": f"{int(now())}000000000"})
        except Exception:
            return None
        out = {c: 0 for c in CLOUDS}
        for r in d["data"]["result"]:
            out[r["metric"].get("cloud", "?")] = int(float(r["value"][1]))
        return out

    def bucket_gaps(self, cloud, t0, t1, bucket_s, max_gap_s):
        """Các khoảng rỗng liên tiếp > max_gap_s (giây) của một cloud trong [t0, t1]."""
        sel = self.selector % cloud
        query = f"sum(count_over_time({sel}[{bucket_s}s]))"
        present = set()
        span = 10000 * bucket_s  # dưới giới hạn 11000 điểm/truy vấn của Loki
        s = t0 + bucket_s
        while s <= t1:
            e = min(t1, s + span)
            d = self._get("/loki/api/v1/query_range",
                          {"query": query, "start": f"{int(s)}000000000", "end": f"{int(e)}000000000",
                           "step": f"{bucket_s}s"}, timeout=60)
            for r in d["data"]["result"]:
                for ts, v in r["values"]:
                    if float(v) > 0:
                        present.add(int(float(ts)))
            s = e + bucket_s
        # mỗi điểm ts (đã có) phủ (ts - bucket, ts]; tìm khoảng không được phủ
        covered_until = t0
        gaps = []
        for ts in sorted(present) + [t1 + max_gap_s + bucket_s + 1]:
            start_cov = ts - bucket_s
            if start_cov - covered_until > max_gap_s:
                gaps.append([covered_until, min(start_cov, t1)])
            covered_until = max(covered_until, ts)
        return [g for g in gaps if g[1] - g[0] > max_gap_s], len(present)


# ── bộ thu ──────────────────────────────────────────────────────────────────
class Stop(Exception):
    pass


def heal_port_forward():
    """Dựng lại tunnel API + port-forward (tests/lib/pf_health.sh) — im lặng, best-effort."""
    try:
        subprocess.run(["bash", "-c", f"source '{HERE}/lib/pf_health.sh' && pf_heal_all"],
                       cwd=REPO, timeout=180, capture_output=True)
    except Exception:
        pass


def wait_preconditions(loki, args):
    """Không mở khúc vào khoảng không: Loki trả lời + cả hai cloud đang tươi."""
    t_begin = now()
    while True:
        if loki.ready():
            fc = loki.fresh_counts(args.fresh_window)
            if fc and all(fc[c] > 0 for c in CLOUDS):
                return fc
            why = f"chưa tươi: {fc}"
        else:
            why = "Loki không trả lời"
            heal_port_forward()
        if now() - t_begin > args.precondition_timeout:
            raise SystemExit(f"[collect] điều kiện đo không đạt sau {args.precondition_timeout}s ({why}) — không mở khúc.")
        print(f"[collect] chờ điều kiện đo: {why}", flush=True)
        time.sleep(15)


def run_chunk(ledger, loki, args, seq):
    chunk_id = f"c{seq:04d}-{time.strftime('%Y%m%dT%H%M%S')}"
    wait_preconditions(loki, args)
    t_start = now()
    ledger.append({"event": "start", "chunk_id": chunk_id, "t_start": t_start, "t_start_iso": iso(t_start),
                   "cloud": "+".join(CLOUDS), "planned_s": args.chunk_minutes * 60,
                   "workload": args.workload or None, "host": socket.gethostname(), "pid": os.getpid()})
    ledger.touch_progress(chunk_id, t_start)
    print(f"[collect] BẮT ĐẦU {chunk_id} ({args.chunk_minutes} phút)", flush=True)

    proc = subprocess.Popen(args.workload, cwd=REPO, start_new_session=True) if args.workload else None
    last_fresh = {c: t_start for c in CLOUDS}
    stale = {c: None for c in CLOUDS}          # thời điểm bắt đầu khoảng không tươi đang mở
    fresh_violations, blind, blind_since = [], [], None
    reason, status = None, None
    deadline = t_start + args.chunk_minutes * 60
    try:
        while now() < deadline:
            time.sleep(min(args.probe_interval, max(0.0, deadline - now())))
            t = now()
            ledger.touch_progress(chunk_id, t)
            if proc and proc.poll() is not None and proc.returncode != 0:
                status, reason = "aborted", f"workload thoát rc={proc.returncode}"
                break
            fc = loki.fresh_counts(args.fresh_window)
            if fc is None:
                blind_since = blind_since or t
                if t - blind_since > 60:
                    heal_port_forward()
                continue
            if blind_since:
                blind.append([blind_since, t]); blind_since = None
            for c in CLOUDS:
                if fc[c] > 0:
                    if stale[c] and t - stale[c] > args.max_gap:
                        fresh_violations.append({"cloud": c, "from": stale[c], "to": t,
                                                 "seconds": round(t - stale[c], 1)})
                    stale[c] = None
                    last_fresh[c] = t
                else:
                    # khoảng không tươi bắt đầu từ lúc dòng mới nhất có thể đã có = t - fresh_window
                    stale[c] = stale[c] or max(t_start, t - args.fresh_window)
                    if t - stale[c] > args.max_gap:
                        print(f"[collect] {chunk_id}: {c} KHÔNG tươi {int(t - stale[c])}s", flush=True)
    except Stop as e:
        status, reason = "aborted", str(e)
    finally:
        if proc and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)

    t_end = now()
    if blind_since:
        blind.append([blind_since, t_end])
    for c in CLOUDS:  # khoảng không tươi còn mở lúc kết thúc khúc
        if stale[c] and t_end - stale[c] > args.max_gap:
            fresh_violations.append({"cloud": c, "from": stale[c], "to": t_end, "seconds": round(t_end - stale[c], 1)})

    posthoc = {}
    if status != "aborted":
        time.sleep(args.settle)  # để batch đang bay (và batch gửi bù) tới Loki trước khi hậu kiểm
        try:
            for c in CLOUDS:
                gaps, nb = loki.bucket_gaps(c, t_start, t_end, args.bucket, args.max_gap)
                posthoc[c] = {"gaps": gaps, "nonempty_buckets": nb,
                              "expected_buckets": int((t_end - t_start) // args.bucket)}
        except Exception as e:  # không hậu kiểm được → không tính (không đếm vào khoảng không)
            status, reason = "gap", f"hậu kiểm Loki thất bại: {e}"
        if status is None:
            if fresh_violations or any(posthoc[c]["gaps"] for c in CLOUDS):
                status = "gap"
                reason = "; ".join(
                    [f"{v['cloud']} không tươi {v['seconds']}s" for v in fresh_violations] +
                    [f"{c} thiếu log {int(g[1] - g[0])}s" for c in CLOUDS for g in posthoc[c]["gaps"]])
            else:
                status = "valid"
    hours = round((t_end - t_start) / 3600, 4) if status == "valid" else 0.0
    rec = {"event": "end", "chunk_id": chunk_id, "t_start": t_start, "t_end": t_end,
           "t_start_iso": iso(t_start), "t_end_iso": iso(t_end), "cloud": "+".join(CLOUDS),
           "status": status, "hours": hours, "reason": reason,
           "fresh_violations": fresh_violations, "probe_blind": blind, "posthoc": posthoc,
           "params": {"max_gap": args.max_gap, "fresh_window": args.fresh_window, "bucket": args.bucket}}
    ledger.append(rec)
    print(f"[collect] KẾT THÚC {chunk_id}: {status} ({hours} h){' — ' + reason if reason else ''}", flush=True)
    return status


def report(ledger):
    cs = sorted(ledger.chunks(), key=lambda c: c.get("t_start", 0))
    print(f"{'chunk_id':28} {'t_start':25} {'t_end':25} {'status':8} {'giờ':>7}  lý do")
    for c in cs:
        print(f"{c['chunk_id']:28} {str(c.get('t_start_iso')):25} {str(c.get('t_end_iso')):25} "
              f"{str(c.get('status', 'đang chạy')):8} {c.get('hours', 0):7.3f}  {c.get('reason') or ''}")
    total = ledger.valid_hours()
    print(f"\nTỔNG GIỜ HỢP LỆ: {total:.3f} h  ({sum(1 for c in cs if c.get('status') == 'valid')} khúc valid, "
          f"{sum(1 for c in cs if c.get('status') == 'gap')} gap, {sum(1 for c in cs if c.get('status') == 'aborted')} aborted)")
    return total


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ledger", default=os.path.join(HERE, "chunks.jsonl"))
    ap.add_argument("--loki-url", default=os.environ.get("LOKI_URL", "http://127.0.0.1:13100"))
    ap.add_argument("--selector", default='{cloud="%s"}', help="LogQL selector, %%s = tên cloud")
    ap.add_argument("--chunk-minutes", type=float, default=120)
    ap.add_argument("--chunks", type=int, default=0, help="số khúc chạy lần này (0 = tới khi đủ --target-hours)")
    ap.add_argument("--target-hours", type=float, default=150)
    ap.add_argument("--max-gap", type=float, default=60)
    ap.add_argument("--fresh-window", type=float, default=30)
    ap.add_argument("--probe-interval", type=float, default=10)
    ap.add_argument("--bucket", type=int, default=10)
    ap.add_argument("--settle", type=float, default=45)
    ap.add_argument("--pause", type=float, default=10, help="nghỉ giữa hai khúc (s)")
    ap.add_argument("--precondition-timeout", type=float, default=1800)
    ap.add_argument("--report", action="store_true")
    ap.add_argument("workload", nargs=argparse.REMAINDER, help="-- <lệnh sinh tải chạy suốt mỗi khúc>")
    args = ap.parse_args()
    if args.workload and args.workload[0] == "--":
        args.workload = args.workload[1:]

    ledger = Ledger(args.ledger)
    closed = ledger.recover()
    if closed:
        print(f"[collect] khôi phục: đóng {len(closed)} khúc mồ côi là aborted: {closed}", flush=True)
    if args.report:
        report(ledger)
        return 0

    def on_signal(signum, _):
        raise Stop(f"nhận tín hiệu {signal.Signals(signum).name}")
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGHUP, on_signal)

    loki = Loki(args.loki_url, args.selector)
    done = 0
    try:
        while True:
            if args.chunks and done >= args.chunks:
                break
            if not args.chunks and ledger.valid_hours() >= args.target_hours:
                print(f"[collect] đã đủ {args.target_hours} giờ hợp lệ.")
                break
            seq = len(ledger.chunks()) + 1
            run_chunk(ledger, loki, args, seq)
            done += 1
            time.sleep(args.pause)
    except Stop as e:  # tín hiệu đến ngoài khúc (lúc nghỉ / chờ điều kiện)
        print(f"[collect] dừng: {e}")
    report(ledger)
    return 0


if __name__ == "__main__":
    sys.exit(main())
