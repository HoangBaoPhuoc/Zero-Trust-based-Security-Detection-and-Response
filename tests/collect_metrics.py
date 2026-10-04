#!/usr/bin/env python3
"""ZTLab MTTD — Mean Time To Detect (Phần 1.5, remediation 2026-09-18).

Bản CŨ đo MTTR bằng cách TỰ APPROVE một playbook qua API của `ai-analyzer`/
`soar-engine` — cả 2 service đó đã bị A4 (KEHOACH-THAYDOI-HETHONG.md) XOÁ HẲN
và gộp thành `incident-analyzer` với API khác hẳn, KHÔNG còn khái niệm
"approve playbook" (A4: hệ thống không có hành động phản ứng tự động nào —
MTTR như định nghĩa cũ không còn ý nghĩa). Xoá hẳn công cụ đo MTTR/FPR/FNR/OVH
cũ (FPR/FNR chưa từng đo được — cần dataset gán nhãn của Giai đoạn B, ngoài
phạm vi; OVH nay đo đúng ở tests/perf_overhead.py, Phần 1.4) — không giữ lại
code chết gọi API không còn tồn tại.

MTTD vẫn rất có nghĩa và đo được: từ lúc tấn công XẢY RA tới lúc evidence
bundle được incident-analyzer GỬI ĐI. Công cụ này chạy 1 kịch bản tấn công
THẬT (mặc định: crapi_lateral_movement.sh — chọn vì Grafana rule "Lateral
Movement" đã verify sống bắn thật, xem BAOCAO-SUA-GOC-2026-09-13.md) rồi đo
đúng CHUỖI THẬT của hệ thống:

    T0 tấn công xảy ra
      -> T1 OPA ghi decision log deny (Loki job=opa-decisions, timestamp
         THẬT của chính dòng log, không phải lúc script query)
      -> T2 incident-analyzer tạo evidence bundle (đã bao hàm độ trễ Grafana
         eval theo chu kỳ + webhook + build bundle — không tách riêng được
         thời điểm Grafana chuyển Firing qua 1 lệnh gọi đơn giản, xem
         methodology_note)
      -> T3 email THẬT tới hộp thư SOC (MailHog, Created timestamp của chính
         message — xác nhận đầu-cuối, không phải suy đoán từ rec.email_sent)

MTTD báo cáo CHÍNH (đúng định nghĩa "attack -> evidence bundle được gửi đi"):
    MTTD_to_evidence_s = T2 - T0
Số bổ sung (đầu-cuối thật, tới khi mail nằm trong hộp thư):
    MTTD_to_email_delivered_s = T3 - T0
Và breakdown từng chặng (T1-T0, T2-T1, T3-T2) để thấy chặng nào chiếm phần lớn.

Usage:
  python3 tests/collect_metrics.py [--scenario crapi_lateral_movement.sh]
                                    [--timeout 180] [--output results/mttd.json]
"""
from __future__ import annotations

import argparse
import statistics
import json
import subprocess
import time
import urllib.parse
import urllib.request
from email.header import decode_header
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOKI_URL = "http://localhost:13100"
INCIDENT_ANALYZER_URL = "http://localhost:8091"
MAILHOG_SOC_URL = "http://localhost:8026"
GRAFANA_URL = "http://localhost:3000"


def _loki_first_ts(query: str, start_s: int, end_s: int) -> float | None:
    """Timestamp (epoch giây, float) của dòng log SỚM NHẤT khớp query trong
    [start_s, end_s] — dùng timestamp THẬT của log (Loki trả nanosecond epoch
    làm key của mỗi value), không phải lúc script gọi Loki."""
    qs = urllib.parse.urlencode({
        "query": query, "start": f"{start_s}000000000", "end": f"{end_s}000000000",
        "limit": 1000, "direction": "forward",
    })
    try:
        with urllib.request.urlopen(f"{LOKI_URL}/loki/api/v1/query_range?{qs}", timeout=10) as r:
            data = json.load(r)
    except Exception:
        return None
    best = None
    for stream in data.get("data", {}).get("result", []):
        for ts_ns, _line in stream.get("values", []):
            t = int(ts_ns) / 1e9
            if best is None or t < best:
                best = t
    return best


def _poll_evidence_bundle(attack_type_hint: str, alert_name_hint: str, after_s: float, timeout: float) -> dict | None:
    """Poll GET /evidence tới khi thấy bản ghi mới có ts > after_s khớp
    attack_type/alert_name — trả về cả record lẫn thời điểm client-side lần
    đầu thấy nó (không dùng để tính MTTD, chỉ để log tiến độ)."""
    deadline = time.time() + timeout
    seen_ids: set[str] = set()
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{INCIDENT_ANALYZER_URL}/evidence", timeout=8) as r:
                items = json.load(r)
        except Exception:
            items = []
        for rec in items:
            if rec["evidence_id"] in seen_ids:
                continue
            seen_ids.add(rec["evidence_id"])
            ts_epoch = _iso_to_epoch(rec["ts"])
            if ts_epoch is None or ts_epoch < after_s - 5:
                continue  # bundle cũ từ trước lần chạy này
            if attack_type_hint and attack_type_hint not in rec.get("attack_type", ""):
                continue
            return rec
        time.sleep(3)
    return None


def _iso_to_epoch(iso: str) -> float | None:
    try:
        import datetime
        return datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _find_mailhog_message(alert_name_hint: str, after_s: float, timeout: float) -> dict | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{MAILHOG_SOC_URL}/api/v2/messages?limit=20", timeout=8) as r:
                data = json.load(r)
        except Exception:
            data = {"items": []}
        for m in data.get("items", []):
            created = _iso_to_epoch(m.get("Created", ""))
            if created is None or created < after_s - 5:
                continue
            raw_subj = m["Content"]["Headers"].get("Subject", [""])[0]
            try:
                subj = str(decode_header(raw_subj)[0][0])
                if isinstance(decode_header(raw_subj)[0][0], bytes):
                    subj = decode_header(raw_subj)[0][0].decode(decode_header(raw_subj)[0][1] or "utf-8")
            except Exception:
                subj = raw_subj
            if alert_name_hint.lower() in subj.lower():
                return {"created_epoch": created, "subject": subj}
        time.sleep(3)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="ZTLab MTTD — chuỗi thật OPA deny -> Loki -> Grafana -> incident-analyzer -> email")
    ap.add_argument("--scenario", default="crapi_lateral_movement.sh",
                     help="script trong tests/ tạo tấn công THẬT (mặc định: Lateral Movement, đã verify sống bắn alert)")
    ap.add_argument("--attack-type-hint", default="lateral_movement")
    ap.add_argument("--alert-name-hint", default="Lateral Movement")
    ap.add_argument("--opa-deny-query", default='{job="opa-decisions", opa_result="false"} |~ "/workshop/api/shop/orders"',
                     help="LogQL cho MỐC T1 (dòng log SỚM NHẤT xác nhận tín hiệu tấn công đã tới Loki) — "
                          "mặc định là opa-decisions cho kịch bản OPA-based; đổi thành query Keycloak "
                          "LOGIN_ERROR (job=envoy-access hoặc namespace=identity) cho brute_force, v.v.")
    ap.add_argument("--timeout", type=float, default=180.0, help="giây chờ evidence bundle + email xuất hiện")
    ap.add_argument("--output", default="results/mttd.json")
    ap.add_argument("--runs", type=int, default=1,
                    help="số lượt (vòng 2026-09-29: >= 10); mỗi lượt chờ rule về inactive trước khi tấn công")
    ap.add_argument("--rule-title", default="",
                    help="tiền tố tiêu đề rule Grafana để chờ về inactive giữa các lượt (vd 'crAPI — Lateral Movement')")
    ap.add_argument("--settle-timeout", type=float, default=900.0,
                    help="giây tối đa chờ rule về inactive trước mỗi lượt")
    args = ap.parse_args()

    print("ZTLab MTTD — đo chuỗi thật (Phần 1.5; nhiều lượt: vòng 2026-09-29)")
    print(f"  kịch bản: {args.scenario}  runs={args.runs}  rule={args.rule_title or '-'}")
    runs = []
    for i in range(1, args.runs + 1):
        print(f"\n── lượt {i}/{args.runs} ──")
        if args.rule_title:
            st = _wait_rule_inactive(args.rule_title, args.settle_timeout)
            print(f"  rule trước lượt: {st}")
        r = run_once(args)
        r["run"] = i
        runs.append(r)
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(_summary(args, runs), indent=2, ensure_ascii=False))
    summ = _summary(args, runs)
    print(f"\nGhi kết quả vào {args.output}")
    print("\n=== MTTD (trung vị [min–max], n lượt có bundle) ===")
    for k, v in summ["summary"].items():
        print(f"  {k:<42}: {v}")
    return 0 if summ["summary"]["mttd_to_evidence_s"]["n"] == args.runs else 1


def _grafana_pass() -> str:
    import base64
    out = subprocess.run(["kubectl", "--context", "ctx-aws", "-n", "plg-stack", "get", "secret",
                          "grafana-admin-secret", "-o", "jsonpath={.data.admin-password}"],
                         capture_output=True, text=True, timeout=30)
    return base64.b64decode(out.stdout.strip()).decode()


def _rule_state(title_prefix: str) -> str:
    import base64
    req = urllib.request.Request(f"{GRAFANA_URL}/api/prometheus/grafana/api/v1/rules")
    req.add_header("Authorization", "Basic " + base64.b64encode(f"admin:{_grafana_pass()}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r)
    except Exception as e:  # noqa: BLE001
        return f"error:{e}"
    for g in data["data"]["groups"]:
        for rule in g["rules"]:
            if rule["name"].startswith(title_prefix):
                return rule["state"]
    return "missing"


def _wait_rule_inactive(title_prefix: str, timeout: float) -> str:
    """H14: hai lượt cùng kịch bản chỉ tách được thành 2 thông báo khi lượt trước
    đã về inactive (rule sum() không nhãn → cùng alert instance; nếu còn firing,
    lượt sau KHÔNG sinh bundle mới cho tới repeat_interval)."""
    deadline = time.time() + timeout
    st = _rule_state(title_prefix)
    while st != "inactive" and time.time() < deadline:
        time.sleep(15)
        st = _rule_state(title_prefix)
    if st == "inactive":
        time.sleep(35)  # > group_interval 30 s: nhóm Alertmanager cũ đã flush resolved và bị xoá
    return st


def _stat(vals: list) -> dict:
    v = sorted(x for x in vals if x is not None)
    if not v:
        return {"n": 0}
    return {"n": len(v), "median": round(statistics.median(v), 2), "min": round(v[0], 2), "max": round(v[-1], 2)}


def _summary(args, runs: list[dict]) -> dict:
    return {
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenario": args.scenario,
        "runs_requested": args.runs,
        "summary": {
            "mttd_to_evidence_s": _stat([r["mttd_to_evidence_s"] for r in runs]),
            "attack_duration_s": _stat([r["attack_duration_s"] for r in runs]),
            "detect_after_attack_end_s": _stat([r["detect_after_attack_end_s"] for r in runs]),
            "detect_after_first_signal_s": _stat([r["breakdown_s"]["opa_deny_to_evidence_bundle"] for r in runs]),
            "mttd_to_email_delivered_s": _stat([r["mttd_to_email_delivered_s"] for r in runs]),
        },
        "runs": runs,
    }


def run_once(args) -> dict:
    t0 = time.time()
    proc = subprocess.run(["bash", str(REPO_ROOT / "tests" / args.scenario)],
                           capture_output=True, text=True, timeout=120)
    t0_attack_end = time.time()
    print(f"  [T0={t0:.0f}] tấn công chạy xong lúc {t0_attack_end:.0f} (exit={proc.returncode})")
    if proc.returncode != 0:
        print("  CẢNH BÁO: script tấn công thoát khác 0 — vẫn tiếp tục đo (có thể vẫn sinh đủ log để Grafana fire)")

    print("  chờ OPA decision log (deny) xuất hiện trên Loki...")
    time.sleep(5)
    t1 = _loki_first_ts(args.opa_deny_query, int(t0) - 5, int(time.time()) + 5)
    if t1:
        print(f"  [T1={t1:.2f}] OPA decision log (deny) đầu tiên — độ trễ tới đây: {t1 - t0:.2f}s")
    else:
        print("  KHÔNG tìm thấy OPA decision log deny khớp query trong cửa sổ — MTTD từng chặng sẽ thiếu T1")

    print(f"  chờ evidence bundle (incident-analyzer, timeout={args.timeout:.0f}s)...")
    rec = _poll_evidence_bundle(args.attack_type_hint, args.alert_name_hint, t0, args.timeout)
    t2 = _iso_to_epoch(rec["ts"]) if rec else None
    if t2:
        print(f"  [T2={t2:.2f}] evidence bundle {rec['evidence_id']} — MTTD (attack->evidence) = {t2 - t0:.2f}s")
    else:
        print("  KHÔNG thấy evidence bundle mới trong timeout — kiểm tra Grafana alert rule có Firing không "
              "(http://localhost:3000/alerting/list) và incident-analyzer có nhận webhook không.")

    email = None
    t3 = None
    if t2:
        print("  chờ email tới hộp thư SOC (MailHog)...")
        email = _find_mailhog_message(args.alert_name_hint, t2, min(args.timeout, 60))
        t3 = email["created_epoch"] if email else None
        if t3:
            print(f"  [T3={t3:.2f}] email nhận được — MTTD đầu-cuối (attack->email) = {t3 - t0:.2f}s")
        else:
            print("  KHÔNG thấy email khớp trong MailHog trong thời gian chờ (rec.email_sent có thể vẫn true — "
                  "kiểm tra SMTP tới MailHog riêng)")

    result = {
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenario": args.scenario,
        "methodology": (
            "Đo chuỗi THẬT: T0=tấn công script chạy xong (crapi_*.sh thật, không "
            "phải log giả) -> T1=timestamp THẬT của dòng OPA decision log deny đầu "
            "tiên trên Loki (xác nhận OPA+Promtail+Loki) -> T2=trường `ts` của "
            "evidence bundle mới trên incident-analyzer GET /evidence (đã bao hàm "
            "chu kỳ eval Grafana + webhook + build bundle, KHÔNG tách riêng được "
            "thời điểm Grafana chuyển Firing bằng 1 lệnh gọi đơn giản) -> "
            "T3=Created timestamp THẬT của email trên MailHog SOC (xác nhận SMTP "
            "dispatch thành công, không suy đoán từ cờ email_sent). MTTD chính "
            "(đúng định nghĩa đề cương 'attack -> evidence bundle được gửi đi') = "
            "T2-T0. MTTR CŨ đã bị bỏ hẳn — A4 xoá soar-engine/ai-analyzer, không "
            "còn hành động phản ứng tự động nào để đo 'thời gian tới thực thi'."
        ),
        "t0_attack_epoch": t0,
        "t1_opa_deny_epoch": t1,
        "t2_evidence_created_epoch": t2,
        "t3_email_received_epoch": t3,
        "evidence_id": rec["evidence_id"] if rec else None,
        "alert_name": rec["alert_name"] if rec else None,
        "email_subject": email["subject"] if email else None,
        "mttd_to_evidence_s": round(t2 - t0, 2) if t2 else None,
        "mttd_to_email_delivered_s": round(t3 - t0, 2) if t3 else None,
        # Vòng 2026-09-29 (H14): tách thời gian bản thân script tấn công chạy (Brute
        # Force ~37 s) khỏi thời gian hệ thống phát hiện.
        "t0_attack_end_epoch": t0_attack_end,
        "attack_duration_s": round(t0_attack_end - t0, 2),
        "detect_after_attack_end_s": round(t2 - t0_attack_end, 2) if t2 else None,
        "breakdown_s": {
            "attack_to_opa_deny": round(t1 - t0, 2) if t1 else None,
            "opa_deny_to_evidence_bundle": round(t2 - t1, 2) if (t1 and t2) else None,
            "evidence_bundle_to_email": round(t3 - t2, 2) if (t2 and t3) else None,
        },
    }

    return result


if __name__ == "__main__":
    raise SystemExit(main())
