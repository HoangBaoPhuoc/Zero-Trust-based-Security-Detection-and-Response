#!/usr/bin/env bash
# Mục 13 vòng 2026-09-29 — tỉ lệ deny LÀNH TÍNH trong lưu lượng người dùng hợp lệ
# (tiêu chí GO/NO-GO Giai đoạn B: deny lành tính < 1 % VÀ 0 evidence bundle).
#
# DURATION giây (mặc định 1800) lưu lượng hợp lệ qua Gateway (mTLS thiết bị compliant):
#   testuser01  (crapi-user)  : đọc dashboard/xe/sản phẩm/đơn/bài viết + thỉnh thoảng đăng bài
#   merchant01  (crapi-user+mechanic): đọc như trên
#   stepup-demo (crapi-user)  : đăng nhập qua /auth/start-stepup (OTP thật) rồi mới đặt hàng
# Không có request nào cố ý vượt quyền. Sau khi chạy: đếm request + mã HTTP (phía
# client), OPA deny trong [T0,T1] (Loki opa-decisions, cả 2 cloud), evidence bundle
# trong [T0,T1], và NHÓM deny theo request_path + source_principal.
set -uo pipefail
SCENARIO="benign_traffic_403"
source "$(dirname "${BASH_SOURCE[0]}")/lib/crapi_common.sh"
DURATION="${DURATION:-1800}"
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-closeout}/benign-403"; mkdir -p "$OUT"
TAG="run$(date +%Y%m%d%H%M%S)"; REQLOG="$OUT/$TAG.requests.tsv"
crapi_preflight
mapfile -t TLS < <(crapi_curl_tls_opts)
form_action() { grep -oE 'action="[^"]+"' | head -1 | sed -E 's/^action="//; s/"$//; s/&amp;/\&/g'; }
SECRET="$(kubectl --context "$KUBE_OS" -n identity get secret stepup-demo-otp -o jsonpath='{.data.secret}' | base64 -d)"
totp() { python3 -c 'import hmac,hashlib,struct,time,sys
s=sys.argv[1].encode(); c=int(time.time()//30)
m=hmac.new(s,struct.pack(">Q",c),hashlib.sha1).digest(); o=m[-1]&15
print("%06d"%((struct.unpack(">I",m[o:o+4])[0]&0x7fffffff)%1000000))' "$SECRET"; }

# login_stepup <jar>: stepup-demo qua /auth/start-stepup + OTP (Keycloak hỏi OTP đúng 1 lần)
LAST_WIN=""
login_stepup() {
  local jar="$1" page act win
  page="$(curl -s -A "$BROWSER_UA" "${TLS[@]}" -c "$jar" -b "$jar" -L "$BFF_URL/auth/start-stepup")"
  act="$(form_action <<<"$page")"
  page="$(curl -s -A "$BROWSER_UA" "${TLS[@]}" -c "$jar" -b "$jar" -L \
    --data-urlencode "username=stepup-demo" --data-urlencode "password=StepupDemo123!" "$act")"
  win=$(( $(date +%s) / 30 )); while [[ "$win" == "$LAST_WIN" ]]; do sleep 2; win=$(( $(date +%s) / 30 )); done
  LAST_WIN="$win"; act="$(form_action <<<"$page")"
  curl -s -A "$BROWSER_UA" "${TLS[@]}" -c "$jar" -b "$jar" -L -o /dev/null \
    --data-urlencode "otp=$(totp)" --data-urlencode "login=Sign In" "$act"
}

READS=(/identity/api/v2/user/dashboard /identity/api/v2/vehicle/vehicles /workshop/api/shop/products
       /workshop/api/shop/orders/all /community/api/v2/community/posts/recent)
req() { # <user> <jar> <method> <path> [data]
  local c; c="$(crapi_call "$2" "$3" "$4" "${5:-}")"
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date +%s.%N)" "$1" "$3" "$4" "$c" >> "$REQLOG"
}

# ── Tự kiểm: decision log OPA PHẢI đang chảy vào Loki trước khi đếm ────────────
# (bước perf_diag_nolog trước đó TẮT tạm decision log; nếu khôi phục lỗi, "0 deny" sẽ
# có nghĩa là "không có log", không phải "không có deny" → PASS giả cho tiêu chí GO/NO-GO.)
# Gửi 1 request CỐ Ý bị từ chối: crapi-community → crapi-workshop (ngoài service_acl) trên
# path KHÔNG phải API nghiệp vụ (/decision-log-probe-…) để không khớp rule Lateral; rồi
# phải thấy chính nó trong Loki opa-decisions opa_result=false trong ≤ 60 s.
PROBE="decision-log-probe-$TAG"
ATTACKER_POD="$(crapi_pod crapi-community)"
kubectl --context "$KUBE_AWS" -n "$NS" exec "$ATTACKER_POD" -c crapi-community -- \
  sh -c "wget -q -O /dev/null -T8 http://crapi-workshop.crapi.svc.cluster.local:8000/$PROBE 2>&1" >/dev/null 2>&1 || true
TP=$(date +%s); DL_OK=""
for _ in $(seq 1 12); do
  sleep 5
  n="$(loki_count "{job=\"opa-decisions\", opa_result=\"false\"} |= \"$PROBE\"" "$((TP-30))" "$(( $(date +%s) + 1 ))")"
  [[ "${n:-0}" -ge 1 ]] && { DL_OK=yes; break; }
done
if [[ -z "$DL_OK" ]]; then
  echo "ABORT: decision log OPA KHÔNG chảy vào Loki (probe $PROBE bị từ chối nhưng không thấy trong opa-decisions sau 60 s)." \
       "Số deny đo lúc này sẽ vô nghĩa — KHÔNG báo PASS." | tee "$OUT/$TAG.ABORT"
  exit 3
fi
log "decision log đang chảy: PASS (probe $PROBE có trong opa-decisions, opa_result=false)"
# Rule Access Denied KHÔNG có ngưỡng (1 deny trong 10 phút là Firing) → chính probe sẽ sinh
# 1 bundle. Chờ cả Access Denied lẫn Lateral về inactive (+35 s > group_interval) rồi mới mở
# cửa sổ đo, để bundle của probe/của bước trước nằm NGOÀI [T0,T1].
for r in "crAPI — Access Denied" "crAPI — Lateral Movement"; do
  for _ in $(seq 1 60); do [[ "$(grafana_rule_state "$r")" == inactive* ]] && break; sleep 20; done
  log "rule '$r' trước cửa sổ đo: $(grafana_rule_state "$r")"
done
sleep 35

T0=$(date +%s)
JU="$(crapi_login testuser01 'Test1234!')"; JM="$(crapi_login merchant01 'Test1234!')"
JS="$(mktemp /tmp/crapi_cj.XXXXXX)"; login_stepup "$JS"
trap 'rm -f "$JU" "$JM" "$JS"' EXIT
end=$(( T0 + DURATION )); i=0
log "chạy $DURATION s lưu lượng hợp lệ (tag=$TAG)"
while [[ $(date +%s) -lt $end ]]; do
  i=$((i+1))
  req testuser01 "$JU" GET "${READS[RANDOM % ${#READS[@]}]}"
  req merchant01 "$JM" GET "${READS[RANDOM % ${#READS[@]}]}"
  req stepup-demo "$JS" GET "${READS[RANDOM % ${#READS[@]}]}"
  (( i % 20 == 0 )) && req testuser01 "$JU" POST /community/api/v2/community/posts \
      "{\"title\":\"benign-$i\",\"content\":\"bài viết thường $i\"}"
  (( i % 30 == 0 )) && req stepup-demo "$JS" POST /workshop/api/shop/orders '{"product_id":1,"quantity":1}'
  (( i % 60 == 0 )) && log "  $(date +%T) vòng $i, $(wc -l < "$REQLOG") request"
  sleep $(( 1 + RANDOM % 3 ))
done
T1=$(( $(date +%s) + 1 ))
sleep 20   # Promtail → Loki

python3 - "$REQLOG" "$T0" "$T1" "$OUT/$TAG.summary.json" <<'PY'
import collections, json, sys, time, urllib.parse, urllib.request, datetime
reqlog, t0, t1, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
rows = [l.rstrip("\n").split("\t") for l in open(reqlog)]
codes = collections.Counter(r[4] for r in rows)
by_path_code = collections.Counter((r[1], r[2], r[3].split("?")[0], r[4]) for r in rows if r[4] != "200")
def loki(q, limit=5000):
    qs = urllib.parse.urlencode({"query": q, "start": f"{t0}000000000", "end": f"{t1}000000000",
                                 "limit": limit, "direction": "forward"})
    return json.load(urllib.request.urlopen("http://localhost:13100/loki/api/v1/query_range?" + qs, timeout=30))
def instant(q):
    qs = urllib.parse.urlencode({"query": q, "time": f"{t1}000000000"})
    r = json.load(urllib.request.urlopen("http://localhost:13100/loki/api/v1/query?" + qs, timeout=30))["data"]["result"]
    return int(float(r[0]["value"][1])) if r else 0
dur = t1 - t0
# mẫu số = dòng QUYẾT ĐỊNH (có nhãn opa_result), không phải mọi dòng của job (gồm log HTTP health của OPA)
opa_total = instant(f'sum(count_over_time({{job="opa-decisions", opa_result=~"true|false"}}[{dur}s]))')
opa_deny = instant(f'sum(count_over_time({{job="opa-decisions", opa_result="false"}}[{dur}s]))')
groups = collections.Counter()
for s in loki('{job="opa-decisions", opa_result="false"}')["data"]["result"]:
    st = s["stream"]
    for _ts, line in s["values"]:
        try:
            d = json.loads(line); a = d["input"]["attributes"]
            path = a["request"]["http"]["path"].split("?")[0]; src = a["source"].get("principal", "")
            reason = d.get("result")
        except Exception:
            path, src = st.get("request_path", "?"), st.get("source_principal", "?")
        groups[(st.get("cloud"), src, path)] += 1
ev = json.load(urllib.request.urlopen("http://localhost:8091/evidence", timeout=30))
def epoch(x): return datetime.datetime.fromisoformat(x.replace("Z", "+00:00")).timestamp()
bundles = [{"ts": e["ts"], "attack_type": e.get("attack_type"), "alert_name": e.get("alert_name")}
           for e in ev if t0 <= epoch(e["ts"]) <= t1 + 300]
n = len(rows); non200 = n - codes.get("200", 0)
summary = {
    "window": [t0, t1], "duration_s": dur, "client_requests": n, "client_codes": dict(codes),
    "client_non200_by_user_method_path": [{"user": k[0], "method": k[1], "path": k[2], "code": k[3], "count": v}
                                          for k, v in by_path_code.most_common()],
    "opa_decisions_total": opa_total, "opa_deny": opa_deny,
    "opa_deny_rate_pct": round(100 * opa_deny / opa_total, 3) if opa_total else None,
    "client_403_rate_pct": round(100 * codes.get("403", 0) / n, 3) if n else None,
    "opa_deny_groups": [{"cloud": k[0], "source_principal": k[1], "path": k[2], "count": v} for k, v in groups.most_common()],
    "evidence_bundles_in_window_plus_5min": bundles,
    "criteria": {"deny_rate_lt_1pct": (opa_total and 100 * opa_deny / opa_total < 1.0), "zero_bundles": len(bundles) == 0},
}
json.dump(summary, open(out, "w"), indent=2, ensure_ascii=False)
print(json.dumps({k: summary[k] for k in ("duration_s", "client_requests", "client_codes", "opa_decisions_total",
                                          "opa_deny", "opa_deny_rate_pct", "client_403_rate_pct", "criteria")}, ensure_ascii=False))
for g in summary["opa_deny_groups"][:15]: print("  deny", g)
for g in summary["client_non200_by_user_method_path"][:15]: print("  non200", g)
for b in bundles: print("  bundle", b)
PY
python3 - "$OUT/$TAG.summary.json" <<'PY' | tee -a "$OUT/$TAG.result.txt"
import json,sys
d=json.load(open(sys.argv[1]))
print(f"KẾT QUẢ mục 13: decision_log_chảy=PASS requests={d['client_requests']} opa_decisions={d['opa_decisions_total']} "
      f"deny={d['opa_deny']} tỉ_lệ_deny={d['opa_deny_rate_pct']}% 403_phía_client={d['client_403_rate_pct']}% "
      f"bundles={len(d['evidence_bundles_in_window_plus_5min'])} "
      f"GO={'CÓ' if d['criteria']['deny_rate_lt_1pct'] and d['criteria']['zero_bundles'] else 'KHÔNG'}")
PY
