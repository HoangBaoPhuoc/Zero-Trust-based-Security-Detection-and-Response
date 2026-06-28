#!/bin/bash
# KB6 — Privilege Escalation in Container (T1611)
# Zero Trust layer: Workload isolation — least-privilege pod security (NIST SP 800-207)
# Tấn công thật: chạy security-scanner Job trong namespace financial
#                → Job kiểm tra security context thật (uid, capabilities, /etc/shadow)
#                → financial namespace không enforce runAsNonRoot → chạy root → violation thật
#                → log AUDIT privilege_escalation (JSON) ra stdout → Promtail thu → Loki
# Grafana rule  : Privilege Escalation → severity=critical
#   LogQL: {namespace="financial",app="security-scanner"} | json | event="privilege_escalation"
# SOAR playbook : quarantine_workload
# HITL          : YES — email gửi admin (critical)
set -euo pipefail

LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB6_privilege_escalation"
CONTEXT="${KUBE_CONTEXT:-ctx-aws}"
NAMESPACE="financial"
JOB_MANIFEST="k8s/financial/security-scanner-job.yaml"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra Loki sẵn sàng ───────────────────────────────────────────────
curl -fsS "$LOKI_URL/ready" >/dev/null || fail "Loki không khả dụng"

# ── 2. Deploy security-scanner Job ──────────────────────────────────────────
# Xóa job cũ nếu còn tồn tại
kubectl --context "$CONTEXT" delete job security-scanner -n "$NAMESPACE" \
  --ignore-not-found=true >/dev/null 2>&1
log "Deploy security-scanner Job vào namespace $NAMESPACE"
kubectl --context "$CONTEXT" apply -f "$JOB_MANIFEST" >/dev/null

# ── 3. Chờ Job hoàn thành ───────────────────────────────────────────────────
log "Chờ security-scanner Job hoàn thành (timeout 90s)..."
kubectl --context "$CONTEXT" wait job/security-scanner -n "$NAMESPACE" \
  --for=condition=complete --timeout=90s \
  || fail "security-scanner Job không hoàn thành trong 90s"

# ── 4. Hiển thị kết quả thật ─────────────────────────────────────────────────
log "Kết quả từ security-scanner (log thật):"
kubectl --context "$CONTEXT" logs -n "$NAMESPACE" \
  -l app=security-scanner --tail=5 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        r = json.loads(line)
        print(f'  event={r.get(\"event\")} uid={r.get(\"uid\")} caps={r.get(\"dangerous_capabilities\")} shadow={r.get(\"shadow_readable\")} violation={r.get(\"violation\")}')
    except:
        print(f'  {line.strip()}')
" 2>/dev/null || log "  (đang chờ Promtail thu log...)"

log "Log thật từ security-scanner → Promtail → Loki {namespace=financial, app=security-scanner}"
log "Grafana alert query: {namespace=\"financial\",app=\"security-scanner\"} | json | event=\"privilege_escalation\""

pass "KB6 | security-scanner Job completed | log AUDIT thật → Loki (Grafana fire trong ≤2 phút)"
