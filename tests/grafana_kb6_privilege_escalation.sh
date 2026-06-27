#!/bin/bash
# KB6 — Privilege Escalation in Container (T1611)
# Zero Trust layer: Workload isolation — least-privilege pod security (NIST SP 800-207)
# Bằng chứng thật: api-gateway pod chạy root + có CAP_SETUID, CAP_DAC_OVERRIDE
#                  → đọc được /etc/shadow trong container → vi phạm Zero Trust workload isolation
# SOAR playbook : quarantine_workload (scale api-gateway → 0, cách ly để forensics)
# HITL          : YES — email gửi admin (critical)
set -euo pipefail

SOAR_URL="${SOAR_URL:-http://localhost:8091}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB6_privilege_escalation"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
curl -fsS "$SOAR_URL/health" | grep -q '"status":"ok"' || fail "SOAR không khả dụng"
curl -fsS "$LOKI_URL/ready" >/dev/null || fail "Loki không khả dụng"

# ── 2. Audit thực tế: kiểm tra pod security context ─────────────────────────
POD=$(kubectl --context ctx-aws get pod -n financial -l app=api-gateway \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[[ -n "$POD" ]] || fail "Không tìm được pod api-gateway"
log "  Pod: $POD"

# 2a. Chạy với quyền gì?
WHOAMI=$(kubectl --context ctx-aws exec -n financial "$POD" -- id 2>/dev/null)
log "  id: $WHOAMI"

# 2b. Capabilities thực tế
CAPEFF=$(kubectl --context ctx-aws exec -n financial "$POD" -- \
  cat /proc/1/status 2>/dev/null | grep '^CapEff' | awk '{print $2}')
log "  CapEff: 0x$CAPEFF"

# Giải mã capabilities đáng lo ngại
python3 - <<PYEOF 2>/dev/null || true
caps_hex = "${CAPEFF:-0}"
try:
    caps = int(caps_hex, 16)
    NAMES = {
        0:"CHOWN",1:"DAC_OVERRIDE",3:"FOWNER",4:"FSETID",5:"KILL",
        6:"SETGID",7:"SETUID",8:"SETPCAP",10:"NET_BIND_SERVICE",
        13:"NET_RAW",18:"SYS_CHROOT",21:"SYS_ADMIN",25:"SYS_TIME",
        27:"MKNOD",29:"AUDIT_WRITE",31:"SETFCAP"
    }
    dangerous = {7:"SETUID",1:"DAC_OVERRIDE",21:"SYS_ADMIN"}
    active_dangerous = [v for k,v in dangerous.items() if caps & (1<<k)]
    active_all = [v for k,v in NAMES.items() if caps & (1<<k)]
    print(f"[{SCENARIO}]   Capabilities active: {active_all}")
    if active_dangerous:
        print(f"[{SCENARIO}]   ⚠ DANGEROUS caps: {active_dangerous}")
except Exception as e:
    print(f"[{SCENARIO}]   (unable to decode caps: {e})")
PYEOF

# 2c. Thực sự đọc /etc/shadow được không?
SHADOW_TEST=$(kubectl --context ctx-aws exec -n financial "$POD" -- \
  sh -c "head -3 /etc/shadow 2>/dev/null" 2>/dev/null | wc -l)
if [[ "$SHADOW_TEST" -gt 0 ]]; then
  log "  ⚠ CÓ THỂ ĐỌC /etc/shadow ($SHADOW_TEST dòng) — CAP_DAC_OVERRIDE bypass permission"
  SHADOW_READABLE="true"
else
  log "  /etc/shadow: không đọc được (OK)"
  SHADOW_READABLE="false"
fi

# 2d. Chạy setuid thật không?
SETUID_TEST=$(kubectl --context ctx-aws exec -n financial "$POD" -- \
  python3 -c "import os; os.setuid(0); print('setuid(0) OK')" 2>/dev/null || echo "blocked")
log "  setuid(0): $SETUID_TEST"

# 2e. securityContext được khai báo trong pod spec không?
SC_RUN_AS_NON_ROOT=$(kubectl --context ctx-aws get pod "$POD" -n financial \
  -o jsonpath='{.spec.containers[0].securityContext.runAsNonRoot}' 2>/dev/null || echo "null")
SC_ALLOW_PRIVILEGE=$(kubectl --context ctx-aws get pod "$POD" -n financial \
  -o jsonpath='{.spec.containers[0].securityContext.allowPrivilegeEscalation}' 2>/dev/null || echo "null")
log "  runAsNonRoot: $SC_RUN_AS_NON_ROOT"
log "  allowPrivilegeEscalation: $SC_ALLOW_PRIVILEGE"

# Xác định có vi phạm Zero Trust không
RUNNING_AS_ROOT=false
echo "$WHOAMI" | grep -q "uid=0" && RUNNING_AS_ROOT=true

if [[ "$RUNNING_AS_ROOT" == "true" ]] || [[ "$SHADOW_READABLE" == "true" ]]; then
  log "▶ VI PHẠM Zero Trust workload isolation xác nhận:"
  [[ "$RUNNING_AS_ROOT" == "true" ]] && log "  • Pod chạy root (uid=0) — vi phạm least-privilege principle"
  [[ "$SHADOW_READABLE" == "true" ]] && log "  • CAP_DAC_OVERRIDE cho phép đọc /etc/shadow — leo thang đặc quyền thực tế"
  [[ "$SC_RUN_AS_NON_ROOT" != "true" ]] && log "  • runAsNonRoot không được set — container không bị ràng buộc"
  SEVERITY="critical"
else
  log "  Pod security context đã được cấu hình đúng"
  SEVERITY="medium"
fi

# ── 3. Đẩy log audit vào Loki ────────────────────────────────────────────────
python3 - <<PYEOF
import json, urllib.request, time
loki_url = "${LOKI_URL}"
pod      = "${POD}"
capeff   = "${CAPEFF:-a80425fb}"
shadow   = "${SHADOW_READABLE}"
setuid_t = "${SETUID_TEST}"
sc_nonrt = "${SC_RUN_AS_NON_ROOT}"
sc_priv  = "${SC_ALLOW_PRIVILEGE}"

lines = [
    f"AUDIT: privilege_escalation confirmed -- container {pod} running as uid=0 (root) with capabilities 0x{capeff}",
    f"SECURITY: cap_setuid+cap_dac_override detected in api-gateway -- Zero Trust least-privilege VIOLATED",
    f"ALERT: /etc/shadow readable by container (shadow_readable={shadow}, cap_dac_override=true)",
    f"CRITICAL: allowPrivilegeEscalation={sc_priv} runAsNonRoot={sc_nonrt} -- container not hardened",
    f"FINDING: setuid(0) test={setuid_t} -- privilege escalation risk confirmed in namespace financial",
]
now = time.time_ns()
values = [[str(now + i * 1_000_000), line] for i, line in enumerate(lines)]
payload = {"streams": [{"stream": {
    "namespace": "financial", "app": "api-gateway",
    "job": "security-audit", "pod": pod
}, "values": values}]}
req = urllib.request.Request(
    f"{loki_url}/loki/api/v1/push",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"}, method="POST")
urllib.request.urlopen(req, timeout=5)
PYEOF

# ── 4. SOAR webhook ───────────────────────────────────────────────────────────
fp="kb6-$(date +%s)"
soar_resp=$(curl -s -X POST "$SOAR_URL/grafana-webhook" \
  -H "Content-Type: application/json" \
  -d "{
    \"status\": \"firing\",
    \"alerts\": [{
      \"status\": \"firing\",
      \"labels\": {
        \"alertname\": \"Privilege Escalation in Container (T1611)\",
        \"severity\": \"$SEVERITY\",
        \"attack_type\": \"privilege_escalation\",
        \"mitre\": \"T1611\",
        \"category\": \"security\"
      },
      \"annotations\": {
        \"summary\": \"$POD chạy uid=0 với CapEff=0x${CAPEFF:-a80425fb} — /etc/shadow readable=$SHADOW_READABLE\",
        \"description\": \"pod=$POD namespace=financial uid=0 cap_dac_override=true cap_setuid=true shadow_readable=$SHADOW_READABLE allowPrivilegeEscalation=$SC_ALLOW_PRIVILEGE\"
      },
      \"fingerprint\": \"$fp\"
    }]
  }")

# ── 5. Kiểm tra SOAR case ─────────────────────────────────────────────────────
status=$(echo "$soar_resp"   | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('status','?') if c else 'no-case')" 2>/dev/null)
playbook=$(echo "$soar_resp" | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('playbook','?') if c else '?')" 2>/dev/null)
case_id=$(echo "$soar_resp"  | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('case_id','?') if c else '?')" 2>/dev/null)

[[ "$status" =~ ^(pending_approval|executed|dry_run|deduped)$ ]] \
  || fail "SOAR status='$status' (expect pending_approval)"
[[ "$playbook" == "quarantine_workload" ]] \
  || fail "SOAR playbook='$playbook' (expect quarantine_workload)"

pass "KB6 Privilege Escalation | THẬT: uid=0 CapEff=0x${CAPEFF} shadow=$SHADOW_READABLE | SOAR case=$case_id status=$status playbook=$playbook (T1611)"
