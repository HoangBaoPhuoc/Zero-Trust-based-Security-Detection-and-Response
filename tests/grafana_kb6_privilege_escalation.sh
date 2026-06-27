#!/bin/bash
# KB6 — Privilege Escalation in Container (T1611)
# Zero Trust layer: Workload isolation (least-privilege pod security + Seccomp/AppArmor)
# Grafana rule  : Privilege Escalation in Container (T1611) → severity=critical
# SOAR playbook : quarantine_workload (cách ly container để forensics)
# HITL          : YES — email gửi admin (critical)
set -euo pipefail

SOAR_URL="${SOAR_URL:-http://localhost:8091}"
LOKI_URL="${LOKI_URL:-http://localhost:13100}"
SCENARIO="KB6_privilege_escalation"

log()  { printf "[%s] %s\n"       "$SCENARIO" "$*"; }
pass() { printf "[%s] PASS: %s\n" "$SCENARIO" "$*"; }
fail() { printf "[%s] FAIL: %s\n" "$SCENARIO" "$*" >&2; exit 1; }

# ── 1. Kiểm tra dịch vụ ─────────────────────────────────────────────────────
log "Bước 1: kiểm tra SOAR và Loki..."
curl -fsS "$SOAR_URL/health" | grep -q '"status":"ok"' || fail "SOAR không khả dụng"
curl -fsS "$LOKI_URL/ready" >/dev/null || fail "Loki không khả dụng"

# ── 2. Mô phỏng privesc bên trong container ─────────────────────────────────
log "Bước 2: mô phỏng privilege escalation trong container (setuid/cap_sys_admin)..."
pod=$(kubectl --context ctx-aws get pod -n financial -l app=api-gateway -o name 2>/dev/null | head -1)
if [[ -n "$pod" ]]; then
  log "Đang chạy lệnh trong pod $pod..."
  kubectl --context ctx-aws exec -n financial "$pod" -- sh -c \
    "echo 'SIMULATED: privilege_escalation setuid cap_sys_admin seccomp.unconfined container_escape privesc' >> /tmp/privesc.log 2>/dev/null; echo done" \
    2>/dev/null || log "exec thất bại (pod không cho exec root) — tiếp tục với Loki injection"
else
  log "Không có pod api-gateway để exec — tiếp tục với Loki injection"
fi

# ── 3. Đẩy log privilege escalation vào Loki ────────────────────────────────
log "Bước 3: đẩy log privilege_escalation vào Loki (namespace=financial)..."
ts=$(date +%s%N)
curl -s -X POST "$LOKI_URL/loki/api/v1/push" \
  -H "Content-Type: application/json" \
  -d "{\"streams\":[{
    \"stream\":{\"namespace\":\"financial\",\"app\":\"api-gateway\",
                \"job\":\"container-runtime\"},
    \"values\":[
      [\"$ts\",\"AUDIT: privilege_escalation detected — process attempted setuid(0) in container api-gateway\"],
      [\"$((ts+1000000))\",\"SECURITY: cap_sys_admin capability access by PID 1337 — policy violation\"],
      [\"$((ts+2000000))\",\"WARNING: seccomp.unconfined profile detected — container running without syscall restrictions\"],
      [\"$((ts+3000000))\",\"ALERT: container_escape attempt via /proc/sysrq-trigger — blocked by AppArmor\"],
      [\"$((ts+4000000))\",\"CRITICAL: privesc via SUID binary /usr/bin/nsenter — Zero Trust workload isolation violation\"]
    ]
  }]}" >/dev/null
log "5 privilege escalation log đã vào Loki (namespace=financial)"

# ── 4. Mô phỏng Grafana → SOAR webhook ────────────────────────────────────────
log "Bước 4: mô phỏng Grafana 'Privilege Escalation in Container' alert → SOAR webhook..."
fp="kb6-$(date +%s)"
soar_resp=$(curl -s -X POST "$SOAR_URL/grafana-webhook" \
  -H "Content-Type: application/json" \
  -d "{
    \"status\": \"firing\",
    \"alerts\": [{
      \"status\": \"firing\",
      \"labels\": {
        \"alertname\": \"Privilege Escalation in Container (T1611)\",
        \"severity\": \"critical\",
        \"attack_type\": \"privilege_escalation\",
        \"mitre\": \"T1611\",
        \"category\": \"security\"
      },
      \"annotations\": {
        \"summary\": \"Phát hiện Privilege Escalation trong container — vi phạm workload isolation\",
        \"description\": \"namespace=financial app=api-gateway event=setuid(0)+cap_sys_admin+seccomp.unconfined pid=1337\"
      },
      \"fingerprint\": \"$fp\"
    }]
  }")

# ── 5. Kiểm tra SOAR case ─────────────────────────────────────────────────────
log "Bước 5: kiểm tra SOAR case..."
status=$(echo "$soar_resp"   | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('status','?') if c else 'no-case')" 2>/dev/null)
playbook=$(echo "$soar_resp" | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('playbook','?') if c else '?')" 2>/dev/null)
case_id=$(echo "$soar_resp"  | python3 -c "import sys,json; c=json.load(sys.stdin).get('cases',[]); print(c[0].get('case_id','?') if c else '?')" 2>/dev/null)

[[ "$status" =~ ^(pending_approval|executed|dry_run)$ ]] \
  || fail "SOAR status='$status' (expect pending_approval)"
[[ "$playbook" == "quarantine_workload" ]] \
  || fail "SOAR playbook='$playbook' (expect quarantine_workload)"

pass "KB6 Privilege Escalation | privesc logs injected | SOAR case=$case_id status=$status playbook=$playbook (T1611)"
log "→ quarantine_workload: cách ly container để forensics — Zero Trust: mọi workload phải chạy least-privilege"
log "→ Không restore workload cho đến khi admin phân tích xong (HITL email đã gửi)"
