#!/usr/bin/env bash
# KỊCH BẢN — Privilege Escalation in Container (T1068) — mục 3 vòng 2026-09-29
# Chạy Job THẬT k8s/crapi/security-scanner-job.yaml (container uid=0 + capability
# nguy hiểm → log event=privilege_escalation) → Loki → rule Grafana Firing →
# evidence bundle attack_type=privilege_escalation.
set -uo pipefail
SCENARIO="crapi_privilege_escalation"
source "$(dirname "${BASH_SOURCE[0]}")/lib/crapi_common.sh"
OUT="$REPO_ROOT/results/${RESULTS_ROUND:-closeout}/alerts"; mkdir -p "$OUT"
RULE="Kịch bản 6 — Privilege Escalation"
log "trạng thái rule trước khi chạy: $(grafana_rule_state "$RULE")"
T0=$(date +%s)
kubectl --context "$KUBE_AWS" -n "$NS" delete job security-scanner --ignore-not-found --wait=true >/dev/null
kubectl --context "$KUBE_AWS" apply -f "$REPO_ROOT/k8s/crapi/security-scanner-job.yaml" || fail "không tạo được Job (Gatekeeper?)"
kubectl --context "$KUBE_AWS" -n "$NS" wait --for=condition=complete job/security-scanner --timeout=180s \
  || fail "Job security-scanner không complete"
line="$(kubectl --context "$KUBE_AWS" -n "$NS" logs job/security-scanner -c security-scanner | grep '"event"' | tail -1)"
log "log scanner: ${line:0:220}"
grep -q '"privilege_escalation"' <<<"$line" || fail "scanner không ghi event=privilege_escalation"
fired="$(wait_rule_firing "$RULE" 240)" || fail "rule không Firing trong 240 s"
log "rule Firing: $fired"
ev="$(wait_evidence privilege_escalation "$T0" 180)" || fail "không có evidence bundle privilege_escalation"
log "evidence: $ev"
echo "ts=$(date -Is) scenario=privilege_escalation firing=[$fired] evidence=$ev" >> "$OUT/firing-evidence.log"
pass "$SCENARIO — scanner uid=0 → Firing ($fired) → evidence bundle"
