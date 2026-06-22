#!/usr/bin/env bash
# Deploy the full ZTLab lab across AWS and OpenStack K3s clusters.
#
# This script intentionally orchestrates the existing focused scripts instead of
# replacing them:
#   - scripts/k8s-tunnel.sh for ctx-aws and ctx-openstack
#   - scripts/sync-financial-images.sh for local image import on all K3s nodes
#   - scripts/deploy-security-stack.sh for SPIRE, OPA, Envoy, and Keycloak
#
# Usage:
#   ./scripts/deploy-all.sh
#   ./scripts/deploy-all.sh --skip-images
#   ./scripts/deploy-all.sh --skip-tunnel
#   ./scripts/deploy-all.sh --skip-security-stack

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"

SKIP_IMAGES=false
SKIP_TUNNEL=false
SKIP_SECURITY_STACK=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[DEPLOY-ALL]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }
step() {
  echo -e "\n${BLUE}══════════════════════════════════════════${NC}"
  echo -e "${BLUE} $*${NC}"
  echo -e "${BLUE}══════════════════════════════════════════${NC}"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [--skip-images] [--skip-tunnel] [--skip-security-stack]

Options:
  --skip-images          Do not rebuild/sync ztlab/* images to K3s nodes
  --skip-tunnel          Assume ctx-aws and ctx-openstack are already reachable
  --skip-security-stack  Skip SPIRE/OPA/Envoy/Keycloak deployment
  -h, --help             Show this help
EOF
}

for arg in "$@"; do
  case "$arg" in
    --skip-images) SKIP_IMAGES=true ;;
    --skip-tunnel) SKIP_TUNNEL=true ;;
    --skip-security-stack) SKIP_SECURITY_STACK=true ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "Unknown option: $arg"
      ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

kaws() {
  kubectl --context "$AWS_CONTEXT" "$@"
}

kos() {
  kubectl --context "$OS_CONTEXT" "$@"
}

verify_context() {
  local ctx="$1"
  kubectl --context "$ctx" get nodes --request-timeout=10s >/dev/null 2>&1 \
    || fail "Cannot reach Kubernetes context: $ctx. Run ./scripts/k8s-tunnel.sh up all"
  ok "Connected to $ctx ($(kubectl --context "$ctx" get nodes --no-headers | wc -l | tr -d ' ') nodes)"
}

wait_deployment() {
  local ctx="$1"
  local ns="$2"
  local name="$3"
  local timeout="${4:-180s}"

  kubectl --context "$ctx" rollout status "deployment/$name" -n "$ns" --timeout="$timeout"
}

wait_daemonset() {
  local ctx="$1"
  local ns="$2"
  local name="$3"
  local timeout="${4:-180s}"

  kubectl --context "$ctx" rollout status "daemonset/$name" -n "$ns" --timeout="$timeout"
}

wait_statefulset() {
  local ctx="$1"
  local ns="$2"
  local name="$3"
  local timeout="${4:-240s}"

  kubectl --context "$ctx" rollout status "statefulset/$name" -n "$ns" --timeout="$timeout"
}

apply_namespaces() {
  step "Step 1: Namespaces"
  kaws apply -f "$REPO_ROOT/k8s/namespaces.yaml"
  kos apply -f "$REPO_ROOT/k8s/namespaces.yaml"
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/namespace.yaml"
  kos apply -f "$REPO_ROOT/k8s/plg-stack/namespace.yaml"
  ok "Namespaces ready on both clusters"
}

sync_images() {
  step "Step 2: Images"
  if [[ "$SKIP_IMAGES" == true ]]; then
    log "Skipping image build/sync"
    return
  fi

  "$REPO_ROOT/scripts/sync-financial-images.sh"
  ok "Images synced to AWS and OpenStack K3s nodes"
}

deploy_security_stack() {
  step "Step 3: Security stack"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping security stack"
    return
  fi

  "$REPO_ROOT/scripts/deploy-security-stack.sh"
  ok "Security stack deployed"
}

deploy_financial_infra() {
  step "Step 4: Financial infrastructure"

  # Shared ConfigMap (financial-common-config) — both clusters need it
  kaws apply -f "$REPO_ROOT/k8s/financial/services.yaml"
  kos apply -f "$REPO_ROOT/k8s/financial/services.yaml"

  # Redis: AWS only (fraud-detection velocity cache + IP block list)
  kaws apply -f "$REPO_ROOT/k8s/financial/redis.yaml"
  wait_deployment "$AWS_CONTEXT" financial redis 120s

  # Postgres: OpenStack only (account-service + transaction-service)
  kos apply -f "$REPO_ROOT/k8s/financial/postgres-accounts.yaml"
  kos apply -f "$REPO_ROOT/k8s/financial/postgres-txn.yaml"
  wait_deployment "$OS_CONTEXT" financial postgres-accounts 180s
  wait_deployment "$OS_CONTEXT" financial postgres-txn 180s

  # DB admin UIs: pgAdmin (port 80) + RedisInsight (port 5540) on AWS
  kaws apply -f "$REPO_ROOT/k8s/financial/db-admin-ui.yaml"

  ok "Redis on AWS, Postgres on OpenStack, DB admin UIs — ready"
}

deploy_financial_services() {
  step "Step 5: Financial workloads"

  create_financial_runtime_secrets
  create_core_banking_integrity_secret

  # OpenStack: OPA + Envoy configmaps must exist before os-services.yaml pods start
  kos apply -f "$REPO_ROOT/k8s/financial/os-security.yaml"

  # AWS: ingress-facing + fraud + notification + web portal
  kaws apply -f "$REPO_ROOT/k8s/financial/aws-services.yaml"
  kaws apply -f "$REPO_ROOT/k8s/financial/web-portal.yaml"
  for svc in api-gateway payment-service fraud-detection notification-service web-portal; do
    wait_deployment "$AWS_CONTEXT" financial "$svc" 180s
  done

  # OpenStack: core banking backend (requires os-security.yaml applied above)
  kos apply -f "$REPO_ROOT/k8s/financial/os-services.yaml"
  for svc in core-banking account-service transaction-service; do
    wait_deployment "$OS_CONTEXT" financial "$svc" 180s
  done

  ok "AWS services, web portal, and OpenStack core banking ready"
}

keycloak_admin_password() {
  if [[ -n "${KEYCLOAK_ADMIN_PASSWORD:-}" ]]; then
    printf '%s' "$KEYCLOAK_ADMIN_PASSWORD"
    return
  fi

  local encoded
  encoded="$(kaws -n identity get secret keycloak-secret -o jsonpath='{.data.admin-password}' 2>/dev/null || true)"
  if [[ -n "$encoded" ]]; then
    printf '%s' "$encoded" | base64 -d
    return
  fi

  fail "KEYCLOAK_ADMIN_PASSWORD is unset and identity/keycloak-secret does not exist"
}

create_keycloak_admin_secret() {
  if kaws get secret keycloak-admin-secret -n plg-stack >/dev/null 2>&1; then
    log "keycloak-admin-secret already exists"
    return
  fi
  local admin_password
  admin_password="$(keycloak_admin_password)"
  kaws create secret generic keycloak-admin-secret -n plg-stack \
    --from-literal=password="$admin_password"
  ok "keycloak-admin-secret created"
}

create_ai_secret() {
  if kaws get secret ai-secrets -n plg-stack >/dev/null 2>&1; then
    log "ai-secrets already exists"
    return
  fi

  kaws create secret generic ai-secrets -n plg-stack \
    --from-literal=AI_PROVIDER="${AI_PROVIDER:-gemini}" \
    --from-literal=GEMINI_API_KEY="${GEMINI_API_KEY:-}" \
    --from-literal=GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.5-flash}" \
    --from-literal=OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
    --from-literal=OPENAI_MODEL="${OPENAI_MODEL:-gpt-4o-mini}" \
    --from-literal=AI_ANALYZER_POLL_ENABLED="true" \
    --from-literal=AI_ANALYZER_POLL_INTERVAL_SECONDS="120" \
    --from-literal=AI_ANALYZER_LOOKBACK_SECONDS="300" \
    --from-literal=AI_ANALYZER_MAX_LOGS_PER_BATCH="10" \
    --from-literal=AI_ANALYZER_MIN_ALERT_SEVERITY="medium" \
    --from-literal=SOAR_DRY_RUN="${SOAR_DRY_RUN:-true}" \
    --from-literal=SOAR_AUTO_EXECUTE="${SOAR_AUTO_EXECUTE:-true}" \
    --from-literal=SOAR_MIN_SEVERITY="medium" \
    --from-literal=SOAR_MIN_CONFIDENCE="0.50" \
    --from-literal=SOAR_NAMESPACE="financial" \
    --from-literal=SOAR_ALLOWED_CONTEXTS="${SOAR_ALLOWED_CONTEXTS:-ctx-aws,ctx-openstack}" \
    --from-literal=SOAR_API_TOKEN="${SOAR_API_TOKEN:-}" \
    --from-literal=SOAR_CASE_STORE_PATH="/data/cases.jsonl" \
    --from-literal=PORTAL_URL="${PORTAL_URL:-http://portal.ztlab.local}" \
    --from-literal=ADMIN_WEBHOOK_URL="${ADMIN_WEBHOOK_URL:-}"
}

create_core_banking_integrity_secret() {
  local secret_value
  if kaws get secret core-banking-integrity-secret -n financial >/dev/null 2>&1; then
    secret_value="$(kaws -n financial get secret core-banking-integrity-secret -o jsonpath='{.data.shared-secret}' | base64 -d)"
    log "core-banking-integrity-secret already exists on AWS"
  else
    secret_value="$(openssl rand -hex 32 2>/dev/null || date +%s%N)"
    kaws create secret generic core-banking-integrity-secret -n financial \
      --from-literal=shared-secret="$secret_value"
    ok "core-banking-integrity-secret created on AWS"
  fi

  if kos get secret core-banking-integrity-secret -n financial >/dev/null 2>&1; then
    log "core-banking-integrity-secret already exists on OpenStack"
  else
    kos create secret generic core-banking-integrity-secret -n financial \
      --from-literal=shared-secret="$secret_value"
    ok "core-banking-integrity-secret created on OpenStack"
  fi
}

create_financial_runtime_secrets() {
  if kaws get secret web-portal-secret -n financial >/dev/null 2>&1; then
    log "web-portal-secret already exists"
    return
  fi

  local admin_password session_secret
  admin_password="$(keycloak_admin_password)"
  session_secret="$(openssl rand -hex 32 2>/dev/null || date +%s%N)"
  kaws create secret generic web-portal-secret -n financial \
    --from-literal=admin-password="$admin_password" \
    --from-literal=session-secret="$session_secret"
  ok "web-portal-secret created"
}

provision_grafana_configmaps() {
  log "Provisioning Grafana ConfigMaps"
  kaws delete configmap grafana-datasources grafana-dashboard-provider grafana-dashboards grafana-alerting \
    -n plg-stack 2>/dev/null || true

  kaws create configmap grafana-datasources -n plg-stack \
    --from-file=loki-datasource.yml="$REPO_ROOT/plg-stack/grafana/datasources/loki-datasource.yml"
  kaws create configmap grafana-dashboard-provider -n plg-stack \
    --from-file=dashboard-provider.yml="$REPO_ROOT/plg-stack/grafana/dashboards/dashboard-provider.yml"
  kaws create configmap grafana-dashboards -n plg-stack \
    --from-file=zta-security-overview.json="$REPO_ROOT/plg-stack/grafana/dashboards/zta-security-overview.json" \
    --from-file=envoy-access-logs.json="$REPO_ROOT/plg-stack/grafana/dashboards/envoy-access-logs.json" \
    --from-file=opa-decision-log.json="$REPO_ROOT/plg-stack/grafana/dashboards/opa-decision-log.json" \
    --from-file=ai-siem-soar.json="$REPO_ROOT/plg-stack/grafana/dashboards/ai-siem-soar.json" \
    --from-file=threat-intel-feed.json="$REPO_ROOT/plg-stack/grafana/dashboards/threat-intel-feed.json"
  kaws create configmap grafana-alerting -n plg-stack \
    --from-file=brute-force-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/brute-force-alert.yml" \
    --from-file=fraud-gate-bypass-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/fraud-gate-bypass-alert.yml" \
    --from-file=large-response-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/large-response-alert.yml" \
    --from-file=lateral-movement-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/lateral-movement-alert.yml" \
    --from-file=ai-analyzer-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/ai-analyzer-alert.yml" \
    --from-file=soar-engine-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/soar-engine-alert.yml" \
    --from-file=notification-policy.yml="$REPO_ROOT/plg-stack/grafana/alerting/notification-policy.yml"
}

deploy_observability_response() {
  step "Step 6: PLG, AI/SOAR, Prometheus"

  create_keycloak_admin_secret
  create_ai_secret

  kaws apply -f "$REPO_ROOT/k8s/plg-stack/loki-configmap.yaml"
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/loki.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack loki 180s

  provision_grafana_configmaps
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/grafana.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack grafana 180s

  kaws apply -f "$REPO_ROOT/k8s/plg-stack/promtail-daemonset.yaml"
  wait_daemonset "$AWS_CONTEXT" plg-stack promtail 180s

  # Ensure socat relay is persistent on AWS worker (OpenStack Promtail → Loki cross-cluster)
  LOKI_CIP=$(kubectl --context "$AWS_CONTEXT" -n plg-stack get svc loki -o jsonpath='{.spec.clusterIP}')
  ssh -o StrictHostKeyChecking=no -i ~/.ssh/ztlab-key \
      -J ubuntu@54.254.252.106 ubuntu@10.10.1.11 \
      "sudo tee /etc/systemd/system/loki-relay.service > /dev/null << 'EOF'
[Unit]
Description=Loki Relay (OpenStack cross-cluster)
After=network.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:31100,fork,reuseaddr TCP:${LOKI_CIP}:3100
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now loki-relay" 2>/dev/null || warn "socat relay setup skipped (SSH unavailable)"

  kos apply -f "$REPO_ROOT/k8s/plg-stack/promtail-daemonset.yaml"
  kos set env daemonset/promtail -n plg-stack LOKI_PUSH_URL=http://10.10.1.11:31100/loki/api/v1/push CLOUD_PROVIDER=openstack
  wait_daemonset "$OS_CONTEXT" plg-stack promtail 180s

  kaws apply -f "$REPO_ROOT/k8s/rbac/soar-rbac.yaml"
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/security-scorer.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack security-scorer 120s
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/ai-soar.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack ai-analyzer 180s
  wait_deployment "$AWS_CONTEXT" plg-stack soar-engine 180s

  kaws apply -f "$REPO_ROOT/k8s/monitoring/prometheus.yaml"
  wait_deployment "$AWS_CONTEXT" monitoring prometheus 180s

  ok "PLG, AI/SOAR, and Prometheus ready on AWS"
}

apply_policies_and_ingress() {
  step "Step 7: Network policies and ingress"

  kaws apply -f "$REPO_ROOT/k8s/financial/network-policies/aws-allow-list.yaml"
  kos apply -f "$REPO_ROOT/k8s/financial/network-policies/os-allow-list.yaml"
  kaws apply -f "$REPO_ROOT/k8s/ingress.yaml"

  ok "Network policies applied on both clusters; ingress applied on AWS"
}

verify_final() {
  step "Step 8: Final status"

  log "AWS non-system pods"
  kaws get pods -A | grep -v kube-system || true

  log "OpenStack non-system pods"
  kos get pods -A | grep -v kube-system || true

  ok "Full multi-cloud deploy flow completed"
}

main() {
  step "Step 0: Prerequisites"
  require_cmd kubectl
  require_cmd bash
  require_cmd grep

  if [[ "$SKIP_TUNNEL" == false ]]; then
    "$REPO_ROOT/scripts/k8s-tunnel.sh" up all
  fi

  verify_context "$AWS_CONTEXT"
  verify_context "$OS_CONTEXT"

  apply_namespaces
  sync_images
  deploy_security_stack
  deploy_financial_infra
  deploy_financial_services
  deploy_observability_response
  apply_policies_and_ingress
  verify_final
}

main "$@"
