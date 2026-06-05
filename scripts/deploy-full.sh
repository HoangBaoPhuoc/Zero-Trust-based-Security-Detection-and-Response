#!/usr/bin/env bash
# deploy-full.sh — Deploy toàn bộ ZTLab system từ đầu trên AWS K3s
#
# Usage:
#   ./scripts/deploy-full.sh                    # Full deploy
#   ./scripts/deploy-full.sh --skip-images      # Skip image rebuild
#   ./scripts/deploy-full.sh --only-infra       # Only deploy infra (DBs, Keycloak)
#   ./scripts/deploy-full.sh --only-apps        # Only deploy application layer
#
# Prerequisites:
#   - kubectl configured (or SSH tunnel active, see scripts/k8s-tunnel.sh)
#   - Docker available (for image build)
#   - Python3 available
#   - SSH key at ~/.ssh/zta-siem-soar-key

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ─── Color output ─────────────────────────────────────────────────────────────
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' NC='\033[0m'
log()  { echo -e "${BLUE}[DEPLOY]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }
step() { echo -e "\n${BLUE}══════════════════════════════════════════${NC}"; echo -e "${BLUE} $*${NC}"; echo -e "${BLUE}══════════════════════════════════════════${NC}"; }

# ─── Options ──────────────────────────────────────────────────────────────────
SKIP_IMAGES=false
SKIP_TUNNEL=false
ONLY_INFRA=false
ONLY_APPS=false
for arg in "$@"; do
  case "$arg" in
    --skip-images) SKIP_IMAGES=true ;;
    --skip-tunnel) SKIP_TUNNEL=true ;;
    --only-infra)  ONLY_INFRA=true ;;
    --only-apps)   ONLY_APPS=true ;;
    --help|-h)
      echo "Usage: $0 [--skip-images] [--skip-tunnel] [--only-infra] [--only-apps]"
      exit 0 ;;
  esac
done

# ─── Configuration ────────────────────────────────────────────────────────────
SSH_KEY="${SSH_KEY:-$HOME/.ssh/zta-siem-soar-key}"
BASTION_IP="${BASTION_IP:-54.254.145.86}"
K3S_MASTER_IP="${K3S_MASTER_IP:-10.10.1.10}"
K3S_LOCAL_PORT="${K3S_LOCAL_PORT:-6444}"
KUBECONFIG_TUNNEL="$HOME/.kube/ztlab/aws-tunnel.yaml"
KUBECONFIG_DIRECT="$HOME/.kube/ztlab/aws.yaml"

IMAGE_TAG="${IMAGE_TAG:-1.0.0}"
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-ZTALab2026!}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-ztlab-admin-2026}"

# ─── Step 0: Prerequisites ────────────────────────────────────────────────────
step "Step 0: Checking prerequisites"

command -v kubectl >/dev/null 2>&1 || fail "kubectl not found"
command -v python3 >/dev/null 2>&1 || fail "python3 not found"
ok "kubectl, python3 found"

# ─── Step 1: K8s connectivity ─────────────────────────────────────────────────
step "Step 1: Establishing K8s connectivity"

setup_tunnel() {
  if pgrep -f "$K3S_LOCAL_PORT:$K3S_MASTER_IP" >/dev/null 2>&1; then
    log "SSH tunnel already running"
    return
  fi
  log "Starting SSH tunnel to K3s API ($K3S_MASTER_IP:6443 → localhost:$K3S_LOCAL_PORT)..."
  ssh -f -N \
    -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o ServerAliveInterval=30 \
    -o ExitOnForwardFailure=yes \
    -L "${K3S_LOCAL_PORT}:${K3S_MASTER_IP}:6443" \
    -J "ubuntu@${BASTION_IP}" \
    "ubuntu@${K3S_MASTER_IP}" || fail "Failed to start SSH tunnel"
  sleep 2
}

if [[ "$SKIP_TUNNEL" == false ]]; then
  setup_tunnel
fi

if [[ -f "$KUBECONFIG_TUNNEL" ]]; then
  export KUBECONFIG="$KUBECONFIG_TUNNEL"
elif [[ -f "$KUBECONFIG_DIRECT" ]]; then
  export KUBECONFIG="$KUBECONFIG_DIRECT"
fi

kubectl get nodes --request-timeout=10s >/dev/null 2>&1 || fail "Cannot connect to K8s API. Check tunnel."
ok "Connected to K8s cluster ($(kubectl get nodes --no-headers | wc -l | tr -d ' ') nodes)"

# ─── Step 2: Build & sync images ──────────────────────────────────────────────
if [[ "$SKIP_IMAGES" == false && "$ONLY_INFRA" == false ]]; then
  step "Step 2: Build & sync Docker images to K3s nodes"
  if command -v docker >/dev/null 2>&1; then
    bash "$REPO_ROOT/scripts/sync-financial-images.sh" --skip-push-openstack 2>&1 | tail -20 \
      || warn "Image sync had errors — continuing (images may already exist on nodes)"
    ok "Images synced"
  else
    warn "Docker not available — skipping image build (assuming images exist on nodes)"
  fi
else
  log "Skipping image build (--skip-images or --only-infra)"
fi

# ─── Step 3: Namespaces ───────────────────────────────────────────────────────
step "Step 3: Apply namespaces"
kubectl apply -f "$REPO_ROOT/k8s/namespaces.yaml" 2>&1
# Ensure plg-stack namespace exists (not in namespaces.yaml)
kubectl create namespace plg-stack --dry-run=client -o yaml | kubectl apply -f - 2>&1
ok "Namespaces ready"

# ─── Step 4: Secrets ─────────────────────────────────────────────────────────
step "Step 4: Apply secrets"

# Keycloak secret
kubectl apply -f "$REPO_ROOT/k8s/keycloak/secret.yaml" 2>&1

# AI secrets (only create if missing)
if ! kubectl get secret ai-secrets -n plg-stack >/dev/null 2>&1; then
  GEMINI_KEY="${GEMINI_API_KEY:-}"
  OPENAI_KEY="${OPENAI_API_KEY:-}"
  AI_PROVIDER="${AI_PROVIDER:-gemini}"
  kubectl create secret generic ai-secrets -n plg-stack \
    --from-literal=AI_PROVIDER="$AI_PROVIDER" \
    --from-literal=GEMINI_API_KEY="$GEMINI_KEY" \
    --from-literal=GEMINI_MODEL="gemini-2.5-flash" \
    --from-literal=OPENAI_API_KEY="$OPENAI_KEY" \
    --from-literal=OPENAI_MODEL="gpt-4o-mini" \
    --from-literal=AI_ANALYZER_POLL_ENABLED="true" \
    --from-literal=AI_ANALYZER_POLL_INTERVAL_SECONDS="120" \
    --from-literal=AI_ANALYZER_LOOKBACK_SECONDS="300" \
    --from-literal=AI_ANALYZER_MAX_LOGS_PER_BATCH="10" \
    --from-literal=AI_ANALYZER_MIN_ALERT_SEVERITY="medium" \
    --from-literal=SOAR_DRY_RUN="true" \
    --from-literal=SOAR_AUTO_EXECUTE="true" \
    --from-literal=SOAR_MIN_SEVERITY="medium" \
    --from-literal=SOAR_MIN_CONFIDENCE="0.50" \
    --from-literal=SOAR_NAMESPACE="financial" \
    --from-literal=SOAR_ALLOWED_CONTEXTS="ctx-aws,ctx-openstack" \
    --from-literal=SOAR_API_TOKEN="" \
    --from-literal=SOAR_CASE_STORE_PATH="/data/cases.jsonl" \
    2>&1
  ok "Created ai-secrets"
else
  log "ai-secrets already exists — skipping"
fi

ok "Secrets ready"

# ─── Step 5: Databases ────────────────────────────────────────────────────────
if [[ "$ONLY_APPS" == false ]]; then
  step "Step 5: Deploy databases (PostgreSQL + Redis)"
  kubectl apply -f "$REPO_ROOT/k8s/financial/postgres-accounts.yaml" 2>&1
  kubectl apply -f "$REPO_ROOT/k8s/financial/postgres-txn.yaml" 2>&1
  kubectl apply -f "$REPO_ROOT/k8s/financial/redis.yaml" 2>&1

  log "Waiting for databases to be ready..."
  kubectl rollout status deployment/postgres-accounts -n financial --timeout=120s 2>&1
  kubectl rollout status deployment/postgres-txn -n financial --timeout=120s 2>&1
  kubectl rollout status deployment/redis -n financial --timeout=90s 2>&1
  ok "Databases ready"

  # ─── Step 6: Keycloak ──────────────────────────────────────────────────────
  step "Step 6: Deploy Keycloak"
  kubectl apply -f "$REPO_ROOT/k8s/keycloak/postgres.yaml" 2>&1
  kubectl rollout status deployment/keycloak-db -n identity --timeout=120s 2>&1
  kubectl apply -f "$REPO_ROOT/k8s/keycloak/realm-configmap.yaml" 2>&1
  kubectl apply -f "$REPO_ROOT/k8s/keycloak/deployment.yaml" 2>&1
  kubectl apply -f "$REPO_ROOT/k8s/keycloak/service.yaml" 2>&1

  log "Waiting for Keycloak (may take ~60s for realm import)..."
  kubectl rollout status deployment/keycloak -n identity --timeout=180s 2>&1
  ok "Keycloak ready"
fi

# ─── Step 7: Financial microservices ─────────────────────────────────────────
step "Step 7: Deploy financial microservices"
kubectl apply -f "$REPO_ROOT/k8s/financial/services.yaml" 2>&1
kubectl apply -f "$REPO_ROOT/k8s/financial/aws-services.yaml" 2>&1

log "Waiting for financial services..."
for svc in api-gateway payment-service fraud-detection core-banking account-service transaction-service notification-service; do
  kubectl rollout status deployment/$svc -n financial --timeout=120s 2>&1 | tail -1
done
ok "Financial services ready"

# ─── Step 8: PLG Stack ───────────────────────────────────────────────────────
step "Step 8: Deploy PLG Stack (Loki + Grafana + Promtail)"

# Loki ConfigMap
kubectl apply -f "$REPO_ROOT/k8s/plg-stack/loki-configmap.yaml" 2>&1
kubectl apply -f "$REPO_ROOT/k8s/plg-stack/namespace.yaml" 2>/dev/null || true

# Loki
kubectl apply -f "$REPO_ROOT/k8s/plg-stack/loki.yaml" 2>&1
kubectl rollout status deployment/loki -n plg-stack --timeout=120s 2>&1

# Grafana ConfigMaps (recreate from provisioning files)
log "Provisioning Grafana ConfigMaps..."
kubectl delete configmap grafana-datasources grafana-dashboard-provider grafana-dashboards grafana-alerting -n plg-stack 2>/dev/null || true
kubectl create configmap grafana-datasources -n plg-stack \
  --from-file=loki-datasource.yml="$REPO_ROOT/plg-stack/grafana/datasources/loki-datasource.yml" 2>&1
kubectl create configmap grafana-dashboard-provider -n plg-stack \
  --from-file=dashboard-provider.yml="$REPO_ROOT/plg-stack/grafana/dashboards/dashboard-provider.yml" 2>&1
kubectl create configmap grafana-dashboards -n plg-stack \
  --from-file=zta-security-overview.json="$REPO_ROOT/plg-stack/grafana/dashboards/zta-security-overview.json" \
  --from-file=envoy-access-logs.json="$REPO_ROOT/plg-stack/grafana/dashboards/envoy-access-logs.json" \
  --from-file=opa-decision-log.json="$REPO_ROOT/plg-stack/grafana/dashboards/opa-decision-log.json" \
  --from-file=ai-siem-soar.json="$REPO_ROOT/plg-stack/grafana/dashboards/ai-siem-soar.json" 2>&1
kubectl create configmap grafana-alerting -n plg-stack \
  --from-file=brute-force-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/brute-force-alert.yml" \
  --from-file=fraud-gate-bypass-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/fraud-gate-bypass-alert.yml" \
  --from-file=large-response-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/large-response-alert.yml" \
  --from-file=lateral-movement-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/lateral-movement-alert.yml" \
  --from-file=ai-analyzer-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/ai-analyzer-alert.yml" \
  --from-file=soar-engine-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/soar-engine-alert.yml" 2>&1

# Grafana
kubectl apply -f "$REPO_ROOT/k8s/plg-stack/grafana.yaml" 2>&1
kubectl rollout status deployment/grafana -n plg-stack --timeout=120s 2>&1

# Promtail DaemonSet
kubectl apply -f "$REPO_ROOT/k8s/plg-stack/promtail-daemonset.yaml" 2>&1
log "Waiting for Promtail DaemonSet..."
kubectl rollout status daemonset/promtail -n plg-stack --timeout=120s 2>&1

ok "PLG Stack ready"

# ─── Step 9: AI Analyzer + SOAR Engine ───────────────────────────────────────
step "Step 9: Deploy AI Analyzer + SOAR Engine"
kubectl apply -f "$REPO_ROOT/k8s/rbac/soar-rbac.yaml" 2>&1
kubectl apply -f "$REPO_ROOT/k8s/plg-stack/ai-soar.yaml" 2>&1

# Patch soar-engine to use RBAC ServiceAccount
kubectl patch deployment soar-engine -n plg-stack \
  --type='json' \
  -p='[{"op":"add","path":"/spec/template/spec/serviceAccountName","value":"soar-engine"}]' \
  2>/dev/null || true

kubectl rollout status deployment/ai-analyzer -n plg-stack --timeout=120s 2>&1
kubectl rollout status deployment/soar-engine -n plg-stack --timeout=120s 2>&1
ok "AI Analyzer + SOAR Engine ready"

# ─── Step 10: Monitoring (Prometheus) ────────────────────────────────────────
step "Step 10: Deploy Prometheus"
kubectl apply -f "$REPO_ROOT/k8s/monitoring/prometheus.yaml" 2>&1
kubectl rollout status deployment/prometheus -n monitoring --timeout=120s 2>&1
ok "Prometheus ready"

# ─── Step 11: Network Policies ───────────────────────────────────────────────
step "Step 11: Apply Network Policies"
kubectl apply -f "$REPO_ROOT/k8s/financial/network-policies/aws-allow-list.yaml" 2>&1
ok "Network policies applied"

# ─── Step 12: Ingress (Traefik IngressRoutes) ────────────────────────────────
step "Step 12: Apply Ingress routes"
kubectl apply -f "$REPO_ROOT/k8s/ingress.yaml" 2>&1
ok "Ingress routes applied"

# ─── Step 13: Create Keycloak test users ─────────────────────────────────────
step "Step 13: Create Keycloak test users"

wait_for_keycloak() {
  local max_attempts=30
  local attempt=0
  log "Waiting for Keycloak to be ready for API calls..."
  while [[ $attempt -lt $max_attempts ]]; do
    if kubectl exec -n identity deploy/keycloak -- \
        curl -s -o /dev/null -w "%{http_code}" \
        "http://localhost:8080/realms/ztlab/.well-known/openid-configuration" 2>/dev/null \
        | grep -q "200"; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 5
  done
  return 1
}

create_keycloak_user() {
  local kc_url="$1" admin_token="$2" username="$3" password="$4" role="$5"

  HTTP=$(curl -s -w "%{http_code}" -o /tmp/kc_create.json \
    -X POST "$kc_url/admin/realms/ztlab/users" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$username\",\"enabled\":true,\"email\":\"$username@ztlab.local\",\"credentials\":[{\"type\":\"password\",\"value\":\"$password\",\"temporary\":false}]}")

  [[ "$HTTP" == "409" ]] && { log "User $username already exists"; return 0; }
  [[ "$HTTP" != "201" ]] && { warn "Failed to create $username: HTTP $HTTP"; return 1; }

  USER_ID=$(curl -s "$kc_url/admin/realms/ztlab/users?username=$username" \
    -H "Authorization: Bearer $admin_token" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['id'] if d else '')")

  ROLE_OBJ=$(curl -s "$kc_url/admin/realms/ztlab/roles/$role" \
    -H "Authorization: Bearer $admin_token")

  curl -s -o /dev/null -X POST \
    "$kc_url/admin/realms/ztlab/users/$USER_ID/role-mappings/realm" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d "[$ROLE_OBJ]"

  ok "Created user: $username (role=$role)"
}

# Port-forward Keycloak temporarily
kubectl port-forward -n identity svc/keycloak 18080:8080 &
KC_PF_PID=$!
sleep 3

KC_URL="http://localhost:18080"
ADMIN_TOKEN=$(curl -s -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=${KEYCLOAK_ADMIN_PASSWORD}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

if [[ -n "$ADMIN_TOKEN" ]]; then
  create_keycloak_user "$KC_URL" "$ADMIN_TOKEN" "testuser01" "Test@1234" "financial-write"
  create_keycloak_user "$KC_URL" "$ADMIN_TOKEN" "testuser02" "Test@1234" "financial-read"
  create_keycloak_user "$KC_URL" "$ADMIN_TOKEN" "security-analyst" "ZTLab@2026" "security-analyst"
  create_keycloak_user "$KC_URL" "$ADMIN_TOKEN" "attacker" "Attack@1234" "financial-read"
else
  warn "Could not get Keycloak admin token — skipping user creation"
fi
kill $KC_PF_PID 2>/dev/null || true

# ─── Step 14: Final health check ─────────────────────────────────────────────
step "Step 14: Health check"

check_pod() {
  local ns="$1" label="$2" name="$3"
  if kubectl get pods -n "$ns" -l "app=$label" --no-headers 2>/dev/null | grep -q "Running"; then
    ok "$name"
  else
    warn "$name NOT running"
  fi
}

check_pod financial api-gateway         "api-gateway"
check_pod financial payment-service     "payment-service"
check_pod financial fraud-detection     "fraud-detection"
check_pod financial core-banking        "core-banking"
check_pod financial account-service     "account-service"
check_pod financial transaction-service "transaction-service"
check_pod financial notification-service "notification-service"
check_pod identity   keycloak           "Keycloak"
check_pod plg-stack  loki               "Loki"
check_pod plg-stack  grafana            "Grafana"
check_pod plg-stack  ai-analyzer        "AI Analyzer"
check_pod plg-stack  soar-engine        "SOAR Engine"
check_pod monitoring prometheus         "Prometheus"

# Quick functional test — generate JWT and call api-gateway
TOKEN=$(bash "$REPO_ROOT/scripts/gen-dev-token.sh" testuser01 financial-write 2>/dev/null | head -1)
RESPONSE=$(kubectl exec -n financial deploy/api-gateway -- python3 -c "
import urllib.request, json
req = urllib.request.Request(
    'http://localhost:8080/payments',
    data=json.dumps({'from_account':'acc001','to_account':'acc002','amount':50000,'currency':'VND'}).encode(),
    headers={'Content-Type':'application/json','Authorization':'Bearer $TOKEN'},
    method='POST'
)
try:
    r = urllib.request.urlopen(req, timeout=10)
    d=json.loads(r.read().decode())
    print(d.get('status','?'))
except urllib.error.HTTPError as e:
    print('HTTP', e.code, e.read().decode()[:100])
" 2>/dev/null)

if [[ "$RESPONSE" == "completed" ]]; then
  ok "End-to-end payment flow: PASS (JWT → api-gateway → payment → fraud → core-banking)"
else
  warn "End-to-end payment flow: $RESPONSE"
fi

# ─── Done ─────────────────────────────────────────────────────────────────────
step "DEPLOYMENT COMPLETE"

BASTION_IP_DISPLAY="${BASTION_IP:-54.254.145.86}"
K3S_MASTER_DISPLAY="${K3S_MASTER_IP:-10.10.1.10}"

echo -e "
${GREEN}══════════════════════════════════════════════════════════════${NC}
${GREEN}  ZTLab System is running!${NC}
${GREEN}══════════════════════════════════════════════════════════════${NC}

  Access via SSH tunnel:
  ${YELLOW}ssh -N -i ~/.ssh/zta-siem-soar-key \\
    -L 8080:${K3S_MASTER_DISPLAY}:80 \\
    -L 9090:${K3S_MASTER_DISPLAY}:9090 \\
    -J ubuntu@${BASTION_IP_DISPLAY} ubuntu@${K3S_MASTER_DISPLAY}${NC}

  Then add to /etc/hosts:
  ${YELLOW}127.0.0.1  api.ztlab.local grafana.ztlab.local keycloak.ztlab.local${NC}
  ${YELLOW}127.0.0.1  ai.ztlab.local soar.ztlab.local prometheus.ztlab.local${NC}

  Service URLs (after tunnel):
    Grafana:    http://grafana.ztlab.local:8080   (admin / ZTALab2026!)
    Keycloak:   http://keycloak.ztlab.local:8080  (admin / ${KEYCLOAK_ADMIN_PASSWORD})
    API GW:     http://api.ztlab.local:8080/payments
    Prometheus: http://prometheus.ztlab.local:8080
    AI Analyzer: http://ai.ztlab.local:8080/health
    SOAR Engine: http://soar.ztlab.local:8080/cases

  Test payment:
  ${YELLOW}TOKEN=\$(./scripts/gen-dev-token.sh testuser01 financial-write | head -1)
  curl -H \"Authorization: Bearer \$TOKEN\" \\
       -H \"Content-Type: application/json\" \\
       -d '{\"from_account\":\"acc001\",\"to_account\":\"acc002\",\"amount\":100000}' \\
       -X POST http://api.ztlab.local:8080/payments${NC}

  Run attack demo:
  ${YELLOW}./scripts/demo-ai-soar.sh${NC}
${GREEN}══════════════════════════════════════════════════════════════${NC}
"
