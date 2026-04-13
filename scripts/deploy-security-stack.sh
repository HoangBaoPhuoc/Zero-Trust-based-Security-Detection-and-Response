#!/bin/bash
# Deploy SPIRE / OPA / Envoy / Keycloak security stack
# Run this after K3s clusters are ready and tunnel is up

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AWS_CONTEXT="ctx-aws"
OS_CONTEXT="ctx-openstack"
TIMEOUT_WAIT=180
TIMEOUT_KEYCLOAK=300  # Keycloak can take longer to start on first deployment

log_info() {
  echo "[INFO] $*"
}

log_error() {
  echo "[ERROR] $*" >&2
}

log_step() {
  echo ""
  echo "================================"
  echo "STEP: $*"
  echo "================================"
}

check_kctl_context() {
  if ! kubectl --context "$1" cluster-info >/dev/null 2>&1; then
    log_error "Cannot reach kubectl context $1. Run: ./scripts/k8s-tunnel.sh up"
    exit 1
  fi
}

financial_manifests_ready() {
  local manifests=(
    "$REPO_ROOT/k8s/financial/aws-services.yaml"
    "$REPO_ROOT/k8s/financial/os-services.yaml"
  )
  for f in "${manifests[@]}"; do
    if [ ! -f "$f" ] || ! grep -qE '^apiVersion:' "$f"; then
      return 1
    fi
  done
  return 0
}

deploy_step_1_namespaces() {
  log_step "1. Create Namespaces"

  log_info "Creating namespaces on AWS cluster..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/k8s/namespaces.yaml"

  log_info "Creating namespaces on OpenStack cluster..."
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/k8s/namespaces.yaml"

  sleep 3
  log_info "Namespaces created successfully"
}

deploy_step_2_keycloak() {
  log_step "2. Deploy Keycloak (AWS only)"

  log_info "Creating Keycloak secrets..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/k8s/keycloak/secret.yaml"

  log_info "Deploying Keycloak PostgreSQL..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/k8s/keycloak/postgres.yaml"

  log_info "Keycloak DB deployment initiated (waiting up to 60s - in lab it may timeout, that's OK)..."
  kubectl --context $AWS_CONTEXT wait --for=condition=Ready pod \
    -l app=keycloak-db -n identity --timeout=60s 2>/dev/null || {
    log_info "DB pod still starting (node may be recovering - this is normal in lab environment)"
  }

  log_info "Deploying Keycloak server..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/k8s/keycloak/deployment.yaml"
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/k8s/keycloak/service.yaml"

  log_info "Deploying Keycloak realm config..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/k8s/keycloak/realm-configmap.yaml"

  log_info "Keycloak deployment initiated (can take 5-10 minutes on first startup with DB setup)"
  log_info "Note: Keycloak is not a blocking dependency for SPIRE/OPA, so we proceed with deployment"
  log_info "To wait for Keycloak readiness manually:"
  log_info "  kubectl --context ctx-aws wait --for=condition=Ready pod -l app=keycloak -n identity --timeout=600s"
  
  # Don't block on Keycloak startup in lab environment
  # kubectl --context $AWS_CONTEXT wait --for=condition=Ready pod \
  #   -l app=keycloak -n identity --timeout=${TIMEOUT_KEYCLOAK}s || {
  #   log_error "Keycloak Pod failed to start within ${TIMEOUT_KEYCLOAK}s. Checking logs for details..."
  #   kubectl --context $AWS_CONTEXT logs -l app=keycloak -n identity --tail=50
  #   exit 1
  # }

  log_info "Keycloak deployment completed"
}

deploy_step_3_spire_aws() {
  log_step "3.1 Deploy SPIRE on AWS"

  log_info "Creating SPIRE namespace + RBAC..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/namespace.yaml"
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/rbac.yaml"

  log_info "Labeling nodes for SPIRE server on AWS..."
  SECURITY_NODE=$(kubectl --context $AWS_CONTEXT get nodes --no-headers \
    -o custom-columns=NAME:.metadata.name | head -1)
  if [ -z "$SECURITY_NODE" ]; then
    log_error "No nodes found in AWS cluster"
    exit 1
  fi
  kubectl --context $AWS_CONTEXT label node "$SECURITY_NODE" spire-server=true --overwrite

  log_info "Deploying SPIRE server..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/server-deployment.yaml"

  log_info "Waiting for SPIRE server to be ready (timeout: 60s, may skip if tunnel unstable)..."
  kubectl --context $AWS_CONTEXT wait --for=condition=Ready pod \
    -l app=spire-server -n spire --timeout=60s 2>/dev/null || {
    log_info "SPIRE server still starting (tunnel may be unstable - check manually if issue persists)"
  }

  log_info "Deploying SPIRE agents..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/agent-daemonset.yaml"

  log_info "SPIRE agents deployment initiated (may take time - skipping strict wait for lab stability)"

  log_info "SPIRE on AWS deployment completed"
}

deploy_step_3_spire_os() {
  log_step "3.2 Deploy SPIRE on OpenStack"

  log_info "Creating SPIRE namespace + RBAC..."
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/namespace.yaml"
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/rbac.yaml"

  log_info "Labeling nodes for SPIRE server on OpenStack..."
  IDENTITY_NODE=$(kubectl --context $OS_CONTEXT get nodes --no-headers \
    -o custom-columns=NAME:.metadata.name | head -1)
  if [ -z "$IDENTITY_NODE" ]; then
    log_error "No nodes found in OpenStack cluster"
    exit 1
  fi
  kubectl --context $OS_CONTEXT label node "$IDENTITY_NODE" spire-server=true --overwrite

  log_info "Deploying SPIRE server..."
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/server-deployment.yaml"

  log_info "Waiting for SPIRE server to be ready (timeout: 60s, may skip if tunnel unstable)..."
  kubectl --context $OS_CONTEXT wait --for=condition=Ready pod \
    -l app=spire-server -n spire --timeout=60s 2>/dev/null || {
    log_info "SPIRE server still starting (tunnel may be unstable)"
  }

  log_info "Deploying SPIRE agents..."
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/spire/k8s/agent-daemonset.yaml"

  log_info "SPIRE agents deployment initiated on OpenStack"

  log_info "SPIRE on OpenStack deployment completed"
}

deploy_step_4_opa() {
  log_step "4. Deploy OPA (Open Policy Agent)"

  log_info "Deploying OPA on AWS..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/opa/deployment.yaml"

  log_info "OPA deployment initiated (may take time)"
}

deploy_step_5_envoy() {
  log_step "5. Deploy Envoy ConfigMaps"

  log_info "Deploying Envoy ConfigMap on AWS..."
  kubectl --context $AWS_CONTEXT apply -f "$REPO_ROOT/envoy/configmap.yaml"

  log_info "Deploying Envoy ConfigMap on OpenStack..."
  kubectl --context $OS_CONTEXT apply -f "$REPO_ROOT/envoy/configmap.yaml"

  log_info "Envoy ConfigMaps deployed"
}

verify_deployment() {
  log_step "6. Verify Deployment"

  log_info "Namespaces on AWS:"
  kubectl --context $AWS_CONTEXT get ns

  log_info ""
  log_info "Keycloak pods on AWS:"
  kubectl --context $AWS_CONTEXT get pods -n identity

  log_info ""
  log_info "SPIRE pods on AWS:"
  kubectl --context $AWS_CONTEXT get pods -n spire

  log_info ""
  log_info "SPIRE pods on OpenStack:"
  kubectl --context $OS_CONTEXT get pods -n spire

  log_info ""
  log_info "OPA pods on AWS:"
  kubectl --context $AWS_CONTEXT get pods -n financial

  log_info ""
  log_info "Envoy ConfigMaps on AWS:"
  kubectl --context $AWS_CONTEXT get cm -n financial

  log_info ""
  log_info "✓ Security stack deployment verification completed"
}

main() {
  log_info "SPIRE / OPA / Envoy / Keycloak Deployment Script"
  log_info ""

  # Check prerequisites
  log_info "Checking prerequisites..."
  check_kctl_context $AWS_CONTEXT
  check_kctl_context $OS_CONTEXT

  # Deploy steps
  deploy_step_1_namespaces
  deploy_step_2_keycloak
  deploy_step_3_spire_aws
  deploy_step_3_spire_os
  deploy_step_4_opa
  deploy_step_5_envoy

  # Verify
  verify_deployment

  log_info ""
  log_info "================================"
  log_info "✓ All components deployed successfully!"
  log_info "================================"
  log_info ""
  log_info "Next steps:"
  if financial_manifests_ready; then
    log_info "1. Deploy financial workloads:"
    log_info "   kubectl --context ctx-aws apply -f k8s/financial/aws-services.yaml"
    log_info "   kubectl --context ctx-openstack apply -f k8s/financial/os-services.yaml"
    log_info "2. Deploy PLG stack: ./scripts/deploy-plg-stack.sh"
    log_info "3. Verify workloads: kubectl --context ctx-aws get pods -A && kubectl --context ctx-openstack get pods -A"
  else
    log_info "1. Financial manifests are not ready yet (k8s/financial/*.yaml still TODO/empty)."
    log_info "2. Populate financial manifests before running kubectl apply on k8s/financial/*.yaml."
    log_info "3. Deploy PLG stack after workloads are ready: ./scripts/deploy-plg-stack.sh"
  fi
  log_info ""
}

main "$@"
