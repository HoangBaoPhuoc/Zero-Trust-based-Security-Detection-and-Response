#!/usr/bin/env bash
# Deploy ứng dụng mục tiêu OWASP crAPI + wiring Zero-Trust, thay cho
# deploy_financial_infra + deploy_financial_services của deploy-app.sh.
#
# Gọi từ deploy-app.sh main() (sau deploy_istio + deploy_security_stack), HOẶC
# chạy độc lập khi hạ tầng + SPIRE/OPA/Istio/Keycloak đã sẵn sàng:
#   AWS_CONTEXT=ctx-aws OS_CONTEXT=ctx-openstack bash scripts/deploy-crapi.sh
#
# Split hybrid (KE-HOACH-CRAPI.md, GATE 0 DB-2):
#   OpenStack: crapi-identity + postgresdb (1 DB chung) + opa
#   AWS:       bff + crapi-web/community/workshop + mongodb + mailhog + redis + opa
#
# PHASE hiện tại được điều khiển bằng biến CRAPI_PHASE (1..7). Mặc định chạy
# hết những gì đã có file. Idempotent.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"
CRAPI_DIR="$REPO_ROOT/k8s/crapi"
CRAPI_KEYS="$REPO_ROOT/deploy/vendor/crapi-keys/jwks.json"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[DEPLOY-CRAPI]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC} $*"; exit 1; }
step() { echo -e "\n${BLUE}══════ $* ══════${NC}"; }

kaws() { kubectl --context "$AWS_CONTEXT" "$@"; }
kos()  { kubectl --context "$OS_CONTEXT" "$@"; }

wait_rollout() { # ctx ns kind/name timeout
  kubectl --context "$1" -n "$2" rollout status "$3" --timeout="${4:-240s}" || warn "rollout $3 ($1) chưa xong trong ${4:-240s} — tiếp tục"
}

verify_contexts() {
  for ctx in "$AWS_CONTEXT" "$OS_CONTEXT"; do
    kubectl --context "$ctx" get nodes --request-timeout=10s >/dev/null 2>&1 \
      || fail "Không kết nối được context $ctx — chạy ./scripts/k8s-tunnel.sh up all"
    ok "Connected $ctx"
  done
}

create_secrets() {
  step "Secrets (cả 2 cluster)"
  [[ -f "$CRAPI_KEYS" ]] || fail "Thiếu $CRAPI_KEYS (khoá JWT crAPI upstream)"
  for k in kaws kos; do
    $k create namespace crapi --dry-run=client -o yaml | $k apply -f - >/dev/null
    $k -n crapi create secret generic crapi-jwt-key \
      --from-file=jwks.json="$CRAPI_KEYS" \
      --dry-run=client -o yaml | $k apply -f -
  done
  ok "crapi-jwt-key created"
}

apply_namespace_and_config() {
  step "Namespace + ConfigMaps"
  kaws apply -f "$CRAPI_DIR/namespace.yaml"
  kos  apply -f "$CRAPI_DIR/namespace.yaml"
  kaws label namespace crapi istio-injection=enabled --overwrite
  kos  label namespace crapi istio-injection=enabled --overwrite
  kaws apply -f "$CRAPI_DIR/configmaps.yaml"
  kos  apply -f "$CRAPI_DIR/configmaps.yaml"
  ok "namespace + configmaps"
}

deploy_databases() {
  step "Databases — Postgres (OpenStack) + Mongo/Redis (AWS)"
  kos  apply -f "$CRAPI_DIR/databases-os.yaml"
  kaws apply -f "$CRAPI_DIR/databases-aws.yaml"
  wait_rollout "$OS_CONTEXT"  crapi statefulset/postgresdb 300s
  wait_rollout "$AWS_CONTEXT" crapi statefulset/mongodb 300s
  wait_rollout "$AWS_CONTEXT" crapi deployment/redis 180s
  ok "databases"
}

deploy_crapi_workloads() {
  step "crAPI workloads — identity (OpenStack) + web/community/workshop + mailhog (AWS)"
  kaws apply -f "$CRAPI_DIR/mailhog.yaml"
  kos  apply -f "$CRAPI_DIR/os-workloads.yaml"
  kaws apply -f "$CRAPI_DIR/aws-workloads.yaml"
  kaws apply -f "$CRAPI_DIR/cross-cloud-aws.yaml"
  kos  apply -f "$CRAPI_DIR/cross-cloud-os.yaml"
  wait_rollout "$AWS_CONTEXT" crapi deployment/mailhog 180s
  wait_rollout "$OS_CONTEXT"  crapi deployment/crapi-identity 300s
  for d in crapi-web crapi-community crapi-workshop; do
    wait_rollout "$AWS_CONTEXT" crapi "deployment/$d" 300s
  done
  ok "crAPI workloads"
}

deploy_bff() {
  [[ -d "$REPO_ROOT/services/bff" && -f "$CRAPI_DIR/bff.yaml" ]] || { log "bff chưa có (Phase 2) — bỏ qua"; return; }
  step "BFF (edge PEP + Keycloak)"
  kaws apply -f "$CRAPI_DIR/bff.yaml"
  kaws apply -f "$CRAPI_DIR/ingress.yaml"
  wait_rollout "$AWS_CONTEXT" crapi deployment/bff 240s
  ok "bff"
}

deploy_mesh_policies() {
  step "Istio mesh policies (PeerAuth + DestinationRule [+ AuthorizationPolicy Phase 3])"
  kaws apply -f "$CRAPI_DIR/istio-policies.yaml"
  kos  apply -f "$CRAPI_DIR/istio-policies.yaml"
  ok "istio-policies"
}

register_spire() {
  step "SPIRE workload entries cho crapi"
  AWS_CONTEXT="$AWS_CONTEXT" OS_CONTEXT="$OS_CONTEXT" "$REPO_ROOT/scripts/ensure-spire-entries.sh"
}

apply_network_policies() {
  [[ -f "$CRAPI_DIR/network-policies/aws-allow-list.yaml" ]] || { log "network-policies chưa có (Phase 4) — bỏ qua"; return; }
  step "NetworkPolicy L4 (Phase 4)"
  kaws apply -f "$CRAPI_DIR/network-policies/aws-allow-list.yaml"
  kos  apply -f "$CRAPI_DIR/network-policies/os-allow-list.yaml"
  [[ -f "$CRAPI_DIR/network-policies/aws-pod-segmentation.yaml" ]] && kaws apply -f "$CRAPI_DIR/network-policies/aws-pod-segmentation.yaml" || true
  [[ -f "$CRAPI_DIR/network-policies/os-pod-segmentation.yaml" ]] && kos apply -f "$CRAPI_DIR/network-policies/os-pod-segmentation.yaml" || true
  ok "network-policies"
}

run_seed() {
  [[ -f "$CRAPI_DIR/seed-job.yaml" ]] || { log "seed-job chưa có (Phase 5) — bỏ qua"; return; }
  step "Seed dữ liệu crAPI (Job — thao tác app, không phải hạ tầng)"
  kaws delete job crapi-seed -n crapi --ignore-not-found >/dev/null 2>&1 || true
  kaws apply -f "$CRAPI_DIR/seed-job.yaml"
  kaws wait --for=condition=complete job/crapi-seed -n crapi --timeout=300s || warn "seed job chưa complete"
}

verify() {
  step "Trạng thái"
  log "AWS ns crapi";  kaws get pods -n crapi -o wide || true
  log "OpenStack ns crapi"; kos get pods -n crapi -o wide || true
}

main() {
  verify_contexts
  create_secrets
  apply_namespace_and_config
  deploy_databases
  deploy_crapi_workloads
  deploy_bff
  register_spire
  deploy_mesh_policies
  apply_network_policies
  run_seed
  verify
  ok "deploy-crapi hoàn tất"
}

main "$@"
