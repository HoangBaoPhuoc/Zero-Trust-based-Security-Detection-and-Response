#!/usr/bin/env bash
# Deploy the ZTLab application layer (K8s manifests) onto AWS and OpenStack K3s
# clusters that are already provisioned and running. For infra-from-zero
# (Terraform + Ansible + this script combined), use scripts/deploy-all.sh instead.
#
# This script intentionally orchestrates the existing focused scripts instead of
# replacing them:
#   - scripts/k8s-tunnel.sh for ctx-aws and ctx-openstack
#   - scripts/sync-app-images.sh for local image import on all K3s nodes
#   - scripts/deploy-security-stack.sh for SPIRE, OPA, Envoy, and Keycloak
#
# Usage:
#   ./scripts/deploy-app.sh
#   ./scripts/deploy-app.sh --skip-images
#   ./scripts/deploy-app.sh --skip-tunnel
#   ./scripts/deploy-app.sh --skip-security-stack

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"
AWS_KEY_PAIR_NAME="${AWS_KEY_PAIR_NAME:-ztlab-key}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/${AWS_KEY_PAIR_NAME}}"
# NodePort 31000 cua Service loki (k8s/plg-stack/loki.yaml) tren master AWS
# (IP private co dinh, terraform/aws). Dung chung cho Promtail va
# security-healthcheck phia OpenStack.
OS_LOKI_PUSH_URL="${OS_LOKI_PUSH_URL:-http://10.10.1.10:31000/loki/api/v1/push}"

# `kubectl run` overrides for the 4 short-lived kc-admin-setup bootstrap pods
# (kc-ldap-federation-setup, kc-audience-mapper-setup, kc-stepup-flow-setup,
# kc-saml-meta — deploy-crapi.sh's kc-crapi-setup has its own identical copy).
# Root-cause bug found live 2026-09-13, genuine destroy+redeploy: a bare
# `kubectl run --overrides="$KC_ADMIN_SETUP_OVERRIDES"`
# gets sidecar-injected (ns identity has istio-injection=enabled) but WITHOUT
# the sidecar.istio.io/userVolume[Mount] annotations that every real SPIRE
# workload's manifest carries (see k8s/keycloak/deployment.yaml) — so these
# pods silently fall back to Istio's OWN self-signed Citadel CA instead of the
# SPIRE workload socket. Their outbound mTLS to Keycloak (which validates
# peers against the SPIRE root, PeerAuthentication STRICT) then fails
# CERTIFICATE_VERIFY_FAILED on every single call — confirmed by exec'ing into
# a throwaway pod under the same SA and diffing `istioctl proxy-config secret`
# against Keycloak's own (real SPIRE socket) pod. This is what surfaced as
# "HTTP Error 503" in every one of these bootstrap steps once Phần 1.2 put
# Keycloak behind STRICT mTLS — before that, these pods called Keycloak over
# plaintext and never needed a real SPIFFE identity at all.
#
# Also sets label app=kc-admin-setup: `kubectl run` labels a pod
# `run=<podname>` by default, never `app=<serviceaccount>` — so NetworkPolicy
# os-pod-keycloak (k8s/crapi/network-policies/os-pod-segmentation.yaml,
# podSelector app=kc-admin-setup) never matched these pods either, blocking
# them at L4 even after the mTLS/ext_authz fixes above. Confirmed live
# 2026-09-13 with `kubectl run ... --dry-run=client -o yaml`, which showed
# only the `run:` label.
KC_ADMIN_SETUP_OVERRIDES='{"metadata":{"labels":{"app":"kc-admin-setup"},"annotations":{"sidecar.istio.io/userVolume":"[{\"name\":\"spire-workload-socket\",\"hostPath\":{\"path\":\"/run/spire/sockets/agent.sock\",\"type\":\"Socket\"}}]","sidecar.istio.io/userVolumeMount":"[{\"name\":\"spire-workload-socket\",\"mountPath\":\"/var/run/secrets/workload-spiffe-uds/socket\"}]"}},"spec":{"serviceAccountName":"kc-admin-setup"}}'

# Phần 1 remediation (2026-09-18, phát hiện thêm ngoài danh sách task): mọi
# call site kc-*-setup bên dưới trước đây làm
# `wait --for=condition=Ready ... --timeout=60s >/dev/null 2>&1 || true` rồi
# `exec` NGAY SAU — cái `|| true` NUỐT LỖI wait, nên nếu istio-proxy sidecar
# của pod chưa Ready (SPIRE cấp SVID chậm khi cụm vừa khởi động — đúng lúc
# các pod này chạy, ngay sau bước SPIRE/Istio), lệnh exec chạy vào một pod mà
# mesh chưa sẵn sàng định tuyến: gọi Keycloak Admin API qua mTLS thất bại,
# rồi bị `|| warn` ở cuối nuốt tiếp — deploy báo "OK" nhưng cấu hình Keycloak
# KHÔNG được áp dụng. Quan sát THẬT trên một lần redeploy sạch (2026-09-18):
# đúng chuỗi này khiến client `crapi-bff` không có redirectUris https, login
# qua Gateway hỏng hoàn toàn dù `deploy-crapi.sh` không báo lỗi nào. Sửa tận
# gốc: retry wait THẬT (không swallow) trước khi exec.
kc_wait_ready() { # <pod> [timeout_per_try] [số lần thử]
  local pod="$1" per="${2:-30s}" tries="${3:-6}" i=0
  until kubectl --context "$KEYCLOAK_CONTEXT" wait --for=condition=Ready "pod/$pod" -n identity --timeout="$per" >/dev/null 2>&1; do
    i=$((i + 1))
    if [[ $i -ge $tries ]]; then
      warn "$pod không Ready sau ${i}x${per} — exec tiếp theo có thể lỗi mesh (sidecar/SPIRE SVID chậm)"
      return 1
    fi
  done
  return 0
}

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

# A1: Keycloak (+ keycloak-db, openldap) chạy trên cụm OpenStack (Nghị định 53).
# Mọi bước thao tác Keycloak Admin API / manifest identity dùng context này.
KEYCLOAK_CONTEXT="${KEYCLOAK_CONTEXT:-$OS_CONTEXT}"
kkc() {
  kubectl --context "$KEYCLOAK_CONTEXT" "$@"
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

regenerate_policy_files() {
  step "Step 0b: Regenerate OPA/NetworkPolicy từ policy/service-graph-crapi.yaml"
  # Safety net for VIEC-CON-TON-DONG.md item 3: opa/policies/service_acl.rego
  # and k8s/financial/network-policies/{aws,os}-pod-segmentation.yaml are
  # GENERATED from policy/service-graph.yaml, committed to the repo as the
  # deployable artifact. If someone edits service-graph.yaml but forgets to
  # re-run the 2 generators before deploying, the cluster silently gets the
  # OLD policy instead (tests/test_service_graph_consistency.py only catches
  # this in CI/manually run, not automatically on deploy). Run both here,
  # before anything reads either output file, so that can no longer happen.
  # No-op (git-clean) when service-graph.yaml already matches committed output.
  python3 "$REPO_ROOT/scripts/gen-rego-acl.py"
  python3 "$REPO_ROOT/scripts/gen-networkpolicy.py"
  ok "Policy files regenerated (crapi)"
}

apply_namespaces() {
  step "Step 1: Namespaces"
  kaws apply -f "$REPO_ROOT/k8s/namespaces.yaml"
  kos apply -f "$REPO_ROOT/k8s/namespaces.yaml"
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/namespace.yaml"
  kos apply -f "$REPO_ROOT/k8s/plg-stack/namespace.yaml"

  # CoreDNS override cho cluster OpenStack: chặn search-domain `openstacklocal`
  # bằng NXDOMAIN tức thì để DNS nội cụm không treo khi upstream (8.8.8.8 qua
  # uplink hotspot) timeout — nếu không, spire-agent dial spire-server timeout
  # → SVID hết hạn → toàn mesh STRICT mТLS 503. Xem k8s/dns/*.
  kos apply -f "$REPO_ROOT/k8s/dns/coredns-custom-openstack.yaml"
  kos -n kube-system rollout restart deployment/coredns >/dev/null 2>&1 || true
  ok "Namespaces + CoreDNS override ready on both clusters"
}

apply_network_policies() {
  step "Step 1b: Network policies (early — must exist before any pod with restricted egress starts)"
  kaws apply -f "$REPO_ROOT/k8s/crapi/network-policies/aws-allow-list.yaml"
  kos apply -f "$REPO_ROOT/k8s/crapi/network-policies/os-allow-list.yaml"
  ok "Network policies applied on both clusters"
}

deploy_gatekeeper() {
  step "Step 1c: OPA Gatekeeper (K8s admission control)"
  kaws apply -f "https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.16.3/deploy/gatekeeper.yaml"
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod -l control-plane=controller-manager -n gatekeeper-system --timeout=180s
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod -l control-plane=audit-controller -n gatekeeper-system --timeout=180s
  kaws apply -f "$REPO_ROOT/k8s/gatekeeper/constraint-templates.yaml"
  sleep 5
  kaws apply -f "$REPO_ROOT/k8s/gatekeeper/constraints.yaml"
  ok "Gatekeeper installed with ConstraintTemplates/Constraints (nonroot=dryrun, image-policy=deny)"
}

deploy_spire_pre_istio() {
  step "Step 1d-pre: SPIRE root CA + agents + workload entries (both clouds)"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping SPIRE pre-provisioning (security stack skipped)"
    return
  fi

  # k8s/istio/istio-operator.yaml hard-mounts a hostPath Socket volume for
  # /run/spire/sockets/agent.sock on istio-ingressgateway — kubelet refuses to
  # mount a hostPath of type Socket unless the file already exists, so the
  # SPIRE agent DaemonSet must be running on every node BEFORE `istioctl
  # install` waits for the gateway to become Ready. Beyond that, the gateway's
  # SDS client authenticates against SPIRE via the k8s:ns/k8s:sa selectors on
  # its own registered entry (spiffe://ztlab.local/aws/edge-gateway in
  # scripts/spire-entries.generated.sh) — without that entry existing yet,
  # SPIRE's Workload API SDS proxy rejects every cert request with "workload
  # is not authorized for the requested identities" and the readiness probe
  # never passes either (confirmed live 2026-09-13: agents alone weren't
  # enough, same 5-minute istioctl timeout recurred one layer deeper).
  # deploy_security_stack (Step 3) used to be the only place SPIRE got
  # deployed AND registered, but it runs after deploy_istio — on a genuinely
  # fresh cluster neither existed yet at gateway-install time. Source the
  # security-stack script to reuse its (idempotent) SPIRE functions instead of
  # duplicating them; deploy_security_stack still runs them again at Step 3,
  # which is a harmless no-op re-apply.
  # shellcheck source=scripts/deploy-security-stack.sh
  source "$REPO_ROOT/scripts/deploy-security-stack.sh"
  provision_spire_root_ca
  deploy_step_3_spire_aws
  deploy_step_3_spire_os
  register_spire_workloads
  ok "SPIRE root CA + agent DaemonSets + workload entries ready on both clouds (ahead of Istio)"
}

deploy_istio() {
  step "Step 1d: Istio (service mesh — ns crapi, 2 cluster, STRICT mTLS)"
  local istio_version="1.22.3"
  local istioctl_bin="istioctl"
  if ! command -v istioctl >/dev/null 2>&1; then
    if [[ -x "$REPO_ROOT/.istio-${istio_version}/bin/istioctl" ]]; then
      istioctl_bin="$REPO_ROOT/.istio-${istio_version}/bin/istioctl"
    else
      log "istioctl not found — downloading pinned version $istio_version"
      (cd "$REPO_ROOT" && curl -sL https://istio.io/downloadIstio | ISTIO_VERSION="$istio_version" TARGET_ARCH=x86_64 sh -)
      mv "$REPO_ROOT/istio-${istio_version}" "$REPO_ROOT/.istio-${istio_version}"
      istioctl_bin="$REPO_ROOT/.istio-${istio_version}/bin/istioctl"
    fi
  fi

  # k8s/istio/istio-operator.yaml is the single source of truth for install
  # config: trustDomain MUST match SPIRE's (ztlab.local), not Istio's
  # cluster.local default — otherwise Istio's own inbound mTLS validation
  # context rejects SPIRE-issued peer certs with a CERTIFICATE_UNKNOWN TLS
  # alert (confirmed via repro). The opa-ext-authz extensionProvider
  # replicates the hand-rolled Envoy's ext_authz filter (fail-closed OPA
  # check) for every migrated service that needs real Rego enforcement, not
  # just a static ALLOW — see the CUSTOM AuthorizationPolicy entries in
  # k8s/financial/istio-policies.yaml. SPIRE stays the actual cert source via
  # the Workload API socket (sidecar.istio.io/userVolume annotations in
  # aws-services.yaml) — trustDomain here only has to match for Istio's own
  # validation logic to accept those certs, Istio's Citadel CA is never
  # actually used.
  # Installed on BOTH clusters — core-banking/account-service/
  # transaction-service (OpenStack) are migrated too, and the cross-cloud
  # payment-service→core-banking call needs a real Istio sidecar on the
  # OpenStack side to present/validate SPIRE certs via ISTIO_MUTUAL.
  # extensionProviders.opa-ext-authz resolves per-cluster to each cluster's
  # own local opa-service — no cross-cluster wiring needed.
  "$istioctl_bin" install --context "$AWS_CONTEXT" -f "$REPO_ROOT/k8s/istio/istio-operator.yaml" -y
  # OpenStack doesn't expose crAPI externally and has no SPIRE registration
  # entry for istio-ingressgateway-service-account (see
  # scripts/spire-entries.generated.sh) — the overlay disables that component
  # for this install only. See its header comment for the failure this fixes.
  "$istioctl_bin" install --context "$OS_CONTEXT" \
    -f "$REPO_ROOT/k8s/istio/istio-operator.yaml" \
    -f "$REPO_ROOT/k8s/istio/istio-operator-os-overlay.yaml" -y

  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod -l app=istiod -n istio-system --timeout=180s
  kubectl --context "$OS_CONTEXT" wait --for=condition=Ready pod -l app=istiod -n istio-system --timeout=180s

  # istio-injection=enabled gates the whole namespace. All 8 financial
  # services are migrated now, so nothing needs the opt-out annotation
  # anymore — kept as a no-op comment in case a future service is added
  # un-migrated: give it sidecar.istio.io/inject: "false" or it will be
  # auto-injected and likely break (no SPIRE workload-socket volume mount).
  kaws label namespace crapi istio-injection=enabled --overwrite
  kos label namespace crapi istio-injection=enabled --overwrite
  # A2: bff PeerAuthentication is STRICT — Prometheus (AWS-only, ns monitoring)
  # scrapes bff:8080/metrics directly and needs a real SVID or that mTLS-only
  # port rejects it outright. Pod-level sidecar.istio.io/inject annotation
  # alone wasn't enough to trigger injection on this cluster; the namespace
  # label is what actually works (k8s/monitoring/prometheus.yaml has the rest).
  kaws label namespace monitoring istio-injection=enabled --overwrite
  ok "Istio installed on both clouds (trustDomain=ztlab.local), crapi namespaces labeled for injection"
}

sync_images() {
  step "Step 2: Images"
  if [[ "$SKIP_IMAGES" == true ]]; then
    log "Skipping image build/sync"
    return
  fi

  "$REPO_ROOT/scripts/sync-app-images.sh"
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

deploy_openldap_and_federation() {
  local kc_step_failed=false
  step "Step 3b: OpenLDAP (SCIM demo directory) + Keycloak User Federation"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping OpenLDAP federation (security stack was skipped, Keycloak not available)"
    return
  fi

  kkc apply -f "$REPO_ROOT/k8s/identity/openldap.yaml"
  kubectl --context "$KEYCLOAK_CONTEXT" wait --for=condition=Ready pod -l app=openldap -n identity-directory --timeout=90s
  kkc apply -f "$REPO_ROOT/k8s/identity/openldap-seed-job.yaml"
  kubectl --context "$KEYCLOAK_CONTEXT" wait --for=condition=complete job/openldap-seed -n identity-directory --timeout=60s || true

  local admin_pass
  admin_pass="$(kkc get secret keycloak-secret -n identity -o jsonpath='{.data.admin-password}' | base64 -d)"

  # Component idempotency: realm-config.json also declares this LDAP provider
  # for a FRESH Keycloak import, but Keycloak's --import-realm only runs on
  # first boot of a realm — it will not retrofit this component onto an
  # already-imported realm. Register it live via Admin API too so it exists
  # even when Keycloak itself wasn't redeployed this run.
  kkc delete pod kc-ldap-federation-setup -n identity --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kkc run kc-ldap-federation-setup --image=python:3.12-alpine -n identity --restart=Never --overrides="$KC_ADMIN_SETUP_OVERRIDES" --command -- sh -c "sleep 60" >/dev/null 2>&1 || true
  kc_wait_ready kc-ldap-federation-setup
  kubectl --context "$KEYCLOAK_CONTEXT" exec -n identity kc-ldap-federation-setup -- python3 -c "
import urllib.request, json, urllib.parse, urllib.error

tok_data = urllib.parse.urlencode({'grant_type':'password','client_id':'admin-cli','username':'admin','password':'$admin_pass'}).encode()
req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/realms/master/protocol/openid-connect/token', data=tok_data)
token = json.load(urllib.request.urlopen(req))['access_token']

req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/admin/realms/ztlab/components', headers={'Authorization': 'Bearer ' + token})
comps = json.load(urllib.request.urlopen(req))
if any(c.get('name') == 'ldap-directory' and c.get('providerId') == 'ldap' for c in comps):
    print('ldap-directory component already registered, skipping')
else:
    payload = {
        'name': 'ldap-directory', 'providerId': 'ldap',
        'providerType': 'org.keycloak.storage.UserStorageProvider', 'parentId': 'ztlab',
        'config': {
            'enabled': ['true'], 'priority': ['0'], 'editMode': ['READ_ONLY'],
            'syncRegistrations': ['false'], 'vendor': ['other'],
            'usernameLDAPAttribute': ['uid'], 'rdnLDAPAttribute': ['uid'],
            'uuidLDAPAttribute': ['entryUUID'],
            'userObjectClasses': ['inetOrgPerson, organizationalPerson'],
            'connectionUrl': ['ldap://openldap.identity-directory.svc.cluster.local:389'],
            'usersDn': ['ou=people,dc=ztlab,dc=local'], 'authType': ['simple'],
            'bindDn': ['cn=admin,dc=ztlab,dc=local'], 'bindCredential': ['ztlab-ldap-admin-2026'],
            'searchScope': ['1'], 'trustEmail': ['true'], 'useTruststoreSpi': ['never'],
            'connectionPooling': ['true'], 'pagination': ['true'],
            'batchSizeForSync': ['1000'], 'fullSyncPeriod': ['-1'], 'changedSyncPeriod': ['-1'],
            'importEnabled': ['true'],
        }
    }
    req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/admin/realms/ztlab/components', data=json.dumps(payload).encode(), headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, method='POST')
    urllib.request.urlopen(req)
    print('ldap-directory component created')
" || { warn "OpenLDAP Keycloak federation setup failed (non-fatal — demo/illustration component)"; kc_step_failed=true; }
  kubectl --context "$KEYCLOAK_CONTEXT" delete pod kc-ldap-federation-setup -n identity --ignore-not-found --wait=false >/dev/null 2>&1 || true

  [[ "${kc_step_failed:-false}" == true ]] || ok "OpenLDAP deployed, seeded, and registered as Keycloak User Federation (READ_ONLY, demo directory — not a real corporate LDAP)"
}

deploy_audience_mapper() {
  local kc_step_failed=false
  step "Step 3b2: Keycloak Audience protocol mapper (crapi-bff -> aud=crapi-bff)"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping Audience mapper (security stack was skipped, Keycloak not available)"
    return
  fi

  local admin_pass
  admin_pass="$(kkc get secret keycloak-secret -n identity -o jsonpath='{.data.admin-password}' | base64 -d)"

  # Same idempotency caveat as deploy_openldap_and_federation: realm-config.json
  # now declares this mapper for a FRESH import, but --import-realm won't
  # retrofit it onto an already-imported realm (T-1.4 regression, 2026-09-05:
  # this exact mapper was added by hand via Admin API in a previous session,
  # then silently lost on the next from-scratch deploy-all.sh because it lived
  # nowhere else). Register it live too so every deploy ends up with it.
  kkc delete pod kc-audience-mapper-setup -n identity --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kkc run kc-audience-mapper-setup --image=python:3.12-alpine -n identity --restart=Never --overrides="$KC_ADMIN_SETUP_OVERRIDES" --command -- sh -c "sleep 60" >/dev/null 2>&1 || true
  kc_wait_ready kc-audience-mapper-setup
  kubectl --context "$KEYCLOAK_CONTEXT" exec -n identity kc-audience-mapper-setup -- python3 -c "
import urllib.request, json, urllib.parse

tok_data = urllib.parse.urlencode({'grant_type':'password','client_id':'admin-cli','username':'admin','password':'$admin_pass'}).encode()
req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/realms/master/protocol/openid-connect/token', data=tok_data)
token = json.load(urllib.request.urlopen(req))['access_token']
headers = {'Authorization': 'Bearer ' + token}

for client_id in ('crapi-bff',):
    req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/admin/realms/ztlab/clients?clientId=' + client_id, headers=headers)
    clients = json.load(urllib.request.urlopen(req))
    if not clients:
        print(client_id, '-> client not found, skipping')
        continue
    internal_id = clients[0]['id']

    req = urllib.request.Request('http://keycloak.identity.svc.cluster.local:8080/admin/realms/ztlab/clients/' + internal_id + '/protocol-mappers/models', headers=headers)
    mappers = json.load(urllib.request.urlopen(req))
    if any(m.get('name') == 'aud-crapi-bff' for m in mappers):
        print(client_id, '-> aud-crapi-bff mapper already present, skipping')
        continue

    payload = {
        'name': 'aud-crapi-bff', 'protocol': 'openid-connect',
        'protocolMapper': 'oidc-audience-mapper', 'consentRequired': False,
        'config': {'included.client.audience': 'crapi-bff', 'id.token.claim': 'false', 'access.token.claim': 'true'},
    }
    req = urllib.request.Request(
        'http://keycloak.identity.svc.cluster.local:8080/admin/realms/ztlab/clients/' + internal_id + '/protocol-mappers/models',
        data=json.dumps(payload).encode(), headers={**headers, 'Content-Type': 'application/json'}, method='POST')
    urllib.request.urlopen(req)
    print(client_id, '-> aud-crapi-bff mapper created')
" || { warn "Keycloak Audience mapper setup failed (non-fatal — but T-1.4 audience check degrades to a no-op without it, see KET-QUA-KIEM-TRA.md)"; kc_step_failed=true; }
  kubectl --context "$KEYCLOAK_CONTEXT" delete pod kc-audience-mapper-setup -n identity --ignore-not-found --wait=false >/dev/null 2>&1 || true

  [[ "${kc_step_failed:-false}" == true ]] || ok "Keycloak Audience mapper ensured on crapi-bff client"
}

deploy_stepup_flow() {
  local kc_step_failed=false
  step "Step 3b3: Keycloak browser-stepup authentication flow (T-4.2 step-up OTP)"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping browser-stepup flow (security stack was skipped, Keycloak not available)"
    return
  fi

  local admin_pass
  admin_pass="$(kkc get secret keycloak-secret -n identity -o jsonpath='{.data.admin-password}' | base64 -d)"

  # Same idempotency caveat as deploy_audience_mapper/deploy_openldap_and_federation:
  # client "crapi-bff-stepup" comes from realm-config.json on fresh --import-realm,
  # but the authentication flow it needs to bind to does NOT — it was hand-built via
  # Admin API in a prior session and lost on the next from-scratch deploy (see
  # VIEC-CON-TON-DONG.md item 1). Register it live too so every deploy ends up with it.
  kkc delete pod kc-stepup-flow-setup -n identity --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kkc run kc-stepup-flow-setup --image=python:3.12-alpine -n identity --restart=Never --overrides="$KC_ADMIN_SETUP_OVERRIDES" --command -- sh -c "sleep 180" >/dev/null 2>&1 || true
  kc_wait_ready kc-stepup-flow-setup
  kubectl --context "$KEYCLOAK_CONTEXT" exec -n identity kc-stepup-flow-setup -- python3 -c "
import urllib.request, json, urllib.parse

KC = 'http://keycloak.identity.svc.cluster.local:8080'
REALM = 'ztlab'

def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(KC + path, data=data, headers=headers, method=method)
    if data is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        resp = urllib.request.urlopen(req)
        raw = resp.read()
        return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raise RuntimeError(f'{method} {path} -> {e.code}: {e.read().decode()}')

tok_data = urllib.parse.urlencode({'grant_type':'password','client_id':'admin-cli','username':'admin','password':'$admin_pass'}).encode()
token = json.load(urllib.request.urlopen(urllib.request.Request(KC + '/realms/master/protocol/openid-connect/token', data=tok_data)))['access_token']
headers = {'Authorization': 'Bearer ' + token}

flows = call('GET', f'/admin/realms/{REALM}/authentication/flows')
if any(f['alias'] == 'browser-stepup' for f in flows):
    print('browser-stepup flow already exists, skipping creation')
else:
    # 1. Copy built-in 'browser' -> 'browser-stepup' (brings 'browser-stepup forms'
    #    and its nested Conditional-OTP subflow along for free).
    call('POST', f'/admin/realms/{REALM}/authentication/flows/browser/copy', {'newName': 'browser-stepup'})

    # 2. Add a new CONDITIONAL subflow 'Stepup-2fa' as a child of 'browser-stepup
    #    forms' (NOT of 'browser-stepup' itself, or it lands at the wrong level).
    call('POST', f'/admin/realms/{REALM}/authentication/flows/browser-stepup%20forms/executions/flow',
         {'name': 'Stepup-2fa', 'description': 'Step-up: OTP khi LoA >= 2 (acr=high)', 'provider': 'basic-flow', 'type': 'basic-flow'})

    execs = call('GET', f'/admin/realms/{REALM}/authentication/flows/browser-stepup/executions')
    stepup_exec = next(e for e in execs if e.get('level') == 1 and e.get('authenticationFlow') and e.get('description', '').startswith('Step-up:'))
    flow_id = stepup_exec['flowId']

    # QUIRK (found 2026-09-08, re-derived from scratch after infra destroy): the
    # 'executions/flow' endpoint's JSON body field is 'name' per the docs, but on
    # this Keycloak 24.0.3 it does NOT set the resulting flow's alias — the new
    # flow comes back with alias=null, so every subsequent by-alias lookup
    # ('/authentication/flows/Stepup-2fa/...') 400s with 'Parent flow doesn't
    # exist'. Fix: PUT the flow object directly with the alias set explicitly.
    call('PUT', f'/admin/realms/{REALM}/authentication/flows/{flow_id}',
         {'id': flow_id, 'alias': 'Stepup-2fa', 'description': 'Step-up: OTP khi LoA >= 2 (acr=high)',
          'providerId': 'basic-flow', 'topLevel': False, 'builtIn': False})

    # 3. Flip the subflow execution from DISABLED -> CONDITIONAL.
    call('PUT', f'/admin/realms/{REALM}/authentication/flows/browser-stepup%20forms/executions',
         {'id': stepup_exec['id'], 'requirement': 'CONDITIONAL'})

    # 4. Add the 2 child executions inside 'Stepup-2fa' and require both.
    call('POST', f'/admin/realms/{REALM}/authentication/flows/Stepup-2fa/executions/execution', {'provider': 'conditional-level-of-authentication'})
    call('POST', f'/admin/realms/{REALM}/authentication/flows/Stepup-2fa/executions/execution', {'provider': 'auth-otp-form'})
    child_execs = call('GET', f'/admin/realms/{REALM}/authentication/flows/Stepup-2fa/executions')
    cond_exec = next(e for e in child_execs if e['providerId'] == 'conditional-level-of-authentication')
    otp_exec = next(e for e in child_execs if e['providerId'] == 'auth-otp-form')
    call('PUT', f'/admin/realms/{REALM}/authentication/flows/Stepup-2fa/executions', {'id': cond_exec['id'], 'requirement': 'REQUIRED'})
    call('PUT', f'/admin/realms/{REALM}/authentication/flows/Stepup-2fa/executions', {'id': otp_exec['id'], 'requirement': 'REQUIRED'})

    # 5. Configure the LoA condition: acr=high (level 2), 10h cached max-age.
    #    Key names MUST be 'loa-condition-level'/'loa-max-age' — the UI helpText
    #    names ('level'/'maxAge') are silently ignored, LoA check never fires.
    call('POST', f'/admin/realms/{REALM}/authentication/executions/{cond_exec[\"id\"]}/config',
         {'alias': 'stepup-loa-2', 'config': {'loa-condition-level': '2', 'loa-max-age': '36000'}})

    print('browser-stepup flow created')

# 5b. (Vòng 2026-09-29, phát hiện khi chạy step-up trọn lần đầu) 'browser-stepup' là
#     BẢN SAO của flow 'browser' nên mang theo subflow 'Browser - Conditional OTP'
#     (OTP khi user đã cấu hình OTP) CẠNH Stepup-2fa (OTP khi LoA 2) → user có OTP bị
#     hỏi OTP HAI LẦN liên tiếp (2 execution auth-otp-form khác nhau), và cùng một mã
#     TOTP không dùng lại được trong cửa sổ 30 s. Tắt subflow sao chép đó CHỈ trong
#     browser-stepup (idempotent, chạy mọi lần) — OTP do Stepup-2fa hỏi đúng một lần.
for e in call('GET', f'/admin/realms/{REALM}/authentication/flows/browser-stepup/executions'):
    if e.get('level') == 1 and e.get('authenticationFlow') and 'Conditional OTP' in (e.get('displayName') or '') \
            and e.get('requirement') != 'DISABLED':
        call('PUT', f'/admin/realms/{REALM}/authentication/flows/browser-stepup/executions',
             {'id': e['id'], 'requirement': 'DISABLED'})
        print('browser-stepup: disabled copied Conditional OTP subflow (tránh hỏi OTP 2 lần)')

# 6. Bind 'browser-stepup' as the browser flow of client 'crapi-bff-stepup' ONLY.
#    Do NOT bind it on 'web-portal' — that forces OTP on every normal login (regression
#    seen once already, see KET-QUA-KIEM-TRA.md).
browser_stepup_id = next(f['id'] for f in call('GET', f'/admin/realms/{REALM}/authentication/flows') if f['alias'] == 'browser-stepup')
clients = call('GET', f'/admin/realms/{REALM}/clients?clientId=crapi-bff-stepup')
if not clients:
    print('crapi-bff-stepup client not found, skipping flow binding')
else:
    client_id = clients[0]['id']
    overrides = clients[0].get('authenticationFlowBindingOverrides', {})
    if overrides.get('browser') == browser_stepup_id:
        print('crapi-bff-stepup already bound to browser-stepup, skipping')
    else:
        overrides['browser'] = browser_stepup_id
        call('PUT', f'/admin/realms/{REALM}/clients/{client_id}', {'authenticationFlowBindingOverrides': overrides})
        print('crapi-bff-stepup bound to browser-stepup')
    # 6b. (Vòng 2026-09-29) ánh xạ ACR↔LoA. Thiếu nó Keycloak trả acr="2" (số LoA)
    #     trong khi BFF (_is_sensitive) và OPA (step_up_ok) so acr == "high" → step-up
    #     KHÔNG BAO GIỜ thành công dù OTP đúng (quan sát sống lần chạy trọn đầu tiên).
    attrs = call('GET', f'/admin/realms/{REALM}/clients/{client_id}').get('attributes', {})
    want = json.dumps({'normal': 1, 'high': 2}, separators=(',', ':'))
    if attrs.get('acr.loa.map') != want:
        call('PUT', f'/admin/realms/{REALM}/clients/{client_id}', {'attributes': {**attrs, 'acr.loa.map': want}})
        print('crapi-bff-stepup: acr.loa.map = ' + want)

# 7. Ensure the demo user exists with CONFIGURE_TOTP pending. No OTP secret is
# fabricated here: enrollment happens right after this block through Keycloak's
# own CONFIGURE_TOTP required-action form (scripts/kc-enroll-stepup-otp.py).
users = call('GET', f'/admin/realms/{REALM}/users?username=stepup-demo&exact=true')
if users:
    print('stepup-demo user already exists, skipping')
else:
    call('POST', f'/admin/realms/{REALM}/users',
         {'username': 'stepup-demo', 'enabled': True, 'requiredActions': ['CONFIGURE_TOTP'],
          'credentials': [{'type': 'password', 'value': 'StepupDemo123!', 'temporary': False}]})
    print('stepup-demo user created (requiredActions=CONFIGURE_TOTP, needs one interactive login to enroll real OTP)')
" || { warn "Keycloak browser-stepup flow setup failed (non-fatal — but T-4.2 step-up OTP degrades to no-op without it, see VIEC-CON-TON-DONG.md item 1)"; kc_step_failed=true; }
  # Mục 6 vòng 2026-09-29: enroll OTP cho stepup-demo NGAY TRONG deploy (trước đây
  # là "việc người dùng làm tay qua trình duyệt" và chưa từng được làm → step-up
  # chưa bao giờ chạy trọn một lần). Script đi đúng luồng CONFIGURE_TOTP của
  # Keycloak (xem docstring scripts/kc-enroll-stepup-otp.py). Secret TOTP cất ở
  # Secret k8s identity/stepup-demo-otp để tests/crapi_step_up_otp.sh tính mã.
  if [[ "${kc_step_failed:-false}" != true ]]; then
    local otp_known otp_out otp_secret
    otp_known="$(kkc get secret stepup-demo-otp -n identity -o jsonpath='{.data.secret}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    if otp_out="$(kubectl --context "$KEYCLOAK_CONTEXT" exec -i -n identity kc-stepup-flow-setup -- \
          env KC_ADMIN_PASSWORD="$admin_pass" OTP_SECRET="$otp_known" python3 - \
          < "$REPO_ROOT/scripts/kc-enroll-stepup-otp.py" 2>&1)"; then
      otp_secret="$(sed -n 's/^OTP_SECRET=//p' <<<"$otp_out" | tail -1)"
      grep -v '^OTP_SECRET=' <<<"$otp_out" | sed 's/^/    /'
      kkc create secret generic stepup-demo-otp -n identity --from-literal=secret="$otp_secret" \
        --dry-run=client -o yaml | kkc apply -f - >/dev/null
      ok "stepup-demo OTP enrolled (secret ở Secret identity/stepup-demo-otp)"
    else
      warn "enroll OTP stepup-demo thất bại — step-up OTP không demo được: $(grep -v '^OTP_SECRET=' <<<"$otp_out" | tail -3)"
      kc_step_failed=true
    fi
  fi
  kubectl --context "$KEYCLOAK_CONTEXT" delete pod kc-stepup-flow-setup -n identity --ignore-not-found --wait=false >/dev/null 2>&1 || true

  [[ "${kc_step_failed:-false}" == true ]] || ok "Keycloak browser-stepup flow ensured, bound to crapi-bff-stepup client"
}

deploy_aws_saml_federation() {
  step "Step 3c: AWS IAM SAML federation (AWS Console SSO via Keycloak)"
  if [[ "$SKIP_SECURITY_STACK" == true ]]; then
    log "Skipping AWS SAML federation (security stack was skipped, Keycloak not available)"
    return
  fi
  if ! command -v terraform >/dev/null 2>&1; then
    warn "terraform not found — skipping AWS SAML federation (non-fatal, admin-console-SSO convenience only)"
    return
  fi
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    warn "No AWS credentials in environment (see DEPLOY.md Step 2: export \$(grep -v '^#' .env | xargs)) — skipping AWS SAML federation"
    return
  fi

  # Vòng 2026-09-29: tải về file tạm, chỉ khi hợp lệ mới thay file CỐ ĐỊNH
  # terraform/aws/keycloak-saml-metadata.xml (default của biến
  # keycloak_saml_metadata_path, gitignore) và GIỮ LẠI — để mọi `terraform plan`
  # không target sau này thấy đúng 3 tài nguyên SAML/IAM thay vì đòi destroy.
  local meta_file="/tmp/ztlab-keycloak-saml-metadata-$$.xml"
  local meta_keep="$REPO_ROOT/terraform/aws/keycloak-saml-metadata.xml"
  # kubectl run --rm's own "pod ... deleted" status line can land on stdout
  # and corrupt a captured file — use a plain pod + exec + explicit delete
  # instead of --rm to keep the captured metadata byte-exact.
  kkc delete pod kc-saml-meta -n identity --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kkc run kc-saml-meta --image=curlimages/curl -n identity --restart=Never --overrides="$KC_ADMIN_SETUP_OVERRIDES" --command -- sh -c "sleep 30" >/dev/null
  kc_wait_ready kc-saml-meta 15s 2
  kubectl --context "$KEYCLOAK_CONTEXT" exec -n identity kc-saml-meta -- curl -s http://keycloak.identity.svc.cluster.local:8080/realms/ztlab/protocol/saml/descriptor > "$meta_file" || true
  kkc delete pod kc-saml-meta -n identity --ignore-not-found --wait=false >/dev/null 2>&1 || true

  if ! python3 -c "import xml.dom.minidom; xml.dom.minidom.parse('$meta_file')" 2>/dev/null; then
    warn "Keycloak SAML metadata unreachable or invalid (is Keycloak Running? check: kubectl --context $KEYCLOAK_CONTEXT get pods -n identity) — skipping AWS SAML federation, non-fatal"
    rm -f "$meta_file"
    return
  fi

  mv -f "$meta_file" "$meta_keep"
  (cd "$REPO_ROOT/terraform/aws" && terraform apply -auto-approve \
    -target=aws_iam_saml_provider.keycloak \
    -target=aws_iam_role.ztlab_sso_admin \
    -target=aws_iam_role_policy_attachment.ztlab_sso_admin_readonly) \
    && ok "AWS IAM SAML provider + ztlab-sso-admin role applied" \
    || warn "AWS SAML federation terraform apply failed (non-fatal — admin-console-SSO convenience only)"
}

deploy_crapi() {
  # Ứng dụng mục tiêu = OWASP crAPI (thay finance app — KE-HOACH-CRAPI.md).
  # scripts/deploy-crapi.sh idempotent: DB (Postgres OpenStack / Mongo+Redis AWS),
  # crapi-identity + mailhog (OpenStack), web/community/workshop + bff (AWS),
  # Keycloak crapi client/role, SPIRE entries, OPA PDP riêng ns crapi + Istio
  # extensionProvider, AuthorizationPolicy, NetworkPolicy, seed Job.
  step "Step 4-5: Deploy crAPI target app + Zero-Trust wiring"
  # ZTLAB_DEFER_ACCEPTANCE=1: nghiệm thu mesh của deploy-crapi.sh chỉ cảnh báo ở
  # đây; nghiệm thu thật (fail) chạy ở verify_final SAU khi stack quan sát đã dựng (H8).
  ZTLAB_DEFER_ACCEPTANCE=1 AWS_CONTEXT="$AWS_CONTEXT" OS_CONTEXT="$OS_CONTEXT" "$REPO_ROOT/scripts/deploy-crapi.sh"
  ok "crAPI target app deployed"
}

keycloak_admin_password() {
  if [[ -n "${KEYCLOAK_ADMIN_PASSWORD:-}" ]]; then
    printf '%s' "$KEYCLOAK_ADMIN_PASSWORD"
    return
  fi

  local encoded
  encoded="$(kkc -n identity get secret keycloak-secret -o jsonpath='{.data.admin-password}' 2>/dev/null || true)"
  if [[ -n "$encoded" ]]; then
    printf '%s' "$encoded" | base64 -d
    return
  fi

  fail "KEYCLOAK_ADMIN_PASSWORD is unset and identity/keycloak-secret does not exist"
}

# A4 removed the SOAR execution engine. The plg-stack secrets it required
# (keycloak-admin-secret for revoke_user_sessions, ai-secrets for SOAR_*,
# soar-main-patch configmap, soar-openstack-kubeconfig for cross-cloud patching)
# are all gone. incident-analyzer keeps no k8s client and notifies through a
# credential-less in-cluster MailHog.
#
# grafana-smtp-secret is UNRELATED to A4/incident-analyzer — it is consumed
# directly by k8s/plg-stack/grafana.yaml (GF_SMTP_PASSWORD) so Grafana's own
# alertmanager can email voha2005@gmail.com (notification-policy.yml's `email`
# contact points), independent of incident-analyzer's MailHog bundle emails.
# Provisioned below from SMTP_PASS (empty default — Grafana still starts, just
# without a working relay until a real app-password is exported).

deploy_vault_and_seed_secrets() {
  log "Deploying Vault (Zero-Trust secrets component) and seeding smtp-secret KV"
  kaws apply -f "$REPO_ROOT/k8s/vault/vault.yaml"
  kubectl --context "$AWS_CONTEXT" wait --for=condition=Ready pod/vault-0 -n vault --timeout=120s

  local vault_status initialized sealed unseal_key root_token init_json

  vault_status="$(kaws exec -n vault vault-0 -- sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json' 2>/dev/null || true)"
  initialized="$(echo "$vault_status" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("initialized", False))
except Exception:
    print(False)' 2>/dev/null || echo False)"

  if [[ "$initialized" != "True" ]]; then
    log "Vault not initialized — running operator init (1 key share, lab-grade)"
    init_json="$(kaws exec -n vault vault-0 -- sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault operator init -key-shares=1 -key-threshold=1 -format=json')"
    unseal_key="$(echo "$init_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["unseal_keys_b64"][0])')"
    root_token="$(echo "$init_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["root_token"])')"
    kaws create secret generic vault-unseal-keys -n vault \
      --from-literal=unseal-key="$unseal_key" \
      --from-literal=root-token="$root_token" \
      --dry-run=client -o yaml | kaws apply -f -
  else
    log "Vault already initialized — reusing unseal key/root token from vault-unseal-keys secret"
    unseal_key="$(kaws get secret vault-unseal-keys -n vault -o jsonpath='{.data.unseal-key}' | base64 -d)"
    root_token="$(kaws get secret vault-unseal-keys -n vault -o jsonpath='{.data.root-token}' | base64 -d)"
  fi

  vault_status="$(kaws exec -n vault vault-0 -- sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status -format=json' 2>/dev/null || true)"
  sealed="$(echo "$vault_status" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("sealed", True))
except Exception:
    print(True)' 2>/dev/null || echo True)"
  if [[ "$sealed" != "False" ]]; then
    log "Unsealing Vault"
    kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 vault operator unseal '$unseal_key'" >/dev/null
  fi

  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault secrets enable -path=secret kv-v2" >/dev/null 2>&1 || true
  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault auth enable kubernetes" >/dev/null 2>&1 || true
  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc:443" >/dev/null
  # Latent capability: a real SMTP relay password for incident-analyzer can be
  # dropped into secret/smtp-secret and consumed via a Vault init container
  # without redeploying Vault. MailHog (the default sink) needs no credential.
  kaws exec -i -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault policy write incident-analyzer -" >/dev/null <<'EOF'
path "secret/data/smtp-secret" {
  capabilities = ["read"]
}
EOF
  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault write auth/kubernetes/role/incident-analyzer bound_service_account_names=incident-analyzer bound_service_account_namespaces=plg-stack policies=incident-analyzer ttl=1h" >/dev/null
  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault kv put secret/smtp-secret password='${SMTP_PASS:-}'" >/dev/null

  # Phần 3.2 (remediation 2026-09) — grafana-smtp-secret VÀ crapi-jwt-key
  # (§4.9 KEHOACH-THAYDOI-HETHONG.md nhận xét đang là k8s Secret trần) nay có
  # Vault làm nguồn sự thật: seed 1 lần nếu Vault chưa có, sau đó LUÔN đọc lại
  # từ Vault (giữ nguyên qua các lần deploy) thay vì phụ thuộc biến môi trường
  # deploy-time hay file vendor cục bộ mỗi lần. k8s Secret vẫn là cơ chế phân
  # phối runtime cho pod (Grafana/bff/crapi-identity không đổi cách đọc) —
  # đây là nơi Vault trở thành nguồn thật, không phải thêm 1 bản sao vô nghĩa.
  kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault kv get -format=json secret/grafana-smtp >/dev/null 2>&1" \
    || kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault kv put secret/grafana-smtp password='${SMTP_PASS:-}'" >/dev/null
  GRAFANA_SMTP_PASSWORD="$(kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault kv get -field=password secret/grafana-smtp" 2>/dev/null)"
  export GRAFANA_SMTP_PASSWORD

  local crapi_jwt_key_file="$REPO_ROOT/deploy/vendor/crapi-keys/jwks.json"
  if [[ -f "$crapi_jwt_key_file" ]] && ! kaws exec -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault kv get -format=json secret/crapi-jwt-key >/dev/null 2>&1"; then
    kaws exec -i -n vault vault-0 -- sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN='$root_token' vault kv put secret/crapi-jwt-key jwks=-" < "$crapi_jwt_key_file" >/dev/null
  fi

  ok "Vault ready: unsealed, kubernetes auth configured, smtp-secret + grafana-smtp + crapi-jwt-key seeded"
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
    --from-file=ztlab-security-overview.json="$REPO_ROOT/plg-stack/grafana/dashboards/ztlab-security-overview.json" \
    --from-file=ztlab-full-logs.json="$REPO_ROOT/plg-stack/grafana/dashboards/ztlab-full-logs.json" \
    --from-file=envoy-access-logs.json="$REPO_ROOT/plg-stack/grafana/dashboards/envoy-access-logs.json" \
    --from-file=opa-decision-log.json="$REPO_ROOT/plg-stack/grafana/dashboards/opa-decision-log.json" \
    --from-file=threat-intel-feed.json="$REPO_ROOT/plg-stack/grafana/dashboards/threat-intel-feed.json" \
    --from-file=incident-evidence-dashboard.json="$REPO_ROOT/plg-stack/grafana/dashboards/incident-evidence-dashboard.json" \
    --from-file=crapi-attack-surface.json="$REPO_ROOT/plg-stack/grafana/dashboards/crapi-attack-surface.json"
  kaws create configmap grafana-alerting -n plg-stack \
    --from-file=brute-force-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/brute-force-alert.yml" \
    --from-file=bfla-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/bfla-alert.yml" \
    --from-file=large-response-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/large-response-alert.yml" \
    --from-file=lateral-movement-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/lateral-movement-alert.yml" \
    --from-file=access-denied-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/access-denied-alert.yml" \
    --from-file=privilege-escalation-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/privilege-escalation-alert.yml" \
    --from-file=incident-analyzer-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/incident-analyzer-alert.yml" \
    --from-file=security-control-plane-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/security-control-plane-alert.yml" \
    --from-file=log-pipeline-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/log-pipeline-alert.yml" \
    --from-file=mesh-integrity-alert.yml="$REPO_ROOT/plg-stack/grafana/alerting/mesh-integrity-alert.yml" \
    --from-file=notification-policy.yml="$REPO_ROOT/plg-stack/grafana/alerting/notification-policy.yml"
}

deploy_observability_response() {
  step "Step 6: PLG, incident-analyzer, Prometheus"

  # Vault stays deployed as the Zero-Trust secrets component; A4 dropped the
  # soar-engine consumer, so no plg-stack redis-auth / keycloak-admin-secret /
  # ai-secrets are needed any more. incident-analyzer notifies via a
  # credential-less in-cluster MailHog.
  deploy_vault_and_seed_secrets

  kaws apply -f "$REPO_ROOT/k8s/plg-stack/loki-configmap.yaml"
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/loki.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack loki 180s

  # Phần 3.2 (remediation 2026-09): giá trị lấy từ Vault (secret/grafana-smtp,
  # seed ở deploy_vault_and_seed_secrets phía trên) — không còn phụ thuộc
  # biến môi trường deploy-time trần. k8s Secret vẫn là cơ chế phân phối cho
  # grafana.yaml's GF_SMTP_PASSWORD (không đổi cách Grafana đọc). Thiếu nó
  # Grafana CreateContainerConfigError-loops forever.
  kaws create secret generic grafana-smtp-secret -n plg-stack \
    --from-literal=password="${GRAFANA_SMTP_PASSWORD:-}" \
    --dry-run=client -o yaml | kaws apply -f -

  # Phần 3.7 remediation (2026-09-19) — audit bí mật tìm thấy: mật khẩu admin
  # Grafana từng hardcode PLAINTEXT trực tiếp trong k8s/plg-stack/grafana.yaml
  # (GF_SECURITY_ADMIN_PASSWORD value: "ZTALab2026!", không qua Secret nào) —
  # trong khi .env.template ĐÃ CÓ sẵn biến GRAFANA_ADMIN_PASSWORD, đúng ý định
  # thiết kế ban đầu, chỉ là chưa từng được nối dây. Cùng mẫu ensure_keycloak_secret
  # (deploy-security-stack.sh) — tạo Secret CHỈ KHI CHƯA TỒN TẠI (đổi mật khẩu
  # ngẫu nhiên mỗi lần re-apply sẽ khoá luôn admin khỏi Grafana của chính họ).
  if ! kaws get secret grafana-admin-secret -n plg-stack >/dev/null 2>&1; then
    kaws create secret generic grafana-admin-secret -n plg-stack \
      --from-literal=admin-user="${GRAFANA_ADMIN_USER:-admin}" \
      --from-literal=admin-password="${GRAFANA_ADMIN_PASSWORD:-$(openssl rand -base64 24)}"
    ok "grafana-admin-secret khởi tạo (từ \$GRAFANA_ADMIN_PASSWORD hoặc ngẫu nhiên)"
  fi

  provision_grafana_configmaps
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/grafana.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack grafana 180s

  kaws apply -f "$REPO_ROOT/k8s/plg-stack/promtail-daemonset.yaml"
  wait_daemonset "$AWS_CONTEXT" plg-stack promtail 180s

  # Muc 1 vong 2026-09-29 — duong log OpenStack -> Loki KHONG con phu thuoc
  # tien trinh nao tren may nguoi dung. Truoc day: Promtail OS -> socat
  # 172.10.10.1:13099 (may deployer) -> kubectl port-forward -> Loki; may ngu /
  # doi mang = mat log am tham (H11). Relay `loki-relay` (socat :31100 tren
  # 10.10.1.11) cung da bo: no chua bao gio dung duoc vi SG chan (xem duoi).
  # Nay: pod OS -> os_gateway -> WireGuard -> aws_gateway (MASQUERADE, nguon =
  # IP private gateway) -> NodePort 31000 cua Service loki tren node AWS.
  # Can SG sg_private mo NodePort cho ${gateway_private_ip}/32
  # (terraform/aws/security_groups.tf) — thieu no thi duong nay bi chan.
  kos apply -f "$REPO_ROOT/k8s/plg-stack/promtail-daemonset.yaml"
  kos set env daemonset/promtail -n plg-stack LOKI_PUSH_URL="$OS_LOKI_PUSH_URL" CLOUD_PROVIDER=openstack
  wait_daemonset "$OS_CONTEXT" plg-stack promtail 180s

  # A4: single detection-side service (no RBAC, no k8s client, no response).
  kaws apply -f "$REPO_ROOT/k8s/plg-stack/incident-analyzer.yaml"
  wait_deployment "$AWS_CONTEXT" plg-stack mailhog 120s
  wait_deployment "$AWS_CONTEXT" plg-stack incident-analyzer 150s

  kaws apply -f "$REPO_ROOT/k8s/monitoring/prometheus.yaml"
  wait_deployment "$AWS_CONTEXT" monitoring prometheus 180s

  ok "PLG, incident-analyzer, and Prometheus ready on AWS"
}

apply_policies_and_ingress() {
  step "Step 7: Ingress"
  # Network policies are applied earlier (apply_network_policies, right after
  # namespaces) so they exist before any pod with restricted egress starts —
  # see the plg-stack → vault NetworkPolicy race that broke soar-engine's
  # vault-fetch-secrets init container on 2026-08-21.
  kaws apply -f "$REPO_ROOT/k8s/ingress.yaml"
  ok "Ingress applied on AWS"
}

verify_final() {
  step "Step 8: Final status"

  log "AWS non-system pods"
  kaws get pods -A | grep -v kube-system || true

  log "OpenStack non-system pods"
  kos get pods -A | grep -v kube-system || true

  verify_observability_stack

  # H8: nghiệm thu kết nối mesh THẬT (request giữa cặp service_acl) — đặt ở cuối
  # để một lỗi tầng app không còn chặn việc dựng stack quan sát, nhưng deploy vẫn
  # KHÔNG báo hoàn tất nếu mesh không thông.
  step "Step 8c: Mesh connectivity acceptance (request thật giữa các cặp service_acl)"
  AWS_CONTEXT="$AWS_CONTEXT" OS_CONTEXT="$OS_CONTEXT" "$REPO_ROOT/scripts/deploy-crapi.sh" --verify-only

  ok "Full multi-cloud deploy flow completed"
}

# Nghiệm thu bắt buộc: stack quan sát/phát hiện PHẢI tồn tại và sẵn sàng, không chỉ "deploy
# xong bước trước". Vòng cuối 2026-09-26 (BAOCAO-CUOI mục 1.1): một cụm từng bị coi là "đã
# redeploy sạch" trong khi KHÔNG có Loki/Grafana/Prometheus (deploy-crapi.sh dừng vì
# verify_mesh_connectivity trước deploy_observability_response, hoặc chỉ chạy lại
# deploy-crapi.sh) — không có bước nào kiểm sự tồn tại của chúng. Hàm này `fail` (không phải
# warn) nếu thiếu, để deploy như vậy KHÔNG BAO GIỜ báo hoàn tất.
verify_observability_stack() {
  step "Step 8b: Observability stack presence (Loki/Grafana/Prometheus/Promtail/incident-analyzer)"
  local missing=()
  local spec ctx ns kind name
  for spec in \
      "$AWS_CONTEXT plg-stack deployment loki" \
      "$AWS_CONTEXT plg-stack deployment grafana" \
      "$AWS_CONTEXT plg-stack deployment incident-analyzer" \
      "$AWS_CONTEXT plg-stack deployment mailhog" \
      "$AWS_CONTEXT monitoring deployment prometheus" \
      "$AWS_CONTEXT plg-stack daemonset promtail" \
      "$OS_CONTEXT plg-stack daemonset promtail"; do
    read -r ctx ns kind name <<<"$spec"
    if ! kubectl --context "$ctx" -n "$ns" rollout status "$kind/$name" --timeout=120s >/dev/null 2>&1; then
      missing+=("$ctx/$ns/$kind/$name")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    fail "stack quan sát KHÔNG sẵn sàng: ${missing[*]} — deploy KHÔNG hoàn tất (không có Loki/Grafana/Prometheus thì không đo được MTTD, không có alert Firing thật). Kiểm: kubectl get pods -n plg-stack -n monitoring"
  fi
  ok "Observability stack present and ready (Loki, Grafana, Prometheus, incident-analyzer, MailHog, Promtail x2)"

  # Mục 1 vòng 2026-09-29: pod Promtail OpenStack "Ready" KHÔNG chứng minh log
  # tới được Loki (đường WireGuard → NodePort có thể bị SG/route chặn, Promtail
  # vẫn Running và chỉ retry). Hỏi Loki trực tiếp: phải có log cloud=openstack
  # trong 5 phút gần nhất, nếu không thì deploy KHÔNG hoàn tất.
  local q n i
  q=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("sum(count_over_time({cloud=\"openstack\"}[5m]))"))')
  for i in $(seq 1 18); do
    n=$(kaws get --raw "/api/v1/namespaces/plg-stack/services/loki:3100/proxy/loki/api/v1/query?query=$q" 2>/dev/null \
        | python3 -c 'import json,sys;r=json.load(sys.stdin)["data"]["result"];print(int(float(r[0]["value"][1])) if r else 0)' 2>/dev/null || echo 0)
    [[ "${n:-0}" -gt 0 ]] && break
    sleep 10
  done
  [[ "${n:-0}" -gt 0 ]] || fail "Loki KHÔNG nhận log nào từ cloud=openstack sau 3 phút — đường Promtail OpenStack → $OS_LOKI_PUSH_URL (WireGuard → NodePort 31000) hỏng. Kiểm SG sg_private (NodePort cho IP private aws_gateway), wg0, và kubectl --context $OS_CONTEXT -n plg-stack logs ds/promtail"
  ok "Log OpenStack tới Loki qua WireGuard ($n dòng / 5 phút)"
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

  regenerate_policy_files
  apply_namespaces
  apply_network_policies
  deploy_gatekeeper
  deploy_spire_pre_istio
  deploy_istio
  sync_images
  deploy_security_stack
  deploy_crapi
  # 4 bước Admin API/SAML của Keycloak PHẢI đứng SAU deploy_crapi (2026-09-25,
  # quan sát sống trên redeploy sạch): deploy-security-stack.sh đã áp
  # keycloak-mesh-policies.yaml (CUSTOM AuthorizationPolicy → OPA
  # opa-service.crapi:9191, fail-closed) từ Step 3, trong khi OPA OpenStack chỉ
  # được dựng ở deploy_crapi (+ netpol keycloak->opa). Chạy chúng trước đó thì
  # Envoy phía Keycloak từ chối MỌI request bằng 403 (token admin-cli 403 ở
  # dòng 6 của script Python). Cùng nguyên nhân với thứ tự register_spire /
  # deploy_crapi_opa / configure_crapi_keycloak trong deploy-crapi.sh main().
  deploy_openldap_and_federation
  deploy_audience_mapper
  deploy_stepup_flow
  deploy_aws_saml_federation
  deploy_observability_response
  apply_policies_and_ingress
  verify_final
}

# Guard so this file can be `source`d to reuse individual functions (e.g. to
# retry a single bootstrap step after a transient failure) without also
# triggering a full main() run — same pattern as deploy-security-stack.sh.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
