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
# A1: Keycloak trên cụm OpenStack — bước Admin API dùng context này.
KEYCLOAK_CONTEXT="${KEYCLOAK_CONTEXT:-$OS_CONTEXT}"
kkc()  { kubectl --context "$KEYCLOAK_CONTEXT" "$@"; }

# kubectl apply chỉ khi manifest có ít nhất 1 object. Bỏ qua file toàn comment
# (vd cross-cloud-os.yaml khi mailhog nằm cùng cluster identity → không có hop
# cross-cloud) — `kubectl apply` trên file rỗng thoát mã 1 "no objects passed
# to apply", `set -e` giết cả script trên đường deploy-from-scratch.
apply_manifest() { # <kaws|kos> <file>
  local kc="$1" file="$2"
  if [[ -s "$file" ]] && grep -vE '^[[:space:]]*(#|---|$)' "$file" | grep -q '[^[:space:]]'; then
    $kc apply -f "$file"
  else
    log "$(basename "$file"): không có object YAML — bỏ qua"
  fi
}

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
  step "crAPI workloads — identity + mailhog (OpenStack) + web/community/workshop (AWS)"
  kos  apply -f "$CRAPI_DIR/mailhog.yaml"
  kos  apply -f "$CRAPI_DIR/os-workloads.yaml"
  kaws apply -f "$CRAPI_DIR/aws-workloads.yaml"
  apply_manifest kaws "$CRAPI_DIR/cross-cloud-aws.yaml"
  apply_manifest kos  "$CRAPI_DIR/cross-cloud-os.yaml"
  wait_rollout "$OS_CONTEXT"  crapi deployment/mailhog 180s
  wait_rollout "$OS_CONTEXT"  crapi deployment/crapi-identity 300s
  for d in crapi-web crapi-community crapi-workshop; do
    wait_rollout "$AWS_CONTEXT" crapi "deployment/$d" 300s
  done
  kaws apply -f "$CRAPI_DIR/posture-agent-cronjob.yaml"
  kos  apply -f "$CRAPI_DIR/posture-agent-cronjob.yaml"
  ok "crAPI workloads"
}

configure_crapi_keycloak() {
  step "Keycloak — role crapi-* + client crapi-bff/-stepup (Admin API, idempotent)"
  # realm-config.json khai báo sẵn cho FRESH import; --import-realm KHÔNG
  # retrofit lên realm đã import → đăng ký live luôn (mẫu deploy_audience_mapper).
  local admin_pass
  admin_pass="$(kkc get secret keycloak-secret -n identity -o jsonpath='{.data.admin-password}' 2>/dev/null | base64 -d)"
  [[ -n "$admin_pass" ]] || { warn "Không lấy được keycloak admin-password — bỏ qua"; return; }
  kkc delete pod kc-crapi-setup -n identity --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kkc run kc-crapi-setup --image=python:3.12-alpine -n identity --restart=Never --command -- sh -c "sleep 90" >/dev/null 2>&1 || true
  kubectl --context "$KEYCLOAK_CONTEXT" wait --for=condition=Ready pod/kc-crapi-setup -n identity --timeout=60s >/dev/null 2>&1 || true
  kubectl --context "$KEYCLOAK_CONTEXT" exec -n identity kc-crapi-setup -- python3 -c "
import urllib.request, json, urllib.parse
KC='http://keycloak.identity.svc.cluster.local:8080'; REALM='ztlab'
def call(method, path, body=None):
    data=json.dumps(body).encode() if body is not None else None
    h=dict(H)
    if data is not None: h['Content-Type']='application/json'
    req=urllib.request.Request(KC+path, data=data, headers=h, method=method)
    try:
        r=urllib.request.urlopen(req); raw=r.read(); return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        if e.code in (404,409): return None
        raise RuntimeError('%s %s -> %s: %s'%(method,path,e.code,e.read().decode()))
tok=urllib.parse.urlencode({'grant_type':'password','client_id':'admin-cli','username':'admin','password':'$admin_pass'}).encode()
H={'Authorization':'Bearer '+json.load(urllib.request.urlopen(urllib.request.Request(KC+'/realms/master/protocol/openid-connect/token',data=tok)))['access_token']}

roles={r['name'] for r in (call('GET','/admin/realms/%s/roles'%REALM) or [])}
for name,desc in [('crapi-user','crAPI user'),('crapi-mechanic','crAPI mechanic'),('crapi-admin','crAPI admin'),('soc-analyst','SOC analyst')]:
    if name not in roles:
        call('POST','/admin/realms/%s/roles'%REALM,{'name':name,'description':desc}); print('role +',name)

# A3: điểm vào HTTPS/mTLS (Traefik websecure) thay cổng HTTP cũ (8080/18081) —
# giữ luôn các entry HTTP cũ cho tương thích ngược debug (bff bypass :18083 vẫn
# HTTP). 18443 = tunnel dev (scripts/open-admin-uis.sh); production/NodePort đi
# qua cổng 443 mặc định nên không cần khai báo cổng riêng.
REDIR=['https://crapi.ztlab.local/*','https://crapi.ztlab.local:18443/*','http://crapi.ztlab.local/*','http://crapi.ztlab.local:8080/*','http://localhost:8080/*','http://localhost:18081/*','http://127.0.0.1:8080/*','http://127.0.0.1:18081/*']
for cid in ('crapi-bff','crapi-bff-stepup'):
    ex=call('GET','/admin/realms/%s/clients?clientId=%s'%(REALM,cid)) or []
    if ex:
        cur=ex[0]
        if set(cur.get('redirectUris') or []) != set(REDIR):
            call('PUT','/admin/realms/%s/clients/%s'%(REALM,cur['id']),{**cur,'redirectUris':REDIR})
            print('client',cid,'redirectUris updated')
        else:
            print('client',cid,'exists, redirectUris up to date')
        continue
    call('POST','/admin/realms/%s/clients'%REALM,{
        'clientId':cid,'protocol':'openid-connect','publicClient':True,'standardFlowEnabled':True,
        'directAccessGrantsEnabled':False,'redirectUris':REDIR,'webOrigins':['+'],
        'attributes':{'pkce.code.challenge.method':'S256'},
        'protocolMappers':[{'name':'aud-crapi-bff','protocol':'openid-connect','protocolMapper':'oidc-audience-mapper',
            'consentRequired':False,'config':{'included.client.audience':'crapi-bff','id.token.claim':'false','access.token.claim':'true'}}]})
    print('client +',cid)

ROLE_ADD={'testuser01':['crapi-user'],'testuser02':['crapi-user'],'merchant01':['crapi-user','crapi-mechanic'],
          'analyst01':['soc-analyst'],'demoadmin':['crapi-user','crapi-mechanic','crapi-admin','soc-analyst'],
          'stepup-demo':['crapi-user']}
allroles={r['name']:r for r in call('GET','/admin/realms/%s/roles'%REALM)}
for uname,rs in ROLE_ADD.items():
    us=call('GET','/admin/realms/%s/users?username=%s&exact=true'%(REALM,uname)) or []
    if not us: continue
    uid=us[0]['id']
    reps=[{'id':allroles[x]['id'],'name':x} for x in rs if x in allroles]
    call('POST','/admin/realms/%s/users/%s/role-mappings/realm'%(REALM,uid),reps)
    print('user',uname,'+',rs)
print('crapi keycloak config OK')
" || warn "cấu hình Keycloak crapi lỗi (non-fatal — login bff sẽ hỏng cho tới khi sửa)"
  kkc delete pod kc-crapi-setup -n identity --ignore-not-found --wait=false >/dev/null 2>&1 || true
  ok "Keycloak crapi roles/clients ensured"
}

deploy_bff() {
  [[ -d "$REPO_ROOT/services/bff" && -f "$CRAPI_DIR/bff.yaml" ]] || { log "bff chưa có (Phase 2) — bỏ qua"; return; }
  step "BFF (edge PEP + Keycloak) + WAF (ModSecurity/CRS DetectionOnly)"
  kaws apply -f "$CRAPI_DIR/bff.yaml"
  [[ -f "$CRAPI_DIR/waf.yaml" ]] && kaws apply -f "$CRAPI_DIR/waf.yaml"
  kaws apply -f "$CRAPI_DIR/ingress-aws.yaml"
  kos apply -f "$CRAPI_DIR/ingress-os.yaml"
  wait_rollout "$AWS_CONTEXT" crapi deployment/bff 240s
  [[ -f "$CRAPI_DIR/waf.yaml" ]] && wait_rollout "$AWS_CONTEXT" crapi deployment/waf 240s
  ok "bff + waf"
}

deploy_crapi_opa() {
  [[ -f "$CRAPI_DIR/opa.yaml" ]] || { log "opa.yaml chưa có (Phase 3) — bỏ qua"; return; }
  step "OPA PDP cho crapi (2 cluster, path khác nhau)"
  python3 "$REPO_ROOT/scripts/gen-rego-acl.py" --crapi
  python3 "$REPO_ROOT/scripts/gen-networkpolicy.py" --crapi 2>/dev/null || true
  # opa-config per-cluster
  kaws -n crapi create configmap opa-config --from-literal=opa-config.yaml="$(printf 'plugins:\n  envoy_ext_authz_grpc:\n    addr: :9191\n    path: zta/crapi/authz/allow\ndecision_logs:\n  console: true\n')" --dry-run=client -o yaml | kaws apply -f -
  kos  -n crapi create configmap opa-config --from-literal=opa-config.yaml="$(printf 'plugins:\n  envoy_ext_authz_grpc:\n    addr: :9191\n    path: zta/crapi/crosscloud/allow\ndecision_logs:\n  console: true\n')" --dry-run=client -o yaml | kos apply -f -
  for k in kaws kos; do
    $k -n crapi create configmap opa-policies-crapi --from-file="$REPO_ROOT/opa/crapi-policies" --dry-run=client -o yaml | $k apply -f -
    $k apply -f "$CRAPI_DIR/opa.yaml"
  done
  wait_rollout "$AWS_CONTEXT" crapi deployment/opa-server 180s
  wait_rollout "$OS_CONTEXT"  crapi deployment/opa-server 180s
  ok "crapi OPA ready (2 cluster)"
}

reinstall_istio_for_crapi_provider() {
  # extensionProvider opa-ext-authz-crapi mới thêm vào istio-operator.yaml —
  # cần re-install istio (idempotent) để meshConfig có nó.
  local istioctl="istioctl"
  command -v istioctl >/dev/null 2>&1 || istioctl="$REPO_ROOT/.istio-1.22.3/bin/istioctl"
  [[ -x "$istioctl" || -n "$(command -v istioctl)" ]] || { warn "istioctl không có — bỏ qua re-install (provider crapi sẽ thiếu)"; return; }
  step "Re-install Istio (meshConfig: +extensionProvider opa-ext-authz-crapi)"
  "$istioctl" install --context "$AWS_CONTEXT" -f "$REPO_ROOT/k8s/istio/istio-operator.yaml" -y >/dev/null 2>&1 && ok "istio AWS" || warn "istio AWS re-install lỗi"
  "$istioctl" install --context "$OS_CONTEXT"  -f "$REPO_ROOT/k8s/istio/istio-operator.yaml" -y >/dev/null 2>&1 && ok "istio OS" || warn "istio OS re-install lỗi"
}

deploy_mesh_policies() {
  step "Istio mesh policies (PeerAuth + DestinationRule + AuthorizationPolicy→OPA)"
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

restart_workloads_for_sds() {
  # Istio-proxy (SDS client) không tự tái lập stream tới spire-agent sau khi
  # spire-agent bị restart / entry SPIRE thêm sau khi sidecar đã start → SVID
  # hết hạn ở mốc TTL 1h mà KHÔNG được gia hạn → `svid:null` → mТLS STRICT fail
  # → mọi hop nội mesh 503 (xem KET-QUA-KIEM-TRA.md T-2.1). Fix: sau khi SPIRE
  # entries + DestinationRule custom-SAN + AuthorizationPolicy đã sẵn sàng, bounce
  # toàn bộ Deployment nghiệp vụ để istio-proxy tái lập SDS sạch.
  step "Restart workload crAPI để istio-proxy tái lập SDS/mТLS (sau SPIRE + mesh policy)"
  kaws -n crapi rollout restart deployment 2>/dev/null || true
  kos  -n crapi rollout restart deployment 2>/dev/null || true
  for d in bff crapi-web crapi-community crapi-workshop; do
    wait_rollout "$AWS_CONTEXT" crapi "deployment/$d" 240s
  done
  wait_rollout "$OS_CONTEXT" crapi deployment/crapi-identity 240s
  wait_rollout "$OS_CONTEXT" crapi deployment/mailhog 180s
  ok "workloads restarted — SVID nên VALID trở lại (kiểm: istioctl proxy-config secret deploy/crapi-workshop -n crapi)"
}

run_seed() {
  [[ -f "$CRAPI_DIR/seed-job.yaml" ]] || { log "seed-job chưa có — bỏ qua"; return; }
  step "Seed dữ liệu crAPI (Job trên OpenStack — thao tác app, KHÔNG phải hạ tầng)"
  kos delete job crapi-seed -n crapi --ignore-not-found >/dev/null 2>&1 || true
  kos apply -f "$CRAPI_DIR/seed-job.yaml"
  kos wait --for=condition=complete job/crapi-seed -n crapi --timeout=300s \
    && kos logs job/crapi-seed -c seed -n crapi 2>/dev/null | tail -8 \
    || warn "seed job chưa complete (xem: kubectl --context $OS_CONTEXT -n crapi logs job/crapi-seed -c seed)"
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
  configure_crapi_keycloak
  deploy_bff
  register_spire
  deploy_crapi_opa
  reinstall_istio_for_crapi_provider
  deploy_mesh_policies
  apply_network_policies
  restart_workloads_for_sds
  run_seed
  verify
  ok "deploy-crapi hoàn tất"
}

main "$@"
