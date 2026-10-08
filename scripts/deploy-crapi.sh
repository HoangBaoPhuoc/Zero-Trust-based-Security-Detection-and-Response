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

# See the identical definition + full explanation in scripts/deploy-app.sh —
# kc-crapi-setup below is the same class of short-lived Keycloak Admin API
# bootstrap pod as kc-ldap-federation-setup/kc-audience-mapper-setup/
# kc-stepup-flow-setup/kc-saml-meta there, and needs the same fix (without
# these annotations it silently gets Istio's own CA instead of SPIRE and
# every call to STRICT-mTLS Keycloak fails CERTIFICATE_VERIFY_FAILED).
KC_ADMIN_SETUP_OVERRIDES='{"metadata":{"labels":{"app":"kc-admin-setup"},"annotations":{"sidecar.istio.io/userVolume":"[{\"name\":\"spire-workload-socket\",\"hostPath\":{\"path\":\"/run/spire/sockets/agent.sock\",\"type\":\"Socket\"}}]","sidecar.istio.io/userVolumeMount":"[{\"name\":\"spire-workload-socket\",\"mountPath\":\"/var/run/secrets/workload-spiffe-uds/socket\"}]"}},"spec":{"serviceAccountName":"kc-admin-setup"}}'

# Phần 1 remediation (2026-09-18, phát hiện thêm ngoài danh sách task) — xem
# bản giải thích đầy đủ trong scripts/deploy-app.sh (định nghĩa giống hệt):
# "wait --for=condition=Ready ... || true" rồi exec ngay sau đó NUỐT LỖI wait,
# nên nếu sidecar istio-proxy của kc-crapi-setup chưa Ready (SPIRE cấp SVID
# chậm), python3 gọi Keycloak Admin API qua mesh thất bại rồi bị `|| warn`
# cuối cùng nuốt tiếp — deploy báo "OK" nhưng redirectUris https của client
# `crapi-bff` KHÔNG được áp dụng. Quan sát THẬT trên một lần redeploy sạch
# (2026-09-18): đúng chuỗi này khiến login qua Gateway hỏng hoàn toàn dù
# deploy-crapi.sh không báo lỗi. Sửa: retry wait thật trước khi exec.
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
  kkc run kc-crapi-setup --image=python:3.12-alpine -n identity --restart=Never --overrides="$KC_ADMIN_SETUP_OVERRIDES" --command -- sh -c "sleep 90" >/dev/null 2>&1 || true
  kc_wait_ready kc-crapi-setup
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

# Phần 1.3 (remediation 2026-09): điểm vào HTTPS/mTLS nay là Istio
# IngressGateway (không còn Traefik websecure — xem k8s/crapi/edge-gateway.yaml)
# — giữ luôn các entry HTTP cũ cho tương thích ngược debug (bff bypass :18081/
# :18083 vẫn HTTP, xem KIEM-KE-HOP.md Phần 1.4 — các cổng này đòi hỏi kubeconfig
# của cụm, không phải đường vào Zero-Trust cho thiết bị thật). 18444 = tunnel
# dev cho Gateway (scripts/open-admin-uis.sh); production/NodePort đi qua cổng
# 8443 mặc định nên không cần khai báo cổng riêng.
REDIR=['https://crapi.ztlab.local/*','https://crapi.ztlab.local:18444/*','http://crapi.ztlab.local/*','http://crapi.ztlab.local:8080/*','http://localhost:8080/*','http://localhost:18081/*','http://127.0.0.1:8080/*','http://127.0.0.1:18081/*']
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

# §B1b: pool nạn nhân BOLA — tạo victim01..victim15 trong Keycloak (idempotent,
# 409 → call() trả None) với password Test1234! để N1/crapi_bola đăng nhập được;
# khớp VICTIM_USERS của seed-job.yaml (signup crAPI + claim xe).
VICTIMS=['victim%02d'%k for k in range(1,16)]
for u in VICTIMS:
    ex=call('GET','/admin/realms/%s/users?username=%s&exact=true'%(REALM,u)) or []
    if ex: continue
    call('POST','/admin/realms/%s/users'%REALM,{'username':u,'email':u+'@ztlab.local',
        'enabled':True,'emailVerified':True,'firstName':'Victim','lastName':u[-2:],
        'credentials':[{'type':'password','value':'Test1234!','temporary':False}]})
    print('victim +',u)
ROLE_ADD={'testuser01':['crapi-user'],'testuser02':['crapi-user'],'merchant01':['crapi-user','crapi-mechanic'],
          'analyst01':['soc-analyst'],'demoadmin':['crapi-user','crapi-mechanic','crapi-admin','soc-analyst'],
          'stepup-demo':['crapi-user']}
ROLE_ADD.update({u:['crapi-user'] for u in VICTIMS})
allroles={r['name']:r for r in call('GET','/admin/realms/%s/roles'%REALM)}
for uname,rs in ROLE_ADD.items():
    us=call('GET','/admin/realms/%s/users?username=%s&exact=true'%(REALM,uname)) or []
    if not us: continue
    uid=us[0]['id']
    reps=[{'id':allroles[x]['id'],'name':x} for x in rs if x in allroles]
    call('POST','/admin/realms/%s/users/%s/role-mappings/realm'%(REALM,uid),reps)
    print('user',uname,'+',rs)
print('crapi keycloak config OK')
" || fail "cấu hình Keycloak crapi (client redirectUris + role mappings) THẤT BẠI — login qua BFF sẽ hỏng. Đây là bước bắt buộc, không còn coi là non-fatal (Phần 1 remediation 2026-09-18: silent warn từng để redirectUris https không được áp dụng mà deploy vẫn báo xong). Kiểm tra: kubectl --context \$KEYCLOAK_CONTEXT logs -n identity kc-crapi-setup; chạy lại: bash scripts/deploy-crapi.sh"
  kkc delete pod kc-crapi-setup -n identity --ignore-not-found --wait=false >/dev/null 2>&1 || true
  ok "Keycloak crapi roles/clients ensured"
}

# Phần 3.2 (remediation 2026-09-19) — tạo ConfigMap device-revocation-list
# CHỈ KHI CHƯA TỒN TẠI (không bao giờ qua `kubectl apply` với nội dung tĩnh —
# xem comment trong k8s/crapi/bff.yaml cho lý do: đây là trạng thái vận hành
# động, apply lại sẽ reset danh sách thu hồi). An toàn gọi lại nhiều lần.
ensure_device_revocation_configmap() {
  kaws get configmap device-revocation-list -n crapi >/dev/null 2>&1 && return 0
  kaws create configmap device-revocation-list -n crapi \
    --from-literal=revoked.json='{"revoked_device_ids": []}'
  ok "device-revocation-list ConfigMap khởi tạo (rỗng)"
}

deploy_bff() {
  [[ -d "$REPO_ROOT/services/bff" && -f "$CRAPI_DIR/bff.yaml" ]] || { log "bff chưa có (Phase 2) — bỏ qua"; return; }
  step "BFF (edge PEP + Keycloak) + WAF (ModSecurity/CRS DetectionOnly)"
  ensure_device_revocation_configmap
  kaws apply -f "$CRAPI_DIR/bff.yaml"
  [[ -f "$CRAPI_DIR/waf.yaml" ]] && kaws apply -f "$CRAPI_DIR/waf.yaml"
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
    # Phần 1.2 remediation (2026-09-18): opa.yaml đổi tên 2 object khi sửa
    # inbound sang STRICT — object cũ (PERMISSIVE/DISABLE) không tự mất khi
    # `apply` một manifest đã đổi tên, dọn tường minh để không để lại policy
    # tài liệu-treo (đúng lớp lỗi Phần 2 của task này cảnh báo).
    $k delete peerauthentication opa-permissive -n crapi --ignore-not-found >/dev/null 2>&1 || true
    $k delete destinationrule opa-service-plaintext -n crapi --ignore-not-found >/dev/null 2>&1 || true
  done
  # Giai đoạn B §1.1: CronJob fetch JWKS/discovery cục bộ — CHỈ AWS (chỉ AWS PDP
  # verify token; OpenStack crosscloud không dùng JWKS). opa.yaml mount
  # opa-jwks-data với optional:true nên OpenStack OPA vẫn boot khi CM vắng mặt.
  if [[ -f "$CRAPI_DIR/opa-jwks-cronjob.yaml" ]]; then
    kaws apply -f "$CRAPI_DIR/opa-jwks-cronjob.yaml"
  fi
  wait_rollout "$AWS_CONTEXT" crapi deployment/opa-server 180s
  wait_rollout "$OS_CONTEXT"  crapi deployment/opa-server 180s
  # Seed opa-jwks-data NGAY (không chờ tới 5 phút cho CronJob tick đầu) để OPA
  # verify được token từ đầu. Chạy một Job từ CronJob rồi chờ hoàn tất; OPA
  # (--watch) tự nạp data mới trong vài giây. Fetch lỗi → Job fail, cảnh báo
  # (không chặn deploy — CronJob sẽ thử lại mỗi 5 phút).
  if kaws -n crapi get cronjob opa-jwks-fetcher >/dev/null 2>&1; then
    local seed="jwks-seed-$(date +%s)"
    kaws -n crapi create job "$seed" --from=cronjob/opa-jwks-fetcher >/dev/null 2>&1 || true
    if kaws -n crapi wait --for=condition=complete "job/$seed" --timeout=90s >/dev/null 2>&1; then
      ok "opa-jwks-data đã seed (AWS)"
    else
      warn "seed opa-jwks-data chưa xong — CronJob opa-jwks-fetcher sẽ thử lại mỗi 5'"
    fi
    kaws -n crapi delete job "$seed" --ignore-not-found >/dev/null 2>&1 || true
  fi
  # 2026-10-04 (redeploy lên cụm OpenStack cũ): pod OPA tạo trong lúc
  # SPIRE/istioctl install của deploy-app.sh đang chạy ra KHÔNG có istio-proxy
  # (istiod không hề nhận request inject cho chúng). DestinationRule
  # opa-service-mtls bắt client gọi OPA bằng ISTIO_MUTUAL → sidecar Keycloak
  # không bắt tay được với OPA trần → ext_authz lỗi, fail-closed → MỌI request
  # tới Keycloak 403 UAEX (kể cả /token của kc-crapi-setup ngay bước sau).
  # Ready 1/1 trông "khỏe" nên wait_rollout không bắt được — kiểm tường minh.
  local ctx missing
  for ctx in "$AWS_CONTEXT" "$OS_CONTEXT"; do
    missing="$(kubectl --context "$ctx" -n crapi get pods -l app=opa \
      -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.containers[*].name}{"\n"}{end}' | grep -vc 'istio-proxy' || true)"
    if [[ "${missing:-0}" -gt 0 ]]; then
      warn "$ctx: $missing pod OPA thiếu istio-proxy — restart để inject"
      kubectl --context "$ctx" -n crapi rollout restart deployment/opa-server
      wait_rollout "$ctx" crapi deployment/opa-server 180s
    fi
  done
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
  # OS overlay tắt ingressGateways — thiếu overlay này thì lệnh dưới tái tạo
  # istio-ingressgateway trên OpenStack (không có SPIRE entry ở cluster này,
  # xem k8s/istio/istio-operator-os-overlay.yaml) và treo 5 phút rồi lỗi,
  # đúng bug đã sửa trong deploy-app.sh::deploy_istio — xác nhận sống
  # 2026-09-13 (log "istio OS re-install lỗi" trước khi có dòng này).
  "$istioctl" install --context "$OS_CONTEXT" \
    -f "$REPO_ROOT/k8s/istio/istio-operator.yaml" \
    -f "$REPO_ROOT/k8s/istio/istio-operator-os-overlay.yaml" -y >/dev/null 2>&1 && ok "istio OS" || warn "istio OS re-install lỗi"
}

deploy_mesh_policies() {
  step "Istio mesh policies (PeerAuth + DestinationRule + AuthorizationPolicy→OPA)"
  kaws apply -f "$CRAPI_DIR/istio-policies.yaml"
  kos  apply -f "$CRAPI_DIR/istio-policies.yaml"
  # Phần 1.3 (remediation 2026-09) — biên vào mesh thật, thay Traefik->waf.
  # Cần chạy SAU reinstall_istio_for_crapi_provider (istio-ingressgateway đã
  # tồn tại, đọc secret edge-gateway-tls do provision_device_ca tạo).
  kaws apply -f "$CRAPI_DIR/edge-gateway.yaml"
  kaws apply -f "$REPO_ROOT/k8s/istio/edge-gateway-cert-header.yaml"
  kaws apply -f "$CRAPI_DIR/waf-strip-forged-cert-header.yaml"
  ok "istio-policies + edge-gateway"
}

register_spire() {
  step "SPIRE workload entries cho crapi"
  AWS_CONTEXT="$AWS_CONTEXT" OS_CONTEXT="$OS_CONTEXT" "$REPO_ROOT/scripts/ensure-spire-entries.sh"
}

apply_network_policies() {
  [[ -f "$CRAPI_DIR/network-policies/aws-allow-list.yaml" ]] || { log "network-policies chưa có (Phase 4) — bỏ qua"; return; }
  step "NetworkPolicy L4 (Phase 4) — baseline + pod-segmentation (per-destination)"
  # Sửa 2026-09-25 (đo trực tiếp `nft -a list ruleset` trên node lúc waf->bff
  # trả 503): baseline `{aws,os}-crapi-allow-baseline` có `podSelector: {}` nên
  # default-deny ingress+egress MỌI pod ns crapi. Quyền ingress nội ns theo edge
  # nằm ở `*-pod-segmentation.yaml` — bản trước (2026-09-19) ngừng apply file
  # này dựa trên chẩn đoán "node thiếu ipset nên rule vô hiệu" là SAI: ipset
  # KUBE-SRC-*/KUBE-DST-* có đủ IP pod, k3s tự có binary ipset, và counter
  # `reject` trong chain KUBE-POD-FW-* của pod tăng đúng khi thiếu rule cho
  # phép. Ngừng apply => không còn allow nội ns nào => waf->bff bị reject.
  # Mọi giá trị cổng egress nội ns của baseline nay được generator TÍNH RA từ
  # edge service-graph (gen-networkpolicy.py::_intra_ns_egress_ports) — lần
  # trước thiếu cổng 8080 ở egress cũng làm waf->bff bị reject ở chain của waf.
  kaws apply -f "$CRAPI_DIR/network-policies/aws-allow-list.yaml"
  kos  apply -f "$CRAPI_DIR/network-policies/os-allow-list.yaml"
  kaws apply -f "$CRAPI_DIR/network-policies/aws-pod-segmentation.yaml"
  kos  apply -f "$CRAPI_DIR/network-policies/os-pod-segmentation.yaml"
  ok "network-policies (baseline + pod-segmentation)"
}

restart_workloads_for_sds() {
  # Istio-proxy (SDS client) không tự tái lập stream tới spire-agent sau khi
  # spire-agent bị restart / entry SPIRE thêm sau khi sidecar đã start → SVID
  # hết hạn ở mốc TTL 1h mà KHÔNG được gia hạn → `svid:null` → mТLS STRICT fail
  # → mọi hop nội mesh 503 (xem KET-QUA-KIEM-TRA.md T-2.1). Fix: sau khi SPIRE
  # entries + DestinationRule custom-SAN + AuthorizationPolicy đã sẵn sàng, bounce
  # toàn bộ Deployment nghiệp vụ để istio-proxy tái lập SDS sạch.
  #
  # Phần 1.1 remediation (2026-09-19, BAOCAO-VONG-2026-09-19.md) — TRƯỚC bản
  # sửa này: `rollout restart deployment` (không tên cụ thể) restart TẤT CẢ
  # deployment trong ns CÙNG LÚC trên CẢ 2 CLUSTER — xác nhận sống đây CHÍNH
  # LÀ kịch bản "restart đồng thời nhiều workload" gây ra
  # diagnostics/2026-09-19-mesh-connectivity-incident (root cause thật: lỗi
  # nền tảng iptables-legacy/nf_tables của network-policy controller nhúng
  # trong k3s — cùng họ với AUDIT-THUC-THI.md §3.2, nhưng có lúc chặn nhầm cả
  # traffic HỢP LỆ, không tự phục hồi). KHÔNG vá được lỗi nền tảng đó, nên đổi
  # sang restart TUẦN TỰ từng deployment + chờ rollout xong thật, giảm số pod
  # churn đồng thời trên cùng node.
  step "Restart workload crAPI để istio-proxy tái lập SDS/mТLS (sau SPIRE + mesh policy) — TUẦN TỰ"
  local d
  for d in $(kaws -n crapi get deployment -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    kaws -n crapi rollout restart "deployment/$d" 2>/dev/null || true
    wait_rollout "$AWS_CONTEXT" crapi "deployment/$d" 240s
  done
  for d in $(kos -n crapi get deployment -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    kos -n crapi rollout restart "deployment/$d" 2>/dev/null || true
    wait_rollout "$OS_CONTEXT" crapi "deployment/$d" 240s
  done
  ok "workloads restarted tuần tự — SVID nên VALID trở lại (kiểm: istioctl proxy-config secret deploy/crapi-workshop -n crapi)"
}

verify_mesh_connectivity() {
  # Phần 1.1 remediation (2026-09-19, BAOCAO-VONG-2026-09-19.md) — `kubectl
  # get pods` Ready KHÔNG đủ để coi là "đã verify": xác nhận sống 2026-09-19
  # một cụm với TOÀN BỘ pod 2/2 Running vẫn có waf->bff (đúng cặp
  # service_acl cho phép) trả 503/"Connection refused" ở tầng L4 (lỗi nền
  # tảng iptables-legacy/nf_tables của kube-router nhúng trong k3s, xem
  # restart_workloads_for_sds() + AUDIT-THUC-THI.md §3.2) — im lặng, không
  # `kubectl get pods` nào phát hiện ra. Gọi request THẬT giữa 1-2 cặp
  # service_acl cho phép, kiểm HTTP code thật — deploy nào dính lỗi này FAIL
  # RÕ RÀNG thay vì báo "OK" giả.
  step "Kiểm connectivity THẬT giữa các service (không chỉ đọc trạng thái Ready)"
  local ok_all=true

  local wpod
  wpod="$(kaws -n crapi get pod -l app=waf -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
  if [[ -n "$wpod" ]]; then
    local code
    code="$(kaws -n crapi exec "$wpod" -c waf -- curl -s -o /dev/null -w '%{http_code}' -m 8 http://bff.crapi.svc.cluster.local:8080/health 2>/dev/null || echo 000)"
    if [[ "$code" == "200" ]]; then
      ok "waf -> bff (AWS, nội cụm): HTTP $code"
    else
      ok_all=false
      warn "waf -> bff (AWS): HTTP $code (kỳ vọng 200) — nghi mesh-connectivity đã biết (BAOCAO-VONG-2026-09-19.md mục 1.1). Kiểm: kubectl --context $AWS_CONTEXT -n crapi exec $wpod -c waf -- curl -v http://bff.crapi.svc.cluster.local:8080/health"
    fi
  else
    warn "Không có pod waf để kiểm connectivity — bỏ qua"
  fi

  local cpod
  cpod="$(kaws -n crapi get pod -l app=crapi-community -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
  if [[ -n "$cpod" ]]; then
    local code2
    code2="$(kaws -n crapi exec "$cpod" -c crapi-community -- curl -s -o /dev/null -w '%{http_code}' -m 8 http://crapi-identity-openstack.crapi.svc.cluster.local:30090/identity/health_check 2>/dev/null || echo 000)"
    if [[ "$code2" == "200" ]]; then
      ok "crapi-community -> crapi-identity (cross-cloud): HTTP $code2"
    else
      ok_all=false
      warn "crapi-community -> crapi-identity (cross-cloud): HTTP $code2 (kỳ vọng 200) — kiểm: kubectl --context $AWS_CONTEXT -n crapi exec $cpod -c crapi-community -- curl -v http://crapi-identity-openstack.crapi.svc.cluster.local:30090/identity/health_check"
    fi
  else
    warn "Không có pod crapi-community để kiểm connectivity — bỏ qua"
  fi

  if [[ "$ok_all" == "true" ]]; then
    ok "mesh connectivity: TẤT CẢ cặp kiểm đều thông"
  elif [[ "${ZTLAB_DEFER_ACCEPTANCE:-0}" == "1" ]]; then
    # H8 (2026-10-04): trong đường deploy đầy đủ (deploy-app.sh), nghiệm thu
    # KHÔNG được chặn các bước sau — chính `fail` ở đây từng khiến stack quan
    # sát không bao giờ được dựng (BAOCAO-CUOI mục 1.1). deploy-app.sh chạy lại
    # hàm này (--verify-only, không hoãn) ở verify_final, sau khi mọi thứ đã dựng.
    warn "mesh connectivity: có cặp KHÔNG thông — HOÃN nghiệm thu tới cuối deploy-app.sh (verify_final)"
  else
    fail "mesh connectivity: có cặp KHÔNG thông (chi tiết ở trên). Nguyên nhân thật đã gặp (2026-09-25): NetworkPolicy — baseline aws-/os-crapi-allow-baseline default-deny cả ingress+egress mọi pod ns crapi; nếu thiếu cổng ở egress baseline hoặc chưa apply *-pod-segmentation.yaml thì kube-router \`reject\` SYN (envoy báo 503 'delayed connect error: 111'). Kiểm: kubectl -n crapi get netpol (phải có aws-pod-*), và trên node đích: sudo nft -a list ruleset | grep -E 'reject' | grep -E 'packets [1-9]' để thấy chain KUBE-POD-FW-* nào đang reject. KHÔNG phải lỗi ipset (k3s tự có ipset). Restart pod đơn lẻ không khỏi."
  fi
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
  verify_mesh_connectivity
}

main() {
  verify_contexts
  create_secrets
  apply_namespace_and_config
  deploy_databases
  deploy_crapi_workloads
  # register_spire + deploy_crapi_opa PHẢI đứng trước configure_crapi_keycloak
  # (remediation 2026-09-19, phát hiện trên fresh deploy sạch): k8s/identity/
  # keycloak-mesh-policies.yaml (áp bởi deploy-security-stack.sh, chạy TRƯỚC
  # deploy-crapi.sh trong deploy-all.sh) đã đặt Keycloak STRICT mTLS + CUSTOM
  # AuthorizationPolicy gọi PDP tại opa-service.crapi.svc.cluster.local:9191
  # (failure_mode_allow: false — fail-closed). Với thứ tự cũ,
  # configure_crapi_keycloak() (kc-crapi-setup gọi Keycloak Admin API) chạy
  # TRƯỚC deploy_crapi_opa() dựng chính OPA đó → ext_authz không có backend
  # để gọi → Envoy từ chối MỌI request tới Keycloak với 403 (xác nhận sống:
  # istio-proxy log phía Keycloak "upstream":null,"response_time":0 — bị chặn
  # ở proxy, chưa từng tới app — trong khi mТLS đã đúng, svid đã đúng
  # spiffe://ztlab.local/openstack/kc-admin-setup). Không phải lỗi thoáng qua
  # của cluster; sửa tại đây để mọi lần deploy-from-scratch không dính lại.
  register_spire
  deploy_crapi_opa
  # apply_network_policies PHẢI đứng ngay sau deploy_crapi_opa, TRƯỚC
  # configure_crapi_keycloak (remediation 2026-09-19, phát hiện NGAY SAU khi
  # sửa bug ở trên — bug này trước giờ luôn bị bug OPA-chưa-tồn-tại che mất,
  # chưa ai chạy tới đây để lộ ra): edge `openstack/keycloak -> openstack/opa`
  # (policy/service-graph-crapi.yaml dòng ~210, đã khai đúng từ 2026-09-13) chỉ
  # sinh ra manifest os-pod-opa ĐÚNG (NetworkPolicy cho phép ns identity/app
  # keycloak gọi cổng 9191+8181) — file đó nằm im tới tận cuối main() cũ vì
  # apply_network_policies() là bước THẬT SỰ `kubectl apply` nó. Trước
  # configure_crapi_keycloak, cluster mới chỉ có os-crapi-allow-baseline (rule
  # ipBlock chung, cổng [8080,5432,15006,8181] — KHÔNG có 9191) → NetworkPolicy
  # ns crapi CHẶN THẬT ext_authz L4 (xác nhận sống bằng curl thẳng TCP tới
  # opa-server:9191 từ sidecar Keycloak: "Connection refused" trên cả 3 pod
  # opa, trong khi :8181 luôn thành công — LƯU Ý: điều này ngược lại kết luận
  # "NetworkPolicy ns crapi không được kube-router enforce" của
  # AUDIT-THUC-THI.md 2026-09-19 cho các rule ipBlock/rule rỗng cổng khác; rule
  # port-list đơn giản này RÕ RÀNG có hiệu lực thật trên hạ tầng đang dùng).
  # kc-crapi-setup vẫn 403 y hệt bug OPA dù OPA đã Ready — root cause khác,
  # cùng lớp lỗi "thứ tự áp chính sách" trong main() này.
  apply_network_policies
  configure_crapi_keycloak
  deploy_bff
  reinstall_istio_for_crapi_provider
  deploy_mesh_policies
  restart_workloads_for_sds
  run_seed
  verify
  ok "deploy-crapi hoàn tất"
}

# Guard so this file can be `source`d to retry a single function without
# also triggering a full main() run — same pattern as deploy-app.sh /
# deploy-security-stack.sh.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ "${1:-}" == "--verify-only" ]]; then
    verify_contexts
    verify_mesh_connectivity
  else
    main "$@"
  fi
fi
