#!/bin/bash
# Idempotently ensure all SPIRE registration entries this app needs exist.
#
# Why this is a separate, standalone script (not just a function inside
# deploy-security-stack.sh): SPIRE's datastore (sqlite3 on a node-pinned
# hostPath — see k8s/spire/*.yaml) has no automatic backup. If the
# spire-server pod is ever recreated in a way that loses that hostPath
# content, every workload registration entry vanishes silently and stays
# gone until someone re-registers them — meanwhile istio-proxy's
# SPIRE-backed SDS keeps failing ("workload is not authorized for the
# requested identities [\"default\"]") for any pod created after the wipe,
# while pods created before it keep working off their already-cached SVID.
# This makes the failure look like an unrelated, delayed Istio/mTLS bug
# (observed once in practice: took over an hour to trace back to 0
# registration entries on spire-server).
#
# deploy-security-stack.sh calls this once as part of the full security
# stack pass, but deploy-app.sh's deploy_financial_services() ALSO calls it
# on every run, unconditionally (not gated behind --skip-security-stack) —
# so a wiped datastore self-heals on the very next `deploy-app.sh` run
# instead of silently breaking whatever pod happens to restart next.
#
# Usage: AWS_CONTEXT=ctx-aws OS_CONTEXT=ctx-openstack ./ensure-spire-entries.sh

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"
TIMEOUT_WAIT="${TIMEOUT_WAIT:-180}"

# Danh sách workload + số lượng kỳ vọng — sinh từ policy/service-graph-crapi.yaml
# (scripts/gen-spire-entries.py, Phần 2 remediation 2026-09). KHÔNG hardcode ở
# đây nữa — sửa graph rồi chạy lại generator, đừng sửa file .generated.sh.
# shellcheck source=/dev/null
source "$ROOT_DIR/scripts/spire-entries.generated.sh"

log_info()  { echo "[SPIRE-ENTRIES] $*"; }
log_error() { echo "[SPIRE-ENTRIES][ERROR] $*" >&2; }

# Real failures must surface immediately (exit non-zero) — only "this exact
# entry already exists" is safe to treat as success on a re-run.
# --- Transient K8s API connectivity -------------------------------------------
# ctx-aws/ctx-openstack đi qua SSH tunnel (scripts/k8s-tunnel.sh) trên uplink
# hotspot của máy aio. Uplink chập chờn vài chục giây là chuyện thường: tunnel
# SSH vẫn sống (ServerAlive 30s x3) nhưng request kubectl trong lúc đó chết với
# "Unable to connect to the server: net/http: TLS handshake timeout" — k3s phía
# sau hoàn toàn khỏe (xác nhận live 2026-09-26: NRestarts=0, load 0.1). Trước
# đây mọi lệnh kubectl ở script này coi lỗi đó là lỗi thật: wait_rollout đốt
# hết 2 lượt thử trong ~20s và cả deploy chết, dù rollout đã xong từ lâu.
# Các lỗi dưới đây nghĩa là "chưa nói chuyện được với API server", KHÔNG phải
# "workload hỏng" — retry an toàn (entry create lặp lại → AlreadyExists = OK).
TRANSIENT_API_RE='Unable to connect to the server|The connection to the server .* was refused|TLS handshake timeout|i/o timeout|connection refused|connection reset by peer|context deadline exceeded|client connection lost|unexpected EOF|error dialing backend|http2: server sent GOAWAY|the server is currently unable to handle the request'
API_RETRIES="${API_RETRIES:-6}"

is_transient_api_error() { grep -Eq "$TRANSIENT_API_RE" <<<"$1"; }

# Kiểm tra API qua tunnel; nếu không trả lời thì nhờ k8s-tunnel.sh dựng lại
# tunnel của đúng cloud đó (nó chỉ restart khi /readyz thật sự fail). Không
# bao giờ làm script chết — vòng retry của caller mới quyết định bỏ cuộc.
heal_api() {
  local ctx="$1" scope
  kubectl --context "$ctx" get --raw=/readyz --request-timeout=10s >/dev/null 2>&1 && return 0
  case "$ctx" in
    "$AWS_CONTEXT") scope=aws ;;
    "$OS_CONTEXT")  scope=openstack ;;
    *) return 0 ;;
  esac
  log_info "K8s API $ctx không phản hồi — kiểm tra/dựng lại tunnel ($scope)..."
  "$ROOT_DIR/scripts/k8s-tunnel.sh" up "$scope" >&2 || log_error "k8s-tunnel.sh up $scope thất bại (sẽ thử lại)"
}

# spire-server CLI qua kubectl exec, retry khi lỗi kết nối tạm thời.
# In stdout+stderr ra stdout; exit code = của lượt cuối.
spire_server_exec() {
  local ctx="$1"; shift
  local out rc attempt
  for ((attempt = 1; attempt <= API_RETRIES; attempt++)); do
    rc=0
    out=$(kubectl --context "$ctx" -n spire exec deploy/spire-server -- /opt/spire/bin/spire-server "$@" \
      -socketPath /tmp/spire-server/private/api.sock 2>&1) || rc=$?
    if [ "$rc" -eq 0 ] || ! is_transient_api_error "$out"; then
      printf '%s\n' "$out"
      return "$rc"
    fi
    log_error "kubectl exec spire-server ($ctx) lỗi kết nối tạm thời (lượt $attempt/$API_RETRIES): $(head -1 <<<"$out")"
    heal_api "$ctx"
    sleep $((attempt * 5))
  done
  printf '%s\n' "$out"
  return "$rc"
}

_spire_entry_create() {
  local ctx="$1"; shift
  local out
  if out=$(spire_server_exec "$ctx" entry create "$@"); then
    return 0
  fi
  if echo "$out" | grep -q "AlreadyExists\|similar entry already exists"; then
    return 0
  fi
  log_error "spire-server entry create failed (ctx=$ctx): $out"
  return 1
}

# TTL X.509-SVID của workload (giây). Entry mang TTL riêng thì GHI ĐÈ
# default_x509_svid_ttl của server.conf — nên phải đặt ở đây, không chỉ ở server.
# 2026-10-04 (mục 2.2 đóng sổ): 1h → 4h. Quyết định cụm chịu được gián đoạn
# SPIRE/WireGuard bao lâu trước khi SVID hết hạn và mТLS STRICT sập dây chuyền
# (§10.2 sự cố số một). Đánh đổi: cert workload bị lộ sống lâu hơn (H17).
SPIRE_X509_SVID_TTL="${SPIRE_X509_SVID_TTL:-14400}"

register_spire_entry() {
  local ctx="$1" spiffe_id="$2" parent_id="$3" ns="$4" sa="$5" out rc=0
  out=$(spire_server_exec "$ctx" entry create \
    -spiffeID "$spiffe_id" -parentID "$parent_id" \
    -selector "k8s:ns:${ns}" -selector "k8s:sa:${sa}" -x509SVIDTTL "$SPIRE_X509_SVID_TTL") || rc=$?
  [ "$rc" -eq 0 ] && return 0
  if ! echo "$out" | grep -q "AlreadyExists\|similar entry already exists"; then
    log_error "spire-server entry create failed (ctx=$ctx): $out"
    return 1
  fi
  # Entry đã có (cụm đang chạy): hội tụ TTL nếu lệch, không thì giữ nguyên.
  local cur
  cur=$(spire_server_exec "$ctx" entry show -spiffeID "$spiffe_id" -parentID "$parent_id" -output json 2>/dev/null \
    | python3 -c 'import json,sys
e=(json.load(sys.stdin).get("entries") or [{}])[0]
print(e.get("id",""), e.get("x509_svid_ttl",""))' 2>/dev/null) || true
  local eid="${cur%% *}" ttl="${cur##* }"
  [ -z "$eid" ] && return 0
  [ "$ttl" = "$SPIRE_X509_SVID_TTL" ] && return 0
  spire_server_exec "$ctx" entry update -entryID "$eid" \
    -spiffeID "$spiffe_id" -parentID "$parent_id" \
    -selector "k8s:ns:${ns}" -selector "k8s:sa:${sa}" -x509SVIDTTL "$SPIRE_X509_SVID_TTL" >/dev/null \
    || { log_error "entry update TTL thất bại ($ctx $spiffe_id)"; return 1; }
}

# Đăng ký toàn bộ workload của một cluster từ mảng "<spiffe_id>:<ns>:<sa>" sinh
# bởi gen-spire-entries.py (xem spire-entries.generated.sh).
register_spire_entries_from_generated() {
  local ctx="$1" parent="$2"; shift 2
  local entry spiffe_id ns sa
  for entry in "$@"; do
    IFS='|' read -r spiffe_id ns sa <<<"$entry"
    register_spire_entry "$ctx" "$spiffe_id" "$parent" "$ns" "$sa"
  done
}

register_node_alias() {
  local ctx="$1" spiffe_id="$2" cluster="$3"
  # Parented to the SPIRE server itself (-node), matched via the
  # k8s_psat:cluster:<name> selector every agent in this cluster gets
  # regardless of its own per-node UUID — so workload entries (parented to
  # this alias) survive node/agent replacement without being redone.
  _spire_entry_create "$ctx" \
    -node -spiffeID "$spiffe_id" -selector "k8s_psat:cluster:${cluster}"
}

# Count entries whose SPIFFE ID contains the given substring — used both to
# confirm each register_spire_entry above actually landed, and as a final
# sanity gate so an empty/wiped datastore is caught at deploy time instead
# of surfacing later as an unrelated-looking pod readiness failure.
count_entries_matching() {
  local ctx="$1" pattern="$2"
  local out
  # Lỗi (kể cả sau khi đã retry) → in 0 để gate bên dưới báo lỗi rõ ràng,
  # thay vì grep nhầm trên thông báo lỗi.
  out=$(spire_server_exec "$ctx" entry show) || { echo 0; return 0; }
  grep -c "$pattern" <<<"$out" || true
}

# A single slow-to-attest spire-agent pod (lab nodes are resource-constrained
# and the OpenStack cluster's uplink is a phone hotspot — see docs on uplink
# fragility) can take longer than one TIMEOUT_WAIT window to go Ready even
# though the rollout is progressing normally, so the overall budget is
# 2 × TIMEOUT_WAIT. Within that budget, a kubectl failure caused by the API
# tunnel (TLS handshake timeout, …) is NOT counted as a rollout failure: heal
# the tunnel and keep watching. Only running out of the deadline — or a
# non-connectivity error (e.g. the object doesn't exist) — fails the step, so
# a truly stuck rollout still fails.
wait_rollout() {
  local ctx="$1" kind="$2" name="$3"
  local deadline=$(( $(date +%s) + 2 * TIMEOUT_WAIT ))
  local out rc remaining
  while :; do
    remaining=$(( deadline - $(date +%s) ))
    if [ "$remaining" -le 0 ]; then
      log_error "rollout status $kind/$name on $ctx not complete after $((2 * TIMEOUT_WAIT))s"
      return 1
    fi
    rc=0
    out=$(kubectl --context "$ctx" -n spire rollout status "$kind/$name" --timeout="${remaining}s" 2>&1) || rc=$?
    printf '%s\n' "$out"
    [ "$rc" -eq 0 ] && return 0
    if is_transient_api_error "$out"; then
      log_error "rollout status $kind/$name on $ctx: API tunnel lỗi tạm thời, dựng lại và chờ tiếp ($((deadline - $(date +%s)))s còn lại)"
      heal_api "$ctx"
      sleep 5
      continue
    fi
    # Hết --timeout (rollout chưa xong) hoặc lỗi thật (object không tồn tại…).
    if grep -q "timed out waiting" <<<"$out"; then
      continue   # vòng lặp sẽ tự dừng ở deadline
    fi
    log_error "rollout status $kind/$name on $ctx failed: $out"
    return 1
  done
}

log_info "Waiting for spire-server/spire-agent on both clusters..."
wait_rollout "$AWS_CONTEXT" deployment spire-server
wait_rollout "$AWS_CONTEXT" daemonset spire-agent
wait_rollout "$OS_CONTEXT" deployment spire-server
wait_rollout "$OS_CONTEXT" daemonset spire-agent

AWS_PARENT="spiffe://ztlab.local/nodes/aws-k3s"
OS_PARENT="spiffe://ztlab.local/nodes/os-k3s"

log_info "Registering node aliases..."
register_node_alias "$AWS_CONTEXT" "$AWS_PARENT" "aws-k3s"
register_node_alias "$OS_CONTEXT" "$OS_PARENT" "os-k3s"

# crAPI target app — danh sách + số lượng kỳ vọng đều sinh từ
# policy/service-graph-crapi.yaml (scripts/gen-spire-entries.py). SA-based selector.
log_info "Registering crAPI workload SVID entries..."
register_spire_entries_from_generated "$AWS_CONTEXT" "$AWS_PARENT" "${AWS_SPIRE_WORKLOADS[@]}"
register_spire_entries_from_generated "$OS_CONTEXT" "$OS_PARENT" "${OPENSTACK_SPIRE_WORKLOADS[@]}"

# Deploy-time gate. Entry idempotent — an toàn khi pod chưa có. Số lượng kỳ
# vọng đến từ CÙNG file generated ở trên nên không thể lệch với danh sách vừa
# đăng ký (trước bản sửa Phần 2: comment/log/check gate là 3 con số hardcode
# khác nhau, từng lệch nhau mà không ai nhận ra vì gate vẫn pass tình cờ).
aws_count=$(count_entries_matching "$AWS_CONTEXT" "spiffe://ztlab.local/aws/")
os_count=$(count_entries_matching "$OS_CONTEXT" "spiffe://ztlab.local/openstack/")
log_info "Verified entries present: AWS=$aws_count (expect $AWS_EXPECTED_COUNT), OpenStack=$os_count (expect $OPENSTACK_EXPECTED_COUNT)"
if [ "$aws_count" -lt "$AWS_EXPECTED_COUNT" ] || [ "$os_count" -lt "$OPENSTACK_EXPECTED_COUNT" ]; then
  log_error "SPIRE registration entries missing after registration attempt — spire-server datastore may be empty/corrupted. Check 'kubectl -n spire exec deploy/spire-server -- /opt/spire/bin/spire-server entry show -socketPath /tmp/spire-server/private/api.sock' on both clusters."
  exit 1
fi

log_info "SPIRE workload registration verified OK"
