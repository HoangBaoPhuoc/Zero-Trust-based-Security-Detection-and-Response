#!/usr/bin/env bash
set -uE -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY_FILE="${INVENTORY_FILE:-$ROOT_DIR/ansible/inventory/hosts.yml}"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"
OS_CONTEXT="${OS_CONTEXT:-ctx-openstack}"
LOKI_URL="${LOKI_URL:-http://127.0.0.1:13100}"
GRAFANA_URL="${GRAFANA_URL:-http://127.0.0.1:3000}"
AI_URL="${AI_URL:-http://127.0.0.1:8090}"
SOAR_URL="${SOAR_URL:-http://127.0.0.1:8091}"
SOAR_API_TOKEN="${SOAR_API_TOKEN:-}"
RUN_REMOTE="${RUN_REMOTE:-0}"
RUN_K8S="${RUN_K8S:-1}"
RUN_LOCAL="${RUN_LOCAL:-1}"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

color() {
  case "$1" in
    pass) printf '\033[32m%s\033[0m' "$2" ;;
    warn) printf '\033[33m%s\033[0m' "$2" ;;
    fail) printf '\033[31m%s\033[0m' "$2" ;;
    *) printf '%s' "$2" ;;
  esac
}

pass() { PASS_COUNT=$((PASS_COUNT + 1)); printf '[%s] %s\n' "$(color pass PASS)" "$*"; }
warn() { WARN_COUNT=$((WARN_COUNT + 1)); printf '[%s] %s\n' "$(color warn WARN)" "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); printf '[%s] %s\n' "$(color fail FAIL)" "$*"; }
info() { printf '[INFO] %s\n' "$*"; }

run_check() {
  local description="$1"
  shift
  local output
  if output="$($@ 2>&1)"; then
    pass "$description"
    if [[ -n "${VERBOSE:-}" ]]; then printf '%s\n' "$output"; fi
    return 0
  fi
  fail "$description"
  printf '%s\n' "$output" | tail -n 20
  return 1
}

run_warn_check() {
  local description="$1"
  shift
  local output
  if output="$($@ 2>&1)"; then
    pass "$description"
    if [[ -n "${VERBOSE:-}" ]]; then printf '%s\n' "$output"; fi
    return 0
  fi
  warn "$description"
  printf '%s\n' "$output" | tail -n 12
  return 1
}

need_cmd() {
  if command -v "$1" >/dev/null 2>&1; then
    pass "command available: $1"
  else
    fail "missing command: $1"
  fi
}

http_check() {
  local description="$1"
  local url="$2"
  run_warn_check "$description" curl -fsS --max-time 5 "$url"
}

soar_http_check() {
  local description="$1"
  local url="$2"
  if [[ -n "$SOAR_API_TOKEN" ]]; then
    run_warn_check "$description" curl -fsS --max-time 5 -H "Authorization: Bearer $SOAR_API_TOKEN" "$url"
  else
    run_warn_check "$description" curl -fsS --max-time 5 "$url"
  fi
}

loki_query_has_results() {
  local query="$1"
  python3 - "$LOKI_URL" "$query" <<\PY_LOKI
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

loki_url, query = sys.argv[1:]
params = urllib.parse.urlencode({"query": query, "limit": "5"})
url = f"{loki_url.rstrip('/')}/loki/api/v1/query_range?{params}"
try:
    with urllib.request.urlopen(url, timeout=10) as response:
        payload = json.loads(response.read().decode())
except urllib.error.URLError as exc:
    raise SystemExit(f"Loki unreachable: {exc.reason}")
except Exception as exc:
    raise SystemExit(f"Loki query failed: {exc}")
results = payload.get("data", {}).get("result", [])
if not results:
    raise SystemExit("no matching Loki streams")
print(f"streams={len(results)}")
PY_LOKI
}

section() {
  printf '\n========== %s ==========' "$1"
  printf '\n'
}

check_files() {
  section "Repository Files"
  [[ -f "$INVENTORY_FILE" ]] && pass "inventory exists: $INVENTORY_FILE" || fail "inventory missing: $INVENTORY_FILE"
  [[ -f "$ROOT_DIR/.env.ai" ]] && pass ".env.ai exists and is gitignored" || warn ".env.ai missing; AI/SOAR will use defaults/placeholders"
  [[ -f "$ROOT_DIR/.env" ]] && pass ".env exists and is gitignored" || warn ".env missing; Terraform/Ansible may need env vars"
  [[ -f "$HOME/.ssh/ztlab-key" ]] && pass "SSH key exists: ~/.ssh/ztlab-key" || warn "SSH key missing: ~/.ssh/ztlab-key"
}

check_commands() {
  section "Local Tooling"
  for cmd in curl ssh; do
    need_cmd "$cmd"
  done
  if [[ "$RUN_REMOTE" == "1" || "$RUN_K8S" == "1" ]]; then
    for cmd in ansible ansible-inventory kubectl; do
      need_cmd "$cmd"
    done
  else
    for cmd in ansible ansible-inventory kubectl; do
      if command -v "$cmd" >/dev/null 2>&1; then pass "command available: $cmd"; else warn "command not needed in this mode: $cmd"; fi
    done
  fi
  if [[ "$RUN_REMOTE" == "1" ]]; then
    need_cmd terraform
  elif command -v terraform >/dev/null 2>&1; then
    pass "command available: terraform"
  else
    warn "terraform not needed unless provisioning/rebuilding cloud infra"
  fi
}

check_inventory() {
  section "Inventory"
  if [[ "$RUN_REMOTE" != "1" && "$RUN_K8S" != "1" ]]; then
    warn "inventory checks skipped in local-only mode"
    return
  fi
  run_warn_check "ansible inventory parses" ansible-inventory -i "$INVENTORY_FILE" --graph
  for host in aws_gateway aws_bastion aws_k3s_master aws_loki os_gateway os_k3s_master; do
    if ansible-inventory -i "$INVENTORY_FILE" --host "$host" >/dev/null 2>&1; then
      pass "inventory host present: $host"
    else
      fail "inventory host missing: $host"
    fi
  done
}

check_remote() {
  section "Remote SSH / Ansible"
  if [[ "$RUN_REMOTE" != "1" ]]; then
    warn "remote SSH checks skipped; run with RUN_REMOTE=1 for full cloud connectivity check"
    return
  fi
  run_warn_check "ansible ping ssh_entrypoints" ansible ssh_entrypoints -i "$INVENTORY_FILE" -m ping
  run_warn_check "ansible ping aws_private" ansible aws_private -i "$INVENTORY_FILE" -m ping
  run_warn_check "ansible ping openstack" ansible openstack -i "$INVENTORY_FILE" -m ping
}

check_k8s() {
  section "Kubernetes Contexts"
  if [[ "$RUN_K8S" != "1" ]]; then
    warn "Kubernetes checks skipped"
    return
  fi
  run_warn_check "k8s tunnel status command" "$ROOT_DIR/scripts/k8s-tunnel.sh" status
  run_warn_check "kubectl context reachable: $AWS_CONTEXT" kubectl --context "$AWS_CONTEXT" get nodes -o wide
  run_warn_check "kubectl context reachable: $OS_CONTEXT" kubectl --context "$OS_CONTEXT" get nodes -o wide
  run_warn_check "AWS pods overview" kubectl --context "$AWS_CONTEXT" get pods -A
  run_warn_check "OpenStack pods overview" kubectl --context "$OS_CONTEXT" get pods -A
  run_warn_check "AWS financial workloads" kubectl --context "$AWS_CONTEXT" -n financial get deploy,svc,pods
  run_warn_check "OpenStack financial workloads" kubectl --context "$OS_CONTEXT" -n financial get deploy,svc,pods
}

check_local_stack() {
  section "Local PLG / AI / SOAR (port-forward required)"
  if [[ "$RUN_LOCAL" != "1" ]]; then
    warn "local PLG checks skipped"
    return
  fi
  http_check "Loki ready              (port 13100)" "$LOKI_URL/ready"
  http_check "Loki API labels         (port 13100)" "$LOKI_URL/loki/api/v1/labels"
  http_check "Grafana health          (port 3000)"  "$GRAFANA_URL/api/health"
  http_check "AI Analyzer health      (port 8090)"  "$AI_URL/health"
  http_check "SOAR health             (port 8091)"  "$SOAR_URL/health"
  soar_http_check "SOAR incidents      (port 8091)" "$SOAR_URL/incidents"
  if [[ "$RUN_K8S" == "1" ]]; then
    _check_api_gw_jwks() {
      local d
      d=$(curl -fsS --max-time 5 http://127.0.0.1:18080/health 2>&1) || return 1
      echo "$d" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('jwks_keys_loaded',0)>0,'jwks=0 — restart api-gateway pod'; print(d)" 2>&1
    }
    run_warn_check "API Gateway health (jwks loaded)" _check_api_gw_jwks
    run_warn_check "Security Scorer health (port 18092)" \
      curl -fsS --max-time 5 http://127.0.0.1:18092/health
    run_warn_check "Keycloak realm reachable (port 8180)" \
      curl -fsS --max-time 5 "http://127.0.0.1:8180/realms/ztlab/.well-known/openid-configuration"
  fi
}

check_loki_data() {
  section "SIEM Log Evidence"
  run_warn_check "Loki has SOAR action stream" loki_query_has_results '{job="soar-engine"} |= "soar_action"'
  run_warn_check "Loki has raw demo stream" loki_query_has_results '{job="demo-raw"}'
}

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--full] [--local-only] [--no-k8s]

Modes:
  default       Check local stack + kubectl contexts if available. Remote SSH checks are skipped.
  --full        Also run Ansible SSH ping checks against AWS/OpenStack inventory.
  --local-only  Only check Docker/Loki/Grafana/AI/SOAR local demo stack.
  --no-k8s      Skip kubectl checks.

Env overrides:
  INVENTORY_FILE, AWS_CONTEXT, OS_CONTEXT, LOKI_URL, GRAFANA_URL, AI_URL, SOAR_URL
  VERBOSE=1      Print successful command output too.
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --full) RUN_REMOTE=1 ;;
    --local-only) RUN_REMOTE=0; RUN_K8S=0; RUN_LOCAL=1 ;;
    --no-k8s) RUN_K8S=0 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $arg"; usage; exit 2 ;;
  esac
done

cd "$ROOT_DIR"

check_files
check_commands
check_inventory
check_remote
check_k8s
check_local_stack
check_loki_data

section "Summary"
printf 'PASS=%s WARN=%s FAIL=%s\n' "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
