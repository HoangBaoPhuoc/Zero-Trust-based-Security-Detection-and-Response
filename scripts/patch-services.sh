#!/bin/bash
# patch-services.sh — hot-patch a Python service's main.py without a full image rebuild.
#
# How it works: each listed service gets a ConfigMap containing the current
# services/<name>/main.py, mounted over /app/main.py in its Deployment. On first
# run for a service this also inserts the volume/volumeMount (one-time, additive
# JSON patch). Subsequent runs just refresh the ConfigMap content and restart.
#
# Use this for fast iteration on service logic (routes, scoring, session handling).
# It does NOT cover template/static asset changes (web-portal's Jinja templates
# are baked into the image) — for those, rebuild the image via
# sync-financial-images.sh / the docker build+save+ctr-import pipeline (see
# DEPLOY.md § Redeploy sau khi sửa code).
#
# Usage:
#   bash scripts/patch-services.sh                       # patch all services below
#   bash scripts/patch-services.sh fraud-detection        # patch just one
#   SERVICES="web-portal api-gateway" bash scripts/patch-services.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AWS_CONTEXT="${AWS_CONTEXT:-ctx-aws}"

# name -> namespace
declare -A SERVICE_NS=(
  [web-portal]=financial
  [api-gateway]=financial
  [fraud-detection]=financial
  [payment-service]=financial
  [soar-engine]=plg-stack
)

REQUESTED="${*:-${SERVICES:-${!SERVICE_NS[@]}}}"

for name in $REQUESTED; do
  ns="${SERVICE_NS[$name]:-}"
  if [[ -z "$ns" ]]; then
    echo "[SKIP] $name — không nằm trong danh sách hỗ trợ (${!SERVICE_NS[*]})"
    continue
  fi
  main_py="$REPO_DIR/services/$name/main.py"
  if [[ ! -f "$main_py" ]]; then
    echo "[SKIP] $name — không tìm thấy $main_py"
    continue
  fi

  echo "[*] $name (ns=$ns) — cập nhật ConfigMap patch-$name ..."
  kubectl --context "$AWS_CONTEXT" create configmap "patch-$name" \
    --from-file=main.py="$main_py" \
    -n "$ns" --dry-run=client -o yaml | kubectl --context "$AWS_CONTEXT" apply -f -

  if ! kubectl --context "$AWS_CONTEXT" get deployment "$name" -n "$ns" -o yaml 2>/dev/null | grep -q "patch-$name"; then
    echo "    -> Chưa có volumeMount, gắn lần đầu ..."
    kubectl --context "$AWS_CONTEXT" patch deployment "$name" -n "$ns" --type=json -p="[
      {\"op\":\"add\",\"path\":\"/spec/template/spec/volumes/-\",\"value\":{\"name\":\"patch-$name\",\"configMap\":{\"name\":\"patch-$name\"}}}
    ]"
    has_mounts=$(kubectl --context "$AWS_CONTEXT" get deployment "$name" -n "$ns" \
      -o jsonpath='{.spec.template.spec.containers[0].volumeMounts}')
    if [[ -z "$has_mounts" ]]; then
      mount_patch="[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/volumeMounts\",\"value\":[{\"name\":\"patch-$name\",\"mountPath\":\"/app/main.py\",\"subPath\":\"main.py\"}]}]"
    else
      mount_patch="[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/volumeMounts/-\",\"value\":{\"name\":\"patch-$name\",\"mountPath\":\"/app/main.py\",\"subPath\":\"main.py\"}}]"
    fi
    kubectl --context "$AWS_CONTEXT" patch deployment "$name" -n "$ns" --type=json -p="$mount_patch"
  fi

  echo "    -> Restart deployment/$name ..."
  kubectl --context "$AWS_CONTEXT" rollout restart "deployment/$name" -n "$ns"
done

echo ""
echo "[*] Chờ rollout ..."
for name in $REQUESTED; do
  ns="${SERVICE_NS[$name]:-}"
  [[ -z "$ns" ]] && continue
  kubectl --context "$AWS_CONTEXT" rollout status "deployment/$name" -n "$ns" --timeout=90s
done

echo ""
echo "=== Xong. Đã patch: $REQUESTED ==="
