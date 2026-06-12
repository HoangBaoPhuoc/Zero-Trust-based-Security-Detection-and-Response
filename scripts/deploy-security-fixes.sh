#!/bin/bash
# Deploy security fix ConfigMaps to K3s clusters
set -e

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
# If called from /tmp, find the repo
[[ ! -d "$REPO_DIR/services" ]] && REPO_DIR="/home/deployer/Zero-Trust-based-Security-Detection-and-Response-for-Microservice-in-Multi-Cloud"

echo "=== Deploying security fixes from $REPO_DIR ==="

# 1. web-portal main.py patch
echo "[1/4] Updating patch-web-portal ConfigMap..."
kubectl create configmap patch-web-portal \
  --from-file=main.py="$REPO_DIR/services/web-portal/main.py" \
  -n financial --dry-run=client -o yaml | kubectl apply -f -

# 2. api-gateway main.py patch (create if not exists)
echo "[2/4] Creating/updating patch-api-gateway ConfigMap..."
kubectl create configmap patch-api-gateway \
  --from-file=main.py="$REPO_DIR/services/api-gateway/main.py" \
  -n financial --dry-run=client -o yaml | kubectl apply -f -

# Check if api-gateway deployment has the volume mount
if ! kubectl get deployment api-gateway -n financial -o yaml 2>/dev/null | grep -q "patch-api-gateway"; then
  echo "  -> Patching api-gateway deployment with volume mount..."
  kubectl patch deployment api-gateway -n financial --type=json -p='[
    {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"patch-api-gateway","configMap":{"name":"patch-api-gateway"}}},
    {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"patch-api-gateway","mountPath":"/app/main.py","subPath":"main.py"}}
  ]'
fi

# 3. soar-engine main.py patch
echo "[3/4] Creating/updating patch-soar-engine ConfigMap..."
kubectl create configmap patch-soar-engine \
  --from-file=main.py="$REPO_DIR/services/soar-engine/main.py" \
  -n plg-stack --dry-run=client -o yaml | kubectl apply -f -

if ! kubectl get deployment soar-engine -n plg-stack -o yaml 2>/dev/null | grep -q "patch-soar-engine"; then
  echo "  -> Patching soar-engine deployment with volume mount..."
  kubectl patch deployment soar-engine -n plg-stack --type=json -p='[
    {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"patch-soar-engine","configMap":{"name":"patch-soar-engine"}}},
    {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"patch-soar-engine","mountPath":"/app/main.py","subPath":"main.py"}}
  ]'
fi

# 4. Make sure ai-secrets is NOT optional for soar-engine
echo "[4/4] Verifying ai-secrets secret exists in plg-stack..."
if ! kubectl get secret ai-secrets -n plg-stack &>/dev/null; then
  echo "  WARNING: ai-secrets does not exist in plg-stack namespace!"
  echo "  Create it with: kubectl create secret generic ai-secrets -n plg-stack \\"
  echo "    --from-literal=SOAR_API_TOKEN=<your-token>"
else
  echo "  ai-secrets exists OK"
fi

# 5. Restart deployments to pick up ConfigMap changes
echo "Restarting deployments..."
kubectl rollout restart deployment/web-portal -n financial
kubectl rollout restart deployment/api-gateway -n financial
kubectl rollout restart deployment/soar-engine -n plg-stack

echo ""
echo "=== Waiting for rollouts ==="
kubectl rollout status deployment/web-portal -n financial --timeout=60s
kubectl rollout status deployment/api-gateway -n financial --timeout=60s
kubectl rollout status deployment/soar-engine -n plg-stack --timeout=60s

echo ""
echo "=== Security fixes deployed successfully ==="
