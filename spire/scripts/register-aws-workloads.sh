#!/bin/bash
set -euo pipefail

SPIRE_SERVER_BIN="${SPIRE_SERVER_BIN:-spire-server}"

register() {
	local spiffe_id="$1"
	local parent_id="$2"
	local ns="$3"
	local sa="$4"

	"$SPIRE_SERVER_BIN" entry create \
		-spiffeID "$spiffe_id" \
		-parentID "$parent_id" \
		-selector "k8s:ns:${ns}" \
		-selector "k8s:sa:${sa}" \
		-ttl 3600 || true
}

register "spiffe://ztlab.local/aws/payment-service" \
	"spiffe://ztlab.local/k8s-psat/aws-k3s/spire-agent" \
	"financial" "payment-service"

register "spiffe://ztlab.local/aws/fraud-detection" \
	"spiffe://ztlab.local/k8s-psat/aws-k3s/spire-agent" \
	"financial" "fraud-detection"

register "spiffe://ztlab.local/aws/notification-service" \
	"spiffe://ztlab.local/k8s-psat/aws-k3s/spire-agent" \
	"financial" "notification-service"

register "spiffe://ztlab.local/aws/api-gateway" \
	"spiffe://ztlab.local/k8s-psat/aws-k3s/spire-agent" \
	"financial" "api-gateway"
