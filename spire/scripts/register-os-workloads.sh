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

register "spiffe://ztlab.local/os/core-banking" \
	"spiffe://ztlab.local/k8s-psat/os-k3s/spire-agent" \
	"financial" "core-banking"

register "spiffe://ztlab.local/os/account-service" \
	"spiffe://ztlab.local/k8s-psat/os-k3s/spire-agent" \
	"financial" "account-service"

register "spiffe://ztlab.local/os/transaction-service" \
	"spiffe://ztlab.local/k8s-psat/os-k3s/spire-agent" \
	"financial" "transaction-service"

register "spiffe://ztlab.local/os/identity-service" \
	"spiffe://ztlab.local/k8s-psat/os-k3s/spire-agent" \
	"identity" "identity-service"
