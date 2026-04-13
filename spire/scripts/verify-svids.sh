#!/bin/bash
set -euo pipefail

SOCKET_PATH="${1:-/run/spire/sockets/agent.sock}"

echo "== SPIRE SVID Verification =="
echo "Agent socket: ${SOCKET_PATH}"

if [[ ! -S "${SOCKET_PATH}" ]]; then
	echo "ERROR: SPIRE agent socket not found"
	exit 1
fi

if command -v spire-agent >/dev/null 2>&1; then
	echo "Fetching X.509 SVID..."
	if spire-agent api fetch x509 -socketPath "${SOCKET_PATH}" >/tmp/spire-svid.json 2>/dev/null; then
		echo "SVID fetch succeeded"
		cat /tmp/spire-svid.json
	else
		echo "WARN: unable to fetch SVID with spire-agent api"
	fi
else
	echo "WARN: spire-agent binary not found"
fi

if command -v spire-server >/dev/null 2>&1; then
	echo "Registered entries summary:"
	spire-server entry show 2>/dev/null | head -40 || true
fi
