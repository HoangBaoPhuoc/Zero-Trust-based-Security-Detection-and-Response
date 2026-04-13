#!/bin/bash
# WireGuard tunnel status and peer diagnostics script
# Displays tunnel status, peer handshake age, and connectivity metrics

set -euo pipefail

WG_INTERFACE="${1:-wg0}"
COLORS_ENABLED=true

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Disable colors if not connected to terminal
[[ ! -t 1 ]] && COLORS_ENABLED=false

color_msg() {
    local color=$1
    local msg=$2
    if [[ "$COLORS_ENABLED" == "true" ]]; then
        echo -e "${color}${msg}${NC}"
    else
        echo "$msg"
    fi
}

# Check if WireGuard interface exists
if ! ip addr show "$WG_INTERFACE" &>/dev/null; then
    color_msg "$RED" "ERROR: WireGuard interface $WG_INTERFACE does not exist on $(hostname)"
    echo "Hint: run this script on aws_gateway or os_gateway after wireguard.yml is applied."
    echo "From controller, use: ansible aws_gateway:os_gateway -i ansible/inventory/hosts.yml -b -m shell -a '/etc/zta-siem-soar/scripts/wg-status.sh'"
    exit 1
fi

color_msg "$BLUE" "=== WireGuard Tunnel Status for $WG_INTERFACE ==="
echo

# Display interface status
echo "Interface Status:"
ip addr show "$WG_INTERFACE" | grep -E "^\s+(inet|inet6)" | sed 's/^\s*/  /'
echo

# Display WireGuard configuration
echo "WireGuard Peer Status:"
wg show "$WG_INTERFACE" | tail -n +3 | while read -r line; do
    if [[ "$line" == "peer:"* ]]; then
        color_msg "$YELLOW" "  $line"
    else
        echo "  $line"
    fi
done
echo

# Check service status
echo "Service Status:"
if systemctl is-active --quiet "wg-quick@$WG_INTERFACE"; then
    color_msg "$GREEN" "  ✓ wg-quick@$WG_INTERFACE is running"
else
    color_msg "$RED" "  ✗ wg-quick@$WG_INTERFACE is not running"
fi
echo

# Calculate and display peer handshake age
echo "Peer Handshake Health:"
wg show "$WG_INTERFACE" endpoints | while read -r peer_endpoint; do
    if [[ -z "$peer_endpoint" ]]; then
        continue
    fi
    
    peer_key=$(echo "$peer_endpoint" | awk '{print $1}')
    endpoint=$(echo "$peer_endpoint" | awk '{print $2}')
    
    # Get latest handshake time
    latest_handshake=$(wg show "$WG_INTERFACE" latest-handshakes | grep "^$peer_key" | awk '{print $2}')
    
    if [[ -z "$latest_handshake" ]]; then
        color_msg "$RED" "  Peer ${peer_key:0:8}... (${endpoint:0:20}...): No handshake"
        continue
    fi
    
    current_time=$(date +%s)
    handshake_age=$((current_time - latest_handshake))
    
    if [[ $handshake_age -lt 60 ]]; then
        status="fresh"
        color="$GREEN"
    elif [[ $handshake_age -lt 300 ]]; then
        status="recent"
        color="$YELLOW"
    else
        status="stale"
        color="$RED"
    fi
    
    color_msg "$color" "  Peer ${peer_key:0:8}... (${endpoint:0:25}...): $handshake_age sec ago ($status)"
done
echo

# Test connectivity to peer if available
echo "Connectivity Test:"
peers_count=$(wg show "$WG_INTERFACE" peers | wc -l)

if [[ $peers_count -eq 0 ]]; then
    color_msg "$YELLOW" "  No peers configured"
else
    hostname=$(hostname)
    if [[ "$hostname" == "ip-"* ]]; then
        # AWS instance
        target="10.200.200.2"  # OpenStack gateway
        if ping -c 1 -W 2 "$target" &>/dev/null; then
            color_msg "$GREEN" "  ✓ Tunnel connectivity test passed (ping $target)"
        else
            color_msg "$RED" "  ✗ Tunnel connectivity test failed (cannot reach $target)"
        fi
    else
        # OpenStack instance or other
        target="10.200.200.1"  # AWS gateway
        if ping -c 1 -W 2 "$target" &>/dev/null; then
            color_msg "$GREEN" "  ✓ Tunnel connectivity test passed (ping $target)"
        else
            color_msg "$RED" "  ✗ Tunnel connectivity test failed (cannot reach $target)"
        fi
    fi
fi

echo
color_msg "$BLUE" "=== End of Report ==="
