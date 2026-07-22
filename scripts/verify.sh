#!/usr/bin/env bash
# Full verification of all bypass settings
# Platforms: macOS 12+ · Linux (systemd / OpenRC / runit / SysV, all major distros)
#
# Run this AFTER applying the bypass to confirm everything is active.
# Requires root for firewall rule inspection.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; GRAY='\033[0;37m'; DARK_GRAY='\033[1;30m'
WHITE='\033[1;37m'; NC='\033[0m'

pass=0
fail=0

has_cmd() { command -v "$1" &>/dev/null; }

# Minimal platform detection
OS_TYPE="linux"
[[ "$(uname -s)" == "Darwin" ]] && OS_TYPE="macos"

INIT_SYSTEM="unknown"
if   has_cmd systemctl && systemctl --version &>/dev/null 2>&1; then INIT_SYSTEM="systemd"
elif has_cmd rc-service;                                         then INIT_SYSTEM="openrc"
elif [[ -d /run/runit ]] || has_cmd sv;                         then INIT_SYSTEM="runit"
elif has_cmd service;                                            then INIT_SYSTEM="sysv"
fi

FW_TYPE="none"
if   [[ "$OS_TYPE" == "macos" ]]; then FW_TYPE="pf"
elif has_cmd iptables;             then FW_TYPE="iptables"
elif has_cmd nft;                  then FW_TYPE="nftables"
fi

# Check helper
check() {
    local name="$1" result="$2" detail="$3"
    if [[ "$result" == "0" ]]; then
        echo -e "  ${GREEN}[PASS]${NC} ${WHITE}${name}${NC} ${GRAY}- ${detail}${NC}"
        (( pass++ )) || true
    else
        echo -e "  ${RED}[FAIL]${NC} ${WHITE}${name}${NC} ${YELLOW}- ${detail}${NC}"
        (( fail++ )) || true
    fi
}

echo ""
echo -e "  ${CYAN}=============================================${NC}"
echo -e "  ${CYAN}AIRTEL BYPASS - FULL VERIFICATION (${OS_TYPE^^})${NC}"
echo -e "  ${CYAN}=============================================${NC}"
echo ""

#  1. TTL
echo -e "  ${DARK_GRAY}--- TTL ---${NC}"
if [[ "$OS_TYPE" == "macos" ]]; then
    ttl=$(sysctl -n net.inet.ip.ttl 2>/dev/null || echo "0")
    [[ "$ttl" == "65" ]] && r=0 || r=1
    check "IPv4 TTL (net.inet.ip.ttl)" "$r" "Expected: 65, Got: $ttl"

    ttl6=$(sysctl -n net.inet6.ip6.hlim 2>/dev/null || echo "0")
    [[ "$ttl6" == "65" ]] && r=0 || r=1
    check "IPv6 Hop Limit (net.inet6.ip6.hlim)" "$r" "Expected: 65, Got: $ttl6"

    # Persistence check
    if grep -q 'net.inet.ip.ttl' /etc/sysctl.conf 2>/dev/null; then
        file_ttl=$(grep 'net.inet.ip.ttl' /etc/sysctl.conf | awk '{print $NF}')
        [[ "$file_ttl" == "65" ]] && r=0 || r=1
        check "IPv4 TTL (persistent /etc/sysctl.conf)" "$r" "Expected: 65, Got: $file_ttl"
    else
        check "IPv4 TTL (persistent /etc/sysctl.conf)" "1" "Key not found in /etc/sysctl.conf"
    fi
else
    ttl=$(sysctl -n net.ipv4.ip_default_ttl 2>/dev/null || echo "0")
    [[ "$ttl" == "65" ]] && r=0 || r=1
    check "IPv4 TTL (sysctl live)" "$r" "Expected: 65, Got: $ttl"

    # Persistence: check dedicated conf file first, then inline sysctl.conf
    if [[ -f /etc/sysctl.d/99-airtel-bypass.conf ]]; then
        file_ttl=$(grep -E '^net\.ipv4\.ip_default_ttl' /etc/sysctl.d/99-airtel-bypass.conf \
                   2>/dev/null | awk '{print $NF}' || echo "not set")
    else
        file_ttl=$(grep -E '^net\.ipv4\.ip_default_ttl' /etc/sysctl.conf \
                   2>/dev/null | awk '{print $NF}' || echo "not set")
    fi
    [[ "$file_ttl" == "65" ]] && r=0 || r=1
    check "IPv4 TTL (persistent)" "$r" "Expected: 65, Got: $file_ttl"

    if [[ "$FW_TYPE" == "iptables" ]]; then
        if has_cmd ip6tables && ip6tables -t mangle -L OUTPUT -n 2>/dev/null | grep -q 'HL set 65'; then
            check "IPv6 Hop Limit (ip6tables HL)" "0" "HL --hl-set 65 rule found"
        else
            check "IPv6 Hop Limit (ip6tables HL)" "1" "HL rule not found (kernel module xt_HL may be missing)"
        fi
    fi
fi

# 2. MTU
echo ""
echo -e "  ${DARK_GRAY}--- MTU ---${NC}"
if [[ "$OS_TYPE" == "macos" ]]; then
    wifi_iface=$(networksetup -listallhardwareports 2>/dev/null \
        | grep -A2 'Wi-Fi\|AirPort' | awk '/^Device:/ {print $2; exit}')
    if [[ -n "${wifi_iface:-}" ]]; then
        mtu=$(ifconfig "$wifi_iface" 2>/dev/null | awk '/mtu/ {print $NF}')
        [[ "${mtu:-0}" == "1400" ]] && r=0 || r=1
        check "MTU on $wifi_iface" "$r" "Expected: 1400, Got: ${mtu:-?}"
    else
        check "MTU" "1" "No Wi-Fi adapter found via networksetup"
    fi

    # pf MSS clamp
    if pfctl -a airtel_bypass -sr 2>/dev/null | grep -q 'max-mss'; then
        check "TCP MSS clamp (pf scrub)" "0" "scrub max-mss 1360 found in pf anchor"
    else
        check "TCP MSS clamp (pf scrub)" "1" "max-mss rule not found in pf airtel_bypass anchor"
    fi
else
    iface_mtu=""
    for dev in /sys/class/net/*/wireless; do
        [[ -e "$dev" ]] || continue
        iface=$(basename "$(dirname "$dev")")
        state=$(cat "/sys/class/net/${iface}/operstate" 2>/dev/null || echo "down")
        if [[ "$state" == "up" ]]; then
            iface_mtu=$(ip link show "$iface" 2>/dev/null \
                | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu") print $(i+1)}' | head -1)
            [[ "${iface_mtu:-0}" == "1400" ]] && r=0 || r=1
            check "MTU on $iface" "$r" "Expected: 1400, Got: ${iface_mtu:-?}"
            break
        fi
    done
    [[ -z "${iface_mtu:-}" ]] && check "MTU" "1" "No active wireless adapter found via /sys/class/net"

    if [[ "$FW_TYPE" == "iptables" ]]; then
        if iptables -t mangle -L OUTPUT -n 2>/dev/null | grep -q 'tcpmss.*1360'; then
            check "TCP MSS clamp (iptables)" "0" "MSS set to 1360 in mangle OUTPUT"
        else
            check "TCP MSS clamp (iptables)" "1" "MSS rule not found in iptables mangle OUTPUT"
        fi
    elif [[ "$FW_TYPE" == "nftables" ]]; then
        if nft list table inet airtel_bypass 2>/dev/null | grep -q 'maxseg'; then
            check "TCP MSS clamp (nftables)" "0" "maxseg rule found in airtel_bypass table"
        else
            check "TCP MSS clamp (nftables)" "1" "maxseg rule not found in airtel_bypass table"
        fi
    fi
fi

# 3. DNS 
echo ""
echo -e "  ${DARK_GRAY}--- DNS ---${NC}"
if grep -q '1\.1\.1\.1' /etc/resolv.conf 2>/dev/null; then
    check "DNS 1.1.1.1 in resolv.conf" "0" "1.1.1.1 is configured"
else
    check "DNS 1.1.1.1 in resolv.conf" "1" "1.1.1.1 NOT found in /etc/resolv.conf"
fi
if grep -q '1\.0\.0\.1' /etc/resolv.conf 2>/dev/null; then
    check "DNS 1.0.0.1 in resolv.conf" "0" "1.0.0.1 is configured"
else
    check "DNS 1.0.0.1 in resolv.conf" "1" "1.0.0.1 NOT found in /etc/resolv.conf"
fi

if [[ "$OS_TYPE" == "macos" ]]; then
    if networksetup -getdnsservers Wi-Fi 2>/dev/null | grep -q '1\.1\.1\.1'; then
        check "DNS 1.1.1.1 via networksetup (Wi-Fi)" "0" "Confirmed active via networksetup"
    else
        check "DNS 1.1.1.1 via networksetup (Wi-Fi)" "1" "Not set via networksetup"
    fi
fi

# 4. Services
echo ""
echo -e "  ${DARK_GRAY}--- SERVICES ---${NC}"
if [[ "$OS_TYPE" == "macos" ]]; then
    # Check pf anchor
    if [[ -f /etc/pf.anchors/airtel_bypass ]]; then
        check "pf anchor file exists" "0" "/etc/pf.anchors/airtel_bypass found"
    else
        check "pf anchor file exists" "1" "/etc/pf.anchors/airtel_bypass not found"
    fi
    if has_cmd pfctl && pfctl -a airtel_bypass -sr 2>/dev/null | grep -q 'block'; then
        check "pf airtel_bypass anchor loaded & blocking" "0" "Block rules found in anchor"
    else
        check "pf airtel_bypass anchor loaded & blocking" "1" "No block rules — anchor may not be loaded or pf disabled"
    fi
elif [[ "$INIT_SYSTEM" == "systemd" ]]; then
    for svc in apt-daily avahi-daemon fwupd; do
        status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
        [[ "$status" != "active" ]] && r=0 || r=1
        check "$svc stopped" "$r" "Expected: inactive/dead, Got: $status"
    done
elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
    for svc in avahi-daemon; do
        status=$(rc-service "$svc" status 2>/dev/null | grep -o 'started\|stopped' || echo "stopped")
        [[ "$status" != "started" ]] && r=0 || r=1
        check "$svc stopped (OpenRC)" "$r" "Expected: stopped, Got: $status"
    done
elif [[ "$INIT_SYSTEM" == "runit" ]]; then
    for svc in avahi-daemon; do
        sv_status=$(sv status "$svc" 2>/dev/null | head -1 || echo "down")
        echo "$sv_status" | grep -q '^run:' && r=1 || r=0
        check "$svc stopped (runit)" "$r" "Status: $sv_status"
    done
else
    check "Service check" "1" "Init system '$INIT_SYSTEM' not supported — check manually"
fi

#  5. Firewall rules
echo ""
echo -e "  ${DARK_GRAY}--- FIREWALL ---${NC}"
if [[ "$OS_TYPE" == "macos" ]]; then
    for port in 1900 5353 5355; do
        if pfctl -a airtel_bypass -sr 2>/dev/null | grep -q "port $port"; then
            check "Port $port blocked (pf)" "0" "Rule found in airtel_bypass anchor"
        else
            check "Port $port blocked (pf)" "1" "Rule NOT found — bypass may not be applied"
        fi
    done
elif [[ "$FW_TYPE" == "iptables" ]]; then
    drop_count=$(iptables -L OUTPUT -n 2>/dev/null | grep -c ' DROP' || echo "0")
    [[ "$drop_count" -gt 10 ]] && r=0 || r=1
    check "DROP rules in OUTPUT chain" "$r" "Found $drop_count rules (expected 10+)"

    for port in 1900 5353 5355; do
        if iptables -L OUTPUT -n 2>/dev/null | grep -qE ":${port}[[:space:]]"; then
            check "Port $port blocked (iptables)" "0" "DROP rule found"
        else
            check "Port $port blocked (iptables)" "1" "DROP rule NOT found"
        fi
    done
elif [[ "$FW_TYPE" == "nftables" ]]; then
    if nft list table inet airtel_bypass 2>/dev/null | grep -q 'drop'; then
        check "nftables airtel_bypass table active" "0" "Drop rules found"
    else
        check "nftables airtel_bypass table active" "1" "No drop rules found — bypass not applied"
    fi
    for port in 1900 5353 5355; do
        if nft list table inet airtel_bypass 2>/dev/null | grep -q "dport $port"; then
            check "Port $port blocked (nftables)" "0" "Rule found"
        else
            check "Port $port blocked (nftables)" "1" "Rule NOT found"
        fi
    done
else
    check "Firewall rules" "1" "No supported firewall found (iptables/nft/pfctl)"
fi

# 6. TCP settings
echo ""
echo -e "  ${DARK_GRAY}--- TCP ---${NC}"
if [[ "$OS_TYPE" == "macos" ]]; then
    pr_first=$(sysctl -n net.inet.ip.portrange.first 2>/dev/null || echo "?")
    [[ "$pr_first" == "49152" ]] && r=0 || r=1
    check "Port range reduced (macOS)" "$r" "Expected: 49152, Got: $pr_first"
else
    ws=$(sysctl -n net.ipv4.tcp_window_scaling 2>/dev/null || echo "?")
    [[ "$ws" == "0" ]] && r=0 || r=1
    check "TCP Window Scaling disabled" "$r" "Expected: 0, Got: $ws"

    pr=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || echo "?")
    [[ "$pr" == "49152	53247" || "$pr" == "49152 53247" ]] && r=0 || r=1
    check "Ephemeral port range reduced" "$r" "Expected: 49152-53247, Got: $pr"
fi

# 7. Connectivity
echo ""
echo -e "  ${DARK_GRAY}--- CONNECTIVITY ---${NC}"

if [[ "$OS_TYPE" == "macos" ]]; then
    ping -c 1 -t 3 1.1.1.1 &>/dev/null 2>&1 && ping_ok=0 || ping_ok=1
else
    ping -c 1 -W 3 1.1.1.1 &>/dev/null 2>&1 && ping_ok=0 || ping_ok=1
fi
check "Internet access (ping 1.1.1.1)" "$ping_ok" \
    "$([[ $ping_ok -eq 0 ]] && echo 'Reachable' || echo 'Cannot reach 1.1.1.1')"

# DNS resolution — cross-platform
dns_ok=1
if [[ "$OS_TYPE" == "macos" ]]; then
    if dscacheutil -q host -a name google.com 2>/dev/null | grep -q 'ip_address'; then
        dns_ok=0
    elif has_cmd host && host google.com &>/dev/null 2>&1; then
        dns_ok=0
    fi
else
    if has_cmd getent && getent hosts google.com &>/dev/null 2>&1; then
        dns_ok=0
    elif has_cmd host && host google.com &>/dev/null 2>&1; then
        dns_ok=0
    elif has_cmd nslookup && nslookup google.com &>/dev/null 2>&1; then
        dns_ok=0
    fi
fi
check "DNS resolution (google.com)" "$dns_ok" \
    "$([[ $dns_ok -eq 0 ]] && echo 'Resolved successfully' || echo 'Cannot resolve google.com')"

# Summary
echo ""
echo -e "  ${DARK_GRAY}=============================================${NC}"
total=$(( pass + fail ))
if [[ "$fail" -eq 0 ]]; then
    echo -e "  ${GREEN}ALL $total CHECKS PASSED ✓${NC}"
    echo -e "  ${GREEN}Your traffic fully mimics a mobile device.${NC}"
else
    echo -e "  ${YELLOW}$pass/$total PASSED, $fail FAILED${NC}"
    echo -e "  ${YELLOW}Some checks failed — see details above.${NC}"
fi
echo -e "  ${DARK_GRAY}=============================================${NC}"
echo ""
