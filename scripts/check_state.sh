#!/usr/bin/env bash
# Pre-bypass state check — shows current network configuration
# Platforms: macOS 12+ · Linux (systemd / OpenRC / runit / SysV, all major distros)
#
# Run this BEFORE applying the bypass to see what needs changing.
# Does not require root — read-only diagnostics only.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
GRAY='\033[0;37m'; YELLOW='\033[1;33m'; DARK_GRAY='\033[1;30m'; NC='\033[0m'

sec()     { echo -e "\n${CYAN}=== $1 ===${NC}"; }
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
if   [[ "$OS_TYPE" == "macos" ]];  then FW_TYPE="pf"
elif has_cmd iptables;              then FW_TYPE="iptables"
elif has_cmd nft;                   then FW_TYPE="nftables"
fi

#  PLATFORM
sec "PLATFORM"
echo -e "  OS: ${CYAN}${OS_TYPE}${NC}   Init: ${CYAN}${INIT_SYSTEM}${NC}   Firewall: ${CYAN}${FW_TYPE}${NC}"
if [[ "$OS_TYPE" == "macos" ]] && has_cmd sw_vers; then
    echo "  macOS $(sw_vers -productVersion) ($(sw_vers -productName))"
elif [[ -f /etc/os-release ]]; then
    echo "  $(. /etc/os-release && echo "${PRETTY_NAME:-$ID}")"
fi
if [[ "$OS_TYPE" == "macos" ]] && has_cmd csrutil; then
    sip_status=$(csrutil status 2>/dev/null | grep -o 'enabled\|disabled' || echo "unknown")
    echo "  SIP: $sip_status"
fi

# ACTIVE NETWORK INTERFACES
sec "ACTIVE NETWORK INTERFACES"
if [[ "$OS_TYPE" == "macos" ]]; then
    networksetup -listallhardwareports 2>/dev/null | awk '
        /Hardware Port:/ {
            port = $0; gsub(/^.*Hardware Port: /, "", port)
        }
        /Device:/ { dev = $2 }
        /Ethernet Address:/ {
            cmd = "ifconfig " dev " 2>/dev/null"
            has_ip = 0; mtu_val = "?"
            while ((cmd | getline ln) > 0) {
                if (ln ~ /inet /)   has_ip = 1
                if (ln ~ /mtu/)     { n = split(ln,a," "); mtu_val = a[n] }
            }
            close(cmd)
            printf "  %-22s  device=%-6s  ip=%-4s  mtu=%s\n",
                port, dev, (has_ip ? "yes" : "no"), mtu_val
        }
    '
else
    if has_cmd ip; then
        ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | while read -r iface; do
            state=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "unknown")
            mtu=$(ip link show "$iface" 2>/dev/null \
                | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu") print $(i+1)}' | head -1)
            printf "  %-20s  state=%-7s  mtu=%s\n" "$iface" "$state" "${mtu:-?}"
        done
    else
        # Fallback for distros without ip (rare but possible on minimal containers)
        ifconfig -a 2>/dev/null | awk '/^[a-z]/ {iface=$1; gsub(/:$/,"",iface)} /inet / {print "  " iface}'
    fi
fi

# CURRENT TTL 
sec "CURRENT TTL"
if [[ "$OS_TYPE" == "macos" ]]; then
    ttl=$(sysctl -n net.inet.ip.ttl 2>/dev/null || echo "?")
    ttl6=$(sysctl -n net.inet6.ip6.hlim 2>/dev/null || echo "?")
    echo "  net.inet.ip.ttl     = $ttl   (target: 65)"
    echo "  net.inet6.ip6.hlim  = $ttl6  (target: 65)"
else
    ttl=$(sysctl -n net.ipv4.ip_default_ttl 2>/dev/null || echo "?")
    echo "  net.ipv4.ip_default_ttl = $ttl  (target: 65)"
fi
[[ "$ttl" == "65" ]] \
    && echo -e "  ${GREEN}✓ TTL looks good${NC}" \
    || echo -e "  ${RED}✗ TTL not set — bypass not applied${NC}"

# CURRENT MTU (Wi-Fi adapter) 
sec "CURRENT MTU (Wi-Fi adapter)"
if [[ "$OS_TYPE" == "macos" ]]; then
    wifi_iface=$(networksetup -listallhardwareports 2>/dev/null \
        | grep -A2 'Wi-Fi\|AirPort' | awk '/^Device:/ {print $2; exit}')
    if [[ -n "${wifi_iface:-}" ]]; then
        mtu=$(ifconfig "$wifi_iface" 2>/dev/null | awk '/mtu/ {print $NF}')
        echo "  $wifi_iface: MTU=${mtu:-?}  (target: 1400)"
        [[ "${mtu:-0}" == "1400" ]] \
            && echo -e "  ${GREEN}✓ MTU looks good${NC}" \
            || echo -e "  ${RED}✗ MTU not clamped${NC}"
    else
        echo -e "  ${YELLOW}⚠ No Wi-Fi adapter found${NC}"
    fi
else
    found_wifi=false
    for dev in /sys/class/net/*/wireless; do
        [[ -e "$dev" ]] || continue
        iface=$(basename "$(dirname "$dev")")
        mtu=$(ip link show "$iface" 2>/dev/null \
            | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu") print $(i+1)}' | head -1)
        echo "  $iface: MTU=${mtu:-?}  (target: 1400)"
        [[ "${mtu:-0}" == "1400" ]] \
            && echo -e "  ${GREEN}✓ MTU looks good${NC}" \
            || echo -e "  ${RED}✗ MTU not clamped${NC}"
        found_wifi=true
    done
    $found_wifi || echo -e "  ${YELLOW}⚠ No wireless interfaces found in /sys/class/net${NC}"
fi

# CURRENT DNS
sec "CURRENT DNS"
if [[ "$OS_TYPE" == "macos" ]]; then
    echo "  networksetup (Wi-Fi):"
    networksetup -getdnsservers Wi-Fi 2>/dev/null | sed 's/^/    /'
    echo ""
fi
echo "  /etc/resolv.conf:"
grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | sed 's/^/    /' || echo "    (none)"
if grep -q '1\.1\.1\.1' /etc/resolv.conf 2>/dev/null; then
    echo -e "  ${GREEN}✓ Cloudflare DNS is active${NC}"
else
    echo -e "  ${RED}✗ Cloudflare DNS not set${NC}"
fi

# TCP SETTINGS 
sec "TCP SETTINGS"
if [[ "$OS_TYPE" == "macos" ]]; then
    pr_first=$(sysctl -n net.inet.ip.portrange.first 2>/dev/null || echo "?")
    pr_last=$(sysctl -n net.inet.ip.portrange.last   2>/dev/null || echo "?")
    echo "  net.inet.ip.portrange.first = $pr_first  (target: 49152)"
    echo "  net.inet.ip.portrange.last  = $pr_last"
    [[ "$pr_first" == "49152" ]] \
        && echo -e "  ${GREEN}✓ Port range reduced${NC}" \
        || echo -e "  ${RED}✗ Port range not changed${NC}"
else
    ws=$(sysctl -n net.ipv4.tcp_window_scaling 2>/dev/null || echo "?")
    echo "  net.ipv4.tcp_window_scaling  = $ws  (target: 0 = disabled)"
    [[ "$ws" == "0" ]] \
        && echo -e "  ${GREEN}✓ TCP Window Scaling disabled${NC}" \
        || echo -e "  ${RED}✗ TCP Window Scaling still enabled${NC}"

    pr=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || echo "?")
    echo "  net.ipv4.ip_local_port_range = $pr  (target: 49152 53247)"
fi

# SERVICES STATUS
sec "SERVICES STATUS"
if [[ "$OS_TYPE" == "macos" ]]; then
    echo -e "  ${DARK_GRAY}macOS daemons are SIP-protected — checking pf anchor instead:${NC}"
    if has_cmd pfctl && pfctl -a airtel_bypass -sr 2>/dev/null | grep -q 'block'; then
        echo -e "  ${GREEN}✓ pf airtel_bypass anchor is active (bypass applied)${NC}"
        pfctl -a airtel_bypass -sr 2>/dev/null | head -5 | sed 's/^/    /'
    else
        echo -e "  ${YELLOW}⚠ pf airtel_bypass anchor is empty or not loaded (bypass not applied)${NC}"
    fi
elif [[ "$INIT_SYSTEM" == "systemd" ]]; then
    for svc in apt-daily avahi-daemon fwupd snapd; do
        status=$(systemctl is-active "$svc" 2>/dev/null || echo "not-found")
        printf "  %-30s %s\n" "$svc:" "$status"
    done
elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
    for svc in avahi-daemon; do
        status=$(rc-service "$svc" status 2>/dev/null | grep -o 'started\|stopped\|crashed' || echo "not-found")
        printf "  %-30s %s\n" "$svc:" "$status"
    done
elif [[ "$INIT_SYSTEM" == "runit" ]]; then
    for svc in avahi-daemon; do
        status=$(sv status "$svc" 2>/dev/null | head -1 || echo "not-found")
        printf "  %-30s %s\n" "$svc:" "$status"
    done
else
    echo "  (init system '$INIT_SYSTEM' — service check not implemented)"
fi

# FIREWALL DROP RULES (preview)
sec "FIREWALL RULES (first 15)"
if [[ "$OS_TYPE" == "macos" ]]; then
    if has_cmd pfctl; then
        pfctl -a airtel_bypass -sr 2>/dev/null | head -15 \
            || echo "  (pf airtel_bypass anchor is empty or not loaded — bypass not applied)"
    else
        echo "  pfctl not found"
    fi
elif [[ "$FW_TYPE" == "iptables" ]]; then
    iptables -L OUTPUT -n --line-numbers 2>/dev/null | head -20 \
        || echo "  (iptables not available or permission denied)"
elif [[ "$FW_TYPE" == "nftables" ]]; then
    nft list table inet airtel_bypass 2>/dev/null | head -20 \
        || echo "  (airtel_bypass nftables table not found — bypass not applied)"
else
    echo "  (no supported firewall found)"
fi

# CONNECTIVITY
sec "CONNECTIVITY TEST"
if [[ "$OS_TYPE" == "macos" ]]; then
    ping_ok=$(ping -c 1 -t 2 1.1.1.1 &>/dev/null 2>&1 && echo "yes" || echo "no")
else
    ping_ok=$(ping -c 1 -W 2 1.1.1.1 &>/dev/null 2>&1 && echo "yes" || echo "no")
fi
if [[ "$ping_ok" == "yes" ]]; then
    echo -e "  ${GREEN}✓ Internet reachable (ping 1.1.1.1)${NC}"
else
    echo -e "  ${RED}✗ Cannot reach 1.1.1.1${NC}"
fi

echo ""
