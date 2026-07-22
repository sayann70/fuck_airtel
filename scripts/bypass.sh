#!/usr/bin/env bash
# ============================================================
# SYNOPSIS
#   Airtel 5G Hotspot Bypass – Makes tethered traffic appear
#   as native mobile traffic.
#
#   Platforms : macOS 12+, Linux (any modern distro)
#   Init      : systemd · OpenRC · runit · SysV
#   Distros   : Ubuntu/Debian · Fedora/RHEL/Rocky/CentOS · Arch/Manjaro
#               openSUSE · Alpine · Gentoo · Void · and derivatives
#   Firewall  : iptables · nftables · pf (macOS)
#
# DESCRIPTION
#   Addresses all known detection vectors:
#     1. TTL normalization (set to 65 so phone decrements to 64 = mobile)
#     2. MTU clamping to mobile-standard 1400
#     3. Block auto-update / package-manager traffic (desktop fingerprint)
#     4. DNS override to avoid APN-based split detection
#     5. Limit parallel TCP connections (desktops open way more than phones)
#     6. Block desktop-specific app / network-discovery fingerprints
#
# NOTES
#   Author  : sayann70 (github.com/sayann70)
#   License : MIT
#   Year    : 2026
#   Repo    : https://github.com/sayann70/fuck_airtel
#
#   Run as root (sudo ./bypass.sh).  Use --undo to revert all changes.
#   Contributions welcome — open a PR to add more sarcastic taglines.
# ============================================================
# Copyright (c) 2026 sayann70 (github.com/sayann70)
# MIT License — do whatever you want, just don't blame me if Airtel catches you.

set -euo pipefail

BACKUP_FILE="$HOME/.airtel_bypass_backup.json"
FW_BACKUP_FILE="$HOME/.airtel_bypass_fw.rules"
PF_ANCHOR_FILE="/etc/pf.anchors/airtel_bypass"

# Platform variables (populated by detect_platform)
OS_TYPE=""        # linux | macos
DISTRO_FAMILY=""  # debian | rhel | arch | alpine | suse | gentoo | void | unknown
INIT_SYSTEM=""    # systemd | openrc | runit | sysv | launchd | unknown
FW_TYPE=""        # iptables | nftables | pf | none
SYSCTL_CONF_FILE="" # path to sysctl persistence file

# Colour helpers 
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; GRAY='\033[0;37m'
DARK_GRAY='\033[1;30m'; WHITE='\033[1;37m'; NC='\033[0m'

# UI helpers
write_banner() {
    echo ""
    echo -e "${CYAN} █████╗ ██╗██████╗ ████████╗███████╗██╗         ██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗${NC}"
    echo -e "${CYAN}██╔══██╗██║██╔══██╗╚══██╔══╝██╔════╝██║         ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝${NC}"
    echo -e "${CYAN}███████║██║██████╔╝   ██║   █████╗  ██║         ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗${NC}"
    echo -e "${CYAN}██╔══██║██║██╔══██╗   ██║   ██╔══╝  ██║         ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║${NC}"
    echo -e "${CYAN}██║  ██║██║██║  ██║   ██║   ███████╗███████╗    ██████╔╝   ██║   ██║     ██║  ██║███████║███████║${NC}"
    echo -e "${CYAN}╚═╝  ╚═╝╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝    ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝${NC}"
    echo -e "${CYAN}    Fuck You Airtel.${NC}"
    echo ""

    # Random sarcastic tagline
    local taglines=(
        '"Unlimited" data but only on the device we choose? Nah.'
        'Airtel: "Unlimited*" (*Terms apply, hotspot not included, happiness not guaranteed)'
        'If my data is unlimited, why are you counting how I use it?'
        'Paying for unlimited data and using it however I want. Revolutionary concept.'
        'Dear Airtel, the "un" in "unlimited" means WITHOUT limits. Look it up.'
        'Airtel spent millions on hotspot detection. I spent 10 minutes on this script.'
        'They restrict your hotspot. We restrict their restrictions.'
        'My data. My device. My rules.'
        '"Your plan includes unlimited data!" ...just not for your laptop, TV, tablet, fridge...'
        'Airtel detects hotspot usage. This script detects Airtel detecting hotspot usage.'
    )
    local pick="${taglines[$((RANDOM % ${#taglines[@]}))]}"
    echo -e "${MAGENTA}  $pick${NC}"
    echo -e "${DARK_GRAY}  ─────────────────────────────────────────────────────────────${NC}"
    echo ""
}

write_step() { echo -e "  ${DARK_GRAY}[${NC}${CYAN}$1${NC}${DARK_GRAY}]${NC} ${WHITE}$2${NC}"; }
write_ok()   { echo -e "      ${GREEN}✓${NC} ${GRAY}$1${NC}"; }
write_warn() { echo -e "      ${YELLOW}⚠${NC} ${GRAY}$1${NC}"; }
write_err()  { echo -e "      ${RED}✗${NC} ${GRAY}$1${NC}"; }

# Utility
has_cmd() { command -v "$1" &>/dev/null; }

# Resolve a domain to its IP addresses (cross-platform, v4 + v6)
resolve_ips() {
    local domain="$1"
    if [[ "$OS_TYPE" == "macos" ]]; then
        if has_cmd dig; then
            dig +short "$domain" 2>/dev/null | grep -E '^[0-9a-fA-F:.]' || true
        elif has_cmd host; then
            host -t A "$domain" 2>/dev/null | awk '/has address/ {print $NF}' || true
        else
            dscacheutil -q host -a name "$domain" 2>/dev/null | awk '/ip_address:/ {print $2}' || true
        fi
    else
        if has_cmd getent; then
            getent ahosts "$domain" 2>/dev/null | awk '{print $1}' | sort -u || true
        elif has_cmd dig; then
            dig +short "$domain" 2>/dev/null | grep -E '^[0-9a-fA-F:.]' || true
        elif has_cmd host; then
            host -t A "$domain" 2>/dev/null | awk '/has address/ {print $NF}' || true
        elif has_cmd nslookup; then
            nslookup "$domain" 2>/dev/null | awk '/^Address/ && !/#/{print $NF}' | grep -E '^[0-9]' || true
        fi
    fi
}

# Platform Detection 
detect_platform() {
    # OS type
    case "$(uname -s)" in
        Darwin) OS_TYPE="macos" ;;
        *)      OS_TYPE="linux" ;;
    esac

    if [[ "$OS_TYPE" == "linux" ]]; then
        # Distro family — read /etc/os-release
        if [[ -f /etc/os-release ]]; then
            local id id_like
            id=$(. /etc/os-release && echo "${ID:-unknown}")
            id_like=$(. /etc/os-release && echo "${ID_LIKE:-}")
            local combined="${id_like,,} ${id,,}"
            case "$combined" in
                *debian*|*ubuntu*|*raspbian*|*mint*|*pop*)  DISTRO_FAMILY="debian" ;;
                *fedora*|*rhel*|*centos*|*rocky*|*alma*|*ol*) DISTRO_FAMILY="rhel" ;;
                *arch*|*manjaro*|*endeavour*|*garuda*)       DISTRO_FAMILY="arch" ;;
                *alpine*)                                    DISTRO_FAMILY="alpine" ;;
                *suse*|*sles*)                               DISTRO_FAMILY="suse" ;;
                *gentoo*)                                    DISTRO_FAMILY="gentoo" ;;
                *void*)                                      DISTRO_FAMILY="void" ;;
                *)                                           DISTRO_FAMILY="unknown" ;;
            esac
        else
            DISTRO_FAMILY="unknown"
        fi

        # Init system
        if   has_cmd systemctl && systemctl --version &>/dev/null 2>&1; then INIT_SYSTEM="systemd"
        elif has_cmd rc-service;                                         then INIT_SYSTEM="openrc"
        elif [[ -d /run/runit ]] || has_cmd sv;                         then INIT_SYSTEM="runit"
        elif has_cmd service;                                            then INIT_SYSTEM="sysv"
        else                                                                  INIT_SYSTEM="unknown"
        fi

        # Firewall
        if   has_cmd iptables; then FW_TYPE="iptables"
        elif has_cmd nft;      then FW_TYPE="nftables"
        else                        FW_TYPE="none"
        fi

        # Sysctl persistence file
        if [[ -d /etc/sysctl.d ]]; then
            SYSCTL_CONF_FILE="/etc/sysctl.d/99-airtel-bypass.conf"
        else
            SYSCTL_CONF_FILE="/etc/sysctl.conf"  # Alpine, older distros
        fi

    else  # macOS
        INIT_SYSTEM="launchd"
        FW_TYPE="pf"
        SYSCTL_CONF_FILE="/etc/sysctl.conf"
    fi
}

# Sysctl helpers 

# Set a sysctl key live and persist to conf file
sysctl_write() {
    local key="$1" val="$2"
    sysctl -w "${key}=${val}" > /dev/null 2>&1 || true
    if [[ -f "$SYSCTL_CONF_FILE" ]] && grep -q "^${key}" "$SYSCTL_CONF_FILE" 2>/dev/null; then
        # Update existing line (sed -i.bak works on both GNU and BSD/macOS sed)
        sed -i.bak "s|^${key}[[:space:]]*=.*|${key} = ${val}|" "$SYSCTL_CONF_FILE" && \
            rm -f "${SYSCTL_CONF_FILE}.bak" || true
    else
        echo "${key} = ${val}" >> "$SYSCTL_CONF_FILE"
    fi
}

# Remove all airtel-added sysctl entries
sysctl_remove_conf() {
    if [[ "$SYSCTL_CONF_FILE" == *"99-airtel-bypass.conf" ]]; then
        rm -f "$SYSCTL_CONF_FILE"
    else
        # Shared file — only remove the keys we added
        local keys=(
            "net.ipv4.ip_default_ttl"
            "net.ipv4.ip_local_port_range"
            "net.ipv4.tcp_window_scaling"
            "net.inet.ip.ttl"
            "net.inet6.ip6.hlim"
            "net.inet.ip.portrange.first"
            "net.inet.ip.portrange.last"
        )
        for key in "${keys[@]}"; do
            sed -i.bak "/^${key}[[:space:]]*=/d" "$SYSCTL_CONF_FILE" 2>/dev/null && \
                rm -f "${SYSCTL_CONF_FILE}.bak" || true
        done
    fi
}

# Service management helpers

svc_stop() {
    local svc="$1"
    case "$INIT_SYSTEM" in
        systemd) systemctl stop     "$svc" 2>/dev/null || true ;;
        openrc)  rc-service "$svc"  stop   2>/dev/null || true ;;
        runit)   sv stop     "$svc"        2>/dev/null || true ;;
        sysv)    service     "$svc" stop   2>/dev/null || true ;;
        launchd) launchctl unload -w "$svc" 2>/dev/null || true ;;
        *)       true ;;
    esac
}

svc_disable() {
    local svc="$1"
    case "$INIT_SYSTEM" in
        systemd) systemctl disable "$svc"  2>/dev/null || true ;;
        openrc)  rc-update del     "$svc"  2>/dev/null || true ;;
        runit)   rm -f "/var/service/${svc##*/}" 2>/dev/null || true ;;
        sysv)
            if   has_cmd update-rc.d; then update-rc.d "$svc" disable 2>/dev/null || true
            elif has_cmd chkconfig;   then chkconfig   "$svc" off     2>/dev/null || true
            fi ;;
        launchd) true ;; # unload -w already persists the disable
        *)       true ;;
    esac
}

svc_enable() {
    local svc="$1"
    case "$INIT_SYSTEM" in
        systemd) systemctl enable "$svc"   2>/dev/null || true ;;
        openrc)  rc-update add    "$svc" default 2>/dev/null || true ;;
        runit)   true ;; # runit enables via symlink — skip
        sysv)
            if   has_cmd update-rc.d; then update-rc.d "$svc" enable 2>/dev/null || true
            elif has_cmd chkconfig;   then chkconfig   "$svc" on     2>/dev/null || true
            fi ;;
        launchd) launchctl load -w "$svc"  2>/dev/null || true ;;
        *)       true ;;
    esac
}

svc_start() {
    local svc="$1"
    case "$INIT_SYSTEM" in
        systemd) systemctl start  "$svc"   2>/dev/null || true ;;
        openrc)  rc-service "$svc" start   2>/dev/null || true ;;
        runit)   sv start   "$svc"         2>/dev/null || true ;;
        sysv)    service    "$svc" start   2>/dev/null || true ;;
        launchd) launchctl load -w "$svc"  2>/dev/null || true ;;
        *)       true ;;
    esac
}

svc_is_active() {
    local svc="$1"
    case "$INIT_SYSTEM" in
        systemd) systemctl is-active --quiet "$svc" 2>/dev/null ;;
        openrc)  rc-service "$svc" status 2>/dev/null | grep -q 'started' ;;
        runit)   sv status  "$svc" 2>/dev/null | grep -q '^run:' ;;
        sysv)    service    "$svc" status 2>/dev/null | grep -q 'running' ;;
        launchd) launchctl list 2>/dev/null | grep -q "${svc##*/}" ;;
        *)       return 1 ;;
    esac
}

# Firewall helpers

# Initialize firewall — save current state and prepare for new rules
fw_init() {
    case "$FW_TYPE" in
        iptables)
            iptables-save > "$FW_BACKUP_FILE" 2>/dev/null || true
            ;;
        nftables)
            nft list ruleset > "$FW_BACKUP_FILE" 2>/dev/null || true
            # Remove stale table if it exists, then recreate cleanly
            nft delete table inet airtel_bypass 2>/dev/null || true
            nft -f - 2>/dev/null <<'NFT' || true
table inet airtel_bypass {
    set blocked_ips {
        type ipv4_addr
        flags interval
    }
    set blocked_ips6 {
        type ipv6_addr
        flags interval
    }
    chain output {
        type filter hook output priority 0 ; policy accept ;
        ip  daddr @blocked_ips  drop
        ip6 daddr @blocked_ips6 drop
    }
}
NFT
            ;;
        pf)
            # Save current pf rules
            pfctl -sr > "$FW_BACKUP_FILE" 2>/dev/null || true
            # Create anchor file
            mkdir -p "$(dirname "$PF_ANCHOR_FILE")"
            printf '# Airtel bypass anchor — managed by bypass.sh\n' > "$PF_ANCHOR_FILE"
            # Add anchor to pf.conf if not already there
            if ! grep -q 'airtel_bypass' /etc/pf.conf 2>/dev/null; then
                printf '\n# Added by airtel bypass script\nanchor "airtel_bypass"\nload anchor "airtel_bypass" from "%s"\n' \
                    "$PF_ANCHOR_FILE" >> /etc/pf.conf
            fi
            ;;
        none)
            write_warn "No firewall tool found (iptables/nft/pfctl). Domain/port blocking skipped."
            ;;
    esac
}

# Commit firewall rules (pf requires explicit reload)
fw_commit() {
    case "$FW_TYPE" in
        pf)
            pfctl -e 2>/dev/null || true
            pfctl -a airtel_bypass -f "$PF_ANCHOR_FILE" 2>/dev/null && \
                pfctl -f /etc/pf.conf 2>/dev/null || true
            ;;
        *) true ;;
    esac
}

# Restore firewall to pre-bypass state
fw_restore() {
    case "$FW_TYPE" in
        iptables)
            if [[ -f "$FW_BACKUP_FILE" ]]; then
                iptables-restore < "$FW_BACKUP_FILE" 2>/dev/null && \
                    write_ok "iptables rules restored from backup" || \
                    write_warn "iptables-restore failed — flushing OUTPUT chain instead"
            else
                iptables -F OUTPUT 2>/dev/null || true
                write_warn "No iptables backup — flushed OUTPUT chain (may affect other rules)"
            fi
            ip6tables -F OUTPUT 2>/dev/null || true
            write_ok "ip6tables OUTPUT chain flushed"
            ;;
        nftables)
            nft delete table inet airtel_bypass 2>/dev/null || true
            write_ok "nftables airtel_bypass table removed"
            ;;
        pf)
            # Flush only our anchor (leave system pf rules intact)
            echo "" | pfctl -a airtel_bypass -f - 2>/dev/null || true
            # Remove anchor lines from pf.conf
            sed -i.bak '/airtel_bypass/d' /etc/pf.conf 2>/dev/null && \
                rm -f /etc/pf.conf.bak || true
            sed -i.bak '/Added by airtel bypass/d' /etc/pf.conf 2>/dev/null && \
                rm -f /etc/pf.conf.bak || true
            rm -f "$PF_ANCHOR_FILE"
            pfctl -f /etc/pf.conf 2>/dev/null || true
            write_ok "pf anchor 'airtel_bypass' flushed and removed from pf.conf"
            ;;
    esac
}

# Drop outbound traffic to an IP address
fw_drop_ip() {
    local ip="$1"
    local is_v6=false
    [[ "$ip" == *:* ]] && is_v6=true

    case "$FW_TYPE" in
        iptables)
            if $is_v6; then
                ip6tables -C OUTPUT -d "$ip" -j DROP 2>/dev/null || \
                    ip6tables -A OUTPUT -d "$ip" -j DROP 2>/dev/null || true
            else
                iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null || \
                    iptables  -A OUTPUT -d "$ip" -j DROP
            fi
            ;;
        nftables)
            if $is_v6; then
                nft add element inet airtel_bypass blocked_ips6 { "$ip" } 2>/dev/null || true
            else
                nft add element inet airtel_bypass blocked_ips  { "$ip" } 2>/dev/null || true
            fi
            ;;
        pf)
            echo "block out quick to $ip" >> "$PF_ANCHOR_FILE"
            ;;
        none) true ;;
    esac
}

# Drop outbound traffic on a port/proto
fw_drop_port() {
    local proto="$1" port="$2" desc="${3:-port $port}"
    case "$FW_TYPE" in
        iptables)
            iptables -C OUTPUT -p "$proto" --dport "$port" -j DROP 2>/dev/null || \
                iptables -A OUTPUT -p "$proto" --dport "$port" -j DROP
            write_ok "Blocked ${desc} — ${port}/${proto} (iptables)"
            ;;
        nftables)
            echo "add rule inet airtel_bypass output $proto dport $port drop" | nft -f - 2>/dev/null || true
            write_ok "Blocked ${desc} — ${port}/${proto} (nftables)"
            ;;
        pf)
            echo "block out quick proto $proto from any to any port $port" >> "$PF_ANCHOR_FILE"
            write_ok "Blocked ${desc} — ${port}/${proto} (pf)"
            ;;
        none)
            write_warn "No firewall — cannot block ${desc} (${port}/${proto})"
            ;;
    esac
}

# Apply TCP MSS clamping
fw_mss_clamp() {
    case "$FW_TYPE" in
        iptables)
            iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
            iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
            iptables -t mangle -D OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
            iptables -t mangle -A OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360
            write_ok "TCP MSS clamped to 1360 (iptables MANGLE)"
            ;;
        nftables)
            # Use nft -f - to avoid shell special-character escaping issues
            echo 'add rule inet airtel_bypass output tcp flags & (syn|rst) == syn tcp option maxseg size set 1360' \
                | nft -f - 2>/dev/null && \
                write_ok "TCP MSS clamped to 1360 (nftables)" || \
                write_warn "nftables MSS clamping failed (kernel may not support tcp option maxseg)"
            ;;
        pf)
            echo "scrub out all max-mss 1360" >> "$PF_ANCHOR_FILE"
            write_ok "TCP MSS clamped to 1360 (pf scrub)"
            ;;
        none)
            write_warn "No firewall — TCP MSS clamping skipped"
            ;;
    esac
}

# Remove TCP MSS clamping rules
fw_mss_remove() {
    case "$FW_TYPE" in
        iptables)
            iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
            iptables -t mangle -D OUTPUT  -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360      2>/dev/null || true
            ;;
        nftables|pf) true ;; # handled by fw_restore
        none) true ;;
    esac
}

# Network helpers

get_wifi_iface() {
    local iface=""
    if [[ "$OS_TYPE" == "macos" ]]; then
        # Primary: networksetup — reliable even when interface is down
        iface=$(networksetup -listallhardwareports 2>/dev/null \
            | grep -A2 'Wi-Fi\|AirPort' \
            | awk '/^Device:/ {print $2; exit}')
        # Verify the interface actually has an IP (i.e., connected)
        if [[ -n "$iface" ]] && ! ifconfig "$iface" 2>/dev/null | grep -q 'inet '; then
            iface=""
        fi
        # Fallback: default route interface
        if [[ -z "$iface" ]]; then
            iface=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
        fi
    else
        # Linux: /sys/class/net/*/wireless is the canonical wireless check
        for dev in /sys/class/net/*/wireless; do
            [[ -e "$dev" ]] || continue
            local candidate
            candidate=$(basename "$(dirname "$dev")")
            local state
            state=$(cat "/sys/class/net/${candidate}/operstate" 2>/dev/null || echo "unknown")
            if [[ "$state" == "up" ]]; then
                iface="$candidate"
                break
            fi
        done
        # Fallback: iw dev (covers some drivers that don't use /sys/class/net/*/wireless)
        if [[ -z "$iface" ]] && has_cmd iw; then
            iface=$(iw dev 2>/dev/null | awk '/Interface/ {print $2; exit}')
        fi
        # Fallback: ip route default interface
        if [[ -z "$iface" ]] && has_cmd ip; then
            iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
        fi
    fi
    echo "$iface"
}

get_iface_mtu() {
    local iface="$1"
    if [[ "$OS_TYPE" == "macos" ]]; then
        ifconfig "$iface" 2>/dev/null | awk '/mtu/ {print $NF}' | head -1
    else
        ip link show "$iface" 2>/dev/null \
            | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu") print $(i+1)}' | head -1
    fi
}

set_iface_mtu() {
    local iface="$1" mtu="$2"
    if [[ "$OS_TYPE" == "macos" ]]; then
        ifconfig "$iface" mtu "$mtu" 2>/dev/null
    else
        ip link set "$iface" mtu "$mtu" 2>/dev/null
    fi
}

iface_bounce() {
    local iface="$1"
    if [[ "$OS_TYPE" == "macos" ]]; then
        ifconfig "$iface" down 2>/dev/null && sleep 2 && ifconfig "$iface" up 2>/dev/null || \
        networksetup -setnetworkserviceenabled Wi-Fi off 2>/dev/null && \
            sleep 2 && networksetup -setnetworkserviceenabled Wi-Fi on 2>/dev/null || true
    else
        ip link set "$iface" down 2>/dev/null && sleep 2 && ip link set "$iface" up 2>/dev/null
    fi
}

iface_state() {
    local iface="$1"
    if [[ "$OS_TYPE" == "macos" ]]; then
        if ifconfig "$iface" 2>/dev/null | grep -q 'status: active'; then
            echo "up"
        elif ifconfig "$iface" 2>/dev/null | grep -q 'inet '; then
            echo "up"
        else
            echo "unknown"
        fi
    else
        cat "/sys/class/net/${iface}/operstate" 2>/dev/null || echo "unknown"
    fi
}

get_current_ttl() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        sysctl -n net.inet.ip.ttl 2>/dev/null || echo "64"
    else
        sysctl -n net.ipv4.ip_default_ttl 2>/dev/null || echo "64"
    fi
}

get_current_dns() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        local ns
        ns=$(networksetup -getdnsservers Wi-Fi 2>/dev/null \
             | grep -v "aren't any" | tr '\n' ',' | sed 's/,$//')
        echo "${ns:-$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')}"
    else
        grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ',' | sed 's/,$//'
    fi
}

flush_dns_cache() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        dscacheutil -flushcache 2>/dev/null || true
        killall -HUP mDNSResponder 2>/dev/null || true
    else
        systemd-resolve --flush-caches 2>/dev/null || \
            resolvectl flush-caches    2>/dev/null || \
            nscd -i hosts              2>/dev/null || true
    fi
}

# SIP check (macOS)
check_sip() {
    if [[ "$OS_TYPE" == "macos" ]] && has_cmd csrutil; then
        if csrutil status 2>/dev/null | grep -qi 'enabled'; then
            write_warn "System Integrity Protection (SIP) is ENABLED."
            write_warn "Some sysctl writes may be silently blocked — domain/port blocking via pf still works."
        fi
    fi
}

# Domain block lists

LINUX_UPDATE_DOMAINS=(
    # Debian / Ubuntu / Raspbian / Mint / Pop!_OS
    "security.ubuntu.com"          "archive.ubuntu.com"
    "packages.debian.org"          "deb.debian.org"
    "ftp.debian.org"               "http.debian.net"
    "security.debian.org"
    "motd.ubuntu.com"              "changelogs.ubuntu.com"
    "livepatch.canonical.com"      "contracts.canonical.com"
    "snapcraft.io"                 "api.snapcraft.io"
    "store.canonical.com"
    # Fedora / RHEL / Rocky / CentOS / AlmaLinux
    "dl.fedoraproject.org"         "mirrors.fedoraproject.org"
    "packages.fedoraproject.org"   "cdn.redhat.com"
    "subscription.rhsm.redhat.com" "cdn-ubi.redhat.com"
    # openSUSE / SLES
    "download.opensuse.org"        "software.opensuse.org"
    "updates.suse.com"
    # Arch Linux / Manjaro / EndeavourOS
    "archlinux.org"                "geo.mirror.pkgbuild.com"
    "mirror.rackspace.com"         "mirrors.kernel.org"
    # Alpine Linux
    "dl-cdn.alpinelinux.org"
    # Gentoo
    "distfiles.gentoo.org"         "rsync.gentoo.org"
    # Void Linux
    "repo-default.voidlinux.org"
)

LINUX_TELEMETRY_DOMAINS=(
    "telemetry.ubuntu.com"         "metrics.ubuntu.com"
    "popcon.ubuntu.com"            "error-tracker.ubuntu.com"
    "report.bugs.launchpad.net"    "daisy.ubuntu.com"
    "certainty.canonical.com"      "oem-share.canonical.com"
    "crash-reports.archlinux.org"  "smolt.fedoraproject.org"
)

MACOS_UPDATE_DOMAINS=(
    "swscan.apple.com"
    "swcdn.apple.com"
    "updates.cdn-apple.com"
    "mesu.apple.com"
    "gdmf.apple.com"
    "xp.apple.com"
    "appldnld.apple.com"
    "oscdn.apple.com"
    "gg.apple.com"
)

MACOS_TELEMETRY_DOMAINS=(
    "analytics.apple.com"
    "radarsubmissions.apple.com"
    "feedbackws.apple.com"
    "metrics.apple.com"
    "pancake.apple.com"
    "icloud-diagnostics.apple.com"
)

#  APPLY MODE
apply_bypass() {
    write_banner
    echo -e "  ${DARK_GRAY}MODE: ${NC}${GREEN}APPLY BYPASS${NC}   Platform: ${CYAN}${OS_TYPE^^}${NC}  Init: ${CYAN}${INIT_SYSTEM}${NC}  FW: ${CYAN}${FW_TYPE}${NC}"
    if [[ "$OS_TYPE" == "linux" && "$DISTRO_FAMILY" != "unknown" ]]; then
        echo -e "  ${DARK_GRAY}Distro family: ${NC}${CYAN}${DISTRO_FAMILY}${NC}"
    fi
    echo ""
    check_sip

    local iface
    iface=$(get_wifi_iface)
    if [[ -z "$iface" ]]; then
        write_err "No active Wi-Fi adapter found. Connect to your phone's hotspot first."
        exit 1
    fi
    write_ok "Detected adapter: $iface"
    echo ""

    # Save backup state
    local orig_ttl orig_mtu orig_dns
    orig_ttl=$(get_current_ttl)
    orig_mtu=$(get_iface_mtu "$iface")
    orig_dns=$(get_current_dns)

    # Init firewall (saves current rules)
    fw_init

    cat > "$BACKUP_FILE" <<JSON
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "os_type": "$OS_TYPE",
  "distro_family": "$DISTRO_FAMILY",
  "init_system": "$INIT_SYSTEM",
  "fw_type": "$FW_TYPE",
  "iface": "$iface",
  "orig_ttl": "$orig_ttl",
  "orig_mtu": "$orig_mtu",
  "orig_dns": "$orig_dns",
  "fw_backup": "$FW_BACKUP_FILE"
}
JSON
    write_ok "Backup saved to $BACKUP_FILE"
    echo ""

    #  1. TTL NORMALIZATION
    # Phones have TTL=64. When phone acts as hotspot router it decrements by 1.
    # Linux/macOS traffic arrives at carrier with TTL=64-1=63 → dead giveaway.
    # Fix: set TTL to 65. Phone decrements to 64. Looks like native mobile traffic.
    write_step "1" "TTL Normalization (65 → phone decrements to 64 = mobile)"

    if [[ "$OS_TYPE" == "macos" ]]; then
        sysctl_write "net.inet.ip.ttl"    "65"
        sysctl_write "net.inet6.ip6.hlim" "65"
        write_ok "IPv4 TTL + IPv6 Hop Limit set to 65 ($SYSCTL_CONF_FILE)"
    else
        sysctl_write "net.ipv4.ip_default_ttl" "65"
        write_ok "IPv4 TTL set to 65 (live + $SYSCTL_CONF_FILE)"

        # IPv6 hop limit via ip6tables HL target (needs xt_HL kernel module)
        if [[ "$FW_TYPE" == "iptables" ]]; then
            ip6tables -t mangle -D OUTPUT -j HL --hl-set 65 2>/dev/null || true
            ip6tables -t mangle -A OUTPUT -j HL --hl-set 65 2>/dev/null && \
                write_ok "IPv6 Hop Limit set to 65 (ip6tables HL)" || \
                write_warn "ip6tables HL target unavailable (needs xt_HL module) — IPv4 TTL still set"
        fi
    fi

    # 2. MTU CLAMPING
    # Mobile devices use MTU ~1400; Linux/macOS default is 1500.
    write_step "2" "MTU Clamping (1500 → 1400 to match mobile)"
    set_iface_mtu "$iface" 1400 2>/dev/null && \
        write_ok "MTU set to 1400 on $iface" || \
        write_warn "Failed to set MTU on $iface — adapter may not support live changes"
    fw_mss_clamp

    #  3. BLOCK AUTO-UPDATE TRAFFIC
    # apt/dnf/snap/softwareupdate traffic is a dead giveaway — phones don't do this.
    write_step "3" "Blocking auto-update traffic (desktop fingerprint)"

    local -a update_domains
    if [[ "$OS_TYPE" == "macos" ]]; then
        update_domains=("${MACOS_UPDATE_DOMAINS[@]}")
    else
        update_domains=("${LINUX_UPDATE_DOMAINS[@]}")
    fi

    local blocked_update=0
    for domain in "${update_domains[@]}"; do
        local ips
        ips=$(resolve_ips "$domain") || true
        for ip in $ips; do
            fw_drop_ip "$ip"
            (( blocked_update++ )) || true
        done
    done
    write_ok "Blocked update domains (${#update_domains[@]} domains, $blocked_update IP entries)"

    # Stop update daemons / timers
    if [[ "$OS_TYPE" == "macos" ]]; then
        write_warn "macOS system update daemons are SIP-protected — domain blocking via pf covers them."
    else
        case "$DISTRO_FAMILY" in
            debian)
                for svc in apt-daily apt-daily-upgrade unattended-upgrades packagekit; do
                    svc_stop    "$svc"
                    svc_disable "$svc"
                done
                for timer in apt-daily.timer apt-daily-upgrade.timer; do
                    svc_stop    "$timer"
                    svc_disable "$timer"
                done
                # Hold snap refreshes if snap is installed
                has_cmd snap && snap set system \
                    refresh.hold="$(date --date='+30 days' +%Y-%m-%dT%H:%M:%S+00:00 2>/dev/null || date -v+30d +%Y-%m-%dT%H:%M:%S+00:00 2>/dev/null)" \
                    2>/dev/null || true
                ;;
            rhel)
                for svc in dnf-automatic packagekit; do
                    svc_stop    "$svc"
                    svc_disable "$svc"
                done
                ;;
            arch)
                svc_stop    "reflector" 2>/dev/null || true
                svc_disable "reflector" 2>/dev/null || true
                ;;
            suse)
                for svc in zypp-refresh packagekit; do
                    svc_stop    "$svc"
                    svc_disable "$svc"
                done
                ;;
            alpine|gentoo|void)
                # These distros have no auto-update daemon by default
                true
                ;;
            *)
                svc_stop    "packagekit"
                svc_disable "packagekit"
                ;;
        esac
        write_ok "Auto-update services/timers stopped & disabled"

        # Systemd timers for snap (Debian/Ubuntu)
        if [[ "$INIT_SYSTEM" == "systemd" ]]; then
            systemctl stop    snapd.refresh.timer 2>/dev/null || true
            systemctl disable snapd.refresh.timer 2>/dev/null || true
        fi
    fi

    # 4. BLOCK TELEMETRY 
    write_step "4" "Blocking telemetry (desktop fingerprint)"

    local -a telemetry_domains
    if [[ "$OS_TYPE" == "macos" ]]; then
        telemetry_domains=("${MACOS_TELEMETRY_DOMAINS[@]}")
    else
        telemetry_domains=("${LINUX_TELEMETRY_DOMAINS[@]}")
    fi

    local blocked_telemetry=0
    for domain in "${telemetry_domains[@]}"; do
        local ips
        ips=$(resolve_ips "$domain") || true
        for ip in $ips; do
            fw_drop_ip "$ip"
            (( blocked_telemetry++ )) || true
        done
    done
    write_ok "Blocked telemetry domains (${#telemetry_domains[@]} domains, $blocked_telemetry IP entries)"

    # 5. DNS OVERRIDE
    # Override DNS to Cloudflare to avoid APN-based routing traps.
    write_step "5" "DNS Override (bypass APN-based traffic splitting)"

    [[ ! -f /etc/resolv.conf.airtel_backup ]] && \
        cp /etc/resolv.conf /etc/resolv.conf.airtel_backup 2>/dev/null || true

    if [[ "$OS_TYPE" == "macos" ]]; then
        networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1 2>/dev/null && \
            write_ok "DNS set via networksetup (Wi-Fi): 1.1.1.1, 1.0.0.1" || \
            write_warn "networksetup DNS set failed — resolv.conf override still applied"
    else
        # systemd-resolved: use resolvectl
        if svc_is_active "systemd-resolved" 2>/dev/null; then
            resolvectl dns "$iface" 1.1.1.1 1.0.0.1 2>/dev/null && \
                write_ok "DNS set via resolvectl on $iface: 1.1.1.1, 1.0.0.1" || \
                write_warn "resolvectl failed — resolv.conf override covers this"
            resolvectl dnsovertls "$iface" opportunistic 2>/dev/null || true
            write_ok "DNS-over-TLS set to opportunistic"
        fi

        # NetworkManager: persist DNS for the active connection
        if svc_is_active "NetworkManager" 2>/dev/null && has_cmd nmcli; then
            local active_con
            active_con=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null \
                | grep "$iface" | cut -d: -f1 | head -1) || true
            if [[ -n "${active_con:-}" ]]; then
                nmcli con mod "$active_con" ipv4.dns "1.1.1.1 1.0.0.1" 2>/dev/null || true
                nmcli con mod "$active_con" ipv4.ignore-auto-dns yes        2>/dev/null || true
                write_ok "DNS pinned in NetworkManager for '$active_con'"
            fi
        fi
    fi

    # Write resolv.conf directly — works universally as belt-and-suspenders
    cat > /etc/resolv.conf <<DNS
# Managed by airtel bypass script — run undo_bypass.sh to restore
nameserver 1.1.1.1
nameserver 1.0.0.1
DNS
    write_ok "DNS set to 1.1.1.1, 1.0.0.1 in /etc/resolv.conf"

    flush_dns_cache
    write_ok "DNS cache flushed"

    # 6. LIMIT PARALLEL TCP CONNECTIONS
    # Desktops open 50-100+ parallel TCP connections. Phones open ~10-20.
    write_step "6" "Limiting parallel TCP connections (desktop → mobile profile)"

    if [[ "$OS_TYPE" == "macos" ]]; then
        sysctl_write "net.inet.ip.portrange.first" "49152"
        sysctl_write "net.inet.ip.portrange.last"  "65535"
        write_ok "Ephemeral port range reduced to 49152-65535 (macOS)"
        write_ok "macOS TCP profile already close to mobile-like — skipping aggressive tuning"
    else
        sysctl_write "net.ipv4.ip_local_port_range" "49152 53247"
        write_ok "Ephemeral port range reduced to 49152-53247"

        sysctl_write "net.ipv4.tcp_window_scaling" "0"
        write_ok "TCP Window Scaling disabled (live + $SYSCTL_CONF_FILE)"

        sysctl -w net.netfilter.nf_conntrack_max=65536 > /dev/null 2>/dev/null || true
        write_ok "conntrack table capped to 65536"
    fi

    # 7. BLOCK DESKTOP-SPECIFIC APP SIGNATURES 
    write_step "7" "Blocking desktop-specific app signatures"

    # SSDP/UPnP — desktop network discovery (phones don't do this on cellular)
    fw_drop_port "udp" "1900" "SSDP/UPnP discovery"
    # mDNS / Bonjour — desktop-only on cellular connections
    fw_drop_port "udp" "5353" "mDNS (Bonjour)"
    # LLMNR — Windows-like but also Linux systemd-resolved
    fw_drop_port "udp" "5355" "LLMNR"
    # NetBIOS — Linux Samba/nmbd, desktop-exclusive on cellular
    fw_drop_port "udp" "137"  "NetBIOS-NS"
    fw_drop_port "udp" "138"  "NetBIOS-DGM"

    if [[ "$OS_TYPE" == "macos" ]]; then
        # Stopping mDNSResponder breaks macOS networking — pf port blocks above suffice
        write_warn "macOS: Bonjour/mDNS daemon is SIP-protected — ports already blocked via pf rules above"
    else
        svc_stop    "avahi-daemon"  ;  svc_disable "avahi-daemon"
        write_ok "Avahi (mDNS daemon) stopped & disabled"
        svc_stop    "nmbd"          ;  svc_disable "nmbd"
        write_ok "nmbd (Samba NetBIOS) stopped & disabled"
        svc_stop    "geoclue"
        write_ok "geoclue (location service) stopped"
        svc_stop    "fwupd"         ;  svc_disable "fwupd"
        write_ok "fwupd (firmware updater) stopped & disabled"
    fi

    # 8. ADDITIONAL HARDENING
    write_step "+" "Additional hardening"

    if [[ "$OS_TYPE" == "linux" ]]; then
        # Disable IPv6 temporary address randomisation (random addresses look like probing)
        sysctl -w "net.ipv6.conf.${iface}.use_tempaddr=0" > /dev/null 2>/dev/null || true
        write_ok "IPv6 temporary address randomisation disabled on $iface"
        # Disable IPv6 router solicitations (phones on cellular don't send RS)
        sysctl -w "net.ipv6.conf.${iface}.router_solicitations=0" > /dev/null 2>/dev/null || true
        write_ok "IPv6 router solicitations disabled on $iface"
    else
        write_ok "macOS: IPv6 RA handling is already minimal on Wi-Fi (no extra changes needed)"
    fi

    # Commit all pf rules in one reload (macOS)
    if [[ "$FW_TYPE" == "pf" ]]; then
        fw_commit && write_ok "pf rules committed and firewall enabled"
    fi

    # ADAPTER BOUNCE
    write_step "⚡" "Bouncing adapter to apply all changes LIVE"
    iface_bounce "$iface"
    sleep 3   # Wait for DHCP / reconnect
    local state
    state=$(iface_state "$iface")
    if [[ "$state" == "up" ]]; then
        write_ok "Adapter $iface is UP — all changes are LIVE"
    else
        write_warn "Adapter $iface state: $state — you may need to reconnect to hotspot manually"
    fi

    #  SUMMARY
    echo ""
    echo -e "  ${DARK_GRAY}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}ALL BYPASSES APPLIED — NO REBOOT NEEDED${NC}"
    echo -e "  ${DARK_GRAY}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${YELLOW}⚡ Everything is live. Your traffic now mimics a mobile device.${NC}"
    echo -e "  ${YELLOW}⚡ If Wi-Fi disconnected, just reconnect to your hotspot.${NC}"
    echo -e "  ${YELLOW}⚡ Run ${NC}${CYAN}sudo ./undo_bypass.sh${NC}${YELLOW} to revert everything.${NC}"
    echo ""

    local live_ttl live_mtu live_dns
    live_ttl=$(get_current_ttl)
    live_mtu=$(get_iface_mtu "$iface")
    live_dns=$(get_current_dns)
    echo -e "  ${DARK_GRAY}Current Settings:${NC}"
    echo -e "  ${GRAY}  TTL: $live_ttl | MTU: $live_mtu | DNS: $live_dns${NC}"
    echo ""
}

#  UNDO MODE
undo_bypass() {
    write_banner
    echo -e "  ${DARK_GRAY}MODE: ${NC}${RED}UNDO / REVERT ALL CHANGES${NC}   Platform: ${CYAN}${OS_TYPE^^}${NC}  FW: ${CYAN}${FW_TYPE}${NC}"
    echo ""

    # Load backup values
    local orig_ttl="64" orig_mtu="1500" orig_dns="" iface=""
    if [[ -f "$BACKUP_FILE" ]]; then
        orig_ttl=$(grep -o '"orig_ttl": *"[^"]*"' "$BACKUP_FILE" | cut -d'"' -f4)
        orig_mtu=$(grep -o '"orig_mtu": *"[^"]*"' "$BACKUP_FILE" | cut -d'"' -f4)
        orig_dns=$(grep -o '"orig_dns": *"[^"]*"' "$BACKUP_FILE" | cut -d'"' -f4)
        iface=$(grep -o '"iface": *"[^"]*"' "$BACKUP_FILE"       | cut -d'"' -f4)
        write_ok "Loaded backup from $BACKUP_FILE"
    else
        write_warn "No backup found — reverting to platform defaults"
        iface=$(get_wifi_iface)
    fi
    echo ""

    # 1. Revert TTL 
    write_step "1" "Reverting TTL"
    if [[ "$OS_TYPE" == "macos" ]]; then
        sysctl -w "net.inet.ip.ttl=${orig_ttl:-64}"    > /dev/null 2>/dev/null || true
        sysctl -w "net.inet6.ip6.hlim=${orig_ttl:-64}" > /dev/null 2>/dev/null || true
        write_ok "IPv4 TTL + IPv6 Hop Limit restored to ${orig_ttl:-64}"
    else
        sysctl -w "net.ipv4.ip_default_ttl=${orig_ttl:-64}" > /dev/null
        write_ok "IPv4 TTL restored to ${orig_ttl:-64}"
        ip6tables -t mangle -D OUTPUT -j HL --hl-set 65 2>/dev/null || true
        write_ok "IPv6 Hop Limit rule removed"
    fi
    sysctl_remove_conf
    write_ok "Sysctl persistence file cleaned up ($SYSCTL_CONF_FILE)"

    # 2. Revert MTU
    write_step "2" "Reverting MTU"
    if [[ -n "$iface" ]]; then
        set_iface_mtu "$iface" "${orig_mtu:-1500}" 2>/dev/null && \
            write_ok "MTU restored to ${orig_mtu:-1500} on $iface" || \
            write_warn "Failed to restore MTU — will reset on next connection"
    fi
    fw_mss_remove
    write_ok "TCPMSS clamp rules removed"

    # 3. Restore firewall
    write_step "3" "Restoring firewall rules"
    fw_restore

    # 4. Restore services
    write_step "4" "Restoring services"
    if [[ "$OS_TYPE" == "macos" ]]; then
        write_ok "macOS services were not stopped (SIP-protected) — nothing to restore"
    else
        case "$DISTRO_FAMILY" in
            debian)
                for svc in apt-daily apt-daily-upgrade unattended-upgrades; do
                    svc_enable "$svc" ; svc_start "$svc"
                done
                for timer in apt-daily.timer apt-daily-upgrade.timer; do
                    svc_enable "$timer" ; svc_start "$timer"
                done
                ;;
            rhel)
                svc_enable "dnf-automatic" ; svc_start "dnf-automatic"
                ;;
            *)
                true ;;
        esac
        svc_enable "avahi-daemon" ; svc_start "avahi-daemon"
        svc_enable "fwupd"        ; svc_start "fwupd"
        write_ok "Services restored (update timers, avahi, fwupd)"

        # Restore Linux TCP settings
        sysctl -w net.ipv4.ip_local_port_range="32768 60999" > /dev/null
        sysctl -w net.ipv4.tcp_window_scaling=1              > /dev/null
        write_ok "Linux TCP settings restored to defaults"
    fi

    # Restore macOS TCP port range
    if [[ "$OS_TYPE" == "macos" ]]; then
        sysctl -w net.inet.ip.portrange.first=1024 > /dev/null 2>/dev/null || true
        sysctl -w net.inet.ip.portrange.last=65535 > /dev/null 2>/dev/null || true
        write_ok "macOS TCP port range restored to defaults"
    fi

    # 5. Revert DNS
    write_step "5" "Reverting DNS"

    if [[ -f /etc/resolv.conf.airtel_backup ]]; then
        cp /etc/resolv.conf.airtel_backup /etc/resolv.conf
        rm -f /etc/resolv.conf.airtel_backup
        write_ok "resolv.conf restored from backup"
    fi

    if [[ "$OS_TYPE" == "macos" ]]; then
        if [[ -n "${orig_dns:-}" ]] && ! echo "$orig_dns" | grep -q "aren't"; then
            # Restore original DNS (comma-separated → space-separated for networksetup)
            local dns_args
            dns_args=$(echo "$orig_dns" | tr ',' ' ')
            # shellcheck disable=SC2086
            networksetup -setdnsservers Wi-Fi $dns_args 2>/dev/null && \
                write_ok "DNS restored to original via networksetup: $orig_dns" || \
                write_warn "networksetup DNS restore failed — check Wi-Fi DNS settings manually"
        else
            # No original DNS saved — revert to DHCP
            networksetup -setdnsservers Wi-Fi "Empty" 2>/dev/null && \
                write_ok "DNS reverted to DHCP (networksetup)" || \
                write_warn "Could not revert to DHCP DNS — check Wi-Fi DNS settings manually"
        fi
    else
        if ! [[ -f /etc/resolv.conf.airtel_backup ]]; then
            # resolv.conf backup didn't exist — try NM / dhclient fallback
            if svc_is_active "NetworkManager" 2>/dev/null && has_cmd nmcli; then
                nmcli general reload dns-full 2>/dev/null || true
                write_ok "NetworkManager DNS reloaded"
            elif [[ -n "$iface" ]] && has_cmd dhclient; then
                dhclient -r "$iface" 2>/dev/null && dhclient "$iface" 2>/dev/null || true
                write_ok "dhclient re-ran for $iface"
            else
                write_warn "Could not restore DNS automatically — check /etc/resolv.conf manually"
            fi
        fi

        if svc_is_active "systemd-resolved" 2>/dev/null && [[ -n "$iface" ]]; then
            resolvectl revert      "$iface" 2>/dev/null || true
            resolvectl flush-caches         2>/dev/null || true
            write_ok "systemd-resolved reverted on $iface and cache flushed"
        fi
    fi

    flush_dns_cache
    write_ok "DNS cache flushed"

    # Cleanup backup files
    rm -f "$BACKUP_FILE" "$FW_BACKUP_FILE"
    write_ok "Backup files removed"

    # Adapter bounce 
    write_step "⚡" "Applying reverts LIVE"
    if [[ -n "$iface" ]]; then
        iface_bounce "$iface"
        sleep 3
        write_ok "Adapter $iface bounced — all reverts are LIVE"
    fi

    echo ""
    echo -e "  ${DARK_GRAY}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}ALL CHANGES REVERTED — NO REBOOT NEEDED${NC}"
    echo -e "  ${DARK_GRAY}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  ${YELLOW}⚡ Everything is back to normal. Reconnect to Wi-Fi if needed.${NC}"
    echo ""
}

# Entry point
if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}  ERROR: This script must be run as root!${NC}"
    echo -e "${YELLOW}  Run: sudo $0${NC}"
    exit 1
fi

detect_platform

if [[ "${1:-}" == "--undo" || "${1:-}" == "-u" ]]; then
    undo_bypass
else
    apply_bypass
fi
