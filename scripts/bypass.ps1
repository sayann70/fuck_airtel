<#
.SYNOPSIS
    Airtel 5G Hotspot Bypass - Makes tethered traffic appear as native mobile traffic.

.DESCRIPTION
    Addresses all known detection vectors:
      1. TTL normalization (set to 65 so phone decrements to 64 = mobile)
      2. MTU clamping to mobile-standard 1400
      3. Block Windows Update & telemetry (OS update requests are a giveaway)
      4. DNS override to avoid APN-based split detection
      5. MTU + packet fragmentation prevention
      6. Limit parallel TCP connections (desktops open way more than phones)
      7. Block desktop-specific User-Agent / app traffic fingerprints

.NOTES
    Author  : sayann70 (github.com/sayann70)
    License : MIT
    Year    : 2026
    Repo    : https://github.com/sayann70/fuck_airtel

    Run as Administrator. Use -Undo to revert all changes.
    Contributions welcome — open a PR to add more sarcastic taglines or any improvemnts to the repo.
#>
# Copyright (c) 2026 sayann70 (github.com/sayann70)
# MIT License — do whatever you want, just don't blame me if Airtel catches you. (well that apples to me as well,fuck!)

param(
    [switch]$Undo
)

# Helpers

$FW_PREFIX      = "AirtelBypass"
$BACKUP_FILE    = "$env:USERPROFILE\.airtel_bypass_backup.json"

function Write-Banner {
    $banner = @"

     █████╗ ██╗██████╗ ████████╗███████╗██╗         ██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
    ██╔══██╗██║██╔══██╗╚══██╔══╝██╔════╝██║         ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
    ███████║██║██████╔╝   ██║   █████╗  ██║         ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
    ██╔══██║██║██╔══██╗   ██║   ██╔══╝  ██║         ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
    ██║  ██║██║██║  ██║   ██║   ███████╗███████╗    ██████╔╝   ██║   ██║     ██║  ██║███████║███████║
    ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝    ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
    Fuck You Airtel.
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
    # Random sarcastic tagline on each run
    $taglines = @(
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
    $pick = $taglines | Get-Random
    Write-Host "  $pick" -ForegroundColor Magenta
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Step([string]$num, [string]$msg) {
    Write-Host "  [" -NoNewline -ForegroundColor DarkGray
    Write-Host $num -NoNewline -ForegroundColor Cyan
    Write-Host "] " -NoNewline -ForegroundColor DarkGray
    Write-Host $msg -ForegroundColor White
}

function Write-Ok([string]$msg) {
    Write-Host "      ✓ " -NoNewline -ForegroundColor Green
    Write-Host $msg -ForegroundColor Gray
}

function Write-Warn([string]$msg) {
    Write-Host "      ⚠ " -NoNewline -ForegroundColor Yellow
    Write-Host $msg -ForegroundColor Gray
}

function Write-Err([string]$msg) {
    Write-Host "      ✗ " -NoNewline -ForegroundColor Red
    Write-Host $msg -ForegroundColor Gray
}

function Get-ActiveWifiAdapter {
    # Get the Wi-Fi adapter connected to the phone's hotspot
    $adapters = Get-NetAdapter | Where-Object {
        $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'Wi-Fi|Wireless|WLAN|802\.11')
    }
    if (-not $adapters) {
        # Fallback: any active adapter
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    }
    return $adapters | Select-Object -First 1
}

# Windows Update domains to block 
# These generate traffic patterns that are uniquely desktop/Windows
$UPDATE_DOMAINS = @(
    "update.microsoft.com"
    "windowsupdate.microsoft.com"
    "download.windowsupdate.com"
    "dl.delivery.mp.microsoft.com"
    "download.microsoft.com"
    "ctldl.windowsupdate.com"
    "ntservicepack.microsoft.com"
    "go.microsoft.com"
    "fe2cr.update.microsoft.com"
    "fe3cr.delivery.mp.microsoft.com"
    "sls.update.microsoft.com"
    "settings-win.data.microsoft.com"
    "wustat.windows.com"
    "cds.d2s7q6s2.hwcdn.net"
    "tsfe.trafficshaping.dsp.mp.microsoft.com"
)

# Telemetry domains (also desktop-specific fingerprints)
$TELEMETRY_DOMAINS = @(
    "vortex.data.microsoft.com"
    "vortex-win.data.microsoft.com"
    "telecommand.telemetry.microsoft.com"
    "oca.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "watson.microsoft.com"
    "feedback.microsoft.com"
    "feedback.windows.com"
    "diagnostics.support.microsoft.com"
)

#  APPLY MODE

function Apply-Bypass {
    Write-Banner
    Write-Host "  MODE: " -NoNewline -ForegroundColor DarkGray
    Write-Host "APPLY BYPASS" -ForegroundColor Green
    Write-Host ""

    $adapter = Get-ActiveWifiAdapter
    if (-not $adapter) {
        Write-Err "No active Wi-Fi adapter found. Connect to your phone's hotspot first."
        return
    }
    $ifIndex = $adapter.ifIndex
    $ifAlias = $adapter.InterfaceAlias
    Write-Ok "Detected adapter: $ifAlias (Index: $ifIndex)"
    Write-Host ""

    # Save backup 
    $backup = @{
        Timestamp   = (Get-Date).ToString("o")
        AdapterName = $ifAlias
        IfIndex     = $ifIndex
    }

    # 1. TTL FIX 
    # Phones have TTL=64. When phone acts as router, it decrements by 1.
    # So laptop traffic arrives at carrier with TTL=127 (Windows default) - 1 = 126. Dead giveaway.
    # Fix: Set TTL to 65. Phone decrements to 64. Looks like native mobile traffic.
    Write-Step "1" "TTL Normalization (65 → phone decrements to 64 = mobile)"

    # Save current TTL
    $currentTTL = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -ErrorAction SilentlyContinue).DefaultTTL
    $backup.OriginalTTL = $currentTTL  # null if not set (Windows default 128)

    # Set IPv4 TTL (registry = persists across reboots)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Value 65 -Type DWord -Force
    # LIVE: Apply TTL immediately to running stack (no reboot needed)
    netsh int ipv4 set global defaultcurhoplimit=65 2>$null | Out-Null
    Write-Ok "IPv4 TTL set to 65 (registry + live)"

    # Set IPv6 Hop Limit
    $ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    if (-not (Test-Path $ipv6Path)) { New-Item -Path $ipv6Path -Force | Out-Null }
    $currentHopLimit = (Get-ItemProperty -Path $ipv6Path -Name "DefaultHopLimit" -ErrorAction SilentlyContinue).DefaultHopLimit
    $backup.OriginalHopLimit = $currentHopLimit
    Set-ItemProperty -Path $ipv6Path -Name "DefaultHopLimit" -Value 65 -Type DWord -Force
    # LIVE: Apply IPv6 hop limit immediately
    netsh int ipv6 set global defaultcurhoplimit=65 2>$null | Out-Null
    Write-Ok "IPv6 Hop Limit set to 65 (registry + live)"

    #  2. MTU CLAMPING
    # Mobile devices use MTU ~1400. Windows defaults to 1500.
    # Carrier can detect fragmentation patterns unique to higher-MTU devices.
    Write-Step "2" "MTU Clamping (1500 → 1400 to match mobile)"

    $currentMTU = (Get-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4).NlMtu
    $backup.OriginalMTU = $currentMTU

    Set-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -NlMtuBytes 1400 -ErrorAction SilentlyContinue
    Set-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv6 -NlMtuBytes 1400 -ErrorAction SilentlyContinue
    Write-Ok "MTU set to 1400 on $ifAlias"

    # 3. BLOCK WINDOWS UPDATE 
    # Windows Update traffic is a dead giveaway — no phone does this.
    # Block via Windows Firewall outbound rules.
    Write-Step "3" "Blocking Windows Update traffic (desktop fingerprint)"

    # Remove any old rules first
    Get-NetFirewallRule -DisplayName "${FW_PREFIX}_BlockUpdate_*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    foreach ($domain in $UPDATE_DOMAINS) {
        try {
            # Resolve to IPs and block
            $ips = [System.Net.Dns]::GetHostAddresses($domain) | ForEach-Object { $_.IPAddressToString }
            if ($ips) {
                $ruleName = "${FW_PREFIX}_BlockUpdate_$($domain -replace '\.','_')"
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound `
                    -RemoteAddress $ips -Action Block -Profile Any `
                    -Description "Blocks $domain to prevent hotspot detection" `
                    -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {
            # DNS resolution failed — domain might not resolve, skip
        }
    }
    Write-Ok "Blocked $($UPDATE_DOMAINS.Count) Windows Update domains"

    # Also stop the Windows Update service temporarily
    $wuStatus = (Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status
    $backup.WUServiceStatus = $wuStatus
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Ok "Windows Update service stopped & disabled"

    # 4. BLOCK TELEMETRY 
    # Telemetry is another desktop-only traffic pattern
    Write-Step "4" "Blocking Windows Telemetry (desktop fingerprint)"

    foreach ($domain in $TELEMETRY_DOMAINS) {
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($domain) | ForEach-Object { $_.IPAddressToString }
            if ($ips) {
                $ruleName = "${FW_PREFIX}_BlockTelemetry_$($domain -replace '\.','_')"
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound `
                    -RemoteAddress $ips -Action Block -Profile Any `
                    -Description "Blocks $domain telemetry" `
                    -ErrorAction SilentlyContinue | Out-Null
            }
        } catch { }
    }
    Write-Ok "Blocked $($TELEMETRY_DOMAINS.Count) telemetry domains"

    # Stop telemetry services
    $diagStatus = (Get-Service -Name DiagTrack -ErrorAction SilentlyContinue).Status
    $backup.DiagTrackStatus = $diagStatus
    Stop-Service -Name DiagTrack -Force -ErrorAction SilentlyContinue
    Set-Service -Name DiagTrack -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Ok "Diagnostics Tracking service stopped & disabled"

    # Stop WpnService (Windows Push Notifications) — connects to Microsoft Azure, 100% desktop-exclusive
    $wpnStatus = (Get-Service -Name WpnService -ErrorAction SilentlyContinue).Status
    $backup.WpnServiceStatus = $wpnStatus
    Stop-Service -Name WpnService -Force -ErrorAction SilentlyContinue
    Set-Service -Name WpnService -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Ok "Windows Push Notification service stopped & disabled"

    # Stop CDPSvc + CDPUserSvc (Connected Devices Platform — both the system and per-user variants)
    # CDPUserSvc is what actually runs CrossDeviceService.exe on Windows 11
    $cdpStatus = (Get-Service -Name CDPSvc -ErrorAction SilentlyContinue).Status
    $backup.CDPSvcStatus = $cdpStatus
    Stop-Service -Name CDPSvc -Force -ErrorAction SilentlyContinue
    Set-Service -Name CDPSvc -StartupType Disabled -ErrorAction SilentlyContinue
    # CDPUserSvc has a per-user suffix (e.g. CDPUserSvc_1a2b3), find and stop all instances
    Get-Service | Where-Object { $_.Name -like 'CDPUserSvc*' } | ForEach-Object {
        Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
        Set-Service  -Name $_.Name -StartupType Disabled -ErrorAction SilentlyContinue
    }
    Write-Ok "Connected Devices Platform (CDPSvc + CDPUserSvc) stopped & disabled"

    # 5. DNS OVERRIDE 
    # If APN is configured to split hotspot traffic via DNS, override it.
    # Use Cloudflare DNS (carrier-neutral) to avoid APN-based routing traps.
    Write-Step "5" "DNS Override (bypass APN-based traffic splitting)"

    $currentDNS = (Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4).ServerAddresses
    $backup.OriginalDNS = $currentDNS

    Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses @("1.1.1.1", "1.0.0.1")
    Write-Ok "DNS set to 1.1.1.1, 1.0.0.1 (Cloudflare)"

    # Enable DNS-over-HTTPS to encrypt DNS queries (prevents DPI on DNS)
    try {
        # Windows 11+ supports DoH natively
        $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        if ($null -ne $dohServers) {
            Set-DnsClientDohServerAddress -ServerAddress "1.1.1.1" -DohTemplate "https://cloudflare-dns.com/dns-query" -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction SilentlyContinue
            Set-DnsClientDohServerAddress -ServerAddress "1.0.0.1" -DohTemplate "https://cloudflare-dns.com/dns-query" -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction SilentlyContinue
            Write-Ok "DNS-over-HTTPS enabled (encrypted DNS)"
        }
    } catch {
        Write-Warn "DoH not available on this Windows version (needs Win11+)"
    }

    # 6. LIMIT PARALLEL CONNECTIONS
    # Desktops open 50-100+ parallel TCP connections. Phones open ~10-20.
    # Throttle to look like a mobile device.
    Write-Step "6" "Limiting parallel TCP connections (desktop → mobile profile)"

    # TCP connection throttling via registry
    $tcpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

    # Save originals
    $backup.OriginalTcpNumConnections = (Get-ItemProperty -Path $tcpPath -Name "TcpNumConnections" -ErrorAction SilentlyContinue).TcpNumConnections
    $backup.OriginalMaxUserPort = (Get-ItemProperty -Path $tcpPath -Name "MaxUserPort" -ErrorAction SilentlyContinue).MaxUserPort

    # Limit max concurrent connections
    Set-ItemProperty -Path $tcpPath -Name "TcpNumConnections" -Value 24 -Type DWord -Force
    Write-Ok "Max TCP connections limited to 24"

    # Reduce ephemeral port range (fewer ports = fewer parallel connections)
    netsh int ipv4 set dynamic tcp start=49152 num=4096 | Out-Null
    Write-Ok "Ephemeral port range reduced (49152-53247)"

    # Disable TCP Window Scaling (mobile devices often don't use aggressive scaling)
    $backup.OriginalTcpWindowSize = (Get-ItemProperty -Path $tcpPath -Name "TcpWindowSize" -ErrorAction SilentlyContinue).TcpWindowSize
    Set-ItemProperty -Path $tcpPath -Name "TcpWindowSize" -Value 65535 -Type DWord -Force
    Set-ItemProperty -Path $tcpPath -Name "Tcp1323Opts" -Value 0 -Type DWord -Force
    # LIVE: Disable auto-tuning immediately (no reboot)
    netsh int tcp set global autotuninglevel=disabled 2>$null | Out-Null
    $backup.OriginalAutoTuning = "normal"
    Write-Ok "TCP Window Scaling disabled (registry + live)"

    # 7. BLOCK DESKTOP-SPECIFIC SIGNATURES 
    # Block traffic from apps that scream "I'M A DESKTOP"
    Write-Step "7" "Blocking desktop-specific app signatures"

    # Block common desktop-only processes from network access
    $desktopApps = @(
        @{ Name = "OneDrive";       Path = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe" }
        @{ Name = "Teams";          Path = "$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe" }
        @{ Name = "Outlook";        Path = "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" }
        @{ Name = "Outlook_x86";    Path = "C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE" }
        @{ Name = "Steam";          Path = "C:\Program Files (x86)\Steam\steam.exe" }
        @{ Name = "Discord";        Path = "$env:LOCALAPPDATA\Discord\Update.exe" }
        @{ Name = "Spotify";        Path = "$env:APPDATA\Spotify\Spotify.exe" }
        @{ Name = "MSEdgeUpdate";   Path = "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" }
        @{ Name = "GoogleUpdate";   Path = "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" }
        @{ Name = "AdobeUpdate";    Path = "C:\Program Files (x86)\Common Files\Adobe\OOBE\PDApp\UWA\UpdaterStartupUtility.exe" }
        @{ Name = "SearchHost";     Path = "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe" }
        @{ Name = "Widgets";        Path = "C:\Windows\SystemApps\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\Dashboard\Widgets.exe" }
        # Newly identified leaks from netstat analysis
        @{ Name = "NearbyShare";        Path = "$env:LOCALAPPDATA\Google\NearbyShare\nearby_share.exe" }
        @{ Name = "NearbyShare_PF";     Path = "C:\Program Files\Google\NearbyShare\nearby_share.exe" }
        @{ Name = "CrossDevice";        Path = "C:\Windows\System32\CrossDeviceService.exe" }
        @{ Name = "CrossDevice_SH";     Path = "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceService.exe" }
        # Phone Link / PhoneExperienceHost — connects to Microsoft Azure, desktop-only
        @{ Name = "PhoneExperienceHost"; Path = "C:\Program Files\WindowsApps\Microsoft.YourPhone_*\PhoneExperienceHost.exe" }
    )

    $blockedCount = 0
    foreach ($app in $desktopApps) {
        # Support wildcard paths (e.g. WindowsApps versioned dirs)
        $resolvedPaths = @()
        if ($app.Path -match '\*') {
            $resolvedPaths = @(Get-Item $app.Path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        } elseif (Test-Path $app.Path) {
            $resolvedPaths = @($app.Path)
        }
        foreach ($resolvedPath in $resolvedPaths) {
            $ruleName = "${FW_PREFIX}_BlockApp_$($app.Name)"
            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound `
                -Program $resolvedPath -Action Block -Profile Any `
                -Description "Blocks $($app.Name) to prevent desktop fingerprinting" `
                -ErrorAction SilentlyContinue | Out-Null
            $blockedCount++
        }
    }
    # Chrome Remote Desktop — path contains version number, find it dynamically
    $crdHost = Get-ChildItem "C:\Program Files (x86)\Google\Chrome Remote Desktop" -Filter "remoting_host.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($crdHost) {
        $ruleName = "${FW_PREFIX}_BlockApp_ChromeRemoteDesktop"
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound `
            -Program $crdHost.FullName -Action Block -Profile Any `
            -Description "Blocks Chrome Remote Desktop to prevent desktop fingerprinting" `
            -ErrorAction SilentlyContinue | Out-Null
        $blockedCount++
    }
    Write-Ok "Blocked $blockedCount desktop-specific applications"

    # FORCE-KILL processes whose existing connections survive firewall rules
    # Firewall rules only block NEW connections; established ones persist until the process is killed.
    $killTargets = @(
        "OneDrive"
        "CrossDeviceService"
        "PhoneExperienceHost"
        "nearby_share"
        "MicrosoftEdgeUpdate"
        "remoting_host"
    )
    foreach ($procName in $killTargets) {
        $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($procs) {
            $procs | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Ok "Killed process: $procName (existing connections terminated)"
        }
    }

    # Block SSDP/UPnP (desktop network discovery — phones don't do this on cellular)
    New-NetFirewallRule -DisplayName "${FW_PREFIX}_BlockSSDP" -Direction Outbound `
        -Protocol UDP -RemotePort 1900 -Action Block -Profile Any `
        -Description "Block SSDP discovery" -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "${FW_PREFIX}_BlockLLMNR" -Direction Outbound `
        -Protocol UDP -RemotePort 5355 -Action Block -Profile Any `
        -Description "Block LLMNR" -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "${FW_PREFIX}_BlockNetBIOS" -Direction Outbound `
        -Protocol UDP -RemotePort 137,138 -Action Block -Profile Any `
        -Description "Block NetBIOS" -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "${FW_PREFIX}_BlockmDNS" -Direction Outbound `
        -Protocol UDP -RemotePort 5353 -Action Block -Profile Any `
        -Description "Block mDNS" -ErrorAction SilentlyContinue | Out-Null
    Write-Ok "Blocked SSDP, LLMNR, NetBIOS, mDNS (network discovery)"

    # 8. ADDITIONAL HARDENING
    Write-Step "+" "Additional hardening"

    # Disable NCSI (Network Connectivity Status Indicator) — Windows pings
    # msftconnecttest.com on every connection, a known desktop fingerprint
    $ncsiPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
    $backup.OriginalNCSI = (Get-ItemProperty -Path $ncsiPath -Name "EnableActiveProbing" -ErrorAction SilentlyContinue).EnableActiveProbing
    Set-ItemProperty -Path $ncsiPath -Name "EnableActiveProbing" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    # LIVE: Restart NLA service so NCSI change takes effect immediately
    Restart-Service -Name NlaSvc -Force -ErrorAction SilentlyContinue
    Write-Ok "Disabled NCSI active probing (registry + live restart)"

    # Block Windows CRL/OCSP checks (certificate validation traffic unique to desktop browsers)
    $crlDomains = @(
        "crl.microsoft.com"
        "ocsp.digicert.com"
        "ocsp.msocsp.com"
        "crl3.digicert.com"     # Additional DigiCert CRL endpoints
        "crl4.digicert.com"
        "ocsp2.globalsign.com"
        "crl.globalsign.com"
    )
    foreach ($domain in $crlDomains) {
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($domain) | ForEach-Object { $_.IPAddressToString }
            if ($ips) {
                $ruleName = "${FW_PREFIX}_BlockCRL_$($domain -replace '\.','_')"
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound `
                    -RemoteAddress $ips -Action Block -Profile Any `
                    -Description "Blocks CRL/OCSP check to $domain" `
                    -ErrorAction SilentlyContinue | Out-Null
            }
        } catch { }
    }
    # Block Fastly CDN IPs used for CRL delivery (seen as CryptSvc → 199.232.214.172:80)
    New-NetFirewallRule -DisplayName "${FW_PREFIX}_BlockCRL_Fastly" -Direction Outbound `
        -RemoteAddress @("199.232.192.0/19") -RemotePort 80 -Protocol TCP -Action Block -Profile Any `
        -Description "Blocks Fastly CDN used for desktop CRL checks (CryptSvc)" `
        -ErrorAction SilentlyContinue | Out-Null
    Write-Ok "Blocked CRL/OCSP certificate checks (+ Fastly CDN)"

    # Save backup
    $backup | ConvertTo-Json -Depth 5 | Set-Content -Path $BACKUP_FILE -Force
    Write-Ok "Backup saved to $BACKUP_FILE"

    #  LIVE APPLY: Bounce adapter to force all changes
    Write-Step "⚡" "Applying all changes LIVE (no reboot needed)"

    # Flush DNS cache so new DNS servers are used immediately
    Clear-DnsClientCache
    Write-Ok "DNS cache flushed"

    # Bounce the network adapter — this forces the full TCP/IP stack to
    # reinitialize with our new TTL, MTU, and TCP settings without a reboot.
    Write-Ok "Bouncing network adapter ($ifAlias)..."
    Disable-NetAdapter -Name $ifAlias -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Enable-NetAdapter -Name $ifAlias -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3  # Wait for reconnection
    Write-Ok "Adapter restarted — all changes are LIVE"

    # Verify the adapter came back up
    $adapterStatus = (Get-NetAdapter -Name $ifAlias -ErrorAction SilentlyContinue).Status
    if ($adapterStatus -eq 'Up') {
        Write-Ok "Adapter is UP and connected"
    } else {
        Write-Warn "Adapter status: $adapterStatus — you may need to reconnect to hotspot"
    }

    # Summary 
    Write-Host ""
    Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "  ALL BYPASSES APPLIED — NO REBOOT NEEDED" -ForegroundColor Green
    Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ⚡ Everything is live. Your traffic now mimics a mobile device." -ForegroundColor Yellow
    Write-Host "  ⚡ If Wi-Fi disconnected, just reconnect to your hotspot." -ForegroundColor Yellow
    Write-Host "  ⚡ Run with " -NoNewline -ForegroundColor Yellow
    Write-Host "-Undo" -NoNewline -ForegroundColor Cyan
    Write-Host " to revert everything." -ForegroundColor Yellow
    Write-Host ""

    # Show current effective settings
    # Re-detect adapter since ifIndex may change after bounce
    $adapter = Get-ActiveWifiAdapter
    if ($adapter) { $ifIndex = $adapter.ifIndex }
    Write-Host "  Current Settings:" -ForegroundColor DarkGray
    $newTTL = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -ErrorAction SilentlyContinue).DefaultTTL
    $liveTTL = (netsh int ipv4 show global | Select-String 'Default Hop Limit').ToString().Trim()
    $newMTU = (Get-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).NlMtu
    $newDNS = (Get-DnsClientServerAddress -InterfaceIndex $ifIndex -AddressFamily IPv4).ServerAddresses -join ", "
    Write-Host "    TTL: $newTTL | MTU: $newMTU | DNS: $newDNS" -ForegroundColor Gray
    Write-Host "    Live Stack: $liveTTL" -ForegroundColor Gray
    Write-Host ""
}

#  UNDO MODE
function Undo-Bypass {
    Write-Banner
    Write-Host "  MODE: " -NoNewline -ForegroundColor DarkGray
    Write-Host "UNDO / REVERT ALL CHANGES" -ForegroundColor Red
    Write-Host ""

    # Load backup
    $backup = $null
    if (Test-Path $BACKUP_FILE) {
        $backup = Get-Content $BACKUP_FILE -Raw | ConvertFrom-Json
        Write-Ok "Loaded backup from $BACKUP_FILE"
    } else {
        Write-Warn "No backup found — reverting to Windows defaults"
    }

    # 1. Revert TTL 
    Write-Step "1" "Reverting TTL"
    $tcpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    if ($backup -and $backup.OriginalTTL) {
        Set-ItemProperty -Path $tcpPath -Name "DefaultTTL" -Value $backup.OriginalTTL -Type DWord -Force
    } else {
        Remove-ItemProperty -Path $tcpPath -Name "DefaultTTL" -Force -ErrorAction SilentlyContinue
    }
    # LIVE: Restore default TTL immediately
    netsh int ipv4 set global defaultcurhoplimit=128 2>$null | Out-Null
    $ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    if ($backup -and $backup.OriginalHopLimit) {
        Set-ItemProperty -Path $ipv6Path -Name "DefaultHopLimit" -Value $backup.OriginalHopLimit -Type DWord -Force
    } else {
        Remove-ItemProperty -Path $ipv6Path -Name "DefaultHopLimit" -Force -ErrorAction SilentlyContinue
    }
    netsh int ipv6 set global defaultcurhoplimit=128 2>$null | Out-Null
    Write-Ok "TTL restored to Windows default (128) — live + registry"

    #  2. Revert MTU 
    Write-Step "2" "Reverting MTU"
    $adapter = Get-ActiveWifiAdapter
    if ($adapter) {
        $ifIndex = $adapter.ifIndex
        Set-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -NlMtuBytes 1500 -ErrorAction SilentlyContinue
        Set-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv6 -NlMtuBytes 1500 -ErrorAction SilentlyContinue
        Write-Ok "MTU restored to 1500"
    } else {
        Write-Warn "No active adapter found — MTU will reset on reconnect"
    }

    # 3-4. Remove all firewall rules 
    Write-Step "3" "Removing firewall rules"
    $rules = Get-NetFirewallRule -DisplayName "${FW_PREFIX}_*" -ErrorAction SilentlyContinue
    $ruleCount = ($rules | Measure-Object).Count
    $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Ok "Removed $ruleCount firewall rules"

    # Restore services 
    Write-Step "4" "Restoring Windows services"
    Set-Service -Name wuauserv -StartupType Manual -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Write-Ok "Windows Update service restored"

    Set-Service -Name DiagTrack -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name DiagTrack -ErrorAction SilentlyContinue
    Write-Ok "Diagnostics Tracking service restored"

    Set-Service -Name WpnService -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name WpnService -ErrorAction SilentlyContinue
    Write-Ok "Windows Push Notification service restored"

    Set-Service -Name CDPSvc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name CDPSvc -ErrorAction SilentlyContinue
    Write-Ok "Connected Devices Platform service restored"

    # 5. Revert DNS 
    Write-Step "5" "Reverting DNS"
    if ($adapter) {
        $ifIndex = $adapter.ifIndex
        if ($backup -and $backup.OriginalDNS) {
            Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses $backup.OriginalDNS
        } else {
            Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ResetServerAddresses
        }
        Write-Ok "DNS restored"
    }

    # 6. Revert TCP settings
    Write-Step "6" "Reverting TCP connection limits"
    Remove-ItemProperty -Path $tcpPath -Name "TcpNumConnections" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $tcpPath -Name "TcpWindowSize" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $tcpPath -Name "Tcp1323Opts" -Force -ErrorAction SilentlyContinue
    netsh int ipv4 set dynamic tcp start=49152 num=16384 | Out-Null
    # LIVE: Re-enable auto-tuning
    netsh int tcp set global autotuninglevel=normal 2>$null | Out-Null
    Write-Ok "TCP settings restored to defaults (live + registry)"

    # 7. Revert NCSI
    Write-Step "7" "Reverting NCSI"
    $ncsiPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
    Set-ItemProperty -Path $ncsiPath -Name "EnableActiveProbing" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Restart-Service -Name NlaSvc -Force -ErrorAction SilentlyContinue
    Write-Ok "NCSI active probing re-enabled (live restart)"

    #  Cleanup
    if (Test-Path $BACKUP_FILE) {
        Remove-Item $BACKUP_FILE -Force
        Write-Ok "Backup file removed"
    }

    #  Bounce adapter to apply reverts live
    Write-Step "⚡" "Applying reverts LIVE"
    $adapter = Get-ActiveWifiAdapter
    if ($adapter) {
        $ifAlias = $adapter.InterfaceAlias
        Clear-DnsClientCache
        Write-Ok "DNS cache flushed"
        Disable-NetAdapter -Name $ifAlias -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Enable-NetAdapter -Name $ifAlias -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Write-Ok "Adapter bounced — all reverts are LIVE"
    }

    Write-Host ""
    Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "  ALL CHANGES REVERTED — NO REBOOT NEEDED" -ForegroundColor Green
    Write-Host "  ═══════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "  ⚡ Everything is back to normal. Reconnect to Wi-Fi if needed." -ForegroundColor Yellow
    Write-Host ""
}

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "  Right-click PowerShell → 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

if ($Undo) {
    Undo-Bypass
} else {
    Apply-Bypass
}
