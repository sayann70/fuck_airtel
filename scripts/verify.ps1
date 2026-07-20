# Full verification of all bypass settings
# Run this after applying the bypass to confirm everything is active

Write-Host ""
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host "  AIRTEL BYPASS - FULL VERIFICATION" -ForegroundColor Cyan
Write-Host "  =============================================" -ForegroundColor Cyan
Write-Host ""

$pass = 0
$fail = 0

function Test-Check([string]$name, [bool]$result, [string]$detail) {
    if ($result) {
        Write-Host "  [PASS] " -NoNewline -ForegroundColor Green
        Write-Host "$name" -NoNewline -ForegroundColor White
        Write-Host " - $detail" -ForegroundColor Gray
        $script:pass++
    } else {
        Write-Host "  [FAIL] " -NoNewline -ForegroundColor Red
        Write-Host "$name" -NoNewline -ForegroundColor White
        Write-Host " - $detail" -ForegroundColor Yellow
        $script:fail++
    }
}

# 1. TTL Check (Registry)
Write-Host "  --- TTL ---" -ForegroundColor DarkGray
$regTTL = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -ErrorAction SilentlyContinue).DefaultTTL
Test-Check "Registry TTL" ($regTTL -eq 65) "Expected: 65, Got: $regTTL"

# 1b. TTL Check (Live stack)
$globalOutput = netsh int ipv4 show global
$hopLine = ($globalOutput | Select-String "Default Hop Limit").ToString()
$liveHop = if ($hopLine -match '(\d+)') { [int]$Matches[1] } else { 0 }
Test-Check "Live Stack TTL" ($liveHop -eq 65) "Expected: 65, Got: $liveHop"

# 1c. IPv6 Hop Limit
$regHop6 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DefaultHopLimit" -ErrorAction SilentlyContinue).DefaultHopLimit
Test-Check "Registry IPv6 Hop Limit" ($regHop6 -eq 65) "Expected: 65, Got: $regHop6"

# 2. MTU Check
Write-Host ""
Write-Host "  --- MTU ---" -ForegroundColor DarkGray
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'Wi-Fi|Wireless|WLAN|802\.11') } | Select-Object -First 1
if ($adapter) {
    $mtu = (Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).NlMtu
    Test-Check "MTU" ($mtu -eq 1400) "Expected: 1400, Got: $mtu (on $($adapter.Name))"
} else {
    Test-Check "MTU" $false "No Wi-Fi adapter found"
}

# 3. DNS Check
Write-Host ""
Write-Host "  --- DNS ---" -ForegroundColor DarkGray
if ($adapter) {
    $dns = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
    $dnsStr = $dns -join ", "
    $dnsOk = ($dns -contains "1.1.1.1") -and ($dns -contains "1.0.0.1")
    Test-Check "DNS Servers" $dnsOk "Expected: 1.1.1.1, 1.0.0.1 | Got: $dnsStr"
}

# 4. Windows Update Service
Write-Host ""
Write-Host "  --- SERVICES ---" -ForegroundColor DarkGray
$wuStatus = (Get-Service -Name wuauserv -ErrorAction SilentlyContinue).Status
Test-Check "Windows Update Service" ($wuStatus -eq 'Stopped') "Expected: Stopped, Got: $wuStatus"

$wuStartup = (Get-Service -Name wuauserv -ErrorAction SilentlyContinue).StartType
Test-Check "Windows Update Startup" ($wuStartup -eq 'Disabled') "Expected: Disabled, Got: $wuStartup"

$diagStatus = (Get-Service -Name DiagTrack -ErrorAction SilentlyContinue).Status
Test-Check "DiagTrack Service" ($diagStatus -eq 'Stopped') "Expected: Stopped, Got: $diagStatus"

# 5. Firewall Rules
Write-Host ""
Write-Host "  --- FIREWALL ---" -ForegroundColor DarkGray
$fwRules = Get-NetFirewallRule -DisplayName "AirtelBypass_*" -ErrorAction SilentlyContinue
$fwCount = ($fwRules | Measure-Object).Count
Test-Check "Firewall Rules Created" ($fwCount -gt 10) "Found $fwCount rules (need 10+)"

$updateRules = $fwRules | Where-Object { $_.DisplayName -like "*BlockUpdate*" }
$updateCount = ($updateRules | Measure-Object).Count
Test-Check "Windows Update Blocked" ($updateCount -gt 0) "$updateCount update domains blocked"

$telemetryRules = $fwRules | Where-Object { $_.DisplayName -like "*BlockTelemetry*" }
$telemetryCount = ($telemetryRules | Measure-Object).Count
Test-Check "Telemetry Blocked" ($telemetryCount -gt 0) "$telemetryCount telemetry domains blocked"

$appRules = $fwRules | Where-Object { $_.DisplayName -like "*BlockApp*" }
$appCount = ($appRules | Measure-Object).Count
Test-Check "Desktop Apps Blocked" ($appCount -gt 0) "$appCount desktop apps blocked"

$discoveryRules = $fwRules | Where-Object { $_.DisplayName -match "SSDP|LLMNR|NetBIOS|mDNS" }
$discCount = ($discoveryRules | Measure-Object).Count
Test-Check "Discovery Protocols Blocked" ($discCount -ge 4) "$discCount/4 protocols blocked (SSDP, LLMNR, NetBIOS, mDNS)"

# 6. TCP Settings
Write-Host ""
Write-Host "  --- TCP ---" -ForegroundColor DarkGray
$tcpConn = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpNumConnections" -ErrorAction SilentlyContinue).TcpNumConnections
Test-Check "TCP Connection Limit" ($tcpConn -eq 24) "Expected: 24, Got: $tcpConn"

$tcpAutoTune = (netsh int tcp show global | Select-String "Auto-Tuning").ToString()
$autoDisabled = $tcpAutoTune -match "disabled"
Test-Check "TCP Auto-Tuning" $autoDisabled "Expected: disabled | $($tcpAutoTune.Trim())"

# 7. NCSI
Write-Host ""
Write-Host "  --- NCSI ---" -ForegroundColor DarkGray
$ncsi = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -ErrorAction SilentlyContinue).EnableActiveProbing
Test-Check "NCSI Probing Disabled" ($ncsi -eq 0) "Expected: 0 (disabled), Got: $ncsi"

# 8. Internet Connectivity
Write-Host ""
Write-Host "  --- CONNECTIVITY ---" -ForegroundColor DarkGray
$ping = Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet -ErrorAction SilentlyContinue
Test-Check "Internet Access" $ping "Ping to 1.1.1.1"

$dnsResolve = $null
try { $dnsResolve = [System.Net.Dns]::GetHostAddresses("google.com") } catch {}
Test-Check "DNS Resolution" ($null -ne $dnsResolve) "Resolving google.com"

# Summary
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkGray
$total = $pass + $fail
if ($fail -eq 0) {
    Write-Host "  ALL $total CHECKS PASSED" -ForegroundColor Green
    Write-Host "  Your traffic fully mimics a mobile device." -ForegroundColor Green
} else {
    Write-Host "  $pass/$total PASSED, $fail FAILED" -ForegroundColor Yellow
    Write-Host "  Some checks failed - see details above." -ForegroundColor Yellow
}
Write-Host "  =============================================" -ForegroundColor DarkGray
Write-Host ""
