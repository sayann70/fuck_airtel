# Pre-bypass check — shows current network state
Write-Host "`n=== ACTIVE ADAPTERS ===" -ForegroundColor Cyan
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Format-Table Name, InterfaceDescription, Status, LinkSpeed -AutoSize

Write-Host "=== CURRENT TTL ===" -ForegroundColor Cyan
$ttl = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -ErrorAction SilentlyContinue).DefaultTTL
if ($ttl) { Write-Host "  DefaultTTL: $ttl" } else { Write-Host "  DefaultTTL: Not set (Windows default = 128)" }

Write-Host "`n=== LIVE TTL (netsh) ===" -ForegroundColor Cyan
netsh int ipv4 show global | findstr "Hop Limit"

Write-Host "`n=== CURRENT MTU ===" -ForegroundColor Cyan
netsh int ipv4 show interfaces

Write-Host "=== CURRENT DNS ===" -ForegroundColor Cyan
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | Format-Table InterfaceAlias, ServerAddresses -AutoSize

Write-Host "=== TCP AUTO-TUNING ===" -ForegroundColor Cyan
netsh int tcp show global | findstr "Auto"

Write-Host "`n=== PING TEST ===" -ForegroundColor Cyan
ping -n 1 google.com
