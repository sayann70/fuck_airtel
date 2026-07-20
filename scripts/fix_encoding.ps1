# Add UTF-8 BOM to bypass.ps1 so Windows PowerShell 5.1 can read the Unicode chars
$filePath = Join-Path $PSScriptRoot "bypass.ps1"
$content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::UTF8)
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($filePath, $content, $utf8Bom)
Write-Host "UTF-8 BOM added to bypass.ps1" -ForegroundColor Green

# Verify
$bytes = [System.IO.File]::ReadAllBytes($filePath)[0..2]
$hasBom = ($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)
Write-Host "BOM present: $hasBom" -ForegroundColor Cyan
