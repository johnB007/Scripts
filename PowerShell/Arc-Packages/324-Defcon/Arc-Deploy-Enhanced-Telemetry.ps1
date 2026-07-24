# Simple: Copy enhanced telemetry script to 324 and restart the task via Arc
param([string]$MachineName = '324-UM-Defcon30')

$localScript = 'C:\Users\jobarbar\github\Scripts\PowerShell\Arc-Packages\324-Defcon\Invoke-ArcInteractiveTelemetry.ps1'
if (-not (Test-Path $localScript)) { throw "Script not found: $localScript" }

Write-Host "[info] Preparing script for Arc upload..." -ForegroundColor Cyan

# Read and encode script
$scriptContent = Get-Content -Path $localScript -Raw
$bytes = [System.Text.Encoding]::UTF8.GetBytes($scriptContent)
$base64 = [Convert]::ToBase64String($bytes)

# Minimal bootstrap: just decode, write, and run
$bootstrap = @"
`$b = @'
$base64
'@
`$x = [Convert]::FromBase64String(`$b)
`$s = [System.Text.Encoding]::UTF8.GetString(`$x)
Set-Content -Path 'C:\Scripts\Invoke-ArcInteractiveTelemetry.ps1' -Value `$s -Encoding UTF8
schtasks /run /tn ArcTelemetryComprehensive
"@

Write-Host "[info] Sending to Arc..." -ForegroundColor Cyan

$cmdName = 'update-telem-' + (Get-Date -Format 'yyyyMMddHHmmss')
$result = az connectedmachine run-command create `
    --name $cmdName `
    --machine-name $MachineName `
    --resource-group SOC-Central `
    --location eastus2 `
    --script $bootstrap `
    -o json 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "[ok] Command sent to Arc" -ForegroundColor Green
    Write-Host "[ok] Script updated on 324, task running" -ForegroundColor Green
    Write-Host "[next] Check Sentinel in 10-15 minutes for all 16 tables" -ForegroundColor Green
} else {
    Write-Host "[error] Arc command failed:" -ForegroundColor Red
    Write-Host $result
}
