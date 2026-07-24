#Requires -Version 5.1
<#
.SYNOPSIS
Deploy telemetry script via Arc run-command using base64 encoding.
PROVEN WORKING METHOD - uses base64 to protect schtasks /flags from CLI parsing.

.EXAMPLE
.\Arc-Deploy-Telemetry.ps1 -Machine 324-UM-Defcon30
.\Arc-Deploy-Telemetry.ps1 -Machine 324-UM-Defcon30 -BrowserDelayMs 100
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Machine,
    
    [string]$ResourceGroup = 'SOC-Central',
    [string]$Subscription = '882d9ca8-f61e-4cc8-a081-dc01aab06b8a',
    [string]$Location = 'eastus2',
    [string]$ScriptPath = 'C:\Users\jobarbar\github\Scripts\PowerShell\Arc-Packages\324-Defcon\Invoke-ArcInteractiveTelemetry.ps1',
    [int]$BrowserDelayMs = 100,
    [string]$RunAsUser = 'AzureAD\elliottalderson'
)

Write-Host "=== Arc Telemetry Deployment ===" -ForegroundColor Cyan
Write-Host "Machine: $Machine" -ForegroundColor Yellow
Write-Host "Script: $ScriptPath" -ForegroundColor Yellow
Write-Host "User: $RunAsUser" -ForegroundColor Yellow

# Ensure subscription context
az account set --subscription $Subscription
az extension add --name connectedmachine --allow-preview true

# Build the actual schtasks commands (DO NOT modify syntax)
$cmd1 = 'schtasks /Create /TN ArcTelemetryComprehensive /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\jobarbar\github\Scripts\PowerShell\Arc-Packages\324-Defcon\Invoke-ArcInteractiveTelemetry.ps1 -BrowserTabDelayMs 100" /SC ONCE /ST 00:00 /F /RU admin /IT'
$cmd2 = 'schtasks /Run /TN ArcTelemetryComprehensive /I'

# CRITICAL: Base64 encode to protect /flags from Azure CLI parsing
$bytes = [System.Text.Encoding]::Unicode.GetBytes("$cmd1`n$cmd2")
$encoded = [Convert]::ToBase64String($bytes)
$script = "powershell -EncodedCommand $encoded"

Write-Host "Deploying to $Machine..." -ForegroundColor Cyan
$c = az connectedmachine run-command create `
    --resource-group $ResourceGroup `
    --machine-name $Machine `
    --name "arc-$(Get-Date -Format 'yyyyMMddHHmmss')" `
    --location $Location `
    --script $script `
    -o json | ConvertFrom-Json

if ($c.id) {
    Write-Host "Created: $($c.name)" -ForegroundColor Green
    
    # Poll for completion (40 iterations × 5 seconds = 3.3 minutes max)
    1..40 | ForEach-Object {
        $v = az connectedmachine run-command show `
            --resource-group $ResourceGroup `
            --machine-name $Machine `
            --name $c.name `
            -o json | ConvertFrom-Json
        
        $st = $v.instanceView.executionState
        Write-Host "[$_/40] State: $st" -ForegroundColor Magenta
        
        if ($st -in 'Succeeded', 'Failed', 'Canceled', 'TimedOut') {
            Write-Host $v.instanceView.output -ForegroundColor Green
            break
        }
        Start-Sleep -Seconds 5
    }
} else {
    Write-Host "ERROR: $($c | ConvertTo-Json)" -ForegroundColor Red
}
