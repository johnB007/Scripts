<#
.SYNOPSIS
Single entry point for lab telemetry generation.

.DESCRIPTION
Runs CloudUserSimulation, Enhanced workbook telemetry, or both.
Can also register a daily CloudUserSimulation scheduled task in live mode.

.EXAMPLE
pwsh -File .\Run-LabTelemetry-AllInOne.ps1 -Mode Both -RunNow

.EXAMPLE
pwsh -File .\Run-LabTelemetry-AllInOne.ps1 -Mode CloudOnly -RegisterDailyTask -DailyAt '08:30'
#>
[CmdletBinding()]
param(
    [ValidateSet('CloudOnly', 'EnhancedOnly', 'Both')]
    [string]$Mode = 'Both',

    [switch]$RunNow,

    [switch]$RegisterDailyTask,

    [switch]$DeployViaArc,

    [switch]$RunViaArc,

    [switch]$RegisterDailyTaskViaArc,

    [datetime]$DailyAt = (Get-Date).Date.AddHours(8),

    [ValidateRange(0, 480)]
    [int]$CloudDurationMinutes = 35,

    [ValidateRange(1, 50)]
    [int]$EnhancedLoops = 5,

    [switch]$NoEnhancedEmail,

    [string]$ArcMachineName = 'DC007',

    [string]$ArcResourceGroup = 'SOC-Central',

    [string]$ArcLocation = 'eastus2',

    [string]$ArcRemoteTaskUserId,

    [string]$CloudTaskName = 'CloudUserSimulationLive'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$paths = [ordered]@{
    CloudScript = 'C:\Users\jobarbar\github\Scripts\PowerShell\Invoke-DailyCloudUserSimulation.ps1'
    CloudConfig = 'C:\Users\jobarbar\github\Scripts\PowerShell\CloudUserSimulation.SampleConfig.json'
    CloudTaskReg = 'C:\Users\jobarbar\github\Scripts\PowerShell\Register-DailyCloudUserSimulationTask.ps1'
    CloudArcPush = 'C:\Users\jobarbar\github\Scripts\PowerShell\Push-CloudUserSimulationViaArc.ps1'
    EnhancedScript = 'C:\Users\jobarbar\github\Threat-Protection\Dashboards\Enhanced-Monitoring-Workbook\Testing\Invoke-EnhancedLabTelemetry.ps1'
    EnhancedArcPush = 'C:\Users\jobarbar\github\Threat-Protection\Dashboards\Enhanced-Monitoring-Workbook\Testing\Push-LabTelemetryViaArc.ps1'
}

function Write-Info {
    param([string]$Message)
    Write-Host "[info] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[ok]   $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[warn] $Message" -ForegroundColor Yellow
}

function Assert-Path {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not (Test-Path $PathValue)) {
        throw "$Label not found: $PathValue"
    }
}

function Test-InteractiveUser {
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($user -match 'SYSTEM$') {
        Write-Warn 'Current context is SYSTEM. Live Office and email telemetry quality will be reduced.'
    }
    else {
        Write-Ok "Running as interactive user: $user"
    }
}

function Register-CloudTaskLive {
    Assert-Path -PathValue $paths.CloudTaskReg -Label 'Task registration script'

    $args = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $paths.CloudTaskReg),
        '-TaskName', $CloudTaskName,
        '-At', ('"{0}"' -f $DailyAt.ToString('yyyy-MM-ddTHH:mm:ss')),
        '-DurationMinutes', $CloudDurationMinutes,
        '-ConfigPath', ('"{0}"' -f $paths.CloudConfig)
    )

    $command = 'pwsh ' + ($args -join ' ')
    Write-Info "Registering daily live task '$CloudTaskName' at $($DailyAt.ToShortTimeString())"
    Invoke-Expression $command
    Write-Ok "Daily task '$CloudTaskName' is registered"
}

function Invoke-CloudLiveRun {
    Assert-Path -PathValue $paths.CloudScript -Label 'Cloud simulation script'
    Assert-Path -PathValue $paths.CloudConfig -Label 'Cloud simulation config'

    $args = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $paths.CloudScript),
        '-DurationMinutes', $CloudDurationMinutes,
        '-ConfigPath', ('"{0}"' -f $paths.CloudConfig)
    )

    $command = 'pwsh ' + ($args -join ' ')
    Write-Info "Starting CloudUserSimulation live run for $CloudDurationMinutes minutes"
    Invoke-Expression $command
    Write-Ok 'CloudUserSimulation live run completed'
}

function Invoke-EnhancedRun {
    Assert-Path -PathValue $paths.EnhancedScript -Label 'Enhanced telemetry script'

    $args = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $paths.EnhancedScript),
        '-Loops', $EnhancedLoops,
        '-Tabs', 'all'
    )

    if ($NoEnhancedEmail) {
        $args += '-NoEmail'
    }

    $command = 'pwsh ' + ($args -join ' ')
    Write-Info "Starting Enhanced workbook telemetry run with $EnhancedLoops loops"
    Invoke-Expression $command
    Write-Ok 'Enhanced workbook telemetry run completed'
}

function Deploy-CloudPackageViaArc {
    Assert-Path -PathValue $paths.CloudArcPush -Label 'Cloud Arc push script'

    $args = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $paths.CloudArcPush),
        '-MachineName', $ArcMachineName,
        '-ResourceGroup', $ArcResourceGroup,
        '-Location', $ArcLocation,
        '-DurationMinutes', $CloudDurationMinutes,
        '-TaskName', $CloudTaskName,
        '-DailyAt', ('"{0}"' -f $DailyAt.ToString('HH:mm'))
    )

    if ($RegisterDailyTaskViaArc) {
        $args += '-RegisterDailyTask'
    }
    if (-not [string]::IsNullOrWhiteSpace($ArcRemoteTaskUserId)) {
        $args += @('-RemoteTaskUserId', ('"{0}"' -f $ArcRemoteTaskUserId))
    }
    if ($RunViaArc) {
        $args += '-RunAfterDeploy'
    }

    $command = 'pwsh ' + ($args -join ' ')
    Write-Info "Deploying CloudUserSimulation package to $ArcMachineName through Arc"
    Invoke-Expression $command
    Write-Ok 'CloudUserSimulation package deployed through Arc'
}

function Deploy-EnhancedPackageViaArc {
    Assert-Path -PathValue $paths.EnhancedArcPush -Label 'Enhanced Arc push script'

    $args = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $paths.EnhancedArcPush),
        '-MachineName', $ArcMachineName,
        '-ResourceGroup', $ArcResourceGroup,
        '-Location', $ArcLocation
    )

    $command = 'pwsh ' + ($args -join ' ')
    Write-Info "Deploying Enhanced telemetry script to $ArcMachineName through Arc"
    Invoke-Expression $command
    Write-Ok 'Enhanced telemetry package deployed through Arc'
}

Write-Info "Mode: $Mode"
Test-InteractiveUser

if ($DeployViaArc) {
    switch ($Mode) {
        'CloudOnly' {
            Deploy-CloudPackageViaArc
        }
        'EnhancedOnly' {
            Deploy-EnhancedPackageViaArc
        }
        'Both' {
            Deploy-CloudPackageViaArc
            Deploy-EnhancedPackageViaArc
        }
    }
}

if ($RunViaArc -and -not $DeployViaArc) {
    Write-Warn 'RunViaArc requires DeployViaArc for CloudUserSimulation. Enabling DeployViaArc behavior is recommended.'
}

if ($RegisterDailyTaskViaArc -and -not $DeployViaArc) {
    Write-Warn 'RegisterDailyTaskViaArc requires DeployViaArc for CloudUserSimulation. Enabling DeployViaArc behavior is recommended.'
}

if ($RegisterDailyTask) {
    if ($Mode -eq 'EnhancedOnly') {
        Write-Warn 'Daily task registration applies to CloudUserSimulation only. EnhancedOnly mode skips task registration.'
    }
    else {
        Register-CloudTaskLive
    }
}

if (-not $RunNow) {
    Write-Info 'RunNow was not set. No telemetry run executed.'
    Write-Host ''
    Write-Host 'Next commands:' -ForegroundColor Cyan
    Write-Host "  pwsh -File `"$PSCommandPath`" -Mode $Mode -RunNow"
    if ($Mode -ne 'EnhancedOnly') {
        Write-Host "  pwsh -File `"$PSCommandPath`" -Mode CloudOnly -RegisterDailyTask -DailyAt '08:30'"
    }
    exit 0
}

switch ($Mode) {
    'CloudOnly' {
        Invoke-CloudLiveRun
    }
    'EnhancedOnly' {
        Invoke-EnhancedRun
    }
    'Both' {
        Invoke-CloudLiveRun
        Invoke-EnhancedRun
    }
}

Write-Host ''
Write-Host 'Done. Wait 15 to 30 minutes, then validate workbook or table counts.' -ForegroundColor Green
