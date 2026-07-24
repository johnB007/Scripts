<#
.SYNOPSIS
Register a daily scheduled task for the cloud user simulation.

.DESCRIPTION
Creates one daily task for the current user, or one task per profile file in a
folder. The task runs only when the chosen user is logged on.

.EXAMPLE
pwsh -File .\Register-DailyCloudUserSimulationTask.ps1 -TaskName CloudUserSimulation -At 08:15

.EXAMPLE
pwsh -File .\Register-DailyCloudUserSimulationTask.ps1 -ProfileFolder .\profiles -TaskPrefix CloudUserSimulation -At 09:00
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$SimulationScriptPath = 'c:\Users\jobarbar\github\Scripts\PowerShell\Invoke-DailyCloudUserSimulation.ps1',

    [string]$TaskName = 'CloudUserSimulation',

    [string]$TaskPrefix = 'CloudUserSimulation',

    [datetime]$At = (Get-Date).Date.AddHours(8),

    [ValidateRange(0, 480)]
    [int]$DurationMinutes = 25,

    [string]$ConfigPath,

    [string]$ProfileFolder,

    [string]$UserId = $env:USERNAME,

    [switch]$ValidateSentinel,

    [switch]$Unattended,

    [switch]$SkipBrowser,

    [switch]$SkipAuthenticatedWeb,

    [switch]$SkipOutlookMail,

    [switch]$SkipAppLaunches
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:TaskAt = $At
$script:TaskDurationMinutes = $DurationMinutes
$script:TaskConfigPath = $ConfigPath
$script:TaskUserId = $UserId
$script:TaskValidateSentinel = $ValidateSentinel
$script:TaskUnattended = $Unattended
$script:TaskSkipBrowser = $SkipBrowser
$script:TaskSkipAuthenticatedWeb = $SkipAuthenticatedWeb
$script:TaskSkipOutlookMail = $SkipOutlookMail
$script:TaskSkipAppLaunches = $SkipAppLaunches

if (-not (Test-Path $SimulationScriptPath)) {
    throw "Simulation script not found: $SimulationScriptPath"
}

function Register-OneTask {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$ProfilePath
    )

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $SimulationScriptPath),
        '-DurationMinutes', $script:TaskDurationMinutes
    )

    if ($script:TaskConfigPath) {
        $arguments += @('-ConfigPath', ('"{0}"' -f $script:TaskConfigPath))
    }
    if ($ProfilePath) {
        $arguments += @('-ProfilePath', ('"{0}"' -f $ProfilePath))
    }
    if ($script:TaskValidateSentinel) {
        $arguments += '-ValidateSentinel'
    }
    if ($script:TaskUnattended) {
        $arguments += '-Unattended'
    }
    if ($script:TaskSkipBrowser) {
        $arguments += '-SkipBrowser'
    }
    if ($script:TaskSkipAuthenticatedWeb) {
        $arguments += '-SkipAuthenticatedWeb'
    }
    if ($script:TaskSkipOutlookMail) {
        $arguments += '-SkipOutlookMail'
    }
    if ($script:TaskSkipAppLaunches) {
        $arguments += '-SkipAppLaunches'
    }

    $action = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument ($arguments -join ' ')
    $trigger = New-ScheduledTaskTrigger -Daily -At $script:TaskAt
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew

    if ($PSCmdlet.ShouldProcess($Name, 'Register scheduled task')) {
        Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger -Settings $settings -User $script:TaskUserId -RunLevel Limited -Force | Out-Null
        Write-Output ("Registered task {0}" -f $Name)
    }
}

if ($ProfileFolder) {
    $profileFiles = Get-ChildItem -Path $ProfileFolder -Filter '*.json' | Sort-Object Name
    foreach ($profileFile in $profileFiles) {
        $shortName = [System.IO.Path]::GetFileNameWithoutExtension($profileFile.Name)
        Register-OneTask -Name ('{0}_{1}' -f $TaskPrefix, $shortName) -ProfilePath $profileFile.FullName
    }
}
else {
    Register-OneTask -Name $TaskName
}

exit 0