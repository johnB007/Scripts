<#
.SYNOPSIS
    Adds scoped Microsoft Defender antivirus exclusions so a benign regsvr32
    Squiblydoo lab run is not blocked as Behavior:Win32/Powemet on this device.
.DESCRIPTION
    Change script for MDE Live Response. It creates one fixed lab folder and
    excludes that folder, the regsvr32 process, and the folder from Attack
    Surface Reduction, so the benign generator can execute and produce real
    telemetry across the six custom tables. The MDE EDR sensor still records
    every event, so this does not reduce the telemetry we want to measure.

    Exclusions persist until removed, so they survive an overnight ingest wait
    on an always on device. Run again with the Remove switch after the demo to
    reverse every change.

    This script intentionally modifies Defender configuration only when the
    Remediate switch is supplied.
.PARAMETER LabDir
    Fixed folder the generator writes to and that this script excludes.
.PARAMETER Remove
    Reverse every exclusion this script adds, and remove the lab folder.
.PARAMETER Remediate
    Apply or remove the exclusions. Without this switch the script performs a
    dry run.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^C:\\ProgramData\\Regsvr32SquiblydooLab(?:\\[^\\]+)*$')]
    [string]$LabDir = 'C:\ProgramData\Regsvr32SquiblydooLab',
    [switch]$Remove,
    [switch]$Remediate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$device = $env:COMPUTERNAME
$utc    = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$proc   = "$env:SystemRoot\System32\regsvr32.exe"

Write-Output ("Device: {0}  UTC: {1}" -f $device, $utc)
Write-Output ("Lab folder: {0}" -f $LabDir)
Write-Output ("Remove: {0}  Remediate: {1}" -f [bool]$Remove, [bool]$Remediate)

if (-not $Remediate) {
    Write-Output 'DRY RUN. No exclusions or folders were changed.'
    if ($Remove) {
        Write-Output 'Would remove the scoped lab exclusions and lab folder.'
    }
    else {
        Write-Output 'Would create the lab folder and add the scoped Defender exclusions.'
    }
    Write-Output 'Run again with -Remediate after authorization.'
    exit 0
}

# Confirm Tamper Protection is off, otherwise exclusion writes are ignored.
try {
    $status = Get-MpComputerStatus
    $tp = $false
    if ($status.PSObject.Properties.Name -contains 'IsTamperProtected') {
        $tp = [bool]$status.IsTamperProtected
    }
    Write-Output ("Tamper Protection: {0}" -f $tp)
    if ($tp -and -not $Remove) {
        Write-Error ("Tamper Protection is on. Exclusion changes will be " +
                     "ignored. Turn it off for this device in the portal or " +
                     "Intune, then run this script again.")
        exit 2
    }
}
catch {
    Write-Output ("Could not read Defender status: {0}" -f $_.Exception.Message)
}

if ($Remove) {
    # Reverse every change, continuing past any single failure.
    foreach ($action in @(
        { Remove-MpPreference -ExclusionPath $LabDir -ErrorAction Stop },
        { Remove-MpPreference -ExclusionProcess $proc -ErrorAction Stop },
        { Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $LabDir -ErrorAction Stop }
    )) {
        try { & $action } catch { Write-Output ("Skip: {0}" -f $_.Exception.Message) }
    }
    if (Test-Path -LiteralPath $LabDir) {
        try { Remove-Item -LiteralPath $LabDir -Recurse -Force }
        catch { Write-Output ("Folder not removed: {0}" -f $_.Exception.Message) }
    }
    Write-Output 'Removed lab exclusions and folder.'
    exit 0
}

try {
    if (-not (Test-Path -LiteralPath $LabDir)) {
        New-Item -ItemType Directory -Path $LabDir -Force | Out-Null
    }

    # Path and process exclusions stop the antivirus block. The ASR only
    # exclusion stops the Powemet behavior rule from killing regsvr32.
    Add-MpPreference -ExclusionPath $LabDir
    Add-MpPreference -ExclusionProcess $proc
    try {
        Add-MpPreference -AttackSurfaceReductionOnlyExclusions $LabDir
    }
    catch {
        Write-Output ("ASR exclusion not applied: {0}" -f $_.Exception.Message)
    }

    # Read back and show what is now in effect for verification.
    $p = Get-MpPreference
    Write-Output '--- Exclusions now in effect ---'
    Write-Output ("ExclusionPath: {0}" -f (($p.ExclusionPath) -join '; '))
    Write-Output ("ExclusionProcess: {0}" -f (($p.ExclusionProcess) -join '; '))
    Write-Output ("ASROnlyExclusions: {0}" -f (($p.AttackSurfaceReductionOnlyExclusions) -join '; '))

    $ok = ($p.ExclusionPath -contains $LabDir)
    if ($ok) {
        Write-Output 'Lab folder exclusion confirmed. Safe to run the generator.'
        exit 0
    }
    else {
        Write-Error 'Lab folder exclusion did not take. Check Tamper Protection and policy.'
        exit 1
    }
}
catch {
    Write-Error ("Failed to set exclusions: {0}" -f $_.Exception.Message)
    exit 1
}
