<#
.SYNOPSIS
    Generates benign registry write activity to validate a Defender for Endpoint
    custom data collection Registry rule (DeviceCustomRegistryEvents).
.DESCRIPTION
    Custom registry telemetry is action based. The DeviceCustomRegistryEvents
    table only fills when a targeted device creates, modifies, or deletes a
    registry key or value that matches the rule filter. This script produces all
    four registry action types under a dedicated demo key so the custom rule has
    something deterministic to capture.

    Actions produced per iteration:
      RegistryKeyCreated    when the demo key is created
      RegistryValueSet      when a value is created and again when it is modified
      RegistryValueDeleted  when the value is removed
      RegistryKeyDeleted    when the demo key is removed (unless -KeepKey)

    By default the script runs as a dry run and only prints the intended actions.
    Pass -Remediate to actually write to the registry. Everything is scoped to
    one demo key and cleaned up afterward, so the device is left as found.
.PARAMETER KeyPath
    Registry key to exercise. Default HKLM:\SOFTWARE\CustomCollectionDemo.
    Scope your custom collection rule to this path (RegistryKey contains
    CustomCollectionDemo) to keep event volume low.
.PARAMETER Iterations
    How many create, modify, delete cycles to run. Default 3.
.PARAMETER KeepKey
    Leave the demo key in place instead of deleting it at the end.
.PARAMETER Remediate
    Perform the registry writes. Without this switch the script only reports
    what it would do.
.EXAMPLE
    run Invoke-RegistryCollectionDemo.ps1 -parameters "-Remediate"
.EXAMPLE
    run Invoke-RegistryCollectionDemo.ps1 -parameters "-Remediate -Iterations 5"
#>
[CmdletBinding()]
param(
    [ValidatePattern('^HKLM:\\SOFTWARE\\CustomCollectionDemo(?:\\[^\\]+)*$')]
    [string]$KeyPath   = 'HKLM:\SOFTWARE\CustomCollectionDemo',
    [ValidateRange(1, 100)]
    [int]$Iterations   = 3,
    [switch]$KeepKey,
    [switch]$Remediate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$device = $env:COMPUTERNAME
$utc    = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$valueName = 'CollectionProbe'

Write-Output ("Device: {0}  UTC: {1}" -f $device, $utc)
Write-Output ("Target key: {0}" -f $KeyPath)
Write-Output ("Iterations: {0}  KeepKey: {1}  Remediate: {2}" -f $Iterations, [bool]$KeepKey, [bool]$Remediate)

if (-not $Remediate) {
    Write-Output ''
    Write-Output 'DRY RUN. No registry changes were made.'
    Write-Output 'Would create the demo key, set and modify a value, delete the value, then delete the key.'
    Write-Output 'Run again with -Remediate to generate the registry events.'
    exit 0
}

$created = 0; $set = 0; $modified = 0; $deletedValues = 0; $deletedKeys = 0

try {
    for ($i = 1; $i -le $Iterations; $i++) {
        # Create key (RegistryKeyCreated)
        if (-not (Test-Path -LiteralPath $KeyPath)) {
            New-Item -Path $KeyPath -Force | Out-Null
            $created++
        }

        # Create value (RegistryValueSet)
        New-ItemProperty -LiteralPath $KeyPath -Name $valueName -Value ("probe-{0}-{1}" -f $i, $utc) -PropertyType String -Force | Out-Null
        $set++

        # Modify value (RegistryValueSet again with new data)
        Set-ItemProperty -LiteralPath $KeyPath -Name $valueName -Value ("modified-{0}-{1}" -f $i, ([Guid]::NewGuid().ToString('N')))
        $modified++

        # Delete value (RegistryValueDeleted)
        Remove-ItemProperty -LiteralPath $KeyPath -Name $valueName -ErrorAction SilentlyContinue
        $deletedValues++

        # Delete key (RegistryKeyDeleted) unless caller wants it kept
        if (-not $KeepKey) {
            Remove-Item -LiteralPath $KeyPath -Recurse -Force -ErrorAction SilentlyContinue
            $deletedKeys++
        }

        Start-Sleep -Milliseconds 250
    }

    Write-Output ''
    Write-Output ("Keys created:    {0}" -f $created)
    Write-Output ("Values set:      {0}" -f $set)
    Write-Output ("Values modified: {0}" -f $modified)
    Write-Output ("Values deleted:  {0}" -f $deletedValues)
    Write-Output ("Keys deleted:    {0}" -f $deletedKeys)
    Write-Output ''
    Write-Output 'Registry activity generated. Allow a few minutes for telemetry to reach Sentinel.'
    Write-Output 'Verify with: DeviceCustomRegistryEvents | where DeviceName == "<thisdevice>" | where Timestamp > ago(1h)'
    exit 0
}
catch {
    Write-Error ("Registry demo failed: {0}" -f $_.Exception.Message)
    exit 1
}
