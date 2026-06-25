<#
.SYNOPSIS
    Collects a snapshot of running processes for triage.
.DESCRIPTION
    Read only Live Response triage script. Saves a process list to a temp CSV
    and prints the path for retrieval with getfile.
.PARAMETER Minutes
    Reserved for filtering. Included to show parameter handling.
#>
[CmdletBinding()]
param(
    [int]$Minutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$device = $env:COMPUTERNAME
$utc    = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$outDir = Join-Path $env:TEMP ("LR_{0}" -f ([Guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

try {
    $results = Get-Process | Select-Object Name, Id, Path, StartTime
    $csv = Join-Path $outDir 'processes.csv'
    $results | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

    Write-Output ("Device: {0}  UTC: {1}  Lookback: {2} min" -f $device, $utc, $Minutes)
    Write-Output ("Saved: {0}" -f $csv)
    Write-Output 'Use getfile to retrieve the path above.'
    exit 0
}
catch {
    Write-Error ("Collection failed: {0}" -f $_.Exception.Message)
    exit 1
}
