<#
.SYNOPSIS
    Collect the MDE Sense ID registry value.
.DESCRIPTION
    Read only MDE Live Response script that reads the SenseId value from
    HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection and saves it
    to a temp CSV for retrieval.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$device = $env:COMPUTERNAME
$utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection'
$outDir = Join-Path $env:TEMP ("LR_SenseId_{0}" -f ([Guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

try {
    $keyExists = Test-Path -LiteralPath $registryPath
    $senseId = $null

    if ($keyExists) {
        $key = Get-Item -LiteralPath $registryPath -ErrorAction Stop
        $senseId = $key.GetValue('SenseId', $null)
    }

    $result = [pscustomobject]@{
        DeviceName = $device
        UTC = $utc
        RegistryPath = $registryPath
        KeyExists = $keyExists
        SenseId = $senseId
    }

    $csv = Join-Path $outDir 'senseid.csv'
    $result | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

    Write-Output ("Device: {0}" -f $device)
    Write-Output ("UTC: {0}" -f $utc)
    Write-Output ("Registry: {0}" -f $registryPath)

    if ($keyExists) {
        Write-Output ("SenseId: {0}" -f $senseId)
    }
    else {
        Write-Output 'Key not found. Ensure the device is onboarded and the registry key exists.'
    }

    Write-Output ("Saved: {0}" -f $csv)
    Write-Output 'Use getfile to retrieve the CSV from the path above.'
    exit 0
}
catch {
    Write-Error ("Collection failed: {0}" -f $_.Exception.Message)
    exit 1
}
