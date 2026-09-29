<#
.SYNOPSIS
    Fire one benign event into all six MDE custom collection tables.
.DESCRIPTION
    Generates marker tagged activity for Process, Image Load, File, Network,
    Registry, and Script so DeviceCustom* tables light up during a class or a
    rule validation. All activity is benign and self cleaning. Nothing is
    downloaded and nothing on the device is left changed unless you pass
    KeepArtifacts. Rows only appear if a custom collection rule already
    captures the matching activity and the device carries the target tag.
    Runs in the SYSTEM context under Live Response.
.PARAMETER Marker
    Distinctive string stamped into every artifact so you can hunt it later.
.PARAMETER RemoteHost
    Destination for the benign outbound connection test.
.PARAMETER RemotePort
    Distinctive destination port for the connection test.
.PARAMETER KeepArtifacts
    Leave the file and registry marker in place instead of cleaning up.
.PARAMETER Remediate
    Generate the telemetry. Without this switch the script performs a dry run.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')]
    [string]$Marker = 'MDECustomTelemetryProbe',
    [string]$RemoteHost = '1.1.1.1',
    [ValidateRange(1, 65535)]
    [int]$RemotePort = 443,
    [switch]$KeepArtifacts,
    [switch]$Remediate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$device = $env:COMPUTERNAME
$utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$workDir = Join-Path $env:TEMP ($Marker + '_' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$regPath = 'HKLM:\SOFTWARE\' + $Marker
$results = New-Object System.Collections.Generic.List[object]

Write-Output ("Device: {0}  UTC: {1}" -f $device, $utc)
Write-Output ("Marker: {0}  Remediate: {1}" -f $Marker, [bool]$Remediate)

if (-not $Remediate) {
    Write-Output 'DRY RUN. No telemetry was generated and no device changes were made.'
    Write-Output 'Run with -Remediate after authorization to generate the test activity.'
    exit 0
}

function Add-Result {
    param([string]$Table, [string]$Action, [string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{
            Table  = $Table
            Action = $Action
            Status = $Status
            Detail = $Detail
        })
}

try {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null

    # 1. Process. Launch a distinctive child process with the marker in its command line.
    try {
        $procArgs = "/c echo $Marker process at $utc"
        $p = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList $procArgs -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 400
        Add-Result 'DeviceCustomProcessEvents' 'cmd.exe with marker command line' 'fired' ("pid " + $p.Id)
    }
    catch {
        Add-Result 'DeviceCustomProcessEvents' 'cmd.exe with marker command line' 'error' $_.Exception.Message
    }

    # 2. Image Load. Copy a benign in box DLL to a marker path and load it, so the load has a distinctive folder path.
    try {
        $dllSrc = "$env:SystemRoot\System32\version.dll"
        $dllDst = Join-Path $workDir ($Marker + '_version.dll')
        Copy-Item -Path $dllSrc -Destination $dllDst -Force
        Add-Type -Namespace MDECustomProbe -Name Loader -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr LoadLibrary(string lpFileName);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FreeLibrary(System.IntPtr hModule);
'@
        $handle = [MDECustomProbe.Loader]::LoadLibrary($dllDst)
        if ($handle -ne [IntPtr]::Zero) {
            [void][MDECustomProbe.Loader]::FreeLibrary($handle)
            Add-Result 'DeviceCustomImageLoadEvents' 'load benign DLL from marker path' 'fired' $dllDst
        }
        else {
            Add-Result 'DeviceCustomImageLoadEvents' 'load benign DLL from marker path' 'error' 'LoadLibrary returned null'
        }
    }
    catch {
        Add-Result 'DeviceCustomImageLoadEvents' 'load benign DLL from marker path' 'error' $_.Exception.Message
    }

    # 3. File. Create, modify, and delete a marker file to cover write and delete events.
    try {
        $filePath = Join-Path $workDir ($Marker + '_file.txt')
        Set-Content -Path $filePath -Value ("$Marker created $utc") -Encoding UTF8
        Add-Content -Path $filePath -Value ("$Marker modified $utc")
        $fileDetail = $filePath
        if (-not $KeepArtifacts) {
            Remove-Item -Path $filePath -Force
            $fileDetail = $filePath + ' (created, modified, deleted)'
        }
        Add-Result 'DeviceCustomFileEvents' 'create, modify, delete marker file' 'fired' $fileDetail
    }
    catch {
        Add-Result 'DeviceCustomFileEvents' 'create, modify, delete marker file' 'error' $_.Exception.Message
    }

    # 4. Network. Complete a short outbound TCP connect so the rule captures a successful connection.
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($RemoteHost, $RemotePort, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(2500, $false)
        if ($ok -and $client.Connected) {
            $client.EndConnect($iar)
            $client.Close()
            Add-Result 'DeviceCustomNetworkEvents' 'outbound TCP connect' 'fired' ("$RemoteHost`:$RemotePort connected")
        }
        else {
            $client.Close()
            Add-Result 'DeviceCustomNetworkEvents' 'outbound TCP connect' 'warn' ("$RemoteHost`:$RemotePort did not complete, rule may skip failed connects")
        }
    }
    catch {
        Add-Result 'DeviceCustomNetworkEvents' 'outbound TCP connect' 'warn' ("$RemoteHost`:$RemotePort attempt only")
    }

    # 5. Registry. Create and modify a marker value, then remove it. Prefer HKLM, fall back to HKCU when not SYSTEM.
    try {
        try {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
        }
        catch {
            $regPath = 'HKCU:\SOFTWARE\' + $Marker
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
        }
        New-ItemProperty -Path $regPath -Name 'Probe' -Value $Marker -PropertyType String -Force | Out-Null
        Set-ItemProperty -Path $regPath -Name 'Probe' -Value ($Marker + '_' + $utc)
        $regDetail = $regPath
        if (-not $KeepArtifacts) {
            Remove-Item -Path $regPath -Recurse -Force
            $regDetail = $regPath + ' (created, modified, deleted)'
        }
        Add-Result 'DeviceCustomRegistryEvents' 'create, modify, delete marker value' 'fired' $regDetail
    }
    catch {
        Add-Result 'DeviceCustomRegistryEvents' 'create, modify, delete marker value' 'error' $_.Exception.Message
    }

    # 6. Script. Run a child PowerShell whose script content carries the marker so AMSI captures it.
    try {
        $scriptBody = "Write-Output '$Marker script content at $utc'"
        $psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $sp = Start-Process -FilePath $psExe -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $scriptBody) -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 400
        Add-Result 'DeviceCustomScriptEvents' 'child PowerShell with marker script content' 'fired' ("pid " + $sp.Id)
    }
    catch {
        Add-Result 'DeviceCustomScriptEvents' 'child PowerShell with marker script content' 'error' $_.Exception.Message
    }

    if (-not $KeepArtifacts) {
        Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Output ("Device: {0}  UTC: {1}  Marker: {2}" -f $device, $utc, $Marker)
    Write-Output '----------------------------------------------------------------'
    $results | Format-Table -AutoSize | Out-String | Write-Output
    Write-Output '----------------------------------------------------------------'
    Write-Output 'Hunt after 5 to 15 minutes with:'
    Write-Output ("  search in (DeviceCustomProcessEvents, DeviceCustomImageLoadEvents, DeviceCustomFileEvents, DeviceCustomNetworkEvents, DeviceCustomRegistryEvents, DeviceCustomScriptEvents) DeviceName has ""{0}"" | where * has ""{1}""" -f $device, $Marker)

    $errCount = @($results | Where-Object { $_.Status -eq 'error' }).Count
    if ($errCount -gt 0) {
        Write-Error ("{0} generator step(s) failed. See table above." -f $errCount)
        exit 1
    }
    exit 0
}
catch {
    Write-Error ("Probe failed: {0}" -f $_.Exception.Message)
    exit 1
}
