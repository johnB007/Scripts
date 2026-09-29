<#
.SYNOPSIS
    Generates benign activity that fires all six MDE event categories so the
    default Device*Events and custom DeviceCustom*Events tables populate.
.DESCRIPTION
    Training and validation generator for MDE Live Response. Fires Process,
    Network, File, Registry, Image Load, and Script events with harmless
    activity, then removes the files and registry value it created. Read the
    marker string in advanced hunting to find exactly what this produced.
.PARAMETER Iterations
    How many times to repeat the activity burst. Default 5.
.PARAMETER NetworkTarget
    Host to open a short lived TCP 443 connection to for network events.
.PARAMETER Marker
    Recognizable string stamped into commands, files, and registry so you can
    filter for exactly this run in advanced hunting.
.PARAMETER Remediate
    Generate the telemetry. Without this switch the script performs a dry run.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 20)]
    [int]$Iterations = 5,
    [string]$NetworkTarget = '1.1.1.1',
    [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')]
    [string]$Marker = 'MDE_CUSTOM_COLLECTION_VALIDATION',
    [switch]$Remediate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$device = $env:COMPUTERNAME
$utc    = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$outDir = Join-Path $env:TEMP ("Telemetry_{0}" -f ([Guid]::NewGuid().ToString('N')))
$regKey = "HKCU:\Software\$Marker"
$fired  = [ordered]@{ Process = 0; Network = 0; File = 0; Registry = 0; ImageLoad = 0; Script = 0 }

Write-Output ("Device: {0}  UTC: {1}" -f $device, $utc)
Write-Output ("Marker: {0}  Iterations: {1}  Remediate: {2}" -f $Marker, $Iterations, [bool]$Remediate)

if (-not $Remediate) {
    Write-Output 'DRY RUN. No telemetry was generated and no device changes were made.'
    Write-Output 'Run with -Remediate after authorization to generate the test activity.'
    exit 0
}

New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Invoke-NativeTool {
    param([string]$File, [string]$ArgumentLine)
    # Spawn a native tool so a ProcessCreated event fires. Suppress its window.
    Start-Process -FilePath $File -ArgumentList $ArgumentLine -WindowStyle Hidden `
        -RedirectStandardOutput ([IO.Path]::Combine($outDir, 'nul.out')) `
        -RedirectStandardError  ([IO.Path]::Combine($outDir, 'nul.err')) `
        -Wait -ErrorAction SilentlyContinue | Out-Null
}

try {
    New-Item -Path $regKey -Force | Out-Null

    for ($i = 1; $i -le $Iterations; $i++) {

        # 1 Process events. Native tools each spawn a new process.
        foreach ($p in @(
            @{ f = 'whoami.exe';   a = '/all' },
            @{ f = 'hostname.exe'; a = '' },
            @{ f = 'ipconfig.exe'; a = '/all' },
            @{ f = 'tasklist.exe'; a = '' }
        )) {
            Invoke-NativeTool -File $p.f -ArgumentLine $p.a
            $fired.Process++
        }

        # 2 Network events. Short lived outbound TCP 443 connection.
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($NetworkTarget, 443, $null, $null)
            [void]$iar.AsyncWaitHandle.WaitOne(3000, $false)
            $client.Close()
            $fired.Network++
        } catch {
            Write-Verbose ("Network step skipped: {0}" -f $_.Exception.Message)
        }

        # 3 File events. Create, modify, rename, then delete.
        $f1 = Join-Path $outDir ("{0}_{1}.txt" -f $Marker, $i)
        $f2 = Join-Path $outDir ("{0}_{1}_renamed.txt" -f $Marker, $i)
        Set-Content -Path $f1 -Value "$Marker created $utc" -Encoding UTF8
        Add-Content -Path $f1 -Value "$Marker modified"
        Rename-Item -Path $f1 -NewName (Split-Path $f2 -Leaf)
        Remove-Item -Path $f2 -Force
        $fired.File++

        # 4 Registry events. Set then delete a value under HKCU.
        $valName = "Run_$i"
        New-ItemProperty -Path $regKey -Name $valName -Value "$Marker $utc" `
            -PropertyType String -Force | Out-Null
        Remove-ItemProperty -Path $regKey -Name $valName -Force
        $fired.Registry++

        # 5 Image load events. New powershell process explicitly loads a module.
        Invoke-NativeTool -File 'powershell.exe' `
            -ArgumentLine "-NoProfile -NonInteractive -Command `"[void][System.Reflection.Assembly]::LoadWithPartialName('System.Xml'); '$Marker imageload'`""
        $fired.ImageLoad++

        # 6 Script events. AMSI inspects this script content on execution.
        Invoke-NativeTool -File 'powershell.exe' `
            -ArgumentLine "-NoProfile -NonInteractive -Command `"`$m='$Marker script content'; Write-Output `$m`""
        $fired.Script++

        Start-Sleep -Milliseconds 500
    }

    Write-Output ("Device: {0}  UTC: {1}" -f $device, $utc)
    Write-Output ("Marker: {0}" -f $Marker)
    Write-Output ("Iterations: {0}" -f $Iterations)
    Write-Output '--- Events fired (source activity, not table row counts) ---'
    foreach ($k in $fired.Keys) { Write-Output ("{0,-10}: {1}" -f $k, $fired[$k]) }
    Write-Output ''
    Write-Output 'Hunt for this run in advanced hunting:'
    Write-Output ("  search in (DeviceProcessEvents, DeviceCustomProcessEvents, DeviceCustomScriptEvents) `"{0}`"" -f $Marker)
    Write-Output 'Custom tables lag the default tables by a few minutes. Give it 5 to 10 min.'
    exit 0
}
catch {
    Write-Error ("Telemetry generation failed: {0}" -f $_.Exception.Message)
    exit 1
}
finally {
    # Clean up everything this script created.
    if (Test-Path $regKey) { Remove-Item -Path $regKey -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $outDir) { Remove-Item -Path $outDir -Recurse -Force -ErrorAction SilentlyContinue }
}
