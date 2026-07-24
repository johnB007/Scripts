<#
.SYNOPSIS
Simple file transfer helper between 324-UM-Defcon30 host and DC007 Hyper-V guest.

.DESCRIPTION
Supports push (324 to DC007 via Copy-VMFile) and pull (DC007 to 324 via network copy).
Run on the 324 device as Administrator.

.EXAMPLE
# Push a file to DC007
.\Move-LabFiles.ps1 -Direction Push -LocalPath "C:\Temp\myscript.ps1" -RemotePath "C:\Lab\myscript.ps1"

.EXAMPLE
# Pull a file from DC007
.\Move-LabFiles.ps1 -Direction Pull -RemotePath "C:\Lab\output.txt" -LocalPath "C:\Temp\output.txt"

.EXAMPLE
# Push entire folder to DC007
.\Move-LabFiles.ps1 -Direction Push -LocalPath "C:\Temp\MyFolder" -RemotePath "C:\Lab\MyFolder" -Recurse

.EXAMPLE
# Test connectivity first
.\Move-LabFiles.ps1 -TestOnly
#>
[CmdletBinding()]
param(
    [ValidateSet('Push','Pull')]
    [string]$Direction,

    [string]$LocalPath,
    [string]$RemotePath,

    [string]$VMName = 'dc007.john.local',

    [string]$VMUser = 'Administrator',
    [string]$VMPassword,

    [switch]$Recurse,
    [switch]$TestOnly
)

$ErrorActionPreference = 'Stop'

function Write-Info([string]$m) { Write-Host "[info] $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "[ok]   $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "[warn] $m" -ForegroundColor Yellow }

# Detect VM IP from Hyper-V network adapters
function Get-VMIp {
    param([string]$Name)
    try {
        $vm = Get-VM -Name $Name -ErrorAction Stop
        $ip = ($vm | Get-VMNetworkAdapter | Select-Object -ExpandProperty IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
        return $ip
    } catch {
        return $null
    }
}

# Check Hyper-V module
$hvModule = Get-Module -ListAvailable -Name Hyper-V
if (-not $hvModule) {
    Write-Warn "Hyper-V module not found. Network path fallback only."
}

# Get VM IP
$vmIp = Get-VMIp -Name $VMName
if ($vmIp) {
    Write-Info "DC007 VM IP detected: $vmIp"
} else {
    Write-Warn "Could not detect VM IP from Hyper-V. Will try network path manually."
    $vmIp = 'DC007'
}

if ($TestOnly) {
    Write-Info "Test mode. Checking VM state and connectivity."

    if ($hvModule) {
        try {
            $vm = Get-VM -Name $VMName
            Write-Ok ("VM state: " + $vm.State)
            $guestServices = ($vm | Get-VMIntegrationService | Where-Object { $_.Name -match 'Guest Service' })
            if ($guestServices -and $guestServices.Enabled) {
                Write-Ok "Guest Services integration is enabled. Copy-VMFile will work."
            } else {
                Write-Warn "Guest Services integration is not enabled. Enable it in VM Settings > Integration Services."
            }
        } catch {
            Write-Warn "Could not query VM: $_"
        }
    }

    if ($vmIp) {
        $tnc = Test-NetConnection -ComputerName $vmIp -Port 445 -ErrorAction SilentlyContinue
        if ($tnc.TcpTestSucceeded) {
            Write-Ok "Port 445 reachable on $vmIp. UNC file copy will work."
        } else {
            Write-Warn "Port 445 not reachable on $vmIp."
        }

        $tnc2 = Test-NetConnection -ComputerName $vmIp -Port 5985 -ErrorAction SilentlyContinue
        if ($tnc2.TcpTestSucceeded) {
            Write-Ok "WinRM port 5985 reachable. Invoke-Command will work."
        } else {
            Write-Warn "WinRM port 5985 not reachable."
        }
    }

    exit 0
}

if (-not $Direction) { throw "Specify -Direction Push or Pull" }
if (-not $LocalPath)  { throw "Specify -LocalPath" }
if (-not $RemotePath) { throw "Specify -RemotePath" }

if ($Direction -eq 'Push') {
    Write-Info "Push: $LocalPath to $VMName : $RemotePath"

    # Try Copy-VMFile first (no network needed)
    if ($hvModule) {
        try {
            $vm = Get-VM -Name $VMName
            $guestServices = ($vm | Get-VMIntegrationService | Where-Object { $_.Name -match 'Guest Service' -and $_.Enabled })
            if ($guestServices) {
                if ((Get-Item $LocalPath) -is [System.IO.DirectoryInfo] -or $Recurse) {
                    $files = Get-ChildItem -Path $LocalPath -Recurse:$Recurse -File
                    foreach ($f in $files) {
                        $rel = $f.FullName.Substring($LocalPath.TrimEnd('\').Length)
                        $dest = $RemotePath.TrimEnd('\') + $rel
                        Write-Info "Copy-VMFile $($f.FullName) to $dest"
                        Copy-VMFile -Name $VMName -SourcePath $f.FullName -DestinationPath $dest -CreateFullPath -FileSource Host
                    }
                } else {
                    Copy-VMFile -Name $VMName -SourcePath $LocalPath -DestinationPath $RemotePath -CreateFullPath -FileSource Host
                }
                Write-Ok "Push complete via Copy-VMFile (no network required)"
                exit 0
            }
        } catch {
            Write-Warn "Copy-VMFile failed: $_. Trying network fallback."
        }
    }

    # Network fallback
    if ($VMPassword) {
        $cred = New-Object PSCredential($VMUser, (ConvertTo-SecureString $VMPassword -AsPlainText -Force))
        $session = New-PSSession -ComputerName $vmIp -Credential $cred
        Copy-Item -Path $LocalPath -Destination $RemotePath -ToSession $session -Recurse:$Recurse -Force
        Remove-PSSession $session
        Write-Ok "Push complete via PSRemoting"
    } else {
        $uncDest = "\\$vmIp\" + ($RemotePath -replace ':','$' -replace '\\','\'  )
        Copy-Item -Path $LocalPath -Destination $uncDest -Recurse:$Recurse -Force
        Write-Ok "Push complete via UNC path"
    }
}

if ($Direction -eq 'Pull') {
    Write-Info "Pull: $VMName : $RemotePath to $LocalPath"

    # Pull requires network since Copy-VMFile is host to guest only
    if ($VMPassword) {
        $cred = New-Object PSCredential($VMUser, (ConvertTo-SecureString $VMPassword -AsPlainText -Force))
        $session = New-PSSession -ComputerName $vmIp -Credential $cred
        Copy-Item -Path $RemotePath -Destination $LocalPath -FromSession $session -Recurse:$Recurse -Force
        Remove-PSSession $session
        Write-Ok "Pull complete via PSRemoting"
    } else {
        $uncSrc = "\\$vmIp\" + ($RemotePath -replace ':','$' -replace '\\','\')
        Copy-Item -Path $uncSrc -Destination $LocalPath -Recurse:$Recurse -Force
        Write-Ok "Pull complete via UNC path"
    }
}
