<# 
.SYNOPSIS
    A comprehensive PowerShell-based system artifact collection and forensic capture tool.

.DESCRIPTION
    This script supports four mutually exclusive modes:
      -ArtifactCapture    : Collects user & non-user artifacts, registry hives, live volatile data,
                            and NTUSER.DAT files.
      -MemoryDumpOnly     : Captures only a full system memory dump.
      -ProcessDumpOnly    : Captures dumps for specified processes (requires -ProcessIdentifiers).
      -NTFSJournaling     : Captures NTFS journaling separately.
    ArtifactCapture collects event logs, prefetch files, recycle bin contents, browser data, LNK/jumplists 
    and registry hives—but it does NOT capture memory or process dumps.
    Live volatile data (network connections, executed commands, scheduled tasks, startup applications,
    network configuration, installed software, and the full process list) are saved in a dedicated subfolder.
    NTUSER.DAT files are extracted from each user profile into the “NTUSER” folder inside Artifacts;
    if a file is locked, a text file is created stating that the file was locked.
    After all tasks complete, the results are zipped and hashed, and a separate external hash file is produced.
    
    Console output includes section notifications along the way, and the very last two lines show the final ZIP
    file path and the HASH file path.
    
.PARAMETER ArtifactCapture
    Switch – collects artifacts, registry hives, live volatile data, and NTUSER.DAT files.

.PARAMETER MemoryDumpOnly
    Switch – captures only a full system memory dump.

.PARAMETER ProcessDumpOnly
    Switch – captures only process dumps (requires -ProcessIdentifiers).

.PARAMETER NTFSJournaling
    Switch – captures NTFS journaling separately.

.PARAMETER ProcessIdentifiers
    An array of process names (or numeric PIDs) when using -ProcessDumpOnly.
    
.NOTES
    Author   : FMA & Microsoft
    Version  : 1.3
    Date     : 2025-06-16
#>

param (
    [switch]$ArtifactCapture,
    [switch]$MemoryDumpOnly,
    [switch]$ProcessDumpOnly,
    [switch]$NTFSJournaling,
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -and [string]::IsNullOrWhiteSpace($_)) { throw "ProcessIdentifiers entries must be nonempty strings." }
        $true
    })]
    [string[]]$ProcessIdentifiers
)

# Validate that at least one mode is specified
if (-not ($ArtifactCapture -or $MemoryDumpOnly -or $ProcessDumpOnly -or $NTFSJournaling)) {
    Write-Error "You must specify at least one mode: -ArtifactCapture, -MemoryDumpOnly, -ProcessDumpOnly, or -NTFSJournaling."
    exit 1
}

# If ProcessDumpOnly is selected, require ProcessIdentifiers
if ($ProcessDumpOnly -and (-not $ProcessIdentifiers -or $ProcessIdentifiers.Count -eq 0)) {
    Write-Error "When using -ProcessDumpOnly you must supply at least one -ProcessIdentifiers value."
    exit 1
}

# Suppress progress and verbose output (notifications below use Write-Host)
$VerbosePreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# Record start time
$global:startTime = Get-Date

#region Helper Functions

function MarkFolderIfEmpty {
    param (
        [string]$FolderPath
    )
    if (Test-Path $FolderPath) {
        $contents = Get-ChildItem -Path $FolderPath -Force
        if ($contents.Count -eq 0) {
            $newName = "$FolderPath" + "_NO_DATA"
            Rename-Item -Path $FolderPath -NewName (Split-Path $newName -Leaf)
        }
    }
}

#endregion Helper Functions

#region Logging Functions

function Append-Log {
    param (
        [string]$Message,
        [string]$LogFile
    )
    $logDir = Split-Path -Path $LogFile
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LogFile -Value "$timestamp : $Message"
}

function Log-AllUsers {
    param (
        [string]$OutputFolder
    )
    $users = Get-UserProfiles | Select-Object Name, FullName
    $usersLog = Join-Path $OutputFolder "UsersLog.txt"
    $users | Out-File -FilePath $usersLog -Force
}

function Get-UserProfiles {
    # Exclude built-in/system profiles
    Get-ChildItem -Path "C:\Users" -Directory -Force |
      Where-Object { $_.Name -notin @("Public","Default","Default User","All Users","systemprofile") }
}

#endregion Logging Functions

#region Registry Hive Collection

function Collect-RegistryHives {
    param (
        [string]$DestinationFolder
    )
    Append-Log "Starting registry hive collection..." $global:CollectionLogFile
    $hiveFolder = Join-Path $DestinationFolder "RegistryHives"
    New-Item -ItemType Directory -Path $hiveFolder -Force | Out-Null

    # System hives
    $systemHives = @("SYSTEM","SOFTWARE","SECURITY","SAM","DEFAULT")
    foreach ($h in $systemHives) {
        $dest = Join-Path $hiveFolder "$h.hiv"
        $args = @("save","HKLM\$h",$dest,"/y")
        Start-Process reg.exe -ArgumentList $args -Wait -WindowStyle Hidden | Out-Null
        if (Test-Path $dest) {
            Append-Log "Saved HKLM\$h to $dest" $global:CollectionLogFile
        }
        else {
            Append-Log "Failed to save HKLM\$h" $global:ErrorLogFile
        }
    }

    # User hives 
    $userHiveFolder = Join-Path $hiveFolder "Users"
    New-Item -ItemType Directory -Path $userHiveFolder -Force | Out-Null
    $uids = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
              Where-Object { $_.PSChildName -notmatch "^(S-1-5-18)$" }
    foreach ($u in $uids) {
        $sid = $u.PSChildName
        $dest = Join-Path $userHiveFolder "$sid.hiv"
        $args = @("save","HKU\$sid",$dest,"/y")
        Start-Process reg.exe -ArgumentList $args -Wait -WindowStyle Hidden | Out-Null
        if (Test-Path $dest) {
            Append-Log "Saved HKU\$sid to $dest" $global:CollectionLogFile
        }
        else {
            Append-Log "Failed to save HKU\$sid" $global:ErrorLogFile
        }
    }
    Append-Log "Registry hive collection complete." $global:CollectionLogFile
}

#endregion Registry Hive Collection

#region User-Specific Artifact Collection

function Get-OneDriveArtifactsAll {
    $results = @()
    foreach ($p in Get-UserProfiles) {
        $path = Join-Path $p.FullName "OneDrive"
        if (Test-Path $path) {
            $results += (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{ FullName = $_.FullName; Name = $_.Name; User = $p.Name }
            })
        }
    }
    return $results
}

function Get-EdgeArtifactsAll {
    $results = @()
    foreach ($p in Get-UserProfiles) {
        $path = Join-Path $p.FullName "AppData\Local\Microsoft\Edge\User Data\Default"
        if (Test-Path $path) {
            $results += (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{ FullName = $_.FullName; Name = $_.Name; User = $p.Name }
            })
        }
    }
    return $results
}

function Get-FirefoxArtifactsAll {
    $results = @()
    foreach ($p in Get-UserProfiles) {
        $path = Join-Path $p.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path $path) {
            $results += (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{ FullName = $_.FullName; Name = $_.Name; User = $p.Name }
            })
        }
    }
    return $results
}

function Get-ChromeArtifactsAll {
    $results = @()
    foreach ($p in Get-UserProfiles) {
        $path = Join-Path $p.FullName "AppData\Local\Google\Chrome\User Data\Default"
        if (Test-Path $path) {
            $results += (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{ FullName = $_.FullName; Name = $_.Name; User = $p.Name }
            })
        }
    }
    return $results
}

function Get-LNKandJumplistsAll {
    $results = @()
    foreach ($p in Get-UserProfiles) {
        $rpath = Join-Path $p.FullName "AppData\Roaming\Microsoft\Windows\Recent"
        if (Test-Path $rpath) {
            $results += (Get-ChildItem -Path $rpath -Recurse -Include *.lnk -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{ FullName = $_.FullName; Name = $_.Name; User = $p.Name }
            })
        }
        $jpath = Join-Path $p.FullName "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
        if (Test-Path $jpath) {
            $results += (Get-ChildItem -Path $jpath -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{ FullName = $_.FullName; Name = $_.Name; User = $p.Name }
            })
        }
    }
    return $results
}

#endregion User-Specific Artifact Collection

#region Non-User-Specific Artifact Collection

function Get-AllEventLogFiles {
    Get-ChildItem -Path "$env:SystemRoot\System32\winevt\Logs" -Filter *.evtx -Recurse -ErrorAction SilentlyContinue
}

function Get-PrefetchFiles {
    Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Filter *.pf -Recurse -ErrorAction SilentlyContinue
}

function Get-RecycleBinContents {
    Get-ChildItem -Path "C:\`$Recycle.Bin" -Force -Recurse -ErrorAction SilentlyContinue
}

function Collect-NTFSJournalingArtifacts {
    param ([string]$OutputFolder)
    $results = @()
    $volumes = Get-Volume | Where-Object { $_.FileSystem -eq 'NTFS' -and $_.DriveLetter }
    foreach ($v in $volumes) {
        $drive = "$($v.DriveLetter):"
        $outputFile = Join-Path $OutputFolder ("USN_Journal_$($v.DriveLetter).csv")
        try {
            fsutil usn readjournal $drive csv | Out-File -FilePath $outputFile -Encoding utf8
            Append-Log "Collected USN journal for $drive to $outputFile" $global:CollectionLogFile
            if (Test-Path $outputFile) {
                $results += [PSCustomObject]@{ FullName = $outputFile; Name = "USN_Journal_$($v.DriveLetter).csv" }
            }
        }
        catch {
            Append-Log "Failed to collect USN journal for {$drive}: $_" $global:ErrorLogFile
        }
    }
    return $results
}

function Get-RegistryTransactionLogs {
    Get-ChildItem -Path "$env:SystemRoot\System32\config" -Include *.LOG1,*.LOG2 -Force -ErrorAction SilentlyContinue
}

#endregion Non-User-Specific Artifact Collection

#region Live Data Collection Functions

function Get-NetworkConnections {
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
}

function Get-ExecutedCommands {
    Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4688)]]' -MaxEvents 1000 |
      Select-Object TimeCreated, @{Name = 'CommandLine'; Expression = { if ($_.Properties.Count -ge 9) { $_.Properties[8].Value } else { 'N/A' } } }
}

function Get-RunningScheduledTasks {
    Get-ScheduledTask | Where-Object State -eq 'Running' | Get-ScheduledTaskInfo | Select-Object TaskName, NextRunTime, LastRunTime
}

function Get-AllScheduledTasks {
    Get-ScheduledTask | Select-Object *
}

function Get-StartupApplications {
    Get-WmiObject -Class Win32_StartupCommand | Select-Object Name, Command, Location, User
}

function Collect-NetworkConnectionsLog {
    param ([string]$OutputFolder)
    $file = Join-Path $OutputFolder "NetworkConnections.txt"
    (Get-NetworkConnections | Format-Table -AutoSize | Out-String) | Out-File $file -Force
}

function Collect-ExecutedCommandsLog {
    param ([string]$OutputFolder)
    $file = Join-Path $OutputFolder "ExecutedCommands.txt"
    (Get-ExecutedCommands | Format-Table -AutoSize | Out-String) | Out-File $file -Force
}

function Collect-RunningScheduledTasksLog {
    param ([string]$OutputFolder)
    $file = Join-Path $OutputFolder "RunningScheduledTasks.txt"
    (Get-RunningScheduledTasks | Format-Table -AutoSize | Out-String) | Out-File $file -Force
}

function Collect-AllScheduledTasksLog {
    param ([string]$OutputFolder)
    $file = Join-Path $OutputFolder "AllScheduledTasks.txt"
    (Get-AllScheduledTasks | Format-Table -AutoSize | Out-String) | Out-File $file -Force
}

function Collect-StartupApplicationsLog {
    param ([string]$OutputFolder)
    $file = Join-Path $OutputFolder "StartupApplications.txt"
    (Get-StartupApplications | Format-Table -AutoSize | Out-String) | Out-File $file -Force
}

#endregion Live Data Collection Functions

#region Memory and Process Dump Functions

function Capture-FullMemoryDump {
    param ([string]$DumpFolder)
    try {
        $dumpPath = Join-Path $DumpFolder "FullMemoryDump.dmp"
        Append-Log "Creating full memory dump to $dumpPath" $global:CollectionLogFile
        Start-Process "C:\Windows\System32\rundll32.exe" -ArgumentList "comsvcs.dll,MiniDump $PID $dumpPath full" -Wait -ErrorAction Stop | Out-Null
        Append-Log "Full memory dump created: $dumpPath" $global:CollectionLogFile
        return $dumpPath
    }
    catch {
        Append-Log "Error capturing full memory dump: $_" $global:ErrorLogFile
        throw
    }
}

function Capture-ProcessDump {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$ProcessIdentifier,
        [string]$DumpFolder
    )
    $dumpPaths = @()
    foreach ($id in $ProcessIdentifier) {
        try {
            $procs = if ($id -as [int]) {
                        @(Get-Process -Id ([int]$id) -ErrorAction SilentlyContinue)
                     }
                     else {
                        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$id*" }
                     }
            if ($procs.Count -eq 0) {
                Append-Log "No process found matching identifier '$id'." $global:ErrorLogFile
                continue
            }
            foreach ($p in $procs) {
                $dumpPath = Join-Path $DumpFolder "$($p.Name)_$($p.Id)_ProcessDump.dmp"
                Append-Log "Creating dump for $($p.Name) (PID $($p.Id)) to $dumpPath" $global:CollectionLogFile
                Start-Process "C:\Windows\System32\rundll32.exe" -ArgumentList "comsvcs.dll,MiniDump $($p.Id) $dumpPath full" -Wait -ErrorAction Stop | Out-Null
                Append-Log "Process dump created: $dumpPath" $global:CollectionLogFile
                $dumpPaths += $dumpPath
            }
        }
        catch {
            Append-Log "Error dumping identifier '$id': $_" $global:ErrorLogFile
        }
    }
    return $dumpPaths
}

#endregion Memory and Process Dump Functions

#region Archive & System Information Functions

function Create-ZipFile {
    param (
        [string]$sourceFolder,
        [string]$zipFilePath
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($sourceFolder, $zipFilePath)
}

function Get-ZipFileHash {
    param (
        [string]$FilePath,
        [string]$Algorithm = "SHA256"
    )
    try {
        (Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop).Hash
    }
    catch {
        "Failed to calculate hash: $_"
    }
}

function Collect-FullProcessList {
    param ([string]$OutputFolder)
    $out = Join-Path $OutputFolder "FullProcessList.txt"
    (Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
         Where-Object { $_.UserName } | Format-Table -AutoSize | Out-String) |
         Out-File -FilePath $out -Force
    Append-Log "Full process list saved to $out" $global:CollectionLogFile
}

function Collect-SystemInfoLog {
    param ([string]$OutputFolder)
    $out = Join-Path $OutputFolder "SystemInfo.txt"
    $sys = Get-ComputerInfo | Out-String
    $hw = Get-CimInstance Win32_ComputerSystem | Out-String
    $bios = Get-CimInstance Win32_BIOS | Out-String
    $text = "=== System ===`r`n$sys`r`n=== Hardware ===`r`n$hw`r`n=== BIOS ===`r`n$bios"
    $text | Out-File -FilePath $out -Force
    Append-Log "System info saved to $out" $global:CollectionLogFile
}

function Collect-NetworkConfigLog {
    param ([string]$OutputFolder)
    $out = Join-Path $OutputFolder "NetworkConfig.txt"
    $ip = ipconfig /all | Out-String
    $arp = arp -a | Out-String
    $route = route print | Out-String
    $combo = "=== IPConfig ===`r`n$ip`r`n=== ARP ===`r`n$arp`r`n=== Route ===`r`n$route"
    $combo | Out-File -FilePath $out -Force
    return $out
}

function Collect-InstalledSoftwareLog {
    param ([string]$OutputFolder)
    $out = Join-Path $OutputFolder "InstalledSoftware.txt"
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $soft = foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }
    ($soft | Format-Table -AutoSize | Out-String) | Out-File -FilePath $out -Force
    return $out
}

#endregion Archive & System Information Functions

#region NTUSER.DAT Collection

# Note: NTUSER.DAT files are now saved into the NTUSER folder inside the main Artifacts folder.
function Capture-NTUSERData {
    param ([string]$DestinationFolder)
    $artifactFolder = Join-Path $DestinationFolder "Artifacts"
    $ntuserFolder = Join-Path $artifactFolder "NTUSER"
    if (-not (Test-Path $ntuserFolder)) {
        New-Item -ItemType Directory -Path $ntuserFolder -Force | Out-Null
    }
    foreach ($profile in Get-UserProfiles) {
        $sourceFile = Join-Path $profile.FullName "NTUSER.DAT"
        $destFile = Join-Path $ntuserFolder ("$($profile.Name)_NTUSER.DAT")
        try {
            if (Test-Path $sourceFile) {
                Copy-Item -Path $sourceFile -Destination $destFile -ErrorAction Stop | Out-Null
                Append-Log "Copied NTUSER.DAT for user $($profile.Name)" $global:CollectionLogFile
            }
            else {
                Append-Log "NTUSER.DAT not found for user $($profile.Name)" $global:ErrorLogFile
            }
        }
        catch {
            $lockedFile = Join-Path $ntuserFolder ("$($profile.Name)_NTUSER_LOCKED.txt")
            "NTUSER.DAT for user $($profile.Name) was locked." | Out-File -FilePath $lockedFile -Force
            Append-Log "NTUSER.DAT for user $($profile.Name) is locked." $global:ErrorLogFile
        }
    }
    # Mark NTUSER folder if empty
    MarkFolderIfEmpty -FolderPath $ntuserFolder
}

#endregion NTUSER.DAT Collection

#region Main Artifact Collection Flow

function Collect-SystemArtifacts {
    param ([string]$ParentFolder)
    $artifactFolder = Join-Path $ParentFolder "Artifacts"
    New-Item -ItemType Directory -Path $artifactFolder -Force | Out-Null

    $functionsList = @(
        @{ Name = "Event Logs";         Function = { Get-AllEventLogFiles } },
        @{ Name = "Prefetch Files";     Function = { Get-PrefetchFiles } },
        @{ Name = "Recycle Bin";        Function = { Get-RecycleBinContents } },
        @{ Name = "Edge Artifacts";     Function = { Get-EdgeArtifactsAll } },
        @{ Name = "Firefox Artifacts";  Function = { Get-FirefoxArtifactsAll } },
        @{ Name = "Chrome Artifacts";   Function = { Get-ChromeArtifactsAll } },
        @{ Name = "OneDrive Artifacts"; Function = { Get-OneDriveArtifactsAll } },
        @{ Name = "LNK & Jumplists";    Function = { Get-LNKandJumplistsAll } }
    )

    foreach ($cf in $functionsList) {
        Append-Log "Begin $($cf.Name)" $global:CollectionLogFile
        try {
            $artifacts = & $cf.Function
            if (-not $artifacts -or ($artifacts -is [System.Collections.IEnumerable] -and $artifacts.Count -eq 0)) {
                # Create subfolder with NO_DATA suffix and drop a NO_DATA.txt file inside
                $noDataFolder = Join-Path $artifactFolder "$($cf.Name)_NO_DATA"
                if (-not (Test-Path $noDataFolder)) { New-Item -ItemType Directory -Path $noDataFolder -Force | Out-Null }
                "No data collected for $($cf.Name)" | Out-File -FilePath (Join-Path $noDataFolder "NO_DATA.txt") -Force
            }
            elseif ($cf.Name -in @("Event Logs", "Prefetch Files", "Recycle Bin")) {
                $destDir = Join-Path $artifactFolder $cf.Name
                if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                foreach ($a in $artifacts) {
                    if ($a.FullName) {
                        $dest = Join-Path $destDir $a.Name
                        Copy-Item -Path $a.FullName -Destination $dest -Recurse:$a.PSIsContainer -Force -ErrorAction Stop | Out-Null
                        Append-Log "Copied $($a.FullName)" $global:CollectionLogFile
                    }
                }
                # Mark subfolder if empty
                MarkFolderIfEmpty -FolderPath $destDir
            }
            else {
                # For user-specific artifacts, create subfolders per section
                foreach ($a in $artifacts) {
                    if ($a.FullName) {
                        $subDir = if ($a.User) { Join-Path $cf.Name $a.User } else { $cf.Name }
                        $destDir = Join-Path $artifactFolder $subDir
                        if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                        $dest = Join-Path $destDir $a.Name
                        Copy-Item -Path $a.FullName -Destination $dest -Recurse:$a.PSIsContainer -Force -ErrorAction Stop | Out-Null
                        Append-Log "Copied $($a.FullName)" $global:CollectionLogFile
                    }
                }
                # For each subfolder created, mark as NO_DATA if it ended up empty
                Get-ChildItem -Path $artifactFolder -Directory | ForEach-Object {
                    MarkFolderIfEmpty -FolderPath $_.FullName
                }
            }
        }
        catch {
            Append-Log "Error in $($cf.Name): $_" $global:ErrorLogFile
        }
        Append-Log "Done $($cf.Name)" $global:CollectionLogFile
    }
}

#endregion Main Artifact Collection Flow

#region Main Execution Flow

# Create a unique parent folder under C:\Windows
$ParentFolder = Join-Path "C:\Windows" ("ArtifactCollection_" + [guid]::NewGuid().ToString())
if (-not (Test-Path $ParentFolder)) { New-Item -ItemType Directory -Path $ParentFolder -Force | Out-Null }

# Initialize log file paths
$global:CollectionLogFile = Join-Path $ParentFolder "CollectionLog.txt"
$global:ErrorLogFile = Join-Path $ParentFolder "ErrorLog.txt"
New-Item -ItemType File -Path $global:CollectionLogFile -Force | Out-Null
New-Item -ItemType File -Path $global:ErrorLogFile -Force | Out-Null

Write-Host "==> Starting Execution..." 

Write-Host "==> Collecting user profiles and logging users..."
Log-AllUsers -OutputFolder $ParentFolder | Out-Null

if ($ArtifactCapture) {
    Write-Host "==> Artifact Capture mode selected."
    Append-Log "Mode=ArtifactCapture" $global:CollectionLogFile

    Write-Host "   -> Collecting file-based artifacts..."
    Collect-SystemArtifacts -ParentFolder $ParentFolder | Out-Null

    Write-Host "   -> Collecting registry hives..."
    Append-Log "Collecting registry hives" $global:CollectionLogFile
    Collect-RegistryHives -DestinationFolder (Join-Path $ParentFolder "Artifacts") | Out-Null

    if ($NTFSJournaling) {
        Write-Host "   -> Capturing NTFS Journaling..."
        $ntfsFolder = Join-Path $ParentFolder "NTFS_Journaling"
        if (-not (Test-Path $ntfsFolder)) { New-Item -ItemType Directory -Path $ntfsFolder -Force | Out-Null }
        Collect-NTFSJournalingArtifacts -OutputFolder $ntfsFolder | Out-Null
        MarkFolderIfEmpty -FolderPath $ntfsFolder
    }

    Write-Host "   -> Capturing NTUSER.DAT files into Artifacts..."
    Capture-NTUSERData -DestinationFolder $ParentFolder | Out-Null

    Write-Host "   -> Collecting live volatile data..."
    $liveFolder = Join-Path $ParentFolder "Artifacts\LiveData"
    if (-not (Test-Path $liveFolder)) { New-Item -ItemType Directory -Path $liveFolder -Force | Out-Null }
    Collect-NetworkConnectionsLog -OutputFolder $liveFolder | Out-Null
    Collect-ExecutedCommandsLog -OutputFolder $liveFolder | Out-Null
    Collect-RunningScheduledTasksLog -OutputFolder $liveFolder | Out-Null
    Collect-AllScheduledTasksLog -OutputFolder $liveFolder | Out-Null
    Collect-StartupApplicationsLog -OutputFolder $liveFolder | Out-Null
    Collect-NetworkConfigLog -OutputFolder $liveFolder | Out-Null
    Collect-InstalledSoftwareLog -OutputFolder $liveFolder | Out-Null
    Collect-SystemInfoLog -OutputFolder $liveFolder | Out-Null
    Collect-FullProcessList -OutputFolder $liveFolder | Out-Null
    MarkFolderIfEmpty -FolderPath $liveFolder
}

if ($MemoryDumpOnly) {
    Write-Host "==> Memory Dump Only mode selected."
    try {
        Capture-FullMemoryDump -DumpFolder $ParentFolder | Out-Null
    }
    catch { Append-Log "Memory dump failed: $_" $global:ErrorLogFile }
}

if ($ProcessDumpOnly) {
    Write-Host "==> Process Dump Only mode selected."
    try {
        Capture-ProcessDump -ProcessIdentifier $ProcessIdentifiers -DumpFolder $ParentFolder | Out-Null
    }
    catch { Append-Log "Process dump failed: $_" $global:ErrorLogFile }
}

Write-Host "==> Creating ZIP archive and calculating hash..."
$zipFilePath = "C:\SystemArtifacts_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
Append-Log "Zipping to $zipFilePath" $global:CollectionLogFile
Create-ZipFile -sourceFolder $ParentFolder -zipFilePath $zipFilePath | Out-Null

$zipHash = Get-ZipFileHash -FilePath $zipFilePath
Append-Log "ZIP hash: $zipHash" $global:CollectionLogFile

Write-Host "==> Creating external hash file..."
$hashFilePath = "C:\SystemArtifacts_$(Get-Date -Format 'yyyyMMdd_HHmmss')_HASH.txt"
$zipHash | Out-File -FilePath $hashFilePath -Force

try {
    Remove-Item -Path $ParentFolder -Recurse -Force | Out-Null
}
catch {
    Append-Log "Cleanup failed: $_" $global:ErrorLogFile
}

Write-Host "==> Execution complete."

# FINAL CONSOLE OUTPUT: Only the ZIP file location and the HASH file location appear last.
Write-Output $zipFilePath
Write-Output $hashFilePath

#endregion Main Execution Flow