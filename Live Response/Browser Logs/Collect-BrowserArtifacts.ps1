<#
.SYNOPSIS
    Collects Chrome and Edge browser artifacts from every user profile on a
    Windows endpoint, optionally parses them to CSV, and zips the result for
    retrieval through MDE Live Response.

.DESCRIPTION
    Designed to run as SYSTEM inside MDE Live Response. Enumerates all user
    profiles under C:\Users, copies Chrome and Edge artifacts from each
    browser profile into a structured folder, exports installed browser
    versions and policy keys, and writes a zip suitable for `getfile`.

    If sqlite3.exe is present in the same folder as this script (or in the
    Live Response Downloads folder), the History, Cookies, Login Data, and
    Web Data SQLite databases are parsed into human readable CSV files under
    a Parsed\ folder inside the zip.

    Encrypted cookie values and saved passwords are NOT decrypted. SYSTEM
    cannot read the per user DPAPI keys without extra work, so CSVs include
    metadata only.

.PARAMETER OutputRoot
    Base folder for staging and the final zip. Defaults to
    C:\ProgramData\BrowserLogs.

.PARAMETER StopBrowsers
    If specified, kills chrome.exe and msedge.exe before copying so the
    SQLite snapshots are clean. Off by default.

.PARAMETER NoZip
    If specified, leaves the staging folder in place and skips zipping.

.EXAMPLE
    From MDE Live Response:
        run Collect-BrowserArtifacts.ps1
        getfile "C:\ProgramData\BrowserLogs\<HOST>_<TIMESTAMP>.zip"

.NOTES
    Tested on Windows PowerShell 5.1 (the version Live Response uses).
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = 'C:\ProgramData\BrowserLogs',
    [switch]$StopBrowsers,
    [switch]$NoZip,
    [switch]$IncludeRecoverable
)

$ErrorActionPreference = 'Continue'
$ts        = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostName  = $env:COMPUTERNAME
$stageName = "${hostName}_${ts}"
$stage     = Join-Path $OutputRoot $stageName
$logPath   = $null

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "{0}  {1,-5}  {2}" -f (Get-Date -Format 's'), $Level, $Message
    Write-Host $line
    if ($logPath) { Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8 }
}

function Copy-FileShared {
    param([string]$Source, [string]$Destination)
    if (-not (Test-Path -LiteralPath $Source)) { return $false }

    # MDE Live Response's PS 5.1 host fails to bind `Split-Path -LiteralPath ... -Parent`
    # (AmbiguousParameterSet). Use the .NET API instead.
    $destDir = [System.IO.Path]::GetDirectoryName($Destination)
    if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
        try { New-Item -ItemType Directory -Path $destDir -Force -ErrorAction Stop | Out-Null }
        catch {
            Write-Log "mkdir failed: $destDir : $($_.Exception.Message)" 'WARN'
            return $false
        }
    }

    # First try Copy-Item. Works for the vast majority of Chromium files,
    # including History/Cookies/Web Data when the browser holds them with
    # FileShare.ReadWrite (the default for Chromium SQLite databases).
    $copyErr = $null
    try {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
        return $true
    }
    catch {
        $copyErr = $_.Exception.Message
    }

    # Fallback: explicit shared read FileStream copy. Use New-Object to
    # avoid static method overload resolution quirks in restricted hosts.
    $src = $null
    $dst = $null
    try {
        $src = New-Object System.IO.FileStream -ArgumentList @(
            $Source,
            ([System.IO.FileMode]::Open),
            ([System.IO.FileAccess]::Read),
            ([System.IO.FileShare]::ReadWrite)
        )
        $dst = New-Object System.IO.FileStream -ArgumentList @(
            $Destination,
            ([System.IO.FileMode]::Create),
            ([System.IO.FileAccess]::Write),
            ([System.IO.FileShare]::None)
        )
        $src.CopyTo($dst)
        return $true
    }
    catch {
        Write-Log "Copy failed: $Source to $Destination : Copy-Item=$copyErr; FileStream=$($_.Exception.Message)" 'WARN'
        return $false
    }
    finally {
        if ($dst) { $dst.Dispose() }
        if ($src) { $src.Dispose() }
    }
}

function Copy-Tree {
    param([string]$Source, [string]$Destination)
    if (-not (Test-Path -LiteralPath $Source)) { return }
    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }
    Get-ChildItem -LiteralPath $Source -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $rel = $_.FullName.Substring($Source.Length).TrimStart('\')
        $target = Join-Path $Destination $rel
        if ($_.PSIsContainer) {
            if (-not (Test-Path -LiteralPath $target)) {
                New-Item -ItemType Directory -Path $target -Force | Out-Null
            }
        }
        else {
            [void](Copy-FileShared -Source $_.FullName -Destination $target)
        }
    }
}

function Get-BrowserProfiles {
    param([string]$UserDataRoot)
    if (-not (Test-Path -LiteralPath $UserDataRoot)) { return @() }
    Get-ChildItem -LiteralPath $UserDataRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -eq 'Default' -or
            $_.Name -like 'Profile *' -or
            $_.Name -eq 'Guest Profile' -or
            $_.Name -like 'System Profile'
        }
}

# Per profile artifact map. Key is the destination subfolder, value is the
# list of file names to copy from the profile folder. Empty arrays mean the
# whole named folder is handled separately below.
$profileArtifacts = @{
    'history'   = @('History','History-journal','History-wal','Top Sites','Top Sites-journal','Top Sites-wal','Visited Links','Favicons','Favicons-journal','Favicons-wal')
    'cookies'   = @('Cookies','Cookies-journal','Cookies-wal')
    'logins'    = @('Login Data','Login Data-journal','Login Data-wal','Login Data For Account','Web Data','Web Data-journal','Web Data-wal','Shortcuts','Shortcuts-journal','Shortcuts-wal')
    'prefs'     = @('Preferences','Secure Preferences')
    'bookmarks' = @('Bookmarks','Bookmarks.bak')
}

# Cache_Data\index plus the four small inline data files preserve URL
# evidence after "Clear browsing data". The large f_* body files are skipped.
function Copy-CacheArtifacts {
    param([System.IO.DirectoryInfo]$ProfileDir, [string]$Dest)
    $cacheData = Join-Path $ProfileDir.FullName 'Cache\Cache_Data'
    if (Test-Path -LiteralPath $cacheData) {
        $cdDest = Join-Path $Dest 'cache\Cache_Data'
        foreach ($name in @('index','data_0','data_1','data_2','data_3')) {
            $src = Join-Path $cacheData $name
            if (Test-Path -LiteralPath $src) {
                [void](Copy-FileShared -Source $src -Destination (Join-Path $cdDest $name))
            }
        }
    }
    $codeCacheJs = Join-Path $ProfileDir.FullName 'Code Cache\Js\index-dir\the-real-index'
    if (Test-Path -LiteralPath $codeCacheJs) {
        [void](Copy-FileShared -Source $codeCacheJs -Destination (Join-Path $Dest 'cache\code_cache_js_index'))
    }
}

# Raw byte regex scan over a SQLite db (and its journal/wal) to recover URL
# fragments from free pages after the user has cleared browsing data. Treats
# bytes as ISO-8859-1 so every byte maps 1:1 to a char and regex sees the
# raw stream.
function Get-RecoverableUrl {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
    } catch {
        Write-Log "Could not read $Path for recoverable scan: $($_.Exception.Message)" 'WARN'
        return @()
    }
    $enc  = [System.Text.Encoding]::GetEncoding(28591)
    $text = $enc.GetString($bytes)
    $rx   = [regex]'https?://[A-Za-z0-9._~:/?#\[\]@!$&''()*+,;=%-]{4,2048}'
    $set  = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($m in $rx.Matches($text)) { [void]$set.Add($m.Value) }
    return $set
}

function Collect-Profile {
    param(
        [string]$BrowserLabel,
        [string]$UserName,
        [System.IO.DirectoryInfo]$ProfileDir,
        [string]$StageRoot
    )
    $profName = $ProfileDir.Name
    $dest = Join-Path $StageRoot (Join-Path $BrowserLabel (Join-Path $UserName $profName))
    Write-Log "$BrowserLabel | $UserName | $profName"

    foreach ($cat in $profileArtifacts.Keys) {
        $catDest = Join-Path $dest $cat
        foreach ($f in $profileArtifacts[$cat]) {
            $src = Join-Path $ProfileDir.FullName $f
            if (Test-Path -LiteralPath $src) {
                [void](Copy-FileShared -Source $src -Destination (Join-Path $catDest $f))
            }
        }
    }

    $sess = Join-Path $ProfileDir.FullName 'Sessions'
    if (Test-Path -LiteralPath $sess) {
        Copy-Tree -Source $sess -Destination (Join-Path $dest 'sessions')
    }

    Copy-CacheArtifacts -ProfileDir $ProfileDir -Dest $dest

    $net = Join-Path $ProfileDir.FullName 'Network'
    if (Test-Path -LiteralPath $net) {
        Copy-Tree -Source $net -Destination (Join-Path $dest 'network')
    }

    $extRoot = Join-Path $ProfileDir.FullName 'Extensions'
    if (Test-Path -LiteralPath $extRoot) {
        $extDest = Join-Path $dest 'extensions'
        New-Item -ItemType Directory -Path $extDest -Force | Out-Null
        Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $extId = $_.Name
            Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $ver = $_.Name
                $manifest = Join-Path $_.FullName 'manifest.json'
                if (Test-Path -LiteralPath $manifest) {
                    $safeId  = ($extId  -replace '[^A-Za-z0-9_.-]','_')
                    $safeVer = ($ver    -replace '[^A-Za-z0-9_.-]','_')
                    $target  = Join-Path $extDest ("${safeId}_${safeVer}_manifest.json")
                    [void](Copy-FileShared -Source $manifest -Destination $target)
                }
            }
        }
    }

    return $dest
}

# Begin
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$summary = Join-Path $stage '_summary'
New-Item -ItemType Directory -Path $summary -Force | Out-Null
$logPath = Join-Path $summary 'collection.log'

Write-Log "Host: $hostName"
Write-Log "Stage: $stage"
Write-Log "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "StopBrowsers: $StopBrowsers"

if ($StopBrowsers) {
    Write-Log "StopBrowsers specified, killing chrome.exe and msedge.exe"
    foreach ($p in 'chrome','msedge') {
        Get-Process -Name $p -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_.Kill(); Write-Log "Killed $($_.ProcessName) PID $($_.Id)" }
            catch { Write-Log "Kill failed for $($_.ProcessName) PID $($_.Id) : $($_.Exception.Message)" 'WARN' }
        }
    }
    Start-Sleep -Seconds 3
}

# Running browser processes
Get-Process -Name chrome,msedge -ErrorAction SilentlyContinue |
    Select-Object Id, ProcessName, StartTime, Path |
    Export-Csv -LiteralPath (Join-Path $summary 'processes.csv') -NoTypeInformation -Encoding UTF8

# Installed browser versions
$browsers = @()
$chromeExe = @(
    'C:\Program Files\Google\Chrome\Application\chrome.exe',
    'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$edgeExe = @(
    'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
foreach ($exe in @($chromeExe, $edgeExe)) {
    if ($exe) {
        $v = (Get-Item -LiteralPath $exe).VersionInfo.FileVersion
        $browsers += "$exe = $v"
    }
}
$browsers | Set-Content -LiteralPath (Join-Path $summary 'installed_browsers.txt') -Encoding UTF8

# Policy keys
$polDir = Join-Path $summary 'policies'
New-Item -ItemType Directory -Path $polDir -Force | Out-Null
$policyKeys = @(
    @{ Name='chrome_policies'; Key='HKLM\SOFTWARE\Policies\Google\Chrome' },
    @{ Name='edge_policies';   Key='HKLM\SOFTWARE\Policies\Microsoft\Edge' }
)
foreach ($k in $policyKeys) {
    $reg = Join-Path $polDir "$($k.Name).reg"
    & reg.exe EXPORT $k.Key $reg /y 2>$null | Out-Null
}

# Enumerate users
$skipUsers = @('Default','Default User','Public','All Users','WDAGUtilityAccount','defaultuser0','defaultuser100000')
$collectedProfiles = New-Object System.Collections.Generic.List[object]

Get-ChildItem -LiteralPath 'C:\Users' -Directory -ErrorAction SilentlyContinue |
    Where-Object { $skipUsers -notcontains $_.Name } | ForEach-Object {

    $userName  = $_.Name
    $userRoot  = $_.FullName
    $chromeUDR = Join-Path $userRoot 'AppData\Local\Google\Chrome\User Data'
    $edgeUDR   = Join-Path $userRoot 'AppData\Local\Microsoft\Edge\User Data'

    foreach ($p in Get-BrowserProfiles -UserDataRoot $chromeUDR) {
        $dest = Collect-Profile -BrowserLabel 'Chrome' -UserName $userName -ProfileDir $p -StageRoot $stage
        $collectedProfiles.Add([pscustomobject]@{ Browser='Chrome'; User=$userName; Profile=$p.Name; Path=$dest })
    }
    $cls = Join-Path $chromeUDR 'Local State'
    if (Test-Path -LiteralPath $cls) {
        $lsDest = Join-Path $stage (Join-Path 'Chrome' (Join-Path $userName '_user_LocalState'))
        [void](Copy-FileShared -Source $cls -Destination $lsDest)
    }
    $cdbg = Join-Path $chromeUDR 'chrome_debug.log'
    if (Test-Path -LiteralPath $cdbg) {
        $dbgDest = Join-Path $stage (Join-Path 'Chrome' (Join-Path $userName 'debug_logs\chrome_debug.log'))
        [void](Copy-FileShared -Source $cdbg -Destination $dbgDest)
    }

    foreach ($p in Get-BrowserProfiles -UserDataRoot $edgeUDR) {
        $dest = Collect-Profile -BrowserLabel 'Edge' -UserName $userName -ProfileDir $p -StageRoot $stage
        $collectedProfiles.Add([pscustomobject]@{ Browser='Edge'; User=$userName; Profile=$p.Name; Path=$dest })
    }
    $els = Join-Path $edgeUDR 'Local State'
    if (Test-Path -LiteralPath $els) {
        $lsDest = Join-Path $stage (Join-Path 'Edge' (Join-Path $userName '_user_LocalState'))
        [void](Copy-FileShared -Source $els -Destination $lsDest)
    }
    $edbg = Join-Path $edgeUDR 'edge_debug.log'
    if (Test-Path -LiteralPath $edbg) {
        $dbgDest = Join-Path $stage (Join-Path 'Edge' (Join-Path $userName 'debug_logs\edge_debug.log'))
        [void](Copy-FileShared -Source $edbg -Destination $dbgDest)
    }
}

Write-Log "Collected $($collectedProfiles.Count) profile(s)"
$collectedProfiles | Export-Csv -LiteralPath (Join-Path $summary 'profiles_collected.csv') -NoTypeInformation -Encoding UTF8

# Find sqlite3.exe
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$sqliteCandidates = @(
    (Join-Path $scriptDir 'sqlite3.exe'),
    'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\sqlite3.exe',
    'C:\Windows\System32\sqlite3.exe'
)
$sqlite = $sqliteCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

function Invoke-SqliteToCsv {
    param(
        [string]$SqliteExe,
        [string]$DbFile,
        [string]$Sql,
        [string]$Label
    )
    $tmpDb = "$DbFile.copy"
    try {
        Copy-Item -LiteralPath $DbFile -Destination $tmpDb -Force -ErrorAction Stop
    }
    catch {
        Write-Log "Could not stage db copy for $DbFile : $($_.Exception.Message)" 'WARN'
        return
    }
    try {
        # PowerShell 5.1 mangles native command stdin pipes: it prepends a UTF-8
        # BOM and collapses newlines. Bypass the pipe and write raw UTF-8 (no
        # BOM) bytes directly to sqlite3's stdin via System.Diagnostics.Process.
        # StandardInputEncoding is .NET Core only, so we write to BaseStream.
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName               = $SqliteExe
        $psi.Arguments              = "`"$tmpDb`""
        $psi.RedirectStandardInput  = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.UseShellExecute        = $false
        $psi.CreateNoWindow         = $true

        $proc     = [System.Diagnostics.Process]::Start($psi)
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        $bytes     = $utf8NoBom.GetBytes($Sql)
        $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $proc.StandardInput.BaseStream.Flush()
        $proc.StandardInput.Close()

        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()

        if ($proc.ExitCode -ne 0) {
            foreach ($line in ($stderr -split "`r?`n" | Where-Object { $_ })) {
                Write-Log "sqlite($Label): $line" 'WARN'
            }
            foreach ($line in ($stdout -split "`r?`n" | Where-Object { $_ })) {
                Write-Log "sqlite($Label): $line" 'WARN'
            }
        }
    }
    catch {
        Write-Log "sqlite invocation failed for $Label : $($_.Exception.Message)" 'WARN'
    }
    finally {
        Remove-Item -LiteralPath $tmpDb -Force -ErrorAction SilentlyContinue
    }
}

if ($sqlite) {
    Write-Log "Using sqlite3.exe at $sqlite"
    $parsedRoot = Join-Path $stage 'Parsed'
    New-Item -ItemType Directory -Path $parsedRoot -Force | Out-Null

    foreach ($prof in $collectedProfiles) {
        $base   = $prof.Path
        $tag    = "{0}_{1}" -f $prof.User, ($prof.Profile -replace '\s','_')
        $outDir = Join-Path $parsedRoot $prof.Browser
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null

        # History and downloads
        $hist = Join-Path $base 'history\History'
        if (Test-Path -LiteralPath $hist) {
            $csvHist = (Join-Path $outDir ("${tag}_history.csv"))      -replace '\\','/'
            $csvDl   = (Join-Path $outDir ("${tag}_downloads.csv"))    -replace '\\','/'
            $csvVis  = (Join-Path $outDir ("${tag}_visits.csv"))       -replace '\\','/'
            $sql = @"
.mode csv
.headers on
.output "$csvHist"
SELECT u.url, u.title, u.visit_count, u.typed_count,
       datetime((u.last_visit_time/1000000)-11644473600,'unixepoch') AS last_visit_utc,
       u.hidden
FROM urls u
ORDER BY u.last_visit_time DESC;
.output "$csvVis"
SELECT u.url, u.title,
       datetime((v.visit_time/1000000)-11644473600,'unixepoch') AS visit_utc,
       v.visit_duration, v.transition, v.from_visit
FROM visits v JOIN urls u ON v.url = u.id
ORDER BY v.visit_time DESC;
.output "$csvDl"
SELECT d.target_path, d.tab_url, d.referrer, d.mime_type, d.total_bytes,
       datetime((d.start_time/1000000)-11644473600,'unixepoch') AS start_utc,
       datetime((d.end_time/1000000)-11644473600,'unixepoch') AS end_utc,
       d.state, d.danger_type
FROM downloads d
ORDER BY d.start_time DESC;
.quit
"@
            Invoke-SqliteToCsv -SqliteExe $sqlite -DbFile $hist -Sql $sql -Label "history-$tag"
        }

        # Cookies (metadata only)
        $cook = Join-Path $base 'cookies\Cookies'
        if (Test-Path -LiteralPath $cook) {
            $csvC = (Join-Path $outDir ("${tag}_cookies.csv")) -replace '\\','/'
            $sql = @"
.mode csv
.headers on
.output "$csvC"
SELECT host_key, name, path,
       datetime((expires_utc/1000000)-11644473600,'unixepoch') AS expires_utc,
       is_secure, is_httponly, samesite, source_scheme
FROM cookies
ORDER BY host_key;
.quit
"@
            Invoke-SqliteToCsv -SqliteExe $sqlite -DbFile $cook -Sql $sql -Label "cookies-$tag"
        }

        # Logins (metadata only)
        $log = Join-Path $base 'logins\Login Data'
        if (Test-Path -LiteralPath $log) {
            $csvL = (Join-Path $outDir ("${tag}_logins.csv")) -replace '\\','/'
            $sql = @"
.mode csv
.headers on
.output "$csvL"
SELECT origin_url, username_value,
       datetime((date_created/1000000)-11644473600,'unixepoch') AS date_created_utc,
       datetime((date_last_used/1000000)-11644473600,'unixepoch') AS date_last_used_utc,
       times_used
FROM logins
ORDER BY date_last_used DESC;
.quit
"@
            Invoke-SqliteToCsv -SqliteExe $sqlite -DbFile $log -Sql $sql -Label "logins-$tag"
        }

        if ($IncludeRecoverable) {
            $sources = @(
                @{ File = 'history\History';         Tag = 'History' },
                @{ File = 'history\History-journal'; Tag = 'History-journal' },
                @{ File = 'history\History-wal';     Tag = 'History-wal' },
                @{ File = 'cookies\Cookies';         Tag = 'Cookies' },
                @{ File = 'cookies\Cookies-journal'; Tag = 'Cookies-journal' },
                @{ File = 'cookies\Cookies-wal';     Tag = 'Cookies-wal' }
            )
            $rows = New-Object 'System.Collections.Generic.List[object]'
            foreach ($s in $sources) {
                $fp = Join-Path $base $s.File
                if (-not (Test-Path -LiteralPath $fp)) { continue }
                $urls = Get-RecoverableUrl -Path $fp
                foreach ($u in $urls) {
                    $rows.Add([pscustomobject]@{ Source = $s.Tag; Url = $u })
                }
            }
            $cdIndex = Join-Path $base 'cache\Cache_Data\index'
            foreach ($cacheFile in @('index','data_0','data_1','data_2','data_3')) {
                $cf = Join-Path $base "cache\Cache_Data\$cacheFile"
                if (-not (Test-Path -LiteralPath $cf)) { continue }
                $urls = Get-RecoverableUrl -Path $cf
                foreach ($u in $urls) {
                    $rows.Add([pscustomobject]@{ Source = "Cache_$cacheFile"; Url = $u })
                }
            }
            if ($rows.Count -gt 0) {
                $rows |
                    Sort-Object Url -Unique |
                    Export-Csv -LiteralPath (Join-Path $outDir ("${tag}_recoverable_urls.csv")) -NoTypeInformation -Encoding UTF8
                Write-Log "Recoverable URLs ($tag): $($rows.Count) hits across $($sources.Count + 5) candidate files"
            }
        }
    }
}
else {
    Write-Log "sqlite3.exe not found. Skipping CSV parsing. Drop sqlite3.exe next to the script in the Live Response library to enable Parsed\ output." 'WARN'
}

# Zip
if (-not $NoZip) {
    $zipPath = "$stage.zip"
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $stage, $zipPath,
            [System.IO.Compression.CompressionLevel]::Optimal, $false
        )
        Write-Log "Zip created: $zipPath"
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host ""
        Write-Host "ZIP_PATH=$zipPath"
    }
    catch {
        Write-Log "Zip creation failed: $($_.Exception.Message)" 'ERROR'
        Write-Host "STAGE_PATH=$stage"
    }
}
else {
    Write-Host "STAGE_PATH=$stage"
}
