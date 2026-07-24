<#
.SYNOPSIS
    Lights up EVERY tab in the Enhanced Monitoring Workbook by emitting
    targeted telemetry from a managed lab endpoint. Replaces the older
    New-EnhancedMonitoringTelemetry.ps1 (kept for reference).

.DESCRIPTION
    Run on the lab device "324-um-defcon30" (any host whose name starts with
    "324"). The script:
      - Drops files containing INTO_TOP_SECRET / INTO_SECRET / INTO_FOUO /
        INTO_LES / Arabic / Chinese / Russian SIT keywords
      - Performs every monitored ACTION on those files (print, USB copy,
        OneDrive upload) so DLP raises one event per (file × action)
      - Sends outbound mail with attachments to a non-gov external recipient
        AND to "DomainList" news domains (cnn.com etc.) so Email DLP fires
      - Sends a "Downdraft file" subject mail
      - Sends mail from a privileged "adm-" / admin sender so ML2 lights up
      - Browses threat-country (.ir/.cn/.ru...) and PRC consultancy URLs via
        msedge.exe so DeviceNetworkEvents shows real user-attributed browsing
      - Uploads to monitored "new services" (wetransfer / file.io / box) so
        NTU tabs fire
      - If Adobe Acrobat Reader 2020 is installed, does the Acrobat
        masquerade (copy AcroRd32.exe out of its folder + invoke with a .dll
        argument) so the "ML1 - Adobe Reader creates DLL or EXE" tab fires

    Uses Microsoft.Graph for mail send. Auth: device-code or interactive.

.PARAMETER Loops
    Repeat each action N times for amplitude. Default = 3. Set high if you
    want to test severity tiers (Red/Yellow/Green).

.PARAMETER ExternalRecipient
    Non-gov external mailbox. Defaults to tiffanylo1983@outlook.com.

.PARAMETER InternalRecipients
    Internal recipients copied on every test message.

.PARAMETER PrivilegedSenders
    Privileged "admin"/"adm-" UPN(s) used for ML2 - Privileged Users tab. Round-robin per loop iteration.

.PARAMETER NormalSenders
    Standard user UPN(s) used for non-privileged email tests. Round-robin per loop iteration.

.PARAMETER UsersCsv
    Optional CSV (output of New-LabUsers.ps1) with columns UPN,Privileged.
    If present, overrides PrivilegedSenders/NormalSenders.

.PARAMETER PrinterName
    Printer to use. Use "auto" to pick the first physical printer.
    Use "skip" to skip print events.

.PARAMETER UsbDrive
    Removable drive letter (e.g. "E:"). Use "auto" to pick the first removable
    drive. Use "skip" to skip USB events.

.PARAMETER Tabs
    Comma-separated list to scope which tabs to drive. Default = "all".
    Choices: Spills, FOUO, LES, LangID, NTU, Print, USB, EmailNonGov,
             EmailNews, Downdraft, ThreatCountry, PRC, AdobeMasq, Privileged

.PARAMETER NoEmail
    Skip ALL email sends (useful when running offline or no Graph consent).

.PARAMETER WaitBetweenLoopsSec
    Sleep between loops to spread events over time. Default = 1.

.EXAMPLE
    .\Invoke-EnhancedLabTelemetry.ps1

.EXAMPLE
    .\Invoke-EnhancedLabTelemetry.ps1 -Loops 10 -PrinterName auto -UsbDrive auto

.EXAMPLE
    .\Invoke-EnhancedLabTelemetry.ps1 -Tabs Spills,FOUO,LES,EmailNonGov -Loops 5
#>
[CmdletBinding()]
param(
    [int]    $Loops              = 3,
    [string] $ExternalRecipient  = "tiffanylo1983@outlook.com",
    [string[]]$InternalRecipients = @(
        "ElliottAlderson@MngEnvMCAP709711.onmicrosoft.com"
    ),
    # Privileged Users tab requires SenderFromAddress / UserId to literally contain 'adm-'
    [string[]]$PrivilegedSenders  = @("adm-ElliottAlderson@MngEnvMCAP709711.onmicrosoft.com"),
    [string[]]$NormalSenders      = @("ElliottAlderson@MngEnvMCAP709711.onmicrosoft.com"),
    [string]  $UsersCsv           = (Join-Path $PSScriptRoot "LabUsers-Credentials.csv"),
    [string] $PrinterName        = "auto",
    [string] $UsbDrive           = "auto",
    [string[]]$Tabs              = @("all"),
    [switch] $NoEmail,
    [int]    $WaitBetweenLoopsSec = 1
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ---------- helpers ---------------------------------------------------------
function Step  { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function OK    { param($m) Write-Host "  [ok]    $m" -ForegroundColor Green }
function Skip_ { param($m) Write-Host "  [skip]  $m" -ForegroundColor DarkGray }
function Fail  { param($m) Write-Host "  [fail]  $m" -ForegroundColor Red }
function Info  { param($m) Write-Host "  [info]  $m" -ForegroundColor Yellow }

function ShouldRun([string]$tabKey) {
    if ($Tabs -contains "all") { return $true }
    return $Tabs -contains $tabKey
}

# ---------- load users from CSV if present ---------------------------------
if ($UsersCsv -and (Test-Path $UsersCsv)) {
    try {
        $rows = Import-Csv -Path $UsersCsv
        $loadedNormal = @($rows | Where-Object { $_.Privileged -ieq 'False' } | Select-Object -ExpandProperty UPN)
        $loadedPriv   = @($rows | Where-Object { $_.Privileged -ieq 'True'  } | Select-Object -ExpandProperty UPN)
        if ($loadedNormal.Count -gt 0) { $NormalSenders     = $loadedNormal }
        if ($loadedPriv.Count   -gt 0) { $PrivilegedSenders = $loadedPriv }
        Info "Loaded $($NormalSenders.Count) normal + $($PrivilegedSenders.Count) privileged senders from $UsersCsv"
    } catch { Info "Could not parse $UsersCsv : $($_.Exception.Message)" }
}

function Pick-Normal { param([int]$i) $NormalSenders[$i % $NormalSenders.Count] }
function Pick-Priv   { param([int]$i) $PrivilegedSenders[$i % $PrivilegedSenders.Count] }

# ---------- preflight -------------------------------------------------------
Step "Preflight"
if ($env:COMPUTERNAME -notmatch '^324') {
    Info "Hostname '$env:COMPUTERNAME' does not start with '324'. Workbook tabs filter on DeviceName startswith '324' - events will be ingested but the workbook will hide them."
}

$TestDir = Join-Path $env:USERPROFILE "Desktop\EnhancedLab"
New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
OK "Working dir: $TestDir"

# Auto-detect OneDrive
$OneDrivePath = $env:OneDrive
if (-not $OneDrivePath -or -not (Test-Path $OneDrivePath)) {
    $cand = Get-ChildItem $env:USERPROFILE -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'OneDrive*' } | Select-Object -First 1
    if ($cand) { $OneDrivePath = $cand.FullName }
}
if ($OneDrivePath) { OK "OneDrive: $OneDrivePath" } else { Skip_ "OneDrive not detected" }

# Auto-detect printer
# IMPORTANT: workbook query excludes ALL these names. Match by -like so
# 'OneNote (Desktop)', 'OneNote for Windows 10', 'Send To OneNote 2016' all skip.
$excludedPrinterPatterns = @(
    'Microsoft Print to PDF','Adobe PDF','Fax','*OneNote*','Microsoft XPS Document Writer','*Send To OneNote*'
)
if ($PrinterName -eq "auto") {
    $PrinterName = (Get-Printer -ErrorAction SilentlyContinue | Where-Object {
            $n = $_.Name
            -not ($excludedPrinterPatterns | Where-Object { $n -like $_ })
        } | Select-Object -First 1 -ExpandProperty Name)
    if (-not $PrinterName) {
        Info "No physical printer. Installing Generic / Text Only -> NUL: as 'LabTextPrinter'"
        try {
            if (-not (Get-Printer -Name 'LabTextPrinter' -ErrorAction SilentlyContinue)) {
                if (-not (Get-PrinterPort -Name 'LabNul' -ErrorAction SilentlyContinue)) {
                    Add-PrinterPort -Name 'LabNul' -ErrorAction Stop
                }
                Add-Printer -Name 'LabTextPrinter' -DriverName 'Generic / Text Only' -PortName 'LabNul' -ErrorAction Stop
            }
            $PrinterName = 'LabTextPrinter'
            OK "Installed fallback printer: $PrinterName"
        } catch {
            $PrinterName = "skip"
            Skip_ "Could not install fallback printer ($($_.Exception.Message)); print events skipped"
        }
    }
}
if ($PrinterName -ne "skip") { OK "Printer: $PrinterName" }

# Auto-detect USB
if ($UsbDrive -eq "auto") {
    $r = Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue |
         Where-Object { $_.DriveType -eq 2 -and $_.Size -gt 0 } | Select-Object -First 1
    if ($r) { $UsbDrive = $r.DeviceID } else { $UsbDrive = "skip" ; Skip_ "No removable drive found; USB events skipped" }
}
if ($UsbDrive -ne "skip") { OK "USB drive: $UsbDrive" }

# Locate msedge.exe for user-attributed browsing
$Edge = @(
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($Edge) { OK "Edge: $Edge" } else { Skip_ "msedge.exe not found; web events will use Invoke-WebRequest under powershell.exe (still surfaces in DeviceNetworkEvents)" }

# ---------- 1. Build SIT-tickling files ------------------------------------
Step "Building SIT-tickling files"
$files = @(
    @{ Name="LAB_INTO_TOP_SECRET_$([guid]::NewGuid().Guid.Substring(0,8)).docx"; Body="TEST-INTO-TOPSECRET INTO_TOP_SECRET TopSecretClassified.`r`nTEST-INTO-TOPSECRET TEST-INTO-TOPSECRET TEST-INTO-TOPSECRET" }
    @{ Name="LAB_INTO_SECRET_$([guid]::NewGuid().Guid.Substring(0,8)).docx";    Body="TEST-INTO-SECRET INTO_SECRET SecretClassified.`r`nTEST-INTO-SECRET TEST-INTO-SECRET TEST-INTO-SECRET" }
    @{ Name="LAB_INTO_FOUO_$([guid]::NewGuid().Guid.Substring(0,8)).docx";      Body="TEST-INTO-FOUO INTO_FOUO For Official Use Only.`r`nTEST-INTO-FOUO TEST-INTO-FOUO TEST-INTO-FOUO" }
    @{ Name="LAB_INTO_LES_$([guid]::NewGuid().Guid.Substring(0,8)).docx";       Body="TEST-INTO-LES INTO_LES Law Enforcement Sensitive.`r`nTEST-INTO-LES TEST-INTO-LES TEST-INTO-LES" }
    @{ Name="LAB_LangID_Arabic_$([guid]::NewGuid().Guid.Substring(0,8)).txt";   Body=(-join (0x645,0x631,0x62D,0x628,0x627,0x20,0x628,0x627,0x644,0x639,0x627,0x644,0x645 | ForEach-Object {[char]$_})) + " test test test test test" }
    @{ Name="LAB_LangID_Chinese_$([guid]::NewGuid().Guid.Substring(0,8)).txt";  Body=(-join (0x4F60,0x597D,0x4E16,0x754C,0x20,0x6D4B,0x8BD5 | ForEach-Object {[char]$_})) + " test test test test test" }
    @{ Name="LAB_LangID_Russian_$([guid]::NewGuid().Guid.Substring(0,8)).txt";  Body=(-join (0x41F,0x440,0x438,0x432,0x435,0x442,0x20,0x43C,0x438,0x440 | ForEach-Object {[char]$_})) + " test test test test test" }
)

# Write each file with multiple keyword instances for higher SIT confidence
$createdFiles = @()
foreach ($f in $files) {
    $path = Join-Path $TestDir $f.Name
    $body = ($f.Body + "`r`n") * 5  # repeat to push SIT confidence
    [System.IO.File]::WriteAllText($path, $body, [System.Text.UTF8Encoding]::new($false))
    $createdFiles += $path
    OK "Wrote $(Split-Path $path -Leaf)"
}

# ---------- 2. OneDrive (FileUploadedToCloud + DLP scan) -------------------
if (ShouldRun "Spills" -or (ShouldRun "FOUO") -or (ShouldRun "LES") -or (ShouldRun "LangID") -or (ShouldRun "NTU")) {
    Step "OneDrive copy (lights up Spills / FOUO / LES / LangID / NTU)"
    if ($OneDrivePath) {
        $dst = Join-Path $OneDrivePath "EnhancedLab"
        New-Item -ItemType Directory -Path $dst -Force | Out-Null
        for ($i = 1; $i -le $Loops; $i++) {
            foreach ($src in $createdFiles) {
                $name = (Split-Path $src -Leaf) -replace '\.', "_loop${i}."
                Copy-Item -LiteralPath $src -Destination (Join-Path $dst $name) -Force
            }
            OK "Loop ${i}: copied $($createdFiles.Count) files to OneDrive"
            Start-Sleep -Seconds $WaitBetweenLoopsSec
        }
        Info "OneDrive client syncs in background; DLP fires on upload."
    } else { Skip_ "No OneDrive path" }
}

# ---------- 3. Print (FilePrinted + DLP) -----------------------------------
if (ShouldRun "Print" -and $PrinterName -ne "skip") {
    Step "Print (lights up Print Egress / Spills / FOUO / LES / Privileged)"
    for ($i = 1; $i -le $Loops; $i++) {
        foreach ($src in $createdFiles | Where-Object { $_ -notmatch 'LangID' }) {
            try {
                Start-Process -FilePath $src -Verb PrintTo -ArgumentList "`"$PrinterName`"" -WindowStyle Hidden -PassThru -ErrorAction Stop | Out-Null
                Start-Sleep -Milliseconds 500
            } catch { Fail "Print: $($_.Exception.Message)" }
        }
        OK "Loop ${i}: printed $($createdFiles.Count - 3) files"
    }
}

# ---------- 4. USB (FileCopiedToRemovableMedia + DLP) ----------------------
if (ShouldRun "USB" -and $UsbDrive -ne "skip") {
    Step "USB copy (lights up Removable Media Egress / Spills / FOUO / LES)"
    $usbDir = Join-Path $UsbDrive "EnhancedLab"
    New-Item -ItemType Directory -Path $usbDir -Force -ErrorAction SilentlyContinue | Out-Null
    for ($i = 1; $i -le $Loops; $i++) {
        foreach ($src in $createdFiles) {
            $name = (Split-Path $src -Leaf) -replace '\.', "_usb${i}."
            try { Copy-Item -LiteralPath $src -Destination (Join-Path $usbDir $name) -Force }
            catch { Fail "USB: $($_.Exception.Message)" }
        }
        OK "Loop ${i}: copied $($createdFiles.Count) files to USB"
    }
    # Add a Program (.exe-named) and Document (.pdf-named) for the count tabs
    "TEST-INTO-SECRET fake document" | Out-File (Join-Path $usbDir "LAB_USB_Doc.pdf") -Encoding utf8
    "TEST-INTO-SECRET fake program" | Out-File (Join-Path $usbDir "LAB_USB_Prog.exe") -Encoding utf8
    OK "Wrote LAB_USB_Doc.pdf + LAB_USB_Prog.exe to USB"
}

# Helper: launch URL via Edge (user-attributed). Falls back to Invoke-WebRequest.
function Open-Url {
    param([string]$Url, [int]$DwellMs = 4000)
    if ($Edge) {
        try {
            $p = Start-Process -FilePath $Edge -ArgumentList "--no-first-run --no-default-browser-check $Url" -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds $DwellMs
            $p | Stop-Process -Force -ErrorAction SilentlyContinue
            return "edge:${Url}"
        } catch {
            return "edge-fail:${Url}:$($_.Exception.Message)"
        }
    } else {
        try {
            $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10 -MaximumRedirection 3 -ErrorAction Stop
            return "iwr:${Url}:$($r.StatusCode)"
        } catch {
            return "iwr-fail:${Url}:$($_.Exception.Message.Split([Environment]::NewLine)[0])"
        }
    }
}

# ---------- 5. NTU - Monitored New Services / NonGov uploads ---------------
# NOTE: FileUploadedToCloud requires a real cloud-app upload that MCAS sees.
# Best route on a managed endpoint: drop classified files into the OneDrive
# sync folder (done in section 2). Browsing the marketing sites below adds
# DeviceNetworkEvents context that helps the NTU 'Monitored New Services'
# variant of the tab.
if (ShouldRun "NTU") {
    Step "NTU - browse monitored new services via Edge"
    $ntuTargets = @(
        "https://wetransfer.com",
        "https://file.io",
        "https://app.box.com",
        "https://www.dropbox.com",
        "https://gofile.io"
    )
    foreach ($loop in 1..$Loops) {
        foreach ($u in $ntuTargets) { OK "Loop $loop : $(Open-Url $u 3000)" }
    }
}

# ---------- 6. Threat country web browsing ---------------------------------
if (ShouldRun "ThreatCountry") {
    Step "Threat-country browsing via Edge (lights up Threat Country Web Browsing)"
    $tcUrls = @(
        "https://www.president.ir/",
        "https://www.kremlin.ru/",
        "https://www.gov.cn/",
        "https://www.belarus.by/",
        "https://moph.gov.sy/",
        "https://gov.ua/"
    )
    foreach ($loop in 1..$Loops) {
        foreach ($u in $tcUrls) { OK "Loop $loop : $(Open-Url $u 3000)" }
    }
}

# ---------- 7. PRC consultancy sites ---------------------------------------
if (ShouldRun "PRC") {
    Step "PRC consultancy sites via Edge (lights up PRC Sites)"
    $prcUrls = @(
        "https://centrikglobalconsulting.com",
        "https://catalystglobalsolutions.com",
        "https://horizoninfoconsult.com",
        "https://policychannel.com"
    )
    foreach ($loop in 1..$Loops) {
        foreach ($u in $prcUrls) { OK "Loop $loop : $(Open-Url $u 3000)" }
    }
}

# ---------- 8. Adobe Reader masquerade (DLL/EXE) ---------------------------
if (ShouldRun "AdobeMasq") {
    Step "Adobe Reader masquerade (lights up ML1 - Adobe Reader DLL/EXE)"
    $acro = Get-ChildItem "$env:ProgramFiles\Adobe","${env:ProgramFiles(x86)}\Adobe" -Recurse -Filter "AcroRd32.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $acro) {
        Skip_ "Adobe Acrobat Reader 2020 not installed; Adobe Reader DLL/EXE tab cannot be lit. Install it (or skip this tab)."
    } else {
        # Verify product name matches workbook's exact filter
        $productName = (Get-Item $acro.FullName).VersionInfo.ProductName
        if ($productName -ne 'Adobe Acrobat Reader 2020') {
            Skip_ "AcroRd32.exe ProductName='$productName' (workbook expects 'Adobe Acrobat Reader 2020'). Install Reader 2020 specifically."
        } else {
            $masqDir = Join-Path $env:TEMP "AdobeMasq"
            New-Item -ItemType Directory -Path $masqDir -Force | Out-Null
            $fake = Join-Path $masqDir "ReaderHelper.exe"
            Copy-Item $acro.FullName $fake -Force
            for ($i = 1; $i -le $Loops; $i++) {
                try {
                    # Run with a .dll arg so workbook's `command line has_any (.dll, .exe)` matches
                    $p = Start-Process -FilePath $fake -ArgumentList "stub_${i}.dll" -PassThru -WindowStyle Hidden -ErrorAction Stop
                    Start-Sleep -Seconds 2
                    $p | Stop-Process -Force -ErrorAction SilentlyContinue
                } catch { Fail "Adobe masq launch: $($_.Exception.Message)" }
            }
            OK "Spawned ReaderHelper.exe (Acrobat metadata) $Loops times with .dll arg"
        }
    }
}

# ---------- 9. Email - Forward Downdraft / NonGovMil / News / FOUO / LES ---
if ($NoEmail) { Skip_ "Email phase skipped (-NoEmail)" }
elseif (ShouldRun "EmailNonGov" -or (ShouldRun "Downdraft") -or (ShouldRun "EmailNews") -or (ShouldRun "FOUO") -or (ShouldRun "LES") -or (ShouldRun "LangID") -or (ShouldRun "Privileged")) {

    Step "Connecting to Microsoft Graph for Mail.Send"
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Mail)) {
        Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Mail -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module Microsoft.Graph.Authentication -Force
    Import-Module Microsoft.Graph.Mail -Force
    try { Connect-MgGraph -Scopes 'Mail.Send','Mail.Send.Shared' -NoWelcome -ErrorAction Stop ; OK "Connected" }
    catch { Fail "Connect-MgGraph: $($_.Exception.Message)" ; return }

    # Discover the signed-in user once; we'll send AS this account by default.
    # Sending as a different user (-From != signed-in account) requires Mail.Send.Shared
    # AND an Exchange "Send As" grant on the target mailbox. If those aren't in place,
    # we fall back to sending as the signed-in user so the Email tabs still populate.
    $script:GraphMe = (Get-MgContext).Account
    Info "Default send-as identity: $script:GraphMe"

    function Send-LabMail {
        param(
            [Parameter(Mandatory)] [string]$From,
            [Parameter(Mandatory)] [string[]]$To,
            [Parameter(Mandatory)] [string]$Subject,
            [Parameter(Mandatory)] [string]$Body,
            [string[]]$AttachmentPaths = @()
        )
        $att = @()
        foreach ($p in $AttachmentPaths) {
            if (-not (Test-Path $p)) { continue }
            $bytes = $null
            for ($try = 1; $try -le 5; $try++) {
                try {
                    $fs = [System.IO.File]::Open($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    $ms = New-Object System.IO.MemoryStream
                    $fs.CopyTo($ms); $fs.Dispose()
                    $bytes = $ms.ToArray(); $ms.Dispose()
                    break
                } catch {
                    if ($try -eq 5) { Fail "attachment read $p : $($_.Exception.Message)" ; break }
                    Start-Sleep -Milliseconds 600
                }
            }
            if (-not $bytes) { continue }
            $att += @{
                "@odata.type"  = "#microsoft.graph.fileAttachment"
                Name           = (Split-Path $p -Leaf)
                ContentType    = "text/plain"
                ContentBytes   = [Convert]::ToBase64String($bytes)
            }
        }
        $msg = @{
            Message = @{
                Subject       = $Subject
                Body          = @{ ContentType = "Text"; Content = $Body }
                ToRecipients  = @($To | ForEach-Object { @{ EmailAddress = @{ Address = $_ } } })
                Attachments   = $att
            }
            SaveToSentItems = $true
        }
        try {
            Send-MgUserMail -UserId $From -BodyParameter $msg -ErrorAction Stop
            OK "$From -> $($To -join ',') :: $Subject"
        } catch {
            $msgErr = $_.Exception.Message
            # If sending as $From was forbidden (no Send-As), the target mailbox is missing,
            # or Graph returned ErrorItemNotFound (typical when delegated Mail.Send can't act
            # on /users/{otherUpn}/sendMail), retry as the signed-in user via /me/sendMail.
            # /me/sendMail is the only endpoint delegated Mail.Send is guaranteed to allow.
            if ($From -ne $script:GraphMe -and ($msgErr -match 'ErrorAccessDenied|MailboxNotEnabledForRESTAPI|ErrorItemNotFound|NotFound|Forbidden|denied')) {
                try {
                    $jsonBody = $msg | ConvertTo-Json -Depth 10 -Compress
                    Invoke-MgGraphRequest -Method POST -Uri 'v1.0/me/sendMail' -Body $jsonBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
                    OK "$script:GraphMe (fallback /me/sendMail) -> $($To -join ',') :: $Subject  [original From=$From blocked]"
                } catch {
                    Fail "send '$Subject' (fallback /me/sendMail as $script:GraphMe also failed): $($_.Exception.Message)"
                }
            } else {
                Fail "send '$Subject': $msgErr"
            }
        }
    }

    $fouoAttach   = $createdFiles | Where-Object { $_ -match 'FOUO' }   | Select-Object -First 1
    $lesAttach    = $createdFiles | Where-Object { $_ -match 'LES' }    | Select-Object -First 1
    $arAttach     = $createdFiles | Where-Object { $_ -match 'Arabic' } | Select-Object -First 1
    $cnAttach     = $createdFiles | Where-Object { $_ -match 'Chinese' }| Select-Object -First 1
    $ruAttach     = $createdFiles | Where-Object { $_ -match 'Russian' }| Select-Object -First 1
    $tsAttach     = $createdFiles | Where-Object { $_ -match 'TOP_SECRET' } | Select-Object -First 1
    $secretAttach = $createdFiles | Where-Object { $_ -match '_SECRET' -and $_ -notmatch 'TOP' } | Select-Object -First 1

    for ($i = 1; $i -le $Loops; $i++) {
        # Forward Downdraft (subject keyword)
        if (ShouldRun "Downdraft") {
            Send-LabMail -From (Pick-Normal $i) -To $ExternalRecipient -Subject "Downdraft file - lab loop $i" -Body "Lab Forward Downdraft test $i."
        }

        # Plain NonGovMil
        if (ShouldRun "EmailNonGov") {
            Send-LabMail -From (Pick-Normal $i) -To $ExternalRecipient -Subject "Lab NonGovMil $i" -Body "Outbound to non-gov non-mil recipient. $i"
        }

        # Extension News Service - send to a fake mailbox at a DomainList domain
        if (ShouldRun "EmailNews") {
            $newsDomains = @("cnn.com","foxnews.com","nytimes.com","washingtonpost.com","reddit.com","wsj.com")
            $fake = "labtest+$([guid]::NewGuid().Guid.Substring(0,6))@$($newsDomains[$i % $newsDomains.Count])"
            Send-LabMail -From (Pick-Normal $i) -To $fake -Subject "Lab News Service $i" -Body "External news domain test $i"
        }

        # FOUO email (with FOUO attachment, outbound to non-gov, has attachment)
        if ((ShouldRun "FOUO") -and $fouoAttach) {
            Send-LabMail -From (Pick-Normal $i) -To $ExternalRecipient -Subject "Lab FOUO outbound $i" -Body "FOUO test attachment $i" -AttachmentPaths @($fouoAttach)
        }

        # LES email
        if ((ShouldRun "LES") -and $lesAttach) {
            Send-LabMail -From (Pick-Normal $i) -To $ExternalRecipient -Subject "Lab LES outbound $i" -Body "LES test attachment $i" -AttachmentPaths @($lesAttach)
        }

        # Language ID emails
        if ((ShouldRun "LangID")) {
            if ($arAttach) { Send-LabMail -From (Pick-Normal $i) -To $ExternalRecipient -Subject "Lab LangID Arabic $i" -Body "Arabic content test $i" -AttachmentPaths @($arAttach) }
            if ($cnAttach) { Send-LabMail -From (Pick-Normal $i) -To $ExternalRecipient -Subject "Lab LangID Chinese $i" -Body "Chinese content test $i" -AttachmentPaths @($cnAttach) }
            if ($ruAttach) { Send-LabMail -From (Pick-Normal $i) -To $ExternalRecipient -Subject "Lab LangID Russian $i" -Body "Russian content test $i" -AttachmentPaths @($ruAttach) }
        }

        # ML2 - Privileged Users (sender starts with adm-/admin)
        if (ShouldRun "Privileged") {
            Send-LabMail -From (Pick-Priv $i) -To $ExternalRecipient -Subject "Lab Priv NonGovMil $i" -Body "Privileged sender outbound $i"
        }

        # Spills via email (Top Secret + Secret attachments)
        if (ShouldRun "Spills") {
            if ($tsAttach)     { Send-LabMail -From (Pick-Normal $i) -To $ExternalRecipient -Subject "Lab TopSecret email $i" -Body "TS attach test $i"     -AttachmentPaths @($tsAttach) }
            if ($secretAttach) { Send-LabMail -From (Pick-Normal $i) -To $ExternalRecipient -Subject "Lab Secret email $i"    -Body "Secret attach test $i" -AttachmentPaths @($secretAttach) }
        }

        Start-Sleep -Seconds $WaitBetweenLoopsSec
    }

    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

Step "Done"
Write-Host "Wait 10-30 minutes for ingestion (Endpoint DLP can take longer)." -ForegroundColor Green
Write-Host "Then run Test-WorkbookTabHits.ps1 to verify which tabs lit up." -ForegroundColor Green
Write-Host ""
Write-Host "NOTE on 'ML2 - Privileged Users' tab:" -ForegroundColor Yellow
Write-Host "  Email path will fire if Mail.Send.Shared + Send-As grant exist for $($PrivilegedSenders -join ',')" -ForegroundColor Yellow
Write-Host "  Device path (CAE FileUploadedToCloud/FilePrinted/USB by adm-*) requires the" -ForegroundColor Yellow
Write-Host "  INTERACTIVE login on 324-UM-Defcon30 to be an adm-* UPN. Sign in as" -ForegroundColor Yellow
Write-Host "  adm-ElliottAlderson and re-run this script for those events to attribute correctly." -ForegroundColor Yellow
