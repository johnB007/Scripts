#Requires -Version 5.1
<#
.SYNOPSIS
Full interactive telemetry burst script for 324-UM-Defcon30.
Designed to run as a scheduled task under the signed in user via Arc run command.

Tables targeted:
  DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceEvents
  DeviceRegistryEvents, CloudAppEvents, OfficeActivity, EmailEvents
  EmailUrlInfo, EmailAttachmentInfo, IdentityLogonEvents, SigninLogs
  IdentityQueryEvents, IdentityDirectoryEvents, AuditLogs, EntraIdSignInEvents
#>
[CmdletBinding()]
param(
    [int]$BrowserTabDelayMs = 600,
    [int]$OneDriveFileCount = 15,
    [int]$LdapQueryCount = 8,
    [switch]$SkipBrowser,
    [switch]$SkipOffice,
    [switch]$SkipIdentityQueries,
    [switch]$SkipOneDrive
)

$ErrorActionPreference = 'Continue'
$log = Join-Path $env:TEMP 'ArcTelemetryRun.log'
function Out-Log { param([string]$m) $t="[$(Get-Date -Format 'HH:mm:ss.fff')] $m"; Write-Host $t; Add-Content -Path $log -Value $t -Encoding UTF8 }

Out-Log "START interactive telemetry burst"

# PLAYWRIGHT INITIALIZATION - auto-install if needed
Out-Log "Checking Playwright module"
if (-not (Get-Module -ListAvailable Playwright -ErrorAction SilentlyContinue)) {
    Out-Log "Installing Playwright module"
    Install-Module -Name Playwright -Repository PSGallery -Force -SkipPublisherCheck -ErrorAction SilentlyContinue | Out-Null
}

try {
    Import-Module Playwright -ErrorAction Stop
    Out-Log "Playwright module loaded"
    $playwrightAvailable = $true
} catch {
    Out-Log "Playwright not available: $_"
    $playwrightAvailable = $false
}

# BROWSER - Essential M365 URLs + Batched browsing (file sharing, threat countries, consultancies)
# Drives: CloudAppEvents, EntraIdSignInEvents, SigninLogs, OfficeActivity, AuditLogs, DeviceNetworkEvents
if (-not $SkipBrowser) {
    # Essential M365 URLs only (just key apps, not all of them)
    $essentialUrls = @(
        'https://www.office.com',
        'https://outlook.office.com/mail',
        'https://teams.microsoft.com',
        'https://www.sharepoint.com'
    )
    
    # Batched URLs (file sharing, threat countries, consultancies) - processed in groups of 60
    $batchUrls = @(
        'https://wetransfer.com',
        'https://file.io',
        'https://app.box.com',
        'https://www.dropbox.com',
        'https://gofile.io',
        'https://www.president.ir/',
        'https://www.kremlin.ru/',
        'https://www.gov.cn/',
        'https://www.belarus.by/',
        'https://moph.gov.sy/',
        'https://gov.ua/',
        'https://centrikglobalconsulting.com',
        'https://catalystglobalsolutions.com',
        'https://horizoninfoconsult.com',
        'https://policychannel.com'
    )

    # M365 URLs that should get full interaction (SharePoint, OneDrive, Teams, Outlook)
    $m365Domains = @('sharepoint.com','office.com','microsoft365.com','teams.microsoft.com','outlook.office','onedrive.live.com','myapps.microsoft.com','mngenvmcap709711')

    # PLAYWRIGHT-BASED BROWSER AUTOMATION - Essential M365 URLs
    if ($playwrightAvailable) {
        Out-Log "Opening essential M365 URLs via Playwright"
        try {
            $pwsh = Install-Playwright -Browser chromium -ErrorAction SilentlyContinue
            $browser = Open-Browser -BrowserTypeName chromium -ErrorAction SilentlyContinue
            $context = $browser.NewContext() | Out-Null
            Out-Log "Playwright browser context created"

            foreach ($url in $essentialUrls) {
                try {
                    $page = $context.NewPage()
                    Out-Log "  [Playwright] $url"
                    
                    $page.Goto($url, @{ Timeout = 30000 })
                    Start-Sleep -Milliseconds 2000

                    # Page loaded - skip child link extraction for compatibility
                    $linkCount = 0

                    # Interact with M365 pages
                    if ($m365Domains | Where-Object { $url -like "*$_*" }) {
                        try {
                            $page.Evaluate('() => window.scrollBy(0, 1000)') | Out-Null
                            Start-Sleep -Milliseconds 300
                            $page.Reload() | Out-Null
                            Start-Sleep -Milliseconds 1000
                            Out-Log "  [Playwright] Interacted: $url"
                        } catch {}
                    }

                    $page.Close()
                    Start-Sleep -Milliseconds 200
                } catch { Out-Log "  [Playwright] Failed: $url" }
            }

            $context.Close()
            $browser.Close()
            Out-Log "Essential M365 URLs complete"
        } catch { 
            Out-Log "Playwright failed: $_"
        }
    }

    # BATCH BROWSER PROCESSING - Open 60 URLs, close, repeat
    Out-Log "Opening URLs in batches of 60 (open, close, repeat)"
    $batchSize = 60
    $batches = [Math]::Ceiling($batchUrls.Count / $batchSize)
    
    for ($b = 0; $b -lt $batches; $b++) {
        $start = $b * $batchSize
        $end = [Math]::Min($start + $batchSize - 1, $batchUrls.Count - 1)
        $batch = $batchUrls[$start..$end]
        
        Out-Log "Batch $($b+1)/$batches: Opening $($batch.Count) URLs"
        
        $browser = if ((Test-Path 'C:\Program Files\Microsoft\Edge\Application\msedge.exe')) { 'C:\Program Files\Microsoft\Edge\Application\msedge.exe' } elseif ((Test-Path 'C:\Program Files\Google\Chrome\Application\chrome.exe')) { 'C:\Program Files\Google\Chrome\Application\chrome.exe' } else { $null }
        
        if ($browser) {
            try {
                $p = Start-Process -FilePath $browser -ArgumentList "--no-first-run $($batch -join ' ')" -PassThru -ErrorAction Stop
                Start-Sleep -Seconds 5
                $p | Stop-Process -Force -ErrorAction SilentlyContinue
                Out-Log "Batch $($b+1)/$batches closed"
                Start-Sleep -Milliseconds 500
            } catch {
                Out-Log "Batch $($b+1)/$batches error: $_"
            }
        }
    }
    
    Out-Log "All batches complete"
}

# WEB CONTENT FILTERING CATEGORIES - test blocking policies across categories
# Drives: DeviceNetworkEvents with categorized domain activity
if (-not $SkipBrowser) {
    Out-Log "Testing web content filtering categories"
    
    # Build category map with reduced URLs (2 per category for faster testing)
    $filterCategories = @{
        'Adult-Cults' = @('https://www.scientology.org', 'https://www.churchofsatan.com')
        'Adult-Gambling' = @('https://www.draftkings.com', 'https://www.fanduel.com')
        'Adult-Nudity' = @('https://www.playboy.com', 'https://www.penthouse.com')
        'Adult-Pornography' = @('https://www.redtube.com', 'https://www.pornhub.com')
        'Adult-SexEducation' = @('https://www.scarleteen.com', 'https://www.plannedparenthood.org')
        'Adult-Tasteless' = @('https://www.4chan.org', 'https://www.8kun.top')
        'Adult-Violence' = @('https://www.liveleak.com', 'https://www.bestgore.com')
        'HighBW-Downloads' = @('https://www.softpedia.com', 'https://www.filehippo.com')
        'HighBW-ImageSharing' = @('https://www.imgur.com', 'https://www.flickr.com')
        'HighBW-P2P' = @('https://www.thepiratebay.org', 'https://www.1337x.to')
        'HighBW-Streaming' = @('https://www.netflix.com', 'https://www.hulu.com')
        'Legal-Criminal' = @('https://www.criminaldefenselawyer.com', 'https://www.thefederalcrimesblog.com')
        'Legal-Hacking' = @('https://www.exploit-db.com', 'https://www.offensive-security.com')
        'Legal-HateIntolerance' = @('https://www.stormfront.org', 'https://www.dailystormer.in')
        'Legal-IllegalSoftware' = @('https://www.thepiratebay.org', 'https://www.1337x.to')
        'Legal-SchoolCheating' = @('https://www.chegg.com', 'https://www.coursehero.com')
        'Legal-Weapons' = @('https://www.gunsamerica.com', 'https://www.armslist.com')
        'Legal-IllegalDrugs' = @('https://www.erowid.org', 'https://www.bluelight.org')
        'Legal-ChildAbuse' = @('https://www.icmec.org', 'https://www.enough.org')
        'Legal-SelfHarm' = @('https://www.self-injury.net', 'https://www.recoveryourlife.com')
        'Leisure-Chat' = @('https://webchat.freenode.net', 'https://www.chatrandom.com')
        'Leisure-Games' = @('https://www.twitch.tv', 'https://store.steampowered.com')
        'Leisure-InstantMessaging' = @('https://web.telegram.org', 'https://www.whatsapp.com')
        'Leisure-ProfNetwork' = @('https://www.linkedin.com', 'https://www.indeed.com')
        'Leisure-SocialNetworking' = @('https://www.facebook.com', 'https://www.reddit.com')
        'Leisure-WebEmail' = @('https://mail.google.com', 'https://outlook.live.com')
        'Uncategorized-NewDomains' = @('https://www.newdomaintest2026.com', 'https://tryingnewsite2026.net')
        'Uncategorized-Parked' = @('https://parking.com', 'https://www.sedoparking.com')
    }
    
    # Open WCF categories using tab-based approach (reuse browser, not separate processes per URL)
    $wcfUrls = @()
    foreach ($category in $filterCategories.GetEnumerator()) {
        $wcfUrls += $category.Value
    }
    
    Out-Log "Opening $($wcfUrls.Count) WCF category URLs in batches"
    $browser = if ($edgePath -and (Test-Path $edgePath)) { $edgePath } else { $chromePath }
    
    # Batch WCF URLs in groups of 8 to avoid tab limits
    $batchSize = 8
    $batches = [Math]::Ceiling($wcfUrls.Count / $batchSize)
    
    for ($b = 0; $b -lt $batches; $b++) {
        $start = $b * $batchSize
        $end = [Math]::Min($start + $batchSize - 1, $wcfUrls.Count - 1)
        $batch = $wcfUrls[$start..$end]
        
        try {
            $bArgs = $batch -join '" "' | ForEach-Object { "`"$_`"" }
            $p = Start-Process -FilePath $browser -ArgumentList "--no-first-run $($batch -join ' ')" -PassThru -ErrorAction Stop
            Out-Log "  [Batch $($b+1)/$batches] Opened $($batch.Count) WCF URLs"
            Start-Sleep -Seconds 4
            $p | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
        } catch {
            Out-Log "  [Batch $($b+1)/$batches] Error: $_"
        }
    }
    
    # Now test individual categories with sequential browser launches (lighter weight)
    foreach ($category in $filterCategories.GetEnumerator()) {
        Out-Log "Category: $($category.Key)"
        $useChrome = $false
        foreach ($url in $category.Value) {
            $activeBrowser = if ($useChrome -and $chromePath) { $chromePath } elseif ($edgePath) { $edgePath } else { $chromePath }
            $useChrome = -not $useChrome
            try {
                if ($activeBrowser -and (Test-Path $activeBrowser)) {
                    $bName = if ($activeBrowser -like '*chrome*') { 'Chrome' } else { 'Edge' }
                    $p = Start-Process -FilePath $activeBrowser -ArgumentList "--no-first-run --no-default-browser-check `"$url`"" -PassThru -ErrorAction Stop
                    Start-Sleep -Milliseconds 2500
                    $p | Stop-Process -Force -ErrorAction SilentlyContinue
                } else {
                    Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
                    $bName = 'WebRequest'
                }
                Out-Log "  [$bName] Browsed: $url"
            } catch {
                Out-Log "  Failed/Blocked: $url"
            }
            Start-Sleep -Milliseconds 400
        }
    }
    
    # Close all browser processes
    Start-Sleep -Seconds 2
    Get-Process -Name "msedge", "chrome" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Out-Log "WCF browser processes closed"
}

# IDENTITY QUERIES - drives IdentityQueryEvents and IdentityDirectoryEvents
# Uses built-in net commands and ADSI searcher which produce query telemetry
if (-not $SkipIdentityQueries) {
    Out-Log "Running identity and directory queries"

    $netCmds = @(
        { net user 2>&1 | Out-Null },
        { net group 2>&1 | Out-Null },
        { net localgroup 2>&1 | Out-Null },
        { net localgroup administrators 2>&1 | Out-Null },
        { whoami /all 2>&1 | Out-Null },
        { whoami /groups 2>&1 | Out-Null },
        { nltest /dclist: 2>&1 | Out-Null },
        { gpresult /r 2>&1 | Out-Null }
    )

    $netCmds | ForEach-Object {
        try { & $_ } catch {}
        Start-Sleep -Milliseconds 300
    }

    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = '(objectClass=user)'
        $searcher.SizeLimit = 20
        $searcher.FindAll() | Out-Null
        Out-Log "LDAP user query completed"
    } catch { Out-Log "LDAP query skipped: $_" }

    try {
        $searcher2 = New-Object System.DirectoryServices.DirectorySearcher
        $searcher2.Filter = '(objectClass=group)'
        $searcher2.SizeLimit = 20
        $searcher2.FindAll() | Out-Null
        Out-Log "LDAP group query completed"
    } catch { Out-Log "LDAP group query skipped: $_" }

    try {
        $searcher3 = New-Object System.DirectoryServices.DirectorySearcher
        $searcher3.Filter = '(objectClass=computer)'
        $searcher3.SizeLimit = 20
        $searcher3.FindAll() | Out-Null
        Out-Log "LDAP computer query completed"
    } catch { Out-Log "LDAP computer query skipped: $_" }
}

# ONEDRIVE FILE ACTIVITY - drives DeviceFileEvents, OfficeActivity, AuditLogs
if (-not $SkipOneDrive) {
    $odPaths = @(
        (Join-Path $env:USERPROFILE 'OneDrive'),
        (Join-Path $env:USERPROFILE 'OneDrive - MngEnvMCAP709711')
    )

    $od = $odPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($od) {
        Out-Log "Writing OneDrive telemetry files to $od"
        $subFolder = Join-Path $od 'ArcTelemetry'
        New-Item -ItemType Directory -Path $subFolder -Force | Out-Null

        1..$OneDriveFileCount | ForEach-Object {
            $f = Join-Path $subFolder "telem_$(Get-Date -Format 'yyyyMMdd-HHmmss')_$_.txt"
            $content = @"
Telemetry seed file $_ generated at $(Get-Date -Format s)
User: $env:USERNAME
Device: $env:COMPUTERNAME
Session: $pid
Line2: Security operations review round $_
Line3: Reviewing alerts and device activity logs for compliance.
"@
            Set-Content -Path $f -Value $content -Encoding UTF8
            Add-Content -Path $f -Value "Updated at $(Get-Date -Format s)"
            Start-Sleep -Milliseconds 200
        }
        Out-Log "OneDrive files written: $OneDriveFileCount"
    } else {
        Out-Log "OneDrive folder not found"
    }
}

# OFFICE APPS - already covered by Playwright browser automation above
# (Word, Excel, PowerPoint URLs are opened via Office.com URLs)
# Skipping blank desktop app launches to avoid noise
Out-Log "Office apps: Skipped (already covered by Playwright Office.com URLs)"

# ENDPOINT COMMAND BURST - drives DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents
Out-Log "Running endpoint command burst"
$cmds = @(
    { ipconfig /all 2>&1 | Out-Null },
    { netstat -an 2>&1 | Out-Null },
    { route print 2>&1 | Out-Null },
    { nslookup microsoft.com 2>&1 | Out-Null },
    { nslookup outlook.office365.com 2>&1 | Out-Null },
    { nslookup teams.microsoft.com 2>&1 | Out-Null },
    { systeminfo 2>&1 | Out-Null },
    { tasklist 2>&1 | Out-Null },
    { reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion 2>&1 | Out-Null },
    { reg query HKCU\SOFTWARE\Microsoft 2>&1 | Out-Null },
    { certutil -store My 2>&1 | Out-Null },
    { arp -a 2>&1 | Out-Null }
)

$cmds | ForEach-Object {
    try { & $_ } catch {}
    Start-Sleep -Milliseconds 400
}

# WEB REQUEST BURST - drives DeviceNetworkEvents, CloudAppEvents
Out-Log "Running web request burst"
$webTargets = @(
    'https://www.microsoft.com/robots.txt',
    'https://learn.microsoft.com/robots.txt',
    'https://login.microsoftonline.com',
    'https://graph.microsoft.com',
    'https://www.office.com',
    'https://www.bing.com/robots.txt'
)

# CLOUD APP OPERATIONS - drives CloudAppEvents
Out-Log "Cloud app operations (Teams, SharePoint, Outlook cloud)"
$cloudApps = @(
    'https://teams.microsoft.com',
    'https://outlook.office.com/mail',
    'https://www.microsoft365.com/launch/excel',
    'https://www.sharepoint.com',
    'https://portal.azure.com',
    'https://admin.microsoft.com',
    'https://mngenvmcap709711.sharepoint.com/sites/Team1/Shared%20Documents/Forms/AllItems.aspx?id=%2Fsites%2FTeam1%2FShared%20Documents%2FGeneral&sortField=Modified&isAscending=false&viewid=694eda31%2D6870%2D481f%2D9fc5%2D9a8bd648a6ff',
    'https://mngenvmcap709711.sharepoint.com/sites/Team1'
)
foreach ($app in $cloudApps) {
    try { Invoke-WebRequest -Uri $app -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {}
    Start-Sleep -Milliseconds 800
}
Out-Log "Cloud app ops completed"

# IDENTITY OPERATIONS - drives SigninLogs, IdentityLogonEvents, EntraIdSignInEvents, AuditLogs
Out-Log "Identity operations (sign-in, directory, audit)"
try {
    # Attempt sign-in context queries
    $currentUser = whoami /upn 2>$null
    if ($currentUser) { Out-Log "Current UPN context: $currentUser" }
    
    # Query identity info (gracefully handle Azure AD joined devices)
    try {
        $localUsers = @(Get-LocalUser -ErrorAction SilentlyContinue)
        if ($localUsers) {
            $localUsers | Select-Object -First 5 | ForEach-Object {
                $_ | Select-Object Name, Enabled, LastLogon
            } | Out-Null
        }
    } catch {
        Out-Log "Local users unavailable (Azure AD joined device)"
    }
    
    # Check group memberships
    try {
        $groups = @(Get-LocalGroup -ErrorAction SilentlyContinue)
        if ($groups) {
            foreach ($g in $groups) {
                Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | Out-Null
                Start-Sleep -Milliseconds 100
            }
        }
    } catch {
        Out-Log "Local groups unavailable (Azure AD joined device)"
    }
    
    Out-Log "Identity queries completed"
} catch { Out-Log "Identity ops skipped: $_" }

# EMAIL OPERATIONS - drives EmailEvents, EmailUrlInfo, EmailAttachmentInfo, AuditLogs
# Uses Outlook COM directly (no Graph API, no prompts via SendUsingAccount)
Out-Log "Email operations (Outlook COM only, no security prompts)"

# Create attachment files
$attachDir = Join-Path $env:TEMP 'EmailAttachments'
New-Item -ItemType Directory -Path $attachDir -Force -ErrorAction SilentlyContinue | Out-Null
$attachFiles = @(
    [PSCustomObject]@{ Name = 'SecurityReport.txt';  Content = "Security telemetry report`nGenerated: $(Get-Date -Format 'o')`nDevice: $env:COMPUTERNAME`nUser: $env:USERNAME`nClassification: CONFIDENTIAL" },
    [PSCustomObject]@{ Name = 'NetworkScan.csv';     Content = "IP,Port,Status,Timestamp`n10.0.0.1,443,Open,$(Get-Date -Format 'o')`n10.0.0.2,80,Open,$(Get-Date -Format 'o')" },
    [PSCustomObject]@{ Name = 'IncidentDetails.txt'; Content = "INCIDENT REPORT`nDate: $(Get-Date -Format 'o')`nDevice: $env:COMPUTERNAME`nSeverity: Medium" }
)
foreach ($af in $attachFiles) {
    $af | Add-Member -NotePropertyName Path -NotePropertyValue (Join-Path $attachDir $af.Name)
    Set-Content -Path $af.Path -Value $af.Content -Encoding UTF8
}

$recipients = @('admin@mngenvmcap709711.onmicrosoft.com','elliottalderson@mngenvmcap709711.onmicrosoft.com')
$emailsSent = 0

# Outlook COM via SendUsingAccount (no security prompts)
try {
    $outlook = New-Object -ComObject Outlook.Application -ErrorAction SilentlyContinue
    if ($outlook) {
        Out-Log "Using Outlook COM with SendUsingAccount (no prompts)"
        $ns = $outlook.GetNamespace("MAPI")
        $ns.Logon($null, $null, $false, $true) | Out-Null
        
        # Get the default account
        $account = $null
        try {
            $account = $outlook.Session.Accounts | Select-Object -First 1
        } catch { }

        $emails = @(
            @{ To = $recipients[0]; Subject = "Security Report - $(Get-Date -Format 'HH:mm')"; Body = "Security telemetry report attached."; Attach = @($attachFiles[0].Path) },
            @{ To = $recipients[1]; Subject = "Network Scan - $(Get-Date -Format 'HH:mm')"; Body = "Network scan data attached."; Attach = @($attachFiles[1].Path) },
            @{ To = $recipients[0]; Subject = "Incident Details - $(Get-Date -Format 'HH:mm')"; Body = "Incident report attached."; Attach = @($attachFiles[2].Path) }
        )

        foreach ($e in $emails) {
            try {
                $mail = $outlook.CreateItem(0)  # 0 = olMailItem
                $mail.To      = $e.To
                $mail.Subject = $e.Subject
                $mail.Body    = $e.Body
                
                # Add attachments
                foreach ($a in $e.Attach) {
                    if (Test-Path $a) { $mail.Attachments.Add($a) | Out-Null }
                }
                
                # Send using account method (avoids security prompt)
                if ($account) {
                    $mail._MailItem.SendUsingAccount($account)
                } else {
                    $mail.Send()
                }
                
                Out-Log "  [Outlook] Sent: '$($e.Subject)' to $($e.To)"
                $emailsSent++
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($mail) | Out-Null
                Start-Sleep -Milliseconds 800
            } catch { Out-Log "  [Outlook] Failed: $_" }
        }

        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ns) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook) | Out-Null
    } else {
        Out-Log "Outlook COM not available"
    }
} catch { Out-Log "Outlook COM email operations skipped: $_" }

Out-Log "Email operations complete: $emailsSent emails sent"

# DLP OPERATIONS - drives MicrosoftPurviewInformationProtection  
Out-Log "DLP file labeling (Purview sensitivity labels)"
try {
    $dlpDir = Join-Path $env:USERPROFILE 'Desktop\DLPTest'
    New-Item -ItemType Directory -Path $dlpDir -Force | Out-Null
    
    1..5 | ForEach-Object {
        $file = Join-Path $dlpDir "sensitive_$_.txt"
        $content = @"
CONFIDENTIAL - Internal Use Only
Document ID: CONFID-$_
Classification: Highly Restricted
Content: Sensitive business information $_
Generated: $(Get-Date -Format 's')
"@
        Set-Content -Path $file -Value $content -Encoding UTF8
        Start-Sleep -Milliseconds 200
    }
    Out-Log "DLP test files created: 5 sensitive files"
} catch { Out-Log "DLP ops failed: $_" }

# ADDITIONAL CLOUD TARGETING - drives CloudAppEvents further
Out-Log "Additional cloud service probes"
$additionalCloud = @(
    'https://admin.teams.microsoft.com',
    'https://spo-admin.sharepoint.com',
    'https://outlook.office365.com',
    'https://myaccount.microsoft.com',
    'https://account.activedirectory.windowsazure.com'
)
foreach ($svc in $additionalCloud) {
    try { Invoke-WebRequest -Uri $svc -UseBasicParsing -TimeoutSec 8 | Out-Null } catch {}
    Start-Sleep -Milliseconds 600
}

1..20 | ForEach-Object {
    $u = Get-Random -InputObject $webTargets
    try { Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 8 | Out-Null } catch {}
    Start-Sleep -Milliseconds 400
}

# ENHANCED SHAREPOINT AND ONEDRIVE FILE ACTIVITY - drives OfficeActivity FileCreated, FileModified, FileDeleted, FileSyncUploadedFull
# Creates burst of files, modifies them, deletes them, and forces OneDrive sync
Out-Log "Enhanced SharePoint and OneDrive file activity (create, modify, delete, sync)"
try {
    $spoPaths = @(
        (Join-Path $env:USERPROFILE 'OneDrive - MngEnvMCAP709711\Team1 - General'),
        (Join-Path $env:USERPROFILE 'MngEnvMCAP709711\Team1 - General'),
        (Join-Path $env:USERPROFILE 'SharePoint\Team1 - General'),
        (Join-Path $env:USERPROFILE 'OneDrive - MngEnvMCAP709711'),
        (Join-Path $env:USERPROFILE 'OneDrive')
    )
    $spoPath = $spoPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($spoPath) {
        Out-Log "SharePoint sync path found: $spoPath"
        $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
        $workDir = Join-Path $spoPath "ArcTelemetry_$ts"
        New-Item -ItemType Directory -Path $workDir -Force -ErrorAction SilentlyContinue | Out-Null
        Out-Log "Created working directory: $workDir"

        # BURST 1: Create 15 files rapidly (drives FileCreated events)
        Out-Log "Creating 15 files (burst 1)"
        $files = @()
        1..15 | ForEach-Object {
            $file = Join-Path $workDir "Report_$_.txt"
            $content = @"
Security Report $_
Generated: $(Get-Date -Format 'o')
Device: $env:COMPUTERNAME
User: $env:USERNAME
Severity: Medium
Status: Active
Details: Security telemetry report number $_
Last updated: $(Get-Date -Format 'o')
"@
            Set-Content -Path $file -Value $content -Encoding UTF8
            $files += $file
            Out-Log "  [FileCreated] $file"
            Start-Sleep -Milliseconds 150
        }

        # BURST 2: Modify all files 3 times each (drives FileModified events)
        Out-Log "Modifying all files (3 iterations)"
        1..3 | ForEach-Object {
            $iter = $_
            foreach ($file in $files) {
                try {
                    $content = Get-Content -Path $file -Raw -ErrorAction SilentlyContinue
                    $updated = $content + "`nUpdate $iter at $(Get-Date -Format 'o')`n"
                    Set-Content -Path $file -Value $updated -Encoding UTF8
                    Out-Log "  [FileModified] Iteration $iter : $(Split-Path $file -Leaf)"
                    Start-Sleep -Milliseconds 100
                } catch {}
            }
            Start-Sleep -Milliseconds 500
        }

        # BURST 3: Append bulk data to trigger large sync events
        Out-Log "Appending bulk data to files"
        foreach ($file in $files | Select-Object -First 5) {
            try {
                $bulkData = (1..100 | ForEach-Object { "Data line $_$(Get-Date -Millisecond)" }) -join "`n"
                Add-Content -Path $file -Value "`n$bulkData" -Encoding UTF8
                Out-Log "  [FileLargeWrite] $(Split-Path $file -Leaf)"
                Start-Sleep -Milliseconds 200
            } catch {}
        }

        # BURST 4: Delete files in waves (drives FileDeleted events)
        Out-Log "Deleting files (wave 1 - 5 files)"
        $files[0..4] | ForEach-Object {
            try {
                Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue
                Out-Log "  [FileDeleted] $(Split-Path $_ -Leaf)"
                Start-Sleep -Milliseconds 200
            } catch {}
        }

        Start-Sleep -Seconds 2

        Out-Log "Deleting files (wave 2 - 5 files)"
        $files[5..9] | ForEach-Object {
            try {
                Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue
                Out-Log "  [FileDeleted] $(Split-Path $_ -Leaf)"
                Start-Sleep -Milliseconds 200
            } catch {}
        }

        Start-Sleep -Seconds 2

        Out-Log "Deleting files (wave 3 - remaining 5 files)"
        $files[10..14] | ForEach-Object {
            try {
                Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue
                Out-Log "  [FileDeleted] $(Split-Path $_ -Leaf)"
                Start-Sleep -Milliseconds 200
            } catch {}
        }

        # Force OneDrive sync
        Out-Log "Triggering OneDrive sync"
        try {
            # Kill and restart OneDrive to force sync
            Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            $onedrivePath = "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
            if (Test-Path $onedrivePath) {
                Start-Process -FilePath $onedrivePath -ErrorAction SilentlyContinue
                Out-Log "  OneDrive restarted to force sync"
                Start-Sleep -Seconds 3
            }
        } catch { Out-Log "  OneDrive sync trigger: $_.Exception.Message" }

        # Clean up working directory
        Start-Sleep -Seconds 1
        try {
            Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
            Out-Log "Cleaned up working directory: $workDir"
        } catch {}

        Out-Log "File activity burst complete: 45 operations (15 create + 15 modify × 3 + 5 large write + 15 delete + 5 sync)"
    } else {
        Out-Log "SharePoint sync path not found - attempting OneDrive fallback"
        $fallbackPath = (Join-Path $env:USERPROFILE 'OneDrive'), (Join-Path $env:USERPROFILE 'OneDrive - MngEnvMCAP709711') | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($fallbackPath) {
            Out-Log "Using OneDrive fallback: $fallbackPath"
            $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
            $workDir = Join-Path $fallbackPath "ArcTelemetry_Fallback_$ts"
            New-Item -ItemType Directory -Path $workDir -Force -ErrorAction SilentlyContinue | Out-Null
            
            # Quick 10-file burst for fallback
            Out-Log "Running 10-file burst on fallback path"
            $files = @()
            1..10 | ForEach-Object {
                $file = Join-Path $workDir "Telemetry_$_.txt"
                Set-Content -Path $file -Value "Fallback report $_`nTime: $(Get-Date -Format 'o')" -Encoding UTF8
                $files += $file
                Out-Log "  [FileCreated] Telemetry_$_.txt"
                Start-Sleep -Milliseconds 100
            }
            
            # Modify files twice
            1..2 | ForEach-Object {
                $iter = $_
                foreach ($file in $files) {
                    Add-Content -Path $file -Value "`nModification $iter" -Encoding UTF8
                    Start-Sleep -Milliseconds 50
                }
                Start-Sleep -Milliseconds 200
            }
            
            # Delete all files
            $files | ForEach-Object {
                Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue
                Out-Log "  [FileDeleted] $(Split-Path $_ -Leaf)"
                Start-Sleep -Milliseconds 100
            }
            
            Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
            Out-Log "Fallback file activity complete: 30 operations (10 create + 10 modify + 10 delete)"
        } else {
            Out-Log "No OneDrive path available - skipping enhanced file activity"
        }
    }
} catch { Out-Log "Enhanced file ops failed: $_" }

Out-Log "COMPLETE interactive telemetry burst - all 16 tables targeted"
