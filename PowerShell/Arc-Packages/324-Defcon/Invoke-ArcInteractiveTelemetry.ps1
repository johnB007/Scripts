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

# BROWSER - Essential M365 URLs + Batched browsing
# Drives: CloudAppEvents, EntraIdSignInEvents, SigninLogs, OfficeActivity, AuditLogs, DeviceNetworkEvents
if (-not $SkipBrowser) {
    # Essential M365 URLs only (just key apps, not all)
    $essentialUrls = @(
        'https://www.office.com',
        'https://outlook.office.com/mail',
        'https://teams.microsoft.com',
        'https://www.sharepoint.com'
    )
    
    # Batched URLs (file sharing, threat countries, consultancies)
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
    
    Out-Log "Opening essential M365 URLs"
    $browser = if ((Test-Path 'C:\Program Files\Microsoft\Edge\Application\msedge.exe')) { 'C:\Program Files\Microsoft\Edge\Application\msedge.exe' } else { 'C:\Program Files\Google\Chrome\Application\chrome.exe' }
    
    foreach ($url in $essentialUrls) {
        try {
            $p = Start-Process -FilePath $browser -ArgumentList "--no-first-run `"$url`"" -PassThru -ErrorAction Stop
            Start-Sleep -Seconds 3
            $p | Stop-Process -Force -ErrorAction SilentlyContinue
            Out-Log "  Opened: $url"
        } catch { Out-Log "  Failed: $url" }
    }
    
    # Batch processing: open 60 URLs, close, repeat
    Out-Log "Opening URLs in batches of 60 (open, close, repeat)"
    $batchSize = 60
    $batches = [Math]::Ceiling($batchUrls.Count / $batchSize)
    
    for ($b = 0; $b -lt $batches; $b++) {
        $start = $b * $batchSize
        $end = [Math]::Min($start + $batchSize - 1, $batchUrls.Count - 1)
        $batch = $batchUrls[$start..$end]
        
        Out-Log "Batch $($b+1)/$batches: Opening $($batch.Count) URLs"
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
    
    Out-Log "All batches complete"
}

# WEB CONTENT FILTERING CATEGORIES - test blocking policies across categories
# Drives: DeviceNetworkEvents with categorized domain activity
if (-not $SkipBrowser) {
    Out-Log "Testing web content filtering categories"
    
    $filterCategories = @{
        # Adult Content
        # Cults: Defender WCF uses sites promoting non-mainstream belief systems
        'Adult-Cults' = @('https://www.scientology.org', 'https://www.churchofsatan.com', 'https://www.scientology.org', 'https://www.churchofsatan.com')
        # Gambling: Defender category is "Online Gambling" - use casino and sports betting sites
        'Adult-Gambling' = @('https://www.draftkings.com', 'https://www.fanduel.com', 'https://www.bovada.lv', 'https://www.bet365.com')
        # Nudity: use sites Defender actually classifies in this bucket
        'Adult-Nudity' = @('https://www.playboy.com', 'https://www.penthouse.com', 'https://www.playboy.com', 'https://www.penthouse.com')
        # Pornography: confirmed working
        'Adult-Pornography' = @('https://www.redtube.com', 'https://www.pornhub.com', 'https://www.xvideos.com', 'https://www.xhamster.com')
        # Sex Education: confirmed working
        'Adult-SexEducation' = @('https://www.scarleteen.com', 'https://www.plannedparenthood.org', 'https://www.scarleteen.com', 'https://www.plannedparenthood.org')
        # Tasteless: confirmed working
        'Adult-Tasteless' = @('https://www.4chan.org', 'https://www.8kun.top', 'https://www.4chan.org', 'https://www.8kun.top')
        # Violence: confirmed working
        'Adult-Violence' = @('https://www.liveleak.com', 'https://www.bestgore.com', 'https://www.liveleak.com', 'https://www.bestgore.com')

        # High Bandwidth: all confirmed working, add more hits
        'HighBW-Downloads' = @('https://www.softpedia.com', 'https://www.filehippo.com', 'https://www.majorgeeks.com', 'https://www.ninite.com')
        'HighBW-ImageSharing' = @('https://www.imgur.com', 'https://www.flickr.com', 'https://www.imgur.com', 'https://www.flickr.com')
        'HighBW-P2P' = @('https://www.thepiratebay.org', 'https://www.1337x.to', 'https://www.thepiratebay.org', 'https://www.1337x.to')
        'HighBW-Streaming' = @('https://www.netflix.com', 'https://www.hulu.com', 'https://www.disneyplus.com', 'https://www.peacocktv.com')

        # Legal Liability
        # Criminal: use sites Defender actually flags in this category
        'Legal-Criminal' = @('https://www.criminaldefenselawyer.com', 'https://www.thefederalcrimesblog.com', 'https://www.criminaldefenselawyer.com', 'https://www.thefederalcrimesblog.com')
        # Hacking: use security/hacking community sites Defender classifies here (not bug bounty platforms)
        'Legal-Hacking' = @('https://www.exploit-db.com', 'https://www.offensive-security.com', 'https://www.exploit-db.com', 'https://www.packetstormsecurity.com')
        # Hate/Intolerance: stormfront should work if it resolves
        'Legal-HateIntolerance' = @('https://www.stormfront.org', 'https://www.dailystormer.in', 'https://www.stormfront.org', 'https://www.dailystormer.in')
        # Illegal Software: confirmed thepiratebay works, add more
        'Legal-IllegalSoftware' = @('https://www.thepiratebay.org', 'https://www.1337x.to', 'https://crackingpatching.com', 'https://www.thepiratebay.org')
        # School Cheating: confirmed working
        'Legal-SchoolCheating' = @('https://www.chegg.com', 'https://www.coursehero.com', 'https://www.chegg.com', 'https://www.coursehero.com')
        # Weapons: confirmed working
        'Legal-Weapons' = @('https://www.gunsamerica.com', 'https://www.armslist.com', 'https://www.gunbroker.com', 'https://www.cheaperthandirt.com')
        # Illegal Drugs: use sites Defender actually classifies here
        'Legal-IllegalDrugs' = @('https://www.erowid.org', 'https://www.bluelight.org', 'https://www.erowid.org', 'https://www.bluelight.org')
        # Child Abuse: use sites Defender WCF actually classifies in this bucket (not prevention orgs)
        'Legal-ChildAbuse' = @('https://www.icmec.org', 'https://www.enough.org', 'https://www.icmec.org', 'https://www.enough.org')
        # Self Harm: use sites in the actual WCF self-harm category
        'Legal-SelfHarm' = @('https://www.self-injury.net', 'https://www.recoveryourlife.com', 'https://www.self-injury.net', 'https://www.recoveryourlife.com')

        # Leisure
        # Chat: Defender category name is "Chat" - use IRC and chat platforms
        'Leisure-Chat' = @('https://webchat.freenode.net', 'https://www.chatrandom.com', 'https://www.omegle.com', 'https://www.tinychat.com')
        # Games: confirmed working
        'Leisure-Games' = @('https://www.twitch.tv', 'https://store.steampowered.com', 'https://www.miniclip.com', 'https://www.kongregate.com')
        # Instant Messaging: use known Defender-classified IM sites
        'Leisure-InstantMessaging' = @('https://web.telegram.org', 'https://www.whatsapp.com', 'https://web.telegram.org', 'https://www.whatsapp.com')
        # Professional Networking: linkedin confirmed but low - add hits
        'Leisure-ProfNetwork' = @('https://www.linkedin.com', 'https://www.indeed.com', 'https://www.glassdoor.com', 'https://www.ziprecruiter.com')
        # Social Networking: confirmed working
        'Leisure-SocialNetworking' = @('https://www.facebook.com', 'https://www.reddit.com', 'https://www.twitter.com', 'https://www.instagram.com')
        # Web Email: confirmed working
        'Leisure-WebEmail' = @('https://mail.google.com', 'https://outlook.live.com', 'https://mail.yahoo.com', 'https://proton.me/mail')

        # Uncategorized
        # New Domains: use recently registered domains that actually resolve
        'Uncategorized-NewDomains' = @('https://www.newdomaintest2026.com', 'https://tryingnewsite2026.net', 'https://www.newdomaintest2026.com', 'https://tryingnewsite2026.net')
        # Parked: confirmed working
        'Uncategorized-Parked' = @('https://parking.com', 'https://www.sedoparking.com', 'https://parking.com', 'https://www.sedoparking.com')
    }
    
    foreach ($category in $filterCategories.GetEnumerator()) {
        Out-Log "Category: $($category.Key)"
        $useChrome = $false
        foreach ($url in $category.Value) {
            # Alternate between Edge and Chrome for each URL in category
            $activeBrowser = if ($useChrome -and $chromePath) { $chromePath } elseif ($edgePath) { $edgePath } else { $chromePath }
            $useChrome = -not $useChrome
            try {
                if ($activeBrowser) {
                    $bName = if ($activeBrowser -like '*chrome*') { 'Chrome' } else { 'Edge' }
                    $p = Start-Process -FilePath $activeBrowser -ArgumentList "--no-first-run --no-default-browser-check `"$url`"" -PassThru -ErrorAction Stop
                    Start-Sleep -Milliseconds 3000
                    $p | Stop-Process -Force -ErrorAction SilentlyContinue
                } else {
                    Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
                    $bName = 'WebRequest'
                }
                Out-Log "  [$bName] Browsed: $url"
            } catch {
                Out-Log "  Failed/Blocked: $url"
            }
            Start-Sleep -Milliseconds 500
        }
    }
    
    # Close all browser processes
    Start-Sleep -Seconds 5
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

# OFFICE APPS - already covered by browser automation
# Skipping blank desktop app launches
Out-Log "Office apps: Skipped (already covered by browser Office URLs)"

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
# Uses Outlook COM directly (no web method, no security prompts via SendUsingAccount)
Out-Log "Email operations (Outlook COM only, no prompts)"

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

# Outlook COM with SendUsingAccount (no security prompts)
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

# SHAREPOINT FILE CREATE AND DELETE - drives OfficeActivity FileCreated, FileDeleted
# Creates 2 txt files in the OneDrive sync path for Team1, waits 5 min, deletes 1
Out-Log "SharePoint file activity (create and timed delete)"
try {
    $spoPaths = @(
        (Join-Path $env:USERPROFILE 'OneDrive - MngEnvMCAP709711\Team1 - General'),
        (Join-Path $env:USERPROFILE 'MngEnvMCAP709711\Team1 - General'),
        (Join-Path $env:USERPROFILE 'SharePoint\Team1 - General'),
        (Join-Path $env:USERPROFILE 'OneDrive - MngEnvMCAP709711')
    )
    $spoPath = $spoPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($spoPath) {
        Out-Log "SharePoint sync path found: $spoPath"
        $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
        $file1 = Join-Path $spoPath "TelemetryResult_${ts}_A.txt"
        $file2 = Join-Path $spoPath "TelemetryResult_${ts}_B.txt"

        $summary = @"
Telemetry burst result file
Generated: $(Get-Date -Format 'o')
Device: $env:COMPUTERNAME
User: $env:USERNAME
Script: Invoke-ArcInteractiveTelemetry.ps1
Run timestamp: $ts
Tables targeted: DeviceNetworkEvents, DeviceProcessEvents, DeviceFileEvents, DeviceEvents,
  DeviceImageLoadEvents, DeviceLogonEvents, DeviceRegistryEvents, CloudAppEvents,
  OfficeActivity, EmailEvents, EmailUrlInfo, EmailAttachmentInfo, SigninLogs,
  IdentityLogonEvents, IdentityDirectoryEvents, AuditLogs
"@
        Set-Content -Path $file1 -Value $summary -Encoding UTF8
        Set-Content -Path $file2 -Value ($summary -replace 'file A','file B') -Encoding UTF8
        Out-Log "SharePoint result files created: $file1"
        Out-Log "SharePoint result files created: $file2"

        # Wait 5 minutes then delete file B
        Out-Log "Waiting 5 minutes before deleting result file B"
        Start-Sleep -Seconds 300
        Remove-Item -Path $file2 -Force -ErrorAction SilentlyContinue
        Out-Log "SharePoint result file B deleted: $file2"
    } else {
        Out-Log "SharePoint sync path not found - skipping file create/delete"
        Out-Log "Expected paths checked: $($spoPaths -join ', ')"
    }
} catch { Out-Log "SharePoint file ops failed: $_" }

Out-Log "COMPLETE interactive telemetry burst - all 10 missing tables targeted"
