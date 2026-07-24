<#
.SYNOPSIS
Simulate a normal Microsoft 365 user day from a Windows endpoint.

.DESCRIPTION
This script creates and edits files in OneDrive, opens Microsoft 365 web apps,
launches common desktop apps, downloads a few benign files, and sends a small
set of mail items through the local Outlook profile when one exists.

Use Task Scheduler with Run only when user is logged on so browser and Office
actions can execute in the signed in user session.

.PARAMETER PlanOnly
Show the planned actions without changing the device.

.PARAMETER JitterSeconds
Extra pause added between groups of actions.

.PARAMETER ValidateSentinel
Run a small Azure Log Analytics check after the workload completes.

.PARAMETER DurationMinutes
How long the simulation should keep cycling through user actions. 0 runs one pass.

.PARAMETER SharePathCandidates
Optional UNC paths to touch during the run for file share style telemetry.

.PARAMETER ConfigPath
Optional path to a JSON file that overrides URLs, download targets, mail routing,
and other simulation settings.

.PARAMETER ProfilePath
Optional path to a JSON user profile. This is intended for BAESL style sandbox
identities or any other exported user roster.

.EXAMPLE
pwsh -File .\Invoke-DailyCloudUserSimulation.ps1

.EXAMPLE
pwsh -File .\Invoke-DailyCloudUserSimulation.ps1 -PlanOnly
#>
[CmdletBinding()]
param(
    [switch]$PlanOnly,

    [ValidateRange(0, 300)]
    [int]$JitterSeconds = 20,

    [switch]$ValidateSentinel,

    [ValidateRange(0, 480)]
    [int]$DurationMinutes = 25,

    [string[]]$SharePathCandidates = @(),

    [string]$ConfigPath,

    [string]$ProfilePath,

    [switch]$Unattended,

    [switch]$SkipBrowser,

    [switch]$SkipAuthenticatedWeb,

    [switch]$SkipOutlookMail,

    [switch]$SkipAppLaunches
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:JitterSeconds = $JitterSeconds
$script:ValidateSentinel = $ValidateSentinel
$script:DurationMinutes = $DurationMinutes
$script:SharePathCandidates = $SharePathCandidates
$script:SimulationProfile = $null
$script:SkipBrowser = $SkipBrowser
$script:SkipAuthenticatedWeb = $SkipAuthenticatedWeb
$script:SkipOutlookMail = $SkipOutlookMail
$script:SkipAppLaunches = $SkipAppLaunches

if ($Unattended) {
    # Avoid known interactive sign in prompts during scheduled runs.
    $script:SkipAuthenticatedWeb = $true
    $script:SkipOutlookMail = $true
    $script:SkipAppLaunches = $true
}

$script:Config = [ordered]@{
    RootFolderName = 'CloudUserSimulation'
    WorkspaceId = '2dde2f51-1428-4f3f-afcb-9aa3e150796e'
    PortalUrls = @(
        'https://www.office.com/?auth=2',
        'https://www.microsoft365.com/',
        'https://outlook.office.com/mail/',
        'https://teams.microsoft.com/',
        'https://www.microsoft365.com/launch/word',
        'https://www.microsoft365.com/launch/excel',
        'https://www.microsoft365.com/launch/powerpoint'
    )
    PublicUrls = @(
        'https://www.microsoft.com/microsoft-365',
        'https://learn.microsoft.com/',
        'https://www.bing.com/news',
        'https://www.cnn.com/',
        'https://www.weather.com/',
        'https://www.bbc.com/',
        'https://www.reuters.com/',
        'https://www.npr.org/',
        'https://www.nytimes.com/'
    )
    AiWebAppUrls = @()
    AiWebAppSampleCount = 8
    CountryUrls = @()
    CountryUrlSampleCount = 10
    DownloadTargets = @(
        @{ Url = 'https://www.microsoft.com/robots.txt'; FileName = 'microsoft-robots.txt' },
        @{ Url = 'https://learn.microsoft.com/robots.txt'; FileName = 'learn-robots.txt' }
    )
    TypingLines = @(
        'Reviewing the tenant morning summary and recent cloud alerts.',
        'Opening Office files from OneDrive and checking status updates.',
        'Scanning Teams, Outlook, and Microsoft 365 portals for routine work.',
        'Reading one public article and one Microsoft Learn page for context.'
    )
    MailRecipients = @()
    UserContext = [ordered]@{
        DisplayName = $env:USERNAME
        Department = 'Security Operations'
        JobTitle = 'Analyst'
        OfficeLocation = 'Remote'
        Manager = 'Team Lead'
        UserPrincipalName = $null
    }
    Wait = [ordered]@{
        Short = 3
        Medium = 8
        Long = 15
    }
    BrowserEngines = @('Edge', 'Chrome')
    BrowserWindowsPerEngine = 3
    BrowserTabsPerWindow = 4
    BrowserWindowDwellSeconds = 20
    BrowserProfileDirectory = 'Default'
    EnableWebRequestBurst = $true
    WebRequestBurstCount = 24
    WebRequestTimeoutSec = 12
    EnableIpProbeActions = $true
    IpProbeTargets = @(
        '10.10.10.10',
        '172.16.10.10',
        '192.168.10.10',
        '192.0.2.10',
        '198.51.100.10',
        '203.0.113.10'
    )
    IpProbePorts = @(80, 443)
    IpProbeSampleCount = 6
    IpProbeTimeoutMs = 1200
    EnableAsrProbeActions = $true
    EnableEndpointCommandBurst = $true
    EndpointCommandBurstCount = 8
    MailBurstCount = 6
    MailSendProbability = 75
}

$script:RunStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogRoot = Join-Path $env:LOCALAPPDATA 'CloudUserSimulation'
$script:LogPath = Join-Path $script:LogRoot ("run-{0}.log" -f $script:RunStamp)

function Initialize-Log {
    New-Item -ItemType Directory -Path $script:LogRoot -Force | Out-Null
    New-Item -ItemType File -Path $script:LogPath -Force | Out-Null
}

function Merge-Hashtable {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Target,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Source
    )

    foreach ($key in $Source.Keys) {
        $incoming = $Source[$key]
        if ($incoming -is [System.Collections.IDictionary] -and $Target.Contains($key) -and $Target[$key] -is [System.Collections.IDictionary]) {
            Merge-Hashtable -Target $Target[$key] -Source $incoming
            continue
        }

        $Target[$key] = $incoming
    }
}

function ConvertTo-Hashtable {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return @{}
    }

    if ($InputObject -is [hashtable]) {
        return $InputObject
    }

    $table = @{}
    foreach ($property in $InputObject.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [pscustomobject]) {
            $table[$property.Name] = ConvertTo-Hashtable -InputObject $value
        }
        else {
            $table[$property.Name] = $value
        }
    }

    return $table
}

function Import-SimulationInput {
    param(
        [string]$JsonConfigPath,
        [string]$JsonProfilePath
    )

    if ($JsonConfigPath) {
        if (-not (Test-Path $JsonConfigPath)) {
            throw "Config file not found: $JsonConfigPath"
        }

        $configData = Get-Content -Path $JsonConfigPath -Raw | ConvertFrom-Json
        $configTable = ConvertTo-Hashtable -InputObject $configData
        Merge-Hashtable -Target $script:Config -Source $configTable
        if ($configData.SharePathCandidates) {
            $script:SharePathCandidates = @($configData.SharePathCandidates)
        }
    }

    if ($JsonProfilePath) {
        if (-not (Test-Path $JsonProfilePath)) {
            throw "Profile file not found: $JsonProfilePath"
        }

        $profileData = Get-Content -Path $JsonProfilePath -Raw | ConvertFrom-Json
        $script:SimulationProfile = $profileData
        if ($profileData.SharePathCandidates) {
            $script:SharePathCandidates = @($script:SharePathCandidates + @($profileData.SharePathCandidates) | Select-Object -Unique)
        }
        if ($profileData.UserContext) {
            $contextTable = ConvertTo-Hashtable -InputObject $profileData.UserContext
            Merge-Hashtable -Target $script:Config.UserContext -Source $contextTable
        }
        if ($profileData.MailRecipients) {
            $script:Config.MailRecipients = @($script:Config.MailRecipients + @($profileData.MailRecipients) | Select-Object -Unique)
        }
        if ($profileData.PortalUrls) {
            $script:Config.PortalUrls = @($script:Config.PortalUrls + @($profileData.PortalUrls) | Select-Object -Unique)
        }
        if ($profileData.PublicUrls) {
            $script:Config.PublicUrls = @($script:Config.PublicUrls + @($profileData.PublicUrls) | Select-Object -Unique)
        }
        if ($profileData.TypingLines) {
            $script:Config.TypingLines = @($script:Config.TypingLines + @($profileData.TypingLines) | Select-Object -Unique)
        }
    }

    if ($script:SharePathCandidates.Count -gt 0) {
        $script:Config.SharePathCandidates = @($script:SharePathCandidates)
    }
}

function Resolve-DefaultConfigPath {
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        return $ConfigPath
    }

    $candidate = Join-Path $PSScriptRoot 'CloudUserSimulation.SampleConfig.json'
    if (Test-Path $candidate) {
        Write-RunLog -Message ("auto using config path {0}" -f $candidate)
        return $candidate
    }

    return $null
}

function Resolve-DefaultProfilePath {
    if (-not [string]::IsNullOrWhiteSpace($ProfilePath)) {
        return $ProfilePath
    }

    $profilesDir = Join-Path $PSScriptRoot '..\profiles\MngEnvMCAP709711'
    if (-not (Test-Path $profilesDir)) {
        $profilesDir = Join-Path $PSScriptRoot '..\Profiles'
    }

    if (-not (Test-Path $profilesDir)) {
        return $null
    }

    $username = [string]$env:USERNAME
    $preferred = Get-ChildItem -Path $profilesDir -Filter '*.json' -ErrorAction SilentlyContinue |
        Where-Object { $_.BaseName -match [Regex]::Escape($username) } |
        Select-Object -First 1

    if ($null -eq $preferred) {
        $preferred = Get-ChildItem -Path $profilesDir -Filter '*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if ($null -ne $preferred) {
        Write-RunLog -Message ("auto using profile path {0}" -f $preferred.FullName)
        return $preferred.FullName
    }

    return $null
}

function Get-UserDisplayLabel {
    $displayName = $script:Config.UserContext.DisplayName
    if ([string]::IsNullOrWhiteSpace([string]$displayName)) {
        return $env:USERNAME
    }

    return $displayName
}

function Write-RunLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'PLAN')]
        [string]$Level = 'INFO'
    )

    $stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = '[{0}] [{1}] {2}' -f $stamp, $Level, $Message
    Add-Content -Path $script:LogPath -Value $line
    Write-Host $line
}

function Invoke-Pause {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Seconds
    )

    if ($PlanOnly) {
        Write-RunLog -Level 'PLAN' -Message ("pause {0} seconds" -f $Seconds)
        return
    }

    Start-Sleep -Seconds $Seconds
}

function Resolve-OneDrivePath {
    if ($env:OneDrive -and (Test-Path $env:OneDrive)) {
        return $env:OneDrive
    }

    $candidate = Get-ChildItem -Path $env:USERPROFILE -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'OneDrive*' } |
        Sort-Object FullName |
        Select-Object -First 1

    if ($null -ne $candidate) {
        return $candidate.FullName
    }

    return (Join-Path $env:USERPROFILE 'Documents')
}

function Get-SimulationRootFolderName {
    $label = Get-UserDisplayLabel
    $safeLabel = $label -replace '[^a-zA-Z0-9]', ''
    if ([string]::IsNullOrWhiteSpace($safeLabel)) {
        return $script:Config.RootFolderName
    }

    return ('{0}_{1}' -f $script:Config.RootFolderName, $safeLabel)
}

function Resolve-Executable {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths,

        [string]$CommandName
    )

    foreach ($path in $Paths) {
        if ($path -and (Test-Path $path)) {
            return $path
        }
    }

    if ($CommandName) {
        $command = Get-Command -Name $CommandName -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }

    return $null
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    Write-RunLog -Message ("start {0}" -f $Name)
    try {
        & $Action
        Write-RunLog -Message ("done {0}" -f $Name)
    }
    catch {
        Write-RunLog -Level 'ERROR' -Message ("{0}: {1}" -f $Name, $_.Exception.Message)
    }

    Invoke-Pause -Seconds ([int]$script:Config.Wait.Short + $script:JitterSeconds)
}

function Write-PlainTextFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Lines
    )

    if ($PlanOnly) {
        Write-RunLog -Level 'PLAN' -Message ("write text file {0}" -f $Path)
        return
    }

    $folder = Split-Path -Path $Path -Parent
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    Set-Content -Path $Path -Value $Lines -Encoding UTF8
}

function Write-WordDocument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Paragraphs
    )

    if ($PlanOnly) {
        Write-RunLog -Level 'PLAN' -Message ("create Word document {0}" -f $Path)
        return $true
    }

    try {
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $doc = $word.Documents.Add()
        foreach ($paragraph in $Paragraphs) {
            $null = $word.Selection.TypeText($paragraph)
            $null = $word.Selection.TypeParagraph()
        }
        $format = [ref]16
        $doc.SaveAs([ref]$Path, $format)
        $doc.Close()
        $word.Quit()
        return $true
    }
    catch {
        Write-RunLog -Level 'WARN' -Message ("Word not available, falling back to text at {0}" -f $Path)
        $fallback = [System.IO.Path]::ChangeExtension($Path, '.txt')
        Write-PlainTextFile -Path $fallback -Lines $Paragraphs
        return $false
    }
    finally {
        foreach ($comObject in 'doc', 'word') {
            if (Get-Variable -Name $comObject -Scope Local -ErrorAction SilentlyContinue) {
                $value = Get-Variable -Name $comObject -Scope Local | Select-Object -ExpandProperty Value
                if ($null -ne $value) {
                    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($value)
                }
            }
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

function Write-ExcelWorkbook {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($PlanOnly) {
        Write-RunLog -Level 'PLAN' -Message ("create Excel workbook {0}" -f $Path)
        return $true
    }

    try {
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $workbook = $excel.Workbooks.Add()
        $sheet = $workbook.Worksheets.Item(1)
        $sheet.Cells.Item(1, 1) = 'Workstream'
        $sheet.Cells.Item(1, 2) = 'Owner'
        $sheet.Cells.Item(1, 3) = 'Status'
        $sheet.Cells.Item(2, 1) = 'Identity'
        $sheet.Cells.Item(2, 2) = $env:USERNAME
        $sheet.Cells.Item(2, 3) = 'In Progress'
        $sheet.Cells.Item(3, 1) = 'Telemetry'
        $sheet.Cells.Item(3, 2) = 'SOC'
        $sheet.Cells.Item(3, 3) = 'Daily Review'
        $workbook.SaveAs($Path)
        $workbook.Close($true)
        $excel.Quit()
        return $true
    }
    catch {
        Write-RunLog -Level 'WARN' -Message ("Excel not available, falling back to csv near {0}" -f $Path)
        $fallback = [System.IO.Path]::ChangeExtension($Path, '.csv')
        Write-PlainTextFile -Path $fallback -Lines @(
            'Workstream,Owner,Status',
            ('Identity,{0},In Progress' -f $env:USERNAME),
            'Telemetry,SOC,Daily Review'
        )
        return $false
    }
    finally {
        foreach ($comObject in 'sheet', 'workbook', 'excel') {
            if (Get-Variable -Name $comObject -Scope Local -ErrorAction SilentlyContinue) {
                $value = Get-Variable -Name $comObject -Scope Local | Select-Object -ExpandProperty Value
                if ($null -ne $value) {
                    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($value)
                }
            }
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

function Write-PowerPointDeck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($PlanOnly) {
        Write-RunLog -Level 'PLAN' -Message ("create PowerPoint deck {0}" -f $Path)
        return $true
    }

    try {
        $powerPoint = New-Object -ComObject PowerPoint.Application
        $presentation = $powerPoint.Presentations.Add()
        $slide = $presentation.Slides.Add(1, 1)
        $slide.Shapes.Title.TextFrame.TextRange.Text = 'Daily cloud routine'
        $slide.Shapes.Placeholders.Item(2).TextFrame.TextRange.Text = 'Office, browser, OneDrive, Teams, and Outlook activity'
        $presentation.SaveAs($Path)
        $presentation.Close()
        $powerPoint.Quit()
        return $true
    }
    catch {
        Write-RunLog -Level 'WARN' -Message ("PowerPoint not available, falling back to markdown near {0}" -f $Path)
        $fallback = [System.IO.Path]::ChangeExtension($Path, '.md')
        Write-PlainTextFile -Path $fallback -Lines @(
            '# Daily cloud routine',
            '',
            'Office, browser, OneDrive, Teams, and Outlook activity.'
        )
        return $false
    }
    finally {
        foreach ($comObject in 'slide', 'presentation', 'powerPoint') {
            if (Get-Variable -Name $comObject -Scope Local -ErrorAction SilentlyContinue) {
                $value = Get-Variable -Name $comObject -Scope Local | Select-Object -ExpandProperty Value
                if ($null -ne $value) {
                    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($value)
                }
            }
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

function Get-OutlookApplication {
    try {
        return New-Object -ComObject Outlook.Application
    }
    catch {
        Write-RunLog -Level 'WARN' -Message 'Outlook is not available in this session'
        return $null
    }
}

function Get-OutlookPrimaryAddress {
    param(
        [Parameter(Mandatory = $true)]
        [object]$OutlookApplication
    )

    try {
        $namespace = $OutlookApplication.GetNamespace('MAPI')
        foreach ($account in $namespace.Accounts) {
            if ($account.SmtpAddress) {
                return $account.SmtpAddress
            }
        }
    }
    catch {
        Write-RunLog -Level 'WARN' -Message 'Could not resolve the Outlook primary address'
    }

    return $null
}

function Open-DocumentWithShell {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        return
    }

    if ($PlanOnly) {
        Write-RunLog -Level 'PLAN' -Message ("open file {0}" -f $Path)
        return
    }

    $process = Start-Process -FilePath $Path -PassThru
    Invoke-Pause -Seconds ([int]$script:Config.Wait.Medium)
    if ($null -ne $process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-OneDriveWorkload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )

    $dayRoot = Join-Path $RootPath (Get-SimulationRootFolderName)
    $todayRoot = Join-Path $dayRoot (Get-Date -Format 'yyyy-MM-dd')
    $folders = @('Projects', 'Finance', 'Legal', 'Research', 'Archive')

    foreach ($folder in $folders) {
        $target = Join-Path $todayRoot $folder
        if ($PlanOnly) {
            Write-RunLog -Level 'PLAN' -Message ("create folder {0}" -f $target)
        }
        else {
            New-Item -ItemType Directory -Path $target -Force | Out-Null
        }
    }

    $briefingPath = Join-Path $todayRoot 'Projects\Daily-Briefing.docx'
    $trackerPath = Join-Path $todayRoot 'Finance\Daily-Tracker.xlsx'
    $deckPath = Join-Path $todayRoot 'Projects\Status-Deck.pptx'
    $notesPath = Join-Path $todayRoot 'Research\browser-notes.md'
    $todoPath = Join-Path $todayRoot 'Projects\task-list.txt'
    $displayName = Get-UserDisplayLabel
    $department = $script:Config.UserContext.Department
    $jobTitle = $script:Config.UserContext.JobTitle
    $officeLocation = $script:Config.UserContext.OfficeLocation
    $manager = $script:Config.UserContext.Manager

    Write-WordDocument -Path $briefingPath -Paragraphs @(
        ('Daily cloud review for {0}.' -f $displayName),
        ('Department: {0}  Role: {1}  Office: {2}' -f $department, $jobTitle, $officeLocation),
        ('Manager: {0}  Review sign in posture, new alerts, open tasks, and follow up items.' -f $manager),
        ('Prepared at {0} by {1}.' -f (Get-Date), $displayName)
    ) | Out-Null

    Write-ExcelWorkbook -Path $trackerPath | Out-Null
    Write-PowerPointDeck -Path $deckPath | Out-Null

    Write-PlainTextFile -Path $notesPath -Lines @(
        '# Browser notes',
        ('User: {0}' -f $displayName),
        'Check Teams, Outlook, OneDrive, and Microsoft 365 web apps.',
        'Review one news site and one Microsoft Learn article.'
    )

    Write-PlainTextFile -Path $todoPath -Lines @(
        ('Review sign in events for {0}' -f $displayName),
        'Open the daily tracker',
        'Read a Teams chat',
        'Check Outlook inbox',
        'Browse one news page'
    )

    if (-not $PlanOnly) {
        Copy-Item -Path $briefingPath -Destination (Join-Path $todayRoot 'Archive\Daily-Briefing-copy.docx') -Force -ErrorAction SilentlyContinue
        Rename-Item -Path $todoPath -NewName 'task-list-reviewed.txt' -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path (Join-Path $todayRoot 'Projects\*') -DestinationPath (Join-Path $todayRoot 'Archive\Projects.zip') -Force -ErrorAction SilentlyContinue
    }

    return [pscustomobject]@{
        DayRoot = $todayRoot
        BriefingPath = $briefingPath
        TrackerPath = $trackerPath
        DeckPath = $deckPath
        NotesPath = $notesPath
    }
}

function Invoke-OfficeDesktopWorkload {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Paths
    )

    Open-DocumentWithShell -Path $Paths.BriefingPath
    Open-DocumentWithShell -Path $Paths.TrackerPath
    Open-DocumentWithShell -Path $Paths.DeckPath
    Open-DocumentWithShell -Path $Paths.NotesPath
}

function Invoke-BrowserSession {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Urls
    )

    $cleanUrls = @($Urls | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    if ($cleanUrls.Count -eq 0) {
        return
    }

    $windowsPerEngine = [Math]::Max(1, [int]$script:Config.BrowserWindowsPerEngine)
    $tabsPerWindow = [Math]::Max(1, [int]$script:Config.BrowserTabsPerWindow)
    $windowDwellSeconds = [Math]::Max(5, [int]$script:Config.BrowserWindowDwellSeconds)
    $profileDirectory = [string]$script:Config.BrowserProfileDirectory

    $engines = @($script:Config.BrowserEngines)
    if ($engines.Count -eq 0) {
        $engines = @('Edge')
    }

    $browserMap = @{}
    foreach ($engine in $engines) {
        switch -Regex ($engine) {
            '^edge$' {
                $path = Resolve-Executable -Paths @(
                    "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe",
                    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
                ) -CommandName 'msedge.exe'
                if ($null -ne $path) {
                    $browserMap['Edge'] = $path
                }
            }
            '^chrome$' {
                $path = Resolve-Executable -Paths @(
                    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
                    "$env:ProgramFiles (x86)\Google\Chrome\Application\chrome.exe"
                ) -CommandName 'chrome.exe'
                if ($null -ne $path) {
                    $browserMap['Chrome'] = $path
                }
            }
        }
    }

    if ($browserMap.Count -eq 0) {
        foreach ($url in $cleanUrls) {
            if ($PlanOnly) {
                Write-RunLog -Level 'PLAN' -Message ("open url {0}" -f $url)
            }
            else {
                Start-Process -FilePath $url | Out-Null
                Invoke-Pause -Seconds 2
            }
        }
        return
    }

    $targetUrlCount = $windowsPerEngine * $tabsPerWindow
    foreach ($browserName in $browserMap.Keys) {
        $browserPath = [string]$browserMap[$browserName]
        $urlPool = New-Object System.Collections.Generic.List[string]
        while ($urlPool.Count -lt $targetUrlCount) {
            $urlPool.Add([string](Get-Random -InputObject $cleanUrls))
        }

        $startedProcesses = @()
        for ($windowIndex = 0; $windowIndex -lt $windowsPerEngine; $windowIndex++) {
            $windowUrls = @()
            $start = $windowIndex * $tabsPerWindow
            for ($tabIndex = 0; $tabIndex -lt $tabsPerWindow; $tabIndex++) {
                $windowUrls += $urlPool[$start + $tabIndex]
            }

            if ($PlanOnly) {
                Write-RunLog -Level 'PLAN' -Message ("start {0} window {1} with {2} urls" -f $browserName, ($windowIndex + 1), $windowUrls.Count)
                foreach ($url in $windowUrls) {
                    Write-RunLog -Level 'PLAN' -Message ("browser url {0}" -f $url)
                }
                continue
            }

            $arguments = @('--new-window')
            if (-not [string]::IsNullOrWhiteSpace($profileDirectory)) {
                $arguments += ("--profile-directory={0}" -f $profileDirectory)
            }
            $arguments += $windowUrls

            $process = Start-Process -FilePath $browserPath -ArgumentList $arguments -PassThru -ErrorAction SilentlyContinue
            if ($null -ne $process) {
                $startedProcesses += $process
            }
            Invoke-Pause -Seconds 2
        }

        if ($PlanOnly) {
            continue
        }

        Invoke-Pause -Seconds $windowDwellSeconds
        foreach ($proc in $startedProcesses) {
            if ($null -ne $proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-RandomCountryUrlChunk {
    if (-not $script:Config.CountryUrls -or $script:Config.CountryUrls.Count -eq 0) {
        return @()
    }

    $sampleCount = [Math]::Min([int]$script:Config.CountryUrlSampleCount, [int]$script:Config.CountryUrls.Count)
    if ($sampleCount -le 0) {
        return @()
    }

    $picked = Get-Random -InputObject $script:Config.CountryUrls -Count $sampleCount
    $urls = foreach ($entry in $picked) {
        if ($entry -is [string]) {
            $entry
        }
        elseif ($null -ne $entry.Url) {
            $entry.Url
        }
    }

    return @($urls | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
}

function Get-RandomAiWebAppUrlChunk {
    if (-not $script:Config.AiWebAppUrls -or $script:Config.AiWebAppUrls.Count -eq 0) {
        return @()
    }

    $sampleCount = [Math]::Min([int]$script:Config.AiWebAppSampleCount, [int]$script:Config.AiWebAppUrls.Count)
    if ($sampleCount -le 0) {
        return @()
    }

    $picked = Get-Random -InputObject $script:Config.AiWebAppUrls -Count $sampleCount
    $urls = foreach ($entry in $picked) {
        if ($entry -is [string]) {
            $entry
        }
        elseif ($null -ne $entry.Url) {
            $entry.Url
        }
    }

    return @($urls | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
}

function Invoke-BrowserWorkload {
    $portalChunk = if ($script:SkipAuthenticatedWeb) { @() } else { @($script:Config.PortalUrls) }
    $publicChunk = @($script:Config.PublicUrls) + @(Get-RandomAiWebAppUrlChunk) + @(Get-RandomCountryUrlChunk)

    if ($portalChunk.Count -gt 0) {
        Invoke-BrowserSession -Urls $portalChunk
        Invoke-Pause -Seconds ([int]$script:Config.Wait.Medium)
    }

    if ($publicChunk.Count -gt 0) {
        Invoke-BrowserSession -Urls $publicChunk
    }
}

function Invoke-NoteTypingWorkload {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Paths,

        [Parameter(Mandatory = $true)]
        [int]$Round
    )

    $noteLine = Get-Random -InputObject $script:Config.TypingLines
    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = '{0}  Round {1}  {2}' -f $stamp, $Round, $noteLine
    $targets = @(
        $Paths.NotesPath,
        (Join-Path $Paths.DayRoot 'Projects\task-list-reviewed.txt')
    )

    foreach ($target in $targets) {
        if ($PlanOnly) {
            Write-RunLog -Level 'PLAN' -Message ("append note to {0}" -f $target)
            continue
        }

        if (-not (Test-Path $target)) {
            continue
        }

        Add-Content -Path $target -Value $line
    }
}

function Invoke-SharePathWorkload {
    if (-not $script:SharePathCandidates -or $script:SharePathCandidates.Count -eq 0) {
        Write-RunLog -Level 'WARN' -Message 'No share paths provided, skipping share path activity'
        return
    }

    foreach ($sharePath in $script:SharePathCandidates) {
        if ($PlanOnly) {
            Write-RunLog -Level 'PLAN' -Message ("touch share path {0}" -f $sharePath)
            continue
        }

        try {
            $probe = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', 'dir', $sharePath) -PassThru -WindowStyle Hidden
            $null = $probe.WaitForExit(15000)
            if (-not $probe.HasExited) {
                Stop-Process -Id $probe.Id -Force -ErrorAction SilentlyContinue
            }
            Write-RunLog -Message ("touched share path {0}" -f $sharePath)
        }
        catch {
            Write-RunLog -Level 'WARN' -Message ("share path probe failed for {0}" -f $sharePath)
        }
    }
}

function Test-IsSafeProbeTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    try {
        $ip = [System.Net.IPAddress]::Parse($Target)
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            return $false
        }

        $bytes = $ip.GetAddressBytes()
        $b0 = [int]$bytes[0]
        $b1 = [int]$bytes[1]
        $b2 = [int]$bytes[2]

        if ($b0 -eq 10) { return $true }
        if ($b0 -eq 172 -and $b1 -ge 16 -and $b1 -le 31) { return $true }
        if ($b0 -eq 192 -and $b1 -eq 168) { return $true }

        # RFC 5737 documentation ranges.
        if ($b0 -eq 192 -and $b1 -eq 0 -and $b2 -eq 2) { return $true }
        if ($b0 -eq 198 -and $b1 -eq 51 -and $b2 -eq 100) { return $true }
        if ($b0 -eq 203 -and $b1 -eq 0 -and $b2 -eq 113) { return $true }

        return $false
    }
    catch {
        return $false
    }
}

function Invoke-IpProbeWorkload {
    if (-not $script:Config.EnableIpProbeActions) {
        return
    }

    $targets = @($script:Config.IpProbeTargets | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        Write-RunLog -Level 'WARN' -Message 'No IP probe targets configured, skipping IP probe activity'
        return
    }

    $ports = @($script:Config.IpProbePorts | Where-Object { [int]$_ -ge 1 -and [int]$_ -le 65535 } | Select-Object -Unique)
    if ($ports.Count -eq 0) {
        $ports = @(443)
    }

    $sampleCount = [Math]::Min([int]$script:Config.IpProbeSampleCount, [int]$targets.Count)
    if ($sampleCount -le 0) {
        $sampleCount = [Math]::Min(3, [int]$targets.Count)
    }

    $pickedTargets = Get-Random -InputObject $targets -Count $sampleCount
    $timeoutMs = [Math]::Max(300, [int]$script:Config.IpProbeTimeoutMs)

    foreach ($target in $pickedTargets) {
        if (-not (Test-IsSafeProbeTarget -Target $target)) {
            Write-RunLog -Level 'WARN' -Message ("Skipping unsafe IP probe target {0}. Allowed ranges are private and RFC 5737 test ranges." -f $target)
            continue
        }

        $port = [int](Get-Random -InputObject $ports)

        if ($PlanOnly) {
            Write-RunLog -Level 'PLAN' -Message ("ip probe {0}:{1}" -f $target, $port)
            continue
        }

        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($target, $port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne($timeoutMs, $false)) {
                $client.EndConnect($async)
                Write-RunLog -Message ("ip probe connected {0}:{1}" -f $target, $port)
            }
            else {
                Write-RunLog -Message ("ip probe timeout {0}:{1}" -f $target, $port)
            }
        }
        catch {
            Write-RunLog -Message ("ip probe failed {0}:{1}" -f $target, $port)
        }
        finally {
            $client.Close()
            Invoke-Pause -Seconds 1
        }
    }
}

function Get-CombinedUrlPool {
    $portalChunk = if ($script:SkipAuthenticatedWeb) { @() } else { @($script:Config.PortalUrls) }
    $publicChunk = @($script:Config.PublicUrls) + @(Get-RandomAiWebAppUrlChunk) + @(Get-RandomCountryUrlChunk)
    return @($portalChunk + $publicChunk | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
}

function Invoke-WebRequestBurstWorkload {
    if (-not $script:Config.EnableWebRequestBurst) {
        return
    }

    $urlPool = Get-CombinedUrlPool
    if ($urlPool.Count -eq 0) {
        Write-RunLog -Level 'WARN' -Message 'No URLs available for web request burst activity'
        return
    }

    $requestCount = [Math]::Max(1, [int]$script:Config.WebRequestBurstCount)
    $timeoutSec = [Math]::Max(3, [int]$script:Config.WebRequestTimeoutSec)
    $userAgents = @(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/137.0.0.0 Safari/537.36'
    )

    for ($i = 0; $i -lt $requestCount; $i++) {
        $url = [string](Get-Random -InputObject $urlPool)
        if ($PlanOnly) {
            Write-RunLog -Level 'PLAN' -Message ("web request burst {0}" -f $url)
            continue
        }

        try {
            $agent = [string](Get-Random -InputObject $userAgents)
            Invoke-WebRequest -Uri $url -Method Get -TimeoutSec $timeoutSec -UserAgent $agent -UseBasicParsing -ErrorAction Stop | Out-Null
            Write-RunLog -Message ("web request success {0}" -f $url)
        }
        catch {
            Write-RunLog -Level 'WARN' -Message ("web request failed {0}" -f $url)
        }

        if (-not $PlanOnly) {
            Invoke-Pause -Seconds 1
        }
    }
}

function Invoke-DownloadWorkload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetFolder
    )

    foreach ($item in $script:Config.DownloadTargets) {
        $path = Join-Path $TargetFolder $item.FileName
        if ($PlanOnly) {
            Write-RunLog -Level 'PLAN' -Message ("download {0} to {1}" -f $item.Url, $path)
            continue
        }

        try {
            Invoke-WebRequest -Uri $item.Url -OutFile $path -UseBasicParsing
            Write-RunLog -Message ("downloaded {0}" -f $item.Url)
        }
        catch {
            Write-RunLog -Level 'WARN' -Message ("download failed for {0}" -f $item.Url)
        }
    }
}

function Invoke-FileBurstWorkload {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Paths,

        [Parameter(Mandatory = $true)]
        [int]$Round
    )

    $burstRoot = Join-Path $Paths.DayRoot 'Research\FileBurst'
    $archiveRoot = Join-Path $Paths.DayRoot 'Archive'
    $displayName = Get-UserDisplayLabel
    $shortcutUrl = if ($script:Config.PortalUrls.Count -gt 0) {
        $script:Config.PortalUrls[$script:Config.PortalUrls.Count - 1]
    }
    else {
        'https://www.microsoft365.com/'
    }
    $items = @(
        @{ Path = (Join-Path $burstRoot 'invoice-review.csv'); Lines = @('Date,Owner,Status', ((Get-Date -Format 'yyyy-MM-dd') + ',' + $displayName + ',Open')) },
        @{ Path = (Join-Path $burstRoot 'browser-session.json'); Lines = @('{', ('  "user": "{0}",' -f $displayName), ('  "round": {0}' -f $Round), '}') },
        @{ Path = (Join-Path $burstRoot 'telemetry-notes.xml'); Lines = @('<notes>', ('  <user>{0}</user>' -f $displayName), ('  <round>{0}</round>' -f $Round), '</notes>') },
        @{ Path = (Join-Path $burstRoot 'analyst-log.log'); Lines = @(('Round {0} file review for {1}' -f $Round, $displayName)) },
        @{ Path = (Join-Path $burstRoot 'macro-review.docm'); Lines = @('Macro enabled document placeholder for ASR and file telemetry.') },
        @{ Path = (Join-Path $burstRoot 'finance-update.xlsm'); Lines = @('Macro enabled workbook placeholder for ASR and file telemetry.') },
        @{ Path = (Join-Path $burstRoot 'review-script.js'); Lines = @('WScript.Echo("Daily simulation review")') },
        @{ Path = (Join-Path $burstRoot 'review-script.vbs'); Lines = @('WScript.Quit 0') },
        @{ Path = (Join-Path $burstRoot 'review-script.ps1'); Lines = @('Write-Output "Daily simulation review"') },
        @{ Path = (Join-Path $burstRoot 'review-script.cmd'); Lines = @('@echo off', 'echo Daily simulation review') },
        @{ Path = (Join-Path $burstRoot 'review-script.bat'); Lines = @('@echo off', 'echo Daily simulation review') },
        @{ Path = (Join-Path $burstRoot 'review-page.hta'); Lines = @('<html><head><title>Review</title></head><body>Daily simulation review</body></html>') },
        @{ Path = (Join-Path $burstRoot 'team-site.url'); Lines = @('[InternetShortcut]', ('URL={0}' -f $shortcutUrl)) }
    )

    foreach ($item in $items) {
        Write-PlainTextFile -Path $item.Path -Lines $item.Lines
    }

    if ($PlanOnly) {
        Write-RunLog -Level 'PLAN' -Message ("copy file burst items into {0}" -f $archiveRoot)
        Write-RunLog -Level 'PLAN' -Message ("compress file burst items into archive zip")
        return
    }

    New-Item -ItemType Directory -Path $archiveRoot -Force | Out-Null
    Copy-Item -Path (Join-Path $burstRoot 'invoice-review.csv') -Destination (Join-Path $archiveRoot ('invoice-review-round-{0}.csv' -f $Round)) -Force -ErrorAction SilentlyContinue
    Move-Item -Path (Join-Path $burstRoot 'analyst-log.log') -Destination (Join-Path $burstRoot ('analyst-log-round-{0}.log' -f $Round)) -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $burstRoot '*') -DestinationPath (Join-Path $archiveRoot ('file-burst-round-{0}.zip' -f $Round)) -Force -ErrorAction SilentlyContinue
}

function Invoke-AsrTelemetryWorkload {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Paths
    )

    $asrRoot = Join-Path $Paths.DayRoot 'Research\ASR'
    $statusPath = Join-Path $asrRoot 'asr-status.csv'
    $probeScript = Join-Path $asrRoot 'encoded-probe.ps1'
    $probeVbs = Join-Path $asrRoot 'benign-check.vbs'

    Write-PlainTextFile -Path $probeScript -Lines @('Write-Output "Daily ASR encoded probe"')
    Write-PlainTextFile -Path $probeVbs -Lines @('WScript.Quit 0')

    $mpPreference = Get-Command -Name 'Get-MpPreference' -ErrorAction SilentlyContinue
    if ($null -eq $mpPreference) {
        Write-RunLog -Level 'WARN' -Message 'Defender preference cmdlet not found, skipping ASR status snapshot'
    }
    elseif ($PlanOnly) {
        Write-RunLog -Level 'PLAN' -Message ("export ASR status to {0}" -f $statusPath)
    }
    else {
        New-Item -ItemType Directory -Path $asrRoot -Force | Out-Null
        $preferences = Get-MpPreference
        $report = @()
        if ($preferences.AttackSurfaceReductionRules_Ids) {
            for ($index = 0; $index -lt $preferences.AttackSurfaceReductionRules_Ids.Count; $index++) {
                $ruleId = $preferences.AttackSurfaceReductionRules_Ids[$index]
                $ruleAction = $preferences.AttackSurfaceReductionRules_Actions[$index]
                $status = switch ($ruleAction) {
                    0 { 'Not Configured' }
                    1 { 'Enabled Block' }
                    2 { 'Audit Mode' }
                    6 { 'Warn Mode' }
                    default { 'Unknown' }
                }
                $report += [pscustomobject]@{
                    RuleId = $ruleId
                    Status = $status
                }
            }
        }
        $report | Export-Csv -Path $statusPath -NoTypeInformation -Encoding UTF8
        Write-RunLog -Message ("saved ASR status snapshot to {0}" -f $statusPath)
    }

    if (-not $script:Config.EnableAsrProbeActions) {
        return
    }

    $encodedBytes = [System.Text.Encoding]::Unicode.GetBytes('Write-Output "Daily ASR encoded probe"')
    $encodedCommand = [Convert]::ToBase64String($encodedBytes)

    if ($PlanOnly) {
        Write-RunLog -Level 'PLAN' -Message 'launch benign encoded PowerShell probe for ASR and process telemetry'
        Write-RunLog -Level 'PLAN' -Message 'launch benign cscript probe for ASR and process telemetry'
        return
    }

    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-EncodedCommand', $encodedCommand) -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
        Write-RunLog -Message 'launched benign encoded PowerShell probe'
    }
    catch {
        Write-RunLog -Level 'WARN' -Message 'PowerShell encoded probe did not run'
    }

    try {
        Start-Process -FilePath 'cscript.exe' -ArgumentList @('//nologo', $probeVbs) -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
        Write-RunLog -Message 'launched benign cscript probe'
    }
    catch {
        Write-RunLog -Level 'WARN' -Message 'cscript probe did not run'
    }
}

function Invoke-AppLaunchWorkload {
    $teams = Resolve-Executable -Paths @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Teams\current\Teams.exe'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Teams\Update.exe'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\ms-teams.exe')
    )

    $outlook = Resolve-Executable -Paths @(
        "$env:ProgramFiles\Microsoft Office\root\Office16\OUTLOOK.EXE",
        "$env:ProgramFiles (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE"
    ) -CommandName 'outlook.exe'

    $oneDrive = Resolve-Executable -Paths @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe'),
        "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe"
    ) -CommandName 'OneDrive.exe'

    foreach ($app in @(
            @{ Name = 'Teams'; Path = $teams; Args = @() },
            @{ Name = 'Outlook'; Path = $outlook; Args = @('/recycle') },
            @{ Name = 'OneDrive'; Path = $oneDrive; Args = @('/background') }
        )) {
        if ([string]::IsNullOrWhiteSpace([string]$app.Path)) {
            Write-RunLog -Level 'WARN' -Message ("{0} not found" -f $app.Name)
            continue
        }

        if ($PlanOnly) {
            Write-RunLog -Level 'PLAN' -Message ("launch {0}" -f $app.Name)
            continue
        }

        Start-Process -FilePath $app.Path -ArgumentList $app.Args -ErrorAction SilentlyContinue | Out-Null
        Write-RunLog -Message ("launched {0}" -f $app.Name)
        Invoke-Pause -Seconds 4
    }
}

function Invoke-OutlookMailWorkload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AttachmentFolder
    )

    $outlook = Get-OutlookApplication
    if ($null -eq $outlook) {
        return
    }

    try {
        $recipients = @()
        if ($script:Config.MailRecipients -and $script:Config.MailRecipients.Count -gt 0) {
            $recipients = @($script:Config.MailRecipients | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
        }
        if ($recipients.Count -eq 0) {
            $primaryRecipient = Get-OutlookPrimaryAddress -OutlookApplication $outlook
            if (-not [string]::IsNullOrWhiteSpace([string]$primaryRecipient)) {
                $recipients = @($primaryRecipient)
            }
        }
        if ($recipients.Count -eq 0) {
            Write-RunLog -Level 'WARN' -Message 'Skipping Outlook mail because no mailbox address was found'
            return
        }

        $displayName = Get-UserDisplayLabel
        $mailBurstCount = [Math]::Max(2, [int]$script:Config.MailBurstCount)
        $mailTemplates = @(
            @{
                Subject = ('Daily cloud routine status for {0}' -f $displayName)
                Body = ('Quick note to create normal Outlook telemetry for {0}. Review https://www.microsoft365.com and https://outlook.office.com/mail/.' -f $displayName)
                Attachment = $null
            },
            @{
                Subject = ('Daily cloud routine attachment for {0}' -f $displayName)
                Body = 'Attaching the daily briefing for routine activity. Related link: https://learn.microsoft.com/'
                Attachment = (Join-Path $AttachmentFolder 'Projects\Daily-Briefing.docx')
            },
            @{
                Subject = ('Daily tracker export for {0}' -f $displayName)
                Body = 'Sharing tracker workbook and one reference URL: https://www.microsoft.com/security/blog/'
                Attachment = (Join-Path $AttachmentFolder 'Finance\Daily-Tracker.xlsx')
            },
            @{
                Subject = ('Project archive review {0}' -f (Get-Date -Format 'yyyy-MM-dd'))
                Body = 'Archive review item with attachment and mail URL payload for telemetry.'
                Attachment = (Join-Path $AttachmentFolder 'Archive\Projects.zip')
            }
        )

        for ($mailIndex = 1; $mailIndex -le $mailBurstCount; $mailIndex++) {
            $mailTemplate = Get-Random -InputObject $mailTemplates
            foreach ($recipient in $recipients) {
                if ($PlanOnly) {
                    Write-RunLog -Level 'PLAN' -Message ("send Outlook mail {0} to {1}" -f $mailTemplate.Subject, $recipient)
                    continue
                }

                $mail = $outlook.CreateItem(0)
                $mail.To = $recipient
                $mail.Subject = ('{0} #{1}' -f $mailTemplate.Subject, $mailIndex)
                $mail.Body = $mailTemplate.Body
                if ($mailTemplate.Attachment -and (Test-Path $mailTemplate.Attachment)) {
                    $null = $mail.Attachments.Add($mailTemplate.Attachment)
                }
                $mail.Save()
                $mail.Send()
                Write-RunLog -Message ("sent Outlook mail {0} to {1}" -f $mail.Subject, $recipient)
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($mail)
                Invoke-Pause -Seconds 3
            }
        }
    }
    catch {
        Write-RunLog -Level 'WARN' -Message ("Outlook send failed: {0}" -f $_.Exception.Message)
    }
    finally {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook)
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

function Invoke-EndpointCommandBurstWorkload {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Paths
    )

    if (-not $script:Config.EnableEndpointCommandBurst) {
        return
    }

    $burstRoot = Join-Path $Paths.DayRoot 'Research\EndpointCommandBurst'
    $count = [Math]::Max(1, [int]$script:Config.EndpointCommandBurstCount)
    $commandCatalog = @(
        @{ Name = 'whoami'; FilePath = 'cmd.exe'; Args = @('/c', 'whoami /all') },
        @{ Name = 'dnslookup'; FilePath = 'cmd.exe'; Args = @('/c', 'nslookup www.microsoft.com') },
        @{ Name = 'routeprint'; FilePath = 'cmd.exe'; Args = @('/c', 'route print') },
        @{ Name = 'tasklist'; FilePath = 'cmd.exe'; Args = @('/c', 'tasklist') },
        @{ Name = 'ipconfig'; FilePath = 'cmd.exe'; Args = @('/c', 'ipconfig /all') },
        @{ Name = 'netstat'; FilePath = 'cmd.exe'; Args = @('/c', 'netstat -ano') },
        @{ Name = 'regquery'; FilePath = 'reg.exe'; Args = @('query', 'HKCU\Software\Microsoft\Office') },
        @{ Name = 'powershellmods'; FilePath = 'powershell.exe'; Args = @('-NoProfile', '-Command', 'Get-Module -ListAvailable | Select-Object -First 25 Name,Version') },
        @{ Name = 'certstore'; FilePath = 'powershell.exe'; Args = @('-NoProfile', '-Command', 'Get-ChildItem Cert:\CurrentUser\My | Select-Object -First 10 Subject,Thumbprint') }
    )

    for ($run = 1; $run -le $count; $run++) {
        $chosen = Get-Random -InputObject $commandCatalog
        $outputPath = Join-Path $burstRoot ("{0}-{1}.txt" -f $chosen.Name, $run)

        if ($PlanOnly) {
            Write-RunLog -Level 'PLAN' -Message ("endpoint command burst {0}" -f $chosen.Name)
            continue
        }

        New-Item -ItemType Directory -Path $burstRoot -Force | Out-Null
        try {
            $result = & $chosen.FilePath @($chosen.Args) 2>&1
            if ($null -eq $result) {
                Set-Content -Path $outputPath -Value ('{0} returned no output' -f $chosen.Name) -Encoding UTF8
            }
            else {
                $result | Out-File -FilePath $outputPath -Encoding UTF8
            }
            Write-RunLog -Message ("endpoint command burst ran {0}" -f $chosen.Name)
        }
        catch {
            Write-RunLog -Level 'WARN' -Message ("endpoint command burst failed {0}" -f $chosen.Name)
        }

        Invoke-Pause -Seconds 1
    }
}

function Invoke-SentinelValidation {
    if (-not $script:ValidateSentinel) {
        return
    }

    $az = Get-Command -Name 'az' -ErrorAction SilentlyContinue
    if ($null -eq $az) {
        Write-RunLog -Level 'WARN' -Message 'Azure CLI not found, skipping Sentinel validation'
        return
    }

    $queries = @(
        @{ Name = 'DeviceNetworkEvents'; Query = "DeviceNetworkEvents | where Timestamp > ago(2h) | where RemoteUrl has_any ('office.com','microsoft365.com','teams.microsoft.com','outlook.office.com') | count" },
        @{ Name = 'DeviceProcessEvents'; Query = "DeviceProcessEvents | where Timestamp > ago(2h) | where FileName has_any ('msedge.exe','WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE','OUTLOOK.EXE') | count" },
        @{ Name = 'EmailEvents'; Query = "EmailEvents | where Timestamp > ago(4h) | where Subject has 'Daily cloud routine' | count" },
        @{ Name = 'DeviceFileEvents'; Query = "DeviceFileEvents | where Timestamp > ago(2h) | where FileName has_any ('macro-review.docm','finance-update.xlsm','review-script.js','review-script.vbs','encoded-probe.ps1') | count" }
    )

    foreach ($query in $queries) {
        try {
            $output = az monitor log-analytics query --workspace $script:Config.WorkspaceId --analytics-query $query.Query -o json 2>$null
            $count = 0
            if ($output) {
                $json = $output | ConvertFrom-Json
                if ($json -and $json[0].Count) {
                    $count = [int]$json[0].Count
                }
                elseif ($json -and $json[0].'count_') {
                    $count = [int]$json[0].'count_'
                }
            }
            Write-RunLog -Message ("validation {0}: {1}" -f $query.Name, $count)
        }
        catch {
            Write-RunLog -Level 'WARN' -Message ("validation failed for {0}" -f $query.Name)
        }
    }
}

function Get-ActivityPlan {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Paths,

        [Parameter(Mandatory = $true)]
        [int]$Round
    )

    $null = $Paths.DayRoot

    $actions = @(
        @{ Name = 'desktop Office activity'; Action = { Invoke-OfficeDesktopWorkload -Paths $Paths } },
        @{ Name = 'download activity'; Action = { Invoke-DownloadWorkload -TargetFolder (Join-Path $Paths.DayRoot 'Research') } },
        @{ Name = 'file burst activity'; Action = { Invoke-FileBurstWorkload -Paths $Paths -Round $Round } },
        @{ Name = 'ASR telemetry activity'; Action = { Invoke-AsrTelemetryWorkload -Paths $Paths } },
        @{ Name = 'endpoint command burst activity'; Action = { Invoke-EndpointCommandBurstWorkload -Paths $Paths } },
        @{ Name = 'web request burst activity'; Action = { Invoke-WebRequestBurstWorkload } },
        @{ Name = 'IP probe activity'; Action = { Invoke-IpProbeWorkload } },
        @{ Name = 'note typing activity'; Action = { Invoke-NoteTypingWorkload -Paths $Paths -Round $Round } }
    )

    if (-not $script:SkipBrowser) {
        $actions += @{ Name = 'browser activity'; Action = { Invoke-BrowserWorkload } }
    }

    if (-not $script:SkipAppLaunches) {
        $actions += @{ Name = 'desktop app launches'; Action = { Invoke-AppLaunchWorkload } }
    }

    if ($script:SharePathCandidates.Count -gt 0) {
        $actions += @{ Name = 'share path activity'; Action = { Invoke-SharePathWorkload } }
    }

    $mailSendProbability = [Math]::Max(0, [Math]::Min(100, [int]$script:Config.MailSendProbability))
    if (-not $script:SkipOutlookMail -and ($Round -eq 1 -or (Get-Random -Minimum 0 -Maximum 100) -lt $mailSendProbability)) {
        $actions += @{ Name = 'Outlook mail activity'; Action = { Invoke-OutlookMailWorkload -AttachmentFolder $Paths.DayRoot } }
    }

    return ($actions | Sort-Object { Get-Random })
}

function Invoke-ActivityLoop {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Paths
    )

    $round = 1
    $deadline = if ($script:DurationMinutes -gt 0) {
        (Get-Date).AddMinutes($script:DurationMinutes)
    }
    else {
        (Get-Date)
    }

    do {
        Write-RunLog -Message ("round {0} start" -f $round)
        $actions = Get-ActivityPlan -Paths $Paths -Round $round
        foreach ($activity in $actions) {
            Invoke-Step -Name $activity.Name -Action $activity.Action
            if ($script:DurationMinutes -gt 0 -and (Get-Date) -ge $deadline) {
                break
            }
        }
        Write-RunLog -Message ("round {0} end" -f $round)
        $round++
    }
    while ($script:DurationMinutes -gt 0 -and (Get-Date) -lt $deadline)
}

Initialize-Log
$resolvedConfigPath = Resolve-DefaultConfigPath
$resolvedProfilePath = Resolve-DefaultProfilePath
Import-SimulationInput -JsonConfigPath $resolvedConfigPath -JsonProfilePath $resolvedProfilePath
Write-RunLog -Message ("run mode: {0}" -f ($(if ($PlanOnly) { 'plan only' } else { 'live' })))
Write-RunLog -Message 'This script is intended for a signed in user session'
Write-RunLog -Message ("duration minutes: {0}" -f $script:DurationMinutes)
Write-RunLog -Message ("user label: {0}" -f (Get-UserDisplayLabel))
Write-RunLog -Message ("unattended mode: {0}" -f $Unattended)
Write-RunLog -Message ("skip browser: {0}" -f $script:SkipBrowser)
Write-RunLog -Message ("skip authenticated web: {0}" -f $script:SkipAuthenticatedWeb)
Write-RunLog -Message ("skip Outlook mail: {0}" -f $script:SkipOutlookMail)
Write-RunLog -Message ("skip app launches: {0}" -f $script:SkipAppLaunches)

$activityRoot = Resolve-OneDrivePath
$workloadPaths = $null

Invoke-Step -Name 'file and OneDrive activity' -Action {
    $script:workloadPaths = Invoke-OneDriveWorkload -RootPath $activityRoot
}

if ($null -ne $script:workloadPaths) {
    Invoke-ActivityLoop -Paths $script:workloadPaths
}

Invoke-Step -Name 'optional Sentinel validation' -Action {
    Invoke-SentinelValidation
}

Write-RunLog -Message ("log path: {0}" -f $script:LogPath)
exit 0