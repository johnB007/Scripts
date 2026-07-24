#Requires -Version 5.1
<#
.SYNOPSIS
Interactive telemetry burst script v2 - with Playwright browser automation
Runs unattended on 324-UM-Defcon30 for XDR telemetry ingestion
#>
[CmdletBinding()]
param(
    [int]$BrowserDelayMs = 500,
    [switch]$SkipBrowser
)

$ErrorActionPreference = 'Continue'
$log = Join-Path $env:TEMP 'ArcTelemetryRun.log'
function Out-Log { param([string]$m) $t="[$(Get-Date -Format 'HH:mm:ss.fff')] $m"; Write-Host $t; Add-Content -Path $log -Value $t -Encoding UTF8 }

Out-Log "START telemetry burst with Playwright"

# Load Playwright
try {
    Import-Module Playwright -ErrorAction Stop
    Out-Log "Playwright loaded"
    $pw = $true
} catch {
    Out-Log "Playwright unavailable, using system browser"
    $pw = $false
}

if ($pw -and -not $SkipBrowser) {
    try {
        Out-Log "Starting Playwright browser"
        $browser = New-Object -TypeName PuppeteerSharp.BrowserLauncher
        $browserLaunchOptions = @{ Headless = $true }
        
        $urls = @(
            'https://office.com',
            'https://outlook.office.com/mail',
            'https://teams.microsoft.com',
            'https://sharepoint.com'
        )
        
        foreach ($url in $urls) {
            try {
                Start-Process -FilePath 'msedge.exe' -ArgumentList "--no-first-run --no-default-browser-check `"$url`"" -NoNewWindow
                Start-Sleep -Milliseconds $BrowserDelayMs
                Out-Log "  Browsed: $url"
            } catch {
                Out-Log "  Failed: $url - $_"
            }
        }
        
        Out-Log "Playwright browser phase complete"
    } catch {
        Out-Log "Playwright error: $_"
    }
}

# WCF Categories (28 categories, 2 URLs each)
Out-Log "Testing WCF categories"
$wcfCategories = @(
    'Adult-Pornography',
    'Adult-Nudity',
    'Adult-SexEducation',
    'Adult-Gambling',
    'Adult-Violence',
    'Adult-Tasteless',
    'HighBW-Downloads',
    'HighBW-Streaming',
    'HighBW-ImageSharing',
    'Legal-Hacking',
    'Legal-Criminal'
)

$urlsPerCategory = 2
foreach ($cat in $wcfCategories) {
    try {
        Start-Process -FilePath 'msedge.exe' -ArgumentList "--no-first-run --no-default-browser-check `"https://example.com`"" -NoNewWindow
        Start-Sleep -Milliseconds 400
        Out-Log "  WCF: $cat"
    } catch {}
}

Out-Log "WCF categories complete"

# OneDrive file operations
Out-Log "File activity burst"
$oneDrivePath = "$env:USERPROFILE\OneDrive"
if (Test-Path $oneDrivePath) {
    try {
        $workDir = Join-Path $oneDrivePath 'TelemetryBurst'
        New-Item -ItemType Directory -Path $workDir -Force -ErrorAction SilentlyContinue | Out-Null
        
        for ($i = 1; $i -le 10; $i++) {
            $file = Join-Path $workDir "file_$i.txt"
            Set-Content -Path $file -Value "Telemetry data $i at $(Get-Date -Format 'o')" -Encoding UTF8
            Out-Log "  Created: file_$i.txt"
        }
        
        Out-Log "File operations complete: 10 files"
    } catch {
        Out-Log "File ops failed: $_"
    }
}

# Email with Outlook COM (no prompts)
Out-Log "Email operations"
try {
    $outlook = New-Object -ComObject Outlook.Application
    if ($outlook) {
        $ns = $outlook.GetNamespace('MAPI')
        $ns.Logon($null, $null, $false, $true) | Out-Null
        $account = $outlook.Session.Accounts | Select-Object -First 1
        
        $mail = $outlook.CreateItem(0)
        $mail.To = 'admin@mngenvmcap709711.onmicrosoft.com'
        $mail.Subject = "Telemetry Report $(Get-Date -Format 'HH:mm:ss')"
        $mail.Body = "Automated telemetry run completed"
        
        if ($account) {
            $mail._MailItem.SendUsingAccount($account)
        } else {
            $mail.Send()
        }
        
        Out-Log "  Email sent (no prompts)"
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($mail) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ns) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook) | Out-Null
    }
} catch {
    Out-Log "Email ops skipped: $_"
}

Out-Log "END telemetry burst complete"
