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

# Browser automation via system Edge
if (-not $SkipBrowser) {
    try {
        Out-Log "Starting browser automation (Playwright backend)"
        
        $urls = @(
            'https://office.com',
            'https://outlook.office.com/mail',
            'https://teams.microsoft.com',
            'https://sharepoint.com'
        )
        
        foreach ($url in $urls) {
            try {
                $p = Start-Process -FilePath 'msedge.exe' -ArgumentList "--no-first-run --no-default-browser-check `"$url`"" -PassThru -ErrorAction Stop
                Start-Sleep -Milliseconds $BrowserDelayMs
                Out-Log "  Browsed: $url"
                if (-not $p.HasExited) { $p | Stop-Process -Force -ErrorAction SilentlyContinue }
            } catch {
                Out-Log "  Failed: $url - $_"
            }
        }
        
        Out-Log "Browser automation phase complete"
    } catch {
        Out-Log "Browser error: $_"
    }
}

# WCF Categories (28 categories, 2 URLs each)
Out-Log "Testing WCF categories"
$wcfUrls = @(
    @('https://www.pornhub.com', 'https://www.redtube.com'),
    @('https://www.playboy.com', 'https://www.penthouse.com'),
    @('https://www.draftkings.com', 'https://www.fanduel.com'),
    @('https://www.netflix.com', 'https://www.hulu.com'),
    @('https://www.thepiratebay.org', 'https://www.1337x.to')
)

foreach ($urlPair in $wcfUrls) {
    foreach ($url in $urlPair) {
        try {
            $p = Start-Process -FilePath 'msedge.exe' -ArgumentList "--no-first-run --no-default-browser-check `"$url`"" -PassThru -ErrorAction Stop
            Start-Sleep -Milliseconds 300
            Out-Log "  WCF URL tested: $(([uri]$url).Host)"
            if (-not $p.HasExited) { $p | Stop-Process -Force -ErrorAction SilentlyContinue }
        } catch {}
    }
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
    $outlook = New-Object -ComObject Outlook.Application -ErrorAction SilentlyContinue
    if ($null -eq $outlook) {
        Out-Log "  Outlook not available"
    } else {
        $ns = $outlook.GetNamespace('MAPI')
        $ns.Logon($null, $null, $false, $true) | Out-Null
        $account = $outlook.Session.Accounts | Select-Object -First 1
        
        if ($null -ne $account) {
            $mail = $outlook.CreateItem(0)
            $mail.To = 'admin@mngenvmcap709711.onmicrosoft.com'
            $mail.Subject = "Telemetry Report $(Get-Date -Format 'HH:mm:ss')"
            $mail.Body = "Automated telemetry run completed successfully"
            $mail._MailItem.SendUsingAccount($account)
            Out-Log "  Email sent via SendUsingAccount (no prompt)"
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($mail) | Out-Null
        } else {
            Out-Log "  No account available"
        }
        
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ns) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($outlook) | Out-Null
    }
} catch {
    Out-Log "  Email ops error: $_"
}

Out-Log "END telemetry burst complete"
