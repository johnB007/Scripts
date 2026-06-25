<#
.SYNOPSIS
    Local validator for MDE Live Response PowerShell scripts.

.DESCRIPTION
    Runs four checks before you upload a script to the Live Response library:
      1. Syntax parse. Confirms the file is valid PowerShell.
      2. PSScriptAnalyzer. Uses PSScriptAnalyzerSettings.psd1 in this repo.
      3. Interactive cmdlet scan. Flags cmdlets that hang a non interactive
         Live Response session, such as Read-Host and Out-GridView.
      4. Optional smoke run. With -Execute, runs the script in a separate
         Windows PowerShell 5.1 process, non interactive, with a timeout, and
         reports the exit code.

    Run from the Scripts repo root.

.PARAMETER Path
    Path to the script to validate.

.PARAMETER Execute
    Also run the script in a child process to confirm it executes and exits 0.

.PARAMETER Parameters
    String of arguments to pass to the script when -Execute is used, for
    example "-Minutes 30".

.PARAMETER TimeoutSeconds
    Maximum seconds the smoke run may take before it is stopped. Default 120.

.EXAMPLE
    .\Test-LRScript.ps1 -Path ".\Live Response\Get-ProcessTree.ps1"

.EXAMPLE
    .\Test-LRScript.ps1 -Path ".\Live Response\Get-ProcessTree.ps1" -Execute -Parameters "-Minutes 30"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [switch]$Execute,

    [string]$Parameters = '',

    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'
$failed = $false

function Write-Step {
    param([string]$Message)
    Write-Host ''
    Write-Host ("=== {0} ===" -f $Message) -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    Write-Host ("PASS: {0}" -f $Message) -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host ("FAIL: {0}" -f $Message) -ForegroundColor Red
    $script:failed = $true
}

# Resolve the script path
if (-not (Test-Path -LiteralPath $Path)) {
    Write-Fail ("Script not found: {0}" -f $Path)
    exit 1
}
$scriptFile = (Resolve-Path -LiteralPath $Path).Path
Write-Host ("Validating: {0}" -f $scriptFile) -ForegroundColor White

# 1. Syntax parse
Write-Step 'Syntax parse'
$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($scriptFile, [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors -and $parseErrors.Count -gt 0) {
    foreach ($e in $parseErrors) {
        Write-Fail ("Line {0}: {1}" -f $e.Extent.StartLineNumber, $e.Message)
    }
}
else {
    Write-Pass 'No syntax errors'
}

# 2. PSScriptAnalyzer
Write-Step 'PSScriptAnalyzer'
if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Write-Fail 'PSScriptAnalyzer is not installed. Run: Install-Module PSScriptAnalyzer -Scope CurrentUser'
}
else {
    Import-Module PSScriptAnalyzer -ErrorAction Stop
    $settingsPath = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
    $analyzerArgs = @{ Path = $scriptFile }
    if (Test-Path -LiteralPath $settingsPath) {
        $analyzerArgs['Settings'] = $settingsPath
    }
    $findings = Invoke-ScriptAnalyzer @analyzerArgs
    if ($findings -and $findings.Count -gt 0) {
        $findings | Sort-Object Severity, Line |
            Select-Object Severity, Line, RuleName, Message |
            Format-Table -AutoSize | Out-String | Write-Host
        $errorCount = ($findings | Where-Object Severity -eq 'Error').Count
        if ($errorCount -gt 0) {
            Write-Fail ("{0} analyzer error(s) found" -f $errorCount)
        }
        else {
            Write-Host ("{0} warning(s) found. Review before upload." -f $findings.Count) -ForegroundColor Yellow
        }
    }
    else {
        Write-Pass 'No analyzer findings'
    }
}

# 3. Interactive cmdlet scan
Write-Step 'Interactive cmdlet scan'
$blocked = @(
    'Read-Host', 'Pause', 'Get-Credential', 'Out-GridView',
    'Start-Transcript', 'Wait-Event', 'Read-Console'
)
$content = Get-Content -LiteralPath $scriptFile -Raw
$hits = @()
foreach ($cmd in $blocked) {
    if ($content -match ("(?im)\b{0}\b" -f [regex]::Escape($cmd))) {
        $hits += $cmd
    }
}
# GUI namespaces that will not work in Live Response
foreach ($ns in @('System.Windows.Forms', 'System.Windows.MessageBox', 'Show-Command')) {
    if ($content -match [regex]::Escape($ns)) {
        $hits += $ns
    }
}
if ($hits.Count -gt 0) {
    Write-Fail ("Interactive or GUI calls found: {0}" -f ($hits -join ', '))
}
else {
    Write-Pass 'No interactive or GUI calls'
}

# 4. Optional smoke run in a child Windows PowerShell 5.1 process
if ($Execute) {
    Write-Step 'Smoke run (child process, non interactive)'
    $psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $psExe)) {
        Write-Fail 'Windows PowerShell 5.1 not found for smoke run'
    }
    else {
        # Quote the script path so spaces in folder names like "Live Response"
        # do not break the -File argument.
        $argList = @(
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-File', ('"{0}"' -f $scriptFile)
        )
        if ($Parameters.Trim().Length -gt 0) {
            $argList += $Parameters.Trim().Split(' ')
        }

        $stdOut = New-TemporaryFile
        $stdErr = New-TemporaryFile
        try {
            $proc = Start-Process -FilePath $psExe -ArgumentList $argList `
                -NoNewWindow -PassThru `
                -RedirectStandardOutput $stdOut.FullName `
                -RedirectStandardError $stdErr.FullName

            if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
                try { $proc.Kill() } catch { }
                Write-Fail ("Smoke run exceeded {0}s timeout and was stopped" -f $TimeoutSeconds)
            }
            else {
                $out = Get-Content -LiteralPath $stdOut.FullName -Raw
                $err = Get-Content -LiteralPath $stdErr.FullName -Raw
                if ($out) {
                    Write-Host '--- script output ---' -ForegroundColor DarkGray
                    Write-Host $out
                }
                if ($err) {
                    Write-Host '--- error stream ---' -ForegroundColor DarkGray
                    Write-Host $err -ForegroundColor Yellow
                }
                if ($proc.ExitCode -eq 0) {
                    Write-Pass 'Script exited with code 0'
                }
                else {
                    Write-Fail ("Script exited with code {0}" -f $proc.ExitCode)
                }
            }
        }
        finally {
            Remove-Item -LiteralPath $stdOut.FullName, $stdErr.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

# Summary
Write-Host ''
if ($failed) {
    Write-Host 'RESULT: NOT READY. Fix the items above before uploading to Live Response.' -ForegroundColor Red
    exit 1
}
else {
    Write-Host 'RESULT: READY. Safe to upload to the Live Response library.' -ForegroundColor Green
    exit 0
}
