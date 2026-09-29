<#
.SYNOPSIS
    Generates controlled telemetry for the unauthorized AI workbook.
.DESCRIPTION
    Creates synthetic files and process activity, then sends header only web
    requests to selected AI services. No prompts, credentials, or file content
    are sent. Test artifacts are removed by default after activity is created.
.PARAMETER Remediate
    Confirms that telemetry generation is authorized.
.PARAMETER ExpectedDeviceName
    Device name guard. The default permits execution only on device 324.
.PARAMETER AllowAnyDevice
    Overrides the device name guard.
.PARAMETER RequestCount
    Number of header requests sent to each selected service.
.PARAMETER IncludePersistence
    Briefly creates and removes a test Run value for persistence telemetry.
.PARAMETER KeepArtifacts
    Retains synthetic files after the run.
.PARAMETER ArtifactHoldSeconds
    Minimum time to retain synthetic files before default cleanup.
.PARAMETER BrowserTraffic
    Opens selected AI service landing pages as visible tabs in Edge and Chrome.
.PARAMETER BrowserSiteLimit
    Maximum number of AI service landing pages visited in each browser.
.PARAMETER McpTest
    Generates bounded local and remote MCP telemetry without credentials.
.PARAMETER McpHoldSeconds
    Number of seconds the local MCP marker process remains active.
#>
[CmdletBinding()]
param(
    [Alias('Generate')]
    [switch]$Remediate,
    [string]$ExpectedDeviceName = '324-UM-DEFCON30',
    [switch]$AllowAnyDevice,
    [ValidateRange(1, 10)]
    [int]$RequestCount = 2,
    [switch]$IncludePersistence,
    [switch]$KeepArtifacts,
    [ValidateRange(0, 60)]
    [int]$ArtifactHoldSeconds = 20,
    [switch]$BrowserTraffic,
    [ValidateRange(1, 75)]
    [int]$BrowserSiteLimit = 75,
    [switch]$McpTest,
    [ValidateRange(30, 300)]
    [int]$McpHoldSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$device = $env:COMPUTERNAME
$utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

if (-not $Remediate) {
    Write-Output ("Device: {0}  UTC: {1}" -f $device, $utc)
    Write-Output 'No telemetry was generated. Run with -Remediate after authorization.'
    Write-Output 'Live Response example: run Invoke-AIWorkbookTelemetry.ps1 -parameters "-Remediate"'
    exit 0
}

if (-not $AllowAnyDevice -and $device -ine $ExpectedDeviceName) {
    Write-Error ("Device guard stopped execution. Expected {0}, found {1}." -f $ExpectedDeviceName, $device)
    exit 2
}

$runId = [Guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramData ("AIWorkbookTelemetryTest\{0}" -f $runId)
$secretDirectory = Join-Path $root 'secret'
$contextDirectory = Join-Path $root '.agents'
$reportPath = Join-Path $env:TEMP ("AIWorkbookTelemetry-{0}.json" -f $runId)
$runKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$runValueName = 'AIWorkbookTelemetryTest'
$runValueCreated = $false
$results = New-Object System.Collections.Generic.List[object]

function Add-TestResult {
    param(
        [string]$Category,
        [string]$Action,
        [string]$Status,
        [string]$Detail
    )

    $script:results.Add([pscustomobject]@{
        TimeUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Device = $script:device
        Category = $Category
        Action = $Action
        Status = $Status
        Detail = $Detail
    })
}

try {
    New-Item -ItemType Directory -Path $secretDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $contextDirectory -Force | Out-Null

    $contextPadding = 'X' * 8192
    $modelPadding = '0' * 1048576

    $syntheticFiles = @(
        [pscustomobject]@{ Path = (Join-Path $secretDirectory 'telemetry-test-secret.csv'); Content = "SyntheticId,Classification`r`n$runId,TestOnly"; Category = 'Exposure indicator' },
        [pscustomobject]@{ Path = (Join-Path $secretDirectory 'MANUAL-UPLOAD-TEST-ONLY.txt'); Content = "Synthetic upload test only.`r`nRunId=$runId`r`nNo production or sensitive data."; Category = 'Manual upload sample' },
        [pscustomobject]@{ Path = (Join-Path $root 'ollama-telemetry-test.exe'); Content = 'Synthetic installer marker. Not executable.'; Category = 'Local AI installer' },
        [pscustomobject]@{ Path = (Join-Path $root 'telemetry-model.gguf'); Content = "Synthetic model marker. Not a model.`r`n$modelPadding"; Category = 'Local AI model' },
        [pscustomobject]@{ Path = (Join-Path $contextDirectory 'AGENTS.md'); Content = "Synthetic agent instruction marker.`r`n$contextPadding"; Category = 'Agent context' },
        [pscustomobject]@{ Path = (Join-Path $contextDirectory 'CLAUDE.md'); Content = "Synthetic Claude context marker.`r`n$contextPadding"; Category = 'Agent context' },
        [pscustomobject]@{ Path = (Join-Path $contextDirectory 'mcp.json'); Content = ('{"servers":{"github":{"type":"http","url":"https://api.githubcopilot.com/mcp/"},"atlassian":{"type":"http","url":"https://mcp.atlassian.com/v1/mcp/authv2"}},"telemetryTest":true,"padding":"' + $contextPadding + '"}'); Category = 'MCP context' }
    )

    foreach ($file in $syntheticFiles) {
        [System.IO.File]::WriteAllText($file.Path, $file.Content, [System.Text.Encoding]::UTF8)
        Add-TestResult -Category $file.Category -Action 'Create synthetic file' -Status 'Created' -Detail $file.Path
    }

    $cmdPath = Join-Path $env:WINDIR 'System32\cmd.exe'
    $cmdArguments = '/d /c echo mcp modelcontextprotocol telemetry test openclaw aider claude-code'
    $cmdProcess = Start-Process -FilePath $cmdPath -ArgumentList $cmdArguments -WindowStyle Hidden -PassThru -Wait
    Add-TestResult -Category 'Agent and MCP' -Action 'Create process event' -Status ("ExitCode {0}" -f $cmdProcess.ExitCode) -Detail $cmdArguments

    if ($McpTest) {
        $nodeCommand = Get-Command 'node.exe' -ErrorAction SilentlyContinue
        if ($nodeCommand) {
            $mcpScriptPath = Join-Path $root 'mcp-telemetry-test.js'
            $mcpScript = @"
const http = require('http');
const holdSeconds = Number(process.argv[2] || 90);
const server = http.createServer((request, response) => {
  response.writeHead(200, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify({ jsonrpc: '2.0', result: { name: 'MCP Telemetry Test' }, id: 1 }));
});
server.listen(0, '127.0.0.1');
setTimeout(() => server.close(() => process.exit(0)), holdSeconds * 1000);
"@
            [System.IO.File]::WriteAllText($mcpScriptPath, $mcpScript, [System.Text.Encoding]::UTF8)
            $mcpArguments = @($mcpScriptPath, $McpHoldSeconds, 'modelcontextprotocol', 'mcp.json')
            $mcpProcess = Start-Process -FilePath $nodeCommand.Source -ArgumentList $mcpArguments -WindowStyle Hidden -PassThru
            Write-Output ("Started bounded MCP marker process {0} for {1} seconds." -f $mcpProcess.Id, $McpHoldSeconds)
            Add-TestResult -Category 'Agent and MCP' -Action 'Start bounded MCP marker' -Status ("ProcessId {0}" -f $mcpProcess.Id) -Detail ("HoldSeconds {0}" -f $McpHoldSeconds)
        }
        else {
            Write-Output 'Node.js was not found. The sustained MCP marker was skipped.'
            Add-TestResult -Category 'Agent and MCP' -Action 'Start bounded MCP marker' -Status 'Skipped' -Detail 'node.exe was not found.'
        }
    }

    if ($IncludePersistence) {
        $persistenceTarget = Join-Path $root 'ollama-telemetry-test.exe'
        New-ItemProperty -Path $runKey -Name $runValueName -Value $persistenceTarget -PropertyType String -Force | Out-Null
        $runValueCreated = $true
        Add-TestResult -Category 'Persistence' -Action 'Create test Run value' -Status 'Created' -Detail $persistenceTarget
        Remove-ItemProperty -Path $runKey -Name $runValueName -Force
        $runValueCreated = $false
        Add-TestResult -Category 'Persistence' -Action 'Remove test Run value' -Status 'Removed' -Detail $runValueName
    }

    $curlPath = Join-Path $env:WINDIR 'System32\curl.exe'
    if (Test-Path -LiteralPath $curlPath) {
        $targets = @(
            'https://chatgpt.com/',
            'https://claude.ai/',
            'https://perplexity.ai/',
            'https://copilot.microsoft.com/'
        )

        if ($McpTest) {
            $targets += @(
                'https://api.githubcopilot.com/mcp/',
                'https://mcp.atlassian.com/v1/mcp/authv2'
            )
        }

        Write-Output ("Sending {0} header requests to each of {1} AI services." -f $RequestCount, $targets.Count)
        foreach ($target in $targets) {
            Write-Output ("Requesting {0}" -f $target)
            for ($request = 1; $request -le $RequestCount; $request++) {
                $curlArguments = @(
                    '--head',
                    '--silent',
                    '--show-error',
                    '--max-time', '12',
                    '--output', 'NUL',
                    '--user-agent', 'AIWorkbookTelemetryValidation/1.0',
                    $target
                )

                $curlProcess = Start-Process -FilePath $curlPath -ArgumentList $curlArguments -WindowStyle Hidden -PassThru -Wait
                $status = if ($curlProcess.ExitCode -eq 0) { 'Connected' } else { "ExitCode {0}" -f $curlProcess.ExitCode }
                Add-TestResult -Category 'Network and API' -Action 'Header request' -Status $status -Detail $target
            }
        }
    }
    else {
        Add-TestResult -Category 'Network and API' -Action 'Header request' -Status 'Skipped' -Detail 'curl.exe was not found.'
    }

    if ($BrowserTraffic) {
        $browserTargets = @(
            'https://chatgpt.com/',
            'https://claude.ai/',
            'https://gemini.google.com/',
            'https://www.perplexity.ai/',
            'https://copilot.microsoft.com/',
            'https://m365.cloud.microsoft/chat/',
            'https://platform.openai.com/',
            'https://deepgram.com/',
            'https://notebooklm.google.com/',
            'https://www.meshy.ai/',
            'https://www.notion.so/',
            'https://www.adobe.com/sensei.html',
            'https://www.synthesia.io/',
            'https://otter.ai/',
            'https://huggingface.co/chat/',
            'https://poe.com/',
            'https://grok.com/',
            'https://www.meta.ai/',
            'https://chat.deepseek.com/',
            'https://chat.mistral.ai/',
            'https://dashboard.cohere.com/playground/chat',
            'https://character.ai/',
            'https://you.com/',
            'https://www.phind.com/',
            'https://gamma.app/',
            'https://app.runwayml.com/',
            'https://www.midjourney.com/',
            'https://app.leonardo.ai/',
            'https://elevenlabs.io/app/speech-synthesis',
            'https://suno.com/',
            'https://pika.art/',
            'https://www.jasper.ai/',
            'https://app.grammarly.com/',
            'https://github.com/features/copilot',
            'https://www.sudowrite.com/',
            'https://duck.ai/',
            'https://www.editpad.org/',
            'https://www.lily.ai/',
            'https://www.gliacloud.com/',
            'https://www.loudly.com/',
            'https://www.imagine.art/',
            'https://www.kimi.com/',
            'https://scout.yahoo.com/',
            'https://use.ai/',
            'https://www.talkie-ai.com/',
            'https://woxo.tech/',
            'https://platform.moonshot.ai/',
            'https://www.baidu.com/',
            'https://www.capcut.com/',
            'https://deepai.org/',
            'https://z.ai/',
            'https://api.githubcopilot.com/mcp/',
            'https://mcp.atlassian.com/v1/mcp/authv2'
        ) | Select-Object -First $BrowserSiteLimit

        $browserDefinitions = @(
            [pscustomobject]@{
                Name = 'Microsoft Edge'
                Paths = @(
                    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
                    (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
                )
            },
            [pscustomobject]@{
                Name = 'Google Chrome'
                Paths = @(
                    (Get-ItemPropertyValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -Name '(default)' -ErrorAction SilentlyContinue),
                    (Get-ItemPropertyValue -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -Name '(default)' -ErrorAction SilentlyContinue),
                    (Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application\chrome.exe'),
                    (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
                    (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe')
                ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            }
        )

        foreach ($browser in $browserDefinitions) {
            $browserPath = $browser.Paths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
            if (-not $browserPath) {
                Write-Output ("{0} was not found. Skipping." -f $browser.Name)
                Add-TestResult -Category 'Browser AI' -Action 'Open visible tabs' -Status 'Skipped' -Detail $browser.Name
                continue
            }

            Write-Output ("Opening {0} with {1} AI service tabs." -f $browser.Name, $browserTargets.Count)
            $browserProcess = Start-Process -FilePath $browserPath -ArgumentList (@('--new-window') + $browserTargets) -PassThru
            Add-TestResult -Category 'Browser AI' -Action 'Open visible tabs' -Status ("ProcessId {0}" -f $browserProcess.Id) -Detail ("{0}: {1} sites" -f $browser.Name, $browserTargets.Count)
        }
    }

    $edgePaths = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
    )
    $edgePath = $edgePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if ($edgePath) {
        $edgeProfile = Join-Path $root 'edge-profile'
        $edgeOutput = Join-Path $root 'edge-output.txt'
        $edgeError = Join-Path $root 'edge-error.txt'
        $edgeArguments = @(
            '--headless=new',
            '--disable-gpu',
            '--disable-extensions',
            '--no-first-run',
            ("--user-data-dir={0}" -f $edgeProfile),
            '--dump-dom',
            'https://chatgpt.com/'
        )

        $edgeProcess = Start-Process -FilePath $edgePath -ArgumentList $edgeArguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $edgeOutput -RedirectStandardError $edgeError
        if (-not $edgeProcess.WaitForExit(20000)) {
            & (Join-Path $env:WINDIR 'System32\taskkill.exe') /PID $edgeProcess.Id /T /F | Out-Null
            Add-TestResult -Category 'Browser AI' -Action 'Headless Edge request' -Status 'Stopped after 20 seconds' -Detail 'https://chatgpt.com/'
        }
        else {
            Add-TestResult -Category 'Browser AI' -Action 'Headless Edge request' -Status ("ExitCode {0}" -f $edgeProcess.ExitCode) -Detail 'https://chatgpt.com/'
        }
    }
    else {
        Add-TestResult -Category 'Browser AI' -Action 'Headless Edge request' -Status 'Skipped' -Detail 'Microsoft Edge was not found.'
    }

    if (-not $KeepArtifacts -and $ArtifactHoldSeconds -gt 0) {
        Write-Output ("Holding synthetic artifacts for {0} seconds before cleanup." -f $ArtifactHoldSeconds)
        Start-Sleep -Seconds $ArtifactHoldSeconds
    }

    $results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding UTF8

    Write-Output ("Device: {0}  UTC: {1}" -f $device, $utc)
    Write-Output ("Run ID: {0}" -f $runId)
    Write-Output ("Events requested: {0}" -f $results.Count)
    $results | Select-Object Category, Action, Status, Detail | Format-Table -AutoSize | Out-String | Write-Output
    Write-Output ("Report: {0}" -f $reportPath)
    if ($KeepArtifacts) {
        Write-Output ("Manual upload sample: {0}" -f (Join-Path $secretDirectory 'MANUAL-UPLOAD-TEST-ONLY.txt'))
        Write-Output 'Only upload the synthetic sample to an authorized test destination.'
    }
    Write-Output 'Allow up to 15 minutes for MDE telemetry ingestion, then filter the workbook to this device.'
    exit 0
}
catch {
    Write-Error ("Telemetry generation failed: {0}" -f $_.Exception.Message)
    exit 1
}
finally {
    if ($runValueCreated) {
        Remove-ItemProperty -Path $runKey -Name $runValueName -Force -ErrorAction SilentlyContinue
    }

    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $root)) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}