#requires -Version 5.1
param([switch]$RegenerateEditions)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Get-CustomDetections.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count) { throw 'Exporter syntax errors.' }
$cdpAssignment = $ast.Find({ param($n)
    $n -is [Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -eq '$cdpClientSource'
}, $true)
Invoke-Expression $cdpAssignment.Extent.Text
if (-not ('CustomDetections.CdpClient' -as [type])) { Add-Type -TypeDefinition $cdpClientSource }
foreach ($definition in $ast.FindAll({ param($n)
    $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Parent -eq $ast.EndBlock
}, $true)) {
    Invoke-Expression $definition.Extent.Text
}
$script:passed = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAILED: $Message" }
    $script:passed++
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $thrown = $false
    try { & $Action | Out-Null } catch { $thrown = $true }
    Assert-True $thrown $Message
}
function New-TestCdpReply {
    param([object]$BrowserReply)
    $serialized = ConvertTo-Json -InputObject $BrowserReply -Depth 100 -Compress
    $wireJson = ConvertTo-Json -InputObject ([ordered]@{
        id = 42; result = [ordered]@{ result = [ordered]@{ type = 'string'; value = $serialized } }
    }) -Depth 100 -Compress
    ConvertFrom-CdpResponse -ResponseJson $wireJson -Method 'Runtime.evaluate'
}
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('CustomDetectionsOffline-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$tenant = [Guid]'11111111-1111-1111-1111-111111111111'
$subscription = [Guid]'22222222-2222-2222-2222-222222222222'
$target = Get-SentinelTarget $tenant $subscription 'Test-RG' 'Test-Workspace' 'Commercial'
function New-TestRule {
    param([string]$Name, [string]$Kind = 'Scheduled', [string]$Display = 'A/B')
    [pscustomobject]@{
        id = $target.CollectionPath + '/' + $Name; name = $Name
        type = 'Microsoft.SecurityInsights/alertRules'; kind = $Kind; etag = '"test"'
        properties = [pscustomobject]@{
            displayName = $Display; query = if ($Kind -in @('Scheduled', 'NRT')) { 'print synthetic=1' } else { $null }
            enabled = $false; entityMappings = @([pscustomobject]@{ entityType = 'Host'; fieldMappings = @() })
            customDetails = [pscustomobject]@{ FutureProperty = 'Preserve me' }
        }
    }
}
$script:replyQueue = New-Object System.Collections.Generic.Queue[object]
$script:requestedUrls = New-Object System.Collections.Generic.List[string]
function Invoke-SentinelBrowserRequest {
    param($Client, $Url)
    $script:requestedUrls.Add($Url)
    if ($script:replyQueue.Count -eq 0) { throw 'Unexpected offline request.' }
    return $script:replyQueue.Dequeue()
}
function Add-TestPage {
    param([object[]]$Rules = @(), [string]$NextLink)
    $page = [ordered]@{ value = @($Rules) }
    if ($NextLink) { $page.nextLink = $NextLink }
    $script:replyQueue.Enqueue([pscustomobject]@{
        status = 'ok'; body = ConvertTo-Json -InputObject $page -Depth 100 -Compress
    })
}
function Invoke-TestExport {
    param([string]$Name, [string[]]$Names)
    $directory = Join-Path $tempRoot $Name
    New-Item -ItemType Directory -Path $directory | Out-Null
    Export-SentinelRules -Target $target -OutputPath $directory -RuleNames $Names
}
try {
    $workspaceLookupQuery = @'
Resources
| where type =~ 'microsoft.operationalinsights/workspaces'
| project TenantId = tenantId, SubscriptionId = subscriptionId, ResourceGroupName = resourceGroup, WorkspaceName = name
| order by WorkspaceName asc
'@
    $workspaceLookupQuery = $workspaceLookupQuery.Replace("`r`n", "`n")
    $documentationPath = Join-Path (Split-Path $scriptPath -Parent) 'Get-CustomDetections.md'
    $documentation = [IO.File]::ReadAllText($documentationPath).Replace("`r`n", "`n")
    $embeddedHelp = $ast.GetHelpContent()
    Assert-True ($null -ne $embeddedHelp -and
        $embeddedHelp.Notes.Replace("`r`n", "`n").Contains($workspaceLookupQuery)) 'Exact manual workspace query is in executable script comment based help'
    Assert-True ($documentation.Contains($workspaceLookupQuery)) 'Shared instructions contain the identical Resource Graph query'
    Assert-True ($embeddedHelp.Notes.Contains('not in Sentinel Logs or Defender advanced hunting') -and
        $embeddedHelp.Notes.Contains('customerId') -and
        $embeddedHelp.Notes.Contains('same selected row')) 'Help distinguishes query surface and Entra tenant from workspace identifiers'
    foreach ($column in @('TenantId', 'SubscriptionId', 'ResourceGroupName', 'WorkspaceName')) {
        Assert-True ($embeddedHelp.Notes.Contains("$column supplies -$column")) "Lookup column maps to exact $column switch"
    }
    # Fingerprints from the full Commercial run that exported 3 Defender and
    # 242 Sentinel resources. Normalize newline style, not source algorithms.
    $commercialCore = @{
        'Get-PortalCustomDetections' = '4126E1343B578E405F42324FF67D64B6F3743B1F9E598103695D764445F2493D'
        'Restore-SentinelControlledTarget' = 'B776795CC8517087FD48853E35B15AB458CFBF38DCB77F93E58DEF03D609606C'
        'Update-SentinelBrowserContexts' = '811639BE826DC5E89C8CF35C83ECFE4F8DFEAA89F501F777AD09A95E06140657'
        'Find-SentinelReadyContext' = '05BF2AD2DC02C75768BF1291D4AC09E9250E5DD89C0C3F52EB9E48E0370070AA'
        'ConvertFrom-CdpResponse' = 'FB96B266D4E62EB75B7245DFB49CDB3F98E298BCD6CD84F472F9315DABE1FE68'
        'Invoke-CdpCommand' = '1E35B1F3E69B5AB0B53FDB6BAD63DC32FC8A5401B0CCA1953F7B966EF35DBF83'
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        # Executable AST fingerprints from published startup fix c44d0aa2.
        # Documentation changes must not alter parameters or runtime statements.
        foreach ($part in @(
            @{ name = 'ParamBlock'; hash = 'F8AB3F5AB15EE2FEF90A3484702829EE67624406A0685E6E8B14EA3DAB48B327' },
            @{ name = 'EndBlock'; hash = 'B3F1A67C85B08D3D818A8DD452F231D99F5E62D51B356FE6D952FDE4687AA95D' }
        )) {
            $normalized = $ast.($part.name).Extent.Text.Replace("`r`n", "`n")
            $actual = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
            Assert-True ($actual -ceq $part.hash) "Published startup fix executable $($part.name) preserved"
        }
        foreach ($name in $commercialCore.Keys) {
            $definition = $ast.Find({param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
            }, $true)
            $normalized = $definition.Extent.Text.Replace("`r`n", "`n")
            $actual = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
            Assert-True ($actual -ceq $commercialCore[$name]) "Live verified Commercial core preserved: $name"
        }
    } finally { $sha.Dispose() }
    $cloudDefault = @($ast.ParamBlock.Parameters | Where-Object {
        $_.Name.VariablePath.UserPath -eq 'CloudEnvironment'
    })[0].DefaultValue.Extent
    Assert-True ($cloudDefault.Text -ceq "'USGovDoD'") 'Canonical DoD edition default preserved'
    $parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    Assert-True (($parameterNames[0..16] -join ',') -ceq
        'TenantId,UserPrincipalName,DetectionNames,ExportMode,CloudEnvironment,SubscriptionId,ResourceGroupName,WorkspaceName,SentinelRuleNames,OutputPath,ProfilePath,SelectEdgeProfile,EdgeProfileDirectory,LoginTimeoutSeconds,CaptureSeconds,RemoveCachedProfile,ResetProfile' -and
        $parameterNames[17] -ceq 'SentinelApiVersion') 'Original positional parameter order retained with version option appended'
    $commercialCopy = $source.Remove($cloudDefault.StartOffset,
        $cloudDefault.EndOffset - $cloudDefault.StartOffset).Insert($cloudDefault.StartOffset, "'Commercial'")
    $copyErrors = $null; $copyTokens = $null
    $copyAst = [Management.Automation.Language.Parser]::ParseInput($commercialCopy, [ref]$copyTokens, [ref]$copyErrors)
    $commercialDefault = @($copyAst.ParamBlock.Parameters | Where-Object {
        $_.Name.VariablePath.UserPath -eq 'CloudEnvironment'
    })[0].DefaultValue.Extent
    Assert-True (@($copyErrors).Count -eq 0 -and $commercialDefault.Text -ceq "'Commercial'") 'Generated Commercial edition has only intentional default change'
    Assert-True ($commercialCopy.Remove($commercialDefault.StartOffset,
        $commercialDefault.EndOffset - $commercialDefault.StartOffset).Insert(
            $commercialDefault.StartOffset, "'USGovDoD'") -ceq $source) 'Edition source identity after normalizing cloud default'
    foreach ($label in @('IL2', 'IL5')) {
        $editionPath = Join-Path (Split-Path $scriptPath -Parent) "Get-CustomDetections_Analytics-$label.ps1"
        $marker = "# Generated $label detection and analytics edition from Get-CustomDetections.ps1. Do not edit this copy."
        $body = if ($label -eq 'IL2') { $commercialCopy } else { $source }
        $expected = $marker + [Environment]::NewLine + $body
        if ($RegenerateEditions) {
            if (Test-Path -LiteralPath $editionPath) {
                $existing = Get-Item -LiteralPath $editionPath
                if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    (([IO.File]::ReadAllText($editionPath) -split '\r?\n', 2)[0] -cne $marker)) {
                    throw 'Refusing to replace an unrecognized or linked edition file.'
                }
            }
            [IO.File]::WriteAllText($editionPath, $expected, (New-Object Text.UTF8Encoding($false)))
        }
        Assert-True (Test-Path -LiteralPath $editionPath) "Standalone $label edition exists"
        $oldEditionPath = Join-Path (Split-Path $scriptPath -Parent) "Get-CustomDetections-$label.ps1"
        Assert-True (-not (Test-Path -LiteralPath $oldEditionPath)) "Old $label edition name removed without duplicate alias"
        $editionSource = [IO.File]::ReadAllText($editionPath)
        Assert-True ($editionSource -ceq $expected) "Standalone $label source parity, including generated marker and intended default"
        $editionErrors = $null; $editionTokens = $null
        $editionAst = [Management.Automation.Language.Parser]::ParseFile(
            $editionPath, [ref]$editionTokens, [ref]$editionErrors)
        $editionDefault = @($editionAst.ParamBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq 'CloudEnvironment'
        })[0].DefaultValue.Extent.Text
        $expectedDefault = if ($label -eq 'IL2') { "'Commercial'" } else { "'USGovDoD'" }
        Assert-True (@($editionErrors).Count -eq 0 -and
            $editionDefault -ceq $expectedDefault) "Standalone $label cloud default and syntax"
        $editionHelp = $editionAst.GetHelpContent()
        Assert-True ($null -ne $editionHelp -and
            $editionHelp.Notes.Replace("`r`n", "`n").Contains($workspaceLookupQuery)) "Standalone $label built in help includes the exact query"
        $helpCommand = "Get-Help .\Get-CustomDetections_Analytics-$label.ps1 -Full"
        Assert-True ($editionHelp.Notes.Contains($helpCommand) -and
            $documentation.Contains($helpCommand)) "Standalone $label help viewing command documented"
        $renderedHelp = Get-Help -Name $editionPath -Full | Out-String -Width 4096
        Assert-True ($renderedHelp.Contains('| order by WorkspaceName asc') -and
            $renderedHelp.Contains('Azure Resource Graph Explorer')) "Actual Get Help Full renders $label lookup instructions without executing exporter"
        $exampleCommand = ".\Get-CustomDetections_Analytics-$label.ps1 -ExportMode Both"
        $exampleLines = @($editionSource -split '\r?\n' | Where-Object { $_.StartsWith($exampleCommand) })
        Assert-True ($exampleLines.Count -eq 1 -and -not $exampleLines[0].Contains('`') -and
            $exampleLines[0].Contains("-WorkspaceName '<workspace name>'") -and
            $documentation.Contains($exampleLines[0])) "Standalone $label invocation is one line with matching shared instructions"
    }
    foreach ($fixture in @(
        @{ text = 'Cannot find context with specified id'; reason = 'ContextUnavailable'; code = -32000 },
        @{ text = 'Promise was collected'; reason = 'PromiseCollected'; code = -32000 },
        @{ text = "Object couldn't be returned by value"; reason = 'SerializationFailed'; code = -32000 },
        @{ text = 'Invalid parameters'; reason = 'InvalidParameters'; code = -32602 },
        @{ text = 'Inspected target navigated or closed'; reason = 'SessionUnavailable'; code = -32000 },
        @{ text = 'SYNTHETIC_SECRET_NOT_FOR_LOGS'; reason = 'OtherProtocolError'; code = -32000 }
    )) {
        try {
            ConvertFrom-CdpResponse -ResponseJson (ConvertTo-Json -InputObject @{
                id = 42; error = @{ code = $fixture.code; message = $fixture.text }
            } -Compress) -Method 'Runtime.evaluate' | Out-Null
            throw 'Protocol error did not throw.'
        } catch {
            $diagnostic = Get-SentinelFailureDiagnostic -ErrorRecord $_ -Stage 'RequestListPage'
            Assert-True ($diagnostic.cdpReason -eq $fixture.reason -and
                $diagnostic.cdpCode -eq $fixture.code -and
                $diagnostic.cdpMethod -eq 'Runtime.evaluate') 'Real protocol parser preserves safe reason method and code'
            Assert-True (-not (($diagnostic | ConvertTo-Json -Compress) -match 'SYNTHETIC_SECRET_NOT_FOR_LOGS')) 'Protocol diagnostics do not leak raw messages'
            if ($fixture.reason -ne 'OtherProtocolError') {
                Assert-True ($diagnostic.cdpMessage -eq $fixture.text) 'Recognized safe original protocol message preserved'
            }
        }
    }
    Assert-SentinelListUrl $target.ListUrl $target
    $badUrls = @(
        $target.ListUrl.Replace('management.azure.com', 'example.invalid'),
        $target.ListUrl.Replace('management.azure.com', 'management.usgovcloudapi.net'),
        $target.ListUrl.Replace('https:', 'http:'),
        $target.ListUrl.Replace('Test-Workspace', 'Other-Workspace'),
        $target.ListUrl.Replace($subscription.ToString(), '33333333-3333-3333-3333-333333333333'),
        $target.ListUrl.Replace('management.azure.com', 'user@management.azure.com'),
        $target.ListUrl.Replace('management.azure.com', 'management.azure.com:444'),
        ($target.ListUrl + '#fragment'),
        $target.ListUrl.Replace('2025-09-01', '2024-01-01'),
        ($target.ListUrl + '&api-version=2025-09-01')
    )
    for ($i = 0; $i -lt $badUrls.Count; $i++) {
        $url = $badUrls[$i]
        Assert-Throws { Assert-SentinelListUrl $url $target } "Unsafe pagination rejected [$i]: $url"
    }
    $gov = Get-SentinelTarget $tenant $subscription 'Test-RG' 'Test-Workspace' 'USGovDoD'
    Assert-True ($gov.ArmHost -eq 'management.usgovcloudapi.net' -and $gov.PortalHost -eq 'portal.azure.us') 'Government scope'
    Assert-True ($gov.RequiresApiVersionDiscovery -and -not $gov.ApiVersion -and -not $gov.ListUrl) 'Government has no guessed default rule API version'
    Assert-True ($target.ApiVersion -eq '2025-09-01' -and -not $target.RequiresApiVersionDiscovery -and
        $target.ApiVersionSource -eq 'CommercialDefault') 'Just tested Commercial API version behavior preserved'
    $explicitGov = Get-SentinelTarget $tenant $subscription 'Test-RG' 'Test-Workspace' 'USGovDoD' '2024-03-01'
    Assert-True (-not $explicitGov.RequiresApiVersionDiscovery -and
        $explicitGov.ApiVersionSource -eq 'ExplicitParameter' -and
        $explicitGov.ListUrl.EndsWith('api-version=2024-03-01')) 'Explicit Government version needs no metadata discovery'
    Assert-Throws { Get-SentinelTarget $tenant $subscription 'Test-RG' 'Test-Workspace' 'USGovDoD' '2024-02-30' } 'Invalid calendar version rejected'
    Assert-Throws { Assert-SentinelListUrl $explicitGov.ListUrl $target } 'Government rule URL refused by Commercial target'
    Assert-Throws { Assert-SentinelListUrl $target.ListUrl $explicitGov } 'Commercial rule URL refused by Government target'
    $script:replyQueue.Enqueue([pscustomobject]@{ status = 'apiVersionSelected'; apiVersion = '2024-03-01' })
    Resolve-SentinelApiVersion -Target $gov
    Assert-True ($gov.ApiVersion -eq '2024-03-01' -and
        $gov.ApiVersionSource -eq 'SubscriptionProviderMetadata' -and
        $script:requestedUrls[$script:requestedUrls.Count - 1] -eq 'discoverApiVersion') 'Host updates target only after browser confirmed Government discovery'
    foreach ($failure in @('httpError', 'unsupportedProviderMetadata', 'apiVersionUnavailable')) {
        $unresolved = Get-SentinelTarget $tenant $subscription 'Test-RG' 'Test-Workspace' 'USGovDoD'
        $script:replyQueue.Enqueue([pscustomobject]@{ status = $failure; httpStatus = 403 })
        Assert-Throws { Resolve-SentinelApiVersion -Target $unresolved } 'Government discovery failure is not a fabricated default'
        Assert-True (-not $unresolved.ListUrl -and $unresolved.RequiresApiVersionDiscovery) 'Failed Government discovery cannot request analytics rules'
    }
    Assert-True (Test-SentinelFrameUrl 'https://sandbox-1.reactblade.portal.azure.net/browse' $target) 'Verified ReactBlade origin'
    foreach ($frameUrl in @('http://sandbox-1.reactblade.portal.azure.net/browse',
        'https://sandbox-1.reactblade.portal.azure.net.example.invalid/browse',
        'https://user@sandbox-1.reactblade.portal.azure.net/browse',
        'https://sandbox-1.reactblade.portal.azure.net:444/browse',
        'https://sandbox-2.reactblade.portal.azure.net/browse')) {
        Assert-True (-not (Test-SentinelFrameUrl $frameUrl $target)) 'Unverified frame origin rejected'
    }
    $contextState = @{
        Contexts = @{ 'test|1' = @{ SessionId = 'test'; ContextId = 1 } }
        Active = @{ SessionId = 'test'; ContextId = 1 }
    }
    Remove-SentinelSessionContexts $contextState 'test'
    Assert-True ($contextState.Contexts.Count -eq 0 -and $null -eq $contextState.Active) 'Detached session invalidates active realm'
    $callOverloads = @([CustomDetections.CdpClient].GetMethods() | Where-Object { $_.Name -eq 'Call' })
    Assert-True ($callOverloads.Count -eq 2 -and @($callOverloads | Where-Object {
        $_.GetParameters().Count -eq 3 }).Count -eq 1) 'Original CDP call signature retained alongside session routing'
    Assert-True ((ConvertTo-SafeFileName 'CON') -eq '_CON') 'Reserved filename'
    $mdeRule = '{"id":1,"name":"MDE rule","huntingQuery":{"queryText":"print synthetic=1"},"frequency":60}' | ConvertFrom-Json
    Assert-True (Test-CustomDetectionRule $mdeRule) 'Original MDE schema'
    Assert-True ((Get-RuleQueryText $mdeRule) -eq 'print synthetic=1') 'Original MDE query'
    Assert-True ((Get-StableRuleKey $mdeRule) -eq 'id:1') 'Original MDE key'
    $wrapped = [pscustomobject]@{ rules = @($mdeRule); nested = [pscustomobject]@{ same = $mdeRule } }
    Assert-True (@(Find-CustomDetectionRule $wrapped).Count -eq 1) 'MDE recursive deduplication'
    $authUrl = 'https://login.microsoftonline.us/common/oauth2/v2.0/authorize?client_id=original&state=original&nonce=n&code_challenge=pkce&prompt=none'
    $changed = Get-TargetUserAuthorizationUrl $authUrl 'test@example.invalid'
    Assert-True ($changed -match 'client_id=original' -and $changed -match 'state=original' -and
        $changed -match 'code_challenge=pkce' -and $changed -match 'prompt=login' -and
        $changed -match 'login_hint=test%40example.invalid') 'MDE account targeting preserves auth parameters'
    Assert-True ($null -eq (Get-TargetUserAuthorizationUrl 'https://example.invalid/oauth2/authorize' 'test@example.invalid')) 'Auth host rejection'

    $next = $target.ListUrl + '&$skiptoken=opaque'
    Add-TestPage @((New-TestRule 'one'), (New-TestRule 'two' 'NRT' 'A:B')) $next
    Add-TestPage @((New-TestRule 'three' 'Fusion' 'Fusion'), (New-TestRule 'four' 'MicrosoftSecurityIncidentCreation' 'Incident'),
        (New-TestRule 'five' 'MLBehaviorAnalytics' 'ML'), (New-TestRule 'six' 'ThreatIntelligence' 'TI'),
        (New-TestRule 'seven' 'FutureKind' 'Future'))
    $result = Invoke-TestExport 'multiple'
    Assert-True ($result.complete -and $result.ruleCount -eq 7 -and $result.captureCount -eq 2) 'All kinds and pagination'
    Assert-True ($result.rules[0].file -ne $result.rules[1].file) 'Sanitized name collision'
    Assert-True (@($result.rules | Where-Object { $_.queryFile }).Count -eq 2) 'Queryless kinds do not get invented KQL'
    $roundTrip = Get-Content (Join-Path (Join-Path $tempRoot 'multiple') $result.rules[0].file) -Raw | ConvertFrom-Json
    Assert-True ($roundTrip.etag -eq '"test"' -and $roundTrip.properties.customDetails.FutureProperty -eq 'Preserve me') 'Complete properties intact'
    Assert-True (-not ((Get-Content (Join-Path $tempRoot 'multiple\captures\page-0001.json') -Raw) -match 'opaque')) 'Pagination not persisted'

    Add-TestPage
    $result = Invoke-TestExport 'zero'
    Assert-True ($result.complete -and $result.ruleCount -eq 0) 'Honest zero'
    Add-TestPage @((New-TestRule 'one' 'Scheduled' 'Match'), (New-TestRule 'two' 'Scheduled' 'Other'))
    $result = Invoke-TestExport 'filter' @('match,Missing')
    Assert-True (-not $result.complete -and $result.ruleCount -eq 1 -and $result.unmatchedRuleNames[0] -eq 'Missing') 'Filter and missing name'
    foreach ($status in @(401, 403, 429, 500)) {
        $script:replyQueue.Enqueue([pscustomobject]@{ status = 'httpError'; httpStatus = $status })
        $result = Invoke-TestExport "http$status"
        Assert-True (-not $result.complete -and $result.errors[0] -match "HTTP $status") 'HTTP failure'
    }
    foreach ($body in @('[]', '{"value":{}}', '{"value":null}', '{"error":{"code":"Forbidden"}}', '{"value":[null]}', 'not json')) {
        $script:replyQueue.Enqueue([pscustomobject]@{ status = 'ok'; body = $body })
        $result = Invoke-TestExport ('envelope' + $script:passed)
        Assert-True (-not $result.complete) 'Unsupported envelope'
    }
    $before = $script:requestedUrls.Count
    Add-TestPage @((New-TestRule 'one')) $target.ListUrl.Replace('management.azure.com', 'example.invalid')
    $result = Invoke-TestExport 'crossHostPartial'
    Assert-True (-not $result.complete -and $result.ruleCount -eq 1 -and
        $script:requestedUrls.Count -eq $before + 1) 'Partial export rejects cross host before fetch'
    Add-TestPage @((New-TestRule 'one')) $next
    $script:replyQueue.Enqueue([pscustomobject]@{ status = 'httpError'; httpStatus = 403 })
    $result = Invoke-TestExport 'partial403'
    Assert-True (-not $result.complete -and $result.ruleCount -eq 1) 'Partial permission failure retains success'
    Add-TestPage @((New-TestRule 'one')) $target.ListUrl
    $result = Invoke-TestExport 'loop'
    Assert-True (-not $result.complete -and $result.ruleCount -eq 1) 'Pagination loop'
    $outside = New-TestRule 'one'
    $outside.id = $outside.id.Replace('Test-Workspace', 'Other-Workspace')
    Add-TestPage @($outside)
    $result = Invoke-TestExport 'outside'
    Assert-True (-not $result.complete -and $result.ruleCount -eq 0) 'Foreign workspace rule'
    Add-TestPage @((New-TestRule 'one'), (New-TestRule 'one'))
    $result = Invoke-TestExport 'duplicate'
    Assert-True (-not $result.complete) 'Duplicate rule ID'
    Assert-Throws { Initialize-ExportDirectory $tempRoot @($scriptPath) } 'Existing output rejected'
    Assert-Throws { Initialize-ExportDirectory (Split-Path $scriptPath -Parent) @($scriptPath) } 'Source protected'
    Assert-Throws { Initialize-ExportDirectory (Join-Path $tempRoot 'profile\output') @((Join-Path $tempRoot 'profile')) } 'Profile protected'
    $existing = Join-Path $tempRoot 'existing.txt'
    Write-NewExportFile $existing 'original'
    Assert-Throws { Write-NewExportFile $existing 'overwrite' } 'Atomic collision rejected'
    Assert-True ((Get-Content $existing -Raw) -eq 'original') 'Original file retained'
    Assert-Throws { & $scriptPath -TenantId $tenant -ExportMode Sentinel -OutputPath (Join-Path $tempRoot 'neverCreated') } 'Actual entrypoint missing target fails before browser'
    Assert-True (-not (Test-Path (Join-Path $tempRoot 'neverCreated'))) 'Preflight has no output side effect'
    Assert-Throws { & $scriptPath -TenantId $tenant -OutputPath $tempRoot } 'Actual entrypoint existing output'

    # Exercise bounded startup separately from authentication and portal recovery.
    & {
        $script:startupProbeCount = 0
        $script:startupProbeMode = 'ready'
        function Invoke-RestMethod {
            [CmdletBinding()]
            param($Uri, [int]$TimeoutSec)
            $script:startupProbeCount++
            Assert-True ($Uri -ceq 'http://127.0.0.1:12345/json/list') 'Startup probes only selected loopback port'
            Assert-True ($TimeoutSec -ge 1 -and $TimeoutSec -le 2) 'Startup request has bounded timeout'
            Assert-True ($PSBoundParameters.ContainsKey('Verbose') -and -not $PSBoundParameters['Verbose']) 'Repetitive WebRequest verbose output disabled'
            Assert-True ($PSBoundParameters['ErrorAction'] -eq 'Stop') 'Startup HTTP failures terminate each probe'
            if ($script:startupProbeMode -eq 'failure') { throw 'SYNTHETIC_SECRET_NOT_FOR_LOGS' }
            if ($script:startupProbeMode -eq 'emptyThenReady' -and $script:startupProbeCount -eq 1) { return @() }
            if ($script:startupProbeMode -eq 'empty') { return @([pscustomobject]@{ type = 'worker' }) }
            @([pscustomobject]@{ type = 'page'; id = 'startup-page' })
        }
        $running = [pscustomobject]@{ Id = -1; HasExited = $false }
        $exited = [pscustomobject]@{ Id = -2; HasExited = $true; ExitCode = 17 }
        $ready = @(Wait-EdgeDevToolsTargets -Port 12345 -Process $running -TimeoutSeconds 1)
        Assert-True ($ready.Count -eq 1 -and $ready[0].id -ceq 'startup-page') 'Running Edge endpoint accepted'
        $ready = @(Wait-EdgeDevToolsTargets -Port 12345 -Process $exited -TimeoutSeconds 1)
        Assert-True ($ready.Count -eq 1) 'Launcher handoff exit alone does not reject healthy endpoint'
        $script:startupProbeMode = 'emptyThenReady'; $script:startupProbeCount = 0
        $ready = @(Wait-EdgeDevToolsTargets -Port 12345 -Process $running -TimeoutSeconds 2)
        Assert-True ($ready.Count -eq 1 -and $script:startupProbeCount -eq 2) 'Endpoint without page waits for page creation'
        foreach ($fixture in @(
            @{ process = $running; mode = 'failure'; state = 'Running' },
            @{ process = $exited; mode = 'failure'; state = 'Exited (exit code 17)' },
            @{ process = $running; mode = 'empty'; state = 'Running' }
        )) {
            $script:startupProbeMode = $fixture.mode
            $failure = $null; $elapsed = [Diagnostics.Stopwatch]::StartNew()
            try { Wait-EdgeDevToolsTargets -Port 12345 -Process $fixture.process -TimeoutSeconds 1 | Out-Null }
            catch { $failure = $_ }
            Assert-True ($null -ne $failure -and $elapsed.Elapsed.TotalSeconds -lt 4) 'Unavailable startup stops within bounded retry budget'
            Assert-True ($failure.Exception.Data['EdgeLauncherState'] -ceq $fixture.state -and
                $failure.Exception.Data['EdgeStartupPort'] -eq 12345) 'Startup failure reports process state and selected port'
            Assert-True ($failure.Exception.Message -match 'before portal sign-in' -and
                $failure.Exception.Message -match 'normal PowerShell' -and
                $failure.Exception.Message -match 'ProfilePath' -and
                $failure.Exception.Message -notmatch 'SYNTHETIC_SECRET') 'Startup failure gives safe next action without raw exception data'
            if ($fixture.mode -eq 'empty') {
                Assert-True ($failure.Exception.Data['EdgeStartupLastProbe'] -ceq 'EndpointAnsweredWithoutPage') 'No page distinguished from failed HTTP request'
            }
        }
    }
    # A real loopback socket accepts a connection but never sends HTTP headers.
    # Verify the production request timeout, not merely a mock's parameter list.
    $stalledListener = New-Object Net.Sockets.TcpListener ([Net.IPAddress]::Loopback), 0
    try {
        $stalledListener.Start()
        $stalledPort = ([Net.IPEndPoint]$stalledListener.LocalEndpoint).Port
        $failure = $null; $elapsed = [Diagnostics.Stopwatch]::StartNew()
        try {
            Wait-EdgeDevToolsTargets -Port $stalledPort `
                -Process ([pscustomobject]@{ HasExited = $false }) -TimeoutSeconds 1 | Out-Null
        }
        catch { $failure = $_ }
        Assert-True ($null -ne $failure -and $elapsed.Elapsed.TotalSeconds -lt 6) 'Real stalled HTTP response cannot leave startup polling blocked'
        Assert-True ($failure.Exception.Data['EdgeStartupPort'] -eq $stalledPort -and
            $failure.Exception.Data['EdgeLauncherState'] -ceq 'Running') 'Real HTTP timeout retains actionable startup diagnosis'
    }
    finally { $stalledListener.Stop() }

    # Restore the real bridge. Entrypoint tests below mock CDP remote replies, not this function.
    $bridgeDefinition = $ast.Find({ param($n)
        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $n.Name -eq 'Invoke-SentinelBrowserRequest'
    }, $true)
    Invoke-Expression $bridgeDefinition.Extent.Text

    # Execute the original entrypoint text with browser boundaries mocked.
    # Only the C# socket Connect line is replaced. No browser or tenant is contacted.
    $entrypoint = $source.Substring($source.IndexOf('$edgeProcess = $null'))
    $entrypoint = $entrypoint.Replace('$client.Connect([string]$target.webSocketDebuggerUrl, 30000)', '# Offline socket connection')
    # Invoke-Expression has no file based automatic variables. Supply the real source paths.
    $entrypoint = $entrypoint.Replace('$PSCommandPath', "'" + $scriptPath.Replace("'", "''") + "'").
        Replace('$PSScriptRoot', "'" + (Split-Path $scriptPath -Parent).Replace("'", "''") + "'")
    function Resolve-EdgeExecutable { 'offline-msedge.exe' }
    function Get-AvailableTcpPort { 12345 }
    function Start-Process { param($FilePath, $ArgumentList, [switch]$PassThru)
        [pscustomobject]@{ Id = -1; HasExited = $true; ExitCode = 0 }
    }
    function Invoke-RestMethod { [CmdletBinding()]param($Uri, $TimeoutSec)
        @([pscustomobject]@{ id = 'controlled-root'; type = 'page'; webSocketDebuggerUrl = 'ws://127.0.0.1:12345/offline' })
    }
    function Get-CdpEvents { param($Client)
        $frameScenario = $script:entryScenario -in @('iframeReady', 'rogueIframe', 'sessionNavigationIframe')
        if ($script:rootReattached) {
            [pscustomobject]@{ method = 'Target.attachedToTarget'; params = [pscustomobject]@{
                sessionId = 'recovered-root'; targetInfo = [pscustomobject]@{ type = 'page'; targetId = 'controlled-root' }
            } }
            [pscustomobject]@{ method = 'Runtime.executionContextCreated'; sessionId = 'recovered-root'; params = [pscustomobject]@{
                context = [pscustomobject]@{ id = 3; origin = "https://$($sentinelTarget.PortalHost)"
                    auxData = [pscustomobject]@{ isDefault = $true; frameId = 'root' }
                }
            } }
            if ($script:entryScenario -eq 'sessionNavigationIframe') {
                [pscustomobject]@{ method = 'Target.detachedFromTarget'; params = [pscustomobject]@{ sessionId = 'react-session' } }
                [pscustomobject]@{ method = 'Target.attachedToTarget'; sessionId = 'recovered-root'; params = [pscustomobject]@{
                    sessionId = 'fresh-react'; targetInfo = [pscustomobject]@{ type = 'iframe'; targetId = 'fresh-blade' }
                } }
                [pscustomobject]@{ method = 'Runtime.executionContextCreated'; sessionId = 'fresh-react'; params = [pscustomobject]@{
                    context = [pscustomobject]@{ id = 4; origin = 'https://sandbox-1.reactblade.portal.azure.net'
                        auxData = [pscustomobject]@{ isDefault = $true; frameId = 'fresh-blade' }
                    }
                } }
            }
            return
        }
        if ($frameScenario -and -not $script:frameEventsSent) {
            $script:frameEventsSent = $true
            [pscustomobject]@{ method = 'Target.attachedToTarget'; params = [pscustomobject]@{
                sessionId = 'react-session'; targetInfo = [pscustomobject]@{ type = 'iframe' }
            } }
        }
        [pscustomobject]@{ method = 'Runtime.executionContextCreated'; params = [pscustomobject]@{
            context = [pscustomobject]@{
                id = if ($script:entryScenario -eq 'listContextLoss' -and $script:listAttemptCount -gt 0) { 2 } else { 1 }
                origin = "https://$($sentinelTarget.PortalHost)"
                auxData = [pscustomobject]@{ isDefault = $true; frameId = 'root' }
            }
        } }
        if ($frameScenario) {
            $origin = if ($script:entryScenario -eq 'rogueIframe') { 'https://example.invalid' }
                else { 'https://sandbox-1.reactblade.portal.azure.net' }
            [pscustomobject]@{ method = 'Runtime.executionContextCreated'; sessionId = 'react-session'; params = [pscustomobject]@{
                context = [pscustomobject]@{
                    id = 2; origin = $origin
                    auxData = [pscustomobject]@{ isDefault = $true; frameId = 'blade' }
                }
            } }
        }
    }
    function Get-PageState { param($Client)
        [pscustomobject]@{ url = $portalUrl; readyState = 'complete' }
    }
    function Add-NetworkEvents { param($Client, $Requests, $Responses, $AuthenticationState)
        $Requests['offline'] = [pscustomobject]@{
            url = "https://$defenderHost/apiproxy/hunting/huntingService/rules/unified"
            method = 'GET'; headers = [pscustomobject]@{ Accept = 'application/json' }
        }
    }
    function Invoke-CdpCommand { param($Client, $Method, $Parameters, $TimeoutMilliseconds, $SessionId)
        $script:commandOrder.Add([pscustomobject]@{
            Method = $Method; SessionId = [string]$SessionId
            Expression = if ($Parameters -and $Parameters.ContainsKey('expression')) { [string]$Parameters.expression } else { '' }
            WaitForDebugger = if ($Parameters -and $Parameters.ContainsKey('waitForDebuggerOnStart')) {
                [bool]$Parameters.waitForDebuggerOnStart
            } else { $false }
        })
        if ($Method -eq 'Target.getTargetInfo') {
            if ($script:listAttemptCount -gt 0 -and $script:entryScenario -eq 'sessionNavigationClosed') {
                return ConvertFrom-CdpResponse -ResponseJson '{"id":42,"error":{"code":-32000,"message":"No target with given id found"}}' -Method $Method
            }
            $id = 'controlled-root'
            $url = $sentinelTarget.PortalUrl
            if ($script:listAttemptCount -gt 0 -and $script:entryScenario -eq 'sessionNavigationForeign') { $url = 'https://example.invalid' }
            if ($script:listAttemptCount -gt 0 -and $script:entryScenario -eq 'sessionNavigationDifferentTarget') { $id = 'different-root' }
            return [pscustomobject]@{ targetInfo = [pscustomobject]@{ targetId = $id; type = 'page'; url = $url } }
        }
        if ($Method -eq 'Target.attachToTarget') {
            Assert-True ($Parameters.targetId -ceq 'controlled-root' -and $Parameters.flatten) 'Recovery attaches only original controlled target'
            $script:rootReattached = $true
            return [pscustomobject]@{ sessionId = 'recovered-root' }
        }
        if ($Method -eq 'Page.getFrameTree') {
            $frame = if ($SessionId -eq 'fresh-react') {
                [pscustomobject]@{ id = 'fresh-blade'; url = 'https://sandbox-1.reactblade.portal.azure.net/browse' }
            } elseif ($SessionId -eq 'react-session') {
                [pscustomobject]@{ id = 'blade'; url = 'https://sandbox-1.reactblade.portal.azure.net/browse' }
            } else {
                [pscustomobject]@{ id = 'root'; url = $sentinelTarget.PortalUrl }
            }
            return [pscustomobject]@{ frameTree = [pscustomobject]@{ frame = $frame } }
        }
        if ($Method -eq 'Runtime.evaluate' -and $Parameters.expression -match 'const tenantId =') {
            $detailRules = @($mdeRule)
            $detailErrors = @()
            if ($script:entryScenario -eq 'mdeFailure') {
                $detailRules = @()
                $detailErrors = @([pscustomobject]@{ id = 1; error = 'HTTP 404' })
            }
            return [pscustomobject]@{ result = [pscustomobject]@{ value = (
                ConvertTo-Json -InputObject ([pscustomobject]@{
                    sourceSelection = [pscustomobject]@{
                        defenderCount = 0; legacyCount = 1; unsupportedCount = 0
                        excludedSentinelCount = if ($script:entryScenario -eq 'MDE') { 249 } else { 0 }
                    }
                    requestedNames = @(); notFound = @(); summaries = @([pscustomobject]@{ Id = 1; Name = 'MDE rule' })
                    rules = $detailRules; errors = $detailErrors
                }) -Depth 100 -Compress) } }
        }
        if ($Method -eq 'Runtime.evaluate' -and $Parameters.expression -match 'window\.__sentinelExporter') {
            if ($Parameters.expression.StartsWith('(() => { if (typeof')) {
                $script:evaluatedSessions.Add([string]$SessionId)
                return [pscustomobject]@{ result = [pscustomobject]@{ type = 'boolean'; value = $true } }
            }
            $poll = $Parameters.expression -match '__sentinelExporter\(""\)'
            if ($Parameters.expression -match '__sentinelExporter\("discoverApiVersion"\)') {
                $script:discoveryCount++
                if ($script:entryScenario -eq 'governmentDiscovery403') {
                    return New-TestCdpReply -BrowserReply ([pscustomobject]@{ status = 'httpError'; httpStatus = 403 })
                }
                return New-TestCdpReply -BrowserReply ([pscustomobject]@{ status = 'apiVersionSelected'; apiVersion = '2024-03-01' })
            }
            if ($poll) {
                $script:protocolPollExpression = $Parameters.expression
                $script:portalPollCount++
                if ($script:entryScenario -eq 'malformedReadiness') {
                    return [pscustomobject]@{ result = [pscustomobject]@{ type = 'undefined' } }
                }
                if ($script:entryScenario -eq 'navigationThenReady' -and $script:portalPollCount -eq 1) {
                    throw 'Execution context was destroyed.'
                }
                $status = 'ready'
                if ($script:entryScenario -in @('iframeReady', 'sessionNavigationIframe') -and $Parameters.contextId -in @(1, 3)) { $status = 'waiting' }
                if ($script:entryScenario -eq 'waitingThenReady') {
                    if ($script:portalPollCount -eq 1) { $status = 'observerUnavailable' }
                    if ($script:portalPollCount -eq 2) { $status = 'waiting' }
                }
                return New-TestCdpReply -BrowserReply ([pscustomobject]@{ status = $status })
            }
            $script:listContexts.Add([int]$Parameters.contextId)
            $script:listSessions.Add([string]$SessionId)
            $script:listAttemptCount++
            Assert-True ($Parameters.awaitPromise -and $Parameters.returnByValue -and
                $Parameters.expression -match 'JSON.stringify') 'Actual list entrypoint uses awaited JSON string serialization'
            if (($script:entryScenario -like 'sessionNavigation*' -or
                $script:entryScenario -eq 'governmentDiscoveryContextLoss') -and
                ($script:listAttemptCount -eq 1 -or $script:entryScenario -eq 'sessionNavigationRepeated')) {
                return ConvertFrom-CdpResponse -ResponseJson '{"id":42,"error":{"code":-32000,"message":"Inspected target navigated or closed"}}' -Method 'Runtime.evaluate'
            }
            if ($script:entryScenario -eq 'listContextLoss' -and $script:listAttemptCount -eq 1) {
                return ConvertFrom-CdpResponse -ResponseJson '{"id":42,"error":{"code":-32000,"message":"Cannot find context with specified id"}}' -Method 'Runtime.evaluate'
            }
            if ($script:entryScenario -eq 'protocolFailure') {
                return ConvertFrom-CdpResponse -ResponseJson '{"id":42,"error":{"code":-32602,"message":"Invalid parameters"}}' -Method 'Runtime.evaluate'
            }
            if ($script:entryScenario -eq 'malformedSerializedReply') {
                return ConvertFrom-CdpResponse -ResponseJson '{"id":42,"result":{"result":{"type":"string","value":"SYNTHETIC_SECRET_NOT_FOR_LOGS invalid json"}}}' -Method 'Runtime.evaluate'
            }
            if ($script:entryScenario -eq 'browserExecutionFailure') {
                return ConvertFrom-CdpResponse -ResponseJson '{"id":42,"result":{"exceptionDetails":{"exception":{"className":"TypeError","description":"SYNTHETIC_SECRET_NOT_FOR_LOGS"}}}}' -Method 'Runtime.evaluate'
            }
            if ($script:entryScenario -eq 'malformedListReply') {
                return [pscustomobject]@{ result = [pscustomobject]@{ type = 'undefined' } }
            }
            if ($script:entryScenario -eq 'sentinelFailure') {
                return New-TestCdpReply -BrowserReply ([pscustomobject]@{ status = 'httpError'; httpStatus = 403 })
            }
            if ($script:entryScenario -eq 'http401') {
                return New-TestCdpReply -BrowserReply ([pscustomobject]@{ status = 'httpError'; httpStatus = 401 })
            }
            $body = '{"value":[]}'
            if ($script:entryScenario -eq 'largeSerializedReply') {
                $largeRule = New-TestRule 'large-serialized-rule'
                $largeRule.properties.query = 'print fixture="' + (([string][char]0x03A9) * 650000) + '";'
                $body = ConvertTo-Json -InputObject @{ value = @($largeRule) } -Depth 100 -Compress
            }
            if ($script:entryScenario -eq 'invalidJson') { $body = 'SYNTHETIC_SECRET_NOT_FOR_LOGS invalid json' }
            if ($script:entryScenario -eq 'captureCollision') {
                [IO.File]::WriteAllText((Join-Path $OutputPath 'captures\page-0001.json'), 'original protected fixture')
            }
            return New-TestCdpReply -BrowserReply ([pscustomobject]@{ status = 'ok'; body = $body })
        }
        [pscustomobject]@{}
    }
    $failureScenarios = @('mdeFailure', 'sentinelFailure', 'malformedReadiness', 'malformedListReply', 'invalidJson', 'captureCollision',
        'protocolFailure', 'malformedSerializedReply', 'browserExecutionFailure', 'http401',
        'sessionNavigationClosed', 'sessionNavigationForeign', 'sessionNavigationDifferentTarget', 'sessionNavigationRepeated',
        'governmentDiscovery403')
    foreach ($scenario in @('MDE', 'Sentinel', 'Both', 'mdeFailure', 'sentinelFailure',
        'waitingThenReady', 'navigationThenReady', 'malformedReadiness', 'malformedListReply', 'invalidJson', 'captureCollision',
        'iframeReady', 'rogueIframe', 'listContextLoss', 'largeSerializedReply',
        'protocolFailure', 'malformedSerializedReply', 'browserExecutionFailure', 'http401',
        'sessionNavigationRoot', 'sessionNavigationIframe', 'sessionNavigationClosed',
        'sessionNavigationForeign', 'sessionNavigationDifferentTarget', 'sessionNavigationRepeated',
        'governmentDiscovery', 'governmentDiscovery403', 'governmentDiscoveryContextLoss', 'commercialBoth')) {
        $script:entryScenario = $scenario
        $script:portalPollCount = 0
        $script:listAttemptCount = 0
        $script:frameEventsSent = $false
        $script:rootReattached = $false
        $script:discoveryCount = 0
        $script:listContexts = New-Object System.Collections.Generic.List[int]
        $script:listSessions = New-Object System.Collections.Generic.List[string]
        $script:evaluatedSessions = New-Object System.Collections.Generic.List[string]
        $script:commandOrder = New-Object System.Collections.Generic.List[object]
        $mode = if ($scenario -in @('mdeFailure', 'sentinelFailure', 'commercialBoth')) { 'Both' }
            elseif ($scenario -in @('MDE', 'Sentinel', 'Both')) { $scenario } else { 'Sentinel' }
        $script:entryThrew = $false
        & {
            $ExportMode = $mode
            $CloudEnvironment = if ($scenario -in @('iframeReady', 'rogueIframe', 'sessionNavigationIframe', 'commercialBoth')) { 'Commercial' } else { 'USGovDoD' }
            $TenantId = $tenant
            $SubscriptionId = $subscription; $ResourceGroupName = 'Test-RG'; $WorkspaceName = 'Test-Workspace'
            $OutputPath = Join-Path $tempRoot "entry$scenario"; $ProfilePath = Join-Path $tempRoot "edge$scenario"
            $PSCommandPath = $scriptPath; $PSScriptRoot = Split-Path $scriptPath -Parent
            $UserPrincipalName = ''; $SelectEdgeProfile = $false; $EdgeProfileDirectory = ''
            $SentinelApiVersion = if ($scenario -like 'governmentDiscovery*' -or $CloudEnvironment -eq 'Commercial') { '' } else { '2025-09-01' }
            $ResetProfile = $false; $RemoveCachedProfile = $true; $DetectionNames = @(); $SentinelRuleNames = @()
            $LoginTimeoutSeconds = 30; $CaptureSeconds = 5
            $defenderHost = 'security.apps.mil'
            $portalUrl = "https://$defenderHost/v2/custom_detection?tid=$tenant"
            try { Invoke-Expression $entrypoint } catch {
                if ($scenario -notin $failureScenarios) { throw }
                $script:entryThrew = $true
            }
        }
        $manifest = Get-Content (Join-Path $tempRoot "entry$scenario\manifest.json") -Raw | ConvertFrom-Json
        if ($scenario -in $failureScenarios) {
            Assert-True (-not $manifest.complete -and $script:entryThrew) 'Combined failure is not success'
            if ($scenario -eq 'mdeFailure') {
                Assert-True ($manifest.Sentinel.complete -and -not $manifest.MDE.complete) 'Sentinel continues after MDE failure'
            } elseif ($scenario -eq 'sentinelFailure') {
                Assert-True ($manifest.MDE.complete -and -not $manifest.Sentinel.complete) 'MDE success retained after Sentinel failure'
                $sentinelManifest = Get-Content (Join-Path $tempRoot "entry$scenario\Sentinel\manifest.json") -Raw | ConvertFrom-Json
                Assert-True ($sentinelManifest.failureDetails[0].browserStatus -eq 'httpError' -and
                    $sentinelManifest.failureDetails[0].httpStatus -eq 403) 'Exact safe browser status and HTTP code preserved'
            } else {
                $expectedStage = switch ($scenario) {
                    'malformedReadiness' { 'WaitForPortalAuthentication' }
                    'malformedListReply' { 'RequestListPage' }
                    'invalidJson' { 'ParseListPage' }
                    'captureCollision' { 'SavePageCapture' }
                    'protocolFailure' { 'RequestListPage' }
                    'malformedSerializedReply' { 'RequestListPage' }
                    'browserExecutionFailure' { 'RequestListPage' }
                    'http401' { 'RequestListPage' }
                    { $_ -like 'sessionNavigation*' } { 'RequestListPage' }
                    'governmentDiscovery403' { 'DiscoverGovernmentApiVersion' }
                }
                Assert-True ($manifest.failureDetails[0].stage -eq $expectedStage -and
                    $manifest.failureDetails[0].scriptLineNumber -gt 0 -and
                    $manifest.failureDetails[0].exceptionType) 'Original exception stage type and line retained'
                Assert-True (-not ((Get-Content (Join-Path $tempRoot "entry$scenario\manifest.json") -Raw) -match
                    'SYNTHETIC_SECRET_NOT_FOR_LOGS|original protected fixture|CustomDetectionsOffline-')) 'Diagnostics do not expose raw response or filesystem exception'
                if ($scenario -eq 'captureCollision') {
                    Assert-True ((Get-Content (Join-Path $tempRoot "entry$scenario\captures\page-0001.json") -Raw) -eq
                        'original protected fixture') 'Preexisting capture preserved'
                }
                if ($scenario -eq 'protocolFailure') {
                    Assert-True ($manifest.failureDetails[0].cdpCode -eq -32602 -and
                        $manifest.failureDetails[0].cdpReason -eq 'InvalidParameters' -and
                        $script:listAttemptCount -eq 1) 'Unknown protocol failures are not retried or mistaken for HTTP failures'
                }
                if ($scenario -eq 'browserExecutionFailure') {
                    Assert-True ($manifest.failureDetails[0].browserExceptionType -eq 'TypeError' -and
                        $script:listAttemptCount -eq 1) 'Safe JavaScript exception class retained without description or retry'
                }
                if ($scenario -eq 'http401') {
                    Assert-True ($manifest.failureDetails[0].browserStatus -eq 'httpError' -and
                        $manifest.failureDetails[0].httpStatus -eq 401 -and
                        $script:listAttemptCount -eq 1) 'Authentication failure retains HTTP 401 and is never retried'
                }
                if ($scenario -like 'sessionNavigation*') {
                    $expectedAttempts = if ($scenario -eq 'sessionNavigationRepeated') { 2 } else { 1 }
                    Assert-True ($manifest.failureDetails[0].cdpReason -eq 'SessionUnavailable' -and
                        $script:listAttemptCount -eq $expectedAttempts) 'Closed foreign or repeatedly lost targets fail without unrestricted retry'
                    Assert-True ($script:rootReattached -eq ($scenario -eq 'sessionNavigationRepeated')) 'Closed or untrusted target is never reattached'
                }
                if ($scenario -eq 'governmentDiscovery403') {
                    Assert-True ($script:listAttemptCount -eq 0 -and $script:discoveryCount -eq 1 -and
                        $manifest.failureDetails[0].httpStatus -eq 403 -and
                        $manifest.failureDetails[0].message -match 'Supply SentinelApiVersion') 'Metadata permission failure stops before rule GET with actionable safe diagnostics'
                }
            }
        } else { Assert-True $manifest.complete "Actual $mode selection entrypoint" }
        if ($scenario -eq 'MDE') {
            Assert-True ($manifest.sourceSelection.excludedSentinelCount -eq 249 -and
                @($manifest.errors).Count -eq 0 -and $manifest.ruleCount -eq 1) 'Foreign Sentinel summaries reported as deliberate exclusion not detail errors'
        }
        if ($scenario -in @('governmentDiscovery', 'governmentDiscoveryContextLoss')) {
            $expectedAttempts = if ($scenario -eq 'governmentDiscoveryContextLoss') { 2 } else { 1 }
            Assert-True ($manifest.apiVersion -eq '2024-03-01' -and
                $manifest.apiVersionSource -eq 'SubscriptionProviderMetadata' -and
                $script:discoveryCount -eq 1 -and $script:listAttemptCount -eq $expectedAttempts) 'Actual Government entrypoint selects advertised version before exporting'
            if ($scenario -eq 'governmentDiscoveryContextLoss') {
                Assert-True ($manifest.browserContextRecoveries -eq 1 -and $manifest.captureCount -eq 1 -and
                    $script:listSessions[1] -eq 'recovered-root') 'Government selection survives controlled target recovery without changing export version'
            }
        }
        if ($scenario -in @('iframeReady', 'rogueIframe', 'sessionNavigationIframe', 'commercialBoth')) {
            Assert-True ($script:discoveryCount -eq 0) 'Commercial entrypoint performs no provider discovery'
        }
        if ($scenario -eq 'commercialBoth') {
            $commercialSentinel = Get-Content (Join-Path $tempRoot "entry$scenario\Sentinel\manifest.json") -Raw | ConvertFrom-Json
            Assert-True ($manifest.MDE.complete -and $manifest.Sentinel.complete -and
                $commercialSentinel.apiVersion -eq '2025-09-01' -and
                $commercialSentinel.apiVersionSource -eq 'CommercialDefault') 'Current Commercial Both path preserves independently complete manifests'
        }
        if ($scenario -eq 'listContextLoss') {
            Assert-True ($manifest.browserContextRecoveries -eq 1 -and
                $script:listContexts.Count -eq 2 -and $script:listContexts[0] -eq 1 -and
                $script:listContexts[1] -eq 2 -and $manifest.captureCount -eq 1) 'Readiness to list navigation race reacquires verified context and saves one page'
        }
        if ($scenario -in @('sessionNavigationRoot', 'sessionNavigationIframe')) {
            $expectedContext = if ($scenario -eq 'sessionNavigationIframe') { 4 } else { 3 }
            $expectedSession = if ($scenario -eq 'sessionNavigationIframe') { 'fresh-react' } else { 'recovered-root' }
            Assert-True ($manifest.browserContextRecoveries -eq 1 -and $manifest.captureCount -eq 1 -and
                $script:listAttemptCount -eq 2 -and $script:listContexts[1] -eq $expectedContext -and
                $script:listSessions[1] -eq $expectedSession) 'Exact navigation protocol error reattaches then revalidates fresh context and saves only one page'
        }
        if ($scenario -eq 'largeSerializedReply') {
            $saved = Get-Content (Join-Path $tempRoot "entry$scenario\rules\A_B.json") -Raw -Encoding UTF8 | ConvertFrom-Json
            Assert-True ($saved.properties.query.Length -gt 650000 -and
                $saved.properties.query.Contains((([string][char]0x03A9) * 100))) 'Real CDP JSON serialization preserves large Unicode rule bodies'
        }
        if ($scenario -eq 'waitingThenReady') {
            Assert-True ($script:portalPollCount -eq 3) 'Unavailable observer and unauthenticated page wait instead of exporting'
        }
        if ($scenario -eq 'navigationThenReady') {
            Assert-True ($script:portalPollCount -eq 2) 'Navigation context loss waits instead of closing Edge'
        }
        if ($scenario -eq 'iframeReady') {
            Assert-True ($script:listContexts.Count -eq 1 -and $script:listContexts[0] -eq 2 -and
                $script:listSessions[0] -eq 'react-session' -and
                $manifest.browserOrigin -eq 'https://sandbox-1.reactblade.portal.azure.net') 'Verified iframe realm used for ARM request without credential transfer'
            $framePreload = -1; $frameResume = -1
            for ($i = 0; $i -lt $script:commandOrder.Count; $i++) {
                $command = $script:commandOrder[$i]
                if ($command.SessionId -ne 'react-session') { continue }
                if ($command.Method -eq 'Page.addScriptToEvaluateOnNewDocument') { $framePreload = $i }
                if ($command.Method -eq 'Runtime.runIfWaitingForDebugger') { $frameResume = $i }
            }
            Assert-True ($framePreload -ge 0 -and $frameResume -gt $framePreload) 'Iframe startup observer registered before application debugger resume'
        }
        if ($scenario -eq 'rogueIframe') {
            Assert-True ('react-session' -notin $script:evaluatedSessions -and
                $script:listContexts[0] -eq 1) 'Untrusted iframe never receives a runtime evaluation'
        }
        if ($scenario -eq 'Sentinel') {
            $rootPreload = -1; $portalNavigation = -1; $pausedAttach = -1
            for ($i = 0; $i -lt $script:commandOrder.Count; $i++) {
                $command = $script:commandOrder[$i]
                if ($command.SessionId) { continue }
                if ($command.Method -eq 'Page.addScriptToEvaluateOnNewDocument') { $rootPreload = $i }
                if ($command.Method -eq 'Target.setAutoAttach' -and $command.WaitForDebugger) { $pausedAttach = $i }
                if ($command.Method -eq 'Runtime.evaluate' -and $command.Expression -match
                    'setTimeout.*location.assign.*https://portal.azure') { $portalNavigation = $i }
            }
            Assert-True ($rootPreload -ge 0 -and $portalNavigation -gt $rootPreload) 'Root startup observer registered before Azure portal navigation'
            Assert-True ($pausedAttach -ge 0 -and $portalNavigation -gt $pausedAttach) 'Iframe pause on startup enabled before Azure portal navigation'
        }
        Assert-True (-not (Test-Path (Join-Path $tempRoot "edge$scenario"))) 'Owned profile cleanup'
    }
    $mdeCopy = Get-Content (Join-Path $tempRoot 'entryBoth\MDE\rules\MDE rule.json') -Raw | ConvertFrom-Json
    Assert-True ($mdeCopy.huntingQuery.queryText -eq $mdeRule.huntingQuery.queryText) 'Combined MDE body preserved'

    # Test actual emitted browser JavaScript using synthetic in memory browser and API fixtures.
    $browserInputs = [ordered]@{
        observer = New-SentinelBrowserObserver $target
        govObserver = New-SentinelBrowserObserver $explicitGov
        govAutoObserver = New-SentinelBrowserObserver (Get-SentinelTarget $tenant $subscription 'Test-RG' 'Test-Workspace' 'USGovDoD')
        protocolPollExpression = $script:protocolPollExpression
        mdeFunction = ($ast.Find({ param($n)
            $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-PortalCustomDetections'
        }, $true)).Extent.Text
    }
    $browserInputs | ConvertTo-Json -Depth 10 -Compress |
        & node (Join-Path $PSScriptRoot 'Test-GetCustomDetections.browser.cjs')
    if ($LASTEXITCODE -ne 0) { throw 'Browser JavaScript regression failed.' }
    "PowerShell offline assertions passed: $script:passed"
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}
