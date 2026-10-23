<#
.SYNOPSIS
    Export Defender XDR custom detections and Microsoft Sentinel analytics rules.

.DESCRIPTION
    Read only collection for PowerShell 7. The script uses the current Azure CLI
    sign in, exports full KQL and rule configuration to CSV and JSON, and creates
    one ZIP file.

    QUICK START FOR A FULL DOD EXPORT

    Run these commands separately in PowerShell 7 on a managed, compliant
    workstation. Replace values inside angle brackets.

    1. Install the Graph authentication module:
       Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber

    2. Select Azure Government:
       az cloud set --name AzureUSGovernment

    3. Sign in with normal browser MFA:
       az login --tenant '<tenant id>'

    4. List subscriptions and select the correct one:
       az account list --query "[].{Name:name,SubscriptionId:id,TenantId:tenantId,Selected:isDefault}" --output table
       az account set --subscription '<subscription id>'

    5. Store the selected tenant and subscription:
       $tenantId = az account show --query tenantId --output tsv
       $subscriptionId = az account show --query id --output tsv

    6. Sign in to DoD Graph with normal browser MFA:
       Connect-MgGraph -Environment USGovDoD -TenantId $tenantId -Scopes 'CustomDetection.Read.All' -NoWelcome

    7. Find the Sentinel workspace and resource group:
       az resource list --resource-type Microsoft.OperationalInsights/workspaces --query "[].{Workspace:name,ResourceGroup:resourceGroup}" --output table

    8. Run the script from its folder:
       .\Export-XdrDetectionRules.ps1 -TenantId $tenantId -SubscriptionId $subscriptionId -ResourceGroupName '<resource group>' -WorkspaceName '<workspace name>'

    9. Open the printed report folder and retrieve the printed ZIP file.

    Do not add UseDeviceCode when Conditional Access blocks device code.
    Do not run pwsh followed by the script when already inside PowerShell.

    For a full DoD export, run the script from PowerShell 7 on a managed,
    compliant workstation. Authenticate Microsoft Graph with the normal browser
    MFA flow before running the script. The script reuses that Graph context.

    Azure Cloud Shell can export Sentinel analytics rules. In some DoD tenants,
    Conditional Access blocks device code authentication and the Cloud Shell
    managed credential cannot request a token for the DoD Graph audience. In
    that case, use a managed workstation for the Defender XDR export.

    In PowerShell Cloud Shell, run the script directly with
    ./Export-XdrDetectionRules.ps1. Do not start a nested pwsh process.

    Automated investigation and response settings are removed from Defender XDR
    output. Microsoft Sentinel automation rules are not queried.

    Microsoft Graph beta currently documents custom detection export for the
    global cloud only. In US Government clouds, the script attempts the selected
    government Graph endpoint and records a partial result if the tenant rejects
    the request. Sentinel analytics rule export remains supported through Azure
    Resource Manager.

.PARAMETER SubscriptionId
    Subscription that contains the Microsoft Sentinel workspace.

.PARAMETER ResourceGroupName
    Resource group that contains the Microsoft Sentinel workspace.

.PARAMETER WorkspaceName
    Log Analytics workspace that is enabled for Microsoft Sentinel.

.PARAMETER TenantId
    Optional tenant identifier used to verify the current Azure CLI sign in.

.PARAMETER CloudEnvironment
    Target cloud. Global uses AzureCloud and graph.microsoft.com. USGov and
    USGovDoD use AzureUSGovernment with their corresponding Graph endpoint.
    The default is USGovDoD.

.PARAMETER OutputFolder
    Existing or new folder for the report directory and ZIP. The default is a
    Reports folder under the current directory. No temporary folder is used.

.PARAMETER UseDeviceCode
    Use Microsoft Graph device code sign in only when required. If omitted, the
    script reuses a matching Graph context or uses the normal browser sign in.
    Do not use this switch when Conditional Access blocks device code.

.EXAMPLE
    az cloud set --name AzureUSGovernment
    az login --tenant '<tenant id>'
    az account set --subscription '<subscription id>'
    az account show --output table

.EXAMPLE
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber

.EXAMPLE
    Connect-MgGraph -Environment USGovDoD -TenantId '<tenant id>' -Scopes 'CustomDetection.Read.All' -NoWelcome

.EXAMPLE
    az resource list --subscription '<subscription id>' --resource-type Microsoft.OperationalInsights/workspaces --query "[].{Workspace:name,ResourceGroup:resourceGroup}" --output table

.EXAMPLE
    ./Export-XdrDetectionRules.ps1 -CloudEnvironment USGovDoD -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -ResourceGroupName '<resource group>' -WorkspaceName '<workspace>'

.EXAMPLE
    ./Export-XdrDetectionRules.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -ResourceGroupName '<resource group>' -WorkspaceName '<workspace>' -OutputFolder ./Reports

.NOTES
    Required Defender XDR permission: CustomDetection.Read.All and a supported
    Defender role such as Security Reader.

    Install the Graph authentication module once:
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber

    Recommended DoD authentication:
    1. Use PowerShell 7 on a managed, compliant workstation.
    2. Connect with Connect-MgGraph and normal browser MFA.
    3. Do not use device code if Conditional Access blocks it.
    4. Run the script from the same PowerShell session.

    Cloud Shell notes:
    1. Run ./Export-XdrDetectionRules.ps1 directly, not pwsh followed by the script.
    2. Sentinel export can succeed even when DoD Graph authentication is blocked.
    3. Use the managed workstation path for a full export when Graph is blocked.

    Required Microsoft Sentinel access: read access to the workspace and its
    Microsoft.SecurityInsights alertRules resources.

    Download the generated ZIP from Cloud Shell by selecting Manage files,
    Download, and entering the printed ZIP path.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceName,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [ValidateSet('Global', 'USGov', 'USGovDoD')]
    [string]$CloudEnvironment = 'USGovDoD',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFolder = (Join-Path -Path (Get-Location).Path -ChildPath 'Reports'),

    [Parameter()]
    [switch]$UseDeviceCode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PropertyValue {
    param(
        [Parameter()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]::Equals([string]$key, $PropertyName, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $InputObject[$key]
            }
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties |
        Where-Object { [string]::Equals($_.Name, $PropertyName, [System.StringComparison]::OrdinalIgnoreCase) } |
        Select-Object -First 1

    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-DictionaryWithoutProperty {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Dictionary,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    $keyToRemove = $null
    foreach ($key in $Dictionary.Keys) {
        if ([string]::Equals([string]$key, $PropertyName, [System.StringComparison]::OrdinalIgnoreCase)) {
            $keyToRemove = $key
            break
        }
    }

    if ($null -ne $keyToRemove) {
        $Dictionary.Remove($keyToRemove)
    }

    return $Dictionary
}

function ConvertTo-CompactJson {
    param(
        [Parameter()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return ''
    }

    return ($InputObject | ConvertTo-Json -Depth 100 -Compress)
}

function Invoke-AzCliText {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = @(& az @Arguments 2>&1 | ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0) {
        throw ("Azure CLI failed: az {0}`n{1}" -f ($Arguments -join ' '), ($output -join [Environment]::NewLine))
    }

    return ($output -join [Environment]::NewLine).Trim()
}

function Invoke-AzCliJson {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $text = Invoke-AzCliText -Arguments $Arguments
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    try {
        return ($text | ConvertFrom-Json -Depth 100)
    }
    catch {
        throw ("Azure CLI returned invalid JSON for az {0}: {1}" -f ($Arguments -join ' '), $_.Exception.Message)
    }
}

function Resolve-CloudSetting {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EnvironmentName
    )

    switch ($EnvironmentName) {
        'Global' {
            return [pscustomobject]@{
                AzureCliCloud = 'AzureCloud'
                GraphHost = 'graph.microsoft.com'
                GraphEnvironment = 'Global'
                GraphSupport = 'Supported'
            }
        }
        'USGov' {
            return [pscustomobject]@{
                AzureCliCloud = 'AzureUSGovernment'
                GraphHost = 'graph.microsoft.us'
                GraphEnvironment = 'USGov'
                GraphSupport = 'Not documented as supported'
            }
        }
        'USGovDoD' {
            return [pscustomobject]@{
                AzureCliCloud = 'AzureUSGovernment'
                GraphHost = 'dod-graph.microsoft.us'
                GraphEnvironment = 'USGovDoD'
                GraphSupport = 'Not documented as supported'
            }
        }
        default {
            throw "Unsupported cloud environment: $EnvironmentName"
        }
    }
}

function Get-XdrCustomDetectionRule {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GraphHost
    )

    $rules = @()
    $uri = "https://$GraphHost/beta/security/rules/detectionRules?`$top=100"

    while (-not [string]::IsNullOrWhiteSpace($uri)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $rules += @(Get-PropertyValue -InputObject $response -PropertyName 'value')
        $uri = [string](Get-PropertyValue -InputObject $response -PropertyName '@odata.nextLink')
    }

    return $rules
}

function ConvertTo-SanitizedXdrRule {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $copy = $Rule | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable -Depth 100
    $detectionAction = Get-PropertyValue -InputObject $copy -PropertyName 'detectionAction'
    if ($detectionAction -is [System.Collections.IDictionary]) {
        $copy['detectionAction'] = ConvertTo-DictionaryWithoutProperty -Dictionary $detectionAction -PropertyName 'automatedActions'
    }

    return $copy
}

function ConvertTo-XdrRuleSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $queryCondition = Get-PropertyValue -InputObject $Rule -PropertyName 'queryCondition'
    $schedule = Get-PropertyValue -InputObject $Rule -PropertyName 'schedule'
    $detectionAction = Get-PropertyValue -InputObject $Rule -PropertyName 'detectionAction'
    $alertTemplate = Get-PropertyValue -InputObject $detectionAction -PropertyName 'alertTemplate'

    [pscustomobject]@{
        RuleId = Get-PropertyValue -InputObject $Rule -PropertyName 'id'
        DisplayName = Get-PropertyValue -InputObject $Rule -PropertyName 'displayName'
        Description = Get-PropertyValue -InputObject $Rule -PropertyName 'description'
        Status = Get-PropertyValue -InputObject $Rule -PropertyName 'status'
        KqlQuery = Get-PropertyValue -InputObject $queryCondition -PropertyName 'queryText'
        ScheduleFrequency = Get-PropertyValue -InputObject $schedule -PropertyName 'frequency'
        ScheduleNextRunUtc = Get-PropertyValue -InputObject $schedule -PropertyName 'nextRunDateTime'
        AlertTitle = Get-PropertyValue -InputObject $alertTemplate -PropertyName 'title'
        AlertDescription = Get-PropertyValue -InputObject $alertTemplate -PropertyName 'description'
        AlertSeverity = Get-PropertyValue -InputObject $alertTemplate -PropertyName 'severity'
        AlertCategory = Get-PropertyValue -InputObject $alertTemplate -PropertyName 'category'
        RecommendedActions = ConvertTo-CompactJson -InputObject (Get-PropertyValue -InputObject $alertTemplate -PropertyName 'recommendedActions')
        CreatedBy = Get-PropertyValue -InputObject $Rule -PropertyName 'createdBy'
        CreatedUtc = Get-PropertyValue -InputObject $Rule -PropertyName 'createdDateTime'
        LastModifiedBy = Get-PropertyValue -InputObject $Rule -PropertyName 'lastModifiedBy'
        LastModifiedUtc = Get-PropertyValue -InputObject $Rule -PropertyName 'lastModifiedDateTime'
    }
}

function Get-SentinelAnalyticsRule {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceManagerEndpoint,

        [Parameter(Mandatory = $true)]
        [string]$Subscription,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroup,

        [Parameter(Mandatory = $true)]
        [string]$Workspace
    )

    $subscriptionPart = [Uri]::EscapeDataString($Subscription)
    $resourceGroupPart = [Uri]::EscapeDataString($ResourceGroup)
    $workspacePart = [Uri]::EscapeDataString($Workspace)
    $baseEndpoint = $ResourceManagerEndpoint.TrimEnd('/')
    $uri = "$baseEndpoint/subscriptions/$subscriptionPart/resourceGroups/$resourceGroupPart/providers/Microsoft.OperationalInsights/workspaces/$workspacePart/providers/Microsoft.SecurityInsights/alertRules?api-version=2025-09-01"
    $rules = @()

    while (-not [string]::IsNullOrWhiteSpace($uri)) {
        $response = Invoke-AzCliJson -Arguments @(
            'rest',
            '--method', 'get',
            '--url', $uri,
            '--output', 'json',
            '--only-show-errors'
        )
        $rules += @(Get-PropertyValue -InputObject $response -PropertyName 'value')
        $uri = [string](Get-PropertyValue -InputObject $response -PropertyName 'nextLink')
    }

    return $rules
}

function ConvertTo-SentinelRuleSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $properties = Get-PropertyValue -InputObject $Rule -PropertyName 'properties'

    [pscustomobject]@{
        RuleId = Get-PropertyValue -InputObject $Rule -PropertyName 'id'
        Name = Get-PropertyValue -InputObject $Rule -PropertyName 'name'
        Kind = Get-PropertyValue -InputObject $Rule -PropertyName 'kind'
        DisplayName = Get-PropertyValue -InputObject $properties -PropertyName 'displayName'
        Description = Get-PropertyValue -InputObject $properties -PropertyName 'description'
        Enabled = Get-PropertyValue -InputObject $properties -PropertyName 'enabled'
        Severity = Get-PropertyValue -InputObject $properties -PropertyName 'severity'
        KqlQuery = Get-PropertyValue -InputObject $properties -PropertyName 'query'
        QueryFrequency = Get-PropertyValue -InputObject $properties -PropertyName 'queryFrequency'
        QueryPeriod = Get-PropertyValue -InputObject $properties -PropertyName 'queryPeriod'
        TriggerOperator = Get-PropertyValue -InputObject $properties -PropertyName 'triggerOperator'
        TriggerThreshold = Get-PropertyValue -InputObject $properties -PropertyName 'triggerThreshold'
        SuppressionEnabled = Get-PropertyValue -InputObject $properties -PropertyName 'suppressionEnabled'
        SuppressionDuration = Get-PropertyValue -InputObject $properties -PropertyName 'suppressionDuration'
        Tactics = (@(Get-PropertyValue -InputObject $properties -PropertyName 'tactics') -join ';')
        Techniques = (@(Get-PropertyValue -InputObject $properties -PropertyName 'techniques') -join ';')
        SubTechniques = (@(Get-PropertyValue -InputObject $properties -PropertyName 'subTechniques') -join ';')
        EntityMappingsJson = ConvertTo-CompactJson -InputObject (Get-PropertyValue -InputObject $properties -PropertyName 'entityMappings')
        AlertDetailsOverrideJson = ConvertTo-CompactJson -InputObject (Get-PropertyValue -InputObject $properties -PropertyName 'alertDetailsOverride')
        IncidentConfigurationJson = ConvertTo-CompactJson -InputObject (Get-PropertyValue -InputObject $properties -PropertyName 'incidentConfiguration')
        EventGroupingSettingsJson = ConvertTo-CompactJson -InputObject (Get-PropertyValue -InputObject $properties -PropertyName 'eventGroupingSettings')
        AlertRuleTemplateName = Get-PropertyValue -InputObject $properties -PropertyName 'alertRuleTemplateName'
        TemplateVersion = Get-PropertyValue -InputObject $properties -PropertyName 'templateVersion'
        CreatedBy = Get-PropertyValue -InputObject (Get-PropertyValue -InputObject $properties -PropertyName 'createdBy') -PropertyName 'name'
        CreatedUtc = Get-PropertyValue -InputObject $properties -PropertyName 'createdDateUtc'
        LastModifiedBy = Get-PropertyValue -InputObject (Get-PropertyValue -InputObject $properties -PropertyName 'lastModifiedBy') -PropertyName 'name'
        LastModifiedUtc = Get-PropertyValue -InputObject $properties -PropertyName 'lastModifiedUtc'
    }
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $InputObject | ConvertTo-Json -Depth 100 | Out-File -LiteralPath $Path -Encoding utf8
}

try {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'PowerShell 7 or later is required. In Cloud Shell, select PowerShell before running the script.'
    }

    if ($null -eq (Get-Command -Name az -ErrorAction SilentlyContinue)) {
        throw 'Azure CLI was not found. Run this script in Azure Cloud Shell or install Azure CLI.'
    }

    $cloud = Resolve-CloudSetting -EnvironmentName $CloudEnvironment
    $activeCloud = Invoke-AzCliText -Arguments @('cloud', 'show', '--query', 'name', '--output', 'tsv', '--only-show-errors')
    if (-not [string]::Equals($activeCloud, $cloud.AzureCliCloud, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("Azure CLI is using {0}. Run: az cloud set --name {1}; az login" -f $activeCloud, $cloud.AzureCliCloud)
    }

    $account = Invoke-AzCliJson -Arguments @('account', 'show', '--output', 'json', '--only-show-errors')
    if ($null -eq $account) {
        throw 'No Azure CLI account is signed in. Run az login before this script.'
    }

    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $currentTenant = [string](Get-PropertyValue -InputObject $account -PropertyName 'tenantId')
        if (-not [string]::Equals($currentTenant, $TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ("Azure CLI is signed in to tenant {0}. Run: az login --tenant {1}" -f $currentTenant, $TenantId)
        }
    }

    $null = Invoke-AzCliText -Arguments @('account', 'set', '--subscription', $SubscriptionId, '--only-show-errors')
    $selectedAccount = Invoke-AzCliJson -Arguments @('account', 'show', '--output', 'json', '--only-show-errors')
    $selectedSubscription = [string](Get-PropertyValue -InputObject $selectedAccount -PropertyName 'id')
    if (-not [string]::Equals($selectedSubscription, $SubscriptionId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("Azure CLI did not select subscription {0}." -f $SubscriptionId)
    }

    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    $resolvedOutputFolder = (Resolve-Path -LiteralPath $OutputFolder).Path
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd_HHmmss')
    $runFolder = Join-Path -Path $resolvedOutputFolder -ChildPath ("XdrDetectionExport_{0}" -f $stamp)
    New-Item -ItemType Directory -Path $runFolder -Force | Out-Null

    $resourceManagerEndpoint = Invoke-AzCliText -Arguments @('cloud', 'show', '--query', 'endpoints.resourceManager', '--output', 'tsv', '--only-show-errors')
    if ([string]::IsNullOrWhiteSpace($resourceManagerEndpoint)) {
        throw 'Azure CLI did not return the Resource Manager endpoint for the active cloud.'
    }

    $sentinelRules = @(Get-SentinelAnalyticsRule -ResourceManagerEndpoint $resourceManagerEndpoint -Subscription $SubscriptionId -ResourceGroup $ResourceGroupName -Workspace $WorkspaceName)
    $sentinelRawPath = Join-Path -Path $runFolder -ChildPath 'sentinel_analytics_rules.json'
    $sentinelCsvPath = Join-Path -Path $runFolder -ChildPath 'sentinel_analytics_rules.csv'
    Write-JsonFile -InputObject $sentinelRules -Path $sentinelRawPath
    @($sentinelRules | ForEach-Object { ConvertTo-SentinelRuleSummary -Rule $_ }) |
        Sort-Object -Property DisplayName |
        Export-Csv -LiteralPath $sentinelCsvPath -NoTypeInformation -Encoding utf8

    $xdrStatus = 'Succeeded'
    $xdrError = ''
    $xdrRules = @()

    try {
        $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication | Select-Object -First 1
        if ($null -eq $graphModule) {
            throw 'Microsoft.Graph.Authentication is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber'
        }

        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
        $reuseGraphContext = $false
        if ($null -ne $graphContext) {
            $contextEnvironment = [string](Get-PropertyValue -InputObject $graphContext -PropertyName 'Environment')
            $contextTenant = [string](Get-PropertyValue -InputObject $graphContext -PropertyName 'TenantId')
            $contextScopes = @(Get-PropertyValue -InputObject $graphContext -PropertyName 'Scopes')
            $environmentMatches = [string]::Equals($contextEnvironment, $cloud.GraphEnvironment, [System.StringComparison]::OrdinalIgnoreCase)
            $tenantMatches = [string]::IsNullOrWhiteSpace($TenantId) -or [string]::Equals($contextTenant, $TenantId, [System.StringComparison]::OrdinalIgnoreCase)
            $scopeMatches = $contextScopes -contains 'CustomDetection.Read.All'
            $reuseGraphContext = $environmentMatches -and $tenantMatches -and $scopeMatches
        }

        $createdGraphContext = $false
        if (-not $reuseGraphContext) {
            $connectParameters = @{
                Scopes = @('CustomDetection.Read.All')
                Environment = $cloud.GraphEnvironment
                NoWelcome = $true
            }
            if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
                $connectParameters['TenantId'] = $TenantId
            }
            if ($UseDeviceCode) {
                $connectParameters['UseDeviceCode'] = $true
            }

            Connect-MgGraph @connectParameters | Out-Null
            $createdGraphContext = $true
        }

        try {
            $xdrRules = @(Get-XdrCustomDetectionRule -GraphHost $cloud.GraphHost)
        }
        finally {
            if ($createdGraphContext) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            }
        }

        $sanitizedXdrRules = @($xdrRules | ForEach-Object { ConvertTo-SanitizedXdrRule -Rule $_ })
        $xdrRawPath = Join-Path -Path $runFolder -ChildPath 'xdr_custom_detection_rules.json'
        $xdrCsvPath = Join-Path -Path $runFolder -ChildPath 'xdr_custom_detection_rules.csv'
        Write-JsonFile -InputObject $sanitizedXdrRules -Path $xdrRawPath
        @($sanitizedXdrRules | ForEach-Object { ConvertTo-XdrRuleSummary -Rule $_ }) |
            Sort-Object -Property DisplayName |
            Export-Csv -LiteralPath $xdrCsvPath -NoTypeInformation -Encoding utf8
    }
    catch {
        $xdrStatus = 'Failed'
        $xdrError = $_.Exception.Message
        $xdrFailurePath = Join-Path -Path $runFolder -ChildPath 'xdr_custom_detection_export_error.txt'
        @(
            "Cloud: $CloudEnvironment"
            "Graph endpoint: https://$($cloud.GraphHost)"
            "Documented support: $($cloud.GraphSupport)"
            'Required permission: CustomDetection.Read.All'
            "Error: $xdrError"
        ) | Out-File -LiteralPath $xdrFailurePath -Encoding utf8
        Write-Warning ("Defender XDR custom detection export failed. Details: {0}" -f $xdrFailurePath)
    }

    $manifest = [ordered]@{
        ExportedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        CloudEnvironment = $CloudEnvironment
        AzureCliCloud = $cloud.AzureCliCloud
        TenantId = Get-PropertyValue -InputObject $selectedAccount -PropertyName 'tenantId'
        SubscriptionId = $SubscriptionId
        SubscriptionName = Get-PropertyValue -InputObject $selectedAccount -PropertyName 'name'
        ResourceGroupName = $ResourceGroupName
        WorkspaceName = $WorkspaceName
        SentinelAnalyticsRuleCount = $sentinelRules.Count
        SentinelAnalyticsRuleExport = 'Succeeded'
        XdrCustomDetectionCount = $xdrRules.Count
        XdrCustomDetectionExport = $xdrStatus
        XdrGraphDocumentedSupport = $cloud.GraphSupport
        XdrExportError = $xdrError
        AirAndAutomationDataIncluded = $false
    }
    $manifestPath = Join-Path -Path $runFolder -ChildPath 'export_manifest.json'
    Write-JsonFile -InputObject $manifest -Path $manifestPath

    $zipPath = Join-Path -Path $resolvedOutputFolder -ChildPath ("XdrDetectionExport_{0}.zip" -f $stamp)
    Compress-Archive -Path (Join-Path -Path $runFolder -ChildPath '*') -DestinationPath $zipPath -CompressionLevel Optimal

    Write-Output ("Cloud: {0}" -f $CloudEnvironment)
    Write-Output ("Subscription: {0}" -f $SubscriptionId)
    Write-Output ("Sentinel analytics rules: {0}" -f $sentinelRules.Count)
    Write-Output ("Defender XDR custom detections: {0} ({1})" -f $xdrRules.Count, $xdrStatus)
    Write-Output ("Report folder: {0}" -f $runFolder)
    Write-Output ("ZIP file: {0}" -f $zipPath)

    if ($xdrStatus -ne 'Succeeded') {
        Write-Error -Message 'Sentinel export succeeded, but Defender XDR custom detection export failed. Review the error file in the ZIP.' -ErrorAction Continue
        exit 2
    }

    exit 0
}
catch {
    Write-Error ("Export failed: {0}" -f $_.Exception.Message)
    exit 1
}
