<#
.SYNOPSIS
Export Microsoft Defender XDR custom detection rules and flag AIR style actions.

.DESCRIPTION
This script lists custom detection rules through Microsoft Graph beta and exports
both raw JSON and a summary CSV. Summary output includes whether a rule has
initiateInvestigations and runAntivirusScans actions.

The script also writes a dedicated CSV that contains only rules that still use
initiateInvestigations so you can update those rules manually.

By default this script is read only. If you set ConvertAirToAvScan, the script
replaces initiateInvestigations with runAntivirusScans on matching rules.

.NOTES
Minimum requirements for read only export:
1. PowerShell 7.
2. A signed in work account in the target tenant.
3. Delegated Microsoft Graph permission CustomDetection.Read.All.
4. Defender role minimum Security Reader.
    Accepted alternatives include Global Reader, Security Operator, or Security Administrator.
5. Graph modules available in user scope:
    Microsoft.Graph.Authentication.

No local admin is required. Module install uses CurrentUser scope.

Cloud Shell notes:
1. You can run this script in Azure Cloud Shell.
2. Permission requirements stay the same for Graph and Defender roles.
3. Azure subscription Owner or Contributor is not required for read only export.

US Government support:
Use -CloudEnvironment AzureUsGovernment.

.PARAMETER OutputFolder
Folder where CSV and JSON files are written.

.PARAMETER CloudEnvironment
Target cloud environment. Supported values:
Global, USGov, USGovDoD, AzureUsGovernment

.PARAMETER TenantId
Optional tenant id for sign in.

.PARAMETER ConvertAirToAvScan
When set, patch rules that use initiateInvestigations.

.PARAMETER InstallModules
Install required Graph modules for the current user when missing.

.PARAMETER UseDeviceCode
Use device code authentication for Graph sign in. Recommended for Cloud Shell.

.PARAMETER UseAzCliToken
Use Azure CLI token for Graph calls. Recommended for Cloud Shell one command execution.

.EXAMPLE
pwsh ./Export-MdeCustomDetectionRules.ps1

.EXAMPLE
pwsh ./Export-MdeCustomDetectionRules.ps1 -CloudEnvironment AzureUsGovernment

.EXAMPLE
## Global tenant copy and paste
$u='https://raw.githubusercontent.com/johnB007/Scripts/7a42712/PowerShell/Export-MdeCustomDetectionRules.ps1'; $f="$env:TEMP\Export-MdeCustomDetectionRules.ps1"; Invoke-WebRequest -Uri $u -OutFile $f; pwsh -File $f -InstallModules

.EXAMPLE
## US Gov tenant copy and paste
$u='https://raw.githubusercontent.com/johnB007/Scripts/7a42712/PowerShell/Export-MdeCustomDetectionRules.ps1'; $f="$env:TEMP\Export-MdeCustomDetectionRules.ps1"; Invoke-WebRequest -Uri $u -OutFile $f; pwsh -File $f -CloudEnvironment AzureUsGovernment -InstallModules

.EXAMPLE
pwsh ./Export-MdeCustomDetectionRules.ps1 -ConvertAirToAvScan

.EXAMPLE
pwsh ./Export-MdeCustomDetectionRules.ps1 -UseDeviceCode

.EXAMPLE
pwsh ./Export-MdeCustomDetectionRules.ps1 -UseAzCliToken
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder = "$env:TEMP\\mde-rules-export",

    [Parameter()]
    [ValidateSet('Global', 'USGov', 'USGovDoD', 'AzureUsGovernment')]
    [string]$CloudEnvironment = 'Global',

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$ConvertAirToAvScan,

    [Parameter()]
    [switch]$InstallModules

    ,
    [Parameter()]
    [switch]$UseDeviceCode

    ,
    [Parameter()]
    [switch]$UseAzCliToken
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-MgEnvironmentName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Cloud
    )

    switch ($Cloud) {
        'Global' { return 'Global' }
        'USGov' { return 'USGov' }
        'USGovDoD' { return 'USGovDoD' }
        'AzureUsGovernment' { return 'USGov' }
        default { throw "Unsupported cloud environment: $Cloud" }
    }
}

function Resolve-GraphHost {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EnvironmentName
    )

    switch ($EnvironmentName) {
        'Global' { return 'graph.microsoft.com' }
        'USGov' { return 'graph.microsoft.us' }
        'USGovDoD' { return 'dod-graph.microsoft.us' }
        default { throw "Unsupported Graph environment: $EnvironmentName" }
    }
}

function Ensure-Module {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter()]
        [switch]$Install
    )

    $module = Get-Module -ListAvailable -Name $Name | Select-Object -First 1
    if ($null -ne $module) {
        return
    }

    if (-not $Install) {
        throw "Module $Name is not installed. Re run with -InstallModules or install it manually."
    }

    Install-Module -Name $Name -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
}

function Get-ActionCount {
    param(
        [Parameter()]
        [object]$ActionList
    )

    if ($null -eq $ActionList) {
        return 0
    }

    return @($ActionList).Count
}

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
        if ($InputObject.Contains($PropertyName)) {
            return $InputObject[$PropertyName]
        }

        foreach ($key in $InputObject.Keys) {
            if ([string]::Equals([string]$key, $PropertyName, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $InputObject[$key]
            }
        }
    }

    $prop = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $prop) {
        return $null
    }

    return $prop.Value
}

function Get-DetectionRules {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$PageSize = 100
    )

    $allRules = @()
    $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules?`$top=$PageSize"

    while (-not [string]::IsNullOrWhiteSpace([string]$uri)) {
        $response = Invoke-GraphRequest -Method GET -Uri $uri
        $pageItems = Get-PropertyValue -InputObject $response -PropertyName 'value'

        if ($null -ne $pageItems) {
            $allRules += @($pageItems)
        }

        $uri = Get-PropertyValue -InputObject $response -PropertyName '@odata.nextLink'
    }

    return $allRules
}

function Get-AzCliGraphToken {
    [CmdletBinding()]
    param()

    $token = az account get-access-token --resource-type ms-graph --query accessToken -o tsv 2>$null
    if ([string]::IsNullOrWhiteSpace([string]$token)) {
        throw 'Failed to get Microsoft Graph token from Azure CLI.'
    }

    return $token
}

function Invoke-GraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'PATCH')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [string]$Body,

        [Parameter()]
        [string]$ContentType = 'application/json'
    )

    if ($script:UseAzCliAuth) {
        $headers = @{ Authorization = "Bearer $($script:AzCliGraphToken)" }
        if ($Method -eq 'GET') {
            return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
        }
        else {
            if ([string]::IsNullOrWhiteSpace($Body)) {
                return Invoke-RestMethod -Method PATCH -Uri $Uri -Headers $headers -ContentType $ContentType
            }

            return Invoke-RestMethod -Method PATCH -Uri $Uri -Headers $headers -Body $Body -ContentType $ContentType
        }
    }

    if ($Method -eq 'GET') {
        return Invoke-MgGraphRequest -Method GET -Uri $Uri
    }

    if ([string]::IsNullOrWhiteSpace($Body)) {
        return Invoke-MgGraphRequest -Method PATCH -Uri $Uri -ContentType $ContentType
    }

    return Invoke-MgGraphRequest -Method PATCH -Uri $Uri -Body $Body -ContentType $ContentType
}

function Get-RuleSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $detectionAction = Get-PropertyValue -InputObject $Rule -PropertyName 'DetectionAction'
    $automatedActions = Get-PropertyValue -InputObject $detectionAction -PropertyName 'AutomatedActions'
    $ruleId = Get-PropertyValue -InputObject $Rule -PropertyName 'Id'
    $displayName = Get-PropertyValue -InputObject $Rule -PropertyName 'DisplayName'
    $status = Get-PropertyValue -InputObject $Rule -PropertyName 'Status'
    $lastModifiedDateTime = Get-PropertyValue -InputObject $Rule -PropertyName 'LastModifiedDateTime'

    if ([string]::IsNullOrWhiteSpace([string]$ruleId)) {
        $ruleId = 'UnknownRuleId'
    }

    if ([string]::IsNullOrWhiteSpace([string]$displayName)) {
        $displayName = '(NoDisplayName)'
    }

    $airActions = Get-PropertyValue -InputObject $automatedActions -PropertyName 'InitiateInvestigations'
    $avActions = Get-PropertyValue -InputObject $automatedActions -PropertyName 'RunAntivirusScans'
    $airCount = Get-ActionCount -ActionList $airActions
    $avCount = Get-ActionCount -ActionList $avActions

    $automationActionsConfigured = @()
    $automationActionDetail = @()

    if ($null -ne $automatedActions) {
        if ($automatedActions -is [System.Collections.IDictionary]) {
            foreach ($key in $automatedActions.Keys) {
                $count = Get-ActionCount -ActionList $automatedActions[$key]
                if ($count -gt 0) {
                    $automationActionsConfigured += [string]$key
                    $automationActionDetail += ("{0}({1})" -f $key, $count)
                }
            }
        }
        else {
            foreach ($prop in $automatedActions.PSObject.Properties) {
                $count = Get-ActionCount -ActionList $prop.Value
                if ($count -gt 0) {
                    $automationActionsConfigured += $prop.Name
                    $automationActionDetail += ("{0}({1})" -f $prop.Name, $count)
                }
            }
        }
    }

    [pscustomobject]@{
        RuleId = $ruleId
        DisplayName = $displayName
        Status = $status
        AutomationActionsConfigured = ($automationActionsConfigured -join ';')
        AutomationActionDetail = ($automationActionDetail -join ';')
        HasInitiateInvestigations = ($airCount -gt 0)
        InitiateInvestigationsCount = $airCount
        HasRunAntivirusScans = ($avCount -gt 0)
        RunAntivirusScansCount = $avCount
        LastModifiedDateTime = $lastModifiedDateTime
    }
}

function Convert-RuleActionsToHashtable {
    param(
        [Parameter()]
        [object]$AutomatedActions
    )

    if ($null -eq $AutomatedActions) {
        return @{}
    }

    $json = $AutomatedActions | ConvertTo-Json -Depth 100
    return ($json | ConvertFrom-Json -AsHashtable)
}

function Patch-RuleToRunAv {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $ruleId = Get-PropertyValue -InputObject $Rule -PropertyName 'Id'
    if ([string]::IsNullOrWhiteSpace([string]$ruleId)) {
        return $false
    }
    $detectionAction = Get-PropertyValue -InputObject $Rule -PropertyName 'DetectionAction'
    $automatedActions = Get-PropertyValue -InputObject $detectionAction -PropertyName 'AutomatedActions'
    $actions = Convert-RuleActionsToHashtable -AutomatedActions $automatedActions

    $airActions = @($actions['initiateInvestigations'])
    if ($airActions.Count -eq 0) {
        return $false
    }

    $existingAvActions = @($actions['runAntivirusScans'])
    if ($existingAvActions.Count -eq 0) {
        $actions['runAntivirusScans'] = $airActions
    }

    $null = $actions.Remove('initiateInvestigations')

    $body = @{
        detectionAction = @{
            automatedActions = $actions
        }
    } | ConvertTo-Json -Depth 100

    $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules/$ruleId"
    Invoke-GraphRequest -Method PATCH -Uri $uri -Body $body -ContentType 'application/json' | Out-Null

    return $true
}

try {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'PowerShell 7 or later is required for this script.'
    }

    $mgEnvironment = Resolve-MgEnvironmentName -Cloud $CloudEnvironment
    $script:UseAzCliAuth = $false
    $script:AzCliGraphToken = $null

    $autoUseAzCli = $false
    if ((Get-Command az -ErrorAction SilentlyContinue) -and ($HOME -like '/home/*')) {
        $autoUseAzCli = $true
    }

    if ($UseAzCliToken -or $autoUseAzCli) {
        $script:UseAzCliAuth = $true
        $script:AzCliGraphToken = Get-AzCliGraphToken
    }

    $context = $null

    if (-not $script:UseAzCliAuth) {
        Ensure-Module -Name 'Microsoft.Graph.Authentication' -Install:$InstallModules
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    }

    $scopes = if ($ConvertAirToAvScan) {
        @('CustomDetection.ReadWrite.All')
    }
    else {
        @('CustomDetection.Read.All')
    }

    $connectParams = @{
        Scopes = $scopes
        Environment = $mgEnvironment
        NoWelcome = $true
    }

    if ($UseDeviceCode) {
        $connectParams['UseDeviceCode'] = $true
    }

    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $connectParams['TenantId'] = $TenantId
    }

    if (-not $script:UseAzCliAuth) {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        $reuseContext = $false

        if ($null -ne $context) {
            $contextEnv = [string](Get-PropertyValue -InputObject $context -PropertyName 'Environment')
            if ([string]::Equals($contextEnv, $mgEnvironment, [System.StringComparison]::OrdinalIgnoreCase)) {
                $reuseContext = $true
            }
        }

        if (-not $reuseContext) {
            Connect-MgGraph @connectParams | Out-Null
            $context = Get-MgContext
        }

        if ($null -eq $context) {
            throw 'Sign in failed. No Graph context was created.'
        }
    }

    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd_HHmmss')

    $rules = Get-DetectionRules

    $rawPath = Join-Path $OutputFolder ("mde_custom_detection_rules_raw_{0}.json" -f $stamp)
    $rules | ConvertTo-Json -Depth 100 | Out-File -FilePath $rawPath -Encoding utf8

    $summary = foreach ($rule in $rules) {
        Get-RuleSummary -Rule $rule
    }

    $csvPath = Join-Path $OutputFolder ("mde_custom_detection_rules_summary_{0}.csv" -f $stamp)
    $summary |
        Sort-Object -Property HasInitiateInvestigations, DisplayName -Descending |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8

    $needsChange = $summary |
        Where-Object { $_.HasInitiateInvestigations -eq $true } |
        Select-Object RuleId, DisplayName, Status, AutomationActionsConfigured, AutomationActionDetail, InitiateInvestigationsCount, HasRunAntivirusScans, RunAntivirusScansCount, LastModifiedDateTime

    $needsChangePath = Join-Path $OutputFolder ("mde_custom_detection_rules_needs_manual_change_{0}.csv" -f $stamp)
    $needsChange |
        Sort-Object DisplayName |
        Export-Csv -Path $needsChangePath -NoTypeInformation -Encoding utf8

    $converted = @()
    if ($ConvertAirToAvScan) {
        foreach ($rule in $rules) {
            $didConvert = Patch-RuleToRunAv -Rule $rule
            if ($didConvert) {
                $rid = Get-PropertyValue -InputObject $rule -PropertyName 'Id'
                $rname = Get-PropertyValue -InputObject $rule -PropertyName 'DisplayName'
                if ([string]::IsNullOrWhiteSpace([string]$rid)) {
                    $rid = 'UnknownRuleId'
                }
                if ([string]::IsNullOrWhiteSpace([string]$rname)) {
                    $rname = '(NoDisplayName)'
                }
                $converted += [pscustomobject]@{
                    RuleId = $rid
                    DisplayName = $rname
                    ConvertedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
                }
            }
        }

        if ($converted.Count -gt 0) {
            $convertedPath = Join-Path $OutputFolder ("mde_custom_detection_rules_converted_{0}.csv" -f $stamp)
            $converted | Export-Csv -Path $convertedPath -NoTypeInformation -Encoding utf8
            Write-Output ("Converted rules CSV: {0}" -f $convertedPath)
        }
        else {
            Write-Output 'No rules required conversion.'
        }
    }

    $tenantIdText = ''
    if ($script:UseAzCliAuth) {
        $tenantIdText = az account show --query tenantId -o tsv 2>$null
    }
    else {
        $tenantIdText = [string](Get-PropertyValue -InputObject $context -PropertyName 'TenantId')
    }

    Write-Output ("Cloud environment: {0}" -f $mgEnvironment)
    if (-not [string]::IsNullOrWhiteSpace($tenantIdText)) {
        Write-Output ("Tenant id: {0}" -f $tenantIdText)
    }
    Write-Output ("Rules found: {0}" -f @($rules).Count)
    Write-Output ("Summary CSV: {0}" -f $csvPath)
    Write-Output ("Needs manual change CSV: {0}" -f $needsChangePath)
    Write-Output ("Rules that need manual change: {0}" -f @($needsChange).Count)
    Write-Output ("Raw JSON: {0}" -f $rawPath)

    exit 0
}
catch {
    Write-Error ("Failed: {0}" -f $_.Exception.Message)
    exit 1
}
finally {
    if (-not $script:UseAzCliAuth) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
