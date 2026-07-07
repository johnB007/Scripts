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
Install required Graph beta modules for the current user when missing.

.EXAMPLE
pwsh ./Export-MdeCustomDetectionRules.ps1

.EXAMPLE
pwsh ./Export-MdeCustomDetectionRules.ps1 -CloudEnvironment AzureUsGovernment

.EXAMPLE
pwsh ./Export-MdeCustomDetectionRules.ps1 -ConvertAirToAvScan
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder = '.\mde-rules-export',

    [Parameter()]
    [ValidateSet('Global', 'USGov', 'USGovDoD', 'AzureUsGovernment')]
    [string]$CloudEnvironment = 'Global',

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [switch]$ConvertAirToAvScan,

    [Parameter()]
    [switch]$InstallModules
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

    Install-Module -Name $Name -Scope CurrentUser -Repository PSGallery -Force
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

    $prop = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $prop) {
        return $null
    }

    return $prop.Value
}

function Get-RuleSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $detectionAction = Get-PropertyValue -InputObject $Rule -PropertyName 'DetectionAction'
    $automatedActions = Get-PropertyValue -InputObject $detectionAction -PropertyName 'AutomatedActions'

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
        RuleId = $Rule.Id
        DisplayName = $Rule.DisplayName
        Status = $Rule.Status
        AutomationActionsConfigured = ($automationActionsConfigured -join ';')
        AutomationActionDetail = ($automationActionDetail -join ';')
        HasInitiateInvestigations = ($airCount -gt 0)
        InitiateInvestigationsCount = $airCount
        HasRunAntivirusScans = ($avCount -gt 0)
        RunAntivirusScansCount = $avCount
        LastModifiedDateTime = $Rule.LastModifiedDateTime
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

    $ruleId = $Rule.Id
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
    Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body -ContentType 'application/json' | Out-Null

    return $true
}

try {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'PowerShell 7 or later is required for this script.'
    }

    Ensure-Module -Name 'Microsoft.Graph.Authentication' -Install:$InstallModules
    Ensure-Module -Name 'Microsoft.Graph.Beta.Security' -Install:$InstallModules

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Beta.Security -ErrorAction Stop

    $mgEnvironment = Resolve-MgEnvironmentName -Cloud $CloudEnvironment

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

    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $connectParams['TenantId'] = $TenantId
    }

    Connect-MgGraph @connectParams | Out-Null

    $context = Get-MgContext
    if ($null -eq $context) {
        throw 'Sign in failed. No Graph context was created.'
    }

    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMdd_HHmmss')

    $rules = Get-MgBetaSecurityRuleDetectionRule -All

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
                $converted += [pscustomobject]@{
                    RuleId = $rule.Id
                    DisplayName = $rule.DisplayName
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

    Write-Output ("Cloud environment: {0}" -f $mgEnvironment)
    Write-Output ("Tenant id: {0}" -f $context.TenantId)
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
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
