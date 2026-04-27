<#
##############################################################################
LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment. THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys' fees, that arise or result
from the use or distribution of the Sample Code.

This posting is provided "AS IS" with no warranties, and confers no rights. Use
of included script samples are subject to the terms specified
at https://www.microsoft.com/en-us/legal/copyright.
##############################################################################
#>

<#
.SYNOPSIS
   Checks Microsoft Defender for Servers prerequisites on a server.
.DESCRIPTION
   This script validates Defender registry settings, update and service health,
   firewall baseline, environment-specific endpoint connectivity, and local
    Defender exclusions for coexistence with Trellix or similar third-party EPP.
    It also classifies passive-mode onboarding readiness so disabled or
    unsupported Defender states are easier to identify.
.INPUTS
   Server name and environment type (Auto, OnPrem, AzureVM)
.OUTPUTS
   Console output with pass/fail results for each automated check
.NOTES
   Name: Defender_For_Server_prereq.ps1
   Authors/Contributors: Nick OConnor
   DateCreated: 9/29/2025
   Revisions:
     1.0 - Initial version (Nick OConnor, 9/29/2025)
     2.0 - Registry-focused Defender prereq checks (Christian Demopoulos, 3/11/2026)
     3.0 - Added environment switch, update validation, firewall baseline,
           endpoint connectivity sets for OnPrem vs AzureVM, exclusion checks,
           and ordered pre-flight summary (John Barbare, 3/26/2026)
#>

param(
    [string]$ServerName,
    [ValidateSet("Auto", "OnPrem", "AzureVM")]
    [string]$EnvironmentType = "Auto",
    [ValidateSet("Passive", "Active", "Either")]
    [string]$ExpectedMdavMode = "Passive",
    [switch]$GenerateHtmlReport,
    [string]$HtmlReportPath
)

$ErrorActionPreference = "Stop"

if (-not $PSBoundParameters.ContainsKey("GenerateHtmlReport")) {
    $GenerateHtmlReport = $true
}

function New-DefaultHtmlReportPath {
    param([string]$TargetServerName)

    $safeServerName = if ([string]::IsNullOrWhiteSpace($TargetServerName)) { "localhost" } else { $TargetServerName }
    $safeServerName = $safeServerName -replace '[\\/:*?"<>|]', '_'
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $desktopDirectory = [Environment]::GetFolderPath("Desktop")
    return Join-Path $desktopDirectory ("Defender_For_Server_prereq_{0}_{1}.html" -f $safeServerName, $timestamp)
}

function Resolve-HtmlReportPath {
    param(
        [string]$RequestedPath,
        [string]$TargetServerName
    )

    if ([string]::IsNullOrWhiteSpace($RequestedPath)) {
        return New-DefaultHtmlReportPath -TargetServerName $TargetServerName
    }

    $desktopDirectory = [Environment]::GetFolderPath("Desktop")
    if ($RequestedPath -match '^(?:[A-Za-z]:\\)?Desktop(?=\\|$)') {
        $RequestedPath = $RequestedPath -replace '^(?:[A-Za-z]:\\)?Desktop', $desktopDirectory
    }

    $reportDirectory = Split-Path -Path $RequestedPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($reportDirectory) -and -not (Test-Path -Path $reportDirectory)) {
        New-Item -Path $reportDirectory -ItemType Directory -Force | Out-Null
    }

    return $RequestedPath
}

function Convert-StatusToBadgeClass {
    param([string]$Status)

    switch ($Status) {
        "PASS" { return "pass" }
        "FAIL" { return "fail" }
        "WARN" { return "warn" }
        "MANUAL" { return "warn" }
        default { return "warn" }
    }
}

function Get-RuntimeSignalStatus {
    param(
        [AllowNull()]$Value,
        [AllowNull()]$Expected
    )

    if ($null -eq $Value) {
        return "WARN"
    }

    if ($null -ne $Expected -and $Value -ne $Expected) {
        return "WARN"
    }

    return "PASS"
}

function New-HtmlReport {
    param(
        [hashtable]$Result,
        [string]$ReportPath,
        [string]$EvaluatedServerName
    )

    $summaryRows = @(
        @{ Name = "Trellix coexistence readiness"; Status = $Result.ThirdPartyAvCoexistenceStatus },
        @{ Name = "Effective Defender operational state"; Status = $Result.DefenderOperationalStateStatus },
        @{ Name = "All critical checks passed"; Passed = $Result.AllCriticalChecksPassed },
        @{ Name = "MDAV running mode meets expectation"; Passed = $Result.MdavModeMatchesExpectation },
        @{ Name = "All registry validations successful"; Passed = $Result.RegistryValidationsSuccessful },
        @{ Name = "All updates installed and verified"; Passed = $Result.UpdatesInstalledAndVerified },
        @{ Name = "All firewall rules configured"; Passed = $Result.FirewallRulesConfigured },
        @{ Name = "All endpoint connectivity tests successful"; Passed = $Result.EndpointConnectivitySuccessful },
        @{ Name = "All exclusions configured"; Passed = $Result.ExclusionsConfiguredSuccessful }
    )

    $registryRows = @(
        @{ Name = "DisableAntiSpyware (legacy policy key)"; Status = if ($Result.DisableAntiSpyware) { "WARN" } else { "PASS" }; Detail = if ($Result.DisableAntiSpyware) { "Set to 1. Treat as a legacy policy signal and confirm effective state in the runtime section." } else { "Not set" } },
        @{ Name = "DisableAntiVirus (legacy policy key)"; Status = if ($Result.DisableAntiVirus) { "WARN" } else { "PASS" }; Detail = if ($Result.DisableAntiVirus) { "Set to 1. Treat as a legacy policy signal and confirm effective state in the runtime section." } else { "Not set" } },
        @{ Name = "ForceDefenderPassiveMode"; Status = if ($Result.PassiveModePolicyCompliant) { "PASS" } else { "FAIL" }; Detail = if ($Result.ForcePassiveMode) { "Set to 1 under Windows Advanced Threat Protection policy" } else { "Not set" } },
        @{ Name = "DisableRealtimeMonitoring"; Status = if ($Result.DisableRealtimeMonitoring) { "FAIL" } else { "PASS" }; Detail = if ($Result.DisableRealtimeMonitoring) { "Set to 1" } else { "Not set" } },
        @{ Name = "DisableBehaviorMonitoring"; Status = if ($Result.DisableBehaviorMonitoring) { "FAIL" } else { "PASS" }; Detail = if ($Result.DisableBehaviorMonitoring) { "Set to 1" } else { "Not set" } },
        @{ Name = "DisableOnAccessProtection"; Status = if ($Result.DisableOnAccessProtection) { "FAIL" } else { "PASS" }; Detail = if ($Result.DisableOnAccessProtection) { "Set to 1" } else { "Not set" } },
        @{ Name = "DisableIOAVProtection"; Status = if ($Result.DisableIOAVProtection) { "FAIL" } else { "PASS" }; Detail = if ($Result.DisableIOAVProtection) { "Set to 1" } else { "Not set" } },
        @{ Name = "DisableScanOnRealtimeEnable"; Status = if ($Result.DisableScanOnRealtimeEnable) { "FAIL" } else { "PASS" }; Detail = if ($Result.DisableScanOnRealtimeEnable) { "Set to 1" } else { "Not set" } },
        @{ Name = "SpynetReporting"; Status = if ($Result.MAPSDisabled) { "FAIL" } else { "PASS" }; Detail = if ($null -eq $Result.MAPSReportingValue) { "Not set" } else { [string]$Result.MAPSReportingValue } },
        @{ Name = "SubmitSamplesConsent"; Status = if ($Result.SampleSubmissionBlocked) { "FAIL" } else { "PASS" }; Detail = if ($null -eq $Result.SubmitSamplesValue) { "Not set" } else { [string]$Result.SubmitSamplesValue } }
    )

    $summaryHtml = ($summaryRows | ForEach-Object {
        $status = if ($_.ContainsKey("Status")) { $_.Status } else { if ($_.Passed) { "PASS" } else { "FAIL" } }
        "<tr><td>$($_.Name)</td><td><span class='badge $(Convert-StatusToBadgeClass $status)'>$status</span></td></tr>"
    }) -join "`n"

    $serviceHtml = (@($Result.WinDefendService, $Result.SenseService, $Result.FirewallService) | ForEach-Object {
        $status = $_.OutputStatus
        $state = if ($_.Exists) { "$($_.State) / $($_.StartMode)" } else { "Missing" }
        "<tr><td>$($_.Name)</td><td><span class='badge $(Convert-StatusToBadgeClass $status)'>$status</span></td><td>$state</td><td>$($_.Note)</td></tr>"
    }) -join "`n"

    $registryHtml = ($registryRows | ForEach-Object {
        $status = $_.Status
        "<tr><td>$($_.Name)</td><td><span class='badge $(Convert-StatusToBadgeClass $status)'>$status</span></td><td>$($_.Detail)</td></tr>"
    }) -join "`n"

    $mdavModeStatus = if ($Result.MdavModeMatchesExpectation) { "PASS" } else { "FAIL" }
    $mdavModeHtml = @(
        "<tr><td>Expected mode</td><td>$($Result.ExpectedMdavMode)</td></tr>",
        "<tr><td>Observed mode</td><td>$($Result.AMRunningMode)</td></tr>",
        "<tr><td>Mode check</td><td><span class='badge $(Convert-StatusToBadgeClass $mdavModeStatus)'>$mdavModeStatus</span></td></tr>",
        "<tr><td>Policy compliance</td><td>$($Result.PassiveModePolicyCompliant)</td></tr>",
        "<tr><td>Detail</td><td>$($Result.MdavModeEvaluationNote)</td></tr>"
    ) -join "`n"

    $passiveExpectedEnabled = if ($Result.ExpectedMdavMode -eq "Either") { $null } else { $true }
    $realTimeExpected = switch ($Result.ExpectedMdavMode) {
        "Active" { $true }
        "Passive" { $false }
        default { $null }
    }

    $runtimeRows = @(
        @{ Name = "Operational state"; Value = $Result.DefenderOperationalStateLabel; Status = $Result.DefenderOperationalStateStatus; Detail = $Result.DefenderOperationalStateNote },
        @{ Name = "AntivirusEnabled"; Value = $Result.AntivirusEnabled; Status = Get-RuntimeSignalStatus -Value $Result.AntivirusEnabled -Expected $passiveExpectedEnabled; Detail = "Runtime signal from Get-MpComputerStatus" },
        @{ Name = "AntispywareEnabled"; Value = $Result.AntispywareEnabled; Status = Get-RuntimeSignalStatus -Value $Result.AntispywareEnabled -Expected $passiveExpectedEnabled; Detail = "Runtime signal from Get-MpComputerStatus" },
        @{ Name = "RealTimeProtectionEnabled"; Value = $Result.RealTimeProtectionEnabled; Status = Get-RuntimeSignalStatus -Value $Result.RealTimeProtectionEnabled -Expected $realTimeExpected; Detail = "Expected to be False in passive mode and True in active mode" },
        @{ Name = "BehaviorMonitorEnabled"; Value = $Result.BehaviorMonitorEnabled; Status = Get-RuntimeSignalStatus -Value $Result.BehaviorMonitorEnabled -Expected $passiveExpectedEnabled; Detail = "Runtime signal from Get-MpComputerStatus" },
        @{ Name = "OnAccessProtectionEnabled"; Value = $Result.OnAccessProtectionEnabled; Status = Get-RuntimeSignalStatus -Value $Result.OnAccessProtectionEnabled -Expected $passiveExpectedEnabled; Detail = "Runtime signal from Get-MpComputerStatus" },
        @{ Name = "IoavProtectionEnabled"; Value = $Result.IoavProtectionEnabled; Status = Get-RuntimeSignalStatus -Value $Result.IoavProtectionEnabled -Expected $passiveExpectedEnabled; Detail = "Runtime signal from Get-MpComputerStatus" },
        @{ Name = "NISEnabled"; Value = $Result.NISEnabled; Status = Get-RuntimeSignalStatus -Value $Result.NISEnabled -Expected $passiveExpectedEnabled; Detail = "Runtime signal from Get-MpComputerStatus" },
        @{ Name = "IsTamperProtected"; Value = $Result.IsTamperProtected; Status = Get-RuntimeSignalStatus -Value $Result.IsTamperProtected -Expected $null; Detail = "Runtime signal from Get-MpComputerStatus" }
    )

    $runtimeHtml = ($runtimeRows | ForEach-Object {
        $displayValue = if ($null -eq $_.Value -or [string]::IsNullOrWhiteSpace([string]$_.Value)) { "N/A" } else { [string]$_.Value }
        "<tr><td>$($_.Name)</td><td><span class='badge $(Convert-StatusToBadgeClass $_.Status)'>$($_.Status)</span></td><td>$displayValue</td><td>$($_.Detail)</td></tr>"
    }) -join "`n"

    $coexistenceHtml = @(
        "<tr><td>Classification</td><td><span class='badge $(Convert-StatusToBadgeClass $Result.ThirdPartyAvCoexistenceStatus)'>$($Result.ThirdPartyAvCoexistenceStatus)</span></td></tr>",
        "<tr><td>Summary</td><td>$($Result.ThirdPartyAvCoexistenceLabel)</td></tr>",
        "<tr><td>Detail</td><td>$($Result.ThirdPartyAvCoexistenceNote)</td></tr>"
    ) -join "`n"

    $updateHtml = @(
        "<tr><td>AMProductVersion</td><td>$($Result.AMProductVersion)</td></tr>",
        "<tr><td>AMEngineVersion</td><td>$($Result.AMEngineVersion)</td></tr>",
        "<tr><td>AntivirusSignatureVersion</td><td>$($Result.AntivirusSignatureVersion)</td></tr>",
        "<tr><td>AntivirusSignatureLastUpdated</td><td>$($Result.AntivirusSignatureLastUpdated)</td></tr>",
        "<tr><td>Signature age</td><td>$($Result.SignatureAgeDays) day(s)</td></tr>",
        "<tr><td>KB4052623 detected</td><td>$($Result.PlatformUpdateKB4052623Installed)</td></tr>",
        "<tr><td>KB5005292 required</td><td>$($Result.SenseUpdateRequired)</td></tr>",
        "<tr><td>KB5005292 detected</td><td>$($Result.SenseUpdateKB5005292Installed)</td></tr>"
    ) -join "`n"

    $firewallHtml = ($Result.FirewallProfiles | ForEach-Object {
        $status = if ($_.Enabled) { "PASS" } else { "FAIL" }
        "<tr><td>$($_.Name)</td><td><span class='badge $(Convert-StatusToBadgeClass $status)'>$status</span></td><td>$($_.DefaultInboundAction)</td><td>$($_.DefaultOutboundAction)</td></tr>"
    }) -join "`n"

    $endpointHtml = ($Result.EndpointChecks | ForEach-Object {
        $resolvedAddress = if ($_.ResolvedAddress) { $_.ResolvedAddress } else { "N/A" }
        "<tr><td>$($_.Name)</td><td>$($_.HostName)</td><td>$($_.Port)</td><td><span class='badge $(Convert-StatusToBadgeClass $_.Status)'>$($_.Status)</span></td><td>$resolvedAddress</td><td>$($_.Note)</td></tr>"
    }) -join "`n"

    $thirdPartyHtml = if ($Result.DetectedThirdPartyServices.Count -gt 0) {
        ($Result.DetectedThirdPartyServices | ForEach-Object {
            "<tr><td>$($_.Name)</td><td>$($_.DisplayName)</td><td>$($_.State)</td></tr>"
        }) -join "`n"
    }
    else {
        "<tr><td colspan='3'>No Trellix, McAfee, HBSS, or Tanium services detected locally.</td></tr>"
    }

    $exclusionHtml = if ($Result.DefenderExclusionMatches.Count -gt 0) {
        ($Result.DefenderExclusionMatches | ForEach-Object {
            "<tr><td>$_</td></tr>"
        }) -join "`n"
    }
    else {
        "<tr><td>No matching local Defender exclusions detected.</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<title>Defender Server Prereq Report</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f3f4f6; }
h1, h2 { margin-bottom: 8px; }
.meta { margin-bottom: 24px; padding: 16px; background: #ffffff; border: 1px solid #d1d5db; border-radius: 8px; }
.section { margin-bottom: 20px; padding: 16px; background: #ffffff; border: 1px solid #d1d5db; border-radius: 8px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
th { background: #f9fafb; }
.badge { display: inline-block; min-width: 64px; text-align: center; padding: 4px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
.pass { background: #dcfce7; color: #166534; }
.fail { background: #fee2e2; color: #991b1b; }
.warn { background: #fef3c7; color: #92400e; }
</style>
</head>
<body>
<h1>Microsoft Defender for Server Prerequisites Report</h1>
<div class='meta'>
<div><strong>Server:</strong> $EvaluatedServerName</div>
<div><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
<div><strong>Requested environment type:</strong> $($Result.RequestedEnvironmentType)</div>
<div><strong>Detected Azure VM:</strong> $($Result.DetectedAzureVM)</div>
<div><strong>Effective environment type:</strong> $($Result.EffectiveEnvironmentType)</div>
<div><strong>Expected MDAV mode:</strong> $($Result.ExpectedMdavMode)</div>
<div><strong>Observed MDAV mode:</strong> $($Result.AMRunningMode)</div>
<div><strong>Operating system:</strong> $($Result.OSCaption) ($($Result.OSVersion))</div>
</div>

<div class='section'>
<h2>Summary</h2>
<table>
<thead><tr><th>Check</th><th>Status</th></tr></thead>
<tbody>
$summaryHtml
</tbody>
</table>
</div>

<div class='section'>
<h2>Trellix Passive-Mode Coexistence Posture</h2>
<table>
<thead><tr><th>Item</th><th>Value</th></tr></thead>
<tbody>
$coexistenceHtml
</tbody>
</table>
</div>

<div class='section'>
<h2>Service Health</h2>
<table>
<thead><tr><th>Service</th><th>Status</th><th>Runtime</th><th>Note</th></tr></thead>
<tbody>
$serviceHtml
</tbody>
</table>
</div>

<div class='section'>
<h2>Registry Validation</h2>
<table>
<thead><tr><th>Setting</th><th>Status</th><th>Detail</th></tr></thead>
<tbody>
$registryHtml
</tbody>
</table>
</div>

<div class='section'>
<h2>MDAV Mode</h2>
<table>
<thead><tr><th>Item</th><th>Value</th></tr></thead>
<tbody>
$mdavModeHtml
</tbody>
</table>
</div>

<div class='section'>
<h2>Defender Runtime State</h2>
<table>
<thead><tr><th>Signal</th><th>Status</th><th>Value</th><th>Detail</th></tr></thead>
<tbody>
$runtimeHtml
</tbody>
</table>
</div>

<div class='section'>
<h2>Update Validation</h2>
<table>
<thead><tr><th>Item</th><th>Value</th></tr></thead>
<tbody>
$updateHtml
</tbody>
</table>
</div>

<div class='section'>
<h2>Firewall Profiles</h2>
<table>
<thead><tr><th>Profile</th><th>Status</th><th>Inbound</th><th>Outbound</th></tr></thead>
<tbody>
$firewallHtml
</tbody>
</table>
</div>

<div class='section'>
<h2>Endpoint Connectivity</h2>
<table>
<thead><tr><th>Name</th><th>Host</th><th>Port</th><th>Status</th><th>Resolved Address</th><th>Note</th></tr></thead>
<tbody>
$endpointHtml
</tbody>
</table>
</div>

<div class='section'>
<h2>Trellix and Other Security Services</h2>
<table>
<thead><tr><th>Name</th><th>Display Name</th><th>State</th></tr></thead>
<tbody>
$thirdPartyHtml
</tbody>
</table>
</div>

<div class='section'>
<h2>Defender Exclusion Matches For Trellix / Other Security Tools</h2>
<table>
<thead><tr><th>Exclusion</th></tr></thead>
<tbody>
$exclusionHtml
</tbody>
</table>
</div>
</body>
</html>
"@

    Set-Content -Path $ReportPath -Value $html -Encoding UTF8
}

function Get-DefenderChecks {
    param(
        [ValidateSet("Auto", "OnPrem", "AzureVM")]
        [string]$EnvironmentType = "Auto",
        [ValidateSet("Passive", "Active", "Either")]
        [string]$ExpectedMdavMode = "Passive"
    )

    function Test-DefenderFeatureInstalled {
        $serverFeatureCommand = Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue
        if ($null -ne $serverFeatureCommand) {
            $feature = Get-WindowsFeature -Name Windows-Defender -ErrorAction SilentlyContinue
            return [ordered]@{
                Installed = ($null -ne $feature -and [bool]$feature.Installed)
                Source = "Get-WindowsFeature"
            }
        }

        $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
        return [ordered]@{
            Installed = $null -ne $defenderService
            Source = "WinDefend service fallback"
        }
    }

    function Get-ServiceCheck {
        param(
            [string]$Name,
            [string]$DisplayName,
            [bool]$RequireRunning = $true,
            [string[]]$AllowedStartModes = @()
        )

        $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            return [ordered]@{
                Name = $Name
                DisplayName = $DisplayName
                Exists = $false
                State = $null
                StartMode = $null
                Passed = $false
                OutputStatus = "FAIL"
                Note = "Service not found"
            }
        }

        $status = "PASS"
        $note = "Service is in the expected state"

        if ($service.StartMode -eq "Disabled") {
            $status = "FAIL"
            $note = "Service is disabled, which is not supported for MDE onboarding or passive-mode coexistence."
        }
        elseif ($RequireRunning -and $service.State -ne "Running") {
            $status = "FAIL"
            $note = "Service must be running for this prerequisite check."
        }
        elseif ($AllowedStartModes.Count -gt 0 -and $AllowedStartModes -notcontains $service.StartMode) {
            $status = "FAIL"
            $note = "Service start mode is not in the expected set: $($AllowedStartModes -join ', ')."
        }
        elseif (-not $RequireRunning -and $service.State -ne "Running") {
            $status = "WARN"
            $note = "Service exists and is not disabled. For passive-mode coexistence, rely on AMRunningMode and policy rather than runtime alone."
        }
        elseif (-not $RequireRunning -and $service.StartMode -ne "Auto") {
            $status = "WARN"
            $note = "Service exists with a non-disabled start mode. For passive-mode coexistence, rely on AMRunningMode and policy rather than Auto start alone."
        }
        elseif ($RequireRunning -and $AllowedStartModes.Count -gt 0) {
            $note = "Running with expected start mode"
        }

        return [ordered]@{
            Name = $Name
            DisplayName = $DisplayName
            Exists = $true
            State = $service.State
            StartMode = $service.StartMode
            Passed = $status -ne "FAIL"
            OutputStatus = $status
            Note = $note
        }
    }

    function Test-MdavModeMatch {
        param(
            [string]$ObservedMode,
            [string]$ExpectedMode
        )

        if ([string]::IsNullOrWhiteSpace($ObservedMode)) {
            return $false
        }

        switch ($ExpectedMode) {
            "Passive" { return $ObservedMode -match "^Passive" -or $ObservedMode -eq "EDR Block Mode" }
            "Active" { return $ObservedMode -eq "Normal" }
            default { return $true }
        }
    }

    function Get-DefenderOperationalState {
        param(
            [hashtable]$EvaluationResult,
            [string]$ExpectedMode
        )

        $state = [ordered]@{
            Status = "WARN"
            Label = "Unknown"
            Note = "Unable to determine the effective Defender operational state."
        }

        if (-not $EvaluationResult.DefenderInstalled) {
            $state.Status = "FAIL"
            $state.Label = "Feature not installed"
            $state.Note = "The Windows Defender feature is not installed, so Microsoft Defender Antivirus cannot operate."
            return $state
        }

        if (-not $EvaluationResult.WinDefendService.Exists -or $EvaluationResult.WinDefendService.StartMode -eq "Disabled") {
            $state.Status = "FAIL"
            $state.Label = "WinDefend disabled or missing"
            $state.Note = "The WinDefend service is missing or disabled, which prevents supported Defender operation."
            return $state
        }

        if ($EvaluationResult.DisableAntiSpyware -or $EvaluationResult.DisableAntiVirus) {
            $state.Status = "WARN"
            $state.Label = "Legacy disable policy present"
            $state.Note = "One or more legacy Defender disable policy keys are set. Confirm the effective runtime state with AMRunningMode and the runtime flags below."
        }

        if (-not $EvaluationResult.MpStatusAvailable) {
            if ($state.Status -eq "WARN") {
                return $state
            }

            $state.Status = "WARN"
            $state.Label = "Runtime status unavailable"
            $state.Note = "Get-MpComputerStatus did not return data, so the effective Defender runtime state could not be confirmed."
            return $state
        }

        if ($EvaluationResult.AMRunningMode -eq "Not running") {
            $state.Status = "FAIL"
            $state.Label = "Not running"
            $state.Note = "Get-MpComputerStatus reports AMRunningMode = Not running. Defender is installed but not operating."
            return $state
        }

        switch ($ExpectedMode) {
            "Passive" {
                if ($EvaluationResult.MdavModeMatchesExpectation) {
                    $state.Status = "PASS"
                    $state.Label = $EvaluationResult.AMRunningMode
                    $state.Note = "The effective runtime state matches the expected passive-mode posture. Real-time protection can be off in passive mode."
                }
                elseif ($EvaluationResult.AMRunningMode -eq "Normal") {
                    $state.Status = "FAIL"
                    $state.Label = "Active instead of passive"
                    $state.Note = "The effective runtime state is active (Normal) when passive mode was requested."
                }
                else {
                    $state.Status = "WARN"
                    $state.Label = if ($EvaluationResult.AMRunningMode) { $EvaluationResult.AMRunningMode } else { "Unknown" }
                    $state.Note = "The runtime state does not clearly align with the requested passive posture. Review policy and onboarding state."
                }
            }
            "Active" {
                if ($EvaluationResult.MdavModeMatchesExpectation -and $EvaluationResult.AntivirusEnabled -and $EvaluationResult.RealTimeProtectionEnabled) {
                    $state.Status = "PASS"
                    $state.Label = "Active"
                    $state.Note = "The effective runtime state is active and real-time protection is enabled."
                }
                elseif ($EvaluationResult.MdavModeMatchesExpectation) {
                    $state.Status = "WARN"
                    $state.Label = "Mode active with partial runtime protection"
                    $state.Note = "AMRunningMode is active, but one or more runtime protection signals are not enabled."
                }
                else {
                    $state.Status = "FAIL"
                    $state.Label = if ($EvaluationResult.AMRunningMode) { $EvaluationResult.AMRunningMode } else { "Unknown" }
                    $state.Note = "The effective runtime state does not match the requested active Defender posture."
                }
            }
            default {
                $state.Status = "PASS"
                $state.Label = if ($EvaluationResult.AMRunningMode) { $EvaluationResult.AMRunningMode } else { "Unknown" }
                $state.Note = "An effective Defender runtime state was detected."
            }
        }

        return $state
    }

    function Test-EndpointConnectivity {
        param(
            [string]$Name,
            [string]$HostName,
            [int]$Port,
            [bool]$Required = $true,
            [bool]$Manual = $false,
            [string]$Note = ""
        )

        $entry = [ordered]@{
            Name = $Name
            HostName = $HostName
            Port = $Port
            Required = $Required
            Status = "FAIL"
            DnsResolved = $false
            ResolvedAddress = $null
            TcpTestSucceeded = $false
            Note = $Note
        }

        if ($Manual) {
            $entry.Status = "MANUAL"
            if (-not $entry.Note) {
                $entry.Note = "Wildcard or tenant-specific endpoint. Validate with the MDE Connectivity Analyzer or an approved concrete host."
            }
            return $entry
        }

        try {
            $dnsRecord = Resolve-DnsName -Name $HostName -ErrorAction Stop |
                Where-Object { $_.Type -in @("A", "AAAA") } |
                Select-Object -First 1
            if ($null -ne $dnsRecord) {
                $entry.DnsResolved = $true
                $entry.ResolvedAddress = $dnsRecord.IPAddress
            }
        }
        catch {
            $entry.Note = "DNS lookup failed: $($_.Exception.Message)"
            return $entry
        }

        try {
            $tcpTest = Test-NetConnection -ComputerName $HostName -Port $Port -WarningAction SilentlyContinue -InformationLevel Detailed
            $entry.TcpTestSucceeded = [bool]$tcpTest.TcpTestSucceeded
            if ($entry.TcpTestSucceeded) {
                $entry.Status = "PASS"
                if (-not $entry.Note) {
                    $entry.Note = "DNS and TCP connectivity succeeded"
                }
            }
            else {
                $entry.Note = "TCP connectivity failed"
            }
        }
        catch {
            $entry.Note = "Connectivity test failed: $($_.Exception.Message)"
        }

        return $entry
    }

    function Get-EndpointDefinitions {
        param([string]$EffectiveEnvironmentType)

        $commonEndpoints = @(
            @{ Name = "MDE Streamlined"; HostName = "*.endpoint.security.microsoft.us"; Port = 443; Required = $true; Manual = $true; Note = "Wildcard MDE service endpoint" },
            @{ Name = "SmartScreen (DoD)"; HostName = "unitedstates2.ss.wd.microsoft.us"; Port = 443; Required = $true; Manual = $false; Note = "" },
            @{ Name = "MDE Config (DoD)"; HostName = "config.ecs.dod.teams.microsoft.us"; Port = 443; Required = $true; Manual = $false; Note = "" },
            @{ Name = "MDE Portal"; HostName = "*.securitycenter.microsoft.us"; Port = 443; Required = $true; Manual = $true; Note = "Wildcard portal endpoint" },
            @{ Name = "Entra Sign-in (Gov)"; HostName = "login.microsoftonline.us"; Port = 443; Required = $true; Manual = $false; Note = "" },
            @{ Name = "CRL - crl.microsoft.com"; HostName = "crl.microsoft.com"; Port = 80; Required = $true; Manual = $false; Note = "" },
            @{ Name = "CRL - ctldl.windowsupdate.com"; HostName = "ctldl.windowsupdate.com"; Port = 80; Required = $true; Manual = $false; Note = "" },
            @{ Name = "CRL - www.microsoft.com/pkiops/*"; HostName = "www.microsoft.com"; Port = 80; Required = $true; Manual = $false; Note = "Host-level check for PKI ops endpoint" },
            @{ Name = "CRL - www.microsoft.com/pki/certs"; HostName = "www.microsoft.com"; Port = 80; Required = $true; Manual = $false; Note = "Host-level check for PKI cert endpoint" },
            @{ Name = "Live Response (WNS)"; HostName = "*.wns.windows.com"; Port = 443; Required = $false; Manual = $true; Note = "Optional Live Response wildcard endpoint" },
            @{ Name = "Live Response Auth"; HostName = "login.live.com"; Port = 443; Required = $false; Manual = $false; Note = "Optional Live Response endpoint" },
            @{ Name = "Entra Sign-in (Common)"; HostName = "login.microsoftonline.com"; Port = 443; Required = $false; Manual = $false; Note = "Optional Live Response endpoint" }
        )

        $onPremEndpoints = @(
            @{ Name = "Arc ARM (Gov)"; HostName = "management.usgovcloudapi.net"; Port = 443; Required = $true; Manual = $false; Note = "" },
            @{ Name = "Arc Identity (Gov)"; HostName = "login.microsoftonline.us"; Port = 443; Required = $true; Manual = $false; Note = "" },
            @{ Name = "Arc Identity Dependency (Gov)"; HostName = "pasff.usgovcloudapi.net"; Port = 443; Required = $true; Manual = $false; Note = "" },
            @{ Name = "Arc Metadata/HIS (Gov)"; HostName = "gbl.his.arc.azure.us"; Port = 443; Required = $true; Manual = $false; Note = "" },
            @{ Name = "Arc Guest Config (Gov)"; HostName = "*.guestconfiguration.azure.us"; Port = 443; Required = $true; Manual = $true; Note = "Wildcard Arc Guest Configuration endpoint" },
            @{ Name = "Arc Extension Packages"; HostName = "*.blob.core.usgovcloudapi.net"; Port = 443; Required = $true; Manual = $true; Note = "Wildcard blob storage endpoint used by Arc extensions" }
        )

        $azureVmEndpoints = @(
            @{ Name = "MDE Onboarding Package (DoD)"; HostName = "onboardingpckgsusgvprd.blob.core.usgovcloudapi.net"; Port = 443; Required = $true; Manual = $false; Note = "" },
            @{ Name = "Defender Portal Dependencies"; HostName = "*.microsoftonline-p.com"; Port = 443; Required = $true; Manual = $true; Note = "Wildcard Defender portal dependency" },
            @{ Name = "Defender Portal Dependencies - secure.aadcdn.microsoftonline-p.com"; HostName = "secure.aadcdn.microsoftonline-p.com"; Port = 443; Required = $true; Manual = $false; Note = "" },
            @{ Name = "Defender Portal Dependencies - static2.sharepointonline.com"; HostName = "static2.sharepointonline.com"; Port = 443; Required = $true; Manual = $false; Note = "" },
            @{ Name = "Defender Portal Storage Dependency"; HostName = "*.blob.core.usgovcloudapi.net"; Port = 443; Required = $true; Manual = $true; Note = "Wildcard storage dependency" },
            @{ Name = "Defender Telemetry"; HostName = "events.data.microsoft.com"; Port = 443; Required = $false; Manual = $false; Note = "Required when standard connectivity mode is used" },
            @{ Name = "MAPS Cloud Protection (DoD)"; HostName = "unitedstates2.cp.wd.microsoft.us"; Port = 443; Required = $false; Manual = $false; Note = "Required when standard connectivity mode is used" }
        )

        if ($EffectiveEnvironmentType -eq "AzureVM") {
            return $commonEndpoints + $azureVmEndpoints
        }

        return $commonEndpoints + $onPremEndpoints
    }

    $result = [ordered]@{}

    try {
        $metadataUrl = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        $headers = @{ Metadata = "true" }
        $null = Invoke-RestMethod -Method GET -Uri $metadataUrl -Headers $headers -TimeoutSec 2 -ErrorAction Stop
        $result.DetectedAzureVM = $true
    }
    catch {
        $result.DetectedAzureVM = $false
    }

    $result.RequestedEnvironmentType = $EnvironmentType
    $result.ExpectedMdavMode = $ExpectedMdavMode
    $result.EffectiveEnvironmentType = if ($EnvironmentType -eq "Auto") {
        if ($result.DetectedAzureVM) { "AzureVM" } else { "OnPrem" }
    }
    else {
        $EnvironmentType
    }

    $operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $result.OSCaption = $operatingSystem.Caption
    $result.OSVersion = $operatingSystem.Version
    $result.DefenderInstalled = $false
    $result.DefenderFeatureName = "Windows-Defender"
    $featureCheck = Test-DefenderFeatureInstalled
    $result.DefenderInstalled = [bool]$featureCheck.Installed
    $result.DefenderFeatureCheckSource = $featureCheck.Source

    $basePath = "HKLM:\Software\Policies\Microsoft\Windows Defender"
    $rtpPath = "$basePath\Real-Time Protection"
    $mapsPath = "$basePath\Spynet"
    $atpPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows Advanced Threat Protection"

    $result.DisableAntiSpyware = $false
    $result.DisableAntiVirus = $false
    $result.ForcePassiveMode = $false
    $result.PassiveModePolicyCompliant = $false
    $result.DisableRealtimeMonitoring = $false
    $result.DisableBehaviorMonitoring = $false
    $result.DisableOnAccessProtection = $false
    $result.DisableIOAVProtection = $false
    $result.DisableScanOnRealtimeEnable = $false
    $result.MAPSDisabled = $false
    $result.MAPSReportingValue = $null
    $result.SampleSubmissionBlocked = $false
    $result.SubmitSamplesValue = $null

    if (Test-Path $basePath) {
        $baseProperties = Get-ItemProperty -Path $basePath -ErrorAction SilentlyContinue
        $result.DisableAntiSpyware = ($null -ne $baseProperties.DisableAntiSpyware -and $baseProperties.DisableAntiSpyware -eq 1)
        $result.DisableAntiVirus = ($null -ne $baseProperties.DisableAntiVirus -and $baseProperties.DisableAntiVirus -eq 1)
    }

    if (Test-Path $atpPolicyPath) {
        $atpProperties = Get-ItemProperty -Path $atpPolicyPath -ErrorAction SilentlyContinue
        $result.ForcePassiveMode = ($null -ne $atpProperties.ForceDefenderPassiveMode -and $atpProperties.ForceDefenderPassiveMode -eq 1)
    }

    if (Test-Path $rtpPath) {
        $rtpProperties = Get-ItemProperty -Path $rtpPath -ErrorAction SilentlyContinue
        $result.DisableRealtimeMonitoring = ($null -ne $rtpProperties.DisableRealtimeMonitoring -and $rtpProperties.DisableRealtimeMonitoring -eq 1)
        $result.DisableBehaviorMonitoring = ($null -ne $rtpProperties.DisableBehaviorMonitoring -and $rtpProperties.DisableBehaviorMonitoring -eq 1)
        $result.DisableOnAccessProtection = ($null -ne $rtpProperties.DisableOnAccessProtection -and $rtpProperties.DisableOnAccessProtection -eq 1)
        $result.DisableIOAVProtection = ($null -ne $rtpProperties.DisableIOAVProtection -and $rtpProperties.DisableIOAVProtection -eq 1)
        $result.DisableScanOnRealtimeEnable = ($null -ne $rtpProperties.DisableScanOnRealtimeEnable -and $rtpProperties.DisableScanOnRealtimeEnable -eq 1)
    }

    if (Test-Path $mapsPath) {
        $mapsProperties = Get-ItemProperty -Path $mapsPath -ErrorAction SilentlyContinue
        $result.MAPSReportingValue = $mapsProperties.SpynetReporting
        $result.MAPSDisabled = ($null -ne $mapsProperties.SpynetReporting -and $mapsProperties.SpynetReporting -eq 0)
        $result.SubmitSamplesValue = $mapsProperties.SubmitSamplesConsent
        $result.SampleSubmissionBlocked = ($null -ne $mapsProperties.SubmitSamplesConsent -and $mapsProperties.SubmitSamplesConsent -eq 2)
    }

    $svcRegChecks = @(
        @{ Name = "WdBoot"; ExpectedStart = 0; Desc = "Defender Boot Driver" },
        @{ Name = "WdFilter"; ExpectedStart = 0; Desc = "Defender Mini-Filter Driver" },
        @{ Name = "WdNisDrv"; ExpectedStart = 3; Desc = "Defender Network Inspection Driver" },
        @{ Name = "WdNisSvc"; ExpectedStart = 3; Desc = "Defender Network Inspection Service" },
        @{ Name = "WinDefend"; ExpectedStart = 2; Desc = "Defender Antivirus Service" },
        @{ Name = "MpsSvc"; ExpectedStart = 2; Desc = "Windows Firewall" }
    )

    $result.ServiceRegChecks = @()
    foreach ($svc in $svcRegChecks) {
        $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
        $startVal = $null
        $exists = Test-Path $svcPath
        if ($exists) {
            $startVal = (Get-ItemProperty -Path $svcPath -Name "Start" -ErrorAction SilentlyContinue).Start
        }

        $result.ServiceRegChecks += [ordered]@{
            Name = $svc.Name
            Desc = $svc.Desc
            ExpectedStart = $svc.ExpectedStart
            ActualStart = $startVal
            Exists = $exists
        }
    }

    $result.WinDefendService = Get-ServiceCheck -Name "WinDefend" -DisplayName "Microsoft Defender Antivirus Service" -RequireRunning $false -AllowedStartModes @("Auto", "Manual")
    $result.SenseService = Get-ServiceCheck -Name "Sense" -DisplayName "Microsoft Defender for Endpoint Sense" -RequireRunning $false -AllowedStartModes @("Auto", "Manual")
    $result.FirewallService = Get-ServiceCheck -Name "MpsSvc" -DisplayName "Windows Defender Firewall" -RequireRunning $true -AllowedStartModes @("Auto")

    $result.MpStatusAvailable = $false
    $result.AMProductVersion = $null
    $result.AMEngineVersion = $null
    $result.AntivirusSignatureVersion = $null
    $result.AntivirusSignatureLastUpdated = $null
    $result.SignatureAgeDays = $null
    $result.SignaturesFresh = $false
    $result.AMRunningMode = $null
    $result.MdavModeMatchesExpectation = $false
    $result.MdavModeEvaluationNote = "AMRunningMode not available"
    $result.AntivirusEnabled = $null
    $result.AntispywareEnabled = $null
    $result.RealTimeProtectionEnabled = $null
    $result.BehaviorMonitorEnabled = $null
    $result.OnAccessProtectionEnabled = $null
    $result.IoavProtectionEnabled = $null
    $result.NISEnabled = $null
    $result.IsTamperProtected = $null

    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $result.MpStatusAvailable = $true
        $result.AMProductVersion = $mpStatus.AMProductVersion
        $result.AMEngineVersion = $mpStatus.AMEngineVersion
        $result.AMRunningMode = $mpStatus.AMRunningMode
        $result.AntivirusEnabled = $mpStatus.AntivirusEnabled
        $result.AntispywareEnabled = $mpStatus.AntispywareEnabled
        $result.RealTimeProtectionEnabled = $mpStatus.RealTimeProtectionEnabled
        $result.BehaviorMonitorEnabled = $mpStatus.BehaviorMonitorEnabled
        $result.OnAccessProtectionEnabled = $mpStatus.OnAccessProtectionEnabled
        $result.IoavProtectionEnabled = $mpStatus.IoavProtectionEnabled
        $result.NISEnabled = $mpStatus.NISEnabled
        $result.IsTamperProtected = $mpStatus.IsTamperProtected
        $result.AntivirusSignatureVersion = $mpStatus.AntivirusSignatureVersion
        $result.AntivirusSignatureLastUpdated = $mpStatus.AntivirusSignatureLastUpdated
        if ($null -ne $mpStatus.AntivirusSignatureLastUpdated) {
            $signatureAge = (Get-Date) - [datetime]$mpStatus.AntivirusSignatureLastUpdated
            $result.SignatureAgeDays = [math]::Floor($signatureAge.TotalDays)
            $result.SignaturesFresh = $signatureAge.TotalDays -le 7
        }
    }
    catch {
        $result.MpStatusError = $_.Exception.Message
    }

    $result.PassiveModePolicyCompliant = switch ($ExpectedMdavMode) {
        "Passive" { $result.ForcePassiveMode }
        "Active" { -not $result.ForcePassiveMode }
        default { $true }
    }

    if ($result.MpStatusAvailable) {
        $result.MdavModeMatchesExpectation = Test-MdavModeMatch -ObservedMode $result.AMRunningMode -ExpectedMode $ExpectedMdavMode
        $result.MdavModeEvaluationNote = switch ($ExpectedMdavMode) {
            "Passive" {
                if ($result.MdavModeMatchesExpectation) {
                    "Passive mode is active or EDR block mode is active."
                }
                else {
                    "Expected passive mode. Validate AMRunningMode and ForceDefenderPassiveMode policy."
                }
            }
            "Active" {
                if ($result.MdavModeMatchesExpectation) {
                    "Active mode is configured as expected."
                }
                else {
                    "Expected active mode. Validate AMRunningMode and ForceDefenderPassiveMode policy."
                }
            }
            default { "Any MDAV running mode is accepted." }
        }
    }

    $operationalState = Get-DefenderOperationalState -EvaluationResult $result -ExpectedMode $ExpectedMdavMode
    $result.DefenderOperationalStateStatus = $operationalState.Status
    $result.DefenderOperationalStateLabel = $operationalState.Label
    $result.DefenderOperationalStateNote = $operationalState.Note

    $result.PlatformUpdateKB4052623Installed = $null -ne (Get-HotFix -Id "KB4052623" -ErrorAction SilentlyContinue)
    $requiresSenseKb = $false
    if ($result.OSCaption -match "2012 R2" -or $result.OSCaption -match "2016") {
        $requiresSenseKb = $true
    }
    $result.SenseUpdateRequired = $requiresSenseKb
    $result.SenseUpdateKB5005292Installed = if ($requiresSenseKb) {
        $null -ne (Get-HotFix -Id "KB5005292" -ErrorAction SilentlyContinue)
    }
    else {
        $null
    }

    $result.FirewallProfiles = @()
    $result.FirewallProfilesHealthy = $false
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop | Sort-Object Name
            foreach ($firewallProfile in $profiles) {
            $result.FirewallProfiles += [ordered]@{
                    Name = $firewallProfile.Name
                    Enabled = [bool]$firewallProfile.Enabled
                    DefaultInboundAction = $firewallProfile.DefaultInboundAction
                    DefaultOutboundAction = $firewallProfile.DefaultOutboundAction
            }
        }

        $disabledProfiles = @($result.FirewallProfiles | Where-Object { -not $_.Enabled })
        $result.FirewallProfilesHealthy = $disabledProfiles.Count -eq 0
    }
    catch {
        $result.FirewallProfilesError = $_.Exception.Message
    }

    $thirdPartyPattern = "Trellix|McAfee|HBSS|Tanium"
    $result.DetectedThirdPartyServices = @()
    try {
        $result.DetectedThirdPartyServices = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $thirdPartyPattern -or $_.DisplayName -match $thirdPartyPattern } |
            Select-Object Name, DisplayName, State)
    }
    catch {
        $result.DetectedThirdPartyServices = @()
    }

    $result.DefenderExclusionMatches = @()
    $result.ExclusionsConfigured = $true
    try {
        $mpPreference = Get-MpPreference -ErrorAction Stop
        $allExclusions = @(
            @($mpPreference.ExclusionPath)
            @($mpPreference.ExclusionProcess)
            @($mpPreference.ExclusionExtension)
            @($mpPreference.ExclusionIpAddress)
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        $result.DefenderExclusionMatches = @($allExclusions | Where-Object { $_ -match $thirdPartyPattern })
        if ($result.DetectedThirdPartyServices.Count -gt 0) {
            $result.ExclusionsConfigured = $result.DefenderExclusionMatches.Count -gt 0
        }
    }
    catch {
        $result.ExclusionsConfigured = $false
        $result.ExclusionsError = $_.Exception.Message
    }

    $result.EndpointChecks = @()
    $endpointDefinitions = Get-EndpointDefinitions -EffectiveEnvironmentType $result.EffectiveEnvironmentType
    foreach ($endpoint in $endpointDefinitions) {
        $result.EndpointChecks += Test-EndpointConnectivity -Name $endpoint.Name -HostName $endpoint.HostName -Port $endpoint.Port -Required $endpoint.Required -Manual $endpoint.Manual -Note $endpoint.Note
    }

    $requiredEndpointFailures = @($result.EndpointChecks | Where-Object { $_.Required -and $_.Status -eq "FAIL" })
    $requiredManualEndpoints = @($result.EndpointChecks | Where-Object { $_.Required -and $_.Status -eq "MANUAL" })

    $result.LegacyDisablePolicyPresent = $result.DisableAntiSpyware -or $result.DisableAntiVirus

    $registryFailures = @(
        $result.DisableRealtimeMonitoring,
        $result.DisableBehaviorMonitoring,
        $result.DisableOnAccessProtection,
        $result.DisableIOAVProtection,
        $result.DisableScanOnRealtimeEnable,
        $result.MAPSDisabled,
        $result.SampleSubmissionBlocked
    ) -contains $true

    $disabledServiceRegistryItems = @($result.ServiceRegChecks | Where-Object { -not $_.Exists -or $null -eq $_.ActualStart -or $_.ActualStart -eq 4 })

    $result.RegistryValidationsSuccessful = -not $registryFailures -and $disabledServiceRegistryItems.Count -eq 0
    $result.UpdatesInstalledAndVerified = $result.MpStatusAvailable -and
        -not [string]::IsNullOrWhiteSpace($result.AMProductVersion) -and
        -not [string]::IsNullOrWhiteSpace($result.AMEngineVersion) -and
        -not [string]::IsNullOrWhiteSpace($result.AntivirusSignatureVersion) -and
        $result.SignaturesFresh
    $result.FirewallRulesConfigured = $result.FirewallService.Passed -and $result.FirewallProfilesHealthy
    $result.EndpointConnectivitySuccessful = $requiredEndpointFailures.Count -eq 0
    $result.EndpointManualReviewRequired = $requiredManualEndpoints.Count -gt 0
    $result.ExclusionsConfiguredSuccessful = $result.ExclusionsConfigured

    $result.ThirdPartyAvCoexistenceStatus = "FAIL"
    $result.ThirdPartyAvCoexistenceLabel = "Disabled or not passive-mode compliant"
    $result.ThirdPartyAvCoexistenceNote = "This posture check focuses on whether Defender is present and not disabled for coexistence with Trellix. The same detection also covers McAfee, HBSS, and Tanium when present."

    $coreMdavDisabled = -not $result.DefenderInstalled
    $serviceDisabledForCoexistence = -not $result.WinDefendService.Exists -or
        $result.WinDefendService.StartMode -eq "Disabled" -or
        -not $result.SenseService.Exists -or
        $result.SenseService.StartMode -eq "Disabled"

    if ($coreMdavDisabled -or $serviceDisabledForCoexistence) {
        $result.ThirdPartyAvCoexistenceStatus = "FAIL"
        $result.ThirdPartyAvCoexistenceLabel = "Disabled or not passive-mode compliant"
        $result.ThirdPartyAvCoexistenceNote = "MDAV must stay installed and not disabled. Do not disable WinDefend, Sense, or Defender policy components when preparing a Trellix-managed server for MDE onboarding."
    }
    elseif ($result.DetectedThirdPartyServices.Count -gt 0 -and -not $result.ExclusionsConfiguredSuccessful) {
        $result.ThirdPartyAvCoexistenceStatus = "FAIL"
        $result.ThirdPartyAvCoexistenceLabel = "Trellix or another security product detected, but coexistence settings are incomplete"
        $result.ThirdPartyAvCoexistenceNote = "A Trellix, McAfee, HBSS, or Tanium service was detected, but matching Defender exclusions were not found. For Trellix onboarding reviews, treat this as a coexistence gap."
    }
    elseif ($ExpectedMdavMode -eq "Passive") {
        if ($result.MdavModeMatchesExpectation -and $result.PassiveModePolicyCompliant) {
            $result.ThirdPartyAvCoexistenceStatus = "PASS"
            $result.ThirdPartyAvCoexistenceLabel = "Ready for MDE onboarding with Trellix in passive mode"
            $result.ThirdPartyAvCoexistenceNote = "Passive mode or EDR block mode is active, Defender is not disabled, and the policy aligns with passive-mode coexistence guidance."
        }
        elseif ($result.MdavModeMatchesExpectation) {
            $result.ThirdPartyAvCoexistenceStatus = "WARN"
            $result.ThirdPartyAvCoexistenceLabel = "Mode looks compatible, but passive-mode policy still needs review"
            $result.ThirdPartyAvCoexistenceNote = "AMRunningMode indicates passive-mode compatibility, but ForceDefenderPassiveMode does not align with the requested passive-mode posture."
        }
        elseif ($result.AMRunningMode -eq "Normal") {
            $result.ThirdPartyAvCoexistenceStatus = "FAIL"
            $result.ThirdPartyAvCoexistenceLabel = "Active instead of passive"
            $result.ThirdPartyAvCoexistenceNote = "The server is reporting active Microsoft Defender Antivirus mode. For Trellix coexistence, validate passive mode or EDR block mode instead."
        }
        else {
            $result.ThirdPartyAvCoexistenceStatus = "FAIL"
            $result.ThirdPartyAvCoexistenceLabel = "Passive-mode readiness could not be confirmed"
            $result.ThirdPartyAvCoexistenceNote = "AMRunningMode did not show Passive Mode or EDR Block Mode. Review Defender installation state, policy, and onboarding status."
        }
    }
    else {
        if ($result.MdavModeMatchesExpectation -and $result.PassiveModePolicyCompliant) {
            $result.ThirdPartyAvCoexistenceStatus = "PASS"
            $result.ThirdPartyAvCoexistenceLabel = "MDAV posture matches the requested operating mode"
            $result.ThirdPartyAvCoexistenceNote = "Defender is present, not disabled, and its operating mode aligns with the requested posture."
        }
        elseif ($result.MdavModeMatchesExpectation) {
            $result.ThirdPartyAvCoexistenceStatus = "WARN"
            $result.ThirdPartyAvCoexistenceLabel = "Operating mode matches, but policy needs review"
            $result.ThirdPartyAvCoexistenceNote = "AMRunningMode aligns with the requested posture, but ForceDefenderPassiveMode does not fully align."
        }
    }

    $result.AllCriticalChecksPassed = ($result.DefenderOperationalStateStatus -eq "PASS") -and
        $result.MdavModeMatchesExpectation -and
        $result.RegistryValidationsSuccessful -and
        $result.UpdatesInstalledAndVerified -and
        $result.FirewallRulesConfigured -and
        $result.EndpointConnectivitySuccessful -and
        $result.ExclusionsConfiguredSuccessful

    return $result
}

if ([string]::IsNullOrWhiteSpace($ServerName)) {
    $ServerName = Read-Host "Enter server name for PowerShell remoting, or press Enter to run locally"
    if ([string]::IsNullOrWhiteSpace($ServerName)) {
        $ServerName = "localhost"
    }
}

if ($PSBoundParameters.ContainsKey("EnvironmentType") -eq $false) {
    Write-Host "Select environment type for endpoint validation:" -ForegroundColor Cyan
    Write-Host "  [1] Auto    - Detect from IMDS when possible"
    Write-Host "  [2] OnPrem  - Use on-prem + Azure Arc endpoint set"
    Write-Host "  [3] AzureVM - Use Azure VM Defender endpoint set"
    $environmentChoice = Read-Host "Enter 1, 2, or 3"
    switch ($environmentChoice) {
        "1" { $EnvironmentType = "Auto" }
        "2" { $EnvironmentType = "OnPrem" }
        "3" { $EnvironmentType = "AzureVM" }
        default {
            Write-Host "[FAIL] Invalid environment selection. Enter 1, 2, or 3." -ForegroundColor Red
            return
        }
    }
}

$isLocal = $ServerName -eq "localhost" -or $ServerName -eq "." -or $ServerName -eq $env:COMPUTERNAME

if ($isLocal) {
    Write-Host "Running local check..." -ForegroundColor Cyan
    $result = Get-DefenderChecks -EnvironmentType $EnvironmentType -ExpectedMdavMode $ExpectedMdavMode
}
else {
    Write-Host "Running remote check on $ServerName..." -ForegroundColor Cyan
    $functionDefinition = ${function:Get-DefenderChecks}.ToString()
    try {
        $result = Invoke-Command -ComputerName $ServerName -ScriptBlock {
            param($definition, $selectedEnvironmentType, $selectedExpectedMdavMode)
            . ([ScriptBlock]::Create($definition))
            Get-DefenderChecks -EnvironmentType $selectedEnvironmentType -ExpectedMdavMode $selectedExpectedMdavMode
        } -ArgumentList $functionDefinition, $EnvironmentType, $ExpectedMdavMode -ErrorAction Stop
    }
    catch {
        Write-Host "[FAIL] Remote execution to '$ServerName' failed." -ForegroundColor Red
        Write-Host "       Any name other than localhost uses PowerShell remoting (WinRM), not a simple DNS lookup." -ForegroundColor Yellow
        Write-Host "       Verify the server name, network reachability, remoting is enabled, and that your account has access." -ForegroundColor Yellow
        Write-Host "       Error: $($_.Exception.Message)" -ForegroundColor Yellow
        return
    }
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Microsoft Defender for Server Prerequisites Check" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Requested environment type : $($result.RequestedEnvironmentType)" -ForegroundColor Gray
Write-Host "  Detected Azure VM          : $($result.DetectedAzureVM)" -ForegroundColor Gray
Write-Host "  Effective environment type : $($result.EffectiveEnvironmentType)" -ForegroundColor Gray
Write-Host "  Expected MDAV mode         : $($result.ExpectedMdavMode)" -ForegroundColor Gray
Write-Host "  Observed MDAV mode         : $($result.AMRunningMode)" -ForegroundColor Gray
Write-Host "  Operating system           : $($result.OSCaption) ($($result.OSVersion))" -ForegroundColor Gray

Write-Host ""
Write-Host "--- Passive-Mode / Trellix Coexistence Posture ---" -ForegroundColor Yellow
$coexistenceColor = switch ($result.ThirdPartyAvCoexistenceStatus) {
    "PASS" { "Green" }
    "WARN" { "Yellow" }
    default { "Red" }
}
$coexistencePrefix = switch ($result.ThirdPartyAvCoexistenceStatus) {
    "PASS" { "[OK]" }
    "WARN" { "[WARN]" }
    default { "[FAIL]" }
}
Write-Host "  $coexistencePrefix $($result.ThirdPartyAvCoexistenceLabel)" -ForegroundColor $coexistenceColor
Write-Host "         $($result.ThirdPartyAvCoexistenceNote)" -ForegroundColor DarkGray
Write-Host "         This posture call does not replace the full prerequisite checks below." -ForegroundColor DarkGray

Write-Host ""
Write-Host "--- Effective Defender Operational State ---" -ForegroundColor Yellow
$operationalStateColor = switch ($result.DefenderOperationalStateStatus) {
    "PASS" { "Green" }
    "WARN" { "Yellow" }
    default { "Red" }
}
$operationalStatePrefix = switch ($result.DefenderOperationalStateStatus) {
    "PASS" { "[OK]" }
    "WARN" { "[WARN]" }
    default { "[FAIL]" }
}
Write-Host "  $operationalStatePrefix $($result.DefenderOperationalStateLabel)" -ForegroundColor $operationalStateColor
Write-Host "         $($result.DefenderOperationalStateNote)" -ForegroundColor DarkGray

Write-Host ""
Write-Host "--- Windows Feature and Service Health ---" -ForegroundColor Yellow
if ($result.DefenderInstalled) {
    Write-Host "  [OK]   Windows Defender feature is installed ($($result.DefenderFeatureCheckSource))" -ForegroundColor Green
}
else {
    Write-Host "  [FAIL] Windows Defender feature is NOT installed ($($result.DefenderFeatureCheckSource))" -ForegroundColor Red
    Write-Host "         Run: Install-WindowsFeature -Name Windows-Defender -IncludeAllSubFeature" -ForegroundColor Yellow
}

foreach ($serviceCheck in @($result.WinDefendService, $result.SenseService, $result.FirewallService)) {
    $servicePrefix = switch ($serviceCheck.OutputStatus) {
        "PASS" { "[OK]" }
        "WARN" { "[WARN]" }
        default { "[FAIL]" }
    }
    $serviceColor = switch ($serviceCheck.OutputStatus) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        default { "Red" }
    }

    if ($serviceCheck.Exists) {
        Write-Host "  $servicePrefix $($serviceCheck.Name) is $($serviceCheck.State) with start mode $($serviceCheck.StartMode)" -ForegroundColor $serviceColor
        Write-Host "         $($serviceCheck.Note)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  [FAIL] $($serviceCheck.Name) service is not present" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "--- Microsoft Defender Antivirus Mode ---" -ForegroundColor Yellow
if ($result.MdavModeMatchesExpectation) {
    Write-Host "  [OK]   AMRunningMode = $($result.AMRunningMode) (expected $($result.ExpectedMdavMode))" -ForegroundColor Green
}
else {
    Write-Host "  [FAIL] AMRunningMode = $($result.AMRunningMode) (expected $($result.ExpectedMdavMode))" -ForegroundColor Red
}

if ($result.PassiveModePolicyCompliant) {
    Write-Host "  [OK]   ForceDefenderPassiveMode policy aligns with expected MDAV mode" -ForegroundColor Green
}
else {
    Write-Host "  [FAIL] ForceDefenderPassiveMode policy does not align with expected MDAV mode" -ForegroundColor Red
}

Write-Host "         Policy path: HKLM:\Software\Policies\Microsoft\Windows Advanced Threat Protection" -ForegroundColor DarkGray

Write-Host ""
Write-Host "--- Registry Policy Checks ---" -ForegroundColor Yellow
Write-Host "  Path: HKLM:\Software\Policies\Microsoft\Windows Defender" -ForegroundColor DarkGray

$regChecks = @(
    @{ Name = "DisableAntiSpyware"; Value = $result.DisableAntiSpyware; Desc = "Legacy policy signal. Confirm effective state with AMRunningMode and runtime signals." },
    @{ Name = "DisableAntiVirus"; Value = $result.DisableAntiVirus; Desc = "Legacy policy signal. Confirm effective state with AMRunningMode and runtime signals." },
    @{ Name = "ForceDefenderPassiveMode"; Value = $result.ForcePassiveMode; Desc = "Requests passive mode from the Defender for Endpoint policy path" }
)

$rtpChecks = @(
    @{ Name = "DisableRealtimeMonitoring"; Value = $result.DisableRealtimeMonitoring; Desc = "Disables real-time protection" },
    @{ Name = "DisableBehaviorMonitoring"; Value = $result.DisableBehaviorMonitoring; Desc = "Disables behavior monitoring" },
    @{ Name = "DisableOnAccessProtection"; Value = $result.DisableOnAccessProtection; Desc = "Disables file access scanning" },
    @{ Name = "DisableIOAVProtection"; Value = $result.DisableIOAVProtection; Desc = "Disables download and attachment scanning" },
    @{ Name = "DisableScanOnRealtimeEnable"; Value = $result.DisableScanOnRealtimeEnable; Desc = "Disables scan when real-time protection starts" }
)

foreach ($check in $regChecks) {
    if ($check.Name -eq "ForceDefenderPassiveMode") {
        if ($result.PassiveModePolicyCompliant) {
            $detail = if ($check.Value) { "set to 1 as expected" } else { "not set as expected" }
            Write-Host "  [OK]   $($check.Name) $detail ($($check.Desc))" -ForegroundColor Green
        }
        else {
            $detail = if ($check.Value) { "set to 1 unexpectedly" } else { "not set" }
            Write-Host "  [FAIL] $($check.Name) $detail ($($check.Desc))" -ForegroundColor Red
        }
    }
    elseif ($check.Value) {
        Write-Host "  [WARN] $($check.Name) = 1 ($($check.Desc))" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [OK]   $($check.Name) not set" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "--- Defender Runtime Signals (Get-MpComputerStatus) ---" -ForegroundColor Yellow

$runtimeChecks = @(
    @{ Name = "AntivirusEnabled"; Value = $result.AntivirusEnabled; Expected = if ($result.ExpectedMdavMode -eq "Active") { $true } elseif ($result.ExpectedMdavMode -eq "Passive") { $true } else { $null } },
    @{ Name = "AntispywareEnabled"; Value = $result.AntispywareEnabled; Expected = if ($result.ExpectedMdavMode -eq "Active") { $true } elseif ($result.ExpectedMdavMode -eq "Passive") { $true } else { $null } },
    @{ Name = "RealTimeProtectionEnabled"; Value = $result.RealTimeProtectionEnabled; Expected = if ($result.ExpectedMdavMode -eq "Active") { $true } elseif ($result.ExpectedMdavMode -eq "Passive") { $false } else { $null } },
    @{ Name = "BehaviorMonitorEnabled"; Value = $result.BehaviorMonitorEnabled; Expected = if ($result.ExpectedMdavMode -eq "Active") { $true } elseif ($result.ExpectedMdavMode -eq "Passive") { $true } else { $null } },
    @{ Name = "OnAccessProtectionEnabled"; Value = $result.OnAccessProtectionEnabled; Expected = if ($result.ExpectedMdavMode -eq "Active") { $true } elseif ($result.ExpectedMdavMode -eq "Passive") { $true } else { $null } },
    @{ Name = "IoavProtectionEnabled"; Value = $result.IoavProtectionEnabled; Expected = if ($result.ExpectedMdavMode -eq "Active") { $true } elseif ($result.ExpectedMdavMode -eq "Passive") { $true } else { $null } },
    @{ Name = "NISEnabled"; Value = $result.NISEnabled; Expected = if ($result.ExpectedMdavMode -eq "Active") { $true } elseif ($result.ExpectedMdavMode -eq "Passive") { $true } else { $null } },
    @{ Name = "IsTamperProtected"; Value = $result.IsTamperProtected; Expected = $null }
)

foreach ($runtimeCheck in $runtimeChecks) {
    if ($null -eq $runtimeCheck.Value) {
        Write-Host "  [WARN] $($runtimeCheck.Name) = N/A" -ForegroundColor Yellow
    }
    elseif ($null -ne $runtimeCheck.Expected -and $runtimeCheck.Value -ne $runtimeCheck.Expected) {
        Write-Host "  [WARN] $($runtimeCheck.Name) = $($runtimeCheck.Value) (expected $($runtimeCheck.Expected) for $($result.ExpectedMdavMode) mode)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [OK]   $($runtimeCheck.Name) = $($runtimeCheck.Value)" -ForegroundColor Green
    }
}

Write-Host "  Path: ...\Real-Time Protection" -ForegroundColor DarkGray
foreach ($check in $rtpChecks) {
    if ($check.Value) {
        Write-Host "  [FAIL] $($check.Name) = 1 ($($check.Desc))" -ForegroundColor Red
    }
    else {
        Write-Host "  [OK]   $($check.Name) not set" -ForegroundColor Green
    }
}

Write-Host "  Path: ...\Spynet (MAPS / Cloud Protection)" -ForegroundColor DarkGray
if ($result.MAPSDisabled) {
    Write-Host "  [FAIL] SpynetReporting = 0 (Cloud protection is disabled)" -ForegroundColor Red
}
elseif ($null -eq $result.MAPSReportingValue) {
    Write-Host "  [OK]   SpynetReporting not set (defaults to enabled)" -ForegroundColor Green
}
else {
    Write-Host "  [OK]   SpynetReporting = $($result.MAPSReportingValue)" -ForegroundColor Green
}

if ($result.SampleSubmissionBlocked) {
    Write-Host "  [FAIL] SubmitSamplesConsent = 2 (Never Send)" -ForegroundColor Red
}
elseif ($null -eq $result.SubmitSamplesValue) {
    Write-Host "  [OK]   SubmitSamplesConsent not set (defaults to send safe samples)" -ForegroundColor Green
}
else {
    Write-Host "  [OK]   SubmitSamplesConsent = $($result.SubmitSamplesValue)" -ForegroundColor Green
}

Write-Host ""
Write-Host "--- Service/Driver Registry Start Types ---" -ForegroundColor Yellow
Write-Host "  Path: HKLM:\SYSTEM\CurrentControlSet\Services\<Name>\Start" -ForegroundColor DarkGray
Write-Host "  (0=Boot, 2=Auto, 3=Manual, 4=Disabled)" -ForegroundColor DarkGray

$startLabels = @{ 0 = "Boot"; 1 = "System"; 2 = "Auto"; 3 = "Manual"; 4 = "Disabled" }
foreach ($svc in $result.ServiceRegChecks) {
    if (-not $svc.Exists) {
        Write-Host "  [FAIL] $($svc.Name) registry key not found ($($svc.Desc))" -ForegroundColor Red
    }
    elseif ($null -eq $svc.ActualStart) {
        Write-Host "  [FAIL] $($svc.Name) Start value missing ($($svc.Desc))" -ForegroundColor Red
    }
    elseif ($svc.ActualStart -eq 4) {
        Write-Host "  [FAIL] $($svc.Name) = 4 (Disabled) ($($svc.Desc))" -ForegroundColor Red
    }
    else {
        $status = if ($svc.ActualStart -eq $svc.ExpectedStart) { "[OK]" } else { "[WARN]" }
        $color = if ($svc.ActualStart -eq $svc.ExpectedStart) { "Green" } else { "Yellow" }
        $actualLabel = $startLabels[$svc.ActualStart]
        $expectedLabel = $startLabels[$svc.ExpectedStart]
        Write-Host "  $status $($svc.Name) = $($svc.ActualStart) ($actualLabel), expected $($svc.ExpectedStart) ($expectedLabel) ($($svc.Desc))" -ForegroundColor $color
    }
}

Write-Host ""
Write-Host "--- Defender Update Validation ---" -ForegroundColor Yellow
if ($result.MpStatusAvailable) {
    Write-Host "  [OK]   AMProductVersion            : $($result.AMProductVersion)" -ForegroundColor Green
    Write-Host "  [OK]   AMEngineVersion             : $($result.AMEngineVersion)" -ForegroundColor Green
    Write-Host "  [OK]   AntivirusSignatureVersion   : $($result.AntivirusSignatureVersion)" -ForegroundColor Green
    Write-Host "  [OK]   AntivirusSignatureLastUpdated: $($result.AntivirusSignatureLastUpdated)" -ForegroundColor Green
    if ($result.SignaturesFresh) {
        Write-Host "  [OK]   Signature age               : $($result.SignatureAgeDays) day(s)" -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] Signature age               : $($result.SignatureAgeDays) day(s)" -ForegroundColor Red
    }
}
else {
    Write-Host "  [FAIL] Get-MpComputerStatus failed: $($result.MpStatusError)" -ForegroundColor Red
}

if ($result.PlatformUpdateKB4052623Installed) {
    Write-Host "  [OK]   KB4052623 detected" -ForegroundColor Green
}
else {
    Write-Host "  [WARN] KB4052623 not detected via Get-HotFix; verify platform version separately if required" -ForegroundColor Yellow
}

if ($result.SenseUpdateRequired -eq $true) {
    if ($result.SenseUpdateKB5005292Installed) {
        Write-Host "  [OK]   KB5005292 detected for legacy Sense platform" -ForegroundColor Green
    }
    else {
        Write-Host "  [WARN] KB5005292 not detected on Server 2012 R2/2016; verify if the modern unified solution is already current" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "--- Firewall Configuration Checks ---" -ForegroundColor Yellow
if ($result.FirewallService.Passed) {
    Write-Host "  [OK]   MpsSvc is running with Automatic start" -ForegroundColor Green
}
else {
    Write-Host "  [FAIL] MpsSvc is not running with Automatic start" -ForegroundColor Red
}

if ($result.FirewallProfiles.Count -gt 0) {
    foreach ($firewallProfile in $result.FirewallProfiles) {
        if ($firewallProfile.Enabled) {
            Write-Host "  [OK]   $($firewallProfile.Name) profile enabled (Inbound: $($firewallProfile.DefaultInboundAction), Outbound: $($firewallProfile.DefaultOutboundAction))" -ForegroundColor Green
        }
        else {
            Write-Host "  [FAIL] $($firewallProfile.Name) profile disabled" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "  [FAIL] Unable to read firewall profiles: $($result.FirewallProfilesError)" -ForegroundColor Red
}

Write-Host ""
Write-Host "--- Endpoint Connectivity Checks ($($result.EffectiveEnvironmentType)) ---" -ForegroundColor Yellow
foreach ($endpoint in $result.EndpointChecks) {
    switch ($endpoint.Status) {
        "PASS" {
            Write-Host "  [OK]   $($endpoint.Name) -> $($endpoint.HostName):$($endpoint.Port) [$($endpoint.ResolvedAddress)]" -ForegroundColor Green
        }
        "MANUAL" {
            Write-Host "  [WARN] $($endpoint.Name) -> $($endpoint.HostName):$($endpoint.Port) ($($endpoint.Note))" -ForegroundColor Yellow
        }
        default {
            Write-Host "  [FAIL] $($endpoint.Name) -> $($endpoint.HostName):$($endpoint.Port) ($($endpoint.Note))" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "--- Trellix / Third-Party Exclusions Checks ---" -ForegroundColor Yellow
if ($result.DetectedThirdPartyServices.Count -gt 0) {
    Write-Host "  Detected Trellix or other security services:" -ForegroundColor DarkGray
    foreach ($service in $result.DetectedThirdPartyServices) {
        Write-Host "    - $($service.Name) ($($service.DisplayName)) [$($service.State)]" -ForegroundColor DarkGray
    }
}
else {
    Write-Host "  [OK]   No Trellix, McAfee, HBSS, or Tanium services detected locally" -ForegroundColor Green
}

if ($result.ExclusionsConfiguredSuccessful) {
    if ($result.DefenderExclusionMatches.Count -gt 0) {
        Write-Host "  [OK]   Defender exclusions include Trellix or other detected security-product entries" -ForegroundColor Green
    }
    else {
        Write-Host "  [OK]   No local Defender exclusion gap detected for Trellix coexistence" -ForegroundColor Green
    }
}
else {
    Write-Host "  [FAIL] Defender exclusions do not appear to include the detected Trellix or other security product" -ForegroundColor Red
    if ($result.ExclusionsError) {
        Write-Host "         $($result.ExclusionsError)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Automated Pre-Flight Summary" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "======================================================================" -ForegroundColor Cyan

$summaryItems = @(
    @{ Name = "Trellix coexistence readiness"; Status = $result.ThirdPartyAvCoexistenceStatus },
    @{ Name = "Effective Defender operational state"; Status = $result.DefenderOperationalStateStatus },
    @{ Name = "All critical checks passed"; Passed = $result.AllCriticalChecksPassed },
    @{ Name = "MDAV running mode meets expectation"; Passed = $result.MdavModeMatchesExpectation },
    @{ Name = "All registry validations successful"; Passed = $result.RegistryValidationsSuccessful },
    @{ Name = "All updates installed and verified"; Passed = $result.UpdatesInstalledAndVerified },
    @{ Name = "All firewall rules configured"; Passed = $result.FirewallRulesConfigured },
    @{ Name = "All endpoint connectivity tests successful"; Passed = $result.EndpointConnectivitySuccessful },
    @{ Name = "All exclusions configured"; Passed = $result.ExclusionsConfiguredSuccessful }
)

foreach ($item in $summaryItems) {
    $itemStatus = if ($item.ContainsKey("Status")) { $item.Status } else { if ($item.Passed) { "PASS" } else { "FAIL" } }
    $itemPrefix = switch ($itemStatus) {
        "PASS" { "[OK]" }
        "WARN" { "[WARN]" }
        default { "[FAIL]" }
    }
    $itemColor = switch ($itemStatus) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        default { "Red" }
    }
    Write-Host "  $itemPrefix $($item.Name)" -ForegroundColor $itemColor
}

if ($result.EndpointManualReviewRequired) {
    Write-Host "" 
    Write-Host "  [WARN] Some required wildcard endpoints still need manual review or MDE Connectivity Analyzer validation." -ForegroundColor Yellow
}

if ($GenerateHtmlReport) {
    $HtmlReportPath = Resolve-HtmlReportPath -RequestedPath $HtmlReportPath -TargetServerName $ServerName

    New-HtmlReport -Result $result -ReportPath $HtmlReportPath -EvaluatedServerName $ServerName
    Write-Host "" 
    Write-Host "HTML report written to: $HtmlReportPath" -ForegroundColor Cyan
    Write-Host "Copy/paste path:" -ForegroundColor Cyan
    Write-Host $HtmlReportPath
}