<#
.SYNOPSIS
Generate simulation profile JSON files for sandbox identities.

.DESCRIPTION
Creates one JSON profile per user for Invoke-DailyCloudUserSimulation.ps1.
The input can be a BAESL style CSV export or generated sample identities.

.EXAMPLE
pwsh -File .\New-CloudUserSimulationProfileSet.ps1 -OutputFolder .\profiles -Domain contoso.com -UserCount 10

.EXAMPLE
pwsh -File .\New-CloudUserSimulationProfileSet.ps1 -InputCsvPath .\UserCredentials.csv -OutputFolder .\profiles
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputFolder,

    [string]$InputCsvPath,

    [ValidateRange(1, 500)]
    [int]$UserCount = 12,

    [string]$Domain = 'contoso.com',

    [string[]]$SharePathCandidates = @(),

    [string[]]$MailRecipients = @(),

    [string[]]$PortalUrls = @(
        'https://www.office.com/?auth=2',
        'https://www.microsoft365.com/',
        'https://outlook.office.com/mail/',
        'https://teams.microsoft.com/'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RandomIdentitySeed {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Count,

        [Parameter(Mandatory = $true)]
        [string]$TenantDomain
    )

    $firstNames = @('Avery','Jordan','Morgan','Casey','Riley','Taylor','Parker','Quinn','Hayden','Skyler','Cameron','Reese')
    $lastNames = @('Baker','Carter','Davis','Ellis','Foster','Gray','Hayes','Jordan','Knight','Lopez','Morris','Perry')
    $departments = @('Finance','Human Resources','Legal','Operations','Research','Sales','Security')
    $titles = @('Analyst','Engineer','Coordinator','Manager','Specialist','Consultant')
    $offices = @('Atlanta','Chicago','Dallas','New York','Remote','Seattle','Washington')

    $records = @()
    for ($index = 1; $index -le $Count; $index++) {
        $firstName = Get-Random -InputObject $firstNames
        $lastName = Get-Random -InputObject $lastNames
        $department = Get-Random -InputObject $departments
        $title = Get-Random -InputObject $titles
        $office = Get-Random -InputObject $offices
        $upn = ('{0}.{1}{2}@{3}' -f $firstName.ToLower(), $lastName.ToLower(), $index, $TenantDomain)
        $records += [pscustomobject]@{
            DisplayName = ('{0} {1}' -f $firstName, $lastName)
            FirstName = $firstName
            LastName = $lastName
            UPN = $upn
            Department = $department
            JobTitle = $title
            OfficeLocation = $office
            Manager = ('{0} Manager' -f $department)
        }
    }

    return $records
}

function ConvertFrom-InputRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Record
    )

    $null = $Record.PSObject.Properties.Count

    function Get-RecordValue {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Name
        )

        $property = $Record.PSObject.Properties[$Name]
        if ($null -eq $property) {
            return $null
        }

        return $property.Value
    }

    $upn = Get-RecordValue -Name 'UPN'
    if (-not $upn) {
        $upn = Get-RecordValue -Name 'UserPrincipalName'
    }
    if (-not $upn) {
        throw 'Each input record must contain UPN or UserPrincipalName.'
    }

    $displayName = Get-RecordValue -Name 'DisplayName'
    if (-not $displayName) {
        $localPart = ($upn -split '@')[0]
        $displayName = (($localPart -split '[._]') | ForEach-Object {
            if ($_.Length -gt 0) {
                $_.Substring(0,1).ToUpper() + $_.Substring(1)
            }
        }) -join ' '
    }

    return [pscustomobject]@{
        DisplayName = $displayName
        FirstName = Get-RecordValue -Name 'FirstName'
        LastName = Get-RecordValue -Name 'LastName'
        UPN = $upn
        Department = $(if (Get-RecordValue -Name 'Department') { Get-RecordValue -Name 'Department' } else { 'Security Operations' })
        JobTitle = $(if (Get-RecordValue -Name 'JobTitle') { Get-RecordValue -Name 'JobTitle' } elseif (Get-RecordValue -Name 'Position') { Get-RecordValue -Name 'Position' } else { 'Analyst' })
        OfficeLocation = $(if (Get-RecordValue -Name 'OfficeLocation') { Get-RecordValue -Name 'OfficeLocation' } elseif (Get-RecordValue -Name 'Office') { Get-RecordValue -Name 'Office' } else { 'Remote' })
        Manager = $(if (Get-RecordValue -Name 'Manager') { Get-RecordValue -Name 'Manager' } else { 'Team Lead' })
        SimulationEnabled = $(if ($null -ne (Get-RecordValue -Name 'SimulationEnabled')) { [string](Get-RecordValue -Name 'SimulationEnabled') } else { 'true' })
    }
}

function Test-SimulationEnabled {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    $text = ([string]$Value).Trim().ToLowerInvariant()
    return ($text -notin @('false', '0', 'no', 'n', 'disabled'))
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$records = if ($InputCsvPath) {
    Import-Csv -Path $InputCsvPath | ForEach-Object { ConvertFrom-InputRecord -Record $_ }
}
else {
    Get-RandomIdentitySeed -Count $UserCount -TenantDomain $Domain
}

$summary = @()
foreach ($record in $records) {
    if (-not (Test-SimulationEnabled -Value $record.SimulationEnabled)) {
        continue
    }

    $safeName = ($record.UPN -replace '[^a-zA-Z0-9@._-]', '') -replace '@', '_at_'
    $profilePath = Join-Path $OutputFolder ("{0}.json" -f $safeName)
    $profileDocument = [pscustomobject]@{
        UserContext = [pscustomobject]@{
            DisplayName = $record.DisplayName
            Department = $record.Department
            JobTitle = $record.JobTitle
            OfficeLocation = $record.OfficeLocation
            Manager = $record.Manager
            UserPrincipalName = $record.UPN
        }
        MailRecipients = @($MailRecipients)
        PortalUrls = @($PortalUrls)
        PublicUrls = @(
            'https://learn.microsoft.com/',
            'https://www.bing.com/news',
            'https://www.microsoft.com/security/blog/'
        )
        SharePathCandidates = @($SharePathCandidates)
        TypingLines = @(
            ('Reviewing tasks for {0}.' -f $record.DisplayName),
            ('Checking Teams and Outlook for {0}.' -f $record.Department),
            ('Opening files and portals for {0}.' -f $record.JobTitle)
        )
    }

    $profileDocument | ConvertTo-Json -Depth 6 | Set-Content -Path $profilePath -Encoding UTF8
    $summary += [pscustomobject]@{
        DisplayName = $record.DisplayName
        UPN = $record.UPN
        Department = $record.Department
        JobTitle = $record.JobTitle
        ProfilePath = $profilePath
    }
}

$summaryPath = Join-Path $OutputFolder 'profile-summary.csv'
$summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
$summary | Format-Table -AutoSize
Write-Output ("Saved profiles to {0}" -f $OutputFolder)
Write-Output ("Saved summary to {0}" -f $summaryPath)
exit 0