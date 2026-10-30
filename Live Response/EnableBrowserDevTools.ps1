<#
.SYNOPSIS
    Checks or enables browser developer tools for Chrome and Edge.
.DESCRIPTION
    Reads the machine DeveloperToolsAvailability policy by default.
    With Remediate, creates missing policy paths and sets the value to DWORD 0.
    Value 0 allows developer tools except for extensions installed by enterprise
    policy. This preserves that restriction rather than allowing all usage.
    Uses the native registry view even from a 32 bit PowerShell process.
    Run with administrator or SYSTEM rights to apply changes. Managed policy
    refresh can overwrite these settings. Restart the browsers if needed.
.PARAMETER Remediate
    Applies and verifies the registry changes. Without this switch, reports only.
.EXAMPLE
    run EnableBrowserDevTools.ps1
.EXAMPLE
    run EnableBrowserDevTools.ps1 -parameters "-Remediate"
#>
[CmdletBinding()]
param(
    [switch]$Remediate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$device = $env:COMPUTERNAME
$utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$keyName = 'DeveloperToolsAvailability'
$desiredValue = 0
$failed = $false
$baseKey = $null
$browsers = @(
    @{ Name = 'Chrome'; Path = 'Software\Policies\Google\Chrome' }
    @{ Name = 'Edge'; Path = 'Software\Policies\Microsoft\Edge' }
)

Write-Output ("Device: {0}  UTC: {1}  Remediate: {2}" -f $device, $utc, $Remediate.IsPresent)

try {
    $view = [Microsoft.Win32.RegistryView]::Registry32
    if ([Environment]::Is64BitOperatingSystem) {
        $view = [Microsoft.Win32.RegistryView]::Registry64
    }
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, $view
    )

    foreach ($browser in $browsers) {
        $policyKey = $null
        try {
            $policyKey = $baseKey.OpenSubKey($browser.Path, $Remediate.IsPresent)
            $currentValue = $null
            $currentKind = $null
            if ($null -ne $policyKey -and $policyKey.GetValueNames() -contains $keyName) {
                $currentValue = $policyKey.GetValue($keyName)
                $currentKind = $policyKey.GetValueKind($keyName)
            }

            $isConfigured = $currentKind -eq [Microsoft.Win32.RegistryValueKind]::DWord -and
                $currentValue -eq $desiredValue
            $status = 'Change required'
            if ($isConfigured) {
                $status = 'Already configured'
            }
            elseif ($Remediate) {
                if ($null -eq $policyKey) {
                    $policyKey = $baseKey.CreateSubKey($browser.Path)
                }
                $policyKey.SetValue($keyName, $desiredValue, [Microsoft.Win32.RegistryValueKind]::DWord)
                if ($policyKey.GetValueKind($keyName) -ne [Microsoft.Win32.RegistryValueKind]::DWord -or
                    $policyKey.GetValue($keyName) -ne $desiredValue) {
                    throw 'Registry verification failed.'
                }
                $status = 'Applied and verified'
            }

            [pscustomobject]@{
                Browser = $browser.Name
                RegistryPath = 'HKLM:\{0}' -f $browser.Path
                Policy = $keyName
                PreviousValue = $currentValue
                PreviousType = $currentKind
                DesiredValue = $desiredValue
                Status = $status
            } | Write-Output
        }
        catch {
            $failed = $true
            Write-Error ("{0} policy operation failed: {1}" -f $browser.Name, $_.Exception.Message) -ErrorAction Continue
        }
        finally {
            if ($null -ne $policyKey) {
                $policyKey.Dispose()
            }
        }
    }
}
catch {
    $failed = $true
    Write-Error ("Registry access failed: {0}" -f $_.Exception.Message) -ErrorAction Continue
}
finally {
    if ($null -ne $baseKey) {
        $baseKey.Dispose()
    }
}

if ($failed) {
    exit 1
}
if (-not $Remediate) {
    Write-Output 'Report only. Use -Remediate to apply changes.'
}
exit 0
