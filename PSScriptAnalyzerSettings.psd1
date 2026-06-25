@{
    # Lint rules for MDE Live Response PowerShell scripts.
    # Live Response runs Windows PowerShell 5.1, so target that for compatibility.

    Severity = @('Error', 'Warning')

    IncludeDefaultRules = $true

    # Write-Host is allowed for human readable status in Live Response output,
    # so it is not flagged here. The Test-LRScript runner checks for the cmdlets
    # that actually break a non interactive session instead.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1')
        }
    }
}
