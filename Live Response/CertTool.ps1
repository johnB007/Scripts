<#
.SYNOPSIS
    Certificate Operations Tool
    Delilo MSFT 28 Jul 26

.EXAMPLE
    .\CertTool.ps1 -Action Enumerate


.EXAMPLE
    .\CertTool.ps1 -Action Export -Thumbprint ABC123...

.EXAMPLE
    .\CertTool.ps1 -Action Delete -Thumbprint ABC123...
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Enumerate","Export","Delete")]
    [string]$Action,

    [string]$Thumbprint,

    [string]$OutputFolder = "C:\TempExport\CertTool"
)

# =================================================================
# Initialization
# =================================================================

$null = New-Item -ItemType Directory -Path $OutputFolder -Force -ErrorAction SilentlyContinue

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $OutputFolder "CertTool_$TimeStamp.log"

$Stores = @(
#Get-ChildItem Cert:\ -Recurse


    "Cert:\LocalMachine\My",
    "Cert:\CurrentUser\My",
    "Cert:\LocalMachine\Root",
    "Cert:\CurrentUser\Root",
    "Cert:\LocalMachine\CA",
    "Cert:\CurrentUser\CA",
    "Cert:\LocalMachine\TrustedPublisher",
    "Cert:\CurrentUser\TrustedPublisher"


)

function Write-Log {
    param([string]$Message)

    $Entry = "{0} - {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message

    $Entry | Tee-Object -FilePath $LogFile -Append
}

function Get-CertificateByThumbprint {

    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    $Thumbprint = $Thumbprint.Replace(" ","").ToUpper()

    foreach ($Store in $Stores) {

        try {

            $Cert = Get-ChildItem $Store -ErrorAction Stop |
                Where-Object {
                    $_.Thumbprint.ToUpper() -eq $Thumbprint
                }

            if ($Cert) {
                return [PSCustomObject]@{
                    Certificate = $Cert
                    Store       = $Store
                }
            }
        }
        catch {
            continue
        }
    }

    return $null
}

function Write-CertificateDetails {

    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$Store
    )

    Write-Log "Store              : $Store"
    Write-Log "Subject            : $($Certificate.Subject)"
    Write-Log "Issuer             : $($Certificate.Issuer)"
    Write-Log "Thumbprint         : $($Certificate.Thumbprint)"
    Write-Log "Serial Number      : $($Certificate.SerialNumber)"
    Write-Log "Not Before         : $($Certificate.NotBefore)"
    Write-Log "Not After          : $($Certificate.NotAfter)"
    Write-Log "Friendly Name      : $($Certificate.FriendlyName)"
    Write-Log "Has Private Key    : $($Certificate.HasPrivateKey)"
}

function Invoke-CertificateEnumeration {

    Write-Log "===== CERTIFICATE ENUMERATION STARTED ====="

    foreach ($Store in $Stores) {

        Write-Log ""
        Write-Log "Enumerating Store: $Store"

        try {

            $Certificates = Get-ChildItem $Store -ErrorAction Stop

            foreach ($Certificate in $Certificates) {

                Write-Log "-------------------------------------------"
                Write-CertificateDetails `
                    -Certificate $Certificate `
                    -Store $Store
            }

            Write-Log "Certificate Count: $($Certificates.Count)"
        }
        catch {

            Write-Log "Unable to access store: $Store"
            Write-Log $_.Exception.Message
        }
    }

    Write-Log "===== CERTIFICATE ENUMERATION COMPLETE ====="
}

function Invoke-CertificateExport {

    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    Write-Log "===== CERTIFICATE EXPORT STARTED ====="

    $Result = Get-CertificateByThumbprint -Thumbprint $Thumbprint

    if (-not $Result) {

        Write-Log "Certificate not found."
        return
    }

    $Certificate = $Result.Certificate
    $Store = $Result.Store

    Write-CertificateDetails `
        -Certificate $Certificate `
        -Store $Store

    $ExportFile = Join-Path $OutputFolder "$($Certificate.Thumbprint).cer"

    try {

        Export-Certificate `
            -Cert $Certificate `
            -FilePath $ExportFile `
            -Force | Out-Null

        Write-Log "Certificate exported successfully."
        Write-Log "Export Path: $ExportFile"
    }
    catch {

        Write-Log "Export failed."
        Write-Log $_.Exception.Message
    }

    Write-Log "===== CERTIFICATE EXPORT COMPLETE ====="
}

function Invoke-CertificateDeletion {

    param(
        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    Write-Log "===== CERTIFICATE DELETION STARTED ====="

    $Result = Get-CertificateByThumbprint -Thumbprint $Thumbprint

    if (-not $Result) {

        Write-Log "Certificate not found."
        return
    }

    $Certificate = $Result.Certificate
    $Store = $Result.Store

    Write-CertificateDetails `
        -Certificate $Certificate `
        -Store $Store

    try {

        Remove-Item `
            -Path $Certificate.PSPath `
            -Force `
            -ErrorAction Stop

        Write-Log "Certificate successfully deleted."
    }
    catch {

        Write-Log "Deletion failed."
        Write-Log $_.Exception.Message
    }

    Write-Log "===== CERTIFICATE DELETION COMPLETE ====="
}

# =================================================================
# Action Processing
# =================================================================

Write-Log "Action Requested: $Action"

switch ($Action) {

    "Enumerate" {

        Invoke-CertificateEnumeration
    }

    "Export" {

        #if (:IsNullOrWhiteSpace($Thumbprint)) {
        #    throw "Thumbprint parameter is required for Export."
        #}

        Invoke-CertificateExport -Thumbprint $Thumbprint
    }

    "Delete" {
#adjusted
        if ([string]::IsNullOrWhiteSpace($Thumbprint))
        {
            throw "Thumbprint parameter is required for Delete."
        }

        Invoke-CertificateDeletion -Thumbprint $Thumbprint
    }
}

Write-Log "Log File: $LogFile"
