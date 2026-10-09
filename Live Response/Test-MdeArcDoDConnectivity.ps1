<#
.SYNOPSIS
    Creates one standalone HTML report that validates Azure Arc and MDE DoD readiness on Windows Server.

.DESCRIPTION
    Validates outbound connectivity from a Windows Server to the URLs Microsoft
    documents as required for:
      - Azure Arc enabled servers onboarding (Azure Government)
      - Microsoft Defender for Endpoint (DoD), streamlined and standard connectivity
      - Defender for Servers auto onboarding of MDE via Arc (MDE.Windows extension)

    It also collects the local evidence behind most onboarding failures:
    Azure Connected Machine agent status, the native azcmagent check, Arc
    extension status and logs, MDE onboarding state and SENSE errors, Arc and
    MDE proxy settings, TLS 1.2 settings, trusted root certificates, automatic
    root update policy, clock skew, TLS inspection, and government Blob hosts
    observed in local Arc logs.

    Each endpoint is tested once through the proxy path used by the agent that
    owns it. Wildcard firewall rules are reported separately with the concrete
    hosts tested beneath each rule.

    Read only. The only artifact is one standalone HTML file.

.PARAMETER ArcLocation
    Azure Government region for the Arc checks. When this parameter is not
    supplied and the agent is connected, the connected region is used.

.PARAMETER MdeConnectivity
    Auto detects streamlined or standard MDE connectivity from local evidence.
    Standard endpoints stay required unless streamlined is detected or chosen.

.PARAMETER ProxyUrl
    Forces every probe through this proxy. By default each probe uses the proxy
    configured for the agent that owns the endpoint.

.PARAMETER TimeoutSeconds
    Timeout for each network probe.

.PARAMETER OutputDirectory
    Directory for the HTML report.

.EXAMPLE
    run Test-MdeArcDoDConnectivity.ps1

.EXAMPLE
    run Test-MdeArcDoDConnectivity.ps1 -parameters "-ArcLocation usgovarizona -MdeConnectivity Streamlined"
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9]+$')]
    [string]$ArcLocation = 'usgovvirginia',

    [ValidateSet('Auto', 'Streamlined', 'Standard')]
    [string]$MdeConnectivity = 'Auto',

    [string]$ProxyUrl = '',

    [ValidateRange(2, 30)]
    [int]$TimeoutSeconds = 5,

    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = $env:TEMP
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Arc and MDE require TLS 1.2. This only affects probes made by this process.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::Expect100Continue = $false

$scriptVersion = '2.0.0'
$startedUtc = [DateTime]::UtcNow
$deviceName = if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { 'UnknownDevice' } else { $env:COMPUTERNAME }
$safeDeviceName = $deviceName -replace '[^A-Za-z0-9._-]', '_'
$reportPath = Join-Path $OutputDirectory ('MDE_Arc_DoD_Connectivity_{0}_{1}.html' -f $safeDeviceName, $startedUtc.ToString('yyyyMMddTHHmmssZ'))

$sources = [ordered]@{
    'Azure Arc network requirements'              = 'https://learn.microsoft.com/azure/azure-arc/servers/network-requirements'
    'azcmagent check reference'                   = 'https://learn.microsoft.com/azure/azure-arc/servers/azcmagent-check'
    'MDE streamlined URLs for US Government'      = 'https://learn.microsoft.com/defender-endpoint/streamlined-device-connectivity-urls-gov'
    'MDE standard URLs for US Government'         = 'https://learn.microsoft.com/defender-endpoint/standard-device-connectivity-urls-gov'
    'MDE network configuration'                   = 'https://learn.microsoft.com/defender-endpoint/configure-environment'
    'MDE Client Analyzer connectivity validation'  = 'https://learn.microsoft.com/defender-endpoint/verify-connectivity'
    'Azure certificate authority details'         = 'https://learn.microsoft.com/azure/security/fundamentals/azure-certificate-authority-details'
}

# Public roots used by Microsoft and Azure endpoints. Any other root suggests TLS inspection.
$publicRootPattern = '(?i)O=Microsoft Corporation|O=DigiCert|O=GeoTrust|Baltimore|GlobalSign|O=Entrust|USERTrust|Sectigo'
$proxyProductPattern = '(?i)squid|bluecoat|blue coat|zscaler|mcafee|skyhigh|websense|forcepoint|palo ?alto|fortinet|fortigate|netskope|cisco|symantec|barracuda|sophos|iboss|checkpoint'
$errorLinePattern = '(?i)\b(error|fail|failed|failure|denied|timeout|timed out|unable|exception|refused|unreachable)\b'

$localChecks = New-Object System.Collections.Generic.List[object]
$evidence = New-Object System.Collections.Generic.List[object]
$endpointDefinitions = New-Object System.Collections.Generic.List[object]

function ConvertTo-HtmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-StatusClass {
    param([AllowNull()][string]$Status)
    switch ($Status) {
        'PASS' { return 'pass' }
        'FAIL' { return 'fail' }
        'WARN' { return 'warn' }
        default { return 'review' }
    }
}

function ConvertTo-StatusCell {
    param([AllowNull()][string]$Status)
    return '<span class="{0}">{1}</span>' -f (Get-StatusClass -Status $Status), (ConvertTo-HtmlText $Status)
}

function Add-LocalCheck {
    param([string]$Area, [string]$Check, [string]$Status, [string]$Detail)
    $localChecks.Add([pscustomobject]@{ Area = $Area; Check = $Check; Status = $Status; Detail = $Detail })
}

function Add-Evidence {
    param([string]$Title, [AllowNull()][string]$Text, [switch]$Open)
    if ([string]::IsNullOrWhiteSpace($Text)) { $Text = 'Not collected or empty.' }
    $evidence.Add([pscustomobject]@{ Title = $Title; Text = $Text; Open = [bool]$Open })
}

function Hide-Credential {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    return ($Text -replace '(?i)(://)[^/\s@]+@', '$1<redacted>@')
}

function Get-InnermostMessage {
    param([System.Exception]$Exception)
    $current = $Exception
    while ($null -ne $current.InnerException) { $current = $current.InnerException }
    return $current.Message
}

function Find-WebException {
    param([System.Exception]$Exception)
    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [System.Net.WebException]) { return $current }
        $current = $current.InnerException
    }
    return $null
}

function Get-ObjectProperty {
    param([AllowNull()][object]$InputObject, [string[]]$Path)
    $current = $InputObject
    foreach ($name in $Path) {
        if ($null -eq $current) { return $null }
        $property = $current.PSObject.Properties[$name]
        if ($null -eq $property) { return $null }
        $current = $property.Value
    }
    return $current
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Arguments = '',
        [int]$TimeoutSec = 60
    )

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = $FilePath
    $process.StartInfo.Arguments = $Arguments
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.CreateNoWindow = $true
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSec * 1000)) {
            try { $process.Kill() } catch { $null = $_ }
            return [pscustomobject]@{ ExitCode = $null; Output = ('Timed out after {0} seconds.' -f $TimeoutSec); TimedOut = $true }
        }
        $process.WaitForExit()
        $text = ($stdout.Result + [Environment]::NewLine + $stderr.Result).Trim()
        $text = $text -replace "\x1b\[[0-9;]*[A-Za-z]", ''
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $text; TimedOut = $false }
    }
    catch {
        return [pscustomobject]@{ ExitCode = $null; Output = (Get-InnermostMessage -Exception $_.Exception); TimedOut = $false }
    }
    finally {
        $process.Dispose()
    }
}

function Get-FileTail {
    param([string]$Path, [int]$MaxLines = 60, [int]$MaxBytes = 524288)
    try {
        $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        try {
            $start = [Math]::Max([long]0, $stream.Length - $MaxBytes)
            [void]$stream.Seek($start, [System.IO.SeekOrigin]::Begin)
            $reader = New-Object System.IO.StreamReader($stream)
            $text = $reader.ReadToEnd()
        }
        finally {
            $stream.Dispose()
        }
        $lines = @($text -split "`r?`n")
        if ($lines.Count -gt $MaxLines) { $lines = $lines[($lines.Count - $MaxLines)..($lines.Count - 1)] }
        return ($lines -join [Environment]::NewLine)
    }
    catch {
        return ('Unable to read {0}: {1}' -f $Path, (Get-InnermostMessage -Exception $_.Exception))
    }
}

function Select-ErrorLine {
    param([AllowNull()][string]$Text, [int]$MaxLines = 40)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $lines = @($Text -split "`r?`n" | Where-Object { $_ -match $errorLinePattern })
    if ($lines.Count -eq 0) { return 'No error lines found in the collected tail.' }
    if ($lines.Count -gt $MaxLines) { $lines = $lines[($lines.Count - $MaxLines)..($lines.Count - 1)] }
    return ($lines -join [Environment]::NewLine)
}

function ConvertTo-ProxyUri {
    param([AllowNull()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $candidate = $Value.Trim().Trim('"').Trim("'")
    if ($candidate -match '^(?i)(\(none\)|none|\[\]|direct.*)$') { return '' }
    if ($candidate -match '(?i)https=([^;\s]+)') { $candidate = $Matches[1] }
    elseif ($candidate -match '(?i)http=([^;\s]+)') { $candidate = $Matches[1] }
    elseif ($candidate.Contains(';')) { $candidate = $candidate.Split(';')[0] }
    if ($candidate -notmatch '^[A-Za-z][A-Za-z0-9+.-]*://') { $candidate = 'http://' + $candidate }
    return $candidate
}

function Get-ObservedHostName {
    param([AllowNull()][string[]]$Text, [string]$Pattern, [int]$Max = 15)
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($block in @($Text)) {
        if ([string]::IsNullOrEmpty($block)) { continue }
        foreach ($match in [regex]::Matches($block, $Pattern)) {
            $name = $match.Value.ToLowerInvariant().Trim('.')
            if (($name.Split('.').Count -ge 3) -and -not $found.Contains($name)) { $found.Add($name) }
            if ($found.Count -ge $Max) { return $found.ToArray() }
        }
    }
    return $found.ToArray()
}

function Get-LevelRank {
    param([string]$Level)
    switch ($Level) {
        'Required' { return 0 }
        'Conditional' { return 1 }
        'Recommended' { return 2 }
        default { return 3 }
    }
}

function Add-Endpoint {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [int]$Port = 443,
        [string]$Path = '/',
        [Parameter(Mandatory)][string]$Rule,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$UsedBy,
        [Parameter(Mandatory)][string]$Purpose,
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Route
    )

    $key = '{0}:{1}' -f $HostName.ToLowerInvariant(), $Port
    $existing = $null
    foreach ($item in $endpointDefinitions) { if ($item.Key -eq $key) { $existing = $item; break } }

    # One probe per host and port. Shared endpoints list every dependent service.
    if ($null -ne $existing) {
        if (-not $existing.UsedBy.Contains($UsedBy)) { $existing.UsedBy = '{0}; {1}' -f $existing.UsedBy, $UsedBy }
        if (-not $existing.Rule.Contains($Rule)) { $existing.Rule = '{0}; {1}' -f $existing.Rule, $Rule }
        if (-not $existing.Purpose.Contains($Purpose)) { $existing.Purpose = '{0} {1}' -f $existing.Purpose, $Purpose }
        if ((Get-LevelRank -Level $Level) -lt (Get-LevelRank -Level $existing.Level)) { $existing.Level = $Level }
        return
    }

    $scheme = if ($Port -eq 80) { 'http' } else { 'https' }
    $endpointDefinitions.Add([pscustomobject]@{
        Key      = $key
        HostName = $HostName.ToLowerInvariant()
        Port     = $Port
        Uri      = ('{0}://{1}{2}' -f $scheme, $HostName, $Path)
        Rule     = $Rule
        Area     = $Area
        UsedBy   = $UsedBy
        Purpose  = $Purpose
        Level    = $Level
        Route    = $Route
    })
}

function Test-TcpPort {
    param([string]$HostName, [int]$Port, [int]$Timeout)
    $client = New-Object System.Net.Sockets.TcpClient
    $asyncResult = $null
    try {
        $asyncResult = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($Timeout * 1000, $false)) {
            return [pscustomobject]@{ Status = 'FAIL'; Detail = 'Direct TCP connection timed out.' }
        }
        $client.EndConnect($asyncResult)
        return [pscustomobject]@{ Status = 'PASS'; Detail = 'Direct TCP connection succeeded.' }
    }
    catch {
        return [pscustomobject]@{ Status = 'FAIL'; Detail = (Get-InnermostMessage -Exception $_.Exception) }
    }
    finally {
        if ($null -ne $asyncResult) { $asyncResult.AsyncWaitHandle.Close() }
        $client.Close()
    }
}

function Test-RootPresent {
    param([string]$Thumbprint)
    foreach ($storeName in @('Root', 'AuthRoot')) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $found = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $Thumbprint, $false)
            if ($found.Count -gt 0) { return $storeName }
        }
        catch {
            $null = $_
        }
        finally {
            $store.Close()
        }
    }
    return ''
}

function Get-RouteProxy {
    param([object]$Definition)
    if (-not [string]::IsNullOrWhiteSpace($ProxyUrl)) { return (ConvertTo-ProxyUri -Value $ProxyUrl) }
    switch ($Definition.Route) {
        'Arc' {
            if (-not $arcProxy) { return '' }
            # Honor the Arc agent proxy bypass list for the service groups it supports.
            if ($arcBypass -match '(?i)\bAAD\b' -and $Definition.HostName -match '(?i)login\.microsoftonline|pasff\.') { return '' }
            if ($arcBypass -match '(?i)\bARM\b' -and $Definition.HostName -match '(?i)^management\.') { return '' }
            if ($arcBypass -match '(?i)\bArc\b' -and $Definition.HostName -match '(?i)his\.arc|guestconfiguration') { return '' }
            return $arcProxy
        }
        'MDE' {
            if ($mdeTelemetryProxy) { return $mdeTelemetryProxy }
            return $winHttpProxy
        }
        default { return $winHttpProxy }
    }
}

function Invoke-EndpointProbe {
    param(
        [Parameter(Mandatory)][object]$Definition,
        [AllowEmptyString()][string]$Proxy,
        [Parameter(Mandatory)][int]$Timeout
    )

    $notes = New-Object System.Collections.Generic.List[string]
    $dnsStatus = 'FAIL'
    $addressText = ''
    try {
        $addresses = @([System.Net.Dns]::GetHostAddresses($Definition.HostName) | ForEach-Object { $_.IPAddressToString } | Select-Object -Unique -First 3)
        if ($addresses.Count -gt 0) {
            $dnsStatus = 'PASS'
            $addressText = $addresses -join ', '
        }
        else {
            $notes.Add('DNS returned no addresses.')
        }
    }
    catch {
        $notes.Add(('DNS: {0}' -f (Get-InnermostMessage -Exception $_.Exception)))
    }

    $pathText = if ($Proxy) { 'Proxy ' + (Hide-Credential -Text $Proxy) } else { 'Direct' }
    $httpStatus = 'FAIL'
    $httpCode = ''
    $tlsStatus = 'N/A'
    $issuer = ''
    $rootName = ''
    $expiry = ''
    $skew = $null
    $inspection = $false
    $elapsed = ''
    $serverCertificate = $null
    $httpErrorNote = ''

    if ($dnsStatus -eq 'FAIL' -and -not $Proxy) {
        $notes.Add('HTTP skipped because the name does not resolve and no proxy is used.')
    }
    else {
        $request = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Definition.Uri)
        $request.Method = 'HEAD'
        $request.AllowAutoRedirect = $false
        $request.KeepAlive = $false
        $request.Timeout = $Timeout * 1000
        $request.ReadWriteTimeout = $Timeout * 1000
        $request.UserAgent = 'MDE-Arc-DoD-Connectivity/{0}' -f $scriptVersion
        if ($Proxy) { $request.Proxy = New-Object System.Net.WebProxy($Proxy) } else { $request.Proxy = $null }

        $response = $null
        $webStatus = ''
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $response = [System.Net.HttpWebResponse]$request.GetResponse()
        }
        catch {
            $webException = Find-WebException -Exception $_.Exception
            if ($null -ne $webException) {
                $webStatus = [string]$webException.Status
                if ($null -ne $webException.Response) {
                    $response = [System.Net.HttpWebResponse]$webException.Response
                }
                else {
                    $httpErrorNote = 'HTTP: {0} ({1}).' -f (Get-InnermostMessage -Exception $webException), $webStatus
                }
            }
            else {
                $httpErrorNote = 'HTTP: {0}' -f (Get-InnermostMessage -Exception $_.Exception)
            }
        }
        $watch.Stop()
        $elapsed = [string]$watch.ElapsedMilliseconds
        $receivedUtc = [DateTime]::UtcNow

        if ($null -ne $response) {
            try {
                $code = [int]$response.StatusCode
                $httpCode = [string]$code
                $server = [string]$response.Headers['Server']
                $dateHeader = [string]$response.Headers['Date']
                if ($dateHeader) {
                    $parsedDate = [DateTime]::MinValue
                    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
                    if ([DateTime]::TryParse($dateHeader, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsedDate)) {
                        $skew = ($receivedUtc - $parsedDate).TotalSeconds
                    }
                }

                $proxyBlock = [bool]$Proxy -and ($code -in @(403, 502, 503, 504)) -and ($server -match $proxyProductPattern)
                if ($code -eq 407) {
                    $notes.Add('HTTP 407: the proxy requires authentication. Arc and MDE run as SYSTEM and need an unauthenticated allow rule.')
                }
                elseif ($proxyBlock) {
                    $notes.Add(('HTTP {0} was generated by proxy product {1}. The proxy blocked the request.' -f $code, $server))
                }
                elseif ($code -ge 500 -and $server -match '(?i)microsoft|azure') {
                    $httpStatus = 'PASS'
                    $notes.Add(('HTTP {0} came from the Microsoft service ({1}), not a proxy, which proves the network path works.' -f $code, $server))
                }
                elseif ($code -ge 500) {
                    $httpStatus = 'WARN'
                    $notes.Add(('HTTP {0} from server {1}. Transport worked; confirm a proxy did not generate this response.' -f $code, $server))
                }
                else {
                    $httpStatus = 'PASS'
                    if ($code -ge 400) { $notes.Add(('HTTP {0}: the service rejected the anonymous request, which proves the network path works.' -f $code)) }
                }
            }
            finally {
                $response.Close()
            }
        }

        if ($Definition.Port -eq 443) {
            $tlsStatus = 'FAIL'
            if ($webStatus -eq 'TrustFailure') {
                $notes.Add('TLS: the certificate chain is not trusted. Check TLS inspection, missing roots, or blocked revocation endpoints.')
            }
            elseif ($webStatus -eq 'SecureChannelFailure') {
                $notes.Add('TLS: the TLS 1.2 handshake failed. Check SCHANNEL protocol and cipher policy or TLS inspection.')
            }

            try { $serverCertificate = $request.ServicePoint.Certificate } catch { $null = $_ }
            if ($null -ne $serverCertificate) {
                $leaf = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($serverCertificate)
                $issuer = $leaf.Issuer
                $expiry = $leaf.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd')
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                [void]$chain.Build($leaf)
                if ($chain.ChainElements.Count -gt 0) { $rootName = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Subject }
                $chain.Reset()
                $inspection = ($rootName -ne '') -and ($rootName -notmatch $publicRootPattern)
                if ($null -ne $response -and $webStatus -notin @('TrustFailure', 'SecureChannelFailure')) {
                    $tlsStatus = if ($inspection) { 'WARN' } else { 'PASS' }
                }
                if ($leaf.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow) {
                    $tlsStatus = 'FAIL'
                    $notes.Add('TLS: the presented certificate is expired.')
                }
                if ($inspection) {
                    $notes.Add(('TLS: root {0} is not a public Microsoft or DigiCert root. TLS inspection is likely.' -f $rootName))
                }
            }
            elseif ($null -ne $response -and $webStatus -eq '') {
                $tlsStatus = 'PASS'
            }
        }

        # Some services, such as WNS, close an anonymous request after a valid TLS handshake.
        $handshakeCompleted = ($Definition.Port -eq 443) -and ($null -ne $serverCertificate) -and -not $inspection -and
            ($webStatus -in @('ConnectionClosed', 'ReceiveFailure', 'KeepAliveFailure', 'PipelineFailure'))
        if ($null -eq $response -and $handshakeCompleted) {
            $httpStatus = 'PASS'
            $tlsStatus = 'PASS'
            $notes.Add('The TLS handshake completed with a trusted certificate, then the service closed the anonymous request. The network path works.')
        }
        elseif ($httpErrorNote) {
            $notes.Add($httpErrorNote)
        }
    }

    $status = 'PASS'
    if ($httpStatus -eq 'FAIL' -or $tlsStatus -eq 'FAIL') {
        $status = 'FAIL'
    }
    elseif ($inspection -and $Definition.Route -eq 'MDE') {
        $status = 'FAIL'
        $notes.Add('MDE traffic must not be inspected or intercepted. Add a TLS inspection bypass for this destination.')
    }
    elseif ($httpStatus -eq 'WARN' -or $tlsStatus -eq 'WARN') {
        $status = 'WARN'
    }

    # Direct TCP is diagnostic only, so it runs only when the real path failed.
    $tcpText = 'Not needed'
    if ($status -eq 'FAIL') {
        if ($dnsStatus -eq 'PASS') {
            $tcp = Test-TcpPort -HostName $Definition.HostName -Port $Definition.Port -Timeout ([Math]::Min($Timeout, 3))
            $tcpText = $tcp.Status
            if ($tcp.Status -eq 'FAIL') { $notes.Add(('Direct TCP: {0}' -f $tcp.Detail)) }
        }
        else {
            $tcpText = 'Skipped'
        }
    }

    if ($status -eq 'PASS' -and $notes.Count -eq 0) { $notes.Add('DNS, HTTP, and TLS succeeded.') }

    return [pscustomobject]@{
        Area             = $Definition.Area
        UsedBy           = $Definition.UsedBy
        Level            = $Definition.Level
        Rule             = $Definition.Rule
        Purpose          = $Definition.Purpose
        HostName         = $Definition.HostName
        Target           = ('{0}:{1}' -f $Definition.HostName, $Definition.Port)
        PathText         = $pathText
        Dns              = $dnsStatus
        Addresses        = $addressText
        HttpCode         = $httpCode
        Tls              = $tlsStatus
        Issuer           = $issuer
        Root             = $rootName
        Expiry           = $expiry
        Tcp              = $tcpText
        Milliseconds     = $elapsed
        Status           = $status
        Detail           = ($notes -join ' ')
        ClockSkewSeconds = $skew
    }
}

#region Local discovery

$osInfo = $null
try { $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { $null = $_ }
$osCaption = if ($null -ne $osInfo) { [string]$osInfo.Caption } else { 'Unknown' }
$osBuild = if ($null -ne $osInfo) { [int]$osInfo.BuildNumber } else { 0 }

# Proxy paths used by each agent.
$netshPath = Join-Path $env:SystemRoot 'System32\netsh.exe'
$winHttpRaw = (Invoke-NativeCommand -FilePath $netshPath -Arguments 'winhttp show proxy' -TimeoutSec 20).Output
$winHttpProxy = ''
if ($winHttpRaw -match '(?im)^\s*Proxy Server\(s\)\s*:\s*(\S.*)$') { $winHttpProxy = ConvertTo-ProxyUri -Value $Matches[1] }

$dataCollectionPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
$mdeTelemetryProxy = ConvertTo-ProxyUri -Value ([string](Get-RegistryValue -Path $dataCollectionPath -Name 'TelemetryProxyServer'))
$disableEnterpriseAuthProxy = Get-RegistryValue -Path $dataCollectionPath -Name 'DisableEnterpriseAuthProxy'

$arcAgentPath = Join-Path $env:ProgramFiles 'AzureConnectedMachineAgent\azcmagent.exe'
$arcInstalled = Test-Path -LiteralPath $arcAgentPath -PathType Leaf
$arcAgentVersion = ''
$arcShow = $null
$arcConfig = $null
$arcShowMap = @{}
$arcProxy = ''
$arcBypass = ''

if ($arcInstalled) {
    try { $arcAgentVersion = (Get-Item -LiteralPath $arcAgentPath).VersionInfo.ProductVersion } catch { $null = $_ }
    $arcShow = Invoke-NativeCommand -FilePath $arcAgentPath -Arguments 'show' -TimeoutSec 45
    foreach ($line in ($arcShow.Output -split "`r?`n")) {
        if ($line -match '^\s*([A-Za-z][^:]{1,60}?)\s*:\s+(.*)$') {
            $key = $Matches[1].Trim()
            if (-not $arcShowMap.ContainsKey($key)) { $arcShowMap[$key] = $Matches[2].Trim() }
        }
    }
    $arcConfig = Invoke-NativeCommand -FilePath $arcAgentPath -Arguments 'config list' -TimeoutSec 30
    if ($arcConfig.Output -match '(?im)^\s*proxy\.url\s*:\s*(\S*)\s*$') { $arcProxy = ConvertTo-ProxyUri -Value $Matches[1] }
    if ($arcConfig.Output -match '(?im)^\s*proxy\.bypass\s*:\s*(.+)$') { $arcBypass = $Matches[1].Trim() }
    if (-not $arcProxy -and $arcShowMap.ContainsKey('Using HTTPS Proxy') -and $arcShowMap['Using HTTPS Proxy'] -match '://') {
        $arcProxy = ConvertTo-ProxyUri -Value $arcShowMap['Using HTTPS Proxy']
    }
}
if (-not $arcProxy) {
    $machineProxy = [Environment]::GetEnvironmentVariable('HTTPS_PROXY', 'Machine')
    if ($machineProxy) { $arcProxy = ConvertTo-ProxyUri -Value $machineProxy }
}

function Get-ArcShowValue {
    param([string]$Name)
    if ($arcShowMap.ContainsKey($Name)) { return [string]$arcShowMap[$Name] }
    return ''
}

$effectiveLocation = $ArcLocation
$connectedLocation = Get-ArcShowValue -Name 'Location'
if (-not $PSBoundParameters.ContainsKey('ArcLocation') -and $connectedLocation -match '^[a-z0-9]+$') {
    $effectiveLocation = $connectedLocation
}
$hisRegionCodes = @{ usgovvirginia = 'usgv'; usgovarizona = 'usga' }

# MDE onboarding evidence.
$atpStatusPath = 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status'
$onboardingState = Get-RegistryValue -Path $atpStatusPath -Name 'OnboardingState'
$orgId = [string](Get-RegistryValue -Path $atpStatusPath -Name 'OrgId')
$onboardingInfo = [string](Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection' -Name 'OnboardingInfo')

$senseEvents = @()
$senseEventNote = ''
try {
    $senseFilter = @{ LogName = 'Microsoft-Windows-SENSE/Operational'; Level = @(1, 2, 3); StartTime = (Get-Date).AddDays(-3) }
    $senseEvents = @(Get-WinEvent -FilterHashtable $senseFilter -MaxEvents 300 -ErrorAction Stop)
}
catch {
    $senseEventNote = if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { 'No SENSE warnings or errors in the last 3 days.' } else { Get-InnermostMessage -Exception $_.Exception }
}

$mdeHostPattern = '(?i)\b(?:[a-z0-9-]+\.)+(?:microsoft\.us|usgovcloudapi\.net)\b|\bwinatp-gw-[a-z0-9]+\.microsoft\.com\b|\b[a-z0-9-]+\.events\.data\.microsoft\.com\b'
$mdeEvidenceText = @($onboardingInfo) + @($senseEvents | ForEach-Object { [string]$_.Message })
$observedMdeHosts = @(Get-ObservedHostName -Text $mdeEvidenceText -Pattern $mdeHostPattern -Max 15)
$observedMdeText = $observedMdeHosts -join ' '

$detectedMdeMode = 'Not detected'
if ($onboardingInfo -match '(?i)endpoint\.security\.microsoft' -or $observedMdeText -match '(?i)endpoint\.security\.microsoft') {
    $detectedMdeMode = 'Streamlined'
}
elseif ($observedMdeText -match '(?i)winatp-gw-') {
    $detectedMdeMode = 'Standard'
}
$effectiveMdeMode = if ($MdeConnectivity -ne 'Auto') { $MdeConnectivity } elseif ($detectedMdeMode -eq 'Not detected') { 'Both' } else { $detectedMdeMode }
$standardLevel = if ($effectiveMdeMode -eq 'Streamlined') { 'Conditional' } else { 'Required' }
$streamlinedLevel = if ($effectiveMdeMode -eq 'Standard') { 'Conditional' } else { 'Required' }

# Arc logs reveal the concrete government Blob accounts used for extension downloads.
$arcLogFiles = New-Object System.Collections.Generic.List[string]
foreach ($candidate in @(
        (Join-Path $env:ProgramData 'AzureConnectedMachineAgent\Log\himds.log'),
        (Join-Path $env:ProgramData 'AzureConnectedMachineAgent\Log\azcmagent.log'),
        (Join-Path $env:ProgramData 'GuestConfig\ext_mgr_logs\gc_ext.log'),
        (Join-Path $env:ProgramData 'GuestConfig\arc_policy_logs\gc_agent.log'))) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $arcLogFiles.Add($candidate) }
}
$extensionLogRoot = Join-Path $env:ProgramData 'GuestConfig\extension_logs'
if (Test-Path -LiteralPath $extensionLogRoot -PathType Container) {
    Get-ChildItem -LiteralPath $extensionLogRoot -Recurse -Depth 2 -File -Filter '*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 15 |
        ForEach-Object { $arcLogFiles.Add($_.FullName) }
}
$arcLogTails = [ordered]@{}
foreach ($file in $arcLogFiles) { $arcLogTails[$file] = Get-FileTail -Path $file -MaxLines 4000 }
$blobPattern = '(?i)\b[a-z0-9]{3,24}\.blob\.core\.usgovcloudapi\.net\b'
$observedBlobHosts = @(Get-ObservedHostName -Text ([string[]]@($arcLogTails.Values)) -Pattern $blobPattern -Max 15)

#endregion

#region Endpoint catalog

$arcSource = 'Azure Arc'
$mdeArea = 'Defender for Endpoint'
$certArea = 'Certificate validation'

# Azure Arc, Azure Government table.
Add-Endpoint -HostName 'download.microsoft.com' -Rule 'download.microsoft.com' -Area $arcSource -UsedBy 'Azure Arc' -Purpose 'Windows agent installation package and automatic agent upgrades.' -Level 'Required' -Route 'Arc'
Add-Endpoint -HostName 'login.microsoftonline.us' -Rule 'login.microsoftonline.us' -Area $arcSource -UsedBy 'Azure Arc' -Purpose 'Microsoft Entra ID token endpoint for the agent.' -Level 'Required' -Route 'Arc'
Add-Endpoint -HostName 'pasff.usgovcloudapi.net' -Rule 'pasff.usgovcloudapi.net' -Area $arcSource -UsedBy 'Azure Arc' -Purpose 'Microsoft Entra ID.' -Level 'Required' -Route 'Arc'
Add-Endpoint -HostName 'management.usgovcloudapi.net' -Rule 'management.usgovcloudapi.net' -Area $arcSource -UsedBy 'Azure Arc' -Purpose 'Azure Resource Manager creates or deletes the Arc resource when you connect or disconnect.' -Level 'Required' -Route 'Arc'
Add-Endpoint -HostName 'gbl.his.arc.azure.us' -Rule '*.his.arc.azure.us' -Area $arcSource -UsedBy 'Azure Arc' -Purpose 'Global hybrid identity and metadata service.' -Level 'Required' -Route 'Arc'
if ($hisRegionCodes.ContainsKey($effectiveLocation)) {
    Add-Endpoint -HostName ('{0}.his.arc.azure.us' -f $hisRegionCodes[$effectiveLocation]) -Rule '*.his.arc.azure.us' -Area $arcSource -UsedBy 'Azure Arc' -Purpose ('Regional hybrid identity service for {0}.' -f $effectiveLocation) -Level 'Required' -Route 'Arc'
}
Add-Endpoint -HostName 'agentserviceapi.guestconfiguration.azure.us' -Rule '*.guestconfiguration.azure.us' -Area $arcSource -UsedBy 'Azure Arc' -Purpose 'Extension management and guest configuration service.' -Level 'Required' -Route 'Arc'
Add-Endpoint -HostName ('{0}-gas.guestconfiguration.azure.us' -f $effectiveLocation) -Rule '*.guestconfiguration.azure.us' -Area $arcSource -UsedBy 'Azure Arc' -Purpose ('Regional guest assignment service that delivers extensions such as MDE.Windows in {0}.' -f $effectiveLocation) -Level 'Required' -Route 'Arc'
foreach ($blobHost in $observedBlobHosts) {
    Add-Endpoint -HostName $blobHost -Rule '*.blob.core.usgovcloudapi.net' -Area $arcSource -UsedBy 'Azure Arc extensions' -Purpose 'Extension package storage observed in local Arc logs.' -Level 'Required' -Route 'Arc'
}
Add-Endpoint -HostName 'www.microsoft.com' -Port 443 -Path '/pkiops/certs' -Rule 'www.microsoft.com/pkiops/certs' -Area $arcSource -UsedBy 'Azure Arc ESU' -Purpose 'Intermediate certificates for Extended Security Updates enabled by Azure Arc.' -Level 'Conditional' -Route 'Arc'
Add-Endpoint -HostName 'dc.applicationinsights.us' -Rule 'dc.applicationinsights.us' -Area $arcSource -UsedBy 'Azure Arc' -Purpose 'Agent telemetry for agent versions earlier than 1.24 only.' -Level 'Optional' -Route 'Arc'

# Defender for Endpoint DoD, streamlined and common.
Add-Endpoint -HostName 'unitedstates2.ss.wd.microsoft.us' -Rule 'unitedstates2.ss.wd.microsoft.us' -Area $mdeArea -UsedBy 'MDE' -Purpose 'DoD SmartScreen, Network Protection, and custom URL indicators.' -Level 'Required' -Route 'MDE'
Add-Endpoint -HostName 'login.microsoftonline.us' -Rule 'login.microsoftonline.us' -Area $mdeArea -UsedBy 'MDE Live Response' -Purpose 'Live Response notification sign in.' -Level 'Required' -Route 'MDE'
Add-Endpoint -HostName 'login.live.com' -Rule 'login.live.com' -Area $mdeArea -UsedBy 'MDE Live Response' -Purpose 'Windows Push Notification Services for Live Response. Direct connection or proxy bypass required.' -Level 'Required' -Route 'MDE'
Add-Endpoint -HostName 'client.wns.windows.com' -Rule '*.wns.windows.com' -Area $mdeArea -UsedBy 'MDE Live Response' -Purpose 'Windows Push Notification Services for Live Response. Direct connection or proxy bypass required.' -Level 'Required' -Route 'MDE'
foreach ($mdeHost in $observedMdeHosts) {
    Add-Endpoint -HostName $mdeHost -Rule $mdeHost -Area $mdeArea -UsedBy 'MDE observed' -Purpose 'Observed in local MDE onboarding data or SENSE events.' -Level 'Required' -Route 'MDE'
}

# Defender for Endpoint DoD, standard connectivity.
$standardPurpose = if ($standardLevel -eq 'Required') { 'Standard connectivity.' } else { 'Standard connectivity; not needed after streamlined onboarding.' }
Add-Endpoint -HostName 'winatp-gw-usgt.microsoft.com' -Rule 'winatp-gw-usgt.microsoft.com' -Area $mdeArea -UsedBy 'MDE standard' -Purpose ('EDR command and control. ' + $standardPurpose) -Level $standardLevel -Route 'MDE'
Add-Endpoint -HostName 'winatp-gw-usgv.microsoft.com' -Rule 'winatp-gw-usgv.microsoft.com' -Area $mdeArea -UsedBy 'MDE standard' -Purpose ('EDR command and control. ' + $standardPurpose) -Level $standardLevel -Route 'MDE'
Add-Endpoint -HostName 'us4-v20.events.data.microsoft.com' -Rule 'us4-v20.events.data.microsoft.com' -Area $mdeArea -UsedBy 'MDE standard' -Purpose ('EDR cyber data. ' + $standardPurpose) -Level $standardLevel -Route 'MDE'
Add-Endpoint -HostName 'events.data.microsoft.com' -Rule 'events.data.microsoft.com' -Area $mdeArea -UsedBy 'MDE standard' -Purpose ('Connected User Experiences and Telemetry. ' + $standardPurpose) -Level $standardLevel -Route 'MDE'
Add-Endpoint -HostName 'unitedstates2.x.cp.wd.microsoft.us' -Rule 'unitedstates2.x.cp.wd.microsoft.us' -Area $mdeArea -UsedBy 'MDE standard' -Purpose ('Cloud delivered protection and security intelligence. ' + $standardPurpose) -Level $standardLevel -Route 'MDE'
Add-Endpoint -HostName 'unitedstates2.cp.wd.microsoft.us' -Rule 'unitedstates2.cp.wd.microsoft.us' -Area $mdeArea -UsedBy 'MDE standard' -Purpose ('Defender Antivirus MAPS cloud protection. ' + $standardPurpose) -Level $standardLevel -Route 'MDE'
foreach ($storageHost in @('automatedirstrffusgt', 'automatedirstrffusgv')) {
    Add-Endpoint -HostName ('{0}.blob.core.usgovcloudapi.net' -f $storageHost) -Rule ('{0}.blob.core.usgovcloudapi.net' -f $storageHost) -Area $mdeArea -UsedBy 'MDE standard' -Purpose ('Automated investigation sample storage. ' + $standardPurpose) -Level $standardLevel -Route 'MDE'
}
foreach ($storageHost in @('ussusd1centralff5', 'ussusd2centralff5', 'wsusd1centralff5', 'ussusd1eastff5', 'ussusd2eastff5', 'wsusd1eastff5')) {
    Add-Endpoint -HostName ('{0}.blob.core.usgovcloudapi.net' -f $storageHost) -Rule ('{0}.blob.core.usgovcloudapi.net' -f $storageHost) -Area $mdeArea -UsedBy 'MDE standard' -Purpose ('Malware sample submission storage. ' + $standardPurpose) -Level $standardLevel -Route 'MDE'
}
Add-Endpoint -HostName 'login.microsoftonline.com' -Rule 'login.microsoftonline.com' -Area $mdeArea -UsedBy 'MDE Live Response standard' -Purpose ('Live Response notification sign in listed for standard connectivity. ' + $standardPurpose) -Level $standardLevel -Route 'MDE'
Add-Endpoint -HostName 'onboardingpckgsusgvprd.blob.core.usgovcloudapi.net' -Rule 'onboardingpckgsusgvprd.blob.core.usgovcloudapi.net' -Area $mdeArea -UsedBy 'MDE portal' -Purpose 'DoD onboarding package storage used when downloading packages from the Defender portal.' -Level 'Conditional' -Route 'MDE'
Add-Endpoint -HostName 'settings-win.data.microsoft.com' -Rule 'settings-win.data.microsoft.com' -Area $mdeArea -UsedBy 'MDE' -Purpose 'Telemetry settings channel. Not required on Windows Server 2019 and later.' -Level 'Optional' -Route 'MDE'

# Certificate validation used by Windows for every TLS connection above.
Add-Endpoint -HostName 'crl.microsoft.com' -Port 80 -Path '/pki/crl/' -Rule 'crl.microsoft.com/pki/crl/*' -Area $certArea -UsedBy 'MDE; Windows' -Purpose 'Microsoft certificate revocation lists.' -Level 'Required' -Route 'Cert'
Add-Endpoint -HostName 'ctldl.windowsupdate.com' -Port 80 -Path '/msdownload/update/v3/static/trustedr/en/authrootstl.cab' -Rule 'ctldl.windowsupdate.com' -Area $certArea -UsedBy 'MDE; Windows' -Purpose 'Automatic root and disallowed certificate trust list updates.' -Level 'Required' -Route 'Cert'
Add-Endpoint -HostName 'www.microsoft.com' -Port 80 -Path '/pkiops/certs/' -Rule 'www.microsoft.com/pkiops/*; www.microsoft.com/pki/certs' -Area $certArea -UsedBy 'MDE; Azure Arc ESU' -Purpose 'Microsoft PKI certificates and revocation used when validating service certificates.' -Level 'Required' -Route 'Cert'
foreach ($caHost in @('cacerts.digicert.com', 'cacerts.geotrust.com', 'caissuers.microsoft.com', 'crl3.digicert.com', 'crl4.digicert.com', 'ocsp.digicert.com', 'oneocsp.microsoft.com')) {
    Add-Endpoint -HostName $caHost -Port 80 -Rule $caHost -Area $certArea -UsedBy 'Azure services' -Purpose 'Azure certificate authority AIA, CRL, or OCSP lookups for Azure Government service certificates.' -Level 'Recommended' -Route 'Cert'
}

# Defender Antivirus updates are optional when WSUS, Configuration Manager, or a file share supplies updates.
Add-Endpoint -HostName 'fe3cr.delivery.mp.microsoft.com' -Path '/ClientWebService/client.asmx' -Rule '*.delivery.mp.microsoft.com' -Area 'Defender Antivirus updates' -UsedBy 'Defender Antivirus' -Purpose 'Security intelligence and platform updates from Microsoft Update.' -Level 'Optional' -Route 'Cert'

#endregion

#region Endpoint probes

$endpointResults = New-Object System.Collections.Generic.List[object]
$clockSamples = New-Object System.Collections.Generic.List[double]
foreach ($definition in $endpointDefinitions) {
    $routeProxy = Get-RouteProxy -Definition $definition
    $probe = Invoke-EndpointProbe -Definition $definition -Proxy $routeProxy -Timeout $TimeoutSeconds
    if ($null -ne $probe.ClockSkewSeconds) { $clockSamples.Add([double]$probe.ClockSkewSeconds) }
    $endpointResults.Add($probe)
}

function Get-EndpointResult {
    param([string]$HostName, [int]$Port)
    foreach ($item in $endpointResults) { if ($item.Target -eq ('{0}:{1}' -f $HostName, $Port)) { return $item } }
    return $null
}

#endregion

#region Wildcard rule coverage

$wildcardRules = @(
    [pscustomobject]@{ Rule = '*.endpoint.security.microsoft.us:443'; Suffix = '.endpoint.security.microsoft.us'; Level = $streamlinedLevel; UsedBy = 'MDE streamlined'; Note = 'Consolidated MDE service URL. Exclude from TLS inspection. Hostnames are assigned at runtime, so validate with MDE Client Analyzer using the DoD onboarding package when no observed host was tested.' }
    [pscustomobject]@{ Rule = '*.his.arc.azure.us:443'; Suffix = '.his.arc.azure.us'; Level = 'Required'; UsedBy = 'Azure Arc'; Note = 'Hybrid identity and metadata services. Private Link capable.' }
    [pscustomobject]@{ Rule = '*.guestconfiguration.azure.us:443'; Suffix = '.guestconfiguration.azure.us'; Level = 'Required'; UsedBy = 'Azure Arc'; Note = 'Extension management and guest configuration. Private Link capable.' }
    [pscustomobject]@{ Rule = '*.blob.core.usgovcloudapi.net:443'; Suffix = '.blob.core.usgovcloudapi.net'; Level = 'Required'; UsedBy = 'Azure Arc extensions; MDE storage; Live Response file transfer'; Note = 'Required unless Arc Private Link is used. Passing specific accounts does not prove the full wildcard is allowed.' }
    [pscustomobject]@{ Rule = '*.wns.windows.com:443'; Suffix = '.wns.windows.com'; Level = 'Required'; UsedBy = 'MDE Live Response'; Note = 'Live Response notifications. Direct connection or proxy bypass required.' }
    [pscustomobject]@{ Rule = ('*.{0}.arcdataservices.azure.us:443' -f $effectiveLocation); Suffix = ('.{0}.arcdataservices.azure.us' -f $effectiveLocation); Level = 'Conditional'; UsedBy = 'SQL Server enabled by Azure Arc'; Note = 'Only when the SQL Server extension is used. TLS 1.2 or 1.3 only.' }
    [pscustomobject]@{ Rule = '*.update.microsoft.com; *.delivery.mp.microsoft.com; *.windowsupdate.com; *.download.windowsupdate.com; *.download.microsoft.com; *.definitionupdates.microsoft.com'; Suffix = '.delivery.mp.microsoft.com'; Level = 'Optional'; UsedBy = 'Defender Antivirus updates'; Note = 'Optional when WSUS, Configuration Manager, or a file share supplies updates.' }
)

$wildcardResults = foreach ($wildcard in $wildcardRules) {
    $covered = @($endpointResults | Where-Object { $_.HostName.EndsWith($wildcard.Suffix) })
    $failed = @($covered | Where-Object { $_.Status -eq 'FAIL' })
    $warned = @($covered | Where-Object { $_.Status -eq 'WARN' })
    if ($covered.Count -eq 0) {
        $wildcardStatus = 'REVIEW'
        $coverage = 'No concrete host available to test from this server.'
    }
    else {
        $wildcardStatus = if ($failed.Count -gt 0) { if ($wildcard.Level -eq 'Required') { 'FAIL' } else { 'WARN' } } elseif ($warned.Count -gt 0) { 'WARN' } else { 'PASS' }
        $coverage = '{0} of {1} tested hosts passed: {2}' -f ($covered.Count - $failed.Count), $covered.Count, (($covered | ForEach-Object { $_.HostName }) -join ', ')
    }
    if ($wildcard.Level -ne 'Required' -and $wildcardStatus -eq 'REVIEW') { $wildcardStatus = 'INFO' }
    [pscustomobject]@{ Rule = $wildcard.Rule; Level = $wildcard.Level; UsedBy = $wildcard.UsedBy; Status = $wildcardStatus; Coverage = $coverage; Note = $wildcard.Note }
}

#endregion

#region Azure Arc agent checks

$arcCheck = $null
$arcCheckHeaders = @()
$arcCheckRows = New-Object System.Collections.Generic.List[object]
$arcCheckStatus = 'INFO'
$arcCheckDetail = 'The Azure Connected Machine agent is not installed. The endpoint table still validates the Arc network path before installation.'

if ($arcInstalled) {
    Add-LocalCheck -Area 'Azure Arc' -Check 'Connected Machine agent installed' -Status 'PASS' -Detail ('Version {0} at {1}.' -f $arcAgentVersion, $arcAgentPath)

    $agentStatus = Get-ArcShowValue -Name 'Agent Status'
    $agentCloud = Get-ArcShowValue -Name 'Cloud'
    $agentErrorCode = Get-ArcShowValue -Name 'Agent Error Code'
    $agentErrorDetail = Get-ArcShowValue -Name 'Agent Error Details'
    $lastHeartbeat = Get-ArcShowValue -Name 'Agent Last Heartbeat'

    if ($agentStatus -match '(?i)^connected') {
        Add-LocalCheck -Area 'Azure Arc' -Check 'Agent status' -Status 'PASS' -Detail ('Connected. Resource {0} in {1}. Last heartbeat {2}.' -f (Get-ArcShowValue -Name 'Resource Name'), $connectedLocation, $lastHeartbeat)
    }
    elseif ($agentStatus -match '(?i)disconnected|expired') {
        Add-LocalCheck -Area 'Azure Arc' -Check 'Agent status' -Status 'FAIL' -Detail ('Agent status is {0}. Last heartbeat {1}. Restore connectivity to the required Arc endpoints; an agent disconnected for 45 days expires and must be reconnected.' -f $agentStatus, $lastHeartbeat)
    }
    else {
        Add-LocalCheck -Area 'Azure Arc' -Check 'Agent status' -Status 'INFO' -Detail ('Agent status is {0}. The server is installed but not yet connected.' -f $(if ($agentStatus) { $agentStatus } else { 'not reported' }))
    }

    if ($agentStatus -match '(?i)connected' -and $agentCloud -and $agentCloud -ne 'AzureUSGovernment') {
        Add-LocalCheck -Area 'Azure Arc' -Check 'Agent cloud' -Status 'FAIL' -Detail ('The agent is connected to {0}. DoD servers must connect to AzureUSGovernment.' -f $agentCloud)
    }
    elseif ($agentCloud) {
        Add-LocalCheck -Area 'Azure Arc' -Check 'Agent cloud' -Status 'PASS' -Detail $agentCloud
    }

    if ($agentErrorCode) {
        Add-LocalCheck -Area 'Azure Arc' -Check 'Agent error' -Status 'FAIL' -Detail ('{0}: {1}' -f $agentErrorCode, $agentErrorDetail)
    }

    foreach ($serviceName in @('himds', 'GCArcService', 'ExtensionService')) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            $serviceStatus = if ($service.Status -eq 'Running') { 'PASS' } else { 'FAIL' }
            Add-LocalCheck -Area 'Azure Arc' -Check ('Service {0}' -f $serviceName) -Status $serviceStatus -Detail ('{0}, start type {1}. {2}' -f $service.Status, $service.StartType, $service.DisplayName)
        }
        catch {
            Add-LocalCheck -Area 'Azure Arc' -Check ('Service {0}' -f $serviceName) -Status 'FAIL' -Detail 'Service not found. Reinstall or repair the Connected Machine agent.'
        }
    }

    $arcCheck = Invoke-NativeCommand -FilePath $arcAgentPath -Arguments ('check --cloud AzureUSGovernment --location {0}' -f $effectiveLocation) -TimeoutSec 150
    foreach ($line in ($arcCheck.Output -split "`r?`n")) {
        if ($line -notmatch '^\s*\|') { continue }
        $cells = @($line.Trim().Trim('|').Split('|') | ForEach-Object { $_.Trim() })
        if ($arcCheckHeaders.Count -eq 0 -and (($cells -join ' ') -match '(?i)reachable')) {
            $arcCheckHeaders = $cells
            continue
        }
        if ($arcCheckHeaders.Count -gt 0 -and $cells.Count -eq $arcCheckHeaders.Count -and $cells[0]) {
            $arcCheckRows.Add($cells)
        }
    }

    $reachableIndex = -1
    for ($index = 0; $index -lt $arcCheckHeaders.Count; $index++) {
        if ($arcCheckHeaders[$index] -match '(?i)reachable') { $reachableIndex = $index; break }
    }
    $unreachable = @()
    if ($reachableIndex -ge 0) {
        $unreachable = @($arcCheckRows | Where-Object { $_[$reachableIndex] -match '(?i)^false$' } | ForEach-Object { $_[0] })
    }

    if ($arcCheck.TimedOut) {
        $arcCheckStatus = 'WARN'
        $arcCheckDetail = 'azcmagent check timed out. Rerun with a longer Live Response window.'
    }
    elseif ($unreachable.Count -gt 0) {
        $arcCheckStatus = 'FAIL'
        $arcCheckDetail = 'Unreachable: {0}' -f ($unreachable -join ', ')
    }
    elseif ($arcCheckRows.Count -gt 0) {
        $arcCheckStatus = 'PASS'
        $arcCheckDetail = '{0} endpoints reported reachable by the agent.' -f $arcCheckRows.Count
    }
    elseif ($arcCheck.ExitCode -eq 0) {
        $arcCheckStatus = 'REVIEW'
        $arcCheckDetail = 'The command completed but its table could not be parsed. Review the raw output.'
    }
    else {
        $arcCheckStatus = 'FAIL'
        $arcCheckDetail = 'azcmagent check failed with exit code {0}.' -f $arcCheck.ExitCode
    }
}
else {
    Add-LocalCheck -Area 'Azure Arc' -Check 'Connected Machine agent installed' -Status 'INFO' -Detail 'Not installed. Endpoint results below validate the network before installation.'
}

# Arc extensions, including the MDE.Windows extension pushed by Defender for Servers.
$mdeExtensionName = 'Microsoft.Azure.AzureDefenderForServers.MDE.Windows'
$pluginRoot = Join-Path $env:SystemDrive 'Packages\Plugins'
$extensionRows = New-Object System.Collections.Generic.List[object]
if (Test-Path -LiteralPath $pluginRoot -PathType Container) {
    foreach ($extensionDirectory in (Get-ChildItem -LiteralPath $pluginRoot -Directory -ErrorAction SilentlyContinue | Select-Object -First 25)) {
        $versionDirectory = Get-ChildItem -LiteralPath $extensionDirectory.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $extensionState = 'Unknown'
        $extensionMessage = 'No status file found.'
        $extensionVersion = ''
        if ($null -ne $versionDirectory) {
            $extensionVersion = $versionDirectory.Name
            $statusDirectory = Join-Path $versionDirectory.FullName 'Status'
            $statusFile = Get-ChildItem -LiteralPath $statusDirectory -Filter '*.status' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($null -ne $statusFile) {
                try {
                    $statusJson = @(Get-Content -LiteralPath $statusFile.FullName -Raw | ConvertFrom-Json)[0]
                    $extensionState = [string](Get-ObjectProperty -InputObject $statusJson -Path @('status', 'status'))
                    $extensionMessage = [string](Get-ObjectProperty -InputObject $statusJson -Path @('status', 'formattedMessage', 'message'))
                    if ($extensionMessage.Length -gt 600) { $extensionMessage = $extensionMessage.Substring(0, 600) + ' ...' }
                }
                catch {
                    $extensionMessage = 'Unable to parse {0}: {1}' -f $statusFile.FullName, (Get-InnermostMessage -Exception $_.Exception)
                }
            }
        }
        $extensionRows.Add([pscustomobject]@{ Name = $extensionDirectory.Name; Version = $extensionVersion; State = $extensionState; Message = $extensionMessage })
    }
}

$arcConnected = (Get-ArcShowValue -Name 'Agent Status') -match '(?i)^connected'
$mdeExtension = $extensionRows | Where-Object { $_.Name -eq $mdeExtensionName } | Select-Object -First 1
if ($null -ne $mdeExtension) {
    $extensionStatus = switch -Regex ($mdeExtension.State) { '(?i)success' { 'PASS' } '(?i)error|fail' { 'FAIL' } default { 'WARN' } }
    Add-LocalCheck -Area 'Defender for Servers' -Check 'MDE.Windows extension' -Status $extensionStatus -Detail ('Version {0}, state {1}. {2}' -f $mdeExtension.Version, $mdeExtension.State, $mdeExtension.Message)
}
elseif ($arcConnected) {
    Add-LocalCheck -Area 'Defender for Servers' -Check 'MDE.Windows extension' -Status 'WARN' -Detail 'Arc is connected but the MDE.Windows extension is not present. Confirm the Defender for Servers plan and Endpoint protection integration are enabled for this subscription in Defender for Cloud, then allow time for deployment.'
}
else {
    Add-LocalCheck -Area 'Defender for Servers' -Check 'MDE.Windows extension' -Status 'INFO' -Detail 'Not present. Defender for Servers deploys it after the Arc agent connects.'
}

#endregion

#region Defender for Endpoint checks

$senseService = $null
try { $senseService = Get-Service -Name 'Sense' -ErrorAction Stop } catch { $null = $_ }
if ($null -ne $senseService) {
    $senseStatus = if ($senseService.Status -eq 'Running') { 'PASS' } elseif ([string]$onboardingState -eq '1' -or $null -ne $mdeExtension) { 'FAIL' } else { 'INFO' }
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'Sense service' -Status $senseStatus -Detail ('{0}, start type {1}.' -f $senseService.Status, $senseService.StartType)
}
else {
    $senseDetail = if ($osBuild -lt 17763) { 'Not installed. On Windows Server 2012 R2 and 2016 the MDE.Windows extension installs the modern unified solution.' } else { 'Sense service not found. It is built into Windows Server 2019 and later.' }
    $senseStatus = if ($osBuild -ge 17763) { 'FAIL' } else { 'INFO' }
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'Sense service' -Status $senseStatus -Detail $senseDetail
}

try {
    $defenderService = Get-Service -Name 'WinDefend' -ErrorAction Stop
    $defenderStatus = if ($defenderService.Status -eq 'Running') { 'PASS' } else { 'WARN' }
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'WinDefend service' -Status $defenderStatus -Detail ('{0}, start type {1}. Passive mode keeps this service running.' -f $defenderService.Status, $defenderService.StartType)
}
catch {
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'WinDefend service' -Status 'WARN' -Detail 'Microsoft Defender Antivirus service not found. Do not uninstall Defender Antivirus when another antivirus product is used; MDE needs it in passive mode.'
}

if ([string]$onboardingState -eq '1') {
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'Onboarding state' -Status 'PASS' -Detail ('Onboarded. OrgId {0}.' -f $orgId)
}
elseif ($null -ne $mdeExtension) {
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'Onboarding state' -Status 'FAIL' -Detail 'The MDE.Windows extension is present but the device is not onboarded. Review the extension status and logs below.'
}
else {
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'Onboarding state' -Status 'INFO' -Detail 'Not onboarded yet.'
}

Add-LocalCheck -Area 'Defender for Endpoint' -Check 'Connectivity method' -Status 'INFO' -Detail ('Detected {0}; evaluated as {1}. Use -MdeConnectivity Streamlined or Standard to override.' -f $detectedMdeMode, $effectiveMdeMode)

$legacyAgent = $null
try { $legacyAgent = Get-Service -Name 'HealthService' -ErrorAction Stop } catch { $null = $_ }
if ($null -ne $legacyAgent -and $osBuild -lt 17763) {
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'Legacy Microsoft Monitoring Agent' -Status 'WARN' -Detail 'HealthService is present on Windows Server 2012 R2 or 2016. MMA based MDE uses legacy URLs and does not support streamlined connectivity. Migrate to the modern unified solution.'
}

$mdeProxyDetail = if ($mdeTelemetryProxy) { 'TelemetryProxyServer is ' + (Hide-Credential -Text $mdeTelemetryProxy) } elseif ($winHttpProxy) { 'No TelemetryProxyServer policy; WinHTTP proxy ' + (Hide-Credential -Text $winHttpProxy) + ' is used.' } else { 'No MDE or WinHTTP proxy configured; MDE connects directly.' }
if ($null -ne $disableEnterpriseAuthProxy) { $mdeProxyDetail += ' DisableEnterpriseAuthProxy is {0}.' -f $disableEnterpriseAuthProxy }
Add-LocalCheck -Area 'Defender for Endpoint' -Check 'MDE proxy path' -Status 'INFO' -Detail $mdeProxyDetail

$mpStatusText = ''
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    $runningMode = [string](Get-ObjectProperty -InputObject $mpStatus -Path @('AMRunningMode'))
    $signatureAge = Get-ObjectProperty -InputObject $mpStatus -Path @('AntivirusSignatureAge')
    $mpStatusText = ($mpStatus | Select-Object AMRunningMode, AMProductVersion, AMEngineVersion, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, AntivirusSignatureAge, RealTimeProtectionEnabled, IsTamperProtected | Format-List | Out-String).Trim()
    $signatureStatus = if ($null -ne $signatureAge -and [int]$signatureAge -gt 7) { 'WARN' } else { 'PASS' }
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'Defender Antivirus' -Status $signatureStatus -Detail ('Running mode {0}, platform {1}, signature age {2} day(s).' -f $runningMode, (Get-ObjectProperty -InputObject $mpStatus -Path @('AMProductVersion')), $signatureAge)
}
catch {
    $mpStatusText = Get-InnermostMessage -Exception $_.Exception
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'Defender Antivirus' -Status 'WARN' -Detail ('Get-MpComputerStatus failed: {0}' -f $mpStatusText)
}

$senseRows = @()
if ($senseEvents.Count -gt 0) {
    $senseRows = @($senseEvents | Group-Object -Property Id | Sort-Object -Property Count -Descending | Select-Object -First 12 | ForEach-Object {
            $latest = $_.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
            $message = [string]$latest.Message
            if ($message.Length -gt 400) { $message = $message.Substring(0, 400) + ' ...' }
            [pscustomobject]@{ Id = $_.Name; Count = $_.Count; Level = $latest.LevelDisplayName; Latest = $latest.TimeCreated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ssZ'); Message = $message }
        })
    $senseErrorCount = @($senseEvents | Where-Object { $_.Level -le 2 }).Count
    $senseCheckStatus = if ($senseErrorCount -gt 0) { 'WARN' } else { 'PASS' }
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'SENSE events, last 3 days' -Status $senseCheckStatus -Detail ('{0} errors and {1} warnings. See the SENSE event summary.' -f $senseErrorCount, ($senseEvents.Count - $senseErrorCount))
}
else {
    Add-LocalCheck -Area 'Defender for Endpoint' -Check 'SENSE events, last 3 days' -Status 'PASS' -Detail $(if ($senseEventNote) { $senseEventNote } else { 'No warnings or errors.' })
}

#endregion

#region System checks

$osStatus = if ($osBuild -ge 9600) { 'PASS' } else { 'FAIL' }
$osDetail = '{0}, build {1}.' -f $osCaption, $osBuild
if ($osBuild -ge 9600 -and $osBuild -lt 17763) { $osDetail += ' Windows Server 2012 R2 and 2016 require the MDE modern unified solution, which the MDE.Windows extension installs.' }
Add-LocalCheck -Area 'System' -Check 'Operating system' -Status $osStatus -Detail $osDetail

$tlsClientPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
$tlsEnabled = Get-RegistryValue -Path $tlsClientPath -Name 'Enabled'
$tlsDisabledByDefault = Get-RegistryValue -Path $tlsClientPath -Name 'DisabledByDefault'
if (($null -ne $tlsEnabled -and [int]$tlsEnabled -eq 0) -or ($null -ne $tlsDisabledByDefault -and [int]$tlsDisabledByDefault -eq 1)) {
    Add-LocalCheck -Area 'System' -Check 'TLS 1.2 client' -Status 'FAIL' -Detail ('SCHANNEL disables TLS 1.2 client (Enabled {0}, DisabledByDefault {1}). Arc and MDE require TLS 1.2.' -f $tlsEnabled, $tlsDisabledByDefault)
}
else {
    Add-LocalCheck -Area 'System' -Check 'TLS 1.2 client' -Status 'PASS' -Detail 'TLS 1.2 client is not disabled in SCHANNEL.'
}

$strongCrypto64 = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto'
$strongCrypto32 = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto'
if ($osBuild -lt 17763 -and ([string]$strongCrypto64 -ne '1' -or [string]$strongCrypto32 -ne '1')) {
    Add-LocalCheck -Area 'System' -Check '.NET strong cryptography' -Status 'WARN' -Detail ('SchUseStrongCrypto is {0} (64 bit) and {1} (32 bit). On Windows Server 2012 R2 and 2016 set both to 1 so .NET onboarding scripts use TLS 1.2.' -f $strongCrypto64, $strongCrypto32)
}
else {
    Add-LocalCheck -Area 'System' -Check '.NET strong cryptography' -Status 'PASS' -Detail $(if ($osBuild -ge 17763) { 'Not required on this OS version.' } else { 'SchUseStrongCrypto 64 bit {0}, 32 bit {1}.' -f $strongCrypto64, $strongCrypto32 })
}

$netRelease = Get-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name 'Release'
$netStatus = if ($null -ne $netRelease -and [int]$netRelease -ge 393295) { 'PASS' } else { 'WARN' }
Add-LocalCheck -Area 'System' -Check '.NET Framework' -Status $netStatus -Detail ('Release {0}. Azure Arc onboarding requires .NET Framework 4.6 or later (release 393295).' -f $netRelease)

$fipsEnabled = Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name 'Enabled'
Add-LocalCheck -Area 'System' -Check 'FIPS mode' -Status 'INFO' -Detail ('FipsAlgorithmPolicy Enabled is {0}.' -f $(if ($null -eq $fipsEnabled) { 'not set' } else { $fipsEnabled }))

if ($clockSamples.Count -gt 0) {
    $sortedSkew = @($clockSamples | Sort-Object)
    $medianSkew = [Math]::Round($sortedSkew[[int][Math]::Floor($sortedSkew.Count / 2)], 1)
    $clockStatus = if ([Math]::Abs($medianSkew) -gt 300) { 'FAIL' } elseif ([Math]::Abs($medianSkew) -gt 60) { 'WARN' } else { 'PASS' }
    Add-LocalCheck -Area 'System' -Check 'Clock skew' -Status $clockStatus -Detail ('Median skew {0} seconds against {1} Microsoft HTTP Date headers. Token authentication fails beyond 5 minutes.' -f $medianSkew, $clockSamples.Count)
}
else {
    Add-LocalCheck -Area 'System' -Check 'Clock skew' -Status 'REVIEW' -Detail 'No HTTP Date header was received, so clock skew could not be measured.'
}
$timeSource = (Invoke-NativeCommand -FilePath (Join-Path $env:SystemRoot 'System32\w32tm.exe') -Arguments '/query /source' -TimeoutSec 15).Output
Add-LocalCheck -Area 'System' -Check 'Time source' -Status 'INFO' -Detail $timeSource

$rootAutoUpdateDisabled = [string](Get-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' -Name 'DisableRootAutoUpdate') -eq '1'
$ctlResult = Get-EndpointResult -HostName 'ctldl.windowsupdate.com' -Port 80
$ctlReachable = ($null -ne $ctlResult -and $ctlResult.Status -ne 'FAIL')
if ($rootAutoUpdateDisabled) {
    Add-LocalCheck -Area 'Certificates' -Check 'Automatic root update' -Status 'WARN' -Detail 'DisableRootAutoUpdate is 1. Required roots must be distributed by policy because Windows will not download them.'
}
else {
    $rootUpdateStatus = if ($ctlReachable) { 'PASS' } else { 'WARN' }
    Add-LocalCheck -Area 'Certificates' -Check 'Automatic root update' -Status $rootUpdateStatus -Detail ('Enabled by policy. ctldl.windowsupdate.com reachable: {0}.' -f $ctlReachable)
}

$rootCatalog = @(
    @{ Name = 'DigiCert Global Root G2'; Thumbprint = 'DF3C24F9BFD666761B268073FE06D1CC8D4F82A4'; Critical = $true }
    @{ Name = 'Microsoft RSA Root Certificate Authority 2017'; Thumbprint = '73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74'; Critical = $true }
    @{ Name = 'DigiCert Global Root CA'; Thumbprint = 'A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436'; Critical = $false }
    @{ Name = 'DigiCert Global Root G3'; Thumbprint = '7E04DE896A3E666D00E687D33FFAD93BE83D349E'; Critical = $false }
    @{ Name = 'DigiCert TLS ECC P384 Root G5'; Thumbprint = '17F3DE5E9F0F19E98EF61F32266E20C407AE30EE'; Critical = $false }
    @{ Name = 'DigiCert TLS RSA4096 Root G5'; Thumbprint = 'A78849DC5D7C758C8CDE399856B3AAD0B2A57135'; Critical = $false }
    @{ Name = 'Microsoft ECC Root Certificate Authority 2017'; Thumbprint = '999A64C37FF47D9FAB95F14769891460EEC4C3C5'; Critical = $false }
)
foreach ($root in $rootCatalog) {
    $storeName = Test-RootPresent -Thumbprint $root.Thumbprint
    if ($storeName) {
        Add-LocalCheck -Area 'Certificates' -Check $root.Name -Status 'PASS' -Detail ('Present in LocalMachine {0} store.' -f $storeName)
    }
    elseif ($root.Critical) {
        $rootStatus = if ($rootAutoUpdateDisabled -or -not $ctlReachable) { 'FAIL' } else { 'WARN' }
        Add-LocalCheck -Area 'Certificates' -Check $root.Name -Status $rootStatus -Detail ('Missing. Azure Government and Entra ID endpoints chain to this root. Deploy it by policy or allow automatic root update. Thumbprint {0}.' -f $root.Thumbprint)
    }
    else {
        $rootStatus = if ($rootAutoUpdateDisabled) { 'WARN' } else { 'INFO' }
        Add-LocalCheck -Area 'Certificates' -Check $root.Name -Status $rootStatus -Detail ('Not present. Some Azure services chain to this root; Windows downloads it on demand when automatic root update works. Thumbprint {0}.' -f $root.Thumbprint)
    }
}

$arcProxyDetail = if ($arcProxy) { Hide-Credential -Text $arcProxy } else { 'none (direct)' }
Add-LocalCheck -Area 'Azure Arc' -Check 'Arc proxy path' -Status 'INFO' -Detail ('Arc proxy {0}. Bypass {1}. WinHTTP proxy {2}.' -f $arcProxyDetail, $(if ($arcBypass) { $arcBypass } else { 'none' }), $(if ($winHttpProxy) { Hide-Credential -Text $winHttpProxy } else { 'none' }))

#endregion

#region Summary

$requiredFailures = @($endpointResults | Where-Object { $_.Status -eq 'FAIL' -and $_.Level -eq 'Required' }).Count +
    @($localChecks | Where-Object { $_.Status -eq 'FAIL' }).Count +
    @($wildcardResults | Where-Object { $_.Status -eq 'FAIL' }).Count +
    $(if ($arcCheckStatus -eq 'FAIL') { 1 } else { 0 })
$warningCount = @($endpointResults | Where-Object { ($_.Status -eq 'FAIL' -and $_.Level -ne 'Required') -or $_.Status -eq 'WARN' }).Count +
    @($localChecks | Where-Object { $_.Status -eq 'WARN' }).Count +
    @($wildcardResults | Where-Object { $_.Status -eq 'WARN' }).Count +
    $(if ($arcCheckStatus -eq 'WARN') { 1 } else { 0 })
$reviewCount = @($wildcardResults | Where-Object { $_.Status -eq 'REVIEW' }).Count +
    @($localChecks | Where-Object { $_.Status -eq 'REVIEW' }).Count +
    $(if ($arcCheckStatus -eq 'REVIEW') { 1 } else { 0 })
$passedEndpoints = @($endpointResults | Where-Object { $_.Status -eq 'PASS' }).Count
$overallStatus = if ($requiredFailures -gt 0) { 'FAIL' } elseif ($warningCount -gt 0) { 'WARN' } elseif ($reviewCount -gt 0) { 'REVIEW' } else { 'PASS' }

$actionItems = New-Object System.Collections.Generic.List[object]
foreach ($item in ($endpointResults | Where-Object { $_.Status -eq 'FAIL' -and $_.Level -eq 'Required' })) {
    $actionItems.Add([pscustomobject]@{ Status = 'FAIL'; Text = ('Allow {0} ({1}) for {2}. {3}' -f $item.Target, $item.Rule, $item.UsedBy, $item.Detail) })
}
foreach ($item in ($localChecks | Where-Object { $_.Status -eq 'FAIL' })) {
    $actionItems.Add([pscustomobject]@{ Status = 'FAIL'; Text = ('{0}, {1}: {2}' -f $item.Area, $item.Check, $item.Detail) })
}
if ($arcCheckStatus -eq 'FAIL') { $actionItems.Add([pscustomobject]@{ Status = 'FAIL'; Text = ('azcmagent check: {0}' -f $arcCheckDetail) }) }
foreach ($item in ($wildcardResults | Where-Object { $_.Status -eq 'FAIL' })) {
    $actionItems.Add([pscustomobject]@{ Status = 'FAIL'; Text = ('Wildcard {0}: {1}' -f $item.Rule, $item.Coverage) })
}
foreach ($item in ($endpointResults | Where-Object { ($_.Status -eq 'FAIL' -and $_.Level -ne 'Required') -or $_.Status -eq 'WARN' })) {
    $actionItems.Add([pscustomobject]@{ Status = 'WARN'; Text = ('{0} {1} ({2}) for {3}. {4}' -f $item.Level, $item.Target, $item.Rule, $item.UsedBy, $item.Detail) })
}
foreach ($item in ($localChecks | Where-Object { $_.Status -eq 'WARN' })) {
    $actionItems.Add([pscustomobject]@{ Status = 'WARN'; Text = ('{0}, {1}: {2}' -f $item.Area, $item.Check, $item.Detail) })
}
foreach ($item in ($wildcardResults | Where-Object { $_.Status -in @('WARN', 'REVIEW') })) {
    $actionItems.Add([pscustomobject]@{ Status = $item.Status; Text = ('Wildcard {0}: {1} {2}' -f $item.Rule, $item.Coverage, $item.Note) })
}

#endregion

#region Evidence

if ($null -ne $arcShow) { Add-Evidence -Title 'azcmagent show' -Text (Hide-Credential -Text $arcShow.Output) }
if ($null -ne $arcCheck) { Add-Evidence -Title ('azcmagent check --cloud AzureUSGovernment --location {0}' -f $effectiveLocation) -Text (Hide-Credential -Text $arcCheck.Output) -Open }
if ($null -ne $arcConfig) { Add-Evidence -Title 'azcmagent config list' -Text (Hide-Credential -Text $arcConfig.Output) }

$proxyEvidence = New-Object System.Text.StringBuilder
[void]$proxyEvidence.AppendLine('WinHTTP proxy')
[void]$proxyEvidence.AppendLine((Hide-Credential -Text $winHttpRaw))
[void]$proxyEvidence.AppendLine('')
[void]$proxyEvidence.AppendLine(('MDE TelemetryProxyServer: {0}' -f $(if ($mdeTelemetryProxy) { Hide-Credential -Text $mdeTelemetryProxy } else { 'not set' })))
[void]$proxyEvidence.AppendLine(('Arc agent proxy.url: {0}' -f $(if ($arcProxy) { Hide-Credential -Text $arcProxy } else { 'not set' })))
[void]$proxyEvidence.AppendLine(('Arc agent proxy.bypass: {0}' -f $(if ($arcBypass) { $arcBypass } else { 'not set' })))
foreach ($variable in @('HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY')) {
    $value = [Environment]::GetEnvironmentVariable($variable, 'Machine')
    [void]$proxyEvidence.AppendLine(('Machine {0}: {1}' -f $variable, $(if ($value) { Hide-Credential -Text $value } else { 'not set' })))
}
if ($ProxyUrl) { [void]$proxyEvidence.AppendLine(('Forced probe proxy: {0}' -f (Hide-Credential -Text $ProxyUrl))) }
Add-Evidence -Title 'Proxy configuration' -Text $proxyEvidence.ToString()

$mdeExtensionLogDirectory = Join-Path $extensionLogRoot $mdeExtensionName
if (Test-Path -LiteralPath $mdeExtensionLogDirectory -PathType Container) {
    $mdeExtensionLog = Get-ChildItem -LiteralPath $mdeExtensionLogDirectory -Recurse -Depth 2 -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($null -ne $mdeExtensionLog) { Add-Evidence -Title ('MDE.Windows extension log tail: {0}' -f $mdeExtensionLog.FullName) -Text (Get-FileTail -Path $mdeExtensionLog.FullName -MaxLines 80) -Open:($null -ne $mdeExtension -and $mdeExtension.State -notmatch '(?i)success') }
}
foreach ($file in $arcLogTails.Keys) {
    if ($file -match '(?i)gc_ext\.log$|himds\.log$|gc_agent\.log$') {
        Add-Evidence -Title ('Error lines from {0}' -f $file) -Text (Hide-Credential -Text (Select-ErrorLine -Text $arcLogTails[$file] -MaxLines 40))
    }
}
Add-Evidence -Title 'Government Blob hosts observed in Arc logs' -Text $(if ($observedBlobHosts.Count -gt 0) { $observedBlobHosts -join [Environment]::NewLine } else { 'None observed. Only the wildcard rule can be reviewed for Arc extension storage.' })
Add-Evidence -Title 'MDE hosts observed in onboarding data and SENSE events' -Text $(if ($observedMdeHosts.Count -gt 0) { $observedMdeHosts -join [Environment]::NewLine } else { 'None observed.' })
Add-Evidence -Title 'Defender Antivirus status' -Text $mpStatusText

#endregion

#region HTML report

$metricHtml = @(
    ('<div class="metric">Overall<strong>{0}</strong></div>' -f (ConvertTo-StatusCell -Status $overallStatus))
    ('<div class="metric">Required failures<strong>{0}</strong></div>' -f $requiredFailures)
    ('<div class="metric">Warnings<strong>{0}</strong></div>' -f $warningCount)
    ('<div class="metric">Manual reviews<strong>{0}</strong></div>' -f $reviewCount)
    ('<div class="metric">Endpoints passed<strong>{0} of {1}</strong></div>' -f $passedEndpoints, $endpointResults.Count)
    ('<div class="metric">Native Arc check<strong>{0}</strong></div>' -f (ConvertTo-StatusCell -Status $arcCheckStatus))
) -join [Environment]::NewLine

$actionHtml = if ($actionItems.Count -eq 0) {
    '<p class="pass">No action required. Every required endpoint and local check passed.</p>'
}
else {
    '<ul>' + (($actionItems | Select-Object -First 60 | ForEach-Object { '<li>{0} {1}</li>' -f (ConvertTo-StatusCell -Status $_.Status), (ConvertTo-HtmlText $_.Text) }) -join [Environment]::NewLine) + '</ul>'
}

$localRows = ($localChecks | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (ConvertTo-StatusCell -Status $_.Status), (ConvertTo-HtmlText $_.Area), (ConvertTo-HtmlText $_.Check), (ConvertTo-HtmlText $_.Detail)
    }) -join [Environment]::NewLine

$endpointRows = ($endpointResults | ForEach-Object {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td><code>{4}</code></td><td>{5}</td><td>{6}</td><td>{7}<br><span class="muted">{8}</span></td><td>{9}</td><td>{10}</td><td>{11}<br><span class="muted">{12}</span></td><td>{13}</td><td>{14}</td><td>{15}</td></tr>' -f `
            (ConvertTo-StatusCell -Status $_.Status), (ConvertTo-HtmlText $_.Area), (ConvertTo-HtmlText $_.UsedBy), (ConvertTo-HtmlText $_.Level), (ConvertTo-HtmlText $_.Rule), (ConvertTo-HtmlText $_.Target),
            (ConvertTo-HtmlText $_.PathText), (ConvertTo-HtmlText $_.Dns), (ConvertTo-HtmlText $_.Addresses), (ConvertTo-HtmlText $_.HttpCode), (ConvertTo-HtmlText $_.Tls),
            (ConvertTo-HtmlText $_.Root), (ConvertTo-HtmlText $_.Expiry), (ConvertTo-HtmlText $_.Tcp), (ConvertTo-HtmlText $_.Milliseconds),
            (ConvertTo-HtmlText ('{0} {1}' -f $_.Purpose, $_.Detail))
    }) -join [Environment]::NewLine

$wildcardRows = ($wildcardResults | ForEach-Object {
        '<tr><td>{0}</td><td><code>{1}</code></td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>' -f (ConvertTo-StatusCell -Status $_.Status), (ConvertTo-HtmlText $_.Rule), (ConvertTo-HtmlText $_.Level), (ConvertTo-HtmlText $_.UsedBy), (ConvertTo-HtmlText $_.Coverage), (ConvertTo-HtmlText $_.Note)
    }) -join [Environment]::NewLine

$arcCheckTable = if ($arcCheckRows.Count -gt 0) {
    $headerHtml = ($arcCheckHeaders | ForEach-Object { '<th>{0}</th>' -f (ConvertTo-HtmlText $_) }) -join ''
    $bodyHtml = ($arcCheckRows | ForEach-Object { '<tr>' + (($_ | ForEach-Object { '<td>{0}</td>' -f (ConvertTo-HtmlText $_) }) -join '') + '</tr>' }) -join [Environment]::NewLine
    '<table><thead><tr>{0}</tr></thead><tbody>{1}</tbody></table>' -f $headerHtml, $bodyHtml
}
else {
    '<p>No parsed table. See the raw output in Detailed evidence.</p>'
}

$extensionHtml = if ($extensionRows.Count -gt 0) {
    '<table><thead><tr><th>Extension</th><th>Version</th><th>State</th><th>Message</th></tr></thead><tbody>' + (($extensionRows | ForEach-Object {
                $state = switch -Regex ($_.State) { '(?i)success' { 'PASS' } '(?i)error|fail' { 'FAIL' } default { $_.State } }
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f (ConvertTo-HtmlText $_.Name), (ConvertTo-HtmlText $_.Version), (ConvertTo-StatusCell -Status $state), (ConvertTo-HtmlText $_.Message)
            }) -join [Environment]::NewLine) + '</tbody></table>'
}
else {
    '<p>No Arc extensions are installed under ' + (ConvertTo-HtmlText $pluginRoot) + '.</p>'
}

$senseHtml = if ($senseRows.Count -gt 0) {
    '<table><thead><tr><th>Event ID</th><th>Count</th><th>Level</th><th>Latest UTC</th><th>Latest message</th></tr></thead><tbody>' + (($senseRows | ForEach-Object {
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f (ConvertTo-HtmlText $_.Id), $_.Count, (ConvertTo-HtmlText $_.Level), (ConvertTo-HtmlText $_.Latest), (ConvertTo-HtmlText $_.Message)
            }) -join [Environment]::NewLine) + '</tbody></table>'
}
else {
    '<p>' + (ConvertTo-HtmlText $(if ($senseEventNote) { $senseEventNote } else { 'No SENSE warnings or errors in the last 3 days.' })) + '</p>'
}

$evidenceHtml = ($evidence | ForEach-Object {
        '<details{0}><summary>{1}</summary><pre>{2}</pre></details>' -f $(if ($_.Open) { ' open' } else { '' }), (ConvertTo-HtmlText $_.Title), (ConvertTo-HtmlText $_.Text)
    }) -join [Environment]::NewLine

$sourceHtml = ($sources.GetEnumerator() | ForEach-Object { '<li><a href="{0}">{1}</a></li>' -f (ConvertTo-HtmlText $_.Value), (ConvertTo-HtmlText $_.Key) }) -join [Environment]::NewLine
$completedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Azure Arc and MDE DoD Connectivity Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 2rem; color: #1f2937; background: #f8fafc; }
h1, h2 { color: #0f172a; }
.card { background: white; border: 1px solid #cbd5e1; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; overflow-x: auto; }
.pass { color: #166534; font-weight: bold; }
.fail { color: #b91c1c; font-weight: bold; }
.warn { color: #b45309; font-weight: bold; }
.review { color: #475569; font-weight: bold; }
.muted { color: #64748b; font-size: 0.75rem; }
.metrics { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-top: 0.75rem; }
.metric { border: 1px solid #cbd5e1; border-radius: 8px; padding: 0.6rem 1rem; min-width: 9rem; background: #f8fafc; }
.metric strong { display: block; font-size: 1.3rem; margin-top: 0.25rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
th, td { border: 1px solid #cbd5e1; padding: 0.4rem; text-align: left; vertical-align: top; }
th { background: #e2e8f0; }
code { font-family: Consolas, monospace; font-size: 0.8rem; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 6px; max-height: 32rem; overflow: auto; }
details { margin-bottom: 0.75rem; }
summary { cursor: pointer; font-weight: bold; padding: 0.5rem; }
li { margin-bottom: 0.35rem; }
</style>
</head>
<body>
<h1>Azure Arc and MDE DoD Connectivity Report</h1>
<div class="card">
<p><strong>Device:</strong> $(ConvertTo-HtmlText $deviceName) &nbsp; <strong>OS:</strong> $(ConvertTo-HtmlText $osCaption) build $osBuild</p>
<p><strong>Completed UTC:</strong> $completedUtc &nbsp; <strong>Script version:</strong> $scriptVersion</p>
<p><strong>Overall result:</strong> $(ConvertTo-StatusCell -Status $overallStatus)</p>
<p><strong>Arc region:</strong> $(ConvertTo-HtmlText $effectiveLocation) &nbsp; <strong>Arc agent:</strong> $(ConvertTo-HtmlText $(if ($arcInstalled) { 'installed ' + $arcAgentVersion + ', ' + (Get-ArcShowValue -Name 'Agent Status') } else { 'not installed' })) &nbsp; <strong>MDE connectivity:</strong> detected $(ConvertTo-HtmlText $detectedMdeMode), evaluated as $(ConvertTo-HtmlText $effectiveMdeMode)</p>
<div class="metrics">
$metricHtml
</div>
</div>

<div class="card">
<h2>Action items</h2>
$actionHtml
</div>

<div class="card">
<h2>Local readiness checks</h2>
<table>
<thead><tr><th>Result</th><th>Area</th><th>Check</th><th>Detail</th></tr></thead>
<tbody>
$localRows
</tbody>
</table>
</div>

<div class="card">
<h2>Endpoint results</h2>
<p>Each host and port is tested once through the proxy path of the agent that owns it. HTTP 400 to 499 responses prove the network path works. Required failures fail the report; Conditional, Recommended, and Optional failures are warnings.</p>
<table>
<thead><tr><th>Result</th><th>Area</th><th>Used by</th><th>Level</th><th>Firewall rule</th><th>Target</th><th>Path</th><th>DNS</th><th>HTTP</th><th>TLS</th><th>Certificate root and expiry</th><th>Direct TCP</th><th>ms</th><th>Purpose and evidence</th></tr></thead>
<tbody>
$endpointRows
</tbody>
</table>
</div>

<div class="card">
<h2>Wildcard firewall rules</h2>
<p>A wildcard cannot be tested literally. Each rule lists the concrete hosts tested beneath it. Keep the full wildcard on the firewall or proxy even when every concrete host passes.</p>
<table>
<thead><tr><th>Result</th><th>Rule</th><th>Level</th><th>Used by</th><th>Concrete coverage</th><th>Note</th></tr></thead>
<tbody>
$wildcardRows
</tbody>
</table>
</div>

<div class="card">
<h2>Native Azure Arc agent check</h2>
<p>$(ConvertTo-StatusCell -Status $arcCheckStatus) $(ConvertTo-HtmlText $arcCheckDetail)</p>
$arcCheckTable
</div>

<div class="card">
<h2>Arc extensions</h2>
$extensionHtml
</div>

<div class="card">
<h2>SENSE event summary, last 3 days</h2>
$senseHtml
</div>

<div class="card">
<h2>Firewall and proxy requirements that one server cannot prove</h2>
<ul>
<li>Azure Arc service tags: <code>AzureActiveDirectory</code>, <code>AzureTrafficManager</code>, <code>AzureResourceManager</code>, <code>AzureArcInfrastructure</code>, <code>Storage</code>, and <code>AzureFrontDoor.Frontend</code> (required as of April 2026).</li>
<li>When filtering Azure Government by IP address, also allow the public cloud <code>AzureArcInfrastructure</code> ranges. Never allow only the address returned by one DNS lookup.</li>
<li>Do not inspect, intercept, or proxy authenticate <code>*.endpoint.security.microsoft.us</code> or the MDE standard endpoints. MDE runs as SYSTEM and cannot answer proxy authentication.</li>
<li>Live Response needs <code>*.wns.windows.com</code>, <code>login.live.com</code>, and <code>login.microsoftonline.us</code> with a direct connection or proxy bypass, and file transfer uses government Blob storage.</li>
<li>Allow the HTTP port 80 certificate AIA, CRL, and OCSP hosts without inspection so Windows can validate Azure Government certificates.</li>
<li>For MDE streamlined connectivity, run MDE Client Analyzer with <code>-o</code> and the DoD onboarding package to validate the runtime assigned hosts.</li>
<li>With Azure Arc Private Link, rerun the native check with <code>--enable-pls-check</code> and confirm the Private Link capable endpoints resolve to private addresses.</li>
</ul>
</div>

<div class="card">
<h2>Detailed evidence</h2>
$evidenceHtml
</div>

<div class="card">
<h2>Microsoft sources</h2>
<ul>
$sourceHtml
</ul>
<p class="muted">Read only report. No configuration, service, firewall, proxy, certificate, or onboarding setting was changed.</p>
</div>
</body>
</html>
"@

try {
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($reportPath, $html, (New-Object System.Text.UTF8Encoding($false)))
}
catch {
    Write-Error ('Unable to save the HTML report: {0}' -f $_.Exception.Message)
    exit 1
}

#endregion

Write-Output ('Device: {0}  UTC: {1}' -f $deviceName, $completedUtc)
Write-Output ('Overall result: {0}' -f $overallStatus)
Write-Output ('Required failures: {0}  Warnings: {1}  Manual reviews: {2}' -f $requiredFailures, $warningCount, $reviewCount)
Write-Output ('HTML report: {0}' -f $reportPath)
Write-Output ('Retrieve HTML: getfile "{0}"' -f $reportPath)
exit 0
