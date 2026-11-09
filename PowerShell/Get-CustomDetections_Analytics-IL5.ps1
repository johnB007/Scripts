# Generated IL5 detection and analytics edition from Get-CustomDetections.ps1. Do not edit this copy.
<#
##################################################################################################################
#
# Microsoft Frontier Security Engineering
# Export custom detection rules from Microsoft Defender XDR portal
#
#
#
#
# Microsoft Disclaimer for custom scripts
# ================================================================================================================
# The sample scripts are not supported under any Microsoft standard support program or service. The sample scripts
# are provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including,
# without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire
# risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event
# shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be
# liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business
# interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to
# use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
# ================================================================================================================
#
##################################################################################################################
# Script variables - please do not change these unless you know what you are doing
##################################################################################################################

.SYNOPSIS
Exports Defender custom detections and Sentinel analytics rules through Edge.

.DESCRIPTION
Launches Microsoft Edge, uses the authenticated Defender portal session to
retrieve custom detection rules, and writes each complete rule configuration
and query to JSON and kql files. Sentinel uses the Azure portal in the same Edge
window and an ARM bearer from its legitimate fetch or XHR requests. RBAC is
enforced by ARM. No CLI or additional authentication module is used.
The script is self-contained and supports Windows
PowerShell 5.1.

.PARAMETER ExportMode
MDE preserves the original behavior and is the default. Sentinel exports only
analytics rules. Both exports each source into its own directory.

.PARAMETER CloudEnvironment
Commercial selects the commercial Defender and Azure portals. USGov selects
the Government Defender portal. USGovDoD selects security.apps.mil.
The edition default is declared in the parameter block. Both Government
choices use portal.azure.us and Government ARM.

.PARAMETER SentinelApiVersion
Optional confirmed alertRules API version. Commercial defaults to 2025-09-01.
Government otherwise discovers an advertised stable version using a browser
GET of the selected subscription's provider metadata. Discovery requires
provider read permission and never registers a provider or grants access.

.PARAMETER SubscriptionId
The subscription containing the Sentinel workspace. Required with Sentinel or Both.

.PARAMETER ResourceGroupName
The resource group containing the Sentinel workspace. Required with Sentinel or Both.

.PARAMETER WorkspaceName
The Sentinel workspace name. Required with Sentinel or Both.

.PARAMETER SentinelRuleNames
Optional exact Sentinel display names as an array or comma separated string.
Rules without a display name use their resource name.

.PARAMETER TenantId
Specifies the Microsoft Entra tenant ID used to open the Defender portal.
This parameter is required.

.PARAMETER UserPrincipalName
Requests this account at Microsoft sign in using login_hint and prompt=login.
Uses a new isolated profile without importing browser authentication. Requires
you to confirm the account shown in Defender before exporting. This is a user
confirmation, not automatic verification of the portal identity. Cannot override
organizational authentication policy. Does not require InPrivate browsing.

.PARAMETER DetectionNames
Specifies which custom detection rules to export by exact name. Provide either
a comma-delimited string or a PowerShell string array. Matching is
case-insensitive. Space-delimited input is not supported because rule names can
contain spaces. If omitted, all custom detection rules are exported.

.PARAMETER OutputPath
Specifies the export directory. The default is a timestamped directory beneath
the script's exports directory.

.PARAMETER ProfilePath
Specifies the isolated Edge user-data directory used by the exporter. The
default is %LOCALAPPDATA%\Get-CustomDetections\EdgeProfile.
With UserPrincipalName, the default is a unique directory for this run, and an
explicit directory must not already exist. Existing profiles are not deleted.

.PARAMETER SelectEdgeProfile
Imports the Edge profile selected by EdgeProfileDirectory into the isolated
exporter profile. Close all Edge windows before the first import or a profile
reset. The source Edge profile is not modified.

.PARAMETER EdgeProfileDirectory
Specifies the Edge profile directory to import, such as Default or Profile 2.
If SelectEdgeProfile is specified and this parameter is omitted, the
script displays the available Edge profile names and prompts for a selection.

.PARAMETER LoginTimeoutSeconds
Specifies how long the script waits for authentication and the Custom
detections page to load. The default is 300 seconds.

.PARAMETER CaptureSeconds
Specifies how long the script waits for the portal's custom detection rule-list
request after the page loads. The default is 20 seconds.

.PARAMETER RemoveCachedProfile
Deletes the isolated Edge profile after the script completes, including when
the export fails. This removes cached authentication artifacts and requires
sign-in on the next run.

.PARAMETER ResetProfile
Deletes and recreates the isolated exporter profile. When combined with
SelectEdgeProfile, the selected source profile is imported again.

.EXAMPLE
.\Get-CustomDetections.ps1 -TenantId '00000000-0000-0000-0000-000000000000'

Exports every custom detection rule from the specified tenant.

.EXAMPLE
.\Get-CustomDetections.ps1 -TenantId '00000000-0000-0000-0000-000000000000' -DetectionNames 'Rule One,Rule Two'

Exports only Rule One and Rule Two using a comma-delimited value.

.EXAMPLE
.\Get-CustomDetections.ps1 -TenantId '00000000-0000-0000-0000-000000000000' -DetectionNames 'Rule One','Rule Two' -SelectEdgeProfile -EdgeProfileDirectory 'Profile 2'

Exports two selected rules after importing Profile 2 into the isolated Edge
profile.

.EXAMPLE
.\Get-CustomDetections.ps1 -TenantId '00000000-0000-0000-0000-000000000000' -SelectEdgeProfile -RemoveCachedProfile

Exports the rules, closes Edge, and removes the isolated profile and its
authentication artifacts.

.EXAMPLE
pwsh -NoProfile -File .\Get-CustomDetections.ps1 -TenantId '00000000-0000-0000-0000-000000000000' -UserPrincipalName 'user@example.invalid' -LoginTimeoutSeconds 600 -CaptureSeconds 60

Requests interactive sign in for the specified account without importing an
Edge profile or using InPrivate. Confirm the email shown in the Defender
webpage account menu when prompted in PowerShell. A mismatch cancels export.

.NOTES
Get-CustomDetections_Analytics-IL2.ps1 and Get-CustomDetections_Analytics-IL5.ps1 are generated
standalone editions of this canonical implementation. IL2 selects Commercial
by default and IL5 selects USGovDoD. These labels identify intended target
environments, not formal authorization or certification. Shared instructions
are in Get-CustomDetections.md. Edit this canonical script and regenerate the
editions using Tests\Test-GetCustomDetections.ps1 -RegenerateEditions.

Account targeting changes apply only when UserPrincipalName is supplied.
Only main frame Microsoft authorization requests are changed. Their existing
client, redirect, tenant, state, nonce, scopes, and PKCE parameters are retained.
No passwords or authentication tokens are requested on the command line.

The Defender portal's internal endpoints are not a public API contract and can
change. Exported rule queries and configuration should be treated as
security-sensitive.
#>

#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [Guid]$TenantId,

    [ValidatePattern('^[^@\s]+@[^@\s]+$')]
    [string]$UserPrincipalName,

    [Alias('CustomDetectionNames')]
    [string[]]$DetectionNames,

    [ValidateSet('MDE', 'Sentinel', 'Both')]
    [string]$ExportMode = 'MDE',

    [ValidateSet('Commercial', 'USGov', 'USGovDoD')]
    [string]$CloudEnvironment = 'USGovDoD',

    [Guid]$SubscriptionId,

    [ValidatePattern('^[A-Za-z0-9_().-]{1,90}$')]
    [string]$ResourceGroupName,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{2,88}[A-Za-z0-9]$')]
    [string]$WorkspaceName,

    [string[]]$SentinelRuleNames,

    [string]$OutputPath,

    [string]$ProfilePath,

    [switch]$SelectEdgeProfile,

    [ValidatePattern('^(Default|Profile \d+)$')]
    [string]$EdgeProfileDirectory,

    [ValidateRange(30, 1800)]
    [int]$LoginTimeoutSeconds = 300,

    [ValidateRange(5, 120)]
    [int]$CaptureSeconds = 20,

    [switch]$RemoveCachedProfile,

    [switch]$ResetProfile,

    [ValidatePattern('^$|^[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?$')]
    [string]$SentinelApiVersion
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Assert-SentinelApiVersion {
    param([string]$Version)
    $date = [DateTime]::MinValue
    if ($Version -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?$' -or
        -not [DateTime]::TryParseExact($Version.Substring(0, 10), 'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date)) {
        throw 'SentinelApiVersion must be a real date in yyyy-MM-dd format, optionally followed by -preview.'
    }
}
if ($SentinelApiVersion) { Assert-SentinelApiVersion -Version $SentinelApiVersion }

if ($UserPrincipalName -and ($SelectEdgeProfile -or $EdgeProfileDirectory -or $ResetProfile)) {
    throw 'With UserPrincipalName, omit SelectEdgeProfile, EdgeProfileDirectory, and ResetProfile. Account selection uses a new isolated profile.'
}
if ($ExportMode -ne 'MDE' -and (
    $SubscriptionId -eq [Guid]::Empty -or
    [string]::IsNullOrWhiteSpace($ResourceGroupName) -or
    [string]::IsNullOrWhiteSpace($WorkspaceName))) {
    throw 'Sentinel and Both require SubscriptionId, ResourceGroupName, and WorkspaceName.'
}
if ($ExportMode -eq 'Sentinel' -and $DetectionNames) {
    throw 'DetectionNames applies only to MDE. Use SentinelRuleNames for Sentinel.'
}
if ($ExportMode -eq 'MDE' -and $SentinelRuleNames) {
    throw 'SentinelRuleNames requires Sentinel or Both.'
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot ('exports\{0:yyyyMMdd-HHmmss}-{1}' -f
        (Get-Date), [Guid]::NewGuid().ToString('N').Substring(0, 8))
}
if ([string]::IsNullOrWhiteSpace($ProfilePath)) {
    $profileDirectory = if ($UserPrincipalName) {
        'Get-CustomDetections\TargetUser-' + [Guid]::NewGuid().ToString('N')
    }
    else {
        'Get-CustomDetections\EdgeProfile'
    }
    $ProfilePath = Join-Path $env:LOCALAPPDATA $profileDirectory
}
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$ProfilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ProfilePath)
$repositoryPath = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent)).TrimEnd('\')
$normalEdgePath = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data')).TrimEnd('\')
foreach ($protectedRoot in @($repositoryPath, $normalEdgePath)) {
    $profileRoot = [IO.Path]::GetFullPath($ProfilePath).TrimEnd('\')
    if ($profileRoot -ieq $protectedRoot -or
        $profileRoot.StartsWith($protectedRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $protectedRoot.StartsWith($profileRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'ProfilePath must be isolated from the repository and normal Edge profiles.'
    }
}
if ($UserPrincipalName -and (Test-Path -LiteralPath $ProfilePath)) {
    throw 'With UserPrincipalName, ProfilePath must be a new directory. Omit ProfilePath to create one automatically.'
}
$defenderHost = switch ($CloudEnvironment) {
    'Commercial' { 'security.microsoft.com' }
    'USGov' { 'security.microsoft.us' }
    'USGovDoD' { 'security.apps.mil' }
}
$portalUrl = ('https://{0}/v2/custom_detection?tid={1}' -f $defenderHost,
    [Uri]::EscapeDataString($TenantId.ToString('D'))
)

$cdpClientSource = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace CustomDetections
{
    public sealed class CdpClient : IDisposable
    {
        private readonly ClientWebSocket socket = new ClientWebSocket();
        private readonly ConcurrentDictionary<int, TaskCompletionSource<string>> pending =
            new ConcurrentDictionary<int, TaskCompletionSource<string>>();
        private readonly ConcurrentQueue<string> events = new ConcurrentQueue<string>();
        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        private int nextId;
        private Task receiveTask;

        public void Connect(string webSocketUrl, int timeoutMilliseconds)
        {
            Task connectTask = socket.ConnectAsync(new Uri(webSocketUrl), cancellation.Token);
            if (!connectTask.Wait(timeoutMilliseconds))
            {
                throw new TimeoutException("Timed out connecting to the Edge DevTools endpoint.");
            }

            receiveTask = Task.Run((Func<Task>)ReceiveLoop);
        }

        public string Call(string method, string parametersJson, int timeoutMilliseconds)
        {
            return Call(method, parametersJson, timeoutMilliseconds, null);
        }

        public string Call(string method, string parametersJson, int timeoutMilliseconds, string sessionId)
        {
            if (socket.State != WebSocketState.Open)
            {
                throw new InvalidOperationException("The Edge DevTools connection is not open.");
            }

            int id = Interlocked.Increment(ref nextId);
            var completion = new TaskCompletionSource<string>();
            if (!pending.TryAdd(id, completion))
            {
                throw new InvalidOperationException("Unable to register the DevTools command.");
            }

            string parameters = String.IsNullOrWhiteSpace(parametersJson) ? "{}" : parametersJson;
            string payload = "{\"id\":" + id +
                ",\"method\":\"" + EscapeJsonString(method) +
                (String.IsNullOrEmpty(sessionId) ? String.Empty :
                    "\",\"sessionId\":\"" + EscapeJsonString(sessionId)) +
                "\",\"params\":" + parameters + "}";

            byte[] bytes = Encoding.UTF8.GetBytes(payload);
            Task sendTask = socket.SendAsync(
                new ArraySegment<byte>(bytes),
                WebSocketMessageType.Text,
                true,
                cancellation.Token);

            if (!sendTask.Wait(timeoutMilliseconds))
            {
                TaskCompletionSource<string> ignored;
                pending.TryRemove(id, out ignored);
                throw new TimeoutException("Timed out sending DevTools command: " + method);
            }

            if (!completion.Task.Wait(timeoutMilliseconds))
            {
                TaskCompletionSource<string> ignored;
                pending.TryRemove(id, out ignored);
                throw new TimeoutException("Timed out waiting for DevTools command: " + method);
            }

            return completion.Task.Result;
        }

        public bool TryTakeEvent(out string message)
        {
            return events.TryDequeue(out message);
        }

        private async Task ReceiveLoop()
        {
            byte[] buffer = new byte[65536];

            try
            {
                while (!cancellation.IsCancellationRequested && socket.State == WebSocketState.Open)
                {
                    using (var stream = new MemoryStream())
                    {
                        WebSocketReceiveResult result;
                        do
                        {
                            result = await socket.ReceiveAsync(
                                new ArraySegment<byte>(buffer),
                                cancellation.Token).ConfigureAwait(false);

                            if (result.MessageType == WebSocketMessageType.Close)
                            {
                                return;
                            }

                            stream.Write(buffer, 0, result.Count);
                        }
                        while (!result.EndOfMessage);

                        string message = Encoding.UTF8.GetString(stream.ToArray());
                        Match responseId = Regex.Match(
                            message,
                            "^\\s*\\{\\s*\"id\"\\s*:\\s*(\\d+)");

                        if (responseId.Success)
                        {
                            int id = Convert.ToInt32(responseId.Groups[1].Value);
                            TaskCompletionSource<string> completion;
                            if (pending.TryRemove(id, out completion))
                            {
                                completion.TrySetResult(message);
                            }
                        }
                        else
                        {
                            events.Enqueue(message);
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception exception)
            {
                events.Enqueue(
                    "{\"method\":\"CustomDetections.ConnectionError\"," +
                    "\"params\":{\"message\":\"" +
                    EscapeJsonString(exception.Message) + "\"}}");
            }
        }

        private static string EscapeJsonString(string value)
        {
            if (String.IsNullOrEmpty(value))
            {
                return String.Empty;
            }

            var builder = new StringBuilder(value.Length);
            foreach (char character in value)
            {
                switch (character)
                {
                    case '\\': builder.Append("\\\\"); break;
                    case '"': builder.Append("\\\""); break;
                    case '\b': builder.Append("\\b"); break;
                    case '\f': builder.Append("\\f"); break;
                    case '\n': builder.Append("\\n"); break;
                    case '\r': builder.Append("\\r"); break;
                    case '\t': builder.Append("\\t"); break;
                    default:
                        if (character < 32)
                        {
                            builder.Append("\\u");
                            builder.Append(((int)character).ToString("x4"));
                        }
                        else
                        {
                            builder.Append(character);
                        }
                        break;
                }
            }

            return builder.ToString();
        }

        public void Dispose()
        {
            cancellation.Cancel();

            if (socket.State == WebSocketState.Open)
            {
                try
                {
                    socket.CloseAsync(
                        WebSocketCloseStatus.NormalClosure,
                        "Exporter completed",
                        CancellationToken.None).Wait(1000);
                }
                catch
                {
                    socket.Abort();
                }
            }

            socket.Dispose();
            cancellation.Dispose();
        }
    }
}
'@

Add-Type -TypeDefinition $cdpClientSource

function Get-SentinelTarget {
    param([Guid]$TenantId, [Guid]$SubscriptionId, [string]$ResourceGroupName,
        [string]$WorkspaceName, [string]$CloudEnvironment, [string]$SentinelApiVersion)

    $government = $CloudEnvironment -ne 'Commercial'
    if ($SentinelApiVersion) { Assert-SentinelApiVersion -Version $SentinelApiVersion }
    $discoverVersion = $government -and -not $SentinelApiVersion
    $version = if ($SentinelApiVersion) { $SentinelApiVersion }
        elseif ($discoverVersion) { '' } else { '2025-09-01' }
    $armHost = if ($government) { 'management.usgovcloudapi.net' } else { 'management.azure.com' }
    $portalHost = if ($government) { 'portal.azure.us' } else { 'portal.azure.com' }
    $resourceId = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.OperationalInsights/workspaces/{2}' -f
        $SubscriptionId.ToString('D'), [Uri]::EscapeDataString($ResourceGroupName),
        [Uri]::EscapeDataString($WorkspaceName)
    $collectionPath = "$resourceId/providers/Microsoft.SecurityInsights/alertRules"
    $providerId = '/subscriptions/{0}/providers/Microsoft.SecurityInsights' -f $SubscriptionId.ToString('D')
    [pscustomobject]@{
        TenantId = $TenantId.ToString('D')
        ArmHost = $armHost
        PortalHost = $portalHost
        BrowserOrigins = @(if ($government) { "https://$portalHost" } else {
            "https://$portalHost"; 'https://sandbox-1.reactblade.portal.azure.net'
        })
        ResourceId = $resourceId
        CollectionPath = $collectionPath
        ApiVersion = $version
        RequiresApiVersionDiscovery = $discoverVersion
        ApiVersionSource = if ($SentinelApiVersion) { 'ExplicitParameter' }
            elseif ($discoverVersion) { 'PendingGovernmentDiscovery' } else { 'CommercialDefault' }
        ProviderId = $providerId
        ProviderMetadataUrl = "https://$armHost$providerId`?api-version=2021-04-01"
        ListUrl = if ($version) { "https://$armHost$collectionPath`?api-version=$version" } else { '' }
        PortalUrl = "https://$portalHost/#@$($TenantId.ToString('D'))/resource$resourceId/overview"
        Audiences = if ($government) {
            @('https://management.core.usgovcloudapi.net', 'https://management.usgovcloudapi.net')
        } else {
            @('https://management.core.windows.net', 'https://management.azure.com')
        }
    }
}

function Assert-SentinelListUrl {
    param([string]$Url, [object]$Target)

    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or -not $uri.IsDefaultPort -or
        $uri.Host -ine $Target.ArmHost -or $uri.UserInfo -or $uri.Fragment -or
        $uri.AbsolutePath -ine $Target.CollectionPath) {
        throw 'Sentinel pagination left the selected cloud or workspace. No request was sent.'
    }
    $versions = @($uri.Query.TrimStart('?').Split('&') | Where-Object {
        [Uri]::UnescapeDataString(($_ -split '=', 2)[0]) -ieq 'api-version'
    })
    if ($versions.Count -ne 1 -or
        [Uri]::UnescapeDataString(($versions[0] -split '=', 2)[1]) -ne $Target.ApiVersion) {
        throw 'Sentinel pagination changed the API version. No request was sent.'
    }
}

function Assert-MdeListUrl {
    param([string]$Url, [string]$PortalHost)

    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or -not $uri.IsDefaultPort -or
        $uri.Host -ine $PortalHost -or $uri.UserInfo -or $uri.Fragment -or
        $uri.AbsolutePath -ne '/apiproxy/hunting/huntingService/rules/unified') {
        throw 'The captured MDE request is outside the selected Defender portal. No replay was performed.'
    }
}

function New-SentinelBrowserObserver {
    param([object]$Target)

    $configuration = $Target | ConvertTo-Json -Depth 10 -Compress
    # The ARM bearer stays inside this document closure. Neither CDP results nor files contain it.
    $source = @'
(() => {
  const cfg = __CONFIG__;
  if (!cfg.BrowserOrigins.includes(location.origin)) return;
  if (typeof window.__sentinelExporter === "function") return;
  let bearer = null;
  let rejected = false;
  let retainedReply = null;
  let versionConfirmed = !cfg.RequiresApiVersionDiscovery;
  const originalFetch = window.fetch;
  const decode = text => JSON.parse(new TextDecoder().decode(Uint8Array.from(
    atob(text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=")),
    c => c.charCodeAt(0))));
  function valid(value) {
    try {
      const parts = value.split(" ");
      if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") return false;
      const token = parts[1];
      if (!/^[A-Za-z0-9_.-]+$/.test(token)) return false;
      const claims = decode(token.split(".")[1]);
      return String(claims.tid).toLowerCase() === cfg.TenantId.toLowerCase() &&
        cfg.Audiences.includes(String(claims.aud).replace(/\/$/, "")) &&
        Number(claims.exp) > Date.now() / 1000 + 30;
    } catch (_) { return false; }
  }
  function observe(url, headers) {
    try {
      const u = new URL(url, location.href);
      if (u.origin !== "https://" + cfg.ArmHost || u.username || u.password) return;
      const authorization = new Headers(headers).get("authorization");
      if (!authorization) return;
      if (valid(authorization)) { bearer = authorization; rejected = false; }
      else { bearer = null; rejected = true; }
    } catch (_) {}
  }
  window.fetch = function(input, init) {
    observe(typeof input === "string" || input instanceof URL ? input : input.url,
      init && init.headers !== undefined ? init.headers : input.headers);
    return originalFetch.apply(this, arguments);
  };
  const open = XMLHttpRequest.prototype.open;
  const setHeader = XMLHttpRequest.prototype.setRequestHeader;
  const send = XMLHttpRequest.prototype.send;
  const xhrState = new WeakMap();
  XMLHttpRequest.prototype.open = function(method, url) {
    xhrState.set(this, { url, headers: {} });
    return open.apply(this, arguments);
  };
  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
    const state = xhrState.get(this);
    if (state) state.headers[name] = value;
    return setHeader.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function() {
    const state = xhrState.get(this);
    if (state) observe(state.url, state.headers);
    return send.apply(this, arguments);
  };
  async function discoverVersion() {
    if (versionConfirmed) return { status: "apiVersionSelected", apiVersion: cfg.ApiVersion };
    if (!bearer || !valid(bearer)) return { status: "authUnavailable" };
    // Fixed first party metadata GET, not an arbitrary URL supplied by the host.
    const metadataUrl = new URL(cfg.ProviderMetadataUrl);
    if (metadataUrl.origin !== "https://" + cfg.ArmHost || metadataUrl.username ||
        metadataUrl.password || metadataUrl.hash || metadataUrl.pathname !== cfg.ProviderId ||
        metadataUrl.search !== "?api-version=2021-04-01")
      return { status: "unsafeUrl" };
    try {
      const response = await originalFetch.call(window, metadataUrl.href, {
        method: "GET", headers: { Authorization: bearer, Accept: "application/json" },
        credentials: "omit", redirect: "error"
      });
      if (response.status !== 200) return { status: "httpError", httpStatus: response.status };
      let provider;
      try { provider = JSON.parse(await response.text()); }
      catch (_) { return { status: "unsupportedProviderMetadata" }; }
      if (!provider || typeof provider.id !== "string" ||
          provider.id.toLowerCase() !== cfg.ProviderId.toLowerCase() ||
          typeof provider.namespace !== "string" ||
          provider.namespace.toLowerCase() !== "microsoft.securityinsights" ||
          !Array.isArray(provider.resourceTypes))
        return { status: "unsupportedProviderMetadata" };
      const types = provider.resourceTypes.filter(t => t && typeof t.resourceType === "string" &&
        t.resourceType.toLowerCase() === "alertrules");
      if (types.length !== 1 || !Array.isArray(types[0].apiVersions) ||
          !types[0].apiVersions.every(v => typeof v === "string" &&
            /^[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?$/.test(v) &&
            Number.isFinite(Date.parse(v.slice(0, 10) + "T00:00:00Z")) &&
            new Date(v.slice(0, 10) + "T00:00:00Z").toISOString().slice(0, 10) === v.slice(0, 10)))
        return { status: "unsupportedProviderMetadata" };
      const stable = types[0].apiVersions.filter(v => !v.endsWith("-preview")).sort().reverse();
      if (!stable.length) return { status: "apiVersionUnavailable" };
      cfg.ApiVersion = stable[0];
      cfg.ListUrl = "https://" + cfg.ArmHost + cfg.CollectionPath + "?api-version=" + cfg.ApiVersion;
      versionConfirmed = true;
      return { status: "apiVersionSelected", apiVersion: cfg.ApiVersion };
    } catch (_) { return { status: "browserRequestFailed" }; }
  }
  async function execute(url) {
    if (!cfg.BrowserOrigins.includes(location.origin))
      return { status: "wrongPortal" };
    if (!url) return { status: bearer && valid(bearer) ? "ready" : rejected ? "wrongIdentity" : "waiting" };
    if (url === "discoverApiVersion") return await discoverVersion();
    const u = new URL(url);
    if (u.origin !== "https://" + cfg.ArmHost || u.username || u.password || u.hash ||
        u.pathname.toLowerCase() !== cfg.CollectionPath.toLowerCase() ||
        u.searchParams.getAll("api-version").length !== 1)
      return { status: "unsafeUrl" };
    if (!bearer || !valid(bearer)) return { status: "authUnavailable" };
    // A new authenticated frame may inherit the original unresolved startup
    // configuration after navigation. Confirm metadata in that realm again;
    // an API version change is refused rather than changing an in progress export.
    if (!versionConfirmed) {
      const selection = await discoverVersion();
      if (selection.status !== "apiVersionSelected") return selection;
    }
    if (u.searchParams.get("api-version") !== cfg.ApiVersion) return { status: "unsafeUrl" };
    try {
      const response = await originalFetch.call(window, u.href, {
        method: "GET", headers: { Authorization: bearer, Accept: "application/json" },
        credentials: "omit", redirect: "error"
      });
      if (response.status !== 200) return { status: "httpError", httpStatus: response.status };
      return { status: "ok", body: await response.text() };
    } catch (_) { return { status: "browserRequestFailed" }; }
  }
  // Retain the asynchronous reply in this realm until the next bridge call.
  // CDP must not lose its promise while the portal is loading or collecting garbage.
  Object.defineProperty(window, "__sentinelExporter", { value: function(url) {
    retainedReply = execute(url);
    return retainedReply;
  }, configurable: false, writable: false });
})()
'@
    return $source.Replace('__CONFIG__', $configuration)
}

function Invoke-SentinelBrowserRequest {
    param([CustomDetections.CdpClient]$Client, [string]$Url, [hashtable]$BrowserState)

    $urlJson = ConvertTo-Json -InputObject $Url -Compress
    $parameters = @{
        expression = "(async () => JSON.stringify(await (window.__sentinelExporter ? window.__sentinelExporter($urlJson) : ({status:'observerUnavailable'}))))()"
        awaitPromise = $true
        returnByValue = $true
    }
    $sessionId = ''
    if ($BrowserState) {
        if (-not $BrowserState.Active) { throw 'Sentinel has no verified active browser context.' }
        $parameters.contextId = [int]$BrowserState.Active.ContextId
        $sessionId = [string]$BrowserState.Active.SessionId
    }
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        try {
            $result = Invoke-CdpCommand -Client $Client -Method 'Runtime.evaluate' `
                -Parameters $parameters -SessionId $sessionId -TimeoutMilliseconds 120000
            break
        }
        catch {
            # A document can navigate after readiness but before the read.
            # Retry only a confirmed browser lifecycle loss, never HTTP or unknown failures.
            if (-not $Url -or -not $BrowserState -or $attempt -gt 0 -or
                (-not (Test-SentinelContextLoss -ErrorRecord $_) -and
                    -not (Test-SentinelDetachedTargetError -ErrorRecord $_))) { throw }
            if (Test-SentinelDetachedTargetError -ErrorRecord $_) {
                if (-not (Restore-SentinelControlledTarget -Client $Client -BrowserState $BrowserState)) { throw }
            }
            else {
                $BrowserState.Contexts.Remove("$sessionId|$($parameters.contextId)")
                $BrowserState.Active = $null
            }
            $deadline = (Get-Date).AddSeconds(60)
            while ($true) {
                Update-SentinelBrowserContexts -Client $Client -BrowserState $BrowserState
                if (Find-SentinelReadyContext -Client $Client -BrowserState $BrowserState) { break }
                if ((Get-Date) -ge $deadline) {
                    throw 'Sentinel could not reacquire a verified authenticated context after navigation.'
                }
                Start-Sleep -Milliseconds 250
            }
            $parameters.contextId = [int]$BrowserState.Active.ContextId
            $sessionId = [string]$BrowserState.Active.SessionId
            if (-not $BrowserState.ContainsKey('RecoveredContextCount')) { $BrowserState.RecoveredContextCount = 0 }
            $BrowserState.RecoveredContextCount++
        }
    }
    if ($null -eq $result) {
        throw 'Sentinel DevTools reply was empty.'
    }
    if ($result.PSObject.Properties['exceptionDetails']) {
        $exception = New-Object InvalidOperationException 'Sentinel browser execution failed. No authentication data was saved.'
        $details = $result.exceptionDetails
        $remoteException = $details.PSObject.Properties['exception']
        if ($remoteException -and $remoteException.Value -and
            $remoteException.Value.PSObject.Properties['className'] -and
            $remoteException.Value.className -in @('Error', 'TypeError', 'SyntaxError', 'ReferenceError', 'RangeError', 'EvalError', 'URIError')) {
            $exception.Data['BrowserExceptionType'] = [string]$remoteException.Value.className
        }
        throw $exception
    }
    $remoteResult = $result.PSObject.Properties['result']
    if ($null -eq $remoteResult -or $null -eq $remoteResult.Value) {
        throw 'Sentinel DevTools reply did not contain a remote result.'
    }
    $remoteValue = $remoteResult.Value.PSObject.Properties['value']
    $remoteType = $remoteResult.Value.PSObject.Properties['type']
    if ($null -eq $remoteValue -or $remoteValue.Value -isnot [string] -or
        $null -eq $remoteType -or $remoteType.Value -ne 'string') {
        throw 'Sentinel DevTools reply did not contain a serialized browser response.'
    }
    try { $reply = $remoteValue.Value | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Sentinel DevTools reply contained invalid serialized response JSON.' }
    if ($null -eq $reply -or $reply -isnot [pscustomobject]) {
        throw 'Sentinel DevTools reply did not contain a browser response object.'
    }
    $status = $reply.PSObject.Properties['status']
    $knownStatuses = @('ready', 'waiting', 'wrongIdentity', 'wrongPortal', 'unsafeUrl',
        'authUnavailable', 'httpError', 'ok', 'browserRequestFailed', 'observerUnavailable',
        'apiVersionSelected', 'unsupportedProviderMetadata', 'apiVersionUnavailable')
    if ($null -eq $status -or $status.Value -isnot [string] -or $status.Value -notin $knownStatuses) {
        throw 'Sentinel DevTools reply contained an unsupported browser status.'
    }
    if ($reply.status -eq 'ok' -and (
        -not $reply.PSObject.Properties['body'] -or $reply.body -isnot [string])) {
        throw 'Sentinel DevTools reply did not contain a JSON response body.'
    }
    if ($reply.status -eq 'httpError' -and (
        -not $reply.PSObject.Properties['httpStatus'] -or
        [string]$reply.httpStatus -notmatch '^[1-5][0-9]{2}$')) {
        throw 'Sentinel DevTools reply contained an invalid HTTP status.'
    }
    if ($Url -and $reply.status -in @('ready', 'waiting')) {
        throw 'Sentinel DevTools list reply contained a readiness status instead of a response.'
    }
    return $reply
}

function Resolve-SentinelApiVersion {
    param([CustomDetections.CdpClient]$Client, [object]$Target, [hashtable]$BrowserState)
    if (-not $Target.RequiresApiVersionDiscovery) { return }
    $reply = Invoke-SentinelBrowserRequest -Client $Client -Url 'discoverApiVersion' -BrowserState $BrowserState
    if ($reply.status -ne 'apiVersionSelected') {
        $message = 'Sentinel Government API version discovery failed. Supply SentinelApiVersion only with a version confirmed for the selected Government workspace.'
        if ($reply.status -eq 'httpError') { $message += " HTTP $($reply.httpStatus)." }
        $exception = New-Object InvalidOperationException $message
        $exception.Data['BrowserStatus'] = [string]$reply.status
        if ($reply.status -eq 'httpError') { $exception.Data['HttpStatus'] = [int]$reply.httpStatus }
        throw $exception
    }
    if (-not $reply.PSObject.Properties['apiVersion'] -or $reply.apiVersion -isnot [string]) {
        throw 'Sentinel Government API version discovery returned an invalid version.'
    }
    Assert-SentinelApiVersion -Version $reply.apiVersion
    if ($reply.apiVersion.EndsWith('-preview')) {
        throw 'Sentinel Government API version discovery returned an invalid version.'
    }
    $Target.ApiVersion = $reply.apiVersion
    $Target.ListUrl = "https://$($Target.ArmHost)$($Target.CollectionPath)?api-version=$($Target.ApiVersion)"
    $Target.RequiresApiVersionDiscovery = $false
    $Target.ApiVersionSource = 'SubscriptionProviderMetadata'
    Assert-SentinelListUrl -Url $Target.ListUrl -Target $Target
}

function Test-SentinelFrameUrl {
    param([string]$Url, [object]$Target)

    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or -not $uri.IsDefaultPort -or $uri.UserInfo) {
        return $false
    }
    return $uri.GetLeftPart([UriPartial]::Authority) -in $Target.BrowserOrigins
}

function Remove-SentinelSessionContexts {
    param([hashtable]$BrowserState, [string]$SessionId)

    foreach ($key in @($BrowserState.Contexts.Keys)) {
        if ($BrowserState.Contexts[$key].SessionId -eq $SessionId) {
            $BrowserState.Contexts.Remove($key)
        }
    }
    if ($BrowserState.Active -and $BrowserState.Active.SessionId -eq $SessionId) {
        $BrowserState.Active = $null
    }
}

function Test-SentinelDetachedTargetError {
    param([Management.Automation.ErrorRecord]$ErrorRecord)
    return (Get-CdpFailureReason -ErrorRecord $ErrorRecord) -eq 'SessionUnavailable' -or
        $ErrorRecord.Exception.Message -match 'No session with given id|Session with given id not found|Target closed|Session closed|No target with given id found'
}

function Get-CdpFailureReason {
    param([Management.Automation.ErrorRecord]$ErrorRecord)
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception.Data.Contains('CdpReason')) { return [string]$exception.Data['CdpReason'] }
        $exception = $exception.InnerException
    }
    return ''
}

function Test-SentinelContextLoss {
    param([Management.Automation.ErrorRecord]$ErrorRecord)
    return (Get-CdpFailureReason -ErrorRecord $ErrorRecord) -eq 'ContextUnavailable' -or
        $ErrorRecord.Exception.Message -match '^(Execution context was destroyed\.?|Cannot find context with specified id\.?|Cannot find default execution context\.?|Cannot find execution context\.?)$'
}

function Restore-SentinelControlledTarget {
    param([CustomDetections.CdpClient]$Client, [hashtable]$BrowserState)

    # Never choose another tab, endpoint, account, or an arbitrary matching portal.
    # Target.getTargetInfo must still identify the exact page selected at launch.
    if (-not $BrowserState.ContainsKey('ControlledTargetId') -or
        [string]::IsNullOrWhiteSpace($BrowserState.ControlledTargetId)) { return $false }
    try {
        $description = Invoke-CdpCommand -Client $Client -Method 'Target.getTargetInfo' -Parameters @{
            targetId = $BrowserState.ControlledTargetId
        }
    }
    catch {
        if (Test-SentinelDetachedTargetError -ErrorRecord $_) { return $false }
        throw
    }
    $info = $description.PSObject.Properties['targetInfo']
    if (-not $info -or -not $info.Value -or
        -not $info.Value.PSObject.Properties['targetId'] -or
        -not $info.Value.PSObject.Properties['type'] -or
        -not $info.Value.PSObject.Properties['url'] -or
        $info.Value.targetId -cne $BrowserState.ControlledTargetId -or
        $info.Value.type -ne 'page' -or
        -not (Test-SentinelFrameUrl -Url $info.Value.url -Target $BrowserState.Target) -or
        ([Uri]$info.Value.url).Host -ine $BrowserState.Target.PortalHost) { return $false }

    $oldRootSession = if ($BrowserState.ContainsKey('RootSessionId')) {
        [string]$BrowserState.RootSessionId
    } else { '' }
    # Turning off auto attachment detaches its old child sessions. They must not
    # remain eligible after a renderer swap or resume paused foreign descendants.
    try {
        Invoke-CdpCommand -Client $Client -Method 'Target.setAutoAttach' -SessionId $oldRootSession `
            -Parameters @{ autoAttach = $false; waitForDebuggerOnStart = $false; flatten = $true } | Out-Null
    }
    catch { if (-not (Test-SentinelDetachedTargetError -ErrorRecord $_)) { throw } }
    $attached = Invoke-CdpCommand -Client $Client -Method 'Target.attachToTarget' -Parameters @{
        targetId = $BrowserState.ControlledTargetId; flatten = $true
    }
    if (-not $attached.PSObject.Properties['sessionId'] -or
        [string]::IsNullOrWhiteSpace([string]$attached.sessionId)) {
        throw 'Sentinel recovery did not return a controlled target session.'
    }
    $newRootSession = [string]$attached.sessionId
    $BrowserState.Contexts.Clear()
    $BrowserState.Sessions.Clear()
    $BrowserState.Active = $null
    $BrowserState.RootSessionId = $newRootSession
    $BrowserState.Sessions[$newRootSession] = $true
    Invoke-CdpCommand -Client $Client -Method 'Page.enable' -SessionId $newRootSession | Out-Null
    Invoke-CdpCommand -Client $Client -Method 'Page.addScriptToEvaluateOnNewDocument' -SessionId $newRootSession `
        -Parameters @{ source = $BrowserState.Observer } | Out-Null
    Invoke-CdpCommand -Client $Client -Method 'Runtime.disable' -SessionId $newRootSession | Out-Null
    Invoke-CdpCommand -Client $Client -Method 'Runtime.enable' -SessionId $newRootSession | Out-Null
    Invoke-CdpCommand -Client $Client -Method 'Target.setAutoAttach' -SessionId $newRootSession -Parameters @{
        autoAttach = $true; waitForDebuggerOnStart = $true; flatten = $true
    } | Out-Null
    return $true
}

function Update-SentinelBrowserContexts {
    param([CustomDetections.CdpClient]$Client, [hashtable]$BrowserState,
        [hashtable]$AuthenticationState)

    foreach ($event in @(Get-CdpEvents -Client $Client)) {
        $owner = if ($event.PSObject.Properties['sessionId']) { [string]$event.sessionId } else { '' }
        if ($event.method -eq 'Fetch.requestPaused' -and -not $owner -and
            $AuthenticationState -and $AuthenticationState.InterceptionEnabled) {
            Complete-TargetUserRequest -Client $Client -Event $event -AuthenticationState $AuthenticationState
        }
        elseif ($event.method -eq 'Target.attachedToTarget') {
            $sessionId = [string]$event.params.sessionId
            # The explicit recovery attachment also emits an attached event.
            if ($BrowserState.ContainsKey('RootSessionId') -and
                $sessionId -eq $BrowserState.RootSessionId -and
                $event.params.targetInfo.type -eq 'page' -and
                $event.params.targetInfo.targetId -ceq $BrowserState.ControlledTargetId) { continue }
            if ($event.params.targetInfo.type -ne 'iframe' -or
                -not $BrowserState.Sessions.ContainsKey($owner)) {
                try {
                    Invoke-CdpCommand -Client $Client -Method 'Runtime.runIfWaitingForDebugger' -SessionId $sessionId | Out-Null
                    Invoke-CdpCommand -Client $Client -Method 'Target.detachFromTarget' -SessionId $owner `
                        -Parameters @{ sessionId = $sessionId } | Out-Null
                }
                catch { if (-not (Test-SentinelDetachedTargetError $_)) { throw } }
                continue
            }
            # Attached iframe sessions are descendants of this controlled Edge page.
            # Preload only the origin guarded observer. Dispatch later requires a verified live frame URL.
            $BrowserState.Sessions[$sessionId] = $true
            try {
                Invoke-CdpCommand -Client $Client -Method 'Page.enable' -SessionId $sessionId | Out-Null
                Invoke-CdpCommand -Client $Client -Method 'Page.addScriptToEvaluateOnNewDocument' -SessionId $sessionId `
                    -Parameters @{ source = $BrowserState.Observer } | Out-Null
                Invoke-CdpCommand -Client $Client -Method 'Runtime.enable' -SessionId $sessionId | Out-Null
                Invoke-CdpCommand -Client $Client -Method 'Target.setAutoAttach' -SessionId $sessionId -Parameters @{
                    autoAttach = $true; waitForDebuggerOnStart = $true; flatten = $true
                } | Out-Null
                Invoke-CdpCommand -Client $Client -Method 'Runtime.runIfWaitingForDebugger' -SessionId $sessionId | Out-Null
            }
            catch {
                if (-not (Test-SentinelDetachedTargetError -ErrorRecord $_)) { throw }
                Remove-SentinelSessionContexts -BrowserState $BrowserState -SessionId $sessionId
                $BrowserState.Sessions.Remove($sessionId)
            }
        }
        elseif ($event.method -eq 'Target.detachedFromTarget') {
            $sessionId = [string]$event.params.sessionId
            Remove-SentinelSessionContexts -BrowserState $BrowserState -SessionId $sessionId
            $BrowserState.Sessions.Remove($sessionId)
        }
        elseif ($event.method -eq 'Runtime.executionContextsCleared') {
            Remove-SentinelSessionContexts -BrowserState $BrowserState -SessionId $owner
        }
        elseif ($event.method -eq 'Runtime.executionContextDestroyed') {
            $BrowserState.Contexts.Remove("$owner|$($event.params.executionContextId)")
            if ($BrowserState.Active -and $BrowserState.Active.SessionId -eq $owner -and
                $BrowserState.Active.ContextId -eq [int]$event.params.executionContextId) {
                $BrowserState.Active = $null
            }
        }
        elseif ($event.method -eq 'Runtime.executionContextCreated') {
            $context = $event.params.context
            $aux = $context.PSObject.Properties['auxData']
            if ($aux -and $aux.Value.PSObject.Properties['isDefault'] -and $aux.Value.isDefault -and
                $aux.Value.PSObject.Properties['frameId'] -and
                [string]$context.origin -in $BrowserState.Target.BrowserOrigins -and
                $BrowserState.Sessions.ContainsKey($owner)) {
                $BrowserState.Contexts["$owner|$($context.id)"] = @{
                    SessionId = $owner; ContextId = [int]$context.id
                    FrameId = [string]$aux.Value.frameId; Origin = [string]$context.origin
                }
            }
        }
    }
}

function Find-SentinelReadyContext {
    param([CustomDetections.CdpClient]$Client, [hashtable]$BrowserState)

    $frames = @{}
    $rootVerified = $false
    $rootSession = if ($BrowserState.ContainsKey('RootSessionId')) { [string]$BrowserState.RootSessionId } else { '' }
    foreach ($sessionId in @($BrowserState.Sessions.Keys)) {
        try {
            $tree = Invoke-CdpCommand -Client $Client -Method 'Page.getFrameTree' -SessionId $sessionId
        }
        catch {
            if (-not (Test-SentinelDetachedTargetError $_)) { throw }
            Remove-SentinelSessionContexts -BrowserState $BrowserState -SessionId $sessionId
            if ($sessionId -eq $rootSession) { return $false }
            $BrowserState.Sessions.Remove($sessionId)
            continue
        }
        if ($sessionId -eq $rootSession -and (Test-SentinelFrameUrl -Url $tree.frameTree.frame.url -Target $BrowserState.Target)) {
            $rootUri = [Uri]$tree.frameTree.frame.url
            $rootVerified = $rootUri.Host -ieq $BrowserState.Target.PortalHost
        }
        function Register-SentinelFrame {
            param([object]$Node)
            $frames["$sessionId|$($Node.frame.id)"] = [string]$Node.frame.url
            $children = $Node.PSObject.Properties['childFrames']
            if ($children) {
                foreach ($child in @($children.Value)) { Register-SentinelFrame -Node $child }
            }
        }
        Register-SentinelFrame -Node $tree.frameTree
    }
    if (-not $rootVerified) { return $false }
    foreach ($key in @($BrowserState.Contexts.Keys | Sort-Object)) {
        if (-not $BrowserState.Contexts.ContainsKey($key)) { continue }
        $context = $BrowserState.Contexts[$key]
        $frameKey = "$($context.SessionId)|$($context.FrameId)"
        if (-not $frames.ContainsKey($frameKey) -or
            -not (Test-SentinelFrameUrl -Url $frames[$frameKey] -Target $BrowserState.Target) -or
            ([Uri]$frames[$frameKey]).GetLeftPart([UriPartial]::Authority) -ne $context.Origin) {
            continue
        }
        try {
            # Newly attached frames may already have a document. Install the same guarded observer there.
            $installation = Invoke-CdpCommand -Client $Client -Method 'Runtime.evaluate' -SessionId $context.SessionId -Parameters @{
                expression = "(() => { if (typeof window.__sentinelExporter !== 'function') { $($BrowserState.Observer); } return true; })()"
                contextId = $context.ContextId; returnByValue = $true
            }
            if ($installation.PSObject.Properties['exceptionDetails']) {
                throw 'Sentinel observer installation failed in a verified browser context.'
            }
            $BrowserState.Active = $context
            $state = Invoke-SentinelBrowserRequest -Client $Client -Url '' -BrowserState $BrowserState
            if ($state.status -eq 'ready') { return $true }
            if ($state.status -eq 'wrongIdentity') {
                throw 'Sentinel portal ARM request used a different tenant, audience, or expired token.'
            }
        }
        catch {
            if (Test-SentinelDetachedTargetError -ErrorRecord $_) {
                Remove-SentinelSessionContexts -BrowserState $BrowserState -SessionId $context.SessionId
                if ($context.SessionId -ne $rootSession) { $BrowserState.Sessions.Remove($context.SessionId) }
            }
            elseif (-not (Test-SentinelContextLoss -ErrorRecord $_)) {
                throw
            }
            $BrowserState.Contexts.Remove($key)
        }
    }
    $BrowserState.Active = $null
    return $false
}

function Get-SentinelFailureDiagnostic {
    param([Management.Automation.ErrorRecord]$ErrorRecord, [string]$Stage)

    $exception = $ErrorRecord.Exception
    while ($null -ne $exception.InnerException) { $exception = $exception.InnerException }
    $type = $exception.GetType().FullName
    $line = $ErrorRecord.InvocationInfo.ScriptLineNumber
    $safeMessages = @(
        'Sentinel recovery did not return a controlled target session.',
        'Sentinel could not identify the original controlled Edge page.',
        'Sentinel Government API version discovery returned an invalid version.',
        'Sentinel DevTools reply was empty.',
        'Sentinel has no verified active browser context.',
        'Sentinel observer installation failed in a verified browser context.',
        'Sentinel DevTools reply did not contain a remote result.',
        'Sentinel DevTools reply did not contain a browser response object.',
        'Sentinel DevTools reply did not contain a serialized browser response.',
        'Sentinel DevTools reply contained invalid serialized response JSON.',
        'Sentinel DevTools reply contained an unsupported browser status.',
        'Sentinel DevTools reply did not contain a JSON response body.',
        'Sentinel DevTools reply contained an invalid HTTP status.',
        'Sentinel DevTools list reply contained a readiness status instead of a response.',
        'Sentinel browser execution failed. No authentication data was saved.',
        'Sentinel pagination left the selected cloud or workspace. No request was sent.',
        'Sentinel pagination changed the API version. No request was sent.',
        'Sentinel pagination repeated a page or exceeded the page limit.',
        'Unsupported Sentinel list envelope. Expected an object containing a value array.',
        'Unsupported Sentinel rule or resource outside the selected workspace.',
        'Sentinel returned a duplicate rule ID. Export is incomplete.',
        'Unsupported Sentinel nextLink.',
        'Sentinel portal ARM request used a different tenant, audience, or expired token.',
        'Sentinel portal did not expose authenticated ARM fetch or XHR in a verified portal context before timeout. Open Analytics in the selected workspace. No alternate authentication was attempted.',
        'Sentinel account confirmation did not match. No Sentinel rules were exported.',
        'Sentinel could not reacquire a verified authenticated context after navigation.'
    )
    $rawMessage = $ErrorRecord.Exception.Message
    $message = 'Sentinel operation failed.'
    if ($rawMessage -in $safeMessages -or
        $exception.Data.Contains('CdpReason') -or
        $rawMessage -match '^Sentinel list request failed: HTTP [1-5][0-9]{2}\. Check portal sign in and workspace RBAC\.$' -or
        $rawMessage -match '^Sentinel browser request failed: (wrongPortal|unsafeUrl|authUnavailable|httpError|browserRequestFailed|observerUnavailable|wrongIdentity|unsupportedProviderMetadata|apiVersionUnavailable)\. No alternate authentication was attempted\.$' -or
        $rawMessage -match '^Sentinel Government API version discovery failed\. Supply SentinelApiVersion only with a version confirmed for the selected Government workspace\.( HTTP [1-5][0-9]{2}\.)?$') {
        $message = if ($exception.Data.Contains('CdpReason')) { $exception.Message } else { $rawMessage }
    }
    $diagnostic = [ordered]@{
        stage = $Stage
        exceptionType = $type
        scriptLineNumber = $line
        category = [string]$ErrorRecord.CategoryInfo.Category
        message = $message
    }
    if ($exception.Data.Contains('CdpReason')) {
        $diagnostic.cdpReason = $exception.Data['CdpReason']
        $diagnostic.cdpMethod = $exception.Data['CdpMethod']
        $diagnostic.cdpCode = $exception.Data['CdpCode']
        if ($exception.Data.Contains('CdpMessage')) { $diagnostic.cdpMessage = $exception.Data['CdpMessage'] }
    }
    if ($exception.Data.Contains('BrowserStatus')) {
        $diagnostic.browserStatus = $exception.Data['BrowserStatus']
        if ($exception.Data.Contains('HttpStatus')) { $diagnostic.httpStatus = $exception.Data['HttpStatus'] }
    }
    if ($exception.Data.Contains('BrowserExceptionType')) {
        $diagnostic.browserExceptionType = $exception.Data['BrowserExceptionType']
    }
    [pscustomobject]$diagnostic
}

function Write-NewExportFile {
    param([string]$Path, [AllowEmptyString()][string]$Content)

    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally { $stream.Dispose() }
}

function Initialize-ExportDirectory {
    param([string]$Path, [string[]]$ProtectedPaths)

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    Assert-NoReparseAncestors -Path $fullPath
    foreach ($protected in $ProtectedPaths) {
        $protectedPath = [IO.Path]::GetFullPath($protected).TrimEnd('\', '/')
        if ($fullPath -ieq $protectedPath -or
            $protectedPath.StartsWith($fullPath + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($protectedPath + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'OutputPath overlaps a protected source or browser profile path.'
        }
    }
    # No Force: an existing directory, file or link must never be reused.
    New-Item -ItemType Directory -Path $fullPath -ErrorAction Stop | Out-Null
}

function Assert-NoReparseAncestors {
    param([string]$Path)

    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'A browser profile or output ancestor is a filesystem link. Use an isolated ordinary directory.'
            }
        }
        $parent = Split-Path $current -Parent
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function Export-SentinelRules {
    param([CustomDetections.CdpClient]$Client, [object]$Target, [string]$OutputPath,
        [string[]]$RuleNames, [hashtable]$BrowserState)

    $capturePath = Join-Path $OutputPath 'captures'
    $rulePath = Join-Path $OutputPath 'rules'
    New-Item -ItemType Directory -Path $capturePath -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path $rulePath -ErrorAction Stop | Out-Null
    $rules = New-Object System.Collections.Generic.List[object]
    $captures = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    $failureDetails = New-Object System.Collections.Generic.List[object]
    $seenUrls = New-Object 'System.Collections.Generic.HashSet[string]'
    $seenIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $usedNames = @{}
    $requested = @($RuleNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Split(',') } |
        ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    $matched = @{}
    $url = $Target.ListUrl
    $pageNumber = 0
    $stage = 'ValidateListUrl'
    try {
        while ($url) {
            $stage = 'ValidateListUrl'
            Assert-SentinelListUrl -Url $url -Target $Target
            if (-not $seenUrls.Add($url) -or $pageNumber -ge 10000) {
                throw 'Sentinel pagination repeated a page or exceeded the page limit.'
            }
            $stage = 'RequestListPage'
            $reply = Invoke-SentinelBrowserRequest -Client $Client -Url $url -BrowserState $BrowserState
            if ($reply.status -ne 'ok') {
                if ($reply.status -eq 'httpError') {
                    $exception = New-Object InvalidOperationException "Sentinel list request failed: HTTP $($reply.httpStatus). Check portal sign in and workspace RBAC."
                    $exception.Data['BrowserStatus'] = 'httpError'
                    $exception.Data['HttpStatus'] = [int]$reply.httpStatus
                    throw $exception
                }
                $exception = New-Object InvalidOperationException "Sentinel browser request failed: $($reply.status). No alternate authentication was attempted."
                $exception.Data['BrowserStatus'] = [string]$reply.status
                throw $exception
            }
            $stage = 'ParseListPage'
            $page = $reply.body | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $page -or $page -is [Array] -or
                -not $page.PSObject.Properties['value'] -or $page.value -isnot [Array]) {
                throw 'Unsupported Sentinel list envelope. Expected an object containing a value array.'
            }
            $pageNumber++
            $stage = 'ValidateRuleResources'
            # Validate every resource before writing this page, including rules excluded by a name filter.
            foreach ($rule in $page.value) {
                if ($null -eq $rule -or -not $rule.PSObject.Properties['id'] -or
                    -not $rule.PSObject.Properties['kind'] -or
                    -not $rule.PSObject.Properties['properties'] -or
                    $rule.properties -isnot [pscustomobject] -or
                    -not $rule.PSObject.Properties['name'] -or
                    -not $rule.PSObject.Properties['type'] -or
                    $rule.type -ine 'Microsoft.SecurityInsights/alertRules' -or
                    [string]::IsNullOrWhiteSpace([string]$rule.kind) -or
                    [string]::IsNullOrWhiteSpace([string]$rule.name) -or
                    [string]$rule.id -ine ($Target.CollectionPath + '/' + [Uri]::EscapeDataString([string]$rule.name))) {
                    throw 'Unsupported Sentinel rule or resource outside the selected workspace.'
                }
                if (-not $seenIds.Add([string]$rule.id)) {
                    throw 'Sentinel returned a duplicate rule ID. Export is incomplete.'
                }
            }
            $captureFile = 'page-{0:D4}.json' -f $pageNumber
            $stage = 'SavePageCapture'
            # Preserve rule bodies, but never persist opaque pagination links.
            Write-NewExportFile -Path (Join-Path $capturePath $captureFile) -Content (
                ConvertTo-Json -InputObject @($page.value) -Depth 100)
            $captures.Add([pscustomobject]@{ file = "captures\$captureFile"; status = 200; ruleCount = $page.value.Count })
            foreach ($rule in $page.value) {
                $stage = 'SaveRuleFiles'
                $displayName = Get-CaseInsensitiveProperty -InputObject $rule.properties -Name @('displayName')
                if ([string]::IsNullOrWhiteSpace([string]$displayName)) { $displayName = [string]$rule.name }
                if ($requested.Count -gt 0 -and $displayName -notin $requested) { continue }
                $matched[[string]$displayName] = $true
                $baseName = ConvertTo-SafeFileName -Name $displayName
                $stem = $baseName
                $suffix = 2
                while ($usedNames.ContainsKey($stem)) { $stem = "$baseName-$suffix"; $suffix++ }
                $usedNames[$stem] = $true
                Write-NewExportFile -Path (Join-Path $rulePath "$stem.json") -Content (
                    ConvertTo-Json -InputObject $rule -Depth 100)
                $query = Get-CaseInsensitiveProperty -InputObject $rule.properties -Name @('query')
                $queryFile = $null
                if (-not [string]::IsNullOrWhiteSpace([string]$query)) {
                    $queryFile = "rules\$stem.kql"
                    Write-NewExportFile -Path (Join-Path $OutputPath $queryFile) -Content ([string]$query)
                }
                $rules.Add([pscustomobject]@{
                    name = $displayName; key = $rule.id; kind = $rule.kind
                    file = "rules\$stem.json"; queryFile = $queryFile
                })
            }
            $next = $page.PSObject.Properties['nextLink']
            $stage = 'ReadNextLink'
            if ($next -and $null -ne $next.Value -and $next.Value -isnot [string]) {
                throw 'Unsupported Sentinel nextLink.'
            }
            $url = if ($next) { [string]$next.Value } else { $null }
        }
    }
    catch {
        # Keep stage, original exception type and source line, but never raw exception text or JSON.
        $diagnostic = Get-SentinelFailureDiagnostic -ErrorRecord $_ -Stage $stage
        $failureDetails.Add($diagnostic)
        $errors.Add(('{0} Stage: {1}; exception: {2}; line: {3}.' -f
            $diagnostic.message, $diagnostic.stage, $diagnostic.exceptionType, $diagnostic.scriptLineNumber))
    }
    $unmatched = @($requested | Where-Object { -not $matched.ContainsKey($_) })
    $manifest = [pscustomobject]@{
        exportedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        source = 'Sentinel'; tenantId = $Target.TenantId; workspaceResourceId = $Target.ResourceId
        apiVersion = $Target.ApiVersion; apiVersionSource = $Target.ApiVersionSource
        ruleCount = $rules.Count; captureCount = $captures.Count
        browserOrigin = if ($BrowserState -and $BrowserState.Active) { $BrowserState.Active.Origin } else { $null }
        browserContextRecoveries = if ($BrowserState -and $BrowserState.ContainsKey('RecoveredContextCount')) {
            $BrowserState.RecoveredContextCount
        } else { 0 }
        complete = ($errors.Count -eq 0 -and $unmatched.Count -eq 0)
        requestedRuleNames = $requested; unmatchedRuleNames = $unmatched
        errors = $errors.ToArray(); failureDetails = $failureDetails.ToArray()
        rules = $rules.ToArray(); captures = $captures.ToArray()
    }
    Write-NewExportFile -Path (Join-Path $OutputPath 'manifest.json') -Content (
        ConvertTo-Json -InputObject $manifest -Depth 100)
    return $manifest
}

function ConvertTo-SafeFileName {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Name,

        [int]$MaximumLength = 100
    )

    $invalidCharacters = [IO.Path]::GetInvalidFileNameChars()
    $escapedCharacters = [Regex]::Escape((-join $invalidCharacters))
    $safeName = [Regex]::Replace($Name, "[$escapedCharacters]", '_')
    $safeName = [Regex]::Replace($safeName, '\s+', ' ').Trim().TrimEnd('.')
    if ($safeName -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
        $safeName = '_' + $safeName
    }

    if ([string]::IsNullOrWhiteSpace($safeName)) {
        $safeName = 'unnamed-rule'
    }
    if ($safeName.Length -gt $MaximumLength) {
        $safeName = $safeName.Substring(0, $MaximumLength).Trim()
    }

    return $safeName
}

function Get-CaseInsensitiveProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    foreach ($candidate in $Name) {
        $property = $InputObject.PSObject.Properties |
            Where-Object { $_.Name -ieq $candidate } |
            Select-Object -First 1
        if ($null -ne $property -and $null -ne $property.Value) {
            return $property.Value
        }
    }

    return $null
}

function Test-CustomDetectionRule {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )

    if ($null -eq $InputObject -or $InputObject -is [string] -or
        $InputObject -is [ValueType] -or $InputObject -is [System.Collections.IDictionary]) {
        return $false
    }

    $name = Get-CaseInsensitiveProperty -InputObject $InputObject -Name @(
        'displayName', 'ruleName', 'name', 'title'
    )
    $query = Get-CaseInsensitiveProperty -InputObject $InputObject -Name @(
        'query', 'queryText', 'detectionQuery', 'queryCondition', 'kql'
    )
    if ([string]::IsNullOrWhiteSpace([string]$query)) {
        $huntingQuery = Get-CaseInsensitiveProperty -InputObject $InputObject -Name @('huntingQuery')
        if ($null -ne $huntingQuery) {
            $query = Get-CaseInsensitiveProperty -InputObject $huntingQuery -Name @('queryText', 'query')
        }
    }
    $identifier = Get-CaseInsensitiveProperty -InputObject $InputObject -Name @(
        'id', 'ruleId', 'detectionRuleId', 'customDetectionId'
    )
    $schedule = Get-CaseInsensitiveProperty -InputObject $InputObject -Name @(
        'frequency', 'frequencyInMinutes', 'schedulingType', 'schedule', 'period', 'lookback'
    )
    $resourceType = Get-CaseInsensitiveProperty -InputObject $InputObject -Name @('usxResourceType')

    return (
        -not [string]::IsNullOrWhiteSpace([string]$name) -and
        -not [string]::IsNullOrWhiteSpace([string]$query) -and
        ($null -ne $identifier -or $null -ne $schedule) -and
        ([string]::IsNullOrWhiteSpace([string]$resourceType) -or
            [string]$resourceType -eq 'DefenderCustomDetectionRule')
    )
}

function Find-CustomDetectionRule {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )

    $results = New-Object System.Collections.Generic.List[object]
    $visited = New-Object 'System.Collections.Generic.HashSet[int]'

    function Visit-Value {
        param([object]$Value)

        if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) {
            return
        }

        $identity = [Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Value)
        if (-not $visited.Add($identity)) {
            return
        }
        if (Test-CustomDetectionRule -InputObject $Value) {
            $results.Add($Value)
        }

        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($item in $Value.Values) {
                Visit-Value -Value $item
            }
            return
        }
        if ($Value -is [System.Collections.IEnumerable]) {
            foreach ($item in $Value) {
                Visit-Value -Value $item
            }
            return
        }

        foreach ($property in $Value.PSObject.Properties) {
            if ($property.MemberType -in @('NoteProperty', 'Property')) {
                Visit-Value -Value $property.Value
            }
        }
    }

    Visit-Value -Value $InputObject
    return $results.ToArray()
}

function Get-StableRuleKey {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $identifier = Get-CaseInsensitiveProperty -InputObject $Rule -Name @(
        'id', 'ruleId', 'detectionRuleId', 'customDetectionId'
    )
    if (-not [string]::IsNullOrWhiteSpace([string]$identifier)) {
        return "id:$identifier"
    }

    $json = $Rule | ConvertTo-Json -Depth 100 -Compress
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        return 'sha256:' + (($sha256.ComputeHash($bytes) | ForEach-Object {
            $_.ToString('x2')
        }) -join '')
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-RuleDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $name = Get-CaseInsensitiveProperty -InputObject $Rule -Name @(
        'displayName', 'ruleName', 'name', 'title'
    )
    if ([string]::IsNullOrWhiteSpace([string]$name)) {
        return 'unnamed-rule'
    }

    return [string]$name
}

function Get-RuleQueryText {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $query = Get-CaseInsensitiveProperty -InputObject $Rule -Name @(
        'query', 'queryText', 'detectionQuery', 'queryCondition', 'kql'
    )
    if ([string]::IsNullOrWhiteSpace([string]$query)) {
        $huntingQuery = Get-CaseInsensitiveProperty -InputObject $Rule -Name @('huntingQuery')
        if ($null -ne $huntingQuery) {
            $query = Get-CaseInsensitiveProperty -InputObject $huntingQuery -Name @(
                'queryText', 'query'
            )
        }
    }

    return [string]$query
}

function Resolve-EdgeExecutable {
    $candidatePaths = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\Application\msedge.exe')
    )

    $edgePath = $candidatePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($edgePath)) {
        throw 'Microsoft Edge was not found. Install Edge or update Resolve-EdgeExecutable with its path.'
    }

    return $edgePath
}

function Invoke-CdpCommand {
    param(
        [Parameter(Mandatory = $true)]
        [CustomDetections.CdpClient]$Client,

        [Parameter(Mandatory = $true)]
        [string]$Method,

        [hashtable]$Parameters = @{},

        [int]$TimeoutMilliseconds = 30000,

        [string]$SessionId
    )

    $parametersJson = $Parameters | ConvertTo-Json -Depth 20 -Compress
    $responseJson = if ($SessionId) {
        $Client.Call($Method, $parametersJson, $TimeoutMilliseconds, $SessionId)
    } else {
        $Client.Call($Method, $parametersJson, $TimeoutMilliseconds)
    }
    return ConvertFrom-CdpResponse -ResponseJson $responseJson -Method $Method
}

function ConvertFrom-CdpResponse {
    param([string]$ResponseJson, [string]$Method)
    $response = $ResponseJson | ConvertFrom-Json -ErrorAction Stop
    $errorProperty = $response.PSObject.Properties['error']
    if ($null -ne $errorProperty) {
        $protocolError = $errorProperty.Value
        $reason = switch -Regex ([string]$protocolError.message) {
            '^(Execution context was destroyed\.?|Execution context with given id not found\.?|Cannot find context with specified (unique )?id\.?|Cannot find context with id [0-9]+\.?|Cannot find execution context with specified id\.?|Cannot find default execution context\.?|Cannot find execution context\.?)$' { 'ContextUnavailable'; break }
            '^Promise was collected\.?$' { 'PromiseCollected'; break }
            '^(Object couldn.t be returned by value\.?|Object reference chain is too long\.?)$' { 'SerializationFailed'; break }
            '^Invalid parameters\.?$' { 'InvalidParameters'; break }
            '^(No session with given id|Session with given id not found|Target closed|Session closed|No target with given id found|Inspected target navigated or closed)\.?$' { 'SessionUnavailable'; break }
            default { 'OtherProtocolError' }
        }
        $exception = New-Object InvalidOperationException "DevTools command '$Method' failed: $reason."
        $exception.Data['CdpReason'] = $reason
        $exception.Data['CdpMethod'] = $Method
        if ($reason -ne 'OtherProtocolError') { $exception.Data['CdpMessage'] = [string]$protocolError.message }
        $codeProperty = $protocolError.PSObject.Properties['code']
        $exception.Data['CdpCode'] = if ($codeProperty -and
            ($codeProperty.Value -is [int] -or $codeProperty.Value -is [long])) {
            [int]$codeProperty.Value
        } else { $null }
        throw $exception
    }

    return $response.PSObject.Properties['result'].Value
}

function Get-AvailableTcpPort {
    $listener = New-Object Net.Sockets.TcpListener ([Net.IPAddress]::Loopback), 0
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Get-EdgeProfile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserDataPath
    )

    $profiles = New-Object System.Collections.Generic.List[object]
    $localStatePath = Join-Path $UserDataPath 'Local State'

    if (Test-Path -LiteralPath $localStatePath) {
        try {
            $localState = Get-Content -LiteralPath $localStatePath -Raw | ConvertFrom-Json
            $infoCache = $localState.profile.info_cache
            if ($null -ne $infoCache) {
                foreach ($property in $infoCache.PSObject.Properties) {
                    $directory = [string]$property.Name
                    if ($directory -eq 'Default' -or $directory -match '^Profile \d+$') {
                        $displayName = [string]$property.Value.name
                        if ([string]::IsNullOrWhiteSpace($displayName)) {
                            $displayName = $directory
                        }

                        $profiles.Add([pscustomobject]@{
                            Directory = $directory
                            Name = $displayName
                        })
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not read Edge profile names from Local State: $($_.Exception.Message)"
        }
    }

    foreach ($directory in @(Get-ChildItem -LiteralPath $UserDataPath -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'Default' -or $_.Name -match '^Profile \d+$' })) {
        if (-not ($profiles | Where-Object { $_.Directory -eq $directory.Name })) {
            $profiles.Add([pscustomobject]@{
                Directory = $directory.Name
                Name = $directory.Name
            })
        }
    }

    return @($profiles | Sort-Object @{
        Expression = {
            if ($_.Directory -eq 'Default') {
                0
            }
            else {
                [int]($_.Directory -replace '^Profile ', '') + 1
            }
        }
    })
}

function Select-EdgeProfileDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserDataPath
    )

    $profiles = @(Get-EdgeProfile -UserDataPath $UserDataPath)
    if ($profiles.Count -eq 0) {
        throw "No Edge profiles were found beneath '$UserDataPath'."
    }

    Write-Host 'Available Microsoft Edge profiles:' -ForegroundColor Cyan
    for ($index = 0; $index -lt $profiles.Count; $index++) {
        Write-Host ('  [{0}] {1} ({2})' -f
            ($index + 1),
            $profiles[$index].Name,
            $profiles[$index].Directory)
    }

    while ($true) {
        $selection = Read-Host "Select an Edge profile [1-$($profiles.Count)]"
        $selectionNumber = 0
        if ([int]::TryParse($selection, [ref]$selectionNumber) -and
            $selectionNumber -ge 1 -and
            $selectionNumber -le $profiles.Count) {
            return [string]$profiles[$selectionNumber - 1].Directory
        }

        Write-Warning "Enter a number from 1 through $($profiles.Count)."
    }
}

function Copy-EdgeProfile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot,

        [Parameter(Mandatory = $true)]
        [string]$DestinationRoot,

        [Parameter(Mandatory = $true)]
        [string]$ProfileDirectory
    )

    $sourceProfilePath = Join-Path $SourceRoot $ProfileDirectory
    if (-not (Test-Path -LiteralPath $sourceProfilePath)) {
        throw "The Edge profile directory '$sourceProfilePath' does not exist."
    }

    $currentSessionId = (Get-Process -Id $PID).SessionId
    $runningEdge = @(Get-Process -Name msedge -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $currentSessionId })
    if ($runningEdge.Count -gt 0) {
        $processIds = ($runningEdge | Select-Object -ExpandProperty Id) -join ', '
        throw "Close Microsoft Edge windows in your own Windows session before importing a profile. Running Edge process IDs in this session: $processIds"
    }

    New-Item -ItemType Directory -Path $DestinationRoot -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $SourceRoot 'Local State') -Destination $DestinationRoot -Force

    $destinationProfilePath = Join-Path $DestinationRoot $ProfileDirectory
    New-Item -ItemType Directory -Path $destinationProfilePath -Force | Out-Null

    $excludedDirectories = @(
        'Cache',
        'Code Cache',
        'GPUCache',
        'GrShaderCache',
        'DawnCache',
        'ShaderCache',
        'Service Worker\CacheStorage'
    )
    $arguments = @(
        $sourceProfilePath,
        $destinationProfilePath,
        '/E',
        '/R:1',
        '/W:1',
        '/NFL',
        '/NDL',
        '/NJH',
        '/NJS',
        '/NP',
        '/XF',
        'LOCK'
    )
    if ($excludedDirectories.Count -gt 0) {
        $arguments += '/XD'
        $arguments += $excludedDirectories | ForEach-Object { Join-Path $sourceProfilePath $_ }
    }

    & robocopy.exe @arguments | Out-Null
    if ($LASTEXITCODE -ge 8) {
        throw "Failed to import Edge profile '$ProfileDirectory'. Robocopy exit code: $LASTEXITCODE"
    }
}

function Get-CdpEvents {
    param(
        [Parameter(Mandatory = $true)]
        [CustomDetections.CdpClient]$Client
    )

    $message = $null
    while ($Client.TryTakeEvent([ref]$message)) {
        $event = $message | ConvertFrom-Json
        if ($event.method -eq 'CustomDetections.ConnectionError') {
            throw "The Edge DevTools connection failed: $($event.params.message)"
        }

        Write-Output $event
        $message = $null
    }
}

function Get-TargetUserAuthorizationUrl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or -not $uri.IsDefaultPort -or
        $uri.Host -notin @('login.microsoftonline.us', 'login.microsoftonline.com') -or
        $uri.AbsolutePath -notmatch '^/[^/]+/oauth2/(v2\.0/)?authorize/?$') {
        return $null
    }

    $parameters = New-Object System.Collections.Generic.List[string]
    foreach ($pair in $uri.Query.TrimStart('?').Split('&')) {
        if ([string]::IsNullOrEmpty($pair)) {
            continue
        }
        $name = [Uri]::UnescapeDataString(($pair -split '=', 2)[0].Replace('+', ' '))
        if ($name -notin @('login_hint', 'domain_hint', 'prompt', 'sid')) {
            $parameters.Add($pair)
        }
    }
    $parameters.Add('prompt=login')
    $parameters.Add('login_hint=' + [Uri]::EscapeDataString($UserPrincipalName))
    $builder = New-Object UriBuilder $uri
    $builder.Query = $parameters -join '&'
    return $builder.Uri.AbsoluteUri
}

function Complete-TargetUserRequest {
    param(
        [Parameter(Mandatory = $true)]
        [CustomDetections.CdpClient]$Client,

        [Parameter(Mandatory = $true)]
        [object]$Event,

        [Parameter(Mandatory = $true)]
        [hashtable]$AuthenticationState
    )

    $parameters = @{ requestId = [string]$Event.params.requestId }
    if ($Event.params.frameId -eq $AuthenticationState.FrameId -and
        $Event.params.resourceType -eq 'Document') {
        $targetUrl = Get-TargetUserAuthorizationUrl `
            -Url ([string]$Event.params.request.url) `
            -UserPrincipalName $AuthenticationState.UserPrincipalName
        if ($targetUrl) {
            if ($Event.params.request.method -ne 'GET') {
                throw 'Account targeting encountered an unsupported authorization request method. No export was performed.'
            }
            $parameters.url = $targetUrl
            $AuthenticationState.AuthorizationRequests++
            Write-Verbose 'Requesting an interactive Microsoft sign in for the selected account.'
        }
    }
    Invoke-CdpCommand -Client $Client -Method 'Fetch.continueRequest' -Parameters $parameters | Out-Null
}

function Confirm-TargetUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName
    )

    Write-Host 'Open the account menu INSIDE the Defender webpage, not the Edge toolbar.' -ForegroundColor Cyan
    Write-Host "Confirm that Defender shows '$UserPrincipalName'. No rules have been exported yet." -ForegroundColor Cyan
    $observedUser = Read-Host 'Enter the full account email shown inside Defender, or enter CANCEL'
    if (-not [string]::Equals($observedUser.Trim(), $UserPrincipalName, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The confirmed Defender account did not match the requested account. No export was performed.'
    }
}

function Add-NetworkEvents {
    param(
        [Parameter(Mandatory = $true)]
        [CustomDetections.CdpClient]$Client,

        [Parameter(Mandatory = $true)]
        [hashtable]$Requests,

        [Parameter(Mandatory = $true)]
        [hashtable]$Responses,

        [hashtable]$AuthenticationState
    )

    foreach ($event in @(Get-CdpEvents -Client $Client)) {
        if ($event.method -eq 'Fetch.requestPaused') {
            if ($null -eq $AuthenticationState) {
                throw 'An intercepted authentication request has no account selection context.'
            }
            if (-not $AuthenticationState.InterceptionEnabled) {
                Write-Verbose 'Skipping a queued sign in event already resumed by Fetch.disable.'
                continue
            }
            Complete-TargetUserRequest -Client $Client -Event $event -AuthenticationState $AuthenticationState
            continue
        }

        if ($event.method -eq 'Network.requestWillBeSent') {
            $Requests[[string]$event.params.requestId] = $event.params.request
            continue
        }

        if ($event.method -eq 'Network.requestWillBeSentExtraInfo') {
            $Requests["headers:$([string]$event.params.requestId)"] = $event.params.headers
            continue
        }

        if ($event.method -eq 'Network.responseReceived') {
            $response = $event.params.response
            $contentType = Get-CaseInsensitiveProperty -InputObject $response.headers -Name @('content-type')
            $isJson = ([string]$response.mimeType -match 'json') -or
                ([string]$contentType -match 'json')
            $isCandidateUrl = [string]$response.url -match '(?i)(custom.?detection|huntingService/rules)'
            $isFetch = [string]$event.params.type -in @('Fetch', 'XHR')

            if ($isJson -and $isFetch -and $isCandidateUrl) {
                $Responses[[string]$event.params.requestId] = $response
            }
        }
    }
}

function Get-PageState {
    param(
        [Parameter(Mandatory = $true)]
        [CustomDetections.CdpClient]$Client
    )

    $expression = @'
JSON.stringify({
  url: location.href,
  title: document.title,
  readyState: document.readyState,
  bodyText: document.body ? document.body.innerText.substring(0, 2000) : ""
})
'@
    $result = Invoke-CdpCommand -Client $Client -Method 'Runtime.evaluate' -Parameters @{
        expression = $expression
        returnByValue = $true
    }

    return $result.result.value | ConvertFrom-Json
}

function Get-PortalCustomDetections {
    param(
        [Parameter(Mandatory = $true)]
        [CustomDetections.CdpClient]$Client,

        [Parameter(Mandatory = $true)]
        [string]$ListUrl,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [string[]]$DetectionNames = @(),

        [Guid]$ExpectedTenantId
    )

    $listUrlBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ListUrl))
    $headersJson = $Headers | ConvertTo-Json -Compress
    $headersBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($headersJson))
    $detectionNameValues = @($DetectionNames | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_)
    })
    $detectionNamesJson = if ($detectionNameValues.Count -eq 0) {
        '[]'
    }
    else {
        ConvertTo-Json -InputObject $detectionNameValues -Compress
    }
    $detectionNamesBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($detectionNamesJson)
    )
    $expression = @'
(async () => {
  const tenantId = new URL(location.href).searchParams.get("tid");
  if (!tenantId) throw new Error("The portal URL does not contain a tenant ID.");

  const listUrl = new TextDecoder().decode(
    Uint8Array.from(atob("__LIST_URL_BASE64__"), character => character.charCodeAt(0))
  );
  if (new URL(listUrl, location.href).origin !== location.origin)
    throw new Error("The MDE list request left the selected portal.");
  if ("__EXPECTED_TENANT__" !== "00000000-0000-0000-0000-000000000000" &&
      tenantId.toLowerCase() !== "__EXPECTED_TENANT__")
    throw new Error("The MDE page tenant changed. No request was sent.");
  const headers = JSON.parse(new TextDecoder().decode(
    Uint8Array.from(atob("__HEADERS_BASE64__"), character => character.charCodeAt(0))
  ));
  const requestOptions = { credentials: "include", headers };
  const listResponse = await fetch(listUrl, requestOptions);
  if (!listResponse.ok) {
    throw new Error(`Rule list request failed: HTTP ${listResponse.status}`);
  }

  const list = await listResponse.json();
  if (!Array.isArray(list)) {
    throw new Error("The rule list response was not an array.");
  }

  // The unified portal list also includes Sentinel rules from other workspaces.
  // Only the observed Defender tuple belongs to this detail API.
  const sourceSelection = {
    defenderCount: 0, legacyCount: 0, excludedSentinelCount: 0, unsupportedCount: 0
  };
  const eligible = [];
  const errors = [];
  const metadataFields = ["UsxSourceType", "UsxResourceType", "SourceType"];
  for (let index = 0; index < list.length; index++) {
    const summary = list[index];
    let classification = "unsupported";
    if (summary && typeof summary === "object" && !Array.isArray(summary)) {
      const keys = Object.keys(summary);
      const fields = metadataFields.map(field =>
        keys.filter(key => key.toLowerCase() === field.toLowerCase()));
      const hasMetadata = fields.some(matches => matches.length > 0) ||
        keys.some(key => key.toLowerCase() === "detectionrulesource");
      if (!hasMetadata) {
        classification = "legacy";
      } else if (fields.every(matches => matches.length === 1)) {
        const [source, resource, sourceType] = fields.map(matches => summary[matches[0]]);
        if (source === "Defender" && resource === "DefenderCustomDetectionRule" && sourceType === 0)
          classification = "defender";
        else if (source === "LogAnalytics" && resource === "SentinelAnalyticsRule" && sourceType === 1)
          classification = "sentinel";
      }
    }
    if (classification === "defender" || classification === "legacy") {
      sourceSelection[classification === "defender" ? "defenderCount" : "legacyCount"]++;
      eligible.push(summary);
    } else if (classification === "sentinel") {
      sourceSelection.excludedSentinelCount++;
    } else {
      sourceSelection.unsupportedCount++;
      errors.push({ index, stage: "classifySummary",
        error: "Unsupported rule summary source metadata. No detail request was sent." });
    }
  }

  const rawRequestedNames = JSON.parse(new TextDecoder().decode(
    Uint8Array.from(atob("__DETECTION_NAMES_BASE64__"), character => character.charCodeAt(0))
  ));
  let requestedNames = rawRequestedNames.flatMap(value => {
    const text = String(value || "").trim();
    return text.includes(",") ? text.split(",").map(name => name.trim()).filter(Boolean) : [text];
  }).filter(Boolean);

  requestedNames = Array.from(new Map(
    requestedNames.map(name => [name.toLocaleLowerCase(), name])
  ).values());
  const requestedKeys = new Set(requestedNames.map(name => name.toLocaleLowerCase()));
  const selected = requestedNames.length === 0
    ? eligible
    : eligible.filter(rule => requestedKeys.has(
        String(rule.Name ?? rule.name ?? "").toLocaleLowerCase()
      ));
  const matchedKeys = new Set(selected.map(rule =>
    String(rule.Name ?? rule.name ?? "").toLocaleLowerCase()
  ));
  const notFound = requestedNames.filter(name => !matchedKeys.has(name.toLocaleLowerCase()));

  const rules = new Array(selected.length);
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const index = nextIndex++;
      if (index >= selected.length) return;

      const summary = selected[index];
      const id = summary.Id ?? summary.id;
      if (id === undefined || id === null) {
        errors.push({ index, name: summary.Name ?? summary.name, error: "Rule ID is missing." });
        continue;
      }

      const detailsUrl = "/apiproxy/hunting/huntingService/rules/" +
        encodeURIComponent(id) +
        "?includeLastRun=true&includeQuery=true&tenantIds=" +
        encodeURIComponent(tenantId) +
        "&isUnifiedRulesListEnabled=true";

      try {
        const response = await fetch(detailsUrl, requestOptions);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        rules[index] = await response.json();
      } catch (error) {
        errors.push({ id, name: summary.Name ?? summary.name, error: String(error.message || error) });
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(4, Math.max(1, selected.length)) }, worker));
  return JSON.stringify({
    sourceSelection,
    requestedNames,
    notFound,
    summaries: selected,
    rules: rules.filter(Boolean),
    errors
  });
})()
'@
    $expression = $expression.Replace('__LIST_URL_BASE64__', $listUrlBase64).
        Replace('__HEADERS_BASE64__', $headersBase64).
        Replace('__DETECTION_NAMES_BASE64__', $detectionNamesBase64).
        Replace('__EXPECTED_TENANT__', $ExpectedTenantId.ToString('D'))

    $result = Invoke-CdpCommand -Client $Client -Method 'Runtime.evaluate' -Parameters @{
        expression = $expression
        awaitPromise = $true
        returnByValue = $true
    } -TimeoutMilliseconds 600000

    $exceptionProperty = $result.PSObject.Properties['exceptionDetails']
    if ($null -ne $exceptionProperty) {
        throw "Portal API export failed: $($exceptionProperty.Value.text)"
    }

    $value = $result.result.value
    if ([string]::IsNullOrWhiteSpace([string]$value)) {
        throw 'Portal API export returned no data.'
    }

    return $value | ConvertFrom-Json
}

function Get-ResponseBody {
    param(
        [Parameter(Mandatory = $true)]
        [CustomDetections.CdpClient]$Client,

        [Parameter(Mandatory = $true)]
        [string]$RequestId
    )

    try {
        $result = Invoke-CdpCommand -Client $Client -Method 'Network.getResponseBody' -Parameters @{
            requestId = $RequestId
        } -TimeoutMilliseconds 10000

        if ($result.base64Encoded) {
            return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.body))
        }

        return [string]$result.body
    }
    catch {
        Write-Verbose "Could not read response body for request $RequestId`: $($_.Exception.Message)"
        return $null
    }
}

$edgeProcess = $null
$client = $null
$requests = @{}
$responses = @{}
$authenticationState = $null
$mdeComplete = $false
$mdeFailure = $false
$sentinelManifest = $null
$originalOutputPath = $OutputPath

# Reserve a fresh output directory before changing profiles or starting Edge.
Assert-NoReparseAncestors -Path $ProfilePath
Initialize-ExportDirectory -Path $OutputPath -ProtectedPaths @(
    $PSCommandPath, (Join-Path $PSScriptRoot 'Get-CustomDetections.md'),
    $ProfilePath, (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data')
)

try {
    $browserUserDataPath = $ProfilePath
    if ($ResetProfile -and (Test-Path -LiteralPath $browserUserDataPath)) {
        Remove-Item -LiteralPath $browserUserDataPath -Recurse -Force
    }

    if ($SelectEdgeProfile) {
        $sourceUserDataPath = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'
        if ([string]::IsNullOrWhiteSpace($EdgeProfileDirectory)) {
            $EdgeProfileDirectory = Select-EdgeProfileDirectory -UserDataPath $sourceUserDataPath
        }
        $importedProfilePath = Join-Path $browserUserDataPath $EdgeProfileDirectory
        if (-not (Test-Path -LiteralPath $importedProfilePath)) {
            Write-Host "Importing Edge profile '$EdgeProfileDirectory' into the isolated exporter profile..." -ForegroundColor Cyan
            Copy-EdgeProfile -SourceRoot $sourceUserDataPath `
                -DestinationRoot $browserUserDataPath `
                -ProfileDirectory $EdgeProfileDirectory
        }
    }
    else {
        New-Item -ItemType Directory -Path $browserUserDataPath -Force | Out-Null
    }

    if ($ExportMode -ne 'Sentinel') {
        if ($ExportMode -eq 'Both') {
            $OutputPath = Join-Path $originalOutputPath 'MDE'
            New-Item -ItemType Directory -Path $OutputPath | Out-Null
        }
        $capturePath = Join-Path $OutputPath 'captures'
        $rulePath = Join-Path $OutputPath 'rules'
        New-Item -ItemType Directory -Path $capturePath | Out-Null
        New-Item -ItemType Directory -Path $rulePath | Out-Null
    }

    $edgePath = Resolve-EdgeExecutable
    $port = Get-AvailableTcpPort
    Write-Verbose "Edge DevTools endpoint: http://127.0.0.1:$port"
    $edgeArguments = @(
        "--remote-debugging-port=$port",
        "--user-data-dir=`"$browserUserDataPath`"",
        '--no-first-run',
        '--disable-features=msEdgeFirstRunExperience',
        'about:blank'
    )
    if ($SelectEdgeProfile) {
        $edgeArguments = @("--profile-directory=`"$EdgeProfileDirectory`"") + $edgeArguments
    }
    $edgeProcess = Start-Process -FilePath $edgePath -ArgumentList $edgeArguments -PassThru

    $devToolsDeadline = (Get-Date).AddSeconds(30)
    $targets = $null
    while ($null -eq $targets) {
        if ((Get-Date) -gt $devToolsDeadline) {
            throw "Timed out waiting for the Edge DevTools endpoint on port $port."
        }
        try {
            $targets = Invoke-RestMethod -Uri "http://127.0.0.1:$port/json/list"
        }
        catch {
            Start-Sleep -Milliseconds 200
        }
    }

    $target = $targets | Where-Object { $_.type -eq 'page' } | Select-Object -First 1
    if ($null -eq $target) {
        throw 'Edge did not expose a page target through DevTools.'
    }

    $client = New-Object CustomDetections.CdpClient
    $client.Connect([string]$target.webSocketDebuggerUrl, 30000)
    Invoke-CdpCommand -Client $client -Method 'Page.enable' | Out-Null
    Invoke-CdpCommand -Client $client -Method 'Runtime.enable' | Out-Null
    Invoke-CdpCommand -Client $client -Method 'Network.enable' -Parameters @{
        maxTotalBufferSize = 100000000
        maxResourceBufferSize = 10000000
        maxPostDataSize = 1000000
    } | Out-Null

    if ($ExportMode -ne 'Sentinel') {
    try {
    if ($UserPrincipalName) {
        $frameTree = Invoke-CdpCommand -Client $client -Method 'Page.getFrameTree'
        $authenticationState = @{
            FrameId = [string]$frameTree.frameTree.frame.id
            UserPrincipalName = $UserPrincipalName
            AuthorizationRequests = 0
            InterceptionEnabled = $true
        }
        Invoke-CdpCommand -Client $client -Method 'Fetch.enable' -Parameters @{
            patterns = @(
                @{ urlPattern = 'https://login.microsoftonline.us/*'; resourceType = 'Document'; requestStage = 'Request' },
                @{ urlPattern = 'https://login.microsoftonline.com/*'; resourceType = 'Document'; requestStage = 'Request' }
            )
        } | Out-Null

        # Return before navigation so the event loop can resume paused sign in requests.
        $portalUrlJson = ConvertTo-Json -InputObject $portalUrl -Compress
        Invoke-CdpCommand -Client $client -Method 'Runtime.evaluate' -Parameters @{
            expression = "setTimeout(() => location.assign($portalUrlJson), 100); true"
            returnByValue = $true
        } | Out-Null
        Write-Host "Sign in as '$UserPrincipalName' and complete any required MFA." -ForegroundColor Cyan
        Write-Warning 'Account targeting cannot override organization policy. Do not approve export if Defender shows another account.'
    }
    else {
        Invoke-CdpCommand -Client $client -Method 'Page.navigate' -Parameters @{
            url = $portalUrl
        } | Out-Null
    }

    Write-Host 'Microsoft Edge is open. Complete sign-in if prompted.' -ForegroundColor Cyan
    Write-Host 'The exporter will continue when the custom detections page has loaded.' -ForegroundColor Cyan

    $loginDeadline = (Get-Date).AddSeconds($LoginTimeoutSeconds)
    $pageReady = $false
    while ((Get-Date) -lt $loginDeadline) {
        Add-NetworkEvents -Client $client -Requests $requests -Responses $responses -AuthenticationState $authenticationState
        try {
            $pageState = Get-PageState -Client $client
        }
        catch {
            if ($UserPrincipalName -and (Test-SentinelContextLoss -ErrorRecord $_)) {
                Write-Verbose 'The sign in page is navigating. Waiting for its next execution context.'
                Start-Sleep -Milliseconds 200
                continue
            }
            throw
        }

        $readyUri = $null
        $pageTenant = if ([Uri]::TryCreate($pageState.url, [UriKind]::Absolute, [ref]$readyUri)) {
            @($readyUri.Query.TrimStart('?').Split('&') | Where-Object { ($_ -split '=', 2)[0] -eq 'tid' })
        } else { @() }
        if ($null -ne $readyUri -and
            $readyUri.Scheme -eq 'https' -and $readyUri.Host -ieq $defenderHost -and
            $readyUri.IsDefaultPort -and -not $readyUri.UserInfo -and
            $readyUri.AbsolutePath -eq '/v2/custom_detection' -and
            @($pageTenant).Count -eq 1 -and
            [Uri]::UnescapeDataString((@($pageTenant)[0] -split '=', 2)[1]) -ieq $TenantId.ToString('D') -and
            $pageState.readyState -eq 'complete' -and
            (-not $UserPrincipalName -or $authenticationState.AuthorizationRequests -gt 0)) {
            $pageReady = $true
            break
        }

        Start-Sleep -Seconds 1
    }

    if (-not $pageReady) {
        if ($UserPrincipalName -and $authenticationState.AuthorizationRequests -eq 0) {
            throw 'No supported interactive Microsoft authorization request was observed before the timeout. Account targeting could not be applied. No export was performed.'
        }
        throw "Timed out after $LoginTimeoutSeconds seconds waiting for the custom detections page and requested sign in. No export was performed."
    }

    if ($UserPrincipalName) {
        Invoke-CdpCommand -Client $client -Method 'Fetch.disable' | Out-Null
        $authenticationState.InterceptionEnabled = $false
        $requests.Clear()
        $responses.Clear()
        Invoke-CdpCommand -Client $client -Method 'Page.reload' -Parameters @{ ignoreCache = $true } | Out-Null
    }

    Write-Host "Waiting up to $CaptureSeconds seconds for the portal rule-list request..." -ForegroundColor Cyan
    $captureDeadline = (Get-Date).AddSeconds($CaptureSeconds)
    while ((Get-Date) -lt $captureDeadline) {
        Add-NetworkEvents -Client $client -Requests $requests -Responses $responses -AuthenticationState $authenticationState
        $listRequestSeen = $requests.GetEnumerator() | Where-Object {
            -not ([string]$_.Key).StartsWith('headers:') -and
            [string]$_.Value.url -match '/huntingService/rules/unified'
        } | Select-Object -First 1
        if ($null -ne $listRequestSeen) {
            break
        }
        Start-Sleep -Milliseconds 500
    }

    Add-NetworkEvents -Client $client -Requests $requests -Responses $responses -AuthenticationState $authenticationState
    $listRequestEntry = $requests.GetEnumerator() |
        Where-Object {
            -not ([string]$_.Key).StartsWith('headers:') -and
            [string]$_.Value.url -match '/huntingService/rules/unified'
        } |
        Select-Object -First 1
    if ($null -eq $listRequestEntry) {
        throw 'The portal did not issue the expected unified rule-list request.'
    }

    if ($UserPrincipalName) {
        Confirm-TargetUser -UserPrincipalName $UserPrincipalName
    }
    Write-Host 'Downloading full details for the selected custom detection rules...' -ForegroundColor Cyan
    Assert-MdeListUrl -Url ([string]$listRequestEntry.Value.url) -PortalHost $defenderHost
    $requestId = [string]$listRequestEntry.Key
    $requestHeaders = $requests["headers:$requestId"]
    if ($null -eq $requestHeaders) {
        $requestHeaders = $listRequestEntry.Value.headers
    }

    $replayHeaders = @{}
    foreach ($property in $requestHeaders.PSObject.Properties) {
        if ($property.Name -match '^[A-Za-z0-9-]+$' -and
            $property.Name -notmatch '(?i)^(host|content-length|cookie|origin|referer|user-agent|accept-encoding|connection|sec-.*)$') {
            $replayHeaders[$property.Name] = [string]$property.Value
        }
    }

    $portalExport = Get-PortalCustomDetections `
        -Client $client `
        -ListUrl ([string]$listRequestEntry.Value.url) `
        -Headers $replayHeaders `
        -DetectionNames $DetectionNames `
        -ExpectedTenantId $TenantId

    $rulesByKey = @{}
    $selectedRuleKeys = @{}
    foreach ($summary in @($portalExport.summaries)) {
        $selectedRuleKeys[(Get-StableRuleKey -Rule $summary)] = $true
    }
    $captureIndex = New-Object System.Collections.Generic.List[object]
    $captureNumber = 0

    $summaryCaptureFile = Join-Path $capturePath 'rules-unified.json'
    Write-NewExportFile -Path $summaryCaptureFile -Content (
        ConvertTo-Json -InputObject @($portalExport.summaries) -Depth 100)
    $captureIndex.Add([pscustomobject]@{
        file = 'captures\rules-unified.json'
        method = 'GET'
        url = '/apiproxy/hunting/huntingService/rules/unified'
        status = 200
        ruleCandidates = @($portalExport.summaries).Count
    })

    $detailsCaptureFile = Join-Path $capturePath 'rule-details.json'
    Write-NewExportFile -Path $detailsCaptureFile -Content (
        ConvertTo-Json -InputObject @($portalExport.rules) -Depth 100)
    $captureIndex.Add([pscustomobject]@{
        file = 'captures\rule-details.json'
        method = 'GET'
        url = '/apiproxy/hunting/huntingService/rules/{id}?includeQuery=true'
        status = 200
        ruleCandidates = @($portalExport.rules).Count
    })

    foreach ($rule in @($portalExport.rules)) {
        if (Test-CustomDetectionRule -InputObject $rule) {
            $rulesByKey[(Get-StableRuleKey -Rule $rule)] = $rule
        }
    }

    foreach ($requestId in @($responses.Keys)) {
        $body = Get-ResponseBody -Client $client -RequestId $requestId
        if ([string]::IsNullOrWhiteSpace($body)) {
            continue
        }

        $parsedBody = $null
        try {
            $parsedBody = $body | ConvertFrom-Json
        }
        catch {
            continue
        }

        $captureNumber++
        $captureFile = 'response-{0:D4}.json' -f $captureNumber
        $captureFilePath = Join-Path $capturePath $captureFile
        Write-NewExportFile -Path $captureFilePath -Content (
            ConvertTo-Json -InputObject $parsedBody -Depth 100)

        $request = $requests[$requestId]
        $response = $responses[$requestId]
        $foundRules = @(Find-CustomDetectionRule -InputObject $parsedBody)
        foreach ($rule in $foundRules) {
            $key = Get-StableRuleKey -Rule $rule
            # Detail responses are authoritative. Captures must not bypass name selection.
            if (-not $rulesByKey.ContainsKey($key) -and
                $selectedRuleKeys.ContainsKey($key) -and
                ((@($portalExport.requestedNames).Count -eq 0) -or
                    (Get-RuleDisplayName -Rule $rule) -in @($portalExport.requestedNames))) {
                $rulesByKey[$key] = $rule
            }
        }

        $captureIndex.Add([pscustomobject]@{
            file = "captures\$captureFile"
            method = if ($null -ne $request) { [string]$request.method } else { $null }
            url = [string]$response.url
            status = [int]$response.status
            ruleCandidates = $foundRules.Count
        })
    }

    $ruleIndex = New-Object System.Collections.Generic.List[object]
    $usedFileNames = @{}
    foreach ($entry in $rulesByKey.GetEnumerator() | Sort-Object Key) {
        $rule = $entry.Value
        $displayName = Get-RuleDisplayName -Rule $rule
        $baseName = ConvertTo-SafeFileName -Name $displayName
        $fileStem = $baseName
        $fileName = "$fileStem.json"
        $suffix = 2

        while ($usedFileNames.ContainsKey($fileName.ToLowerInvariant())) {
            $fileStem = "$baseName-$suffix"
            $fileName = "$fileStem.json"
            $suffix++
        }
        $usedFileNames[$fileName.ToLowerInvariant()] = $true

        Write-NewExportFile -Path (Join-Path $rulePath $fileName) -Content (
            ConvertTo-Json -InputObject $rule -Depth 100)
        $queryFileName = "$fileStem.kql"
        $queryText = Get-RuleQueryText -Rule $rule
        Write-NewExportFile -Path (Join-Path $rulePath $queryFileName) -Content $queryText
        $ruleIndex.Add([pscustomobject]@{
            name = $displayName
            key = $entry.Key
            file = "rules\$fileName"
            queryFile = "rules\$queryFileName"
        })
    }

    $manifest = [pscustomobject]@{
        exportedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        tenantId = $TenantId.ToString('D')
        portalUrl = $portalUrl
        ruleCount = $ruleIndex.Count
        captureCount = $captureIndex.Count
        complete = (
            @($portalExport.errors).Count -eq 0 -and
            @($portalExport.notFound).Count -eq 0 -and
            $ruleIndex.Count -eq @($portalExport.summaries).Count
        )
        requestedDetectionNames = @($portalExport.requestedNames)
        unmatchedDetectionNames = @($portalExport.notFound)
        sourceSelection = Get-CaseInsensitiveProperty -InputObject $portalExport -Name @('sourceSelection')
        errors = @($portalExport.errors)
        rules = $ruleIndex.ToArray()
        captures = $captureIndex.ToArray()
    }
    Write-NewExportFile -Path (Join-Path $OutputPath 'manifest.json') -Content (
        ConvertTo-Json -InputObject $manifest -Depth 100)

    if ($null -ne $manifest.sourceSelection -and $manifest.sourceSelection.excludedSentinelCount -gt 0) {
        Write-Host "Excluded $($manifest.sourceSelection.excludedSentinelCount) Sentinel summaries from MDE selection. Sentinel export uses only the selected ARM workspace."
    }
    if (@($portalExport.notFound).Count -gt 0) {
        throw "The following requested detection name(s) were not found: $(@($portalExport.notFound) -join ', ')"
    }
    if ($ruleIndex.Count -eq 0 -and @($portalExport.summaries).Count -gt 0) {
        throw "No custom detection rules were recognized. Raw JSON captures were saved to '$capturePath' for schema analysis."
    }
    if (@($portalExport.errors).Count -gt 0) {
        throw "Exported $($ruleIndex.Count) rule(s), but $(@($portalExport.errors).Count) source classification or detail error(s) occurred. See manifest.json."
    }
    if (-not $manifest.complete) {
        throw 'Some MDE rule details were not recognized. See manifest.json.'
    }

    $mdeComplete = $true
    Write-Host "Exported $($ruleIndex.Count) custom detection rule(s) to '$OutputPath'." -ForegroundColor Green
    }
    catch {
        $mdeFailure = $true
        if (-not (Test-Path -LiteralPath (Join-Path $OutputPath 'manifest.json'))) {
            Write-NewExportFile -Path (Join-Path $OutputPath 'manifest.json') -Content (
                ConvertTo-Json -InputObject ([pscustomobject]@{
                    source = 'MDE'; complete = $false; ruleCount = 0
                    errors = @('MDE browser export failed before a complete manifest was available.')
                    rules = @(); captures = @()
                }) -Depth 100)
        }
        if ($ExportMode -eq 'MDE') { throw }
        Write-Warning 'MDE export is incomplete. Continuing with Sentinel in the same Edge session.'
    }
    }

    if ($ExportMode -ne 'MDE') {
        $OutputPath = if ($ExportMode -eq 'Both') {
            $directory = Join-Path $originalOutputPath 'Sentinel'
            New-Item -ItemType Directory -Path $directory | Out-Null
            $directory
        } else { $originalOutputPath }
        $sentinelTarget = Get-SentinelTarget -TenantId $TenantId -SubscriptionId $SubscriptionId `
            -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -CloudEnvironment $CloudEnvironment `
            -SentinelApiVersion $SentinelApiVersion
        $sentinelStage = 'InitializeBrowserObserver'
        try {
            # Stop collecting network headers. Sentinel authentication remains in the page closure.
            Invoke-CdpCommand -Client $client -Method 'Network.disable' | Out-Null
            $requests.Clear()
            $responses.Clear()
            if ($authenticationState -and $authenticationState.InterceptionEnabled) {
                Invoke-CdpCommand -Client $client -Method 'Fetch.disable' | Out-Null
            }
            $observer = New-SentinelBrowserObserver -Target $sentinelTarget
            $controlledPage = Invoke-CdpCommand -Client $client -Method 'Target.getTargetInfo'
            if (-not $controlledPage.PSObject.Properties['targetInfo'] -or
                $controlledPage.targetInfo.type -ne 'page' -or
                $controlledPage.targetInfo.targetId -cne [string]$target.id) {
                throw 'Sentinel could not identify the original controlled Edge page.'
            }
            $sentinelBrowserState = @{
                Target = $sentinelTarget; Observer = $observer
                Sessions = @{ '' = $true }; Contexts = @{}; Active = $null
                ControlledTargetId = [string]$controlledPage.targetInfo.targetId; RootSessionId = ''
            }
            Invoke-CdpCommand -Client $client -Method 'Page.addScriptToEvaluateOnNewDocument' -Parameters @{
                source = $observer
            } | Out-Null
            Invoke-CdpCommand -Client $client -Method 'Runtime.disable' | Out-Null
            Invoke-CdpCommand -Client $client -Method 'Runtime.enable' | Out-Null
            Invoke-CdpCommand -Client $client -Method 'Target.setAutoAttach' -Parameters @{
                autoAttach = $true; waitForDebuggerOnStart = $true; flatten = $true
            } | Out-Null
            $authenticationState = $null
            if ($UserPrincipalName) {
                $frameTree = Invoke-CdpCommand -Client $client -Method 'Page.getFrameTree'
                $authenticationState = @{
                    FrameId = [string]$frameTree.frameTree.frame.id; UserPrincipalName = $UserPrincipalName
                    AuthorizationRequests = 0; InterceptionEnabled = $true
                }
                Invoke-CdpCommand -Client $client -Method 'Fetch.enable' -Parameters @{
                    patterns = @(
                        @{ urlPattern = 'https://login.microsoftonline.us/*'; resourceType = 'Document'; requestStage = 'Request' },
                        @{ urlPattern = 'https://login.microsoftonline.com/*'; resourceType = 'Document'; requestStage = 'Request' }
                    )
                } | Out-Null
            }
            $sentinelStage = 'NavigateAzurePortal'
            $sentinelUrlJson = ConvertTo-Json -InputObject $sentinelTarget.PortalUrl -Compress
            Invoke-CdpCommand -Client $client -Method 'Runtime.evaluate' -Parameters @{
                expression = "setTimeout(() => location.assign($sentinelUrlJson), 100); true"; returnByValue = $true
            } | Out-Null
            Write-Host 'In Edge, complete normal Azure portal sign in and open Microsoft Sentinel Analytics for the selected workspace.' -ForegroundColor Cyan
            Write-Host "Selected workspace: $($sentinelTarget.ResourceId)" -ForegroundColor Cyan
            $deadline = (Get-Date).AddSeconds($LoginTimeoutSeconds)
            $ready = $false
            $sentinelStage = 'WaitForPortalAuthentication'
            while ((Get-Date) -lt $deadline) {
                Update-SentinelBrowserContexts -Client $client -BrowserState $sentinelBrowserState `
                    -AuthenticationState $authenticationState
                $ready = Find-SentinelReadyContext -Client $client -BrowserState $sentinelBrowserState
                if ($ready) { break }
                Start-Sleep -Milliseconds 500
            }
            if (-not $ready) {
                throw 'Sentinel portal did not expose authenticated ARM fetch or XHR in a verified portal context before timeout. Open Analytics in the selected workspace. No alternate authentication was attempted.'
            }
            Write-Verbose "Using verified portal browser origin: $($sentinelBrowserState.Active.Origin)"
            if ($authenticationState) {
                $sentinelStage = 'FinishAccountTargeting'
                Invoke-CdpCommand -Client $client -Method 'Fetch.disable' | Out-Null
                $authenticationState.InterceptionEnabled = $false
            }
            if ($UserPrincipalName) {
                $sentinelStage = 'ConfirmPortalAccount'
                Write-Host 'Open the account menu inside the Azure portal, not the Edge toolbar.' -ForegroundColor Cyan
                $observed = Read-Host 'Enter the full Azure portal account email, or CANCEL'
                if (-not [string]::Equals($observed.Trim(), $UserPrincipalName, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Sentinel account confirmation did not match. No Sentinel rules were exported.'
                }
            }
            if ($sentinelTarget.RequiresApiVersionDiscovery) {
                $sentinelStage = 'DiscoverGovernmentApiVersion'
                Resolve-SentinelApiVersion -Client $client -Target $sentinelTarget -BrowserState $sentinelBrowserState
            }
            $sentinelStage = 'ExportRuleCollection'
            $sentinelManifest = Export-SentinelRules -Client $client -Target $sentinelTarget `
                -OutputPath $OutputPath -RuleNames $SentinelRuleNames -BrowserState $sentinelBrowserState
        }
        catch {
            $diagnostic = Get-SentinelFailureDiagnostic -ErrorRecord $_ -Stage $sentinelStage
            $message = '{0} Stage: {1}; exception: {2}; line: {3}.' -f
                $diagnostic.message, $diagnostic.stage, $diagnostic.exceptionType, $diagnostic.scriptLineNumber
            $sentinelManifest = [pscustomobject]@{
                source = 'Sentinel'; complete = $false; ruleCount = 0
                errors = @($message); failureDetails = @($diagnostic); rules = @(); captures = @()
            }
            # An export manifest may already exist after a filesystem failure. Never replace it.
            if (Test-Path -LiteralPath (Join-Path $OutputPath 'manifest.json')) { throw }
            Write-NewExportFile -Path (Join-Path $OutputPath 'manifest.json') -Content (
                ConvertTo-Json -InputObject $sentinelManifest -Depth 100)
        }
    }
    if ($ExportMode -eq 'Both') {
        $combined = [pscustomobject]@{
            exportedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
            exportMode = $ExportMode; complete = ($mdeComplete -and $sentinelManifest.complete)
            MDE = [pscustomobject]@{ complete = $mdeComplete; failed = $mdeFailure; manifest = 'MDE\manifest.json' }
            Sentinel = [pscustomobject]@{ complete = $sentinelManifest.complete; manifest = 'Sentinel\manifest.json' }
        }
        Write-NewExportFile -Path (Join-Path $originalOutputPath 'manifest.json') -Content (
            ConvertTo-Json -InputObject $combined -Depth 100)
        if (-not $combined.complete) { throw 'Combined export is incomplete. Successful files were retained. See the source manifests.' }
    }
    if ($sentinelManifest) {
        if (-not $sentinelManifest.complete) { throw "Sentinel export is incomplete: $($sentinelManifest.errors -join ' ') See manifest.json." }
        Write-Host "Exported $($sentinelManifest.ruleCount) Sentinel analytics rule(s) to '$OutputPath'." -ForegroundColor Green
    }
}
finally {
    if ($null -ne $client) {
        try {
            Invoke-CdpCommand -Client $client -Method 'Browser.close' -TimeoutMilliseconds 5000 | Out-Null
        }
        catch {
            Write-Verbose "Edge did not accept Browser.close: $($_.Exception.Message)"
        }
    }

    if ($null -ne $client) {
        $client.Dispose()
    }

    if ($null -eq $client -and
        $null -ne $edgeProcess -and -not $edgeProcess.HasExited) {
        Stop-Process -Id $edgeProcess.Id
    }

    if ($RemoveCachedProfile -and (Test-Path -LiteralPath $ProfilePath)) {
        $profileRemovalDeadline = (Get-Date).AddSeconds(15)
        do {
            try {
                Remove-Item -LiteralPath $ProfilePath -Recurse -Force
                break
            }
            catch {
                if ((Get-Date) -ge $profileRemovalDeadline) {
                    throw "Could not remove the cached Edge profile '$ProfilePath': $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 500
            }
        }
        while (Test-Path -LiteralPath $ProfilePath)

        Write-Host "Removed cached Edge profile '$ProfilePath'." -ForegroundColor Green
    }
}
