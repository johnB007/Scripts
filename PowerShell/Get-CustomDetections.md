# AVD Defender and Sentinel exporter

[The exporter](Get-CustomDetections.ps1) is the working AVD copy of
Jesse Esquivel's Defender custom detection exporter, with optional account
selection for shared Windows sessions. It now also exports existing Microsoft
Sentinel analytics rules through the Azure portal in Microsoft Edge.

Source: [johnB007/MDATP account selection contribution](https://github.com/johnB007/MDATP/blob/ecf576fbc332223e829bd01a58c127e1171f5aa0/Scripts/Custom%20Detections/Get-CustomDetections/Get-CustomDetections.ps1).
Original project: [JesseEsquivel/MDATP](https://github.com/JesseEsquivel/MDATP/tree/master/Scripts/Custom%20Detections/Get-CustomDetections).
The original disclaimer and Edge launch arguments are retained. Startup polling
is bounded and reports failures separately from portal sign in. MDE remains the default.

## Run

Use Windows with Microsoft Edge and PowerShell 5.1 or PowerShell 7. Use an
account authorized for the selected source. No Azure CLI, Az module, Graph
module, device code flow, app registration, or new consent grant is used.

For the original DoD MDE export, replace the placeholders:

```powershell
pwsh -NoProfile -File .\Get-CustomDetections.ps1 -TenantId '<tenant-guid>' -UserPrincipalName 'user@example.invalid' -LoginTimeoutSeconds 600 -CaptureSeconds 60 -Verbose
```

1. Complete sign in and any required MFA in the Edge window opened by the script.
2. Open the account menu inside the Defender webpage, not the Edge toolbar.
3. Enter the account email displayed there when PowerShell requests confirmation.
   Enter `CANCEL` if the account is incorrect.

The username is supplied at runtime, not hard coded. This mode creates a fresh
isolated Edge profile. Do not combine it with `-SelectEdgeProfile`,
`-EdgeProfileDirectory`, or `-ResetProfile`. The script cannot override
organizational authentication policy. Account confirmation is manual.

## Combined export

Select one cloud and supply the subscription, resource group and workspace
explicitly. The script does not discover subscriptions or switch accounts.
Replace every placeholder:

```powershell
pwsh -NoProfile -File .\Get-CustomDetections.ps1 -ExportMode Both -CloudEnvironment Commercial -TenantId '<tenant-guid>' -SubscriptionId '<subscription-guid>' -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' -LoginTimeoutSeconds 600 -CaptureSeconds 60 -RemoveCachedProfile
```

The script exports MDE first, then opens the selected workspace in the Azure
portal in the same Edge window. Complete normal sign in and MFA when prompted.
Open Microsoft Sentinel and select Analytics for that workspace if the portal
does not load it automatically. No rules are deployed or changed.

For only Sentinel, use the same command with `-ExportMode Sentinel`. This mode
does not open Defender. For only MDE, use `-ExportMode MDE` and omit the
subscription, resource group and workspace arguments.

Use `-DetectionNames 'Rule One,Rule Two'` for exact MDE names and
`-SentinelRuleNames 'Rule A,Rule B'` for exact Sentinel display names. Both also
accept PowerShell string arrays. Matching ignores case. A Sentinel rule without
a display name is matched by resource name. Missing names make the export
incomplete.

Existing `-SelectEdgeProfile`, `-EdgeProfileDirectory`, `-ResetProfile` and
`-RemoveCachedProfile` behavior remains available. With `-UserPrincipalName`,
confirm the displayed account separately inside each portal. The login hint
does not bypass organizational policy or verify the account automatically.

## Find the workspace switch values

These are manual browser instructions, not automatic parameter population.
The exporter does not execute the query, discover subscriptions or acquire
another authentication session for this lookup.

View the instructions built into either standalone script without running it:

```powershell
Get-Help .\Get-CustomDetections_Analytics-IL2.ps1 -Full
Get-Help .\Get-CustomDetections_Analytics-IL5.ps1 -Full
```

For IL2, open `https://portal.azure.com`. For IL5, open
`https://portal.azure.us`. In the correct directory, open **Azure Resource
Graph Explorer** in that browser portal and select only approved subscriptions.
Run this query there, **not Sentinel Logs or Defender advanced hunting**:

```kusto
Resources
| where type =~ 'microsoft.operationalinsights/workspaces'
| project TenantId = tenantId, SubscriptionId = subscriptionId, ResourceGroupName = resourceGroup, WorkspaceName = name
| order by WorkspaceName asc
```

The query lists accessible Log Analytics workspaces. It does not filter for or
prove that Sentinel is enabled. Choose one result and confirm Microsoft
Sentinel is enabled for that workspace in the portal.

Copy all values from that same result row. `TenantId` maps to `-TenantId`,
`SubscriptionId` maps to `-SubscriptionId`, `ResourceGroupName` maps to
`-ResourceGroupName`, and `WorkspaceName` maps to `-WorkspaceName`.

The Resource Graph `tenantId` is the Microsoft Entra tenant GUID. Do not copy
the Log Analytics workspace `TenantId` or `customerId` property as the Entra
tenant argument. Those workspace identifiers are different. With Both, the
Defender tenant and workspace must match the specified Entra tenant.

Replace every placeholder, choose a new approved local directory for
`-OutputPath`, and paste the appropriate command as **one line**:

```powershell
.\Get-CustomDetections_Analytics-IL2.ps1 -ExportMode Both -CloudEnvironment Commercial -TenantId '<Entra tenant GUID>' -SubscriptionId '<subscription GUID>' -ResourceGroupName '<resource group>' -WorkspaceName '<workspace name>' -OutputPath '<new approved export directory>'
```

```powershell
.\Get-CustomDetections_Analytics-IL5.ps1 -ExportMode Both -CloudEnvironment USGovDoD -TenantId '<Entra tenant GUID>' -SubscriptionId '<subscription GUID>' -ResourceGroupName '<resource group>' -WorkspaceName '<workspace name>' -OutputPath '<new approved export directory>'
```

Name filters are optional and omitted from these examples. No account,
subscription context, permission or authentication setting is changed by
adding these instructions.

## Authentication and permissions

RBAC authorizes operations. It does not remove the need for an access token.
The Defender portal session is not an ARM token and is never passed to ARM.
For Sentinel, the Azure portal must acquire its own ARM token through its
normal browser authentication.

The script observes the portal's own ARM fetch or XMLHttpRequest, including
an ARM batch request, in a verified browser context. Commercial Azure also
allows the observed ReactBlade origin
`https://sandbox-1.reactblade.portal.azure.net`. CDP attaches iframe targets and
selects a default execution context only after checking the live frame URL,
context origin and parent Azure portal. Other origins are excluded.

The observer is registered before navigating to Azure portal. New iframe
targets pause until their startup observer is registered. This ordering matters
because portal applications can cache fetch references during startup.
Installing an observer after an application has loaded cannot reliably observe
those cached references. A late observer alone is not proof that browser
authentication is unavailable.

Sentinel bridge replies are awaited and serialized as JSON strings before CDP
returns them. The browser retains the pending reply in its original realm.
The exporter validates the serialized envelope before parsing rule resources.
It does not return authentication headers.

The bearer remains only in a document closure in its original browser realm.
The script sends a GET to the documented alertRules list endpoint from that
same realm. It does not transfer credentials between frames or read cross
origin DOM. Destroyed and detached contexts are invalidated. Only the selected
ARM host and exact workspace collection are
allowed. Tenant, audience and expiration claims must match before use.
ARM validates the bearer and enforces the caller's existing permissions.
This claim check is not a substitute for ARM token validation.

The script does not read token caches, cookies, passwords or browser storage
for Sentinel. It does not create an OAuth client, spoof a client, or fall back
to another authentication tool. It does not print or export authentication
headers. The isolated Edge profile itself can retain normal browser
authentication unless `-RemoveCachedProfile` is supplied.

MDE requires permission to view custom detections in Defender. Sentinel needs
workspace access and `Microsoft.SecurityInsights/alertRules/read`, such as
Microsoft Sentinel Reader at the selected workspace or an appropriate broader
scope. HTTP 401 and 403 are failures, not empty results.

The Defender unified list can also contain Sentinel summaries from other
workspaces. MDE selection accepts the observed combination of
`UsxSourceType` equal to `Defender`, `UsxResourceType` equal to
`DefenderCustomDetectionRule`, and numeric `SourceType` equal to `0`.
The known `LogAnalytics`, `SentinelAnalyticsRule`, and numeric `1` combination
is deliberately excluded before detection name matching. Those summaries are
never sent to the Defender detail endpoint. Sentinel export still uses only
the explicitly selected ARM workspace.

Legacy summaries without these source metadata fields or `DetectionRuleSource`
retain the original detail request behavior. Partially typed, conflicting,
unknown, or malformed summaries produce classification errors and an incomplete
MDE manifest. Their identifiers are not guessed or remapped. Valid Defender
records can still be saved. Supplemental response captures cannot add rules
outside the selected summary identifiers.

## Clouds

`-CloudEnvironment Commercial` uses `security.microsoft.com`,
`portal.azure.com` and `management.azure.com`.

`-CloudEnvironment USGov` uses `security.microsoft.us`, `portal.azure.us`
and `management.usgovcloudapi.net`.

The default `-CloudEnvironment USGovDoD` preserves `security.apps.mil` for
MDE and uses the Government Azure portal and ARM host for Sentinel. This does
not imply that a DoD Defender token authorizes a Government workspace.
Both sources must belong to the specified tenant in the selected cloud.
Government API version availability is not assumed to match Commercial.
Government browser contexts currently allow only the Government portal origin.
No Government ReactBlade origin has been verified or added.

### Government API version selection

Commercial retains the live tested `2025-09-01` default and performs no provider
metadata discovery. `-SentinelApiVersion` can select an explicitly confirmed
version in either cloud. The value must be a real calendar date, optionally
followed by `-preview`. Explicit selection does not prove service availability;
the actual rule GET must still succeed.

Without that parameter, Government starts with no rule API version and no rule
list URL. After normal portal authentication, the same private browser closure
performs this fixed read only request in the selected Government subscription:

```http
GET https://management.usgovcloudapi.net/subscriptions/{subscriptionId}/providers/Microsoft.SecurityInsights?api-version=2021-04-01
```

The exporter verifies the provider identifier, namespace, `resourceTypes`
envelope and the single `alertRules` entry. It chooses the newest advertised
stable date in `apiVersions`. Preview versions are never selected automatically.
Only the selected version and status return through CDP, not the metadata body
or authentication headers. This request never registers a provider.

Provider metadata read permission at the subscription may be broader than
workspace Sentinel Reader. A denied request, unsupported metadata or absence
of a stable version stops the export before any rule GET. Nothing grants
additional permission or silently selects a guessed version. An operator with
a version independently confirmed for that Government workspace can supply
`-SentinelApiVersion` to avoid metadata discovery.

The provider metadata API itself is not live verified in DoD. If its documented
version is unavailable there, the failure remains explicit and the confirmed
rule version parameter remains available. An advertised provider version is
not proof of regional service availability or IL5 authorization.

Pagination retains the selected version. A recovered browser realm with the
original unresolved startup configuration performs its own private discovery
before a rule GET. If its selected version differs from the in progress export,
the request is refused rather than changing versions.

### DoD IL5 usage and boundary

The dedicated DoD copy defaults to `USGovDoD`. The dedicated Commercial copy
defaults to `Commercial`. They are generated from the same canonical script;
the repository files are `Get-CustomDetections_Analytics-IL5.ps1` and
`Get-CustomDetections_Analytics-IL2.ps1`, respectively. Their names reflect both
custom detection and analytics exports. Only a generated label comment and
the cloud parameter default differ. Modes remain selectable and MDE remains
the default mode. These shared instructions apply to all three scripts.

The names IL2 and IL5 identify intended target environments. They do not assert
formal IL2 or IL5 certification, authorization or a compliant storage boundary.
The existing `Get-CustomDetections.ps1` filename and published URL remain
compatible, with its original DoD default.

Replace the placeholders and choose a new approved export directory:

```powershell
.\Get-CustomDetections_Analytics-IL5.ps1 -ExportMode Both -CloudEnvironment USGovDoD -TenantId '<DoD tenant GUID>' -SubscriptionId '<Government subscription GUID>' -ResourceGroupName '<resource group>' -WorkspaceName '<workspace name>' -OutputPath '<new approved export directory>' -LoginTimeoutSeconds 1800 -Verbose
```

For a version already confirmed by the agency, add
`-SentinelApiVersion '<confirmed API version>'`. Do not copy the Commercial
version without checking Government support.

DoD Defender uses `https://security.apps.mil`. Government Azure portal uses
`https://portal.azure.us`, ARM uses `https://management.usgovcloudapi.net` and
normal Government Entra sign in uses `https://login.microsoftonline.us`.
No separate Sentinel ARM host ending in `.mil` is introduced.

The accepted Government ARM audiences are
`https://management.core.usgovcloudapi.net` and
`https://management.usgovcloudapi.net`, with an optional trailing slash.
Commercial ARM audiences and public Defender service API audiences are refused
for Government Sentinel requests. The public MDE Government API
`https://api-gov.securitycenter.microsoft.us` and XDR Government API
`https://api-gov.security.microsoft.us` are not substituted for the preserved
Defender browser portal proxy.

Selecting DoD does not certify an Azure region, workspace, endpoint machine or
export directory for IL5. Verify agency authorization, applicable service audit
scope, regional availability and handling requirements before exporting data.
Rule configuration and queries can contain sensitive information. Keep the
browser profile and exported data within approved agency storage.

No DoD tenant or live browser session was available for validation. Government
endpoint routing, version discovery, explicit selection, cloud boundaries and
failure handling are tested offline. IL5 live validation is pending the user's
planned test in the real tenant. No credentials are needed for offline testing.
If the actual Government portal obtains
ARM authentication only in an unverified iframe origin, the script times out
without an alternate authentication path. That frame origin must be observed
and verified before adding support; no wildcard Government frame trust is used.

### Commercial IL2 usage

Use the same required workspace targeting with the Commercial edition:

```powershell
.\Get-CustomDetections_Analytics-IL2.ps1 -ExportMode Both -CloudEnvironment Commercial -TenantId '<Commercial tenant GUID>' -SubscriptionId '<Commercial subscription GUID>' -ResourceGroupName '<resource group>' -WorkspaceName '<workspace name>' -OutputPath '<new approved export directory>' -Verbose
```

Either edition can select a different supported cloud explicitly. MDE only
does not require workspace parameters. Sentinel only uses `-ExportMode Sentinel`.
The editions contain all implementation code and do not require the canonical
script to be present beside them.

### Maintaining the generated editions

Edit only `Get-CustomDetections.ps1`, then run this command from the repository
root to regenerate the labelled standalone files and validate them:

```powershell
pwsh -NoProfile -File .\PowerShell\Tests\Test-GetCustomDetections.ps1 -RegenerateEditions
```

Running the test without `-RegenerateEditions` verifies source identity and
both cloud defaults without writing repository files. It refuses missing or
stale editions. The generator refuses to replace an unrecognized edition or a
filesystem link. Only the label comment and intended cloud default may differ.
Generated HTML instructions are ignored and must not be staged.

### Official endpoint and version references

[Defender for Endpoint Government portals, sign in and service APIs](https://learn.microsoft.com/en-us/defender-endpoint/gov)

[Defender XDR Government service APIs](https://learn.microsoft.com/en-us/defender-xdr/usgov)

[Azure Government endpoint comparison](https://learn.microsoft.com/en-us/azure/azure-government/compare-azure-government-global-azure)

[Government ARM environment and modern audience source](https://learn.microsoft.com/en-us/dotnet/api/azure.resourcemanager.armenvironment.azuregovernment)

[Published cloud endpoint metadata including the legacy ARM resource audience](https://learn.microsoft.com/en-us/cli/azure/azure-cli-endpoints)

The preceding endpoint metadata reference is documentation only. No CLI command
or Azure module is executed by this exporter.

[Resource provider metadata GET and advertised API versions](https://learn.microsoft.com/en-us/rest/api/resources/providers/get?view=rest-resources-2021-04-01)

[Sentinel Government feature availability](https://learn.microsoft.com/en-us/azure/sentinel/feature-availability)

[DoD regions, IL5 and service audit scope](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-overview-dod)

## Output and limitations

The default output is `exports\<timestamp>-<random-id>` beside the script.
`-OutputPath` must name a new directory. Existing files and directories are
never reused. Source files, normal Edge profiles, the isolated profile and
filesystem link ancestors are protected. File creation refuses collisions.
Duplicate sanitized rule names receive a numeric suffix.

Individual modes write `rules`, `captures` and `manifest.json` in that directory.
Both writes `MDE\rules`, `MDE\captures`, `MDE\manifest.json`,
`Sentinel\rules`, `Sentinel\captures`, `Sentinel\manifest.json` and a root
`manifest.json` recording completion for each source.

The MDE manifest includes `sourceSelection` counts for typed Defender records,
legacy records, deliberately excluded Sentinel summaries, and unsupported
summaries. Deliberate exclusions are not detail errors.

MDE output retains complete rule JSON and KQL. Sentinel output retains each
complete returned resource, including id, name, type, kind, etag, queries and
all properties. Rules with a query also receive a KQL file. Queryless kinds do
not receive invented queries. Scheduled, NRT, Fusion and other returned kinds
are retained. The capture files contain rule bodies, not pagination links or
authentication headers. These are resource exports, not deployment templates.

Commercial Sentinel defaults to API version `2025-09-01`. Government uses the
explicitly supplied or discovered version described above. Pagination follows
`nextLink` only within the selected cloud, subscription, resource group,
workspace and API version.
Repeated pages, duplicate IDs, foreign resources and unsupported envelopes
fail explicitly. A valid empty list completes honestly with zero rules.
If a later page fails, earlier files remain and the manifest is incomplete.

MDE detail requests can return HTTP 404. Successful files remain and failures
are recorded. Both attempts Sentinel even if MDE fails. An incomplete source
or unmatched name causes a terminating error rather than a success message
for the overall export. A confirmed CDP execution context loss or target
navigation permits one recovery attempt for the same GET. For a lost session,
the script asks CDP for the original controlled page identifier and verifies
that it still identifies a page at the selected Azure portal origin. It never
chooses another tab or an arbitrary matching portal. A closed page or an
untrusted destination is refused.

The script retires the old child sessions, attaches a new session to that
same controlled page and consumes fresh attachment and execution context
events. It revalidates the live frame, origin and authenticated tenant before
retrying. The startup observer remains registered and repeated installation
does not replace its private authentication state. HTTP and authentication
failures are not retried. A second lifecycle failure is final. Only an accepted
reply is persisted, so recovery does not create duplicate page captures.
`browserContextRecoveries` records the recovery count.
HTTP, authentication and other protocol failures are not automatically retried.
There is no deployment feature.

Sentinel failures now include `failureDetails` with the operation stage,
original exception type, source line and error category. Console errors include
the same location information. Raw exception messages, response bodies and
authentication data are not included in diagnostics. A DevTools reply must
contain the expected browser response object before it is used.

### Edge startup troubleshooting

The script prints a startup message before launching Edge. With `-Verbose`,
it also prints the localhost DevTools endpoint and launcher PID. It waits
30 seconds for a page target, with each HTTP probe limited to at most two
seconds. An in flight probe can finish slightly after that deadline.
Repeated PowerShell WebRequest verbose lines are suppressed.

If startup fails, the error reports whether the launcher is still running or
has exited, its exit code when available, and whether the endpoint answered
without a page or the HTTP probe failed. A launcher exit alone is not failure:
Edge can hand off to another process. Raw HTTP exception messages are not logged.
This stage precedes portal sign in. Increasing `-LoginTimeoutSeconds` does
not extend Edge startup.

If the failure occurs in an Administrator terminal, retry in a normal
PowerShell window. Use a new isolated profile and output directory to
distinguish a profile-specific issue without resetting or importing an
existing profile. Replace the target placeholders:

```powershell
$runId = [Guid]::NewGuid().ToString('N')
.\Get-CustomDetections_Analytics-IL2.ps1 -ExportMode Both `
    -TenantId '<tenant-guid>' -SubscriptionId '<subscription-guid>' `
    -ResourceGroupName '<resource-group>' -WorkspaceName '<workspace-name>' `
    -ProfilePath (Join-Path $env:TEMP "RuleExporter-$runId") `
    -OutputPath (Join-Path $env:LOCALAPPDATA "RuleExports\IL2-$runId") `
    -LoginTimeoutSeconds 1800 -Verbose
```

For IL5 use its edition and approved profile and output storage instead.
This retry is a diagnostic distinction, not proof that elevation or the old
profile caused the failure. Do not disable browser policies, change global
proxy settings or close unrelated Edge windows. Endpoint absence observed
after script termination does not establish that Edge never started, because
startup failure cleanup can stop the launched process.

The default profile is `%LOCALAPPDATA%\Get-CustomDetections\EdgeProfile`,
independent of the script's working directory. Paths with spaces are quoted
in the Edge launch arguments.

The script closes its Edge window when it completes or fails. There is no
keep open flag. Increasing `-LoginTimeoutSeconds` gives more time to sign in
but does not prevent closing after completion. Omitting
`-RemoveCachedProfile` retains the isolated browser profile.

MDE uses internal Defender portal requests, not a public export contract.
Sentinel uses a public ARM endpoint, but its browser observation depends on
Azure portal implementation details. Worker only authentication, unverified
iframe origins,
portal changes, browser policy, CORS failures, redirects, opaque tokens or an
unavailable API version can stop export. The script reports that limitation
without switching tools or requesting new permissions.

Treat exports and the isolated browser profile as sensitive. Account selection
profiles remain under `%LOCALAPPDATA%\Get-CustomDetections\TargetUser-<random-id>`
unless `-RemoveCachedProfile` is supplied to delete the isolated profile after
the run. Normal Edge profiles and other users' Windows sessions are not deleted.

## Offline validation

Run the focused tests without authentication:

```powershell
pwsh -NoProfile -File .\Tests\Test-GetCustomDetections.ps1
```

The tests use synthetic responses and mocked browser boundaries. Node.js is
needed only for the JavaScript test fixtures, not for the exporter. They cover
MDE preservation, individual and combined selection, multiple Sentinel kinds,
pagination, tenant and audience checks, HTTP errors, partial results, output
protection and browser cleanup. No existing exporter regression suite was
present in this repository.

Startup tests cover a ready endpoint, launcher handoff, delayed page creation,
running and exited launchers without an endpoint, and an endpoint without a
page. A real temporary loopback listener that never returns HTTP headers
verifies that a stalled request terminates within the test budget. No Edge
window or portal is opened by the regression suite.

Entrypoint tests exercise the real Sentinel browser request bridge with
mocked CDP replies, including observer startup, navigation, malformed replies,
JSON parsing failures, trusted iframe context selection and output collisions.
They also verify startup observer registration before portal navigation and
iframe resume. Browser fixtures demonstrate the difference between fetch
references cached before and after observer installation.
The production CDP JSON parser is exercised with large Unicode responses,
protocol errors and malformed serialized envelopes. Main entrypoint fixtures
cover navigation between readiness and the list read. Safe protocol reason,
method and code, browser status, and HTTP code remain in failure diagnostics.
They verify sanitized failure
locations and preserve files that already exist.

Offline success does not verify a live tenant, current portal implementation
or Government cloud availability. A live run must separately confirm the
selected workspace, portal account, complete manifests and expected rule count.

## Microsoft references

[Alert Rules List REST API](https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/list?view=rest-securityinsights-2025-09-01)

[Azure Government endpoint comparison](https://learn.microsoft.com/en-us/azure/azure-government/compare-azure-government-global-azure)
