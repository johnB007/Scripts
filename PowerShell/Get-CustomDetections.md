# AVD custom detection exporter

[Get-CustomDetections.ps1](Get-CustomDetections.ps1) is the working AVD copy of
Jesse Esquivel's Defender custom detection exporter, with optional account
selection for shared Windows sessions.

Source: [johnB007/MDATP account selection contribution](https://github.com/johnB007/MDATP/blob/ecf576fbc332223e829bd01a58c127e1171f5aa0/Scripts/Custom%20Detections/Get-CustomDetections/Get-CustomDetections.ps1).
Original project: [JesseEsquivel/MDATP](https://github.com/JesseEsquivel/MDATP/tree/master/Scripts/Custom%20Detections/Get-CustomDetections).
The script is copied without code changes and retains its original disclaimer.

## Run

Use Windows with Microsoft Edge, PowerShell 7, and authorized access to the
target Defender tenant. No Azure CLI token, Graph module, or device code flow
is required by this script.

From the folder containing the script, replace both placeholders:

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

## Output and limitations

The script targets `https://security.apps.mil`. It saves results under
`exports\<timestamp>` in the current PowerShell folder unless `-OutputPath`
specifies another location. Output includes rule JSON files, KQL files,
captured rule responses, and `manifest.json`.

This exports Defender custom detection rules, not Sentinel analytics rules or
hash reputation results. Entries that the Defender detail endpoint cannot
retrieve can return HTTP 404. Successful files are retained and failures are
recorded in the manifest; an incomplete export is not reported as complete.

It uses internal Defender portal requests, not a supported public export API.
Portal changes can break the exporter.

Treat exports and the isolated browser profile as sensitive. Account selection
profiles remain under `%LOCALAPPDATA%\Get-CustomDetections\TargetUser-<random-id>`
unless `-RemoveCachedProfile` is supplied to delete the isolated profile after
the run. Normal Edge profiles and other users' Windows sessions are not deleted.
