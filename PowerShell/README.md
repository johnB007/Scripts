# PowerShell scripts

PowerShell utilities for Microsoft Defender for Endpoint administration,
diagnostics, and security operations.

## Get-MdeTelemetryHealth.ps1

`Get-MdeTelemetryHealth.ps1` is a read only troubleshooting script for Windows
devices onboarded to Microsoft Defender for Endpoint. It helps identify sensor
telemetry quota cycling and authentication service communication failures.

### What it reports

- Cumulative Event 92 quota stops and Event 93 resumes for 1, 3, 5, and 7 days.
- Daily quota stop and resume totals.
- Event 405 authentication service communication failures.
- The latest Event 35 disk quota and daily upload quota configuration.
- Sense service status.
- Current file count and disk footprint of the local sensor Cyber folder.
- Troubleshooting guidance based on the collected events.

The summary labels these values separately:

- `AssignedCacheQuotaMiB` is the Event 35 local disk limit.
- `AssignedDailyUploadQuotaMiB` is the Event 35 daily upload limit.
- `CurrentCacheUsageMiB` is the current Cyber folder disk footprint when the
  execution context has permission to read it.

The assigned limits are not actual usage. The Cyber folder measurement is a
point in time disk footprint, not an exact count of unsent events, cloud
ingestion latency, or historical queue size. Exact telemetry bytes collected
or uploaded per day are not exposed by the supported local SENSE event log
interface.

### Requirements

- A Windows device onboarded to Microsoft Defender for Endpoint.
- Windows PowerShell 5.1 or later.
- Administrator or SYSTEM execution context.
- An enabled `Microsoft-Windows-SENSE/Operational` event log.

The script uses built in Windows cmdlets and `robocopy.exe`, requires no
additional modules, and does not change services, permissions, protection
settings, event logs, or sensor files. If direct Cyber folder access is denied,
the script retries with `robocopy /L /B`. The `/L` switch lists files without
copying, deleting, or changing them, while `/B` uses the elevated
administrator token's backup privilege.

### Execution classification

This is a **Windows PowerShell diagnostic script**. It has been validated in an
elevated local PowerShell session and through Azure Arc Run Command running as
SYSTEM. It has **not** been validated in a Microsoft Defender for Endpoint Live
Response session and should not be represented as Live Response tested.

### Run locally

Open Windows PowerShell as administrator:

```powershell
.\Get-MdeTelemetryHealth.ps1
```

### Interpret common results

| Result | Meaning | Recommended checks |
|---|---|---|
| Repeated Events 92 and 93 | Sensor telemetry repeatedly stops and resumes because a communication quota is exceeded | Review Event 35 quota values, free disk space, sensor connectivity, and recent workload changes |
| Event 92 without a newer Event 93 | Telemetry transmission might currently be stopped | Confirm connectivity and collect a fresh diagnostic result |
| Repeated Event 405 | The sensor cannot reliably reach the authentication service | Validate service URLs, DNS, proxy settings, TLS inspection, and outbound connectivity |
| Cyber folder near the Event 35 disk quota | The local sensor queue is using most of its assigned disk allowance | Investigate upload connectivity and quota events; do not modify the folder |
| Cyber folder access denied | Direct PowerShell enumeration cannot read the protected folder | The script automatically retries with read only administrator backup mode; verify the account retains its Backup files and directories user right if that fallback also fails |
| `LogCoversWindow` is `False` | The local event log does not retain the entire requested period | Increase event log retention if longer local history is operationally required |

If quota cycling or communication failures continue, collect the Microsoft
Defender for Endpoint client analyzer package for deeper analysis.
Do not delete Cyber folder files, change its permissions, or apply undocumented
registry settings.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | Collection completed |
| `1` | Required diagnostic collection failed |
| `2` | Core results completed, but Cyber folder measurement was unavailable |

## Disclaimer

<#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                               
//  Disclaimer:                                                                  
//  The sample scripts are not supported under any Microsoft standard support    
//  program or service. The sample scripts are provided AS IS without warranty   
//  of any kind. Microsoft further disclaims all implied warranties including,   
//  without limitation, any implied warranties of merchantability or of fitness  
//  for a particular purpose. The entire risk arising out of the use or          
//  performance of the sample scripts and documentation remains with you. In no  
//  event shall Microsoft, its authors, or anyone else involved in the creation,    
//  production, or delivery of the scripts be liable for any damages whatsoever     
//  (including, without limitation, damages for loss of business profits,        
//  business interruption, loss of business information, or other pecuniary      
//  loss) arising out of the use of or inability to use the sample scripts or    
//  documentation, even if Microsoft has been advised of the  possibility of     
//  such damages.                                                                
//                                                                               
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
