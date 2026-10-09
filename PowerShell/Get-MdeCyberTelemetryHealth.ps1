<#
.SYNOPSIS
    Collects local Microsoft Defender for Endpoint sensor telemetry health.
.DESCRIPTION
    This read only troubleshooting script examines the local
    Microsoft-Windows-SENSE/Operational event log on a Windows device.

    It reports:
    * Event 92 telemetry quota stops and Event 93 telemetry resumes.
    * Event 405 authentication service communication failures.
    * Event 35 sensor disk and daily upload quota updates.
    * Cumulative event counts for the last 1, 3, 5, and 7 days.
    * The Microsoft Defender for Endpoint Sense service status.
    * The current file count and disk footprint of the sensor Cyber folder.

    Run the script in an elevated Windows PowerShell session or through Azure
    Arc Run Command. It uses only built in Windows PowerShell 5.1 cmdlets and
    does not require internet access.

    The Cyber folder measurement is current disk usage. It is not an exact
    count of unsent events, cloud ingestion latency, or historical queue size.
    The script does not modify services, permissions, protection settings,
    event logs, or sensor files.
.OUTPUTS
    Writes formatted diagnostic results and troubleshooting guidance to the
    success stream.
.NOTES
    Requirements:
    * Windows device onboarded to Microsoft Defender for Endpoint.
    * Administrator or SYSTEM execution context.
    * Enabled Microsoft-Windows-SENSE/Operational event log.

    Execution classification:
    * Windows PowerShell diagnostic script.
    * Validated locally and through Azure Arc Run Command as SYSTEM.
    * Not validated in Microsoft Defender for Endpoint Live Response.

    Event interpretation:
    * 35: Communication quota configuration was updated.
    * 92: Sensor cyber data transmission stopped because quota was exceeded.
    * 93: Sensor cyber data transmission resumed.
    * 405: Communication with the authentication service failed.

    Exit codes:
    * 0: Collection completed.
    * 1: Required diagnostic collection failed.
    * 2: Core results completed, but Cyber folder measurement was unavailable.
.EXAMPLE
    PS> .\Get-MdeCyberTelemetryHealth.ps1

    Runs the script in an elevated PowerShell session on the local device.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open PowerShell as administrator and rerun.'
    }

    $log = 'Microsoft-Windows-SENSE/Operational'
    $now = Get-Date
    $logInfo = Get-WinEvent -ListLog $log
    if (-not $logInfo.IsEnabled) {
        throw 'The Sense Operational log is disabled.'
    }
    if ($logInfo.RecordCount -eq 0) {
        throw 'The Sense Operational log is empty. No history is available.'
    }

    $oldest = Get-WinEvent -LogName $log -Oldest -MaxEvents 1
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = $log
            StartTime = $now.AddDays(-7)
            EndTime = $now
            Id = 35, 92, 93, 405
        })
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            $events = @()
            Write-Warning 'No matching Sense events found in the last seven days.'
        }
        else {
            throw
        }
    }

    Write-Output "PC: $env:COMPUTERNAME"
    Write-Output "Checked UTC: $($now.ToUniversalTime().ToString('o'))"
    Write-Output "Oldest retained event UTC: $($oldest.TimeCreated.ToUniversalTime().ToString('o'))"
    Write-Output 'Event times below use the local time zone.'

    $summary = foreach ($days in 1, 3, 5, 7) {
        $start = $now.AddDays(-$days)
        $window = @($events | Where-Object TimeCreated -ge $start)
        [pscustomobject]@{
            Days = $days
            LogCoversWindow = ($oldest.TimeCreated -le $start)
            QuotaStops = @($window | Where-Object Id -eq 92).Count
            QuotaResumes = @($window | Where-Object Id -eq 93).Count
            Event405 = @($window | Where-Object Id -eq 405).Count
            QuotaUpdates = @($window | Where-Object Id -eq 35).Count
        }
    }
    Write-Output "`nCumulative lookback summary:"
    $summary | Format-Table -AutoSize
    Write-Output 'LogCoversWindow indicates retained time range only, not uninterrupted logging.'

    Write-Output "`nDaily quota events:"
    $events |
        Where-Object { $_.Id -in 92, 93 } |
        Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd') } |
        Sort-Object Name |
        ForEach-Object {
            [pscustomobject]@{
                Date = $_.Name
                Stops = @($_.Group | Where-Object Id -eq 92).Count
                Resumes = @($_.Group | Where-Object Id -eq 93).Count
            }
        } | Format-Table -AutoSize

    Write-Output "`nLatest relevant events:"
    $events | Sort-Object TimeCreated -Descending |
        Select-Object -First 12 TimeCreated, Id, Message | Format-List

    Write-Output "`nLatest quota configuration event:"
    $latestQuotaUpdate = $events |
        Where-Object Id -eq 35 |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 1
    $assignedCacheQuotaMiB = $null
    $assignedDailyUploadQuotaMiB = $null
    if ($null -eq $latestQuotaUpdate) {
        Write-Output 'No Event 35 quota update was found in the retained seven day window.'
    }
    else {
        $latestQuotaUpdate | Select-Object TimeCreated, Message | Format-List
        if ($latestQuotaUpdate.Message -match 'Disk quota in MB:\s*(\d+).*daily upload quota in MB:\s*(\d+)') {
            $assignedCacheQuotaMiB = [int]$Matches[1]
            $assignedDailyUploadQuotaMiB = [int]$Matches[2]
        }
    }

    Write-Output "`nSense service:"
    Get-Service -Name Sense | Select-Object Name, Status | Format-Table

    $exitCode = 0
    $cyberFileCount = $null
    $cyberSizeMiB = $null
    $cyberMeasurementError = $null
    try {
        $path = Join-Path $env:ProgramData 'Microsoft\Windows Defender Advanced Threat Protection\Cyber'
        $files = @(Get-ChildItem -LiteralPath $path -File)
        $bytes = 0L
        foreach ($file in $files) {
            $bytes += $file.Length
        }
        $cyberFileCount = $files.Count
        $cyberSizeMiB = [math]::Round($bytes / 1MB, 2)
    }
    catch {
        $directAccessError = $_.Exception.Message
        try {
            $robocopyPath = (Get-Command robocopy.exe -ErrorAction Stop).Source
            $robocopyDestination = Join-Path $env:TEMP (
                'MdeCyberMeasure_{0}' -f [Guid]::NewGuid().ToString('N')
            )
            $robocopyArguments = @(
                $path
                $robocopyDestination
                '/L'
                '/B'
                '/BYTES'
                '/FP'
                '/NJH'
                '/NJS'
                '/NDL'
                '/NC'
                '/XX'
                '/R:0'
                '/W:0'
                '/XJ'
            )
            $robocopyOutput = @(& $robocopyPath @robocopyArguments 2>&1)
            $robocopyExitCode = $LASTEXITCODE
            if ($robocopyExitCode -ge 8) {
                $robocopyError = @(
                    $robocopyOutput |
                        Where-Object { $_ -match 'ERROR|denied|privilege|rights' } |
                        Select-Object -First 3
                ) -join ' '
                throw "Robocopy returned exit code $robocopyExitCode. $robocopyError"
            }

            $listedFiles = @(
                $robocopyOutput | ForEach-Object {
                    if ($_ -match '^\s*(?<Bytes>\d+)\s+(?<Path>[A-Za-z]:\\.+)$') {
                        [pscustomobject]@{
                            Bytes = [int64]$Matches.Bytes
                            Path = $Matches.Path
                        }
                    }
                }
            )
            $bytes = 0L
            foreach ($listedFile in $listedFiles) {
                $bytes += $listedFile.Bytes
            }
            $cyberFileCount = $listedFiles.Count
            $cyberSizeMiB = [math]::Round($bytes / 1MB, 2)
            Write-Warning 'Direct Cyber folder access was denied. Measurement succeeded with read only administrator backup mode.'
        }
        catch {
            $cyberMeasurementError = "Direct access failed: $directAccessError Backup mode failed: $($_.Exception.Message)"
            Write-Warning "Cyber folder measurement unavailable: $cyberMeasurementError"
            Write-Warning 'The elevated account must have Backup files and directories rights. Do not change Cyber folder permissions or delete sensor files.'
            $exitCode = 2
        }
    }

    Write-Output "`nTelemetry storage and upload summary:"
    [pscustomobject]@{
        PC = $env:COMPUTERNAME
        CheckedUtc = [datetime]::UtcNow.ToString('o')
        AssignedCacheQuotaMiB = $assignedCacheQuotaMiB
        AssignedDailyUploadQuotaMiB = $assignedDailyUploadQuotaMiB
        CurrentCacheFileCount = $cyberFileCount
        CurrentCacheUsageMiB = $cyberSizeMiB
    } | Format-List
    if ($null -ne $cyberMeasurementError) {
        Write-Output ("Current cache usage was not measured: {0}" -f $cyberMeasurementError)
    }
    Write-Output 'AssignedCacheQuotaMiB is the Event 35 local disk limit, not current cache usage.'
    Write-Output 'AssignedDailyUploadQuotaMiB is the Event 35 upload limit, not the amount collected or uploaded today.'
    Write-Output 'CurrentCacheUsageMiB is a point in time disk footprint, not an exact unsent event count.'
    Write-Output 'Exact telemetry bytes collected or uploaded per day are not exposed by this supported local event log interface.'

    $quotaStopCount = @($events | Where-Object Id -eq 92).Count
    $authenticationFailureCount = @($events | Where-Object Id -eq 405).Count
    Write-Output "`nTroubleshooting guidance:"
    if ($quotaStopCount -gt 0) {
        Write-Output ("Detected {0} telemetry quota stop events in the retained seven day window." -f $quotaStopCount)
        Write-Output 'Frequent Event 92 and 93 cycling can indicate sustained telemetry volume, constrained communication quota, or interrupted uploads.'
        Write-Output 'Review Event 35 values, available disk space, sensor connectivity, and recent workload changes. Do not alter Cyber folder files or permissions.'
    }
    else {
        Write-Output 'No telemetry quota stop events were detected in the retained seven day window.'
    }
    if ($authenticationFailureCount -gt 0) {
        Write-Output ("Detected {0} authentication service communication failures in the retained seven day window." -f $authenticationFailureCount)
        Write-Output 'Validate Defender for Endpoint service URLs, DNS resolution, proxy configuration, TLS inspection, and outbound connectivity.'
    }
    else {
        Write-Output 'No authentication service communication failures were detected in the retained seven day window.'
    }
    Write-Output 'If repeated quota stops or communication failures continue, collect the Microsoft Defender for Endpoint client analyzer package for deeper analysis.'
    exit $exitCode
}
catch {
    Write-Error "MDE diagnostic collection failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
