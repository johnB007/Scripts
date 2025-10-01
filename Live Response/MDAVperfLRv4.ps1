<#
.SYNOPSIS
    This script performs two main actions:
    1. Gathers the current status of Microsoft Defender Antivirus and saves it to a CSV file.
    2. Runs a performance analysis and saves detailed reports to separate CSV files.
    This script is designed for non-interactive execution in MDE Live Response.
    All output files are created in a temporary directory and only appear in the final .zip file.
#>

# --- CONFIGURATION ---
# These values are hardcoded for non-interactive execution
$RecordingDuration = 300  # Duration in seconds for performance recording
$OutputFolder = "MDAVperf"  # Folder name for output files
$OutputPath = Join-Path $PWD $OutputFolder  # Output files will be saved in MDAVperf folder
$SkipCleanup = $false     # Set to $true to keep the ETL file

# --- PREREQUISITES CHECK ---
# Check if Microsoft Defender cmdlets are available
$requiredCmdlets = @('Get-MpComputerStatus', 'New-MpPerformanceRecording', 'Get-MpPerformanceReport')
$cmdletsAvailable = $true

foreach ($cmdlet in $requiredCmdlets) {
    if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
        Write-Error "Required cmdlet not found: $cmdlet"
        $cmdletsAvailable = $false
    }
}

if (-not $cmdletsAvailable) {
    Write-Error "Microsoft Defender cmdlets not available. Ensure Windows Defender is installed and enabled."
    exit 1
}

Write-Output "Microsoft Defender cmdlets verified."

# --- ADMINISTRATIVE PRIVILEGES CHECK ---
# MDE Live Response runs as SYSTEM, so this check should always pass
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "This script requires administrative privileges. In MDE Live Response, this should not occur."
    exit 1
}

Write-Output "Administrative privileges confirmed."

# --- SETUP ---
# Create output folder if it doesn't exist
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    Write-Output "Created output folder: $OutputPath"
}

# Create temporary directory for intermediate files
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$tempOutputPath = Join-Path $OutputPath "temp_$timestamp"
New-Item -Path $tempOutputPath -ItemType Directory -Force | Out-Null
Write-Output "Created temporary output folder: $tempOutputPath"

# Generate timestamp for unique file names
$hostname = $env:COMPUTERNAME

# Define output file names with timestamp and hostname (in temp directory)
$statusOutputFile = Join-Path $tempOutputPath "MDAV_Status_${hostname}_${timestamp}.csv"
$perfOverviewFile = Join-Path $tempOutputPath "MDAV_Perf_Overview_${hostname}_${timestamp}.csv"
$perfProcessesFile = Join-Path $tempOutputPath "MDAV_Perf_TopProcesses_${hostname}_${timestamp}.csv"
$perfScansFile = Join-Path $tempOutputPath "MDAV_Perf_TopScans_${hostname}_${timestamp}.csv"
$perfFilesFile = Join-Path $tempOutputPath "MDAV_Perf_TopFiles_${hostname}_${timestamp}.csv"
$perfPathsFile = Join-Path $tempOutputPath "MDAV_Perf_TopPaths_${hostname}_${timestamp}.csv"
$summaryFile = Join-Path $tempOutputPath "MDAV_Summary_${hostname}_${timestamp}.txt"

# Use temp directory for ETL file
$recordingPath = Join-Path $env:TEMP "mde_perf_${timestamp}.etl"

# Start tracking execution time
$scriptStartTime = Get-Date

# Initialize summary content
$summaryContent = @"
Microsoft Defender AV Status and Performance Report
===================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $hostname
User: $env:USERNAME
Recording Duration: $RecordingDuration seconds
Output Path: $OutputPath

"@

# --- PART 1: GET MICROSOFT DEFENDER ANTIVIRUS STATUS ---
Write-Output ""
Write-Output "=========================================="
Write-Output "PART 1: Microsoft Defender Antivirus Status"
Write-Output "=========================================="

try {
    Write-Output "Gathering Microsoft Defender Antivirus status..."

    # Get the status of Microsoft Defender Antivirus
    $avStatus = Get-MpComputerStatus

    # Define all possible properties we want to export
    $propertiesToExport = @(
        'AMServiceEnabled',
        'AntispywareEnabled',
        'AntivirusEnabled',
        'BehaviorMonitorEnabled',
        'IoavProtectionEnabled',
        'OnAccessProtectionEnabled',
        'RealTimeProtectionEnabled',
        'AntispywareSignatureLastUpdated',
        'AntivirusSignatureLastUpdated',
        'NISEngineVersion',
        'NISSignatureVersion',
        'AntivirusSignatureVersion',
        'AMEngineVersion',
        'AMProductVersion',
        'AMServiceVersion',
        'QuickScanSignatureVersion',
        'FullScanSignatureVersion'
    )

    # Filter only existing properties to avoid errors
    $existingProperties = $avStatus.PSObject.Properties.Name
    $actualPropertiesToExport = $propertiesToExport | Where-Object { $_ -in $existingProperties }

    # Export the selected properties to a CSV file
    $avStatus | Select-Object -Property $actualPropertiesToExport | Export-Csv -Path $statusOutputFile -NoTypeInformation

    Write-Output "SUCCESS: Created $statusOutputFile"
    
    # Add key status info to console
    Write-Output ""
    Write-Output "Key Status Information:"
    Write-Output "  Real-Time Protection: $($avStatus.RealTimeProtectionEnabled)"
    Write-Output "  Antivirus Enabled: $($avStatus.AntivirusEnabled)"
    Write-Output "  Last Signature Update: $($avStatus.AntivirusSignatureLastUpdated)"
    Write-Output ""
    
    # Add to summary
    $summaryContent += @"
PART 1 RESULTS: SUCCESS
-----------------------
Output File: $statusOutputFile
Real-Time Protection: $($avStatus.RealTimeProtectionEnabled)
Antivirus Enabled: $($avStatus.AntivirusEnabled)
Last Signature Update: $($avStatus.AntivirusSignatureLastUpdated)
Properties Exported: $($actualPropertiesToExport.Count)

"@
}
catch {
    $errorMessage = "ERROR in Part 1 (AV Status): $($_.Exception.Message)"
    Write-Error $errorMessage
    $summaryContent += @"
PART 1 RESULTS: FAILED
----------------------
Error: $($_.Exception.Message)

"@
}

# --- PART 2: GET MICROSOFT DEFENDER PERFORMANCE REPORT ---
Write-Output ""
Write-Output "=========================================="
Write-Output "PART 2: Microsoft Defender Performance Analysis"
Write-Output "=========================================="

try {
    Write-Output "Starting performance data collection..."
    
    # Ensure temp directory exists
    $tempDir = Split-Path $recordingPath -Parent
    if (-not (Test-Path -Path $tempDir)) {
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
    }

    # Start performance recording
    Write-Output "Recording performance data for $RecordingDuration seconds..."
    Write-Output "Please wait - this will take $RecordingDuration seconds to complete..."
    
    # Use New-MpPerformanceRecording with -Seconds parameter for non-interactive execution
    New-MpPerformanceRecording -RecordTo $recordingPath -Seconds $RecordingDuration

    Write-Output "Performance recording completed."

    # Verify the ETL file was created
    if (-not (Test-Path -Path $recordingPath)) {
        throw "Performance recording file was not created at $recordingPath"
    }

    $etlFileInfo = Get-Item $recordingPath
    $etlFileSizeMB = [Math]::Round($etlFileInfo.Length / 1MB, 2)
    Write-Output "ETL file created successfully: $etlFileSizeMB MB"

    # Generate the performance report
    Write-Output ""
    Write-Output "Analyzing performance data..."
    $performanceReport = Get-MpPerformanceReport -Path $recordingPath -TopProcesses 15 -TopScans 15 -TopFilesPerProcess 15 -TopPaths 15 -Overview

    # Export each section to its own CSV file
    Write-Output "Exporting performance report sections..."
    
    $exportedFiles = @()
    $exportResults = ""
    
    # Export Overview
    if ($performanceReport.Overview) {
        try {
            $performanceReport.Overview | Export-Csv -Path $perfOverviewFile -NoTypeInformation
            $exportedFiles += $perfOverviewFile
            Write-Output "  [OK] Overview exported"
            $exportResults += "  - Overview: $(Split-Path $perfOverviewFile -Leaf)`n"
        }
        catch {
            Write-Warning "  [WARN] Failed to export Overview: $_"
        }
    }

    # Export Top Processes
    if ($performanceReport.TopProcesses) {
        try {
            $performanceReport.TopProcesses | Export-Csv -Path $perfProcessesFile -NoTypeInformation
            $exportedFiles += $perfProcessesFile
            Write-Output "  [OK] Top Processes exported"
            $exportResults += "  - Top Processes: $(Split-Path $perfProcessesFile -Leaf)`n"
        }
        catch {
            Write-Warning "  [WARN] Failed to export Top Processes: $_"
        }
    }

    # Export Top Scans
    if ($performanceReport.TopScans) {
        try {
            $performanceReport.TopScans | Export-Csv -Path $perfScansFile -NoTypeInformation
            $exportedFiles += $perfScansFile
            Write-Output "  [OK] Top Scans exported"
            $exportResults += "  - Top Scans: $(Split-Path $perfScansFile -Leaf)`n"
        }
        catch {
            Write-Warning "  [WARN] Failed to export Top Scans: $_"
        }
    }

    # Export Top Files
    if ($performanceReport.TopFiles) {
        try {
            $performanceReport.TopFiles | Export-Csv -Path $perfFilesFile -NoTypeInformation
            $exportedFiles += $perfFilesFile
            Write-Output "  [OK] Top Files exported"
            $exportResults += "  - Top Files: $(Split-Path $perfFilesFile -Leaf)`n"
        }
        catch {
            Write-Warning "  [WARN] Failed to export Top Files: $_"
        }
    }

    # Export Top Paths
    if ($performanceReport.TopPaths) {
        try {
            $performanceReport.TopPaths | Export-Csv -Path $perfPathsFile -NoTypeInformation
            $exportedFiles += $perfPathsFile
            Write-Output "  [OK] Top Paths exported"
            $exportResults += "  - Top Paths: $(Split-Path $perfPathsFile -Leaf)`n"
        }
        catch {
            Write-Warning "  [WARN] Failed to export Top Paths: $_"
        }
    }

    Write-Output ""
    Write-Output "Performance report export completed."
    Write-Output "Total files created: $($exportedFiles.Count)"
    
    # Add to summary
    $summaryContent += @"
PART 2 RESULTS: SUCCESS
-----------------------
ETL File Size: $etlFileSizeMB MB
Performance Files Created: $($exportedFiles.Count)
$exportResults
"@
}
catch {
    $errorMessage = "ERROR in Part 2 (Performance Report): $($_.Exception.Message)"
    Write-Error $errorMessage
    $summaryContent += @"
PART 2 RESULTS: FAILED
----------------------
Error: $($_.Exception.Message)

"@
}
finally {
    # Clean up the temporary ETL file
    if ((Test-Path -Path $recordingPath) -and (-not $SkipCleanup)) {
        Write-Output ""
        Write-Output "Cleaning up temporary files..."
        try {
            Remove-Item -Path $recordingPath -Force -ErrorAction Stop
            Write-Output "ETL file removed successfully."
        }
        catch {
            Write-Warning "Failed to remove ETL file: $($_.Exception.Message)"
            $summaryContent += "Warning: Failed to clean up ETL file at $recordingPath`n"
        }
    }
    elseif ($SkipCleanup -and (Test-Path -Path $recordingPath)) {
        Write-Output "Cleanup skipped. ETL file retained at: $recordingPath"
        $summaryContent += "Note: ETL file retained at $recordingPath (cleanup skipped)`n"
    }
}

# --- PART 3: CREATE SUMMARY FILE ---
Write-Output ""
Write-Output "=========================================="
Write-Output "Creating summary report..."

$scriptEndTime = Get-Date
$executionTime = [Math]::Round(($scriptEndTime - $scriptStartTime).TotalSeconds, 2)

$summaryContent += @"

EXECUTION SUMMARY
-----------------
Script Start: $($scriptStartTime.ToString("yyyy-MM-dd HH:mm:ss"))
Script End: $($scriptEndTime.ToString("yyyy-MM-dd HH:mm:ss"))
Total Execution Time: $executionTime seconds

All output files saved to: $OutputPath (inside ZIP)
"@

try {
    $summaryContent | Out-File -FilePath $summaryFile -Encoding UTF8
    Write-Output "Summary report saved: $summaryFile"
}
catch {
    Write-Warning "Failed to create summary file: $($_.Exception.Message)"
}

# --- PART 4: COMPRESS OUTPUT FILES INTO ZIP ---
Write-Output ""
Write-Output "=========================================="
Write-Output "Compressing output files into ZIP..."

$zipFileName = "MDAV_Output_${hostname}_${timestamp}.zip"
$zipFilePath = Join-Path $OutputPath $zipFileName

# Get all files to compress from the temporary directory
$filesToZip = Get-ChildItem -Path $tempOutputPath -File

if ($filesToZip) {
    try {
        # Use Compress-Archive to create the ZIP file
        Compress-Archive -Path $filesToZip.FullName -DestinationPath $zipFilePath -Force
        Write-Output "ZIP file created successfully: $zipFilePath"

        # Clean up the temporary output directory
        try {
            Remove-Item -Path $tempOutputPath -Recurse -Force -ErrorAction Stop
            Write-Output "Temporary output directory removed: $tempOutputPath"
        }
        catch {
            Write-Warning "Failed to remove temporary output directory: $($_.Exception.Message)"
        }
    }
    catch {
        Write-Warning "Failed to create ZIP file: $($_.Exception.Message)"
    }
}
else {
    Write-Output "No files to compress."
}

# --- FINAL OUTPUT ---
Write-Output ""
Write-Output "=========================================="
Write-Output "SCRIPT COMPLETED"
Write-Output "=========================================="
Write-Output "Execution time: $executionTime seconds"
Write-Output "Output location: $OutputPath"
Write-Output "Compressed output: $zipFilePath"

# List all created files (should only be the ZIP file in OutputPath)
$allFiles = Get-ChildItem -Path $OutputPath -Filter "*${hostname}_${timestamp}*" -File
if ($allFiles) {
    Write-Output "Files created:"
    foreach ($file in $allFiles) {
        Write-Output "  - $($file.Name) ($([Math]::Round($file.Length / 1KB, 2)) KB)"
    }
}

# Special note for MDE Live Response
if ($env:USERNAME -eq "SYSTEM") {
    Write-Output ""
    Write-Output "=========================================="
    Write-Output "MDE LIVE RESPONSE DETECTED"
    Write-Output "=========================================="
    Write-Output "Running as SYSTEM user indicates MDE Live Response session."
    Write-Output "Use 'getfile' command to retrieve the ZIP file:"
    Write-Output "  getfile `"$zipFilePath`""
}

Write-Output ""
Write-Output "Script finished."