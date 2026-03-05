<#
.SYNOPSIS
    Microsoft Defender AV Performance Analysis and Status Report
    Gathers current Defender status and performs 5-minute performance analysis.
    Designed for automated execution in MDE Live Response.
    All outputs compressed into single ZIP file for easy download.
.NOTES
    Requires: PowerShell 5.0+, Windows Defender, Administrative privileges
    Output: ZIP file containing CSV reports and summary
    Compatible with: MDE Live Response (runscript)
#>

<#/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Disclaimer:
// The sample scripts are not supported under any Microsoft standard support
// program or service. The sample scripts are provided AS IS without warranty
// of any kind. Microsoft further disclaims all implied warranties including,
// without limitation, any implied warranties of merchantability or of fitness
// for a particular purpose. The entire risk arising out of the use or
// performance of the sample scripts and documentation remains with you. In no
// event shall Microsoft, its authors, or anyone else involved in the creation,
// production, or delivery of the scripts be liable for any damages whatsoever
// (including, without limitation, damages for loss of business profits,
// business interruption, loss of business information, or other pecuniary
// loss) arising out of the use of or inability to use the sample scripts or
// documentation, even if Microsoft has been advised of the possibility of
// such damages.
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////#>

# --- CONFIGURATION ---
$RecordingDuration = 300     # Performance recording duration (seconds)
$SkipCleanup = $false        # Set to $true to retain ETL file after analysis
$ErrorActionPreference = "Stop"

# Build output paths
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$desktop = "C:\Users\Public\Desktop"
$outputFolder = "MDAV-Analysis_${hostname}_$timestamp"
$outputPath = Join-Path $desktop $outputFolder
$tempPath = Join-Path $outputPath "temp"
$summaryFile = Join-Path $outputPath "MDAV_Summary_${hostname}_${timestamp}.txt"

# Create directories
New-Item -ItemType Directory -Path $tempPath -Force | Out-Null

# Track execution time
$scriptStartTime = Get-Date

# Initialize summary
$summaryContent = @"
========================================================
Microsoft Defender Status and Performance Analysis
========================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $hostname
Recording Duration: $RecordingDuration seconds
Output Path: $outputPath

"@

# --- PREREQUISITES CHECK ---
Write-Host ""
Write-Host "=========================================="
Write-Host "PREREQUISITES CHECK"
Write-Host "=========================================="

$requiredCmdlets = @('Get-MpComputerStatus', 'New-MpPerformanceRecording', 'Get-MpPerformanceReport')
$cmdletsAvailable = $true

foreach ($cmdlet in $requiredCmdlets) {
    if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
        Write-Host "[FAIL] Required cmdlet not found: $cmdlet"
        $cmdletsAvailable = $false
    }
}

if (-not $cmdletsAvailable) {
    Write-Error "Microsoft Defender cmdlets not available. Ensure Windows Defender is installed."
    exit 1
}

Write-Host "[OK] All required cmdlets available"

# --- PART 1: DEFENDER STATUS ---
Write-Host ""
Write-Host "=========================================="
Write-Host "PART 1: DEFENDER ANTIVIRUS STATUS"
Write-Host "=========================================="

$statusFile = Join-Path $tempPath "MDAV_Status_${hostname}_${timestamp}.csv"

try {
    Write-Host "Gathering Defender antivirus status..."
    $avStatus = Get-MpComputerStatus
    
    # Export status information
    $statusProperties = @(
        'AMServiceEnabled', 'AntispywareEnabled', 'AntivirusEnabled',
        'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'OnAccessProtectionEnabled',
        'RealTimeProtectionEnabled', 'AntispywareSignatureLastUpdated',
        'AntivirusSignatureLastUpdated', 'AntivirusSignatureVersion',
        'AMEngineVersion', 'AMProductVersion'
    )
    
    $existingProps = $avStatus.PSObject.Properties.Name
    $propsToExport = $statusProperties | Where-Object { $_ -in $existingProps }
    
    $avStatus | Select-Object -Property $propsToExport | Export-Csv -Path $statusFile -NoTypeInformation
    
    Write-Host "[OK] Status exported: Real-Time=$($avStatus.RealTimeProtectionEnabled), Antivirus=$($avStatus.AntivirusEnabled)"
    Write-Host "[OK] Last Signature Update: $($avStatus.AntivirusSignatureLastUpdated)"
    
    $summaryContent += @"
PART 1: DEFENDER STATUS - SUCCESS
-----------------------------------
Real-Time Protection: $($avStatus.RealTimeProtectionEnabled)
Antivirus Enabled: $($avStatus.AntivirusEnabled)
Last Signature Update: $($avStatus.AntivirusSignatureLastUpdated)
Output File: $statusFile

"@
}
catch {
    Write-Host "[FAIL] Error gathering status: $_"
    $summaryContent += "PART 1: DEFENDER STATUS - FAILED`n  Error: $_`n`n"
}

# --- PART 2: PERFORMANCE ANALYSIS ---
Write-Host ""
Write-Host "=========================================="
Write-Host "PART 2: DEFENDER PERFORMANCE ANALYSIS"
Write-Host "=========================================="

$etlPath = Join-Path $env:TEMP "mde_perf_${timestamp}.etl"
$perfFiles = @()

try {
    Write-Host "Recording performance data for $RecordingDuration seconds..."
    Write-Host "Please wait - this will take approximately $($RecordingDuration / 60) minutes..."
    
    New-MpPerformanceRecording -RecordTo $etlPath -Seconds $RecordingDuration
    
    if (-not (Test-Path -Path $etlPath)) {
        throw "ETL file was not created at $etlPath"
    }
    
    $etlSize = [Math]::Round((Get-Item $etlPath).Length / 1MB, 2)
    Write-Host "[OK] Recording complete. ETL size: $etlSize MB"
    
    Write-Host "Analyzing performance data..."
    $report = Get-MpPerformanceReport -Path $etlPath `
        -TopPaths 50 -TopFiles 50 -TopProcesses 50 -TopExtensions 50 `
        -TopFilesPerExtension 20 -TopPathsPerExtension 20 `
        -TopProcessesPerPath 20 -TopFilesPerProcess 20 `
        -TopScansPerFile 20 -TopScansPerFilePerProcess 20
    
    # Export function with null-safe handling
    function Export-IfPresent {
        param(
            [Parameter(Mandatory = $false)][object]$Data,
            [Parameter(Mandatory = $true)][string]$CsvPath,
            [Parameter(Mandatory = $true)][string]$DatasetName
        )
        if ($null -ne $Data) {
            $arr = @($Data)
            if ($arr.Count -gt 0) {
                try {
                    $arr | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $CsvPath
                    Write-Host "[OK] Exported $DatasetName ($($arr.Count) rows)"
                    return $CsvPath
                } catch {
                    Write-Host "[FAIL] Failed to export $DatasetName : $_"
                    return $null
                }
            }
        }
        Write-Host "[WARN] No data for $DatasetName"
        return $null
    }
    
    Write-Host ""
    Write-Host "Exporting performance datasets..."
    
    $perfFiles += (Export-IfPresent -Data $report.TopPaths -CsvPath (Join-Path $tempPath "TopPaths.csv") -DatasetName "TopPaths")
    $perfFiles += (Export-IfPresent -Data $report.TopFiles -CsvPath (Join-Path $tempPath "TopFiles.csv") -DatasetName "TopFiles")
    $perfFiles += (Export-IfPresent -Data $report.TopProcesses -CsvPath (Join-Path $tempPath "TopProcesses.csv") -DatasetName "TopProcesses")
    $perfFiles += (Export-IfPresent -Data $report.TopExtensions -CsvPath (Join-Path $tempPath "TopExtensions.csv") -DatasetName "TopExtensions")
    $perfFiles += (Export-IfPresent -Data $report.TopFilesPerExtension -CsvPath (Join-Path $tempPath "TopFilesPerExtension.csv") -DatasetName "TopFilesPerExtension")
    $perfFiles += (Export-IfPresent -Data $report.TopPathsPerExtension -CsvPath (Join-Path $tempPath "TopPathsPerExtension.csv") -DatasetName "TopPathsPerExtension")
    $perfFiles += (Export-IfPresent -Data $report.TopProcessesPerPath -CsvPath (Join-Path $tempPath "TopProcessesPerPath.csv") -DatasetName "TopProcessesPerPath")
    $perfFiles += (Export-IfPresent -Data $report.TopFilesPerProcess -CsvPath (Join-Path $tempPath "TopFilesPerProcess.csv") -DatasetName "TopFilesPerProcess")
    $perfFiles += (Export-IfPresent -Data $report.TopScansPerFile -CsvPath (Join-Path $tempPath "TopScansPerFile.csv") -DatasetName "TopScansPerFile")
    $perfFiles += (Export-IfPresent -Data $report.TopScansPerFilePerProcess -CsvPath (Join-Path $tempPath "TopScansPerFilePerProcess.csv") -DatasetName "TopScansPerFilePerProcess")
    
    $perfFiles = $perfFiles | Where-Object { $null -ne $_ }
    
    Write-Host ""
    Write-Host "[OK] Performance analysis complete. Files created: $($perfFiles.Count)"
    
    $summaryContent += @"
PART 2: PERFORMANCE ANALYSIS - SUCCESS
---------------------------------------
ETL File Size: $etlSize MB
Performance Datasets Created: $($perfFiles.Count)

"@
}
catch {
    Write-Host "[FAIL] Error during performance analysis: $_"
    $summaryContent += "PART 2: PERFORMANCE ANALYSIS - FAILED`n  Error: $_`n`n"
}
finally {
    # Cleanup ETL
    if ((Test-Path -Path $etlPath) -and (-not $SkipCleanup)) {
        try {
            Remove-Item -Path $etlPath -Force -ErrorAction Stop
            Write-Host "[OK] Cleaned up temporary ETL file"
        }
        catch {
            Write-Host "[WARN] Could not remove ETL file: $_"
        }
    }
}

# --- PART 3: CREATE SUMMARY AND INDEX ---
Write-Host ""
Write-Host "=========================================="
Write-Host "CREATING SUMMARY AND INDEX"
Write-Host "=========================================="

try {
    # Create file index
    Get-ChildItem -Path $tempPath -File |
        Select-Object Name, @{Name="Size (KB)"; Expression={[Math]::Round($_.Length / 1KB, 2)}}, LastWriteTime |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $tempPath "FileIndex.csv")
    
    # Create summary file
    $scriptEndTime = Get-Date
    $executionTime = [Math]::Round(($scriptEndTime - $scriptStartTime).TotalSeconds, 2)
    
    $summaryContent += @"
EXECUTION SUMMARY
-----------------
Script Start Time: $($scriptStartTime.ToString("yyyy-MM-dd HH:mm:ss"))
Script End Time: $($scriptEndTime.ToString("yyyy-MM-dd HH:mm:ss"))
Total Execution Time: $executionTime seconds

All files packaged in: $outputFolder.zip
"@
    
    $summaryContent | Out-File -FilePath $summaryFile -Encoding UTF8
    Write-Host "[OK] Summary file created"
}
catch {
    Write-Host "[WARN] Error creating summary: $_"
}

# --- PART 4: COMPRESS TO ZIP ---
Write-Host ""
Write-Host "=========================================="
Write-Host "COMPRESSING OUTPUT TO ZIP"
Write-Host "=========================================="

$zipPath = "$outputPath.zip"

try {
    Compress-Archive -Path $tempPath -DestinationPath $zipPath -Force
    Write-Host "[OK] ZIP file created: $zipPath"
    
    # Cleanup temp directory
    Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Temporary directory cleaned up"
}
catch {
    Write-Host "[FAIL] Failed to create ZIP: $_"
}

# --- FINAL SUMMARY ---
Write-Host ""
Write-Host "=========================================="
Write-Host "SCRIPT COMPLETED"
Write-Host "=========================================="
Write-Host "Total Execution Time: $executionTime seconds"
Write-Host "Output Location: $outputPath"
Write-Host "Compressed Archive: $zipPath"
Write-Host ""

if ($env:USERNAME -eq "SYSTEM") {
    Write-Host "=========================================="
    Write-Host "MDE LIVE RESPONSE DETECTED"
    Write-Host "=========================================="
    Write-Host "To download the ZIP file, use:"
    Write-Host "  getfile `"$zipPath`""
    Write-Host ""
}

Write-Host "Analysis complete."
