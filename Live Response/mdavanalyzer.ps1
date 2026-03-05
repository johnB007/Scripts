# mdavanalyzer.ps1
# Runs in MDE Live Response via runscript
# Fixed: Better diagnostics
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

$ErrorActionPreference = "Stop"

# Use Public Desktop so path is stable under SYSTEM/live response context
$desktop = "C:\Users\Public\Desktop"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $desktop "MDAV-Perf-$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$etlPath = Join-Path $outDir "Defender-scans-$stamp.etl"

Write-Host "Starting Defender AV performance recording for 300 seconds (5 min)..."
# Timed mode auto-stops after specified duration
New-MpPerformanceRecording -RecordTo $etlPath -Seconds 300

Write-Host "Recording complete: $etlPath"
Write-Host "Analyzing performance data..."

# Pull report - NO -Raw flag, add TopFilesPerProcess parameter
$report = Get-MpPerformanceReport -Path $etlPath `
    -TopPaths 50 `
    -TopFiles 50 `
    -TopProcesses 50 `
    -TopExtensions 50 `
    -TopFilesPerExtension 20 `
    -TopPathsPerExtension 20 `
    -TopProcessesPerPath 20 `
    -TopFilesPerProcess 20 `
    -TopScansPerFile 20 `
    -TopScansPerFilePerProcess 20

# Diagnostic: Check report structure
Write-Host "Report object type: $($report.GetType().Name)"
Write-Host "Report properties:" 
if ($report -is [System.Collections.IDictionary]) {
    Write-Host "  Keys: $($report.Keys -join ', ')"
} else {
    Write-Host "  Members: $(($report | Get-Member -MemberType Property).Name -join ', ')"
}

# Export function with better null handling
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
                Write-Host "✓ Exported $DatasetName ($($arr.Count) rows): $CsvPath"
            } catch {
                Write-Host "✗ Failed to export $DatasetName : $_"
            }
        } else {
            Write-Host "⚠ No data for $DatasetName (array is empty)"
        }
    } else {
        Write-Host "⚠ No data for $DatasetName (null)"
    }
}

# Export all datasets
Write-Host "`nExporting datasets..."
Export-IfPresent -Data $report.TopPaths -CsvPath (Join-Path $outDir "TopPaths.csv") -DatasetName "TopPaths"
Export-IfPresent -Data $report.TopFiles -CsvPath (Join-Path $outDir "TopFiles.csv") -DatasetName "TopFiles"
Export-IfPresent -Data $report.TopProcesses -CsvPath (Join-Path $outDir "TopProcesses.csv") -DatasetName "TopProcesses"
Export-IfPresent -Data $report.TopExtensions -CsvPath (Join-Path $outDir "TopExtensions.csv") -DatasetName "TopExtensions"
Export-IfPresent -Data $report.TopFilesPerExtension -CsvPath (Join-Path $outDir "TopFilesPerExtension.csv") -DatasetName "TopFilesPerExtension"
Export-IfPresent -Data $report.TopPathsPerExtension -CsvPath (Join-Path $outDir "TopPathsPerExtension.csv") -DatasetName "TopPathsPerExtension"
Export-IfPresent -Data $report.TopProcessesPerPath -CsvPath (Join-Path $outDir "TopProcessesPerPath.csv") -DatasetName "TopProcessesPerPath"
Export-IfPresent -Data $report.TopFilesPerProcess -CsvPath (Join-Path $outDir "TopFilesPerProcess.csv") -DatasetName "TopFilesPerProcess"
Export-IfPresent -Data $report.TopScansPerFile -CsvPath (Join-Path $outDir "TopScansPerFile.csv") -DatasetName "TopScansPerFile"
Export-IfPresent -Data $report.TopScansPerFilePerProcess -CsvPath (Join-Path $outDir "TopScansPerFilePerProcess.csv") -DatasetName "TopScansPerFilePerProcess"

# Create an index file so you know what to download
Write-Host "`nCreating file index..."
Get-ChildItem -Path $outDir -File |
    Select-Object Name, @{Name="Size (bytes)"; Expression={$_.Length}}, LastWriteTime |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir "FileIndex.csv")

Write-Host "`n=========================================="
Write-Host "DONE. Output folder: $outDir"
Write-Host "Download all files from: $outDir"
Write-Host "=========================================="
