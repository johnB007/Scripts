<#
.SYNOPSIS
    Export eventlog files from computer and compress the logs.
.DESCRIPTION
    Allows to export specific eventlog file or all eventlog files.
    The exported logs will be compressed.
.OUTPUTS
  path to compress file contains the eventlog files.
#>
BEGIN
{
    $baseDirectory = "C:\WINDOWS\TEMP\" 
    $targetCompressedFilePath = $baseDirectory + $env:computername + "eventlog" + (get-date -f _yyyyMMdd-HHmmss)
}
PROCESS
{
    # Create a temporary folder for the exporated logs
    $output = New-Item -ItemType Directory -Path $targetCompressedFilePath -Force

    # build menu of eventlog files to export
    $index =1;
    $logList=@()
    $logList += New-Object psobject -Property @{LogFileName="All"; Option=$index}
    $index+=1
   
    $logFiles = Get-WmiObject Win32_NTEventlogFile 

    $output = foreach($logFile in $logFiles)
    {
        $exportFileName = $logFile.LogfileName + (get-date -f _yyyyMMdd-HHmmss) + ".evt"            
        $logFile.backupeventlog($targetCompressedFilePath + '\\' + $exportFileName)
    }   

    # compress the temporary folder to compresses file
    Compress-Archive -Path $targetCompressedFilePath -DestinationPath $targetCompressedFilePath -CompressionLevel Optimal
    # remove the temporary folder 
    Remove-Item -Path $targetCompressedFilePath -Recurse        

    Write-Host "compressed eventlog archive saved to:"
    Write-Host "$($targetCompressedFilePath).zip"
}
END {}

