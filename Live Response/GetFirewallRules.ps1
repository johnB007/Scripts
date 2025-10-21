<#
.SYNOPSIS
    Export firewall rules to csv file.
.DESCRIPTION
    convert machine's firewall rules to csv file and export resuts to file.
.OUTPUTS
  path to firewall rules csv file.
#>
BEGIN
{
    $baseDirectory = "C:\WINDOWS\TEMP\" 
    $targetCsvFilePath = $baseDirectory + $env:computername + "_FirewallRules" + (get-date -f _yyyyMMdd-HHmmss)+".csv"
}
PROCESS
{
    
    Get-NetFirewallRule | Export-Csv $targetCsvFilePath
    write-host "successfully export rules to csv file:" 
    write-host $targetCsvFilePath
}
