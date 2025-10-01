$folderPath = "C:\Temp1"
 
if (-not (Test-Path -Path $folderPath)) {
    New-Item -Path $folderPath -ItemType Directory
    Write-Output "Folder Created Successfully!"
}
else {
    Write-Output "Folder already exists!"
}
Get-LocalGroupMember -Group "Administrators" | Export-csv c:\temp1\admins.csv -NoTypeInformation