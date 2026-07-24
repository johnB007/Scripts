<#
.SYNOPSIS
Push the CloudUserSimulation package to an Azure Arc connected Windows device.

.DESCRIPTION
Uploads the local CloudUserSimulation script set to Azure Storage, then uses
Azure Arc run command to download the files onto the target machine.
#>
[CmdletBinding()]
param(
    [string]$MachineName = 'DC007',
    [string]$ResourceGroup = 'SOC-Central',
    [string]$Location = 'eastus2',
    [string]$StorageAccount = 'labtelemetrystage',
    [string]$Container = 'cloud-user-sim',
    [string]$LocalRoot = 'C:\Users\jobarbar\github\Scripts\PowerShell',
    [string]$RemoteRoot = 'C:\Lab\CloudUserSimulation',
    [switch]$RunAfterDeploy,
    [switch]$RegisterDailyTask,
    [string]$RemoteTaskUserId,
    [ValidateRange(0, 480)]
    [int]$DurationMinutes = 35,
    [string]$TaskName = 'CloudUserSimulationArc',
    [string]$DailyAt = '08:30'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info {
    param([string]$Message)
    Write-Host "[info] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[ok]   $Message" -ForegroundColor Green
}

function Assert-Path {
    param([string]$PathValue, [string]$Label)
    if (-not (Test-Path $PathValue)) {
        throw "$Label not found: $PathValue"
    }
}

Assert-Path -PathValue $LocalRoot -Label 'Local CloudUserSimulation root'
$requiredFiles = @(
    'Invoke-DailyCloudUserSimulation.ps1',
    'CloudUserSimulation.SampleConfig.json',
    'Register-DailyCloudUserSimulationTask.ps1'
)
foreach ($requiredFile in $requiredFiles) {
    Assert-Path -PathValue (Join-Path $LocalRoot $requiredFile) -Label $requiredFile
}

$archivePath = Join-Path $env:TEMP ('CloudUserSimulation-{0}.zip' -f (Get-Date -Format 'yyyyMMddHHmmss'))
if (Test-Path $archivePath) {
    Remove-Item $archivePath -Force
}
Compress-Archive -Path (Join-Path $LocalRoot 'Invoke-DailyCloudUserSimulation.ps1'), (Join-Path $LocalRoot 'CloudUserSimulation.SampleConfig.json'), (Join-Path $LocalRoot 'Register-DailyCloudUserSimulationTask.ps1') -DestinationPath $archivePath -Force
Write-Ok "Created archive $archivePath"

$arc = az connectedmachine show --name $MachineName --resource-group $ResourceGroup -o json | ConvertFrom-Json
if ($arc.status -ne 'Connected') {
    throw "Arc machine $MachineName is not connected. Status: $($arc.status)"
}
Write-Ok "Arc machine $MachineName is connected"

$storage = az storage account show --name $StorageAccount --resource-group $ResourceGroup -o json 2>$null | ConvertFrom-Json
if (-not $storage) {
    Write-Info "Creating storage account $StorageAccount"
    az storage account create --name $StorageAccount --resource-group $ResourceGroup --location $Location --sku Standard_LRS --kind StorageV2 --allow-blob-public-access false --min-tls-version TLS1_2 --https-only true --output none
}
$key = az storage account keys list --account-name $StorageAccount --resource-group $ResourceGroup --query "[0].value" -o tsv
az storage container create --name $Container --account-name $StorageAccount --account-key $key --public-access off --output none | Out-Null

$blobName = Split-Path $archivePath -Leaf
az storage blob upload --account-name $StorageAccount --account-key $key --container-name $Container --file $archivePath --name $blobName --overwrite --output none
$sasExpiry = (Get-Date).ToUniversalTime().AddHours(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
$sasToken = az storage blob generate-sas --account-name $StorageAccount --account-key $key --container-name $Container --name $blobName --permissions r --expiry $sasExpiry --https-only -o tsv
$blobUrl = "https://$StorageAccount.blob.core.windows.net/$Container/$blobName`?$sasToken"
Write-Ok "Uploaded archive and generated temporary SAS"

$remoteArchive = "$RemoteRoot\CloudUserSimulation.zip"
$remoteScript = "$RemoteRoot\Invoke-DailyCloudUserSimulation.ps1"
$remoteConfig = "$RemoteRoot\CloudUserSimulation.SampleConfig.json"
$remoteTaskUserLiteral = if ([string]::IsNullOrWhiteSpace($RemoteTaskUserId)) { '' } else { $RemoteTaskUserId }
$bootstrap = @"
`$ErrorActionPreference = 'Stop'
`$remoteRoot = '$RemoteRoot'
`$remoteArchive = '$remoteArchive'
`$remoteScript = '$remoteScript'
`$remoteConfig = '$remoteConfig'
`$interactiveTaskUser = '$remoteTaskUserLiteral'
if (-not (Test-Path `$remoteRoot)) {
    New-Item -ItemType Directory -Path `$remoteRoot -Force | Out-Null
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri '$blobUrl' -OutFile `$remoteArchive -UseBasicParsing -TimeoutSec 120
Expand-Archive -Path `$remoteArchive -DestinationPath `$remoteRoot -Force
Get-ChildItem `$remoteRoot | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-String -Width 200
if ($RegisterDailyTask) {
    `$taskArgs = '-NoProfile -ExecutionPolicy Bypass -File "' + `$remoteScript + '" -DurationMinutes $DurationMinutes -ConfigPath "' + `$remoteConfig + '"'
    `$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument `$taskArgs
    `$trigger = New-ScheduledTaskTrigger -Daily -At '$DailyAt'
    `$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    if ([string]::IsNullOrWhiteSpace(`$interactiveTaskUser)) {
        `$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        `$registeredAs = 'SYSTEM'
    }
    else {
        `$principal = New-ScheduledTaskPrincipal -UserId `$interactiveTaskUser -LogonType InteractiveToken -RunLevel Limited
        `$registeredAs = `$interactiveTaskUser
    }
    if (Get-ScheduledTask -TaskName '$TaskName' -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false
    }
    Register-ScheduledTask -TaskName '$TaskName' -Action `$action -Trigger `$trigger -Settings `$settings -Principal `$principal | Out-Null
    Write-Host ('REMOTE_TASK_REGISTERED: $TaskName user=' + `$registeredAs + ' at $DailyAt')
}
if ($RunAfterDeploy) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `$remoteScript -DurationMinutes $DurationMinutes -ConfigPath `$remoteConfig
    Write-Host 'REMOTE_RUN_COMPLETED'
}
"@

$runCommandName = 'push-cloudsim-' + (Get-Date -Format 'yyyyMMddHHmmss')
$rc = az connectedmachine run-command create --name $runCommandName --machine-name $MachineName --resource-group $ResourceGroup --location $Location --script $bootstrap -o json | ConvertFrom-Json
$state = $null
$deadline = (Get-Date).AddMinutes(5)
do {
    $view = az connectedmachine run-command show --name $runCommandName --machine-name $MachineName --resource-group $ResourceGroup --expand instanceView -o json | ConvertFrom-Json
    $state = $view.instanceView.executionState
    if ($state -in @('Succeeded', 'Failed', 'Canceled', 'TimedOut')) {
        break
    }
    Start-Sleep -Seconds 8
} while ((Get-Date) -lt $deadline)

Write-Host $view.instanceView.output
if ($view.instanceView.error) {
    Write-Host $view.instanceView.error -ForegroundColor Yellow
}

az connectedmachine run-command delete --name $runCommandName --machine-name $MachineName --resource-group $ResourceGroup --yes --output none 2>$null
Remove-Item $archivePath -Force -ErrorAction SilentlyContinue

if ($state -ne 'Succeeded') {
    throw "Arc deployment failed. Final state: $state"
}

Write-Ok "CloudUserSimulation package deployed to $MachineName at $RemoteRoot"
