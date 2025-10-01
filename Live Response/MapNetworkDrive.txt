<#
.SYNOPSIS
    Map network drive
.DESCRIPTION
    Create a mapping of a network drive with the current user credentials or with diffrent credentials 
.INPUTS
    DriveName - the drive of the new mapped drive (for example X:)
    NetworkPath - the network path we want the new drive will mapped to (for example '\\Server01\Share1')
    Username - (optional) the username we want to use for the drive mapping (for example Contoso\JohnD). 
    Password - (optional) the username's password.
.EXAMPLE
    MapNetworkDrive 'X:' '\\Server01\Share1'
    MapNetworkDrive 'X:' '\\Server01\Share1' 'contoso\JohnD' 'TheBestPassword!!!'    
#> 
Param (
[parameter(Position=0,mandatory=$true)][String]$DriveName,
[parameter(Position=1,mandatory=$true)][String]$NetworkPath,
[parameter(Position=2,mandatory=$false)][String]$Username,
[parameter(Position=3,mandatory=$false)][String]$Password
)

if($PSBoundParameters.ContainsKey('Username') -and $PSBoundParameters.ContainsKey('Password'))
{
    New-SmbMapping -LocalPath $DriveName -RemotePath $NetworkPath -UserName $Username -Password $Password
}
else
{
    New-SmbMapping -LocalPath $DriveName -RemotePath $NetworkPath -Persistent $true 
}
