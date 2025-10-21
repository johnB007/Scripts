Param (
[parameter(Position=0,mandatory=$true)][String]$DriveName,
[parameter(Position=1,mandatory=$true)][String]$NetworkPath,
[parameter(Position=2,mandatory=$false)][String]$Username,
[parameter(Position=3,mandatory=$false)][String]$Password
)

if($PSBoundParameters.ContainsKey('Username') -and $PSBoundParameters.ContainsKey('Password'))
{
	Write-host "$DriveName $NetworkPath $Username $Password"
}
else
{
    Write-host "$DriveName $NetworkPath"
}
