<#
.SYNOPSIS
    Unmap network drive
.DESCRIPTION
    remove a mapping of a network drive
.INPUTS
    DriveName - the drive of the new mapped drive (for example X:)
.EXAMPLE
    UnmapNetworkDrive 'X:'
#> 
Param (
[parameter(Position=0,mandatory=$true)][String]$DriveName
)

Remove-smbmapping -LocalPath $DriveName -Force
