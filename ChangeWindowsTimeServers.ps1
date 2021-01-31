#Requires -Version 4.0
#Requires -RunAsAdministrator

<#
	.SYNOPSIS
	Can change ntp time servers for Windows
	
	.Description
	Changes the Windows Time Servers. Script are able to change the HyperV Time Synchronization setting that makes HyperV able or unable to time synchronization.
	
	.PARAMETER -ntpserver1
	Determine the first priority NTP Server
	
	.PARAMETER -ntpserver2
	Determine the second priority NTP Server
	
	.PARAMETER -ntpserver3
	Determine the third priority NTP Server
	
	.PARAMETER -hyperv
	Enables or Disables the HyperV Time Synchronization setting for Windows Time service (Default: Ignore)
	
	.INPUTS
	None. You cannot pipe objects to this script.
	
	.EXAMPLE
	PS> .\ChangeTimeServers.ps1 [-ntpserver1 <string>] [-ntpserver2 <string>] [-ntpserver3 <string>]
	
	.EXAMPLE
	PS> .\ChangeTimeServers.ps1 [-ntpserver1 <string>] [-ntpserver2 <string>] [-ntpserver3 <string>] [-hyperv <boolean>]
	
	.LINK
	https://github.com/dexoidan/Win10ChangeTimeServers
#>

param (
	[CmdletBinding()]
	[Parameter(Mandatory=$true, ValueFromPipeline=$false)]
	[ValidateNotNullOrEmpty()][ValidatePattern('^((?:(?:(?:\w[\.\-\+]?)*)\w)+)((?:(?:(?:\w[\.\-\+]?){0,62})\w)+)\.(\w{2,6})$')][string]$ntpserver1,
	[Parameter(Mandatory=$true, ValueFromPipeline=$false)]
	[ValidateNotNullOrEmpty()][ValidatePattern('^((?:(?:(?:\w[\.\-\+]?)*)\w)+)((?:(?:(?:\w[\.\-\+]?){0,62})\w)+)\.(\w{2,6})$')][string]$ntpserver2,
	[Parameter(Mandatory=$true, ValueFromPipeline=$false)]
	[ValidateNotNullOrEmpty()][ValidatePattern('^((?:(?:(?:\w[\.\-\+]?)*)\w)+)((?:(?:(?:\w[\.\-\+]?){0,62})\w)+)\.(\w{2,6})$')][string]$ntpserver3,
	[Parameter(Mandatory=$false)][Nullable[Boolean]]$hyperv = $null
)

function Stop-TimeService {
	
	if(Get-Service w32time | Where-Object {$_.Status -eq "Running"})
	{
		Write-Host "Stopping Windows Time Service..."
		Stop-Service -Name w32time -ErrorAction SilentlyContinue -Force
	}
}

function Start-TimeService {
	
	if(Get-Service w32time | Where-Object {$_.Status -eq "Stopped"})
	{
		Write-Host "Starting Windows Time Service..."
		Start-Service -Name w32time -ErrorAction SilentlyContinue
	}
}

function ChangeTimeServers
{
	if(Get-Service w32time | Where-Object {$_.Status -eq "Stopped"})
	{
		Write-Host "Setting the Time Zone..."
		SetTimezone
		Write-Host "Change NTP Time Servers..."
		if([Environment]::Is64BitOperatingSystem)
		{
			Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers -Name 1 -Value $ntpserver1
			Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers -Name 2 -Value $ntpserver2
			Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers -Name 3 -Value $ntpserver3
		}
		if([Environment]::Is64BitOperatingSystem)
		{
			Set-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\DateTime\Servers -Name 1 -Value $ntpserver1
			Set-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\DateTime\Servers -Name 2 -Value $ntpserver2
			Set-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\DateTime\Servers -Name 3 -Value $ntpserver3
		}
		Start-TimeService
		$changeNTPcommand = "w32tm /config /manualpeerlist:'$ntpserver1,0x8 $ntpserver2,0x8 $ntpserver3,0x8' /syncfromflags:manual /reliable:yes /update"
		Invoke-Expression -Command $changeNTPcommand
	}
}

function EnableHyperVTimeSync
{
	if(Get-Service w32time | Where-Object {$_.Status -eq "Stopped"})
	{
		Write-Host "Enable HyperV Time Synchronization..."
		Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider -Name Enabled -Value 1 -Force
	}
}

function DisableHyperVTimeSync
{
	if(Get-Service w32time | Where-Object {$_.Status -eq "Stopped"})
	{
		Write-Host "Disable HyperV Time Synchronization..."
		Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider -Name Enabled -Value 0 -Force
	}
}

function SetTimezone
{
	Set-TimeZone -Id $TimezoneLocation
}

function EnumHyperV
{
	if($hyperv -eq $True)
	{
		EnableHyperVTimeSync
	}
	
	if($hyperv -eq $False)
	{
		DisableHyperVTimeSync
	}
}

function WinTimeSynchronization
{
	if(Get-Service w32time | Where-Object {$_.Status -eq "Running"})
	{
		Write-Host "Running time synchronization..."
		Invoke-Expression -Command 'w32tm /resync'
	}
}

$TimezoneLocation = "Romance Standard Time"

if($ntpserver1 -and $ntpserver2 -and $ntpserver3)
{
	Write-Host "First NTP Server: $ntpserver1"
	Write-Host "Second NTP Server: $ntpserver2"
	Write-Host "Third NTP Server: $ntpserver3"
	Stop-TimeService
	EnumHyperV
	ChangeTimeServers
	WinTimeSynchronization
	Stop-TimeService
	Start-TimeService
}
else
{
	if(($args.Count -eq 0) -or ($args.Count -eq 1) -or ($args.Count -eq 2))
	{
		
	}
	Write-Host "You need to define three domain names on ntp servers that you want use to change."
}