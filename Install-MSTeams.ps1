<#
.SYNOPSIS
This script installs/uninstalls Microsoft Teams (New) either offline or online using Teamsbootstrapper.

.DESCRIPTION
The script performs an installation/uninstallation of Microsoft Teams (New) by executing the Teamsbootstrapper.exe with the appropriate flags based on the invocation parameters.
It supports offline installation using a local MSIX package or an online installation that downloads the necessary files. The process is logged in a specified log file.

.PARAMETER EXE
The name  of the executable file for the MSTeams installation bootstrapper. Default is "Teamsbootstrapper.exe".

.PARAMETER MSIX
The name of the MSIX file for offline installation of MSTeams, only required if using -Offline. Default is "MSTeams-x64.msix".

.PARAMETER LogFile
The path to the log file where the installation process will be logged. Default is "$env:TEMP\Install-MSTeams.log".

.PARAMETER TryFix
A switch parameter that, when present, will rey to fix and retry the installation of MSTeams if it fails with errorCode "0x80004004" by first deleting the regsitry key:
HKLM\Software\Wow6432Node\Microsoft\Office\Teams

.PARAMETER Offline
A switch parameter that, when present, will initiate an offline installation of MSTeams using the local MSIX file.

.PARAMETER Uninstall
A switch parameter that, when present, will deprovision MSTeams using the Teamsbootstrapper.exe and uninstall the MSTeams AppcPackage for AllUsers .

.EXAMPLE
.\Install-MSTeams.ps1
Executes the script to install MSTeams online with default parameters.

.EXAMPLE
.\Install-MSTeams.ps1 -Offline
Executes the script to install MSTeams offline using the specified MSIX file.

.EXAMPLE
.\Install-MSTeams.ps1 -TryFix
Executes the script and attempts to force the installation if certain errors are encountered.

.EXAMPLE
.\Install-MSTeams.ps1 Uninstall
Executes the script to deprovision and uninstall MSTeams for all users.

.NOTES
Author:     Sassan Fanai
Date:       2023-11-06
Version:    1.0.0.0
#>

param (
    $EXE = "Teamsbootstrapper.exe",
    $MSIX = "MSTeams-x64.msix",
    $LogFile = "$env:TEMP\Install-MSTeams.log",
    [switch]$TryFix,
    [switch]$Offline,
    [switch]$Uninstall
)

function Install-MSTeams {
    param (
        [switch]$Offline
    )
    if ($Offline) {
        $Result = & "$PSScriptRoot\$EXE" -p -o "$PSScriptRoot\$MSIX"
    }
    else {
        $Result = & "$PSScriptRoot\$EXE" -p
    }
    $ResultPSO = $Result | ConvertFrom-Json
    return $ResultPSO
}

function Uninstall-MSTeams {
    $InstalledAppx = Get-AppxPackage -AllUsers | Where-Object {$PSItem.Name -eq "MSTeams"}
    if ($InstalledAppx) {
        Log "$(Get-Now): MSTeams $($InstalledAppx.Version) package is installed for these users:"
        Log "$(Get-Now): PackageUserInformation $($InstalledAppx.PackageUserInformation.UserSecurityId.UserName)"
        Log "$(Get-Now): Uninstalling AppxPackage for AllUsers"
        $InstalledAppx | Remove-AppxPackage -AllUsers
    }
    Log "$(Get-Now): Deprovisioning MSTeams using $EXE"
    $Result = & "$PSScriptRoot\$EXE" -x

    $ResultPSO = $Result | ConvertFrom-Json
    return $ResultPSO
}

function Get-Now { return "{0:yyyy-MM-dd HH:mm:ss}" -f [DateTime]::Now }

function Log {
    param (
        $Text
     )

    $Text | Out-File -FilePath $LogFile -Append
    Write-Output $Text
}

if (-not(Test-Path -Path $PSScriptRoot\$EXE)) {
    Log "$(Get-Now): Could not find $EXE"
    exit 2
}

$EXEinfo = Get-ChildItem -Path "$PSScriptRoot\$EXE"
Log "$(Get-Now): $EXE version is $($EXEinfo.VersionInfo.ProductVersion)"

if ($Uninstall) {
    $LogFile = $LogFile.Replace("Install","Uninstall")
    $result = Uninstall-MSTeams
    $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem. Name -eq "MSTeams"}
    $ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq "MSTeams"}

    if (!$Appx -and !$ProvApp) {
        Log "$(Get-Now): MSTeams was successfully deprovisioned and uninstalled for all users"
        exit 0
    }
    else {
        Log "$(Get-Now): Error uninstalling MSTeans"
        Log "$(Get-Now): Result AppxPackage: $Appx"
        Log "$(Get-Now): Result Get-ProvisionedAppPackage: $ProvApp"
        exit 1
    }
}

if ($Offline) {
    if (-not(Test-Path -Path "$PSScriptRoot\$MSIX")) {
        Log "$(Get-Now): Offline parameter specified but could not find $MSIX"
        exit 2
    }
    $MSIXinfo = Get-AppLockerFileInformation "$PSScriptRoot\$MSIX"
    Log "$(Get-Now): $MSIX version is $($MSIXinfo.Publisher.BinaryVersion.ToString())"

    $result = Install-MSTeams -Offline
    if ($result.Success) {
        Log "$(Get-Now): $EXE ($($EXEinfo.VersionInfo.ProductVersion)) successfully installed $MSIX ($($MSIXinfo.Publisher.BinaryVersion.ToString())) offline"
        exit 0
    }
    if ($result.errorCode -eq "0x80004004" -and $TryFix) {
        Log "$(Get-Now): $EXE returned errorCode $($result.errorCode) and -TryFix was specified. This may happen if the registry key HKLM\Software\Wow6432Node\Microsoft\Office\Teams exists, will try to delete it and re-run installation"
        Remove-Item HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams -Force -ErrorAction SilentlyContinue
        $result = Install-MSTeams -Offline
        if ($result.Success) {
            Log "$(Get-Now): $EXE ($($EXEinfo.VersionInfo.ProductVersion)) successfully installed $MSIX ($($MSIXinfo.Publisher.BinaryVersion.ToString())) offline"
            exit 0
        }

    }
    Log "$(Get-Now): Error installing MSTeams offline using $EXE ($($EXEinfo.VersionInfo.ProductVersion)) and $MSIX ($($MSIXinfo.Publisher.BinaryVersion.ToString()))"
    Log "$(Get-Now): $EXE returned errorCode = $($result.errorCode)"
    Log "$(Get-Now): Result: $result"
    exit 1
}
else {
    $result = Install-MSTeams
    if ($result.Success) {
        Log "$(Get-Now): $EXE ($($EXEinfo.VersionInfo.ProductVersion)) successfully downloaded and installed MSTeams"
        exit 0
    }
    if ($result.errorCode -eq "0x80004004" -and $TryFix) {
        Log "$(Get-Now): $EXE returned errorCode $($result.errorCode) and -TryFix was specified. This may happen if the registry key HKLM\Software\Wow6432Node\Microsoft\Office\Teams exists, will try to delete it and re-run installation"
        Remove-Item HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams -Force -ErrorAction SilentlyContinue
        $result = Install-MSTeams
        if ($result.Success) {
            Log "$(Get-Now): $EXE ($($EXEinfo.VersionInfo.ProductVersion)) successfully downloaded and installed MSTeams"
            exit 0
        }
    }
    Log "$(Get-Now): Error installing MSTeams online using $EXE ($($EXEinfo.VersionInfo.ProductVersion))"
    Log "$(Get-Now): $EXE returned errorCode = $($result.errorCode)"
    Log "$(Get-Now): Result: $result"
    exit 1
}
