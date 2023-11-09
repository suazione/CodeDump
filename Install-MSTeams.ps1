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
The path to the log file where the install/uninstall process will be logged. Default is "$env:TEMP\Install-MSTeams.log".

.PARAMETER TryFix
A switch parameter that, when present, will rey to fix and retry the installation of MSTeams if it fails with errorCode "0x80004004" by first deleting the regsitry key:
HKLM\Software\Wow6432Node\Microsoft\Office\Teams

.PARAMETER Offline
A switch parameter that, when present, will initiate an offline installation of MSTeams using the local MSIX file.

.PARAMETER Uninstall
A switch parameter that, when present, will deprovision MSTeams using the Teamsbootstrapper.exe and uninstall the MSTeams AppcPackage for AllUsers.

.PARAMETER ForceInstall
A switch parameter that, when present, will uninstall and deprovision MSTeams before attempting installation.

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
Date:       2023-11-09
Version:    1.0.0.6

Install command example: PowerShell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File ".\Install-NewTeams.ps1" -Offline -ForceInstall
Detection script example 1: if ("MSTeams" -in (Get-ProvisionedAppPackage -Online).DisplayName) { Write-Output "Installed" }
Detection script example 2: $MinVersion = "23285.3604.2469.4152"
                            $MSTeams = Get-ProvisionedAppPackage -Online |  Where-Object {$PSitem.DisplayName -like "MSTeams"}
                            if ($MSTeams.version -ge [version]$MinVersion ) { Write-Output "Installed" }
#>

param (
    $EXE = "Teamsbootstrapper.exe",
    $MSIX = "MSTeams-x64.msix",
    $LogFile = "$env:TEMP\Install-MSTeams.log",
    [switch]$TryFix,
    [switch]$Offline,
    [switch]$Uninstall,
    [switch]$ForceInstall
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
    $ResultPSO = try { $Result | ConvertFrom-Json } catch {$null}
    if ($null -ne $ResultPSO) {
        return $ResultPSO
    }
    else {
        return $Result
    }
}

function Uninstall-MSTeams {
    $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem.Name -eq "MSTeams"}
    if ($Appx) {
        Log "MSTeams $($Appx.Version) package is installed for these users:" -NoOutput
        Log "PackageUserInformation: $($Appx.PackageUserInformation.UserSecurityId.UserName)" -NoOutput
        Log "Uninstalling AppxPackage for AllUsers" -NoOutput
        $Appx | Remove-AppxPackage -AllUsers
    }
    Log "Deprovisioning MSTeams using $EXE" -NoOutput
    $Result = & "$PSScriptRoot\$EXE" -x

    $ResultPSO = try { $Result | ConvertFrom-Json } catch {$null}
    if ($null -ne $ResultPSO) {
        return $ResultPSO
    }
    else {
        return $Result
    }
}

function IsAppInstalled {
    param (
        $AppName = "MSTeams"
    )
    $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem. Name -eq $AppName}
    $ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq $AppName}
    if ($Appx) {
        Log "$AppName AppxPackage ($Appx) is currently installed for these users:"
        Log "PackageUserInformation: $($Appx.PackageUserInformation.UserSecurityId.UserName)"
    }
    else {
        Log "$AppName AppxPackage is currently NOT installed for any user"
    }
    if ($ProvApp) {
        Log "$AppName ProvisionedAppPackage ($($ProvApp.PackageName)) is currently installed"
    }
    else {
        Log "$AppName ProvisionedAppPackage is currently NOT installed"
    }
}

function Log {
    param (
        $Text,
        $LogFile = $LogFile,
        [switch]$NoOutput,
        [switch]$NoLog
     )

     $Now = "{0:yyyy-MM-dd HH:mm:ss}" -f [DateTime]::Now
     if (!$NoLog) {
        "$Now`: $($Text)" | Out-File -FilePath $LogFile -Append
    }
    if (!$NoOutput) {
        Write-Output "$Now`: $($Text)"
    }
}

if (-not(Test-Path -Path $PSScriptRoot\$EXE)) {
    Log "Failed to find $EXE"
    exit 2
}

$EXEinfo = Get-ChildItem -Path "$PSScriptRoot\$EXE"

if ($Uninstall) {
    $LogFile = $LogFile.Replace("Install","Uninstall")
    Log "Attempting to uninstall MSTeams"
    Log "$EXE version is $($EXEinfo.VersionInfo.ProductVersion)"

    $result = Uninstall-MSTeams
    $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem. Name -eq "MSTeams"}
    $ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq "MSTeams"}

    if (!$Appx -and !$ProvApp) {
        Log "MSTeams was successfully deprovisioned and uninstalled for all users"
        IsAppInstalled "MSTeams"
        exit 0
    }
    else {
        Log "Error uninstalling MSTeams: $Result"
        IsAppInstalled "MSTeams"
        exit 1
    }
}

if ($Offline) {
    if (-not(Test-Path -Path "$PSScriptRoot\$MSIX")) {
        Log "Offline parameter specified but failed to find $MSIX"
        exit 2
    }
    Log "Attempting to install MSTeams offline"
    $MSIXinfo = Get-AppLockerFileInformation "$PSScriptRoot\$MSIX"
    Log "$EXE version is $($EXEinfo.VersionInfo.ProductVersion)"
    Log "$MSIX version is $($MSIXinfo.Publisher.BinaryVersion.ToString())"

    if ($ForceInstall) {
        Log "ForceInstall parameter was specified, will attempt to uninstall and deprovision MSTeams before installing"
        $result = Uninstall-MSTeams
        Remove-Item HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams -Force -ErrorAction SilentlyContinue
        $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem. Name -eq "MSTeams"}
        $ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq "MSTeams"}

        if (!$Appx -and !$ProvApp) {
            Log "MSTeams was successfully deprovisioned and uninstalled for all users"
        }
        else {
            Log "Error uninstalling MSTeams: $Result"
            IsAppInstalled "MSTeams"
        }
    }
    $result = Install-MSTeams -Offline
    if ($result.Success) {
        Log "$EXE ($($EXEinfo.VersionInfo.ProductVersion)) successfully installed $MSIX ($($MSIXinfo.Publisher.BinaryVersion.ToString())) offline"
        exit 0
    }
    if ($result.errorCode -eq "0x80004004" -and $TryFix) {
        Log "$EXE returned errorCode $($result.errorCode) and -TryFix was specified. This may happen if the registry key HKLM\Software\Wow6432Node\Microsoft\Office\Teams exists, will try to delete it and re-run installation"
        Remove-Item HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams -Force -ErrorAction SilentlyContinue
        $result = Install-MSTeams -Offline
        if ($result.Success) {
            Log "$EXE ($($EXEinfo.VersionInfo.ProductVersion)) successfully installed $MSIX ($($MSIXinfo.Publisher.BinaryVersion.ToString())) offline"
            exit 0
        }
    }
    Log "Error installing MSTeams offline using $EXE ($($EXEinfo.VersionInfo.ProductVersion)) and $MSIX ($($MSIXinfo.Publisher.BinaryVersion.ToString()))"
    Log "$EXE returned errorCode = $($result.errorCode)"
    Log "Result: $result"
    Log "Installation will fail if the AppxPackage is already installed for any user. You can run the script with -ForceInstall to uninstall it prior to installation"
    IsAppInstalled "MSTeams"
    exit 1
}
else {
    Log "Attempting to install MSTeams online with $EXE"
    Log "$EXE version is $($EXEinfo.VersionInfo.ProductVersion)"
    if ($ForceInstall) {
        Log "ForceInstall parameter was specified, will attempt to uninstall and deprovision MSTeams before install"
        $result = Uninstall-MSTeams
        Remove-Item HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams -Force -ErrorAction SilentlyContinue
        $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem. Name -eq "MSTeams"}
        $ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq "MSTeams"}

        if (!$Appx -and !$ProvApp) {
            Log "MSTeams was successfully deprovisioned and uninstalled for all users"
        }
        else {
            Log "Error uninstalling MSTeams: $Result"
            IsAppInstalled "MSTeams"
        }
    }

    $result = Install-MSTeams
    if ($result.Success) {
        Log "$EXE ($($EXEinfo.VersionInfo.ProductVersion)) successfully downloaded and installed MSTeams"
        exit 0
    }
    if ($result.errorCode -eq "0x80004004" -and $TryFix) {
        Log "$EXE returned errorCode $($result.errorCode) and -TryFix was specified. This may happen if the registry key HKLM\Software\Wow6432Node\Microsoft\Office\Teams exists, will attempt to delete it and re-run installation"
        Remove-Item HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams -Force -ErrorAction SilentlyContinue
        $result = Install-MSTeams
        if ($result.Success) {
            Log "$EXE ($($EXEinfo.VersionInfo.ProductVersion)) successfully downloaded and installed MSTeams"
            exit 0
        }
    }
    Log "Error installing MSTeams online using $EXE ($($EXEinfo.VersionInfo.ProductVersion))"
    Log "$EXE returned errorCode = $($result.errorCode)"
    Log "Result: $result"
    Log "Installation will fail if the AppxPackage is already installed for any user. You can run the script with -ForceInstall to uninstall it prior to installation"
    IsAppInstalled "MSTeams"
    exit 1
}
