<#
.SYNOPSIS
This script installs/uninstalls Microsoft Teams (New) either offline or online using Teamsbootstrapper.

.DESCRIPTION
The script performs an installation/uninstallation of Microsoft Teams (New) by executing the Teamsbootstrapper.exe with the appropriate flags based on the invocation parameters.
It supports offline installation using a local MSIX package or an online installation that downloads the necessary files. The process is logged in a specified log file.
In an attempt to make the installation experience better and faster the -ForceInstall and -SetRunOnce parameters were made

.PARAMETER EXE
The name  of the executable file for the MSTeams installation bootstrapper. Default is "Teamsbootstrapper.exe".

.PARAMETER MSIX
The name of the MSIX file for offline installation of MSTeams, only required if using -Offline. Default is "MSTeams-x64.msix".

.PARAMETER LogFile
The path to the log file where the install/uninstall process will be logged. Default is "$env:TEMP\Install-MSTeams.log".

.PARAMETER Offline
A switch parameter that, when present, will initiate an offline installation of MSTeams using the local MSIX file.

.PARAMETER Uninstall
A switch parameter that, when present, will deprovision MSTeams using the Teamsbootstrapper.exe and uninstall the MSTeams AppcPackage for AllUsers.
Uninstall will delete the registry key: HKLM\Software\Wow6432Node\Microsoft\Office\Teams that can can block installations of MSTeams.
Uninstall will attempt to remove InstallMSTeams RunOnce registry item for Default User and existing profiles that may have been set by SetRunOnce.

.PARAMETER ForceInstall
A switch parameter that, when present, will uninstall and deprovision MSTeams before attempting installation. It will also delete the registry key:
HKLM\Software\Wow6432Node\Microsoft\Office\Teams that can can block the installation of MSTeams.

.PARAMETER SetRunOnce
A switch parameter that, when present, will configure RunOnce registry value for the Default User profile and all existing profiles to speed up installation of
MSTeams after a user sign in. The RunOnce key will be deleted when uninstalling MSTeams using -Uninstall.
If there is a active currently logged on user, a scheduled task will be be created that installs MSTeams as an AppxPackage to speed up the installation.

.PARAMETER DownloadExe
A switch parameter that, when present, will attempt to download Teamsbootstrapper.exe from Microsoft and verify its digital signature.
Using this parameter removes the need to include a local Teamsbootstrapper.exe. Has to be specified for -Uninstall as well.

.EXAMPLE
.\Install-MSTeams.ps1
Executes the script to install MSTeams "online" with default parameters.

.EXAMPLE
.\Install-MSTeams.ps1 -Offline
Executes the script to install MSTeams offline using the specified MSIX file.

.EXAMPLE
.\Install-MSTeams.ps1 -Uninstall
Executes the script to deprovision and uninstall MSTeams for all users.

.EXAMPLE
.\Install-MSTeams.ps1 -DownloadExe
Executes the script to first download the Teamsbootstrapper.exe from Microsoft and then install MSTeams "online".

.EXAMPLE
.\Install-MSTeams.ps1 -ForceInstall -SetRunOnce
Executes the script and attempts to force the installation by uninstalling MSTeams before attepmting an installation.
SetRunOnce will add a RunOnce registry entry and scheduled task to speed up the installation of MSTeams.
These are the recommended parameters for installation.

.NOTES
Author:     Sassan Fanai
Date:       2023-11-22
Version:    1.0.3.2 - Added -DownloadExe parameter that attempts to download Teamsbootstrapper.exe from Microsoft, removing the need of any local other local files.
                      Functions used for download and verification were stolen with pride from @JankeSkanke and MSEndpointMgr @ https://github.com/MSEndpointMgr/M365Apps. Thank you!

Install command example:    %windir%\Sysnative\WindowsPowerShell\v1.0\PowerShell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -File ".\Install-MSTeams.ps1" -Offline -ForceInstall
Detection script example 1: if ("MSTeams" -in (Get-ProvisionedAppPackage -Online).DisplayName) { Write-Output "Installed" }
Detection script example 2: $MinVersion = "23285.3604.2469.4152"
                            $MSTeams = Get-ProvisionedAppPackage -Online |  Where-Object {$PSitem.DisplayName -like "MSTeams"}
                            if ($MSTeams.version -ge [version]$MinVersion ) { Write-Output "Installed" }
#>
[CmdletBinding()]
param (
    $EXE = "Teamsbootstrapper.exe",
    $MSIX = "MSTeams-x64.msix",
    $LogFile = "$env:TEMP\Install-MSTeams.log",
    [switch]$Offline,
    [switch]$Uninstall,
    [Alias("TryFix")]
    [switch]$ForceInstall,
    [switch]$SetRunOnce,
    [switch]$DownloadExe,
    $DownloadExeURL = "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409" # URL to Teamsbootstrapper.exe from https://learn.microsoft.com/en-us/microsoftteams/new-teams-bulk-install-client
)

#region functions
function CreateScheduledTask {
    param (
        $TaskName = "InstallMSTeams",
        $PackageName
    )
    Log "Running CreateScheduledTask function"
    $LoggedOnUsers = ((query user) -replace '\s{20,39}', ',,') -replace '\s{2,}', ',' |
        ConvertFrom-Csv | Select-Object USERNAME, ID, STATE, @{n='IdleTime';e='IDLE TIME'}, @{n='LogonTime';e='LOGON TIME'}
    $ActiveUser = $LoggedOnUsers | Where-Object {$_.State -eq "Active" } | Select-Object -ExpandProperty Username

    if (-not $ActiveUser) {
        Log "No active user currently logged on"
        return
    }
    else {
        $ActiveUser = $ActiveUser.Replace(">","")
        Log "Active user currently logged on is: $ActiveUser"
    }

    Log "Creating scheduled task that will run for the current logged on user to speed up the installation"
    $commands = "Add-AppxPackage -RegisterByFamilyName -MainPackage $PackageName -EA SilentlyContinue"
    Log "Creating scheduled task [$taskName] that will run [$commands] for the currently logged on user [$ActiveUser]"

    # Create the action to execute the PowerShell commands
    $action = New-ScheduledTaskAction -Execute "cmd" -Argument "/c start /min `"`" powershell.exe -EP Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command `"$commands`""

    # Set the trigger for immediate execution
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(1)

    # Run in the user context
    $principal = New-ScheduledTaskPrincipal -UserId "$($ActiveUser)" -LogonType Interactive

    # Define task settings
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable

    # Register the task (hidden)
    $RegTask = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

    Log "Sleeping for a couple of seconds before removing the scheduled task [$taskName] "
    Start-Sleep -Seconds 5
    $UnregTask = Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}


function SetRunOnce {
    param (
        $PackageName,
        $RunOnceRegName,
        [switch]$Delete
    )
    Log "Running SetRunOnce function"
    Log "Loading NTUSER.DAT for Default User"
    $load = REG.EXE LOAD HKLM\Default C:\Users\Default\NTUSER.DAT

    $Value = "cmd /c start /min `"`" powershell.exe -EP Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command `"Add-AppxPackage -RegisterByFamilyName -MainPackage $PackageName -EA SilentlyContinue`""
    if ($Delete) {
        Log "Delete parameter was specified for SetRunOnce function"
        $RunOnceReg = Get-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name $RunOnceRegName -ErrorAction SilentlyContinue
        if ($RunOnceReg) {
            Log "Deleting $RunOnceRegName RunOnce entry from Default User profile"
            $reg = Remove-ItemProperty -Path "$($RunOnceReg.PSPath)" -Name $RunOnceRegName -Force
        }
    }
    else {
        Log "Creating RunOnce registry value: $value"
        $reg = New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\RunOnce" -PropertyType "String" -Name "$($RunOnceRegName)" -Value $Value -Force
    }

    Log "Running garbage collect and unloading Default User profile"
    try { $reg.Handle.Close() } catch {}
    [GC]::Collect()
    $unload = REG.EXE UNLOAD HKLM\Default

    # Run for existing profiles
    $UserProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
    Where-Object {$_.PSChildName -match "S-1-5-21-(\d+-?){4}$" } |
        Select-Object @{Name="SID"; Expression={$_.PSChildName}}, @{Name="UserHive";Expression={"$($_.ProfileImagePath)\NTuser.dat"}}

    foreach ($UserProfile in $UserProfiles) {
        # Load User NTUser.dat if it's not already loaded
        if (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Log "Loading NTUSER.DAT for profile: $($UserProfile.UserHive)"
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
        }
        else {
            Log "Profile already loaded for: $($UserProfile.UserHive), no need to load NTUSER.DAT"
        }
        if ($Delete) {
            $RunOnceReg = Get-ItemProperty -Path "registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name $RunOnceRegName -ErrorAction SilentlyContinue
            if ($RunOnceReg) {
                Log "Deleting $RunOnceRegName RunOnce entry from the user hive for: $($UserProfile.UserHive)"
                $reg = Remove-ItemProperty -Path "$($RunOnceReg.PSPath)" -Name $RunOnceRegName -Force
            }
        }
        else {
            Log "Creating RunOnce registry value for: $($UserProfile.UserHive) with SID $($UserProfile.SID)"
            $reg = New-ItemProperty "registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\RunOnce" -PropertyType "String" -Name "$($RunOnceRegName)" -Value $Value -Force
        }

        try { $reg.Handle.Close() } catch {}
        if ($ProfileWasLoaded -eq $false) {
            Log "Running garbage collector and unloading user profile: $($UserProfile.UserHive)"
            [GC]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden
        }
    }
}

function Install-MSTeams {
    param (
        [switch]$Offline
    )
    if ($Offline) {
        $Result = & "$EXEFolder\$EXE" -p -o "$MSIXFolder\$MSIX"
    }
    else {
        $Result = & "$EXEFolder\$EXE" -p
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
    Log "Running Uninstall-MSTeams function" -NoOutput
    $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem.Name -eq "MSTeams"}
    if ($Appx) {
        Log "MSTeams $($Appx.Version) package is installed for these users: $($Appx.PackageUserInformation.UserSecurityId.UserName)" -NoOutput
        Log "Uninstalling AppxPackage for AllUsers" -NoOutput
        $Appx | Remove-AppxPackage -AllUsers
    }
    Log "Deprovisioning MSTeams using $EXE" -NoOutput
    $Result = & "$EXEFolder\$EXE" -x

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
        Log "$AppName AppxPackage ($Appx) is currently installed for these users: $($Appx.PackageUserInformation.UserSecurityId.UserName)"
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

function Start-DownloadFile {
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$URL,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    Begin {
        # Construct WebClient object
        $WebClient = New-Object -TypeName System.Net.WebClient
    }
    Process {
        # Create path if it doesn't exist
        if (-not(Test-Path -Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        # Start download of file
        $WebClient.DownloadFile($URL, (Join-Path -Path $Path -ChildPath $Name))
    }
    End {
        # Dispose of the WebClient object
        $WebClient.Dispose()
    }
}
function Invoke-FileCertVerification {
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )
    # Get a X590Certificate2 certificate object for a file
    $Cert = (Get-AuthenticodeSignature -FilePath $FilePath).SignerCertificate
    $CertStatus = (Get-AuthenticodeSignature -FilePath $FilePath).Status
    if ($Cert){
        #Verify signed by Microsoft and Validity
        if ($cert.Subject -match "O=Microsoft Corporation" -and $CertStatus -eq "Valid"){
            #Verify Chain and check if Root is Microsoft
            $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
            $chain.Build($cert) | Out-Null
            $RootCert = $chain.ChainElements | ForEach-Object {$_.Certificate}| Where-Object {$PSItem.Subject -match "CN=Microsoft Root"}
            if (-not [string ]::IsNullOrEmpty($RootCert)){
                #Verify root certificate exists in local Root Store
                $TrustedRoot = Get-ChildItem -Path "Cert:\LocalMachine\Root" -Recurse | Where-Object { $PSItem.Thumbprint -eq $RootCert.Thumbprint}
                if (-not [string]::IsNullOrEmpty($TrustedRoot)){
                    Log "Verified setupfile signed by : $($Cert.Issuer)"
                    Return $True
                }
                else {
                    Log "No trust found to root cert - aborting"
                    Return $False
                }
            }
            else {
                Log "Certificate chain not verified to Microsoft - aborting"
                Return $False
            }
        }
        else {
            Log "Certificate not valid or not signed by Microsoft - aborting"
            Return $False
        }
    }
    else {
        Log "Setup file not signed - aborting"
        Return $False
    }
}

#endregion functions

Log "### Starting Install-MSTeams execution ###"
$EXEFolder = $PSScriptRoot
$MSIXFolder = $PSScriptRoot

if ($DownloadExe) {
    Log "Attempting to download Teamsbootstrapper.exe"
    Start-DownloadFile -URL $DownloadExeURL -Path $env:TEMP -Name "Teamsbootstrapper.exe"
    $FileCheck = Invoke-FileCertVerification -FilePath (Join-Path -Path $env:TEMP -ChildPath $EXE)
    if ($FileCheck) {
        Log "Verification of downloaded Teamsbootstrapper.exe was successful"
        $EXEFolder = $Env:TEMP
    }
    else {
        Log "Verification of downloaded Teamsbootstrapper.exe failed"
    }
}



if (-not(Test-Path -Path $EXEFolder\$EXE)) {
    Log "Failed to find $EXE"
    exit 2
}

$EXEinfo = Get-ChildItem -Path "$EXEFolder\$EXE"

if ($Uninstall) {
    $LogFile = $LogFile.Replace("Install","Uninstall")
    Log "Attempting to uninstall MSTeams"
    IsAppInstalled "MSTeams"
    Log "$EXE version is $($EXEinfo.VersionInfo.ProductVersion)"

    $result = Uninstall-MSTeams
    $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem. Name -eq "MSTeams"}
    $ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq "MSTeams"}

    if (!$Appx -and !$ProvApp) {
        Log "Deleting registry key (if it exists): HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams"
        Remove-Item HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams -Force -ErrorAction SilentlyContinue
        Log "MSTeams is not installed as a ProvisionedAppPackage or AppxPackage for any user"
        SetRunOnce -RunOnceRegName "InstallMSTeams" -Delete
        exit 0
    }
    else {
        Log "Error uninstalling MSTeams: $Result"
        IsAppInstalled "MSTeams"
        exit 1
    }
}

if ($Offline) {
    if (-not(Test-Path -Path "$MSIXFolder\$MSIX")) {
        Log "Offline parameter specified but failed to find $MSIX"
        exit 2
    }
    Log "Attempting to install MSTeams offline with local MSIX"
    $MSIXinfo = Get-AppLockerFileInformation "$MSIXFolder\$MSIX"
    Log "$EXE version is $($EXEinfo.VersionInfo.ProductVersion)"
    Log "$MSIX version is $($MSIXinfo.Publisher.BinaryVersion.ToString())"

    if ($ForceInstall) {
        Log "ForceInstall parameter was specified, will attempt to uninstall and deprovision MSTeams before installing"
        IsAppInstalled "MSTeams"
        $result = Uninstall-MSTeams
        Log "Deleting registry key (if it exists): HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams"
        Remove-Item HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams -Force -ErrorAction SilentlyContinue
        $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem. Name -eq "MSTeams"}
        $ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq "MSTeams"}

        if (!$Appx -and !$ProvApp) {
            "MSTeams is not installed as a ProvisionedAppPackage or AppxPackage for any user"
        }
        else {
            Log "Error uninstalling MSTeams: $Result"
            IsAppInstalled "MSTeams"
        }
    }
    $result = Install-MSTeams -Offline
    if ($result.Success) {
        Log "$EXE ($($EXEinfo.VersionInfo.ProductVersion)) successfully installed $MSIX ($($MSIXinfo.Publisher.BinaryVersion.ToString())) offline"
        if ($SetRunOnce) {
            $ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq "MSTeams"}
            Log "SetRunOnce parameter specified, attempting to configure RunOnce registry key for Default User and existing profiles to speed up installation of MSTeams after sign in"
            SetRunOnce -PackageName "$($ProvApp.PackageName)" -RunOnceRegName "InstallMSTeams"
            CreateScheduledTask -PackageName "$($ProvApp.PackageName)"
        }
        Log "### Finished Install-MSTeams execution ###"
        exit 0
    }

    Log "Error installing MSTeams offline using $EXE ($($EXEinfo.VersionInfo.ProductVersion)) and $MSIX ($($MSIXinfo.Publisher.BinaryVersion.ToString()))"
    Log "$EXE returned errorCode = $($result.errorCode)"
    Log "Result: $result"
    Log "Installation will fail if the AppxPackage is already installed for any user. You can run the script with -ForceInstall to uninstall MSTeams prior to installation"
    IsAppInstalled "MSTeams"
    exit 1
}
else {
    Log "Attempting to install MSTeams online with $EXE"
    Log "$EXE version is $($EXEinfo.VersionInfo.ProductVersion)"
    if ($ForceInstall) {
        Log "ForceInstall parameter was specified, will attempt to uninstall and deprovision MSTeams before install"
        $result = Uninstall-MSTeams
        Log "Deleting registry key (if it exists): HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams"
        Remove-Item HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\Teams -Force -ErrorAction SilentlyContinue
        $Appx = Get-AppxPackage -AllUsers | Where-Object {$PSItem. Name -eq "MSTeams"}
        $ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq "MSTeams"}

        if (!$Appx -and !$ProvApp) {
            Log "MSTeams is not installed as a ProvisionedAppPackage or AppxPackage for any user"
        }
        else {
            Log "Error uninstalling MSTeams: $Result"
            IsAppInstalled "MSTeams"
        }
    }

    $result = Install-MSTeams
    if ($result.Success) {
        Log "$EXE ($($EXEinfo.VersionInfo.ProductVersion)) successfully downloaded and installed MSTeams"
        if ($SetRunOnce) {
            $ProvApp = Get-ProvisionedAppPackage -Online | Where-Object {$PSItem. DisplayName -eq "MSTeams"}
            Log "SetRunOnce parameter specified, attempting to configure RunOnce registry key for Default User and existing profiles to speed up installation of MSTeams after sign in"
            SetRunOnce -PackageName "$($ProvApp.PackageName)" -RunOnceRegName "InstallMSTeams"
            CreateScheduledTask -PackageName "$($ProvApp.PackageName)"
        }
        Log "### Finished Install-MSTeams execution ###"
        exit 0
    }

    Log "Error installing MSTeams online using $EXE ($($EXEinfo.VersionInfo.ProductVersion))"
    Log "$EXE returned errorCode = $($result.errorCode)"
    Log "Result: $result"
    Log "Installation will fail if the AppxPackage is already installed for any user. You can run the script with -ForceInstall to uninstall MSTeams prior to installation"
    IsAppInstalled "MSTeams"
    exit 1
}
