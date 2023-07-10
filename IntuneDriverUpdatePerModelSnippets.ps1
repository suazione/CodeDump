<#
    Graph snippets for creating AAD dynamic groups, Driver update profiles and assignments for every unique device model in Intune.
    Required modules: Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement, Microsoft.Graph.Groups and
    Microsoft.Graph.DeviceManagement.Actions (PowerShell Graph SDK v1) or Microsoft.Graph.Beta.DeviceManagement.Actions (PowerShell Graph SDK v2)

    Updated: 2023-07-10
    Author: Sassan Fanai @ Onevinn.se

    Version 0.0.0.2 - Works with PowerShell Graph SDK v2 (default). Set $GraphVersion to v1 or v2 depending on
                      the version you are using.
                      Stole some code from @jarwidmark to normalize Manufacturer/Make.
#>

# Set version of PowerShell Graph SDK that will be used, v1 or v2
$GraphVersion = "v2"

# Set naming scheme (prefix and suffix) for Groups and Driver Update profiles name. Can be omitted by setting them to "".
# Example result: DriverUpdate - LENOVO ThinkPad L13 Gen 3 - Pilot
$NamePrefix = "GraphV2 - "
$NameSuffix = " - Test2"

# Set Models to exclude creating groups and profiles for
$ExcludedModels = @("Virtual Machine")

# Set Approval type and number of deferral days in Driver Update profiles
$approvalType = "manual" # manual or automatic
$deploymentDeferralInDays = 7 # only used if approvalType is set to automatic

# Lenovo convert MTM to friendly name, thanks to Damien Van Robaeys @ https://www.systanddeploy.com/2023/01/get-list-uptodate-of-all-lenovo-models.html
function Get-LenovoFriendlyName {
        param (
            $MTM
        )
        $URL = "https://download.lenovo.com/bsco/public/allModels.json"
        $Get_Web_Content = Invoke-RestMethod -Uri $URL -Method GET
        $Current_Model = ($Get_Web_Content | where-object {($_ -like "*$MTM*") -and ($_ -notlike "*-UEFI Lenovo*") -and ($_ -notlike "*dTPM*") -and ($_ -notlike "*Asset*") -and ($_ -notlike "*fTPM*")})[0]
        $Get_FamilyName = ($Current_Model.name.split("("))[0].TrimEnd()
        $Get_FamilyName
}

# Connect to Graph
Connect-MgGraph -Scopes "DeviceManagementManagedDevices.ReadWrite.All", "Group.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All"

if ($GraphVersion -eq "v1") {
    Select-MgProfile -Name beta # This cmdlet does not exist and thus not needed uf using Microsoft Graph PowerShell SDK v1
}
#Import-Module Microsoft.Graph.DeviceManagement.Actions

# Get all unique Models in Intune with Windows as OS
$IntuneDevices = Get-MgDeviceManagementManagedDevice -Filter "OperatingSystem eq 'Windows'" | Sort-Object -Property Model -Unique
#$IntuneDevices | select Manufacturer, Model

# Create AAD groups for each unique model
foreach ($Device in $IntuneDevices) {
    Write-Host "Processing Make and Model: [$($Device.Manufacturer)] and [$($Device.Model)]" -ForegroundColor Cyan
    if ($Device.Model -notin $ExcludedModels) {
        $Make = $Device.Manufacturer
        $Model = $Device.Model

        switch -Wildcard ($Make) {
            "*Microsoft*" {
                $Make = "Microsoft"
            }
            "*HP*" {
                $Make = "HP"
            }
            "*Hewlett-Packard*" {
                $Make = "HP"
            }
            "*Dell*" {
                $Make = "Dell"
            }
            "*Lenovo*" {
                $Make = "Lenovo"
                $Model = Get-LenovoFriendlyName -MTM $Model.Substring(0,4)
                Write-Host "Manufacturer is [$Make]. Converting Model name from [$($Device.Model)] to [$Model] (for group/profile names)" -ForegroundColor Cyan
            }
        }

        $GroupName =  "$NamePrefix$($Make) $($Model)$($NameSuffix)"

        if ($Model.StartsWith($Make)) {
            Write-Host "Model name [$Model] starts with Manufacturer name [$Make]. Omitting Manufacturer from Group Name" -ForegroundColor Yellow
            $GroupName =  "$($NamePrefix)$($Model)$($NameSuffix)"
        }

        Write-Host "GroupName is [$GroupName]" -ForegroundColor Cyan
        $MR = '(device.deviceModel -eq "' + $($Device.Model) + '") and (device.deviceManufacturer -eq "' + $Make + '")'
        Write-Host "Dynamic MembershipRule = $MR" -ForegroundColor Magenta

        $ExistingGroup = Get-MgGroup -Filter "DisplayName eq '$GroupName'"
        if (!$ExistingGroup) {
            Write-Host "Group [$GroupName] does not exist, creating" -ForegroundColor Green
            $GroupParam = @{
                DisplayName = "$GroupName"
                Description = "Dynamic group for $($Model)"
                GroupTypes = @(
                    'DynamicMembership'
                )
                SecurityEnabled     = $true
                IsAssignableToRole  = $false
                MailEnabled         = $false
                membershipRuleProcessingState = 'On'
                MembershipRule = $($MR)
                MailNickname        = (New-Guid).Guid.Substring(0,10)
                "Owners@odata.bind" = @(
                    "https://graph.microsoft.com/v1.0/me"
                )
            }
            $GroupResult = New-MgGroup -BodyParameter $GroupParam
        }
        else {
            Write-Host "Group [$GroupName] already exists, skipping" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "$($Device.Model) is in ExcludedList, skipping" -ForegroundColor Yellow
    }
}

# Get all Driver profiles
$AllDriverProfiles = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles").value

# Get all AAD groups with NamePrefix
$AllDriverGroups = Get-MgGroup -Filter "startsWith(DisplayName,'$NamePrefix')"

# Create Driver Update Profile for each AAD group
foreach ($DriverGroup in $AllDriverGroups) {
    if ($DriverGroup.DisplayName -notin $AllDriverProfiles.displayName){
        Write-Host "No Driver Update profile named [$($DriverGroup.DisplayName)] exists, creating" -ForegroundColor Green
        $ProfileBody = @{
            '@odata.type' = "#microsoft.graph.windowsDriverUpdateProfile"
            displayName = "$($DriverGroup.DisplayName)"
            approvalType = "$approvalType"
            roleScopeTagIds = @()
            ContentType = "application/json"
        }
        if ($approvalType -eq "automatic"){
            $ProfileBody.Add("deploymentDeferralInDays",$deploymentDeferralInDays)
        }
        $DriverProfile = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles" -Body (ConvertTo-Json $ProfileBody)
    }
    else {
        Write-Host "Driver Update profile named [$($DriverGroup.DisplayName)] already exists, skipping" -ForegroundColor Yellow
        $DriverProfile = $AllDriverProfiles | Where-Object {$_.DisplayName -eq $DriverGroup.DisplayName}
    }

    # Create assignment for each Driver Update Profile to the AAD group with same name
    $AssignedGroups = (Invoke-MgGraphRequest -Method GET -Uri " https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles/$($DriverProfile.Id)/assignments").value.target.groupid
    if ($DriverGroup.Id -notin $AssignedGroups){
        Write-Host "Driver Udate Profile [$($DriverProfile.displayname)] is not assigned to AAD group [$($DriverGroup.DisplayName)], creating assignment" -ForegroundColor Green

        $AssignBody = @{
            assignments = @(
                @{
                    target = @{
                        '@odata.type' = "#microsoft.graph.groupAssignmentTarget"
                        groupId = "$($DriverGroup.Id)"
                    }
                }
            )
        }

        #Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles/$($DriverProfile.Id)/assignments" -Body (ConvertTo-Json $AssignBody) -ContentType "application/json"

        # If using Microsoft Graph PowerShell SDK v1
        if ($GraphVersion -eq "v1") {
            Set-MgDeviceManagementWindowDriverUpdateProfile -WindowsDriverUpdateProfileId $DriverProfile.Id -BodyParameter $AssignBody
        }

        # If using Microsoft Graph PowerShell SDK v2
        if ($GraphVersion -eq "v2") {
            Set-MgBetaDeviceManagementWindowsDriverUpdateProfile -WindowsDriverUpdateProfileId $DriverProfile.Id -BodyParameter $AssignBody
        }
    }
    else {
        Write-Host "Driver Udate Profile [$($DriverProfile.displayname)] is already assigned to AAD group [$($DriverGroup.DisplayName)], skipping" -ForegroundColor Yellow
    }
}
