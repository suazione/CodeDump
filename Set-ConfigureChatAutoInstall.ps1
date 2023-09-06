<#
 Sets the registry item ConfigureChatAutoInstall to 0 to disable Teams Consumer installation.
 It's the same registry value that is being set when using it in unattend.xml

 The registry key is owned by TrustedInstaller and System does not have permissions to write to it.
 This script sets System as owner on the registry key [HKLM:\Software\Microsoft\Windows\CurrentVersion\Communications]
 to be able to set ACL permission for System on it. It then sets ConfigureChatAutoInstall to 0 and restores both ACL and owner
 permissions.
 Script will also try to remove Consumer Teams if it exists.

 Sassan Fanai
 Version 1.0.0.1 - 2023-06-02 - Created
 Version 1.0.0.2 - 2023-07-05 - Remove MicrosotTeams (consumer) AppxPackage if installed

#>
function Set-RegACL {
    <#
    .SYNOPSIS
     Sets ACL permission on registry key.

    .DESCRIPTION
     Sets ACL on regsitry key based on specified RegistryRights Enum.
     Made primarly for setting ACL on registry keys where only TrustedInstaller
     have full control. This function does not take ownership of the registry key,
     should be used with Take-Ownership function.

    .PARAMETER Path (Required)
     The path to the object on which you wish to change ownership.  It can be a file or a folder.

    .PARAMETER User (Required)
     The user whom you want to be the owner of the specified object.  The user should be in the format
     <domain>\<username>.  Other user formats will not work.  For system accounts, such as System, the user
     should be specified as "NT AUTHORITY\System".  If the domain is missing, the local machine will be assumed.

    .PARAMETER Permission (switch)
     What permission to set on registry key.

    .NOTES
     Name:    Set-RegACL
     Author:  Sassan Fanai
     Date:    2023-06-02
    #>
        [CmdletBinding()]
        param (
            $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications",
            $User = "NT AUTHORITY\System",
            [ValidateSet("FullControl","ReadKey","SetValue","TakeOwnership","WriteKey","ChangePermissions","CreateSubKey","NeptDeleteune","QueryValues")]
            $Permission = "FullControl"
        )

        $Item = Get-Item -Path $Path
        switch ($Item.Name.Split("\")[0]) {
            "HKEY_CLASSES_ROOT"   { $rootKey=[Microsoft.Win32.Registry]::ClassesRoot; break }
            "HKEY_LOCAL_MACHINE"  { $rootKey=[Microsoft.Win32.Registry]::LocalMachine; break }
            "HKEY_CURRENT_USER"   { $rootKey=[Microsoft.Win32.Registry]::CurrentUser; break }
            "HKEY_USERS"          { $rootKey=[Microsoft.Win32.Registry]::Users; break }
            "HKEY_CURRENT_CONFIG" { $rootKey=[Microsoft.Win32.Registry]::CurrentConfig; break }
        }
        Write-Verbose "Setting ACL permission [$Permission] for user [$User] @ [$Path]"
        $Key = $Item.Name.Replace(($Item.Name.Split("\")[0]+"\"),"")
        $Item = $rootKey.OpenSubKey($Key,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
        $acl = $Item.GetAccessControl()
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($User,$Permission,@("ObjectInherit","ContainerInherit"),"None","Allow")
        $acl.SetAccessRule($rule)
        $Item.SetAccessControl($acl)
    }

function Take-Ownership {
    <#
.SYNOPSIS
 Give ownership of a file or folder to the specified user.

.DESCRIPTION
 Give the current process the SeTakeOwnershipPrivilege" and "SeRestorePrivilege" rights which allows it
 to reset ownership of an object.  The script will then set the owner to be the specified user.

.PARAMETER Path (Required)
 The path to the object on which you wish to change ownership.  It can be a file or a folder.

.PARAMETER User (Required)
 The user whom you want to be the owner of the specified object.  The user should be in the format
 <domain>\<username>.  Other user formats will not work.  For system accounts, such as System, the user
 should be specified as "NT AUTHORITY\System".  If the domain is missing, the local machine will be assumed.

.PARAMETER Recurse (switch)
 Causes the function to parse through the Path recursively.

.INPUTS
 None. You cannot pipe objects to Take-Ownership

.OUTPUTS
 None

.NOTES
 Name:    Take-Ownership.ps1
 Author:  Jason Eberhardt
 Date:    2017-07-20
#>
    [CmdletBinding(SupportsShouldProcess=$false)]
    Param([Parameter(Mandatory=$true, ValueFromPipeline=$false)] [ValidateNotNullOrEmpty()] [string]$Path,
          [Parameter(Mandatory=$true, ValueFromPipeline=$false)] [ValidateNotNullOrEmpty()] [string]$User,
          [Parameter(Mandatory=$false, ValueFromPipeline=$false)] [switch]$Recurse)

    Begin {
$AdjustTokenPrivileges=@"
  using System;
  using System.Runtime.InteropServices;

    public class TokenManipulator {
      [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern IntPtr GetCurrentProcess();

      [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
      [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
      [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

      [StructLayout(LayoutKind.Sequential, Pack = 1)]
      internal struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
      }

      internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
      internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
      internal const int TOKEN_QUERY = 0x00000008;
      internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

      public static bool AddPrivilege(string privilege) {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = GetCurrentProcess();
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_ENABLED;
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
      }

      public static bool RemovePrivilege(string privilege) {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = GetCurrentProcess();
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_DISABLED;
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
      }
    }
"@
    }

    Process {
      Start-Transcript -Path $env:TEMP\MSTeamsPersonalRemove.log
      $Item=Get-Item $Path
      Write-Verbose "Giving current process token ownership rights"
      Add-Type $AdjustTokenPrivileges -PassThru > $null
      [void][TokenManipulator]::AddPrivilege("SeTakeOwnershipPrivilege")
      [void][TokenManipulator]::AddPrivilege("SeRestorePrivilege")

      # Change ownership
      $Account=$User.Split("\")
      if ($Account.Count -eq 1) { $Account+=$Account[0]; $Account[0]=$env:COMPUTERNAME }
      $Owner=New-Object System.Security.Principal.NTAccount($Account[0],$Account[1])
      Write-Verbose "Change ownership to '$($Account[0])\$($Account[1])'"

      $Provider=$Item.PSProvider.Name
      if ($Item.PSIsContainer) {
        switch ($Provider) {
          "FileSystem" { $ACL=[System.Security.AccessControl.DirectorySecurity]::new() }
          "Registry"   { $ACL=[System.Security.AccessControl.RegistrySecurity]::new()
                         # Get-Item doesn't open the registry in a way that we can write to it.
                         switch ($Item.Name.Split("\")[0]) {
                           "HKEY_CLASSES_ROOT"   { $rootKey=[Microsoft.Win32.Registry]::ClassesRoot; break }
                           "HKEY_LOCAL_MACHINE"  { $rootKey=[Microsoft.Win32.Registry]::LocalMachine; break }
                           "HKEY_CURRENT_USER"   { $rootKey=[Microsoft.Win32.Registry]::CurrentUser; break }
                           "HKEY_USERS"          { $rootKey=[Microsoft.Win32.Registry]::Users; break }
                           "HKEY_CURRENT_CONFIG" { $rootKey=[Microsoft.Win32.Registry]::CurrentConfig; break }
                         }
                         $Key=$Item.Name.Replace(($Item.Name.Split("\")[0]+"\"),"")
                         $Item=$rootKey.OpenSubKey($Key,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::TakeOwnership) }
          default { throw "Unknown provider:  $($Item.PSProvider.Name)" }
        }
        $ACL.SetOwner($Owner)
        Write-Verbose "Setting owner on $Path"
        $Item.SetAccessControl($ACL)
        if ($Provider -eq "Registry") { $Item.Close() }

        if ($Recurse.IsPresent) {
          # You can't set ownership on Registry Values
          if ($Provider -eq "Registry") { $Items=Get-ChildItem -Path $Path -Recurse -Force | Where-Object { $_.PSIsContainer } }
          else { $Items=Get-ChildItem -Path $Path -Recurse -Force }
          $Items=@($Items)
          for ($i=0; $i -lt $Items.Count; $i++) {
            switch ($Provider) {
              "FileSystem" { $Item=Get-Item $Items[$i].FullName
                             if ($Item.PSIsContainer) { $ACL=[System.Security.AccessControl.DirectorySecurity]::new() }
                             else { $ACL=[System.Security.AccessControl.FileSecurity]::new() } }
              "Registry"   { $Item=Get-Item $Items[$i].PSPath
                             $ACL=[System.Security.AccessControl.RegistrySecurity]::new()
                             # Get-Item doesn't open the registry in a way that we can write to it.
                             switch ($Item.Name.Split("\")[0]) {
                               "HKEY_CLASSES_ROOT"   { $rootKey=[Microsoft.Win32.Registry]::ClassesRoot; break }
                               "HKEY_LOCAL_MACHINE"  { $rootKey=[Microsoft.Win32.Registry]::LocalMachine; break }
                               "HKEY_CURRENT_USER"   { $rootKey=[Microsoft.Win32.Registry]::CurrentUser; break }
                               "HKEY_USERS"          { $rootKey=[Microsoft.Win32.Registry]::Users; break }
                               "HKEY_CURRENT_CONFIG" { $rootKey=[Microsoft.Win32.Registry]::CurrentConfig; break }
                             }
                             $Key=$Item.Name.Replace(($Item.Name.Split("\")[0]+"\"),"")
                             $Item=$rootKey.OpenSubKey($Key,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::TakeOwnership) }
              default { throw "Unknown provider:  $($Item.PSProvider.Name)" }
            }
            $ACL.SetOwner($Owner)
            Write-Verbose "Setting owner on $($Item.Name)"
            $Item.SetAccessControl($ACL)
            if ($Provider -eq "Registry") { $Item.Close() }
          }
        } # Recursion
      }
      else {
        if ($Recurse.IsPresent) { Write-Warning "Object specified is neither a folder nor a registry key.  Recursion is not possible." }
        switch ($Provider) {
          "FileSystem" { $ACL=[System.Security.AccessControl.FileSecurity]::new() }
          "Registry"   { throw "You cannot set ownership on a registry value"  }
          default { throw "Unknown provider:  $($Item.PSProvider.Name)" }
        }
        $ACL.SetOwner($Owner)
        Write-Verbose "Setting owner on $Path"
        $Item.SetAccessControl($ACL)
      }
    }
  }


  if ($null -eq (Get-AppxPackage -Name MicrosoftTeams -AllUsers)) {
      Write-Output “Microsoft Teams Personal App not present”
  }
  else {
      try {
          Write-Output “Removing Microsoft Teams Personal App”
          Get-AppxPackage -Name MicrosoftTeams -AllUsers | Remove-AppPackage -AllUsers
      }
      catch {
          Write-Output “Error removing Microsoft Teams Personal App”
      }
  }


Take-Ownership -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" -User "NT AUTHORITY\System" -Verbose

Set-RegACL -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" -User "NT AUTHORITY\System" -Permission FullControl -Verbose
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" -Name "ConfigureChatAutoInstall" -Value "0" -PropertyType Dword -Force | Out-Null
Set-RegACL -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" -User "NT AUTHORITY\System" -Permission ReadKey -Verbose

Take-Ownership -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" -User "NT SERVICE\TrustedInstaller" -Verbose
