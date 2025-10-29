# =======================================================================================
# SecurityBaseline-RegistryOwnership.ps1
# TrustedInstaller Registry Ownership Management (Best Practice 2025)
# =======================================================================================

<#
.SYNOPSIS
    Enables setting of TrustedInstaller-protected Registry keys
    
.DESCRIPTION
    Professional ownership management for protected Registry keys.
    
    PROCESS:
    1. Backup: Save original owner and permissions
    2. Take Ownership: Change to BUILTIN\Administrators
    3. Grant Access: Give Administrators Full Control
    4. Modify: Set the desired value
    5. Restore: Restore original owner and permissions
    
.NOTES
    Version:        1.0.0
    Author:         NoID Privacy Team
    Creation Date:  January 2026
    
    SECURITY:
    - Complete backup before changes
    - Automatic restore after changes
    - Error handling at every level
    
    TESTED WITH:
    - HKLM:\SOFTWARE\Microsoft\Windows Defender\Features
    - Other TrustedInstaller-protected keys
#>

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

# ===== PRIVILEGE MANAGEMENT (CRITICAL FOR TRUSTEDINSTALLER RESTORE!) ======

function Enable-Privilege {
    <#
    .SYNOPSIS
        Enables Windows privilege for current process
    .DESCRIPTION
        CRITICAL: SeRestorePrivilege is required to restore ownership back to TrustedInstaller!
        Based on Best Practice from StackOverflow (2025)
    .PARAMETER Privilege
        Privilege name (e.g. "SeRestorePrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege")
    .OUTPUTS
        [bool] $true on success
    .LINK
        https://stackoverflow.com/questions/5467909/how-to-write-in-a-registry-key-own-by-trustedinstaller
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('SeRestorePrivilege', 'SeBackupPrivilege', 'SeTakeOwnershipPrivilege', 'SeSecurityPrivilege')]
        [string]$Privilege
    )
    
    try {
        # P/Invoke definitions for token manipulation
        $signature = @"
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
            
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
                ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
            
            [DllImport("kernel32.dll", ExactSpelling = true)]
            public static extern IntPtr GetCurrentProcess();
            
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            public static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
            
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct TokPriv1Luid {
                public int Count;
                public long Luid;
                public int Attr;
            }
            
            public const int SE_PRIVILEGE_ENABLED = 0x00000002;
            public const int TOKEN_QUERY = 0x00000008;
            public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
"@
        
        # Create type if not already present
        if (-not ([System.Management.Automation.PSTypeName]'TokenManipulator').Type) {
            Add-Type -MemberDefinition $signature -Name TokenManipulator -Namespace RegistryOwnership -ErrorAction Stop
        }
        
        # Get current process token
        $token = [IntPtr]::Zero
        $hProcess = [RegistryOwnership.TokenManipulator]::GetCurrentProcess()
        
        if (-not [RegistryOwnership.TokenManipulator]::OpenProcessToken(
            $hProcess,
            [RegistryOwnership.TokenManipulator]::TOKEN_ADJUST_PRIVILEGES -bor [RegistryOwnership.TokenManipulator]::TOKEN_QUERY,
            [ref]$token
        )) {
            Write-Verbose "Error opening process token"
            return $false
        }
        
        # Lookup Privilege Value
        $luid = 0L
        if (-not [RegistryOwnership.TokenManipulator]::LookupPrivilegeValue($null, $Privilege, [ref]$luid)) {
            Write-Verbose "Error looking up $Privilege"
            return $false
        }
        
        # Prepare TOKEN_PRIVILEGES structure
        $tokPriv = New-Object RegistryOwnership.TokenManipulator+TokPriv1Luid
        $tokPriv.Count = 1
        $tokPriv.Luid = $luid
        $tokPriv.Attr = [RegistryOwnership.TokenManipulator]::SE_PRIVILEGE_ENABLED
        
        # Adjust Token Privileges
        if (-not [RegistryOwnership.TokenManipulator]::AdjustTokenPrivileges(
            $token,
            $false,
            [ref]$tokPriv,
            0,
            [IntPtr]::Zero,
            [IntPtr]::Zero
        )) {
            Write-Verbose "Error adjusting token privileges for $Privilege"
            return $false
        }
        
        Write-Verbose "Privilege enabled: $Privilege"
        return $true
    }
    catch {
        Write-Verbose "Error enabling $Privilege : $_"
        return $false
    }
}

function Set-RegistryValueWithOwnership {
    <#
    .SYNOPSIS
        Sets Registry value even with TrustedInstaller protection
    .DESCRIPTION
        Temporarily takes ownership, sets value, restores ownership.
        Best Practice 2025: Complete backup/restore
    .PARAMETER Path
        Registry path
    .PARAMETER Name
        Value name
    .PARAMETER Value
        Value
    .PARAMETER Type
        Registry type (DWord, String, etc.)
    .PARAMETER Description
        Description for logging
    .OUTPUTS
        [bool] $true on success, $false on error
    .EXAMPLE
        Set-RegistryValueWithOwnership -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" `
            -Name "EnableAppInstallControl" -Value 1 -Type DWord
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [object]$Value,
        
        [Parameter()]
        [Microsoft.Win32.RegistryValueKind]$Type = 'DWord',
        
        [Parameter()]
        [string]$Description
    )
    
    # IMPORTANT: Convert PowerShell path to Registry path
    # "HKLM:\SOFTWARE\..." -> "HKEY_LOCAL_MACHINE\SOFTWARE\..."
    $registryPath = $Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' `
                         -replace '^HKCU:\\', 'HKEY_CURRENT_USER\' `
                         -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\' `
                         -replace '^HKU:\\', 'HKEY_USERS\' `
                         -replace '^HKCC:\\', 'HKEY_CURRENT_CONFIG\'
    
    Write-Verbose "Registry-Path: $registryPath"
    Write-Verbose "Setting: $Name = $Value"
    if ($Description) {
        Write-Verbose "Description: $Description"
    }
    
    # ===== BACKUP: Speichere Original-ACL =====
    $originalACL = $null
    $originalOwner = $null
    
    # Determine Registry Hive (HKLM, HKCU, HKU, etc.)
    $hive = $null
    $subKeyPath = ''
    
    if ($registryPath -match '^HKEY_LOCAL_MACHINE\\(.*)') {
        $hive = [Microsoft.Win32.Registry]::LocalMachine
        $subKeyPath = $matches[1]
    }
    elseif ($registryPath -match '^HKEY_CURRENT_USER\\(.*)') {
        $hive = [Microsoft.Win32.Registry]::CurrentUser
        $subKeyPath = $matches[1]
    }
    elseif ($registryPath -match '^HKEY_USERS\\(.*)') {
        $hive = [Microsoft.Win32.Registry]::Users
        $subKeyPath = $matches[1]
    }
    elseif ($registryPath -match '^HKEY_CLASSES_ROOT\\(.*)') {
        $hive = [Microsoft.Win32.Registry]::ClassesRoot
        $subKeyPath = $matches[1]
    }
    elseif ($registryPath -match '^HKEY_CURRENT_CONFIG\\(.*)') {
        $hive = [Microsoft.Win32.Registry]::CurrentConfig
        $subKeyPath = $matches[1]
    }
    else {
        Write-Error-Custom "Unsupported registry hive: $registryPath"
        return $false
    }
    
    try {
        # Hole aktuelle ACL (Owner + Permissions)
        $key = $hive.OpenSubKey(
            $subKeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
            [System.Security.AccessControl.RegistryRights]::ReadPermissions
        )
        
        if ($null -eq $key) {
            Write-Verbose "Registry-Key nicht gefunden: $Path (nicht kritisch)"
            return $false
        }
        
        $originalACL = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::All)
        $originalOwner = $originalACL.Owner
        $key.Close()
        
        Write-Verbose "Original Owner: $originalOwner"
        Write-Verbose "Original ACL gesichert"
    }
    catch {
        Write-Verbose "Error reading original ACL: $_ (TrustedInstaller-Protected)"
        return $false
    }
    
    # ===== STEP 1: TAKE OWNERSHIP =====
    try {
        Write-Verbose "STEP 1: Take Ownership to BUILTIN\Administrators"
        
        # CRITICAL: Enable SeTakeOwnershipPrivilege BEFORE we call OpenSubKey!
        # Without this privilege, OpenSubKey fails with "Access Denied"!
        Write-Verbose "     Activate SeTakeOwnershipPrivilege..."
        $takeOwnershipEnabled = Enable-Privilege -Privilege 'SeTakeOwnershipPrivilege'
        
        if (-not $takeOwnershipEnabled) {
            Write-Verbose "SeTakeOwnershipPrivilege could not be enabled (TrustedInstaller-Protected)"
            Write-Verbose "Administrator rights present but key is protected"
            return $false
        }
        
        # Open key with TakeOwnership rights
        # IMPORTANT: We need ReadPermissions + TakeOwnership combined!
        $key = $hive.OpenSubKey(
            $subKeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ReadPermissions -bor
            [System.Security.AccessControl.RegistryRights]::TakeOwnership
        )
        
        if ($null -eq $key) {
            Write-Verbose "Could not open key for TakeOwnership: $Path (TrustedInstaller-Protected)"
            return $false
        }
        
        # Create new ACL with Administrators as owner
        $acl = $key.GetAccessControl()
        
        # BUILTIN\Administrators as new owner
        # CRITICAL: Use SID instead of name (language-independent!)
        # S-1-5-32-544 = BUILTIN\Administrators (in all languages!)
        $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $administratorsGroup = $adminsSid.Translate([System.Security.Principal.NTAccount])
        $acl.SetOwner($administratorsGroup)
        
        # Set new ACL
        $key.SetAccessControl($acl)
        $key.Close()
        
        Write-Verbose "     Ownership changed to: BUILTIN\Administrators"
    }
    catch {
        Write-Verbose "Take Ownership failed (TrustedInstaller too strong): $_"
        Write-Verbose "ACCEPTED: Registry-Key remains TrustedInstaller-protected (not critical)"
        # NO further attempts! TrustedInstaller keys are INTENTIONALLY protected!
        # The functionality (e.g. PUA) works EVEN WITHOUT these Registry values!
        # Set-MpPreference sets the settings via a different way.
        return $false
    }
    
    # ===== STEP 2: GRANT FULL CONTROL =====
    try {
        Write-Verbose "STEP 2: Grant Full Control to Administrators"
        
        # Open key with ChangePermissions rights
        $key = $hive.OpenSubKey(
            $subKeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions
        )
        
        $acl = $key.GetAccessControl()
        
        # Create Full Control rule for Administrators
        # CRITICAL: Use SID instead of name (language-independent!)
        # S-1-5-32-544 = BUILTIN\Administrators (in all languages!)
        $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $administratorsGroup = $adminsSid.Translate([System.Security.Principal.NTAccount])
        $fullControlRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $administratorsGroup,
            [System.Security.AccessControl.RegistryRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        
        # Add rule
        $acl.AddAccessRule($fullControlRule)
        $key.SetAccessControl($acl)
        $key.Close()
        
        Write-Verbose "  -> Full Control granted to: BUILTIN\Administrators"
    }
    catch {
        Write-Verbose "Error granting access: $_ (TrustedInstaller-Protected)"
        
        # Try restore
        try {
            Write-Verbose "Trying to restore original ACL..."
            # Enable SeRestorePrivilege for TrustedInstaller restore
            $null = Enable-Privilege -Privilege 'SeRestorePrivilege'
            $key = $hive.OpenSubKey(
                $subKeyPath,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
                [System.Security.AccessControl.RegistryRights]::TakeOwnership
            )
            $key.SetAccessControl($originalACL)
            $key.Close()
            Write-Verbose "     Original ACL restored"
        }
        catch {
            Write-Warning-Custom "Could not restore original ACL: $_"
        }
        
        return $false
    }
    
    # ===== STEP 3: MODIFY VALUE =====
    try {
        Write-Verbose "STEP 3: Set Registry value"
        
        # Check if value exists
        $valueExists = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        
        if ($valueExists) {
            # Value exists - Set-ItemProperty (NO -PropertyType parameter in PS 5.1!)
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
        }
        else {
            # Value does NOT exist - New-ItemProperty (WITH -PropertyType!)
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        }
        
        Write-Verbose "  -> Value successfully set: $Name = $Value"
    }
    catch {
        Write-Verbose "Error setting value: $_ (TrustedInstaller-Protected)"
        
        # Try restore
        try {
            Write-Verbose "Trying to restore original ACL..."
            # Enable SeRestorePrivilege for TrustedInstaller restore
            $null = Enable-Privilege -Privilege 'SeRestorePrivilege'
            $key = $hive.OpenSubKey(
                $subKeyPath,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
                [System.Security.AccessControl.RegistryRights]::TakeOwnership
            )
            $key.SetAccessControl($originalACL)
            $key.Close()
            Write-Verbose "     Original ACL restored"
        }
        catch {
            Write-Warning-Custom "Could not restore original ACL: $_"
        }
        
        return $false
    }
    
    # ===== STEP 4: RESTORE ORIGINAL ACL =====
    try {
        Write-Verbose "STEP 4: Restore Original Owner and Permissions"
        
        # CRITICAL: Enable SeRestorePrivilege BEFORE we restore TrustedInstaller ownership!
        # Without this privilege, SetAccessControl fails with TrustedInstaller owner!
        # Best Practice aus StackOverflow: https://stackoverflow.com/questions/5467909
        Write-Verbose "     Activate SeRestorePrivilege for TrustedInstaller-Restore..."
        $privilegeEnabled = Enable-Privilege -Privilege 'SeRestorePrivilege'
        
        if (-not $privilegeEnabled) {
            Write-Verbose "     WARNING: SeRestorePrivilege could not be enabled"
            Write-Verbose "     Restore will still be attempted (may not work with TrustedInstaller)"
        }
        
        # Open key with full rights
        $key = $hive.OpenSubKey(
            $subKeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
            [System.Security.AccessControl.RegistryRights]::TakeOwnership
        )
        
        # Restore original ACL (including owner)
        # With SeRestorePrivilege, TrustedInstaller can also be set as owner!
        $key.SetAccessControl($originalACL)
        $key.Close()
        
        Write-Verbose "  -> Original owner restored: $originalOwner"
        Write-Verbose "  -> Original permissions restored"
    }
    catch {
        # NOT CRITICAL! Registry value was SUCCESSFULLY set!
        # Only the restore of the original owner failed (usually TrustedInstaller)
        Write-Verbose "Original ACL restore failed (NOT CRITICAL): $_"
        Write-Verbose "Key owner remains: BUILTIN\Administrators (instead of $originalOwner)"
        Write-Verbose "Registry value was SUCCESSFULLY set - Windows functions normally"
        Write-Verbose "Possible cause: SeRestorePrivilege not available or TrustedInstaller restore blocked"
        # Do NOT throw error - the main function (setting Registry value) was SUCCESSFUL!
    }
    
    # ===== SUCCESS =====
    if ($Description) {
        Write-Verbose "[OK] $Description"
    }
    Write-Verbose "[OK] Registry value successfully set (with ownership management)"
    
    return $true
}

function Set-RegistryValueSmart {
    <#
    .SYNOPSIS
        Intelligent Registry function with automatic ownership management
    .DESCRIPTION
        Tries normal Set-ItemProperty first.
        On Access Denied -> automatic ownership management.
        Best Practice 2025: Try normal first, escalate only if needed
    .PARAMETER Path
        Registry path
    .PARAMETER Name
        Value name
    .PARAMETER Value
        Value
    .PARAMETER Type
        Registry type
    .PARAMETER Description
        Description
    .OUTPUTS
        [bool] $true on success
    .EXAMPLE
        Set-RegistryValueSmart -Path $path -Name $name -Value $value -Type DWord
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [object]$Value,
        
        [Parameter()]
        [Microsoft.Win32.RegistryValueKind]$Type = 'DWord',
        
        [Parameter()]
        [string]$Description
    )
    
    # STEP 1: Try normal Set-ItemProperty
    Write-Verbose "Trying normal Set-ItemProperty..."
    
    # CRITICAL FIX: Set-ItemProperty with ErrorActionPreference = 'SilentlyContinue'
    # Suppresses error in transcript but Try-Catch still works!
    $oldPref = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    
    # Create key if not present
    if (-not (Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
        Write-Verbose "Creating Registry key: $Path"
        $null = New-Item -Path $Path -Force
    }
    
    # Check if value exists (SAFE method - no error records!)
    # Get ALL properties first, then check if our property is in the list
    # This prevents error records from being created when property doesn't exist
    $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    $valueExists = $item -and ($item.PSObject.Properties.Name -contains $Name)
    
    # Track errors AFTER the exists check
    $errorBefore = $Error.Count
    
    if ($valueExists) {
        # Value exists - Set-ItemProperty (NO -PropertyType in PS 5.1!)
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    }
    else {
        # Value does NOT exist - New-ItemProperty (WITH -PropertyType!)
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
    
    # Reset ErrorActionPreference immediately
    $ErrorActionPreference = $oldPref
    
    # Check if error occurred (ONLY from Set/New, not from exists check!)
    $errorAfter = $Error.Count
    if ($errorAfter -eq $errorBefore) {
        # No error = success!
        if ($Description) {
            Write-Verbose "     $Description : $Name = $Value"
        }
        return $true
    }
    else {
        # Error occurred - check if Access Denied
        $lastError = $Error[0]
        $errorMsg = $lastError.Exception.Message
        $isAccessDenied = $false
        
        # German + English error messages
        if ($errorMsg -match "Access.*denied|Zugriff.*verweigert|unzulässig|angeforderte.*Registrierungszugriff") {
            $isAccessDenied = $true
        }
        
        # HResult Check (0x80070005 = Access Denied)
        if ($lastError.Exception.HResult -eq 0x80070005 -or $lastError.Exception.HResult -eq -2147024891) {
            $isAccessDenied = $true
        }
        
        if ($isAccessDenied) {
            # Access Denied - this is EXPECTED with TrustedInstaller keys!
            # Caller (e.g. Core module) has fallback (Set-RegistryValueWithOwnership)
            # IMPORTANT: Remove error from $Error array (will be handled by caller!)
            $Error.RemoveAt(0)
            Write-Verbose "Access Denied at $Path\$Name (expected, caller has fallback)"
            return $false
        }
        else {
            # Other error - only Verbose, no Error (caller decides if Warning)
            Write-Verbose "Error setting $Path\$Name : $errorMsg"
            return $false
        }
    }
}

# Export Functions (for dot-sourcing)
# Functions are automatically available in calling scope
