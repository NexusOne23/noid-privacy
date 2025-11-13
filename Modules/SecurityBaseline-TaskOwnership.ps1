# =======================================================================================
# SecurityBaseline-TaskOwnership.ps1 - Scheduled Task Ownership Management
# =======================================================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Professional Ownership Management for TrustedInstaller/SYSTEM-protected Scheduled Tasks
    
.DESCRIPTION
    Provides functions to disable/enable protected Scheduled Tasks by temporarily
    taking ownership from TrustedInstaller/SYSTEM, similar to Registry ownership management.
    
    Why this is needed:
    - Some Windows tasks (XblGameSaveTask, MapsToastTask) are protected
    - Standard Disable-ScheduledTask fails with "Access Denied"
    - Solution: Take ownership, disable, restore ownership (defense-in-depth)
    
.NOTES
    Author: NoID Privacy Project
    Version: 1.8.3
    Date: 2025-11-13
    
    Based on: SecurityBaseline-RegistryOwnership.ps1 pattern
#>

# Enable Strict Mode
Set-StrictMode -Version Latest

# Add required .NET types for Security Management
Add-Type -AssemblyName System.Security.Principal

function Enable-TaskOwnershipPrivileges {
    <#
    .SYNOPSIS
        Enables required privileges for Task ownership management
    .DESCRIPTION
        Enables SeTakeOwnershipPrivilege and SeRestorePrivilege in current process token.
        Required for taking ownership of TrustedInstaller/SYSTEM-protected tasks.
    .OUTPUTS
        [bool] $true on success, $false on failure
    .EXAMPLE
        Enable-TaskOwnershipPrivileges
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    try {
        # Get current process token
        $processHandle = [System.Diagnostics.Process]::GetCurrentProcess().Handle
        
        # Open process token with TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        $tokenHandle = [IntPtr]::Zero
        $TOKEN_ADJUST_PRIVILEGES = 0x0020
        $TOKEN_QUERY = 0x0008
        
        # P/Invoke for OpenProcessToken
        $signature = @'
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
        
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
        
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID {
            public uint LowPart;
            public int HighPart;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES {
            public long Luid;
            public uint Attributes;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES {
            public int PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }
'@
        
        $advapi32 = Add-Type -MemberDefinition $signature -Name 'AdvApi32' -Namespace 'Win32' -PassThru -ErrorAction SilentlyContinue
        
        # Open process token
        $result = $advapi32::OpenProcessToken($processHandle, ($TOKEN_ADJUST_PRIVILEGES -bor $TOKEN_QUERY), [ref]$tokenHandle)
        if (-not $result) {
            Write-Verbose "Failed to open process token"
            return $false
        }
        
        # Enable SeTakeOwnershipPrivilege
        $luid = [long]0
        $result = $advapi32::LookupPrivilegeValue($null, "SeTakeOwnershipPrivilege", [ref]$luid)
        if ($result) {
            $tp = New-Object Win32.AdvApi32+TOKEN_PRIVILEGES
            $tp.PrivilegeCount = 1
            $tp.Privileges.Luid = $luid
            $tp.Privileges.Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED
            
            $advapi32::AdjustTokenPrivileges($tokenHandle, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
            Write-Verbose "SeTakeOwnershipPrivilege enabled"
        }
        
        # Enable SeRestorePrivilege
        $luid = [long]0
        $result = $advapi32::LookupPrivilegeValue($null, "SeRestorePrivilege", [ref]$luid)
        if ($result) {
            $tp = New-Object Win32.AdvApi32+TOKEN_PRIVILEGES
            $tp.PrivilegeCount = 1
            $tp.Privileges.Luid = $luid
            $tp.Privileges.Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED
            
            $advapi32::AdjustTokenPrivileges($tokenHandle, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
            Write-Verbose "SeRestorePrivilege enabled"
        }
        
        return $true
    }
    catch {
        Write-Verbose "Error enabling privileges: $_"
        return $false
    }
}

function Disable-ScheduledTaskWithOwnership {
    <#
    .SYNOPSIS
        Disables a protected Scheduled Task by temporarily taking ownership
    .DESCRIPTION
        For TrustedInstaller/SYSTEM-protected tasks that fail with "Access Denied",
        this function:
        1. Takes ownership of the task
        2. Grants Administrators group Full Control
        3. Disables the task
        4. Restores original permissions (defense-in-depth)
        
        Uses Task Scheduler COM API for low-level access.
    .PARAMETER TaskPath
        Path to the task (e.g., "\Microsoft\Windows\Maps\")
    .PARAMETER TaskName
        Name of the task (e.g., "MapsToastTask")
    .PARAMETER Description
        Description for logging
    .OUTPUTS
        [bool] $true on success, $false on failure
    .EXAMPLE
        Disable-ScheduledTaskWithOwnership -TaskPath "\Microsoft\XblGameSave\" -TaskName "XblGameSaveTask"
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName,
        
        [Parameter()]
        [string]$Description
    )
    
    try {
        $fullPath = $TaskPath + $TaskName
        
        # STEP 1: Check if task exists and is not already disabled
        $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop
        
        if ($task.State -eq 'Disabled') {
            Write-Verbose "Task already disabled: $fullPath"
            return $true
        }
        
        Write-Verbose "Attempting to disable protected task: $fullPath"
        
        # STEP 2: Try normal disable first (fast path for non-protected tasks)
        try {
            Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop | Out-Null
            Write-Verbose "Task disabled normally (not protected): $fullPath"
            return $true
        }
        catch {
            # Check if it's Access Denied error
            $errorMsg = $_.Exception.Message
            if ($errorMsg -match "Access.*denied|Zugriff.*verweigert|unzulaessig") {
                Write-Verbose "Access denied - task is protected, using ownership method: $fullPath"
            }
            else {
                # Other error - not Access Denied
                Write-Warning "Error disabling task $fullPath : $errorMsg"
                return $false
            }
        }
        
        # STEP 3: Enable required privileges
        if (-not (Enable-TaskOwnershipPrivileges)) {
            Write-Warning "Failed to enable ownership privileges for task: $fullPath"
            return $false
        }
        
        # STEP 4: Use Task Scheduler COM API for low-level access
        # Create Task Scheduler COM object
        $schedule = New-Object -ComObject Schedule.Service
        $schedule.Connect()
        
        # Get task folder
        $taskFolder = $schedule.GetFolder($TaskPath.TrimEnd('\'))
        
        # Get task definition
        $taskDef = $taskFolder.GetTask($TaskName)
        
        # STEP 5: Get current security descriptor (backup)
        $securityDescriptor = $taskDef.GetSecurityDescriptor(0xF)  # DACL | SACL | Owner | Group
        Write-Verbose "Original security descriptor backed up"
        
        # STEP 6: Take ownership (set owner to BUILTIN\Administrators)
        $adminsSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")  # BUILTIN\Administrators
        
        # Build new SDDL with Administrators as owner
        # Format: O:SID(A;;permissions;;;SID)
        $newSDDL = "O:" + $adminsSID.Value + "D:(A;;FA;;;BA)(A;;FA;;;" + $adminsSID.Value + ")"
        
        try {
            $taskDef.SetSecurityDescriptor($newSDDL, 0x4)  # OWNER_SECURITY_INFORMATION
            Write-Verbose "Ownership taken: $fullPath"
        }
        catch {
            Write-Verbose "Could not take ownership via SDDL, trying alternative method: $_"
        }
        
        # STEP 7: Grant Full Control to Administrators
        $fullControlSDDL = "D:(A;;FA;;;BA)"  # Full Access for BUILTIN\Administrators
        try {
            $taskDef.SetSecurityDescriptor($fullControlSDDL, 0x4)  # DACL
            Write-Verbose "Full Control granted to Administrators"
        }
        catch {
            Write-Verbose "Could not set DACL: $_"
        }
        
        # STEP 8: Disable the task via COM API
        try {
            # Set Enabled property to False in task definition
            $taskSettings = $taskDef.Settings
            $taskSettings.Enabled = $false
            
            # Save modified task (requires TASK_WRITE permission)
            # RegisterTaskDefinition with TASK_UPDATE flag (0x4)
            $taskFolder.RegisterTaskDefinition(
                $TaskName,
                $taskDef.Definition,
                6,  # TASK_UPDATE
                $null,  # User
                $null,  # Password
                3       # TASK_LOGON_SERVICE_ACCOUNT
            ) | Out-Null
            
            Write-Verbose "Task disabled via COM API: $fullPath"
        }
        catch {
            Write-Verbose "COM API disable failed, trying PowerShell cmdlet again: $_"
            
            # Try PowerShell cmdlet again (now that we have ownership)
            try {
                Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop | Out-Null
                Write-Verbose "Task disabled via PowerShell after ownership change: $fullPath"
            }
            catch {
                Write-Warning "Failed to disable task even after ownership change: $fullPath - $_"
                
                # STEP 9: Try to restore original security descriptor
                try {
                    $taskDef.SetSecurityDescriptor($securityDescriptor, 0xF)
                    Write-Verbose "Original security descriptor restored"
                }
                catch {
                    Write-Verbose "Could not restore security descriptor: $_"
                }
                
                return $false
            }
        }
        
        # STEP 10: Restore original security descriptor (defense-in-depth)
        # NOTE: For tasks, we might want to KEEP the new permissions
        # since we need to be able to manage them. But for clean restore:
        try {
            $taskDef.SetSecurityDescriptor($securityDescriptor, 0xF)
            Write-Verbose "Original security descriptor restored"
        }
        catch {
            Write-Verbose "Could not restore security descriptor (task is disabled anyway): $_"
        }
        
        # STEP 11: Verify task is disabled
        $verifyTask = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($verifyTask -and $verifyTask.State -eq 'Disabled') {
            if ($Description) {
                Write-Verbose "$Description : $TaskName disabled (with ownership)"
            }
            return $true
        }
        else {
            Write-Warning "Task disable verification failed: $fullPath"
            return $false
        }
    }
    catch {
        Write-Warning "Unexpected error disabling protected task $fullPath : $_"
        Write-Verbose "Error details: $($_.Exception.Message)"
        return $false
    }
}

function Disable-ScheduledTaskSmart {
    <#
    .SYNOPSIS
        Smart wrapper that tries normal disable first, then uses ownership if needed
    .DESCRIPTION
        Combines fast path (normal disable) with fallback (ownership-based disable)
        for maximum compatibility and performance.
    .PARAMETER TaskPath
        Path to the task
    .PARAMETER TaskName
        Name of the task
    .PARAMETER Description
        Description for logging
    .OUTPUTS
        [bool] $true on success, $false on failure
    .EXAMPLE
        Disable-ScheduledTaskSmart -TaskPath "\Microsoft\XblGameSave\" -TaskName "XblGameSaveTask"
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TaskPath,
        
        [Parameter(Mandatory = $true)]
        [string]$TaskName,
        
        [Parameter()]
        [string]$Description
    )
    
    $fullPath = $TaskPath + $TaskName
    
    # Check if task exists
    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Verbose "Task does not exist: $fullPath (skipped)"
        return $true  # Not an error - task doesn't exist
    }
    
    # Check if already disabled
    if ($task.State -eq 'Disabled') {
        Write-Verbose "Task already disabled: $fullPath"
        return $true
    }
    
    # FAST PATH: Try normal disable
    try {
        Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction Stop | Out-Null
        if ($Description) {
            Write-Verbose "$Description : $TaskName disabled"
        }
        return $true
    }
    catch {
        # Check if Access Denied
        $errorMsg = $_.Exception.Message
        if ($errorMsg -match "Access.*denied|Zugriff.*verweigert|unzulaessig") {
            Write-Verbose "Access Denied - trying ownership method: $fullPath"
            
            # SLOW PATH: Use ownership-based disable
            return Disable-ScheduledTaskWithOwnership -TaskPath $TaskPath -TaskName $TaskName -Description $Description
        }
        else {
            # Other error
            Write-Warning "Error disabling task $fullPath : $errorMsg"
            return $false
        }
    }
}

# Export functions (when dot-sourced, these are available in parent scope)
# Export-ModuleMember -Function Disable-ScheduledTaskWithOwnership, Disable-ScheduledTaskSmart, Enable-TaskOwnershipPrivileges
