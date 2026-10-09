<#
.SYNOPSIS
    Shared runtime contract for the shell, menu and standalone verifier.
.NOTES
    Version: 2.2.6
#>

function Test-NoIDPowerShellRuntime {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [System.Collections.IDictionary]$VersionTable = $PSVersionTable,
        [bool]$Is64BitProcess = [Environment]::Is64BitProcess
    )

    $version = $VersionTable['PSVersion']
    return $Is64BitProcess -and $version -is [version] -and
        $version.Major -eq 5 -and $version.Minor -eq 1 -and
        [string]$VersionTable['PSEdition'] -ceq 'Desktop'
}

function Assert-NoIDPowerShellRuntime {
    [CmdletBinding()]
    param()

    if (-not (Test-NoIDPowerShellRuntime)) {
        throw '64-bit Windows PowerShell 5.1 is required. Start Windows PowerShell from the Windows Start menu.'
    }
}

function ConvertTo-NoIDRegistryLocation {
    <#
    .SYNOPSIS
        Splits a PowerShell registry path into a native hive and subkey path.

    .DESCRIPTION
        Accepts the path forms the framework uses (HKLM:\, HKCU:\, HKU:\,
        HKCR:\, HKCC:\ and Registry::HKEY_*\ or Registry::HKLM\ style provider
        paths). The conversion is purely textual: it never depends on a
        PowerShell drive being defined in the caller's scope.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $hives = @{
        'HKLM'                = [Microsoft.Win32.RegistryHive]::LocalMachine
        'HKEY_LOCAL_MACHINE'  = [Microsoft.Win32.RegistryHive]::LocalMachine
        'HKCU'                = [Microsoft.Win32.RegistryHive]::CurrentUser
        'HKEY_CURRENT_USER'   = [Microsoft.Win32.RegistryHive]::CurrentUser
        'HKU'                 = [Microsoft.Win32.RegistryHive]::Users
        'HKEY_USERS'          = [Microsoft.Win32.RegistryHive]::Users
        'HKCR'                = [Microsoft.Win32.RegistryHive]::ClassesRoot
        'HKEY_CLASSES_ROOT'   = [Microsoft.Win32.RegistryHive]::ClassesRoot
        'HKCC'                = [Microsoft.Win32.RegistryHive]::CurrentConfig
        'HKEY_CURRENT_CONFIG' = [Microsoft.Win32.RegistryHive]::CurrentConfig
    }
    $path = $LiteralPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', 'Registry::'
    if ($path -match '^Registry::(?<hive>[^\\:]+)(?:\\(?<sub>.*))?$' -or
        $path -match '^(?<hive>HKLM|HKCU|HKU|HKCR|HKCC):(?:\\(?<sub>.*))?$') {
        $hiveName = $Matches['hive'].ToUpperInvariant()
        if ($hives.ContainsKey($hiveName)) {
            $subKey = ([string]$Matches['sub'] -replace '\\{2,}', '\').Trim('\')
            return [pscustomobject]@{ Hive = $hives[$hiveName]; SubKey = $subKey }
        }
    }
    throw "Not a supported registry path: $LiteralPath"
}

function Test-NoIDRegistryKey {
    <#
    .SYNOPSIS
        Tests whether a registry key exists with one native lookup.

    .DESCRIPTION
        For a missing key, the PowerShell registry provider behind
        Test-Path -PathType Container and New-Item -Force enumerates the
        deepest existing parent key. When Windows adds or removes sibling keys
        at the same moment, that enumeration fails with "No more data is
        available" (ERROR_NO_MORE_ITEMS), so a plain existence check could
        abort a backup, Apply, Restore or verification. RegOpenKeyEx performs
        one atomic lookup instead. A key that exists but denies read access
        is reported as existing.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $location = ConvertTo-NoIDRegistryLocation -LiteralPath $LiteralPath
    if ($location.SubKey.Length -eq 0) { return $true }
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($location.Hive, [Microsoft.Win32.RegistryView]::Default)
    try {
        try {
            $key = $baseKey.OpenSubKey($location.SubKey, $false)
        }
        catch [System.Security.SecurityException], [System.UnauthorizedAccessException] {
            return $true
        }
        if ($null -eq $key) { return $false }
        $key.Dispose()
        return $true
    }
    finally {
        $baseKey.Dispose()
    }
}

function New-NoIDRegistryKey {
    <#
    .SYNOPSIS
        Creates a registry key and any missing parent keys with one native call.

    .DESCRIPTION
        Replaces New-Item -Path <registry key> -Force, whose provider
        implementation enumerates existing parents and can fail with
        "No more data is available" while Windows changes sibling keys
        (see Test-NoIDRegistryKey). RegCreateKeyEx creates the complete path
        atomically and opens an existing key unchanged.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $location = ConvertTo-NoIDRegistryLocation -LiteralPath $LiteralPath
    if ($location.SubKey.Length -eq 0) { return }
    if (-not $PSCmdlet.ShouldProcess($LiteralPath, 'Create registry key')) { return }
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($location.Hive, [Microsoft.Win32.RegistryView]::Default)
    try {
        $key = $baseKey.CreateSubKey($location.SubKey, $true)
        if ($null -eq $key) { throw "Registry key could not be created: $LiteralPath" }
        $key.Dispose()
    }
    finally {
        $baseKey.Dispose()
    }
}

function Test-NoIDProtectedPolicyRegistryKey {
    <#
    .SYNOPSIS
        Tells whether a key is a Windows-protected policy key.

    .DESCRIPTION
        Windows creates HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking
        with a protected DACL: SYSTEM has full control, Administrators may only
        read. Group Policy writes the policy value as SYSTEM, so an ordinary
        write from the elevated shell fails with "Requested registry access is
        not allowed". The list is closed; every other key keeps the ordinary
        DACL-checked write path.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $location = ConvertTo-NoIDRegistryLocation -LiteralPath $LiteralPath
    $protectedKeys = @('SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking')
    return ($location.Hive -eq [Microsoft.Win32.RegistryHive]::LocalMachine -and
        @($protectedKeys | Where-Object {
                $_.Equals($location.SubKey, [StringComparison]::OrdinalIgnoreCase)
            }).Count -eq 1)
}

function Initialize-NoIDProtectedPolicyRegistry {
    <#
    .SYNOPSIS
        Loads the native opener used for protected policy keys.

    .DESCRIPTION
        RegCreateKeyEx with REG_OPTION_BACKUP_RESTORE opens a key with KEY_WRITE
        and DELETE access when the caller's SeRestorePrivilege is enabled;
        elevated Administrators hold that privilege. It is enabled for the open
        call only and then returned to its previous state. The opener accepts
        existing keys only and never changes a key's security descriptor.
        https://learn.microsoft.com/windows/win32/api/winreg/nf-winreg-regcreatekeyexw
    #>
    [CmdletBinding()]
    param()

    if (-not ('NoIDPrivacy.ProtectedPolicyRegistry' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace NoIDPrivacy
{
    public static class ProtectedPolicyRegistry
    {
        private const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const UInt32 TOKEN_QUERY = 0x0008;
        private const UInt32 SE_PRIVILEGE_ENABLED = 0x0002;
        private const Int32 ERROR_NOT_ALL_ASSIGNED = 1300;
        private const Int32 REG_OPTION_BACKUP_RESTORE = 0x0004;
        private const Int32 REG_OPENED_EXISTING_KEY = 2;
        private static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((Int32)0x80000002));

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public LUID Luid;
            public UInt32 Attributes;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, UInt32 desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupPrivilegeValue(string systemName, string name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
            ref TOKEN_PRIVILEGES newState, Int32 bufferLength, out TOKEN_PRIVILEGES previousState, out Int32 returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern Int32 RegCreateKeyEx(IntPtr key, string subKey, Int32 reserved, string className,
            Int32 options, Int32 desired, IntPtr securityAttributes, out IntPtr result, out Int32 disposition);

        [DllImport("advapi32.dll")]
        private static extern Int32 RegCloseKey(IntPtr key);

        public static RegistryKey OpenExistingLocalMachineKey(string subKey)
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try
            {
                LUID luid;
                if (!LookupPrivilegeValue(null, "SeRestorePrivilege", out luid))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                TOKEN_PRIVILEGES enable = new TOKEN_PRIVILEGES();
                enable.PrivilegeCount = 1;
                enable.Luid = luid;
                enable.Attributes = SE_PRIVILEGE_ENABLED;
                TOKEN_PRIVILEGES previous;
                Int32 returnLength;
                Int32 size = Marshal.SizeOf(typeof(TOKEN_PRIVILEGES));
                if (!AdjustTokenPrivileges(token, false, ref enable, size, out previous, out returnLength))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                // Success with ERROR_NOT_ALL_ASSIGNED means the token lacks the privilege.
                if (Marshal.GetLastWin32Error() == ERROR_NOT_ALL_ASSIGNED)
                {
                    throw new Win32Exception(ERROR_NOT_ALL_ASSIGNED, "SeRestorePrivilege is not held by this process");
                }
                try
                {
                    IntPtr handle;
                    Int32 disposition;
                    Int32 status = RegCreateKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, null, REG_OPTION_BACKUP_RESTORE,
                        0, IntPtr.Zero, out handle, out disposition);
                    if (status != 0)
                    {
                        throw new Win32Exception(status);
                    }
                    if (disposition != REG_OPENED_EXISTING_KEY)
                    {
                        RegCloseKey(handle);
                        throw new InvalidOperationException("Protected policy registry key did not exist: " + subKey);
                    }
                    return RegistryKey.FromHandle(new SafeRegistryHandle(handle, true));
                }
                finally
                {
                    // PrivilegeCount is 0 when the privilege was already enabled.
                    if (previous.PrivilegeCount == 1)
                    {
                        TOKEN_PRIVILEGES ignored;
                        Int32 ignoredLength;
                        AdjustTokenPrivileges(token, false, ref previous, size, out ignored, out ignoredLength);
                    }
                }
            }
            finally
            {
                CloseHandle(token);
            }
        }
    }
}
'@
    }
}

function Open-NoIDProtectedPolicyRegistryKey {
    <#
    .SYNOPSIS
        Opens an existing protected policy key for writing without changing its DACL.
    #>
    [CmdletBinding()]
    [OutputType([Microsoft.Win32.RegistryKey])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    if (-not (Test-NoIDProtectedPolicyRegistryKey -LiteralPath $LiteralPath)) {
        throw "Not a protected policy registry key: $LiteralPath"
    }
    if (-not (Test-NoIDRegistryKey -LiteralPath $LiteralPath)) {
        throw "Protected policy registry key does not exist: $LiteralPath"
    }
    Initialize-NoIDProtectedPolicyRegistry
    $location = ConvertTo-NoIDRegistryLocation -LiteralPath $LiteralPath
    return [NoIDPrivacy.ProtectedPolicyRegistry]::OpenExistingLocalMachineKey($location.SubKey)
}

function Set-NoIDProtectedPolicyRegistryValue {
    <#
    .SYNOPSIS
        Writes one value under a protected policy key (see Open-NoIDProtectedPolicyRegistryKey).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        $Value,

        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.RegistryValueKind]$Kind
    )

    if (-not $PSCmdlet.ShouldProcess("$LiteralPath\$Name", 'Set protected policy registry value')) { return }
    $nativeValue = switch ($Kind.ToString()) {
        'DWord' {
            # REG_DWORD data covers the signed and unsigned 32-bit ranges.
            $number = [int64]$Value
            if ($number -lt [int32]::MinValue -or $number -gt [uint32]::MaxValue) {
                throw "REG_DWORD value is out of range: $LiteralPath\$Name"
            }
            [BitConverter]::ToInt32([BitConverter]::GetBytes($number), 0)
        }
        'QWord' { [int64]$Value }
        'Binary' { , ([byte[]]@($Value | ForEach-Object { [byte]$_ })) }
        'MultiString' { , ([string[]]@($Value)) }
        'String' { [string]$Value }
        'ExpandString' { [string]$Value }
        default { throw "Unsupported protected policy registry type: $Kind" }
    }
    $key = Open-NoIDProtectedPolicyRegistryKey -LiteralPath $LiteralPath
    try {
        $key.SetValue($Name, $nativeValue, $Kind)
    }
    finally {
        $key.Dispose()
    }
}

function Remove-NoIDProtectedPolicyRegistryValue {
    <#
    .SYNOPSIS
        Deletes one existing value under a protected policy key (see Open-NoIDProtectedPolicyRegistryKey).
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not $PSCmdlet.ShouldProcess("$LiteralPath\$Name", 'Remove protected policy registry value')) { return }
    $key = Open-NoIDProtectedPolicyRegistryKey -LiteralPath $LiteralPath
    try {
        $key.DeleteValue($Name, $true)
    }
    finally {
        $key.Dispose()
    }
}

function Test-NoIDInteractiveConsoleSession {
    <#
    .SYNOPSIS
        Tells whether Windows PowerShell was started as an interactive console.

    .DESCRIPTION
        PSHost.SetShouldExit ends an interactive console session as soon as the
        current command completes, which would close the window of a user who
        typed .\NoIDPrivacy.ps1 at the prompt. A host started with -File,
        -Command, -EncodedCommand, a positional command or '-' (standard input)
        and without -NoExit ends with the script anyway and needs the explicit
        exit code. Parameter prefixes follow powershell.exe's own matching.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowEmptyCollection()]
        [string[]]$CommandLineArguments = @([Environment]::GetCommandLineArgs() | Select-Object -Skip 1)
    )

    $valueSwitches = @('executionpolicy', 'ep', 'windowstyle', 'outputformat', 'inputformat',
        'version', 'psconsolefile', 'configurationname')
    $noExit = $false
    $scripted = $false
    for ($index = 0; $index -lt $CommandLineArguments.Count; $index++) {
        $argument = [string]$CommandLineArguments[$index]
        if ($argument -notmatch '^[-/]') { $scripted = $true; break }
        $name = $argument.Substring(1).ToLowerInvariant()
        if ($name.Length -eq 0) { $scripted = $true; break }
        if ($name.Length -ge 3 -and 'noexit'.StartsWith($name, [StringComparison]::Ordinal)) {
            $noExit = $true
            continue
        }
        if ('file'.StartsWith($name, [StringComparison]::Ordinal) -or
            'command'.StartsWith($name, [StringComparison]::Ordinal) -or
            'encodedcommand'.StartsWith($name, [StringComparison]::Ordinal) -or $name -ceq 'ec') {
            # Everything after these switches belongs to the script or command.
            $scripted = $true
            break
        }
        $takesValue = @($valueSwitches | Where-Object {
                ($name.Length -ge 2 -and $_.StartsWith($name, [StringComparison]::Ordinal)) -or $_ -ceq $name
            }).Count -gt 0
        if ($takesValue) { $index++ }
    }
    return ($noExit -or -not $scripted)
}

function Test-NoIDNetworkConnection {
    <#
    .SYNOPSIS
        Tells whether this PC has any network connection that can carry traffic.

    .DESCRIPTION
        True when at least one connected IP interface has a default route
        (IPv4 0.0.0.0/0 or IPv6 ::/0); a VPN counts. Without one no remote
        endpoint is reachable, so a network-dependent check (for example a
        resolver reachability test) cannot run and is reported as information
        instead of a failure. The probe reads the local routing table and sends
        no traffic. If the table cannot be read, the PC is treated as online so
        that every existing network validation still runs.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $defaultRoutes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { [string]$_.DestinationPrefix -in @('0.0.0.0/0', '::/0') })
        foreach ($route in $defaultRoutes) {
            $interface = @(Get-NetIPInterface -InterfaceIndex ([int]$route.InterfaceIndex) `
                -AddressFamily $route.AddressFamily -ErrorAction SilentlyContinue)
            if (@($interface | Where-Object { [string]$_.ConnectionState -eq 'Connected' }).Count -gt 0) {
                return $true
            }
        }
        return $false
    }
    catch {
        return $true
    }
}

function Test-NoIDPlainConsole {
    <#
    .SYNOPSIS
        True when a person reads this console (plain sentences, no log records).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return ($global:LoggerConfig -is [hashtable] -and $global:LoggerConfig.ContainsKey('ConsoleStyle') -and
        [string]$global:LoggerConfig.ConsoleStyle -eq 'Plain')
}

function Write-NoIDDetail {
    <#
    .SYNOPSIS
        Writes a detail line for the GUI log and automation.

    .DESCRIPTION
        A person at the plain console gets each module's one-line results
        instead of per-feature banners; everything stays in the log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [AllowEmptyString()]
        [string]$Object = '',

        [Parameter()]
        [ConsoleColor]$ForegroundColor,

        [Parameter()]
        [switch]$NoNewline
    )

    if (Test-NoIDPlainConsole) {
        return
    }
    $hostParameters = @{ Object = $Object; NoNewline = $NoNewline }
    if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
        $hostParameters.ForegroundColor = $ForegroundColor
    }
    Write-Host @hostParameters
}

function Test-NoIDFileNotFoundError {
    <#
    .SYNOPSIS
        True when an error carries HRESULT 0x80070002 (file not found).

    .DESCRIPTION
        The Task Scheduler COM interface reports a missing task as
        System.IO.FileNotFoundException; the ScheduledTasks cmdlets report the
        same HRESULT as a CimException with the error ID
        "HRESULT 0x80070002,<cmdlet>".
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    if ([string]$ErrorRecord.FullyQualifiedErrorId -like 'HRESULT 0x80070002,*') { return $true }
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception.HResult -eq -2147024894) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}

function Get-NoIDScheduledTask {
    <#
    .SYNOPSIS
        Get-ScheduledTask with a bounded retry for concurrent task deletion.

    .DESCRIPTION
        Get-ScheduledTask enumerates every registered task, also when -TaskPath
        and -TaskName name a single task. If another program deletes any task
        during that enumeration, the query fails with "The system cannot find
        the file specified" (HRESULT 0x80070002). A new enumeration sees a
        consistent task list. Any other error, or the same error five times in
        a row, is thrown unchanged; a task that does not exist still fails
        with the cmdlet's own not-found error.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TaskPath,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName
    )

    $query = @{ ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('TaskPath')) { $query.TaskPath = $TaskPath }
    if ($PSBoundParameters.ContainsKey('TaskName')) { $query.TaskName = $TaskName }
    for ($attempt = 1; ; $attempt++) {
        try {
            # Collect first: a failed enumeration may already have emitted
            # some tasks, and a retry must not return them twice.
            $tasks = @(Get-ScheduledTask @query)
            return $tasks
        }
        catch {
            if ($attempt -ge 5 -or -not (Test-NoIDFileNotFoundError -ErrorRecord $_)) { throw }
            Start-Sleep -Milliseconds 200
        }
    }
}

function Get-NoIDScheduledTaskState {
    <#
    .SYNOPSIS
        Reads the state of one task in the root task folder.

    .DESCRIPTION
        Unlike Get-ScheduledTask, ITaskFolder.GetTask opens only the named task,
        so another program deleting a task meanwhile cannot fail the lookup.
        This matters while NoID Privacy polls its own transient worker task.
        Returns the cmdlet's State name (Unknown, Disabled, Queued, Ready,
        Running), or $null when the task is not registered.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName
    )

    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    try {
        $task = $service.GetFolder('\').GetTask($TaskName)
    }
    catch {
        if (Test-NoIDFileNotFoundError -ErrorRecord $_) { return $null }
        throw
    }
    $stateNames = @('Unknown', 'Disabled', 'Queued', 'Ready', 'Running')
    $state = [int]$task.State
    if ($state -lt 0 -or $state -ge $stateNames.Count) { return 'Unknown' }
    return $stateNames[$state]
}

function Unregister-NoIDScheduledTask {
    <#
    .SYNOPSIS
        Deletes one task in the root task folder.

    .DESCRIPTION
        Unregister-ScheduledTask -TaskName enumerates every registered task
        first and fails when another program deletes a task meanwhile.
        ITaskFolder.DeleteTask deletes only the named task. Returns $true when
        the task was deleted and $false when it was not registered.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName
    )

    if (-not $PSCmdlet.ShouldProcess("\$TaskName", 'Delete scheduled task')) { return $false }
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    try {
        $service.GetFolder('\').DeleteTask($TaskName, 0)
        return $true
    }
    catch {
        if (Test-NoIDFileNotFoundError -ErrorRecord $_) { return $false }
        throw
    }
}
