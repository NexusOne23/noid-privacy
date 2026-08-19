#Requires -Version 5.1

function Get-SecurityBaselineUserContext {
    <#
    .SYNOPSIS
        Resolve the interactive desktop user's loaded registry hive.

    .DESCRIPTION
        Credential-based UAC elevation can run this module under a different
        administrator identity. User-scope baseline policies must target the
        account owning Explorer in the current Windows session, not the
        elevated process account's HKCU hive.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    if (-not ('NoIDInteractiveTokenInspector' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NoIDInteractiveTokenInspector
{
    private const UInt32 PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const UInt32 TOKEN_QUERY = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_GROUPS
    {
        public UInt32 GroupCount;
        public SID_AND_ATTRIBUTES Groups;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(UInt32 access, bool inheritHandle, UInt32 processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, UInt32 desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle, Int32 tokenInformationClass, IntPtr tokenInformation, Int32 tokenInformationLength, out Int32 returnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSidToSid(string stringSid, out IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool EqualSid(IntPtr sid1, IntPtr sid2);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr handle);

    public static bool TokenContainsGroupSid(int processId, string groupSid)
    {
        IntPtr processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (UInt32)processId);
        if (processHandle == IntPtr.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed");

        IntPtr tokenHandle = IntPtr.Zero;
        IntPtr tokenGroups = IntPtr.Zero;
        IntPtr targetSid = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(processHandle, TOKEN_QUERY, out tokenHandle))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");

            Int32 requiredLength;
            GetTokenInformation(tokenHandle, 2, IntPtr.Zero, 0, out requiredLength); // TokenGroups
            if (requiredLength <= 0)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation size query failed");
            tokenGroups = Marshal.AllocHGlobal(requiredLength);
            if (!GetTokenInformation(tokenHandle, 2, tokenGroups, requiredLength, out requiredLength))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "GetTokenInformation(TokenGroups) failed");
            if (!ConvertStringSidToSid(groupSid, out targetSid))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "ConvertStringSidToSid failed");

            Int32 groupCount = Marshal.ReadInt32(tokenGroups);
            Int32 entryOffset = Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups").ToInt32();
            Int32 entrySize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            for (Int32 index = 0; index < groupCount; index++)
            {
                IntPtr entryPointer = IntPtr.Add(tokenGroups, entryOffset + (index * entrySize));
                SID_AND_ATTRIBUTES entry = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(entryPointer, typeof(SID_AND_ATTRIBUTES));
                if (EqualSid(entry.Sid, targetSid)) return true;
            }
            return false;
        }
        finally
        {
            if (targetSid != IntPtr.Zero) LocalFree(targetSid);
            if (tokenGroups != IntPtr.Zero) Marshal.FreeHGlobal(tokenGroups);
            if (tokenHandle != IntPtr.Zero) CloseHandle(tokenHandle);
            CloseHandle(processHandle);
        }
    }
}
'@ -ErrorAction Stop
    }

    if ($script:SecurityBaselineUserContext) {
        return $script:SecurityBaselineUserContext
    }

    $sessionId = (Get-Process -Id $PID -ErrorAction Stop).SessionId
    $interactiveProcesses = @(Get-Process -Name explorer -IncludeUserName -ErrorAction Stop |
        Where-Object {
            $_.SessionId -eq $sessionId -and
            -not [string]::IsNullOrWhiteSpace([string]$_.UserName)
        })
    $interactiveNames = @($interactiveProcesses |
        ForEach-Object { [string]$_.UserName } |
        Sort-Object -Unique)
    if ($interactiveNames.Count -ne 1) {
        throw "Interactive user identity is unavailable or ambiguous in Windows session $sessionId"
    }

    $account = [System.Security.Principal.NTAccount]::new($interactiveNames[0])
    $sid = [string]$account.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($sid -notmatch '^S-1-(5-21|12-1)-[0-9-]+$') {
        throw 'Interactive account SID is not a supported local/domain/Microsoft/Entra user SID'
    }
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        # The returned Root is consumed after this function exits, so HKU must
        # live for the process rather than only for this function scope.
        $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Global -ErrorAction Stop
    }
    $root = "HKU:\$sid"
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'The interactive user registry hive is not loaded'
    }

    # Read the Explorer token rather than the elevated PowerShell token. This
    # remains correct for over-the-shoulder elevation with separate admin
    # credentials. UAC-filtered administrator tokens retain the built-in
    # Administrators SID as a group SID, so this tests membership rather than
    # whether that SID is currently enabled for authorization.
    $explorerProcessIds = @($interactiveProcesses | Select-Object -ExpandProperty Id -Unique)
    if ($explorerProcessIds.Count -lt 1) {
        throw 'The interactive Explorer token is unavailable'
    }
    $administratorMembership = @($explorerProcessIds | ForEach-Object {
        [NoIDInteractiveTokenInspector]::TokenContainsGroupSid([int]$_, 'S-1-5-32-544')
    } | Sort-Object -Unique)
    if ($administratorMembership.Count -ne 1) {
        throw 'Interactive account administrator membership is ambiguous across Explorer processes'
    }

    $script:SecurityBaselineUserContext = [PSCustomObject]@{
        Sid             = $sid
        Root            = $root
        IsAdministrator = [bool]$administratorMembership[0]
    }
    return $script:SecurityBaselineUserContext
}
