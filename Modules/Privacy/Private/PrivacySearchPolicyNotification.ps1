#Requires -Version 5.1

function Test-PrivacySearchPolicyNotificationRequired {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Entries
    )

    return @($Entries | Where-Object {
            $path = [string]$_.Path
            $path -ieq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -or
            $path -match '(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Search(?:Settings)?(?:\\WebSearchProviders)?$'
        }).Count -gt 0
}

function Get-PrivacySearchSettingNotificationAreas {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Entries
    )

    if (-not (Test-PrivacySearchPolicyNotificationRequired -Entries $Entries)) {
        return @()
    }

    $areas = [Collections.Generic.List[string]]::new()
    $areas.Add('Policy')
    foreach ($leaf in @('Search', 'SearchSettings', 'WebSearchProviders')) {
        if (@($Entries | Where-Object {
                    [string]$_.Path -match ("(?i)\\{0}$" -f [regex]::Escape($leaf))
                }).Count -gt 0) {
            $areas.Add($leaf)
        }
    }
    return @($areas)
}

function Send-PrivacySearchPolicyChangeNotification {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Entries
    )

    $notificationAreas = @(Get-PrivacySearchSettingNotificationAreas -Entries $Entries)
    if ($notificationAreas.Count -eq 0) {
        return $true
    }

    # Microsoft documents WM_SETTINGCHANGE with lParam "Policy" after policy
    # changes and also permits the leaf registry node as the affected area.
    # The sealed plan contains both managed Search policies and interactive-
    # user Search preferences. Broadcast the policy event plus each affected
    # user-preference leaf so the running Search surface reloads both layers
    # without terminating SearchHost or Explorer.
    if (-not ('NoIDPrivacy.NativeMethods.PrivacyPolicyNotification' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace NoIDPrivacy.NativeMethods
{
    public static class PrivacyPolicyNotification
    {
        [DllImport("kernel32.dll")]
        public static extern void SetLastError(uint errorCode);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr SendMessageTimeout(
            IntPtr windowHandle,
            uint message,
            UIntPtr wordParameter,
            string longParameter,
            uint flags,
            uint timeoutMilliseconds,
            out UIntPtr messageResult);
    }
}
'@ -ErrorAction Stop
    }

    $hwndBroadcast = [IntPtr]0xffff
    $wmSettingChange = [uint32]0x001a
    $smtoAbortIfHung = [uint32]0x0002
    foreach ($area in $notificationAreas) {
        $messageResult = [UIntPtr]::Zero
        [NoIDPrivacy.NativeMethods.PrivacyPolicyNotification]::SetLastError(0)
        $callResult = [NoIDPrivacy.NativeMethods.PrivacyPolicyNotification]::SendMessageTimeout(
            $hwndBroadcast,
            $wmSettingChange,
            [UIntPtr]::Zero,
            $area,
            $smtoAbortIfHung,
            2000,
            [ref]$messageResult
        )
        if ($callResult -eq [IntPtr]::Zero) {
            $nativeError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "Windows did not accept the Privacy Search setting-change notification for '$area' (Win32 error $nativeError)"
        }
    }
    return $true
}
