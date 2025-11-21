#Requires -Version 5.1

<#
.SYNOPSIS
    Applies enterprise-grade Recall protection (app/URI deny lists, storage limits).

.DESCRIPTION
    Configures 4 additional Recall policies for maximum data protection:
    1. SetDenyAppListForRecall - Apps never captured in snapshots (Browser, Terminal, Password managers, RDP)
    2. SetDenyUriListForRecall - Websites/URLs never captured (Banking, Email, Login pages)
    3. SetMaximumStorageDurationForRecallSnapshots - Max retention: 30 days
    4. SetMaximumStorageSpaceForRecallSnapshots - Max storage: 10 GB
    
    Note: These are additional protection layers BEYOND core Recall disable policies.
          Even though Recall is disabled, these provide defense-in-depth.

.EXAMPLE
    Set-RecallProtection
#>
function Set-RecallProtection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-Log -Level DEBUG -Message "Applying Recall enterprise protection (deny lists + storage limits)" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
    }
    
    try {
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would set Recall protection (Deny lists + Storage limits)" -Module "AntiAI"
            $result.Success = $true
            return $result
        }
        
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $regPath" -Module "AntiAI"
        }
        
        # 1. App Deny List - Critical apps never captured in snapshots
        $denyApps = @(
            "Microsoft.MicrosoftEdge_8wekyb3d8bbwe!App",           # Edge Browser (Banking, passwords)
            "Microsoft.WindowsTerminal_8wekyb3d8bbwe!App",        # Terminal (CLI passwords, keys)
            "KeePassXC_8wekyb3d8bbwe!KeePassXC",                  # Password Manager
            "Microsoft.RemoteDesktop_8wekyb3d8bbwe!App"           # RDP (remote system access)
        )
        
        # Store as proper MultiString (string array) so policies are visible to compliance checks
        $existing = Get-ItemProperty -Path $regPath -Name "SetDenyAppListForRecall" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "SetDenyAppListForRecall" -Value $denyApps -Force
        } else {
            New-ItemProperty -Path $regPath -Name "SetDenyAppListForRecall" -Value $denyApps -PropertyType MultiString -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set App Deny List: $($denyApps.Count) critical apps protected" -Module "AntiAI"
        $result.Applied++
        
        # 2. URI Deny List - Critical websites never captured in snapshots
        $denyUris = @(
            "*.bank.*",              # All banking sites
            "*.paypal.*",            # Payment processor
            "*.bankofamerica.*",     # Major bank
            "mail.*",                # Email sites
            "webmail.*",             # Webmail sites
            "*password*",            # Any password-related pages
            "*login*"                # Any login pages
        )
        
        # Store as MultiString using string array
        $existing = Get-ItemProperty -Path $regPath -Name "SetDenyUriListForRecall" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "SetDenyUriListForRecall" -Value $denyUris -Force
        } else {
            New-ItemProperty -Path $regPath -Name "SetDenyUriListForRecall" -Value $denyUris -PropertyType MultiString -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set URI Deny List: $($denyUris.Count) URL patterns protected" -Module "AntiAI"
        $result.Applied++
        
        # 3. Storage Duration Limit - Max 30 days retention
        $existing = Get-ItemProperty -Path $regPath -Name "SetMaximumStorageDurationForRecallSnapshots" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "SetMaximumStorageDurationForRecallSnapshots" -Value 30 -Force
        } else {
            New-ItemProperty -Path $regPath -Name "SetMaximumStorageDurationForRecallSnapshots" -Value 30 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set max snapshot retention: 30 days" -Module "AntiAI"
        $result.Applied++
        
        # 4. Storage Space Limit - Max 10 GB
        $existing = Get-ItemProperty -Path $regPath -Name "SetMaximumStorageSpaceForRecallSnapshots" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $regPath -Name "SetMaximumStorageSpaceForRecallSnapshots" -Value 10 -Force
        } else {
            New-ItemProperty -Path $regPath -Name "SetMaximumStorageSpaceForRecallSnapshots" -Value 10 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set max snapshot storage: 10 GB" -Module "AntiAI"
        $result.Applied++
        
        # Verify
        $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        
        $verified = ($null -ne $values.SetDenyAppListForRecall) -and
                   ($null -ne $values.SetDenyUriListForRecall) -and
                   ($values.SetMaximumStorageDurationForRecallSnapshots -eq 30) -and
                   ($values.SetMaximumStorageSpaceForRecallSnapshots -eq 10)
        
        if ($verified) {
            Write-Log -Level DEBUG -Message "Verification SUCCESS: All Recall protection policies applied" -Module "AntiAI"
            $result.Success = $true
        }
        else {
            $result.Errors += "Verification FAILED: Not all Recall protection policies were applied"
        }
    }
    catch {
        $result.Errors += "Failed to apply Recall protection: $($_.Exception.Message)"
        Write-Error $result.Errors[-1]
    }
    
    return $result
}
