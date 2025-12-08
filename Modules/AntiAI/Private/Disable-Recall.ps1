#Requires -Version 5.1

<#
.SYNOPSIS
    Disables Windows Recall completely (component removal + snapshots + data providers).

.DESCRIPTION
    Applies 3 core Recall policies:
    1. AllowRecallEnablement = 0 (Removes Recall component, deletes existing snapshots, requires reboot)
    2. DisableAIDataAnalysis = 1 (Prevents new snapshots - Device and User scope)
    3. DisableRecallDataProviders = 1 (Disables background data providers - Enterprise/Education)
    
    WARNING: Requires system reboot for Recall component removal to take effect!

.EXAMPLE
    Disable-Recall
#>
function Disable-Recall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-Log -Level DEBUG -Message "Disabling Windows Recall (component + snapshots + providers)" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
        RequiresReboot = $true
    }
    
    try {
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would disable Recall (AllowRecallEnablement=0, DisableAIDataAnalysis=1)" -Module "AntiAI"
            $result.Success = $true
            return $result
        }
        
        # Device-scope policies (HKLM)
        $devicePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        if (-not (Test-Path $devicePath)) {
            New-Item -Path $devicePath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $devicePath" -Module "AntiAI"
        }
        
        # 1. Remove Recall component (deletes bits + existing snapshots)
        $existing = Get-ItemProperty -Path $devicePath -Name "AllowRecallEnablement" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $devicePath -Name "AllowRecallEnablement" -Value 0 -Force | Out-Null
        } else {
            New-ItemProperty -Path $devicePath -Name "AllowRecallEnablement" -Value 0 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set AllowRecallEnablement = 0 (Recall component will be removed on reboot)" -Module "AntiAI"
        $result.Applied++
        
        # 2. Disable AI data analysis (Device-scope)
        $existing = Get-ItemProperty -Path $devicePath -Name "DisableAIDataAnalysis" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $devicePath -Name "DisableAIDataAnalysis" -Value 1 -Force | Out-Null
        } else {
            New-ItemProperty -Path $devicePath -Name "DisableAIDataAnalysis" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set DisableAIDataAnalysis = 1 (Device-scope - no new snapshots)" -Module "AntiAI"
        $result.Applied++
        
        # User-scope policies (HKCU)
        $userPath = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        if (-not (Test-Path $userPath)) {
            New-Item -Path $userPath -Force | Out-Null
            Write-Log -Level DEBUG -Message "Created registry path: $userPath" -Module "AntiAI"
        }
        
        # 3. Disable AI data analysis (User-scope)
        $existing = Get-ItemProperty -Path $userPath -Name "DisableAIDataAnalysis" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $userPath -Name "DisableAIDataAnalysis" -Value 1 -Force | Out-Null
        } else {
            New-ItemProperty -Path $userPath -Name "DisableAIDataAnalysis" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set DisableAIDataAnalysis = 1 (User-scope - no new snapshots)" -Module "AntiAI"
        $result.Applied++
        
        # 4. Disable Recall data providers (Enterprise/Education only, User-scope)
        $existing = Get-ItemProperty -Path $userPath -Name "DisableRecallDataProviders" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $userPath -Name "DisableRecallDataProviders" -Value 1 -Force | Out-Null
        } else {
            New-ItemProperty -Path $userPath -Name "DisableRecallDataProviders" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level DEBUG -Message "Set DisableRecallDataProviders = 1 (Background data providers disabled)" -Module "AntiAI"
        $result.Applied++
        
        # Verify
        $deviceValues = Get-ItemProperty -Path $devicePath -ErrorAction SilentlyContinue
        $userValues = Get-ItemProperty -Path $userPath -ErrorAction SilentlyContinue
        
        $verified = ($deviceValues.AllowRecallEnablement -eq 0) -and 
                   ($deviceValues.DisableAIDataAnalysis -eq 1) -and
                   ($userValues.DisableAIDataAnalysis -eq 1) -and
                   ($userValues.DisableRecallDataProviders -eq 1)
        
        if ($verified) {
            Write-Log -Level DEBUG -Message "Verification SUCCESS: All Recall policies applied" -Module "AntiAI"
            Write-Host ""  # Ensure warning appears on new line
            Write-Warning "REBOOT REQUIRED to remove Recall component and delete existing snapshots!"
            $result.Success = $true
        }
        else {
            $result.Errors += "Verification FAILED: Not all Recall policies were applied correctly"
        }
    }
    catch {
        $result.Errors += "Failed to disable Recall: $($_.Exception.Message)"
        Write-Error $result.Errors[-1]
    }
    
    return $result
}
