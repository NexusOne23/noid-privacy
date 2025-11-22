function Restore-AdvancedSecuritySettings {
    <#
    .SYNOPSIS
        Restore Advanced Security settings from backup
        
    .DESCRIPTION
        Restores custom Advanced Security settings that are not handled by the generic
        registry/service restore logic. This includes:
        - Firewall Rules (Risky Ports)
        - Windows Features (PowerShell v2)
        - SMB Shares (Admin Shares)
        
    .PARAMETER BackupFilePath
        Path to the JSON backup file
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFilePath
    )
    
    if (-not (Test-Path $BackupFilePath)) {
        Write-Log -Level ERROR -Message "Backup file not found: $BackupFilePath" -Module "AdvancedSecurity"
        return $false
    }
    
    try {
        $filename = Split-Path $BackupFilePath -Leaf
        Write-Log -Level INFO -Message "Processing Advanced Security backup: $filename" -Module "AdvancedSecurity"
        
        # Skip Empty Marker files - these are already processed by generic Empty Marker logic in Core/Rollback.ps1
        if ($filename -match "_EMPTY\.json$") {
            Write-Log -Level DEBUG -Message "Skipping Empty Marker file (already processed): $filename" -Module "AdvancedSecurity"
            return $true  # Success - nothing to do here
        }
        
        # Load backup data
        $backupData = Get-Content -Path $BackupFilePath -Raw | ConvertFrom-Json
        
        # Determine backup type based on filename or content
        if ($filename -match "RiskyPorts_Firewall") {
            return Restore-FirewallRules -BackupData $backupData
        }
        elseif ($filename -match "PowerShellV2") {
            return Restore-PowerShellV2 -BackupData $backupData
        }
        elseif ($filename -match "AdminShares") {
            return Restore-AdminShares -BackupData $backupData
        }
        elseif ($filename -match "RDP_Hardening") {
            # RDP settings are already restored via the Smart JSON-Fallback mechanism in Rollback.ps1
            # This JSON backup serves as a fallback and doesn't require separate restore logic
            Write-Log -Level DEBUG -Message "RDP_Hardening.json acknowledged (already handled by Smart JSON-Fallback)" -Module "AdvancedSecurity"
            return $true
        }
        else {
            Write-Log -Level WARNING -Message "Unknown Advanced Security backup type: $filename" -Module "AdvancedSecurity"
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to restore Advanced Security settings: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}

function Restore-FirewallRules {
    param($BackupData)
    
    Write-Log -Level INFO -Message "Restoring firewall rules..." -Module "AdvancedSecurity"
    
    try {
        # 1. Remove rules created by hardening (identified by Group or Name pattern)
        # The hardening module creates rules with specific names/groups.
        # Since we don't have the exact names of created rules stored in a "CreatedRules" list here,
        # we rely on the fact that we are restoring the *previous* state.
        
        # However, for firewall rules, "restoring" usually means:
        # 1. Deleting the BLOCK rules we added
        # 2. Re-enabling any rules we disabled (if any)
        
        # The backup contains a SNAPSHOT of rules matching the risky ports.
        # We should restore their state (Enabled/Disabled, Action).
        
        if ($BackupData.Rules) {
            foreach ($rule in $BackupData.Rules) {
                # Check if rule exists
                $currentRule = Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
                
                if ($currentRule) {
                    # Restore state
                    Set-NetFirewallRule -Name $rule.Name `
                        -Enabled $rule.Enabled `
                        -Action $rule.Action `
                        -ErrorAction SilentlyContinue
                        
                    Write-Log -Level DEBUG -Message "Restored rule state: $($rule.Name)" -Module "AdvancedSecurity"
                }
            }
        }
        
        # Also remove the specific block rules added by AdvancedSecurity
        # These include:
        #  - Block Risky Port * (legacy patterns)
        #  - NoID Privacy Pro - Block Finger Protocol (Port 79)
        #  - NoID Privacy Pro - Block SSDP (UDP 1900)
        #  - Block Admin Shares - NoID Privacy (TCP 445 on Public profile)
        $blockRules = Get-NetFirewallRule -DisplayName "Block Risky Port *" -ErrorAction SilentlyContinue
        if ($blockRules) {
            Remove-NetFirewallRule -InputObject $blockRules -ErrorAction SilentlyContinue
            Write-Log -Level INFO -Message "Removed $($blockRules.Count) hardening block rules" -Module "AdvancedSecurity"
        }

        # Remove Finger Protocol rule (corrected name with NoID prefix)
        Remove-NetFirewallRule -DisplayName "NoID Privacy Pro - Block Finger Protocol (Port 79)" -ErrorAction SilentlyContinue

        # Remove SSDP block rule (UDP 1900)
        Remove-NetFirewallRule -DisplayName "NoID Privacy Pro - Block SSDP (UDP 1900)" -ErrorAction SilentlyContinue
        
        # Remove Admin Shares SMB block rule (TCP 445 on Public profile)
        Remove-NetFirewallRule -DisplayName "Block Admin Shares - NoID Privacy" -ErrorAction SilentlyContinue
        
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to restore firewall rules: $_" -Module "AdvancedSecurity"
        return $false
    }
}

function Restore-PowerShellV2 {
    param($BackupData)
    
    Write-Log -Level INFO -Message "Restoring PowerShell v2 state..." -Module "AdvancedSecurity"
    
    try {
        $shouldEnable = ($BackupData.State -eq "Enabled")
        
        # Check current state
        $psv2RegPath = "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine"
        $psv2EngineVersion = (Get-ItemProperty -Path $psv2RegPath -Name "PowerShellVersion" -ErrorAction SilentlyContinue).PowerShellVersion
        $isEnabled = ($null -ne $psv2EngineVersion -and $psv2EngineVersion -like "2.*")
        
        if ($shouldEnable -and -not $isEnabled) {
            Write-Log -Level INFO -Message "Re-enabling PowerShell v2 (via DISM)..." -Module "AdvancedSecurity"
            Enable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction Stop | Out-Null
        }
        elseif (-not $shouldEnable -and $isEnabled) {
            Write-Log -Level INFO -Message "Disabling PowerShell v2 (via DISM)..." -Module "AdvancedSecurity"
            Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction Stop | Out-Null
        }
        else {
            Write-Log -Level INFO -Message "PowerShell v2 state already matches backup ($($BackupData.State))" -Module "AdvancedSecurity"
        }
        
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to restore PowerShell v2: $_" -Module "AdvancedSecurity"
        return $false
    }
}

function Restore-AdminShares {
    param($BackupData)
    
    Write-Log -Level INFO -Message "Restoring Admin Shares..." -Module "AdvancedSecurity"
    
    try {
        # The backup contains a list of shares that existed.
        # If we disabled them, they might be gone or the AutoShareServer/Wks registry keys were changed.
        # Registry keys are handled by the generic Registry restore!
        # So we mainly need to verify if we need to manually recreate shares or if registry restore + reboot is enough.
        
        # Changing AutoShareServer/AutoShareWks requires a reboot to take effect.
        # So simply restoring the registry keys (which happens before this) should be sufficient for the next boot.
        
        # However, we can try to force re-creation if possible, but usually LanmanServer needs restart.
        Write-Log -Level INFO -Message "Admin Shares settings restored via Registry. A reboot is required to fully restore shares." -Module "AdvancedSecurity"
        
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to restore Admin Shares: $_" -Module "AdvancedSecurity"
        return $false
    }
}
