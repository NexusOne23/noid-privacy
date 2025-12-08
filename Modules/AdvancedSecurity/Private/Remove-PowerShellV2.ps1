function Remove-PowerShellV2 {
    <#
    .SYNOPSIS
        Remove PowerShell v2 to prevent downgrade attacks
    
    .DESCRIPTION
        Removes the PowerShell v2 Windows Feature to prevent downgrade attacks.
        PowerShell v2 bypasses logging, AMSI, and Constrained Language Mode.
        
        Attack Prevention: Downgrade attacks, script logging bypass, AMSI bypass
        
        Impact: Legacy scripts using -Version 2 will not work
    
    .EXAMPLE
        Remove-PowerShellV2
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Level INFO -Message "Checking PowerShell v2 optional feature state..." -Module "AdvancedSecurity"
        
        # Canonical detection: use Windows Optional Feature state
        $psv2Feature = $null
        try {
            $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
        }
        catch {
            $psv2Feature = $null
        }
        
        if (-not $psv2Feature) {
            # Feature is not available on this OS (e.g. removed in newer Windows 11 builds)
            Write-Log -Level INFO -Message "PowerShell v2 optional feature not available on this OS (nothing to remove)" -Module "AdvancedSecurity"
            return [PSCustomObject]@{
                Success = $true
                Changed = $false
            }
        }
        
        if ($psv2Feature.State -ne 'Enabled') {
            # Feature exists but is not enabled/installed
            Write-Log -Level SUCCESS -Message "PowerShell v2 feature state: $($psv2Feature.State) - no removal required" -Module "AdvancedSecurity"
            return [PSCustomObject]@{
                Success = $true
                Changed = $false
            }
        }
        
        # PSv2 feature is enabled - proceed with backup and removal
        Write-Log -Level DEBUG -Message "PowerShell v2 feature is ENABLED - preparing backup and removal via DISM..." -Module "AdvancedSecurity"
        
        # Backup current state
        $backupData = @{
            FeatureName = $psv2Feature.FeatureName
            State       = $psv2Feature.State
            BackupDate  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        Register-Backup -Type "WindowsFeature" -Data ($backupData | ConvertTo-Json) -Name "PowerShellV2"
        
        # Remove PowerShell v2
        Write-Log -Level WARNING -Message "Removing PowerShell v2 (this may take a moment)..." -Module "AdvancedSecurity"
        Write-Host ""
        Write-Host "Removing PowerShell v2..." -ForegroundColor Yellow
        Write-Host "This may take up to 60 seconds..." -ForegroundColor Gray
        Write-Host ""
        
        $result = Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -ErrorAction Stop
        
        if ($result.RestartNeeded) {
            Write-Log -Level WARNING -Message "PowerShell v2 removed - REBOOT REQUIRED to complete" -Module "AdvancedSecurity"
            Write-Host ""
            Write-Host "PowerShell v2 Removed!" -ForegroundColor Green
            Write-Host ""
            Write-Host "IMPORTANT: REBOOT REQUIRED" -ForegroundColor Yellow
            Write-Host "Changes will take effect after reboot." -ForegroundColor Gray
            Write-Host ""
        }
        else {
            Write-Log -Level SUCCESS -Message "PowerShell v2 removed successfully" -Module "AdvancedSecurity"
            Write-Host ""
            Write-Host "PowerShell v2 Removed!" -ForegroundColor Green
            Write-Host ""
        }
        
        return [PSCustomObject]@{
            Success = $true
            Changed = $true
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to remove PowerShell v2: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return [PSCustomObject]@{
            Success = $false
            Changed = $false
        }
    }
}
