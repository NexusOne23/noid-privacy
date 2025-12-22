function Set-WindowsUpdate {
    <#
    .SYNOPSIS
        Configures Windows Update using simple GUI-equivalent settings
        
    .DESCRIPTION
        Applies 3 simple Windows Update settings that align with the Windows Settings GUI:
        1. Get the latest updates as soon as they're available (ON, enforced via policy)
        2. Receive updates for other Microsoft products (ON, user-toggleable)
        3. Delivery Optimization - Downloads from other devices (OFF, enforced via policy)
        
        NO forced schedules and NO auto-reboot policies are configured.
        Installation timing remains user-controlled via the Windows Update GUI; where
        policies are used, Windows clearly indicates that "Some settings are managed
        by your organization".
        
    .PARAMETER DryRun
        Preview changes without applying them
        
    .EXAMPLE
        Set-WindowsUpdate
        
    .NOTES
        Author: NexusOne23
        Version: 2.2.2
        Requires: Administrator privileges
        Based on: Windows Settings > Windows Update > Advanced options
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        $configPath = Join-Path $PSScriptRoot "..\Config\WindowsUpdate.json"
        
        if (-not (Test-Path $configPath)) {
            Write-Log -Level ERROR -Message "WindowsUpdate.json not found: $configPath" -Module "AdvancedSecurity"
            return $false
        }
        
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        
        Write-Log -Level INFO -Message "Configuring Windows Update (3 simple GUI settings)..." -Module "AdvancedSecurity"
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would configure 3 Windows Update settings" -Module "AdvancedSecurity"
            return $true
        }
        
        $settingsApplied = 0
        
        # Loop through all 3 settings from config
        foreach ($settingKey in $config.Settings.PSObject.Properties.Name) {
            $setting = $config.Settings.$settingKey
            $regPath = $setting.RegistryPath
            
            # Ensure registry path exists
            if (-not (Test-Path $regPath)) {
                Write-Log -Level DEBUG -Message "Creating registry path: $regPath" -Module "AdvancedSecurity"
                New-Item -Path $regPath -Force | Out-Null
            }
            
            # Apply each value in this setting
            foreach ($valueName in $setting.Values.PSObject.Properties.Name) {
                $valueData = $setting.Values.$valueName
                
                # Always use New-ItemProperty with -Force to ensure correct type and value
                # -Force will overwrite existing keys
                New-ItemProperty -Path $regPath -Name $valueName -Value $valueData.Value -PropertyType DWord -Force | Out-Null
                
                Write-Log -Level SUCCESS -Message "$($setting.Name): $valueName = $($valueData.Value)" -Module "AdvancedSecurity"
                $settingsApplied++
            }
        }
        
        Write-Log -Level SUCCESS -Message "Windows Update configured: $settingsApplied registry keys set" -Module "AdvancedSecurity"
        
        # Restart Windows Update service to apply changes immediately
        Write-Log -Level INFO -Message "Restarting Windows Update service to apply changes..." -Module "AdvancedSecurity"
        try {
            Restart-Service -Name wuauserv -Force -ErrorAction Stop | Out-Null
            Write-Log -Level SUCCESS -Message "Windows Update service restarted successfully" -Module "AdvancedSecurity"
        }
        catch {
            Write-Log -Level WARNING -Message "Could not restart Windows Update service: $($_.Exception.Message)" -Module "AdvancedSecurity"
        }
        
        Write-Host ""
        Write-Host "================================================" -ForegroundColor Green
        Write-Host "  Windows Update Configured (3 Settings)" -ForegroundColor Green
        Write-Host "================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "[1] Get latest updates immediately:  ON (Policy)" -ForegroundColor Gray
        Write-Host "[2] Microsoft Update (Office, etc.): ON (User can toggle)" -ForegroundColor Gray
        Write-Host "[3] P2P Delivery Optimization:       OFF (Policy)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Installation timing remains user-controlled (no forced schedules, no auto-reboot policies)." -ForegroundColor White
        Write-Host "Windows will indicate where settings are managed by policy in the GUI." -ForegroundColor White
        Write-Host ""
        
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to configure Windows Update: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
