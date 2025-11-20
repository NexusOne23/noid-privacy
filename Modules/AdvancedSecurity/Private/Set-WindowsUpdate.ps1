function Set-WindowsUpdate {
    <#
    .SYNOPSIS
        Configures Windows Update using simple GUI-equivalent settings
        
    .DESCRIPTION
        Applies 3 simple Windows Update settings that match the Windows Settings GUI:
        1. Get the latest updates as soon as they're available (ON)
        2. Receive updates for other Microsoft products (ON)
        3. Delivery Optimization - Downloads from other devices (OFF)
        
        NO forced schedules, NO auto-reboot policies, NO hidden deferrals.
        User keeps full control via Windows Settings GUI.
        
    .PARAMETER DryRun
        Preview changes without applying them
        
    .EXAMPLE
        Set-WindowsUpdate
        
    .NOTES
        Author: NoID Privacy Pro Team
        Version: 2.1.0
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
                
                $existing = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
                
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData.Value -Force | Out-Null
                }
                else {
                    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData.Value -PropertyType DWord -Force | Out-Null
                }
                
                Write-Log -Level SUCCESS -Message "$($setting.Name): $valueName = $($valueData.Value)" -Module "AdvancedSecurity"
                $settingsApplied++
            }
        }
        
        Write-Log -Level SUCCESS -Message "Windows Update configured: $settingsApplied registry keys set" -Module "AdvancedSecurity"
        
        Write-Host ""
        Write-Host "================================================" -ForegroundColor Green
        Write-Host "  Windows Update Configured (3 Settings)" -ForegroundColor Green
        Write-Host "================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "[1] Get latest updates immediately:  ON" -ForegroundColor Gray
        Write-Host "[2] Microsoft Update (Office, etc.): ON" -ForegroundColor Gray
        Write-Host "[3] P2P Delivery Optimization:       OFF" -ForegroundColor Gray
        Write-Host ""
        Write-Host "User retains full control via Windows Settings GUI" -ForegroundColor White
        Write-Host "No forced schedules, no auto-reboot policies" -ForegroundColor White
        Write-Host ""
        
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to configure Windows Update: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
