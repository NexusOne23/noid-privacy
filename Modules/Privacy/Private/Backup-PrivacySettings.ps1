function Backup-PrivacySettings {
    <#
    .SYNOPSIS
        Backup all privacy-related settings using Session-based backup system
    
    .DESCRIPTION
        Creates a complete backup of all settings that will be modified by the Privacy module:
        - Registry keys (all categories)
        - Service startup types
        - Scheduled task states
        - Installed AppxPackages list
        
        Uses Core/Rollback.ps1 Register-Backup for Session-based backup.
    
    .EXAMPLE
        Backup-PrivacySettings
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Level INFO -Message "Starting privacy settings backup (Session-based)..." -Module "Privacy"
        
        # Registry keys to backup using Core/Rollback.ps1
        $registryKeys = @(
            # HKLM Policy Keys
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
            "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
            "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive",
            "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore",
            "HKLM:\SOFTWARE\Policies\Microsoft\Dsh",
            "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics",
            # HKCU User Keys
            "HKCU:\Software\Policies\Microsoft\Windows\Explorer",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            # NEW: Anti-Advertising & Search Settings (v2.2.0)
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings",
            "HKCU:\Control Panel\International\User Profile",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement",
            "HKCU:\SOFTWARE\Microsoft\Personalization\Settings",
            # NEW: Input Personalization Settings (v2.2.0 - FIX missing HKCU backup)
            "HKCU:\SOFTWARE\Microsoft\InputPersonalization",
            "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"
        )
        
        # Backup registry keys using Session system (.reg files for reference)
        $backupCount = 0
        foreach ($key in $registryKeys) {
            $keyName = $key -replace "[:\\]", "_" -replace "^HKLM_", "" -replace "^HKCU_", "USER_"
            try {
                $result = Backup-RegistryKey -KeyPath $key -BackupName $keyName
                if ($result) {
                    $backupCount++
                    Write-Log -Level DEBUG -Message "Backed up registry key: $key" -Module "Privacy"
                }
            } catch {
                Write-Log -Level WARNING -Message "Failed to backup registry key $key : $_" -Module "Privacy"
            }
        }
        
        # CRITICAL: Create JSON snapshot of all registry values for precise restore
        # This counters GPO tattooing and ensures values not in backup get deleted
        Write-Log -Level INFO -Message "Creating Privacy registry pre-state snapshot (JSON)..." -Module "Privacy"
        $preStateSnapshot = @()
        
        foreach ($key in $registryKeys) {
            if (Test-Path $key) {
                try {
                    $properties = Get-ItemProperty -Path $key -ErrorAction Stop
                    $propertyNames = $properties.PSObject.Properties.Name | Where-Object { $_ -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider') }
                    
                    foreach ($propName in $propertyNames) {
                        $propValue = $properties.$propName
                        $propType = (Get-Item $key).GetValueKind($propName)
                        
                        $preStateSnapshot += [PSCustomObject]@{
                            Path = $key
                            Name = $propName
                            Value = $propValue
                            Type = $propType.ToString()
                            Exists = $true
                        }
                    }
                } catch {
                    Write-Log -Level DEBUG -Message "Could not read properties from $key : $_" -Module "Privacy"
                }
            }
        }
        
        # Save JSON snapshot
        try {
            $snapshotJson = $preStateSnapshot | ConvertTo-Json -Depth 5
            $result = Register-Backup -Type "Privacy" -Data $snapshotJson -Name "Privacy_PreState"
            if ($result) {
                $backupCount++
                Write-Log -Level SUCCESS -Message "Privacy pre-state snapshot created ($($preStateSnapshot.Count) registry values)" -Module "Privacy"
            }
        } catch {
            Write-Log -Level WARNING -Message "Failed to create Privacy pre-state snapshot: $_" -Module "Privacy"
        }
        
        # Backup service states using Session system
        $services = @("DiagTrack", "dmwappushservice", "WerSvc")
        foreach ($serviceName in $services) {
            try {
                $result = Backup-ServiceConfiguration -ServiceName $serviceName
                if ($result) {
                    $backupCount++
                    Write-Log -Level DEBUG -Message "Backed up service: $serviceName" -Module "Privacy"
                }
            } catch {
                Write-Log -Level WARNING -Message "Failed to backup service $serviceName : $_" -Module "Privacy"
            }
        }
        
        # Backup scheduled task states using Session system
        $tasks = @(
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Application Experience\StartupAppTask",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
        )
        
        foreach ($taskPath in $tasks) {
            try {
                $result = Backup-ScheduledTask -TaskPath $taskPath
                if ($result) {
                    $backupCount++
                    Write-Log -Level DEBUG -Message "Backed up task: $taskPath" -Module "Privacy"
                }
                # If $result is $null, task doesn't exist (already logged as DEBUG by Backup-ScheduledTask)
            } catch {
                Write-Log -Level WARNING -Message "Unexpected error backing up task: $taskPath - $_" -Module "Privacy"
            }
        }
        
        # Backup installed AppxPackages list for bloatware restore reference
        try {
            $installedApps = Get-AppxPackage -AllUsers | Select-Object Name, Version, PackageFullName, Publisher
            $appBackupData = @{
                BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                AppsCount = $installedApps.Count
                Apps = $installedApps
            }
            
            $appBackupJson = $appBackupData | ConvertTo-Json -Depth 5
            $result = Register-Backup -Type "AppxPackages" -Data $appBackupJson -Name "InstalledApps"
            if ($result) {
                $backupCount++
                Write-Log -Level INFO -Message "Backed up installed AppxPackages list ($($installedApps.Count) apps)" -Module "Privacy"
            }
        } catch {
            Write-Log -Level WARNING -Message "Failed to backup AppxPackages list: $_" -Module "Privacy"
        }
        
        Write-Log -Level SUCCESS -Message "Privacy settings backup completed ($backupCount items backed up)" -Module "Privacy"
        return $backupCount
        
    } catch {
        Write-Log -Level ERROR -Message "Failed to backup privacy settings: $_" -Module "Privacy"
        return $false
    }
}
