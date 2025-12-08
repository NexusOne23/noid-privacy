function Disable-WPAD {
    <#
    .SYNOPSIS
        Disable WPAD (Web Proxy Auto-Discovery) to prevent proxy hijacking
    
    .DESCRIPTION
        Disables WPAD auto-discovery to prevent MITM attacks and proxy hijacking.
        Uses the official Microsoft-recommended registry key (DisableWpad) plus
        browser-level AutoDetect settings for third-party app compatibility.
        
        Reference: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features
        
        Attack Prevention: MITM attacks, proxy hijacking, credential theft
    
    .EXAMPLE
        Disable-WPAD
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Level INFO -Message "Disabling WPAD (Web Proxy Auto-Discovery)..." -Module "AdvancedSecurity"
        
        # HKLM keys (machine-wide)
        # Key 1: Official Microsoft-recommended key (Windows 10 1809+ / Server 2019+)
        # Key 2: Legacy WpadOverride (for older compatibility)
        # Key 3: AutoDetect for HKLM (browser-level setting)
        $hklmKeys = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
                Name = "DisableWpad"
                Value = 1
                Description = "Official MS key - disables WPAD for all WinHTTP API calls"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
                Name = "WpadOverride"
                Value = 1
                Description = "Legacy override key"
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
                Name = "AutoDetect"
                Value = 0
                Description = "Browser-level auto-detect (HKLM)"
            }
        )
        
        # Backup HKLM keys
        $backupData = @{}
        foreach ($key in $hklmKeys) {
            if (Test-Path $key.Path) {
                $currentValue = (Get-ItemProperty -Path $key.Path -Name $key.Name -ErrorAction SilentlyContinue).($key.Name)
                $backupData["$($key.Path)\$($key.Name)"] = $currentValue
            }
        }
        
        # Apply HKLM keys
        $setCount = 0
        foreach ($key in $hklmKeys) {
            if (-not (Test-Path $key.Path)) {
                New-Item -Path $key.Path -Force | Out-Null
            }
            
            $existing = Get-ItemProperty -Path $key.Path -Name $key.Name -ErrorAction SilentlyContinue
            if ($null -ne $existing -and $null -ne $existing.($key.Name)) {
                Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force | Out-Null
            } else {
                New-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -PropertyType DWord -Force | Out-Null
            }
            $setCount++
        }
        
        # HKCU key - must be set for ALL user profiles, not just current elevated admin
        # When running as admin, HKCU points to admin's profile, not the logged-in user
        # Solution: Iterate through all user profiles via HKU (HKEY_USERS)
        $hkuPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        $hkuName = "AutoDetect"
        $hkuValue = 0
        
        # Mount HKU if not already available
        if (-not (Test-Path "HKU:")) {
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
        }
        
        # Get all user SIDs (excluding system accounts)
        $userSIDs = Get-ChildItem -Path "HKU:\" -ErrorAction SilentlyContinue | 
                    Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
                    Select-Object -ExpandProperty PSChildName
        
        foreach ($sid in $userSIDs) {
            $userKeyPath = "HKU:\$sid\$hkuPath"
            try {
                # Backup
                if (Test-Path $userKeyPath) {
                    $currentValue = (Get-ItemProperty -Path $userKeyPath -Name $hkuName -ErrorAction SilentlyContinue).($hkuName)
                    $backupData["HKU\$sid\$hkuPath\$hkuName"] = $currentValue
                }
                
                # Create path if not exists
                if (-not (Test-Path $userKeyPath)) {
                    New-Item -Path $userKeyPath -Force | Out-Null
                }
                
                # Always use Set-ItemProperty with -Type to ensure correct value type
                # Remove existing value first to avoid type conflicts
                Remove-ItemProperty -Path $userKeyPath -Name $hkuName -ErrorAction SilentlyContinue
                New-ItemProperty -Path $userKeyPath -Name $hkuName -Value $hkuValue -PropertyType DWord -Force | Out-Null
                
                # Verify the value was set correctly
                $verifyVal = (Get-ItemProperty -Path $userKeyPath -Name $hkuName -ErrorAction SilentlyContinue).($hkuName)
                if ($verifyVal -eq $hkuValue) {
                    $setCount++
                    Write-Log -Level DEBUG -Message "WPAD AutoDetect set for SID $sid (verified: $verifyVal)" -Module "AdvancedSecurity"
                }
                else {
                    Write-Log -Level WARNING -Message "WPAD AutoDetect verification failed for SID $sid (expected $hkuValue, got $verifyVal)" -Module "AdvancedSecurity"
                }
            }
            catch {
                Write-Log -Level DEBUG -Message "Could not set WPAD for SID $sid : $_" -Module "AdvancedSecurity"
            }
        }
        
        # Also set for .DEFAULT (applies to new users)
        $defaultPath = "HKU:\.DEFAULT\$hkuPath"
        try {
            if (-not (Test-Path $defaultPath)) {
                New-Item -Path $defaultPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            New-ItemProperty -Path $defaultPath -Name $hkuName -Value $hkuValue -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
            $setCount++
        }
        catch {
            Write-Log -Level DEBUG -Message "Could not set WPAD for .DEFAULT: $_" -Module "AdvancedSecurity"
        }
        
        Register-Backup -Type "WPAD_Settings" -Data ($backupData | ConvertTo-Json) -Name "WPAD"
        
        Write-Log -Level SUCCESS -Message "WPAD disabled ($setCount registry keys set across all user profiles)" -Module "AdvancedSecurity"
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to disable WPAD: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
