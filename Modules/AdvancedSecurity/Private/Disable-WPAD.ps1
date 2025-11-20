function Disable-WPAD {
    <#
    .SYNOPSIS
        Disable WPAD (Web Proxy Auto-Discovery) to prevent proxy hijacking
    
    .DESCRIPTION
        Disables WPAD auto-discovery to prevent MITM attacks and proxy hijacking.
        Sets registry keys to prevent automatic proxy detection.
        
        Attack Prevention: MITM attacks, proxy hijacking, credential theft
    
    .EXAMPLE
        Disable-WPAD
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Level INFO -Message "Disabling WPAD (Web Proxy Auto-Discovery)..." -Module "AdvancedSecurity"
        
        $wpadKeys = @(
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
                Name = "WpadOverride"
                Value = 1
            },
            @{
                Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
                Name = "AutoDetect"
                Value = 0
            },
            @{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
                Name = "AutoDetect"
                Value = 0
            }
        )
        
        # Backup
        $backupData = @{}
        foreach ($key in $wpadKeys) {
            if (Test-Path $key.Path) {
                $currentValue = (Get-ItemProperty -Path $key.Path -Name $key.Name -ErrorAction SilentlyContinue).($key.Name)
                $backupData["$($key.Path)\$($key.Name)"] = $currentValue
            }
        }
        Register-Backup -Type "WPAD_Settings" -Data ($backupData | ConvertTo-Json) -Name "WPAD"
        
        # Apply
        $setCount = 0
        foreach ($key in $wpadKeys) {
            if (-not (Test-Path $key.Path)) {
                New-Item -Path $key.Path -Force | Out-Null
            }
            
            $existing = Get-ItemProperty -Path $key.Path -Name $key.Name -ErrorAction SilentlyContinue
            if ($null -ne $existing) {
                Set-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -Force | Out-Null
            } else {
                New-ItemProperty -Path $key.Path -Name $key.Name -Value $key.Value -PropertyType DWord -Force | Out-Null
            }
            $setCount++
        }
        
        Write-Log -Level SUCCESS -Message "WPAD disabled ($setCount registry keys set)" -Module "AdvancedSecurity"
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to disable WPAD: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
