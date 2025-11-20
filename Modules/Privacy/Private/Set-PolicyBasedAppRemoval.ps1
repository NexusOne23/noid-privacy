function Set-PolicyBasedAppRemoval {
    <#
    .SYNOPSIS
        Configure policy-based inbox app removal for Windows 11 25H2+ Enterprise/Education
    
    .DESCRIPTION
        Uses Microsoft's official RemoveDefaultMicrosoftStorePackages policy to remove
        preinstalled apps at the policy level. This is the recommended method for Win11 25H2+.
        
        Registry structure:
        HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages
          Enabled = 1 (DWORD)
          <AppID> (subkey)
            RemovedPackage = 1 (DWORD)
    
    .EXAMPLE
        Set-PolicyBasedAppRemoval
    
    .NOTES
        Requires Windows 11 25H2+ Enterprise or Education edition
        Apps are removed at next sign-in or OOBE
        While policy is active, removed apps cannot be reinstalled
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Level INFO -Message "Configuring policy-based inbox app removal..." -Module "Privacy"
        
        # Load configuration
        $configPath = Join-Path $PSScriptRoot "..\Config\Bloatware.json"
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        
        $policyMethod = $config.PolicyMethod
        $policyConfiguredApps = @()  # Track apps configured for removal
        $registryPath = $policyMethod.RegistryPath
        
        # Create root policy key if not exists
        if (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            Write-Log -Level INFO -Message "Created policy key: $registryPath" -Module "Privacy"
        }
        
        # Enable the policy
        $existing = Get-ItemProperty -Path $registryPath -Name "Enabled" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $registryPath -Name "Enabled" -Value 1 -Force | Out-Null
        } else {
            New-ItemProperty -Path $registryPath -Name "Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Write-Log -Level SUCCESS -Message "Policy enabled: RemoveDefaultMicrosoftStorePackages" -Module "Privacy"
        
        # Configure each app
        $appsToRemove = @()
        foreach ($appId in $policyMethod.Apps.PSObject.Properties.Name) {
            $shouldRemove = $policyMethod.Apps.$appId
            
            if ($shouldRemove) {
                # Create subkey for app
                $appKeyPath = Join-Path $registryPath $appId
                if (!(Test-Path $appKeyPath)) {
                    New-Item -Path $appKeyPath -Force | Out-Null
                }
                
                # Set RemovedPackage flag
                $existing = Get-ItemProperty -Path $appKeyPath -Name "RemovedPackage" -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $appKeyPath -Name "RemovedPackage" -Value 1 -Force | Out-Null
                } else {
                    New-ItemProperty -Path $appKeyPath -Name "RemovedPackage" -Value 1 -PropertyType DWord -Force | Out-Null
                }
                
                $packageName = $policyMethod.AppMapping.$appId
                Write-Log -Level SUCCESS -Message "Marked for removal: $appId ($packageName)" -Module "Privacy"
                $appsToRemove += $appId
                $policyConfiguredApps += $packageName  # Track readable app name
            } else {
                # Ensure app is NOT marked for removal (defensive)
                $appKeyPath = Join-Path $registryPath $appId
                if (Test-Path $appKeyPath) {
                    Remove-Item -Path $appKeyPath -Recurse -Force
                    Write-Log -Level INFO -Message "Ensured NOT removed: $appId" -Module "Privacy"
                }
            }
        }
        
        Write-Host "`n============================================" -ForegroundColor Cyan
        Write-Host "  POLICY-BASED APP REMOVAL CONFIGURED" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "`nApps marked for removal: $($appsToRemove.Count)" -ForegroundColor Green
        foreach ($app in $appsToRemove) {
            Write-Host "  - $app" -ForegroundColor Gray
        }
        Write-Host "`nNOTE: Apps will be removed at:" -ForegroundColor Yellow
        Write-Host "  - Next user sign-in" -ForegroundColor Gray
        Write-Host "  - OOBE (new device setup)" -ForegroundColor Gray
        Write-Host "  - After OS upgrade" -ForegroundColor Gray
        Write-Host "`nWhile policy is active, removed apps CANNOT be reinstalled.`n" -ForegroundColor Yellow
        
        Write-Log -Level SUCCESS -Message "Policy-based app removal configured successfully" -Module "Privacy"
        
        # Return list of configured apps for user info
        return [PSCustomObject]@{
            Success = $true
            RemovedApps = $policyConfiguredApps
            Count = $appsToRemove.Count
        }
        
    } catch {
        Write-Log -Level ERROR -Message "Failed to configure policy-based app removal: $_" -Module "Privacy"
        return [PSCustomObject]@{
            Success = $false
            RemovedApps = @()
            Count = 0
        }
    }
}
