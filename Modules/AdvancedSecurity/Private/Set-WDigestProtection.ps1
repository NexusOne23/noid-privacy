function Set-WDigestProtection {
    <#
    .SYNOPSIS
        Disable WDigest credential caching to prevent plaintext password storage in LSASS
    
    .DESCRIPTION
        Configures WDigest to NOT store plaintext credentials in LSASS memory.
        Prevents Mimikatz, Windows Credential Editor (WCE), and other memory-dumping
        tools from extracting plaintext passwords.
        
        Status: This setting is DEPRECATED in Windows 11 24H2+ (default is already secure),
        but we set it explicitly for:
        - Backwards compatibility with older Windows versions
        - Defense-in-depth (explicit is better than implicit)
        - Mixed environments with Win7/8/Server 2008/2012
        
        No negative impact on modern systems (setting is ignored on Win11 24H2+).
    
    .EXAMPLE
        Set-WDigestProtection
        Sets UseLogonCredential = 0 to prevent plaintext credential storage
    
    .NOTES
        Microsoft Security Advisory: KB2871997 (May 2014)
        Deprecated in Windows 11 24H2 Security Baseline (September 2024)
        
        Default behavior:
        - Windows 7/8/Server 2008/2012: UseLogonCredential = 1 (INSECURE!)
        - Windows 8.1+: UseLogonCredential = 0 (Secure)
        - Windows 11 24H2+: Setting ignored (hardcoded secure)
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log -Level INFO -Message "Configuring WDigest credential protection..." -Module "AdvancedSecurity"
        
        $wdigestRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        
        # Check Windows version for informational logging
        $osVersion = [System.Environment]::OSVersion.Version
        $isWin11 = $osVersion.Major -ge 10 -and $osVersion.Build -ge 22000
        
        if ($isWin11 -and $osVersion.Build -ge 26100) {
            # Windows 11 24H2+ (Build 26100+)
            Write-Log -Level INFO -Message "Windows 11 24H2+ detected - WDigest setting is deprecated but will be set for backwards compatibility" -Module "AdvancedSecurity"
        }
        
        # Backup current setting
        $currentValue = $null
        if (Test-Path $wdigestRegPath) {
            $currentValue = (Get-ItemProperty -Path $wdigestRegPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
        }
        
        $backupData = @{
            OriginalValue = $currentValue
            RegistryPath = $wdigestRegPath
            SettingName = "UseLogonCredential"
            BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        # Register backup
        $backupJson = $backupData | ConvertTo-Json -Depth 10
        Register-Backup -Type "WDigest_Settings" -Data $backupJson -Name "WDigest_Protection"
        
        # Create registry path if it doesn't exist
        if (-not (Test-Path $wdigestRegPath)) {
            Write-Log -Level INFO -Message "Creating WDigest registry path..." -Module "AdvancedSecurity"
            New-Item -Path $wdigestRegPath -Force | Out-Null
        }
        
        # Set UseLogonCredential = 0 (Secure - no plaintext in memory)
        $existing = Get-ItemProperty -Path $wdigestRegPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $wdigestRegPath -Name "UseLogonCredential" -Value 0 -Force | Out-Null
        } else {
            New-ItemProperty -Path $wdigestRegPath -Name "UseLogonCredential" -Value 0 -PropertyType DWord -Force | Out-Null
        }
        
        # Verify
        $newValue = (Get-ItemProperty -Path $wdigestRegPath -Name "UseLogonCredential").UseLogonCredential
        
        if ($newValue -eq 0) {
            if ($currentValue -eq 1) {
                Write-Log -Level SUCCESS -Message "WDigest credential protection enabled (UseLogonCredential = 0)" -Module "AdvancedSecurity"
                Write-Log -Level WARNING -Message "Previous value was 1 (INSECURE) - system was vulnerable to plaintext credential dumps!" -Module "AdvancedSecurity"
                Write-Host ""
                Write-Host "SECURITY IMPROVEMENT: WDigest was storing plaintext credentials!" -ForegroundColor Yellow
                Write-Host "This has now been FIXED. Plaintext credential storage is disabled." -ForegroundColor Green
                Write-Host ""
            }
            elseif ($null -eq $currentValue) {
                Write-Log -Level SUCCESS -Message "WDigest credential protection configured (UseLogonCredential = 0)" -Module "AdvancedSecurity"
                Write-Log -Level INFO -Message "WDigest setting was not previously configured (default varies by OS version)" -Module "AdvancedSecurity"
            }
            else {
                # currentValue was already 0
                Write-Log -Level SUCCESS -Message "WDigest credential protection verified (UseLogonCredential = 0)" -Module "AdvancedSecurity"
                Write-Log -Level INFO -Message "Setting was already correct (no change needed)" -Module "AdvancedSecurity"
            }
            
            return $true
        }
        else {
            Write-Log -Level ERROR -Message "Failed to verify WDigest setting (expected 0, got $newValue)" -Module "AdvancedSecurity"
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to configure WDigest protection: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
