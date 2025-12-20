function Set-SRPRules {
    <#
    .SYNOPSIS
        Configures Software Restriction Policies (SRP) to block .lnk execution from Temp/Downloads
        
    .DESCRIPTION
        Implements SRP rules to mitigate CVE-2025-9491 (Windows LNK Remote Code Execution).
        
        CRITICAL ZERO-DAY MITIGATION:
        - CVE-2025-9491: Actively exploited since 2017
        - No patch available (Microsoft: "does not meet servicing threshold")
        - ASR and SmartScreen do NOT protect against this
        
        SRP Rules Created:
        1. Block *.lnk from %LOCALAPPDATA%\Temp\* (Outlook attachments)
        2. Block *.lnk from %USERPROFILE%\Downloads\* (Browser downloads)
        
        Windows 11 Bug Fix:
        - Removes buggy registry keys that disable SRP on Win11
        
    .PARAMETER DryRun
        Preview changes without applying them
        
    .EXAMPLE
        Set-SRPRules
        Applies SRP rules to block malicious .lnk execution
        
    .NOTES
        Author: NexusOne23
        Version: 2.2.1
        Requires: Administrator privileges
        
        REFERENCES:
        - CVE-2025-9491: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-9491
        - CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
        - SRP Documentation: https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/applocker/software-restriction-policies
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        $configPath = Join-Path $PSScriptRoot "..\Config\SRP-Rules.json"
        
        if (-not (Test-Path $configPath)) {
            Write-Log -Level ERROR -Message "SRP-Rules.json not found: $configPath" -Module "AdvancedSecurity"
            return $false
        }
        
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        
        Write-Log -Level INFO -Message "Configuring Software Restriction Policies (SRP) for CVE-2025-9491..." -Module "AdvancedSecurity"
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would configure SRP with following rules:" -Module "AdvancedSecurity"
            foreach ($rule in $config.PathRules) {
                Write-Log -Level INFO -Message "[DRYRUN]   - $($rule.Name): $($rule.Path)" -Module "AdvancedSecurity"
            }
            return $true
        }
        
        # Step 1: Create SRP Policy Root
        $policyRoot = $config.RegistryPaths.PolicyRoot
        
        if (-not (Test-Path $policyRoot)) {
            Write-Log -Level INFO -Message "Creating SRP policy root: $policyRoot" -Module "AdvancedSecurity"
            New-Item -Path $policyRoot -Force | Out-Null
        }
        
        # Step 2: Set Default Level (Unrestricted)
        Write-Log -Level INFO -Message "Setting SRP default level to Unrestricted (262144)" -Module "AdvancedSecurity"
        
        $existingDefaultLevel = Get-ItemProperty -Path $policyRoot -Name "DefaultLevel" -ErrorAction SilentlyContinue
        if ($null -ne $existingDefaultLevel) {
            Set-ItemProperty -Path $policyRoot -Name "DefaultLevel" -Value $config.SRPConfiguration.DefaultLevel -Force | Out-Null
        }
        else {
            New-ItemProperty -Path $policyRoot -Name "DefaultLevel" -Value $config.SRPConfiguration.DefaultLevel -PropertyType DWord -Force | Out-Null
        }
        
        # Step 3: Enable Transparent Enforcement
        $existingTransparent = Get-ItemProperty -Path $policyRoot -Name "TransparentEnabled" -ErrorAction SilentlyContinue
        if ($null -ne $existingTransparent) {
            Set-ItemProperty -Path $policyRoot -Name "TransparentEnabled" -Value $config.SRPConfiguration.TransparentEnabled -Force | Out-Null
        }
        else {
            New-ItemProperty -Path $policyRoot -Name "TransparentEnabled" -Value $config.SRPConfiguration.TransparentEnabled -PropertyType DWord -Force | Out-Null
        }
        
        # Step 4: Create Path Rules
        $pathRulesRoot = $config.RegistryPaths.PathRules
        
        if (-not (Test-Path $pathRulesRoot)) {
            Write-Log -Level INFO -Message "Creating SRP path rules root: $pathRulesRoot" -Module "AdvancedSecurity"
            New-Item -Path $pathRulesRoot -Force | Out-Null
        }
        
        $rulesCreated = 0
        
        foreach ($rule in $config.PathRules) {
            if (-not $rule.Enabled) {
                Write-Log -Level INFO -Message "Skipping disabled rule: $($rule.Name)" -Module "AdvancedSecurity"
                continue
            }
            
            # Generate GUID for rule
            $ruleGuid = "{$([guid]::NewGuid().ToString())}"
            $rulePath = Join-Path $pathRulesRoot $ruleGuid
            
            Write-Log -Level INFO -Message "Creating SRP rule: $($rule.Name)" -Module "AdvancedSecurity"
            
            # Create rule key
            if (-not (Test-Path $rulePath)) {
                New-Item -Path $rulePath -Force | Out-Null
            }
            
            # Set ItemData (path pattern)
            $existingItemData = Get-ItemProperty -Path $rulePath -Name "ItemData" -ErrorAction SilentlyContinue
            if ($null -ne $existingItemData) {
                Set-ItemProperty -Path $rulePath -Name "ItemData" -Value $rule.Path -Force | Out-Null
            }
            else {
                New-ItemProperty -Path $rulePath -Name "ItemData" -Value $rule.Path -PropertyType ExpandString -Force | Out-Null
            }
            
            # Set Description
            $existingDescription = Get-ItemProperty -Path $rulePath -Name "Description" -ErrorAction SilentlyContinue
            if ($null -ne $existingDescription) {
                Set-ItemProperty -Path $rulePath -Name "Description" -Value $rule.Description -Force | Out-Null
            }
            else {
                New-ItemProperty -Path $rulePath -Name "Description" -Value $rule.Description -PropertyType String -Force | Out-Null
            }
            
            # Set SaferFlags
            $existingSaferFlags = Get-ItemProperty -Path $rulePath -Name "SaferFlags" -ErrorAction SilentlyContinue
            if ($null -ne $existingSaferFlags) {
                Set-ItemProperty -Path $rulePath -Name "SaferFlags" -Value $rule.SaferFlags -Force | Out-Null
            }
            else {
                New-ItemProperty -Path $rulePath -Name "SaferFlags" -Value $rule.SaferFlags -PropertyType DWord -Force | Out-Null
            }
            
            $rulesCreated++
            Write-Log -Level SUCCESS -Message "SRP rule created: $($rule.Name) -> $($rule.Path)" -Module "AdvancedSecurity"
        }
        
        # Step 5: Windows 11 Bug Fix
        $bugFixPath = $config.RegistryPaths.Win11BugFix
        
        if (Test-Path $bugFixPath) {
            Write-Log -Level INFO -Message "Applying Windows 11 SRP bug fix..." -Module "AdvancedSecurity"
            
            foreach ($keyName in $config.Windows11BugFix.KeysToRemove) {
                $keyExists = Get-ItemProperty -Path $bugFixPath -Name $keyName -ErrorAction SilentlyContinue
                
                if ($null -ne $keyExists) {
                    Remove-ItemProperty -Path $bugFixPath -Name $keyName -Force -ErrorAction SilentlyContinue
                    Write-Log -Level SUCCESS -Message "Removed buggy key: $keyName (Windows 11 SRP fix)" -Module "AdvancedSecurity"
                }
            }
        }
        
        Write-Log -Level SUCCESS -Message "SRP configuration completed: $rulesCreated rules created" -Module "AdvancedSecurity"
        Write-Log -Level INFO -Message "CVE-2025-9491 mitigation active - .lnk files from Temp/Downloads now blocked" -Module "AdvancedSecurity"
        
        Write-Host ""
        Write-Host "================================================" -ForegroundColor Green
        Write-Host "  SRP RULES CONFIGURED (CVE-2025-9491)" -ForegroundColor Green
        Write-Host "================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Zero-Day Protection: Windows LNK RCE (ACTIVELY EXPLOITED)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Rules Created:    $rulesCreated" -ForegroundColor Cyan
        Write-Host "Protected Paths:" -ForegroundColor White
        Write-Host "  - Outlook Temp (%LOCALAPPDATA%\Temp\*.lnk)" -ForegroundColor Gray
        Write-Host "  - Downloads    (%USERPROFILE%\Downloads\*.lnk)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Status:           ACTIVE (malicious .lnk files blocked)" -ForegroundColor Green
        Write-Host "CVE-2025-9491:    MITIGATED" -ForegroundColor Green
        Write-Host ""
        
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to configure SRP rules: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
