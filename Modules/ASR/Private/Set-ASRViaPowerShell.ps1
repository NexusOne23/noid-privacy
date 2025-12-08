<#
.SYNOPSIS
    Apply ASR rules using Set-MpPreference (PowerShell)
    
.DESCRIPTION
    Uses Microsoft's recommended PowerShell cmdlet to apply ASR rules
    Cleaner and more validated than direct registry manipulation
    
.PARAMETER Rules
    Array of rule objects to apply
    
.PARAMETER DryRun
    Preview changes without applying
    
.OUTPUTS
    PSCustomObject with applied count and errors
#>

function Set-ASRViaPowerShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Array]$Rules,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    $result = [PSCustomObject]@{
        Applied = 0
        Errors = @()
        Warnings = @()
    }
    
    try {
        # Build arrays for Set-MpPreference
        $ruleIds = @()
        $ruleActions = @()
        
        foreach ($rule in $Rules) {
            $ruleIds += $rule.GUID
            $ruleActions += $rule.Action
        }
        
        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would apply $($ruleIds.Count) ASR rules via Set-MpPreference" -Module "ASR"
            $result.Applied = $ruleIds.Count
            return $result
        }
        
        Write-Log -Level INFO -Message "Applying $($ruleIds.Count) ASR rules via Set-MpPreference..." -Module "ASR"
        
        # Apply all rules at once
        Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds `
                         -AttackSurfaceReductionRules_Actions $ruleActions `
                         -ErrorAction Stop | Out-Null
        
        $result.Applied = $ruleIds.Count
        
        # WORKAROUND: GPO Registry has higher priority than Set-MpPreference
        # We must set BOTH Set-MpPreference AND GPO Registry to ensure the rule is actually applied
        # This applies to user-configurable rules (PSExec/WMI and Prevalence)
        $asrRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
        
        # User-configurable rules that need GPO Registry sync
        $userConfigurableRules = @(
            "d1e49aac-8f56-4280-b9ba-993a6d77406c",  # PSExec/WMI (Management Tools)
            "01443614-cd74-433a-b99e-2ecdc07bfc25"   # Prevalence (New/Unknown Software)
        )
        
        foreach ($rule in $Rules) {
            # For user-configurable rules: Always sync to GPO Registry (Block OR Audit)
            if ($userConfigurableRules -contains $rule.GUID) {
                try {
                    $currentValue = Get-ItemProperty -Path $asrRegistryPath -Name $rule.GUID -ErrorAction SilentlyContinue
                    $needsUpdate = $false
                    
                    if ($currentValue) {
                        # Registry exists - check if value differs
                        if ([int]$currentValue.($rule.GUID) -ne $rule.Action) {
                            $needsUpdate = $true
                        }
                    } else {
                        # Registry doesn't exist - need to create it
                        $needsUpdate = $true
                    }
                    
                    if ($needsUpdate) {
                        # Ensure path exists
                        if (-not (Test-Path $asrRegistryPath)) {
                            New-Item -Path $asrRegistryPath -Force | Out-Null
                        }
                        
                        # Set the registry value (using string type like Security Baseline does)
                        Set-ItemProperty -Path $asrRegistryPath -Name $rule.GUID -Value $rule.Action.ToString() -Type String -Force -ErrorAction Stop | Out-Null
                        
                        $modeName = switch ($rule.Action) { 1 { "Block" } 2 { "Audit" } default { "Unknown" } }
                        Write-Log -Level INFO -Message "Synced $($rule.Name) to GPO Registry: $modeName mode" -Module "ASR"
                    }
                }
                catch {
                    $result.Warnings += "Could not sync rule $($rule.Name) to GPO registry: $($_.Exception.Message)"
                    Write-Log -Level WARNING -Message "Could not sync $($rule.Name) to GPO registry: $($_.Exception.Message)" -Module "ASR"
                }
            }
            # For non-configurable rules: Only override if user wants Block and Baseline had Audit
            elseif ($rule.Action -eq 1 -and $rule.BaselineStatus -eq "Audit") {
                try {
                    $currentValue = Get-ItemProperty -Path $asrRegistryPath -Name $rule.GUID -ErrorAction SilentlyContinue
                    
                    if ($currentValue -and [int]$currentValue.($rule.GUID) -ne 1) {
                        Set-ItemProperty -Path $asrRegistryPath -Name $rule.GUID -Value "1" -Type String -Force -ErrorAction Stop | Out-Null
                        Write-Log -Level INFO -Message "Force-applied $($rule.Name) to Block mode via registry (was Audit from Baseline)" -Module "ASR"
                    }
                }
                catch {
                    $result.Warnings += "Could not force-apply rule $($rule.Name) via registry: $($_.Exception.Message)"
                    Write-Log -Level WARNING -Message "Could not force-apply $($rule.Name) via registry: $($_.Exception.Message)" -Module "ASR"
                }
            }
        }
        
        Write-Log -Level INFO -Message "Successfully applied $($ruleIds.Count) ASR rules" -Module "ASR"
    }
    catch {
        $result.Errors += "Failed to apply ASR rules: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message "Set-MpPreference failed: $($_.Exception.Message)" -Module "ASR"
    }
    
    return $result
}
