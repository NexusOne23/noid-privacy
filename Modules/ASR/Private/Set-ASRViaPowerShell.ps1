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
        
        # WORKAROUND: Security Baseline may have set some rules to Audit mode already
        # Force-override via registry for critical rules that MUST be in Block mode
        # This is necessary because Set-MpPreference doesn't always override existing GP settings
        $asrRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
        
        foreach ($rule in $Rules) {
            # Only force-override if user explicitly wants Block mode (Action=1) 
            # and rule has BaselineStatus "Audit" (meaning Baseline set it to Audit)
            if ($rule.Action -eq 1 -and $rule.BaselineStatus -eq "Audit") {
                try {
                    # Verify current registry value
                    $currentValue = Get-ItemProperty -Path $asrRegistryPath -Name $rule.GUID -ErrorAction SilentlyContinue
                    
                    if ($currentValue -and $currentValue.($rule.GUID) -ne 1) {
                        # Force-set via registry
                        $existing = Get-ItemProperty -Path $asrRegistryPath -Name $rule.GUID -ErrorAction SilentlyContinue
                        if ($null -ne $existing) {
                            Set-ItemProperty -Path $asrRegistryPath -Name $rule.GUID -Value 1 -Force -ErrorAction Stop | Out-Null
                        } else {
                            New-ItemProperty -Path $asrRegistryPath -Name $rule.GUID -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                        }
                        Write-Log -Level INFO -Message "Force-applied $($rule.Name) to Block mode via registry (was Audit from Baseline)" -Module "ASR"
                        # This is an intentional upgrade, not a warning
                        # $result.Warnings += "Rule '$($rule.Name)' upgraded from Audit to Block (Security Baseline override)"
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
