<#
.SYNOPSIS
    Verify ASR rules are correctly applied
    
.DESCRIPTION
    Uses Get-MpPreference to verify all ASR rules are active with correct actions
    
.PARAMETER ExpectedRules
    Array of rule objects with GUID and Action properties
    
.OUTPUTS
    PSCustomObject with verification results
#>

function Test-ASRCompliance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Array]$ExpectedRules
    )
    
    $result = [PSCustomObject]@{
        Passed = $true
        CheckedCount = 0
        FailedCount = 0
        FailedRules = @()
    }
    
    try {
        # Get current ASR configuration from Defender
        $mpPref = Get-MpPreference -ErrorAction Stop
        
        # Get configured ASR rule IDs and actions
        $configuredIds = $mpPref.AttackSurfaceReductionRules_Ids
        $configuredActions = $mpPref.AttackSurfaceReductionRules_Actions
        
        if (-not $configuredIds -or $configuredIds.Count -eq 0) {
            $result.Passed = $false
            $result.FailedCount = $ExpectedRules.Count
            Write-Log -Level WARNING -Message "No ASR rules found in Defender configuration" -Module "ASR"
            return $result
        }
        
        # Create hashtable for quick lookup
        $configuredRules = @{}
        for ($i = 0; $i -lt $configuredIds.Count; $i++) {
            $configuredRules[$configuredIds[$i]] = $configuredActions[$i]
        }
        
        # Rules where both BLOCK (1) and AUDIT (2) are considered "Pass"
        # These are user-configurable rules where either mode is valid
        $flexibleRules = @(
            "d1e49aac-8f56-4280-b9ba-993a6d77406c",  # PSExec/WMI (Management Tools)
            "01443614-cd74-433a-b99e-2ecdc07bfc25"   # Prevalence (New/Unknown Software)
        )
        
        # Verify each expected rule
        foreach ($rule in $ExpectedRules) {
            $result.CheckedCount++
            
            if ($configuredRules.ContainsKey($rule.GUID)) {
                $actualAction = $configuredRules[$rule.GUID]
                
                # Check if this is a flexible rule (Block or Audit both count as Pass)
                $isFlexibleRule = $flexibleRules -contains $rule.GUID
                $isActiveMode = $actualAction -in @(1, 2)  # Block or Audit
                
                # For flexible rules: Pass if Block OR Audit
                # For other rules: Pass only if exact match
                $rulePassed = if ($isFlexibleRule) { $isActiveMode } else { $actualAction -eq $rule.Action }
                
                if (-not $rulePassed) {
                    $result.FailedCount++
                    $result.Passed = $false
                    $result.FailedRules += $rule.GUID
                    
                    $actionName = switch ($actualAction) {
                        0 { "Disabled" }
                        1 { "Block" }
                        2 { "Audit" }
                        6 { "Warn" }
                        default { "Unknown($actualAction)" }
                    }
                    $expectedName = switch ($rule.Action) {
                        0 { "Disabled" }
                        1 { "Block" }
                        2 { "Audit" }
                        6 { "Warn" }
                        default { "Unknown($($rule.Action))" }
                    }
                    
                    Write-Log -Level WARNING -Message "Rule '$($rule.Name)' has action $actionName, expected $expectedName" -Module "ASR"
                }
            }
            else {
                $result.FailedCount++
                $result.Passed = $false
                $result.FailedRules += $rule.GUID
                Write-Log -Level WARNING -Message "Rule '$($rule.Name)' not found in Defender configuration" -Module "ASR"
            }
        }
        
        if ($result.Passed) {
            Write-Log -Level INFO -Message "ASR compliance check passed - all $($result.CheckedCount) rules verified" -Module "ASR"
        }
        else {
            Write-Log -Level WARNING -Message "ASR compliance check found $($result.FailedCount) issues out of $($result.CheckedCount) rules" -Module "ASR"
        }
    }
    catch {
        $result.Passed = $false
        $result.FailedCount = $ExpectedRules.Count
        Write-Log -Level ERROR -Message "Compliance check failed: $($_.Exception.Message)" -Module "ASR"
    }
    
    return $result
}
