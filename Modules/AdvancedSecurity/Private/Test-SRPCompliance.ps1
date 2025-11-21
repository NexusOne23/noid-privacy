function Test-SRPCompliance {
    <#
    .SYNOPSIS
        Verifies Software Restriction Policies (SRP) configuration for CVE-2025-9491
        
    .DESCRIPTION
        Tests whether SRP rules are correctly configured to block .lnk execution from Temp/Downloads.
        Returns compliance status for CVE-2025-9491 mitigation.
        
    .EXAMPLE
        Test-SRPCompliance
        
    .OUTPUTS
        PSCustomObject with compliance results
    #>
    
    [CmdletBinding()]
    param()
    
    try {
        $configPath = Join-Path $PSScriptRoot "..\Config\SRP-Rules.json"
        
        if (-not (Test-Path $configPath)) {
            return [PSCustomObject]@{
                Feature = "SRP Configuration"
                Status = "Not Configured"
                Compliant = $false
                Details = "SRP-Rules.json not found"
            }
        }
        
        $config = Get-Content $configPath -Raw | ConvertFrom-Json
        $policyRoot = $config.RegistryPaths.PolicyRoot
        
        # Check if SRP policy exists
        if (-not (Test-Path $policyRoot)) {
            Write-Log -Level WARNING -Message "SRP Check Failed: Policy root not found ($policyRoot)" -Module "AdvancedSecurity"
            return [PSCustomObject]@{
                Feature = "SRP CVE-2025-9491"
                Status = "Not Configured"
                Compliant = $false
                Details = "SRP policy root not found"
            }
        }
        
        # Check Default Level
        $defaultLevel = Get-ItemProperty -Path $policyRoot -Name "DefaultLevel" -ErrorAction SilentlyContinue
        if ($null -eq $defaultLevel -or $defaultLevel.DefaultLevel -ne 262144) {
            Write-Log -Level WARNING -Message "SRP Check Failed: DefaultLevel is not Unrestricted (262144)" -Module "AdvancedSecurity"
            return [PSCustomObject]@{
                Feature = "SRP CVE-2025-9491"
                Status = "Misconfigured"
                Compliant = $false
                Details = "Default level not set to Unrestricted (262144)"
            }
        }
        
        # Check Path Rules
        $pathRulesRoot = $config.RegistryPaths.PathRules
        
        if (-not (Test-Path $pathRulesRoot)) {
            Write-Log -Level WARNING -Message "SRP Check Failed: PathRules root not found ($pathRulesRoot)" -Module "AdvancedSecurity"
            return [PSCustomObject]@{
                Feature = "SRP CVE-2025-9491"
                Status = "Incomplete"
                Compliant = $false
                Details = "Path rules not configured"
            }
        }
        
        # Count configured rules
        $configuredRules = Get-ChildItem -Path $pathRulesRoot -ErrorAction SilentlyContinue
        $ruleCount = if ($configuredRules) { $configuredRules.Count } else { 0 }
        
        # Check for Windows 11 bug
        $bugFixPath = $config.RegistryPaths.Win11BugFix
        $hasBuggyKeys = $false
        
        if (Test-Path $bugFixPath) {
            foreach ($keyName in $config.Windows11BugFix.KeysToRemove) {
                $keyExists = Get-ItemProperty -Path $bugFixPath -Name $keyName -ErrorAction SilentlyContinue
                if ($null -ne $keyExists) {
                    $hasBuggyKeys = $true
                    break
                }
            }
        }
        
        if ($hasBuggyKeys) {
            Write-Log -Level WARNING -Message "SRP Check Failed: Windows 11 buggy keys present (RuleCount/LastWriteTime)" -Module "AdvancedSecurity"
            return [PSCustomObject]@{
                Feature = "SRP CVE-2025-9491"
                Status = "Windows 11 Bug Detected"
                Compliant = $false
                Details = "Buggy registry keys present (RuleCount/LastWriteTime) - SRP may not work"
            }
        }
        
        # All checks passed
        if ($ruleCount -ge 2) {
            return [PSCustomObject]@{
                Feature = "SRP CVE-2025-9491"
                Status = "Protected"
                Compliant = $true
                Details = "$ruleCount path rules configured, Windows 11 bug fix applied"
            }
        }
        else {
            Write-Log -Level WARNING -Message "SRP Check Failed: Insufficient rules found ($ruleCount, expected 2+)" -Module "AdvancedSecurity"
            return [PSCustomObject]@{
                Feature = "SRP CVE-2025-9491"
                Status = "Incomplete"
                Compliant = $false
                Details = "Only $ruleCount path rules found (expected 2+)"
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            Feature = "SRP CVE-2025-9491"
            Status = "Error"
            Compliant = $false
            Details = "Test failed: $_"
        }
    }
}
