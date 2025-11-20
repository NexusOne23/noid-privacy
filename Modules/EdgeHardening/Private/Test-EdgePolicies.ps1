<#
.SYNOPSIS
    Test Microsoft Edge security policies compliance
    
.DESCRIPTION
    Verifies that all Edge v139 Security Baseline policies are correctly applied.
    Returns detailed compliance status for each policy.
    
    NOTE: Supports optional policies that count as SUCCESS even if not applied:
    - GPO deletion markers (**delvals) - infrastructure, not a real policy
    - ExtensionInstallBlocklist - optional based on -AllowExtensions flag
    
.PARAMETER EdgePoliciesPath
    Path to EdgePolicies.json (default: module ParsedSettings folder)
    
.OUTPUTS
    PSCustomObject with compliance status and details
    
.NOTES
    Checks registry values against expected baseline values
    Treats optional policies as SUCCESS if not set (user choice)
#>

function Test-EdgePolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$EdgePoliciesPath
    )
    
    # Default path if not specified
    if (-not $EdgePoliciesPath) {
        $modulePath = Split-Path -Parent $PSScriptRoot
        $EdgePoliciesPath = Join-Path $modulePath "Config\EdgePolicies.json"
    }
    
    if (-not (Test-Path $EdgePoliciesPath)) {
        return [PSCustomObject]@{
            Compliant = $false
            Message   = "EdgePolicies.json not found: $EdgePoliciesPath"
            Details   = @()
        }
    }
    
    try {
        $edgePolicies = Get-Content -Path $EdgePoliciesPath -Raw | ConvertFrom-Json
        
        $compliantCount = 0
        $nonCompliantCount = 0
        $details = @()
        
        foreach ($policy in $edgePolicies) {
            # Determine if this policy is optional
            $isOptional = $false
            
            # GPO deletion markers are optional (infrastructure, not real policies)
            if ($policy.ValueName -like "**delvals.*") {
                $isOptional = $true
            }
            
            # ExtensionInstallBlocklist is optional (user may choose -AllowExtensions)
            if ($policy.ValueName -eq "1" -and $policy.KeyName -like "*ExtensionInstallBlocklist*") {
                $isOptional = $true
            }
            
            # Parse key path
            $keyPath = $policy.KeyName -replace '^\[', '' -replace '\]$', ''
            $fullPath = "HKLM:\$keyPath"
            
            $policyCompliant = $false
            $actualValue = $null
            $status = "Not Set"
            
            try {
                if (Test-Path $fullPath) {
                    $regValue = Get-ItemProperty -Path $fullPath -Name $policy.ValueName -ErrorAction Stop
                    $actualValue = $regValue.$($policy.ValueName)
                    
                    # Compare values
                    if ($policy.Type -eq "REG_DWORD") {
                        $policyCompliant = ([int]$actualValue -eq [int]$policy.Data)
                    }
                    elseif ($policy.Type -eq "REG_MULTI_SZ") {
                        # Compare arrays
                        $expected = $policy.Data
                        $policyCompliant = ($null -eq (Compare-Object $actualValue $expected))
                    }
                    else {
                        $policyCompliant = ($actualValue -eq $policy.Data)
                    }
                    
                    $status = if ($policyCompliant) { "Compliant" } else { "Non-Compliant (Wrong Value)" }
                }
                else {
                    # Key doesn't exist
                    if ($isOptional) {
                        # Optional policy not set = SUCCESS (user choice)
                        $policyCompliant = $true
                        $status = "Compliant (Optional - Not Set)"
                    }
                    else {
                        $status = "Non-Compliant (Key Not Found)"
                    }
                }
            }
            catch {
                # Value doesn't exist
                if ($isOptional) {
                    # Optional policy not set = SUCCESS (user choice)
                    $policyCompliant = $true
                    $status = "Compliant (Optional - Not Set)"
                }
                else {
                    $status = "Non-Compliant (Value Not Found)"
                }
            }
            
            if ($policyCompliant) {
                $compliantCount++
            }
            else {
                $nonCompliantCount++
            }
            
            $details += [PSCustomObject]@{
                Policy    = $policy.ValueName
                Expected  = $policy.Data
                Actual    = $actualValue
                Status    = $status
                Compliant = $policyCompliant
                Optional  = $isOptional
            }
        }
        
        # Total policies = all 20 entries in JSON
        $totalPolicies = $compliantCount + $nonCompliantCount
        $compliancePercentage = if ($totalPolicies -gt 0) { 
            [math]::Round(($compliantCount / $totalPolicies) * 100, 1) 
        }
        else { 
            0 
        }
        
        return [PSCustomObject]@{
            Compliant            = ($nonCompliantCount -eq 0)
            Message              = "Edge Security: $compliantCount/$totalPolicies policies compliant ($compliancePercentage%)"
            CompliantCount       = $compliantCount
            NonCompliantCount    = $nonCompliantCount
            CompliancePercentage = $compliancePercentage
            Details              = $details
        }
    }
    catch {
        return [PSCustomObject]@{
            Compliant = $false
            Message   = "Edge policy compliance test failed: $($_.Exception.Message)"
            Details   = @()
        }
    }
}
