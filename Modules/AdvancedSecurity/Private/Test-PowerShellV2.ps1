function Test-PowerShellV2 {
    <#
    .SYNOPSIS
        Test PowerShell v2 status
    
    .DESCRIPTION
        Verifies that the PowerShell v2 feature is disabled or not present.
    
    .OUTPUTS
        PSCustomObject with compliance details
    #>
    [CmdletBinding()]
    param()
    
    try {
        $result = [PSCustomObject]@{
            Feature = "PowerShell v2 (Downgrade Attack)"
            Status = "Unknown"
            Details = @()
            Compliant = $true
        }
        
        $psv2Feature = $null
        try {
            $psv2Feature = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -ErrorAction SilentlyContinue
        }
        catch {
            $psv2Feature = $null
        }
        
        if (-not $psv2Feature) {
            # Feature not present on OS - Secure by default
            $result.Status = "Secure (Not Present)"
            $result.Compliant = $true
            $result.Details += "Feature 'MicrosoftWindowsPowerShellV2Root' not found on this OS"
        }
        elseif ($psv2Feature.State -ne 'Enabled') {
            # Feature present but disabled - Secure
            $result.Status = "Secure (Disabled)"
            $result.Compliant = $true
            $result.Details += "Feature state: $($psv2Feature.State)"
        }
        else {
            # Feature Enabled - Insecure
            $result.Status = "Insecure (Enabled)"
            $result.Compliant = $false
            $result.Details += "PowerShell v2 is enabled (allows downgrade attacks)"
        }
        
        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test PowerShell v2: $_" -Module "AdvancedSecurity"
        return [PSCustomObject]@{
            Feature = "PowerShell v2"
            Status = "Error"
            Details = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
