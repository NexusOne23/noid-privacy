<#
.SYNOPSIS
    Test Microsoft Edge security baseline compliance
    
.DESCRIPTION
    Public wrapper for Test-EdgePolicies.
    Verifies all Edge v139+ Security Baseline policies are correctly applied.
    Returns user-friendly compliance report.
    
.PARAMETER Detailed
    Show detailed policy-by-policy results
    
.EXAMPLE
    Test-EdgeHardening
    Run compliance check with summary
    
.EXAMPLE
    Test-EdgeHardening -Detailed
    Show detailed policy-by-policy compliance status
    
.OUTPUTS
    PSCustomObject with compliance status and details
    
.NOTES
    Author: NexusOne23
    Version: 2.2.3
    Can be run without Administrator privileges
#>

function Test-EdgeHardening {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Edge Security Compliance Test" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        # Run compliance test
        $testResult = Test-EdgePolicies
        
        # Display summary
        Write-Host "  Testing Microsoft Edge v139 Security Baseline..." -ForegroundColor White
        Write-Host ""
        
        if ($testResult.Compliant) {
            Write-Host "  Status: COMPLIANT" -ForegroundColor Green
            Write-Host "  $($testResult.Message)" -ForegroundColor Green
        }
        else {
            Write-Host "  Status: NON-COMPLIANT" -ForegroundColor Yellow
            Write-Host "  $($testResult.Message)" -ForegroundColor Yellow
        }
        
        Write-Host ""
        
        # Show details if requested
        if ($Detailed -and $testResult.Details) {
            Write-Host "  Policy Details:" -ForegroundColor White
            Write-Host "  " + ("-" * 70) -ForegroundColor Gray
            
            foreach ($detail in $testResult.Details) {
                $statusColor = if ($detail.Compliant) { "Green" } else { "Yellow" }
                $statusSymbol = if ($detail.Compliant) { "[X]" } else { "[ ]" }
                
                Write-Host "  $statusSymbol " -ForegroundColor $statusColor -NoNewline
                Write-Host "$($detail.Policy)" -ForegroundColor White
                
                if (-not $detail.Compliant) {
                    Write-Host "      Expected: $($detail.Expected)" -ForegroundColor Gray
                    Write-Host "      Actual:   $($detail.Actual)" -ForegroundColor Gray
                }
            }
            
            Write-Host ""
        }
        
        # Show summary statistics
        if ($testResult.PSObject.Properties.Name -contains 'CompliantCount') {
            Write-Host "  Summary:" -ForegroundColor White
            Write-Host "  - Compliant:     $($testResult.CompliantCount)" -ForegroundColor Green
            Write-Host "  - Non-Compliant: $($testResult.NonCompliantCount)" -ForegroundColor $(if ($testResult.NonCompliantCount -gt 0) { "Yellow" } else { "Green" })
            Write-Host "  - Compliance:    $($testResult.CompliancePercentage)%" -ForegroundColor White
            Write-Host ""
        }
        
        if (-not $testResult.Compliant) {
            Write-Host "  Recommendation: Run Invoke-EdgeHardening to apply baseline" -ForegroundColor Yellow
            Write-Host ""
        }
        
        return $testResult
    }
    catch {
        Write-Host "  ERROR: Compliance test failed" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        
        return [PSCustomObject]@{
            Compliant = $false
            Message   = "Test failed: $($_.Exception.Message)"
            Details   = @()
        }
    }
}
