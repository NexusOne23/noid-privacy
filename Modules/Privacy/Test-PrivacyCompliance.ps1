function Test-PrivacyCompliance {
    <#
    .SYNOPSIS
        Verify privacy settings compliance
    
    .DESCRIPTION
        Checks if all privacy settings were applied correctly according to the selected mode
    
    .PARAMETER Config
        Configuration object to verify against
    
    .EXAMPLE
        Test-PrivacyCompliance -Config $config
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )
    
    try {
        Write-Log -Level INFO -Message "Verifying privacy settings compliance..." -Module "Privacy"
        
        $compliant = $true
        $totalChecks = 0
        $passed = 0
        $failed = @()
        
        # Verify registry settings
        $categories = @("DataCollection", "Personalization", "SearchAndCloud", "InputAndSync", "LocationAndAppPrivacy")
        
        foreach ($category in $categories) {
            if ($Config.PSObject.Properties.Name -contains $category) {
                foreach ($keyPath in $Config.$category.PSObject.Properties.Name) {
                    foreach ($valueName in $Config.$category.$keyPath.PSObject.Properties.Name) {
                        $totalChecks++
                        $expected = $Config.$category.$keyPath.$valueName.Value
                        
                        try {
                            $actual = (Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction Stop).$valueName
                            if ($actual -eq $expected) {
                                $passed++
                            } else {
                                $failMsg = "MISMATCH: $keyPath\$valueName = $actual (expected: $expected)"
                                Write-Log -Level WARNING -Message $failMsg -Module "Privacy"
                                $failed += $failMsg
                                $compliant = $false
                            }
                        } catch {
                            $failMsg = "NOT FOUND: $keyPath\$valueName (expected: $expected)"
                            Write-Log -Level WARNING -Message $failMsg -Module "Privacy"
                            $failed += $failMsg
                            $compliant = $false
                        }
                    }
                }
            }
        }
        
        # Verify services
        if ($Config.Services.Count -gt 0) {
            foreach ($svc in $Config.Services) {
                $totalChecks++
                $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
                if ($service -and $service.StartType -eq "Disabled") {
                    $passed++
                } else {
                    $failMsg = "SERVICE: $($svc.Name) not disabled (current: $($service.StartType))"
                    Write-Log -Level WARNING -Message $failMsg -Module "Privacy"
                    $failed += $failMsg
                    $compliant = $false
                }
            }
        }
        
        $percentage = [math]::Round(($passed / $totalChecks) * 100, 1)
        Write-Log -Level INFO -Message "Compliance check: $passed/$totalChecks checks passed ($percentage%)" -Module "Privacy"
        
        if ($compliant) {
            Write-Log -Level SUCCESS -Message "Privacy settings are fully compliant" -Module "Privacy"
        } else {
            Write-Log -Level WARNING -Message "Some privacy settings are not compliant - $($failed.Count) issue(s) found" -Module "Privacy"
            # Log each failed check individually
            foreach ($fail in $failed) {
                Write-Log -Level WARNING -Message "  - $fail" -Module "Privacy"
            }
        }
        
        # Return detailed result object instead of just boolean
        return [PSCustomObject]@{
            Compliant = $compliant
            TotalChecks = $totalChecks
            Passed = $passed
            Failed = ($totalChecks - $passed)
            Percentage = $percentage
            FailedChecks = $failed
        }
        
    } catch {
        Write-Log -Level ERROR -Message "Compliance verification failed: $_" -Module "Privacy"
        return $false
    }
}
