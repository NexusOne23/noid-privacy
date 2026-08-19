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
        if ($ExpectedRules.Count -eq 0) { throw 'No expected ASR rules were supplied' }
        $expectedMap = @{}
        foreach ($rule in $ExpectedRules) {
            $parsedExpectedId = [Guid]::Empty
            if (-not [Guid]::TryParse([string]$rule.GUID, [ref]$parsedExpectedId) -or
                [int]$rule.Action -notin @(0, 1, 2, 6)) {
                throw "Invalid expected ASR rule: $($rule.GUID)"
            }
            $expectedId = $parsedExpectedId.ToString('D').ToLowerInvariant()
            if ($expectedMap.ContainsKey($expectedId)) { throw "Duplicate expected ASR rule: $expectedId" }
            $expectedMap[$expectedId] = $rule
        }

        $configuredRules = (ConvertFrom-ASRPreference -Preference (
                Get-MpPreference -ErrorAction Stop
            )).Map
        if ($configuredRules.Count -eq 0) {
            $result.Passed = $false
            $result.FailedCount = $ExpectedRules.Count
            Write-Log -Level WARNING -Message "No ASR rules found in Defender configuration" -Module "ASR"
            return $result
        }

        # Verify each expected rule
        foreach ($rule in $ExpectedRules) {
            $result.CheckedCount++
            $ruleId = ([Guid]([string]$rule.GUID)).ToString('D').ToLowerInvariant()
            if ($configuredRules.ContainsKey($ruleId)) {
                $actualAction = $configuredRules[$ruleId]

                $rulePassed = ([int]$actualAction -eq [int]$rule.Action)

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
