<#
.SYNOPSIS
    Load all 19 ASR rule definitions

.DESCRIPTION
    Loads ASR rules from JSON data file with all metadata

.OUTPUTS
    Array of ASR rule objects
#>

function Get-ASRRuleDefinitions {
    [CmdletBinding()]
    [OutputType([Array])]
    param()

    try {
        $configPath = Join-Path $PSScriptRoot "..\Config\ASR-Rules.json"

        if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
            throw "ASR rules configuration file not found: $configPath"
        }

        # Windows PowerShell 5.1 returns a top-level JSON array as Object[].
        # Wrapping the conversion itself in @() nests that array as one item.
        $rules = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $countsPath = Join-Path $PSScriptRoot '..\..\..\Config\SettingsCounts.json'
        $expectedCount = [int](Get-Content -LiteralPath $countsPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop).modules.ASR.rules
        if ($rules.Count -ne $expectedCount) {
            throw "ASR rule count mismatch: expected $expectedCount, found $($rules.Count)"
        }
        $seen = [System.Collections.Generic.HashSet[Guid]]::new()
        foreach ($rule in $rules) {
            $parsedGuid = [Guid]::Empty
            if ([string]::IsNullOrWhiteSpace([string]$rule.Name) -or
                -not [Guid]::TryParse([string]$rule.GUID, [ref]$parsedGuid) -or
                -not $seen.Add($parsedGuid) -or
                [int]$rule.Action -notin @(0, 1, 2, 6) -or
                [string]$rule.BaselineStatus -notin @('Block', 'Audit', 'Missing')) {
                throw "ASR configuration contains an invalid or duplicate rule: $($rule.GUID)"
            }
            $rule.GUID = $parsedGuid.ToString('D').ToLowerInvariant()
            $rule.Action = [int]$rule.Action
            if (-not ($rule.PSObject.Properties.Name -contains 'UserConfigurable')) {
                $rule | Add-Member -NotePropertyName UserConfigurable -NotePropertyValue $false
            }
            if ($rule.UserConfigurable -isnot [bool]) {
                throw "ASR UserConfigurable must be Boolean: $($rule.GUID)"
            }
            if (-not ($rule.PSObject.Properties.Name -contains 'WindowsClientApplicable')) {
                $rule | Add-Member -NotePropertyName WindowsClientApplicable -NotePropertyValue $true
            }
            if ($rule.WindowsClientApplicable -isnot [bool]) {
                throw "ASR WindowsClientApplicable must be Boolean: $($rule.GUID)"
            }
            if (-not ($rule.PSObject.Properties.Name -contains 'NotApplicableReason')) {
                $rule | Add-Member -NotePropertyName NotApplicableReason -NotePropertyValue $null
            }
            if (-not [bool]$rule.WindowsClientApplicable -and
                [string]::IsNullOrWhiteSpace([string]$rule.NotApplicableReason)) {
                throw "ASR Windows-client NotApplicable reason is missing: $($rule.GUID)"
            }
        }

        Write-Log -Level INFO -Message "Loaded $($rules.Count) ASR rule definitions" -Module "ASR"

        return $rules
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to load ASR rules: $($_.Exception.Message)" -Module "ASR"
        throw
    }
}
