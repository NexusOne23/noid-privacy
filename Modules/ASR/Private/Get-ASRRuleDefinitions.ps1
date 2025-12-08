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
        
        if (-not (Test-Path $configPath)) {
            throw "ASR rules configuration file not found: $configPath"
        }
        
        $rules = Get-Content $configPath -Raw | ConvertFrom-Json
        
        Write-Log -Level INFO -Message "Loaded $($rules.Count) ASR rule definitions" -Module "ASR"
        
        return $rules
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to load ASR rules: $($_.Exception.Message)" -Module "ASR"
        throw
    }
}
