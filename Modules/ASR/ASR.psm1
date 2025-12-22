<#
.SYNOPSIS
    Attack Surface Reduction (ASR) Module
    
.DESCRIPTION
    Enables all 19 Microsoft Defender ASR rules in Block mode for comprehensive protection.
    
    Hybrid implementation:
    - Registry for backup/verification
    - Set-MpPreference for clean application
    
.NOTES
    Author: NexusOne23
    Version: 2.2.2
    Requires: PowerShell 5.1+, Administrator privileges, Windows Defender
#>

# Get the module root path
$ModuleRoot = $PSScriptRoot

# Dot source all Private functions
$PrivatePath = Join-Path $ModuleRoot "Private"
if (Test-Path $PrivatePath) {
    Get-ChildItem -Path $PrivatePath -Filter "*.ps1" | ForEach-Object {
        try {
            . $_.FullName
        }
        catch {
            Write-Host "WARNING: Failed to import private function $($_.Name): $_" -ForegroundColor Yellow
        }
    }
}

# Dot source all Public functions
$PublicPath = Join-Path $ModuleRoot "Public"
if (Test-Path $PublicPath) {
    Get-ChildItem -Path $PublicPath -Filter "*.ps1" | ForEach-Object {
        try {
            . $_.FullName
        }
        catch {
            Write-Host "WARNING: Failed to import public function $($_.Name): $_" -ForegroundColor Yellow
        }
    }
}

# Export public functions + Test-ASRCompliance (needed for Invoke-ASRRules verification)
Export-ModuleMember -Function @('Invoke-ASRRules', 'Test-ASRCompliance')

# Alias for naming consistency (non-breaking change)
New-Alias -Name 'Invoke-ASR' -Value 'Invoke-ASRRules' -Force
Export-ModuleMember -Alias 'Invoke-ASR'
