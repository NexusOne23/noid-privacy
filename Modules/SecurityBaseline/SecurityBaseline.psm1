<#
.SYNOPSIS
    Microsoft Security Baseline for Windows 11 25H2
    
.DESCRIPTION
    Implements all 425 Microsoft Security Baseline settings:
    - 330 Computer Registry policies
    - 5 User Registry policies
    - 67 Security Template settings
    - 23 Advanced Audit Policies
    
    Auto-detects domain membership and applies appropriate adjustments.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.2
    Requires: PowerShell 5.1+, Administrator privileges
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

# Export only public functions
Export-ModuleMember -Function Invoke-SecurityBaseline, Restore-SecurityBaseline, Restore-RegistryPolicies
