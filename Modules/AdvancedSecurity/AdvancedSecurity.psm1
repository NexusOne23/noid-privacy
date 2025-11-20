# AdvancedSecurity Module Loader
# Version: 2.1.0
# Description: Advanced Security Hardening - Beyond Microsoft Security Baseline

# Get module path
$ModulePath = $PSScriptRoot

# Load Private functions
$PrivateFunctions = @(
    'Enable-RdpNLA',
    'Set-WDigestProtection',
    'Disable-AdminShares',
    'Disable-RiskyPorts',
    'Stop-RiskyServices',
    'Disable-WPAD',
    'Disable-LegacyTLS',
    'Remove-PowerShellV2',
    'Block-FingerProtocol',
    'Set-SRPRules',
    'Set-WindowsUpdate',
    'Test-RdpSecurity',
    'Test-WDigest',
    'Test-RiskyPorts',
    'Test-RiskyServices',
    'Test-AdminShares',
    'Test-SRPCompliance',
    'Test-WindowsUpdate',
    'Backup-AdvancedSecuritySettings'
)

foreach ($function in $PrivateFunctions) {
    $functionPath = Join-Path $ModulePath "Private\$function.ps1"
    if (Test-Path $functionPath) {
        . $functionPath
    }
}

# Load Public functions
$PublicFunctions = @(
    'Invoke-AdvancedSecurity',
    'Test-AdvancedSecurity',
    'Restore-AdvancedSecuritySettings'
)

foreach ($function in $PublicFunctions) {
    $functionPath = Join-Path $ModulePath "Public\$function.ps1"
    if (Test-Path $functionPath) {
        . $functionPath
    }
}

# Export only Public functions
Export-ModuleMember -Function $PublicFunctions
