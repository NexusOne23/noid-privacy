# AdvancedSecurity Module Loader
# Description: Advanced Security Hardening - Beyond Microsoft Security Baseline

# Module-level variables
$script:ModuleName = "AdvancedSecurity"
$script:ModuleRoot = $PSScriptRoot

# Discover Private + Public functions dynamically (no hardcoded array)
$privatePath = Join-Path $PSScriptRoot 'Private'
$publicPath = Join-Path $PSScriptRoot 'Public'
if (-not (Test-Path -LiteralPath $privatePath -PathType Container)) { throw "Required AdvancedSecurity Private directory is missing: $privatePath" }
if (-not (Test-Path -LiteralPath $publicPath -PathType Container)) { throw "Required AdvancedSecurity Public directory is missing: $publicPath" }
$Private = @(Get-ChildItem -LiteralPath $privatePath -Filter "*.ps1" -File -ErrorAction Stop)
$Public  = @(Get-ChildItem -LiteralPath $publicPath -Filter "*.ps1" -File -ErrorAction Stop)

# Dot-source all functions
foreach ($import in @($Private + $Public)) {
    try {
        . $import.FullName
    }
    catch {
        throw "Failed to import required AdvancedSecurity file '$($import.FullName)': $($_.Exception.Message)"
    }
}

# Export Public functions
Export-ModuleMember -Function $Public.BaseName
