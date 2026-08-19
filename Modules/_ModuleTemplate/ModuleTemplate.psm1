<#
.SYNOPSIS
    Module Template for NoID Privacy Framework

.DESCRIPTION
    Non-mutating scaffold for creating new hardening modules. It refuses live
    execution until the copied module implements the framework's complete,
    sealed BACKUP/APPLY/VERIFY/RESTORE contract.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+

.EXAMPLE
    Import-Module .\ModuleTemplate.psm1
    Invoke-ModuleTemplate -DryRun
#>

# Module-level variables
$script:ModuleName = "ModuleTemplate"
$script:ModuleVersion = "2.2.5"

# Load required Public/Private functions. A copied scaffold must fail import if
# either directory is missing or any required file cannot be loaded.
$publicPath = Join-Path $PSScriptRoot 'Public'
$privatePath = Join-Path $PSScriptRoot 'Private'
foreach ($requiredPath in @($publicPath, $privatePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Container)) {
        throw "Required module directory is missing: $requiredPath"
    }
}
$publicFunctions = @(Get-ChildItem -LiteralPath $publicPath -Filter '*.ps1' -File -ErrorAction Stop)
$privateFunctions = @(Get-ChildItem -LiteralPath $privatePath -Filter '*.ps1' -File -ErrorAction Stop)
if ($publicFunctions.Count -eq 0) { throw 'Module template has no public function files' }
if ($privateFunctions.Count -eq 0) { throw 'Module template has no private function files' }

foreach ($function in $publicFunctions) {
    try {
        . $function.FullName
        Write-Verbose "Loaded public function: $($function.BaseName)"
    }
    catch {
        throw "Failed to load public function '$($function.FullName)': $($_.Exception.Message)"
    }
}

foreach ($function in $privateFunctions) {
    try {
        . $function.FullName
        Write-Verbose "Loaded private function: $($function.BaseName)"
    }
    catch {
        throw "Failed to load private function '$($function.FullName)': $($_.Exception.Message)"
    }
}

# Export only public functions
$functionNames = @($publicFunctions | ForEach-Object { $_.BaseName })
Export-ModuleMember -Function $functionNames
