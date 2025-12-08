<#
.SYNOPSIS
    Module Template for NoID Privacy Framework
    
.DESCRIPTION
    This is a template for creating new hardening modules.
    Each module should implement the BACKUP/APPLY/VERIFY/RESTORE pattern
    and follow PowerShell 5.1 best practices.
    
.NOTES
    Author: NexusOne23
    Version: 1.0.0
    Requires: PowerShell 5.1+
    
.EXAMPLE
    Import-Module .\ModuleTemplate.psm1
    Invoke-ModuleTemplate -DryRun
#>

# Module-level variables
$script:ModuleName = "ModuleTemplate"
$script:ModuleVersion = "1.0.0"

# Load Public functions
$publicFunctions = Get-ChildItem -Path "$PSScriptRoot\Public" -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue

foreach ($function in $publicFunctions) {
    try {
        . $function.FullName
        Write-Verbose "Loaded public function: $($function.BaseName)"
    }
    catch {
        Write-Error "Failed to load function $($function.FullName): $_"
    }
}

# Load Private functions
$privateFunctions = Get-ChildItem -Path "$PSScriptRoot\Private" -Filter *.ps1 -Recurse -ErrorAction SilentlyContinue

foreach ($function in $privateFunctions) {
    try {
        . $function.FullName
        Write-Verbose "Loaded private function: $($function.BaseName)"
    }
    catch {
        Write-Error "Failed to load function $($function.FullName): $_"
    }
}

# Export only public functions
if ($publicFunctions) {
    $functionNames = $publicFunctions | ForEach-Object { $_.BaseName }
    Export-ModuleMember -Function $functionNames
}
