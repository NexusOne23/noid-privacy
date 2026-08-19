#Requires -Version 5.1

# Shared BeforeAll bootstrap for Tests/Integration/*.
#
# Dot-source this from each Integration Describe's BeforeAll. It:
#   1. Computes repo paths in a cross-platform way (Join-Path, no backslash literals).
#   2. Loads the Core chain (Logger.ps1, Config.ps1, Validator.ps1, Rollback.ps1,
#      NonInteractive.ps1) plus Utils/Hardware.ps1, Utils/Compatibility.ps1 and
#      Utils/Dependencies.ps1 -- all 8 entries of $supportFiles are required for
#      function promotion; none is an optional extra.
#   3. Promotes Write-Log + co. into the GLOBAL function table so Import-Module-loaded
#      modules can resolve them via scope fallback (production does the equivalent by
#      dot-sourcing everything into one shared session).
#
# Usage from inside a BeforeAll:
#   . (Join-Path $PSScriptRoot '_Common.ps1')
#   Initialize-IntegrationTestEnvironment
#   $script:ModulePath = Get-IntegrationModulePath -Module 'AdvancedSecurity'
#   $script:ManifestPath = Join-Path $script:ModulePath 'AdvancedSecurity.psd1'

function Get-IntegrationRepoRoot {
    Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
}

function Get-IntegrationModulePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Module
    )
    Join-Path (Get-IntegrationRepoRoot) 'Modules' | Join-Path -ChildPath $Module
}

function Initialize-IntegrationTestEnvironment {
    [CmdletBinding()]
    param()

    $repoRoot = Get-IntegrationRepoRoot
    $corePath = Join-Path $repoRoot 'Core'

    $supportFiles = @(
        Join-Path $corePath 'Logger.ps1'
        Join-Path $corePath 'Config.ps1'
        Join-Path $corePath 'Validator.ps1'
        Join-Path $corePath 'Rollback.ps1'
        Join-Path $corePath 'NonInteractive.ps1'
        Join-Path $repoRoot 'Utils\Hardware.ps1'
        Join-Path $repoRoot 'Utils\Compatibility.ps1'
        Join-Path $repoRoot 'Utils\Dependencies.ps1'
    )
    $supportFunctions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in $supportFiles) {
        if (Test-Path $p) {
            . $p
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $p,
                [ref]$tokens,
                [ref]$parseErrors
            )
            if (@($parseErrors).Count -gt 0) {
                throw "Integration support file does not parse: $p"
            }
            foreach ($functionAst in $ast.FindAll({
                        param($node)
                        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
                    }, $true)) {
                $null = $supportFunctions.Add([string]$functionAst.Name)
            }
        }
    }

    # Imported modules have isolated session state and can only fall back to the
    # global command table. Promote the exact functions supplied by the same
    # Core/Utils files that Framework.ps1 dot-sources in production.
    foreach ($fn in $supportFunctions) {
        if (Test-Path "function:$fn") {
            Set-Item -Path "function:global:$fn" -Value (Get-Item "function:$fn").ScriptBlock
        }
    }

    if (Get-Command Initialize-Logger -ErrorAction SilentlyContinue) {
        Initialize-Logger -EnableConsole $false
    }

    # Core's non-interactive transport flag is deliberately not authority on
    # its own. Integration entry points therefore use the same validated
    # repository configuration contract as production before a helper may
    # temporarily enable options.nonInteractive.
    Initialize-Config -ConfigPath (Join-Path $repoRoot 'config.json') -CreateDefault $false
}

function Invoke-IntegrationNonInteractive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )

    $previous = [Environment]::GetEnvironmentVariable('NOIDPRIVACY_NONINTERACTIVE', 'Process')
    $previousConfigChoice = $null
    $hasConfigChoice = ($null -ne $script:Config -and $null -ne $script:Config.options -and
        $script:Config.options.PSObject.Properties.Name -contains 'nonInteractive')
    try {
        if (-not $hasConfigChoice) {
            throw 'Integration non-interactive helper requires an initialized validated config'
        }
        $previousConfigChoice = [bool]$script:Config.options.nonInteractive
        $script:Config.options.nonInteractive = $true
        $env:NOIDPRIVACY_NONINTERACTIVE = 'true'
        & $ScriptBlock
    }
    finally {
        if ($null -eq $previous) {
            Remove-Item Env:NOIDPRIVACY_NONINTERACTIVE -ErrorAction SilentlyContinue
        }
        else {
            $env:NOIDPRIVACY_NONINTERACTIVE = $previous
        }
        if ($hasConfigChoice) {
            $script:Config.options.nonInteractive = $previousConfigChoice
        }
    }
}

function Assert-SingleStructuredModuleResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Result,

        [string]$Context = 'module invocation'
    )

    @($Result).Count | Should -Be 1 -Because "$Context must emit exactly one structured result"
    $item = @($Result)[0]
    $item | Should -Not -BeNullOrEmpty
    $item.PSObject.Properties.Name | Should -Contain 'Success'
    $item.Success | Should -BeOfType ([bool])
    if ([bool]$item.Success -and $item.PSObject.Properties['Errors']) {
        @($item.Errors).Count | Should -Be 0 -Because "$Context cannot be successful with recorded errors"
    }
}
