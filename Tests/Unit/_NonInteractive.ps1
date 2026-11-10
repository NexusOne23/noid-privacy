#Requires -Version 5.1

# Shared non-interactive guard for Tests/Unit/*.
#
# The 'Interactive' tag on the module smoke tests marks tests that call a real
# module entry point against the live machine. It does not mean a human answers
# questions: a module entry point asks its decision questions through Read-Host
# whenever Test-NonInteractiveMode is false, so on a real interactive desktop
# those tests block forever waiting for input, and nothing in the repository
# excludes that tag. Running the suite from a service session hid this because
# Read-Host fails immediately when there is no console.
#
# Wrap every such call in Invoke-UnitNonInteractive. It sets both parts of the
# GUI contract: transport metadata plus the independently validated config
# decision. The module consumes exact config choices instead of prompting, and
# the helper restores both values afterwards.
#
# Usage from inside a BeforeAll:
#   . (Join-Path $PSScriptRoot '_NonInteractive.ps1')

function Invoke-UnitNonInteractive {
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
            throw 'Unit non-interactive helper requires an initialized validated config'
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
