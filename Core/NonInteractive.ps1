#Requires -Version 5.1

<#
.SYNOPSIS
    NonInteractive mode helper functions for NoID Privacy GUI integration

.DESCRIPTION
    Provides helper functions to check if running in NonInteractive mode (GUI)
    and to retrieve config values instead of prompting users.

    Used by all modules to support both CLI (interactive) and GUI (non-interactive) modes.

.NOTES
    Author: NexusOne23
    Version: 2.2.5

    Usage in modules:
    1. Call Test-NonInteractiveMode to check if prompts should be skipped
    2. Use Get-NonInteractiveValue -Required for every decision-bearing value
#>

<#
.SYNOPSIS
    Test if running in NonInteractive mode (GUI)

.DESCRIPTION
    Checks if the global config has nonInteractive=true set.
    When true, all Read-Host prompts should be skipped and config values used instead.

.OUTPUTS
    [bool] True if nonInteractive mode is enabled

.EXAMPLE
    if (Test-NonInteractiveMode) {
        # Use the exact validated config value or fail closed
        $choice = Get-NonInteractiveValue -Module "DNS" -Key "provider" -Required
    } else {
        # Interactive prompt
        $choice = Read-Host "Select provider"
    }
#>
function Test-NonInteractiveMode {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # The environment flag is transport metadata, not authority. It may only
    # confirm a validated configuration that independently requests
    # non-interactive execution; a stale user/machine environment variable
    # must never suppress prompts or manufacture decision defaults.
    if ($env:NOIDPRIVACY_NONINTERACTIVE -eq "true") {
        if (-not $script:Config -or -not $script:Config.options -or
            $script:Config.options.nonInteractive -ne $true) {
            throw 'NOIDPRIVACY_NONINTERACTIVE requires a validated configuration with options.nonInteractive=true'
        }
        return $true
    }

    # Check global config
    if ($script:Config -and $script:Config.options) {
        if ($script:Config.options.nonInteractive -eq $true) {
            return $true
        }
    }

    return $false
}

# Show the environment-mode banner only once across repeated dot-sourcing. The
# actual mode is always computed by Test-NonInteractiveMode, never cached here.
if ($env:NOIDPRIVACY_NONINTERACTIVE -eq "true") {
    $niVar = Get-Variable -Name NoIDNonInteractiveBannerShown -Scope Global -ErrorAction SilentlyContinue
    $niValue = if ($niVar) { [bool]$niVar.Value } else { $false }

    if (-not $niValue) {
        Write-Host "[GUI] Non-Interactive mode detected (environment variable)" -ForegroundColor Cyan
    }

    $global:NoIDNonInteractiveBannerShown = $true
}

<#
.SYNOPSIS
    Get a value from config for NonInteractive mode

.DESCRIPTION
    Retrieves a module-specific config value when running in NonInteractive mode.
    Decision-bearing callers use -Required; defaults are reserved for
    non-mutating display/compatibility metadata.

.PARAMETER Module
    The module name (SecurityBaseline, ASR, DNS, Privacy, AntiAI, EdgeHardening, AdvancedSecurity)

.PARAMETER Key
    The config key to retrieve

.PARAMETER Default
    Default value if key not found

.OUTPUTS
    The config value or default

.EXAMPLE
    $provider = Get-NonInteractiveValue -Module "DNS" -Key "provider" -Required
#>
function Get-NonInteractiveValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Module,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $false)]
        $Default = $null,

        # Decision-bearing non-interactive paths use this switch. Missing or
        # unreadable configuration then aborts instead of substituting an
        # unrelated default.
        [Parameter(Mandatory = $false)]
        [switch]$Required
    )

    $requiredValueMissing = $false
    try {
        # Strict-mode-safe property access:
        # `$obj.$Key` on a PSCustomObject throws PropertyNotFoundException under
        # Set-StrictMode -Version Latest (set by NoIDPrivacy.ps1). Check via
        # PSObject.Properties.Name -contains first, then access by name.
        $hasConfig = $null -ne $script:Config
        $hasModules = $hasConfig -and ($null -ne $script:Config.modules) -and `
            ($script:Config.modules.PSObject.Properties.Name -contains $Module)

        if ($hasModules) {
            $moduleConfig = $script:Config.modules.$Module
            if ($null -ne $moduleConfig -and $moduleConfig.PSObject.Properties.Name -contains $Key) {
                $value = $moduleConfig.$Key
                Write-Log -Level DEBUG -Message "[NonInteractive] $Module.$Key = $value (from config)" -Module "Core"
                return $value
            }
        }
        $requiredValueMissing = [bool]$Required
    }
    catch {
        Write-Log -Level WARNING -Message "[NonInteractive] Failed to read $Module.$Key from config: $_" -Module "Core"
        if ($Required) {
            throw "Required non-interactive decision could not be read: $Module.$Key. $($_.Exception.Message)"
        }
    }

    # Missing authority is a contract violation, not a read failure. Keep this
    # guard outside the read catch so logs and callers can distinguish absent
    # user intent from corrupt/unreadable configuration.
    if ($requiredValueMissing) {
        throw "Required non-interactive decision is missing: $Module.$Key"
    }

    Write-Log -Level DEBUG -Message "[NonInteractive] $Module.$Key = $Default (default)" -Module "Core"
    return $Default
}

<#
.SYNOPSIS
    Log a NonInteractive mode decision

.DESCRIPTION
    Helper to log when a decision was made automatically in NonInteractive mode.
    Outputs to both console and log file for transparency.

.PARAMETER Module
    The module name

.PARAMETER Decision
    Description of the decision made

.PARAMETER Value
    The value that was used
#>
function Write-NonInteractiveDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Module,

        [Parameter(Mandatory = $true)]
        [string]$Decision,

        [Parameter(Mandatory = $false)]
        $Value = $null
    )

    $message = if ($null -ne $Value) {
        "[GUI] $Decision : $Value"
    }
    else {
        "[GUI] $Decision"
    }

    Write-Host $message -ForegroundColor Cyan
    Write-Log -Level INFO -Message $message -Module $Module
}

# Functions are available globally when dot-sourced by Framework.ps1
# No Export-ModuleMember needed (script is not loaded as a module)
