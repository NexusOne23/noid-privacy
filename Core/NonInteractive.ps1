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
    Version: 2.2.1
    
    Usage in modules:
    1. Call Test-NonInteractiveMode to check if prompts should be skipped
    2. Use Get-NonInteractiveValue to get config values with defaults
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
        # Use config value
        $choice = Get-NonInteractiveValue -Module "DNS" -Key "provider" -Default "Quad9"
    } else {
        # Interactive prompt
        $choice = Read-Host "Select provider"
    }
#>
function Test-NonInteractiveMode {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    # Check environment variable FIRST (set by GUI before process starts)
    if ($env:NOIDPRIVACY_NONINTERACTIVE -eq "true") {
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

# Set global variable at load time if environment variable is set
# This allows modules to check $global:NonInteractiveMode directly
if ($env:NOIDPRIVACY_NONINTERACTIVE -eq "true") {
    # Only show banner once per session, even if this file is dot-sourced multiple times
    # Use Get-Variable to avoid strict-mode errors when the variable does not yet exist
    $niVar = Get-Variable -Name NonInteractiveMode -Scope Global -ErrorAction SilentlyContinue
    $niValue = if ($niVar) { [bool]$niVar.Value } else { $false }
    
    if (-not $niValue) {
        Write-Host "[GUI] Non-Interactive mode detected (environment variable)" -ForegroundColor Cyan
    }
    
    $global:NonInteractiveMode = $true
}

<#
.SYNOPSIS
    Get a value from config for NonInteractive mode

.DESCRIPTION
    Retrieves a module-specific config value when running in NonInteractive mode.
    Falls back to default if not found.

.PARAMETER Module
    The module name (SecurityBaseline, ASR, DNS, Privacy, AntiAI, EdgeHardening, AdvancedSecurity)

.PARAMETER Key
    The config key to retrieve

.PARAMETER Default
    Default value if key not found

.OUTPUTS
    The config value or default

.EXAMPLE
    $provider = Get-NonInteractiveValue -Module "DNS" -Key "provider" -Default "Quad9"
#>
function Get-NonInteractiveValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Module,
        
        [Parameter(Mandatory = $true)]
        [string]$Key,
        
        [Parameter(Mandatory = $false)]
        $Default = $null
    )
    
    try {
        $hasConfig = $null -ne $script:Config
        $hasModules = $hasConfig -and ($null -ne $script:Config.modules)
        $hasModule = $hasModules -and ($null -ne $script:Config.modules.$Module)
        
        if ($hasModule) {
            $moduleConfig = $script:Config.modules.$Module
            $hasKey = $null -ne $moduleConfig.$Key
            
            if ($hasKey) {
                $value = $moduleConfig.$Key
                Write-Log -Level DEBUG -Message "[NonInteractive] $Module.$Key = $value (from config)" -Module "Core"
                return $value
            }
        }
    }
    catch {
        Write-Log -Level WARNING -Message "[NonInteractive] Failed to read $Module.$Key from config: $_" -Module "Core"
    }
    
    Write-Log -Level DEBUG -Message "[NonInteractive] $Module.$Key = $Default (default)" -Module "Core"
    return $Default
}

<#
.SYNOPSIS
    Check if auto-confirm is enabled

.DESCRIPTION
    Returns true if autoConfirm or nonInteractive is enabled.
    Used for Y/N confirmation prompts that should auto-confirm to Y.

.OUTPUTS
    [bool] True if should auto-confirm
#>
function Test-AutoConfirm {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    if ($script:Config -and $script:Config.options) {
        if ($script:Config.options.autoConfirm -eq $true) {
            return $true
        }
        if ($script:Config.options.nonInteractive -eq $true) {
            return $true
        }
    }
    
    return $false
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
    } else {
        "[GUI] $Decision"
    }
    
    Write-Host $message -ForegroundColor Cyan
    Write-Log -Level INFO -Message $message -Module $Module
}

# Functions are available globally when dot-sourced by Framework.ps1
# No Export-ModuleMember needed (script is not loaded as a module)
