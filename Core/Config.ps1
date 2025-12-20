<#
.SYNOPSIS
    Configuration management for NoID Privacy Framework
    
.DESCRIPTION
    Handles loading, saving, and validating configuration settings
    from JSON configuration files.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.1
    Requires: PowerShell 5.1+
#>

# Global configuration object
$script:Config = $null

function Initialize-Config {
    <#
    .SYNOPSIS
        Initialize configuration system
        
    .PARAMETER ConfigPath
        Path to configuration file (JSON)
        
    .PARAMETER CreateDefault
        Create default configuration if file doesn't exist
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigPath = (Join-Path $PSScriptRoot "..\config.json"),
        
        [Parameter(Mandatory = $false)]
        [bool]$CreateDefault = $true
    )
    
    # Check if config file exists
    if (-not (Test-Path -Path $ConfigPath)) {
        if ($CreateDefault) {
            Write-Log -Level INFO -Message "Configuration file not found, creating default" -Module "Config"
            New-DefaultConfig -Path $ConfigPath
        }
        else {
            throw "Configuration file not found: $ConfigPath"
        }
    }
    
    # Load configuration
    try {
        $configContent = Get-Content -Path $ConfigPath -Raw -Encoding UTF8
        $script:Config = $configContent | ConvertFrom-Json
        
        Write-Log -Level INFO -Message "Configuration loaded successfully" -Module "Config"
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to load configuration" -Module "Config" -Exception $_.Exception
        throw
    }
    
    # Validate configuration
    if (-not (Test-ConfigValid)) {
        throw "Configuration validation failed"
    }
}

function New-DefaultConfig {
    <#
    .SYNOPSIS
        Create default configuration file
        
    .PARAMETER Path
        Path where configuration file should be created
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    $defaultConfig = @{
        version = "2.2.1"
        modules = @{
            SecurityBaseline = @{
                enabled = $true
                priority = 1
                status = "IMPLEMENTED"
            }
            ASR = @{
                enabled = $true
                priority = 2
                status = "IMPLEMENTED"
            }
            DNS = @{
                enabled = $true
                priority = 3
                provider = ""
                status = "IMPLEMENTED"
            }
            Privacy = @{
                enabled = $true
                priority = 4
                mode = ""
                status = "IMPLEMENTED"
            }
            AntiAI = @{
                enabled = $true
                priority = 5
                status = "IMPLEMENTED"
                description = "Disable all Windows 11 AI features (Recall, Copilot, Paint AI, etc.)"
            }
            EdgeHardening = @{
                enabled = $true
                priority = 6
                status = "IMPLEMENTED"
                description = "Microsoft Edge v139 Security Baseline: 20 security policies including SmartScreen enforcement, site isolation, SSL/TLS hardening, extension blocklist, IE Mode restrictions, and Spectre mitigations. No LGPO.exe dependency."
                version = "2.2.1"
                baseline = "Edge v139"
                policies = 20
                features = @{
                    smartscreen_enforcement = $true
                    site_isolation = $true
                    ssl_error_blocking = $true
                    extension_blocklist = $true
                    ie_mode_restrictions = $true
                    spectre_mitigations = $true
                    application_encryption = $true
                    auth_scheme_restrictions = $true
                }
            }
            AdvancedSecurity = @{
                enabled = $true
                priority = 7
                status = "IMPLEMENTED"
                description = "Advanced Security hardening beyond MS Baseline: RDP NLA/Disable, WDigest protection, Admin Shares disable, Risky ports/services, Legacy TLS disable, WPAD disable, PowerShell v2 removal, SRP .lnk protection, Windows Update (3 GUI settings), Finger Protocol block. Opt-in by design (use -SecurityProfile Balanced/Enterprise/Maximum)"
                version = "2.2.1"
                policies = 36
                features = @{
                    rdp_hardening = $true
                    wdigest_protection = $true
                    admin_shares_disable = $true
                    risky_ports_closure = $true
                    risky_services_stop = $true
                    legacy_tls_disable = $true
                    wpad_disable = $true
                    powershell_v2_removal = $true
                    srp_lnk_protection = $true
                    windows_update_config = $true
                    finger_protocol_block = $true
                }
                profiles = @("Balanced", "Enterprise", "Maximum")
            }
        }
        options = @{
            dryRun = $false
            createBackup = $true
            verboseLogging = $true
            autoReboot = $false
        }
    }
    
    try {
        $defaultConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8 | Out-Null
        Write-Log -Level SUCCESS -Message "Default configuration created: $Path" -Module "Config"
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to create default configuration" -Module "Config" -Exception $_.Exception
        throw
    }
}

function Test-ConfigValid {
    <#
    .SYNOPSIS
        Validate configuration structure and values
        
    .OUTPUTS
        Boolean indicating if configuration is valid
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    if ($null -eq $script:Config) {
        Write-Log -Level ERROR -Message "Configuration is null" -Module "Config"
        return $false
    }
    
    # Check required properties
    $requiredProps = @('version', 'modules', 'options')
    foreach ($prop in $requiredProps) {
        if (-not (Get-Member -InputObject $script:Config -Name $prop -MemberType NoteProperty)) {
            Write-Log -Level ERROR -Message "Missing required property: $prop" -Module "Config"
            return $false
        }
    }
    
    # Validate modules
    if ($null -eq $script:Config.modules) {
        Write-Log -Level ERROR -Message "Modules configuration is missing" -Module "Config"
        return $false
    }
    
    # Validate each module configuration
    foreach ($prop in $script:Config.modules.PSObject.Properties) {
        $moduleName = $prop.Name
        $moduleConfig = $prop.Value
        
        # Check required module properties
        $requiredModuleProps = @('enabled', 'priority')
        foreach ($moduleProp in $requiredModuleProps) {
            if (-not (Get-Member -InputObject $moduleConfig -Name $moduleProp -MemberType NoteProperty)) {
                Write-Log -Level ERROR -Message "Module '$moduleName' missing required property: $moduleProp" -Module "Config"
                return $false
            }
        }
        
        # Validate property types
        if ($moduleConfig.enabled -isnot [bool]) {
            Write-Log -Level ERROR -Message "Module '$moduleName' property 'enabled' must be boolean" -Module "Config"
            return $false
        }
        
        if ($moduleConfig.priority -isnot [int] -and $moduleConfig.priority -isnot [long]) {
            Write-Log -Level ERROR -Message "Module '$moduleName' property 'priority' must be integer" -Module "Config"
            return $false
        }
        
        # Module-specific validation
        if ($moduleName -eq "DNS") {
            # Validate DNS provider if specified
            if (Get-Member -InputObject $moduleConfig -Name 'provider' -MemberType NoteProperty) {
                $validProviders = @('Cloudflare', 'Quad9', 'AdGuard', '', 'KEEP')
                
                # Empty string means interactive selection
                if ($moduleConfig.provider -eq '') {
                    Write-Log -Level DEBUG -Message "DNS provider not specified - will prompt user for selection" -Module "Config"
                }
                elseif ($moduleConfig.provider -eq 'KEEP') {
                    Write-Log -Level DEBUG -Message "DNS provider set to KEEP - will detect and preserve current provider" -Module "Config"
                }
                elseif ($validProviders -notcontains $moduleConfig.provider) {
                    Write-Log -Level ERROR -Message "DNS module has invalid provider: '$($moduleConfig.provider)'. Valid providers: $($validProviders -join ', ')" -Module "Config"
                    return $false
                }
                else {
                    Write-Log -Level DEBUG -Message "DNS provider validated: $($moduleConfig.provider)" -Module "Config"
                }
            }
            else {
                # Provider property missing - will prompt for selection
                Write-Log -Level DEBUG -Message "DNS provider not specified - will prompt user for selection" -Module "Config"
            }
        }
        
        if ($moduleName -eq "Privacy") {
            # Validate Privacy mode if specified
            if (Get-Member -InputObject $moduleConfig -Name 'mode' -MemberType NoteProperty) {
                $validModes = @('MSRecommended', 'Strict', 'Paranoid', '')
                
                # Empty string means interactive selection
                if ($moduleConfig.mode -eq '') {
                    Write-Log -Level DEBUG -Message "Privacy mode not specified - will prompt user for selection" -Module "Config"
                }
                elseif ($validModes -notcontains $moduleConfig.mode) {
                    Write-Log -Level ERROR -Message "Privacy module has invalid mode: '$($moduleConfig.mode)'. Valid modes: $($validModes -join ', ')" -Module "Config"
                    return $false
                }
                else {
                    Write-Log -Level DEBUG -Message "Privacy mode validated: $($moduleConfig.mode)" -Module "Config"
                }
            }
            else {
                # Mode property missing - will prompt for selection
                Write-Log -Level DEBUG -Message "Privacy mode not specified - will prompt user for selection" -Module "Config"
            }
        }
    }
    
    # Validate options
    if ($null -eq $script:Config.options) {
        Write-Log -Level ERROR -Message "Options configuration is missing" -Module "Config"
        return $false
    }
    
    # Check required option properties
    $requiredOptions = @('dryRun', 'createBackup', 'verboseLogging', 'autoReboot')
    foreach ($option in $requiredOptions) {
        if (-not (Get-Member -InputObject $script:Config.options -Name $option -MemberType NoteProperty)) {
            Write-Log -Level ERROR -Message "Missing required option: $option" -Module "Config"
            return $false
        }
    }
    
    Write-Log -Level INFO -Message "Configuration validation passed" -Module "Config"
    return $true
}

function Get-Config {
    <#
    .SYNOPSIS
        Get current configuration object
        
    .OUTPUTS
        Configuration object
    #>
    return $script:Config
}

function Get-ModuleConfig {
    <#
    .SYNOPSIS
        Get configuration for specific module
        
    .PARAMETER ModuleName
        Name of the module
        
    .OUTPUTS
        Module configuration object or $null if not found
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )
    
    if ($null -eq $script:Config -or $null -eq $script:Config.modules) {
        Write-Log -Level WARNING -Message "Configuration not initialized" -Module "Config"
        return $null
    }
    
    $moduleConfig = $script:Config.modules | Get-Member -Name $ModuleName -MemberType NoteProperty
    if ($null -eq $moduleConfig) {
        Write-Log -Level WARNING -Message "Module configuration not found: $ModuleName" -Module "Config"
        return $null
    }
    
    return $script:Config.modules.$ModuleName
}

function Test-ModuleAvailability {
    <#
    .SYNOPSIS
        Check if a module is actually implemented and available
        
    .DESCRIPTION
        Checks if module directory exists and contains the required .psd1 manifest file
        
    .PARAMETER ModuleName
        Name of the module to check
        
    .OUTPUTS
        Boolean - True if module is implemented, False otherwise
        
    .EXAMPLE
        Test-ModuleAvailability -ModuleName "SecurityBaseline"
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )
    
    # Get framework root (3 levels up from Config.ps1)
    $frameworkRoot = Split-Path $PSScriptRoot -Parent
    $modulePath = Join-Path $frameworkRoot "Modules\$ModuleName"
    $manifestPath = Join-Path $modulePath "$ModuleName.psd1"
    
    # Check if module directory exists
    if (-not (Test-Path $modulePath)) {
        Write-Log -Level DEBUG -Message "Module directory not found: $modulePath" -Module "Config"
        return $false
    }
    
    # Check if module manifest exists
    if (-not (Test-Path $manifestPath)) {
        Write-Log -Level DEBUG -Message "Module manifest not found: $manifestPath" -Module "Config"
        return $false
    }
    
    Write-Log -Level DEBUG -Message "Module $ModuleName is available" -Module "Config"
    return $true
}

function Get-EnabledModules {
    <#
    .SYNOPSIS
        Get list of enabled modules sorted by priority
        
    .DESCRIPTION
        Returns only modules that are both enabled in config AND actually implemented
        
    .OUTPUTS
        Array of enabled module names sorted by priority
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    
    if ($null -eq $script:Config -or $null -eq $script:Config.modules) {
        Write-Log -Level WARNING -Message "Configuration not initialized" -Module "Config"
        return @()
    }
    
    $enabledModules = @()
    
    foreach ($prop in $script:Config.modules.PSObject.Properties) {
        $moduleName = $prop.Name
        $moduleConfig = $prop.Value
        
        if ($moduleConfig.enabled -eq $true) {
            # Check if module is actually implemented
            if (Test-ModuleAvailability -ModuleName $moduleName) {
                $enabledModules += [PSCustomObject]@{
                    Name = $moduleName
                    Priority = $moduleConfig.priority
                }
            }
            else {
                $status = if ($moduleConfig.PSObject.Properties.Name -contains 'status') { $moduleConfig.status } else { 'UNKNOWN' }
                Write-Log -Level WARNING -Message "Module '$moduleName' is enabled in config but not implemented (Status: $status)" -Module "Config"
            }
        }
    }
    
    # Sort by priority
    $sorted = $enabledModules | Sort-Object -Property Priority
    
    return $sorted | ForEach-Object { $_.Name }
}

function Set-ModuleEnabled {
    <#
    .SYNOPSIS
        Enable or disable a module
        
    .PARAMETER ModuleName
        Name of the module
        
    .PARAMETER Enabled
        Enable (true) or disable (false) the module
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )
    
    if ($null -eq $script:Config -or $null -eq $script:Config.modules) {
        throw "Configuration not initialized"
    }
    
    $moduleConfig = $script:Config.modules | Get-Member -Name $ModuleName -MemberType NoteProperty
    if ($null -eq $moduleConfig) {
        throw "Module not found: $ModuleName"
    }
    
    $script:Config.modules.$ModuleName.enabled = $Enabled
    Write-Log -Level INFO -Message "Module '$ModuleName' set to: $Enabled" -Module "Config"
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
