<#
.SYNOPSIS
    Configuration management for NoID Privacy Framework

.DESCRIPTION
    Handles loading, saving, and validating configuration settings
    from JSON configuration files.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+
#>

# Global configuration object
$script:Config = $null

function Assert-NoIDJsonPropertyNamesUnique {
    <#
    .SYNOPSIS
        Reject duplicate JSON property names before ConvertFrom-Json can collapse them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Json
    )

    Add-Type -AssemblyName System.Runtime.Serialization -ErrorAction Stop
    $reader = $null
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
        $reader = [System.Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader(
            $bytes,
            [System.Xml.XmlDictionaryReaderQuotas]::Max
        )
        $document = [System.Xml.XmlDocument]::new()
        $document.Load($reader)
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }

    foreach ($objectNode in @($document.SelectNodes('//*[@type="object"]'))) {
        $propertyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($propertyNode in @($objectNode.ChildNodes)) {
            if ($propertyNode.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            if (-not $propertyNames.Add([string]$propertyNode.LocalName)) {
                throw "Duplicate JSON property name is not allowed: '$($propertyNode.LocalName)'"
            }
        }
    }
}

function Get-FrameworkVersion {
    <#
    .SYNOPSIS
        Read the framework version from the canonical VERSION file
    .DESCRIPTION
        Single source of truth helper. Reads VERSION from the framework root.
        Fails closed if VERSION is missing or malformed.
    .OUTPUTS
        String version (e.g. "2.2.5")
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $versionPath = Join-Path $PSScriptRoot "..\VERSION"
    if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
        throw "Canonical VERSION file is missing: $versionPath"
    }
    $version = (Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8 -ErrorAction Stop).Trim()
    if ($version -notmatch '^\d+\.\d+\.\d+$') {
        throw "Canonical VERSION value is invalid: '$version'"
    }
    return $version
}

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
        [string]$ConfigPath,

        # In-memory GUI contract. This avoids a writable temporary file between
        # the elevated GUI and the engine process. It is mutually exclusive
        # with ConfigPath and is never persisted by this function.
        [Parameter(Mandatory = $false)]
        [string]$ConfigJson,

        [Parameter(Mandatory = $false)]
        [bool]$CreateDefault = $false
    )

    if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and
        -not [string]::IsNullOrWhiteSpace($ConfigJson)) {
        throw 'Configuration path and in-memory configuration are mutually exclusive'
    }
    if ([string]::IsNullOrWhiteSpace($ConfigPath) -and
        [string]::IsNullOrWhiteSpace($ConfigJson)) {
        $ConfigPath = Join-Path $PSScriptRoot '..\config.json'
    }

    # Check if file-backed config exists.
    if ([string]::IsNullOrWhiteSpace($ConfigJson) -and -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
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
        $configContent = if (-not [string]::IsNullOrWhiteSpace($ConfigJson)) {
            $ConfigJson
        } else {
            Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 -ErrorAction Stop
        }
        Assert-NoIDJsonPropertyNamesUnique -Json $configContent
        $script:Config = $configContent | ConvertFrom-Json

        # Bind the machine result contract to the exact UTF-8 configuration
        # payload that was parsed. The commercial wrapper independently hashes
        # the Base64 transport bytes and rejects a child engine that ignores or
        # substitutes its requested options while still reporting the same
        # module identities.
        $configBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($configContent)
        $configHasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $script:ConfigPayloadSha256 = ([BitConverter]::ToString(
                    $configHasher.ComputeHash($configBytes)
                ) -replace '-', '').ToLowerInvariant()
        }
        finally { $configHasher.Dispose() }

        Write-Log -Level INFO -Message $(if ([string]::IsNullOrWhiteSpace($ConfigJson)) {
                'File-backed configuration loaded successfully'
            } else { 'In-memory configuration contract loaded successfully' }) -Module "Config"
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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not $PSCmdlet.ShouldProcess($Path, 'Write default configuration')) {
        return
    }

    $frameworkVersion = Get-FrameworkVersion

    $defaultConfig = @{
        version = $frameworkVersion
        modules = @{
            SecurityBaseline = @{
                enabled                 = $true
                priority                = 1
                status                  = "IMPLEMENTED"
                bitLockerUSBEnforcement = $false
                submitAllSamples        = $false
                smartScreenWarnMode     = $false
                standardUserElevationMode = "Strict"
            }
            ASR              = @{
                enabled              = $true
                priority             = 2
                status               = "IMPLEMENTED"
                usesManagementTools  = $false
                allowNewSoftware     = $true
                continueWithoutCloud = $false
            }
            DNS              = @{
                enabled  = $true
                priority = 3
                status   = "IMPLEMENTED"
                provider = "Quad9"
                dohMode  = "REQUIRE"
            }
            Privacy          = @{
                enabled               = $true
                priority              = 4
                status                = "IMPLEMENTED"
                mode                  = "MSRecommended"
                disableCloudClipboard = $true
                applyStorePackagePolicy = $false
                removeBloatwareApps   = "none"
                removeWeatherWidget   = $false
            }
            AntiAI           = @{
                enabled     = $true
                priority    = 5
                status      = "IMPLEMENTED"
                description = "Reversible hardening of declared Windows/Edge AI policy targets; current Copilot MSIX requires separate AppLocker/App Control coverage"
            }
            EdgeHardening    = @{
                enabled         = $true
                priority        = 6
                status          = "IMPLEMENTED"
                description     = "Microsoft Edge v139: 19 baseline values plus 7 explicit privacy additions"
                allowExtensions = $true
            }
            AdvancedSecurity = @{
                enabled                   = $true
                priority                  = 7
                status                    = "IMPLEMENTED"
                description               = "Advanced Security hardening beyond MS Baseline"
                securityProfile           = "Balanced"
                skipFirewallLayer         = $false
                disableRDP                = $true
                forceAdminShares          = $false
                disableUPnP               = $true
                disableWirelessDisplay    = $false
                disableDiscoveryProtocols = $false
                disableIPv6               = $false
            }
        }
        options = @{
            nonInteractive = $false
        }
    }

    try {
        # UTF-8 NO-BOM: PS 5.1 `Set-Content -Encoding UTF8` emits a BOM; keep framework-emitted JSON BOM-less.
        [System.IO.File]::WriteAllText($Path, ($defaultConfig | ConvertTo-Json -Depth 10), [System.Text.UTF8Encoding]::new($false))
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
    $allowedRootProperties = @('version', 'modules', 'options')
    foreach ($rootProperty in @($script:Config.PSObject.Properties)) {
        if ($allowedRootProperties -cnotcontains $rootProperty.Name) {
            Write-Log -Level ERROR -Message "Unsupported root configuration property '$($rootProperty.Name)'" -Module 'Config'
            return $false
        }
    }

    $expectedVersion = Get-FrameworkVersion
    if ([string]$script:Config.version -cne $expectedVersion) {
        Write-Log -Level ERROR -Message "Configuration version '$($script:Config.version)' does not match framework VERSION '$expectedVersion'" -Module 'Config'
        return $false
    }

    # Validate modules
    if ($null -eq $script:Config.modules) {
        Write-Log -Level ERROR -Message "Modules configuration is missing" -Module "Config"
        return $false
    }

    $expectedModules = [ordered]@{
        SecurityBaseline = 1
        ASR              = 2
        DNS              = 3
        Privacy          = 4
        AntiAI           = 5
        EdgeHardening    = 6
        AdvancedSecurity = 7
    }
    $actualModuleNames = @($script:Config.modules.PSObject.Properties.Name)
    if ($actualModuleNames.Count -ne $expectedModules.Count -or
        @($actualModuleNames | Where-Object { $expectedModules.Keys -cnotcontains $_ }).Count -gt 0 -or
        @($expectedModules.Keys | Where-Object { $actualModuleNames -cnotcontains $_ }).Count -gt 0) {
        Write-Log -Level ERROR -Message "Configuration must contain exactly these modules: $($expectedModules.Keys -join ', ')" -Module 'Config'
        return $false
    }

    $allowedModuleProperties = @{
        SecurityBaseline = @('enabled','priority','status','description','_comment','bitLockerUSBEnforcement','submitAllSamples','smartScreenWarnMode','standardUserElevationMode')
        ASR              = @('enabled','priority','status','description','_comment','usesManagementTools','allowNewSoftware','continueWithoutCloud')
        DNS              = @('enabled','priority','status','description','_comment','provider','dohMode')
        Privacy          = @('enabled','priority','status','description','_comment','mode','disableCloudClipboard','applyStorePackagePolicy','removeBloatwareApps','removeWeatherWidget')
        AntiAI           = @('enabled','priority','status','description','_comment')
        EdgeHardening    = @('enabled','priority','status','description','_comment','allowExtensions')
        AdvancedSecurity = @('enabled','priority','status','description','_comment','securityProfile','skipFirewallLayer','disableRDP','forceAdminShares','disableUPnP','disableWirelessDisplay','disableDiscoveryProtocols','disableIPv6')
    }
    $requiredBooleanDecisions = @{
        SecurityBaseline = @('bitLockerUSBEnforcement','submitAllSamples','smartScreenWarnMode')
        ASR              = @('usesManagementTools','allowNewSoftware','continueWithoutCloud')
        DNS              = @()
        Privacy          = @('disableCloudClipboard','applyStorePackagePolicy','removeWeatherWidget')
        AntiAI           = @()
        EdgeHardening    = @('allowExtensions')
        AdvancedSecurity = @('skipFirewallLayer','disableRDP','forceAdminShares','disableUPnP','disableWirelessDisplay','disableDiscoveryProtocols','disableIPv6')
    }

    # Validate each module configuration
    foreach ($prop in $script:Config.modules.PSObject.Properties) {
        $moduleName = $prop.Name
        $moduleConfig = $prop.Value

        # Check required module properties
        $requiredModuleProps = @('enabled', 'priority', 'status')
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

        if ([int]$moduleConfig.priority -ne [int]$expectedModules[$moduleName]) {
            Write-Log -Level ERROR -Message "Module '$moduleName' priority must be $($expectedModules[$moduleName])" -Module 'Config'
            return $false
        }
        if ([string]$moduleConfig.status -cne 'IMPLEMENTED') {
            Write-Log -Level ERROR -Message "Module '$moduleName' status must be IMPLEMENTED" -Module 'Config'
            return $false
        }
        foreach ($moduleProperty in @($moduleConfig.PSObject.Properties)) {
            if ($allowedModuleProperties[$moduleName] -cnotcontains $moduleProperty.Name) {
                Write-Log -Level ERROR -Message "Module '$moduleName' has unsupported configuration property '$($moduleProperty.Name)'" -Module 'Config'
                return $false
            }
        }
        foreach ($booleanDecision in @($requiredBooleanDecisions[$moduleName])) {
            if ($moduleConfig.PSObject.Properties.Name -cnotcontains $booleanDecision -or
                $moduleConfig.$booleanDecision -isnot [bool]) {
                Write-Log -Level ERROR -Message "Module '$moduleName' property '$booleanDecision' is required and must be boolean" -Module 'Config'
                return $false
            }
        }

        # Module-specific validation
        if ($moduleName -eq "DNS") {
            # Validate DNS provider if specified
            if (Get-Member -InputObject $moduleConfig -Name 'provider' -MemberType NoteProperty) {
                $validProviders = @('Cloudflare', 'Quad9', 'AdGuard', 'KEEP')

                if ($moduleConfig.provider -ceq 'KEEP') {
                    # REQUIRE/ALLOW remains a valid persisted UI choice but is
                    # not acted on while KEEP is selected. The module returns
                    # the canonical effective decision KEEP/KEEP.
                    Write-Log -Level DEBUG -Message "DNS provider set to KEEP - current DNS and DoH configuration will be preserved without mutation" -Module "Config"
                }
                elseif ($validProviders -cnotcontains $moduleConfig.provider) {
                    Write-Log -Level ERROR -Message "DNS module has invalid provider: '$($moduleConfig.provider)'. Valid providers: $($validProviders -join ', ')" -Module "Config"
                    return $false
                }
                else {
                    Write-Log -Level DEBUG -Message "DNS provider validated: $($moduleConfig.provider)" -Module "Config"
                }
            }
            else {
                Write-Log -Level ERROR -Message "DNS module property 'provider' is required" -Module 'Config'
                return $false
            }
            if (-not (Get-Member -InputObject $moduleConfig -Name 'dohMode' -MemberType NoteProperty) -or
                [string]$moduleConfig.dohMode -cnotin @('REQUIRE', 'ALLOW')) {
                Write-Log -Level ERROR -Message "DNS module property 'dohMode' must be REQUIRE or ALLOW" -Module "Config"
                return $false
            }
        }

        if ($moduleName -eq "Privacy") {
            # Validate Privacy mode if specified
            if (Get-Member -InputObject $moduleConfig -Name 'mode' -MemberType NoteProperty) {
                $validModes = @('MSRecommended', 'Strict', 'Paranoid')

                if ($validModes -cnotcontains $moduleConfig.mode) {
                    Write-Log -Level ERROR -Message "Privacy module has invalid mode: '$($moduleConfig.mode)'. Valid modes: $($validModes -join ', ')" -Module "Config"
                    return $false
                }
                else {
                    Write-Log -Level DEBUG -Message "Privacy mode validated: $($moduleConfig.mode)" -Module "Config"
                }
            }
            else {
                Write-Log -Level ERROR -Message "Privacy module property 'mode' is required" -Module 'Config'
                return $false
            }

            # Tier 2 classic bloatware removal knob: "none" (default, nothing removed)
            # or "standard" (curated Tier 2 list). Fails closed on any other value.
            if (-not (Get-Member -InputObject $moduleConfig -Name 'removeBloatwareApps' -MemberType NoteProperty) -or
                [string]$moduleConfig.removeBloatwareApps -cnotin @('none', 'standard')) {
                Write-Log -Level ERROR -Message "Privacy module property 'removeBloatwareApps' must be 'none' or 'standard'" -Module 'Config'
                return $false
            }
            if ([bool]$moduleConfig.removeWeatherWidget -and
                [string]$moduleConfig.removeBloatwareApps -cne 'standard') {
                Write-Log -Level ERROR -Message "Privacy module property 'removeWeatherWidget' can be true only when 'removeBloatwareApps' is 'standard'" -Module 'Config'
                return $false
            }
        }

        if ($moduleName -eq 'SecurityBaseline') {
            if (-not (Get-Member -InputObject $moduleConfig -Name 'standardUserElevationMode' -MemberType NoteProperty)) {
                Write-Log -Level ERROR -Message "SecurityBaseline property 'standardUserElevationMode' is required" -Module 'Config'
                return $false
            }
            $validElevationModes = @('Strict', 'SecureDesktop')
            if ($moduleConfig.standardUserElevationMode -cnotin $validElevationModes) {
                Write-Log -Level ERROR -Message "SecurityBaseline has invalid standardUserElevationMode: '$($moduleConfig.standardUserElevationMode)'. Valid modes: $($validElevationModes -join ', ')" -Module 'Config'
                return $false
            }
        }

        if ($moduleName -eq 'AdvancedSecurity') {
            if ($moduleConfig.PSObject.Properties.Name -notcontains 'securityProfile' -or
                [string]$moduleConfig.securityProfile -cnotin @('Balanced','Enterprise','Maximum')) {
                Write-Log -Level ERROR -Message "AdvancedSecurity property 'securityProfile' must be Balanced, Enterprise, or Maximum" -Module 'Config'
                return $false
            }
        }
    }

    # Validate options
    if ($null -eq $script:Config.options) {
        Write-Log -Level ERROR -Message "Options configuration is missing" -Module "Config"
        return $false
    }

    # Check required option properties
    $requiredOptions = @('nonInteractive')
    foreach ($option in $requiredOptions) {
        if (-not (Get-Member -InputObject $script:Config.options -Name $option -MemberType NoteProperty)) {
            Write-Log -Level ERROR -Message "Missing required option: $option" -Module "Config"
            return $false
        }
    }

    if ($script:Config.options.nonInteractive -isnot [bool]) {
        Write-Log -Level ERROR -Message "Option 'nonInteractive' must be boolean" -Module 'Config'
        return $false
    }
    foreach ($optionProperty in @($script:Config.options.PSObject.Properties)) {
        if ($optionProperty.Name -cnotin @('nonInteractive','sessionType','_comment')) {
            Write-Log -Level ERROR -Message "Unsupported global option '$($optionProperty.Name)'" -Module 'Config'
            return $false
        }
    }
    if ($script:Config.options.PSObject.Properties.Name -ccontains 'sessionType') {
        if ([string]$script:Config.options.sessionType -cnotin @('wizard','advanced','manual','unknown')) {
            Write-Log -Level ERROR -Message "Option 'sessionType' must be wizard, advanced, manual, or unknown" -Module 'Config'
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
        Returns enabled modules in priority order. An enabled module whose
        implementation is missing is installation corruption and fails closed.

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
                    Name     = $moduleName
                    Priority = $moduleConfig.priority
                }
            }
            else {
                $status = if ($moduleConfig.PSObject.Properties.Name -contains 'status') { $moduleConfig.status } else { 'UNKNOWN' }
                throw "Module '$moduleName' is enabled in config but unavailable (Status: $status)"
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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )

    if (-not $PSCmdlet.ShouldProcess($ModuleName, "Set enabled=$Enabled in config")) {
        return
    }

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
