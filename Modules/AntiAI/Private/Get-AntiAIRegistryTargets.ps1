#Requires -Version 5.1

function Get-AntiAIRegistryTargets {
    <#
    .SYNOPSIS
        Returns the canonical, de-duplicated AntiAI registry target set.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $configPath = Join-Path $script:ModuleRoot 'Config\AntiAI-Settings.json'
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "AntiAI configuration not found: $configPath"
    }
    $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if (-not $config.Features) {
        throw 'AntiAI configuration contains no Features object'
    }
    if ([int]$config.TotalPolicies -ne 43 -or [int]$config.TotalFeatureGroups -ne 12) {
        throw 'AntiAI configuration header does not declare the canonical 43 targets / 12 groups'
    }

    $userContext = Get-AntiAIUserContext
    $targetsByIdentity = @{}
    foreach ($featureProperty in $config.Features.PSObject.Properties) {
        $feature = $featureProperty.Value
        foreach ($containerName in @('Registry', 'EnterpriseProtection')) {
            $containerProperty = $feature.PSObject.Properties[$containerName]
            if (-not $containerProperty) { continue }

            foreach ($pathProperty in $containerProperty.Value.PSObject.Properties) {
                $configuredPath = [string]$pathProperty.Name
                $path = if ($configuredPath.StartsWith('HKCU:\', [StringComparison]::OrdinalIgnoreCase)) {
                    $userContext.Root + '\' + $configuredPath.Substring(6)
                }
                else {
                    $configuredPath
                }
                $allowedMachinePaths = @(
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy',
                    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI',
                    'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint',
                    'HKLM:\SOFTWARE\Policies\WindowsNotepad'
                )
                $allowedUserPaths = @(
                    ($userContext.Root + '\SOFTWARE\Policies\Microsoft\Windows\WindowsAI')
                    ($userContext.Root + '\Software\Policies\Microsoft\Windows\WindowsCopilot')
                    ($userContext.Root + '\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced')
                    ($userContext.Root + '\Software\Policies\Microsoft\Windows\CopilotKey')
                )
                if ($path -notin @($allowedMachinePaths + $allowedUserPaths)) {
                    throw "AntiAI configuration target is outside the strict allowlist: $path"
                }

                foreach ($valueProperty in $pathProperty.Value.PSObject.Properties) {
                    $definition = $valueProperty.Value
                    foreach ($requiredProperty in @('Type', 'Value', 'Description')) {
                        if (-not $definition.PSObject.Properties[$requiredProperty]) {
                            throw "AntiAI definition is missing '$requiredProperty': $path::$($valueProperty.Name)"
                        }
                    }
                    $type = [string]$definition.Type
                    $value = switch ($type) {
                        'DWord' {
                            if ($definition.Value -isnot [int] -and $definition.Value -isnot [long]) {
                                throw "AntiAI DWord definition is not an integer: $path::$($valueProperty.Name)"
                            }
                            [int]$definition.Value
                        }
                        'QWord' {
                            if ($definition.Value -isnot [int] -and $definition.Value -isnot [long]) {
                                throw "AntiAI QWord definition is not an integer: $path::$($valueProperty.Name)"
                            }
                            [long]$definition.Value
                        }
                        'String' {
                            if ($definition.Value -isnot [string]) {
                                throw "AntiAI String definition is not a string: $path::$($valueProperty.Name)"
                            }
                            [string]$definition.Value
                        }
                        'ExpandString' {
                            if ($definition.Value -isnot [string]) {
                                throw "AntiAI ExpandString definition is not a string: $path::$($valueProperty.Name)"
                            }
                            [string]$definition.Value
                        }
                        'MultiString' {
                            foreach ($item in @($definition.Value)) {
                                if ($item -isnot [string]) {
                                    throw "AntiAI MultiString definition contains a non-string: $path::$($valueProperty.Name)"
                                }
                            }
                            [string[]]@($definition.Value)
                        }
                        'Binary' {
                            foreach ($item in @($definition.Value)) {
                                if ([int]$item -lt 0 -or [int]$item -gt 255) {
                                    throw "AntiAI Binary definition contains a byte outside 0..255: $path::$($valueProperty.Name)"
                                }
                            }
                            [byte[]]@($definition.Value)
                        }
                        default { throw "Unsupported AntiAI registry type '$type' for $path::$($valueProperty.Name)" }
                    }
                    $identity = ($path + '::' + [string]$valueProperty.Name).ToLowerInvariant()
                    $candidate = [PSCustomObject]@{
                        Path        = $path
                        Name        = [string]$valueProperty.Name
                        Type        = $type
                        Value       = $value
                        Feature     = [string]$featureProperty.Name
                        Description = [string]$definition.Description
                    }
                    if ($targetsByIdentity.ContainsKey($identity)) {
                        $existingJson = $targetsByIdentity[$identity] | Select-Object Path, Name, Type, Value | ConvertTo-Json -Compress -Depth 10
                        $candidateJson = $candidate | Select-Object Path, Name, Type, Value | ConvertTo-Json -Compress -Depth 10
                        if ($existingJson -cne $candidateJson) {
                            throw "Conflicting duplicate AntiAI registry target: $path::$($valueProperty.Name)"
                        }
                        continue
                    }
                    $targetsByIdentity[$identity] = $candidate
                }
            }
        }
    }

    $targets = @($targetsByIdentity.Values | Sort-Object Path, Name)
    if ($targets.Count -eq 0) {
        throw 'AntiAI configuration produced no registry targets'
    }
    if ($targets.Count -ne [int]$config.TotalPolicies) {
        throw "AntiAI configuration target count drift: header=$($config.TotalPolicies), derived=$($targets.Count)"
    }
    return $targets
}
