#Requires -Version 5.1

function Get-PrivacyRegistryTargets {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )

    $userRoot = (Get-PrivacyUserContext).Root
    $oneDrivePath = Join-Path $script:ModuleRoot 'Config\OneDrive.json'
    if (-not (Test-Path -LiteralPath $oneDrivePath -PathType Leaf)) {
        throw "Privacy OneDrive configuration is missing: $oneDrivePath"
    }
    $oneDrive = Get-Content -LiteralPath $oneDrivePath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $sections = [System.Collections.Generic.List[object]]::new()
    foreach ($name in @('DataCollection', 'Personalization', 'SearchAndCloud', 'InputAndSync', 'LocationAndAppPrivacy')) {
        if (-not $Config.PSObject.Properties[$name]) { throw "Privacy configuration section is missing: $name" }
        $sections.Add([PSCustomObject]@{ Name = $name; Value = $Config.$name })
    }
    foreach ($name in @('OneDrivePolicies', 'StorePolicies')) {
        if (-not $oneDrive.PSObject.Properties[$name]) { throw "OneDrive configuration section is missing: $name" }
        $sections.Add([PSCustomObject]@{ Name = $name; Value = $oneDrive.$name })
    }

    # Tier 1 is always part of the declared 645-target framework inventory. The
    # decision controls Selected/NotChecked, never whether these 27 identities
    # silently disappear from accounting.
    $tier1Selected = [bool]($Config.PSObject.Properties['Tier1PolicyRemovalSelected'] -and $Config.Tier1PolicyRemovalSelected)
    $tier1Policy = Get-PrivacyTier1PolicyDefinition

    $targets = @{}
    foreach ($section in $sections) {
        foreach ($pathProperty in $section.Value.PSObject.Properties) {
            $configuredPath = [string]$pathProperty.Name
            $path = if ($configuredPath.StartsWith('HKCU:\', [StringComparison]::OrdinalIgnoreCase)) {
                $userRoot + '\' + $configuredPath.Substring(6)
            }
            elseif ($configuredPath.StartsWith('HKLM:\', [StringComparison]::OrdinalIgnoreCase)) {
                $configuredPath
            }
            else {
                throw "Privacy registry target uses an unsupported hive: $configuredPath"
            }

            foreach ($valueProperty in $pathProperty.Value.PSObject.Properties) {
                $definition = $valueProperty.Value
                $type = [string]$definition.Type
                $value = $null
                switch ($type) {
                    'DWord'        { $value = [int]$definition.Value }
                    'QWord'        { $value = [long]$definition.Value }
                    'String'       { $value = [string]$definition.Value }
                    'ExpandString' { $value = [string]$definition.Value }
                    'MultiString'  { $value = [string[]]@($definition.Value) }
                    'Binary'       { $value = [byte[]]@($definition.Value) }
                    default { throw "Unsupported Privacy registry type '$type' for $path::$($valueProperty.Name)" }
                }
                $identity = ($path + '::' + [string]$valueProperty.Name).ToLowerInvariant()
                $candidate = [PSCustomObject]@{
                    Path = $path; Name = [string]$valueProperty.Name; Type = $type
                    Value = $value; Section = [string]$section.Name; Selected = $true
                }
                if ($targets.ContainsKey($identity)) {
                    $old = $targets[$identity] | Select-Object Path, Name, Type, Value | ConvertTo-Json -Compress -Depth 10
                    $new = $candidate | Select-Object Path, Name, Type, Value | ConvertTo-Json -Compress -Depth 10
                    if ($old -cne $new) { throw "Conflicting duplicate Privacy registry target: $path::$($valueProperty.Name)" }
                    continue
                }
                $targets[$identity] = $candidate
            }
        }
    }
    foreach ($tier1Target in @($tier1Policy.Targets)) {
        $identity = ($tier1Target.Path + '::' + $tier1Target.Name).ToLowerInvariant()
        if ($targets.ContainsKey($identity)) { throw "Tier 1 Privacy target collides with another section: $identity" }
        $targets[$identity] = [PSCustomObject]@{
            Path=[string]$tier1Target.Path; Name=[string]$tier1Target.Name
            Type=[string]$tier1Target.Type; Value=$tier1Target.Value
            Section='Tier1Policy'; Selected=$tier1Selected
        }
    }
    $result = @($targets.Values | Sort-Object Path, Name)
    if ($result.Count -eq 0) { throw 'Privacy configuration produced no registry targets' }
    return $result
}
