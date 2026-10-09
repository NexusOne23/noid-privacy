function Get-AdvancedSecurityConfig {
    <#
    .SYNOPSIS
        Loads or validates the fixed Windows Update Apply contract.
    .DESCRIPTION
        Backup owns a closed registry inventory. Configuration files may describe
        those targets, but cannot add paths, weaken values or change edition gates.
        Invoke captures this configuration before Backup and passes it through
        Apply and Verify. Historical Restore uses its own frozen backup readers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('WindowsUpdate')]
        [string]$Name,

        [object]$Configuration
    )

    if ($null -eq $Configuration) {
        $path = Join-Path $script:ModuleRoot (Join-Path 'Config' 'WindowsUpdate.json')
        $Configuration = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    }
    if ($Configuration -isnot [pscustomobject]) {
        throw "AdvancedSecurity $Name configuration must be one object"
    }

    function Assert-ConfigInteger {
        param([object]$Actual, [long]$Expected, [string]$Field)
        if (($Actual -isnot [int] -and $Actual -isnot [long]) -or $Actual -ne $Expected) {
            throw "AdvancedSecurity $Name configuration violates the fixed contract: $Field"
        }
    }

    $expectedSettings = @{
        '1_OptionalUpdatesPolicy' = @{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Managed = $true
            # WindowsUpdate.admx AllowOptionalContent: enabling the policy writes
            # SetAllowOptionalContent=1; the choice "users select optional
            # updates" is AllowOptionalContent=3.
            Values = [ordered]@{ SetAllowOptionalContent = 1; AllowOptionalContent = 3 }
        }
        '2_ContinuousInnovationPreference' = @{
            Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'; Managed = $false
            Values = [ordered]@{ IsContinuousInnovationOptedIn = 0 }
        }
        '3_DeliveryOptimization' = @{
            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Managed = $true
            Values = [ordered]@{ DODownloadMode = 0 }
        }
    }
    if ($Configuration.Settings -isnot [pscustomobject] -or
        @($Configuration.Settings.PSObject.Properties).Count -ne $expectedSettings.Count) {
        throw 'AdvancedSecurity Windows Update configuration must contain exactly three owned settings'
    }
    foreach ($property in $Configuration.Settings.PSObject.Properties) {
        if (-not $expectedSettings.ContainsKey($property.Name)) {
            throw 'AdvancedSecurity Windows Update configuration contains an unowned setting'
        }
        $expected = $expectedSettings[$property.Name]
        $setting = $property.Value
        if ($setting.RegistryPath -cne $expected.Path -or
            $setting.RequiresManagedPolicyEdition -isnot [bool] -or
            $setting.RequiresManagedPolicyEdition -ne $expected.Managed -or
            $setting.Values -isnot [pscustomobject] -or
            (@($setting.Values.PSObject.Properties.Name) -join ([char]31)) -cne (@($expected.Values.Keys) -join ([char]31))) {
            throw 'AdvancedSecurity Windows Update configuration changes an owned target or edition gate'
        }
        foreach ($valueName in $expected.Values.Keys) {
            $value = $setting.Values.$valueName
            if ($value.Type -cne 'DWord') {
                throw 'AdvancedSecurity Windows Update configuration changes an owned value type'
            }
            Assert-ConfigInteger $value.Value $expected.Values[$valueName] $valueName
        }
    }
    return $Configuration
}
