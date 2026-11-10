#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/ASR/Private/Test-CloudProtection.ps1')
    Set-Item -Path Function:Write-Log -Value {
        param([string]$Level, [string]$Message, [string]$Module)
        $null = $Level, $Message, $Module
    }
}

Describe 'ASR cloud configuration authority' {
    It 'accepts the documented enabled MAPS membership <Value>' -TestCases @(
        @{Value = [byte]1}, @{Value = [byte]2}, @{Value = 1}, @{Value = 2}
    ) {
        param($Value)
        $script:PreferenceResult = [pscustomobject]@{MAPSReporting = $Value}
        Mock Get-MpPreference { $script:PreferenceResult }
        Test-CloudProtection | Should -BeTrue
    }

    It 'does not infer enabled cloud configuration from <Label>' -TestCases @(
        @{Label='disabled'; Value=0},
        @{Label='null'; Value=$null},
        @{Label='an unknown numeric value'; Value=3},
        @{Label='a negative value'; Value=-1},
        @{Label='a boolean'; Value=$true},
        @{Label='a fractional value'; Value=1.4},
        @{Label='an arbitrary string'; Value='unknown'},
        @{Label='multiple values'; Value=@(1, 2)}
    ) {
        param($Label, $Value)
        $null = $Label
        $script:PreferenceResult = [pscustomobject]@{MAPSReporting = $Value}
        Mock Get-MpPreference { $script:PreferenceResult }
        Test-CloudProtection | Should -BeFalse
    }

    It 'rejects a missing property even without StrictMode' {
        Set-StrictMode -Off
        Mock Get-MpPreference { [pscustomobject]@{OtherSetting = 1} }
        Test-CloudProtection | Should -BeFalse
    }

    It 'rejects an absent preference result even without StrictMode' {
        Set-StrictMode -Off
        Mock Get-MpPreference { $null }
        Test-CloudProtection | Should -BeFalse
    }

    It 'returns false when the preference query fails' {
        Mock Get-MpPreference { throw 'Preference query failed' }
        Test-CloudProtection | Should -BeFalse
    }
}
