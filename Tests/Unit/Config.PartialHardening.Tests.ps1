#Requires -Version 5.1
BeforeAll {
    $script:RepoRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $script:RepoRoot 'Core/Config.ps1')
    function Write-Log {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Test placeholder for the engine logger.')]
        [CmdletBinding()] param($Level,$Message,$Module) $null=$Level,$Message,$Module
    }
}
Describe 'Explicit partial-run configuration boundary' {
    BeforeEach { $script:Config=Get-Content (Join-Path $script:RepoRoot 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json }
    It 'accepts the legacy configuration without the optional choice' { Test-ConfigValid | Should -BeTrue }
    It 'accepts only a Boolean partial-run choice: <Value>' -ForEach @(@{Value=$true},@{Value=$false}) {
        $script:Config.options | Add-Member allowPartialHardening $Value
        Test-ConfigValid | Should -BeTrue
    }
    It 'rejects a malformed partial-run choice: <Label>' -ForEach @(
        @{Label='string';Value='false'}, @{Label='number';Value=1}, @{Label='null';Value=$null}
    ) {
        $script:Config.options | Add-Member allowPartialHardening $Value
        Test-ConfigValid | Should -BeFalse
    }
    It 'still rejects an unknown option' {
        $script:Config.options | Add-Member skipPreflight $true
        Test-ConfigValid | Should -BeFalse
    }
}
