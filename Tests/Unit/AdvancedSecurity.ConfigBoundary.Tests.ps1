#Requires -Version 5.1

BeforeDiscovery {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $repo 'Modules/AdvancedSecurity/AdvancedSecurity.psm1') -Force
}

Describe 'AdvancedSecurity Apply stays within its sealed configuration contract' {
    InModuleScope AdvancedSecurity {
        BeforeAll {
            $script:OriginalUpdateConfig = Get-Content (Join-Path $script:ModuleRoot 'Config/WindowsUpdate.json') -Raw
            Set-Item -Path Function:Write-Log -Value {
                param($Level, $Message, $Module, $Exception)
                $null = $Level, $Message, $Module, $Exception
            }
            function Get-ConfigBoundaryKey {
                param([string]$Path)
                if (-not $script:ConfigBoundaryKeys.ContainsKey($Path)) {
                    $key = [pscustomobject]@{ Values = @{}; Kinds = @{} }
                    $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @($this.Values.Keys) }
                    $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value { param($Name) $this.Kinds[$Name] }
                    $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                        param($Name, $Default, $Options)
                        $null = $Options
                        if ($this.Values.ContainsKey($Name)) { return $this.Values[$Name] }
                        return $Default
                    }
                    $script:ConfigBoundaryKeys[$Path] = $key
                }
                return $script:ConfigBoundaryKeys[$Path]
            }
        }

        BeforeEach {
            Set-StrictMode -Off
            $script:UpdateApplyConfig = $script:OriginalUpdateConfig | ConvertFrom-Json
            $script:ConfigBoundaryKeys = @{}
            $script:ConfigBoundaryWrites = [Collections.Generic.List[object]]::new()
            Mock Write-Log {}
            Mock Write-Host {}
            Mock Test-Path { $true }
            Mock Test-NoIDRegistryKey { $true }
            Mock Get-Content { $script:UpdateApplyConfig | ConvertTo-Json -Depth 20 } -ParameterFilter {
                [string]$Path -like '*WindowsUpdate.json' -or [string]$LiteralPath -like '*WindowsUpdate.json'
            }
            Mock Get-Item { Get-ConfigBoundaryKey -Path ([string]$LiteralPath) }
            Mock New-Item { throw 'All fixture keys are present' }
            Mock New-NoIDRegistryKey { throw 'All fixture keys are present' }
            Mock Remove-ItemProperty {
                $key = Get-ConfigBoundaryKey -Path ([string]$LiteralPath)
                $key.Values.Remove([string]$Name)
                $key.Kinds.Remove([string]$Name)
            }
            Mock New-ItemProperty {
                $key = Get-ConfigBoundaryKey -Path ([string]$Path)
                $key.Values[[string]$Name] = $Value
                $key.Kinds[[string]$Name] = [string]$PropertyType
                $script:ConfigBoundaryWrites.Add([pscustomobject]@{ Path = [string]$Path; Name = [string]$Name; Value = $Value })
            }
        }

        It 'rejects Windows Update configuration drift before writes: <Change>' -TestCases @(
            @{ Change = 'registry root' }, @{ Change = 'value identity' }, @{ Change = 'missing policies' },
            @{ Change = 'wrong desired value' }, @{ Change = 'automatic optional updates' },
            @{ Change = 'missing optional-update choice' }, @{ Change = 'unsupported Home policies' },
            @{ Change = 'extra setting' }, @{ Change = 'extra value' },
            @{ Change = 'string edition flag' }, @{ Change = 'string value' }, @{ Change = 'wrong value type' }
        ) {
            param($Change)
            $managedEdition = $true
            switch ($Change) {
                'registry root' { $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.RegistryPath = 'HKLM:\SOFTWARE\NoID-Outside-Backup' }
                'value identity' {
                    $value = $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.Values.SetAllowOptionalContent
                    $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.Values = [pscustomobject]@{ OutsideBackup = $value }
                }
                'missing policies' {
                    $script:UpdateApplyConfig.Settings.PSObject.Properties.Remove('1_OptionalUpdatesPolicy')
                    $script:UpdateApplyConfig.Settings.PSObject.Properties.Remove('3_DeliveryOptimization')
                }
                'wrong desired value' { $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.Values.SetAllowOptionalContent.Value = 3 }
                'automatic optional updates' { $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.Values.AllowOptionalContent.Value = 1 }
                'missing optional-update choice' { $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.Values.PSObject.Properties.Remove('AllowOptionalContent') }
                'unsupported Home policies' {
                    $managedEdition = $false
                    $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.RequiresManagedPolicyEdition = $false
                    $script:UpdateApplyConfig.Settings.'3_DeliveryOptimization'.RequiresManagedPolicyEdition = $false
                }
                'extra setting' { $script:UpdateApplyConfig.Settings | Add-Member -NotePropertyName OutsideBackup -NotePropertyValue $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy' }
                'extra value' { $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.Values | Add-Member -NotePropertyName OutsideBackup -NotePropertyValue ([pscustomobject]@{ Type = 'DWord'; Value = 3 }) }
                'string edition flag' { $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.RequiresManagedPolicyEdition = 'true' }
                'string value' { $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.Values.SetAllowOptionalContent.Value = '3' }
                'wrong value type' { $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.Values.SetAllowOptionalContent.Type = 'String' }
            }
            Set-WindowsUpdate -ManagedPoliciesSupported:$managedEdition -Confirm:$false | Should -BeFalse
            $script:ConfigBoundaryWrites.Count | Should -Be 0
            Should -Invoke Remove-ItemProperty -Times 0 -Exactly
        }

        It 'enables the optional-updates policy with the user-selects choice (WindowsUpdate.admx)' {
            Set-WindowsUpdate -Confirm:$false | Should -BeTrue
            $policy = Get-ConfigBoundaryKey -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            $policy.Values.SetAllowOptionalContent | Should -Be 1
            $policy.Values.AllowOptionalContent | Should -Be 3
        }

        It 'applies the reviewed Windows Update edition scope: <Managed>' -TestCases @(
            @{ Managed = $true; Count = 4 }, @{ Managed = $false; Count = 1 }
        ) {
            param($Managed, $Count)
            Set-WindowsUpdate -ManagedPoliciesSupported:$Managed -Confirm:$false | Should -BeTrue
            $script:ConfigBoundaryWrites.Count | Should -Be $Count
            (Test-WindowsUpdate -ManagedPoliciesSupported:$Managed).Compliant | Should -BeTrue
        }

        It 'does not verify Windows Update through a reduced config scope' {
            Set-WindowsUpdate -Confirm:$false | Should -BeTrue
            $script:UpdateApplyConfig.Settings.PSObject.Properties.Remove('1_OptionalUpdatesPolicy')
            $script:UpdateApplyConfig.Settings.PSObject.Properties.Remove('3_DeliveryOptimization')
            (Test-WindowsUpdate).Compliant | Should -BeFalse
        }

        It 'uses the captured Windows Update plan throughout Apply and Verify after JSON drift' {
            $captured = $script:OriginalUpdateConfig | ConvertFrom-Json
            $script:UpdateApplyConfig.Settings.'1_OptionalUpdatesPolicy'.RegistryPath = 'HKLM:\SOFTWARE\NoID-Outside-Backup'
            Set-WindowsUpdate -Configuration $captured -Confirm:$false | Should -BeTrue
            (Test-WindowsUpdate -Configuration $captured).Compliant | Should -BeTrue
            $script:ConfigBoundaryWrites.Count | Should -Be 4
            Should -Invoke Get-Content -Times 0 -Exactly
            $owned = @(Get-AdvancedSecurityRegistryTargets | Where-Object { -not $_.KeyOnly } | ForEach-Object { "$($_.Path)|$($_.Name)" })
            foreach ($write in $script:ConfigBoundaryWrites) { $owned | Should -Contain "$($write.Path)|$($write.Name)" }
        }

        It 'stops Windows Update before writes when the user-choice registry cannot be inspected' {
            $ErrorActionPreference = 'Continue'
            Mock Test-Path { Write-Error 'User-choice registry unavailable'; $false } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
            }
            Set-WindowsUpdate -Confirm:$false 2>$null | Should -BeFalse
            $script:ConfigBoundaryWrites.Count | Should -Be 0
        }

        It 'preserves a readable stamped manual Windows Update opt-in' {
            $key = Get-ConfigBoundaryKey -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
            $key.Values.IsContinuousInnovationOptedIn = 1
            $key.Kinds.IsContinuousInnovationOptedIn = 'DWord'
            $key.Values.CIOptinModified = 1784342400000
            $key.Kinds.CIOptinModified = 'QWord'
            Set-WindowsUpdate -Confirm:$false | Should -BeTrue
            $script:ConfigBoundaryWrites.Count | Should -Be 3
            $key.Values.IsContinuousInnovationOptedIn | Should -Be 1
            (Test-WindowsUpdate).NotCheckedCount | Should -Be 1
        }
    }
}

AfterAll {
    Remove-Module AdvancedSecurity -ErrorAction SilentlyContinue
}
