#Requires -Version 5.1

BeforeDiscovery {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $repo 'Modules/AdvancedSecurity/AdvancedSecurity.psm1') -Force
    $script:InvalidDomainResults = @(
        @{ Label = 'no instance'; Result = $null },
        @{ Label = 'multiple instances'; Result = @(
            [pscustomobject]@{ PartOfDomain = $false },
            [pscustomobject]@{ PartOfDomain = $false }) },
        @{ Label = 'a missing property'; Result = [pscustomobject]@{ Other = 1 } },
        @{ Label = 'a null property'; Result = [pscustomobject]@{ PartOfDomain = $null } },
        @{ Label = 'a string Boolean'; Result = [pscustomobject]@{ PartOfDomain = 'false' } },
        @{ Label = 'a numeric Boolean'; Result = [pscustomobject]@{ PartOfDomain = 0 } }
    )
}

Describe 'AdvancedSecurity domain evidence before mutation' {
    InModuleScope AdvancedSecurity -Parameters @{ InvalidCases = $script:InvalidDomainResults } {
        param($InvalidCases)

        BeforeAll {
            Set-Item -Path Function:Write-Log -Value {
                param($Level, $Message, $Module, $Exception)
                $null = $Level, $Message, $Module, $Exception
            }
        }

        BeforeEach {
            Set-StrictMode -Off
            $script:ComputerResult = [pscustomobject]@{ PartOfDomain = $false }
            Mock Get-CimInstance { $script:ComputerResult } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
            Mock Get-AdvancedSecurityApplicability { throw 'Reached edition planning' }
            Mock Write-Log {}
            Mock Write-Host {}
            Mock Test-Path { $true }
            Mock Test-NoIDRegistryKey { $true }
            Mock New-Item { throw 'Existing fixture keys must not be created' }
            Mock New-NoIDRegistryKey { throw 'Existing fixture keys must not be created' }
            Mock New-ItemProperty {}
            Mock Remove-ItemProperty {}
            Mock Get-Item {
                $key = [pscustomobject]@{
                    Values = @{ AutoShareWks = 0; AutoShareServer = 0; UserAuthentication = 1; SecurityLayer = 2; fDenyTSConnections = 1 }
                }
                $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @($this.Values.Keys) }
                $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value { param($Name) $null = $Name; 'DWord' }
                $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($Name) $this.Values[$Name] }
                return $key
            }
        }

        It 'stops the public planner on <Label>' -TestCases $InvalidCases {
            param($Label, $Result)
            $null = $Label
            $script:ComputerResult = $Result
            $outcome = Invoke-AdvancedSecurity -SecurityProfile Balanced -DryRun
            $outcome.Success | Should -BeFalse
            $outcome.ErrorMessage | Should -BeLike '*domain-membership evidence*'
            Should -Invoke Get-AdvancedSecurityApplicability -Times 0 -Exactly
            Should -Invoke New-ItemProperty -Times 0 -Exactly
        }

        It 'leaves admin-share state untouched on <Label>, including Force' -TestCases $InvalidCases {
            param($Label, $Result)
            $null = $Label
            $script:ComputerResult = $Result
            foreach ($forceChoice in @($false, $true)) {
                Disable-AdminShares -SkipFirewallChanges -Force:$forceChoice -Confirm:$false | Should -BeFalse
            }
            Should -Invoke New-ItemProperty -Times 0 -Exactly
            Should -Invoke Remove-ItemProperty -Times 0 -Exactly
            Should -Invoke New-Item -Times 0 -Exactly
            Should -Invoke New-NoIDRegistryKey -Times 0 -Exactly
        }

        It 'leaves all RDP policy state untouched on <Label>, including Force' -TestCases $InvalidCases {
            param($Label, $Result)
            $null = $Label
            $script:ComputerResult = $Result
            foreach ($forceChoice in @($false, $true)) {
                Enable-RdpNLA -DisableRDP -Force:$forceChoice -Confirm:$false | Should -BeFalse
            }
            Should -Invoke New-ItemProperty -Times 0 -Exactly
            Should -Invoke Remove-ItemProperty -Times 0 -Exactly
            Should -Invoke New-Item -Times 0 -Exactly
            Should -Invoke New-NoIDRegistryKey -Times 0 -Exactly
        }

        It 'accepts native domain membership <Joined> in the public planner' -TestCases @(
            @{ Joined = $false }, @{ Joined = $true }
        ) {
            param($Joined)
            $script:ComputerResult = [pscustomobject]@{ PartOfDomain = $Joined }
            $outcome = Invoke-AdvancedSecurity -SecurityProfile Balanced -DryRun
            $outcome.ErrorMessage | Should -BeExactly 'Reached edition planning'
            Should -Invoke Get-AdvancedSecurityApplicability -Times 1 -Exactly
        }

        It 'preserves the admin-share domain decision: joined=<Joined>, force=<ForceChoice>' -TestCases @(
            @{ Joined = $false; ForceChoice = $false; Applied = $true; Writes = 2 },
            @{ Joined = $true; ForceChoice = $false; Applied = $false; Writes = 0 },
            @{ Joined = $true; ForceChoice = $true; Applied = $true; Writes = 2 }
        ) {
            param($Joined, $ForceChoice, $Applied, $Writes)
            $script:ComputerResult = [pscustomobject]@{ PartOfDomain = $Joined }
            Disable-AdminShares -SkipFirewallChanges -Force:$ForceChoice -Confirm:$false | Should -Be $Applied
            Should -Invoke New-ItemProperty -Times $Writes -Exactly
        }

        It 'preserves the RDP domain decision: joined=<Joined>, force=<ForceChoice>' -TestCases @(
            @{ Joined = $false; ForceChoice = $false; DisableWrites = 1 },
            @{ Joined = $true; ForceChoice = $false; DisableWrites = 0 },
            @{ Joined = $true; ForceChoice = $true; DisableWrites = 1 }
        ) {
            param($Joined, $ForceChoice, $DisableWrites)
            $script:ComputerResult = [pscustomobject]@{ PartOfDomain = $Joined }
            Enable-RdpNLA -DisableRDP -Force:$ForceChoice -Confirm:$false | Should -BeTrue
            Should -Invoke New-ItemProperty -Times $DisableWrites -Exactly -ParameterFilter { $Name -eq 'fDenyTSConnections' }
            Should -Invoke New-ItemProperty -Times 2 -Exactly -ParameterFilter { $Name -in @('UserAuthentication', 'SecurityLayer') }
        }

        It 'hardens NLA without querying domain membership when complete disable is unselected' {
            Mock Get-CimInstance { throw 'Unselected RDP disable must not need a domain query' }
            Enable-RdpNLA -Confirm:$false | Should -BeTrue
            Should -Invoke Get-CimInstance -Times 0 -Exactly
            Should -Invoke New-ItemProperty -Times 0 -Exactly -ParameterFilter { $Name -eq 'fDenyTSConnections' }
            Should -Invoke New-ItemProperty -Times 2 -Exactly
        }
    }
}

AfterAll {
    Remove-Module AdvancedSecurity -ErrorAction SilentlyContinue
}
