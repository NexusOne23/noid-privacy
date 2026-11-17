#Requires -Version 5.1

BeforeDiscovery {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $repo 'Modules/AdvancedSecurity/AdvancedSecurity.psm1') -Force
}

Describe 'AdvancedSecurity verification requires evidence for the complete selected scope' {
    InModuleScope AdvancedSecurity {
        BeforeAll {
            Set-Item -Path Function:Write-Log -Value {
                param($Level, $Message, $Module, $Exception)
                $null = $Level, $Message, $Module, $Exception
            }
        }

        BeforeEach {
            Set-StrictMode -Off
            $script:ScopeIntent = @{
                SecurityProfile = 'Maximum'; DisableRDP = $true; AdminSharesDisabled = $true
                DisableUPnP = $true; DisableWirelessDisplayCompletely = $true
                DisableDiscoveryProtocolsCompletely = $true; DisableIPv6Completely = $true
                SkipFirewallLayer = $false
            }
            $script:ScopeReplies = @{}
            foreach ($name in @('RDP', 'Shares', 'TLS', 'WPAD', 'Ports', 'Services', 'Update', 'Finger')) {
                $script:ScopeReplies[$name] = [pscustomobject]@{
                    Feature = $name; Status = 'Configured'; Compliant = $true; Details = 'Fixture state verified'
                }
            }
            $script:ScopeReplies.RDP | Add-Member -NotePropertyName RDP_DenyType -NotePropertyValue 'DWord'
            $script:ScopeReplies.RDP | Add-Member -NotePropertyName RDP_DenyValue -NotePropertyValue 1
            $script:ScopeReplies.Wireless = [pscustomobject]@{ FullyDisabled = $true; Compliant = $true }
            $script:ScopeReplies.Discovery = [pscustomobject]@{
                Compliant = $true; EnableMDNS = 0; FDResPubDisabled = $true
                FdPHostDisabled = $true; FirewallChecksSkipped = $false; FirewallRulesEnabled = 4
            }
            $script:ScopeReplies.Shields = [pscustomobject]@{ IsEnabled = $true; Pass = $true; Message = 'Verified' }
            $script:ScopeReplies.IPv6 = [pscustomobject]@{ Compliant = $true; Message = 'Verified' }
            Mock Write-Host {}
            Mock Write-Log {}
            Mock Write-FirewallControllerRuntimeWarning {}
            Mock Test-RdpSecurity { $script:ScopeReplies.RDP }
            Mock Test-AdminShares { $script:ScopeReplies.Shares }
            Mock Test-LegacyTLS { $script:ScopeReplies.TLS }
            Mock Test-WPAD { $script:ScopeReplies.WPAD }
            Mock Test-RiskyPorts { $script:ScopeReplies.Ports }
            Mock Test-RiskyServices { $script:ScopeReplies.Services }
            Mock Test-WindowsUpdate { $script:ScopeReplies.Update }
            Mock Test-FingerProtocol { $script:ScopeReplies.Finger }
            Mock Test-WirelessDisplaySecurity { $script:ScopeReplies.Wireless }
            Mock Test-DiscoveryProtocolsSecurity { $script:ScopeReplies.Discovery }
            Mock Test-FirewallShieldsUp { $script:ScopeReplies.Shields }
            Mock Test-IPv6Security { $script:ScopeReplies.IPv6 }
        }

        It 'accepts all twelve complete selected results' {
            $result = Test-AdvancedSecurity @script:ScopeIntent
            $result.Compliance | Should -Be 100
            $result.TotalChecks | Should -Be 12
            $result.Results.Count | Should -Be 12
        }

        It 'does not report full compliance after losing the selected <Feature> result' -TestCases @(
            @{ Feature = 'RDP' }, @{ Feature = 'Shares' }, @{ Feature = 'TLS' },
            @{ Feature = 'WPAD' }, @{ Feature = 'Ports' }, @{ Feature = 'Services' },
            @{ Feature = 'Update' }, @{ Feature = 'Finger' },
            @{ Feature = 'Wireless' }, @{ Feature = 'Discovery' }, @{ Feature = 'Shields' }, @{ Feature = 'IPv6' }
        ) {
            param($Feature)
            $script:ScopeReplies[$Feature] = $null
            $result = Test-AdvancedSecurity @script:ScopeIntent
            ($null -ne $result -and $result.Compliance -eq 100) | Should -BeFalse
        }

        It 'does not coerce malformed compliance evidence into full success: <Kind>' -TestCases @(
            @{ Kind = 'string' }, @{ Kind = 'integer' }, @{ Kind = 'array' }, @{ Kind = 'duplicate identity' },
            @{ Kind = 'wireless full string' }, @{ Kind = 'wireless base integer' }
        ) {
            param($Kind)
            switch ($Kind) {
                'string' { $script:ScopeReplies.TLS.Compliant = 'true' }
                'integer' { $script:ScopeReplies.TLS.Compliant = 1 }
                'array' { $script:ScopeReplies.TLS.Compliant = @($true, $false) }
                'duplicate identity' { $script:ScopeReplies.TLS.Feature = $script:ScopeReplies.RDP.Feature }
                'wireless full string' { $script:ScopeReplies.Wireless.FullyDisabled = 'false' }
                'wireless base integer' {
                    $script:ScopeIntent.DisableWirelessDisplayCompletely = $false
                    $script:ScopeReplies.Wireless.Compliant = 1
                }
            }
            $result = Test-AdvancedSecurity @script:ScopeIntent
            ($null -ne $result -and $result.Compliance -eq 100) | Should -BeFalse
        }

        It 'retains explicit skipped and inapplicable rows in the twelve-feature inventory' {
            $script:ScopeIntent.SecurityProfile = 'Balanced'
            $script:ScopeIntent.DisableRDP = $false
            $script:ScopeIntent.AdminSharesDisabled = $false
            $script:ScopeIntent.DisableWirelessDisplayCompletely = $false
            $script:ScopeIntent.DisableDiscoveryProtocolsCompletely = $false
            $script:ScopeIntent.DisableIPv6Completely = $false
            $script:ScopeIntent.SkipFirewallLayer = $true
            $result = Test-AdvancedSecurity @script:ScopeIntent -RdpHostSupported:$false -WirelessDisplaySupported:$false
            $result.Results.Count | Should -Be 12
            $result.Compliance | Should -Be 100
            $result.NotApplicableCount | Should -Be 2
            $result.NotCheckedCount | Should -Be 5
            $result.TotalChecks | Should -Be 5
        }
    }
}

AfterAll {
    Remove-Module AdvancedSecurity -ErrorAction SilentlyContinue
}
