#Requires -Version 5.1

BeforeAll {
    $script:FrameworkRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $script:FrameworkRoot 'Core/Runtime.ps1')
    . (Join-Path $script:FrameworkRoot 'Core/QuickActions.ps1')
    foreach ($name in @('Get-MpComputerStatus', 'Get-MpPreference')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            Set-Item "Function:$name" { throw 'The Defender query must be mocked' }
        }
    }
}

Describe 'ASR Quick Actions require a running primary Defender engine' {
    BeforeEach {
        Mock Read-NoIDAsrRuntimeRecord { $null }
        Mock Get-MpPreference {
            [pscustomobject]@{
                AttackSurfaceReductionRules_Ids=@('d1e49aac-8f56-4280-b9ba-993a6d77406c','01443614-cd74-433a-b99e-2ecdc07bfc25')
                AttackSurfaceReductionRules_Actions=@(1,2)
            }
        }
        Mock Get-MpComputerStatus {
            [pscustomobject]@{AMRunningMode='Normal';AntivirusEnabled=$true;RealTimeProtectionEnabled=$true}
        }
        Mock Get-QuickActionRegistryValueState {
            [pscustomobject]@{kind='RegistryValue';path=$Path;name=$Name;keyExisted=$false;valueExisted=$false;type=$null;value=$null}
        }
    }

    It 'does not offer either ASR toggle for <Label> even with readable configured rules' -TestCases @(
        @{Label='passive mode';Mode='Passive Mode';Antivirus=$true;Realtime=$true},
        @{Label='EDR-only mode';Mode='EDR Block Mode';Antivirus=$true;Realtime=$true},
        @{Label='disabled antivirus';Mode='Normal';Antivirus=$false;Realtime=$true},
        @{Label='disabled realtime protection';Mode='Normal';Antivirus=$true;Realtime=$false},
        @{Label='unrecognized mode';Mode='Unknown';Antivirus=$true;Realtime=$true},
        @{Label='malformed status';Mode='Normal';Antivirus='true';Realtime=$true}
    ) {
        param($Label, $Mode, $Antivirus, $Realtime)
        $null = $Label, $Mode, $Antivirus, $Realtime
        Mock Get-MpComputerStatus {
            [pscustomobject]@{AMRunningMode=$Mode;AntivirusEnabled=$Antivirus;RealTimeProtectionEnabled=$Realtime}
        }
        $states = @(Get-AllQuickActionStates -ActionIds @('ManagementTools','NewSoftware'))
        $states.Count | Should -Be 2
        @($states | Where-Object actionable).Count | Should -Be 0
        @($states | Where-Object { $_.state -cne 'Unknown' }).Count | Should -Be 0
        Should -Invoke Get-MpComputerStatus -Times 1 -Exactly
    }

    It 'reads Defender authority once per batch and retains the two distinct rule choices' {
        $states = @(Get-AllQuickActionStates -ActionIds @('ManagementTools','NewSoftware'))
        @($states | Where-Object actionable).Count | Should -Be 2
        $states[0].state | Should -BeExactly 'Block'
        $states[1].state | Should -BeExactly 'Allow'
        Should -Invoke Get-MpComputerStatus -Times 1 -Exactly
        Should -Invoke Get-MpPreference -Times 1 -Exactly
    }

    It 'refuses a pending runtime recovery without treating registry readback as success' {
        Mock Read-NoIDAsrRuntimeRecord { [pscustomobject]@{Target='AsrPolicyRuntime'} }
        { Get-QuickActionAsrState -Definition (Get-QuickActionDefinition ManagementTools) } |
            Should -Throw '*interrupted ASR change*'
        Should -Invoke Get-MpPreference -Times 0 -Exactly
    }
}
