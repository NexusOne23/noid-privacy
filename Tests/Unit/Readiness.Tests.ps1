#Requires -Version 5.1
BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Core/Readiness.ps1')
}

Describe 'ASR preflight evidence and decisions' {
    BeforeEach {
        Mock Get-MpComputerStatus {
            [pscustomobject]@{ AMRunningMode='Normal'; AntivirusEnabled=$true; RealTimeProtectionEnabled=$true }
        }
        Mock Get-MpPreference { [pscustomobject]@{ MAPSReporting=2 } }
    }

    It 'accepts an active primary Defender with configured cloud protection' {
        $state = Get-NoIDASRReadiness
        $state.Defender | Should -BeExactly 'Active'
        $state.CloudProtection | Should -BeExactly 'Enabled'
    }

    It 'does not treat <Mode> as active primary protection' -ForEach @(
        @{Mode='Passive'}, @{Mode='EDR Block Mode'}, @{Mode='SxS Passive Mode'}
    ) {
        Mock Get-MpComputerStatus {
            [pscustomobject]@{ AMRunningMode=$Mode; AntivirusEnabled=$true; RealTimeProtectionEnabled=$true }
        }
        $state = Get-NoIDASRReadiness
        $state.Defender | Should -BeExactly 'Unavailable'
        $state.CloudProtection | Should -BeExactly 'Unknown'
        Should -Invoke Get-MpPreference -Times 0 -Exactly
    }

    It 'does not accept a string Boolean as proof of real-time protection' {
        Mock Get-MpComputerStatus {
            [pscustomobject]@{ AMRunningMode='Normal'; AntivirusEnabled=$true; RealTimeProtectionEnabled='false' }
        }
        (Get-NoIDASRReadiness).Defender | Should -BeExactly 'Unknown'
    }

    It 'keeps a status query failure distinct from a confirmed unavailable engine' {
        Mock Get-MpComputerStatus { throw 'fixture query failure' }
        (Get-NoIDASRReadiness).Defender | Should -BeExactly 'Unknown'
    }

    It 'does not mistake a cloud query failure for enabled protection' {
        Mock Get-MpPreference { throw 'fixture query failure' }
        (Get-NoIDASRReadiness).CloudProtection | Should -BeExactly 'Unknown'
    }

    It 'distinguishes disabled cloud protection from missing evidence' {
        Mock Get-MpPreference { [pscustomobject]@{ MAPSReporting=0 } }
        (Get-NoIDASRReadiness).CloudProtection | Should -BeExactly 'Disabled'
    }

    It 'rejects invalid MAPS data: <Label>' -ForEach @(
        @{Label='string'; Value='2'}, @{Label='Boolean'; Value=$true},
        @{Label='unknown integer'; Value=3}, @{Label='null'; Value=$null}
    ) {
        Mock Get-MpPreference { [pscustomobject]@{ MAPSReporting=$Value } }
        (Get-NoIDASRReadiness).CloudProtection | Should -BeExactly 'Unknown'
    }

    It 'requires an explicit partial-run decision when Defender is <State>' -ForEach @(
        @{State='Unavailable'}, @{State='Unknown'}
    ) {
        $state = [pscustomobject]@{Defender=$State; CloudProtection='Unknown'}
        foreach ($continue in @($true,$false)) {
            $blocked = Get-NoIDASRPreflightDecision $state $continue $false
            $blocked.Blocked | Should -BeTrue
            $blocked.SkipASR | Should -BeFalse
            $partial = Get-NoIDASRPreflightDecision $state $continue $true
            $partial.Blocked | Should -BeFalse
            $partial.SkipASR | Should -BeTrue
        }
    }

    It 'does not weaken the strict cloud choice: <Cloud>' -ForEach @(
        @{Cloud='Disabled'}, @{Cloud='Unknown'}
    ) {
        $state = [pscustomobject]@{Defender='Active'; CloudProtection=$Cloud}
        (Get-NoIDASRPreflightDecision $state $false $false).Blocked | Should -BeTrue
        (Get-NoIDASRPreflightDecision $state $false $true).SkipASR | Should -BeTrue
        $limited = Get-NoIDASRPreflightDecision $state $true $false
        $limited.Blocked | Should -BeFalse
        $limited.SkipASR | Should -BeFalse
    }

    It 'runs ASR normally when all prerequisites are proven' {
        $state = [pscustomobject]@{Defender='Active'; CloudProtection='Enabled'}
        $decision = Get-NoIDASRPreflightDecision $state $false $false
        $decision.Blocked | Should -BeFalse
        $decision.SkipASR | Should -BeFalse
        $decision.Reason | Should -BeNullOrEmpty
    }
}
