#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $script:RepoRoot 'Tools/Private/Get-SecurityBaselineRuntimeStatus.ps1')
    # Pester can only mock existing commands. Supply fail-closed placeholders
    # for isolated non-Windows runs; every test below mocks them.
    foreach ($nativeCommand in @('Get-CimInstance', 'Get-WinEvent')) {
        if (-not (Get-Command $nativeCommand -ErrorAction SilentlyContinue)) {
            Set-Item -Path "Function:script:$nativeCommand" -Value {
                [CmdletBinding()] param($ClassName, $Namespace, $FilterHashtable, $MaxEvents)
                $null = $ClassName, $Namespace, $FilterHashtable, $MaxEvents
                throw 'The native query must be mocked'
            }
        }
    }
}

Describe 'SecurityBaseline runtime observations' {
    BeforeEach {
        $script:Boot = (Get-Date).AddHours(-1)
        $script:Guard = [pscustomobject]@{
            VirtualizationBasedSecurityStatus = [uint32]2
            SecurityServicesConfigured = [uint32[]]@(1,2,3,5)
            SecurityServicesRunning = [uint32[]]@(1,2,3,5)
        }
        $script:BootEvent = [pscustomobject]@{
            Id=12; ProviderName='Microsoft-Windows-Wininit'; TimeCreated=$script:Boot.AddSeconds(1)
        }
        Mock Get-CimInstance { $script:Guard } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }
        Mock Get-CimInstance { [pscustomobject]@{ LastBootUpTime=$script:Boot } } `
            -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }
        Mock Get-WinEvent { $script:BootEvent }
    }

    It 'reports native running protections and only current-boot evidence for LSA' {
        $result = Get-SecurityBaselineRuntimeStatus
        @($result.Features | Where-Object State -eq Running).Count | Should -Be 5
        $result.Features[5].State | Should -BeExactly 'ProtectedAtBoot'
        $result.Features[5].Label | Should -BeExactly 'Protected at this boot'
        Should -Invoke Get-CimInstance -Times 1 -Exactly -ParameterFilter {
            $ClassName -eq 'Win32_DeviceGuard' -and $Namespace -eq 'root\Microsoft\Windows\DeviceGuard'
        }
        Should -Invoke Get-WinEvent -Times 1 -Exactly -ParameterFilter {
            $FilterHashtable.Id -eq 12 -and $FilterHashtable.StartTime -eq $script:Boot -and $MaxEvents -eq 1
        }
    }

    It 'does not confuse configured services with running protection' {
        $script:Guard.VirtualizationBasedSecurityStatus = [uint32]1
        $script:Guard.SecurityServicesRunning = [uint32[]]@(0)
        $result = Get-SecurityBaselineRuntimeStatus
        @($result.Features | Where-Object State -eq NotRunning).Count | Should -Be 5
        $result.Features[0].Label | Should -BeExactly 'Enabled, not running'
        $result.Features[5].State | Should -BeExactly 'ProtectedAtBoot'
    }

    It 'retains the observed state without guessing support from an edition' {
        $script:Guard.SecurityServicesRunning = [uint32[]]@(2)
        $result = Get-SecurityBaselineRuntimeStatus
        $result.Features[1].State | Should -BeExactly 'Running'
        $result.Features[2].State | Should -BeExactly 'NotRunning'
        ($result | ConvertTo-Json -Depth 5) | Should -Not -Match 'unsupported|not applicable'
    }

    It 'distinguishes audit mode from enforced kernel stack protection' {
        $script:Guard.SecurityServicesRunning = [uint32[]]@(2,6)
        (Get-SecurityBaselineRuntimeStatus).Features[4].State | Should -BeExactly 'Audit'
    }

    It 'reports unavailable evidence for <Fault> without inventing disabled state' -TestCases @(
        @{Fault='missing status'}, @{Fault='missing services'}, @{Fault='empty services'},
        @{Fault='Boolean status'}, @{Fault='string service'}, @{Fault='negative service'},
        @{Fault='fractional service'}, @{Fault='unknown status'}, @{Fault='zero with active service'},
        @{Fault='VBS stopped with HVCI running'}
    ) {
        param($Fault)
        switch ($Fault) {
            'missing status' { $script:Guard.PSObject.Properties.Remove('VirtualizationBasedSecurityStatus') }
            'missing services' { $script:Guard.PSObject.Properties.Remove('SecurityServicesRunning') }
            'empty services' { $script:Guard.SecurityServicesRunning = @() }
            'Boolean status' { $script:Guard.VirtualizationBasedSecurityStatus = $true }
            'string service' { $script:Guard.SecurityServicesRunning = @('2') }
            'negative service' { $script:Guard.SecurityServicesRunning = @(-1) }
            'fractional service' { $script:Guard.SecurityServicesRunning = @(1.5) }
            'unknown status' { $script:Guard.VirtualizationBasedSecurityStatus = 99 }
            'zero with active service' { $script:Guard.SecurityServicesRunning = @(0,2) }
            'VBS stopped with HVCI running' { $script:Guard.VirtualizationBasedSecurityStatus = 0 }
        }
        $result = Get-SecurityBaselineRuntimeStatus
        @($result.Features | Where-Object State -eq Unavailable).Count | Should -Be 5
        $result.Features[5].State | Should -BeExactly 'ProtectedAtBoot'
    }

    It 'keeps Device Guard provider failure independent from LSA and omits raw errors' {
        Mock Get-CimInstance { throw 'PRIVATE-PROVIDER-CONTENT' } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }
        $result = Get-SecurityBaselineRuntimeStatus
        @($result.Features | Where-Object State -eq Unavailable).Count | Should -Be 5
        $result.Features[5].State | Should -BeExactly 'ProtectedAtBoot'
        ($result | ConvertTo-Json -Depth 5) | Should -Not -Match 'PRIVATE-PROVIDER-CONTENT'
    }

    It 'never uses <Fault> as evidence of current-boot LSA protection' -TestCases @(
        @{Fault='earlier boot'}, @{Fault='other provider'}, @{Fault='other event'}, @{Fault='missing timestamp'}
    ) {
        param($Fault)
        switch ($Fault) {
            'earlier boot' { $script:BootEvent.TimeCreated = $script:Boot.AddSeconds(-1) }
            'other provider' { $script:BootEvent.ProviderName = 'Other' }
            'other event' { $script:BootEvent.Id = 13 }
            'missing timestamp' { $script:BootEvent.TimeCreated = $null }
        }
        $result = Get-SecurityBaselineRuntimeStatus
        $result.Features[5].State | Should -BeExactly 'NoEvidence'
        @($result.Features | Where-Object State -eq Running).Count | Should -Be 5
    }

    It 'distinguishes an empty event log from an unreadable event log' {
        Mock Get-WinEvent {
            $exception = [InvalidOperationException]::new('No matching events')
            $record = [System.Management.Automation.ErrorRecord]::new($exception, 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand', 'ObjectNotFound', $null)
            throw $record
        }
        (Get-SecurityBaselineRuntimeStatus).Features[5].State | Should -BeExactly 'NoEvidence'
        Mock Get-WinEvent { throw 'Access denied PRIVATE-EVENT-CONTENT' }
        $result = Get-SecurityBaselineRuntimeStatus
        $result.Features[5].State | Should -BeExactly 'Unavailable'
        ($result | ConvertTo-Json -Depth 5) | Should -Not -Match 'PRIVATE-EVENT-CONTENT'
    }

    It 'does not infer current-boot evidence without a valid boot time' {
        $script:Boot = $null
        (Get-SecurityBaselineRuntimeStatus).Features[5].State | Should -BeExactly 'Unavailable'
        Should -Invoke Get-WinEvent -Times 0 -Exactly
    }
}
