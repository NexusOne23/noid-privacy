#Requires -Version 5.1

BeforeDiscovery {
    $script:InvalidComputerResults = @(
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

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path (Join-Path $repo 'Core') 'Runtime.ps1')
    . (Join-Path $repo 'Modules/EdgeHardening/Private/Get-EdgeRuntimeApplicability.ps1')
    . (Join-Path $repo 'Modules/Privacy/Private/Get-PrivacyManagementState.ps1')
    . (Join-Path $repo 'Modules/Privacy/Private/Get-PrivacyApplicability.ps1')
    . (Join-Path $repo 'Modules/Privacy/Private/Get-PrivacyUcpdProtectionState.ps1')
    if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        Set-Item -Path Function:Get-CimInstance -Value {
            [CmdletBinding()] param([string]$ClassName)
            throw "Unmocked CIM query: $ClassName"
        }
    }
    if (-not (Get-Command Get-Service -ErrorAction SilentlyContinue)) {
        Set-Item -Path Function:Get-Service -Value {
            [CmdletBinding()] param([string]$Name)
            throw "Unmocked service query: $Name"
        }
    }
    Set-Item -Path Function:Write-Log -Value {
        param($Level, $Message, $Module)
        $null = $Level, $Message, $Module
    }
}

Describe 'UCPD applicability evidence' {
    It 'does not turn a failed registry query into an absent unprotected driver' {
        $ErrorActionPreference = 'Continue'
        Mock Test-NoIDRegistryKey { throw 'Registry provider query failed' }
        Mock Get-Service { throw 'A failed registry query must not reach the service query' }
        $state = Get-PrivacyUcpdProtectionState 2>$null
        $state.StateKnown | Should -BeFalse
        $state.Active | Should -BeTrue
        $state.Status | Should -BeExactly 'Unknown'
        $state.Error | Should -BeLike '*Registry provider query failed*'
        Should -Invoke Get-Service -Times 0 -Exactly
    }

    It 'accepts proven driver absence' {
        Mock Test-NoIDRegistryKey { $false }
        Mock Get-Service { throw 'An absent driver must not reach the service query' }
        $state = Get-PrivacyUcpdProtectionState
        $state.StateKnown | Should -BeTrue
        $state.Installed | Should -BeFalse
        $state.Active | Should -BeFalse
        $state.Status | Should -BeExactly 'Absent'
        Should -Invoke Get-Service -Times 0 -Exactly
    }

    It 'accepts only a stopped driver as unprotected: <Status>' -TestCases @(
        @{ Status = 'Stopped'; Active = $false },
        @{ Status = 'Running'; Active = $true },
        @{ Status = 'StartPending'; Active = $true },
        @{ Status = 'StopPending'; Active = $true }
    ) {
        param($Status, $Active)
        $script:UcpdTestStatus = $Status
        Mock Test-NoIDRegistryKey { $true }
        Mock Get-Service { [pscustomobject]@{ Status = $script:UcpdTestStatus } }
        $state = Get-PrivacyUcpdProtectionState
        $state.StateKnown | Should -BeTrue
        $state.Installed | Should -BeTrue
        $state.Active | Should -Be $Active
        $state.Status | Should -BeExactly $Status
    }
}

Describe 'Domain evidence for policy applicability' {
    BeforeEach {
        Set-StrictMode -Off
        $script:ComputerResult = [pscustomobject]@{ PartOfDomain = $false }
        Mock Get-CimInstance {
            param($ClassName)
            if ($ClassName -eq 'Win32_ComputerSystem') { return $script:ComputerResult }
            if ($ClassName -eq 'Win32_OperatingSystem') {
                return [pscustomobject]@{ OperatingSystemSKU = [uint32]48 }
            }
            throw "Unexpected CIM class: $ClassName"
        }
        Mock Get-Item {
            $key = [pscustomobject]@{}
            $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
                param($Name, $Default)
                $null = $Name, $Default
                return 'Professional'
            }
            return $key
        }
        Mock Test-EdgeMdmRegistration { $false }
        Mock Test-PrivacyMdmRegistration { $false }
        Mock Write-Log {}
    }

    It 'rejects Edge applicability from <Label>' -TestCases $script:InvalidComputerResults {
        param($Label, $Result)
        $null = $Label
        $script:ComputerResult = $Result
        { Get-EdgeRuntimeApplicability } | Should -Throw '*domain-membership evidence*'
    }

    It 'keeps Privacy policies closed for <Label> while retaining non-policy preferences' -TestCases $script:InvalidComputerResults {
        param($Label, $Result)
        $null = $Label
        $script:ComputerResult = $Result
        $management = Get-PrivacyManagementState
        $management.StateKnown | Should -BeFalse
        $management.DomainJoinKnown | Should -BeFalse
        $management.MdmRegistrationKnown | Should -BeTrue
        $management.ExternallyManaged | Should -BeTrue
        @($management.QueryErrors).Count | Should -Be 1
        $management.QueryErrors[0] | Should -BeLike '*domain-membership evidence*'

        $applicability = [pscustomobject]@{
            EditionFamily = 'Enterprise'
            EnterprisePolicySupported = $true
            WindowsManagedPolicySupported = $true
            Tier1PolicyRemovalOsSupported = $true
            Tier1PolicyRemovalSupported = -not $management.ExternallyManaged
            ManagementStateKnown = $management.StateKnown
            DomainJoined = $management.DomainJoined
            MdmRegistered = $management.MdmRegistered
        }
        $tier1 = Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages' -Name 'Enabled' -Applicability $applicability
        $tier1.Applicable | Should -BeFalse
        $tier1.Reason | Should -BeLike '*could not be checked*'
        (Get-PrivacyTargetApplicability -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsSpotlightFeatures' -Applicability $applicability).Applicable | Should -BeFalse
        (Get-PrivacyTargetApplicability -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackProgs' -Applicability $applicability).Applicable | Should -BeTrue
    }

    It 'retains authoritative domain membership <Joined>' -TestCases @(
        @{ Joined = $false }, @{ Joined = $true }
    ) {
        param($Joined)
        $script:ComputerResult = [pscustomobject]@{ PartOfDomain = $Joined }
        $edge = Get-EdgeRuntimeApplicability
        $edge.DomainJoined | Should -Be $Joined
        $edge.ManagedWindowsEligible | Should -Be $Joined
        $privacy = Get-PrivacyManagementState
        $privacy.StateKnown | Should -BeTrue
        $privacy.DomainJoined | Should -Be $Joined
        $privacy.ExternallyManaged | Should -Be $Joined
        @($privacy.QueryErrors).Count | Should -Be 0
    }

    It 'retains MDM management when a valid domain query reports a workgroup' {
        Mock Test-EdgeMdmRegistration { $true }
        Mock Test-PrivacyMdmRegistration { $true }
        $edge = Get-EdgeRuntimeApplicability
        $edge.DomainJoined | Should -BeFalse
        $edge.ManagedWindowsEligible | Should -BeTrue
        $edge.EvidenceSource | Should -BeExactly 'WindowsMdmRegistrationApi'
        $privacy = Get-PrivacyManagementState
        $privacy.StateKnown | Should -BeTrue
        $privacy.MdmRegistered | Should -BeTrue
        $privacy.ExternallyManaged | Should -BeTrue
    }
}
