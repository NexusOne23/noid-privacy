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
        Mock Start-Sleep {}
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
        $tier1.ManagementUnknown | Should -BeTrue
        $tier1.Reason | Should -BeLike 'Device management could not be checked*'
        Should -Invoke Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' } -Times 3 -Exactly
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

    It 'retries a briefly failing domain query before Privacy treats ownership as unknown' {
        $script:DomainQueryCalls = 0
        Mock Get-CimInstance {
            param($ClassName)
            if ($ClassName -ne 'Win32_ComputerSystem') { throw "Unexpected CIM class: $ClassName" }
            $script:DomainQueryCalls++
            if ($script:DomainQueryCalls -eq 1) { throw 'WMI is starting' }
            return [pscustomobject]@{ PartOfDomain = $false }
        }
        $privacy = Get-PrivacyManagementState
        $privacy.StateKnown | Should -BeTrue
        $privacy.ExternallyManaged | Should -BeFalse
        @($privacy.QueryErrors).Count | Should -Be 0
        $script:DomainQueryCalls | Should -Be 2
        Should -Invoke Start-Sleep -Times 1 -Exactly
        Should -Invoke Write-Log -Times 0 -Exactly
    }

    It 'gives up after three failed attempts per query and warns once' {
        Mock Get-CimInstance { throw 'WMI repository is unavailable' }
        Mock Test-PrivacyMdmRegistration { throw 'MDM API unavailable' }
        $privacy = Get-PrivacyManagementState
        $privacy.StateKnown | Should -BeFalse
        $privacy.ExternallyManaged | Should -BeTrue
        @($privacy.QueryErrors).Count | Should -Be 2
        Should -Invoke Get-CimInstance -Times 3 -Exactly
        Should -Invoke Test-PrivacyMdmRegistration -Times 3 -Exactly
        Should -Invoke Start-Sleep -Times 4 -Exactly
        Should -Invoke Write-Log -Times 1 -Exactly
    }

    It 'names unknown ownership apart from a proven domain or MDM controller' {
        $base = @{
            EditionFamily = 'Professional'; EnterprisePolicySupported = $false; WindowsManagedPolicySupported = $true
            Tier1PolicyRemovalOsSupported = $false; Tier1PolicyRemovalSupported = $false
        }
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        $unknown = [pscustomobject]($base + @{ ManagementStateKnown = $false; DomainJoined = $false; MdmRegistered = $false })
        $unknownResult = Get-PrivacyTargetApplicability -Path $policyPath -Name 'AllowTelemetry' -Applicability $unknown
        $unknownResult.Applicable | Should -BeFalse
        $unknownResult.ManagementUnknown | Should -BeTrue
        $unknownResult.Reason | Should -BeExactly 'Device management could not be checked; Privacy leaves policies unchanged'

        $managed = [pscustomobject]($base + @{ ManagementStateKnown = $true; DomainJoined = $false; MdmRegistered = $true })
        $managedResult = Get-PrivacyTargetApplicability -Path $policyPath -Name 'AllowTelemetry' -Applicability $managed
        $managedResult.Applicable | Should -BeFalse
        $managedResult.ManagementUnknown | Should -BeFalse
        $managedResult.Reason | Should -BeExactly 'This PC is managed by an AD domain or MDM; Privacy leaves policies unchanged'

        # Malformed evidence counts as unknown, never as an unmanaged PC.
        $malformed = [pscustomobject]($base + @{ ManagementStateKnown = 'true'; DomainJoined = $false; MdmRegistered = $false })
        (Get-PrivacyTargetApplicability -Path $policyPath -Name 'AllowTelemetry' -Applicability $malformed).ManagementUnknown |
            Should -BeTrue
        Test-PrivacyManagementUnknown -Applicability $null | Should -BeTrue
    }

    It 'reports unknown ownership in Verify as not verifiable and a proven controller as not applicable' {
        $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $verifier = Get-Content (Join-Path $repo 'Tools/Verify-Complete-Hardening.ps1') -Raw -Encoding UTF8
        $verifier | Should -Match '\$privacyManagementUnknown = Test-PrivacyManagementUnknown -Applicability \$privacyApplicability'
        ([regex]::Matches($verifier, "VerificationReasonCode = 'Privacy\.ManagementUnknown'")).Count | Should -Be 3
        ([regex]::Matches($verifier, "VerificationDisposition = 'CannotVerify'\s+VerificationEvidenceSource = 'RuntimeQuery'\s+VerificationReasonCode = 'Privacy\.ManagementUnknown'")).Count |
            Should -Be 3
        ([regex]::Matches($verifier, 'if \(\$privacyPreserveManagedResources -and \$privacyManagementUnknown\) \{')).Count | Should -Be 2
        $verifier | Should -Not -Match 'Device management owns this setting or could not be checked'
    }
}
