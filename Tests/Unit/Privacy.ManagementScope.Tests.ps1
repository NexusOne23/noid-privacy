#Requires -Version 5.1
BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/Privacy/Private/Get-PrivacyApplicability.ps1')
    . (Join-Path $repo 'Modules/Privacy/Private/Get-PrivacyTargetPlan.ps1')
    . (Join-Path $repo 'Modules/Privacy/Private/Get-PrivacyRuntimeTargetPlan.ps1')
    function Write-Log {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Test placeholder for the engine logger.')]
        [CmdletBinding()] param($Level,$Message,$Module) $null=$Level,$Message,$Module
    }
    function Get-PrivacyRegistryTargets {
        param($Config) $null=$Config
        @(
            [pscustomobject]@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync';Name='DisableSettingSync';Type='DWord';Value=2},
            [pscustomobject]@{Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';Name='Start_TrackProgs';Type='DWord';Value=0}
        )
    }
    function Get-NoIDScheduledTask {
        [pscustomobject]@{TaskPath='\Microsoft\Windows\NoIDTest\';TaskName='Task'}
    }
}

Describe 'Privacy preserves device-management ownership' {
    BeforeEach {
        $script:ownership = [pscustomobject]@{
            EditionFamily='Professional';EnterprisePolicySupported=$false;WindowsManagedPolicySupported=$true
            ManagementStateKnown=$true;DomainJoined=$false;MdmRegistered=$false
        }
        Mock Get-PrivacyApplicability { $script:ownership }
        Mock Get-Service { @([pscustomobject]@{Name='DiagTrack'},[pscustomobject]@{Name='dmwappushservice'}) }
        $script:config = [pscustomobject]@{
            Mode='Strict'
            Services=@([pscustomobject]@{Name='DiagTrack';StartupType='Disabled'},[pscustomobject]@{Name='dmwappushservice';StartupType='Disabled'})
            ScheduledTasks=@('\Microsoft\Windows\NoIDTest\Task')
        }
    }

    It 'applies the full declared scope on a positively identified unmanaged PC' {
        $plan = Get-PrivacyRuntimeTargetPlan $script:config
        $plan.ApplicableChecks | Should -Be 5
        $plan.NotApplicableChecks | Should -Be 0
        @($plan.PreservedServiceNames).Count | Should -Be 0
        @($plan.PreservedScheduledTaskPaths).Count | Should -Be 0
    }

    It 'preserves policy, services and tasks for <Case>, retaining user preferences' -ForEach @(
        @{Case='AD domain';Field='DomainJoined';Value=$true},
        @{Case='MDM';Field='MdmRegistered';Value=$true},
        @{Case='unknown ownership';Field='ManagementStateKnown';Value=$false},
        @{Case='malformed ownership';Field='ManagementStateKnown';Value='true'}
    ) {
        $script:ownership.($Field) = $Value
        $plan = Get-PrivacyRuntimeTargetPlan $script:config
        $plan.DeclaredChecks | Should -Be 5
        $plan.ApplicableChecks | Should -Be 1
        $plan.NotApplicableChecks | Should -Be 4
        @($plan.ApplicableServiceNames).Count | Should -Be 0
        @($plan.ApplicableScheduledTaskPaths).Count | Should -Be 0
        @($plan.PreservedServiceNames) | Should -Contain 'dmwappushservice'
        @($plan.PreservedServiceNames).Count | Should -Be 2
        @($plan.PreservedScheduledTaskPaths).Count | Should -Be 1
        $plan.RegistryPlan.ApplicableTargets[0].Name | Should -BeExactly 'Start_TrackProgs'
        $plan.RegistryPlan.NotApplicableTargets[0].Reason | Should -Match '(managed|management)'
    }

    It 'preserves per-user policy paths as well as machine policy paths' {
        $script:ownership.MdmRegistered=$true
        foreach ($path in @(
                'HKCU:\Software\Policies\Microsoft\Windows\CloudContent',
                'HKU:\S-1-5-21-1-2-3-1001\Software\Policies\Microsoft\Windows\CloudContent',
                'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput'
            )) {
            (Get-PrivacyTargetApplicability -Path $path -Name 'Fixture' -Applicability $script:ownership).Applicable | Should -BeFalse
        }
    }
}
