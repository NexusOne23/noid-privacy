#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path (Join-Path $repo 'Core') 'Runtime.ps1')
    foreach ($helper in @('Get-AdvancedSecuritySchema5RegistryTargets',
            'Assert-AdvancedSecurityRegistrySnapshot', 'AdvancedSecurityFirewallPolicyState',
            'Restore-AdvancedSecurityRegistryState')) {
        . (Join-Path $repo "Modules/AdvancedSecurity/Private/$helper.ps1")
    }
    . (Join-Path $repo 'Modules/AdvancedSecurity/Public/Restore-AdvancedSecuritySettings.ps1')
    Set-Item -Path function:Write-Log -Value {
        param($Level, $Message, $Module, $Exception)
        $null = $Level, $Message, $Module, $Exception
    }
    function Get-AdvancedSecurityInteractiveUser {
        param([switch]$AllowNone)
        $null = $AllowNone
        throw 'Interactive user fixture must be mocked'
    }
    function Invoke-FirewallRestoreFixture {
        param([string]$PolicyPath)
        Set-StrictMode -Version Latest
        $parameters = @{ BackupPath=$script:ShieldsBackup; Confirm=$false }
        # Exercise the previous reader too, so the regression demonstrates its
        # stale engine state and failure to use the complete sealed policy.
        if ((Get-Command Restore-AdvancedSecurityRegistryState).Parameters.ContainsKey('FirewallPolicyBackupPath')) {
            $parameters.FirewallPolicyBackupPath = $PolicyPath
        }
        Restore-AdvancedSecurityRegistryState @parameters
    }
}

Describe 'Firewall Restore bounds the native audit-mode export default for older backups' {
    BeforeEach {
        $script:ReferenceEntries = @(
            [pscustomobject]@{Kind='Key';Path='';Name='';Type='';Data=''},
            [pscustomobject]@{Kind='Value';Path='';Name='PolicyVersion';Type='DWord';Data='545'}
        )
        $script:AuditEntry = [pscustomobject]@{Kind='Value';Path='';Name='EnableAuditMode';Type='DWord';Data='0'}
        $script:CandidateEntries = @($script:ReferenceEntries[0], $script:AuditEntry, $script:ReferenceEntries[1])
        Mock Get-AdvancedSecurityFirewallPolicyState {
            $items = if ($PolicyFilePath -ceq 'reference.wfw') { $script:ReferenceEntries } else { $script:CandidateEntries }
            [pscustomobject]@{SchemaVersion=1;EntryCount=@($items).Count;Entries=@($items)}
        }
    }

    It 'accepts only the added disabled native default during opted-in Restore comparison' {
        Assert-AdvancedSecurityFirewallPolicyEquivalent -ReferenceFilePath reference.wfw -CandidateFilePath candidate.wfw -AllowNativeAuditModeDefault | Should -BeTrue
        $script:CandidateEntries.Count | Should -Be 3
        $script:ReferenceEntries.Count | Should -Be 2
    }

    It 'keeps Backup and pre-Apply comparisons strict by default' {
        { Assert-AdvancedSecurityFirewallPolicyEquivalent -ReferenceFilePath reference.wfw -CandidateFilePath candidate.wfw } | Should -Throw '*entry count changed*'
    }

    It 'rejects a changed audit-mode field: <Field> = <Value>' -TestCases @(
        @{Field='Data';Value='1'}, @{Field='Data';Value='2'},
        @{Field='Type';Value='String'}, @{Field='Type';Value='QWord'},
        @{Field='Path';Value='PublicProfile'}, @{Field='Name';Value='OtherDefault'},
        @{Field='Name';Value='enableauditmode'}, @{Field='Kind';Value='Key'}
    ) {
        param($Field,$Value)
        $script:AuditEntry.$Field = $Value
        { Assert-AdvancedSecurityFirewallPolicyEquivalent -ReferenceFilePath reference.wfw -CandidateFilePath candidate.wfw -AllowNativeAuditModeDefault } | Should -Throw
    }

    It 'still rejects a different policy value beside the materialized default' {
        $script:CandidateEntries[2] = [pscustomobject]@{Kind='Value';Path='';Name='PolicyVersion';Type='DWord';Data='538'}
        { Assert-AdvancedSecurityFirewallPolicyEquivalent -ReferenceFilePath reference.wfw -CandidateFilePath candidate.wfw -AllowNativeAuditModeDefault } | Should -Throw '*property Data*'
    }

    It 'rejects loss or modification of an explicitly backed-up audit-mode setting' {
        $script:ReferenceEntries = @($script:CandidateEntries)
        $script:CandidateEntries = @($script:ReferenceEntries[0],$script:ReferenceEntries[2])
        { Assert-AdvancedSecurityFirewallPolicyEquivalent -ReferenceFilePath reference.wfw -CandidateFilePath candidate.wfw -AllowNativeAuditModeDefault } | Should -Throw
        $script:CandidateEntries = @($script:ReferenceEntries[0],[pscustomobject]@{Kind='Value';Path='';Name='EnableAuditMode';Type='DWord';Data='1'},$script:ReferenceEntries[2])
        { Assert-AdvancedSecurityFirewallPolicyEquivalent -ReferenceFilePath reference.wfw -CandidateFilePath candidate.wfw -AllowNativeAuditModeDefault } | Should -Throw '*property Data*'
    }

    It 'rejects duplicated export defaults' {
        $script:CandidateEntries = @($script:CandidateEntries) + $script:AuditEntry
        { Assert-AdvancedSecurityFirewallPolicyEquivalent -ReferenceFilePath reference.wfw -CandidateFilePath candidate.wfw -AllowNativeAuditModeDefault } | Should -Throw
    }
}

Describe 'AdvancedSecurity restores the sealed firewall before exact registry state' {
    BeforeEach {
        $script:ShieldsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'
        $script:ShieldsBackup = Join-Path $TestDrive 'prestate.json'
        $script:ShieldsPolicy = Join-Path $TestDrive 'policy.wfw'
        Set-Content -LiteralPath $script:ShieldsPolicy -Value 'Policy fixture; native import is mocked'
        $script:RestoreOperations = [Collections.Generic.List[string]]::new()
        $script:ActiveAllowRules = 'False'
        $script:ShieldsKey = [pscustomobject]@{ Exists=$true; Kind='DWord'; Data=1; SubKeyCount=0 }
        $script:ShieldsKey | Add-Member ScriptMethod GetValueNames {
            if ($this.Exists) { 'DoNotAllowExceptions' }
        }
        $script:ShieldsKey | Add-Member ScriptMethod GetValueKind {
            param($Name)
            $null = $Name
            [Microsoft.Win32.RegistryValueKind]$this.Kind
        }
        $script:ShieldsKey | Add-Member ScriptMethod GetValue {
            param($Name, $Default, $Options)
            $null = $Name, $Default, $Options
            $this.Data
        }
        $script:ShieldsSnapshot = [pscustomobject]@{
            SchemaVersion=5; CapturedAt=[DateTime]::UtcNow.ToString('o')
            EditionFamily='Professional'; RdpHostSupported=$true
            ManagedPolicySupported=$true; WirelessDisplaySupported=$true
            SkipFirewallLayer=$false; DisableRDP=$false; AdminSharesDisabled=$false
            DisableUPnP=$false; DisableWirelessDisplayCompletely=$false
            DisableDiscoveryProtocolsCompletely=$false; DisableIPv6Completely=$false
            EnableFirewallShieldsUp=$true; WinInetUsers=@(); TargetCount=1
            Entries=@([pscustomobject]@{
                Path=$script:ShieldsPath; Name='DoNotAllowExceptions'; KeyOnly=$false
                KeyExisted=$true; Exists=$true; Type='DWord'; Value=0
            })
        }
        Mock Get-AdvancedSecuritySchema5RegistryTargets {
            [pscustomobject]@{ Path=$script:ShieldsPath; Name='DoNotAllowExceptions'; KeyOnly=$false }
        }
        Mock Get-AdvancedSecurityInteractiveUser { $null }
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq $script:ShieldsPath }
        Mock Test-NoIDRegistryKey { $true } -ParameterFilter { $LiteralPath -eq $script:ShieldsPath }
        Mock Get-Item { $script:ShieldsKey } -ParameterFilter { $LiteralPath -eq $script:ShieldsPath }
        Mock New-ItemProperty {
            $script:RestoreOperations.Add('Registry')
            $script:ShieldsKey.Exists = $true
            $script:ShieldsKey.Kind = $PropertyType
            $script:ShieldsKey.Data = $Value
        }
        Mock Remove-ItemProperty {
            $script:RestoreOperations.Add('Registry')
            $script:ShieldsKey.Exists = $false
            $script:ShieldsKey.Kind = $null
            $script:ShieldsKey.Data = $null
        }
        Mock Set-NetFirewallProfile {
            # Model the native no-op: a raw DWORD write updates the persistent
            # getter first, so setting that same API value need not refresh the
            # still different active engine state.
            $persistent = if (-not $script:ShieldsKey.Exists) { 'NotConfigured' }
                elseif ($script:ShieldsKey.Data -eq 0) { 'True' } else { 'False' }
            if ($persistent -cne [string]$AllowInboundRules) {
                $script:ShieldsKey.Exists = $true
                $script:ShieldsKey.Kind = 'DWord'
                $script:ShieldsKey.Data = if ([string]$AllowInboundRules -eq 'True') { 0 } else { 1 }
                $script:ActiveAllowRules = [string]$AllowInboundRules
            }
        }
        Mock Get-NetFirewallProfile { [pscustomobject]@{ AllowInboundRules=$script:ActiveAllowRules } }
        Mock Restore-FirewallPolicy {
            $script:RestoreOperations.Add('Firewall')
            $entry = $script:ShieldsSnapshot.Entries[0]
            $script:ShieldsKey.Exists = $entry.Exists
            $script:ShieldsKey.Kind = $entry.Type
            # Native policy import can normalize a nonzero raw DWORD to one.
            # The subsequent exact registry restore must recover its saved bits.
            $script:ShieldsKey.Data = if ($entry.Exists -and $entry.Value -ne 0) { 1 } else { $entry.Value }
            $script:ActiveAllowRules = if ($entry.Exists -and $entry.Value -ne 0) { 'False' } else { 'True' }
            $true
        }
    }

    It 'restores the original <Label> and synchronizes through the sealed policy' -TestCases @(
        @{ Label='absent value'; Exists=$false; Value=$null },
        @{ Label='explicit DWORD zero'; Exists=$true; Value=0 },
        @{ Label='DWORD one'; Exists=$true; Value=1 },
        @{ Label='historical DWORD two'; Exists=$true; Value=2 },
        @{ Label='signed DWORD minus one'; Exists=$true; Value=-1 }
    ) {
        param($Label, $Exists, $Value)
        $null = $Label
        $entry = $script:ShieldsSnapshot.Entries[0]
        $entry.Exists = $Exists
        $entry.Value = $Value
        $entry.Type = if ($Exists) { 'DWord' } else { $null }
        $script:ShieldsSnapshot | ConvertTo-Json -Depth 12 | Set-Content $script:ShieldsBackup
        $result = Invoke-FirewallRestoreFixture -PolicyPath $script:ShieldsPolicy
        $result.Success | Should -BeTrue -Because ($result.Errors -join '; ')
        $script:ShieldsKey.Exists | Should -Be $Exists
        $script:ShieldsKey.Data | Should -Be $Value
        $script:ActiveAllowRules | Should -Be $(if ($Exists -and $Value -ne 0) { 'False' } else { 'True' })
        $script:RestoreOperations[0] | Should -Be 'Firewall'
        Should -Invoke Restore-FirewallPolicy -Times 1 -Exactly -ParameterFilter {
            $BackupFilePath -eq $script:ShieldsPolicy -and $Confirm -eq $false
        }
        Should -Invoke Set-NetFirewallProfile -Times 0 -Exactly
    }

    It 'passes a sealed firewall GPO editor registration of <Registered> to the firewall import' -TestCases @(
        @{ Registered=$false }, @{ Registered=$true }
    ) {
        param($Registered)
        $script:ShieldsSnapshot | Add-Member -NotePropertyName FirewallGpoEditorRegistered -NotePropertyValue $Registered
        $script:ShieldsSnapshot | ConvertTo-Json -Depth 12 | Set-Content $script:ShieldsBackup
        $result = Invoke-FirewallRestoreFixture -PolicyPath $script:ShieldsPolicy
        $result.Success | Should -BeTrue -Because ($result.Errors -join '; ')
        Should -Invoke Restore-FirewallPolicy -Times 1 -Exactly -ParameterFilter {
            $PesterBoundParameters.ContainsKey('SealedEditorRegistration') -and $SealedEditorRegistration -eq $Registered
        }
    }

    It 'keeps the 2.2.5 firewall import path when the prestate has no editor registration' {
        $script:ShieldsSnapshot | ConvertTo-Json -Depth 12 | Set-Content $script:ShieldsBackup
        $result = Invoke-FirewallRestoreFixture -PolicyPath $script:ShieldsPolicy
        $result.Success | Should -BeTrue -Because ($result.Errors -join '; ')
        Should -Invoke Restore-FirewallPolicy -Times 1 -Exactly -ParameterFilter {
            -not $PesterBoundParameters.ContainsKey('SealedEditorRegistration')
        }
    }

    It 'rejects an invalid sealed editor registration: <Label>' -TestCases @(
        @{ Label='non-Boolean value'; Value='false'; Skip=$false },
        @{ Label='registration beside a skipped firewall layer'; Value=$false; Skip=$true }
    ) {
        param($Label, $Value, $Skip)
        $null = $Label
        $script:ShieldsSnapshot | Add-Member -NotePropertyName FirewallGpoEditorRegistered -NotePropertyValue $Value
        if ($Skip) {
            $script:ShieldsPath = 'HKLM:\SOFTWARE\NoIDFixture'
            $script:ShieldsSnapshot.Entries[0].Path = $script:ShieldsPath
            $script:ShieldsSnapshot.SkipFirewallLayer = $true
            $script:ShieldsSnapshot.EnableFirewallShieldsUp = $false
        }
        { Assert-AdvancedSecurityRegistrySnapshot -Snapshot $script:ShieldsSnapshot -RestoreOnly } |
            Should -Throw '*invalid firewall GPO editor registration*'
    }

    It 'rejects a missing sealed firewall image before any registry write' {
        $script:ShieldsSnapshot | ConvertTo-Json -Depth 12 | Set-Content $script:ShieldsBackup
        $result = Invoke-FirewallRestoreFixture -PolicyPath (Join-Path $TestDrive 'missing.wfw')
        $result.Success | Should -BeFalse
        $script:RestoreOperations.Count | Should -Be 0
    }

    It 'stops before registry writes when the complete firewall import fails' {
        Mock Restore-FirewallPolicy { $false }
        $script:ShieldsSnapshot | ConvertTo-Json -Depth 12 | Set-Content $script:ShieldsBackup
        $result = Invoke-FirewallRestoreFixture -PolicyPath $script:ShieldsPolicy
        $result.Success | Should -BeFalse
        $script:RestoreOperations.Count | Should -Be 0
        Should -Invoke Restore-FirewallPolicy -Times 1 -Exactly
    }

    It 'restores a skipped firewall layer without requesting a policy import' {
        $script:ShieldsPath = 'HKLM:\SOFTWARE\NoIDFixture'
        $script:ShieldsSnapshot.Entries[0].Path = $script:ShieldsPath
        $script:ShieldsSnapshot.SkipFirewallLayer = $true
        $script:ShieldsSnapshot.EnableFirewallShieldsUp = $false
        $script:ShieldsSnapshot | ConvertTo-Json -Depth 12 | Set-Content $script:ShieldsBackup
        $result = Invoke-FirewallRestoreFixture
        $result.Success | Should -BeTrue -Because ($result.Errors -join '; ')
        $script:ShieldsKey.Data | Should -Be 0
        Should -Invoke Restore-FirewallPolicy -Times 0 -Exactly
    }

    It 'rejects a supplied firewall policy when the sealed layer was skipped' {
        $script:ShieldsPath = 'HKLM:\SOFTWARE\NoIDFixture'
        $script:ShieldsSnapshot.Entries[0].Path = $script:ShieldsPath
        $script:ShieldsSnapshot.SkipFirewallLayer = $true
        $script:ShieldsSnapshot.EnableFirewallShieldsUp = $false
        $script:ShieldsSnapshot | ConvertTo-Json -Depth 12 | Set-Content $script:ShieldsBackup
        $result = Invoke-FirewallRestoreFixture -PolicyPath $script:ShieldsPolicy
        $result.Success | Should -BeFalse
        $script:RestoreOperations.Count | Should -Be 0
        Should -Invoke Restore-FirewallPolicy -Times 0 -Exactly
    }

    It 'validates every saved registry value before importing the firewall image' {
        $script:ShieldsSnapshot.Entries[0].Value = 'invalid DWORD'
        $script:ShieldsSnapshot | ConvertTo-Json -Depth 12 | Set-Content $script:ShieldsBackup
        $result = Invoke-FirewallRestoreFixture -PolicyPath $script:ShieldsPolicy
        $result.Success | Should -BeFalse
        $script:RestoreOperations.Count | Should -Be 0
        Should -Invoke Restore-FirewallPolicy -Times 0 -Exactly
    }
}

Describe 'Firewall Restore removes the registry residue of netsh advfirewall import' {
    BeforeEach {
        $script:FirewallRoot = 'HKCU:\Software\NoIDPrivacyTests\FirewallPolicy-' + [guid]::NewGuid().ToString('N')
        foreach ($profileName in 'DomainProfile', 'PublicProfile', 'StandardProfile') {
            $logging = Join-Path (Join-Path $script:FirewallRoot $profileName) 'Logging'
            New-NoIDRegistryKey -LiteralPath $logging | Out-Null
            New-ItemProperty -LiteralPath $logging -Name LogFilePath -PropertyType ExpandString `
                -Value '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' | Out-Null
        }
        New-NoIDRegistryKey -LiteralPath (Join-Path $script:FirewallRoot 'PublicProfile\GloballyOpenPorts') | Out-Null
    }
    AfterEach {
        Remove-Item -LiteralPath $script:FirewallRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'removes only the empty legacy keys the import added and restores REG_EXPAND_SZ for an unchanged path' {
        $state = @(Get-AdvancedSecurityFirewallImportResidueState -Root $script:FirewallRoot)
        foreach ($profileName in 'DomainProfile', 'PublicProfile', 'StandardProfile') {
            $profilePath = Join-Path $script:FirewallRoot $profileName
            foreach ($legacy in 'AuthorizedApplications', 'GloballyOpenPorts') {
                New-NoIDRegistryKey -LiteralPath (Join-Path $profilePath $legacy) | Out-Null
            }
            New-ItemProperty -LiteralPath (Join-Path $profilePath 'Logging') -Name LogFilePath -PropertyType String `
                -Value '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' -Force | Out-Null
        }
        New-ItemProperty -LiteralPath (Join-Path $script:FirewallRoot 'DomainProfile\Logging') -Name LogFilePath -PropertyType String `
            -Value 'D:\other.log' -Force | Out-Null
        New-ItemProperty -LiteralPath (Join-Path $script:FirewallRoot 'StandardProfile\AuthorizedApplications') -Name Kept `
            -PropertyType DWord -Value 1 | Out-Null

        Restore-AdvancedSecurityFirewallImportResidue -Expected $state -Confirm:$false

        Test-NoIDRegistryKey -LiteralPath (Join-Path $script:FirewallRoot 'DomainProfile\AuthorizedApplications') | Should -BeFalse
        Test-NoIDRegistryKey -LiteralPath (Join-Path $script:FirewallRoot 'PublicProfile\GloballyOpenPorts') | Should -BeTrue
        Test-NoIDRegistryKey -LiteralPath (Join-Path $script:FirewallRoot 'StandardProfile\AuthorizedApplications') | Should -BeTrue
        (Get-Item -LiteralPath (Join-Path $script:FirewallRoot 'PublicProfile\Logging')).GetValueKind('LogFilePath') |
            Should -Be ([Microsoft.Win32.RegistryValueKind]::ExpandString)
        (Get-Item -LiteralPath (Join-Path $script:FirewallRoot 'DomainProfile\Logging')).GetValueKind('LogFilePath') |
            Should -Be ([Microsoft.Win32.RegistryValueKind]::String)
    }

    It 'captures the residue state before the import and reconciles it only after verified equivalence' {
        $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $restore = Get-Content -LiteralPath (Join-Path $repo 'Modules/AdvancedSecurity/Public/Restore-AdvancedSecuritySettings.ps1') -Raw
        $capture = $restore.IndexOf('$importResidue = @(Get-AdvancedSecurityFirewallImportResidueState)')
        $import = $restore.IndexOf("'advfirewall', 'import'", $capture)
        $verify = $restore.IndexOf("-Context 'Post-restore firewall policy verification'", $import)
        $reconcile = $restore.IndexOf('Restore-AdvancedSecurityFirewallImportResidue -Expected $importResidue', $verify)
        $capture | Should -BeGreaterThan -1
        $capture | Should -BeLessThan $import
        $import | Should -BeLessThan $verify
        $verify | Should -BeLessThan $reconcile
    }
}
