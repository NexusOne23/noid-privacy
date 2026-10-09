#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Core/Rollback.ps1')
    . (Join-Path $repo 'Core/IntentState.ps1')
    . (Join-Path $repo 'Core/DeviceGuardRecovery.ps1')
    . (Join-Path $repo 'Modules/SecurityBaseline/Private/Get-SecurityBaselineDeviceGuardPlan.ps1')
    . (Join-Path $repo 'Modules/SecurityBaseline/Private/SecurityBaselineDeviceGuardGpoStore.ps1')
    . (Join-Path $repo 'Modules/SecurityBaseline/Private/Restore-RegistryPolicies.ps1')
    Initialize-SecurityBaselineDeviceGuardGpoStore
    $script:RegistryValidationBody = (Get-Command Restore-RegistryPolicies).ScriptBlock

    function New-RecoverySourceFixture {
        [CmdletBinding(SupportsShouldProcess)]
        param()
        if (-not $PSCmdlet.ShouldProcess($TestDrive, 'Create isolated sealed session fixture')) { return }
        $id = 'Session_20260912_120000_000_' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $path = Join-Path $TestDrive $id
        $directory = Join-Path $path 'SecurityBaseline'
        $null = New-Item -ItemType Directory -Path $directory
        $gpo = [NoIDPrivacy.DeviceGuardGpoStore]::Read((Join-Path $TestDrive 'absent-gpo')) |
            ConvertTo-Json -Depth 10 | ConvertFrom-Json
        $targets = @(Get-SecurityBaselineDeviceGuardLocalBackupTargets)
        $targets += @(foreach ($value in $gpo.Values) {
                [pscustomobject]@{ KeyName='[SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; ValueName=$value.Name }
            })
        $registry = [pscustomobject]@{
            SchemaVersion=4; UserRegistryRoot='HKU:\S-1-5-21-101-202-303-1001'
            Computer=@(foreach ($target in $targets) {
                    [pscustomobject]@{
                        KeyName=$target.KeyName; ValueName=$target.ValueName; KeyExisted=$false; Exists=$false
                        Type='REG_DWORD'; OriginalValue=$null; OriginalValueName=$null
                    }
                })
            User=@(); ComputerClearKeys=@(); UserClearKeys=@(); AbsentAncestorKeys=@(); DirectiveCount=28
        }
        $names = @('RegistryPolicies', 'SecurityTemplate', 'UACStandardUserElevation',
            'SecurityTemplateRegistryState', 'AuditPolicies', 'XboxTask', 'DeviceGuardGpo')
        $artifacts = @(foreach ($name in $names) {
                $extension = if ($name -eq 'SecurityTemplate') { '.inf' } else { '.json' }
                $file = Join-Path $directory ($name + $extension)
                $content = switch ($name) {
                    'RegistryPolicies' { $registry | ConvertTo-Json -Depth 10 }
                    'DeviceGuardGpo' { $gpo | ConvertTo-Json -Depth 10 }
                    default { '{}' }
                }
                [IO.File]::WriteAllText($file, $content, [Text.UTF8Encoding]::new($true))
                $target = switch ($name) {
                    'DeviceGuardGpo' { 'SecurityBaselineDeviceGuardGpo' }
                    'SecurityTemplateRegistryState' { 'SecurityTemplateRegistryValues' }
                    'UACStandardUserElevation' { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser' }
                    default { $name }
                }
                [pscustomobject]@{
                    type='SecurityBaseline'; name=$name; target=$target
                    relativePath=('SecurityBaseline/' + $name + $extension); sha256=(Get-FileHash $file).Hash
                }
            })
        $stamp = '2026-09-12T12:00:00.0000000+00:00'
        $manifest = [pscustomobject]@{
            schemaVersion=2; sessionId=$id; displayName='Backup: SecurityBaseline'; sessionType='manual'
            timestamp=$stamp; frameworkVersion='2.2.6'; sharedArtifacts=@(); totalItems=7; restorable=$true
            modules=@([pscustomobject]@{
                    name='SecurityBaseline'; backupPath='SecurityBaseline'; status='Success'
                    itemsBackedUp=7; timestamp=$stamp; artifacts=$artifacts
                })
        }
        $manifest | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $path 'manifest.json') -Encoding UTF8
        [pscustomobject]@{ Path=$path; Manifest=$manifest; Gpo=$gpo; Registry=$registry }
    }
}

Describe 'Immutable recovery evidence for historical SecurityBaseline backups' {
    BeforeEach {
        $script:StateDirectory = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:StateDirectory
        $script:StatePath = Join-Path $script:StateDirectory 'deviceguard-legacy-recovery.json'
        Mock Get-NoIDDeviceGuardRecoveryPath { $script:StatePath }
        Mock Initialize-NoIDIntentStateDirectory { $script:StateDirectory }
        # ACL mechanics have native tests in IntentState; these tests exercise
        # this reader's refusal to accept an ACL failure, without host changes.
        Mock Set-NoIDIntentPathSecurity { }
        Mock Assert-NoIDIntentStateAcl { $true }
        Mock Assert-ArtifactContentBinding { } -ParameterFilter { $Artifact.name -ne 'DeviceGuardGpo' }
        Mock Restore-SecurityBaselineDeviceGuardGpo { throw 'Unexpected native GPO mutation' }
        Mock Get-SecurityBaselineDeviceGuardGpoSnapshot { throw 'Unexpected live GPO query' }
        $script:Fixture = New-RecoverySourceFixture
    }

    It 'retains only recorded local targets, original GPO bytes and source hashes without rewriting any backup' {
        $files = @(Get-ChildItem $script:Fixture.Path -File -Recurse)
        $before = @($files | Get-FileHash | ForEach-Object Hash)
        Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path
        $record = Read-NoIDDeviceGuardRecovery
        $local = $record.RegistryJson | ConvertFrom-Json
        $local.Computer.Count | Should -Be 20
        $local.DirectiveCount | Should -Be 20
        @($local.Computer | Where-Object KeyName -Like '*SOFTWARE*').Count | Should -Be 0
        ($local.Computer | ConvertTo-Json -Depth 12 -Compress) |
            Should -BeExactly ($script:Fixture.Registry.Computer[0..19] | ConvertTo-Json -Depth 12 -Compress)
        ($record.GpoJson | ConvertFrom-Json | ConvertTo-Json -Depth 12 -Compress) |
            Should -BeExactly ($script:Fixture.Gpo | ConvertTo-Json -Depth 12 -Compress)
        $record.SourceManifestSha256 | Should -BeExactly (Get-FileHash (Join-Path $script:Fixture.Path 'manifest.json')).Hash.ToLowerInvariant()
        (@($files | Get-FileHash | ForEach-Object Hash) -join '|') | Should -BeExactly ($before -join '|')
        @(Get-ChildItem $script:StateDirectory -File).Count | Should -Be 1
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
    }

    It 'never replaces the first supplement even if the original backup has moved or a later source is unavailable' {
        Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path
        $hash = (Get-FileHash $script:StatePath).Hash
        Move-Item $script:Fixture.Path ($script:Fixture.Path + '-moved')
        Initialize-NoIDDeviceGuardRecovery -SessionPath (Join-Path $TestDrive 'does-not-exist')
        (Get-FileHash $script:StatePath).Hash | Should -BeExactly $hash
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
    }

    It 'rejects a source artifact changed after sealing before publishing a supplement' {
        Add-Content (Join-Path $script:Fixture.Path 'SecurityBaseline/RegistryPolicies.json') ' '
        { Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path } | Should -Throw
        Test-Path $script:StatePath | Should -BeFalse
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
    }

    It 'rejects malformed recorded local data before publishing or touching native GPO state' {
        $regPath = Join-Path $script:Fixture.Path 'SecurityBaseline/RegistryPolicies.json'
        $script:Fixture.Registry.Computer[0].Exists = $true
        $script:Fixture.Registry | ConvertTo-Json -Depth 10 | Set-Content $regPath -Encoding UTF8
        @($script:Fixture.Manifest.modules[0].artifacts | Where-Object name -EQ RegistryPolicies)[0].sha256 = (Get-FileHash $regPath).Hash
        $script:Fixture.Manifest | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $script:Fixture.Path 'manifest.json') -Encoding UTF8
        { Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path } | Should -Throw '*inconsistent existence*'
        Test-Path $script:StatePath | Should -BeFalse
        @(Get-ChildItem $script:StateDirectory -File).Count | Should -Be 0
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
    }

    It 'fails closed for <Fault> in the protected record' -ForEach @(
        @{Fault='schema'}, @{Fault='hash'}, @{Fault='content'}, @{Fault='unknown field'}, @{Fault='permissions'}
    ) {
        Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path
        $record = Read-NoIDDeviceGuardRecovery
        switch ($Fault) {
            'schema' { $record.SchemaVersion = 9 }
            'hash' { $record.SourceGpoSha256 = 'invalid' }
            'content' { $record.RegistryJson += ' ' }
            'unknown field' { $record | Add-Member NoteProperty Unexpected 'untrusted' }
            'permissions' { Mock Assert-NoIDIntentStateAcl { throw 'Untrusted recovery permissions' } }
        }
        $record | ConvertTo-Json -Depth 6 | Set-Content $script:StatePath -Encoding UTF8
        $hash = (Get-FileHash $script:StatePath).Hash
        { Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path } | Should -Throw
        { Restore-NoIDLegacyDeviceGuard -Confirm:$false } | Should -Throw
        (Get-FileHash $script:StatePath).Hash | Should -BeExactly $hash
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
    }

    It 'does not manufacture recovery evidence if initialization is interrupted' {
        Mock Write-AtomicUtf8File { throw 'Interrupted publication' }
        { Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path } | Should -Throw '*Interrupted publication*'
        Test-Path $script:StatePath | Should -BeFalse
        @(Get-ChildItem $script:StateDirectory -File).Count | Should -Be 0
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
    }

    It 'accepts the supported byte boundary and rejects the next byte' {
        { Assert-NoIDDeviceGuardRecoverySize -ByteCount 134217728 } | Should -Not -Throw
        { Assert-NoIDDeviceGuardRecoverySize -ByteCount 134217729 } | Should -Throw '*exceeds the supported size*'
    }

    It 'rejects excessive serialized size before creating an immutable record' {
        Mock Assert-NoIDDeviceGuardRecoverySize { throw 'Device Guard recovery supplement exceeds the supported size' }
        Mock Write-AtomicUtf8File { throw 'Unexpected publication' }
        { Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path } | Should -Throw '*exceeds the supported size*'
        Should -Invoke Assert-NoIDDeviceGuardRecoverySize -ParameterFilter { $ByteCount -gt 0 } -Times 1 -Exactly
        Should -Invoke Write-AtomicUtf8File -Times 0 -Exactly
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
        Test-Path $script:StatePath | Should -BeFalse
        @(Get-ChildItem $script:StateDirectory -File).Count | Should -Be 0
    }

    It 'replays GPO before local prestate and remains reusable after repeated restores' {
        Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path
        $hash = (Get-FileHash $script:StatePath).Hash
        $script:ReplayOrder = [Collections.Generic.List[string]]::new()
        Mock Restore-SecurityBaselineDeviceGuardGpo { $script:ReplayOrder.Add('GPO') }
        Mock Restore-RegistryPolicies {
            if ($ValidateOnly) {
                return (& $script:RegistryValidationBody -BackupPath $BackupPath -DeviceGuardLocalOnly -ValidateOnly)
            }
            if (-not $DeviceGuardLocalOnly) { throw 'Foreign settings entered recovery scope' }
            $script:ReplayOrder.Add('Local')
            [pscustomobject]@{ Success=$true; ItemsVerified=20; Errors=@() }
        }
        1..2 | ForEach-Object { Restore-NoIDLegacyDeviceGuard -Confirm:$false | Should -BeTrue }
        ($script:ReplayOrder -join '|') | Should -BeExactly 'GPO|Local|GPO|Local'
        (Get-FileHash $script:StatePath).Hash | Should -BeExactly $hash
        @(Get-ChildItem $script:StateDirectory -File).Count | Should -Be 1
    }

    It 'does not replay local values when native GPO recovery fails' {
        Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path
        Mock Restore-SecurityBaselineDeviceGuardGpo { throw 'Native save failed' }
        Mock Restore-RegistryPolicies {
            if ($ValidateOnly) {
                return (& $script:RegistryValidationBody -BackupPath $BackupPath -DeviceGuardLocalOnly -ValidateOnly)
            }
            throw 'Unexpected local mutation'
        }
        { Restore-NoIDLegacyDeviceGuard -Confirm:$false } | Should -Throw '*Native save failed*'
        Should -Invoke Restore-RegistryPolicies -ParameterFilter { -not $ValidateOnly } -Times 0 -Exactly
        @(Get-ChildItem $script:StateDirectory -File).Count | Should -Be 1
    }

    It 'validates local records before GPO replay even when malformed content has a matching hash' {
        Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path
        $record = Read-NoIDDeviceGuardRecovery
        $local = $record.RegistryJson | ConvertFrom-Json
        $local.Computer[0].Exists = $true
        $record.RegistryJson = $local | ConvertTo-Json -Depth 12
        $record.RegistryJsonSha256 = Get-NoIDDeviceGuardRecoveryTextHash -Text $record.RegistryJson
        $record | ConvertTo-Json -Depth 6 | Set-Content $script:StatePath -Encoding UTF8
        { Restore-NoIDLegacyDeviceGuard -Confirm:$false } | Should -Throw '*registry contract is invalid*'
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
        @(Get-ChildItem $script:StateDirectory -File).Count | Should -Be 1
    }

    It 'reports incomplete local recovery instead of succeeding after a successful GPO save' {
        Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path
        Mock Restore-SecurityBaselineDeviceGuardGpo { $true }
        Mock Restore-RegistryPolicies {
            if ($ValidateOnly) {
                return (& $script:RegistryValidationBody -BackupPath $BackupPath -DeviceGuardLocalOnly -ValidateOnly)
            }
            [pscustomobject]@{ Success=$false; ItemsVerified=19; Errors=@('Recorded local value differs') }
        }
        { Restore-NoIDLegacyDeviceGuard -Confirm:$false } | Should -Throw '*Device Guard local recovery failed*'
        @(Get-ChildItem $script:StateDirectory -File).Count | Should -Be 1
    }

    It 'does not create replay files or call native mutation under WhatIf' {
        Initialize-NoIDDeviceGuardRecovery -SessionPath $script:Fixture.Path
        Restore-NoIDLegacyDeviceGuard -WhatIf | Should -BeFalse
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
        @(Get-ChildItem $script:StateDirectory -File).Count | Should -Be 1
    }

    It 'allows a historical restore without a supplement when NoID never registered the new backend' {
        Mock Get-SecurityBaselineDeviceGuardGpoSnapshot { $script:Fixture.Gpo }
        Restore-NoIDLegacyDeviceGuard -Confirm:$false | Should -BeFalse
        Test-Path $script:StatePath | Should -BeFalse
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
    }

    It 'refuses a false success when <Registration> remains but recovery evidence is missing' -ForEach @(
        @{Registration='RegistryEditorPresent'}, @{Registration='DeviceGuardEditorPresent'}
    ) {
        $script:Fixture.Gpo.$Registration = $true
        Mock Get-SecurityBaselineDeviceGuardGpoSnapshot { $script:Fixture.Gpo }
        { Restore-NoIDLegacyDeviceGuard -Confirm:$false } | Should -Throw '*supplement is missing*'
        Test-Path $script:StatePath | Should -BeFalse
        Should -Invoke Restore-SecurityBaselineDeviceGuardGpo -Times 0 -Exactly
    }
}
