#Requires -Version 5.1

BeforeAll {
    $script:Repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $script:Repo 'Core/Rollback.ps1')
    . (Join-Path $script:Repo 'Modules/SecurityBaseline/Private/SecurityBaselineDeviceGuardGpoStore.ps1')
    . (Join-Path $script:Repo 'Modules/SecurityBaseline/Private/Get-SecurityBaselineDeviceGuardPlan.ps1')
    Initialize-SecurityBaselineDeviceGuardGpoStore
    $script:AbsentDirectory = Join-Path $TestDrive 'absent-native-store'
    function Get-TestGpoState {
        [NoIDPrivacy.DeviceGuardGpoStore]::Read($script:AbsentDirectory) |
            ConvertTo-Json -Depth 10 | ConvertFrom-Json
    }
    function New-DeviceGuardSessionFixture {
        [CmdletBinding(SupportsShouldProcess)]
        param([switch]$Historical, [int]$Missing = -1, [switch]$Duplicate)
        if (-not $PSCmdlet.ShouldProcess($TestDrive, 'Create isolated session fixture')) { return }
        $id = 'Session_20260912_120000_000_' + [Guid]::NewGuid().ToString('N').Substring(0,8)
        $path = Join-Path $TestDrive $id
        $directory = Join-Path $path 'SecurityBaseline'
        $null = New-Item -ItemType Directory -Path $directory
        $gpo = Get-TestGpoState
        $targets = @(Get-SecurityBaselineDeviceGuardLocalBackupTargets)
        $targets += @(foreach ($value in $gpo.Values) {
                [pscustomobject]@{ KeyName='[SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; ValueName=$value.Name }
            })
        if ($Historical) { $targets = @() }
        elseif ($Missing -ge 0) { $targets = @(for ($i=0; $i -lt 28; $i++) { if ($i -ne $Missing) { $targets[$i] } }) }
        elseif ($Duplicate) { $targets += $targets[0].PSObject.Copy() }
        $registry = [pscustomobject]@{
            SchemaVersion=4; Computer=$targets; User=@(); ComputerClearKeys=@(); UserClearKeys=@()
            DirectiveCount=$targets.Count; AbsentAncestorKeys=@()
        }
        $names = @('RegistryPolicies','SecurityTemplate','UACStandardUserElevation','SecurityTemplateRegistryState','AuditPolicies','XboxTask')
        if (-not $Historical) { $names += 'DeviceGuardGpo' }
        $artifacts = @(foreach ($name in $names) {
                $extension = if ($name -eq 'SecurityTemplate') { '.inf' } else { '.json' }
                $file = Join-Path $directory ($name + $extension)
                $content = switch ($name) {
                    'DeviceGuardGpo' { $gpo | ConvertTo-Json -Depth 10 }
                    'RegistryPolicies' { $registry | ConvertTo-Json -Depth 10 }
                    default { '{}' }
                }
                [IO.File]::WriteAllText($file, $content)
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
            timestamp=$stamp; frameworkVersion=$(if ($Historical) { '2.2.5' } else { '2.2.6' })
            sharedArtifacts=@(); totalItems=$artifacts.Count; restorable=$true
            modules=@([pscustomobject]@{
                    name='SecurityBaseline'; backupPath='SecurityBaseline'; status='Success'
                    itemsBackedUp=$artifacts.Count; timestamp=$stamp; artifacts=$artifacts
                })
        }
        $manifest | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $path 'manifest.json') -Encoding UTF8
        [pscustomobject]@{ Path=$path; Manifest=$manifest; Gpo=$gpo; Registry=$registry }
    }
}

Describe 'Device Guard backup and prestate reconciliation' {
    BeforeEach {
        $script:CurrentGpo = Get-TestGpoState
        Mock Get-SecurityBaselineDeviceGuardGpoSnapshot { $script:CurrentGpo }
    }

    It 'writes valid original data once and refuses to overwrite an existing backup' {
        $path = Join-Path $TestDrive 'DeviceGuardGpo.json'
        $null = Backup-SecurityBaselineDeviceGuardGpo -BackupPath $path
        $hash = (Get-FileHash $path).Hash
        $saved = Get-Content $path -Raw | ConvertFrom-Json
        $null = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot $saved
        $saved.Values.Count | Should -Be 8
        $saved.PolicyFileSha256 | Should -BeNullOrEmpty
        { Backup-SecurityBaselineDeviceGuardGpo -BackupPath $path } | Should -Throw
        (Get-FileHash $path).Hash | Should -BeExactly $hash
        Test-Path $script:AbsentDirectory | Should -BeFalse
    }

    It 'does not write an artifact when native capture fails' {
        Mock Get-SecurityBaselineDeviceGuardGpoSnapshot { throw 'native capture failed' }
        $path = Join-Path $TestDrive 'failed.json'
        { Backup-SecurityBaselineDeviceGuardGpo -BackupPath $path } | Should -Throw '*native capture failed*'
        Test-Path $path | Should -BeFalse
    }

    It 'accepts unchanged prestate without changing its serialized data' {
        $saved = Get-TestGpoState
        $json = $saved | ConvertTo-Json -Depth 10 -Compress
        Assert-SecurityBaselineDeviceGuardGpoPrestate -Snapshot $saved | Should -BeTrue
        ($saved | ConvertTo-Json -Depth 10 -Compress) | Should -BeExactly $json
    }

    It 'rejects <Drift> after backup' -TestCases @(
        @{Drift='policy file'}, @{Drift='metadata file'}, @{Drift='editor'}, @{Drift='value'}
    ) {
        param($Drift)
        $saved = Get-TestGpoState
        switch ($Drift) {
            'policy file' { $script:CurrentGpo.PolicyFileSha256 = 'a' * 64 }
            'metadata file' { $script:CurrentGpo.GptFileSha256 = 'a' * 64 }
            'editor' { $script:CurrentGpo.RegistryEditorPresent = $true }
            'value' { $script:CurrentGpo.Values[0].Exists = $true }
        }
        { Assert-SecurityBaselineDeviceGuardGpoPrestate -Snapshot $saved } | Should -Throw '*changed after backup*'
    }
}

Describe 'Device Guard sealed session compatibility' {
    BeforeEach {
        # Isolate unrelated artifact formats. GPO validation, complete manifest
        # inventory/hashes and the GPO/registry coverage check remain real.
        Mock Assert-ArtifactContentBinding { } -ParameterFilter { $Artifact.name -ne 'DeviceGuardGpo' }
    }

    It 'accepts the historical six-artifact inventory without inventing local controls' {
        $fixture = New-DeviceGuardSessionFixture -Historical
        $before = $fixture.Manifest | ConvertTo-Json -Depth 10 -Compress
        { Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest } | Should -Not -Throw
        $fixture.Registry.Computer.Count | Should -Be 0
        ($fixture.Manifest | ConvertTo-Json -Depth 10 -Compress) | Should -BeExactly $before
        Test-Path (Join-Path $fixture.Path 'SecurityBaseline/DeviceGuardGpo.json') | Should -BeFalse
    }

    It 'accepts the additional sealed GPO artifact with all 28 recorded registry targets' {
        $fixture = New-DeviceGuardSessionFixture
        $fixture.Registry.Computer.Count | Should -Be 28
        { Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest } | Should -Not -Throw
    }

    It 'rejects a sealed GPO snapshot missing registry target <Missing>' -TestCases @(
        foreach ($index in 0..27) { @{Missing=$index} }
    ) {
        param($Missing)
        $fixture = New-DeviceGuardSessionFixture -Missing $Missing
        { Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest } |
            Should -Throw '*registry prestate is missing or duplicated*'
    }

    It 'rejects duplicated local registry prestate' {
        $fixture = New-DeviceGuardSessionFixture -Duplicate
        { Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest } |
            Should -Throw '*registry prestate is missing or duplicated*'
    }

    It 'rejects altered GPO content even with an updated file hash' {
        $fixture = New-DeviceGuardSessionFixture
        $path = Join-Path $fixture.Path 'SecurityBaseline/DeviceGuardGpo.json'
        $fixture.Gpo.Values[0].Name = 'ForeignValue'
        $fixture.Gpo | ConvertTo-Json -Depth 10 | Set-Content $path -Encoding UTF8
        @($fixture.Manifest.modules[0].artifacts | Where-Object name -eq DeviceGuardGpo)[0].sha256 = (Get-FileHash $path).Hash
        { Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest } |
            Should -Throw '*target identity differs*'
    }

    It 'rejects a missing sealed GPO file without treating the session as historical' {
        $fixture = New-DeviceGuardSessionFixture
        Remove-Item (Join-Path $fixture.Path 'SecurityBaseline/DeviceGuardGpo.json')
        { Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest } |
            Should -Throw '*Declared backup artifact does not exist*'
    }

    It 'recognizes an interrupted new GPO backup without reading or promoting its content' {
        $path = Join-Path $TestDrive 'SecurityBaseline'
        $directory = New-Item -ItemType Directory -Path $path
        $file = Join-Path $path 'DeviceGuardGpo.json'
        [IO.File]::WriteAllText($file, '{"incomplete":')
        $hash = (Get-FileHash $file).Hash
        Test-NoIDUnsealedModuleDirectory -Directory $directory | Should -BeTrue
        (Get-FileHash $file).Hash | Should -BeExactly $hash
    }
}
