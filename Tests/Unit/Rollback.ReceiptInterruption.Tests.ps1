#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Core/Rollback.ps1')
    . (Join-Path $repo 'Core/QuickActions.ps1')
    function Get-FrameworkVersion { return '2.2.6' }
    Set-Item Function:Write-Log -Value { param($Level, $Message, $Module); $null = $Level, $Message, $Module }

    function Get-ReceiptFixtureActionState {
        param([string]$State)
        $payload = [ordered]@{
            actionId='ManagementTools'; owningModule='ASR'; state=$State
            actionable=$true; reason=''; targetIds=@('registry:hklm:test:managementtools')
            targets=[ordered]@{ marker=$State; unrelatedEffectiveRules=[ordered]@{ fingerprint=('a' * 64) } }
        }
        $record = [ordered]@{ schemaVersion=1 }
        foreach ($key in $payload.Keys) { $record[$key] = $payload[$key] }
        $record.fingerprint = Get-QuickActionObjectSha256 -InputObject $payload
        return [pscustomobject]$record
    }

    function New-ReceiptFixtureSession {
        [CmdletBinding(SupportsShouldProcess)]
        param([string]$Root, [string]$Type)
        if (-not $PSCmdlet.ShouldProcess($Root, 'Create isolated receipt fixture')) { return }
        if ($Type -eq 'QuickAction') {
            $prepared = New-QuickActionPreparedSession -PreState (Get-ReceiptFixtureActionState Allow) `
                -DesiredState Block -BackupDirectory $Root -Confirm:$false
            $manifest = Complete-QuickActionSession -PreparedSession $prepared `
                -PostState (Get-ReceiptFixtureActionState Block) -Confirm:$false
            return @{ Path=$prepared.SessionPath; Manifest=$manifest; Scope='action:ManagementTools' }
        }
        $id = 'Session_20260905_120000_000_00000001'
        $path = Join-Path $Root $id
        $directory = Join-Path $path 'DNS'
        $null = New-Item -ItemType Directory -Path $directory -Force
        $artifact = Join-Path $directory 'state.json'
        [IO.File]::WriteAllText($artifact, '{}')
        $stamp = '2026-09-05T12:00:00.0000000+00:00'
        $manifest = [pscustomobject]@{
            schemaVersion=2; sessionId=$id; displayName='Backup: DNS'; sessionType='manual'
            timestamp=$stamp; frameworkVersion='2.2.5'; sharedArtifacts=@(); totalItems=1; restorable=$true
            modules=@([pscustomobject]@{
                name='DNS'; backupPath='DNS'; status='Success'; itemsBackedUp=1; timestamp=$stamp
                artifacts=@([pscustomobject]@{
                    type='DNS'; name='DNS_PreState'; target='DNS_PreState'; relativePath='DNS/state.json'
                    sha256=(Get-FileHash $artifact).Hash
                })
            })
        }
        $manifest | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $path 'manifest.json') -Encoding UTF8
        return @{ Path=$path; Manifest=$manifest; Scope='module:DNS' }
    }

    function Assert-ReceiptFixtureSession {
        param($Session, [string]$Type)
        if ($Type -eq 'QuickAction') {
            $null = Get-QuickActionSessionDocument -SessionPath $Session.Path
        }
        else {
            Assert-SessionManifest -SessionPath $Session.Path -Manifest $Session.Manifest
        }
    }
}

Describe 'Interrupted restore receipt metadata never becomes restore authority' {
    BeforeEach {
        # The module case isolates session-root validation; artifact content
        # validation has its own native/typed coverage. Quick Action artifacts
        # pass the real complete reader without these module-only seams.
        Mock Assert-AllowedModuleArtifact { }
        Mock Assert-ArtifactContentBinding { }
    }

    It 'keeps <Type> restorable with an uncommitted <Suffix> of <Length> bytes' -TestCases @(
        foreach ($type in @('QuickAction', 'Module')) {
            foreach ($suffix in @('tmp', 'replace-backup')) {
                foreach ($length in @(0, 128, 65536)) { @{Type=$type; Suffix=$suffix; Length=$length} }
            }
        }
    ) {
        param($Type, $Suffix, $Length)
        $session = New-ReceiptFixtureSession -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) -Type $Type -Confirm:$false
        Assert-ReceiptFixtureSession $session $Type
        $manifestPath = Join-Path $session.Path 'manifest.json'
        $manifestHash = (Get-FileHash $manifestPath).Hash
        $orphan = Join-Path $session.Path ('restore-receipt.json.' + ('1' * 32) + '.' + $Suffix)
        [IO.File]::WriteAllBytes($orphan, [byte[]]::new($Length))

        { Assert-ReceiptFixtureSession $session $Type } | Should -Not -Throw
        Get-SessionRestoreReceipt -SessionPath $session.Path -Manifest $session.Manifest | Should -BeNullOrEmpty
        $receipt = Write-SessionRestoreReceipt -SessionPath $session.Path -Manifest $session.Manifest -Scopes @($session.Scope) -Confirm:$false
        @($receipt.restoredScopes) | Should -Be @($session.Scope)
        Assert-ReceiptFixtureSession $session $Type
        (Get-FileHash $manifestPath).Hash | Should -BeExactly $manifestHash
        (Get-Item $orphan).Length | Should -Be $Length
    }

    It 'does not use the module-manifest exception for a Quick Action session' {
        $session = New-ReceiptFixtureSession -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) -Type QuickAction -Confirm:$false
        $path = Join-Path $session.Path ('manifest.json.' + ('1' * 32) + '.tmp')
        [IO.File]::WriteAllText($path, '{}')
        { Assert-ReceiptFixtureSession $session QuickAction } | Should -Throw '*undeclared*'
    }

    It 'rejects <Type> with foreign or oversized root file <Fault>' -TestCases @(
        foreach ($type in @('QuickAction', 'Module')) {
            foreach ($fault in @('foreign', 'missing-id', 'invalid-id', 'manifest', 'executable', 'oversized')) {
                @{Type=$type; Fault=$fault}
            }
        }
    ) {
        param($Type, $Fault)
        $session = New-ReceiptFixtureSession -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) -Type $Type -Confirm:$false
        Assert-ReceiptFixtureSession $session $Type
        $name = switch ($Fault) {
            'foreign' { 'foreign.tmp' }
            'missing-id' { 'restore-receipt.json.tmp' }
            'invalid-id' { 'restore-receipt.json.' + ('g' * 32) + '.tmp' }
            'manifest' { 'manifest.json.not-a-writer-id.tmp' }
            'executable' { 'restore-receipt.json.' + ('1' * 32) + '.tmp.ps1' }
            'oversized' { 'restore-receipt.json.' + ('1' * 32) + '.tmp' }
        }
        [IO.File]::WriteAllBytes((Join-Path $session.Path $name), [byte[]]::new($(if ($Fault -eq 'oversized') {65537} else {1})))
        { Assert-ReceiptFixtureSession $session $Type } | Should -Throw '*undeclared*'
    }

    It 'rejects a <Type> directory using a reserved transient file name' -TestCases @(
        @{Type='QuickAction'}, @{Type='Module'}
    ) {
        param($Type)
        $session = New-ReceiptFixtureSession -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) -Type $Type -Confirm:$false
        $null = New-Item -ItemType Directory -Path (Join-Path $session.Path ('restore-receipt.json.' + ('1' * 32) + '.tmp'))
        { Assert-ReceiptFixtureSession $session $Type } | Should -Throw '*undeclared*'
    }

    It 'rejects a <Type> reparse-point file using a reserved transient name' -TestCases @(
        @{Type='QuickAction'}, @{Type='Module'}
    ) {
        param($Type)
        $session = New-ReceiptFixtureSession -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) -Type $Type -Confirm:$false
        $outside = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.json')
        [IO.File]::WriteAllText($outside, '{}')
        $link = Join-Path $session.Path ('restore-receipt.json.' + ('1' * 32) + '.tmp')
        $null = New-Item -ItemType SymbolicLink -Path $link -Target $outside -ErrorAction Stop
        { Assert-ReceiptFixtureSession $session $Type } | Should -Throw
        Get-Content $outside -Raw | Should -BeExactly '{}'
    }

    It 'still rejects a corrupt canonical receipt in <Type> beside an orphan' -TestCases @(
        @{Type='QuickAction'}, @{Type='Module'}
    ) {
        param($Type)
        $session = New-ReceiptFixtureSession -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) -Type $Type -Confirm:$false
        [IO.File]::WriteAllText((Join-Path $session.Path ('restore-receipt.json.' + ('1' * 32) + '.tmp')), '{}')
        Assert-ReceiptFixtureSession $session $Type
        [IO.File]::WriteAllText((Join-Path $session.Path 'restore-receipt.json'), '{')
        { Assert-ReceiptFixtureSession $session $Type } | Should -Throw
    }

    It 'still rejects a changed sealed artifact in <Type> beside an orphan' -TestCases @(
        @{Type='QuickAction'}, @{Type='Module'}
    ) {
        param($Type)
        $session = New-ReceiptFixtureSession -Root (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) -Type $Type -Confirm:$false
        [IO.File]::WriteAllText((Join-Path $session.Path ('restore-receipt.json.' + ('1' * 32) + '.tmp')), '{}')
        Assert-ReceiptFixtureSession $session $Type
        $artifact = if ($Type -eq 'QuickAction') { 'prestate.json' } else { 'DNS/state.json' }
        [IO.File]::WriteAllText((Join-Path $session.Path $artifact), 'changed')
        { Assert-ReceiptFixtureSession $session $Type } | Should -Throw
    }
}
