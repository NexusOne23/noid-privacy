#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Core/Rollback.ps1')
    . (Join-Path $repo 'Core/QuickActions.ps1')
    . (Join-Path $repo 'Core/IntentState.ps1')
    function Get-FrameworkVersion { '2.2.6' }
    Set-Item Function:Write-Log -Value { param($Level,$Message,$Module); $null=$Level,$Message,$Module }

    function New-InterruptedBackupFixture {
        [CmdletBinding(SupportsShouldProcess)]
        param([string]$Root,[string]$SealedModule='DNS')
        if(-not $PSCmdlet.ShouldProcess($Root,'Create isolated interrupted-backup fixture')){return}
        $id='Session_20260905_120000_000_'+[Guid]::NewGuid().ToString('N').Substring(0,8)
        $path=Join-Path $Root $id
        $directory=Join-Path $path $SealedModule
        $null=New-Item -ItemType Directory -Path $directory -Force
        $artifact=Join-Path $directory 'state.json'
        [IO.File]::WriteAllText($artifact,'{}')
        $stamp='2026-09-05T12:00:00.0000000+00:00'
        $manifest=[pscustomobject]@{
            schemaVersion=2; sessionId=$id; displayName="Backup: $SealedModule"; sessionType='manual'
            timestamp=$stamp; frameworkVersion='2.2.5'; sharedArtifacts=@(); totalItems=1; restorable=$true
            modules=@([pscustomobject]@{
                name=$SealedModule; backupPath=$SealedModule; status='Success'; itemsBackedUp=1; timestamp=$stamp
                artifacts=@([pscustomobject]@{
                    type=$SealedModule; name=($SealedModule+'_PreState'); target=($SealedModule+'_PreState')
                    relativePath=($SealedModule+'/state.json'); sha256=(Get-FileHash $artifact).Hash
                })
            })
        }
        $manifest|ConvertTo-Json -Depth 10|Set-Content (Join-Path $path 'manifest.json') -Encoding UTF8
        return @{Path=$path;Manifest=$manifest;Artifact=$artifact}
    }
}

Describe 'Interrupted module preparation cannot authorize unsealed state' {
    BeforeEach {
        # Isolate root/discovery authority. Real native artifact binding and
        # Restore are exercised with original release sessions in the VM.
        Mock Assert-AllowedModuleArtifact { }
        Mock Assert-ArtifactContentBinding { }
    }
    AfterEach {
        $global:BackupBasePath='';$global:BackupIndex=@();$global:SessionManifest=@{};$global:CurrentModule=''
    }

    It 'retains the earlier sealed module with <Pending> preparation (<Payload>)' -TestCases @(
        foreach($pending in @('SecurityBaseline','ASR','DNS','Privacy','AntiAI','EdgeHardening','AdvancedSecurity')) {
            foreach($payload in @('empty-directory','partial-json')) { @{Pending=$pending;Payload=$payload} }
        }
    ) {
        param($Pending,$Payload)
        $sealed=if($Pending -eq 'DNS'){'EdgeHardening'}else{'DNS'}
        $fixture=New-InterruptedBackupFixture -Root $TestDrive -SealedModule $sealed
        $global:BackupBasePath=$fixture.Path;$global:SessionManifest=$fixture.Manifest
        $null=Start-ModuleBackup -ModuleName $Pending -Confirm:$false
        $manifestPath=Join-Path $fixture.Path 'manifest.json'
        $manifestHash=(Get-FileHash $manifestPath).Hash
        if($Payload -eq 'partial-json') {
            $name=switch($Pending){'SecurityBaseline'{'RegistryPolicies'};'ASR'{'ASR_ActiveConfiguration'};default{$Pending+'_PreState'}}
            $pendingFile=Register-Backup -Type $Pending -Name $name -Data '{"incomplete":'
            $pendingHash=(Get-FileHash $pendingFile).Hash
        }
        { Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest } | Should -Not -Throw
        { Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest -RequestedModules @($Pending) } |
            Should -Throw '*Requested module is not present*'
        $sessions=@(Get-BackupSessions -BackupDirectory $TestDrive)
        $session=@($sessions|Where-Object SessionId -eq $fixture.Manifest.sessionId)[0]
        $session.Restorable | Should -BeTrue
        @($session.Modules.name) | Should -Be @($sealed)
        $session.DisplayName | Should -Match 'incomplete backup'
        @($session.IncompleteModules) | Should -Be @($Pending)
        (Get-FileHash $manifestPath).Hash | Should -BeExactly $manifestHash
        if($Payload -eq 'partial-json'){(Get-FileHash $pendingFile).Hash | Should -BeExactly $pendingHash}
        Test-Path (Join-Path $fixture.Path 'restore-receipt.json') | Should -BeFalse
    }

    It 'ignores uncommitted manifest <Suffix> data of <Length> bytes without promoting it' -TestCases @(
        foreach($suffix in @('tmp','replace-backup')) {
            foreach($length in @(0,128,1048577)){@{Suffix=$suffix;Length=$length}}
        }
    ) {
        param($Suffix,$Length)
        $fixture=New-InterruptedBackupFixture -Root $TestDrive
        $path=Join-Path $fixture.Path ('manifest.json.'+('a'*32)+'.'+$Suffix)
        [IO.File]::WriteAllBytes($path,[byte[]]::new($Length))
        $hash=(Get-FileHash $path).Hash
        { Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest } | Should -Not -Throw
        (Get-FileHash $path).Hash | Should -BeExactly $hash
        @((Get-BackupSessions -BackupDirectory $TestDrive)|Where-Object SessionId -eq $fixture.Manifest.sessionId)[0].Restorable | Should -BeTrue
        Remove-Item (Join-Path $fixture.Path 'manifest.json') -Force
        @((Get-BackupSessions -BackupDirectory $TestDrive)|Where-Object SessionId -eq $fixture.Manifest.sessionId)[0].Restorable | Should -BeFalse
    }

    It 'rejects <Fault> instead of broadening the sealed authority' -TestCases @(
        @{Fault='unknown-directory'},@{Fault='second-unsealed-module'},@{Fault='unknown-file'},
        @{Fault='nested-directory'},@{Fault='executable'},@{Fault='wrong-module-file'},
        @{Fault='bad-manifest-guid'},@{Fault='manifest-executable'},@{Fault='transient-directory'},
        @{Fault='changed-sealed-artifact'},@{Fault='corrupt-canonical-receipt'},@{Fault='no-sealed-modules'}
    ) {
        param($Fault)
        $fixture=New-InterruptedBackupFixture -Root $TestDrive
        $pending=Join-Path $fixture.Path 'Privacy'
        $null=New-Item -ItemType Directory -Path $pending
        switch($Fault) {
            'unknown-directory' {$null=New-Item -ItemType Directory -Path (Join-Path $fixture.Path 'foreign')}
            'second-unsealed-module' {$null=New-Item -ItemType Directory -Path (Join-Path $fixture.Path 'AntiAI')}
            'unknown-file' {[IO.File]::WriteAllText((Join-Path $pending 'foreign.json'),'{}')}
            'nested-directory' {$null=New-Item -ItemType Directory -Path (Join-Path $pending 'nested')}
            'executable' {[IO.File]::WriteAllText((Join-Path $pending 'Privacy_PreState.json.ps1'),'throw "must not run"')}
            'wrong-module-file' {[IO.File]::WriteAllText((Join-Path $pending 'AntiAI_PreState.json'),'{}')}
            'bad-manifest-guid' {[IO.File]::WriteAllText((Join-Path $fixture.Path ('manifest.json.'+('g'*32)+'.tmp')),'{}')}
            'manifest-executable' {[IO.File]::WriteAllText((Join-Path $fixture.Path ('manifest.json.'+('a'*32)+'.tmp.ps1')),'throw "must not run"')}
            'transient-directory' {$null=New-Item -ItemType Directory -Path (Join-Path $fixture.Path ('manifest.json.'+('a'*32)+'.tmp'))}
            'changed-sealed-artifact' {[IO.File]::WriteAllText($fixture.Artifact,'changed')}
            'corrupt-canonical-receipt' {[IO.File]::WriteAllText((Join-Path $fixture.Path 'restore-receipt.json'),'not json')}
            'no-sealed-modules' {$fixture.Manifest.modules=@();$fixture.Manifest.totalItems=0}
        }
        { Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest } | Should -Throw
    }

    It 'rejects a real <Location> symlink without traversing it' -TestCases @(
        @{Location='pending-directory'},@{Location='pending-file'},@{Location='manifest-transient'}
    ) {
        param($Location)
        $fixture=New-InterruptedBackupFixture -Root $TestDrive
        $foreign=Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $null=New-Item -ItemType Directory -Path $foreign
        $target=Join-Path $foreign 'untouched.json'
        [IO.File]::WriteAllText($target,'{"canary":true}')
        $hash=(Get-FileHash $target).Hash
        $pending=Join-Path $fixture.Path 'Privacy'
        if($Location -eq 'pending-directory'){$link=$pending;$destination=$foreign}
        else {
            $null=New-Item -ItemType Directory -Path $pending
            $link=if($Location -eq 'pending-file'){Join-Path $pending 'Privacy_PreState.json'}else{Join-Path $fixture.Path ('manifest.json.'+('a'*32)+'.tmp')}
            $destination=$target
        }
        $null=New-Item -ItemType SymbolicLink -Path $link -Target $destination -ErrorAction Stop
        try {{ Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest } | Should -Throw}
        finally {
            # Delete only the owned link; WinPS Remove-Item prompts for a
            # directory link whose target is nonempty, even with -Force.
            if($Location -eq 'pending-directory'){[IO.Directory]::Delete($link,$false)}
            else {[IO.File]::Delete($link)}
        }
        (Get-FileHash $target).Hash | Should -BeExactly $hash
    }

    It 'binds successful Apply intent to the sealed module (<Requested>)' -TestCases @(
        @{Requested='DNS';Allowed=$true},@{Requested='ASR';Allowed=$false}
    ) {
        param($Requested,$Allowed)
        $fixture=New-InterruptedBackupFixture -Root $TestDrive
        $null=New-Item -ItemType Directory -Path (Join-Path $fixture.Path 'ASR')
        Mock Get-NoIDEngineContractFingerprint { 'a'*64 }
        Mock Read-NoIDIntentState {
            param($AllowMissing)
            if(-not $AllowMissing){[pscustomobject]@{engineContractFingerprint=('a'*64)}}
        }
        Mock New-NoIDModuleIntent { [pscustomobject]@{fixture='not restore authority'} }
        Mock Publish-NoIDIntentState { 'fixture-state.json' }
        $result=[pscustomobject]@{ModuleName=$Requested;Success=$true;Provider='QUAD9';DoHMode='SECURE'}
        $operation={Write-NoIDApplyIntentState -ModuleResults @($result) -SessionPath $fixture.Path}
        if($Allowed){& $operation|Should -Be 'fixture-state.json';Should -Invoke Publish-NoIDIntentState -Times 1 -Exactly}
        else {
            $operation|Should -Throw '*no sealed module record*'
            Should -Invoke Publish-NoIDIntentState -Times 0 -Exactly
        }
    }
}
