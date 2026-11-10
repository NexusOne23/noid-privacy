#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Tests/Windows11/Windows11NativePolicyFingerprint.ps1')
    . (Join-Path $repo 'Tests/Windows11/Windows11GroupPolicyRecovery.ps1')
    . (Join-Path $repo 'Tests/Windows11/Windows11StateFingerprint.ps1')
    $tokens=$null; $errors=$null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repo 'Tests/Windows11/Invoke-Windows11BavrValidation.ps1'), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'BAVR runner does not parse' }
    foreach ($name in @('Compare-IndependentStateFingerprint', 'Get-RegistryEntryIdentity', 'Test-IsAllowedOsVolatileRegistryEntry')) {
        $function = $ast.Find({param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
        }, $false)
        . ([scriptblock]::Create($function.Extent.Text))
    }
    function Get-FixtureHash($Value) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(
            ($Value | ConvertTo-Json -Depth 20 -Compress)))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    function Get-GpoFixture([switch]$After, [uint32]$Revision = 32) {
        $entries = @(
            [pscustomobject]@{Path='';Directory=$true;AclSha256='root';Bytes=$null;Sha256=$null}
            [pscustomobject]@{Path='Machine';Directory=$true;AclSha256='parent';Bytes=$null;Sha256=$null}
            [pscustomobject]@{Path='gpt.ini';Directory=$false;AclSha256='ini';Bytes=$null;Sha256=$null}
        )
        if ($After) { $entries += [pscustomobject]@{Path='Machine\Registry.pol';Directory=$false;AclSha256='inherited';Bytes=8;Sha256='5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89'} }
        $content = if ($After) { "[General]`r`ngPCMachineExtensionNames= `r`nVersion=$Revision`r`n" } else { "[General]`r`n" }
        $bytes = [Text.Encoding]::ASCII.GetBytes($content)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $entries[2].Sha256 = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
        $entries[2].Bytes = $bytes.Length
        return [pscustomobject]@{
            RawState=[pscustomobject]@{Present=$true;Entries=$entries}
            EmptyComputerGpt=(Get-Windows11EmptyComputerGptState -Bytes ([Text.Encoding]::ASCII.GetBytes($content)))
            EmptyPolicyHasParentAccess=[bool]$After
        }
    }
    function Get-StateFixture($Evidence, [string]$Combined) {
        return [pscustomobject]@{
            StateAfter=[pscustomobject]@{Components=[pscustomobject]@{Registry='same';LocalGroupPolicy=(Get-FixtureHash $Evidence.RawState)};
                CombinedHash=$Combined;StableRegistryEntryCount=0;LocalGroupPolicyRecoveryEvidence=$Evidence}
            RegistrySnapshotBefore=@()
        }
    }
    function Get-FreshGpoFixture([switch]$After) {
        $evidence = Get-GpoFixture -After:$After -Revision 4
        $evidence.RawState.Entries += [pscustomobject]@{Path='User';Directory=$true;AclSha256='user';Bytes=$null;Sha256=$null}
        $evidence | Add-Member -NotePropertyName EmptyGptHasParentAccess -NotePropertyValue ([bool]$After)
        if (-not $After) {
            $evidence.RawState.Entries = @($evidence.RawState.Entries | Where-Object Path -ne 'gpt.ini')
            $evidence.EmptyComputerGpt = Get-Windows11EmptyComputerGptState -Bytes ([byte[]]@())
        }
        return $evidence
    }
    function Get-PristineGpoFixture([switch]$After) {
        if ($After) {
            $evidence = Get-FreshGpoFixture -After
            $evidence | Add-Member -NotePropertyName PolicyDirectoriesHaveParentAccess -NotePropertyValue $true
            return $evidence
        }
        return [pscustomobject]@{
            RawState=[pscustomobject]@{Present=$true;Entries=@(
                [pscustomobject]@{Path='';Directory=$true;AclSha256='root';Bytes=$null;Sha256=$null})}
            EmptyComputerGpt=(Get-Windows11EmptyComputerGptState -Bytes ([byte[]]@()))
            EmptyPolicyHasParentAccess=$false; EmptyGptHasParentAccess=$false; PolicyDirectoriesHaveParentAccess=$false
        }
    }
    function Get-NonemptyGpoFixture([uint32]$Revision = 2, [string]$Extra = '') {
        $text = "[General]`r`ngPCMachineExtensionNames=[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}]`r`nVersion=$Revision`r`n$Extra"
        $revisionState = Get-Windows11ComputerGptRevisionState -Bytes ([Text.Encoding]::ASCII.GetBytes($text))
        $evidence = Get-GpoFixture -After
        $evidence.EmptyComputerGpt = Get-Windows11EmptyComputerGptState -Bytes ([Text.Encoding]::ASCII.GetBytes($text))
        $evidence | Add-Member -NotePropertyName ComputerGptRevision -NotePropertyValue $revisionState
        $evidence.RawState.Entries[2].Bytes = $revisionState.Bytes
        $evidence.RawState.Entries[2].Sha256 = $revisionState.Sha256
        $evidence.RawState.Entries[3].Bytes = 1024
        $evidence.RawState.Entries[3].Sha256 = 'f' * 64
        return $evidence
    }
}

Describe 'Bounded empty local computer policy recovery' {
    It 'recognizes only the empty native General/revision/extension forms' {
        foreach ($text in @("[General]`r`n", "[General]`nVersion=0`n", "[General]`r`ngPCMachineExtensionNames= `r`nVersion=65535`r`n")) {
            (Get-Windows11EmptyComputerGptState -Bytes ([Text.Encoding]::ASCII.GetBytes($text))).Supported | Should -BeTrue
        }
    }

    It 'refuses to classify <Kind> as empty computer bookkeeping' -TestCases @(
        @{Kind='user revision';Text="[General]`nVersion=65536`n"}
        @{Kind='integer overflow';Text="[General]`nVersion=4294967296`n"}
        @{Kind='duplicate revision';Text="[General]`nVersion=1`nVersion=2`n"}
        @{Kind='functional CSE';Text="[General]`ngPCMachineExtensionNames=[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}]`n"}
        @{Kind='unknown field';Text="[General]`nUnknown=1`n"}
        @{Kind='unknown section';Text="[General]`n[Unknown]`n"}
        @{Kind='embedded NUL';Text="[General]`0`n"}
    ) {
        param($Kind,$Text)
        $null=$Kind
        (Get-Windows11EmptyComputerGptState -Bytes ([Text.Encoding]::ASCII.GetBytes($Text))).Supported | Should -BeFalse
    }

    It 'classifies the native empty Save outcome while retaining different raw evidence' {
        $before=Get-GpoFixture; $after=Get-GpoFixture -After
        (Compare-Windows11GroupPolicyRecoveryEvidence -Before $before -After $after).Accepted | Should -BeTrue
        (Get-FixtureHash $before.RawState) | Should -Not -Be (Get-FixtureHash $after.RawState)
        $before=$after | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $after=Get-GpoFixture -After -Revision 33
        (Compare-Windows11GroupPolicyRecoveryEvidence -Before $before -After $after).Accepted | Should -BeTrue
    }

    It 'keeps <Change> outside the bookkeeping disposition' -TestCases @(
        @{Change='policy record'}, @{Change='existing file ACL'}, @{Change='parent ACL'},
        @{Change='new directory'}, @{Change='user policy'}, @{Change='unproved new file access'},
        @{Change='unsupported INI'}, @{Change='absent root'}, @{Change='removed policy file'},
        @{Change='unbound INI hash'}, @{Change='unbound INI size'}, @{Change='missing INI binding'},
        @{Change='missing root entry'}, @{Change='revision rollback'}, @{Change='same revision'},
        @{Change='machine revision wraparound'}
    ) {
        param($Change)
        $before=Get-GpoFixture; $after=Get-GpoFixture -After
        switch ($Change) {
            'policy record' { $after.RawState.Entries[3].Bytes=286 }
            'existing file ACL' { $after.RawState.Entries[2].AclSha256='changed' }
            'parent ACL' { $after.RawState.Entries[1].AclSha256='changed' }
            'new directory' { $after.RawState.Entries += [pscustomobject]@{Path='extra';Directory=$true;AclSha256='new'} }
            'user policy' { $after.RawState.Entries += [pscustomobject]@{Path='User\Registry.pol';Directory=$false;Bytes=8;Sha256='new';AclSha256='new'} }
            'unproved new file access' { $after.EmptyPolicyHasParentAccess=$false }
            'unsupported INI' { $after.EmptyComputerGpt.Supported=$false }
            'absent root' { $before.RawState.Present=$false }
            'removed policy file' { $before=Get-GpoFixture -After; $after.RawState.Entries=@($after.RawState.Entries | Select-Object -First 3) }
            'unbound INI hash' { $after.RawState.Entries[2].Sha256='f' * 64 }
            'unbound INI size' { $after.RawState.Entries[2].Bytes++ }
            'missing INI binding' { $after.EmptyComputerGpt.PSObject.Properties.Remove('Sha256') }
            'missing root entry' {
                $before.RawState.Entries=@($before.RawState.Entries | Where-Object Path -ne '')
                $after.RawState.Entries=@($after.RawState.Entries | Where-Object Path -ne '')
            }
            'revision rollback' { $before=Get-GpoFixture -After -Revision 32; $after=Get-GpoFixture -After -Revision 1 }
            'same revision' { $before=Get-GpoFixture -After; $after=Get-GpoFixture -After }
            'machine revision wraparound' { $before=Get-GpoFixture -After -Revision 65535; $after=Get-GpoFixture -After -Revision 0 }
        }
        (Compare-Windows11GroupPolicyRecoveryEvidence -Before $before -After $after).Accepted | Should -BeFalse
    }

    It 'requires native writer scope <Module>, matching raw hashes and unchanged other components' -TestCases @(
        @{Module='AdvancedSecurity'}, @{Module='SecurityBaseline'}
    ) {
        param($Module)
        $before=Get-StateFixture (Get-GpoFixture) 'before'; $after=Get-StateFixture (Get-GpoFixture -After) 'after'
        (Compare-IndependentStateFingerprint -Before $before -After $after).Passed | Should -BeFalse
        $result=Compare-IndependentStateFingerprint -Before $before -After $after -Module $Module
        $result.Passed | Should -BeTrue
        $result.RawCombinedHashEqual | Should -BeFalse
        ($result.ComponentComparisons | Where-Object Name -eq LocalGroupPolicy).Equal | Should -BeFalse
        $after.StateAfter.Components.Registry='changed'
        (Compare-IndependentStateFingerprint -Before $before -After $after -Module $Module).Passed | Should -BeFalse
        $after.StateAfter.Components.Registry='same'
        $after.StateAfter.Components.LocalGroupPolicy='unbound'
        { Compare-IndependentStateFingerprint -Before $before -After $after -Module $Module } | Should -Throw '*raw component hash*'
    }
}

Describe 'Fresh native computer policy initialization after recovery' {
    It 'classifies only inherited empty metadata added to unchanged original directories' {
        $before=Get-FreshGpoFixture; $after=Get-FreshGpoFixture -After
        (Compare-Windows11GroupPolicyRecoveryEvidence -Before $before -After $after).Accepted | Should -BeTrue
        (Get-FixtureHash $before.RawState) | Should -Not -Be (Get-FixtureHash $after.RawState)
        $left=Get-StateFixture $before 'before'; $right=Get-StateFixture $after 'after'
        foreach ($module in @('AdvancedSecurity','SecurityBaseline')) {
            $result=Compare-IndependentStateFingerprint -Before $left -After $right -Module $module
            $result.Passed | Should -BeTrue
            $result.RawCombinedHashEqual | Should -BeFalse
            ($result.ComponentComparisons | Where-Object Name -eq LocalGroupPolicy).Equal | Should -BeFalse
        }
        (Compare-IndependentStateFingerprint -Before $left -After $right -Module Privacy).Passed | Should -BeFalse
    }

    It 'rejects fresh metadata with <Change>' -TestCases @(
        @{Change='unproved INI access'}, @{Change='missing INI access observation'},
        @{Change='unproved policy access'}, @{Change='unbound INI hash'}, @{Change='unbound INI size'},
        @{Change='no revision'}, @{Change='zero revision'}, @{Change='alternative INI layout'},
        @{Change='prior policy file'}, @{Change='missing resulting policy'}, @{Change='nonempty resulting policy'},
        @{Change='existing root access'}, @{Change='existing machine access'}, @{Change='existing user access'},
        @{Change='missing prior machine'}, @{Change='duplicate path'}, @{Change='new directory'},
        @{Change='unchanged foreign file'}, @{Change='contradictory absent INI observation'},
        @{Change='removed old INI'}, @{Change='unknown INI field'}
    ) {
        param($Change)
        $before=Get-FreshGpoFixture; $after=Get-FreshGpoFixture -After
        switch ($Change) {
            'unproved INI access' { $after.EmptyGptHasParentAccess=$false }
            'missing INI access observation' { $after.PSObject.Properties.Remove('EmptyGptHasParentAccess') }
            'unproved policy access' { $after.EmptyPolicyHasParentAccess=$false }
            'unbound INI hash' { $after.RawState.Entries[2].Sha256='f' * 64 }
            'unbound INI size' { $after.RawState.Entries[2].Bytes++ }
            'no revision' { $after.EmptyComputerGpt.VersionPresent=$false }
            'zero revision' { $after.EmptyComputerGpt.Revision=0 }
            'alternative INI layout' {
                $parsed=Get-Windows11EmptyComputerGptState -Bytes ([Text.Encoding]::ASCII.GetBytes("[General]`nVersion=4`n"))
                $after.EmptyComputerGpt=$parsed; $after.RawState.Entries[2].Sha256=$parsed.Sha256; $after.RawState.Entries[2].Bytes=$parsed.Bytes
            }
            'prior policy file' { $before.RawState.Entries += $after.RawState.Entries[3] }
            'missing resulting policy' { $after.RawState.Entries=@($after.RawState.Entries | Where-Object Path -ne 'Machine\Registry.pol') }
            'nonempty resulting policy' { $after.RawState.Entries[3].Bytes=9 }
            'existing root access' { $after.RawState.Entries[0].AclSha256='changed' }
            'existing machine access' { $after.RawState.Entries[1].AclSha256='changed' }
            'existing user access' { $after.RawState.Entries[4].AclSha256='changed' }
            'missing prior machine' { $before.RawState.Entries=@($before.RawState.Entries | Where-Object Path -ne Machine) }
            'duplicate path' { $after.RawState.Entries += $after.RawState.Entries[3] }
            'new directory' { $after.RawState.Entries += [pscustomobject]@{Path='other';Directory=$true;AclSha256='other'} }
            'unchanged foreign file' {
                $entry=[pscustomobject]@{Path='User\Registry.pol';Directory=$false;AclSha256='user-pol';Bytes=200;Sha256=('e' * 64)}
                $before.RawState.Entries += $entry; $after.RawState.Entries += $entry
            }
            'contradictory absent INI observation' { $before.EmptyComputerGpt.Supported=$true }
            'removed old INI' {
                $before=Get-GpoFixture
                $after.RawState.Entries=@($after.RawState.Entries | Where-Object Path -ne 'gpt.ini')
            }
            'unknown INI field' {
                $after.EmptyComputerGpt=Get-Windows11EmptyComputerGptState -Bytes ([Text.Encoding]::ASCII.GetBytes("[General]`r`nVersion=4`r`nUnknown=1`r`n"))
            }
        }
        (Compare-Windows11GroupPolicyRecoveryEvidence -Before $before -After $after).Accepted | Should -BeFalse
    }
}

Describe 'Fresh native local GPO creation in a previously empty root' {
    It 'classifies root-inherited folders and empty metadata created by native Save' {
        $before=Get-PristineGpoFixture; $after=Get-PristineGpoFixture -After
        $result=Compare-Windows11GroupPolicyRecoveryEvidence -Before $before -After $after
        $result.Accepted | Should -BeTrue
        $result.Disposition | Should -Match 'previously empty root'
        $left=Get-StateFixture $before 'before'; $right=Get-StateFixture $after 'after'
        foreach ($module in @('AdvancedSecurity','SecurityBaseline')) {
            $comparison=Compare-IndependentStateFingerprint -Before $left -After $right -Module $module
            $comparison.Passed | Should -BeTrue
            $comparison.RawCombinedHashEqual | Should -BeFalse
        }
        (Compare-IndependentStateFingerprint -Before $left -After $right -Module Privacy).Passed | Should -BeFalse
    }

    It 'rejects a pristine-root outcome with <Change>' -TestCases @(
        @{Change='unproved folder access'}, @{Change='missing folder observation'}, @{Change='changed root access'},
        @{Change='extra folder'}, @{Change='missing Machine folder'}, @{Change='user policy file'},
        @{Change='nonempty policy'}, @{Change='unproved policy access'}, @{Change='unproved INI access'},
        @{Change='prior root file'}, @{Change='folder as file'}
    ) {
        param($Change)
        $before=Get-PristineGpoFixture; $after=Get-PristineGpoFixture -After
        switch ($Change) {
            'unproved folder access' { $after.PolicyDirectoriesHaveParentAccess=$false }
            'missing folder observation' { $after.PSObject.Properties.Remove('PolicyDirectoriesHaveParentAccess') }
            'changed root access' { $after.RawState.Entries[0].AclSha256='changed' }
            'extra folder' { $after.RawState.Entries += [pscustomobject]@{Path='Other';Directory=$true;AclSha256='other';Bytes=$null;Sha256=$null} }
            'missing Machine folder' { $after.RawState.Entries=@($after.RawState.Entries | Where-Object { $_.Path -notlike 'Machine*' }) }
            'user policy file' { $after.RawState.Entries += [pscustomobject]@{Path='User\Registry.pol';Directory=$false;AclSha256='inherited';Bytes=8;Sha256='5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89'} }
            'nonempty policy' { $after.RawState.Entries[3].Bytes=9 }
            'unproved policy access' { $after.EmptyPolicyHasParentAccess=$false }
            'unproved INI access' { $after.EmptyGptHasParentAccess=$false }
            'prior root file' { $before.RawState.Entries += [pscustomobject]@{Path='Other.txt';Directory=$false;AclSha256='f';Bytes=1;Sha256=('a' * 64)} }
            'folder as file' { $after.RawState.Entries[4].Directory=$false }
        }
        (Compare-Windows11GroupPolicyRecoveryEvidence -Before $before -After $after).Accepted | Should -BeFalse
    }
}

Describe 'Native new policy folder access evidence' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        $script:Root=Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $null=New-Item -ItemType Directory -Path $script:Root -Force
    }

    It 'derives the folder DACL that NTFS inherits from <Label>' -TestCases @(
        # The observed Windows 11 System32\GroupPolicy root: generic inherit-only grants.
        @{Label='generic inherit-only grants';Dacl='D:PAI(A;;0x1200a9;;;AU)(A;OICIIO;GXGR;;;AU)(A;OICIIO;GA;;;SY)(A;;FA;;;SY)(A;OICIIO;GA;;;BA)(A;;FA;;;BA)'},
        @{Label='specific inheritable grants';Dacl='D:PAI(A;OICI;0x1200a9;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'},
        @{Label='object-only and no-propagate grants';Dacl='D:PAI(A;OI;0x1200a9;;;AU)(A;OICINP;FA;;;SY)(A;OICI;FA;;;BA)'}
    ) {
        param($Label, $Dacl)
        $null=$Label
        $acl=Get-Acl -LiteralPath $script:Root
        $acl.SetSecurityDescriptorSddlForm($Dacl, 'Access')
        Set-Acl -LiteralPath $script:Root -AclObject $acl
        $child=New-Item -ItemType Directory -Path (Join-Path $script:Root 'Machine')
        (Test-Windows11NewPolicyDirectoryAccess -DirectorySecurity (Get-Acl -LiteralPath $child.FullName) `
            -ParentSecurity (Get-Acl -LiteralPath $script:Root)) | Should -BeTrue
    }

    It 'rejects <Change> on a new policy folder' -TestCases @(
        @{Change='an explicit writable grant'}, @{Change='a protected DACL'}, @{Change='a creator-owner root grant'},
        @{Change='a foreign owner'}
    ) {
        param($Change)
        $acl=Get-Acl -LiteralPath $script:Root
        $dacl=if ($Change -eq 'a creator-owner root grant') { 'D:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' }
            else { 'D:PAI(A;OICI;0x1200a9;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' }
        $acl.SetSecurityDescriptorSddlForm($dacl, 'Access')
        Set-Acl -LiteralPath $script:Root -AclObject $acl
        $child=New-Item -ItemType Directory -Path (Join-Path $script:Root 'Machine')
        $childAcl=Get-Acl -LiteralPath $child.FullName
        switch ($Change) {
            'an explicit writable grant' {
                $childAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new('S-1-5-11'), 'Modify', 'Allow'))
            }
            'a protected DACL' { $childAcl.SetAccessRuleProtection($true, $true) }
            'a foreign owner' { $childAcl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-1-0')) }
        }
        (Test-Windows11NewPolicyDirectoryAccess -DirectorySecurity $childAcl -ParentSecurity (Get-Acl -LiteralPath $script:Root)) |
            Should -BeFalse
    }
}

Describe 'Bounded nonempty local computer policy revision recovery' {
    It 'accepts only a machine revision advance with all policy and access bytes unchanged' {
        $before = Get-NonemptyGpoFixture -Revision 2
        $after = Get-NonemptyGpoFixture -Revision 19
        $before.EmptyComputerGpt.Supported | Should -BeFalse
        (Compare-Windows11GroupPolicyRecoveryEvidence -Before $before -After $after).Accepted | Should -BeTrue
        (Get-FixtureHash $before.RawState) | Should -Not -Be (Get-FixtureHash $after.RawState)
        $before = Get-NonemptyGpoFixture -Revision 65538
        $after = Get-NonemptyGpoFixture -Revision 65555
        (Compare-Windows11GroupPolicyRecoveryEvidence -Before $before -After $after).Accepted | Should -BeTrue
    }

    It 'rejects <Change> in an otherwise matching nonempty policy capture' -TestCases @(
        @{Change='policy content'}, @{Change='policy size'}, @{Change='policy access'},
        @{Change='INI access'}, @{Change='parent access'}, @{Change='new file'},
        @{Change='removed file'}, @{Change='missing root'}, @{Change='duplicate path'},
        @{Change='unbound INI hash'}, @{Change='unbound INI size'}, @{Change='changed INI fields'},
        @{Change='missing revision evidence'}, @{Change='rollback'}, @{Change='same revision'},
        @{Change='user revision'}, @{Change='machine wraparound'}
    ) {
        param($Change)
        $before = Get-NonemptyGpoFixture -Revision 2
        $after = Get-NonemptyGpoFixture -Revision 19
        switch ($Change) {
            'policy content' { $after.RawState.Entries[3].Sha256 = 'e' * 64 }
            'policy size' { $after.RawState.Entries[3].Bytes++ }
            'policy access' { $after.RawState.Entries[3].AclSha256 = 'changed' }
            'INI access' { $after.RawState.Entries[2].AclSha256 = 'changed' }
            'parent access' { $after.RawState.Entries[1].AclSha256 = 'changed' }
            'new file' { $after.RawState.Entries += [pscustomobject]@{Path='extra';Directory=$false;Sha256='new';Bytes=1;AclSha256='new'} }
            'removed file' { $after.RawState.Entries = @($after.RawState.Entries | Select-Object -First 3) }
            'missing root' { $after.RawState.Entries = @($after.RawState.Entries | Where-Object Path -ne '') }
            'duplicate path' { $after.RawState.Entries += $after.RawState.Entries[3] }
            'unbound INI hash' { $after.ComputerGptRevision.Sha256 = 'e' * 64 }
            'unbound INI size' { $after.ComputerGptRevision.Bytes++ }
            'changed INI fields' { $after.ComputerGptRevision.StableSha256 = 'e' * 64 }
            'missing revision evidence' { $after.PSObject.Properties.Remove('ComputerGptRevision') }
            'rollback' { $after = Get-NonemptyGpoFixture -Revision 1 }
            'same revision' { $after = Get-NonemptyGpoFixture -Revision 2 }
            'user revision' { $after = Get-NonemptyGpoFixture -Revision 65555 }
            'machine wraparound' { $before = Get-NonemptyGpoFixture -Revision 65535; $after = Get-NonemptyGpoFixture -Revision 0 }
        }
        (Compare-Windows11GroupPolicyRecoveryEvidence -Before $before -After $after).Accepted | Should -BeFalse
    }

    It 'refuses unsupported INI form <Change>' -TestCases @(
        @{Change='unknown field';Suffix="Unknown=1`r`n"},
        @{Change='duplicate revision';Suffix="Version=20`r`n"},
        @{Change='user extension';Suffix="gPCUserExtensionNames=[]`r`n"},
        @{Change='new section';Suffix="[Other]`r`n"},
        @{Change='embedded NUL';Suffix="`0"}
    ) {
        param($Change, $Suffix)
        $null = $Change
        (Get-NonemptyGpoFixture -Extra $Suffix).ComputerGptRevision.Supported | Should -BeFalse
    }

    It 'keeps <Module> scope, other components and raw evidence binding mandatory' -TestCases @(
        @{Module='AdvancedSecurity'}, @{Module='SecurityBaseline'}
    ) {
        param($Module)
        $before = Get-StateFixture (Get-NonemptyGpoFixture -Revision 2) 'before'
        $after = Get-StateFixture (Get-NonemptyGpoFixture -Revision 19) 'after'
        (Compare-IndependentStateFingerprint -Before $before -After $after).Passed | Should -BeFalse
        $result = Compare-IndependentStateFingerprint -Before $before -After $after -Module $Module
        $result.Passed | Should -BeTrue
        $result.RawCombinedHashEqual | Should -BeFalse
        ($result.ComponentComparisons | Where-Object Name -eq LocalGroupPolicy).Equal | Should -BeFalse
        $after.StateAfter.Components.Registry = 'changed'
        (Compare-IndependentStateFingerprint -Before $before -After $after -Module $Module).Passed | Should -BeFalse
        $after.StateAfter.Components.Registry = 'same'
        $after.StateAfter.Components.LocalGroupPolicy = 'unbound'
        { Compare-IndependentStateFingerprint -Before $before -After $after -Module $Module } | Should -Throw '*raw component hash*'
    }
}

Describe 'Native empty policy access evidence' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        $script:Root=Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        $script:Machine=Join-Path $script:Root 'Machine'
        $null=New-Item -ItemType Directory -Path $script:Machine -Force
        [IO.File]::WriteAllText((Join-Path $script:Root 'gpt.ini'), "[General]`r`nVersion=1`r`n")
        # Let NTFS perform actual inheritance in a private fixture. Do not
        # require CI's host to have initialized its own local GPO directory.
        $parentAcl=Get-Acl $script:Machine
        $parentAcl.SetAccessRuleProtection($true,$false)
        $parentAcl.SetGroup([Security.Principal.SecurityIdentifier]::new('S-1-5-11'))
        foreach ($grant in @(@{Sid='S-1-5-11';Rights='ReadAndExecute'},
            @{Sid='S-1-5-32-544';Rights='FullControl'}, @{Sid='S-1-5-18';Rights='FullControl'})) {
            $parentAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($grant.Sid), $grant.Rights,
                'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        Set-Acl -LiteralPath $script:Machine -AclObject $parentAcl
        $script:Pol=Join-Path $script:Machine 'Registry.pol'
        [IO.File]::WriteAllBytes($script:Pol, [byte[]]@(80,82,101,103,1,0,0,0))
        $acl=Get-Acl $script:Pol
        $parent=Get-Acl $script:Machine
        $acl.SetOwner($parent.GetOwner([Security.Principal.SecurityIdentifier]))
        Set-Acl -LiteralPath $script:Pol -AclObject $acl
    }

    It 'proves native inherited access without emitting identities' {
        $sidType=[Security.Principal.SecurityIdentifier]
        (Get-Acl $script:Pol).GetGroup($sidType).Equals((Get-Acl $script:Machine).GetGroup($sidType)) | Should -BeFalse
        $state=Get-Windows11LocalGroupPolicyFingerprintState -RootPath $script:Root
        $evidence=Get-Windows11GroupPolicyRecoveryEvidence -RawState $state -RootPath $script:Root
        $evidence.EmptyPolicyHasParentAccess | Should -BeTrue
        ($evidence | ConvertTo-Json -Depth 20) | Should -Not -Match 'S-1-'
    }

    It 'rejects a protected ACL, an explicit writable grant and an unrelated primary group' {
        $acl=Get-Acl $script:Pol
        $acl.SetAccessRuleProtection($true,$true)
        (Test-Windows11EmptyPolicyFileAccess -FileSecurity $acl -ParentSecurity (Get-Acl $script:Machine)) | Should -BeFalse
        $acl=Get-Acl $script:Pol
        $acl.SetGroup([Security.Principal.SecurityIdentifier]::new('S-1-1-0'))
        (Test-Windows11EmptyPolicyFileAccess -FileSecurity $acl -ParentSecurity (Get-Acl $script:Machine)) | Should -BeFalse
        $acl=Get-Acl $script:Pol
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-11'), 'Write', 'Allow'))
        (Test-Windows11EmptyPolicyFileAccess -FileSecurity $acl -ParentSecurity (Get-Acl $script:Machine)) | Should -BeFalse
    }

    It 'allows only an administrator owner already granted full control of the parent for a new INI' {
        $sidType=[Security.Principal.SecurityIdentifier]
        $admin=$sidType::new('S-1-5-32-544')
        $parent=Get-Acl $script:Machine
        $parent.SetOwner($sidType::new('S-1-5-18'))
        $file=Get-Acl $script:Pol
        $file.SetOwner($admin)
        (Test-Windows11EmptyPolicyFileAccess -FileSecurity $file -ParentSecurity $parent) | Should -BeFalse
        (Test-Windows11EmptyPolicyFileAccess -FileSecurity $file -ParentSecurity $parent -AllowAdministratorOwner) | Should -BeTrue
        $file.SetOwner($sidType::new('S-1-1-0'))
        (Test-Windows11EmptyPolicyFileAccess -FileSecurity $file -ParentSecurity $parent -AllowAdministratorOwner) | Should -BeFalse
        $file.SetOwner($admin)
        $parent.PurgeAccessRules($admin)
        (Test-Windows11EmptyPolicyFileAccess -FileSecurity $file -ParentSecurity $parent -AllowAdministratorOwner) | Should -BeFalse
    }
}
