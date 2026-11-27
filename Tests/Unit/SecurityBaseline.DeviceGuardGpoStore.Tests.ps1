#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/SecurityBaseline/Private/SecurityBaselineDeviceGuardGpoStore.ps1')
    Initialize-SecurityBaselineDeviceGuardGpoStore
    function Get-TestDeviceGuardGpoSnapshot {
        [pscustomobject]@{
            SchemaVersion = 1
            Target = 'SecurityBaselineDeviceGuardGpo'
            KeyExisted = $false
            AbsentAncestorKeys = @('SOFTWARE', 'SOFTWARE\Policies', 'SOFTWARE\Policies\Microsoft', 'SOFTWARE\Policies\Microsoft\Windows')
            Values = @(foreach ($name in @('EnableVirtualizationBasedSecurity', 'RequirePlatformSecurityFeatures',
                        'HypervisorEnforcedCodeIntegrity', 'HVCIMATRequired', 'LsaCfgFlags', 'MachineIdentityIsolation',
                        'ConfigureSystemGuardLaunch', 'ConfigureKernelShadowStacksLaunch')) {
                    [pscustomobject]@{ Name=$name; Exists=$false; OriginalName=$null; Kind=0; Data=$null }
                })
            RegistryEditorPresent = $false
            DeviceGuardEditorPresent = $false
            PolicyFileSha256 = $null
            GptFileSha256 = $null
        }
    }
    function Initialize-TestDeviceGuardGpoPresent {
        param($Snapshot)
        $Snapshot.KeyExisted = $true
        $Snapshot.AbsentAncestorKeys = @()
        $Snapshot.PolicyFileSha256 = 'a' * 64
        $Snapshot.GptFileSha256 = 'b' * 64
    }
}

Describe 'Device Guard native GPO snapshot boundary' {
    BeforeEach { $script:Snapshot = Get-TestDeviceGuardGpoSnapshot }

    It 'round-trips genuine absent state without inventing empty strings or values' {
        $json = $script:Snapshot | ConvertTo-Json -Depth 10 -Compress
        $native = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot ($json | ConvertFrom-Json)
        $native.KeyExisted | Should -BeFalse
        $native.Values.Count | Should -Be 8
        $native.AbsentAncestorKeys.Count | Should -Be 4
        $native.PolicyFileSha256 | Should -BeNullOrEmpty
        ($native.Values | Where-Object { $null -ne $_.Data -or $null -ne $_.OriginalName -or $_.Exists }).Count | Should -Be 0
        ($script:Snapshot | ConvertTo-Json -Depth 10 -Compress) | Should -BeExactly $json
    }

    It 'keeps original native kind <Kind> and raw bytes exactly through JSON' -TestCases @(
        @{ Kind=0; Bytes=[byte[]]@(0,255) },
        @{ Kind=1; Bytes=[byte[]]@(65,0,0,0) },
        @{ Kind=2; Bytes=[byte[]]@(37,0,88,0,37,0,0,0) },
        @{ Kind=3; Bytes=[byte[]]@(0,127,255) },
        @{ Kind=4; Bytes=[byte[]]@(1,0,0,0) },
        @{ Kind=7; Bytes=[byte[]]@(65,0,0,0,0,0,66,0,0,0,0,0) },
        @{ Kind=11; Bytes=[byte[]]@(255,255,255,255,255,255,255,127) }
    ) {
        param($Kind, $Bytes)
        Initialize-TestDeviceGuardGpoPresent $script:Snapshot
        $entry = $script:Snapshot.Values[0]
        $entry.Exists = $true
        $entry.OriginalName = $entry.Name.ToUpperInvariant()
        $entry.Kind = $Kind
        $entry.Data = [Convert]::ToBase64String($Bytes)
        $json = $script:Snapshot | ConvertTo-Json -Depth 10 -Compress
        $native = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot ($json | ConvertFrom-Json)
        $native.Values[0].Kind | Should -Be $Kind
        $native.Values[0].OriginalName | Should -BeExactly $entry.OriginalName
        $native.Values[0].Data | Should -BeExactly $entry.Data
        [Convert]::ToBase64String([Convert]::FromBase64String($native.Values[0].Data)) | Should -BeExactly $entry.Data
    }

    It 'preserves original DWORD <Value> instead of remapping it to the Apply choice' -TestCases @(
        @{ Value=0 }, @{ Value=1 }, @{ Value=2 }, @{ Value=7 }
    ) {
        param($Value)
        Initialize-TestDeviceGuardGpoPresent $script:Snapshot
        $entry = $script:Snapshot.Values[2]
        $entry.Exists = $true; $entry.OriginalName = $entry.Name; $entry.Kind = 4
        $entry.Data = [Convert]::ToBase64String([BitConverter]::GetBytes([int]$Value))
        $native = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot $script:Snapshot
        [BitConverter]::ToInt32([Convert]::FromBase64String($native.Values[2].Data), 0) | Should -Be $Value
    }

    It 'keeps a present zero-byte REG_BINARY distinct from absent data' {
        Initialize-TestDeviceGuardGpoPresent $script:Snapshot
        $entry = $script:Snapshot.Values[0]
        $entry.Exists = $true; $entry.OriginalName = $entry.Name; $entry.Kind = 3; $entry.Data = ''
        $json = $script:Snapshot | ConvertTo-Json -Depth 10 -Compress
        $native = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot ($json | ConvertFrom-Json)
        $native.Values[0].Exists | Should -BeTrue
        ($null -ne $native.Values[0].Data) | Should -BeTrue
        $native.Values[0].Data.Length | Should -Be 0
        ($null -eq $native.Values[1].Data) | Should -BeTrue
    }

    It 'retains existing empty keys and both original editor registrations' {
        Initialize-TestDeviceGuardGpoPresent $script:Snapshot
        $script:Snapshot.RegistryEditorPresent = $true
        $script:Snapshot.DeviceGuardEditorPresent = $true
        $native = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot $script:Snapshot
        $native.KeyExisted | Should -BeTrue
        $native.AbsentAncestorKeys.Count | Should -Be 0
        $native.RegistryEditorPresent | Should -BeTrue
        $native.DeviceGuardEditorPresent | Should -BeTrue
        @($native.Values | Where-Object Exists).Count | Should -Be 0
    }

    It 'rejects <Fault> before emitting a native snapshot' -TestCases @(
        @{ Fault='missing field' }, @{ Fault='extra field' }, @{ Fault='string schema' },
        @{ Fault='unknown schema' }, @{ Fault='wrong target' }, @{ Fault='string existence' },
        @{ Fault='string editor flag' }, @{ Fault='scalar ancestors' }, @{ Fault='scalar values' },
        @{ Fault='missing target' }, @{ Fault='duplicate target' }, @{ Fault='changed target' },
        @{ Fault='missing value field' }, @{ Fault='extra value field' }, @{ Fault='string value existence' },
        @{ Fault='string kind' }, @{ Fault='overflow kind' }, @{ Fault='invented absent data' },
        @{ Fault='invented absent name' }, @{ Fault='foreign ancestor' }, @{ Fault='duplicate ancestor' },
        @{ Fault='gap in ancestors' }, @{ Fault='out of order ancestors' }, @{ Fault='invalid hash' },
        @{ Fault='numeric hash' }, @{ Fault='editor without metadata' }, @{ Fault='key without policy file' },
        @{ Fault='value without key' }, @{ Fault='wrong original name' }, @{ Fault='registry link type' },
        @{ Fault='invalid base64' }, @{ Fault='noncanonical base64' }
    ) {
        param($Fault)
        if ($Fault -in @('wrong original name', 'registry link type', 'invalid base64', 'noncanonical base64')) {
            Initialize-TestDeviceGuardGpoPresent $script:Snapshot
            $entry = $script:Snapshot.Values[0]
            $entry.Exists = $true; $entry.OriginalName = $entry.Name; $entry.Kind = 4; $entry.Data = 'AQAAAA=='
        }
        switch ($Fault) {
            'missing field' { $script:Snapshot.PSObject.Properties.Remove('KeyExisted') }
            'extra field' { $script:Snapshot | Add-Member NoteProperty LocalDefaults @() }
            'string schema' { $script:Snapshot.SchemaVersion = '1' }
            'unknown schema' { $script:Snapshot.SchemaVersion = 2 }
            'wrong target' { $script:Snapshot.Target = 'OtherPolicy' }
            'string existence' { $script:Snapshot.KeyExisted = 'false' }
            'string editor flag' { $script:Snapshot.RegistryEditorPresent = 'false' }
            'scalar ancestors' { $script:Snapshot.AbsentAncestorKeys = 'SOFTWARE' }
            'scalar values' { $script:Snapshot.Values = $script:Snapshot.Values[0] }
            'missing target' { $script:Snapshot.Values = @($script:Snapshot.Values | Select-Object -Skip 1) }
            'duplicate target' { $script:Snapshot.Values[1] = $script:Snapshot.Values[0].PSObject.Copy() }
            'changed target' { $script:Snapshot.Values[0].Name = 'UnknownOption' }
            'missing value field' { $script:Snapshot.Values[0].PSObject.Properties.Remove('Exists') }
            'extra value field' { $script:Snapshot.Values[0] | Add-Member NoteProperty ApplyValue 2 }
            'string value existence' { $script:Snapshot.Values[0].Exists = 'false' }
            'string kind' { $script:Snapshot.Values[0].Kind = '0' }
            'overflow kind' { $script:Snapshot.Values[0].Kind = [long]2147483648 }
            'invented absent data' { $script:Snapshot.Values[0].Data = '' }
            'invented absent name' { $script:Snapshot.Values[0].OriginalName = $script:Snapshot.Values[0].Name }
            'foreign ancestor' { $script:Snapshot.AbsentAncestorKeys = @('SOFTWARE\Other') }
            'duplicate ancestor' { $script:Snapshot.AbsentAncestorKeys += 'SOFTWARE' }
            'gap in ancestors' { $script:Snapshot.AbsentAncestorKeys = @('SOFTWARE', 'SOFTWARE\Policies\Microsoft\Windows') }
            'out of order ancestors' { [array]::Reverse($script:Snapshot.AbsentAncestorKeys) }
            'invalid hash' { $script:Snapshot.GptFileSha256 = 'x' * 64 }
            'numeric hash' { $script:Snapshot.GptFileSha256 = 42 }
            'editor without metadata' { $script:Snapshot.DeviceGuardEditorPresent = $true }
            'key without policy file' { $script:Snapshot.KeyExisted = $true; $script:Snapshot.AbsentAncestorKeys = @() }
            'value without key' { $script:Snapshot.Values[0].Exists = $true }
            'wrong original name' { $entry.OriginalName = 'OtherSetting' }
            'registry link type' { $entry.Kind = 6 }
            'invalid base64' { $entry.Data = '!' }
            'noncanonical base64' { $entry.Data = "AQAA AA==`n" }
        }
        $emitted = [Collections.Generic.List[object]]::new()
        { ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot $script:Snapshot | ForEach-Object { $emitted.Add($_) } } | Should -Throw
        $emitted.Count | Should -Be 0
    }

    It 'does not create native bookkeeping while reading an absent store' {
        $directory = Join-Path $TestDrive 'absent-policy-store'
        $native = [NoIDPrivacy.DeviceGuardGpoStore]::Read($directory)
        $native.KeyExisted | Should -BeFalse
        $native.AbsentAncestorKeys.Count | Should -Be 4
        Test-Path -LiteralPath $directory | Should -BeFalse
        [NoIDPrivacy.DeviceGuardGpoStore]::Restore($native, $directory) | Should -BeFalse
        Test-Path -LiteralPath $directory | Should -BeFalse
    }

    It 'rejects a malformed direct CLR snapshot before native Apply or Restore' {
        $native = [NoIDPrivacy.DeviceGuardGpoSnapshot]::new()
        $directory = Join-Path $TestDrive 'invalid-policy-store'
        { [NoIDPrivacy.DeviceGuardGpoStore]::Apply($native, $directory) } | Should -Throw
        { [NoIDPrivacy.DeviceGuardGpoStore]::Restore($native, $directory) } | Should -Throw
        Test-Path -LiteralPath $directory | Should -BeFalse
    }
}

Describe 'Native GPO editor registration parsing' {
    BeforeAll {
        $script:Cse = '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
        $script:EditorA = '{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}'
        $script:EditorB = '{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}'
    }
    It 'keeps multiple editors under the same native CSE identity' {
        $pairs = [NoIDPrivacy.DeviceGuardGpoStore]::ParseExtensionPairs("[$script:Cse$script:EditorA$script:EditorB]")
        $pairs.Count | Should -Be 2
        $pairs | Should -Contain '35378eac-683f-11d2-a89a-00c04fbbcfa2|8fc0b734-a0e1-11d1-a7d3-0000f87571e3'
        $pairs | Should -Contain '35378eac-683f-11d2-a89a-00c04fbbcfa2|b05566ac-fe9c-4368-be01-7a4cbb6cba11'
    }
    It 'accepts an empty extension list without inventing a registry processor' {
        [NoIDPrivacy.DeviceGuardGpoStore]::ParseExtensionPairs('').Count | Should -Be 0
    }
    It 'rejects <Fault> instead of silently dropping foreign registrations' -TestCases @(
        @{ Fault='duplicate CSE' }, @{ Fault='duplicate editor' }, @{ Fault='missing editor' },
        @{ Fault='truncated block' }, @{ Fault='prefix garbage' }, @{ Fault='suffix garbage' }
    ) {
        param($Fault)
        $text = "[$script:Cse$script:EditorA]"
        switch ($Fault) {
            'duplicate CSE' { $text += "[$script:Cse$script:EditorB]" }
            'duplicate editor' { $text = "[$script:Cse$script:EditorA$script:EditorA]" }
            'missing editor' { $text = "[$script:Cse]" }
            'truncated block' { $text = $text.TrimEnd(']') }
            'prefix garbage' { $text = 'garbage' + $text }
            'suffix garbage' { $text += 'garbage' }
        }
        { [NoIDPrivacy.DeviceGuardGpoStore]::ParseExtensionPairs($text) } | Should -Throw
    }
}

Describe 'First writable opening of an empty native GPO' {
    It 'recognizes only the eleven-byte native header appearing from complete file absence' {
        $header = [Text.Encoding]::ASCII.GetBytes("[General]`r`n")
        [NoIDPrivacy.DeviceGuardGpoStore]::IsEmptyGptInitialization($null, $null, $null, $header) | Should -BeTrue
    }

    It 'rejects <Change> as first-open initialization' -TestCases @(
        @{Change='existing policy'}, @{Change='existing metadata'}, @{Change='new policy'},
        @{Change='still absent'}, @{Change='empty file'}, @{Change='different newline'},
        @{Change='revision'}, @{Change='extension'}, @{Change='user metadata'},
        @{Change='trailing bytes'}, @{Change='UTF-8 BOM'}
    ) {
        param($Change)
        $beforePolicy=$null; $beforeGpt=$null; $afterPolicy=$null
        $afterGpt=[Text.Encoding]::ASCII.GetBytes("[General]`r`n")
        switch ($Change) {
            'existing policy' { $beforePolicy=[byte[]]@(80,82,101,103,1,0,0,0) }
            'existing metadata' { $beforeGpt=$afterGpt }
            'new policy' { $afterPolicy=[byte[]]@(80,82,101,103,1,0,0,0) }
            'still absent' { $afterGpt=$null }
            'empty file' { $afterGpt=[byte[]]@() }
            'different newline' { $afterGpt=[Text.Encoding]::ASCII.GetBytes("[General]`n") }
            'revision' { $afterGpt=[Text.Encoding]::ASCII.GetBytes("[General]`r`nVersion=0`r`n") }
            'extension' { $afterGpt=[Text.Encoding]::ASCII.GetBytes("[General]`r`ngPCMachineExtensionNames= `r`n") }
            'user metadata' { $afterGpt=[Text.Encoding]::ASCII.GetBytes("[General]`r`ngPCUserExtensionNames= `r`n") }
            'trailing bytes' { $afterGpt += [byte]0 }
            'UTF-8 BOM' { $afterGpt=[byte[]]@(239,187,191)+$afterGpt }
        }
        [NoIDPrivacy.DeviceGuardGpoStore]::IsEmptyGptInitialization($beforePolicy, $beforeGpt, $afterPolicy, $afterGpt) | Should -BeFalse
    }
}

Describe 'Device Guard GPO restore ordering' {
    It 'waits for the policy processing its own Save requested before registry prestate is replayed' {
        $source = Get-Content (Join-Path $repo 'Modules/SecurityBaseline/Private/SecurityBaselineDeviceGuardGpoStore.ps1') -Raw -Encoding UTF8
        $restore = [regex]::Match($source, '(?s)function Restore-SecurityBaselineDeviceGuardGpo \{.*?\n\}').Value
        $restore | Should -Match '\$changed = \[NoIDPrivacy\.DeviceGuardGpoStore\]::Restore\('
        $restore | Should -Match 'if \(\$changed\) \{ \$null = Wait-SecurityBaselineComputerPolicyProcessing \}'
        $wait = [regex]::Match($source, '(?s)function Wait-SecurityBaselineComputerPolicyProcessing \{.*?\n\}').Value
        $wait | Should -Match "Join-Path \`$env:SystemRoot 'System32\\gpupdate\.exe'"
        $invocation = @($wait -split "`n" | Where-Object { $_ -match '& \$gpupdate ' })
        $invocation.Count | Should -Be 1
        $invocation[0] | Should -Match '/target:computer "/wait:\$TimeoutSeconds"'
        $invocation[0] | Should -Not -Match '/force' -Because 'only the changed local policy may be processed'
    }
}
