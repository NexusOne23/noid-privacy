#Requires -Version 5.1

BeforeAll {
    . (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Core/Rollback.ps1')
}

Describe 'Restore ordering uses the same module identity comparison as manifests' {
    $pairs = @(
        @{ First='SecurityBaseline'; Second='ASR'; Guard='Assert-NoIDSecurityBaselineOverlapRestore' },
        @{ First='SecurityBaseline'; Second='DNS'; Guard='Assert-NoIDSecurityBaselineOverlapRestore' },
        @{ First='SecurityBaseline'; Second='AntiAI'; Guard='Assert-NoIDSecurityBaselineOverlapRestore' },
        @{ First='SecurityBaseline'; Second='AdvancedSecurity'; Guard='Assert-NoIDSecurityBaselineOverlapRestore' },
        @{ First='SecurityBaseline'; Second='Privacy'; Guard='Assert-NoIDPrivacyPolicyOverlapRestore' },
        @{ First='Privacy'; Second='AntiAI'; Guard='Assert-NoIDPrivacyPolicyOverlapRestore' },
        @{ First='AntiAI'; Second='EdgeHardening'; Guard='Assert-NoIDEdgePolicyOverlapRestore' }
    )
    $cases = foreach ($pair in $pairs) {
        foreach ($reverse in @($false, $true)) {
            foreach ($mixed in @($false, $true)) {
                $first = if ($reverse) { $pair.Second } else { $pair.First }
                $second = if ($reverse) { $pair.First } else { $pair.Second }
                @{
                    Order=[string[]]@(
                        $(if ($mixed) { $first.ToUpperInvariant() } else { $first.ToLowerInvariant() })
                        $second.ToLowerInvariant()
                    )
                    Earlier=$first.ToUpperInvariant(); Later=$second.ToUpperInvariant()
                    Guard=$pair.Guard
                    Label="$first -> $second; mixedCase=$mixed"
                }
            }
        }
    }
    It '<Label> retains both ordering protection and allowed restore scopes' -ForEach $cases {
        { & $Guard -SessionModuleNames $Order -RequestedModules @($Earlier) } |
            Should -Throw -ExpectedMessage '*overlaps the later*'
        { & $Guard -SessionModuleNames $Order -RequestedModules @($Later) } | Should -Not -Throw
        { & $Guard -SessionModuleNames $Order -RequestedModules @($Earlier, $Later) } | Should -Not -Throw
        { & $Guard -SessionModuleNames $Order -RequestedModules @() } | Should -Not -Throw
    }
}

Describe 'Baseline, Privacy and AntiAI shared policies follow all sealed orders and restore subsets' {
    # Bits are Baseline=1, Privacy=2, AntiAI=4. Each table enumerates allowed
    # outcomes independently of the production decision code. Zero means full.
    $orders = @(
        @{ Order=@('SecurityBaseline', 'Privacy', 'AntiAI'); Allowed=@(0, 4, 6, 7) },
        @{ Order=@('SecurityBaseline', 'AntiAI', 'Privacy'); Allowed=@(0, 2, 6, 7) },
        @{ Order=@('Privacy', 'SecurityBaseline', 'AntiAI'); Allowed=@(0, 4, 5, 7) },
        @{ Order=@('Privacy', 'AntiAI', 'SecurityBaseline'); Allowed=@(0, 1, 5, 7) },
        @{ Order=@('AntiAI', 'SecurityBaseline', 'Privacy'); Allowed=@(0, 2, 3, 7) },
        @{ Order=@('AntiAI', 'Privacy', 'SecurityBaseline'); Allowed=@(0, 1, 3, 7) }
    )
    $cases = foreach ($entry in $orders) {
        foreach ($mask in 0..7) {
            @{
                Order=[string[]]$entry.Order
                Requested=[string[]]@(
                    if ($mask -band 1) { 'SecurityBaseline' }
                    if ($mask -band 2) { 'Privacy' }
                    if ($mask -band 4) { 'AntiAI' }
                )
                Allowed=($mask -in $entry.Allowed)
                Label=($entry.Order -join ' -> ') + '; restore mask ' + $mask
            }
        }
    }
    It '<Label>: allowed=<Allowed>' -ForEach $cases {
        $operation = {
            Assert-NoIDSecurityBaselineOverlapRestore -SessionModuleNames $Order -RequestedModules $Requested
            Assert-NoIDPrivacyPolicyOverlapRestore -SessionModuleNames $Order -RequestedModules $Requested
        }
        if ($Allowed) { $operation | Should -Not -Throw }
        else { $operation | Should -Throw -ExpectedMessage '*overlaps the later*' }
    }

    It 'does not couple absent or independent owners' {
        foreach ($order in @(@('ASR', 'AntiAI'), @('Privacy', 'DNS'))) {
            foreach ($module in $order) {
                { Assert-NoIDPrivacyPolicyOverlapRestore -SessionModuleNames $order -RequestedModules @($module) } |
                    Should -Not -Throw
            }
        }
    }
}

Describe 'SecurityBaseline partial restore follows the sealed application order' {
    # Bits identify requested modules: Baseline=1, ASR=2, DNS=4.
    # These explicit allowed sets describe the ownership contract for all six
    # orders. ASR and DNS are independent; each shares state with Baseline.
    # A zero request means full restore, as in the public API.
    $orders = @(
        @{ Order=@('SecurityBaseline', 'ASR', 'DNS'); Allowed=@(0, 2, 4, 6, 7) },
        @{ Order=@('SecurityBaseline', 'DNS', 'ASR'); Allowed=@(0, 2, 4, 6, 7) },
        @{ Order=@('ASR', 'SecurityBaseline', 'DNS'); Allowed=@(0, 4, 5, 7) },
        @{ Order=@('DNS', 'SecurityBaseline', 'ASR'); Allowed=@(0, 2, 3, 7) },
        @{ Order=@('ASR', 'DNS', 'SecurityBaseline'); Allowed=@(0, 1, 3, 5, 7) },
        @{ Order=@('DNS', 'ASR', 'SecurityBaseline'); Allowed=@(0, 1, 3, 5, 7) }
    )
    $cases = foreach ($entry in $orders) {
        foreach ($mask in 0..7) {
            $requested = @(
                if ($mask -band 1) { 'SecurityBaseline' }
                if ($mask -band 2) { 'ASR' }
                if ($mask -band 4) { 'DNS' }
            )
            @{
                Order=[string[]]$entry.Order
                Requested=[string[]]$requested
                Allowed=($mask -in $entry.Allowed)
                Label=($entry.Order -join ' -> ') + '; restore ' + ($requested -join ',')
            }
        }
    }

    It '<Label>: allowed=<Allowed>' -ForEach $cases {
        $operation = {
            Assert-NoIDSecurityBaselineOverlapRestore -SessionModuleNames $Order -RequestedModules $Requested
        }
        if ($Allowed) { $operation | Should -Not -Throw }
        else { $operation | Should -Throw -ExpectedMessage '*overlaps the later*' }
    }

    It 'does not couple ASR and DNS when the baseline was never applied' {
        foreach ($order in @(@('ASR', 'DNS'), @('DNS', 'ASR'))) {
            foreach ($module in $order) {
                {
                    Assert-NoIDSecurityBaselineOverlapRestore -SessionModuleNames $order -RequestedModules @($module)
                } | Should -Not -Throw
            }
        }
    }
}

Describe 'Privacy AppX firewall overlap follows the sealed optional scopes' {
    BeforeAll {
        function New-AppxFirewallOrderFixture {
            [CmdletBinding(SupportsShouldProcess)]
            param([string]$Root,[string[]]$Order,[bool]$HasFamilies,[bool]$SkipFirewall,[int]$AdvancedSchema=5)
            if(-not $PSCmdlet.ShouldProcess($Root,'Create isolated firewall-order fixture')){return}
            $id='Session_'+[guid]::NewGuid().ToString('N')
            $path=Join-Path $Root $id
            $stamp='2026-09-05T12:00:00.0000000+00:00'
            $families=@(if($HasFamilies){'Microsoft.TestApp_8wekyb3d8bbwe'})
            $privacy=[pscustomobject]@{
                SchemaVersion=7;ApplicableServiceNames=@();ApplicableScheduledTaskPaths=@()
                Tier1PolicyRemovalSelected=$false;Tier2BloatwareRemovalSelected=$HasFamilies
                WeatherWidgetRemovalSelected=$false
                AppxFirewallState=[pscustomobject]@{PackageFamilyNames=$families;EntryCount=0;Entries=@()}
            }
            $advanced=[pscustomobject]@{
                SchemaVersion=$AdvancedSchema;SkipFirewallLayer=$SkipFirewall;DisableRDP=$false;AdminSharesDisabled=$false
                DisableUPnP=$false;DisableWirelessDisplayCompletely=$false;DisableDiscoveryProtocolsCompletely=$false
                DisableIPv6Completely=$false;EnableFirewallShieldsUp=$false;RdpHostSupported=$true
                ManagedPolicySupported=$true;WirelessDisplaySupported=$false
            }
            $manifest=[pscustomobject]@{
                schemaVersion=2;sessionId=$id;displayName='Firewall order fixture';sessionType='manual'
                timestamp=$stamp;frameworkVersion='2.2.5';sharedArtifacts=@();totalItems=0;restorable=$true;modules=@()
            }
            foreach($name in $Order){
                $directory=Join-Path $path $name
                $null=New-Item -ItemType Directory -Path $directory -Force
                $data=if($name -eq 'Privacy'){@{Privacy_PreState=$privacy}}else{@{AdvancedSecurity_PreState=$advanced;NetBIOS_Adapters=@()}}
                if($name -eq 'Privacy' -and $HasFamilies){
                    $data.Privacy_BloatwareActions=[pscustomobject]@{
                        SchemaVersion=3;WeatherWidgetRemovalSelected=$false
                        Entries=@([pscustomobject]@{Present=$true;PackageFamilyName=$families[0]})
                    }
                }
                if($name -eq 'AdvancedSecurity' -and -not $SkipFirewall){$data.AdvancedSecurity_FirewallPolicy='isolated fixture'}
                $artifacts=@(foreach($key in $data.Keys){
                    $firewall=$key -eq 'AdvancedSecurity_FirewallPolicy'
                    $fileName=$key+$(if($firewall){'.wfw'}else{'.json'})
                    $file=Join-Path $directory $fileName
                    ConvertTo-Json -InputObject $data[$key] -Depth 10|Set-Content $file -Encoding UTF8
                    [pscustomobject]@{
                        name=$key;type=$(if($firewall){'FirewallPolicy'}else{$name})
                        target=$(if($firewall){'LocalFirewallPolicy'}else{$key})
                        relativePath=($name+'/'+$fileName);sha256=(Get-FileHash $file).Hash
                    }
                })
                $manifest.modules+=@([pscustomobject]@{
                    name=$name;backupPath=$name;status='Success';timestamp=$stamp
                    itemsBackedUp=$artifacts.Count;artifacts=$artifacts
                })
                $manifest.totalItems+=$artifacts.Count
            }
            $manifest|ConvertTo-Json -Depth 15|Set-Content (Join-Path $path 'manifest.json') -Encoding UTF8
            return @{Path=$path;Manifest=$manifest}
        }
    }
    BeforeEach {
        # Exercise real session/file/hash/decision validation. Native payload
        # semantics have their own tests; these inert files isolate ordering.
        Mock Assert-ArtifactContentBinding { }
    }
    It '<First> first: families=<HasFamilies>, skipped firewall=<SkipFirewall>' -ForEach @(
        foreach($first in @('Privacy','AdvancedSecurity')){
            foreach($case in @(
                @{HasFamilies=$true;SkipFirewall=$false;Coupled=$true},
                @{HasFamilies=$false;SkipFirewall=$false;Coupled=$false},
                @{HasFamilies=$true;SkipFirewall=$true;Coupled=$false}
            )){@{First=$first;HasFamilies=$case.HasFamilies;SkipFirewall=$case.SkipFirewall;Coupled=$case.Coupled}}
        }
    ) {
        $later=if($First -eq 'Privacy'){'AdvancedSecurity'}else{'Privacy'}
        $fixture=New-AppxFirewallOrderFixture -Root $TestDrive -Order @($First,$later) -HasFamilies $HasFamilies -SkipFirewall $SkipFirewall
        $files=@(Get-ChildItem $fixture.Path -File -Recurse|ForEach-Object{(Get-FileHash $_.FullName).Hash}|Sort-Object)
        $earlierOnly={Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest -RequestedModules @($First.ToUpperInvariant())}
        if($Coupled){$earlierOnly|Should -Throw '*overlaps the later*'}
        else {$earlierOnly|Should -Not -Throw}
        {Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest -RequestedModules @($later.ToUpperInvariant())}|Should -Not -Throw
        {Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest -RequestedModules @($First,$later)}|Should -Not -Throw
        {Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest}|Should -Not -Throw
        @(Get-ChildItem $fixture.Path -File -Recurse|ForEach-Object{(Get-FileHash $_.FullName).Hash}|Sort-Object)|Should -Be $files
        Test-Path (Join-Path $fixture.Path 'restore-receipt.json')|Should -BeFalse
    }
    It 'accepts AdvancedSecurity prestate schema <Schema>: <Accepted>' -ForEach @(
        @{Schema=5;Accepted=$true},@{Schema=6;Accepted=$true},@{Schema=4;Accepted=$false},@{Schema=7;Accepted=$false}
    ) {
        # Sessions sealed by earlier 2.2.6 builds use schema 5; new backups use 6.
        $fixture=New-AppxFirewallOrderFixture -Root $TestDrive -Order @('AdvancedSecurity') -HasFamilies $false -SkipFirewall $false -AdvancedSchema $Schema
        $assert={Assert-SessionManifest -SessionPath $fixture.Path -Manifest $fixture.Manifest}
        if($Accepted){$assert|Should -Not -Throw}
        else {$assert|Should -Throw "*AdvancedSecurity pre-state has unsupported schema $Schema*"}
    }
}
