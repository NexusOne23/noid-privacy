#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repoRoot 'Tests/Windows11/Windows11StateFingerprint.ps1')

    function Get-FirewallEntry {
        param(
            [string]$Name = '{E299FCA6-C891-49AC-A87B-10415DE331A2}',
            [string]$Data = 'v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=5353|App=C:\Program Files (x86)\Microsoft\EdgeWebView\Application\150.0.4078.83\msedgewebview2.exe|Name=Microsoft Edge (mDNS-In)|EmbedCtxt=Microsoft Edge WebView2 Runtime|'
        )
        return [PSCustomObject]@{
            Kind = 'Value'; Path = 'FirewallRules'; Name = $Name; Type = 'String'; Data = $Data
        }
    }

    function Get-SecHealthFirewallEntry {
        param(
            [string]$Sid = 'S-1-5-21-1111111111-2222222222-3333333333-1001',
            [string]$Version = '1000.29628.1000.0',
            [ValidateSet('In', 'Out')]
            [string]$Direction = 'In'
        )
        $suffix = if ($Direction -ceq 'In') { 'In-Allow-ServerCapability' } else { 'Out-Allow-AllCapabilities' }
        $profiles = if ($Direction -ceq 'In') {
            'Dir=In|Profile=Domain|Profile=Private|'
        }
        else {
            'Dir=Out|Profile=Domain|Profile=Private|Profile=Public|'
        }
        $display = "@{Microsoft.SecHealthUI_${Version}_x64__8wekyb3d8bbwe?ms-resource://Microsoft.SecHealthUI/resources/PackageDisplayName}"
        $description = "@{Microsoft.SecHealthUI_${Version}_x64__8wekyb3d8bbwe?ms-resource://Microsoft.SecHealthUI/resources/ProductDescription}"
        $data = "v2.33|Action=Allow|Active=TRUE|$profiles" +
            "Name=$display|Desc=$description|PFN=Microsoft.SecHealthUI_8wekyb3d8bbwe|" +
            "LUOwn=$Sid|EmbedCtxt=$display|Platform=2:6:2|Platform2=GTEQ|"
        return Get-FirewallEntry `
            -Name "Microsoft.SecHealthUI_8wekyb3d8bbwe$Sid-$suffix" -Data $data
    }
}

Describe 'Windows 11 stable firewall fingerprint' {
    It 'excludes the exact OS-owned Edge WebView2 mDNS auto-rule' {
        $ordinary = Get-FirewallEntry -Name 'NoID-owned' -Data 'v2.33|Action=Block|Active=TRUE|Dir=Out|Name=NoID owned|'
        $volatile = Get-FirewallEntry
        $state = [PSCustomObject]@{ SchemaVersion = 1; EntryCount = 2; Entries = @($ordinary, $volatile) }

        $stable = Get-Windows11StableFirewallFingerprintState -State $state

        $stable.EntryCount | Should -Be 1
        @($stable.Entries).Count | Should -Be 1
        [string]$stable.Entries[0].Name | Should -Be 'NoID-owned'
    }

    It 'keeps every near match fail-closed' {
        $canonical = (Get-FirewallEntry).Data
        $nearMatches = @(
            (Get-FirewallEntry -Name 'not-a-guid')
            (Get-FirewallEntry -Data $canonical.Replace('|LPort=5353|', '|LPort=5354|'))
            (Get-FirewallEntry -Data $canonical.Replace('|Dir=In|', '|Dir=Out|'))
            (Get-FirewallEntry -Data $canonical.Replace('\Microsoft\EdgeWebView\', '\NoID\EdgeWebView\'))
            (Get-FirewallEntry -Data $canonical.Replace('|Name=Microsoft Edge (mDNS-In)|', '|Name=NoID rule|'))
            (Get-FirewallEntry -Data ($canonical + 'RA4=192.0.2.1|'))
            (Get-FirewallEntry -Data ($canonical + 'RPort=443|'))
            (Get-FirewallEntry -Data ($canonical + 'Dir=Out|'))
            (Get-FirewallEntry -Data $canonical.Replace('v2.33|', 'v2.34|'))
            (Get-FirewallEntry -Data $canonical.Replace('|EmbedCtxt=Microsoft Edge WebView2 Runtime|', '|EmbedCtxt=Custom|'))
        )
        $state = [PSCustomObject]@{
            SchemaVersion = 1; EntryCount = $nearMatches.Count; Entries = $nearMatches
        }

        $stable = Get-Windows11StableFirewallFingerprintState -State $state

        $stable.EntryCount | Should -Be $nearMatches.Count
        @($stable.Entries).Count | Should -Be $nearMatches.Count
    }

    It 'excludes only the exact Windows Security application capability rules' {
        $state = [PSCustomObject]@{
            SchemaVersion = 1
            EntryCount = 4
            Entries = @(
                (Get-SecHealthFirewallEntry -Sid 'S-1-5-21-1-2-3-1000' -Version '1000.26100.1.0' -Direction In)
                (Get-SecHealthFirewallEntry -Sid 'S-1-5-21-1-2-3-1000' -Version '1000.26100.1.0' -Direction Out)
                (Get-SecHealthFirewallEntry -Sid 'S-1-5-21-1-2-3-1001' -Version '1000.29628.1000.0' -Direction In)
                (Get-SecHealthFirewallEntry -Sid 'S-1-5-21-1-2-3-1001' -Version '1000.29628.1000.0' -Direction Out)
            )
        }

        $stable = Get-Windows11StableFirewallFingerprintState -State $state

        $stable.EntryCount | Should -Be 0
        @($stable.Entries).Count | Should -Be 0
    }

    It 'keeps every Windows Security near match fail-closed' {
        $canonical = Get-SecHealthFirewallEntry
        $nearMatches = @(
            (Get-FirewallEntry -Name $canonical.Name.Replace('-In-', '-Out-') -Data $canonical.Data)
            (Get-FirewallEntry -Name $canonical.Name -Data $canonical.Data.Replace('|Action=Allow|', '|Action=Block|'))
            (Get-FirewallEntry -Name $canonical.Name -Data $canonical.Data.Replace('|Active=TRUE|', '|Active=FALSE|'))
            (Get-FirewallEntry -Name $canonical.Name -Data $canonical.Data.Replace('|LUOwn=S-1-5-21-1111111111-2222222222-3333333333-1001|', '|LUOwn=S-1-5-21-1-2-3-1002|'))
            (Get-FirewallEntry -Name $canonical.Name -Data $canonical.Data.Replace('resources/ProductDescription', 'resources/OtherDescription'))
            (Get-FirewallEntry -Name $canonical.Name -Data $canonical.Data.Replace('PFN=Microsoft.SecHealthUI_8wekyb3d8bbwe', 'PFN=NoID.SecHealthUI_8wekyb3d8bbwe'))
            (Get-FirewallEntry -Name $canonical.Name -Data $canonical.Data.Replace('|Platform2=GTEQ|', '|Platform2=EQ|'))
        )
        $state = [PSCustomObject]@{
            SchemaVersion = 1; EntryCount = $nearMatches.Count; Entries = $nearMatches
        }

        $stable = Get-Windows11StableFirewallFingerprintState -State $state

        $stable.EntryCount | Should -Be $nearMatches.Count
        @($stable.Entries).Count | Should -Be $nearMatches.Count
    }

    It 'rejects an internally inconsistent input state' {
        $state = [PSCustomObject]@{ SchemaVersion = 1; EntryCount = 2; Entries = @((Get-FirewallEntry)) }
        { Get-Windows11StableFirewallFingerprintState -State $state } | Should -Throw
    }
}

Describe 'Windows 11 stable registry fingerprint' {
    It 'excludes only the proven Search jump-list timestamp subtree' {
        (Test-Windows11OsOwnedVolatileRegistryEntry -Entry ([PSCustomObject]@{
                    Root = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
                    Kind = 'Value'; Path = 'JumplistData'; Name = 'powershell.exe'
                })) | Should -BeTrue
        foreach ($nearMatch in @(
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Kind='Value'; Path=''; Name='BingSearchEnabled' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Kind='Value'; Path='JumplistDataOther'; Name='powershell.exe' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Kind='Key'; Path='JumplistData'; Name='' }
            )) {
            (Test-Windows11OsOwnedVolatileRegistryEntry -Entry $nearMatch) | Should -BeFalse
        }
    }

    It 'excludes only the exact Windows Search installed-package revision cache' {
        (Test-Windows11OsOwnedVolatileRegistryEntry -Entry ([PSCustomObject]@{
                    Root = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
                    Kind = 'Value'; Path = ''; Name = 'InstalledPackagedAppsRevision'
                    Type = 'String'; Data = '{0871BF21-1596-4253-8407-B23106E6B576}'
                })) | Should -BeTrue
        foreach ($nearMatch in @(
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Kind='Value'; Path='Child'; Name='InstalledPackagedAppsRevision'; Type='String'; Data='{0871BF21-1596-4253-8407-B23106E6B576}' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Kind='Value'; Path=''; Name='InstalledPackagedAppsRevisionOther'; Type='String'; Data='{0871BF21-1596-4253-8407-B23106E6B576}' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Kind='Value'; Path=''; Name='InstalledPackagedAppsRevision'; Type='DWord'; Data='1' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Kind='Value'; Path=''; Name='InstalledPackagedAppsRevision'; Type='String'; Data='not-a-guid' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Kind='Key'; Path=''; Name='InstalledPackagedAppsRevision'; Type='String'; Data='{0871BF21-1596-4253-8407-B23106E6B576}' }
            )) {
            (Test-Windows11OsOwnedVolatileRegistryEntry -Entry $nearMatch) | Should -BeFalse
        }
    }

    It 'bounds the clean-reboot runtime exception for <Name>' -ForEach @(
        @{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'; Name='InstalledWin32AppsRevision'; Type='String'; Data='{0871BF21-1596-4253-8407-B23106E6B576}'; Neighbor='BingSearchEnabled' }
        @{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'; Name='WebProviderLastNotificationBehaviorTimestamp'; Type='QWord'; Data='133000000000000000'; Neighbor='IsDynamicSearchBoxEnabled' }
        @{ Root='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; Name='InstanceID'; Type='String'; Data='0871bf21-1596-4253-8407-b23106e'; Neighbor='fDenyTSConnections' }
    ) {
        $entry = [PSCustomObject]@{ Root=$Root; Kind='Value'; Path=''; Name=$Name; Type=$Type; Data=$Data }
        Test-Windows11OsOwnedVolatileRegistryEntry -Entry $entry | Should -BeTrue
        foreach ($change in @(
                @{ Root=($Root + 'Other') }
                @{ Kind='Key' }
                @{ Path='Child' }
                @{ Name=($Name + 'Other') }
                @{ Name=$Neighbor }
                @{ Type='DWord' }
                @{ Data='invalid-runtime-data' }
            )) {
            $nearMatch = $entry.PSObject.Copy()
            foreach ($property in $change.Keys) { $nearMatch.$property = $change[$property] }
            Test-Windows11OsOwnedVolatileRegistryEntry -Entry $nearMatch | Should -BeFalse
        }
    }

    It 'bounds the console session number exception to its exact DWORD identity' {
        $entry = [PSCustomObject]@{ Root='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; Kind='Value'; Path=''; Name='GlassSessionId'; Type='DWord'; Data='2' }
        Test-Windows11OsOwnedVolatileRegistryEntry -Entry $entry | Should -BeTrue
        foreach ($change in @(
                @{ Kind='Key' }, @{ Path='WinStations' }, @{ Name='fDenyTSConnections' },
                @{ Type='String' }, @{ Data='-1' }, @{ Data='123456' }
            )) {
            $nearMatch = $entry.PSObject.Copy()
            foreach ($property in $change.Keys) { $nearMatch.$property = $change[$property] }
            Test-Windows11OsOwnedVolatileRegistryEntry -Entry $nearMatch | Should -BeFalse
        }
    }

    It 'excludes only proven Content Delivery Manager runtime records' {
        foreach ($path in @('Health', 'Health\Placement-SubscribedContent-353694')) {
            (Test-Windows11OsOwnedVolatileRegistryEntry -Entry ([PSCustomObject]@{
                        Root = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
                        Kind = 'Value'; Path = $path; Name = 'HealthEvaluation'
                    })) | Should -BeTrue
        }
        foreach ($entry in @(
                [PSCustomObject]@{ Kind='Key'; Path='CreativeEventCache'; Name=''; Type=''; Data='' }
                [PSCustomObject]@{ Kind='Value'; Path='CreativeEventCache\SubscribedContent-338387'; Name='LastCreativeBatchId'; Type='String'; Data='1786818017' }
                [PSCustomObject]@{ Kind='Key'; Path='CreativeEvents\SubscribedContent-280810'; Name=''; Type=''; Data='' }
                [PSCustomObject]@{ Kind='Value'; Path='CreativeEvents\SubscribedContent-338387'; Name=''; Type='DWord'; Data='0' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='AccelerateCacheRefreshLastDetected'; Type='QWord'; Data='134313420516398406' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='AccelerateUpdatePlacementLastHandled'; Type='QWord'; Data='134313420516398406' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='LastAccessed'; Type='QWord'; Data='134313420516398406' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='Availability'; Type='DWord'; Data='2' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='Availability'; Type='DWord'; Data='0' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='ContentId'; Type='String'; Data='6231017346`JJ_673555555550435534_QR-QR`5`0047ro36n3949nrsn82312s9o310no5q' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='ContentId'; Type='String'; Data='' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='HasContent'; Type='DWord'; Data='1' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='HasContent'; Type='DWord'; Data='0' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='LastUpdated'; Type='QWord'; Data='134313420516398406' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='ShortContentId'; Type='String'; Data='8ae0e47e363b4587860f5ad1e4c48805' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='ShortContentId'; Type='String'; Data='' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='UpdateDrivenByExpiration'; Type='DWord'; Data='0' }
                [PSCustomObject]@{ Kind='Value'; Path='Subscriptions\338387'; Name='UpdateDrivenByExpiration'; Type='DWord'; Data='1' }
                [PSCustomObject]@{ Kind='Value'; Path=''; Name='PreInstalledAppsEverEnabled'; Type='DWord'; Data='1' }
            )) {
            $entry | Add-Member -NotePropertyName Root -NotePropertyValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
            (Test-Windows11OsOwnedVolatileRegistryEntry -Entry $entry) | Should -BeTrue
        }
        foreach ($nearMatch in @(
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path=''; Name='Start_IrisRecommendations' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path=''; Name='ContentDeliveryAllowed'; Type='DWord'; Data='0' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path=''; Name='PreInstalledAppsEnabled'; Type='DWord'; Data='0' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path=''; Name='PreInstalledAppsEverEnabled'; Type='String'; Data='1' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='ContentId'; Type='String'; Data='contains a space' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='ContentId'; Type='String'; Data=('a' * 257) }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='ContentId'; Type='DWord'; Data='1' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='Availability'; Type='DWord'; Data='1' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='Availability'; Type='String'; Data='2' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='HasContent'; Type='String'; Data='1' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='HasContent'; Type='DWord'; Data='2' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='LastUpdated'; Type='DWord'; Data='134313420516398406' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='LastUpdated'; Type='QWord'; Data='not-a-clock' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='ShortContentId'; Type='String'; Data='not-32-hex-characters' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='ShortContentId'; Type='Binary'; Data='8ae0e47e363b4587860f5ad1e4c48805' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='UpdateDrivenByExpiration'; Type='String'; Data='0' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='UpdateDrivenByExpiration'; Type='DWord'; Data='2' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='AccelerateUpdatePlacementLastHandled'; Type='DWord'; Data='1' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='AccelerateUpdatePlacementLastHandled'; Type='QWord'; Data='not-a-clock' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\not-numeric'; Name='AccelerateUpdatePlacementLastHandled'; Type='QWord'; Data='134313420516398406' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\338387'; Name='SubscribedContent-338387Enabled'; Type='DWord'; Data='0' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Subscriptions\not-numeric'; Name='LastAccessed'; Type='QWord'; Data='134313420516398406' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Value'; Path='Healthy'; Name='HealthEvaluation' }
                [PSCustomObject]@{ Root='HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Kind='Key'; Path='Health'; Name='' }
            )) {
            (Test-Windows11OsOwnedVolatileRegistryEntry -Entry $nearMatch) | Should -BeFalse
        }
    }
}

Describe 'Windows 11 stable service fingerprint' {
    It 'normalizes only the Running or Stopped runtime of proven manual OS services' {
        foreach ($serviceName in @('SSDPSRV', 'WerSvc')) {
            $running = Get-Windows11StableServiceFingerprintState -ExactRuntimeNames @() -Services @(
                [PSCustomObject]@{ Name = $serviceName; StartMode = 'Manual'; State = 'Running' }
            )
            $stopped = Get-Windows11StableServiceFingerprintState -ExactRuntimeNames @() -Services @(
                [PSCustomObject]@{ Name = $serviceName; StartMode = 'Manual'; State = 'Stopped' }
            )

            $running[0].State | Should -Be '<OS_RUNTIME_MANAGED>'
            ($running | ConvertTo-Json -Compress) | Should -Be ($stopped | ConvertTo-Json -Compress)
        }
    }

    It 'detects runtime drift for both potentially owned services by default' {
        foreach ($serviceName in @('SSDPSRV', 'WerSvc')) {
            $running = Get-Windows11StableServiceFingerprintState -Services @(
                [PSCustomObject]@{ Name = $serviceName; StartMode = 'Manual'; State = 'Running' }
            )
            $stopped = Get-Windows11StableServiceFingerprintState -Services @(
                [PSCustomObject]@{ Name = $serviceName; StartMode = 'Manual'; State = 'Stopped' }
            )
            $running[0].State | Should -Be 'Running'
            $stopped[0].State | Should -Be 'Stopped'
            ($running | ConvertTo-Json -Compress) | Should -Not -Be ($stopped | ConvertTo-Json -Compress)
        }
    }

    It 'normalizes only the unowned service in a module-scoped capture' {
        $state = Get-Windows11StableServiceFingerprintState -ExactRuntimeNames @('ssdpSrv') -Services @(
            [PSCustomObject]@{ Name = 'SSDPSRV'; StartMode = 'Manual'; State = 'Running' }
            [PSCustomObject]@{ Name = 'WerSvc'; StartMode = 'Manual'; State = 'Running' }
        )
        $state[0].State | Should -Be 'Running'
        $state[1].State | Should -Be '<OS_RUNTIME_MANAGED>'
    }

    It 'keeps service identity, persistent mode, and noncanonical states fail-closed' {
        $wrongName = Get-Windows11StableServiceFingerprintState -Services @(
            [PSCustomObject]@{ Name = 'NotSSDPSRV'; StartMode = 'Manual'; State = 'Running' }
        )
        $disabled = Get-Windows11StableServiceFingerprintState -Services @(
            [PSCustomObject]@{ Name = 'SSDPSRV'; StartMode = 'Disabled'; State = 'Stopped' }
        )
        $paused = Get-Windows11StableServiceFingerprintState -Services @(
            [PSCustomObject]@{ Name = 'ssdpSrv'; StartMode = 'Manual'; State = 'Paused' }
        )
        $automaticWer = Get-Windows11StableServiceFingerprintState -Services @(
            [PSCustomObject]@{ Name = 'WerSvc'; StartMode = 'Auto'; State = 'Running' }
        )
        $pendingWer = Get-Windows11StableServiceFingerprintState -Services @(
            [PSCustomObject]@{ Name = 'WerSvc'; StartMode = 'Manual'; State = 'Start Pending' }
        )

        @($wrongName[0].State, $disabled[0].State, $paused[0].State,
            $automaticWer[0].State, $pendingWer[0].State) |
            Should -Be @('Running', 'Stopped', 'Paused', 'Running', 'Start Pending')
        @($wrongName[0].StartMode, $disabled[0].StartMode, $paused[0].StartMode,
            $automaticWer[0].StartMode, $pendingWer[0].StartMode) |
            Should -Be @('Manual', 'Disabled', 'Manual', 'Auto', 'Manual')
    }

    It 'rejects missing properties and duplicate service identities' {
        { Get-Windows11StableServiceFingerprintState -Services @(
                [PSCustomObject]@{ Name = 'SSDPSRV'; StartMode = 'Manual' }
            ) } | Should -Throw
        { Get-Windows11StableServiceFingerprintState -Services @(
                [PSCustomObject]@{ Name = 'SSDPSRV'; StartMode = 'Manual'; State = 'Stopped' }
                [PSCustomObject]@{ Name = 'ssdpSrv'; StartMode = 'Manual'; State = 'Running' }
            ) } | Should -Throw
    }
}
