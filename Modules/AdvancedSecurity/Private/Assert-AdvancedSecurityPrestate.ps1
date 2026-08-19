#Requires -Version 5.1

function Assert-AdvancedSecurityPrestate {
    <#
    .SYNOPSIS
        Reconcile every sealed AdvancedSecurity input immediately before Apply.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $artifacts = @($global:BackupIndex | Where-Object { [string]$_.Module -eq 'AdvancedSecurity' })
    $prestateArtifacts = @($artifacts | Where-Object {
            [string]$_.Type -eq 'AdvancedSecurity' -and [string]$_.Name -eq 'AdvancedSecurity_PreState'
        })
    if ($prestateArtifacts.Count -ne 1) {
        throw "Expected one AdvancedSecurity prestate artifact; found $($prestateArtifacts.Count)"
    }
    $snapshot = Get-Content -LiteralPath $prestateArtifacts[0].BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $validation = Assert-AdvancedSecurityRegistrySnapshot -Snapshot $snapshot

    $liveApplicability = Get-AdvancedSecurityApplicability
    if ([string]$liveApplicability.EditionFamily -cne [string]$snapshot.EditionFamily -or
        [bool]$liveApplicability.RdpHostSupported -ne [bool]$snapshot.RdpHostSupported -or
        [bool]$liveApplicability.ManagedPolicySupported -ne [bool]$snapshot.ManagedPolicySupported -or
        [bool]$liveApplicability.WirelessDisplaySupported -ne [bool]$snapshot.WirelessDisplaySupported) {
        throw 'AdvancedSecurity edition applicability changed after backup'
    }

    $savedWinInetUsers = @($validation.WinInetUsers)
    $currentInteractiveUser = Get-AdvancedSecurityInteractiveUser -AllowNone
    # Keep array shape explicit on Windows PowerShell 5.1; an array emitted by
    # an if-expression is otherwise unwrapped when it contains one object.
    $currentInteractiveUsers = @()
    if ($null -ne $currentInteractiveUser) {
        $currentInteractiveUsers = @($currentInteractiveUser)
    }
    if ($savedWinInetUsers.Count -ne $currentInteractiveUsers.Count -or
        ($savedWinInetUsers.Count -eq 1 -and
            ([string]$savedWinInetUsers[0].Sid -cne [string]$currentInteractiveUsers[0].Sid -or
             [int]$savedWinInetUsers[0].SessionId -ne [int]$currentInteractiveUsers[0].SessionId))) {
        throw 'Interactive Explorer user changed after AdvancedSecurity backup'
    }
    if ($savedWinInetUsers.Count -eq 1) {
        $currentWinInet = Invoke-AdvancedSecurityWinInetUserState -User $currentInteractiveUsers[0] -Operation Query
        if ([bool]$currentWinInet.AutoDetectEnabled -ne [bool]$savedWinInetUsers[0].AutoDetectEnabled) {
            throw 'WinINet AutoDetect state changed after AdvancedSecurity backup'
        }
    }

    foreach ($entry in @($validation.Entries)) {
        $path = [string]$entry.Path
        $name = [string]$entry.Name
        $keyExists = Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop
        if ($keyExists -ne [bool]$entry.KeyExisted) {
            throw "AdvancedSecurity key existence changed after backup: $path"
        }
        if ([bool]$entry.KeyOnly) { continue }

        $valueExists = $false
        $actualValue = $null
        $actualType = $null
        if ($keyExists) {
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            $valueExists = $key.GetValueNames() -contains $name
            if ($valueExists) {
                $actualValue = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $actualType = $key.GetValueKind($name).ToString()
            }
        }
        if ($valueExists -ne [bool]$entry.Exists) {
            throw "AdvancedSecurity value existence changed after backup: $path::$name"
        }
        if ($valueExists) {
            $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
            $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
            if ($actualType -cne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                throw "AdvancedSecurity value changed after backup: $path::$name"
            }
        }
    }

    $expectedServiceNames = @('lmhosts')
    if ([bool]$snapshot.DisableUPnP) { $expectedServiceNames += @('SSDPSRV', 'upnphost') }
    if ([bool]$snapshot.WirelessDisplaySupported -and [bool]$snapshot.DisableWirelessDisplayCompletely) {
        $expectedServiceNames += 'WFDSConMgrSvc'
    }
    if ([bool]$snapshot.DisableDiscoveryProtocolsCompletely) {
        $expectedServiceNames += @('FDResPub', 'fdPHost')
    }
    $allServiceArtifacts = @($artifacts | Where-Object { [string]$_.Type -eq 'Service' })
    $allServiceNames = @($allServiceArtifacts | ForEach-Object { [string]$_.ServiceName })
    if (@($allServiceNames | Sort-Object -Unique).Count -ne $allServiceNames.Count -or
        @($allServiceNames | Where-Object { $_ -notin $expectedServiceNames }).Count -ne 0) {
        throw 'AdvancedSecurity service artifact inventory is duplicated or outside the sealed decision'
    }
    $installedServices = @(Get-Service -ErrorAction Stop)
    foreach ($serviceName in $expectedServiceNames) {
        $live = @($installedServices | Where-Object { [string]$_.Name -eq $serviceName })
        $serviceArtifacts = @($artifacts | Where-Object {
                [string]$_.Type -eq 'Service' -and [string]$_.ServiceName -eq $serviceName
            })
        if ($serviceArtifacts.Count -eq 0) {
            if ($live.Count -ne 0) { throw "AdvancedSecurity service appeared after backup: $serviceName" }
            continue
        }
        if ($serviceArtifacts.Count -ne 1 -or $live.Count -ne 1) {
            throw "AdvancedSecurity service inventory changed after backup: $serviceName"
        }
        $saved = Get-Content -LiteralPath $serviceArtifacts[0].BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ([string]$live[0].Status -ne [string]$saved.Status -or
            [string]$live[0].StartType -ne [string]$saved.StartType) {
            throw "AdvancedSecurity service state changed after backup: $serviceName"
        }
        $serviceKey = Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -ErrorAction Stop
        $delayedExists = $serviceKey.GetValueNames() -contains 'DelayedAutoStart'
        if ($delayedExists -ne [bool]$saved.DelayedAutoStartExists -or
            ($delayedExists -and
                ($serviceKey.GetValueKind('DelayedAutoStart').ToString() -ne 'DWord' -or
                 [int]$serviceKey.GetValue('DelayedAutoStart') -ne [int]$saved.DelayedAutoStart))) {
            throw "AdvancedSecurity service delayed-start state changed after backup: $serviceName"
        }
    }

    $firewallArtifacts = @($artifacts | Where-Object {
            [string]$_.Type -eq 'FirewallPolicy' -and [string]$_.Name -eq 'AdvancedSecurity_FirewallPolicy'
        })
    if ([bool]$snapshot.SkipFirewallLayer) {
        if ($firewallArtifacts.Count -ne 0) { throw 'Skipped firewall layer unexpectedly has a backup artifact' }
    }
    else {
        if ($firewallArtifacts.Count -ne 1) { throw 'Enabled firewall layer has no unique policy artifact' }
        $verificationPath = Join-Path $env:TEMP "NoID_FirewallPreApply_$([Guid]::NewGuid().ToString('N')).wfw"
        try {
            $export = Start-Process -FilePath 'netsh.exe' `
                -ArgumentList @('advfirewall', 'export', "`"$verificationPath`"") `
                -Wait -NoNewWindow -PassThru -RedirectStandardOutput 'NUL' -ErrorAction Stop
            if ($export.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $verificationPath -PathType Leaf)) {
                throw "Firewall pre-Apply export failed with exit code $($export.ExitCode)"
            }
            $null = Assert-AdvancedSecurityFirewallPolicyEquivalent `
                -ReferenceFilePath $firewallArtifacts[0].BackupFile `
                -CandidateFilePath $verificationPath `
                -Context 'Firewall policy changed after AdvancedSecurity backup'
        }
        finally {
            Remove-Item -LiteralPath $verificationPath -Force -ErrorAction SilentlyContinue
        }
    }

    $wifiArtifacts = @($artifacts | Where-Object {
            [string]$_.Type -eq 'AdvancedSecurity' -and [string]$_.Name -eq 'WiFiDirect_Adapters'
        })
    $expectsWifi = [bool]$snapshot.WirelessDisplaySupported -and [bool]$snapshot.DisableWirelessDisplayCompletely
    if ($wifiArtifacts.Count -ne $(if ($expectsWifi) { 1 } else { 0 })) {
        throw 'Wi-Fi Direct artifact does not match the sealed decision'
    }
    if ($expectsWifi) {
        $savedWifi = Get-Content -LiteralPath $wifiArtifacts[0].BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $savedWifiState = @($savedWifi.Adapters | Select-Object InterfaceGuid, InterfaceDescription, AdminStatus |
            Sort-Object InterfaceGuid)
        $liveWifiState = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
            Where-Object { [string]$_.InterfaceDescription -like 'Microsoft Wi-Fi Direct Virtual*' } |
            Select-Object InterfaceGuid, InterfaceDescription, AdminStatus | Sort-Object InterfaceGuid)
        if (($savedWifiState | ConvertTo-Json -Compress) -cne ($liveWifiState | ConvertTo-Json -Compress)) {
            throw 'Wi-Fi Direct adapter inventory/state changed after AdvancedSecurity backup'
        }
    }

    $netbiosArtifacts = @($artifacts | Where-Object {
            [string]$_.Type -eq 'AdvancedSecurity' -and [string]$_.Name -eq 'NetBIOS_Adapters'
        })
    if ($netbiosArtifacts.Count -ne 1) { throw 'NetBIOS adapter artifact is missing or duplicated' }
    $savedNetbios = Get-Content -LiteralPath $netbiosArtifacts[0].BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $null = Assert-AdvancedSecurityNetBIOSSnapshot -Snapshot $savedNetbios
    $liveNetbios = Get-AdvancedSecurityNetBIOSState
    if (-not (Test-AdvancedSecurityNetBIOSStateEqual `
            -Reference $savedNetbios -Candidate $liveNetbios)) {
        throw 'NetBIOS adapter inventory/state changed after AdvancedSecurity backup'
    }

    $advancedArtifacts = @($artifacts | Where-Object { [string]$_.Type -eq 'AdvancedSecurity' })
    $expectedAdvancedNames = @('AdvancedSecurity_PreState', 'NetBIOS_Adapters')
    if ($expectsWifi) { $expectedAdvancedNames += 'WiFiDirect_Adapters' }
    $advancedNames = @($advancedArtifacts | ForEach-Object { [string]$_.Name })
    $expectedTotalArtifacts = $expectedAdvancedNames.Count + $allServiceArtifacts.Count +
        $firewallArtifacts.Count
    if ($artifacts.Count -ne $expectedTotalArtifacts -or
        @($advancedNames | Sort-Object -Unique).Count -ne $advancedNames.Count -or
        @($expectedAdvancedNames | Where-Object { $_ -notin $advancedNames }).Count -ne 0 -or
        @($advancedNames | Where-Object { $_ -notin $expectedAdvancedNames }).Count -ne 0) {
        throw 'AdvancedSecurity backup artifact inventory is incomplete, duplicated or unsupported'
    }

    return $true
}
