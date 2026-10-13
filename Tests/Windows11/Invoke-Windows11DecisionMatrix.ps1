#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Exercise every supported non-interactive module decision on a disposable Windows 11 VM.

.DESCRIPTION
    This is a non-mutating release gate. It enumerates the complete Cartesian
    product of every public/configurable decision inside each module (455 live
    DryRun scenarios), proves that invalid configuration values fail closed,
    and verifies that no backup session or covered live state changed.

    Destructive Apply/Verify/Restore coverage remains the responsibility of
    Invoke-Windows11BavrValidation.ps1; this runner complements it by covering
    decision routing without repeatedly mutating the host.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmDisposableVm,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot 'Windows11-Decision-Matrix.json'),

    [Parameter(Mandatory = $false)]
    [switch]$StateOnly,

    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI', 'EdgeHardening', 'AdvancedSecurity')]
    [string]$RuntimeScope = 'All',

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 300)]
    [int]$StabilityDelaySeconds = 5
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ConfirmDisposableVm -or $env:NOID_DISPOSABLE_VM -ne 'true') {
    throw 'Refusing the Windows 11 decision matrix without both -ConfirmDisposableVm and NOID_DISPOSABLE_VM=true'
}
if (-not $StateOnly -and $RuntimeScope -ne 'All') {
    throw 'The complete DryRun matrix requires exact potentially owned service runtime for All modules'
}
# Resolve operator paths once. .NET file APIs and child processes use the
# process working directory, which Windows PowerShell does not move with Set-Location.
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$backupRoot = Join-Path $repoRoot 'Backups'
$tempRoot = Join-Path $env:TEMP ('NoIDDecisionMatrix_' + [Guid]::NewGuid().ToString('N'))
$matrixConfigPath = Join-Path $tempRoot 'config.json'
$firewallStateHelper = Join-Path $repoRoot 'Modules\AdvancedSecurity\Private\AdvancedSecurityFirewallPolicyState.ps1'
$stateFingerprintHelper = Join-Path $PSScriptRoot 'Windows11StateFingerprint.ps1'
$nativePolicyFingerprintHelper = Join-Path $PSScriptRoot 'Windows11NativePolicyFingerprint.ps1'
$winInetStateHelper = Join-Path $repoRoot 'Modules\AdvancedSecurity\Private\AdvancedSecurityWinInet.ps1'
$moduleNames = @('SecurityBaseline', 'ASR', 'DNS', 'Privacy', 'AntiAI', 'EdgeHardening', 'AdvancedSecurity')
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function ConvertTo-CanonicalValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Value,
        [Parameter(Mandatory = $true)]
        [string]$Kind
    )

    if ($null -eq $Value) { return '<null>' }
    switch ($Kind) {
        'Binary' { return [Convert]::ToBase64String([byte[]]$Value) }
        'Unknown' { return [Convert]::ToBase64String([byte[]]$Value) }
        'MultiString' { return (ConvertTo-Json -InputObject @([string[]]$Value) -Compress) }
        # Registry APIs expose the bit pattern through signed Int32/Int64 on
        # Windows PowerShell 5.1. BitConverter preserves values such as
        # DWORD 0xFFFFFFFF instead of throwing on a direct [uint32] cast.
        'DWord' {
            $unsigned = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$Value), 0)
            return $unsigned.ToString([Globalization.CultureInfo]::InvariantCulture)
        }
        'QWord' {
            $unsigned = [BitConverter]::ToUInt64([BitConverter]::GetBytes([int64]$Value), 0)
            return $unsigned.ToString([Globalization.CultureInfo]::InvariantCulture)
        }
        default { return [string]$Value }
    }
}

function Get-RegistryTreeState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Roots,
        [hashtable]$ValueNamesByRoot = @{},
        [string]$InteractiveUserSid
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($root in $Roots) {
        $rootMatch = [regex]::Match($root, '^(HKLM|HKCU):\\(.+)$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $rootMatch.Success) { throw "Unsupported registry fingerprint root: $root" }
        $subKeyPath = $rootMatch.Groups[2].Value
        $isUserRoot = $rootMatch.Groups[1].Value -ieq 'HKCU'
        $hive = if (-not $isUserRoot) {
            [Microsoft.Win32.RegistryHive]::LocalMachine
        }
        else {
            # Administrator protection can give the elevated runner a separate
            # profile. Bind every HKCU measurement to the resolved desktop user;
            # never substitute the elevated process's current-user hive.
            if ($InteractiveUserSid -cnotmatch '^S-1-(?:5-21|12-1)-[0-9]+(?:-[0-9]+)+$') {
                throw 'User registry fingerprint requires a resolved interactive user SID'
            }
            $subKeyPath = $InteractiveUserSid + '\' + $subKeyPath
            [Microsoft.Win32.RegistryHive]::Users
        }
        $baseKey = $null
        $rootKey = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
            if ($isUserRoot) {
                $userHive = $baseKey.OpenSubKey($InteractiveUserSid, $false)
                if ($null -eq $userHive) { throw 'Interactive user registry hive is not loaded' }
                $userHive.Dispose()
            }
            $rootKey = $baseKey.OpenSubKey($subKeyPath, $false)
            if ($null -eq $rootKey) {
                $entries.Add([PSCustomObject]@{ Root = $root; Kind = 'Missing'; Path = ''; Name = ''; Type = ''; Data = '' })
                continue
            }

            function Read-MatrixRegistryKey {
                param(
                    [Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$Key,
                    [AllowEmptyString()][string]$RelativePath,
                    [Parameter(Mandatory = $true)][hashtable]$SelectedValues
                )
                try {
                    $entries.Add([PSCustomObject]@{ Root = $root; Kind = 'Key'; Path = $RelativePath; Name = ''; Type = ''; Data = '' })
                    [string[]]$valueNames = @($Key.GetValueNames())
                    if ($SelectedValues.ContainsKey($root)) {
                        $valueNames = @($valueNames | Where-Object { $_ -in $SelectedValues[$root] })
                    }
                    [Array]::Sort($valueNames, [StringComparer]::Ordinal)
                    foreach ($valueName in $valueNames) {
                        $valueKind = $Key.GetValueKind($valueName).ToString()
                        $rawValue = $Key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        $entries.Add([PSCustomObject]@{
                                Root = $root; Kind = 'Value'; Path = $RelativePath; Name = [string]$valueName; Type = $valueKind
                                Data = ConvertTo-CanonicalValue -Value $rawValue -Kind $valueKind
                            })
                    }
                    # A value-scoped root must not capture unrelated data such
                    # as an autologon password beside Winlogon's ScRemoveOption.
                    if ($SelectedValues.ContainsKey($root)) { return }
                    [string[]]$subKeyNames = @($Key.GetSubKeyNames())
                    [Array]::Sort($subKeyNames, [StringComparer]::Ordinal)
                    foreach ($subKeyName in $subKeyNames) {
                        $subPath = if ([string]::IsNullOrEmpty($RelativePath)) { $subKeyName } else { "$RelativePath\$subKeyName" }
                        $subKey = $null
                        try { $subKey = $Key.OpenSubKey($subKeyName, $false) }
                        catch [System.Security.SecurityException] {
                            $entries.Add([PSCustomObject]@{ Root = $root; Kind = 'Inaccessible'; Path = $subPath; Name = ''; Type = $_.Exception.GetType().FullName; Data = '' })
                            continue
                        }
                        catch [System.UnauthorizedAccessException] {
                            $entries.Add([PSCustomObject]@{ Root = $root; Kind = 'Inaccessible'; Path = $subPath; Name = ''; Type = $_.Exception.GetType().FullName; Data = '' })
                            continue
                        }
                        if ($null -eq $subKey) {
                            throw "Registry key disappeared during fingerprint capture: $root\$subPath"
                        }
                        Read-MatrixRegistryKey -Key $subKey -RelativePath $subPath -SelectedValues $SelectedValues
                    }
                }
                finally {
                    if ($Key -ne $rootKey) { $Key.Dispose() }
                }
            }
            Read-MatrixRegistryKey -Key $rootKey -RelativePath '' -SelectedValues $ValueNamesByRoot
        }
        finally {
            if ($null -ne $rootKey) { $rootKey.Dispose() }
            if ($null -ne $baseKey) { $baseKey.Dispose() }
        }
    }
    return @($entries)
}

function Get-ObjectHash {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$InputObject)

    $json = ConvertTo-Json -InputObject $InputObject -Depth 20 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-StableRegistryFingerprintEntries {
    <#
    .SYNOPSIS
        Normalizes registry identities and omits OS-owned volatile values.

    .DESCRIPTION
        Registry paths and value names are case-insensitive.  A fingerprint
        must therefore normalize their casing.  Process IDs, DHCP lease
        clocks, adapter-derived DHCP aggregate caches, TCP/IP health state, the
        LSA boot-latched RunAsPPL mirror, and the Server service's boot-generated
        GUID are OS-owned runtime state rather than NoID-managed configuration;
        they remain in the diagnostic snapshot but are excluded from the gate
        hash.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entries)

    $stableEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in @($Entries)) {
        $isVolatile = Test-Windows11OsOwnedVolatileRegistryEntry -Entry $entry
        if ($isVolatile) { continue }
        $stableEntries.Add([PSCustomObject]@{
                Root = ([string]$entry.Root).ToLowerInvariant()
                Kind = [string]$entry.Kind
                Path = ([string]$entry.Path).ToLowerInvariant()
                Name = ([string]$entry.Name).ToLowerInvariant()
                Type = [string]$entry.Type
                Data = [string]$entry.Data
            })
    }
    # Registry providers do not promise cross-process enumeration order. Hash a
    # canonical sequence so two equal states cannot produce different hashes.
    return @($stableEntries | Sort-Object Root, Path, Kind, Name, Type, Data)
}

function Get-DeclaredAppxCatalogState {
    <#
    .SYNOPSIS
        Captures the stable AppX identities that NoID explicitly classifies.

    .DESCRIPTION
        The complete Get-AppxPackage inventory is not a configuration surface
        owned by NoID. Windows can install a language/resource package or swap
        a Store-app version while an unrelated module is being tested. Hashing
        PackageFullName therefore turns an OS update into a false BAVR failure.

        Keep the safety net scoped to the canonical Privacy catalog instead:
        every removable and protected app remains covered, while package
        version churn and unrelated Windows packages are excluded. User SIDs,
        install states and package-family identities still expose an actual
        removal, registration change or protected-app regression.
    #>
    [CmdletBinding()]
    param()

    $catalogPath = Join-Path $repoRoot 'Modules\Privacy\Config\Bloatware.json'
    $catalog = Get-Content -LiteralPath $catalogPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    $removeApps = @($catalog.RemoveApps | ForEach-Object { [string]$_ })
    $optionalRemoveApps = @($catalog.OptionalRemoveApps.PSObject.Properties | ForEach-Object { [string]$_.Value })
    $protectedApps = @($catalog.ProtectedApps | ForEach-Object { [string]$_ })
    $catalogNames = @($removeApps + $optionalRemoveApps + $protectedApps | Sort-Object -Unique)
    if ($removeApps.Count -eq 0 -or $optionalRemoveApps.Count -eq 0 -or $protectedApps.Count -eq 0 -or
        $catalogNames.Count -ne ($removeApps.Count + $optionalRemoveApps.Count + $protectedApps.Count) -or
        @($catalogNames | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -match '[*?]' }).Count -gt 0) {
        throw 'Privacy AppX catalog is empty, malformed, duplicated, or contains wildcards'
    }

    $state = [System.Collections.Generic.List[object]]::new()
    foreach ($catalogName in $catalogNames) {
        $packages = @(Get-AppxPackage -AllUsers -Name $catalogName -ErrorAction Stop)
        $familyNames = @($packages | ForEach-Object { [string]$_.PackageFamilyName } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        $userStates = @($packages | ForEach-Object {
                foreach ($userInformation in @($_.PackageUserInformation)) {
                    [PSCustomObject]@{
                        Sid = [string]$userInformation.UserSecurityId.Sid
                        InstallState = [string]$userInformation.InstallState
                    }
                }
            } | Sort-Object Sid, InstallState -Unique)
        $state.Add([PSCustomObject]@{
                Name = $catalogName
                Classification = if ($catalogName -in $removeApps) {
                    'Removable'
                }
                elseif ($catalogName -in $optionalRemoveApps) {
                    'OptionalRemovable'
                }
                else {
                    'Protected'
                }
                Present = $packages.Count -gt 0
                PackageFamilyNames = $familyNames
                UserStates = $userStates
            })
    }
    return @($state)
}

function Get-CoveredLiveState {
    [CmdletBinding()]
    param()

    # Use one desktop identity for both HKCU and WinINet. A missing or ambiguous
    # desktop cannot prove recovery of that user's configuration.
    $winInetUser = Get-AdvancedSecurityInteractiveUser

    # Roots the product provably writes. The two SYSTEM roots are required:
    # Enable-RdpNLA writes Control\Terminal Server (fDenyTSConnections) and the
    # Maximum-profile IPv6 disable writes Services\Tcpip6\Parameters
    # (DisabledComponents). Without them, a restore that failed to bring those
    # values back would still fingerprint as "exact prestate restored".
    $registryRoots = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server',
        'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters',
        'HKLM:\SOFTWARE\Policies',
        'HKCU:\Software\Policies',
        'HKLM:\SOFTWARE\Classes\ms-copilot',
        'HKLM:\SOFTWARE\Classes\ms-edge-copilot',
        'HKCU:\Software\Classes\ms-copilot',
        'HKCU:\Software\Classes\ms-edge-copilot',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies',
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings\WebSearchProviders',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement',
        'HKCU:\SOFTWARE\Microsoft\InputPersonalization',
        'HKCU:\SOFTWARE\Microsoft\Personalization\Settings',
        'HKCU:\Control Panel\International\User Profile',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders',
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    )
    # The baseline also owns values outside these policy subtrees. Capture
    # exact key/value presence, type and data without dumping adjacent secrets.
    $additionalRegistryValues = @{
        # VBS policies and the local scenario controls are separate state. Read
        # both before Apply so a post-reboot runtime difference cannot be
        # mistaken for an exact restore merely because SOFTWARE\Policies matches.
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' = @('EnableVirtualizationBasedSecurity', 'RequirePlatformSecurityFeatures', 'Locked', 'Mandatory', 'RequireMicrosoftSignedBootChain')
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' = @('Enabled', 'Locked', 'WasEnabledBy', 'EnabledBootId', 'HVCIMATRequired')
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard' = @('Enabled', 'Locked', 'Managed')
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' = @('Enabled', 'Locked')
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks' = @('Enabled', 'Locked', 'AuditModeEnabled', 'WasEnabledBy')
        'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE' = @('RDVDenyWriteAccess')
        'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' = @('AutoConnectAllowedOEM')
        'HKLM:\SYSTEM\CurrentControlSet\Control\Print' = @('RpcAuthnLevelPrivacyEnabled')
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' = @('DisableExceptionChainValidation')
        'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' = @('DriverLoadPolicy')
        'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10' = @('Start')
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' = @('EnablePlainTextPassword', 'RequireSecuritySignature')
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' = @('ScRemoveOption')
        'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' = @('DisablePasswordChange', 'requiresignorseal', 'requirestrongkey', 'sealsecurechannel', 'signsecurechannel')
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' = @('ProtectionMode')
        'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' = @('LDAPClientIntegrity')
    }

    $firewallExport = Join-Path $tempRoot ('firewall_' + [Guid]::NewGuid().ToString('N') + '.wfw')
    try {
        $netshOutput = @(& netsh.exe advfirewall export $firewallExport 2>&1)
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $firewallExport -PathType Leaf)) {
            throw "Firewall state export failed (exit $LASTEXITCODE): $($netshOutput -join ' ')"
        }
        $firewallState = Get-AdvancedSecurityFirewallPolicyState -PolicyFilePath $firewallExport
        $stableFirewallState = Get-Windows11StableFirewallFingerprintState -State $firewallState
    }
    finally {
        if (Test-Path -LiteralPath $firewallExport) { Remove-Item -LiteralPath $firewallExport -Force -ErrorAction Stop }
    }

    $defender = Get-MpPreference -ErrorAction Stop
    $asrIds = @($defender.AttackSurfaceReductionRules_Ids)
    $asrActions = @($defender.AttackSurfaceReductionRules_Actions)
    if ($asrIds.Count -ne $asrActions.Count) {
        throw "Defender returned mismatched ASR ID/action arrays: ids=$($asrIds.Count), actions=$($asrActions.Count)"
    }
    $asrRules = @(
        for ($index = 0; $index -lt $asrIds.Count; $index++) {
            [PSCustomObject]@{
                Id = ([string]$asrIds[$index]).ToLowerInvariant()
                Action = [int]$asrActions[$index]
            }
        }
    ) | Sort-Object Id, Action
    # Defender does not define ordering for either the parallel ASR arrays or
    # exclusion output. Hash their semantic set instead of provider order so
    # an exact remove/re-add restore cannot produce a false state drift.
    $asrExclusions = @(
        $defender.AttackSurfaceReductionOnlyExclusions |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ } |
            Sort-Object -Unique
    )
    $defenderState = [PSCustomObject]@{
        AttackSurfaceReductionRules = @($asrRules)
        AttackSurfaceReductionOnlyExclusions = @($asrExclusions)
        MAPSReporting = $defender.MAPSReporting
        SubmitSamplesConsent = $defender.SubmitSamplesConsent
        DisableBlockAtFirstSeen = $defender.DisableBlockAtFirstSeen
        CloudBlockLevel = $defender.CloudBlockLevel
    }
    $dnsState = @(
        Get-DnsClientServerAddress -ErrorAction Stop |
            Sort-Object InterfaceIndex, AddressFamily |
            Select-Object InterfaceIndex, InterfaceAlias, AddressFamily, @{ Name = 'ServerAddresses'; Expression = { @($_.ServerAddresses) } }
    )
    $dohState = @(
        Get-DnsClientDohServerAddress -ErrorAction Stop |
            Sort-Object ServerAddress |
            Select-Object ServerAddress, DohTemplate, AllowFallbackToUdp, AutoUpgrade
    )
    $dnsInterfaceHelperPath = Join-Path $repoRoot 'Modules\DNS\Private\DnsInterfaceDoh.ps1'
    $dnsCanonicalHelperPath = Join-Path $repoRoot 'Modules\DNS\Private\ConvertTo-DnsCanonicalAddress.ps1'
    if (-not (Test-Path -LiteralPath $dnsInterfaceHelperPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $dnsCanonicalHelperPath -PathType Leaf)) {
        throw 'Native DNS interface fingerprint helpers are missing'
    }
    . $dnsCanonicalHelperPath
    . $dnsInterfaceHelperPath
    $dnsInterfaceState = @(foreach ($adapter in @(Get-NetAdapter -Physical -ErrorAction Stop |
                Where-Object { $_.Status -in @('Up', 'Disconnected') } | Sort-Object InterfaceGuid)) {
            [PSCustomObject]@{
                InterfaceGuid = [string]$adapter.InterfaceGuid
                IPv4 = Get-DnsInterfaceDohState -InterfaceGuid ([string]$adapter.InterfaceGuid) -AddressFamily 2
                IPv6 = Get-DnsInterfaceDohState -InterfaceGuid ([string]$adapter.InterfaceGuid) -AddressFamily 23
            }
        })
    $serviceNames = @('WinDefend', 'LanmanServer', 'TermService', 'SessionEnv', 'UmRdpService', 'RemoteRegistry', 'SSDPSRV', 'upnphost', 'lmhosts', 'WFDSConMgrSvc', 'fdPHost', 'FDResPub', 'XboxGipSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc')
    # Every service a module config declares for mutation MUST be part of the
    # fingerprint, or a restore that fails to re-enable it is invisible (for
    # example DiagTrack, dmwappushservice and WerSvc in the Privacy Strict and
    # Paranoid profiles). Derive the union from the shipped configs and fail the
    # capture loudly if a config names a service without an identity.
    foreach ($privacyConfigPath in @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'Modules\Privacy\Config') -Filter 'Privacy-*.json' -File)) {
        $privacyConfig = Get-Content -LiteralPath $privacyConfigPath.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($privacyConfig.PSObject.Properties['Services']) {
            foreach ($declaredService in @($privacyConfig.Services)) {
                $declaredName = if ($declaredService -is [string]) { $declaredService } else { [string]$declaredService.Name }
                if ([string]::IsNullOrWhiteSpace($declaredName)) {
                    throw "Privacy config $($privacyConfigPath.Name) declares a service without a name"
                }
                if ($declaredName -notin $serviceNames) { $serviceNames += $declaredName }
            }
        }
    }
    $services = @(
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Where-Object Name -in $serviceNames |
            Sort-Object Name |
            Select-Object Name, StartMode, State
    )
    $exactRuntimeNames = @(switch ($RuntimeScope) {
        'All' { 'SSDPSRV'; 'WerSvc' }
        'AdvancedSecurity' { 'SSDPSRV' }
        'Privacy' { 'WerSvc' }
    })
    $stableServices = @(Get-Windows11StableServiceFingerprintState -Services $services -ExactRuntimeNames $exactRuntimeNames)
    foreach ($serviceName in $serviceNames) {
        $additionalRegistryValues["HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"] = @('Start', 'DelayedAutoStart')
    }
    $netbios = @(
        Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop |
            Where-Object IPEnabled |
            Sort-Object InterfaceIndex |
            Select-Object InterfaceIndex, TcpipNetbiosOptions
    )
    $ipv6Bindings = @(
        Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop |
            Sort-Object Name |
            Select-Object Name, InterfaceDescription, Enabled
    )
    $taskNames = @(
        '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator',
        '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip',
        '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser',
        '\Microsoft\XblGameSave\XblGameSaveTask'
    )
    $taskState = @(
        Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $taskNames -contains ("$($_.TaskPath)$($_.TaskName)") } |
            Sort-Object TaskPath, TaskName |
            Select-Object TaskPath, TaskName,
                @{ Name='Enabled'; Expression={ [string]$_.State -ne 'Disabled' } },
                @{ Name='Definition'; Expression={
                    ([xml](Export-ScheduledTask -TaskPath $_.TaskPath -TaskName $_.TaskName -ErrorAction Stop)).OuterXml
                } }
    )
    $appxCatalogState = @(Get-DeclaredAppxCatalogState)
    $queriedWinInetState = Invoke-AdvancedSecurityWinInetUserState -User $winInetUser -Operation Query
    $winInetAutoDetectState = [PSCustomObject]@{
        Applicable       = $true
        Sid              = [string]$winInetUser.Sid
        AutoDetectEnabled = [bool]$queriedWinInetState.AutoDetectEnabled
    }

    # Intermediate empty keys created by Apply also belong to exact restore.
    # Record their existence only, without broadening the value capture.
    foreach ($valueRoot in @($additionalRegistryValues.Keys)) {
        $parent = $valueRoot.Substring(0, $valueRoot.LastIndexOf('\'))
        while ($parent -notin @('HKLM:\SOFTWARE', 'HKLM:\SYSTEM')) {
            if (-not $additionalRegistryValues.ContainsKey($parent)) { $additionalRegistryValues[$parent] = @() }
            $separator = $parent.LastIndexOf('\')
            if ($separator -lt 0) { throw 'Additional registry fingerprint root has no supported boundary' }
            $parent = $parent.Substring(0, $separator)
        }
    }
    $registryState = @(Get-RegistryTreeState -Roots $registryRoots -InteractiveUserSid $winInetUser.Sid)
    $registryState += @(Get-RegistryTreeState -Roots @($additionalRegistryValues.Keys | Sort-Object) -ValueNamesByRoot $additionalRegistryValues)
    $stableRegistryState = @(Get-StableRegistryFingerprintEntries -Entries $registryState)
    $nativePolicies = Get-Windows11NativePolicyFingerprintState -TemporaryDirectory $tempRoot
    $localGroupPolicy = Get-Windows11LocalGroupPolicyFingerprintState
    $groupPolicyRecovery = Get-Windows11GroupPolicyRecoveryEvidence -RawState $localGroupPolicy

    $components = [ordered]@{
        Registry = Get-ObjectHash -InputObject $stableRegistryState
        Firewall = Get-ObjectHash -InputObject $stableFirewallState
        Defender = Get-ObjectHash -InputObject $defenderState
        DNS = Get-ObjectHash -InputObject @($dnsState, $dohState, $dnsInterfaceState)
        Services = Get-ObjectHash -InputObject $stableServices
        NetBIOS = Get-ObjectHash -InputObject $netbios
        IPv6Bindings = Get-ObjectHash -InputObject $ipv6Bindings
        ScheduledTasks = Get-ObjectHash -InputObject $taskState
        AppxCatalogTargets = Get-ObjectHash -InputObject $appxCatalogState
        WinInetAutoDetect = Get-ObjectHash -InputObject $winInetAutoDetectState
        AuditPolicies = Get-ObjectHash -InputObject @($nativePolicies.AuditPolicies)
        AccountAndPrivilegePolicies = Get-ObjectHash -InputObject @($nativePolicies.SecurityPolicies)
        LocalGroupPolicy = Get-ObjectHash -InputObject $localGroupPolicy
    }
    return [PSCustomObject]@{
        Components = [PSCustomObject]$components
        CombinedHash = Get-ObjectHash -InputObject ([PSCustomObject]$components)
        RegistryEntries = @($registryState)
        StableRegistryEntries = @($stableRegistryState)
        FirewallEntryCount = [int]$firewallState.EntryCount
        StableFirewallEntryCount = [int]$stableFirewallState.EntryCount
        StableFirewallState = $stableFirewallState
        AppxCatalogEntries = @($appxCatalogState)
        ServiceEntries = @($services)
        StableServiceEntries = @($stableServices)
        AuditPolicyEntryCount = @($nativePolicies.AuditPolicies).Count
        AccountAndPrivilegeEntryCount = @($nativePolicies.SecurityPolicies).Count
        LocalGroupPolicyEntryCount = @($localGroupPolicy.Entries).Count
        LocalGroupPolicyRecoveryEvidence = $groupPolicyRecovery
    }
}

function Get-PublicStateSummary {
    param([Parameter(Mandatory = $false)]$State)
    if ($null -eq $State) { return $null }
    return [PSCustomObject]@{
        Components = $State.Components
        CombinedHash = $State.CombinedHash
        RegistryEntryCount = @($State.RegistryEntries).Count
        StableRegistryEntryCount = @($State.StableRegistryEntries).Count
        FirewallEntryCount = [int]$State.FirewallEntryCount
        StableFirewallEntryCount = [int]$State.StableFirewallEntryCount
        ServiceEntries = @($State.ServiceEntries)
        StableServiceEntries = @($State.StableServiceEntries)
        AuditPolicyEntryCount = $State.AuditPolicyEntryCount
        AccountAndPrivilegeEntryCount = $State.AccountAndPrivilegeEntryCount
        LocalGroupPolicyEntryCount = $State.LocalGroupPolicyEntryCount
        LocalGroupPolicyRecoveryEvidence = $State.LocalGroupPolicyRecoveryEvidence
    }
}

function Get-RegistryStateDifferences {
    param(
        [Parameter(Mandatory = $true)]$Reference,
        [Parameter(Mandatory = $true)]$Candidate
    )
    $referenceLines = @($Reference | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress })
    $candidateLines = @($Candidate | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress })
    return @(Compare-Object -ReferenceObject $referenceLines -DifferenceObject $candidateLines -CaseSensitive |
        Select-Object InputObject, SideIndicator)
}

function Get-BackupFolderNames {
    if (-not (Test-Path -LiteralPath $backupRoot -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $backupRoot -Directory -ErrorAction Stop | Sort-Object Name | ForEach-Object Name)
}

function ConvertTo-ScenarioRecord {
    param([string]$Module, [string]$Id, [hashtable]$Decisions, [bool]$ExpectedSuccess = $true)
    return [PSCustomObject]@{ Module = $Module; Id = $Id; Decisions = $Decisions; ExpectedSuccess = $ExpectedSuccess }
}

function Get-Scenarios {
    $items = [System.Collections.Generic.List[object]]::new()
    # The three Administrator protection modes rotate through the sixteen
    # combinations, so each mode runs with both UAC and all Boolean values.
    $adminProtectionModes = @('Credentials', 'Consent', 'Classic')
    $securityBaselineIndex = 0
    foreach ($bitLocker in @($false, $true)) {
        foreach ($samples in @($false, $true)) {
            foreach ($screen in @($false, $true)) {
                foreach ($uac in @('Strict', 'SecureDesktop')) {
                    $adminProtection = $adminProtectionModes[$securityBaselineIndex % $adminProtectionModes.Count]
                    $securityBaselineIndex++
                    $items.Add((ConvertTo-ScenarioRecord -Module SecurityBaseline -Id "bitlocker-$bitLocker-samples-$samples-screen-$screen-uac-$uac-adminprotection-$adminProtection" -ExpectedSuccess:$true -Decisions @{
                                bitLockerUSBEnforcement = $bitLocker; submitAllSamples = $samples; smartScreenWarnMode = $screen; standardUserElevationMode = $uac
                                adminProtectionMode = $adminProtection
                            }))
                }
            }
        }
    }
    foreach ($management in @($false, $true)) {
        foreach ($software in @($false, $true)) {
            foreach ($cloud in @($false, $true)) {
                $items.Add((ConvertTo-ScenarioRecord -Module ASR -Id "management-$management-software-$software-cloud-$cloud" -Decisions @{
                            usesManagementTools = $management; allowNewSoftware = $software; continueWithoutCloud = $cloud
                        }))
            }
        }
    }
    foreach ($provider in @('Cloudflare', 'Quad9', 'AdGuard', 'KEEP')) {
        foreach ($mode in @('REQUIRE', 'ALLOW')) {
            $items.Add((ConvertTo-ScenarioRecord -Module DNS -Id "provider-$provider-mode-$mode" -ExpectedSuccess:$true -Decisions @{ provider = $provider; dohMode = $mode }))
        }
    }
    foreach ($mode in @('MSRecommended', 'Strict', 'Paranoid')) {
        foreach ($clipboard in @($false, $true)) {
            foreach ($tier1 in @($false, $true)) {
                foreach ($tier2 in @('none', 'standard')) {
                    $weatherWidgetChoices = if ($tier2 -eq 'standard') { @($false, $true) } else { @($false) }
                    foreach ($weatherWidget in $weatherWidgetChoices) {
                        $items.Add((ConvertTo-ScenarioRecord -Module Privacy -Id "mode-$mode-clipboard-$clipboard-tier1-$tier1-tier2-$tier2-weather-$weatherWidget" -Decisions @{
                                    mode = $mode; disableCloudClipboard = $clipboard; applyStorePackagePolicy = $tier1
                                    removeBloatwareApps = $tier2; removeWeatherWidget = $weatherWidget
                                }))
                    }
                }
            }
        }
    }
    $items.Add((ConvertTo-ScenarioRecord -Module AntiAI -Id 'canonical' -Decisions @{}))
    foreach ($extensions in @($false, $true)) {
        $items.Add((ConvertTo-ScenarioRecord -Module EdgeHardening -Id "allowExtensions-$extensions" -Decisions @{ allowExtensions = $extensions }))
    }
    foreach ($securityProfileChoice in @('Balanced', 'Enterprise', 'Maximum')) {
        foreach ($mask in 0..127) {
            $items.Add((ConvertTo-ScenarioRecord -Module AdvancedSecurity -Id "profile-$securityProfileChoice-mask-$mask" -Decisions @{
                        securityProfile = $securityProfileChoice
                        skipFirewallLayer = [bool]($mask -band 1)
                        disableRDP = [bool]($mask -band 2)
                        forceAdminShares = [bool]($mask -band 4)
                        disableUPnP = [bool]($mask -band 8)
                        disableWirelessDisplay = [bool]($mask -band 16)
                        disableDiscoveryProtocols = [bool]($mask -band 32)
                        disableIPv6 = [bool]($mask -band 64)
                    }))
        }
    }
    return @($items)
}

function Initialize-MatrixScenarioConfig {
    param([Parameter(Mandatory = $true)]$Scenario)
    $config = Get-Content -LiteralPath (Join-Path $repoRoot 'config.json') -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $config.options.nonInteractive = $true
    foreach ($name in $moduleNames) { $config.modules.$name.enabled = ($name -ceq $Scenario.Module) }
    foreach ($decision in $Scenario.Decisions.GetEnumerator()) {
        $config.modules.($Scenario.Module).($decision.Key) = $decision.Value
    }
    [IO.File]::WriteAllText($matrixConfigPath, ($config | ConvertTo-Json -Depth 12), $utf8NoBom)
    Initialize-Config -ConfigPath $matrixConfigPath -CreateDefault $false
    # Directly imported modules use the process-global matrix facade installed
    # below. Publish only the already schema-validated object to that facade.
    $global:NoIDMatrixConfig = $config
}

function Invoke-Scenario {
    param([Parameter(Mandatory = $true)]$Scenario)
    Initialize-MatrixScenarioConfig -Scenario $Scenario
    $manifest = Join-Path $repoRoot "Modules\$($Scenario.Module)\$($Scenario.Module).psd1"
    Remove-Module $Scenario.Module -Force -ErrorAction SilentlyContinue
    Import-Module $manifest -Force -ErrorAction Stop
    $environment = @{}
    $asrDefinitions = @()
    if ($Scenario.Module -ceq 'ASR') {
        $environment = & (Get-Module ASR) {
            @{ CloudProtectionEnabled = (Test-CloudProtection); ConfigMgrDetected = [bool](Test-ConfigMgrPresence) }
        }
        $asrDefinitions = Get-Content -LiteralPath (Join-Path $repoRoot 'Modules\ASR\Config\ASR-Rules.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    elseif ($Scenario.Module -ceq 'AdvancedSecurity') {
        $environment = & (Get-Module AdvancedSecurity) {
            $applicability = Get-AdvancedSecurityApplicability
            $computer = Get-AdvancedSecurityComputerSystem
            @{ RdpHostSupported = $applicability.RdpHostSupported
               WirelessDisplaySupported = $applicability.WirelessDisplaySupported
               DomainJoined = [bool]$computer.PartOfDomain }
        }
    }
    elseif ($Scenario.Module -ceq 'AntiAI') {
        $environment = & (Get-Module AntiAI) { @{ AntiAITargets = @(Get-AntiAIRegistryTargets) } }
    }
    $commandName = switch ($Scenario.Module) {
        'SecurityBaseline' { 'Invoke-SecurityBaseline' }
        'ASR' { 'Invoke-ASRRules' }
        'DNS' { 'Invoke-DNSConfiguration' }
        'Privacy' { 'Invoke-PrivacyHardening' }
        'AntiAI' { 'Invoke-AntiAI' }
        'EdgeHardening' { 'Invoke-EdgeHardening' }
        'AdvancedSecurity' { 'Invoke-AdvancedSecurity' }
    }
    $beforeBackups = @(Get-BackupFolderNames)
    $started = Get-Date
    $allOutput = @(& $commandName -DryRun -InformationAction SilentlyContinue)
    $resultObjects = @($allOutput | Where-Object { $null -ne $_ -and $_.PSObject.Properties.Name -contains 'Success' })
    if ($resultObjects.Count -ne 1) {
        throw "Scenario $($Scenario.Module)/$($Scenario.Id) returned $($resultObjects.Count) result objects with a Success contract"
    }
    $result = $resultObjects[0]
    $afterBackups = @(Get-BackupFolderNames)
    if (($beforeBackups -join '|') -cne ($afterBackups -join '|')) {
        throw "DryRun scenario $($Scenario.Module)/$($Scenario.Id) changed the backup-session inventory"
    }
    if ($result.PSObject.Properties.Name -contains 'BackupCreated' -and [bool]$result.BackupCreated) {
        throw "DryRun scenario $($Scenario.Module)/$($Scenario.Id) reported BackupCreated=true"
    }
    foreach ($property in @($result.PSObject.Properties | Where-Object { $_.Name -match '(?i)Applied$|Changed$|Removed$|Configured$' })) {
        if ($null -ne $property.Value -and [int64]$property.Value -ne 0) {
            throw "DryRun scenario $($Scenario.Module)/$($Scenario.Id) reported a mutation count in $($property.Name)=$($property.Value)"
        }
    }
    $expectedSuccess = [bool]$Scenario.ExpectedSuccess
    if ($Scenario.Module -ceq 'ASR' -and -not $environment.CloudProtectionEnabled -and
        -not $Scenario.Decisions.continueWithoutCloud) { $expectedSuccess = $false }
    if ([bool]$result.Success -ne $expectedSuccess) {
        throw "Scenario $($Scenario.Module)/$($Scenario.Id) success mismatch: expected $expectedSuccess, got $($result.Success); errors=$(@($result.Errors) -join '; ')"
    }
    if ($Scenario.Module -eq 'SecurityBaseline') {
        foreach ($decisionProperty in @(
                'BitLockerUSBEnforcement',
                'SubmitAllSamples',
                'SmartScreenWarnMode',
                'StandardUserElevationMode',
                'ConsentPromptBehaviorUser',
                'AdminProtectionMode',
                'TypeOfAdminApprovalMode',
                'InteractiveAccountIsAdministrator'
            )) {
            if ($null -eq $result.Details.$decisionProperty) {
                throw "SecurityBaseline scenario $($Scenario.Id) returned no authoritative $decisionProperty decision"
            }
        }
        if ([bool]$result.Details.BitLockerUSBEnforcement -ne [bool]$Scenario.Decisions.bitLockerUSBEnforcement) {
            throw "SecurityBaseline scenario $($Scenario.Id) consumed BitLockerUSBEnforcement=$($result.Details.BitLockerUSBEnforcement) instead of the configured $($Scenario.Decisions.bitLockerUSBEnforcement)"
        }
        if ([bool]$result.Details.SubmitAllSamples -ne [bool]$Scenario.Decisions.submitAllSamples) {
            throw "SecurityBaseline scenario $($Scenario.Id) consumed SubmitAllSamples=$($result.Details.SubmitAllSamples) instead of the configured $($Scenario.Decisions.submitAllSamples)"
        }
        if ([bool]$result.Details.SmartScreenWarnMode -ne [bool]$Scenario.Decisions.smartScreenWarnMode) {
            throw "SecurityBaseline scenario $($Scenario.Id) consumed SmartScreenWarnMode=$($result.Details.SmartScreenWarnMode) instead of the configured $($Scenario.Decisions.smartScreenWarnMode)"
        }
        if ($result.Details.StandardUserElevationMode -and
            [string]$result.Details.StandardUserElevationMode -cne [string]$Scenario.Decisions.standardUserElevationMode) {
            throw "SecurityBaseline scenario $($Scenario.Id) consumed '$($result.Details.StandardUserElevationMode)' instead of the configured '$($Scenario.Decisions.standardUserElevationMode)'"
        }
        if ([string]$Scenario.Decisions.standardUserElevationMode -ceq 'Strict' -and
            $null -ne $result.Details.ConsentPromptBehaviorUser -and [int]$result.Details.ConsentPromptBehaviorUser -ne 0) {
            throw "SecurityBaseline Strict scenario $($Scenario.Id) did not select ConsentPromptBehaviorUser=0"
        }
        if ([string]$Scenario.Decisions.standardUserElevationMode -ceq 'SecureDesktop') {
            if ([string]$result.Details.StandardUserElevationMode -cne 'SecureDesktop' -or
                [int]$result.Details.ConsentPromptBehaviorUser -ne 1) {
                throw "SecurityBaseline SecureDesktop scenario $($Scenario.Id) did not select ConsentPromptBehaviorUser=1"
            }
        }
        if ([string]$result.Details.AdminProtectionMode -cne [string]$Scenario.Decisions.adminProtectionMode -or
            [int]$result.Details.TypeOfAdminApprovalMode -ne $(if ([string]$Scenario.Decisions.adminProtectionMode -ceq 'Classic') { 1 } else { 2 })) {
            throw "SecurityBaseline scenario $($Scenario.Id) consumed administrator protection '$($result.Details.AdminProtectionMode)' (TypeOfAdminApprovalMode=$($result.Details.TypeOfAdminApprovalMode)) instead of the configured '$($Scenario.Decisions.adminProtectionMode)'"
        }
    }
    if ($Scenario.Module -eq 'DNS' -and [string]$Scenario.Decisions.provider -ceq 'KEEP' -and
        ([string]$result.Status -cne 'Success' -or
            [string]$result.Provider -cne 'KEEP' -or
            [string]$result.DoHMode -cne 'KEEP')) {
        throw "DNS KEEP scenario $($Scenario.Id) was not reported as a successful canonical KEEP/KEEP decision"
    }
    $decisionEvidence = Assert-Windows11DecisionEvidence -Scenario $Scenario -Result $result `
        -Environment $environment -AsrDefinitions $asrDefinitions
    return [PSCustomObject]@{
        Module = $Scenario.Module
        Id = $Scenario.Id
        Decisions = [PSCustomObject]$Scenario.Decisions
        ExpectedSuccess = $expectedSuccess
        ActualSuccess = [bool]$result.Success
        DecisionEvidence = $decisionEvidence
        Status = if ($result.PSObject.Properties.Name -contains 'Status') { [string]$result.Status } else { $null }
        DurationMs = [int64]((Get-Date) - $started).TotalMilliseconds
        Passed = $true
    }
}

function Test-InvalidConfigurations {
    $cases = @(
        @{ Id = 'SecurityBaseline.standardUserElevationMode'; Module = 'SecurityBaseline'; Key = 'standardUserElevationMode'; Value = 'Prompt' },
        @{ Id = 'SecurityBaseline.adminProtectionMode'; Module = 'SecurityBaseline'; Key = 'adminProtectionMode'; Value = 'Off' },
        @{ Id = 'SecurityBaseline.bitLockerUSBEnforcement'; Module = 'SecurityBaseline'; Key = 'bitLockerUSBEnforcement'; Value = 'false' },
        @{ Id = 'SecurityBaseline.submitAllSamples'; Module = 'SecurityBaseline'; Key = 'submitAllSamples'; Value = 'false' },
        @{ Id = 'SecurityBaseline.smartScreenWarnMode'; Module = 'SecurityBaseline'; Key = 'smartScreenWarnMode'; Value = 'false' },
        @{ Id = 'ASR.usesManagementTools'; Module = 'ASR'; Key = 'usesManagementTools'; Value = 'false' },
        @{ Id = 'ASR.allowNewSoftware'; Module = 'ASR'; Key = 'allowNewSoftware'; Value = 0 },
        @{ Id = 'ASR.continueWithoutCloud'; Module = 'ASR'; Key = 'continueWithoutCloud'; Value = 'yes' },
        @{ Id = 'DNS.provider'; Module = 'DNS'; Key = 'provider'; Value = 'Automatic' },
        @{ Id = 'DNS.dohMode'; Module = 'DNS'; Key = 'dohMode'; Value = 'OFF' },
        @{ Id = 'Privacy.mode'; Module = 'Privacy'; Key = 'mode'; Value = 'Default' },
        @{ Id = 'Privacy.disableCloudClipboard'; Module = 'Privacy'; Key = 'disableCloudClipboard'; Value = 'true' },
        @{ Id = 'Privacy.applyStorePackagePolicy'; Module = 'Privacy'; Key = 'applyStorePackagePolicy'; Value = 1 },
        @{ Id = 'Privacy.removeBloatwareApps'; Module = 'Privacy'; Key = 'removeBloatwareApps'; Value = 'all' },
        @{ Id = 'Privacy.removeWeatherWidget'; Module = 'Privacy'; Key = 'removeWeatherWidget'; Value = $true },
        @{ Id = 'EdgeHardening.allowExtensions'; Module = 'EdgeHardening'; Key = 'allowExtensions'; Value = 'false' },
        @{ Id = 'AdvancedSecurity.securityProfile'; Module = 'AdvancedSecurity'; Key = 'securityProfile'; Value = 'Custom' },
        @{ Id = 'AdvancedSecurity.skipFirewallLayer'; Module = 'AdvancedSecurity'; Key = 'skipFirewallLayer'; Value = 'false' },
        @{ Id = 'AdvancedSecurity.disableRDP'; Module = 'AdvancedSecurity'; Key = 'disableRDP'; Value = 0 },
        @{ Id = 'AdvancedSecurity.forceAdminShares'; Module = 'AdvancedSecurity'; Key = 'forceAdminShares'; Value = 'true' },
        @{ Id = 'AdvancedSecurity.disableUPnP'; Module = 'AdvancedSecurity'; Key = 'disableUPnP'; Value = 1 },
        @{ Id = 'AdvancedSecurity.disableWirelessDisplay'; Module = 'AdvancedSecurity'; Key = 'disableWirelessDisplay'; Value = 'no' },
        @{ Id = 'AdvancedSecurity.disableDiscoveryProtocols'; Module = 'AdvancedSecurity'; Key = 'disableDiscoveryProtocols'; Value = 'false' },
        @{ Id = 'AdvancedSecurity.disableIPv6'; Module = 'AdvancedSecurity'; Key = 'disableIPv6'; Value = 'true' }
    )
    $records = foreach ($case in $cases) {
        $config = Get-Content -LiteralPath (Join-Path $repoRoot 'config.json') -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $config.modules.($case.Module).($case.Key) = $case.Value
        [IO.File]::WriteAllText($matrixConfigPath, ($config | ConvertTo-Json -Depth 12), $utf8NoBom)
        $rejected = $false
        $message = $null
        try { Initialize-Config -ConfigPath $matrixConfigPath -CreateDefault $false }
        catch { $rejected = $true; $message = $_.Exception.Message }
        if (-not $rejected) { throw "Invalid configuration case was accepted: $($case.Id)" }
        [PSCustomObject]@{ Id = $case.Id; Rejected = $true; Error = $message }
    }
    return @($records)
}

$startedAt = Get-Date
$failure = $null
$invalidRecords = @()
$beforeState = $null
$afterState = $null
$displayVersion = $null
$os = $null
$stateDifferences = @()
$scenarioRecords = [System.Collections.Generic.List[object]]::new()
try {
    $null = New-Item -ItemType Directory -Path $tempRoot -Force -ErrorAction Stop
    $functionsBeforeCoreLoad = @(Get-ChildItem Function: | ForEach-Object Name)
    . (Join-Path $repoRoot 'Core\Logger.ps1')
    . (Join-Path $repoRoot 'Core\Config.ps1')
    . (Join-Path $repoRoot 'Core\Validator.ps1')
    . (Join-Path $repoRoot 'Core\Rollback.ps1')
    . (Join-Path $repoRoot 'Core\NonInteractive.ps1')
    . (Join-Path $repoRoot 'Utils\Hardware.ps1')
    . (Join-Path $repoRoot 'Utils\Compatibility.ps1')
    . (Join-Path $repoRoot 'Utils\Dependencies.ps1')
    . $firewallStateHelper
    . $stateFingerprintHelper
    . $nativePolicyFingerprintHelper
    . (Join-Path $PSScriptRoot 'Windows11GroupPolicyRecovery.ps1')
    . (Join-Path $PSScriptRoot 'Windows11DecisionEvidence.ps1')
    . $winInetStateHelper
    # Imported product modules execute in their own module session state. The
    # production entry point exposes these dot-sourced framework functions to
    # that session state; reproduce that visibility explicitly for this direct
    # module matrix without importing the full orchestration workflow.
    $coreFunctionNames = @(Get-ChildItem Function: | ForEach-Object Name | Where-Object { $_ -notin $functionsBeforeCoreLoad })
    foreach ($coreFunctionName in $coreFunctionNames) {
        $definition = (Get-Item -LiteralPath "Function:$coreFunctionName" -ErrorAction Stop).ScriptBlock
        Set-Item -LiteralPath "Function:global:$coreFunctionName" -Value $definition -Force -ErrorAction Stop
    }
    # PowerShell functions copied between session states retain their original
    # script-scope binding. A direct module import would therefore be able to
    # see the helper but not the runner's changing $script:Config object. Use a
    # strict facade for this matrix: a missing decision is an error, never a
    # silent fallback to the helper's Default argument.
    $global:NoIDMatrixConfig = $null
    Set-Item -LiteralPath Function:global:Get-Config -Force -Value {
        if ($null -eq $global:NoIDMatrixConfig) { throw 'Decision-matrix configuration has not been published' }
        return $global:NoIDMatrixConfig
    }
    Set-Item -LiteralPath Function:global:Test-NonInteractiveMode -Force -Value { return $true }
    Set-Item -LiteralPath Function:global:Get-NonInteractiveValue -Force -Value {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)][string]$Module,
            [Parameter(Mandatory = $true)][string]$Key,
            $Default = $null,
            [switch]$Required
        )
        $null = $Default, $Required
        if ($null -eq $global:NoIDMatrixConfig -or
            $global:NoIDMatrixConfig.modules.PSObject.Properties.Name -notcontains $Module -or
            $global:NoIDMatrixConfig.modules.$Module.PSObject.Properties.Name -notcontains $Key) {
            throw "Decision-matrix configuration is missing $Module.$Key"
        }
        return $global:NoIDMatrixConfig.modules.$Module.$Key
    }
    Set-Item -LiteralPath Function:global:Write-NonInteractiveDecision -Force -Value {
        [CmdletBinding()]
        param([Parameter(Mandatory = $true)][string]$Module, [Parameter(Mandatory = $true)][string]$Decision, $Value = $null)
        Write-Log -Level INFO -Message "[DecisionMatrix] $Decision : $Value" -Module $Module
    }
    Initialize-Logger -LogDirectory (Join-Path $tempRoot 'Logs') -MinimumLevel ERROR -EnableConsole $false -EnableFile $true
    $env:NOIDPRIVACY_NONINTERACTIVE = 'true'

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $currentVersion = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $displayVersion = [string]$currentVersion.GetValue('DisplayVersion', '')
    $build = [int]$os.BuildNumber
    $supported24H2Profile = $displayVersion -ceq '24H2' -and $build -in 26100..26199
    $supported25H2Profile = $displayVersion -ceq '25H2' -and $build -in 26200..26299
    $supported26H2Profile = $displayVersion -ceq '26H2' -and $build -in 26300..27999
    $supportedProfile = $supported24H2Profile -or $supported25H2Profile -or $supported26H2Profile
    if ([int]$os.ProductType -ne 1 -or -not $supportedProfile) {
        throw "The complete release decision matrix requires an exact Windows 11 24H2/26100..26199, 25H2/26200..26299 or 26H2/26300..27999 client profile; DisplayVersion='$displayVersion', build=$build, ProductType=$($os.ProductType)"
    }

    $beforeBackups = @(Get-BackupFolderNames)
    $beforeState = Get-CoveredLiveState
    if ($StateOnly) {
        if ($StabilityDelaySeconds -gt 0) { Start-Sleep -Seconds $StabilityDelaySeconds }
    }
    else {
        $invalidRecords = @(Test-InvalidConfigurations)
        $scenarios = @(Get-Scenarios)
        if ($scenarios.Count -ne 455) { throw "Decision-matrix generator produced $($scenarios.Count) scenarios instead of 455" }
        foreach ($scenario in $scenarios) {
            $scenarioRecords.Add((Invoke-Scenario -Scenario $scenario))
        }
    }
    $afterState = Get-CoveredLiveState
    $afterBackups = @(Get-BackupFolderNames)
    if ($beforeState.CombinedHash -cne $afterState.CombinedHash) {
        $changedComponents = @($beforeState.Components.PSObject.Properties.Name | Where-Object {
                [string]$beforeState.Components.$_ -cne [string]$afterState.Components.$_
            })
        if ($changedComponents -contains 'Registry') {
            $stateDifferences = @(Get-RegistryStateDifferences -Reference $beforeState.StableRegistryEntries -Candidate $afterState.StableRegistryEntries)
        }
        $contextName = if ($StateOnly) { 'fingerprint stability interval' } else { 'DryRun matrix' }
        throw "Covered live state changed across ${contextName}: $($changedComponents -join ', ')"
    }
    if (($beforeBackups -join '|') -cne ($afterBackups -join '|')) {
        throw 'Backup-session inventory changed across the DryRun matrix'
    }
}
catch {
    $failure = $_.Exception.ToString()
}
finally {
    foreach ($name in $moduleNames) { Remove-Module $name -Force -ErrorAction SilentlyContinue }
    # Write-Log holds a process-lifetime handle on the log file under
    # $tempRoot; release it or the recursive delete below leaks the tree.
    if (Get-Command Close-Logger -ErrorAction SilentlyContinue) { Close-Logger }
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

$summaryByModule = @($scenarioRecords | Group-Object Module | Sort-Object Name | ForEach-Object {
        [PSCustomObject]@{ Module = $_.Name; ScenarioCount = $_.Count; Passed = @($_.Group | Where-Object Passed -ne $true).Count -eq 0 }
    })
$expectedScenarioCount = if ($StateOnly) { 0 } else { 455 }
$expectedInvalidCount = if ($StateOnly) { 0 } else { 23 }
$resultDocument = [PSCustomObject]@{
    SchemaVersion = 1
    CapturedAt = (Get-Date).ToString('o')
    StartedAt = $startedAt.ToString('o')
    DisplayVersion = $displayVersion
    BuildNumber = if ($null -ne $os) { [int]$os.BuildNumber } else { $null }
    Mode = if ($StateOnly) { 'StateOnly' } else { 'DecisionMatrix' }
    RuntimeScope = $RuntimeScope
    ExpectedScenarioCount = $expectedScenarioCount
    ExecutedScenarioCount = $scenarioRecords.Count
    InvalidConfigurationCount = @($invalidRecords).Count
    InvalidConfigurations = @($invalidRecords)
    StateBefore = Get-PublicStateSummary -State $beforeState
    StateAfter = Get-PublicStateSummary -State $afterState
    RegistryDifferences = @($stateDifferences)
    RegistrySnapshotBefore = if ($StateOnly -and $null -ne $beforeState) { @($beforeState.RegistryEntries) } else { @() }
    FirewallSnapshotBefore = if ($StateOnly -and $null -ne $beforeState) { $beforeState.StableFirewallState } else { $null }
    AppxCatalogSnapshotBefore = if ($StateOnly -and $null -ne $beforeState) { @($beforeState.AppxCatalogEntries) } else { @() }
    SummaryByModule = $summaryByModule
    Scenarios = @($scenarioRecords)
    Error = $failure
    Passed = ($null -eq $failure -and $scenarioRecords.Count -eq $expectedScenarioCount -and @($invalidRecords).Count -eq $expectedInvalidCount)
}
$outputDirectory = Split-Path $OutputPath -Parent
if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
    $null = New-Item -ItemType Directory -Path $outputDirectory -Force -ErrorAction Stop
}
[IO.File]::WriteAllText($OutputPath, ($resultDocument | ConvertTo-Json -Depth 20), $utf8NoBom)
if (-not $resultDocument.Passed) {
    Write-Host "Windows 11 decision matrix failed: $failure" -ForegroundColor Red
    exit 1
}
if ($StateOnly) {
    Write-Host 'Windows 11 covered-state fingerprint remained stable.' -ForegroundColor Green
}
else {
    Write-Host "Windows 11 decision matrix passed: $($scenarioRecords.Count) live scenarios, $(@($invalidRecords).Count) invalid cases rejected." -ForegroundColor Green
}
exit 0
