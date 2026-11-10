#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Exercise the original 2.2.5 DNS writer and current restore on a disposable NIC.
.DESCRIPTION
    Requires one disconnected physical test NIC with automatic DNS and no
    native static metadata. Exercises automatic/static IPv4, managed/unmanaged
    IPv6 (automatic and static), later unowned changes, native DoH metadata
    and repeat restores.
    Reads the exact registry/native state independently after every restore.
    The original VM state is reinstated and checked in finally. This gate
    validates configuration recovery, not network reachability or transport.
.PARAMETER HistoricalBackupPath
    Original Modules/DNS/Private/Backup-DNSSettings.ps1 from published 2.2.5.
    Its exact hash is checked before loading it; the writer emits schema 5.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HistoricalBackupPath,
    [Parameter(Mandatory = $true)][switch]$ConfirmDisposableVm,
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\Results\Windows11-Dns-Compatibility.json')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ConfirmDisposableVm -or $env:NOID_DISPOSABLE_VM -ne 'true' -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
    throw 'Run this gate in an interactive disposable Windows VM with both explicit VM guards'
}
# Resolve operator paths once. .NET file APIs and child processes use the
# process working directory, which Windows PowerShell does not move with Set-Location.
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$historicalHash = (Get-FileHash -LiteralPath $HistoricalBackupPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($historicalHash -cne '804380c0d4a246d24871903814083552778302067b98594d8c9be54bbfe4b76e') {
    throw 'Historical DNS writer does not match the pinned published 2.2.5 source'
}
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$restoreHash = (Get-FileHash -LiteralPath (Join-Path $repo 'Modules/DNS/Public/Restore-DNSSettings.ps1') -Algorithm SHA256).Hash
$nativeHelperHash = (Get-FileHash -LiteralPath (Join-Path $repo 'Modules/DNS/Private/DnsInterfaceDoh.ps1') -Algorithm SHA256).Hash
foreach ($relative in @(
        'Private/ConvertTo-DnsCanonicalAddress.ps1', 'Private/DnsDohRegistryState.ps1', 'Private/DnsInterfaceDoh.ps1',
        'Private/Test-DNSIPv6StackEnabled.ps1', 'Private/Assert-DNSBackupSnapshot.ps1',
        'Public/Restore-DNSSettings.ps1'
    )) {
    . (Join-Path $repo "Modules/DNS/$relative")
}
. $HistoricalBackupPath
$script:ModuleName = 'DNS'
$checks = [Collections.Generic.List[object]]::new()
$evidence = Join-Path ([IO.Path]::GetTempPath()) ('NoIDDnsCompatibility_' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $evidence -ErrorAction Stop
$script:DnsAuditArtifact = $null
$script:DnsAuditLastError = $null
Set-Item -Path Function:Write-Log -Value { param($Level, $Message, $Module) $null = $Level, $Message, $Module }
function Write-ErrorLog {
    param($Message, $Module, $ErrorRecord)
    $null = $Module
    $script:DnsAuditLastError = "$Message`: $($ErrorRecord.Exception.Message)"
}
function Get-PhysicalAdapters {
    param([switch]$RequireVpnInspection)
    $null = $RequireVpnInspection
    return $script:DnsAuditAdapter
}
function Register-Backup {
    param($Type, $Data, $Name)
    if ($Type -cne 'DNS' -or $Name -cne 'DNS_PreState') { throw 'Unexpected historical writer registration' }
    if (Test-Path -LiteralPath $script:DnsAuditArtifact) { throw 'Audit artifact already exists' }
    [IO.File]::WriteAllText($script:DnsAuditArtifact, ($Data | ConvertTo-Json -Depth 25), [Text.UTF8Encoding]::new($false))
    return $script:DnsAuditArtifact
}
function Assert-DnsAuditCondition {
    param([string]$Name, [bool]$Passed)
    $checks.Add([PSCustomObject]@{ Name = $Name; Passed = $Passed })
    if (-not $Passed) { throw "$Name; $script:DnsAuditLastError" }
}
function Get-DnsAuditFamilyState {
    param([string]$Path, [string]$InterfaceGuid, [int]$AddressFamily)
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    try {
        $exists = $key.GetValueNames() -contains 'NameServer'
        $registry = [PSCustomObject]@{
            Exists = $exists
            Type = if ($exists) { $key.GetValueKind('NameServer').ToString() } else { $null }
            Value = if ($exists) {
                $key.GetValue('NameServer', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            } else { $null }
        }
    }
    finally { $key.Close() }
    return [PSCustomObject]@{
        Registry = $registry
        Native = Get-DnsInterfaceDohState -InterfaceGuid $InterfaceGuid -AddressFamily $AddressFamily
    }
}
function ConvertTo-DnsAuditJson {
    param($State)
    return ($State | ConvertTo-Json -Depth 20 -Compress)
}
function Invoke-DnsAuditCleanup {
    # Cleanup only: both families belong to this disposable fixture. Product
    # Restore must never use this adapter-wide reset for a single-family scope.
    $script:DnsAuditBinding | Enable-NetAdapterBinding -Confirm:$false -ErrorAction Stop
    foreach ($family in @(2, 23)) {
        $native = Get-DnsInterfaceDohState -InterfaceGuid $script:DnsAuditGuid -AddressFamily $family
        if (@($native.Properties).Count -gt 0) {
            $null = Clear-DnsInterfaceDohPropertiesForResolverReset -InterfaceGuid $script:DnsAuditGuid `
                -AddressFamily $family -CurrentNameServers @($native.NameServers) -Confirm:$false
        }
    }
    Set-DnsClientServerAddress -InterfaceIndex $script:DnsAuditAdapter.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
    foreach ($family in @(2, 23)) {
        $saved = $script:DnsAuditOriginal[$family].Registry
        $path = $script:DnsAuditPaths[$family]
        if ($saved.Exists) {
            $null = New-ItemProperty -LiteralPath $path -Name NameServer -PropertyType $saved.Type -Value $saved.Value -Force -ErrorAction Stop
        }
        else {
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            try {
                if ($key.GetValueNames() -contains 'NameServer') {
                    Remove-ItemProperty -LiteralPath $path -Name NameServer -ErrorAction Stop
                }
            }
            finally { $key.Close() }
        }
        $actual = Get-DnsAuditFamilyState -Path $path -InterfaceGuid $script:DnsAuditGuid -AddressFamily $family
        if ((ConvertTo-DnsAuditJson $actual) -cne (ConvertTo-DnsAuditJson $script:DnsAuditOriginal[$family])) {
            throw "Fixture cleanup did not restore original DNS family $family"
        }
    }
    if (-not ($script:DnsAuditAdapter | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop).Enabled) {
        throw 'Fixture cleanup did not restore the original IPv6 binding'
    }
}

$failure = $null
$cleanupFailure = $null
$changed = $false
try {
    $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop)
    if ($adapters.Count -ne 1 -or [string]$adapters[0].Status -cne 'Disconnected') {
        throw 'This gate requires exactly one disconnected physical test NIC'
    }
    $script:DnsAuditAdapter = $adapters[0]
    $script:DnsAuditGuid = '{' + ([guid]$adapters[0].InterfaceGuid).ToString('D') + '}'
    $script:DnsAuditBinding = $adapters[0] | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop
    if (-not $script:DnsAuditBinding.Enabled -or -not (Test-DNSIPv6StackEnabled)) {
        throw 'Initial IPv6 binding and transport must be enabled'
    }
    $script:DnsAuditPaths = @{
        2 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$script:DnsAuditGuid"
        23 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$script:DnsAuditGuid"
    }
    $script:DnsAuditOriginal = @{}
    foreach ($family in @(2, 23)) {
        $state = Get-DnsAuditFamilyState -Path $script:DnsAuditPaths[$family] -InterfaceGuid $script:DnsAuditGuid -AddressFamily $family
        if (-not [string]::IsNullOrWhiteSpace([string]$state.Registry.Value) -or
            @($state.Native.NameServers).Count -gt 0 -or @($state.Native.Properties).Count -gt 0) {
            throw 'This gate requires initial automatic DNS without native static metadata'
        }
        $script:DnsAuditOriginal[$family] = $state
    }
    $originalRecords = @(foreach ($family in @(2, 23)) {
            [PSCustomObject]@{ AddressFamily = $family; State = $script:DnsAuditOriginal[$family] }
        })
    [IO.File]::WriteAllText((Join-Path $evidence 'original.json'), (ConvertTo-DnsAuditJson $originalRecords), [Text.UTF8Encoding]::new($false))
    foreach ($staticIPv4 in @($false, $true)) {
        foreach ($ipv6Profile in @('UnmanagedStatic', 'ManagedStatic', 'ManagedAutomatic')) {
            $manageIPv6 = ($ipv6Profile -cne 'UnmanagedStatic')
            $case = "ipv4-static-$staticIPv4-ipv6-$ipv6Profile"
            $changed = $true
            if ($staticIPv4) {
                $v4 = Get-DnsClientServerAddress -InterfaceIndex $adapters[0].InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
                Set-DnsClientServerAddress -InputObject $v4 -ServerAddresses @('192.0.2.10', '192.0.2.11') -ErrorAction Stop
            }
            if ($ipv6Profile -cne 'ManagedAutomatic') {
                $v6Target = ConvertTo-DnsInterfaceDohTargetState -AddressFamily 23 `
                    -NameServers @('2001:db8:53::1', '2001:db8:53::2') `
                    -DohTemplate 'https://ipv6.example.invalid/dns-query' -AllowFallbackToUdp $false
                $null = Set-DnsInterfaceDohState -InterfaceGuid $script:DnsAuditGuid -AddressFamily 23 `
                    -NameServers @($v6Target.NameServers) -Properties @($v6Target.Properties) -Confirm:$false
            }
            if (-not $manageIPv6) { $script:DnsAuditBinding | Disable-NetAdapterBinding -Confirm:$false -ErrorAction Stop }
            $expectedIPv4 = Get-DnsAuditFamilyState -Path $script:DnsAuditPaths[2] -InterfaceGuid $script:DnsAuditGuid -AddressFamily 2
            $expectedIPv6 = Get-DnsAuditFamilyState -Path $script:DnsAuditPaths[23] -InterfaceGuid $script:DnsAuditGuid -AddressFamily 23
            $script:DnsAuditArtifact = Join-Path $evidence "$case.json"
            $backup = Backup-DNSSettings -Confirm:$false
            Assert-DnsAuditCondition "$case original writer creates an artifact" (-not [string]::IsNullOrWhiteSpace([string]$backup))
            $snapshot = Get-Content -LiteralPath $backup -Raw -Encoding UTF8 | ConvertFrom-Json
            Assert-DnsAuditCondition "$case uses historical schema 5" ([int]$snapshot.SchemaVersion -eq 5)
            $savedIPv6 = @($snapshot.Adapters[0].Families | Where-Object AddressFamily -eq 23)[0]
            Assert-DnsAuditCondition "$case seals the intended family scope" (
                [bool]$savedIPv6.Managed -eq $manageIPv6 -and [bool]$savedIPv6.InterfaceDohManaged -eq $manageIPv6)
            $sealedHash = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
            if (-not $manageIPv6) {
                # A later user change is outside this backup's ownership.
                # Restoring its old observed IPv6 data would also be wrong.
                $laterTarget = ConvertTo-DnsInterfaceDohTargetState -AddressFamily 23 `
                    -NameServers @('2001:db8:54::1', '2001:db8:54::2') `
                    -DohTemplate 'https://later.example.invalid/dns-query' -AllowFallbackToUdp $true
                $null = Set-DnsInterfaceDohState -InterfaceGuid $script:DnsAuditGuid -AddressFamily 23 `
                    -NameServers @($laterTarget.NameServers) -Properties @($laterTarget.Properties) -Confirm:$false
                $expectedIPv6 = Get-DnsAuditFamilyState -Path $script:DnsAuditPaths[23] -InterfaceGuid $script:DnsAuditGuid -AddressFamily 23
                Assert-DnsAuditCondition "$case establishes a later unowned change" (
                    [string]$expectedIPv6.Registry.Value -match '2001:db8:54::1')
            }
            else {
                $appliedIPv6 = ConvertTo-DnsInterfaceDohTargetState -AddressFamily 23 `
                    -NameServers @('2001:db8:55::1', '2001:db8:55::2') `
                    -DohTemplate 'https://applied-ipv6.example.invalid/dns-query' -AllowFallbackToUdp $false
                $null = Set-DnsInterfaceDohState -InterfaceGuid $script:DnsAuditGuid -AddressFamily 23 `
                    -NameServers @($appliedIPv6.NameServers) -Properties @($appliedIPv6.Properties) -Confirm:$false
            }
            $applied = ConvertTo-DnsInterfaceDohTargetState -AddressFamily 2 `
                -NameServers @('192.0.2.53', '192.0.2.54') `
                -DohTemplate 'https://ipv4.example.invalid/dns-query' -AllowFallbackToUdp $false
            $null = Set-DnsInterfaceDohState -InterfaceGuid $script:DnsAuditGuid -AddressFamily 2 `
                -NameServers @($applied.NameServers) -Properties @($applied.Properties) -Confirm:$false
            for ($repeat = 1; $repeat -le 2; $repeat++) {
                Assert-DnsAuditCondition "$case restore $repeat succeeds" (Restore-DNSSettings -BackupFilePath $backup -Confirm:$false)
                foreach ($family in @(2, 23)) {
                    $expected = if ($family -eq 2) { $expectedIPv4 } else { $expectedIPv6 }
                    $actual = Get-DnsAuditFamilyState -Path $script:DnsAuditPaths[$family] -InterfaceGuid $script:DnsAuditGuid -AddressFamily $family
                    Assert-DnsAuditCondition "$case restore $repeat exact registry/native family $family" (
                        (ConvertTo-DnsAuditJson $actual) -ceq (ConvertTo-DnsAuditJson $expected))
                }
                Assert-DnsAuditCondition "$case restore $repeat preserves sealed bytes" (
                    (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ceq $sealedHash)
            }
            Invoke-DnsAuditCleanup
            $changed = $false
        }
    }
}
catch { $failure = $_.Exception.Message }
finally {
    if ($changed) {
        try { Invoke-DnsAuditCleanup }
        catch { $cleanupFailure = $_.Exception.Message }
    }
    $parent = Split-Path $OutputPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { $null = New-Item -ItemType Directory -Path $parent -Force }
    $result = [ordered]@{
        Passed = ($null -eq $failure -and $null -eq $cleanupFailure)
        HistoricalWriterVersion = '2.2.5'; HistoricalWriterSha256 = $historicalHash
        RestoreSha256 = $restoreHash; NativeHelperSha256 = $nativeHelperHash
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        Checks = @($checks); Error = $failure; CleanupError = $cleanupFailure
        EvidenceDirectory = $evidence
    }
    [IO.File]::WriteAllText($OutputPath, ($result | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
}
if (-not $result.Passed) { throw "DNS compatibility failed: $failure; cleanup: $cleanupFailure" }
Write-Output "DNS compatibility passed: $($checks.Count) native checks"
