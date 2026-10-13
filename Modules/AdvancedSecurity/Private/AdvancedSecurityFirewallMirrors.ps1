#Requires -Version 5.1

function Get-AdvancedSecurityFirewallMirrorContract {
    [CmdletBinding()]
    param()

    # This is a persistent recovery contract. Keep existing names readable
    # when future releases add, rename or retire hardening definitions.
    [pscustomobject]@{
        Group = 'NoIDPrivacy.ManagedFirewallMirror.v1'
        Suffix = '-LocalBackup'
        Names = @(
            'NoID-Block-LLMNR-UDP-5355', 'NoID-Block-NetBIOS-UDP-137',
            'NoID-Block-NetBIOS-UDP-138', 'NoID-Block-NetBIOS-TCP-139',
            'NoID-Block-SSDP-UDP-1900', 'NoID-Block-UPnP-TCP-2869',
            'NoID-Block-AdminShares-TCP-445', 'NoID-Block-Finger-TCP-79',
            'NoID-Block-WSD-UDP-3702', 'NoID-Block-WSD-TCP-5357',
            'NoID-Block-WSD-TCP-5358', 'NoID-Block-mDNS-UDP-5353',
            'NoID-Block-Miracast-TCP-7236', 'NoID-Block-Miracast-TCP-7250',
            'NoID-Block-Miracast-UDP-7236', 'NoID-Block-Miracast-UDP-7250'
        )
    }
}

function Get-AdvancedSecurityFirewallRuleConfiguration {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Rule)

    # Compare every provider property and every associated filter. Only the
    # identifier and derived status/source fields differ between native copies.
    # Unknown future configuration properties therefore remain in the comparison.
    $sets = @(
        @{ Name='Rule'; Items=@($Rule) },
        @{ Name='Port'; Items=@($Rule | Get-NetFirewallPortFilter -ErrorAction Stop) },
        @{ Name='Address'; Items=@($Rule | Get-NetFirewallAddressFilter -ErrorAction Stop) },
        @{ Name='Application'; Items=@($Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop) },
        @{ Name='Service'; Items=@($Rule | Get-NetFirewallServiceFilter -ErrorAction Stop) },
        @{ Name='Interface'; Items=@($Rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop) },
        @{ Name='InterfaceType'; Items=@($Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop) },
        @{ Name='Security'; Items=@($Rule | Get-NetFirewallSecurityFilter -ErrorAction Stop) }
    )
    $configuration = [ordered]@{}
    foreach ($set in $sets) {
        if ($set.Items.Count -ne 1 -or $null -eq $set.Items[0].CimInstanceProperties) {
            throw "Firewall $($set.Name) configuration is missing or ambiguous"
        }
        $values = [ordered]@{}
        foreach ($property in @($set.Items[0].CimInstanceProperties | Sort-Object Name)) {
            # NetSecurity also encodes the rule identifier in CreationClassName
            # on the rule and all seven filters. Microsoft reserves this field
            # for its WMI provider; a native NewName copy changes it as expected.
            if ($property.Name -cin @('InstanceID', 'Name', 'CreationClassName', 'EnforcementStatus',
                    'PolicyStoreSource', 'PolicyStoreSourceType', 'Status', 'StatusCode', 'PrimaryStatus')) {
                continue
            }
            $values[$property.Name] = $property.Value
        }
        $configuration[$set.Name] = $values
    }
    return ConvertTo-Json -InputObject $configuration -Depth 20 -Compress
}

function Get-AdvancedSecurityFirewallMirrorState {
    [CmdletBinding()]
    param(
        [switch]$RequireSynchronized,
        [string[]]$NamesToVerify
    )

    $contract = Get-AdvancedSecurityFirewallMirrorContract
    $selected = $PSBoundParameters.ContainsKey('NamesToVerify')
    if ($selected -and -not $RequireSynchronized) { throw 'Selected mirror verification requires synchronization checks' }
    if ($selected -and (@($NamesToVerify).Count -eq 0 -or
            @($NamesToVerify | Where-Object { $_ -cnotin $contract.Names }).Count -gt 0 -or
            @($NamesToVerify | Sort-Object -Unique).Count -ne $NamesToVerify.Count)) {
        throw 'Unknown, duplicate or empty selected firewall mirror verification scope'
    }
    if (-not (Get-Command Get-AdvancedSecurityLocalFirewallGpoState -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'AdvancedSecurityFirewallGpoStore.ps1')
    }
    $state = Get-AdvancedSecurityLocalFirewallGpoState
    if ($state.Sources.Count -gt 0) {
        # Require Windows to recognize every native source. Comparing complete
        # source/GPO strings below retains all fields, including future fields;
        # registry strings that Windows cannot parse must not become a backup.
        $sourceNames = @($state.Sources.Keys | ForEach-Object { $_ + $contract.Suffix })
        $native = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $sourceNames -ErrorAction Stop)
        if ($native.Count -ne $sourceNames.Count) { throw 'Native NoID firewall recovery-copy inventory is incomplete or ambiguous' }
        foreach ($name in $sourceNames) {
            $sourceMatches = @($native | Where-Object { [string]$_.Name -ceq $name -and [string]$_.Group -ceq $contract.Group })
            if ($sourceMatches.Count -ne 1) { throw 'Native NoID firewall recovery-copy ownership is missing or ambiguous' }
        }
        $fresh = Get-AdvancedSecurityLocalFirewallGpoState
        if ($state.Sources.Count -ne $fresh.Sources.Count -or @($state.Sources.Keys | Where-Object {
                    -not $fresh.Sources.ContainsKey($_) -or $state.Sources[$_] -cne $fresh.Sources[$_]
                }).Count -gt 0) { throw 'NoID firewall recovery sources changed during native verification' }
        $state = $fresh
    }
    if ($RequireSynchronized) {
        $checkNames = if ($selected) { @($NamesToVerify) }
            else { @(@($state.Sources.Keys) + @($state.Mirrors.Keys) | Sort-Object -Unique) }
        foreach ($name in $checkNames) {
            if (-not $state.Sources.ContainsKey($name) -and -not $state.Mirrors.ContainsKey($name)) { continue }
            if (-not $state.Sources.ContainsKey($name) -or -not $state.Mirrors.ContainsKey($name) -or
                $state.Sources[$name] -cne $state.Mirrors[$name]) {
                throw "NoID firewall mirror prestate is incomplete or differs for $name; restore the last sealed AdvancedSecurity backup before a new Apply"
            }
        }
    }
    return $state
}

function Get-AdvancedSecurityFirewallMirrorRestorePlan {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PolicyFilePath)

    $contract = Get-AdvancedSecurityFirewallMirrorContract
    $policy = Get-AdvancedSecurityFirewallPolicyState -PolicyFilePath $PolicyFilePath
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @($policy.Entries)) {
        if ([string]$entry.Kind -cne 'Value' -or [string]$entry.Path -cne 'FirewallRules' -or
            [string]$entry.Type -cne 'String' -or
            @(([string]$entry.Data -split '\|') | Where-Object { $_ -ceq ('EmbedCtxt=' + $contract.Group) }).Count -eq 0) {
            continue
        }
        $name = [string]$entry.Name
        if (-not $name.EndsWith($contract.Suffix, [StringComparison]::Ordinal)) {
            throw 'The firewall backup contains an invalid NoID mirror source name'
        }
        $canonicalName = $name.Substring(0, $name.Length - $contract.Suffix.Length)
        if ($canonicalName -cnotin $contract.Names -or $names.Contains($canonicalName)) {
            throw 'The firewall backup contains an unknown or duplicate NoID mirror source'
        }
        $names.Add($canonicalName)
    }
    $state = Get-AdvancedSecurityFirewallMirrorState
    foreach ($name in $names) {
        if ($state.UnownedGpo.ContainsKey($name)) {
            throw "Firewall restore would overwrite an unowned local-GPO rule: $name"
        }
    }
    # A genuine 2.2.5 WFW has no mirror marker. Its empty desired set removes
    # subsequently created NoID GPO mirrors without altering the old artifact.
    return [pscustomobject]@{ Names=@($names | Sort-Object) }
}

function Assert-AdvancedSecurityFirewallMirrorApplicability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Names,
        [switch]$SelectedRulesOnly,
        [switch]$PassThru
    )

    $contract = Get-AdvancedSecurityFirewallMirrorContract
    $checks = @{ RequireSynchronized=$true }
    if ($SelectedRulesOnly) { $checks.NamesToVerify = $Names }
    $state = Get-AdvancedSecurityFirewallMirrorState @checks
    foreach ($name in $Names) {
        if ($name -cnotin $contract.Names) { throw "Unknown firewall mirror contract: $name" }
        if ($state.UnownedGpo.ContainsKey($name)) {
            throw "An unowned local-GPO rule already uses the selected NoID name: $name"
        }
        $localCopyName = $name + $contract.Suffix
        if ($state.UnownedLocal.ContainsKey($localCopyName)) {
            throw "An unowned local rule already uses the NoID recovery-copy name: $localCopyName"
        }
    }
    if ($PassThru) { return $state }
}

function Invoke-AdvancedSecurityFirewallPolicyRefresh {
    [CmdletBinding()]
    param()

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = Join-Path $env:SystemRoot 'System32\gpupdate.exe'
    $startInfo.Arguments = '/target:computer /force /wait:-1'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'Cannot start computer-policy refresh' }
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        # Do not return while Registry CSE processing can still change the
        # policy tree beneath the following exact registry restore.
        $process.WaitForExit()
        $null = $stdout.Result, $stderr.Result
        if ($process.ExitCode -ne 0) {
            throw "Computer-policy refresh failed with exit code $($process.ExitCode)"
        }
    }
    finally { $process.Dispose() }
}

function Sync-AdvancedSecurityFirewallMirrors {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ExpectedNames,
        [string[]]$NamesToSynchronize,
        [bool]$SealedEditorRegistration
    )

    if (-not $PSCmdlet.ShouldProcess('NoID firewall GPO mirrors', 'Reconcile from the restored local firewall policy')) {
        return $false
    }
    $contract = Get-AdvancedSecurityFirewallMirrorContract
    # Restore reconciles the entire WFW inventory. Apply changes one selected
    # pair; do not repeatedly inspect or rewrite the other already-applied
    # pairs. Backup and final module verification still check every pair.
    $selected = $PSBoundParameters.ContainsKey('NamesToSynchronize')
    if ($selected -and (@($NamesToSynchronize).Count -eq 0 -or
            @($NamesToSynchronize | Where-Object { $_ -cnotin $contract.Names }).Count -gt 0 -or
            @($NamesToSynchronize | Sort-Object -Unique).Count -ne $NamesToSynchronize.Count)) {
        throw 'Unknown, duplicate or empty selected firewall synchronization scope'
    }
    $restoreRegistration = $PSBoundParameters.ContainsKey('SealedEditorRegistration')
    if ($selected -and $restoreRegistration) {
        throw 'The sealed firewall editor registration belongs to a complete restore, not a selected Apply'
    }
    $state = Get-AdvancedSecurityFirewallMirrorState
    $actualNames = @($state.Sources.Keys | Sort-Object)
    if ((ConvertTo-Json -InputObject $actualNames -Compress) -cne
        (ConvertTo-Json -InputObject @($ExpectedNames | Sort-Object) -Compress)) {
        throw 'Restored NoID firewall sources differ from the prevalidated WFW plan'
    }
    foreach ($name in $actualNames) {
        if ($state.UnownedGpo.ContainsKey($name)) {
            throw "Firewall synchronization would overwrite an unowned local-GPO rule: $name"
        }
    }
    # Computer-name NetSecurity stores can depend on ADMIN$, which Maximum
    # intentionally suppresses after restart. Reconcile through the documented
    # local GPO API, preserving complete Windows-generated source strings.
    if (-not (Get-Command Sync-AdvancedSecurityLocalFirewallGpo -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'AdvancedSecurityFirewallGpoStore.ps1')
    }
    $synchronize = @{ ExpectedSources=$state.Sources; Confirm=$false }
    if ($selected) { $synchronize.NamesToSynchronize = $NamesToSynchronize }
    $changed = Sync-AdvancedSecurityLocalFirewallGpo @synchronize
    if ($restoreRegistration) {
        # Apply registers the firewall editor for the Registry CSE. A Save that
        # leaves other policy (for example Device Guard policy restored later
        # by SecurityBaseline) keeps it, so return it to its sealed prestate.
        $registration = Set-AdvancedSecurityFirewallGpoEditorRegistration -Registered $SealedEditorRegistration -Confirm:$false
        if ($registration -ceq 'Changed') { $changed = $true }
        elseif ($registration -ceq 'Retained') {
            Write-Log -Level INFO -Message 'Firewall GPO editor registration retained because remaining local policy still depends on it' -Module 'AdvancedSecurity'
        }
        elseif ($registration -cne 'Unchanged') { throw "Unexpected firewall editor registration result: $registration" }
    }
    $localPolicyFile = Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Registry.pol'
    if ($changed -or (Test-Path -LiteralPath $localPolicyFile -PathType Leaf -ErrorAction Stop)) {
        # An interrupted previous removal may leave an empty policy file even
        # though both inventories are already empty. Complete Registry CSE
        # processing before the caller restores any exact registry values.
        Invoke-AdvancedSecurityFirewallPolicyRefresh
    }
    $checks = @{ RequireSynchronized=$true }
    if ($selected) { $checks.NamesToVerify = $NamesToSynchronize }
    $verified = Get-AdvancedSecurityFirewallMirrorState @checks
    if ((ConvertTo-Json -InputObject @($verified.Sources.Keys | Sort-Object) -Compress) -cne
        (ConvertTo-Json -InputObject $actualNames -Compress)) {
        throw 'NoID firewall source inventory changed during synchronization'
    }
    return $true
}
