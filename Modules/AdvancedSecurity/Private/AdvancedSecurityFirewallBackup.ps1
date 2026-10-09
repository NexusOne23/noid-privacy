#Requires -Version 5.1

function Test-AdvancedSecurityWindowsAppFirewallEntry {
    <#
    .SYNOPSIS
        Recognize Windows-generated package capability rules, not custom rules.
    .DESCRIPTION
        PFN and LUOwn must bind the generated rule name to the same package and
        user. A package SID or a WindowsApps executable path alone is insufficient.
        Unknown paths, fields and rule forms fail closed. This classification is
        used only to refresh an unsealed backup, never to relax exact Restore.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Entry)

    if ([string]$Entry.Kind -cne 'Value' -or [string]$Entry.Path -cne 'FirewallRules' -or
        [string]$Entry.Type -cne 'String' -or
        ([string]$Entry.Data).Contains([string][char]0)) { return $false }

    $nameMatch = [regex]::Match([string]$Entry.Name,
        '^(?<family>[A-Za-z0-9][A-Za-z0-9.-]{0,127}_[A-Za-z0-9]{13})(?<user>S-1-(?:5-21-(?:[0-9]+-){3}[0-9]+|12-1-(?:[0-9]+-){3}[0-9]+))-(?<rule>Out-Allow-AllCapabilities|In-Allow-ServerCapability)$')
    if (-not $nameMatch.Success) { return $false }

    $parts = ([string]$Entry.Data).Split('|')
    if ($parts.Count -lt 3 -or $parts[0] -cnotmatch '^v2\.[0-9]+$' -or
        $parts[-1] -cne '') { return $false }
    $fields = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    $profiles = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($part in $parts[1..($parts.Count - 2)]) {
        $split = $part.IndexOf('=')
        if ($split -le 0) { return $false }
        $key = $part.Substring(0, $split)
        $value = $part.Substring($split + 1)
        if ($key -ceq 'Profile') {
            if ($value -cnotin @('Domain', 'Private', 'Public') -or
                -not $profiles.Add($value)) { return $false }
        }
        else {
            if ($key -cnotin @('Action', 'Active', 'Dir', 'Name', 'Desc', 'PFN', 'LUOwn', 'EmbedCtxt', 'Platform', 'Platform2') -or
                [string]::IsNullOrWhiteSpace($value) -or $fields.ContainsKey($key)) { return $false }
            $fields.Add($key, $value)
        }
    }
    foreach ($required in @('Action', 'Active', 'Dir', 'PFN', 'LUOwn')) {
        if (-not $fields.ContainsKey($required)) { return $false }
    }
    $outbound = $nameMatch.Groups['rule'].Value -ceq 'Out-Allow-AllCapabilities'
    $direction = if ($outbound) { 'Out' } else { 'In' }
    $profileCount = if ($outbound) { 3 } else { 2 }
    return $fields['PFN'] -ceq $nameMatch.Groups['family'].Value -and
        $fields['LUOwn'] -ceq $nameMatch.Groups['user'].Value -and
        $fields['Action'] -ceq 'Allow' -and $fields['Active'] -ceq 'TRUE' -and
        $fields['Dir'] -ceq $direction -and $profiles.Count -eq $profileCount -and
        $profiles.Contains('Domain') -and $profiles.Contains('Private') -and
        ($outbound -or -not $profiles.Contains('Public'))
}

function Get-AdvancedSecurityFirewallPolicyDifference {
    <# Compare the union of both inventories; never stop at the first app rule. #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]$Reference,
        [Parameter(Mandatory = $true)]$Candidate
    )

    $maps = @()
    foreach ($state in @($Reference, $Candidate)) {
        $entries = @($state.Entries)
        if ([int]$state.SchemaVersion -ne 1 -or [int]$state.EntryCount -ne $entries.Count -or
            $entries.Count -eq 0) { throw 'Invalid firewall semantic snapshot schema/count' }
        $map = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
        $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $entries) {
            foreach ($property in @('Kind', 'Path', 'Name', 'Type', 'Data')) {
                if (-not $entry.PSObject.Properties[$property] -or $entry.$property -isnot [string]) {
                    throw 'Invalid firewall semantic snapshot entry'
                }
                if ($property -in @('Kind', 'Path', 'Name') -and $entry.$property.Contains([string][char]0)) {
                    throw 'Invalid firewall semantic snapshot identity'
                }
            }
            if ($entry.Kind -cnotin @('Key', 'Value')) { throw 'Invalid firewall semantic entry kind' }
            $identity = $entry.Kind + [char]0 + $entry.Path + [char]0 + $entry.Name
            if (-not $identities.Add($identity)) { throw 'Duplicate firewall semantic snapshot identity' }
            $map.Add($identity, $entry)
        }
        $maps += ,$map
    }

    $keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($map in $maps) { foreach ($key in $map.Keys) { $null = $keys.Add($key) } }
    $changed = 0
    $other = 0
    foreach ($key in $keys) {
        $before = $null; $after = $null
        $hasBefore = $maps[0].TryGetValue($key, [ref]$before)
        $hasAfter = $maps[1].TryGetValue($key, [ref]$after)
        if ($hasBefore -and $hasAfter -and $before.Type -ceq $after.Type -and
            $before.Data -ceq $after.Data) { continue }
        $changed++
        if (($hasBefore -and -not (Test-AdvancedSecurityWindowsAppFirewallEntry -Entry $before)) -or
            ($hasAfter -and -not (Test-AdvancedSecurityWindowsAppFirewallEntry -Entry $after))) { $other++ }
    }
    return [PSCustomObject]@{
        Equivalent = $changed -eq 0
        AppRulesOnly = $changed -gt 0 -and $other -eq 0
        ChangedEntries = $changed
        OtherChanges = $other
    }
}

function Assert-AdvancedSecurityFirewallBackupWritable {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PolicyFilePath)

    # This helper has no sealed-backup mode. Check both authorities before any
    # export/overwrite, including calls made during the initial backup capture.
    if ([string]$global:CurrentModule -cne 'AdvancedSecurity' -or
        -not $global:SessionManifest -or
        @($global:SessionManifest.modules | Where-Object { $_.name -eq 'AdvancedSecurity' }).Count -ne 0) {
        throw 'Firewall refresh requires an active, unsealed AdvancedSecurity backup'
    }
    $expectedPath = Join-Path (Join-Path $global:BackupBasePath 'AdvancedSecurity') 'AdvancedSecurity_FirewallPolicy.wfw'
    if (-not [IO.Path]::GetFullPath($PolicyFilePath).Equals(
            [IO.Path]::GetFullPath($expectedPath), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Firewall refresh target is outside the active module backup'
    }
    foreach ($path in @($global:BackupBasePath, (Split-Path $expectedPath -Parent), $expectedPath)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ([bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Firewall refresh target contains a reparse point'
        }
    }
    $manifestPath = Join-Path $global:BackupBasePath 'manifest.json'
    if (Test-Path -LiteralPath $manifestPath) {
        $manifest = Get-SessionManifest -SessionPath $global:BackupBasePath
        if (@($manifest.modules | Where-Object { $_.name -eq 'AdvancedSecurity' }).Count -ne 0) {
            throw 'Firewall refresh cannot overwrite an artifact sealed on disk'
        }
    }
}

function Sync-AdvancedSecurityFirewallBackup {
    <#
    .SYNOPSIS
        Reconcile live policy and refresh only an active, unsealed firewall backup.
    .DESCRIPTION
        Each replacement is the exact export whose complete difference was
        classified. Registration stores only the path; Complete-ModuleBackup
        computes its SHA-256 after reconciliation, with the existing schema.
        Other module prestates are checked again before every retry export.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$PolicyFilePath,
        [scriptblock]$ValidateOtherPrestate = {},
        [string]$Context = 'Firewall policy changed after AdvancedSecurity backup'
    )

    Assert-AdvancedSecurityFirewallBackupWritable -PolicyFilePath $PolicyFilePath

    $reference = Get-AdvancedSecurityFirewallPolicyState -PolicyFilePath $PolicyFilePath
    $candidatePath = Join-Path $env:TEMP "NoID_FirewallPreApply_$([Guid]::NewGuid().ToString('N')).wfw"
    try {
        for ($attempt = 0; $attempt -le 3; $attempt++) {
            $null = & $ValidateOtherPrestate
            $export = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\netsh.exe') `
                -ArgumentList @('advfirewall', 'export', "`"$candidatePath`"") `
                -Wait -NoNewWindow -PassThru -RedirectStandardOutput 'NUL' -ErrorAction Stop
            if ($export.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
                throw "Firewall pre-Apply export failed with exit code $($export.ExitCode)"
            }
            $candidate = Get-AdvancedSecurityFirewallPolicyState -PolicyFilePath $candidatePath
            $difference = Get-AdvancedSecurityFirewallPolicyDifference -Reference $reference -Candidate $candidate
            if ($difference.Equivalent) { return $true }
            if (-not $difference.AppRulesOnly) {
                throw "$Context contains $($difference.OtherChanges) non-app changes; refusing backup refresh"
            }
            if ($attempt -eq 3) {
                throw "$Context did not stabilize after 3 Windows app-rule backup refreshes"
            }
            Write-Log -Level WARNING -Message "Windows updated $($difference.ChangedEntries) app firewall rules; refreshing the unsealed firewall backup (attempt $($attempt + 1)/3)" -Module 'AdvancedSecurity'
            Write-NoIDDetail '  Windows updated app firewall rules; taking the firewall backup again...' -ForegroundColor Yellow
            Assert-AdvancedSecurityFirewallBackupWritable -PolicyFilePath $PolicyFilePath
            Copy-Item -LiteralPath $candidatePath -Destination $PolicyFilePath -Force -ErrorAction Stop
            $reference = $candidate
            # netsh refuses an existing export destination, including its own
            # previous candidate. The classified bytes are now in the backup.
            Remove-Item -LiteralPath $candidatePath -Force -ErrorAction Stop
            Start-Sleep -Milliseconds 500
        }
    }
    finally {
        Remove-Item -LiteralPath $candidatePath -Force -ErrorAction SilentlyContinue
    }
}
