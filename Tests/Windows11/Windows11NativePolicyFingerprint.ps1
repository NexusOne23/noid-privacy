#Requires -Version 5.1

# Independent readers: do not call the product's backup, restore or verifier.
function Get-Windows11LocalGroupPolicyFingerprintState {
    [CmdletBinding()]
    param([string]$RootPath = (Join-Path $env:SystemRoot 'System32\GroupPolicy'))

    # Native firewall GPO operations also update Registry.pol, gpt.ini and
    # their directories. A local WFW export cannot detect this state. Keep
    # file bytes, directory presence and access control in the independent
    # evidence; no version counters or empty policy files are silently ignored.
    try { $root = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] {
        return [pscustomobject]@{ Present=$false; Entries=@() }
    }
    if ($root -isnot [IO.DirectoryInfo]) { throw 'Local Group Policy root is not a filesystem directory' }
    $rootFullName = $root.FullName.TrimEnd('\', '/')
    $pending = [Collections.Generic.Queue[object]]::new()
    $pending.Enqueue($root)
    $entries = [Collections.Generic.List[object]]::new()
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        while ($pending.Count -gt 0) {
            $item = $pending.Dequeue()
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Local Group Policy fingerprint refuses reparse points'
            }
            $relative = $item.FullName.Substring($rootFullName.Length).TrimStart('\', '/')
            $security = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
            $sddl = $security.GetSecurityDescriptorSddlForm(
                [Security.AccessControl.AccessControlSections]'Owner,Group,Access')
            # Record the digest, not account names or security identifiers.
            $aclHash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sddl))).Replace('-', '').ToLowerInvariant()
            $directory = $item -is [IO.DirectoryInfo]
            $entries.Add([pscustomobject]@{
                Path=$relative; Directory=$directory; AclSha256=$aclHash
                Bytes=$(if ($directory) { $null } else { [long]$item.Length })
                Sha256=$(if ($directory) { $null } else {
                    (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                })
            })
            if ($directory) {
                foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop)) {
                    $pending.Enqueue($child)
                }
            }
        }
        return [pscustomobject]@{ Present=$true; Entries=@($entries | Sort-Object Path) }
    }
    finally { $sha.Dispose() }
}

function ConvertFrom-Windows11AuditPolicyCsv {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Content)

    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
    $reader = [IO.StringReader]::new($Content)
    $parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($reader)
    $parser.SetDelimiters(',')
    $parser.HasFieldsEnclosedInQuotes = $true
    $parser.TrimWhiteSpace = $false
    $records = [Collections.Generic.List[object]]::new()
    $identities = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $subcategoryCount = 0
    try {
        $headers = $parser.ReadFields()
        if ($null -eq $headers -or $headers.Count -ne 7) { throw 'Audit CSV must have seven columns' }
        while (-not $parser.EndOfData) {
            $fields = $parser.ReadFields()
            if ($fields.Count -ne 7) { throw 'Audit CSV contains an incomplete or expanded row' }
            # Captions/descriptions are localized. Native field positions and
            # GUID/numeric identities are stable; omit the computer-name column.
            $guid = [Guid]::Empty
            $flags = [uint32]0
            if (-not [uint32]::TryParse($fields[6], [ref]$flags)) { throw 'Audit CSV has nonnumeric flags' }
            if ([Guid]::TryParse($fields[3], [ref]$guid) -and $guid -ne [Guid]::Empty) {
                $identity = $guid.ToString('D')
                $subcategoryCount++
            }
            elseif ([string]::IsNullOrEmpty($fields[3]) -and $fields[2] -cmatch '^Option:[A-Za-z]+$') {
                $identity = $fields[2]
            }
            else { throw 'Audit CSV has an invalid subcategory or option identity' }
            if (-not $identities.Add($fields[1] + '|' + $identity)) { throw 'Audit CSV has a duplicate policy identity' }
            $records.Add([PSCustomObject]@{ Target=$fields[1]; Identity=$identity; Flags=$flags })
        }
        if ($subcategoryCount -eq 0) { throw 'Audit CSV contains no system or per-user subcategories' }
        return @($records | Sort-Object Target, Identity)
    }
    finally { $parser.Dispose(); $reader.Dispose() }
}

function ConvertFrom-Windows11SecurityPolicyInf {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Content)

    $sections = @{}
    $section = ''
    foreach ($line in ($Content -split '\r\n|\n|\r')) {
        $text = $line.Trim()
        if (-not $text -or $text.StartsWith(';')) { continue }
        if ($text -match '^\[([^\]]+)\]$') {
            $section = $Matches[1]
            if ($sections.ContainsKey($section)) { throw 'Security INF has a duplicate section' }
            $sections[$section] = @{}
            continue
        }
        if ($section -notin @('System Access', 'Privilege Rights')) { continue }
        if ($text -notmatch '^([^=]+?)\s*=\s*(.*)$') { throw 'Security INF has a malformed policy entry' }
        $name = $Matches[1].Trim()
        $value = $Matches[2].Trim()
        if (-not $name -or $sections[$section].ContainsKey($name)) { throw 'Security INF has an empty or duplicate policy identity' }
        $sections[$section][$name] = $value
    }
    $records = [Collections.Generic.List[object]]::new()
    foreach ($required in @('System Access', 'Privilege Rights')) {
        if (-not $sections.ContainsKey($required)) { throw "Security INF is missing [$required]" }
        foreach ($name in @($sections[$required].Keys | Sort-Object)) {
            $value = [string]$sections[$required][$name]
            if ($required -eq 'Privilege Rights') {
                # Native export can omit an unassigned right. Principal order
                # does not change the assignment; actual membership does.
                $value = (@($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object) -join ',')
                if (-not $value) { continue }
            }
            $records.Add([PSCustomObject]@{ Section=$required; Name=$name; Value=$value })
        }
    }
    if ($sections['System Access'].Count -eq 0) { throw 'Security INF has no account-policy settings' }
    return @($records)
}

function Get-Windows11NativePolicyFingerprintState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$TemporaryDirectory)

    $prefix = Join-Path $TemporaryDirectory ('native-policy-' + [Guid]::NewGuid().ToString('N'))
    $auditPath = $prefix + '.csv'
    $securityPath = $prefix + '.inf'
    $logPath = $prefix + '.log'
    $stdoutPath = $prefix + '.out'
    $stderrPath = $prefix + '.err'
    try {
        $global:LASTEXITCODE = $null
        & (Join-Path $env:SystemRoot 'System32\auditpol.exe') /backup "/file:$auditPath" > $stdoutPath 2> $stderrPath
        $auditExitCode = $global:LASTEXITCODE
        if ($null -eq $auditExitCode -or $auditExitCode -ne 0 -or -not (Test-Path -LiteralPath $auditPath -PathType Leaf)) {
            throw "Independent audit-policy export failed: exit $auditExitCode"
        }
        $global:LASTEXITCODE = $null
        & (Join-Path $env:SystemRoot 'System32\secedit.exe') /export /cfg $securityPath /log $logPath /quiet > $stdoutPath 2> $stderrPath
        $securityExitCode = $global:LASTEXITCODE
        if ($null -eq $securityExitCode -or $securityExitCode -ne 0 -or -not (Test-Path -LiteralPath $securityPath -PathType Leaf)) {
            throw "Independent security-policy export failed: exit $securityExitCode"
        }
        # auditpol writes local ANSI CSV. Preserve its bytes without guessing a
        # code page; the retained SID/GUID/option/flag fields use ASCII. Localized
        # descriptions and the computer name are excluded by the CSV reader.
        $auditContent = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($auditPath))
        $auditState = @(ConvertFrom-Windows11AuditPolicyCsv -Content $auditContent)
        $securityState = @(ConvertFrom-Windows11SecurityPolicyInf -Content (Get-Content -LiteralPath $securityPath -Raw -ErrorAction Stop))
        return [PSCustomObject]@{ AuditPolicies=$auditState; SecurityPolicies=$securityState }
    }
    finally {
        Remove-Item -LiteralPath $auditPath, $securityPath, $logPath, $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
    }
}
