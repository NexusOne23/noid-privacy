#Requires -Version 5.1

# Independent, read-only evidence for proven native Save bookkeeping. Raw
# filesystem fingerprints remain available and unequal. Nonempty Registry.pol
# files stay byte-exact; their INI allows only a bound computer revision advance.
function Get-Windows11EmptyComputerGptState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    $unsupported = [pscustomobject]@{ Supported=$false; VersionPresent=$false; Revision=0; Bytes=0; Sha256='' }
    if (@($Bytes | Where-Object { $_ -gt 127 -or $_ -eq 0 }).Count) { return $unsupported }
    $lines = @([Text.Encoding]::ASCII.GetString($Bytes) -split '\r\n|\n')
    if ($lines.Count -and $lines[-1] -ceq '') { $lines = @($lines | Select-Object -SkipLast 1) }
    if (-not $lines.Count -or $lines[0] -cne '[General]') { return $unsupported }
    $seen = @{}
    $revision = [uint32]0
    foreach ($line in @($lines | Select-Object -Skip 1)) {
        if ($line -cmatch '^Version=([0-9]+)$') {
            if ($seen.ContainsKey('Version') -or -not [uint32]::TryParse($Matches[1], [ref]$revision) -or
                $revision -gt 65535) { return $unsupported }
            $seen.Version = $true
        }
        elseif ($line -cmatch '^gPCMachineExtensionNames= *$') {
            if ($seen.ContainsKey('Extensions')) { return $unsupported }
            $seen.Extensions = $true
        }
        else { return $unsupported }
    }
    # A user revision, unknown INI field, comment, section or nonempty CSE list
    # is outside this empty-computer-policy contract, even if plausible.
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $rawHash = [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    return [pscustomobject]@{ Supported=$true; VersionPresent=$seen.ContainsKey('Version'); Revision=$revision; Bytes=$Bytes.Length; Sha256=$rawHash }
}

function Get-Windows11ComputerGptRevisionState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    $unsupported = [pscustomobject]@{ Supported=$false; Revision=0; Bytes=0; Sha256=''; StableSha256='' }
    if (@($Bytes | Where-Object { $_ -gt 127 -or $_ -eq 0 }).Count) { return $unsupported }
    $text = [Text.Encoding]::ASCII.GetString($Bytes)
    $guid = '\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}'
    # This is the observed native three-line INI form. Unknown fields, user
    # extensions, mixed newlines, duplicate revisions and other layouts remain
    # unclassified. Preserve every byte except the revision's decimal digits.
    $pattern = '\A\[General\](?<nl>\r\n|\n)gPCMachineExtensionNames=(?:\[' +
        $guid + '(?:' + $guid + ')+\])+\k<nl>Version=(?<revision>0|[1-9][0-9]*)\k<nl>\z'
    $match = [regex]::Match($text, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $revision = [uint32]0
    if (-not $match.Success -or -not [uint32]::TryParse($match.Groups['revision'].Value, [ref]$revision)) {
        return $unsupported
    }
    $digits = $match.Groups['revision']
    $stable = $text.Substring(0, $digits.Index) + '<revision>' + $text.Substring($digits.Index + $digits.Length)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $rawHash = [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()
        $stableHash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($stable))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
    return [pscustomobject]@{ Supported=$true; Revision=$revision; Bytes=$Bytes.Length; Sha256=$rawHash; StableSha256=$stableHash }
}

function Compare-Windows11NonemptyPolicyRevisionEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Before, [Parameter(Mandatory = $true)]$After)

    $rejected = [pscustomobject]@{ Accepted=$false; Disposition='Unclassified nonempty local Group Policy difference' }
    $states = @($Before, $After)
    $maps = @(@{}, @{})
    for ($i = 0; $i -lt 2; $i++) {
        $state = $states[$i]
        if (-not $state.RawState.Present -or -not $state.PSObject.Properties['ComputerGptRevision'] -or
            -not $state.ComputerGptRevision.Supported) { return $rejected }
        foreach ($entry in @($state.RawState.Entries)) {
            $path = ([string]$entry.Path -replace '[\\/]+', '\').ToLowerInvariant()
            if ($maps[$i].ContainsKey($path)) { return $rejected }
            $maps[$i][$path] = $entry
        }
        if (-not $maps[$i].ContainsKey('') -or -not $maps[$i][''].Directory -or
            -not $maps[$i].ContainsKey('gpt.ini') -or $maps[$i]['gpt.ini'].Directory -or
            -not $maps[$i].ContainsKey('machine') -or -not $maps[$i]['machine'].Directory -or
            -not $maps[$i].ContainsKey('machine\registry.pol')) { return $rejected }
        $pol = $maps[$i]['machine\registry.pol']
        $gpt = $maps[$i]['gpt.ini']
        $revision = $state.ComputerGptRevision
        if ($pol.Directory -or $pol.Bytes -le 8 -or $pol.Sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $revision.Bytes -ne $gpt.Bytes -or $revision.Sha256 -cne $gpt.Sha256 -or
            $revision.StableSha256 -cnotmatch '^[0-9a-f]{64}$') { return $rejected }
    }
    $leftRevision = $Before.ComputerGptRevision
    $rightRevision = $After.ComputerGptRevision
    # Native Save increments the machine half of the version. Never authorize
    # a user revision change, rollback or wraparound from this observed case.
    # https://learn.microsoft.com/windows/win32/api/gpedit/nf-gpedit-igrouppolicyobject-save
    if ($leftRevision.StableSha256 -cne $rightRevision.StableSha256 -or
        ([uint32]$leftRevision.Revision -shr 16) -ne ([uint32]$rightRevision.Revision -shr 16) -or
        ([uint32]$rightRevision.Revision -band 65535) -le ([uint32]$leftRevision.Revision -band 65535)) { return $rejected }
    foreach ($path in @(@($maps[0].Keys) + @($maps[1].Keys) | Sort-Object -Unique)) {
        $left = $maps[0][$path]; $right = $maps[1][$path]
        if ($null -eq $left -or $null -eq $right) { return $rejected }
        $excluded = @('Path')
        if ($path -ceq 'gpt.ini') { $excluded += @('Bytes', 'Sha256') }
        if (($left | Select-Object * -ExcludeProperty $excluded | ConvertTo-Json -Depth 20 -Compress) -cne
            ($right | Select-Object * -ExcludeProperty $excluded | ConvertTo-Json -Depth 20 -Compress)) { return $rejected }
    }
    return [pscustomobject]@{
        Accepted=$true
        Disposition='Native computer revision advance only; unchanged nonempty policy bytes, INI fields, file layout and access; raw differences retained'
    }
}

function Test-Windows11CurrentPrimaryGroup {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Group)

    # Windows assigns a new object's primary group from its creator's token,
    # not necessarily from its parent directory. Query that exact field; group
    # membership alone is insufficient. No identity is returned in evidence.
    # https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-token_primary_group
    if (-not ('NoIDPrivacyAudit.CreationGroup' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace NoIDPrivacyAudit {
    public static class CreationGroup {
        [DllImport("advapi32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, int size, out int needed);
        public static bool Matches(IntPtr token, SecurityIdentifier group) {
            const int TokenPrimaryGroup = 5;
            int size;
            bool success = GetTokenInformation(token, TokenPrimaryGroup, IntPtr.Zero, 0, out size);
            int error = Marshal.GetLastWin32Error();
            if (success || error != 122) throw new Win32Exception(error, "Cannot size token primary-group information");
            if (size <= IntPtr.Size || size > 65536) throw new InvalidOperationException("Invalid token primary-group buffer size");
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try {
                int returned;
                if (!GetTokenInformation(token, TokenPrimaryGroup, buffer, size, out returned))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (returned <= IntPtr.Size || returned > size) throw new InvalidOperationException("Incomplete token primary-group information");
                return group.Equals(new SecurityIdentifier(Marshal.ReadIntPtr(buffer)));
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }
}
'@
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { return [NoIDPrivacyAudit.CreationGroup]::Matches($identity.Token, $Group) }
    finally { $identity.Dispose() }
}

function Test-Windows11EmptyPolicyFileAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$FileSecurity,
        [Parameter(Mandatory = $true)]$ParentSecurity,
        [switch]$AllowAdministratorOwner
    )

    $sidType = [Security.Principal.SecurityIdentifier]
    if ($FileSecurity.AreAccessRulesProtected -or -not $FileSecurity.AreAccessRulesCanonical) { return $false }
    $parentRules = @($ParentSecurity.GetAccessRules($true, $true, $sidType))
    if (@($parentRules | Where-Object AccessControlType -ne Allow).Count) { return $false }
    $effectiveParentRules = @($parentRules | Where-Object { ([int]$_.PropagationFlags -band 2) -eq 0 })
    $owner = $FileSecurity.GetOwner($sidType)
    if (-not $owner.Equals($ParentSecurity.GetOwner($sidType))) {
        # Native Save on a fresh client creates gpt.ini with Administrators
        # as owner. Classify only that observed owner, already granted full
        # control of the unchanged parent. Do not extend the existing pol case.
        if (-not $AllowAdministratorOwner -or -not $owner.Equals($sidType::new('S-1-5-32-544')) -or
            @($effectiveParentRules | Where-Object {
                $_.IdentityReference.Equals($owner) -and
                ([int64]$_.FileSystemRights -band 2032127) -eq 2032127
            }).Count -eq 0) { return $false }
    }
    $fileGroup = $FileSecurity.GetGroup($sidType)
    if (-not $fileGroup.Equals($ParentSecurity.GetGroup($sidType)) -and
        -not (Test-Windows11CurrentPrimaryGroup -Group $fileGroup)) { return $false }
    $fileRules = @($FileSecurity.GetAccessRules($true, $true, $sidType))
    if (-not $fileRules.Count -or $fileRules.Count -ne $effectiveParentRules.Count) { return $false }
    $matched = [Collections.Generic.HashSet[int]]::new()
    foreach ($rule in $fileRules) {
        $rights = [int64]$rule.FileSystemRights
        if (-not $rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or
            [int]$rule.InheritanceFlags -ne 0 -or [int]$rule.PropagationFlags -ne 0 -or $rights -le 0) { return $false }
        $index = -1
        for ($i = 0; $i -lt $effectiveParentRules.Count; $i++) {
            $parentRule = $effectiveParentRules[$i]
            if (-not $matched.Contains($i) -and $rule.IdentityReference.Equals($parentRule.IdentityReference) -and
                $rights -eq [int64]$parentRule.FileSystemRights) { $index = $i; break }
        }
        if ($index -lt 0) { return $false }
        $null = $matched.Add($index)
        # Any write/delete/ownership grant must already include the right to
        # create a file in the unchanged parent. Read-only grants add no writer.
        if (($rights -band 852310) -ne 0 -and ($rights -band 2) -eq 0) { return $false }
    }
    return $true
}

function Test-Windows11NewPolicyDirectoryAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$DirectorySecurity,
        [Parameter(Mandatory = $true)]$ParentSecurity
    )

    # A folder that native Save creates in a previously empty root must carry
    # exactly the DACL that Windows inheritance derives from the unchanged
    # parent. Creator identities and any explicit grant stay unclassified.
    # https://learn.microsoft.com/windows/win32/secauthz/ace-inheritance-rules
    $sidType = [Security.Principal.SecurityIdentifier]
    if ($DirectorySecurity.AreAccessRulesProtected -or -not $DirectorySecurity.AreAccessRulesCanonical) { return $false }
    $parentRules = @($ParentSecurity.GetAccessRules($true, $true, $sidType))
    if (@($parentRules | Where-Object AccessControlType -ne Allow).Count) { return $false }
    $owner = $DirectorySecurity.GetOwner($sidType)
    if (-not $owner.Equals($ParentSecurity.GetOwner($sidType))) {
        if (-not $owner.Equals($sidType::new('S-1-5-32-544')) -or
            @($parentRules | Where-Object {
                $_.IdentityReference.Equals($owner) -and ([int]$_.PropagationFlags -band 2) -eq 0 -and
                ([int64]$_.FileSystemRights -band 2032127) -eq 2032127
            }).Count -eq 0) { return $false }
    }
    $group = $DirectorySecurity.GetGroup($sidType)
    if (-not $group.Equals($ParentSecurity.GetGroup($sidType)) -and
        -not (Test-Windows11CurrentPrimaryGroup -Group $group)) { return $false }

    $genericMap = @(
        @{ Bit=[int64]2147483648; Rights=[int64]1179785 }  # GENERIC_READ -> FILE_GENERIC_READ
        @{ Bit=[int64]1073741824; Rights=[int64]1179926 }  # GENERIC_WRITE -> FILE_GENERIC_WRITE
        @{ Bit=[int64]536870912; Rights=[int64]1179808 }   # GENERIC_EXECUTE -> FILE_GENERIC_EXECUTE
        @{ Bit=[int64]268435456; Rights=[int64]2032127 }   # GENERIC_ALL -> FILE_ALL_ACCESS
    )
    $expected = [Collections.Generic.List[string]]::new()
    foreach ($rule in $parentRules) {
        $flags = [int]$rule.InheritanceFlags
        if ($flags -eq 0) { continue }
        if ([string]$rule.IdentityReference.Value -cin @('S-1-3-0', 'S-1-3-1', 'S-1-3-4')) { return $false }
        $mask = [int64][int]$rule.FileSystemRights -band [int64]4294967295
        $noPropagate = ([int]$rule.PropagationFlags -band 1) -ne 0
        $generic = [int64]0; $mapped = $mask
        foreach ($entry in $genericMap) {
            if (($mask -band $entry.Bit) -ne 0) { $generic = $generic -bor $entry.Bit; $mapped = ($mapped -bxor $entry.Bit) -bor $entry.Rights }
        }
        $identity = [string]$rule.IdentityReference.Value
        if (($flags -band 1) -eq 0) {
            # Object-only inheritance reaches a child folder only as inherit-only.
            if (-not $noPropagate) { $expected.Add("$identity|$mask|$flags|2") }
            continue
        }
        if ($noPropagate) { $expected.Add("$identity|$mapped|0|0") }
        elseif ($generic -ne 0) { $expected.Add("$identity|$mapped|0|0"); $expected.Add("$identity|$mask|$flags|2") }
        else { $expected.Add("$identity|$mask|$flags|0") }
    }
    $actual = [Collections.Generic.List[string]]::new()
    foreach ($rule in @($DirectorySecurity.GetAccessRules($true, $true, $sidType))) {
        if (-not $rule.IsInherited -or $rule.AccessControlType -ne 'Allow') { return $false }
        $mask = [int64][int]$rule.FileSystemRights -band [int64]4294967295
        $actual.Add("$([string]$rule.IdentityReference.Value)|$mask|$([int]$rule.InheritanceFlags)|$([int]$rule.PropagationFlags)")
    }
    if (-not $expected.Count) { return $false }
    return (@($expected | Sort-Object) -join "`n") -ceq (@($actual | Sort-Object) -join "`n")
}

function Get-Windows11GroupPolicyRecoveryEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$RawState,
        [string]$RootPath = (Join-Path $env:SystemRoot 'System32\GroupPolicy')
    )

    $gptState = Get-Windows11EmptyComputerGptState -Bytes ([byte[]]@())
    $gptRevision = Get-Windows11ComputerGptRevisionState -Bytes ([byte[]]@())
    $parentAccess = $false
    $gptParentAccess = $false
    $directoryParentAccess = $false
    if ($RawState.Present) {
        $gpt = Join-Path $RootPath 'gpt.ini'
        if (Test-Path -LiteralPath $gpt -PathType Leaf) {
            $gptBytes = [IO.File]::ReadAllBytes($gpt)
            $gptState = Get-Windows11EmptyComputerGptState -Bytes $gptBytes
            $gptRevision = Get-Windows11ComputerGptRevisionState -Bytes $gptBytes
            $gptParentAccess = Test-Windows11EmptyPolicyFileAccess -FileSecurity (Get-Acl -LiteralPath $gpt) `
                -ParentSecurity (Get-Acl -LiteralPath $RootPath) -AllowAdministratorOwner
        }
        $pol = Join-Path $RootPath 'Machine\Registry.pol'
        if (Test-Path -LiteralPath $pol -PathType Leaf) {
            $parentAccess = Test-Windows11EmptyPolicyFileAccess -FileSecurity (Get-Acl -LiteralPath $pol) `
                -ParentSecurity (Get-Acl -LiteralPath (Split-Path $pol -Parent))
        }
        $machineDirectory = Join-Path $RootPath 'Machine'
        if (Test-Path -LiteralPath $machineDirectory -PathType Container) {
            $rootSecurity = Get-Acl -LiteralPath $RootPath
            $directoryParentAccess = $true
            foreach ($directory in @($machineDirectory, (Join-Path $RootPath 'User'))) {
                if (-not (Test-Path -LiteralPath $directory -PathType Container)) { continue }
                if (-not (Test-Windows11NewPolicyDirectoryAccess -DirectorySecurity (Get-Acl -LiteralPath $directory) `
                        -ParentSecurity $rootSecurity)) { $directoryParentAccess = $false }
            }
        }
    }
    # Bind the additional observations to the same bytes, layout and ACLs.
    $recheck = Get-Windows11LocalGroupPolicyFingerprintState -RootPath $RootPath
    if (($RawState | ConvertTo-Json -Depth 20 -Compress) -cne ($recheck | ConvertTo-Json -Depth 20 -Compress)) {
        throw 'Local Group Policy changed while collecting recovery evidence'
    }
    return [pscustomobject]@{ RawState=$RawState; EmptyComputerGpt=$gptState; EmptyPolicyHasParentAccess=$parentAccess; ComputerGptRevision=$gptRevision; EmptyGptHasParentAccess=$gptParentAccess; PolicyDirectoriesHaveParentAccess=$directoryParentAccess }
}

function Compare-Windows11GroupPolicyRecoveryEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Before, [Parameter(Mandatory = $true)]$After)

    $rejected = [pscustomobject]@{ Accepted=$false; Disposition='Unclassified local Group Policy difference' }
    $nonemptyRevision = Compare-Windows11NonemptyPolicyRevisionEvidence -Before $Before -After $After
    if ($nonemptyRevision.Accepted) { return $nonemptyRevision }
    if (-not $Before.RawState.Present -or -not $After.RawState.Present -or
        -not $After.EmptyComputerGpt.Supported -or -not $After.EmptyComputerGpt.VersionPresent) { return $rejected }
    $maps = @(@{}, @{})
    $states = @($Before.RawState, $After.RawState)
    for ($i = 0; $i -lt 2; $i++) {
        foreach ($entry in @($states[$i].Entries)) {
            # Windows PowerShell providers can repeat the path separator.
            $path = ([string]$entry.Path -replace '[\\/]+', '\').ToLowerInvariant()
            if ($maps[$i].ContainsKey($path)) { return $rejected }
            $maps[$i][$path] = $entry
        }
    }
    # A pristine installation has only the empty root; native Save then also
    # creates the Machine and User folders with inherited root access.
    $pristine = $maps[0].Count -eq 1 -and $maps[0].ContainsKey('') -and [bool]$maps[0][''].Directory
    for ($i = 0; $i -lt 2; $i++) {
        if (-not $maps[$i].ContainsKey('') -or -not $maps[$i][''].Directory) { return $rejected }
        if ($pristine -and $i -eq 0) { continue }
        if (-not $maps[$i].ContainsKey('machine') -or -not $maps[$i]['machine'].Directory) { return $rejected }
    }
    if ($pristine -and (-not $After.PSObject.Properties['PolicyDirectoriesHaveParentAccess'] -or
            -not [bool]$After.PolicyDirectoriesHaveParentAccess)) { return $rejected }
    $newGpt = -not $maps[0].ContainsKey('gpt.ini')
    if ($newGpt) {
        # Fresh native Save adds both metadata files to existing empty
        # root/Machine/User directories. Require this exact observed form,
        # separate inherited-access evidence and no pre-existing policy files.
        if ($Before.EmptyComputerGpt.Supported -or
            -not $After.PSObject.Properties['EmptyGptHasParentAccess'] -or -not $After.EmptyGptHasParentAccess -or
            -not $maps[1].ContainsKey('machine\registry.pol') -or [uint32]$After.EmptyComputerGpt.Revision -eq 0 -or
            @($maps[0].Keys | Where-Object { $_ -cnotin @('', 'machine', 'user') -or -not $maps[0][$_].Directory }).Count) { return $rejected }
        $nativeText = "[General]`r`ngPCMachineExtensionNames= `r`nVersion=$($After.EmptyComputerGpt.Revision)`r`n"
        $nativeGpt = Get-Windows11EmptyComputerGptState -Bytes ([Text.Encoding]::ASCII.GetBytes($nativeText))
        if (-not $nativeGpt.Supported -or $nativeGpt.Sha256 -cne $After.EmptyComputerGpt.Sha256) { return $rejected }
    }
    elseif (-not $Before.EmptyComputerGpt.Supported -or
        [uint32]$After.EmptyComputerGpt.Revision -le [uint32]$Before.EmptyComputerGpt.Revision) { return $rejected }
    for ($i = 0; $i -lt 2; $i++) {
        if ($newGpt -and $i -eq 0) { continue }
        if (-not $maps[$i].ContainsKey('gpt.ini') -or $maps[$i]['gpt.ini'].Directory) { return $rejected }
        $gpt = $maps[$i]['gpt.ini']
        $parsed = if ($i -eq 0) { $Before.EmptyComputerGpt } else { $After.EmptyComputerGpt }
        # Classify only the exact observed INI bytes, as for nonempty policy.
        # A missing binding, rollback or counter wrap is not native recovery.
        if (-not $parsed.PSObject.Properties['Bytes'] -or -not $parsed.PSObject.Properties['Sha256'] -or
            $parsed.Bytes -ne $gpt.Bytes -or $parsed.Sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $parsed.Sha256 -cne $gpt.Sha256) { return $rejected }
        if ($maps[$i].ContainsKey('machine\registry.pol')) {
            $pol = $maps[$i]['machine\registry.pol']
            if ($pol.Directory -or $pol.Bytes -ne 8 -or
                $pol.Sha256 -cne '5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89') { return $rejected }
        }
    }
    foreach ($path in @(@($maps[0].Keys) + @($maps[1].Keys) | Sort-Object -Unique)) {
        $left = $maps[0][$path]; $right = $maps[1][$path]
        if ($null -eq $left -or $null -eq $right) {
            if ($newGpt -and $path -ceq 'gpt.ini' -and $null -eq $left -and $null -ne $right) { continue }
            if ($pristine -and $path -cin @('machine', 'user') -and $null -eq $left -and [bool]$right.Directory) { continue }
            if ($path -cne 'machine\registry.pol' -or $null -ne $left -or
                -not $After.EmptyPolicyHasParentAccess) { return $rejected }
            continue
        }
        $excluded = @('Path')
        if ($path -ceq 'gpt.ini') { $excluded += @('Bytes', 'Sha256') }
        $leftJson = $left | Select-Object * -ExcludeProperty $excluded | ConvertTo-Json -Depth 20 -Compress
        $rightJson = $right | Select-Object * -ExcludeProperty $excluded | ConvertTo-Json -Depth 20 -Compress
        if ($leftJson -cne $rightJson) { return $rejected }
    }
    return [pscustomobject]@{
        Accepted=$true
        Disposition=$(if ($pristine) {
            'Fresh native empty local GPO in a previously empty root: root-inherited Machine/User folders, empty computer INI and eight-byte policy file with proven inherited access; raw differences retained'
        } elseif ($newGpt) {
            'Fresh native empty computer INI and eight-byte policy file with proven inherited access; original directories unchanged; raw differences retained'
        } else {
            'Native computer revision/empty extension registration and optional inherited eight-byte empty policy file; raw differences retained'
        })
    }
}
