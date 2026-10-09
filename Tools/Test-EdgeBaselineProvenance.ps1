#Requires -Version 5.1

<#
.SYNOPSIS
    Reproduce and verify the embedded Microsoft Edge v151 baseline inventory.

.DESCRIPTION
    Validates the exact official ZIP bytes, reparses the single PolicyRules
    source, and compares all 24 Microsoft-managed values plus the one
    **delvals. metadata directive with the checked-in Edge configuration.  The
    seven separately classified NoID Privacy additions must be disjoint and are
    reported separately; they are never presented as Microsoft baseline rows.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,

    [Parameter(Mandatory = $true)]
    [string]$BaselinePath
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$parserPath = Join-Path $PSScriptRoot 'Parse-EdgeBaseline.ps1'
$configRoot = Join-Path $repoRoot 'Modules\EdgeHardening\Config'
$expectedArchiveLength = 466831L
$expectedArchiveSha256 = 'c8d1be7073a17a96fd1a5140fc68770068cc15497a27036b16d783d1e5c7a6ab'
$expectedPolicyRulesMember = 'Microsoft Edge v151 Security Baseline/Documentation/MSFT-Edge-v151.PolicyRules'
$expectedPolicyRulesSha256 = 'b19b1c2ae6bceb9eec4e2530798420d5a035e0b5b7540fdc0d0b1803fb414202'

function Read-EdgeJson {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required Edge JSON artifact not found: $Path"
    }
    $parsed = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    # Normalize the root-array pipeline behavior across Windows PowerShell 5.1
    # and PowerShell 7+ before applying exact inventory counts and comparisons.
    foreach ($entry in @($parsed)) { $entry }
}

function ConvertTo-EdgeLine {
    param(
        [Parameter(Mandatory = $true)][object]$Entry,
        [Parameter(Mandatory = $false)][switch]$Repository
    )

    $key = ([string]$Entry.KeyName).Trim()
    if ($Repository) {
        if (-not $key.StartsWith('[', [StringComparison]::Ordinal)) {
            throw "Repository Edge key is missing its policy-file marker: $key"
        }
        $key = $key.Substring(1)
    }
    $data = ConvertTo-Json -InputObject @($Entry.Data) -Compress -Depth 10
    return @($key, [string]$Entry.ValueName, [string]$Entry.Type, $data) -join ([char]31)
}

function Assert-ExactEdgeSet {
    param(
        [Parameter(Mandatory = $true)][string[]]$Source,
        [Parameter(Mandatory = $true)][string[]]$Repository
    )

    if (@($Source | Group-Object -CaseSensitive | Where-Object Count -ne 1).Count -gt 0 -or
        @($Repository | Group-Object -CaseSensitive | Where-Object Count -ne 1).Count -gt 0) {
        throw 'Edge baseline source or repository contains duplicate identities'
    }
    $difference = @(Compare-Object -ReferenceObject @($Source | Sort-Object) `
            -DifferenceObject @($Repository | Sort-Object) -CaseSensitive)
    if ($difference.Count -gt 0) {
        $sample = @($difference | Select-Object -First 10 | ForEach-Object {
                "$($_.SideIndicator) $($_.InputObject)"
            }) -join '; '
        throw "Embedded Edge baseline differs from the official PolicyRules source: $sample"
    }
}

$temporaryOutput = Join-Path ([System.IO.Path]::GetTempPath()) (
    'NoID-Edge-Provenance_{0}' -f [Guid]::NewGuid().ToString('N')
)
try {
    $archive = Get-Item -LiteralPath $ArchivePath -ErrorAction Stop
    if ($archive.PSIsContainer -or $archive.Length -ne $expectedArchiveLength) {
        throw "Official Edge baseline archive length mismatch: expected $expectedArchiveLength, got $($archive.Length)"
    }
    $archiveHash = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($archiveHash -cne $expectedArchiveSha256) {
        throw "Official Edge baseline archive SHA-256 mismatch: expected $expectedArchiveSha256, got $archiveHash"
    }
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $zip = [System.IO.Compression.ZipFile]::OpenRead($archive.FullName)
    try {
        $archiveMembers = @($zip.Entries | Where-Object { [string]$_.FullName -ceq $expectedPolicyRulesMember })
        if ($archiveMembers.Count -ne 1) {
            throw "Official Edge archive must contain exactly one '$expectedPolicyRulesMember' member; found $($archiveMembers.Count)"
        }
        $memberStream = $archiveMembers[0].Open()
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $archivePolicyRulesHash = [BitConverter]::ToString($sha256.ComputeHash($memberStream)).Replace('-', '').ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
            $memberStream.Dispose()
        }
    }
    finally {
        $zip.Dispose()
    }
    if ($archivePolicyRulesHash -cne $expectedPolicyRulesSha256) {
        throw "Official Edge archive PolicyRules SHA-256 mismatch: expected $expectedPolicyRulesSha256, got $archivePolicyRulesHash"
    }
    if (-not (Test-Path -LiteralPath $BaselinePath -PathType Container)) {
        throw "Extracted Edge baseline directory not found: $BaselinePath"
    }
    $policyRuleFiles = @(Get-ChildItem -LiteralPath $BaselinePath -Filter '*.PolicyRules' -File -Recurse -ErrorAction Stop)
    if ($policyRuleFiles.Count -ne 1) {
        throw "Expected exactly one official Edge PolicyRules file; found $($policyRuleFiles.Count)"
    }
    $policyRulesHash = (Get-FileHash -LiteralPath $policyRuleFiles[0].FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($policyRulesHash -cne $expectedPolicyRulesSha256) {
        throw "Official Edge PolicyRules SHA-256 mismatch: expected $expectedPolicyRulesSha256, got $policyRulesHash"
    }

    $null = New-Item -Path $temporaryOutput -ItemType Directory -ErrorAction Stop
    $null = & $parserPath -BaselinePath $BaselinePath -OutputPath $temporaryOutput -SourcePackagePath $archive.FullName -Confirm:$false
    $source = @(Read-EdgeJson (Join-Path $temporaryOutput 'MicrosoftBaselinePolicies.json'))
    $runtime = @(Read-EdgeJson (Join-Path $configRoot 'EdgePolicies.json'))
    $summary = Read-EdgeJson (Join-Path $configRoot 'Summary.json')

    if ([int]$summary.SchemaVersion -ne 3 -or
        [string]$summary.BaselineVersion -cne 'Microsoft Edge v151' -or
        [int]$summary.MicrosoftBaselinePolicyCount -ne 24 -or
        [int]$summary.PrivacyAdditionPolicyCount -ne 7 -or
        [int]$summary.ManagedPolicyCount -ne 31 -or
        [int]$summary.MetadataEntryCount -ne 1) {
        throw 'Edge summary count/version contract failed'
    }
    if ([string]$summary.OfficialPackage.FileName -cne $archive.Name -or
        [int64]$summary.OfficialPackage.SizeBytes -ne $archive.Length -or
        [string]$summary.OfficialPackage.Sha256 -cne $archiveHash -or
        [string]$summary.OfficialPackage.PolicyRulesMember -cne $expectedPolicyRulesMember -or
        [string]$summary.OfficialPackage.PolicyRulesSha256 -cne $policyRulesHash) {
        throw 'Edge summary does not identify the exact verified official package'
    }

    $baselineNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @($summary.MicrosoftBaselinePolicyNames)) {
        if (-not $baselineNames.Add([string]$name)) {
            throw "Edge summary contains a duplicate Microsoft baseline name: $name"
        }
    }
    $privacyNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @($summary.PrivacyAdditionPolicyNames)) {
        if ($baselineNames.Contains([string]$name) -or -not $privacyNames.Add([string]$name)) {
            throw "Edge privacy-addition name overlaps or is duplicated: $name"
        }
    }
    if ($baselineNames.Count -ne 24 -or $privacyNames.Count -ne 7) {
        throw 'Edge baseline/privacy name inventory count failed'
    }

    $runtimeBaseline = @($runtime | Where-Object {
            $baselineNames.Contains([string]$_.ValueName) -or [string]$_.ValueName -ceq '**delvals.'
        })
    $runtimePrivacy = @($runtime | Where-Object { $privacyNames.Contains([string]$_.ValueName) })
    $unclassified = @($runtime | Where-Object {
            -not $baselineNames.Contains([string]$_.ValueName) -and
            -not $privacyNames.Contains([string]$_.ValueName) -and
            [string]$_.ValueName -cne '**delvals.'
        })
    if ($source.Count -ne 25 -or $runtimeBaseline.Count -ne 25 -or
        $runtimePrivacy.Count -ne 7 -or $unclassified.Count -ne 0 -or $runtime.Count -ne 32) {
        throw 'Edge source/runtime baseline, metadata, privacy, or classification count failed'
    }

    $v151Contracts = @(
        [PSCustomObject]@{ Name = 'ProcessIsolationEnabled'; Minimum = 151; Value = 1; Managed = $false },
        [PSCustomObject]@{ Name = 'RendererAppContainerEnabled'; Minimum = 96; Value = 1; Managed = $false },
        [PSCustomObject]@{ Name = 'NetworkServiceSandboxEnabled'; Minimum = 102; Value = 1; Managed = $false },
        [PSCustomObject]@{ Name = 'BrowserCodeIntegritySetting'; Minimum = 104; Value = 2; Managed = $true },
        [PSCustomObject]@{ Name = 'EnhanceSecurityMode'; Minimum = 98; Value = 1; Managed = $false }
    )
    foreach ($contract in $v151Contracts) {
        $entry = @($runtimeBaseline | Where-Object { [string]$_.ValueName -ceq [string]$contract.Name })
        $minimumProperty = $summary.MinimumEdgeMajorByPolicy.PSObject.Properties[[string]$contract.Name]
        $sourceProperty = $summary.Sources.PSObject.Properties[[string]$contract.Name]
        $managed = [string]$contract.Name -in @($summary.ManagedWindowsOnlyPolicies)
        if ($entry.Count -ne 1 -or
            [string]$entry[0].KeyName -cne '[Software\Policies\Microsoft\Edge' -or
            [string]$entry[0].Type -cne 'REG_DWORD' -or [int]$entry[0].Data -ne [int]$contract.Value -or
            -not $minimumProperty -or [int]$minimumProperty.Value -ne [int]$contract.Minimum -or
            -not $sourceProperty -or [string]::IsNullOrWhiteSpace([string]$sourceProperty.Value) -or
            $managed -ne [bool]$contract.Managed) {
            throw "Edge v151 source/type/value/minimum/applicability contract failed: $($contract.Name)"
        }
    }

    # All seven privacy additions carry an explicit key/type/VALUE/minimum
    # contract, so a hand-edited EdgePolicies.json (for example DiagnosticData=2
    # or TrackingPrevention=0) cannot pass this provenance gate. The three
    # newest additions additionally pin their documented source URL.
    $newPrivacyContracts = @(
        [PSCustomObject]@{ Name = 'PersonalizationReportingEnabled'; Minimum = 80; Value = 0; Url = $null },
        [PSCustomObject]@{ Name = 'DiagnosticData'; Minimum = 122; Value = 0; Url = $null },
        [PSCustomObject]@{ Name = 'TrackingPrevention'; Minimum = 78; Value = 2; Url = $null },
        [PSCustomObject]@{ Name = 'EdgeShoppingAssistantEnabled'; Minimum = 87; Value = 0; Url = $null },
        [PSCustomObject]@{
            Name = 'SearchSuggestEnabled'; Minimum = 77; Value = 0
            Url = 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/searchsuggestenabled'
        },
        [PSCustomObject]@{
            Name = 'AddressBarTrendingSuggestEnabled'; Minimum = 135; Value = 0
            Url = 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/addressbartrendingsuggestenabled'
        },
        [PSCustomObject]@{
            Name = 'EdgeReadingModeServiceBasedExtractionEnabled'; Minimum = 151; Value = 0
            Url = 'https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/edgereadingmodeservicebasedextractionenabled'
        }
    )
    if (@($newPrivacyContracts).Count -ne $runtimePrivacy.Count) {
        throw "Privacy-addition contract table covers $(@($newPrivacyContracts).Count) policies but the runtime declares $($runtimePrivacy.Count)"
    }
    foreach ($contract in $newPrivacyContracts) {
        $entry = @($runtimePrivacy | Where-Object { [string]$_.ValueName -ceq [string]$contract.Name })
        $minimumProperty = $summary.MinimumEdgeMajorByPolicy.PSObject.Properties[[string]$contract.Name]
        if ($entry.Count -ne 1 -or
            [string]$entry[0].KeyName -cne '[Software\Policies\Microsoft\Edge' -or
            [string]$entry[0].Type -cne 'REG_DWORD' -or [int]$entry[0].Data -ne [int]$contract.Value -or
            -not $minimumProperty -or [int]$minimumProperty.Value -ne [int]$contract.Minimum) {
            throw "Edge privacy-addition source/type/value/minimum contract failed: $($contract.Name)"
        }
        if ($null -ne $contract.Url) {
            $sourceProperty = $summary.Sources.PSObject.Properties[[string]$contract.Name]
            if (-not $sourceProperty -or [string]$sourceProperty.Value -cne [string]$contract.Url) {
                throw "Edge privacy-addition documented-source contract failed: $($contract.Name)"
            }
        }
    }

    $sourceLines = @($source | ForEach-Object { ConvertTo-EdgeLine -Entry $_ })
    $runtimeLines = @($runtimeBaseline | ForEach-Object { ConvertTo-EdgeLine -Entry $_ -Repository })
    Assert-ExactEdgeSet -Source $sourceLines -Repository $runtimeLines

    [PSCustomObject]@{
        Success                   = $true
        ArchiveBytes              = $archive.Length
        ArchiveSha256             = $archiveHash
        PolicyRulesMember         = $expectedPolicyRulesMember
        PolicyRulesSha256         = $policyRulesHash
        MicrosoftManagedValues    = 24
        MetadataDirectives        = 1
        PrivacyAdditions          = 7
        DeclaredProductDeviations = @($summary.IntentionalDeviations).Count
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryOutput) {
        Remove-Item -LiteralPath $temporaryOutput -Recurse -Force -ErrorAction Stop
    }
}
