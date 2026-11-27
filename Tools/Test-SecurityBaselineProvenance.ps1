#Requires -Version 5.1

<#
.SYNOPSIS
    Reproduce and verify the embedded Windows 11 26H2 baseline profile.

.DESCRIPTION
    Validates the exact official archive bytes observed for the Microsoft
    Windows 11 v26H2 Security Baseline v2 package, reparses the extracted GPO
    sources, and compares every registry, security-template, and audit target
    with the checked-in NoID Privacy profile. Exactly two declared product deviations
    are permitted: RDVDenyWriteAccess is 0 instead of Microsoft's 1, and
    SubmitSamplesConsent is 1 (safe samples only) instead of Microsoft's 3
    (send all samples).

.PARAMETER ArchivePath
    Path to the unmodified Microsoft ZIP package.

.PARAMETER BaselinePath
    Deprecated and ignored. The source is always extracted from the
    hash-verified archive itself, never from a separately supplied directory.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,

    # Deprecated and ignored: parsing a separately supplied extraction would
    # decouple the parsed source from the hash-verified archive.
    [Parameter(Mandatory = $false)]
    [string]$BaselinePath
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$parserPath = Join-Path $PSScriptRoot 'Parse-SecurityBaseline.ps1'
$profilePath = Join-Path $repoRoot 'Modules/SecurityBaseline/ParsedSettings'
$expectedArchiveLength = 1328685L
$expectedArchiveSha256 = '369f8dad02485b3fc20be089649a29eb6432a7d0f63cef75addace9685e45d18'
$expectedProfileHashes = [ordered]@{
    'AuditPolicies.json'             = '0dddae691dbad43ec71f97a84032aaf6eda9ddb4884cb993b37cf6dd86772101'
    'Computer-RegistryPolicies.json' = 'b0f39d0f1e81faf3e752bcbd2ead6f54bbae57b067216cbe9decac3d23e903c2'
    'SecurityTemplates.json'         = '12fd84ee2ecfcdeb3515d08b9fd4a634d3308be6285a1a79cf77b6a538109e93'
    'Summary.json'                   = '5aa03d1be0bf2d454eaef7674a0a72d4e1c17836dc1c7a6646edf2ffb6f03c91'
    'User-RegistryPolicies.json'     = '3178f4f031eaef144d23c4435694df2afea75237442a788acf446602120cb3ea'
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required JSON artifact not found: $Path"
    }
    $parsed = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    # Windows PowerShell 5.1 can emit a JSON root array as one pipeline object
    # when it is returned directly from a function. Emit every root element so
    # callers get the same inventory shape on 5.1 and PowerShell 7+.
    foreach ($entry in @($parsed)) { $entry }
}

function ConvertTo-RegistryLine {
    param([Parameter(Mandatory = $true)][object]$Entry)

    $required = @('GPO', 'KeyName', 'ValueName', 'Type', 'Data')
    $actual = @($Entry.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ([char]10)) -cne (($required | Sort-Object) -join ([char]10))) {
        throw "Unexpected registry record shape for $($Entry.GPO)/$($Entry.ValueName): [$($actual -join ', ')]"
    }
    $data = ConvertTo-Json -InputObject @($Entry.Data) -Compress -Depth 20
    return @([string]$Entry.GPO, [string]$Entry.KeyName, [string]$Entry.ValueName, [string]$Entry.Type, $data) -join ([char]31)
}

function Assert-ExactLineSet {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$Source,
        [Parameter(Mandatory = $true)][string[]]$Repository
    )

    $sourceDuplicates = @($Source | Group-Object -CaseSensitive | Where-Object Count -ne 1)
    $repoDuplicates = @($Repository | Group-Object -CaseSensitive | Where-Object Count -ne 1)
    if ($sourceDuplicates.Count -gt 0 -or $repoDuplicates.Count -gt 0) {
        throw "$Name contains duplicate identities"
    }
    $difference = @(Compare-Object -ReferenceObject @($Source | Sort-Object) -DifferenceObject @($Repository | Sort-Object) -CaseSensitive)
    if ($difference.Count -gt 0) {
        $sample = @($difference | Select-Object -First 10 | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }) -join '; '
        throw "$Name differs from the official parsed source: $sample"
    }
}

function ConvertTo-TemplateLines {
    param([Parameter(Mandatory = $true)][object]$Templates)

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($gpo in @($Templates.PSObject.Properties | Sort-Object Name)) {
        foreach ($section in @($gpo.Value.PSObject.Properties | Sort-Object Name)) {
            foreach ($setting in @($section.Value.PSObject.Properties | Sort-Object Name)) {
                $lines.Add((@($gpo.Name, $section.Name, $setting.Name, [string]$setting.Value) -join ([char]31)))
            }
        }
    }
    return $lines.ToArray()
}

function ConvertTo-AuditLines {
    param([Parameter(Mandatory = $true)][object[]]$Policies)

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($policy in $Policies) {
        $required = @('GPO', 'Subcategory', 'SubcategoryGUID', 'InclusionSetting', 'SettingValue')
        $actual = @($policy.PSObject.Properties.Name | Sort-Object)
        if (($actual -join ([char]10)) -cne (($required | Sort-Object) -join ([char]10))) {
            throw "Unexpected audit record shape for $($policy.SubcategoryGUID)"
        }
        $lines.Add((@(
                    [string]$policy.GPO,
                    [string]$policy.Subcategory,
                    [string]$policy.SubcategoryGUID,
                    [string]$policy.InclusionSetting,
                    [string]$policy.SettingValue
                ) -join ([char]31)))
    }
    return $lines.ToArray()
}

# Short prefix on purpose: the deepest baseline path inside the archive is
# ~151 characters, and Windows PowerShell still enforces MAX_PATH (260). A
# verbose prefix plus a deep %TEMP% could make ExtractToDirectory fail with
# PathTooLongException.
$temporaryOutput = Join-Path ([System.IO.Path]::GetTempPath()) ("nbp-{0}" -f [Guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    $archive = Get-Item -LiteralPath $ArchivePath -ErrorAction Stop
    if ($archive.PSIsContainer -or $archive.Length -ne $expectedArchiveLength) {
        throw "Official baseline archive length mismatch: expected $expectedArchiveLength, got $($archive.Length)"
    }
    $archiveHash = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($archiveHash -cne $expectedArchiveSha256) {
        throw "Official baseline archive SHA-256 mismatch: expected $expectedArchiveSha256, got $archiveHash"
    }
    if ($PSBoundParameters.ContainsKey('BaselinePath') -and -not [string]::IsNullOrWhiteSpace($BaselinePath)) {
        Write-Warning 'BaselinePath is deprecated and ignored: the source is now parsed from the hash-verified archive itself, never from a separate extraction.'
    }
    foreach ($artifact in $expectedProfileHashes.GetEnumerator()) {
        $path = Join-Path $profilePath $artifact.Key
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($hash -cne $artifact.Value) {
            throw "Embedded profile hash mismatch for $($artifact.Key): expected $($artifact.Value), got $hash"
        }
    }

    $null = New-Item -Path $temporaryOutput -ItemType Directory -ErrorAction Stop

    # Parse the bytes we just verified, not a directory someone prepared. The
    # archive hash above is the ONLY provenance anchor; everything the parser
    # reads must descend from it.
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $extractedSourcePath = Join-Path $temporaryOutput 'source'
    $null = New-Item -Path $extractedSourcePath -ItemType Directory -ErrorAction Stop
    [System.IO.Compression.ZipFile]::ExtractToDirectory($archive.FullName, $extractedSourcePath)
    $gpoRoots = @(Get-ChildItem -LiteralPath $extractedSourcePath -Directory -Recurse -Force |
            Where-Object { $_.Name -ceq 'GPOs' })
    if ($gpoRoots.Count -ne 1) {
        throw "Verified archive must contain exactly one GPOs directory; found $($gpoRoots.Count)"
    }
    $verifiedBaselinePath = $gpoRoots[0].Parent.FullName
    $parsedOutputPath = Join-Path $temporaryOutput 'parsed'

    & $parserPath -BaselinePath $verifiedBaselinePath -OutputPath $parsedOutputPath

    $sourceComputer = @(Read-JsonFile (Join-Path $parsedOutputPath 'Computer-RegistryPolicies.json'))
    $repoComputer = @(Read-JsonFile (Join-Path $profilePath 'Computer-RegistryPolicies.json'))

    # Declared deviation 1: RDVDenyWriteAccess (BitLocker removable drives)
    $deviationKey = '[System\CurrentControlSet\Policies\Microsoft\FVE'
    $deviationName = 'RDVDenyWriteAccess'
    $sourceDeviation = @($sourceComputer | Where-Object {
            $_.GPO -ceq 'MSFT Windows 11 26H2 - BitLocker' -and
            $_.KeyName -ceq $deviationKey -and $_.ValueName -ceq $deviationName
        })
    $repoDeviation = @($repoComputer | Where-Object {
            $_.GPO -ceq 'MSFT Windows 11 26H2 - BitLocker' -and
            $_.KeyName -ceq $deviationKey -and $_.ValueName -ceq $deviationName
        })
    $expectedComment = 'HOME USER DEFAULT: Allow USB write access. Enterprise users: Change to 1 to mount removable drives without BitLocker protection read-only. This policy does not encrypt a drive automatically; users can enable BitLocker separately.'
    if ($sourceDeviation.Count -ne 1 -or $sourceDeviation[0].Type -cne 'REG_DWORD' -or [int]$sourceDeviation[0].Data -ne 1) {
        throw 'Microsoft RDVDenyWriteAccess source value is not the expected single REG_DWORD 1 target'
    }
    if ($repoDeviation.Count -ne 1 -or $repoDeviation[0].Type -cne 'REG_DWORD' -or
        [int]$repoDeviation[0].Data -ne 0 -or [string]$repoDeviation[0].Comment -cne $expectedComment) {
        throw 'NoID Privacy RDVDenyWriteAccess deviation is not the expected documented REG_DWORD 0 target'
    }

    # Declared deviation 2: SubmitSamplesConsent (Defender sample submission)
    $samplesKey = '[Software\Policies\Microsoft\Windows Defender\Spynet'
    $samplesName = 'SubmitSamplesConsent'
    $sourceSamplesDeviation = @($sourceComputer | Where-Object {
            $_.GPO -ceq 'MSFT Windows 11 26H2 - Defender Antivirus' -and
            $_.KeyName -ceq $samplesKey -and $_.ValueName -ceq $samplesName
        })
    $repoSamplesDeviation = @($repoComputer | Where-Object {
            $_.GPO -ceq 'MSFT Windows 11 26H2 - Defender Antivirus' -and
            $_.KeyName -ceq $samplesKey -and $_.ValueName -ceq $samplesName
        })
    $expectedSamplesComment = "PRIVACY DEFAULT: Send safe samples only (1). Microsoft's 26H2 baseline value is 3 (send ALL samples automatically), which can upload personal documents to Microsoft. Block-at-First-Seen stays functional with 1. The interactive Defender sample-submission choice or submitAllSamples=true restores Microsoft's 3."
    if ($sourceSamplesDeviation.Count -ne 1 -or $sourceSamplesDeviation[0].Type -cne 'REG_DWORD' -or [int]$sourceSamplesDeviation[0].Data -ne 3) {
        throw 'Microsoft SubmitSamplesConsent source value is not the expected single REG_DWORD 3 target'
    }
    if ($repoSamplesDeviation.Count -ne 1 -or $repoSamplesDeviation[0].Type -cne 'REG_DWORD' -or
        [int]$repoSamplesDeviation[0].Data -ne 1 -or [string]$repoSamplesDeviation[0].Comment -cne $expectedSamplesComment) {
        throw 'NoID Privacy SubmitSamplesConsent deviation is not the expected documented REG_DWORD 1 target'
    }

    $sourceComputerWithoutDeviation = @($sourceComputer | Where-Object { $_ -ne $sourceDeviation[0] -and $_ -ne $sourceSamplesDeviation[0] } | ForEach-Object { ConvertTo-RegistryLine $_ })
    $repoComputerWithoutDeviation = @($repoComputer | Where-Object { $_ -ne $repoDeviation[0] -and $_ -ne $repoSamplesDeviation[0] } | ForEach-Object { ConvertTo-RegistryLine $_ })
    Assert-ExactLineSet -Name 'Computer registry policies excluding the two declared deviations' -Source $sourceComputerWithoutDeviation -Repository $repoComputerWithoutDeviation

    $sourceUser = @(Read-JsonFile (Join-Path $parsedOutputPath 'User-RegistryPolicies.json'))
    $repoUser = @(Read-JsonFile (Join-Path $profilePath 'User-RegistryPolicies.json'))
    $sourceUserLines = @($sourceUser | ForEach-Object { ConvertTo-RegistryLine $_ })
    $repoUserLines = @($repoUser | ForEach-Object { ConvertTo-RegistryLine $_ })
    Assert-ExactLineSet -Name 'User registry policies' -Source $sourceUserLines -Repository $repoUserLines

    $sourceTemplates = Read-JsonFile (Join-Path $parsedOutputPath 'SecurityTemplates.json')
    $repoTemplates = Read-JsonFile (Join-Path $profilePath 'SecurityTemplates.json')
    $sourceTemplateLines = @(ConvertTo-TemplateLines $sourceTemplates)
    $repoTemplateLines = @(ConvertTo-TemplateLines $repoTemplates)
    Assert-ExactLineSet -Name 'Security template settings' -Source $sourceTemplateLines -Repository $repoTemplateLines

    $sourceAudit = @(Read-JsonFile (Join-Path $parsedOutputPath 'AuditPolicies.json'))
    $repoAudit = @(Read-JsonFile (Join-Path $profilePath 'AuditPolicies.json'))
    $sourceAuditLines = @(ConvertTo-AuditLines $sourceAudit)
    $repoAuditLines = @(ConvertTo-AuditLines $repoAudit)
    Assert-ExactLineSet -Name 'Advanced audit policies' -Source $sourceAuditLines -Repository $repoAuditLines

    $sourceSummary = Read-JsonFile (Join-Path $parsedOutputPath 'Summary.json')
    $repoSummary = Read-JsonFile (Join-Path $profilePath 'Summary.json')
    if ([int]$sourceSummary.TotalRegistrySettings -ne 336 -or
        [int]$sourceSummary.TotalSecuritySettings -ne 79 -or
        [int]$sourceSummary.TotalAuditPolicies -ne 23 -or
        [int]$sourceSummary.TotalSettings -ne 438 -or
        [int]$repoSummary.TotalSettingsParsed -ne 438 -or
        [int]$repoSummary.TotalRegistrySettings -ne 336 -or
        [int]$repoSummary.TotalRegistrySettingsApplied -ne 335 -or
        [int]$repoSummary.MetadataEntriesSkipped -ne 13 -or
        [int]$repoSummary.TotalSettingsApplied -ne 425) {
        throw 'Baseline source/repository summary count contract failed'
    }

    [PSCustomObject]@{
        Success                   = $true
        ArchiveBytes              = $archive.Length
        ArchiveSha256             = $archiveHash
        SourceRegistryPolicies    = 336
        SourceSecuritySettings    = 79
        SourceAuditPolicies       = 23
        SourceTotal               = 438
        FrameworkAppliedTargets   = 425
        DeclaredProductDeviations = 2
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryOutput) {
        # Best-effort: a locked freshly-extracted file (AV scan) must not mask
        # the actual verification result with a cleanup exception.
        Remove-Item -LiteralPath $temporaryOutput -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $temporaryOutput) {
            Write-Warning "Temporary provenance extraction could not be fully removed: $temporaryOutput"
        }
    }
}
