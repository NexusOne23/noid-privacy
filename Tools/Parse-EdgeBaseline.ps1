#Requires -Version 5.1

<#
.SYNOPSIS
    Parse and validate an extracted official Microsoft Edge v139 baseline.

.DESCRIPTION
    Developer-only provenance tool. It reads the official *.PolicyRules file,
    emits a sanitized baseline-only JSON inventory, and never overwrites the
    runtime EdgePolicies.json or Summary.json files. SourceFile fields from the
    Microsoft package are intentionally excluded because they can contain a
    packager's local user path.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaselinePath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\Modules\EdgeHardening\ParsedSettings'),

    [Parameter(Mandatory = $false)]
    [string]$SourcePackagePath
)

$ErrorActionPreference = 'Stop'
$baselineRoot = [System.IO.Path]::GetFullPath($BaselinePath)
if (-not (Test-Path -LiteralPath $baselineRoot -PathType Container)) {
    throw "Extracted Edge baseline folder not found: $baselineRoot"
}

$policyRuleFiles = @(Get-ChildItem -LiteralPath $baselineRoot -Filter '*.PolicyRules' -File -Recurse -ErrorAction Stop)
if ($policyRuleFiles.Count -ne 1) {
    throw "Expected exactly one official *.PolicyRules file under '$baselineRoot'; found $($policyRuleFiles.Count)"
}
$policyRulesPath = $policyRuleFiles[0].FullName
$policyRulesHash = (Get-FileHash -LiteralPath $policyRulesPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()

$document = [System.Xml.XmlDocument]::new()
$document.PreserveWhitespace = $true
$document.Load($policyRulesPath)
$nodes = @($document.PolicyRules.ComputerConfig)
if ($nodes.Count -ne 20) {
    throw "Edge v139 PolicyRules must contain 20 rows (19 values plus one metadata directive); found $($nodes.Count)"
}

$entries = [System.Collections.Generic.List[object]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$metadataCount = 0
foreach ($node in $nodes) {
    $key = [string]$node.SelectSingleNode('Key').InnerText
    $name = [string]$node.SelectSingleNode('Value').InnerText
    $type = [string]$node.SelectSingleNode('RegType').InnerText
    $rawData = [string]$node.SelectSingleNode('RegData').InnerText
    if ($key -notin @(
            'Software\Policies\Microsoft\Edge',
            'Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
        )) {
        throw "Official Edge baseline row is outside the exact key allowlist: $key::$name"
    }
    if ([string]::IsNullOrWhiteSpace($name) -or -not $seen.Add("$key`0$name")) {
        throw "Official Edge baseline contains an empty or duplicate target: $key::$name"
    }

    if ($name -eq '**delvals.') {
        $metadataCount++
        if ($key -ne 'Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist' -or $type -ne 'REG_SZ') {
            throw 'Official Edge baseline metadata directive is malformed'
        }
        $data = $rawData
    }
    else {
        $data = switch ($type) {
            'REG_DWORD' {
                $number = 0
                if (-not [int]::TryParse($rawData, [ref]$number)) {
                    throw "Official Edge DWord is not an integer: $key::$name"
                }
                $number
            }
            'REG_SZ' { $rawData }
            default { throw "Unsupported official Edge v139 registry type '$type': $key::$name" }
        }
    }

    $entries.Add([PSCustomObject]@{
            KeyName   = $key
            ValueName = $name
            Type      = $type
            Data      = $data
        })
}
if ($metadataCount -ne 1 -or @($entries | Where-Object ValueName -ne '**delvals.').Count -ne 19) {
    throw 'Official Edge v139 metadata/managed-value count is not exactly 1/19'
}

$package = $null
if (-not [string]::IsNullOrWhiteSpace($SourcePackagePath)) {
    $packagePath = [System.IO.Path]::GetFullPath($SourcePackagePath)
    if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
        throw "Source package not found: $packagePath"
    }
    $package = [PSCustomObject]@{
        FileName  = [System.IO.Path]::GetFileName($packagePath)
        SizeBytes = (Get-Item -LiteralPath $packagePath -ErrorAction Stop).Length
        Sha256    = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    }
}

$outputRoot = [System.IO.Path]::GetFullPath($OutputPath)
if (-not $PSCmdlet.ShouldProcess($outputRoot, 'Write sanitized Edge baseline parse outputs')) {
    return
}
if (-not (Test-Path -LiteralPath $outputRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $outputRoot -Force -ErrorAction Stop | Out-Null
}

$inventoryPath = Join-Path $outputRoot 'MicrosoftBaselinePolicies.json'
$provenancePath = Join-Path $outputRoot 'MicrosoftBaselineProvenance.json'
$provenance = [PSCustomObject]@{
    SchemaVersion       = 1
    BaselineVersion     = 'Microsoft Edge v139'
    ParsedAtUtc         = (Get-Date).ToUniversalTime().ToString('o')
    ManagedValueCount   = 19
    MetadataEntryCount  = 1
    PolicyRulesFileName = $policyRuleFiles[0].Name
    PolicyRulesSha256   = $policyRulesHash
    SourcePackage       = $package
}
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($inventoryPath, (ConvertTo-Json -InputObject @($entries) -Depth 10), $utf8NoBom)
[System.IO.File]::WriteAllText($provenancePath, (ConvertTo-Json -InputObject $provenance -Depth 10), $utf8NoBom)

return [PSCustomObject]@{
    Success            = $true
    ManagedValueCount  = 19
    MetadataEntryCount = 1
    InventoryPath      = $inventoryPath
    ProvenancePath     = $provenancePath
}
