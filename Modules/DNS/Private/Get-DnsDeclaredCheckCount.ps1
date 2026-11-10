function Get-DnsDeclaredCheckCount {
    [CmdletBinding()]
    [OutputType([int])]
    param()

    $countsPath = Join-Path $script:ModuleRoot '..\..\Config\SettingsCounts.json'
    if (-not (Test-Path -LiteralPath $countsPath -PathType Leaf)) {
        throw "Canonical SettingsCounts.json is missing: $countsPath"
    }
    $counts = Get-Content -LiteralPath $countsPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$counts.schemaVersion -ne 1 -or
        -not $counts.modules.PSObject.Properties['DNS'] -or
        [int]$counts.modules.DNS.checks -lt 1) {
        throw 'Canonical DNS check count is invalid'
    }
    return [int]$counts.modules.DNS.checks
}
