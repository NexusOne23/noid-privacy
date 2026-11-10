#Requires -Version 5.1

function Get-SecurityTemplateBackupMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory = $true)][string]$Path)

    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ($content.IndexOf([char]0) -ge 0) { throw 'SecurityTemplate artifact contains a NUL character' }
    $map = @{}
    $section = ''
    foreach ($line in ($content -split '\r\n|\n|\r')) {
        $text = $line.Trim()
        if (-not $text -or $text.StartsWith(';')) { continue }
        if ($text.StartsWith('[')) {
            if ($text -notmatch '^\[([^\[\]]+)\]$') { throw 'SecurityTemplate artifact contains a malformed section header' }
            $section = $Matches[1]
            if ($section -notin @('Unicode', 'Version', 'System Access', 'Privilege Rights')) {
                throw "SecurityTemplate artifact contains an unexpected section [$section]"
            }
            if ($map.ContainsKey($section)) { throw "SecurityTemplate artifact contains duplicate section [$section]" }
            $map[$section] = @{}
            continue
        }
        if (-not $section -or $text -notmatch '^([^=]+?)\s*=\s*(.*)$') {
            throw 'SecurityTemplate artifact contains an entry outside a section or a malformed entry'
        }
        $name = $Matches[1].Trim()
        $value = $Matches[2].Trim()
        if (-not $name -or $map[$section].ContainsKey($name)) {
            throw "SecurityTemplate artifact contains duplicate or empty [$section] entry"
        }
        $map[$section][$name] = $value
    }

    $targetsPath = Join-Path $PSScriptRoot '../ParsedSettings/SecurityTemplates.json'
    $targets = Get-Content -LiteralPath $targetsPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    foreach ($sectionName in @('System Access', 'Privilege Rights')) {
        if (-not $map.ContainsKey($sectionName)) { throw "SecurityTemplate artifact is missing required section [$sectionName]" }
        $expectedNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($group in $targets.PSObject.Properties) {
            $sectionProperty = $group.Value.PSObject.Properties[$sectionName]
            if ($null -eq $sectionProperty) { continue }
            foreach ($name in $sectionProperty.Value.PSObject.Properties.Name) { $null = $expectedNames.Add([string]$name) }
        }
        # With account lockout off (LockoutBadCount = 0) Windows reports no
        # lockout duration, reset counter or administrator-lockout switch, so
        # a backup taken in that state legitimately lacks exactly those three.
        $absentAllowed = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        if ($sectionName -eq 'System Access' -and
            $map[$sectionName].ContainsKey('LockoutBadCount') -and
            [string]$map[$sectionName]['LockoutBadCount'] -ceq '0') {
            foreach ($name in @('LockoutDuration', 'ResetLockoutCount', 'AllowAdministratorLockout')) {
                if (-not $map[$sectionName].ContainsKey($name)) { $null = $absentAllowed.Add($name) }
            }
        }
        if ($expectedNames.Count -eq 0 -or $map[$sectionName].Count -ne ($expectedNames.Count - $absentAllowed.Count)) {
            throw "SecurityTemplate artifact [$sectionName] target count differs from the canonical inventory"
        }
        foreach ($name in $expectedNames) {
            if (-not $map[$sectionName].ContainsKey($name) -and -not $absentAllowed.Contains($name)) {
                throw "SecurityTemplate artifact is missing canonical [$sectionName] $name"
            }
        }
    }
    return $map
}
