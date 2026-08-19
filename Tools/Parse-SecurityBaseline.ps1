<#
.SYNOPSIS
    Parse Microsoft Security Baseline GPO files to JSON (DEVELOPER TOOL ONLY)

.DESCRIPTION
    **NOTE: This is a DEVELOPER/MAINTENANCE tool - NOT needed for production use!**

    The runtime JSON files are already included in Modules/SecurityBaseline/ParsedSettings/.
    This tool emits raw Microsoft source data to a separate empty staging path.
    Direct output to the runtime profile is prohibited because NoID Privacy has a
    documented product deviation and a different executable-count summary.

    Parses GPO backups from Microsoft Security Baseline:
    - Registry.pol (Computer + User)
    - GptTmpl.inf (Security Template)
    - audit.csv (Audit Policies)

    Outputs structured JSON files for each category.

.PARAMETER BaselinePath
    Path to Microsoft Security Baseline folder (download separately from Microsoft)
    Download: https://www.microsoft.com/en-us/download/details.aspx?id=55319

.PARAMETER OutputPath
    New or empty staging directory where raw source JSON files will be saved.
    The runtime ParsedSettings directory is rejected.

.NOTES
    Author: NexusOne23
    Version: 2.2.5
    Requires: PowerShell 5.1+

.EXAMPLE
    .\Parse-SecurityBaseline.ps1 -BaselinePath 'C:\Baseline\Windows 11 v25H2 Security Baseline' -OutputPath 'C:\Baseline\Parsed-Source'
    Parse the exact 25H2 source package into a separate staging directory.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaselinePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

#region Helper Functions

function Read-PolFile {
    <#
    .SYNOPSIS
        Parse binary Registry.pol file

    .DESCRIPTION
        Based on Microsoft GPRegistryPolicyParser format
        Registry.pol binary format:
        - Signature: PReg (4 bytes)
        - Version: 1 (4 bytes)
        - Entries: [KeyName;ValueName;Type;Size;Data]
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Registry.pol not found: $Path"
    }

    try {
        $entries = [System.Collections.Generic.List[object]]::new()
        $bytes = [System.IO.File]::ReadAllBytes($Path)

        if ($bytes.Length -lt 8) {
            throw 'Registry.pol is shorter than its mandatory header'
        }

        # Check signature (PReg)
        $signature = [System.Text.Encoding]::ASCII.GetString($bytes[0..3])
        if ($signature -ne 'PReg') {
            throw "Invalid Registry.pol signature: $signature"
        }

        # Check version
        $version = [BitConverter]::ToInt32($bytes, 4)
        if ($version -ne 1) {
            throw "Unsupported Registry.pol version: $version"
        }

        $index = 8  # Start after signature and version

        while ($index -lt $bytes.Length) {
            # Read entry: [KeyName;ValueName;Type;Size;Data]

            # Read KeyName (Unicode null-terminated string). The leading '[' is
            # intentionally retained because the checked-in 25H2 artifacts use
            # the native Registry.pol key representation.
            $keyNameBytes = [System.Collections.Generic.List[byte]]::new()
            $keyTerminated = $false
            while ($index -lt ($bytes.Length - 1)) {
                $b1 = $bytes[$index]
                $b2 = $bytes[$index + 1]
                $index += 2

                if ($b1 -eq 0 -and $b2 -eq 0) {
                    $keyTerminated = $true
                    break
                }

                $keyNameBytes.Add($b1)
                $keyNameBytes.Add($b2)
            }

            if (-not $keyTerminated) { throw "Unterminated key name at byte $index" }

            $keyName = [System.Text.Encoding]::Unicode.GetString($keyNameBytes.ToArray())

            # Require semicolon
            if ($index + 2 -gt $bytes.Length -or $bytes[$index] -ne 0x3B -or $bytes[$index + 1] -ne 0) {
                throw "Missing key/value delimiter at byte $index"
            }
            $index += 2

            # Read ValueName (Unicode null-terminated string)
            $valueNameBytes = [System.Collections.Generic.List[byte]]::new()
            $valueTerminated = $false
            while ($index -lt ($bytes.Length - 1)) {
                $b1 = $bytes[$index]
                $b2 = $bytes[$index + 1]
                $index += 2

                if ($b1 -eq 0 -and $b2 -eq 0) {
                    $valueTerminated = $true
                    break
                }

                $valueNameBytes.Add($b1)
                $valueNameBytes.Add($b2)
            }

            if (-not $valueTerminated) { throw "Unterminated value name at byte $index" }

            $valueName = [System.Text.Encoding]::Unicode.GetString($valueNameBytes.ToArray())

            # Require semicolon
            if ($index + 2 -gt $bytes.Length -or $bytes[$index] -ne 0x3B -or $bytes[$index + 1] -ne 0) {
                throw "Missing value/type delimiter at byte $index"
            }
            $index += 2

            # Read Type (DWORD - 4 bytes)
            if ($index + 4 -gt $bytes.Length) { throw "Truncated registry type at byte $index" }
            $type = [BitConverter]::ToInt32($bytes, $index)
            $index += 4

            # Require semicolon
            if ($index + 2 -gt $bytes.Length -or $bytes[$index] -ne 0x3B -or $bytes[$index + 1] -ne 0) {
                throw "Missing type/size delimiter at byte $index"
            }
            $index += 2

            # Read Size (DWORD - 4 bytes)
            if ($index + 4 -gt $bytes.Length) { throw "Truncated registry size at byte $index" }
            $size = [BitConverter]::ToInt32($bytes, $index)
            $index += 4

            if ($size -lt 0) { throw "Negative registry data size at byte $index" }

            # Require semicolon
            if ($index + 2 -gt $bytes.Length -or $bytes[$index] -ne 0x3B -or $bytes[$index + 1] -ne 0) {
                throw "Missing size/data delimiter at byte $index"
            }
            $index += 2

            # Read Data
            $data = $null
            if (($index + $size) -gt $bytes.Length) {
                throw "Registry data overruns the file at byte $index"
            }
            $dataBytes = if ($size -gt 0) { [byte[]]$bytes[$index..($index + $size - 1)] } else { [byte[]]@() }
            if ($size -gt 0) {

                # Parse based on type
                switch ($type) {
                    1 {
                        # REG_SZ (String)
                        if (($size % 2) -ne 0) { throw 'REG_SZ data has an odd byte count' }
                        $data = [System.Text.Encoding]::Unicode.GetString($dataBytes).TrimEnd([char]0)
                    }
                    2 {
                        # REG_EXPAND_SZ
                        if (($size % 2) -ne 0) { throw 'REG_EXPAND_SZ data has an odd byte count' }
                        $data = [System.Text.Encoding]::Unicode.GetString($dataBytes).TrimEnd([char]0)
                    }
                    3 {
                        # REG_BINARY
                        $data = $dataBytes
                    }
                    4 {
                        if ($dataBytes.Length -ne 4) { throw 'REG_DWORD data is not exactly four bytes' }
                        $data = [BitConverter]::ToInt32($dataBytes, 0)
                    }
                    7 {
                        # REG_MULTI_SZ
                        if (($size % 2) -ne 0) { throw 'REG_MULTI_SZ data has an odd byte count' }
                        $data = [System.Text.Encoding]::Unicode.GetString($dataBytes).TrimEnd([char]0) -split '\x00'
                    }
                    11 {
                        if ($dataBytes.Length -ne 8) { throw 'REG_QWORD data is not exactly eight bytes' }
                        $data = [BitConverter]::ToInt64($dataBytes, 0)
                    }
                    default {
                        throw "Unsupported Registry.pol value type: $type"
                    }
                }
            }
            $index += $size

            # Require closing bracket
            if ($index + 2 -gt $bytes.Length -or $bytes[$index] -ne 0x5D -or $bytes[$index + 1] -ne 0) {
                throw "Missing closing entry bracket at byte $index"
            }
            $index += 2

            # Add entry
            $entries.Add([PSCustomObject]@{
                KeyName   = $keyName
                ValueName = $valueName
                Type      = switch ($type) {
                    1 { "REG_SZ" }
                    2 { "REG_EXPAND_SZ" }
                    3 { "REG_BINARY" }
                    4 { "REG_DWORD" }
                    7 { "REG_MULTI_SZ" }
                    11 { "REG_QWORD" }
                    default { throw "Unsupported Registry.pol value type: $type" }
                }
                Data      = $data
            })
        }

        return $entries.ToArray()
    }
    catch {
        throw "Failed to parse Registry.pol '$Path': $($_.Exception.Message)"
    }
}

function Read-GptTmplInf {
    <#
    .SYNOPSIS
        Parse GptTmpl.inf security template file
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "GptTmpl.inf not found: $Path"
    }

    try {
        $content = Get-Content -Path $Path -Encoding Unicode
        $settings = @{}
        $currentSection = ""

        foreach ($line in $content) {
            $line = $line.Trim()

            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith(';')) {
                continue
            }

            # Section header
            if ($line -match '^\[(.+)\]$') {
                $currentSection = $matches[1]
                $settings[$currentSection] = @{}
                continue
            }

            # Key = Value (normal format)
            if ($line -match '^(.+?)\s*=\s*(.*)$' -and $currentSection) {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()

                $settings[$currentSection][$key] = $value
                continue
            }

            # Service format: "ServiceName",StartupType,"SecurityDescriptor"
            # Example: "XboxGipSvc",4,""
            if ($line -match '^"(.+?)",(\d+),(.*)$' -and $currentSection) {
                $serviceName = $matches[1]
                $startupType = $matches[2]
                # Note: $matches[3] contains SecurityDescriptor (not used currently)

                # Service startup type mapping:
                # 2 = Automatic, 3 = Manual, 4 = Disabled
                $startupTypeName = switch ($startupType) {
                    "2" { "Automatic" }
                    "3" { "Manual" }
                    "4" { "Disabled" }
                    default { $startupType }
                }

                $settings[$currentSection][$serviceName] = "StartupType=$startupTypeName"
            }
        }

        return $settings
    }
    catch {
        throw "Failed to parse GptTmpl.inf '$Path': $($_.Exception.Message)"
    }
}

function Read-AuditCsv {
    <#
    .SYNOPSIS
        Parse audit.csv advanced audit policy file
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "audit.csv not found: $Path"
    }

    try {
        $csv = Import-Csv -Path $Path -Header "Machine Name", "Policy Target", "Subcategory", "Subcategory GUID", "Inclusion Setting", "Exclusion Setting", "Setting Value"

        # Skip header row
        $policies = $csv | Select-Object -Skip 1 | ForEach-Object {
            [PSCustomObject]@{
                Subcategory      = $_.'Subcategory'
                SubcategoryGUID  = $_.'Subcategory GUID'
                InclusionSetting = $_.'Inclusion Setting'
                SettingValue     = $_.'Setting Value'
            }
        }

        return $policies
    }
    catch {
        throw "Failed to parse audit.csv '$Path': $($_.Exception.Message)"
    }
}

#endregion

#region Main Processing

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "MS Security Baseline Parser - Windows 11 25H2" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Validate paths
if (-not (Test-Path -LiteralPath $BaselinePath -PathType Container)) {
    throw "Baseline path not found: $BaselinePath"
}

$outputFullPath = [System.IO.Path]::GetFullPath($OutputPath)
$runtimeProfilePath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Modules\SecurityBaseline\ParsedSettings'))
if ([string]::Equals($outputFullPath, $runtimeProfilePath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to overwrite the runtime ParsedSettings profile; parse raw Microsoft source to a separate staging directory'
}
if (Test-Path -LiteralPath $outputFullPath -PathType Leaf) {
    throw "OutputPath is a file, not a directory: $outputFullPath"
}
if ((Test-Path -LiteralPath $outputFullPath -PathType Container) -and
    @(Get-ChildItem -LiteralPath $outputFullPath -Force -ErrorAction Stop).Count -gt 0) {
    throw "OutputPath must be new or empty: $outputFullPath"
}

# GPO mapping
$gpoMapping = [ordered]@{
    "{02DB0E53-0925-4E5A-B775-E7A1A9370AB8}" = "MSFT Windows 11 25H2 - Computer"
    "{D233D0A9-D74E-4AEE-9B89-2398C7AD1DDE}" = "MSFT Windows 11 25H2 - User"
    "{E2D5B48E-8BB0-4ACC-AEB6-8DD82FDD825F}" = "MSFT Windows 11 25H2 - BitLocker"
    "{FC357767-040F-49C3-965E-B071D17C29A0}" = "MSFT Windows 11 25H2 - Credential Guard"
    "{D42CD0A5-F321-4CB1-ADA9-03A0F0A6E3B2}" = "MSFT Windows 11 25H2 - Defender Antivirus"
    "{666ED8AB-DF4A-45CE-9666-61F802515051}" = "MSFT Windows 11 25H2 - Domain Security"
    "{1879C2DC-00C6-4692-B167-15B9366DF5D4}" = "MSFT Internet Explorer 11 - Computer"
    "{56977988-BEEC-4E61-B649-731EC7AB997B}" = "MSFT Internet Explorer 11 - User"
}

# The 25H2 package has a deliberately sparse artifact layout. Treat both a
# missing expected artifact and an unexpected new one as a source-version
# mismatch instead of silently emitting a partial or mixed-version profile.
$expectedArtifacts = [ordered]@{
    ComputerRegistry = @(
        '{02DB0E53-0925-4E5A-B775-E7A1A9370AB8}'
        '{E2D5B48E-8BB0-4ACC-AEB6-8DD82FDD825F}'
        '{FC357767-040F-49C3-965E-B071D17C29A0}'
        '{D42CD0A5-F321-4CB1-ADA9-03A0F0A6E3B2}'
        '{1879C2DC-00C6-4692-B167-15B9366DF5D4}'
    )
    UserRegistry = @(
        '{D233D0A9-D74E-4AEE-9B89-2398C7AD1DDE}'
        '{56977988-BEEC-4E61-B649-731EC7AB997B}'
    )
    SecurityTemplate = @(
        '{02DB0E53-0925-4E5A-B775-E7A1A9370AB8}'
        '{E2D5B48E-8BB0-4ACC-AEB6-8DD82FDD825F}'
        '{666ED8AB-DF4A-45CE-9666-61F802515051}'
        '{1879C2DC-00C6-4692-B167-15B9366DF5D4}'
    )
    Audit = @('{02DB0E53-0925-4E5A-B775-E7A1A9370AB8}')
}

$gpoPath = Join-Path $BaselinePath "GPOs"
if (-not (Test-Path -LiteralPath $gpoPath -PathType Container)) {
    throw "GPO directory not found: $gpoPath"
}
$actualGpoFolders = @(Get-ChildItem -LiteralPath $gpoPath -Directory -ErrorAction Stop |
        Where-Object { $_.Name -match '^\{[0-9A-Fa-f-]{36}\}$' } |
        ForEach-Object { $_.Name.ToUpperInvariant() })
$expectedGpoFolders = @($gpoMapping.Keys | ForEach-Object { $_.ToUpperInvariant() })
$missingGpos = @($expectedGpoFolders | Where-Object { $_ -notin $actualGpoFolders })
$unexpectedGpos = @($actualGpoFolders | Where-Object { $_ -notin $expectedGpoFolders })
if ($missingGpos.Count -gt 0 -or $unexpectedGpos.Count -gt 0) {
    throw "25H2 GPO inventory mismatch. Missing=[$($missingGpos -join ', ')]; Unexpected=[$($unexpectedGpos -join ', ')]"
}

$allSettings = @{
    RegistryPolicies  = @{
        Computer = @()
        User     = @()
    }
    SecurityTemplates = @{}
    AuditPolicies     = @()
    Summary           = @{
        TotalRegistrySettings = 0
        TotalSecuritySettings = 0
        TotalAuditPolicies    = 0
        TotalSettings         = 0
    }
}

# Process each GPO
foreach ($guid in $gpoMapping.Keys) {
    $gpoName = $gpoMapping[$guid]
    $gpoFolder = Join-Path $gpoPath $guid

    if (-not (Test-Path -LiteralPath $gpoFolder -PathType Container)) {
        throw "GPO folder not found: $guid"
    }

    Write-Host "Processing: $gpoName" -ForegroundColor Yellow
    Write-Host "  GUID: $guid" -ForegroundColor Gray

    # Parse Computer Registry.pol
    $computerPolPath = Join-Path $gpoFolder "DomainSysvol\GPO\Machine\registry.pol"
    $computerPolExpected = $guid -in $expectedArtifacts.ComputerRegistry
    if ((Test-Path -LiteralPath $computerPolPath -PathType Leaf) -ne $computerPolExpected) {
        throw "Computer Registry.pol presence mismatch for $gpoName"
    }
    if ($computerPolExpected) {
        Write-Host "  [*] Parsing Computer registry.pol..." -ForegroundColor Gray
        $entries = Read-PolFile -Path $computerPolPath

        foreach ($entry in $entries) {
            $allSettings.RegistryPolicies.Computer += [PSCustomObject]@{
                GPO       = $gpoName
                KeyName   = $entry.KeyName
                ValueName = $entry.ValueName
                Type      = $entry.Type
                Data      = $entry.Data
            }
        }

        Write-Host "    Found $($entries.Count) settings" -ForegroundColor Green
        $allSettings.Summary.TotalRegistrySettings += $entries.Count
    }

    # Parse User Registry.pol
    $userPolPath = Join-Path $gpoFolder "DomainSysvol\GPO\User\registry.pol"
    $userPolExpected = $guid -in $expectedArtifacts.UserRegistry
    if ((Test-Path -LiteralPath $userPolPath -PathType Leaf) -ne $userPolExpected) {
        throw "User Registry.pol presence mismatch for $gpoName"
    }
    if ($userPolExpected) {
        Write-Host "  [*] Parsing User registry.pol..." -ForegroundColor Gray
        $entries = Read-PolFile -Path $userPolPath

        foreach ($entry in $entries) {
            $allSettings.RegistryPolicies.User += [PSCustomObject]@{
                GPO       = $gpoName
                KeyName   = $entry.KeyName
                ValueName = $entry.ValueName
                Type      = $entry.Type
                Data      = $entry.Data
            }
        }

        Write-Host "    Found $($entries.Count) settings" -ForegroundColor Green
        $allSettings.Summary.TotalRegistrySettings += $entries.Count
    }

    # Parse GptTmpl.inf (Security Template)
    $gptTmplPath = Join-Path $gpoFolder "DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
    $securityTemplateExpected = $guid -in $expectedArtifacts.SecurityTemplate
    if ((Test-Path -LiteralPath $gptTmplPath -PathType Leaf) -ne $securityTemplateExpected) {
        throw "GptTmpl.inf presence mismatch for $gpoName"
    }
    if ($securityTemplateExpected) {
        Write-Host "  [*] Parsing GptTmpl.inf..." -ForegroundColor Gray
        $template = Read-GptTmplInf -Path $gptTmplPath

        $settingCount = ($template.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum

        $allSettings.SecurityTemplates[$gpoName] = $template

        Write-Host "    Found $settingCount settings in $($template.Count) sections" -ForegroundColor Green
        $allSettings.Summary.TotalSecuritySettings += $settingCount
    }

    # Parse audit.csv (Advanced Audit Policies)
    $auditCsvPath = Join-Path $gpoFolder "DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv"
    $auditExpected = $guid -in $expectedArtifacts.Audit
    if ((Test-Path -LiteralPath $auditCsvPath -PathType Leaf) -ne $auditExpected) {
        throw "audit.csv presence mismatch for $gpoName"
    }
    if ($auditExpected) {
        Write-Host "  [*] Parsing audit.csv..." -ForegroundColor Gray
        $policies = Read-AuditCsv -Path $auditCsvPath

        foreach ($policy in $policies) {
            $allSettings.AuditPolicies += [PSCustomObject]@{
                GPO              = $gpoName
                Subcategory      = $policy.Subcategory
                SubcategoryGUID  = $policy.SubcategoryGUID
                InclusionSetting = $policy.InclusionSetting
                SettingValue     = $policy.SettingValue
            }
        }

        Write-Host "    Found $($policies.Count) audit policies" -ForegroundColor Green
        $allSettings.Summary.TotalAuditPolicies += $policies.Count
    }

    Write-Host ""
}

# Calculate total
$allSettings.Summary.TotalSettings = $allSettings.Summary.TotalRegistrySettings +
$allSettings.Summary.TotalSecuritySettings +
$allSettings.Summary.TotalAuditPolicies

$expectedCounts = [ordered]@{
    ComputerRegistry = 330
    UserRegistry     = 5
    RegistryTotal   = 335
    Security         = 79
    Audit            = 23
    Total            = 437
}
if ($allSettings.RegistryPolicies.Computer.Count -ne $expectedCounts.ComputerRegistry -or
    $allSettings.RegistryPolicies.User.Count -ne $expectedCounts.UserRegistry -or
    $allSettings.Summary.TotalRegistrySettings -ne $expectedCounts.RegistryTotal -or
    $allSettings.Summary.TotalSecuritySettings -ne $expectedCounts.Security -or
    $allSettings.Summary.TotalAuditPolicies -ne $expectedCounts.Audit -or
    $allSettings.Summary.TotalSettings -ne $expectedCounts.Total) {
    throw ('25H2 source count mismatch: ComputerRegistry={0}, UserRegistry={1}, RegistryTotal={2}, Security={3}, Audit={4}, Total={5}' -f
        $allSettings.RegistryPolicies.Computer.Count,
        $allSettings.RegistryPolicies.User.Count,
        $allSettings.Summary.TotalRegistrySettings,
        $allSettings.Summary.TotalSecuritySettings,
        $allSettings.Summary.TotalAuditPolicies,
        $allSettings.Summary.TotalSettings)
}

# Save outputs via .NET WriteAllText (UTF-8 NO-BOM for cross-tool compatibility -- PS 5.1's
# `Set-Content -Encoding UTF8` writes a leading EF BB BF that confuses Python json / jq /
# Node JSON.parse / utf-8-strict parsers. PowerShell's ConvertFrom-Json tolerates BOM but
# emitting NO-BOM is the canonical convention for JSON-on-disk).
Write-Host "Saving parsed settings transactionally..." -ForegroundColor Cyan
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$outputParent = Split-Path $outputFullPath -Parent
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    $null = New-Item -Path $outputParent -ItemType Directory -Force -ErrorAction Stop
}
$stagingPath = "$outputFullPath.NoIDStaging_$([Guid]::NewGuid().ToString('N'))"
try {
    $null = New-Item -Path $stagingPath -ItemType Directory -ErrorAction Stop
    $outputDocuments = [ordered]@{
        'Computer-RegistryPolicies.json' = ($allSettings.RegistryPolicies.Computer | ConvertTo-Json -Depth 10)
        'User-RegistryPolicies.json'     = ($allSettings.RegistryPolicies.User | ConvertTo-Json -Depth 10)
        'SecurityTemplates.json'         = ($allSettings.SecurityTemplates | ConvertTo-Json -Depth 10)
        'AuditPolicies.json'             = ($allSettings.AuditPolicies | ConvertTo-Json -Depth 10)
        'Summary.json'                   = ($allSettings.Summary | ConvertTo-Json -Depth 10)
    }
    foreach ($document in $outputDocuments.GetEnumerator()) {
        $path = Join-Path $stagingPath $document.Key
        [System.IO.File]::WriteAllText($path, [string]$document.Value, $utf8NoBom)
        $null = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    $stagedFiles = @(Get-ChildItem -LiteralPath $stagingPath -File -Force -ErrorAction Stop)
    if ($stagedFiles.Count -ne $outputDocuments.Count) {
        throw "Staged output count mismatch: expected $($outputDocuments.Count), got $($stagedFiles.Count)"
    }
    if (Test-Path -LiteralPath $outputFullPath -PathType Container) {
        Remove-Item -LiteralPath $outputFullPath -Force -ErrorAction Stop
    }
    Move-Item -LiteralPath $stagingPath -Destination $outputFullPath -ErrorAction Stop
}
catch {
    $writeFailure = $_
    if (Test-Path -LiteralPath $stagingPath) {
        try {
            Remove-Item -LiteralPath $stagingPath -Recurse -Force -ErrorAction Stop
        }
        catch {
            throw "Baseline output failed: $($writeFailure.Exception.Message); staging cleanup also failed: $($_.Exception.Message)"
        }
    }
    throw $writeFailure
}

Write-Host "[OK] Computer Registry Policies: $(Join-Path $outputFullPath 'Computer-RegistryPolicies.json')" -ForegroundColor Green
Write-Host "[OK] User Registry Policies: $(Join-Path $outputFullPath 'User-RegistryPolicies.json')" -ForegroundColor Green
Write-Host "[OK] Security Templates: $(Join-Path $outputFullPath 'SecurityTemplates.json')" -ForegroundColor Green
Write-Host "[OK] Audit Policies: $(Join-Path $outputFullPath 'AuditPolicies.json')" -ForegroundColor Green
Write-Host "[OK] Summary: $(Join-Path $outputFullPath 'Summary.json')" -ForegroundColor Green

# Display summary
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "PARSING COMPLETE" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Total Registry Settings: $($allSettings.Summary.TotalRegistrySettings)" -ForegroundColor White
Write-Host "  - Computer:            $($allSettings.RegistryPolicies.Computer.Count)" -ForegroundColor Gray
Write-Host "  - User:                $($allSettings.RegistryPolicies.User.Count)" -ForegroundColor Gray
Write-Host "Total Security Settings: $($allSettings.Summary.TotalSecuritySettings)" -ForegroundColor White
Write-Host "Total Audit Policies:    $($allSettings.Summary.TotalAuditPolicies)" -ForegroundColor White
Write-Host ""
Write-Host "GRAND TOTAL:             $($allSettings.Summary.TotalSettings) SETTINGS" -ForegroundColor Green
Write-Host ""
Write-Host "Output location: $outputFullPath" -ForegroundColor Cyan
Write-Host ""

#endregion
