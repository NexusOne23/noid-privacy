<#
.SYNOPSIS
    Parse Microsoft Security Baseline GPO files to JSON (DEVELOPER TOOL ONLY)
    
.DESCRIPTION
    **NOTE: This is a DEVELOPER/MAINTENANCE tool - NOT needed for production use!**
    
    The parsed JSON files are already included in Modules/SecurityBaseline/ParsedSettings/.
    This tool is only used during development to update those JSON files when Microsoft
    releases new Security Baselines.
    
    Parses GPO backups from Microsoft Security Baseline:
    - Registry.pol (Computer + User)
    - GptTmpl.inf (Security Template)
    - audit.csv (Audit Policies)
    
    Outputs structured JSON files for each category.
    
.PARAMETER BaselinePath
    Path to Microsoft Security Baseline folder (download separately from Microsoft)
    Download: https://www.microsoft.com/en-us/download/details.aspx?id=55319
    
.PARAMETER OutputPath
    Path where JSON output files will be saved
    
.NOTES
    Author: NexusOne23
    Version: 2.2.3
    Requires: PowerShell 5.1+
    
.EXAMPLE
    .\Parse-SecurityBaseline.ps1
    Parse baseline and output to default location
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaselinePath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\Modules\SecurityBaseline\ParsedSettings")
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
    
    if (-not (Test-Path $Path)) {
        Write-Warning "Registry.pol not found: $Path"
        return @()
    }
    
    try {
        $entries = @()
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        
        # Check signature (PReg)
        $signature = [System.Text.Encoding]::ASCII.GetString($bytes[0..3])
        if ($signature -ne 'PReg') {
            Write-Warning "Invalid Registry.pol signature: $signature"
            return @()
        }
        
        # Check version
        $version = [BitConverter]::ToInt32($bytes, 4)
        if ($version -ne 1) {
            Write-Warning "Unsupported Registry.pol version: $version"
            return @()
        }
        
        $index = 8  # Start after signature and version
        
        while ($index -lt $bytes.Length) {
            # Read entry: [KeyName;ValueName;Type;Size;Data]
            
            # Read KeyName (Unicode null-terminated string)
            $keyNameBytes = @()
            while ($index -lt ($bytes.Length - 1)) {
                $b1 = $bytes[$index]
                $b2 = $bytes[$index + 1]
                $index += 2
                
                if ($b1 -eq 0 -and $b2 -eq 0) {
                    break
                }
                
                $keyNameBytes += $b1, $b2
            }
            
            $keyName = [System.Text.Encoding]::Unicode.GetString($keyNameBytes)
            
            # Skip semicolon
            $index += 2
            
            # Read ValueName (Unicode null-terminated string)
            $valueNameBytes = @()
            while ($index -lt ($bytes.Length - 1)) {
                $b1 = $bytes[$index]
                $b2 = $bytes[$index + 1]
                $index += 2
                
                if ($b1 -eq 0 -and $b2 -eq 0) {
                    break
                }
                
                $valueNameBytes += $b1, $b2
            }
            
            $valueName = [System.Text.Encoding]::Unicode.GetString($valueNameBytes)
            
            # Skip semicolon
            $index += 2
            
            # Read Type (DWORD - 4 bytes)
            if ($index + 4 -gt $bytes.Length) { break }
            $type = [BitConverter]::ToInt32($bytes, $index)
            $index += 4
            
            # Skip semicolon
            $index += 2
            
            # Read Size (DWORD - 4 bytes)
            if ($index + 4 -gt $bytes.Length) { break }
            $size = [BitConverter]::ToInt32($bytes, $index)
            $index += 4
            
            # Skip semicolon
            $index += 2
            
            # Read Data
            $data = $null
            if ($size -gt 0 -and ($index + $size) -le $bytes.Length) {
                $dataBytes = $bytes[$index..($index + $size - 1)]
                
                # Parse based on type
                switch ($type) {
                    1 {
                        # REG_SZ (String)
                        $data = [System.Text.Encoding]::Unicode.GetString($dataBytes).TrimEnd([char]0)
                    }
                    2 {
                        # REG_EXPAND_SZ
                        $data = [System.Text.Encoding]::Unicode.GetString($dataBytes).TrimEnd([char]0)
                    }
                    3 {
                        # REG_BINARY
                        $data = $dataBytes
                    }
                    4 {
                        # REG_DWORD
                        if ($dataBytes.Length -ge 4) {
                            $data = [BitConverter]::ToInt32($dataBytes, 0)
                        }
                    }
                    7 {
                        # REG_MULTI_SZ
                        $data = [System.Text.Encoding]::Unicode.GetString($dataBytes).TrimEnd([char]0) -split '\x00'
                    }
                    default {
                        $data = $dataBytes
                    }
                }
                
                $index += $size
            }
            
            # Skip closing bracket
            $index += 2
            
            # Add entry
            $entries += [PSCustomObject]@{
                KeyName   = $keyName
                ValueName = $valueName
                Type      = switch ($type) {
                    1 { "REG_SZ" }
                    2 { "REG_EXPAND_SZ" }
                    3 { "REG_BINARY" }
                    4 { "REG_DWORD" }
                    7 { "REG_MULTI_SZ" }
                    11 { "REG_QWORD" }
                    default { "Unknown($type)" }
                }
                Data      = $data
            }
        }
        
        return $entries
    }
    catch {
        Write-Error "Failed to parse Registry.pol: $Path - $_"
        return @()
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
    
    if (-not (Test-Path $Path)) {
        Write-Warning "GptTmpl.inf not found: $Path"
        return @{}
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
        Write-Error "Failed to parse GptTmpl.inf: $Path - $_"
        return @{}
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
    
    if (-not (Test-Path $Path)) {
        Write-Warning "audit.csv not found: $Path"
        return @()
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
        Write-Error "Failed to parse audit.csv: $Path - $_"
        return @()
    }
}

#endregion

#region Main Processing

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "MS Security Baseline Parser - Windows 11 25H2" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Validate paths
if (-not (Test-Path $BaselinePath)) {
    Write-Error "Baseline path not found: $BaselinePath"
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# GPO mapping
$gpoMapping = @{
    "{02DB0E53-0925-4E5A-B775-E7A1A9370AB8}" = "MSFT Windows 11 25H2 - Computer"
    "{D233D0A9-D74E-4AEE-9B89-2398C7AD1DDE}" = "MSFT Windows 11 25H2 - User"
    "{E2D5B48E-8BB0-4ACC-AEB6-8DD82FDD825F}" = "MSFT Windows 11 25H2 - BitLocker"
    "{FC357767-040F-49C3-965E-B071D17C29A0}" = "MSFT Windows 11 25H2 - Credential Guard"
    "{D42CD0A5-F321-4CB1-ADA9-03A0F0A6E3B2}" = "MSFT Windows 11 25H2 - Defender Antivirus"
    "{666ED8AB-DF4A-45CE-9666-61F802515051}" = "MSFT Windows 11 25H2 - Domain Security"
    "{1879C2DC-00C6-4692-B167-15B9366DF5D4}" = "MSFT Internet Explorer 11 - Computer"
    "{56977988-BEEC-4E61-B649-731EC7AB997B}" = "MSFT Internet Explorer 11 - User"
}

$gpoPath = Join-Path $BaselinePath "GPOs"

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
    
    if (-not (Test-Path $gpoFolder)) {
        Write-Warning "GPO folder not found: $guid"
        continue
    }
    
    Write-Host "Processing: $gpoName" -ForegroundColor Yellow
    Write-Host "  GUID: $guid" -ForegroundColor Gray
    
    # Parse Computer Registry.pol
    $computerPolPath = Join-Path $gpoFolder "DomainSysvol\GPO\Machine\registry.pol"
    if (Test-Path $computerPolPath) {
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
    if (Test-Path $userPolPath) {
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
    if (Test-Path $gptTmplPath) {
        Write-Host "  [*] Parsing GptTmpl.inf..." -ForegroundColor Gray
        $template = Read-GptTmplInf -Path $gptTmplPath
        
        $settingCount = ($template.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        
        $allSettings.SecurityTemplates[$gpoName] = $template
        
        Write-Host "    Found $settingCount settings in $($template.Count) sections" -ForegroundColor Green
        $allSettings.Summary.TotalSecuritySettings += $settingCount
    }
    
    # Parse audit.csv (Advanced Audit Policies)
    $auditCsvPath = Join-Path $gpoFolder "DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv"
    if (Test-Path $auditCsvPath) {
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

# Save outputs
Write-Host "Saving parsed settings..." -ForegroundColor Cyan

$computerRegPath = Join-Path $OutputPath "Computer-RegistryPolicies.json"
$allSettings.RegistryPolicies.Computer | ConvertTo-Json -Depth 10 | Set-Content -Path $computerRegPath -Encoding UTF8 | Out-Null
Write-Host "[OK] Computer Registry Policies: $computerRegPath" -ForegroundColor Green

$userRegPath = Join-Path $OutputPath "User-RegistryPolicies.json"
$allSettings.RegistryPolicies.User | ConvertTo-Json -Depth 10 | Set-Content -Path $userRegPath -Encoding UTF8 | Out-Null
Write-Host "[OK] User Registry Policies: $userRegPath" -ForegroundColor Green

$securityPath = Join-Path $OutputPath "SecurityTemplates.json"
$allSettings.SecurityTemplates | ConvertTo-Json -Depth 10 | Set-Content -Path $securityPath -Encoding UTF8 | Out-Null
Write-Host "[OK] Security Templates: $securityPath" -ForegroundColor Green

$auditPath = Join-Path $OutputPath "AuditPolicies.json"
$allSettings.AuditPolicies | ConvertTo-Json -Depth 10 | Set-Content -Path $auditPath -Encoding UTF8 | Out-Null
Write-Host "[OK] Audit Policies: $auditPath" -ForegroundColor Green

$summaryPath = Join-Path $OutputPath "Summary.json"
$allSettings.Summary | ConvertTo-Json -Depth 10 | Set-Content -Path $summaryPath -Encoding UTF8 | Out-Null
Write-Host "[OK] Summary: $summaryPath" -ForegroundColor Green

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
Write-Host "Output location: $OutputPath" -ForegroundColor Cyan
Write-Host ""

#endregion
