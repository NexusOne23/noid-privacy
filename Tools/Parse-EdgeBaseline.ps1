<#
.SYNOPSIS
    Parse Microsoft Edge Security Baseline GPO files to JSON (DEVELOPER TOOL ONLY)
    
.DESCRIPTION
    **NOTE: This is a DEVELOPER/MAINTENANCE tool - NOT needed for production use!**
    
    Parses GPO backups from Microsoft Edge Security Baseline:
    - Registry.pol (Computer policies for Microsoft Edge)
    
    Outputs structured JSON files for Edge hardening settings.
    
.PARAMETER BaselinePath
    Path to Microsoft Edge Security Baseline folder
    
.PARAMETER OutputPath
    Path where JSON output files will be saved
    
.NOTES
    Author: NexusOne23
    Version: 2.2.3
    Requires: PowerShell 5.1+
    
.EXAMPLE
    .\Parse-EdgeBaseline.ps1 -BaselinePath "C:\Edge Baseline" -OutputPath ".\Modules\EdgeHardening\ParsedSettings"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaselinePath,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\Modules\EdgeHardening\ParsedSettings")
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

#endregion

#region Main Parsing Logic

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Microsoft Edge Security Baseline Parser" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Validate baseline path
if (-not (Test-Path $BaselinePath)) {
    Write-Error "Baseline path not found: $BaselinePath"
    exit 1
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
}

# Find GPO folder (should be only one GPO in Edge Baseline)
$gpoFolders = Get-ChildItem -Path (Join-Path $BaselinePath "GPOs") -Directory

if ($gpoFolders.Count -eq 0) {
    Write-Error "No GPO folders found in $BaselinePath\GPOs"
    exit 1
}

Write-Host "Found $($gpoFolders.Count) GPO folder(s)" -ForegroundColor Cyan
Write-Host ""

$allComputerPolicies = @()

foreach ($gpoFolder in $gpoFolders) {
    $gpoName = $gpoFolder.Name
    Write-Host "Processing GPO: $gpoName" -ForegroundColor Yellow
    
    # Parse Computer Registry policies
    $computerPolPath = Join-Path $gpoFolder.FullName "DomainSysvol\GPO\Machine\registry.pol"
    
    if (Test-Path $computerPolPath) {
        Write-Host "  Parsing Computer registry policies..." -ForegroundColor Gray
        $computerPolicies = Read-PolFile -Path $computerPolPath
        
        if ($computerPolicies.Count -gt 0) {
            $allComputerPolicies += $computerPolicies
            Write-Host "  Found $($computerPolicies.Count) Computer registry policies" -ForegroundColor Green
        }
        else {
            Write-Warning "  No Computer registry policies found"
        }
    }
    else {
        Write-Warning "  Computer registry.pol not found"
    }
    
    # Check for User policies (Edge baseline typically doesn't have user policies)
    $userPolPath = Join-Path $gpoFolder.FullName "DomainSysvol\GPO\User\registry.pol"
    
    if (Test-Path $userPolPath) {
        Write-Host "  User registry.pol found (unexpected for Edge baseline)" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Save Computer Registry Policies
if ($allComputerPolicies.Count -gt 0) {
    $computerPoliciesFile = Join-Path $OutputPath "EdgePolicies.json"
    $allComputerPolicies | ConvertTo-Json -Depth 10 | Out-File -FilePath $computerPoliciesFile -Encoding UTF8 -Force
    Write-Host "Saved $($allComputerPolicies.Count) policies to: EdgePolicies.json" -ForegroundColor Green
}

# Create summary
$summary = [PSCustomObject]@{
    TotalEdgePolicies = $allComputerPolicies.Count
    ParsedDate        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    BaselineVersion   = "Edge v139"
    RegistryPaths     = ($allComputerPolicies | Select-Object -ExpandProperty KeyName -Unique | Sort-Object)
}

$summaryFile = Join-Path $OutputPath "Summary.json"
$summary | ConvertTo-Json -Depth 10 | Out-File -FilePath $summaryFile -Encoding UTF8 -Force

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Parsing Complete" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Edge Policies: $($allComputerPolicies.Count)" -ForegroundColor White
Write-Host ""
Write-Host "Output files:" -ForegroundColor White
Write-Host "  - EdgePolicies.json" -ForegroundColor Gray
Write-Host "  - Summary.json" -ForegroundColor Gray
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Review parsed policies in EdgePolicies.json" -ForegroundColor Gray
Write-Host "  2. Implement Set-EdgePolicies.ps1 (native PowerShell)" -ForegroundColor Gray
Write-Host "  3. Implement Test-EdgePolicies.ps1 (compliance check)" -ForegroundColor Gray
Write-Host "  4. Implement Invoke-EdgeHardening.ps1 (main entry point)" -ForegroundColor Gray
Write-Host ""

#endregion
