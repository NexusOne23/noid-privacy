<#
.SYNOPSIS
    Apply Microsoft Edge security policies from parsed baseline JSON
    
.DESCRIPTION
    Native PowerShell implementation - no LGPO.exe dependency.
    Applies 20 Microsoft Edge v139 Security Baseline policies directly to registry.
    
    Policies include:
    - SmartScreen enforcement (no override)
    - Site isolation (SitePerProcess)
    - SSL/TLS error override blocking
    - Extension blocklist (block all)
    - IE Mode restrictions
    - Spectre mitigations (SharedArrayBuffer)
    - Application-bound encryption
    
.PARAMETER EdgePoliciesPath
    Path to EdgePolicies.json (default: module ParsedSettings folder)
    
.PARAMETER DryRun
    Preview changes without applying
    
.PARAMETER AllowExtensions
    Skip ExtensionInstallBlocklist policy (allows users to install any extensions)
    Default: Block all extensions (Microsoft Security Baseline)
    
.OUTPUTS
    PSCustomObject with applied count and errors
    
.NOTES
    Applies policies to: HKLM:\Software\Policies\Microsoft\Edge
    Requires Administrator privileges
#>

function Set-EdgePolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$EdgePoliciesPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [switch]$AllowExtensions
    )
    
    $result = [PSCustomObject]@{
        Applied = 0
        Skipped = 0
        Errors  = @()
    }
    
    # Default path if not specified
    if (-not $EdgePoliciesPath) {
        $modulePath = Split-Path -Parent $PSScriptRoot
        $EdgePoliciesPath = Join-Path $modulePath "Config\EdgePolicies.json"
    }
    
    if (-not (Test-Path $EdgePoliciesPath)) {
        $result.Errors += "EdgePolicies.json not found: $EdgePoliciesPath"
        return $result
    }
    
    try {
        Write-Log -Level DEBUG -Message "Applying Microsoft Edge security policies..." -Module "EdgeHardening"
        
        $edgePolicies = Get-Content -Path $EdgePoliciesPath -Raw | ConvertFrom-Json
        
        if ($edgePolicies.Count -eq 0) {
            Write-Log -Level DEBUG -Message "No Edge policies to apply" -Module "EdgeHardening"
            return $result
        }
        
        # Calculate actual policy count that will be applied
        # Total JSON entries vary - dynamically count from loaded policies
        # Extension blocklist (2 entries: **delvals + blocklist value) skipped if AllowExtensions
        # **delvals GPO markers always skipped
        $actualPolicyCount = ($edgePolicies | Where-Object { 
            $_.ValueName -notlike "**delvals*" -and 
            (-not $AllowExtensions -or $_.KeyName -notlike "*ExtensionInstallBlocklist*") 
        }).Count
        
        Write-Host "    Applying $actualPolicyCount Edge security policies..." -ForegroundColor Cyan
        
        if ($AllowExtensions) {
            Write-Host "    Note: Extension blocklist will be skipped (AllowExtensions specified)" -ForegroundColor Yellow
        }
        
        foreach ($policy in $edgePolicies) {
            try {
                # Parse key path: [Software\Policies\... -> HKLM:\Software\Policies\...
                $keyPath = $policy.KeyName -replace '^\[', '' -replace '\]$', ''
                
                # All Edge policies are under HKLM
                $fullPath = "HKLM:\$keyPath"
                
                # Skip ExtensionInstallBlocklist if AllowExtensions is specified
                if ($AllowExtensions -and $keyPath -like "*ExtensionInstallBlocklist*") {
                    Write-Log -Level DEBUG -Message "Skipping ExtensionInstallBlocklist (AllowExtensions specified): $($policy.ValueName)" -Module "EdgeHardening"
                    $result.Skipped++
                    continue
                }
                
                if ($DryRun) {
                    Write-Log -Level DEBUG -Message "[DRYRUN] Would set: $fullPath\$($policy.ValueName) = $($policy.Data) ($($policy.Type))" -Module "EdgeHardening"
                    $result.Applied++
                    continue
                }
                
                # Ensure parent key exists
                if (-not (Test-Path $fullPath)) {
                    New-Item -Path $fullPath -Force -ErrorAction Stop | Out-Null
                    Write-Log -Level DEBUG -Message "Created registry path: $fullPath" -Module "EdgeHardening"
                }
                
                # Handle special GPO deletion markers
                if ($policy.ValueName -like "**delvals.*") {
                    # This is a GPO marker to delete all values in this key before setting new ones
                    # We'll skip this as we're setting explicit values
                    Write-Log -Level DEBUG -Message "Skipping GPO deletion marker: $($policy.ValueName)" -Module "EdgeHardening"
                    $result.Skipped++
                    continue
                }
                
                # Convert registry type
                $regType = switch ($policy.Type) {
                    "REG_DWORD" { "DWord" }
                    "REG_SZ" { "String" }
                    "REG_EXPAND_SZ" { "ExpandString" }
                    "REG_BINARY" { "Binary" }
                    "REG_MULTI_SZ" { "MultiString" }
                    default {
                        Write-Log -Level DEBUG -Message "Unknown registry type: $($policy.Type) for $($policy.ValueName)" -Module "EdgeHardening"
                        "String"
                    }
                }
                
                # Apply setting (create or update with correct type)
                $existingValue = Get-ItemProperty -Path $fullPath -Name $policy.ValueName -ErrorAction SilentlyContinue
                
                if ($null -ne $existingValue) {
                    # Value exists - update it (type is preserved)
                    Set-ItemProperty -Path $fullPath `
                        -Name $policy.ValueName `
                        -Value $policy.Data `
                        -Force `
                        -ErrorAction Stop | Out-Null
                }
                else {
                    # Value does not exist - create it with proper type
                    New-ItemProperty -Path $fullPath `
                        -Name $policy.ValueName `
                        -Value $policy.Data `
                        -PropertyType $regType `
                        -Force `
                        -ErrorAction Stop | Out-Null
                }
                
                Write-Log -Level DEBUG -Message "Applied: $($policy.ValueName) = $($policy.Data) ($regType)" -Module "EdgeHardening"
                $result.Applied++
                
            }
            catch {
                $result.Errors += "Failed to set $($policy.KeyName)\$($policy.ValueName): $($_.Exception.Message)"
                Write-Log -Level WARNING -Message "Failed to set $($policy.KeyName)\$($policy.ValueName): $_" -Module "EdgeHardening"
                Write-Host "  [ERROR] $($policy.ValueName): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        Write-Log -Level DEBUG -Message "Applied $($result.Applied) Edge policies (Skipped: $($result.Skipped))" -Module "EdgeHardening"
        Write-Host "    Completed: $($result.Applied) Edge policies applied" -ForegroundColor Green
        
        if ($result.Skipped -gt 0) {
            Write-Host "    Note: $($result.Skipped) GPO markers skipped (expected)" -ForegroundColor Gray
        }
    }
    catch {
        $result.Errors += "Edge policy application failed: $($_.Exception.Message)"
        Write-Log -Level DEBUG -Message "Edge policy application failed: $_" -Module "EdgeHardening"
    }
    
    return $result
}
