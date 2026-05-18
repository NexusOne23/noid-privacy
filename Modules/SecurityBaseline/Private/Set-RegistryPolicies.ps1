<#
.SYNOPSIS
    Apply registry policies from parsed Security Baseline JSON
    
.DESCRIPTION
    Native PowerShell registry application without LGPO.exe dependency.
    Applies Computer (HKLM) and User (HKCU) registry settings from JSON configs.
    
    Supports all registry types:
    - REG_DWORD, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_MULTI_SZ
    
.PARAMETER ComputerPoliciesPath
    Path to Computer-RegistryPolicies.json
    
.PARAMETER UserPoliciesPath
    Path to User-RegistryPolicies.json
    
.PARAMETER DryRun
    Preview changes without applying
    
.OUTPUTS
    PSCustomObject with applied count and errors
    
.NOTES
    This replaces LGPO.exe for registry policy application
    Uses native PowerShell New-Item/Set-ItemProperty
#>

function Set-RegistryPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ComputerPoliciesPath,
        
        [Parameter(Mandatory = $false)]
        [string]$UserPoliciesPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    $result = [PSCustomObject]@{
        Applied = 0
        Skipped = 0
        Errors = @()
        Details = @{
            Computer = 0
            User = 0
        }
    }
    
    try {
        # Apply Computer policies (HKLM)
        if ($ComputerPoliciesPath -and (Test-Path $ComputerPoliciesPath)) {
            Write-Log -Level DEBUG -Message "Applying Computer registry policies..." -Module "SecurityBaseline"
            
            $computerPolicies = Get-Content -Path $ComputerPoliciesPath -Raw | ConvertFrom-Json
            
            foreach ($policy in $computerPolicies) {
                try {
                    # Parse key path: [SOFTWARE\... -> HKLM:\SOFTWARE\...
                    $keyPath = $policy.KeyName -replace '^\[', '' -replace '\]$', ''
                    
                    # Determine registry root
                    if ($keyPath -match '^(SOFTWARE|SYSTEM)\\') {
                        $fullPath = "HKLM:\$keyPath"
                    }
                    else {
                        Write-Log -Level DEBUG -Message "Unknown registry root for: $keyPath" -Module "SecurityBaseline"
                        $result.Skipped++
                        continue
                    }
                    
                    if ($DryRun) {
                        Write-Log -Level DEBUG -Message "[DRYRUN] Would set: $fullPath\$($policy.ValueName) = $($policy.Data)" -Module "SecurityBaseline"
                        $result.Applied++
                        $result.Details.Computer++
                        continue
                    }
                    
                    # Ensure parent key exists
                    if (-not (Test-Path $fullPath)) {
                        New-Item -Path $fullPath -Force -ErrorAction Stop | Out-Null
                    }
                    
                    # Convert registry type
                    $regType = switch ($policy.Type) {
                        "REG_DWORD" { "DWord" }
                        "REG_SZ" { "String" }
                        "REG_EXPAND_SZ" { "ExpandString" }
                        "REG_BINARY" { "Binary" }
                        "REG_MULTI_SZ" { "MultiString" }
                        default {
                            Write-Log -Level DEBUG -Message "Unknown registry type: $($policy.Type) for $($policy.ValueName)" -Module "SecurityBaseline"
                            "String"
                        }
                    }
                    
                    # Apply setting (create or update with correct type)
                    $existingValue = Get-ItemProperty -Path $fullPath -Name $policy.ValueName -ErrorAction SilentlyContinue
                    
                    if ($null -ne $existingValue) {
                        # Value exists - update it (specify Type to ensure it's preserved/corrected)
                        Set-ItemProperty -Path $fullPath `
                                         -Name $policy.ValueName `
                                         -Value $policy.Data `
                                         -Type $regType `
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
                    
                    $result.Applied++
                    $result.Details.Computer++
                    
                }
                catch {
                    $result.Errors += "Failed to set $($policy.KeyName)\$($policy.ValueName): $($_.Exception.Message)"
                    Write-Log -Level DEBUG -Message "Failed to set $($policy.KeyName)\$($policy.ValueName): $_" -Module "SecurityBaseline"
                }
            }
            
            Write-Log -Level DEBUG -Message "Applied $($result.Details.Computer) Computer registry policies" -Module "SecurityBaseline"
        }
        
        # Apply User policies (HKCU)
        if ($UserPoliciesPath -and (Test-Path $UserPoliciesPath)) {
            Write-Log -Level DEBUG -Message "Applying User registry policies..." -Module "SecurityBaseline"
            
            $userPolicies = Get-Content -Path $UserPoliciesPath -Raw | ConvertFrom-Json
            
            foreach ($policy in $userPolicies) {
                try {
                    # Parse key path
                    $keyPath = $policy.KeyName -replace '^\[', '' -replace '\]$', ''
                    
                    # User policies go to HKCU
                    if ($keyPath -match '^SOFTWARE\\') {
                        $fullPath = "HKCU:\$keyPath"
                    }
                    else {
                        Write-Log -Level DEBUG -Message "Unknown user registry root for: $keyPath" -Module "SecurityBaseline"
                        $result.Skipped++
                        continue
                    }
                    
                    if ($DryRun) {
                        Write-Log -Level DEBUG -Message "[DRYRUN] Would set: $fullPath\$($policy.ValueName) = $($policy.Data)" -Module "SecurityBaseline"
                        $result.Applied++
                        $result.Details.User++
                        continue
                    }
                    
                    # Ensure parent key exists
                    if (-not (Test-Path $fullPath)) {
                        New-Item -Path $fullPath -Force -ErrorAction Stop | Out-Null
                    }
                    
                    # Convert registry type
                    $regType = switch ($policy.Type) {
                        "REG_DWORD" { "DWord" }
                        "REG_SZ" { "String" }
                        "REG_EXPAND_SZ" { "ExpandString" }
                        "REG_BINARY" { "Binary" }
                        "REG_MULTI_SZ" { "MultiString" }
                        default { "String" }
                    }
                    
                    # Apply setting (create or update with correct type)
                    $existingValue = Get-ItemProperty -Path $fullPath -Name $policy.ValueName -ErrorAction SilentlyContinue
                    
                    if ($null -ne $existingValue) {
                        # Value exists - update it (specify Type to ensure it's preserved/corrected)
                        Set-ItemProperty -Path $fullPath `
                                         -Name $policy.ValueName `
                                         -Value $policy.Data `
                                         -Type $regType `
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
                    
                    $result.Applied++
                    $result.Details.User++
                    
                }
                catch {
                    $result.Errors += "Failed to set User $($policy.KeyName)\$($policy.ValueName): $($_.Exception.Message)"
                    Write-Log -Level DEBUG -Message "Failed to set User $($policy.KeyName)\$($policy.ValueName): $_" -Module "SecurityBaseline"
                }
            }
            
            Write-Log -Level DEBUG -Message "Applied $($result.Details.User) User registry policies" -Module "SecurityBaseline"
        }
        
    }
    catch {
        $result.Errors += "Registry policy application failed: $($_.Exception.Message)"
        Write-Log -Level DEBUG -Message "Registry policy application failed: $_" -Module "SecurityBaseline"
    }
    
    return $result
}
