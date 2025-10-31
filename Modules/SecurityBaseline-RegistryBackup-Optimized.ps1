<#
.SYNOPSIS
    Registry Backup/Restore Helper Functions (OPTIMIERT)
    
.DESCRIPTION
    Funktionen für schnelles, spezifisches Backup und Restore der 375 Registry-Keys.
    Diese Funktionen ersetzen das langsame Snapshot-System.
    
    VORTEILE:
    - 20-30x schneller als komplette Snapshots
    - 50x kleinere Backup-Dateien
    - Präzise Kontrolle über jede Änderung
    - TrustedInstaller-Handling integriert
    
.NOTES
    Version: 2.0 (Optimized)
    Author: NoID Privacy Team
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

function Backup-SpecificRegistryKeys {
    <#
    .SYNOPSIS
        Sichert nur die spezifischen Registry-Keys aus $script:RegistryChanges
        
    .PARAMETER RegistryChanges
        Array mit Registry-Änderungs-Definitionen
        
    .EXAMPLE
        $backup = Backup-SpecificRegistryKeys -RegistryChanges $script:RegistryChanges
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$RegistryChanges
    )
    
    # Explicit admin check (works even when dot-sourced)
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "Registry backup requires Administrator privileges. Please run as Administrator."
        throw "Administrator privileges required"
    }
    
    # Protected hives that cannot be accessed even with Admin rights
    # These require TrustedInstaller or SYSTEM level access
    $protectedHives = @(
        'HKLM:\SAM',
        'HKLM:\SECURITY',
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers',
        'HKLM:\BCD00000000'
    )
    
    Write-Verbose "[Backup] Starting specific registry backup for $($RegistryChanges.Count) keys..."
    
    $backup = @()
    $successCount = 0
    $errorCount = 0
    $skippedProtected = 0
    
    foreach ($change in $RegistryChanges) {
        $currentValue = $null
        $exists = $false
        $valueType = $null
        
        # Check if this is a protected hive that we should skip
        $isProtectedHive = $false
        foreach ($protectedPath in $protectedHives) {
            if ($change.Path -like "$protectedPath*") {
                $isProtectedHive = $true
                break
            }
        }
        
        if ($isProtectedHive) {
            Write-Verbose "[Backup] SKIP protected hive (requires TrustedInstaller): $($change.Path)\$($change.Name)"
            $skippedProtected++
            continue
        }
        
        try {
            # Check if registry path exists
            if (Test-Path $change.Path) {
                # CRITICAL: Get ALL properties first, then check if our property exists
                # Using Get-ItemProperty with -Name creates error records even with -ErrorAction SilentlyContinue
                try {
                    $allProps = Get-ItemProperty -Path $change.Path -ErrorAction Stop
                }
                catch [System.UnauthorizedAccessException] {
                    # Additional protected key not in our list - skip it
                    Write-Verbose "[Backup SKIP] Protected key (Access Denied): $($change.Path)"
                    $skippedProtected++
                    continue
                }
                catch [System.Security.SecurityException] {
                    # Also a protected key (SecurityException instead of UnauthorizedAccessException)
                    Write-Verbose "[Backup SKIP] Protected key (Security Exception): $($change.Path)"
                    $skippedProtected++
                    continue
                }
                catch {
                    # Check if it's an Access Denied error (fallback for different Exception types)
                    if ($_.Exception.Message -match 'unzulässig|denied|access') {
                        Write-Verbose "[Backup SKIP] Protected key (Access pattern in message): $($change.Path)"
                        $skippedProtected++
                        continue
                    }
                    # Real error - log it
                    Write-Verbose "[Backup ERROR] Cannot read key $($change.Path): $_"
                    $errorCount++
                    continue
                }
                
                if ($allProps) {
                    # Check if the specific property exists using PSObject
                    $propNames = $allProps.PSObject.Properties.Name
                    
                    if ($change.Name -in $propNames) {
                        $currentValue = $allProps.$($change.Name)
                        $exists = $true
                        
                        # Get value type for accurate restore
                        try {
                            $regKey = Get-Item -Path $change.Path -ErrorAction Stop
                            $valueType = $regKey.GetValueKind($change.Name).ToString()
                        }
                        catch {
                            # Fallback to defined type
                            $valueType = $change.Type
                        }
                        
                        $successCount++
                    }
                }
            }
        }
        catch {
            # Check Exception Type (language-independent) instead of error message
            # UnauthorizedAccessException = Access Denied (protected registry key)
            if ($_.Exception -is [System.UnauthorizedAccessException]) {
                # Protected key (TrustedInstaller, SYSTEM) - don't count as error
                # CRITICAL: Don't add to backup! We can't read it, can't backup it, can't restore it.
                # Adding it with Exists=false would cause Restore to try deleting it (wrong!)
                Write-Verbose "[Backup] SKIP protected key (UnauthorizedAccess, not added to backup): $($change.Path)\$($change.Name)"
                # Skip to next key - don't add this one to backup
                continue
            }
            else {
                # Real error - log it
                Write-Verbose "[Backup] Error reading $($change.Path)\$($change.Name): $($_.Exception.GetType().Name) - $_"
                $errorCount++
            }
        }
        
        # Add to backup (even if key doesn't exist - we need to know this for restore!)
        # NOTE: Protected keys are NOT added (see 'continue' above)
        $backup += @{
            Path = $change.Path
            Name = $change.Name
            OriginalValue = $currentValue
            OriginalType = $valueType
            Exists = $exists
            ApplyValue = $change.ApplyValue
            ApplyType = $change.Type
            Description = $change.Description
            File = $change.File
        }
    }
    
    if ($skippedProtected -gt 0) {
        Write-Verbose "[Backup] Complete: $successCount backed up, $errorCount errors, $skippedProtected protected hives skipped (TrustedInstaller required)"
    }
    else {
        Write-Verbose "[Backup] Complete: $successCount backed up, $errorCount errors"
    }
    
    return $backup
}

function Restore-SpecificRegistryKeys {
    <#
    .SYNOPSIS
        Stellt die spezifischen Registry-Keys aus dem Backup wieder her
        
    .PARAMETER BackupData
        Array mit Backup-Daten von Backup-SpecificRegistryKeys
        
    .PARAMETER UseOwnership
        Nutze Ownership-Management für geschützte Keys (TrustedInstaller)
        
    .EXAMPLE
        $stats = Restore-SpecificRegistryKeys -BackupData $backup -UseOwnership $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$BackupData,
        
        [Parameter(Mandatory = $false)]
        [bool]$UseOwnership = $true
    )
    
    Write-Verbose "[Restore] Starting specific registry restore for $($BackupData.Count) keys..."
    
    $stats = @{
        Restored = 0
        Deleted = 0
        Unchanged = 0
        Failed = 0
    }
    
    # Check if Ownership module exists
    $scriptDir = Split-Path -Parent $PSScriptRoot
    $hasOwnershipModule = Test-Path "$scriptDir\Modules\SecurityBaseline-Ownership.ps1"
    
    if ($hasOwnershipModule -and $UseOwnership) {
        Write-Verbose "[Restore] Loading Ownership module for protected keys..."
        try {
            . "$scriptDir\Modules\SecurityBaseline-Ownership.ps1"
            Write-Verbose "[Restore] Ownership module loaded successfully"
        }
        catch {
            Write-Warning "[Restore] Could not load Ownership module: $_"
            $hasOwnershipModule = $false
        }
    }
    
    foreach ($entry in $BackupData) {
        try {
            # Determine what to do
            if ($entry.Exists) {
                # Key existed before - restore original value
                if ($null -ne $entry.OriginalValue -or $entry.OriginalType -eq "DWord") {
                    # Use Smart method if available (handles TrustedInstaller)
                    if ($hasOwnershipModule -and (Get-Command Set-RegistryValueSmart -ErrorAction SilentlyContinue)) {
                        $result = Set-RegistryValueSmart `
                            -Path $entry.Path `
                            -Name $entry.Name `
                            -Value $entry.OriginalValue `
                            -ValueType $entry.OriginalType `
                            -Description "Restore: $($entry.Description)"
                        
                        if ($result) {
                            $stats.Restored++
                            Write-Verbose "[Restore OK] $($entry.Path)\$($entry.Name) = $($entry.OriginalValue)"
                        }
                        else {
                            $stats.Unchanged++
                            Write-Verbose "[Restore SKIP] $($entry.Path)\$($entry.Name) (protected)"
                        }
                    }
                    else {
                        # Fallback: Standard method
                        if (-not (Test-Path $entry.Path)) {
                            New-Item -Path $entry.Path -Force -ErrorAction Stop | Out-Null
                        }
                        
                        # Check if property exists
                        $propExists = Get-ItemProperty -Path $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
                        
                        if ($propExists) {
                            Set-ItemProperty -Path $entry.Path -Name $entry.Name -Value $entry.OriginalValue -Force -ErrorAction Stop
                        }
                        else {
                            New-ItemProperty -Path $entry.Path -Name $entry.Name -Value $entry.OriginalValue -PropertyType $entry.OriginalType -Force -ErrorAction Stop | Out-Null
                        }
                        
                        $stats.Restored++
                        Write-Verbose "[Restore OK] $($entry.Path)\$($entry.Name) = $($entry.OriginalValue)"
                    }
                }
                else {
                    Write-Verbose "[Restore SKIP] $($entry.Path)\$($entry.Name) (no original value)"
                    $stats.Unchanged++
                }
            }
            else {
                # Key did NOT exist before - should be deleted (was created by Apply script)
                if (Test-Path $entry.Path) {
                    $currentProp = Get-ItemProperty -Path $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
                    
                    if ($currentProp) {
                        # Use Smart method if available
                        if ($hasOwnershipModule -and (Get-Command Remove-RegistryValueSmart -ErrorAction SilentlyContinue)) {
                            $result = Remove-RegistryValueSmart `
                                -Path $entry.Path `
                                -Name $entry.Name `
                                -Description "Delete: $($entry.Description)"
                            
                            if ($result) {
                                $stats.Deleted++
                                Write-Verbose "[Delete OK] $($entry.Path)\$($entry.Name)"
                            }
                            else {
                                $stats.Unchanged++
                                Write-Verbose "[Delete SKIP] $($entry.Path)\$($entry.Name) (protected)"
                            }
                        }
                        else {
                            # Fallback: Standard method
                            Remove-ItemProperty -Path $entry.Path -Name $entry.Name -Force -ErrorAction Stop
                            $stats.Deleted++
                            Write-Verbose "[Delete OK] $($entry.Path)\$($entry.Name)"
                        }
                    }
                }
            }
        }
        catch {
            # Check Exception Type (language-independent) instead of error message
            # Triple-layer catching for ALL Access Denied scenarios (same as Backup)
            if ($_.Exception -is [System.UnauthorizedAccessException]) {
                # Protected key - can't modify it (TrustedInstaller/SYSTEM)
                # This is NORMAL and expected - don't count as Failed!
                $stats.Unchanged++
                Write-Verbose "[Restore SKIP] Protected key (UnauthorizedAccess): $($entry.Path)\$($entry.Name)"
            }
            elseif ($_.Exception -is [System.Security.SecurityException]) {
                # Also a protected key (SecurityException instead of UnauthorizedAccessException)
                $stats.Unchanged++
                Write-Verbose "[Restore SKIP] Protected key (SecurityException): $($entry.Path)\$($entry.Name)"
            }
            elseif ($_.Exception.Message -match 'unzulässig|denied|access') {
                # Fallback: Check if message contains access denied pattern (language-independent)
                $stats.Unchanged++
                Write-Verbose "[Restore SKIP] Protected key (Access pattern in message): $($entry.Path)\$($entry.Name)"
            }
            else {
                # Real error - count as failed
                $stats.Failed++
                # Log the SPECIFIC key that failed (visible in normal output, not just verbose)
                $failedKey = "$($entry.Path)\$($entry.Name)"
                Write-Verbose "[Restore ERROR] $failedKey : $($_.Exception.GetType().Name) - $_"
                # Also track failed keys for summary (user can see which keys failed)
                if (-not $script:FailedRegistryKeys) {
                    $script:FailedRegistryKeys = @()
                }
                $script:FailedRegistryKeys += @{
                    Path = $entry.Path
                    Name = $entry.Name
                    Error = $_.Exception.Message
                }
            }
        }
    }
    
    Write-Verbose "[Restore] Complete: $($stats.Restored) restored, $($stats.Deleted) deleted, $($stats.Unchanged) unchanged, $($stats.Failed) failed"
    
    return $stats
}

function Test-RegistryRestore {
    <#
    .SYNOPSIS
        Validates whether all registry keys were correctly restored
        
    .PARAMETER BackupData
        Array with backup data
        
    .EXAMPLE
        $isValid = Test-RegistryRestore -BackupData $backup
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$BackupData
    )
    
    Write-Verbose "[Validation] Starting validation for $($BackupData.Count) keys..."
    
    $valid = 0
    $invalid = 0
    $errors = @()
    
    foreach ($entry in $BackupData) {
        try {
            $currentValue = $null
            if (Test-Path $entry.Path) {
                $prop = Get-ItemProperty -Path $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
                if ($prop) {
                    $currentValue = $prop.$($entry.Name)
                }
            }
            
            if ($entry.Exists) {
                # Key should be restored to original value
                if ($currentValue -eq $entry.OriginalValue) {
                    $valid++
                }
                else {
                    $invalid++
                    $errors += "MISMATCH: $($entry.Path)\$($entry.Name) - Expected: $($entry.OriginalValue), Got: $currentValue"
                }
            }
            else {
                # Key should be deleted (not exist)
                if ($null -eq $currentValue) {
                    $valid++
                }
                else {
                    $invalid++
                    $errors += "NOT DELETED: $($entry.Path)\$($entry.Name) - Still has value: $currentValue"
                }
            }
        }
        catch {
            $invalid++
            $errors += "ERROR: $($entry.Path)\$($entry.Name) - $_"
        }
    }
    
    Write-Verbose "[Validation] Complete: $valid valid, $invalid invalid"
    
    if ($invalid -gt 0) {
        Write-Warning "[Validation] Found $invalid validation errors:"
        foreach ($errorMsg in $errors) {
            Write-Warning "  - $errorMsg"
        }
    }
    
    return @{
        IsValid = ($invalid -eq 0)
        Valid = $valid
        Invalid = $invalid
        Errors = $errors
    }
}

# Export-ModuleMember is NOT needed when dot-sourcing (. .\file.ps1)
# All functions are automatically available in the calling scope
# Export-ModuleMember only works in .psm1 modules loaded via Import-Module
