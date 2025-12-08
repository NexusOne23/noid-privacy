<#
.SYNOPSIS
    Restore registry policies from backup
    
.DESCRIPTION
    Restores all registry keys/values from a backup JSON file.
    Handles non-existent keys/values correctly.
    
.PARAMETER BackupPath
    Path to backup JSON file created by Backup-RegistryPolicies
    
.OUTPUTS
    PSCustomObject with restore status
    
.NOTES
    Restores ORIGINAL values including deletions if keys didn't exist before
#>

function Restore-RegistryPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    
    $result = [PSCustomObject]@{
        Success = $false
        ItemsRestored = 0
        Errors = @()
    }
    
    if (-not (Test-Path $BackupPath)) {
        $result.Errors += "Backup file not found: $BackupPath"
        return $result
    }
    
    try {
        Write-Log -Level DEBUG -Message "Loading backup from: $BackupPath" -Module "SecurityBaseline"
        $backup = Get-Content -Path $BackupPath -Raw | ConvertFrom-Json
        
        # Restore Computer policies (HKLM)
        if ($backup.Computer) {
            Write-Log -Level DEBUG -Message "Restoring $($backup.Computer.Count) Computer registry values..." -Module "SecurityBaseline"
            
            foreach ($item in $backup.Computer) {
                try {
                    # Parse key path
                    $keyPath = $item.KeyName -replace '^\[', '' -replace '\]$', ''
                    
                    if ($keyPath -match '^(SOFTWARE|SYSTEM)\\') {
                        $fullPath = "HKLM:\$keyPath"
                    }
                    else {
                        continue
                    }
                    
                    # Handle restoration based on original state
                    # CRITICAL FIX: **del* values are GPO DELETE markers - they should NOT be restored!
                    # These markers instruct GPO to delete a value. If we restore them, verification fails
                    # because verification expects these values to be DELETED (not present).
                    if ($item.ValueName -like "**del*" -or $item.ValueName -like "**delvals*") {
                        # DELETE marker - ensure value is deleted (not restored)
                        if (Test-Path $fullPath) {
                            try {
                                Remove-ItemProperty -Path $fullPath -Name $item.ValueName -ErrorAction SilentlyContinue
                                Write-Log -Level DEBUG -Message "Removed DELETE marker: $fullPath\$($item.ValueName)" -Module "SecurityBaseline"
                            }
                            catch { $null = $null }
                        }
                    }
                    elseif ($item.Exists -eq $false) {
                        # Item didn't exist before - delete it
                        if (Test-Path $fullPath) {
                            try {
                                Remove-ItemProperty -Path $fullPath -Name $item.ValueName -ErrorAction Stop
                                Write-Log -Level DEBUG -Message "Removed: $fullPath\$($item.ValueName)" -Module "SecurityBaseline"
                            }
                            catch {
                                # Value doesn't exist anymore - that's fine
                                $null = $null
                            }
                        }
                    }
                    else {
                        # Item existed - restore original value
                        if (-not (Test-Path $fullPath)) {
                            New-Item -Path $fullPath -Force | Out-Null
                        }
                        
                        # Convert type
                        $regType = switch ($item.Type) {
                            "REG_DWORD" { "DWord" }
                            "REG_SZ" { "String" }
                            "REG_EXPAND_SZ" { "ExpandString" }
                            "REG_BINARY" { "Binary" }
                            "REG_MULTI_SZ" { "MultiString" }
                            default { "String" }
                        }
                        
                        # Restore value (create or update with correct type)
                        $existingValue = Get-ItemProperty -Path $fullPath -Name $item.ValueName -ErrorAction SilentlyContinue
                        
                        if ($null -ne $existingValue) {
                            # Value exists - update it
                            Set-ItemProperty -Path $fullPath `
                                             -Name $item.ValueName `
                                             -Value $item.OriginalValue `
                                             -Force `
                                             -ErrorAction Stop
                        }
                        else {
                            # Value does not exist - create it with proper type
                            New-ItemProperty -Path $fullPath `
                                             -Name $item.ValueName `
                                             -Value $item.OriginalValue `
                                             -PropertyType $regType `
                                             -Force `
                                             -ErrorAction Stop | Out-Null
                        }
                        
                        Write-Log -Level DEBUG -Message "Restored: $fullPath\$($item.ValueName) = $($item.OriginalValue)" -Module "SecurityBaseline"
                    }
                    
                    $result.ItemsRestored++
                }
                catch {
                    $result.Errors += "Failed to restore $($item.KeyName)\$($item.ValueName): $_"
                }
            }
        }
        
        # Restore User policies (HKCU)
        if ($backup.User) {
            Write-Log -Level DEBUG -Message "Restoring $($backup.User.Count) User registry values..." -Module "SecurityBaseline"
            
            foreach ($item in $backup.User) {
                try {
                    # Parse key path
                    $keyPath = $item.KeyName -replace '^\[', '' -replace '\]$', ''
                    
                    if ($keyPath -match '^SOFTWARE\\') {
                        $fullPath = "HKCU:\$keyPath"
                    }
                    else {
                        continue
                    }
                    
                    # Handle restoration based on original state
                    # CRITICAL FIX: **del* values are GPO DELETE markers - they should NOT be restored!
                    if ($item.ValueName -like "**del*" -or $item.ValueName -like "**delvals*") {
                        # DELETE marker - ensure value is deleted (not restored)
                        if (Test-Path $fullPath) {
                            try {
                                Remove-ItemProperty -Path $fullPath -Name $item.ValueName -ErrorAction SilentlyContinue
                                Write-Log -Level DEBUG -Message "Removed DELETE marker: $fullPath\$($item.ValueName)" -Module "SecurityBaseline"
                            }
                            catch { $null = $null }
                        }
                    }
                    elseif ($item.Exists -eq $false) {
                        # Item didn't exist before - delete it
                        if (Test-Path $fullPath) {
                            try {
                                Remove-ItemProperty -Path $fullPath -Name $item.ValueName -ErrorAction Stop
                                Write-Log -Level DEBUG -Message "Removed: $fullPath\$($item.ValueName)" -Module "SecurityBaseline"
                            }
                            catch {
                                # Value doesn't exist anymore - that's fine
                                $null = $null
                            }
                        }
                    }
                    else {
                        # Item existed - restore original value
                        if (-not (Test-Path $fullPath)) {
                            New-Item -Path $fullPath -Force | Out-Null
                        }
                        
                        # Convert type
                        $regType = switch ($item.Type) {
                            "REG_DWORD" { "DWord" }
                            "REG_SZ" { "String" }
                            "REG_EXPAND_SZ" { "ExpandString" }
                            "REG_BINARY" { "Binary" }
                            "REG_MULTI_SZ" { "MultiString" }
                            default { "String" }
                        }
                        
                        # Restore value (create or update with correct type)
                        $existingValue = Get-ItemProperty -Path $fullPath -Name $item.ValueName -ErrorAction SilentlyContinue
                        
                        if ($null -ne $existingValue) {
                            # Value exists - update it
                            Set-ItemProperty -Path $fullPath `
                                             -Name $item.ValueName `
                                             -Value $item.OriginalValue `
                                             -Force `
                                             -ErrorAction Stop
                        }
                        else {
                            # Value does not exist - create it with proper type
                            New-ItemProperty -Path $fullPath `
                                             -Name $item.ValueName `
                                             -Value $item.OriginalValue `
                                             -PropertyType $regType `
                                             -Force `
                                             -ErrorAction Stop | Out-Null
                        }
                        
                        Write-Log -Level DEBUG -Message "Restored: $fullPath\$($item.ValueName) = $($item.OriginalValue)" -Module "SecurityBaseline"
                    }
                    
                    $result.ItemsRestored++
                }
                catch {
                    $result.Errors += "Failed to restore User $($item.KeyName)\$($item.ValueName): $_"
                }
            }
        }
        
        $result.Success = ($result.Errors.Count -eq 0)
        Write-Log -Level DEBUG -Message "Registry restore complete: $($result.ItemsRestored) items restored" -Module "SecurityBaseline"
        
    }
    catch {
        $result.Errors += "Registry restore failed: $_"
        Write-Error "Registry restore failed: $_"
    }
    
    return $result
}
