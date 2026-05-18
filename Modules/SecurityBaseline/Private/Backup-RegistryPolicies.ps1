<#
.SYNOPSIS
    Backup all registry policies that will be modified by Security Baseline
    
.DESCRIPTION
    Creates a backup of all registry keys/values that will be modified.
    Backup is stored in JSON format for easy restore.
    
.PARAMETER ComputerPoliciesPath
    Path to Computer-RegistryPolicies.json (list of keys to backup)
    
.PARAMETER UserPoliciesPath
    Path to User-RegistryPolicies.json (list of keys to backup)
    
.PARAMETER BackupPath
    Path where backup JSON will be saved
    
.OUTPUTS
    PSCustomObject with backup status and path
    
.NOTES
    Backs up CURRENT values before any changes are made
#>

function Backup-RegistryPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ComputerPoliciesPath,
        
        [Parameter(Mandatory = $false)]
        [string]$UserPoliciesPath,
        
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    
    $result = [PSCustomObject]@{
        Success = $false
        BackupPath = $BackupPath
        ItemsBackedUp = 0
        Errors = @()
    }
    
    $backup = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Computer = @()
        User = @()
    }
    
    try {
        # Backup Computer policies (HKLM)
        if ($ComputerPoliciesPath -and (Test-Path $ComputerPoliciesPath)) {
            Write-Log -Level DEBUG -Message "Backing up Computer registry policies..." -Module "SecurityBaseline"
            
            $computerPolicies = Get-Content -Path $ComputerPoliciesPath -Raw | ConvertFrom-Json
            
            foreach ($policy in $computerPolicies) {
                try {
                    # Parse key path
                    $keyPath = $policy.KeyName -replace '^\[', '' -replace '\]$', ''
                    
                    # Determine registry root
                    if ($keyPath -match '^(SOFTWARE|SYSTEM)\\') {
                        $fullPath = "HKLM:\$keyPath"
                    }
                    else {
                        continue
                    }
                    
                    # Read current value
                    if (Test-Path $fullPath) {
                        try {
                            $currentValue = Get-ItemProperty -Path $fullPath -Name $policy.ValueName -ErrorAction Stop
                            
                            $backup.Computer += [PSCustomObject]@{
                                KeyName = $policy.KeyName
                                ValueName = $policy.ValueName
                                Type = $policy.Type
                                OriginalValue = $currentValue.$($policy.ValueName)
                                Exists = $true
                            }
                            
                            $result.ItemsBackedUp++
                        }
                        catch {
                            # Value doesn't exist - backup as non-existent
                            $backup.Computer += [PSCustomObject]@{
                                KeyName = $policy.KeyName
                                ValueName = $policy.ValueName
                                Type = $policy.Type
                                OriginalValue = $null
                                Exists = $false
                            }
                            
                            $result.ItemsBackedUp++
                        }
                    }
                    else {
                        # Key doesn't exist - backup as non-existent
                        $backup.Computer += [PSCustomObject]@{
                            KeyName = $policy.KeyName
                            ValueName = $policy.ValueName
                            Type = $policy.Type
                            OriginalValue = $null
                            Exists = $false
                            KeyExists = $false
                        }
                        
                        $result.ItemsBackedUp++
                    }
                }
                catch {
                    $result.Errors += "Failed to backup $($policy.KeyName)\$($policy.ValueName): $_"
                }
            }
            
            Write-Log -Level DEBUG -Message "Backed up $($backup.Computer.Count) Computer registry values" -Module "SecurityBaseline"
        }
        
        # Backup User policies (HKCU)
        if ($UserPoliciesPath -and (Test-Path $UserPoliciesPath)) {
            Write-Log -Level DEBUG -Message "Backing up User registry policies..." -Module "SecurityBaseline"
            
            $userPolicies = Get-Content -Path $UserPoliciesPath -Raw | ConvertFrom-Json
            
            foreach ($policy in $userPolicies) {
                try {
                    # Parse key path
                    $keyPath = $policy.KeyName -replace '^\[', '' -replace '\]$', ''
                    
                    if ($keyPath -match '^SOFTWARE\\') {
                        $fullPath = "HKCU:\$keyPath"
                    }
                    else {
                        continue
                    }
                    
                    # Read current value
                    if (Test-Path $fullPath) {
                        try {
                            $currentValue = Get-ItemProperty -Path $fullPath -Name $policy.ValueName -ErrorAction Stop
                            
                            $backup.User += [PSCustomObject]@{
                                KeyName = $policy.KeyName
                                ValueName = $policy.ValueName
                                Type = $policy.Type
                                OriginalValue = $currentValue.$($policy.ValueName)
                                Exists = $true
                            }
                            
                            $result.ItemsBackedUp++
                        }
                        catch {
                            $backup.User += [PSCustomObject]@{
                                KeyName = $policy.KeyName
                                ValueName = $policy.ValueName
                                Type = $policy.Type
                                OriginalValue = $null
                                Exists = $false
                            }
                            
                            $result.ItemsBackedUp++
                        }
                    }
                    else {
                        $backup.User += [PSCustomObject]@{
                            KeyName = $policy.KeyName
                            ValueName = $policy.ValueName
                            Type = $policy.Type
                            OriginalValue = $null
                            Exists = $false
                            KeyExists = $false
                        }
                        
                        $result.ItemsBackedUp++
                    }
                }
                catch {
                    $result.Errors += "Failed to backup User $($policy.KeyName)\$($policy.ValueName): $_"
                }
            }
            
            Write-Log -Level DEBUG -Message "Backed up $($backup.User.Count) User registry values" -Module "SecurityBaseline"
        }
        
        # Save backup to JSON
        $backup | ConvertTo-Json -Depth 5 | Out-File -FilePath $BackupPath -Encoding UTF8 -Force
        
        $result.Success = $true
        Write-Log -Level DEBUG -Message "Registry backup saved to: $BackupPath" -Module "SecurityBaseline"
        
    }
    catch {
        $result.Errors += "Registry backup failed: $_"
        Write-Error "Registry backup failed: $_"
    }
    
    return $result
}
