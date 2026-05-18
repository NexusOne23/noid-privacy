<#
.SYNOPSIS
    Backup current Microsoft Edge policy settings
    
.DESCRIPTION
    Creates backup of existing Edge policy registry keys before applying baseline.
    Integrates with Core Rollback system (Backup-RegistryKey).
    
.PARAMETER BackupName
    Name for this backup (default: auto-generated timestamp)
    
.OUTPUTS
    PSCustomObject with backup status and path
    
.NOTES
    Backs up: HKLM:\Software\Policies\Microsoft\Edge (entire subtree)
#>

function Backup-EdgePolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupName
    )
    
    $result = [PSCustomObject]@{
        Success      = $false
        BackupPath   = $null
        KeysBackedUp = 0
        Errors       = @()
    }
    
    try {
        Write-Log -Level DEBUG -Message "Backing up Edge policy settings..." -Module "EdgeHardening"
        
        # Edge policy root path
        $edgePolicyPath = "HKLM:\Software\Policies\Microsoft\Edge"
        
        # Check if Backup-RegistryKey is available (from Core/Rollback.ps1)
        if (-not (Get-Command Backup-RegistryKey -ErrorAction SilentlyContinue)) {
            Write-Warning "Backup-RegistryKey not available - using standalone backup"
            
            # Fallback: Export to .reg file
            if (-not $BackupName) {
                $BackupName = "EdgePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            }
            
            $backupFolder = Join-Path $env:TEMP "NoIDPrivacy_Backups"
            if (-not (Test-Path $backupFolder)) {
                New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
            }
            
            $backupFile = Join-Path $backupFolder "$BackupName.reg"
            
            if (Test-Path $edgePolicyPath) {
                # Export using reg.exe (built-in)
                $regPath = "HKLM\Software\Policies\Microsoft\Edge"
                $process = Start-Process -FilePath "reg.exe" `
                    -ArgumentList "export `"$regPath`" `"$backupFile`" /y" `
                    -Wait `
                    -NoNewWindow `
                    -PassThru
                
                if ($process.ExitCode -eq 0) {
                    $result.Success = $true
                    $result.BackupPath = $backupFile
                    $result.KeysBackedUp = 1
                    Write-Log -Level DEBUG -Message "Standalone backup created: $backupFile" -Module "EdgeHardening"
                }
                else {
                    $result.Errors += "reg.exe export failed with exit code: $($process.ExitCode)"
                }
            }
            else {
                # No existing Edge policies - nothing to backup
                $result.Success = $true
                $result.KeysBackedUp = 0
                Write-Log -Level DEBUG -Message "No existing Edge policies to backup" -Module "EdgeHardening"
            }
        }
        else {
            $backupResult = Backup-RegistryKey -KeyPath $edgePolicyPath -BackupName "EdgeHardening"
            
            if ($backupResult) {
                if ($backupResult -match "_EMPTY\.json$") {
                    Write-Log -Level INFO -Message "Edge policy key does not exist - Created Empty Marker for cleanup" -Module "EdgeHardening"
                    $result.Success = $true
                    $result.KeysBackedUp = 0
                }
                else {
                    $result.Success = $true
                    $result.BackupPath = $backupResult
                    $result.KeysBackedUp = 1
                    Write-Log -Level DEBUG -Message "Edge policies backed up via Core Rollback system: $backupResult" -Module "EdgeHardening"

                    try {
                        $preStateEntries = @()
                        if (Test-Path $edgePolicyPath) {
                            $keysToSnapshot = @()
                            $keysToSnapshot += $edgePolicyPath
                            $childKeys = Get-ChildItem -Path $edgePolicyPath -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer }
                            foreach ($child in $childKeys) {
                                $keysToSnapshot += $child.PSPath
                            }

                            foreach ($key in $keysToSnapshot) {
                                try {
                                    $properties = Get-ItemProperty -Path $key -ErrorAction Stop
                                    $propertyNames = $properties.PSObject.Properties.Name | Where-Object { $_ -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive') }
                                    foreach ($propName in $propertyNames) {
                                        $propValue = $properties.$propName
                                        $propType = (Get-Item $key).GetValueKind($propName)
                                        $preStateEntries += [PSCustomObject]@{
                                            Path  = $key
                                            Name  = $propName
                                            Value = $propValue
                                            Type  = $propType.ToString()
                                        }
                                    }
                                }
                                catch {
                                    Write-Log -Level DEBUG -Message "Could not read properties from $key : $_" -Module "EdgeHardening"
                                }
                            }
                        }

                        $backupFolder = [System.IO.Path]::GetDirectoryName($backupResult)
                        $preStatePath = Join-Path $backupFolder "EdgeHardening_PreState.json"
                        $preStateEntries | ConvertTo-Json -Depth 5 | Set-Content -Path $preStatePath -Encoding UTF8
                        Write-Log -Level INFO -Message "Edge policy pre-state snapshot created ($($preStateEntries.Count) registry values)" -Module "EdgeHardening"
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Failed to create EdgeHardening pre-state snapshot: $_" -Module "EdgeHardening"
                    }
                }
            }
            else {
                $result.Success = $true
                $result.KeysBackedUp = 0
                Write-Log -Level DEBUG -Message "Backup-RegistryKey returned null (unexpected but handled)" -Module "EdgeHardening"
            }
        }
        
    }
    catch {
        $result.Errors += "Backup failed: $($_.Exception.Message)"
        Write-Log -Level DEBUG -Message "Backup failed: $_" -Module "EdgeHardening"
    }
    
    return $result
}
