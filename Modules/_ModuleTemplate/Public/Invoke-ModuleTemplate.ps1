function Invoke-ModuleTemplate {
    <#
    .SYNOPSIS
        Template function implementing BACKUP/APPLY/VERIFY/RESTORE pattern
        
    .DESCRIPTION
        This is a template function showing how to properly implement
        the four-phase hardening pattern required for all modules.
        
    .PARAMETER DryRun
        Preview changes without applying them
        
    .PARAMETER SkipBackup
        Skip backup phase (not recommended)
        
    .PARAMETER SkipVerify
        Skip verification phase (not recommended)
        
    .EXAMPLE
        Invoke-ModuleTemplate -DryRun
        Preview what changes would be made
        
    .EXAMPLE
        Invoke-ModuleTemplate
        Apply all hardening changes with backup
        
    .OUTPUTS
        PSCustomObject with execution results
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipBackup,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipVerify
    )
    
    begin {
        Write-Log -Level INFO -Message "Starting ModuleTemplate execution" -Module "ModuleTemplate"
        
        $result = [PSCustomObject]@{
            ModuleName = "ModuleTemplate"
            Success = $true
            ChangesApplied = 0
            Errors = @()
            Warnings = @()
            BackupCreated = $false
            VerificationPassed = $false
        }
    }
    
    process {
        try {
            # ========================================
            # PHASE 1: BACKUP
            # ========================================
            if (-not $SkipBackup -and -not $DryRun) {
                Write-Log -Level INFO -Message "PHASE 1: Creating backups" -Module "ModuleTemplate"
                
                try {
                    # Example: Backup a registry key
                    $backupFile = Backup-RegistryKey `
                        -KeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows" `
                        -BackupName "ModuleTemplate_Example"
                    
                    if ($null -ne $backupFile) {
                        $result.BackupCreated = $true
                        Write-Log -Level SUCCESS -Message "Backup created successfully" -Module "ModuleTemplate"
                    }
                    else {
                        $result.Warnings += "Backup creation failed"
                        Write-Log -Level WARNING -Message "Backup creation failed" -Module "ModuleTemplate"
                    }
                }
                catch {
                    $result.Warnings += "Backup error: $($_.Exception.Message)"
                    Write-Log -Level WARNING -Message "Backup error" -Module "ModuleTemplate" -Exception $_
                }
            }
            elseif ($DryRun) {
                Write-Log -Level INFO -Message "[DRY RUN] Would create backup" -Module "ModuleTemplate"
            }
            
            # ========================================
            # PHASE 2: APPLY
            # ========================================
            Write-Log -Level INFO -Message "PHASE 2: Applying changes" -Module "ModuleTemplate"
            
            if ($DryRun) {
                Write-Log -Level INFO -Message "[DRY RUN] Would apply the following changes:" -Module "ModuleTemplate"
                Write-Log -Level INFO -Message "[DRY RUN]   - Example registry key modification" -Module "ModuleTemplate"
                Write-Log -Level INFO -Message "[DRY RUN]   - Example service configuration" -Module "ModuleTemplate"
            }
            else {
                # Example: Apply a registry setting
                $registrySuccess = Set-RegistryValue `
                    -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Example" `
                    -Name "ExampleSetting" `
                    -Value 1 `
                    -Type "DWord" `
                    -BackupName "ModuleTemplate_Registry"
                
                if ($registrySuccess) {
                    $result.ChangesApplied++
                    Write-Log -Level SUCCESS -Message "Registry setting applied" -Module "ModuleTemplate"
                }
                else {
                    $result.Errors += "Failed to apply registry setting"
                    Write-Log -Level ERROR -Message "Failed to apply registry setting" -Module "ModuleTemplate"
                }
                
                # Example: Configure a service
                if (Test-ServiceExists -ServiceName "ExampleService") {
                    $serviceSuccess = Set-ServiceStartupType `
                        -ServiceName "ExampleService" `
                        -StartupType "Disabled" `
                        -BackupName "ModuleTemplate_Service"
                    
                    if ($serviceSuccess) {
                        $result.ChangesApplied++
                        Write-Log -Level SUCCESS -Message "Service configured" -Module "ModuleTemplate"
                    }
                    else {
                        $result.Errors += "Failed to configure service"
                        Write-Log -Level ERROR -Message "Failed to configure service" -Module "ModuleTemplate"
                    }
                }
            }
            
            # ========================================
            # PHASE 3: VERIFY
            # ========================================
            if (-not $SkipVerify) {
                Write-Log -Level INFO -Message "PHASE 3: Verifying changes" -Module "ModuleTemplate"
                
                if ($DryRun) {
                    Write-Log -Level INFO -Message "[DRY RUN] Would verify all settings" -Module "ModuleTemplate"
                    $result.VerificationPassed = $true
                }
                else {
                    # Example: Verify registry setting
                    $actualValue = Get-RegistryValue `
                        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Example" `
                        -Name "ExampleSetting" `
                        -DefaultValue 0
                    
                    if ($actualValue -eq 1) {
                        Write-Log -Level SUCCESS -Message "Registry setting verified" -Module "ModuleTemplate"
                        $result.VerificationPassed = $true
                    }
                    else {
                        $result.VerificationPassed = $false
                        $result.Errors += "Verification failed: Registry setting not applied correctly"
                        Write-Log -Level ERROR -Message "Verification failed" -Module "ModuleTemplate"
                    }
                }
            }
            
            # ========================================
            # PHASE 4: RESTORE (Only if errors occurred)
            # ========================================
            if ($result.Errors.Count -gt 0 -and -not $DryRun) {
                Write-Log -Level WARNING -Message "PHASE 4: Errors detected, initiating rollback" -Module "ModuleTemplate"
                
                # Restore from backup would go here
                # This is handled by the Rollback.ps1 module
                Write-Log -Level INFO -Message "Run Restore-AllBackups to undo changes" -Module "ModuleTemplate"
            }
            
        }
        catch {
            $result.Success = $false
            $result.Errors += $_.Exception.Message
            Write-Log -Level ERROR -Message "Module execution failed" -Module "ModuleTemplate" -Exception $_
        }
    }
    
    end {
        # Final status
        if ($result.Errors.Count -eq 0) {
            Write-Log -Level SUCCESS -Message "ModuleTemplate completed successfully" -Module "ModuleTemplate"
            $result.Success = $true
        }
        else {
            Write-Log -Level ERROR -Message "ModuleTemplate completed with errors" -Module "ModuleTemplate"
            $result.Success = $false
        }
        
        Write-Log -Level INFO -Message "Changes applied: $($result.ChangesApplied)" -Module "ModuleTemplate"
        Write-Log -Level INFO -Message "Errors: $($result.Errors.Count)" -Module "ModuleTemplate"
        Write-Log -Level INFO -Message "Warnings: $($result.Warnings.Count)" -Module "ModuleTemplate"
        
        return $result
    }
}
