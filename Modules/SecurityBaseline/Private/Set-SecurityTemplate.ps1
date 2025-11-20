<#
.SYNOPSIS
    Apply security template settings from parsed Security Baseline JSON
    
.DESCRIPTION
    Converts JSON security template to INF format and applies via secedit.exe.
    Handles:
    - Password Policies
    - Account Policies  
    - User Rights Assignments
    - Security Options
    - Event Log Settings
    - Registry Values (security-related)
    
.PARAMETER SecurityTemplatePath
    Path to SecurityTemplates.json
    
.PARAMETER DryRun
    Preview changes without applying
    
.OUTPUTS
    PSCustomObject with success status and errors
    
.NOTES
    Requires Administrator privileges
    Uses secedit.exe (built into Windows since Windows 2000)
#>

function Set-SecurityTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SecurityTemplatePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    $result = [PSCustomObject]@{
        Success = $false
        SectionsApplied = 0
        SettingsApplied = 0
        Errors = @()
    }
    
    if (-not (Test-Path $SecurityTemplatePath)) {
        $result.Errors += "Security template file not found: $SecurityTemplatePath"
        return $result
    }
    
    try {
        $templates = Get-Content -Path $SecurityTemplatePath -Raw | ConvertFrom-Json
        
        # Merge all GPO templates into one master INF
        $infContent = @()
        $infContent += "[Unicode]"
        $infContent += "Unicode=yes"
        $infContent += ""
        $infContent += "[Version]"
        $infContent += "signature=`"`$CHICAGO$`""
        $infContent += "Revision=1"
        $infContent += ""
        
        # Track which sections we have
        $sectionsProcessed = @{}
        
        # Process each GPO's security template
        foreach ($gpoName in ($templates.PSObject.Properties.Name)) {
            $gpoTemplate = $templates.$gpoName
            
            foreach ($sectionName in ($gpoTemplate.PSObject.Properties.Name)) {
                # Skip metadata sections
                if ($sectionName -in @("Unicode", "Version")) {
                    continue
                }
                
                $section = $gpoTemplate.$sectionName
                
                if (-not $sectionsProcessed.ContainsKey($sectionName)) {
                    $sectionsProcessed[$sectionName] = @()
                }
                
                # Add settings from this section
                foreach ($key in ($section.PSObject.Properties.Name)) {
                    $value = $section.$key
                    
                    # Service General Setting requires special format per MS-GPSB 2.2.8
                    # Format: "ServiceName",StartupMode,""
                    # StartupMode: 2=Automatic, 3=Manual, 4=Disabled
                    if ($sectionName -eq 'Service General Setting') {
                        # Parse StartupType from value (e.g., "StartupType=Disabled")
                        $startupMode = 4  # Default: Disabled
                        if ($value -match 'StartupType=(\w+)') {
                            $startupType = $matches[1]
                            switch ($startupType) {
                                'Disabled'  { $startupMode = 4 }
                                'Manual'    { $startupMode = 3 }
                                'Automatic' { $startupMode = 2 }
                                default     { $startupMode = 4 }
                            }
                        }
                        
                        # Microsoft INF format: "ServiceName",Mode,""
                        $settingLine = "`"$key`",$startupMode,`"`""
                    }
                    else {
                        # Standard format for other sections
                        # Values are used directly from JSON as they are already in correct MS INF format
                        # Examples:
                        #   ScRemoveOption: 1,"1" (REG_SZ with string "1")
                        #   RestrictRemoteSAM: 1,"O:BAG:BAD:(A;;RC;;;BA)" (REG_SZ with SDDL)
                        #   EnableInstallerDetection: 4,1 (REG_DWORD with value 1)
                        
                        # Format: Key = Value
                        $settingLine = "$key = $value"
                    }
                    
                    # Avoid duplicates
                    if ($sectionsProcessed[$sectionName] -notcontains $settingLine) {
                        $sectionsProcessed[$sectionName] += $settingLine
                    }
                }
            }
        }
        
        # Write all sections in Microsoft INF required order
        # Order matters! secedit expects sections in specific sequence
        $sectionOrder = @(
            'System Access',
            'Event Audit',
            'Registry Values',
            'Privilege Rights',
            'Service General Setting'
        )
        
        foreach ($sectionName in $sectionOrder) {
            if ($sectionsProcessed.ContainsKey($sectionName)) {
                $infContent += "[$sectionName]"
                $infContent += $sectionsProcessed[$sectionName]
                $infContent += ""
                
                $result.SectionsApplied++
                $result.SettingsApplied += $sectionsProcessed[$sectionName].Count
            }
        }
        
        # Write any remaining sections not in standard order (safety net)
        foreach ($sectionName in $sectionsProcessed.Keys) {
            if ($sectionName -notin $sectionOrder) {
                $infContent += "[$sectionName]"
                $infContent += $sectionsProcessed[$sectionName]
                $infContent += ""
                
                $result.SectionsApplied++
                $result.SettingsApplied += $sectionsProcessed[$sectionName].Count
            }
        }
        
        Write-Log -Level DEBUG -Message "Generated security template: $($result.SectionsApplied) sections, $($result.SettingsApplied) settings" -Module "SecurityBaseline"
        
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Security template content:" -Module "SecurityBaseline"
            $infContent | ForEach-Object { Write-Log -Level DEBUG -Message "  $_" -Module "SecurityBaseline" }
            $result.Success = $true
            return $result
        }
        
        # Initialize temp file paths
        $tempInf = $null
        $dbFile = $null
        $logFile = $null
        
        try {
            # Save to temporary INF file
            $tempInf = Join-Path $env:TEMP "SecurityBaseline_$(Get-Date -Format 'yyyyMMddHHmmss').inf"
            $infContent | Out-File -FilePath $tempInf -Encoding unicode -Force
            
            Write-Log -Level DEBUG -Message "Applying security template via secedit.exe..." -Module "SecurityBaseline"
            
            # Apply via secedit
            $dbFile = Join-Path $env:TEMP "secedit_$(Get-Date -Format 'yyyyMMddHHmmss').sdb"
            $logFile = Join-Path $env:TEMP "secedit_$(Get-Date -Format 'yyyyMMddHHmmss').log"
            
            $seceditArgs = @(
                "/configure",
                "/db", "`"$dbFile`"",
                "/cfg", "`"$tempInf`"",
                "/log", "`"$logFile`"",
                "/quiet"
            )
            
            $process = Start-Process -FilePath "secedit.exe" `
                                     -ArgumentList $seceditArgs `
                                     -Wait `
                                     -NoNewWindow `
                                     -PassThru
            
            if ($process.ExitCode -eq 0) {
                $result.Success = $true
                Write-Log -Level DEBUG -Message "Security template applied successfully" -Module "SecurityBaseline"
            }
            if ($process.ExitCode -ne 0) {
                $stderr = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
                $result.Errors += "secedit failed with exit code $($process.ExitCode): $stderr"
                Write-Log -Level DEBUG -Message "secedit failed: $stderr" -Module "SecurityBaseline"
                
                # On error: Save INF and log to Desktop for debugging
                $debugInf = Join-Path ([Environment]::GetFolderPath("Desktop")) "SecurityBaseline_ERROR.inf"
                $debugLog = Join-Path ([Environment]::GetFolderPath("Desktop")) "secedit_ERROR.log"
                Copy-Item $tempInf $debugInf -Force -ErrorAction SilentlyContinue
                Copy-Item $logFile $debugLog -Force -ErrorAction SilentlyContinue
                Write-Log -Level DEBUG -Message "Error files saved to Desktop for debugging" -Module "SecurityBaseline"
            }
        }
        catch {
            $result.Errors += "Security template application failed: $($_.Exception.Message)"
            Write-Log -Level DEBUG -Message "Security template application failed: $_" -Module "SecurityBaseline"
        }
        finally {
            # ALWAYS cleanup temp files (even on error)
            if ($tempInf -and (Test-Path $tempInf)) {
                Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
            }
            if ($dbFile -and (Test-Path $dbFile)) {
                Remove-Item $dbFile -Force -ErrorAction SilentlyContinue
            }
            if ($logFile -and (Test-Path $logFile)) {
                Remove-Item $logFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        # Outer catch for JSON parsing or INF generation errors
        $result.Errors += "Failed to process security template: $($_.Exception.Message)"
        Write-Log -Level DEBUG -Message "Security template processing error: $_" -Module "SecurityBaseline"
    }
    
    return $result
}
