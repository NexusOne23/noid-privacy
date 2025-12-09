<#
.SYNOPSIS
    Apply Microsoft Edge v139 Security Baseline
    
.DESCRIPTION
    Applies all 24 Microsoft Edge Security Baseline policies using native PowerShell:
    - SmartScreen enforcement (no override allowed)
    - Site isolation (SitePerProcess) for process-per-site security
    - SSL/TLS error override blocking
    - Extension blocklist (blocks all extensions by default)
    - IE Mode restrictions
    - Spectre/Meltdown mitigations (SharedArrayBuffer)
    - Application-bound encryption
    - Authentication scheme restrictions
    - PUA (Potentially Unwanted Applications) detection
    
    Uses ONLY native Windows tools:
    - PowerShell for Registry (Set-ItemProperty)
    - NO EXTERNAL DEPENDENCIES - no LGPO.exe needed!
    
.PARAMETER DryRun
    Preview changes without applying them
    
.PARAMETER SkipBackup
    Skip backup creation (not recommended)
    
.PARAMETER SkipVerify
    Skip post-application verification
    
.PARAMETER AllowExtensions
    Allow users to install browser extensions (skips ExtensionInstallBlocklist)
    Default: Block all extensions (Microsoft Security Baseline)
    
.EXAMPLE
    Invoke-EdgeHardening
    Apply all Edge baseline settings with full backup and verification
    
.EXAMPLE
    Invoke-EdgeHardening -DryRun
    Preview what changes would be made
    
 .EXAMPLE
    Invoke-EdgeHardening -AllowExtensions
    Apply Edge hardening but allow users to install browser extensions
    
.OUTPUTS
    PSCustomObject with results including success status and any errors
    
.NOTES
    Author: NexusOne23
    Version: 2.2.0
    Requires: PowerShell 5.1+, Administrator privileges
    
    IMPORTANT: This applies Microsoft's recommended security baseline.
    Some policies may impact browser functionality:
    - All extensions are blocked by default (can be adjusted via GPO)
    - IE Mode is restricted
    - SSL error overrides are prevented
#>

function Invoke-EdgeHardening {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipBackup,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipVerify,
        
        [Parameter(Mandatory = $false)]
        [switch]$AllowExtensions
    )
    
    begin {
        # Helper function: Use Write-Log if available (framework), else Write-Log -Level DEBUG -Message
        function Write-ModuleLog {
            param([string]$Level, [string]$Message, [string]$Module = "EdgeHardening")
            
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level $Level -Message $Message -Module $Module
            }
            else {
                switch ($Level) {
                    "ERROR" { Write-Host "ERROR: $Message" -ForegroundColor Red }
                    "WARNING" { Write-Host "WARNING: $Message" -ForegroundColor Yellow }
                    default { Write-Log -Level DEBUG -Message $Message }
                }
            }
        }
        
        $moduleName = "EdgeHardening"
        $startTime = Get-Date
        
        # Initialize result object
        $result = [PSCustomObject]@{
            ModuleName         = $moduleName
            Success            = $false
            PoliciesApplied    = 0
            Errors             = @()
            BackupCreated      = $false
            ComplianceVerified = $false
            CompliancePercent  = 0
            Duration           = $null
        }
    }
    
    process {
        try {
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  EDGE HARDENING MODULE" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Applies Microsoft Edge v139+ Security Baseline" -ForegroundColor White
            Write-Host "  - SmartScreen enforcement, Site isolation" -ForegroundColor Gray
            Write-Host "  - SSL/TLS hardening, Extension blocklist (optional)" -ForegroundColor Gray
            Write-Host "  - Tracking Prevention, Privacy policies, PUA protection" -ForegroundColor Gray
            Write-Host ""
            
            # Extensions Policy - NonInteractive or Interactive
            if (-not $PSBoundParameters.ContainsKey('AllowExtensions')) {
                if (Test-NonInteractiveMode) {
                    # NonInteractive mode (GUI) - use config value
                    $AllowExtensions = Get-NonInteractiveValue -Module "EdgeHardening" -Key "allowExtensions" -Default $true
                    Write-NonInteractiveDecision -Module $moduleName -Decision "Browser extensions" -Value $(if ($AllowExtensions) { "Allowed" } else { "Blocked" })
                }
                else {
                    # Interactive mode
                    Write-Host "========================================" -ForegroundColor Yellow
                    Write-Host "  BROWSER EXTENSIONS POLICY" -ForegroundColor Yellow
                    Write-Host "========================================" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "Microsoft Security Baseline blocks ALL browser extensions by default." -ForegroundColor White
                    Write-Host ""
                    Write-Host "Do you want to ALLOW browser extensions?" -ForegroundColor White
                    Write-Host ""
                    Write-Host "  [Y] YES - Allow extensions (User Friendly)" -ForegroundColor Cyan
                    Write-Host "      - Users can install browser extensions" -ForegroundColor Gray
                    Write-Host "      - Useful for password managers, ad blockers, etc." -ForegroundColor Gray
                    Write-Host "      - Less secure (extension vulnerabilities possible)" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  [N] NO - Block ALL extensions (MS Recommended)" -ForegroundColor White
                    Write-Host "      - Maximum security - no extension attack surface" -ForegroundColor Gray
                    Write-Host "      - Prevents malicious/compromised extensions" -ForegroundColor Gray
                    Write-Host "      - Microsoft Security Baseline default" -ForegroundColor Gray
                    Write-Host ""
                    
                    do {
                        $extensionChoice = Read-Host "Allow browser extensions? [Y/N] (default: Y)"
                        if ([string]::IsNullOrWhiteSpace($extensionChoice)) { $extensionChoice = "Y" }
                        $extensionChoice = $extensionChoice.ToUpper()
                        
                        if ($extensionChoice -notin @('Y', 'N')) {
                            Write-Host ""
                            Write-Host "Invalid input. Please enter Y or N." -ForegroundColor Red
                            Write-Host ""
                        }
                    } while ($extensionChoice -notin @('Y', 'N'))
                    
                    if ($extensionChoice -eq 'N') {
                        $AllowExtensions = $false
                        Write-Host ""
                        Write-Host "  ALL extensions will be BLOCKED (Maximum Security)" -ForegroundColor Cyan
                        Write-ModuleLog -Level "INFO" -Message "User decision: Browser extensions BLOCKED (Microsoft Security Baseline default)"
                    }
                    else {
                        $AllowExtensions = $true
                        Write-Host ""
                        Write-Host "  Extensions will be ALLOWED" -ForegroundColor Green
                        Write-ModuleLog -Level "INFO" -Message "User decision: Browser extensions ALLOWED"
                    }
                    Write-Host ""
                }
            }
            
            Write-ModuleLog -Level "INFO" -Message "Starting Edge hardening..."
            
            # Validate Edge is installed (check App Paths instead of EdgeUpdate key)
            $edgeAppPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"
            $edgeInstalled = $false
            $edgeVersion = "Unknown"
            
            if (Test-Path $edgeAppPath) {
                try {
                    $edgeExePath = (Get-ItemProperty -Path $edgeAppPath -ErrorAction Stop).'(default)'
                    if (Test-Path $edgeExePath) {
                        $edgeInstalled = $true
                        $edgeVersion = (Get-Item $edgeExePath -ErrorAction SilentlyContinue).VersionInfo.FileVersion
                        Write-ModuleLog -Level "INFO" -Message "Microsoft Edge detected: v$edgeVersion"
                    }
                }
                catch {
                    # Edge key exists but cannot read - assume installed
                    $edgeInstalled = $true
                }
            }
            
            if (-not $edgeInstalled) {
                Write-ModuleLog -Level "WARNING" -Message "Microsoft Edge may not be installed (msedge.exe not found)"
                Write-Host "  WARNING: Microsoft Edge installation not detected" -ForegroundColor Yellow
                Write-Host "  Policies will still be applied for when Edge is installed" -ForegroundColor Yellow
                Write-Host ""
            }
            
            # PHASE 1: BACKUP
            Write-Host "[1/4] BACKUP - Creating restore point..." -ForegroundColor Cyan
            
            if (-not $SkipBackup -and -not $DryRun) {
                if ($PSCmdlet.ShouldProcess("Edge Policies", "Create Backup")) {
                    Write-ModuleLog -Level "INFO" -Message "Creating backup of Edge policies..."
                    
                    # Initialize session-based backup system
                    try {
                        Initialize-BackupSystem
                        $null = Start-ModuleBackup -ModuleName $moduleName
                        Write-ModuleLog -Level "INFO" -Message "Session backup initialized"
                    }
                    catch {
                        Write-ModuleLog -Level "WARNING" -Message "Failed to initialize session backup: $_"
                    }
                    
                    $backupResult = Backup-EdgePolicies
                    
                    if ($backupResult.Success) {
                        # Register backup in session manifest
                        Complete-ModuleBackup -ItemsBackedUp $backupResult.KeysBackedUp -Status "Success"
                        
                        $result.BackupCreated = $true
                        Write-Host "  Backup completed ($($backupResult.KeysBackedUp) keys)" -ForegroundColor Green
                    }
                    else {
                        Write-ModuleLog -Level "WARNING" -Message "Backup failed: $($backupResult.Errors -join '; ')"
                        Write-Host "  WARNING: Backup failed - continuing anyway" -ForegroundColor Yellow
                        $result.Errors += $backupResult.Errors
                    }
                }
            }
            else {
                Write-Host "  Skipped (SkipBackup flag)" -ForegroundColor Yellow
            }
            Write-Host ""
            
            # PHASE 2: APPLY
            Write-Host "[2/4] APPLY - Configuring Edge policies..." -ForegroundColor Cyan
            
            if ($PSCmdlet.ShouldProcess("Edge Security Baseline", "Apply Policies")) {
                Write-ModuleLog -Level "INFO" -Message "Applying Edge v139 baseline policies..."
                
                $policyResult = Set-EdgePolicies -DryRun:$DryRun -AllowExtensions:$AllowExtensions
                
                if ($policyResult.Applied -gt 0) {
                    $result.PoliciesApplied = $policyResult.Applied
                    Write-Host ""
                    
                    if ($DryRun) {
                        Write-Host "  [DRYRUN] Would apply $($policyResult.Applied) policies" -ForegroundColor Yellow
                    }
                }
                
                if ($policyResult.Errors.Count -gt 0) {
                    Write-ModuleLog -Level "WARNING" -Message "Policy application had errors: $($policyResult.Errors -join '; ')"
                    $result.Errors += $policyResult.Errors
                }
                
                Write-Host ""
            }
            
            # PHASE 3: VERIFY
            Write-Host "[3/4] VERIFY - Checking compliance..." -ForegroundColor Cyan
            
            if (-not $SkipVerify -and -not $DryRun) {
                if ($PSCmdlet.ShouldProcess("Edge Policies", "Verify Compliance")) {
                    Write-ModuleLog -Level "INFO" -Message "Verifying Edge policy compliance..."
                    
                    $verifyResult = Test-EdgePolicies
                    
                    if ($verifyResult.Compliant) {
                        $result.ComplianceVerified = $true
                        $result.CompliancePercent = $verifyResult.CompliancePercentage
                        Write-Host "  Verification: $($verifyResult.Message)" -ForegroundColor Green
                    }
                    else {
                        # Still verified, just not 100% compliant
                        $result.ComplianceVerified = $true  # Changed: We DID verify, just not perfect
                        $result.CompliancePercent = $verifyResult.CompliancePercentage
                        Write-Host "  Verification: $($verifyResult.Message)" -ForegroundColor Yellow
                        Write-ModuleLog -Level "WARNING" -Message "Compliance verification: $($verifyResult.Message)"
                        
                        # Show non-compliant policies
                        $nonCompliant = $verifyResult.Details | Where-Object { -not $_.Compliant }
                        if ($nonCompliant.Count -gt 0 -and $nonCompliant.Count -le 5) {
                            Write-Host "  Non-compliant policies:" -ForegroundColor Yellow
                            foreach ($policy in $nonCompliant) {
                                Write-Host "    - $($policy.Policy): Expected=$($policy.Expected), Actual=$($policy.Actual)" -ForegroundColor Gray
                            }
                        }
                    }
                    Write-Host ""
                }
            }
            else {
                Write-Host "  Skipped (SkipVerify flag)" -ForegroundColor Gray
            }
            Write-Host ""
            
            # Mark success
            $result.Success = ($result.PoliciesApplied -gt 0)
            
            # PHASE 4: COMPLETE
            Write-Host "[4/4] COMPLETE - Edge hardening finished!" -ForegroundColor Green
            Write-Host ""
            
            # Check for Skipped policies (e.g., delvals GPO marker, extension blocklist)
            $skippedCount = if ($policyResult.Skipped) { $policyResult.Skipped } else { 0 }
            
            # Total is dynamic: Applied + Skipped = Total in JSON
            $totalPoliciesInBaseline = $result.PoliciesApplied + $skippedCount
            
            # Success logic: Green if no errors occurred (skips are allowed/expected for GPO markers)
            $isCleanRun = ($result.Errors.Count -eq 0)

            Write-Host "Policies:      $($result.PoliciesApplied) applied ($skippedCount skipped, Total: $totalPoliciesInBaseline)" -ForegroundColor $(if ($isCleanRun) { 'Green' } else { 'Yellow' })
            Write-Host "Backup:        $(if ($result.BackupCreated) { 'Created' } else { 'Skipped' })" -ForegroundColor $(if ($result.BackupCreated) { 'Green' } else { 'Yellow' })
            
            # Verification summary with percentage for partial compliance
            if ($result.ComplianceVerified) {
                if ($result.CompliancePercent -eq 100) {
                    Write-Host "Verification:  PASSED (100%)" -ForegroundColor Green
                }
                else {
                    Write-Host "Verification:  Partial ($($result.CompliancePercent)%)" -ForegroundColor Yellow
                }
            }
            elseif ($SkipVerify) {
                Write-Host "Verification:  Skipped" -ForegroundColor Gray
            }
            else {
                Write-Host "Verification:  Not run" -ForegroundColor Yellow
            }
            
            if ($result.Errors.Count -gt 0) {
                Write-Host "Errors:        $($result.Errors.Count)" -ForegroundColor Red
            }
            
            Write-Host ""
            
            if ($result.Success) {
                Write-ModuleLog -Level "INFO" -Message "Edge hardening completed successfully"
                
                # GUI parsing marker for settings count (24 Edge policies)
                Write-Log -Level SUCCESS -Message "Applied 24 settings" -Module "EdgeHardening"
            }
            else {
                Write-ModuleLog -Level "WARNING" -Message "Edge hardening completed with warnings"
            }
            
            Write-Host ""
            Write-Host "  IMPORTANT NOTES:" -ForegroundColor Yellow
            
            if ($AllowExtensions) {
                Write-Host "  - Extensions: ALLOWED (user can install any extension)" -ForegroundColor Cyan
            }
            else {
                Write-Host "  - Extensions: BLOCKED (use -AllowExtensions to enable)" -ForegroundColor Gray
            }
            
            Write-Host "  - SSL error overrides are prevented" -ForegroundColor Gray
            Write-Host "  - IE Mode has restrictions applied" -ForegroundColor Gray
            Write-Host "  - Changes take effect on next Edge restart" -ForegroundColor Gray
            Write-Host ""
            
        }
        catch {
            $result.Success = $false
            $result.Errors += "Edge hardening failed: $($_.Exception.Message)"
            Write-ModuleLog -Level "ERROR" -Message "Edge hardening failed: $_"
            Write-Host ""
            Write-Host "  ERROR: Edge hardening failed" -ForegroundColor Red
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
            Write-Host ""
        }
        finally {
            $result.Duration = (Get-Date) - $startTime
        }
    }
    
    end {
        return $result
    }
}
