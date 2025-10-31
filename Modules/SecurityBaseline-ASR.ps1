# ============================================================================
# SecurityBaseline-ASR.ps1
# NoID Privacy - ASR Rules (Baseline 25H2 compliant)
# ============================================================================

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

function Set-AttackSurfaceReductionRules {
    <#
    .SYNOPSIS
        Configure Attack Surface Reduction Rules (ASR)
    .DESCRIPTION
        Sets 19 Microsoft-recommended ASR rules for Windows 11.
        ASR reduces the attack surface by blocking dangerous behaviors.
        Best Practice 25H2: Audit or Block Mode, CmdletBinding, ArrayList Performance.
    .PARAMETER Mode
        Audit = Logging only (recommended for testing)
        Enforce = Active blocking (production)
    .EXAMPLE
        Set-AttackSurfaceReductionRules -Mode Audit
    .EXAMPLE
        Set-AttackSurfaceReductionRules -Mode Enforce
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet('Audit', 'Enforce')]
        [string]$Mode = 'Audit'
    )
    
    Write-Section "Attack Surface Reduction (ASR) Rules"
    
    # Convert Mode to ASR Action Code
    # 0 = Disabled, 1 = Block, 2 = Audit, 6 = Warn
    # Best Practice 25H2: Enforce = Block Mode
    $asrMode = if ($Mode -eq 'Enforce') { 1 } else { 2 }
    
    Write-Info (Get-LocalizedString 'ASRMode' $Mode)
    if ($Mode -eq 'Audit') {
        Write-Warning-Custom "$(Get-LocalizedString 'ASRAuditWarning')"
        Write-Warning-Custom "$(Get-LocalizedString 'ASREvaluateLogs')"
    }
    
    # 19 ASR Rules (Microsoft Best Practice 25H2)
    $asrRules = @{
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = @{
            Name = "Block abuse of exploited vulnerable signed drivers"
            Mode = $asrMode
            Critical = $true
            Description = "Prevents abuse of signed but vulnerable drivers"
        }
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = @{
            Name = "Block Adobe Reader from creating child processes"
            Mode = $asrMode
            Critical = $false
            Description = "Adobe Reader may not start processes"
        }
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = @{
            Name = "Block all Office applications from creating child processes"
            Mode = $asrMode
            Critical = $true
            Description = "Office apps may not start processes (Anti-Macro-Malware)"
        }
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = @{
            Name = "Block credential stealing from LSASS"
            Mode = $asrMode
            Critical = $true
            Description = "Prevents credential dumping from LSASS (Mimikatz protection)"
        }
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = @{
            Name = "Block executable content from email and webmail"
            Mode = $asrMode
            Critical = $true
            Description = "Blocks executable files from emails"
        }
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = @{
            Name = "Block executable files unless they meet prevalence, age, or trusted list criteria"
            Mode = $asrMode
            Critical = $true
            Description = "Only known/trusted EXEs allowed"
        }
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = @{
            Name = "Block execution of potentially obfuscated scripts"
            Mode = $asrMode
            Critical = $true
            Description = "Blocks obfuscated scripts (PowerShell/VBS/JS)"
        }
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = @{
            Name = "Block Win32 API calls from Office macros"
            Mode = $asrMode
            Critical = $true
            Description = "Office macros may not call Win32 APIs"
        }
        "3b576869-a4ec-4529-8536-b80a7769e899" = @{
            Name = "Block Office apps from creating executable content"
            Mode = $asrMode
            Critical = $true
            Description = "Office may not create EXEs"
        }
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = @{
            Name = "Block Office apps from injecting into other processes"
            Mode = $asrMode
            Critical = $true
            Description = "Office may not inject into other processes"
        }
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = @{
            Name = "Block Office communication apps from creating child processes"
            Mode = $asrMode
            Critical = $false
            Description = "Outlook/Teams may not start processes"
        }
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = @{
            Name = "Block persistence through WMI event subscription"
            Mode = $asrMode
            Critical = $true
            Description = "Prevents persistence via WMI events"
        }
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = @{
            Name = "Block process creations from PSExec and WMI"
            Mode = $asrMode
            Critical = $true
            Description = "Block/Audit privilege escalation via PSExec/WMI"
        }
        "d3e037e1-3eb8-44c8-a917-57927947596d" = @{
            Name = "Block JavaScript or VBScript from launching downloaded executable content"
            Mode = $asrMode
            Critical = $true
            Description = "Block script-based downloads"
        }
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = @{
            Name = "Block untrusted and unsigned processes from USB"
            Mode = $asrMode
            Critical = $true
            Description = "Only signed programs from USB allowed"
        }
        "33ddedf1-c6e0-47cb-833e-de6133960387" = @{
            Name = "Block rebooting machine in Safe Mode"
            Mode = $asrMode
            Critical = $true
            Description = "Prevent ransomware Safe Mode boot"
        }
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = @{
            Name = "Block use of copied or impersonated system tools"
            Mode = $asrMode
            Critical = $true
            Description = "Block Living-off-the-Land"
        }
        "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = @{
            Name = "Block Webshell creation for Servers"
            Mode = $asrMode
            Critical = $false
            Description = "Webshell Prevention (Server)"
        }
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = @{
            Name = "Use advanced protection against ransomware"
            Mode = $asrMode
            Critical = $true
            Description = "Controlled Folder Access (Anti-Ransomware)"
        }
    }
    
    # CRITICAL FIX: Defender Service MUST be running!
    # CRITICAL CHECK: Is Windows Defender even available?
    Write-Verbose "$(Get-LocalizedString 'ASRCheckingDefender')"
    try {
        [void](Get-MpComputerStatus -ErrorAction Stop)
        Write-Verbose "$(Get-LocalizedString 'ASRDefenderAvailable')"
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'ASRDefenderNotAvailable')"
        Write-Info "$(Get-LocalizedString 'ASRConfigSkipped')"
        return
    }
    
    Write-Verbose "$(Get-LocalizedString 'ASRCheckingService')"
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        if ($defenderService.Status -ne 'Running') {
            Write-Info "$(Get-LocalizedString 'ASRStartingService')"
            Start-Service -Name WinDefend -ErrorAction Stop
            # CRITICAL: 3 second delay for Defender initialization
            Write-Verbose "$(Get-LocalizedString 'ASRWaitingInit')"
            Start-Sleep -Seconds 3
            Write-Verbose "$(Get-LocalizedString 'ASRServiceStarted')"
        }
        else {
            # Service already running, but still wait briefly for stability
            Write-Verbose "$(Get-LocalizedString 'ASRWaitingStability')"
            Start-Sleep -Seconds 1
        }
    }
    catch {
        Write-Warning "$(Get-LocalizedString 'ASRServiceNotAvailable')"
        Write-Info "$(Get-LocalizedString 'ASRServiceSolution')"
        return
    }
    
    # Configure ASR rules
    try {
        # Check if ASR rules already exist (Null-Safe Check!)
        # CRITICAL FIX v1.7.6: SilentlyContinue instead of Stop prevents Transcript pollution
        $existingPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        # Check if property exists (Third-Party AV compatibility)
        $existingRulesCount = if ($existingPrefs -and 
                                  $existingPrefs.PSObject.Properties['AttackSurfaceReductionRules_Ids'] -and 
                                  $existingPrefs.AttackSurfaceReductionRules_Ids) { 
            $existingPrefs.AttackSurfaceReductionRules_Ids.Count 
        } else { 
            0 
        }
        
        if ($existingRulesCount -gt 0) {
            Write-Warning-Custom (Get-LocalizedString 'ASRExistingRules' $existingRulesCount)
            Write-Warning-Custom "$(Get-LocalizedString 'ASRWillOverwrite')"
        }
        
        # Use ArrayList for better performance (O(1) instead of O(n) with +=)
        $asrIdsList = [System.Collections.ArrayList]::new()
        $asrActionsList = [System.Collections.ArrayList]::new()
        
        foreach ($ruleGuid in $asrRules.Keys) {
            $rule = $asrRules[$ruleGuid]
            # ArrayList.Add() returns index - suppress output with $null =
            $null = $asrIdsList.Add($ruleGuid)
            $null = $asrActionsList.Add($rule.Mode)
            
            $modeText = switch ($rule.Mode) {
                0 { "Disabled" }
                1 { "Block" }
                2 { "Audit" }
                6 { "Warn" }
            }
            
            $criticalMarker = if ($rule.Critical) { "[CRITICAL]" } else { "" }
            Write-Verbose "     $($rule.Name) : $modeText $criticalMarker"
            Write-Verbose "     $($rule.Description)"
        }
        
        # Convert ArrayList to Array for Set-MpPreference
        # Explicit type cast to avoid type mismatch - Best Practice 25H2
        $asrIds = [string[]]$asrIdsList.ToArray()
        $asrActions = [int[]]$asrActionsList.ToArray()
        
        # Set all ASR rules in one batch (Set instead of Add for idempotency)
        # ErrorAction SilentlyContinue - ignore known 0x800106ba timing issue
        # CRITICAL: Suppress unwanted output (causes horizontal spam!)
        $null = Set-MpPreference -AttackSurfaceReductionRules_Ids $asrIds -AttackSurfaceReductionRules_Actions $asrActions -ErrorAction SilentlyContinue
        
        # Verify if ASR rules were really set
        $verifyMpPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        # Check if property exists before accessing Count (Third-Party AV compatibility)
        if ($verifyMpPrefs -and 
            $verifyMpPrefs.PSObject.Properties['AttackSurfaceReductionRules_Ids'] -and 
            $verifyMpPrefs.AttackSurfaceReductionRules_Ids -and 
            $verifyMpPrefs.AttackSurfaceReductionRules_Ids.Count -gt 0) {
            Write-Success (Get-LocalizedString 'ASRConfigured' $verifyMpPrefs.AttackSurfaceReductionRules_Ids.Count)
            Write-Info (Get-LocalizedString 'ASRModeSet' $Mode)
        }
        else {
            Write-Info "$(Get-LocalizedString 'ASRCannotSetScript')"
            Write-Info "$(Get-LocalizedString 'ASRPropertyNotFound')"
            Write-Info "$(Get-LocalizedString 'ASRManualActivation')"
            Write-Info "                    "
            Write-Info "$(Get-LocalizedString 'ASRReasonThirdParty')"
        }
        
        if ($Mode -eq 'Audit') {
            Write-Warning-Custom "$(Get-LocalizedString 'ASRAuditModeActive')"
            Write-Warning-Custom "$(Get-LocalizedString 'ASRSwitchToEnforce')"
        }
        
        # ASR Exclusions note
        Write-Info "$(Get-LocalizedString 'ASRExclusionsNote')"
        
    }
    catch {
        # Ignore known Defender timing issue (0x800106ba)
        # Functionality is still activated - error is cosmetic
        if ($_.Exception.Message -notmatch '0x800106ba') {
            Write-Info "$(Get-LocalizedString 'ASRCannotSetScript')"
            Write-Info "$(Get-LocalizedString 'ASRManualActivation')"
            Write-Info "                    "
            Write-Info "Grund: $($_.Exception.Message)"
            Write-Verbose "Tip: For conflicts with existing rules, delete them first with Remove-MpPreference"
        }
        else {
            Write-Verbose "Ignoring known Defender timing issue (0x800106ba)"
            Write-Verbose "ASR rules are still activated - error is cosmetic"
        }
    }
}

function Get-ASRRuleStatus {
    <#
    .SYNOPSIS
        Shows the status of all configured ASR rules
    .DESCRIPTION
        Retrieves the currently configured Attack Surface Reduction Rules.
        Best Practice 25H2: CmdletBinding + Null-Checks.
    .EXAMPLE
        Get-ASRRuleStatus
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "ASR Rules Status"
    
    try {
        # CRITICAL FIX v1.7.6: SilentlyContinue instead of Stop prevents Transcript pollution
        $mpPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        if (-not $mpPrefs) {
            Write-Warning "$(Get-LocalizedString 'ASRPreferencesError')"
            return
        }
        
        if (-not $mpPrefs.AttackSurfaceReductionRules_Ids -or $mpPrefs.AttackSurfaceReductionRules_Ids.Count -eq 0) {
            Write-Warning "$(Get-LocalizedString 'ASRNoRulesConfigured')"
            return
        }
        
        Write-Info (Get-LocalizedString 'ASRConfiguredRules' $mpPrefs.AttackSurfaceReductionRules_Ids.Count)
        
        for ($i = 0; $i -lt $mpPrefs.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $ruleId = $mpPrefs.AttackSurfaceReductionRules_Ids[$i]
            $ruleAction = $mpPrefs.AttackSurfaceReductionRules_Actions[$i]
            
            $actionText = switch ($ruleAction) {
                0 { "Disabled" }
                1 { "Block" }
                2 { "Audit" }
                6 { "Warn" }
                default { "Unknown ($ruleAction)" }
            }
            
            Write-Info "  [$actionText] $ruleId"
        }
    }
    catch {
        Write-Error-Custom "Fehler beim Abrufen der ASR-Regeln: $_"
    }
}

function Enable-USBDeviceControl {
    <#
    .SYNOPSIS
        Configure USB Device Control (Removable Storage Protection)
    .DESCRIPTION
        Prevents execution of files on USB sticks (BadUSB protection).
        Reading and writing remain allowed.
        Best Practice 25H2: CmdletBinding.
    .EXAMPLE
        Enable-USBDeviceControl
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "USB Device Control (Removable Storage Protection)"
    
    Write-Info "$(Get-LocalizedString 'USBConfiguring')"
    
    # ONLY forbid execution (NOT writing!)
    $removableDiskPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
    
    # Deny_Execute = 1 (forbid execution)
    Set-RegistryValue -Path $removableDiskPath -Name "Deny_Execute" -Value 1 -Type DWord -Description "USB: Deny execution"
    
    # Deny_Write = 0 (writing ALLOWED!)
    # DO NOT set! If key doesn't exist = allowed
    
    Write-Success "$(Get-LocalizedString 'USBActivated')"
    Write-Info "$(Get-LocalizedString 'USBNote')"
    Write-Warning-Custom "$(Get-LocalizedString 'USBProtection')"
}

function Enable-SmartAppControl {
    <#
    .SYNOPSIS
        Configure Smart App Control Policies
    .DESCRIPTION
        Sets policies for Smart App Control and SmartScreen.
        IMPORTANT: Smart App Control is activated automatically by Windows after evaluation.
        Best Practice 25H2: Do not force manually!
    .EXAMPLE
        Enable-SmartAppControl
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Smart App Control Policies"
    
    Write-Info "$(Get-LocalizedString 'SACConfiguring')"
    
    # Best Practice 25H2: Do NOT set Smart App Control manually!
    # WHY: Windows must activate SAC itself after Evaluation Period (7-14 days)
    # If we intervene here, it prevents automatic activation!
    
    # CHECK: Current Smart App Control status
    $sacPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\SmartAppControl"
    $sacStatus = Get-ItemProperty -Path $sacPath -Name "Enabled" -ErrorAction SilentlyContinue
    
    if ($sacStatus) {
        $statusText = switch ($sacStatus.Enabled) {
            0 { "Off (Disabled)" }
            1 { "Evaluation Mode (Learning)" }
            2 { "On (Enforcing)" }
            default { "Unknown" }
        }
        Write-Info (Get-LocalizedString 'SACStatus' $statusText)
    } else {
        Write-Info "$(Get-LocalizedString 'SACNotConfigured')"
    }
    
    # Force SmartScreen for Apps (independent of Smart App Control)
    $smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    Set-RegistryValue -Path $smartScreenPath -Name "SmartScreenEnabled" -Value "RequireAdmin" -Type String -Description "Enforce SmartScreen"
    
    Write-Success "$(Get-LocalizedString 'SACWindowsManages')"
    Write-Info "$(Get-LocalizedString 'SACEvaluationPeriod')"
    Write-Success "$(Get-LocalizedString 'SACSmartScreenActive')"
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
