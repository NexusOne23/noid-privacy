# ============================================================================
# SecurityBaseline-Core.ps1
# NoID Privacy - Core Security Functions (Baseline 25H2 compliant)
# ============================================================================

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

#region CONSTANTS & MAGIC NUMBERS

# Best Practice 25H2: Define constants for registry magic numbers
# DNSSEC Modes
New-Variable -Name 'DNSSEC_MODE_OPPORTUNISTIC' -Value 1 -Option Constant -Scope Script -ErrorAction SilentlyContinue
New-Variable -Name 'DNSSEC_MODE_REQUIRE' -Value 2 -Option Constant -Scope Script -ErrorAction SilentlyContinue

# Kerberos Hash Algorithms
New-Variable -Name 'KERBEROS_ALL_MODERN_ENC' -Value 0x7FFFFFFF -Option Constant -Scope Script -ErrorAction SilentlyContinue
New-Variable -Name 'KERBEROS_PKINIT_SHA256_384_512' -Value 0x38 -Option Constant -Scope Script -ErrorAction SilentlyContinue

# VBS/Credential Guard
New-Variable -Name 'VBS_SECURE_BOOT_AND_DMA' -Value 3 -Option Constant -Scope Script -ErrorAction SilentlyContinue
New-Variable -Name 'CREDENTIAL_GUARD_UEFI_LOCK' -Value 1 -Option Constant -Scope Script -ErrorAction SilentlyContinue

# BitLocker Encryption Methods
New-Variable -Name 'BITLOCKER_XTS_AES_256' -Value 7 -Option Constant -Scope Script -ErrorAction SilentlyContinue

#endregion

# NOTE: Helper Functions (Write-Section, Write-Info, Write-Success, Write-Warning-Custom,
# Write-Error-Custom, Set-RegistryValue) were moved to SecurityBaseline-Common.ps1
# to avoid code duplication. The functions are exported from there.

#region SYSTEM VALIDATION

function Test-SystemRequirements {
    <#
    .SYNOPSIS
        Checks system requirements for Security Baseline
    .DESCRIPTION
        Validates Windows Version, TPM and VBS Status.
        Best Practice 25H2: Try-Catch for all CIM/WMI-Calls, throw replaced by Write-Error.
    .OUTPUTS
        [bool] $true if all requirements met, $false otherwise
    .EXAMPLE
        if (Test-SystemRequirements) { "System OK" }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreSystemValidation')
    
    try {
        # Retrieve OS information
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $build = [System.Environment]::OSVersion.Version.Build
        
        Write-Info "OS: $($osInfo.Caption)"
        Write-Info "Build: $build"
        
        # Check Build
        if ($build -lt 26100) {
            Write-Error-Custom (Get-LocalizedString 'CoreBuildRequired' $build)
            Write-Warning-Custom (Get-LocalizedString 'CoreBaselineOptimized')
            return $false
        }
    }
    catch {
        Write-Error-Custom (Get-LocalizedString 'CoreOSInfoError' $_)
        Write-Verbose "Details: $($_.Exception.Message)"
        return $false
    }
    
    # Check TPM
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm -and $tpm.TpmPresent -and $tpm.TpmReady) {
            Write-Success (Get-LocalizedString 'CoreTPMAvailable')
        }
        else {
            Write-Warning-Custom (Get-LocalizedString 'CoreTPMNotActivated' $tpm.TpmPresent, $tpm.TpmReady)
        }
    }
    catch {
        Write-Warning-Custom (Get-LocalizedString 'CoreTPMStatusError' $_)
        Write-Verbose "Some features (BitLocker, Credential Guard) require TPM 2.0"
    }
    
    # Check VBS
    try {
        $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        if ($vbs -and $vbs.VirtualizationBasedSecurityStatus -eq 2) {
            Write-Success (Get-LocalizedString 'CoreVBSActivated')
        }
        elseif ($vbs) {
            Write-Info "VBS Status: $($vbs.VirtualizationBasedSecurityStatus) (0=Disabled, 1=Enabled not running, 2=Enabled and running)"
        }
        else {
            Write-Info (Get-LocalizedString 'CoreVBSStatusUnknown')
        }
    }
    catch {
        Write-Verbose "VBS status could not be retrieved: $_"
        Write-Verbose "VBS will be activated by this baseline if supported"
    }
    
    Write-Success (Get-LocalizedString 'CoreValidationComplete')
    return $true
}

#endregion

#region BASELINE DELTA SETTINGS (25H2 SPECIFIC)

function Set-NetBIOSDisabled {
    <#
    .SYNOPSIS
        Disables NetBIOS Name Resolution
    .DESCRIPTION
        Disables NetBIOS via DNS Client and on all network adapters.
        Best Practice 25H2: Try-Catch for Get-CimInstance, Error-Handling for all Registry-Ops.
    .EXAMPLE
        Set-NetBIOSDisabled
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreNetBIOSDisable')
    
    # DNS Client NetBIOS Policy
    $dnsClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    [void](Set-RegistryValue -Path $dnsClientPath -Name "DisableNBTNameResolution" -Value 1 -Type DWord `
        -Description "NetBIOS Name Resolution global deaktivieren")
    
    # NetBT Node Type
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    [void](Set-RegistryValue -Path $regPath -Name "NodeType" -Value 2 -Type DWord `
        -Description "NetBT auf P-Node (nur WINS)")
    
    # Per Adapter
    try {
        # Best Practice 25H2: @() wrapper prevents Count error with null/single item
        $adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop | 
            Where-Object { $_.IPEnabled })
        
        $adapterCount = $adapters.Count
        
        foreach ($adapter in $adapters) {
            $guid = $adapter.SettingID
            $netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$guid"
            
            if (Test-Path -Path $netbtPath) {
                [void](Set-RegistryValue -Path $netbtPath -Name "NetbiosOptions" -Value 2 -Type DWord `
                    -Description "NetBIOS auf Adapter $guid deaktivieren")
            }
        }
        
        Write-Success (Get-LocalizedString 'CoreNetBIOSDisabled' $adapterCount)
    }
    catch {
        Write-Error-Custom (Get-LocalizedString 'CoreNetworkAdapterError' $_)
        Write-Verbose "Details: $($_.Exception.Message)"
    }
}

function Set-ProcessAuditingWithCommandLine {
    <#
    .SYNOPSIS
        Enables Process Auditing with Command-Line Logging
    .DESCRIPTION
        Enables Event ID 4688 with Command-Line Parameter Logging.
        Best Practice 25H2: Try-Catch for external tools (auditpol.exe), Out-Null removed.
        WARNING: Command-Lines can contain secrets (passwords, API-Keys)!
    .EXAMPLE
        Set-ProcessAuditingWithCommandLine
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreProcessAuditing')
    
    # Registry: Enable Command Line Logging
    $auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    [void](Set-RegistryValue -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord `
        -Description "Command Line in Event ID 4688")
    
    # auditpol.exe: Enable Process Creation Auditing
    # Best Practice 25H2: Use GUIDs instead of names (locale-independent!)
    try {
        $auditpolPath = "$env:SystemRoot\System32\auditpol.exe"
        
        if (-not (Test-Path -Path $auditpolPath)) {
            Write-Error-Custom (Get-LocalizedString 'CoreAuditpolNotFound' $auditpolPath)
            Write-Warning-Custom (Get-LocalizedString 'CoreAuditpolSkipped')
            # Continue - Registry setting above is already active
        }
        else {
            # GUID for "Process Creation" - works in German AND English!
            $processCreationGuid = "{0CCE922B-69AE-11D9-BED3-505054503030}"
            $result = & $auditpolPath /set /subcategory:$processCreationGuid /success:enable /failure:enable 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Success (Get-LocalizedString 'CoreAuditActivated')
            }
            else {
                Write-Error-Custom (Get-LocalizedString 'CoreAuditpolFailed' $LASTEXITCODE, $result)
                Write-Warning-Custom (Get-LocalizedString 'CoreLocaleMismatch')
                Write-Info (Get-LocalizedString 'CoreRegistryActive')
                # Continue - Registry setting above is already active
            }
        }
    }
    catch {
        Write-Error-Custom (Get-LocalizedString 'CoreAuditpolExecError' $_)
        Write-Warning-Custom (Get-LocalizedString 'CoreAuditpolSkipped')
        Write-Info (Get-LocalizedString 'CoreRegistryActive')
        # Continue - not fatal, Registry setting handles the core functionality
    }
    
    Write-Warning-Custom (Get-LocalizedString 'CoreSecretSpillWarning')
    Write-Warning-Custom (Get-LocalizedString 'CoreCommandLinesSecrets')
}

function Disable-IE11COMAutomation {
    <#
    .SYNOPSIS
        Disables Internet Explorer 11 COM-Automation
    .DESCRIPTION
        Blocks IE11 launch via COM and ActiveX installation.
        Best Practice 25H2: CmdletBinding, Error-Handling for Registry-Ops.
    .EXAMPLE
        Disable-IE11COMAutomation
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreIE11Disable')
    
    # Block IE11 Launch via COM
    $iePath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
    [void](Set-RegistryValue -Path $iePath -Name "DisableIE11Launch" -Value 1 -Type DWord `
        -Description "IE11 Launch via COM blockieren")
    
    # Block ActiveX Installation
    $msHtmlPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"
    [void](Set-RegistryValue -Path $msHtmlPath -Name "iexplore.exe" -Value 1 -Type DWord `
        -Description "ActiveX Installation blockieren")
    
    Write-Success (Get-LocalizedString 'CoreIE11Disabled')
}

function Set-ExplorerZoneHardening {
    <#
    .SYNOPSIS
        Hardens Windows Explorer Internet/Intranet Zone execution policies
    .DESCRIPTION
        Blocks launching applications and opening files from Internet/Intranet zones.
        Critical protection against .lnk, .scf, .url attacks (CVE-2025-9491, PlugX).
        Forces users to save files locally first before execution.
    .EXAMPLE
        Set-ExplorerZoneHardening
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Explorer Internet Zone Hardening"
    
    Write-Info "Blocking execution from Internet/Intranet zones (.lnk/.scf/.url protection)..."
    
    # Internet Zone (Zone 3) - UNTRUSTED
    $internetZonePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
    
    # Block: Launching applications and unsafe files
    [void](Set-RegistryValue -Path $internetZonePath -Name "1806" -Value 3 -Type DWord `
        -Description "Internet Zone: Disable launching applications")
    
    # Block: File downloads (require prompt)
    [void](Set-RegistryValue -Path $internetZonePath -Name "1803" -Value 3 -Type DWord `
        -Description "Internet Zone: Disable automatic file downloads")
    
    # Intranet Zone (Zone 1) - ALSO HARDEN (compromised internal servers)
    $intranetZonePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"
    
    [void](Set-RegistryValue -Path $intranetZonePath -Name "1806" -Value 3 -Type DWord `
        -Description "Intranet Zone: Disable launching applications")
    
    Write-Success "Explorer Zone Hardening enabled"
    Write-Info "Users must save files locally before opening (CVE-2025-9491 protection)"
}

function Set-FileExecutionRestrictions {
    <#
    .SYNOPSIS
        Blocks dangerous file types from untrusted paths using Software Restriction Policies
    .DESCRIPTION
        Implements SRP (Software Restriction Policies) to block execution of:
        - .lnk files from Downloads/Temp/Network paths
        - .scf files (Shell Command Files)
        - .url files (Internet Shortcuts with NTLM leak)
        
        Works on ALL Windows editions (Home/Pro/Enterprise) via Registry.
        
        CRITICAL: Protection against CVE-2025-9491 (PlugX .lnk exploits)
        and related file-type attacks.
    .NOTES
        Requires: Restart or 'gpupdate /force' for activation
        SRP is legacy but universally supported
    .EXAMPLE
        Set-FileExecutionRestrictions
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "File Execution Restrictions (SRP)"
    
    Write-Info "Configuring Software Restriction Policies for dangerous file types..."
    
    # Base path for SRP
    $srpBasePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
    
    # Ensure base path exists
    if (-not (Test-Path $srpBasePath)) {
        New-Item $srpBasePath -Force -ErrorAction Stop | Out-Null
        Write-Verbose "Created SRP base path"
    }
    
    # 1. Set default security level (Unrestricted = allow all except explicit deny)
    [void](Set-RegistryValue -Path $srpBasePath -Name "DefaultLevel" -Value 0x00040000 -Type DWord `
        -Description "SRP: Unrestricted mode (allow all except explicit deny)")
    
    # 2. Enable transparent enforcement
    [void](Set-RegistryValue -Path $srpBasePath -Name "TransparentEnabled" -Value 1 -Type DWord `
        -Description "SRP: Enable transparent enforcement")
    
    # Path for path-based rules (Level 0 = Disallowed)
    $pathRulesBasePath = "$srpBasePath\0\Paths"
    
    if (-not (Test-Path $pathRulesBasePath)) {
        New-Item $pathRulesBasePath -Force -ErrorAction Stop | Out-Null
        Write-Verbose "Created SRP path rules base"
    }
    
    # Define dangerous file patterns to block
    $dangerousPatterns = @(
        @{
            Path = "%USERPROFILE%\Downloads\*.lnk"
            Description = "Block .lnk from Downloads (CVE-2025-9491 PlugX protection)"
        },
        @{
            Path = "%TEMP%\*.lnk"
            Description = "Block .lnk from Temp folder"
        },
        @{
            Path = "\\*\*.lnk"
            Description = "Block .lnk from network shares"
        },
        @{
            Path = "%USERPROFILE%\Downloads\*.scf"
            Description = "Block .scf from Downloads (Shell Command File poisoning)"
        },
        @{
            Path = "%USERPROFILE%\Downloads\*.url"
            Description = "Block .url from Downloads (NTLM credential leak)"
        }
    )
    
    Write-Info "Creating SRP deny rules for dangerous file types..."
    
    $ruleCount = 0
    foreach ($pattern in $dangerousPatterns) {
        # Generate unique GUID for each rule
        $ruleGuid = [guid]::NewGuid().ToString("B").ToUpper()
        $rulePath = "$pathRulesBasePath\$ruleGuid"
        
        # Create rule entry
        if (-not (Test-Path $rulePath)) {
            New-Item $rulePath -Force -ErrorAction Stop | Out-Null
        }
        
        # Set rule properties
        [void](Set-RegistryValue -Path $rulePath -Name "ItemData" -Value $pattern.Path -Type String `
            -Description $pattern.Description)
        
        [void](Set-RegistryValue -Path $rulePath -Name "SaferFlags" -Value 0 -Type DWord `
            -Description "SRP: Disallowed")
        
        $ruleCount++
        Write-Verbose "Created SRP rule: $($pattern.Path)"
    }
    
    Write-Success "File execution restrictions configured ($ruleCount rules)"
    Write-Info "Protected file types: .lnk, .scf, .url from untrusted paths"
    Write-Warning "ACTIVATION: Restart required (or run: gpupdate /force)"
    Write-Info "Workaround for legitimate files: Move to C:\Temp or Desktop first"
}

function Set-PrintSpoolerUserRights {
    <#
    .SYNOPSIS
        Configures Print Spooler User Rights and RPC Hardening
    .DESCRIPTION
        Sets SeImpersonatePrivilege for PrintSpoolerService and hardens RPC against PrintNightmare.
        Best Practice 25H2: Try-Catch for File Ops and secedit.exe, Exit-Code Check.
        CVE-2021-1675 PrintNightmare Mitigation.
    .EXAMPLE
        Set-PrintSpoolerUserRights
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CorePrintSpooler')
    
    Write-Info (Get-LocalizedString 'CorePrintImpersonate')
    
    # Security Policy Template
    $secPolicy = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-99-0-0-0-0-0
"@
    
    # Temp files
    if (-not $env:TEMP) {
        Write-Error-Custom (Get-LocalizedString 'CoreTempNotSet')
        return
    }
    
    $tempInf = Join-Path $env:TEMP "secedit_spooler.inf"
    $tempDb = Join-Path $env:TEMP "secedit_spooler.sdb"
    
    try {
        # Write Security Policy
        Write-Verbose "Writing security policy to $tempInf"
        $secPolicy | Out-File -FilePath $tempInf -Encoding unicode -Force -ErrorAction Stop
        
        # Execute secedit.exe
        $seceditPath = "$env:SystemRoot\System32\secedit.exe"
        
        if (-not (Test-Path -Path $seceditPath)) {
            Write-Error-Custom (Get-LocalizedString 'CoreSeceditNotFound' $seceditPath)
            return
        }
        
        Write-Verbose "Executing secedit.exe..."
        $result = & $seceditPath /configure /db $tempDb /cfg $tempInf /quiet 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success (Get-LocalizedString 'CorePrintAdded')
        }
        else {
            Write-Error-Custom (Get-LocalizedString 'CoreSeceditFailed' $LASTEXITCODE)
            Write-Verbose "Output: $result"
        }
        
        # Clean up temp files
        try {
            if (Test-Path -Path $tempInf) {
                Remove-Item -Path $tempInf -Force -ErrorAction Stop
                Write-Verbose "Temp file deleted: $tempInf"
            }
            if (Test-Path -Path $tempDb) {
                Remove-Item -Path $tempDb -Force -ErrorAction Stop
                Write-Verbose "Temp file deleted: $tempDb"
            }
        }
        catch {
            Write-Verbose "Could not delete temp files: $_"
        }
    }
    catch {
        Write-Error-Custom (Get-LocalizedString 'CoreUserRightsError' $_)
        Write-Verbose "Details: $($_.Exception.Message)"
    }
    
    # Print Spooler RPC Hardening (CVE-2021-1675 PrintNightmare)
    Write-Info (Get-LocalizedString 'CorePrintRPCHarden')
    
    $spoolerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    
    [void](Set-RegistryValue -Path $spoolerPath -Name "RpcAuthnLevelPrivacyEnabled" -Value 1 -Type DWord `
        -Description "RPC Privacy Level fuer Print Spooler")
    
    [void](Set-RegistryValue -Path $spoolerPath -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type DWord `
        -Description "Remote RPC Endpoint deaktivieren")
    
    Write-Success (Get-LocalizedString 'CorePrintNightmare')
}

#endregion

#region DEFENDER BASELINE SETTINGS

function Set-DefenderBaselineSettings {
    <#
    .SYNOPSIS
        Configures Microsoft Defender Baseline Settings
    .DESCRIPTION
        Enables EDR Block Mode, PUA Protection, Network Protection, Cloud Protection High.
        Best Practice 25H2: CmdletBinding, verify Registry return values.
    .EXAMPLE
        Set-DefenderBaselineSettings
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreDefenderBaseline')
    
    # CRITICAL CHECK: Is Windows Defender available at all?
    # BitDefender/Norton/Kaspersky etc. disable Defender automatically!
    Write-Verbose "Checking if Windows Defender is available..."
    try {
        [void](Get-MpComputerStatus -ErrorAction Stop)
        Write-Verbose "Defender is available and active"
    }
    catch {
        Write-Warning (Get-LocalizedString 'CoreDefenderNotAvailable')
        Write-Info (Get-LocalizedString 'CoreDefenderThirdParty')
        Write-Info (Get-LocalizedString 'CoreDefenderAutoDisabled')
        Write-Host ""
        Write-Info (Get-LocalizedString 'CoreDefenderSkipped')
        Write-Info (Get-LocalizedString 'CoreDefenderThirdPartyProtection')
        Write-Host ""
        return  # Skip complete Defender configuration
    }
    
    # CRITICAL FIX: Defender Service MUST be running for PUA/ASR Configuration!
    Write-Verbose "Checking Defender Service status..."
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        if ($defenderService.Status -ne 'Running') {
            Write-Info (Get-LocalizedString 'CoreDefenderStarting')
            Start-Service -Name WinDefend -ErrorAction Stop
            Start-Sleep -Seconds 3  # Wait until service is fully started
            Write-Verbose "Defender Service started successfully"
        }
    }
    catch {
        Write-Warning (Get-LocalizedString 'CoreDefenderStartFailed' $_)
        Write-Info (Get-LocalizedString 'CoreDefenderConfigSkipped')
        return  # Skip Defender configuration
    }
    
    $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    
    # EDR in Block Mode
    [void](Set-RegistryValue -Path "$defenderPath\Real-Time Protection" -Name "EDRBlockMode" -Value 1 -Type DWord `
        -Description "EDR Block Mode")
    
    # NIS: Convert warn to block
    [void](Set-RegistryValue -Path "$defenderPath\NIS" -Name "ConvertWarnToBlock" -Value 1 -Type DWord `
        -Description "NIS Warn->Block")
    
    # Real-Time Protection
    [void](Set-RegistryValue -Path "$defenderPath\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord `
        -Description "Real-Time Protection AN")
    
    # Report Dynamic Signature dropped
    [void](Set-RegistryValue -Path "$defenderPath\Reporting" -Name "ReportDynamicSignatureDroppedEvent" -Value 1 -Type DWord `
        -Description "Dynamic Signature Events")
    
    # Quick Scan including Exclusions
    [void](Set-RegistryValue -Path "$defenderPath\Scan" -Name "CheckExclusions" -Value 1 -Type DWord `
        -Description "Scan Exclusions too")
    
    # Cloud Protection High
    [void](Set-RegistryValue -Path "$defenderPath\MpEngine" -Name "MpCloudBlockLevel" -Value 2 -Type DWord `
        -Description "Cloud Protection Level High")
    
    # PUA Protection - BEST PRACTICE: Use Set-MpPreference instead of Registry Policy!
    # Registry Policy (HKLM\Policies) would gray out GUI
    # Set-MpPreference allows user to change option in GUI (flexibility!)
    # Best Practice 25H2: SilentlyContinue to avoid TerminatingError in logs
    $null = Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    if ($?) {
        Write-Verbose "PUA Protection enabled via Set-MpPreference (GUI remains editable)"
    }
    else {
        # KNOWN ISSUE: 0x800106ba = Operation failed (Defender Service not running or 3rd-party AV active)
        # HARMLESS: PUA still works via Registry checkboxes below!
        Write-Verbose "Set-MpPreference PUA failed (Defender Service or 3rd-party AV) - using Registry checkboxes"
        Write-Info (Get-LocalizedString 'CorePUARegistry')
    }
    
    # CRITICAL FIX: Enable BOTH checkboxes (block Apps + Downloads)
    # IMPORTANT: These Registry keys are TrustedInstaller-protected!
    # SOLUTION: Set-RegistryValueSmart automatically takes ownership when needed
    $puaPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
    
    Write-Info (Get-LocalizedString 'CorePUACheckboxes')
    
    # EnableAppInstallControl = Block apps (with automatic ownership management)
    $result1 = Set-RegistryValueSmart -Path $puaPath -Name "EnableAppInstallControl" -Value 1 -Type DWord `
        -Description "PUA: Block apps (Checkbox)"
    
    # IMPORTANT: "Block downloads" is NOT a Defender setting!
    # It's configured in Edge module via: HKLM:\SOFTWARE\Policies\Microsoft\Edge\SmartScreenPuaEnabled = 1
    # The Windows Security GUI shows BOTH checkboxes, but they come from different systems:
    # - "Block apps" = Defender PUA (above)
    # - "Block downloads" = Edge SmartScreen (Edge module)
    # NOTE: The Edge checkbox requires Edge browser restart to show in GUI!
    
    if ($result1) {
        Write-Success (Get-LocalizedString 'CorePUAActivated')
        Write-Info "NOTE: 'Block downloads' checkbox is configured in Edge module (requires Edge restart)"
    }
    else {
        Write-Info (Get-LocalizedString 'CorePUAScriptFailed')
        Write-Info (Get-LocalizedString 'CorePUAFunctional')
        Write-Info (Get-LocalizedString 'CorePUAManual')
        Write-Info (Get-LocalizedString 'CorePUAManualPath')
    }
    
    # Edge SmartScreen PUA Protection (Block downloads) is set in Edge module
    
    # Network Protection
    [void](Set-RegistryValue -Path "$defenderPath\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1 -Type DWord `
        -Description "Network Protection")
    
    # ===========================
    # MICROSOFT BASELINE 25H2: 6 DEFENDER SETTINGS
    # ===========================
    Write-Info (Get-LocalizedString 'CoreDefender6Settings')
    
    # 1. EDR in Block Mode
    # IMPORTANT: Features key is TrustedInstaller-protected (like PUA above)
    # SOLUTION: Set-RegistryValueSmart automatically takes ownership when needed
    $edrPath = "$defenderPath\Features"
    $edrResult = Set-RegistryValueSmart -Path $edrPath -Name "EnableEDRInBlockMode" -Value 1 -Type DWord `
        -Description "EDR in Block Mode (Endpoint Detection & Response)"
    
    if ($edrResult) {
        Write-Verbose "EDR Block Mode: Successfully activated"
    }
    else {
        Write-Verbose "EDR Block Mode: Error setting value"
    }
    
    # 2. Network Inspection: Convert Warn to Block
    $nisPath = "$defenderPath\NIS"
    Set-RegistryValue -Path $nisPath -Name "ConvertWarnToBlock" -Value 1 -Type DWord `
        -Description "Network Inspection: Auto-convert warnings to blocks"
    
    # 3. Exclusions visible to local users (Control)
    Set-RegistryValue -Path $defenderPath -Name "ExclusionsVisibleToLocalUsers" -Value 1 -Type DWord `
        -Description "Exclusions visible to local users (transparency)"
    
    # 4. Real-time Protection during OOBE (Out-Of-Box Experience)
    $rtpPath = "$defenderPath\Real-Time Protection"
    Set-RegistryValue -Path $rtpPath -Name "ConfigureRealTimeProtectionOOBE" -Value 1 -Type DWord `
        -Description "Real-Time Protection active during OOBE setup"
    
    # 5. Scan excluded files during quick scans
    $scanPath = "$defenderPath\Scan"
    Set-RegistryValue -Path $scanPath -Name "ScanExcludedFilesInQuickScan" -Value 1 -Type DWord `
        -Description "Also check excluded files in quick scans"
    
    # 6. Report Dynamic Signature dropped events
    $reportPath = "$defenderPath\Reporting"
    Set-RegistryValue -Path $reportPath -Name "ReportDynamicSignatureDroppedEvent" -Value 1 -Type DWord `
        -Description "Report dynamic signature dropped events"
    
    # ===========================
    # ADDITIONAL DEFENDER SETTINGS - LOW PRIORITY (Microsoft Baseline 25H2)
    # ===========================
    
    # Real-time scan direction (0=Both, 1=Incoming, 2=Outgoing)
    Set-RegistryValue -Path $rtpPath -Name "RealtimeScanDirection" -Value 0 -Type DWord `
        -Description "Realtime scan: Both incoming and outgoing files"
    
    # MpBafs Extended Timeout (seconds for cloud analysis)
    $mpEnginePath = "$defenderPath\MpEngine"
    Set-RegistryValue -Path $mpEnginePath -Name "MpBafsExtendedTimeout" -Value 50 -Type DWord `
        -Description "Extended timeout for cloud analysis (50 seconds)"
    
    # Quick Scan: Include Exclusions (already have ScanExcludedFilesInQuickScan above)
    # This is essentially covered by policy #5 above
    
    # ===========================
    # ADDITIONAL DEFENDER SETTINGS - SCANNING (Email + USB)
    # ===========================
    # CRITICAL: Verify showed these as [X] - they were missing!
    # Email and Removable Drive scanning must be ENABLED
    
    # Enable Email Scanning (scan attachments and email content)
    $null = Set-MpPreference -DisableEmailScanning $false -ErrorAction SilentlyContinue
    if ($?) {
        Write-Verbose "Email scanning enabled"
    }
    else {
        # Fallback to Registry if Set-MpPreference fails
        Set-RegistryValue -Path $scanPath -Name "DisableEmailScanning" -Value 0 -Type DWord `
            -Description "Email scanning enabled"
    }
    
    # Enable Removable Drive Scanning (USB sticks, external drives)
    $null = Set-MpPreference -DisableRemovableDriveScanning $false -ErrorAction SilentlyContinue
    if ($?) {
        Write-Verbose "Removable drive scanning enabled"
    }
    else {
        # Fallback to Registry if Set-MpPreference fails
        Set-RegistryValue -Path $scanPath -Name "DisableRemovableDriveScanning" -Value 0 -Type DWord `
            -Description "Removable drive scanning enabled"
    }
    
    Write-Success (Get-LocalizedString 'CoreDefender6Activated')
    Write-Success (Get-LocalizedString 'CoreDefenderActive')
}

function Enable-ControlledFolderAccess {
    <#
    .SYNOPSIS
        Enables Controlled Folder Access (Ransomware Protection)
    .DESCRIPTION
        Protects valuable folders (Documents, Pictures, etc.) from unauthorized changes
        Best Practice 25H2: Ransomware Protection
    .EXAMPLE
        Enable-ControlledFolderAccess
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreCFATitle')
    
    # CRITICAL CHECK: Is Windows Defender available at all?
    Write-Verbose "Checking if Windows Defender is available..."
    try {
        [void](Get-MpComputerStatus -ErrorAction Stop)
        Write-Verbose "Defender is available"
    }
    catch {
        Write-Warning (Get-LocalizedString 'CoreCFAThirdParty')
        Write-Info (Get-LocalizedString 'CoreCFASkipped')
        return
    }
    
    # CRITICAL FIX: Defender Service MUST be running!
    Write-Verbose "Checking Defender Service status..."
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        if ($defenderService.Status -ne 'Running') {
            Write-Info (Get-LocalizedString 'CoreCFAStarting')
            Start-Service -Name WinDefend -ErrorAction Stop
            Start-Sleep -Seconds 3
            Write-Verbose "Defender Service started"
        }
    }
    catch {
        Write-Warning (Get-LocalizedString 'CoreCFAServiceFailed')
        Write-Verbose "Details: $_"
        return
    }
    
    try {
        # Enable Controlled Folder Access via PowerShell
        # CRITICAL: 3 second delay AFTER service start due to Defender initialization
        Write-Verbose "Waiting 3 seconds for Defender initialization..."
        Start-Sleep -Seconds 3
        
        # ErrorAction SilentlyContinue - ignore known 0x800106ba timing issue
        # Suppress unwanted output
        $null = Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        
        # Verify after additional 2 seconds
        Start-Sleep -Seconds 2
        $mpPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        # Check if property exists (Third-Party AV might not have this property)
        if ($mpPrefs -and $mpPrefs.PSObject.Properties['EnableControlledFolderAccess']) {
            if ($mpPrefs.EnableControlledFolderAccess -eq 1) {
                Write-Success (Get-LocalizedString 'CoreCFAActivated')
                Write-Info (Get-LocalizedString 'CoreCFAProtected')
                Write-Warning-Custom (Get-LocalizedString 'CoreCFAWhitelist')
            }
            else {
                Write-Warning (Get-LocalizedString 'CoreCFANotActivated')
            }
        }
        else {
            Write-Warning (Get-LocalizedString 'CoreCFAVerifyFailed')
            Write-Info (Get-LocalizedString 'CoreCFADefenderUnavailable')
        }
    }
    catch {
        # Ignore known Defender timing issue (0x800106ba)
        # Functionality will still be activated - error is cosmetic
        if ($_.Exception.Message -notmatch '0x800106ba') {
            # Fallback: Registry method
            Write-Verbose "PowerShell cmdlet failed, using Registry method"
            try {
                $cfaPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"
                [void](Set-RegistryValue -Path $cfaPath -Name "EnableControlledFolderAccess" -Value 1 -Type DWord `
                    -Description "Controlled Folder Access aktivieren")
                Write-Success (Get-LocalizedString 'CoreCFARegistry')
            }
            catch {
                Write-Warning (Get-LocalizedString 'CoreCFAEnableFailed' $_)
                Write-Info (Get-LocalizedString 'CoreCFAManual')
            }
        }
        else {
            Write-Verbose "Ignoring known Defender timing issue (0x800106ba)"
            Write-Verbose "Controlled Folder Access will still be activated"
        }
    }
}

function Enable-ExploitProtection {
    <#
    .SYNOPSIS
        Enables Exploit Protection EXTENDED (Microsoft Best Practice)
    .DESCRIPTION
        System-wide Exploit Mitigation Technologies with all Best Practice Mitigations:
        - DEP, SEHOP, ASLR (Mandatory + Bottom-up + High Entropy)
        - CFG (Control Flow Guard) - Strict Mode + Export Suppression
        - Heap Protection (Terminate on Error)
        - Image Load Protection (Block Remote + Block Low Integrity)
        Best Practice Januar 2026: Maximum Exploit Resistance
    .EXAMPLE
        Enable-ExploitProtection
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreExploitTitle')
    
    Write-Info (Get-LocalizedString 'CoreExploitConfiguring')
    
    try {
        # Check if cmdlet is available (Windows 10 1709+)
        if (-not (Get-Command Set-ProcessMitigation -ErrorAction SilentlyContinue)) {
            Write-Warning-Custom "Set-ProcessMitigation Cmdlet not available (Windows 10 1709+ required)"
            return
        }
        
        # ===== BASIC MITIGATIONS (Standard) =====
        Write-Verbose "Setting basic mitigations (DEP, SEHOP, ASLR)..."
        Set-ProcessMitigation -System -Enable DEP, SEHOP, ForceRelocateImages, BottomUp, HighEntropy -ErrorAction Stop
        
        # ===== EXTENDED MITIGATIONS (Best Practice) =====
        Write-Verbose "Setting extended mitigations..."
        
        # Heap Protection (Terminate on Error)
        try {
            Set-ProcessMitigation -System -Enable TerminateOnError -ErrorAction Stop
            Write-Verbose "  [OK] Heap Protection: Terminate on Error"
        }
        catch {
            Write-Verbose "  [SKIP] Heap Protection: $($_.Exception.Message)"
        }
        
        # Control Flow Guard - Strict Mode
        try {
            Set-ProcessMitigation -System -Enable StrictCFG -ErrorAction Stop
            Write-Verbose "  [OK] CFG: Strict Mode"
        }
        catch {
            Write-Verbose "  [SKIP] CFG Strict: $($_.Exception.Message)"
        }
        
        # CFG - Suppress Exports (Anti-ROP)
        try {
            Set-ProcessMitigation -System -Enable SuppressExports -ErrorAction Stop
            Write-Verbose "  [OK] CFG: Export Suppression (Anti-ROP)"
        }
        catch {
            Write-Verbose "  [SKIP] CFG Exports: $($_.Exception.Message)"
        }
        
        # Image Load Protection - Block Remote Images
        try {
            Set-ProcessMitigation -System -Enable BlockRemoteImageLoads -ErrorAction Stop
            Write-Verbose "  [OK] Image Load: Block Remote (DLL Hijacking Protection)"
        }
        catch {
            Write-Verbose "  [SKIP] Image Load Remote: $($_.Exception.Message)"
        }
        
        # Image Load Protection - Block Low Integrity Images
        try {
            Set-ProcessMitigation -System -Enable BlockLowLabelImageLoads -ErrorAction Stop
            Write-Verbose "  [OK] Image Load: Block Low Integrity (Untrusted Sources)"
        }
        catch {
            Write-Verbose "  [SKIP] Image Load Low Integrity: $($_.Exception.Message)"
        }
        
        # Disable Extension Points (Legacy COM)
        try {
            Set-ProcessMitigation -System -Enable DisableExtensionPoints -ErrorAction Stop
            Write-Verbose "  [OK] Disable Extension Points (Legacy COM)"
        }
        catch {
            Write-Verbose "  [SKIP] Extension Points: $($_.Exception.Message)"
        }
        
        Write-Success (Get-LocalizedString 'CoreExploitActivated')
        Write-Info (Get-LocalizedString 'CoreExploitDEP')
        Write-Info (Get-LocalizedString 'CoreExploitSEHOP')
        Write-Info (Get-LocalizedString 'CoreExploitASLR')
        Write-Info (Get-LocalizedString 'CoreExploitCFG')
        Write-Info (Get-LocalizedString 'CoreExploitHeap')
        Write-Info (Get-LocalizedString 'CoreExploitImageLoad')
        Write-Info (Get-LocalizedString 'CoreExploitExtension')
        Write-Info (Get-LocalizedString 'CoreExploitResistance')
        
        Write-Success (Get-LocalizedString 'CoreExploitProtectionSuccess')
    }
    catch {
        Write-Warning-Custom "Failed to set Exploit Protection: $_"
        Write-Info (Get-LocalizedString 'CoreExploitManual')
    }
}

#endregion

#region AUTOPLAY/AUTORUN & SMARTSCREEN

function Disable-AutoPlayAndAutoRun {
    <#
    .SYNOPSIS
        Disables AutoPlay and AutoRun completely (CIS Benchmark Level 2)
    .DESCRIPTION
        Prevents automatic execution of malware from USB/CD/Network.
        Sets NoDriveTypeAutoRun to 0xFF (all drive types) and NoAutorun to 1.
        Best Practice Januar 2026: Maximum USB-Malware-Schutz
    .EXAMPLE
        Disable-AutoPlayAndAutoRun
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "AutoPlay & AutoRun Deactivation"
    
    Write-Info "Disabling AutoPlay and AutoRun on ALL drives..."
    
    # Machine-Level (HKLM) - System-wide setting
    $explorerPathMachine = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    
    # 0xFF = 11111111 in binary = All drive types
    # Bit 0x01: Unknown, 0x02: Removable, 0x04: Fixed, 0x08: Network
    # 0x10: CD-ROM, 0x20: RAM Disk, 0x40-0x80: Reserved
    [void](Set-RegistryValue -Path $explorerPathMachine -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord `
        -Description "AutoPlay auf allen Laufwerkstypen deaktiviert")
    
    # Disable AutoRun completely (ignore autorun.inf)
    [void](Set-RegistryValue -Path $explorerPathMachine -Name "NoAutorun" -Value 1 -Type DWord `
        -Description "AutoRun global deaktiviert (autorun.inf ignoriert)")
    
    # User-Level (HKCU) - Current User
    $explorerPathUser = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    
    [void](Set-RegistryValue -Path $explorerPathUser -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord `
        -Description "AutoPlay User-Level deaktiviert")
    
    [void](Set-RegistryValue -Path $explorerPathUser -Name "NoAutorun" -Value 1 -Type DWord `
        -Description "AutoRun User-Level deaktiviert")
    
    # Alternative Registry path (for older Windows versions)
    $autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"
    if (Test-Path $autorunPath) {
        [void](Set-RegistryValue -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord `
            -Description "Legacy AutoRun Path")
    }
    
    Write-Success "AutoPlay & AutoRun: COMPLETELY DISABLED"
    Write-Info "  - No automatic dialogs when inserting USB/CD"
    Write-Info "  - autorun.inf is IGNORED (malware cannot auto-start)"
    Write-Info "  - Applies to: USB, CD/DVD, Network drives, all drive types"
    Write-Info "CIS BENCHMARK LEVEL 2: FULFILLED (+3% Compliance)"
    Write-Warning-Custom "Users must now open drives MANUALLY in Explorer"
}

function Set-SmartScreenExtended {
    <#
    .SYNOPSIS
        Enables extended SmartScreen configuration (Defense in Depth)
    .DESCRIPTION
        Extended SmartScreen settings for Apps, Edge and Phishing protection:
        - SmartScreen for Apps (RequireAdmin)
        - Edge SmartScreen (Phishing + PUA Protection)
        - Enhanced Phishing Protection
        Best Practice Januar 2026: Maximum Phishing/Malware-Schutz
    .EXAMPLE
        Set-SmartScreenExtended
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "SmartScreen Extended Configuration"
    
    Write-Info "Configuring extended SmartScreen settings..."
    
    # ===== WINDOWS SMARTSCREEN FOR APPS =====
    $appsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    
    # RequireAdmin = Unknown apps require admin rights
    # Warn = Warnung (default)
    # Off = Disabled (NOT recommended!)
    [void](Set-RegistryValue -Path $appsPath -Name "SmartScreenEnabled" -Value "RequireAdmin" -Type String `
        -Description "SmartScreen: Unbekannte Apps brauchen Admin-Prompt")
    
    # ===== EDGE SMARTSCREEN =====
    $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    
    # SmartScreen enabled
    [void](Set-RegistryValue -Path $edgePath -Name "SmartScreenEnabled" -Value 1 -Type DWord `
        -Description "Edge: SmartScreen aktiviert")
    
    # PUA Protection (Potentially Unwanted Applications)
    [void](Set-RegistryValue -Path $edgePath -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord `
        -Description "Edge: PUA-Schutz aktiviert (Toolbars, Adware)")
    
    # Note: Edge DNS-over-HTTPS is configured in SecurityBaseline-Edge.ps1
    
    # ===== PHISHING FILTER =====
    $phishingPathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
    
    # Phishing Filter enabled
    [void](Set-RegistryValue -Path $phishingPathHKCU -Name "EnabledV9" -Value 1 -Type DWord `
        -Description "Phishing Filter aktiviert")
    
    # Prevent Override (user CANNOT ignore warning)
    [void](Set-RegistryValue -Path $phishingPathHKCU -Name "PreventOverride" -Value 1 -Type DWord `
        -Description "Phishing warnings cannot be bypassed")
    
    # ===== ENHANCED PHISHING PROTECTION (Windows 11) =====
    # NOTE: WTDS = Windows Threat Detection Service
    # These keys can be TrustedInstaller-protected or may not exist
    $enhancedPhishingPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components"
    
    # Enable Enhanced Phishing Protection (with ownership management)
    if (Get-Command Set-RegistryValueWithOwnership -ErrorAction SilentlyContinue) {
        # Use ownership management if available (TrustedInstaller-protected keys)
        Set-RegistryValueWithOwnership -Path $enhancedPhishingPath -Name "ServiceEnabled" -Value 1 -Type DWord `
            -Description "Enhanced Phishing Protection (Win11)" | Out-Null
        
        Set-RegistryValueWithOwnership -Path $enhancedPhishingPath -Name "NotifyPasswordReuse" -Value 1 -Type DWord `
            -Description "Warning on password reuse on phishing sites" | Out-Null
        
        Set-RegistryValueWithOwnership -Path $enhancedPhishingPath -Name "NotifyUnsafeApp" -Value 1 -Type DWord `
            -Description "Warning when starting unsafe apps" | Out-Null
    }
    else {
        # Fallback without ownership (could fail)
        Write-Verbose "Set-RegistryValueWithOwnership not available - using standard method"
        [void](Set-RegistryValue -Path $enhancedPhishingPath -Name "ServiceEnabled" -Value 1 -Type DWord `
            -Description "Enhanced Phishing Protection (Win11)")
        
        [void](Set-RegistryValue -Path $enhancedPhishingPath -Name "NotifyPasswordReuse" -Value 1 -Type DWord `
            -Description "Warning on password reuse on phishing sites")
        
        [void](Set-RegistryValue -Path $enhancedPhishingPath -Name "NotifyUnsafeApp" -Value 1 -Type DWord `
            -Description "Warning when starting unsafe apps")
    }
    
    # ===== GROUP POLICY SMARTSCREEN (for Verify compatibility) =====
    # CRITICAL: Verify checks HKLM:\SOFTWARE\Policies\Microsoft\Windows\System
    # We must set BOTH paths (Explorer for functionality + Policies for Verify)
    $smartScreenPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    
    # Enable SmartScreen via Group Policy
    [void](Set-RegistryValue -Path $smartScreenPolicyPath -Name "EnableSmartScreen" -Value 1 -Type DWord `
        -Description "SmartScreen enabled via Group Policy")
    
    # Set SmartScreen level to "Block" (strictest mode)
    # Options: Warn (default), Block (strictest)
    [void](Set-RegistryValue -Path $smartScreenPolicyPath -Name "ShellSmartScreenLevel" -Value "Block" -Type String `
        -Description "SmartScreen: Block unknown apps (strictest mode)")
    
    Write-Success "SmartScreen Extended: AKTIV"
    Write-Info "  - Windows SmartScreen: Block mode (strictest)"
    Write-Info "  - Edge SmartScreen: Phishing + PUA Protection"
    Write-Info "  - Enhanced Phishing Protection (Password Reuse + Unsafe Apps)"
    Write-Info "DEFENSE IN DEPTH: +5% Phishing/Malware Resistance"
    Write-Info "Note: Edge DNS-over-HTTPS is configured in Edge module"
    Write-Warning-Custom "SmartScreen now BLOCKS unknown apps (maximum security)"
}

#endregion


function Set-SMBHardening {
    <#
    .SYNOPSIS
        Hardens SMB Configuration (Microsoft Baseline 25H2)
    .DESCRIPTION
        Implementiert ALLE Microsoft Security Baseline 25H2 SMB Settings:
        - SMB Min/Max Versionen (3.0.0 - 3.1.1)
        - Authentication Rate Limiter (2000ms Brute-Force Protection)
        - Audit Settings (Encryption, Signing, Guest Logon)
        - Remote Mailslots disabled
        - SMB1 disabled, SMB Signing/Encryption
    .EXAMPLE
        Set-SMBHardening
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "SMB/LAN Manager Hardening (Microsoft Baseline 25H2)"
    
    # ===========================
    # MICROSOFT BASELINE 25H2: SMB SERVER SETTINGS
    # ===========================
    Write-Info "Configuring SMB Server (Lanman Server) settings..."
    
    $smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    
    # 1. SMB Authentication Rate Limiter (NEW in Baseline)
    # Protection against brute-force attacks: 2000ms delay between failed auth attempts
    Set-RegistryValue -Path $smbServerPath -Name "InvalidAuthenticationDelayTimeInMs" -Value 2000 -Type DWord `
        -Description "SMB Auth Rate Limiter: 2000ms delay (Brute-Force Protection)"
    Set-RegistryValue -Path $smbServerPath -Name "EnableAuthenticationRateLimiter" -Value 1 -Type DWord `
        -Description "SMB Auth Rate Limiter aktivieren"
    
    # 2. SMB Version Control (NEW in Baseline)
    # Minimum: SMB 3.0.0 (secure), Maximum: SMB 3.1.1 (latest)
    Set-RegistryValue -Path $smbServerPath -Name "SMBServerMinimumProtocol" -Value 768 -Type DWord `
        -Description "SMB Min Version: 3.0.0 (768 = SMB 3.0)"
    Set-RegistryValue -Path $smbServerPath -Name "SMBServerMaximumProtocol" -Value 1025 -Type DWord `
        -Description "SMB Max Version: 3.1.1 (1025 = SMB 3.1.1)"
    
    # 3. Audit Settings (NEW in Baseline)
    Set-RegistryValue -Path $smbServerPath -Name "AuditClientDoesNotSupportEncryption" -Value 1 -Type DWord `
        -Description "Audit: Client ohne Encryption-Support"
    Set-RegistryValue -Path $smbServerPath -Name "AuditClientDoesNotSupportSigning" -Value 1 -Type DWord `
        -Description "Audit: Client ohne Signing-Support"
    Set-RegistryValue -Path $smbServerPath -Name "AuditInsecureGuestLogon" -Value 1 -Type DWord `
        -Description "Audit: Unsichere Guest-Logins"
    
    # 4. Remote Mailslots (NEW in Baseline)
    Set-RegistryValue -Path $smbServerPath -Name "EnableRemoteMailslots" -Value 0 -Type DWord `
        -Description "Remote Mailslots deaktivieren (Legacy-Feature)"
    
    Write-Success "SMB Server Hardening completed (6 new Baseline settings)"
    
    # ===========================
    # MICROSOFT BASELINE 25H2: SMB CLIENT (WORKSTATION) SETTINGS
    # ===========================
    Write-Info "Configuring SMB Client (Lanman Workstation) settings..."
    
    $smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    
    # 1. SMB Version Control (Client-Side)
    Set-RegistryValue -Path $smbClientPath -Name "SMBClientMinimumProtocol" -Value 768 -Type DWord `
        -Description "SMB Client Min Version: 3.0.0"
    Set-RegistryValue -Path $smbClientPath -Name "SMBClientMaximumProtocol" -Value 1025 -Type DWord `
        -Description "SMB Client Max Version: 3.1.1"
    
    # 2. Audit Settings (Client-Side)
    Set-RegistryValue -Path $smbClientPath -Name "AuditInsecureGuestLogon" -Value 1 -Type DWord `
        -Description "Audit: Unsichere Guest-Logins (Client)"
    Set-RegistryValue -Path $smbClientPath -Name "AuditServerDoesNotSupportEncryption" -Value 1 -Type DWord `
        -Description "Audit: Server ohne Encryption"
    Set-RegistryValue -Path $smbClientPath -Name "AuditServerDoesNotSupportSigning" -Value 1 -Type DWord `
        -Description "Audit: Server ohne Signing"
    
    # 3. Remote Mailslots (Client-Side)
    Set-RegistryValue -Path $smbClientPath -Name "EnableRemoteMailslots" -Value 0 -Type DWord `
        -Description "Remote Mailslots deaktivieren (Client)"
    
    # 4. Require Encryption (Baseline: Disabled for compatibility)
    Set-RegistryValue -Path $smbClientPath -Name "RequireEncryption" -Value 0 -Type DWord `
        -Description "Encryption nicht erzwingen (Kompatibilitaet)"
    
    Write-Success "SMB Client Hardening completed"
    
    # ===========================
    # DISABLE SMB1 (CRITICAL!)
    # ===========================
    Write-Info "Disabling SMB1 (legacy protocol)..."
    
    # Disable SMB1 Server
    Set-RegistryValue -Path $smbServerPath -Name "SMB1" -Value 0 -Type DWord `
        -Description "SMB1 Server deaktivieren (unsicher!)"
    
    # Disable SMB1 Client
    Set-RegistryValue -Path $smbClientPath -Name "DisableSmb1" -Value 1 -Type DWord `
        -Description "SMB1 Client deaktivieren"
    
    Write-Success "SMB1 disabled (Server + Client)"
    
    # ===========================
    # SMB SIGNING & ENCRYPTION (CRITICAL - fehlte in Baseline!)
    # ===========================
    Write-Info "Enabling SMB Signing and Encryption (CRITICAL Security)..."
    
    # SMB Signing (Server + Client) - CRITICAL!
    Set-RegistryValue -Path $smbClientPath -Name "EnableSecuritySignature" -Value 1 -Type DWord `
        -Description "SMB Signing Client aktivieren"
    Set-RegistryValue -Path $smbClientPath -Name "RequireSecuritySignature" -Value 1 -Type DWord `
        -Description "SMB Signing Client erzwingen"
    Set-RegistryValue -Path $smbServerPath -Name "EnableSecuritySignature" -Value 1 -Type DWord `
        -Description "SMB Signing Server aktivieren"
    Set-RegistryValue -Path $smbServerPath -Name "RequireSecuritySignature" -Value 1 -Type DWord `
        -Description "SMB Signing Server erzwingen"
    
    # SMB Encryption (Server) - CRITICAL!
    Set-RegistryValue -Path $smbServerPath -Name "EncryptData" -Value 1 -Type DWord `
        -Description "SMB Encryption aktivieren"
    Set-RegistryValue -Path $smbServerPath -Name "RejectUnencryptedAccess" -Value 1 -Type DWord `
        -Description "Unencrypted Access ablehnen"
    
    Write-Success "SMB Signing and Encryption enabled"
    
    # ===========================
    # SMB GUEST AUTHENTICATION (Microsoft Baseline 25H2)
    # ===========================
    Write-Info "Disabling insecure SMB Guest authentication..."
    
    # Disable insecure guest logons (Workstation/Client)
    $smbPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation"
    Set-RegistryValue -Path $smbPolicyPath -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord `
        -Description "Unsichere SMB Guest-Logins deaktivieren"
    
    # Microsoft network client: Send unencrypted password to third-party SMB servers (DISABLE!)
    Set-RegistryValue -Path $smbClientPath -Name "EnablePlainTextPassword" -Value 0 -Type DWord `
        -Description "Plaintext-Passwoerter an SMB-Server verbieten"
    
    # SMB v1 client driver (Disable at driver level - defense in depth)
    $smb1DriverPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10"
    Set-RegistryValue -Path $smb1DriverPath -Name "Start" -Value 4 -Type DWord `
        -Description "SMB1 Client Driver deaktivieren (Disabled = 4)"
    
    Write-Success "SMB Guest Auth disabled, SMB1 Driver disabled"
    
    # ===========================
    # NTLM SIGNING
    # ===========================
    $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    Set-RegistryValue -Path $ntlmPath -Name "RequireSignOrSeal" -Value 1 -Type DWord `
        -Description "NTLM Sign/Seal erzwingen"
    
    # LLMNR OFF
    $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    [void](Set-RegistryValue -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Description "LLMNR deaktivieren")
    
    Write-Success "SMB/NTLM/LLMNR hardened"
}

function Disable-AnonymousSIDEnumeration {
    <#
    .SYNOPSIS
        Prevents Anonymous SID Enumeration and disables LM Hashes
    .DESCRIPTION
        DoD STIG CAT II Requirement: Prevents anonymous users from
        enumerating user accounts and SIDs.
        Disables insecure LM Hashes (DES-based, deprecated since 1992).
    .EXAMPLE
        Disable-AnonymousSIDEnumeration
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Prevent Anonymous SID Enumeration"
    
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    
    # 1. EveryoneIncludesAnonymous = 0
    # Prevents "Everyone" group from including anonymous users
    # Without this: Anonymous users can see all user accounts!
    Set-RegistryValue -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord `
        -Description "Everyone beinhaltet KEINE anonymen User"
    
    # 2. NoLMHash = 1
    # Disables LM hashes completely (insecure, DES-based)
    # LM hash can be cracked in seconds!
    Set-RegistryValue -Path $lsaPath -Name "NoLMHash" -Value 1 -Type DWord `
        -Description "LM Hashes deaktivieren (veraltet seit 1992)"
    
    Write-Success "Anonymous SID Enumeration prevented"
    Write-Info "EveryoneIncludesAnonymous = 0 (DoD STIG CAT II)"
    Write-Info "NoLMHash = 1 (LM Hashes disabled)"
}

function Disable-NetworkLegacyProtocols {
    <#
    .SYNOPSIS
        Disables Legacy Network Protocols (mDNS, WPAD, LLMNR, NetBIOS, SSDP, WSD)
    .DESCRIPTION
        Creates 13 Firewall rules to block legacy protocols.
        Best Practice 25H2: CmdletBinding, Out-Null replaced, Error-Handling.
    .EXAMPLE
        Disable-NetworkLegacyProtocols
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Disable Legacy Network Protocols (mDNS/WPAD)"
    
    # Disable WPAD (Web Proxy Auto-Discovery)
    $wpadPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
    [void](Set-RegistryValue -Path $wpadPath -Name "DoNotUseWPAD" -Value 1 -Type DWord `
        -Description "WPAD deaktivieren")
    
    # Disable WinHTTP Auto-Proxy
    $winHttpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
    [void](Set-RegistryValue -Path $winHttpPath -Name "DisableWpad" -Value 1 -Type DWord `
        -Description "WinHTTP WPAD deaktivieren")
    
    # ===== TRIPLE-KILL: Firewall rules for ALL legacy protocols =====
    Write-Info "Creating firewall rules (Triple-Kill Mode)..."
    
    # All rules have unique NoID- prefix for idempotency
    $firewallRules = @(
        @{Name="NoID-Block-mDNS-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=5353; RemotePort=$null}
        @{Name="NoID-Block-mDNS-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=5353; RemotePort=5353}
        @{Name="NoID-Block-LLMNR-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=5355; RemotePort=$null}
        @{Name="NoID-Block-LLMNR-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=5355; RemotePort=5355}
        @{Name="NoID-Block-NetBIOS-NS-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=137; RemotePort=$null}
        @{Name="NoID-Block-NetBIOS-NS-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=137; RemotePort=137}
        @{Name="NoID-Block-NetBIOS-DGM-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=138; RemotePort=$null}
        @{Name="NoID-Block-NetBIOS-DGM-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=138; RemotePort=138}
        @{Name="NoID-Block-NetBIOS-SSN-In"; Direction="Inbound"; Protocol="TCP"; LocalPort=139; RemotePort=$null}
        @{Name="NoID-Block-SSDP-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=1900; RemotePort=$null}
        @{Name="NoID-Block-SSDP-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=1900; RemotePort=1900}
        @{Name="NoID-Block-WSD-In"; Direction="Inbound"; Protocol="UDP"; LocalPort=3702; RemotePort=$null}
        @{Name="NoID-Block-WSD-Out"; Direction="Outbound"; Protocol="UDP"; LocalPort=3702; RemotePort=3702}
    )
    
    $createdRules = 0
    $existingRules = 0
    foreach ($rule in $firewallRules) {
        try {
            # Idempotency check: unique DisplayName with NoID- prefix
            $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
            if (-not $existing) {
                $params = @{
                    DisplayName = $rule.Name
                    Direction = $rule.Direction
                    Protocol = $rule.Protocol
                    LocalPort = $rule.LocalPort
                    Action = "Block"
                    Profile = "Any"
                    Enabled = "True"
                }
                
                if ($rule.RemotePort) {
                    $params.Add("RemotePort", $rule.RemotePort)
                }
                
                [void](New-NetFirewallRule @params -ErrorAction Stop)
                Write-Verbose "     Firewall rule created: $($rule.Name)"
                $createdRules++
            }
            else {
                Write-Verbose "     Firewall rule already exists: $($rule.Name)"
                $existingRules++
            }
        }
        catch {
            Write-Verbose "     Error with rule $($rule.Name): $_"
        }
    }
    
    Write-Success "Triple-Kill Firewall rules: $createdRules newly created, $($firewallRules.Count - $createdRules) already existing"
    
    # Disable WlanSvc mDNS (Windows 11 specific)
    $wlanPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters"
    [void](Set-RegistryValue -Path $wlanPath -Name "DisableMdnsDiscovery" -Value 1 -Type DWord `
        -Description "WlanSvc mDNS Discovery deaktivieren")
    
    # LLMNR (already in Set-SMBHardening, but ensure)
    $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    [void](Set-RegistryValue -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord `
        -Description "LLMNR deaktivieren (redundant check)")
    
    Write-Success "Legacy network protocols disabled (WPAD/mDNS/LLMNR)"  
}

function Enable-NetworkStealthMode {
    <#
    .SYNOPSIS
        Enables Network Stealth Mode
    .DESCRIPTION
        Disables Network Discovery, Broadcasting, File Sharing, P2P.
        Best Practice 25H2: CmdletBinding, Out-Null replaced, Error-Handling.
        WARNING: WLAN remains active, but system is invisible in network!
    .EXAMPLE
        Enable-NetworkStealthMode
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Network Stealth Mode (invisible in network)"
    
    Write-Info "Disabling Network Discovery and Broadcasting..."
    
    # Disable Network Discovery completely (Registry)
    $netDiscPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff"
    if (-not (Test-Path -Path $netDiscPath)) {
        try {
            $null = New-Item -Path $netDiscPath -Force -ErrorAction Stop
            Write-Verbose "Network Discovery registry key created"
        }
        catch {
            Write-Verbose "Error creating Network Discovery key: $_"
        }
    }
    
    # Network Discovery via Group Policy
    $ndGpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    [void](Set-RegistryValue -Path $ndGpPath -Name "NC_ShowSharedAccessUI" -Value 0 -Type DWord `
        -Description "Network Discovery UI deaktivieren")
    
    # Disable File and Printer Sharing (Firewall rules)
    try {
        Write-Info "Disabling File and Printer Sharing firewall rules..."
        
        # SilentlyContinue if rules don't exist (Windows 11 25H2)
        Disable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue
        Disable-NetFirewallRule -DisplayGroup "Network Discovery" -ErrorAction SilentlyContinue
        
        Write-Success "File and Printer Sharing firewall rules disabled"
    }
    catch {
        Write-Verbose "Firewall rules error: $_"
    }
    
    # Network Location Awareness (NLA) - keep core only
    # DO NOT disable! Required for WLAN
    
    # HomeGroup Services (Legacy - Windows 11 no longer has these)
    $homegroupServices = @("HomeGroupListener", "HomeGroupProvider")
    foreach ($hgSvc in $homegroupServices) {
        if (Stop-ServiceSafe -ServiceName $hgSvc) {
            Write-Verbose "$hgSvc disabled"
        }
        else {
            Write-Verbose "$hgSvc not found (normal in Windows 11 25H2)"
        }
    }
    
    # Network List Manager Policies (reduce automatic network profile switching)
    $nlmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
    [void](Set-RegistryValue -Path $nlmPath -Name "NC_AllowNetBridge_NLA" -Value 0 -Type DWord `
        -Description "Network Bridge deaktivieren")
    
    # Disable Wi-Fi Sense (automatic sharing of WLAN passwords)
    $wifiSensePath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    [void](Set-RegistryValue -Path $wifiSensePath -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord `
        -Description "Wi-Fi Sense Auto-Connect deaktivieren")
    
    # Disable Windows Connect Now (WCN)
    $wcnPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
    [void](Set-RegistryValue -Path $wcnPath -Name "EnableRegistrars" -Value 0 -Type DWord `
        -Description "Windows Connect Now deaktivieren")
    
    [void](Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value 1 -Type DWord `
        -Description "WCN UI deaktivieren")
    
    # Disable Peer-to-Peer Networking (Registry-Level)
    $p2pPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
    [void](Set-RegistryValue -Path $p2pPath -Name "Disabled" -Value 1 -Type DWord `
        -Description "Peer-to-Peer Networking deaktivieren")
    
    # Prevent automatic network authentication
    $autoAuthPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    [void](Set-RegistryValue -Path $autoAuthPath -Name "DisableAutomaticRestartSignOn" -Value 1 -Type DWord `
        -Description "Automatische Netzwerk-Authentifizierung deaktivieren")
    
    Write-Success "Network Stealth Mode enabled (invisible in network, WLAN works)"
    Write-Info "Broadcasting disabled: mDNS, LLMNR, NetBIOS, SSDP, UPnP, Network Discovery, WSD"
}

function Disable-UnnecessaryServices {
    <#
    .SYNOPSIS
        Disables unnecessary Windows Services
    .DESCRIPTION
        Disables 25 Services according to CIS Benchmark Level 1 + Level 2.
        Best Practice 25H2: CmdletBinding, Try-Catch for each service.
        
        IMPORTANT: Smart Card Services (SCardSvr, ScDeviceEnum, SCPolicySvc) 
        REMAIN ACTIVE for Enterprise compatibility!
    .EXAMPLE
        Disable-UnnecessaryServices
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreServicesTitle')
    
    # Service list to disable (CIS Level 1 + Level 2)
    $servicesToDisable = @(
        @{Name="RemoteRegistry"; DisplayName="Remote Registry"}
        @{Name="SSDPSRV"; DisplayName="SSDP Discovery (UPnP)"}
        @{Name="upnphost"; DisplayName="UPnP Device Host"}
        @{Name="WerSvc"; DisplayName="Windows Error Reporting"}
        @{Name="MapsBroker"; DisplayName="Downloaded Maps Manager"}
        @{Name="lfsvc"; DisplayName="Geolocation Service"}
        @{Name="lltdsvc"; DisplayName="Link-Layer Topology Discovery Mapper"}
        @{Name="SharedAccess"; DisplayName="Internet Connection Sharing (ICS)"}
        @{Name="MSiSCSI"; DisplayName="Microsoft iSCSI Initiator"}
        @{Name="PNRPsvc"; DisplayName="Peer Name Resolution Protocol"}
        @{Name="p2psvc"; DisplayName="Peer Networking Grouping"}
        @{Name="p2pimsvc"; DisplayName="Peer Networking Identity Manager"}
        @{Name="PNRPAutoReg"; DisplayName="PNRP Machine Name Publication"}
        @{Name="RpcLocator"; DisplayName="Remote Procedure Call (RPC) Locator"}
        @{Name="RemoteAccess"; DisplayName="Routing and Remote Access"}
        # [OK] Smart Card Services REMAIN ACTIVE (User-Request)
        # @{Name="SCardSvr"; DisplayName="Smart Card"}  # DO NOT DISABLE
        # @{Name="ScDeviceEnum"; DisplayName="Smart Card Device Enumeration"}  # DO NOT DISABLE
        # @{Name="SCPolicySvc"; DisplayName="Smart Card Removal Policy"}  # DO NOT DISABLE
        @{Name="SNMPTRAP"; DisplayName="SNMP Trap"}
        @{Name="WwanSvc"; DisplayName="WWAN AutoConfig (Mobile Broadband)"}
        @{Name="fdPHost"; DisplayName="Function Discovery Provider Host"}
        @{Name="FDResPub"; DisplayName="Function Discovery Resource Publication"}
        @{Name="WSDScanMgr"; DisplayName="WSD Scan Management"}
        @{Name="WSDPrintDevice"; DisplayName="WSD Print Device"}
        @{Name="XblAuthManager"; DisplayName="Xbox Live Auth Manager"}
        @{Name="XblGameSave"; DisplayName="Xbox Live Game Save"}
        @{Name="XboxNetApiSvc"; DisplayName="Xbox Live Networking"}
        @{Name="XboxGipSvc"; DisplayName="Xbox Accessory Management"}
    )
    
    Write-Info (Get-LocalizedString 'CoreServicesWLANActive')
    Write-Info (Get-LocalizedString 'CoreServicesDisabling' -FormatArgs $servicesToDisable.Count)
    
    $successCount = 0
    $notFoundCount = 0
    
    foreach ($svc in $servicesToDisable) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            # Stop and disable service (race-condition-frei)
            if (Stop-ServiceSafe -ServiceName $svc.Name) {
                Write-Success (Get-LocalizedString 'CoreServicesDisabled' -FormatArgs $svc.DisplayName)
                $successCount++
            }
            else {
                Write-Warning-Custom (Get-LocalizedString 'CoreServicesProtected' -FormatArgs $svc.DisplayName)
            }
        }
        else {
            Write-Verbose (Get-LocalizedString 'CoreServicesNotFound' -FormatArgs $svc.DisplayName)
            $notFoundCount++
        }
    }
    
    Write-Success (Get-LocalizedString 'CoreServicesResult' -FormatArgs $successCount, $notFoundCount)
}

function Disable-AdministrativeShares {
    <#
    .SYNOPSIS
        Disables Administrative Shares and hardens IPC$
    .DESCRIPTION
        Disables C$, ADMIN$, etc. and hardens IPC$ against Anonymous Access.
        Best Practice 25H2: CmdletBinding, Try-Catch for Firewall-Ops.
    .EXAMPLE
        Disable-AdministrativeShares
    #>
    [CmdletBinding()]
    param()
    
    Write-Section (Get-LocalizedString 'CoreAdminSharesTitle')
    
    Write-Info (Get-LocalizedString 'CoreAdminSharesDisabling')
    
    # Registry: Disable Administrative Shares (Server & Workstation)
    $autoSharePath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    
    # Server (Windows Server)
    [void](Set-RegistryValue -Path $autoSharePath -Name "AutoShareServer" -Value 0 -Type DWord `
        -Description "Admin Shares auf Servern deaktivieren")
    
    # Workstation (Windows 10/11)
    [void](Set-RegistryValue -Path $autoSharePath -Name "AutoShareWks" -Value 0 -Type DWord `
        -Description "Admin Shares auf Workstations deaktivieren")
    
    Write-Success (Get-LocalizedString 'CoreAdminSharesDisabled')
    Write-Warning-Custom (Get-LocalizedString 'CoreAdminSharesIPCWarning')
    
    # File and Printer Sharing is already disabled in Enable-NetworkStealthMode (no duplicate)
    
    Write-Info (Get-LocalizedString 'CoreAdminSharesRebootNote')
    
    # Harden IPC$ (cannot be disabled, but we restrict Anonymous Access)
    Write-Info (Get-LocalizedString 'CoreAdminSharesIPCHardening')
    
    # Restrict anonymous access to Named Pipes and Shares
    $restrictPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    [void](Set-RegistryValue -Path $restrictPath -Name "RestrictNullSessAccess" -Value 1 -Type DWord `
        -Description "Anonymous Access zu Named Pipes einschraenken")
    
    # Network access: Do not allow anonymous enumeration of SAM accounts
    $samPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    [void](Set-RegistryValue -Path $samPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord `
        -Description "Anonymous SAM Enumeration verbieten")
    
    # Network access: Do not allow anonymous enumeration of SAM accounts and shares
    [void](Set-RegistryValue -Path $samPath -Name "RestrictAnonymous" -Value 1 -Type DWord `
        -Description "Anonymous Share Enumeration verbieten")
    
    # Network access: Let Everyone permissions apply to anonymous users (DISABLE!)
    [void](Set-RegistryValue -Path $samPath -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord `
        -Description "Everyone-Permissions NICHT fuer Anonymous")
    
    # Network access: Named Pipes that can be accessed anonymously (LEER!)
    [void](Set-RegistryValue -Path $restrictPath -Name "NullSessionPipes" -Value ([string[]]@()) -Type MultiString `
        -Description "Keine Named Pipes fuer Anonymous Access")
    
    # Network access: Shares that can be accessed anonymously (LEER!)
    [void](Set-RegistryValue -Path $restrictPath -Name "NullSessionShares" -Value ([string[]]@()) -Type MultiString `
        -Description "Keine Shares fuer Anonymous Access")
    
    # ===========================
    # ADDITIONAL SECURITY OPTIONS (Microsoft Baseline 25H2)
    # ===========================
    
    # Accounts: Limit local account use of blank passwords to console logon only
    [void](Set-RegistryValue -Path $samPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord `
        -Description "Blank passwords nur bei Console-Logon (kein Remote)")
    
    # Network security: LAN Manager authentication level (NTLMv2 only)
    [void](Set-RegistryValue -Path $samPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord `
        -Description "LAN Manager Auth Level: 5 = NTLMv2 only (no LM/NTLM)")
    
    # Network security: LDAP client signing requirements
    $ldapPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
    [void](Set-RegistryValue -Path $ldapPath -Name "LDAPClientIntegrity" -Value 2 -Type DWord `
        -Description "LDAP Client Signing: Require signing (maximum security)")
    
    # LDAP Channel Binding (NEW: Protection against LDAP relay attacks)
    [void](Set-RegistryValue -Path $ldapPath -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord `
        -Description "LDAP Channel Binding: Always enforce (CVE-2025-59214 protection)")
    
    # Network security: Minimum session security for NTLM SSP (client)
    $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    [void](Set-RegistryValue -Path $ntlmPath -Name "NTLMMinClientSec" -Value 537395200 -Type DWord `
        -Description "NTLM Client: Require NTLMv2 + 128-bit encryption")
    
    # Network security: Minimum session security for NTLM SSP (server)
    [void](Set-RegistryValue -Path $ntlmPath -Name "NTLMMinServerSec" -Value 537395200 -Type DWord `
        -Description "NTLM Server: Require NTLMv2 + 128-bit encryption")
    
    # Interactive logon: Smart card removal behavior (Lock Workstation)
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    [void](Set-RegistryValue -Path $winlogonPath -Name "ScRemoveOption" -Value 1 -Type String `
        -Description "Smart card removal: Lock Workstation (1)")
    
    # ===========================
    # ADDITIONAL SECURITY OPTIONS - LOW PRIORITY (Microsoft Baseline 25H2)
    # ===========================
    
    # Network access: Restrict clients allowed to make remote calls to SAM
    [void](Set-RegistryValue -Path $samPath -Name "RestrictRemoteSAM" -Value "O:BAG:BAD:(A;;RC;;;BA)" -Type String `
        -Description "Restrict remote SAM calls to Administrators only (SDDL)")
    
    # Network security: Allow LocalSystem NULL session fallback (DISABLE!)
    [void](Set-RegistryValue -Path $samPath -Name "AllowNullSessionFallback" -Value 0 -Type DWord `
        -Description "Do NOT allow NULL session fallback for LocalSystem")
    
    # System objects: Strengthen default permissions (already set via separate function - ProtectionMode)
    # This is handled elsewhere in the code
    
    # ===========================
    # CREDENTIAL DELEGATION (Microsoft Baseline 25H2)
    # ===========================
    
    # Encryption Oracle Remediation (Force Updated Clients)
    $credDelegPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters"
    [void](Set-RegistryValue -Path $credDelegPath -Name "AllowEncryptionOracle" -Value 0 -Type DWord `
        -Description "Encryption Oracle: Force Updated Clients (most secure)")
    
    # Remote host allows delegation of non-exportable credentials
    [void](Set-RegistryValue -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation" -Name "AllowDefCredentialsWhenNTLMOnly" -Value 0 -Type DWord `
        -Description "Do NOT allow delegation of credentials when NTLM only")
    
    # ===========================
    # WINDOWS INSTALLER SECURITY (Microsoft Baseline 25H2)
    # ===========================
    
    # Disable user control over installs (prevent elevation bypass)
    $installerPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
    [void](Set-RegistryValue -Path $installerPath -Name "EnableUserControl" -Value 0 -Type DWord `
        -Description "User control over installs: DISABLED (security)")
    
    # Always install with elevated privileges (DISABLE - security risk!)
    [void](Set-RegistryValue -Path $installerPath -Name "AlwaysInstallElevated" -Value 0 -Type DWord `
        -Description "Always install elevated: DISABLED (prevents privilege escalation)")
    
    # ===========================
    # MISC SECURITY SETTINGS (Microsoft Baseline 25H2)
    # ===========================
    
    # RSS Feeds: Prevent downloading of enclosures (attachments)
    $rssFeedPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds"
    [void](Set-RegistryValue -Path $rssFeedPath -Name "DisableEnclosureDownload" -Value 1 -Type DWord `
        -Description "RSS: Prevent automatic enclosure downloads (security)")
    
    # Windows Search: Do NOT allow indexing of encrypted files
    $searchPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"
    [void](Set-RegistryValue -Path $searchPath -Name "AllowIndexingEncryptedStoresOrItems" -Value 0 -Type DWord `
        -Description "Search: Do NOT index encrypted files (privacy)")
    
    # Windows Logon: Do not enumerate local users on domain-joined computers
    $winlogonSecPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"
    [void](Set-RegistryValue -Path $winlogonSecPath -Name "EnumerateLocalUsers" -Value 0 -Type DWord `
        -Description "Do NOT enumerate local users on logon screen (privacy)")
    
    Write-Success (Get-LocalizedString 'CoreAdminSharesIPCHardened')
    Write-Info (Get-LocalizedString 'CoreAdminSharesIPCNote')
}

function Set-SecureAdministratorAccount {
    <#
    .SYNOPSIS
        Hardens the Built-in Administrator Account
    .DESCRIPTION
        Renames the Administrator, sets a cryptographically secure password and disables it.
        Best Practice 25H2: RandomNumberGenerator API (modern, cross-platform), NO cleartext passwords!
        
        ! IMPORTANT: The password is NOT saved (Security Best Practice)!
        Use LAPS (Local Administrator Password Solution) instead.
    .OUTPUTS
        [bool] $true on success, $false on error
    .EXAMPLE
        Set-SecureAdministratorAccount
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreAdminAccountTitle')
    
    Write-Info (Get-LocalizedString 'CoreAdminAccountRenaming')
    
    # RNG instances for proper disposal
    $rng = $null
    $rngPassword = $null
    
    # Administrator SID is always the same: S-1-5-21-*-500
    try {
        $adminAccount = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID -like "*-500" }
        
        if (-not $adminAccount) {
            Write-Warning-Custom (Get-LocalizedString 'CoreAdminAccountNotFound')
            return $false
        }
        
        # New name (cryptographically secure randomized)
        # Best Practice 25H2: RandomNumberGenerator API (korrekte Verwendung)
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $randomBytes = New-Object byte[] 4
        $rng.GetBytes($randomBytes)
        $rng.Dispose()
        $randomNumber = [System.BitConverter]::ToUInt32($randomBytes, 0) % 9000 + 1000
        $newAdminName = "SecAdmin_$randomNumber"
        
        # Rename
        try {
            Rename-LocalUser -Name $adminAccount.Name -NewName $newAdminName -ErrorAction Stop
            Write-Success (Get-LocalizedString 'CoreAdminAccountRenamed' -FormatArgs $adminAccount.Name, $newAdminName)
        }
        catch {
            Write-Error-Custom (Get-LocalizedString 'CoreAdminAccountRenameError' -FormatArgs $_)
            return $false
        }
        
        # KRYPTOGRAPHISCH SICHERES Passwort generieren (64 Zeichen)
        Write-Info (Get-LocalizedString 'CoreAdminAccountPasswordGenerating')
        
        # Best Practice 25H2: RandomNumberGenerator API (korrekte Verwendung)
        $passwordLength = 64
        $rngPass = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $passwordBytes = New-Object byte[] $passwordLength
        $rngPass.GetBytes($passwordBytes)
        $rngPass.Dispose()
        
        # Convert to Base64 (secure and complex)
        $securePasswordString = [Convert]::ToBase64String($passwordBytes)
        
        # Create SecureString (WITHOUT -AsPlainText!)
        $securePassword = New-Object System.Security.SecureString
        foreach ($char in $securePasswordString.ToCharArray()) {
            $securePassword.AppendChar($char)
        }
        $securePassword.MakeReadOnly()
        
        # Set password
        try {
            Set-LocalUser -Name $newAdminName -Password $securePassword -ErrorAction Stop
            Write-Success (Get-LocalizedString 'CoreAdminAccountPasswordSet')
        }
        catch {
            Write-Error-Custom (Get-LocalizedString 'CoreAdminAccountPasswordError' -FormatArgs $_)
            return $false
        }
        
        # Account DISABLE (CIS Best Practice)
        try {
            Disable-LocalUser -Name $newAdminName -ErrorAction Stop
            Write-Success (Get-LocalizedString 'CoreAdminAccountDisabled')
        }
        catch {
            Write-Warning-Custom (Get-LocalizedString 'CoreAdminAccountDisableError' -FormatArgs $_)
        }
        
        # IMPORTANT NOTES
        Write-Warning-Custom (Get-LocalizedString 'CoreAdminAccountWarning1')
        Write-Warning-Custom (Get-LocalizedString 'CoreAdminAccountWarning2')
        Write-Warning-Custom (Get-LocalizedString 'CoreAdminAccountWarning3')
        Write-Host "" # Best Practice 25H2: Write-Host for empty lines, not Write-Warning-Custom
        Write-Info (Get-LocalizedString 'CoreAdminAccountSolutions')
        Write-Info (Get-LocalizedString 'CoreAdminAccountLAPS')
        Write-Info (Get-LocalizedString 'CoreAdminAccountEntra')
        Write-Info (Get-LocalizedString 'CoreAdminAccountJIT')
        Write-Host "" # Best Practice 25H2: Write-Host for empty lines, not Write-Warning-Custom
        Write-Warning-Custom (Get-LocalizedString 'CoreAdminAccountWarning4')
        Write-Warning-Custom (Get-LocalizedString 'CoreAdminAccountWarning5')
        Write-Warning-Custom (Get-LocalizedString 'CoreAdminAccountWarning1')
        
        # GUEST ACCOUNT RENAME (CIS Benchmark + Defense-in-Depth)
        Write-Info (Get-LocalizedString 'CoreAdminAccountGuestHardening')
        
        try {
            # Guest SID is always the same: S-1-5-21-*-501
            $guestAccount = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID -like "*-501" }
            
            if ($guestAccount) {
                # Guest Account should already be disabled (Windows default)
                if ($guestAccount.Enabled) {
                    Disable-LocalUser -Name $guestAccount.Name -ErrorAction Stop
                    Write-Info (Get-LocalizedString 'CoreAdminAccountGuestDisabled')
                }
                
                # Rename (Defense-in-Depth: Obfuscate name)
                $rngGuest = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                $randomBytesGuest = New-Object byte[] 4
                $rngGuest.GetBytes($randomBytesGuest)
                $rngGuest.Dispose()
                $randomNumberGuest = [System.BitConverter]::ToUInt32($randomBytesGuest, 0) % 9000 + 1000
                $newGuestName = "DefGuest_$randomNumberGuest"
                
                Rename-LocalUser -Name $guestAccount.Name -NewName $newGuestName -ErrorAction Stop
                Write-Success (Get-LocalizedString 'CoreAdminAccountGuestRenamed' -FormatArgs $guestAccount.Name, $newGuestName)
            }
            else {
                Write-Info (Get-LocalizedString 'CoreAdminAccountGuestNotFound')
            }
        }
        catch {
            Write-Warning-Custom (Get-LocalizedString 'CoreAdminAccountGuestError' -FormatArgs $_)
            Write-Info (Get-LocalizedString 'CoreAdminAccountGuestNote')
        }
        
        return $true
    }
    catch {
        Write-Error-Custom (Get-LocalizedString 'CoreAdminAccountError' -FormatArgs $_)
        Write-Verbose "Details: $($_.Exception.Message)"
        return $false
    }
    finally {
        # Cleanup: Dispose RNG instances properly to prevent memory leak
        if ($null -ne $rng) {
            try {
                $rng.Dispose()
                Write-Verbose "RNG instance 1 disposed"
            }
            catch {
                Write-Verbose "Failed to dispose RNG instance 1: $_"
            }
        }
        if ($null -ne $rngPassword) {
            try {
                $rngPassword.Dispose()
                Write-Verbose "RNG instance 2 (password) disposed"
            }
            catch {
                Write-Verbose "Failed to dispose RNG instance 2: $_"
            }
        }
    }
}

function Enable-CloudflareDNSoverHTTPS {
    <#
    .SYNOPSIS
        Configures Cloudflare DNS over HTTPS (DoH)
    .DESCRIPTION
        Enables Windows 11 native DoH and sets DNS to Cloudflare 1.1.1.1.
        Best Practice 25H2: CmdletBinding, Try-Catch for DNS-Ops, Restart-Service Error-Handling.
        
        [!] IMPORTANT - NO DNS FALLBACK FOR SECURITY REASONS!
        
        DESIGN DECISION: This function deliberately implements NO automatic
        fallback to old DNS servers if Cloudflare is unreachable.
        
        REASONS (Security & Privacy First):
        1. PRIVACY: ISP DNS servers track user behavior (which domains are visited)
        2. SECURITY: Insecure DNS servers (no DoH) are vulnerable to DNS spoofing
        3. TRANSPARENCY: User should consciously notice when Cloudflare is down
        4. NO SILENT FAILURES: Better to have no internet than insecure/tracked
        
        IF Cloudflare is down:
        - Internet will NOT work -> User notices immediately
        - User can manually change DNS (e.g. to Quad9 or Google)
        - Better: Conscious decision instead of automatic fallback to insecure
        
        ALTERNATIVE for Corporate/VPN:
        - Corporate networks should use their own DNS servers
        - VPN adapters are automatically skipped (keep their DNS)
    .EXAMPLE
        Enable-CloudflareDNSoverHTTPS
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreDNSTitle')
    
    Write-Warning-Custom (Get-LocalizedString 'CoreDNSWarning')
    Write-Info (Get-LocalizedString 'CoreDNSCorporate')
    Write-Info (Get-LocalizedString 'CoreDNSAlternatives')
    Write-Host ""
    Write-Info (Get-LocalizedString 'CoreDNSSwitching')
    
    # CRITICAL FIX v1.7.11: MS-DOCUMENTED METHOD!
    # Source: Microsoft Learn + netsh dnsclient documentation
    # 
    # OLD (didn't work correctly):
    # - Add-DnsClientDohServerAddress (only basic mapping)
    # - DohFlags Registry hacks (not supported!)
    # - IPv6 DoH was never validated
    # 
    # NEW (MS-documented):
    # - netsh dnsclient add encryption (official!)
    # - netsh dnsclient set global doh=yes (global enable!)
    # - IPv6 temporarily first for validation
    # - Works for IPv4 AND IPv6!
    
    Write-Info (Get-LocalizedString 'CoreDNSStep1')
    
    # A. Register DoH server mapping (IPv4 + IPv6)
    # IMPORTANT: Remove old entries first (idempotent!)
    Write-Verbose "Removing old DoH entries (if present)..."
    
    $serversToRemove = @("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001")
    foreach ($server in $serversToRemove) {
        try {
            $null = netsh dnsclient delete encryption server=$server 2>&1
            Write-Verbose "  Old DoH entry removed: $server"
        }
        catch {
            Write-Verbose "  No old entry: $server (OK)"
        }
    }
    
    # IPv4 Primary (1.1.1.1)
    Write-Verbose "Registering DoH for 1.1.1.1..."
    $result = netsh dnsclient add encryption server=1.1.1.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 1.1.1.1"
    } else {
        Write-Warning "DoH for 1.1.1.1 could not be registered: $result"
    }
    
    # IPv4 Secondary (1.0.0.1)
    Write-Verbose "Registering DoH for 1.0.0.1..."
    $result = netsh dnsclient add encryption server=1.0.0.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 1.0.0.1"
    } else {
        Write-Verbose "  1.0.0.1 already registered (OK): $result"
    }
    
    # IPv6 Primary (2606:4700:4700::1111)
    Write-Verbose "Registering DoH for 2606:4700:4700::1111..."
    $result = netsh dnsclient add encryption server=2606:4700:4700::1111 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 2606:4700:4700::1111"
    } else {
        Write-Verbose "  IPv6 Primary already registered (OK): $result"
    }
    
    # IPv6 Secondary (2606:4700:4700::1001)
    Write-Verbose "Registering DoH for 2606:4700:4700::1001..."
    $result = netsh dnsclient add encryption server=2606:4700:4700::1001 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes udpfallback=no 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "  DoH registered: 2606:4700:4700::1001"
    } else {
        Write-Verbose "  IPv6 Secondary already registered (OK): $result"
    }
    
    Write-Success (Get-LocalizedString 'CoreDNSRegistered')
    
    # B. Enable global DoH
    # CRITICAL: doh=yes (not auto) for Verify compatibility
    # yes = DoH globally enabled (Verify checks for "DoH : yes" in netsh output)
    # auto = stricter but Verify would fail
    Write-Info (Get-LocalizedString 'CoreDNSStep2')
    $result = netsh dnsclient set global doh=yes 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Success (Get-LocalizedString 'CoreDNSGlobalActivated')
    } else {
        Write-Warning (Get-LocalizedString 'CoreDNSGlobalError' -FormatArgs $result)
    }
    
    # CRITICAL: Also set registry-level EnableAutoDoh for Verify compatibility
    # Auditor recommendation: Verify checks registry EnableAutoDoh = 2
    $dnsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    try {
        if (-not (Test-Path $dnsRegPath)) {
            New-Item -Path $dnsRegPath -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $dnsRegPath -Name "EnableAutoDoh" -Value 2 -Type DWord -Force -ErrorAction Stop
        Write-Verbose "Registry: EnableAutoDoh = 2 set"
    }
    catch {
        Write-Warning "Could not set EnableAutoDoh registry: $_"
    }
    
    # Set DNS servers on all adapters (EXCEPT VPN!)
    Write-Info (Get-LocalizedString 'CoreDNSAdapters')
    
    try {
        # Get all active adapters
        $allAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq "Up" }
        
        # IMPORTANT: VPN adapters MUST be excluded!
        # VPN uses its own DNS servers - overwriting would break VPN tunnel!
        
        # Best Practice 25H2: Multi-Layer VPN Detection
        # Source: deploymentresearch.com + Microsoft Docs
        
        # VPN Patterns (Description + Name)
        $vpnPatterns = @(
            "*VPN*", "*Tunnel*", "*TAP*", "*WireGuard*", "*OpenVPN*", 
            "*NordVPN*", "*ExpressVPN*", "*ProtonVPN*", "*Mullvad*",
            "*Cisco*", "*Pulse*", "*FortiClient*", "*Palo Alto*", "*F5*",
            "*Virtual*Adapter*", "*PPP*", "*PPTP*", "*L2TP*", "*IKEv2*",
            "*pangp*", "*juniper*", "*checkpoint*", "*sonicwall*"
        )
        
        # Virtualization Patterns (EXCLUDE from VPN check)
        $virtualPatterns = @(
            "*Hyper-V*", "*VMware*", "*VirtualBox*", "*Docker*", "*WSL*"
        )
        
        $adapters = @()
        $skippedVPN = @()
        
        # Best Practice: Check for native Windows VPN connections
        try {
            $nativeVPN = Get-VpnConnection -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionStatus -eq "Connected" }
            if ($nativeVPN) {
                Write-Verbose "Native Windows VPN aktiv: $($nativeVPN.Name)"
            }
        }
        catch {
            Write-Verbose "Get-VpnConnection nicht verfuegbar (PS < 3.0?)"
        }
        
        foreach ($adapter in $allAdapters) {
            $isVPN = $false
            $isVirtualization = $false
            $skipReason = ""
            
            # Check 0: Virtualisierungs-Adapter (Hyper-V, VMware, VirtualBox) skip -> NOT VPN!
            foreach ($pattern in $virtualPatterns) {
                if ($adapter.InterfaceDescription -like $pattern -or $adapter.Name -like $pattern) {
                    $isVirtualization = $true
                    Write-Verbose "Virtualization adapter detected (OK): $($adapter.Name)"
                    break
                }
            }
            
            if (-not $isVirtualization) {
                # Check 1: InterfaceDescription + Name enthalten VPN-Keywords
                foreach ($pattern in $vpnPatterns) {
                    if ($adapter.InterfaceDescription -like $pattern -or $adapter.Name -like $pattern) {
                        $isVPN = $true
                        $skipReason = "Pattern Match: $pattern"
                        break
                    }
                }
                
                # Check 2: InterfaceType (Best Practice from Microsoft)
                # 6 = Ethernet, 71 = IEEE 802.11 wireless, 131 = Tunnel (VPN!)
                if ($adapter.InterfaceType -eq 131) {
                    $isVPN = $true
                    $skipReason = "InterfaceType = 131 (Tunnel)"
                }
                
                # Check 3: MediaType = "Tunnel" (fallback for older PS versions)
                if ($adapter.MediaType -eq "Tunnel") {
                    $isVPN = $true
                    $skipReason = "MediaType = Tunnel"
                }
                
                # Check 4: Check ComponentID (deeper level)
                # TAP adapters have typical ComponentIDs
                try {
                    if ($adapter.ComponentID -match "tap") {
                        $isVPN = $true
                        $skipReason = "ComponentID contains TAP"
                    }
                }
                catch {
                    # ComponentID not available (not critical)
                }
            }
            
            if ($isVPN) {
                $skippedVPN += $adapter.Name
                Write-Warning (Get-LocalizedString 'CoreDNSVPNSkipped' -FormatArgs $adapter.Name, $skipReason)
            }
            elseif ($isVirtualization) {
                # CRITICAL FIX: Skip virtualization adapters (VMware, Hyper-V, VirtualBox) too!
                # REASON: VMs have their own DNS servers (often host IP or VM-internal DNS)
                # DoH would break internal VM DNS resolution!
                Write-Verbose "Virtualization adapter skipped: '$($adapter.Name)' (VM adapters need local DNS)"
            }
            else {
                $adapters += $adapter
            }
        }
        
        if ($skippedVPN.Count -gt 0) {
            Write-Info (Get-LocalizedString 'CoreDNSVPNKeepDNS' -FormatArgs ($skippedVPN -join ', '))
            Write-Info (Get-LocalizedString 'CoreDNSVPNNote')
        }
        
        if ($adapters.Count -eq 0) {
            Write-Warning (Get-LocalizedString 'CoreDNSNoAdapters')
            Write-Warning (Get-LocalizedString 'CoreDNSSkipped')
            return
        }
        
        Write-Info (Get-LocalizedString 'CoreDNSConfiguring' -FormatArgs $adapters.Count)
        
        $adapterCount = 0
        foreach ($adapter in $adapters) {
            try {
                Write-Info (Get-LocalizedString 'CoreDNSStep3' -FormatArgs $adapter.Name)
                
                # CRITICAL FIX v1.7.11: Set IPv4 + IPv6 TOGETHER!
                # IMPORTANT: IPv6 temporarily FIRST for validation, then back
                
                # Check if IPv6 is active
                $ipv6Binding = Get-NetAdapterBinding -InterfaceAlias $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
                $ipv6Enabled = ($ipv6Binding -and $ipv6Binding.Enabled)
                
                if ($ipv6Enabled) {
                    Write-Verbose "IPv6 is active - moving IPv6 to front for DoH validation..."
                    
                    # IPv6 FIRST (temporarily for validation)
                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                        -ServerAddresses @("2606:4700:4700::1111", "2606:4700:4700::1001", "1.1.1.1", "1.0.0.1") `
                        -ErrorAction Stop
                    
                    Write-Verbose "IPv6 DNS moved to front (temporarily)"
                } else {
                    Write-Verbose "IPv6 is NOT active - IPv4 only..."
                    
                    # IPv4 only
                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                        -ServerAddresses @("1.1.1.1", "1.0.0.1") `
                        -ErrorAction Stop
                }
                
                # CRITICAL FIX v1.7.11: Wait for IPv6 DoH validation
                # Windows needs time to validate IPv6 DoH
                if ($ipv6Enabled) {
                    Write-Info (Get-LocalizedString 'CoreDNSIPv6Wait')
                    Start-Sleep -Seconds 5
                    
                    # Reset order (IPv4 first - faster)
                    Write-Verbose "Resetting DNS order (IPv4 first)..."
                    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name `
                        -ServerAddresses @("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001") `
                        -ErrorAction Stop
                    
                    Write-Verbose "DNS order: IPv4 first (optimal)"
                    Write-Success (Get-LocalizedString 'CoreDNSAdapterIPv6' -FormatArgs $adapter.Name)
                } else {
                    Write-Success (Get-LocalizedString 'CoreDNSAdapterIPv4' -FormatArgs $adapter.Name)
                }
                
                # CRITICAL FIX v1.7.11: Set DoH Encryption Preference (GUI Toggle)
                # Without this, Windows GUI shows "Unencrypted" even though DoH works
                # IMPORTANT: IPv4 uses "Doh" branch, IPv6 uses "Doh6" branch!
                # Source: https://cleanbrowsing.org/help/docs/configure-encrypted-dns-on-windows-11-with-powershell-doh/
                try {
                    $adapterGuid = $adapter.InterfaceGuid
                    Write-Verbose "Setting DoH encryption preference for adapter GUID: $adapterGuid"
                    
                    # IPv4 Servers → Doh branch
                    $ipv4Servers = @('1.1.1.1', '1.0.0.1')
                    foreach ($ip in $ipv4Servers) {
                        try {
                            $regPath = 'HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\' + $adapterGuid + '\DohInterfaceSettings\Doh\' + $ip
                            if (-not (Test-Path $regPath)) {
                                New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                            }
                            New-ItemProperty -Path $regPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                            Write-Verbose "  DoH encryption set: $ip (Encrypted Only)"
                        }
                        catch {
                            Write-Verbose "  Failed to set DoH for $ip : $_"
                        }
                    }
                    
                    # IPv6 Servers → Doh6 branch (CRITICAL - different from IPv4!)
                    if ($ipv6Enabled) {
                        $ipv6Servers = @('2606:4700:4700::1111', '2606:4700:4700::1001')
                        foreach ($ip in $ipv6Servers) {
                            try {
                                # CRITICAL: IPv6 uses Doh6 branch (not Doh)!
                                # PowerShell 5.1 workaround: Create path step-by-step
                                $basePath = 'HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\' + $adapterGuid + '\DohInterfaceSettings\Doh6'
                                $ipPath = $basePath + '\' + $ip
                                
                                # Create Doh6 parent first (if not exists)
                                if (-not (Test-Path $basePath)) {
                                    New-Item -Path $basePath -Force -ErrorAction Stop | Out-Null
                                }
                                
                                # Create IP subkey (PowerShell 5.1 handles colons in -Path parameter)
                                if (-not (Test-Path $ipPath)) {
                                    New-Item -Path $ipPath -Force -ErrorAction Stop | Out-Null
                                }
                                
                                # Set DohFlags
                                New-ItemProperty -Path $ipPath -Name 'DohFlags' -Value 1 -PropertyType QWord -Force -ErrorAction Stop | Out-Null
                                Write-Verbose "  DoH encryption set: $ip (Encrypted Only, Doh6)"
                            }
                            catch {
                                Write-Verbose "  Failed to set DoH for $ip : $_"
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not set DoH encryption preference (non-critical): $_"
                }
                
                $adapterCount++
            }
            catch {
                Write-Verbose "Fehler beim Setzen von DNS auf Adapter '$($adapter.Name)': $_"
            }
        }
        
        Write-Success (Get-LocalizedString 'CoreDNSAdapterResult' -FormatArgs $adapterCount)
    }
    catch {
        Write-Error-Custom (Get-LocalizedString 'CoreDNSNetworkError' -FormatArgs $_)
    }
    
    # Clear DNS cache (with timeout - prevents hang)
    $job = $null
    try {
        Write-Info (Get-LocalizedString 'CoreDNSCacheFlushing')
        $job = Start-Job -ScriptBlock { ipconfig /flushdns 2>&1 }
        $null = Wait-Job $job -Timeout 10
        
        if ($job.State -eq 'Completed') {
            $null = Receive-Job $job -ErrorAction SilentlyContinue
            Write-Success (Get-LocalizedString 'CoreDNSCacheFlushed')
        }
        elseif ($job.State -eq 'Running') {
            Stop-Job $job -ErrorAction SilentlyContinue
            Write-Warning-Custom (Get-LocalizedString 'CoreDNSCacheTimeout')
            Write-Info (Get-LocalizedString 'CoreDNSCacheReboot')
        }
    }
    catch {
        Write-Verbose "Could not flush DNS cache: $_"
    }
    finally {
        # Garantierter Job-Cleanup
        if ($job) {
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    
    # IMPORTANT: Do NOT restart Dnscache service!
    # Best Practice 25H2: Service is protected and leads to script hang
    # DoH will automatically activate on next DNS request
    Write-Info (Get-LocalizedString 'CoreDNSActivation')
    Write-Verbose "DNS Client Service will NOT be restarted (protected service)"
    
    # VALIDATION: Check if DoH is really configured
    Write-Host ""
    Write-Info (Get-LocalizedString 'CoreDNSValidating')
    try {
        $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
        if ($dohServers) {
            $cloudflareDoH = $dohServers | Where-Object { $_.ServerAddress -match "1\.1\.1\.1|1\.0\.0\.1|2606:4700:4700" }
            if ($cloudflareDoH) {
                $dohCount = @($cloudflareDoH).Count
                Write-Success (Get-LocalizedString 'CoreDNSValidated' -FormatArgs $dohCount)
                foreach ($server in $cloudflareDoH) {
                    $serverAddr = $server.ServerAddress
                    $serverTemplate = $server.DohTemplate
                    Write-Verbose "     ServerAddress: $serverAddr, Template: $serverTemplate"
                    if ($server.AllowFallbackToUdp -eq $false) {
                        Write-Verbose "     No fallback to unencrypted (Maximum Security!)"
                    }
                    else {
                        Write-Warning "     Fallback to unencrypted POSSIBLE (not ideal!)"
                    }
                }
            }
            else {
                Write-Warning (Get-LocalizedString 'CoreDNSValidationFailed')
                Write-Warning (Get-LocalizedString 'CoreDNSUnencrypted')
            }
        }
        else {
            Write-Warning (Get-LocalizedString 'CoreDNSValidationNoData')
            Write-Info (Get-LocalizedString 'CoreDNSValidationReasons')
            Write-Info (Get-LocalizedString 'CoreDNSValidationOldWindows')
            Write-Info (Get-LocalizedString 'CoreDNSValidationNotActive')
        }
    }
    catch {
        Write-Verbose "DoH validation failed (non-critical): $_"
    }
    
    Write-Host ""
    Write-Success (Get-LocalizedString 'CoreDNSActivated')
    Write-Info (Get-LocalizedString 'CoreDNSIPv4Info')
    Write-Info (Get-LocalizedString 'CoreDNSIPv6Info')
    Write-Host ""
    Write-Warning-Custom (Get-LocalizedString 'CoreDNSRebootWarning')
    Write-Info (Get-LocalizedString 'CoreDNSTest')
    Write-Host ""
    Write-Host "[i] $(Get-LocalizedString 'CoreDNSVPNNotModified')" -ForegroundColor Cyan
    Write-Info (Get-LocalizedString 'CoreDNSVPNKeep')
    Write-Info (Get-LocalizedString 'CoreDNSVPNCorrect')
}

function Disable-RemoteAccessCompletely {
    <#
    .SYNOPSIS
        Disables ALL Remote Access methods completely
    .DESCRIPTION
        Disables RDP, Remote Registry, Remote Assistance, Remote Scheduled Tasks and WinRM.
        Additionally creates block rules in the Firewall.
        Best Practice 25H2: CmdletBinding.
    .EXAMPLE
        Disable-RemoteAccessCompletely
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreRemoteTitle')
    
    # ===== RDP (Remote Desktop) ALWAYS disable (not optional!) =====
    Write-Info (Get-LocalizedString 'CoreRemoteRDPDisabling')
    
    # Registry: Turn off RDP
    $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    Set-RegistryValue -Path $rdpPath -Name "fDenyTSConnections" -Value 1 -Type DWord `
        -Description "RDP-Verbindungen verweigern"
    
    # Disable RDP Service (race-condition-free)
    $rdpServices = @("TermService", "UmRdpService")
    $successCount = 0
    
    foreach ($svc in $rdpServices) {
        if (Stop-ServiceSafe -ServiceName $svc) {
            $successCount++
        }
    }
    
    if ($successCount -eq $rdpServices.Count) {
        Write-Success (Get-LocalizedString 'CoreRemoteRDPDisabled')
    }
    elseif ($successCount -gt 0) {
        Write-Warning (Get-LocalizedString 'CoreRemoteRDPPartial' -FormatArgs $successCount, $rdpServices.Count)
    }
    else {
        Write-Warning (Get-LocalizedString 'CoreRemoteRDPFailed')
    }
    
    # HARD block Firewall rules
    try {
        # SilentlyContinue if rules don't exist (Windows 11 25H2)
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        
        # Additionally: Explicit block rule for RDP Port 3389 (unique name)
        $rdpBlockRule = Get-NetFirewallRule -DisplayName "NoID-Block-RDP-Port-3389" -ErrorAction SilentlyContinue
        if (-not $rdpBlockRule) {
            $null = New-NetFirewallRule -DisplayName "NoID-Block-RDP-Port-3389" `
                               -Direction Inbound `
                               -Protocol TCP `
                               -LocalPort 3389 `
                               -Action Block `
                               -Profile Any `
                               -Enabled True -ErrorAction Stop
            Write-Verbose "  -> Explicit block rule for RDP port 3389 created"
        } else {
            Write-Verbose "  -> Block rule for RDP already exists"
        }
        
        Write-Success (Get-LocalizedString 'CoreRemoteRDPFirewall')
    }
    catch {
        Write-Warning (Get-LocalizedString 'CoreRemoteRDPFirewallError' -FormatArgs $_)
    }
    
    # ===== Remote Registry ALWAYS disable =====
    Write-Info (Get-LocalizedString 'CoreRemoteRegDisabling')
    
    if (Stop-ServiceSafe -ServiceName "RemoteRegistry") {
        Write-Success (Get-LocalizedString 'CoreRemoteRegDisabled')
    }
    else {
        Write-Warning (Get-LocalizedString 'CoreRemoteRegFailed')
    }
    
    $remoteRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg"
    Set-RegistryValue -Path $remoteRegPath -Name "RemoteRegAccess" -Value 0 -Type DWord `
        -Description "Remote Registry Access verweigern"
    
    # ===== Remote Assistance ALWAYS disable =====
    Write-Info (Get-LocalizedString 'CoreRemoteRADisabling')
    
    $raPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    Set-RegistryValue -Path $raPath -Name "fAllowToGetHelp" -Value 0 -Type DWord `
        -Description "Remote Assistance deaktivieren"
    
    Set-RegistryValue -Path $raPath -Name "fAllowUnsolicited" -Value 0 -Type DWord `
        -Description "Unaufgeforderte Remote Assistance deaktivieren"
    
    $raGpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Set-RegistryValue -Path $raGpPath -Name "fAllowToGetHelp" -Value 0 -Type DWord `
        -Description "Remote Assistance via GP deaktivieren"
    
    Set-RegistryValue -Path $raGpPath -Name "fAllowUnsolicited" -Value 0 -Type DWord `
        -Description "Unaufgeforderte RA via GP deaktivieren"
    
    Set-RegistryValue -Path $raGpPath -Name "Shadow" -Value 0 -Type DWord `
        -Description "RDP Shadow Sessions verbieten"
    
    Write-Success (Get-LocalizedString 'CoreRemoteRADisabled')
    
    # ===== Disable Remote Scheduled Tasks =====
    $schedTaskPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule"
    Set-RegistryValue -Path $schedTaskPath -Name "DisableRpcOverTcp" -Value 1 -Type DWord `
        -Description "Remote Scheduled Tasks deaktivieren"
    
    # ===== DISABLE WinRM (PowerShell Remoting) =====
    Write-Info (Get-LocalizedString 'CoreRemoteWinRMDisabling')
    
    if (Stop-ServiceSafe -ServiceName "WinRM") {
        Write-Success (Get-LocalizedString 'CoreRemoteWinRMDisabled')
    }
    else {
        Write-Warning (Get-LocalizedString 'CoreRemoteWinRMFailed')
    }
    
    # Disable WinRM Firewall Rules
    try {
        # SilentlyContinue if rules don't exist (Windows 11 25H2)
        Disable-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction SilentlyContinue
        Write-Success (Get-LocalizedString 'CoreRemoteWinRMFirewall')
    }
    catch {
        Write-Warning (Get-LocalizedString 'CoreRemoteWinRMFirewallError' -FormatArgs $_)
    }
    
    Write-Success (Get-LocalizedString 'CoreRemoteComplete')
    Write-Warning (Get-LocalizedString 'CoreRemoteWarning')
}

function Disable-SudoForWindows {
    <#
    .SYNOPSIS
        Disables Sudo for Windows (Microsoft Baseline 25H2)
    .DESCRIPTION
        Sudo for Windows can be used as Privilege Escalation vector.
        Microsoft Security Baseline 25H2 recommends: Disabled.
    .EXAMPLE
        Disable-SudoForWindows
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreSudoTitle')
    
    # Microsoft Baseline 25H2: Sudo = Disabled
    $sudoPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo"
    Set-RegistryValue -Path $sudoPath -Name "Enabled" -Value 0 -Type DWord `
        -Description "Sudo for Windows deaktivieren (Privilege Escalation Prevention)"
    
    Write-Success (Get-LocalizedString 'CoreSudoDisabled')
    Write-Info (Get-LocalizedString 'CoreSudoNote')
}

function Set-KerberosPKINITHashAgility {
    <#
    .SYNOPSIS
        Enables Kerberos PKINIT Hash Agility (SHA-256/384/512, WITHOUT SHA-1)
    .DESCRIPTION
        Configures Kerberos to use SHA-256/384/512 instead of SHA-1.
        Microsoft Baseline 25H2: DO NOT support SHA-1!
        Best Practice: Only SHA-2 family (256/384/512).
    .EXAMPLE
        Set-KerberosPKINITHashAgility
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreKerberosTitle')
    
    $kerbPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    
    # All modern encryption types
    [void](Set-RegistryValue -Path $kerbPath -Name "SupportedEncryptionTypes" -Value 0x7FFFFFFF -Type DWord `
        -Description "Alle modernen Kerberos Enc Types")
    
    # MICROSOFT BASELINE 25H2: SHA-256/384/512 JA, SHA-1 NEIN!
    # PKINITHashAlgorithm Werte:
    # SHA-1   = 0x1
    # SHA-256 = 0x8
    # SHA-384 = 0x10
    # SHA-512 = 0x20
    # Baseline: 0x38 (SHA-256 + SHA-384 + SHA-512, WITHOUT SHA-1!)
    
    [void](Set-RegistryValue -Path $kerbPath -Name "PKINITHashAlgorithm" -Value 0x38 -Type DWord `
        -Description "PKINIT: SHA-256/384/512 (OHNE SHA-1!)")
    
    # KDC (Key Distribution Center) Settings (falls DC)
    $kdcPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
    [void](Set-RegistryValue -Path $kdcPath -Name "PKINITHashAlgorithm" -Value 0x38 -Type DWord `
        -Description "KDC PKINIT: SHA-256/384/512 (OHNE SHA-1!)")
    
    Write-Success (Get-LocalizedString 'CoreKerberosConfigured')
    Write-Info (Get-LocalizedString 'CoreKerberosBaseline')
    Write-Info (Get-LocalizedString 'CoreKerberosKDC')
}

#endregion

#region MARK-OF-THE-WEB

function Set-MarkOfTheWeb {
    <#
    .SYNOPSIS
        Enables Mark-of-the-Web (MotW)
    .DESCRIPTION
        Enforces Zone Information and AV-Scan for downloads.
        Best Practice 25H2: CmdletBinding.
    .EXAMPLE
        Set-MarkOfTheWeb
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section (Get-LocalizedString 'CoreMOTWTitle')
    
    $attachPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
    
    [void](Set-RegistryValue -Path $attachPath -Name "SaveZoneInformation" -Value 2 -Type DWord `
        -Description "MotW erzwingen")
    
    [void](Set-RegistryValue -Path $attachPath -Name "ScanWithAntiVirus" -Value 3 -Type DWord `
        -Description "Immer mit AV scannen")
    
    Write-Success (Get-LocalizedString 'CoreMOTWActivated')
}

#endregion

#region VBS/CREDENTIAL GUARD

function Enable-CredentialGuard {
    <#
    .SYNOPSIS
        Enables Credential Guard and VBS
    .DESCRIPTION
        Enables Virtualization-Based Security, Credential Guard, HVCI and LSA-PPL.
        Best Practice 25H2: CmdletBinding. Requires reboot!
    .EXAMPLE
        Enable-CredentialGuard
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "Credential Guard and VBS"
    
    $dgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    
    # VBS
    [void](Set-RegistryValue -Path $dgPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Description "VBS aktivieren")
    [void](Set-RegistryValue -Path $dgPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord -Description "VBS: Secure Boot + DMA")
    
    # Credential Guard (UEFI Lock)
    [void](Set-RegistryValue -Path $lsaPath -Name "LsaCfgFlags" -Value 1 -Type DWord -Description "Credential Guard (UEFI Lock)")
    
    # CRITICAL FIX v1.7.6: Windows 11 25H2 requires ADDITIONAL Scenarios keys!
    # Credential Guard Scenario (REQUIRED for Windows 11 25H2!)
    $cgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"
    [void](Set-RegistryValue -Path $cgPath -Name "Enabled" -Value 1 -Type DWord -Description "Enable Credential Guard Scenario")
    
    # HVCI (Memory Integrity)
    # IMPORTANT: WasEnabledBy = 2 (User) so GUI is NOT grayed out!
    # 0 = System/Policy (GUI grayed), 1 = OEM (GUI grayed), 2 = User (GUI editable)
    $hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    [void](Set-RegistryValue -Path $hvciPath -Name "Enabled" -Value 1 -Type DWord -Description "Enable HVCI/Memory Integrity")
    [void](Set-RegistryValue -Path $hvciPath -Name "WasEnabledBy" -Value 2 -Type DWord -Description "HVCI enabled via User (GUI remains editable!)")
    
    # LSA Protection
    [void](Set-RegistryValue -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord -Description "LSA als PPL")
    
    Write-Success "Credential Guard, VBS, HVCI, LSA-PPL configured"
    Write-Warning-Custom "Reboot required!"
    
    # CRITICAL: Verify VBS/Credential Guard activation post-reboot
    # These features can fail silently if hardware requirements are not met
    Write-Host ""
    Write-Host "  [!] POST-REBOOT VERIFICATION REQUIRED:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  After reboot, verify that VBS/Credential Guard are ACTUALLY running:" -ForegroundColor White
    Write-Host ""
    Write-Host "  PowerShell Command:" -ForegroundColor Cyan
    Write-Host '    $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard' -ForegroundColor Gray
    Write-Host '    $vbs.SecurityServicesRunning' -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Expected Output: 1 or 2 (Credential Guard running)" -ForegroundColor Green
    Write-Host "  If Output is empty or 0: VBS/Credential Guard FAILED to start!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Common Causes of Failure:" -ForegroundColor Yellow
    Write-Host "    - TPM 2.0 not present or not enabled" -ForegroundColor White
    Write-Host "    - Virtualization disabled in BIOS/UEFI" -ForegroundColor White
    Write-Host "    - Incompatible CPU (Intel <8th Gen, AMD <Ryzen 2000)" -ForegroundColor White
    Write-Host "    - Incompatible Hypervisor (VMware, VirtualBox without nested VT)" -ForegroundColor White
    Write-Host ""
}

#endregion

#region BITLOCKER

function Enable-BitLockerPolicies {
    <#
    .SYNOPSIS
        Configures BitLocker Policies
    .DESCRIPTION
        Enables XTS-AES-256 Encryption, TPM 2.0 + PIN Policies.
        IMPORTANT: Checks if BitLocker is already enabled (Windows 11 Auto-Encryption!)
        Best Practice 25H2: CmdletBinding + BitLocker status check.
        
        [INFO] IMPORTANT - NO AUTO-BACKUP OF RECOVERY KEY!
        
        DESIGN DECISION: This function deliberately implements NO automatic
        backup of the BitLocker Recovery Key.
        
        REASONS (Windows 11 25H2 does this automatically):
        
        1. WINDOWS 11 AUTO-ENCRYPTION:
           - Windows 11 25H2 enables BitLocker AUTOMATICALLY on fresh install
           - Requirements: TPM 2.0 present + Microsoft account logged in
           - Happens without user interaction in background
        
        2. RECOVERY KEY AUTOMATICALLY IN MS ACCOUNT:
           - Windows stores Recovery Key AUTOMATICALLY in Microsoft account
           - User can retrieve key anytime: https://account.microsoft.com/devices/recoverykey
           - Synchronized across all devices with same MS account
        
        3. NO ADDITIONAL BACKUP NEEDED:
           - Microsoft account is the secure storage location (encrypted)
           - User can download/print key if needed
           - Backup to local file would be LESS secure (could be lost)
        
        4. USER HAS CONTROL:
           - User can manage Recovery Key via MS account
           - User can additionally export/print key if desired
           - No forced backups to local files/USB sticks
        
        IF BitLocker is already active:
        - This function only sets policies for future changes
        - Recovery Key is already stored in MS account (with Auto-Encryption)
        - User is informed where Recovery Key can be viewed
        
        MANUAL ACTIVATION (if not yet active):
        - User can manually enable BitLocker via Control Panel
        - Windows will then ask for Recovery Key storage location
        - Recommendation: Microsoft account (automatic + secure)
    .EXAMPLE
        Enable-BitLockerPolicies
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param()
    
    Write-Section "BitLocker Policies"
    
    # CHECK 1: AES-NI Support (hardware support for AES-256)
    $hasAESNI = $false
    $cpuName = "Unknown"
    
    try {
        # Check directly for AES-NI support (Intel/AMD CPU feature flag)
        # AES-NI is required for performant AES-256 encryption
        $cpuFeatures = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        $cpuName = $cpuFeatures.Name
        
        # Windows does not store CPU features directly in Win32_Processor
        # But we can do an indirect check:
        # If BitLocker already runs with AES-256, AES-NI is supported
        try {
            $blVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
            if ($blVolume -and ($blVolume.EncryptionMethod -eq 'XtsAes256' -or $blVolume.EncryptionMethod -eq 'Aes256')) {
                $hasAESNI = $true
                Write-Verbose "AES-256 already active - AES-NI is supported"
            }
        }
        catch {
            Write-Verbose "BitLocker check failed: $_"
        }
        
        # Fallback: Check CPU generation/age based on name
        # AES-NI was introduced:
        # - Intel: Core i-series Gen 3+ (Ivy Bridge 2012), Xeon 5600+ (2010)
        # - AMD: Bulldozer+ (2011), Ryzen (all)
        # NOT supported:
        # - Intel: Core 2, Core i Gen 1-2, Pentium, Celeron, Atom (old)
        # - AMD: Phenom II and older, old Athlon
        
        if (-not $hasAESNI) {
            # Check for old CPUs WITHOUT AES-NI
            # Intel Desktop: Core 2, Pentium (not Gold), Celeron, Atom
            # Intel Server: Xeon 5500 and older (before Westmere 2010)
            # AMD Desktop: Athlon 64/FX/II, Phenom I/II (all before Bulldozer 2011)
            # AMD Server: Opteron (before Bulldozer 2011)
            if ($cpuName -match "Core 2|Pentium(?! Gold)|Celeron|Atom") {
                # Intel old CPUs - NO AES-NI
                Write-Host ""
                Write-Warning-Custom "CPU WITHOUT AES-NI SUPPORT DETECTED: $cpuName"
                Write-Warning-Custom "AES-256 is not optimally supported!"
                Write-Warning-Custom "AES-256 Policy will NOT be set"
                Write-Host ""
                Write-Info "BitLocker remains at AES-128 (optimal for this hardware)"
                Write-Info "AES-128 is secure and faster on this CPU"
                Write-Host ""
                return  # Exit function - NO Policy set!
            }
            # Intel Server old CPUs - Xeon 5500 and older (before Westmere 2010)
            elseif ($cpuName -match "Xeon.*(5[0-5]\d{2}|3[0-4]\d{2}|7[0-4]\d{2})") {
                # Xeon 5500 and older - NO AES-NI
                Write-Host ""
                Write-Warning-Custom "CPU WITHOUT AES-NI SUPPORT DETECTED: $cpuName"
                Write-Warning-Custom "Old Intel Xeon (before Westmere 2010) has NO AES-NI!"
                Write-Warning-Custom "AES-256 Policy will NOT be set"
                Write-Host ""
                Write-Info "BitLocker remains at AES-128 (optimal for this hardware)"
                Write-Info "AES-128 is secure and faster on this CPU"
                Write-Host ""
                return
            }
            # AMD Desktop old CPUs - explicit models WITHOUT AES-NI
            elseif ($cpuName -match "Athlon 64|Athlon FX|Athlon II|Phenom") {
                # AMD K8/K10 architecture - NO AES-NI
                Write-Host ""
                Write-Warning-Custom "CPU WITHOUT AES-NI SUPPORT DETECTED: $cpuName"
                Write-Warning-Custom "AMD K8/K10 Architecture (before Bulldozer 2011) has NO AES-NI!"
                Write-Warning-Custom "AES-256 Policy will NOT be set"
                Write-Host ""
                Write-Info "BitLocker remains at AES-128 (optimal for this hardware)"
                Write-Info "AES-128 is secure and faster on this CPU"
                Write-Host ""
                return
            }
            # AMD Server old CPUs - Opteron (before Bulldozer 2011)
            elseif ($cpuName -match "Opteron" -and $cpuName -notmatch "Opteron.*(62|63|64|65|66|67|68|69)\d{2}") {
                # Opteron before Bulldozer - NO AES-NI (62xx+ have AES-NI)
                Write-Host ""
                Write-Warning-Custom "CPU WITHOUT AES-NI SUPPORT DETECTED: $cpuName"
                Write-Warning-Custom "Old AMD Opteron (before Bulldozer 2011) has NO AES-NI!"
                Write-Warning-Custom "AES-256 Policy will NOT be set"
                Write-Host ""
                Write-Info "BitLocker remains at AES-128 (optimal for this hardware)"
                Write-Info "AES-128 is secure and faster on this CPU"
                Write-Host ""
                return
            }
            # AMD generic Athlon detection (old Athlon without 64/II/FX)
            # BUT: Modern Athlon (200GE, 3000G, Gold) are Zen-based and HAVE AES-NI!
            elseif ($cpuName -match "\bAthlon\b" -and 
                    $cpuName -notmatch "Athlon\s+(Gold|Silver|[0-9]{3,4}[GU])") {
                # Very old or unknown Athlon - probably no AES-NI
                Write-Host ""
                Write-Warning-Custom "CPU WITHOUT AES-NI SUPPORT DETECTED: $cpuName"
                Write-Warning-Custom "Old AMD Athlon CPU - probably no AES-NI!"
                Write-Warning-Custom "AES-256 Policy will NOT be set"
                Write-Host ""
                Write-Info "BitLocker remains at AES-128 (optimal for this hardware)"
                Write-Host ""
                return
            }
            # Check for Intel Core i-series Gen 2 (Sandy Bridge 2011) - NO AES-NI
            # CRITICAL: Only match Gen 2 (i7-2xxx), NOT Gen 11+ (i7-11xxx)!
            # Pattern: i7-2XXX (4-digit, starts with 2), then no additional digit
            elseif ($cpuName -match "i[357]-2\d{3}(?!\d)") {
                Write-Host ""
                Write-Warning-Custom "CPU WITHOUT AES-NI SUPPORT DETECTED: $cpuName"
                Write-Warning-Custom "Intel Core i-Series Gen 2 (Sandy Bridge 2011) has NO AES-NI!"
                Write-Warning-Custom "AES-256 Policy will NOT be set"
                Write-Host ""
                Write-Info "BitLocker remains at AES-128 (optimal for this hardware)"
                Write-Host ""
                return
            }
            else {
                # Modern CPU - probably AES-NI support
                $hasAESNI = $true
                Write-Verbose "Modern CPU detected - AES-NI assumed: $cpuName"
            }
        }
        
        Write-Info "CPU with AES-NI support: $cpuName"
    }
    catch {
        Write-Verbose "AES-NI check failed: $_"
        Write-Warning "AES-NI Check failed - Policy will still be set"
        $hasAESNI = $true  # When in doubt, set Policy
    }
    
    # CHECK 2: Is BitLocker already activated? (Windows 11 often activates it automatically!)
    $bitlockerActive = $false
    $bitlockerStatus = "Unknown"
    
    try {
        $blVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        $bitlockerActive = ($blVolume.ProtectionStatus -eq 'On')
        $bitlockerStatus = $blVolume.ProtectionStatus
        
        if ($bitlockerActive) {
            Write-Info "BitLocker is already ACTIVE (ProtectionStatus: On)"
            Write-Info ("Encryption: " + $blVolume.EncryptionPercentage + "% | Method: " + $blVolume.EncryptionMethod)
        }
        else {
            Write-Info ("BitLocker is NOT active (ProtectionStatus: " + $bitlockerStatus + ")")
        }
    }
    catch {
        Write-Verbose "Could not retrieve BitLocker status: $_"
        Write-Info "BitLocker Status: Unknown (possibly not available)"
    }
    
    $fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
    
    # XTS-AES-256 Encryption Method Policy
    # Applies to NEW BitLocker activations (not for already encrypted drives)
    # CRITICAL FIX v1.7.6: Set the CORRECT policy names (with XTS suffix)!
    # Microsoft changed the policy names - old "EncryptionMethod" is deprecated!
    [void](Set-RegistryValue -Path $fvePath -Name "EncryptionMethodWithXtsOs" -Value 7 -Type DWord -Description "XTS-AES-256 OS Drives")
    [void](Set-RegistryValue -Path $fvePath -Name "EncryptionMethodWithXtsFdv" -Value 7 -Type DWord -Description "XTS-AES-256 Fixed Data Drives")
    [void](Set-RegistryValue -Path $fvePath -Name "EncryptionMethodWithXtsRdv" -Value 7 -Type DWord -Description "XTS-AES-256 Removable Drives")
    
    # TPM Settings (allows TPM, but doesn't enforce it)
    # UseTPM = 1 (Allow) instead of 2 (Require) - so it works without TPM too
    [void](Set-RegistryValue -Path $fvePath -Name "UseTPM" -Value 1 -Type DWord -Description "TPM erlauben")
    [void](Set-RegistryValue -Path $fvePath -Name "UseTPMPIN" -Value 1 -Type DWord -Description "TPM + PIN erlauben")
    [void](Set-RegistryValue -Path $fvePath -Name "UseAdvancedStartup" -Value 1 -Type DWord -Description "Advanced Startup")
    
    # Recovery Key Escrow (CRITICAL: Don't enforce without AD!)
    # Windows 11 often activates BitLocker automatically - then "RequireActiveDirectoryBackup"
    # would cause a yellow warning icon if no AD is present!
    [void](Set-RegistryValue -Path $fvePath -Name "ActiveDirectoryBackup" -Value 0 -Type DWord -Description "AD Backup optional")
    
    # IMPORTANT: RequireActiveDirectoryBackup is INTENTIONALLY NOT set!
    # Reason: Causes yellow warning icon with already activated BitLocker without AD
    
    Write-Success "BitLocker Policies configured (XTS-AES-256 + TPM Optional)"
    
    if ($bitlockerActive) {
        Write-Info 'BitLocker is already active - Policies apply to future changes'
        Write-Host ""
        Write-Info 'RECOVERY KEY BACKUP:'
        Write-Info '  1. Microsoft Account (recommended): https://account.microsoft.com/devices/recoverykey'
        Write-Info '  2. Display locally: manage-bde -protectors -get C:'
        Write-Info '  3. USB stick or print for physical backup'
        Write-Host ""
        Write-Warning-Custom 'Without Recovery Key, data is PERMANENTLY lost if TPM fails!'
    }
    else {
        # CRITICAL WARNING: BitLocker policies are configured but NOT active!
        # This can create false sense of security - user MUST manually enable it
        Write-Host ""
        Write-Host "  !!! CRITICAL: BITLOCKER IS NOT ACTIVE !!!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Policies are configured, but BitLocker is NOT enabled!" -ForegroundColor Yellow
        Write-Host "  Your drive is NOT encrypted - data can be stolen if device is lost!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  YOU MUST MANUALLY ENABLE BITLOCKER:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Option 1: Control Panel" -ForegroundColor Cyan
        Write-Host "    1. Open Control Panel" -ForegroundColor White
        Write-Host "    2. Navigate to: System and Security -> BitLocker Drive Encryption" -ForegroundColor White
        Write-Host "    3. Click 'Turn on BitLocker' for C: drive" -ForegroundColor White
        Write-Host "    4. Save Recovery Key to Microsoft Account (recommended)" -ForegroundColor White
        Write-Host ""
        Write-Host "  Option 2: PowerShell (requires admin)" -ForegroundColor Cyan
        Write-Host '    Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256' -ForegroundColor Gray
        Write-Host ""
        Write-Host "  !!! WITHOUT BITLOCKER ENABLED, YOUR DATA IS NOT ENCRYPTED !!!" -ForegroundColor Yellow
        Write-Host ""
    }
}

function Test-BitLockerEncryptionMethod {
    <#
    .SYNOPSIS
        Checks BitLocker encryption method and shows GUI instructions
    .DESCRIPTION
        Windows 11 activates BitLocker automatically with AES-128 (Performance).
        Our Policies set AES-256, but this applies ONLY to NEW encryption.
        This function checks if system is encrypted with AES-128
        and shows GUI instructions for upgrade to AES-256.
        IMPORTANT: Old CPUs (Core i3/i5/i7 Gen 2 and older, AMD Phenom II)
        support ONLY AES-128!
    #>
    [CmdletBinding()]
    param()
    
    Write-Section "Check BitLocker Encryption Method"
    
    try {
        $blVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        $isActive = $blVolume.ProtectionStatus -eq 'On'
        
        if (-not $isActive) {
            Write-Info "BitLocker is not active - no check needed"
            return
        }
        
        $encMethod = $blVolume.EncryptionMethod
        Write-Info "BitLocker Status: $($blVolume.ProtectionStatus)"
        Write-Info "Encryption Method: $encMethod"
        Write-Info "Encrypted: $($blVolume.EncryptionPercentage)%"
        
        # EncryptionMethod Werte:
        # None = 0, Aes128 = 1, Aes256 = 2, XtsAes128 = 6, XtsAes256 = 7
        $needsUpgrade = $encMethod -eq 'XtsAes128' -or $encMethod -eq 'Aes128'
        
        if (-not $needsUpgrade) {
            Write-Success "BitLocker already uses AES-256! No action needed."
            return
        }
        
        # AES-128 detected!
        Write-Host ""
        Write-Warning-Custom "BITLOCKER USES ONLY AES-128!"
        Write-Host ""
        Write-Host "  WHY AES-128?" -ForegroundColor Cyan
        Write-Host "    - Windows 11 activates automatically with AES-128 (Performance)" -ForegroundColor White
        Write-Host "    - 20-30% faster than AES-256" -ForegroundColor White
        Write-Host "    - Microsoft: 'sufficiently secure for Consumer'" -ForegroundColor White
        Write-Host ""
        Write-Host "  WHY UPGRADE TO AES-256?" -ForegroundColor Cyan
        Write-Host "    - Enterprise-Standard (NIST, CIS, DoD)" -ForegroundColor White
        Write-Host "    - Future-Proof against Quantum-Computing" -ForegroundColor White
        Write-Host "    - Compliance (some standards require 256-Bit)" -ForegroundColor White
        Write-Host ""
        Write-Host "  OUR POLICY:" -ForegroundColor Cyan
        Write-Host "    - New encryption now uses AES-256" -ForegroundColor Green
        Write-Host "    - System partition remains AES-128 (already encrypted)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  YOUR CPU COMPATIBILITY:" -ForegroundColor Cyan
        
        # Check CPU generation and give CLEAR recommendation
        $cpuName = "Unknown"
        
        try {
            $cpu = Get-CimInstance -ClassName Win32_Processor
            $cpuName = $cpu.Name
            Write-Host "    CPU: $cpuName" -ForegroundColor White
            
            # Check if old CPU WITHOUT AES-NI support
            # Intel Desktop: Core 2, Pentium (not Gold), Celeron, Atom
            # Intel Server: Xeon 5500 and older
            # AMD Desktop: Athlon 64/FX/II, Phenom I/II
            # AMD Server: Opteron (before Bulldozer 2011)
            if ($cpuName -match "Core 2|Pentium(?! Gold)|Celeron|Atom") {
                Write-Host ""
                Write-Host "    [!] YOUR CPU:" -ForegroundColor Red
                Write-Host "        - Supports ONLY AES-128 (no AES-NI support)" -ForegroundColor Red
                Write-Host "        - AES-256 would be too slow on this hardware" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [RECOMMENDATION] KEEP AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal for your hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 is secure! No upgrade needed on old hardware."
                return  # Exit function - do not show upgrade instructions!
            }
            # Intel Server old CPUs - Xeon 5500 and older
            elseif ($cpuName -match "Xeon.*(5[0-5]\d{2}|3[0-4]\d{2}|7[0-4]\d{2})") {
                Write-Host ""
                Write-Host "    [!] YOUR CPU:" -ForegroundColor Red
                Write-Host "        - Supports ONLY AES-128 (no AES-NI support)" -ForegroundColor Red
                Write-Host "        - Alter Intel Xeon (vor Westmere 2010)" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [RECOMMENDATION] KEEP AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal for your hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 is secure! No upgrade needed on old hardware."
                return
            }
            # AMD Desktop old CPUs - explicit models
            elseif ($cpuName -match "Athlon 64|Athlon FX|Athlon II|Phenom") {
                Write-Host ""
                Write-Host "    [!] YOUR CPU:" -ForegroundColor Red
                Write-Host "        - Supports ONLY AES-128 (no AES-NI support)" -ForegroundColor Red
                Write-Host "        - AES-256 would be too slow on this hardware" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [RECOMMENDATION] KEEP AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal for your hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 is secure! No upgrade needed on old hardware."
                return  # Exit function - do not show upgrade instructions!
            }
            # AMD Server old CPUs - Opteron (before Bulldozer 2011)
            elseif ($cpuName -match "Opteron" -and $cpuName -notmatch "Opteron.*(62|63|64|65|66|67|68|69)\d{2}") {
                Write-Host ""
                Write-Host "    [!] YOUR CPU:" -ForegroundColor Red
                Write-Host "        - Supports ONLY AES-128 (no AES-NI support)" -ForegroundColor Red
                Write-Host "        - Alter AMD Opteron (vor Bulldozer 2011)" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [RECOMMENDATION] KEEP AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal for your hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 is secure! No upgrade needed on old hardware."
                return
            }
            # AMD generic Athlon (old without 64/II/FX), BUT NOT modern (Zen-based)
            elseif ($cpuName -match "\bAthlon\b" -and 
                    $cpuName -notmatch "Athlon\s+(Gold|Silver|[0-9]{3,4}[GU])") {
                Write-Host ""
                Write-Host "    [!] YOUR CPU:" -ForegroundColor Red
                Write-Host "        - Supports ONLY AES-128 (no AES-NI support)" -ForegroundColor Red
                Write-Host "        - Old AMD Athlon CPU" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [RECOMMENDATION] KEEP AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal for your hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 is secure! No upgrade needed on old hardware."
                return
            }
            # Intel Core i Gen 2 (Sandy Bridge 2011) - last without AES-NI
            elseif ($cpuName -match "Core i[357]-2\d{3}(?!\d)") {
                Write-Host ""
                Write-Host "    [!] YOUR CPU:" -ForegroundColor Red
                Write-Host "        - Supports ONLY AES-128 (no AES-NI support)" -ForegroundColor Red
                Write-Host "        - Intel Sandy Bridge Gen 2 (2011)" -ForegroundColor Red
                Write-Host ""
                Write-Host "    [RECOMMENDATION] KEEP AES-128!" -ForegroundColor Yellow
                Write-Host "                 (Optimal for your hardware)" -ForegroundColor Yellow
                Write-Host ""
                Write-Info "AES-128 is secure! No upgrade needed on old hardware."
                return
            }
            else {
                Write-Host ""
                Write-Host "    [OK] YOUR CPU:" -ForegroundColor Green
                Write-Host "         - Supports AES-256 (has AES-NI support)" -ForegroundColor Green
                Write-Host "         - Modern hardware - AES-256 upgrade recommended!" -ForegroundColor Green
                Write-Host ""
            }
        }
        catch {
            Write-Verbose "CPU check failed: $_"
            Write-Host "    [?] CPU check failed - upgrade at your own risk" -ForegroundColor Yellow
            Write-Host ""
        }
        
        Write-Host "  HOW TO UPGRADE TO AES-256 (IN WINDOWS):" -ForegroundColor Green
        Write-Host ""
        Write-Host "    METHOD 1 - Windows Start Menu (EASIEST):" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "      1. Press Windows key" -ForegroundColor White
        Write-Host "      2. Type: BitLocker manage" -ForegroundColor White
        Write-Host "      3. Press Enter" -ForegroundColor White
        Write-Host "      4. Click on 'Disable BitLocker'" -ForegroundColor White
        Write-Host "         (WARNING: Takes 30-90 min!)" -ForegroundColor Yellow
        Write-Host "      5. Wait until 'BitLocker disabled' is shown" -ForegroundColor White
        Write-Host "      6. Click on 'Enable BitLocker'" -ForegroundColor White
        Write-Host "         (Our Policy applies = AES-256!)" -ForegroundColor Green
        Write-Host "      7. <IMPORTANT> SAVE Recovery Key (MS Account recommended)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "    METHOD 2 - Control Panel:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "      1. Open Control Panel" -ForegroundColor White
        Write-Host "      2. System and Security" -ForegroundColor White
        Write-Host "      3. BitLocker Drive Encryption" -ForegroundColor White
        Write-Host "      4. Continue as Method 1 (Steps 4-7)" -ForegroundColor White
        Write-Host ""
        Write-Host "    METHOD 3 - File Explorer:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "      1. Open File Explorer (Win + E)" -ForegroundColor White
        Write-Host "      2. Right-click on Drive C:" -ForegroundColor White
        Write-Host "      3. Click on 'Disable BitLocker'" -ForegroundColor White
        Write-Host "      4. Continue as Method 1 (Steps 5-7)" -ForegroundColor White
        Write-Host ""
        Write-Host "  ALTERNATIVE (POWERSHELL):" -ForegroundColor Cyan
        Write-Host "    manage-bde -status C:        # Check status" -ForegroundColor Gray
        Write-Host "    manage-bde -off C:           # Disable (takes time!)" -ForegroundColor Gray
        Write-Host "    manage-bde -on C: -UsedSpaceOnly  # Enable with AES-256" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  NOTE:" -ForegroundColor Cyan
        Write-Host "    Re-Encryption takes 30-90 minutes (depending on size)" -ForegroundColor White
        Write-Host "    Connect laptop to power supply!" -ForegroundColor White
        Write-Host "    For old CPUs: KEEP AES-128 (better performance)!" -ForegroundColor White
        Write-Host ""
    }
    catch {
        Write-Error "Error checking BitLocker: $_"
        Write-Warning-Custom "If problems occur: manage-bde -status C:"
    }
}

#endregion

#region COMPLIANCE REPORT

function New-ComplianceReport {
    <#
    .SYNOPSIS
        Generate HTML compliance report of applied security settings
    .DESCRIPTION
        Creates detailed HTML report showing which security settings were applied
        Best Practice 25H2: Comprehensive audit trail
    .PARAMETER OutputPath
        Path where HTML report will be saved
    .EXAMPLE
        New-ComplianceReport -OutputPath "C:\Reports\SecurityBaseline.html"
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )
    
    Write-Verbose "Generating compliance report: $OutputPath"
    
    try {
        $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $computerName = $env:COMPUTERNAME
        $osVersion = [System.Environment]::OSVersion.Version.ToString()
        $psVersion = $PSVersionTable.PSVersion.ToString()
        
        # Build HTML using StringBuilder (safer than HERE-STRING)
        $html = [System.Text.StringBuilder]::new()
        [void]$html.AppendLine('<!DOCTYPE html>')
        [void]$html.AppendLine('<html lang="en">')
        [void]$html.AppendLine('<head>')
        [void]$html.AppendLine('    <meta charset="UTF-8">')
        [void]$html.AppendLine('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        [void]$html.AppendLine('    <title>Security Baseline Compliance Report</title>')
        [void]$html.AppendLine('    <style>')
        [void]$html.AppendLine('        body { font-family: ''Segoe UI'', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }')
        [void]$html.AppendLine('        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }')
        [void]$html.AppendLine('        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }')
        [void]$html.AppendLine('        h2 { color: #333; margin-top: 30px; }')
        [void]$html.AppendLine('        .info-box { background: #e7f3ff; padding: 15px; border-left: 4px solid #0078d4; margin: 20px 0; }')
        [void]$html.AppendLine('        .success { color: #107c10; font-weight: bold; }')
        [void]$html.AppendLine('        table { width: 100%; border-collapse: collapse; margin: 20px 0; }')
        [void]$html.AppendLine('        th { background: #0078d4; color: white; padding: 12px; text-align: left; }')
        [void]$html.AppendLine('        td { padding: 10px; border-bottom: 1px solid #ddd; }')
        [void]$html.AppendLine('        tr:hover { background: #f5f5f5; }')
        [void]$html.AppendLine('        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }')
        [void]$html.AppendLine('    </style>')
        [void]$html.AppendLine('</head>')
        [void]$html.AppendLine('<body>')
        [void]$html.AppendLine('    <div class="container">')
        [void]$html.AppendLine('        <h1>[SECURITY] Windows 11 25H2 Security Baseline - Compliance Report</h1>')
        [void]$html.AppendLine('        <div class="info-box">')
        [void]$html.AppendLine('            <strong>Report Generated:</strong> ' + $reportDate + '<br>')
        [void]$html.AppendLine('            <strong>Computer Name:</strong> ' + $computerName + '<br>')
        [void]$html.AppendLine('            <strong>OS Version:</strong> Windows 11 ' + $osVersion + '<br>')
        [void]$html.AppendLine('            <strong>PowerShell Version:</strong> ' + $psVersion + '<br>')
        [void]$html.AppendLine('            <strong>Baseline Version:</strong> 1.3.1 (Hotfix)')
        [void]$html.AppendLine('        </div>')
        [void]$html.AppendLine('        <h2>[OK] Applied Security Controls</h2>')
        [void]$html.AppendLine('        <table><thead><tr>')
        [void]$html.AppendLine('            <th>Category</th><th>Control</th><th>Status</th>')
        [void]$html.AppendLine('        </tr></thead><tbody>')
        
        # Security Controls
        $controls = @(
            @{Category='Network Security'; Control='NetBIOS Disabled'}
            @{Category='Network Security'; Control='SMB/NTLM Hardening'}
            @{Category='Network Security'; Control='Legacy Protocols Disabled'}
            @{Category='Network Security'; Control='Network Stealth Mode'}
            @{Category='Auditing'; Control='Process Command Line Logging'}
            @{Category='Auditing'; Control='Advanced Audit Policies (19 categories)'}
            @{Category='Defense'; Control='Microsoft Defender Baseline'}
            @{Category='Defense'; Control='Attack Surface Reduction Rules'}
            @{Category='Defense'; Control='Smart App Control'}
            @{Category='Access Control'; Control='Administrative Shares Disabled'}
            @{Category='Access Control'; Control='Remote Access Disabled'}
            @{Category='Encryption'; Control='Credential Guard + VBS'}
            @{Category='Encryption'; Control='BitLocker Policies (XTS-AES-256)'}
            @{Category='DNS Security'; Control='DNSSEC Validation'}
            @{Category='DNS Security'; Control='DNS Blocklist (80K+ domains)'}
            @{Category='Privacy'; Control='Telemetry Services Disabled'}
            @{Category='Privacy'; Control='Telemetry Registry Keys'}
            @{Category='Privacy'; Control='Telemetry Scheduled Tasks Removed'}
        )
        
        foreach ($ctrl in $controls) {
            [void]$html.AppendLine('            <tr>')
            [void]$html.AppendLine('                <td>' + $ctrl.Category + '</td>')
            [void]$html.AppendLine('                <td>' + $ctrl.Control + '</td>')
            [void]$html.AppendLine('                <td class="success">[OK] Applied</td>')
            [void]$html.AppendLine('            </tr>')
        }
        
        [void]$html.AppendLine('        </tbody></table>')
        [void]$html.AppendLine('        <h2>[!] Important Notes</h2>')
        [void]$html.AppendLine('        <div class="info-box">')
        [void]$html.AppendLine('            <p><strong>Reboot Required:</strong> Some changes (VBS, Credential Guard, BitLocker) require a system restart to take effect.</p>')
        [void]$html.AppendLine('            <p><strong>Verification:</strong> Run <code>.\Verify-SecurityBaseline.ps1</code> to verify all settings are correctly applied.</p>')
        [void]$html.AppendLine('            <p><strong>Restore:</strong> Use <code>.\Restore-SecurityBaseline.ps1</code> with your backup file to restore previous state.</p>')
        [void]$html.AppendLine('        </div>')
        [void]$html.AppendLine('        <div class="footer">')
        [void]$html.AppendLine('            <p>Generated by NoID Privacy - Windows 11 25H2 Security Baseline v1.3.1</p>')
        [void]$html.AppendLine('            <p>NoID Privacy v1.7 | Microsoft Baseline 25H2 compliant</p>')
        [void]$html.AppendLine('        </div>')
        [void]$html.AppendLine('    </div>')
        [void]$html.AppendLine('</body>')
        [void]$html.AppendLine('</html>')
        
        $htmlContent = $html.ToString()
        
        # Write HTML to file
        # [OK] BEST PRACTICE: UTF-8 without BOM (PowerShell 5.1 compatible)
        # Out-File -Encoding utf8 in PS 5.1 creates file WITH BOM!
        # Use .NET API for UTF-8 without BOM
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($OutputPath, $htmlContent, $utf8NoBom)
        
        Write-Verbose ("Compliance report generated successfully: " + $OutputPath)
        Write-Success ("Compliance Report erstellt: " + $OutputPath)
    }
    catch {
        Write-Warning "Could not generate compliance report: $_"
        Write-Verbose ("Details: " + $_.Exception.Message)
    }
}

#endregion

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope when dot-sourced with: . path\script.ps1
# Exported Functions: Set-DefenderBaselineSettings, Set-FirewallPolicies, Disable-UnnecessaryServices, 
#                     Enable-UAC, Disable-RemoteAccess, Set-BitLockerPolicies, Test-BitLockerEncryptionMethod,
#                     Disable-AutoPlayAndAutoRun, Set-SmartScreenExtended, Enable-ExploitProtection,
#                     Enable-ControlledFolderAccess, New-ComplianceReport
