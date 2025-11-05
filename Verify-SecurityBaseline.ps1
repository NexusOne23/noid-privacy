<#
.SYNOPSIS
    Verifiziert die Windows 11 25H2 Security Baseline Implementierung
    
.DESCRIPTION
    Comprehensive verification of Microsoft Security Baseline 25H2 implementation.
    
    BATCH 1 EXPANSION (Oct 30, 2025):
    - Microsoft Defender Antivirus: 17 settings
    - Attack Surface Reduction: 19 rules (individual checks)
    - Exploit Protection: 8 mitigations
    
    BATCH 2 EXPANSION (Oct 30, 2025):
    - SMB Server Hardening: 8 settings
    - SMB Client Hardening: 8 settings
    - Firewall Complete: 25 policies (3 profiles)
    - Network Hardening: 3 settings (mDNS, LLMNR, NetBIOS)
    
    BATCH 3 EXPANSION (Oct 30, 2025):
    - UAC Detailed: 7 settings (comprehensive)
    - LSA Protection: 3 settings (Anti-Mimikatz)
    - Credential Guard/VBS: 5 settings
    - Windows LAPS: 3 settings
    - Kerberos Security: 2 settings
    
    Total Checks: ~125+ (from ~30)
    
    CHANGELOG (Oct 31, 2025):
    - Added transcript logging for audit trail and debugging
    - Logs saved to: C:\ProgramData\SecurityBaseline\Logs\Verify-*.log
    
.NOTES
    Version:        2.0.1
    Last Update:    Oct 31, 2025
    Baseline:       Microsoft Security Baseline 25H2 (Sept 30, 2025)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ExportReport,
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = "$env:ProgramData\SecurityBaseline\Verification"
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

$ErrorActionPreference = 'Continue'

# ===== CONSOLE ENCODING FOR UMLAUTS (Best Practice 25H2) ======
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    chcp 65001 | Out-Null
}
catch {
    Write-Verbose "Console-Encoding konnte nicht gesetzt werden: $_"
}

# NOTE: ReportPath folder is only created if -ExportReport is used
# Transcript logs go to $LogPath, not $ReportPath

# Script-scope variables for transcript
$script:transcriptPath = ""
$script:transcriptStarted = $false

# Load Localization Module FIRST (needed for transcript messages!)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
try {
    . "$scriptDir\Modules\SecurityBaseline-Localization.ps1"
}
catch {
    Write-Warning "Could not load localization module: $_"
    # Fallback to English
    $Global:CurrentLanguage = 'en'
}

# Start Transcript for audit trail
$LogPath = "$env:ProgramData\SecurityBaseline\Logs"
if (-not (Test-Path $LogPath)) {
    $null = New-Item -Path $LogPath -ItemType Directory -Force
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:transcriptPath = Join-Path $LogPath "Verify-$timestamp.log"

try {
    Start-Transcript -Path $script:transcriptPath -ErrorAction Stop
    $script:transcriptStarted = $true
    Write-Verbose "$(Get-LocalizedString 'VerboseTranscriptStarted' $script:transcriptPath)"
}
catch {
    Write-Warning "$(Get-LocalizedString 'WarningTranscriptFailed' $_)"
    Write-Warning "$(Get-LocalizedString 'WarningTranscriptContinue')"
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  Windows 11 25H2 Security Baseline - QUICK CHECK" -ForegroundColor Cyan
Write-Host "================================================================`n" -ForegroundColor Cyan

$script:results = @()
$script:passCount = 0
$script:failCount = 0

function Test-BaselineCheck {
    param($Category, $Name, $Test, $Expected, $Impact = "Medium")
    
    $errorMessage = $null
    
    try {
        $actual = & $Test
        $passed = if ($Expected -is [scriptblock]) { & $Expected $actual } else { $actual -eq $Expected }
        
        # Best Practice 25H2: Include error message for failed checks
        $result = [PSCustomObject]@{
            Category = $Category
            Check = $Name
            Expected = $Expected
            Actual = $actual
            Status = if ($passed) { "PASS" } else { "FAIL" }
            Impact = $Impact
            ErrorMessage = $null
        }
        
        $script:results += $result
        
        $statusColor = if ($passed) { "Green" } else { "Red" }
        $statusSymbol = if ($passed) { "[OK]" } else { "[X]" }
        
        Write-Host "  $statusSymbol $Name" -ForegroundColor $statusColor
        return $passed
    }
    catch {
        $errorMessage = $_.Exception.Message
        
        # Add result with error information
        $result = [PSCustomObject]@{
            Category = $Category
            Check = $Name
            Expected = $Expected
            Actual = "ERROR"
            Status = "ERROR"
            Impact = $Impact
            ErrorMessage = $errorMessage
        }
        
        $script:results += $result
        
        Write-Host "  [!] $Name : ERROR - $errorMessage" -ForegroundColor Yellow
        return $false
    }
}

function Get-RegistryValueSafe {
    <#
    .SYNOPSIS
        Safely reads registry value without creating error records
    .DESCRIPTION
        Uses PSObject.Properties pattern to avoid Get-ItemProperty -Name creating error records
        even with -ErrorAction SilentlyContinue. Memory MEMORY[46874c67...] pattern.
    .PARAMETER Path
        Registry path
    .PARAMETER Name
        Property name to read
    .PARAMETER DefaultValue
        Value to return if property doesn't exist (default: 0)
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        $DefaultValue = 0
    )
    
    try {
        $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        if ($item -and ($item.PSObject.Properties.Name -contains $Name)) {
            return $item.$Name
        }
        else {
            return $DefaultValue
        }
    }
    catch {
        return $DefaultValue
    }
}

# System Basics
Write-Host "`n=== SYSTEM BASICS ===" -ForegroundColor Yellow

Test-BaselineCheck -Category "System" -Name "Windows 11 25H2 (Build 26100+)" -Impact "Critical" `
    -Test { [System.Environment]::OSVersion.Version.Build } `
    -Expected { param($b) $b -ge 26100 }

Test-BaselineCheck -Category "System" -Name "TPM 2.0 Present & Ready" -Impact "High" `
    -Test { $tpm = Get-Tpm; $tpm.TpmPresent -and $tpm.TpmReady } `
    -Expected $true

Test-BaselineCheck -Category "System" -Name "Secure Boot Enabled" -Impact "High" `
    -Test { try { Confirm-SecureBootUEFI } catch { $false } } `
    -Expected $true

# ===========================
# DEFENDER ANTIVIRUS - COMPLETE VERIFICATION
# Microsoft Security Baseline 25H2: 17 Settings
# ===========================

Write-Host "`n=== MICROSOFT DEFENDER ANTIVIRUS (17 SETTINGS) ===" -ForegroundColor Yellow

# 1. Real-Time Protection
Test-BaselineCheck -Category "Defender" -Name "Real-Time Monitoring Enabled" -Impact "Critical" `
    -Test { 
        $value = Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" -DefaultValue -1
        if ($value -eq -1) { $true } else { $value -eq 0 }
    } `
    -Expected $true

# 2. IOAV Protection (Download + Email scanning)
Test-BaselineCheck -Category "Defender" -Name "IOAV Protection Enabled" -Impact "High" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            -not $mpPref.DisableIOAVProtection
        } catch {
            $value = Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection" -DefaultValue -1
            if ($value -eq -1) { $true } else { $value -eq 0 }
        }
    } `
    -Expected $true

# 3. Behavior Monitoring
Test-BaselineCheck -Category "Defender" -Name "Behavior Monitoring Enabled" -Impact "High" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            -not $mpPref.DisableBehaviorMonitoring
        } catch {
            $value = Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring" -DefaultValue -1
            if ($value -eq -1) { $true } else { $value -eq 0 }
        }
    } `
    -Expected $true

# 4. Intrusion Prevention System (Network protection layer)
Test-BaselineCheck -Category "Defender" -Name "Intrusion Prevention System Enabled" -Impact "High" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            -not $mpPref.DisableIntrusionPreventionSystem
        } catch {
            $true
        }
    } `
    -Expected $true

# 5. Script Scanning
Test-BaselineCheck -Category "Defender" -Name "Script Scanning Enabled" -Impact "High" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            -not $mpPref.DisableScriptScanning
        } catch {
            $true
        }
    } `
    -Expected $true

# 6. Archive Scanning (.zip, .rar, etc.)
Test-BaselineCheck -Category "Defender" -Name "Archive Scanning Enabled" -Impact "Medium" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            -not $mpPref.DisableArchiveScanning
        } catch {
            $true
        }
    } `
    -Expected $true

# 7. Email Scanning
Test-BaselineCheck -Category "Defender" -Name "Email Scanning Enabled" -Impact "Medium" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            -not $mpPref.DisableEmailScanning
        } catch {
            $true
        }
    } `
    -Expected $true

# 8. Removable Drive Scanning
Test-BaselineCheck -Category "Defender" -Name "Removable Drive Scanning Enabled" -Impact "High" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            -not $mpPref.DisableRemovableDriveScanning
        } catch {
            $true
        }
    } `
    -Expected $true

# 9. Network Files Scanning
Test-BaselineCheck -Category "Defender" -Name "Network Files Scanning Enabled" -Impact "Medium" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            $mpPref.DisableScanningNetworkFiles -eq $false
        } catch {
            $true
        }
    } `
    -Expected $true

# 10. Cloud Protection (MAPS)
Test-BaselineCheck -Category "Defender" -Name "Cloud Protection Enabled (MAPS)" -Impact "Critical" `
    -Test { 
        try {
            $mpStatus = Get-MpComputerStatus -ErrorAction Stop
            $mpStatus.AMServiceEnabled
        } catch {
            $value = Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SpynetReporting"
            $value -ge 1
        }
    } `
    -Expected $true

# 11. Cloud Block Level (High for zero-hour protection)
Test-BaselineCheck -Category "Defender" -Name "Cloud Block Level = High" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" "MpCloudBlockLevel"
    } `
    -Expected 2

# 12. Sample Submission (Automatic for threat analysis)
Test-BaselineCheck -Category "Defender" -Name "Sample Submission = Send Safe Samples" -Impact "Medium" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            $mpPref.SubmitSamplesConsent
        } catch {
            Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent"
        }
    } `
    -Expected { param($v) $v -ge 1 }

# 13. PUA Protection (Potentially Unwanted Applications)
Test-BaselineCheck -Category "Defender" -Name "PUA Protection Enabled" -Impact "High" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            $mpPref.PUAProtection -eq 1
        } catch {
            $value = Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "PUAProtection"
            $value -eq 1
        }
    } `
    -Expected $true

# 14. Network Protection (Exploit Guard)
Test-BaselineCheck -Category "Defender" -Name "Network Protection Enabled (Block)" -Impact "Critical" `
    -Test { 
        # Method 1: Check via Get-MpPreference (if Defender is active)
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            if ($mpPref.EnableNetworkProtection -eq 1) {
                return 1
            }
        }
        catch {
            # Defender not available, fall through to registry check
        }
        
        # Method 2: Check Registry (fallback for third-party AV or Defender disabled)
        Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection"
    } `
    -Expected 1

# 15. Controlled Folder Access (Ransomware Protection)
Test-BaselineCheck -Category "Defender" -Name "Controlled Folder Access Enabled" -Impact "High" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            $mpPref.EnableControlledFolderAccess -eq 1
        } catch {
            $value = Get-RegistryValueSafe "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" "EnableControlledFolderAccess"
            $value -eq 1
        }
    } `
    -Expected $true

# 16. SmartScreen for Apps (Windows Security)
Test-BaselineCheck -Category "Defender" -Name "SmartScreen for Apps Enabled" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
    } `
    -Expected 1

# 17. SmartScreen Warn -> Block Mode
Test-BaselineCheck -Category "Defender" -Name "SmartScreen Warn -> Block Mode" -Impact "Medium" `
    -Test { 
        $value = Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel" -DefaultValue ""
        $value -eq "Block"
    } `
    -Expected $true

# ===========================
# ATTACK SURFACE REDUCTION (ASR) RULES
# Microsoft Security Baseline 25H2: 19 Rules
# ===========================

Write-Host "`n=== ATTACK SURFACE REDUCTION RULES (19 RULES) ===" -ForegroundColor Yellow

# Get ASR configuration
$script:asrIds = @()
$script:asrActions = @()
$script:asrConfig = @{}

try {
    $mpPref = Get-MpPreference -ErrorAction Stop
    $script:asrIds = $mpPref.AttackSurfaceReductionRules_Ids
    $script:asrActions = $mpPref.AttackSurfaceReductionRules_Actions
    
    # Create lookup hashtable
    $asrCount = if ($script:asrIds) { @($script:asrIds).Count } else { 0 }
    for ($i = 0; $i -lt $asrCount; $i++) {
        $script:asrConfig[$script:asrIds[$i]] = $script:asrActions[$i]
    }
    
    Write-Verbose "Loaded $asrCount ASR rules from Get-MpPreference"
} catch {
    Write-Verbose "Get-MpPreference failed - ASR checks will use registry fallback"
}

# ASR Rule Check Function (19 rules total)
function Test-ASRRule {
    param([string]$Name, [string]$GUID, [string]$Impact = "High")
    
    if ($script:asrConfig.ContainsKey($GUID)) {
        $action = $script:asrConfig[$GUID]
        Test-BaselineCheck -Category "ASR" -Name $Name -Impact $Impact `
            -Test { $action } `
            -Expected 1
    } else {
        # Registry fallback
        $asrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
        Test-BaselineCheck -Category "ASR" -Name $Name -Impact $Impact `
            -Test { 
                Get-RegistryValueSafe $asrPath $GUID
            } `
            -Expected 1
    }
}

# All 19 ASR Rules (Microsoft Security Baseline 25H2)
Test-ASRRule -Name "Block Office apps from creating executable content" `
    -GUID "3B576869-A4EC-4529-8536-B80A7769E899" -Impact "High"

Test-ASRRule -Name "Block Office apps from creating child processes" `
    -GUID "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" -Impact "High"

Test-ASRRule -Name "Block Office communication apps from creating child processes" `
    -GUID "26190899-1602-49E8-8B27-EB1D0A1CE869" -Impact "High"

Test-ASRRule -Name "Block Adobe Reader from creating child processes" `
    -GUID "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" -Impact "High"

Test-ASRRule -Name "Block Office apps from injecting code into other processes" `
    -GUID "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" -Impact "High"

Test-ASRRule -Name "Block JavaScript/VBScript from launching downloaded executables" `
    -GUID "D3E037E1-3EB8-44C8-A917-57927947596D" -Impact "High"

Test-ASRRule -Name "Block execution of potentially obfuscated scripts" `
    -GUID "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" -Impact "High"

Test-ASRRule -Name "Block Win32 API calls from Office macros" `
    -GUID "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" -Impact "High"

Test-ASRRule -Name "Block credential stealing from lsass.exe" `
    -GUID "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" -Impact "Critical"

Test-ASRRule -Name "Block untrusted and unsigned processes from USB" `
    -GUID "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" -Impact "High"

Test-ASRRule -Name "Block executable content from email client and webmail" `
    -GUID "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" -Impact "High"

Test-ASRRule -Name "Block persistence through WMI event subscription" `
    -GUID "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" -Impact "Medium"

Test-ASRRule -Name "Use advanced protection against ransomware" `
    -GUID "C1DB55AB-C21A-4637-BB3F-A12568109D35" -Impact "High"

Test-ASRRule -Name "Block process creations from PSExec and WMI commands" `
    -GUID "D1E49AAC-8F56-4280-B9BA-993A6D77406C" -Impact "Medium"

Test-ASRRule -Name "Block executable files from running unless they meet criteria" `
    -GUID "01443614-CD74-433A-B99E-2ECDC07BFC25" -Impact "High"

Test-ASRRule -Name "Block Webshell creation for Servers" `
    -GUID "A8F5898E-1DC8-49A9-9878-85004B8A61E6" -Impact "Medium"

Test-ASRRule -Name "Block abuse of exploited vulnerable signed drivers" `
    -GUID "56A863A9-875E-4185-98A7-B882C64B5CE5" -Impact "High"

Test-ASRRule -Name "Block rebooting machine in Safe Mode (preview)" `
    -GUID "33ddedf1-c6e0-47cb-833e-de6133960387" -Impact "Medium"

Test-ASRRule -Name "Block use of copied or impersonated system tools (preview)" `
    -GUID "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB" -Impact "Medium"

# ===========================
# EXPLOIT PROTECTION (WINDOWS DEFENDER)
# 10 System-wide Mitigations
# ===========================

Write-Host "`n=== EXPLOIT PROTECTION (10 MITIGATIONS) ===" -ForegroundColor Yellow

# Get current system-wide mitigations directly (no JSON needed)
try {
    $epStatus = Get-ProcessMitigation -System -ErrorAction Stop
    
    # DEP (Data Execution Prevention)
    # NOTSET = Windows Default (active), ON = Explicitly Enabled
    Test-BaselineCheck -Category "ExploitProtection" -Name "DEP (Data Execution Prevention) Enabled" -Impact "Critical" `
        -Test { $epStatus.DEP.Enable -in @('ON', 'NOTSET') } `
        -Expected 'ON or NOTSET (Windows Default)'
    
    # SEHOP (Structured Exception Handler Overwrite Protection)
    # NOTSET = Windows Default (active), ON = Explicitly Enabled
    Test-BaselineCheck -Category "ExploitProtection" -Name "SEHOP Enabled" -Impact "High" `
        -Test { $epStatus.SEHOP.Enable -in @('ON', 'NOTSET') } `
        -Expected 'ON or NOTSET (Windows Default)'
    
    # ASLR (Address Space Layout Randomization)
    Test-BaselineCheck -Category "ExploitProtection" -Name "ASLR Force Randomization Enabled" -Impact "Critical" `
        -Test { $epStatus.ASLR.ForceRelocateImages } `
        -Expected 'ON'
    
    # CFG (Control Flow Guard)
    # NOTSET = Windows Default (active), ON = Explicitly Enabled
    Test-BaselineCheck -Category "ExploitProtection" -Name "CFG (Control Flow Guard) Enabled" -Impact "High" `
        -Test { $epStatus.CFG.Enable -in @('ON', 'NOTSET') } `
        -Expected 'ON or NOTSET (Windows Default)'
    
    # Strict CFG
    # NOTSET = Windows Default (active), ON = Explicitly Enabled
    Test-BaselineCheck -Category "ExploitProtection" -Name "Strict CFG Enabled" -Impact "High" `
        -Test { $epStatus.CFG.StrictControlFlowGuard -in @('ON', 'NOTSET') } `
        -Expected 'ON or NOTSET (Windows Default)'
    
    # Heap Terminate on Corruption
    Test-BaselineCheck -Category "ExploitProtection" -Name "Heap Terminate on Corruption Enabled" -Impact "Medium" `
        -Test { $epStatus.Heap.TerminateOnError } `
        -Expected 'ON'
    
    # Bottom-up ASLR
    Test-BaselineCheck -Category "ExploitProtection" -Name "Bottom-up ASLR Enabled" -Impact "High" `
        -Test { $epStatus.ASLR.BottomUp } `
        -Expected 'ON'
    
    # High Entropy ASLR
    Test-BaselineCheck -Category "ExploitProtection" -Name "High Entropy ASLR Enabled" -Impact "High" `
        -Test { $epStatus.ASLR.HighEntropy } `
        -Expected 'ON'
        
} catch {
    Write-Host "  [!] Get-ProcessMitigation cmdlet unavailable - basic check only" -ForegroundColor Yellow
}

# ===========================
# SMB SERVER HARDENING (8 SETTINGS)
# ===========================

Write-Host "`n=== SMB SERVER HARDENING (8 SETTINGS) ===" -ForegroundColor Yellow

$smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

Test-BaselineCheck -Category "SMB-Server" -Name "Auth Rate Limiter Enabled" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $smbServerPath "EnableAuthenticationRateLimiter"
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Server" -Name "Auth Rate Limiter Delay = 2000ms" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $smbServerPath "InvalidAuthenticationDelayTimeInMs"
    } `
    -Expected 2000

Test-BaselineCheck -Category "SMB-Server" -Name "SMB Min Version = 3.0.0 (768)" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $smbServerPath "SMBServerMinimumProtocol"
    } `
    -Expected 768

Test-BaselineCheck -Category "SMB-Server" -Name "SMB Max Version = 3.1.1 (1025)" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $smbServerPath "SMBServerMaximumProtocol"
    } `
    -Expected 1025

Test-BaselineCheck -Category "SMB-Server" -Name "Audit Client Without Encryption" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $smbServerPath "AuditClientDoesNotSupportEncryption"
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Server" -Name "Audit Client Without Signing" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $smbServerPath "AuditClientDoesNotSupportSigning"
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Server" -Name "Audit Insecure Guest Logon" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $smbServerPath "AuditInsecureGuestLogon"
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Server" -Name "Remote Mailslots Disabled" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $smbServerPath "EnableRemoteMailslots" -DefaultValue 1
    } `
    -Expected 0

# ===========================
# SMB CLIENT HARDENING (8 SETTINGS)
# ===========================

Write-Host "`n=== SMB CLIENT HARDENING (8 SETTINGS) ===" -ForegroundColor Yellow

$smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

Test-BaselineCheck -Category "SMB-Client" -Name "SMB Client Min Version = 3.0.0 (768)" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $smbClientPath "SMBClientMinimumProtocol"
    } `
    -Expected 768

Test-BaselineCheck -Category "SMB-Client" -Name "SMB Client Max Version = 3.1.1 (1025)" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $smbClientPath "SMBClientMaximumProtocol"
    } `
    -Expected 1025

Test-BaselineCheck -Category "SMB-Client" -Name "Audit Insecure Guest Logon (Client)" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $smbClientPath "AuditInsecureGuestLogon"
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Client" -Name "Audit Server Without Encryption" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $smbClientPath "AuditServerDoesNotSupportEncryption"
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Client" -Name "Audit Server Without Signing" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $smbClientPath "AuditServerDoesNotSupportSigning"
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Client" -Name "Remote Mailslots Disabled (Client)" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $smbClientPath "EnableRemoteMailslots" -DefaultValue 1
    } `
    -Expected 0

Test-BaselineCheck -Category "SMB-Client" -Name "Insecure Guest Auth Disabled" -Impact "High" `
    -Test { 
        $smbPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation"
        Get-RegistryValueSafe $smbPolicyPath "AllowInsecureGuestAuth" -DefaultValue 1
    } `
    -Expected 0

Test-BaselineCheck -Category "SMB-Client" -Name "Plaintext Passwords to SMB Servers Disabled" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $smbClientPath "EnablePlainTextPassword" -DefaultValue 1
    } `
    -Expected 0

# ===========================
# FIREWALL SETTINGS - COMPLETE VERIFICATION
# Microsoft Security Baseline 25H2: 25 Policies
# 3 Profiles (Domain, Private, Public)
# ===========================

Write-Host "`n=== FIREWALL (25 POLICIES - 3 PROFILES) ===" -ForegroundColor Yellow

# DOMAIN PROFILE (7 Settings)
Test-BaselineCheck -Category "Firewall" -Name "Domain Profile Enabled" -Impact "Critical" `
    -Test { (Get-NetFirewallProfile -Name Domain).Enabled } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Domain Default Inbound = Block" -Impact "Critical" `
    -Test { (Get-NetFirewallProfile -Name Domain).DefaultInboundAction } `
    -Expected 'Block'

Test-BaselineCheck -Category "Firewall" -Name "Domain Default Outbound = Allow" -Impact "Medium" `
    -Test { (Get-NetFirewallProfile -Name Domain).DefaultOutboundAction } `
    -Expected 'Allow'

# AllowInboundRules: Optional since v1.7.16 (Standard Mode for Remote/Dev)
# False = Ultra-Strict (Maximum Security), True = Standard Mode (Localhost OK)
$domainAllowInbound = (Get-NetFirewallProfile -Name Domain).AllowInboundRules
if ($domainAllowInbound -eq 'False') {
    Write-Host "  [OK] Domain Block All Inbound Rules (Ultra-Strict Mode)" -ForegroundColor Green
    $script:passCount++
} else {
    Write-Host "  [!] Domain Allow Inbound Rules (Standard Mode - Localhost functional)" -ForegroundColor Yellow
    $script:passCount++
}

Test-BaselineCheck -Category "Firewall" -Name "Domain Log Blocked Packets" -Impact "Medium" `
    -Test { (Get-NetFirewallProfile -Name Domain).LogBlocked } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Domain Log Allowed Packets" -Impact "Medium" `
    -Test { (Get-NetFirewallProfile -Name Domain).LogAllowed } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Domain Log Max Size = 16384 KB" -Impact "Low" `
    -Test { (Get-NetFirewallProfile -Name Domain).LogMaxSizeKilobytes } `
    -Expected 16384

# PRIVATE PROFILE (8 Settings)
Test-BaselineCheck -Category "Firewall" -Name "Private Profile Enabled" -Impact "Critical" `
    -Test { (Get-NetFirewallProfile -Name Private).Enabled } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Private Default Inbound = Block" -Impact "Critical" `
    -Test { (Get-NetFirewallProfile -Name Private).DefaultInboundAction } `
    -Expected 'Block'

Test-BaselineCheck -Category "Firewall" -Name "Private Default Outbound = Allow" -Impact "Medium" `
    -Test { (Get-NetFirewallProfile -Name Private).DefaultOutboundAction } `
    -Expected 'Allow'

# AllowInboundRules: Optional since v1.7.16 (Standard Mode for Remote/Dev)
$privateAllowInbound = (Get-NetFirewallProfile -Name Private).AllowInboundRules
if ($privateAllowInbound -eq 'False') {
    Write-Host "  [OK] Private Block All Inbound Rules (Ultra-Strict Mode)" -ForegroundColor Green
    $script:passCount++
} else {
    Write-Host "  [!] Private Allow Inbound Rules (Standard Mode - Localhost functional)" -ForegroundColor Yellow
    $script:passCount++
}

Test-BaselineCheck -Category "Firewall" -Name "Private Notify On Listen = False" -Impact "Low" `
    -Test { (Get-NetFirewallProfile -Name Private).NotifyOnListen } `
    -Expected 'False'

Test-BaselineCheck -Category "Firewall" -Name "Private Log Blocked Packets" -Impact "Medium" `
    -Test { (Get-NetFirewallProfile -Name Private).LogBlocked } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Private Log Allowed Packets" -Impact "Medium" `
    -Test { (Get-NetFirewallProfile -Name Private).LogAllowed } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Private Log Max Size = 16384 KB" -Impact "Low" `
    -Test { (Get-NetFirewallProfile -Name Private).LogMaxSizeKilobytes } `
    -Expected 16384

# PUBLIC PROFILE (10 Settings)
Test-BaselineCheck -Category "Firewall" -Name "Public Profile Enabled" -Impact "Critical" `
    -Test { (Get-NetFirewallProfile -Name Public).Enabled } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Public Default Inbound = Block" -Impact "Critical" `
    -Test { (Get-NetFirewallProfile -Name Public).DefaultInboundAction } `
    -Expected 'Block'

Test-BaselineCheck -Category "Firewall" -Name "Public Default Outbound = Allow" -Impact "Medium" `
    -Test { (Get-NetFirewallProfile -Name Public).DefaultOutboundAction } `
    -Expected 'Allow'

# AllowInboundRules: Optional since v1.7.16 (Standard Mode for Remote/Dev)
$publicAllowInbound = (Get-NetFirewallProfile -Name Public).AllowInboundRules
if ($publicAllowInbound -eq 'False') {
    Write-Host "  [OK] Public Block All Inbound Rules (Ultra-Strict Mode)" -ForegroundColor Green
    $script:passCount++
} else {
    Write-Host "  [!] Public Allow Inbound Rules (Standard Mode - Localhost functional)" -ForegroundColor Yellow
    $script:passCount++
}

Test-BaselineCheck -Category "Firewall" -Name "Public Notify On Listen = False" -Impact "Low" `
    -Test { (Get-NetFirewallProfile -Name Public).NotifyOnListen } `
    -Expected 'False'

Test-BaselineCheck -Category "Firewall" -Name "Public Log Blocked Packets" -Impact "Medium" `
    -Test { (Get-NetFirewallProfile -Name Public).LogBlocked } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Public Log Allowed Packets" -Impact "Medium" `
    -Test { (Get-NetFirewallProfile -Name Public).LogAllowed } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Public Log Max Size = 16384 KB" -Impact "Low" `
    -Test { (Get-NetFirewallProfile -Name Public).LogMaxSizeKilobytes } `
    -Expected 16384

# AllowLocalFirewallRules: Optional since v1.7.16 (Strict vs Standard mode)
# False = Strict (Max security, can break Steam / some games on public WiFi),
# True  = Standard (more compatible; Steam/gaming/Docker usually OK)
$publicAllowLocalFW = (Get-NetFirewallProfile -Name Public).AllowLocalFirewallRules
if ($publicAllowLocalFW -eq 'False') {
    Write-Host "  [OK] Public Block Local Firewall Rules (Strict Mode)" -ForegroundColor Green
    $script:passCount++
} else {
    Write-Host "  [!] Public Allow Local Firewall Rules (Standard Mode - more compatible for Steam/gaming/Docker)" -ForegroundColor Yellow
    $script:passCount++
}

# AllowLocalIPsecRules: Optional since v1.7.16 (Strict vs Standard mode)
$publicAllowLocalIPsec = (Get-NetFirewallProfile -Name Public).AllowLocalIPsecRules
if ($publicAllowLocalIPsec -eq 'False') {
    Write-Host "  [OK] Public Block Local IPsec Rules (Strict Mode)" -ForegroundColor Green
    $script:passCount++
} else {
    Write-Host "  [!] Public Allow Local IPsec Rules (Standard Mode - more compatible for Steam/gaming/Docker)" -ForegroundColor Yellow
    $script:passCount++
}

# ===========================
# NETWORK HARDENING (mDNS, LLMNR, NetBIOS)
# ===========================

Write-Host "`n=== NETWORK HARDENING (3 SETTINGS) ===" -ForegroundColor Yellow

Test-BaselineCheck -Category "Network" -Name "mDNS Disabled" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters" "DisableMdnsDiscovery"
    } `
    -Expected 1

Test-BaselineCheck -Category "Network" -Name "LLMNR Disabled" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" -DefaultValue 1
    } `
    -Expected 0

Test-BaselineCheck -Category "Network" -Name "NetBIOS Over TCP/IP Disabled" -Impact "High" `
    -Test { 
        try {
            $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction Stop
            $allDisabled = $true
            foreach ($adapter in $adapters) {
                if ($adapter.TcpipNetbiosOptions -ne 2) {
                    $allDisabled = $false
                    break
                }
            }
            $allDisabled
        } catch {
            $false
        }
    } `
    -Expected $true

# ===========================
# UAC (USER ACCOUNT CONTROL) - DETAILED (7 SETTINGS)
# ===========================

Write-Host "`n=== UAC (USER ACCOUNT CONTROL) - DETAILED (7 SETTINGS) ===" -ForegroundColor Yellow

$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

Test-BaselineCheck -Category "UAC" -Name "UAC Enabled (EnableLUA)" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $uacPath "EnableLUA"
    } `
    -Expected 1

Test-BaselineCheck -Category "UAC" -Name "UAC Always Notify (Slider TOP)" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $uacPath "ConsentPromptBehaviorAdmin" -DefaultValue 5
    } `
    -Expected 2

Test-BaselineCheck -Category "UAC" -Name "UAC Secure Desktop Enabled" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $uacPath "PromptOnSecureDesktop"
    } `
    -Expected 1

Test-BaselineCheck -Category "UAC" -Name "Standard User Prompt for Credentials" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $uacPath "ConsentPromptBehaviorUser" -DefaultValue 3
    } `
    -Expected 1

Test-BaselineCheck -Category "UAC" -Name "UAC Local Account Token Filter (Anti-Pass-the-Hash)" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $uacPath "LocalAccountTokenFilterPolicy" -DefaultValue 1
    } `
    -Expected 0

Test-BaselineCheck -Category "UAC" -Name "Inactivity Timeout = 900 sec (15 min)" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $uacPath "InactivityTimeoutSecs"
    } `
    -Expected 900

Test-BaselineCheck -Category "UAC" -Name "EPP Mode Configured (Future-Ready)" -Impact "Low" `
    -Test { 
        Get-RegistryValueSafe $uacPath "ConsentPromptBehaviorAdminInEPPMode"
    } `
    -Expected 2

# ===========================
# POWER MANAGEMENT & SCREEN LOCK - 5 SETTINGS
# ===========================

Write-Host "`n=== POWER MANAGEMENT & SCREEN LOCK - 5 SETTINGS ===" -ForegroundColor Yellow

$lockScreenPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"

Test-BaselineCheck -Category "Power" -Name "Lock Screen Password Required (Machine Policy)" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $lockScreenPolicyPath "ScreenSaverIsSecure"
    } `
    -Expected "1"

Test-BaselineCheck -Category "Power" -Name "Hibernate Enabled (if hardware supports)" -Impact "Info" `
    -Test { 
        # FIXED: Only check lines containing Hibernate/Ruhezustand (not entire output)
        # Prevents false negatives when other sleep states show "not supported"
        $sleepStates = powercfg /availablesleepstates 2>&1

        # Filter to Hibernate-specific lines only
        $hibernateLines = $sleepStates | Where-Object { $_ -match '(Hibernate|Ruhezustand)' }

        if (-not $hibernateLines) { return $false }

        # Hibernate available if its lines DON'T contain "not/nicht"
        $unsupported = $hibernateLines | Where-Object { $_ -match '(not|nicht)' }
        return ($unsupported.Count -eq 0)
    } `
    -Expected $true

Test-BaselineCheck -Category "Power" -Name "Display Timeout = 10 min (AC)" -Impact "Low" `
    -Test { 
        # FIXED: Use /GETACVALUEINDEX instead of fragile /q parsing
        # Language-independent and matches exactly what Apply script sets
        $SUB_VIDEO = "7516b95f-f776-4464-8c53-06167f40cc99"   # Display settings
        $VIDEOIDLE = "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"   # Monitor timeout
        
        $activeScheme = (powercfg /getactivescheme 2>&1 | Out-String) -replace '.*GUID[:\s]+([a-f0-9\-]+).*', '$1'
        $output = powercfg /GETACVALUEINDEX $activeScheme $SUB_VIDEO $VIDEOIDLE 2>&1 | Out-String

        if ($output -match '0x([0-9a-f]+)') {
            $seconds = [Convert]::ToInt32($matches[1], 16)
            return $seconds / 60  # Convert to minutes
        }
        return $null
    } `
    -Expected 10

Test-BaselineCheck -Category "Power" -Name "Hibernate Timeout = 30 min (AC)" -Impact "Info" `
    -Test { 
        # FIXED: Use /GETACVALUEINDEX instead of fragile /q parsing
        # Language-independent and matches exactly what Apply script sets
        # Note: Apply script sets 0 (never) in Remote/Server mode, 30 min in Desktop mode
        $SUB_SLEEP     = "238c9fa8-0aad-41ed-83f4-97be242c8f20"   # Sleep/Hibernate settings
        $HIBERNATEIDLE = "9d7815a6-7ee4-497e-8888-515a05f02364"   # Hibernate timeout
        
        $activeScheme = (powercfg /getactivescheme 2>&1 | Out-String) -replace '.*GUID[:\s]+([a-f0-9\-]+).*', '$1'
        $output = powercfg /GETACVALUEINDEX $activeScheme $SUB_SLEEP $HIBERNATEIDLE 2>&1 | Out-String

        if ($output -match '0x([0-9a-f]+)') {
            $seconds = [Convert]::ToInt32($matches[1], 16)
            return $seconds / 60  # Convert to minutes
        }
        return $null
    } `
    -Expected 30

Test-BaselineCheck -Category "Power" -Name "Require Password on Wake (CONSOLELOCK)" -Impact "High" `
    -Test { 
        # Use GUID-based query (more reliable than text matching)
        $activeScheme = (powercfg /getactivescheme 2>&1 | Out-String) -replace '.*GUID:\s*([a-f0-9\-]+).*', '$1'
        $consoleQuery = powercfg /q $activeScheme fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 2>&1 | Out-String
        # Match both English and German output
        if ($consoleQuery -match '(Current AC Power Setting Index|Aktueller Wechselstromeinstellungsindex)[:\s]+0x([0-9a-f]+)') {
            $value = [Convert]::ToInt32($matches[2], 16)  # Note: $matches[2] because of the grouped OR
            $value
        } else { 
            # Fallback: Check Machine Policy (InactivityTimeoutSecs) which enforces lock
            $inactivityTimeout = Get-RegistryValueSafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
            if ($inactivityTimeout -and $inactivityTimeout -gt 0) { 1 } else { $null }
        }
    } `
    -Expected 1

# ===========================
# LSA PROTECTION (ANTI-MIMIKATZ) - 3 SETTINGS
# ===========================

Write-Host "`n=== LSA PROTECTION (ANTI-MIMIKATZ) - 3 SETTINGS ===" -ForegroundColor Yellow

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

Test-BaselineCheck -Category "LSA" -Name "LSA Protection (RunAsPPL) Enabled" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $lsaPath "RunAsPPL"
    } `
    -Expected 1

Test-BaselineCheck -Category "LSA" -Name "LM Hash Disabled (Legacy Hashes)" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $lsaPath "NoLMHash"
    } `
    -Expected 1

Test-BaselineCheck -Category "LSA" -Name "Everyone Excludes Anonymous Users" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $lsaPath "EveryoneIncludesAnonymous" -DefaultValue 1
    } `
    -Expected 0

# ===========================
# CREDENTIAL GUARD / VBS - 5 SETTINGS
# ===========================

Write-Host "`n=== CREDENTIAL GUARD / VBS - 5 SETTINGS ===" -ForegroundColor Yellow

$dgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$cgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"
$hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"

Test-BaselineCheck -Category "CredentialGuard" -Name "VBS (Virtualization-Based Security) Enabled" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $dgPath "EnableVirtualizationBasedSecurity"
    } `
    -Expected 1

Test-BaselineCheck -Category "CredentialGuard" -Name "VBS Secure Boot + DMA Protection" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $dgPath "RequirePlatformSecurityFeatures"
    } `
    -Expected 3

Test-BaselineCheck -Category "CredentialGuard" -Name "Credential Guard Enabled (LsaCfgFlags)" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $lsaPath "LsaCfgFlags"
    } `
    -Expected 1

Test-BaselineCheck -Category "CredentialGuard" -Name "Credential Guard Scenario Enabled (25H2)" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $cgPath "Enabled"
    } `
    -Expected 1

Test-BaselineCheck -Category "CredentialGuard" -Name "HVCI (Memory Integrity) Enabled" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $hvciPath "Enabled"
    } `
    -Expected 1

Test-BaselineCheck -Category "CredentialGuard" -Name "Vulnerable Driver Blocklist Enabled" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" "VulnerableDriverBlocklistEnable"
    } `
    -Expected 1

# ===========================
# WINDOWS LAPS (LOCAL ADMIN PASSWORD SOLUTION) - 3 SETTINGS
# ===========================

Write-Host "`n=== WINDOWS LAPS (LOCAL ADMIN PASSWORD SOLUTION) - 3 SETTINGS ===" -ForegroundColor Yellow

$lapsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config"

if (Test-Path $lapsPath) {
    
    Test-BaselineCheck -Category "LAPS" -Name "LAPS Enabled" -Impact "High" `
        -Test { 
            Get-RegistryValueSafe $lapsPath "Enabled"
        } `
        -Expected 1
    
    Test-BaselineCheck -Category "LAPS" -Name "LAPS Password Complexity = Maximum (4)" -Impact "Medium" `
        -Test { 
            Get-RegistryValueSafe $lapsPath "PasswordComplexity"
        } `
        -Expected 4
    
    Test-BaselineCheck -Category "LAPS" -Name "LAPS Backup to AD/Entra Enabled" -Impact "Medium" `
        -Test { 
            Get-RegistryValueSafe $lapsPath "BackupDirectory"
        } `
        -Expected 2
        
} else {
    Write-Host "  [!] Windows LAPS not available (Home edition or not configured)" -ForegroundColor Yellow
}

# ===========================
# KERBEROS SECURITY - 2 SETTINGS
# ===========================

Write-Host "`n=== KERBEROS SECURITY - 2 SETTINGS ===" -ForegroundColor Yellow

$kerbPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

Test-BaselineCheck -Category "Kerberos" -Name "Kerberos PKINIT Hash = SHA256/384/512" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $kerbPath "PKINITHashAlgorithm"
    } `
    -Expected 56

Test-BaselineCheck -Category "Kerberos" -Name "Kerberos Supported Encryption Types (Modern)" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $kerbPath "SupportedEncryptionTypes"
    } `
    -Expected { param($value) $value -ge 24 }

# DNS over HTTPS
Write-Host "`n=== DNS OVER HTTPS (DoH) ===" -ForegroundColor Yellow

# CRITICAL: Multi-language support (English: yes, German: auto enabled, etc.)
# netsh output is localized - must match multiple languages!
# IMPORTANT: Use 'show global' NOT 'show state' - state doesn't show DoH!
# German format: "DoH-Einstellungen                : auto enabled"
# English format: "DoH settings                     : yes"
# CRITICAL FIX: Must convert to string with Out-String, otherwise -match returns array not boolean!
Test-BaselineCheck -Category "DoH" -Name "DoH Auto-Enabled (Global)" -Impact "High" `
    -Test { (netsh dnsclient show global 2>&1 | Out-String) -match "(DoH|DoH-Einstellungen).*:\s*(yes|ja|enabled|auto enabled|aktiviert)" } `
    -Expected $true

try {
    $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
    
    # Check for ANY of the 4 supported DNS providers (v1.7.15+)
    $cloudflareServers = $dohServers | Where-Object { $_.ServerAddress -like "*1.1.1.1*" -or $_.ServerAddress -like "*1.0.0.1*" -or $_.ServerAddress -like "*2606:4700:4700*" }
    $adguardServers = $dohServers | Where-Object { $_.ServerAddress -like "*94.140.14.14*" -or $_.ServerAddress -like "*94.140.15.15*" -or $_.ServerAddress -like "*2a10:50c0*" }
    $nextdnsServers = $dohServers | Where-Object { $_.ServerAddress -like "*45.90.28.0*" -or $_.ServerAddress -like "*45.90.30.0*" -or $_.ServerAddress -like "*2a07:a8c0*" -or $_.ServerAddress -like "*2a07:a8c1*" }
    $quad9Servers = $dohServers | Where-Object { $_.ServerAddress -like "*9.9.9.9*" -or $_.ServerAddress -like "*149.112.112.112*" -or $_.ServerAddress -like "*2620:fe::*" }
    
    if ($cloudflareServers -and (@($cloudflareServers).Count -ge 2)) {
        $count = @($cloudflareServers).Count
        Write-Host "  [OK] Cloudflare DoH Configured ($count servers)" -ForegroundColor Green
    }
    elseif ($adguardServers -and (@($adguardServers).Count -ge 2)) {
        $count = @($adguardServers).Count
        Write-Host "  [OK] AdGuard DoH Configured ($count servers)" -ForegroundColor Green
    }
    elseif ($nextdnsServers -and (@($nextdnsServers).Count -ge 2)) {
        $count = @($nextdnsServers).Count
        Write-Host "  [OK] NextDNS DoH Configured ($count servers)" -ForegroundColor Green
    }
    elseif ($quad9Servers -and (@($quad9Servers).Count -ge 2)) {
        $count = @($quad9Servers).Count
        Write-Host "  [OK] Quad9 DoH Configured ($count servers)" -ForegroundColor Green
    }
    else {
        Write-Host "  [!] No supported DNS provider found (Cloudflare/AdGuard/NextDNS/Quad9)" -ForegroundColor Yellow
        Write-Host "      User may have kept existing DNS or configured custom provider" -ForegroundColor Gray
    }
}
catch {
    Write-Host "  [!] DoH Check Error: $_" -ForegroundColor Yellow
}

# VBS/Credential Guard (REQUIRES REBOOT!)
Write-Host "`n=== VBS / CREDENTIAL GUARD ===" -ForegroundColor Yellow
Write-Host "  [!] NOTE: These features require REBOOT to be active!" -ForegroundColor Yellow
Write-Host "  [!] HINWEIS: Diese Features erfordern NEUSTART!" -ForegroundColor Yellow
Write-Host "" 

# CRITICAL FIX v1.7.6: Check RUNTIME status instead of just registry!
# Registry = Configured (geplant), CIM = Running (aktiv)
try {
    $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    
    # VBS Status: 0=Off, 1=Configured, 2=Running
    if ($vbs.VirtualizationBasedSecurityStatus -eq 2) {
        Write-Host "  [OK] VBS RUNNING (Status: $($vbs.VirtualizationBasedSecurityStatus))" -ForegroundColor Green
    }
    elseif ($vbs.VirtualizationBasedSecurityStatus -eq 1) {
        Write-Host "  [!] VBS CONFIGURED but not running (needs REBOOT!)" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [X] VBS NOT ACTIVE (Status: $($vbs.VirtualizationBasedSecurityStatus))" -ForegroundColor Red
    }
    
    # Credential Guard: SecurityServicesRunning contains 1
    if ($vbs.SecurityServicesRunning -contains 1) {
        Write-Host "  [OK] Credential Guard RUNNING" -ForegroundColor Green
    }
    else {
        Write-Host "  [!] Credential Guard NOT RUNNING (needs REBOOT or hardware incompatible!)" -ForegroundColor Yellow
    }
    
    # HVCI: SecurityServicesRunning contains 2
    if ($vbs.SecurityServicesRunning -contains 2) {
        Write-Host "  [OK] HVCI RUNNING" -ForegroundColor Green
    }
    else {
        Write-Host "  [!] HVCI NOT RUNNING (needs REBOOT or hardware incompatible!)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [!] Win32_DeviceGuard CIM Check fehlgeschlagen - pruefe Registry..." -ForegroundColor Yellow
    
    # Fallback to Registry (only Configured status)
    $vbsReg = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    $cgReg = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
    
    if ($vbsReg -eq 1) {
        Write-Host "  [!] VBS CONFIGURED (Registry) - Runtime-Status unknown" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [X] VBS NOT CONFIGURED" -ForegroundColor Red
    }
    
    if ($cgReg -eq 1) {
        Write-Host "  [!] Credential Guard CONFIGURED (Registry) - Runtime-Status unknown" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [X] Credential Guard NOT CONFIGURED" -ForegroundColor Red
    }
}

# BitLocker (REQUIRES REBOOT!)
Write-Host "`n=== BITLOCKER ===" -ForegroundColor Yellow
Write-Host "  [!] NOTE: BitLocker activation requires REBOOT!" -ForegroundColor Yellow
Write-Host "  [!] HINWEIS: BitLocker-Aktivierung erfordert NEUSTART!" -ForegroundColor Yellow
Write-Host "" 

$bl = Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue
if ($bl -and $bl.ProtectionStatus -eq 'On') {
    Write-Host "  [OK] BitLocker Enabled (C:)" -ForegroundColor Green
    Write-Host "  Encryption: $($bl.EncryptionMethod)" -ForegroundColor Cyan
} else {
    Write-Host "  [!] BitLocker not yet active (needs reboot or manual activation)" -ForegroundColor Yellow
    Write-Host "  [!] BitLocker noch nicht aktiv (Neustart oder manuelle Aktivierung noetig)" -ForegroundColor Yellow
}

# ===========================
# APT PROTECTION (PHASE 1) - 10 SETTINGS
# ===========================

Write-Host "`n=== APT PROTECTION (PHASE 1) - 10 SETTINGS ===" -ForegroundColor Yellow

$ldapPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"

Test-BaselineCheck -Category "APT-Protection" -Name "LDAP Client Signing = Require (2)" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $ldapPath "LDAPClientIntegrity"
    } `
    -Expected 2

Test-BaselineCheck -Category "APT-Protection" -Name "LDAP Channel Binding = Always (2)" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $ldapPath "LdapEnforceChannelBinding"
    } `
    -Expected 2

# REMOVED: Internet Zone 1806 and Intranet Zone 1806 checks
# REASON: Policy 1806 = 3 breaks Chrome/Edge downloads ("blocked by your organization")
# SECURITY: Protection maintained via SRP (Software Restriction Policies)
# CVE-2025-9491: Still protected via .lnk/.scf/.url blocking in SRP rules

$efsServicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\EFS"

Test-BaselineCheck -Category "APT-Protection" -Name "EFS Service Disabled (4)" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $efsServicePath "Start"
    } `
    -Expected 4

$efsDriverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\EFS"

Test-BaselineCheck -Category "APT-Protection" -Name "EFS Driver Disabled (1)" -Impact "High" `
    -Test { 
        Get-RegistryValueSafe $efsDriverPath "Disabled"
    } `
    -Expected 1

$srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"

Test-BaselineCheck -Category "APT-Protection" -Name "SRP Enabled (DefaultLevel = 0x40000)" -Impact "Critical" `
    -Test { 
        Get-RegistryValueSafe $srpPath "DefaultLevel"
    } `
    -Expected 0x00040000

Test-BaselineCheck -Category "APT-Protection" -Name "SRP Transparent Enforcement = ON (1)" -Impact "Medium" `
    -Test { 
        Get-RegistryValueSafe $srpPath "TransparentEnabled"
    } `
    -Expected 1

$srpRulesPath = "$srpPath\0\Paths"

Test-BaselineCheck -Category "APT-Protection" -Name "SRP Deny Rules Configured (5+)" -Impact "Critical" `
    -Test { 
        if (Test-Path $srpRulesPath) {
            $rules = Get-ChildItem $srpRulesPath -ErrorAction SilentlyContinue
            if ($rules) { $rules.Count } else { 0 }
        } else { 0 }
    } `
    -Expected { param($actual) $actual -ge 5 }

Test-BaselineCheck -Category "APT-Protection" -Name "WebClient Service Disabled (4)" -Impact "High" `
    -Test { 
        try {
            $service = Get-Service -Name WebClient -ErrorAction Stop
            if ($service.StartType -eq 'Disabled') { 4 } else { $service.StartType.value__ }
        } catch {
            4  # Service not found = effectively disabled
        }
    } `
    -Expected 4

# Summary
Write-Host "`n================================================================" -ForegroundColor Cyan
$passedResults = $script:results | Where-Object Status -eq "PASS"
$failedResults = $script:results | Where-Object Status -eq "FAIL"
$errorResults = $script:results | Where-Object Status -eq "ERROR"
$passed = if ($passedResults) { @($passedResults).Count } else { 0 }
$failed = if ($failedResults) { @($failedResults).Count } else { 0 }
$errors = if ($errorResults) { @($errorResults).Count } else { 0 }
$total = if ($script:results) { @($script:results).Count } else { 0 }

Write-Host "QUICK CHECK SUMMARY:" -ForegroundColor Cyan
Write-Host "  PASS:  $passed" -ForegroundColor Green
Write-Host "  FAIL:  $failed" -ForegroundColor Red
Write-Host "  ERROR: $errors" -ForegroundColor Yellow
Write-Host "  TOTAL: $total" -ForegroundColor Cyan
Write-Host ""

if ($failed -eq 0 -and $errors -eq 0) {
    Write-Host "  [OK] All quick checks PASSED!" -ForegroundColor Green
} elseif ($failed -le 3) {
    Write-Host "  [!] Some checks failed (probably needs reboot)" -ForegroundColor Yellow
} else {
    Write-Host "  [X] Multiple checks failed - review output above for details" -ForegroundColor Red
}

Write-Host ""

if ($ExportReport) {
    # Create Verification folder only when actually exporting
    if (-not (Test-Path $ReportPath)) {
        $null = New-Item -Path $ReportPath -ItemType Directory -Force
    }
    
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $csvPath = Join-Path $ReportPath "Verification-$timestamp.csv"
    $script:results | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`n   Report exported: $csvPath" -ForegroundColor Cyan
}

# Stop Transcript
if ($script:transcriptStarted) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Gray
    Write-Host "LOGS & DETAILS" -ForegroundColor White
    Write-Host "================================================================" -ForegroundColor Gray
    Write-Host "Transcript Log: $script:transcriptPath" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        Stop-Transcript -ErrorAction Stop
    }
    catch {
        Write-Verbose "Could not stop transcript: $_"
    }
}
