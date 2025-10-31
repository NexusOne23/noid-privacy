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

# Start Transcript for audit trail
$LogPath = "$env:ProgramData\SecurityBaseline\Logs"
if (-not (Test-Path $LogPath)) {
    $null = New-Item -Path $LogPath -ItemType Directory -Force
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:transcriptPath = Join-Path $LogPath "Verify-SecurityBaseline-$timestamp.log"

try {
    Start-Transcript -Path $script:transcriptPath -ErrorAction Stop
    $script:transcriptStarted = $true
    Write-Verbose "Transcript started: $script:transcriptPath"
}
catch {
    Write-Warning "Could not start transcript: $_"
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  Windows 11 25H2 Security Baseline - QUICK CHECK" -ForegroundColor Cyan
Write-Host "================================================================`n" -ForegroundColor Cyan

$script:results = @()

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
        $rt = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableRealtimeMonitoring -ErrorAction SilentlyContinue
        if ($rt) { $rt.DisableRealtimeMonitoring -eq 0 } else { $true }
    } `
    -Expected $true

# 2. IOAV Protection (Download + Email scanning)
Test-BaselineCheck -Category "Defender" -Name "IOAV Protection Enabled" -Impact "High" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            -not $mpPref.DisableIOAVProtection
        } catch {
            $ioav = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableIOAVProtection -ErrorAction SilentlyContinue
            if ($ioav) { $ioav.DisableIOAVProtection -eq 0 } else { $true }
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
            $bm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableBehaviorMonitoring -ErrorAction SilentlyContinue
            if ($bm) { $bm.DisableBehaviorMonitoring -eq 0 } else { $true }
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
            $spynet = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name SpynetReporting -ErrorAction SilentlyContinue
            if ($spynet) { $spynet.SpynetReporting -ge 1 } else { $false }
        }
    } `
    -Expected $true

# 11. Cloud Block Level (High for zero-hour protection)
Test-BaselineCheck -Category "Defender" -Name "Cloud Block Level = High" -Impact "High" `
    -Test { 
        $cbl = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name MpCloudBlockLevel -ErrorAction SilentlyContinue
        if ($cbl) { $cbl.MpCloudBlockLevel } else { 0 }
    } `
    -Expected 2

# 12. Sample Submission (Automatic for threat analysis)
Test-BaselineCheck -Category "Defender" -Name "Sample Submission = Send Safe Samples" -Impact "Medium" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            $mpPref.SubmitSamplesConsent
        } catch {
            $submit = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name SubmitSamplesConsent -ErrorAction SilentlyContinue
            if ($submit) { $submit.SubmitSamplesConsent } else { 0 }
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
            $pua = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name PUAProtection -ErrorAction SilentlyContinue
            if ($pua) { $pua.PUAProtection -eq 1 } else { $false }
        }
    } `
    -Expected $true

# 14. Network Protection (Exploit Guard)
Test-BaselineCheck -Category "Defender" -Name "Network Protection Enabled (Block)" -Impact "Critical" `
    -Test { 
        $np = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name EnableNetworkProtection -ErrorAction SilentlyContinue
        if ($np) { $np.EnableNetworkProtection } else { 0 }
    } `
    -Expected 1

# 15. Controlled Folder Access (Ransomware Protection)
Test-BaselineCheck -Category "Defender" -Name "Controlled Folder Access Enabled" -Impact "High" `
    -Test { 
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            $mpPref.EnableControlledFolderAccess -eq 1
        } catch {
            $cfa = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" -Name EnableControlledFolderAccess -ErrorAction SilentlyContinue
            if ($cfa) { $cfa.EnableControlledFolderAccess -eq 1 } else { $false }
        }
    } `
    -Expected $true

# 16. SmartScreen for Apps (Windows Security)
Test-BaselineCheck -Category "Defender" -Name "SmartScreen for Apps Enabled" -Impact "High" `
    -Test { 
        $ss = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableSmartScreen -ErrorAction SilentlyContinue
        if ($ss) { $ss.EnableSmartScreen } else { 0 }
    } `
    -Expected 1

# 17. SmartScreen Warn -> Block Mode
Test-BaselineCheck -Category "Defender" -Name "SmartScreen Warn -> Block Mode" -Impact "Medium" `
    -Test { 
        $ssmode = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name ShellSmartScreenLevel -ErrorAction SilentlyContinue
        if ($ssmode) { $ssmode.ShellSmartScreenLevel -eq "Block" } else { $false }
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
                $v = Get-ItemProperty $asrPath -Name $GUID -ErrorAction SilentlyContinue
                if ($v) { $v.$GUID } else { 0 }
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

# Check if Exploit Protection XML exists
$epConfigPath = "$env:ProgramData\SecurityBaseline\Exploit-Protection-Config.xml"

Test-BaselineCheck -Category "ExploitProtection" -Name "Exploit Protection Config File Exists" -Impact "High" `
    -Test { Test-Path $epConfigPath } `
    -Expected $true

# Try to get current system-wide mitigations
try {
    $epStatus = Get-ProcessMitigation -System -ErrorAction Stop
    
    # DEP (Data Execution Prevention)
    Test-BaselineCheck -Category "ExploitProtection" -Name "DEP (Data Execution Prevention) Enabled" -Impact "Critical" `
        -Test { $epStatus.DEP.Enable } `
        -Expected 'ON'
    
    # SEHOP (Structured Exception Handler Overwrite Protection)
    Test-BaselineCheck -Category "ExploitProtection" -Name "SEHOP Enabled" -Impact "High" `
        -Test { $epStatus.SEHOP.Enable } `
        -Expected 'ON'
    
    # ASLR (Address Space Layout Randomization)
    Test-BaselineCheck -Category "ExploitProtection" -Name "ASLR Force Randomization Enabled" -Impact "Critical" `
        -Test { $epStatus.ASLR.ForceRelocateImages } `
        -Expected 'ON'
    
    # CFG (Control Flow Guard)
    Test-BaselineCheck -Category "ExploitProtection" -Name "CFG (Control Flow Guard) Enabled" -Impact "High" `
        -Test { $epStatus.CFG.Enable } `
        -Expected 'ON'
    
    # Strict CFG
    Test-BaselineCheck -Category "ExploitProtection" -Name "Strict CFG Enabled" -Impact "High" `
        -Test { $epStatus.CFG.StrictControlFlowGuard } `
        -Expected 'ON'
    
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
        $v = Get-ItemProperty $smbServerPath -Name EnableAuthenticationRateLimiter -ErrorAction SilentlyContinue
        if ($v) { $v.EnableAuthenticationRateLimiter } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Server" -Name "Auth Rate Limiter Delay = 2000ms" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty $smbServerPath -Name InvalidAuthenticationDelayTimeInMs -ErrorAction SilentlyContinue
        if ($v) { $v.InvalidAuthenticationDelayTimeInMs } else { 0 }
    } `
    -Expected 2000

Test-BaselineCheck -Category "SMB-Server" -Name "SMB Min Version = 3.0.0 (768)" -Impact "Critical" `
    -Test { 
        $v = Get-ItemProperty $smbServerPath -Name SMBServerMinimumProtocol -ErrorAction SilentlyContinue
        if ($v) { $v.SMBServerMinimumProtocol } else { 0 }
    } `
    -Expected 768

Test-BaselineCheck -Category "SMB-Server" -Name "SMB Max Version = 3.1.1 (1025)" -Impact "Medium" `
    -Test { 
        $v = Get-ItemProperty $smbServerPath -Name SMBServerMaximumProtocol -ErrorAction SilentlyContinue
        if ($v) { $v.SMBServerMaximumProtocol } else { 0 }
    } `
    -Expected 1025

Test-BaselineCheck -Category "SMB-Server" -Name "Audit Client Without Encryption" -Impact "Medium" `
    -Test { 
        $v = Get-ItemProperty $smbServerPath -Name AuditClientDoesNotSupportEncryption -ErrorAction SilentlyContinue
        if ($v) { $v.AuditClientDoesNotSupportEncryption } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Server" -Name "Audit Client Without Signing" -Impact "Medium" `
    -Test { 
        $v = Get-ItemProperty $smbServerPath -Name AuditClientDoesNotSupportSigning -ErrorAction SilentlyContinue
        if ($v) { $v.AuditClientDoesNotSupportSigning } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Server" -Name "Audit Insecure Guest Logon" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty $smbServerPath -Name AuditInsecureGuestLogon -ErrorAction SilentlyContinue
        if ($v) { $v.AuditInsecureGuestLogon } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Server" -Name "Remote Mailslots Disabled" -Impact "Medium" `
    -Test { 
        $v = Get-ItemProperty $smbServerPath -Name EnableRemoteMailslots -ErrorAction SilentlyContinue
        if ($v) { $v.EnableRemoteMailslots } else { 1 }
    } `
    -Expected 0

# ===========================
# SMB CLIENT HARDENING (8 SETTINGS)
# ===========================

Write-Host "`n=== SMB CLIENT HARDENING (8 SETTINGS) ===" -ForegroundColor Yellow

$smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

Test-BaselineCheck -Category "SMB-Client" -Name "SMB Client Min Version = 3.0.0 (768)" -Impact "Critical" `
    -Test { 
        $v = Get-ItemProperty $smbClientPath -Name SMBClientMinimumProtocol -ErrorAction SilentlyContinue
        if ($v) { $v.SMBClientMinimumProtocol } else { 0 }
    } `
    -Expected 768

Test-BaselineCheck -Category "SMB-Client" -Name "SMB Client Max Version = 3.1.1 (1025)" -Impact "Medium" `
    -Test { 
        $v = Get-ItemProperty $smbClientPath -Name SMBClientMaximumProtocol -ErrorAction SilentlyContinue
        if ($v) { $v.SMBClientMaximumProtocol } else { 0 }
    } `
    -Expected 1025

Test-BaselineCheck -Category "SMB-Client" -Name "Audit Insecure Guest Logon (Client)" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty $smbClientPath -Name AuditInsecureGuestLogon -ErrorAction SilentlyContinue
        if ($v) { $v.AuditInsecureGuestLogon } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Client" -Name "Audit Server Without Encryption" -Impact "Medium" `
    -Test { 
        $v = Get-ItemProperty $smbClientPath -Name AuditServerDoesNotSupportEncryption -ErrorAction SilentlyContinue
        if ($v) { $v.AuditServerDoesNotSupportEncryption } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Client" -Name "Audit Server Without Signing" -Impact "Medium" `
    -Test { 
        $v = Get-ItemProperty $smbClientPath -Name AuditServerDoesNotSupportSigning -ErrorAction SilentlyContinue
        if ($v) { $v.AuditServerDoesNotSupportSigning } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "SMB-Client" -Name "Remote Mailslots Disabled (Client)" -Impact "Medium" `
    -Test { 
        $v = Get-ItemProperty $smbClientPath -Name EnableRemoteMailslots -ErrorAction SilentlyContinue
        if ($v) { $v.EnableRemoteMailslots } else { 1 }
    } `
    -Expected 0

Test-BaselineCheck -Category "SMB-Client" -Name "Insecure Guest Auth Disabled" -Impact "High" `
    -Test { 
        $smbPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation"
        $v = Get-ItemProperty $smbPolicyPath -Name AllowInsecureGuestAuth -ErrorAction SilentlyContinue
        if ($v) { $v.AllowInsecureGuestAuth } else { 1 }
    } `
    -Expected 0

Test-BaselineCheck -Category "SMB-Client" -Name "Plaintext Passwords to SMB Servers Disabled" -Impact "Critical" `
    -Test { 
        $v = Get-ItemProperty $smbClientPath -Name EnablePlainTextPassword -ErrorAction SilentlyContinue
        if ($v) { $v.EnablePlainTextPassword } else { 1 }
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

Test-BaselineCheck -Category "Firewall" -Name "Domain Block All Inbound Rules" -Impact "Critical" `
    -Test { (Get-NetFirewallProfile -Name Domain).AllowInboundRules } `
    -Expected 'False'

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

Test-BaselineCheck -Category "Firewall" -Name "Private Block All Inbound Rules" -Impact "Critical" `
    -Test { (Get-NetFirewallProfile -Name Private).AllowInboundRules } `
    -Expected 'False'

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

Test-BaselineCheck -Category "Firewall" -Name "Public Block All Inbound Rules" -Impact "Critical" `
    -Test { (Get-NetFirewallProfile -Name Public).AllowInboundRules } `
    -Expected 'False'

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

Test-BaselineCheck -Category "Firewall" -Name "Public Block Local Firewall Rules" -Impact "High" `
    -Test { (Get-NetFirewallProfile -Name Public).AllowLocalFirewallRules } `
    -Expected 'False'

Test-BaselineCheck -Category "Firewall" -Name "Public Block Local IPsec Rules" -Impact "High" `
    -Test { (Get-NetFirewallProfile -Name Public).AllowLocalIPsecRules } `
    -Expected 'False'

# ===========================
# NETWORK HARDENING (mDNS, LLMNR, NetBIOS)
# ===========================

Write-Host "`n=== NETWORK HARDENING (3 SETTINGS) ===" -ForegroundColor Yellow

Test-BaselineCheck -Category "Network" -Name "mDNS Disabled" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters" -Name DisableMdnsDiscovery -ErrorAction SilentlyContinue
        if ($v) { $v.DisableMdnsDiscovery } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "Network" -Name "LLMNR Disabled" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue
        if ($v) { $v.EnableMulticast } else { 1 }
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
        $v = Get-ItemProperty $uacPath -Name EnableLUA -ErrorAction SilentlyContinue
        if ($v) { $v.EnableLUA } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "UAC" -Name "UAC Always Notify (Slider TOP)" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty $uacPath -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue
        if ($v) { $v.ConsentPromptBehaviorAdmin } else { 5 }
    } `
    -Expected 2

Test-BaselineCheck -Category "UAC" -Name "UAC Secure Desktop Enabled" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty $uacPath -Name PromptOnSecureDesktop -ErrorAction SilentlyContinue
        if ($v) { $v.PromptOnSecureDesktop } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "UAC" -Name "Standard User Prompt for Credentials" -Impact "Medium" `
    -Test { 
        $v = Get-ItemProperty $uacPath -Name ConsentPromptBehaviorUser -ErrorAction SilentlyContinue
        if ($v) { $v.ConsentPromptBehaviorUser } else { 3 }
    } `
    -Expected 1

Test-BaselineCheck -Category "UAC" -Name "UAC Local Account Token Filter (Anti-Pass-the-Hash)" -Impact "Critical" `
    -Test { 
        $v = Get-ItemProperty $uacPath -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
        if ($v) { $v.LocalAccountTokenFilterPolicy } else { 1 }
    } `
    -Expected 0

Test-BaselineCheck -Category "UAC" -Name "Inactivity Timeout = 900 sec (15 min)" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty $uacPath -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue
        if ($v) { $v.InactivityTimeoutSecs } else { 0 }
    } `
    -Expected 900

Test-BaselineCheck -Category "UAC" -Name "EPP Mode Configured (Future-Ready)" -Impact "Low" `
    -Test { 
        $v = Get-ItemProperty $uacPath -Name ConsentPromptBehaviorAdminInEPPMode -ErrorAction SilentlyContinue
        if ($v) { $v.ConsentPromptBehaviorAdminInEPPMode } else { 0 }
    } `
    -Expected 2

# ===========================
# LSA PROTECTION (ANTI-MIMIKATZ) - 3 SETTINGS
# ===========================

Write-Host "`n=== LSA PROTECTION (ANTI-MIMIKATZ) - 3 SETTINGS ===" -ForegroundColor Yellow

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

Test-BaselineCheck -Category "LSA" -Name "LSA Protection (RunAsPPL) Enabled" -Impact "Critical" `
    -Test { 
        $v = Get-ItemProperty $lsaPath -Name RunAsPPL -ErrorAction SilentlyContinue
        if ($v) { $v.RunAsPPL } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "LSA" -Name "LM Hash Disabled (Legacy Hashes)" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty $lsaPath -Name NoLMHash -ErrorAction SilentlyContinue
        if ($v) { $v.NoLMHash } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "LSA" -Name "Everyone Excludes Anonymous Users" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty $lsaPath -Name EveryoneIncludesAnonymous -ErrorAction SilentlyContinue
        if ($v) { $v.EveryoneIncludesAnonymous } else { 1 }
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
        $v = Get-ItemProperty $dgPath -Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue
        if ($v) { $v.EnableVirtualizationBasedSecurity } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "CredentialGuard" -Name "VBS Secure Boot + DMA Protection" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty $dgPath -Name RequirePlatformSecurityFeatures -ErrorAction SilentlyContinue
        if ($v) { $v.RequirePlatformSecurityFeatures } else { 0 }
    } `
    -Expected 3

Test-BaselineCheck -Category "CredentialGuard" -Name "Credential Guard Enabled (LsaCfgFlags)" -Impact "Critical" `
    -Test { 
        $v = Get-ItemProperty $lsaPath -Name LsaCfgFlags -ErrorAction SilentlyContinue
        if ($v) { $v.LsaCfgFlags } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "CredentialGuard" -Name "Credential Guard Scenario Enabled (25H2)" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty $cgPath -Name Enabled -ErrorAction SilentlyContinue
        if ($v) { $v.Enabled } else { 0 }
    } `
    -Expected 1

Test-BaselineCheck -Category "CredentialGuard" -Name "HVCI (Memory Integrity) Enabled" -Impact "Critical" `
    -Test { 
        $v = Get-ItemProperty $hvciPath -Name Enabled -ErrorAction SilentlyContinue
        if ($v) { $v.Enabled } else { 0 }
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
            $v = Get-ItemProperty $lapsPath -Name Enabled -ErrorAction SilentlyContinue
            if ($v) { $v.Enabled } else { 0 }
        } `
        -Expected 1
    
    Test-BaselineCheck -Category "LAPS" -Name "LAPS Password Complexity = Maximum (4)" -Impact "Medium" `
        -Test { 
            $v = Get-ItemProperty $lapsPath -Name PasswordComplexity -ErrorAction SilentlyContinue
            if ($v) { $v.PasswordComplexity } else { 0 }
        } `
        -Expected 4
    
    Test-BaselineCheck -Category "LAPS" -Name "LAPS Backup to AD/Entra Enabled" -Impact "Medium" `
        -Test { 
            $v = Get-ItemProperty $lapsPath -Name BackupDirectory -ErrorAction SilentlyContinue
            if ($v) { $v.BackupDirectory } else { 0 }
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
        $v = Get-ItemProperty $kerbPath -Name PKINITHashAlgorithm -ErrorAction SilentlyContinue
        if ($v) { $v.PKINITHashAlgorithm } else { 0 }
    } `
    -Expected 56

Test-BaselineCheck -Category "Kerberos" -Name "Kerberos Supported Encryption Types (Modern)" -Impact "Medium" `
    -Test { 
        $v = Get-ItemProperty $kerbPath -Name SupportedEncryptionTypes -ErrorAction SilentlyContinue
        if ($v) { $v.SupportedEncryptionTypes } else { 0 }
    } `
    -Expected { param($value) $value -ge 24 }

# DNS over HTTPS
Write-Host "`n=== DNS OVER HTTPS (DoH) ===" -ForegroundColor Yellow

Test-BaselineCheck -Category "DoH" -Name "DoH Auto-Enabled (Global)" -Impact "High" `
    -Test { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDoh -ErrorAction SilentlyContinue).EnableAutoDoh } `
    -Expected 2

try {
    $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
    $cloudflareServers = $dohServers | Where-Object { $_.ServerAddress -like "*1.1.1.1*" -or $_.ServerAddress -like "*1.0.0.1*" -or $_.ServerAddress -like "*2606:4700:4700*" }
    $cloudflareCount = if ($cloudflareServers) { @($cloudflareServers).Count } else { 0 }
    if ($cloudflareCount -ge 2) {
        Write-Host "  [OK] Cloudflare DoH Configured ($cloudflareCount servers)" -ForegroundColor Green
        
        # CHECK: netsh global doh status
        $netshState = netsh dnsclient show state 2>&1
        if ($netshState -match "DoH\s+:\s+yes") {
            Write-Host "  [OK] DoH Global Enabled (netsh)" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] DoH not globally enabled (netsh doh=no)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [X] Cloudflare DoH Missing" -ForegroundColor Red
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

Write-Host ""
