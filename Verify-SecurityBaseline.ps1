<#
.SYNOPSIS
    Verifiziert die Windows 11 25H2 Security Baseline Implementierung
    
.DESCRIPTION
    Prueft alle Baseline-Einstellungen und generiert einen detaillierten Compliance-Report
    
.NOTES
    Version:        1.0.0
    Creation Date:  25H2
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

if (-not (Test-Path $ReportPath)) {
    $null = New-Item -Path $ReportPath -ItemType Directory -Force
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

# Defender
Write-Host "`n=== MICROSOFT DEFENDER ===" -ForegroundColor Yellow

Test-BaselineCheck -Category "Defender" -Name "Real-Time Protection" -Impact "Critical" `
    -Test { -not (Get-MpPreference).DisableRealtimeMonitoring } `
    -Expected $true

Test-BaselineCheck -Category "Defender" -Name "Cloud Protection" -Impact "High" `
    -Test { (Get-MpComputerStatus).AMServiceEnabled } `
    -Expected $true

Test-BaselineCheck -Category "Defender" -Name "Network Protection" -Impact "High" `
    -Test { 
        $v = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name EnableNetworkProtection -ErrorAction SilentlyContinue
        $v.EnableNetworkProtection 
    } `
    -Expected 1

# ASR Rules
Write-Host "`n=== ASR RULES ===" -ForegroundColor Yellow

$mpPref = Get-MpPreference
$asrCount = $mpPref.AttackSurfaceReductionRules_Ids.Count

Write-Host "  Configured ASR Rules: $asrCount" -ForegroundColor Cyan

if ($asrCount -ge 15) {
    Write-Host "  [OK] ASR Rules Configured (15+)" -ForegroundColor Green
} else {
    Write-Host "  [X] ASR Rules Insufficient ($asrCount)" -ForegroundColor Red
}

# Firewall
Write-Host "`n=== FIREWALL ===" -ForegroundColor Yellow

Test-BaselineCheck -Category "Firewall" -Name "Private Profile Enabled" -Impact "High" `
    -Test { (Get-NetFirewallProfile -Name Private).Enabled } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Public Profile Enabled" -Impact "High" `
    -Test { (Get-NetFirewallProfile -Name Public).Enabled } `
    -Expected 'True'

Test-BaselineCheck -Category "Firewall" -Name "Block All Inbound (Private)" -Impact "Critical" `
    -Test { (Get-NetFirewallProfile -Name Private).AllowInboundRules } `
    -Expected 'False'

# UAC
Write-Host "`n=== UAC (USER ACCOUNT CONTROL) ===" -ForegroundColor Yellow

Test-BaselineCheck -Category "UAC" -Name "UAC Enabled" -Impact "Critical" `
    -Test { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA } `
    -Expected 1

Test-BaselineCheck -Category "UAC" -Name "UAC Maximum (Slider TOP)" -Impact "High" `
    -Test { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin } `
    -Expected 2

# DNS over HTTPS
Write-Host "`n=== DNS OVER HTTPS (DoH) ===" -ForegroundColor Yellow

Test-BaselineCheck -Category "DoH" -Name "DoH Auto-Enabled (Global)" -Impact "High" `
    -Test { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDoh -ErrorAction SilentlyContinue).EnableAutoDoh } `
    -Expected 2

try {
    $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
    $cloudflareCount = ($dohServers | Where-Object { $_.ServerAddress -like "*1.1.1.1*" -or $_.ServerAddress -like "*1.0.0.1*" -or $_.ServerAddress -like "*2606:4700:4700*" }).Count
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
$passed = ($script:results | Where-Object Status -eq "PASS").Count
$failed = ($script:results | Where-Object Status -eq "FAIL").Count
$errors = ($script:results | Where-Object Status -eq "ERROR").Count
$total = $script:results.Count

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
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $csvPath = Join-Path $ReportPath "Verification-$timestamp.csv"
    $script:results | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "`n   Report exported: $csvPath" -ForegroundColor Cyan
}

Write-Host ""
