# Attack Surface Reduction (ASR) Rules - Complete Reference

This document provides a complete reference for all **Attack Surface Reduction (ASR) rules** implemented in the Security Baseline script.

---

## 📋 Overview

**Total Rules:** 19 (as of Windows 11 25H2)  
**Default Mode:** Enforce (Block)  
**Script Module:** `Modules\SecurityBaseline-ASR.ps1`

**Deployment Strategy:**
1. **Audit Mode:** Test for 2-4 weeks, monitor Event Log for false positives
2. **Warn Mode:** Show warnings to users before blocking (if supported)
3. **Block Mode:** Fully enforce (production)

---

## 🛡️ ASR Rules Matrix

### 1. Block Office Applications from Creating Executable Content

| Property | Value |
|----------|-------|
| **GUID** | `3B576869-A4EC-4529-8536-B80A7769E899` |
| **Category** | Office Exploits |
| **Default Mode** | Block |
| **Risk** | High - Blocks malicious macros creating .exe files |
| **False Positives** | Low |
| **Exclusions** | Rare - may need for legitimate installer macros |

**Description:** Prevents Office applications (Word, Excel, PowerPoint, OneNote) from creating executable content (`.exe`, `.dll`, `.scr`, etc.). Blocks common macro-based malware delivery.

**Event IDs:** 1121 (Blocked), 1122 (Audited)

---

### 2. Block Office Applications from Creating Child Processes

| Property | Value |
|----------|-------|
| **GUID** | `D4F940AB-401B-4EFC-AADC-AD5F3C50688A` |
| **Category** | Office Exploits |
| **Default Mode** | Block |
| **Risk** | High - Blocks macro-based process execution |
| **False Positives** | Medium - Some add-ins spawn processes |
| **Exclusions** | May need for: Adobe Acrobat add-in, some BI tools |

**Description:** Prevents Office apps from launching child processes (e.g., `cmd.exe`, `powershell.exe`, `wscript.exe`). Critical for blocking macro-based attacks.

**Common Exclusions:**
```
C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe
C:\Program Files\Microsoft Office\root\Client\AppVLP.exe (App-V)
```

---

### 3. Block Office Communication App from Creating Child Processes

| Property | Value |
|----------|-------|
| **GUID** | `26190899-1602-49E8-8B27-EB1D0A1CE869` |
| **Category** | Office Exploits |
| **Default Mode** | Block |
| **Risk** | High - Outlook exploit mitigation |
| **False Positives** | Low |
| **Exclusions** | Rare |

**Description:** Prevents Outlook from creating child processes. Mitigates email-based exploits attempting to launch malicious payloads.

---

### 4. Block Adobe Reader from Creating Child Processes

| Property | Value |
|----------|-------|
| **GUID** | `7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C` |
| **Category** | PDF Exploits |
| **Default Mode** | Block |
| **Risk** | High - PDF exploit mitigation |
| **False Positives** | Medium - Some PDF forms use scripts |
| **Exclusions** | May need for: Complex PDF forms, JavaScript-heavy PDFs |

**Description:** Prevents Adobe Reader/Acrobat from launching child processes. Blocks common PDF exploit techniques.

---

### 5. Block All Office Applications from Injecting Code into Other Processes

| Property | Value |
|----------|-------|
| **GUID** | `75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84` |
| **Category** | Office Exploits |
| **Default Mode** | Block |
| **Risk** | High - Code injection prevention |
| **False Positives** | Low |
| **Exclusions** | Rare |

**Description:** Prevents Office apps from injecting code into other running processes. Blocks advanced exploitation techniques.

---

### 6. Block JavaScript or VBScript from Launching Downloaded Executable Content

| Property | Value |
|----------|-------|
| **GUID** | `D3E037E1-3EB8-44C8-A917-57927947596D` |
| **Category** | Script Protection |
| **Default Mode** | Block |
| **Risk** | High - Blocks script-based malware |
| **False Positives** | Low |
| **Exclusions** | Rare - some enterprise deployment scripts |

**Description:** Prevents scripts from launching executables downloaded from the internet. Critical for blocking drive-by downloads.

---

### 7. Block Execution of Potentially Obfuscated Scripts

| Property | Value |
|----------|-------|
| **GUID** | `5BEB7EFE-FD9A-4556-801D-275E5FFC04CC` |
| **Category** | Script Protection |
| **Default Mode** | Block |
| **Risk** | High - Blocks obfuscated PowerShell/JS/VBS |
| **False Positives** | Medium - Some legitimate scripts trigger |
| **Exclusions** | May need for: Minified JavaScript, some enterprise scripts |

**Description:** Uses heuristics to detect and block obfuscated scripts (PowerShell, JavaScript, VBScript). Targets fileless malware.

**Common False Positives:**
- Minified JavaScript in web dev
- Base64-encoded PowerShell (even legitimate)
- Some SCCM/Intune deployment scripts

---

### 8. Block Win32 API Calls from Office Macros

| Property | Value |
|----------|-------|
| **GUID** | `92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B` |
| **Category** | Office Exploits |
| **Default Mode** | Block |
| **Risk** | High - Blocks advanced macro exploits |
| **False Positives** | Medium - Some power-user macros break |
| **Exclusions** | May need for: Complex Excel/Access macros with API calls |

**Description:** Prevents Office macros from calling Win32 APIs directly. Blocks advanced macro-based attacks (e.g., memory manipulation, process injection).

**Note:** This is one of the most aggressive rules - test thoroughly in Audit mode first!

---

### 9. Block Executable Content from Email Client and Webmail

| Property | Value |
|----------|-------|
| **GUID** | `BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550` |
| **Category** | Email Protection |
| **Default Mode** | Block |
| **Risk** | High - Blocks email-based malware |
| **False Positives** | Low |
| **Exclusions** | Rare |

**Description:** Prevents execution of files downloaded from email clients (Outlook) or webmail. Blocks common phishing attack vectors.

---

### 10. Block Executable Files from Running Unless They Meet Prevalence, Age, or Trusted List Criteria

| Property | Value |
|----------|-------|
| **GUID** | `01443614-CD74-433A-B99E-2ECDC07BFC25` |
| **Category** | Zero-Day Protection |
| **Default Mode** | Block |
| **Risk** | High - Cloud-based reputation check |
| **False Positives** | High - Blocks new/custom software |
| **Exclusions** | **REQUIRED** for: Custom apps, in-house tools, new software |

**Description:** Blocks executables that don't meet Microsoft's cloud-based reputation criteria (prevalence, age, trusted publisher). **Very aggressive** - requires extensive exclusion management.

**⚠️ Warning:** This rule can break legitimate software! Use **Audit mode** for extended period (4-8 weeks) before enforcing.

**Recommended Exclusions:**
```
C:\CustomApps\*
C:\Program Files\YourCompany\*
\\FileServer\SharedApps\*
```

---

### 11. Use Advanced Protection Against Ransomware

| Property | Value |
|----------|-------|
| **GUID** | `C1DB55AB-C21A-4637-BB3F-A12568109D35` |
| **Category** | Ransomware Protection |
| **Default Mode** | Block |
| **Risk** | High - Heuristic ransomware detection |
| **False Positives** | Medium - Some backup/compression tools |
| **Exclusions** | May need for: Backup software, compression tools, dev environments |

**Description:** Uses behavioral analysis to detect and block ransomware-like activity (rapid file encryption, mass file modifications).

**Common Exclusions:**
```
C:\Program Files\Veeam\*
C:\Program Files\7-Zip\*
C:\Program Files\WinRAR\*
```

---

### 12. Block Process Creations Originating from PSExec and WMI Commands

| Property | Value |
|----------|-------|
| **GUID** | `D1E49AAC-8F56-4280-B9BA-993A6D77406C` |
| **Category** | Lateral Movement Prevention |
| **Default Mode** | Block |
| **Risk** | High - Blocks remote execution tools |
| **False Positives** | High - Breaks admin tools |
| **Exclusions** | **REQUIRED** for: IT admin tasks, remote management |

**Description:** Blocks process creation via PSExec and WMI commands. Mitigates lateral movement in attacks.

**⚠️ Warning:** This breaks common IT admin workflows! Use **Audit mode** or exclude admin workstations.

**Common Exclusions:**
```
C:\Program Files\SysInternals\*
C:\Windows\System32\wbem\*
```

---

### 13. Block Untrusted and Unsigned Processes from Running from USB

| Property | Value |
|----------|-------|
| **GUID** | `B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4` |
| **Category** | USB/Removable Media Protection |
| **Default Mode** | Block |
| **Risk** | Medium - USB-based malware |
| **False Positives** | High - Blocks unsigned portable apps |
| **Exclusions** | May need for: Portable software, USB installers |

**Description:** Prevents unsigned/untrusted executables from running from USB drives. Mitigates USB-based malware (e.g., BadUSB attacks).

---

### 14. Block Credential Stealing from Windows Local Security Authority Subsystem (lsass.exe)

| Property | Value |
|----------|-------|
| **GUID** | `9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2` |
| **Category** | Credential Theft Prevention |
| **Default Mode** | Block |
| **Risk** | High - Blocks Mimikatz and similar tools |
| **False Positives** | Low |
| **Exclusions** | Rare - may need for security testing tools |

**Description:** Prevents processes from reading memory of `lsass.exe` (Local Security Authority Subsystem). Critical for blocking credential dumping tools like Mimikatz.

**⚠️ Note:** This is one of the most important ASR rules for preventing credential theft!

---

### 15. Block Persistence Through WMI Event Subscription

| Property | Value |
|----------|-------|
| **GUID** | `E6DB77E5-3DF2-4CF1-B95A-636979351E5B` |
| **Category** | Persistence Prevention |
| **Default Mode** | Block |
| **Risk** | Medium - Blocks malware persistence |
| **False Positives** | Low |
| **Exclusions** | Rare - some monitoring tools use WMI events |

**Description:** Prevents malware from using WMI event subscriptions for persistence. Blocks a common technique used by advanced threats.

---

### 16. Block Abuse of Exploited Vulnerable Signed Drivers (NEW in 2024)

| Property | Value |
|----------|-------|
| **GUID** | `56A863A9-875E-4185-98A7-B882C64B5CE5` |
| **Category** | Kernel Exploit Prevention |
| **Default Mode** | Block |
| **Risk** | High - BYOVD (Bring Your Own Vulnerable Driver) attacks |
| **False Positives** | Low - only blocks known-vulnerable drivers |
| **Exclusions** | Rare |

**Description:** Blocks known-vulnerable signed drivers from loading. Mitigates BYOVD attacks where attackers abuse legitimate but vulnerable drivers to gain kernel access.

**References:**
- [Microsoft Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)

---

### 17. Block Rebooting Machine in Safe Mode (NEW in 2024)

| Property | Value |
|----------|-------|
| **GUID** | `33DDEDF1-C6E0-47CB-833E-DE6133960387` |
| **Category** | Ransomware Protection |
| **Default Mode** | Block |
| **Risk** | High - Prevents ransomware from disabling security in Safe Mode |
| **False Positives** | Very Low - Normal users rarely use bcdedit/bootcfg |
| **Exclusions** | Rare |

**Description:** Prevents attackers from restarting the machine in Safe Mode where security products are disabled. Blocks commands like `bcdedit` and `bootcfg` that modify boot configuration to force Safe Mode. This is a common ransomware technique to disable antivirus before encryption.

**⚠️ Note:** Manual Safe Mode access via Windows Recovery Environment is still possible - only automated command-line modifications are blocked.

**Blocked Commands:**
```
bcdedit /set {default} safeboot minimal
bootcfg /raw /a /safeboot:minimal /id 1
```

---

### 18. Block Use of Copied or Impersonated System Tools (NEW in 2024)

| Property | Value |
|----------|-------|
| **GUID** | `C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB` |
| **Category** | Living-off-the-Land Prevention |
| **Default Mode** | Block |
| **Risk** | High - Prevents LOLBin (Living-off-the-Land Binaries) abuse |
| **False Positives** | Low - Legitimate software rarely copies system tools |
| **Exclusions** | May need for: Some backup tools, forensic tools |

**Description:** Blocks execution of copies or impostors of Windows system tools (e.g., `cmd.exe`, `powershell.exe`, `certutil.exe` copied to non-standard locations). Attackers often copy legitimate system binaries to evade detection or gain privileges.

**Common Attack Technique:** Copying `cmd.exe` to `C:\Temp\notmalware.exe` to bypass application whitelisting.

**Detected Behaviors:**
- Executable files that are byte-for-byte copies of system tools
- Files with modified names but identical binary signatures
- System tool executables in non-Windows directories

---

### 19. Block Webshell Creation for Servers (Server-Specific)

| Property | Value |
|----------|-------|
| **GUID** | `A8F5898E-1DC8-49A9-9878-85004B8A61E6` |
| **Category** | Web Server Protection |
| **Default Mode** | Block |
| **Risk** | High - Prevents web server compromise and persistence |
| **False Positives** | Low on workstations (rule is server-focused) |
| **Exclusions** | Generally not needed on client machines |

**Description:** Blocks creation of web shell scripts on Microsoft Server and Exchange Server roles. A web shell is a malicious script that allows remote command execution through a web server. This rule is primarily designed for server environments but can be enabled on workstations for defense-in-depth.

**⚠️ Note:** This rule is most relevant for servers running IIS, Exchange, or other web services. On Windows 11 workstations, it provides minimal value unless hosting web services.

**Blocked Activities:**
- Creation of suspicious scripts in web directories (`.aspx`, `.asp`, `.php`, `.jsp`)
- Upload of executable code to web-accessible folders
- Modification of existing web files to add backdoor functionality

**Common False Positives:**
- Legitimate web application deployments (require exclusions)
- Automated CMS updates
- Development/testing environments

---

## 📊 Deployment Modes

### Mode Values

| Mode | Value | Description | Use Case |
|------|-------|-------------|----------|
| **Not Configured** | 0 | Rule disabled | Default state |
| **Block** | 1 | Block and log | Production |
| **Audit** | 2 | Log only, don't block | Testing phase |
| **Warn** | 6 | Warn user, allow bypass | Transition phase |

### Recommended Rollout

```powershell
# Phase 1: Audit Mode (2-4 weeks)
Set-MpPreference -AttackSurfaceReductionRules_Actions 2

# Phase 2: Warn Mode (1-2 weeks) - if supported by rule
Set-MpPreference -AttackSurfaceReductionRules_Actions 6

# Phase 3: Block Mode (Production)
Set-MpPreference -AttackSurfaceReductionRules_Actions 1
```

---

## 🔍 Monitoring & Troubleshooting

### Event Log Location

**Path:** `Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational`

### Key Event IDs

| Event ID | Description | Action |
|----------|-------------|--------|
| **1121** | ASR rule blocked an action | Investigate - potential threat or false positive |
| **1122** | ASR rule audited an action | Review - would have been blocked in Enforce mode |
| **1125** | ASR rule configuration changed | Audit trail |
| **5007** | ASR rule settings modified | Audit trail |

### PowerShell Commands

```powershell
# List all ASR rules and their states
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions

# Check ASR events (last 7 days)
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[(EventID=1121 or EventID=1122) and TimeCreated[timediff(@SystemTime) <= 604800000]]]" | Format-Table TimeCreated, Id, Message -AutoSize

# Export ASR audit events to CSV
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[EventID=1122]]" | 
    Select-Object TimeCreated, @{N='RuleName';E={$_.Properties[0].Value}}, @{N='Path';E={$_.Properties[1].Value}} | 
    Export-Csv -Path "ASR-Audit-Log.csv" -NoTypeInformation
```

---

## ⚙️ Exclusion Management

### Add Exclusions

```powershell
# Add file/folder exclusion
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\CustomApps\MyApp.exe"
Add-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\TrustedFolder\*"

# View current exclusions
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionOnlyExclusions
```

### Common Exclusion Patterns

```powershell
# Development environments
"C:\Dev\*"
"C:\Source\*"

# Enterprise applications
"C:\Program Files\YourCompany\*"
"\\FileServer\Apps\*"

# Build systems
"C:\BuildAgent\*"
"C:\Jenkins\*"

# Admin tools
"C:\AdminTools\*"
"C:\Program Files\SysInternals\*"
```

---

## 🎯 Rule Priority Recommendations

### High Priority (Enable First)

These rules have **low false positive rates** and **high security value**:

1. **Block credential stealing from lsass.exe** (`9E6C4E1F-...`)
2. **Block executable content from email** (`BE9BA2D9-...`)
3. **Block Office apps from creating executables** (`3B576869-...`)
4. **Block persistence through WMI** (`E6DB77E5-...`)
5. **Block vulnerable signed drivers** (`56A863A9-...`)
6. **Block Safe Mode rebooting** (`33DDEDF1-...`) - NEW

### Medium Priority (Test Thoroughly)

These rules are effective but may cause **some false positives**:

7. **Block Office apps from creating child processes** (`D4F940AB-...`)
8. **Block JavaScript/VBScript launching executables** (`D3E037E1-...`)
9. **Block obfuscated scripts** (`5BEB7EFE-...`)
10. **Use advanced ransomware protection** (`C1DB55AB-...`)
11. **Block copied/impersonated system tools** (`C0033C00-...`) - NEW

### Low Priority (Require Extensive Testing)

These rules are **highly aggressive** and require **careful exclusion management**:

12. **Block Win32 API calls from Office macros** (`92E97FA1-...`) - Breaks advanced Excel macros
13. **Block executables by prevalence/age** (`01443614-...`) - Breaks new/custom software
14. **Block PSExec and WMI commands** (`D1E49AAC-...`) - Breaks admin workflows
15. **Block unsigned processes from USB** (`B2B3F03D-...`) - Breaks portable software

### Optional (Server/Specialized Workloads)

These rules provide value in specific scenarios:

16. **Block Webshell creation** (`A8F5898E-...`) - Primarily for servers running web services
17. **Block Adobe Reader child processes** (`7674BA52-...`) - If Adobe Reader is used
18. **Block Office communication child processes** (`26190899-...`) - If Outlook is heavily used
19. **Block Office code injection** (`75668C1F-...`) - Defense-in-depth for Office security

---

## 📚 References

1. **Microsoft Official Documentation**
   - [ASR Rules Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)
   - [ASR Deployment Guide](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-deployment)

2. **Security Baseline 25H2**
   - [Windows 11 25H2 Baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-windows-11-version-25h2/ba-p/4266613)

3. **Event Monitoring**
   - [ASR Events Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-deployment-test)

---

## 🔄 Script Integration

This project implements ASR rules via:

- **Module:** `Modules\SecurityBaseline-ASR.ps1`
- **Default Mode:** Enforce (Block) - configurable via `-Mode` parameter
- **Validation:** Script checks Defender availability before applying rules
- **Fallback:** Manual instructions provided if automated deployment fails

**Script Features:**
- Automatic mode detection (Audit/Warn/Enforce)
- Event log validation
- BitDefender/3rd-party AV detection
- Graceful fallback with user instructions

---

**Last Updated:** November 7, 2025 (Windows 11 25H2, NoID Privacy v1.8.1)
