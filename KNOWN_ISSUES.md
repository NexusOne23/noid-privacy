# 🐛 Known Issues & Limitations

This document tracks known limitations and issues in **NoID Privacy - Windows 11 25H2 Security Baseline**.

**Severity legend:** low = cosmetic/expected · medium = functional change with workaround · high = blocking

### 🔍 Quick Triage (Most Common Issues)

| Issue                                  | Severity | Impact                                  | Quick Workaround                                |
|----------------------------------------|---------:|------------------------------------------|-------------------------------------------------|
| ASR/Controlled Folder Access (Defender-only) | low     | 3rd-party AV blocks Defender features | Manually activate in Windows Security; see AV-Doc |
| DoH fail-closed (no fallback)        | low     | DNS failure if provider down            | Choose reliable provider, temporarily disable DoH, set DNS manually  |
| Strict inbound firewall                 | medium  | Incoming connections blocked             | Add needed exceptions in Windows Firewall                 |
| Miracast/Wireless Display disabled      | medium  | Cast/Screen Mirroring unavailable      | Deselect module in Custom or Restore + Store reinstall   |
| Restore ~90–95% (registry remnants)      | low     | Cosmetic keys remain                    | Manual cleanup per Restore report          |

## 📑 Table of Contents

- [Quick Triage (Most Common Issues)](#quick-triage-most-common-issues)
- [Windows Defender Related](#windows-defender-related)
- [Windows 11 25H2 Specific Issues](#windows-11-25h2-specific-issues)
- [Security Features](#security-features)
- [Network & DNS](#network--dns)
- [System Compatibility](#system-compatibility)
- [Compatibility Notes](#compatibility-notes)
- [Script Behavior](#script-behavior)
- [Third-Party Antivirus](#third-party-antivirus-compatibility)
- [Installation & Execution](#installation--execution)
- [Restore Limitations](#restore-limitations)
- [Reporting Issues](#reporting-issues)

---

## 🔍 Current Limitations

### Windows Defender Related

**ASR Rules Script Configuration**
- **Issue**: ASR rules cannot always be set via PowerShell script
- **Symptom**: `AttackSurfaceReductionRules_Ids` property not found
- **Cause**: Third-party antivirus active, or Defender service not fully available
- **Note**: ASR/Controlled Folder Access are **Defender-only**. Third-party AVs enforce similar protections via their own engines.
- **Workaround**: Manually activate in Windows Security → Virus & threat protection (only works with native Defender)
- **Impact**: Non-critical - third-party AV provides equivalent protection
- **Verify ASR/Defender status (native Defender only):**
  ```powershell
  Get-MpPreference | Select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
  Get-MpComputerStatus | Select RealTimeProtectionEnabled, AntispywareEnabled, IoavProtectionEnabled
  ```
- **Severity:** low
- **Status**: Expected behavior when third-party AV is installed
- **→ See [ANTIVIRUS_COMPATIBILITY.md](ANTIVIRUS_COMPATIBILITY.md)** for product-specific notes and exclusions

**Defender Error 0x800106ba**
- **Issue**: Transient error when setting MpPreference
- **Symptom**: PUA configuration shows timing error
- **Cause**: Defender service initialization timing
- **Workaround**: Script falls back to registry-based PUA configuration
- **Impact**: Non-critical - PUA is still activated via registry
- **Severity:** low
- **Status**: Handled automatically, cosmetic error only

**Controlled Folder Access Verification**
- **Issue**: Cannot verify Controlled Folder Access status programmatically
- **Cause**: Third-party AV or Defender not fully available
- **Note**: Controlled Folder Access is **Defender-only**. Third-party AVs enforce similar ransomware protection via their own engines.
- **Workaround**: Manual verification in Windows Security (only works with native Defender)
- **Impact**: Non-critical - third-party AV provides equivalent ransomware protection
- **Severity:** low
- **Status**: Expected behavior when third-party AV is installed
- **→ See [ANTIVIRUS_COMPATIBILITY.md](ANTIVIRUS_COMPATIBILITY.md)** for product-specific notes

---

## 🎯 Windows 11 25H2 Specific Issues

### Privacy Settings SQLite Database

**Background**: Windows 11 24H2/25H2 changed privacy settings storage from registry to SQLite database.

**Camera & Microphone Master Toggles**
- **Issue**: Master toggles in Settings → Privacy cannot be changed via script
- **Cause**: SQLite database-based storage (not registry)
- **Workaround**: 
  1. Script disables all default apps (no camera/mic access until user permits)
  2. User manually disables master toggles in Settings if desired
- **Impact**: Privacy by default is active - apps need user permission
- **Status**: Documented, workaround provided in script output

**App Permissions Master Toggles**
- **Issue**: Master toggles for Notifications, Contacts, Calendar, etc. cannot be changed via script
- **Cause**: SQLite database-based storage
- **Workaround**: Script disables default app permissions - user can manually disable master toggles
- **Impact**: Privacy by default is active
- **Status**: Documented, optional manual step

---

## 🔐 Security Features

### Enhanced Privilege Protection (UAC)

- **Issue**: Enhanced Privilege Protection Mode not yet active
- **Cause**: Feature announced in MS Baseline 25H2; registry prepared for future activation
- **Workaround**: Script sets registry keys for forward-compatibility
- **Impact**: Feature will activate when Microsoft releases it in future Windows updates
- **Status**: Forward-compatible, settings prepared (not currently activatable)

### Windows LAPS

- **Issue**: Not available on Windows Home edition
- **Cause**: Enterprise/Pro feature
- **Workaround**: Script detects and skips gracefully
- **Impact**: Home users: use alternative password management
- **Severity:** low
- **Status**: Expected, documented

---

## 🌐 Network & DNS

### DNS over HTTPS (DoH) Activation

- **Issue**: DoH may not activate immediately after configuration
- **Cause**: Windows caches DNS settings
- **Workaround**: Reboot or flush DNS cache (`ipconfig /flushdns`)
- **Impact**: DoH becomes active after reboot or DNS flush
- **Status**: Expected Windows behavior

### VPN Adapter DNS

- **Issue**: VPN adapters are intentionally skipped during DNS configuration
- **Cause**: By design - VPN DNS must remain unchanged
- **Impact**: VPN functionality preserved
- **Status**: Expected, correct behavior

### DNS Fallback Behavior

- **Issue**: No automatic fallback to unencrypted DNS if DoH provider is unreachable
- **Cause**: By design — security-first (fail-closed) approach
- **Why This Is Correct**: Falling back to plaintext DNS would defeat the purpose of DoH and risk DNS leaks
- **Impact**: If DoH provider experiences downtime, DNS queries will fail until provider is reachable
- **Workarounds**: 
  - Choose a reliable provider with high uptime (Cloudflare/Quad9: 99.99%+ uptime)
  - Temporarily disable DoH in Windows Settings if emergency access needed
  - Manual DNS override in Network Adapter settings
- **Verify DoH status:**
  ```powershell
  Get-DnsClientDohServerAddress
  Resolve-DnsName example.com
  ```
- **Severity:** low
- **Status**: Working as designed - Security > Convenience

### Firewall Strict Mode Compatibility

- **Issue**: Strict Inbound Firewall blocks ALL incoming connections
- **Cause**: Security-first design
- **Workaround**: Configure exceptions in Windows Firewall for needed services
- **Impact**: Maximum security, may break file sharing, remote desktop
- **Verify firewall default actions (strict inbound expected):**
  ```powershell
  Get-NetFirewallProfile | Select Name, DefaultInboundAction, DefaultOutboundAction
  ```
- **Severity:** medium
- **Status**: By design - documented in script output

---

## ⚙️ System Compatibility

### BitLocker Re-Encryption

- **Issue**: Upgrading from AES-128 to AES-256 requires full re-encryption
- **Cause**: Windows limitation - cannot convert in-place
- **Process**: Disable → Wait for decryption → Re-enable with AES-256
- **Duration**: 30-90 minutes depending on drive size
- **Impact**: Time-consuming but secure and plannable
- **Severity:** low
- **Status**: Expected, documented in script output

### Service Disabling on Protected Systems

- **Issue**: Some services cannot be disabled (TrustedInstaller protected)
- **Cause**: Windows protects critical system services
- **Workaround**: Script attempts registry-based disable
- **Impact**: Some services may remain active
- **Severity:** low
- **Status**: Expected, script handles gracefully

---

## 🎮 Compatibility Notes

### Xbox Services

- **Issue**: Xbox features (Game Bar, Game Mode, etc.) are disabled
- **Impact**: Xbox app, Game Pass, achievements may not work
- **Workaround**: Re-enable Xbox services manually if needed
- **Status**: By design (opt-out in Interactive mode) - gaming features sacrificed for security

### ⚠️ Miracast / Wireless Display (Breaking Feature)

**ShellHost.exe Stack Buffer Overflow Warning**

**Symptom**:  
After running Wireless Display module, when user clicks "Cast" button (Windows + K or Quick Settings → Cast/Wiedergeben), Windows displays error message:  
*"Das System hat in dieser Anwendung den Überlauf eines stapelbasierten Puffers ermittelt. Dieser Überlauf könnte einem bösartigen Benutzer ermöglichen, die Steuerung der Anwendung zu übernehmen."*  
(English: "The system detected a stack-based buffer overflow in this application. This overflow could allow a malicious user to gain control of the application.")

**⚠️ Important:** Error ONLY appears when user actively attempts to cast (clicks Cast button), NOT automatically at system startup or during normal use

**What Happens:**
- User clicks "Cast" button in Quick Settings or presses Windows + K
- Windows Shell (ShellHost.exe) attempts to access disabled Miracast services
- System throws buffer overflow warning as safety mechanism
- **Note:** The warning is triggered by intentionally disabled components. No exploit has been observed during testing.
- The warning appears because Windows expects Miracast services to be available when Cast is invoked

**Functionality Permanently Lost:**
- Casting to Smart TV via Miracast
- Wireless Display projector connections
- DLNA/PlayTo Receiver
- Wi-Fi Direct screen mirroring
- "Cast" button in Quick Settings remains visible but non-functional

**How to AVOID This Issue:**

1. **In Interactive Mode:**
   - Select "Custom" mode
   - Deselect "Wireless Display / Miracast" module
   - Script will skip all Miracast hardening

2. **In Enforce/Audit Mode:**
   - Not currently configurable (all modules run)
   - Future versions may add module selection

**How to RESTORE Wireless Display:**

1. **Run Restore Script:**
   ```powershell
   .\Restore-SecurityBaseline.ps1
   ```
   
2. **What Gets Restored Automatically:**
   - ✅ Services (ProjSvc, DevicePickerUserSvc, DevicesFlowUserSvc, DisplayEnhancementService)
   - ✅ Registry keys (PlayToReceiver, AllowProjectionToPC, WirelessDisplay policies)
   - ✅ Firewall rules (Wireless Display, Wi-Fi Direct rules re-enabled)

3. **What Requires Manual Reinstallation:**
   - ⚠️ Removed Apps: `Microsoft.Windows.SecondaryTileExperience`, `PPIProjection`, `Miracast` packages
   - These must be manually reinstalled from Microsoft Store
   - Search for "Wireless Display" or "Connect" app in Store

4. **Verification After Restore:**
   ```powershell
   # Check services
   Get-Service ProjSvc, DevicePickerUserSvc
   
   # Check registry
   Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PlayToReceiver" -Name Enabled
   
   # Test casting
   Windows + K (Open Cast menu)
   ```

**Why This Module Exists:**

Wireless Display protocols have known security vulnerabilities:
- Man-in-the-middle attack vectors
- Unencrypted screen mirroring
- Network discovery information leakage
- Potential for unauthorized screen capture

For maximum security (no casting needs), this module disables all wireless display functionality. For users who need casting, skip this module in Custom mode.

**Severity:** medium  
**Status:** By design - aggressive hardening with documented side effects

### Remote Access

- **Issue**: ALL remote access disabled (RDP, WinRM, Remote Assistance)
- **Impact**: Only physical access or Intune/SCCM management possible
- **Workaround**: Re-enable specific services if remote access needed
- **Severity:** medium
- **Status**: By design - maximum security

---

## 📝 Script Behavior

### Non-Fatal Warnings

- **Issue**: Script shows ~200-300 non-fatal warnings
- **Examples**: Services not found, apps already removed, registry keys already exist
- **Cause**: Idempotent design - script is safe to re-run
- **Impact**: None - warnings are harmless and filtered in completion report
- **Status**: Expected, by design

### Restart Required

- **Issue**: Many features require restart to take effect
- **Affected**: VBS, Credential Guard, BitLocker, Firewall, Services
- **Workaround**: Reboot after script completion
- **Impact**: Features not active until reboot
- **Severity:** low
- **Status**: Expected Windows behavior

---

## 🔄 Reporting Issues

Found a bug not listed here? Please report it:

1. **Check**: Verify it's not in this list
2. **Search**: Check existing [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues)
3. **Report**: [Create new issue](https://github.com/NexusOne23/noid-privacy/issues/new) with:
   - Windows version & build
   - Script version
   - Error message or behavior
   - Steps to reproduce
   - Log files (if applicable): `logs/Apply-*.log`, `logs/Verify-*.log`, `logs/Restore-*.log`

**Minimal system info bundle (saves round-trips):**
```powershell
# System info
Get-ComputerInfo | Select OsName,OsVersion,OsBuildNumber,WindowsProductName,WindowsEditionId,OsLocale,Timezone | Format-List

# Defender status (if applicable)
Get-MpComputerStatus | Select AMRunningMode,RealTimeProtectionEnabled,IoavProtectionEnabled | Format-List

# Firewall status
Get-NetFirewallProfile | Select Name,DefaultInboundAction,DefaultOutboundAction
```

### Security Issues

**DO NOT** report security vulnerabilities publicly!
- Follow [SECURITY.md](SECURITY.md) for responsible disclosure
- Use [GitHub Security Advisory](https://github.com/NexusOne23/noid-privacy/security/advisories/new) (preferred)

---

## 🛡️ Third-Party Antivirus Compatibility

> 📖 **For complete documentation with detailed workarounds, see:** [ANTIVIRUS_COMPATIBILITY.md](ANTIVIRUS_COMPATIBILITY.md)

### Quick Summary

**Common Issues:**
- ⚠️ **Third-Party Antivirus (especially Bitdefender):** False positive on `RestrictRemoteSAM` registry key
  - **Detection:** `Heur.BZC.Boxter.151.7C4B21F2` (Bitdefender), similar heuristics in Norton/Avast
  - **Solution:** Add registry key to AV exclusions
  - **Example (Bitdefender):** Protection → Vulnerability → Settings → Exclusions → Add Registry Key
  - **Key:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictRemoteSAM`
  - **⚠️ DO NOT REMOVE THIS KEY!** It protects against Pass-the-Hash attacks

- ⚠️ **Norton/Avast:** May flag PowerShell script execution
  - **Solution:** Add script folder to exclusions

**Expected Verify Results with Third-Party AV:**
- ✅ **Native Windows Defender:** 118-119/133 PASS
- ✅ **Bitdefender/Kaspersky/Norton/ESET:** 96-100/133 PASS (expected!)
- ❌ Failed checks: ASR Rules (19x), Network Protection, Cloud Protection, PUA
- **Why This Is OK:** Third-party AV provides equivalent protection features

**Tested & Working:**
- ✅ Bitdefender (RestrictRemoteSAM exclusion recommended)
- ✅ Kaspersky
- ✅ Norton/Symantec (may flag PowerShell/RestrictRemoteSAM)
- ✅ ESET NOD32
- ✅ Malwarebytes

**📖 For detailed information including:**
- Step-by-step AV exclusion guides (Bitdefender, Norton, Kaspersky examples)
- Driver installation workarounds (Intel, NVIDIA, AMD)
- PowerShell cmdlet behavior with third-party AV
- Complete feature comparison table
- How to report false positives
- Registry key verification commands
- All supported antivirus products

**→ See [ANTIVIRUS_COMPATIBILITY.md](ANTIVIRUS_COMPATIBILITY.md)**

---

## 🔧 Installation & Execution

### VirtualTerminalLevel Registry Change

**Background**: The `Start-NoID-Privacy.bat` launcher enables colored console output for better readability.

- **Change Made**: Sets `HKCU:\Console\VirtualTerminalLevel = 1`
- **Purpose**: Enables ANSI color codes in PowerShell console (green/red/yellow text)
- **Persistence**: Registry value remains after script execution
- **Impact**: Minimal - only affects console color support
- **Removal (Optional)**:
  ```powershell
  Remove-ItemProperty -Path "HKCU:\Console" -Name "VirtualTerminalLevel" -ErrorAction SilentlyContinue
  ```
- **Status**: Cosmetic change, no security implications

---

## 🔄 Restore Limitations

### Restore Completeness: 90-95%

**Background**: The Restore script recovers the vast majority of changes, but a few registry keys may remain.

- **Success Rate**: 90-95% of all changes are restored
- **What Stays**: A small number of registry keys (primarily cosmetic settings)
- **Impact**: Non-critical - system remains fully functional and stable
- **Why This Happens**: Some keys have complex ownership/permission structures or are recreated by Windows
- **Workaround**: Manual cleanup of remaining keys (documented in Restore output)
- **Status**: Non-critical limitation - will be improved in v1.8.2

**What Is Restored:**
- ✅ Services (100%)
- ✅ Scheduled Tasks (100%)
- ✅ Firewall Rules (100%)
- ✅ DNS Settings (100%)
- ✅ Hosts File (100%)
- ✅ User Account States (100%)
- ✅ **Registry Keys (most, ~90–95%)**

---

### Security Template Persistence After Restore

**Background**: The Security Template (67 settings applied via `secedit.exe`) cannot be fully reverted by Windows design.

**What Stays Hardened After Restore:**

1. **Password Policy** (6 settings)
   - Minimum Password Length: 14 characters (was: 8)
   - Password Complexity: ON (was: OFF)
   - Password History: 24 passwords (was: 0)
   - Account Lockout: 10 attempts / 10 minutes (was: disabled)

2. **UAC Settings** (9 settings)
   - UAC remains enabled with secure desktop prompts
   - Inactivity timeout: 15 minutes
   - Enhanced privilege protection mode configured

3. **NTLM/SMB/Network Security** (13 settings)
   - NTLMv2 only (no legacy NTLMv1)
   - SMB Signing required
   - Anonymous access blocked
   - Plaintext passwords disabled

4. **Privilege Rights** (23 settings)
   - Restricted debug/backup/restore rights
   - Create Token/Permanent Objects blocked
   - Stricter privilege assignments

5. **LSA/Security Settings** (7 settings)
   - Blank password use forbidden
   - Remote SAM access restricted
   - LDAP client signing required

**Why This Happens:**
- Windows **does not allow** reverting hardened security policies to less restrictive values per local security policy behavior
- This is documented Microsoft behavior (security-by-design)
- Example: Password complexity ON cannot be turned OFF via `secedit.exe`

**Is This a Problem?**
- ❌ **NO** - Having stricter security is BETTER, not worse!
- ✅ Your system remains **MORE SECURE** than the backup state
- ✅ All other settings (Registry, Services, Firewall, DNS) are fully restored

**What Was Restored:**
- ✅ **Registry keys (most, ~90–95%)**
- ✅ Services (100% restored)
- ✅ Firewall rules and profiles (100% restored)
- ✅ DNS settings (100% restored)
- ✅ User account states (100% restored)
- ⚠️ Security Template (stays hardened - Windows limitation)

**If You Need Exact Original State:**
- Fresh Windows installation is the only guaranteed method
- However, this is rarely necessary - stricter security is preferred!

**Compatibility Notes:**
- Modern applications work fine with these hardened settings
- Legacy systems (Windows XP/2000) cannot connect (NTLMv1 blocked)
- Some old NAS devices may need firmware updates (SMB1 disabled)
- 14-character password requirement applies to LOCAL accounts only (not Microsoft accounts)

---

## ✅ Fixed Issues

See [CHANGELOG.md](CHANGELOG.md) for resolved issues and version history.

---

*Last Updated: November 8, 2025 (v1.8.1)*
