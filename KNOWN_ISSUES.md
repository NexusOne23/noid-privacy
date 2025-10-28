# 🐛 Known Issues & Limitations

This document tracks known limitations and issues in **NoID Privacy - Windows 11 25H2 Security Baseline**.

---

## 🔍 Current Limitations

### Windows Defender Related

**ASR Rules Script Configuration**
- **Issue**: ASR rules cannot always be set via PowerShell script
- **Symptom**: `AttackSurfaceReductionRules_Ids` property not found
- **Cause**: Third-party antivirus active, or Defender service not fully available
- **Workaround**: Manually activate in Windows Security → Virus & threat protection → Manage settings → Attack surface reduction rules
- **Impact**: Non-critical - script continues with other hardening
- **Status**: Expected behavior, documented in script output

**Defender Error 0x800106ba**
- **Issue**: Transient error when setting MpPreference
- **Symptom**: PUA configuration shows timing error
- **Cause**: Defender service initialization timing
- **Workaround**: Script falls back to registry-based PUA configuration
- **Impact**: Non-critical - PUA is still activated via registry
- **Status**: Handled automatically, cosmetic error only

**Controlled Folder Access Verification**
- **Issue**: Cannot verify Controlled Folder Access status programmatically
- **Cause**: Third-party AV or Defender not fully available
- **Workaround**: Manual verification in Windows Security
- **Impact**: Non-critical - feature may still be active
- **Status**: Expected when third-party AV is present

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
- **Cause**: Feature announced in Baseline 25H2 but not yet released
- **Workaround**: Script sets registry keys for future-proofing
- **Impact**: Feature will activate in future Windows updates
- **Status**: Forward-compatible, settings prepared

### Windows LAPS

- **Issue**: Not available on Windows Home edition
- **Cause**: Enterprise/Pro feature
- **Workaround**: Script detects and skips gracefully
- **Impact**: Home users: use alternative password management
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

### Firewall Strict Mode Compatibility

- **Issue**: Strict Inbound Firewall blocks ALL incoming connections
- **Cause**: Security-first design
- **Workaround**: Configure exceptions in Windows Firewall for needed services
- **Impact**: Maximum security, may break file sharing, remote desktop
- **Status**: By design - documented in script output

---

## ⚙️ System Compatibility

### BitLocker Re-Encryption

- **Issue**: Upgrading from AES-128 to AES-256 requires full re-encryption
- **Cause**: Windows limitation - cannot convert in-place
- **Process**: Disable → Wait for decryption → Re-enable with AES-256
- **Duration**: 30-90 minutes depending on drive size
- **Impact**: Time-consuming but secure
- **Status**: Expected, documented in script output

### Service Disabling on Protected Systems

- **Issue**: Some services cannot be disabled (TrustedInstaller protected)
- **Cause**: Windows protects critical system services
- **Workaround**: Script attempts registry-based disable
- **Impact**: Some services may remain active
- **Status**: Expected, script handles gracefully

---

## 🎮 Compatibility Notes

### Xbox Services

- **Issue**: Xbox features (Game Bar, Game Mode, etc.) are disabled
- **Impact**: Xbox app, Game Pass, achievements may not work
- **Workaround**: Re-enable Xbox services manually if needed
- **Status**: By design - gaming features sacrificed for security

### Miracast / Wireless Display

- **Issue**: Casting to Smart TV disabled
- **Impact**: "Cast" button in Quick Settings remains but doesn't work
- **Workaround**: Manually remove button (Windows + A → Edit) or re-enable services
- **Status**: By design - wireless display is security risk

### Remote Access

- **Issue**: ALL remote access disabled (RDP, WinRM, Remote Assistance)
- **Impact**: Only physical access or Intune/SCCM management possible
- **Workaround**: Re-enable specific services if remote access needed
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
- **Status**: Expected Windows behavior

---

## 🔄 Reporting Issues

Found a bug not listed here? Please report it:

1. **Check**: Verify it's not in this list
2. **Search**: Check existing [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues)
3. **Report**: Create new issue with:
   - Windows version & build
   - Script version
   - Error message or behavior
   - Steps to reproduce
   - Log file (if applicable)

### Security Issues

**DO NOT** report security vulnerabilities publicly!
- Follow [SECURITY.md](SECURITY.md) for responsible disclosure
- Use GitHub Security Advisory (preferred)

---

## ✅ Fixed Issues

See [CHANGELOG.md](CHANGELOG.md) for resolved issues and version history.

---

*Last Updated: October 2025*
