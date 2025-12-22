# Changelog

All notable changes to NoID Privacy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.2.2] - 2025-12-22

### 🚀 Performance Release

**Major performance improvement for AdvancedSecurity firewall operations.**

### ⚡ Performance

**Firewall Snapshot Performance Fix (Critical)**
- Fixed: Firewall rules backup took 60-120 seconds (especially in offline mode)
- Root cause: `Get-NetFirewallPortFilter` was called individually for each of ~300+ firewall rules (~200ms per call)
- Fix: Batch query approach - load all port filters once into hashtable, then fast lookup by InstanceID
- Result: **60-120 seconds → 2-5 seconds** (both online and offline)
- Affected files:
  - `Modules/AdvancedSecurity/Private/Backup-AdvancedSecuritySettings.ps1`
  - `Modules/AdvancedSecurity/Private/Disable-RiskyPorts.ps1`

### ✅ Changed

**Version Alignment**
- All 60+ framework files updated to v2.2.2
- Module manifests (.psd1), module loaders (.psm1), core scripts, utilities, tests, and documentation synchronized

---

## [2.2.1] - 2025-12-19

### 🔧 Maintenance Release

**Critical bugfix for multi-run sessions and code review.**

### 🔨 Fixed

**Multi-Run Session Bug (Critical)**
- Fixed: Running framework multiple times in same PowerShell session caused `auditpol.exe` backup failures
- Root cause: `$global:BackupBasePath` was not reset between runs, causing auditpol to fail with "file exists" error
- Fix: Global backup variables (`BackupBasePath`, `BackupIndex`, `NewlyCreatedKeys`, `SessionManifest`, `CurrentModule`) are now reset at script start in `NoIDPrivacy.ps1`
- Impact: Users can now run individual modules, then "Apply All", then individual modules again without errors

**`.Count` Property Bug (5 files)**
- Fixed: `.Count` property failed on single-object results from `Where-Object`
- Affected files: `Invoke-ASRRules.ps1`, `Framework.ps1`, `Test-AdvancedSecurity.ps1`, `Test-DiscoveryProtocolsSecurity.ps1`, `Restore-DNSSettings.ps1`
- Fix: Wrapped results in `@()` to ensure array type

### ✅ Changed

**ASR Prompt Text Improved**
- Changed "untrusted software" to "new software" in ASR prevalence rule prompt
- More neutral language - the software isn't necessarily untrusted, just new/unknown to Microsoft's reputation system

**Code Quality**
- Full codebase review of backup/restore system (2970 lines in `Core/Rollback.ps1`)
- Wireless Display (Miracast) security implementation verified against Microsoft documentation
- All 7 registry policies confirmed correct per MS Policy CSP docs
- Version numbers aligned across all 50+ files

---

## [2.2.0] - 2025-12-08

### 🚀 Enhanced Framework - 630+ Settings

**Major update with expanded AI lockdown, improved privacy coverage, and ASR quick-toggle fix.**

---

## 🌟 Release Highlights

✅ **630+ Settings** - Expanded from 580+ (Privacy, AntiAI, EdgeHardening, AdvSec Wireless Display)  
✅ **NonInteractive Mode** - Full GUI integration via config.json  
✅ **Third-Party AV Support** - Automatic detection, graceful ASR skip  
✅ **AntiAI Enhanced** - 32 policies (was 24), Recall Export Block, Edge Copilot disabled  
✅ **Pre-Framework ASR Snapshot** - Preserves rule state before multi-module runs  
✅ **Smart Registry Backup** - JSON fallback for protected keys  
✅ **Critical Bugfixes** - ASR Quick-Toggle, NonInteractive strict-mode, DNS offline

### ✅ Added

**NonInteractive Mode (GUI Integration)**
- Complete `config.json` support for automated execution
- All 7 modules fully configurable without prompts when values are provided in `config.json`
- Enables GUI-driven hardening in non-interactive mode (no Read-Host prompts)

**Pre-Framework ASR Snapshot**
- Captures all 19 ASR rules before multi-module runs
- Ensures original system state is preserved
- Prevents ASR rule loss during complex operations

**AntiAI Module Enhancements (24 → 32 policies)**
- Recall Export Block (prevents snapshot export)
- Advanced Copilot Blocks (URI handlers, Edge sidebar)
- Improved Edge Copilot sidebar disable (5 additional policies)
- Hardware Copilot key remapped to Notepad
- CapabilityAccessManager AI blocking

**AdvancedSecurity: Wireless Display / Miracast Hardening**
- New Wireless Display security available in all AdvancedSecurity profiles (Balanced/Enterprise/Maximum)
- Default: Block receiving projections and require PIN for incoming connections
- Optional: Complete disable (blocks sending projections, mDNS discovery, ports 7236/7250, and Wi-Fi Direct adapters)

**AdvancedSecurity: Discovery Protocols Security (Maximum profile)**
- Optional WS-Discovery + mDNS complete disable
- Blocks automatic device discovery (printers, TVs, scanners)
- Firewall rules for UDP 3702 (WS-Discovery) and UDP 5353 (mDNS)
- Prevents network mapping and mDNS spoofing attacks

**AdvancedSecurity: IPv6 Disable (Maximum profile - mitm6 mitigation)**
- Optional complete IPv6 disable (DisabledComponents = 0xFF)
- Prevents mitm6 attacks (DHCPv6 spoofing → DNS takeover → NTLM relay)
- Defense-in-depth (WPAD already disabled by framework)
- Recommended for air-gapped/standalone systems

**Privacy Module Expansion (55+ → 78 settings)**
- Cloud Clipboard toggle (user-configurable)
- Enhanced compliance verification
- Improved bloatware detection
- Better OneDrive sync compatibility

**Third-Party Antivirus Detection**
- Automatic detection of Kaspersky, Norton, Bitdefender, etc.
- ASR module gracefully skipped when 3rd-party AV active
- Clear user notification explaining why
- All other modules continue normally (614 settings)

**Smart Registry Backup System**
- JSON fallback for protected system keys
- Handles access-denied scenarios gracefully
- Empty marker files for non-existent keys
- Improved restore reliability

**Documentation**
- AV Compatibility section: "Designed for Microsoft Defender – Works with Any Antivirus"
- Clear 633 vs 614 explanation for Defender vs. 3rd-party AV setups
- Improved troubleshooting guides

### 🔨 Fixed

**ASR Quick-Toggle Bug (Critical)**
- Fixed: Quick-toggling ASR rules caused 3 advanced rules to disappear
- Affected rules: Safe Mode Reboot, Copied System Tools, Webshell Creation
- Root cause: `Set-MpPreference` was called with single rule instead of full rule set
- Fix: Now reads existing rules, updates target, writes complete set back

**NonInteractive Strict-Mode Error**
- Fixed fatal error when dot-sourcing `NonInteractive.ps1` in GUI context
- Safe check for `$global:NonInteractiveMode` variable

**Registry Backup Protected Keys**
- Enhanced JSON fallback for protected system keys
- Prevents backup failures on restricted registry paths
- Creates marker files for rollback tracking

**DNS Offline Handling**
- Graceful handling when system temporarily offline during DNS test
- Configuration proceeds and activates when connection restored

**Module Progress Feedback**
- Improved status messages during long operations
- No more "stuck at 95%" feeling

### 📊 What Changed

| Component | v2.1.0 | v2.2.0 |
|-----------|--------|--------|
| Total Settings | 580+ | **633** |
| AntiAI Policies | 24 | **32** |
| Privacy Settings | 55+ | **78** |
| NonInteractive Mode | ❌ | ✅ |
| 3rd-Party AV Detection | ❌ | ✅ |
| Pre-Framework ASR Snapshot | ❌ | ✅ |
| Smart Registry Backup | Basic | **JSON Fallback** |

---

## [2.1.0] - 2025-11-23

### 🎉 Production Release - Complete Windows 11 Security Framework

**The first complete, production-ready release of NoID Privacy v2.x - 580+ settings, 7 modules, full BAVR pattern implementation.**

---

## 🌟 Release Highlights

✅ **All 7 Modules Production-Ready** - Complete framework with 580+ security settings  
✅ **Zero-Day Protection** - CVE-2025-9491 mitigation (SRP .lnk protection)  
✅ **100% BAVR Coverage** - Every setting can be backed up, applied, verified, and restored  
✅ **Professional Code Quality** - All lint warnings resolved, comprehensive error handling  
✅ **Zero Tracking** - No cookies, no analytics, no telemetry (we practice what we preach)

### ✅ Added - Complete Framework

#### All 7 Security Modules

**SecurityBaseline** (425 settings) - Microsoft Security Baseline for Windows 11 25H2
- 335 Registry policies (Computer + User Configuration)
- 67 Security Template settings (Password Policy, Account Lockout, User Rights, Security Options)
- 23 Advanced Audit policies (Complete security event logging)
- Credential Guard (Enterprise/Education only), BitLocker policies, VBS & HVCI
- No LGPO.exe dependency (100% native PowerShell)

**ASR** (19 rules) - Attack Surface Reduction
- 17 Block + 2 Configurable (PSExec/WMI + New/Unknown Software)
- Blocks ransomware, macros, exploits, credential theft
- Office/Adobe/Email protection
- ConfigMgr detection for compatibility

**DNS** (5 checks) - Secure DNS with DoH encryption
- 3 providers: Quad9 (default), Cloudflare, AdGuard
- REQUIRE mode (no unencrypted fallback) or ALLOW mode (VPN-friendly)
- IPv4 + IPv6 dual-stack support
- DNSSEC validation

**Privacy** (55+ settings) - Telemetry & Privacy Hardening
- 3 operating modes: MSRecommended (default), Strict, Paranoid
- Telemetry minimized to Security-Essential level
- Bloatware removal with auto-restore via winget (policy-based on 25H2+ Ent/Edu)
- OneDrive telemetry off (sync functional)
- App permissions default-deny

**AntiAI** (24 policies) - AI Lockdown
- Generative AI Master Switch (blocks ALL AI models system-wide)
- Windows Recall (complete deactivation + component protection)
- Windows Copilot (system-wide disabled + hardware key remapped)
- Click to Do, Paint AI, Notepad AI, Settings Agent - all disabled

**EdgeHardening** (20 policies) - Microsoft Edge Security Baseline
- SmartScreen enforced, Tracking Prevention strict
- SSL/TLS hardening, Extension security
- IE Mode restrictions
- Native PowerShell implementation (no LGPO.exe)

**AdvancedSecurity** (44 settings) - Beyond Microsoft Baseline
- **SRP .lnk Protection (CVE-2025-9491)** - Zero-day mitigation for ClickFix malware
- **RDP Hardening** - Disabled by default, TLS + NLA enforced
- **Legacy Protocol Blocking** - SMBv1, NetBIOS, LLMNR, WPAD, PowerShell v2
- **TLS Hardening** - 1.0/1.1 OFF, 1.2/1.3 ON
- **Windows Update** - 3 GUI-equivalent settings (interactive configuration)
- **Finger Protocol** - Blocked (ClickFix malware protection)

#### Core Features

**Complete BAVR Pattern (Backup-Apply-Verify-Restore)**
- All 580+ settings now fully verified in `Verify-Complete-Hardening.ps1`
- EdgeHardening: 20 verification checks added
- AdvancedSecurity: 42 verification checks added
- 100% coverage achieved (was 89.4%)

**Bloatware Removal & Restore**
- `REMOVED_APPS_LIST.txt` created in backup folder with reinstall instructions
- `REMOVED_APPS_WINGET.json` metadata enables automatic reinstallation via `winget`
- Session restore attempts auto-restore first, falls back to manual Microsoft Store reinstall
- Policy-based removal for Windows 11 25H2+ Ent/Edu editions

**Documentation & Repository**
- **FEATURES.md** - Complete settings reference
- **SECURITY-ANALYSIS.md** - Home user impact analysis
- **README.md** - Professional restructure with improved visual hierarchy
- **CHANGELOG.md** - Comprehensive release history
- **.gitignore** - Clean repository (ignores Logs/, Backups/, Reports/)

---

### 🔨 Fixed - Critical Bugfixes

**DNS Module Crash (CRITICAL)**
- Fixed `System.Object[]` to `System.Int32` type conversion error in `Get-PhysicalAdapters`
- Removed unary comma operator causing DNS configuration failure
- Prevents complete DNS module failure on certain network configurations

**Bloatware Count Accuracy**
- Corrected misleading console output showing "2 apps removed" instead of actual count
- Fixed pipeline contamination from `Register-Backup` output in `Remove-Bloatware.ps1`
- Now shows accurate count (e.g., "14 apps removed")

**Restore Logging System**
- Implemented dedicated `RESTORE_Session_XXXXXX_timestamp.log` file
- Captures all restore activities from A-Z with detailed logging
- Fixed empty `Message` parameter validation errors in `Write-RestoreLog`

**User Selection Logs**
- Moved user selection messages from INFO to DEBUG (cleaner console output)
- Affects: Privacy mode selection, DNS provider selection, ASR mode selection
- Console now shows only critical information, detailed logs in log file

**Code Quality & Linting**
- Removed all unused variables (`$isAdmin` in `Invoke-AdvancedSecurity.ps1`)
- Fixed PSScriptAnalyzer warnings across entire project
- Resolved double backslash escaping in documentation paths

**Terminal Services GPO Cleanup**
- Enhanced GPO cleanup with explicit value removal
- Improved restore consistency for Terminal Services registry keys
- Cosmetic variance only (no functional impact)

**Temporary File Leaks**
- SecurityBaseline: Added `finally` blocks to prevent temp file pollution
- Ensures cleanup of `secedit.exe` temp files even on errors
- Prevents TEMP folder accumulation

---

### 📊 What Changed

**Framework Completion**
- Status: **7/7 modules (100%)** - All production-ready
- Total Settings: **580+** (was 521)
- BAVR Coverage: **100%** (was 89.4%)
- Verification: **EdgeHardening** (20 checks) + **AdvancedSecurity** (44 checks) added

**Module Structure**
- All 7 modules now use consistent `/Config/` folder structure
- ASR: `Data/` → `Config/`
- EdgeHardening: `ParsedSettings/` → `Config/`

**Documentation Improvements**
- README: Professional restructure, improved navigation
- Added "Why NoID Privacy?" section (Security ↔ Privacy connection)
- Added "Our Privacy Promise" section (Zero tracking)
- Fixed all inconsistent list formatting (trailing spaces → proper bullets)

**Restore System**
- Production tested with full apply-restore cycle verification
- Restores to clean baseline state
- AdvancedSecurity: 100% perfect restoration

---

### ⚠️ Breaking Changes

**License Change**
- **MIT (v1.x) → GPL v3.0 (v2.x+)**
- Reason: Complete rewrite from scratch (100% new codebase)
- Impact: Derivatives must comply with GPL v3.0 copyleft requirements
- Note: v1.8.x releases remain under MIT license (unchanged)
- **Dual-Licensing:** Commercial licenses available for closed-source use

---

### 📈 Before/After Comparison

**Before v2.1.0:**
```
Modules:             5/7 (71%)
Settings:            521
BAVR Coverage:       89.4%
Restore Accuracy:    Unknown
Code Quality:        Lint warnings present
Temp File Cleanup:   Partial
```

**After v2.1.0:**
```
Modules:             7/7 (100%)
Settings:            580+
BAVR Coverage:       100%
Restore:             Verified (full cycle)
Code Quality:        PSScriptAnalyzer clean
Temp File Cleanup:   Complete
```

---

## 📚 Additional Resources

- **Full Documentation:** See [README.md](README.md) and [FEATURES.md](Docs/FEATURES.md)
- **Security Analysis:** See [SECURITY-ANALYSIS.md](Docs/SECURITY-ANALYSIS.md)
- **Bug Reports:** [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues)
- **Discussions:** [GitHub Discussions](https://github.com/NexusOne23/noid-privacy/discussions)

---

**Made with 🛡️ for the Windows Security Community**
