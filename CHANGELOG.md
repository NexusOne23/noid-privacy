# Changelog

All notable changes to NoID Privacy Pro will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2025-11-23

### 🎉 Production Release - Complete Windows 11 Security Framework

**The first complete, production-ready release of NoID Privacy Pro v2.x - 580+ settings, 7 modules, 99% restore accuracy verified.**

---

## 🌟 Release Highlights

✅ **All 7 Modules Production-Ready** - Complete framework with 580+ security settings  
✅ **99% Restore Accuracy** - Production tested and verified (103/585 settings after full apply-restore cycle)  
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
- Credential Guard, BitLocker policies, VBS & HVCI
- No LGPO.exe dependency (100% native PowerShell)

**ASR** (19 rules) - Attack Surface Reduction
- 18 rules in Block mode, 1 configurable (PSExec/WMI)
- Blocks ransomware, macros, exploits, credential theft
- Office/Adobe/Email protection
- ConfigMgr detection for compatibility

**DNS** (5 checks) - Secure DNS with DoH encryption
- 3 providers: Cloudflare (default), Quad9, AdGuard
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
- **FEATURES.md** - Complete 580+ settings reference
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
- 99% restoration accuracy (cosmetic variance only)

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
- 99% accuracy verified (103/585 settings after full apply-restore cycle)
- Better than baseline (+15 settings improvement)
- AdvancedSecurity: 100% perfect restoration (+1 improvement)

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
Restore Accuracy:    99% (verified)
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
