# Changelog

All notable changes to NoID Privacy Pro will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2025-11-20

### 🎉 Major Release - Complete Framework with Zero-Day Protection

Complete implementation of all 7 planned modules (583 security settings) with full BAVR pattern compliance and production-ready quality.

### ✅ Added

#### New Modules

**AdvancedSecurity Module (v2.1.0) - 42 Settings**
- **SRP .lnk Protection (CVE-2025-9491)** - Critical zero-day mitigation
  - Blocks .lnk execution from `%LOCALAPPDATA%\Temp\*.lnk` (Outlook attachments)
  - Blocks .lnk execution from `%USERPROFILE%\Downloads\*.lnk` (Browser downloads)
  - Windows 11 SRP bug fix implemented (removes buggy registry keys)
  - Compliance testing: `Test-SRPCompliance`
  - Protection against actively exploited vulnerability (no patch available)
  
- **Windows Update Configuration** - 3 simple GUI-equivalent settings
  - Get latest updates immediately: `IsContinuousInnovationOptedIn = 1`
  - Microsoft Update for other products: `AllowMUUpdateService = 1`
  - Delivery Optimization P2P off: `DODownloadMode = 0`
  - Compliance testing: `Test-WindowsUpdate`
  
- **Finger Protocol Block** - ClickFix malware protection
  - Outbound TCP port 79 blocked via Windows Firewall
  - Prevents `finger.exe` abuse by ClickFix campaign
  - Zero impact (protocol obsolete since 1990s)

**EdgeHardening Module (v2.1.0) - 20 Settings**
- Microsoft Edge v139 Security Baseline policies
- Native PowerShell implementation (no LGPO.exe dependency)
- SitePerProcess, SmartScreenEnabled, SSL/TLS hardening
- IE Mode restrictions, Extension security
- Full BAVR pattern implementation

#### Core Features

**Complete BAVR Pattern (Backup-Apply-Verify-Restore)**
- All 583 settings now fully verified in `Verify-Complete-Hardening.ps1`
- EdgeHardening: 20 verification checks added
- AdvancedSecurity: 42 verification checks added
- 100% coverage achieved (was 89.4%)

**Bloatware Removal & Restore User Experience**
- `REMOVED_APPS_LIST.txt` created in backup folder
- Lists all removed apps with reinstall instructions as fallback
- New `REMOVED_APPS_WINGET.json` metadata enables automatic reinstallation of most removed apps via `winget` during session restore (where mappings exist)
- Restore process now attempts auto-restore first and keeps manual Microsoft Store reinstall as backup path

**Resource Management**
- Temporary file cleanup with `finally` blocks
- SecurityBaseline: 3 temp files now always cleaned up
- Prevents TEMP folder pollution from secedit.exe
- Memory leak prevention

#### Documentation
- **FEATURES.md** - Complete feature reference (583 settings documented)
- **SECURITY-ANALYSIS.md** - Home user impact analysis
  - Password policies only affect local accounts (~5% of users)
  - FireWire blocking documented with workaround
  - BitLocker USB policy analysis

### 📊 Changed

**Module Completion**
- Framework Status: **7/7 modules (100%)**
- Total Settings: **583**
  - SecurityBaseline: 425 settings
  - ASR: 19 rules
  - DNS: 5 checks (when enabled)
  - Privacy: 48 checks (when enabled)
  - AntiAI: 24 policies (when enabled)
  - EdgeHardening: 20 policies (NEW)
  - AdvancedSecurity: 42 settings (NEW)

**Module Structure Consistency**
- ASR: Renamed `Data/` → `Config/` for consistency
- EdgeHardening: Renamed `ParsedSettings/` → `Config/`
- All 7 modules now use `/Config/` folder structure
- Updated all code references to new paths

**Verification System**
- Verify-Complete-Hardening.ps1 coverage: 89.4% → **100%**
- Base settings count: 444 → 506
- Total verification steps: 4 → 6
- Added EdgeHardening verification (20 checks)
- Added AdvancedSecurity verification (42 checks)
- Result object now includes all 7 modules

**Windows Update Configuration**
- Simplified from 8 complex settings to 3 GUI-equivalent settings
- Removed: Auto-install schedule, auto-reboot, feature/quality deferrals
- Kept: Update notifications, Microsoft Update, Delivery Optimization LAN-only
- Rationale: Matches Windows Settings GUI, MS Best Practice

**Interactive Menu**
- EdgeHardening: Now shows "(20 policies)"
- AdvancedSecurity: Shows comprehensive list of all 42 settings
- Module selection improved with detailed descriptions

### � Fixed

**Critical: Temporary File Leaks**
- SecurityBaseline: secedit.exe temp files not cleaned up on errors
- Added `finally` blocks to 3 files:
  - Set-SecurityTemplate.ps1
  - Backup-SecurityTemplate.ps1
  - Restore-SecurityTemplate.ps1
- Ensures cleanup of $tempInf, $dbFile, $logFile in ALL cases
- Prevents TEMP folder pollution (~30 lines changed)

**Critical: BAVR Pattern Completion**
- EdgeHardening: Added missing 20 verification checks
- AdvancedSecurity: Added missing 42 verification checks
- Verify-Complete-Hardening.ps1: +190 lines
- BAVR coverage: 89.4% → 100%

**User Experience: Bloatware Reinstall**
- Created `REMOVED_APPS_LIST.txt` in backup folder
- Added `REMOVED_APPS_WINGET.json` with mapping to `winget` IDs (where available)
- Session restore now auto-reinstalls mapped apps via `winget` when possible
- Unmapped apps still have clear manual reinstall instructions via Microsoft Store
- 5 files modified (~120 lines total):
  - Remove-Bloatware.ps1: Track removed apps
  - Set-PolicyBasedAppRemoval.ps1: Track policy apps
  - Invoke-PrivacyHardening.ps1: Create list file + winget metadata
  - Restore-PrivacySettings.ps1: Updated messaging for auto/ manual restore
  - Core/Rollback.ps1: Integrated Privacy app restore into `Restore-Session`

### 🎯 Release Highlights

**Zero Known Issues**
- ✅ All 7 modules production-ready (583 settings)
- ✅ 100% BAVR coverage (Backup-Apply-Verify-Restore)
- ✅ Zero-day protection (CVE-2025-9491)
- ✅ No temp file leaks
- ✅ Complete user documentation
- ✅ Professional code quality (verified by external audit)

**Before v2.1.0:**
```
Modules:             5/7 (71%)
Settings:            521
BAVR Coverage:       89.4%
Temp File Cleanup:   Partial
Bloatware Info:      None
Module Structure:    2 inconsistencies
```

**After v2.1.0:**
```
Modules:             7/7 (100%)
Settings:            583
BAVR Coverage:       100%
Temp File Cleanup:   Complete
Bloatware Info:      REMOVED_APPS_LIST.txt
Module Structure:    100% consistent
```

---

## [2.0.1] - 2025-11-16

### 🐛 Fixed
- **Privacy Module:** Corrected check count from 49 to 48 (34 Registry + 14 Bloatware)
  - Fixed off-by-one verification error
  - Updated all documentation to reflect accurate count
  
- **Audit Policies:** Added progress output during apply phase
  - Shows "[1/23] Policy Name... OK" every 5 policies
  - Prevents appearance of script hanging during audit policy application
  - Displays completion summary

- **AntiAI Module:** Added CapabilityAccessManager workaround (24 policies total, was 23)
  - Added `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels = Deny`
  - Workaround for undocumented Paint AI features (Generative Erase, Background Removal)
  - No official Microsoft policies exist for these features
  - Full BACKUP-APPLY-VERIFY-RESTORE integration

### 📊 Changed
- **Total Settings:** Updated from 512 to 521 (all modules enabled)
  - Base: 444 (SecurityBaseline 425 + ASR 19)
  - DNS: 5
  - Privacy: 48 (was 49)
  - AntiAI: 24 (was 23)

---

## [2.0.0] - 2025-01-16

### 🎉 Major Release - Production Ready

First production-ready release with 5 fully implemented modules.

### ✅ Added

#### Modules
- **SecurityBaseline** - Microsoft Security Baseline for Windows 11 25H2 (425 settings)
  - 335 Registry policies
  - 67 Security Template settings
  - 23 Advanced Audit policies
  - No LGPO.exe dependency (native tools only)
  
- **ASR** - Attack Surface Reduction (19 rules)
  - All rules in Block mode
  - ConfigMgr detection for compatibility
  - Cloud Protection validation
  
- **DNS** - Secure DNS with DoH
  - 3 providers: Cloudflare, Quad9, AdGuard
  - IPv4 + IPv6 support
  - DNSSEC validation
  - DHCP-aware backup/restore
  
- **Privacy** - Telemetry & Privacy Hardening (48 checks)
  - 3 modes: MSRecommended, Strict, Paranoid
  - MSRecommended: User-friendly, max compatibility
  - Bloatware removal (policy-based on 25H2+ Ent/Edu)
  - OneDrive hardening (telemetry off, sync functional)
  - Microsoft Store policies
  
- **AntiAI** - Windows 11 AI Feature Management (24 policies)
  - Generative AI Master Switch (AppPrivacy + CapabilityAccessManager)
  - Windows Recall (complete deactivation + enterprise protection)
  - Windows Copilot + hardware key remap
  - Click to Do
  - Paint AI (Cocreator, Generative Fill, Image Creator)
  - Notepad AI
  - Settings Agent
  - **Note:** Paint Generative Erase/Background Removal workaround (no official MS policies)

#### Framework
- Core orchestration engine (`Core/Framework.ps1`)
- Configuration management (`Core/Config.ps1`)
- Logging system with multiple levels (`Core/Logger.ps1`)
- System validation (`Core/Validator.ps1`)
- Backup/Restore system (`Core/Rollback.ps1`)
- Comprehensive verification script (`Verify-Complete-Hardening.ps1`)

#### Testing
- Integration tests for all 5 modules
- Test runner script (`Tests/Run-AllTests.ps1`)
- Verification of 512 total settings

#### Documentation
- Complete README.md
- STATUS.md with implementation tracking
- Module-specific analysis documents
- Inline code documentation

### 🔧 Changed
- Config synchronization: `config.json` now matches `Core/Config.ps1`
- AntiAI module: Now enabled by default in config
- Privacy module MSRecommended: User-friendly settings
  - Settings Sync: Default off, user can enable (Value=2)
  - Location: User-controlled (removed from config, Windows default)
  - All App Privacy: User decides (Value=0)

### 🔨 Fixed
- Framework.ps1: Module execution fully wired (deprecated old placeholder API)
- Config.ps1: Removed obsolete modules (Bloatware, OneDrive, Telemetry, Performance, CredentialGuard)
- Verify-Complete-Hardening.ps1: Updated counts (512 total, 49 Privacy, 35 Registry)
- AntiAI-Settings.json: Removed overpromising "100%" marketing claims, replaced with accurate descriptions

### 📝 Technical Details
- **Total Settings:** Up to 512 (444 base + 5 DNS + 49 Privacy + 14 AntiAI)
- **Verification Coverage:** 100% of applied settings
- **Test Coverage:** Integration tests for all production modules
- **Windows Support:** Windows 11 build 26100+ (24H2 or 25H2)
- **PowerShell:** 5.1+ compatible

---

## Legend

- ✅ Added: New features
- 🔧 Changed: Changes to existing functionality
- 🔨 Fixed: Bug fixes
- ❌ Removed: Removed features
- 🔒 Security: Security improvements
- 📝 Documentation: Documentation changes
- 🎉 Major milestone

---

**For detailed technical documentation, see:** `/Docs/Analysis/` 
**For module details, see:** `README.md` 
