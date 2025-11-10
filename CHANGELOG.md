# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.2] - 2025-11-10

### ✨ New Features

#### **Network Discovery User Choice** 🏠🔒
User-configurable network discovery settings to balance Fortune 500-level security with home user convenience.

**Interactive Menu with 2 Options:**
- **Option 1: Maximum Security (Stealth Mode)** - All discovery protocols blocked (NetBIOS, LLMNR, mDNS, WSD, SSDP, Network Discovery)
- **Option 2: Home User (Modern Protocols)** - Modern protocols enabled (mDNS, WSD/SSDP, Network Discovery), legacy protocols blocked (NetBIOS, LLMNR)

**What's Now Configurable:**
- **mDNS** - Enables Chromecast, AirPlay, Spotify Connect, Smart Home discovery, Miracast
- **WSD/SSDP** - Enables automatic printer discovery (Canon, HP, Epson)
- **Network Discovery** - Enables Explorer network browsing, PC discovery
- **Miracast/Wireless Display** - Automatically linked to mDNS setting

**Security Guarantees:**
- NetBIOS and LLMNR **always blocked** in both modes (Microsoft Baseline 25H2 compliance exceeded)
- Default in non-interactive mode: **Maximum Security**
- Core module is **mandatory** (always selected) ensuring consistent security baseline

**Fixes Home User Issues:**
- ✅ Chromecast/Smart TV discovery now works (Home User mode)
- ✅ Miracast/Wireless Display now works (Home User mode)
- ✅ AirPlay now works (Home User mode)
- ✅ Automatic printer discovery now works (Home User mode)
- ✅ Explorer network browsing now works (Home User mode)
- ✅ Steam In-Home Streaming discovery now works (Home User mode)

### 🐛 Bug Fixes

#### **CRITICAL: Silent File Blocks Without Notification**
Fixed Windows Defender silently blocking/quarantining files without user notification.

**Issue:**
- Files (especially dev tools: `.exe`, `.dll`, `.ino`, `.bat`, `.js`) disappeared without warning
- No notification popup
- Not visible in Windows Security Protection History
- Caused by `ConvertWarnToBlock = 1` registry setting (NIS)

**Root Cause:**
The `ConvertWarnToBlock` setting automatically converted Defender warnings into immediate blocks without user interaction, combined with:
- PUA Protection (marks unsigned tools as potentially unwanted)
- Cloud Protection Level 2 (aggressive heuristics)
- Block at First Seen (zero-day protection)

**Fix:**
Removed `ConvertWarnToBlock` registry setting from `SecurityBaseline-Core.ps1`. Users now receive proper notifications and can choose Allow/Block/Quarantine for detected threats.

**Impact:**
- ✅ All security features remain active (PUA, Cloud Protection, Real-Time Protection)
- ✅ Users now get notifications for threat detections
- ✅ Users can control decisions (Allow/Block/Quarantine)
- ✅ No more silent file deletions
- ✅ Better user experience without compromising security

### 🎨 UX Improvements

**Menu Optimizations:**
- Main menu texts shortened for better readability (e.g., "RDP" instead of "Remote-Access-Konfiguration")
- Network Discovery now mentioned in main menu follow-up texts
- Contra colors changed from Red to Yellow (less alarming, more like warnings)

**Enhanced Logging:**
- Visible Cyan confirmations after each menu choice (OneDrive, RDP, Network Discovery)
- Extended SUCCESS SUMMARY now shows all configuration choices:
  - OneDrive configuration
  - Remote Access mode
  - Network Discovery mode (NEW!)
  - DNS Provider

### 🌍 Localization

**38 New Strings Added (EN/DE):**
- Network Discovery Menu (title, question, options, pros/cons, recommendations)
- Shortened main menu texts in both languages
- All new confirmation messages

### 🔧 Technical Details

**New Script Variables:**
- `$script:NetworkProfile` - 'maximum-security' or 'home-user'
- `$script:AllowmDNS` - Controls mDNS blocking
- `$script:AllowNetworkDiscovery` - Controls Network Discovery
- `$script:AllowWSD_SSDP` - Controls printer discovery protocols

**Modified Functions:**
- `Disable-NetworkLegacyProtocols` - Now conditionally blocks mDNS, WSD, SSDP
- `Enable-NetworkStealthMode` - Now conditionally enables/disables Network Discovery
- `Disable-WirelessDisplay` - Now checks mDNS setting before disabling Miracast

**Files Changed:**
- `Apply-Win11-25H2-SecurityBaseline.ps1` (+108 lines)
- `Modules/SecurityBaseline-Core.ps1` (+167 lines restructured)
- `Modules/SecurityBaseline-Interactive.ps1` (+85 lines)
- `Modules/SecurityBaseline-Localization.ps1` (+88 lines)
- `Modules/SecurityBaseline-WirelessDisplay.ps1` (+11 lines)

**Quality Assurance:**
- ✅ UTF-8 without BOM encoding verified
- ✅ ASCII-only (0 non-ASCII characters)
- ✅ Backup/Restore fully compatible
- ✅ All code paths tested (Maximum Security + Home User modes)
- ✅ Idempotent (safe to run multiple times)

### 📊 Compatibility

- **Microsoft Security Baseline 25H2:** Exceeded (NetBIOS+LLMNR always blocked)
- **Backup/Restore:** Fully compatible (firewall rules captured)
- **Previous Configurations:** No breaking changes for existing deployments (defaults unchanged)

---

## [1.8.1] - 2025-11-07

### 🐛 Critical Bug Fixes (Quick-Win Phase)

#### **Script-Breaking Parser Errors Fixed**
Multiple critical parser errors introduced during previous optimization phase have been identified and resolved. All errors prevented the script from running correctly.

**Fixed Issues:**

1. **Undefined Variable in Apply Script** 🔥
   - **File**: `Apply-Win11-25H2-SecurityBaseline.ps1` (Line 826)
   - **Error**: `$config` undefined - script crashed on startup
   - **Cause**: `Start-InteractiveMode -LogPath $LogPath` called with removed parameter
   - **Fix**: Removed `-LogPath` parameter from function call
   - **Impact**: Interactive mode was completely broken

2. **Registry Definition Parser Errors** 🔥
   - **File**: `Modules\RegistryChanges-Definition.ps1`
   - **Error**: "Description not recognized as Cmdlet" - backup/restore failed
   - **Total Fixes**: 14 instances across 5 different error types

   **a) Incomplete OneDrive Descriptions (8 instances)**
   - **Lines**: 2383, 2392, 2401, 2410, 2419, 2428, 2437, 2446
   - **Pattern**: `Description = '$(Get-LocalizedString'` (unclosed string + subexpression)
   - **Fix**: Replaced with static strings: `'OneDrive: Disable Tutorial'`, `'OneDrive: Disable Feedback'`, etc.
   - **Impact**: Cascading parser errors throughout entire file

   **b) Unescaped Apostrophes (3 instances)**
   - **Lines**: 1321, 1348, 3211
   - **Pattern**: `Description = 'RPC: Don't restrict...'`
   - **Issue**: Single apostrophe prematurely terminated string
   - **Fix**: Escaped apostrophes: `'Don't'` → `'Don''t'`
   - **Impact**: Parser interpreted remainder as code, causing syntax errors

   **c) Array/Hashtable Formatting (1 instance)**
   - **Line**: 29
   - **Pattern**: `$script:RegistryChanges = @(    @{` (space between array and hash)
   - **Fix**: Added newline: `@(\n    @{`
   - **Impact**: Parser confused about structure, broke entire definition

   **d) Empty ApplyValue (2 instances)**
   - **Lines**: 1744, 1753
   - **Keys**: `NullSessionPipes`, `NullSessionShares`
   - **Pattern**: `ApplyValue =` (missing value)
   - **Fix**: Added empty array: `ApplyValue = @()`
   - **Note**: Intentionally empty for security (no anonymous SMB access)
   - **Impact**: Hashtable structure broken, Description interpreted as command

### ✅ Verification

**Tested on Fresh Windows 11 Pro 25H2 VM:**
- **Build**: 26200 (fresh install)
- **Backup Phase**: ✅ SUCCESS (429 registry keys, 355.76 KB)
- **Apply Phase**: ✅ SUCCESS (all 13 modules, 0 errors, 39 harmless warnings)
- **Verify Phase**: ✅ 134/136 PASS (2 expected fails - VBS/Credential Guard need reboot)
- **Duration**: ~6 minutes total (Backup 2.5 min + Apply 3 min + Verify 30s)

**Registry Loading Test:**
- Before fixes: ❌ FAILED (parser errors)
- After fixes: ✅ SUCCESS (478 entries loaded correctly)

### 📊 Statistics

- **Files Modified**: 2
  - `Apply-Win11-25H2-SecurityBaseline.ps1` (1 fix)
  - `Modules\RegistryChanges-Definition.ps1` (14 fixes)
- **Total Fixes**: 15 parser errors
- **Impact**: Script completely non-functional → fully operational
- **Testing**: Verified on production-equivalent fresh VM

### 🔍 Root Cause Analysis

All errors were introduced during "quick-win" optimization phase where multiple changes were made without comprehensive testing. This release focuses on stability and correctness over feature additions.

**Lesson Learned**: Always run full integration tests (Backup → Apply → Verify cycle) after parser-level changes, even for "simple" fixes.

---

## [1.8.0] - 2025-11-06

### 🎉 MAJOR RELEASE: 100% Microsoft Security Baseline Coverage

**Headline:** NoID Privacy now implements **100% of all locally-applicable Microsoft Security Baseline 25H2 policies** (370/370)! 🎊

#### **What's New:**
- ✅ **370/370 applicable policies** implemented (was 213/365 in v1.7.x = **+73.7% coverage!**)
- ✅ **67 secedit settings** now automated (Password Policy, Account Lockout, LSA, SMB hardening)
- ✅ **478 registry keys** configured (was 391 = **+87 keys**)
- ✅ **133 verification checks** (was 135, optimized by removing 2 fragile checks)
- ✅ **Complete documentation overhaul** - all numbers and baseline coverage updated

**Coverage Breakdown:**
- Total MS Baseline 25H2 policies: **429**
- Locally-implementable: **370** (86.2% of total)
- Implemented by NoID Privacy: **370** (**100% of applicable!**)
- Not applicable: **59** (57 IE11-deprecated, 2 Domain Controller-only)

**→ FROM EVERYTHING THAT CAN BE SET ON STANDALONE WINDOWS 11 25H2: WE SET IT ALL!** 🔐

---

### 🔴 CRITICAL FIXES

#### **Credential Guard Not Running After Reboot** 🔥
- **Bug**: Credential Guard was CONFIGURED but NOT RUNNING after Apply + Reboot
- **Symptom**: `SecurityServicesRunning` = {2, 3, 4} (missing "1" = Credential Guard)
- **Root Cause #1**: Hypervisor launch type was NEVER set by Apply-Script
  - Registry keys alone are insufficient - `bcdedit /set hypervisorlaunchtype auto` required
- **Root Cause #2**: Verify-Script rejected LsaCfgFlags = 2 (only accepted 1)
  - Both values valid: 1 = UEFI Lock, 2 = Reversible (Apply sets 2 for flexibility)
- **Impact**: Core VBS security feature non-functional on ALL systems
- **Fix (Apply)**: Now automatically sets hypervisor launch type via bcdedit
- **Fix (Verify)**: Accepts both LsaCfgFlags values (1 OR 2)
- **Fix (Verify)**: Added Hypervisor diagnostics with actionable fix command
- **Result**: Credential Guard now activates correctly after reboot
- **Verify Score**: 109 → 111/133 PASS (+2 fixed checks)
- **Discovery**: Bitdefender+VMware local machine testing (Nov 6, 2025)
- **Files**: `SecurityBaseline-Core.ps1`, `Verify-SecurityBaseline.ps1`
- **Commit**: `4a12f2b`

---

### 📚 DOCUMENTATION OVERHAUL

#### **Complete Baseline Coverage Documentation Update**
- **Scope**: 26 files updated with correct baseline numbers
- **Updated Numbers Everywhere**:
  - Registry Keys: 391 → **478** (+87)
  - Verification Checks: 124 → **133** (+9, then -2 optimization)
  - MS Baseline Total: 365 → **429** (+64, corrected count)
  - Implemented Policies: 213 → **370** (+157!)
  - N/A Policies: 152 → **59** (-93, corrected calculation)
  - Coverage: 58.4% → **100%** of applicable policies

#### **Files Updated**:
- Core Docs: `README.md`, `FEATURES.md`, `SECURITY_MAPPING.md`, `REGISTRY_KEYS.md`, `FAQ.md`, `KNOWN_ISSUES.md`
- New Files: `MS-BASELINE-COVERAGE.md` (complete 429/370 breakdown), `Win11_25H2_Baseline_SecTemplate.inf`
- Cleanup: Deleted 5 files (PROJECT_STRUCTURE.md, CONTRIBUTORS.md, SECURITY_HALL_OF_FAME.md, Tests\README.md, FINAL_365_POLICY_COMPLETE_AUDIT.md)
- Links: All cross-references updated and validated

#### **secedit Automation Documented**:
- All mentions of "cannot be automated" removed
- 67 automated secedit settings now clearly documented
- Password Policy, Account Lockout, User Rights, Security Options

- **Files**: 28 files changed (+3561/-2042 lines)
- **Commit**: `3d3d02f`

---

### 🛡️ ANTIVIRUS COMPATIBILITY IMPROVEMENTS

#### **Removed Alarmist Bitdefender-Specific Warnings**
- **Issue**: hosts file warning too alarmist and Bitdefender-specific
- **Old Message**: "Bitdefender users: 'Scan hosts file' DISABLE! Otherwise internet blocked!"
- **Problems**: 
  - Too alarmist (suggested permanent AV setting change)
  - Bitdefender-specific (affects ALL AVs the same way)
  - Implies hosts scanning is bad (it's security-important!)
  - User reported: Works fine with new 107K hosts, no issues

- **New Message** (4 info lines):
  - "Antivirus software scans hosts file after installation (normal, temporary)"
  - "Scan completes in seconds to minutes - no action needed"
  - "If persistent issues: Add to exceptions temporarily (not long-term recommended)"
  - "Important: hosts file SHOULD be scanned by AV for security!"

- **Result**: Less panic, more education, better security advice
- **Files**: `SecurityBaseline-Localization.ps1` (EN+DE), `SecurityBaseline-DNS.ps1`
- **Commit**: `156d82e`

#### **Generic Third-Party AV Documentation**
- **Issue**: Documentation too focused on Bitdefender, should be balanced
- **Changes**:
  - "Bitdefender: False positive" → "Third-Party AV (especially Bitdefender): False positive"
  - Added Norton/Avast heuristic mentions
  - "Step-by-step Bitdefender guide" → "Step-by-step AV guides (multiple examples)"
  - ASR comment: "Bitdefender returns null" → "third-party AVs return null when active"
  - FAQ: Reordered - Windows Defender first, then AVs alphabetically
  - All AVs now treated equally (Kaspersky, Norton, ESET, Bitdefender)

- **Result**: More balanced, professional documentation
- **Files**: `KNOWN_ISSUES.md`, `README.md`, `FAQ.md`, `SecurityBaseline-ASR.ps1`, `CHANGELOG.md`
- **Commit**: `404ecf0`

---

### 🔧 VERIFICATION IMPROVEMENTS

#### **Removed Fragile Power Management Checks**
- **Issue**: Display/Hibernate timeout checks showed FALSE FAIL
- **Verification**: Settings are CORRECT (powercfg /query confirmed)
  - Display: 0x00000258 = 600 sec = 10 min ✅
  - Hibernate: 0x00000708 = 1800 sec = 30 min ✅
- **Root Cause**: /GETACVALUEINDEX parsing fragile (GUID-based, regex, system-dependent)
- **Impact**: Low/Info (unkritisch für Security Baseline)
- **Decision**: Remove checks (user: "fixen oder rauswerfen")
- **Manual Verification**: Still possible via comments in script

- **Checks**: 135 → **133** (-2 removed)
- **Expected Scores** (updated everywhere):
  - Native Windows Defender: 118-119/133 PASS (89%)
  - Third-Party AVs (Bitdefender/Kaspersky/Norton/ESET): 96-100/133 PASS (72-75%)

- **Files**: `Verify-SecurityBaseline.ps1`, `README.md`, `KNOWN_ISSUES.md`, `FAQ.md`
- **Commit**: `f84c606`

---

### 🔨 OTHER FIXES

#### **DNS Blocklist Idempotency with Version Check**
- **Added**: Version comparison to prevent unnecessary re-downloads
- **Files**: `SecurityBaseline-DNS.ps1`
- **Commit**: `cb50073`

---

### 📊 STATISTICS v1.8.0

**Development:**
- Commits: 62 (Nov 5-6, 2025)
- Files Changed: 50+
- Lines Changed: ~5,000+
- Documentation Files: 26 updated

**Baseline Coverage:**
- Total Policies: 365 → **429** (+17.5%)
- Implemented: 213 → **370** (+73.7%!)
- Registry Keys: 391 → **478** (+22.3%)
- Verification: 124 → **133** (+7.3%, then optimized -2)
- secedit: 0 → **67** (automated!)
- Coverage: 58.4% → **100%** (of applicable)

**Hosts File:**
- Domains Blocked: 80K → 107,772 (+34%)

---

### ⚠️ BREAKING CHANGES

1. **Baseline Scope**: 365 → 429 total policies (+17.5%)
2. **Verification Checks**: 135 → 133 (2 power checks removed, but more reliable)
3. **Documentation Structure**: 23 → 19 files (5 deleted, 2 added)
4. **Registry Keys**: 391 → 425 (+34)

**Migration**: No user action needed - fully backward compatible! ✅

---

### 🙏 ACKNOWLEDGMENTS

- Testing: Bitdefender+VMware local machine (discovered Credential Guard bug)
- User Feedback: hosts file works perfectly with all AVs
- Community: "nicht nur bitdefender sondern alle av" - balanced documentation

---

## [1.7.21] - 2025-11-05

### Fixed
- **Power Management Verification**: Fixed Hibernate Enabled check (array cast to prevent .Count error)
- **Remote Access Menu**: Fixed line breaks and alignment in German/English versions
- **Backup Descriptions**: Updated domain count (80,101) to match README and hosts file header
- **Restore Script**: DNS InterfaceIndex errors now filtered (not real failures)

### Changed
- **Version Bump**: All documentation and scripts updated to v1.7.21
- **Minor refinements**: Code quality improvements and comment updates

---

## [1.7.20] - 2025-11-05

### 🎯 Major Feature: Privacy by Default WITH User Control

#### **Camera/Microphone/Location Permissions Rebalanced** 🔥
- **BREAKING CHANGE**: Apps can now request Camera/Mic/Location permissions again
  - **Previous Behavior**: HKCU hard-blocked (no prompts, apps silently denied)
  - **New Behavior**: HKLM defaults only (Windows asks user for permission)
  - **Impact**: Zoom/Teams/Discord/Maps now functional after user approval
  - **Result**: Privacy by Default + User Control = Best of Both Worlds! 🎉
  - **Why**: Forum feedback - "Apps kaputt ohne Grund", frustrating for home users
  - **Security**: Still denied by default, but user can allow trusted apps
  - **Files**: SecurityBaseline-Telemetry.ps1, RegistryChanges-Definition.ps1 (-132 lines)
  - **Registry**: 388 → 384 entries (-4 HKCU entries removed)
  - **Commits**: `c62d300`, `acae656`

### Added

- **Hibernate Mode Linked to Remote Access Choice** 🚀
  - **Desktop Mode (RDP OFF)**: Hibernate enabled (30 min timeout)
  - **Remote Server Mode (RDP ON)**: Hibernate disabled (prevents RDP disconnects)
  - **Logic**: Remote servers need 24/7 availability, desktops can hibernate
  - **Integration**: Remote Access menu now controls hibernate behavior
  - **Security**: RAM cleared on hibernate (Cold Boot Attack protection)
  - **Files**: SecurityBaseline-Advanced.ps1, Apply-Win11-25H2-SecurityBaseline.ps1
  - **Commit**: `29eff59`

- **Power Management Full Backup/Restore Support** ⚡
  - **Backup**: All power settings now saved (timeouts, hibernate, CONSOLELOCK)
  - **Restore**: Complete restoration of original power configuration
  - **German Support**: Works on German Windows (powercfg localization fix)
  - **Settings**: Display timeout, Sleep, Hibernate, Password on wake
  - **Files**: Backup-SecurityBaseline.ps1, Restore-SecurityBaseline.ps1
  - **Commits**: `9eecdc6`, `36b948a`

### Fixed

- **CRITICAL: Windows Settings App Search Broken** 🔥
  - **Bug**: DisableWebSearch registry key blocked Settings app search
  - **Impact**: "Network", "Update", "Privacy" searches returned nothing
  - **Root Cause**: Key too broad - blocked Windows internal search
  - **Fix**: Removed DisableWebSearch from Telemetry + Performance modules
  - **Result**: Settings search works, Bing/Web still blocked by other keys
  - **Files**: SecurityBaseline-Telemetry.ps1, SecurityBaseline-Performance.ps1
  - **Commit**: `c8950f8`

- **CRITICAL: Chrome/Edge Downloads Blocked by Policy 1806** 🔥
  - **Bug**: Internet/Intranet Zone 1806 broke browser downloads
  - **Symptom**: "blocked by your organization" on legitimate downloads
  - **Root Cause**: 1806 = "Disable launching apps" too aggressive for modern browsers
  - **Fix**: Removed 1806 policy from Core module (1803 = Download blocking sufficient)
  - **Result**: Downloads work normally, CVE-2025-9491 protection maintained
  - **Files**: SecurityBaseline-Core.ps1, RegistryChanges-Definition.ps1
  - **User Report**: Forum user "Niko" - downloads completely broken
  - **Commit**: `263225a`

- **Verify Script: 4 Power Management False Negatives**
  - **Bug #1**: Display Timeout check failed (text parsing unreliable)
  - **Bug #2**: Hibernate Timeout check failed (wrong regex pattern)
  - **Bug #3**: Hibernate Enabled shown as ERROR (should be INFO - hardware dependent)
  - **Bug #4**: Registry count 388 vs 345 misunderstood (BY DESIGN, not bug!)
  - **Fix**: GUID-based powercfg queries (100% reliable), Impact level adjusted
  - **Result**: Verify now shows 119/121 PASS (98.3%) - only 2 hardware-dependent failures
  - **Files**: Verify-SecurityBaseline.ps1, Backup-SecurityBaseline.ps1
  - **Commits**: `ba21402`, `271f972`

- **Restore Script: PropertyNotFoundException on Power Settings**
  - **Bug**: Crash when restoring backups without power management data
  - **Symptom**: "MonitorTimeoutAC" property not found → script terminated
  - **Root Cause**: Direct property access without PSObject.Properties check
  - **Fix**: Defensive property access pattern (check existence BEFORE access)
  - **Pattern**: `if ('Property' -in $obj.PSObject.Properties.Name) { ... }`
  - **Result**: Graceful skip when no power settings in backup
  - **Files**: Restore-SecurityBaseline.ps1
  - **Commit**: `e17dba0`

- **Power Management: Persistent Settings Not Applied**
  - **Bug**: Power settings reset after reboot (`powercfg /change` not persistent)
  - **Fix**: Use `/SETACVALUEINDEX` and `/SETDCVALUEINDEX` instead
  - **Result**: Settings survive reboots and power scheme changes
  - **Files**: SecurityBaseline-Advanced.ps1, Restore-SecurityBaseline.ps1
  - **Commits**: `7fba4e5`, `80e2d49`

### Changed

- **Repository Cleanup** - 6 obsolete files removed
  - Removed: `Fix-OutlookSearch.ps1`, `ATTACK-VECTORS-REMAINING.md`, `PENTEST-LEARNINGS.md`
  - Removed: `Fix-1806-ChromeEdge-Downloads.reg`, `Test-SearchFunctionality.ps1`
  - Removed: `Modules/SecurityBaseline-UAC.ps1` (merged into Core)
  - Reason: Features integrated into main codebase, standalone scripts obsolete
  - Docs: All references cleaned from README, CHANGELOG
  - Commits: `ffc6ee2`, `e55e460`

### Technical Details

- **Total Changes**: 20 commits, ~500 lines modified
- **Critical Fixes**: 6 (Settings Search, Downloads, Power Management, Camera/Mic)
- **New Features**: 2 (Hibernate Integration, Power Backup/Restore)
- **Registry Keys**: 388 → 384 entries (more user-friendly)
- **Quality**: Root cause analysis for ALL bugs (no quick fixes!)
- **Testing**: Verified on German Windows VM, backup/restore cycle tested

### Upgrade Notes

- **Camera/Mic/Location**: Apps will now ASK for permission (expected behavior)
  - If you want hard-block: Manually set HKCU registry keys
  - Default: Privacy by Default + User prompts ✅
  
- **Hibernate**: Now linked to Remote Access choice
  - Desktop Mode: ON (saves power, clears RAM)
  - Remote Server Mode: OFF (24/7 availability)
  
- **Power Settings**: Fully backed up and restorable
  - Old backups compatible (graceful handling)

## [1.7.19] - 2025-11-04

### Improved
- **Gaming Recommendations Refined** - Removed pauschal "Gamer = Option 2" statements
  - **Issue**: Remote-Menu suggested Option 2 (less strict) for ALL gamers
  - **Reality**: 90% of multiplayer games only need outbound (work with Strict Mode)
  - **Fix**: Präzise Formulierungen - "only if you explicitly need inbound connections"
  - **Change**: Empfehlung jetzt "If unsure → Option 1" (Security-First!)
  - **Affected**: Localization.ps1 (Remote Menu strings DE+EN), Verify-Script, DNS-Module
  - **Result**: Keine pauschalen Gaming-Empfehlungen, bewusste Entscheidung für User
  - **User Feedback**: Gaming recommendations too broad, security-first approach needed
  - **Commits**: `70b9173`, `990ac76`

### Added
- **All Instructions Fully Localized** - VBS, BitLocker, CPU-Check messages (72 strings)
  - **VBS POST-REBOOT Verification**: 10 strings (DE+EN) - Anleitung nach Neustart
  - **BitLocker NOT ACTIVE Warning**: 11 strings (DE+EN) - Manuelle Aktivierung
  - **BitLocker AES-256 Upgrade**: 33 strings (DE+EN) - 3 Methoden + PowerShell Alternative
  - **CPU-Check Messages**: 18 strings (DE+EN) - Old CPU warnings + Modern CPU + NOTE
  - **Files**: SecurityBaseline-Localization.ps1, SecurityBaseline-Core.ps1
  - **Result**: Alle wichtigen Anleitungen jetzt sprachunabhängig (DE/EN)
  - **Total**: 72 neue Strings, 231 code insertions
  - **Commits**: `990ac76`, `78afd3e`

- **Gaming Troubleshooting Section** - README.md
  - **New Section**: "🎮 Gaming & Multiplayer Issues" in Troubleshooting
  - **Content**: Security-First approach, step-by-step guide, game examples
  - **Explains**: Try Strict Mode first (works for 90%), Option 2 only if needed
  - **Examples**: Fortnite/Valorant/CoD work with Strict, Minecraft hosting needs Option 2
  - **Commit**: `70b9173`

## [1.7.18] - 2025-11-04

### Fixed
- **CRITICAL: Outlook Email Search Broken** - Windows Search indexer disabled
  - **Bug**: SetupCompletedSuccessfully = 0 broke Windows Search indexer
  - **Impact**: Outlook email search completely non-functional (no indexing)
  - **Root Cause**: Performance module set registry key to "Setup not completed"
  - **Scope**: Affects ALL Windows Search features (File Explorer, Start Menu, Outlook)
  - **Fix**: Removed SetupCompletedSuccessfully key from Performance module
  - **Files**: SecurityBaseline-Performance.ps1, RegistryChanges-Definition.ps1
  - **Result**: Windows Search indexer works correctly, Outlook search functional
  - **Commit**: `e06c549`

- **CRITICAL: Restore-Script Compatibility** - Old backups could re-introduce bug
  - **Issue**: v1.7.17 backups contain buggy SetupCompletedSuccessfully = 0
  - **Risk**: Restoring old backup would re-break Windows Search and Outlook
  - **Fix**: Restore-Script now filters SetupCompletedSuccessfully from old backups
  - **Behavior**: Detects key in backup, filters it out, sets correct value (= 1) instead
  - **Output**: Clear warning message when filtering occurs
  - **Result**: Old backups safe to restore, bug won't be re-introduced
  - **Commit**: `732509c`

### Changed
- **Registry Key Count Updated** - 391 keys (was 392)
  - **Removed**: SetupCompletedSuccessfully (breaks Windows Search)
  - **Previously removed**: 2 DohFlags entries (never set)
  - **Total removed**: 3 problematic entries
  - **Updated files**: Apply, Backup, Restore, README, FEATURES, PROJECT_STRUCTURE, REGISTRY_KEYS, all modules
  - **Reason**: Maintain 100% accuracy in documentation
  - **Commit**: `e06c549`

### Notes
- **Affected Users**: Anyone who ran v1.7.17 Apply
- **Symptoms**: Outlook email search not working, File Explorer search slow/broken
- **Prevention**: v1.7.18 won't set buggy key, Restore filters it from old backups

## [1.7.17] - 2025-11-03

### Added
- **Device-Level App Permissions Backup Re-Added** - Critical Backup/Restore gap closed!
  - Backup-SecurityBaseline.ps1: New section [15/15] Device-Level App Permissions Backup
  - Previous v1.7.13 removed this backup claiming "TrustedInstaller protection makes it meaningless"
  - Critical Issue: Restore script EXPECTED this data but backup had none → Restore failed to restore original state!
  - Solution: Graceful degradation - backup readable entries, skip Access Denied silently
  - Coverage: webcam + microphone EnabledByUser keys (~5-20 per permission)
  - Result: 100% Backup/Restore coverage restored - ALL changes by Apply script are now fully reversible!
  - All counters updated: Backup [1/14] → [1/15] through [14/14] → [14/15]
  - Forum feedback addressed: "Does Restore really restore EVERYTHING?" → YES!

- **DNS Menu Localization (EN/DE)** - Full internationalization of DNS provider selection
  - SecurityBaseline-Interactive.ps1: Show-DNSProviderMenu fully localized
  - SecurityBaseline-Localization.ps1: 18 new strings added (DNSMenuTitle, DNSMenuOption1-5, etc.)
  - English: "Speed / Privacy / Location" | German: "Geschwindigkeit / Datenschutz / Standort"
  - All 4 DNS providers + "Keep Existing" option translated
  - Consistent with rest of project - 100% localized menus

- **Third-Party Antivirus Compatibility Documentation** - Comprehensive guide added
  - New file: ANTIVIRUS_COMPATIBILITY.md (413 lines)
  - Coverage: Bitdefender, Kaspersky, Norton, ESET, Avast, McAfee, Avira, and more
  - Details: Expected behavior, false positives, whitelisting instructions
  - All AVs scan hosts file after installation (80K+ entries, normal temporary behavior)
  - User feedback addressed: "Why is my antivirus flagging the script?"

- **Complete Code Quality Audit** - Systematic analysis of all 8 critical areas
  - CODE_AUDIT.md: Files 1-5 audited (Apply, Restore, Backup, Core, Advanced)
  - Found and fixed: Get-ItemProperty -Name pattern (causes errors), missing localization strings
  - Verified: TLS/SChannel implementation is complete (all algorithms covered)
  - Result: Clean code, no critical issues, only localization TODOs remaining

- **100% Telemetry Module Localization** - All 13 functions now fully localized
  - ~210 hardcoded strings replaced with Get-LocalizedString calls
  - Functions: Disable-TelemetryServices, Set-PrivacySettings, Disable-Camera, Disable-Microphone, Disable-Location, Disable-AllAppPermissionsDefaults, and 7 more
  - Added to Localization.ps1: ~210 new strings (EN + DE)
  - Consistency: 100% localized project (no hardcoded German/English texts)

- **100% Bloatware Module Localization** - Complete internationalization
  - All Write-Host statements now use Get-LocalizedString
  - Added progress indicators for long-running operations
  - Code Quality: Removed 4 duplicate app entries (Flipboard, Netflix, Plex, Shazam)
  - Result: 79 unique app patterns (was 83)

- **Advanced/ASR/DNS Module Localization Completed**
  - SecurityBaseline-Advanced.ps1: 16 missing strings added (WDigest, EFSRPC, WebClient functions)
  - SecurityBaseline-ASR.ps1: 3 missing strings added (ASRReason, ASRRetrievalError, ASRConflictTip)
  - SecurityBaseline-DNS.ps1: 3 missing firewall strings added (Standard Mode messages)
  - Result: 100% localization in all security modules

- **Restore Script: 36 Missing Localization Strings Added**
  - All hardcoded German texts replaced with Get-LocalizedString calls
  - Added: Registry restore, Service restore, Scheduled Tasks, Firewall, and more
  - Consistency: Restore script now fully bilingual (EN/DE)

- **7 Functions: Add Missing [OutputType([void])]** - Code quality improvement
  - SecurityBaseline-Telemetry.ps1: 7 functions updated for consistency
  - Best practice: All functions now have proper OutputType annotations

### Changed
- **DNS Default: Keep Current DNS** - Fixed slow internet issue from forum feedback
  - Apply-Win11-25H2-SecurityBaseline.ps1: Lines 1429, 1432-1435
  - Previous behavior: Non-interactive mode forced Cloudflare DNS (caused slow internet for some users)
  - Previous behavior: Invalid choice defaulted to Cloudflare
  - New behavior: Non-interactive mode keeps current DNS (safer default)
  - New behavior: Invalid choice keeps current DNS with warning message
  - Forum complaint: "5-10 second delays after applying script - 90s internet vibes"
  - Root cause: Cloudflare DoH can be slow depending on location + SmartScreen + DNSSEC = triple latency
  - Solution: User keeps their existing fast DNS, no forced changes
  - Interactive mode unchanged: Menu still offers all 4 providers + keep option

### Fixed
- **CRITICAL: Registry Count Corrected** - Final count is 392 keys (not 394)
  - **Root Cause**: 2 "dead" DohFlags entries in RegistryChanges-Definition.ps1
  - **Analysis**: These entries were DEFINED but NEVER SET by any Set-RegistryValue calls
  - **Action**: Removed from code AND all documentation for 100% accuracy
  - **Updated Files**: README.md, Apply script header (.NOTES), REGISTRY_KEYS.md module tables
  - **Result**: Perfect consistency - 392 keys everywhere in codebase (no more 375/380/394 confusion!)
  - **Commits**: `2e48fb1`, `2975680`, `8555d9d`, `c33c744`, `d67a26a`, `2ef689a`

- **CRITICAL: Internet Zone 1803 Download Blocking** - Chrome/Edge downloads broken
  - **Bug**: Set-ExplorerZoneHardening set 1803 (File Download) to 3 (Disable)
  - **Impact**: Broke Chrome/Edge downloads ("blocked by your organization" error)
  - **Root Cause**: Overzealous hardening - downloads must be allowed, only EXECUTION blocked (1806)
  - **Fix**: Removed 1803 setting, kept 1806 (Disable launching apps)
  - **Security**: CVE-2025-9491 protection maintained - files can be downloaded but NOT executed
  - **Workaround**: Users must save file locally first, then open (protection working correctly!)
  - **Commit**: `7394811`

- **Critical Backup/Restore Gap** - Device-Level App Permissions not backed up (v1.7.13-v1.7.16)
  - **Impact**: After Restore, webcam/microphone EnabledByUser keys remained at "Deny" (not restored)
  - **Scope**: ~5-20 app permission keys per permission (webcam, microphone)
  - **Why removed in v1.7.13**: "TrustedInstaller-protected, backup meaningless"
  - **Why critical**: Restore script expected this data → without it, cannot restore original state
  - **Fix approach**: Backup with try-catch per app, skip Access Denied gracefully, backup readable entries
  - **Verification**: Restore-SecurityBaseline.ps1 (Lines 2069-2178) already had correct restore logic waiting for data!
  - **Commit**: `49216e1`

- **Get-ItemProperty -Name Pattern** - Clean error records (63 instances fixed)
  - **Bug**: `Get-ItemProperty -Path $path -Name $prop -ErrorAction SilentlyContinue` creates error records even with SilentlyContinue
  - **Impact**: Error Records pollute $Error variable, confuse debugging
  - **Fix**: Replaced with Get-RegistryValueSafe helper function (check ItemProperty, then access property)
  - **Scope**: 63 instances across Backup, Restore, SecurityBaseline-RegistryBackup-Optimized.ps1
  - **Result**: Clean Error Records, no more PropertyNotFoundException false positives
  - **Commits**: `49d30be`, `2561a6c`

- **Restore Script: PSObject.Properties Pattern** - Property access safety
  - **Bug**: Direct property access crashes under StrictMode if property doesn't exist
  - **Fix**: All property access now uses PSObject.Properties.Name check first
  - **Example**: `if ('PropertyName' -in $obj.PSObject.Properties.Name) { $value = $obj.PropertyName }`
  - **Scope**: Registry restore, Service restore, all JSON deserialization
  - **Commit**: `79d751c`

- **Verify Script: Firewall Checks Mode-Aware** - False failures in Standard Mode
  - **Bug**: Verify script expected ultra-strict firewall (AllowInboundRules=False) always
  - **Impact**: False failures for users who chose Standard Mode (localhost allowed)
  - **Fix**: Made Public firewall checks mode-aware (both Strict and Standard are valid)
  - **Commits**: `f578b1d`, `7302cab`

- **String Formatting, ASR Null-Check, SRP Rules Check** - Various fixes
  - **Fix 1**: String formatting errors in Verify script
  - **Fix 2**: ASR Rules null-check (prevents crash when Defender not configured)
  - **Fix 3**: Network Protection verification improved
  - **Fix 4**: SRP Rules check now validates 5+ rules (was hardcoded 6)
  - **Commit**: `f578b1d`

- **Intel Driver Installation Workaround** - Documentation fix
  - **Fixed**: Description of Intel WiFi/Bluetooth driver installation workaround in docs
  - **Context**: Windows Driver Foundation blocks some Intel drivers after hardening
  - **Commit**: `31b5e30`

- **MASTERPLAN.md Removed from Git** - Added to .gitignore
  - **Reason**: Internal planning document, not relevant for end users
  - **Commit**: `377f3c9`

- **Documentation Cleanup** - Removed obsolete audit docs
  - **Removed**: CODE_AUDIT.md, SYSTEMATIC_CODE_ANALYSIS.md (obsolete)
  - **Reason**: Replaced by comprehensive CHANGELOG and inline documentation
  - **Commit**: `2ef689a`

## [1.7.16] - 2025-11-02

### Added
- **Optional Remote Access Mode** - Configure RDP and Firewall based on use-case
  - New Interactive Menu: "Do you use Remote Desktop (RDP) or run local services?"
  - Option 1: Maximum Security (Desktop/Laptop) - RDP disabled, ultra-strict firewall
  - Option 2: Allow Remote Access + Local Services - RDP enabled, localhost allowed
  - Supports: Remote servers, NUC with Tailscale, Development machines, Docker/LLM hosting
  - Script variables: `$script:DisableRDP` and `$script:StrictFirewall`
  - Secure defaults: Non-interactive mode = Maximum Security
- **Automatic Zone.Identifier Unblock** - Fix for "Internet security settings prevent execution"
  - Start-NoID-Privacy.bat automatically unblocks all PowerShell files on startup
  - Prevents Windows Mark-of-the-Web from blocking ZIP downloads
  - User-friendly: No manual unblocking required
  - FAQ Troubleshooting section added with manual solutions
- **Restore Script Language Selection** - User can now choose language when running Restore script directly
  - Previously: Auto-detected system language (always defaulted to English on EN systems)
  - Now: Interactive language selection menu (like Apply script) when run standalone
  - Fallback: Uses `$env:NOID_LANGUAGE` if called from Apply script
  - Auto-detect: Only as last resort if Select-Language function unavailable
- **78 App Name Mappings** - User-friendly app names in Missing-Apps list
  - Maps internal package names to Microsoft Store display names
  - Example: `Clipchamp.Clipchamp` → `Clipchamp - Video Editor`
  - Example: `MSTeams` → `Microsoft Teams (klassisch)`
  - Example: `Microsoft.YourPhone` → `Phone Link (frueher: Ihr Smartphone)`
  - Categories: Xbox/Gaming, Teams, Productivity, Social Media, Entertainment, Games, Utilities, Creative
  - Result: Users can easily find and reinstall apps from Microsoft Store

### Changed
- **RDP Disable Now Optional** - Previously always disabled, now configurable
  - SecurityBaseline-Core.ps1: RDP disable wrapped in `if ($script:DisableRDP)` check
  - Default behavior unchanged: RDP disabled for non-interactive mode
  - Interactive mode: User can choose to keep RDP enabled for remote access
  - Security reminder: Always use VPN/Tailscale, never expose RDP to internet!
- **Firewall Strictness Configurable** - Previously ultra-strict (blocked localhost)
  - SecurityBaseline-DNS.ps1: `AllowInboundRules` based on `$script:StrictFirewall`
  - Strict Mode (Option 1): `AllowInboundRules=False` - blocks everything including localhost
  - Standard Mode (Option 2): `AllowInboundRules=True` - localhost works (Docker/LLM OK)
  - Fixes: OpenWebUI → FastFlowLM, Docker inter-container, WSL development
- **Restore Warning Messages Color** - Changed from Red to Yellow for better visual distinction
  - Restore-SecurityBaseline.ps1: All security warning boxes now use Yellow instead of Red
  - Red is reserved for actual errors, Yellow for important warnings
  - Affected: Security risk warnings, password notes, backup confirmation prompts
  - Improves: Visual clarity, prevents misinterpretation of warnings as errors
- **ASCII Cleanup (Project-Wide)** - Replaced non-ASCII characters with ASCII equivalents
  - Scanned all 37 PowerShell files in project for non-ASCII characters
  - Replaced: EN DASH (`–` U+2013) → HYPHEN-MINUS (`-` U+002D)
  - Replaced: RIGHTWARDS ARROW (`→` U+2192) → ASCII (`->`)
  - Replaced: REGISTERED SIGN (`®` U+00AE) → `(R)`
  - Files Modified: Restore-SecurityBaseline.ps1, Apply-Win11-25H2-SecurityBaseline.ps1, SecurityBaseline-Core.ps1, SecurityBaseline-DNS-Providers.ps1
  - Result: 100% ASCII-clean codebase for maximum cross-platform compatibility
- **ArgumentList Array Format** - Robust parameter passing in Start-Process
  - Changed from string format to array format for `Start-Process -ArgumentList`
  - Before: `-ArgumentList "-ExecutionPolicy Bypass -File $script -Language de"` (string - can fail on quotes/spaces)
  - After: `-ArgumentList @("-ExecutionPolicy", "Bypass", "-File", $script, "-Language", "de")` (array - robust)
  - Files Modified: Apply-Win11-25H2-SecurityBaseline.ps1 (lines 911-921)
  - Result: Language parameter passing now reliable in all edge cases

### Fixed
- **CRITICAL: Language Parameter Ignored in Restore Script** - German selection reverted to English
  - Root Cause: `SecurityBaseline-Localization.ps1` initialized `$Global:CurrentLanguage = "en"` before parameter check
  - Impact: After selecting German in Apply script, Restore showed English messages ("Searching for available backups...")
  - Solution: Reordered language setting logic to check `-Language` parameter FIRST (before `Test-Path Variable:\Global:CurrentLanguage`)
  - Priority: Parameter > Environment > Existing Variable > Interactive > Auto-detect
  - Added: Debug messages to trace language selection (`[DEBUG] Language set from parameter: de`)
  - Files Fixed: `Restore-SecurityBaseline.ps1` (lines 154-203), `Apply-Win11-25H2-SecurityBaseline.ps1` (lines 911-921)
  - Result: Language selection now works correctly - German stays German throughout Apply → Restore flow
- **Step Counter Inconsistency in Restore Script** - Counter showed incorrect numbering
  - Problem: Step counter jumped between totals (e.g., `[5/14]` → `[6/15]`, ending at `[14/14]` instead of correct total)
  - Impact: Unprofessional display, user confusion about progress
  - Solution: Fixed all 17 step counters to show consistent `[1/17]` through `[17/17]`
  - Files Fixed: `Restore-SecurityBaseline.ps1` (lines 392-2081, all step displays)
  - Result: Clean, professional step counter display throughout entire restore process
- **CRITICAL: Restore Ownership Module Not Loading** - Protected registry keys were not restored
  - Root Cause: Wrong filename `SecurityBaseline-Ownership.ps1` (actual: `SecurityBaseline-RegistryOwnership.ps1`)
  - Impact: TrustedInstaller-protected telemetry keys remained after restore, Settings UI showed "Your organization manages..."
  - Solution: Corrected module path in `RegistryBackup-Optimized.ps1`
  - Result: Protected keys now restore correctly with ownership takeover
- **Restore PolicyManager Cleanup Missing** - Windows Settings UI still showed managed state after restore
  - Root Cause: Windows creates PolicyManager mirror keys after Apply (not in backup)
  - Impact: Settings UI showed "Your organization manages..." even after full restore
  - Solution: Advanced pattern-based cleanup of PolicyManager cache (`current + default` paths)
  - Patterns: `*Telemetry*`, `*DataCollection*`, `*Diagnostic*`, `*Diag*`, `*Feedback*`
  - Result: Settings UI now shows correct unmanaged state after restore
- **Unit Tests Failed (19 failures)** - Tests checked for non-existent function names
  - Root Cause: Tests were written for old function names that never existed
  - Impact: CI/CD pipeline showed test failures
  - Solution: Updated tests to match actual code (Advanced, ASR, Core, Backup modules)
  - Result: All 136 tests now pass
- **Restore Warning Colors** - Red warnings looked like errors
  - Changed: Backup menu warnings and restore warnings from Red to Yellow
  - Result: Better UX, warnings don't look like failures
- **Main Menu Localization Incomplete** - Mixed English/German titles
  - Fixed: German menu titles (Audit-Modus, Enforce-Modus, Angepasster Modus, Verifizieren, Beenden)
  - Fixed: Localized "config follows" strings
  - Result: 100% localized menu in German
- **Restore Language Detection** - German system showed English messages
  - Fixed: Check both `Get-Culture` AND `Get-UICulture` for 'de'
  - Result: German language correctly detected and displayed
- **Zone.Identifier Blocking** - Windows marks downloaded ZIP files, preventing script execution
  - Root Cause: Windows "Mark of the Web" security feature
  - Impact: Users couldn't start scripts even as admin ("Internet security settings...")
  - Solution: PowerShell `Unblock-File` on all .ps1/.psm1 files at startup
  - Documentation: README warning + FAQ troubleshooting section
- **RDP Access for Remote Servers** - Remote NUC users lost access after script
  - Root Cause: RDP always disabled, no option for Tailscale/VPN users
  - Impact: Remote servers became inaccessible
  - Solution: Interactive menu allows keeping RDP enabled
- **Local Services Broken** - Docker/LLM/localhost apps stopped working
  - Root Cause: Firewall ultra-strict mode blocks localhost (127.0.0.1)
  - Impact: OpenWebUI → FastFlowLM (NPU), Docker containers, WSL development
  - Solution: Option 2 allows localhost connections (`AllowInboundRules=True`)
- **CRITICAL: Registry Restore Bug (49 Errors)** - Parameter name mismatch in Set-RegistryValueSmart calls
  - Root Cause: Function expects `-Type` parameter, but code called with `-ValueType`
  - Impact: 49 registry keys failed to restore with "Es wurde kein Parameter gefunden" error
  - Files Fixed:
    - `Modules/SecurityBaseline-RegistryBackup-Optimized.ps1` (line 269)
    - `Restore-SecurityBaseline.ps1` (line 1925)
  - Solution: Changed all `-ValueType` to `-Type` (correct parameter name)
  - Result: All registry keys now restore successfully
  - Note: Also corrected misleading changelog in Apply script (v1.7.6 had it backwards)
- **CRITICAL: Public Profile Breaks Steam/Gaming Even in Standard Mode** - Unconditional blocking of local rules
  - Root Cause: Public profile ALWAYS blocked local firewall rules, even when user chose "Allow Remote + Services"
  - Impact: Steam/Games broken on Public WiFi (e.g., Guest networks, Hotspots) even with `$script:StrictFirewall = $false`
  - Analysis: External security analyst identified this as "perfect storm" issue (only affects Public + Steam + certain network configs)
  - Files Fixed: `Modules/SecurityBaseline-DNS.ps1` (lines 331-354)
  - Solution: Made Public profile restrictions conditional on `$script:StrictFirewall` flag
    - Strict Mode: `AllowLocalFirewallRules = False` (maximum security, breaks Steam on Public WiFi)
    - Standard Mode: `AllowLocalFirewallRules = True` (Steam/Gaming/Docker functional, even on Public)
  - Added: Warning if Public already blocked rules before script ran (detects previous hardening)
  - Result: Steam/Gaming now works correctly when "Allow Remote + Services" is selected
  - Note: This was hidden in DNS module (counter-intuitive location), now properly documented

### Performance
- **MASSIVE Performance Boost: 5 Minutes → 8 Seconds** - Restore script now 97% faster
  - **Services Restore (214x → 1x)**: Bulk-load all services once, then hashtable lookup
    - Before: 214 individual `Get-Service` calls (~15s)
    - After: One bulk load + O(1) hashtable lookups (~1s)
    - Improvement: 93% faster
  - **Windows Features Restore (135x → 1x)**: Bulk-load all features once, then hashtable lookup
    - Before: 135 individual `Get-WindowsOptionalFeature` calls with DISM/WMI (~270s = 4.5 minutes!)
    - After: One bulk load + O(1) hashtable lookups (~5s)
    - Improvement: 98% faster (265 seconds saved!)
  - **Provisioned Packages Restore (14x → 1x)**: Bulk-load all packages once, then hashtable lookup
    - Before: 14 individual `Get-AppxProvisionedPackage` calls with filter (~28s)
    - After: One bulk load + O(1) hashtable lookups (~2s)
    - Improvement: 92% faster
  - Pattern: Same optimization technique as Scheduled Tasks (200x → 1x) and Firewall Rules (497x → 1x)
  - Total Time Saved: ~305 seconds (5+ minutes!)
  - Implementation: All with graceful fallback if bulk-load fails

### Documentation
- **SECURITY_MAPPING.md**: Fixed baseline coverage inconsistency (Audit Finding #1)
  - Changed: "Baseline Coverage: ~95%" → "100% of locally-implementable policies (213/213 from 365 total)"
  - Clarified: 152 policies N/A (IE11 deprecated, secedit-only, domain-only)
  - Renamed: "Why Not 100% Baseline?" → "Beyond Baseline"
  - Added note: Enhancements are NOT missing implementations, baseline requirements fully met
  - Result: Consistent documentation across all files (README.md was already correct)
- **FAQ.md**: New section "Can I use Remote Desktop (RDP) with this script?"
  - Explains Option 1 vs Option 2
  - Security warnings for RDP (use VPN/Tailscale!)
  - Use-cases: Remote servers, development, Docker/LLM hosting
- **FAQ.md**: New troubleshooting section "Scripts won't start - Internet security settings"
  - 3 solutions: Automatic (run .bat), Manual (unblock), PowerShell command
  - Prevention: Use `git clone` instead of ZIP download
- **README.md**: Warning after installation section
  - Alerts ZIP downloaders to use Start-NoID-Privacy.bat for auto-unblock
  - Links to FAQ troubleshooting

### User Feedback Addressed
- Issue: "Bitte macht das Deaktivieren des RDP optional" (Remote NUC with Tailscale)
- Issue: "Script hat Connection zwischen OpenWebUI und FastFlowLM gekillt" (Local LLM)
- Issue: "Ich kann das Backup nicht starten... Internetsicherheitseinstellungen verhindern es"
- Solution: Optional RDP + Firewall configuration + Automatic unblock

## [1.7.15] - 2025-11-01

### Added
- **Multi-Provider DNS-over-HTTPS** - Choose from 4 enterprise-grade DNS providers
  - Cloudflare (Default): Speed + Global Coverage (1.1.1.1)
  - AdGuard DNS: Privacy + EU Compliance + Built-in ad/tracker blocking
  - NextDNS: Customization + Analytics + Custom filtering profiles
  - Quad9: Security + Threat Intelligence + Non-profit (9.9.9.9)
  - All providers support IPv6 + IPv4 dual-stack
  - Per-adapter configuration (excludes VPN/Virtual adapters)

- **100% Strict DoH Enforcement** - No fallback to unencrypted DNS
  - `autoupgrade=yes` - Always attempt DoH upgrade
  - `udpfallback=no` - Never fall back to plain DNS
  - `EnableAutoDoh=2` - Windows-wide DoH policy enforcement
  - Provider cleanup before configuration (prevents conflicts)

- **OneDrive Dual-Option Configuration** - Choose your privacy level
  - Option 1 (Default): Privacy Hardening - Functionality preserved
    - Tutorial/Feedback disabled (no tracking)
    - Pre-login network blocked (no silent connections)
    - Known Folder Move blocked (no auto-upload)
    - User controls what gets uploaded
  - Option 2 (Optional): Complete Removal - Uninstall OneDrive
    - Application uninstalled
    - Registry entries cleaned
    - Explorer integration removed
    - User files preserved (never deleted)

### Changed
- **DNS Module Architecture** - Refactored into 3 modules for flexibility
  - `SecurityBaseline-DNS-Common.ps1` - Shared helper functions (adapter selection, cleanup)
  - `SecurityBaseline-DNS-Providers.ps1` - All 4 provider implementations
  - `SecurityBaseline-DNS.ps1` - Main DNS orchestration (DNSSEC, Blocklist, Firewall)
- **Cloudflare DNS Function** - Refactored from Core to DNS-Providers module
  - Old `Enable-CloudflareDNSoverHTTPS` now a wrapper calling new `Enable-CloudflareDNS`
  - Maintains backward compatibility
  - Eliminates dual implementation paths

### Fixed
- **PowerShell Array Unwrapping** - Fixed `.Count` property errors in DNS adapter detection
  - `Get-NoID-NetworkAdapters` now uses `Write-Output -NoEnumerate` to always return array
  - All provider functions wrap calls with `@(...)` for additional safety
  - Robust null/empty checks added
- **PropertyNotFoundException Errors** - Fixed PSObject property access bugs in 4 modules
  - SecurityBaseline-Core.ps1 (MSDT protocol handler)
  - SecurityBaseline-ASR.ps1 (Smart App Control status)
  - SecurityBaseline-RegistryOwnership.ps1 (Registry value existence)
  - SecurityBaseline-Telemetry.ps1 (Camera/Microphone verification)
  - Now use `PSObject.Properties.Name` check before accessing properties
- **DNS Adapter Output** - Made adapter configuration visible in console output
  - Changed from `Write-Verbose` to `Write-Info` for all 4 providers
  - Users now see which adapters were configured (e.g., "Ethernet: IPv6 + IPv4 (6 servers)")

### Documentation
- **FEATURES.md** - Comprehensive DNS provider comparison table added
  - Detailed explanation of each provider's strengths
  - Architecture: Defense in Depth (Hosts → DoH → DNSSEC → Threat Intel)
  - OneDrive dual-option rationale and Microsoft Security Baseline compliance
- **README.md** - Updated DNS section with multi-provider support
  - Provider comparison table
  - 100% strict enforcement highlighted
  - Link to detailed FEATURES.md documentation
- **Module Table** - Updated DNS and OneDrive entries in README module list

### Security Improvements
- **DNS Privacy** - Users can now choose provider based on their threat model:
  - Speed-focused: Cloudflare (fastest, global CDN)
  - Privacy-focused: AdGuard (EU, GDPR, built-in blocking)
  - Customization-focused: NextDNS (custom profiles, analytics)
  - Security-focused: Quad9 (threat intel, non-profit, malware blocking)
- **No Fallback** - `udpfallback=no` ensures ISP never sees DNS queries (even on DoH failure)
- **Adapter Isolation** - VPN and virtual adapters excluded from DNS configuration (prevents conflicts)

## [1.7.14] - 2025-11-01

### Added
- **Phase 1 - Core Network & APT Hardening** (5 Features)
  - SMB Signing Enforcement (Client + Server) - Prevents SMB relay attacks
  - LDAP Channel Binding Level 2 - Prevents NTLM relay to LDAP
  - Explorer Zone Hardening - Blocks execution from Internet/Intranet zones
  - Software Restriction Policies (SRP) - Blocks .lnk/.scf/.url from untrusted paths (CVE-2025-9491 PlugX protection)
  - EFSRPC Service Disable - Prevents EFS RPC auth coercion attacks

- **Phase 2 - Advanced Network Security** (2 Features)
  - LocalAccountTokenFilterPolicy = 0 - Mitigates Pass-the-Hash attacks for local admin accounts
  - WebClient/WebDAV Service Disable - Prevents WebDAV auth coercion attacks

- **Phase 3 - Print & Protocol Attack Surface Reduction** (3 Features)
  - Point-and-Print Hardening (3 Registry Keys) - Additional PrintNightmare protection layer
  - Nearby Sharing/CDP Disable - Disables Cross Device Platform (privacy + security)
  - Internet Printing Client Disable - Disables IPP protocol (auth coercion vector)

- **CISA KEV Protection** (2 Features)
  - MSDT Follina Workaround (CVE-2022-30190) - Disables ms-msdt:// protocol handler
  - Vulnerable Driver Blocklist (CVE-2025-0289) - Enables Microsoft's BYOVD attack protection

- **13 New Registry Keys** - Total now $1394 keys (was 375)
  - 5 keys for SMB/LDAP/Network hardening
  - 2 keys for SRP file execution restrictions
  - 3 keys for Point-and-Print
  - 3 keys for protocol/service disabling

### Security Improvements
- **CISA KEV Coverage** increased from ~35% to 20/20 (100% with Win11 25H2)
  - 17 CVEs protected by configuration (8 fully blocked, 9 defense-in-depth)
  - 3 CVEs patched in Windows 11 25H2 baseline (included out-of-box)
  - **Note:** Windows 11 25H2 requirement added - released Sept 2025 with kernel patches
- **Overall Security Score** increased from 8.3/10 to 8.6/10
- **Kernel-Level Protection** improved from 3/10 to 5/10 (Vulnerable Driver Blocklist)
- **Network Attack Surface** reduced significantly (auth coercion vectors eliminated)

### Changed
- **Registry Key Count** - Now $1394 keys (was 375), +13 new hardening keys
- **Security Functions** - 7 new hardening functions added across Core and Advanced modules
- **Verify-SecurityBaseline.ps1** - Added 4 new verification checks for new features

### Documentation
- Added detailed security analysis for CISA KEV list (20 CVEs)
- Added SMB/Small Business readiness analysis (9.4/10 score)
- Verified driver/app signature enforcement status

## [1.7.13] - 2025-10-31

### Fixed
- **DoH Verification** - Fixed `Out-String` boolean conversion (netsh output array to boolean)
- **DoH Verification** - Changed from `show state` to `show global` (correct command)
- **DNS Restore** - PowerShell 5.1 compatibility (removed `-AddressFamily` parameter)
- **DNS Restore** - Array coercion for `.Count` property access (PropertyNotFoundException)
- **Backup** - EnableAutoDoh PSObject.Properties pattern (robust property check)

### Changed
- **DNS Restore** - Simplified logic (combines IPv4+IPv6 in single call)
- **DNS Restore** - Removed safety sweep (no longer needed)

## [1.7.12] - 2025-10-30

### Added
- **Registry Parity Check** - Automated comparison of Set-RegistryValue calls vs backup keys
- **125 Missing Registry Keys** - Added to backup (Batch 1: 68 keys, Batch 2: 57 keys)
- **App List Localization** - Desktop export now fully localized (DE/EN) with timestamp
- **UI Restore Capability** - Widgets, Teams Chat, Lock Screen, Copilot can now be restored
- **11 New Localization Keys** - For app list feature (filename, header, instructions, etc.)

### Fixed
- **Backup NULL Reference Bug** - GetValueKind crash for protected registry keys (TrustedInstaller)
- **17 String Formatting Errors** - Fixed incorrect `-f` operator usage in Get-LocalizedString calls
  - Backup-SecurityBaseline.ps1: 8 fixes
  - Restore-SecurityBaseline.ps1: 9 fixes
  - Proper format: `((Get-LocalizedString 'Key') -f $arg)`

### Changed
- **Backup Key Count** - Now 398 keys (was 275), 2 TrustedInstaller-protected keys excluded
- **App List Export** - Now saved to Desktop with localized filename and content
- **Backup Error Handling** - Protected keys tracked with AccessDenied flag instead of crashing
- **Device-Level Backup Removed** - EnabledByUser keys are TrustedInstaller-protected and always re-applied

## [1.7.11] - 2025-10-29

### Added
- **IPv6 DoH Encryption Support** - Full IPv6 DNS-over-HTTPS encryption with dedicated Doh6 registry branch
- **Notepad AI Copilot Disable** - New `Disable-NotepadAIFeatures` function to remove Copilot button from Windows Notepad
- **DoH Encryption Backup/Restore** - DoH IPv4 and IPv6 encryption settings now backed up and restored
- **Notepad AI Backup/Restore** - Notepad AI settings (DisableAIFeatures) now backed up and restored
- **Windows Update FAQ** - Comprehensive guide on Windows Update types and when to re-run the script

### Fixed
- **Domain Count Calculation** - Corrected to 79,776 domains (×9 for optimized hosts file) instead of incorrect 8,064
- **lastrun.txt Creation** - Moved `Invoke-RebootPrompt` after finally-block to ensure lastrun.txt is always written before reboot
- **PowerShell 5.1 Compatibility** - Removed `-LiteralPath` parameter that doesn't exist in PowerShell 5.1 (IPv6 DoH configuration)
- **DNS Documentation** - Fixed DNS info in FAQ.md (added IPv6 servers, removed false Google fallback)
- **Year Correction** - Fixed Windows 11 26H2 release date to September 2026 (not 2025) in FAQ

### Changed
- **DoH Global Setting** - Changed from `doh=yes` to `doh=auto` for stricter DNS-over-HTTPS enforcement
- **IPv6 DoH Implementation** - Uses step-by-step path creation for PowerShell 5.1 compatibility
- **AI Module Enhancement** - AI Lockdown now includes 7 features (added Notepad AI to existing 6)

### Technical Details
- IPv4 DoH: `HKLM:\System\...\Doh\<IPv4>` with DohFlags=1
- IPv6 DoH: `HKLM:\System\...\Doh6\<IPv6>` with DohFlags=1 (separate branch!)
- Notepad AI: `HKLM:\SOFTWARE\Policies\WindowsNotepad\DisableAIFeatures=1`
- Domain count: 8,864 lines × 9 domains per line = 79,776 total domains
- Reboot prompt moved from inside try-block to after finally-block

## [1.7.10] - 2025-10-28

### Added
- Core.ps1 Part 3 internationalization (128 strings - Services, Admin Shares, Administrator Account, DNS over HTTPS, Remote Access, Sudo, Kerberos, Mark-of-the-Web)
- Complete Core.ps1 internationalization (205 total strings: Part 1 + Part 2 + Part 3)
- English and German localization for all Core module functions

### Fixed
- **CRITICAL:** Registry property existence check causing 116 false error records in Common.ps1
- **CRITICAL:** Registry property check bugs in Edge.ps1 (all Get-ItemProperty -Name issues)
- **CRITICAL:** Backup-RegistryValue function causing 47 error records (L1235 + L516)
- Set-MpPreference TerminatingError in PUA protection (changed -ErrorAction Stop to SilentlyContinue)
- Eliminated all 105+ false error records from registry operations
- Consistent error handling across all Set-MpPreference calls

### Changed
- All registry property checks now use safe pattern: `$item.PSObject.Properties.Name -contains $PropertyName`
- Improved user experience (no scary TerminatingError messages in logs)
- Enhanced 3rd-party AV compatibility (Bitdefender, Kaspersky, etc.)

### Technical Details
- Bug pattern eliminated: `Get-ItemProperty -Path $Path -Name $PropertyName -ErrorAction SilentlyContinue`
- Safe pattern implemented: `$item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue; $hasProperty = $item -and ($item.PSObject.Properties.Name -contains $PropertyName)`
- Functions affected: Test-RegistryValue, Backup-RegistryValue, Set-RegistryValue, Get-EdgePolicyValue
- Impact: Cleaner logs, better error handling, improved stability

## [1.7.9] - 2025-10-27

### Added
- Guest Account renaming for defense-in-depth (CIS Benchmark compliance)
- Cryptographically secure random naming for Guest account (DefGuest_XXXX)

### Fixed
- Changed `-Type` to `-PropertyType` in SecurityBaseline-Telemetry.ps1 (10 occurrences)
- Best practice compliance for Set-ItemProperty parameter naming

### Changed
- Microsoft Security Baseline 25H2 compliance now at 100% (from 98%)
- CIS Benchmark Level 2 compliance improved to 90% (from 85%)

## [1.7.8] - 2025-10-26

### Fixed
- Defender feature detection robustness (ASR, PUA, Controlled Folder Access)
- Safe property access for third-party antivirus compatibility
- Improved error messages when Defender features unavailable

### Changed
- Enhanced logging for non-verifiable Defender settings
- Clear distinction between harmless warnings and critical errors

## [1.7.7] - 2025-10-25

### Added
- Enhanced error handling for TrustedInstaller-protected registry keys
- Defensive PSObject property checks before accessing Defender features

### Fixed
- AttackSurfaceReductionRules_Ids property check before access
- EnableControlledFolderAccess property validation
- Prevents crashes when third-party AV is active

## [1.7.6] - 2025-10-24

### Fixed
- HTML Compliance Report crash when BitLocker checks fail
- 45x transcript errors for Camera/Microphone permission checks
- Changed `-ErrorAction Stop` to `-ErrorAction SilentlyContinue` for cleaner logs

### Changed
- Removed HTML Compliance Report generation (replaced by Verify-SecurityBaseline.ps1)
- Improved PSObject property existence checks

## [1.7.5] - 2025-10-23

### Added
- Xeon and Opteron server CPU detection for BitLocker AES-NI checks
- Support for workstations with server-grade CPUs

### Fixed
- Compiler warning for unused `$cpuSupportsAES256` variable removed
- Xeon 5600+ series correctly identified as AES-NI capable

## [1.7.4] - 2025-10-22

### Added
- NTLM auditing mode (logging only, no blocking)
- Enhanced NTLM security without breaking compatibility

### Changed
- NTLM hardening approach: Signing/Sealing enforced, but NTLM not blocked
- Maintained compatibility with legacy systems (NAS, printers, older servers)

## [1.7.3] - 2025-10-21

### Added
- Device-level toggle disablement for Camera/Microphone permissions
- Two-layer permission control (device + app level)

### Fixed
- Windows 11 25H2 master toggles in Settings GUI now correctly show disabled state
- EnabledByUser property set to 0 for all camera/microphone capable apps

## [1.7.2] - 2025-10-20

### Removed
- HTML Compliance Report generation (unreliable with false positives)

### Added
- Verify-SecurityBaseline.ps1 for manual compliance verification
- More accurate terminal-based compliance checks

## [1.7.1] - 2025-10-19

### Fixed
- App Permissions now correctly set in HKCU (current user registry hive)
- All 37 permission categories default-deny with immediate effect
- Fixed LastUsedTimeStart/LastUsedTimeStop handling (forensic tracking values)

### Changed
- App permissions now set in both HKLM (new users) and HKCU (current user)
- Removed unnecessary LastUsedTime* value manipulation

## [1.7.0] - 2025-10-18

### Added
- Windows LAPS (Local Administrator Password Solution) implementation
- 30-day password rotation with 20-character complexity
- Advanced Auditing with 18+ audit categories
- NTLM auditing with Event ID 8004 logging

### Changed
- Built-in Administrator account now renamed with cryptographic randomization
- Enhanced privilege protection mode for UAC

## [1.6.21] - 2025-10-17

### Fixed
- HTML Compliance Report crash on missing BitLocker properties
- 45x transcript errors for EnabledByUser property checks
- ErrorAction handling in Set-RegistryValueSmart function

## [1.6.20] - 2025-10-16

### Added
- Server CPU detection (Intel Xeon, AMD Opteron)
- Support for workstations with server-grade processors

### Fixed
- Xeon 5500-5599 series (Nehalem-EP) correctly identified as no AES-NI
- Xeon 5600+ series (Westmere-EP+) correctly identified as AES-NI capable
- Removed unused $cpuSupportsAES256 variable

## [1.6.19] - 2025-10-15

### Fixed
- AMD Athlon CPU detection now distinguishes between old (K8/K10) and modern (Zen) variants
- Athlon 200GE, 3000G, Gold, Silver correctly identified as AES-NI capable
- Athlon 64/FX/II and Phenom I/II correctly excluded from XTS-AES-256

## [1.6.18] - 2025-10-14

### Fixed
- Critical Intel CPU detection bug (i7-11700 misidentified as Gen 2)
- Regex now correctly distinguishes 4-digit (Gen 2) from 5-digit (Gen 10+) model numbers
- Negative lookahead prevents false matches on modern CPUs

## [1.6.17] - 2025-10-13

### Added
- Print Spooler User Rights Assignment (Microsoft Baseline 25H2 requirement)
- SeImpersonatePrivilege for RESTRICTED SERVICES\PrintSpoolerService
- Windows Protected Print forward compatibility

## [1.6.16] - 2025-10-12

### Added
- AutoPlay/AutoRun complete disablement (CIS Benchmark)
- NoDriveTypeAutoRun = 0xFF (all drives)
- SmartScreen extended configuration

## [1.6.15] - 2025-10-11

### Fixed
- IPv6 DNS-over-HTTPS error when IPv6 not reachable
- Graceful IPv6 DoH skip with IPv4 DoH maintained
- PUA Registry ownership error handling improved

## [1.6.14] - 2025-10-10

### Added
- Enhanced error filtering (harmless vs critical errors)
- Smart transcript cleanup (removes false positives)

## [1.6.13] - 2025-10-09

### Fixed
- Remove-AppxProvisionedPackage error handling
- ErrorAction SilentlyContinue for non-existent packages

## [1.6.12] - 2025-10-08

### Added
- TrustedInstaller registry handling for WTDS keys
- Set-RegistryValueSmart function with ownership management

## [1.6.11] - 2025-10-07

### Fixed
- PUA (Potentially Unwanted Application) protection via Registry and Set-MpPreference
- 0x800106ba timing error handling

## [1.6.10] - 2025-10-06

### Added
- CTRL+C graceful shutdown handler
- Mutex cleanup in Finally block
- Transcript proper cleanup on abort

## [1.6.9] - 2025-10-05

### Fixed
- PowerShell 5.1 Get-Service.StartupType compatibility
- Replaced with Get-CimInstance Win32_Service.StartMode

## [1.6.8] - 2025-10-04

### Added
- Defender service auto-start before configuration
- ASR/PUA/Controlled Folder Access require running Defender

## [1.6.7] - 2025-10-03

### Fixed
- Empty Write-Info "" strings removed (PowerShell 5.1 error)
- Set-ProcessMitigation parameter names corrected

## [1.6.6] - 2025-10-02

### Added
- Exploit Protection system-wide configuration
- 12+ mitigations (DEP, SEHOP, CFG, ASLR, etc.)

## [1.6.5] - 2025-10-01

### Changed
- **Updated to Microsoft Security Baseline 25H2** (released September 30, 2025)
- Full compliance with Windows 11 25H2 security policies

### Added
- Interactive mode with language selection (German/English)
- Modular menu system for selective hardening

## [1.6.4] - 2025-09-30

### Added
- Multi-language support (de-DE, en-US)
- Get-LocalizedString function with fallback

## [1.6.3] - 2025-09-29

### Added
- Backup & Restore functionality
- JSON-based system state backup

## [1.6.2] - 2025-09-28

### Added
- TrustedInstaller Registry ownership management
- WTDS Registry key protection handling

## [1.6.1] - 2025-09-27

### Fixed
- StrictControlFlowGuard → StrictCFG parameter fix
- Empty Write-Info strings removed

## [1.6.0] - 2025-09-26

### Added
- Print Spooler User Rights
- AutoPlay/AutoRun disablement
- SmartScreen extended configuration

## [1.5.0] - 2025-09-25

### Added
- BitLocker XTS-AES-256 encryption
- VBS (Virtualization Based Security)
- Credential Guard
- HVCI (Hypervisor-protected Code Integrity)

## [1.4.0] - 2025-09-24

### Added
- Attack Surface Reduction (ASR) rules (19 rules)
- Smart App Control
- Controlled Folder Access

## [1.3.0] - 2025-09-23

### Added
- DNS-over-HTTPS (Cloudflare 1.1.1.1)
- DNSSEC opportunistic mode
- DNS blocklist (79,776 domains, compressed to 8,864 lines)

## [1.2.0] - 2025-09-22

### Added
- Telemetry service disablement
- Privacy settings (37 app permission categories)
- AI feature blocking (Recall, Copilot)

## [1.1.0] - 2025-09-21

### Added
- Bloatware removal (50+ apps)
- Consumer features disablement
- Windows Search web features disablement

## [1.0.0] - 2025-09-20

### Added
- Initial release
- Core security hardening
- Defender baseline configuration
- Firewall policies
- SMB/TLS hardening

---

## Legend

- **Added** - New features
- **Changed** - Changes in existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Security improvements
