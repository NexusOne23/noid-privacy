# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

- **13 New Registry Keys** - Total now 388 keys (was 375)
  - 5 keys for SMB/LDAP/Network hardening
  - 2 keys for SRP file execution restrictions
  - 3 keys for Point-and-Print
  - 3 keys for protocol/service disabling

### Security Improvements
- **CISA KEV Coverage** increased from ~35% to 85% (17/20 CVEs protected or mitigated)
  - 8 CVEs fully protected (40%)
  - 9 CVEs defense-in-depth protected (45%)
  - 3 CVEs require Windows Updates only (15%)
- **Overall Security Score** increased from 8.3/10 to 8.6/10
- **Kernel-Level Protection** improved from 3/10 to 5/10 (Vulnerable Driver Blocklist)
- **Network Attack Surface** reduced significantly (auth coercion vectors eliminated)

### Changed
- **Registry Key Count** - Now 388 keys (was 375), +13 new hardening keys
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
