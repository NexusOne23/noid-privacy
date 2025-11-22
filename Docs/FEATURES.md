# NoID Privacy Pro - Complete Feature List

**Framework Version:** v2.1.0  
**Total Security Settings:** 583  
**Modules:** 7 (All Production-Ready)  
**Last Updated:** November 22, 2025

---

## 📊 Module Overview

| Module | Settings | Status | Description |
|--------|----------|--------|-------------|
| **SecurityBaseline** | 425 | ✅ v2.1.0 | Microsoft Security Baseline for Windows 11 v25H2 |
| **ASR** | 19 | ✅ v2.1.0 | Attack Surface Reduction rules |
| **DNS** | 5 | ✅ v2.1.0 | Secure DNS with DoH encryption |
| **Privacy** | 48 | ✅ v2.1.0 | Telemetry control, Bloatware removal, OneDrive/Store telemetry |
| **AntiAI** | 24 | ✅ v2.1.0 | Disable AI features (Recall, Copilot, etc.) |
| **EdgeHardening** | 20 | ✅ v2.1.0 | Microsoft Edge browser security |
| **AdvancedSecurity** | 42 | ✅ v2.1.0 | Advanced hardening beyond MS Baseline |
| **TOTAL** | **583** | ✅ **100%** | **Complete Framework** |

---

## 🔒 Module 1: SecurityBaseline (425 Settings)

**Description:** Complete implementation of Microsoft's official Windows 11 v25H2 Security Baseline

### Components:

#### Registry Policies (335 settings)
- Computer Configuration policies (330 settings)
- User Configuration policies (5 settings)
- Windows Defender Antivirus baseline
- Windows Firewall configuration
- BitLocker drive encryption settings
- Internet Explorer 11 security zones

#### Security Template (67 settings)
- **Password Policy:** MinimumPasswordLength (14), PasswordHistorySize (24), etc.
- **Account Lockout:** LockoutBadCount (10), LockoutDuration (10 minutes)
- **User Rights Assignment:** Administrative permissions and privileges
- **Security Options:** Network access, authentication, object access
- **Service Configuration:** Xbox services disabled for security

#### Audit Policies (23 subcategories)
- Logon/Logoff events
- Account Management
- Policy Change tracking
- Privilege Use monitoring
- System events
- Object Access auditing

### Key Features:
- ✅ VBS (Virtualization Based Security)
- ✅ Credential Guard
- ✅ System Guard Secure Launch
- ✅ Kernel CET Shadow Stacks (Win11 25H2)
- ✅ Memory Integrity (HVCI)
- ✅ Interactive BitLocker USB prompt (Home/Enterprise choice)

### Home User Adjustments:
- **BitLocker USB:** Default = 0 (Home Mode - USB works normally)
- **Password Policies:** Only affect local accounts (~5% of users)

---

## 🛡️ Module 2: ASR (19 Settings)

**Description:** All 19 Microsoft Defender Attack Surface Reduction rules

### What ASR Rules Block (and Why It's Important):

#### Email & Download Attacks
1. **Block executable content from email** - Stops malware from .exe/.dll/.ps1 email attachments
2. **Block JavaScript/VBScript from launching downloads** - Prevents drive-by downloads from malicious websites
3. **Block execution of obfuscated scripts** - Detects and blocks heavily obfuscated PowerShell/JS scripts used by malware
4. **Block untrusted/unsigned processes from USB** - Prevents USB-based malware execution (BadUSB attacks)

#### Office Exploits
5. **Block Office from creating child processes** - Stops Word/Excel macros from spawning cmd.exe/powershell.exe
6. **Block Office from creating executable content** - Prevents Office from writing .exe files to disk
7. **Block Office from injecting code into other processes** - Stops process injection attacks
8. **Block Win32 API calls from Office macros** - Prevents macros from calling dangerous Windows APIs
9. **Block Adobe Reader from creating child processes** - Same protection for PDF exploits
10. **Block Office communication apps (Outlook) child processes** - Stops email-based exploit chains

#### Credential Theft & Persistence
11. **Block credential stealing from LSASS** - Protects against Mimikatz and similar tools
12. **Block persistence through WMI** - Prevents malware from hiding in WMI event subscriptions
13. **Block process creation from PSExec/WMI** - Stops lateral movement tools (configurable: Block or Audit)

#### Ransomware Protection
14. **Use advanced ransomware protection** - AI-powered behavioral detection of ransomware
15. **Block executable files unless they meet reputation criteria** - SmartScreen integration

#### Advanced Threats
16. **Block abuse of exploited vulnerable signed drivers** - Prevents BYOVD (Bring Your Own Vulnerable Driver) attacks
17. **Block webshell creation** - Stops IIS/Apache webshell deployment (Server-focused)
18. **Block rebooting in Safe Mode** - Prevents ransomware from bypassing defenses
19. **Block use of copied/impersonated system tools** - Detects renamed legitimate tools (rundll32.exe → run.exe)

### Interactive Prompt:
- **PSExec/WMI Rule (d1e49aac):** Choose **Block** or **Audit**
  - Block: Maximum security (may break SCCM/remote admin tools)
  - Audit: Logs events only (good for enterprise compatibility testing)

---

## 🌐 Module 3: DNS (5 Settings)

**Description:** Secure DNS with DNS-over-HTTPS encryption

### Providers (3 available):

#### Cloudflare (Default)
- **IPv4:** 1.1.1.1, 1.0.0.1
- **IPv6:** 2606:4700:4700::1111, 2606:4700:4700::1001
- **DoH:** https://cloudflare-dns.com/dns-query
- **Ratings:** Speed 5/5, Privacy 5/5, Security 4/5, Filtering 2/5

#### Quad9
- **IPv4:** 9.9.9.9, 149.112.112.112
- **IPv6:** 2620:fe::fe, 2620:fe::9
- **DoH:** https://dns.quad9.net/dns-query
- **Ratings:** Speed 4/5, Privacy 5/5, Security 5/5, Filtering 4/5

#### AdGuard
- **IPv4:** 94.140.14.14, 94.140.15.15
- **IPv6:** 2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff
- **DoH:** https://dns.adguard-dns.com/dns-query
- **Ratings:** Speed 4/5, Privacy 5/5, Security 4/5, Filtering 5/5

### Features:
- ✅ **DoH Encryption with 2 Interactive Modes:**
  - **[1] REQUIRE Mode (Default):** NO unencrypted fallback (AllowFallbackToUdp = $False)
    - Best for: Home networks, single-location systems
    - Maximum security - DNS queries always encrypted
  - **[2] ALLOW Mode:** Fallback to UDP allowed (AllowFallbackToUdp = $True)
    - Best for: VPN users, mobile devices, corporate networks, captive portals
    - Balanced security - falls back to unencrypted if DoH unavailable
  - **[3] Skip:** Keep current DNS settings unchanged
- ✅ DNSSEC validation (server-side by all providers)
- ✅ DHCP-aware backup/restore
- ✅ Physical adapter auto-detection (excludes virtual/VPN adapters)
- ✅ Connectivity validation before apply

---

## 🔇 Module 4: Privacy (48 Settings)

**Description:** Windows telemetry control, OneDrive/MS Store telemetry, and bloatware removal

### What's Actually Done:
- ✅ **Windows Telemetry:** 3 modes (MSRecommended/Strict/Paranoid)
- ✅ **OneDrive Telemetry:** Feedback & sync reports disabled
- ✅ **OneDrive Sync:** Remains FUNCTIONAL (DisablePersonalSync = 0)
- ✅ **MS Store Telemetry:** AutoDownload = 3 (auto-update apps, no upgrade prompts)
- ✅ **Bloatware Removal:** 23 apps removed (policy-based on Win11 25H2+ Ent/Edu)

### Operating Modes (Interactive Selection):

#### MSRecommended (Default - Fully Supported)
- AllowTelemetry = 1 (Required)
- Services NOT disabled (policies only)
- AppPrivacy: Selective (Location/Radios Force Deny, Mic/Camera user decides)
- **Best for:** Production, business environments

#### Strict (Maximum Privacy)
- AllowTelemetry = 0 (Off)
- Services: DiagTrack + dmwappushservice disabled
- AppPrivacy: Force Deny Mic/Camera/Contacts/Calendar
- **Warning:** Breaks Teams/Zoom, Windows Update error reporting
- **Best for:** High-security, standalone systems

#### Paranoid (Hardcore - NOT Recommended)
- Everything from Strict + WerSvc disabled
- Tasks: CEIP/AppExperience/DiskDiag disabled
- **Warning:** Breaks error analysis, support severely limited
- **Best for:** Air-gapped, extreme privacy only

### Bloatware Removal (23 apps):
- BingNews, BingWeather, MicrosoftSolitaireCollection
- MicrosoftStickyNotes, GamingApp, WindowsFeedbackHub
- Xbox components (GamingOverlay, IdentityProvider, etc.)

### Protected Apps (18 kept):
- WindowsStore, WindowsCalculator, Photos, Paint
- WindowsNotepad, WindowsTerminal, WindowsCamera
- Clipchamp, Copilot, OfficeHub, Teams, etc.

### OneDrive Settings:
- Telemetry: Disabled
- Sync: Functional (not broken)
- Store: Enabled (app updates needed)

---

## 🤖 Module 5: AntiAI (24 Settings)

**Description:** Disable Windows AI features

### Features Disabled:

#### Recall (Windows 11 24H2+)
- DisableAIDataAnalysis = 1
- Snapshots disabled
- Screenshot OCR disabled

#### Copilot
- TurnOffWindowsCopilot = 1
- Taskbar button removed
- Sidebar disabled

#### Click to Do
- 3 registry keys (Phone Link integration)

#### Paint Cocreator (AI)
- ImagingDevicesCocreatorHideEntryPointsPolicy = 1

#### Notepad Cocreator (AI)
- DisableCocreator = 1

#### Settings Agent (AI recommendations)
- AllowExperimentationAndConfigurationActions = 0

#### Proactive Suggestions
- UserActivityPublishingEnabled = 0

### Impact:
- ✅ No AI data collection
- ✅ No cloud processing of local data
- ✅ Copilot completely hidden from taskbar and Start menu
- ✅ Traditional app experience restored

### ⚠️ Known Limitations:
Some UI elements in Paint and Photos apps may **still be visible** but non-functional due to lack of Microsoft-provided policies:
- **Photos:** Generative Erase button, Background Blur/Remove options
- **Paint:** Some AI feature UI elements

**Why?** Microsoft does NOT provide dedicated policies to hide these UI elements. Functionality is **blocked via systemAIModels API Master Switch** (LetAppsAccessSystemAIModels = 2), but UI removal requires Microsoft to add policies in future Windows updates.

**Result:** Buttons are visible but clicking them does nothing (API access blocked).

---

## 🌐 Module 6: EdgeHardening (20 Settings)

**Description:** Microsoft Edge v139 Security Baseline

### Core Security:
- EnhanceSecurityMode = 2 (Strict)
- SmartScreenEnabled = 1
- SmartScreenPuaEnabled = 1
- PreventSmartScreenPromptOverride = 1
- SitePerProcess = 1 (Site isolation)

### Privacy:
- TrackingPrevention = 2 (Strict)
- PersonalizationReportingEnabled = 0
- DiagnosticData = 0
- DoNotTrack = 1

### Security Mitigations:
- SSL/TLS error override blocked
- Extension blocklist (blocks all by default)
- IE Mode restrictions
- SharedArrayBuffer disabled (Spectre protection)
- Application-bound encryption enabled

### Features:
- ✅ Native PowerShell implementation (no LGPO.exe)
- ✅ AllowExtensions parameter available
- ✅ Full backup/restore support

---

## 🔐 Module 7: AdvancedSecurity (42 Settings)

**Description:** Advanced hardening beyond Microsoft Security Baseline

### Profile-Based Execution:

| Feature | Home | Enterprise | AirGapped |
|---------|------|------------|-----------|
| RDP NLA Enforcement | ✅ | ✅ | ✅ |
| WDigest Protection | ✅ | ✅ | ✅ |
| Risky Ports/Services | ✅ | ✅ | ✅ |
| Legacy TLS Disable | ✅ | ✅ | ✅ |
| WPAD Disable | ✅ | ✅ | ✅ |
| PowerShell v2 Removal | ✅ | ✅ | ✅ |
| Admin Shares Disable | ✅ | ⚠️ Domain Check | ✅ |
| RDP Complete Disable | ❌ | ❌ | ✅ Optional |
| SRP .lnk Protection | ✅ | ✅ | ✅ |
| Windows Update Config | ✅ | ✅ | ✅ |
| Finger Protocol Block | ✅ | ✅ | ✅ |

### Components:

#### 1. RDP Hardening (3 settings)
- **NLA Enforcement:** UserAuthentication = 1, SecurityLayer = 2
- **Optional Disable:** fDenyTSConnections = 1 (AirGapped profile only)
- **Protection:** Prevents RDP brute-force attacks

#### 2. WDigest Credential Protection (1 setting)
- **Registry:** UseLogonCredential = 0
- **Protection:** Prevents LSASS memory credential theft (Mimikatz)
- **Note:** Deprecated in Win11 24H2+ but kept for backwards compatibility

#### 3. Risky Ports Closure (15 firewall rules)
- **LLMNR:** Port 5355 TCP/UDP (MITM attack prevention)
- **NetBIOS:** Ports 137-138 TCP/UDP (name resolution hijacking)
- **UPnP:** Ports 1900, 2869 TCP/UDP (NAT traversal exploits)

#### 4. Risky Services (3 services)
- **SSDP Discovery:** Disabled (UPnP)
- **UPnP Device Host:** Disabled
- **TCP/IP NetBIOS Helper:** Disabled

#### 5. Administrative Shares (2 registry keys)
- **AutoShareWks = 0:** Disables C$, ADMIN$
- **AutoShareServer = 0:** Server shares
- **Domain-Aware:** Auto-skipped for domain-joined systems unless -Force

#### 6. Legacy TLS Disable (8 registry keys)
- **TLS 1.0:** Client + Server disabled
- **TLS 1.1:** Client + Server disabled
- **Protection:** BEAST, CRIME, POODLE attacks prevented

#### 7. WPAD Disable (3 registry keys)
- **User + Machine:** AutoDetect = 0
- **WinHTTP:** DisableWpad = 1
- **Protection:** Proxy hijacking attacks prevented

#### 8. PowerShell v2 Removal (1 Windows Feature)
- **Feature:** MicrosoftWindowsPowerShellV2Root
- **Protection:** Prevents downgrade attacks (bypasses logging, AMSI, CLM)

#### 9. SRP .lnk Protection - CVE-2025-9491 (2 rules)
- **Rule 1:** Block %LOCALAPPDATA%\Temp\*.lnk (Outlook attachments)
- **Rule 2:** Block %USERPROFILE%\Downloads\*.lnk (Browser downloads)
- **Protection:** Prevents zero-day LNK RCE exploitation
- **Status:** CRITICAL - Actively exploited since 2017, no patch available

#### 10. Windows Update Configuration (3 Simple GUI Settings)

**Aligns with Windows Settings GUI toggles** – NO forced schedules, NO auto-reboot, and only the documented policy keys needed to drive the visible switches

**Settings Applied:**

**1. Get Latest Updates Immediately (ON, managed by policy)**
- Registry: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
- Keys:
  - `AllowOptionalContent = 1`
  - `SetAllowOptionalContent = 1`
- Effect: Enables optional/content configuration updates so the toggle "Get the latest updates as soon as they're available" is effectively ON and enforced by policy
- GUI Path: Settings > Windows Update > Advanced options > Get the latest updates as soon as they're available (will show as managed by your organization)

**2. Microsoft Update for Other Products (ON, user-toggleable)**
- Registry: `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings`
- Key: `AllowMUUpdateService = 1`
- Effect: Get updates for Office, drivers, and other Microsoft products when updating Windows
- GUI Path: Settings > Windows Update > Advanced options > Receive updates for other Microsoft products (user can still toggle)

**3. Delivery Optimization - Downloads from Other Devices (OFF, managed by policy)**
- Registry: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization`
- Key: `DODownloadMode = 0`
- Effect: HTTP only (Microsoft servers) – no peer-to-peer, no LAN sharing
- GUI Path: Settings > Windows Update > Advanced options > Delivery Optimization > Allow downloads from other devices = OFF (managed by your organization)

**User Control & Transparency:**
- ✅ NO forced installation schedules
- ✅ NO auto-reboot policies
- ✅ Microsoft Update toggle remains user-controlled in the GUI
- ✅ Windows clearly indicates where policies manage settings ("Some settings are managed by your organization")

**Why This Approach?**
- Follows Microsoft Best Practice - matches GUI behavior
- User keeps control over installation timing
- No unexpected reboots at 3 AM
- Transparent - exactly what Windows Settings shows

#### 11. Finger Protocol Block (1 firewall rule)
- **Port:** TCP 79 outbound
- **Protection:** ClickFix malware campaign mitigation
- **Attack:** Malware uses finger.exe to retrieve commands from attacker servers
- **Impact:** Zero (Finger protocol obsolete since 1990s)

---

## 🎯 Protection Coverage

### Zero-Day Vulnerabilities:

#### CVE-2025-9491 - Windows LNK RCE ✅ MITIGATED
- **Status:** Unpatched (Microsoft: "does not meet servicing threshold")
- **Exploited Since:** 2017 by APT groups
- **Our Protection:** SRP rules block .lnk execution from Temp/Downloads
- **Why ASR Fails:** .lnk files not classified as "executable content"
- **Why SmartScreen Fails:** .lnk points to legitimate cmd.exe (trusted)

#### ClickFix Malware Campaign ✅ MITIGATED
- **Attack Vector:** finger.exe abuse to retrieve malicious commands
- **Our Protection:** Outbound TCP port 79 blocked
- **Impact:** Zero (legacy protocol unused in 2025)

### Attack Surface Reduction:

| Attack Type | Protection |
|-------------|-----------|
| **Email Malware** | ASR: Block executables from email |
| **USB Malware** | ASR: Block untrusted USB processes |
| **Office Macros** | ASR: Block Win32 API calls |
| **Credential Theft** | ASR: Block LSASS access + WDigest disabled |
| **Ransomware** | ASR: Advanced ransomware protection |
| **MITM Attacks** | DNS DoH + LLMNR/NetBIOS disabled |
| **RDP Brute-Force** | NLA enforcement + optional disable |
| **Proxy Hijacking** | WPAD disabled |
| **TLS Exploits** | TLS 1.0/1.1 disabled (BEAST/CRIME) |
| **PowerShell Downgrade** | PSv2 removed |
| **DMA Attacks** | FireWire (IEEE 1394) blocked |

---

## 📋 Interactive Features

### User Prompts:

1. **SecurityBaseline:** BitLocker USB Policy (Home/Enterprise)
   - Home Mode: USB works normally (no encryption enforcement)
   - Enterprise Mode: Require BitLocker encryption on USB drives

2. **ASR:** PSExec/WMI rule mode (Block/Audit)
   - Block: Maximum security (may break SCCM/remote admin)
   - Audit: Log only (compatibility testing)

3. **DNS:** Provider selection (Cloudflare/Quad9/AdGuard/Skip)
   - 3 DNS providers available with ratings
   - Skip option to keep current DNS

4. **DNS:** DoH Mode selection (REQUIRE/ALLOW/Skip)
   - REQUIRE: No unencrypted fallback (maximum security)
   - ALLOW: Fallback to UDP if needed (VPN/corporate/mobile)
   - Skip: Keep current DNS settings

5. **Privacy:** Mode selection (MSRecommended/Strict/Paranoid)
   - MSRecommended: Fully supported, production-safe
   - Strict: Maximum privacy (may break Teams/Zoom)
   - Paranoid: Extreme privacy (very limited support)

6. **AdvancedSecurity:** Profile selection (Home/EnterpriseConservative/AirGappedMax)
   - Home: Safe defaults for home users
   - EnterpriseConservative: Domain-aware checks
   - AirGappedMax: Maximum hardening (includes RDP disable option)

### Backup & Restore:

- ✅ Session-based backup system (Initialize-BackupSystem)
- ✅ Full registry backup before changes
- ✅ Service state backup
- ✅ Feature state backup
- ✅ DHCP settings backup (DNS module)
- ✅ Restore capability for all modules

### Verification:

- ✅ Test-BaselineCompliance (SecurityBaseline)
- ✅ Test-ASRCompliance (ASR)
- ✅ Test-DNSConnectivity (DNS)
- ✅ Test-AntiAI (AntiAI)
- ✅ Test-PrivacyCompliance (Privacy)
- ✅ Test-EdgeHardening (EdgeHardening)
- ✅ Test-AdvancedSecurity (AdvancedSecurity)

---

## 🔧 Safety Features

### Pre-Flight Checks:
- ✅ Administrator elevation required
- ✅ OS version detection (Windows 11 24H2+)
- ✅ Hardware capability detection (TPM, VBS)
- ✅ Domain-joined system detection

### Execution Safety:
- ✅ WhatIf mode (dry-run preview)
- ✅ Profile-based execution (Home/Enterprise/AirGapped)
- ✅ Incremental backups
- ✅ Error handling with graceful degradation
- ✅ Comprehensive logging

### Rollback:
- ✅ Restore-SecurityBaseline
- ✅ Restore-DNSSettings
- ✅ Restore-PrivacySettings
- ✅ Restore-AdvancedSecuritySettings

---

## 📊 Home User Friendly

### Password Policies (Low Impact):
- ✅ Only affect local accounts (~5% of home users)
- ✅ 95%+ use Microsoft Accounts (managed online by Microsoft)
- ✅ Policies: MinimumPasswordLength (14), PasswordHistory (24), Lockout (10)

### BitLocker USB (User Choice):
- ✅ Default: Home Mode (USB works normally)
- ✅ Option: Enterprise Mode (encryption enforcement)
- ✅ Interactive prompt during SecurityBaseline

### FireWire Blocking:
- ✅ Blocks IEEE 1394 devices (DMA attack prevention)
- ✅ Impact: <1% of users (obsolete technology)


---

## 🎉 Framework Status

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NOID PRIVACY PRO v2.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Settings:             583 ✅
Modules:                    7/7 (100%) ✅
Production Status:          Ready ✅
Verification:               100% ✅
BACKUP-APPLY-VERIFY-RESTORE: Complete ✅

Zero-Day Protection:        ✅ CVE-2025-9491 + ClickFix
Microsoft Best Practices:   100% ✅
Home User Friendly:         ✅ Interactive prompts
Enterprise Ready:           ✅ Profile-based execution

Framework Completion:       🎉 100% COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

**Last Updated:** November 22, 2025  
**Framework Version:** v2.1.0  
