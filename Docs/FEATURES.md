# NoID Privacy - Complete Feature List

**Framework Version:** v2.2.0  
**Total Security Settings:** 632 (Paranoid mode)  
**Modules:** 7 (All Production-Ready)  
**Last Updated:** December 8, 2025

---

## 📊 Module Overview

| Module | Settings | Status | Description |
|--------|----------|--------|-------------|
| **SecurityBaseline** | 425 | ✅ v2.2.0 | Microsoft Security Baseline for Windows 11 v25H2 |
| **ASR** | 19 | ✅ v2.2.0 | Attack Surface Reduction rules |
| **DNS** | 5 | ✅ v2.2.0 | Secure DNS with DoH encryption |
| **Privacy** | 77 | ✅ v2.2.0 | Telemetry control, OneDrive hardening (Strict: 69 Registry + 2 Services + 6 OneDrive) |
| **AntiAI** | 32 | ✅ v2.2.0 | AI lockdown (15 features, 32 compliance checks) |
| **EdgeHardening** | 24 | ✅ v2.2.0 | Microsoft Edge browser security (24 policies) |
| **AdvancedSecurity** | 50 | ✅ v2.2.0 | Advanced hardening beyond MS Baseline (incl. Wireless Display, Discovery Protocols, IPv6) |
| **TOTAL** | **632** | ✅ **100%** | **Complete Framework (Paranoid mode)** |

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

#### Quad9 (Default - Security)
- **IPv4:** 9.9.9.9, 149.112.112.112
- **IPv6:** 2620:fe::fe, 2620:fe::9
- **DoH:** https://dns.quad9.net/dns-query
- **Ratings:** Speed 4/5, Privacy 5/5, Security 5/5, Filtering 4/5
- **Best for:** Security-focused users, malware protection

#### Cloudflare (Speed)
- **IPv4:** 1.1.1.1, 1.0.0.1
- **IPv6:** 2606:4700:4700::1111, 2606:4700:4700::1001
- **DoH:** https://cloudflare-dns.com/dns-query
- **Ratings:** Speed 5/5, Privacy 4/5, Security 4/5, Filtering 2/5
- **Best for:** Speed-focused users, fastest resolver

#### AdGuard (Ad-Blocking)
- **IPv4:** 94.140.14.14, 94.140.15.15
- **IPv6:** 2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff
- **DoH:** https://dns.adguard-dns.com/dns-query
- **Ratings:** Speed 4/5, Privacy 4/5, Security 4/5, Filtering 5/5
- **Best for:** Ad/tracker blocking at DNS level

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

## 🔇 Module 4: Privacy (77 Settings)

**Description:** Windows telemetry control, OneDrive/MS Store telemetry, and bloatware removal

### What's Actually Done:
- ✅ **Windows Telemetry:** 3 modes (MSRecommended/Strict/Paranoid)
- ✅ **OneDrive Telemetry:** Feedback & sync reports disabled
- ✅ **OneDrive Sync:** Remains FUNCTIONAL (DisablePersonalSync = 0)
- ✅ **MS Store Telemetry:** AutoDownload = 3 (auto-update apps, no upgrade prompts)
- ✅ **Bloatware Removal:** 8-24 apps removed (PolicyMethod for ENT/EDU, ClassicMethod for others)

### Operating Modes (Interactive Selection):

#### MSRecommended (Default - Fully Supported)
- AllowTelemetry = 1 (Required)
- Services NOT disabled (policies only)
- AppPrivacy: Selective (Location/Radios Force Deny, Mic/Camera user decides)
- **Best for:** Production, business environments

#### Strict (Maximum Privacy)
- AllowTelemetry = 0 (Off - Enterprise/Edu only, Pro falls back)
- Services: DiagTrack + dmwappushservice disabled
- AppPrivacy: Force Deny Location/App-Diagnose/Generative AI only
- Mic/Camera: User decides (Teams/Zoom work!)
- **Best for:** Privacy-focused home users, small business

#### Paranoid (Hardcore - NOT Recommended)
- Everything from Strict + WerSvc disabled
- Tasks: CEIP/AppExperience/DiskDiag disabled
- AppPrivacy: Force Deny ALL (Mic/Camera/Contacts/Calendar)
- **WARNING:** BREAKS Teams/Zoom/Skype!
- **Best for:** Air-gapped, kiosk, extreme privacy only

### ⚠️ Windows Insider Program Compatibility

**MSRecommended mode** sets `AllowTelemetry=1` via Group Policy, which blocks Windows Insider Program enrollment. The Insider Program requires "Optional diagnostic data" (AllowTelemetry=3) for initial enrollment.

**Workaround:** Temporarily remove the `AllowTelemetry` policy before Insider enrollment:
```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
```

After enrollment, you can optionally re-apply Privacy hardening. Insider builds will continue to download even with `AllowTelemetry=1` restored.

**See:** [README Troubleshooting - Windows Insider Program Compatibility](../README.md#windows-insider-program-compatibility)

---

### Bloatware Removal:

**PolicyMethod (8 apps - ENT/EDU Win11 25H2+):**
- BingNews, BingWeather, MicrosoftSolitaireCollection
- MicrosoftStickyNotes, GamingApp, WindowsFeedbackHub  
- Xbox components (GamingOverlay, IdentityProvider)

**ClassicMethod (24 apps - All other editions):**
```
Microsoft.BingNews, Microsoft.BingWeather
Microsoft.MicrosoftSolitaireCollection, Microsoft.MicrosoftStickyNotes
Microsoft.GamingApp, Microsoft.XboxApp
Microsoft.XboxGamingOverlay, Microsoft.XboxIdentityProvider
Microsoft.XboxSpeechToTextOverlay, Microsoft.Xbox.TCUI
Microsoft.ZuneMusic, Microsoft.ZuneVideo
Microsoft.WindowsFeedbackHub, Microsoft.GetHelp
Microsoft.Getstarted, Microsoft.MixedReality.Portal
Microsoft.People, Microsoft.YourPhone
Clipchamp.Clipchamp, SpotifyAB.SpotifyMusic
*CandyCrush*, Disney.*, Facebook.*, TikTok.TikTok
```

### Protected Apps (19 kept):
- **Core Apps:** WindowsStore, WindowsCalculator, Photos, Paint
- **Productivity:** WindowsNotepad, WindowsTerminal, WindowsCamera, ScreenSketch, WindowsSoundRecorder
- **System:** DesktopAppInstaller (winget), StorePurchaseApp
- **Media Codecs:** HEIF, HEVC, WebP, VP9, WebMedia, AV1, MPEG2, RAW (8 extensions)

### OneDrive Settings:
- Telemetry: Disabled
- Sync: Functional (not broken)
- Store: Enabled (app updates needed)

---

## 🤖 Module 5: AntiAI (32 Policies)

**Description:** Disable 15 Windows AI features via 32 registry policies (v2.2.0)

### 15 AI Features Disabled:

| # | Feature | Policies | Description |
|---|---------|----------|-------------|
| 1 | **Generative AI Master Switch** | 2 | Blocks ALL apps from using on-device AI models |
| 2 | **Windows Recall** | 8 | Screenshots, OCR, component removal + Enterprise Protection |
| 3 | **Windows Copilot** | 6 | 4-layer disable: WindowsAI, WindowsCopilot, Taskbar, Explorer |
| 4 | **Click to Do** | 2 | Screenshot AI analysis with action suggestions |
| 5 | **Paint Cocreator** | 1 | Cloud-based text-to-image generation |
| 6 | **Paint Generative Fill** | 1 | AI-powered image editing |
| 7 | **Paint Image Creator** | 1 | DALL-E art generator |
| 8 | **Notepad AI** | 1 | Write, Summarize, Rewrite features (GPT) |
| 9 | **Settings Agent** | 1 | AI-powered Settings search |
| 10 | **Recall Export Block** | 1 | Prevents export of Recall data |
| 11 | **Copilot URI Handlers** | 1 | Blocks ms-copilot:// and ms-chat:// URI schemes |
| 12 | **Edge Copilot Sidebar** | 3 | EdgeSidebarEnabled, ShowHubsSidebar, HubsSidebarEnabled |
| 13 | **Region Policy Override** | 1 | Prevents region bypass for AI features |
| 14 | **Copilot Network Block** | 1 | Blocks Copilot endpoints via hosts file |
| 15 | **File Explorer AI Actions** | 1 | HideAIActionsMenu in Explorer context menu |

### Recall Enterprise Protection:
- **App Deny List:** Browser, Terminal, Password managers, RDP never captured
- **URI Deny List:** Banking (*.bank.*), Email (mail.*), Login pages (*password*, *login*)
- **Storage Duration:** Maximum 30 days retention
- **Storage Space:** Maximum 10 GB allocated

### Automatically Blocked (by Master Switch):
- Photos Generative Erase / Background effects
- Clipchamp Auto Compose
- Snipping Tool AI-OCR / Quick Redact
- All future generative AI apps

### 32 Registry Policies Applied:
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\LetAppsAccessSystemAIModels = 2
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels\Value = Deny
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\AllowRecallEnablement = 0
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis = 1
HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis = 1
HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableRecallDataProviders = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\SetDenyAppListForRecall = [...]
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\SetDenyUriListForRecall = [...]
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\SetMaximumStorageDurationForRecallSnapshots = 30
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\SetMaximumStorageSpaceForRecallSnapshots = 10
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\TurnOffWindowsCopilot = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot\TurnOffWindowsCopilot = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot\ShowCopilotButton = 0
HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\DisableWindowsCopilot = 1
HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot\TurnOffWindowsCopilot = 1
HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot\ShowCopilotButton = 0
HKCU:\Software\Policies\Microsoft\Windows\WindowsAI\SetCopilotHardwareKey = Notepad (redirect)
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableClickToDo = 1
HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableClickToDo = 1
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint\DisableCocreator = 1
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint\DisableGenerativeFill = 1
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint\DisableImageCreator = 1
HKLM:\SOFTWARE\Policies\WindowsNotepad\DisableAIFeatures = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableSettingsAgent = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\AllowRecallExport = 0
HKLM:\SOFTWARE\Policies\Microsoft\Edge\EdgeSidebarEnabled = 0
HKLM:\SOFTWARE\Policies\Microsoft\Edge\ShowHubsSidebar = 0
HKLM:\SOFTWARE\Policies\Microsoft\Edge\HubsSidebarEnabled = 0
HKLM:\SOFTWARE\Policies\Microsoft\Edge\CopilotPageContext = 0
HKLM:\SOFTWARE\Policies\Microsoft\Edge\CopilotCDPPageContext = 0
```

### Impact:
- ✅ No AI data collection
- ✅ No cloud processing of local data
- ✅ Copilot completely hidden from taskbar and Start menu
- ✅ Edge Copilot sidebar disabled
- ✅ Traditional app experience restored
- ✅ **Reboot required** for Recall component removal

### ⚠️ Known Limitations:
Some UI elements in Paint and Photos apps may **still be visible** but non-functional due to lack of Microsoft-provided policies:
- **Photos:** Generative Erase button, Background Blur/Remove options
- **Paint:** Some AI feature UI elements

**Why?** Microsoft does NOT provide dedicated policies to hide these UI elements. Functionality is **blocked via systemAIModels API Master Switch** (LetAppsAccessSystemAIModels = 2), but UI removal requires Microsoft to add policies in future Windows updates.

**Result:** Buttons are visible but clicking them does nothing (API access blocked).

---

## 🌐 Module 6: EdgeHardening (24 Settings)

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

## 🔐 Module 7: AdvancedSecurity (50 Settings)

**Description:** Advanced hardening beyond Microsoft Security Baseline

### Profile-Based Execution:

| Feature | Balanced | Enterprise | Maximum |
|---------|------|------------|-----------|
| RDP NLA Enforcement | ✅ | ✅ | ✅ |
| WDigest Protection | ✅ | ✅ | ✅ |
| Risky Ports/Services | ✅ | ✅ | ✅ |
| Legacy TLS Disable | ✅ | ✅ | ✅ |
| WPAD Disable | ✅ | ✅ | ✅ |
| PowerShell v2 Removal | ✅ | ✅ | ✅ |
| Admin Shares Disable | ✅ | ⚠️ Domain Check | ✅ |
| RDP Complete Disable | ⚠️ Optional | ❌ | ✅ |
| UPnP/SSDP Block | ⚠️ Optional | ✅ | ✅ |
| Wireless Display Hardening | ✅ | ✅ | ✅ |
| Wireless Display Full Disable | ⚠️ Optional | ⚠️ Optional | ⚠️ Optional |
| Discovery Protocols (WSD/mDNS) Disable | ❌ | ❌ | ⚠️ Optional |
| Firewall Shields Up | ❌ | ❌ | ⚠️ Optional |
| IPv6 Disable (mitm6 mitigation) | ❌ | ❌ | ⚠️ Optional |
| SRP .lnk Protection | ✅ | ✅ | ✅ |
| Windows Update Config | ✅ | ✅ | ✅ |
| Finger Protocol Block | ✅ | ✅ | ✅ |

### Components:

#### 1. RDP Hardening (3 settings)
- **NLA Enforcement:** UserAuthentication = 1, SecurityLayer = 2
- **Optional Disable:** fDenyTSConnections = 1 (Maximum profile only, for air-gapped systems)
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

#### 12. Wireless Display Security (9 settings)

**Default Hardening (always applied, all profiles):**
- **AllowProjectionToPC = 0:** Block receiving projections (PC can't be used as display)
- **RequirePinForPairing = 2:** Always require PIN for pairing

**Optional Full Disable (user choice):**
- **AllowProjectionFromPC = 0:** Block sending projections
- **AllowMdnsAdvertisement = 0:** Don't advertise as receiver via mDNS
- **AllowMdnsDiscovery = 0:** Don't discover displays via mDNS
- **AllowProjectionFromPCOverInfrastructure = 0:** Block infrastructure projection
- **AllowProjectionToPCOverInfrastructure = 0:** Block infrastructure receiving
- **Firewall Rules:** Block Miracast ports 7236/7250 (TCP + UDP)

**Protection:**
- Prevents rogue Miracast receiver attacks (screen capture by attackers in network)
- Blocks WPS PIN brute-force on Miracast connections
- Prevents mDNS spoofing for fake display discovery
- Defense-in-depth for Miracast attack surface

**Impact:**
- Default: Presentations to TV/projector still work (sending allowed)
- Full Disable: Use HDMI/USB-C cables instead of Miracast

#### 13. Discovery Protocols Security (WS-Discovery + mDNS)

**Optional (Maximum profile - user choice):**
- **mDNS Resolver:** Disabled via registry (EnableMDNS = 0)
- **WS-Discovery Services:** FDResPub + SSDPSRV disabled
- **Firewall Blocks:** 
  - WS-Discovery ports: UDP 3702 (blocked inbound/outbound)
  - mDNS port: UDP 5353 (blocked inbound/outbound)

**Protection:**
- Prevents network mapping via WS-Discovery
- Blocks mDNS spoofing attacks (fake printers/devices)
- Reduces lateral movement attack surface
- Stops automatic device enumeration by attackers

**Impact:**
- Automatic network printer/scanner discovery stops
- Smart TV discovery via mDNS stops
- Miracast discovery via mDNS stops (even if Feature 12 allows sending)
- Manual IP configuration required for network devices

#### 14. Firewall Shields Up (Maximum profile only)

**Optional (Maximum profile):**
- **Block All Inbound:** DefaultInboundAction = Block
- **Block All Outbound:** DefaultOutboundAction = Block (with exceptions)
- Applies to Domain, Private, and Public profiles

**Protection:**
- Maximum network isolation
- Blocks all unsolicited inbound connections
- Prevents unauthorized outbound connections

**Impact:**
- Only explicitly allowed traffic passes
- Recommended for air-gapped or high-security systems

#### 15. IPv6 Disable (Maximum profile only - optional)

**Optional (Maximum profile - user choice):**
- **DisabledComponents = 0xFF:** Completely disables IPv6 stack
- Prevents all IPv6 traffic including DHCPv6 Solicitation

**Protection (mitm6 attack):**
- Prevents DHCPv6 spoofing attacks
- Blocks fake DHCPv6 server → DNS takeover
- Prevents NTLM credential relay via IPv6
- Defense-in-depth (WPAD already disabled)

**Impact:**
- IPv6-only services/websites won't work
- Exchange Server may have issues if using IPv6
- Some Active Directory features may be affected
- **REBOOT REQUIRED**

**Recommended for:**
- Air-gapped systems
- Standalone workstations (no Exchange/AD)
- High-security environments where IPv6 is not needed

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

### User Prompts (13 Total):

#### SecurityBaseline (1 prompt):
1. **BitLocker USB Policy** (Home/Enterprise)
   - Home Mode: USB works normally (no encryption enforcement)
   - Enterprise Mode: Require BitLocker encryption on USB drives

#### ASR (2 prompts):
2. **PSExec/WMI rule mode** (Block/Audit)
   - Block: Maximum security (may break SCCM/remote admin)
   - Audit: Log only (compatibility testing)

3. **New Software rule mode** (Block/Audit)
   - Block: Block executables that don't meet prevalence criteria
   - Audit: Log only (recommended for new software installs)

#### DNS (2 prompts):
4. **Provider selection** (Quad9/Cloudflare/AdGuard/Skip)
   - 3 DNS providers available with ratings
   - Skip option to keep current DNS

5. **DoH Mode selection** (REQUIRE/ALLOW/Skip)
   - REQUIRE: No unencrypted fallback (maximum security)
   - ALLOW: Fallback to UDP if needed (VPN/corporate/mobile)
   - Skip: Keep current DNS settings

#### Privacy (3 prompts):
6. **Mode selection** (MSRecommended/Strict/Paranoid)
   - MSRecommended: Fully supported, production-safe
   - Strict: Maximum privacy (Teams/Zoom work)
   - Paranoid: Extreme privacy (BREAKS Teams/Zoom!)

7. **Cloud Clipboard** (Enable/Disable) - *only in MSRecommended mode*
   - Disable: No cross-device clipboard sync (privacy)
   - Enable: Keep cloud clipboard functionality

8. **Bloatware Removal** (Yes/No)
   - Yes: Remove 8-24 pre-installed apps
   - No: Keep all apps installed

#### AdvancedSecurity (5 prompts):
9. **Profile selection** (Balanced/Enterprise/Maximum)
   - Balanced: Safe defaults for home users
   - Enterprise: Domain-aware checks
   - Maximum: Maximum hardening

10. **RDP Disable** (Yes/No) - *Balanced profile only, Maximum always disables*
    - Yes: Completely disable Remote Desktop
    - No: Keep RDP enabled (with NLA hardening)

11. **UPnP/SSDP Block** (Yes/No) - *Balanced profile only, others always block*
    - Yes: Block UPnP/SSDP (may break DLNA streaming)
    - No: Keep UPnP enabled

12. **Wireless Display Disable** (Yes/No) - *all profiles*
    - Yes: Completely disable Miracast (use HDMI instead)
    - No: Keep Miracast hardened but usable

13. **Admin Shares Disable** (Yes/No) - *Domain-joined systems only*
    - Yes: Disable C$/ADMIN$ even on domain (may break IT tools)
    - No: Keep admin shares for IT management (SCCM, PDQ, etc.)

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
- ✅ Profile-based execution (Balanced/Enterprise/Maximum)
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
NoID Privacy v2.2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Settings:             632 ✅
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

**Last Updated:** December 8, 2025  
**Framework Version:** v2.2.0  
