# 🚀 Complete Feature List

**NoID Privacy - Windows 11 25H2 Security Baseline**

> **Every single feature, setting, and configuration in one complete list**

---

## 📑 Table of Contents

- [Security Features](#-security-features) - 550+ Settings
- [Privacy Features](#-privacy-features) - 700+ Settings  
- [Network Security](#-network-security) - DNS, Firewall, SMB
- [AI & Tracking Lockdown](#-ai--tracking-lockdown) - 8 AI Features Disabled
- [Telemetry Control](#-telemetry-control) - 25 Services, 180 Keys, 60 Tasks
- [Application Control](#-application-control) - 50+ Apps Removed
- [Windows Update](#-windows-update) - Secure Auto-Update Configuration
- [System Hardening](#-system-hardening) - 15+ Additional Protections
- [Performance Optimization](#-performance-optimization) - Background Tasks, Logs
- [User Experience](#-user-experience) - Interactive Menu, Multi-Language
- [Backup & Recovery](#-backup--recovery) - Complete Undo Capability
- [Advanced Features](#-advanced-features) - LAPS, Auditing, SAC
- [Verification](#-verification--validation) - Post-Apply Validation

---

## 🛡️ Security Features

### Microsoft Defender - Real-Time Protection
✅ **11 Protection Layers Configured**

**Module:** `SecurityBaseline-Core.ps1` → `Set-DefenderBaselineSettings`

| Feature | User Benefit |
|---------|--------------|
| Real-Time Protection | Instant malware detection |
| Cloud-Delivered Protection | Zero-day attack prevention |
| Automatic Sample Submission | Global threat intelligence |
| Behavior Monitoring | Fileless malware detection |
| Network Protection | Malicious website blocking |
| PUA Protection | No crapware/adware |
| Archive Scanning | Hidden malware in ZIPs |
| Removable Drive Scanning | USB threat protection |
| Email Scanning | Phishing attachment blocking |
| Script Scanning | PowerShell/JS attack prevention |
| Tamper Protection | Can't be disabled by malware |

### Attack Surface Reduction (ASR)
✅ **19 ASR Rules = 19 Attack Vectors Blocked**

**Module:** `SecurityBaseline-ASR.ps1`

| What It Blocks | Your Protection |
|----------------|-----------------|
| Office executable content | Macro viruses |
| Office child processes | Cmd.exe exploits |
| Win32 API calls from Office | Advanced macro attacks |
| Office process injection | Code injection |
| JavaScript/VBScript launches | Script malware |
| Obfuscated scripts | Hidden PowerShell attacks |
| Untrusted USB executables | USB-based malware |
| Adobe Reader child processes | PDF exploits |
| LSASS credential theft | Mimikatz protection |
| Exploited vulnerable drivers | Rootkit prevention |
| Ransomware behavior | File encryption blocking |
| WMI persistence | Advanced persistent threats |
| PsExec-style process creation | Lateral movement |
| Untrusted executables | Unknown malware |
| Webshell execution | Web server compromises |
| Office suspicious communications | Data exfiltration |
| NTLM brute force | Password attacks |
| Safe mode reboot blocking | Anti-forensics prevention |
| Advanced ransomware protection | Multi-stage ransomware |

### BitLocker Encryption
✅ **XTS-AES-256 Military-Grade Encryption**

| Configuration | What It Means |
|---------------|---------------|
| TPM 2.0 + PIN | Two-factor boot security |
| Recovery Key Saved | Can recover if PIN forgotten |
| All Drives Encrypted | Complete disk protection |
| Removable Media Encrypted | USB drives protected |
| Pre-Boot Authentication | Stolen laptop = useless brick |

### Credential Protection
✅ **7 Credential Theft Protections**

| Technology | Blocks |
|------------|--------|
| LSA Protection (PPL) | Mimikatz credential dumping |
| Credential Guard (VBS) | Pass-the-hash attacks |
| Restricted Admin RDP | RDP credential theft |
| NTLM Restrictions | Forced Kerberos usage |
| Cached Credentials Limit (2) | Offline password attacks |
| RunAsPPL | LSASS memory access |
| NTLM Auditing | Outdated auth detection |

### Exploit Protection
✅ **13 System-Wide Exploit Mitigations**

| Mitigation | Blocks |
|------------|--------|
| DEP (NX bit) | Buffer overflows |
| SEHOP | Exception handler exploits |
| CFG | ROP chain attacks |
| Mandatory ASLR | Memory exploits |
| Bottom-Up ASLR | Heap spraying |
| High Entropy ASLR (64-bit) | ASLR bypass |
| Force ASLR | Legacy app protection |
| Exception Chain Validation | Exception exploits |
| Stack Integrity Validation | Stack overflows |
| Arbitrary Code Guard (ACG) | Code injection |
| Low Integrity Image Block | Privilege escalation |
| Remote Image Block | Remote code execution |
| Win32k Disable | Kernel exploits |

### User Account Control (UAC)
✅ **Maximum Elevation Security**

**Module:** `SecurityBaseline-UAC.ps1` → `Set-MaximumUAC` + `Enable-EnhancedPrivilegeProtectionMode`

- **Level:** Always notify (highest)
- **Secure Desktop:** Dimmed screen (can't be faked)
- **Admin Approval Mode:** Even admins get prompted
- **Enhanced Privilege Protection:** Future-ready EPP mode

### Firewall
✅ **Strict Inbound = Zero Unsolicited Connections**

- Inbound: BLOCK ALL
- Outbound: Allow (you can surf normally)
- Discovery: Blocked (no network scanning)
- Public Wi-Fi: Maximum restrictions

---

## 🔒 Privacy Features

### Complete Telemetry Shutdown
✅ **Microsoft Gets Minimal Data (Defender Cloud Only)**

**Module:** `SecurityBaseline-Telemetry.ps1`

**25 Services Stopped:**
- DiagTrack (Connected User Experiences)
- WerSvc (Windows Error Reporting)  
- All diagnostic services
- CEIP services
- 20+ more data collection services

**180+ Registry Keys Set:**
- AllowTelemetry = 0 (Security level)
- Diagnostic data viewer = BLOCKED
- Feedback = DISABLED
- Advertising ID = DELETED
- 175+ more privacy settings

**60+ Scheduled Tasks Disabled:**
- Microsoft Compatibility Appraiser
- Consolidator
- UsbCeip
- KernelCeipTask
- 56+ more data collection tasks

**200+ Domains Blocked (Firewall):**
- vortex.data.microsoft.com
- telemetry.microsoft.com
- watson.microsoft.com
- 197+ more Microsoft servers

### Windows Search Privacy
✅ **Local-Only Search**

- Web Search: OFF (no Bing queries)
- Cortana: Removed
- Search Suggestions: OFF
- Cloud Search: OFF
- Location in Search: OFF

### App Permissions - Default DENY
✅ **37 Permission Categories Locked Down**

All apps CANNOT access (unless you allow):
- Camera, Microphone, Location
- Contacts, Calendar, Email, Messages
- Call History, Radios, Notifications
- Account Info, Documents, Pictures, Videos
- File System, Bluetooth, Phone Calls
- Screenshots, Downloads, Music
- Background Apps, App Diagnostics
- Cellular/Wi-Fi Data, Tasks
- Graphics Capture, Spatial Perception
- Gaze Input, and 10+ more

**You control EVERYTHING apps can access!**

### OneDrive Privacy
✅ **Privacy-First Cloud Sync**

- Tutorial: OFF (no first-run tracking)
- Feedback: OFF (no bug report data leaks)
- Pre-Login Network: BLOCKED (no silent connections)
- Known Folder Move: BLOCKED (no auto-upload)
- **OneDrive still works - YOU control uploads!**

---

## 🌐 Network Security

### DNS Security - Triple Protection
✅ **Encrypted + Validated + Blocked**

**Module:** `SecurityBaseline-DNS.ps1` + `SecurityBaseline-Core.ps1`

**1. DNS-over-HTTPS (DoH)**
- Provider: Cloudflare 1.1.1.1 / 1.0.0.1
- Encryption: HTTPS (Port 443)
- ISP Can't See: Your DNS queries
- No Logging: Anonymous DNS
- Speed: Faster than ISP DNS

**2. DNSSEC Validation (by Cloudflare)**
- Prevents: DNS spoofing
- Prevents: Cache poisoning
- Prevents: DNS hijacking
- Mode: Opportunistic (balanced)

**3. Steven Black Unified Hosts**
- **79,776 domains blocked** at DNS level
- Malware + Ads + Tracking + Telemetry
- Compressed format (9 per line)
- Zero performance impact
- Updated October 2025

**Result: 79,776 threats blocked BEFORE they load!**

### SMB Hardening
✅ **Secure File Sharing**

**Module:** `SecurityBaseline-Core.ps1` → `Set-SMBHardening`

- SMB v1: COMPLETELY REMOVED (WannaCry protection)
- SMB Signing: REQUIRED (MITM prevention)
- SMB Encryption: ENABLED (packet sniffing protection)
- Guest Auth: DISABLED (no anonymous access)

### TLS/SSL Hardening
✅ **Only Secure Protocols + Strong Ciphers**

**Module:** `SecurityBaseline-Advanced.ps1` → `Set-TLSHardening`

**Protocols:**
- ❌ SSL 2.0 / 3.0 (DROWN, POODLE attacks)
- ❌ TLS 1.0 / 1.1 (Deprecated, weak)
- ✅ TLS 1.2 / 1.3 (Modern & Secure)

**Ciphers:**
- ❌ Weak: RC4, 3DES, DES, NULL, MD5
- ❌ CBC Ciphers (vulnerable to BEAST/Lucky13)
- ✅ Strong: AES-GCM, ChaCha20-Poly1305 only (AEAD)
- ✅ Hash: SHA-256/384/512 (no SHA-1)

**User Benefit:** Bank-grade TLS encryption, no weak crypto

### Legacy Protocols - All Disabled
✅ **Attack Surface Minimized**

**Module:** `SecurityBaseline-Core.ps1` → `Disable-NetworkLegacyProtocols`

- LLMNR: OFF (MITM credential theft)
- NetBIOS: OFF (network poisoning)
- WPAD: OFF (proxy attacks)
- WDigest: OFF (plaintext passwords)
- mDNS: OFF (multicast DNS)
- SSDP: OFF (UPnP discovery)
- WSD: OFF (Web Services Discovery)

### Network Stealth Mode
✅ **Invisible on Network**

**Module:** `SecurityBaseline-Core.ps1` → `Enable-NetworkStealthMode`

**What's Disabled:**
- Network Discovery: OFF (can't be found by other PCs)
- Network Browsing: OFF (not visible in Network Neighborhood)
- File and Printer Sharing: Firewall rules disabled
- Broadcasting: All disabled (mDNS, LLMNR, NetBIOS, SSDP, UPnP)
- P2P Services: Peer Networking disabled
- WSD: Web Services Discovery disabled

**What Still Works:**
- ✅ Internet access (browsing, downloads)
- ✅ Wi-Fi / Ethernet connection
- ✅ VPN connections
- ✅ Outgoing connections to network shares (if you manually connect)

**User Benefit:** Your PC is invisible on the network, can't be scanned/discovered
**Use Case:** Coffee shop Wi-Fi, untrusted networks

### Unnecessary Services Disabled
✅ **24 Services Disabled (CIS Benchmark)**

**Module:** `SecurityBaseline-Core.ps1` → `Disable-UnnecessaryServices`

**Services Disabled:**
- Remote Registry (remote access to registry)
- SSDP Discovery (UPnP)
- UPnP Device Host
- Windows Error Reporting (handled separately)
- Downloaded Maps Manager (Maps app removed)
- Geolocation Service (privacy)
- Link-Layer Topology Discovery
- Internet Connection Sharing (ICS)
- Microsoft iSCSI Initiator
- Peer Networking (P2P - all 4 services)
- RPC Locator
- Routing and Remote Access
- SNMP Trap
- WWAN AutoConfig (Mobile Broadband)
- Function Discovery (2 services)
- WSD Scan/Print (2 services)
- Xbox Live (4 services: Auth, Game Save, Networking, Accessories)

**Services KEPT Active:**
- ✅ Smart Card Services (3 services) - Enterprise compatibility
- ✅ Windows Update
- ✅ Windows Defender
- ✅ All critical system services

**User Benefit:** Less attack surface, better performance, no unnecessary background processes

### Wireless Security
✅ **No Wireless Eavesdropping**

**Module:** `SecurityBaseline-WirelessDisplay.ps1` → `Disable-WirelessDisplay`

- Miracast: DISABLED (4 layers)
- Wireless Display: DISABLED
- Wi-Fi Direct: DISABLED
- Cast to Device: DISABLED
- Miracast Ports: BLOCKED (TCP 7236, 7250)

---

## 🤖 AI & Tracking Lockdown

### 8 AI Features Completely Disabled
✅ **Zero AI Spying**

**Module:** `SecurityBaseline-AI.ps1`

| AI Feature | Privacy Risk | Status |
|------------|--------------|--------|
| **Windows Recall** | Screenshots EVERYTHING (passwords!) | ❌ DISABLED |
| **Windows Copilot** | AI data collection | ❌ DISABLED (4 layers) |
| **Click to Do** | Screenshot AI analysis | ❌ DISABLED |
| **Paint Cocreator** | Cloud-based image generation | ❌ DISABLED |
| **Paint Generative Fill** | Cloud AI editing | ❌ DISABLED |
| **Paint Image Creator** | Cloud AI art | ❌ DISABLED |
| **Settings Agent** | AI in Settings menu | ❌ DISABLED |
| **Copilot Proactive** | Unsolicited AI suggestions | ❌ DISABLED |

**Fallback:** If user re-enables Recall: 10 GB max, 1 day retention

### Microsoft Edge Privacy
✅ **Security Locked, Convenience Customizable**

**Module:** `SecurityBaseline-Edge.ps1` → `Set-EdgeSecurityBaseline`

**Enforced (Greyed Out):**
- SmartScreen: ON (malware blocking)
- Tracking Prevention: STRICT
- DNS-over-HTTPS: ON
- Site Isolation: ON
- Extensions: Microsoft Store only

**Your Choice (Can Change):**
- Password Manager: Default ON
- AutoFill: Default ON
- Payment Methods: Default ON
- InPrivate Mode: Available

---

## 📡 Telemetry Control

### What Gets Stopped
✅ **Complete Telemetry Lockdown**

**Services (25):**
Every single diagnostic/telemetry service disabled

**Registry (180+ keys):**
Every telemetry setting = OFF/BLOCKED/DISABLED

**Tasks (60+):**
All data collection tasks disabled

**Network (200+ domains):**
Microsoft telemetry servers blocked

**Result: Telemetry minimized to essential security data only**

---

## 🎮 Application Control

### Bloatware Removal
✅ **50+ Pre-Installed Apps Removed**

**Module:** `SecurityBaseline-Bloatware.ps1` → `Remove-BloatwareApps` + `Disable-ConsumerFeatures`

**Communication:**
Teams, Skype, Messenger, Your Phone, Cortana, People

**Entertainment:**
Xbox (5 apps), Mixed Reality, Groove, Movies & TV

**Shopping:**
Get Started, Tips, Feedback Hub

**News:**
Microsoft News, Weather, To Do

**Games:**
Solitaire, Candy Crush, Bubble Witch

**3D:**
3D Builder, 3D Viewer, Paint 3D, Print 3D

**And 30+ more!**

**Result: Clean system, faster boot, more disk space**

---

## 🔄 Windows Update

### Secure Auto-Update Configuration
✅ **HYBRID Approach: Security + User Control**

**Module:** `SecurityBaseline-WindowsUpdate.ps1`

| Setting | Configuration | User Benefit |
|---------|---------------|--------------|
| **Updates for MS Products** | ON (default) | Office/Defender updates automatic |
| **Get Latest Updates** | ON (default) | Continuous Innovation features |
| **Metered Connections** | ON (default) | Security > Data costs |
| **Restart Notifications** | ON (default) | Controlled restarts |
| **Expedited Updates** | ON (default) | Security patches ASAP |
| **Preview Builds** | OFF (enforced) | No unstable Windows Insider builds |

**Philosophy:** All toggles ON = Maximum security, but user CAN change

### Delivery Optimization
✅ **HTTP-Only (No P2P)**

| Setting | Configuration | User Benefit |
|---------|---------------|--------------|
| **Download Mode** | HTTP only (1) | No peer-to-peer sharing |
| **LAN Sharing** | Disabled | Privacy on local network |
| **Internet Sharing** | Disabled | No uploads to strangers |
| **Background Download** | Optimized | Less bandwidth usage |

**User Benefit:** Fast updates WITHOUT becoming a P2P node

---

## 🔐 System Hardening

### Controlled Folder Access (Ransomware Protection)
✅ **Advanced Ransomware Defense**

**Module:** `SecurityBaseline-Core.ps1`

- **Protected Folders:** Documents, Pictures, Desktop, Videos
- **Only Trusted Apps:** Can modify protected folders
- **Ransomware:** Can't encrypt your files
- **User Control:** Add custom folders/apps
- **Status:** Enabled + monitored

**User Benefit:** Ransomware CANNOT encrypt your documents!

### AutoPlay/AutoRun Disablement
✅ **USB Attack Prevention**

| Feature | Status | Protection Against |
|---------|--------|---------------------|
| **AutoPlay** | Disabled | USB malware auto-execution |
| **AutoRun** | Disabled | CD/DVD auto-launch attacks |
| **All Drive Types** | Blocked | Network shares, optical media |
| **Registry Lock** | Enforced | Can't be re-enabled easily |

**User Benefit:** USB stick can't auto-infect your PC

### Administrative Shares Disablement
✅ **Hidden Share Protection**

| Share | Status | Security Impact |
|-------|--------|-----------------|
| **ADMIN$** | Disabled | No remote C:\ access |
| **C$, D$, etc.** | Disabled | No admin share access |
| **IPC$** | Hardened | No anonymous access |
| **Print$** | Controlled | Printer security |

**User Benefit:** Hackers can't access C$ remotely

### Print Spooler Hardening
✅ **PrintNightmare Protection**

- RPC Authentication: REQUIRED
- RPC Encryption: ENABLED
- Point and Print: RESTRICTED
- Driver Installation: ADMIN-ONLY
- Network Printing: HARDENED

**Blocks:** PrintNightmare exploit + variants

### Remote Access Complete Lockdown
✅ **Zero Remote Access**

**ALL Remote Methods Disabled:**
- Remote Desktop (RDP)
- Remote Assistance
- Remote Registry
- Remote Scheduled Tasks
- Remote Service Management
- WinRM / PSRemoting
- Network Access (Server service)

**Exception:** Intune/SCCM management still works

**User Benefit:** Can't be hacked remotely

### IE11 & Legacy COM Disablement
✅ **No Legacy Browser Exploits**

- Internet Explorer 11: DISABLED
- MSHTML.DLL: BLOCKED
- ActiveX Controls: DISABLED
- COM Automation: BLOCKED
- Jscript.dll: HARDENED

**User Benefit:** No IE exploits, must use Edge

### Sudo for Windows Disablement
✅ **No Privilege Escalation Vector**

- Sudo Command: DISABLED
- Windows 11 24H2+ Feature
- Potential Security Risk: BLOCKED

**User Benefit:** UAC can't be bypassed via sudo

### Anonymous SID Enumeration Blocking
✅ **User Enumeration Prevention**

- RestrictAnonymousSAM = 1
- RestrictAnonymous = 1
- EveryoneIncludesAnonymous = 0
- LM Hashes: DISABLED
- NoLMHash = 1

**User Benefit:** Attackers can't enumerate users

### Mark-of-the-Web (MotW)
✅ **Downloaded File Protection**

- SmartScreen: Checks downloaded files
- Zone.Identifier: Preserved
- Office: Won't open untrusted docs
- Saves Against: Downloaded malware

**User Benefit:** Downloads are automatically scanned

### Kerberos PKINIT Hash Agility
✅ **Modern Kerberos Only**

- SHA-256/384/512: ENABLED
- SHA-1: DISABLED
- Smart Card Auth: SHA-256+
- Certificate-based: HARDENED

**User Benefit:** No weak Kerberos attacks

### Secure Administrator Account
✅ **Built-in Admin Hardening**

- Account: Renamed (not "Administrator")
- Status: Disabled (not in use)
- Description: Randomized
- Password: Complex (if enabled)
- SID: S-1-5-21-*-500 (tracked)

**User Benefit:** Built-in admin can't be brute-forced

### Process Auditing with Command Line
✅ **Full Command Line Logging**

- Process Creation: LOGGED
- Command Lines: CAPTURED
- Audit Category: Enabled
- Event ID: 4688

**Warning:** May log passwords in scripts!
**Use Case:** Forensics, incident response

### SmartScreen Extended Configuration
✅ **Multi-Layer SmartScreen**

- Windows Defender SmartScreen: ON
- Microsoft Edge SmartScreen: ON
- Microsoft Store Apps: CHECKED
- Unrecognized Apps: WARNED
- Bypass: BLOCKED (where possible)

**User Benefit:** Protection across all entry points

---

## ⚡ Performance Optimization

### Background Task Control
✅ **50+ Tasks Disabled**

**Module:** `SecurityBaseline-Performance.ps1` → `Optimize-ScheduledTasks`

- WinSAT, Defrag, Error Reporting
- CEIP, Application Experience
- Diagnostics (non-security)
- **Windows Update/Defender: KEPT ACTIVE**

### Event Log Optimization
✅ **Less Disk I/O**

**Module:** `SecurityBaseline-Performance.ps1` → `Optimize-EventLogs`

**Log Size Reduction:**
- Application Log: 20 MB → 10 MB
- System Log: 20 MB → 10 MB  
- Setup Log: 20 MB → 10 MB
- Forwarded Events: 20 MB → 10 MB
- **Security Log: KEPT at 100 MB** (critical!)

**Noisy Logs Reduced:**
- Microsoft-Windows-NCSI: 15 MB → 5 MB
- Microsoft-Windows-NetworkProfile: 15 MB → 5 MB
- Microsoft-Windows-WindowsUpdateClient: 15 MB → 5 MB
- And 10+ more chatty logs reduced

**User Benefit:** Less disk writes, faster log access, less I/O noise

### Background Activities Control
✅ **Quieter System**

**Module:** `SecurityBaseline-Performance.ps1` → `Disable-BackgroundActivities`

**Disabled Background Features:**
- Cortana Background Tasks
- Windows Tips & Tricks
- Timeline Activity History
- Clipboard History Sync
- Feedback Notifications
- Suggested Content
- Background App Refresh (user-controlled)
- Storage Sense Automation (manual control)

**User Benefit:** Less CPU/disk usage when idle, more battery life

### System Maintenance Optimization
✅ **Controlled Maintenance Windows**

**Module:** `SecurityBaseline-Performance.ps1` → `Optimize-SystemMaintenance`

**Optimized Tasks:**
- Idle Maintenance: Less aggressive
- Registry Backup: Less frequent
- Notification Cleanup: Minimal processing
- Automatic Maintenance: User-controlled
- Maintenance Windows: Optimized timing

**User Benefit:** Less interruptions during work, maintenance runs when YOU want

### Visual Effects Optimization
✅ **Performance > Eye Candy**

**Module:** `SecurityBaseline-Performance.ps1` → `Disable-VisualEffects`

**Optimized Settings:**
- Animations: Reduced (not disabled)
- Transparency: Minimal
- Shadows: Reduced
- Smooth Scrolling: OFF (performance)
- Aero Peek: ON (still useful)
- Thumbnails: ON (still useful)

**User Benefit:** Snappier UI, faster window operations
**Note:** User can re-enable animations in Settings > Accessibility > Visual Effects

### Performance Report
✅ **See What Changed**

**Module:** `SecurityBaseline-Performance.ps1` → `Show-PerformanceReport`

**Shows:**
- Tasks disabled count
- Event logs optimized count
- Background activities disabled
- Visual effects optimized
- Estimated performance gain
- What's still active (Windows Update, Defender)

**User Benefit:** Know exactly what was optimized

---

## 🎨 User Experience

### Interactive Menu
✅ **4 Modes**

**Module:** `SecurityBaseline-Interactive.ps1` + `Apply-Win11-25H2-SecurityBaseline.ps1`

- **Audit:** Check status (no changes)
- **Enforce:** Apply ALL settings
- **Custom:** Pick specific modules
- **Verify:** Validate applied settings

### Multi-Language
✅ **English + German**

**Module:** `SecurityBaseline-Localization.ps1` → `Get-LocalizedString` + `Select-Language`

- Real-time language switching
- All messages localized
- Menu system translated

### Progress Visualization
✅ **Always Know What's Happening**

- Progress bar
- Step counter (X/Y)
- Per-module status
- Estimated time remaining

---

## 💾 Backup & Recovery

### Complete System Backup
✅ **Can Undo EVERYTHING**

**Module:** `Backup-SecurityBaseline.ps1`

**6 Backup Components:**

**1. Registry Snapshots (1,200+ keys)**
- All security policy keys (500+)
- All privacy setting keys (700+)
- Network configuration keys
- All HKLM:\SOFTWARE\Policies paths
- All HKLM:\SYSTEM\CurrentControlSet paths
- Telemetry-related keys
- Application permission keys

**2. Service States (25+ services)**
- Service name
- Startup type (Automatic, Manual, Disabled)
- Running status (Running, Stopped)
- Dependencies
- Service description

**3. Scheduled Tasks (60+ tasks)**
- Task name
- Task path (\Microsoft\Windows\*)
- Enabled/Disabled state
- Task configuration XML
- Triggers and actions

**4. Firewall Rules**
- All custom rules created
- Telemetry blocking rules (200+ domains)
- Miracast port blocks
- Rule direction, action, protocol, ports
- Rule enabled/disabled state

**5. File Backups**
- Original hosts file (before 80K blocklist)
- PowerShell profiles (if modified)
- Configuration files
- DNS settings

**6. Metadata**
- Backup timestamp (UTC)
- Windows version (build number)
- Script version (e.g., 1.7.12)
- Applied modules list
- User settings
- Computer name
- Backup hash (integrity check)

**Backup Format:** JSON (human-readable + compressed)
**Location:** `C:\SecurityBaseline\Backups\`
**Filename:** `Backup-YYYY-MM-DD-HHmmss.json`
**Compression:** Optional ZIP

**User Benefit:** Can undo EVERYTHING with one command

### Granular Restore
✅ **Flexible Undo Options**

**Module:** `Restore-SecurityBaseline.ps1`

| Restore Mode | What Gets Restored | Use Case |
|--------------|-------------------|----------|
| **Full Restore** | All 6 components | Complete undo |
| **Registry Only** | Just registry keys | Quick settings revert |
| **Services Only** | Just service states | Fix broken services |
| **Tasks Only** | Just scheduled tasks | Re-enable background tasks |
| **Firewall Only** | Just firewall rules | Remove custom blocks |
| **Files Only** | Just file backups | Restore hosts file |
| **Selective** | Pick specific modules | Undo one feature |

**Safety Features:**
- Backup validation before restore
- Dry-run mode (simulate without applying)
- Rollback on error
- Integrity checks (hash verification)
- Timestamp verification

### Rollback Functionality
✅ **Safe Experimentation**

**Module:** `Rollback-SecurityBaseline.ps1`

**Features:**
- Automatic backup detection
- Latest backup auto-selection
- Pre-rollback system check
- Step-by-step restore
- Error recovery
- Post-rollback verification

**Use Case:** "I don't like this, go back to before!"

**User Benefit:** Zero risk - can always revert

---

## 🔧 Advanced Features

### Windows LAPS
✅ **Automatic Admin Password Rotation**

**Module:** `SecurityBaseline-Advanced.ps1` → `Enable-WindowsLAPS`

- Rotation: Every 30 days
- Length: 20 characters
- Complexity: High entropy
- Storage: Active Directory
- Audit: Every change logged

### Advanced Auditing
✅ **18 Security Event Categories**

**Module:** `SecurityBaseline-Advanced.ps1` → `Enable-AdvancedAuditing`

- Logon/Logoff tracking
- Account management
- Policy changes
- Privilege usage
- Process creation
- And 13+ more categories

**Use Case:** Security incident investigation

### NTLM Auditing
✅ **Legacy Authentication Tracking**

**Module:** `SecurityBaseline-Advanced.ps1` → `Enable-NTLMAuditing`

- **Tracks:** All NTLM authentication attempts
- **Event IDs:** 4624 (NTLM Logon), 8004 (NTLM Auth), 8002 (NTLM Blocked)
- **Mode:** Audit-only (no blocking, for compatibility)
- **Purpose:** Identify legacy NTLM usage for Kerberos migration
- **Security:** Detect Pass-the-Hash attacks

**User Benefit:** See who's still using outdated NTLM (vs Kerberos)

### Smart App Control
✅ **AI-Based App Reputation**

**Module:** `SecurityBaseline-ASR.ps1` → `Enable-SmartAppControl`

- Cloud verification
- Machine learning detection
- Zero-day protection
- Untrusted app blocking

### USB Device Control
✅ **Removable Media Protection**

**Module:** `SecurityBaseline-ASR.ps1` → `Enable-USBDeviceControl`

- **Blocks:** Untrusted USB executables
- **Allows:** Read/Write of files (USB storage works)
- **Prevents:** USB-based malware auto-execution
- **ASR Rule:** Part of 19 ASR rules

**User Benefit:** USB sticks work, but can't infect you

### Game Bar & Game Mode
✅ **Gaming Telemetry Disabled**

**Module:** `SecurityBaseline-Telemetry.ps1` → `Disable-GameBarAndGameMode`

- **Xbox Game Bar:** DISABLED (no gaming overlay)
- **Game Mode:** DISABLED (no performance tracking)
- **Game DVR:** DISABLED (no screen recordings)
- **Broadcasting:** DISABLED (no streaming telemetry)

**User Benefit:** No gaming data sent to Microsoft

### Registry Ownership Management
✅ **TrustedInstaller Handling**

**Module:** `SecurityBaseline-RegistryOwnership.ps1`

| Feature | Purpose |
|---------|---------|
| **Automatic Ownership Taking** | Modify TrustedInstaller keys |
| **Privilege Elevation** | SeBackupPrivilege, SeRestorePrivilege |
| **Safe Rollback** | Restore original ownership |
| **Error Recovery** | Graceful failure handling |

**Use Case:** Modify system-protected registry keys safely

---

## 📊 Verification & Validation

### Verification Mode
✅ **Post-Apply Validation**

**Script:** `Verify-SecurityBaseline.ps1`

**What Gets Verified:**
- Registry keys (security + privacy settings)
- Service states (disabled services)
- Scheduled tasks (disabled tasks)
- Firewall rules (custom blocks)
- Defender configuration (real-time protection, ASR rules)
- Network settings (SMB, TLS, protocols)
- System settings (UAC, BitLocker, etc.)

**Output:** 
- Per-setting Pass/Fail status
- Summary count (X passed, Y failed)
- Detailed error messages for failures
- Recommendations for fixes

**Use Case:** Validate that Apply script worked correctly

**User Benefit:** Know exactly what's configured and what failed

---

## 📊 Statistics Summary

| Category | Count | Details |
|----------|-------|---------|
| **Security Settings** | 550+ | Defender, ASR, BitLocker, Firewall, etc. |
| **Privacy Settings** | 700+ | Telemetry, Permissions, AI, Tracking |
| **System Hardening** | 15 | Controlled Folder Access, AutoPlay, Admin Shares, Print Spooler, Remote Access, IE11, Sudo, SID Enum, MotW, Kerberos, Admin Account, Process Auditing, SmartScreen, etc. |
| **Network Hardening** | 5 | SMB, TLS/SSL (ciphers!), Legacy Protocols, Wireless, DNS |
| **Advanced Security** | 5 | LAPS, Advanced Auditing, NTLM Auditing, Smart App Control, USB Device Control |
| **Services Disabled** | 25 | DiagTrack, WerSvc, Diagnostics, etc. |
| **Tasks Disabled** | 60+ | CEIP, Appraiser, Data Collection |
| **Registry Keys** | 180+ | Telemetry/Privacy/Security |
| **Domains Blocked** | 79,776 | Malware + Ads + Tracking (hosts) |
| **Domains Blocked** | 200+ | Microsoft telemetry (firewall) |
| **Apps Removed** | 50+ | Bloatware, Xbox, 3D, Games |
| **Windows Update** | 6 settings | Auto-update config + Delivery Optimization |
| **ASR Rules** | 19 | Attack Surface Reduction |
| **Exploit Mitigations** | 13 | DEP, ASLR, CFG, SEHOP, etc. |
| **App Permissions** | 37 | Default-DENY categories |
| **AI Features Blocked** | 8 | Recall, Copilot, Paint AI, etc. |
| **Audit Categories** | 18 | Security event logging |
| **Backup Components** | 6 | Registry, Services, Tasks, Firewall, Files, Metadata |

---

## 🎯 Quick Feature Lookup

**Want Maximum Security?**
→ Defender (11 layers) + ASR (19 rules) + BitLocker + Exploit Protection (13 mitigations) + System Hardening (15 protections)

**Want Maximum Privacy?**
→ Telemetry OFF (25 services + 60 tasks + 180 keys) + App Permissions (37 categories) + AI Lockdown (8 features) + 79,776 domains blocked

**Want Ransomware Protection?**
→ ASR Rules + Controlled Folder Access + AutoPlay OFF + Network Protection

**Want Secure Updates?**
→ Windows Update (all toggles ON) + Delivery Optimization (HTTP-only, no P2P)

**Want System Hardening?**
→ Remote Access OFF + Admin Shares OFF + Print Spooler hardened + IE11 disabled + AutoPlay OFF

**Want Performance?**
→ 50+ tasks disabled + Event log optimization + Visual effects optimized + Bloatware removed

**Want Control?**
→ Custom Mode = Pick specific modules

**Want Proof of Configuration?**
→ Verification Mode (Verify-SecurityBaseline.ps1)

**Made a Mistake?**
→ Backup/Restore = Complete undo (6 backup components)

---

## 📚 Related Documentation

- **[Installation Guide](INSTALLATION.md)** - How to apply
- **[FAQ](FAQ.md)** - Common questions
- **[Quick Start](QUICKSTART.md)** - Get started in 5 minutes
- **[Changelog](CHANGELOG.md)** - What's new
- **[Project Structure](PROJECT_STRUCTURE.md)** - Technical details

---

**Last Updated:** October 2025 (v1.7.12)  
**Source:** [NoID Privacy GitHub](https://github.com/NexusOne23/noid-privacy)
