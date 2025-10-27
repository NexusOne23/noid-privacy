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
- [Performance](#-performance-optimization) - Background Tasks, Logs
- [User Experience](#-user-experience) - Interactive Menu, Multi-Language
- [Backup & Recovery](#-backup--recovery) - Complete Undo Capability
- [Advanced Features](#-advanced-features) - LAPS, Auditing, SAC

---

## 🛡️ Security Features

### Microsoft Defender - Real-Time Protection
✅ **11 Protection Layers Configured**

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
✅ **Microsoft Gets ZERO Data**

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

**1. DNS-over-HTTPS (DoH)**
- Provider: Cloudflare 1.1.1.1 / 1.0.0.1
- Encryption: HTTPS (Port 443)
- ISP Can't See: Your DNS queries
- No Logging: Anonymous DNS
- Speed: Faster than ISP DNS

**2. DNSSEC Validation**
- Prevents: DNS spoofing
- Prevents: Cache poisoning
- Prevents: DNS hijacking
- Mode: Opportunistic (balanced)

**3. Steven Black Unified Hosts**
- **80,101 domains blocked** at DNS level
- Malware + Ads + Tracking + Telemetry
- Compressed format (9 per line)
- Zero performance impact
- Updated October 2025

**Result: 80,000+ threats blocked BEFORE they load!**

### SMB Hardening
✅ **Secure File Sharing**

- SMB v1: COMPLETELY REMOVED (WannaCry protection)
- SMB Signing: REQUIRED (MITM prevention)
- SMB Encryption: ENABLED (packet sniffing protection)
- Guest Auth: DISABLED (no anonymous access)

### TLS/SSL - Modern Only
✅ **Only Secure Protocols**

- ❌ SSL 2.0 / 3.0 (DROWN, POODLE)
- ❌ TLS 1.0 / 1.1 (Deprecated)
- ✅ TLS 1.2 / 1.3 (Modern & Secure)

### Legacy Protocols - All Disabled
✅ **Attack Surface Minimized**

- LLMNR: OFF (MITM credential theft)
- NetBIOS: OFF (network poisoning)
- WPAD: OFF (proxy attacks)
- WDigest: OFF (plaintext passwords)

### Wireless Security
✅ **No Wireless Eavesdropping**

- Miracast: DISABLED (4 layers)
- Wireless Display: DISABLED
- Wi-Fi Direct: DISABLED
- Cast to Device: DISABLED
- Miracast Ports: BLOCKED (TCP 7236, 7250)

---

## 🤖 AI & Tracking Lockdown

### 8 AI Features Completely Disabled
✅ **Zero AI Spying**

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

**Result: ZERO usage data sent to Microsoft**

---

## 🎮 Application Control

### Bloatware Removal
✅ **50+ Pre-Installed Apps Removed**

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

## ⚡ Performance Optimization

### Background Task Control
✅ **50+ Tasks Disabled**

- WinSAT, Defrag, Error Reporting
- CEIP, Application Experience
- Diagnostics (non-security)
- **Windows Update/Defender: KEPT ACTIVE**

### Event Log Optimization
✅ **Less Disk I/O**

- Application: 20 MB → 10 MB
- System: 20 MB → 10 MB  
- Noisy Logs: 15 MB → 5 MB
- **Security Log: KEPT LARGE**

### Visual Effects
✅ **Performance-Optimized Defaults**

- Animations: Reduced
- Transparency: Minimal
- Shadows: Reduced
- **User can customize everything!**

---

## 🎨 User Experience

### Interactive Menu
✅ **4 Modes**

- **Audit:** Check status (no changes)
- **Enforce:** Apply ALL settings
- **Custom:** Pick specific modules
- **Verify:** Validate applied settings

### Multi-Language
✅ **English + German**

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

**What's Backed Up:**
- 500+ security registry keys
- 700+ privacy registry keys
- 25 service states
- 60+ task states
- Firewall rules
- Hosts file
- Configuration files
- Metadata (timestamp, version, modules)

**Format:** JSON (human-readable)

### Granular Restore
✅ **Flexible Undo**

- Full Restore: Everything back
- Partial Restore: Select modules
- Registry Only: Quick revert
- Services Only: Fix services

---

## 🔧 Advanced Features

### Windows LAPS
✅ **Automatic Admin Password Rotation**

- Rotation: Every 30 days
- Length: 20 characters
- Complexity: High entropy
- Storage: Active Directory
- Audit: Every change logged

### Advanced Auditing
✅ **18 Security Event Categories**

- Logon/Logoff tracking
- Account management
- Policy changes
- Privilege usage
- Process creation
- And 13+ more categories

**Use Case:** Security incident investigation

### Smart App Control
✅ **AI-Based App Reputation**

- Cloud verification
- Machine learning detection
- Zero-day protection
- Untrusted app blocking

---

## 📊 Statistics Summary

| Category | Count | Details |
|----------|-------|---------|
| **Security Settings** | 550+ | Defender, ASR, BitLocker, Firewall, etc. |
| **Privacy Settings** | 700+ | Telemetry, Permissions, AI, Tracking |
| **Services Disabled** | 25 | DiagTrack, WerSvc, Diagnostics, etc. |
| **Tasks Disabled** | 60+ | CEIP, Appraiser, Data Collection |
| **Registry Keys** | 180+ | Telemetry/Privacy/Security |
| **Domains Blocked** | 80,101 | Malware + Ads + Tracking (hosts) |
| **Domains Blocked** | 200+ | Microsoft telemetry (firewall) |
| **Apps Removed** | 50+ | Bloatware, Xbox, 3D, Games |
| **ASR Rules** | 19 | Attack Surface Reduction |
| **Exploit Mitigations** | 13 | DEP, ASLR, CFG, SEHOP, etc. |
| **App Permissions** | 37 | Default-DENY categories |
| **AI Features Blocked** | 8 | Recall, Copilot, Paint AI, etc. |
| **Audit Categories** | 18 | Security event logging |

---

## 🎯 Quick Feature Lookup

**Want Maximum Security?**
→ Defender + ASR (19 rules) + BitLocker + Exploit Protection

**Want Maximum Privacy?**
→ Telemetry OFF (25 services) + App Permissions (37 categories) + AI Lockdown (8 features)

**Want Both?**
→ Enforce Mode = Everything!

**Want Performance?**
→ 50+ tasks disabled + Event log optimization + Visual effects optimized

**Want Control?**
→ Custom Mode = Pick what you want

**Made a Mistake?**
→ Backup/Restore = Complete undo

---

## 📚 Related Documentation

- **[Installation Guide](INSTALLATION.md)** - How to apply
- **[FAQ](FAQ.md)** - Common questions
- **[Quick Start](QUICKSTART.md)** - Get started in 5 minutes
- **[Changelog](CHANGELOG.md)** - What's new
- **[Project Structure](PROJECT_STRUCTURE.md)** - Technical details

---

**Last Updated:** October 2025 (v1.7.9)  
**Source:** [NoID Privacy GitHub](https://github.com/NexusOne23/noid-privacy)
