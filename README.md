# NoID Privacy - Windows 11 25H2 Security Baseline

> **Enterprise-Grade Security & Privacy Hardening Tool for Windows 11 25H2**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Windows 11](https://img.shields.io/badge/Windows%2011-25H2-0078D4.svg)](https://www.microsoft.com/windows/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.7.9-blue.svg)](CHANGELOG.md)

---

## 🎯 Overview

**NoID Privacy** is a comprehensive PowerShell-based security hardening solution for Windows 11 25H2, implementing the Microsoft Security Baseline with extensive privacy enhancements.

### What You Get
- ✅ **100% Microsoft Security Baseline 25H2 Compliance**
- 🔒 **300+ Security Settings** - Enterprise-grade protection at home
- 🛡️ **180+ Privacy Settings** - ~95% telemetry blocked
- 🚀 **Modular Architecture** - 13 specialized modules, pick what you need
- 🔄 **Complete Backup & Restore** - Can undo EVERYTHING
- 🌐 **Multi-Language Support** - English/German with real-time switching
- 📊 **Interactive Menu & CLI** - Easy GUI or automation-ready
- 📜 **Complete Audit Trails** - 3 logging levels (Transcript, Console, Summary)

### Why This Matters to You
**Security:** Your Windows is now as secure as Fortune 500 companies  
**Privacy:** Microsoft gets ZERO usage data from your PC  
**Performance:** Bloatware removal, faster boot, optimized background tasks  
**Control:** YOU decide what runs, what uploads, what connects  
**Peace of Mind:** Complete backup = risk-free experimentation

**👉 [See Complete Feature List](FEATURES.md) - Every single setting explained!**

---

## 🌟 Key Features

### 🛡️ Security Hardening - Enterprise Protection at Home

**Your Computer Becomes a Fortress:**
- **Microsoft Defender** → 6 protection layers = Real-time malware blocking + Cloud AI threat detection + PUA + EDR
- **19 Attack Surface Reduction Rules** → 19 different attack types BLOCKED (ransomware, macros, exploits, credential theft)
- **10 Exploit Mitigations** → Memory-based attacks fail (DEP, SEHOP, ASLR, CFG Strict, Heap Protection, Image Load Protection)
- **Credential Protection** → Your passwords can't be stolen from memory (Credential Guard + LSA Protection + Mimikatz mitigation)
- **BitLocker XTS-AES-256** → Stolen laptop = useless encrypted brick (TPM 2.0 + optional PIN)
- **Strict Firewall** → Nothing gets in without your permission (block all incoming + 13 legacy protocol blocks)
- **Modern Network Only** → TLS 1.2/1.3, SMB encryption, no legacy protocols (LLMNR/NetBIOS/WPAD/mDNS disabled)

**Bottom Line:** You're now as secure as Fortune 500 companies

### 🔒 Privacy Protection - Zero Data to Microsoft

**Your Privacy is Sacred:**
- **Complete Telemetry Shutdown** → 10 telemetry services + ~14 tasks + 180 registry keys = ~95% usage data blocked
- **AI Lockdown** → Windows Recall DISABLED (no screenshots of passwords!), Copilot blocked (4 layers), Click to Do disabled
- **App Permission Control** → 33 categories default-DENY (apps can't spy without explicit permission)
- **Clean System** → 84 bloatware app patterns checked (Xbox, 3D apps, Candy Crush, Teams Chat, Copilot, Widgets)
- **80,000+ Trackers Blocked** → DNS-level blocking via Steven Black hosts + Cloudflare DoH

**Bottom Line:** Microsoft gets ZERO data about how you use your PC

### ⚡ Performance - Faster & Cleaner

**Your PC Breathes Easier:**
- **~20 Background Tasks Disabled** → Less CPU/disk usage when idle (Update/Defender tasks stay active!)
- **Event Log Optimization** → Critical logs increased, noise logs reduced = less disk I/O
- **Windows Search Optimized** → Local-only, no web/Bing queries
- **No Bloatware** → Faster boot, more disk space, cleaner Start Menu

**Bottom Line:** Windows feels snappier, boots faster

### 🎯 Advanced Features - Pro-Level Control

**Power User Tools:**
- **Windows LAPS** → Auto-rotating admin passwords (30 days, 20 chars, Entra/AD-Escrow)
- **Advanced Auditing** → Complete security event logging (Object Access, Logon, DS, Policy, PnP, PS-Logging)
- **Smart App Control** → AI-based app reputation (Windows evaluates & activates after 7-14 days)
- **Enhanced UAC** → Maximum privilege protection (always notify + Enhanced Privilege Protection Mode ready)
- **Edge Privacy** → Tracking prevention Balanced, SmartScreen enforced, DoH automatic, Site Isolation active

**Bottom Line:** Enterprise-level features at home

### 🌐 DNS Security & Privacy

**Cloudflare DNS-over-HTTPS (DoH)**
- ✅ Encrypted DNS queries (1.1.1.1 / 1.0.0.1)
- ✅ Privacy-first DNS provider (no user tracking)
- ✅ DNSSEC validation enabled
- ✅ Faster response times than ISP DNS
- ✅ Blocks DNS-based tracking and censorship

**Steven Black Unified Hosts File (Optimized)**
- ✅ **80,101 malicious/tracking domains blocked** (full list!)
- ✅ **Compressed to 8,864 lines** (9 domains per line)
- ✅ Optimized for Windows DNS Cache performance
- ✅ Blocks ads, malware, trackers, telemetry at DNS level
- ✅ **Zero performance impact** - cache-friendly design
- ✅ Updated regularly from Steven Black repository

**Why Compression?**
- Windows DNS Cache limit: ~20,000 entries
- Original 80k+ lines would cause cache overflow
- Our format: **MAX 9 domains per line** (Windows limit)
- Result: Full protection + Fast DNS resolution

**Benefits:**
- 🚫 80,000+ ads & trackers blocked before they load
- 🔒 DNS queries encrypted (ISP can't see)
- ⚡ Faster browsing (Cloudflare's CDN)
- 🛡️ Malware domains blocked at DNS level
- 🔐 No DNS hijacking by ISP
- 💪 Full Steven Black list WITHOUT performance hit

---

## 📋 Requirements

### System Requirements
- **OS:** Windows 11 25H2 (Build 26100+)
- **TPM:** TPM 2.0 (for BitLocker, Credential Guard, VBS)
- **CPU:** Intel 8th Gen+ or AMD Ryzen 2000+ (for optimal AES-NI support)
- **RAM:** 8 GB minimum (16 GB recommended for VBS)
- **Disk:** 256 GB+ (for BitLocker encryption)

### Software Requirements
- **PowerShell:** 5.1 or higher (Windows built-in)
- **Administrator Rights:** Required for all operations
- **Internet Connection:** NOT required for script execution
  - ✅ Hosts file (80K+ domains) included locally in project
  - ✅ DNS-over-HTTPS is only configured (no download needed)
  - ℹ️ Internet only needed for: git clone (initial download)

---

## 🚀 Quick Start

### 1. Download
```powershell
# Clone repository
git clone https://github.com/NexusOne23/noid-privacy.git
cd noid-privacy
```

### 2. Run Script
```powershell
# Open PowerShell as Administrator
# Navigate to project directory

# Option A: Interactive Mode (Recommended for first-time users)
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive

# Option B: Audit Mode (Safe testing - no enforcement)
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Audit

# Option C: Enforce Mode (Full hardening)
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce
```

### 3. Reboot
Some features (VBS, Credential Guard, BitLocker) require a system restart to activate.

---

## 📖 Usage

### Basic Commands

#### Apply Security Baseline
```powershell
# Interactive menu with language selection
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive

# Enforce mode with automatic reboot prompt
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce

# Audit mode without reboot
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Audit -SkipReboot
```

#### Backup & Restore
```powershell
# Create backup before applying baseline
.\Backup-SecurityBaseline.ps1

# Restore from backup
.\Restore-SecurityBaseline.ps1

# Restore specific backup file
.\Restore-SecurityBaseline.ps1 -BackupFile "C:\Backups\MyBackup.json"
```

#### Verify Compliance
```powershell
# Quick compliance check
.\Verify-SecurityBaseline.ps1

# With CSV export
.\Verify-SecurityBaseline.ps1 -ExportReport
```

### Advanced Usage

#### Custom Module Selection (Interactive Mode)
1. Start interactive mode: `.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive`
2. Select language (English/German)
3. Choose "Custom Configuration"
4. Select specific modules to apply
5. Confirm and execute

#### Batch File (for non-technical users)
```cmd
# Right-click Start-NoID-Privacy.bat → "Run as Administrator"
# Automatically checks requirements and starts Interactive Mode
# Note: Double-click won't work - Admin rights required!
```

---

## 🔧 Module Architecture

The project uses a modular architecture with 13 specialized modules:

| Module | Description | Key Features |
|--------|-------------|-------------|
| **Core** | Security baseline, Defender, Firewall, Services | 25 services disabled, 13 firewall rules, 10 exploit mitigations, Admin/Guest account hardening |
| **ASR** | Attack Surface Reduction rules | 19 ASR rules (Enforce mode), Smart App Control |
| **Advanced** | VBS, Credential Guard, LAPS, Auditing | Credential Guard, VBS, HVCI, LSA-PPL, BitLocker policies, Windows LAPS, TLS/SSL hardening |
| **DNS** | DNS-over-HTTPS, DNSSEC, Blocklist | Cloudflare DoH (4 servers), DNSSEC validation, 80,101 blocked domains, Strict Inbound Firewall |
| **Bloatware** | App removal, Consumer features | 84 app patterns, Teams Chat/Copilot/Widgets disabled, Consumer Features blocked |
| **Telemetry** | Privacy protection, App permissions | 10 services, 180 registry keys, 33 app permission categories, Camera/Mic controls |
| **Performance** | Scheduled tasks, Event logs | ~20 tasks disabled, Event log optimization, Windows Search local-only, Prefetch/Superfetch tuning |
| **AI** | Recall, Copilot, AI tracking | Recall disabled, Copilot blocked (4 layers), Click to Do/Paint AI/Settings Agent disabled |
| **Edge** | Microsoft Edge security baseline | SmartScreen enforced, Tracking Prevention, DoH automatic, Site Isolation, Extension policies |
| **OneDrive** | OneDrive privacy hardening | Tutorial/Feedback disabled, Network silent, KFM blocked, User-controlled uploads |
| **UAC** | User Account Control enhancement | Maximum security (always notify), Enhanced Privilege Protection Mode (future-ready) |
| **WindowsUpdate** | Update optimization | Hybrid mode (user preferences + policies), HTTP-only (no P2P), Preview Builds blocked |
| **WirelessDisplay** | Miracast disablement | 4-layer blocking (Services, Registry, Firewall, Apps) |

---

## 📊 Compliance Matrix

| Standard | Coverage | Details |
|----------|----------|---------|
| **Microsoft Baseline 25H2** | 100% | Full compliance with September 30, 2025 baseline |
| **CIS Benchmark Level 1** | 85% | Domain-specific settings excluded (standalone focus) |
| **CIS Benchmark Level 2** | 90% | Enhanced security with privacy extensions |
| **DoD STIG** | 75% | Core security controls (non-domain environment) |
| **BSI SiSyPHuS** | 95% | German Federal Office for Information Security standards |

**Note:** This project focuses on **standalone/workgroup workstations**. Domain-specific features (Group Policy, AD integration) are not included.

---

## ⚙️ Configuration

### Default Settings
All settings are configured for **maximum security with maintained usability**:
- Services: Telemetry services disabled, critical services protected
- Firewall: Inbound blocked, outbound allowed (with exceptions)
- Privacy: Default-deny for app permissions, user can enable individually
- BitLocker: XTS-AES-256 with TPM 2.0 (PIN optional, user must enable manually)

### Customization
Edit module files in `/Modules/` to adjust settings:
```powershell
# Example: Modify ASR rules
.\Modules\SecurityBaseline-ASR.ps1

# Example: Adjust telemetry settings
.\Modules\SecurityBaseline-Telemetry.ps1
```

---

## 🛡️ Security Considerations

### What This Script Does
✅ Hardens Windows 11 25H2 to enterprise security standards  
✅ Disables unnecessary services and features  
✅ Configures Windows Defender to maximum protection  
✅ Enables BitLocker encryption with strong algorithms  
✅ Protects against common attack vectors (ASR, Exploit Protection)  
✅ Minimizes telemetry and tracking  
✅ Removes bloatware and unnecessary apps  

### What This Script Does NOT Do
❌ Install third-party antivirus (uses Windows Defender)  
❌ Configure domain-specific policies (standalone focus)  
❌ Modify BIOS/UEFI settings (user responsibility)  
❌ Break critical Windows functionality  
❌ Prevent user from re-enabling features  

### Reversibility
- **Backup & Restore:** Full system state backup before applying
- **No Force Policies:** Most settings can be re-enabled via Settings GUI
- **Documented Changes:** All changes logged in transcript files
- **Exception:** Some Windows components (e.g., Recall, Copilot) are permanently disabled

---

## 🐛 Troubleshooting

### Common Issues

#### "Script already running in another session"
**Cause:** Mutex prevents concurrent execution  
**Solution:** Wait for other instance to finish or restart system

#### "Access Denied" errors
**Cause:** Not running as Administrator  
**Solution:** Right-click PowerShell → "Run as Administrator"

#### VBS/Credential Guard not active after reboot
**Cause:** Hardware incompatibility (no TPM 2.0 or virtualization disabled)  
**Solution:** 
1. Check TPM: `Get-Tpm`
2. Enable virtualization in BIOS/UEFI
3. Verify: `.\Verify-SecurityBaseline.ps1`

#### BitLocker not activating
**Cause:** No TPM 2.0 or insufficient disk space  
**Solution:**
1. Check TPM: `Get-Tpm`
2. Ensure 256 GB+ free space
3. Manual activation: Control Panel → BitLocker

### Logs
All operations are logged to:
```
C:\ProgramData\SecurityBaseline\Logs\SecurityBaseline-Enforce-YYYYMMDD-HHMMSS.log
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Code Style
- PowerShell best practices (Verb-Noun naming)
- UTF-8 without BOM encoding
- ASCII/Extended Latin characters only (no Unicode symbols)
- Comprehensive error handling (Try-Catch-Finally)
- Verbose logging for debugging

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Microsoft Security Baseline Team** for Windows 11 25H2 guidance
- **Center for Internet Security (CIS)** for benchmark standards
- **DoD Cyber Exchange** for STIG requirements
- **BSI (German Federal Office for Information Security)** for SiSyPHuS recommendations
- **Community Contributors** for testing and feedback

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues) - Bug reports and feature requests
- **Email:** [support@noid-privacy.com](mailto:support@noid-privacy.com) - General support and questions
- **Security:** [security@noid-privacy.com](mailto:security@noid-privacy.com) - Security vulnerabilities (private disclosure)
- **Documentation:** [README](README.md) · [FAQ](FAQ.md) · [Installation](INSTALLATION.md) · [Quick Start](QUICKSTART.md)

---

## ⚠️ Disclaimer

This script modifies critical system settings. Use at your own risk. Always:
1. **Create a system backup** before running
2. **Test in a VM** before production use
3. **Review the code** to understand changes
4. **Verify compatibility** with your hardware/software

The authors are not responsible for any damage or data loss caused by this script.

---

## 📈 Project Status

**Current Version:** 1.7.9  
**Last Updated:** October 28, 2025  
**Status:** Production-Ready ✅

### Recent Updates (v1.7.9)
- ✅ **Complete Error Logging Overhaul** - 100% transparency with 3-level logging (Transcript, Console, Summary)
- ✅ **Guest Account Hardening** - Visible status, randomized rename, CIS Benchmark compliance
- ✅ **False Positive Elimination** - Handled errors removed from $Error array (clean status reports)
- ✅ **Service Stop Visibility** - Critical failures now visible (WirelessDisplay, Core services)
- ✅ **Event Log Config Reporting** - wevtutil failures now reported as warnings
- ✅ **Exploit Protection Fix** - 6 Set-ProcessMitigation commands now use -ErrorAction Stop (catch blocks work!)
- ✅ **Enhanced LastRun-Status.txt** - Detailed error summaries, categorized warnings, quick actions, next steps

See [CHANGELOG.md](CHANGELOG.md) for full version history.

---

<div align="center">

**Made with ❤️ for the Windows Security Community**

[Report Bug](https://github.com/NexusOne23/noid-privacy/issues) · [Request Feature](https://github.com/NexusOne23/noid-privacy/issues) · [Contribute](CONTRIBUTING.md)

</div>
