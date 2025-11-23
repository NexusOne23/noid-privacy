# 🛡️ NoID Privacy Pro - Enterprise-Grade Windows 11 Security & Privacy Hardening Tool

> **⚠️ DISCLAIMER: USE AT YOUR OWN RISK.**  
> This tool makes deep modifications to the Windows Registry and System Services. While extensive backups are created, the authors accept **no responsibility for any damage, data loss, or system instability**. Always review changes before applying.

<div align="center">

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![Windows 11](https://img.shields.io/badge/Windows%2011-25H2-0078D4.svg?logo=windows11)](https://www.microsoft.com/windows/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg?logo=gnu)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)]()

---

### 🔒 Complete Windows 11 Security Framework
**580+ Settings • 7 Modules • Full Backup & Restore**

[📥 Quick Start](#-quick-start) • [📚 Documentation](#documentation) • [🎯 Key Features](#-key-features) • [💬 Community](https://github.com/NexusOne23/noid-privacy/discussions)

---

![NoID Privacy Pro Framework](assets/framework-architecture.png)

**7 Independent Security Modules • Modular Design • Complete BAVR Pattern**

</div>

---

## ⚠️ CRITICAL: Domain-Joined Systems & System Backup

> **⚡ READ THIS BEFORE RUNNING** This tool modifies critical Windows security settings!

### 🏢 Domain-Joined Systems (Active Directory)

**WARNING:** This tool is **NOT recommended for production domain-joined systems** without AD team coordination!

**Why?**
- This tool modifies **local Group Policies**
- Domain Group Policies **override local policies every 90 minutes**
- Your hardening **may be reset automatically** by domain GPOs
- Can lead to configuration conflicts and "flapping" behavior

**RECOMMENDED USE CASES:**
- Standalone systems (Home/Workgroup)
- Home/Personal PCs (not domain-joined)
- Virtual machines (testing/lab environments)
- Air-gapped systems
- Test/development domain-joined systems (non-production)

**For Enterprise/Domain Environments:** 
- **Integrate these settings into your Domain Group Policies instead!** 
- Coordinate with your Active Directory team before using this tool

---

### 💾 System Backup REQUIRED

**Before running this tool, you MUST create:**

1. **Windows System Restore Point** (recommended)
2. **Full System Image/Backup** (critical!)
3. **VM Snapshot** (if running in virtual machine)

**Why?**
- This tool creates **internal backups** for rollback (Registry, Services, Tasks)
- However, a **full system backup** protects against:
 - Unforeseen system issues
 - Hardware failures during hardening
 - Configuration conflicts
 - Critical errors

**Backup Tools:**
- Windows Backup (Settings System Storage Backup)
- System Image (wbadmin, Macrium Reflect, Acronis)
- Hyper-V/VMware: Checkpoint/Snapshot

**⚠️ IMPORTANT: Create your backup BEFORE running the tool. The tool does NOT verify backup existence.**

---

## ⚡ In 30 Seconds

**What?** Microsoft Security Baseline + Advanced Hardening for Windows 11 25H2 
**How?** PowerShell: **Backup** **Apply** **Verify** **Restore** (100% reversible!) 
**For whom?** Professionals, power users, SMBs **without Intune/Active Directory**

**580+ Security Settings 7 Modules 100% BAVR Coverage Production-Ready**

---

## 🤔 Why "NoID Privacy" when it's mostly Security?

**Because security and privacy are inseparable. You can't have one without the other.**

**🛡️ Security Foundation**
- 425 settings: MS Security Baseline for Win11 25H2
- 20 settings: MS Security Baseline for Edge
- 19 rules: Attack Surface Reduction
- VBS + Credential Guard: Hardware-level protection

**🔒 Privacy Layer**
- DNS: Block telemetry, tracking, ads
- Telemetry: Settings, services & tasks off
- AntiAI: Recall, Copilot, AI features off
- Bloatware: Pre-installed apps removed

**🎯 The Result:** A hardened system that's both secure against attacks and private from surveillance.

---

## 🌟 Why NoID Privacy Pro?

<div align="center">

| **SECURITY** | **PRIVACY** | **RELIABILITY** | **SAFETY** |
|:---:|:---:|:---:|:---:|
| **Microsoft Baseline 25H2** | **AI Lockdown** | **Professional Quality** | **100% Reversible** |
| 425+ Hardening Settings | No Recall / Copilot / NPU | 580+ Verified Checks | BAVR Architecture |
| 19 ASR Rules (Block Mode) | Telemetry & Ads Blocked | Detailed Logging | Exact Pre-State Restore |
| Zero-Day CVE-2025-9491 | DNS-over-HTTPS (DoH) | Modular Design | 0 Data Loss Guaranteed |
| VBS & Credential Guard | Edge Browser Hardened | Open Source / Auditable | Safe for Production |

** [3-Minute Quick Start](#-quick-start)** **[Full Feature List](Docs/FEATURES.md)**

</div>

---

## 🚀 What Makes This Different?

**Full BAVR pattern (Backup → Apply → Verify → Restore) • Zero external binaries • 100% native PowerShell**

| Feature | **NoID Privacy Pro** | HardeningKitty | ChrisTitus winutil | O&O ShutUp10++ |
|:---|:---:|:---:|:---:|:---:|
| **Focus** | **MS Baseline 25H2 + ASR + DNS + Privacy (580+ settings)** | CIS/MS baseline audit & CSV-based hardening | System tweaks, debloat & app installs | Privacy toggles & telemetry control |
| **BAVR Pattern** | **Backup → Apply → Verify → Restore (all modules)** | Audit + HailMary apply + partial restore | System Restore point (no verify) | System Restore + profile export |
| **Verification** | **580+ automated compliance checks** | Audit mode with severity scoring | No compliance scan | No compliance scan |
| **Dependencies** | **Zero (runs on stock PS 5.1/7+)** | PowerShell only | winget/chocolatey required | Portable EXE (closed-source) |
| **AI Lockdown** | **24 policies (Copilot+/Recall/24H2)** | No dedicated AI profile | Individual AI tweaks | Multiple AI/Copilot toggles |

** BAVR = Backup-Apply-Verify-Restore** (Every change is reversible) 
** Air-Gapped Ready** No LGPO.exe, no DLLs, no external downloads

---

## 🔒 Our Privacy Promise

**"We practice what we preach"**

| | |
|---|---|
| 🍪 **Zero Cookies** | No cookie banners, no tracking cookies, no consent popups |
| 📊 **Zero Analytics** | No Google Analytics, no third-party tracking scripts |
| 🔍 **Zero Telemetry** | PowerShell tool and GUI app collect nothing |
| ✅ **100% Verifiable** | Open source - inspect the code yourself |

**Actions speak louder than privacy policies.** Unlike other "privacy" tools that track you, we actually respect your privacy.

---

## 🎯 Key Features

### 🔐 Security Baseline (425 Settings)

**Microsoft Security Baseline 25H2 - 100% Implementation**
- **335 Registry Policies** Computer + User Configuration
- **67 Security Template Settings** Password Policy, Account Lockout, User Rights, Security Options
- **23 Advanced Audit Policies** Complete security event logging
- **Credential Guard** Passwords can't be stolen from memory
- **BitLocker Policies** USB drive protection, enhanced PIN, DMA attack prevention
- **VBS & HVCI** Virtualization-based security

### 🛡️ Attack Surface Reduction (19 Rules)

**19 ASR Rules (18 Block + 1 Configurable)**
- Blocks ransomware, macros, exploits, credential theft
- Office/Adobe/Email protection
- Script & executable blocking
- PSExec/WMI: Audit mode (if management tools used), Block mode otherwise
- Configurable exceptions for compatibility

### 🌐 Secure DNS (3 Providers)

**DNS-over-HTTPS with Secure Default (REQUIRE)**
- **Cloudflare** (Default) Fastest, 1.1.1.1
- **Quad9** Malware blocking, GDPR-compliant
- **AdGuard** Ad/tracker blocking built-in
- REQUIRE mode (default): no unencrypted fallback
- ALLOW mode (optional): fallback allowed for VPN/mobile/enterprise networks
- IPv4 + IPv6 dual-stack support

### 🔒 Privacy Hardening (55+ Settings)

**3 Operating Modes**
- **MSRecommended** (Default) MS-supported, max compatibility
- **Strict** Maximum privacy (AllowTelemetry=0 Enterprise/Education only, Force Deny breaks UCC apps)
- **Paranoid** Hardcore (not recommended)

**Features:**
- Telemetry minimized to Security-Essential level
- Bloatware removal (policy-based on 25H2+ Ent/Edu)
- OneDrive telemetry off (sync functional)
- App permissions default-deny

### 🤖 AI Lockdown (24 Policies)

**8 AI Features + Master Switch (Blocks All Generative AI)**
- **Master Switch** Blocks ALL generative AI models system-wide
- **Windows Recall** Complete deactivation (component removal + protection)
- **Windows Copilot** System-wide disabled + hardware key remapped
- **Click to Do** Screenshot AI analysis disabled
- **Paint AI** Cocreator, Generative Fill, Image Creator all blocked
- **Notepad AI** GPT features disabled
- **Settings Agent** AI-powered settings search disabled

### 🌐 Edge Hardening (20 Policies)

**Microsoft Edge Security Baseline**
- SmartScreen enforced
- Tracking Prevention strict
- SSL/TLS hardening
- Extension security
- IE Mode restrictions

### 🔧 Advanced Security (44 Settings)

**Beyond Microsoft Baseline**
- **SRP .lnk Protection** CVE-2025-9491 zero-day mitigation
- **RDP Hardening** Disabled by default, TLS + NLA enforced
- **Legacy Protocol Blocking** SMBv1, NetBIOS, LLMNR, WPAD, PowerShell v2
- **TLS Hardening** 1.0/1.1 OFF, 1.2/1.3 ON
- **Windows Update** Interactive configuration
- **Finger Protocol** Blocked (ClickFix malware protection)

---

## BAVR Pattern - Our Unique Approach

**Every change is tracked, verified, and 100% reversible!**

```
[1/4] BACKUP Full system state backup before changes
[2/4] APPLY Settings applied with comprehensive logging
[3/4] VERIFY 580+ automated checks confirm success
[4/4] RESTORE One command reverts everything
```

**What sets us apart:**
- **100% Coverage** All 580+ settings verified (not just applied!)
- **Professional Code Quality** Advanced functions, comprehensive error handling
- **Complete Restore** Registry, Services, Tasks, Files - everything
- **Production-Ready** Tested on Windows 11 25H2, PowerShell 5.1+

**Before v2.1.0:** 89.4% verification coverage (62 settings missing) 
**After v2.1.0:** 100% verification coverage (all 580+ settings verified) 

---

## 📥 Quick Start

### ⚡ One-Liner Install (Recommended)

**Step 1:** Open PowerShell as Administrator
- Press `Win + X` Click **"Terminal (Admin)"**

**Step 2:** Run installer

```powershell
# Download and run (Windows 11 25H2 recommended)
irm https://raw.githubusercontent.com/NexusOne23/noid-privacy/main/install.ps1 | iex
```

**What it does:**
1. Checks Administrator privileges
2. Verifies Windows 11 25H2
3. Downloads latest release from GitHub
4. Extracts & unblocks all files
5. Starts interactive mode

**Alternative - Manual Install:**

```powershell
# 1. Clone repository
git clone https://github.com/NexusOne23/noid-privacy.git
cd noid-privacy

# 2. Run as Admin
.\Start-NoIDPrivacy.bat

# 3. Verify after reboot
.\Tools\Verify-Complete-Hardening.ps1
```

> **Downloaded ZIP?** Run `Start-NoIDPrivacy.bat` - it automatically unblocks all files!

---

## Usage Examples

### Interactive Mode (Recommended)

```powershell
# Start interactive menu
.\Start-NoIDPrivacy.bat

# Follow prompts:
# 1. Select modules (all or custom)
# 2. Choose settings (DNS provider, Privacy mode, etc.)
# 3. Automatic backup apply verify
# 4. Reboot prompt
```

### Direct Execution

```powershell
# Apply all modules
.\NoIDPrivacy.ps1 -Module All

# Apply specific module
.\NoIDPrivacy.ps1 -Module Privacy

# Dry-run (no changes)
.\NoIDPrivacy.ps1 -Module All -DryRun
```

### Verification

```powershell
# Full verification (580+ checks)
.\Tools\Verify-Complete-Hardening.ps1

# Expected output (all modules enabled):
# SecurityBaseline: 425/425 verified
# ASR: 19/19 verified
# DNS: 5/5 verified
# Privacy: 55+/55+ verified
# AntiAI: 24/24 verified
# EdgeHardening: 20/20 verified
# AdvancedSecurity: 44/44 verified
# Total: 580+/580+ (100%)
```

### Restore

```powershell
# Restore from latest backup
.\Core\Rollback.ps1 -RestoreLatest

# Or via interactive menu
.\Start-NoIDPrivacy.bat
# Select "Restore from backup"
```

---

## Module Overview

| Module | Settings | Description | Status |
|--------|----------|-------------|--------|
| **SecurityBaseline** | 425 | Microsoft Security Baseline 25H2 | v2.1.0 |
| **ASR** | 19 | Attack Surface Reduction Rules | v2.1.0 |
| **DNS** | 5 | Secure DNS with DoH encryption | v2.1.0 |
| **Privacy** | 55+ | Telemetry, Bloatware, OneDrive hardening | v2.1.0 |
| **AntiAI** | 24 | AI lockdown (8 features + master switch, 24 policies) | v2.1.0 |
| **EdgeHardening** | 20 | Microsoft Edge security | v2.1.0 |
| **AdvancedSecurity** | 44 | Beyond MS Baseline (SRP, Legacy protocols) | v2.1.0 |
| **TOTAL** | **580+** | **Complete Framework** | **Production** |

**Release Highlights:**

 **v2.1.0:** 100% verification coverage (all 580+ settings verified)
 **v2.1.0:** Improved Advanced Security module with SRP .lnk protection
 **v2.1.0:** Enhanced RDP hardening with TLS + NLA enforced
 **v2.1.0:** Legacy protocol blocking (SMBv1, NetBIOS, LLMNR, WPAD, PowerShell v2)
 **v2.1.0:** TLS hardening (1.0/1.1 OFF, 1.2/1.3 ON)
 **v2.1.0:** Windows Update interactive configuration
 **v2.1.0:** Finger Protocol blocked (ClickFix malware protection)
 **v2.1.0:** Enhanced Registry Backup (Smart JSON-Fallback for protected system keys)

** [Detailed Module Documentation](Docs/FEATURES.md)**

---

## Perfect For

### **Ideal Use Cases**

**Small/Medium Business (SMB)** 
 No Active Directory/Intune licenses 
 Cloud-first (Microsoft 365, Google Workspace) 
 Remote/hybrid work security 
 Compliance without enterprise infrastructure

**Freelancers & Consultants** 
 Client data protection 
 Secure workstations without domain 
 Professional security standards 
 Safe experimentation (complete backup)

**Power Users & Privacy-Conscious** 
 Real security, not just "debloat" 
 AI/Telemetry lockdown 
 Understand every setting 
 Full control + reversibility

**IT Pros Without Intune** 
 Standalone Windows 11 hardening 
 Microsoft Baseline compliance locally 
 Quick deploy for clients 
 No domain controller required

### **Not Ideal For**

**Enterprise with Intune/AD** 
 Use [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10) with Group Policy instead

**Windows 10 or Older** 
 This tool is designed for Windows 11 (24H2/25H2 recommended, 23H2 compatible)

**Legacy Software Dependencies** 
 If you rely on unsafe SMB1/RPC/DCOM

**Strict MDM Reporting** 
 If compliance must be centrally reported

---

## Requirements

**System Requirements:**
- **OS:** Windows 11 25H2 (Build 26200+) or 24H2 (Build 26100+) recommended
- **PowerShell:** 5.1+ (built-in)
- **Admin Rights:** Required
- **TPM:** 2.0 (for BitLocker, Credential Guard, VBS)
- **RAM:** 8 GB minimum (16 GB recommended for VBS)

**Tested & Compatible:**

| OS Version | Status |
|------------|--------|
| Windows 11 25H2 (Build 26200+) | **Fully Tested** |
| Windows 11 24H2 (Build 26100+) | Compatible |
| Windows 11 23H2 (Build 22631+) | Some features N/A |

---

## Security & Quality

### Code Quality

- **PSScriptAnalyzer:** Available for static analysis
- **Pester Tests:** Unit and integration tests in `Tests/` directory (`.\\Tests\\Run-Tests.ps1`)
- **Verification:** 580+ automated compliance checks in production
- **Production-Ready:** Professional error handling and comprehensive logging
- **Best Practices:** Advanced Functions, CmdletBinding, Validated Parameters

### What This Tool Does

 Hardens Windows 11 to enterprise standards 
 Implements Microsoft Security Baseline 25H2 
 Protects against zero-day exploits (CVE-2025-9491) 
 Minimizes telemetry to Security-Essential level 
 Locks down AI features (Recall, Copilot, etc.) 
 Configures BitLocker policies, Credential Guard, VBS 

### What This Tool Does NOT Do

 Install third-party antivirus (uses Windows Defender) 
 Configure domain-specific policies 
 Modify BIOS/UEFI settings 
 Break critical Windows functionality 
 Prevent re-enabling features 

### Reversibility

- **What CAN be restored:** Services, Registry, Firewall, DNS, Tasks, AI features
- **What CAN be auto-restored:** Most removed bloatware apps via `winget` during session restore (where mappings exist)
- **What may still need manual reinstall:** Unmapped/third-party bloatware apps (use Microsoft Store)
- **Backup System:** Complete system state before applying
- **REMOVED_APPS_LIST.txt:** Created during bloatware removal with a full list of removed apps for manual reinstall if needed
- **Documented Changes:** All changes logged

---

## Configuration

### Default Settings

All settings configured for **maximum security with maintained usability**:
- Services: Telemetry services controlled, critical services protected
- Firewall: Inbound blocked, outbound allowed
- Privacy: Default-deny for app permissions (user can enable individually)
- BitLocker: Policies set, user must enable manually
- AI Features: Disabled via Registry (100% reversible)

### Customization

All module settings can be customized via JSON files in `Modules/*/Config/`:

```powershell
# Example: Adjust DNS provider
Edit: Modules/DNS/Config/Providers.json

# Example: Modify Privacy mode
Edit: Modules/Privacy/Config/Privacy-MSRecommended.json

# Example: Configure ASR exceptions
Edit: Modules/ASR/Config/ASR-Rules.json
```

---

## Troubleshooting

> **Can't install software after hardening?** See [Temporarily Disable ASR Rule](#temporarily-disable-asr-rule-for-software-installation) for step-by-step solution

### Common Issues

**"Access Denied" errors** 
 Not running as Administrator 
 Right-click PowerShell "Run as Administrator"

**VBS/Credential Guard not active after reboot** 
 Hardware incompatibility (no TPM 2.0 or virtualization disabled) 
 Enable virtualization in BIOS/UEFI 
 Verify: `.\Tools\Verify-Complete-Hardening.ps1`

**BitLocker not activating** 
 No TPM 2.0 or insufficient disk space 
 Check TPM: `Get-Tpm` 
 Manual activation: Control Panel BitLocker

**ASR blocking legitimate software installation** 
 ASR rule "Block executable files unless they meet prevalence" blocks unknown installers 
 See [Temporarily Disable ASR Rule](#temporarily-disable-asr-rule-for-software-installation) below

---

### Temporarily Disable ASR Rule for Software Installation

**Problem:** ASR blocks installation of legitimate software (e.g., downloaded installers not in Microsoft's reputation database)

**Blocked Rule:** `01443614-cd74-433a-b99e-2ecdc07bfc25` ("Block executable files unless they meet prevalence, age, or trusted list")

**Solution:** Temporarily set the rule to AUDIT mode (warns only, doesn't block)

**Step 1: Disable Tamper Protection** (GUI method - easiest)
1. Press `Win` key Type "Windows Security" Enter
2. Go to: **Virus & threat protection**
3. Click: **Manage settings**
4. Scroll down to: **Tamper Protection** Toggle **OFF**

**Step 2: Set ASR Rule to AUDIT** (PowerShell as Admin)

```powershell
# Get current ASR configuration
$currentIds = (Get-MpPreference).AttackSurfaceReductionRules_Ids
$currentActions = (Get-MpPreference).AttackSurfaceReductionRules_Actions

# Convert to arrays
$ids = @($currentIds)
$actions = @($currentActions)

# Find the prevalence rule
$targetGuid = "01443614-cd74-433a-b99e-2ecdc07bfc25"
$index = [array]::IndexOf($ids, $targetGuid)

# Set to AUDIT (2 = Audit, 1 = Block)
$actions[$index] = 2

# Apply changes
Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions

Write-Host " ASR Prevalence Rule: AUDIT (Installation now possible)" -ForegroundColor Green
```

**Step 3: Install your software**

**Step 4: Re-enable the ASR Rule** (PowerShell as Admin)

```powershell
# Get current ASR configuration
$currentIds = (Get-MpPreference).AttackSurfaceReductionRules_Ids
$currentActions = (Get-MpPreference).AttackSurfaceReductionRules_Actions

# Convert to arrays
$ids = @($currentIds)
$actions = @($currentActions)

# Find the prevalence rule
$targetGuid = "01443614-cd74-433a-b99e-2ecdc07bfc25"
$index = [array]::IndexOf($ids, $targetGuid)

# Set back to BLOCK
$actions[$index] = 1

# Apply changes
Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions

Write-Host " ASR Prevalence Rule: BLOCK (Protection restored)" -ForegroundColor Green
```

**Step 5: Re-enable Tamper Protection** (Windows Security Toggle ON)

**IMPORTANT:** Always re-enable both the ASR rule AND Tamper Protection after installation!

---

### Windows Insider Program Compatibility

**Problem:** After applying Privacy hardening (MSRecommended mode), Windows Insider enrollment requires extra steps.

**Cause:** Privacy module sets `AllowTelemetry=1` (Required diagnostic data) via Group Policy, which prevents the user from enabling "Optional diagnostic data" in Settings - a requirement for Insider Program enrollment.

**Solution:**

**Step 1: Temporarily remove the telemetry policy** (PowerShell as Admin)

```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
```

**Step 2: Reboot** (recommended for policy changes to take effect)

```powershell
Restart-Computer
```

**Step 3: Join Windows Insider Program**
1. Go to: Settings > Windows Update > Windows Insider Program
2. Click: **Get Started**
3. When prompted, enable "Optional diagnostic data"
4. Complete Insider enrollment and select your channel (Dev/Beta/Release Preview)

**Step 4 (Optional): Re-apply Privacy hardening**

```powershell
.\NoIDPrivacy.ps1 -Module Privacy
```

**Note:** Once enrolled in the Insider Program, Windows will continue to receive preview builds even after re-applying Privacy hardening with `AllowTelemetry=1`.

---

### Logs

All operations logged to:
```
Logs/NoIDPrivacy_YYYYMMDD_HHMMSS.log
```

**Example:** `NoIDPrivacy_20251117_142345.log`

---

## Documentation

### Core Documentation
- **[Features](Docs/FEATURES.md)** - Complete 580+-setting reference
- **[Changelog](CHANGELOG.md)** - Version history
- **[Quick Start](#-quick-start)** - Installation guide (see above)
- **[Troubleshooting](#troubleshooting)** - Common issues (see above)

### 💬 Community

- **[💬 Discussions](https://github.com/NexusOne23/noid-privacy/discussions)** - Questions, ideas, and commercial licensing inquiries
- **[🐛 Issues](https://github.com/NexusOne23/noid-privacy/issues)** - Bug reports only
- **[📚 Documentation](Docs/FEATURES.md)** - Complete feature reference

---

## Acknowledgments

- **Microsoft Security Baseline Team** for Windows 11 25H2 guidance
- **PowerShell Community** for best practices and patterns
- **Open Source Contributors** for testing and feedback

---

## 📜 License

### Dual-License Model

NoID Privacy Pro is available under a **dual-licensing** model:

#### 🆓 Open Source License (GPL v3.0)

**For individuals, researchers, and open-source projects:**

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0). 

✅ **You CAN:**
- ✔️ Use the software freely for personal and commercial purposes
- ✔️ Modify the source code
- ✔️ Distribute the software
- ✔️ Distribute your modifications

⚠️ **You MUST:**
- 📝 Disclose your source code when distributing
- 🔓 License your modifications under GPL v3.0
- 📄 Include the original copyright notice
- 📋 State significant changes made to the software

[Read the full GPL v3.0 License](LICENSE)

#### 💼 Commercial License

**For companies and organizations that want to:**
- Integrate this software into closed-source/proprietary products
- Distribute this software without disclosing source code
- Receive dedicated commercial support and warranties
- Avoid GPL v3.0 copyleft requirements

**Contact:** Open a [💬 GitHub Discussion](https://github.com/NexusOne23/noid-privacy/discussions) to inquire about commercial licensing.

---

### Third-Party Components

This software implements security configurations based on:
- **Microsoft Security Baselines** - Public documentation
- **Microsoft Defender ASR Rules** - Official documentation  
- **DNS Providers** - Cloudflare, Quad9, AdGuard (public services)

Microsoft, Windows, and Edge are trademarks of Microsoft Corporation. This project is not affiliated with Microsoft.

---

## ⚠️ Disclaimer

This script modifies critical system settings. Use at your own risk. Always:
1. **Create a system backup** before running
2. **Test in a VM** first
3. **Review the code** to understand changes
4. **Verify compatibility** with your environment

The authors are not responsible for any damage or data loss.

---

## Project Status

**Current Version:** 2.1.0 
**Last Updated:** November 23, 2025 
**Status:** Production-Ready

### Release Highlights v2.1.0

 All 7 modules production-ready (580+ settings) 
 100% BAVR coverage (was 89.4%) 
 Zero-day protection (CVE-2025-9491 via SRP) 
 Professional code quality with comprehensive testing 
 Complete verification: EdgeHardening (20) + AdvancedSecurity (44) 
 Bloatware reinstall list with instructions

** [See Full Changelog](CHANGELOG.md)**

---

<div align="center">

**Made with 🛡️ for the Windows Security Community**

[Report Bug](https://github.com/NexusOne23/noid-privacy/issues) [Request Feature](https://github.com/NexusOne23/noid-privacy/issues) [Discussions](https://github.com/NexusOne23/noid-privacy/discussions)

 **Star this repo** if you find it useful!

</div>



