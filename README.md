<div align="center">

# 🛡️ NoID Privacy

### Windows 11 Security & Privacy Hardening Framework

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![Windows 11](https://img.shields.io/badge/Windows%2011-25H2-0078D4.svg?logo=windows11)](https://www.microsoft.com/windows/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg?logo=gnu)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.2.4-blue.svg)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)](CHANGELOG.md)
[![GitHub Stars](https://img.shields.io/github/stars/NexusOne23/noid-privacy?style=flat&logo=github)](https://github.com/NexusOne23/noid-privacy/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/NexusOne23/noid-privacy?style=flat)](https://github.com/NexusOne23/noid-privacy/commits)
[![Website](https://img.shields.io/badge/Website-noid--privacy.com-0078D4?style=flat)](https://noid-privacy.com)

**630+ Settings • 7 Modules • BAVR Pattern (Backup-Apply-Verify-Restore)**

[📥 Quick Start](#-quick-start) • [📚 Documentation](#-documentation) • [🎯 Key Features](#-key-features) • [💬 Community](https://github.com/NexusOne23/noid-privacy/discussions)

---

![NoID Privacy Framework](assets/framework-architecture.png)

**7 Independent Security Modules • Modular Design • BAVR Pattern**

[![Get NoID Privacy PRO for Windows](https://img.shields.io/badge/Get_PRO_for_Windows-€39.99_One--Time_Purchase-success?style=for-the-badge&logo=windows)](https://noid-privacy.com)

</div>

> **⚠️ DISCLAIMER:** This tool modifies Windows Registry and System Services. Full backups are created automatically (BAVR pattern), but always [create a system backup](#-system-backup-required) before running. Use at your own risk.

---

<details>
<summary><strong>⚠️ CRITICAL: Domain-Joined Systems & System Backup (click to expand)</strong></summary>

### 🏢 Domain-Joined Systems (Active Directory)

**WARNING:** This tool is **NOT recommended for production domain-joined systems** without AD team coordination!

- This tool modifies **local Group Policies**
- Domain Group Policies **override local policies every 90 minutes**
- Your hardening **may be reset automatically** by domain GPOs

**Recommended for:** Standalone systems, Home/Personal PCs, VMs, air-gapped systems, test/dev environments.

**For Enterprise/Domain Environments:** Integrate these settings into your Domain Group Policies instead!

### 💾 System Backup REQUIRED

**Before running this tool, create:**

1. **Windows System Restore Point** (recommended)
2. **Full System Image/Backup** (critical!)
3. **VM Snapshot** (if running in virtual machine)

The tool creates internal backups for rollback (BAVR pattern), but a full system backup protects against unforeseen issues, hardware failures, and configuration conflicts.

**Backup Tools:** Windows Backup, wbadmin, Macrium Reflect, Acronis, Hyper-V/VMware Snapshots.

</details>

---

## ⚡ In 30 Seconds

**What?** Microsoft Security Baseline + Advanced Hardening for Windows 11 25H2 
**How?** PowerShell: **Backup** **Apply** **Verify** **Restore** (registry/services/firewall changes are reversible; some bloatware removals require manual reinstall via Microsoft Store)
**For whom?** Professionals, power users, SMBs **without Intune/Active Directory**

**630+ Security Settings • 7 Modules • BAVR Pattern for all applied settings**

*_For all settings changed by NoID Privacy. Some bloatware removals on certain editions are intentionally not auto-reversible; see "Reversibility" below._

---

## 🤔 Why "NoID Privacy" when it's mostly Security?

**Because security and privacy are inseparable. You can't have one without the other.**

**🛡️ Security Foundation**
- 425 settings: MS Security Baseline for Win11 25H2
- 24 settings: MS Security Baseline for Edge
- 19 rules: Attack Surface Reduction
- VBS + Credential Guard*: Hardware-level protection

**🔒 Privacy Layer**
- DNS: Block telemetry, tracking, ads (DoH)
- Telemetry: 3 modes (MSRecommended/Strict/Paranoid)
- AntiAI: 15 AI features disabled (Recall, Copilot, Paint AI, Notepad AI, Edge AI, etc.)
- Bloatware: 24 pre-installed apps removed

**🎯 The Result:** A hardened system that's both secure against attacks and private from surveillance.

*_Credential Guard requires Windows 11 Enterprise or Education_

---

## 🌟 Why NoID Privacy?

<div align="center">

| **SECURITY** | **PRIVACY** | **RELIABILITY** | **SAFETY** |
|:---:|:---:|:---:|:---:|
| **Microsoft Baseline 25H2** | **AI Lockdown** | **Comprehensive Verification** | **Reversible Design** |
| 630+ Security Settings | No Recall / Copilot / AI | Verification covers all applied settings | BAVR Architecture |
| 19 ASR Rules (17 Block + 2 Configurable) | Telemetry & Ads Blocked | Detailed Logging | Exact Pre-State Restore |
| Zero-Day CVE-2025-9491 | DNS-over-HTTPS (DoH) | Modular Design | Designed for Zero Data Loss |
| VBS & Credential Guard* | Edge Browser Hardened | Open Source / Auditable | Tested on Windows 11 25H2 |

👉 [3-Minute Quick Start](#-quick-start) • 📖 [Full Feature List](Docs/FEATURES.md)

</div>

---

## 🚀 What Makes This Different?

**Full BAVR pattern (Backup → Apply → Verify → Restore) • Zero external binaries • 100% native PowerShell**

| Feature | **NoID Privacy** | HardeningKitty | ChrisTitus winutil | O&O ShutUp10++ |
|:---|:---:|:---:|:---:|:---:|
| **Focus** | **MS Baseline 25H2 + ASR + DNS + Privacy (630+ settings)** | CIS/MS baseline audit & CSV-based hardening | System tweaks, debloat & app installs | Privacy toggles & telemetry control |
| **BAVR Pattern** | **Backup → Apply → Verify → Restore (all modules)** | Audit + HailMary apply + partial restore | System Restore point (no verify) | System Restore + profile export |
| **Verification** | **630+ automated compliance checks** | Audit mode with severity scoring | No compliance scan | No compliance scan |
| **Dependencies** | **Zero (runs on stock PS 5.1/7+)** | PowerShell only | winget/chocolatey required | Portable EXE (closed-source) |
| **AI Lockdown** | **32 policies (Copilot+/Recall/25H2)** | No dedicated AI profile | Individual AI tweaks | Multiple AI/Copilot toggles |

🔄 **BAVR** = Backup-Apply-Verify-Restore (Every change is reversible) 
✈️ **Air-Gapped Ready** — No LGPO.exe, no DLLs, no external downloads

---

## 🔒 Our Privacy Promise

**"We practice what we preach"**

| | |
|---|---|
| 🍪 **Zero Cookies** | No cookie banners, no tracking cookies, no consent popups |
| 📊 **Zero Analytics** | No Google Analytics, no third-party tracking scripts |
| 🔍 **Zero Telemetry** | No usage tracking, no telemetry – only minimal license validation |
| ✅ **100% Verifiable** | Open source - inspect the code yourself |

**Actions speak louder than privacy policies.** Unlike other "privacy" tools that track you, we actually respect your privacy.

---

## 🎯 Key Features

### 🔐 Security Baseline (425 Settings)

**Implements the full Microsoft Security Baseline for Windows 11 v25H2**
- **335 Registry Policies** Computer + User Configuration
- **67 Security Template Settings** Password Policy, Account Lockout, User Rights, Security Options
- **23 Advanced Audit Policies** Complete security event logging
- **Credential Guard*** Passwords can't be stolen from memory (Enterprise/Education only)
- **BitLocker Policies** USB drive protection, enhanced PIN, DMA attack prevention
- **VBS & HVCI** Virtualization-based security

### 🛡️ Attack Surface Reduction (19 Rules)

**19 ASR Rules (17 Block + 2 Configurable)**
- Helps block common ransomware, macro, exploit, and credential theft techniques
- Office/Adobe/Email protection
- Script & executable blocking
- PSExec/WMI: Audit mode (if management tools used), Block otherwise
- New/Unknown Software: Audit mode (if installing untrusted software), Block otherwise

### 🌐 Secure DNS (3 Providers)

**DNS-over-HTTPS with Secure Default (REQUIRE)**
- **Quad9** (Default) Security-focused, malware blocking, 9.9.9.9
- **Cloudflare** Fastest resolver, 1.1.1.1
- **AdGuard** Ad/tracker blocking built-in
- REQUIRE mode (default): no unencrypted fallback
- ALLOW mode (optional): fallback allowed for VPN/mobile/enterprise networks
- IPv4 + IPv6 dual-stack support

### 🔒 Privacy Hardening (78 Settings)

**3 Operating Modes**
- **MSRecommended** (Default) MS-supported, max compatibility
- **Strict** Maximum privacy (AllowTelemetry=0 Ent/Edu only, Teams/Zoom work)
- **Paranoid** Hardcore (Force Deny ALL - BREAKS Teams/Zoom!)

**Features:**
- Telemetry minimized to Security-Essential level
- Bloatware removal (policy-based on 25H2+ Ent/Edu)
- OneDrive telemetry off (sync functional)
- App permissions configurable per mode

### 🤖 AI Lockdown (32 Policies)

**15 AI Features Disabled (incl. Master Switch)**
- **Master Switch** Disables generative AI models system-wide
- **Windows Recall** Complete deactivation (component removal + protection)
- **Windows Copilot** System-wide disabled + hardware key remapped
- **Click to Do** Screenshot AI analysis disabled
- **Paint AI** Cocreator, Generative Fill, Image Creator all blocked
- **Notepad AI** GPT features disabled
- **Settings Agent** AI-powered settings search disabled

### 🌐 Edge Hardening (24 Policies)

**Microsoft Edge Security Baseline**
- SmartScreen enforced
- Tracking Prevention strict
- SSL/TLS hardening
- Extension security
- IE Mode restrictions

### 🔧 Advanced Security (50 Settings)

**Beyond Microsoft Baseline**
- **SRP .lnk Protection** — CVE-2025-9491 zero-day mitigation
- **RDP Hardening** — Disabled by default, TLS + NLA enforced
- **Wireless Display Security** — Miracast hardening, screen interception protection
- **Legacy Protocol Blocking** — SMBv1, NetBIOS, LLMNR, WPAD, PowerShell v2
- **TLS Hardening** — 1.0/1.1 OFF, 1.2/1.3 ON
- **UPnP/SSDP Blocking** — Port forwarding attack prevention
- **Discovery Protocols** — Optional WS-Discovery + mDNS disable (Maximum profile)
- **Windows Update** — Interactive configuration
- **Finger Protocol** — Blocked (ClickFix malware protection)

📖 [Detailed Feature Documentation](Docs/FEATURES.md)

---

## 🔄 BAVR Pattern

**Every applied change is tracked, verified, and designed to be reversible.**

```
[1/4] BACKUP Full system state backup before changes
[2/4] APPLY Settings applied with comprehensive logging
[3/4] VERIFY Automated compliance checks confirm what was applied
[4/4] RESTORE One command reverts most changes (see Reversibility notes below)
```

**What this means in practice:**
- **BAVR for all applied settings** — every setting NoID writes is backed up and re-checkable
- **Comprehensive error handling** — advanced functions, structured logging
- **Wide restore coverage** — Registry, Services, Scheduled Tasks, configuration files
- **Tested on Windows 11 25H2** with PowerShell 5.1+ and 7+

**Verification scope improved across v2.x:**
- v2.1.0 added EdgeHardening (20 checks) + AdvancedSecurity (44 checks), closing the v2.0.x verification gap
- See `Tools/Verify-Complete-Hardening.ps1` for the exact checks performed

---

## ⚠️ What This Does NOT Protect Against

**Important Limitations:**

| Threat | Why Not Protected |
|--------|-------------------|
| **Social Engineering** | If users deliberately bypass all warnings and run malicious files |
| **Supply-Chain Attacks** | Malware embedded in legitimate signed software |
| **Physical Access** | Stolen device without BitLocker (use BitLocker!) |
| **Nation-State Actors** | Sophisticated targeted attacks require enterprise EDR/XDR |
| **Zero-Day Exploits** | Unknown vulnerabilities not yet patched by Microsoft |

**What you need additionally:**
- **Regular Windows Updates** — Critical for security patches
- **BitLocker** — For lost/stolen device protection
- **User Awareness** — Don't click suspicious links/attachments
- **Backups** — 3-2-1 backup strategy for ransomware resilience

> **NoID Privacy hardens your system significantly, but no security solution provides 100% protection.** 
> Defense in depth is always recommended.

---

## 📥 Quick Start

### ⚡ One-Liner Install (Recommended)

**Step 1:** Open PowerShell as Administrator
- Press `Win + X` → Click **"Terminal (Admin)"**

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

## 💻 Usage Examples

### Interactive Mode (Recommended)

```powershell
# Start interactive menu
.\Start-NoIDPrivacy.bat

# Follow prompts:
# 1. Select modules (all or custom)
# 2. Choose settings (DNS provider, Privacy mode, etc.)
# 3. Automatic backup → apply → verify
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
# Full verification (633 checks with Paranoid mode)
.\Tools\Verify-Complete-Hardening.ps1

# Expected output (all modules enabled, Paranoid mode):
# SecurityBaseline: 425/425 verified
# ASR: 19/19 verified
# DNS: 5/5 verified
# Privacy: 78/78 verified
# AntiAI: 32/32 verified
# EdgeHardening: 24/24 verified
# AdvancedSecurity: 50/50 verified
# Total: 633/633 (100%)
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

## 📊 Module Overview

| Module | Settings | Description | Status |
|--------|----------|-------------|--------|
| **SecurityBaseline** | 425 | Microsoft Security Baseline 25H2 | v2.2.4 |
| **ASR** | 19 | Attack Surface Reduction Rules | v2.2.4 |
| **DNS** | 5 | Secure DNS with DoH encryption | v2.2.4 |
| **Privacy** | 78 | Telemetry, Bloatware, OneDrive hardening (Strict) | v2.2.4 |
| **AntiAI** | 32 | AI lockdown (15 features, 32 compliance checks) | v2.2.4 |
| **EdgeHardening** | 24 | Microsoft Edge security (24 policies) | v2.2.4 |
| **AdvancedSecurity** | 50 | Beyond MS Baseline (SRP, Legacy protocols, Wireless Display, Discovery Protocols, IPv6) | v2.2.4 |
| **TOTAL** | **633** | All 7 modules (Paranoid mode). With a third-party endpoint product as primary engine: 614 (ASR not applicable) | **v2.2.4** |

**Release Highlights:**

- **v2.2.4:** Third-party endpoint product detection — ASR module skipped gracefully when a non-Defender engine is primary (works with CrowdStrike, SentinelOne, Carbon Black, Bitdefender, Kaspersky, ESET, Sophos, Trend Micro and ~15 more) ([#15](https://github.com/NexusOne23/noid-privacy/issues/15))
- **v2.2.3:** Restore Mode crash fix, Recall snapshot storage verification fix ([#14](https://github.com/NexusOne23/noid-privacy/issues/14))
- **v2.2.2:** Firewall snapshot 60-120s → 2-5s (batch query performance fix)
- **v2.2.1:** Multi-run session bug fix, `.Count` property bug in 5 files
- **v2.2.0:** Verification coverage extended to all 7 modules (EdgeHardening + AdvancedSecurity added), SRP .lnk protection, RDP/TLS hardening, legacy protocol blocking

📖 [Detailed Module Documentation](Docs/FEATURES.md)

---

## ✅ Perfect For

### **Ideal Use Cases**

**Small/Medium Business (SMB)**
- No Active Directory/Intune licenses
- Cloud-first (Microsoft 365, Google Workspace)
- Remote/hybrid work security
- Compliance without enterprise infrastructure

**Freelancers & Consultants**
- Client data protection
- Secure workstations without domain
- Professional security standards
- Safe experimentation (complete backup)

**Power Users & Privacy-Conscious**
- Real security, not just "debloat"
- AI/Telemetry lockdown
- Understand every setting
- Full control + reversibility

**IT Pros Without Intune**
- Standalone Windows 11 hardening
- Microsoft Baseline compliance locally
- Quick deploy for clients
- No domain controller required

### **Not Ideal For**

**Enterprise with Intune/AD**
- Use [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10) with Group Policy instead

**Windows 10 or Older**
- This tool is designed for Windows 11 24H2 or newer

**Legacy Software Dependencies**
- If you rely on unsafe SMB1/RPC/DCOM

**Strict MDM Reporting**
- If compliance must be centrally reported

---

## ⚙️ Requirements & Compatibility

### Hardware & OS

NoID Privacy is designed for modern, officially supported Windows 11 systems.

If your PC can run Windows 11 according to Microsoft's **official requirements**, it is compatible with NoID Privacy:

- **OS:** Windows 11 24H2 or newer (25H2 fully tested)
- **CPU:** Any CPU on Microsoft's Windows 11 support list (Intel 8th Gen / AMD Ryzen 2000+)
- **Firmware:** UEFI with **Secure Boot** enabled
- **TPM:** 2.0 (required for BitLocker, Credential Guard*, VBS)
- **RAM:** 8 GB minimum, 16 GB recommended for VBS
- **Admin Rights:** Required

> **Short version:** If Windows 11 is officially supported on your PC, NoID Privacy is supported too.

**Tested & Compatible:**

| OS Version | Status |
|------------|--------|
| Windows 11 25H2 (Build 26200+) | **Fully Tested** |
| Windows 11 24H2 (Build 26100+) | Compatible |
| Windows 11 23H2 or older | ❌ Not Supported |

### Legacy Devices & Protocols

The **AdvancedSecurity** and **SecurityBaseline** modules intentionally disable legacy and insecure protocols:

- **TLS 1.0/1.1** (TLS 1.2+ required)
- **NetBIOS** name resolution, **LLMNR**, **WPAD**
- **PowerShell v2**
- **Administrative shares** (C$, ADMIN$) in some scenarios
- **NTLMv1/LM** authentication (NTLMv2 only)

This can affect **very old hardware and software**, for example:

- NAS, printers, IP cameras, and IoT devices that only support TLS 1.0/1.1
- Legacy Windows systems (XP, 7) and old Samba implementations
- Old management tools that rely on hidden admin shares

**In practice:** Environments using hardware and software from **~2018 onwards** are fully compatible.

If you still depend on legacy devices, use the built-in **BAVR** pattern (Backup → Apply → Verify → Restore) to roll back if something breaks.

### 🛡️ Antivirus Compatibility

#### Microsoft Defender vs. Third-Party Endpoint Products

NoID Privacy works alongside whichever AV / endpoint product you already use. The key
difference is how many of NoID's checks are applicable to your configuration:

| Your Setup | NoID Modules Applied | Modules Skipped |
|------------|----------------------|-----------------|
| **Microsoft Defender as primary engine** | All 7 modules — SecurityBaseline, ASR, DNS, Privacy, AntiAI, Edge, AdvancedSecurity | None |
| **Third-party endpoint product as primary** (any vendor — consumer AV or enterprise EDR/XDR) | 6 modules — SecurityBaseline, DNS, Privacy, AntiAI, Edge, AdvancedSecurity | ASR (see note below) |

> **Why ASR is Defender-specific:** ASR (Attack Surface Reduction) is a set of rules exposed
> through a Microsoft-Defender-specific API (`Get-MpPreference` / `Set-MpPreference`).
> When Defender is not the primary engine, NoID cannot configure or verify ASR rules.
>
> **This does NOT mean your existing endpoint product is inferior.** Modern AV and EDR/XDR
> products from Bitdefender, Kaspersky, Norton, ESET, CrowdStrike, SentinelOne, Sophos,
> Trend Micro, and others typically include their own attack-surface-reduction features
> — behavioral analysis, exploit prevention, ML/AI-based detection, reputation systems,
> cloud sandboxing, and more. NoID cannot read those vendor-specific configurations and
> therefore does not attempt to verify them.
>
> **Recommendation if you run a third-party endpoint product:** consult your vendor's
> documentation or management console to confirm equivalent attack-surface-reduction
> features are enabled. The other 6 NoID modules are unaffected.

When a third-party endpoint product is detected, NoID shows a clear notification:

```
========================================
  ASR Module Skipped
========================================

Third-party endpoint product detected: <Product Name>

ASR (Attack Surface Reduction) is a Microsoft-Defender-specific API and
cannot be configured by NoID when Defender is not the primary engine.

Your product (<Product Name>) likely provides its own attack-surface-reduction
features (behavioral analysis, exploit prevention, ML-based detection, etc.).
NoID cannot verify those — please consult your vendor's documentation or
management console to confirm equivalent protections are enabled.

This is NOT an error - ASR will be skipped.
```

**The other 6 modules apply normally regardless of which endpoint product you use.**

---

## 🔒 Security & Quality

### Code Quality

- **PSScriptAnalyzer:** Available for static analysis
- **Pester Tests:** Unit and integration tests in `Tests/` directory (`.\Tests\Run-Tests.ps1`)
- **Verification:** 630+ automated compliance checks performed by `Tools\Verify-Complete-Hardening.ps1`
- **Comprehensive error handling** and structured logging
- **Best Practices:** Advanced Functions, CmdletBinding, Validated Parameters

### What This Tool Does

- Applies the Microsoft Security Baseline for Windows 11 v25H2 + the additional NoID hardening modules
- Implements Microsoft Security Baseline 25H2
- Protects against zero-day exploits (CVE-2025-9491)
- Minimizes telemetry to Security-Essential level
- Locks down AI features (Recall, Copilot, etc.)
- Configures BitLocker policies, Credential Guard*, VBS 

### What This Tool Does NOT Do

- Install third-party antivirus (uses Windows Defender)
- Configure domain-specific policies
- Modify BIOS/UEFI settings
- Break critical Windows functionality
- Prevent re-enabling features 

### Reversibility

- **What CAN be restored:** Services, Registry, Firewall, DNS, Tasks, AI features
- **What CAN be auto-restored:** Most removed bloatware apps via `winget` during session restore (where mappings exist)
- **What may still need manual reinstall:** Unmapped/third-party bloatware apps (use Microsoft Store)
- **Backup System:** Complete system state before applying
- **REMOVED_APPS_LIST.txt:** Created during bloatware removal with a full list of removed apps for manual reinstall if needed
- **Documented Changes:** All changes logged

---

## ⚙️ Configuration

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

## 🔧 Troubleshooting

> **Can't install software after hardening?** See [Temporarily Disable ASR Rule](#temporarily-disable-asr-rule-for-software-installation) for step-by-step solution

### Common Issues

**"Access Denied" errors**
- Not running as Administrator
- Right-click PowerShell → "Run as Administrator"

**VBS/Credential Guard not active after reboot**
- Credential Guard requires Windows 11 Enterprise or Education
- Hardware incompatibility (no TPM 2.0 or virtualization disabled)
- Enable virtualization in BIOS/UEFI
- Verify: `.\Tools\Verify-Complete-Hardening.ps1`

**BitLocker not activating**
- No TPM 2.0 or insufficient disk space
- Check TPM: `Get-Tpm`
- Manual activation: Control Panel → BitLocker

**ASR blocking legitimate software installation**
- ASR rule "Block executable files unless they meet prevalence" blocks unknown installers
- See [Temporarily Disable ASR Rule](#temporarily-disable-asr-rule-for-software-installation) below

---

### Temporarily Disable ASR Rule for Software Installation

**Problem:** ASR blocks installation of legitimate software (e.g., downloaded installers not in Microsoft's reputation database)

**Blocked Rule:** `01443614-cd74-433a-b99e-2ecdc07bfc25` ("Block executable files unless they meet prevalence, age, or trusted list")

**Solution:** Temporarily set the rule to AUDIT mode (warns only, doesn't block)

**Step 1: Disable Tamper Protection** (GUI method - easiest)
1. Press `Win` key → Type "Windows Security" → Enter
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

## 📚 Documentation

### Core Documentation
- **[Features](Docs/FEATURES.md)** - Complete 630+ setting reference
- **[Changelog](CHANGELOG.md)** - Version history
- **[Quick Start](#-quick-start)** - Installation guide (see above)
- **[Troubleshooting](#-troubleshooting)** - Common issues (see above)

### 💬 Community

- **[💬 Discussions](https://github.com/NexusOne23/noid-privacy/discussions)** - Questions and ideas
- **[🐛 Issues](https://github.com/NexusOne23/noid-privacy/issues)** - Bug reports only
- **[📚 Documentation](Docs/FEATURES.md)** - Complete feature reference

---

## 🙏 Acknowledgments

- **Microsoft Security Baseline Team** for Windows 11 25H2 guidance
- **PowerShell Community** for best practices and patterns
- **Open Source Contributors** for testing and feedback

---

## 🔗 The NoID Privacy Ecosystem

| Platform | Link |
|----------|------|
| 🌐 **Website** | [NoID-Privacy.com](https://noid-privacy.com) — All platforms, pricing, and documentation |
| 🪟 **Windows** | You're here! |
| 🐧 **Linux** | [NoID Privacy for Linux](https://github.com/NexusOne23/noid-privacy-linux) — 300+ checks, 42 sections, `--ai` flag for AI-powered fixes (free & open source) |
| 📱 **Android** | [NoID Privacy on Google Play](https://play.google.com/store/apps/details?id=com.noid.privacy) — 81 checks, 10 categories, permission audit, Chrome hardening, anti-theft |

---

## 📜 License

### Dual-License Model

NoID Privacy is available under a **dual-licensing** model:

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

**Contact:**
- **Email:** [support@noid-privacy.com](mailto:support@noid-privacy.com) (Preferred for commercial inquiries)
- **GitHub:** [💬 Discussions](https://github.com/NexusOne23/noid-privacy/discussions) (Public questions)

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

## 📈 Project Status

**Current Version:** 2.2.4
**Status:** Released

### Release Highlights v2.2.4

- **Enhancement:** 3-layer detection for third-party endpoint products (based on registration mechanism — Security-Center-registered AV vs Defender-passive-mode endpoint products — not on product class or sophistication)
- **Enhancement:** ASR module gracefully skips when a third-party endpoint product is detected as primary engine, since ASR is a Defender-specific API ([#15](https://github.com/NexusOne23/noid-privacy/issues/15))
- **Tooling:** `VERSION` file + `Bump-Version.ps1` for automated version management

### Release Highlights v2.2.3

- **Critical Fix:** Restore Mode manual module selection crash (`.Split()` → `-split`)
- **Bug Fix:** Recall snapshot storage verification — MB vs GB unit mismatch ([#14](https://github.com/NexusOne23/noid-privacy/issues/14))

### Release Highlights v2.2.2

- **Performance:** Firewall snapshot 60-120s → 2-5s (batch query fix)
- Version alignment across 60+ framework files

### Release Highlights v2.2.1

- **Critical Fix:** Multi-run session bug (auditpol backup failures when running multiple times)
- **Fix:** `.Count` property bug in 5 files (Where-Object single-object results)
- **Improved:** ASR prompt text ("untrusted" → "new software" - more neutral)

📋 [See Full Changelog](CHANGELOG.md)

---

<div align="center">

**Made with 🛡️ for the Windows Security Community**

[Report Bug](https://github.com/NexusOne23/noid-privacy/issues) · [Request Feature](https://github.com/NexusOne23/noid-privacy/issues) · [Discussions](https://github.com/NexusOne23/noid-privacy/discussions) · [Website](https://noid-privacy.com)

**[⭐ Star this repo](https://github.com/NexusOne23/noid-privacy)** if you find it useful!

</div>



