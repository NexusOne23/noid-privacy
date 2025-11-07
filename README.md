# ðŸ›¡ï¸ NoID Privacy â€“ Windows 11 Security & Privacy Hardening Toolkit for Everyone

> **Enterprise-Grade Security & Privacy Hardening Tool for Windows 11 25H2 â€“ No Intune, No AD, Complete Backup Included**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Windows 11](https://img.shields.io/badge/Windows%2011-25H2-0078D4.svg)](https://www.microsoft.com/windows/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.8.1-blue.svg)](CHANGELOG.md)

---

## ðŸŽ¯ In 30 Seconds

ðŸ“Œ **What?** â†’ Microsoft Security Baseline 25H2 + CISA KEV Protection, locally on Windows 11  
ðŸ“Œ **How?** â†’ PowerShell: **Apply** â†’ **Verify** â†’ **Restore** (fully reversible!)  
ðŸ“Œ **For whom?** â†’ SMB, freelancers, power users **without Intune/Active Directory**

**478 Registry Keys Â· 19 ASR Rules Â· 133 Verification Checks Â· Complete Backup/Restore**

---

### ðŸŽ¯ At a Glance

<div align="center">

| ðŸ›¡ï¸ **SECURITY** | ðŸ”’ **PRIVACY** | âš¡ **PERFORMANCE** | ðŸ”„ **REVERSIBLE** |
|:---:|:---:|:---:|:---:|
| **100% locally-implementable<br>MS Baseline (370/429)** | **95% Telemetry Reduced** | **30 Tasks Disabled** | **Complete Backup** |
| 19 ASR Rules (Enforce) | 9 AI Features Locked | Event Logs Optimized | 494 Settings Restored |
| 13 Exploit Mitigations | 37 App Permissions | No Bloatware | **0 Errors** |
| Credential Guard + VBS | 107,772 Domains Blocked | Faster Boot | Safe to Experiment |

**â†’ [3-Minute Setup](#-quick-start)** Â· **[See All 400+ Settings](FEATURES.md)** Â· **[Compare with Others](#-why-noid-privacy)**

</div>

---

![NoID Privacy - Enforce Mode](docs/screenshots/enforce-mode.png)
*Screenshot: Interactive 'Enforce' run on Windows 11 25H2 â€“ 400+ settings hardened in ~3 minutes*

> ðŸ‡©ðŸ‡ª **Deutsche Nutzer:** Runtime-Switch EN/DE â€“ alle MenÃ¼s und UI-Texte auf Deutsch verfÃ¼gbar (kein Extra-Download nÃ¶tig)

---

## ðŸš€ Quick Start

### One-Liner Install (No Git Required!)

**Step 1:** Open PowerShell as Administrator
- Press `Win + X` â†’ Click **"Terminal (Admin)"** or **"PowerShell (Admin)"**

**Step 2:** Choose your installation method:

#### ðŸš€ Fast Install (Quick & Easy)
```powershell
irm https://raw.githubusercontent.com/NexusOne23/noid-privacy/main/install.ps1 | iex
```

#### ðŸ”’ Safe Install (Recommended for Security-Conscious Users)
```powershell
# Download installer
irm https://raw.githubusercontent.com/NexusOne23/noid-privacy/main/install.ps1 -OutFile install.ps1

# OPTIONAL: Inspect the file before running
notepad install.ps1

# Run installer
.\install.ps1
```

> âš ï¸ **Important:** This only works in **PowerShell** (not CMD)!  
> ðŸ’¡ **Why two methods?** Fast install uses `| iex` (pipe to execute) which is convenient but downloads and executes in one step. Safe install lets you inspect the code first.

**What it does:**
1. **[1/5] Checks Administrator privileges** - Exits with clear message if not admin
2. **[2/5] Checks Windows 11** - Verifies Build 22000+ (25H2 recommended)
3. **[3/5] Downloads latest release** - Fetches from GitHub API automatically
4. **[4/5] Extracts & Unblocks** - Removes Zone.Identifier from all PowerShell files
5. **[5/5] Starts interactive mode** - No manual steps needed!

**Benefits:**
- âœ… No Git installation required
- âœ… No manual unblocking needed
- âœ… Always latest release
- âœ… Instant start

### Manual Install (Git Required)
```powershell
# 1. Download
git clone https://github.com/NexusOne23/noid-privacy.git
cd noid-privacy

# 2. Run as Admin
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive

# 3. Verify
.\Verify-SecurityBaseline.ps1
```

> **âš ï¸ Downloaded ZIP instead of Git Clone?**  
> Windows marks downloaded files as "blocked" (Zone.Identifier).  
> **Solution:** Run `Start-NoID-Privacy.bat` - it automatically unblocks all files!  
> **Manual:** Right-click each file â†’ Properties â†’ Check "Unblock" â†’ OK  
> **Details:** [FAQ - Troubleshooting](FAQ.md#-troubleshooting)

**â†’ [Detailed Installation Guide](QUICKSTART.md)** Â· **[See All Features](FEATURES.md)** Â· **[View Changelog](CHANGELOG.md)**

---

## ðŸŒŸ Key Features

### ðŸ›¡ï¸ Security Hardening - Enterprise Protection at Home

**Your Computer Becomes a Fortress:**
- **Microsoft Defender** â†’ 11 protection layers = Real-time, Cloud, Behavior, Network, PUA, Archive, USB, Email, Script scanning + Tamper Protection
- **19 Attack Surface Reduction Rules** â†’ Blocks ransomware, macros, exploits, credential theft - [See ASR Details](ASR_RULES.md)
- **13 Exploit Mitigations** â†’ Memory-based attacks fail (DEP, SEHOP, ASLR, CFG, Heap Protection, Image Load Protection, Bottom-Up ASLR, High Entropy, etc.)
- **Credential Protection** â†’ Your passwords can't be stolen from memory (Credential Guard + LSA Protection + Mimikatz mitigation)
- **BitLocker XTS-AES-256** â†’ Stolen laptop = useless encrypted brick (TPM 2.0 + optional PIN)
- **Strict Firewall** â†’ Nothing gets in without your permission (block all incoming + 13 legacy protocol blocks)
- **Modern Network Only** â†’ TLS 1.2/1.3, SMB encryption, no legacy protocols (LLMNR/NetBIOS/WPAD/mDNS disabled)

**Bottom line:** You get Fortune-500-style hardening on a standalone device

### ðŸ”’ Privacy Protection - Minimized Telemetry

**Your Privacy is Maximized:**
- **Telemetry Minimized** â†’ 25+ services + 30 tasks + 478 Registry Keys configured for minimum data collection
- **AI Lockdown (9 features)** â†’ Windows Recall DISABLED (no screenshots of passwords!), Copilot blocked (4 layers), Click to Do, Paint AI (3), Notepad AI, Settings Agent, Copilot Proactive
- **App Permission Control** â†’ 37 categories default-DENY (apps can't spy without explicit permission)
- **Clean System** â†’ 80+ bloatware app patterns checked (Xbox, 3D apps, Candy Crush, Teams Chat, Copilot, Widgets)
- **107,772 Trackers Blocked** â†’ DNS-level blocking via Steven Black hosts (Nov 2025) + Cloudflare DoH

**Bottom Line:** Telemetry reduced to Security-Essential level (Required Diagnostic Data for Windows Update/Defender)

**â„¹ï¸ Reality Check:** Windows 11 requires minimum telemetry for:
- Windows Update (security patches)
- Microsoft Defender updates (malware signatures)
- Compatibility checks (driver updates)

This project minimizes telemetry via Registry, Services, Firewall, and DNS blocking - but cannot eliminate it entirely without breaking core functionality.

### âš¡ Performance - Faster & Cleaner

**Your PC Breathes Easier:**
- **30 Background Tasks Disabled** â†’ Less CPU/disk usage when idle (Update/Defender tasks stay active!)
- **Event Log Optimization** â†’ Critical logs increased, noise logs reduced = less disk I/O
- **Windows Search Optimized** â†’ Local-only, no web/Bing queries
- **No Bloatware** â†’ Faster boot, more disk space, cleaner Start Menu

**Bottom Line:** Windows feels snappier, boots faster

### ðŸŽ¯ Advanced Features - Pro-Level Control

**Power User Tools:**
- **Windows LAPS** â†’ Auto-rotating admin passwords (30 days, 20 chars, Entra/AD-Escrow)
- **Advanced Auditing** â†’ Complete security event logging (Object Access, Logon, DS, Policy, PnP, PS-Logging)
- **Smart App Control** â†’ AI-based app reputation (requires clean install - script prepares policies)
- **Enhanced UAC** â†’ Maximum privilege protection (always notify + Enhanced Privilege Protection Mode ready)
- **Edge Privacy** â†’ Tracking prevention Balanced, SmartScreen enforced, DoH automatic, Site Isolation active

**Bottom Line:** Enterprise-level features at home

### ðŸŒ DNS Security & Privacy

**Multi-Provider DNS-over-HTTPS** â†’ Choose from 4 providers (Cloudflare, AdGuard, NextDNS, Quad9)  
**100% Strict DoH Enforcement** â†’ No fallback to unencrypted DNS (`autoupgrade=yes`, `udpfallback=no`)  
**Steven Black Hosts** â†’ 107,772 malicious/tracking domains blocked (updated Nov 2025, cache-optimized)

<details>
<summary><b>ðŸ“‹ DNS Details (click to expand)</b></summary>

**Choose Your DNS-over-HTTPS Provider:**

| Provider | Best For | Unique Features |
|----------|----------|----------------|
| **Cloudflare** (Default) | Speed + Global Coverage | 1.1.1.1, Fastest, WARP integration |
| **AdGuard** | Privacy + EU Compliance | Built-in ad/tracker blocking, GDPR |
| **NextDNS** | Customization + Analytics | Custom profiles, detailed analytics |
| **Quad9** | Security + Threat Intel | Malware blocking, Non-profit, GDPR |

**All Providers Include:**
- âœ… **100% Strict Enforcement:** No fallback to unencrypted DNS
- âœ… **Dual-Stack:** IPv6 + IPv4 (IPv6 preferred when available)
- âœ… **Per-Adapter:** Only real network adapters (VPN/Virtual excluded)
- âœ… **Global Policy:** `EnableAutoDoh=2` (Windows-wide enforcement)
- âœ… **DNSSEC Validation:** Prevents DNS spoofing/poisoning

**Steven Black Unified Hosts File (Optimized)**
- âœ… **107,772 malicious/tracking domains blocked** at DNS level (before queries even reach DNS!)
- âœ… **Compressed to 12,025 lines** (9 domains per line - Windows DNS Cache optimized)
- âœ… **Zero performance impact** - in-memory lookup
- âœ… **Updated regularly** from Steven Black repository (last: Nov 5, 2025)

**Defense in Depth Architecture:**
1. **Hosts file** (107K+) â†’ Blocks before DNS query
2. **DoH Provider** â†’ Encrypts queries (ISP can't see)
3. **DNSSEC** â†’ Validates responses (prevents spoofing)
4. **Threat Intel** (Quad9) or **Ad Blocking** (AdGuard) â†’ Extra protection

**â†’ [See Full DNS Provider Comparison](FEATURES.md#-network-security)**

</details>

---

## âœ… Why NoID Privacy?

**The only Windows 11 hardening tool with Apply + Verify + Complete Restore â€“ no Intune required.**

| Feature | NoID Privacy | simeononsecurity | W4RH4WK Debloat | ChrisTitus winutil | O&O ShutUp10++ |
|---------|--------------|------------------|-----------------|---------------------|----------------|
| **MS Baseline 25H2** | âœ… 100% of locally-implementable (370/429) | âš ï¸ ~70% | âŒ ~20% | âš ï¸ ~40% | âš ï¸ ~30% |
| **Full Backup/Restore** | âœ… All (Registry, Services, Tasks, Firewall, DNS) | âŒ Registry only | âŒ None | âŒ None | âš ï¸ Profiles only |
| **Verification** | âœ… 133 checks | âš ï¸ Limited | âŒ None | âŒ None | âŒ None |
| **CISA KEV Coverage** | âœ… 85% (17/20 config-mitigable, not patch-only) | âš ï¸ ~50% | âŒ ~10% | âš ï¸ ~30% | âŒ Minimal |
| **Privacy/AI Lockdown** | âœ… 9 AI features + 37 app permissions | âœ… Yes | âœ… Yes | âœ… Yes | âœ… Yes |
| **Requires Intune/AD** | âŒ No | âŒ No | âŒ No | âŒ No | âŒ No |

**â†’ Only tool combining enterprise-grade baseline compliance with complete backup/restore for standalone systems.**

**About CISA KEV Coverage (85%):**  
We count KEV items that can be mitigated through hardening (ASR rules, protocol disablement, driver blocklist, service hardening) â€“ not patch-based CVEs that require Windows Updates. Our 17/20 coverage focuses on configuration-based protections that this tool can actually implement.

**âŒ Not for you?**  
This tool targets **Windows 11 25H2 standalone systems**. Not ideal for: Enterprise with Intune/AD (use Group Policy instead), Windows 10/older, legacy software requiring unsafe protocols, strict MDM reporting. â†’ [Full details below](#-perfect-for)

---

## ðŸŽ¯ Perfect For

### âœ… **Ideal Use Cases**

**Small/Medium Business (SMB)**  
â†’ No Active Directory/Intune licenses  
â†’ Cloud-first (Microsoft 365, Google Workspace)  
â†’ Remote/hybrid work, BYOD security  
â†’ Compliance requirements without enterprise infrastructure

**Freelancers & Consultants**  
â†’ Client data protection  
â†’ Secure workstations without domain  
â†’ Professional security standards  
â†’ Safe experimentation (complete backup)

**Power Users & Privacy-Conscious**  
â†’ Real security, not just "debloat"  
â†’ AI/Telemetry/Recall lockdown  
â†’ Understand what each setting does  
â†’ Full control + reversibility

**Sysadmins Without Intune**  
â†’ Standalone Windows 11 hardening  
â†’ Microsoft Baseline compliance locally  
â†’ Quick deploy for multiple clients  
â†’ No domain controller required

### âŒ **Not Ideal For**

**Enterprise with Intune/AD**  
â†’ Use Group Policy/Intune instead (better for large-scale management)

**Windows 10 or Older**  
â†’ This tool targets Windows 11 25H2 specifically

**Legacy Software Dependencies**  
â†’ If you rely on unsafe SMB1/RPC/DCOM configurations  
â†’ Check [Known Issues](KNOWN_ISSUES.md) first

**Strict MDM Reporting**  
â†’ If compliance must be reported to central MDM (Intune wins)

---

## ðŸ“‹ Requirements

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
  - âœ… **Hosts file (107K+ domains) included** - compressed to 2.2 MB (from 3 MB original)
  - âœ… DNS-over-HTTPS is only configured (no download needed)
  - â„¹ï¸ Internet only needed for: git clone (initial download)
  
> **ðŸ“¦ Note on Repository Size:** The compressed hosts file (~2.2 MB) is included in the repo for offline use. Original uncompressed Steven Black hosts files are excluded via .gitignore to keep the repository lean. The script uses the pre-compressed version for optimal performance.

---

## ðŸ“– Usage & Examples

### Core Workflow

```powershell
# 1. Apply hardening (Interactive Mode recommended)
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive

# 2. Verify settings (133 checks)
.\Verify-SecurityBaseline.ps1

# 3. Reboot (for VBS, Credential Guard, BitLocker)
shutdown /r /t 0
```

### Backup & Restore

```powershell
# Create backup BEFORE applying
.\Backup-SecurityBaseline.ps1

# Restore if needed
.\Restore-SecurityBaseline.ps1
```

### Modes

```powershell
# Audit Mode (all settings applied, ASR rules log-only)
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Audit

# Enforce Mode (all settings + ASR rules enforcement)
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce

# Custom modules (interactive selection)
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive
  â†’ Choose language (EN/DE)
  â†’ Select "Custom Configuration"
  â†’ Pick modules (Core, ASR, Privacy, etc.)
```

**â†’ Full documentation: [QUICKSTART.md](QUICKSTART.md) Â· [INSTALLATION.md](INSTALLATION.md) Â· [FAQ.md](FAQ.md)**

---

## ðŸ”§ Module Architecture

The project uses a modular architecture with **13 specialized modules**: Core, ASR, Advanced, DNS, Bloatware, Telemetry, Performance, AI, Edge, OneDrive, UAC, WindowsUpdate, WirelessDisplay

<details>
<summary><b>ðŸ“‹ Module Details (click to expand)</b></summary>

| Module | Description | Key Features |
|--------|-------------|-------------|
| **Core** | Security baseline, Defender, Firewall, Services | 25 services disabled, 13 firewall rules, 13 exploit mitigations, Admin/Guest account hardening |
| **ASR** | Attack Surface Reduction rules | 19 ASR rules (Enforce mode), Smart App Control |
| **Advanced** | VBS, Credential Guard, LAPS, Auditing | Credential Guard, VBS, HVCI, LSA-PPL, BitLocker policies, Windows LAPS, TLS/SSL hardening |
| **DNS** | Multi-Provider DoH, DNSSEC, Blocklist | 4 providers (Cloudflare/AdGuard/NextDNS/Quad9), 100% strict enforcement, DNSSEC validation, 107,772 blocked domains, Strict Inbound Firewall |
| **Bloatware** | App removal, Consumer features | 80+ app patterns, Teams Chat/Copilot/Widgets disabled, Consumer Features blocked |
| **Telemetry** | Privacy protection, App permissions | 25+ services, 478 Registry Keys (110 telemetry-specific), 37 app permission categories, Camera/Mic controls |
| **Performance** | Scheduled tasks, Event logs | 30 tasks disabled, Event log optimization, Windows Search local-only, Prefetch/Superfetch tuning |
| **AI** | Recall, Copilot, AI tracking | 9 AI features disabled: Recall, Copilot (4 layers), Click to Do, Paint AI (3), Notepad AI, Settings Agent, Copilot Proactive |
| **Edge** | Microsoft Edge security baseline | SmartScreen enforced, Tracking Prevention, DoH automatic, Site Isolation, Extension policies |
| **OneDrive** | Privacy hardening OR complete removal | Default: Privacy hardening (Tutorial/Feedback/KFM blocked, user-controlled uploads). Optional: Complete removal (uninstall + registry cleanup) |
| **UAC** | User Account Control enhancement | Maximum security (always notify), Enhanced Privilege Protection Mode (future-ready) |
| **WindowsUpdate** | Update optimization | Hybrid mode (user preferences + policies), HTTP-only (no P2P), Preview Builds blocked |
| **WirelessDisplay** | Miracast disablement | 4-layer blocking (Services, Registry, Firewall, Apps) |

</details>

<details>
<summary><b>ðŸ—ï¸ Backup/Restore Architecture (click to expand)</b></summary>

### System Components

The Backup/Restore system uses a **two-layer architecture** for maximum performance and precision:

**1. Data Layer: `RegistryChanges-Definition.ps1`**
- Central source of truth for all **478 registry changes**
- Each entry contains: Path, Name, Type, ApplyValue, Description, Source Module
- Used by: Backup, Restore, and Verify scripts
- **Why separate?** Separation of concerns - data definition independent of logic

**2. Logic Layer: `SecurityBaseline-RegistryBackup-Optimized.ps1`**
- `Backup-SpecificRegistryKeys` - Reads current values from Registry (30 seconds)
- `Restore-SpecificRegistryKeys` - Writes original values back (1-2 minutes)
- Handles TrustedInstaller-protected keys automatically (Tamper Protection, EDR, PUA)
- Error recovery and protected key detection

### Workflow

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ 1. APPLY                            â”‚
â”‚    Sets 478 Registry Keys           â”‚
â”‚    Modifies Services, Tasks, etc.   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
              â†“
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ 2. BACKUP (Before Apply!)           â”‚
â”‚    Reads current values             â”‚
â”‚    Saves to JSON (100 KB)           â”‚
â”‚    Time: 30 seconds                 â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
              â†“
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ 3. RESTORE (If needed)              â”‚
â”‚    Loads backup JSON                â”‚
â”‚    Writes original values back      â”‚
â”‚    System restored to pre-Apply     â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

### Performance Comparison

| Metric | Old System (v1.x) | New System (v2.0) | Improvement |
|--------|-------------------|-------------------|-------------|
| **Keys Backed Up** | 50,000+ (entire Registry) | 394 (only changed) | 99% reduction |
| **Backup Time** | 5-15 minutes | 30 seconds | **20-30x faster** âš¡ |
| **Backup Size** | 5 MB | 100 KB | **50x smaller** |
| **Restore Time** | 10-20 minutes | 1-2 minutes | **10x faster** |
| **Precision** | Low (all keys) | High (exact tracking) | 100% accurate |

### TrustedInstaller Handling

Some registry keys (Tamper Protection, EDR in Block Mode, PUA Protection) are owned by **TrustedInstaller** and require special handling:

- **Backup:** Can read with Admin rights âœ… (no ownership change needed)
- **Restore:** Uses `Set-RegistryValueSmart` to temporarily take ownership âœ…
  1. Takes ownership (TrustedInstaller â†’ Administrators)
  2. Grants write permissions
  3. Writes original value
  4. Restores ownership (Administrators â†’ TrustedInstaller)

### Why Two Separate Files?

**Separation of Concerns:**
- **Data** (`RegistryChanges-Definition.ps1`) â‰  **Logic** (`RegistryBackup-Optimized.ps1`)
- Change data without touching logic (add new key â†’ just add entry)
- Reusable across multiple scripts (Backup, Restore, Verify)
- Maintainable (clear responsibility boundaries)

**Developer Workflow:**
1. Add new registry key to module (e.g., `SecurityBaseline-Core.ps1`)
2. Add entry to `RegistryChanges-Definition.ps1`
3. Done! Backup/Restore automatically handles it âœ…

</details>

---

## ðŸ“Š Compliance Matrix

| Standard | Coverage | Details |
|----------|----------|---------|
| **Microsoft Baseline 25H2** | **100%** | All 370 locally applicable settings for standalone systems (429 total, 59 N/A: IE11 deprecated, domain-only) - **Includes automatic secedit.exe deployment with 67 settings!** |
| **CIS Benchmark Level 1** | ~85% | Majority of recommendations (standalone focus) |
| **CIS Benchmark Level 2** | ~90% | Enhanced security with privacy extensions |
| **DoD STIG** | ~75% | Core security controls (non-domain environment) |
| **BSI SiSyPHuS** | ~90% | Based on Windows 10 guidelines |

**Sources:** 
- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319) - Official security baseline for Windows 11 25H2
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) - Industry-standard security configuration guidelines
- [DoD STIG](https://public.cyber.mil/stigs/) - Department of Defense Security Technical Implementation Guides
- [BSI SiSyPHuS](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Empfehlungen-nach-Angriffszielen/Windows-Systeme/SiSyPHuS/sisyphus_node.html) - German Federal Office for Information Security guidelines

**Note:** Percentages are estimates for **standalone/workgroup workstations**. Domain-specific features (Group Policy, AD integration) are excluded. Exact compliance requires manual audit.

### Understanding "100% Microsoft Baseline Coverage"

**100% = All 370 locally-implementable policies fully configured + automatic secedit deployment + 100+ additional hardening settings beyond baseline**

<details>
<summary><b>ðŸ“‹ Coverage Details (click to expand)</b></summary>

**What does 100% mean?**
- All **370 locally-implementable policies** from Microsoft Security Baseline 25H2 are fully configured
- **Includes 67 secedit settings** automatically deployed via `Import-SecurityTemplate` (Password Policy, Account Lockout, User Rights, Security Options)
- **335 Registry policies** set via PowerShell
- **23 Advanced Audit policies** configured via `auditpol.exe`
- **4 Services** disabled (Xbox Gaming Services)
- Plus 100+ additional hardening settings **beyond** the baseline

**What's NOT included (59 N/A policies)?**
- **Internet Explorer 11 (57 policies)** - Completely deprecated in Windows 11, replaced by Microsoft Edge (IE11-specific FeatureControl settings)
- **Domain-only policies (2 policies)** - LAPS Domain Controller settings (ADPasswordEncryptionEnabled, ADBackupDSRMPassword)

**Why 429 total but only 370 implementable?**
- Microsoft Security Baseline 25H2 contains **429 total policies**
- **59 policies** are N/A for standalone systems (57 IE11-deprecated + 2 Domain Controller-only)
- This project implements **100% of what CAN be automated** (370/370) including:
  - âœ… **secedit automation with Backup/Restore** (67 settings)
  - âœ… **Registry policies** (335 settings)
  - âœ… **Advanced Audit** (23 categories)
  - âœ… **Services** (4 Xbox services)

**Bottom line:** You get **every single implementable security policy** from the Microsoft baseline (370/370), including automatic secedit deployment with full backup/restore capability, plus extensive privacy hardening!

</details>

---

## âš™ï¸ Configuration

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

## ðŸ›¡ï¸ Security Considerations

### What This Script Does
âœ… Hardens Windows 11 25H2 to enterprise security standards  
âœ… Disables unnecessary services and features  
âœ… Configures Windows Defender to maximum protection  
âœ… Enables BitLocker encryption with strong algorithms  
âœ… Protects against common attack vectors (ASR, Exploit Protection)  
âœ… Minimizes telemetry and tracking  
âœ… Removes bloatware and unnecessary apps  

### What This Script Does NOT Do
âŒ Install third-party antivirus (uses Windows Defender)  
âŒ Configure domain-specific policies (standalone focus)  
âŒ Modify BIOS/UEFI settings (user responsibility)  
âŒ Break critical Windows functionality  
âŒ Prevent user from re-enabling features  

### Reversibility
- **What CAN be restored automatically:** Services, Registry (including AI features), Firewall rules, DNS settings, Scheduled Tasks
- **What requires manual reinstall:** Removed apps (bloatware, Xbox, OneDrive) - must reinstall from Microsoft Store
- **Backup System:** Full system state backup before applying
- **No Force Policies:** Most settings can be re-enabled via Settings GUI or restore script
- **Documented Changes:** All changes logged in transcript files

**Note:** AI features (Recall, Copilot, etc.) are disabled via Registry - fully reversible with restore script.

---

## ðŸ› Troubleshooting

### Common Issues

#### "Script already running in another session"
**Cause:** Mutex prevents concurrent execution  
**Solution:** Wait for other instance to finish or restart system

#### "Access Denied" errors
**Cause:** Not running as Administrator  
**Solution:** Right-click PowerShell â†’ "Run as Administrator"

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
3. Manual activation: Control Panel â†’ BitLocker

#### ðŸŽ® Gaming & Multiplayer Issues

**Symptom:** Online multiplayer game won't connect / NAT issues / "Can't join friends"

**Try this first (Security-First approach):**
1. Keep **Strict Mode** (Option 1) - works for 90% of games!
2. Add game to Windows Firewall exceptions manually:
   - Settings â†’ Privacy & Security â†’ Windows Security â†’ Firewall
   - Allow an app â†’ Browse â†’ Select game executable
   - Check both Private and Public â†’ Add
3. Most games work fine with this!

**If still not working:**
1. Re-run Apply script
2. Choose **Option 2 (Allow Remote + Services)** in Remote Access menu
3. This fixes 95% of remaining issues

**Why this order?**
- Most games only need **outbound** connections (work with Strict Mode)
- Only **hosting games yourself** or **P2P modes** need inbound
- Router/NAT issues are more common than firewall issues
- Security-First: Try minimal change before opening firewall

**Examples:**
- âœ… **Fortnite, Valorant, Apex Legends:** Work with Strict Mode (Option 1)
- âœ… **Call of Duty, Diablo IV, Overwatch:** Work with Strict Mode (Option 1)
- âš ï¸ **Minecraft Server (hosting):** Needs Option 2
- âš ï¸ **P2P Games (hosting sessions):** Needs Option 2

#### âš ï¸ ShellHost.exe "Stack Buffer Overflow" Warning
**Symptom:** After running Wireless Display module, when user clicks "Cast" button (Windows + K or Quick Settings â†’ Cast), Windows shows:  
*"Das System hat in dieser Anwendung den Ãœberlauf eines stapelbasierten Puffers ermittelt..."*

**Important:** Error ONLY appears when attempting to cast, NOT automatically at system startup

**Cause:** Windows Shell attempts to access disabled Miracast services when Cast button is clicked  
**Impact:** Cosmetic error message only - NOT an actual security vulnerability  
**Functionality Lost:** Casting to Smart TV, Miracast, Wireless Display completely disabled

**How to Avoid:**
- In Interactive Mode: Choose "Custom"
- Deselect "Wireless Display / Miracast" module
- Script will skip Miracast hardening

**How to Restore:**
1. Run `.\Restore-SecurityBaseline.ps1` with your backup file
2. Services and Registry will be restored automatically
3. âš ï¸ Removed apps (SecondaryTileExperience, PPIProjection) must be manually reinstalled from Microsoft Store
4. Firewall rules will be reactivated automatically

**Note:** See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for detailed explanation

### Logs
All operations are logged to:
```
C:\ProgramData\SecurityBaseline\Logs\SecurityBaseline-Enforce-YYYYMMDD-HHMMSS.log
```

---

## ðŸ”§ CI/CD & Code Quality

This project uses GitHub Actions for automated quality checks and releases:

### Automated Workflows

**Code Quality** (Runs on every push/PR)
- PSScriptAnalyzer - PowerShell best practices validation
- Syntax validation - Ensures all scripts are parseable
- Error detection - Catches issues before merge

**Release Automation** (Triggers on version tags)
- Automatic GitHub Release creation
- Changelog generation from commits
- Release archive with SHA256 checksums
- Usage: `git tag v1.7.14 && git push --tags`

**Code Signing** (Prepared for SignPath Foundation)
- Status: Pending approval (Application submitted Oct 30, 2025)
- Will sign all PowerShell scripts once approved
- Free signing service for Open Source projects
- Expected: 1-2 weeks for response

### Running Checks Locally

```powershell
# Install PSScriptAnalyzer
Install-Module -Name PSScriptAnalyzer -Force

# Run analysis with project settings (recommended)
Invoke-ScriptAnalyzer -Path . -Settings .pssa-settings.psd1 -Recurse

# Or check specific file
Invoke-ScriptAnalyzer -Path "Apply-Win11-25H2-SecurityBaseline.ps1" -Settings .pssa-settings.psd1

# Validate syntax
$file = "Apply-Win11-25H2-SecurityBaseline.ps1"
[System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$null)
```

**Note:** This project uses `.pssa-settings.psd1` to exclude rules not applicable to interactive, user-facing scripts (e.g., `PSAvoidUsingWriteHost` is intentionally used for colored console output).

---

## ðŸ¤ Contributing

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

## ðŸ“œ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ðŸ“š Security Documentation

### Baseline Compliance & Verification

- **[Security Baseline Mapping](SECURITY_MAPPING.md)** - Complete mapping to Microsoft Security Baseline 25H2
  - Policy-by-policy comparison
  - GPO paths and registry keys
  - Verification commands
  - **100% coverage** of all locally-implementable policies (370/429)
  - **Automatic secedit deployment** with 67 settings (Password Policy, User Rights, Security Options)
  - 100+ extended hardening settings beyond baseline

- **[ASR Rules Reference](ASR_RULES.md)** - Attack Surface Reduction rules detailed breakdown
  - All 19 rule GUIDs and descriptions
  - Deployment modes (Audit/Warn/Block)
  - False positive guidance
  - Event monitoring and troubleshooting

- **[Known Issues](KNOWN_ISSUES.md)** - Compatibility notes and workarounds
- **[Security Policy](SECURITY.md)** - Vulnerability disclosure and security practices

### Why These Documents Matter

**For Auditors:** Provides verifiable evidence of baseline compliance  
**For IT Admins:** Shows exact GPO/Registry mappings for enterprise deployment  
**For Power Users:** Understand what each setting does and why  
**For Security Researchers:** Full transparency into implementation

---

## ðŸ™ Acknowledgments

- **Microsoft Security Baseline Team** for Windows 11 25H2 guidance
- **Center for Internet Security (CIS)** for benchmark standards
- **DoD Cyber Exchange** for STIG requirements
- **BSI (German Federal Office for Information Security)** for SiSyPHuS recommendations
- **Community Contributors** for testing and feedback

---

## ðŸ“ž Support

- **Issues:** [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues) - Bug reports and feature requests
- **Email:** [support@noid-privacy.com](mailto:support@noid-privacy.com) - General support and questions
- **Security:** [security@noid-privacy.com](mailto:security@noid-privacy.com) - Security vulnerabilities (private disclosure)
- **Documentation:** [README](README.md) Â· [FAQ](FAQ.md) Â· [Installation](INSTALLATION.md) Â· [Quick Start](QUICKSTART.md)
- **âš ï¸ Antivirus:** [Compatibility & False Positives](ANTIVIRUS_COMPATIBILITY.md) - Third-party AV compatibility (Bitdefender, Kaspersky, Norton, ESET, and others)

---

## âš ï¸ Disclaimer

This script modifies critical system settings. Use at your own risk. Always:
1. **Create a system backup** before running
2. **Test in a VM** before production use
3. **Review the code** to understand changes
4. **Verify compatibility** with your hardware/software

The authors are not responsible for any damage or data loss caused by this script.

---

## ðŸ“ˆ Project Status

**Current Version:** 1.8.1 ðŸŽ‰  
**Last Updated:** November 7, 2025  
**Status:** Production-Ready âœ…

### ðŸŽŠ Major Release (v1.8.0) - 100% Microsoft Security Baseline Coverage

**ðŸš€ Headline:** NoID Privacy now implements **100% of all locally-applicable Microsoft Security Baseline 25H2 policies** (370/370)!

#### **What's New:**
- âœ… **370/370 applicable policies** (was 213/365 = **+73.7% coverage!**)
- âœ… **67 secedit settings** automated (Password Policy, Account Lockout, LSA, SMB)
- âœ… **478 Registry Keys** (was 391 = **+87 keys**)
- âœ… **133 verification checks** (optimized from 135)
- âœ… **CRITICAL FIX:** Credential Guard now actually runs (Hypervisor + LsaCfgFlags)
- âœ… **Complete documentation overhaul** - 26 files updated, all numbers corrected
- âœ… **Antivirus compatibility improved** - Generic warnings, all AVs treated equally
- âœ… **Hosts file: 107,772 domains** (was 80K = **+34%**)

**â†’ See [CHANGELOG.md](CHANGELOG.md) for complete v1.8.0 details (186 lines!)**

<details>
<summary><b>Previous Updates (click to expand)</b></summary>

### ðŸŽŠ Major Release (v1.8.0) - 100% Microsoft Security Baseline Coverage

**ðŸš€ Headline:** NoID Privacy now implements **100% of all locally-applicable Microsoft Security Baseline 25H2 policies** (370/370)!

#### **What's New:**
- âœ… **370/370 applicable policies** (was 213/365 = **+73.7% coverage!**)
- âœ… **67 secedit settings** automated (Password Policy, Account Lockout, LSA, SMB)
- âœ… **478 Registry Keys** (was 391 = **+87 keys**)
- âœ… **133 verification checks** (optimized from 135)
- âœ… **CRITICAL FIX:** Credential Guard now actually runs (Hypervisor + LsaCfgFlags)
- âœ… **Complete documentation overhaul** - 26 files updated, all numbers corrected
- âœ… **Antivirus compatibility improved** - Generic warnings, all AVs treated equally
- âœ… **Hosts file: 107,772 domains** (was 80K = **+34%**)

### v1.7.21
- âœ… **Gaming Recommendations Improved** - Removed "Gamer = Option 2" statements, Security-First approach
- âœ… **All Instructions Localized** - VBS, BitLocker, CPU-Check messages now fully DE+EN (72 strings)
- âœ… **Gaming Troubleshooting Added** - Step-by-step guide in README for multiplayer issues

### v1.7.20
- âœ… **Camera/Mic/Location Permissions Rebalanced** - Privacy by Default + User Control (Apps can now request permissions)
- âœ… **Hibernate Linked to Remote Access** - Desktop Mode: ON (30 min), Remote Server Mode: OFF (24/7 availability)
- âœ… **Power Management Full Backup/Restore** - All power settings saved and restorable (Display, Sleep, Hibernate, CONSOLELOCK)
- âœ… **CRITICAL: Windows Settings App Search Fixed** - DisableWebSearch removed (Settings app search works again)
- âœ… **CRITICAL: Chrome/Edge Downloads Fixed** - Policy 1806 removed (downloads work normally, CVE-2025-9491 protection maintained)
- âœ… **Verify Script: Power Management Checks Fixed** - GUID-based powercfg queries (119/121 PASS, 98.3%)
- âœ… **Restore Script: PropertyNotFoundException Fixed** - Defensive property access pattern (graceful skip)
- âœ… **Repository Cleanup** - 6 obsolete files removed (features integrated into main codebase)
- âœ… **Registry Keys Updated** - 388 â†’ 384 entries (more user-friendly, -4 HKCU entries removed)

### v1.7.18
- âœ… **CRITICAL: Outlook Email Search Fixed** - Removed SetupCompletedSuccessfully key that broke Windows Search indexer
- âœ… **CRITICAL: Restore-Script Compatibility** - Old backups now filtered, buggy key won't be re-introduced
- âœ… **Registry Count Corrected** - 391 keys (was 392) - SetupCompletedSuccessfully removed

### v1.7.17
- âœ… **CRITICAL: Registry Count Corrected** - Final count is 391 keys (not 394) - 3 problematic entries removed for 100% accuracy
- âœ… **CRITICAL: Internet Zone Download Bug Fixed** - Removed 1803 blocking (Chrome/Edge downloads work again, CVE-2025-9491 protection maintained)
- âœ… **CRITICAL: Device-Level App Permissions Backup Re-Added** - Backup now includes webcam/microphone EnabledByUser keys (Backup/Restore gap closed!)
- âœ… **DNS Default Changed** - 'Keep Current DNS' instead of forced Cloudflare (fixes slow internet issue from forum feedback)
- âœ… **DNS Menu Localized** - Full EN/DE translation for DNS provider selection menu
- âœ… **100% Telemetry Module Localization** - All 13 functions now fully localized (~210 strings EN/DE)
- âœ… **100% Bloatware Module Localization** - Complete internationalization with progress indicators
- âœ… **Third-Party Antivirus Documentation** - New comprehensive compatibility guide (Bitdefender, Kaspersky, Norton, ESET, etc.)
- âœ… **Code Quality: Get-ItemProperty Pattern** - 63 instances fixed (clean error records, no PropertyNotFoundException)
- âœ… **Code Quality: PSObject.Properties Pattern** - Property access safety in Restore script (StrictMode compatible)
- âœ… **Complete Localization** - Advanced/ASR/DNS modules, Restore script (36 strings), 100% German/English support
- âœ… **Verify Script: Firewall Checks Mode-Aware** - No false failures for Standard Mode users

### v1.7.16
- âœ… **Optional Remote Access Mode** - Configure RDP and Firewall based on use-case (Desktop vs Remote Server/Development)
- âœ… **Firewall Standard Mode** - Allows localhost connections (Docker, LLM, WSL services functional)
- âœ… **Automatic Zone.Identifier Unblock** - ZIP downloads work out-of-the-box (no manual unblocking needed)
- âœ… **Restore Script Language Selection** - User can choose language when running Restore directly
- âœ… **78 App Name Mappings** - Missing-Apps list shows readable Microsoft Store names
- âœ… **100% ASCII Clean** - All 37 PowerShell files cleaned (no encoding issues, cross-platform compatible)

### v1.7.15
- âœ… **Multi-Provider DNS-over-HTTPS** - Choose from 4 enterprise-grade DNS providers
- âœ… **Interactive DNS Selection** - Cloudflare, AdGuard, NextDNS, Quad9, or Keep Existing
- âœ… **OneDrive Interactive Menu** - Privacy Hardening, Complete Removal, or Skip
- âœ… **Enhanced DoH Configuration** - Per-adapter IPv4+IPv6 dual-stack support
- âœ… **Improved Logging** - Clear DNS provider selection and configuration feedback

### v1.7.14
- âœ… **Phase 1 - APT Protection** - 5 features (SMB Signing, LDAP Hardening, Explorer Zone, SRP, EFS RPC Disable)
- âœ… **Phase 2 - Network Security** - 2 features (LocalAccountTokenFilterPolicy, WebClient/WebDAV Disable)
- âœ… **Phase 3 - Print & Protocol** - 3 features (Point-and-Print, Nearby Sharing, Internet Printing Client)
- âœ… **CISA KEV Protection** - 2 features (MSDT Follina, Vulnerable Driver Blocklist)
- âœ… **Bug Fixes** - 4 fixes (Internet Printing Client PropertyNotFoundException, Verify Phase 1 count, Clipboard clear, Misleading restore message)

### v1.7.13
- âœ… **DoH Verification Fixed** - Boolean conversion (Out-String) and correct command (show global)
- âœ… **DNS Restore Fixed** - PowerShell 5.1 compatibility (removed -AddressFamily parameter)
- âœ… **DNS Restore Fixed** - Array coercion for .Count property (PropertyNotFoundException)
- âœ… **Backup Fixed** - EnableAutoDoh PSObject.Properties pattern (robust property check)
- âœ… **DNS Restore Simplified** - Combines IPv4+IPv6 in single call, removed safety sweep

### v1.7.12
- âœ… **Access Denied Errors Fixed** - Device-Level Backup removed (TrustedInstaller-protected)
- âœ… **Bloatware TerminatingError Fixed** - Removed problematic Solitaire patterns
- âœ… **Step Counters Updated** - Changed from [X/14] to [X/13] (13 user-visible backup steps)
- âœ… **Registry Parity** - 125 missing keys added (100% parity achieved)
- âœ… **App List Localization** - Desktop export now fully localized (DE/EN)

### v1.7.11
- âœ… **IPv6 DoH Encryption** - Full IPv6 DNS-over-HTTPS support (Doh6 registry branch)
- âœ… **Notepad AI Copilot Disable** - Removes Copilot button from Windows Notepad
- âœ… **Domain Count Fix** - Corrected calculation (79,776 domains instead of 8,064)
- âœ… **lastrun.txt Creation Fix** - Reboot prompt moved after finally-block
- âœ… **Backup/Restore Enhancement** - DoH & Notepad AI settings now backed up
- âœ… **FAQ Documentation** - Added Windows Update guide, fixed DNS info, corrected 26H2 year

</details>

---

## ðŸ“š References

This project is based on and implements security standards from the following authoritative sources:

### Security Standards
- **[Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)** - Official security baseline configurations for Windows 11 25H2
- **[Microsoft Security Baseline 25H2 Announcement](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-windows-11-version-25h2/ba-p/4266613)** - TechCommunity release notes
- **[CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)** - Industry-standard security configuration guidelines
- **[DoD STIG](https://public.cyber.mil/stigs/)** - Department of Defense Security Technical Implementation Guides
- **[BSI SiSyPHuS](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Empfehlungen-nach-Angriffszielen/Windows-Systeme/SiSyPHuS/sisyphus_node.html)** - German Federal Office for Information Security guidelines

### Attack Surface Reduction
- **[ASR Rules Reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference)** - Microsoft Defender ASR documentation
- **[NSA Top 10 Mitigations](https://media.defense.gov/2024/Sep/18/2003553985/-1/-1/0/CSI-TOP-TEN-CYBERSECURITY-MITIGATION-STRATEGIES.PDF)** - National Security Agency cybersecurity guidance

### Privacy & Telemetry
- **[StevenBlack/hosts](https://github.com/StevenBlack/hosts)** - Unified hosts file for blocking tracking domains
- **[Windows Privacy Guide](https://learn.microsoft.com/en-us/windows/privacy/)** - Microsoft's official privacy documentation

### Additional Resources
- **[SECURITY_MAPPING.md](SECURITY_MAPPING.md)** - Detailed mapping of all implemented security controls
- **[REGISTRY_KEYS.md](REGISTRY_KEYS.md)** - Complete reference of all 478 registry modifications
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Guidelines for contributing to this project

---

<div align="center">

**Made with â¤ï¸ for the Windows Security Community**

[Report Bug](https://github.com/NexusOne23/noid-privacy/issues) Â· [Request Feature](https://github.com/NexusOne23/noid-privacy/issues) Â· [Contribute](CONTRIBUTING.md)

</div>
