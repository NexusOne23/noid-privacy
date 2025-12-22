# 🚀 NoID Privacy v2.2.2 - Performance Release
**Major Performance Fix for Firewall Snapshot Operations**

This is a performance release with a critical fix for slow firewall backup operations that could take 60-120 seconds.

## 🌟 Highlights

- ✅ **Performance Fix** - Firewall snapshot 60-120s → 2-5s
- ✅ **633 Security Settings** across 7 independent modules
- ✅ **100% BAVR Coverage** - Backup, Apply, Verify, Restore
- ✅ **100% Restore Accuracy** - VM tested & verified
- ✅ **Version Alignment** - All 60+ framework files synchronized
- ✅ **GPL v3.0 License** - Dual-licensing available
- ✅ **Production-Ready** - Tested on Windows 11 24H2/25H2

---

## ⚡ What's New in v2.2.2

### Firewall Snapshot Performance Fix (Critical)

| Before | After |
|--------|-------|
| 60-120 seconds | 2-5 seconds |

- **Problem:** Firewall rules backup took 60-120 seconds, especially in offline mode
- **Root Cause:** `Get-NetFirewallPortFilter` was called individually for each of ~300+ firewall rules (~200ms per call)
- **Fix:** Batch query approach - load all port filters once into hashtable, then fast lookup by InstanceID
- **Affected Files:**
  - `Modules/AdvancedSecurity/Private/Backup-AdvancedSecuritySettings.ps1`
  - `Modules/AdvancedSecurity/Private/Disable-RiskyPorts.ps1`

### Version Alignment

- All 60+ framework files updated to v2.2.2
- Module manifests (.psd1), module loaders (.psm1), core scripts, utilities, tests, and documentation synchronized

---

## 📦 Module Overview

| Module | Settings | Description |
|--------|----------|-------------|
| **SecurityBaseline** | 425 | Microsoft Security Baseline 25H2 |
| **ASR** | 19 | Attack Surface Reduction Rules |
| **DNS** | 5 | Secure DNS with DoH encryption |
| **Privacy** | 78 | Telemetry, Bloatware, OneDrive hardening |
| **AntiAI** | 32 | AI Lockdown (Recall, Copilot, Click to Do) |
| **EdgeHardening** | 24 | Microsoft Edge v139 Baseline |
| **AdvancedSecurity** | 50 | Beyond MS Baseline (15 features) |
| **TOTAL** | **633** | **Complete Hardening** |

---

## 🚀 Quick Start

### One-Liner Install:
```powershell
irm https://raw.githubusercontent.com/NexusOne23/noid-privacy/main/install.ps1 | iex
```

### Manual Install:
1. Download **Source code (zip)** below
2. Extract to a folder
3. Run `Start-NoIDPrivacy.bat` as Administrator

### Verify After Installation:
```powershell
.\Tools\Verify-Complete-Hardening.ps1

# Expected output:
# SecurityBaseline: 425/425 verified
# ASR: 19/19 verified
# DNS: 5/5 verified
# Privacy: 78/78 verified
# AntiAI: 32/32 verified
# EdgeHardening: 24/24 verified
# AdvancedSecurity: 50/50 verified
# Total: 633/633 (100%)
```

---

## 🎯 System Requirements

| Requirement | Specification |
|-------------|---------------|
| **OS** | Windows 11 24H2 (Build 26100+) or 25H2 (Build 26200+) |
| **PowerShell** | 5.1+ (built-in) |
| **Admin Rights** | Required |
| **TPM** | 2.0 (for BitLocker, Credential Guard, VBS) |
| **RAM** | 8 GB minimum (16 GB recommended for VBS) |

> ⚠️ **Note:** Windows 11 23H2 and older are **not supported**. Please update to 24H2 or newer.

---

## 🛡️ Antivirus Compatibility

| Your Setup | What Happens | Coverage |
|------------|--------------|----------|
| **Defender Active** | All modules applied | 633 settings (100%) |
| **3rd-Party AV** | ASR skipped, all other modules applied | 614 settings (~97%) |

---

## 📋 Full Changelog

See [CHANGELOG.md](CHANGELOG.md)

---

## 📜 License

| Version | License |
|---------|---------|
| v1.8.3 and earlier | MIT License |
| v2.0.0 and later | GPL v3.0 + Commercial dual-licensing |

See [LICENSE](LICENSE)

---

## 🔐 Code Quality & Testing

- **Testing:** Unit and integration tests available in `Tests/` directory
- **Verification:** 633 automated compliance checks in production
- **VM Tested:** Full Apply → Verify → Restore cycle verified
- **Performance:** Firewall operations now complete in seconds, not minutes
- **Version Alignment:** All 60+ files now have consistent version numbers
- **Analysis:** Run `.\Tests\Run-Tests.ps1` to validate yourself
- **Report vulnerabilities:** [Security Advisories](https://github.com/NexusOne23/noid-privacy/security/advisories)

---

## 💬 Support & Community

- 📖 **Documentation:** [README.md](README.md)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/NexusOne23/noid-privacy/discussions)
- 🐛 **Issues:** [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues)
- 💼 **Commercial Licensing:** Contact via Discussions

---

## ⚠️ Important Warnings

- ⚠️ **Create a system backup** before running (CRITICAL!)
- ⚠️ **Test in a VM first** (recommended)
- ⚠️ **Domain-joined systems:** Coordinate with IT team
- ⚠️ **Read documentation** thoroughly

---

<div align="center">

**Made with 🛡️ for the Windows Security Community**

**NexusOne23** • **v2.2.2** • **December 2025**

</div>
