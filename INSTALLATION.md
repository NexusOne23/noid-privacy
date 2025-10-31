# Installation Guide

Complete guide for installing and running NoID Privacy on Windows 11 25H2.

---

## 📋 Pre-Installation Checklist

Before proceeding, verify:

- [ ] **Operating System**: Windows 11 25H2 (Build 26100+)
- [ ] **Administrator Rights**: You have admin access
- [ ] **Backup**: System backup or restore point created
- [ ] **TPM**: TPM 2.0 enabled (for BitLocker, VBS, Credential Guard)
- [ ] **Virtualization**: Enabled in BIOS/UEFI (for VBS, Credential Guard)
- [ ] **Internet**: NOT required (hosts file included locally, DoH only configured)
- [ ] **PowerShell**: Version 5.1+ (check with `$PSVersionTable.PSVersion`)

---

## 🚀 Method 1: Quick Start (Recommended)

### Step 1: Download
```powershell
# Open PowerShell as Administrator
# Press Win+X → "Terminal (Admin)" or "PowerShell (Admin)"

# Navigate to desired location
cd C:\Tools

# Download repository (choose one method):

# Option A: Git Clone
git clone https://github.com/NexusOne23/noid-privacy.git
cd noid-privacy

# Option B: Download ZIP
# Download from: https://github.com/NexusOne23/noid-privacy/archive/refs/heads/main.zip
# Extract to C:\Tools\noid-privacy
```

### Step 2: Verify Integrity (Optional but Recommended)
```powershell
# Verify file hashes to ensure authenticity
# Get-FileHash .\Apply-Win11-25H2-SecurityBaseline.ps1
# Compare with published hash on GitHub Releases
```

### Step 3: Unblock Files
```powershell
# Windows marks downloaded files as potentially unsafe
# Unblock all PowerShell scripts
Get-ChildItem -Path . -Recurse -Filter "*.ps1" | Unblock-File
```

### Step 4: Run Interactive Mode
```powershell
# Start with interactive menu (safest for beginners)
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive
```

---

## 📖 Method 2: Step-by-Step Installation

### Step 1: System Preparation

#### 1.1 Create Backup
```powershell
# Create system restore point
Checkpoint-Computer -Description "Before NoID Privacy" -RestorePointType MODIFY_SETTINGS

# Or use built-in backup
.\Backup-SecurityBaseline.ps1
```

#### 1.2 Verify Requirements
```powershell
# Check Windows version
[System.Environment]::OSVersion.Version
# Should show: Major 10, Build 26100+

# Check PowerShell version
$PSVersionTable.PSVersion
# Should show: 5.1+ or 7.x

# Check TPM status
Get-Tpm
# TpmPresent: True, TpmReady: True

# Check virtualization (for VBS)
Get-ComputerInfo | Select-Object HyperVisorPresent, HyperVRequirementVirtualizationFirmwareEnabled
# Both should be True
```

### Step 2: Download & Extract

#### Option A: Git
```powershell
# Install Git (if not present)
winget install --id Git.Git -e --source winget

# Clone repository
git clone https://github.com/NexusOne23/noid-privacy.git
cd noid-privacy
```

#### Option B: Manual Download
1. Visit: https://github.com/NexusOne23/noid-privacy
2. Click "Code" → "Download ZIP"
3. Extract to desired location (e.g., `C:\Tools\noid-privacy`)
4. Open PowerShell as Administrator
5. Navigate to extracted folder

### Step 3: Configure Execution Policy (If Needed)
```powershell
# Check current policy
Get-ExecutionPolicy

# If "Restricted", temporarily allow scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

# This only affects current PowerShell session
```

### Step 4: Choose Installation Mode

#### Mode A: Interactive (Recommended for First-Time Users)
```powershell
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive

# Features:
# - Language selection (English/German)
# - Module-by-module selection
# - Backup prompt before changes
# - Reboot prompt at end
```

#### Mode B: Audit Mode (Safe Testing)
```powershell
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Audit -SkipReboot

# Features:
# - No enforcement, only logging
# - Safe to test multiple times
# - Review transcript log afterward
# - No system reboot
```

#### Mode C: Enforce Mode (Full Hardening)
```powershell
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce

# Features:
# - Full security baseline enforcement
# - All modules applied
# - Reboot prompt at end
# - Maximum protection
```

### Step 5: Post-Installation

#### 5.1 Reboot System
Some features require restart:
- VBS (Virtualization Based Security)
- Credential Guard
- HVCI (Hypervisor-protected Code Integrity)
- BitLocker (if newly enabled)

```powershell
# Reboot now
Restart-Computer

# Or schedule for later
shutdown /r /t 3600 /c "System reboot for security features"
```

#### 5.2 Verify Installation
```powershell
# After reboot, verify configuration
.\Verify-SecurityBaseline.ps1

# With report export
.\Verify-SecurityBaseline.ps1 -ExportReport

# Check log files
Get-ChildItem "C:\ProgramData\SecurityBaseline\Logs\"
```

#### 5.3 Check Critical Features
```powershell
# Windows Defender status
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, BehaviorMonitorEnabled, AntivirusEnabled

# VBS status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# BitLocker status
Get-BitLockerVolume -MountPoint C:

# Firewall status
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction
```

---

## 🔧 Advanced Installation

### Custom Module Selection

#### Select Specific Modules
```powershell
# Run interactive mode
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive

# Choose:
# 1. Language → English/German
# 2. Mode → Custom Configuration
# 3. Select modules individually
# 4. Review selection
# 5. Confirm and apply
```

### Silent Installation (Automation)
```powershell
# For automated deployment (use with caution!)
# Create backup first
.\Backup-SecurityBaseline.ps1

# Apply in enforce mode without prompts
$confirmation = 'y' | .\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce -SkipReboot

# Schedule reboot
shutdown /r /t 300 /c "Security baseline applied - system will reboot in 5 minutes"
```

### Partial Installation
```powershell
# Load only specific modules manually
. .\Modules\SecurityBaseline-Common.ps1
. .\Modules\SecurityBaseline-Telemetry.ps1

# Apply telemetry hardening only
Disable-TelemetryServices
Set-TelemetryRegistry
Remove-TelemetryTasks
```

---

## 🛠️ Troubleshooting Installation

### Issue: "Script cannot be loaded - Execution Policy"
**Solution:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
```

### Issue: "Access Denied" or "Unauthorized"
**Solution:**
```powershell
# Ensure PowerShell is running as Administrator
# Right-click PowerShell → "Run as Administrator"
```

### Issue: "Module not found"
**Solution:**
```powershell
# Verify all files extracted correctly
Get-ChildItem .\Modules\

# Should show 17 module files
# If missing, re-download from GitHub
```

### Issue: "TPM not found" or "VBS not supported"
**Solution:**
```powershell
# Check TPM
Get-Tpm

# If not present:
# - Check BIOS/UEFI settings
# - Enable TPM 2.0
# - Enable virtualization

# Some features will be skipped automatically if TPM unavailable
```

### Issue: "Script hangs or freezes"
**Solution:**
1. Press `CTRL+C` to interrupt
2. Check transcript log: `C:\ProgramData\SecurityBaseline\Logs\`
3. Identify hanging operation
4. Report issue on GitHub

### Issue: "Third-Party Antivirus Conflicts"
**Solution:**
```powershell
# Some third-party AV may block Defender configuration
# Script detects this and shows warnings

# Options:
# 1. Temporarily disable third-party AV during installation
# 2. Review warnings - most features still work
# 3. Some Defender features (ASR, PUA) may be unavailable
```

---

## 🔄 Post-Installation Management

### Verify Configuration
```powershell
# Quick check
.\Verify-SecurityBaseline.ps1

# Detailed report with CSV export
.\Verify-SecurityBaseline.ps1 -ExportReport
# Report saved to: C:\ProgramData\SecurityBaseline\Verification\
```

### Update Installation
```powershell
# Navigate to repository
cd C:\Tools\noid-privacy

# Pull latest changes
git pull origin main

# Re-apply with updated version
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce
```

### Rollback Changes
```powershell
# Restore from backup
.\Restore-SecurityBaseline.ps1

# Or specify backup file
.\Restore-SecurityBaseline.ps1 -BackupFile "C:\Backups\SecurityBaseline-Backup-20251027-120000.json"
```

---

## 📚 Additional Resources

- **Documentation**: [README.md](README.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security Policy**: [SECURITY.md](SECURITY.md)
- **GitHub Issues**: https://github.com/NexusOne23/noid-privacy/issues
- **Support Email**: [support@noid-privacy.com](mailto:support@noid-privacy.com)

---

## ✅ Installation Complete!

After successful installation and reboot:

1. ✅ Windows Defender: Maximum protection active
2. ✅ Firewall: Inbound blocked, discovery disabled
3. ✅ Telemetry: Services, tasks, registry disabled
4. ✅ Privacy: App permissions default-deny
5. ✅ Bloatware: Pre-installed apps removed
6. ✅ BitLocker: Encryption policies configured
7. ✅ VBS/Credential Guard: Active (if supported)
8. ✅ Network: Stealth mode, legacy protocols disabled
9. ✅ DNS: DNS-over-HTTPS, DNSSEC, blocklist active
10. ✅ Edge: Security hardening applied

**System is now hardened to enterprise security standards!** 🎉

---

**Last Updated**: October 31, 2025  
**Version**: 1.7.13
