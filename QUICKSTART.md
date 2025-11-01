# Quick Start Guide

Get NoID Privacy up and running in 5 minutes!

---

## ⚡ Super Quick Start (3 Steps)

### 1. Download
```powershell
# Open PowerShell as Administrator (Win+X → "Terminal (Admin)")
cd C:\Tools
git clone https://github.com/NexusOne23/noid-privacy.git
cd noid-privacy
```

### 2. Unblock Files
```powershell
Get-ChildItem -Recurse -Filter "*.ps1" | Unblock-File
```

### 3. Run
```powershell
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive
```

**Done!** Follow the on-screen menu.

---

## 📖 For Absolute Beginners

### What You Need
- Windows 11 25H2 (latest version)
- Administrator access
- 10 minutes

### Step-by-Step

#### 1. Open PowerShell as Admin
1. Press `Win + X` on your keyboard
2. Click "Terminal (Admin)" or "Windows PowerShell (Admin)"
3. Click "Yes" when Windows asks for permission

#### 2. Navigate to Your Desired Location
```powershell
# For example, create a Tools folder
cd C:\
mkdir Tools
cd Tools
```

#### 3. Download NoID Privacy

**Option A: If you have Git**
```powershell
git clone https://github.com/NexusOne23/noid-privacy.git
cd noid-privacy
```

**Option B: No Git (Manual Download)**
1. Go to: https://github.com/NexusOne23/noid-privacy
2. Click green "Code" button → "Download ZIP"
3. Extract ZIP to `C:\Tools\noid-privacy`
4. In PowerShell:
```powershell
cd C:\Tools\noid-privacy
```

#### 4. Unblock Downloaded Files
```powershell
Get-ChildItem -Recurse -Filter "*.ps1" | Unblock-File
```

This tells Windows that these files are safe.

#### 5. Run the Script
```powershell
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive
```

#### 6. Follow the Menu
1. **Choose Language**: English or German
2. **Select Mode**: 
   - "Audit Mode" (safe testing) ← Start here!
   - "Enforce Mode" (full hardening)
   - "Custom" (pick specific features)
3. **Create Backup**: Choose "Yes"
4. **Wait**: Script runs (5-10 minutes)
5. **Reboot**: When prompted (some features need restart)

---

## 🎯 What Happens?

### After Audit Mode
- ✅ Settings are **logged** but not enforced
- ✅ You can review what **would** change
- ✅ No actual changes made
- ✅ Safe to test

### After Enforce Mode
- ✅ Windows Defender at maximum protection
- ✅ Firewall hardened (inbound blocked)
- ✅ Telemetry disabled
- ✅ Bloatware removed
- ✅ Privacy settings maximized
- ✅ BitLocker configured (if TPM available)
- ✅ VBS/Credential Guard enabled (after reboot)

---

## ❓ Common Questions

### "Do I need to backup first?"
**Recommended!** The script offers automatic backup. Choose "Yes" when asked.

### "Can I undo changes?"
**Yes!** Run: `.\Restore-SecurityBaseline.ps1`

### "Will this break my PC?"
**No.** The script is designed for maximum security **with** usability. Thousands of systems hardened successfully.

### "How long does it take?"
- **Audit Mode**: 5 minutes
- **Enforce Mode**: 5-10 minutes
- **Reboot**: 2 minutes
- **Total**: 15-20 minutes

### "Do I need TPM 2.0?"
**Not required.** TPM enables additional features:
- BitLocker encryption
- VBS (Virtualization Based Security)
- Credential Guard

Without TPM, other features still work (Defender, Firewall, Privacy, etc.)

### "What if I get an error?"
1. Check if you're running as **Administrator**
2. Check transcript log: `C:\ProgramData\SecurityBaseline\Logs\`
3. Report on GitHub Issues with log attached

---

## 🔍 Verify It Worked

After reboot:
```powershell
cd C:\Tools\noid-privacy
.\Verify-SecurityBaseline.ps1
```

You'll see:
- ✅ Green checkmarks for active features
- ⚠️ Yellow warnings for features needing reboot
- ❌ Red X for missing features (usually hardware-dependent)

---

## 🚀 Next Steps

### Option 1: Stay Updated
```powershell
cd C:\Tools\noid-privacy
git pull origin main
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce
```

### Option 2: Customize
Edit modules in `/Modules/` to adjust settings.

### Option 3: Contribute
See [CONTRIBUTING.md](CONTRIBUTING.md) to improve the project!

---

## 🆘 Need Help?

- **Documentation**: [README.md](README.md) | [INSTALLATION.md](INSTALLATION.md)
- **Issues**: [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues)
- **Support**: [support@noid-privacy.com](mailto:support@noid-privacy.com)

---

## 🎉 You're Done!

Your Windows 11 is now hardened to enterprise security standards!

**What Changed?**
- 🛡️ Security: 400+ settings
- 🔒 Privacy: 300+ settings
- 📊 Coverage: Microsoft Baseline 25H2 (100%)

**Enjoy your secure and private Windows!** 🚀

---

**Last Updated**: November 1, 2025  
**Version**: 1.7.14
