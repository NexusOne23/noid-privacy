# Frequently Asked Questions (FAQ)

Common questions about NoID Privacy and their answers.

---

## 📋 General Questions

### What is NoID Privacy?

NoID Privacy is a comprehensive PowerShell-based security hardening solution for Windows 11 25H2. It implements the Microsoft Security Baseline with extensive privacy enhancements.

### Who is this for?

- Home power users who want enterprise-grade security
- Small business workstations
- IT professionals managing standalone systems
- Privacy-conscious users
- Security researchers

### Is this safe to use?

**Yes.** The script:
- ✅ Follows Microsoft Security Baseline 25H2
- ✅ Uses only official Windows commands
- ✅ Includes backup & restore functionality
- ✅ Has been tested on numerous systems
- ✅ Is completely open-source (you can review the code)

### Can I undo changes?

**Absolutely!** Use the backup & restore functionality:
```powershell
.\Restore-SecurityBaseline.ps1
```

---

## 🔧 Installation & Usage

### Do I need to be an expert to use this?

**No.** The interactive mode guides you through:
1. Language selection
2. Mode selection (Audit/Enforce)
3. Automatic backup
4. Progress indicators
5. Clear status messages

### What's the difference between Audit and Enforce mode?

| Mode | What It Does | Safe? | Actual Changes? |
|------|--------------|-------|-----------------|
| **Audit** | Logs what would change | ✅ Yes | ❌ No |
| **Enforce** | Applies all changes | ✅ Yes | ✅ Yes |

**Recommendation**: Start with Audit mode to review changes.

### How long does it take?

- **Audit Mode**: ~5 minutes
- **Enforce Mode**: ~5-10 minutes
- **Reboot**: ~2 minutes (for VBS, Credential Guard, BitLocker)
- **Total**: 15-20 minutes including reboot

### Can I run it multiple times?

**Yes!** The script is idempotent - you can run it as many times as you want without issues.

### What happens after Windows Updates?

**It depends on the update type:**

| Update Type | Frequency | Impact on Settings | Action Required |
|-------------|-----------|-------------------|------------------|
| **Monthly Quality Updates** | Every month (Patch Tuesday) | ✅ Minimal - settings stay intact | ❌ No re-run needed |
| **Cumulative Updates** | As released | ✅ Minimal - settings stay intact | ❌ No re-run needed |
| **Feature Updates** | 1-2x per year (e.g., 25H2 → 26H2) | ⚠️ **Can reset many settings** | ✅ **Re-run script recommended** |
| **Preview/Insider Builds** | Beta releases | 🔴 Can reset everything | ✅ Disabled by script (Module 12) |

**What gets reset in Feature Updates?**
- ❌ Privacy Toggles (Camera, Microphone, Location - **must set manually**)
- ❌ Start Menu Layout, Taskbar Settings
- ⚠️ Telemetry Settings (often back to 'Basic')
- ⚠️ OneDrive Auto-Backup, Consumer Features
- ✅ Most critical settings stay (Services, Firewall, ASR, VBS, DoH, hosts file)

**When to re-run the script:**
1. **After Feature Updates** (e.g., Windows 11 26H2 in ~September 2026)
2. **If you notice:** New apps installed, telemetry running, web search results in Start Menu
3. **Anytime you want** - script is idempotent and safe to repeat!

**Next major update:** Windows 11 26H2 (~September 2026) - re-run script after upgrade!

---

## 🛡️ Security Questions

### Does this replace antivirus software?

**No, it enhances Windows Defender.** The script:
- Configures Windows Defender to maximum protection
- Does **not** install third-party antivirus
- Works alongside most third-party AV (may show warnings)

If you have third-party AV, some Defender features (ASR, PUA) may be unavailable - this is normal and expected.

### What about ransomware protection?

**Multiple layers:**
- ✅ Windows Defender with real-time protection
- ✅ Attack Surface Reduction (ASR) rules (19 rules)
- ✅ Controlled Folder Access (ransomware protection)
- ✅ Exploit Protection (system-wide mitigations)
- ✅ Smart App Control (reputation-based)

### Why is Tamper Protection NOT included?

**Tamper Protection would prevent you from managing Defender.**

**What Tamper Protection does:**
- Locks Windows Defender settings (cannot be disabled)
- Blocks registry modifications to Defender keys
- Prevents stopping Defender services
- Makes it impossible to temporarily disable real-time protection

**Why we DON'T include it:**
1. **Too restrictive for daily use**
   - Cannot temporarily disable Defender for software installation
   - Cannot quick-disable for troubleshooting
   - Requires restore script just to install some software

2. **Our target audience doesn't need it**
   - We target power users and SMB, not enterprise
   - Power users need flexibility
   - Restore script available for full reset if needed

3. **What you CAN do instead:**
   - Add exclusions via Windows Security GUI (always works)
   - Use the restore script when you need full Defender control
   - Controlled Folder Access + ASR rules provide strong protection

**If you WANT Tamper Protection:**
- Enable it manually: Windows Security → Virus & threat protection → Manage settings → Tamper Protection (toggle ON)
- This is an informed choice you can make after running the script

**Note:** This is an intentional decision for user flexibility. Enterprise environments should use Group Policy to enforce Tamper Protection centrally.

### Does this protect against all attacks?

**No solution is 100% secure.** This script provides:
- ✅ Strong baseline security (Microsoft standards)
- ✅ Defense-in-depth (multiple layers)
- ✅ Privacy protection (telemetry disabled)
- ❌ Not a substitute for safe browsing habits
- ❌ Not a substitute for software updates
- ❌ Not a substitute for user awareness

### Will this stop zero-day attacks?

**It significantly reduces attack surface:**
- ✅ ASR rules block many exploit techniques
- ✅ Exploit protection mitigates zero-day exploitation
- ✅ Credential Guard prevents credential theft
- ✅ Smart App Control blocks unknown malware
- ⚠️ But zero-day attacks by definition exploit unknown vulnerabilities

---

## 💻 Technical Questions

### What Windows version do I need?

**Windows 11 25H2** (Build 26100+)

Older versions may work but are not officially supported.

### Do I need TPM 2.0?

**Not required, but recommended.**

**Without TPM:**
- ✅ Defender, Firewall, Privacy, DNS, etc. all work
- ❌ No BitLocker encryption
- ❌ No VBS (Virtualization Based Security)
- ❌ No Credential Guard

**With TPM 2.0:**
- ✅ All features available
- ✅ BitLocker with XTS-AES-256
- ✅ VBS + HVCI
- ✅ Credential Guard (LSA-PPL)

### What about domain-joined systems?

**This script is designed for standalone/workgroup systems.**

For domain environments:
- Use Group Policy instead
- Some settings (Password Policy, Account Lockout) require domain
- This script focuses on local machine hardening

### Can I use Remote Desktop (RDP) with this script?

**Yes! The script asks during setup:**

**During Interactive Mode:**
```
Do you use Remote Desktop (RDP) or run local services?

[1] Maximum Security (Desktop/Laptop)
    - RDP completely disabled
    - Firewall ultra-strict (blocks all inbound)

[2] Allow Remote Access + Local Services
    - RDP stays enabled (for Tailscale/VPN)
    - Firewall allows localhost connections
```

**Choose Option 2 if you:**
- ✅ Access your PC remotely (RDP, Tailscale, VPN)
- ✅ Run a home server or NUC
- ✅ Host local services (Docker, LLM, OpenWebUI, Ollama)
- ✅ Develop software (Node, Python, WSL)

**Choose Option 1 if you:**
- ✅ Use a standard desktop or laptop
- ✅ Never access remotely
- ✅ Want maximum security

**Important Security Note:**
If you choose Option 2 (RDP enabled):
- ⚠️ **NEVER expose RDP directly to the internet!**
- ✅ Always use VPN (WireGuard, Tailscale, OpenVPN)
- ✅ Or use SSH tunneling
- 🔴 Direct internet exposure = **HIGH RISK** (brute-force attacks!)

**Non-Interactive Mode:**
- Default = Maximum Security (RDP disabled)
- Use parameter `-AllowRemoteAccess` to keep RDP enabled (future feature)

### Does this work with third-party antivirus?

**Yes! But Verify results will differ:**

Third-party antivirus products (Bitdefender, Kaspersky, Norton, etc.) **replace** Windows Defender, which affects certain features.

---

**📊 Expected Verify Results:**

| Antivirus Type | PASS Count | Percentage | Status |
|----------------|-----------|------------|--------|
| **Windows Defender** | 120/121 | 99% | ✅ Excellent |
| **Third-Party AV** | 98-102/121 | 81-84% | ✅ **Expected!** |

---

**✅ Still Works (99% of script):**
- ✅ All Registry-based policies
- ✅ Firewall rules
- ✅ BitLocker policies
- ✅ UAC settings
- ✅ VBS/Credential Guard
- ✅ SMB/Network hardening
- ✅ Services management
- ✅ Bloatware removal
- ✅ Telemetry disabling

**❌ May Not Work (Defender-specific):**
- ❌ ASR Rules (19 checks) - **Replaced by AV's exploit prevention**
- ❌ Network Protection - **Replaced by AV's web filtering**
- ❌ Cloud Protection - **Replaced by AV's cloud scanning**
- ❌ PUA Protection - **Replaced by AV's malware detection**
- ❌ Controlled Folders - **Replaced by AV's ransomware protection**

**Result:** Your system is **still fully protected** - third-party AV provides equivalent features!

---

**✅ Tested & Working (Third-Party AVs):**
- ✅ **Windows Defender** (native) - 120/121 PASS
- ✅ **Bitdefender** - 98/121 PASS (RestrictRemoteSAM exclusion recommended)
- ✅ **Kaspersky** - ~100/121 PASS
- ✅ **Norton/Symantec** - ~100/121 PASS
- ✅ **ESET NOD32** - ~100/121 PASS

**⚠️ May Require Exclusions:**
- Third-party AVs (especially Bitdefender): RestrictRemoteSAM false positive (add registry key to exclusions)
- Norton/Avast: May flag PowerShell execution (add script folder to exclusions)

**📖 Full Documentation:** See [ANTIVIRUS_COMPATIBILITY.md](ANTIVIRUS_COMPATIBILITY.md) for detailed workarounds and solutions

### Does this slow down my PC?

**Minimal performance impact:**
- VBS/Credential Guard: ~2-5% CPU overhead (modern CPUs)
- BitLocker: Negligible (hardware AES-NI acceleration)
- Telemetry disablement: Actually *improves* performance
- Bloatware removal: Improves startup time

**Real-world:** Most users notice no difference or slightly faster boot times.

---

## 🔒 Privacy Questions

### What telemetry is disabled?

**Comprehensive telemetry disablement:**
- ✅ Diagnostic & usage data
- ✅ Advertising ID
- ✅ Activity history
- ✅ App diagnostic info
- ✅ Feedback requests
- ✅ Handwriting & typing data
- ✅ Location services
- ✅ Windows Search web integration
- ✅ Timeline sync
- ✅ Xbox Game Bar telemetry

### Are Recall and Copilot removed?

**Yes, completely blocked (4 layers):**

1. **Services**: Disabled
2. **Registry**: Blocked
3. **Scheduled Tasks**: Disabled
4. **Group Policy**: Enforced

**Result:** Recall and Copilot are permanently disabled and cannot be re-enabled via Settings.

### What happens to my camera and microphone?

**Default-deny for apps:**
- ✅ Apps have **no access** by default
- ✅ You can enable per-app in Settings
- ✅ System camera/mic still work (video calls, etc.)
- ✅ User has full control

**Not blocked:** Windows Hello (facial recognition), if you use it.

### Can Microsoft still track me?

**Heavily reduced, but not 100%:**
- ✅ ~95% of telemetry disabled
- ✅ Advertising ID disabled
- ✅ Activity history disabled
- ✅ App diagnostics disabled
- ❌ Some core telemetry remains (e.g., Windows Update)
- ❌ Microsoft accounts still sync (if you use one)

**For 100% privacy:** Use local account instead of Microsoft account.

---

## 🌐 DNS & Network Questions

### What DNS provider is used?

**You can choose from 4 enterprise-grade DNS-over-HTTPS (DoH) providers:**

| Provider | Best For | Servers (IPv4) |
|----------|----------|----------------|
| **Cloudflare** (Default) | Speed + Global Coverage | 1.1.1.1, 1.0.0.1 |
| **AdGuard DNS** | Privacy + Built-in Blocking | 94.140.14.14, 94.140.15.15 |
| **NextDNS** | Customization + Analytics | 45.90.28.0, 45.90.30.0 |
| **Quad9** | Security + Threat Intel | 9.9.9.9, 149.112.112.112 |

**All Providers Include:**
- ✅ **100% Encrypted:** DNS-over-HTTPS (DoH) with no fallback to plain DNS
- ✅ **Strict Enforcement:** `autoupgrade=yes`, `udpfallback=no`
- ✅ **Dual-Stack:** IPv6 + IPv4 support
- ✅ **DNSSEC:** Validated DNS responses (prevents spoofing)
- ✅ **Privacy:** No user tracking, better than ISP DNS

**Default:** Cloudflare (fastest, global CDN, 1.1.1.1)

**→ See [FEATURES.md](FEATURES.md#-network-security) for detailed provider comparison**

### How many domains are blocked?

**107,772 unique domains** from Steven Black Unified Hosts list (updated Nov 5, 2025, 12,025 lines × 9 domains per line).

**Categories:**
- Malware domains
- Tracking/analytics
- Ad networks
- Coin miners
- Phishing sites
- Telemetry servers

### Why only 12,025 lines in the hosts file?

**Reason:** Windows DNS Cache optimization

**Background:**
- Steven Black hosts list has 107,772 unique domains
- Original format: 1 domain per line = 107,772 lines
- Windows DNS Cache has ~16,000 line limit (breaks after that!)

**Our Solution:**
- ✅ **9 domains per line** (community best practice)
- ✅ 107,772 domains compressed to 12,025 lines
- ✅ **Full protection, zero performance impact**
- ✅ DNS cache stays fast and efficient

**Format example:**
```
0.0.0.0 tracker1.com tracker2.com tracker3.com ... (9 domains)
```

### Will this block legitimate websites?

**No.** Steven Black Unified Hosts is community-vetted:
- ✅ Only malicious/tracking domains
- ✅ No false positives on major sites
- ✅ Regularly updated
- ❌ Won't block Google, Facebook, Amazon, etc. (main domains)
- ✅ Will block their tracking/analytics subdomains

**If a site breaks:** Temporarily disable by renaming hosts file and reboot.

### Can I use my own DNS provider?

**Yes - 4 providers are built-in!**

**Option 1: Use Built-in Providers (Recommended)**
- Edit `Modules/SecurityBaseline-DNS.ps1` and call your preferred provider:
  - `Enable-CloudflareDNS` - Fast, global CDN (default)
  - `Enable-AdGuardDNS` - Privacy + ad blocking
  - `Enable-NextDNS` - Customization (optional profile ID)
  - `Enable-Quad9DNS` - Security + threat intel

**Option 2: Custom Provider**
- Edit `Modules/SecurityBaseline-DNS-Providers.ps1`
- Add your own function following the existing patterns
- Must support DoH with strict enforcement (`autoupgrade=yes`, `udpfallback=no`)

### Does DNS-over-HTTPS slow down browsing?

**No, usually faster:**
- Initial DoH connection: ~50ms overhead (one-time)
- After that: Same speed or faster (depends on provider's CDN)
- Encryption overhead: Negligible (<1ms per query)
- **Benefit:** ISP can't see or hijack your DNS queries

---

## 🚨 Troubleshooting

### "Script already running in another session"

**Cause:** Another instance is running or didn't exit cleanly.

**Solution:**
1. Wait for other instance to finish
2. Or reboot system
3. Or manually release mutex (advanced)

### "Access Denied" errors

**Cause:** Not running as Administrator.

**Solution:** Right-click PowerShell → "Run as Administrator"

### VBS/Credential Guard not active after reboot

**Causes:**
1. No TPM 2.0
2. Virtualization disabled in BIOS
3. Hardware incompatibility

**Solution:**
1. Check TPM: `Get-Tpm`
2. Enable virtualization in BIOS/UEFI
3. Verify: `.\Verify-SecurityBaseline.ps1`

### BitLocker not activating

**Causes:**
1. No TPM 2.0
2. Insufficient disk space
3. Disk already encrypted by third-party tool

**Solution:**
1. Check TPM: `Get-Tpm`
2. Ensure 256 GB+ free space
3. Manual activation: Control Panel → BitLocker

### Some settings not applied

**Check:**
1. Third-party AV may block some Defender features (expected)
2. Review transcript log: `C:\ProgramData\SecurityBaseline\Logs\`
3. Run `.\Verify-SecurityBaseline.ps1` to see what's active

### Script hangs or freezes

**Solution:**
1. Press `CTRL+C` to interrupt
2. Check transcript log for hanging operation
3. Report issue on GitHub with log attached

---

## 📊 Compliance Questions

### Is this HIPAA/GDPR/SOC2 compliant?

**Partially.** This script provides:
- ✅ Strong technical security controls
- ✅ Privacy protection
- ✅ Audit logging

**But compliance also requires:**
- ❌ Organizational policies
- ❌ Access controls
- ❌ Incident response procedures
- ❌ Regular audits
- ❌ Documentation

**Conclusion:** This script is a *component* of compliance, not complete compliance.

### Does this meet CIS Benchmark?

**CIS Level 1:** ~85% (standalone focus)  
**CIS Level 2:** ~90% (with privacy extensions)

**Missing:** Domain-specific settings (Password Policy, Account Lockout, etc.)

### What about DoD STIG?

**~75% coverage** (standalone environment)

**Missing:** Domain-specific requirements, physical security, FIPS 140-2 mode

---

## 🐛 Troubleshooting

### Why do I get a "Stack Buffer Overflow" error from ShellHost.exe?

**Full Error Message:**  
*"Das System hat in dieser Anwendung den Überlauf eines stapelbasierten Puffers ermittelt..."*

**What It Means:**
- This error appears ONLY when you click the **"Cast"** button (Windows + K or Quick Settings → Cast/Wiedergeben)
- It happens after running the **Wireless Display / Miracast** module
- Windows Shell tries to access disabled Miracast services
- **It's a COSMETIC warning, NOT a real security threat**
- The system is working as designed - services are intentionally disabled

**Important:** Error does NOT appear automatically at startup - only when you actively try to cast

**Why Does It Happen:**
The Wireless Display module disables casting functionality on 4 levels:
1. Services (ProjSvc, DevicePickerUserSvc)
2. Registry policies (PlayToReceiver, WirelessDisplay)
3. Firewall rules
4. App removal (SecondaryTileExperience)

When Windows Shell expects these services but finds them disabled, it throws this warning as a safety mechanism.

**How to Avoid:**
```
1. Run script in Interactive Mode
2. Select "Custom" when prompted
3. DESELECT "Wireless Display / Miracast" module
4. Script will skip Miracast hardening
```

**How to Fix If Already Applied:**
```powershell
# Run restore script
.\Restore-SecurityBaseline.ps1

# Services and Registry will restore automatically
# Apps need manual reinstall from Microsoft Store
```

**Impact:**
- Casting to Smart TV won't work
- Miracast/Wireless Display disabled
- "Cast" button in Quick Settings remains but does nothing

**See Also:** [KNOWN_ISSUES.md](KNOWN_ISSUES.md#miracast--wireless-display-breaking-feature) for detailed explanation

---

## 🔄 Update & Maintenance

### How do I update to the latest version?

```powershell
cd C:\Tools\noid-privacy
git pull origin main
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce
```

### Do I need to reapply after Windows Updates?

**Usually no.** Most settings persist through Windows Updates.

**Exception:** Major feature updates (e.g., 25H2 → 26H2) may reset some settings. Re-run script after major updates.

### How often should I run this?

**Once is usually enough.**

**Re-run if:**
- After major Windows feature updates
- After hardware changes (new CPU, TPM)
- If you notice settings reverted
- When script updates with new features

---

## 🔧 Troubleshooting

### Scripts won't start - "Internet security settings prevent execution"

**Symptom:**
- Can't start `.bat` or `.ps1` files
- Error: "Internet security settings prevent opening this file"
- Windows blocks downloaded files

**Cause:**
Windows marks files downloaded from the Internet with a **Zone.Identifier** (Mark of the Web). This prevents execution even with admin rights.

**Solution 1: Automatic (Recommended)**
```batch
# Simply run Start-NoID-Privacy.bat as Administrator
# It will automatically unblock all files!
```

The launcher automatically runs:
```powershell
Get-ChildItem -Recurse -Include *.ps1,*.psm1 | Unblock-File
```

**Solution 2: Manual Unblock**

If automatic unblock fails:

1. **Right-click** on `Start-NoID-Privacy.bat`
2. Select **Properties**
3. At the bottom: Check **"Unblock"** ✅
4. Click **OK**
5. Repeat for all `.ps1` files if needed

**Solution 3: PowerShell Command**

Open PowerShell as Administrator in the project folder:
```powershell
Get-ChildItem -Path . -Recurse -Include *.ps1,*.psm1,*.bat -File | Unblock-File
```

**Prevention:**

Download the repository directly via Git instead of ZIP:
```bash
git clone https://github.com/NexusOne23/noid-privacy.git
```
Git-cloned files don't have Zone.Identifier!

---

## 🆘 Still Have Questions?

- **Documentation**: [README.md](README.md) | [INSTALLATION.md](INSTALLATION.md) | [FEATURES.md](FEATURES.md)
- **Issues**: [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues)
- **Support**: [support@noid-privacy.com](mailto:support@noid-privacy.com) - General questions and help
- **Security**: [security@noid-privacy.com](mailto:security@noid-privacy.com) - Security vulnerabilities only

---

**Last Updated**: November 5, 2025  
**Version:** 1.7.21
