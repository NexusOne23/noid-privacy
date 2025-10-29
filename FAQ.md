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

### Does this work with third-party antivirus?

**Mostly yes, with caveats:**

✅ **Works with:**
- Bitdefender
- Norton
- Kaspersky
- ESET
- McAfee
- Most others

⚠️ **May show warnings:**
- Some Windows Defender features unavailable (ASR, PUA)
- This is expected and harmless
- Core hardening still works

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

**Cloudflare DNS-over-HTTPS (DoH)**

**IPv4:**
- Primary: 1.1.1.1
- Secondary: 1.0.0.1

**IPv6:**
- Primary: 2606:4700:4700::1111
- Secondary: 2606:4700:4700::1001

**Protocol:** DNS-over-HTTPS (encrypted, no fallback to unencrypted DNS)

**Why Cloudflare?**
- ✅ Privacy-first (no user tracking)
- ✅ Fast (one of the fastest DNS resolvers globally)
- ✅ Supports DNSSEC (validated by Cloudflare resolver)
- ✅ Free and open
- ✅ Better privacy than ISP DNS

### How many domains are blocked?

**79,776 unique domains** from Steven Black Unified Hosts list (8,864 lines × 9 domains per line).

**Categories:**
- Malware domains
- Tracking/analytics
- Ad networks
- Coin miners
- Phishing sites
- Telemetry servers

### Why only 8,864 lines in the hosts file?

**Compression for Windows DNS Cache performance!**

**The Problem:**
- Steven Black original: ~80,000+ domains = ~80,000+ lines
- Windows DNS Cache: Performance issues with large hosts files (community best practice: keep under ~20k entries)
- 80k+ lines would cause cache overflow
- Result: Slow DNS lookups, network issues

**Our Solution:**
- ✅ **9 domains per line** (community best practice)
- ✅ 79,776 domains compressed to 8,864 lines
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

**Yes!** Edit the DNS module before running:
- File: `Modules/SecurityBaseline-DNS.ps1`
- Change Cloudflare IPs to your preferred DNS
- Examples: Quad9 (9.9.9.9), Google (8.8.8.8), NextDNS

### Does DNS-over-HTTPS slow down browsing?

**No, usually faster:**
- Initial DoH connection: ~50ms overhead (one-time)
- After that: Same speed or faster (Cloudflare's CDN)
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

## 🆘 Still Have Questions?

- **Documentation**: [README.md](README.md) | [INSTALLATION.md](INSTALLATION.md) | [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)
- **Issues**: [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues)
- **Support**: [support@noid-privacy.com](mailto:support@noid-privacy.com) - General questions and help
- **Security**: [security@noid-privacy.com](mailto:security@noid-privacy.com) - Security vulnerabilities only

---

**Last Updated**: October 27, 2025  
**Version**: 1.0
