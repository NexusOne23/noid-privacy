# Security Policy

## 🔒 Reporting Security Vulnerabilities

We take the security of NoID Privacy seriously. If you discover a security vulnerability, please follow responsible disclosure practices.

Before attaching logs or exported reports, review them for environment-specific data. HTML compliance reports redact the computer name, user SIDs, user-profile paths and e-mail-like identifiers by default; plain-text operational logs are local diagnostic artifacts and can still contain paths, adapter names or administrator-entered values.

### ✅ How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security issues via one of these methods:

1. **GitHub Security Advisory** (Preferred)
   - Go to: https://github.com/NexusOne23/noid-privacy/security/advisories
   - Click "Report a vulnerability"
   - Fill out the private security advisory form

Do not place vulnerability details in Issues or Discussions; those surfaces are not assumed private. If GitHub's private advisory form is unavailable, publish no sensitive reproduction data until a private channel is available.

### 📋 What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What can an attacker achieve?
- **Affected Versions**: Which versions are affected?
- **Steps to Reproduce**: Detailed reproduction steps
- **Proof of Concept**: PoC code if applicable (optional)
- **Suggested Fix**: If you have one (optional)

### ⏱️ Response Handling

Reports are triaged by severity and reproducibility. We aim to acknowledge new reports within 72 hours and to remediate confirmed vulnerabilities in a timely, severity-appropriate manner; security fixes for NoID Privacy Pro are delivered free of charge as regular product updates. For the free-standing open-source distribution of this repository, no fixed contractual remediation deadline is guaranteed.

### 🎖️ Recognition

We appreciate responsible disclosure! Contributors will be:
- Credited in the CHANGELOG (if desired)
- Acknowledged in the published security advisory for the fix
- Eligible for recognition for significant findings

---

## 🛡️ Security Features

NoID Privacy implements multiple security layers:

### Design Principles
- ✅ **Inbox runtime boundary**: No bundled third-party DLLs/executables and no LGPO.exe; Windows PowerShell 5.1, Windows cmdlets and inbox executables are required
- 🔐 **Code-signing boundary**: The NoID Privacy Pro installer and application binaries are Authenticode-signed (publisher: Fabio Mantegna). This standalone engine repository distributes reviewed source scripts rather than Authenticode-signed script artifacts. Its published SHA256 manifest detects ZIP corruption/substitution relative to that manifest; establish publisher trust by starting from a specifically reviewed tag/commit (see "Before Running" below)
- ✅ **Verification**: complete declared-target accounting (a stable 703-target scope; the 647-check MSRecommended/default-decision profile, applicability and unselected options remain distinct; see `Config/SettingsCounts.json`)
- ✅ **Rollback**: exact sealed prestate restore for every applicable NoID Privacy-owned target admitted to Apply (see the scope boundary in README)

### Security Hardening Applied
- 🔐 One Microsoft Security Baseline 26H2-derived profile for fully supported Windows 11 24H2/25H2/26H2 (425 targets)
- 🛡️ Attack Surface Reduction (19 declared rules; 18 apply to Windows 11 clients and the Exchange-server Webshell rule is NotApplicable)
- 🔒 Credential Guard* + VBS + HVCI policy configuration (*Credential Guard entitlement is Enterprise/Education; hardware/licensing still apply)
- 🤖 AI policy hardening (Recall, Copilot compatibility controls, etc.)
- 🌐 DNS-over-HTTPS with explicit REQUIRE (no classic-DNS fallback) or ALLOW mode

---

## 📊 Supported Versions

The current release is **2.2.6**, targeting Windows 11 26H2 with full 24H2 and
25H2 support. Native x64 and 64-bit Windows PowerShell 5.1 are required;
per-target edition, hardware and product limits still apply.

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 2.2.x   | ✅ Supported | Use 2.2.6 for Windows 11 26H2; its default decisions declare 647 checks |
| 2.1.x   | ⚠️ Limited Support  | Upgrade to 2.2.x recommended |
| 2.0.x   | ❌ Not Supported   | Deprecated |
| 1.8.x   | ❌ Not Supported   | Legacy version (MIT license) |

Backup compatibility is separate from security support: valid sealed backups
from 2.2.5 onward retain their historical restore readers. The
[retained 2.2.4 release](https://github.com/NexusOne23/noid-privacy/releases/tag/v2.2.4)
provides the recovery path for the older format; never migrate or relabel those
backup directories as current sealed sessions.

**Recommendation:** Use a specifically reviewed tagged release and verify its published checksum manifest; do not treat the moving main branch as a release artifact.

---

## 🔐 Security Best Practices for Users

### Before Running
1. ✅ **Verify Script Integrity**

   A locally reviewed copy of the web installer (`install.ps1`) downloads and verifies
   the exact tagged release ZIP against `CHECKSUMS.sha256` before unpacking.
   It refuses missing/ambiguous assets and does not fall back to an unverified
   main-branch archive. For a manual tagged-release download:
   ```powershell
   # Compare this hash and exact ZIP filename with the release's CHECKSUMS.sha256 line
   Get-FileHash .\NoIDPrivacy-v2.2.6.zip -Algorithm SHA256
   ```
   Each correctly published GitHub release manifest binds the distributable ZIP consumed by the
   installer. The installer then validates the extracted version markers,
   all PowerShell syntax and every JSON file before replacing an installation.
   Main-branch downloads are not covered by a published release manifest.

   Do not pipe the network response for `install.ps1` directly into execution. That would not independently authenticate or permit prior review of the bootstrap script itself. Download it separately from an exact reviewed commit/tag, inspect or verify the local file, and only then execute that file.

2. ✅ **Choose a protected install location on shared PCs**
   - The scripts run with Administrator rights. The default folder
     `%USERPROFILE%\NoIDPrivacy` can be modified by any process running as
     your user account.
   - On shared or managed PCs install to a folder only administrators can
     change: run the installer with `-InstallPath "$env:ProgramFiles\NoIDPrivacy"`.
     Backups, logs and reports are kept in that folder as well.

3. ✅ **Review Code**
   - This is open-source - read the code!
   - Understand what changes will be made
   - Check CHANGELOG for recent changes

4. ✅ **Create Backup**
   - System Restore Point
   - Full system image
   - VM snapshot (if applicable)

### During Execution
- ⚠️ Run as Administrator (required)
- ⚠️ Keep endpoint protection enabled; if it blocks the tool, investigate the exact detection rather than disabling protection globally
- ⚠️ Close sensitive applications
- ⚠️ Review verification report

### After Execution
- ✅ Run verification: `.\Tools\Verify-Complete-Hardening.ps1`
- ✅ Review HTML compliance report
- ✅ Test critical applications
- ✅ Retain independent backups according to your own recovery policy

---

## 🚨 Known Security Considerations

### Domain-Joined Systems
- ⚠️ Effective local values can conflict with overlapping Domain GPOs
- ⚠️ Domain policy can overwrite overlapping values during startup, sign-in, manual or background refresh
- ✅ **Recommendation**: Use in standalone/workgroup systems only

### Third-Party Software Compatibility
- ⚠️ ASR rules may block unknown installers
- ⚠️ Some hardening settings may affect application functionality
- ✅ **Response**: Identify the exact control, prefer a verified single-file ASR exclusion, or rerun the ASR module with its explicit audited compatibility choice; keep Tamper Protection enabled (see `Docs/TROUBLESHOOTING.md`)

### Rollback Boundary
- ✅ Privacy Tier 1 (policy-based in-box app removal, Enterprise/Education 24H2+) backs up and restores its owned policy values exactly
- ⚠️ Tier 1's downstream removal is destructive: restoring the policy removes the block but does not reprovision apps or recover deleted local app data
- ✅ Privacy Tier 2 (classic per-user AppX removal, all editions) is explicitly excluded from the exact-restore BAVR boundary because a winget reinstall cannot be restored byte-for-byte to the prior package/provisioning state; its restore path (`Restore-BloatwareApps`) is a separate, clearly labeled best-effort action, never an automatic or exact restore
- ⚠️ AntiAI Recall policies can delete existing Recall snapshots and remove the component after restart. Registry Restore cannot recreate deleted data or automatically reinstall the component; see [the recorded policy boundary](Docs/RELEASE-NOTES-2.2.6.md#backup-and-restore-compatibility).
- ⚠️ SecurityBaseline restart and firmware recovery require separate evidence; restoring registry values alone does not prove post-restart recovery. See [recovery limits](Docs/SECURITY-BASELINE-RECOVERY.md).
- ✅ **Solution**: Test in a disposable VM and maintain an independent system backup

---

## 📚 Security Resources

- **Microsoft Security Baseline**: https://aka.ms/securitybaselines
- **Attack Surface Reduction**: https://aka.ms/ASRrules
- **Windows Security Documentation**: https://learn.microsoft.com/windows/security/

---

## 🔍 Code Quality

### Testing & Validation
- **PSScriptAnalyzer 1.25.0**: exact CI version for static analysis
- **Pester 5.9.0**: exact local/CI version for the unit and integration suites in `Tests/`
- **Verification**: declared-target verification against the 647-check MSRecommended/default-decision profile in `Config/SettingsCounts.json`; unselected or inapplicable checks are never counted as passed

Run tests yourself:
```powershell
.\Tests\Run-Tests.ps1
```

## 📄 License & Legal

- **License**: GNU General Public License v3.0
- **Disclaimer**: Use at your own risk. No warranties provided.
- **Policy origin**: Implements a profile derived from Microsoft's Windows 11 26H2 Security Baseline plus explicitly documented deviations and additional NoID Privacy security/privacy choices; it is not a Microsoft compliance certification

For licensing questions, see [LICENSE](LICENSE) or open a [Discussion](https://github.com/NexusOne23/noid-privacy/discussions).

---

**Last Updated**: 2026-10-03
**Policy Version**: 2.2.6
