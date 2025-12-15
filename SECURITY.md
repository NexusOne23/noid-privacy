# Security Policy

## 🔒 Reporting Security Vulnerabilities

We take the security of NoID Privacy seriously. If you discover a security vulnerability, please follow responsible disclosure practices.

### ✅ How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security issues via one of these methods:

1. **GitHub Security Advisory** (Preferred)
   - Go to: https://github.com/NexusOne23/noid-privacy/security/advisories
   - Click "Report a vulnerability"
   - Fill out the private security advisory form

2. **GitHub Discussions** (Private)
   - Create a new discussion in the Security category
   - Mark it as "Private" if possible
   - Provide full details

3. **Email** (Alternative)
   - Create a discussion requesting secure contact
   - We'll provide a secure communication channel

### 📋 What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What can an attacker achieve?
- **Affected Versions**: Which versions are affected?
- **Steps to Reproduce**: Detailed reproduction steps
- **Proof of Concept**: PoC code if applicable (optional)
- **Suggested Fix**: If you have one (optional)

### ⏱️ Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium: 30-60 days
  - Low: 60-90 days

### 🎖️ Recognition

We appreciate responsible disclosure! Contributors will be:
- Credited in the CHANGELOG (if desired)
- Listed in the Security Hall of Fame (coming soon)
- Eligible for swag/recognition (for significant findings)

---

## 🛡️ Security Features

NoID Privacy implements multiple security layers:

### Secure by Design
- ✅ **No External Dependencies**: Zero third-party DLLs or executables
- ✅ **Code Signing (Planned)**: Code signing for all PowerShell scripts is planned (coming soon)
- ✅ **Verification**: 630+ automated compliance checks
- ✅ **Rollback**: Complete backup & restore functionality

### Security Hardening Applied
- 🔐 Microsoft Security Baseline 25H2 (425 settings)
- 🛡️ Attack Surface Reduction (19 rules)
- 🔒 Credential Guard* + VBS + HVCI (*Enterprise/Education only)
- 🤖 AI Lockdown (Recall, Copilot, etc.)
- 🌐 DNS-over-HTTPS with no fallback
- 🚫 Zero-Day Protection (CVE-2025-9491 SRP)

---

## 📊 Supported Versions

| Version | Supported          | Notes |
| ------- | ------------------ | ----- |
| 2.2.x   | ✅ Fully Supported | Current release, 630+ settings |
| 2.1.x   | ⚠️ Limited Support  | Upgrade to 2.2.x recommended |
| 2.0.x   | ❌ Not Supported   | Deprecated |
| 1.8.x   | ❌ Not Supported   | Legacy version (MIT license) |

**Recommendation:** Always use the latest v2.x release.

---

## 🔐 Security Best Practices for Users

### Before Running
1. ✅ **Verify Script Integrity**
   ```powershell
   # Check file hash (coming soon - SHA256 checksums in releases)
   Get-FileHash .\NoIDPrivacy.ps1 -Algorithm SHA256
   ```

2. ✅ **Review Code**
   - This is open-source - read the code!
   - Understand what changes will be made
   - Check CHANGELOG for recent changes

3. ✅ **Create Backup**
   - System Restore Point
   - Full system image
   - VM snapshot (if applicable)

### During Execution
- ⚠️ Run as Administrator (required)
- ⚠️ Disable third-party antivirus temporarily (may interfere)
- ⚠️ Close sensitive applications
- ⚠️ Review verification report

### After Execution
- ✅ Run verification: `.\Tools\Verify-Complete-Hardening.ps1`
- ✅ Review HTML compliance report
- ✅ Test critical applications
- ✅ Keep backups for 30 days

---

## 🚨 Known Security Considerations

### Domain-Joined Systems
- ⚠️ Local Group Policies may conflict with Domain GPOs
- ⚠️ Domain GPOs override local policies every 90 minutes
- ✅ **Recommendation**: Use in standalone/workgroup systems only

### Third-Party Software Compatibility
- ⚠️ ASR rules may block unknown installers
- ⚠️ Some hardening settings may affect application functionality
- ✅ **Solution**: Temporarily disable specific ASR rules (see README)

### Rollback Limitations
- ⚠️ Bloatware removal is partially reversible (policy-based on 25H2+ Enterprise/Education)
- ⚠️ Some changes require manual reverification after restore
- ✅ **Solution**: Test in VM first, maintain system backups

---

## 📚 Security Resources

- **Microsoft Security Baseline**: https://aka.ms/securitybaselines
- **Attack Surface Reduction**: https://aka.ms/ASRrules
- **Windows Security Documentation**: https://learn.microsoft.com/windows/security/

---

## 🔍 Code Quality

### Testing & Validation
- **PSScriptAnalyzer**: Available for static analysis
- **Pester Tests**: Unit and integration tests available in `Tests/` directory
- **Verification**: 630+ automated compliance checks in production

Run tests yourself:
```powershell
.\Tests\Run-Tests.ps1
```

### Vulnerability Disclosures
*No security vulnerabilities reported to date.*

---

## 📄 License & Legal

- **License**: GNU General Public License v3.0
- **Disclaimer**: Use at your own risk. No warranties provided.
- **Compliance**: Implements Microsoft-recommended security settings

For licensing questions, see [LICENSE](LICENSE) or open a [Discussion](https://github.com/NexusOne23/noid-privacy/discussions).

---

**Last Updated**: December 8, 2025  
**Policy Version**: 1.1
