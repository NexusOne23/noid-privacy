# Security Policy

## 🚨 Quick Reference

**Found a vulnerability?** Email: [security@noid-privacy.com](mailto:security@noid-privacy.com)  
**Response Time:** Within 48 hours  
**Need help?** See [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues)

**Critical Security Note:** This tool requires Administrator privileges. Always:
- ✅ Review code before running
- ✅ Test in VM first
- ✅ Create system backup
- ✅ Download from official repository only

---

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 1.7.x   | :white_check_mark: | Current stable release |
| 1.6.x   | :white_check_mark: | Maintenance mode (critical fixes only) |
| < 1.6   | :x:                | No longer supported |

## Reporting a Vulnerability

We take the security of NoID Privacy seriously. If you discover a security vulnerability, please follow these steps:

### 🔒 Private Disclosure

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security issues via:

1. **Email**: [security@noid-privacy.com](mailto:security@noid-privacy.com)
2. **Subject Line**: "SECURITY: [Brief Description]"
3. **Include**:
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)
   - Your contact information for follow-up

### ⏱️ Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: 
  - Critical: 7-14 days
  - High: 14-30 days
  - Medium: 30-60 days
  - Low: 60-90 days

### 🎯 Severity Classification

We classify security vulnerabilities using the following criteria:

**Critical Severity** 🔴
- Remote code execution without authentication
- Privilege escalation to SYSTEM level
- Complete system compromise
- Mass data exfiltration
- **Examples**: Arbitrary code execution, unrestricted file write with SYSTEM privileges

**High Severity** 🟠
- Privilege escalation requiring user interaction
- Local code execution vulnerabilities
- Authentication bypass
- Sensitive data disclosure (credentials, personal data)
- **Examples**: Registry key manipulation allowing persistent backdoor, credential theft from backup files

**Medium Severity** 🟡
- Denial of service vulnerabilities
- Information disclosure (non-sensitive)
- Logic errors affecting security features
- Path traversal vulnerabilities
- **Examples**: Script crashes preventing security hardening, exposure of non-sensitive system information

**Low Severity** 🟢
- Minor information leaks
- Issues requiring unlikely conditions
- Cosmetic security issues
- **Examples**: Verbose error messages, timing attacks on non-critical operations

### 🏆 Recognition

We appreciate security researchers who follow responsible disclosure:
- Your name (if desired) will be credited in the security advisory
- You'll be listed in our [SECURITY_HALL_OF_FAME.md](SECURITY_HALL_OF_FAME.md)
- We'll link to your website/GitHub profile (with permission)

### 🚫 What We Consider Security Vulnerabilities

**In Scope:**
- Privilege escalation vulnerabilities
- Code execution vulnerabilities
- Authentication/authorization bypasses
- Information disclosure (sensitive data)
- Cryptographic weaknesses
- Denial of service (if exploitable)

**Out of Scope:**
- Social engineering attacks
- Physical attacks
- Issues requiring physical access to victim's device
- Issues already documented as known limitations
- Third-party dependencies (report to upstream)

### ⚡ PowerShell-Specific Security Considerations

As a PowerShell-based tool, we pay special attention to:

**Command Injection Vulnerabilities**
- All user inputs are validated before use
- No dynamic script generation from user input
- Registry paths are sanitized
- File paths use absolute paths only

**Path Traversal Protection**
- All file operations use validated absolute paths
- No user-controlled path components
- Backup files use fixed directory structure

**Privilege Escalation Prevention**
- Script requires explicit Administrator elevation
- No privilege escalation within script execution
- Mutex prevents concurrent execution
- No credential storage or handling

**Data Integrity**
- JSON backups use structured serialization
- Registry operations validated before write
- Atomic operations where possible
- Transaction-like backup before changes

**Known PowerShell Attack Vectors (Mitigated)**
- ✅ Script injection via parameters: Not accepting user script input
- ✅ Credential theft: No credential handling in code
- ✅ Process injection: No inter-process manipulation
- ✅ Fileless malware: All changes logged and reversible

### 📋 Security Best Practices

When using NoID Privacy:

1. **Always Backup**: Create system backup before applying
2. **Test First**: Run in VM before production
3. **Review Code**: Understand what the script does
4. **Verify Integrity**: Check file hashes before running
5. **Keep Updated**: Use latest version for security fixes
6. **Admin Rights**: Only run with Administrator privileges when necessary
7. **Trusted Sources**: Only download from official repository

### 🔐 Security Features

This project implements multiple security layers:

| Feature | Purpose | Status |
|---------|---------|--------|
| **Script Signing** | Verify script authenticity | 🔄 Pending (SignPath application submitted) |
| **Mutex Lock** | Prevent concurrent execution | ✅ Implemented |
| **Error Handling** | Safe failure modes | ✅ Implemented |
| **Backup System** | Rollback capability | ✅ Implemented |
| **Verbose Logging** | Audit trail | ✅ Implemented |
| **Privilege Checks** | Admin rights validation | ✅ Implemented |
| **BitLocker Warning** | Prevent false sense of security | ✅ Implemented (v1.7.13) |
| **VBS Verification** | Verify Credential Guard activation | ✅ Implemented (v1.7.13) |
| **Hardware Checks** | TPM/CPU/Virtualization validation | ✅ Implemented |

### 📖 Security Documentation

- [Microsoft Security Baseline 25H2](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/windows-11-version-25h2-security-baseline/4456231)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [DoD STIG](https://public.cyber.mil/stigs/)
- [BSI IT-Grundschutz](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/it-grundschutz_node.html)

### 🛡️ Security Audits

We welcome security audits from the community. If you'd like to perform a security audit:

1. Contact us beforehand
2. Focus on code review and functionality testing
3. Share findings privately first
4. Allow reasonable time for fixes before public disclosure

### ⚠️ Known Security Limitations

**Current Limitations:**
1. **Standalone Focus**: Not designed for domain environments
2. **Third-Party AV**: May conflict with some antivirus products
3. **Hardware Requirements**: Some features require TPM 2.0, modern CPU, enabled virtualization
4. **Reversibility**: Some changes (Recall, Copilot, app removal) are permanent
5. **Manual Steps**: Certain features require post-script configuration

**Critical Security Considerations (Added v1.7.13):**

6. **BitLocker Not Auto-Enabled**: 
   - Script configures BitLocker policies but does NOT automatically enable encryption
   - Users must manually enable BitLocker via Control Panel or PowerShell
   - **Risk**: False sense of security if user assumes policies = encryption
   - **Mitigation**: Critical warning displayed when BitLocker inactive

7. **VBS/Credential Guard Silent Failures**:
   - Features can fail silently if hardware requirements not met
   - No automatic post-reboot verification
   - **Risk**: User thinks Credential Guard is running when it's not
   - **Mitigation**: Post-reboot verification instructions provided

8. **No Automatic Code Signing** (yet):
   - Scripts are not digitally signed (SignPath application pending)
   - Users must trust based on GitHub repository verification
   - **Mitigation**: Download only from official repository, verify commit signatures

**Documented Issues:**
- See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for current limitations
- See [CHANGELOG.md](CHANGELOG.md) for fixed vulnerabilities

### 🔄 Security Update Process

When a security issue is confirmed:

1. **Acknowledgment**: Issue reporter receives confirmation
2. **Investigation**: Team investigates and validates
3. **Fix Development**: Patch is developed and tested
4. **Security Advisory**: CVE is requested (if applicable)
5. **Release**: Patch is released with security notes
6. **Notification**: Users are notified via GitHub Security Advisory
7. **Public Disclosure**: After fix is available (coordinated disclosure)

### 📞 Contact

For security concerns:
- **Email**: [security@noid-privacy.com](mailto:security@noid-privacy.com)
- **PGP Key**: Not yet available (planned for future)
- **Encrypted Contact**: For highly sensitive reports, request secure channel via initial email

For general issues:
- **GitHub Issues**: [Report here](https://github.com/NexusOne23/noid-privacy/issues)
- **General Support**: [support@noid-privacy.com](mailto:support@noid-privacy.com)

### 💰 Bug Bounty Program

We currently do **not** offer a paid bug bounty program. However:
- We deeply appreciate responsible disclosure
- Contributors will be publicly credited (with permission)
- We respond promptly and take all reports seriously
- Consider this a learning opportunity and community contribution

---

**Last Updated**: October 30, 2025  
**Version**: 2.0 (Comprehensive Security Policy Update)

**Changelog:**
- Added comprehensive severity classification system
- Added PowerShell-specific security considerations
- Updated security features with v1.7.13 improvements
- Documented BitLocker and VBS/Credential Guard limitations
- Clarified PGP key status and bug bounty program
- Added detailed attack vector mitigations

---

## Security Hall of Fame

We thank the following security researchers for responsible disclosure:

<!-- This section will be updated as vulnerabilities are reported and fixed -->

*No security vulnerabilities have been publicly disclosed at this time.*

---

**Thank you for helping keep NoID Privacy secure!** 🙏
