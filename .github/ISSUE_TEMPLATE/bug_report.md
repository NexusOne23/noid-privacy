---
name: 🐛 Bug Report
about: Report a bug or unexpected behavior
title: '[BUG] '
labels: 'bug'
assignees: ''
---

## 🐛 Bug Description

A clear and concise description of what the bug is.

## 📋 Steps to Reproduce

1. Run command: `...`
2. Configure module: `...`
3. Execute script: `...`
4. See error

## ✅ Expected Behavior

A clear description of what you expected to happen.

## ❌ Actual Behavior

A clear description of what actually happened.

## 💻 System Information

- **OS**: Windows 11 [26H2, 25H2 or 24H2; include edition, DisplayVersion and full build/UBR]
- **PowerShell Version**: [64-bit Windows PowerShell 5.1; include the full version]
- **CPU**: [e.g., AMD Ryzen 7 9800X3D]
- **TPM**: [e.g., 2.0 Present]
- **Third-Party AV**: [e.g., None, Windows Defender only]
- **Script Version**: [e.g., v2.2.6]
- **Execution Mode**: [Interactive / Direct / DryRun]

**Get System Info:**
```powershell
# Run this to get system info
$PSVersionTable
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
    Select-Object EditionID, DisplayVersion, CurrentBuild, UBR
Get-Tpm | Select-Object TpmPresent, TpmReady
```

## 📝 Log Files

Please attach or paste only the relevant, reviewed and redacted portion of the log file. Remove computer/user names, SIDs, profile paths, adapter names/addresses, e-mail-like identifiers and any administrator-entered values that are not essential to reproduction.

**Location**: `Logs\NoIDPrivacy_YYYYMMDD_HHMMSS_fff_<nonce>.log`

```
[Paste relevant log excerpt here]
```

## 📸 Screenshots

If applicable, add screenshots to help explain your problem.

## 🔍 Additional Context

Add any other context about the problem here:
- Was this a fresh installation or re-run?
- Did the script work previously?
- Any recent system changes?
- Running in VM or physical machine?

## ✔️ Checklist

- [ ] I have searched for similar issues
- [ ] I have verified this is reproducible
- [ ] I have included a reviewed/redacted relevant log excerpt
- [ ] I have provided only the system information needed to reproduce the issue
- [ ] I have tested on a clean supported Windows 11 24H2/25H2/26H2 installation (if possible)

## 🔒 Security Note

If this is a **security vulnerability**, please **DO NOT** create a public issue!
Instead, report it privately via: https://github.com/NexusOne23/noid-privacy/security/advisories
