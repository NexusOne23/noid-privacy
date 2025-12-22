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

- **OS**: Windows 11 [e.g., 25H2 Build 26200]
- **PowerShell Version**: [e.g., 5.1.26100.2161]
- **CPU**: [e.g., AMD Ryzen 7 9800X3D]
- **TPM**: [e.g., 2.0 Present]
- **Third-Party AV**: [e.g., None, Windows Defender only]
- **Script Version**: [e.g., v2.2.2]
- **Execution Mode**: [Interactive / Direct / DryRun]

**Get System Info:**
```powershell
# Run this to get system info
$PSVersionTable
Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber
Get-Tpm | Select-Object TpmPresent, TpmReady
```

## 📝 Log Files

Please attach or paste the relevant portion of the log file:

**Location**: `Logs\NoIDPrivacy_YYYYMMDD_HHMMSS.log`

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
- [ ] I have included the log file
- [ ] I have provided complete system information
- [ ] I have tested on a clean Windows 11 25H2 installation (if possible)

## 🔒 Security Note

If this is a **security vulnerability**, please **DO NOT** create a public issue!  
Instead, report it privately via: https://github.com/NexusOne23/noid-privacy/security/advisories
