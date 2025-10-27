# Pull Request

## 📋 Description

Brief description of what this PR does.

Closes #(issue number)

## 🔍 Type of Change

Please delete options that are not relevant:

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📝 Documentation update
- [ ] ♻️ Code refactoring (no functional changes)
- [ ] 🎨 Style/formatting changes
- [ ] ⚡ Performance improvement
- [ ] ✅ Test additions or changes
- [ ] 🔧 Configuration changes

## 🎯 Motivation and Context

Why is this change required? What problem does it solve?

## 🧪 How Has This Been Tested?

Please describe the tests you ran to verify your changes:

- [ ] Tested on clean Windows 11 25H2 VM
- [ ] Tested in Audit mode
- [ ] Tested in Enforce mode
- [ ] Tested idempotence (multiple runs)
- [ ] Tested with TPM 2.0
- [ ] Tested without TPM
- [ ] Tested with third-party AV
- [ ] Tested Backup & Restore
- [ ] Verified transcript log is clean
- [ ] Verified no breaking changes

### Test Environment
- **OS**: Windows 11 25H2 (Build XXXXX)
- **PowerShell**: Version X.X.XXXXX
- **Hardware**: [VM / Physical]
- **TPM**: [Present / Not Present]

## 📸 Screenshots (if applicable)

Add screenshots to demonstrate changes, especially for UI/UX modifications.

## ✅ Checklist

Please review and check all that apply:

### Code Quality
- [ ] My code follows the PowerShell style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have used UTF-8 without BOM encoding
- [ ] I have used ASCII/Extended Latin characters only (no Unicode symbols)
- [ ] My code uses approved PowerShell verbs (Get, Set, Enable, Disable, etc.)
- [ ] I have included proper error handling (Try-Catch-Finally)
- [ ] I have added verbose logging where appropriate

### Documentation
- [ ] I have updated the README.md (if needed)
- [ ] I have updated the CHANGELOG.md
- [ ] I have added/updated function documentation (comment-based help)
- [ ] I have updated PROJECT_STRUCTURE.md (if adding new files)

### Testing
- [ ] My changes work on Windows 11 25H2
- [ ] My changes are idempotent (can run multiple times)
- [ ] My changes don't break existing functionality
- [ ] I have tested with and without TPM 2.0 (if applicable)
- [ ] I have verified the transcript log is clean

### Security & Privacy
- [ ] My changes don't introduce security vulnerabilities
- [ ] My changes don't compromise user privacy
- [ ] My changes follow the principle of least privilege
- [ ] My changes are reversible (via Backup & Restore)

### Breaking Changes
- [ ] This PR introduces no breaking changes
- [ ] OR: I have documented all breaking changes in CHANGELOG.md
- [ ] OR: I have provided migration instructions

## 📝 Additional Notes

Any additional information, concerns, or notes for reviewers.

## 🔗 Related Issues

Link to related issues, discussions, or PRs:

- Related to #XXX
- Depends on #XXX
- Blocked by #XXX

---

**By submitting this pull request, I confirm that my contribution is made under the terms of the MIT License.**
