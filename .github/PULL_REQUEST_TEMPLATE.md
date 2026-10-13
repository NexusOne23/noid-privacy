# Pull Request

## 📝 Description

Please include a summary of the changes and the related issue. Explain the motivation and context.

Fixes #(issue number)

## 🎯 Type of Change

Please delete options that are not relevant:

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📚 Documentation update
- [ ] 🔧 Code refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] ✅ Test coverage improvement

## 🧪 Testing

Please describe the tests you ran to verify your changes:

- [ ] Tested on Windows 11 24H2
- [ ] Tested on Windows 11 25H2
- [ ] Tested on an explicit Windows 11 26H2 client
- [ ] Tested in VM environment
- [ ] Tested on physical hardware
- [ ] Unit tests pass (`.\Tests\Run-Tests.ps1`)
- [ ] Integration tests pass
- [ ] Verification script passes (`.\Tools\Verify-Complete-Hardening.ps1`)

**Test Configuration:**
- **OS Version**: Windows 11 24H2 Build 26100 / 25H2 Build 26200 / 26H2 Build 26300
- **PowerShell Version**: 64-bit Windows PowerShell 5.1 [full version]
- **Test Environment**: VM / Physical

## 📋 Checklist

- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published
- [ ] I have updated the CHANGELOG.md
- [ ] I have read and agree to the [Code of Conduct](../CODE_OF_CONDUCT.md)

## 🔒 Security Considerations

- [ ] This change does not introduce security vulnerabilities
- [ ] This change has been reviewed for security implications
- [ ] Sensitive data is handled properly (if applicable)
- [ ] No hardcoded credentials or secrets

**Security Impact Details:**

## 📚 Documentation

- [ ] README.md updated (if needed)
- [ ] CHANGELOG.md updated
- [ ] Docs/ folder updated (if needed)
- [ ] Code comments added/updated

## 🔄 Backwards Compatibility

- [ ] This change is backwards compatible
- [ ] Existing sealed 2.2.5+ backup sessions still restore unchanged (no backup schema or restore-reader change, or the historical reader is kept)
- [ ] This change includes migration path for existing users
- [ ] Breaking changes are documented

**Compatibility Details:**

## 🎨 Screenshots (if applicable)

Add screenshots to help explain your changes (e.g., UI changes, verification report).

## 📝 Additional Notes

Add any additional notes for reviewers here.

---

## For Maintainers

**Review Checklist:**
- [ ] Code quality meets project standards
- [ ] Tests are comprehensive
- [ ] Documentation is complete
- [ ] Security implications reviewed
- [ ] Backwards compatibility considered
- [ ] CHANGELOG updated
- [ ] Ready to merge
