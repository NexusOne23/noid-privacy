# Contributing to NoID Privacy

First off, thank you for considering contributing to NoID Privacy! It's people like you that make this project a great tool for the Windows security community.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Pull Requests](#pull-requests)
- [Development Guidelines](#development-guidelines)
  - [PowerShell Style Guide](#powershell-style-guide)
  - [Testing](#testing)
  - [Documentation](#documentation)
- [Community](#community)

---

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

**Expected Behavior:**
- Be respectful and inclusive
- Welcome newcomers
- Focus on what is best for the community
- Show empathy towards other community members

**Unacceptable Behavior:**
- Harassment, discrimination, or trolling
- Publishing others' private information
- Other conduct which could reasonably be considered inappropriate

---

## How Can I Contribute?

### Reporting Bugs

**Before Submitting a Bug Report:**
1. Check the [existing issues](https://github.com/NexusOne23/noid-privacy/issues) to avoid duplicates
2. Verify the bug occurs on a clean Windows 11 25H2 installation
3. Check if the bug is already fixed in the latest version
4. Collect system information (OS version, PowerShell version, hardware specs)

**How to Submit a Bug Report:**

Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md) and include:

1. **Clear Title**: Short, descriptive summary
2. **Description**: Detailed explanation of the bug
3. **Steps to Reproduce**:
   ```
   1. Run script with command '...'
   2. Navigate to '...'
   3. See error
   ```
4. **Expected Behavior**: What should happen
5. **Actual Behavior**: What actually happens
6. **System Information**:
   - OS: Windows 11 25H2 Build XXXXX
   - PowerShell: 5.1.XXXXX
   - CPU: Intel i7-11700 / AMD Ryzen 5 5600X
   - TPM: 2.0 / Not Present
7. **Logs**: Attach transcript log from `C:\ProgramData\SecurityBaseline\Logs\`
8. **Screenshots**: If applicable

---

### Suggesting Enhancements

**Before Submitting an Enhancement:**
1. Check if the feature aligns with project goals (security, privacy, usability)
2. Search existing [feature requests](https://github.com/NexusOne23/noid-privacy/issues?q=is%3Aissue+label%3Aenhancement)
3. Consider if the enhancement would benefit the majority of users

**How to Submit an Enhancement:**

Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.md) and include:

1. **Clear Title**: Concise feature description
2. **Problem Statement**: What problem does this solve?
3. **Proposed Solution**: How should it work?
4. **Alternatives Considered**: What other approaches did you think about?
5. **Additional Context**: Examples, mockups, references
6. **Impact Assessment**:
   - Security impact
   - Privacy impact
   - Compatibility concerns
   - Breaking changes (if any)

---

### Pull Requests

**Before Creating a Pull Request:**
1. Discuss major changes in an issue first
2. Fork the repository
3. Create a feature branch (`git checkout -b feature/AmazingFeature`)
4. Test your changes thoroughly
5. Update documentation if needed

**Pull Request Guidelines:**

1. **Title Format**: `[Type] Short description`
   - `[Feature]` - New functionality
   - `[Fix]` - Bug fix
   - `[Docs]` - Documentation changes
   - `[Refactor]` - Code refactoring
   - `[Test]` - Test additions/changes

2. **Description**: Use the [Pull Request template](.github/PULL_REQUEST_TEMPLATE.md)
   - What does this PR do?
   - Why is this change needed?
   - How has this been tested?
   - Related issues (closes #123)

3. **Code Quality**:
   - Follow [PowerShell Style Guide](#powershell-style-guide)
   - Include error handling
   - Add verbose logging
   - Update CHANGELOG.md

4. **Testing**:
   - Test on clean Windows 11 25H2 VM
   - Verify no breaking changes
   - Check idempotence (can run multiple times)
   - Test with and without TPM 2.0

---

## Development Guidelines

### PowerShell Style Guide

#### General Principles
- **PowerShell Version**: Target PowerShell 5.1 (Windows built-in)
- **Encoding**: UTF-8 without BOM
- **Characters**: ASCII/Extended Latin only (0-255), no Unicode symbols
- **Line Length**: Max 120 characters (preferably 80-100)

#### Naming Conventions
```powershell
# Functions: Verb-Noun pattern (Approved Verbs only)
function Set-RegistryValue { }        # ✅ Good
function Configure-Registry { }       # ❌ Bad (Configure not approved verb)

# Variables: camelCase for local, PascalCase for script-scope
$localVariable = "value"              # ✅ Local
$script:GlobalVariable = "value"      # ✅ Script scope

# Parameters: PascalCase
param(
    [string]$FilePath,                # ✅ Good
    [switch]$Force                    # ✅ Good
)
```

#### Error Handling
```powershell
# Always use Try-Catch-Finally for critical operations
try {
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction Stop
    Write-Success "Registry value set successfully"
}
catch {
    Write-Error-Custom "Failed to set registry value: $_"
    Write-Verbose "Details: $($_.Exception.Message)"
    return $false
}
finally {
    # Cleanup resources (if needed)
}

# Use -ErrorAction for non-critical operations
Get-Service -Name ServiceName -ErrorAction SilentlyContinue
```

#### Logging
```powershell
# Use consistent logging functions
Write-Section "Module Name"          # Major sections
Write-Info "Informational message"   # Normal operations
Write-Success "Operation succeeded"  # Success confirmations
Write-Warning-Custom "Warning text"  # Warnings
Write-Error-Custom "Error text"      # Errors
Write-Verbose "Debug information"    # Verbose/debug
```

#### Documentation
```powershell
function Set-RegistryValue {
    <#
    .SYNOPSIS
        Sets a registry value with error handling
    
    .DESCRIPTION
        Creates or updates a registry value with automatic path creation
        and comprehensive error handling.
    
    .PARAMETER Path
        Registry path (e.g., "HKLM:\SOFTWARE\MyApp")
    
    .PARAMETER Name
        Value name
    
    .PARAMETER Value
        Value data
    
    .PARAMETER Type
        Value type (String, DWord, QWord, Binary, MultiString, ExpandString)
    
    .EXAMPLE
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Test" -Name "MyValue" -Value 1 -Type DWord
    
    .OUTPUTS
        [bool] $true if successful, $false otherwise
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        $Value,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('String', 'DWord', 'QWord', 'Binary', 'MultiString', 'ExpandString')]
        [string]$Type
    )
    
    # Implementation...
}
```

#### Best Practices
```powershell
# 1. Parameter Validation
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,
    
    [ValidateSet('Audit', 'Enforce')]
    [string]$Mode = 'Audit'
)

# 2. Null Checks
if (-not $variable) {
    Write-Error-Custom "Variable is null or empty"
    return
}

# 3. Safe Property Access
if ($object.PSObject.Properties['PropertyName']) {
    $value = $object.PropertyName
}

# 4. Idempotence
# Always check current state before modifying
$currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
if ($currentValue.$Name -ne $desiredValue) {
    Set-ItemProperty -Path $Path -Name $Name -Value $desiredValue
}

# 5. Cleanup in Finally
$resource = $null
try {
    $resource = Get-SomeResource
    # Use resource
}
finally {
    if ($null -ne $resource) {
        $resource.Dispose()
    }
}
```

---

### Testing

#### Test Checklist
- [ ] Runs without errors on clean Windows 11 25H2 VM
- [ ] Idempotent (can run multiple times without issues)
- [ ] No breaking changes to existing functionality
- [ ] Works with and without TPM 2.0
- [ ] Handles third-party antivirus gracefully
- [ ] Transcript log is clean (no false positive errors)
- [ ] Backup & Restore work correctly
- [ ] Changes are reversible (if applicable)

#### Test Environments
1. **Minimal VM**: Windows 11 25H2, 8 GB RAM, no TPM
2. **Full VM**: Windows 11 25H2, 16 GB RAM, TPM 2.0, virtualization enabled
3. **Physical Machine**: (Optional) Real hardware with all features

#### Test Scenarios
```powershell
# 1. Fresh Installation
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Audit

# 2. Idempotence (run 3x)
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Audit
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Audit
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Audit

# 3. Backup & Restore
.\Backup-SecurityBaseline.ps1
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce
.\Restore-SecurityBaseline.ps1

# 4. Verification
.\Verify-SecurityBaseline.ps1 -ExportReport

# 5. CTRL+C Handling
# Start script, wait 10 seconds, press CTRL+C
# Verify mutex is released and transcript is stopped
```

---

### Documentation

#### Update Documentation When:
- Adding new features
- Changing existing behavior
- Fixing bugs with user-facing impact
- Adding new modules or functions

#### Documentation Locations:
1. **README.md**: Overview, features, quick start
2. **CHANGELOG.md**: Version history, changes
3. **CONTRIBUTING.md**: This file
4. **Code Comments**: Inline explanations for complex logic
5. **Function Documentation**: PowerShell comment-based help
6. **Wiki**: Detailed guides, troubleshooting, FAQs

---

## Community

### Communication Channels
- **GitHub Issues**: Bug reports, feature requests, questions
- **Pull Requests**: Code contributions

### Getting Help
- Read the [README.md](README.md), [FAQ.md](FAQ.md), and [INSTALLATION.md](INSTALLATION.md)
- Search [existing issues](https://github.com/NexusOne23/noid-privacy/issues)
- Ask questions via GitHub Issues

### Recognition
Contributors will be:
- Listed on [GitHub Contributors Page](https://github.com/NexusOne23/noid-privacy/graphs/contributors)
- Mentioned in release notes
- Credited in relevant documentation

---

## Questions?

If you have questions about contributing, feel free to:
- Open a [GitHub Issue](https://github.com/NexusOne23/noid-privacy/issues) with the question tag
- Email us at [support@noid-privacy.com](mailto:support@noid-privacy.com) for general questions
- Review [existing contributions](https://github.com/NexusOne23/noid-privacy/pulls)
- Contact the maintainers

**Thank you for contributing to NoID Privacy!** 🎉
