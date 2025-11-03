# 🧪 NoID Privacy - Test Suite

## Overview

This directory contains Pester tests for the NoID Privacy project. Tests are organized into Unit and Integration categories.

## Structure

```
Tests/
├── Unit/              # Unit tests for individual modules
│   ├── Core.Tests.ps1
│   ├── ASR.Tests.ps1
│   ├── Advanced.Tests.ps1
│   ├── Backup.Tests.ps1
│   ├── Telemetry.Tests.ps1
│   └── Restore.Tests.ps1
├── Integration/       # Integration tests for workflows
│   ├── ApplyVerify.Tests.ps1
│   └── BackupRestore.Tests.ps1
└── Helpers/           # Test helper functions
    └── TestHelpers.psm1
```

## Requirements

- **Pester 5.x** or higher
- **PowerShell 5.1** or higher
- **Windows 11** (for full integration tests)

## Installation

```powershell
# Install Pester (if not already installed)
Install-Module -Name Pester -MinimumVersion 5.0 -Force -SkipPublisherCheck
```

## Running Tests

### Run All Tests

```powershell
# From project root
Invoke-Pester -Path .\Tests\
```

### Run Unit Tests Only

```powershell
Invoke-Pester -Path .\Tests\Unit\
```

### Run Specific Test File

```powershell
Invoke-Pester -Path .\Tests\Unit\Core.Tests.ps1
```

### Run with Detailed Output

```powershell
$config = New-PesterConfiguration
$config.Run.Path = ".\Tests"
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
```

### Run with Code Coverage

```powershell
$config = New-PesterConfiguration
$config.Run.Path = ".\Tests"
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = ".\Modules\*.ps1"
Invoke-Pester -Configuration $config
```

## Test Categories

### Unit Tests

**Purpose:** Test individual modules in isolation
**Scope:** Function existence, parameters, syntax, error handling
**Requirements:** No admin rights needed (syntax validation only)

**Covered Modules:**
- ✅ Core (Defender, Firewall, Services)
- ✅ ASR (19 Attack Surface Reduction Rules)
- ✅ Advanced (VBS, Credential Guard, LAPS, Exploit Protection)
- ✅ Backup (Registry backup functionality)
- ✅ Telemetry (Privacy features, 110 keys, 37 services)
- ✅ Restore (Registry restore functionality)

### Integration Tests

**Purpose:** Test complete workflows
**Scope:** End-to-end scenarios
**Requirements:** Admin rights for full execution (structure tests work without)

**Covered Workflows:**
- ✅ Apply → Verify (Security baseline application and verification)
- ✅ Backup → Restore (State preservation and restoration)

## Test Coverage

**Current Status:**
- **Unit Tests:** 6 modules, ~150+ test cases
- **Integration Tests:** 2 workflows, ~30+ test cases
- **Estimated Coverage:** 60-70% of critical code paths

**Coverage Goals:**
- Target: 80%+ code coverage
- All critical modules tested
- All main workflows tested
- Error handling validated

## CI/CD Integration

Tests run automatically on GitHub Actions:
- ✅ Every commit to main
- ✅ Every pull request
- ✅ Manual workflow dispatch

**Workflow:** `.github/workflows/code-quality.yml`

## Writing New Tests

### Test Template

```powershell
#Requires -Version 5.1
#Requires -Modules Pester

BeforeAll {
    $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $modulePath = Join-Path $projectRoot "Modules\YourModule.ps1"
    . $modulePath
}

Describe "Module Name - Category" {
    Context "What you're testing" {
        It "Should do something specific" {
            # Arrange
            $expected = "value"
            
            # Act
            $actual = Get-Something
            
            # Assert
            $actual | Should -Be $expected
        }
    }
}
```

### Best Practices

1. **Use Descriptive Names**
   - Describe blocks: Module name + category
   - Context blocks: Feature being tested
   - It blocks: Specific behavior

2. **Follow AAA Pattern**
   - Arrange: Set up test data
   - Act: Execute the code
   - Assert: Verify the result

3. **Keep Tests Independent**
   - Each test should run in isolation
   - No dependencies between tests
   - Use BeforeEach/AfterEach for setup/cleanup

4. **Test One Thing**
   - Each It block tests one specific behavior
   - Use multiple It blocks for multiple behaviors

5. **Use Appropriate Matchers**
   - `Should -Be`: Exact equality
   - `Should -BeGreaterThan`: Numeric comparison
   - `Should -Match`: Regex matching
   - `Should -Contain`: Collection membership
   - `Should -Not -BeNullOrEmpty`: Null/empty check

## Troubleshooting

### Pester Version Issues

If tests fail with "Cannot find Pester":
```powershell
# Remove old version
Get-Module Pester -ListAvailable | Remove-Module -Force

# Install latest
Install-Module Pester -Force -SkipPublisherCheck
```

### Import Errors

If modules fail to load:
```powershell
# Check syntax first
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    ".\Modules\YourModule.ps1",
    [ref]$null,
    [ref]$errors
)
$errors
```

### Admin Rights

Some tests check for admin-only features but don't require admin to run.
For full integration testing, use a dedicated VM with admin rights.

## Contributing

When adding new features:
1. Write tests first (TDD approach)
2. Ensure all tests pass
3. Aim for >80% coverage of new code
4. Update this README if adding new test categories

## Notes

- **Unit Tests:** Run without admin, validate structure/syntax
- **Integration Tests:** Full execution requires admin + clean VM
- **CI/CD:** Tests run automatically, must pass before merge
- **User Impact:** None - tests are developer-only, not in release ZIP

---

**Last Updated:** 2025-11-01  
**Pester Version:** 5.x  
**Test Count:** 180+ individual tests  
**Coverage:** ~60-70% (Target: 80%+)
