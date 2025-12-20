# 🛠️ Contributor Guide - Building New Modules

**How to build production-quality hardening modules for NoID Privacy**

This guide shows you how to create a new module using the **AdvancedSecurity** module as the reference implementation. Every principle, pattern, and structure you see here is based on real, production-tested code.

---

## 📋 Table of Contents

1. [Module Architecture](#module-architecture)
2. [File Structure](#file-structure)
3. [Core Integration Points](#core-integration-points)
4. [Implementation Checklist](#implementation-checklist)
5. [Best Practices](#best-practices)
6. [Testing & Verification](#testing--verification)

---

## 🏗️ Module Architecture

### Design Principles

All modules in NoID Privacy follow these principles:

1. **Separation of Concerns** - Public vs Private functions
2. **Backup Before Modify** - Always backup before changes
3. **Comprehensive Testing** - Test functions for compliance
4. **Structured Logging** - Use Write-Log for everything
5. **Error Handling** - Try/Catch everywhere
6. **PowerShell Best Practices** - Modern CIM, explicit returns, validated parameters

### Module Types

| Type | Example | Auto-Enabled | Use Case |
|------|---------|--------------|----------|
| **Core Hardening** | SecurityBaseline, ASR | ✅ Yes | Standard security settings, always safe |
| **Service-Based** | DNS, Privacy | ⚠️ Optional | User choice (provider, mode) |
| **Advanced/Aggressive** | AdvancedSecurity | ❌ Opt-in only | Breaking changes, requires testing |

---

## 📁 File Structure

### Required Structure

```
Modules/
└── YourModule/
    ├── YourModule.psd1              # Module Manifest (REQUIRED)
    ├── YourModule.psm1              # Module Loader (REQUIRED)
    ├── Config/                      # Configuration files
    │   ├── Feature1.json            # Feature-specific config
    │   └── Feature2.json
    ├── Private/                     # Internal functions (not exported)
    │   ├── Set-Feature1.ps1         # Implementation functions
    │   ├── Set-Feature2.ps1
    │   ├── Test-Feature1.ps1        # Compliance test functions
    │   ├── Test-Feature2.ps1
    │   ├── Backup-YourModuleSettings.ps1   # Comprehensive backup
    │   └── Restore-YourModuleSettings.ps1  # Comprehensive restore
    └── Public/                      # Exported functions (user-facing)
        ├── Invoke-YourModule.ps1    # Main entry point
        └── Test-YourModule.ps1      # Compliance test entry point
```

### Example: AdvancedSecurity Module Structure

```
Modules/AdvancedSecurity/
├── AdvancedSecurity.psd1            # Manifest with version 2.2.1
├── AdvancedSecurity.psm1            # Loads Private/*.ps1 and Public/*.ps1
├── Config/
│   ├── RDP.json                     # RDP hardening config
│   ├── Credentials.json             # WDigest config
│   └── AdminShares.json             # Admin shares config
├── Private/
│   ├── Enable-RdpNLA.ps1            # RDP hardening implementation
│   ├── Set-WDigestProtection.ps1    # WDigest implementation
│   ├── Disable-AdminShares.ps1      # Admin shares implementation
│   ├── Disable-RiskyPorts.ps1       # Firewall ports
│   ├── Stop-RiskyServices.ps1       # Services management
│   ├── Disable-WPAD.ps1             # WPAD disable
│   ├── Disable-LegacyTLS.ps1        # TLS 1.0/1.1 disable
│   ├── Remove-PowerShellV2.ps1      # PSv2 removal
│   ├── Test-RdpSecurity.ps1         # RDP compliance test
│   ├── Test-WDigest.ps1             # WDigest compliance test
│   ├── Test-AdminShares.ps1         # Admin shares test
│   ├── Test-RiskyPorts.ps1          # Ports compliance test
│   ├── Test-RiskyServices.ps1       # Services compliance test
│   ├── Backup-AdvancedSecuritySettings.ps1   # Full backup
│   └── Restore-AdvancedSecuritySettings.ps1  # Full restore
└── Public/
    ├── Invoke-AdvancedSecurity.ps1  # Main function with profiles
    └── Test-AdvancedSecurity.ps1    # Compliance aggregator
```

---

## 🔧 Core Integration Points

### 1. Module Manifest (.psd1)

**Template:**
```powershell
@{
    RootModule = 'YourModule.psm1'
    ModuleVersion = '2.2.1'
    GUID = 'YOUR-GUID-HERE'  # Generate with [guid]::NewGuid()
    Author = 'Your Name'
    CompanyName = 'NoID Privacy'
    Copyright = '(c) 2025. All rights reserved.'
    Description = 'Brief description of what your module does'
    
    PowerShellVersion = '5.1'
    
    FunctionsToExport = @(
        'Invoke-YourModule',
        'Test-YourModule'
    )
    
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Hardening', 'Windows11')
            ProjectUri = 'https://github.com/yourusername/noid-privacy'
            ReleaseNotes = @"
v2.2.1 - Initial Release
- Feature 1
- Feature 2
"@
        }
    }
}
```

**Real Example (AdvancedSecurity.psd1):**
```powershell
@{
    RootModule = 'AdvancedSecurity.psm1'
    ModuleVersion = '2.2.1'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'NexusOne23'
    Description = 'Advanced Security hardening beyond Microsoft Security Baseline'
    
    FunctionsToExport = @(
        'Invoke-AdvancedSecurity',
        'Test-AdvancedSecurity'
    )
    
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Hardening', 'RDP', 'TLS', 'Windows11')
            ReleaseNotes = @"
v2.2.1 - Production Release
- RDP NLA enforcement + optional complete disable
- WDigest credential protection
- Administrative shares disable (domain-aware)
- Risky firewall ports closure (LLMNR, NetBIOS, UPnP/SSDP)
- Risky network services stop
- Legacy TLS 1.0/1.1 disable
- WPAD auto-discovery disable
- PowerShell v2 removal
- Profile system (Balanced/Enterprise/Maximum)
- Comprehensive backup/restore
"@
        }
    }
}
```

---

### 2. Module Loader (.psm1)

**Template:**
```powershell
<#
.SYNOPSIS
    Module loader for YourModule
#>

# Get module root path
$ModuleRoot = $PSScriptRoot

# Import Private functions (not exported)
$PrivateFunctions = Get-ChildItem -Path "$ModuleRoot\Private\*.ps1" -ErrorAction SilentlyContinue

foreach ($function in $PrivateFunctions) {
    try {
        . $function.FullName
        Write-Verbose "Imported private function: $($function.BaseName)"
    }
    catch {
        Write-Error "Failed to import private function $($function.FullName): $_"
    }
}

# Import Public functions (will be exported)
$PublicFunctions = Get-ChildItem -Path "$ModuleRoot\Public\*.ps1" -ErrorAction SilentlyContinue

foreach ($function in $PublicFunctions) {
    try {
        . $function.FullName
        Write-Verbose "Imported public function: $($function.BaseName)"
    }
    catch {
        Write-Error "Failed to import public function $($function.FullName): $_"
    }
}

# Export only Public functions
$PublicFunctionNames = $PublicFunctions | ForEach-Object { $_.BaseName }
Export-ModuleMember -Function $PublicFunctionNames

Write-Verbose "YourModule loaded successfully. Exported functions: $($PublicFunctionNames -join ', ')"
```

---

### 3. Logging Integration

**Always use Write-Log from Core/Logger.ps1:**

```powershell
# Import at module level if not using framework
. "$PSScriptRoot\..\..\Core\Logger.ps1"

# In your functions
Write-Log -Level INFO -Message "Starting feature configuration..." -Module "YourModule"
Write-Log -Level SUCCESS -Message "Feature configured successfully" -Module "YourModule"
Write-Log -Level WARNING -Message "Non-critical issue detected" -Module "YourModule"
Write-Log -Level ERROR -Message "Failed to apply setting" -Module "YourModule" -Exception $_.Exception
Write-Log -Level DEBUG -Message "Registry key set: $regPath" -Module "YourModule"
```

**Log Levels:**
- `INFO` - General progress
- `SUCCESS` - Operation completed
- `WARNING` - Non-critical issues
- `ERROR` - Failures
- `DEBUG` - Detailed diagnostic info

---

### 4. Backup Integration

**Use Core/Rollback.ps1 functions:**

```powershell
# Backup registry key
Backup-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\..." -BackupName "YourFeature"

# Backup service
Backup-ServiceConfiguration -ServiceName "YourService"

# Register custom backup data
$backupData = @{
    YourData = $someValue
    BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
} | ConvertTo-Json

Register-Backup -Type "YourFeature_Settings" -Data $backupData -Name "YourFeatureName"
```

**Real Example (from AdvancedSecurity):**
```powershell
function Backup-AdvancedSecuritySettings {
    try {
        # Start backup session
        $backupSession = Start-ModuleBackup -ModuleName "AdvancedSecurity"
        
        $backupCount = 0
        
        # 1. RDP Settings
        $rdpBackup = Backup-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -BackupName "RDP_Settings"
        if ($rdpBackup) { $backupCount++ }
        
        # 2. Services
        $services = @("SSDPSRV", "upnphost", "lmhosts")
        foreach ($svc in $services) {
            $svcBackup = Backup-ServiceConfiguration -ServiceName $svc
            if ($svcBackup) { $backupCount++ }
        }
        
        # 3. Custom data (firewall rules snapshot)
        $firewallRules = Get-NetFirewallRule | Where-Object { ... }
        $firewallData = @{
            Rules = $firewallRules
            BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        } | ConvertTo-Json -Depth 10
        
        $firewallBackup = Register-Backup -Type "Firewall_Rules" -Data $firewallData -Name "RiskyPorts_Firewall"
        if ($firewallBackup) { $backupCount++ }
        
        return $backupCount
    }
    catch {
        Write-Log -Level ERROR -Message "Backup failed: $_" -Module "YourModule"
        return $false
    }
}
```

---

## ✅ Implementation Checklist

### Phase 1: Planning & Structure

- [ ] Define module name and purpose
- [ ] Choose module type (Core/Service/Advanced)
- [ ] Plan features and settings
- [ ] Create folder structure
- [ ] Generate GUID for manifest
- [ ] Write module manifest (.psd1)
- [ ] Write module loader (.psm1)

### Phase 2: Configuration

- [ ] Create Config/*.json files for each feature
- [ ] Document settings with rationale
- [ ] Include impact assessment
- [ ] Add Microsoft documentation links
- [ ] Define default values

### Phase 3: Implementation Functions (Private/)

For each feature:
- [ ] Create Set-FeatureName.ps1
  - [ ] Add comprehensive help block
  - [ ] Implement backup integration
  - [ ] Add registry/service/file modifications
  - [ ] Include error handling (try/catch)
  - [ ] Add logging at every step
  - [ ] Return $true on success, $false on failure
- [ ] Create Test-FeatureName.ps1
  - [ ] Check compliance
  - [ ] Return PSCustomObject with status
  - [ ] Include Details array for human-readable output

### Phase 4: Aggregation Functions (Private/)

- [ ] Create Backup-YourModuleSettings.ps1
  - [ ] Backup all features
  - [ ] Use Start-ModuleBackup for session tracking
  - [ ] Return backup count
- [ ] Create Restore-YourModuleSettings.ps1
  - [ ] Restore from backup directory
  - [ ] Handle missing backups gracefully
  - [ ] Log all restore operations

### Phase 5: Public Interface (Public/)

- [ ] Create Invoke-YourModule.ps1
  - [ ] Add [CmdletBinding(SupportsShouldProcess=$true)]
  - [ ] Define parameters (profiles, modes, switches)
  - [ ] Check for admin rights
  - [ ] Initialize backup system
  - [ ] Call Backup-YourModuleSettings (unless -SkipBackup)
  - [ ] Call all Set-Feature functions
  - [ ] Track applied/failed features
  - [ ] Return structured PSCustomObject
  - [ ] Provide user-friendly console output
- [ ] Create Test-YourModule.ps1
  - [ ] Call all Test-Feature functions
  - [ ] Aggregate results
  - [ ] Calculate compliance percentage
  - [ ] Return array of compliance objects

### Phase 6: Integration

- [ ] Update config.json with module entry
  - [ ] Set appropriate status (IMPLEMENTED/PLANNED)
  - [ ] Set enabled (true for auto, false for opt-in)
  - [ ] Add priority number
  - [ ] Include description
- [ ] Update README.md
  - [ ] Add module to appropriate table
  - [ ] Document features
  - [ ] Provide usage examples
  - [ ] Explain opt-in if applicable
- [ ] Update Verify-Complete-Hardening.ps1 (if auto-enabled)

### Phase 7: Testing

- [ ] Test on clean Windows 11 VM
- [ ] Verify backup creation
- [ ] Verify settings application
- [ ] Test compliance checks
- [ ] Verify restore functionality
- [ ] Test error scenarios
- [ ] Test -WhatIf mode
- [ ] Document any issues

---

## 📚 Best Practices

### 1. Use Modern PowerShell

**✅ DO:**
```powershell
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE"
```

**❌ DON'T:**
```powershell
$computerSystem = Get-WmiObject Win32_ComputerSystem  # Deprecated
```

---

### 2. Explicit Error Handling

**✅ DO:**
```powershell
try {
    Set-ItemProperty -Path $regPath -Name $valueName -Value $value -Type DWord -Force -ErrorAction Stop
    Write-Log -Level SUCCESS -Message "Registry value set successfully" -Module "YourModule"
    return $true
}
catch {
    Write-Log -Level ERROR -Message "Failed to set registry value: $_" -Module "YourModule" -Exception $_.Exception
    return $false
}
```

**❌ DON'T:**
```powershell
Set-ItemProperty -Path $regPath -Name $valueName -Value $value  # No error handling!
```

---

### 3. Structured Returns

**✅ DO (for action functions):**
```powershell
function Set-YourFeature {
    try {
        # ... implementation ...
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed: $_" -Module "YourModule"
        return $false
    }
}
```

**✅ DO (for test functions):**
```powershell
function Test-YourFeature {
    try {
        $result = [PSCustomObject]@{
            Feature = "Your Feature Name"
            Status = "Secure" # or "Insecure" or "Partially Secure"
            Details = @()
            Compliant = $true  # or $false
        }
        
        # ... check settings ...
        
        if ($settingCorrect) {
            $result.Details += "Setting is correct"
        } else {
            $result.Status = "Insecure"
            $result.Compliant = $false
            $result.Details += "Setting is incorrect!"
        }
        
        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Test failed: $_" -Module "YourModule"
        return [PSCustomObject]@{
            Feature = "Your Feature Name"
            Status = "Error"
            Details = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
```

**✅ DO (for main public function with scripting support):**
```powershell
function Invoke-YourModule {
    try {
        # ... apply all features ...
        
        # Return structured object
        return [PSCustomObject]@{
            Success = $true
            FeaturesApplied = $appliedFeatures
            FeaturesFailed = $failedFeatures
            TotalFeatures = $appliedFeatures.Count + $failedFeatures.Count
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            ErrorMessage = $_.Exception.Message
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
}
```

---

### 4. Validated Parameters

**✅ DO:**
```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Mode1', 'Mode2', 'Mode3')]
    [string]$Mode = 'Mode1',
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)
```

---

### 5. Comprehensive Help

**✅ DO:**
```powershell
function Set-YourFeature {
    <#
    .SYNOPSIS
        Brief one-line description
    
    .DESCRIPTION
        Detailed description of what the function does.
        
        Why this feature is important:
        - Security benefit 1
        - Security benefit 2
        
        Potential impact:
        - Impact consideration 1
        - Impact consideration 2
    
    .PARAMETER ParameterName
        Description of parameter
    
    .EXAMPLE
        Set-YourFeature
        Basic usage
    
    .EXAMPLE
        Set-YourFeature -Force
        Force mode example
    
    .NOTES
        Additional important information
        References: Microsoft KB article, CVE, etc.
    #>
    [CmdletBinding()]
    param(...)
    
    # Implementation
}
```

---

### 6. WhatIf Support for Destructive Operations

**✅ DO:**
```powershell
function Invoke-YourModule {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(...)
    
    if ($PSCmdlet.ShouldProcess("YourModule", "Apply hardening")) {
        # Apply changes
    }
    else {
        Write-Host "WhatIf mode - no changes applied" -ForegroundColor Yellow
        return $true
    }
}
```

**Usage:**
```powershell
Invoke-YourModule -WhatIf  # Dry run
```

---

## 🧪 Testing & Verification

### Pester Test Runner (Framework-Wide)

```powershell
# 1) Test-Umgebung vorbereiten (einmalig)
.\Tests\Setup-TestEnvironment.ps1

# 2) Alle Tests (Unit + Integration + Validation) ausführen
.\Tests\Run-Tests.ps1

# 3) Nur bestimmte Testtypen ausführen
.\Tests\Run-Tests.ps1 -TestType Unit
.\Tests\Run-Tests.ps1 -TestType Integration
.\Tests\Run-Tests.ps1 -TestType Validation

# 4) Mit Code Coverage
.\Tests\Run-Tests.ps1 -TestType All -CodeCoverage

# Alternative: Einfacher Runner für alle Tests
.\Tests\Run-AllTests.ps1
```

### Manual Testing Checklist

1. **Clean Windows 11 VM**
   ```powershell
   # Check Windows version
   winver  # Should be 24H2 or 25H2
   
   # Check PowerShell version
   $PSVersionTable.PSVersion  # Should be 5.1+
   ```

2. **Import Module**
   ```powershell
   Import-Module .\Modules\YourModule\YourModule.psd1 -Force -Verbose
   ```

3. **Test Compliance (Before)**
   ```powershell
   $before = Test-YourModule
   $before | Format-Table
   ```

4. **Apply Hardening**
   ```powershell
   $result = Invoke-YourModule
   $result
   ```

5. **Test Compliance (After)**
   ```powershell
   $after = Test-YourModule
   $after | Format-Table
   
   # Check improvement
   $beforeCompliant = ($before | Where-Object { $_.Compliant }).Count
   $afterCompliant = ($after | Where-Object { $_.Compliant }).Count
   Write-Host "Before: $beforeCompliant compliant"
   Write-Host "After: $afterCompliant compliant"
   ```

6. **Test Restore**
   ```powershell
   Restore-YourModuleSettings
   
   $restored = Test-YourModule
   $restored | Format-Table
   ```

7. **Test WhatIf**
   ```powershell
   Invoke-YourModule -WhatIf
   ```

### Automated Testing Template

```powershell
# Test-YourModule-Integration.ps1

Describe "YourModule Integration Tests" {
    BeforeAll {
        Import-Module ".\Modules\YourModule\YourModule.psd1" -Force
    }
    
    Context "Module Loading" {
        It "Should export public functions" {
            $commands = Get-Command -Module YourModule
            $commands.Count | Should -Be 2
            $commands.Name | Should -Contain 'Invoke-YourModule'
            $commands.Name | Should -Contain 'Test-YourModule'
        }
    }
    
    Context "Compliance Testing" {
        It "Should return compliance results" {
            $results = Test-YourModule
            $results | Should -Not -BeNullOrEmpty
            $results[0].PSObject.Properties.Name | Should -Contain 'Feature'
            $results[0].PSObject.Properties.Name | Should -Contain 'Status'
            $results[0].PSObject.Properties.Name | Should -Contain 'Compliant'
        }
    }
    
    Context "Application" {
        It "Should apply hardening successfully" {
            $result = Invoke-YourModule
            $result.Success | Should -Be $true
            $result.FeaturesApplied.Count | Should -BeGreaterThan 0
        }
    }
}
```

---

## 🎯 Real-World Example: AdvancedSecurity Module

The **AdvancedSecurity** module is the gold standard reference implementation. Study these files:

### Key Files to Study

1. **Manifest & Loader**
   - `AdvancedSecurity.psd1` - Version, exports, metadata
   - `AdvancedSecurity.psm1` - Function loading pattern

2. **Feature Implementation**
   - `Private/Enable-RdpNLA.ps1` - Registry modification with backup
   - `Private/Disable-AdminShares.ps1` - Domain-aware safety checks
   - `Private/Stop-RiskyServices.ps1` - Service management with dependencies

3. **Testing**
   - `Private/Test-RdpSecurity.ps1` - Compliance check pattern
   - `Public/Test-AdvancedSecurity.ps1` - Test aggregation

4. **Public Interface**
   - `Public/Invoke-AdvancedSecurity.ps1` - Profile system, backup, structured returns

5. **Backup/Restore**
   - `Private/Backup-AdvancedSecuritySettings.ps1` - Comprehensive backup
   - `Private/Restore-AdvancedSecuritySettings.ps1` - Full restore logic

---

## 📝 Summary

### Key Takeaways

1. **Structure Matters** - Follow the Private/Public separation
2. **Always Backup** - Before ANY modification
3. **Log Everything** - Use Write-Log consistently
4. **Error Handling** - Try/Catch everywhere
5. **Explicit Returns** - $true/$false for actions, PSCustomObject for tests
6. **Modern PowerShell** - CIM instead of WMI
7. **User-Friendly** - Clear console output + structured data for scripts
8. **Test Thoroughly** - Clean VM, before/after, restore

### Quick Start for New Module

```powershell
# 1. Create structure
mkdir "Modules\YourModule\Private"
mkdir "Modules\YourModule\Public"
mkdir "Modules\YourModule\Config"

# 2. Generate GUID
[guid]::NewGuid()

# 3. Create manifest (use template above)
# 4. Create loader (use template above)
# 5. Implement Private functions (Set-*, Test-*, Backup-*, Restore-*)
# 6. Implement Public functions (Invoke-*, Test-*)
# 7. Update config.json
# 8. Update README.md
# 9. Test on clean VM
```

---

**Questions? Study AdvancedSecurity v2.2.1 - it's the reference implementation!** 🎯
