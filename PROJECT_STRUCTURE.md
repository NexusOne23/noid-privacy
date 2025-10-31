# Project Structure

Complete overview of the NoID Privacy project structure and file organization.

---

## 📁 Directory Layout

```
noid-privacy/
│
├── 📄 Apply-Win11-25H2-SecurityBaseline.ps1  # Main application script
├── 📄 Backup-SecurityBaseline.ps1            # Backup system state
├── 📄 Restore-SecurityBaseline.ps1           # Restore from backup
├── 📄 Verify-SecurityBaseline.ps1            # Configuration verification
├── 📄 Start-NoID-Privacy.bat                 # Convenience launcher
│
├── 📂 Modules/                               # PowerShell modules (19 files)
│   ├── SecurityBaseline-Common.ps1
│   ├── SecurityBaseline-Localization.ps1
│   ├── SecurityBaseline-RegistryOwnership.ps1
│   ├── SecurityBaseline-RegistryBackup-Optimized.ps1  # NEW v2.0
│   ├── RegistryChanges-Definition.ps1                 # NEW v2.0
│   ├── SecurityBaseline-Core.ps1
│   ├── SecurityBaseline-Telemetry.ps1
│   ├── SecurityBaseline-ASR.ps1
│   ├── SecurityBaseline-Advanced.ps1
│   ├── SecurityBaseline-DNS.ps1
│   ├── SecurityBaseline-Bloatware.ps1
│   ├── SecurityBaseline-Performance.ps1
│   ├── SecurityBaseline-AI.ps1
│   ├── SecurityBaseline-Edge.ps1
│   ├── SecurityBaseline-OneDrive.ps1
│   ├── SecurityBaseline-UAC.ps1
│   ├── SecurityBaseline-WindowsUpdate.ps1
│   ├── SecurityBaseline-WirelessDisplay.ps1
│   └── SecurityBaseline-Interactive.ps1
│
├── 📄 hosts                                  # DNS blocklist (79,776 domains, compressed)
│
├── 📄 README.md                              # Project overview & documentation
├── 📄 LICENSE                                # MIT License
├── 📄 CHANGELOG.md                           # Version history
├── 📄 CONTRIBUTING.md                        # Contribution guidelines
├── 📄 SECURITY.md                            # Security policy
├── 📄 CODE_OF_CONDUCT.md                     # Community guidelines
├── 📄 INSTALLATION.md                        # Installation guide
├── 📄 PROJECT_STRUCTURE.md                   # This file
└── 📄 .gitignore                             # Git ignore rules
```

---

## 📄 Main Scripts

### Apply-Win11-25H2-SecurityBaseline.ps1
**Purpose**: Main application script - orchestrates all hardening operations

**Features**:
- Interactive mode with language selection
- Audit mode (safe testing)
- Enforce mode (full hardening)
- Module dependency management
- Backup integration
- Comprehensive logging
- Error handling & cleanup
- Reboot management

**Usage**:
```powershell
# Interactive
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Interactive

# Audit mode
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Audit

# Enforce mode
.\Apply-Win11-25H2-SecurityBaseline.ps1 -Mode Enforce
```

**Lines of Code**: ~1,563  
**Dependencies**: All 17 modules

---

### Backup-SecurityBaseline.ps1
**Purpose**: Create JSON backup of current system state

**Backs Up**:
- Registry keys (475+ keys)
- Services status (50+ services)
- Scheduled tasks (300+ tasks)
- Firewall rules (500+ rules)
- Windows Features state
- Defender settings
- App list (before removal)
- Network settings

**Usage**:
```powershell
.\Backup-SecurityBaseline.ps1

# Custom path
.\Backup-SecurityBaseline.ps1 -BackupPath "C:\MyBackups"
```

**Lines of Code**: ~1,066 (was ~1,543, -477 lines in v2.0)  
**Output**: JSON file (~50-150 KB, was 2-5 MB)

---

### Restore-SecurityBaseline.ps1
**Purpose**: Restore system from backup

**Restores**:
- Registry values
- Service startup types & states
- Scheduled task states
- Firewall rules (removes custom, restores original)
- Windows Features
- Network settings

**Usage**:
```powershell
# Auto-select latest backup
.\Restore-SecurityBaseline.ps1

# Specific backup
.\Restore-SecurityBaseline.ps1 -BackupFile "C:\Backups\MyBackup.json"
```

**Lines of Code**: ~1,482 (was ~1,710, -228 lines in v2.0)  
**Safety**: Validates backup before restore

---

### Verify-SecurityBaseline.ps1
**Purpose**: Quick configuration check

**Verifies**:
- Windows 11 25H2 build
- TPM 2.0 presence
- Secure Boot status
- Defender status
- ASR rules count
- Firewall profiles
- UAC level
- DNS-over-HTTPS
- VBS/Credential Guard (post-reboot)
- BitLocker status (post-reboot)

**Usage**:
```powershell
# Terminal output
.\Verify-SecurityBaseline.ps1

# CSV export
.\Verify-SecurityBaseline.ps1 -ExportReport
```

**Lines of Code**: ~307  
**Runtime**: ~30 seconds

---

### Start-NoID-Privacy.bat
**Purpose**: User-friendly launcher (no PowerShell knowledge needed)

**Features**:
- Auto-elevates to Administrator
- Opens PowerShell with correct script
- Handles execution policy
- User-friendly error messages

**Usage**: Double-click in Windows Explorer

**Lines of Code**: ~40

---

## 📂 Modules Directory

### Core Modules (Always Loaded)

#### SecurityBaseline-Common.ps1
**Purpose**: Shared utility functions

**Exports**:
- `Write-Section` - Formatted section headers
- `Write-Info` - Informational messages
- `Write-Success` - Success confirmations
- `Write-Warning-Custom` - Warnings
- `Write-Error-Custom` - Error messages
- `Set-RegistryValue` - Safe registry write
- `Stop-ServiceSafe` - Safe service stop

**Lines of Code**: ~323  
**Dependencies**: None

---

#### SecurityBaseline-Localization.ps1
**Purpose**: Multi-language support

**Exports**:
- `Get-LocalizedString` - Retrieve translated string
- `Select-Language` - User language selection

**Supported Languages**:
- German (de-DE)
- English (en-US)

**Lines of Code**: ~834  
**Dependencies**: None

---

#### SecurityBaseline-RegistryOwnership.ps1
**Purpose**: TrustedInstaller registry handling

**Exports**:
- `Enable-Privilege` - Enable SeRestorePrivilege/SeTakeOwnershipPrivilege
- `Set-RegistryValueWithOwnership` - Change ownership & set value
- `Set-RegistryValueSmart` - Auto-fallback to ownership method

**Lines of Code**: ~595  
**Dependencies**: None

**Critical For**: WTDS (Windows Telemetry Data Sharing) registry keys

---

### Registry Backup System (v2.0 - Optimized)

**NEW in v2.0**: Complete rewrite of registry backup system for massive performance improvement.

**Previous System (v1.8.0 - Snapshot-Based)**:
- Backed up entire registry trees (7 areas)
- 50,000+ keys compared
- 5-15 minutes backup time
- 10-30 minutes restore time
- 3-8 MB backup files

**New System (v2.0 - Specific Keys)**:
- Backs up only 375 keys that Apply actually modifies
- 30 seconds backup time (**20-30x faster**)
- 1-2 minutes restore time (**10-15x faster**)
- 50-150 KB backup files (**50x smaller**)
- 99.25% reduction in data volume

---

#### RegistryChanges-Definition.ps1
**Purpose**: Data-only module containing all 375 registry changes

**Structure**:
```powershell
$script:RegistryChanges = @(
    @{
        Path = 'HKLM:\SOFTWARE\Policies\...'
        Name = 'ValueName'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'What this key does'
        File = 'SecurityBaseline-AI.ps1'
    },
    # ... 374 more entries
)
```

**Contains**:
- 374 registry keys with full metadata
- Path, Name, Type, ApplyValue, Description, Source File
- Organized by source module
- Auto-generated from registry-changes-complete.txt

**Lines of Code**: ~3,012  
**Size**: 103 KB  
**Dependencies**: None (data only)

**Used By**:
- Backup-SecurityBaseline.ps1 (loads at startup)
- Backup-SpecificRegistryKeys function

**Source**: `registry-changes-complete.txt` (human-readable, 127 KB)

---

#### SecurityBaseline-RegistryBackup-Optimized.ps1
**Purpose**: Fast backup/restore functions for specific registry keys

**Exports** (3 functions):
- `Backup-SpecificRegistryKeys` - Iterates 375 keys, reads current values
- `Restore-SpecificRegistryKeys` - Compares current vs backup, restores changes
- `Validate-RegistryRestore` - Post-restore verification

**Features**:
- PSObject.Properties check (no error records)
- TrustedInstaller handling (optional)
- Graceful handling of protected keys
- Detailed statistics (restored/deleted/unchanged/failed)

**Lines of Code**: ~319  
**Dependencies**: RegistryOwnership (optional for protected keys)

**Performance**:
```
Backup:  30 seconds for 375 keys
Restore: 1-2 minutes with validation
Success Rate: 99%+ (1-2 protected keys may fail)
```

**Used By**:
- Backup-SecurityBaseline.ps1 Line 583: `Backup-SpecificRegistryKeys`
- Restore-SecurityBaseline.ps1 Line 767: `Restore-SpecificRegistryKeys`

---

### Feature Modules

#### SecurityBaseline-Core.ps1
**Purpose**: Core security baseline (largest module)

**Exports** (26 functions):
- `Test-SystemRequirements` - Windows version & TPM checks
- `Set-DefenderBaselineSettings` - Defender hardening
- `Enable-ControlledFolderAccess` - Ransomware protection
- `Enable-ExploitProtection` - System-wide mitigations
- `Set-SMBHardening` - SMB signing/encryption
- `Set-TLSHardening` - TLS 1.2/1.3 only
- `Set-KerberosPKINITHashAgility` - SHA-2 only Kerberos
- `Set-BitLockerPolicies` - BitLocker configuration
- `Set-NetBIOSDisabled` - NetBIOS over TCP/IP disable
- `Disable-LegacyProtocols` - mDNS, LLMNR, WPAD
- `Enable-NetworkStealthMode` - Discovery disable
- `Disable-UnnecessaryServices` - 25+ services
- `Disable-RemoteAccessCompletely` - RDP, WinRM, RA
- `Disable-AdministrativeShares` - C$, ADMIN$, IPC$
- `Set-SecureAdministratorAccount` - Rename + disable + secure password
- `Disable-AnonymousSIDEnumeration` - Prevent SID enumeration
- `Set-MarkOfTheWeb` - MOTW enforcement
- `Set-PrintSpoolerUserRights` - PrintNightmare mitigation
- `Enable-CloudflareDNSoverHTTPS` - DoH 1.1.1.2
- `Set-FirewallPolicies` - Strict inbound blocking
- And more...

**Lines of Code**: ~2,813  
**Dependencies**: Common, Localization, RegistryOwnership, WindowsUpdate

---

#### SecurityBaseline-Telemetry.ps1
**Purpose**: Privacy protection

**Exports** (12 functions):
- `Disable-TelemetryServices` - 10+ telemetry services
- `Set-TelemetryRegistry` - 17+ registry keys
- `Remove-TelemetryTasks` - 11+ scheduled tasks
- `Disable-WindowsSearchWebFeatures` - No Bing integration
- `Disable-CameraAndMicrophone` - Default-deny
- `Disable-AllAppPermissionsDefaults` - 37 permission categories
- `Set-LocationServicesDefault` - Location OFF
- `Disable-PrivacyExperienceSettings` - OOBE privacy
- `Disable-InkingAndTypingPersonalization` - Handwriting data
- `Disable-XboxGameBarAndMode` - Gaming telemetry
- `Disable-BackgroundActivities` - Background apps
- `Get-TelemetryStatus` - Current status report

**Lines of Code**: ~1,525  
**Dependencies**: Common, Core

---

#### SecurityBaseline-ASR.ps1
**Purpose**: Attack Surface Reduction

**Exports** (4 functions):
- `Set-AttackSurfaceReductionRules` - 19 ASR rules
- `Get-ASRRuleStatus` - Current ASR configuration
- `Enable-ControlledFolderAccess` - Ransomware folders
- `Enable-SmartAppControl` - App reputation

**Lines of Code**: ~431  
**Dependencies**: Common, Core

---

#### SecurityBaseline-Advanced.ps1
**Purpose**: Advanced security features

**Exports** (5 functions):
- `Enable-VirtualizationBasedSecurity` - VBS + HVCI
- `Enable-CredentialGuard` - LSA-PPL protection
- `Enable-WindowsLAPS` - Password rotation
- `Enable-AdvancedAuditing` - 18+ audit categories
- `Enable-NTLMAuditing` - NTLM usage logging

**Lines of Code**: ~520  
**Dependencies**: Common, Core

---

#### SecurityBaseline-DNS.ps1
**Purpose**: DNS security

**Exports** (3 functions):
- `Enable-DNSSEC` - Opportunistic mode
- `Install-DNSBlocklist` - 79,776-domain hosts file (compressed to 8,864 lines)
- `Set-StrictInboundFirewall` - Discovery blocking

**Lines of Code**: ~306  
**Dependencies**: Common, Core, WindowsUpdate

---

#### SecurityBaseline-Bloatware.ps1
**Purpose**: App removal

**Exports** (3 functions):
- `Remove-BloatwareApps` - 50+ app patterns
- `Disable-ConsumerFeatures` - Suggested apps
- `Remove-SpecificApps` - Targeted removal

**Lines of Code**: ~371  
**Dependencies**: Common, Telemetry

---

#### SecurityBaseline-Performance.ps1
**Purpose**: Performance optimization

**Exports** (6 functions):
- `Optimize-ScheduledTasks` - Disable 40+ tasks
- `Optimize-EventLogs` - Reduce log sizes
- `Disable-BackgroundActivities` - Background apps
- `Optimize-SystemMaintenance` - Idle-only maintenance
- `Disable-VisualEffects` - Minimal effects
- `Show-PerformanceReport` - Status report

**Lines of Code**: ~648  
**Dependencies**: Common, Telemetry

---

#### SecurityBaseline-AI.ps1
**Purpose**: AI feature blocking

**Exports** (8 functions):
- `Disable-WindowsRecall` - 4-layer blocking
- `Disable-WindowsCopilot` - Complete removal
- `Disable-ClickToDo` - Context menu AI
- `Disable-PaintAIFeatures` - Paint AI tools
- `Disable-SettingsAgent` - Settings AI
- `Disable-CopilotProactive` - Proactive suggestions
- `Set-RecallMaximumStorage` - Storage minimum
- `Disable-SudoForWindows` - Sudo command

**Lines of Code**: ~236  
**Dependencies**: Common, Telemetry

---

#### SecurityBaseline-Edge.ps1
**Purpose**: Microsoft Edge hardening

**Exports** (1 function):
- `Set-EdgeSecurityBaseline` - 42 security settings

**Settings**:
- SmartScreen for sites & downloads
- Tracking prevention (Strict)
- DNS-over-HTTPS
- Enhanced security mode
- Site isolation
- TLS 1.2+ only
- WebRTC IP leak prevention
- AutoFill disabled by default
- Password manager off by default

**Lines of Code**: ~203  
**Dependencies**: Common, Core

---

#### SecurityBaseline-OneDrive.ps1
**Purpose**: OneDrive privacy

**Exports** (1 function):
- `Set-OneDrivePrivacyHardening` - Tutorial, feedback, folder move blocking

**Lines of Code**: ~97  
**Dependencies**: Common, Telemetry

---

#### SecurityBaseline-UAC.ps1
**Purpose**: UAC enhancement

**Exports** (2 functions):
- `Set-MaximumUAC` - Slider to top (always prompt)
- `Enable-EnhancedPrivilegeProtectionMode` - EPP mode

**Lines of Code**: ~107  
**Dependencies**: Common

---

#### SecurityBaseline-WindowsUpdate.ps1
**Purpose**: Update configuration

**Exports** (2 functions):
- `Set-WindowsUpdateDefaults` - 7 update settings
- `Set-DeliveryOptimizationDefaults` - HTTP-only, no P2P

**Lines of Code**: ~125  
**Dependencies**: Common

---

#### SecurityBaseline-WirelessDisplay.ps1
**Purpose**: Miracast disablement

**Exports** (1 function):
- `Disable-WirelessDisplay` - Services, registry, firewall, apps

**Lines of Code**: ~191  
**Dependencies**: Common

---

#### SecurityBaseline-Interactive.ps1
**Purpose**: Menu system

**Exports** (12 functions):
- `Show-Banner` - ASCII art banner
- `Show-MainMenu` - Main menu display
- `Get-UserChoice` - Arrow key navigation
- `Start-InteractiveMode` - Menu orchestrator
- `Invoke-AuditMode` - Audit execution
- `Invoke-EnforceMode` - Enforce execution
- `Invoke-CustomMode` - Module selection
- `Invoke-RestoreMode` - Restore trigger
- `Invoke-VerifyMode` - Verify trigger
- `Invoke-RebootPrompt` - Reboot dialog
- `Show-ModeSelectionDialog` - Language selector

**Lines of Code**: ~1,296  
**Dependencies**: All other modules

---

## 📄 Additional Files

### hosts
**Purpose**: DNS blocklist for malware/tracking/ads

**Domains**: 79,776 unique domains (Steven Black Unified, 8,864 lines × 9)  
**Lines**: 8,864 (compressed format - 9 domains per line)  
**Size**: ~1.6 MB  
**Format**: Windows-optimized hosts file (0.0.0.0 domain.com)  
**Optimization**: Compressed for Windows DNS Cache performance

**Categories**:
- Malware domains
- Tracking/analytics
- Ad networks
- Coin miners
- Phishing sites

**Source**: Community-maintained blocklist  
**Location**: Copied to `C:\Windows\System32\drivers\etc\hosts`

---

### registry-changes-complete.txt
**Purpose**: Human-readable documentation of all 375 registry changes

**Format**: Text file with detailed breakdown by module  
**Size**: 127 KB  
**Lines**: 2,669

**Contains**:
- All 375 registry operations
- Organized by source file (14 modules)
- Shows: Path, Name, Value, Type, Description
- Line numbers from source files
- Operation counts per module

**Usage**:
- **Source for code generation** (RegistryChanges-Definition.ps1)
- **Documentation** - what each key does
- **Code review** - verify all changes
- **NOT read at runtime** - only for reference

**Example Entry**:
```
[1] Zeile 27: Set-RegistryValue
    Registry-Pfad: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
    Name:          DisableAIDataAnalysis
    Wert:          1
    Typ:           DWord
    Beschreibung:  Windows Recall deaktivieren (KEINE Screenshots!)
```

**Generated**: 2025-10-31 05:49:48  
**Last Updated**: Same as module changes

---

## 📚 Documentation Files

| File | Purpose | Size |
|------|---------|------|
| README.md | Project overview, quick start | ~15 KB |
| CHANGELOG.md | Version history | ~12 KB |
| LICENSE | MIT License | ~1 KB |
| CONTRIBUTING.md | Contribution guidelines | ~18 KB |
| SECURITY.md | Security policy | ~8 KB |
| CODE_OF_CONDUCT.md | Community guidelines | ~5 KB |
| INSTALLATION.md | Installation guide | ~15 KB |
| PROJECT_STRUCTURE.md | This file | ~12 KB |
| .gitignore | Git ignore rules | ~1 KB |

---

## 📊 Statistics

### Code Metrics
```
Total Lines of Code:    ~18,500 (was ~15,200)
PowerShell Scripts:     21 files
Modules:                19 files (was 17)
Functions:              105 defined (was 102)
Dependencies:           Managed via $moduleDependencies hashtable
Error Handling:         210+ Try-Catch blocks
Registry Operations:    375 specific keys (was 190+ unique paths)
Documentation:          ~90 KB
```

### Module Breakdown
```
RegistryChanges-Def:    3,012 LOC  (16.3%)  [NEW v2.0 - Data only]
Core Module:            2,813 LOC  (15.2%)
Main Script:            1,563 LOC  (8.4%)
Telemetry Module:       1,525 LOC  (8.2%)
Restore Script:         1,482 LOC  (8.0%)  [v2.0: -228 LOC]
Interactive Module:     1,296 LOC  (7.0%)
Backup Script:          1,066 LOC  (5.8%)  [v2.0: -477 LOC]
Localization Module:    834 LOC    (4.5%)
Performance Module:     648 LOC    (3.5%)
RegistryOwnership:      595 LOC    (3.2%)
Advanced Module:        520 LOC    (2.8%)
ASR Module:             431 LOC    (2.3%)
Bloatware Module:       371 LOC    (2.0%)
Common Module:          323 LOC    (1.7%)
RegistryBackup-Opt:     319 LOC    (1.7%)  [NEW v2.0 - Functions]
DNS Module:             306 LOC    (1.7%)
Verify Script:          307 LOC    (1.7%)
AI Module:              236 LOC    (1.3%)
Edge Module:            203 LOC    (1.1%)
WirelessDisplay:        191 LOC    (1.0%)
WindowsUpdate:          125 LOC    (0.7%)
UAC Module:             107 LOC    (0.6%)
OneDrive Module:        97 LOC     (0.5%)
Batch Launcher:         40 LOC     (0.2%)
```

---

## 🔄 Module Dependencies

```
flowchart TB
    Common[Common]
    Local[Localization]
    RegOwn[RegistryOwnership]
    WinUpd[WindowsUpdate]
    Core[Core]
    Telem[Telemetry]
    ASR[ASR]
    Adv[Advanced]
    DNS[DNS]
    Bloat[Bloatware]
    Perf[Performance]
    AI[AI]
    Edge[Edge]
    OneDrive[OneDrive]
    UAC[UAC]
    Wireless[WirelessDisplay]
    Interactive[Interactive]
    
    Core --> Common
    Core --> Local
    Core --> RegOwn
    Core --> WinUpd
    
    Telem --> Common
    Telem --> Core
    
    ASR --> Common
    ASR --> Core
    
    Adv --> Common
    Adv --> Core
    
    DNS --> Common
    DNS --> Core
    DNS --> WinUpd
    
    Bloat --> Common
    Bloat --> Telem
    
    Perf --> Common
    Perf --> Telem
    
    AI --> Common
    AI --> Telem
    
    Edge --> Common
    Edge --> Core
    
    OneDrive --> Common
    OneDrive --> Telem
    
    UAC --> Common
    
    Wireless --> Common
    
    Interactive --> Common
    Interactive --> Local
    Interactive --> Core
    Interactive --> Telem
    Interactive --> ASR
    Interactive --> Adv
    Interactive --> DNS
    Interactive --> Bloat
    Interactive --> Perf
    Interactive --> AI
    Interactive --> Edge
    Interactive --> OneDrive
    Interactive --> UAC
    Interactive --> Wireless
```

---

## 🚀 Execution Flow

```
1. Apply-Win11-25H2-SecurityBaseline.ps1 starts
2. Initialize script-scope variables
3. Register CTRL+C handler
4. Acquire mutex (prevent concurrent execution)
5. Start transcript logging
6. Load Common module (base functions)
7. Load Localization module (language support)
8. Load RegistryOwnership module (TrustedInstaller)
9. Check system requirements
10. Language selection (if Interactive mode)
11. Load remaining modules (based on dependencies)
12. Validate all module functions loaded
13. Execute selected hardening operations
14. Generate verification report (optional)
15. Prompt for reboot (if needed)
16. Stop transcript
17. Release mutex
18. Exit gracefully
```

---

## 📁 Runtime Directories

Created during execution:

```
C:\ProgramData\SecurityBaseline\
├── Logs\                              # Transcript logs
│   └── SecurityBaseline-Enforce-YYYYMMDD-HHMMSS.log
├── Backups\                           # JSON backups
│   └── SecurityBaseline-Backup-YYYYMMDD-HHMMSS.json
└── Verification\                      # Verification reports
    └── Verification-YYYYMMDD-HHMMSS.csv
```

---

**Last Updated**: October 31, 2025  
**Version**: 2.0 (Registry Backup System Overhaul)
