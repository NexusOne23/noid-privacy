# Registry Keys Reference

**Complete list of all 478 registry keys modified by NoID Privacy**

> Auto-generated reference for v1.8.1 - November 7, 2025

---

## Overview by Module

| Module | Keys | Purpose |
|--------|------|---------|
| **SecurityBaseline-Core.ps1** | 153 | Defender, Firewall, Services, Exploit Protection |
| **SecurityBaseline-Telemetry.ps1** | 118 | Privacy, Telemetry, Data Collection, Tracking |
| **SecurityBaseline-Advanced.ps1** | 90 | VBS, Credential Guard, LAPS, TLS/SSL, Auditing |
| **SecurityBaseline-Edge.ps1** | 20 | Microsoft Edge security baseline |
| **SecurityBaseline-AI.ps1** | 16 | Recall, Copilot, AI features blocking |
| **SecurityBaseline-UAC.ps1** | 15 | User Account Control maximum settings |
| **SecurityBaseline-Bloatware.ps1** | 14 | Consumer features, app installation blocking |
| **SecurityBaseline-AppPermissions.ps1** | 11 | App permission categories (37 categories default-deny) |
| **SecurityBaseline-WindowsUpdate.ps1** | 10 | Update configuration, delivery optimization |
| **SecurityBaseline-Performance.ps1** | 10 | Event logs, background tasks |
| **SecurityBaseline-OneDrive.ps1** | 8 | OneDrive privacy hardening |
| **SecurityBaseline-WirelessDisplay.ps1** | 7 | Miracast, wireless display disablement |
| **SecurityBaseline-DNS.ps1** | 4 | DNS-over-HTTPS global settings |
| **SecurityBaseline-ASR.ps1** | 2 | Attack Surface Reduction enablement |
| **Total** | **478** | |

---

## Security Categories

### Defender & Security (153 keys)
- Real-Time Protection
- Cloud Protection
- Sample Submission
- Behavior Monitoring
- Network Protection
- PUA Protection
- Archive Scanning
- Script Scanning
- Tamper Protection
- EDR in Block Mode
- ASR Rules (19 rules)
- Exploit Protection (13 mitigations)
- Firewall configuration
- SmartScreen settings

### Privacy & Telemetry (129 keys)
- Diagnostic data (Security level)
- Telemetry services
- Activity history
- Feedback & diagnostics
- Advertising ID
- Location services
- App permissions (37 categories)
- Cloud search
- Inking & typing
- Speech recognition
- Account notifications
- Background apps

### Advanced Security (90 keys)
- Credential Guard (VBS)
- LSA Protection (RunAsPPL)
- WDigest disablement
- TLS 1.2/1.3 enablement
- SSL 2.0/3.0/TLS 1.0/1.1 disablement
- Weak cipher disablement
- NTLM restrictions
- Kerberos hardening
- Advanced audit policies
- Windows LAPS configuration

### Microsoft Edge (20 keys)
- SmartScreen enforcement
- Tracking prevention
- DNS-over-HTTPS
- Site isolation
- Extension policies
- Password manager
- AutoFill configuration
- InPrivate mode

### AI Features (16 keys)
- Windows Recall disablement
- Windows Copilot (4 layers)
- Click to Do
- Paint Cocreator
- Paint Generative Fill
- Paint Image Creator
- Notepad AI
- Settings Agent
- Copilot Proactive

### Bloatware Control (14 keys)
- Consumer features
- App suggestions
- Lock screen tips
- Welcome experience
- Windows Spotlight
- Cloud content
- Pre-installed apps blocking

### User Account Control (15 keys)
- Admin approval mode
- Secure desktop
- Elevation prompts
- Admin detection
- Enhanced privilege protection

### Windows Update (10 keys)
- Automatic updates
- Feature updates
- Driver updates
- Preview builds blocking
- Delivery optimization
- P2P disablement

### Performance (10 keys)
- Event log sizing
- Application log
- System log
- Security log
- Background activities
- Maintenance windows

### Wireless Display (7 keys)
- Miracast disablement
- Wireless display
- Wi-Fi Direct
- Cast to device
- Network discovery

### OneDrive (8 keys)
- Tutorial disablement
- Feedback disablement
- Pre-login network blocking
- Known Folder Move blocking
- File collaboration
- Automatic sync

### DNS Security (4 keys)
- DNS-over-HTTPS enablement
- DNSSEC validation
- Global DoH policy

### ASR Configuration (2 keys)
- ASR rule enablement
- ASR mode configuration

---

## Module Details

### Core Module (153 keys)

**Purpose:** Microsoft Defender, Firewall, Services, Exploit Protection, System Hardening

**Key Highlights:**
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection` (11 keys)
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet` (4 keys)
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR` (19 keys)
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection` (2 keys)
- `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel` (13 exploit mitigations)
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers` (Software Restriction Policies)
- `HKLM:\SYSTEM\CurrentControlSet\Services` (25+ service configurations)
- `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` (Credential protection)
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths` (UNC hardening)
- Print Spooler hardening (RPC authentication)
- Remote access restrictions
- SMB hardening (signing, encryption)
- AutoPlay/AutoRun disablement
- Administrative shares disablement

---

### Telemetry Module (110 keys)

**Purpose:** Privacy Protection, Telemetry Minimization, App Permissions

**Key Highlights:**
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection` (8 keys)
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection` (3 keys)
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy` (37 app permission categories)
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo` (Advertising ID)
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\System` (Activity history, location)
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` (Cloud search, tips)
- `HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization` (Inking, typing, speech)
- `HKLM:\SOFTWARE\Microsoft\Siuf\Rules` (Feedback frequency)
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` (Suggestions)
- Camera/Microphone device-level blocking
- Location services disablement
- Diagnostics & feedback minimization

---

### Advanced Module (41 keys)

**Purpose:** Credential Protection, TLS/SSL Hardening, Advanced Auditing

**Key Highlights:**
- `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` (Credential Guard, LSA-PPL, WDigest)
- `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard` (VBS, HVCI)
- `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` (SMB signing)
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS` (Windows LAPS)
- TLS 1.2/1.3 enablement (6 protocol paths)
- SSL 2.0/3.0/TLS 1.0/1.1 disablement (8 protocol paths)
- Weak cipher disablement (7 cipher paths)
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit` (23 audit categories)
- NTLM auditing and restrictions
- Kerberos PKINIT hardening
- Network security hardening (LLMNR, NetBIOS, WPAD)

---

### Edge Module (25 keys)

**Purpose:** Microsoft Edge Security Baseline

**Key Highlights:**
- `HKLM:\SOFTWARE\Policies\Microsoft\Edge` (25 keys)
- SmartScreen enforcement
- Tracking Prevention (Strict)
- DNS-over-HTTPS automatic
- Site Isolation enablement
- Extension policies (Store-only)
- Password manager configuration
- AutoFill & payment methods
- InPrivate mode availability
- Certificate transparency
- Typo protection
- Download restrictions

---

### AI Module (15 keys)

**Purpose:** Windows AI Features Disablement

**Key Highlights:**
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` (Recall, Copilot)
- `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced` (Click to Do)
- Paint Cocreator disablement (3 keys)
- Notepad AI disablement
- Settings Agent disablement
- Copilot proactive suggestions disablement
- Copilot taskbar icon removal
- Copilot hotkey disablement
- AI Explorer disablement

---

### Bloatware Module (15 keys)

**Purpose:** Consumer Features & App Installation Blocking

**Key Highlights:**
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` (10 keys)
- Consumer features disablement
- App suggestions disablement
- Lock screen tips/tricks disablement
- Welcome experience disablement
- Windows Spotlight disablement
- Pre-installed apps blocking
- Microsoft account suggestions
- Third-party app suggestions
- Settings tips disablement

---

### UAC Module (10 keys)

**Purpose:** User Account Control Maximum Security

**Key Highlights:**
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` (10 keys)
- EnableLUA = 1 (UAC enabled)
- ConsentPromptBehaviorAdmin = 2 (Always notify)
- ConsentPromptBehaviorUser = 0 (Auto deny)
- PromptOnSecureDesktop = 1 (Secure desktop)
- EnableVirtualization = 1 (Virtualization enabled)
- FilterAdministratorToken = 1 (Admin approval mode)
- EnableInstallerDetection = 1 (Installer detection)
- ValidateAdminCodeSignatures = 0 (Compatibility)
- EnableSecureUIAPaths = 1 (Secure paths)
- Enhanced Privilege Protection Mode (future-ready)

---

### WindowsUpdate Module (9 keys)

**Purpose:** Secure Auto-Update Configuration

**Key Highlights:**
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` (9 keys)
- AllowMUUpdateService = 1 (MS products updates)
- BranchReadinessLevel = 32 (Get latest updates)
- DeferFeatureUpdates = 0 (No delays)
- ExcludeWUDriversInQualityUpdate = 0 (Include drivers)
- AllowAutoWindowsUpdateDownloadOverMeteredNetwork = 1 (Security > cost)
- Delivery Optimization = 1 (HTTP-only, no P2P)
- DisableWindowsUpdateAccess = 0 (User can check)
- DoNotConnectToWindowsUpdateInternetLocations = 0 (Allow updates)
- Preview builds blocking

---

### Performance Module (9 keys)

**Purpose:** Event Log Optimization, Background Activity Control

**Key Highlights:**
- `HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application` (MaxSize = 10 MB)
- `HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System` (MaxSize = 10 MB)
- `HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security` (MaxSize = 100 MB - kept large!)
- Noisy log reduction (NCSI, NetworkProfile, WindowsUpdateClient)
- Background app refresh control
- Maintenance window optimization
- Visual effects optimization

---

### WirelessDisplay Module (9 keys)

**Purpose:** Miracast & Wireless Display Disablement

**Key Highlights:**
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect` (3 keys)
- AllowProjectionToPC = 0
- RequirePinForPairing = 1
- `HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WirelessDisplay` (6 keys)
- AllowProjectionFromPC = 0
- AllowProjectionToPCOverInfrastructure = 0
- AllowUserInputFromWirelessDisplayReceiver = 0
- AllowMdnsAdvertisement = 0
- AllowMdnsDiscovery = 0

---

### OneDrive Module (8 keys)

**Purpose:** OneDrive Privacy Hardening (not removal)

**Key Highlights:**
- `HKLM:\SOFTWARE\Policies\Microsoft\OneDrive` (5 keys)
- DisableFileSyncNGSC = 0 (Sync enabled)
- DisableTutorial = 1 (No tracking dialogs)
- DisableFeedbackWizard = 1 (No diagnostics)
- PreventNetworkTrafficPreUserSignIn = 1 (No pre-login tracking)
- KFMBlockOptIn = 1 (No automatic folder move)
- `HKCU:\SOFTWARE\Microsoft\OneDrive` (3 keys)
- File collaboration settings
- Automatic upload blocking

---

### DNS Module (3 keys)

**Purpose:** DNS-over-HTTPS Global Configuration

**Key Highlights:**
- `HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters` (3 keys)
- EnableAutoDoh = 2 (Global enforcement)
- DohFlags = 1 (Strict mode)
- OpportunisticDnssec = 1 (DNSSEC validation)

---

### ASR Module (2 keys)

**Purpose:** Attack Surface Reduction Global Enablement

**Key Highlights:**
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR` (2 keys)
- ExploitGuard_ASR_Rules = 1 (ASR enabled)
- ASROnlyExclusions (empty by default)

---

### Common Module (1 key)

**Purpose:** Shared Configuration Flags

**Key Highlights:**
- `HKLM:\SOFTWARE\NoIDPrivacy\Config` (1 key)
- Version = 1.8.3 (Script version tracking)

---

## Registry Key Types

| Type | Count | Usage |
|------|-------|-------|
| **DWord** | 420 | Numeric values (0/1, flags, sizes) |
| **String** | 35 | Text values (paths, GUIDs, SDDLs) |
| **MultiString** | 15 | Array values (lists, multiple entries) |
| **ExpandString** | 5 | Expandable strings (environment variables) |
| **Binary** | 3 | Binary data (specialized configs) |

---

## Security Impact Categories

### Critical Security (200+ keys)
- Defender Real-Time Protection
- ASR Rules (19 exploit mitigations)
- Exploit Protection (13 system-wide)
- Credential Guard & VBS
- Firewall configuration
- TLS/SSL hardening
- Print Spooler hardening
- SMB security

### High Privacy (110+ keys)
- Telemetry minimization
- App permissions (37 categories)
- Activity history disablement
- Advertising ID removal
- Location services OFF
- AI features blocking (9 features)
- Cloud content disablement

### Medium Security (100+ keys)
- UAC maximum settings
- Windows Update configuration
- Edge security baseline
- OneDrive privacy hardening
- Bloatware blocking
- Wireless display disablement

### System Hardening (68+ keys)
- Advanced auditing (23 categories)
- Windows LAPS
- NTLM restrictions
- Network protocol hardening
- Service disablement
- Remote access lockdown

---

## Backup & Restore

**All 478 registry keys are fully backed up and restorable!**

- **Backup Script:** `Backup-SecurityBaseline.ps1`
- **Restore Script:** `Restore-SecurityBaseline.ps1`
- **Backup Location:** `C:\ProgramData\SecurityBaseline\Backups\`
- **Backup Format:** JSON (human-readable)
- **Integrity:** SHA256 hash verification
- **Reversibility:** 100% - Every change can be undone

---

## Verification

**All 478 registry keys are verified by Verify-SecurityBaseline.ps1**

- **133 verification checks** across all categories
- **Pass/Fail status** for each check
- **HTML compliance report** with dashboard
- **Actionable recommendations** for failed checks

---

## Documentation References

- **[Complete Feature List](FEATURES.md)** - All features explained
- **[Security Mapping](SECURITY_MAPPING.md)** - MS Baseline 25H2 compliance
- **[Changelog](CHANGELOG.md)** - Version history
- **[FAQ](FAQ.md)** - Common questions

---

**Last Updated:** November 7, 2025 (v1.8.1)  
**Source:** [NoID Privacy GitHub](https://github.com/NexusOne23/noid-privacy)
