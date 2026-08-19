# NoID Privacy - Feature List

**Framework Version:** v2.2.5
**Default-Decision Declared Checks:** 645 (mode and explicit choices can change the declared scope)
**Modules:** 7
**Last Updated:** 2026-08-13

Current include/exclude decisions are backed by the [Windows 11 security and privacy primary-source review (2026)](SECURITY-PRIVACY-PRIMARY-SOURCE-REVIEW-2026.md); documented controls are added only when their applicability, UX and recovery boundary fit the product.

---

## 📊 Module Overview

| Module | Settings | Status | Description |
|--------|----------|--------|-------------|
| **SecurityBaseline** | 425 | v2.2.5 | One Windows 11 v25H2-derived Microsoft Security Baseline profile for supported 24H2/25H2 clients |
| **ASR** | 19 | v2.2.5 | Attack Surface Reduction rules (Defender-specific API) |
| **DNS** | 5 | v2.2.5 | Secure DNS with DoH encryption |
| **Privacy** | 63 | v2.2.5 | 32 MSRecommended targets + 4 OneDrive/Store targets with Cloud Clipboard disable selected (Strict: 61 including services; Paranoid: 90 including services/tasks) + 27 Tier 1 policy-based bloatware-removal targets (ENT/EDU 24H2+, NotApplicable elsewhere). Strict/Paranoid additionally disable periodic Windows settings/app-list cloud backup and cellular text-message cloud sync. Six base targets are explicitly labelled interactive-user preferences with exact registry BAVR, not managed-policy effectiveness claims. MSRecommended/Strict preserve useful local device-search history while disabling their selected web/Bing surfaces; Paranoid additionally disables local history, online font providers and automatic device-metadata companion-app downloads. Apply and exact Restore notify the live Search surface through Windows' documented policy and registry-leaf setting-change messages rather than killing Explorer/SearchHost. Tier 2 best-effort removal (26 base apps including Microsoft Copilot + optional Weather/Widgets package) is separate and not counted. |
| **AntiAI** | 47 | v2.2.5 | 43 registry targets + 4 URI source checks across 12 groups |
| **EdgeHardening** | 26 | v2.2.5 | 19 Microsoft Edge v139 baseline values + 7 explicit privacy additions |
| **AdvancedSecurity** | 60 | v2.2.5 | 17 deterministic firewall targets + 43 non-firewall checks; unsupported Home-edition policy/host targets are NotApplicable |
| **TOTAL** | **645** | v2.2.5 | All 7 modules with default decisions. Explicit extension/firewall/ASR/Privacy choices are reported separately, never as passed. |

---

## 🔒 Module 1: SecurityBaseline (425 Settings)

**Description:** One 425-target profile derived from Microsoft's Windows 11 v25H2 Security Baseline and admitted on supported 24H2/25H2 clients, with documented UAC/BitLocker/sample-submission/standalone application choices and an explicit upstream-provenance and 24H2-delta boundary. See [SecurityBaseline provenance and deviations](SECURITY-BASELINE-PROVENANCE.md).

### Components:

#### Registry Policies (335 settings)
- Computer Configuration policies (330 settings)
- User Configuration policies (5 settings)
- Windows Defender Antivirus baseline
- Windows Firewall configuration
- BitLocker drive encryption settings
- Internet Explorer 11 security zones

#### Security Template (67 settings)
- **Password Policy:** MinimumPasswordLength (14), PasswordHistorySize (24), etc.
- **Account Lockout:** LockoutBadCount (10), LockoutDuration (10 minutes)
- **User Rights Assignment:** Administrative permissions and privileges
- **Security Options:** Network access, authentication, object access
- **Service Configuration:** Xbox services disabled for security

#### Audit Policies (23 subcategories)
- Logon/Logoff events
- Account Management
- Policy Change tracking
- Privilege Use monitoring
- System events
- Object Access auditing

### Key Features:
- ✅ VBS (Virtualization Based Security)
- ✅ Credential Guard (Enterprise/Education only)
- ✅ System Guard Secure Launch
- ✅ Kernel CET Shadow Stacks (Win11 25H2)
- ✅ Memory Integrity (HVCI)
- ✅ Interactive BitLocker removable-drive write policy (Home/Enterprise choice; no automatic encryption claim)
- ✅ Standard-user UAC choice: strict deny (`0`) or administrator credentials on the secure desktop (`1`)

### Home User Adjustments:
- **BitLocker USB:** Default = 0 (Home Mode - USB works normally)
- **Standard-user elevation:** Default = Strict (`ConsentPromptBehaviorUser=0`). `SecureDesktop=1` is the explicit system-wide convenience choice that lets standard users enter separate administrator credentials on the secure desktop. This policy governs standard users only and does not alter an administrator account's own elevation prompts.
- **Password Policies:** Affect local Windows account policy; Microsoft-account cloud password policy is separate

---

## 🛡️ Module 2: ASR (19 Settings)

**Description:** Nineteen declared Microsoft Defender ASR identities. Microsoft's current [operating-system support matrix](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#operating-system-support-for-asr-rules) marks `Block Webshell creation for Servers` as Exchange-server-only and `n/a` for Windows 11, so the module applies 18 rules and reports that one as `NotApplicable`.

### What ASR Rules Block (and Why It's Important):

#### Email & Download Attacks
1. **Block executable content from email** - Stops malware from .exe/.dll/.ps1 email attachments
2. **Block JavaScript/VBScript from launching downloads** - Prevents drive-by downloads from malicious websites
3. **Block execution of potentially obfuscated scripts** - Blocks matching script characteristics when Defender enforces the rule
4. **Block untrusted/unsigned processes from USB** - Blocks untrusted executable content from USB/removable drives; it is not a general BadUSB/HID defense

#### Office Exploits
5. **Block Office from creating child processes** - Stops Word/Excel macros from spawning cmd.exe/powershell.exe
6. **Block Office from creating executable content** - Prevents Office from writing .exe files to disk
7. **Block Office from injecting code into other processes** - Stops process injection attacks
8. **Block Win32 API calls from Office macros** - Prevents macros from calling dangerous Windows APIs
9. **Block Adobe Reader from creating child processes** - Same protection for PDF exploits
10. **Block Office communication apps (Outlook) child processes** - Stops email-based exploit chains

#### Credential Theft & Persistence
11. **Block credential stealing from LSASS** - Denies matching LSASS-memory access; Microsoft notes it adds no protection when LSA protection is already active
12. **Block persistence through WMI** - Blocks the documented WMI event-subscription behavior
13. **Block process creation from PSExec/WMI** - Blocks matching process creation (configurable: Block or Audit; can conflict with Configuration Manager)

#### Ransomware Protection
14. **Use advanced ransomware protection** - Uses Defender client/cloud heuristics and requires cloud protection
15. **Block executable files unless they meet reputation criteria** - Uses Microsoft cloud protection's prevalence, age and trusted-list assessment; it is not documented as a SmartScreen setting

#### Advanced Threats
16. **Block abuse of exploited vulnerable signed drivers** - Blocks applications from writing known vulnerable signed drivers; it does not block a vulnerable driver already present from loading
17. **Block webshell creation for Servers** - Exchange-server-only; declared but `NotApplicable` on Windows 11 clients
18. **Block rebooting in Safe Mode** - Blocks commonly abused commands that request a Safe Mode restart; manual Windows Recovery Environment access remains
19. **Block use of copied/impersonated system tools** - Blocks executables Defender identifies as copies or impostors of Windows system tools

### Interactive Prompt:
- **PSExec/WMI Rule (d1e49aac):** Choose **Block** or **Audit**
  - Block: Maximum security (may break SCCM/remote admin tools)
  - Audit: Logs events only (good for enterprise compatibility testing)

---

## 🌐 Module 3: DNS (5 Settings)

**Description:** Secure DNS with DNS-over-HTTPS encryption

### Providers (3 available):

#### Quad9 (Default - Threat Blocking)
- **IPv4:** 9.9.9.9, 149.112.112.112
- **IPv6:** 2620:fe::fe, 2620:fe::9
- **DoH:** https://dns.quad9.net/dns-query
- **Documented behavior:** Threat-domain blocking; under normal service conditions its policy says it does not retain information that identifies an individual user
- **Best for:** Users who want malicious-domain blocking

#### Cloudflare (Unfiltered)
- **IPv4:** 1.1.1.1, 1.0.0.1
- **IPv6:** 2606:4700:4700::1111, 2606:4700:4700::1001
- **DoH:** https://cloudflare-dns.com/dns-query
- **Documented behavior:** Unfiltered endpoints; limited resolver logs and truncated source IPs deleted within 25 hours
- **Best for:** Users who want an unfiltered public resolver with published privacy commitments

#### AdGuard (Ad-Blocking)
- **IPv4:** 94.140.14.14, 94.140.15.15
- **IPv6:** 2a10:50c0::ad1:ff, 2a10:50c0::ad2:ff
- **DoH:** https://dns.adguard-dns.com/dns-query
- **Documented behavior:** Ad/tracker/malicious-domain filtering; the public-service policy describes aggregated metrics and an anonymous requested-domain set retained for 24 hours
- **Best for:** Ad/tracker blocking at DNS level

Provider claims were rechecked on 2026-07-10 against the providers' primary documentation: [Quad9 service/privacy](https://docs.quad9.net/), [Cloudflare public-resolver privacy](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/), [AdGuard DNS service](https://adguard-dns.io/en/welcome.html), and [AdGuard DNS privacy](https://adguard-dns.io/en/privacy.html).

### Features:
- ✅ **Windows DNS Client DoH configuration with 2 interactive modes:**
  - **[1] REQUIRE Mode (Default):** NO unencrypted fallback (AllowFallbackToUdp = $False)
    - Best for: Home networks, single-location systems
    - Windows DNS Client resolution through the managed endpoints fails rather than falling back to classic DNS; apps/VPNs with their own resolver stack remain outside this policy
  - **[2] ALLOW Mode:** Fallback to UDP allowed (AllowFallbackToUdp = $True)
    - Best for: VPN users, mobile devices, corporate networks, captive portals
    - Balanced security - falls back to unencrypted if DoH unavailable
  - **[0] Skip:** Keep current DNS settings unchanged
- ✅ Native per-adapter DoH state through Microsoft's supported DNS interface API, so the managed IPv4/IPv6 endpoints are also shown as encrypted in Windows Settings
- ✅ The same REQUIRE/ALLOW decision controls native adapter fallback; there is no extra technical prompt
- ✅ Exact schema-v5 backup, Apply readback, verifier/HTML evidence and Restore for effective resolver order plus the separately scoped native/UI-visible per-adapter DoH state; unknown native property types fail closed before mutation
- ✅ If the optional AdvancedSecurity control has disabled IPv6 transport with `DisabledComponents=0xFF`, the native IPv6 endpoints can still be shown as encrypted in Windows Settings, but NoID Privacy explicitly reports that as persisted configuration rather than active IPv6 traffic
- ℹ️ An already-open Windows Settings network page can cache the old label; close and reopen that page to display the newly applied native state. No Windows restart is required for the DNS Apply itself.
- ✅ DNSSEC validation (server-side by all providers)
- ✅ DHCP-aware backup/restore
- ✅ Physical adapter auto-detection (excludes virtual/VPN adapters)
- ✅ Connectivity validation before apply

---

## 🔇 Module 4: Privacy (63 default-decision declared targets: 36 base + 27 Tier 1 policy values)

**Description:** Windows telemetry control, OneDrive/MS Store policy hardening, and two-tier bloatware removal with exact target-level BAVR

### What's Actually Done:
- ✅ **Windows Telemetry:** 3 modes (MSRecommended/Strict/Paranoid)
- ✅ **OneDrive Telemetry:** Feedback & sync reports disabled
- ✅ **OneDrive/Store preservation:** NoID Privacy does not write the allow-valued `DisablePersonalSync=0` or `RemoveWindowsStore=0`; stricter existing policy is preserved
- ✅ **Store OS-upgrade offer:** the documented `DisableOSUpgrade=1` policy is applied; ordinary Windows Update is outside that Store policy
- ✅ **Tier 1 policy prestate:** Microsoft's native `RemoveDefaultMicrosoftStorePackages` policy (Enterprise/Education, Windows 11 24H2/build 26100+) removes a curated set of in-box apps; its owned policy values are backed up and restored exactly
- ⚠️ **Tier 1 downstream boundary:** Microsoft documents that deselecting/restoring the policy does not reinstall an already-removed app; reprovisioning is separate and deleted local app data is not recovered
- ✅ **Tier 2 bloatware removal (best-effort, all editions):** classic per-user `Remove-AppxPackage` on a curated list, honestly labeled as NOT an exact restore -- see [AppX packages](#appx-packages-two-tier-honest-restore-boundary) below
- ✅ **User scope:** HKCU targets are bound to and verified for the single interactive Explorer owner; offline profiles are not modified or advertised as verified
- ✅ **Decision-bound BAVR:** registry Apply intent and installed service/task applicability are sealed with the exact prestate and rechecked before mutation
- ✅ **Edition-aware:** Windows managed-policy targets are NotApplicable on Home; Microsoft-documented Enterprise-only Spotlight/CloudContent controls are NotApplicable on Pro; Tier 1 targets are NotApplicable outside Enterprise/Education 24H2+

### Operating Modes (Interactive Selection):

#### MSRecommended (Default - Least Disruptive Non-Relaxing Profile)
- AllowTelemetry = 1 (Required)
- Services NOT disabled (policies only)
- AppPrivacy and Settings Sync policy: preserved, not overwritten
- **Best for:** Compatibility-focused standalone workstations

#### Strict (Selected Strict Controls)
- AllowTelemetry = 0 (Off - Enterprise/Edu only, Pro falls back)
- Services: DiagTrack + dmwappushservice disabled
- AppPrivacy: Force Deny Location/App-Diagnose/Generative AI only
- Mic/Camera policy: preserved; NoID Privacy does not loosen or tighten it in Strict mode
- **Best for:** Privacy-focused home users, small business

#### Paranoid (Broadest Policy Set - NOT Recommended for general workstations)
- Everything from Strict + WerSvc disabled
- Tasks: CEIP/AppExperience/DiskDiag disabled
- AppPrivacy: Force Deny the broad declared capability set (Mic/Camera/Contacts/Calendar and others)
- **WARNING:** denied microphone/camera and related capabilities are unavailable to affected conferencing and communications apps
- **Best for:** Air-gapped, kiosk, extreme privacy only

### ⚠️ Windows Insider Program Compatibility

**MSRecommended mode** sets `AllowTelemetry=1` via Group Policy, which blocks the optional diagnostic-data level required for Windows Insider Preview builds. Microsoft states that optional diagnostic data must remain enabled to run Insider Preview builds: [official Insider data-setting requirement](https://learn.microsoft.com/en-us/windows-insider/data-settings).

**Workaround:** Temporarily remove the `AllowTelemetry` policy before Insider enrollment:
```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
```

Do not re-apply a Privacy mode that forces `AllowTelemetry=1` while the device is meant to keep running Insider Preview builds. Re-applying it turns the required optional diagnostic-data level off again. Leave the policy absent/at the optional level for the duration of Insider participation, or leave the Insider program before re-applying that Privacy policy.

**See:** [Troubleshooting - Windows Insider Program Compatibility](TROUBLESHOOTING.md#windows-insider-program-compatibility)

---

### AppX packages (two-tier, honest restore boundary)

**Tier 1 -- policy-based, exact policy BAVR:** the 27 identities are always declared. On an eligible unmanaged single-session Enterprise/Education 24H2+ client, default No is `NotChecked`; selecting Yes applies root `Enabled`, the native empty `DynamicRemovalList` and 25 PFN-based static-app flags. Unsupported, multi-session, AD-domain-joined and MDM-registered hosts are `NotApplicable` to avoid competing policy controllers. The prompt lists the seven removal-enabled apps from the current inbox gpedit defaults plus the explicitly selected Copilot PFN and warns that device-wide removal can delete app data. Restoring policy prestate does not reinstall apps or recover data. The byte-level layout and sign-in effect were confirmed through actual 25H2 Enterprise gpedit/gpupdate and remain a release gate.

**Tier 2 -- classic per-user removal, explicitly NOT an exact restore:** the first prompt lists the 26 base candidates, including the exact `Microsoft.Copilot` package, and warns that local app data can be lost. If selected, a second default-No decision controls only `MicrosoftWindows.Client.WebExperience` (the taskbar Weather/Widgets board). Keeping it excludes it from the action scope and remains a green verification outcome; selecting it seals, removes and verifies its absence. Backup records a catalog-bound package/provisioning inventory for exactly the selected set; a second pre-Apply query must match it exactly. Apply removes only sealed package full names and verifies their absence; any selected removal failure fails the action/module. Session restore integrity-checks but skips this non-exact artifact. `Restore-BloatwareApps` separately validates the full manifest/hash/catalog, must run as the original user, verifies resulting package registration and reports skipped/failed work as incomplete. It still cannot restore exact app data, version, licensing, dependencies or provisioning.

### Widgets policy under Windows UCPD

Strict and Paranoid declare `HKLM:\SOFTWARE\Policies\Microsoft\Dsh\AllowNewsAndInterests = 0` (disable the Widgets board / News and Interests). Windows 11's **User Choice Protection Driver (UCPD)** blocks direct writes to exactly this value from PowerShell and other command-line tools, so on a host with an active UCPD driver the target fails closed: nothing is written, exact BAVR preserves the state unchanged, and Apply/Verify honestly report the target as `NotApplicable`. **The Widgets board (taskbar weather/news) therefore stays visible on such systems even after a Strict apply** -- this is the OS protecting the value, not a failed apply. After Tier 2 is selected, the separate Weather/Widgets decision can add the "Windows Web Experience Pack" (`MicrosoftWindows.Client.WebExperience`) without touching the UCPD-protected policy (best-effort Store reinstall like every Tier 2 app). Leaving that decision off is explicitly valid and does not reduce verification. Manual alternative: Settings > Personalization > Taskbar > Widgets = Off.

### OneDrive Settings:
- Telemetry: Disabled
- Sync: Functional (not broken)
- Personal OneDrive and Store-access policy: preserved, not forced enabled

---

## 🤖 Module 5: AntiAI (43 Registry Targets + 4 URI Checks)

**Description:** Declare 43 registry targets plus four URI source hives across 12 reversible Windows AI hardening groups. Before backup, each registry target is classified against documented edition, build, preview and installed Edge/Notepad version constraints. Only the applicable subset is backed up, written, restored and exactly verified; every other target remains untouched and is reported as `NotApplicable`.

The source-backed matrix, 26H2 Experimental boundary and current-Copilot AppLocker limitation are documented in [Windows AI applicability](WINDOWS-AI-APPLICABILITY.md).

### Policy groups and compatibility controls:

| # | Feature | Policies | Description |
|---|---------|----------|-------------|
| 1 | **Generative AI AppPrivacy** | 1 | Force-denies documented Windows app access |
| 2 | **Windows Recall** | 9 | Component/snapshot policy, interactive-user data providers, two ADMX enable values, two separate list strings, and storage controls |
| 3 | **Windows Copilot / agents** | 9 | Three interactive-user compatibility controls plus six Insider agent policies |
| 4 | **Click to Do** | 1 | Device-scope availability policy |
| 5 | **Paint Cocreator** | 1 | Cloud-based text-to-image generation |
| 6 | **Paint Generative Fill** | 1 | AI-powered image editing |
| 7 | **Paint Image Creator** | 1 | DALL-E art generator |
| 8 | **Notepad AI** | 1 | Write, Summarize, Rewrite features (GPT) |
| 9 | **Settings Agent** | 1 | AI-powered Settings search |
| 10 | **Recall Export Block** | 1 | Declared only. Microsoft scopes the policy to EEA Insider devices, and the framework has no authoritative device-geography attestation, so the target is never written and is always reported `NotApplicable` |
| 11 | **Copilot URI Handlers** | — | Removes two URI schemes from HKLM plus the interactive user's real Classes source hive; four source checks |
| 12 | **Edge Copilot / AI Policies** | 17 | Sidebar, classic/Copilot new-tab entry points, page context, local model, Compose, Visual Search, History AI, and related versioned policies |

**Total: 43 registry targets** across 11 registry groups, plus four source-hive checks in the URI-handler group. Protected region-policy edits, hosts-file blocking, destructive package removal, and the unsupported `HideAIActionsMenu` value are excluded from Apply. Canonical breakdown: [`Config/SettingsCounts.json`](../Config/SettingsCounts.json).

### Recall Enterprise Protection:
- **App Deny List:** Browser, Terminal, Password managers, RDP never captured
- **URI Deny List:** Six explicit HTTPS origins separated by semicolons; wildcard pseudo-URIs are not used
- **Storage Duration:** Maximum 30 days retention
- **Storage Space:** Maximum 10 GB allocated

### Registry targets (representative subset):
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\LetAppsAccessGenerativeAI = 2
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\AllowRecallEnablement = 0
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis = 1
HKU:\<interactive-user-SID>\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableRecallDataProviders = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\SetDenyAppListForRecall = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DenyAppListForRecall = [...]
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\SetDenyUriListForRecall = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DenyUriListForRecall = [...]
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\SetMaximumStorageDurationForRecallSnapshots = 30
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\SetMaximumStorageSpaceForRecallSnapshots = 10240
HKU:\<interactive-user-SID>\Software\Policies\Microsoft\Windows\WindowsCopilot\TurnOffWindowsCopilot = 1
HKU:\<interactive-user-SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowCopilotButton = 0   (declared; reported NotApplicable - legacy preference, no effect on the current Copilot app)
HKU:\<interactive-user-SID>\Software\Policies\Microsoft\Windows\CopilotKey\SetCopilotHardwareKey = Notepad AUMID
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableClickToDo = 1
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint\DisableCocreator = 1
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint\DisableGenerativeFill = 1
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Paint\DisableImageCreator = 1
HKLM:\SOFTWARE\Policies\WindowsNotepad\DisableAIFeatures = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableSettingsAgent = 1
HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\AllowRecallExport = 0        (declared; reported NotApplicable - EEA-only Insider policy, no device-geography attestation)
HKLM:\SOFTWARE\Policies\Microsoft\Edge\HubsSidebarEnabled = 0
HKLM:\SOFTWARE\Policies\Microsoft\Edge\CopilotPageContext = 0
```

### Impact:
- ✅ Exact configured registry type/value readback
- ✅ Interactive-user targeting survives elevation with different admin credentials
- ✅ Copilot URI source keys backed up/restored from real hives
- ⚠️ Registry PASS does not prove runtime effectiveness outside documented applicability
- ✅ **Reboot required** for applicable Recall/Windows AI policies to be reevaluated

### ⚠️ Known Limitations:
Some UI elements in Paint and Photos apps may **still be visible** but non-functional due to lack of Microsoft-provided policies:
- **Photos:** Generative Erase button, Background Blur/Remove options
- **Paint:** Some AI feature UI elements

**Why?** Microsoft does not provide a documented policy for every product/UI surface. The framework verifies only its declared policy values; it does not claim that every visible button is nonfunctional without a product-specific runtime test.

---

## 🌐 Module 6: EdgeHardening (26 Managed Values)

**Description:** 19 Microsoft Edge v139 baseline values plus seven separately identified NoID Privacy additions. The default profile leaves the extension block-all value unmanaged (25 selected); the strict choice selects all 26. Cloud address-bar suggestions, Bing trending suggestions and Reading Mode's online text extraction are disabled without removing local history/favorite suggestions or Reading Mode itself. Four SmartScreen values enter Apply only when the documented managed-Windows prerequisite is proven by AD domain membership or the Windows MDM registration API on Pro/Enterprise; otherwise they remain untouched and are `NotApplicable`. Edge-151-only policy is likewise per-target `NotApplicable` on an installed older Edge. The `**delvals.` parser row is metadata and is not counted.

Exact Microsoft package provenance, hash, deviations and applicability notes: [EDGE-POLICY-PROVENANCE.md](EDGE-POLICY-PROVENANCE.md).

### Core Security:
- SmartScreenEnabled = 1
- SmartScreenPuaEnabled = 1
- PreventSmartScreenPromptOverride = 1
- SitePerProcess = 1 (Site isolation)

### Privacy:
- TrackingPrevention = 2 (Balanced)
- PersonalizationReportingEnabled = 0
- DiagnosticData = 0
- EdgeShoppingAssistantEnabled = 0

### Security Mitigations:
- SSL/TLS error override blocked
- Extension blocklist (Microsoft baseline block-all is opt-in; existing external policy is preserved by the default profile). Selecting block-all writes `ExtensionInstallBlocklist\1 = "*"`: Edge then blocks **every** extension install and disables already-installed extensions. Exceptions work only through extension IDs added to `ExtensionInstallAllowlist` — a list the user maintains themselves (registry/Intune); NoID Privacy does not curate it. Restore removes the policy exactly and previously installed extensions are re-enabled. In verification this target appears as `ExtensionInstallBlocklist entry "1" (block-all "*")` — list policies consist of numbered registry values, so the raw value name is literally `1`; with the default allow-extensions profile it is honestly reported as NotChecked (deliberately not selected), never as passed.
- IE Mode restrictions
- SharedArrayBuffer disabled (Spectre protection)
- Application-bound encryption enabled

### Features:
- ✅ Native PowerShell implementation (no LGPO.exe)
- ✅ `AllowExtensions` compatibility parameter selects the default unmanaged-blocklist profile; it does not erase an existing administrator blocklist
- ✅ Sealed BAVR for the declared applicable target set

---

## 🔐 Module 7: AdvancedSecurity (60 Declared Checks)

**Description:** Advanced hardening beyond Microsoft Security Baseline

### Profile-Based Execution:

| Feature | Balanced | Enterprise | Maximum |
|---------|------|------------|-----------|
| RDP NLA Enforcement | ✅ | ✅ | ✅ |
| Risky Ports/Services | ✅ | ✅ | ✅ |
| Legacy TLS Disable | ✅ | ✅ | ✅ |
| WPAD Disable | ✅ | ✅ | ✅ |
| Admin Shares Disable | ✅ | ⚠️ Domain Check | ✅ |
| RDP Complete Disable | ⚠️ Optional | ❌ | ✅ |
| UPnP/SSDP Block | ⚠️ Optional | ✅ | ✅ |
| Wireless Display Hardening | ✅ | ✅ | ✅ |
| Wireless Display Full Disable | ⚠️ Optional | ⚠️ Optional | ⚠️ Optional |
| Discovery Protocols (WSD/mDNS) Disable | ❌ | ❌ | ⚠️ Optional |
| Firewall Shields Up | ❌ | ❌ | ⚠️ Optional |
| IPv6 component disable (`0xFF`) | ❌ | ❌ | ⚠️ Optional |
| SRP .lnk Protection | ✅ | ✅ | ✅ |
| Windows Update Config | ✅ | ✅ | ✅ |
| Finger Protocol Block | ✅ | ✅ | ✅ |

### Components:

#### 1. RDP Hardening (3 settings)
- **Applicability:** [Microsoft documents Remote Desktop hosting](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access) for Professional, Enterprise and Education; all three RDP host targets are NotApplicable on Home
- **NLA Enforcement:** UserAuthentication = 1, SecurityLayer = 2 on host-capable editions
- **Optional Disable:** fDenyTSConnections = 1 (forced by Maximum; an explicit choice in Balanced; not selected by Enterprise)
- **Protection:** Prevents RDP brute-force attacks

#### 2. Base risky-port firewall rules (6 rules)
- **LLMNR:** inbound UDP 5355
- **NetBIOS:** inbound UDP 137/138 and TCP 139
- **UPnP/SSDP:** inbound UDP 1900 and TCP 2869 when that choice is selected
- Additional stable rules cover Public SMB 445, Finger TCP 79, optional discovery and optional Miracast; there are 16 module-owned rule identities in the complete declared firewall inventory plus the separate Public-profile Shields Up value

#### 3. Risky Services (3 services)
- **SSDP Discovery:** Disabled only when the UPnP/SSDP choice is selected
- **UPnP Device Host:** Disabled only when the UPnP/SSDP choice is selected
- **TCP/IP NetBIOS Helper:** Disabled by every profile when the service exists
- Missing optional Windows services are reported `NotApplicable`, never as applied or failed

#### 4. Administrative Shares (2 registry keys)
- **AutoShareWks = 0:** Disables C$, ADMIN$
- **AutoShareServer = 0:** Server shares
- **Domain-Aware:** Auto-skipped for domain-joined systems unless -Force

#### 5. Legacy TLS Disable (8 values across 4 registry keys)
- **TLS 1.0:** Client + Server disabled
- **TLS 1.1:** Client + Server disabled
- **Boundary:** Disables SCHANNEL client/server state for TLS 1.0 and 1.1. It does not claim that every legacy-protocol attack is prevented or that every other protocol is enabled.

#### 6. WPAD Disable (2 checks)
- **WinHTTP machine policy:** `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DisableWpad = 1`
- **Interactive Explorer user:** Clears only `PROXY_TYPE_AUTO_DETECT` (bit `0x8`) through WinINet option 75 in that user's token and preserves every unrelated proxy flag
- **Restore boundary:** Seals the machine value plus that user's SID/session identity and original auto-detect bit. Restore fails closed if the saved user is not the active Explorer user; it never writes `HKU\.DEFAULT`, scalar `AutoDetect`/`WpadOverride` values or raw connection blobs.
- **Applicability:** The user check is `NotApplicable` when no unambiguous interactive Explorer user exists
- **Protection boundary:** Reduces WPAD auto-discovery/proxy-hijacking exposure; it is not a universal proxy-attack prevention claim

Microsoft [removed Windows PowerShell 2.0 from updated Windows 11 24H2 in August 2025](https://learn.microsoft.com/en-us/windows/whats-new/removed-features) and from later releases. It is therefore not a declared target, query, backup, Apply step, verifier row or UX warning in a new NoID Privacy run. The historical `PowerShellV2` reader remains only for compatibility with older sealed v2.2.5 sessions. It reproduces the recorded prestate only while Windows still exposes that optional-feature identity; if later servicing removed it, Restore fails closed and reports the external incompatibility instead of reporting a false exact restore.

#### 7. Legacy SRP .lnk path rules (2 rules / 8 registry values)
- **Rule 1:** Block %LOCALAPPDATA%\Temp\*.lnk (Outlook attachments)
- **Rule 2:** Block %USERPROFILE%\Downloads\*.lnk (Browser downloads)
- **Verified scope:** Exact registry configuration of two stable path rules
- **Boundary:** Runtime enforcement is not asserted. Microsoft deprecated SRP beginning with Windows 10 1803 and recommends WDAC or AppLocker on modern Windows.
- **Enforcement-suppression detection (read-only):** stock Windows 11 22H2+ images ship `HKLM\SYSTEM\CurrentControlSet\Control\Srp\Gp\RuleCount` non-zero, which makes the SAFER/SRP engine defer to AppLocker and stop applying SRP rules. `Test-SRPCompliance` reads that OS counter and, when non-zero, surfaces an explicit warning that these path rules may be registered but not enforced. NoID Privacy never writes that OS `Control` key; correcting `RuleCount` to 0 is an owner decision.

#### 8. Stable Windows Update Configuration (3 documented values)

**Uses current documented policy/UX values** – NO forced schedules, NO deadlines, and NO restart policy

On Windows Home, Microsoft does not list the [`AllowOptionalContent`](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#allowoptionalcontent) or [`DODownloadMode`](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deliveryoptimization#dodownloadmode) policy CSPs as supported. The framework therefore applies only the documented early-rollout UX preference there and reports both managed-policy targets as NotApplicable. Pro, Enterprise, Education and IoT Enterprise apply all three values.

**Settings Applied:**

**1. Optional Updates (user-selected, managed by policy)**
- Registry: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
- Key: `SetAllowOptionalContent = 3`
- Effect: Official `AllowOptionalContent` policy choice 3. Users choose optional updates themselves; the device is not automatically enrolled in optional cumulative previews or early CFRs.

**2. Early continuous-innovation rollout (OFF)**
- Registry: `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings`
- Key: `IsContinuousInnovationOptedIn = 0`
- Effect: Leaves "Get the latest updates as soon as they're available" off. Regular security updates continue normally; additional non-security and feature changes are not prioritized.
- Limitation: this value is a Windows-owned Settings preference, not a policy. If the toggle was ever turned **on** manually, Windows stores that choice as a stamped opt-in intent (`CIOptinModified`) and re-asserts `1` over the hardened value at boot and on Settings activity — and `SetAllowOptionalContent = 3` deliberately leaves this decision with the toggle. Apply detects a stored opt-in and reports it; the only durable fix is to turn the toggle **off** under Settings > Windows Update. Until then, verification honestly reports the drift.

**3. Delivery Optimization - Downloads from Other Devices (HTTP-only, managed by policy)**
- Registry: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization`
- Key: `DODownloadMode = 0`
- Effect: HTTP only (Microsoft servers) – no peer-to-peer, no LAN sharing
- GUI Path: Settings > Windows Update > Advanced options > Delivery Optimization > Allow downloads from other devices = OFF (managed by your organization)

**User Control & Transparency:**
- ✅ NO forced installation schedules
- ✅ NO auto-reboot policies
- ✅ Optional non-security updates remain user-selected
- ✅ Microsoft-product update enrollment remains untouched
- ✅ Windows clearly indicates where policies manage settings ("Some settings are managed by your organization")

**Why This Approach?**
- Uses current Microsoft-documented registry mappings
- Avoids automatic optional preview/CFR enrollment and preserves regular security updates
- Avoids changing update-source enrollment, whose downstream product installations cannot be undone by BAVR
- No unexpected reboots at 3 AM
- Separates policy-enforced behavior from user-visible UX preferences

#### 9. NetBIOS adapter hardening (1 aggregate)
- Sets `TcpipNetbiosOptions = 2` through the language-independent CIM provider for every IP-enabled adapter
- Apply and Verify require every currently IP-enabled adapter to report the disabled state
- BAVR additionally captures every present physical adapter, including media-disconnected/IP-disabled ones (schema 2), so no adapter is silently excluded from the sealed prestate
- BAVR seals and restores the exact per-adapter prestate; adapter inventory drift fails closed rather than claiming an exact restore

#### 10. Finger Protocol Block (1 firewall rule)
- **Port:** TCP 79 outbound
- **Scope:** exact outbound TCP/79 rule; alternate ClickFix executables/ports/protocols remain outside this control
- **Attack:** Malware uses finger.exe to retrieve commands from attacker servers
- **Impact:** Blocks outbound TCP/79 for every program under the rule's Any-program scope; a legacy Finger client or another legitimate TCP/79 workflow would be affected

#### 11. Wireless Display Security (9 settings)

**Default Hardening (all profiles on [supported Pro/Enterprise/Education/IoT editions](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-wirelessdisplay)):**
- **AllowProjectionToPC = 0:** Block receiving projections (PC can't be used as display)
- **RequirePinForPairing = 2:** Always require PIN for pairing

**Optional Full Disable (user choice):**
- **AllowProjectionFromPC = 0:** Block sending projections
- **AllowMdnsAdvertisement = 0:** Don't advertise as receiver via mDNS
- **AllowMdnsDiscovery = 0:** Don't discover displays via mDNS
- **AllowProjectionFromPCOverInfrastructure = 0:** Block infrastructure projection
- **AllowProjectionToPCOverInfrastructure = 0:** Block infrastructure receiving
- **Firewall Rules:** Block Miracast ports 7236/7250 (TCP + UDP)

**Verified scope:**
- Exact receive/send/infrastructure/mDNS policy values selected by the profile
- Exact module-owned TCP/UDP 7236/7250 firewall rules when the firewall layer is selected
- Exact Wi-Fi Direct service and virtual-adapter state for the complete-disable choice
- No universal prevention claim is inferred from policy/firewall readback

**Impact:**
- Default: Presentations to TV/projector still work (sending allowed)
- Full Disable: Use HDMI/USB-C cables instead of Miracast

#### 12. Discovery Protocols Security (WS-Discovery + mDNS)

**Optional (Maximum profile - user choice):**
- **mDNS Resolver:** Disabled via registry (EnableMDNS = 0)
- **WS-Discovery Services:** FDResPub + fdPHost disabled
- **Firewall Blocks:**
  - WS-Discovery: inbound UDP 3702 plus TCP 5357/5358
  - mDNS: inbound UDP 5353

**Verified scope:**
- Exact `EnableMDNS=0` registry state
- Exact selected WS-Discovery service disablement
- Exact module-owned UDP 3702/5353 firewall rules when the firewall layer is selected
- This reduces selected discovery exposure; it is not proof that every mapping, spoofing or lateral-movement path is blocked

**Impact:**
- Affected network printer/scanner discovery can stop
- Affected Smart TV and Miracast discovery can stop
- Direct-IP or vendor-specific discovery behavior remains product-dependent

#### 13. Firewall Shields Up (Maximum profile only)

**Maximum-profile firewall value:**
- Sets `PublicProfile\DoNotAllowExceptions=1`.
- On the Public firewall profile, inbound exceptions are ignored; it does not change outbound default action and does not apply this value to Domain or Private profiles.

**Protection boundary:**
- Narrows Public-profile inbound exposure by ignoring configured inbound exceptions.
- Does not create an outbound default-deny policy and is not complete network isolation.

**Impact:**
- Public-profile applications that require inbound exceptions can stop receiving traffic.
- Intended only for a specifically tested Maximum-profile environment.

#### 14. IPv6 component disable (`0xFF`, Maximum profile only - optional)

**Optional (Maximum profile - user choice):**
- **DisabledComponents = 0xFF:** Microsoft's documented broad IPv6-disable value
- **Exact boundary:** Windows retains internal IPv6 functionality such as loopback; complete runtime absence is not asserted

**Security effect:**
- Reduces network-facing DHCPv6/Router Advertisement attack surface after reboot
- Can limit fake-DHCPv6/DNS takeover paths as defense-in-depth
- Does not by itself guarantee complete mitm6 or NTLM-relay prevention

**Impact:**
- IPv6-only services/websites won't work
- Exchange Server may have issues if using IPv6
- Some Active Directory features may be affected
- **REBOOT REQUIRED**

**Microsoft guidance:**
- IPv6 is a mandatory Windows component and Microsoft does not recommend disabling it
- Keep IPv6 enabled for ordinary use; Microsoft recommends `0x20` (prefer IPv4) instead when address preference is the actual requirement
- Select `0xFF` only for a specifically tested environment with a documented need and rollback plan

---

## 🎯 Protection Coverage

### Supplemental controls:

#### CVE-2025-9491 supplemental legacy SRP path rules (registry configuration only)
- **Status:** Microsoft advisory ADV25258226; the framework adds two legacy location-based SRP rules
- **Verified scope:** Stable rule registry state only; effective enforcement and complete CVE mitigation are not claimed
- **Microsoft guidance:** Prefer WDAC or AppLocker on modern Windows

#### Finger protocol egress restriction
- **Attack Vector:** finger.exe abuse to retrieve malicious commands
- **Verified scope:** One exact module-owned outbound TCP/79 block rule and its complete filter set
- **Boundary:** This narrows one possible command-retrieval path; it is not a complete malware-campaign mitigation

### Attack Surface Reduction:

| Attack Type | Protection |
|-------------|-----------|
| **Email Malware** | ASR: Block executables from email |
| **USB Malware** | ASR: Block untrusted USB processes |
| **Office Macros** | ASR: Block Win32 API calls |
| **Credential Theft** | ASR: Block credential stealing from LSASS |
| **Ransomware** | ASR: Advanced ransomware protection |
| **Name-resolution interception exposure** | DNS DoH plus selected LLMNR/NetBIOS controls reduce specific paths; they do not prevent every MITM technique |
| **RDP exposure** | NLA/TLS policy plus optional host disable; NLA alone does not make password brute force impossible |
| **Proxy Hijacking** | WPAD disabled |
| **Legacy TLS exposure** | SCHANNEL TLS 1.0/1.1 client/server values disabled; no universal exploit-prevention claim |
| **DMA/device-installation exposure** | Baseline-derived policy state is applied; complete elimination of physical DMA paths is not claimed |

---

## 📋 Interactive Features

### Conditional interactive decision points

The number shown depends on edition, domain state, Defender/cloud state, selected profile and installed features; there is no fixed prompt total.

#### SecurityBaseline (up to 4 prompts):
- **BitLocker USB Policy** (all supported editions)
   - Home Mode: USB works normally (no encryption enforcement)
   - Enterprise Mode: Require BitLocker encryption on USB drives

- **Defender sample submission** (Y/N: safe samples/all samples)
   - Safe samples (`1`, default): privacy-preserving documented deviation
   - All samples (`3`): Microsoft baseline value; suspicious personal files may be uploaded

- **SmartScreen level** (Y/N: Block/Warn)
   - Block (default): Microsoft baseline value without a "Run anyway" bypass
   - Warn: compatibility choice that keeps SmartScreen active and restores the explicit bypass

- **Standard-user elevation** (Y/N: Strict/SecureDesktop; asked for the machine even when the current account is an administrator)
   - Strict (`0`, default): automatically deny standard-user elevation for maximum separation
   - SecureDesktop (`1`): permit standard users to enter separate administrator credentials on the secure desktop

#### ASR (2 regular decisions plus a conditional cloud decision):
- **PSExec/WMI rule mode** (Block/Audit)
   - Block: Maximum security (may break SCCM/remote admin)
   - Audit: Log only (compatibility testing)

- **New Software rule mode** (Block/Audit)
   - Audit (default): Log only - new software remains installable (recommended for most users)
   - Block: Block executables that don't meet prevalence criteria (maximum security)

If Defender cloud protection is unavailable, a third conditional Continue/Abort decision is shown.

#### DNS (2 prompts):
- **Provider selection** (Quad9/Cloudflare/AdGuard/Skip)
   - 3 DNS providers with source-linked factual capability descriptions
   - Skip option to keep current DNS
   - LAN-resolver hint shown with the Skip option and mirrored to unattended
     logs: "Your selection replaces network DNS; if your router or LAN
     filtering provides DNS, Skip preserves it." The client does not claim it
     can distinguish ordinary router forwarding from custom LAN filtering.

- **DoH Mode selection** (REQUIRE/ALLOW)
   - REQUIRE: No unencrypted fallback (maximum security)
   - ALLOW: Fallback to UDP if needed (VPN/corporate/mobile)
   - Skip: Keep current DNS settings

#### Privacy (2 decisions plus conditional warning confirmation):
- **Mode selection** (MSRecommended/Strict/Paranoid)
   - MSRecommended: least disruptive profile; target-host compatibility still requires validation
   - Strict: selected strict controls; non-selected app-permission policy is preserved
   - Paranoid: broadest app-permission deny set; microphone/camera-dependent app functions are unavailable

- **Cloud Clipboard** (Disable/Preserve) - *only in MSRecommended mode*
   - Disable: No cross-device clipboard sync (privacy)
   - Preserve: Do not change the current Cloud Clipboard policy/state

#### EdgeHardening (1 prompt):

- Leave the extension block-all value unmanaged (default) or select the strict block-all profile.

#### AdvancedSecurity (profile- and host-dependent prompts):
- **Profile selection** (Balanced/Enterprise/Maximum)
   - Balanced: Safe defaults for home users
   - Enterprise: Domain-aware checks
   - Maximum: Maximum hardening

- **Windows Firewall layer** (Apply/Skip)
   - Controller detection supplies only the default; the answer is authoritative
   - Skip is reported as `NotChecked`, never Applied

- **Final continue confirmation**

- **RDP Disable** (Yes/No) - *Balanced profile only; Maximum disables on host-capable editions; Home is NotApplicable*
    - Yes: Completely disable Remote Desktop
    - No: Keep RDP enabled (with NLA hardening)

- **UPnP/SSDP Block** (Yes/No) - *Balanced profile only, others always block*
    - Yes: Block UPnP/SSDP (may break DLNA streaming)
    - No: Keep UPnP enabled

- **Wireless Display Disable** (Yes/No) - *all profiles on supported editions; Home is NotApplicable*
    - Yes: Completely disable Miracast (use HDMI instead)
    - No: Keep Miracast hardened but usable

- **Admin Shares Disable** (Yes/No) - *Balanced profile on domain-joined systems only*
    - Yes: Disable C$/ADMIN$ even on domain (may break IT tools)
    - No: Keep admin shares for IT management (SCCM, PDQ, etc.)

- **Discovery protocols** (Yes/No) - *Maximum only*
    - Optional exact mDNS/WS-Discovery service, registry and firewall target set

- **IPv6 `DisabledComponents=0xFF`** (Yes/No) - *Maximum only*
    - Default No; Microsoft recommends keeping IPv6 enabled

### Backup & Restore:

- ✅ Session-based backup system (Initialize-BackupSystem)
- ✅ Exact selected-target registry prestate before changes
- ✅ Service state backup
- ✅ Feature state backup
- ✅ DHCP settings backup (DNS module)
- ✅ Restore capability for all modules
- ✅ Collision-resistant session identity: timestamp + milliseconds + random nonce
- ✅ Indefinite retention: no automatic age/count/size deletion of backup sessions
- ✅ Complete visibility: every directory in the backup root is listed, including renamed, legacy, hidden, invalid and unsealed folders
- ✅ Failed pre-Apply backups are detached, hash-inventoried and retained as clearly named incomplete/non-restorable records; they are never silently cleaned up

### Verification:

- ✅ `Tools/Verify-Complete-Hardening.ps1` reconciles the SecurityBaseline and cross-module declared scope
- ✅ `Test-ASRCompliance` (ASR)
- ✅ Exact DNS Apply/Restore/status checks plus the global five-check DNS aggregate
- ✅ `Test-AntiAICompliance` (AntiAI)
- ✅ `Test-PrivacyCompliance` (Privacy)
- ✅ `Test-EdgeHardening` (EdgeHardening)
- ✅ `Test-AdvancedSecurity` (AdvancedSecurity)

---

## 🔧 Safety Features

### Pre-Flight Checks:
- ✅ Administrator elevation required
- ✅ Explicit Windows 11 client profile detection (24H2/25H2 stable; the same 25H2-derived SecurityBaseline target/BAVR contract is used on both; an explicitly reported 26H2 preview is admitted as an Experimental full-BAVR apply path that is currently not runtime-validated or release-approved)
- ✅ Hardware capability detection with explicit query state (TPM specification/readiness, Secure Boot, firmware virtualization, VM extensions and SLAT)
- ✅ Domain-joined system detection

### Execution Safety:
- ✅ WhatIf mode (dry-run preview)
- ✅ Profile-based execution (Balanced/Enterprise/Maximum)
- ✅ Incremental backups
- ✅ Fail-closed backup/apply/verify gates
- ✅ Structured execution, verification and restore logging

### Rollback:
- ✅ `Restore-Session` is the authoritative sealed-session engine for all seven modules
- ✅ `Restore-SecurityBaseline`, `Restore-DNSSettings` and `Restore-AdvancedSecuritySettings` are module-specific public wrappers/helpers
- ✅ Privacy, AntiAI, Edge and ASR artifacts are restored by the same typed Core session engine

---

## 📊 Home User Friendly

### Password Policies (Compatibility review required):
- ✅ Local Windows account policy is configured; Microsoft-account cloud password policy is separate
- ✅ Policies: MinimumPasswordLength (14), PasswordHistory (24), Lockout (10)

### BitLocker USB (User Choice):
- ✅ Default: Home Mode (USB works normally)
- ✅ Option: Enterprise Mode (encryption enforcement)
- ✅ Interactive prompt during SecurityBaseline

### IEEE 1394 / DMA-related device policy:
- ✅ Exact baseline-derived device-installation policy state is applied
- ⚠️ Test any required legacy capture hardware; no population-impact percentage or total DMA-prevention claim is made


---

## 🎉 Framework Status

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NoID Privacy v2.2.5
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Default Declared Checks:    645 (default decisions, Defender as primary engine)
                            626 outside ASR (with third-party primary endpoint product; 18 applicable ASR checks are NotChecked and 1 is NotApplicable)
Modules:                    7/7
Status:                     Released (v2.2.5); Windows 11 Pro 25H2 runtime evidence recorded (gate: Docs/WINDOWS-VM-RELEASE-GATE.md)
Verification:               Tools/Verify-Complete-Hardening.ps1 reconciles the declared four-state scope
BACKUP-APPLY-VERIFY-RESTORE: Implemented for all module-applied settings

Supplemental controls:      Legacy SRP .lnk path rules (runtime not asserted) + exact Finger TCP/79 block rule
Microsoft Baseline:         MS Security Baseline for Windows 11 v25H2 implemented
Compatibility choices:      Interactive prompts for potentially disruptive decisions
Profile-Based Execution:    Balanced / Enterprise / Maximum
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

**Last Updated:** 2026-08-02
**Framework Version:** v2.2.5
