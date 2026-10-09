# Changelog

All notable changes to NoID Privacy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries record the state at each release. Current counts and support
> boundaries are defined by `Config/SettingsCounts.json`, the provenance
> documents in `Docs/`, and the generated test artifacts.

---

## [2.2.6] - 2026-09-30

Windows 11 26H2 support, updated Windows and Edge security baselines, and
more reliable Backup, Apply, Verify and Restore across all seven modules.
See the [release notes](Docs/RELEASE-NOTES-2.2.6.md) for details and recovery limits.
The build of 2026-10-08 brings AntiAI in line with Microsoft's current Windows AI
policy set and adds the Microsoft Copilot app and more Edge AI controls. DNS
Restore now returns settings made in Windows Settings exactly.
The build of 2026-10-09 moves SecurityBaseline to Microsoft's v2 package,
makes Privacy Paranoid turn Windows Error Reporting off with Microsoft's
policy, which actually stops error reports, and removes AdvancedSecurity
values that Windows never applied.

### Breaking

- SecurityBaseline keeps Microsoft's `LocalAccountTokenFilterPolicy=0` on
  standalone/workgroup PCs. The automatic override and `-SkipStandaloneDelta`
  were removed. After a new Apply, privileged SMB, WMI and WinRM operations
  with a local administrator account can return **Access denied**. Local UAC
  prompts and interactive RDP sessions are unaffected.
- New Apply requests LSA protection (both `RunAsPPL` entries), Credential Guard
  and memory integrity with value `2` instead of Microsoft's `1`, avoiding new
  UEFI locks so recovery can stay in Windows. This reduces resistance to
  privileged reconfiguration. Existing locks are not removed, and Restore
  keeps each backup's recorded values. See [recovery limits](Docs/SECURITY-BASELINE-RECOVERY.md).

### Added

- Full Windows 11 26H2 x64 support alongside 24H2 and 25H2, with the same
  seven-module BAVR lifecycle and explicit per-target applicability.
- Administrator protection choices: PIN/password/Windows Hello (default),
  Yes/No with protection enabled, or classic UAC for compatibility.
  Administrator protection needs Windows update KB5120998 or later and starts
  after a restart.
- Microsoft Edge v151 baseline: 24 Microsoft values plus seven separately
  identified privacy additions; 30 values are selected by default.
- WindowsAI agent controls for supported 26H2 commercial editions, and a
  separate verification summary showing which Windows protections are running.
- Microsoft Copilot app policies (no browsing, no Cowork actions), no
  telemetry from Microsoft Execution Containers, and six more Edge AI policies:
  cloud text prediction, AI tab organization, cloud autofill models, Microsoft
  Editor cloud proofing, Copilot Cowork browser actions and automatic
  Copilot/Bing/MSN sign-in linking (build of 2026-10-08).
- A block on installing Copilot through Microsoft Edge Update on domain-joined
  or MDM-enrolled PCs. Edge Update ignores its policies on other PCs, so the
  block is reported as not applicable there (build of 2026-10-08).
- The Microsoft 365 Copilot and Copilot apps no longer start at sign-in. AntiAI
  turns off their startup tasks for the desktop user, the same as Settings >
  Apps > Startup, and only where the app is installed (build of 2026-10-08).
- Shared Xbox Quick Action backend: detect and switch Xbox apps, services and
  recording settings together, with app recovery and explicitly settings-only
  Restore. Mixed states can be repaired in either direction.

### Changed

- Unattended ASR runs check Defender and cloud prerequisites before any module
  starts. An explicit partial-run choice can apply the other modules; missing
  ASR or limited cloud protection no longer appears as complete success.
- Privacy preserves organization-controlled policy paths, services and tasks
  on managed PCs or when management ownership cannot be checked. Ordinary
  user preferences remain available, and existing backups remain restorable.
- All supported releases use the 425-target Windows 11 v26H2 baseline v2-derived
  profile, including TLS 1.2/1.3 for WinINet/IE mode and Windows Ready Print
  driver ranking. Native Device Guard policy processing also supports exact
  recovery of its recorded local state.
- Complete verification always accounts for 703 targets. Reports distinguish
  passed, failed, excluded by choice and not applicable; missing required
  evidence counts as failed. Default decisions declare 647 checks, Strict 672
  and Paranoid 703 (build of 2026-10-09; builds of 2026-10-08 declared 658, 683
  and 712, the first 2.2.6 builds 651, 676 and 705).
- AntiAI declares 50 registry targets plus four URI source checks (build of
  2026-10-08; earlier 2.2.6 builds declared 43). Windows app access to text and
  image generation is denied through `LetAppsAccessSystemAIModels`, the
  AppPrivacy policy Windows reads; AntiAI and Privacy Strict/Paranoid no longer
  write `LetAppsAccessGenerativeAI`, which no Windows build reads.
  `DisableRecallDataProviders` is written only on detected Windows Insider
  builds. New AntiAI backups use snapshot schema 5; schema-4 sessions restore
  exactly as before.
- Offline DNS configuration verifies local settings without requiring resolver
  reachability. Store-only app recovery waits for a later online run.
- The console uses concise per-module results and named warnings. HTML reports
  use consistent counts, searchable evidence and complete detailed printouts.
- Privacy captures and restores both cloud content search toggles. Strict and
  Paranoid retain their settings-backup restrictions on 26H2.
- SecurityBaseline uses Microsoft's Windows 11 v26H2 Security Baseline v2,
  which replaced the first 26H2 package on 2026-10-08. The only change is the
  Administrator protection prompt policy, now set explicitly to Microsoft's
  credentials prompt (`ConsentPromptBehaviorEnhancedAdmin=1`); the Yes/No
  choice still sets 2. The prompt itself does not change, because Windows used
  1 when the value was not set. SecurityBaseline declares 425 targets, and
  verification names the value on PCs where only an earlier 2.2.6 build
  applied the baseline until it is applied again; 2.2.4 and 2.2.5 set it from
  Microsoft's 25H2 baseline (build of 2026-10-09).
- AdvancedSecurity no longer writes the two legacy SRP `.lnk` path rules.
  Measured on 25H2 and 26H2, Windows never enforced them: the AppLocker/Smart
  App Control marker `Srp\Gp\RuleCount=2` turns SRP off. It also no longer
  writes the five Wireless Display values (`AllowProjectionFromPC`, the two
  mDNS values and the two infrastructure values) that Windows reads only
  through MDM; the complete-disable choice keeps the Wi-Fi Direct service,
  adapters and Miracast firewall rules, and the Wireless Display Quick Action
  does the same and removes the five values when it re-enables Wireless
  Display. AdvancedSecurity declares 48 checks in 13 areas; new backups use
  schema 6, and sessions saved by earlier builds restore all their values
  (build of 2026-10-09).

### Fixed

- Firewall Quick Actions reject altered rule scopes before changing anything.
  Failed Windows queries no longer look like missing rules; existing rule
  identities and backup formats are unchanged.
- ASR changes update the running Defender engine on Apply and Restore while
  preserving existing local rule preferences. ASR Quick Actions require active
  Defender protection and refuse an unfinished recovery.
- The Wireless Display Quick Action recognizes the module's receiving-only
  protection and can switch sending on or off without removing that protection.
- Leaving the Edge extension blocklist unchanged no longer causes a false
  verification failure when an earlier profile or administrator set a block.
  Reports show the retained value as excluded by choice.
- HTML verification keeps cloud-dependent ASR rules unproven when required
  Defender cloud protection is disabled or cannot be established.
- Restart recommendations survive partially failed Apply runs, while failures
  retain their error status. ASR-only runs do not request a Windows restart.
- App removal preserves verified per-app results when another app remains
  installed or Windows registers it again. Already absent sealed packages no
  longer cause an identity-drift error.
- Temporary user tasks for app removal, Windows Search and WinINet run without
  flashing terminal windows and also work with the ASR new-software rule set
  to Block. Failed task starts are reported without waiting for the full timeout.
- AdvancedSecurity refreshes its unsealed firewall backup when Windows changes
  only generated app-package capability rules. Other drift still stops Apply.
  Newly written rules are verified with bounded retries while Windows exposes
  their full active state; persistent mismatches still fail.
- Firewall GPO initialization and recovery preserve unrelated policy. UPnP and
  Wireless Display Quick Actions now recognize AdvancedSecurity's GPO rules.
  On Home, an incompatible local-rule merge policy is detected before Apply.
- Registry-key and scheduled-task lookups tolerate concurrent Windows changes;
  manual-service transitions and clock adjustments no longer cause false
  failures. Slow Windows Search refreshes receive a bounded longer wait.
- Interrupted backups or receipt writes no longer hide earlier sealed modules.
  Partial restores respect shared targets, and UTF-8, multiline and typed
  registry values retain their original data.
- Explicit ASR choices take precedence over baseline defaults. DNS Restore
  preserves unowned address families, and Device Guard Restore waits for native
  policy processing before returning recorded registry values.
- App recovery works after combined Privacy/AntiAI Restore, tries local package
  registration first and repairs an incompatible WinGet client through a pinned,
  Microsoft-signed App Installer update when Store access is needed.
- Temporary helper folders resist replacement and redirected cleanup. Installer
  upgrades preserve Backups, Logs and Reports; the launcher supports protected
  install folders and no longer closes an existing PowerShell window.
- Privacy and AdvancedSecurity no longer stop with "Hidden worker parent permits
  replacement by another principal" when other software has loosened the
  permissions of `C:\ProgramData` or `C:\`. The SYSTEM task that starts
  user-level helpers runs only inputs whose SHA-256 its task definition names
  and deletes them through its own handles. The system check names such an
  account and right as a warning.
- A failed AdvancedSecurity backup step no longer adds a misleading
  "Interactive Explorer user changed" follow-on error.
- AntiAI no longer writes `DisableAgentConnectors`, `DisableAgentWorkspaces`,
  `DisableRemoteAgentConnectors` and `AgentConnectorMinimumPolicy`: Microsoft
  removed them from the WindowsAI CSP, no official template contains them and
  no Windows build reads them. Values written by earlier 2.2.6 builds stay until
  that session is restored. Descriptions no longer overstate the legacy Copilot
  policy, the Copilot key remap, the Click to Do policy or several Edge
  policies. Verification reports AntiAI as not proven, with the reason, when the
  saved plan predates the current list; applying AntiAI again saves a new one
  (build of 2026-10-08).
- DNS Restore no longer fails, and no longer leaves DNS over HTTPS turned off,
  when an adapter used "On (automatic template)" in Windows Settings before
  Apply; Windows rejected the empty template it received (error 12006). Restore
  also returns Windows' built-in DoH list, the entries added for AdGuard and the
  adapter's DoH registry keys exactly instead of leaving `Flags` values of 0 and
  empty keys. New DNS backups use schema 6; sessions saved by earlier builds
  restore the same settings, and the raw details they did not record can
  remain as empty keys or zero `Flags` values (build of 2026-10-08).
- DNS Restore rejects a backup whose adapter key names contain `/`, which the
  registry provider treats as a path separator, and it reads the raw registry
  state and decides every restore step before the first write, so unsupported
  registry state can no longer leave DNS half restored (build of 2026-10-09).
- The DNS ALLOW mode is described as measured: Windows also sends a lookup
  unencrypted when DNS over HTTPS fails and for names that do not exist.
  REQUIRE sent no lookup unencrypted in the same tests (build of 2026-10-08).
- AdvancedSecurity sets Windows Update's optional-updates policy as
  `WindowsUpdate.admx` defines it: `SetAllowOptionalContent=1` (enabled) with
  `AllowOptionalContent=3` (users select optional updates). 2.2.5 and earlier
  2.2.6 builds wrote `SetAllowOptionalContent=3` without the choice value; on
  PCs hardened by them, verification names both values and asks to apply
  AdvancedSecurity again (build of 2026-10-09).
- AdvancedSecurity Restore removes what `netsh advfirewall import` adds: empty
  `AuthorizedApplications` and `GloballyOpenPorts` keys under each firewall
  profile and a changed `LogFilePath` value type, so the firewall registry
  returns exactly (build of 2026-10-09).
- Privacy Paranoid turns Windows Error Reporting off with Microsoft's
  documented `DisableWindowsErrorReporting` policy instead of disabling the
  `WerSvc` service. Measured on 25H2 and 26H2, earlier 2.2.6 builds did not stop
  error reports: Windows still created them and sent them to Microsoft once the
  PC was online, and a .NET program that crashed hung instead of closing. With
  the policy no report is created or sent and crashed programs close normally.
  The policy is Pro/Enterprise/Education only, like Paranoid's other Windows
  policies; on Home, Paranoid sets Microsoft's documented non-policy WER
  setting (`Windows Error Reporting\Disabled=1`) instead, measured on 26H2 Home
  to stop report creation and upload. Paranoid also sets `WerSvc` back to its
  Windows default, Manual,
  because a disabled service kept .NET crashes hanging even with the policy.
  Sessions saved by earlier builds still restore `WerSvc` (build of
  2026-10-09).
- Privacy documentation now says that Strict and Paranoid disable
  `dmwappushservice`, without which Microsoft documents that Intune cannot sync,
  and that neither app-removal tier removes the merged Copilot app that
  Microsoft Edge Update installs as a desktop program (build of 2026-10-09).

### Compatibility

- Requires native x64 Windows 11 24H2, 25H2 or explicitly identified 26H2 and
  64-bit Windows PowerShell 5.1. ARM64, 26H1 and unrecognized builds are rejected.
- Valid sealed 2.2.5+ backups keep their original restore readers without
  migration. Use the retained [2.2.4 release](https://github.com/NexusOne23/noid-privacy/releases/tag/v2.2.4)
  for backups created by 2.2.4 or earlier.
- Exact configuration Restore cannot recover deleted Recall snapshots or app
  data; app reinstallation remains a separate best-effort action.

## [2.2.5] - 2026-08-08

Exact BAVR v2, safer two-tier app removal, current Windows privacy controls
and a verification-accuracy overhaul across all seven modules. The detailed
engineering changes, provenance and validation history remain in
[Release Notes 2.2.5](Docs/RELEASE-NOTES-2.2.5.md).

### Breaking

- Backups from 2.2.4 and earlier are intentionally rejected before mutation.
  Restore those sessions with the permanently available matching 2.2.4
  release, then create a fresh v2 backup. There is no lossy converter.
- BAVR v2 seals target identity, exact prestate, type, ownership, user context
  and hashes before Apply. Restore returns the recorded prestate rather than a
  guessed Windows default and is itself verified.

### Highlights

- The seven-module inventory is a stable 699 targets, and the verified scope
  follows the chosen Privacy profile — 645 for MSRecommended, 670 for Strict,
  699 for Paranoid — instead of inventing states for unselected profiles.
  Passed, Failed, NotChecked and NotApplicable stay distinct, and every
  NotChecked entry says why: `BY CHOICE`, `NO SAVED CHOICE` or `CANNOT VERIFY`.
- The 425-target Microsoft Security Baseline uses one safety-reviewed BAVR path
  on Windows 11 24H2 and 25H2. An explicitly identified 26H2 preview can run the
  same full lifecycle only as Experimental; it is not release-approved.
- Native Windows x64 (AMD64/x86-64) is the supported architecture. The
  prerequisite and installer gates reject Windows on Arm (ARM64) before any
  hardening mutation instead of treating x64 emulation as product support.
- Privacy restores the visible interactive-user preference layer without
  claiming managed-policy effectiveness: preferences bind to the actual
  Explorer user's limited token with live Search-surface notification, so a
  separate elevation account cannot receive them by mistake. MSRecommended and
  Strict keep useful local search history while disabling selected web/Bing
  surfaces; Paranoid also disables local device-search history. Unsupported
  Home policies report as NotApplicable.
- Encrypted DNS now seals effective resolver state and Windows' native
  per-adapter-family DoH state separately. IPv4 and IPv6 encrypted labels,
  fallback policy, verification and exact Restore share the same decision and
  BAVR session.
- Tier 1 policy removal and Tier 2 per-user removal are separate, explicit and
  off by default. Both use exact package identities, include Microsoft Copilot
  in their curated choices and keep Weather/Widgets separate. Policy prestate
  restores exactly; removed apps and personal app data remain honestly
  best-effort recovery.
- Current documented Edge privacy controls, modern Windows AI controls,
  corrected Setting Sync semantics and supported 24H2 applicability replace
  undocumented, inert or overclaimed registry writes from earlier builds.
- Nine GUI quick actions consume the same sealed Engine lifecycle as full
  module runs. Overlap detection prevents an older module restore from silently
  undoing a newer quick action.
- Schemas, target counts, dependencies and provenance are machine-checked
  fail-closed; partial backup artifacts are kept for diagnosis, never
  misrepresented as restorable sessions.
- Standalone verification measures the live state of all seven modules and
  reports one verdict for the selected Privacy profile. The HTML report keeps
  each module's evidence in searchable, collapsible rows and prints either a
  compact summary or the full evidence. Without a trusted Apply decision
  Privacy is reported incomplete rather than guessed, and deleting backups
  cannot change the measurement.
- Exact rollback survives later maintenance: every sealed artifact is validated
  against its own schema, Quick Action restores are ordered per target, and an
  interrupted Restore can be repeated safely.
- Explicit non-interactive config paths, required decisions and `-Module All`
  fail closed when incomplete; no missing input can silently become a
  destructive default or a smaller successful scope.

### Security and compatibility

- Apply mutates only the sealed target plan, repeated Apply/Restore remain
  deterministic, and reports encode untrusted system text before rendering.
- Standard-user elevation remains an explicit, exactly restorable system-wide
  choice: Strict denies automatically (`0`), while SecureDesktop permits
  separate administrator credentials on the secure desktop (`1`). The selected
  behavior is no longer inferred from whichever account happens to run Apply.
- Neutral Allow writes, wildcard app deletion, hosts/region-file manipulation,
  the false DHCP-DNS override, OS-owned SRP mutations and WDigest stay removed.
  New runs also omit Windows PowerShell 2.0, which current supported Windows
  images no longer expose; legacy sealed artifacts retain a constrained
  compatibility reader.
- Exact PFN catalogs, bounded recovery processes, immutable-pinned CI actions,
  safe installer extraction and source-pinned recovery routes replace guessed
  identities and unbounded helpers.
- ConfigMgr detection for the PSExec/WMI ASR rule now treats an installed
  `CcmExec` service registration as authoritative even while it is stopped
  (the client can start later and would then conflict with the Block rule),
  and a failed inspection aborts a `-Force` run instead of silently assuming
  absence. The undocumented Edge value `CopilotCDPPageContext` was replaced by
  the documented successor policy `EdgeEntraCopilotPageContext` (Edge 130+).
- NoID Privacy 2.2.4 remains available solely for restoring its own backup
  format; 2.2.5 is the maintained Engine identity for this release line.

---

## [2.2.4] - 2026-03-24

**Enhancement Release.** Third-party security product detection for ASR module and verification.

### Added

**Third-party endpoint product detection ([#15](https://github.com/NexusOne23/noid-privacy/issues/15))**
- New: 3-layer detection function for third-party endpoint products. The layer reflects
  REGISTRATION MECHANISM, not product class:
  - Layer 1: WMI `SecurityCenter2` — products registered with Windows Security Center
    (consumer AV SKUs such as Bitdefender, Kaspersky, Avira, Norton, ESET often appear here)
  - Layer 2: Defender Passive Mode via `Get-MpComputerStatus` — products that put Defender
    into passive mode rather than registering with Security Center (enterprise EDR/XDR
    deployments such as CrowdStrike Falcon, SentinelOne often appear here)
  - Layer 3: 18 known service names for product display-name lookup on Layer-2 detections
- New: `Test-ThirdPartySecurityProduct` function in `Utils/Dependencies.ps1` (central, reusable)
- New: `Test-WindowsDefenderAvailable` now reports `IsPassiveMode` property
- ASR module gracefully skips when a third-party endpoint product is detected (`Success = $true`,
  not an error)
- Verify script reports ASR as "not verifiable" when a third-party endpoint product is the
  primary engine (ASR is a Defender-specific API; the compliance percentage reflects what
  was actually verified by NoID)
- Reported by: VM-Master

**Version Management**
- New: `VERSION` file as single source of truth for version numbers
- New: `Tools/Bump-Version.ps1` — automated version bump across all 61 project files
  - DryRun mode for preview, CHANGELOG.md excluded (historical entries preserved)

### Changed — files
- `Utils/Dependencies.ps1` — New `Test-ThirdPartySecurityProduct`, updated `Test-WindowsDefenderAvailable`, updated `Test-AllDependencies`
- `Modules/ASR/Public/Invoke-ASRRules.ps1` — 3-layer detection before Defender check, inline fallback for standalone mode
- `Tools/Verify-Complete-Hardening.ps1` — 3-layer detection, ASR verified as skipped when third-party product active
- `Tools/Bump-Version.ps1` — New file
- `VERSION` — New file

---

## [2.2.3] - 2026-03-05

**Bugfix Release.** Restore Mode crash fix and Recall snapshot storage verification fix.

### Fixed

**Restore Mode Module Selection Crash (Critical)**
- Fixed: Selecting `[M] Restore only SELECTED modules` and entering any module number caused a fatal PowerShell error
- Root cause: `.Split(',', ';', ' ')` triggered wrong .NET overload `Split(string, Int32)`, interpreting `;` as count parameter
- Fix: Replaced with native PowerShell `-split '[,; ]'` operator
- Impact: Manual module selection in Restore workflow now works correctly
- Reported by: KatCat2

**Recall Snapshot Storage Verification (Bug)**
- Fixed: "Maximum snapshot storage: 10 GB" verification always reported as failed
- Root cause: Microsoft's WindowsAI CSP stores snapshot storage in **MB**, not GB (e.g., `10240` = 10 GB)
- Fix: Updated expected values in config, apply, verify, and docs to use MB values
- Affected values: 10→10240, 25→25600, 50→51200, 75→76800, 100→102400, 150→153600, 0=OS default unchanged
- Reported by: VM-Master ([#14](https://github.com/NexusOne23/noid-privacy/issues/14))

---

## [2.2.2] - 2025-12-22

**Performance Release.** Major performance improvement for AdvancedSecurity firewall operations.

### Changed — performance

**Firewall Snapshot Performance Fix (Critical)**
- Fixed: Firewall rules backup took 60-120 seconds (especially in offline mode)
- Root cause: `Get-NetFirewallPortFilter` was called individually for each of ~300+ firewall rules (~200ms per call)
- Fix: Batch query approach - load all port filters once into hashtable, then fast lookup by InstanceID
- Result: **60-120 seconds → 2-5 seconds** (both online and offline)
- Affected files:
  - `Modules/AdvancedSecurity/Private/Backup-AdvancedSecuritySettings.ps1`
  - `Modules/AdvancedSecurity/Private/Disable-RiskyPorts.ps1`

### Changed

**Version Alignment**
- All 60+ framework files updated to v2.2.2
- Module manifests (.psd1), module loaders (.psm1), core scripts, utilities, tests, and documentation synchronized

---

## [2.2.1] - 2025-12-19

**Maintenance Release.** Critical bugfix for multi-run sessions and code review.

### Fixed

**Multi-Run Session Bug (Critical)**
- Fixed: Running framework multiple times in same PowerShell session caused `auditpol.exe` backup failures
- Root cause: `$global:BackupBasePath` was not reset between runs, causing auditpol to fail with "file exists" error
- Fix: Global backup variables (`BackupBasePath`, `BackupIndex`, `NewlyCreatedKeys`, `SessionManifest`, `CurrentModule`) are now reset at script start in `NoIDPrivacy.ps1`
- Impact: Users can now run individual modules, then "Apply All", then individual modules again without errors

**`.Count` Property Bug (5 files)**
- Fixed: `.Count` property failed on single-object results from `Where-Object`
- Affected files: `Invoke-ASRRules.ps1`, `Framework.ps1`, `Test-AdvancedSecurity.ps1`, `Test-DiscoveryProtocolsSecurity.ps1`, `Restore-DNSSettings.ps1`
- Fix: Wrapped results in `@()` to ensure array type

### Changed

**ASR Prompt Text Improved**
- Changed "untrusted software" to "new software" in ASR prevalence rule prompt
- More neutral language - the software isn't necessarily untrusted, just new/unknown to Microsoft's reputation system

**Code Quality**
- Full codebase review of backup/restore system (2970 lines in `Core/Rollback.ps1`)
- Wireless Display (Miracast) security implementation verified against Microsoft documentation
- All 7 registry policies confirmed correct per MS Policy CSP docs
- Version numbers aligned across all 50+ files

---

## [2.2.0] - 2025-12-08

**Enhanced Framework - 630+ Settings.** Major update with expanded AI lockdown, improved privacy coverage, and ASR quick-toggle fix.

---

### Highlights

- **630+ Settings** - Expanded from 580+ (Privacy, AntiAI, EdgeHardening, AdvSec Wireless Display)
- **NonInteractive Mode** - Full GUI integration via config.json
- **Third-Party AV Support** - Automatic detection, graceful ASR skip
- **AntiAI Enhanced** - 32 policies (was 24), Recall Export Block, Edge Copilot disabled
- **Pre-Framework ASR Snapshot** - Preserves rule state before multi-module runs
- **Smart Registry Backup** - JSON fallback for protected keys
- **Critical Bugfixes** - ASR Quick-Toggle, NonInteractive strict-mode, DNS offline

### Added

**NonInteractive Mode (GUI Integration)**
- Complete `config.json` support for automated execution
- All 7 modules fully configurable without prompts when values are provided in `config.json`
- Enables GUI-driven hardening in non-interactive mode (no Read-Host prompts)

**Pre-Framework ASR Snapshot**
- Captures all 19 ASR rules before multi-module runs
- Ensures original system state is preserved
- Prevents ASR rule loss during complex operations

**AntiAI Module Enhancements (24 → 32 policies)**
- Recall Export Block (prevents snapshot export)
- Advanced Copilot Blocks (URI handlers, Edge sidebar)
- Improved Edge Copilot sidebar disable (5 additional policies)
- Hardware Copilot key remapped to Notepad
- CapabilityAccessManager AI blocking

**AdvancedSecurity: Wireless Display / Miracast Hardening**
- New Wireless Display security available in all AdvancedSecurity profiles (Balanced/Enterprise/Maximum)
- Default: Block receiving projections and require PIN for incoming connections
- Optional: Complete disable (blocks sending projections, mDNS discovery, ports 7236/7250, and Wi-Fi Direct adapters)

**AdvancedSecurity: Discovery Protocols Security (Maximum profile)**
- Optional WS-Discovery + mDNS complete disable
- Blocks automatic device discovery (printers, TVs, scanners)
- Firewall rules for UDP 3702 (WS-Discovery) and UDP 5353 (mDNS)
- Prevents network mapping and mDNS spoofing attacks

**AdvancedSecurity: IPv6 Disable (Maximum profile - mitm6 mitigation)**
- Optional complete IPv6 disable (DisabledComponents = 0xFF)
- Prevents mitm6 attacks (DHCPv6 spoofing → DNS takeover → NTLM relay)
- Defense-in-depth (WPAD already disabled by framework)
- Recommended for air-gapped/standalone systems

**Privacy Module Expansion (55+ → 78 settings)**
- Cloud Clipboard toggle (user-configurable)
- Enhanced compliance verification
- Improved bloatware detection
- Better OneDrive sync compatibility

**Third-Party Antivirus Detection**
- Automatic detection of Kaspersky, Norton, Bitdefender, etc.
- ASR module gracefully skipped when 3rd-party AV active
- Clear user notification explaining why
- All other modules continue normally (614 settings)

**Smart Registry Backup System**
- JSON fallback for protected system keys
- Handles access-denied scenarios gracefully
- Empty marker files for non-existent keys
- Improved restore reliability

**Documentation**
- AV Compatibility section: "Designed for Microsoft Defender – Works with Any Antivirus"
- Clear 633 vs 614 explanation for Defender vs. 3rd-party AV setups
- Improved troubleshooting guides

### Fixed

**ASR Quick-Toggle Bug (Critical)**
- Fixed: Quick-toggling ASR rules caused 3 advanced rules to disappear
- Affected rules: Safe Mode Reboot, Copied System Tools, Webshell Creation
- Root cause: `Set-MpPreference` was called with single rule instead of full rule set
- Fix: Now reads existing rules, updates target, writes complete set back

**NonInteractive Strict-Mode Error**
- Fixed fatal error when dot-sourcing `NonInteractive.ps1` in GUI context
- Safe check for `$global:NonInteractiveMode` variable

**Registry Backup Protected Keys**
- Enhanced JSON fallback for protected system keys
- Prevents backup failures on restricted registry paths
- Creates marker files for rollback tracking

**DNS Offline Handling**
- Graceful handling when system temporarily offline during DNS test
- Configuration proceeds and activates when connection restored

**Module Progress Feedback**
- Improved status messages during long operations
- No more "stuck at 95%" feeling

### Changed — overview

| Component | v2.1.0 | v2.2.0 |
|-----------|--------|--------|
| Total Settings | 580+ | **633** |
| AntiAI Policies | 24 | **32** |
| Privacy Settings | 55+ | **78** |
| NonInteractive Mode | no | yes |
| 3rd-Party AV Detection | no | yes |
| Pre-Framework ASR Snapshot | no | yes |
| Smart Registry Backup | Basic | **JSON Fallback** |

---

## [2.1.0] - 2025-11-23

**Production Release - Complete Windows 11 Security Framework**

**Historical v2.1.0 release description:** the project was presented as complete at that time. Later releases tightened BAVR and applicability substantially.

---

### Highlights

- **All 7 Modules Initially Marked Implemented** - Historical release status; not a current readiness certification
- **Zero-Day Protection** - CVE-2025-9491 mitigation (SRP .lnk protection)
- **BAVR Coverage** - All settings applied by NoID can be backed up, applied, verified, and restored (some bloatware removals on certain Windows editions are intentionally not auto-reinstallable — manual reinstall via Microsoft Store)
- **Professional Code Quality** - All lint warnings resolved, comprehensive error handling
- **Zero Tracking** - No cookies, no analytics, no telemetry (we practice what we preach)

### Added — complete framework

#### All 7 Security Modules

**SecurityBaseline** (425 settings) - Microsoft Security Baseline for Windows 11 25H2
- 335 Registry policies (Computer + User Configuration)
- 67 Security Template settings (Password Policy, Account Lockout, User Rights, Security Options)
- 23 Advanced Audit policies (Complete security event logging)
- Credential Guard (Enterprise/Education only), BitLocker policies, VBS & HVCI
- No LGPO.exe dependency (100% native PowerShell)

**ASR** (19 rules) - Attack Surface Reduction
- 17 Block + 2 Configurable (PSExec/WMI + New/Unknown Software)
- Blocks ransomware, macros, exploits, credential theft
- Office/Adobe/Email protection
- ConfigMgr detection for compatibility

**DNS** (5 checks) - Secure DNS with DoH encryption
- 3 providers: Quad9 (default), Cloudflare, AdGuard
- REQUIRE mode (no unencrypted fallback) or ALLOW mode (VPN-friendly)
- IPv4 + IPv6 dual-stack support
- DNSSEC validation

**Privacy** (55+ settings) - Telemetry & Privacy Hardening
- 3 operating modes: MSRecommended (default), Strict, Paranoid
- Telemetry minimized to Security-Essential level
- Bloatware removal with auto-restore via winget (policy-based on 25H2+ Ent/Edu)
- OneDrive telemetry off (sync functional)
- App permissions default-deny

**AntiAI** (24 policies) - AI Lockdown
- Generative AI Master Switch (blocks ALL AI models system-wide)
- Windows Recall (complete deactivation + component protection)
- Windows Copilot (system-wide disabled + hardware key remapped)
- Click to Do, Paint AI, Notepad AI, Settings Agent - all disabled

**EdgeHardening** (24 policies) - Microsoft Edge Security Baseline
- SmartScreen enforced, Tracking Prevention strict
- SSL/TLS hardening, Extension security
- IE Mode restrictions
- Native PowerShell implementation (no LGPO.exe)

**AdvancedSecurity** (50 settings) - Beyond Microsoft Baseline
- **SRP .lnk Protection (CVE-2025-9491)** - Zero-day mitigation for ClickFix malware
- **RDP Hardening** - Disabled by default, TLS + NLA enforced
- **Legacy Protocol Blocking** - SMBv1, NetBIOS, LLMNR, WPAD, PowerShell v2
- **TLS Hardening** - 1.0/1.1 OFF, 1.2/1.3 ON
- **Windows Update** - 3 GUI-equivalent settings (interactive configuration)
- **Finger Protocol** - Blocked (ClickFix malware protection)

#### Core Features

**Complete BAVR Pattern (Backup-Apply-Verify-Restore)**
- All 580+ settings now fully verified in `Verify-Complete-Hardening.ps1`
- EdgeHardening: 20 verification checks added
- AdvancedSecurity: 44 verification checks added
- 100% coverage achieved (was 89.4%)

**Bloatware Removal & Restore**
- `REMOVED_APPS_LIST.txt` created in backup folder with reinstall instructions
- `REMOVED_APPS_WINGET.json` metadata enables automatic reinstallation via `winget`
- Session restore attempts auto-restore first, falls back to manual Microsoft Store reinstall
- Policy-based removal for Windows 11 25H2+ Ent/Edu editions

**Documentation & Repository**
- **FEATURES.md** - Complete settings reference
- **SECURITY-ANALYSIS.md** - Home user impact analysis
- **README.md** - Professional restructure with improved visual hierarchy
- **CHANGELOG.md** - Comprehensive release history
- **.gitignore** - Clean repository (ignores Logs/, Backups/, Reports/)

---

### Fixed — critical bugfixes

**DNS Module Crash (CRITICAL)**
- Fixed `System.Object[]` to `System.Int32` type conversion error in `Get-PhysicalAdapters`
- Removed unary comma operator causing DNS configuration failure
- Prevents complete DNS module failure on certain network configurations

**Bloatware Count Accuracy**
- Corrected misleading console output showing "2 apps removed" instead of actual count
- Fixed pipeline contamination from `Register-Backup` output in `Remove-Bloatware.ps1`
- Now shows accurate count (e.g., "14 apps removed")

**Restore Logging System**
- Implemented dedicated `RESTORE_Session_XXXXXX_timestamp.log` file
- Captures all restore activities from A-Z with detailed logging
- Fixed empty `Message` parameter validation errors in `Write-RestoreLog`

**User Selection Logs**
- Moved user selection messages from INFO to DEBUG (cleaner console output)
- Affects: Privacy mode selection, DNS provider selection, ASR mode selection
- Console now shows only critical information, detailed logs in log file

**Code Quality & Linting**
- Removed all unused variables (`$isAdmin` in `Invoke-AdvancedSecurity.ps1`)
- Fixed PSScriptAnalyzer warnings across entire project
- Resolved double backslash escaping in documentation paths

**Terminal Services GPO Cleanup**
- Enhanced GPO cleanup with explicit value removal
- Improved restore consistency for Terminal Services registry keys
- Cosmetic variance only (no functional impact)

**Temporary File Leaks**
- SecurityBaseline: Added `finally` blocks to prevent temp file pollution
- Ensures cleanup of `secedit.exe` temp files even on errors
- Prevents TEMP folder accumulation

---

### Changed — overview

**Framework Completion**
- Historical status: **7/7 modules implemented**
- Total Settings: **580+** (was 521)
- BAVR Coverage: **100%** (was 89.4%)
- Verification: **EdgeHardening** (20 checks) + **AdvancedSecurity** (44 checks) added

**Module Structure**
- All 7 modules now use consistent `/Config/` folder structure
- ASR: `Data/` → `Config/`
- EdgeHardening: `ParsedSettings/` → `Config/`

**Documentation Improvements**
- README: Professional restructure, improved navigation
- Added "Why NoID Privacy?" section (Security ↔ Privacy connection)
- Added "Our Privacy Promise" section (Zero tracking)
- Fixed all inconsistent list formatting (trailing spaces → proper bullets)

**Restore System**
- Production tested with full apply-restore cycle verification
- Restores to clean baseline state
- AdvancedSecurity: Verified restoration of registry/services/firewall settings

---

### Breaking

**License Change**
- **MIT (v1.x) → GPL v3.0 (v2.x+)**
- Reason: Complete rewrite from scratch (100% new codebase)
- Impact: Derivatives must comply with GPL v3.0 copyleft requirements
- Note: v1.8.x releases remain under MIT license (unchanged)
- **Dual-Licensing:** Commercial licenses available for closed-source use

---

### Changed — before/after comparison

**Before v2.1.0:**
```
Modules:             5/7 (71%)
Settings:            521
BAVR Coverage:       89.4%
Restore Accuracy:    Unknown
Code Quality:        Lint warnings present
Temp File Cleanup:   Partial
```

**After v2.1.0:**
```
Modules:             7/7 (100%)
Settings:            580+
BAVR Coverage:       100%
Restore:             Verified (full cycle)
Code Quality:        PSScriptAnalyzer reported clean for that release
Temp File Cleanup:   Complete
```

---

## Additional Resources

- **Full Documentation:** See [README.md](README.md) and [FEATURES.md](Docs/FEATURES.md)
- **Security Analysis:** See [SECURITY-ANALYSIS.md](Docs/SECURITY-ANALYSIS.md)
- **Bug Reports:** [GitHub Issues](https://github.com/NexusOne23/noid-privacy/issues)
- **Discussions:** [GitHub Discussions](https://github.com/NexusOne23/noid-privacy/discussions)

---

**Made with 🛡️ for the Windows Security Community**
