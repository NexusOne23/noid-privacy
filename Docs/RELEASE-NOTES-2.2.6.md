# Release Notes — v2.2.6 (2026-09-30)

NoID Privacy 2.2.6 adds full Windows 11 26H2 support, adopts Microsoft's
Windows 11 v26H2 security baseline, updates Microsoft Edge hardening to the v151
security baseline and hardens Backup, Apply, Verify and
Restore (BAVR) across all seven modules. Windows 11 24H2, 25H2 and 26H2 are
all supported releases and share one product contract; per-target
applicability and runtime evidence stay explicit on each of them. The [CHANGELOG](../CHANGELOG.md) carries
the short summary.

## Windows 11 26H2

- Windows 11 26H2 is supported exactly like 24H2 and 25H2. Windows 11 x64
  clients that report `DisplayVersion=26H2` in build family `26300..27999`
  run the normal Backup → Apply → Verify/HTML → exact Restore lifecycle. A missing or mismatched DisplayVersion, 26H1, ARM64 and future
  build families remain rejected before any change.
- SecurityBaseline is derived from Microsoft's Windows 11 v26H2 Security
  Baseline v2, published in the Security Compliance Toolkit on 2026-10-08
  (1,328,685 bytes, SHA-256 `369f8dad…5d18`). It replaced Microsoft's first
  26H2 package of 2026-09-29, which earlier 2.2.6 builds used. The same
  425-target profile runs on 24H2, 25H2 and 26H2. Against the 25H2 source it
  changes two targets: WinINet/IE mode allows TLS 1.2 and TLS 1.3
  (`SecureProtocols` 2560 → 10240), and Windows Ready Print driver ranking is
  enabled. Printers that
  are installed through an IPP-capable connection then use Windows' inbox IPP
  class driver; directly added TCP/IP and non-IPP printers are unchanged.
  Windows creates the `DriverRanking` policy key with read-only access for
  administrators; SecurityBaseline writes and restores that value through
  backup/restore key access (`SeRestorePrivilege`) and leaves the key's
  permissions unchanged.
- Every registry target was matched against the policy definitions shipped in
  Windows 11 26H2: none requires a release newer than 24H2. Sessions sealed by
  2.2.5 and earlier 2.2.6 builds keep restoring their recorded values exactly.
  [SecurityBaseline provenance](SECURITY-BASELINE-PROVENANCE.md) records the
  package, the comparison and the carry-back review.

## Registry and scheduled-task races

- A SecurityBaseline Apply on Windows 11 26H2 could stop during backup with
  "No more data is available" shortly after Windows setup, before any change.
  Cause: for a registry key that does not exist, PowerShell's registry
  provider (`Test-Path -PathType Container`, `New-Item -Force`) enumerates the
  deepest existing parent key. When Windows creates or deletes other keys under
  that parent at the same moment, the enumeration fails. The same race exists
  on every Windows release and in every module.
- All modules, the restore engine and the verifier now use two shared helpers
  that check and create registry keys with single native calls
  (`RegOpenKeyEx`/`RegCreateKeyEx`), avoiding sibling-key enumeration.
  Backup formats and restore semantics are unchanged.
- Privacy Tier 2 app removal could fail with "The system cannot find the file
  specified" when another program created or deleted a scheduled task at that
  moment.
  `Get-ScheduledTask` and `Unregister-ScheduledTask` resolve a task name by
  enumerating every registered task, also in a dedicated folder, and the
  enumeration can fail when any task disappears meanwhile. Direct lookup
  through the Task Scheduler interface avoids that enumeration.
- The short-lived user tasks for app removal, Windows Search and WinINet are
  now polled and deleted directly by name through the Task Scheduler interface.
  Task inventories in backup, Apply, Restore and verification repeat an
  enumeration that a concurrent deletion interrupted, up to five times.

## AntiAI and WindowsAI agents

The build of 8 October 2026 brings AntiAI in line with Microsoft's current
Windows AI policy set. It was checked against the WindowsAI Policy CSP
(revision of 23 September 2026), the official 24H2, 25H2 and 26H2
Administrative Templates and the policy names that the 25H2 and 26H2 system
binaries actually read. See [Windows AI applicability](WINDOWS-AI-APPLICABILITY.md).

- AntiAI declares 50 registry targets plus four URI source checks; earlier
  2.2.6 builds declared 43.
- Windows app access to text and image generation is denied through
  `LetAppsAccessSystemAIModels=2`, the AppPrivacy policy that Windows reads.
  `LetAppsAccessGenerativeAI` is in no Microsoft template and no Windows build
  reads it; AntiAI and Privacy Strict/Paranoid no longer write it.
- On explicit 26H2 Enterprise, Education and IoT Enterprise clients, AntiAI
  applies `ConfigureAgentConnectors=2` (Force Disable) and
  `AgentConsentDuration=1`. Microsoft removed `DisableAgentConnectors`,
  `DisableAgentWorkspaces`, `DisableRemoteAgentConnectors` and
  `AgentConnectorMinimumPolicy` from the CSP, and no template or Windows build
  contains them, so they are no longer written.
- `DisableRecallDataProviders=1` is written only on detected Windows Insider
  builds, the only applicability Microsoft documents.
- New: the Microsoft Copilot app cannot browse the web or let Cowork act on the
  user's behalf, and Microsoft Execution Containers, the Windows sandbox for AI
  agents, collect no diagnostic data. These machine policies are staged on
  every edition, whether or not the app is installed.
- New: on domain-joined or MDM-enrolled PCs, Copilot cannot be installed through
  Microsoft Edge Update. On other PCs Edge Update reads none of its policies;
  tests on Home, Pro and Enterprise without a domain or MDM showed it ignoring
  the block and downloading the Copilot installer. AntiAI therefore reports the
  block as not applicable there. Microsoft offers no other control for those
  PCs; its pause value for the Copilot app merge has the same limit and expires
  on 1 December 2026.
- New: the Microsoft 365 Copilot app, which Windows starts in the background at
  every sign-in, and the Copilot app no longer start at sign-in. AntiAI turns
  off their startup tasks for the desktop user, the same as Settings > Apps >
  Startup, and only where the app is installed. You can turn them back on in
  Settings. Restoring this setting requires that user to be signed in.
- New Edge policies: cloud text prediction, AI tab organization, cloud autofill
  models, Microsoft Editor cloud proofing, Copilot Cowork browser actions and
  automatic Copilot/Bing/MSN sign-in linking are off. Microsoft marks most Edge
  Copilot/AI policies as not applying to profiles signed in with a personal
  Microsoft account on managed devices, and several apply only to work
  profiles.
- Actual Windows Insider (WindowsSelfHost) enrollment remains an independent
  signal; no release fabricates it. A 25H2 client without that enrollment
  leaves the agent controls untouched and reports them `NotApplicable`.
- All 21 headings of the current WindowsAI Policy CSP have an explicit
  include/exclude decision. `AgentConnectorAccessPolicy` stays excluded because
  Microsoft publishes no usable JSON schema, `OnDeviceRegistryLoggingLevel`
  only changes logging, `SetDataLossPreventionProvider` requires a
  provider-specific value, and the destructive `RemoveMicrosoftCopilotApp`
  remains a separate explicit Privacy choice.

### After installing the build of 8 October 2026

- New AntiAI backups use snapshot schema 5. Sessions saved by earlier 2.2.6
  builds and by 2.2.5 keep restoring exactly with their schema-4 reader.
- NoID Privacy never deletes values that another backup session owns. Values
  that an earlier 2.2.6 build wrote stay in place until you restore that
  session; current Windows builds ignore them.
- Until AntiAI is applied again, verification reports its checks as not proven
  with the reason "applied with an earlier policy list". Applying AntiAI again
  saves a plan for the current list.

## DNS (build of 8 October 2026)

- Restore no longer fails when an adapter used "On (automatic template)" in
  Windows Settings before Apply. Earlier 2.2.6 builds passed an empty template,
  Windows rejected it (error 12006) and DNS over HTTPS was left turned off.
  Settings made in Windows Settings now come back exactly, field by field in
  the Settings dialog.
- Restore also returns the registry state that Windows' DoH interfaces cannot
  recreate: built-in DoH list entries get no `Flags` value where they had none,
  the four entries added for AdGuard are removed completely, and the adapter's
  `DohInterfaceSettings` keys and template values match the backup. New DNS
  backups use schema 6.
- Sessions saved by earlier 2.2.6 builds restore the same settings with this
  build. Registry details those backups did not record can remain (measured on
  25H2 and 26H2): a `Flags` value of 0 on built-in DoH entries such as Quad9's,
  the empty keys of the four AdGuard entries under `DohWellKnownServers`, empty
  `InterfaceSpecificParameters\{adapter}\DohInterfaceSettings` keys (`Doh`,
  `Doh6`) of each managed adapter, and the stored template of an
  automatic-template entry. They hold no data or the value 0; the restored
  DNS servers, DoH registrations and adapter DoH state verify as before.
- Measured on 25H2 and 26H2 with the network on: in REQUIRE mode no lookup left
  the PC on port 53, also not for names that do not exist or while HTTPS to the
  provider was blocked; resolution then fails. In ALLOW mode existing names
  resolve over DNS over HTTPS, but Windows also sends the lookup unencrypted
  when DNS over HTTPS fails and for names that do not exist, for example typos.
  Windows Settings shows ALLOW endpoints as "Encrypted preferred".
- Restore rejects a backup whose adapter key names contain `/`, which the
  registry provider treats as a path separator, and reads the raw registry
  state and decides every restore step before its first write, so unsupported
  registry state can no longer leave DNS half restored (build of 9 October
  2026).
- Microsoft's DNS client policy is now called "Configure encrypted name
  resolution" and also covers DNS over TLS. NoID Privacy sets `DoHPolicy`
  (3 = encryption required, 2 = allowed) and DoH templates only; the new
  per-protocol values stay unset.

## SecurityBaseline v2 (build of 9 October 2026)

- Microsoft removed its first Windows 11 v26H2 Security Baseline package from
  the Download Center on 2026-10-07 and published v2 on 2026-10-08 "to reflect
  the general availability of Administrator protection". SecurityBaseline now
  uses v2.
- Parsed with the same tool, v2 differs from the first package in exactly one
  value: the security template sets *User Account Control: Behavior of the
  elevation prompt for administrators running with Administrator protection*
  to prompt for credentials on the secure desktop
  (`ConsentPromptBehaviorEnhancedAdmin=1`). All 336 registry values, the 23
  audit subcategories and every other template entry are identical. Nothing
  was removed, also not for PCs outside a domain.
- Windows already used credentials when the value was not set, so the prompt
  does not change. SecurityBaseline now sets the value explicitly: 1 for
  "PIN, password or Windows Hello" and "Classic User Account Control", 2 for
  "Yes/No confirmation". It counts as one more baseline target: 425
  SecurityBaseline targets.
- Verification expects the selected value. On a PC where only an earlier
  2.2.6 build applied SecurityBaseline, the value is not set and verification
  names this target until SecurityBaseline is applied again. 2.2.4 and 2.2.5
  set it from Microsoft's 25H2 baseline.

## Privacy (build of 9 October 2026)

- Paranoid turns Windows Error Reporting off with Microsoft's documented
  `DisableWindowsErrorReporting` policy (`Disabled=1`) instead of disabling the
  `WerSvc` service. Measured on 25H2 and 26H2 with earlier 2.2.6 builds: with
  `WerSvc` disabled, Windows still created error reports and sent them to
  Microsoft as soon as the PC was online, and a .NET program that crashed hung
  instead of closing. With the policy, a crash creates no report, a report
  queued before Apply is not sent, and the crashed program closes normally.
- Like Paranoid's other Windows policies, the new policy is applied on Pro,
  Enterprise and Education and is not applicable on Home or on PCs managed by
  a domain or MDM.
- On Home, Paranoid instead sets Microsoft's documented WER setting
  `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Disabled=1`, which
  is not a policy. Measured on 26H2 Home: without it, crash reports were created
  and uploaded (the server assigned buckets); with it, a crash created no
  report, also after a restart, a report queued before was not sent, and
  crashed programs closed normally. On Pro, Enterprise and Education this
  setting is not applicable because the policy applies there.
- Paranoid also sets `WerSvc` to its Windows default start type, Manual. With
  the service disabled, a crashed .NET program kept hanging even with the
  policy set (measured), so a PC on which an earlier build or another tool
  disabled `WerSvc` gets the default back. Restore returns the recorded start
  type, also for sessions saved by earlier builds. Paranoid declares 94 base
  targets (121 with the Tier 1 values).
- Checked in Windows Settings on 25H2 and 26H2 Home, Pro and Enterprise after a
  Paranoid Apply: app permissions, diagnostic data, the advertising ID,
  personalized offers, Bing and cloud search, clipboard history and Windows
  text and image generation are off and locked on Pro and Enterprise; personal
  preferences such as the website language list are off and can still be
  changed. After Restore every switch shows its previous state.
- The values behind "Recommendations and offers in Settings"
  (`SubscribedContent-338393/353694/353696Enabled`) are the ones Windows 26H2
  writes itself when that switch is turned off.
- Strict and Paranoid disable `dmwappushservice`; Microsoft documents that
  Intune cannot sync without it. Privacy leaves both services unchanged on
  domain- or MDM-managed PCs.
- Neither app-removal tier removes the merged Microsoft Copilot app that
  Microsoft Edge Update installs as a desktop program under
  `C:\Program Files (x86)\Microsoft\Copilot`; both tiers act only on Store
  packages.

## AdvancedSecurity (build of 9 October 2026)

- Windows Update's optional-updates policy is now written as the inbox
  `WindowsUpdate.admx` template defines it: `SetAllowOptionalContent=1`
  enables the policy and `AllowOptionalContent=3` selects "users can select
  which optional updates to receive". Earlier 2.2.6 builds wrote
  `SetAllowOptionalContent=3` without the choice value, a combination the
  template does not define; 2.2.5 did the same. On a PC hardened by such a
  build, verification names both values and asks to apply AdvancedSecurity
  again.
- The two legacy SRP `.lnk` path rules are no longer written. Measured on 25H2
  and 26H2, Windows never enforced them: the AppLocker/Smart App Control
  marker `HKLM\SYSTEM\CurrentControlSet\Control\Srp\Gp\RuleCount=2`
  turns SRP off. With the marker set to 0 and a restart, the same rules did
  block shortcuts in the two folders, so the rules themselves were correct.
- The complete Wireless Display disable no longer writes
  `AllowProjectionFromPC`, `AllowMdnsAdvertisement`, `AllowMdnsDiscovery`,
  `AllowProjectionFromPCOverInfrastructure` and
  `AllowProjectionToPCOverInfrastructure`. Windows' policy store maps no
  Group Policy registry value to them; Windows reads them only through MDM.
  The choice still disables the Wi-Fi Direct service and adapters and adds the
  Miracast firewall rules. The Wireless Display Quick Action does the same;
  re-enabling Wireless Display removes the five values left by earlier builds.
- Firewall Restore now also removes what `netsh advfirewall import` adds to
  the registry: empty `AuthorizedApplications` and `GloballyOpenPorts` keys
  under each profile and a `LogFilePath` value stored with a different type.
- New backups use schema 6. Sessions saved by earlier builds restore every
  value they recorded, including the SRP rules and the five Wireless Display
  values. AdvancedSecurity declares 48 checks in 13 areas (default total 647,
  Strict 672, verification scope 703).

## Microsoft Edge v151

- The official `Microsoft Edge v151 Security Baseline.zip` from Microsoft's
  Security Compliance Toolkit: 466,831 bytes, SHA-256
  `c8d1be7073a17a96fd1a5140fc68770068cc15497a27036b16d783d1e5c7a6ab`.
- Archive member `Microsoft Edge v151 Security Baseline/Documentation/MSFT-Edge-v151.PolicyRules`
  has SHA-256 `b19b1c2ae6bceb9eec4e2530798420d5a035e0b5b7540fdc0d0b1803fb414202`.
  All 24 Microsoft values match at exact key, name, type and data.
- New in this release: `ProcessIsolationEnabled=1`,
  `RendererAppContainerEnabled=1`, `NetworkServiceSandboxEnabled=1`,
  `BrowserCodeIntegritySetting=2` and `EnhanceSecurityMode=1`.
  `ApplicationBoundEncryptionEnabled=1`, the sixth control Microsoft
  highlighted for v151, was already included.
- The seven NoID Privacy privacy additions remain separately labelled.
  Automatic HTTPS is only recommended for evaluation by Microsoft and is not
  one of the 24 enforced values.
- The default profile selects 30 managed values; the extension block-all
  choice selects all 31. The four SmartScreen values and
  `BrowserCodeIntegritySetting` stay untouched without AD-domain or eligible
  MDM evidence.
- New Edge backups use snapshot schema 7. Schemas 4 and 5 stay bound to the
  23-value v2.2.5 inventory and schema 6 to its 26-value inventory; all three
  are restore-only.

## SecurityBaseline and Device Guard

- New applications configure LSA protection, Credential Guard and memory
  integrity without requesting new UEFI locks: the four source directives
  (`RunAsPPL` twice, `LsaCfgFlags`, `HypervisorEnforcedCodeIntegrity`) are
  applied as `2` instead of Microsoft's `1`. This keeps recovery inside
  Windows without an EFI/BIOS opt-out workflow, but omits firmware tamper
  persistence and reduces resistance to privileged reconfiguration. It is a
  fixed decision with no extra choice. Existing firmware locks are not
  removed. See [firmware and restart recovery](SECURITY-BASELINE-RECOVERY.md).
- The eight Device Guard options are processed through the native local Group
  Policy API. New sessions add `DeviceGuardGpo.json` and capture 20 additional
  local controls in the existing schema-4 registry snapshot before any policy
  Save. Restore first restores the recorded GPO values and this tool's editor
  registrations, then the recorded registry state. Foreign policies are
  preserved and a historical `Registry.pol` or GPO directory is never
  replaced.
- A protected, create-only machine-local supplement records the native Device
  Guard backend's first prestate before the first Apply. Historical 2.2.5+
  sessions without the new artifact use it to undo that backend before
  restoring their own recorded values. Later sessions and moved backup folders
  cannot replace the first record.
- Windows Home additionally configures VBS and memory integrity through
  Microsoft's documented local registry controls, keeping the baseline's
  `HVCIMATRequired=1` requirement. Existing lock values are preserved;
  nonzero or unfamiliar lock configurations block activation before any local
  write. Pro and Enterprise keep native policy processing.
- The native firewall policy-format version `WindowsFirewall\PolicyVersion`
  is left to Windows. New Backup, Apply and Verify plans exclude that one
  metadata entry and retain all real security directives: 335 registry
  targets and 425 baseline targets. Historical backups keep their recorded
  inventories.
- Within an `ASR,SecurityBaseline` Apply session, the explicit PSExec/WMI ASR
  choice takes precedence over the baseline's Audit default and over older
  saved intent. Restore never substitutes the requested action for the
  backup's recorded prestate. The noninteractive PSExec/WMI display now also
  respects `-AllowPSExecWMI`.
- `**delvals.` directives clear and restore exact native value names,
  including unnamed defaults, whitespace and literal `(default)` names; typed
  arrays keep their type through native writes.
- Security-template Backup, Apply, Restore and their verification exports check
  native exit codes and output files directly. Failed template Apply reports no
  applied settings. Imports accept only the complete owned account-policy and
  privilege inventory; indented or duplicate foreign sections are rejected
  before `secedit` starts.
- On a fresh Windows installation, opening a writable local GPO can create an
  eleven-byte `[General]` header before the first Save. SecurityBaseline accepts
  only that exact transition, with originally absent files and an empty loaded
  policy, and keeps every other concurrency check.

## Administrator protection choice

- Microsoft's Windows 11 26H2 baseline turns on Administrator protection
  (`TypeOfAdminApprovalMode=2`): an app gets administrator rights only for the
  approved task, in a separate hidden account, and every approval asks for
  PIN, password or Windows Hello. SecurityBaseline now asks how to approve,
  in the Shell and in the Pro GUI:
  - **PIN, password or Windows Hello** (default, Microsoft baseline):
    `ConsentPromptBehaviorEnhancedAdmin=1`, the credentials prompt.
  - **Yes/No confirmation**: Administrator protection stays on, and
    `ConsentPromptBehaviorEnhancedAdmin=2` selects Microsoft's documented
    consent prompt on the secure desktop. Malware still cannot elevate
    silently; someone at the unlocked PC can confirm without a password.
  - **Classic User Account Control**: `TypeOfAdminApprovalMode=1` for
    Hyper-V, WSL and developer tools that must run elevated, which Microsoft
    lists as reasons not to enable Administrator protection. This deviates
    from the baseline and keeps the baseline's Yes/No prompt for
    administrators; the Administrator protection prompt policy keeps
    Microsoft's value 1, which has no effect while protection is off.
- Microsoft's v2 baseline sets the prompt policy to 1. Backup seals its
  prestate with the security-template registry values, Apply writes the
  selected value through the security template, Verify checks it as its own
  target, and Restore returns it exactly, including an originally absent
  value. Windows activates a change after a restart.
- Administrator protection needs Windows update KB5120998 (August 2026) or
  later and starts after a restart; Microsoft's v2 baseline calls it generally
  available. Without the update, administrators keep the classic Yes/No prompt
  and elevated apps run in their own account, whichever choice is set.
  Checked on fully updated 25H2 and 26H2 test PCs: after Apply and a restart,
  "PIN, password or Windows Hello" asks for the password in the "Windows
  Security" dialog, "Yes/No confirmation" shows "Allow changes" and "Don't
  allow" there, and after Restore and a restart the classic User Account
  Control prompt returns.

## Remote UAC compatibility change

- SecurityBaseline now applies Microsoft's exact
  `LocalAccountTokenFilterPolicy=0` value on standalone/workgroup systems. The
  former implicit override to `1` and its public `-SkipStandaloneDelta`
  parameter have been removed.
- Upgrading a system hardened by 2.2.5 means the next SecurityBaseline Apply
  changes this value from `1` to `0`. A local administrator used through SMB,
  WMI, WinRM, Remote Registry, administrative shares or remote service control
  receives a filtered network token, so privileged operations can return
  **Access denied**. Local UAC dialogs and interactive RDP sessions are not
  affected.
- Workgroup environments that deliberately need full remote-administration
  tokens must own, restrict and document that exception outside the automatic
  425-target baseline. Existing sealed sessions continue to restore the exact
  recorded prestate, including an older value of `1` when that was the true
  prestate.

## Backup and restore compatibility

- The session contract remains sealed BAVR v2. Valid 2.2.5-or-newer sessions
  restore through their frozen target and schema readers; no backup is
  migrated or rewritten.
- The 2.2.4 boundary is unchanged: 2.2.4-and-older sessions are rejected before
  any change and need the matching
  [2.2.4 release](https://github.com/NexusOne23/noid-privacy/releases/tag/v2.2.4).
  No lossy converter exists.
- AntiAI's Recall policies have an irreversible data effect: disabling
  `AllowRecallEnablement` and enabling `DisableAIDataAnalysis` both delete
  existing Recall snapshots, and the former also removes the Recall component
  after restart. AntiAI states this before Apply. Exact registry Restore cannot
  recover those snapshots or automatically reinstall the component
  ([Microsoft's policy contract](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableaidataanalysis)).
- A process terminated during a later module backup no longer hides earlier
  sealed modules. One excluded preparation directory with its known writer
  filenames and exact manifest temporary files may remain; its contents are
  never read as snapshots, promoted or deleted, and only the canonical manifest
  grants restore scope. Discovery and Restore name the excluded module.
- A terminated receipt writer can leave
  `restore-receipt.json.<32 lowercase hex>.tmp` or `.replace-backup` beside a
  sealed backup. Restore tolerates only these reserved regular files up to
  65,536 bytes and never reads them as receipts.
- Partial restores follow the application order recorded in the session,
  including custom module orders. Restoring an earlier module that shares state
  with a later one requires including the later module: Privacy with
  SecurityBaseline (CloudContent), Privacy with AntiAI (AppPrivacy),
  SecurityBaseline with AntiAI (AppPrivacy) and AdvancedSecurity (Terminal
  Services), and Privacy with AdvancedSecurity when selected AppX package
  families overlap a saved firewall policy. The check runs before any change.
- Module names are compared case-insensitively in manifest validation, order
  checks, restore dispatch and saved-choice invalidation.
- Registry artifacts are validated section by section before native import;
  deletion directives and keys outside the sealed subtree are rejected.
  Multiline `REG_SZ` values restore through a separate hex-encoded import so
  `reg.exe` cannot drop or misinterpret their data.
- AntiAI accepts native `Byte[]` prestate as well as JSON-decoded integer
  arrays, so existing nonempty Binary values no longer stop Apply before backup
  sealing.
- Interactive partial Restore asks again when any selected module number is
  invalid; input such as `1,junk` no longer silently selects only module 1.

## AdvancedSecurity

- After creating a firewall rule, Apply checks the complete active rule up to
  five times, with two-second pauses between attempts, while Windows processes
  the policy change. Each attempt checks all filters, profiles and enforcement
  evidence again. A persistent mismatch still fails, and polling does not
  repeat policy writes or alter the backup or Restore contract.
- When Windows updates its generated app-package capability rules during
  Backup, AdvancedSecurity compares every firewall difference and takes the
  unsealed firewall backup again, up to three times per reconciliation. A
  changed ordinary rule, profile or global setting, or mixed drift, still
  stops Apply. Other managed settings are checked again before each retry.
  The final firewall comparison precedes sealing; after sealing, the manifest
  and artifact hashes are verified without reopening a live app-servicing
  comparison. Restore still imports and verifies the complete sealed policy,
  including for existing 2.2.5+ sessions. Rules created after that checkpoint,
  including rules for newly installed apps, are removed when absent from the
  saved policy; restoring firewall rules does not uninstall those apps.
- On a PC with no local Group Policy, Windows creates an empty metadata header
  when AdvancedSecurity first opens the native policy editor. This exact
  initialization no longer stops firewall Apply as concurrent policy drift.
  Existing policy, revisions, registrations and subsequent changes still
  trigger the original safety checks.
- Firewall verification reads the active firewall state: rules, filters,
  enforcement status, every covered profile and the separate app-package and
  security filters. Disabled profiles, suppressed local rules, a configured
  local-rule merge ban and blocks limited to one package or user group fail
  verification. Live and cached checks use the same evidence.
- Firewall Apply uses local GPO mirrors on supported commercial editions and
  local rules on Home, keeping complete local recovery copies in the existing
  WFW format. On Home, a configured local-rule merge ban (SecurityBaseline sets
  one for the Public profile) keeps those local rules from taking effect: the
  interactive prompt then recommends skipping the firewall layer, and a
  requested layer stops AdvancedSecurity before any change instead of failing
  verification after Apply. All owned GPO reconciliation uses `OpenLocalMachineGPO` with one
  native Save, preserves complete Windows rule data and unrelated policy, and
  stops on foreign name collisions or source drift. Recovery also works after
  Maximum disabled administrative shares. Removing the last owned GPO rule also
  removes its empty store metadata.
- The UPnP and Wireless Display Quick Actions read, create and remove their
  block rules where AdvancedSecurity keeps them: as local GPO mirrors on
  commercial editions and as local rules on Home. Previously the Quick Actions
  looked only at local rules, so after a profile with AdvancedSecurity on Pro,
  Enterprise or Education both showed "State unavailable" and could not be
  changed. Sessions record each rule's placement and Restore returns it;
  earlier Quick Action sessions keep restoring as local rules.
- Firewall Quick Actions check program, package, address, service, interface
  and security scopes as well as ports before accepting a rule as their own.
  Modified or foreign rules are left untouched. Read errors are reported as
  unavailable state rather than missing rules. The 16 rule identities,
  serialized Quick Action states and existing backup formats are unchanged.
- New backups record whether the firewall editor was registered for the local
  GPO's registry extension, and Restore returns that registration to the
  recorded state with a registration-only native Save. Previously, restoring
  AdvancedSecurity while SecurityBaseline's Device Guard policy was still
  present left the registration in `gpt.ini` after both modules were restored.
  A registration that remaining firewall policy, or other policy without
  another registry-extension registration, still needs is kept and logged.
  2.2.5 backups predate the mirrors and keep their restore path.
- Historical WFW exports remain restorable when Windows adds the disabled
  default `EnableAuditMode=0`; every other difference still fails.
- Shields Up verification requires an enabled Public profile with an inbound
  Block default and accepts Windows' profile-wide blocking as the replacement
  for ignored inbound rules only with confirmed IPv4/IPv6 blocks. Apply never
  enables a disabled profile implicitly.
- NetBIOS Restore survives connection changes, adapter renames and index
  changes while preserving the GUID-bound registry value. The firewall policy
  is restored before registry values.
- Unreadable registry state and incomplete domain-membership evidence stop
  the module before changes. The Windows Update configuration is validated and
  captured once before Backup; Apply and Verify use the captured object.
- Risky-service verification requires `Stopped`; all twelve feature results
  must be present and valid. The restart-required result survives a later
  partial failure. Temporary WinINet and firewall-hive directories are cleaned
  up only when this run created them.
- The per-user WinINet, Windows Search and app helpers get a least-privilege
  exchange folder: the signed-in user may create and change the result files
  but cannot delete, rename or replace the folder or add subfolders. The
  elevated side removes only the known files and the empty folder, never
  recursively, and rejects a reparse point.
- Every wait for a helper task, service state or Quick Action result is bounded
  by a monotonic timer instead of the adjustable wall clock, so a time-service
  correction during a run cannot end the wait early.

## ASR mode changes

- Apply and Restore notify the running Defender engine when ASR rules change.
  This also covers the baseline's overlapping rules and the Management Tools
  and New Software Quick Actions. Existing local rule preferences are preserved.
- An interrupted change is recovered before the next ASR Apply or Restore.
  Later changes are not overwritten. While recovery is pending, Quick Actions
  stay unavailable and the report does not mark ASR as passed.
- ASR Quick Actions require Defender to be active with real-time protection.
  Readable saved rules alone do not prove protection when Defender is disabled
  or another antivirus is the primary engine.

## DNS and Privacy

- ASR, DNS, Privacy, AdvancedSecurity and the restore engine read their UTF-8
  backup artifacts as UTF-8, so non-ASCII values such as adapter descriptions
  or task definitions restore exactly on Windows PowerShell 5.1.
- A rule in Defender's documented "Not configured" mode (`5`) is accepted as
  existing ASR state instead of blocking ASR Backup and Restore.
- Windows starting or stopping a Manual (demand/trigger-start) service between
  backup and Apply no longer aborts Privacy or AdvancedSecurity; the startup
  configuration must still match the backup.
- Privacy's Windows Search and app-removal helpers also run for accounts
  without a filtered token (UAC turned off, or the built-in Administrator
  without Admin Approval Mode), still bound to the exact user and session.

- DNS Restore resets automatic resolvers for the owned address family only; an
  IPv4 reset no longer erases an unowned IPv6 resolver list.
- Apply preflight, Edge and Privacy require one complete native Boolean
  domain-membership result. Unknown management state keeps Privacy Tier 1
  closed without excluding unrelated targets.
- Privacy registry, AppX-firewall and UCPD query errors fail closed instead of
  being treated as absent state. The Windows Search refresh check also detects
  created or deleted empty keys.
- MSRecommended is described precisely: it selects Required diagnostic data
  and preserves existing app-permission policies.
- Best-effort app recovery recognizes the original recorded app even when its
  Store mapping names a replacement package.

## App recovery

- Store app recovery checks the installed WinGet client first. When a client
  compatibility or certificate-pin error prevents installation, it updates
  Microsoft App Installer automatically from Microsoft's signed MSIX release
  and dependency archive, checked against pinned size and SHA-256 values, for
  the original user. It never disables certificate checks or downgrades a newer
  client. Successful local package re-registration avoids the Store and this
  update entirely.

## Xbox Quick Action

- The shared engine detects the Xbox app, Game Bar, Identity Provider and
  optional legacy Xbox components together with the four Xbox services,
  Xbox game-save task and supported game-recording policy. A partially enabled
  installation is reported as **Mixed** and can be switched either way.
- **Off** removes the six Xbox apps in Privacy's removal list for the desktop
  user and disables the Xbox services, task and supported recording policy.
  **On** enables these settings and recovers missing apps, trying local package
  registration before the Microsoft Store. Retired optional apps may remain
  absent. Shared Gaming Services, installed games and game-save folders are
  outside the action's direct targets; Store installation may bring required
  dependencies, and Xbox manages additional game prerequisites separately.
- Enabling Xbox removes only Xbox entries from an active native app-removal
  policy. The global policy and other app selections remain unchanged. Managed
  devices and unknown management ownership are refused before mutation.
- A real change records its configuration for **settings-only Restore**.
  App versions and deleted app data cannot be restored exactly. Restoring
  settings leaves installed apps unchanged and may therefore produce Mixed
  status. An already matching state creates no backup or app worker.
- Interrupted operations remain visible. Recovery rechecks the displayed
  settings before restoring them, refuses newer overlapping changes and never
  reports a failed app operation as successfully applied.
- Saved report choices change only for the affected Xbox settings. Other
  SecurityBaseline and Privacy checks retain their selected expectations;
  existing backup formats keep their original readers.

## User-level helper tasks

- Privacy, AdvancedSecurity and the Xbox Quick Action change some settings in
  the signed-in user's own account. A short-lived SYSTEM task starts these
  helpers with that user's limited token. Its task definition names the
  SHA-256 of the two staged input files, and it runs only the bytes it read and
  verified; changed input ends the task with result 13 before any token is
  used. The files are deleted through the handles that created them.
- Earlier 2.2.6 builds instead required that no other account could delete or
  re-permission items in `C:\ProgramData` or `C:\`, and stopped with "Hidden
  worker parent permits replacement by another principal" when other software
  had loosened those permissions. The system check now reports such an owner or
  grant as a warning with folder, account and right; see
  [Troubleshooting](TROUBLESHOOTING.md#warning-an-account-can-delete-or-replace-items-in-cprogramdata-or-c).
- When an AdvancedSecurity backup step fails, the module reports that failure
  without the misleading "Interactive Explorer user changed" follow-on error.

## Verification and reports

- One verdict vocabulary on every surface. The console, the HTML report and
  the Pro GUI call a check **passed**, **failed**, **by choice** or **not
  applicable**, and a module or complete run `PASSED` or `FAILED`
  (`NOT APPLICABLE` only for a module that has no supported target on the
  PC). A required check without evidence — no saved Apply choice, or runtime
  state that Windows did not report — is a failed check, shown as
  "not proven" beside measured mismatches, for example
  `58 passed; 647 failed (441 mismatched, 206 not proven); 0 by choice;
  7 not applicable (712 targets)`. The former `INCOMPLETE` verdict,
  "unproven" and the alternating "No Saved Choice" / "Excluded by Choice"
  card are gone: every report shows the same five cards (Verification Scope,
  Passed, Failed, By Choice, Not Applicable), filters and row badges use the
  same words, and not-proven rows name the missing evidence. A module that
  was never applied is reported as failed (not proven: module not applied);
  the Pro GUI presets, including Quick & Secure, apply all seven modules, so
  a complete verification after any preset can pass. The scoped verification
  right after an Apply still covers only the applied modules.
  `NOID_VERIFY_JSON` keeps its counters and `complete` flag.
- The **Windows protection at verification** summary lists all six features
  in one row on desktop-width reports and wraps to three or two columns on
  narrow windows and printouts.
- Verify and the HTML report include a compact **Windows protection at
  verification** summary. Passed setting checks establish configuration;
  running VBS, memory integrity, Credential Guard, Secure Launch and kernel
  stack protection are reported separately, and LSA protection uses evidence
  from the current boot. Unreadable or absent evidence is shown as such. See
  the [runtime and recovery contract](SECURITY-BASELINE-RECOVERY.md).
- Verification takes the shared mutation lock before reading saved decisions
  and Windows state.
- DNS verification uses exactly the adapters the DNS module backs up, applies
  and restores; virtual, tunnel and VPN adapters keep their own resolvers.
- Restoring the Device Guard policy waits for the Windows policy processing
  that its own GPO save requested before the recorded registry values are
  replayed. The restore summary names Windows Firewall and Device Guard
  policy among the settings that take full effect after a restart, because the
  running firewall service keeps its loaded profile policy until then.
- ASR reports cloud protection as enabled only for documented MAPS values and
  returns a terminal `Failed` status after an aborted preview, application or
  failed final metadata validation.
- AntiAI verification is bound to the 50 canonical target identities and their
  reviewed types and values; duplicate, overlapping, foreign or weakened checks
  are rejected.
- HTML detailed printing includes every evidence row regardless of on-screen
  search and status filters, and filters open collapsed sections that contain
  matches. Clearing both restores the previous expansion state.

## Offline use and message levels

- Without any network connection (no connected interface with a default
  route) every network-dependent step says so calmly as information:
  - DNS writes the selected provider and its encryption settings, verifies
    them exactly on this PC and notes that the provider could not be
    contacted; Windows uses it as soon as a network is connected.
  - Best-effort app recovery re-registers what it can locally and leaves apps
    that only the Microsoft Store can bring back for a later online run
    (status `NeedsNetwork`, not a failure).
  - The web installer stops with "no network connection; nothing was changed"
    before it touches the destination.
- With a network that does not reach the selected DNS provider (for example a
  hotel sign-in page or a network that blocks it), DNS still fails closed and
  changes nothing, now with a plain explanation instead of a raw Windows error
  and an empty stack-trace line.
- Warnings are reserved for something on this PC that needs attention. Static
  design notes, edition facts such as "not applicable on Windows Home",
  expected reboot notices, menu prompts and the user's own choices are shown as
  information. Warnings remain visible when the current PC needs attention.
- The interactive console speaks to people: no timestamps, levels or
  component names, no internal bookkeeping (backup paths, manifests, loader
  lists), no machine result line, and one result line per module during Apply
  and Restore. Notes worth reading are marked "[i]"; any warning is listed by
  name in the run summary under "Needs your attention" instead of a bare count
  and a pointer to the log. The GUI and automation keep the complete log
  records they parse, and every detail stays in the log files. Every section
  uses the same frame width, steps read "[n/m]" at the left margin, status and
  detail lines share a two-space indent, every module ends its check with
  "N passed, F failed, M not applicable", and every choice is confirmed in one
  line. Under the menu the framework no longer repeats its banner or the
  reboot note the menu shows itself. App recovery after a restore reports one
  result line ("15 of 15 app(s) are back") and lists only apps that still need
  attention; the full per-app record is in the log. Windows' per-package
  registration progress is no longer drawn, because Windows PowerShell left
  unfinished progress panes over the reboot prompt that followed.
- The HTML report's Failed card shows the total only; the split into
  mismatched and not proven appears once, in the compliance line under the
  bar. The "Windows protection at verification" features sit in one row of
  equal tiles whose labels never wrap, so their spacing no longer depends on
  the length of a feature name; the tile reads "Secure Launch".
- Declining a module at its prompt, or at the module's own confirmation, is
  reported as "skipped by your choice" and no longer turns the whole Apply
  into a failure; Verify still reports that module as not applied. The
  AntiAI prompt now states before confirmation that, on Pro and higher, the
  Recall policies delete existing Recall snapshots, which Restore cannot bring
  back.

## Installation

- The installer accepts `%ProgramFiles%\NoIDPrivacy` as a protected
  installation folder. The default `%USERPROFILE%\NoIDPrivacy` can be changed
  by any process of the signed-in user, while the scripts run elevated; shared
  or managed PCs should use the protected folder.
- Running `.\NoIDPrivacy.ps1` from an open PowerShell window no longer closes
  the window at the end. `-File`, `-Command` and embedded hosts still receive
  the documented exit codes.
- `Start-NoIDPrivacy.bat` is checked out with CRLF line endings, which cmd.exe
  needs for reliable label handling.

- The shell, interactive menu and standalone verifier require 64-bit Windows
  PowerShell 5.1 and stop before reading machine state on other hosts.
- The bootstrap installer reserves temporary paths exclusively, refuses an
  occupied destination and cleans up only paths it owns. Backups, Logs and
  Reports are kept on successful and failed upgrades.
- The release workflow passes tag inputs as environment values, so PowerShell
  syntax in an invalid tag is rejected without execution. Release publication
  pins `softprops/action-gh-release` 3.0.3 by commit.

## Point-in-time restore

- Microsoft's Windows 11 point-in-time restore is reviewed explicitly. It is
  not added as a guessed registry target: the supported configuration surface
  is Windows Settings or the `Recovery/PointInTimeRestore` CSP, and the feature
  is a full-system recovery decision rather than an exact NoID-owned policy.
- Microsoft documents default enablement for Home and unmanaged Pro, and that
  enterprise-managed systems remain default-off only until 26H2. Every
  default-on case also requires an OS volume of at least 200 GB; a smaller
  volume can still be enabled manually.
- Restore points are local VSS state and can include the OS, applications,
  settings, local files, passwords, certificates and keys. A restore can also
  revert recent security updates or NoID-owned policy state. After any restore,
  run a complete NoID verification and deliberately re-apply only if the
  restored posture is no longer the intended one.
- Local restore requires the BitLocker recovery key on encrypted volumes.
  Microsoft also documents that Recall is disabled after restoration while
  previously captured Recall snapshots remain; this does not replace AntiAI
  verification or delete those snapshots.

## Privacy and declared scope

- Strict/Paranoid already apply Microsoft's exact Pro+ settings-backup deny
  contract: `DisableSettingSync=2`, `DisableSettingSyncUserOverride=1`,
  `EnableWindowsBackup=0`. This covers the default-on backup behavior of
  eligible commercial 26H2 devices. MSRecommended preserves the user's or
  organization's existing state.
- Privacy owns the two cloud content search toggles `IsMSACloudSearchEnabled`
  and `IsAADCloudSearchEnabled` in every mode. Windows writes them as `0` while
  `AllowCloudSearch=0` is active and keeps them after that policy is removed;
  without ownership, Restore left cloud content search switched off. Sessions
  created by 2.2.5 did not record these toggles; after restoring such a
  session, re-enable cloud content search in Settings > Privacy & security >
  Search permissions if you used it.
- The Windows Search worker now allows up to 300 seconds for a slow first
  provider call after Privacy Restore, avoiding premature timeout failures.
- Tier 2 app removal logs each app's cause when it fails, and a removal error
  no longer fails an app that is verifiably absent within a bounded wait:
  Windows can remove the same package concurrently, for example through Tier
  1's policy. The elevated absence check remains the deciding postcondition.
- Search configuration uses the documented policy/preference and
  `Set-WindowsSearchSetting` state, including the consolidated web/Store-results
  surface. UI labels do not introduce additional registry targets.
- Declared default-decision total is now 647: 425 SecurityBaseline + 19 ASR + 5 DNS + 65 Privacy + 54 AntiAI + 31 EdgeHardening + 48 AdvancedSecurity. Strict is 672 and Paranoid is 703 (builds of 2026-10-08: 658, 683 and 712; the first 2.2.6 builds: 651, 676 and 705).
- Verification totals are stable: a complete verification always evaluates the
  whole 121-target Privacy inventory and therefore always reports 703 declared
  targets. Targets that only a stricter Privacy profile contains are shown as
  NotChecked "by choice" with the selected profile named, instead of changing
  the total between 647, 672 and 703. A missing saved Privacy choice or a
  failed Privacy check keeps the same 703-target total.
