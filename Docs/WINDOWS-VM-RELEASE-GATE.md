# Windows 11 release acceptance gate

This acceptance gate is run on disposable physical/VM Windows 11 clients before each public distribution; it records runtime evidence that cannot honestly be produced on Linux or a Windows Server CI runner.

## Required profiles

1. Windows 11 25H2, build family 26200, current cumulative update.
2. For Tier 1 only, a single-session standalone Enterprise or Education client. Also exercise Pro/Home to confirm all 27 identities remain untouched and report NotApplicable.
3. A separate-standard-user/separate-admin account setup and an everyday account that is already a local administrator.
4. The signed Pro GUI/installer built from the same engine tree, including an uninstall/reinstall cycle that preserves user data by default.

The complete seven-module matrix below is run on Windows 11 25H2 Home, Pro and Enterprise. SecurityBaseline uses the same 425-target profile and BAVR implementation on supported 24H2 and 25H2; 24H2 admission is based on the documented semantic comparison of both official Microsoft baselines, not a second profile, schema, user choice or release-gate branch. For an explicitly identified 26H2 Experimental preview, the product code permits full Backup, Apply, Verify/HTML and Restore for enabled, applicable targets, including the carried-forward 425-target baseline. That technical path is not runtime-validated or release-approved by this evidence set. A future 26H2 claim requires a separate clean-snapshot run of this complete gate against then-current Microsoft primary sources.

## Acceptance sequence

- Run the complete Pester suite and PSScriptAnalyzer with zero analyzer errors.
- Run `Tools/Test-PrivacyPolicyProvenance.ps1` against both the current release
  image's inbox ADMX files and the recorded official 24H2 V2 Administrative
  Templates. Preserve the package/file hashes and reject any semantic drift;
  registry readback alone cannot detect a wrong ADMX enabled/disabled value.
- If the self-hosted GitHub Actions gate is used, update its runner to version
  2.329.0 or newer before running the Node 24 checkout/upload actions.
- Run DryRun for all modules and confirm four-state reconciliation: Passed + Failed + NotChecked + NotApplicable = Declared.
- Run `Tests/Windows11/Invoke-Windows11BavrValidation.ps1` on a disposable client and preserve its JSON, NUnit/Pester XML and logs.
- For every applied module, require the scoped verifier export, GUI machine
  contract and generated HTML report to reconcile the same Passed, Failed,
  NotChecked and NotApplicable counts before restoring the sealed prestate.
- With a protected Privacy Apply choice, require exactly one console verdict
  for the selected profile. In HTML, require that profile only in `Declared
  Scope`, require every module summary to expand into its reconciled evidence
  rows, and reject the raw intent reference, a separate Privacy verdict card
  and all unselected-profile comparisons. The machine export retains all three
  scorecards for diagnostics. Without a trusted Apply choice, require Privacy
  and the overall console result to say `INCOMPLETE`; the HTML must omit a
  profile label instead of guessing one.
- Exercise the HTML result bar with a fully passed, partially failed,
  partially unresolved and all-failed fixture. Its denominator is exactly
  Passed + Failed + unresolved NotChecked: passed is green, failed is red and
  unresolved is yellow. Require an all-failed run to show 0%, never 100%; keep
  NotApplicable and proven deliberate exclusions visible in their count cards
  without treating either as failed or required live checks.
- Exercise all structured NotChecked dispositions: `BY CHOICE`, `NO SAVED
  CHOICE`, `CANNOT VERIFY`, and the neutral mixed `Settings Not Checked` aggregate. Require
  each category's `AffectedTargetCount` sum to equal its NotChecked counter;
  the compact no-intent Privacy row must visibly identify every target it
  represents.
- Capture an independent before/after/restore state for registry values, user hives, services, tasks, firewall rules, DNS, AppX packages and URI source hives.
- Apply, verify, restore in reverse sealed-manifest order, reboot/sign out where a policy requires it, then prove exact prestate for every exact-BAVR target.
- Prove layered module prestates explicitly: Apply all seven modules, capture the
  resulting covered-state fingerprint, then Apply ASR again in a distinct
  module session. Restore that newer ASR session first and require byte-/state-
  exact equality with the already-hardened state captured after Apply All;
  only then Restore the older All session and require equality with the
  original machine prestate. Repeat with an ASR choice that changes at least
  one owned target so the gate proves a real transition rather than a no-op.
- Confirm every intentional skip is NotChecked and every unsupported host target is NotApplicable; neither state may be counted green.

## High-risk focused checks

- Create disposable HKLM and HKU canary keys whose names include an interior
  `HKEY_USERS` segment. Exercise `ConvertTo-NativeRegistryPath`, `reg.exe export`,
  sealed artifact validation, `reg.exe import` and `ConvertFrom-NativeRegistryPath`.
  Prove the `.reg` header has one separator at every key boundary, the interior
  root-like name is unchanged, ambiguous doubled/forward/trailing separators are
  rejected before `reg.exe` starts, and the restored key is byte-equivalent.
- Produce the Tier 1 policy once through current `gpedit.msc` on 25H2 Enterprise/Education and diff the exact registry type/layout against `BloatwareRemovalPolicy.json`: current expected shape is root `Enabled`, an empty `DynamicRemovalList` REG_MULTI_SZ and 25 PFN-based `RemovePackage` DWORDs (27 values total). Reject symbolic CSP presentation IDs as registry subkeys and investigate any template drift before release.
- Exercise exact restore with both a current complete PFN snapshot and a genuine
  complete v2.2.5 symbolic-ID snapshot. Require the prestate to return byte- and
  type-exactly in both cases, reject partial/mixed contracts before mutation,
  and prove that only the PFN contract can be used by a new Apply/Verify plan.
- Confirm Tier 1 takes effect only at the documented provisioning/sign-in boundary and that the UI warning matches the observed device-wide/data-loss behavior. Confirm policy restore unblocks reprovisioning but does not claim app/data recovery.
- With Tier 2 selected, test absent apps, multiple exact package identities, inventory drift between Backup and Apply, one forced removal failure, missing winget, one unmapped app, one winget failure and a successful post-checked reinstall from the original standard user.
- Resolve every non-empty `StoreId` in `Bloatware-Map.json` on the release-date Microsoft Store catalog with `winget show --id <StoreId> --source msstore --exact --accept-source-agreements`. Record the returned product name and identifier, reject missing/redirected/wrong products, and confirm a test install registers one of that mapping's exact `ExpectedPackageNames`; empty IDs must remain explicit non-reinstallable skips.
- Run hardening by elevating with separate administrator credentials and prove all HKU, AppX and best-effort reinstall operations bind to the Explorer owner rather than the elevation account.
- Exercise the interactive Shell's Y/N UAC choice from both an administrator and a standard-user desktop, then exercise `ConsentPromptBehaviorUser=0` and `1` through explicit decisions while both account types exist. Prove that both Shell sessions receive the machine-wide choice, `1` gives the standard account a secure-desktop credential prompt, neither choice changes the administrator account's own prompt behavior, and restore reproduces the exact previous type/value/key state.
- Exercise Windows Firewall Control and at least two other controller products before and after selection. Confirm the prompt is authoritative, late installation warns, and skipped firewall targets are NotChecked in console, JSON, HTML and GUI.
- Validate the LAN-resolver DNS hint with ordinary router DHCP, explicit public DNS and a LAN filtering resolver; no branch may claim it detected custom router DNS.
- Run DNS once with ordinary dual-stack transport and once after setting the
  documented optional `DisabledComponents=0xFF` state **and restarting the
  disposable client**, as Microsoft requires before that registry change takes
  effect. Do not accept a value written in the current boot as proof that the
  live IPv6 transport is disabled. In the second case,
  require effective IPv6 DNS-client readback to remain outside transport scope
  while the binding-enabled adapter's exact native IPv6 resolver/DoH state is
  sealed, applied and shown as encrypted in Windows Settings. Verify/HTML must
  distinguish those scopes and must not claim active IPv6 traffic. Restore must
  reproduce the exact prior native properties, `Doh6`/`NameServer` registry
  existence, types and data; repeat Apply and Restore to prove idempotence.
  Test both a newly opened and already-open Settings page: the newly opened
  page must show all four encrypted labels, while a stale already-open page is
  documented as requiring close/reopen rather than a system restart.
  Restore the exact `DisabledComponents` prestate after the evidence run and
  restart once more before reusing the client, so both the registry and the
  effective network stack are back at their original state.
- Validate both Copilot URI handlers in HKLM Classes and the original user's HKU Classes with absent keys, values, subkeys and mixed machine/user ownership; restore must be byte-equivalent and must never operate through merged HKCR.
- On Home, Pro and Enterprise, validate every declared interactive-user
  preference through its visible Windows Settings/File Explorer surface where
  one exists, then prove exact typed Apply and Restore against the interactive
  Explorer owner's hive. Confirm MSRecommended/Strict leave the visible local
  device-search-history switch and its registry prestate unchanged, Paranoid
  turns it off, and every profile turns its selected global Web/Bing provider
  controls visibly off. Start the first profile from a visibly enabled
  Web/Bing prestate and require the live Search result surface to remove its
  Microsoft Bing tab and web suggestions immediately after Apply, not merely
  after a later profile or logon. In every mode, a local search for an
  installed app, a Settings page and an indexed local file must still return
  local results. Restore must reproduce both the exact typed registry prestate
  and its live Search-surface effect. The supported refresh combines Microsoft's
  `WM_SETTINGCHANGE` policy/Search-leaf broadcasts with
  `Set-WindowsSearchSetting -EnableWebResultsSetting` in the actual Explorer
  user's limited token. Require the worker to prove zero Search/SearchSettings
  registry delta and zero unrelated WindowsSearch API delta, and require the
  shared verifier/HTML row to show `EnableWebResultsSetting=False`. Killing
  Explorer/SearchHost, targeting a separate UAC credential account or accepting
  a stale result surface does not pass this gate.
- On 24H2 and 25H2, parse the inbox `SettingSync.admx` and require the exact
  `DisableSettingSync` enabled DWORD `2`, `DisableSettingSyncUserOverride=1`
  option and `EnableWindowsBackup` disabled DWORD `0` contract. On Pro and
  Enterprise, Strict/Paranoid must visibly disable the relevant Accounts >
  Windows backup controls and the periodic backup must not run; exact registry
  prestate must restore. Home must keep all three targets untouched and report
  them `NotApplicable`, not registry success.
  `Tools/Test-PrivacyPolicyProvenance.ps1` is the fail-closed machine gate for
  this semantic contract and must return `Success=true` on both release images.
- On 24H2 and 25H2, the same machine gate must also bind `messaging.admx`
  (`AllowMessageSync`, disabled DWORD `0`), `GroupPolicy.admx`
  (`EnableFontProviders`, disabled DWORD `0`) and `DeviceSetup.admx`
  (`DeviceMetadata_PreventDeviceMetadataFromNetwork`, enabled DWORD `1`) to
  their checked-in profile provenance. Strict/Paranoid must block cellular
  text-message cloud sync on Pro/Enterprise; Paranoid alone must disable online
  fonts and automatic device-metadata companion-app downloads. Home must keep
  all three targets untouched and report them `NotApplicable`. Verify and the
  HTML report must use the sealed target plan, and Restore must reproduce exact
  value/type/key absence or presence for each target.

## Pro GUI and installer checks

- Compare every wizard choice and advanced module option with the generated
  closed module-schema JSON, and compare every Quick Action with its separate
  closed action-schema contract. Run each profile, each module and each of the
  nine action scopes individually; no old option may be missing and no
  GUI-only option may be silently ignored.
- Prove that the firewall prompt is authoritative for every wizard profile and
  full Advanced module execution, and that its detection is only a prefill.
  Quick Actions must never invoke a full module or alter the full
  AdvancedSecurity firewall layer. Action-owned firewall targets may change
  only when they are explicitly present in that action's declared target IDs.
- Exercise the UAC choice from a real standard-user desktop elevated with
  separate administrator credentials, and from an everyday administrator
  account. The account used to start NoID Privacy Pro must not silently
  override the selected machine-wide decision: Quick & Secure and Balanced
  apply SecureDesktop `1`, High Security applies Strict `0`, and Custom applies
  its explicit current choice. Prove both values while both account types
  exist, and prove neither value changes an administrator account's own
  elevation-prompt behavior.
- Test Defender cloud unavailable for every ASR entry path: fail closed by default, continue only after explicit informed selection, and reflect all skipped rules as NotChecked rather than Applied.
- On every Quick Actions tab entry, prove all nine controls remain disabled
  until their authoritative Windows states pass the closed contract. Before
  confirmation, re-read the selected state; after acquiring the global
  mutation lock, reject any fingerprint drift without changing Windows.
- Verify each Quick Action changes only its declared target IDs, creates a
  uniquely named sealed action-scoped BAVR session, verifies the exact
  poststate, and refreshes all nine states after Apply, failure, cancellation
  and Restore. It must never run the owning module, reconcile unrelated module
  targets or mark that module Applied/Restored.
- Exercise both directions of all nine actions on a machine where no module
  has been applied. Prove RDP and UPnP are governed by live state rather than a
  saved profile, unknown/ambiguous states fail closed (especially encrypted
  DNS; SmartScreen requires the applied EnableSmartScreen policy pair), and
  overlapping action sessions restore only in reverse sealed order.
- For RDP, include `TermService`, `SessionEnv` and `UmRdpService` in the sealed
  target scope because Windows starts them as a side effect of enabling the
  host. Prove Disable stops them, Restore reproduces their exact runtime,
  startup and delayed-start prestate, and legacy v2.2.5 action sessions compare
  only through their original registry/firewall projection without expanding
  the old restore scope.
- Create valid, incomplete, empty, renamed, hidden, corrupt and reparse-point backup directories under every known engine root. The GUI must show every directory with name, session ID, date/status/modules/item count/path/reason, restore only sealed valid sessions, never follow a link for size/delete/restore, and never delete automatically.
- Upgrade an existing installation containing several valid, invalid and incomplete sessions plus Logs and Reports. Force one mid-upgrade failure and one old-program cleanup failure; prove all three runtime roots remain byte-identical and every backup directory stays listed after recovery/retry.
- Uninstall with the default choice and prove all backups, reports, logs, license and settings remain. Repeat with the explicit full-deletion choice and confirm its default is No and its warning names every deleted category.
- Validate the GUI's retained hardening-choice snapshot across restart. A
  damaged snapshot must fall back to closed allowed values and may never expand
  the module schema. Separately prove Quick Actions ignore that snapshot and
  derive their state only from the current authoritative Windows query.
- Run Apply → machine contract → Verify → sealed Restore for each module and all modules. Exercise cancellation and forced pre-Apply failure; captured incomplete artifacts must remain detached, visible and non-restorable.
- Test the Tier 2 reinstall button only from the original interactive user and confirm it is labelled best-effort, cannot be mistaken for exact Restore and never turns skips/failures into success.
- Build the signed self-contained package through `Build-Release.ps1` — that script is not part of this repository; it belongs to the signed Pro build, which consumes this engine tree — and verify Authenticode on EXE/installer/uninstaller, install without a preinstalled .NET runtime, and test upgrade/uninstall on 25H2 plus the supported 24H2 path. Do not infer 26H2 runtime approval from successful compilation or version recognition.
- Verify About and installer labels identify 24H2 and 25H2 as supported releases while keeping the runtime-evidence scope explicit. Any 26H2/26300–27999 path must remain explicitly Experimental and outside the current release-evidence claim; 26H1, future/Canary and mislabeled builds remain rejected.
- Repeat the full apply/verify/restore path across all nine supported UI
  languages. Confirm no decision parses localized command output or translated
  account/group/service/display names; Defender/third-party AV detection must
  agree across languages.
- Exercise Encrypted DNS as an action-scoped BAVR cycle after a DNS-module
  ALLOW Apply: switch to REQUIRE, prove all four global endpoint fallback
  flags and every applicable physical adapter/family native DoH property,
  including the binding-enabled IPv6 native family while its transport is
  disabled, restore
  the sealed action session exactly to ALLOW, then restore the owning DNS
  module session and compare the independent original/final DNS state.

## Release evidence record

Record OS edition, `DisplayVersion`, full build/UBR, framework commit, test result hashes and pass/fail outcome. Do not record real names, email addresses, machine names, device IDs or other personal/hardware identifiers in the repository.
