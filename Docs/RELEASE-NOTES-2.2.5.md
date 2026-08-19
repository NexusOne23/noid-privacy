# Release Notes — v2.2.5 (2026-08-08)

Full engineering detail for the 2.2.5 release. The [CHANGELOG](../CHANGELOG.md)
carries the user-facing summary; this document carries the complete record,
including the two dated validation passes that ran during the release cycle.

Scope note: this document follows the maintained 2.2.5 engine release line;
the immutable tag remains its historical publication point. Current counts and
support boundaries live in `Config/SettingsCounts.json`, the provenance
documents under `Docs/`, and the generated test artifacts.

---

### Maintenance hardening

- Parameterless verification now measures the complete live Windows state.
  When the protected atomic Apply record identifies the selected Privacy
  profile, the console names that profile's live VERIFIED, FAILED or INCOMPLETE
  verdict. The HTML names it only in `Verification Scope`, then presents searchable,
  collapsible per-module evidence. Unselected scorecards and their mismatch
  paths stay out of the human report and remain available only in the machine
  export; the raw intent timestamp is not exposed. If the record is absent,
  Privacy is explicitly incomplete and no profile is guessed. Backup sessions
  and shipped defaults never choose the target set or expected values.
- BAVR restore uses the sealed artifact's own schema and historic target
  inventory. Target-aware Quick Action ordering, authoritative scope receipts
  and repeat-safe receipt recovery keep older 2.2.5 sessions restorable after
  later maintenance changes.
- Explicit non-interactive configuration, module availability and every
  destructive decision fail closed when missing or unreadable. No fallback can
  silently replace DNS, disable RDP or shrink an `All` run.


### ⚠️ Breaking

- **Backups created by 2.2.4 or earlier cannot be restored by this version.**
  The backup format moved to sealed BAVR v2 (session/artifact `schemaVersion`
  2, per-artifact SHA-256 integrity, target-scoped module prestates, removed
  `sharedArtifacts`). The restore engine rejects pre-v2 sessions fail-closed
  with an explicit message before touching any system state; the old backup
  directory itself stays intact and remains restorable by its matching older
  release. Recommended upgrade path: restore any old backup you still need
  **before** upgrading (or keep the older release available), then create a
  fresh backup with this version. There is no 2.2.4→2.2.5 backup converter.

### Added

- SecurityBaseline: Defender sample submission is an explicit informed choice.
  The shipped profile carries the documented privacy deviation
  `SubmitSamplesConsent=1` (safe samples only; cloud protection and
  Block-at-First-Seen stay active); the interactive prompt or
  `submitAllSamples=true` restores Microsoft's `3`. Both declared deviations
  (`RDVDenyWriteAccess`, `SubmitSamplesConsent`) are machine-validated by
  `Tools/Test-SecurityBaselineProvenance.ps1` against the recorded official
  25H2 package (2026-08-08 verification run: exact match, hash-bound).
- SecurityBaseline: the OS SmartScreen level (`ShellSmartScreenLevel`) is an
  informed choice on every path — Apply prompt (default: Microsoft's `Block`),
  `smartScreenWarnMode` config key, and the Pro GUI's ninth quick action
  SmartScreen (Block ↔ Warn) with a sealed action-scoped BAVR session.
  Verification treats `Block`/`Warn` as the openly labeled decision set;
  `EnableSmartScreen=1` keeps its exact match.
- Backup retention is now lossless even on a failed Backup phase: captured
  partial module artifacts are detached from the active BAVR session, retained
  under a collision-resistant `Incomplete_<Module>` identity, hash-inventoried
  and always listed as non-restorable. No framework path automatically deletes
  sealed, invalid, legacy, renamed or incomplete backup directories.
- SecurityBaseline: informed standard-user UAC elevation choice
  (`ConsentPromptBehaviorUser`): Strict deny (`0`, default) or secure-desktop
  credentials (`1`) as an explicit system-wide standard-user convenience
  choice; `3` is never written. The setting does not alter an administrator
  account's own elevation prompts. Choice is mirrored in NonInteractive config,
  logs, reports and BAVR.
- AdvancedSecurity: three-layer third-party-firewall flow — detection prefill,
  always-shown authoritative user prompt, and a runtime conflict warning when a
  firewall controller appears later. A skip reports firewall targets as
  Skipped/NotChecked, never as applied.
- DNS: honest LAN-resolver hint at the provider menu, mirrored to unattended
  logs and `[GUI]` decision output.
- AntiAI: lossless Copilot URI-handler restore — both handlers are backed up
  from their real HKLM and interactive-user HKU Classes source hives (never the
  merged HKCR view) and restored byte-verified.
- Privacy: bloatware removal returns as an honest two-tier feature. Tier 1 is
  Microsoft's native `RemoveDefaultMicrosoftStorePackages` policy (Enterprise/
  Education, Windows 11 24H2/build 26100+ only) for a curated default app list,
  riding the same exact registry-policy prestate plan as every other Privacy target (27
  declared targets: 1 `Enabled` flag + 26 per-app `RemovePackage` flags); its
  policy restore is exact, but the downstream removal is not: it re-allows
  reprovisioning and cannot itself bring the app or deleted local data back.
  Tier 2 is a best-effort classic per-user `Remove-AppxPackage` removal (all
  editions) with a catalog-bound, user-bound sealed pre-removal inventory
  (`Privacy_BloatwareActions`); the session restore engine reports it
  skipped-by-design and never replays it -- restore is the separate,
  explicitly non-exact-restore `Restore-BloatwareApps` winget reinstall. That
  command validates the complete session manifest and hashes, requires the
  original user, and reports missing mappings, winget failures and failed
  package post-checks as incomplete rather than success. Both
  tiers default to off and require an explicit prompt/NonInteractive opt-in
  (`applyStorePackagePolicy`, `removeBloatwareApps`).

### Changed

- Privacy Search Apply and exact Restore now refresh Microsoft's documented
  WindowsSearch API in the actual Explorer user's limited token after the
  sealed registry write/restore. The existing Bing-search verification row and
  HTML report also require effective web results to be off; local apps,
  Settings and indexed-file search stay available in all three modes.
- Privacy app recovery now consumes sealed Tier 1 and Tier 2 original-user
  inventories together, deduplicates overlapping apps, and tries Windows'
  staged package-family registration before winget. This restores packages such
  as Solitaire, Xbox.TCUI and Xbox Speech-to-Text without guessed Store IDs.
  Winget remains the verified current-Store fallback and refreshes only the
  `msstore` source after an actual failed install; it never resets or removes
  user-configured sources. New Privacy prestates use schema 5 so a selected Tier
  1 decision must have its inventory, while schema-4 backups remain compatible.

- The Bing News mapping no longer advertises Store product `9WZDNCRFHVFW` as
  a recovery fallback. The release-date catalog still resolves the product,
  but an actual install/postcheck in the normal Tier 2 post-removal state is
  blocked by Windows with `ERROR_PACKAGE_ALREADY_EXISTS` (`0x80073CFB`) while
  the package remains staged/provisioned. NoID Privacy still attempts the
  sealed local package-family registration first; it now reports an honest
  skip if that exact local route is unavailable instead of promising an
  unverified Store recovery. Microsoft documents that exact deployment code
  as a blocked reinstall of an already-present package in its
  [AppX deployment error reference](https://learn.microsoft.com/windows/win32/appxpkg/troubleshooting#error-codes).
  The immediately preceding v3.3 inventory hash remains a closed restore-only
  reader for existing sealed sessions. It can still use the recorded local
  package family, but a Store fallback executes only when the same exact ID and
  expected-package contract also remains approved in the current v3.4 map.

- Verification verdict ladder: the console reports `Overall Result` and each
  selected module as VERIFIED, FAILED or INCOMPLETE from the reconciled four
  states. `Evaluated Live` and one required-check result percentage replace the
  ambiguous former Success Rate. The HTML deliberately has no second header
  verdict; its five count cards and one stacked result bar carry the aggregate
  state. Green is the passed share of required checks, red is failed and yellow
  is unresolved. NotApplicable and proven deliberate exclusions stay visible
  without distorting that denominator. The compatible machine state remains
  `NotChecked`, while every detail carries a stable disposition, reason,
  evidence source and affected-target count. Human output calls proven
  exclusions `BY CHOICE`, missing durable decisions `NO SAVED CHOICE` and
  runtime evidence failures `CANNOT VERIFY`; mixed reasons retain the neutral
  `Settings Not Checked` label. Classification never depends on the display prose. The meta block shows
  `Verification Scope: <total> targets (Privacy mode: <mode>)` via the
  `PrivacyMode` result property. Without valid Privacy intent the same field
  explicitly says `Privacy profile unproven; maximum scope used`. The first
  dashboard card repeats only `Verification Scope`, so its four state cards
  reconcile exactly without a second inventory number competing for attention.
  Older result objects use their selected total as the internal
  product-inventory fallback.
- HTML report: collapsed sections get `overflow: hidden` so collapse works;
  search and the state filter compose through one `applyFilters()`;
  `Format-ReportValue` unwraps `{"Value":...}` wrappers and one-of lists for
  display only (verifier result strings unchanged); the duplicated IE
  zone-name map is corrected against the documented URL-action values
  (30 renames); ASR GUID rows resolve their names from `ASR-Rules.json`; the
  Edge blocklist NotChecked row carries its reason in Actual like every
  other row. Weighted summary rows state how many declared targets they
  represent, and the renderer rejects any per-category weight mismatch.
  `Print Summary` prints the aggregate dashboard and compact module
  counters; `Print Detailed Report` prints every evidence row. Both modes are
  deterministic and independent of the current screen-collapse state. The
  detailed mode repeats table headers across pages and keeps individual rows
  intact while allowing large module tables to span pages.
- AdvancedSecurity firewall verification:
  `Get-AdvancedSecurityFirewallFilterCache` snapshots all six firewall filter
  types once, keyed by rule InstanceID, and
  `Test-AdvancedSecurityFirewallRuleDefinition` accepts the snapshot pair
  with results identical to the live association queries (covered by an
  equivalence test against real rules). The verifier falls back to live
  per-rule queries when the store-wide enumeration is access-denied;
  apply-time verification keeps live reads.
- Quick Action page load: `Get-AllQuickActionStates` snapshots the six
  canonical NoID Privacy firewall rule names in one `Get-NetFirewallRule` call
  (`Get-QuickActionNamedFirewallRuleSnapshot`), consumed by the UPnP and
  Wireless Display readers with byte-identical results (equivalence test
  against the live per-name path under StrictMode). Any snapshot failure
  falls back to the live per-name queries; the per-rule port-filter value
  checks, single-action reads, apply, verify polling and restore are
  unchanged. Measured on the reference machine: the warm nine-action batch
  drops from 7.9s to 4.5s.
- Encrypted DNS Quick Action: ALLOW/REQUIRE now owns the same complete
  transport state as the DNS module instead of changing only `DoHPolicy`.
  Its sealed target set includes all four selected-provider endpoint
  registrations and the native `DNS_INTERFACE_SETTINGS3` state for every
  applicable physical adapter/family, including disconnected adapters and the
  persisted IPv6 family while `DisabledComponents=0xFF` suppresses its active
  transport. Apply,
  polling verification, compensating rollback and Restore therefore keep the
  Windows Settings encrypted label and fallback behavior consistent. Mixed
  policy/endpoint/adapter state fails closed and asks for a DNS-module reapply;
  earlier 2.2.5 policy-only sealed sessions retain their historic restore
  scope through an explicit compatibility projection. Native-aware 2.2.5
  sessions created before the transport/UI split likewise project comparison
  onto their exact sealed adapter-family identities, so an old IPv4-only
  session neither acquires nor masks the newly managed IPv6 native scope.
- Windows Settings can cache the prior DNS label in an already-open network
  page. Closing and reopening that page displays the applied native state; DNS
  Apply itself does not require a Windows restart.
- Prompt unification across the interactive surfaces: `[Y/N]` bracket form
  everywhere, option blocks printed once before the validation loop, the
  default option listed first in green with the alternative in cyan, a
  `Your choice [Y/N] (default: X)` prompt line, and error messages wrapped in
  blank lines. The restore confirmation, domain-join warning, session and
  module selection, and installer overwrite prompts gain explicit defaults
  and validation loops with unchanged answer semantics.
- Dependency/tooling refresh: Pester is pinned to the latest compatible v5
  release (5.9.0), the deprecated `Assert-MockCalled` assertion is migrated,
  and GitHub Actions are immutable-SHA pinned to checkout 7.0.0,
  upload-artifact 7.0.1 and action-gh-release 3.0.2. The Node 24 actions require
  self-hosted runner 2.329.0 or newer.
- Declared default-decision total is now 645: Privacy has 36 default base
  targets plus the 27 Tier 1 policy-based bloatware-removal targets described
  above (63 total). EdgeHardening adds three documented current-product
  policies -- `SearchSuggestEnabled=0`,
  `AddressBarTrendingSuggestEnabled=0`, and
  `EdgeReadingModeServiceBasedExtractionEnabled=0` -- to the 23-target scope
  (26 total). AntiAI retains its 47 complete checks, including Edge's
  documented `NewTabPageBingChatEnabled=0` target. AdvancedSecurity removes
  Windows PowerShell 2.0
  from new runs after Microsoft removed the feature from updated 24H2 and later,
  while retaining the historical sealed-session reader (61 to 60). It had
  already removed the unrelated
  `AllowMUUpdateService` preference and two undocumented WPAD pseudo-targets
  from its owned target set (64 to 61) so
  applying hardening cannot enroll other Microsoft products into an update
  source whose downstream installations BAVR cannot uninstall.
  Tier 2's 27 best-effort classic-removal candidates -- 26 base apps including
  the exact Microsoft Copilot package plus the separately selected
  Weather/Widgets package -- are informational only
  (`bloatwareBestEffortApps` in `Config/SettingsCounts.json`) and are not part
  of this count.
- The intermediate review total was 642, before the three current-product Edge
  privacy policies above were admitted through the primary-source review.
- The immediately preceding default-decision total was 637: Privacy had 30
  base targets plus the same 27 Tier 1 targets, and AdvancedSecurity still
  declared the removed Windows PowerShell 2.0 feature.
- Declared default-decision total was previously 612 (from 647): Privacy
  narrowed to documented policy targets with exact BAVR (78 to 30),
  AdvancedSecurity aggregates expanded and made deterministic (50 to 64),
  EdgeHardening counts exclude the LGPO `**delvals.` metadata row (24 to 23),
  and the ASR Exchange-server Webshell rule is declared but NotApplicable on
  Windows 11 clients per Microsoft's operating-system matrix (18 applicable + 1).

### Fixed

- Configuration loading now enforces the documented closed schema before any
  module can run (2026-07-19): duplicate JSON property names are rejected at
  every object depth before PowerShell can collapse them, root properties are
  limited to `version`, `modules`, and `options`, and all documented enum
  values are case-exact. Defaults and supported values are unchanged.

- An `All` run with every module explicitly disabled now returns the structured
  fail-closed `NoModulesSelected` result instead of crashing under StrictMode
  while reading `.Count` from a null pipeline result (2026-07-18). The enabled-
  module enumeration is normalized to an array before the existing zero-count
  gate; no backup or system mutation is attempted.
- Privacy schema-5 execution is internally consistent again (2026-07-18).
  Backup already emitted schema 5, but Apply and verification still required
  schema 4 and exact registry restore still rejected schema 5. This made every
  current Privacy run fail after sealing a valid backup and made the same
  session's Privacy registry prestate unrestorable. Apply/Verify now require
  the current schema 5, while Restore accepts sealed schemas 2/3/4/5. The
  framework also preserves module `Error`/`ErrorMessage` details instead of
  replacing them with the generic “failure without an error detail” message.
- AdvancedSecurity no longer fails Apply All when Windows reasserts a stored
  manual “Get the latest updates as soon as they're available” choice
  (2026-07-18). A `DWord=1` plus `CIOptinModified` is preserved without a
  transient raw registry write, verified as one deliberate `NotChecked`, and
  excluded from `SettingsApplied`; value 1 without the intent stamp remains a
  hard failure. Microsoft's documented `SetAllowOptionalContent=3` and
  `DODownloadMode=0` policies remain required and exactly verified.
- Tier-2 app reinstall is now gated by a shared, read-only engine assessment
  (2026-07-18). Shell restores and the Pro GUI offer Store work only when a
  catalog-mapped app recorded as present before removal is currently missing
  for the original user. Already-present apps require neither a prompt nor
  `winget`; unmapped inventory is reported without claiming that it can be
  restored. `Restore-BloatwareApps` consumes the same validated assessment and
  attempts only the missing mapped set.
- Restore-log completeness (2026-07-18): SecurityBaseline restore steps are
  numbered contiguously again, and service and Xbox-task restore successes are
  now written to the session restore log too (previously they appeared only in
  the main log; restore outcomes were never affected).
- `Restore-Session` itself now owns the optional Tier-2 Store-reinstall offer
  (2026-07-18). Direct interactive calls previously bypassed the offer because
  it existed only in the two menu wrappers, even when the sealed restore was
  successful and contained `Privacy_BloatwareActions`. Menu, direct-shell and
  partial-Privacy restores now share one hook before any reboot prompt;
  `-NoReboot`, `-ForceReboot` and noninteractive/GUI runs remain prompt-free and
  receive an actionable log hint. A real `winget --version` startup probe also
  rejects broken App Installer aliases before per-app work begins.
- The interactive Tier-2 Store-reinstall offer can no longer be swallowed by
  the restore reboot prompt, and it now exists in BOTH interactive restore
  surfaces (2026-07-16). Previously the offer lived only in the
  `NoIDPrivacy.ps1` restore menu and ran AFTER `Restore-Session`'s internal
  reboot prompt (default Y) — accepting the reboot skipped it, and the
  `NoIDPrivacy-Interactive.ps1` `[R]` menu never offered it at all. Both
  flows now run restore → Tier-2 offer → deferred reboot prompt, via the new
  silent `Restore-Session -SuppressRebootPrompt` and the shared
  `Get-RestoreRebootReasons` helper. Partial `[M]` restores offer the
  reinstall only when Privacy is part of the restored set. The noninteractive
  `-RestoreSessionPath` automation path (GUI) keeps `-NoReboot` unchanged.

- Standalone verification no longer reports documented Apply choices as
  failures (choice-aware audit, 2026-07-16). Non-authoritative runs (no
  `options.nonInteractive=true` config) now: accept both documented
  BitLocker removable-drive values (`RDVDenyWriteAccess` 0/1, labeled
  one-of, same contract as the PSExec/WMI rule and the existing UAC 4,0/4,1
  handling); honor the documented DNS no-takeover choice (declared
  `provider: KEEP` turns the five DNS checks into deliberate NotChecked;
  a zero-signature host without the declaration reports open uncertainty
  instead of five failures, while any partial provider signature still
  fails hard as drift); honor an explicit `modules.<Name>.enabled=false`
  declaration by removing that module from the bare-run scope (named in
  the console output); and detect an applied Tier-1 policy key as
  decisive evidence of the interactive selection so its targets are
  verified exactly instead of parked as NotChecked (edition/build gating
  unchanged and evaluated first).
- The `IsContinuousInnovationOptedIn` check no longer raises a permanent
  false alarm when Windows re-commits a stored manual Settings opt-in
  (`CIOptinModified` intent stamp): that case is now a deliberate
  NotChecked naming the only durable fix (turning the Settings toggle
  off). Value 1 without the intent stamp remains a failure. Verify counts,
  the NOID_VERIFY_JSON schema and authoritative GUI runs are unchanged.

- Fixed the default Advanced Security contract so the Maximum-only
  `disableDiscoveryProtocols` choice is `false` for the shipped Balanced
  profile, matching the interactive default and the GUI presets.

- AdvancedSecurity WPAD handling now uses exactly Microsoft's documented
  WinHTTP `DisableWpad` machine value plus the interactive Explorer user's
  WinINet `PROXY_TYPE_AUTO_DETECT` bit through option 75. Backup and Restore
  seal and restore only that bit while preserving unrelated proxy flags; raw
  connection blobs, `HKU\.DEFAULT`, and undocumented scalar
  `AutoDetect`/`WpadOverride` values are no longer treated as targets.

- AdvancedSecurity no longer treats Windows PowerShell 2.0 as a new-run target:
  Microsoft removed it from updated Windows 11 24H2 and later. New runs do not
  query, back up, apply, verify, count or expose that removed component. The
  historical reader still recognizes older sealed v2.2.5 artifacts, restores
  them only while Windows exposes the recorded feature identity and otherwise
  fails closed rather than claiming an exact restore. Runtime applicability is
  still resolved before accounting or mutation for services and network
  adapters, so absent components cannot turn valid profiles into false failures.
- Privacy now fails closed for the protected `AllowNewsAndInterests` target
  while Windows UCPD protection is active or cannot be established. The target
  remains untouched and is reported `NotApplicable`, preserving exact BAVR
  instead of claiming a write that Windows can reject or revert.
- The destructive Windows BAVR harness now records independent pre/post
  fingerprints, validates every sealed module/session artifact and hash, proves
  retained-session immutability, rejects partial backups, and requires an exact
  covered-state match after both module and complete-session restore.
- Windows 11 26H2 is consistently admitted only as an Experimental full-BAVR apply path
  that is currently not runtime-validated or release-approved; the v2.2.5
  runtime gate remains Windows 11 Pro 25H2.

- AdvancedSecurity no longer opts a stable workstation into automatic
  optional cumulative previews and early controlled feature rollouts.
  Microsoft's documented `AllowOptionalContent=1` behavior can automatically
  install those updates, contradicting the previous user-control claim and
  producing downstream OS state that registry restore cannot reverse. The
  fixed contract uses `SetAllowOptionalContent=3`, turns the early-rollout UX
  preference off, preserves Microsoft-product update enrollment, keeps regular
  security updates intact, and continues to disable Delivery Optimization P2P.

- AntiAI now classifies editions primarily by language-independent
  `OperatingSystemSKU`, so `EnterpriseEval` is no longer misclassified as an
  unknown/non-commercial edition. Stable 25H2 no longer writes the current
  Insider-only Click to Do, Settings Agent or agent-connector policies.
- AntiAI now declares Microsoft's documented
  `NewTabPageBingChatEnabled=0` control for the Edge Enterprise new-tab page.
  Live Edge 150 testing proved an important profile boundary: Edge loaded the
  value as mandatory with status `OK`, but an unsigned local Workgroup profile
  still exposed an active search-box `Open Copilot` control. The policy is no
  longer described as universal local/Home/Pro new-tab coverage.
- Runtime verification on Paint 11.2603.251.0 and Notepad 11.2605.29.0 now
  informs the published scope: Notepad's writing-tools control disappears;
  Paint's Image Creator disappears, but its Copilot container and Generative
  Erase remain because Microsoft currently publishes no Generative Erase
  policy. Registry success is no longer described as complete Paint-AI
  removal.

- SecurityBaseline BAVR now captures every absent registry ancestor that
  `New-Item -Force` would create and removes/verifies those ancestors during
  restore. It also preserves the native casing of pre-existing registry value
  names. New RegistryPolicies, security-template and UAC artifacts use the
  hierarchy-aware schemas while restore remains compatible with the previous
  sealed schema versions.
- ASR schema 5 now applies all 18 Windows-client targets through target-scoped
  Defender policy values and seals their exact policy prestate, created
  ancestors and native value-name casing. It never writes the merged effective
  `Get-MpPreference` view back through `Set-MpPreference`, which previously
  materialized SecurityBaseline policy rules into local Defender state and
  broke exact restore in a combined run. Sealed schema 3 and 4 artifacts remain
  restorable with their original semantics.
- AdvancedSecurity now includes the TLS 1.0 and TLS 1.1 version parent keys in
  its sealed registry target plan, so restore removes those parents when Apply
  created them instead of leaving empty SCHANNEL protocol keys.
- The Windows 11 decision-matrix fingerprint now compares registry identities
  case-insensitively and excludes only explicitly identified OS-owned volatile
  telemetry (process IDs, DHCP lease state, TCP/IP health and the Server
  service boot GUID) from its gate hash; raw diagnostic snapshots retain those
  values.

### Removed

- AntiAI: the `RemoveMicrosoftCopilotApp` policy write (conditional uninstall
  whose package state cannot be exactly restored); registry-policy Copilot
  controls remain. The Copilot MSIX AppLocker gap is documented explicitly.
- AdvancedSecurity: the obsolete WDigest policy mutation. Microsoft deprecated
  the WDigest policy CSP in Windows 11 24H2 and removed the setting from the
  25H2 security baseline; it is no longer backed up, written, verified or
  counted.

### Security

- The release installer now validates exact GitHub asset URLs and rejects ZIP
  traversal, alternate-data-stream paths, reserved Windows names, case
  collisions, file-parent conflicts, link/reparse metadata and resource
  exhaustion before extraction. Destination reparse ancestors are rejected.
- Installer help and Quick Start no longer pipe mutable network content directly
  into execution. The documented bootstrap is downloaded from an exact reviewed
  tag for inspection or independent verification before local execution.
- ASR backup schema 5 restores only the sealed NoID Privacy-owned per-GUID policy
  values and exact policy/ancestor prestate, preserving local and unrelated
  current Defender rules. Older ASR
  artifacts without the schema-3 ownership/decision plan do not contain enough
  data for that guarantee and are therefore rejected instead of being restored
  destructively. Schemas 3 and 4 remain supported for existing sealed sessions;
  schema 5 owns every declared target only on the native policy surface. Other modules
  in an old session are not silently substituted for the rejected ASR restore.
- Hardware reporting now distinguishes TPM/Secure Boot/virtualization query
  failure from a confirmed absent/disabled result, reports the actual TPM
  `SpecVersion`, and evaluates all CPU sockets plus VM extensions and SLAT.

Fresh Windows 11 Pro 25H2 runtime evidence covers all seven modules individually
and together through Apply→Verify→Restore, sealed-artifact validation and an
independent ten-component exact-prestate comparison. The broader release gate
continues with the Pro wrapper and GUI validation.

---

### 🧪 Live production-validation pass (2026-07-15)

Live validation on fresh Windows 11 Pro 25H2 VMs, closing the gap between
passing tests and honest production behavior. The full
Backup→Apply→Verify→Restore round-trip is now proven end to end: the
standalone verification before Apply and after Restore + reboot are
byte-identical in every result line (only duration and report filename
differ); Apply ran 7/7 modules with zero errors, Tier 2 removed and verified
14/14 apps, and restore completed with zero errors. A four-layer counting
audit (verifier, HTML renderer, CLI shell, module compliance tests) confirmed
the four-state core sound; every change below was found, fixed and
re-verified directly on the live systems.

#### ✅ Added

- **Verify JSON contract schema 2**: `NOID_VERIFY_JSON` adds
  `notCheckedDeliberate` — the verifier-proven subset of `notChecked` that is
  a deliberate Apply-time choice (e.g. an optional Edge target the user did
  not select) — so consumers can distinguish a fully compliant run with
  deliberately unselected options from real uncertainty. The `complete` flag
  keeps its strict schema-1 formula; the Pro GUI moves to the new closed
  field set in lockstep.
- **Tier 2 removal catalog grows to 22 apps (was 21)**:
  `MicrosoftWindows.Client.WebExperience` ("Windows Web Experience Pack",
  Store ID 9MSSGKG348SP), the Widgets board host, joins the best-effort
  catalog. This is the only supported removal path for the taskbar
  weather/news surface, because the Windows User Choice Protection Driver
  (UCPD) blocks command-line writes to `Dsh\AllowNewsAndInterests` on
  protected hosts — the framework fails closed and reports that target
  `NotApplicable`; FEATURES and TROUBLESHOOTING now document the mechanism
  and the manual remedies. Note the deliberate catalog binding: sessions
  sealed against the previous 21-app catalog refuse `Restore-BloatwareApps`
  fail-closed after this change ("bound to a different removal/reinstall
  catalog"); their exact policy restore is unaffected.
- The interactive `[R]` restore now offers the separate best-effort Store
  reinstall after successfully restoring a session that sealed Tier 2
  actions (default No). The result is reported independently — status plus
  reinstalled/already-present/failed/skipped — and never changes the
  exact-restore verdict or exit code; declining prints the manual
  invocation, and the restore engine's Tier 2 skip notice now carries the
  concrete `Restore-BloatwareApps` command including the session path. The
  noninteractive `-RestoreSessionPath` path is untouched.
- AdvancedSecurity now detects a stored continuous-innovation opt-in
  (`IsContinuousInnovationOptedIn` plus the stamped `CIOptinModified` intent
  that Windows re-commits at boot after a manual Settings-toggle click,
  proven via ETL events and sealed prestate) and names the only durable
  fix — turning the toggle off under Settings → Windows Update — as an INFO
  log line, a console NOTICE and in the verify check description. Nothing is
  forced; the user's stored Settings choice is never silently overridden.
- HTML report: the attested machine is named by default — the computer name
  is the subject of the attestation — and the new `-RedactComputerName`
  switch produces the shareable variant. Personal identities (user SIDs,
  profile paths, e-mail addresses) remain always redacted.
- Verify progress: the slow `[9/9]` AdvancedSecurity runtime checks
  (filter-level firewall rules, DISM feature inventory, per-user WinINet)
  announce their up-to-a-minute duration and print dim progress lines, with
  the duration hint sitting on the slow firewall step itself.

#### ⚙️ Changed

- At this dated validation pass, verification was choice-aware end to end: the
  closing console verdict, then-current HTML badge and the shell Verify menu
  all reported success when zero checks
  failed and every `NotChecked` entry is a proven deliberate choice, with a
  one-line explanation. The shell Verify menu now parses the contract line
  and exits honestly — module error on failures, general error on unresolved
  uncertainty or a missing contract, success only on a proven verdict —
  instead of the former unconditional exit 0.
- At this dated validation pass, the report header used one short evidence
  verdict: `100% VERIFIED` only when
  every selected target passed, is not applicable, or is backed by a proven
  deliberate exclusion. Any live mismatch becomes FAILED and any unresolved
  target becomes INCOMPLETE. Separate cards retain the complete four-state
  counts and evidence coverage denominator.
- At this dated validation pass, the Privacy console result and HTML card named
  the selected profile first,
  show its evaluated-live ratio and distinguish deliberate exclusions from
  unresolved checks. Unselected profiles stay out of the primary verdict and
  appeared only in the collapsed technical comparison. The maintained
  renderer's current presentation is documented in Maintenance hardening and
  the main verification bullets above.
- The destructive Tier 1 policy-removal prompt is gated by the same
  fail-closed eligibility classifier as Apply/Verify; ineligible editions
  get an honest not-available note instead of a prompt. The non-interactive
  (GUI) branch and its pinned defaults are untouched.
- ASR: the prevalence ("new software") rule — a NoID Privacy addition — defaults to
  AUDIT everywhere (interactive prompt, DryRun, shipped config,
  `New-DefaultConfig`), matching the Pro GUI presets; verification keeps
  accepting Block or Audit.
- Edge: the interactive block-all-extensions option states its full
  consequences before the choice (blocks all installs, disables installed
  extensions, the allowlist is self-maintained and starts empty), and the
  blocklist target is labeled by intent in every report table.
- Edition/geography applicability facts (Enterprise-only Recall and agent
  policies, EEA-only Recall export, unproven AD/MDM SmartScreen management)
  are INFO notes instead of module warnings; real protection-gap
  disclosures remain warnings.
- CLI polish: calm session/backup listings (per-session warnings demoted to
  DEBUG, yellow status keyword with the reason on a dimmed line), rounded
  durations, silenced raw `netsh` output, and an AdvancedSecurity
  compliance summary that reconciles all four states and actually renders
  its detailed results table to the console.

#### 🔨 Fixed

- Verify no longer raises fail-closed false errors on fresh or
  self-hardened hosts: the paired null ASR placeholder from
  `Get-MpPreference` is normalized, the missing Wireless Display policy key
  is guarded (an unhardened host no longer fails all 60 AdvancedSecurity
  checks), Tcpip6 `DisabledComponents=0xFF` removes only effective IPv6
  transport from scope while leaving its native/UI-visible configuration in
  the separate exact scope,
  and non-authoritative runs detect the applied Privacy mode and the exact
  RDP complete-disable state from live machine state.
- DNS re-apply survives the module's own first Apply: an active DoH REQUIRE
  policy no longer breaks the pre-apply probe or live IPv4 validation (the
  proof remains exact post-write readback plus DoH verification), and hosts
  whose IPv6 stack was disabled by AdvancedSecurity's opt-in hardening are
  treated as effective-IPv6-transport-outside-scope across backup, prestate
  guard and DryRun without dropping the Windows-visible native IPv6 state.
- DNS now also owns Microsoft's native per-interface secure-DNS state for
  each applicable IPv4/IPv6 adapter family. The existing REQUIRE/ALLOW choice is
  reused without another UX decision, Windows Settings can identify the
  endpoints as encrypted, and backup, Apply readback, verifier/HTML evidence
  and Restore all use the same exact schema-v5 DoH state. Effective resolver
  scope and native/UI scope are sealed separately, so an encrypted IPv6 label
  under `DisabledComponents=0xFF` is never presented as active IPv6 traffic.
  Unknown native secure-DNS property types fail closed before mutation.
- The Encrypted DNS Quick Action now loads its closed canonicalization,
  physical-adapter and native `DNS_INTERFACE_SETTINGS3` helper surface at the
  Quick Action script boundary. Previously those functions were created only
  in the local resolver-query scope: a valid Quad9/Cloudflare/AdGuard query
  could succeed and then leave comparison or Apply unable to resolve the same
  native helper. A production-load-path test pins that all seven required
  functions remain available for query, Apply, verification, compensating
  rollback and exact Restore.
- Shell apply results: a pure module skip reads "SKIPPED (disabled in
  configuration or not selected)" instead of "FAILED" with zero errors;
  exit codes are unchanged (fail-closed).
- Counting-audit display fixes across verifier, HTML report and module
  compliance tests: scoped runs sum to the printed total, empty scopes
  report n/a instead of fabricated rates, ASR Warn (action 6) is labeled
  Warn, ASR rule names show in NotChecked/NotApplicable rows, and the
  AdvancedSecurity compliance line goes green only at zero live
  non-compliance. Deliberately unchanged after dependency checks:
  `modulesExecuted` keeps counting module self-skips (GUI contract), and
  the ASR third-party summary line stays yellow when zero rules were
  positively verified.
- Repository hygiene: `.gitattributes` pins LF for text files, Dependabot
  keeps the SHA-pinned GitHub Actions current, blank issues are disabled in
  favor of templates with security reports routed to private advisories,
  and local release-build artifacts are ignored.

---

### 🔍 Quality & robustness pass (2026-05-31)

Full repository audit pass addressing backup-rollback symmetry,
documentation-source drift, and CI safety-nets. Plus tooling additions to
prevent recurrence of the same drift classes.

#### ✅ Added

**CI / Workflow**
- Module-GUID validation job (`ci.yml`): rejects Nil GUID outside
  `_ModuleTemplate/` and detects duplicates across the 7 production manifests.
- Documentation cross-check job (`ci.yml`): README / FEATURES / SECURITY counts
  are validated against `Config/SettingsCounts.json` (canonical source) on
  every PR. Catches doc-drift before merge.
- New workflow `.github/workflows/release-checksums.yml`: on `git tag v*`,
  automatically generates `CHECKSUMS.sha256` via the existing tooling and
  attaches the file as a release asset. Closes the manual-discipline gap
  between `Tools/Generate-ReleaseChecksums.ps1` and the integrity-verification
  instructions in `SECURITY.md`.

**Tests**
- `Tests/Unit/Framework.Consistency.Tests.ps1`: cross-module Pester suite
  covering per-module manifest integrity (`Test-ModuleManifest`, GUID
  parseable + non-Nil, `ModuleVersion` synced to canonical `VERSION` file,
  `FunctionsToExport` is a fixed list), GUID uniqueness across the 7
  production manifests, settings-count self-consistency, config-JSON schema
  spot-checks for every module, and UTF-8 NO-BOM hygiene.

**Templates**
- `Modules/_ModuleTemplate/ModuleTemplate.psd1`: Nil-GUID placeholder strategy
  documented inline with a pointer to the CI guard that rejects it.

#### ⚙️ Changed

- **Minimum supported Windows version raised to Windows 11 24H2 (build 26100).**
  The installer and the SecurityBaseline / ASR prerequisite checks now reject
  Windows 11 21H2–23H2, matching the long-documented 24H2 requirement (23H2
  consumer support ended November 2025).
- Internal cleanup: removed unused `config.json` module metadata and three
  unreachable rollback helpers (`Clear-AuditPolicies`, `Reset-SecurityTemplate`,
  `Clear-LocalGPO`); aligned copyright notices to the 2025–2026 span. The
  never-called `New-SystemRestorePoint` helper was removed on the same
  reasoning (no caller in any product path; the sealed BAVR backup is the
  restore mechanism, and a system restore point remains a recommended manual
  pre-step only), together with the AdvancedSecurity console line that
  wrongly announced "Creating restore point".

#### 🔨 Fixed

**Rollback Safety — Registry-key tracking**
- `Register-NewRegistryKey` tracking added across **29 helpers / 46 call-sites**
  so the rollback path can auto-delete registry keys that did not exist
  pre-hardening. Affected modules:
  - `EdgeHardening` (1 helper / 1 call-site): Set-EdgePolicies parent-key creation.
  - `AdvancedSecurity` (11 helpers / 14 call-sites): Disable-LegacyTLS,
    Disable-AdminShares, Disable-WPAD, Enable-RdpNLA, Set-WDigestProtection,
    Set-WindowsUpdate, Set-WirelessDisplaySecurity,
    Set-DiscoveryProtocolsSecurity, Set-FirewallShieldsUp, Set-IPv6Security,
    Set-SRPRules.
  - `AntiAI` (10 helpers / 18 call-sites): Disable-ClickToDo, Disable-Copilot,
    Disable-CopilotAdvanced, Disable-ExplorerAI, Disable-NotepadAI,
    Disable-PaintAI, Disable-Recall, Disable-SettingsAgent,
    Set-RecallProtection, Set-SystemAIModels.
  - `Privacy` (2 helpers / 3 call-sites): Set-PolicyBasedAppRemoval,
    Set-PrivacyRegistrySection.
  - `SecurityBaseline` (2 helpers / 3 call-sites): Set-RegistryPolicies,
    Invoke-SecurityBaseline standalone-delta path
    (`LocalAccountTokenFilterPolicy`).
  - `DNS` (2 helpers / 6 call-sites): Set-DoHPolicy parent keys,
    Invoke-DNSConfiguration DohFlags IPv4/IPv6 branches.
  - `ASR` (1 helper / 1 call-site): Set-ASRViaPowerShell GPO-registry sync.
- `Restore-RegistryPolicies.ps1`: documented why restore-side `New-Item` calls
  intentionally skip tracking (rollback semantics — there is no
  "rollback of a rollback" in this framework).

**Backup Snapshot Drift**
- `Backup-PrivacySettings.ps1`: PSObject-property filter now excludes
  `PSDrive` alongside `PSPath` / `PSParentPath` / `PSChildName` / `PSProvider`,
  matching every other module's snapshot helper.
- `Backup-AdvancedSecuritySettings.ps1`: registry path casing aligned for
  the `Internet Settings\\Wpad` key (was lowercase `Software`, now
  uppercase `SOFTWARE` consistent with neighbouring keys).
- `Backup-EdgePolicies.ps1`: PreState snapshot now written via
  `[System.IO.File]::WriteAllText` with `UTF8Encoding($false)` instead of
  `Set-Content -Encoding UTF8` (which emits a BOM on PowerShell 5.1).

**Compliance Verification**
- `Test-RdpSecurity` now reads NLA + SSL-Layer from **both** the GPO path
  (`SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services`) and the
  station path (`WinStations\\RDP-Tcp`). Previously only the station path
  was read while `Enable-RdpNLA` writes to the GPO path -- this caused
  false NON-COMPLIANT reports immediately after hardening.
- `Test-EdgeHardening`: Write-Host argument-parsing bug fixed (separator
  string `'+'` was being passed as a literal positional argument between
  two padded dashes instead of acting as the concatenation operator).
- `Tests/Unit/EdgeHardening.Tests.ps1`: corrected JSON-shape assertions
  (`EdgePolicies.json` is a flat array, not a `.Policies` wrapper).

**JSON / Source Encoding — UTF-8 NO-BOM consistency**
- UTF-8 NO-BOM enforced via `[System.IO.File]::WriteAllText` +
  `UTF8Encoding($false)` for all framework-emitted JSON / text:
  `AntiAI_PreState.json`, `EdgeHardening_PreState.json`,
  `AdvancedSecurity_PreState.json`, ParsedSettings JSONs from
  `Tools/Parse-*Baseline.ps1`, the HTML compliance report,
  `REMOVED_APPS_LIST.txt`, `REMOVED_APPS_WINGET.json`, audit-policy
  registry backups.
- `auditpol.exe` temp-file leak: backup / restore / set helpers now use
  GUID-suffixed temp paths with `try/finally` cleanup, preventing
  `%TEMP%` pollution on long-running sessions.

**Module Surface Consistency**
- `EdgeHardening.psm1`: switched to dynamic `Get-ChildItem` function
  discovery so new `Private/*.ps1` or `Public/*.ps1` files are picked up
  automatically. Matches the loader pattern used by SecurityBaseline,
  ASR, DNS, Privacy, AntiAI, AdvancedSecurity.
- `EdgeHardening.psd1` ReleaseNotes: "20 security policies" → 24
  (alignment with canonical settings count).
- `AntiAI.psd1` / `ASR.psd1` / `Privacy.psd1` / `DNS.psd1`: cross-module
  test functions (`Test-AntiAICompliance`, `Test-ASRCompliance`,
  `Test-PrivacyCompliance`) are exported via psm1 + declared in psd1
  `FunctionsToExport` for `Tools/Verify-Complete-Hardening.ps1`
  consumption.
- `Set-ASRViaPowerShell.ps1`: GPO-registry sync path tracks freshly-created
  `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\...\ASR\Rules`
  parent keys via `Register-NewRegistryKey`.

**Documentation / Templates**
- `ModuleTemplate.psd1`: Author / Copyright default to repo maintainer
  (`NexusOne23`) instead of literal `<your-name>` placeholders -- the
  template is single-maintainer-realistic; external forkers get an
  inline comment pointing at the Author field.
- `CONTRIBUTING.md` template manifest: `CompanyName` and `Copyright`
  aligned with the 7 real production manifests (`Open Source Project`,
  `Licensed under GPL-3.0`).

**Static Analysis (PSScriptAnalyzer)**
- New `PSScriptAnalyzerSettings.psd1` ships with the repo and documents
  five architectural rule suppressions in-place: `PSAvoidUsingWriteHost`
  (interactive CLI is the intended surface), `PSUseBOMForUnicodeEncodedFile`
  (cross-tool NO-BOM hygiene), `PSAvoidOverwritingBuiltInCmdlets` (the
  framework's `Write-Log` predates the PS 6.1+ builtin), `PSUseSingularNouns`
  (public API uses plural for bulk operations -- `Invoke-ASRRules`,
  `Set-EdgePolicies`), and `PSAvoidGlobalVars` (dot-sourced Core/* loaders
  use seven documented `$global:` slots as the canonical cross-file state
  channel).
- 1 ParseError fixed: `Restore-SecurityBaseline` had a `ShouldProcess`
  gate floating outside the `begin/process/end` blocks; flattened to a
  single function body with `try/catch/finally` semantics preserved.
- 9 empty catch blocks converted to `Write-Verbose` so diagnostics aren't
  silently dropped (covers SettingsCounts.json reads in every module, plus
  VERSION-file reads in Rollback + Invoke-PrivacyHardening, plus the
  config.json + DoH-probe fallback paths).
- 8 `SupportsShouldProcess` gates added (`Config.New-DefaultConfig`,
  `Config.Set-ModuleEnabled`, `Rollback.Set-SessionType`,
  `Rollback.Update-SessionDisplayName`, `Rollback.Start-ModuleBackup`,
  `Rollback.New-SystemRestorePoint` — helper later removed entirely, see
  Changed above,
  `Framework.Start-HardeningProcess`, `New-HardeningHtmlReport`). `-WhatIf`
  and `-Confirm` now propagate cleanly from the top-level orchestrator down
  to every state-changing helper.
- 2 unused-parameter warnings fixed: `Verify-Complete-Hardening.ps1`
  `Find-RegistrySettings` now takes `ExcludeCategories` as an explicit
  parameter (was relying on PowerShell's dynamic-scope lookup -- worked at
  runtime but flagged as a latent bug); `Restore-ASRSettings.ps1` `BackupId`
  is preserved for API parity with the documented `$null =` discard idiom.
- `NoIDPrivacy-Interactive.ps1` dummy `Write-Log` fallback (used before
  `Logger.ps1` initializes) now uses the `$null = $Level, $Message, ...`
  discard pattern so the intentional no-op is statically visible.
- CI workflow now runs `Invoke-ScriptAnalyzer -Settings ./PSScriptAnalyzerSettings.psd1`
  and **fails on any new Error/Warning/ParseError** instead of only on
  Errors. The strict gate catches architectural drift at PR-review time.
- Historical release record: the release process reported that `Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1`
  returned **0 findings** (down from 187 Warning + 1 ParseError before that
  cycle, plus 2128 `PSAvoidUsingWriteHost` and 10 `PSUseBOMForUnicodeEncodedFile`
  that are now correctly suppressed at the settings layer).

**Test Coverage (Pester 5)**
- New cross-module Pester 5 consistency suite already present (see "Tests"
  above) is joined by a fully passing per-module + integration suite. 0
  permanent `-Skip:$true` gates remain in `Tests/Unit/` -- the previous
  guards were over-conservative; modules catch the platform-incompatibility
  exception internally and return graceful Success=false results, so the
  `Should -Not -Throw` smoke tests pass on Linux + Windows alike.
- New shared bootstrap `Tests/Integration/_Common.ps1` centralises
  cross-platform path resolution and the global-function promotion logic
  needed to let Import-Module-loaded modules find Write-Log /
  Test-NonInteractiveMode / Get-ErrorContext during test execution.
- Six `.psm1` module loaders fixed (AdvancedSecurity, EdgeHardening, DNS,
  AntiAI, Privacy, _ModuleTemplate): backslash path-joins like
  `"$PSScriptRoot\Private"` and `"Private\$function.ps1"` replaced with
  `Join-Path` so the module discovery loop works on both Windows pwsh and
  Linux/macOS pwsh. ASR + SecurityBaseline already used the portable pattern.
- 14 Context-level skip-gates removed; every test in `Tests/Unit/` +
  `Tests/Integration/` + `Framework.Consistency.Tests.ps1` now executes
  in a CI run. Result: **210 passed / 0 failed / 0 skipped** locally on
  pwsh 7.6.1 + Pester 5.7.1.
- Release-cycle record: the last full local pass on Windows 11 Pro 25H2 build
  26200.8737 reported **479 passed / 0 failed / 0 skipped / 0 not run** under
  Pester 5.9.0. Both figures are point-in-time records from this cycle; the
  suite grew further afterwards, and the CI gate re-runs `Tests/Unit` and
  `Tests/Integration` on every push.

#### 📁 Files Changed

302 files across `Modules/`, `Core/`, `Tools/`, `Tests/`, `.github/`,
`Docs/`, and root.
