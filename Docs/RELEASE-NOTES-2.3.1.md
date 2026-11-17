# Release Notes — v2.3.1 (2026-11-10)

NoID Privacy 2.3.1 keeps the complete 2.3.0 product: Windows 11 24H2, 25H2
and 26H2 are all supported releases with the same seven modules, baselines,
Backup, Apply, Verify and Restore (BAVR) contract and counts. It adds a check
that compares a PC with a profile before anything is hardened, makes the
verification result say why a check is open, lets the encrypted DNS quick
action work without a network connection and through a change of network, and
fixes the exit code of a command-line restore.
Declared default-decision total is now 677 (MSRecommended 658, Paranoid 711),
as in 2.3.0; every complete verification reports 711 targets. The
[CHANGELOG](../CHANGELOG.md) carries the short summary, and the
[2.3.0 release notes](RELEASE-NOTES-2.3.0.md) remain the reference for that
release's changes.

## Check before hardening

`Tools/Verify-Complete-Hardening.ps1 -Assessment` measures a PC against a
profile configuration although nothing was applied. It changes nothing.

```powershell
.\Tools\Verify-Complete-Hardening.ps1 -Assessment -ConfigPath .\config.json `
    -ModulesCsv SecurityBaseline,ASR,DNS,Privacy,AntiAI,EdgeHardening,AdvancedSecurity
```

- It takes the `config.json` an unattended Apply would use and the modules
  enabled in it, and measures the same targets with the same rules as a
  verification after an Apply. It needs no Apply session and no saved choices.
- The console and the report say "already in place", "not hardened yet" and
  "not in this profile" where a verification after an Apply says passed,
  failed and by choice. An open setting is work that hardening would do, not a
  protection that failed. The report is written to `Reports\Assessment_*.html`
  in the ten report languages and is marked as a check before hardening.
- The two ASR rules that are a choice get the action an Apply of the profile
  would set on this PC, including Audit for the PSExec/WMI rule where a
  Configuration Manager client is installed. Block where the profile asks for
  Audit counts as in place.
- Measured on a fresh Windows 11 Pro 26H2 with the released `config.json`:
  711 targets, 58 already in place, 549 not hardened yet, 49 not in this
  profile, 55 not applicable; the run takes 10 to 16 seconds.

NoID Privacy Pro uses this mode for its free check before a license exists.

## Verification says why a check is open

- **Not readable is not a mismatch.** When a query, a helper or the declared
  scope failed while an area was measured, 2.3.0 recorded every target of that
  area as a failed check: a registry verification without a resolvable desktop
  user reported 335 settings as differing although none had been compared. All
  nine areas now record one row that names the error and count its targets as
  not proven. The run still fails, because a required check passes only when
  it is proven; the summary reads "0 mismatched, 335 not proven", and the
  report badge reads "Failed · not readable".
- **Saved ASR choices that do not fit this version.** A standalone
  verification stopped before measuring anything, and without a report, when
  the saved ASR choices named another rule set than this version declares or
  held a damaged entry. They are now set aside and named on the console; the
  two rules that are a choice are then judged as on a PC without a saved
  choice.
- **Protection tiles name the unmet requirement.** The Windows runtime tiles
  of the report said "Not running" for a protection this PC cannot run. They
  now say why, for example "Needs Windows Enterprise or Education" for
  Credential Guard on Pro or "Not available on this processor" for the kernel
  shadow stack on a processor without CET.
- **Export.** `-ExportPath` now carries `NotProven` and `RequiredFailed`
  (`Failed` + `NotProven`, the number the console and the report call failed),
  so that a script testing `Failed -eq 0` alone cannot pass a run whose
  evidence is missing. The export also carries the redaction of the HTML
  report: the account SID in HKU paths reads `[USER-SID]`, the profile folder
  `%USERPROFILE%` and e-mail addresses `[EMAIL]`. Counters, setting names and
  values are unchanged; see
  [Verification Without Interaction](NONINTERACTIVE-MODE.md#verification-without-interaction).

## Encrypted DNS quick action: offline and across networks

- **Offline.** Without a default route the action showed no status and could
  not be used. The DNS servers the DNS module writes are static adapter
  settings and stay readable without a connection, so the action now reads the
  provider from them and can be switched and restored offline. A PC whose
  adapters take their DNS servers from the network keeps the "no connection"
  answer, because nothing can be read there.
- **Change of network.** The sealed state of the action recorded which adapter
  held the default route. That is the state of the network, not a setting: the
  fingerprint changed when a laptop moved from Wi-Fi to a cable or went
  offline, and the restore of the action then refused the unchanged settings
  as drift, which also blocked the restore of the DNS module session behind
  it. A session is now compared by its settings. Any changed setting still
  stops the restore.
- Measured on Windows 11 Pro 26H2: switch offline and restore online, switch
  online and restore offline after a restart.

## Restore

- **Command line and quick-action sessions.**
  `NoIDPrivacy.ps1 -RestoreSessionPath <quick-action session>` restored and
  verified the settings, then printed an error and returned exit code 4. It
  returns 0 now. The interactive menu and NoID Privacy Pro were not affected.
- **Restart advice after an incomplete restore.** A restore that did not
  complete gets no restart prompt, on purpose. The modules it processed can
  still have put restart-sensitive settings back, and until Windows restarts
  those look unrestored. One warning now says to restart before checking the
  result.
- **A quick action that was changed by hand.** When a setting is changed again
  outside NoID Privacy after a quick action, the action's restore and every
  older module session that owns the same settings stop without changing
  anything. [Troubleshooting](TROUBLESHOOTING.md) now describes both messages
  and the two ways out.

## Checked, no change needed

Measured on Windows 11 Pro 26H2, because both were open questions: with the
Remote Access Connection Manager service (RasMan) disabled, Windows still
answers the VPN connection query the DNS module depends on, with and without
a VPN profile; with the Windows Search service disabled, Windows still reads
and writes the search settings the Privacy module manages.

## Documentation

- **Direct script calls.** Windows 11 clients ship with the `Restricted`
  execution policy, which refuses a direct
  `.\Tools\Verify-Complete-Hardening.ps1` with "running scripts is disabled
  on this system". The README, the installer's closing text and
  [Troubleshooting](TROUBLESHOOTING.md) now show the start that works there:
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` for the
  current window, or `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
  <script>` for one call. Neither changes a machine or user policy.
  `Start-NoIDPrivacy.bat` and the bootstrap install were not affected.
- **Mark-of-the-web.** Measured on Windows 11 Pro 26H2: a file written by
  `Invoke-WebRequest` carries no mark-of-the-web; a script saved by a browser
  does. The earlier text named both for the bootstrap download.

## Upgrade

Replace the engine folder with the 2.3.1 release. Backups made with 2.2.5 to
2.3.0 restore as before; 2.3.1 introduces no backup conversion. The
configuration file must carry `"version": "2.3.1"`, which the released
`config.json` already does. A PC hardened with 2.3.0 needs no new Apply.
