# Release Notes — v2.3.0 (2026-10-22)

NoID Privacy 2.3.0 keeps Windows 11 24H2, 25H2 and 26H2 as supported releases
with the same seven modules and the Backup, Apply, Verify and Restore (BAVR)
contract. Microsoft Edge no longer starts by itself and prints again,
SmartScreen warns instead of blocking by default, Privacy defaults to Strict
and Administrator protection to a Yes/No confirmation, the app removal lists
only apps that come back, Restore finishes where earlier versions refused, and
Restore and Verify no longer depend on the full Apply pre-flight. Windows 11
Home receives the policies it was measured to honour, AntiAI policies are in
place before a Windows or app update adds their feature, DNS checks name
resolution online after the Apply, and the release files are signed. It also
fixes three modules that stopped: SecurityBaseline with account lockout off,
DNS with a network card owned by a Hyper-V virtual switch, and AdvancedSecurity
on a Wi-Fi reconnect.
Declared default-decision total is now 677 (MSRecommended 658, Paranoid 711);
every complete verification reports 711 targets. The [CHANGELOG](../CHANGELOG.md)
carries the short summary.

## Microsoft Edge no longer starts by itself

The first time Edge opens on a PC, for example to show a NoID Privacy report,
Edge turns on its Startup Boost. From then on Edge started at every sign-in,
with a visible "New tab" window, and restarted in the background after its last
window was closed. No NoID Privacy module causes this; each module was applied,
restarted and restored on its own to rule that out.

EdgeHardening now sets two documented Edge policies as privacy additions:

- `StartupBoostEnabled=0`: Edge no longer starts at sign-in.
- `BackgroundModeEnabled=0`: Edge no longer keeps running after its last window
  is closed.

EdgeHardening now manages 33 values (24 Microsoft Edge v151 baseline values and
9 privacy additions; the default selects 32). Measured on Windows 11 26H2: a
running Edge does not remove its sign-in entry at once. At the first restart
after the Apply, Edge opens one last time and removes the entry itself; from
the second restart on, Edge stays closed until you open it.

## Microsoft Edge prints again

With the Microsoft baseline value `DynamicCodeSettings=1`, the Edge browser
process may not create dynamic code. Microsoft's policy documentation notes
that this can break printer drivers that must run in the browser process.
Measured on Windows 11 26H2 with Edge 155 and only Microsoft Print to PDF
installed: every print attempt made Windows block dynamic code in the Edge
browser process, and Edge closed.

EdgeHardening now writes `DynamicCodeSettings=0`, Edge's own default, so Edge
prints. The baseline value `1` is a separate choice: a question in the shell,
an option in the Pro app and `allowBrowserDynamicCode` in `config.json`. The
value is backed up, applied, verified and restored like every other Edge
value.

## SmartScreen warns by default

SmartScreen now warns by default instead of blocking. An unrecognized or
unsigned download shows the SmartScreen warning and starts only after "More
info > Run anyway". With Microsoft's baseline value Block there is no such
option, so new or rarely downloaded programs could not be started at all.

Block stays available as the stricter choice: in the shell, answer Y to the
SmartScreen question; in `config.json`, set `smartScreenWarnMode` to `false`;
in the Pro app, choose High Security or select Block in the Custom setup. Quick
& Secure and Balanced already used Warn; the Custom setup now starts from Warn
as well. SmartScreen itself stays on in every case, and Verify checks the level
you chose.

## Privacy Strict and a Yes/No administrator prompt by default

Two more shell questions now start from the NoID Privacy recommendation:

- Privacy: Strict is option 1 and the default; MSRecommended is option 2 and
  Paranoid option 3. Strict turns off DiagTrack and dmwappushservice, denies app
  access to location, app diagnostics and generative AI, and turns off settings
  cloud backup and cellular text-message cloud sync. Diagnostic data is set to
  Off where the edition supports it (Enterprise and Education). The released
  `config.json` selects `"mode": "Strict"`. MSRecommended stays the choice for
  PCs managed with MDM or Intune, because Strict turns off telemetry services
  that such management uses.
- Administrator protection: the Yes/No confirmation
  (`ConsentPromptBehaviorEnhancedAdmin=2`) is option 1 and the default;
  Microsoft's prompt for PIN, password or Windows Hello is option 2 and classic
  User Account Control option 3. Administrator protection itself stays on, so
  elevated apps still run in a separate hidden account. Someone at the unlocked
  PC can confirm Yes/No; Microsoft's prompt also stops that. The released
  `config.json` selects `"adminProtectionMode": "Consent"`.

In the Pro app, the Custom setup starts from the same choices, in the same
order. The default-decision total rises from 658 to 677 because Strict declares
more Privacy targets; the 711-target verification scope stays the same.

## App removal: only apps that come back

Tier 2 now removes 18 apps (catalog 3.6). Each one comes back from Windows'
local copy or from a Microsoft Store product, and no Windows feature or game
needs it. Every Store product was measured on Windows 11 Home 26H2: removed as
Tier 2 removes it, then installed through WinGet with the same app registered
afterwards.

- New: Microsoft 365 Copilot, Microsoft To Do, Power Automate, Microsoft Family
  Safety and Quick Assist, which Microsoft recommends removing when it is not
  used. TikTok uses its current Store package.
- Kept from now on: Media Player (the default player for music and video), Get
  Help (it hosts the Windows troubleshooters), Sticky Notes (notes that are
  only stored locally would be lost), Game Bar (without it Windows can ask for
  an app for "ms-gamingoverlay" when a game starts, a controller connects or
  Win+G is pressed), Xbox Identity Provider and Xbox TCUI (games use them for
  Xbox sign-in and the in-game Xbox overlay).
- No longer listed, because no Store product brings them back: the Xbox Speech
  Window, Xbox Console Companion, Tips, Mixed Reality Portal, People and both
  Candy Crush games.

Tier 1 (Enterprise and Education) removes four apps: Copilot, News, Weather and
Xbox. Xbox Identity Provider and Xbox TCUI stay for the same reason.

Sessions saved before this change keep their exact app list. App recovery
brings their apps back as before, including the Store route for apps the new
lists no longer remove.

## Windows 11 Home: measured policies apply

Microsoft's policy documentation lists no Home support for most Windows
policies, so earlier versions left every Windows policy out on Home. Measured on
Windows 11 Home 26H2: for the policies below, Settings shows "Some of these
settings are managed by your organization" and locks the switch, or the
documented effect is visible. 2.3.0 applies, verifies and restores them on Home
as on Pro:

- Privacy: diagnostic data and feedback prompts, every app permission, clipboard
  history, clipboard sync, nearby sharing, location, Find my device, settings
  sync and Windows backup, tailored experiences and cloud search.
- AntiAI: Windows apps no longer use the text and image generation features of
  Windows (`LetAppsAccessSystemAIModels=2`).
- AdvancedSecurity: Delivery Optimization downloads only from Microsoft, not
  from other PCs (`DODownloadMode=0`). The AdvancedSecurity backup moves to
  schema 7; schema-5 and schema-6 sessions restore as before.

Every other Windows policy stays not applicable on Home until it is measured
too. Sessions saved before 2.3.0 did not change these values on Home, so
restoring them leaves the values as they are.

## AntiAI policies in place before the feature arrives

AntiAI used to leave a policy out while the feature behind it was not yet on
the PC: Recall, Click to Do and the Settings agent below the Windows build that
adds them, Paint AI below its build, and Notepad's AI policy below Notepad
11.2503.16. The Store often updates Notepad while the hardening runs; the
verification after the Apply then found the Notepad policy applicable but not
set, and reported the hardening as failed. A second run passed.

2.3.0 writes these policies on every eligible edition whatever the build or app
version, so a later update finds them in place. A target that was not
applicable at the Apply and is applicable now, for example after an edition
upgrade or the update to 26H2, fails Verify with the note to apply AntiAI
again.

## Restore finishes instead of refusing

2.2.5 to 2.2.9 restored each module all or nothing. A module refused its whole
restore before changing anything when, for example, a key that its Apply had
created now also held other settings, a value had changed since the Apply, or
the user profile that applied it no longer existed. A common case: after
adding an Edge extension allowlist, the Edge restore refused.

2.3.0 restores what it can and names the rest, in every module:

- Every value the session changed returns to its earlier state. A key that did
  not exist before the Apply is removed once it is empty again. If it also
  holds other settings, Restore keeps the key with those settings and names
  them.
- When one step fails, the independent steps still run. Each failure is
  reported, and the session restore counts as failed.
- Machine-wide settings are restored even when the user who applied them is
  gone. The per-user values of a deleted profile are reported as not restored.
- ASR: a rule that another tool or person changed after the Apply keeps its
  current value and is reported. A rule that another policy layer controls has
  NoID Privacy's own policy value restored. With Microsoft Defender stopped,
  ASR sessions in the current format (schema 5, as written by 2.2.5 and later)
  restore their policy values, which Defender applies when it runs again;
  sessions in an older ASR format still need Defender running.
- DNS: Restore returns DNS on every adapter that is present and restores the
  global DNS-over-HTTPS settings. An adapter that is unplugged, disabled or
  removed is left unchanged and named with the DNS settings it had before the
  Apply.
- AdvancedSecurity: NetBIOS is restored adapter by adapter, the firewall policy
  and the registry values no longer depend on each other, and a Windows image
  without the PowerShell 2.0 feature is reported instead of failing the
  restore.
- SecurityBaseline: a removed Xbox save task is reported instead of failing
  the restore, and Device Guard settings from another Group Policy source are
  kept.

Restore ends with a list of these notes. They do not change the result: a
session whose own values all returned counts as restored.

## Restore and Verify without the Apply pre-flight

Restore, Verify and the backup list now check only the PowerShell host and
administrator rights. A Windows build that this release does not list yet, or a
failed domain query, no longer blocks undoing or checking the hardening. Apply
keeps all checks.

## Device management that cannot be checked

Privacy leaves Windows policies unchanged on a PC joined to an Active Directory
domain or registered with an MDM service, and also when that cannot be checked.
AntiAI uses the same check for the Edge Update block on Copilot installs, which
it writes only on managed PCs. 2.3.0 tries each query three times, two seconds
apart, before it counts as failed. When it still fails, Verify reports the policies Privacy left
unchanged as not checked, because they could not be verified, instead of as not
applicable. Privacy names the cause: "Device management could not be checked"
or "This PC is managed by an AD domain or MDM".

## Further changes

- DNS: after the Apply, DNS now checks online that a test name resolves
  through the Windows DNS client with the new settings, the same path every app
  uses, including encrypted DNS when it is required. A pass appears as a note,
  like the note on a PC without a network. A failed lookup is a warning: on a
  network that blocks encrypted DNS, apply DNS again with fallback allowed or
  restore the DNS session. The Apply result still depends only on the
  verification on this PC.
- Unattended runs: when SecurityBaseline runs before ASR, cloud protection that
  is off no longer stops the run before it starts. The baseline sets
  Microsoft's cloud-protection policy, which Microsoft Defender applies at
  once. ASR checks cloud protection again before its backup. The Pro app's
  readiness check follows the same rule.
- ASR: when Defender cloud protection is off, all rules are applied.
  Microsoft requires cloud protection for three of them (prevalence,
  obfuscated scripts and advanced ransomware protection); the others need no
  cloud. The shell shows a notice instead of the earlier Continue/Abort
  question, because Abort applied no ASR rule at all and never protected
  better. Unattended runs keep `continueWithoutCloud`, now `true` by default;
  `false` still applies no ASR rule. The notice appears only when cloud
  protection is switched off and SecurityBaseline does not run before ASR,
  because SecurityBaseline turns cloud protection on.
- Xbox Quick Action: Off now turns off exactly what the hardening turns off,
  the four Xbox services, the XblGameSave task and game recording, and removes
  no app; removing the Xbox app stays Privacy's Tier 2 choice. On turns the
  same settings on again and installs the required Xbox apps that are missing,
  from Windows' local copy or the Microsoft Store. After the hardening, with or
  without Tier 2, the switch shows Off instead of Partly off. Xbox backups made
  with 2.2.5 to 2.2.9, whose switch removed all six apps, stay readable and
  restorable.
- The verification report that the menu ([V]) and `NoIDPrivacy.ps1` open uses
  the Windows display language, with English as the fallback.
  `Tools\Verify-Complete-Hardening.ps1` run directly still defaults to English.
- AdvancedSecurity refreshes the computer policy after it changes firewall
  rules. A refresh takes about six seconds; one that does not finish within 10
  minutes is now stopped and reported as failed instead of blocking the run.

## Fixes

- SecurityBaseline: with account lockout turned off (`LockoutBadCount=0`),
  Windows reports no lockout duration, reset counter or administrator-lockout
  setting, and the SecurityBaseline backup stopped with "secedit export is
  missing managed [System Access] ...". The backup now records lockout as off,
  and Restore switches it off again.
- DNS: a network card that a Hyper-V external virtual switch owns has no IPv4
  binding and no DNS settings. DNS now leaves such a card out instead of
  stopping.
- AdvancedSecurity: a Wi-Fi reconnect, or a service with the start type
  "Manual" that started or stopped during the backup, no longer stops the
  module.
- An engine folder whose files a cloud-sync client such as OneDrive manages no
  longer turns a successful Apply into FAILED. Only links (junctions and
  symbolic links) in the engine folder are still refused.
- Verify's console output ends with one aligned summary, the Windows
  protections running at verification, the path of the report and the final
  PASSED or FAILED line. The report lists every failed check, including those Verify could
  not prove, with the expected and the found value or the missing evidence;
  the console no longer repeats them. Progress bars of Windows PowerShell 5.1
  no longer overwrite the console text.
- The interactive menu explains each Apply result by its cause, for example
  ASR skipped because Microsoft Defender is not the active antivirus, instead
  of "Some steps failed".
- `Start-NoIDPrivacy.bat` starts 64-bit Windows PowerShell also from a 32-bit
  program.
- When newer sessions changed the same modules, Restore names them in a note
  before it starts and advises restoring them first, newest first. The note was
  written only to the log file before.
- App recovery with Windows Administrator protection: an elevated window runs
  as a separate account whose name starts with `ADMIN_`. After Restore, the app
  check therefore refused with "must run as the original interactive user",
  and the shell and the Pro app offered no app recovery. The check now reads
  the apps of the user who is signed in at the desktop, and the recovery runs
  in that user's own account through a short-lived task, the same way Apply
  removes the apps. NoID Privacy confirms every recovered app in that user's
  registrations afterwards. This also covers a standard user who elevates with
  another administrator's credentials. Measured on Windows 11 Pro 26H2 with
  Administrator protection on: 12 of 12 apps back, 11 from the local copy and
  To Do, whose local copy had been removed as well, from the Microsoft Store.
  Only when the user who removed the apps is
  not signed in does that user still have to run app recovery themselves.
- A Restore started straight from the menu, without an Apply in the same
  window, printed two log records and switched the rest of the window to full
  log records when it checked the apps. The console stays in plain text now.

## Signed release files

The PowerShell files of the release ZIP and the files of NoID Privacy Pro carry
an Authenticode signature. Smart App Control and other application control can
check the publisher instead of blocking unsigned files. A signature block does
not change how the engine reads its files.

## Documentation

- Upgrading from 2.2.4: breaking changes, the order for restoring 2.2.4
  backups with 2.2.4 itself, and the values 2.2.4 leaves behind
  ([README](../README.md#upgrading-from-224-or-earlier)).
- The status behind exit code 4, and Troubleshooting entries for each stop
  ([Non-Interactive Mode](NONINTERACTIVE-MODE.md#apply-status-behind-exit-code-4)).
- Reset and uninstall, including the engine state under
  `C:\ProgramData\NoID Privacy\EngineState`
  ([Troubleshooting](TROUBLESHOOTING.md#reset-and-uninstall)).
- Corrected: the baseline refuses network and Remote Desktop logon for local
  accounts; Shields Up is part of the Maximum profile; administrative shares
  disappear after the next restart; Tier 2 app removal applies to the current
  user only; memory integrity can conflict with
  incompatible drivers; with another antivirus Verify stays FAILED because the
  ASR checks cannot be proven.
- Corrected: 2.2.4 MSRecommended wrote `DisableSettingSync=2` with
  `DisableSettingSyncUserOverride=0`, which turns sync off but lets the user turn
  it back on ([Privacy policy provenance](PRIVACY-POLICY-PROVENANCE.md)).

## Upgrade

Replace the engine folder with the 2.3.0 release. Backups made with 2.2.5 to
2.2.9 restore with the new behavior described above; 2.3.0 introduces no backup
conversion. The configuration file must carry `"version": "2.3.0"`, which the
released `config.json` already does. The released file selects Privacy Strict,
the Yes/No administrator prompt, SmartScreen Warn and Continue without cloud
protection; an own configuration keeps its values. Apply EdgeHardening again to turn Startup
Boost and background mode off and to print from Edge again; until then Verify
reports the two Edge values as mismatched, and Edge keeps the baseline value
`DynamicCodeSettings=1`. On Windows 11 Home, also apply Privacy, AntiAI and
AdvancedSecurity again; until then Verify reports the policies that now apply on
Home as mismatched. The same holds for AntiAI policies that 2.2.x left out below
a Windows build or Notepad version. On Enterprise and Education with Tier 1,
apply Privacy again; until then Verify reports the Tier 1 values for Xbox
Identity Provider and Xbox TCUI as mismatched.
