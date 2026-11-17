# Release Notes — v2.2.7 (2026-10-17)

NoID Privacy 2.2.7 keeps the complete 2.2.6 product: Windows 11 24H2, 25H2
and 26H2 are all supported releases with the same seven modules, baselines and
Backup, Apply, Verify and Restore (BAVR) contract. It turns advertising in
Windows Settings and Start and the advertising ID off in every Privacy mode,
also on Home, adds two Search policies
and three Paranoid app-permission policies, and fixes Backup and Restore after
File Explorer access to the engine's state folder.
Declared default-decision total is now 656 (Strict 675, Paranoid 709); every
complete verification reports 709 targets. The [CHANGELOG](../CHANGELOG.md) carries the short
summary, and the [2.2.6 release notes](RELEASE-NOTES-2.2.6.md) remain the
reference for that release's changes and recovery limits.

## Privacy: advertising in Settings and Start

Each page under Settings > Privacy & security was checked on Windows 11 26H2
Pro and Enterprise after hardening and compared with Microsoft's Policy CSP.
On Pro and Home, "Recommendations and offers in Settings" and the account
notifications in Settings stayed on after the default Privacy mode, because the
Microsoft policies for them apply only to Enterprise and Education. On Home,
the advertising ID also stayed on, because its policy does not apply there.

- Every Privacy mode now turns off "Recommendations and offers in Settings"
  with the three values Windows writes itself when that switch is turned off
  (`SubscribedContent-338393Enabled`, `SubscribedContent-353694Enabled` and
  `SubscribedContent-353696Enabled` = 0), and the account notifications in
  Settings (`EnableAccountNotifications=0`, Home and Pro, which show this
  switch) and Start (`Start_AccountNotifications=0`). These are user
  preferences: they apply to the signed-in desktop user, the switches stay
  changeable, and Restore returns the exact previous values.
- Every mode turns the advertising ID off for the desktop user with
  `HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo\Enabled=0`,
  the value the Settings switch writes. Measured on 26H2 Home: apps then
  receive no advertising ID, the switch shows Off, and Restore returns the same
  ID. The machine-wide `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo\Enabled=0`
  that older Microsoft guidance names changed neither the switch nor the ID on
  26H2, so it is not written. On Pro and higher the `DisabledByGroupPolicy`
  policy also stays in place.
- MSRecommended also sets `AcceptedPrivacyPolicy=0`. It already stopped the
  collection of typing and inking data, but the switch "Custom inking and
  typing dictionary" still showed On. Windows writes this value itself when
  that switch is turned off.
- Every mode sets the Search policies `AllowSearchToUseLocation=0` (Search
  cannot use location) and `EnableDynamicContentInWSB=0` (search highlights
  off) on Pro and higher. On Home they are not applicable; the existing user
  preference still turns search highlights off there.
- Paranoid denies apps presence sensing, the eye tracker and motion data
  (`LetAppsAccessHumanPresence`, `LetAppsAccessGazeInput` and
  `LetAppsAccessMotion` = 2) on Pro and higher.

Deliberately unchanged: the file-library pages (Documents, Downloads folder,
Music library, Pictures, Videos, File system) and automatic file downloads have
no Microsoft policy and stay your choice; the passkey policies are available
only to Windows Insiders, and passkeys are a security feature.

Privacy now declares 74 targets in MSRecommended, 93 in Strict and 127 in
Paranoid.

## Engine state folder after File Explorer access

The engine keeps machine-local recovery records in
`C:\ProgramData\NoID Privacy\EngineState`: the Apply record used by
verification, the Device Guard recovery supplement for historical
SecurityBaseline backups and the ASR runtime journal. Only SYSTEM and the
Administrators group may change them, and the engine refuses a record that
anyone else could have written.

File Explorer cannot open this folder for a normal account. If you confirm its
**Continue** prompt, Windows gives your account full control of the folder. In
2.2.6 every later SecurityBaseline backup, ASR recovery and Apply-record read
then stopped with "Apply-intent path grants write access to an untrusted
identity", and reinstalling did not help.

2.2.7 resolves this without weakening the check:

- Before a record is read, the engine checks `NoID Privacy` and `EngineState`.
  If SYSTEM or the Administrators group still owns a folder, it restores that
  folder's protected permissions and logs a warning that names the removed
  account.
- Records are never repaired. Each one keeps its own owner and permission
  check, so a record that your account created or could change is still
  rejected.
- A folder owned by any other account is left as it is and still rejected.
- Only these two folders are ever changed.

On 2.2.6 the same result needs one command in an administrator terminal per
folder, for example:

```powershell
icacls "C:\ProgramData\NoID Privacy\EngineState" /remove:g "<account>"
```

## Upgrade

Replace the engine folder with the 2.2.7 release. Backups made with 2.2.5 and
2.2.6 restore exactly as before; 2.2.7 introduces no backup conversion. The
configuration file must carry `"version": "2.2.7"`, which the released
`config.json` already does.

On a PC hardened with an earlier version, verification reports the Privacy
targets added in 2.2.7 as failed until you apply the hardening again. Apply
takes a new backup first, so Restore of that session returns those values
exactly.
