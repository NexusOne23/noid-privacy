# Release Notes — v2.3.2 (2026-11-17)

> Historical release notes: this release is no longer published on GitHub.
> For installation, upgrades and the current release, see the
> [README](../README.md) and the [CHANGELOG](../CHANGELOG.md).

NoID Privacy 2.3.2 keeps the complete 2.3.1 product: Windows 11 24H2, 25H2
and 26H2 are all supported releases with the same seven modules, baselines,
Backup, Apply, Verify and Restore (BAVR) contract and counts. It fixes
Privacy and AdvancedSecurity on PCs with Windows Administrator protection
whose engine was installed with the README command.
Declared default-decision total is now 677 (MSRecommended 658, Paranoid 711),
unchanged from 2.3.1; every complete verification reports 711 targets. The
[CHANGELOG](../CHANGELOG.md) carries the short summary, and the
[2.3.1 release notes](RELEASE-NOTES-2.3.1.md) remain the reference for that
release's changes.

## Privacy and AdvancedSecurity with Administrator protection

With Administrator protection, an app that gets administrator rights runs in
a separate hidden account whose profile is `C:\Users\ADMIN_<name>`. In an
elevated terminal `%USERPROFILE%` points there, and up to 2.3.1 the installer
used `%USERPROFILE%\NoIDPrivacy` as its default folder.

Privacy and AdvancedSecurity save part of their state in the desktop account:
the Windows Search setting, the per-user app list and the WinINet proxy
detection. For that they start a short task in the desktop account, which
loads NoID Privacy's scripts from the installation folder. The desktop
account cannot read the hidden account's profile, so the task ended without a
result:

```
Original-user worker ended without a result; task result=1
```

Privacy stopped while recording its starting state and AdvancedSecurity while
creating its backup. Neither module changed a setting. The other five modules
were applied, sealed and can be restored.

2.3.2 changes four things:

- **Installation folder.** The installer's default is now
  `C:\Program Files\NoIDPrivacy`. Only administrators can change the scripts
  there, and the desktop account can read them.
- **Check before the first module.** An Apply from a folder inside another
  account's profile stops before any module runs and says why. Nothing is
  changed. Restore and Verify still start from such a folder, so sessions
  made there stay restorable.
- **Clear message.** A desktop-account task that cannot load its scripts ends
  with task result 11. The error names the installation folder and points
  to the install command in the README.
- **Verify.** When the Windows Search state cannot be read, the Bing search
  setting is not proven and the reason is shown; the other Privacy checks are
  still evaluated. Before, the whole Privacy area was not proven.

Measured on Windows 11 Pro 26H2 (build 26300.9711) with Administrator
protection active, all runs from an elevated terminal:

- 2.3.1 in `C:\Users\ADMIN_<name>` reproduced the message above for both
  modules; with all seven modules selected the other five were applied, and
  `[R]` Restore from that folder restored and verified all five.
- 2.3.2 in the same folder stopped before the first module and created no
  session. Verify from there measured every target except the two that need
  the desktop account (150 targets verified instead of 92 with 2.3.1).
- 2.3.2 in a folder outside any profile that only administrators can read
  reported task result 11 with the folder name.
- 2.3.2 in `C:\Program Files\NoIDPrivacy` applied both modules; Verify passed
  Privacy and AdvancedSecurity, and Restore restored and verified them.
- The 2.3.2 installer downloaded and verified the published release into
  `C:\Program Files\NoIDPrivacy`, named the old installation, and started
  the menu from there.

If you saw the message above, install 2.3.2 with the README command and apply
Privacy and AdvancedSecurity again from `C:\Program Files\NoIDPrivacy`. The
other modules need no new Apply. Sessions from the old folder are restored
from the old folder.

## Other fixes

- **Third-party firewall detection.** AdvancedSecurity's advisory detection
  of Windows Firewall Control, Bitdefender, ESET and Kaspersky read the
  programs installed for the elevated account. With Administrator protection
  that is the hidden account, so a program installed only for the signed-in
  user was missed. Detection now also reads the signed-in user's list; a
  per-user entry that 2.3.1 did not see is found. It still only sets the
  suggested default of the firewall question.
- **Failed run.** When a run ends as failed after some modules were applied,
  the result names how many were applied and the rollback session, as a
  partial or stopped run already did.

## Documentation

- README and SECURITY.md describe the new default folder;
  [Troubleshooting](TROUBLESHOOTING.md) says what to do after
  "task result=1" or "task result=11".
- README and the documentation describe this repository only. The sections
  about other products are removed.
- README: the Chinese summary is removed.
- License: NoID Privacy is available only under the GPL-3.0; the commercial
  dual-license offer has ended.
- SECURITY.md: the HTML report names the computer unless
  `-RedactComputerName` is used.
- The 2.2.4 release is no longer published. README, Troubleshooting and
  SECURITY.md say that backups from 2.2.4 or earlier are restored with your
  own copy of 2.2.4.

## Upgrade

Run the README install command. It installs 2.3.2 to
`C:\Program Files\NoIDPrivacy`; add `-InstallPath` to keep another folder. An
installation in `%USERPROFILE%\NoIDPrivacy` is left untouched together with
its `Backups` folder, and the installer says where it is. Backups made with
2.2.5 to 2.3.1 restore as before; 2.3.2 introduces no backup conversion. The
configuration file must carry `"version": "2.3.2"`, which the released
`config.json` already does.
