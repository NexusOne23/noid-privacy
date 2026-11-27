# Release Notes — v2.3.3 (2026-11-27)

NoID Privacy 2.3.3 keeps the complete 2.3.2 product: Windows 11 24H2, 25H2
and 26H2 are all supported releases with the same seven modules, baselines,
Backup, Apply, Verify and Restore (BAVR) contract and counts. It fixes backup
failing with `"Get-FileHash" was not recognized` when NoID Privacy is launched
from an elevated PowerShell 7 prompt
([#22](https://github.com/NexusOne23/noid-privacy/issues/22)), and closes the
remaining Windows Administrator protection edge cases in the pre-flight check,
installer, SecurityBaseline user context and verifier.
Declared default-decision total is now 677 (MSRecommended 658, Paranoid 711),
unchanged from 2.3.2; every complete verification reports 711 targets. The
[CHANGELOG](../CHANGELOG.md) carries the short summary, and the
[2.3.2 release notes](RELEASE-NOTES-2.3.2.md) remain the reference for that
release's changes.

## `Get-FileHash` failure when launched from PowerShell 7 ([#22](https://github.com/NexusOne23/noid-privacy/issues/22))

When PowerShell 7 (`pwsh.exe`) runs a `.bat` file such as
`Start-NoIDPrivacy.bat`, Windows executes it through `cmd.exe`, which inherits
PowerShell 7's unmodified `PSModulePath` with PowerShell 7 module directories
ahead of `C:\Windows\System32\WindowsPowerShell\v1.0\Modules`. In an already
elevated PowerShell 7 window, `Start-NoIDPrivacy.bat` launched 64-bit Windows
PowerShell 5.1 (`powershell.exe`) directly with that inherited `PSModulePath`.

In Windows PowerShell 5.1, `Get-FileHash` is a script function in
`Microsoft.PowerShell.Utility.psm1`. Because PowerShell 7's
`Microsoft.PowerShell.Utility` directory appeared first in `PSModulePath`,
Windows PowerShell 5.1 failed to resolve `Get-FileHash` while hashing backup
artifacts during backup verification and sealing, causing the BAVR safety
contract to block Apply before any setting was changed.

2.3.3 fixes this across the launcher, runtime and bootstrap installer:

- **`Start-NoIDPrivacy.bat`.** Clears `PSModulePath` inside `setlocal` before
  invoking 64-bit Windows PowerShell 5.1 (covering both elevation and direct
  elevated execution), so Windows PowerShell 5.1 builds its own clean default
  module path without modifying the caller's environment.
- **`Core/Runtime.ps1` and `install.ps1`.** Sanitize `$env:PSModulePath` on
  Windows PowerShell 5.1 startup by removing PowerShell 7 user/machine/version
  module roots and any foreign `$PSHOME\Modules` folder carrying another
  `Microsoft.PowerShell.Utility.psd1`, guarantee `$PSHOME\Modules` is present,
  and explicitly import Windows PowerShell 5.1's
  `Microsoft.PowerShell.Utility.psd1` if `Get-FileHash` is still unresolved.
  This also covers direct `powershell.exe` and wrapped `install.ps1` calls.

## Remaining Administrator protection hardening

- **Engine location pre-flight (`Core/Framework.ps1`).**
  `Test-NoIDEngineLocation` now also checks the elevated process's own
  `$env:USERPROFILE` directly whenever its SID differs from the signed-in
  desktop user's SID, refusing an engine inside a hidden `ADMIN_` profile even
  when `ProfileList` does not list that shadow account.
- **Installer (`install.ps1`).** Legacy-installation discovery checks user
  profiles in `ProfileList` in addition to `$env:USERPROFILE`, so an earlier
  installation in the desktop user's profile (`C:\Users\<name>\NoIDPrivacy`) is
  still found and named after Administrator protection is turned on. Passing an
  explicit `-InstallPath` inside the elevated account's private profile is
  refused when it differs from the signed-in desktop user.
- **Interactive user SID resolution (`SecurityBaseline` and `Verify`).**
  `Get-SecurityBaselineUserContext.ps1` and the registry/Privacy user checks in
  `Tools/Verify-Complete-Hardening.ps1` now resolve the Explorer owner SID
  through `Win32_Process.GetOwnerSid` with bounded retries instead of
  `Get-Process -Name explorer -IncludeUserName` + `NTAccount.Translate`,
  matching `Privacy`, `AntiAI` and `AdvancedSecurity`.

## Release files

The PowerShell files of the release ZIP carry no Authenticode signature, as
before 2.3.0; each file equals its tagged source. The installer checks the ZIP
against `CHECKSUMS.sha256` of the same release. On a PC that only runs signed
scripts (AllSigned execution policy or App Control for Business), NoID Privacy
does not start.

## Documentation

- [Troubleshooting](TROUBLESHOOTING.md) documents the
  `"Get-FileHash" was not recognized` error, its cause, and how to start older
  2.3.2 copies outside PowerShell 7.
- [README](../README.md) removes the legacy 2.2.4 upgrade checklist, the inline
  Release Highlights list, and the per-version Release Notes links. The full
  version history remains in [CHANGELOG.md](../CHANGELOG.md) and `Docs/`.

## Upgrade

Run the README install command. It installs 2.3.3 to
`C:\Program Files\NoIDPrivacy`; add `-InstallPath` to keep another folder.
Backups made with 2.2.5 to 2.3.2 restore as before; 2.3.3 introduces no backup
conversion. The configuration file must carry `"version": "2.3.3"`, which the
released `config.json` already does.
