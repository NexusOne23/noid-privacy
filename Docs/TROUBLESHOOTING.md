# 🔧 Troubleshooting

Common issues and step-by-step fixes for NoID Privacy 2.3.1 on Windows 11 26H2, 25H2 and 24H2 (x64). See the main [README](../README.md) for installation and feature documentation.

---

## Common Issues

**A backup was created by 2.2.4 or earlier**
- Those backups predate sealed BAVR v2; the current version lists them but
  never restores them. Use the
  [retained 2.2.4 release](https://github.com/NexusOne23/noid-privacy/releases/tag/v2.2.4)
  for them. Download that tagged source archive; the current installer selects
  the current release and is not a legacy reader.
- The installer keeps the `Backups` folder, so the old sessions
  (`Session_yyyyMMdd_HHmmss`) are in the `Backups` folder of the current
  installation. Restore in this order:
  1. With the current version, restore every session created since the
     upgrade, newest first.
  2. Extract the 2.2.4 archive into its own folder, never over the current
     installation.
  3. Copy (do not move) only the `Session_yyyyMMdd_HHmmss` folders into the
     `Backups` folder of the extracted 2.2.4; create that folder if it is
     missing. Do not rename or edit them.
  4. Start 2.2.4 as administrator, choose Restore and restore its sessions,
     newest first.
- The order matters: 2.2.4 removes ASR and DNS-over-HTTPS values that newer
  sessions recorded, after which their restore reports drift.
- Do not copy, rename or convert a legacy directory into a current sealed
  session. This historical format boundary does not apply to valid sealed
  backups created with 2.2.5 or newer.

**An older session containing ASR refuses to restore**
- Current ASR BAVR uses schema 5: all 18 Windows-client targets are applied through target-scoped Defender policy values, with sealed exact per-GUID policy prestate, created-ancestor state and native value-name casing. This prevents a merged policy-derived `Get-MpPreference` view from being materialized into unrelated local Defender state during a multi-module run. Sealed schema 3 and 4 sessions remain restorable with their original semantics. Older ASR artifacts cannot prove which target values the framework owned, so converting them would risk deleting unrelated or later Defender state.
- The restore engine therefore rejects that ASR artifact fail-closed and reports the session failure; it does not claim partial-session success.
- Keep the old session directory unchanged for forensic/manual comparison. Use its captured data only for an administrator-reviewed manual recovery; do not copy or rename it into a current sealed session.
- Newly created ASR sessions use schema 5. Existing valid sealed 2.2.5+ sessions
  retain automated restoration through their frozen schema readers.

**AdvancedSecurity stops with "NetBIOS adapter snapshot failed: Physical network adapter '...' has no matching Win32_NetworkAdapterConfiguration"**
- Affects 2.2.6 and 2.2.7. Windows keeps listing some network adapters as "Not Present", for example the mobile-broadband interfaces of a 5G or LTE modem that is switched off (`Get-NetAdapter` shows them with the status `Not Present`). These versions required a Windows network configuration for every physical adapter and stopped the AdvancedSecurity backup; the other modules still applied.
- Fix: update to 2.2.8 or later. It disables NetBIOS on such an adapter through its NetBT value, which Windows applies when the adapter connects.

**DNS stops with "Failed to create complete DNS pre-state backup - DNS pre-state contains a duplicate server for {...}/23"**
- Affects 2.2.6 to 2.2.8. Many home routers announce their IPv6 DNS resolver both in Router Advertisements and through DHCPv6; Windows then lists the same address twice for the adapter (`Get-DnsClientServerAddress -AddressFamily IPv6`). These versions refused that list, so DNS changed nothing and its five checks stayed unproven; the other modules still applied.
- Fix: update to 2.2.9 or later and run DNS again. The incomplete DNS session from the failed attempt contains nothing to restore and can be removed.

**Restore says a network adapter from the backup was not restored**
- DNS servers are set through the live adapter. Since 2.3.0 Restore returns DNS on every adapter that is present, restores the global DNS-over-HTTPS settings, and names each adapter it could not reach (unplugged, disabled or removed) together with the DNS settings it had before the Apply.
- Reconnect or enable that adapter (for example a USB network adapter or a dock) and run Restore for the same session again; the adapters already restored are simply set again. If the adapter is gone for good, there is nothing left to restore on it.
- Wi-Fi Direct adapters after the complete Wireless Display disable: reconnect the Wi-Fi adapter and run Restore again.
- NetBIOS needs no adapter: Restore returns each adapter's exact NetBT value even when the adapter is unplugged.

**Restore says it kept a registry key "because it also holds settings this restore did not change"**
- Since 2.3.0 Restore returns every value the session changed. A key that did not exist before the Apply is removed only when it is empty again. If someone or something added other values or subkeys there in the meantime (for example an Edge extension allowlist, another policy tool or another NoID Privacy session), Restore keeps the key with those settings and names them in the note.
- Nothing is wrong and the restore counts as successful. Remove the remaining settings yourself only if you know where they came from.

**Restore says a user profile no longer exists**
- Per-user settings live in that user's profile. If the account or its profile was deleted after the Apply, Restore restores all machine-wide settings and reports the per-user settings of that profile as not restored; there is nothing left to restore them into.
- If the profile still exists but could not be loaded (for example because another program holds its registry file open), Restore reports an error for those settings only. Sign in as that user, which makes Windows load the profile, and run Restore for the same session again as administrator.

**"...cannot be loaded because running scripts is disabled on this system"**
- Cause: Windows 11 clients ship with the `Restricted` execution policy, which refuses a direct `& .\Script.ps1` call. A script saved by a browser additionally carries the internet mark-of-the-web; a file written by `Invoke-WebRequest` does not. This is Windows' default, not a NoID Privacy setting.
- Supported start for the downloaded bootstrap: `& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $installer`. The relaxation applies to that one process; the machine-wide policy is not changed and needs no cleanup afterwards.
- After installation start through `Start-NoIDPrivacy.bat`, which already launches the framework the same way and requests elevation.
- For a direct call such as `.\Tools\Verify-Complete-Hardening.ps1`, allow scripts for the current window only with `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`, or start the single call as `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Tools\Verify-Complete-Hardening.ps1`. Neither changes a machine or user policy.
- On a managed device where Group Policy defines the execution policy, the process-level value is ignored by design. Ask the administrator for an approved start path instead of weakening the policy machine-wide.

**"64-bit Windows PowerShell 5.1 is required" (exit code 2)**
- Cause: the script was started from PowerShell 7 (`pwsh`), from 32-bit Windows PowerShell, or from a 32-bit program. NoID Privacy runs only in 64-bit Windows PowerShell 5.1.
- Start through `Start-NoIDPrivacy.bat`, which selects 64-bit Windows PowerShell even from a 32-bit program, or open "Windows PowerShell" (not the "(x86)" entry and not PowerShell 7) from the Start menu.

**"Configuration version '…' does not match framework VERSION '…'" or an "Unsupported … property" error (exit code 3)**
- Cause: `config.json` comes from another release, for example a copy kept from 2.2.4. Each release accepts only its own `config.json` version and property names. The 2.2.4 options `dryRun`, `createBackup`, `verboseLogging`, `autoReboot` and `autoConfirm`, and descriptive module entries such as `policies` or `features` no longer exist. Each module entry keeps `enabled`, `priority` and `status` (`"IMPLEMENTED"`).
- Start from the `config.json` shipped with this release and enter your choices there again. Verbose logging is the `-VerboseLogging` switch; a preview is the `-DryRun` switch.

**"Another NoID Privacy Apply or Restore operation is already running" (exit code 4, status `Busy`)**
- Only one Apply or Restore runs at a time on a PC, across the Shell and NoID Privacy Pro. Nothing was changed.
- Wait until the other run has finished, or finish it in its window, and start again.

**Apply ends with exit code 4 although most modules succeeded**
- Exit code 4 covers every Apply that did not fully succeed. The status tells the cases apart: `Partial` means no module failed but one was skipped or limited, typically ASR on a PC where Microsoft Defender is not the active antivirus. The changes of the successful modules stay, with backup. See the [status table](NONINTERACTIVE-MODE.md#apply-status-behind-exit-code-4).
- Unattended runs stop with `PreflightBlocked` before any change when ASR prerequisites are missing; `options.allowPartialHardening` is the explicit choice to apply the other modules anyway.

**Verify shows many "not proven" checks after an upgrade or a Restore**
- Verify compares the PC with the choices saved by the last Apply. After an upgrade from 2.2.4 there are no saved choices yet, and a Restore clears them. Privacy (127 checks), AntiAI and the optional AdvancedSecurity and Edge choices are then reported as not proven, and the overall result is FAILED.
- Run Apply once with the current version, then Verify.
- After an update from an earlier 2.2 release, Edge reports `StartupBoostEnabled` and `BackgroundModeEnabled` as mismatched until EdgeHardening is applied again; both values are new in 2.3.0. On Windows 11 Home, Privacy, AntiAI and AdvancedSecurity report the policies that now apply on Home as mismatched until they are applied again; the same holds for AntiAI policies that 2.2.x left out below a Windows build or Notepad version, and on Enterprise/Education with Tier 1 for the Xbox Identity Provider and Xbox TCUI values.

**"Access Denied" errors**
- Not running as Administrator
- Right-click PowerShell → "Run as Administrator"

**Remote SMB/WMI/WinRM or Remote Desktop refuses a local account**
- Cause: the Microsoft security baseline that SecurityBaseline applies assigns
  `Local account` (`S-1-5-113`) to "Deny access to this computer from the
  network" (`SeDenyNetworkLogonRight`) and "Deny log on through Remote Desktop
  Services" (`SeDenyRemoteInteractiveLogonRight`). Local accounts, including
  local administrators, therefore cannot sign in over SMB, WMI, WinRM or Remote
  Desktop. Windows reports this as "Access denied" or as a logon type that is
  not granted. 2.2.4 applied the same two rights.
- Since 2.2.6 SecurityBaseline also keeps Microsoft's
  `LocalAccountTokenFilterPolicy=0` instead of replacing it with `1` on
  standalone/workgroup systems. Setting `1` on its own therefore does not
  restore remote access for local accounts: the two deny rights block the
  logon first.
- Local sign-in and local UAC prompts are not affected. For remote
  administration use a domain-managed identity, a locally installed management
  agent or narrowly delegated share/WMI rights where those models fit.
- If remote administration with local accounts is an explicit requirement,
  treat it as a separate security exception outside NoID Privacy's automatic
  baseline: remove `Local account` from the two deny rights (Local Security
  Policy → User Rights Assignment) and, for full administrator rights over
  SMB/WinRM/WMI, also set `LocalAccountTokenFilterPolicy=1`, which removes
  Remote UAC filtering for local administrator accounts. Restrict the relevant
  SMB/WinRM/WMI/RDP firewall exposure to the required source address and use a
  different local administrator password on every machine. The next
  SecurityBaseline Apply intentionally returns these targets to the baseline.
- Restore remains exact: a sealed older session restores the state recorded
  before its Apply, including `LocalAccountTokenFilterPolicy=1` when that was
  the real prestate.

**A device or app stops working after SecurityBaseline and a restart**
- Possible cause: memory integrity (HVCI), which SecurityBaseline turns on, blocks a driver that is not compatible with it. [Microsoft warns](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity) that incompatible drivers or apps can malfunction and, in rare cases, Windows fails to start.
- Install a current driver from the device or PC maker (Device Manager or the maker's website) and restart.
- If no compatible driver exists, run `[R]` Restore for the SecurityBaseline session and restart; Restore returns the recorded Device Guard values.
- If Windows no longer starts, follow Microsoft's recovery steps on that page: in the Windows Recovery Environment set `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` `Enabled` to `0` and restart. NoID Privacy adds no UEFI lock; only a lock that already existed requires turning Secure Boot off first. Once Windows starts, run Restore as above; otherwise the policy can turn memory integrity on again at the next restart.

**Standard user sees "This program is blocked by group policy" instead of an administrator password prompt**
- Cause: the security baseline applies `ConsentPromptBehaviorUser = 0` (automatically deny standard-user elevation requests). Installs then require a full administrator sign-in.
- To permit standard users to enter separate administrator credentials, rerun the SecurityBaseline module and choose `[Y]` at the "Standard User - Administrator Elevation" prompt (or set `standardUserElevationMode` to `SecureDesktop` in `config.json`). The interactive Shell asks this machine-wide question even when the current everyday account is an administrator. That writes `ConsentPromptBehaviorUser = 1` and keeps credential entry on the secure desktop.
- This policy governs standard users only. Selecting `SecureDesktop` does not change an administrator account's own elevation prompts.
- The choice is recorded in logs and reports as a user-selected documented deviation, not drift; `[R]` Restore reverts the value to its sealed prestate.

**Starting an app as administrator asks for PIN, password or Windows Hello**
- Cause: the Windows 11 26H2 security baseline turns on Administrator protection (`TypeOfAdminApprovalMode = 2`). An app gets administrator rights only for the approved task, in a separate hidden account, and the elevation prompt asks for your PIN, password or Windows Hello. Commands inside an already elevated terminal do not each trigger a new prompt.
- To confirm with Yes/No instead, rerun the SecurityBaseline module and choose `[2]` at the "Administrator Protection - Elevation Prompt" question (or set `adminProtectionMode` to `Consent` in `config.json`). Administrator protection stays on; someone at your unlocked PC could then confirm without your password.
- For Hyper-V or compatibility problems with elevated WSL or developer tools, choose `[3]` (`Classic`): classic User Account Control without Administrator protection, a documented deviation from the Microsoft baseline.
- Restart Windows after the change. `[R]` Restore returns both values to their sealed prestate.

**PIN/password was chosen, but Windows still asks Yes/No**
- Cause: Administrator protection needs Windows security update KB5127648 (October 2026) or later, and it starts only after a restart. Earlier updates since August 2026 distributed it only gradually. NoID Privacy sets and verifies `TypeOfAdminApprovalMode = 2`; without the update, administrators can keep the baseline's classic Yes/No prompt on the secure desktop (`ConsentPromptBehaviorAdmin = 2`), and elevated apps then run in their own account. With KB5127648, elevation asked in the "Windows Security" dialog after the restart on Pro and Enterprise test PCs.
- To check: when Administrator protection is active, `whoami` in a window started as administrator shows a separate account whose name starts with `ADMIN_`.
- Install the latest Windows updates and restart. The policy stays in place; NoID Privacy does not install updates itself.

**VBS/Credential Guard not active after reboot**
- Credential Guard requires Windows 11 Enterprise or Education
- Check Secure Boot, firmware virtualization, VM-monitor extensions and SLAT in the UEFI setup and in `msinfo32` (System Summary → Virtualization-based security)
- TPM strengthens Credential Guard by hardware-binding its keys, but Microsoft's current [Credential Guard requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/) describe TPM as recommended rather than mandatory (TPM 1.2 and 2.0 are supported there)
- Enable virtualization in BIOS/UEFI
- Verify: `.\Tools\Verify-Complete-Hardening.ps1`

**BitLocker not activating**
- Check edition, TPM readiness, disk layout/space and the exact BitLocker event/error; do not infer one cause from an inactive volume
- Check TPM: `Get-Tpm`
- A compatible TPM enables the normal transparent startup path. On supported editions, [Microsoft's BitLocker configuration reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure#require-additional-authentication-at-startup) also permits a deliberately configured non-TPM path with a startup USB key or password; that is a different security and recovery model
- Manual activation: Control Panel → BitLocker

**Can't install software after hardening?**
- Defender controls applied by NoID Privacy (the ASR "prevalence" rule, SmartScreen set to *Block* if you chose it or the Pro app's High Security profile, and PUA protection) can block unsigned or unrecognized downloads.
- The cleanest framework rollback is the interactive **`[R]` Restore from Backup** menu. It restores and verifies every sealed NoID Privacy-owned target in the selected session and names what it kept, for example a key that now also holds other settings; it does not replace an independent system backup.
- To keep the hardening on and allow *individual* trusted files, see [Allow Specific Files While Keeping Hardening On](#allow-specific-files-while-keeping-hardening-on-per-file) (recommended).
- For recurring new-software work, see [Use the Framework's Audited ASR Compatibility Choice](#use-the-frameworks-audited-asr-compatibility-choice).
- The **SmartScreen level choice** sets the OS SmartScreen level to *Warn* (default) or *Block*. *Warn* keeps SmartScreen active and offers "More info > Run anyway" for downloads you trust; *Block* is Microsoft's baseline value and stops unrecognized downloads without that option. Shell users get the choice during SecurityBaseline Apply (or via `smartScreenWarnMode` in `config.json`); NoID Privacy Pro users can switch it any time with the SmartScreen quick action and its sealed backup session.

**Microsoft Edge closes when you print**
- The Microsoft baseline value `DynamicCodeSettings=1` keeps the Edge browser process from creating dynamic code, and Edge then closes when it prints, also to PDF. Since 2.3.0 EdgeHardening writes Edge's default `0` unless you chose the baseline lockdown.
- An Apply with 2.2.x wrote `1`. Apply EdgeHardening again with 2.3.0 and keep the default answer to "Keep printing in Edge working?" (Pro app: "Keep printing in Edge working" on). Restart Edge afterwards; `edge://policy` shows the value Edge loaded.

**Widgets / taskbar weather still visible after a Strict or Paranoid apply**
- Cause: Windows 11's User Choice Protection Driver (UCPD) blocks command-line writes to the only policy lever for the Widgets board (`HKLM:\SOFTWARE\Policies\Microsoft\Dsh\AllowNewsAndInterests`). With an active UCPD driver the framework fails closed: nothing is written and the target is honestly reported as `NotApplicable` -- this is the OS protecting the value, not an incomplete apply.
- Note the distinction: the *BingWeather app* is removed by Tier 2 as sealed; the taskbar weather flyout belongs to the separate Widgets/Web Experience component.
- Supported removal path: select Tier 2, then answer Yes to its separate default-No Weather/Widgets question. That adds the "Windows Web Experience Pack" (`MicrosoftWindows.Client.WebExperience`) for the current user without touching the UCPD-protected policy. Answering No is a valid green verification outcome. Manual alternative: Settings > Personalization > Taskbar > Widgets = Off.

**Apps removed by Tier 1 or Tier 2 are still missing after Restore**
- Exact Restore returns the sealed configuration. The interactive `[R]` workflow then offers separate best-effort app recovery when recorded apps are missing; its default is No. The automated `-RestoreSessionPath` path never prompts, and the Pro GUI has its own app-recovery action. Declining or skipping recovery leaves the apps uninstalled; no path can recover deleted app data exactly.
- To request app recovery separately, run it after session Restore while the user who removed the apps is signed in at the desktop: `Import-Module '.\Modules\Privacy\Privacy.psd1'; Restore-BloatwareApps -SessionPath '.\Backups\<session folder>'`. A window started as administrator works too; with Administrator protection it runs as an `ADMIN_` account, and the recovery then runs in the signed-in user's own account. It validates the sealed session, tries recorded local package registration first, then verified Store recovery through WinGet. Store-only apps need a connection; results identify failed, skipped or network-dependent work.

**Restore refuses after a quick action: "differs from the sealed post-Apply fingerprint" or "A newer overlapping Quick Action must be restored first"**
- Cause: a quick action (for example Remote Desktop, SmartScreen or encrypted DNS) was used, and the same setting was changed again afterwards outside NoID Privacy. The quick action's restore then finds neither the state it left nor the state it started from and stops with `Current Quick Action state differs from the sealed post-Apply fingerprint; refusing to overwrite drift or newer state.` Every older module session that owns the same settings waits for it and stops with `A newer overlapping Quick Action must be restored first: <session>`. Nothing is changed in either case.
- Fix 1, keeps every undo step: put the setting back to what the quick action had set, then restore the quick action and after it the module session. Example: the encrypted DNS action was switched to *Allow* and the policy `DoHPolicy` was later set to `3` by hand; setting it back to `2` lets both restores run.
- Fix 2, if the earlier value is not known: move the quick action's session folder out of the `Backups` folder (its name ends in `_QuickAction_<action>`; keep it, do not delete it), then restore the module session. The module restore returns every setting the module saved to its original state. This gives up the quick action's own undo step; a setting that only the quick action had touched stays as it is now and can be set by hand.
- Which adapter currently carries the connection, or being offline, is not such a change: the encrypted DNS action compares its settings, not the route.

**Cloud content search stays off after restoring a 2.2.5 backup**
- Cause: while the Privacy policy `AllowCloudSearch=0` was active, Windows set your own cloud content search toggles to off, and it keeps them off after the policy is removed. 2.2.5 backups did not record those toggles.
- Fix: turn **Microsoft account** and **Work or School account** back on in Settings → Privacy & security → Search permissions → Cloud content search if you used them. Backups created by 2.2.6 record and restore both toggles exactly.

**Windows Security warns that "blocking potentially unwanted app downloads and files is off" after hardening**
- What you see: **Windows Security > App & browser control > Reputation-based protection** flags that potentially-unwanted-app *download/file* blocking is disabled ("your device may be at risk"), even after a Strict or Maximum run. This warning often first appears after the post-hardening reboot, when Windows Security re-evaluates.
- What is actually active: the SecurityBaseline enables the Defender half of this feature — `PUAProtection = 1` ("block apps"), cloud-delivered protection (`MAPSReporting = 2`), block-at-first-seen, and the `EnableSmartScreen` policy; real-time and tamper protection are untouched. Confirm with `Get-MpPreference | Select-Object PUAProtection, MAPSReporting`.
- Why the *download* half stays off: the "block downloads and files" control is backed by **Microsoft Edge SmartScreen** (`SmartScreenEnabled` / `SmartScreenPuaEnabled`), not by `PUAProtection`. Those Edge values are **managed-only** — Microsoft documents them as applying only when the device proves AD domain membership or MDM registration. On a standalone Pro or Home machine, EdgeHardening reports them `NotApplicable` and writes nothing, so the control keeps its Windows default. This is deliberate: writing `HKLM\...\Policies\Microsoft\Edge` on an unmanaged device makes Edge display a false "managed by your organization" banner. See [EDGE-POLICY-PROVENANCE.md](EDGE-POLICY-PROVENANCE.md).
- This is not a regression and not a NoID Privacy setting that was switched off — the core PUA and cloud protections are on. The warning reflects a Windows architecture limit on unmanaged devices, not an incomplete apply.
- If you want the download check anyway — note that Edge SmartScreen sends downloaded-file URLs/hashes to Microsoft for a reputation lookup, a cloud-telemetry trade-off a privacy build will not enable silently — turn it on manually in **Windows Security > App & browser control > Reputation-based protection settings > Potentially unwanted app blocking > Block downloads**, or enable SmartScreen in **Edge > Settings > Privacy, search, and services**.

---

## Allow Specific Files While Keeping Hardening On (Per-File)

**Problem:** You want Defender controls to remain enabled but have verified that one specific file is legitimate and an ASR rule blocks it.

First identify the control that actually blocked the file in **Windows Security > Virus & threat protection > Protection history**. An ASR exclusion is not a universal Defender allow: it affects ASR evaluation, not every SmartScreen, antivirus or PUA decision.

| Control | Narrow action | Exact effect |
|---|---|---|
| Mark-of-the-Web / downloaded PowerShell script | `Unblock-File -LiteralPath` after independent verification | Removes only the `Zone.Identifier` stream; it does not prove that the file is safe |
| ASR block, including prevalence rule `01443614…` | Exact-file `AttackSurfaceReductionOnlyExclusions` entry | Excludes that path from **all** ASR rules, not just the rule that fired |
| Defender malware or PUA detection | Review the detection and use the action offered by Windows Security only if the file is independently trusted | Does not change the global PUA setting, but accepting a detected threat is still a security exception |

Before creating an exception, compare the publisher signature and file hash with the software vendor's official source, then run a targeted Defender scan:

```powershell
$file = "C:\Tools\thatapp.exe"
Get-AuthenticodeSignature -LiteralPath $file
Get-FileHash -LiteralPath $file -Algorithm SHA256
Start-MpScan -ScanType CustomScan -ScanPath $file
```

If Protection history identifies an ASR block and you accept the risk, add only the canonical full file path, then verify the effective list contains exactly that path:

```powershell
$file = [System.IO.Path]::GetFullPath("C:\Tools\thatapp.exe")
if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
    throw "File does not exist: $file"
}

Add-MpPreference -AttackSurfaceReductionOnlyExclusions $file -ErrorAction Stop
$effective = @((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionOnlyExclusions)
if ($effective -notcontains $file) {
    throw "The ASR exclusion was not accepted by the effective Defender policy"
}
```

- `Add-MpPreference` appends; `Set-MpPreference` would replace the complete exclusion list.
- Do not use a broad folder when a single file is sufficient. One global ASR exclusion applies to every ASR rule for that path.
- NoID Privacy's carried-forward baseline has `DisableLocalAdminMerge=0`, but Intune, Configuration Manager, Defender for Endpoint or Group Policy can remain authoritative and can reject or overwrite local changes. Never infer success from a command returning without error; verify the effective value as above.
- Keep Tamper Protection enabled. Microsoft warns that protected changes can appear successful while being blocked. On a managed device, use the organization's management plane; do not work around it locally.
- `Unblock-File` is a separate, deliberate decision. Microsoft documents that it removes the Internet-zone marker and recommends reviewing the file and source first:

```powershell
Unblock-File -LiteralPath $file -Confirm
```

Remove the ASR exception immediately after it is no longer needed and verify removal:

```powershell
Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $file -ErrorAction Stop
$effective = @((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionOnlyExclusions)
if ($effective -contains $file) {
    throw "The ASR exclusion is still effective"
}
```

Microsoft's current references: [configure ASR rules and exclusions](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure), [ASR exclusion behavior](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-faq), [tamper protection](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection), and [`Unblock-File`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-7.5).

**IMPORTANT:** an exclusion is a reduction in protection, not a trust verdict. Keep it exact, temporary and independently justified.

> Administrator-defined allow lists are a separate App Control for Business
> (WDAC) or AppLocker policy design, outside this framework's configuration.
> Smart App Control uses Microsoft's reputation and signature decisions;
> it does not provide an individual-app exception list. See
> [Microsoft's Smart App Control FAQ](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions).

---

## Use the Framework's Audited ASR Compatibility Choice

**Problem:** ASR blocks installation of legitimate software (e.g., downloaded installers not in Microsoft's reputation database)

**Blocked Rule:** `01443614-cd74-433a-b99e-2ecdc07bfc25` ("Block executable files unless they meet prevalence, age, or trusted list")

Do not disable Tamper Protection or manually overwrite Defender's paired rule-ID/action arrays. That old procedure could modify the wrong element when the GUID was absent, discard concurrent policy state, falsely report success when tamper protection rejected the write, and restore `Block` instead of the actual pre-state.

Use NoID Privacy's own ASR module so the complete effective pre-state is captured before any change, the selected rule modes are read back exactly, and `[R]` can restore the sealed session:

```powershell
.\NoIDPrivacy.ps1 -Module ASR
```

At **ASR Rule: New / Unknown Software**, choose:

- **Y / Audit** — the prompt default — when recurring new-software compatibility is needed. Audit records events but does not block this rule's matches.
- **N / Block** for the stricter setting.

Run the module again and choose **N / Block** when the compatibility period ends. Each successful non-DryRun invocation creates and verifies a new BAVR session. If a management authority or Tamper Protection prevents the requested state, verification fails instead of claiming success. On a managed device, request the change through Intune, Configuration Manager, Defender for Endpoint or the responsible security team.

---

## Windows Insider Program Compatibility

**Problem:** After applying Privacy hardening (MSRecommended mode), Windows Insider enrollment or continued Preview-build eligibility requires a different diagnostic-data setting.

**Cause:** Privacy module sets `AllowTelemetry=1` (Required diagnostic data) via Group Policy, which prevents the user from enabling "Optional diagnostic data" in Settings. Microsoft states that optional diagnostic data must remain enabled to run Insider Preview builds: [official requirement](https://learn.microsoft.com/en-us/windows-insider/data-settings).

**Solution:**

**Step 1: Temporarily remove the telemetry policy** (PowerShell as Admin)

```powershell
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
```

**Step 2: Reboot** (recommended for policy changes to take effect)

```powershell
Restart-Computer
```

**Step 3: Join Windows Insider Program**
1. Go to: Settings > Windows Update > Windows Insider Program
2. Click: **Get Started**
3. When prompted, enable "Optional diagnostic data"
4. Complete Insider enrollment and select your channel (Canary/Dev/Beta/Release Preview)

**Step 4: Keep the required diagnostic-data level while participating**

Do not re-apply a Privacy mode that forces `AllowTelemetry=1` while this device is intended to keep running Insider Preview builds. Doing so disables the required optional diagnostic-data level again. Re-apply the Privacy policy only after leaving the Insider program, or deliberately keep the telemetry policy absent/at the optional level and accept that privacy tradeoff.

---

## Warning: an account can delete or replace items in `C:\ProgramData` or `C:\`

The system check at the start of Apply reports, for example:

```
BUILTIN\Users can delete or replace items in C:\ProgramData (Modify). Programs that keep files under this folder can be tampered with by that account; NoID Privacy verifies its own files and is not affected.
```

- **Cause:** Windows lets only SYSTEM, Administrators and TrustedInstaller own
  these folders or delete, re-permission or take over items in them. Another
  program, a game launcher or a permissions "repair" tool added a broader entry
  or changed the owner. Software that keeps privileged files in `ProgramData`
  can then be tampered with by that account. Apply continues; Restore and
  Verify do not run this check.
- **Earlier 2.2.6 builds** stopped Privacy and AdvancedSecurity in this
  situation with `Hidden worker parent permits replacement by another principal`.
  Current builds verify their temporary helper files by SHA-256 instead. Each
  stopped attempt left an empty folder `C:\ProgramData\NoID-HiddenWorker-<id>`
  that only SYSTEM and Administrators can access; these empty folders can be
  deleted.
- **Check** in an administrator PowerShell:
  ```powershell
  icacls C:\ProgramData
  icacls C:\
  (Get-Acl C:\ProgramData).Owner
  (Get-Acl C:\).Owner
  ```
- **Windows defaults** (names appear in your Windows language):
  - `C:\ProgramData`: owner `NT AUTHORITY\SYSTEM`; `NT AUTHORITY\SYSTEM:(OI)(CI)(F)`,
    `BUILTIN\Administrators:(OI)(CI)(F)`, `CREATOR OWNER:(OI)(CI)(IO)(F)`,
    `BUILTIN\Users:(OI)(CI)(RX)`, `BUILTIN\Users:(CI)(WD,AD,WEA,WA)`.
  - `C:\`: owner `NT SERVICE\TrustedInstaller`; `BUILTIN\Administrators:(OI)(CI)(F)`,
    `NT AUTHORITY\SYSTEM:(OI)(CI)(F)`, `BUILTIN\Users:(OI)(CI)(RX)`,
    `NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)`,
    `NT AUTHORITY\Authenticated Users:(AD)`, plus a read-only app capability
    entry (`S-1-15-3-...:(S,RD,X,RA)`) and a mandatory label.
- **Fix:** first find out which program added the entry; it may only need
  access to its own subfolder. Then remove exactly the entry named in the
  warning: right-click the folder, **Properties > Security > Advanced**, select
  that entry and choose **Remove**. For an owner warning, use **Change** next to
  the owner and enter the default owner listed above. Do not run
  `icacls /reset` or `icacls /remove` on these folders: `/remove` deletes every
  entry of that account, including the defaults above.

---

## Reset and Uninstall

Deleting the NoID Privacy folder undoes nothing. To undo the hardening, first
restore the sessions with `[R]` Restore, newest first, then remove the folder.
Keep its `Backups` folder for as long as you may want to restore a session.

The engine also keeps machine-wide state outside the installation folder, in
`C:\ProgramData\NoID Privacy\EngineState`. Only SYSTEM and Administrators can
write there, and the engine refuses files that another account created or
changed:

| File | Purpose | Delete? |
|---|---|---|
| `last-apply-intent.json` | Choices of the last Apply; Verify compares the PC with them. Restore removes the restored modules' entries and the file with the last one. | Possible. Verify then reports the affected checks as not proven until the next Apply. |
| `asr-runtime-pending.json` | Exists only after an interrupted ASR change; the next Apply or Restore that includes ASR or SecurityBaseline uses it to put Defender's own ASR preference back exactly. | No. Run such an Apply or Restore once; it removes the file when done. |
| `deviceguard-legacy-recovery.json` | Device Guard state from before the first Apply of 2.2.6 or later; restoring a session created by 2.2.5 needs it. | Only if you will never restore a 2.2.5 session. |

Delete these files from an elevated PowerShell. After all sessions are
restored and the installation folder is removed, the whole
`C:\ProgramData\NoID Privacy` folder can be deleted; the next installation
starts without saved choices.

Folders named `C:\ProgramData\NoID-HiddenWorker-<id>` or
`NoID-XboxRecovery-<id>` and scheduled tasks named `NoID-…` exist only while a
step runs. One that is left after a power loss can be deleted when no NoID
Privacy window is open.

## Logs

All operations logged to:
```
Logs/NoIDPrivacy_YYYYMMDD_HHMMSS_fff_<nonce>.log
```

**Example:** `NoIDPrivacy_20251117_142345_123_ab12cd34.log`
