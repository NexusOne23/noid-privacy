# 🔧 Troubleshooting

Common issues and step-by-step fixes for NoID Privacy. See the main [README](../README.md) for installation and feature documentation.

---

## Common Issues

**An older session containing ASR refuses to restore**
- Current ASR BAVR uses schema 5: all 18 Windows-client targets are applied through target-scoped Defender policy values, with sealed exact per-GUID policy prestate, created-ancestor state and native value-name casing. This prevents a merged policy-derived `Get-MpPreference` view from being materialized into unrelated local Defender state during a multi-module run. Sealed schema 3 and 4 sessions remain restorable with their original semantics. Older ASR artifacts cannot prove which target values the framework owned, so converting them would risk deleting unrelated or later Defender state.
- The restore engine therefore rejects that ASR artifact fail-closed and reports the session failure; it does not claim partial-session success.
- Keep the old session directory unchanged for forensic/manual comparison. Use its captured data only for an administrator-reviewed manual recovery; do not copy or rename it into a current sealed session.
- Newly created sessions use schema 5 and are the supported automated restore path.

**"...cannot be loaded because running scripts is disabled on this system"**
- Cause: Windows 11 clients ship with the `Restricted` execution policy, and a file downloaded with `Invoke-WebRequest` additionally carries the internet mark-of-the-web. Both block a direct `& .\Script.ps1` call — this is Windows' default, not a NoID Privacy setting.
- Supported start for the downloaded bootstrap: `& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $installer`. The relaxation applies to that one process; the machine-wide policy is not changed and needs no cleanup afterwards.
- After installation always start through `Start-NoIDPrivacy.bat`, which already launches the framework the same way and requests elevation.
- On a managed device where Group Policy defines the execution policy, the process-level value is ignored by design. Ask the administrator for an approved start path instead of weakening the policy machine-wide.

**"Access Denied" errors**
- Not running as Administrator
- Right-click PowerShell → "Run as Administrator"

**Standard user sees "This program is blocked by group policy" instead of an administrator password prompt**
- Cause: the security baseline applies `ConsentPromptBehaviorUser = 0` (automatically deny standard-user elevation requests). Installs then require a full administrator sign-in.
- To permit standard users to enter separate administrator credentials, rerun the SecurityBaseline module and choose `[Y]` at the "Standard User - Administrator Elevation" prompt (or set `standardUserElevationMode` to `SecureDesktop` in `config.json`). The interactive Shell asks this machine-wide question even when the current everyday account is an administrator. That writes `ConsentPromptBehaviorUser = 1` and keeps credential entry on the secure desktop.
- This policy governs standard users only. Selecting `SecureDesktop` does not change an administrator account's own elevation prompts.
- The choice is recorded in logs and reports as a user-selected documented deviation, not drift; `[R]` Restore reverts the value to its sealed prestate.

**VBS/Credential Guard not active after reboot**
- Credential Guard requires Windows 11 Enterprise or Education
- Check Secure Boot, firmware virtualization, VM-monitor extensions and SLAT; the hardware report keeps query failure distinct from a confirmed Disabled result
- TPM strengthens Credential Guard by hardware-binding its keys, but Microsoft's current [Credential Guard requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/) describe TPM as recommended rather than mandatory (TPM 1.2 and 2.0 are supported there)
- Enable virtualization in BIOS/UEFI
- Verify: `.\Tools\Verify-Complete-Hardening.ps1`

**BitLocker not activating**
- Check edition, TPM readiness, disk layout/space and the exact BitLocker event/error; do not infer one cause from an inactive volume
- Check TPM: `Get-Tpm`
- A compatible TPM enables the normal transparent startup path. On supported editions, [Microsoft's BitLocker configuration reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure#require-additional-authentication-at-startup) also permits a deliberately configured non-TPM path with a startup USB key or password; that is a different security and recovery model
- Manual activation: Control Panel → BitLocker

**Can't install software after hardening?**
- Defender controls applied by NoID Privacy (the ASR "prevalence" rule, SmartScreen set to *Block*, and PUA protection) can block unsigned or unrecognized downloads.
- The cleanest framework rollback is the interactive **`[R]` Restore from Backup** menu. It restores and verifies every sealed NoID Privacy-owned target in the selected session; it does not replace an independent system backup and fails closed if later unowned state would need destructive removal.
- To keep the hardening on and allow *individual* trusted files, see [Allow Specific Files While Keeping Hardening On](#allow-specific-files-while-keeping-hardening-on-per-file) (recommended).
- For recurring new-software work, see [Use the Framework's Audited ASR Compatibility Choice](#use-the-frameworks-audited-asr-compatibility-choice).
- The **SmartScreen level choice** switches the OS SmartScreen level from *Block* to *Warn*: SmartScreen stays active but restores the "Run anyway" option for downloads you trust. Shell users get the choice during SecurityBaseline Apply (or via `smartScreenWarnMode` in `config.json`); NoID Privacy Pro users can flip it any time with the SmartScreen quick action and its sealed backup session, and switch back to *Block* the same way when done.

**Widgets / taskbar weather still visible after a Strict or Paranoid apply**
- Cause: Windows 11's User Choice Protection Driver (UCPD) blocks command-line writes to the only policy lever for the Widgets board (`HKLM:\SOFTWARE\Policies\Microsoft\Dsh\AllowNewsAndInterests`). With an active UCPD driver the framework fails closed: nothing is written and the target is honestly reported as `NotApplicable` -- this is the OS protecting the value, not an incomplete apply.
- Note the distinction: the *BingWeather app* is removed by Tier 2 as sealed; the taskbar weather flyout belongs to the separate Widgets/Web Experience component.
- Supported removal path: select Tier 2, then answer Yes to its separate default-No Weather/Widgets question. That adds the "Windows Web Experience Pack" (`MicrosoftWindows.Client.WebExperience`) for the current user without touching the UCPD-protected policy. Answering No is a valid green verification outcome. Manual alternative: Settings > Personalization > Taskbar > Widgets = Off.

**Apps removed by Tier 2 are not reinstalled by [R] Restore**
- By design: the exact restore only re-applies sealed prestate values; a Store reinstall can never be exact (version, app data, licensing and provisioning differ), so it is a separate, explicitly best-effort step.
- Run it as the original user after the session restore: `Import-Module '.\Modules\Privacy\Privacy.psd1'; Restore-BloatwareApps -SessionPath '.\Backups\<session folder>'`. The command validates the sealed manifest and catalog binding, refuses to run under a different account, and reports skipped or failed reinstalls honestly.

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

> For a true default-deny "only things I have explicitly approved can run" model, the Windows-native tools are WDAC, AppLocker, or Smart App Control (publisher- or hash-based allow rules). NoID Privacy does not configure those, and they are heavy for a personal PC — but they are the right path if you want full allow-listing.

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
4. Complete Insider enrollment and select your channel (Dev/Beta/Release Preview)

**Step 4: Keep the required diagnostic-data level while participating**

Do not re-apply a Privacy mode that forces `AllowTelemetry=1` while this device is intended to keep running Insider Preview builds. Doing so disables the required optional diagnostic-data level again. Re-apply the Privacy policy only after leaving the Insider program, or deliberately keep the telemetry policy absent/at the optional level and accept that privacy tradeoff.

---

## Logs

All operations logged to:
```
Logs/NoIDPrivacy_YYYYMMDD_HHMMSS_fff_<nonce>.log
```

**Example:** `NoIDPrivacy_20251117_142345_123_ab12cd34.log`
