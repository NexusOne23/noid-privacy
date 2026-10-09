# NonInteractive Mode - Interactive-Desktop Automation Guide

## Overview

NoID Privacy 2.2.6 supports promptless execution from a logged-on Windows 11 26H2, 25H2 or 24H2 desktop session, using native x64 Windows PowerShell 5.1. `NonInteractive` means that frozen configuration replaces `Read-Host`; it does **not** mean that the complete seven-module profile is safe to run headlessly as `SYSTEM` in session 0.

SecurityBaseline, Privacy and AntiAI contain user-scoped policy targets. They deliberately bind those targets to the interactive Explorer user's loaded HKU hive, including when separate administrator credentials were supplied for UAC elevation. A GPO computer-startup script, service, hosted CI runner or scheduled task configured to run without an interactive desktop cannot establish that identity and the full run must fail closed. Use the repository's guarded, self-hosted Windows 11 BAVR workflow for lab validation; use an interactive elevated session for a real workstation.

---

## Configuration-Based Execution

The framework enters non-interactive mode when the validated configuration has `options.nonInteractive=true`. The optional transport flag `NOIDPRIVACY_NONINTERACTIVE=true` requires that same configuration choice; it cannot enable the mode by itself. Module values in `config.json` are then authoritative inputs instead of prompt answers.

### Required Configuration Keys

The JSON blocks below are explanatory excerpts, not standalone replacement files. Start from the shipped `config.json`: runtime validation requires its exact seven-module schema, canonical version, priorities, supported property names and correctly typed decision values, so a typo or partial file fails before any module mutation.

#### **1. DNS Module - Provider Selection**

```json
{
  "modules": {
    "DNS": {
      "enabled": true,
      "priority": 3,
      "status": "IMPLEMENTED",
      "description": "Secure DNS with DoH",
      "provider": "Quad9",
      "dohMode": "REQUIRE"
    }
  }
}
```

**Valid provider values:**
- `"Quad9"` (default, security-focused, Swiss privacy)
- `"Cloudflare"` (unfiltered resolver with published privacy commitments)
- `"AdGuard"` (ad/tracker blocking)
- `"KEEP"` (preserve current DNS and report the module as skipped)

**Valid `dohMode` values:** `"REQUIRE"` (no classic-DNS fallback for the managed endpoints) or `"ALLOW"` (classic-DNS fallback permitted; when DoH fails and for names that do not exist Windows also sends the lookup unencrypted).

**When provider is set:**
- No interactive DNS provider selection prompt
- Direct application of specified provider
- The LAN-resolver note is still written to the log and `[GUI]` decision
  output: "Your selection replaces network DNS; if your router or LAN
  filtering provides DNS, Skip preserves it."

---

#### **2. Privacy Module - Mode Selection**

```json
{
  "modules": {
    "Privacy": {
      "enabled": true,
      "priority": 4,
      "status": "IMPLEMENTED",
      "description": "Privacy hardening",
      "mode": "MSRecommended",
      "disableCloudClipboard": true,
      "applyStorePackagePolicy": false,
      "removeBloatwareApps": "none",
      "removeWeatherWidget": false
    }
  }
}
```

**Valid mode values:**
- `"MSRecommended"` (default; selects Required diagnostic data and preserves existing app-permission policies; validate it against the target workstation)
- `"Strict"` (broader privacy restrictions; application compatibility must be tested)
- `"Paranoid"` (broadest declared restrictions; can disrupt camera, microphone and other app functions)

**When mode is set:**
- No interactive privacy mode selection prompt
- Direct application of specified mode with warnings logged

**Bloatware removal knobs (both independent of Mode, both default off):**
- `applyStorePackagePolicy` (Boolean, default `false`): Tier 1, Microsoft's native `RemoveDefaultMicrosoftStorePackages` policy for the curated default app list. Its owned policy values have exact prestate restore, but its later app/data deletion does not. It is only ever written on eligible standalone single-session Enterprise/Education, Windows 11 24H2/build 26100+; NotApplicable everywhere else.
- `removeBloatwareApps` (`"none"` default or `"standard"`): Tier 2, classic per-user AppX removal on any edition. Separate `Restore-BloatwareApps` recovery tries recorded local package registration first and verified Store installation through WinGet as fallback. It cannot restore deleted app data or guarantee the original package version.
- `removeWeatherWidget` (Boolean, default `false`): optionally adds `MicrosoftWindows.Client.WebExperience` (the taskbar Weather/Widgets board) to Tier 2. It is valid only when `removeBloatwareApps` is `"standard"`. `false` excludes the component from the selected action and is a fully valid green verification outcome; `true` seals, removes, and verifies it like every other selected Tier 2 package.

---

#### **3. Global Option - Prompt Replacement**

```json
{
  "options": {
    "nonInteractive": true
  }
}
```

`nonInteractive` explicitly replaces all decision prompts with the validated module values. Dry-run and debug logging are explicit entry-point switches (`-DryRun`, `-VerboseLogging`); configuration does not silently enable them. Automatic confirmation and automatic reboot are deliberately unsupported.

If ASR is selected, the framework checks active primary Defender and configured cloud protection **before any module or backup starts**. With unavailable or unknown Defender, or missing cloud protection when `continueWithoutCloud=false`, it returns `PreflightBlocked` without hardening changes.

`options.allowPartialHardening` is optional, Boolean and defaults to `false`. Set it to `true` only after an explicit choice to apply the other modules without ASR. The result remains `Partial` (or `Skipped` if nothing runs), never full success. It does not turn Defender on or weaken the ASR cloud choice. When `continueWithoutCloud=true`, ASR may configure its rules with limited protection; its module status is `Limited` and the overall result is `Partial`. Successfully changed settings still keep their sealed backup and Apply intent.

`Get-HardeningReadiness.ps1` returns read-only schema-1 JSON for the GUI: Defender, cloud configuration, Configuration Manager, edition support and management ownership. Unknown evidence stays unknown. Cloud configuration is not a live cloud-connectivity test; the framework repeats ASR prerequisites at Apply time.

Before a module changes owned settings, it must capture and seal their pre-state backup. This is mandatory and therefore has no configuration switch. Skipped modules and previews do not need a mutation backup; the app/data recovery limits described above still apply.

The shipped `config.json` contains the complete decision set. Review every value before enabling non-interactive mode, especially:

- `SecurityBaseline.standardUserElevationMode`: `Strict` automatically denies standard-user elevation; `SecureDesktop` permits standard users to enter separate administrator credentials on the secure desktop.
- `SecurityBaseline.adminProtectionMode`: `Credentials` keeps Microsoft's Administrator protection with PIN, password or Windows Hello when an app requests administrator rights; `Consent` keeps Administrator protection with a Yes/No prompt; `Classic` turns Administrator protection off.
- `ASR.usesManagementTools`, `allowNewSoftware`, and `continueWithoutCloud`.
- `DNS.provider` and `dohMode`.
- `Privacy.mode`, `disableCloudClipboard`, `applyStorePackagePolicy` (Tier 1 bloatware policy, ENT/EDU 24H2+ only), `removeBloatwareApps` (Tier 2 best-effort removal, non-exact restore), and its conditional `removeWeatherWidget` choice.
- `EdgeHardening.allowExtensions`.
- Every `AdvancedSecurity` choice, including `skipFirewallLayer`; firewall-controller detection is a prefill only and never substitutes for this frozen decision.

---

## Quick Actions

A Quick Action changes only its declared target IDs. It does not run the complete
owning module. Current Windows state and the saved safety snapshot must agree
before a change; if they differ, refresh the state and try again. The engine
never ignores a stale snapshot to force an action. A real change records its
own scope; an already matching state creates no backup. The original nine
actions retain their sealed backups and exact scoped Restore.

Xbox additionally removes or recovers apps. Its backup is explicitly
**settings only**: Restore returns the recorded configuration and leaves
installed apps unchanged. App versions and deleted app data are not restored.
An interrupted Xbox operation requires a fresh settings comparison before
recovery. See [Xbox behavior and recovery](RELEASE-NOTES-2.2.6.md#xbox-quick-action).
Quick Actions are a shared engine interface for Pro; the interactive Shell
does not add a separate Quick Action menu.

## Command-Line Execution

For `SecurityBaseline.standardUserElevationMode`, `Strict` sets `ConsentPromptBehaviorUser=0` and provides maximum separation by denying standard-user elevation automatically. `SecureDesktop` sets `ConsentPromptBehaviorUser=1` and permits a standard user to enter separate administrator credentials on the secure desktop. This is a system-wide standard-user choice; it does not change an administrator account's own elevation prompts. Value `3` is never used by this option.

For `SecurityBaseline.adminProtectionMode`, `Credentials` applies the Microsoft baseline values `TypeOfAdminApprovalMode=2` (Administrator protection) and `ConsentPromptBehaviorEnhancedAdmin=1`: an elevation request asks for PIN, password or Windows Hello. `Consent` keeps Administrator protection and sets `ConsentPromptBehaviorEnhancedAdmin=2`, Microsoft's documented Yes/No prompt on the secure desktop. `Classic` sets `TypeOfAdminApprovalMode=1`: classic User Account Control with the baseline's Yes/No prompt for administrators, for Hyper-V or compatibility problems with elevated WSL and developer tools, which Microsoft lists as reasons not to enable Administrator protection. A change takes effect after a restart; Restore returns both values to their sealed prestate. Administrator protection needs Windows update KB5120998 (August 2026) or later; without it, administrators keep the classic Yes/No prompt and elevated apps run in their own account.

### **Basic Non-Interactive Execution**

```powershell
# Run all enabled modules from config.json
.\NoIDPrivacy.ps1 -Module All

# Run specific module with provider pre-configured
.\NoIDPrivacy.ps1 -Module DNS

# Run with command-line overrides
.\NoIDPrivacy.ps1 -Module Privacy -DryRun

# Run in verbose mode for logging
.\NoIDPrivacy.ps1 -Module All -VerboseLogging
```

---

### **Automated BAVR Validation**

The repository includes `.github/workflows/windows11-bavr.yml`. It is manual, self-hosted and environment-gated because it mutates and restores the Windows host. Its runner must be a disposable Windows 11 client with an interactive Explorer session and administrator execution. It runs deterministic tests, applies the selected modules, performs complete four-state verification, restores the exact sealed session and collects the evidence artifacts.

Do not substitute `windows-latest` or another hosted runner and interpret a checkout/test result as a real Windows 11 BAVR certification. Do not schedule a mutation workflow against a personal or production workstation.

---

## Group Policy and Session-0 Boundary

Do not deploy `-Module All` as a computer-startup GPO, service or `SYSTEM` scheduled task. Session 0 has no authoritative everyday Explorer user, so user-scoped target selection would be unavailable or wrong. The framework refuses that ambiguity instead of silently writing the service account's HKCU hive.

For a managed fleet, translate reviewed settings into the organization's supported Intune, Configuration Manager, Defender, Policy CSP or Group Policy management plane and validate conflict/precedence there. NoID Privacy's local BAVR session is designed for the machine on which it runs; it is not a replacement for an enterprise policy rollback or a claim of Local GPO store equivalence.

---

## Verification Without Interaction

### **Silent Verification**

```powershell
# Use a unique export path so an interrupted run cannot reuse an older result
$exportPath = Join-Path $env:TEMP ('NoIDVerify-' + [guid]::NewGuid().ToString('N') + '.json')
.\Tools\Verify-Complete-Hardening.ps1 -ExportPath $exportPath

# Parse results programmatically
$verification = Get-Content -LiteralPath $exportPath -Raw -Encoding UTF8 -ErrorAction Stop |
    ConvertFrom-Json -ErrorAction Stop
$accounted = $verification.Verified + $verification.Failed +
    $verification.NotChecked + $verification.NotApplicable

if ($verification.VerificationComplete -eq $true -and
    $verification.Failed -eq 0 -and
    $verification.NotChecked -eq $verification.NotCheckedDeliberate -and
    $verification.TotalSettings -eq 703 -and
    $accounted -eq $verification.TotalSettings) {
    Write-Output "All required checks passed; deliberate exclusions remain separate"
    exit 0
} else {
    Write-Error "Required checks failed, lack evidence, or do not reconcile; inspect $exportPath"
    exit 1
}
```

`NotCheckedDeliberate` is the proven by-choice subset of `NotChecked`; those
targets are excluded, not passed. Other NotChecked targets are unresolved
requirements and fail this check. The standalone verifier's process exit code
is not a compliance verdict; use its export or `NOID_VERIFY_JSON` contract.

---

## Environment Variables

| Variable | Status | Description |
|---|---|---|
| `NOIDPRIVACY_NONINTERACTIVE` | ✅ Implemented | Transport flag that requires validated `options.nonInteractive=true`; never an independent prompt override (`Core/NonInteractive.ps1`). |
| `NO_COLOR` | ✅ Implemented | Set to any value to disable color throughout the interactive shell chrome (`NoIDPrivacy-Interactive.ps1`), including banners and startup errors. Module/engine processes keep their own output contract. Cross-platform convention. |
| `NOIDPRIVACY_QUIET` | ✅ Implemented | Set to `"true"` to suppress banner, progress, informational and wait-step output in the interactive shell while retaining menus, prompts, warnings, errors and completion results. |

Provider, privacy mode and the other module decisions are read from `config.json`; no undocumented per-module environment variables are accepted.

---

## Exit Codes (v2.0.0+)

The framework returns structured process exit codes for automation:

| Code | Name | Description |
|------|------|-------------|
| **0** | `SUCCESS` | All operations completed successfully |
| **1** | `ERROR_GENERAL` | General/unspecified error |
| **2** | `ERROR_PREREQUISITES` | System requirements not met (OS, PowerShell, Admin) |
| **3** | `ERROR_CONFIG` | Configuration file error (missing, invalid JSON) |
| **4** | `ERROR_MODULE` | One or more modules failed during execution |
| **5** | `ERROR_FATAL` | Fatal/unexpected exception |
| **10** | `SUCCESS_REBOOT` | Success, but reboot is required for changes to take effect |

The `NOID_RESULT_JSON` summary uses schema 3. Its boolean `requiresReboot` records
applied changes that need a restart independently of overall success. A partially
failed run still returns exit code 4; a restart recommendation does not mean that
the failed modules succeeded. Preview runs always report `requiresReboot: false`.

### **Example: Process Exit Code Handling**

```powershell
# Run hardening and capture exit code
$process = Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `".\NoIDPrivacy.ps1`" -Module All" -Wait -PassThru
$exitCode = $process.ExitCode

switch ($exitCode) {
    0  { Write-Host "SUCCESS: All modules applied" -ForegroundColor Green }
    10 { Write-Host "SUCCESS: Restart Windows when your work is saved" -ForegroundColor Yellow }
    2  { Write-Host "FAILED: Prerequisites not met" -ForegroundColor Red; exit 1 }
    3  { Write-Host "FAILED: Config error" -ForegroundColor Red; exit 1 }
    4  { Write-Host "FAILED: Module errors" -ForegroundColor Red; exit 1 }
    5  { Write-Host "FAILED: Fatal exception" -ForegroundColor Red; exit 1 }
    default { Write-Host "FAILED: Unknown error ($exitCode)" -ForegroundColor Red; exit 1 }
}
```

### **Example: Simple Success/Failure Check**

```powershell
.\NoIDPrivacy.ps1 -Module All
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0 -or $exitCode -eq 10) {
    Write-Host "Hardening completed successfully"
    if ($exitCode -eq 10) { Write-Host "Reboot recommended" }
}
else {
    Write-Host "Hardening failed with exit code: $exitCode"
    # Check logs for details
    $latestLog = Get-ChildItem "Logs" -Filter "NoIDPrivacy_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Get-Content $latestLog.FullName | Select-String "ERROR"
    exit $exitCode
}
```

---

## Best Practices for Automation

### **1. Always Use DryRun First**

```powershell
# Test configuration without applying
.\NoIDPrivacy.ps1 -Module All -DryRun -VerboseLogging

# Review logs before production run
Get-Content "Logs\NoIDPrivacy_*.log" | Select-String "ERROR|WARNING"
```

---

### **2. Centralized Logging**

Configure log aggregation for enterprise deployment:

```powershell
# Example: Copy logs to central location
$logPath = "C:\NoIDPrivacy\Logs"
$centralPath = "\\fileserver\HardeningLogs\$env:COMPUTERNAME"

if (Test-Path $logPath) {
    Copy-Item -Path "$logPath\*" -Destination $centralPath -Recurse -Force
}
```

---

### **3. Rollback Plan**

Always maintain rollback capability. Restore is driven by the functions in
`Core/Rollback.ps1`. The public CLI can restore one explicit sealed session and
returns failure if exact post-restore verification is incomplete:

```powershell
# Record existing sessions on a disposable Windows 11 host
. .\Core\Logger.ps1
. .\Core\Config.ps1
. .\Core\Rollback.ps1
$backupRoot = Join-Path $PWD 'Backups'
$existingIds = @(Get-BackupSessions -BackupDirectory $backupRoot |
    ForEach-Object { $_.SessionId })
$entryPoint = Join-Path $PWD 'NoIDPrivacy.ps1'
$apply = Start-Process powershell.exe -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    "`"$entryPoint`"", '-Module', 'DNS'
) -Wait -PassThru
if ($apply.ExitCode -notin @(0, 10)) { throw "DNS Apply failed: $($apply.ExitCode)" }

# Require exactly one new, validated session rather than guessing by age
$created = @(Get-BackupSessions -BackupDirectory $backupRoot |
    Where-Object { $_.Restorable -and $_.SessionId -notin $existingIds })
if ($created.Count -ne 1) { throw 'Expected one newly sealed DNS session' }
$session = $created[0]

# Restore that explicit session in a child process and retain its exit code
$process = Start-Process powershell.exe -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    "`"$entryPoint`"",
    '-RestoreSessionPath', "`"$($session.SessionPath)`""
) -Wait -PassThru
if ($process.ExitCode -ne 0) {
    throw "Exact session restore failed with exit code $($process.ExitCode)"
}
```

Do not use `Verify-Complete-Hardening.ps1` to prove rollback: that tool verifies the requested hardened profile, whereas a successful restore deliberately returns targets to their captured pre-hardening state. `Restore-Session` performs the target-specific exact restore verification itself and records it in the session restore log.

> Interactive alternative: run `.\NoIDPrivacy.ps1` and choose the **R. Restore Backup**
> menu option to pick a session without scripting.

---

## Troubleshooting Non-Interactive Mode

### **Issue: Still Showing Prompts**

**Cause:** `options.nonInteractive` is false/missing, or the module was invoked directly without loading the framework configuration.

**Solution:**
```json
{
  "options": { "nonInteractive": true },
  "modules": {
    "DNS": { "provider": "Quad9", "dohMode": "REQUIRE" },
    "Privacy": { "mode": "MSRecommended", "disableCloudClipboard": true, "applyStorePackagePolicy": false, "removeBloatwareApps": "none", "removeWeatherWidget": false }
  }
}
```

Keep the other shipped module decision keys in the real `config.json`; the fragment above illustrates only the mode trigger and two modules.

---

### **Issue: Script Fails Silently**

**Cause:** Error suppression in an automation wrapper

**Solution:**
```powershell
# Use verbose logging + error action
.\NoIDPrivacy.ps1 -Module All -VerboseLogging -ErrorAction Stop
```

---

### **Issue: Insufficient Permissions**

**Cause:** Not running as Administrator

**Solution:**
```powershell
# Full seven-module execution requires an elevated interactive Windows 11
# desktop session; SYSTEM/session-0 deployment is intentionally unsupported.
```

---

## Deployment Wrapper Example

```powershell
<#
.SYNOPSIS
    Non-interactive wrapper that preserves NoID Privacy's process exit code
#>

param(
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

try {
    # Pre-flight checks
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Must run as Administrator"
    }

    # Use a child process to capture the CLI exit code independently of this
    # wrapper's own state and retain control of log collection afterwards.
    Write-Output "Starting NoID Privacy hardening..."
    $noidScript = Join-Path $scriptRoot 'NoIDPrivacy.ps1'
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        "`"$noidScript`"", '-Module', 'All', '-VerboseLogging')
    if ($DryRun) { $arguments += '-DryRun' }
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Wait -PassThru

    # Collect logs
    $logPath = "$scriptRoot\Logs"
    $latestLog = Get-ChildItem $logPath -Filter "NoIDPrivacy_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    Write-Output "NoID Privacy exit code: $($process.ExitCode)"
    if ($latestLog) { Write-Output "Log: $($latestLog.FullName)" }
    exit $process.ExitCode
}
catch {
    Write-Error "Hardening failed: $_"
    exit 1
}
```

---

## Summary

**For non-interactive execution:**

1. ✅ Review all shipped decisions and set `options.nonInteractive=true` in `config.json`
2. ✅ Use `-Module All` parameter
3. ✅ Enable `-VerboseLogging` for an evidence run
4. ✅ Always test with `-DryRun` first
5. ✅ Keep logs and sealed backup sessions together on the target host
6. ✅ Prove Apply/Verify/Restore on a disposable Windows 11 test machine first

The framework exposes a non-interactive workflow, but unattended deployment is not a substitute for the Windows 11 compatibility and exact-restore validation described above.
