# NonInteractive Mode - Interactive-Desktop Automation Guide

## Overview

NoID Privacy supports promptless execution from a logged-on Windows 11 desktop session. `NonInteractive` means that frozen configuration replaces `Read-Host`; it does **not** mean that the complete seven-module profile is safe to run headlessly as `SYSTEM` in session 0.

SecurityBaseline, Privacy and AntiAI contain user-scoped policy targets. They deliberately bind those targets to the interactive Explorer user's loaded HKU hive, including when separate administrator credentials were supplied for UAC elevation. A GPO computer-startup script, service, hosted CI runner or scheduled task configured to run without an interactive desktop cannot establish that identity and the full run must fail closed. Use the repository's guarded, self-hosted Windows 11 BAVR workflow for lab validation; use an interactive elevated session for a real workstation.

---

## Configuration-Based Execution

The framework enters non-interactive mode only when `options.nonInteractive` is `true` or `NOIDPRIVACY_NONINTERACTIVE=true`. Module values in `config.json` are then authoritative inputs instead of prompt answers.

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

**Valid `dohMode` values:** `"REQUIRE"` (no classic-DNS fallback for the managed endpoints) or `"ALLOW"` (fallback explicitly permitted).

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
- `"MSRecommended"` (default, least-disruptive non-relaxing profile; validate it against the target workstation)
- `"Strict"` (broader privacy restrictions; application compatibility must be tested)
- `"Paranoid"` (hardcore, not recommended for production)

**When mode is set:**
- No interactive privacy mode selection prompt
- Direct application of specified mode with warnings logged

**Bloatware removal knobs (both independent of Mode, both default off):**
- `applyStorePackagePolicy` (Boolean, default `false`): Tier 1, Microsoft's native `RemoveDefaultMicrosoftStorePackages` policy for the curated default app list. Its owned policy values have exact prestate restore, but its later app/data deletion does not. It is only ever written on eligible standalone single-session Enterprise/Education, Windows 11 24H2/build 26100+; NotApplicable everywhere else.
- `removeBloatwareApps` (`"none"` default or `"standard"`): Tier 2, classic per-user AppX removal on any edition. This is explicitly and always a best-effort action -- restore is the separate `Restore-BloatwareApps` winget reinstall, never an exact-restore claim.
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

Every live module invocation creates and seals its own exact pre-state backup. This is mandatory and therefore has no configuration switch.

The shipped `config.json` contains the complete decision set. Review every value before enabling non-interactive mode, especially:

- `SecurityBaseline.standardUserElevationMode`: `Strict` automatically denies standard-user elevation; `SecureDesktop` permits standard users to enter separate administrator credentials on the secure desktop.
- `ASR.usesManagementTools`, `allowNewSoftware`, and `continueWithoutCloud`.
- `DNS.provider` and `dohMode`.
- `Privacy.mode`, `disableCloudClipboard`, `applyStorePackagePolicy` (Tier 1 bloatware policy, ENT/EDU 24H2+ only), `removeBloatwareApps` (Tier 2 best-effort removal, non-exact restore), and its conditional `removeWeatherWidget` choice.
- `EdgeHardening.allowExtensions`.
- Every `AdvancedSecurity` choice, including `skipFirewallLayer`; firewall-controller detection is a prefill only and never substitutes for this frozen decision.

---

## Command-Line Execution

For `SecurityBaseline.standardUserElevationMode`, `Strict` sets `ConsentPromptBehaviorUser=0` and provides maximum separation by denying standard-user elevation automatically. `SecureDesktop` sets `ConsentPromptBehaviorUser=1` and permits a standard user to enter separate administrator credentials on the secure desktop. This is a system-wide standard-user choice; it does not change an administrator account's own elevation prompts. Value `3` is never used by this option.

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
# Run verification and export structured JSON
.\Tools\Verify-Complete-Hardening.ps1 -ExportPath "verification-result.json"

# Parse results programmatically
$verification = Get-Content "verification-result.json" | ConvertFrom-Json

if ($verification.VerificationComplete -eq $true -and
    $verification.Failed -eq 0 -and
    $verification.NotChecked -eq 0 -and
    ($verification.Verified + $verification.NotApplicable) -eq $verification.TotalSettings) {
    Write-Output "Every applicable declared target was verified"
    exit 0
} else {
    Write-Error "Verification incomplete: $($verification.Failed) failed, $($verification.NotChecked) not checked, $($verification.NotApplicable) not applicable"
    exit 1
}
```

---

## Environment Variables

| Variable | Status | Description |
|---|---|---|
| `NOIDPRIVACY_NONINTERACTIVE` | ✅ Implemented | Set to `"true"` to force non-interactive mode globally (`Core/NonInteractive.ps1`). |
| `NO_COLOR` | ✅ Implemented | Set to any value to disable ANSI color output in the interactive shell (`NoIDPrivacy-Interactive.ps1`). Cross-platform convention. |
| `NOIDPRIVACY_QUIET` | ✅ Implemented | Set to `"true"` to suppress banner/info output in the interactive shell. |

Provider, privacy mode and the other module decisions are read from `config.json`; no undocumented per-module environment variables are accepted.

---

## Exit Codes (v2.0.0+)

The framework returns structured process exit codes for audited automation:

| Code | Name | Description |
|------|------|-------------|
| **0** | `SUCCESS` | All operations completed successfully |
| **1** | `ERROR_GENERAL` | General/unspecified error |
| **2** | `ERROR_PREREQUISITES` | System requirements not met (OS, PowerShell, Admin) |
| **3** | `ERROR_CONFIG` | Configuration file error (missing, invalid JSON) |
| **4** | `ERROR_MODULE` | One or more modules failed during execution |
| **5** | `ERROR_FATAL` | Fatal/unexpected exception |
| **10** | `SUCCESS_REBOOT` | Success, but reboot is required for changes to take effect |

### **Example: Process Exit Code Handling**

```powershell
# Run hardening and capture exit code
$process = Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `".\NoIDPrivacy.ps1`" -Module All" -Wait -PassThru
$exitCode = $process.ExitCode

switch ($exitCode) {
    0  { Write-Host "SUCCESS: All modules applied" -ForegroundColor Green }
    10 { Write-Host "SUCCESS: Reboot required" -ForegroundColor Yellow; Restart-Computer -Force }
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
# Create a test session on a disposable Windows 11 host
.\NoIDPrivacy.ps1 -Module DNS

# Enumerate validated sessions to choose the exact one just created
. .\Core\Logger.ps1
. .\Core\Config.ps1
. .\Core\Rollback.ps1
$session = Get-BackupSessions |
    Sort-Object Timestamp -Descending |
    Select-Object -First 1
if ($null -eq $session) { throw 'No sealed backup session found' }

# Restore that explicit session in a child process and retain its exit code
$process = Start-Process powershell.exe -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    (Join-Path $PWD 'NoIDPrivacy.ps1'),
    '-RestoreSessionPath', $session.SessionPath
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

    # Run in a child process. NoIDPrivacy.ps1 uses process exit codes; invoking
    # it directly with '&' would exit this wrapper before post-processing.
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

1. ✅ Configure `provider` and `mode` in `config.json`
2. ✅ Use `-Module All` parameter
3. ✅ Enable `-VerboseLogging` for an evidence run
4. ✅ Always test with `-DryRun` first
5. ✅ Keep logs and sealed backup sessions together on the target host
6. ✅ Prove Apply/Verify/Restore on a disposable Windows 11 test machine first

The framework exposes a non-interactive workflow, but unattended deployment is not a substitute for the Windows 11 compatibility and exact-restore validation described above.
