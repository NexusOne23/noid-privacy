# Contributor guide

This guide describes the current engineering contract for adding or changing a NoID Privacy module. The seven production modules are useful references, but the audited tree is not considered release-validated until its Pester suite and destructive BAVR harness pass on a real Windows 11 client VM.

Start from [`Modules/_ModuleTemplate`](Modules/_ModuleTemplate/ModuleTemplate.psd1), then compare the relevant target type with an existing production module. Do not copy a module GUID or introduce a second restore engine.

## Non-negotiable BAVR contract

Every live mutation must satisfy all of these requirements:

1. Define the complete owned target inventory from configuration and frozen user choices.
2. Classify build, edition, product, domain/MDM and feature applicability from authoritative signals. Registry writability is not applicability.
3. Capture exact prestate before Apply: target identity, key/object existence, value type, value data and every owned runtime property.
4. Validate the complete snapshot and artifact inventory before sealing.
5. Reconcile live prestate immediately before and immediately after `Complete-ModuleBackup`.
6. Perform the first mutation only after the second reconciliation succeeds.
7. Apply only the decision-bound targets stored in the sealed snapshot. Do not re-read a mutable configuration file during Apply.
8. Read back every applicable owned target exactly. A query failure, missing target, duplicate identity, wrong type or partial helper result fails the module.
9. Report `Passed`, `Failed`, `NotChecked` and `NotApplicable` distinctly. A skip, DryRun or unselected option is never Applied/Passed.
10. Restore through `Core/Rollback.ps1`'s sealed `Restore-Session` engine in reverse manifest order, then verify exact prestate.
11. Refuse destructive cleanup when an originally absent shared key/object contains later unowned state.
12. Emit exactly one structured module result. Success requires complete Apply and Verify; diagnostic pipeline output must not contaminate the result.

`-SkipBackup` and `-SkipVerify` are not supported and must not exist on a live or scaffold public surface. Backup and exact verification are structural parts of the module contract, not optional switches.

## Required structure

```text
Modules/YourModule/
├── YourModule.psd1
├── YourModule.psm1
├── Config/
├── Private/
│   ├── Get-YourModuleTargetPlan.ps1
│   ├── Backup-YourModuleState.ps1
│   ├── Assert-YourModuleSnapshot.ps1
│   ├── Assert-YourModulePrestate.ps1
│   ├── Set-YourModuleTargets.ps1
│   ├── Test-YourModuleCompliance.ps1
│   └── Restore-YourModuleState.ps1
└── Public/
    └── Invoke-YourModule.ps1
```

The exact filenames can vary, but those responsibilities cannot be omitted. A public standalone restore command must delegate to the canonical sealed-session engine; it must not replay files independently.

## Manifest and loader

- Require Windows PowerShell 5.1 in the manifest and scripts.
- Generate a new GUID with `[guid]::NewGuid()`.
- Export only intentional public functions.
- Do not put real names, e-mail addresses or machine-specific identifiers in metadata. Use `NexusOne23` for the public project identity.
- Missing or invalid private/public files must terminate module import.

Fail-closed loader pattern:

```powershell
$privatePath = Join-Path $PSScriptRoot 'Private'
$publicPath = Join-Path $PSScriptRoot 'Public'
if (-not (Test-Path -LiteralPath $privatePath -PathType Container)) {
    throw "Required Private directory is missing: $privatePath"
}

$privateFiles = @(Get-ChildItem -LiteralPath $privatePath -Filter '*.ps1' -File -ErrorAction Stop)
$publicFiles = @(Get-ChildItem -LiteralPath $publicPath -Filter '*.ps1' -File -ErrorAction Stop)
foreach ($file in @($privateFiles + $publicFiles)) {
    try { . $file.FullName }
    catch { throw "Failed to import '$($file.FullName)': $($_.Exception.Message)" }
}
Export-ModuleMember -Function $publicFiles.BaseName
```

Do not use `-ErrorAction SilentlyContinue` for required file discovery, and do not turn an import failure into a non-terminating warning.

## Lifecycle skeleton

This is deliberately pseudocode: the snapshot schema and artifact types must be designed for the concrete targets.

```powershell
$decision = Get-YourModuleDecision
$plan = Get-YourModuleTargetPlan -Decision $decision

if ($DryRun) {
    $preview = Test-YourModulePlan -Plan $plan
    return [PSCustomObject]@{
        Success = [bool]$preview.Success
        Status = 'DryRun'
        Applied = 0
        Previewed = [int]$preview.Applicable
        NotApplicable = [int]$preview.NotApplicable
        VerificationPassed = $null
        ChangesMade = 0
        Errors = @($preview.Errors)
    }
}

if (-not (Initialize-BackupSystem)) { throw 'Backup initialization failed' }
$modulePath = Start-ModuleBackup -ModuleName 'YourModule'
if (-not $modulePath) { throw 'Module backup folder was not created' }

$snapshot = Backup-YourModuleState -Plan $plan
$artifacts = @($global:BackupIndex | Where-Object Module -eq 'YourModule')
$null = Assert-YourModulePrestate -Snapshot $snapshot -Artifacts $artifacts
if (-not (Complete-ModuleBackup -ItemsBackedUp $artifacts.Count -Status 'Success')) {
    throw 'Module backup could not be sealed'
}
$null = Assert-YourModulePrestate -Snapshot $snapshot -Artifacts $artifacts

$apply = Set-YourModuleTargets -Snapshot $snapshot
$verify = Test-YourModuleCompliance -Snapshot $snapshot
$success = [bool]($apply.Success -and $verify.Compliant)
```

On an unsealed failure, call `Save-IncompleteModuleBackup` only for the active module. It detaches and retains the partial artifacts as a separately listed, non-restorable record; never invalidate or delete an earlier sealed module in the active session.

## Artifact onboarding

`Register-Backup` does not make an arbitrary artifact restorable. A new artifact type/name must also be integrated into all relevant Core contracts:

- manifest schema and exact count validation;
- allowed module/type/name/target combinations;
- path containment and content binding;
- required-artifact checks;
- pre-mutation validation;
- restore dispatch;
- post-restore exact verification;
- overlap ownership and reverse-order/partial-restore safety;
- unit and Windows 11 BAVR tests.

Prefer target-scoped typed JSON over broad registry exports. A `.reg` subtree import is a merge operation and is suitable only where the module explicitly owns the complete subtree and byte-stable re-export proves the restored state. Shared keys normally require value-by-value snapshots.

## Target-specific rules

### Registry

Capture `KeyExisted`, `Exists`, exact registry kind and data. Preserve `ExpandString`, `MultiString` and `Binary` without lossy string conversion. If Apply owns only one value, Restore owns only that value. Verify original key existence after removing an originally absent value, and reject cleanup if later unowned values/subkeys exist.

### Interactive-user state

An elevated PowerShell process can run under a different administrator identity. Resolve the Explorer owner for the current session and bind HKCU intent to that loaded `HKEY_USERS\<SID>` hive. Seal the SID/root and reject drift. Do not enumerate and modify every profile unless that is an explicitly designed, tested ownership model.

### Services

Use a decisive service inventory and require a unique name. Capture startup type, owned runtime state and exact `DelayedAutoStart` existence/type/value. If a module owns startup configuration only, it must not restore runtime status. Do not force-stop dependent services that were not declared and backed up.

### Scheduled tasks

Canonical identity is `\` or `\Folder\` plus the exact task name. Back up the XML definition and enabled state, bind the XML registration URI to the manifest target and require a unique live identity.

### Firewall

Use stable module-owned rule names. Verify the rule and every relevant filter (direction, action, profile, protocol, port side, addresses, application, service, interface and interface type). A firewall-layer skip must become `Skipped`/`NotChecked` in counts and reports. If a whole-policy snapshot is used, prove export stability before relying on byte-exact post-restore comparison.

### Adapters and optional features

Bind adapters by stable GUID plus description and fail on missing/duplicate/replaced identities. Preserve ordered DNS server lists. Optional features must resolve to zero or one exact feature identity; ambiguity fails.

### External tools and native APIs

Check exit codes, output existence and semantic readback. Do not parse localized console prose when a structured/native API exists. Temporary-file cleanup may be best-effort, but cleanup failure must not hide a failed operation.

## DryRun and structured results

DryRun validates configuration, applicability, target uniqueness and declared-count reconciliation. It performs no backup or mutation and returns:

- `Status = 'DryRun'`;
- applied/change counters equal to zero;
- separate preview and NotApplicable counters;
- verification fields equal to `$null` when no verification ran;
- exactly one result object.

Never increment an `Applied` counter in a DryRun branch. Never return scalar `$true` from a public module entry point.

## Testing

Add deterministic tests for:

- configuration/schema parsing and duplicate rejection;
- build, edition, domain/MDM, product and feature applicability matrices;
- incomplete backup and failed sealing before the first mutation;
- both prestate reconciliation gates around `Complete-ModuleBackup`;
- one structured result and exact counters;
- query failures and ambiguous/missing identities;
- wrong type/data and partial helper failure;
- originally absent keys containing later unowned state;
- reverse-order overlap and unsafe partial restore rejection;
- DryRun zero-mutation accounting;
- exact restore failure propagation.

Run locally on Windows PowerShell 5.1:

```powershell
.\Tests\Setup-TestEnvironment.ps1
.\Tests\Run-Tests.ps1 -TestType All -OutputFormat NUnitXml
```

The GitHub-hosted `windows-latest` runner is Windows Server and is not Windows 11 client evidence. Destructive Prestate → Apply → Verify → Restore validation belongs on a disposable, non-domain-joined, interactive Windows 11 client VM using:

```powershell
$env:NOID_DISPOSABLE_VM = 'true'
.\Tests\Windows11\Invoke-Windows11BavrValidation.ps1 -ConfirmDisposableVm
```

For the current release, the VM must use Windows 11 25H2, run in the Explorer user's session, and be disposable. Preserve the generated result JSON, Pester XML and logs as release evidence. Windows 11 26H2 is recognized only as an Experimental Preview and is currently not runtime-validated or release-approved; any future 26H2 gate requires its own complete evidence run.

## Documentation and provenance

- Use Microsoft primary sources for Windows policy names, hives, value types, value semantics, edition/build requirements and current preview behavior.
- Record archive URL, byte size, SHA-256, parser contract and intentional deviations for imported baselines.
- State what exact registry/object state is verified separately from runtime effectiveness.
- Do not claim complete protection, universal compatibility, all-machine backup or fresh test results without corresponding artifacts.
- Update `Config/SettingsCounts.json` only from the canonical target inventory and add a consistency test.
- Provide deterministic evidence (tests or reproducible checks) with the change; real-VM execution gaps must be stated explicitly in the PR.

## Review checklist

- [ ] New GUID and PowerShell 5.1 requirements
- [ ] Complete decision-bound target/applicability plan
- [ ] Typed exact prestate and snapshot validator
- [ ] Two prestate gates around successful sealing
- [ ] First mutation after the second gate
- [ ] Apply only from the sealed plan
- [ ] Exact four-state verification and reconciled counts
- [ ] Canonical Core restore integration and exact post-restore proof
- [ ] Later-unowned-state protection
- [ ] Direct-invocation incomplete-backup cleanup
- [ ] DryRun preview/applied separation
- [ ] Unit, integration and disposable Windows 11 BAVR tests
- [ ] Primary-source claims and documented limitations
- [ ] No telemetry, new third-party calls or sensitive identity data
- [ ] `git diff --check`, JSON/YAML parsing and PowerShell syntax checks are clean

The known external validation gate is the disposable Windows 11 BAVR run
(`Tests/Windows11/Invoke-Windows11BavrValidation.ps1` via the self-hosted workflow).
