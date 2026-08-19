# Windows 11 25H2-derived SecurityBaseline provenance, 24H2 carry-back and deviations

**Review date:** 2026-08-13
**Declared framework scope:** one 425-target profile derived from the Windows 11 v25H2 Security Baseline and admitted on supported Windows 11 24H2/25H2 clients

## Upstream source

The intended upstream is Microsoft's **Windows 11 v25H2 Security Baseline, version 1.0**, published through the [Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10) and announced by the [Microsoft Security Baselines team](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/windows-11-version-25h2-security-baseline/4456231).

On 2026-07-10, the package was retrieved from Microsoft's Download Center through its official HTTPS asset URL:

`https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip`

Observed package contract:

| Field | Verified value |
|---|---|
| Download Center filename | `Windows 11 v25H2 Security Baseline.zip` |
| Version | `1.0` |
| Bytes | `1,247,155` |
| SHA-256 | `3517a53030a3e437c9fe00c04274d80965d3527a8eb0514520cba75023c376f7` |
| ZIP integrity | Every entry passed `unzip -t`; no compressed-data error |

Microsoft’s page does not publish a separate vendor-signed SHA-256. The recorded hash therefore binds the exact artifact retrieved from Microsoft’s official HTTPS asset URL; it is not described as a Microsoft-signed digest.

## Windows 11 24H2 carry-back review

NoID Privacy does not ship a second 24H2 profile, a second BAVR schema or another user
choice. The same 25H2-derived target plan is used on 24H2. Before admitting that
path, the official Microsoft 24H2 package was retrieved from the same Security
Compliance Toolkit Download Center entry and compared semantically with the
recorded 25H2 source:

| Field | Verified value |
|---|---|
| Download Center filename | `Windows 11 v24H2 Security Baseline.zip` |
| Official HTTPS asset | `https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip` |
| Version | `1.0` |
| Bytes | `1,359,988` |
| SHA-256 | `b75439a231c64edaccaad16a16268d199f56ce78273104e117d893f82cf174a5` |
| ZIP integrity | Every entry passed `unzip -t`; no compressed-data error |

The raw source contains 438 semantic records for 24H2 and 437 for 25H2. Only
12 identities differ. Four are merely a different order of the same SIDs in
`SeCreateGlobalPrivilege`, `SeInteractiveLogonRight`, `SeNetworkLogonRight`
and the pre-existing portion of `SeImpersonatePrivilege`; security-template
semantics are set-based and therefore unchanged. Because
`SeImpersonatePrivilege` also gains one SID, there are nine material deltas:

| Identity | 24H2 source | 25H2 source used by NoID Privacy | 24H2 safety conclusion |
|---|---|---|---|
| `SeImpersonatePrivilege` | Administrators, SERVICE, LOCAL SERVICE, NETWORK SERVICE | Same set plus the restricted `PrintSpoolerService` SID | Additive least-privilege service identity introduced for Windows Protected Print; Microsoft requires it for forward-compatible print operation even when WPP is not enabled. |
| `NoLMHash` | `1` | Not configured | Windows client’s effective default is enabled and Microsoft removed NTLMv1 beginning with 24H2. The 25H2 source no longer materializes this default; it does not enable LM hash storage. |
| `UseLogonCredential` (WDigest) | `0` | Removed | Microsoft states the policy was deprecated starting with a 24H2 update; WDigest is disabled by default. Retaining the obsolete write provides no supported protection. |
| `HideExclusionsFromLocalUsers` | `1` | Removed; `HideExclusionsFromLocalAdmins=1` remains | Microsoft documents that the retained parent setting implicitly enables the local-user restriction. No visibility protection is lost. |
| `DisablePackedExeScanning` | `0` | Removed | Microsoft states the policy is no longer functional and Defender always scans packed executables. |
| PsExec/WMI ASR rule | Absent | Audit (`2`) | The existing Defender rule is observed only; Audit does not block PsExec/WMI execution. NoID Privacy’s separate ASR module may later replace the same owned identity according to its sealed overlap contract. |
| `EnableNetbios` | `2` (disable on public networks) | `0` (disable on all adapters) | Supported by 24H2; this is a deliberate security tightening, not a version incompatibility. It can break legacy single-label/NetBIOS discovery and is reported as such. |
| `DisableInternetExplorerLaunchViaCOM` | Absent | `1` | Supported since Windows 10/IE11 and prevents legacy COM automation. Legacy applications that automate IE can stop working on both 24H2 and 25H2. |
| `ProcessCreationIncludeCmdLine_Enabled` | Absent | `1` | Supported before 24H2 and improves process audit evidence. Command lines can contain sensitive arguments, so access to the local Security log remains privileged and this logging/privacy trade-off is documented rather than called harmless. |

Microsoft’s 25H2 release notes also describe enhanced NTLM auditing as a
25H2 system default that requires no explicit baseline target. NoID Privacy therefore
does not invent a 24H2 registry substitute. The review conclusion is narrow:
the embedded 25H2 profile contains no value that is unsafe merely because the
host is 24H2. It does not claim that every hardening value is compatibility-free.
NetBIOS, IE COM automation and command-line auditing retain their documented
effects on both releases.

`Tools/Parse-SecurityBaseline.ps1` now fails closed unless the 25H2 package contains the exact eight-GPO/artifact inventory and raw counts (330 computer registry, 5 user registry, 79 security-template and 23 audit entries). `Tools/Test-SecurityBaselineProvenance.ps1` additionally binds the archive bytes, all five embedded artifact hashes and the two permitted product deviations.

## Embedded artifact hashes

| Artifact | SHA-256 |
|---|---|
| `AuditPolicies.json` | `b3bb1556301c86067f2f230fbc949660b2f8a0299def613ada0ac015238691b3` |
| `Computer-RegistryPolicies.json` | `002119a81795d1e9c19fea34a40d979b0a4afaf0ac15a1cb349a397f2de1c493` |
| `SecurityTemplates.json` | `f51332d08885419f276529eab934b0d56c653b100b3c79d45c5974e646dff3f2` |
| `Summary.json` | `fb7228ce139f719608990041e87f7a6fe1ef362cb5b53578b68ee6362b19abb5` |
| `User-RegistryPolicies.json` | `9d27162dd31b8bae59d3eae5cb5a0b38a672df75c4344fa16f63be3dc6c06051` |

These hashes identify the repository artifacts only. They are not Microsoft package hashes.

## Complete source comparison

The official package was extracted outside the repository and every source record was parsed from `registry.pol`, `GptTmpl.inf` and `audit.csv`. Identity, type and data were compared case-sensitively and order-independently against the checked-in JSON profile.

| Source class | Microsoft source | Repository | Result |
|---|---:|---:|---|
| Computer registry, excluding declared deviations | 328 | 328 | Exact semantic match |
| User registry | 5 | 5 | Exact semantic match |
| Security-template entries | 79 | 79 | Exact semantic match |
| Advanced-audit entries | 23 | 23 | Exact semantic match |
| Declared `RDVDenyWriteAccess` deviation | Microsoft `REG_DWORD 1` | NoID Privacy `REG_DWORD 0` | Exact documented deviation |
| Declared `SubmitSamplesConsent` deviation | Microsoft `REG_DWORD 3` | NoID Privacy `REG_DWORD 1` | Exact documented deviation |

Raw Microsoft source total: 335 registry + 79 security-template + 23 audit = 437 parsed entries. The framework executes 425 targets because 12 INF metadata entries (`Unicode`/`Version`) are not executable settings. The comparison found no data/type/identity deviation beyond the two declared ones.

Reproduction on Windows PowerShell 5.1 (the tool extracts and parses the hash-verified archive itself; no separate extraction is consulted):

```powershell
.\Tools\Test-SecurityBaselineProvenance.ps1 `
    -ArchivePath '.\Windows 11 v25H2 Security Baseline.zip'
```

## Framework deviations and application model

- `ConsentPromptBehaviorUser` is `0` in the embedded baseline. NoID Privacy retains `0` as the interactive Shell default and accepts the explicit system-wide `1` convenience choice; `3` is never used by this option. Microsoft's current [Windows 11 UAC settings reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration) maps `0` to automatic denial, `1` to credentials on the secure desktop and `3` to credentials on the interactive desktop. Microsoft's archived [policy best-practices reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-account-control-behavior-of-the-elevation-prompt-for-standard-users) recommends the secure-desktop credential choice specifically when users possess separate standard and administrator-level accounts; the strict deny remains the baseline default here. The policy governs standard users and does not change an administrator account's own elevation prompts.
- `RDVDenyWriteAccess` is an informed BitLocker-removable-drive choice rather than an invariant upstream value.
- `SubmitSamplesConsent` is `3` (send all samples automatically) in Microsoft's source. NoID Privacy ships the documented privacy deviation `1` (send safe samples automatically): value 3 can upload files that contain personal information, which a privacy build never enables silently. Cloud protection (`SpynetReporting=2`) and Block-at-First-Seen remain fully active with value 1 per [Microsoft's cloud-protection documentation](https://learn.microsoft.com/en-us/defender-endpoint/enable-cloud-protection-microsoft-defender-antivirus). The interactive Defender sample-submission prompt (default N) or `SecurityBaseline.submitAllSamples=true` restores Microsoft's 3 as a deliberate choice; verification accepts exactly the two decision values 1 and 3.
- `ShellSmartScreenLevel` ships and defaults to Microsoft's `Block`. The Apply prompt (default N), `smartScreenWarnMode=true`, or the Pro GUI's SmartScreen quick action selects the documented security-reducing `Warn` choice; SmartScreen itself stays enforced (`EnableSmartScreen=1` is never optional). The shipped profile data is unchanged, so this is an application-model choice, not a third data deviation; verification accepts exactly `Block` and `Warn`.
- On standalone systems, NoID Privacy can add `LocalAccountTokenFilterPolicy=1` unless the standalone delta is explicitly skipped. This is a NoID Privacy compatibility deviation, not a Microsoft baseline target.
- NoID Privacy writes effective policy registry values directly and applies selected security-template/audit state with Windows APIs/inbox tools. It does not recreate the complete Local Group Policy object store or claim LGPO-store equivalence.
- Missing optional Xbox services and host-inapplicable rights are reported `NotApplicable`; they are not counted as successfully applied.
- Windows 11 24H2 and 25H2 use the one 25H2-derived profile and exact BAVR contract described above. An explicitly reported Windows 11 26H2 preview (`DisplayVersion=26H2`, build `26300..27999`) is admitted only as Experimental: the code executes the same carried-forward 425-target Backup, Apply, Verify/HTML and exact Restore contract because Microsoft has not published a final 26H2 baseline. This technical apply path is currently not runtime-validated or release-approved, and 26H2 equivalence is not asserted.

## Count boundary

The repository declares 335 registry directives, 67 security-template targets and 23 advanced-audit subcategories: 425 targets total. A successful run requires every applicable target to be applied and verified and every inapplicable target to be explicitly accounted for. The number physically changed on a particular host can therefore be lower than 425.

## Provenance boundary

This evidence proves exact correspondence to the recorded package downloaded from Microsoft's official asset host, except for the two declared product decisions (`RDVDenyWriteAccess`, `SubmitSamplesConsent`). It does not turn the direct policy writes into a Local Group Policy object-store clone or certify policy runtime behavior on every edition. The common BAVR implementation is exercised by the disposable Windows 11 release gate without creating a 24H2-specific branch.
