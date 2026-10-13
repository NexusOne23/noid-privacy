# Windows 11 26H2-derived SecurityBaseline provenance, 24H2/25H2 carry-back and deviations

**Review date:** 2026-10-09
**Declared framework scope:** one 425-target profile derived from the Windows 11 v26H2 Security Baseline v2 and admitted on explicit supported Windows 11 24H2, 25H2 and 26H2 x64 client profiles

## Upstream source

The upstream is Microsoft's **Windows 11 v26H2 Security Baseline v2**, published on 2026-10-08 through the [Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10). Microsoft first published the 26H2 baseline on 2026-09-29, the day Windows 11, version 26H2 reached general availability, removed that package from the Download Center on 2026-10-07 and replaced it with v2 "to reflect the general availability of Administrator protection". The package's own release notes (`Documentation/Windows 11 26H2 Security Baseline Release Notes.pdf`) list two changes since the 25H2 baseline plus this Administrator protection update.

On 2026-10-09, the package was retrieved from Microsoft's Download Center through its official HTTPS asset URL:

`https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v26H2%20Security%20Baseline%20v2.zip`

Observed package contract:

| Field | Verified value |
|---|---|
| Download Center filename | `Windows 11 v26H2 Security Baseline v2.zip` |
| Download Center version | `1.0` (shown for the whole toolkit entry); the package name carries `v2` |
| Bytes | `1,328,685` |
| SHA-256 | `369f8dad02485b3fc20be089649a29eb6432a7d0f63cef75addace9685e45d18` |
| ZIP integrity | Every entry passed `unzip -t`; no compressed-data error |

Microsoft’s page does not publish a separate vendor-signed SHA-256. The recorded hash therefore binds the exact artifact retrieved from Microsoft’s official HTTPS asset URL; it is not described as a Microsoft-signed digest.

### Change from the first 26H2 package

The first package (`Windows 11 v26H2 Security Baseline.zip`, 1,213,091 bytes, SHA-256 `bc4c35d8b19fa8863ee37cac24ad518c501913ae4a682aed08190487d5b2f4d2`) is no longer offered. Parsed with the same tool, v2 differs from it in exactly one record: the Computer GPO's security template adds `ConsentPromptBehaviorEnhancedAdmin=4,1` (*User Account Control: Behavior of the elevation prompt for administrators running with Administrator protection* = prompt for credentials on the secure desktop). All 336 registry records, the 23 audit subcategories and every other security-template entry are identical. v2 also exports the eight GPOs under new backup GUIDs with the same names and artifacts.

## Windows 11 25H2 carry-back review

NoID Privacy does not ship a per-release profile, a second BAVR schema or another user
choice. The same 26H2-derived target plan is used on 24H2 and 25H2. Before admitting
that path, the official Microsoft 25H2 package was retrieved again from the same
Download Center entry and compared semantically with the recorded 26H2 source:

| Field | Verified value |
|---|---|
| Download Center filename | `Windows 11 v25H2 Security Baseline.zip` |
| Official HTTPS asset | `https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip` |
| Version | `1.0` |
| Bytes | `1,247,155` |
| SHA-256 | `3517a53030a3e437c9fe00c04274d80965d3527a8eb0514520cba75023c376f7` (identical to the 25H2 package recorded on 2026-07-10) |
| ZIP integrity | Every entry passed `unzip -t`; no compressed-data error |

The 25H2 source contains 437 semantic records and the 26H2 v2 source 438, in
the same eight GPOs. Six identities differ. Four are merely a different order of
the same SIDs in `SeCreateGlobalPrivilege`, `SeImpersonatePrivilege`,
`SeInteractiveLogonRight` and `SeNetworkLogonRight`; security-template semantics
are set-based and therefore unchanged. Two are material:

| Identity | 25H2 source | 26H2 source used by NoID Privacy | 24H2/25H2 conclusion |
|---|---|---|---|
| `SecureProtocols` (Internet Explorer: *Turn off encryption support*) | `2560` (TLS 1.1 + TLS 1.2) | `10240` (TLS 1.2 + TLS 1.3) | Microsoft's release notes call TLS 1.1 obsolete. TLS 1.3 is available on every supported Windows 11 release. Endpoints that WinINet or IE mode can reach only through TLS 1.1 or older stop working on all three releases. |
| `UseWindowsReadyPrintDriverRankingGroupPolicy` (*Configure Windows Ready Print driver ranking*) | Not configured | `1` | The inbox `Printing.admx` policy `ConfigureWindowsReadyPrintDriverRanking` declares `SUPPORTED_Windows_11_0_24H2`. For printers installed through an IPP-capable connection such as USB or network discovery, Windows uses the inbox IPP class driver even when a vendor V3/V4 driver exists; directly added TCP/IP and non-IPP printers are unchanged. Vendor-driver features can be unavailable for affected printers. Windows creates the `DriverRanking` key with a protected DACL (SYSTEM full control, Administrators read only); NoID Privacy writes and restores this value through `REG_OPTION_BACKUP_RESTORE` with `SeRestorePrivilege` and leaves the DACL unchanged. |

The first 26H2 package had also omitted `ConsentPromptBehaviorEnhancedAdmin`; v2
sets the same value `4,1` as the 25H2 source.

Every one of the 336 registry records was also matched against the policy
definitions shipped in Windows 11 26H2 (`C:\Windows\PolicyDefinitions`, 4,237
policies): 255 records declare a minimum release at or before Windows 11 22H2
(including the legacy Internet Explorer templates), 78 are not ADMX-backed and
are unchanged from the 25H2-derived profile already used on 24H2, and three
declare *at least Windows 11, version 24H2*
(`InvalidAuthenticationDelayTimeInMs`, `RpcAuthnLevelPrivacyEnabled` and
`UseWindowsReadyPrintDriverRankingGroupPolicy`). No record requires 25H2 or
26H2. The review conclusion is narrow: the embedded 26H2 profile contains no
value that is unsupported or unsafe merely because the host is 24H2 or 25H2;
it does not claim that every hardening value is compatibility-free.

## Windows 11 24H2 carry-back review

The step from Microsoft's 24H2 to its 25H2 baseline was reviewed on 2026-08-29,
when the 25H2 package became the source of the shared profile. The 26H2 source
re-adds none of the values removed there, so this review still describes every
difference between Microsoft's 24H2 package and the profile used on 24H2:

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

| Identity | 24H2 source | 25H2 and 26H2 source used by NoID Privacy | 24H2 safety conclusion |
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
does not invent a 24H2 registry substitute. NetBIOS, IE COM automation and
command-line auditing retain their documented effects on all three releases.

`Tools/Parse-SecurityBaseline.ps1` fails closed unless the 26H2 package contains the exact eight-GPO/artifact inventory and raw counts (331 computer registry, 5 user registry, 79 security-template and 23 audit entries). `Tools/Test-SecurityBaselineProvenance.ps1` additionally binds the archive bytes, all five embedded artifact hashes and the two permitted product deviations.

## Supported Windows versions

NoID Privacy defines one fully supported 425-target SecurityBaseline/BAVR product contract for Windows 11 24H2, 25H2 and explicitly identified 26H2 clients. The framework admits only an explicit `DisplayVersion=26H2` client in build family `26300..27999`. A missing/mismatched DisplayVersion, 26H1 build family and future/Canary families remain rejected. All three releases use the same Backup, Apply, Verify/HTML and exact Restore lifecycle on Home, Pro and Enterprise.

## Embedded artifact hashes

| Artifact | SHA-256 |
|---|---|
| `AuditPolicies.json` | `0dddae691dbad43ec71f97a84032aaf6eda9ddb4884cb993b37cf6dd86772101` |
| `Computer-RegistryPolicies.json` | `b0f39d0f1e81faf3e752bcbd2ead6f54bbae57b067216cbe9decac3d23e903c2` |
| `SecurityTemplates.json` | `12fd84ee2ecfcdeb3515d08b9fd4a634d3308be6285a1a79cf77b6a538109e93` |
| `Summary.json` | `5aa03d1be0bf2d454eaef7674a0a72d4e1c17836dc1c7a6646edf2ffb6f03c91` |
| `User-RegistryPolicies.json` | `3178f4f031eaef144d23c4435694df2afea75237442a788acf446602120cb3ea` |

These hashes identify the repository artifacts only. They are not Microsoft package hashes.

## Complete source comparison

The official package was extracted outside the repository and every source record was parsed from `registry.pol`, `GptTmpl.inf` and `audit.csv`. Identity, type and data were compared case-sensitively and order-independently against the checked-in JSON profile.

| Source class | Microsoft source | Repository | Result |
|---|---:|---:|---|
| Computer registry, excluding declared deviations | 329 | 329 | Exact semantic match |
| User registry | 5 | 5 | Exact semantic match |
| Security-template entries | 79 | 79 | Exact semantic match |
| Advanced-audit entries | 23 | 23 | Exact semantic match |
| Declared `RDVDenyWriteAccess` deviation | Microsoft `REG_DWORD 1` | NoID Privacy `REG_DWORD 0` | Exact documented deviation |
| Declared `SubmitSamplesConsent` deviation | Microsoft `REG_DWORD 3` | NoID Privacy `REG_DWORD 1` | Exact documented deviation |

Raw Microsoft source total: 336 registry + 79 security-template + 23 audit = 438 parsed entries. The framework executes 425 targets: 12 INF metadata entries (`Unicode`/`Version`) and one native firewall format entry (`WindowsFirewall\PolicyVersion`) are not security settings. The comparison found no data/type/identity deviation beyond the two declared ones.

Reproduction on Windows PowerShell 5.1 (the tool extracts and parses the hash-verified archive itself; no separate extraction is consulted):

```powershell
.\Tools\Test-SecurityBaselineProvenance.ps1 `
    -ArchivePath '.\Windows 11 v26H2 Security Baseline v2.zip'
```

## Framework deviations and application model

- New 2.2.6 Backup, Apply and Verify plans exclude exactly the source entry
  `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PolicyVersion`.
  Microsoft defines it as the [per-store firewall schema version](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/faf4ffbe-1d51-40ad-ae90-2230f2c0b6a9),
  not a security setting. The recorded package contains `REG_DWORD 538`
  (`0x021A`); the native Windows 11 25H2 firewall writer produced `545`
  (`0x0221`). Copying the package value would overwrite newer format metadata.
  The source JSON remains unchanged. The plan validates that exact source
  identity, type and value before excluding it; unrelated values remain owned.
  Historical backups still restore their sealed inventories, including this
  value if recorded. This exclusion does not establish recovery of local-GPO
  files, their revision counters or foreign policy changes.
- New 2.2.6 Apply and verification plans map the four UEFI-lock directives (`RunAsPPL` at both policy/runtime paths, `LsaCfgFlags`, and `HypervisorEnforcedCodeIntegrity`) from source value `1` to enabled-without-lock value `2`. The source JSON and its hashes are retained. This fixed BAVR decision omits additional firmware resistance to privileged reconfiguration so recovery can remain in Windows, with normal restarts and no EFI/BIOS opt-out workflow or added selection. It does not remove existing locks. Historical Restore still uses the recorded prestate. See [firmware and restart recovery](SECURITY-BASELINE-RECOVERY.md).
- `ConsentPromptBehaviorUser` is `0` in the embedded baseline. NoID Privacy retains `0` as the interactive Shell default and accepts the explicit system-wide `1` convenience choice; `3` is never used by this option. Microsoft's current [Windows 11 UAC settings reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration) maps `0` to automatic denial, `1` to credentials on the secure desktop and `3` to credentials on the interactive desktop. Microsoft's archived [policy best-practices reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-account-control-behavior-of-the-elevation-prompt-for-standard-users) recommends the secure-desktop credential choice specifically when users possess separate standard and administrator-level accounts; the strict deny remains the baseline default here. The policy governs standard users and does not change an administrator account's own elevation prompts.
- `ConsentPromptBehaviorEnhancedAdmin` is `1` (credentials on the secure desktop) in the v2 baseline; the [LocalPoliciesSecurityOptions CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions) documents `1` as the default and `2` as consent on the secure desktop. NoID Privacy offers the prompt as an explicit choice (`adminProtectionMode`): `Credentials` keeps Microsoft's `1` with Administrator protection on (`TypeOfAdminApprovalMode=2`), `Consent` writes `2` (Yes/No on the secure desktop), and `Classic` sets `TypeOfAdminApprovalMode=1` and keeps the baseline value `1`, which then has no effect. The value's prestate is sealed with the security-template registry values, and verification expects exactly the selected value. Builds before v2 left the value unset; verification reports it as not set until SecurityBaseline is applied again.
- `RDVDenyWriteAccess` is an informed BitLocker-removable-drive choice rather than an invariant upstream value.
- `SubmitSamplesConsent` is `3` (send all samples automatically) in Microsoft's source. NoID Privacy ships the documented privacy deviation `1` (send safe samples automatically): value 3 can upload files that contain personal information, which a privacy build never enables silently. Cloud protection (`SpynetReporting=2`) and Block-at-First-Seen remain fully active with value 1 per [Microsoft's cloud-protection documentation](https://learn.microsoft.com/en-us/defender-endpoint/enable-cloud-protection-microsoft-defender-antivirus). The interactive Defender sample-submission prompt (default N) or `SecurityBaseline.submitAllSamples=true` restores Microsoft's 3 as a deliberate choice; verification accepts exactly the two decision values 1 and 3.
- `ShellSmartScreenLevel` ships and defaults to Microsoft's `Block`. The Apply prompt (default N), `smartScreenWarnMode=true`, or the Pro GUI's SmartScreen quick action selects the documented security-reducing `Warn` choice; SmartScreen itself stays enforced (`EnableSmartScreen=1` is never optional). The shipped profile data is unchanged, so this is an application-model choice, not a third data deviation; verification accepts exactly `Block` and `Warn`.
- `LocalAccountTokenFilterPolicy` remains the Microsoft baseline `REG_DWORD 0` on standalone and domain-joined systems. This keeps Remote UAC token filtering enabled for network logons made with local administrator accounts: administrative shares and other privileged remote-management operations can return access denied instead of offering an elevation prompt. Interactive RDP sessions and the separate local `ConsentPromptBehaviorUser` policy are unaffected. NoID Privacy adds no implicit remote-administration compatibility exception.
- NoID Privacy writes effective policy registry values and applies selected security-template/audit state with Windows APIs/inbox tools. The eight Device Guard options additionally use the native local GPO store so Windows processes their runtime configuration. Targeted GPO/local prestate is sealed before Save; Restore preserves foreign policy and recorded historical values. This does not recreate Microsoft's complete Local Group Policy object store or claim LGPO-store equivalence. See [Device Guard recovery](SECURITY-BASELINE-RECOVERY.md).
- Missing optional Xbox services and host-inapplicable rights are reported `NotApplicable`; they are not counted as successfully applied.
- Windows 11 24H2, 25H2 and explicit 26H2 clients use the one 26H2-derived profile and exact BAVR contract described above.

## Count boundary

The repository declares 335 registry directives, 67 security-template targets and 23 advanced-audit subcategories: 425 targets total. A successful run requires every applicable target to be applied and verified and every inapplicable target to be explicitly accounted for. The number physically changed on a particular host can therefore be lower than 425.

## Provenance boundary

This evidence proves exact correspondence to the recorded package downloaded from Microsoft's official asset host, except for the two declared product decisions (`RDVDenyWriteAccess`, `SubmitSamplesConsent`). It does not turn the direct policy writes into a Local Group Policy object-store clone or certify policy runtime behavior on every edition.
