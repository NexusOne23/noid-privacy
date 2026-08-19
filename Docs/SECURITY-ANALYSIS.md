# Security and compatibility impact for standalone Windows 11 workstations

This document describes likely user-visible effects of the declared policy state. It is not a compatibility guarantee: applications, devices, Windows editions and servicing levels differ, and runtime behavior must be tested on the target machine.

## 1. Password and elevation policies

The 25H2-derived profile declares `MinimumPasswordLength=14` and `PasswordHistorySize=24` for the local Windows account policy. Those settings govern local account-password handling; they do not define the cloud-side password policy for a Microsoft account. Windows Hello PIN/biometric sign-in is a separate authentication mechanism, but the underlying account and recovery credentials still matter.

`ConsentPromptBehaviorUser` has a separate, explicit choice:

- Strict (`0`) automatically denies standard-user elevation and provides the strongest separation.
- SecureDesktop (`1`) permits standard users to enter separate administrator credentials on the secure desktop. It is a system-wide convenience choice and does not govern an administrator account's own elevation prompts.
- Value `3` is never selected by this option.

## 2. BitLocker removable-drive write policy

Microsoft's 25H2 source sets `RDVDenyWriteAccess=1`, which denies write access to removable data drives not protected by BitLocker. NoID Privacy's default is the documented product deviation `0`; the interactive Enterprise choice restores `1`. This changes policy state only—it does not encrypt a drive or prove that BitLocker is active.

Compatibility consequences of choosing `1` can include read-only removable media until that media satisfies the policy. Keep the default `0` when unencrypted cross-platform removable media is required.

## 2b. Defender sample submission

Microsoft's 25H2 source sets `SubmitSamplesConsent=3`, which uploads any suspicious file sample to Microsoft automatically—including documents that may contain personal information. NoID Privacy's default is the documented privacy deviation `1` (send safe samples only: file types unlikely to contain personal data). Cloud protection (`SpynetReporting=2`) and Block-at-First-Seen remain fully active with `1`. The interactive sample-submission choice (default N) or `submitAllSamples=true` restores Microsoft's `3` deliberately; verification treats exactly `1` and `3` as owned decision values and everything else as failure.

Security consequence of keeping `1`: in the rare case where cloud analysis would need a full document upload to convict a novel threat, detection can be marginally slower. The privacy consequence of `3` is a standing consent to upload potentially personal files; a privacy build never enables that silently.

## 2c. SmartScreen level

Microsoft's 25H2 source sets `EnableSmartScreen=1` with `ShellSmartScreenLevel="Block"`: unrecognized or unsigned downloads are stopped without a "Run anyway" option. NoID Privacy applies `Block` by default. The interactive choice (default N), `smartScreenWarnMode=true`, or the Pro GUI's SmartScreen quick action selects `Warn` — SmartScreen stays fully active and still warns, but trusted downloads regain the bypass. `Warn` is a documented security-reducing choice: it re-opens the path where a user can run a genuinely malicious file after ignoring the warning. `EnableSmartScreen=1` is never optional and keeps its exact verification match.

## 3. Device-installation and DMA-related policy

The baseline-derived registry inventory contains device-installation and DMA-related restrictions, including IEEE 1394-related class entries. NoID Privacy verifies the exact policy values; it does not claim that every physical DMA path is eliminated. Do not edit an unrelated parent value as a supposed temporary bypass. Use the sealed session restore or an administrator-reviewed policy change tied to the exact value that caused the compatibility issue.

## 4. Attack Surface Reduction

The ASR module declares 19 Microsoft Defender identities and applies 18 only when Defender is positively proven to be the primary, active real-time engine. Sixteen applicable rules default to Block and two are explicit Block/Audit choices; Microsoft's operating-system matrix marks the Exchange-server Webshell rule NotApplicable on Windows 11. These controls can block legitimate scripts, macros, management tools or low-prevalence executables. A block is not proof that the file is malicious; inspect Windows Security protection history and the exact ASR rule before adding a narrowly scoped exception.

With a third-party primary endpoint product, ASR is `Skipped`/`NotChecked`; NoID Privacy makes no claim about equivalent vendor controls.

## 5. Legacy protocols and applications

The AdvancedSecurity choices can disable or block SMBv1-related components, NetBIOS helper/name-resolution state, LLMNR, WPAD, UPnP/SSDP and legacy TLS. Older NAS devices, printers, discovery/casting workflows and management tools may rely on one or more of these. The module reports the exact selected service, registry and firewall state; it does not promise that every application remains compatible. Windows PowerShell 2.0 is not a new-run target because Microsoft removed it from updated Windows 11 24H2 and later. Its historical reader exists only for already sealed v2.2.5 sessions: it restores while Windows still exposes the recorded feature identity and fails closed after servicing removes it.

## 6. AI policy scope

AntiAI writes only the build/edition/product-applicable subset of 43 typed registry targets and removes two URI handlers from their four real source hives. Exact policy/source-hive state is verified. Runtime effect is deliberately narrower:

- The current Copilot MSIX app is not claimed removed or AppLocker-blocked.
- Recall component removal can require restart and supported hardware/edition.
- Notepad's documented AI switch removed its writing-tools control in the 25H2 VM test. Paint's three documented policies removed Image Creator but did not remove the Copilot container or Generative Erase in Paint 11.2603.251.0; Microsoft currently documents no Generative Erase policy.
- Edge's documented policies removed the toolbar/sidepane controls in Edge 150. `NewTabPageBingChatEnabled=0` was loaded as mandatory with status `OK`, but did not remove the active search-box Copilot control from an unsigned local Workgroup profile. It is retained for Microsoft's documented Edge Enterprise new-tab scope and is not claimed as universal local/Home/Pro coverage.
- Click to Do, Settings Agent and agent controls remain subject to their documented hardware/edition/preview applicability.

See [Windows AI applicability](WINDOWS-AI-APPLICABILITY.md) for the current 25H2/26H2 boundary.

## 7. Recovery rule

Use the interactive `[R]` restore for the exact sealed session and review any fail-closed conflict with later unowned state. BAVR covers declared NoID Privacy-owned mutations; retain an independent system image or VM snapshot for failures outside that scope.
