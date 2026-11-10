# Security and compatibility impact for standalone Windows 11 workstations

This document describes NoID Privacy 2.3.1 on Windows 11 26H2, with the same profile supported on 24H2 and 25H2 (x64). Applications, devices, editions and servicing levels differ; test the selected settings on the target machine.

## 1. Password and elevation policies

The 26H2-derived profile declares `MinimumPasswordLength=14` and `PasswordHistorySize=24` for the local Windows account policy. Those settings govern local account-password handling; they do not define the cloud-side password policy for a Microsoft account. Windows Hello PIN/biometric sign-in is a separate authentication mechanism, but the underlying account and recovery credentials still matter.

`ConsentPromptBehaviorUser` has a separate, explicit choice:

- Strict (`0`) automatically denies standard-user elevation and provides the strongest separation.
- SecureDesktop (`1`) permits standard users to enter separate administrator credentials on the secure desktop. It is a system-wide convenience choice and does not govern an administrator account's own elevation prompts.
- Value `3` is never selected by this option.

The Pro GUI presets Quick & Secure and Balanced apply SecureDesktop `1`;
High Security applies Strict `0`. Running under a separate elevated account
must not silently override the selected machine-wide decision.

Administrator protection (`TypeOfAdminApprovalMode=2`, Microsoft's 26H2 baseline) is a separate, explicit choice for administrator accounts:

- Consent (default) keeps Administrator protection and asks Yes/No on the secure desktop (`ConsentPromptBehaviorEnhancedAdmin=2`). You confirm without entering your PIN or password again; someone at the unlocked PC can also confirm. Elevated apps run in a separate hidden account, so their settings are not shared with the everyday profile.
- Credentials, Microsoft's baseline value, asks for PIN, password or Windows Hello when an app requests administrator rights, which also stops someone at the unlocked PC.
- Classic (`TypeOfAdminApprovalMode=1`) restores classic User Account Control. This is the compatibility choice for Hyper-V, problems with elevated WSL or developer tools, and apps that need to share the everyday and elevated account profiles.

The Pro GUI uses Consent for Quick & Secure and Balanced, and Credentials for
High Security. Custom offers all three administrator-prompt choices and starts
from Consent, like the shell.

Administrator protection needs Windows security update KB5127648 (October 2026) or later and starts after a restart. Microsoft introduced it with the optional non-security update of August 2026 through a gradual rollout and made it generally available, with enterprise management controls, in the optional non-security update of September 2026 (KB5124010), which KB5127648 includes. With earlier updates the policy switches it on only on PCs the rollout has reached; elsewhere administrators keep the classic Yes/No prompt and elevated apps run in their own account. With KB5127648 (builds 26200.9711 and 26300.9711), elevation asked in the "Windows Security" dialog after the restart on a Windows 11 Pro test PC (26H2) and on Windows 11 Enterprise test PCs (25H2 and 26H2). NoID Privacy sets and verifies the policy; Verify does not claim that the feature is active on a given PC.

## 2. BitLocker removable-drive write policy

Microsoft's 26H2 source sets `RDVDenyWriteAccess=1`, which denies write access to removable data drives not protected by BitLocker. NoID Privacy's default is the documented product deviation `0` ("Home Mode"); choosing "Enterprise Mode" at the interactive BitLocker USB prompt restores `1`. This changes policy state only—it does not encrypt a drive or prove that BitLocker is active.

Compatibility consequences of choosing `1` can include read-only removable media until that media satisfies the policy. Keep the default `0` when unencrypted cross-platform removable media is required.

## 2b. Defender sample submission

Microsoft's 26H2 source sets `SubmitSamplesConsent=3`, which uploads any suspicious file sample to Microsoft automatically—including documents that may contain personal information. NoID Privacy's default is the documented privacy deviation `1` (send safe samples only: file types unlikely to contain personal data). Cloud protection (`SpynetReporting=2`) and Block-at-First-Seen remain fully active with `1`. The interactive sample-submission choice (default N) or `submitAllSamples=true` restores Microsoft's `3` deliberately; verification treats exactly `1` and `3` as owned decision values and everything else as failure.

Security consequence of keeping `1`: in the rare case where cloud analysis would need a full document upload to convict a novel threat, detection can be marginally slower. The privacy consequence of `3` is a standing consent to upload potentially personal files; a privacy build never enables that silently.

## 2c. SmartScreen level

Microsoft's 26H2 source sets `EnableSmartScreen=1` with `ShellSmartScreenLevel="Block"`: unrecognized or unsigned downloads are stopped without a "Run anyway" option. Since 2.3.0 NoID Privacy applies `Warn` by default (interactive choice default N, `smartScreenWarnMode=true`, the Pro app's Quick & Secure, Balanced and Custom start value). SmartScreen stays fully active and still warns, and a download the user trusts can be started with "More info > Run anyway". Microsoft's `Block` is the explicit choice: the interactive answer Y, `smartScreenWarnMode=false`, the Pro app's High Security profile or its SmartScreen quick action.

Why `Warn` is the default: `Block` gives no exception, so new or rarely downloaded legitimate programs cannot be started from Explorer at all. On a private PC that tends to end with the whole hardening being restored to install one program. Security consequence of `Warn`: a user who ignores the warning can still run a genuinely malicious file. Defender real-time and cloud protection and the ASR rules stay active either way. `EnableSmartScreen=1` is never optional and keeps its exact verification match.

## 3. Device-installation and DMA-related policy

The baseline-derived registry inventory contains device-installation and DMA-related restrictions, including IEEE 1394-related class entries. NoID Privacy verifies the exact policy values; it does not claim that every physical DMA path is eliminated. Do not edit an unrelated parent value as a supposed temporary bypass. Use the sealed session restore or an administrator-reviewed policy change tied to the exact value that caused the compatibility issue.

## 4. Attack Surface Reduction

The ASR module declares 19 Microsoft Defender identities and applies 18 only when Defender is positively proven to be the primary, active real-time engine. Sixteen applicable rules default to Block and two are explicit Block/Audit choices; Microsoft's operating-system matrix marks the Exchange-server Webshell rule NotApplicable on Windows 11. These controls can block legitimate scripts, macros, management tools or low-prevalence executables. A block is not proof that the file is malicious; inspect Windows Security protection history and the exact ASR rule before adding a narrowly scoped exception.

With a third-party primary endpoint product, ASR is `Skipped`/`NotChecked`; NoID Privacy makes no claim about equivalent vendor controls.

## 5. Legacy protocols and applications

SecurityBaseline disables SMBv1 and LLMNR through Microsoft's baseline policies, and the AdvancedSecurity choices can disable or block NetBIOS helper/name-resolution state, LLMNR traffic, WPAD, UPnP/SSDP and legacy TLS. Older NAS devices, printers, discovery/casting workflows and management tools may rely on one or more of these. The module reports the exact selected service, registry and firewall state; it does not promise that every application remains compatible. Windows PowerShell 2.0 is not a new-run target because Microsoft removed it from updated Windows 11 24H2 and later. Its historical reader exists only for already sealed v2.2.5 sessions: it restores while Windows still exposes the recorded feature identity and fails closed after servicing removes it.

## 6. AI policy scope

AntiAI writes the edition/preview-applicable subset of 50 typed registry targets, including policies staged ahead of the Windows or app update that adds their feature, and removes two URI handlers from their four real source hives. Exact policy/source-hive state is verified. Runtime effect is deliberately narrower:

- The current Copilot MSIX app is not claimed removed or AppLocker-blocked.
- Microsoft Edge Update reads its policies only on domain-joined or MDM-enrolled devices. On other PCs the Copilot install block would have no effect, so AntiAI does not write it there and nothing stops Edge Update from installing the Copilot app.
- Both `AllowRecallEnablement=0` and `DisableAIDataAnalysis=1` delete existing Recall snapshots. The former also removes the component after restart. Registry Restore cannot recover those snapshots or automatically reinstall the component. [Microsoft's Recall policy contract](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableaidataanalysis).
- Notepad's documented AI policy controls its writing tools on supported app versions. Paint's policies cover Cocreator, Generative Fill and Image Creator; they do not promise removal of its Copilot container or Generative Erase. Microsoft provides no corresponding Generative Erase policy in the reviewed contract.
- Edge's Copilot policies have product and management prerequisites. The Enterprise new-tab policy `NewTabPageBingChatEnabled=0` does not establish universal coverage of local, unsigned Home/Pro browser profiles; a mandatory policy status alone is not proof that every Copilot entry point is disabled.
- Click to Do and the Settings Agent are staged on eligible editions; the features themselves run only on eligible Copilot+ PCs. Agent controls remain subject to their documented edition/preview applicability.

See [Windows AI applicability](WINDOWS-AI-APPLICABILITY.md) for the current 24H2/25H2/26H2 boundary.

## 7. Recovery rule

Use the interactive `[R]` restore for the exact sealed session and review its notes: a key that now also holds settings from someone else is kept and those settings are named. BAVR covers declared NoID Privacy-owned mutations; retain an independent system image or VM snapshot for failures outside that scope.
