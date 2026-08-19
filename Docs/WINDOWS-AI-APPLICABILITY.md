# Windows 11 AI applicability contract

**Primary-source review date:** 2026-07-12
**Framework scope:** Windows 11 24H2 and 25H2, plus an explicitly admitted Windows 11 26H2 Experimental Preview apply path that is currently not runtime-validated or release-approved.

This document separates three facts that must not be collapsed into one success claim:

1. NoID Privacy wrote and read back the exact owned registry/source-hive state.
2. Microsoft documents the policy for this Windows build, edition, geography, and product version.
3. The product/runtime demonstrably enforced the requested behavior.

AntiAI verification proves item 1 only for the item-2-applicable subset. Targets outside documented build, edition, preview, geography, or product-version constraints are not written or restored and are reported individually as `NotApplicable`. It does not infer item 3 from registry presence.

## Windows release profiles

- 24H2 (`26100`) and 25H2 (`26200`) are stable framework profiles.
- 26H2 is admitted only as an Experimental Preview when Windows explicitly reports `DisplayVersion=26H2` with build `26300..27999`; the framework then runs Backup, Apply, Verify/HTML and Restore for every enabled, applicable target. It is currently not runtime-validated or release-approved. A build-family guess with a missing/different DisplayVersion is rejected.
- Microsoft's 19 June 2026 announcement first labels the branch as 26H2 Experimental and confirms that it is delivered as an enablement package from 25H2 on the same servicing branch. It also states that 26H1 build `28000` uses a different core and is not an upgrade path to 26H2: [official Windows Insider announcement](https://blogs.windows.com/windows-insider/2026/06/19/announcing-new-builds-for-19-june-2026-26h2-for-experimental/).
- The latest primary release notes reviewed for this audit are Microsoft's 6 July 2026 [Experimental build 26300.8772 notes](https://learn.microsoft.com/en-us/windows-insider/release-notes/experimental/preview-build-26300-8772). Microsoft's [same-day overview](https://blogs.windows.com/windows-insider/2026/07/06/announcing-new-builds-for-july-6-2026/) labels the linked Experimental release `26300.8782`, while the detailed release-note title and its 26H2 reminder both say `26300.8772`. The framework therefore intentionally validates the release family (`26300..27999` plus explicit `DisplayVersion=26H2`) rather than hard-coding a disputed or single UBR, so later 26H2 servicing revisions remain classifiable without admitting 26H1/future-core builds.

Experimental support is a real technical execution path, not detection-only: enabled modules run their build-/edition-applicable targets through the same sealed BAVR lifecycle. It is not a promise that Insider-only policy names or behavior will remain unchanged before general availability, and it is not release approval.

## WindowsAI policies

The canonical source is Microsoft's current [WindowsAI Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai), updated 2026-06-23.

| Control | Framework state | Microsoft applicability / caveat |
|---|---|---|
| `AllowRecallEnablement=0` | Applied only when applicable | Pro+ and Windows 11 24H2 KB5055627 (`26100.3915`)+. |
| `DisableAIDataAnalysis=1` | Applied only when applicable | Pro+ and Windows 11 24H2 `26100.3915`+. |
| Recall deny lists | Applied subset uses enable DWords plus separate list strings | Enterprise/Education/IoT; `26100.3915`+; restart required. |
| Recall storage limits | Applied only when applicable | Enterprise/Education/IoT; `26100.3915`+. |
| `AllowRecallExport=0` | Not written | Insider Preview, commercial editions, and EEA-only. NoID Privacy has no authoritative device-geography attestation and therefore does not claim this target. |
| Agent connector/workspace controls | Force Disable (`2`) only when applicable | Recognized 26H2 Experimental Preview/Insider profile and Enterprise/Education/IoT Enterprise only. The 26H2 path is currently not runtime-validated or release-approved; stable 25H2 is left untouched. |
| `AgentConnectorMinimumPolicy=1` | Restricted floor only when applicable | Same preview/edition constraint; `2` means Bypass and is not used. |
| `AgentConsentDuration=1` | Minimum documented lifetime only when applicable | Same preview/edition constraint; valid range 1–8760 hours. |
| `AgentConnectorAccessPolicy` | Not configured | Microsoft says the value is a JSON allowlist, but its current schema link redirects back to the CSP page and publishes no schema/example. NoID Privacy does not invent a security-policy format; the separate connector policies are force-disabled. |
| `DisableSettingsAgent=1` | Applied on documented servicing-level commercial profiles | Microsoft documents the Settings Agent from Windows 11 24H2 KB5062660 (`26100.4770`) onward and says the 25H2 feature update ends its temporary enterprise-feature-control hold. Runtime presence still requires an eligible Copilot+ PC. |
| `DisableClickToDo=1` | Applied on documented servicing-level Pro+ profiles | Microsoft documents the policy for Click to Do, which arrived with KB5055627 (`26100.3915`); the 25H2 feature update ends its temporary enterprise-feature-control hold. The feature itself still requires a Copilot+ PC or eligible Cloud PC. |
| `RemoveMicrosoftCopilotApp` | Excluded from reversible AntiAI | AntiAI never turns this destructive policy on. Microsoft Copilot package removal is available only after the user separately selects Privacy Tier 1 or Tier 2; exact policy/registry prestate remains BAVR, while app/data recovery is explicitly best effort. |

The official [enterprise feature-control table](https://learn.microsoft.com/en-us/windows/whats-new/temporary-enterprise-feature-control) records that the Windows 11 25H2 feature update ends the temporary hold for Settings Agent and Click to Do, while their dedicated management pages document the permanent controls and hardware requirements. Those newer, feature-specific sources take precedence over the consolidated WindowsAI CSP rows that still say Insider Preview. The planner therefore applies the policies on supported servicing levels and editions, while continuing to describe runtime feature presence as hardware-dependent. No Microsoft policy named `HideAIActionsMenu` exists in the official 25H2 ADMX package, so that previously declared value was removed.

## Other current 26H2 changes reviewed

The 6 July 2026 Experimental notes add Cloud rebuild, a refreshed Account Control flyout, and default Windows settings backup/restore on eligible Microsoft Entra joined or hybrid-joined commercial devices. None introduces a new WindowsAI policy target, so no extra AntiAI registry value is fabricated.

The settings-backup change is nevertheless privacy-relevant: Privacy `Strict` and `Paranoid` set the documented `DisableSettingSync=2` and `DisableSettingSyncUserOverride=1` controls and the separately documented `EnableWindowsBackup=0` disabled state. The first pair blocks all preference groups and user override; the third prevents the periodic Windows settings/app-list cloud-backup job. These ADMX-backed policies are documented for Pro, Enterprise, Education and IoT Enterprise, not Home. `MSRecommended` deliberately preserves the user's existing Settings Sync/Windows Backup policy instead of silently overriding account backup behavior. A user on an applicable edition who wants both preference roaming and periodic Windows cloud backup disabled must therefore choose `Strict` or `Paranoid`; Home is reported `NotApplicable` until a separately validated Home mechanism exists.

## Current Copilot app

Microsoft states that the deprecated `TurnOffWindowsCopilot` policy does not control the current Copilot experience and recommends AppLocker for the consumer `MICROSOFT.COPILOT` package. A publisher rule covers installation and launch: [Microsoft's current Copilot management guidance](https://learn.microsoft.com/en-us/windows/client-management/manage-windows-copilot).

AppLocker enforcement requires the Application Identity (`AppIDSvc`) service. Microsoft documents that stopping the service disables enforcement, recommends Automatic startup for Group Policy, and warns that the protected service cannot be reset to Manual with `sc.exe`: [Application Identity service guidance](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-the-application-identity-service).

For that reason NoID Privacy does not silently enable AppLocker/AppIDSvc inside AntiAI and then claim exact BAVR. Reversible AntiAI does not promise to block the current Copilot MSIX from reinstalling or launching. Users who explicitly select Privacy's existing destructive Tier 1 or Tier 2 app-removal choice also select the exact `Microsoft.Copilot` package: its sealed package identities and Store ID support honest best-effort recovery, never exact app-data or version restoration. With both app-removal tiers left off, Copilot is not uninstalled.

## Product-specific policies

- Notepad `DisableAIFeatures=1` is documented for Windows 11 22H2+ with Notepad `11.2503.16.0`+ and has no edition restriction on the feature-specific page; it is therefore planned on Home as well when the package version qualifies: [Notepad AI management](https://learn.microsoft.com/en-us/windows/client-management/manage-notepad).
- Paint Cocreator, Generative Fill, and Image Creator policies are documented in the WindowsAI CSP with Windows 11 build floors. On the German 25H2 VM, Paint 11.2603.251.0 consumed `DisableImageCreator=1`, but its Copilot container and Generative Erase remained. Microsoft currently publishes no Generative Erase policy, so NoID Privacy does not claim complete Paint-AI removal.
- Edge policies are versioned independently from Windows. Edge 150 consumed the sidebar/toolbar controls. It also loaded the documented `NewTabPageBingChatEnabled=0` policy (Edge 117+) as mandatory with status `OK`, but an unsigned local Workgroup profile still exposed an active search-box `Open Copilot` control. Microsoft describes this target for the Edge Enterprise new-tab page; NoID Privacy therefore retains the documented target without treating it as local/MSA/Home/Pro coverage. `CopilotNewTabPageEnabled` likewise applies only to Entra Edge-for-Business profiles.
- `LetAppsAccessGenerativeAI` is retained as a policy-catalog compatibility target, but it is not treated as a blanket switch for every Windows or third-party AI feature.

## Unsupported or unsafe mechanisms excluded

- Protected `IntegratedServicesRegionPolicySet.json` edits.
- Hosts-file blocks against shared Microsoft/Bing endpoints.
- Runtime `CapabilityAccessManager\ConsentStore` writes (for example the
  `systemAIModels` global `Value=Deny` applied by earlier versions): consent-store
  entries are runtime state, not documented policy, and are excluded from the
  exact-BAVR target set.
- Wildcard Copilot/Recall AppX removal, or any automatic uninstall outside Privacy's explicit destructive app-removal tiers.
- Undocumented `HideAIActionsMenu`.
- Undocumented community keys `Explorer\DisableWindowsCopilot` and
  `AppPrivacy\LetAppsAccessSystemAIModels`: neither name exists in the official
  25H2 ADMX/CSP documentation, so earlier writes of both were removed with the
  same reasoning as `HideAIActionsMenu`.
- User-scope (HKCU) duplicates of `DisableAIDataAnalysis` and `DisableClickToDo`:
  the enforced device-scope (HKLM) policy already governs the machine, so the
  redundant per-user variants written by earlier versions are deliberately not
  declared as targets.
- Invented `AgentConnectorAccessPolicy` JSON.
- Claims that removing `ms-copilot:` / `ms-edge-copilot:` URI sources also removes Start, search, Store-app, browser, or Microsoft 365 Copilot entry points.
