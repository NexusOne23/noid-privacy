# Windows 11 AI applicability contract

**Primary-source review date:** 2026-10-08
**Framework scope:** fully supported Windows 11 24H2, 25H2 and explicit 26H2 x64 client profiles.

This document separates three facts that must not be collapsed into one success claim:

1. NoID Privacy wrote and read back the exact owned registry/source-hive state.
2. Microsoft documents the policy for this Windows build, edition, geography, and product version.
3. The product/runtime demonstrably enforced the requested behavior.

AntiAI verification proves item 1 only for the item-2-applicable subset. Targets outside documented build, edition, enrollment, geography, or product-version constraints are not written or restored and are reported individually as `NotApplicable`. It does not infer item 3 from registry presence.

Exact policy Restore does not recover Recall data. Microsoft documents that
`AllowRecallEnablement=0` and `DisableAIDataAnalysis=1` both delete existing Recall
snapshots. The former also removes the Recall component after a restart. AntiAI
reports this boundary before Apply; its sealed registry backups contain neither
those snapshots nor the component files. Restoring an older policy value cannot
recreate them. [Microsoft Recall policy contracts](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#allowrecallenablement).

## Sources and how they were checked

- Microsoft's [WindowsAI Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai), page revision of 2026-09-23 (21 policy headings).
- The official Administrative Templates for Windows 11 24H2, 25H2 and 26H2 from the Microsoft Download Center (`WindowsCopilot.admx`, `CAM_AI.admx`, `AppPrivacy.admx`, `CloudContent.admx`).
- Microsoft's Copilot app pages: [Configure Microsoft Copilot policies](https://learn.microsoft.com/en-us/windows/client-management/configure-microsoft-copilot-policies), [Copilot update policies](https://learn.microsoft.com/en-us/windows/client-management/copilot-update-policy-control), [Deploy the unified Copilot app](https://learn.microsoft.com/en-us/windows/client-management/deploy-unified-copilot-app) and [Pause the unified Copilot app deployment](https://learn.microsoft.com/en-us/windows/client-management/pause-unified-copilot-app-deployment), plus the [Microsoft Edge Update policy reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-update-policies).
- The [`StartupTaskState`](https://learn.microsoft.com/en-us/uwp/api/windows.applicationmodel.startuptaskstate) values Windows uses for packaged apps that start at sign-in.
- The [Microsoft Edge policy reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies) (Edge 154 Stable, reference revision for 157).
- Microsoft's [MXC telemetry documentation](https://github.com/microsoft/mxc/blob/main/docs/telemetry.md).
- A read-only search of the Windows 11 26H2 (26300.9457) and 25H2 system binaries for each policy value name. A value name that no shipped binary contains is not read by Windows itself.
- Tests on fresh, fully updated Windows 11 25H2 and 26H2 Home, Pro and Enterprise installations without a domain or MDM enrollment (Microsoft Edge 154, Microsoft Edge Update 1.3.279.5, Microsoft 365 Copilot app 19.2610).

## Windows release profiles

- 24H2 (`26100`), 25H2 (`26200`) and explicit 26H2 (`26300..27999`) are supported framework profiles.
- 26H2 requires Windows to report `DisplayVersion=26H2`; a build-family guess with a missing/different DisplayVersion is rejected. The framework runs Backup, Apply, Verify/HTML and Restore through the same sealed BAVR lifecycle.
- All three releases support the same module lifecycle on Home, Pro and Enterprise.
- 26H1 uses a different core and is not treated as a 26H2 upgrade path. Missing/mislabeled 26H2, 26H1 and future/Canary families remain fail-closed.

## WindowsAI and AppPrivacy policies

| Control | Framework state | Microsoft applicability / caveat |
|---|---|---|
| `LetAppsAccessSystemAIModels=2` | Applied on Pro and higher | `AppPrivacy.admx` in the 25H2 and 26H2 templates: "Let Windows apps make use of Text and image generation features of Windows". `CapabilityAccessManager.dll` reads it. Like every Windows Administrative Template target, it is not written on Home. |
| `AllowRecallEnablement=0` | Applied only when applicable | Pro+ and Windows 11 24H2 KB5055627 (`26100.3915`)+. |
| `DisableAIDataAnalysis=1` | Applied only when applicable | Pro+ and Windows 11 24H2 `26100.3915`+. |
| Recall deny lists | Applied subset uses enable DWords plus separate list strings | Enterprise/Education/IoT; `26100.3915`+; restart required. |
| Recall storage limits | Applied only when applicable | Enterprise/Education/IoT; `26100.3915`+. |
| `AllowRecallExport=0` | Not written | Insider Preview, commercial editions, and EEA-only. Not configured already denies export. NoID Privacy has no authoritative device-geography attestation and therefore does not claim this target. |
| `DisableRecallDataProviders=1` | Applied only on detected Insider builds | The CSP documents this user policy for Windows Insider builds on Enterprise/Education/IoT Enterprise only. No official ADMX contains it and no current Windows system binary references it, so a supported release alone is not treated as applicable. |
| `ConfigureAgentConnectors=2` | Force Disable on explicit 26H2 or detected Insider commercial profiles | In the 26H2 `CAM_AI.admx` and read by `CapabilityAccessManager.dll`. The CSP table lists Enterprise/Education/IoT Enterprise; the ADMX supports every edition. NoID follows the narrower CSP. |
| `AgentConsentDuration=1` | Minimum documented lifetime on the same profiles | Range 1–8760 hours, default 720. In the 26H2 `CAM_AI.admx` (Pro and higher) and read by `CapabilityAccessManager.dll`; NoID follows the narrower CSP edition list. |
| `AgentConnectorAccessPolicy` | Not configured | Microsoft says the value is a JSON allowlist, but its schema link still redirects back to the CSP page and publishes no schema/example. NoID Privacy does not invent a security-policy format; `ConfigureAgentConnectors` is force-disabled instead. |
| `OnDeviceRegistryLoggingLevel` | Not configured | Controls agent-registry logging verbosity, not whether agents/connectors run. The default already logs least. |
| `SetDataLossPreventionProvider` | Not configured | Requires a real installed provider-specific identifier. No generic value can be safely invented for unmanaged workstations. |
| `DisableSettingsAgent=1` | Applied on documented servicing-level commercial profiles | Windows 11 24H2 KB5062660 (`26100.4770`) onward; the 25H2 feature update ends its temporary enterprise-feature-control hold. The CSP lists Enterprise/Education; the ADMX also names Pro. NoID follows the narrower CSP. Runtime presence still requires an eligible Copilot+ PC. |
| `DisableClickToDo=1` | Applied on documented servicing-level Pro+ profiles | Click to Do arrived with KB5055627 (`26100.3915`); the 25H2 feature update ends its temporary hold. Microsoft notes that the policy does not affect Click to Do inside Recall. The feature itself still requires a Copilot+ PC or eligible Cloud PC. |
| `RemoveMicrosoftCopilotApp` | Excluded from reversible AntiAI | It uninstalls the app, only under conditions NoID cannot guarantee, and users can reinstall. Copilot package removal is available only after the user separately selects Privacy Tier 1 or Tier 2. |
| `DisableCopilotPinScreen` | Not configured | `CloudContent.admx`; the CSP lists it for Insider Enterprise/Education. It only suppresses Microsoft 365 Copilot recommendations at sign-in and shares the CloudContent key with other modules. |

### Complete current WindowsAI CSP delta

The 2026-09-23 revision contains 21 policy headings. AntiAI maps every heading as follows:

| CSP headings | Result |
|---|---|
| `ConfigureAgentConnectors`, `AgentConsentDuration` | Declared and applicability-gated. |
| `AllowRecallEnablement`, `AllowRecallExport`, `DisableAIDataAnalysis`, `DisableClickToDo`, `DisableCocreator`, `DisableGenerativeFill`, `DisableImageCreator`, `DisableRecallDataProviders`, `DisableSettingsAgent` | Declared; each is gated by its documented build, edition, enrollment/geography or product requirement. |
| `SetDenyAppListForRecall`, `SetDenyUriListForRecall`, `SetMaximumStorageDurationForRecallSnapshots`, `SetMaximumStorageSpaceForRecallSnapshots` | Declared with their required enable/list values or documented numeric choices. |
| `SetCopilotHardwareKey`, `TurnOffWindowsCopilot` | Declared, with the current-Copilot-app limitation reported separately. |
| `AgentConnectorAccessPolicy` | Excluded: the linked JSON schema/example is still unavailable; no format is invented. |
| `OnDeviceRegistryLoggingLevel` | Excluded: it changes logging verbosity, not agent availability or connector permission. |
| `RemoveMicrosoftCopilotApp` | Excluded from reversible AntiAI: it is destructive; package removal remains a separate explicit Privacy choice. |
| `SetDataLossPreventionProvider` | Excluded: Microsoft requires an installed provider's specific registry/DLL identifier; there is no safe generic value. |

The official [enterprise feature-control table](https://learn.microsoft.com/en-us/windows/whats-new/temporary-enterprise-feature-control) records that the Windows 11 25H2 feature update ends the temporary hold for Settings Agent and Click to Do, while their dedicated management pages document the permanent controls and hardware requirements. Those newer, feature-specific sources take precedence over the consolidated WindowsAI CSP rows that still say Insider Preview.

### Retired targets

Earlier versions wrote values that Microsoft no longer documents. They are no longer declared:

| Value | Reason |
|---|---|
| `DisableAgentConnectors`, `DisableAgentWorkspaces`, `DisableRemoteAgentConnectors`, `AgentConnectorMinimumPolicy` | Removed from the WindowsAI CSP (revision of 2026-09-23), never in any official ADMX, and referenced by no 26H2 system binary. Microsoft never published a registry location for them. |
| `LetAppsAccessGenerativeAI` | In no official ADMX and referenced by no 25H2/26H2 system binary. The policy Windows reads is `LetAppsAccessSystemAIModels`; 2.2.4 wrote both names, and 2.2.5 removed the documented one by mistake. |
| `ShowCopilotButton` | A legacy taskbar preference, not a policy. It was declared but never written. |

NoID Privacy never deletes registry state that another backup session owns. Values written by 2.2.5 or 2.2.6 stay in place until that session is restored, which removes them exactly as before. They have no effect on current Windows builds. A durable Apply record from 2.2.6 still names the earlier 43-target inventory (2.2.5 records saved no AntiAI plan); verification therefore reports AntiAI as not proven until AntiAI is applied again.

## Microsoft Copilot app, Edge Update and agent containers

- **Copilot app policies.** `HKLM\SOFTWARE\Policies\Microsoft\Copilot` `BrowsingEnabled=0` and `CopilotCoworkToolActionsEnabled=0` (`CopilotApp.admx`, Copilot 152+). They disable browsing in the app and stop Cowork from acting on the user's behalf; the user cannot turn either back on in Settings. They are staged whether or not the app is installed.
- **Installs through Microsoft Edge Update.** Microsoft merged the Microsoft Copilot and Microsoft 365 Copilot apps into one app that Microsoft Edge Update delivers. `HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate` `Install{C50565E9-CCCF-44B4-BA15-5AC5C6569197}=0` ("Installs disabled", `copilotupdate.admx`, Edge Update 1.3.253.25+) stops installs through that channel. It does not uninstall an existing app or block its updates, and Store or web installs are a separate channel. The app installs as a desktop program under `C:\Program Files (x86)\Microsoft\Copilot`; Privacy's app-removal tiers act only on Store packages such as `Microsoft.Copilot` and do not remove it.
  Microsoft's page states no device limit for `Install`, but Edge Update reads none of its policies on a device that is neither joined to an Active Directory domain nor registered with an MDM service. On such a device its log records `Machine is not Enterprise Managed`, and with this value set it still downloaded and ran the Copilot installer. AntiAI therefore writes the value only on domain-joined or MDM-enrolled devices and reports it `NotApplicable` everywhere else; it is also `NotApplicable` when the management state cannot be read.
  Microsoft also documents `PauseCopilotAppUnificationRollout=1` under `HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate` to pause the automatic merge of the two apps. Edge Update 1.3.279.5 honours it only on the same managed devices and only before 1 December 2026, so AntiAI does not write it. On a home PC without a domain or MDM, Microsoft offers no control that stops Edge Update from installing the Copilot app.
- **Copilot apps starting at sign-in.** The Microsoft 365 Copilot app (`Microsoft.MicrosoftOfficeHub`) declares a startup task that its manifest enables by default; on every tested 25H2 and 26H2 Home, Pro and Enterprise installation that includes the app, it started in the background at each sign-in. The Copilot app (`Microsoft.Copilot`) has its own startup task, off by default, that the app can offer to turn on. For the desktop user, AntiAI sets each task's `State` under `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\<package family>\<task>` to `1` (`DisabledByUser`), the value Settings > Apps > Startup writes. Windows then shows the app as off and does not start it; only the user can turn it back on. A task is written only when the app has registered it for that user, and AntiAI never creates the key. Restoring these values requires the same user to be signed in, because their Classes hive is loaded only then.
- **Microsoft Execution Containers.** `HKLM\SOFTWARE\Policies\Mxc` `AllowTelemetry=0` stops MXC, the Windows sandbox for AI agents, from collecting diagnostic data and from asking for consent. MXC reads only this key, not the Windows `DataCollection` policy. The container itself is a security boundary and stays usable.

## Current Copilot app

Microsoft states that the deprecated `TurnOffWindowsCopilot` policy does not control the current Copilot experience and recommends AppLocker for the consumer `MICROSOFT.COPILOT` package. A publisher rule covers installation and launch: [Microsoft's current Copilot management guidance](https://learn.microsoft.com/en-us/windows/client-management/manage-windows-copilot).

AppLocker enforcement requires the Application Identity (`AppIDSvc`) service. Microsoft documents that stopping the service disables enforcement, recommends Automatic startup for Group Policy, and warns that the protected service cannot be reset to Manual with `sc.exe`: [Application Identity service guidance](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-the-application-identity-service).

For that reason NoID Privacy does not silently enable AppLocker/AppIDSvc inside AntiAI and then claim exact BAVR. Reversible AntiAI restricts the app through its documented policies but does not promise to block it from launching or from being installed through the Store. Users who explicitly select Privacy's existing destructive Tier 1 or Tier 2 app-removal choice also select the exact `Microsoft.Copilot` package: its sealed package identities and Store ID support honest best-effort recovery, never exact app-data or version restoration. With both app-removal tiers left off, Copilot is not uninstalled.

`SetCopilotHardwareKey` sets which app the Copilot key opens. Microsoft lets the user change the assignment in Settings, so it is a default, not a lock.

## Product-specific policies

- Notepad `DisableAIFeatures=1` is documented for Windows 11 22H2+ with Notepad `11.2503.16.0`+ and has no edition restriction on the feature-specific page; the applicability planner therefore includes it on Home whenever the package version qualifies: [Notepad AI management](https://learn.microsoft.com/en-us/windows/client-management/manage-notepad).
- Paint Cocreator, Generative Fill, and Image Creator policies are documented in the WindowsAI CSP with Windows 11 build floors. Microsoft publishes no policy for Sticker generator, Restyle, Object select, Generative Erase or background removal, so NoID Privacy does not claim complete Paint-AI removal.
- Edge policies are versioned independently from Windows. The AntiAI planner stages each documented machine policy for absent/older Edge and records version evidence without claiming runtime consumption. Microsoft marks most Edge Copilot/AI policies as not applying to profiles signed in with a personal Microsoft account on managed devices ([policy filters](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-personal-browser-policies)); several apply only to work (Entra ID) profiles, and since Edge 141 no policy hides the Copilot toolbar button for local or personal-account profiles. EdgeHardening separately carries Microsoft's exact Edge v151 security baseline.

## Features without a documented admin control

Microsoft documents no policy for these features. NoID Privacy does not invent one:

- Turning the agent workspace on or off (a user setting, off by default); Copilot voice and "Hey Copilot".
- Semantic indexing in Windows Search, AI components such as Phi Silica, and Windows ML execution-provider downloads.
- AI actions in File Explorer, "Ask Copilot" in Narrator and Click to Do, and the Bing visual search in Photos, Snipping Tool and File Explorer.
- Edge Journeys and Copilot Mode for personal profiles, and Copilot Vision.
- `LetAppsAccessBackgroundAITasks`, which 26H2's `CapabilityAccessManager.dll` already contains but no Microsoft template or page documents yet.

## Unsupported or unsafe mechanisms excluded

- Protected `IntegratedServicesRegionPolicySet.json` edits.
- Hosts-file blocks against shared Microsoft/Bing endpoints.
- Runtime `CapabilityAccessManager\ConsentStore` writes (for example the
  `systemAIModels` global `Value=Deny` applied by earlier versions): consent-store
  entries are runtime state, not documented policy, and are excluded from the
  exact-BAVR target set. The documented `LetAppsAccessSystemAIModels` policy is used instead.
- Wildcard Copilot/Recall AppX removal, or automatic AppX uninstall outside Privacy's explicit destructive app-removal tiers. Recall optional-component removal by its native policy has the separate recovery limit described above.
- Undocumented `HideAIActionsMenu` and `Explorer\DisableWindowsCopilot`.
- User-scope (HKCU) duplicates of `DisableAIDataAnalysis` and `DisableClickToDo`:
  the enforced device-scope (HKLM) policy already governs the machine, so the
  redundant per-user variants written by earlier versions are deliberately not
  declared as targets.
- Invented `AgentConnectorAccessPolicy` JSON.
- Claims that removing `ms-copilot:` / `ms-edge-copilot:` URI sources also removes Start, search, Store-app, browser, or Microsoft 365 Copilot entry points. The removal is an undocumented compatibility control; an app update can register the protocols again, which verification then reports.
