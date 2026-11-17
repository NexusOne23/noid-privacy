# Microsoft Edge policy provenance

**Review date:** 2026-08-29 (Edge 152 security review rechecked 2026-09-22; Startup Boost and background-mode policies checked 2026-10-21)
**Runtime contract:** Microsoft Edge v151 baseline, 24 Microsoft values plus 9 separately labelled NoID Privacy additions

## Microsoft v151 baseline source

The authoritative archive was downloaded from Microsoft's [Security Compliance Toolkit Download Center](https://www.microsoft.com/en-us/download/details.aspx?id=55319). Microsoft announced the new recommendations in [Security baseline for Microsoft Edge version 151](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-151/4549607). The subsequent [Edge 152 security review](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-review-for-microsoft-edge-version-152/4550956) added no enforcement recommendation, so v151 remains the current baseline reviewed for this release.

| Field | Verified value |
|---|---|
| File | `Microsoft Edge v151 Security Baseline.zip` |
| Bytes | `466,831` |
| Archive SHA-256 | `c8d1be7073a17a96fd1a5140fc68770068cc15497a27036b16d783d1e5c7a6ab` |
| Compared member | `Microsoft Edge v151 Security Baseline/Documentation/MSFT-Edge-v151.PolicyRules` |
| PolicyRules SHA-256 | `b19b1c2ae6bceb9eec4e2530798420d5a035e0b5b7540fdc0d0b1803fb414202` |
| ZIP integrity | Every entry passed the archive integrity check |
| Semantic result | All 24 Microsoft registry values match at exact key, name, type and data |

The package also contains one `**delvals.` LGPO parser directive. It clears a list before LGPO writes and is metadata, not a registry value; NoID Privacy excludes it from Apply, Verify and all declared counts.

Compared with the repository's former v139 baseline, Microsoft's v151 package adds five values that were not already present here:

| Policy | Exact value | Minimum Edge | Purpose |
|---|---:|---:|---|
| `ProcessIsolationEnabled` | `1` | 151 | Enables process isolation. |
| `RendererAppContainerEnabled` | `1` | 96 | Runs renderer processes in an AppContainer. |
| `NetworkServiceSandboxEnabled` | `1` | 102 | Keeps the network service sandbox enabled. |
| `BrowserCodeIntegritySetting` | `2` | 104 | Requires browser code integrity; Microsoft limits enforcement to AD-joined or eligible MDM-managed Pro/Enterprise devices. |
| `EnhanceSecurityMode` | `1` | 98 | Selects Balanced enhanced security mode. |

Microsoft describes six newly recommended controls because `ApplicationBoundEncryptionEnabled=1` is part of the v151 recommendation set but was already present in the repository's earlier v139 inventory. The exact repository delta is therefore five, not six. Automatic HTTPS is described as worth evaluating but is not one of the 24 enforced `PolicyRules` values, so it is not silently added.

## Explicit NoID Privacy additions

These nine documented policies are deliberate product choices and are never represented as Microsoft v151 baseline values:

| Policy | Value | Product choice |
|---|---:|---|
| `PersonalizationReportingEnabled` | `0` | Disables browsing-data-based Microsoft personalization. |
| `DiagnosticData` | `0` | Disables required and optional Edge diagnostic data. Microsoft labels `0` not recommended, so this is an explicit privacy deviation. |
| `TrackingPrevention` | `2` | Enforces Balanced tracking prevention. |
| `EdgeShoppingAssistantEnabled` | `0` | Disables shopping-assistant features. |
| `SearchSuggestEnabled` | `0` | Disables web address-bar suggestions and transmission of typed characters/visited URLs while preserving local history and favorite suggestions. |
| `AddressBarTrendingSuggestEnabled` | `0` | Disables Bing trending suggestions in the address bar. |
| `EdgeReadingModeServiceBasedExtractionEnabled` | `0` | Prevents Reading Mode from sending page text to Microsoft's online extraction service; Reading Mode remains available with potentially reduced extraction quality. |
| [`StartupBoostEnabled`](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/startupboostenabled) | `0` | Turns Startup Boost off: Edge processes no longer start at sign-in or restart in the background after the last browser window closes (Windows, Edge 88 and later). Edge opens a little slower. |
| [`BackgroundModeEnabled`](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/backgroundmodeenabled) | `0` | Turns background mode off: Edge and its background apps stop when the last browser window closes (Windows, Edge 77 and later). |

Startup Boost is what makes Edge open by itself after sign-in once it has been used: Edge registers `msedge --no-startup-window --win-session-start` under the user's `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` key, and on Windows 11 26H2 that start showed a visible "New tab" window. Measured on Windows 11 26H2 with Edge 151: with both policies set, the next sign-in starts Edge one last time, Edge removes its own Run entry, and later sign-ins start no Edge process; closing the last window leaves no Edge process running. NoID Privacy does not edit Edge's Run entry itself; Edge maintains it.

Exact classifications, minimum versions and primary-source URLs are machine-validated in [`Summary.json`](../Modules/EdgeHardening/Config/Summary.json).

## Profiles, applicability and BAVR

- Default: 23 Microsoft values plus all 9 privacy additions. The extension block-all value is not selected, so an existing administrator extension policy is preserved.
- Block-all: all 24 Microsoft values plus all 9 privacy additions.
- Printing: by default `DynamicCodeSettings` carries `0`, Edge's own default, instead of the Microsoft baseline value `1`. With `1` the Edge browser process may not create dynamic code. Microsoft notes that this can break printer drivers that run in the browser process ([DynamicCodeSettings](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/dynamiccodesettings)). Measured on Windows 11 26H2 with Edge 155 and only Microsoft Print to PDF installed: each print attempt made Windows block dynamic code in the Edge browser process (Security-Mitigations event 2), and Edge closed. The baseline value `1` is a separate choice (`allowBrowserDynamicCode=false`); both values are backed up, applied, verified and restored like every other target. An Apply of an earlier version wrote `1`; applying EdgeHardening again writes `0`.
- Documented policies are staged when Edge is absent or older than their minimum version. Registry readback proves staged owned state; it is never reported as proof that an older browser consumed the policy.
- Five targets require Microsoft's managed-Windows condition: the four SmartScreen policies and `BrowserCodeIntegritySetting`. NoID Privacy proves AD membership with `Win32_ComputerSystem` or MDM registration with `IsDeviceRegisteredWithManagement`, with eligible Pro/Enterprise gating for MDM. Otherwise those values remain untouched and are `NotApplicable`.
- New backups use Edge snapshot schema 8 and seal the 33-value declaration, exact applicable/NotApplicable split, installation evidence and Apply contract. Schema 4/5 remain frozen to the closed 23-value v2.2.5 inventory, schema 6 to its 26-value successor inventory and schema 7 to the 31-value v151 inventory of 2.2.6 to 2.2.9. All four older schemas are accepted for exact Restore only and can never absorb values they did not seal.
- Several policies require an Edge restart. `EnableUnsafeSwiftShader=0` remains documented but temporary; the baseline provenance check forces this inventory to be reviewed again on the next baseline update.

Individual semantics come from Microsoft's [Edge policy documentation](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/). Management-condition references are [SmartScreenEnabled availability](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/smartscreenenabled) and [IsDeviceRegisteredWithManagement](https://learn.microsoft.com/en-us/windows/win32/api/mdmregistration/nf-mdmregistration-isdeviceregisteredwithmanagement).
