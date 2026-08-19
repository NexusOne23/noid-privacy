# Microsoft Edge policy provenance

Audit date: 2026-08-13

## Microsoft v139 baseline source

The runtime inventory contains 19 registry values from Microsoft's Edge v139 security baseline. The authoritative package was downloaded from the [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319):

- File: `Microsoft Edge v139 Security Baseline.zip`
- Published package size: 400,613 bytes
- SHA-256 on 2026-07-10: `ac54ff9ccb9e86c4f65d8be7968e499f2ed1f9daa4aecb6294f429141c943e3f`
- Compared source inside the package: `Documentation/MSFT-Edge-v139.PolicyRules`
- Result: all 19 managed Microsoft values match the module at exact key, value name, registry type and data.

The package also contains one `**delvals.` LGPO parser directive. It is metadata that clears a list before writing it; it is not a registry value and is excluded from Apply, Verify and all setting counts. Microsoft's current Intune reference independently lists the same 19 v139 baseline values. See the [Edge v139 announcement](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-for-microsoft-edge-version-139/4441251) and [Microsoft's v139 settings reference](https://learn.microsoft.com/en-us/intune/device-security/security-baselines/ref-v2-edge-settings).

## Explicit NoID Privacy additions

These seven current, documented Edge policies are separate product choices and are never represented as Microsoft v139 baseline entries:

| Policy | Value | Product choice |
|---|---:|---|
| `PersonalizationReportingEnabled` | `0` | Disables browsing-data-based Microsoft personalization. |
| `DiagnosticData` | `0` | Disables required and optional Edge diagnostic data. Microsoft explicitly labels `0` as not recommended, so this is a privacy deviation. |
| `TrackingPrevention` | `2` | Enforces Balanced tracking prevention. |
| `EdgeShoppingAssistantEnabled` | `0` | Disables shopping-assistant features. |
| `SearchSuggestEnabled` | `0` | Disables web address-bar suggestions and the related transmission of typed characters/visited URLs while preserving local history and favorite suggestions. |
| `AddressBarTrendingSuggestEnabled` | `0` | Disables Microsoft Bing trending suggestions in the address bar. |
| `EdgeReadingModeServiceBasedExtractionEnabled` | `0` | Prevents page text from being sent to Microsoft's online extraction service. Reading Mode remains available, with potentially reduced extraction quality. |

The source URLs, documented minimum Edge versions and the exact baseline/privacy classification are machine-validated in [`Summary.json`](../Modules/EdgeHardening/Config/Summary.json).

## Profiles and applicability

Primary management-condition references: [SmartScreenEnabled availability](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/smartscreenenabled) and [IsDeviceRegisteredWithManagement](https://learn.microsoft.com/en-us/windows/win32/api/mdmregistration/nf-mdmregistration-isdeviceregisteredwithmanagement).

- Default profile: 18 Microsoft values plus seven privacy additions; the extension blocklist is not mutated. Existing administrator extension policy is preserved.
- Block-all profile: all 19 Microsoft values plus seven privacy additions; `ExtensionInstallBlocklist\1="*"` is applied.
- The module rejects an installed Edge version older than 139. If Edge is absent, it stages policy for a future installation but does not claim runtime verification.
- Per-policy version applicability is sealed into schema-6 BAVR. `EdgeReadingModeServiceBasedExtractionEnabled` requires Edge 151; on an installed older supported Edge that single value stays untouched and is `NotApplicable`. Legacy schema-4/5 snapshots remain restorable against the closed 23-value v2.2.5 inventory and never absorb later policies.
- Four SmartScreen policies have Microsoft-documented managed-Windows prerequisites. The module proves AD domain membership through `Win32_ComputerSystem` or MDM registration through Windows' documented `IsDeviceRegisteredWithManagement` API, with Pro/Enterprise edition gating for the MDM branch. If neither condition is proven, those four targets stay untouched and are reported `NotApplicable`. Registry readback still proves owned state, not acceptance in `edge://policy`.
- Several policies require an Edge restart. `EnableUnsafeSwiftShader=0` remains documented as of 2026-05-22, but Microsoft marks the policy temporary and scheduled for future removal; this must be rechecked on every baseline update.

Individual policy semantics are sourced from [Microsoft Edge policy documentation](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/).
