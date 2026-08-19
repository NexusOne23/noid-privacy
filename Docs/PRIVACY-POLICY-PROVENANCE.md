# Privacy policy provenance and applicability

**Reviewed:** 2026-08-14
**Target:** Windows 11 24H2 and 25H2; an explicitly reported 26H2 preview is admitted only as an Experimental full-BAVR path and is currently not runtime-validated or release-approved

## Verification contract

The Privacy module proves the exact typed registry state for its applicable, sealed targets and the exact disabled/startup state of installed services and scheduled tasks selected by the active mode. It does not treat registry writability as proof that Windows supports or consumes a policy.

- Windows managed-policy targets are `NotApplicable` on Home.
- `DisableWindowsSpotlightFeatures`, `DisableWindowsSpotlightOnSettings`, `DisableWindowsSpotlightOnActionCenter`, `DisableSpotlightCollectionOnDesktop`, `DisableCloudOptimizedContent` and `DisableSoftLanding` are `NotApplicable` on Professional because Microsoft's current applicability tables list only Enterprise, Education and IoT Enterprise.
- On Professional, `DisableThirdPartySuggestions=1` remains applicable and blocks third-party Spotlight suggestions, but Microsoft explicitly says users can still receive suggestions for Microsoft features, apps and services. NoID Privacy therefore does not report Spotlight as fully disabled on Pro. It does not substitute undocumented ContentDeliveryManager preferences for the Enterprise-only master controls.
- User-scoped CloudContent policies are written to the interactive Explorer owner's real `HKEY_USERS\<SID>` policy hive. `DisableCloudOptimizedContent` and `DisableSoftLanding` are computer policies under HKLM.
- `AllowTelemetry=0` is stored exactly in Strict/Paranoid, but Microsoft documents Diagnostic Data Off as effective only on Enterprise/Education/IoT Enterprise. On other supported editions, Windows treats it as required diagnostic data.
- Windows 11 26H2 remains an Experimental Preview that is currently not runtime-validated or release-approved. Exact policy state can be inspected there, but no final 26H2 security/privacy baseline or runtime guarantee is claimed.

## Microsoft primary sources

| Target family | Primary source | Boundaries used by NoID Privacy |
|---|---|---|
| Diagnostic data, OneSettings and diagnostic log collection | [System Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system) | Current registry mapping, values, Pro+ applicability and the edition limitation of Diagnostic Data Off |
| Feedback, Spotlight, tailored experiences, clipboard and CloudContent | [Experience Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience) | Device/user scope, real registry mapping, minimum edition and allowed values |
| Widgets board and lock-screen widgets | [NewsAndInterests Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-newsandinterests) and [Microsoft's preview-policy inventory](https://learn.microsoft.com/en-us/windows/client-management/mdm/policies-in-preview) | Stable `AllowNewsAndInterests=0` is selected in Strict/Paranoid on Pro+, but active UCPD blocks direct local command-line Apply/Restore and is never bypassed. `DisableWidgetsBoard` and `DisableWidgetsOnLockScreen` remain Insider Preview-only and are excluded from stable profiles. |
| Search web/cloud controls | [Search Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search), [Windows connection-management guidance](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services), [Windows Search and privacy](https://support.microsoft.com/en-us/windows/windows-search-and-privacy-99fb8251-7260-1cd6-1bbb-15c2370eb168), [`Set-WindowsSearchSetting`](https://learn.microsoft.com/en-us/powershell/module/windowssearch/set-windowssearchsetting?view=windowsserver2025-ps) and [`WM_SETTINGCHANGE`](https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-settingchange) | Documented Windows Search policies are the managed layer; `BingSearchEnabled`, `IsDynamicSearchBoxEnabled`, `IsGlobalWebSearchProviderToggleEnabled`, the Bing provider value and Paranoid's `IsDeviceSearchHistoryEnabled` are separately labelled interactive-user preferences and never reported as policy enforcement. MSRecommended/Strict preserve local device-search history because Microsoft documents it as device-local ranking data that helps users find prior local results faster; Paranoid deliberately accepts that local convenience loss. Apply and exact Restore broadcast Microsoft's documented notifications and call its per-user WindowsSearch API with the already written/restored effective value in the Explorer user's limited token. Verify binds `BingSearchEnabled=0` to `EnableWebResultsSetting=False`; no extra registry target is created. |
| Settings Sync and Windows settings/app-list backup | [ADMX SettingSync Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-settingsync), [SettingsSync Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-settingssync), [Windows Backup for Organizations](https://learn.microsoft.com/en-us/windows/configuration/windows-backup/) and [Windows connection-management guidance, section 21](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#21-sync-your-settings) | `DisableSettingSync=2` is the documented enabled value and `DisableSettingSyncUserOverride=1` prevents all preference-group roaming; Strict/Paranoid additionally set the current inbox `EnableWindowsBackup=0` disabled value so periodic Windows settings/app-list cloud backup does not run. All are Pro+ only, so Home remains `NotApplicable` rather than receiving a registry-only success claim. |
| Cellular text-message cloud sync | [Messaging Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-messaging#allowmessagesync) | Strict/Paranoid set the current inbox `AllowMessageSync=0` disabled value to prevent cellular text-message backup/restore through Microsoft cloud services. The policy is Pro+; Home remains untouched and `NotApplicable`. |
| Online fonts and automatic device companion apps | [System Policy CSP: AllowFontProviders](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#allowfontproviders) and [DeviceInstallation Policy CSP: PreventDeviceMetadataFromNetwork](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceinstallation#preventdevicemetadatafromnetwork) | Paranoid alone sets the current inbox `EnableFontProviders=0` disabled value and `PreventDeviceMetadataFromNetwork=1` enabled value. This removes online-font traffic and automatic device-metadata app downloads but can reduce font/device convenience; it is deliberately excluded from compatibility-oriented modes. Both policies are Pro+ and `NotApplicable` on Home. |
| App capability access, including Generative AI | [Privacy Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy) | Documented policy values only; raw ConsentStore duplication is excluded |
| File Explorer cloud metadata | [FileExplorer Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-fileexplorer) | `DisableGraphRecentItems=1`, Pro+ and Windows 11 22H2+ |
| OneDrive feedback, sync reports and pre-sign-in traffic | [OneDrive administrative policies](https://learn.microsoft.com/en-us/sharepoint/use-group-policy) | OneDrive-client policy state; NoID Privacy does not force Personal OneDrive allowed or disabled |
| Store access and OS-upgrade offers | [ADMX WindowsStore Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsstore) | `DisableOSUpgrade=1` is Pro+; NoID Privacy does not force Store access allowed |
| Policy-based in-box app removal | [Policy-based in-box app removal](https://learn.microsoft.com/en-us/windows/configuration/policy-based-inbox-app-removal/policy-based-inbox-app-removal) | Enterprise/Education, Windows 11 24H2+, device scope, no multi-session; app data can be deleted and restoring/deselecting policy does not reprovision an app |
| User privacy preferences used only by Strict/Paranoid | [Microsoft Windows 11 VDI optimization guidance](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-services-vdi-optimize-configuration) | Current Microsoft-published registry recommendations for Windows 11; only exact state is certified, not universal runtime effect on every shell build |

## Interactive-user preference layer

The following visible shell settings are included as a separate preference layer for the interactive Explorer user:

- `Start_IrisRecommendations=0`
- `ShowSyncProviderNotifications=0`
- `BingSearchEnabled=0`
- `IsDynamicSearchBoxEnabled=0`
- `IsGlobalWebSearchProviderToggleEnabled=0` and `SearchSettings\WebSearchProviders\Microsoft.BingSearch_8wekyb3d8bbwe!App=0`
- `IsDeviceSearchHistoryEnabled=0` in Paranoid only
- `Start_AccountNotifications=0` in Strict/Paranoid only
- `EnableAccountNotifications=0` in Strict/Paranoid only

These values are not documented Microsoft Administrative Template or Policy CSP contracts. NoID Privacy therefore certifies only their sealed, typed registry state and exact restore, and requires release-matrix runtime validation on each supported Windows build and edition before claiming visible effect. They remain applicable on Home because they are user preferences, not an attempt to make a Home-unsupported managed policy look effective.

The release matrix additionally verifies the live Search result surface. A
registry readback or visible Settings toggle alone is insufficient: the running
Search process can retain a prior web-provider state. NoID Privacy emits the
documented `WM_SETTINGCHANGE` notifications, then invokes Microsoft's
`Set-WindowsSearchSetting -EnableWebResultsSetting` with the already applied or
restored value in the actual Explorer user's limited token. The worker proves
that the complete Search/SearchSettings registry tree and every unrelated
WindowsSearch API setting remain unchanged. Module verification and the shared
HTML report bind the existing `BingSearchEnabled` row to the effective API
state; any worker, notification or effective-state failure fails closed.

## Excluded or corrected targets

The audit removed targets whose prior description was stronger than the available primary evidence or whose write could reduce an existing restriction:

- raw HKCU/HKLM `ConsentStore\appDiagnostics` writes
- allow/user-control writes for AppPrivacy, Settings Sync, local clipboard history, location, Personal OneDrive and Store access
- `IsDeviceSearchHistoryEnabled`: MSRecommended and Strict preserve local device-search history. Microsoft documents it as local to the device and used to improve local result ranking; disabling web/Bing and cloud-content search does not require disabling it. Paranoid alone disables it as an explicit maximum-minimization trade-off.
- `DisableCredentialsSettingSync` and the other per-category SettingSync values: the documented enabled `DisableSettingSync=2` master policy already disables all setting groups, while `DisableSettingSyncUserOverride=1` prevents user override. NoID Privacy does not duplicate subordinate values that add no protection to the selected master state. `EnableWindowsBackup=0` is not a redundant group toggle: Microsoft separately documents it as the control for the periodic Windows settings/app-list backup job, so Strict/Paranoid include it.
- `DisableWidgetsBoard` and `DisableWidgetsOnLockScreen`: Microsoft still lists both as Windows Insider Preview policies. They are not written on the stable 24H2/25H2 product path and are not carried forward speculatively to 26H2. Strict/Paranoid already select the stable Pro+ `AllowNewsAndInterests=0` policy; if Windows UCPD protects that registry target from local command-line writes, BAVR preserves it untouched and reports `NotApplicable`. The ordinary user can still hide the taskbar entry in Windows Settings, while the separate Weather/Widgets Tier-2 choice is an explicit destructive removal of Windows Web Experience Pack and not a reversible policy substitute.
- Full Windows Spotlight disable on Professional: Microsoft's current applicability tables exclude Pro from the Spotlight master, Settings, Action Center, Desktop collection, cloud-optimized-content and Windows-tips controls. The applicable `DisableThirdPartySuggestions=1` target is retained, but Microsoft states that it does not suppress Microsoft's own suggestions. The product reports the other targets `NotApplicable` and does not manufacture a stronger Pro claim from undocumented preferences.

The exact machine contract was checked on the release 25H2 build against the inbox ADMX files: `SettingSync.admx` gives `DisableSettingSync` enabled DWORD `2`/disabled `0` and `EnableWindowsBackup` enabled `1`/disabled `0`; `messaging.admx` gives `AllowMessageSync` enabled `1`/disabled `0`; `GroupPolicy.admx` gives `EnableFontProviders` enabled `1`/disabled `0`; and `DeviceSetup.admx` gives `PreventDeviceMetadataFromNetwork` enabled `1`/disabled `0`. `Tools/Test-PrivacyPolicyProvenance.ps1` binds the JSON values and source metadata to all four inbox files and records their SHA-256 hashes.

The same gate also passed against Microsoft's official [Windows 11 24H2 V2 Administrative Templates](https://www.microsoft.com/en-us/download/details.aspx?id=108293), rather than assuming that the 25H2 inbox definitions applied to 24H2. The package was retrieved from Microsoft's official HTTPS asset URL on 2026-08-13:

`https://download.microsoft.com/download/bdb3aa7b-4d8b-4e76-bb96-c99572d99c69/Administrative%20Templates%20%28.admx%29%20for%20Windows%2011%20May%202025%20Update-V2.msi`

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `Administrative Templates (.admx) for Windows 11 May 2025 Update-V2.msi` | 14,819,328 | `8c4ff1b631d056775c7d36b8ec04e96299a71a0e45af4d61d3b49c9cd94557dc` |
| `SettingSync.admx` | 12,145 | `d610eed2b43dffbc3b1f631f868fc0adc84a0f9e4462a8ae58598de5b8e45cfe` |
| `messaging.admx` | 1,323 | `5efc195188bc8ce3ca6757e627004efa3d80e96d1f047c711d86e38b377832a4` |
| `GroupPolicy.admx` | 32,930 | `9939b21e46c5ee37e276cf0059385001ae9369e98f834b66bda46332dc75d9ea` |
| `DeviceSetup.admx` | 7,583 | `ca1682cf73cc64ba0829e7090d3ed5750fbe921b906f8d61fe369aebac165d5a` |

Microsoft's download page identifies the package as version 2.0, published 2025-07-24 for Windows 11 24H2. The recorded hashes bind the exact bytes retrieved from Microsoft's HTTPS asset; Microsoft does not publish those hashes as vendor-signed digests. The Windows PowerShell 5.1 gate validated all ten Strict/Paranoid JSON-to-ADMX contracts against these four extracted 24H2 files. This establishes that the newly selected Setting Sync, Windows Backup, message-sync, online-font and device-metadata values need no separate 24H2 configuration branch.

`AllowExperimentation=0` was not added. Microsoft documents the CSP semantics, but the release 25H2 inbox ADMX set exposes no equivalent local Administrative Template contract on the unmanaged client. NoID Privacy does not turn an unproven direct registry write into an effectiveness claim. Controlled Folder Access, Smart App Control/App Control, Tamper Protection, BitLocker activation, Secure Boot/TPM changes and cloud-data deletion are likewise not ordinary Privacy registry targets: they require audit/allowlist learning, device lifecycle/recovery, protected UI/management channels, or irreversible external actions.

`DisableSoftLanding` was corrected from an unsupported HKCU Explorer location to Microsoft's documented HKLM CloudContent computer-policy path. Six other CloudContent controls were corrected from HKLM to the interactive user's policy hive because Microsoft documents them as user policies.

## BAVR decision binding

Schema 7 seals the active edition/build, domain/MDM/multi-session classification, Tier 1, Tier 2 and conditional Weather/Widgets decisions, all `NotChecked`/`NotApplicable` identities, exact registry prestate, exact Apply type/value and the installed service/task applicability list. The module reconciles that prestate once before sealing and again immediately before Apply. Restore validates the same content and manifest relationship before its first mutation. Schema 2-6 registry snapshots remain accepted for exact restore of older sealed sessions but are never accepted as a current Apply plan.

Tier 1's 27 registry-policy identities are always declared: root `Enabled`, an empty root `DynamicRemovalList` of type `REG_MULTI_SZ`, and 25 static Package-Family-Name subkeys carrying `RemovePackage` DWORDs. On an eligible standalone single-session Enterprise/Education 24H2+ system they are `NotChecked` when the user leaves the destructive option off; on an unsupported, multi-session, AD-domain-joined or MDM-registered system they are `NotApplicable` and untouched. If domain/MDM state cannot be queried, only Tier 1 fails closed as `NotApplicable`; the error is logged and unrelated Privacy targets remain usable. The local policy values have exact prestate restoration. Their later device-wide AppX/data deletion does not: Microsoft requires separate reprovisioning and deleted app data cannot be reconstructed.

Restore also recognizes both complete historical Tier 1 contracts: the immediately preceding PFN contract selected seven apps and left Copilot unselected, while the original v2.2.5 contract
used 26 symbolic presentation IDs below the policy root and selected nine app
identities. That closed set exists only so an already sealed session can restore
its exact recorded prestate and feed the separate best-effort app-recovery
assessment. New Backup, Apply and Verify plans never emit or accept it as the
current policy layout. A partial or mixed current/legacy set is rejected before
the first restore mutation.

The byte-level contract was produced through the inbox `AppxPackageManager.admx`/German ADML and actual `gpedit.msc` on Windows 11 Enterprise 25H2 build 26200.8875, then shown unchanged by `gpupdate /force`. It created 27 values across 26 keys: `Enabled=1`, an empty `DynamicRemovalList`, and 25 PFN subkeys. Seven static flags came from the inbox presentation. NoID Privacy's existing destructive Tier 1 opt-in now deliberately selects the eighth, already-declared Copilot PFN as well; leaving Tier 1 off writes none of them. One sign-out/sign-in removed exactly the seven inbox-selected previously present AppX registrations and provisioned identities; returning the policy to Not Configured removed the registry subtree but did not recreate apps or data. The Microsoft Learn CSP example uses symbolic XML data IDs and currently shows a broader illustrative list; those IDs are not registry subkey names. NoID Privacy writes the native empty dynamic value but never adds an unaudited custom PFN.

Tier 2 is deliberately outside the exact configuration-check total. Backup captures a schema-3, catalog-hashed, user-bound inventory of the 26 base candidates (now including the exact `Microsoft.Copilot` package) plus `MicrosoftWindows.Client.WebExperience` only when the separate Weather/Widgets decision is selected. The sealed Boolean and exact present package identities bind the decision to Apply and restore assessment; any AppX/provisioning enumeration error aborts Backup. Immediately before Apply the same selected live inventory hash must still match. Keeping the widget excludes it from action scope and is a valid green verification result. Apply removes only sealed per-user identities, uses terminating queries, verifies each selected absence and fails the module if any selected removal fails. `Restore-BloatwareApps` validates the session manifest and hashes, requires the original user context and post-checks current Store registration, but remains a separately invoked best-effort reinstall that cannot recreate version, app data, licensing, dependencies or provisioning. The pinned pre-Copilot catalog hash keeps already sealed schema-2/schema-3 action logs valid without allowing arbitrary old catalogs.
