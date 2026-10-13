# Windows 11 security and privacy controls

NoID Privacy 2.2.6 supports Windows 11 24H2, 25H2 and 26H2 x64. This reference
describes the configured controls, their compatibility limits and the relevant
Microsoft documentation. Exact Backup → Apply → Verify → Restore (BAVR) covers
owned settings; destructive app and Recall effects have separate recovery limits.

## Control coverage

| Area | Microsoft control | NoID Privacy behavior |
|---|---|---|
| Windows Security Baseline | Microsoft published the Windows 11 v26H2 package on 2026-09-29 and replaced it with v2 on 2026-10-08, which also sets the administrator-protection prompt policy to its default, credentials (1). Against 25H2 it moves WinINet/IE mode to TLS 1.2 and TLS 1.3 and enables Windows Ready Print driver ranking; none of its registry targets requires a release newer than 24H2. | Windows 11 24H2, 25H2 and explicit 26H2 use the same exact 425-target 26H2-derived profile and complete BAVR contract. Product deviations and provenance are documented in [SECURITY-BASELINE-PROVENANCE.md](SECURITY-BASELINE-PROVENANCE.md). |
| Edge Security Baseline | Microsoft’s Edge v151 package contains 24 enforced registry values. The v152 guidance adds no enforced setting. | All 24 v151 values are exact at key/name/type/data. The five-value repository delta, archive/member hashes and exclusions are machine-bound; Automatic HTTPS remains evaluation-only, not silently enforced. |
| Edge search privacy | Microsoft documents that disabling `SearchSuggestEnabled` prevents web suggestions and transmission of typed characters/visited URLs while keeping local history/favorite suggestions. Trending suggestions and Reading Mode online extraction have separate current policies. | Included as three separately labelled privacy additions with minimum-version evidence. Full Edge scope is 24 baseline + 7 privacy values; schema-7 BAVR seals the new inventory while schemas 4–6 remain restore-only frozen contracts. |
| Edge XSLT | Microsoft’s v147 review describes `XSLTEnabled` as a transition/test control for a legacy feature planned for removal and recommends dependency testing, not universal enforcement. | Excluded from normal profiles because disabling it can break legacy enterprise web applications. It is not mislabelled as a baseline requirement. |
| Defender core protection | Current Microsoft guidance continues to recommend real-time/behavior protection, cloud protection, PUA blocking, Block at First Sight and Network Protection. | Already covered by the Microsoft Security Baseline (`PUAProtection`, `SpynetReporting`, `DisableBlockAtFirstSeen`, `EnableNetworkProtection` and related values). Safe-sample submission remains the explicit NoID Privacy default; “send all” requires an informed choice. |
| Attack Surface Reduction | Microsoft’s current OS matrix marks the Exchange webshell rule inapplicable to Windows 11 clients; other ASR rules have compatibility and cloud prerequisites. | Nineteen identities remain declared; 18 are client-applicable. Rules, user choices, third-party endpoint state and cloud prerequisites are sealed and reported as Passed/Failed/NotChecked/NotApplicable rather than flattened to green. |
| Controlled Folder Access | Microsoft documents block, audit and disk-only modes plus environment-specific protected folders/allowed apps. Blind block mode can deny legitimate application writes. | Not inserted into Quick Secure/Balanced/High Security. Configure and test application exceptions in Windows Security before enabling it separately. |
| Smart App Control | Microsoft documents clean-install/region requirements and lifecycle states; selecting Off/On can be a one-way user operation. Registry forcing is documented for testing only and can compromise protection. | Never automated as an ordinary tweak and never claimed BAVR-exact. NoID Privacy may display the authoritative Windows state, but the user controls it through Windows Security. |
| App Control for Business / AppLocker | Microsoft requires policy design, audit deployment and app-specific trust rules; an incorrect allow/deny policy can block required software or boot paths. | Outside the one-click profiles; NoID Privacy configures no application control. Earlier 2.2.6 builds wrote two legacy SRP `.lnk` path rules. Measured on 25H2 and 26H2, Windows never enforced them: the AppLocker/Smart App Control marker `Srp\Gp\RuleCount=2` turns SRP off. They are no longer written; sessions saved by those builds still restore them. |
| Tamper Protection | Microsoft states that Tamper Protection blocks registry attempts and standalone users manage it in Windows Security; managed environments use the authoritative security-management channel. | No registry write and no false enforcement claim. Preserve the protected state and give a manual Windows Security path when relevant. |
| LSA, Credential Guard and HVCI | Microsoft documents enabled modes with and without UEFI locks. An activated lock is not reversible by a registry-only restore; removing Credential Guard values may also be insufficient to disable its runtime state. | New 2.2.6 Apply plans map the four source values from `1` to `2` as a fixed Windows-based BAVR decision, without an added selection or EFI/BIOS opt-out workflow. They disclose the reduced firmware resistance to privileged reconfiguration. Existing locks are not removed. Historical backups retain their exact recorded values. Restart and recovery limits are detailed in [SECURITY-BASELINE-RECOVERY.md](SECURITY-BASELINE-RECOVERY.md); policy equality alone does not prove active protection or runtime recovery. |
| Secure Boot, Trusted Boot and TPM | These are firmware/hardware roots of trust. Changing boot mode or clearing/reconfiguring TPM can cause boot or protected-data loss. | Detect/report only; never an automatic profile mutation. Windows/OEM servicing remains responsible for Secure Boot certificate updates. |
| BitLocker | Microsoft recommends volume encryption for lost/stolen-device protection; activation and recovery-key custody are user/device/account decisions. | Baseline policies are applied exactly, including an explicit removable-drive write choice. NoID Privacy does not auto-encrypt a system drive or claim encryption is active from policy state alone. |
| Windows Hello/passkeys | Microsoft recommends phishing-resistant, TPM-backed passwordless sign-in. Enrollment is identity-, biometric-, hardware- and recovery-specific. | Recommended/manual workflow, not a reversible machine-policy tweak. The product preserves the user’s account model. |
| Windows Update | Microsoft recommends automatic servicing with a small policy set and preserving safeguard holds; bypassing a hold can expose known compatibility failures. | Security/quality updating stays enabled. Optional non-security content remains user-selected, early-rollout intent remains user-owned, peer-to-peer Delivery Optimization is disabled where supported, and NoID Privacy never bypasses safeguard holds. |
| Root certificates, licensing, NCSI and time | Microsoft’s restricted-traffic guidance documents ways to suppress these connections but warns that several are required for security, licensing, connectivity detection or correct operation. | Not disabled merely to reduce traffic. Breaking trust updates, activation, captive-portal/connectivity detection or time integrity would be a security/UX regression. |
| Diagnostic data and OneSettings | Microsoft documents edition-specific diagnostic floors and separate log/OneSettings controls. | Required diagnostic data in MSRecommended; the supported minimum in stricter modes; extra log collection, feedback prompts, tailored experiences and OneSettings downloads are reduced through documented policies. Home never receives a false Enterprise-only success. |
| Windows Search | Microsoft distinguishes local device-search history/ranking from web/cloud results, documents `Set-WindowsSearchSetting -EnableWebResultsSetting` for web results/suggestions and provides a consolidated 26H2 Search web/Store-results UI toggle without publishing a new policy key. | Existing documented policy/preference targets and the native WindowsSearch API disable web/Bing/cloud results in every mode. The engine uses the documented policy and API controls. MSRecommended/Strict preserve local history; Paranoid alone disables it. |
| Widgets | Microsoft documents stable `AllowNewsAndInterests` for Pro+; the newer `DisableWidgetsBoard` and `DisableWidgetsOnLockScreen` contracts remain Insider Preview-only. Current Windows UCPD can protect the stable registry value from local command-line mutation. | Strict/Paranoid select the stable policy where exact local Apply/Restore is available. Active/unknown UCPD makes that target untouched and `NotApplicable`; NoID Privacy never disables UCPD to force it. Preview-only widget policies are excluded from stable profiles. Weather/Widgets package removal remains a separate, destructive default-off choice. |
| Windows Spotlight on Pro | Microsoft limits the Spotlight master, Settings, Action Center, Desktop collection, cloud-optimized-content and Windows-tips policies to Enterprise/Education/IoT Enterprise. The third-party-suggestions policy supports Pro but explicitly does not block Microsoft's own suggestions. | Pro gets the supported third-party-suggestion control and honest `NotApplicable` results for the Enterprise-only controls. NoID Privacy does not claim full Spotlight disable on Pro and does not replace the missing contract with undocumented ContentDeliveryManager writes. |
| Settings Sync and Windows Backup | Current Policy CSP and inbox `SettingSync.admx` use `DisableSettingSync=2`, user-override false value `1`, and `EnableWindowsBackup` disabled value `0`. Eligible commercial 26H2 devices default settings backup on when policy is Not Configured; explicit policy wins. | Strict/Paranoid include the exact Pro+ deny contract and therefore cover the new default. MSRecommended deliberately preserves the user's/organization's existing backup choice. Home remains untouched/NotApplicable. |
| Point-in-time restore | Microsoft documents local VSS restore points containing the complete system state and local files, a default 24-hour frequency/72-hour retention, a 2% storage limit, default enablement for Home/unmanaged Pro, enterprise-managed default-off behavior only until 26H2, and a 200-GB OS-volume threshold for every default-on case. A restore can revert updates, policies, passwords, certificates and keys; encrypted volumes require a BitLocker recovery key, and pre-restore Recall snapshots remain after Recall itself is disabled. | Not configured by NoID Privacy. The supported surfaces are Windows Settings and the `Recovery/PointInTimeRestore` CSP, not a stable unmanaged registry contract. A full-system rollback cannot be represented as an exact NoID BAVR target. After a system restore, run a full NoID verification before re-applying a profile. |
| Cellular message cloud sync | Microsoft documents `AllowMessageSync=0` as preventing text-message backup/restore through Microsoft cloud services. Inbox `messaging.admx` confirms disabled DWORD `0`. | Added to Strict/Paranoid on Pro+. Home remains untouched/NotApplicable. |
| Online fonts | Microsoft documents `EnableFontProviders=0` as stopping `fs.microsoft.com` font/catalog traffic and limiting Windows components to local fonts; it can affect text/font availability. | Added only to Paranoid on Pro+ with an explicit UX warning. MSRecommended and Strict retain online font availability. |
| Device metadata companion apps | Microsoft documents `PreventDeviceMetadataFromNetwork=1` as blocking automatic downloads of applications associated with installed-device metadata. | Added only to Paranoid on Pro+ because printer/device companion convenience can be lost. |
| Windows Error Reporting | Microsoft documents `DisableWindowsErrorReporting` (`Disabled=1`) as turning error reporting off so that reports are neither collected nor sent; its service guidance says not to disable `WerSvc`. | Added only to Paranoid: through the policy on Pro+ and through Microsoft's documented non-policy WER setting (`Disabled=1`) on Home, measured effective on 26H2 Home; Paranoid sets `WerSvc` to its Windows default, Manual. Measured: disabling the service instead still sent reports and made crashed .NET programs hang, also with the policy set. |
| Product experimentation | Microsoft documents `AllowExperimentation=0` in Policy CSP, but the release 25H2 inbox ADMX set exposes no equivalent unmanaged-client Administrative Template contract. | Not configured without a documented unmanaged-client mechanism. |
| Online speech and input personalization | Microsoft’s current connection guidance and inbox `Globalization.admx` bind cloud input personalization to `AllowInputPersonalization`. | Already disabled (`0`) in all Privacy modes; redundant preference writes are not added. |
| App capability privacy | Microsoft provides Force Deny values for location, microphone, camera, messages, diagnostics, generative AI and other app capabilities. | Profile-separated: MSRecommended preserves user choice; Strict denies a focused privacy set; Paranoid denies the broad documented set and names conferencing/feature breakage. Neutral `0` values that could relax an existing deny stay excluded. |
| Activity/clipboard/cross-device state | Upload/publish activity and cross-device clipboard have documented controls; local history provides local convenience. | Cloud activity/cross-device paths are blocked according to profile decisions. Strict preserves local Win+V history; Paranoid can disable it. Deprecated cloud activity-history upload is not presented as a current extra win. |
| Cloud data deletion / privacy dashboard | Deleting previously uploaded account or diagnostic data is external and irreversible; local policy cannot reconstruct it. | Manual guidance only. It is not mixed into exact Restore or reported as a BAVR action. |
| OneDrive and Store | Microsoft documents policy surfaces, but forcing Allow values can relax a stricter existing organization policy and blocking all Store/OneDrive access can damage normal user workflows. | Feedback/sync-health/pre-sign-in traffic and Store OS-upgrade offers are reduced without writing neutral allows. Personal OneDrive and Store access are preserved unless the user manages them separately. |
| In-box app removal | Microsoft’s policy-based removal is Enterprise/Education 24H2+, has management-state constraints and does not restore deleted app data. Store/AppX removal likewise cannot recreate personal app state. | Tier 1 and Tier 2 remain explicit, default-off destructive choices. Policy prestate restores exactly; app/data recovery is honestly best effort. Microsoft Copilot is in both selected removal paths; Weather/Widgets remains a separate choice. No profile silently uninstalls apps. |
| AI/Copilot surfaces | The current WindowsAI CSP contains 25 headings and still provides no universal “all AI off” contract. The structured applicability table includes Enterprise, Education and IoT Enterprise for the current agent controls, while one provider-policy detail note says Enterprise/Education only. | Coverage and limits for all 25 headings are listed in [WINDOWS-AI-APPLICABILITY.md](WINDOWS-AI-APPLICABILITY.md). AntiAI applies the seven exact documented values on explicit 26H2 applicability profiles without inventing Insider enrollment; a 25H2 client still needs the documented enrollment evidence. The conflicting Microsoft IoT applicability wording is documented there. JSON without a published schema, logging-only controls and provider-specific DLP values are not fabricated. |
| Recall recovery | Microsoft's `AllowRecallEnablement=0` and `DisableAIDataAnalysis=1` contracts both delete existing Recall snapshots; the former also removes component files after restart. | AntiAI warns before Apply. BAVR restores recorded registry policy values, not deleted snapshots or removed component files. The product must not describe this as full data/component recovery. |
| DNS over HTTPS | Microsoft’s DNS client API exposes server templates, fallback and native per-interface-family encrypted state. Microsoft also requires a restart before a `DisabledComponents` change takes effect. | All four selected-provider IPv4/IPv6 endpoints plus every applicable adapter/family are applied and verified. Schema-6 BAVR separates effective transport scope from native/UI-visible state and also restores the raw registry values Windows' DoH APIs cannot reproduce: a binding-enabled IPv6 family remains exactly backed up, applied, verified and restored when a boot-effective `DisabledComponents=0xFF` state suppresses active IPv6 transport. Windows Settings can therefore show the persisted IPv6 resolvers as encrypted without NoID Privacy claiming IPv6 traffic occurred. A changed DisabledComponents value is not effective until restart. |
| Legacy network protocols/firewall | LLMNR, NetBIOS, WPAD, legacy TLS, discovery and inbound firewall posture have real security benefits and real LAN/device compatibility effects. | Profile-/prompt-separated AdvancedSecurity controls with exact target ownership. Third-party firewall detection is advisory; the user decision is authoritative. Unowned firewall rules are preserved. |
| Windows PowerShell 2.0 and WDigest | Microsoft removed Windows PowerShell 2.0 from serviced supported Windows 11 and removed/deprecated the obsolete WDigest baseline write. | No new-run target or count. Legacy sealed artifacts retain a fail-closed restore reader; removed components are not reintroduced. |
| Microsoft 365 Apps baseline | Microsoft publishes a separate current baseline for Microsoft 365 Apps. It is product/version/licensing-specific and not the Windows operating-system baseline. | Not silently imported into this Windows engine. ASR already protects relevant Office attack classes. Microsoft 365 policies are managed separately from Windows policies. |

## Editions and Privacy modes

Home support is not equivalent to “write every Pro policy anyway.” User-scope
preferences, supported APIs, DNS, firewall and other non-edition-limited controls
remain real protection on Home. A managed policy documented only for Pro+
remains untouched and is reported `NotApplicable`; the HTML/GUI must explain the
coverage difference without calling the whole device unprotected.

The three engine Privacy modes therefore keep a deliberate gradient:

- **MSRecommended:** broad security and privacy with normal local
  search, app permissions and cloud-account workflows preserved where possible.
- **Strict:** stronger privacy, disables settings/app-list backup and
  cellular message cloud sync, while preserving local search history, local
  clipboard history and online fonts.
- **Paranoid:** maximum documented data minimization, including
  local search-history, online-font and device-metadata companion-app trade-offs;
  its microphone/camera/app-capability and diagnostic restrictions remain
  intentionally unsuitable for many general-purpose workstations.

The Pro GUI uses MSRecommended for Quick & Secure and Strict for Balanced
and High Security. Custom also offers Paranoid; its additional restrictions
can disrupt everyday applications.

Windows 11 24H2, 25H2 and an explicitly reported 26H2 client in build family
`26300..27999` are fully supported product profiles. The framework runs Backup,
Apply, Verify/HTML and Restore for every enabled applicable target, including
the common 425-target SecurityBaseline.

App removal is not automatically selected by any profile. Destructive Tier 1,
Tier 2 and Weather/Widgets decisions remain explicit so a friendly wizard does
not hide an irreversible data-loss boundary.

## Primary sources

- [Per-interface DNS settings and address-family selectors](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-dns_interface_settings3)
- [SetInterfaceDnsSettings](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings)
- [Microsoft Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10)
- [Windows 11 v26H2 Security Baseline package and release notes](https://www.microsoft.com/en-us/download/details.aspx?id=55319) (Security Compliance Toolkit, 2026-09-29)
- [Windows 11 25H2 security baseline](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/windows-11-version-25h2-security-baseline/4456231)
- [Microsoft Edge security baseline/reviews](https://techcommunity.microsoft.com/category/security-baselines/blog/microsoft-security-baselines/)
- [Microsoft Edge policy reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies)
- [Microsoft Defender protection features](https://learn.microsoft.com/en-us/defender-endpoint/configure-protection-features-microsoft-defender-antivirus)
- [Controlled Folder Access](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure)
- [Smart App Control](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview)
- [App Control for Business](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview)
- [Tamper Protection](https://learn.microsoft.com/en-us/defender-endpoint/manage-tamper-protection-individual-device)
- [Windows privacy compliance guide](https://learn.microsoft.com/en-us/windows/privacy/windows-privacy-compliance-guide)
- [Manage Windows connections to Microsoft services](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
- [`WM_SETTINGCHANGE` message](https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-settingchange)
- [`Set-WindowsSearchSetting`](https://learn.microsoft.com/en-us/powershell/module/windowssearch/set-windowssearchsetting?view=windowsserver2025-ps)
- [`SendMessageTimeoutW` function](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeoutw)
- [System Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system)
- [Messaging Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-messaging)
- [DeviceInstallation Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceinstallation)
- [SettingsSync Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-settingssync)
- [Point-in-time restore for Windows](https://learn.microsoft.com/en-us/windows/configuration/point-in-time-restore)
- [Windows Update client policies](https://learn.microsoft.com/en-us/windows/deployment/update/waas-manage-updates-wufb)
- [Windows Update safeguard holds](https://learn.microsoft.com/en-us/windows/deployment/update/safeguard-holds)
- [BitLocker overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
- [Secure Boot and Trusted Boot](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/trusted-boot)
- [Windows Hello/passwordless sign-in](https://learn.microsoft.com/en-us/windows/security/book/identity-protection-passwordless-sign-in)
- [Configure IPv6 in Windows (`DisabledComponents` and restart requirement)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows)

## Configuration and runtime protection

A matching policy value confirms configuration, not that every related Windows
feature is running. The verification report shows runtime protection separately;
see [restart and recovery limits](SECURITY-BASELINE-RECOVERY.md).

DNS Restore selects the recorded address family through the native Windows API.
It preserves an unowned peer family; a configuration check does not prove DHCP
renewal or encrypted network traffic.
