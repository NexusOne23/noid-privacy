# Windows 11 security and privacy primary-source review (2026)

**Review date:** 2026-08-13
**Product scope:** NoID Privacy v2.2.5 engine on supported Windows 11 24H2/25H2 clients, plus the explicitly admitted but not release-approved Windows 11 26H2 Experimental Preview path
**Source boundary:** Microsoft primary documentation, shipped Microsoft baseline packages and inbox ADMX files on the release images

## Decision rule

A documented control is not automatically a good product default. NoID Privacy
adds a control only when its security/privacy benefit, supported applicability,
user-facing effect and recovery contract are all understood. Every automated
mutation must enter the same sealed Backup → Apply → Verify/HTML → exact Restore
path. Unsupported policies, irreversible cloud/device actions and protected
security settings are never reported as successful registry writes.

The product priority used in this review is correctness, security, privacy,
stability/recoverability, UX and then simplicity. “Maximum number of disabled
features” is not a release objective.

## Review result

| Area | 2026 primary-source finding | NoID Privacy decision |
|---|---|---|
| Windows Security Baseline | Microsoft’s Windows 11 25H2 baseline remains the current client baseline. The recorded 24H2/25H2 semantic delta contains no target that is unsafe merely because the client is 24H2. | Included as the 425-target SecurityBaseline on supported 24H2/25H2 through one BAVR implementation. Product deviations and the 24H2 carry-back are machine-documented in [SECURITY-BASELINE-PROVENANCE.md](SECURITY-BASELINE-PROVENANCE.md). |
| Edge Security Baseline | Microsoft’s Edge reviews through version 149 state that v139 remains the recommended baseline and no additional new setting requires enforcement. | All 19 v139 baseline values remain exact. The reviews do not justify silently adding later Edge settings as baseline values. |
| Edge search privacy | Microsoft documents that disabling `SearchSuggestEnabled` prevents web suggestions and transmission of typed characters/visited URLs while keeping local history/favorite suggestions. Trending suggestions and Reading Mode online extraction have separate current policies. | Included as three separately labelled privacy additions with per-policy minimum Edge versions. Local browser history remains useful. Full Edge scope is 19 baseline + 7 privacy values; schema-6 BAVR seals Edge installation/version applicability. |
| Edge XSLT | Microsoft’s v147 review describes `XSLTEnabled` as a transition/test control for a legacy feature planned for removal and recommends dependency testing, not universal enforcement. | Excluded from normal profiles because disabling it can break legacy enterprise web applications. It is not mislabelled as a baseline requirement. |
| Defender core protection | Current Microsoft guidance continues to recommend real-time/behavior protection, cloud protection, PUA blocking, Block at First Sight and Network Protection. | Already covered by the Microsoft Security Baseline (`PUAProtection`, `SpynetReporting`, `DisableBlockAtFirstSeen`, `EnableNetworkProtection` and related values). Safe-sample submission remains the explicit NoID Privacy default; “send all” requires an informed choice. |
| Attack Surface Reduction | Microsoft’s current OS matrix marks the Exchange webshell rule inapplicable to Windows 11 clients; other ASR rules have compatibility and cloud prerequisites. | Nineteen identities remain declared; 18 are client-applicable. Rules, user choices, third-party endpoint state and cloud prerequisites are sealed and reported as Passed/Failed/NotChecked/NotApplicable rather than flattened to green. |
| Controlled Folder Access | Microsoft documents block, audit and disk-only modes plus environment-specific protected folders/allowed apps. Blind block mode can deny legitimate application writes. | Not inserted into Quick Secure/Balanced/High Security. A future feature would require a separate audit/learning and allowlist workflow, conflict handling, target-level BAVR and clear block-event UX. |
| Smart App Control | Microsoft documents clean-install/region requirements and lifecycle states; selecting Off/On can be a one-way user operation. Registry forcing is documented for testing only and can compromise protection. | Never automated as an ordinary tweak and never claimed BAVR-exact. NoID Privacy may display the authoritative Windows state, but the user controls it through Windows Security. |
| App Control for Business / AppLocker | Microsoft requires policy design, audit deployment and app-specific trust rules; an incorrect allow/deny policy can block required software or boot paths. | Outside the one-click profiles. The existing limited SRP compatibility scope is not marketed as equivalent App Control enforcement. A future App Control product requires its own audited deployment lifecycle. |
| Tamper Protection | Microsoft states that Tamper Protection blocks registry attempts and standalone users manage it in Windows Security; managed environments use the authoritative security-management channel. | No registry write and no false enforcement claim. Preserve the protected state and give a manual Windows Security path when relevant. |
| LSA, Credential Guard and HVCI | Microsoft recommends hardware-backed credential/code-integrity protection and documents recovery considerations for incompatible drivers. | Covered by current baseline targets where supported. Edition/feature absence is NotApplicable. NoID Privacy does not claim hardware capability merely because a policy value exists. |
| Secure Boot, Trusted Boot and TPM | These are firmware/hardware roots of trust. Changing boot mode or clearing/reconfiguring TPM can cause boot or protected-data loss. | Detect/report only in release/system checks; never an automatic profile mutation. Windows/OEM servicing remains responsible for Secure Boot certificate updates. |
| BitLocker | Microsoft recommends volume encryption for lost/stolen-device protection; activation and recovery-key custody are user/device/account decisions. | Baseline policies are applied exactly, including an explicit removable-drive write choice. NoID Privacy does not auto-encrypt a system drive or claim encryption is active from policy state alone. |
| Windows Hello/passkeys | Microsoft recommends phishing-resistant, TPM-backed passwordless sign-in. Enrollment is identity-, biometric-, hardware- and recovery-specific. | Recommended/manual workflow, not a reversible machine-policy tweak. The product preserves the user’s account model. |
| Windows Update | Microsoft recommends automatic servicing with a small policy set and preserving safeguard holds; bypassing a hold can expose known compatibility failures. | Security/quality updating stays enabled. Optional non-security content remains user-selected, early-rollout intent remains user-owned, peer-to-peer Delivery Optimization is disabled where supported, and NoID Privacy never bypasses safeguard holds. |
| Root certificates, licensing, NCSI and time | Microsoft’s restricted-traffic guidance documents ways to suppress these connections but warns that several are required for security, licensing, connectivity detection or correct operation. | Not disabled merely to reduce traffic. Breaking trust updates, activation, captive-portal/connectivity detection or time integrity would be a security/UX regression. |
| Diagnostic data and OneSettings | Microsoft documents edition-specific diagnostic floors and separate log/OneSettings controls. | Required diagnostic data in MSRecommended; the supported minimum in stricter modes; extra log collection, feedback prompts, tailored experiences and OneSettings downloads are reduced through documented policies. Home never receives a false Enterprise-only success. |
| Windows Search | Microsoft distinguishes local device-search history/ranking from web/cloud results, documents `Set-WindowsSearchSetting -EnableWebResultsSetting` for web results/suggestions and documents `WM_SETTINGCHANGE` for settings/policy changes. | Web/Bing/cloud surfaces are disabled in every mode. MSRecommended/Strict preserve local search history and must still find local apps, Settings and indexed files. Paranoid alone disables local device-search history as an explicit convenience trade-off. Apply and exact Restore use the actual Explorer user's limited token for the native API refresh, prove no additional Search registry/API state changed and retain the documented broadcasts; Verify/HTML bind the raw target to the effective API result rather than accepting stale UI state. |
| Widgets | Microsoft documents stable `AllowNewsAndInterests` for Pro+; the newer `DisableWidgetsBoard` and `DisableWidgetsOnLockScreen` contracts remain Insider Preview-only. Current Windows UCPD can protect the stable registry value from local command-line mutation. | Strict/Paranoid select the stable policy where exact local Apply/Restore is available. Active/unknown UCPD makes that target untouched and `NotApplicable`; NoID Privacy never disables UCPD to force it. Preview-only widget policies are excluded from stable profiles. Weather/Widgets package removal remains a separate, destructive default-off choice. |
| Windows Spotlight on Pro | Microsoft limits the Spotlight master, Settings, Action Center, Desktop collection, cloud-optimized-content and Windows-tips policies to Enterprise/Education/IoT Enterprise. The third-party-suggestions policy supports Pro but explicitly does not block Microsoft's own suggestions. | Pro gets the supported third-party-suggestion control and honest `NotApplicable` results for the Enterprise-only controls. NoID Privacy does not claim full Spotlight disable on Pro and does not replace the missing contract with undocumented ContentDeliveryManager writes. |
| Settings Sync and Windows Backup | Current Policy CSP and inbox `SettingSync.admx` use `DisableSettingSync=2`, user-override false value `1`, and `EnableWindowsBackup` disabled value `0`. The machine gate also passed against Microsoft's official 24H2 V2 Administrative Templates. | Strict/Paranoid include the exact Pro+ contracts without a 25H2-only branch. Per-category Sync values are deliberately not duplicated because the master policy already blocks every group. Home remains untouched/NotApplicable. |
| Cellular message cloud sync | Microsoft documents `AllowMessageSync=0` as preventing text-message backup/restore through Microsoft cloud services. Inbox `messaging.admx` confirms disabled DWORD `0`. | Added to Strict/Paranoid on Pro+. Home remains untouched/NotApplicable. |
| Online fonts | Microsoft documents `EnableFontProviders=0` as stopping `fs.microsoft.com` font/catalog traffic and limiting Windows components to local fonts; it can affect text/font availability. | Added only to Paranoid on Pro+ with an explicit UX warning. MSRecommended and Strict retain online font availability. |
| Device metadata companion apps | Microsoft documents `PreventDeviceMetadataFromNetwork=1` as blocking automatic downloads of applications associated with installed-device metadata. | Added only to Paranoid on Pro+ because printer/device companion convenience can be lost. |
| Product experimentation | Microsoft documents `AllowExperimentation=0` in Policy CSP, but the release 25H2 inbox ADMX set exposes no equivalent unmanaged-client Administrative Template contract. | Excluded until a locally supported, runtime-verifiable mechanism is proven. A direct speculative registry write would repeat the false-compliance error class removed in v2.2.5. |
| Online speech and input personalization | Microsoft’s current connection guidance and inbox `Globalization.admx` bind cloud input personalization to `AllowInputPersonalization`. | Already disabled (`0`) in all Privacy modes; redundant preference writes are not added. |
| App capability privacy | Microsoft provides Force Deny values for location, microphone, camera, messages, diagnostics, generative AI and other app capabilities. | Profile-separated: MSRecommended preserves user choice; Strict denies a focused privacy set; Paranoid denies the broad documented set and names conferencing/feature breakage. Neutral `0` values that could relax an existing deny stay excluded. |
| Activity/clipboard/cross-device state | Upload/publish activity and cross-device clipboard have documented controls; local history provides local convenience. | Cloud activity/cross-device paths are blocked according to profile decisions. Strict preserves local Win+V history; Paranoid can disable it. Deprecated cloud activity-history upload is not presented as a current extra win. |
| Cloud data deletion / privacy dashboard | Deleting previously uploaded account or diagnostic data is external and irreversible; local policy cannot reconstruct it. | Manual guidance only. It is not mixed into exact Restore or reported as a BAVR action. |
| OneDrive and Store | Microsoft documents policy surfaces, but forcing Allow values can relax a stricter existing organization policy and blocking all Store/OneDrive access can damage normal user workflows. | Feedback/sync-health/pre-sign-in traffic and Store OS-upgrade offers are reduced without writing neutral allows. Personal OneDrive and Store access are preserved unless the user manages them separately. |
| In-box app removal | Microsoft’s policy-based removal is Enterprise/Education 24H2+, has management-state constraints and does not restore deleted app data. Store/AppX removal likewise cannot recreate personal app state. | Tier 1 and Tier 2 remain explicit, default-off destructive choices. Policy prestate restores exactly; app/data recovery is honestly best effort. Microsoft Copilot is in both selected removal paths; Weather/Widgets remains a separate choice. No profile silently uninstalls apps. |
| AI/Copilot surfaces | Current Microsoft policies cover multiple Windows, Edge and app AI surfaces but do not provide one universal “all AI off” contract. | AntiAI keeps exact build/edition/product applicability and four URI-source checks. No hosts/region-file tricks or universal protection claims. App removal remains the separate destructive tier. |
| DNS over HTTPS | Microsoft’s DNS client API exposes server templates, fallback and native per-interface-family encrypted state. Microsoft also requires a restart before a `DisabledComponents` change takes effect. | All four selected-provider IPv4/IPv6 endpoints plus every applicable adapter/family are applied and verified. Schema-5 BAVR separates effective transport scope from native/UI-visible state: a binding-enabled IPv6 family remains exactly backed up, applied, verified and restored when a boot-effective `DisabledComponents=0xFF` state suppresses active IPv6 transport. Windows Settings can therefore show the persisted IPv6 resolvers as encrypted without NoID Privacy claiming IPv6 traffic occurred. The release gate rejects an un-restarted registry-only simulation. |
| Legacy network protocols/firewall | LLMNR, NetBIOS, WPAD, legacy TLS, discovery and inbound firewall posture have real security benefits and real LAN/device compatibility effects. | Profile-/prompt-separated AdvancedSecurity controls with exact target ownership. Third-party firewall detection is advisory; the user decision is authoritative. Unowned firewall rules are preserved. |
| Windows PowerShell 2.0 and WDigest | Microsoft removed Windows PowerShell 2.0 from serviced supported Windows 11 and removed/deprecated the obsolete WDigest baseline write. | No new-run target or count. Legacy sealed artifacts retain a fail-closed restore reader; removed components are not reintroduced. |
| Microsoft 365 Apps baseline | Microsoft publishes a separate current baseline for Microsoft 365 Apps. It is product/version/licensing-specific and not the Windows operating-system baseline. | Not silently imported into this Windows engine. ASR already protects relevant Office attack classes. A future Office module would need product discovery, its own provenance, compatibility decisions and BAVR. |

## Edition and UX conclusion

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

The Pro GUI maps these engine modes into user-oriented presets and Custom
choices. That mapping is a separate release contract and must be revalidated
after the final engine is synchronized; the engine-mode names are deliberately
not presented here as one-to-one aliases for Quick Secure, Balanced or High
Security.

An explicitly reported Windows 11 26H2 preview in build family `26300..27999`
is admitted as `Experimental`: the framework runs Backup, Apply, Verify/HTML and
Restore for every enabled target whose module/build/edition applicability
matches, including the carried-forward 425-target SecurityBaseline. This is a
technical apply path, not runtime-validation evidence or release approval. The
stable support claim remains 24H2/25H2 until the full release gate passes on a
26H2 image against then-current Microsoft primary sources.

App removal is not automatically selected by any profile. Destructive Tier 1,
Tier 2 and Weather/Widgets decisions remain explicit so a friendly wizard does
not hide an irreversible data-loss boundary.

## Primary sources

- [Microsoft Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10)
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
- [Windows Update client policies](https://learn.microsoft.com/en-us/windows/deployment/update/waas-manage-updates-wufb)
- [Windows Update safeguard holds](https://learn.microsoft.com/en-us/windows/deployment/update/safeguard-holds)
- [BitLocker overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
- [Secure Boot and Trusted Boot](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/trusted-boot)
- [Windows Hello/passwordless sign-in](https://learn.microsoft.com/en-us/windows/security/book/identity-protection-passwordless-sign-in)
- [Configure IPv6 in Windows (`DisabledComponents` and restart requirement)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows)

## Evidence boundary

This review proves that the selected automated controls have current primary
support and that excluded controls have an explicit reason. It does not prove a
specific device is fully protected. Release approval still requires the Home,
Pro and Enterprise VM matrix, every GUI profile, exact BAVR/HTML reconciliation,
IPv4/IPv6 DoH visibility, installer lifecycle and independent prestate/restore
comparisons described in [WINDOWS-VM-RELEASE-GATE.md](WINDOWS-VM-RELEASE-GATE.md).
