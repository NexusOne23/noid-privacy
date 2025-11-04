# 🔐 Registry Keys Reference

**Complete list of all 391 registry keys modified by NoID Privacy**


> Auto-generated from RegistryChanges-Definition.ps1


---


## 📑 Modules

- **SecurityBaseline-Advanced.ps1**: 41 keys

- **SecurityBaseline-AI.ps1**: 15 keys

- **SecurityBaseline-ASR.ps1**: 2 keys

- **SecurityBaseline-Bloatware.ps1**: 15 keys

- **SecurityBaseline-Common.ps1**: 1 keys

- **SecurityBaseline-Core.ps1**: 135 keys

- **SecurityBaseline-DNS.ps1**: 3 keys

- **SecurityBaseline-Edge.ps1**: 25 keys

- **SecurityBaseline-OneDrive.ps1**: 8 keys

- **SecurityBaseline-Performance.ps1**: 9 keys

- **SecurityBaseline-Telemetry.ps1**: 110 keys

- **SecurityBaseline-UAC.ps1**: 10 keys

- **SecurityBaseline-WindowsUpdate.ps1**: 9 keys

- **SecurityBaseline-WirelessDisplay.ps1**: 9 keys


---


## Advanced Module

**Source**: `SecurityBaseline-Advanced.ps1`

**Keys**: 41


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config` | Enabled | 1 | DWord | Enable LAPS |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config` | PasswordAgeDays | 30 | DWord | PW rotation every 30 days |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config` | PasswordComplexity | 4 | DWord | Max complexity |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config` | PasswordLength | 20 | DWord | PW length 20 characters |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config` | BackupDirectory | 2 | DWord | Backup to AD/Entra |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config` | PostAuthenticationActions | 3 | DWord | Reset PW after auth |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | SCENoApplyLegacyAuditPolicy | 1 | DWord | Force advanced audit subcategory settings (override legacy) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` | EnableScriptBlockLogging | 1 | DWord | PowerShell Script Block Logging |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` | EnableTranscripting | 1 | DWord | PowerShell Transcription |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` | EnableInvocationHeader | 1 | DWord | Invocation Header |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` | OutputDirectory | $transcriptDir | String | Transcript Output Dir |

| `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | AuditNTLMInDomain | 7 | DWord | NTLM Auditing: Track all NTLM auth in domain |

| `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | RestrictNTLMInDomain | 1 | DWord | NTLM Restriction: Audit-Only (no blocking) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | AuditReceivingNTLMTraffic | 2 | DWord | Audit incoming NTLM traffic (2=Enable) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | RestrictReceivingNTLMTraffic | 1 | DWord | NTLM Restriction Outbound: Audit-Only |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server` | Enabled | 0 | DWord | Disable $protocol Server |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server` | DisabledByDefault | 1 | DWord | $protocol Server default off |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client` | Enabled | 0 | DWord | Disable $protocol Client |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client` | DisabledByDefault | 1 | DWord | $protocol Client default off |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server` | Enabled | 1 | DWord | Enable $protocol Server |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server` | DisabledByDefault | 0 | DWord | $protocol Server default on |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client` | Enabled | 1 | DWord | Enable $protocol Client |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client` | DisabledByDefault | 0 | DWord | $protocol Client default on |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher` | Enabled | 0 | DWord | Disable $cipher |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher` | Enabled | -1 | DWord | Enable $cipher |

| `HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002` | Functions | $cipherSuiteOrder | String | Cipher Suite Order (TLS 1.3 + 1.2 GCM/CHACHA only, no CBC) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA` | Enabled | 0 | DWord | Disable SHA-1 for TLS/SSL |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256` | Enabled | -1 | DWord | Enable SHA-256 |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384` | Enabled | -1 | DWord | Enable SHA-384 |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512` | Enabled | -1 | DWord | Enable SHA-512 |

| `$path` | SchUseStrongCrypto | 1 | DWord | .NET Strong Crypto |

| `$path` | SystemDefaultTlsVersions | 1 | DWord | .NET System TLS Versions |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL` | EventLogging | 7 | DWord | Schannel Event Logging (all events) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` | UseLogonCredential | 0 | DWord | WDigest disabled (no plaintext passwords in RAM) |




## AI Module

**Source**: `SecurityBaseline-AI.ps1`

**Keys**: 15


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` | DisableAIDataAnalysis | 1 | DWord | Windows Recall deaktivieren (KEINE Screenshots!) |

| `HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableAIDataAnalysis` | value | 1 | DWord | Recall Policy Manager: DISABLED |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` | TurnOffWindowsCopilot | 1 | DWord | Copilot: Layer 1 - Main Policy (HKLM) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot` | TurnOffWindowsCopilot | 1 | DWord | Copilot: Layer 2 - Legacy Policy Path |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot` | ShowCopilotButton | 0 | DWord | Copilot: Layer 3 - Hide Taskbar Button |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer` | DisableWindowsCopilot | 1 | DWord | Copilot: Layer 4 - Explorer Disable |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` | DisableClickToDo | 1 | DWord | Click to Do deaktivieren (AI Screenshot Analysis) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint` | DisableCocreator | 1 | DWord | Paint Cocreator deaktivieren (AI Image Gen) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint` | DisableGenerativeFill | 1 | DWord | Paint Generative Fill deaktivieren (AI Edit) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint` | DisableImageCreator | 1 | DWord | Paint Image Creator deaktivieren (AI Art) |

| `HKLM:\SOFTWARE\Policies\WindowsNotepad` | DisableAIFeatures | 1 | DWord | Notepad AI Features deaktivieren (Copilot Button + AI Assistance) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` | DisableSettingsAgent | 1 | DWord | Settings Agent deaktivieren (AI in Settings) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot` | DisableCopilotProactive | 1 | DWord | Copilot Proactive deaktivieren (keine ungewollten Vorschlaege) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` | SetMaximumStorageSpaceForRecallSnapshots | 10 | DWord | Recall: Max Storage = 10GB (Minimum, if reactivated) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` | SetMaximumStorageDurationForRecallSnapshots | 1 | DWord | Recall: Max Duration = 1 Day (Minimum, if reactivated) |




## ASR Module

**Source**: `SecurityBaseline-ASR.ps1`

**Keys**: 2


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}` | Deny_Execute | 1 | DWord | USB: Deny execution |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer` | SmartScreenEnabled | RequireAdmin | String | Enforce SmartScreen |




## Bloatware Module

**Source**: `SecurityBaseline-Bloatware.ps1`

**Keys**: 15


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableWindowsConsumerFeatures | 1 | DWord | Disable Consumer Features (no auto-install apps) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableSoftLanding | 1 | DWord | Disable Soft Landing (no app suggestions) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableCloudOptimizedContent | 1 | DWord | Disable cloud-optimized content |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableThirdPartySuggestions | 1 | DWord | Disable third-party suggestions in Start Menu |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableWindowsSpotlightFeatures | 1 | DWord | Disable Windows Spotlight features |

| `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | SubscribedContent-338388Enabled | 0 | DWord | Disable suggested apps in Start Menu (stub apps) |

| `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | SubscribedContent-338389Enabled | 0 | DWord | Disable tips and tricks |

| `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | SubscribedContent-310093Enabled | 0 | DWord | Disable app suggestions after Windows Update |

| `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | SubscribedContent-353698Enabled | 0 | DWord | Disable Timeline suggestions |

| `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | SilentInstalledAppsEnabled | 0 | DWord | Disable silent installation of apps |

| `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | SystemPaneSuggestionsEnabled | 0 | DWord | Disable suggestions in Settings |

| `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | PreInstalledAppsEnabled | 0 | DWord | Disable pre-installed app advertising |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat` | ChatIcon | 3 | DWord | Disable Teams Chat icon |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot` | TurnOffWindowsCopilot | 1 | DWord | Disable Windows Copilot |

| `HKLM:\SOFTWARE\Policies\Microsoft\Dsh` | AllowNewsAndInterests | 0 | DWord | Disable Widgets |




## Common Module

**Source**: `SecurityBaseline-Common.ps1`

**Keys**: 1


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SOFTWARE\Test` | Value | 1 | DWord |  |




## Core Module

**Source**: `SecurityBaseline-Core.ps1`

**Keys**: 135


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters` | DisableNBTNameResolution | 1 | DWord | NetBIOS Name Resolution global deaktivieren |

| `HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\` | NodeType | 2 | DWord | NetBT auf P-Node (nur WINS) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$guid` | NetbiosOptions | 2 | DWord | NetBIOS auf Adapter $guid deaktivieren |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit` | ProcessCreationIncludeCmdLine_Enabled | 1 | DWord | Command Line in Event ID 4688 |

| `HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main` | DisableIE11Launch | 1 | DWord | IE11 Launch via COM blockieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL` | iexplore.exe | 1 | DWord | ActiveX Installation blockieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers` | RpcAuthnLevelPrivacyEnabled | 1 | DWord | RPC Privacy Level fuer Print Spooler |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers` | RegisterSpoolerRemoteRpcEndPoint | 2 | DWord | Remote RPC Endpoint deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS` | ConvertWarnToBlock | 1 | DWord | NIS Warn->Block |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting` | ReportDynamicSignatureDroppedEvent | 1 | DWord | Dynamic Signature Events |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan` | CheckExclusions | 1 | DWord | Scan Exclusions too |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine` | MpCloudBlockLevel | 2 | DWord | Cloud Protection Level High |

| `$nisPath` | ConvertWarnToBlock | 1 | DWord | Network Inspection: Auto-convert warnings to blocks |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender` | ExclusionsVisibleToLocalUsers | 1 | DWord | Exclusions visible to local users (transparency) |

| `$rtpPath` | ConfigureRealTimeProtectionOOBE | 1 | DWord | Real-Time Protection active during OOBE setup |

| `$scanPath` | ScanExcludedFilesInQuickScan | 1 | DWord | Also check excluded files in quick scans |

| `$reportPath` | ReportDynamicSignatureDroppedEvent | 1 | DWord | Report dynamic signature dropped events |

| `$rtpPath` | RealtimeScanDirection | 0 | DWord | Realtime scan: Both incoming and outgoing files |

| `$mpEnginePath` | MpBafsExtendedTimeout | 50 | DWord | Extended timeout for cloud analysis (50 seconds) |

| `HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access` | EnableControlledFolderAccess | 1 | DWord | Controlled Folder Access aktivieren |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | NoDriveTypeAutoRun | 255 | DWord | AutoPlay auf allen Laufwerkstypen deaktiviert |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | NoAutorun | 1 | DWord | AutoRun global deaktiviert (autorun.inf ignoriert) |

| `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | NoDriveTypeAutoRun | 255 | DWord | AutoPlay User-Level deaktiviert |

| `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | NoAutorun | 1 | DWord | AutoRun User-Level deaktiviert |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun` | NoDriveTypeAutoRun | 255 | DWord | Legacy AutoRun Path |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer` | SmartScreenEnabled | RequireAdmin | String | SmartScreen: Unbekannte Apps brauchen Admin-Prompt |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | SmartScreenEnabled | 1 | DWord | Edge: SmartScreen aktiviert |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | SmartScreenPuaEnabled | 1 | DWord | Edge: PUA-Schutz aktiviert (Toolbars, Adware) |

| `HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter` | EnabledV9 | 1 | DWord | Phishing Filter aktiviert |

| `HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter` | PreventOverride | 1 | DWord | Phishing warnings cannot be bypassed |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components` | ServiceEnabled | 1 | DWord | Enhanced Phishing Protection (Win11) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components` | NotifyPasswordReuse | 1 | DWord | Warning on password reuse on phishing sites |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components` | NotifyUnsafeApp | 1 | DWord | Warning when starting unsafe apps |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | InvalidAuthenticationDelayTimeInMs | 2000 | DWord | SMB Auth Rate Limiter: 2000ms delay (Brute-Force Protection) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | EnableAuthenticationRateLimiter | 1 | DWord | SMB Auth Rate Limiter aktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | SMBServerMinimumProtocol | 768 | DWord | SMB Min Version: 3.0.0 (768 = SMB 3.0) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | SMBServerMaximumProtocol | 1025 | DWord | SMB Max Version: 3.1.1 (1025 = SMB 3.1.1) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | AuditClientDoesNotSupportEncryption | 1 | DWord | Audit: Client ohne Encryption-Support |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | AuditClientDoesNotSupportSigning | 1 | DWord | Audit: Client ohne Signing-Support |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | AuditInsecureGuestLogon | 1 | DWord | Audit: Unsichere Guest-Logins |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | EnableRemoteMailslots | 0 | DWord | Remote Mailslots deaktivieren (Legacy-Feature) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | SMBClientMinimumProtocol | 768 | DWord | SMB Client Min Version: 3.0.0 |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | SMBClientMaximumProtocol | 1025 | DWord | SMB Client Max Version: 3.1.1 |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | AuditInsecureGuestLogon | 1 | DWord | Audit: Unsichere Guest-Logins (Client) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | AuditServerDoesNotSupportEncryption | 1 | DWord | Audit: Server ohne Encryption |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | AuditServerDoesNotSupportSigning | 1 | DWord | Audit: Server ohne Signing |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | EnableRemoteMailslots | 0 | DWord | Remote Mailslots deaktivieren (Client) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | RequireEncryption | 0 | DWord | Encryption nicht erzwingen (Kompatibilitaet) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | SMB1 | 0 | DWord | SMB1 Server deaktivieren (unsicher!) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | DisableSmb1 | 1 | DWord | SMB1 Client deaktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | EnableSecuritySignature | 1 | DWord | SMB Signing Client aktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | RequireSecuritySignature | 1 | DWord | SMB Signing Client erzwingen |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | EnableSecuritySignature | 1 | DWord | SMB Signing Server aktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | RequireSecuritySignature | 1 | DWord | SMB Signing Server erzwingen |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | EncryptData | 1 | DWord | SMB Encryption aktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | RejectUnencryptedAccess | 1 | DWord | Unencrypted Access ablehnen |

| `HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation` | AllowInsecureGuestAuth | 0 | DWord | Unsichere SMB Guest-Logins deaktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | EnablePlainTextPassword | 0 | DWord | Plaintext-Passwoerter an SMB-Server verbieten |

| `HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10` | Start | 4 | DWord | SMB1 Client Driver deaktivieren (Disabled = 4) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | RequireSignOrSeal | 1 | DWord | NTLM Sign/Seal erzwingen |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` | EnableMulticast | 0 | DWord | LLMNR deaktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | EveryoneIncludesAnonymous | 0 | DWord | Everyone beinhaltet KEINE anonymen User |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | NoLMHash | 1 | DWord | LM Hashes deaktivieren (veraltet seit 1992) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad` | DoNotUseWPAD | 1 | DWord | WPAD deaktivieren |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp` | DisableWpad | 1 | DWord | WinHTTP WPAD deaktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters` | DisableMdnsDiscovery | 1 | DWord | WlanSvc mDNS Discovery deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` | EnableMulticast | 0 | DWord | LLMNR deaktivieren (redundant check) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections` | NC_ShowSharedAccessUI | 0 | DWord | Network Discovery UI deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections` | NC_AllowNetBridge_NLA | 0 | DWord | Network Bridge deaktivieren |

| `HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config` | AutoConnectAllowedOEM | 0 | DWord | Wi-Fi Sense Auto-Connect deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars` | EnableRegistrars | 0 | DWord | Windows Connect Now deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI` | DisableWcnUi | 1 | DWord | WCN UI deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Peernet` | Disabled | 1 | DWord | Peer-to-Peer Networking deaktivieren |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | DisableAutomaticRestartSignOn | 1 | DWord | Automatische Netzwerk-Authentifizierung deaktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | AutoShareServer | 0 | DWord | Admin Shares auf Servern deaktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | AutoShareWks | 0 | DWord | Admin Shares auf Workstations deaktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | RestrictNullSessAccess | 1 | DWord | Anonymous Access zu Named Pipes einschraenken |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | RestrictAnonymousSAM | 1 | DWord | Anonymous SAM Enumeration verbieten |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | RestrictAnonymous | 1 | DWord | Anonymous Share Enumeration verbieten |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | EveryoneIncludesAnonymous | 0 | DWord | Everyone-Permissions NICHT fuer Anonymous |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | NullSessionPipes |  | MultiString | Keine Named Pipes fuer Anonymous Access |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | NullSessionShares |  | MultiString | Keine Shares fuer Anonymous Access |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | LimitBlankPasswordUse | 1 | DWord | Blank passwords nur bei Console-Logon (kein Remote) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | LmCompatibilityLevel | 5 | DWord | LAN Manager Auth Level: 5 = NTLMv2 only (no LM/NTLM) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\LDAP` | LDAPClientIntegrity | 1 | DWord | LDAP Client Signing: Negotiate signing |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | NTLMMinClientSec | 537395200 | DWord | NTLM Client: Require NTLMv2 + 128-bit encryption |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | NTLMMinServerSec | 537395200 | DWord | NTLM Server: Require NTLMv2 + 128-bit encryption |

| `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | ScRemoveOption | 1 | String | Smart card removal: Lock Workstation (1) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | RestrictRemoteSAM | O:BAG:BAD:(A;;RC;;;BA) | String | Restrict remote SAM calls to Administrators only (SDDL) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | AllowNullSessionFallback | 0 | DWord | Do NOT allow NULL session fallback for LocalSystem |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters` | AllowEncryptionOracle | 0 | DWord | Encryption Oracle: Force Updated Clients (most secure) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation` | AllowDefCredentialsWhenNTLMOnly | 0 | DWord | Do NOT allow delegation of credentials when NTLM only |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer` | EnableUserControl | 0 | DWord | User control over installs: DISABLED (security) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer` | AlwaysInstallElevated | 0 | DWord | Always install elevated: DISABLED (prevents privilege escalation) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds` | DisableEnclosureDownload | 1 | DWord | RSS: Prevent automatic enclosure downloads (security) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | AllowIndexingEncryptedStoresOrItems | 0 | DWord | Search: Do NOT index encrypted files (privacy) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\System` | EnumerateLocalUsers | 0 | DWord | Do NOT enumerate local users on logon screen (privacy) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server` | fDenyTSConnections | 1 | DWord | RDP-Verbindungen verweigern |

| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg` | RemoteRegAccess | 0 | DWord | Remote Registry Access verweigern |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance` | fAllowToGetHelp | 0 | DWord | Remote Assistance deaktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance` | fAllowUnsolicited | 0 | DWord | Unaufgeforderte Remote Assistance deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | fAllowToGetHelp | 0 | DWord | Remote Assistance via GP deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | fAllowUnsolicited | 0 | DWord | Unaufgeforderte RA via GP deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | Shadow | 0 | DWord | RDP Shadow Sessions verbieten |

| `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule` | DisableRpcOverTcp | 1 | DWord | Remote Scheduled Tasks deaktivieren |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo` | Enabled | 0 | DWord | Sudo for Windows deaktivieren (Privilege Escalation Prevention) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` | SupportedEncryptionTypes | 2147483647 | DWord | Alle modernen Kerberos Enc Types |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` | PKINITHashAlgorithm | 56 | DWord | PKINIT: SHA-256/384/512 (OHNE SHA-1!) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters` | PKINITHashAlgorithm | 56 | DWord | KDC PKINIT: SHA-256/384/512 (OHNE SHA-1!) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments` | SaveZoneInformation | 2 | DWord | MotW erzwingen |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments` | ScanWithAntiVirus | 3 | DWord | Immer mit AV scannen |

| `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard` | EnableVirtualizationBasedSecurity | 1 | DWord | VBS aktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard` | RequirePlatformSecurityFeatures | 3 | DWord | VBS: Secure Boot + DMA |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | LsaCfgFlags | 1 | DWord | Credential Guard (UEFI Lock) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard` | Enabled | 1 | DWord | Enable Credential Guard Scenario |

| `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` | Enabled | 1 | DWord | Enable HVCI/Memory Integrity |

| `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` | WasEnabledBy | 2 | DWord | HVCI enabled via User (GUI remains editable!) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | RunAsPPL | 1 | DWord | LSA als PPL |

| `HKLM:\SOFTWARE\Policies\Microsoft\FVE` | EncryptionMethodWithXtsOs | 7 | DWord | XTS-AES-256 OS Drives |

| `HKLM:\SOFTWARE\Policies\Microsoft\FVE` | EncryptionMethodWithXtsFdv | 7 | DWord | XTS-AES-256 Fixed Data Drives |

| `HKLM:\SOFTWARE\Policies\Microsoft\FVE` | EncryptionMethodWithXtsRdv | 7 | DWord | XTS-AES-256 Removable Drives |

| `HKLM:\SOFTWARE\Policies\Microsoft\FVE` | UseTPM | 1 | DWord | TPM erlauben |

| `HKLM:\SOFTWARE\Policies\Microsoft\FVE` | UseTPMPIN | 1 | DWord | TPM + PIN erlauben |

| `HKLM:\SOFTWARE\Policies\Microsoft\FVE` | UseAdvancedStartup | 1 | DWord | Advanced Startup |

| `HKLM:\SOFTWARE\Policies\Microsoft\FVE` | ActiveDirectoryBackup | 0 | DWord | AD Backup optional |




## DNS Module

**Source**: `SecurityBaseline-DNS.ps1`

**Keys**: 3


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters` | EnableDnssec | 1 | DWord | Enable DNSSEC Validation |

| `HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters` | DnssecMode | 1 | DWord | DNSSEC Mode: 1 = Opportunistic (validate if available) |

| `HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters` | EnableDnssecIPv6 | 1 | DWord | DNSSEC for IPv6 |




## Edge Module

**Source**: `SecurityBaseline-Edge.ps1`

**Keys**: 25


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | SmartScreenEnabled | 1 | DWord | Enable SmartScreen (even if deprecated since Edge v139+) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | SmartScreenPuaEnabled | 1 | DWord | Enable SmartScreen PUA (Blocks downloads of potentially unwanted apps) |

| `HKCU:\SOFTWARE\Microsoft\Edge` | SmartScreenPuaEnabled | 1 | DWord | Enable SmartScreen PUA for current user (Windows Security GUI) |

| `HKCU:\SOFTWARE\Policies\Microsoft\Edge` | SmartScreenEnabled | 1 | DWord | Enable SmartScreen for current user - Policy path (Windows Security GUI) |

| `HKCU:\SOFTWARE\Policies\Microsoft\Edge` | SmartScreenPuaEnabled | 1 | DWord | Enable SmartScreen PUA for current user - Policy path (Windows Security GUI) |

| `$userEdgePath` | SmartScreenPuaEnabled | 1 | DWord |  |

| `$userEdgePolicyPath` | SmartScreenEnabled | 1 | DWord |  |

| `$userEdgePolicyPath` | SmartScreenPuaEnabled | 1 | DWord |  |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | PreventSmartScreenPromptOverride | true | String | SmartScreen warnings cannot be bypassed |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | PreventSmartScreenPromptOverrideForFiles | true | String | SmartScreen file warnings cannot be bypassed |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | SitePerProcess | 1 | DWord | Enable Site Isolation |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | TrackingPrevention | 2 | DWord | Tracking Prevention: Strict (2) - Maximum Privacy |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | BlockThirdPartyCookies | 0 | DWord | Allow Third-Party Cookies (normal websites work) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | DnsOverHttpsMode | automatic | String | DNS over HTTPS: Automatic (not enforced) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | BuiltInDnsClientEnabled | 1 | DWord | Enable Built-in DNS Client |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | EnhancedSecurityMode | 1 | DWord | Enhanced Security Mode: Basic (1) - Balance between Security & Compatibility |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | DownloadRestrictions | 1 | DWord | Warn for dangerous downloads (not block) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Edge` | ExtensionInstallSources | https://microsoftedge.microsoft.com/addons/* | MultiString | Extensions only from Microsoft Store |

| `HKLM:\SOFTWARE\Microsoft\Edge` | QuicAllowed | 1 | DWord | QUIC/HTTP3 Default: Enabled (User can change) |

| `HKLM:\SOFTWARE\Microsoft\Edge` | PasswordManagerEnabled | 1 | DWord | Password Manager Default: Enabled (User can disable) |

| `HKLM:\SOFTWARE\Microsoft\Edge` | AutofillAddressEnabled | 1 | DWord | AutoFill Address Default: Enabled (User can disable) |

| `HKLM:\SOFTWARE\Microsoft\Edge` | AutofillCreditCardEnabled | 1 | DWord | AutoFill Credit Card Default: Enabled (User can disable) |

| `HKLM:\SOFTWARE\Microsoft\Edge` | PaymentMethodQueryEnabled | 1 | DWord | Payment Methods Default: Enabled (User can disable) |

| `HKLM:\SOFTWARE\Microsoft\Edge` | WebRtcLocalhostIpHandling | default_public_interface_only | String | WebRTC IP-Leak Prevention Default (User can change) |

| `HKLM:\SOFTWARE\Microsoft\Edge` | InPrivateModeAvailability | 0 | DWord | InPrivate Mode Default: Available (User can change) |




## OneDrive Module

**Source**: `SecurityBaseline-OneDrive.ps1`

**Keys**: 8


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKCU:\SOFTWARE\Policies\Microsoft\OneDrive` | DisableTutorial | 1 | DWord | $(Get-LocalizedString |

| `HKLM:\SOFTWARE\Policies\Microsoft\OneDrive` | DisableTutorial | 1 | DWord | $(Get-LocalizedString |

| `HKCU:\SOFTWARE\Policies\Microsoft\OneDrive` | DisableFeedback | 1 | DWord | $(Get-LocalizedString |

| `HKLM:\SOFTWARE\Policies\Microsoft\OneDrive` | DisableFeedback | 1 | DWord | $(Get-LocalizedString |

| `HKCU:\SOFTWARE\Policies\Microsoft\OneDrive` | PreventNetworkTrafficPreUserSignIn | 1 | DWord | $(Get-LocalizedString |

| `HKLM:\SOFTWARE\Policies\Microsoft\OneDrive` | PreventNetworkTrafficPreUserSignIn | 1 | DWord | $(Get-LocalizedString |

| `HKCU:\SOFTWARE\Policies\Microsoft\OneDrive` | KFMBlockOptIn | 1 | DWord | $(Get-LocalizedString |

| `HKLM:\SOFTWARE\Policies\Microsoft\OneDrive` | KFMBlockOptIn | 1 | DWord | $(Get-LocalizedString |




## Performance Module

**Source**: `SecurityBaseline-Performance.ps1`

**Keys**: 9


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SOFTWARE\Microsoft\Windows Search` | SetupCompletedSuccessfully | 0 | DWord | Search Setup Reset (fuer Re-Index) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | AllowCortana | 0 | DWord | Cortana deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | DisableWebSearch | 1 | DWord | Web-Suche deaktivieren (nur lokal) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | ConnectedSearchUseWeb | 0 | DWord | Connected Search Web deaktivieren |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters` | EnablePrefetcher | 2 | DWord | Prefetch: Nur Boot (SSD-optimiert) |

| `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters` | EnableSuperfetch | 0 | DWord | Superfetch: Aus (SSD braucht das nicht) |

| `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance` | MaintenanceDisabled | 0 | DWord | Maintenance aktiviert (aber optimiert) |

| `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance` | IdleOnly | 1 | DWord | Maintenance nur im Idle |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization` | DODownloadMode | 0 | DWord | Delivery Optimization: HTTP-Only (kein Seeding) |




## Telemetry Module

**Source**: `SecurityBaseline-Telemetry.ps1`

**Keys**: 110


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | AllowTelemetry | 0 | DWord | Telemetrie: Security (0 = Minimum) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | MaxTelemetryAllowed | 0 | DWord | Maximum Telemetrie: Security |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | DoNotShowFeedbackNotifications | 1 | DWord | Feedback-Benachrichtigungen deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | DoNotShowFeedbackNotifications | 1 | DWord | Windows Feedback deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows` | CEIPEnable | 0 | DWord | CEIP deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat` | AITEnable | 0 | DWord | Application Impact Telemetry deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat` | DisableInventory | 1 | DWord | Application Inventory deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo` | DisabledByGroupPolicy | 1 | DWord | Advertising ID deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo` | DisabledByGroupPolicy | 1 | DWord | Advertising ID Policy (applies to ALL users) |

| `HKCU:\Control Panel\International\User Profile` | HttpAcceptLanguageOptOut | 1 | DWord | Websites locally relevant content verhindern |

| `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | Start_TrackProgs | 0 | DWord | App Launch Tracking OFF (Start/Search improvement) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer` | NoInstrumentation | 1 | DWord | Disable Windows Instrumentation (App Tracking) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | AllowSearchToUseLocation | 0 | DWord | Search darf Location nicht nutzen |

| `HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | SubscribedContent-338393Enabled | 0 | DWord | Settings Suggested Content OFF |

| `HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | SubscribedContent-353694Enabled | 0 | DWord | Settings Suggested Content OFF (2) |

| `HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | SubscribedContent-353696Enabled | 0 | DWord | Settings Suggested Content OFF (3) |

| `HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications` | EnableAccountNotifications | 0 | Unknown |  |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\System` | EnableActivityFeed | 0 | DWord | Activity Feed deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\System` | PublishUserActivities | 0 | DWord | User Activities Upload deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\System` | UploadUserActivities | 0 | DWord | User Activities Upload verbieten |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\System` | AllowClipboardHistory | 0 | DWord | Cloud Clipboard History deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\System` | AllowCrossDeviceClipboard | 0 | DWord | Cross-Device Clipboard deaktivieren |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location` | DisableLocation | 1 | DWord | Location Services deaktivieren |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location` | DisableWindowsLocationProvider | 1 | DWord | Windows Location Provider deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization` | RestrictImplicitTextCollection | 1 | DWord | Handwriting/Typing Data Collection einschraenken |

| `HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization` | RestrictImplicitInkCollection | 1 | DWord | Ink Data Collection einschraenken |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection` | AllowTelemetry | 0 | DWord | Telemetrie auf Security-Level |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync` | DisableSettingSync | 2 | DWord | Settings Sync deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync` | DisableSettingSyncUserOverride | 1 | DWord | Settings Sync User Override verbieten |

| `HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice` | AllowFindMyDevice | 0 | DWord | Find My Device deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableSoftLanding | 1 | DWord | Windows Tips deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableWindowsSpotlightFeatures | 1 | DWord | Windows Spotlight deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableTailoredExperiencesWithDiagnosticData | 1 | DWord | Tailored Experiences deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy` | Value | Deny | String | App Diagnostics Zugriff verweigern |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | AllowCortana | 0 | DWord | Cortana deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | DisableWebSearch | 1 | DWord | Web-Suche deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | ConnectedSearchUseWeb | 0 | DWord | Connected Search Web deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | BingSearchEnabled | 0 | DWord | Bing-Integration deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | EnableDynamicContentInWSB | 0 | DWord | Search Highlights deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | AllowCloudSearch | 0 | DWord | Cloud Search deaktivieren |

| `HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer` | DisableSearchBoxSuggestions | 1 | DWord | Search Box Web Suggestions deaktivieren |

| `HKCU:\Software\Microsoft\Windows\CurrentVersion\Search` | BingSearchEnabled | 0 | DWord | Bing Search (User) deaktivieren |

| `HKCU:\Software\Microsoft\Windows\CurrentVersion\Search` | CortanaConsent | 0 | DWord | Cortana Consent (User) deaktivieren |

| `HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam` | Value | Deny | String |  |

| `$app.PSPath` | Value | Deny | String |  |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam` | Value | Deny | String |  |

| `HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone` | Value | Deny | String |  |

| `$app.PSPath` | Value | Deny | String |  |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone` | Value | Deny | String |  |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableWindowsConsumerFeatures | 1 | DWord | Consumer Features deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableSoftLanding | 1 | DWord | Vorgeschlagene Inhalte deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | DisableThirdPartySuggestions | 1 | DWord | Drittanbieter-Vorschlaege deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization` | RestrictImplicitInkCollection | 1 | DWord | Freihand-Datensammlung einschraenken (Policy) |

| `HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization` | RestrictImplicitTextCollection | 1 | DWord | Text-Datensammlung einschraenken (Policy) |

| `HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization` | AllowInputPersonalization | 0 | DWord | Input Personalization komplett deaktivieren |

| `HKCU:\Software\Microsoft\InputPersonalization` | RestrictImplicitInkCollection | 1 | DWord | Freihand-Datensammlung einschraenken (User) |

| `HKCU:\Software\Microsoft\InputPersonalization` | RestrictImplicitTextCollection | 1 | DWord | Text-Datensammlung einschraenken (User) |

| `HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore` | HarvestContacts | 0 | DWord | Kontakte-Harvest deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization` | AcceptedPrivacyPolicy | 0 | DWord | Personalization Privacy Policy ablehnen |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location` | Value | Deny | String | Standort: App-Zugriff VERWEIGERT |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors` | DisableLocation | 1 | DWord | Standortdienste deaktivieren |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\locationHKCU` | Value | Deny | String |  |

| `$app.PSPath` | Value | Deny | String |  |

| `HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy` | HasAccepted | 0 | DWord | Online Speech Recognition OFF (Privacy) |

| `HKLM:\$consentStoreBase\userNotificationListener` | Value | Deny | String | Apps: Notifications OFF |

| `HKLM:\$consentStoreBase\userAccountInformation` | Value | Deny | String | Apps: Account Info OFF |

| `HKLM:\$consentStoreBase\contacts` | Value | Deny | String | Apps: Contacts OFF |

| `HKLM:\$consentStoreBase\appointments` | Value | Deny | String | Apps: Calendar OFF |

| `HKLM:\$consentStoreBase\email` | Value | Deny | String | Apps: Email OFF |

| `HKLM:\$consentStoreBase\phoneCall` | Value | Deny | String | Apps: Phone Calls OFF |

| `HKLM:\$consentStoreBase\phoneCallHistory` | Value | Deny | String | Apps: Call History OFF |

| `HKLM:\$consentStoreBase\chat` | Value | Deny | String | Apps: Messaging/SMS OFF |

| `HKLM:\$consentStoreBase\userDataTasks` | Value | Deny | String | Apps: Tasks OFF |

| `HKLM:\$consentStoreBase\radios` | Value | Deny | String | Apps: Radios Control OFF |

| `HKLM:\$consentStoreBase\bluetoothSync` | Value | Deny | String | Apps: Other Devices OFF |

| `HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences` | VoiceActivationEnableAboveLockscreen | 0 | DWord | Voice Activation above Lockscreen OFF |

| `HKLM:\$consentStoreBase\documentsLibrary` | Value | Deny | String | Apps: Documents OFF |

| `HKLM:\$consentStoreBase\picturesLibrary` | Value | Deny | String | Apps: Pictures OFF |

| `HKLM:\$consentStoreBase\videosLibrary` | Value | Deny | String | Apps: Videos OFF |

| `HKLM:\$consentStoreBase\broadFileSystemAccess` | Value | Deny | String | Apps: Broad File System OFF (Maximum Security!) |

| `HKLM:\$consentStoreBase\downloadsFolder` | Value | Deny | String | Apps: Downloads Folder OFF |

| `HKLM:\$consentStoreBase\musicLibrary` | Value | Deny | String | Apps: Music Library OFF |

| `HKLM:\$consentStoreBase\automaticFileDownloads` | Value | Deny | String | Apps: Automatic File Downloads OFF |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy` | LetAppsGetDiagnosticInfo | 2 | DWord | Apps: Diagnostics OFF (Value 2 means User Denied) |

| `HKLM:\$consentStoreBase\activity` | Value | Deny | String | Apps: Activity History OFF |

| `HKLM:\$consentStoreBase\bluetooth` | Value | Deny | String | Apps: Bluetooth OFF |

| `HKLM:\$consentStoreBase\cellularData` | Value | Deny | String | Apps: Cellular Data OFF |

| `HKLM:\$consentStoreBase\gazeInput` | Value | Deny | String | Apps: Gaze Input/Eye Tracking OFF |

| `HKLM:\$consentStoreBase\graphicsCaptureProgrammatic` | Value | Deny | String | Apps: Graphics Capture Programmatic OFF |

| `HKLM:\$consentStoreBase\graphicsCaptureWithoutBorder` | Value | Deny | String | Apps: Graphics Capture Without Border OFF |

| `HKLM:\$consentStoreBase\humanInterfaceDevice` | Value | Deny | String | Apps: Human Interface Device OFF |

| `HKLM:\$consentStoreBase\passkeys` | Value | Deny | String | Apps: Passkeys OFF |

| `HKLM:\$consentStoreBase\passkeysEnumeration` | Value | Deny | String | Apps: Passkeys Enumeration OFF |

| `HKLM:\$consentStoreBase\sensors.custom` | Value | Deny | String | Apps: Custom Sensors OFF |

| `HKLM:\$consentStoreBase\serialCommunication` | Value | Deny | String | Apps: Serial Communication OFF |

| `HKLM:\$consentStoreBase\systemAIModels` | Value | Deny | String | Apps: System AI Models OFF (Windows 11 25H2) |

| `HKLM:\$consentStoreBase\usb` | Value | Deny | String | Apps: USB Devices OFF |

| `HKLM:\$consentStoreBase\wifiData` | Value | Deny | String | Apps: WiFi Data OFF |

| `HKLM:\$consentStoreBase\wiFiDirect` | Value | Deny | String | Apps: WiFi Direct OFF |

| `$hkcuPath` | Value | Deny | String |  |

| `$appKey.PSPath` | Value | Deny | String |  |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacyHKCU` | LetAppsGetDiagnosticInfo | 2 | DWord | CURRENT USER: App Diagnostics OFF |

| `HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR` | AppCaptureEnabled | 0 | DWord | Game Capture deaktivieren |

| `HKCU:\System\GameConfigStore` | GameDVR_Enabled | 0 | DWord | GameDVR deaktivieren |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR` | AllowGameDVR | 0 | DWord | GameDVR Policy: Verbieten |

| `HKCU:\Software\Microsoft\GameBar` | AutoGameModeEnabled | 0 | DWord | Auto Game Mode deaktivieren |

| `HKCU:\Software\Microsoft\GameBar` | AllowAutoGameMode | 0 | DWord | Auto Game Mode verbieten |

| `HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications` | NoToastApplicationNotificationOnLockScreen | 1 | DWord | No toast notifications on lock screen (privacy + security) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization` | NoLockScreenCamera | 1 | DWord | Prevent lock screen camera (privacy) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization` | NoLockScreenSlideshow | 1 | DWord | Prevent lock screen slideshow (privacy) |




## UAC Module

**Source**: `SecurityBaseline-UAC.ps1`

**Keys**: 10


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | EnableLUA | 1 | DWord | Enable UAC |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | ConsentPromptBehaviorAdmin | 2 | DWord | UAC: Always notify (Slider at top) - Prompt for credentials on secure desktop |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | PromptOnSecureDesktop | 1 | DWord | UAC: Enable Secure Desktop (Anti-Malware Protection) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | ConsentPromptBehaviorUser | 1 | DWord | UAC: Standard User Prompt for credentials |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | ValidateAdminCodeSignatures | 0 | DWord | UAC: No signature check (too restrictive for normal environments) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | EnableSecureUIAPaths | 1 | DWord | UAC: Only allow secure UIAccess paths |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | LocalAccountTokenFilterPolicy | 0 | DWord | UAC: Prevent remote UAC bypass for local accounts (anti-PtH) |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | InactivityTimeoutSecs | 900 | DWord | Auto-lock after 15 minutes (900 sec) inactivity |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | ConsentPromptBehaviorAdminInEPPMode | 2 | DWord | UAC EPP: Prompt for credentials on secure desktop |

| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | AdminApprovalModeType | 1 | DWord | UAC: Admin Approval Mode with Enhanced Privilege Protection |




## WindowsUpdate Module

**Source**: `SecurityBaseline-WindowsUpdate.ps1`

**Keys**: 9


| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings` | AllowMUUpdateService | 1 | DWord | Updates for other MS products: ON |

| `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings` | IsContinuousInnovationOptedIn | 1 | DWord | Get latest updates as soon as available: ON |

| `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings` | AllowAutoWindowsUpdateDownloadOverMeteredNetwork | 1 | DWord | Download updates over metered connections: ON (Security First!) |

| `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings` | RestartNotificationsAllowed2 | 1 | DWord | Restart notifications: ON |

| `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings` | IsExpedited | 1 | DWord | Get latest updates immediately: ON |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization` | ManagePreviewBuilds | 1 | DWord | Preview Builds Policy: Managed |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization` | ManagePreviewBuildsPolicyValue | 0 | DWord | Preview Builds Policy: NO Preview Builds (guaranteed!) |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization` | DODownloadMode | 0 | DWord | Delivery Optimization Policy: HTTP-Only (guaranteed!) |

| `HKLM:\SOFTWARE\Microsoft\Windows\DeliveryOptimization\Config` | DODownloadMode | 0 | DWord | Delivery Optimization Config: HTTP-Only (Fallback) |




## WirelessDisplay Module

**Source**: `SecurityBaseline-WirelessDisplay.ps1`

**Keys**: 9

| Path | Name | Value | Type | Description |

|------|------|-------|------|-------------|

| `HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Reg)` | Start | 4 | Unknown |  |

| `HKLM:\SOFTWARE\Microsoft\PlayToReceiver` | Enabled | 0 | DWord | Disable PlayToReceiver |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect` | AllowProjectionToPC | 0 | DWord | Prohibit projection to this PC |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect` | RequirePinForPairing | 1 | DWord | Enforce PIN for pairing |

| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WirelessDisplay` | Enabled | 0 | DWord | Disable Wireless Display Feature |

| `HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer` | PreventWirelessReceiver | 1 | DWord | Prevent Wireless Media Streaming |

| `HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache` | OsuRegistrationStatus | 0 | DWord | Disable Wi-Fi Direct OSU |



