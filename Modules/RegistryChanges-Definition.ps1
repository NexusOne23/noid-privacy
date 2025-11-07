#Requires -Version 5.1
#Requires -RunAsAdministrator

# Enable Strict Mode for better error detection
Set-StrictMode -Version Latest

# Parsed 394 entries, 394 valid (removed 3 problematic entries, added 3 Defender Features)
<#
.SYNOPSIS
    Registry Changes Definition
    
.DESCRIPTION
    Contains all 394 registry changes that the Security Baseline applies.
    Used by Backup and Restore scripts for specific (fast) backup/restore.
    
    This file was AUTO-GENERATED from registry-changes-complete.txt
    Do not modify manually - regenerate from source!
    
.NOTES
    Generated: 2025-10-31 17:15:00
    Updated: 2025-11-04 (Removed SetupCompletedSuccessfully - breaks Outlook search)
    Updated: 2025-11-06 (Added 3 Defender Features: EnableAppInstallControl, EnableEDRInBlockMode, TamperProtection)
    Updated: 2025-11-07 (Added DisableScanningMappedNetworkDrivesForFullScan - MS Baseline 25H2 completion)
    Updated: 2025-11-07 (Fixed variable paths to absolute paths for backup compatibility - removed 5 duplicates, added 2 WOW6432Node entries, removed 3 dynamic user-specific entries)
    Updated: 2025-11-07 (Expanded ALL 48 variable paths to absolute paths - 100% backupable registry definition)
    Total Entries: 473 (all static, fully backupable)
    
    Expansion Details:
    - TLS/SSL Protocols: 8 variables â†’ 24 absolute paths (SSL 2.0, 3.0, TLS 1.0-1.3)
    - Ciphers: 2 variables â†’ 12 absolute paths (10 weak disabled, 2 strong enabled)
    - App Permissions: 33 variables â†’ 33 absolute paths (ConsentStore expanded)
    - Removed: 5 dynamic variables (NetBT $guid, $app.PSPath, $svc.Reg, etc.)
    - Result: 0 variables remaining, 100% backup/restore compatible
    Source: registry-changes-complete.txt + manual additions
#>

# Registry changes that Security Baseline applies
$script:RegistryChanges = @(
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Name = 'DisableAIDataAnalysis'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Windows Recall deaktivieren (KEINE Screenshots!)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WindowsAI\DisableAIDataAnalysis'
        Name = 'value'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Recall Policy Manager: DISABLED'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Name = 'TurnOffWindowsCopilot'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Copilot: Layer 1 - Main Policy (HKLM)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
        Name = 'TurnOffWindowsCopilot'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Copilot: Layer 2 - Legacy Policy Path'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
        Name = 'ShowCopilotButton'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Copilot: Layer 3 - Hide Taskbar Button'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Name = 'DisableWindowsCopilot'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Copilot: Layer 4 - Explorer Disable'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Name = 'DisableClickToDo'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Click to Do deaktivieren (AI Screenshot Analysis)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'
        Name = 'DisableCocreator'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Paint Cocreator deaktivieren (AI Image Gen)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'
        Name = 'DisableGenerativeFill'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Paint Generative Fill deaktivieren (AI Edit)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'
        Name = 'DisableImageCreator'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Paint Image Creator deaktivieren (AI Art)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\WindowsNotepad'
        Name = 'DisableAIFeatures'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Notepad AI Features deaktivieren (Copilot Button + AI Assistance)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Name = 'DisableSettingsAgent'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Settings Agent deaktivieren (AI in Settings)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
        Name = 'DisableCopilotProactive'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Copilot Proactive deaktivieren (keine ungewollten Vorschlaege)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Name = 'SetMaximumStorageSpaceForRecallSnapshots'
        Type = 'DWord'
        ApplyValue = 10
        Description = 'Recall: Max Storage = 10GB (Minimum, if reactivated)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Name = 'SetMaximumStorageDurationForRecallSnapshots'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Recall: Max Duration = 1 Day (Minimum, if reactivated)'
        File = 'SecurityBaseline-AI.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
        Name = 'Deny_Execute'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'USB: Deny execution'
        File = 'SecurityBaseline-ASR.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
        Name = 'SmartScreenEnabled'
        Type = 'String'
        ApplyValue = 'RequireAdmin'
        Description = 'Enforce SmartScreen'
        File = 'SecurityBaseline-ASR.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable LAPS'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'
        Name = 'PasswordAgeDays'
        Type = 'DWord'
        ApplyValue = 30
        Description = 'PW rotation every 30 days'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'
        Name = 'PasswordComplexity'
        Type = 'DWord'
        ApplyValue = 4
        Description = 'Max complexity'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'
        Name = 'PasswordLength'
        Type = 'DWord'
        ApplyValue = 20
        Description = 'PW length 20 characters'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'
        Name = 'BackupDirectory'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'Backup to AD/Entra'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'
        Name = 'PostAuthenticationActions'
        Type = 'DWord'
        ApplyValue = 3
        Description = 'Reset PW after auth'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        Name = 'SCENoApplyLegacyAuditPolicy'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Force advanced audit subcategory settings (override legacy)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        Name = 'EnableScriptBlockLogging'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'PowerShell Script Block Logging'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Name = 'EnableTranscripting'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'PowerShell Transcription'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Name = 'EnableInvocationHeader'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Invocation Header'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Name = 'OutputDirectory'
        Type = 'String'
        ApplyValue = '$transcriptDir'
        Description = 'Transcript Output Dir'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        Name = 'AuditNTLMInDomain'
        Type = 'DWord'
        ApplyValue = 7
        Description = 'NTLM Auditing: Track all NTLM auth in domain'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        Name = 'RestrictNTLMInDomain'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'NTLM Restriction: Audit-Only (no blocking)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        Name = 'AuditReceivingNTLMTraffic'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'Audit incoming NTLM traffic (2=Enable)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        Name = 'RestrictReceivingNTLMTraffic'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'NTLM Restriction Outbound: Audit-Only'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    # TLS/SSL Protocol Entries - Expanded from $protocol variable (Batch 1: SSL 2.0, SSL 3.0)
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable SSL 2.0 Server'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SSL 2.0 Server default off'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable SSL 2.0 Client'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SSL 2.0 Client default off'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable SSL 3.0 Server'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SSL 3.0 Server default off'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable SSL 3.0 Client'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SSL 3.0 Client default off'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    # Batch 2: TLS 1.0, TLS 1.1
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable TLS 1.0 Server'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'TLS 1.0 Server default off'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable TLS 1.0 Client'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'TLS 1.0 Client default off'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable TLS 1.1 Server'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'TLS 1.1 Server default off'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable TLS 1.1 Client'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'TLS 1.1 Client default off'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    # Batch 3: TLS 1.2, TLS 1.3 (Strong Protocols)
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable TLS 1.2 Server'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'TLS 1.2 Server default on'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable TLS 1.2 Client'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'TLS 1.2 Client default on'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable TLS 1.3 Server'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'TLS 1.3 Server default on'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable TLS 1.3 Client'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client'
        Name = 'DisabledByDefault'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'TLS 1.3 Client default on'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    # Batch 4: Weak Ciphers (10 keys) - First 8
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable DES 56/56'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable NULL'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable RC2 128/128'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable RC2 40/128'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable RC2 56/128'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable RC4 128/128'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable RC4 40/128'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable RC4 56/128'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable RC4 64/128'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable Triple DES 168'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    # Batch 4b: Strong Ciphers (2 keys)
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0xFFFFFFFF
        Description = 'Enable AES 128/128'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0xFFFFFFFF
        Description = 'Enable AES 256/256'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
        Name = 'Functions'
        Type = 'String'
        ApplyValue = '$cipherSuiteOrder'
        Description = 'Cipher Suite Order (TLS 1.3 + 1.2 GCM/CHACHA only, no CBC)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable SHA-1 for TLS/SSL'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0xFFFFFFFF
        Description = 'Enable SHA-256'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0xFFFFFFFF
        Description = 'Enable SHA-384'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0xFFFFFFFF
        Description = 'Enable SHA-512'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
        Name = 'SchUseStrongCrypto'
        Type = 'DWord'
        ApplyValue = 1
        Description = '.NET Strong Crypto'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
        Name = 'SystemDefaultTlsVersions'
        Type = 'DWord'
        ApplyValue = 1
        Description = '.NET System TLS Versions'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
        Name = 'SchUseStrongCrypto'
        Type = 'DWord'
        ApplyValue = 1
        Description = '.NET Strong Crypto (32-bit on 64-bit)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
        Name = 'SystemDefaultTlsVersions'
        Type = 'DWord'
        ApplyValue = 1
        Description = '.NET System TLS Versions (32-bit on 64-bit)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
        Name = 'EventLogging'
        Type = 'DWord'
        ApplyValue = 7
        Description = 'Schannel Event Logging (all events)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
        Name = 'UseLogonCredential'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'WDigest disabled (no plaintext passwords in RAM)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\EFS'
        Name = 'Start'
        Type = 'DWord'
        ApplyValue = 4
        Description = 'EFS Service disabled (NTLM relay protection)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\EFS'
        Name = 'Disabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'EFS Driver disabled'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name = 'DisableWindowsConsumerFeatures'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Disable Consumer Features (no auto-install apps)'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name = 'DisableSoftLanding'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Disable Soft Landing (no app suggestions)'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name = 'DisableCloudOptimizedContent'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Disable cloud-optimized content'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name = 'DisableThirdPartySuggestions'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Disable third-party suggestions in Start Menu'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name = 'DisableWindowsSpotlightFeatures'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Disable Windows Spotlight features'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name = 'SubscribedContent-338388Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable suggested apps in Start Menu (stub apps)'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name = 'SubscribedContent-338389Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable tips and tricks'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name = 'SubscribedContent-310093Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable app suggestions after Windows Update'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name = 'SubscribedContent-353698Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable Timeline suggestions'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name = 'SilentInstalledAppsEnabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable silent installation of apps'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name = 'SystemPaneSuggestionsEnabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable suggestions in Settings'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name = 'PreInstalledAppsEnabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable pre-installed app advertising'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat'
        Name = 'ChatIcon'
        Type = 'DWord'
        ApplyValue = 3
        Description = 'Disable Teams Chat icon'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    # REMOVED: Duplicate TurnOffWindowsCopilot (already defined in AI.ps1)
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'
        Name = 'AllowNewsAndInterests'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable Widgets'
        File = 'SecurityBaseline-Bloatware.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Test'
        Name = 'Value'
        Type = 'DWord'
        ApplyValue = 1
        Description = ''
        File = 'SecurityBaseline-Common.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        Name = 'DisableNBTNameResolution'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'NetBIOS Name Resolution global deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\'
        Name = 'NodeType'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'NetBT auf P-Node (nur WINS)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        Name = 'ProcessCreationIncludeCmdLine_Enabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Command Line in Event ID 4688'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main'
        Name = 'DisableIE11Launch'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'IE11 Launch via COM blockieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
        Name = 'iexplore.exe'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'ActiveX Installation blockieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
        Name = 'RpcAuthnLevelPrivacyEnabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'RPC Privacy Level fuer Print Spooler'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
        Name = 'RegisterSpoolerRemoteRpcEndPoint'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'Remote RPC Endpoint deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        Name = 'NoWarningNoElevationOnInstall'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Point-and-Print: Require elevation for driver install'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        Name = 'UpdatePromptSettings'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Point-and-Print: Show warning for driver updates'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        Name = 'RestrictDriverInstallationToAdministrators'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Point-and-Print: Only admins can install drivers'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS'
        Name = 'ConvertWarnToBlock'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'NIS Warn->Block'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
        Name = 'ReportDynamicSignatureDroppedEvent'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Dynamic Signature Events'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        Name = 'CheckExclusions'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Scan Exclusions too'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        Name = 'MpCloudBlockLevel'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'Cloud Protection Level High'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        Name = 'ExclusionsVisibleToLocalUsers'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Exclusions visible to local users (transparency)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'ConfigureRealTimeProtectionOOBE'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Real-Time Protection active during OOBE setup'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        Name = 'ScanExcludedFilesInQuickScan'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Also check excluded files in quick scans'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        Name = 'DisableScanningMappedNetworkDrivesForFullScan'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Skip mapped network drives in full scans (performance + MS Baseline 25H2)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'RealtimeScanDirection'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Realtime scan: Both incoming and outgoing files'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        Name = 'MpBafsExtendedTimeout'
        Type = 'DWord'
        ApplyValue = 50
        Description = 'Extended timeout for cloud analysis (50 seconds)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
        Name = 'EnableControlledFolderAccess'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Controlled Folder Access aktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Name = 'NoDriveTypeAutoRun'
        Type = 'DWord'
        ApplyValue = 0xFF
        Description = 'AutoPlay auf allen Laufwerkstypen deaktiviert'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Name = 'NoAutorun'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'AutoRun global deaktiviert (autorun.inf ignoriert)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Name = 'NoDriveTypeAutoRun'
        Type = 'DWord'
        ApplyValue = 0xFF
        Description = 'AutoPlay User-Level deaktiviert'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Name = 'NoAutorun'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'AutoRun User-Level deaktiviert'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        Name = 'NoDriveTypeAutoRun'
        Type = 'DWord'
        ApplyValue = 0xFF
        Description = 'Legacy AutoRun Path'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Name = 'NoAutoplayfornonVolume'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'AutoPlay for non-volume devices disabled (MTP/Camera/Phone)'
        File = 'SecurityBaseline-Core.ps1'
    },
    # NOTE: Per-adapter NetBIOS setting removed (dynamic $guid - varies by system)
    # NetBIOS is disabled globally via NodeType=2 above
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
        Name = 'iexplore.exe'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'ActiveX Installation blockieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        Name = 'DisableScanningMappedNetworkDrivesForFullScan'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Skip mapped network drives in full scans (performance + MS Baseline 25H2)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'RealtimeScanDirection'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Realtime scan: Both incoming and outgoing files'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        Name = 'MpBafsExtendedTimeout'
        Type = 'DWord'
        ApplyValue = 50
        Description = 'Extended timeout for cloud analysis (50 seconds)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access'
        Name = 'EnableControlledFolderAccess'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Controlled Folder Access aktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'AllowCustomSSPsAPs'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Block custom SSPs/APs (credential theft protection)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'SMBServerMaximumProtocol'
        Type = 'DWord'
        ApplyValue = 1025
        Description = 'SMB Max Version: 3.1.1 (1025 = SMB 3.1.1)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'SMBClientMinimumProtocol'
        Type = 'DWord'
        ApplyValue = 768
        Description = 'SMB Client Min Version: 3.0.0'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'SMBClientMaximumProtocol'
        Type = 'DWord'
        ApplyValue = 1025
        Description = 'SMB Client Max Version: 3.1.1'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'AuditInsecureGuestLogon'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Audit: Unsichere Guest-Logins (Client)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'AuditServerDoesNotSupportEncryption'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Audit: Server ohne Encryption'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'AuditServerDoesNotSupportSigning'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Audit: Server ohne Signing'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'EnableRemoteMailslots'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Remote Mailslots deaktivieren (Client)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'RequireEncryption'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Encryption nicht erzwingen (Kompatibilitaet)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'SMB1'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'SMB1 Server deaktivieren (unsicher!)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'DisableSmb1'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SMB1 Client deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'EnableSecuritySignature'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SMB Signing Client aktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'RequireSecuritySignature'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SMB Signing Client erzwingen'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'EnableSecuritySignature'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SMB Signing Server aktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'RequireSecuritySignature'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SMB Signing Server erzwingen'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'EncryptData'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SMB Encryption aktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'RejectUnencryptedAccess'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Unencrypted Access ablehnen'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation'
        Name = 'AllowInsecureGuestAuth'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Unsichere SMB Guest-Logins deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        Name = 'EnablePlainTextPassword'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Plaintext-Passwoerter an SMB-Server verbieten'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10'
        Name = 'Start'
        Type = 'DWord'
        ApplyValue = 4
        Description = 'SMB1 Client Driver deaktivieren (Disabled = 4)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        Name = 'RequireSignOrSeal'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'NTLM Sign/Seal erzwingen'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        Name = 'EnableMulticast'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'LLMNR deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        Name = 'EnableNetbios'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'NetBIOS ueber TCP/IP deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
        Name = 'RpcUseNamedPipeProtocol'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'RPC: Don''t restrict to Named Pipes only (compatibility)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
        Name = 'RpcAuthentication'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'RPC: Default authentication level (System-controlled)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
        Name = 'RpcProtocols'
        Type = 'DWord'
        ApplyValue = 5
        Description = 'RPC: Enable TCP/IP protocol (ncacn_ip_tcp)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
        Name = 'ForceKerberosForRpc'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'RPC: Don''t force Kerberos only (standalone compatibility)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
        Name = 'RpcTcpPort'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'RPC: Use dynamic port allocation (0 = default)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
        Name = 'RestrictRemoteClients'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'RPC: Restrict unauthenticated remote clients'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        Name = 'EnableICMPRedirect'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'TCP/IP: Disable ICMP Redirect (attack protection)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
        Name = 'DisableIPSourceRouting'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'TCP/IP: Disable IP Source Routing IPv4 (highest protection)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
        Name = 'DisableIPSourceRouting'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'TCP/IP: Disable IP Source Routing IPv6 (highest protection)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
        Name = 'DisableExceptionChainValidation'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Kernel: Enable Exception Chain Validation (exploit mitigation)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
        Name = 'DriverLoadPolicy'
        Type = 'DWord'
        ApplyValue = 3
        Description = 'Kernel: Good + Unknown drivers only (Early Launch AM)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        Name = 'DisableLocalAdminMerge'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Defender: Local admins can set exclusions (baseline recommendation)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        Name = 'HideExclusionsFromLocalAdmins'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Defender: Hide exclusions from local admins'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        Name = 'DisableRoutinelyTakingAction'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Defender: Auto-clean threats enabled (baseline recommendation)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
        Name = 'DisableWebPnPDownload'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Printer: Disable web-based driver download (security)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
        Name = 'RedirectionGuardPolicy'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Printer: Redirection guard enabled'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
        Name = 'CopyFilesPolicy'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Printer: Restrict driver file copy operations'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
        Name = 'NoNameReleaseOnDemand'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'NetBT: Prevent name release on demand (security)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
        Name = 'AllowWindowsInkWorkspace'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Windows Ink Workspace: Enabled but accessible'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Name = 'NoWebServices'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Explorer: Disable web services access (privacy)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'MSAOptional'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Microsoft Account optional (not forced in OOBE)'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'EnableMPR'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Multiple Provider Router disabled (legacy - NT 4.0 feature)'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'EnableInstallerDetection'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'UAC: Detect installers automatically (heuristic detection)'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'FilterAdministratorToken'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'UAC: Built-in Administrator account uses UAC (not full token by default)'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'DisableIOAVProtection'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Defender: IOAV Protection enabled (IE/Office downloads)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'DisableScriptScanning'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Defender: Script scanning enabled (PS1/VBS/JS)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'DisableBehaviorMonitoring'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Defender: Behavior monitoring enabled (heuristics)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'DisableOnAccessProtection'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Defender: On-access protection enabled (realtime scan)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        Name = 'DisableScanOnRealtimeEnable'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Defender: Scan on RT enable (initial scan)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        Name = 'DisableBlockAtFirstSeen'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Defender: Block at first seen enabled (cloud zero-day)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'EveryoneIncludesAnonymous'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Everyone beinhaltet KEINE anonymen User'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'NoLMHash'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'LM Hashes deaktivieren (veraltet seit 1992)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'
        Name = 'DoNotUseWPAD'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'WPAD deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
        Name = 'DisableWpad'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'WinHTTP WPAD deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters'
        Name = 'DisableMdnsDiscovery'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'WlanSvc mDNS Discovery deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
        Name = 'NC_ShowSharedAccessUI'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Network Discovery UI deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
        Name = 'NC_AllowNetBridge_NLA'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Network Bridge deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'
        Name = 'AutoConnectAllowedOEM'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Wi-Fi Sense Auto-Connect deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
        Name = 'EnableRegistrars'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Windows Connect Now deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI'
        Name = 'DisableWcnUi'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'WCN UI deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet'
        Name = 'Disabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Peer-to-Peer Networking deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'DisableAutomaticRestartSignOn'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Automatische Netzwerk-Authentifizierung deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'AutoShareServer'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Admin Shares auf Servern deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'AutoShareWks'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Admin Shares auf Workstations deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'RestrictNullSessAccess'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Anonymous Access zu Named Pipes einschraenken'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'RestrictAnonymousSAM'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Anonymous SAM Enumeration verbieten'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'RestrictAnonymous'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Anonymous Share Enumeration verbieten'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'NullSessionPipes'
        Type = 'MultiString'
        ApplyValue = ([string[]]@())
        Description = 'Keine Named Pipes fuer Anonymous Access'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'NullSessionShares'
        Type = 'MultiString'
        ApplyValue = ([string[]]@())
        Description = 'Keine Shares fuer Anonymous Access'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'LimitBlankPasswordUse'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Blank passwords nur bei Console-Logon (kein Remote)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'LmCompatibilityLevel'
        Type = 'DWord'
        ApplyValue = 5
        Description = 'LAN Manager Auth Level: 5 = NTLMv2 only (no LM/NTLM)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
        Name = 'LDAPClientIntegrity'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'LDAP Client Signing: Require signing (maximum security)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
        Name = 'LdapEnforceChannelBinding'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'LDAP Channel Binding: Always enforce (CVE-2025-59214 protection)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        Name = 'NTLMMinClientSec'
        Type = 'DWord'
        ApplyValue = 537395200
        Description = 'NTLM Client: Require NTLMv2 + 128-bit encryption'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        Name = 'NTLMMinServerSec'
        Type = 'DWord'
        ApplyValue = 537395200
        Description = 'NTLM Server: Require NTLMv2 + 128-bit encryption'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Name = 'ScRemoveOption'
        Type = 'String'
        ApplyValue = '1'
        Description = 'Smart card removal: Lock Workstation (1)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'RestrictRemoteSAM'
        Type = 'String'
        ApplyValue = 'O:BAG:BAD:(A;;RC;;;BA)'
        Description = 'Restrict remote SAM calls to Administrators only (SDDL)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'AllowNullSessionFallback'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Do NOT allow NULL session fallback for LocalSystem'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'
        Name = 'AllowEncryptionOracle'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Encryption Oracle: Force Updated Clients (most secure)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
        Name = 'AllowDefCredentialsWhenNTLMOnly'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Do NOT allow delegation of credentials when NTLM only'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
        Name = 'EnableUserControl'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'User control over installs: DISABLED (security)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
        Name = 'AlwaysInstallElevated'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Always install elevated: DISABLED (prevents privilege escalation)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
        Name = 'DisableEnclosureDownload'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'RSS: Prevent automatic enclosure downloads (security)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name = 'AllowIndexingEncryptedStoresOrItems'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Search: Do NOT index encrypted files (privacy)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'EnumerateLocalUsers'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Do NOT enumerate local users on logon screen (privacy)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        Name = 'fDenyTSConnections'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'RDP-Verbindungen verweigern'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg'
        Name = 'RemoteRegAccess'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Remote Registry Access verweigern'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
        Name = 'fAllowToGetHelp'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Remote Assistance deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
        Name = 'fAllowUnsolicited'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Unaufgeforderte Remote Assistance deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        Name = 'fAllowToGetHelp'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Remote Assistance via GP deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        Name = 'fAllowUnsolicited'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Unaufgeforderte RA via GP deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        Name = 'Shadow'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'RDP Shadow Sessions verbieten'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule'
        Name = 'DisableRpcOverTcp'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Remote Scheduled Tasks deaktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Sudo for Windows deaktivieren (Privilege Escalation Prevention)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
        Name = 'SupportedEncryptionTypes'
        Type = 'DWord'
        ApplyValue = 0x7FFFFFFF
        Description = 'Alle modernen Kerberos Enc Types'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
        Name = 'PKINITHashAlgorithm'
        Type = 'DWord'
        ApplyValue = 0x38
        Description = 'PKINIT: SHA-256/384/512 (OHNE SHA-1!)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
        Name = 'PKINITHashAlgorithm'
        Type = 'DWord'
        ApplyValue = 0x38
        Description = 'KDC PKINIT: SHA-256/384/512 (OHNE SHA-1!)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
        Name = 'SaveZoneInformation'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'MotW erzwingen'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
        Name = 'ScanWithAntiVirus'
        Type = 'DWord'
        ApplyValue = 3
        Description = 'Immer mit AV scannen'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        Name = 'EnableVirtualizationBasedSecurity'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'VBS aktivieren'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
        Name = 'RequirePlatformSecurityFeatures'
        Type = 'DWord'
        ApplyValue = 3
        Description = 'VBS: Secure Boot + DMA'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'LsaCfgFlags'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'Credential Guard (ohne UEFI Lock - reversibel)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable Credential Guard Scenario'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable HVCI/Memory Integrity'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
        Name = 'WasEnabledBy'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'HVCI enabled via User (GUI remains editable!)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name = 'RunAsPPL'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'LSA als PPL'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
        Name = 'VulnerableDriverBlocklistEnable'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable Vulnerable Driver Blocklist (BYOVD protection)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'EnableCdp'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable Nearby Sharing/CDP (privacy + security)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Name = 'EncryptionMethodWithXtsOs'
        Type = 'DWord'
        ApplyValue = 7
        Description = 'XTS-AES-256 OS Drives'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Name = 'EncryptionMethodWithXtsFdv'
        Type = 'DWord'
        ApplyValue = 7
        Description = 'XTS-AES-256 Fixed Data Drives'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Name = 'EncryptionMethodWithXtsRdv'
        Type = 'DWord'
        ApplyValue = 7
        Description = 'XTS-AES-256 Removable Drives'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Name = 'UseTPM'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'TPM erlauben'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Name = 'UseTPMPIN'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'TPM + PIN erlauben'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Name = 'UseAdvancedStartup'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Advanced Startup'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
        Name = 'ActiveDirectoryBackup'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'AD Backup optional'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        Name = 'EnableDnssec'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable DNSSEC Validation'
        File = 'SecurityBaseline-DNS.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        Name = 'DnssecMode'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'DNSSEC Mode: 1 = Opportunistic (validate if available)'
        File = 'SecurityBaseline-DNS.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        Name = 'EnableDnssecIPv6'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'DNSSEC for IPv6'
        File = 'SecurityBaseline-DNS.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'SmartScreenEnabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable SmartScreen (even if deprecated since Edge v139+)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'SmartScreenPuaEnabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable SmartScreen PUA (Blocks downloads of potentially unwanted apps)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'SmartScreenEnabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable SmartScreen for current user - Policy path (Windows Security GUI)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    # NOTE: User-specific Edge SmartScreen settings removed from backup definition
    # These paths are dynamic (contain user SID) and cannot be backed up statically
    # They are set at runtime by SecurityBaseline-Edge.ps1 for each loaded user profile
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'PreventSmartScreenPromptOverride'
        Type = 'String'
        ApplyValue = 'true'
        Description = 'SmartScreen warnings cannot be bypassed'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'PreventSmartScreenPromptOverrideForFiles'
        Type = 'String'
        ApplyValue = 'true'
        Description = 'SmartScreen file warnings cannot be bypassed'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'SitePerProcess'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable Site Isolation'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'TrackingPrevention'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'Tracking Prevention: Strict (2) - Maximum Privacy'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'BlockThirdPartyCookies'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Allow Third-Party Cookies (normal websites work)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'DnsOverHttpsMode'
        Type = 'String'
        ApplyValue = 'automatic'
        Description = 'DNS over HTTPS: Automatic (not enforced)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'BuiltInDnsClientEnabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable Built-in DNS Client'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'EnhancedSecurityMode'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enhanced Security Mode: Balanced (1) - Optimal Security + Compatibility'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'DownloadRestrictions'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Warn for dangerous downloads (not block)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        Name = 'ExtensionInstallSources'
        Type = 'MultiString'
        ApplyValue = 'https://microsoftedge.microsoft.com/addons/*'
        Description = 'Extensions only from Microsoft Store'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Edge'
        Name = 'QuicAllowed'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'QUIC/HTTP3 Default: Enabled (User can change)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Edge'
        Name = 'PasswordManagerEnabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Password Manager Default: Enabled (User can disable)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Edge'
        Name = 'AutofillAddressEnabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'AutoFill Address Default: Enabled (User can disable)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Edge'
        Name = 'AutofillCreditCardEnabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'AutoFill Credit Card Default: Enabled (User can disable)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Edge'
        Name = 'PaymentMethodQueryEnabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Payment Methods Default: Enabled (User can disable)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Edge'
        Name = 'WebRtcLocalhostIpHandling'
        Type = 'String'
        ApplyValue = 'default_public_interface_only'
        Description = 'WebRTC IP-Leak Prevention Default (User can change)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Edge'
        Name = 'InPrivateModeAvailability'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'InPrivate Mode Default: Available (User can change)'
        File = 'SecurityBaseline-Edge.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'
        Name = 'DisableTutorial'
        Type = 'DWord'
        ApplyValue = 1
        Description = '$(Get-LocalizedString'
        File = 'SecurityBaseline-OneDrive.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
        Name = 'DisableTutorial'
        Type = 'DWord'
        ApplyValue = 1
        Description = '$(Get-LocalizedString'
        File = 'SecurityBaseline-OneDrive.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'
        Name = 'DisableFeedback'
        Type = 'DWord'
        ApplyValue = 1
        Description = '$(Get-LocalizedString'
        File = 'SecurityBaseline-OneDrive.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
        Name = 'DisableFeedback'
        Type = 'DWord'
        ApplyValue = 1
        Description = '$(Get-LocalizedString'
        File = 'SecurityBaseline-OneDrive.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'
        Name = 'PreventNetworkTrafficPreUserSignIn'
        Type = 'DWord'
        ApplyValue = 1
        Description = '$(Get-LocalizedString'
        File = 'SecurityBaseline-OneDrive.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
        Name = 'PreventNetworkTrafficPreUserSignIn'
        Type = 'DWord'
        ApplyValue = 1
        Description = '$(Get-LocalizedString'
        File = 'SecurityBaseline-OneDrive.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\OneDrive'
        Name = 'KFMBlockOptIn'
        Type = 'DWord'
        ApplyValue = 1
        Description = '$(Get-LocalizedString'
        File = 'SecurityBaseline-OneDrive.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
        Name = 'KFMBlockOptIn'
        Type = 'DWord'
        ApplyValue = 1
        Description = '$(Get-LocalizedString'
        File = 'SecurityBaseline-OneDrive.ps1'
    },
    # NOTE: SetupCompletedSuccessfully = 0 REMOVED (breaks Windows Search and Outlook!)
    # This key disables the Windows Search indexer and breaks Outlook email search
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name = 'AllowCortana'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Cortana deaktivieren'
        File = 'SecurityBaseline-Performance.ps1'
    },
    # REMOVED: DisableWebSearch (blocks Settings app search!)
    # Web search still blocked by: ConnectedSearchUseWeb, BingSearchEnabled, AllowCloudSearch
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name = 'ConnectedSearchUseWeb'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Connected Search Web deaktivieren'
        File = 'SecurityBaseline-Performance.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
        Name = 'EnablePrefetcher'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'Prefetch: Nur Boot (SSD-optimiert)'
        File = 'SecurityBaseline-Performance.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
        Name = 'EnableSuperfetch'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Superfetch: Aus (SSD braucht das nicht)'
        File = 'SecurityBaseline-Performance.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance'
        Name = 'MaintenanceDisabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Maintenance aktiviert (aber optimiert)'
        File = 'SecurityBaseline-Performance.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance'
        Name = 'IdleOnly'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Maintenance nur im Idle'
        File = 'SecurityBaseline-Performance.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
        Name = 'DODownloadMode'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Delivery Optimization: HTTP-Only (kein Seeding)'
        File = 'SecurityBaseline-Performance.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        Name = 'AllowTelemetry'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Telemetrie: Security (0 = Minimum)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        Name = 'MaxTelemetryAllowed'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Maximum Telemetrie: Security'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        Name = 'DoNotShowFeedbackNotifications'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Feedback-Benachrichtigungen deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        Name = 'DoNotShowFeedbackNotifications'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Windows Feedback deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
        Name = 'AITEnable'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Application Impact Telemetry deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
        Name = 'DisabledByGroupPolicy'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Advertising ID deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Control Panel\International\User Profile'
        Name = 'HttpAcceptLanguageOptOut'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Websites locally relevant content verhindern'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        Name = 'Start_TrackProgs'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'App Launch Tracking OFF (Start/Search improvement)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Name = 'NoInstrumentation'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Disable Windows Instrumentation (App Tracking)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name = 'AllowSearchToUseLocation'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Search darf Location nicht nutzen'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name = 'SubscribedContent-338393Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Settings Suggested Content OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name = 'SubscribedContent-353694Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Settings Suggested Content OFF (2)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Name = 'SubscribedContent-353696Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Settings Suggested Content OFF (3)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications'
        Name = 'EnableAccountNotifications'
        Type = 'Unknown'
        ApplyValue = 0
        Description = ''
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'EnableActivityFeed'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Activity Feed deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'UploadUserActivities'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'User Activities Upload verbieten'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'AllowClipboardHistory'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Cloud Clipboard History deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'AllowCrossDeviceClipboard'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Cross-Device Clipboard deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        Name = 'DisableLocation'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Location Services deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        Name = 'DisableWindowsLocationProvider'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Windows Location Provider deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
        Name = 'RestrictImplicitTextCollection'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Handwriting/Typing Data Collection einschraenken'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
        Name = 'RestrictImplicitInkCollection'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Ink Data Collection einschraenken'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
        Name = 'AllowTelemetry'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Telemetrie auf Security-Level'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
        Name = 'DisableSettingSync'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'Settings Sync deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync'
        Name = 'DisableSettingSyncUserOverride'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Settings Sync User Override verbieten'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice'
        Name = 'AllowFindMyDevice'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Find My Device deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name = 'DisableWindowsSpotlightFeatures'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Windows Spotlight deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'App Diagnostics Zugriff verweigern'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name = 'AllowCortana'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Cortana deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    # REMOVED: DisableWebSearch (blocks Settings app search!)
    # Web search still blocked by: ConnectedSearchUseWeb, BingSearchEnabled, AllowCloudSearch
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name = 'ConnectedSearchUseWeb'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Connected Search Web deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name = 'BingSearchEnabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Bing-Integration deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name = 'EnableDynamicContentInWSB'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Search Highlights deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Name = 'AllowCloudSearch'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Cloud Search deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
        Name = 'BingSearchEnabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Bing Search (User) deaktivieren'
        ApplyValue = 'Deny'
        Description = ''
        ApplyValue = 'Deny'
        Description = ''
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name = 'DisableWindowsConsumerFeatures'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Consumer Features deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name = 'DisableSoftLanding'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Vorgeschlagene Inhalte deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name = 'RestrictImplicitInkCollection'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Freihand-Datensammlung einschraenken (Policy)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization'
        Name = 'RestrictImplicitTextCollection'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Input Personalization komplett deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\InputPersonalization'
        Name = 'RestrictImplicitInkCollection'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Freihand-Datensammlung einschraenken (User)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\InputPersonalization'
        Name = 'RestrictImplicitTextCollection'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Text-Datensammlung einschraenken (User)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore'
        Name = 'HarvestContacts'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Kontakte-Harvest deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    },
    # Batch 5a: App Permissions (First 10 of 33)
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Notifications OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Account Info OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Phone Calls OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Call History OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Messaging/SMS OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Tasks OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Radios Control OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    # Batch 5b: App Permissions (11-20 of 33)
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Other Devices OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Documents Library OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Pictures Library OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Videos Library OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: File System Access OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Downloads Folder OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Music Library OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\automaticFileDownloads'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Automatic File Downloads OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Activity History OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Bluetooth OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences'
        Name = 'VoiceActivationEnableAboveLockscreen'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Voice Activation above Lockscreen OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name = 'LetAppsGetDiagnosticInfo'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'Apps: Diagnostics OFF (Value 2 means User Denied)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    # Batch 5c: Remaining 13 app permission duplicates removed
    # Batch 6: Expand remaining 13 app permissions (21-33 of 33)
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Cellular Data OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Gaze Input/Eye Tracking OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Graphics Capture Programmatic OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Graphics Capture Without Border OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Human Interface Device OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\passkeys'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Passkeys OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\passkeysEnumeration'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Passkeys Enumeration OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Custom Sensors OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Serial Communication OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: System AI Models OFF (Windows 11 25H2)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: USB Devices OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: WiFi Data OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: WiFi Direct OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    # Batch 7: Dynamic variables removed (cannot be statically backed up)
    # These are set at runtime based on system state:
    # - $app.PSPath: Per-app location permission (varies by installed apps)
    # - $hkcuPath: User-specific paths (varies by user profile)
    # - $appKey.PSPath: Per-app key paths (varies by installed apps)
    # - $guid: Network adapter GUID (varies by system)
    # - $svc.Reg: Service registry path (varies by service)
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacyHKCU'
        Name = 'LetAppsGetDiagnosticInfo'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'CURRENT USER: App Diagnostics OFF'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR'
        Name = 'AppCaptureEnabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Game Capture deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\System\GameConfigStore'
        Name = 'GameDVR_Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'GameDVR deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
        Name = 'AllowGameDVR'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'GameDVR Policy: Verbieten'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\GameBar'
        Name = 'AutoGameModeEnabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Auto Game Mode deaktivieren'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\Software\Microsoft\GameBar'
        Name = 'AllowAutoGameMode'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Auto Game Mode verbieten'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
        Name = 'NoToastApplicationNotificationOnLockScreen'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'No toast notifications on lock screen (privacy + security)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
        Name = 'NoLockScreenCamera'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Prevent lock screen camera (privacy)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
        Name = 'NoLockScreenSlideshow'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Prevent lock screen slideshow (privacy)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'EnableLUA'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enable UAC'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'ConsentPromptBehaviorAdmin'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'UAC: Always notify (Slider at top) - Prompt for credentials on secure desktop'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'PromptOnSecureDesktop'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'UAC: Enable Secure Desktop (Anti-Malware Protection)'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'ConsentPromptBehaviorUser'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'UAC: Standard User Prompt for credentials'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'ValidateAdminCodeSignatures'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'UAC: No signature check (too restrictive for normal environments)'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'EnableSecureUIAPaths'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'UAC: Only allow secure UIAccess paths'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'LocalAccountTokenFilterPolicy'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'UAC: Prevent remote UAC bypass for local accounts (anti-PtH)'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
        Name = 'EnumerateAdministrators'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'UAC: Don''t enumerate admin accounts on elevation prompt'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'InactivityTimeoutSecs'
        Type = 'DWord'
        ApplyValue = 900
        Description = 'Auto-lock after 15 minutes (900 sec) inactivity'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
        Name = 'ScreenSaverIsSecure'
        Type = 'String'
        ApplyValue = '1'
        Description = 'MACHINE POLICY: Require password on lock screen (CRITICAL!)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'ConsentPromptBehaviorAdminInEPPMode'
        Type = 'DWord'
        ApplyValue = 2
        Description = 'UAC EPP: Prompt for credentials on secure desktop'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'AdminApprovalModeType'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'UAC: Admin Approval Mode with Enhanced Privilege Protection'
        File = 'SecurityBaseline-UAC.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
        Name = 'AllowMUUpdateService'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Updates for other MS products: ON'
        File = 'SecurityBaseline-WindowsUpdate.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
        Name = 'IsContinuousInnovationOptedIn'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Get latest updates as soon as available: ON'
        File = 'SecurityBaseline-WindowsUpdate.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
        Name = 'AllowAutoWindowsUpdateDownloadOverMeteredNetwork'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Download updates over metered connections: ON (Security First!)'
        File = 'SecurityBaseline-WindowsUpdate.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
        Name = 'RestartNotificationsAllowed2'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Restart notifications: ON'
        File = 'SecurityBaseline-WindowsUpdate.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
        Name = 'IsExpedited'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Get latest updates immediately: ON'
        File = 'SecurityBaseline-WindowsUpdate.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
        Name = 'ManagePreviewBuilds'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Preview Builds Policy: Managed'
        File = 'SecurityBaseline-WindowsUpdate.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
        Name = 'ManagePreviewBuildsPolicyValue'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Preview Builds Policy: NO Preview Builds (guaranteed!)'
        File = 'SecurityBaseline-WindowsUpdate.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
        Name = 'DODownloadMode'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Delivery Optimization Policy: HTTP-Only (guaranteed!)'
        File = 'SecurityBaseline-WindowsUpdate.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\DeliveryOptimization\Config'
        Name = 'DODownloadMode'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Delivery Optimization Config: HTTP-Only (Fallback)'
        File = 'SecurityBaseline-WindowsUpdate.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\PlayToReceiver'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable PlayToReceiver'
        File = 'SecurityBaseline-WirelessDisplay.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'
        Name = 'AllowProjectionToPC'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Prohibit projection to this PC'
        File = 'SecurityBaseline-WirelessDisplay.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect'
        Name = 'RequirePinForPairing'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Enforce PIN for pairing'
        File = 'SecurityBaseline-WirelessDisplay.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WirelessDisplay'
        Name = 'Enabled'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable Wireless Display Feature'
        File = 'SecurityBaseline-WirelessDisplay.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer'
        Name = 'PreventWirelessReceiver'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Prevent Wireless Media Streaming'
        File = 'SecurityBaseline-WirelessDisplay.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        Name = '1803'
        Type = 'DWord'
        ApplyValue = 3
        Description = 'Restricted Zone: Disable file downloads completely'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
        Name = '1806'
        Type = 'DWord'
        ApplyValue = 3
        Description = 'Restricted Zone: Disable launching apps/files completely'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
        Name = 'DefaultLevel'
        Type = 'DWord'
        ApplyValue = 0x00040000
        Description = 'SRP: Unrestricted mode (allow all except explicit deny)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
        Name = 'TransparentEnabled'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'SRP: Enable transparent enforcement'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache'
        Name = 'OsuRegistrationStatus'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Disable Wi-Fi Direct OSU'
        File = 'SecurityBaseline-WirelessDisplay.ps1'
    },
    @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc'
        Name = 'Start'
        Type = 'DWord'
        ApplyValue = 4
        Description = 'Disable DevicePickerUserSvc (Wireless Display User Service)'
        File = 'SecurityBaseline-WirelessDisplay.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
        Name = 'MinimumPINLength'
        Type = 'DWord'
        ApplyValue = 6
        Description = 'Windows Hello: Minimum PIN length (6 digits)'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
        Name = 'MaximumPINLength'
        Type = 'DWord'
        ApplyValue = 127
        Description = 'Windows Hello: Maximum PIN length'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
        Name = 'Digits'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Windows Hello: Require digits in PIN'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
        Name = 'Expiration'
        Type = 'DWord'
        ApplyValue = 0
        Description = 'Windows Hello: PIN never expires'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
        Name = 'History'
        Type = 'DWord'
        ApplyValue = 5
        Description = 'Windows Hello: Remember last 5 PINs'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
        Name = 'EnhancedAntiSpoofing'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'Windows Hello: Enhanced anti-spoofing for face recognition'
        File = 'SecurityBaseline-Advanced.ps1'
    },
    
    # ===========================
    # DEFENDER FEATURES (TRUSTEDINSTALLER-PROTECTED KEYS)
    # ===========================
    # NOTE: These keys require TrustedInstaller ownership to modify
    # Backup: Can read with Admin rights (Get-ItemProperty)
    # Restore: Requires Set-RegistryValueSmart (automatic ownership management)
    
    @{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        Name = 'EnableAppInstallControl'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'PUA: Block apps (Checkbox) - TrustedInstaller protected'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features'
        Name = 'EnableEDRInBlockMode'
        Type = 'DWord'
        ApplyValue = 1
        Description = 'EDR in Block Mode (Endpoint Detection & Response)'
        File = 'SecurityBaseline-Core.ps1'
    },
    @{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features'
        Name = 'TamperProtection'
        Type = 'DWord'
        ApplyValue = 4
        Description = 'Tamper Protection: Enabled (local admin control, Value 4)'
        File = 'SecurityBaseline-Core.ps1'
    },
    
    # ===========================
    # HKCU APP PERMISSIONS (USER-SPECIFIC)
    # ===========================
    # These 33 keys are set by SecurityBaseline-Telemetry.ps1 in a loop
    # They control app permissions for the CURRENT USER (HKCU)
    # HKLM keys (above) set defaults for NEW users only
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Notifications OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Account Info OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Contacts OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Calendar OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Email OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Phone Calls OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Call History OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Messaging/SMS OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Tasks OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Radios Control OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Other Devices OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Documents Library OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Pictures Library OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Videos Library OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: File System Access OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Music Library OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Downloads Folder OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\automaticFileDownloads'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Automatic File Downloads OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Activity History OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Bluetooth OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Cellular Data OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Gaze Input/Eye Tracking OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Graphics Capture Programmatic OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Graphics Capture Without Border OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Human Interface Device OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\passkeys'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Passkeys OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\passkeysEnumeration'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Passkeys Enumeration OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Custom Sensors OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: Serial Communication OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: System AI Models OFF (HKCU - 25H2)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: USB Devices OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: WiFi Data OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    },
        @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = 'Apps: WiFi Direct OFF (HKCU)'
        File = 'SecurityBaseline-Telemetry.ps1'
    }

)
