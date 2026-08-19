@{
    # Module manifest for AdvancedSecurity

    # Version
    ModuleVersion     = '2.2.5'

    # Unique ID
    GUID              = 'e7f5a3d2-8c9b-4f1e-a6d3-9b2c8f4e5a1d'

    # Author
    Author            = 'NexusOne23'

    # Company
    CompanyName       = 'Open Source Project'

    # Copyright
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'

    # Description
    Description       = 'Advanced Security hardening beyond Microsoft Security Baseline: 60 declared verification targets across RDP, Admin Shares, risky ports/services, TLS/WPAD, legacy SRP registry state, stable Windows Update preferences, Finger, Wireless Display, Discovery and IPv6. Optional/profile/firewall targets are reported as NotChecked when not selected.'

    # Minimum PowerShell version
    PowerShellVersion = '5.1'

    # Root module
    RootModule        = 'AdvancedSecurity.psm1'

    # Functions to export
    FunctionsToExport = @(
        'Invoke-AdvancedSecurity',
        'Test-AdvancedSecurity',
        'Restore-AdvancedSecuritySettings'
    )

    # Cmdlets to export
    CmdletsToExport   = @()

    # Variables to export
    VariablesToExport = @()

    # Aliases to export
    AliasesToExport   = @()

    # Private data
    PrivateData       = @{
        PSData = @{
            Tags         = @('Security', 'Hardening', 'Windows11', 'Advanced', 'RDP', 'Credentials', 'NetworkSecurity')
            LicenseUri   = 'https://github.com/NexusOne23/noid-privacy/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/NexusOne23/noid-privacy'
            ReleaseNotes = @'
v2.2.5
- AdvancedSecurity module contract for repository version 2.2.5
- 60 declared verification targets (see Config/SettingsCounts.json)
- NEW: Wireless Display (Miracast) security hardening
  - Default on supported Pro/Enterprise/Education/IoT editions: block receiving projections + require PIN
  - Optional: Complete disable (blocks sending, mDNS, ports 7236/7250)
  - Verifies exact selected policy/service/adapter/firewall state; no universal screen-interception prevention claim
- Profile-based execution (Balanced/Enterprise/Maximum)
- RDP NLA enforcement + optional complete disable
- Administrative shares disable (domain-aware)
- Risky firewall ports closure (LLMNR, NetBIOS, UPnP/SSDP)
- Risky network services stop (SSDPSRV, upnphost, lmhosts)
- Legacy TLS 1.0/1.1 disable
- WPAD auto-discovery disable through the documented WinHTTP value and the interactive Explorer user's WinINet API bit, preserving unrelated proxy flags
- Windows PowerShell 2.0 is no longer a new-run target because Microsoft removed it from updated Windows 11 24H2 and later; the historical reader recognizes old sealed artifacts, restores only while Windows exposes the feature identity and otherwise fails closed
- Sealed restore coverage for the module-owned selected state
- WhatIf mode and change log export
- Compliance testing function
'@
        }
    }
}
