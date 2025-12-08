@{
    # Module manifest for AdvancedSecurity
    
    # Version
    ModuleVersion     = '2.2.0'
    
    # Unique ID
    GUID              = 'e7f5a3d2-8c9b-4f1e-a6d3-9b2c8f4e5a1d'
    
    # Author
    Author            = 'NexusOne23'
    
    # Company
    CompanyName       = 'Open Source Project'
    
    # Copyright
    Copyright         = '(c) 2025 NexusOne23. Licensed under GPL-3.0.'
    
    # Description
    Description       = 'Advanced Security hardening beyond Microsoft Security Baseline: RDP hardening, WDigest protection, Admin Shares disable, Risky Ports/Services, Legacy TLS/WPAD/PSv2, SRP .lnk protection (CVE-2025-9491), Windows Update (3 simple GUI settings), Finger Protocol block, Wireless Display (Miracast) security. 38+ settings total with profile-based execution (Balanced/Enterprise/Maximum) and domain-safety checks plus full backup/restore.'
    
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
            LicenseUri   = ''
            ProjectUri   = ''
            ReleaseNotes = @'
v2.2.0 (2025-12-08)
- Production release of AdvancedSecurity module
- 49 advanced hardening settings implemented (was 36)
- NEW: Wireless Display (Miracast) security hardening
  - Default: Block receiving projections + require PIN (all profiles)
  - Optional: Complete disable (blocks sending, mDNS, ports 7236/7250)
  - Prevents screen interception attacks from network attackers
- Profile-based execution (Balanced/Enterprise/Maximum)
- RDP NLA enforcement + optional complete disable
- WDigest credential protection (backwards compatible)
- Administrative shares disable (domain-aware)
- Risky firewall ports closure (LLMNR, NetBIOS, UPnP/SSDP)
- Risky network services stop (SSDPSRV, upnphost, lmhosts)
- Legacy TLS 1.0/1.1 disable
- WPAD auto-discovery disable
- PowerShell v2 removal
- Full backup/restore capability
- WhatIf mode and change log export
- Compliance testing function
'@
        }
    }
}
