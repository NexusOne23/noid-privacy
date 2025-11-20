@{
    # Module manifest for AdvancedSecurity
    
    # Version
    ModuleVersion     = '2.1.0'
    
    # Unique ID
    GUID              = 'e7f5a3d2-8c9b-4f1e-a6d3-9b2c8f4e5a1d'
    
    # Author
    Author            = 'NoID Privacy Pro Team'
    
    # Company
    CompanyName       = 'NoID Privacy'
    
    # Copyright
    Copyright         = '(c) 2025 NoID Privacy. All rights reserved.'
    
    # Description
    Description       = 'Advanced Security hardening beyond Microsoft Security Baseline: RDP hardening, WDigest protection, Admin Shares disable, Risky Ports/Services, Legacy TLS/WPAD/PSv2, SRP .lnk protection (CVE-2025-9491), Windows Update (3 simple GUI settings), Finger Protocol block. 42 settings total (37 legacy + SRP 2 + Windows Update 3). Profile-based execution (Home/Enterprise/AirGapped) with domain-safety checks and full backup/restore.'
    
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
v2.1.0 (2025-11-18)
- Production release of AdvancedSecurity module
- 37 advanced hardening settings implemented
- Profile-based execution (Home/Enterprise/AirGapped)
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
