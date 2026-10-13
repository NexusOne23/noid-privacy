@{
    RootModule        = 'SecurityBaseline.psm1'
    ModuleVersion     = '2.2.6'
    GUID              = '60beefe6-de01-494e-b053-cff56addade7'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'
    Description       = '425-target profile derived from the Microsoft Security Baseline for Windows 11 v26H2 (v2), with documented NoID Privacy deviations and repository-local parsed-artifact provenance. No LGPO.exe required.'

    PowerShellVersion = '5.1'

    RequiredModules   = @()

    FunctionsToExport = @(
        'Invoke-SecurityBaseline',
        'Restore-SecurityBaseline',
        # Restore-RegistryPolicies is exported because Core/Rollback.ps1 calls it
        # cross-module during session restore (the SecurityBaseline "Registry Policies
        # Restore" step of Restore-Session). It lives in Private/ by directory but is
        # part of the public cross-module surface.
        'Restore-RegistryPolicies'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags         = @('Security', 'Hardening', 'Windows11', 'Baseline', 'Microsoft')
            LicenseUri   = 'https://github.com/NexusOne23/noid-privacy/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/NexusOne23/noid-privacy'
            ReleaseNotes = @"
v2.2.6 - Self-Contained Edition
- No LGPO.exe dependency -- self-contained PowerShell implementation
- 425 declared targets derived from the Microsoft Security Baseline for Windows 11 v26H2 (v2)
- 335 Registry policies (Computer + User)
- 67 Security Template settings (account policies, user rights, security options, service startup)
- 23 Advanced Audit Policies
- Note: 438 entries parsed from GPO files (12 INF metadata entries and 1 native firewall format entry excluded)
- Native Windows tools only (PowerShell, secedit, auditpol)
- Same declared profile on standalone and domain-joined systems
- Microsoft remote-UAC baseline retained (LocalAccountTokenFilterPolicy=0)
- Fixed Windows-based BAVR decision: four LSA/Credential Guard/HVCI values use 2 instead of 1, requesting enabled protection without new UEFI locks
- This omits firmware resistance to privileged reconfiguration; no extra choice, and existing locks or recorded Restore values remain unchanged
- Exact scoped BACKUP/RESTORE for every applicable mutation; host-inapplicable targets are reported separately
- No Microsoft file redistribution (license compliant)
"@
        }
    }
}
