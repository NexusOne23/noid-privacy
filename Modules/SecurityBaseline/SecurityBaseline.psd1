@{
    RootModule        = 'SecurityBaseline.psm1'
    ModuleVersion     = '2.2.5'
    GUID              = '60beefe6-de01-494e-b053-cff56addade7'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'
    Description       = '425-target profile derived from the Microsoft Security Baseline for Windows 11 25H2, with documented NoID Privacy deviations and repository-local parsed-artifact provenance. No LGPO.exe required.'

    PowerShellVersion = '5.1'

    RequiredModules   = @()

    FunctionsToExport = @(
        'Invoke-SecurityBaseline',
        'Restore-SecurityBaseline',
        # Restore-RegistryPolicies is exported because Core/Rollback.ps1 needs to call it
        # cross-module during session restore (see Restore-Session step "[STEP 2] Registry
        # Policies Restore"). It lives in Private/ by directory but is part of the public
        # cross-module surface.
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
v2.2.5 - Self-Contained Edition
- No LGPO.exe dependency -- self-contained PowerShell implementation
- 425 declared targets derived from the Microsoft Security Baseline for Windows 11 25H2
- 335 Registry policies (Computer + User)
- 67 Security Template settings (Password/Account/User Rights)
- 23 Advanced Audit Policies
- Note: 437 entries parsed from GPO files (12 INF metadata entries excluded)
- Native Windows tools only (PowerShell, secedit, auditpol)
- Automatic domain membership detection
- Standalone system adjustments (LocalAccountTokenFilterPolicy)
- Exact scoped BACKUP/RESTORE for every applicable mutation; host-inapplicable targets are reported separately
- No Microsoft file redistribution (license compliant)
"@
        }
    }
}
