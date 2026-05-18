@{
    RootModule        = 'SecurityBaseline.psm1'
    ModuleVersion     = '2.2.4'
    GUID              = '60beefe6-de01-494e-b053-cff56addade7'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'
    Description       = 'Microsoft Security Baseline for Windows 11 25H2 -- 425 hardening settings. Self-contained PowerShell implementation, no LGPO.exe required. (437 entries parsed, 12 are INF metadata.)'
    
    PowerShellVersion = '5.1'
    
    RequiredModules   = @()
    
    FunctionsToExport = @(
        'Invoke-SecurityBaseline',
        'Restore-SecurityBaseline'
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
v2.2.4 - Self-Contained Edition
- No LGPO.exe dependency -- self-contained PowerShell implementation
- 425 Microsoft Security Baseline settings for Windows 11 25H2
- 335 Registry policies (Computer + User)
- 67 Security Template settings (Password/Account/User Rights)
- 23 Advanced Audit Policies
- Note: 437 entries parsed from GPO files (12 INF metadata entries excluded)
- Native Windows tools only (PowerShell, secedit, auditpol)
- Automatic domain membership detection
- Standalone system adjustments (LocalAccountTokenFilterPolicy)
- BACKUP/RESTORE for all 425 applied settings
- No Microsoft file redistribution (license compliant)
"@
        }
    }
}
