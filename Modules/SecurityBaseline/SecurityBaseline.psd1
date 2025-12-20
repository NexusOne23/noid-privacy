@{
    RootModule = 'SecurityBaseline.psm1'
    ModuleVersion = '2.2.1'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'NexusOne23'
    CompanyName = 'Open Source Project'
    Copyright = '(c) 2025 NexusOne23. Licensed under GPL-3.0.'
    Description = 'Microsoft Security Baseline for Windows 11 25H2 - 425 hardening settings implementing enterprise-grade security standards. Self-contained, no LGPO.exe required. (437 entries parsed, 12 are INF metadata)'
    
    PowerShellVersion = '5.1'
    
    RequiredModules = @()
    
    FunctionsToExport = @(
        'Invoke-SecurityBaseline',
        'Restore-SecurityBaseline'
    )
    
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Hardening', 'Windows11', 'Baseline', 'Microsoft', 'Enterprise')
            LicenseUri = ''
            ProjectUri = ''
            ReleaseNotes = @"
v2.2.1 - Self-Contained Edition
- NO LGPO.exe REQUIRED! Fully self-contained implementation
- 425 Microsoft Security Baseline settings for Windows 11 25H2
- 335 Registry policies (Computer + User)
- 67 Security Template settings (Password/Account/User Rights)
- 23 Advanced Audit Policies
- Note: 437 entries parsed from GPO files (12 INF metadata entries excluded)
- Native Windows tools only (PowerShell, secedit, auditpol)
- Automatic domain membership detection
- Standalone system adjustments (LocalAccountTokenFilterPolicy)
- Comprehensive BACKUP/RESTORE for all 425 settings
- 100% rollback capability
- Legal compliant (no Microsoft file redistribution)
"@
        }
    }
}
