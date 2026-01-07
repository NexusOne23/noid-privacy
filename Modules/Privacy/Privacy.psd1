@{
    RootModule        = 'Privacy.psm1'
    ModuleVersion     = '2.2.3'
    GUID              = 'a9f7c8d3-2e5b-4a1f-9c3d-7e8f5a6b2c4d'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025 NexusOne23. Licensed under GPL-3.0.'
    Description       = 'Privacy & Telemetry hardening module with Bloatware removal and OneDrive configuration. Supports 3 modes: MSRecommended (default), Strict (maximum privacy, apps still work), and Paranoid (hardcore).'
    
    PowerShellVersion = '5.1'
    
    FunctionsToExport = @(
        'Invoke-PrivacyHardening',
        'Restore-Bloatware',
        'Test-PrivacyCompliance'
    )
    
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    
    PrivateData       = @{
        PSData = @{
            Tags         = @('Privacy', 'Telemetry', 'Bloatware', 'OneDrive', 'Windows11', 'Security')
            LicenseUri   = 'https://github.com/yourusername/NoIDPrivacyPro/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/yourusername/NoIDPrivacyPro'
            ReleaseNotes = 'Initial release - Privacy module with 3-mode support'
        }
    }
}
