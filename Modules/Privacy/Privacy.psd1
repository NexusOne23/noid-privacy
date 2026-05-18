@{
    RootModule        = 'Privacy.psm1'
    ModuleVersion     = '2.2.4'
    GUID              = 'a9f7c8d3-2e5b-4a1f-9c3d-7e8f5a6b2c4d'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'
    Description       = 'Privacy & Telemetry hardening module with Bloatware removal and OneDrive configuration. Supports 3 modes: MSRecommended (default, MDM-friendly), Strict (maximum privacy with Teams/Zoom still working), and Paranoid (extreme -- breaks Teams/Zoom).'
    
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
            LicenseUri   = 'https://github.com/NexusOne23/noid-privacy/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/NexusOne23/noid-privacy'
            ReleaseNotes = 'v2.2.4 -- Privacy module with 3 modes (MSRecommended/Strict/Paranoid), bloatware removal with winget-based restore, OneDrive telemetry hardening. See project CHANGELOG.md for full version history.'
        }
    }
}
