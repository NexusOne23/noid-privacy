@{
    RootModule        = 'Privacy.psm1'
    ModuleVersion     = '2.2.5'
    GUID              = 'a9f7c8d3-2e5b-4a1f-9c3d-7e8f5a6b2c4d'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'
    Description       = 'Privacy & Telemetry hardening with exact target-level BAVR, OneDrive/Store configuration, and two optional destructive app-removal tiers. Policy/registry state restores exactly; sealed Tier 1/Tier 2 app inventories enable separate original-user package re-registration with verified Store fallback, but deleted app data remains unrecoverable.'

    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Invoke-PrivacyHardening',
        'Test-PrivacyCompliance',
        'Get-BloatwareRestoreAssessment',
        'Restore-BloatwareApps'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @(
        # Privacy.psm1 declares `Invoke-Privacy` as a naming-consistency alias for Invoke-PrivacyHardening.
        'Invoke-Privacy'
    )

    PrivateData       = @{
        PSData = @{
            Tags         = @('Privacy', 'Telemetry', 'OneDrive', 'Windows11', 'Security', 'BAVR', 'Bloatware')
            LicenseUri   = 'https://github.com/NexusOne23/noid-privacy/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/NexusOne23/noid-privacy'
            ReleaseNotes = 'v2.2.5 -- Privacy module with 3 modes, exact target-level backup/restore, interactive-user HKU handling, and OneDrive/Store hardening. Both optional app-removal tiers seal original-user app identities. Separate recovery re-registers staged package families first and uses a verified winget Store fallback; it never claims to recover deleted app data or licensing.'
        }
    }
}
