@{
    # Script module or binary module file associated with this manifest
    RootModule        = 'EdgeHardening.psm1'

    # Version number of this module
    ModuleVersion     = '2.2.5'

    # ID used to uniquely identify this module
    GUID              = '8e3f4c2a-9b1d-4e7a-a2c5-6f8b3d9e1a4c'

    # Author of this module
    Author            = 'NexusOne23'

    # Company or vendor of this module
    CompanyName       = 'Open Source Project'

    # Copyright statement for this module
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'

    # Description of the functionality provided by this module
    Description       = 'Microsoft Edge hardening with 19 Microsoft v139 baseline values plus seven explicit NoID Privacy additions. Default selects 25 values; extension block-all is opt-in for 26. Uses native PowerShell with exact BAVR registry state.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules   = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Invoke-EdgeHardening',
        'Test-EdgeHardening'
    )

    # Cmdlets to export from this module
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport   = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData       = @{
        PSData = @{
            Tags         = @('Security', 'Edge', 'Browser', 'Hardening', 'Baseline', 'Windows11', 'Privacy')
            LicenseUri   = 'https://github.com/NexusOne23/noid-privacy/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/NexusOne23/noid-privacy'
            ReleaseNotes = @"
v2.2.5 - Target-state hardening release
- Microsoft Edge v139 Security Baseline implementation
- 19 Microsoft baseline values plus 7 explicitly labelled privacy additions
- SmartScreen enforcement with override prevention
- Site isolation (SitePerProcess) enabled
- SSL/TLS error override blocking
- Extension blocklist (MS baseline block-all is opt-in; default preserves existing policy)
- IE Mode restrictions
- Spectre/Meltdown mitigations (SharedArrayBuffer)
- Application-bound encryption
- Backup and restore functionality
- Compliance testing
"@
        }
    }
}
