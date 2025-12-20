@{
    # Script module or binary module file associated with this manifest
    RootModule = 'EdgeHardening.psm1'
    
    # Version number of this module
    ModuleVersion = '2.2.1'
    
    # ID used to uniquely identify this module
    GUID = '8e3f4c2a-9b1d-4e7a-a2c5-6f8b3d9e1a4c'
    
    # Author of this module
    Author = 'NexusOne23'
    
    # Company or vendor of this module
    CompanyName = 'Open Source Project'
    
    # Copyright statement for this module
    Copyright = '(c) 2025 NexusOne23. Licensed under GPL-3.0.'
    
    # Description of the functionality provided by this module
    Description = 'Microsoft Edge Security Hardening based on MS Edge v139 Security Baseline. Applies 24 security policies to harden Microsoft Edge browser using native PowerShell (no LGPO.exe dependency). Includes SmartScreen enforcement, site isolation, SSL/TLS hardening, extension blocking, and IE mode restrictions.'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'
    
    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()
    
    # Functions to export from this module
    FunctionsToExport = @(
        'Invoke-EdgeHardening',
        'Test-EdgeHardening'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module
    AliasesToExport = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Edge', 'Browser', 'Hardening', 'Baseline', 'Windows11', 'Privacy')
            LicenseUri = ''
            ProjectUri = ''
            ReleaseNotes = @"
v2.2.1 - Production Release
- Microsoft Edge v139 Security Baseline implementation
- 20 security policies (native PowerShell, no LGPO.exe)
- SmartScreen enforcement with override prevention
- Site isolation (SitePerProcess) enabled
- SSL/TLS error override blocking
- Extension blocklist (block all by default)
- IE Mode restrictions
- Spectre/Meltdown mitigations (SharedArrayBuffer)
- Application-bound encryption
- Backup and restore functionality
- Compliance testing
"@
        }
    }
}
