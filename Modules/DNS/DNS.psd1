@{
    # Module manifest for DNS module
    
    RootModule        = 'DNS.psm1'
    ModuleVersion     = '2.1.0'
    GUID              = 'a8f7b3c9-4e5d-4a2b-9c1d-8f3e5a7b9c2d'
    Author            = 'NoID Privacy Pro'
    CompanyName       = 'NoID Privacy Pro'
    Copyright         = '(c) 2025 NoID Privacy Pro. All rights reserved.'
    Description       = 'Secure DNS configuration module with DoH support for Cloudflare, Quad9, and AdGuard DNS providers'
    
    PowerShellVersion = '5.1'
    
    # Functions to export from this module
    FunctionsToExport = @(
        'Invoke-DNSConfiguration',
        'Get-DNSStatus',
        'Restore-DNSSettings'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport   = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module
    AliasesToExport   = @()
    
    PrivateData       = @{
        PSData = @{
            Tags         = @('DNS', 'DoH', 'Security', 'Privacy', 'Cloudflare', 'Quad9', 'AdGuard')
            LicenseUri   = ''
            ProjectUri   = ''
            ReleaseNotes = 'Initial release with DoH support for 3 major DNS providers'
        }
    }
}
