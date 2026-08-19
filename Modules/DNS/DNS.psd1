@{
    # Module manifest for DNS module

    RootModule        = 'DNS.psm1'
    ModuleVersion     = '2.2.5'
    GUID              = 'a8f7b3c9-4e5d-4a2b-9c1d-8f3e5a7b9c2d'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'
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
    AliasesToExport   = @(
        # DNS.psm1 declares `Invoke-DNS` as a naming-consistency alias for Invoke-DNSConfiguration.
        'Invoke-DNS'
    )

    PrivateData       = @{
        PSData = @{
            Tags         = @('DNS', 'DoH', 'Security', 'Privacy', 'Cloudflare', 'Quad9', 'AdGuard')
            LicenseUri   = 'https://github.com/NexusOne23/noid-privacy/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/NexusOne23/noid-privacy'
            ReleaseNotes = 'DoH (DNS-over-HTTPS) for Quad9, Cloudflare, and AdGuard with REQUIRE/ALLOW modes, IPv4/IPv6 dual-stack, and an explicit KEEP/preserve-current-DNS choice. See project CHANGELOG.md for full version history.'
        }
    }
}
