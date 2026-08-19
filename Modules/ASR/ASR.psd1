@{
    RootModule        = 'ASR.psm1'
    ModuleVersion     = '2.2.5'
    GUID              = 'b2c3d4e5-f6a7-8901-bcde-f23456789012'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'
    Description       = 'Attack Surface Reduction (ASR) - 19 declared Defender rules with exact Windows 11 client applicability and BAVR'

    PowerShellVersion = '5.1'

    RequiredModules   = @()

    FunctionsToExport = @(
        'Invoke-ASRRules',
        # Test-ASRCompliance lives in Private/ by directory but is exported as the
        # module's stable standalone compliance surface. Tools/Verify-Complete-Hardening.ps1
        # does NOT call it; the verifier maintains its own independent inline checks.
        'Test-ASRCompliance'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @(
        # ASR.psm1 declares `Invoke-ASR` as a naming-consistency alias for Invoke-ASRRules.
        'Invoke-ASR'
    )

    PrivateData       = @{
        PSData = @{
            Tags         = @('Security', 'ASR', 'AttackSurfaceReduction', 'Defender', 'Windows11', 'Ransomware')
            LicenseUri   = 'https://github.com/NexusOne23/noid-privacy/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/NexusOne23/noid-privacy'
            ReleaseNotes = @"
v2.2.5 - Target-state hardening release
- 19 declared ASR identities; 18 Windows-client rules applied and one Exchange-server rule NotApplicable
- Target-scoped Defender policy application with effective-state verification
- Schema 5 exact policy prestate; sealed schema 3/4 restore compatibility
- SCCM/Configuration Manager detection
- Cloud protection verification
- Sealed target-scoped BACKUP/APPLY/VERIFY/RESTORE implementation
- Security Baseline overlap detection and logging
"@
        }
    }
}
