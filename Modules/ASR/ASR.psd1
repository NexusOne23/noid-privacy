@{
    RootModule        = 'ASR.psm1'
    ModuleVersion     = '2.2.3'
    GUID              = 'b2c3d4e5-f6a7-8901-bcde-f23456789012'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025 NexusOne23. Licensed under GPL-3.0.'
    Description       = 'Attack Surface Reduction (ASR) - All 19 Microsoft Defender ASR rules in Block mode for maximum protection against modern threats'
    
    PowerShellVersion = '5.1'
    
    RequiredModules   = @()
    
    FunctionsToExport = @(
        'Invoke-ASRRules'
    )
    
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    
    PrivateData       = @{
        PSData = @{
            Tags         = @('Security', 'ASR', 'AttackSurfaceReduction', 'Defender', 'Windows11', 'Ransomware')
            LicenseUri   = ''
            ProjectUri   = ''
            ReleaseNotes = @"
v2.2.3 - Production Release
- All 19 ASR rules implementation
- Hybrid approach: Registry backup + Set-MpPreference application
- SCCM/Configuration Manager detection
- Cloud protection verification
- Exclusions management support
- Full BACKUP/APPLY/VERIFY/RESTORE support
- Security Baseline overlap detection and logging
"@
        }
    }
}
