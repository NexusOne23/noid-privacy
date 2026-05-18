@{
    RootModule        = 'AntiAI.psm1'
    ModuleVersion     = '2.2.4'
    GUID              = 'f8e9d7c6-5b4a-3c2d-1e0f-9a8b7c6d5e4f'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025 NexusOne23. Licensed under GPL-3.0.'
    Description       = 'Windows 11 AI lockdown -- Disables 15 AI features using official Microsoft policies (Recall, Copilot, Paint AI, Notepad AI, Click to Do, Settings Agent, etc.) with Recall app/URI deny-list protection.'
    PowerShellVersion = '5.1'
    
    FunctionsToExport = @(
        'Invoke-AntiAI'
    )
    
    PrivateData       = @{
        PSData = @{
            Tags         = @('Windows11', 'AI', 'Privacy', 'Security', 'Recall', 'Copilot', 'AntiAI')
            LicenseUri   = 'https://github.com/NexusOne23/noid-privacy/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/NexusOne23/noid-privacy'
            ReleaseNotes = @'
v2.2.4 -- see project CHANGELOG.md for full version history.
This module disables 15 Windows 11 AI features via 32 official Microsoft policies:
- Master switch: blocks all generative AI models (Paint, Notepad, Photos, Clipchamp, Snipping Tool)
- Windows Recall: full deactivation (component removal + snapshots + data providers)
- Windows Recall: app/URI deny lists, storage duration & space limits
- Windows Copilot: system-wide deactivation + hardware key remapping
- Click to Do: screenshot analysis disabled
- Paint AI: Cocreator, Generative Fill, Image Creator disabled
- Notepad AI: Write, Summarize, Rewrite features disabled
- Settings Agent: AI-powered Settings search disabled
- Backup/restore for all applied registry settings
- Compliance verification via Test-AntiAICompliance
'@
        }
    }
}
