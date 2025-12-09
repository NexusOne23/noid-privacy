@{
    RootModule = 'AntiAI.psm1'
    ModuleVersion = '2.2.0'
    GUID = 'f8e9d7c6-5b4a-3c2d-1e0f-9a8b7c6d5e4f'
    Author = 'NexusOne23'
    CompanyName = 'Open Source Project'
    Copyright = '(c) 2025 NexusOne23. Licensed under GPL-3.0.'
    Description = 'Comprehensive Windows 11 AI deactivation - Disables all 15 AI features using official Microsoft policies (Recall, Copilot, Paint AI, Notepad AI, Click to Do, Settings Agent, etc.). Maximum compliance mode with enterprise-grade Recall protection.'
    PowerShellVersion = '5.1'
    
    FunctionsToExport = @(
        'Invoke-AntiAI'
    )
    
    PrivateData = @{
        PSData = @{
            Tags = @('Windows11', 'AI', 'Privacy', 'Security', 'Recall', 'Copilot', 'AntiAI')
            ProjectUri = 'https://github.com/yourusername/NoIDPrivacy'
            ReleaseNotes = @'
v1.0.0 - Initial Release
- Disables 8+ Windows 11 AI features using official Microsoft policies
- Master switch: Blocks all generative AI models (Paint, Notepad, Photos, Clipchamp, Snipping Tool)
- Windows Recall: Complete deactivation (component removal + snapshots + data providers)
- Windows Recall: Enterprise protection (app/URI deny lists, storage limits)
- Windows Copilot: System-wide deactivation + hardware key remapping
- Click to Do: Screenshot analysis disabled
- Paint AI: Cocreator, Generative Fill, Image Creator disabled
- Notepad AI: Write, Summarize, Rewrite features disabled
- Settings Agent: AI-powered search in Settings disabled
- Full backup/restore capability
- Comprehensive compliance verification
'@
        }
    }
}
