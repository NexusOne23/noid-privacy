@{
    RootModule        = 'AntiAI.psm1'
    ModuleVersion     = '2.2.5'
    GUID              = 'f8e9d7c6-5b4a-3c2d-1e0f-9a8b7c6d5e4f'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'
    Description       = 'Reversible Windows 11 AI policy hardening with 43 config-derived registry targets, interactive-user scope handling, four exact URI-handler source checks, and sealed BAVR.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Invoke-AntiAI',
        # Test-AntiAICompliance lives in Private/ by directory but is exported as the
        # module's stable standalone compliance surface. The complete verifier
        # also consumes the durable target-plan resolver exported below, while
        # retaining independent live-state checks.
        'Test-AntiAICompliance',
        'Get-AntiAITargetPlan',
        # Standalone verification resolves the durable Apply-time target
        # partition through this manifest import. Keep it in the manifest's
        # explicit allowlist as well as Export-ModuleMember in AntiAI.psm1.
        'Get-AntiAIIntentTargetPlan'
    )

    PrivateData       = @{
        PSData = @{
            Tags         = @('Windows11', 'AI', 'Privacy', 'Security', 'Recall', 'Copilot', 'AntiAI')
            LicenseUri   = 'https://github.com/NexusOne23/noid-privacy/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/NexusOne23/noid-privacy'
            ReleaseNotes = @'
v2.2.5 -- see project CHANGELOG.md for full version history.
This module configures 43 registry targets plus four URI source checks across 12 reversible AI-hardening groups:
- AppPrivacy: force-denies documented app access to Windows generative-AI features
- Windows Recall: component-availability and snapshot policies plus data-provider controls
- Windows Recall: app/URI deny lists, storage duration & space limits
- Windows Copilot: reversible policy layers + hardware key remapping + exact URI-handler BAVR
- Agentic AI preview: Connectors/Workspaces/Remote + restricted floor + one-hour consent lifetime
- Click to Do: screenshot analysis disabled
- Paint AI: documented Cocreator, Generative Fill and Image Creator policies; Generative Erase has no published policy
- Notepad AI: Write, Summarize, Rewrite features disabled
- Settings Agent: preview-only disable policy on documented eligible commercial Copilot+ profiles
- Microsoft Edge: 17 Copilot/generative-AI policies (sidebar, classic/Copilot new-tab entry points, page-context, on-device AI APIs, writing assistance, AI history/visual search, themes)
- Interactive-user values target the desktop owner even after over-the-shoulder elevation
- Exact backup/restore for the documented applicable subset; every other declared target is reported NotApplicable and left untouched
- Unsupported HideAIActionsMenu and destructive package-removal workarounds are excluded
- Compliance verification is registry/source-hive exactness, not a blanket runtime-effectiveness claim
'@
        }
    }
}
