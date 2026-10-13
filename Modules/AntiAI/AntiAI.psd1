@{
    RootModule        = 'AntiAI.psm1'
    ModuleVersion     = '2.2.6'
    GUID              = 'f8e9d7c6-5b4a-3c2d-1e0f-9a8b7c6d5e4f'
    Author            = 'NexusOne23'
    CompanyName       = 'Open Source Project'
    Copyright         = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'
    Description       = 'Reversible Windows 11 AI policy hardening with 50 config-derived registry targets, interactive-user scope handling, four exact URI-handler source checks, and sealed BAVR.'
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
v2.2.6 -- explicit Windows 11 26H2 applicability and current WindowsAI agent-policy planning; see project CHANGELOG.md.
This module configures 50 registry targets plus four URI source checks across 12 reversible AI-hardening groups:
- AppPrivacy: force-denies Windows apps the text and image generation features of Windows (LetAppsAccessSystemAIModels)
- Windows Recall: component-availability and snapshot policies plus the Insider-only data-provider control
- Windows Recall: app/URI deny lists, storage duration & space limits
- Microsoft Copilot app: browsing and Cowork actions disabled; installs through Microsoft Edge Update blocked on domain-joined or MDM-enrolled devices (Edge Update ignores its policies elsewhere); Microsoft 365 Copilot and Copilot apps no longer start at sign-in; legacy Copilot policy, Copilot key remapping and exact URI-handler BAVR
- Windows AI agents: connectors force-disabled and one-hour consent lifetime on explicit 26H2 or Insider commercial profiles; Microsoft Execution Containers telemetry blocked
- Click to Do: screenshot analysis disabled
- Paint AI: documented Cocreator, Generative Fill and Image Creator policies; Generative Erase has no published policy
- Notepad AI: Write, Summarize, Rewrite features disabled
- Settings Agent: disable policy on commercial editions from build 26100.4770; the feature itself needs an eligible Copilot+ PC
- Microsoft Edge: 23 Copilot/AI policies (sidebar, new-tab Copilot, page context, agentic browsing, on-device AI models and APIs, writing assistance and text prediction, AI tab organization, cloud autofill models and proofing, AI history/visual search, Copilot sign-in linking, themes)
- Interactive-user values target the desktop owner even after over-the-shoulder elevation
- Exact backup/restore for the documented applicable subset; every other declared target is reported NotApplicable and left untouched
- Unsupported HideAIActionsMenu and destructive package-removal workarounds are excluded
- Compliance verification is registry/source-hive exactness, not a blanket runtime-effectiveness claim
'@
        }
    }
}
