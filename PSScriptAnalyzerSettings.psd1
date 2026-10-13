@{
    # PSScriptAnalyzer settings for NoID Privacy framework.
    #
    # Used by:
    #   - CI workflow (.github/workflows/ci.yml) via -Settings ./PSScriptAnalyzerSettings.psd1
    #   - Local dev: pwsh -c "Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1"
    #
    # Target environment:
    #   - 64-bit Windows PowerShell 5.1 for the product runtime
    #   - PowerShell 7.4 for static analysis; not a supported product runtime

    Severity     = @('Error', 'Warning')

    # Rules excluded by architectural decision (with rationale).
    ExcludeRules = @(
        # PSAvoidUsingWriteHost
        #   NoID Privacy is an INTERACTIVE CLI hardening framework. Write-Host
        #   is the intended channel for user-facing console output; since
        #   PowerShell 5.0 it writes to the information stream, so it can still
        #   be captured or suppressed. Write-Output would mix display text into
        #   the structured module results that callers consume from the success
        #   pipeline. Logging goes through Write-Log/Logger.ps1.
        'PSAvoidUsingWriteHost',

        # PSUseBOMForUnicodeEncodedFile
        #   NoID Privacy emits JSON, HTML, and checksum files with UTF-8 NO-BOM
        #   for cross-tool compatibility (some JSON parsers reject a BOM and a
        #   checksum tool can treat it as part of the first hash token). All
        #   PowerShell source files are kept ASCII-only, so Windows PowerShell
        #   5.1 does not need a BOM to select a Unicode source encoding. See the
        #   UTF-8 NO-BOM decision in Docs/RELEASE-NOTES-2.2.5.md.
        'PSUseBOMForUnicodeEncodedFile',

        # PSUseSingularNouns
        #   NoID's public function names favor plural nouns where the operation
        #   acts on a SET of items rather than a single one -- e.g.
        #   `Invoke-ASRRules` (applies N rules), `Set-EdgePolicies` (writes the
        #   selected Edge policy set as one transaction), `Get-PhysicalAdapters` (returns
        #   a collection). Renaming would break the public PowerShell API
        #   exposed via every module's psd1 `FunctionsToExport` and cascade
        #   through README/CHANGELOG/Tests. The plural form is intentional
        #   and conveys the bulk-operation semantics correctly.
        'PSUseSingularNouns',

        # PSAvoidGlobalVars
        #   The framework loads core scripts (Logger.ps1, Rollback.ps1,
        #   Framework.ps1, NonInteractive.ps1) by dot-sourcing rather than
        #   importing as modules. `$script:` scope is therefore not shared
        #   across files. The six cross-file state slots
        #     $global:LoggerConfig, $global:BackupIndex, $global:SessionManifest,
        #     $global:BackupBasePath, $global:CurrentModule,
        #     $global:NoIDNonInteractiveBannerShown
        #   are the intentional cross-script communication channel. Converting
        #   to module-scoped state would require packaging Core/* as a proper
        #   PS module -- a larger architectural change, deferred to keep the
        #   BAVR backup/restore contract stable.
        'PSAvoidGlobalVars'
    )

    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }

        PSPlaceOpenBrace = @{
            Enable             = $false
            # We intentionally accept both inline `{ ` and newline-then-`{`
            # bracket styles -- the framework mixes them based on context
            # (single-line guards vs. block declarations).
        }
    }
}
