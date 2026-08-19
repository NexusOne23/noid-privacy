@{
    # Script module or binary module file associated with this manifest
    RootModule = 'ModuleTemplate.psm1'

    # Version number of this module
    ModuleVersion = '2.2.5'

    # ID used to uniquely identify this module
    # PLACEHOLDER: Nil GUID is intentional -- .github/workflows/ci.yml validate-structure
    # rejects this exact value outside Modules/_ModuleTemplate/ so a copied template
    # cannot reach main without first regenerating via `[guid]::NewGuid()`.
    GUID = '00000000-0000-0000-0000-000000000000'

    # Author of this module. Default is the repo maintainer (NexusOne23). External
    # contributors who fork the template into a new module should replace this with
    # their own name before opening a PR.
    Author = 'NexusOne23'

    # Company or vendor of this module
    CompanyName = 'Open Source Project'

    # Copyright statement for this module
    Copyright = '(c) 2025-2026 NexusOne23. Licensed under GPL-3.0.'

    # Description of the functionality provided by this module
    Description = 'Non-mutating scaffold for a new NoID Privacy module; live use is refused until exact sealed BAVR is implemented.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @('Invoke-ModuleTemplate')

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('Windows11', 'Security', 'Hardening', 'Privacy')

            # License URL for this module
            LicenseUri = ''

            # Project site URL for this module
            ProjectUri = ''

            # Release notes for this module
            ReleaseNotes = 'Initial template version'
        }
    }
}
