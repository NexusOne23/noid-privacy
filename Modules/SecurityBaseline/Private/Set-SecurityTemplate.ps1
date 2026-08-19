<#
.SYNOPSIS
    Apply security template settings from parsed Security Baseline JSON

.DESCRIPTION
    Converts JSON security template to INF format and applies via secedit.exe.
    The accepted section set is deliberately closed to the exact backup and
    restore owners: System Access, Privilege Rights, Registry Values and
    Service General Setting. Unknown sections are rejected before mutation.

.PARAMETER SecurityTemplatePath
    Path to SecurityTemplates.json

.PARAMETER DryRun
    Preview changes without applying

.OUTPUTS
    PSCustomObject with success status and errors

.NOTES
    Requires Administrator privileges
    Uses secedit.exe (built into Windows since Windows 2000)
#>

function Set-SecurityTemplate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SecurityTemplatePath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ServiceNamesWithSealedPrestate,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Set SecurityTemplate')) {
        return
    }


    $result = [PSCustomObject]@{
        Success = $false
        SectionsApplied = 0
        SettingsApplied = 0
        SettingsNotApplicable = 0
        Errors = @()
    }

    # What the generated INF would apply, tracked separately from what secedit
    # actually applied. Only a verified success copies these into $result.
    $plannedSections = 0
    $plannedSettings = 0

    if (-not (Test-Path $SecurityTemplatePath)) {
        $result.Errors += "Security template file not found: $SecurityTemplatePath"
        return $result
    }

    try {
        $templates = Get-Content -LiteralPath $SecurityTemplatePath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $installedServices = @(Get-Service -ErrorAction Stop)
        $canonicalServiceNames = @('XboxGipSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc')
        if (@($ServiceNamesWithSealedPrestate | Sort-Object -Unique).Count -ne $ServiceNamesWithSealedPrestate.Count -or
            @($ServiceNamesWithSealedPrestate | Where-Object { $_ -notin $canonicalServiceNames }).Count -gt 0) {
            throw 'ServiceNamesWithSealedPrestate contains an invalid or duplicate service identity'
        }

        # Merge all GPO templates into one master INF
        $infContent = @()
        $infContent += "[Unicode]"
        $infContent += "Unicode=yes"
        $infContent += ""
        $infContent += "[Version]"
        $infContent += "signature=`"`$CHICAGO$`""
        $infContent += "Revision=1"
        $infContent += ""

        # Track which sections we have
        $sectionsProcessed = @{}
        $settingLinesByIdentity = @{}
        $ownedSectionNames = @(
            'System Access',
            'Registry Values',
            'Privilege Rights',
            'Service General Setting'
        )

        # Process each GPO's security template
        foreach ($gpoName in ($templates.PSObject.Properties.Name)) {
            $gpoTemplate = $templates.$gpoName

            foreach ($sectionName in ($gpoTemplate.PSObject.Properties.Name)) {
                # Skip metadata sections
                if ($sectionName -in @("Unicode", "Version")) {
                    continue
                }
                if ($sectionName -notin $ownedSectionNames) {
                    throw "Security-template section is outside the sealed backup/restore contract: [$sectionName]"
                }

                $section = $gpoTemplate.$sectionName

                if (-not $sectionsProcessed.ContainsKey($sectionName)) {
                    $sectionsProcessed[$sectionName] = @()
                }

                # Add settings from this section
                foreach ($key in ($section.PSObject.Properties.Name)) {
                    $value = $section.$key

                    # Service General Setting requires special format per MS-GPSB 2.2.8
                    # Format: "ServiceName",StartupMode,""
                    # StartupMode: 2=Automatic, 3=Manual, 4=Disabled
                    if ($sectionName -eq 'Service General Setting') {
                        $serviceInstalled = @($installedServices | Where-Object { [string]$_.Name -eq [string]$key }).Count -eq 1
                        $serviceWasSealed = [string]$key -in $ServiceNamesWithSealedPrestate
                        if ($serviceInstalled -ne $serviceWasSealed) {
                            throw "Security-template service inventory differs from sealed prestate: $key"
                        }
                        if (-not $serviceInstalled) {
                            Write-Log -Level INFO -Message "Service is not installed; security-template service setting skipped: $key" -Module 'SecurityBaseline'
                            $result.SettingsNotApplicable++
                            continue
                        }
                        # Parse StartupType from value (e.g., "StartupType=Disabled")
                        $startupMode = 4  # Default: Disabled
                        if ($value -match 'StartupType=(\w+)') {
                            $startupType = $matches[1]
                            switch ($startupType) {
                                'Disabled'  { $startupMode = 4 }
                                'Manual'    { $startupMode = 3 }
                                'Automatic' { $startupMode = 2 }
                                default     { throw "Unsupported service startup type '$startupType' for $key" }
                            }
                        }

                        # Microsoft INF format: "ServiceName",Mode,""
                        $settingLine = "`"$key`",$startupMode,`"`""
                    }
                    else {
                        # Standard format for other sections
                        # Values are used directly from JSON as they are already in correct MS INF format
                        # Examples:
                        #   ScRemoveOption: 1,"1" (REG_SZ with string "1")
                        #   RestrictRemoteSAM: 1,"O:BAG:BAD:(A;;RC;;;BA)" (REG_SZ with SDDL)
                        #   EnableInstallerDetection: 4,1 (REG_DWORD with value 1)

                        # Format: Key = Value
                        $settingLine = "$key = $value"
                    }

                    # A repeated identical setting is harmless; conflicting
                    # duplicates are ambiguous and must fail before secedit.
                    $settingIdentity = "$sectionName`0$key"
                    if ($settingLinesByIdentity.ContainsKey($settingIdentity) -and
                        [string]$settingLinesByIdentity[$settingIdentity] -cne $settingLine) {
                        throw "Conflicting duplicate security-template setting: [$sectionName] $key"
                    }
                    if (-not $settingLinesByIdentity.ContainsKey($settingIdentity)) {
                        $settingLinesByIdentity[$settingIdentity] = $settingLine
                        $sectionsProcessed[$sectionName] += $settingLine
                    }
                }
            }
        }

        # Write all sections in Microsoft INF required order
        # Order matters! secedit expects sections in specific sequence
        $sectionOrder = @(
            'System Access',
            'Registry Values',
            'Privilege Rights',
            'Service General Setting'
        )

        foreach ($sectionName in $sectionOrder) {
            if ($sectionsProcessed.ContainsKey($sectionName) -and $sectionsProcessed[$sectionName].Count -gt 0) {
                $infContent += "[$sectionName]"
                $infContent += $sectionsProcessed[$sectionName]
                $infContent += ""

                # Count what the generated INF WOULD apply. These are plans, not
                # results: they are copied into $result only after secedit has run
                # and the post-apply export verification has passed. Incrementing
                # $result here meant a run whose `secedit /configure` returned a
                # non-zero exit code still reported 67 settings applied, and
                # Invoke-SecurityBaseline rolled that into "Total Settings Applied:
                # 425" for a machine whose security template was never written.
                $plannedSections++
                $plannedSettings += $sectionsProcessed[$sectionName].Count
            }
        }

        Write-Log -Level DEBUG -Message "Generated security template: $plannedSections sections, $plannedSettings settings" -Module "SecurityBaseline"

        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Security template content:" -Module "SecurityBaseline"
            $infContent | ForEach-Object { Write-Log -Level DEBUG -Message "  $_" -Module "SecurityBaseline" }
            # Module preview convention (Set-RegistryPolicies/Set-AuditPolicies):
            # in DryRun, Applied carries the planned count; Invoke-SecurityBaseline
            # end{} folds it into SettingsPreviewed, re-zeroes SettingsApplied and
            # reconciles the sum against the canonical declared total. Returning
            # zero here made every DryRun fail that reconciliation (358 vs 425).
            $result.SectionsApplied = $plannedSections
            $result.SettingsApplied = $plannedSettings
            $result.Success = $true
            return $result
        }

        # Initialize temp file paths
        $tempInf = $null
        $dbFile = $null
        $logFile = $null
        $verificationInf = $null
        $verificationLog = $null

        try {
            # Save to temporary INF file
            $operationId = [Guid]::NewGuid().ToString('N')
            $tempInf = Join-Path $env:TEMP "SecurityBaseline_$operationId.inf"
            $infContent | Out-File -FilePath $tempInf -Encoding unicode -Force

            Write-Log -Level DEBUG -Message "Applying security template via secedit.exe..." -Module "SecurityBaseline"

            # Apply via secedit
            $dbFile = Join-Path $env:TEMP "secedit_$operationId.sdb"
            $logFile = Join-Path $env:TEMP "secedit_$operationId.log"

            $seceditArgs = @(
                "/configure",
                "/db", "`"$dbFile`"",
                "/cfg", "`"$tempInf`"",
                "/log", "`"$logFile`"",
                "/quiet"
            )

            $process = Start-Process -FilePath "secedit.exe" `
                                     -ArgumentList $seceditArgs `
                                     -Wait `
                                     -NoNewWindow `
                                     -PassThru `
                                     -ErrorAction Stop

            if ($process.ExitCode -eq 0) {
                $verificationInf = Join-Path $env:TEMP "SecurityBaseline_Verify_$operationId.inf"
                $verificationLog = Join-Path $env:TEMP "SecurityBaseline_Verify_$operationId.log"
                $verifyProcess = Start-Process -FilePath 'secedit.exe' `
                    -ArgumentList @('/export', '/cfg', "`"$verificationInf`"", '/log', "`"$verificationLog`"", '/quiet') `
                    -Wait -NoNewWindow -PassThru -ErrorAction Stop
                if ($verifyProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $verificationInf -PathType Leaf)) {
                    throw "secedit post-apply export failed with exit code $($verifyProcess.ExitCode)"
                }

                function Convert-SecurityInfToMap {
                    param([string]$Path)
                    $map = @{}
                    $section = ''
                    foreach ($line in Get-Content -LiteralPath $Path -ErrorAction Stop) {
                        $trimmed = $line.Trim()
                        if (-not $trimmed -or $trimmed.StartsWith(';')) { continue }
                        if ($trimmed -match '^\[(.+)\]$') {
                            $section = $Matches[1]
                            if (-not $map.ContainsKey($section)) { $map[$section] = @{} }
                            continue
                        }
                        if ($section -and $trimmed -match '^([^=]+?)\s*=\s*(.*)$') {
                            $map[$section][$Matches[1].Trim()] = $Matches[2].Trim()
                        }
                        elseif ($section -eq 'Service General Setting' -and
                            $trimmed -match '^"([^"]+)"\s*,\s*([0-9]+)\s*,') {
                            # This module owns only startup mode. The third INF
                            # field is a service security descriptor and the
                            # generated template deliberately leaves it empty.
                            $map[$section][$Matches[1]] = $Matches[2]
                        }
                    }
                    return $map
                }

                $expectedMap = Convert-SecurityInfToMap -Path $tempInf
                $actualMap = Convert-SecurityInfToMap -Path $verificationInf
                foreach ($section in @($sectionsProcessed.Keys | Where-Object { $sectionsProcessed[$_].Count -gt 0 })) {
                    if (-not $expectedMap.ContainsKey($section)) {
                        throw "Security-template verification is missing section [$section]"
                    }
                    if ($section -eq 'Service General Setting') {
                        # secedit applies service startup modes but does not
                        # reliably emit this section from a later /export.
                        # Verify the effective SCM state directly instead.
                        foreach ($name in $expectedMap[$section].Keys) {
                            $expectedStartType = switch ([string]$expectedMap[$section][$name]) {
                                '2' { 'Automatic' }
                                '3' { 'Manual' }
                                '4' { 'Disabled' }
                                default { throw "Unsupported expected service startup mode for $name" }
                            }
                            $serviceMatches = @(Get-Service -Name ([string]$name) -ErrorAction Stop)
                            if ($serviceMatches.Count -ne 1 -or
                                [string]$serviceMatches[0].StartType -cne $expectedStartType) {
                                throw "Security-template service verification mismatch: $name"
                            }
                        }
                        continue
                    }
                    if (-not $actualMap.ContainsKey($section)) {
                        throw "Security-template verification is missing section [$section]"
                    }
                    foreach ($name in $expectedMap[$section].Keys) {
                        if (-not $actualMap[$section].ContainsKey($name)) {
                            if ($section -eq 'Privilege Rights' -and
                                [string]::IsNullOrWhiteSpace([string]$expectedMap[$section][$name])) {
                                # An explicitly cleared right is commonly
                                # omitted from secedit export; both states mean
                                # that no principal holds the right.
                                continue
                            }
                            throw "Security-template verification is missing [$section] $name"
                        }
                        $expectedValue = [string]$expectedMap[$section][$name]
                        $actualValue = [string]$actualMap[$section][$name]
                        if ($section -eq 'Privilege Rights') {
                            $expectedValue = (@($expectedValue -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object) -join ',')
                            $actualValue = (@($actualValue -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object) -join ',')
                        }
                        if ($actualValue -cne $expectedValue) {
                            throw "Security-template verification mismatch: [$section] $name"
                        }
                    }
                }
                # secedit succeeded AND the post-apply export verification above
                # matched every selected name. Only now is "applied" true.
                $result.SectionsApplied = $plannedSections
                $result.SettingsApplied = $plannedSettings
                $result.Success = $true
                Write-Log -Level SUCCESS -Message "Security template applied and all $($result.SettingsApplied) selected settings verified" -Module 'SecurityBaseline'
            }
            else {
                $stderr = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
                $result.Errors += "secedit failed with exit code $($process.ExitCode): $stderr"
                Write-Log -Level DEBUG -Message "secedit failed: $stderr" -Module "SecurityBaseline"

            }
        }
        catch {
            $result.Errors += "Security template application failed: $($_.Exception.Message)"
            Write-Log -Level DEBUG -Message "Security template application failed: $_" -Module "SecurityBaseline"
        }
        finally {
            # ALWAYS cleanup temp files (even on error)
            if ($tempInf -and (Test-Path $tempInf)) {
                Remove-Item $tempInf -Force -ErrorAction SilentlyContinue
            }
            if ($dbFile -and (Test-Path $dbFile)) {
                Remove-Item $dbFile -Force -ErrorAction SilentlyContinue
            }
            if ($logFile -and (Test-Path $logFile)) {
                Remove-Item $logFile -Force -ErrorAction SilentlyContinue
            }
            if ($verificationInf -and (Test-Path $verificationInf)) {
                Remove-Item $verificationInf -Force -ErrorAction SilentlyContinue
            }
            if ($verificationLog -and (Test-Path $verificationLog)) {
                Remove-Item $verificationLog -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        # Outer catch for JSON parsing or INF generation errors
        $result.Errors += "Failed to process security template: $($_.Exception.Message)"
        Write-Log -Level DEBUG -Message "Security template processing error: $_" -Module "SecurityBaseline"
    }

    return $result
}
