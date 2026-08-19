<#
.SYNOPSIS
    Backup current security template settings

.DESCRIPTION
    Uses secedit.exe to read current security settings, then writes a filtered
    INF containing only the System Access and Privilege Rights targets owned by
    this module. Registry Values use the separate exact typed prestate, and
    service startup/runtime state uses sealed service artifacts. This prevents
    restore from replaying unrelated security policy that changed after Apply.

.PARAMETER BackupPath
    Path where backup INF will be saved

.OUTPUTS
    PSCustomObject with backup status

.NOTES
    Uses secedit.exe /export command
#>

function Backup-SecurityTemplate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [Parameter(Mandatory = $true)]
        [string]$SecurityTemplatePath
    )

    $result = [PSCustomObject]@{
        Success = $false
        BackupPath = $BackupPath
        Errors = @()
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Backup SecurityTemplate')) {
        $result.Errors += 'Operation was not confirmed'
        return $result
    }

    # Initialize temp file paths
    $logFile = $null

    try {
        Write-Log -Level DEBUG -Message "Backing up security template via secedit.exe..." -Module "SecurityBaseline"

        # Create temp paths
        $operationId = [Guid]::NewGuid().ToString('N')
        $logFile = Join-Path $env:TEMP "secedit_backup_$operationId.log"

        # Export current settings
        $seceditArgs = @(
            "/export",
            "/cfg", "`"$BackupPath`"",
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
            if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
                throw 'secedit reported success but did not create the security-template backup'
            }
            $exportContent = Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop
            $requiredSections = @('System Access', 'Privilege Rights')
            foreach ($requiredSection in $requiredSections) {
                if ($exportContent -notmatch "(?m)^\[$([regex]::Escape($requiredSection))\]\s*$") {
                    throw "secedit export is missing required section [$requiredSection]"
                }
            }

            $sourceMap = @{}
            $currentSection = ''
            foreach ($line in Get-Content -LiteralPath $BackupPath -ErrorAction Stop) {
                $trimmed = $line.Trim()
                if (-not $trimmed -or $trimmed.StartsWith(';')) { continue }
                if ($trimmed -match '^\[(.+)\]$') {
                    $currentSection = $Matches[1]
                    if (-not $sourceMap.ContainsKey($currentSection)) { $sourceMap[$currentSection] = @{} }
                    continue
                }
                if ($currentSection -and $trimmed -match '^([^=]+?)\s*=\s*(.*)$') {
                    $name = $Matches[1].Trim()
                    $value = $Matches[2].Trim()
                    if ($sourceMap[$currentSection].ContainsKey($name) -and
                        [string]$sourceMap[$currentSection][$name] -cne $value) {
                        throw "secedit export contains conflicting duplicate [$currentSection] $name"
                    }
                    $sourceMap[$currentSection][$name] = $value
                }
            }

            $templates = Get-Content -LiteralPath $SecurityTemplatePath -Raw -Encoding UTF8 -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop
            $managedNames = @{
                'System Access'    = [System.Collections.Generic.List[string]]::new()
                'Privilege Rights' = [System.Collections.Generic.List[string]]::new()
            }
            $seenManaged = @{
                'System Access'    = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                'Privilege Rights' = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            }
            foreach ($gpoProperty in $templates.PSObject.Properties) {
                foreach ($sectionName in $managedNames.Keys) {
                    $sectionProperty = $gpoProperty.Value.PSObject.Properties[$sectionName]
                    if ($null -eq $sectionProperty) { continue }
                    $section = $sectionProperty.Value
                    foreach ($name in $section.PSObject.Properties.Name) {
                        if ($seenManaged[$sectionName].Add([string]$name)) {
                            $managedNames[$sectionName].Add([string]$name)
                        }
                    }
                }
            }
            if ($managedNames['System Access'].Count -eq 0 -or $managedNames['Privilege Rights'].Count -eq 0) {
                throw 'Security-template target inventory has no System Access or Privilege Rights settings'
            }

            $filteredLines = [System.Collections.Generic.List[string]]::new()
            foreach ($line in @('[Unicode]', 'Unicode=yes', '', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '')) {
                $filteredLines.Add($line)
            }
            foreach ($sectionName in @('System Access', 'Privilege Rights')) {
                $filteredLines.Add("[$sectionName]")
                foreach ($name in $managedNames[$sectionName]) {
                    if ($sourceMap[$sectionName].ContainsKey($name)) {
                        $filteredLines.Add("$name = $($sourceMap[$sectionName][$name])")
                    }
                    elseif ($sectionName -eq 'Privilege Rights') {
                        # secedit omits an unassigned right; an explicit empty
                        # assignment is required to remove a later assignment.
                        $filteredLines.Add("$name =")
                    }
                    else {
                        throw "secedit export is missing managed [$sectionName] $name"
                    }
                }
                $filteredLines.Add('')
            }
            Set-Content -LiteralPath $BackupPath -Value $filteredLines -Encoding Unicode -Force -ErrorAction Stop

            $filteredContent = Get-Content -LiteralPath $BackupPath -Raw -ErrorAction Stop
            foreach ($sectionName in @('System Access', 'Privilege Rights')) {
                if ($filteredContent -notmatch "(?m)^\[$([regex]::Escape($sectionName))\]\s*$") {
                    throw "Filtered security-template backup is missing [$sectionName]"
                }
            }
            $filteredMap = @{}
            $filteredSection = ''
            foreach ($line in Get-Content -LiteralPath $BackupPath -ErrorAction Stop) {
                $trimmed = $line.Trim()
                if (-not $trimmed -or $trimmed.StartsWith(';')) { continue }
                if ($trimmed -match '^\[(.+)\]$') {
                    $filteredSection = $Matches[1]
                    if (-not $filteredMap.ContainsKey($filteredSection)) { $filteredMap[$filteredSection] = @{} }
                    continue
                }
                if ($filteredSection -and $trimmed -match '^([^=]+?)\s*=\s*(.*)$') {
                    $filteredMap[$filteredSection][$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
            foreach ($sectionName in @('System Access', 'Privilege Rights')) {
                if ($filteredMap[$sectionName].Count -ne $managedNames[$sectionName].Count) {
                    throw "Filtered [$sectionName] target count mismatch"
                }
                foreach ($name in $managedNames[$sectionName]) {
                    $expectedValue = if ($sourceMap[$sectionName].ContainsKey($name)) {
                        [string]$sourceMap[$sectionName][$name]
                    }
                    else { '' }
                    if (-not $filteredMap[$sectionName].ContainsKey($name) -or
                        [string]$filteredMap[$sectionName][$name] -cne $expectedValue) {
                        throw "Filtered security-template backup round-trip mismatch: [$sectionName] $name"
                    }
                }
            }
            $result.Success = $true
            Write-Log -Level DEBUG -Message "Filtered owned security-template backup saved to: $BackupPath" -Module "SecurityBaseline"
        }
        else {
            $logContent = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
            $result.Errors += "secedit export failed with exit code $($process.ExitCode): $logContent"
            Write-Error "secedit export failed: $logContent"
        }
    }
    catch {
        $result.Errors += "Security template backup failed: $_"
        Write-Error "Security template backup failed: $_"
    }
    finally {
        # ALWAYS cleanup temp files (even on error)
        if ($logFile -and (Test-Path $logFile)) {
            Remove-Item $logFile -Force -ErrorAction SilentlyContinue
        }
    }

    return $result
}
