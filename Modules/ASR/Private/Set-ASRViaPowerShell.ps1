<#
.SYNOPSIS
    Apply and verify declared ASR rules through target-scoped Defender policy
    values without modifying local or unrelated Defender ASR configuration.
#>
function Set-ASRViaPowerShell {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [Array]$Rules,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors  = @()
        Warnings = @()
    }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Apply target-scoped ASR policy rules')) {
        $result.Errors += 'Operation was not confirmed'
        return $result
    }

    try {
        if ($Rules.Count -eq 0) { throw 'No ASR rules were supplied' }
        $declaredRules = @{}
        foreach ($rule in $Rules) {
            $parsedGuid = [Guid]::Empty
            if ([string]::IsNullOrWhiteSpace([string]$rule.Name) -or
                -not [Guid]::TryParse([string]$rule.GUID, [ref]$parsedGuid) -or
                [int]$rule.Action -notin @(0, 1, 2, 6)) {
                throw "Invalid ASR rule definition: $($rule.GUID)"
            }
            $id = $parsedGuid.ToString('D').ToLowerInvariant()
            if ($declaredRules.ContainsKey($id)) { throw "Duplicate ASR rule definition: $id" }
            $declaredRules[$id] = [PSCustomObject]@{
                Id = $id; Action = [int]$rule.Action; Definition = $rule
            }
        }

        if ($DryRun) {
            Write-Log -Level INFO -Message "[DRYRUN] Would apply $($declaredRules.Count) target-scoped ASR policy rules" -Module 'ASR'
            $result.Applied = $declaredRules.Count
            $result.Success = $true
            return $result
        }

        $before = ConvertFrom-ASRPreference -Preference (Get-MpPreference -ErrorAction Stop)
        $expected = @{}
        foreach ($entry in $before.Map.GetEnumerator()) {
            $expected[[string]$entry.Key] = [int]$entry.Value
        }
        foreach ($declared in $declaredRules.Values) {
            $expected[[string]$declared.Id] = [int]$declared.Action
        }

        # Use the native device-policy surface for every declared ASR target.
        # Writing a merged effective Get-MpPreference view back through
        # Set-MpPreference materializes policy-derived rules as local rules and
        # makes a later multi-module restore non-exact. Target-scoped policy
        # writes preserve all local and unrelated Defender rules untouched.
        $rulesPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        if (-not (Test-Path -LiteralPath $rulesPath -PathType Container)) {
            New-Item -Path $rulesPath -Force -ErrorAction Stop | Out-Null
        }
        foreach ($declared in @($declaredRules.Values | Sort-Object Id)) {
            $name = [string]$declared.Id
            $data = ([int]$declared.Action).ToString([Globalization.CultureInfo]::InvariantCulture)
            $rulesKey = Get-Item -LiteralPath $rulesPath -ErrorAction Stop
            $matchingNames = @($rulesKey.GetValueNames() | Where-Object {
                    ([string]$_).Equals($name, [StringComparison]::OrdinalIgnoreCase)
                })
            if ($matchingNames.Count -gt 1) {
                throw "ASR policy value-name identity is ambiguous: $name"
            }
            $writeName = if ($matchingNames.Count -eq 1) { [string]$matchingNames[0] } else { $name }
            New-ItemProperty -LiteralPath $rulesPath -Name $writeName -PropertyType String `
                -Value $data -Force -ErrorAction Stop | Out-Null

            $rulesKey = Get-Item -LiteralPath $rulesPath -ErrorAction Stop
            $actualData = [string]$rulesKey.GetValue($writeName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $actualType = $rulesKey.GetValueKind($writeName).ToString()
            if ($actualType -ne 'String' -or $actualData -cne $data) {
                throw "ASR policy registry verification failed: $name"
            }
        }

        $after = ConvertFrom-ASRPreference -Preference (Get-MpPreference -ErrorAction Stop)
        if ($after.Count -ne $expected.Count) {
            throw "ASR post-apply count mismatch: expected $($expected.Count), got $($after.Count)"
        }
        foreach ($entry in $expected.GetEnumerator()) {
            $id = [string]$entry.Key
            if (-not $after.Map.ContainsKey($id) -or
                [int]$after.Map[$id] -ne [int]$entry.Value) {
                throw "ASR post-apply state mismatch: $id"
            }
        }

        $result.Applied = $declaredRules.Count
        $result.Success = $true
        Write-Log -Level SUCCESS -Message "Applied and verified $($declaredRules.Count) target-scoped ASR policy rules while preserving local and unrelated Defender state" -Module 'ASR'
    }
    catch {
        $result.Errors += "Failed to apply ASR rules: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message $result.Errors[-1] -Module 'ASR'
    }
    return $result
}
