#Requires -Version 5.1

function Backup-ASRRegistry {
    <#
    .SYNOPSIS
        Capture exact target-scoped Defender and policy prestates plus the
        decision-bound Windows-client ASR plan.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [Array]$Rules,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Array]$NotApplicableRules
    )

    $result = [PSCustomObject]@{ Success=$false; BackupPath=$null; Errors=@() }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Back up decision-bound ASR target state')) {
        $result.Errors += 'ASR backup was not confirmed'
        return $result
    }

    try {
        if ($Rules.Count -eq 0) { throw 'ASR backup received no applicable rules' }
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        $policyKeyExisted = Test-Path -LiteralPath $policyPath -PathType Container -ErrorAction Stop
        $policyKey = if ($policyKeyExisted) { Get-Item -LiteralPath $policyPath -ErrorAction Stop } else { $null }
        $policyValueNames = if ($policyKeyExisted) { @($policyKey.GetValueNames()) } else { @() }
        $absentAncestorKeys = [System.Collections.Generic.List[string]]::new()
        $policyBoundary = 'HKLM:\SOFTWARE\Policies'
        $ancestorCursor = $policyPath.Substring(0, $policyPath.LastIndexOf('\'))
        while ($ancestorCursor.Length -gt $policyBoundary.Length) {
            if (Test-Path -LiteralPath $ancestorCursor -PathType Container -ErrorAction Stop) { break }
            $absentAncestorKeys.Add($ancestorCursor)
            $ancestorCursor = $ancestorCursor.Substring(0, $ancestorCursor.LastIndexOf('\'))
        }

        $preference = Get-MpPreference -ErrorAction Stop
        $current = (ConvertFrom-ASRPreference -Preference $preference).Map

        $targets = @()
        $seenTargets = [System.Collections.Generic.HashSet[Guid]]::new()
        foreach ($rule in $Rules) {
            $parsed = [Guid]::Empty
            if (-not [Guid]::TryParseExact([string]$rule.GUID, 'D', [ref]$parsed) -or
                -not $seenTargets.Add($parsed) -or
                [int]$rule.Action -notin @(0, 1, 2, 6)) {
                throw "ASR backup received an invalid or duplicate target: $($rule.GUID)"
            }
            $id = $parsed.ToString('D').ToLowerInvariant()
            $originalExists = $current.ContainsKey($id)
            $nameMatches = @($policyValueNames | Where-Object {
                    ([string]$_).Equals($id, [StringComparison]::OrdinalIgnoreCase)
                })
            if ($nameMatches.Count -gt 1) {
                throw "ASR policy value-name identity is ambiguous: $id"
            }
            $policyExists = $nameMatches.Count -eq 1
            $policyType = $null
            $policyData = $null
            $policyOriginalName = if ($policyExists) { [string]$nameMatches[0] } else { $null }
            if ($policyExists) {
                $policyType = $policyKey.GetValueKind($policyOriginalName).ToString()
                $policyData = $policyKey.GetValue(
                    $policyOriginalName, $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                if ($policyType -eq 'Binary') { $policyData = [byte[]]@($policyData) }
                elseif ($policyType -eq 'MultiString') { $policyData = [string[]]@($policyData) }
            }
            $policyValue = [PSCustomObject]@{
                Exists = [bool]$policyExists
                OriginalName = $policyOriginalName
                Type   = $policyType
                Value  = $policyData
            }

            $targets += [PSCustomObject]@{
                Name            = [string]$rule.Name
                GUID            = $id
                RequestedAction = [int]$rule.Action
                OriginalExists  = [bool]$originalExists
                OriginalAction  = if ($originalExists) { [int]$current[$id] } else { $null }
                PolicyOverride  = $true
                PolicyValue     = $policyValue
                BaselineStatus  = [string]$rule.BaselineStatus
                UserConfigurable = [bool]$rule.UserConfigurable
            }
        }

        $notApplicable = @($NotApplicableRules | ForEach-Object {
                [PSCustomObject]@{
                    Name   = [string]$_.Name
                    GUID   = ([Guid]([string]$_.GUID)).ToString('D').ToLowerInvariant()
                    Reason = [string]$_.Reason
                }
            })
        $snapshot = [PSCustomObject]@{
            SchemaVersion      = 5
            Target             = 'WindowsClientDefenderASR'
            BackupDate         = (Get-Date).ToString('o')
            PolicyPath         = $policyPath
            PolicyKeyExisted   = [bool]$policyKeyExisted
            AbsentAncestorKeys = @($absentAncestorKeys)
            DeclaredCount      = [int]($targets.Count + $notApplicable.Count)
            TargetCount        = [int]$targets.Count
            NotApplicableCount = [int]$notApplicable.Count
            Targets            = @($targets)
            NotApplicable      = @($notApplicable)
        }
        $null = Assert-ASRSnapshot -Snapshot $snapshot

        $json = $snapshot | ConvertTo-Json -Depth 20
        $backupFile = Register-Backup -Type 'ASR' -Data $json -Name 'ASR_ActiveConfiguration'
        if ([string]::IsNullOrWhiteSpace([string]$backupFile)) {
            throw 'ASR prestate artifact registration returned no path'
        }
        $registered = @($global:BackupIndex | Where-Object {
                [string]$_.Module -eq 'ASR' -and [string]$_.Type -eq 'ASR' -and
                [string]$_.Name -eq 'ASR_ActiveConfiguration'
            })
        if ($registered.Count -ne 1) {
            throw "ASR prestate registration is ambiguous: $($registered.Count) artifacts"
        }
        $registered[0] | Add-Member -NotePropertyName Path -NotePropertyValue 'DefenderASR' -Force
        $roundTrip = Get-Content -LiteralPath $backupFile -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $null = Assert-ASRSnapshot -Snapshot $roundTrip

        $result.Success = $true
        $result.BackupPath = $backupFile
        Write-Log -Level SUCCESS -Message "ASR target prestate sealed for $($targets.Count) applicable and $($notApplicable.Count) NotApplicable rule(s)" -Module 'ASR'
    }
    catch {
        $result.Errors += "ASR backup failed: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message $result.Errors[-1] -Module 'ASR'
    }
    return $result
}
