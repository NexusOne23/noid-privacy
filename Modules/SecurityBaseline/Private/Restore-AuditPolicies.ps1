<#
.SYNOPSIS
    Restore exact module-owned Advanced Audit Policy subcategories.

.DESCRIPTION
    Validates the complete schema-v2 snapshot before mutation, restores each
    sealed GUID through the Windows auditpol command, and re-queries the exact
    native flags. Audit subcategories outside the snapshot remain untouched.
#>

function Restore-AuditPolicies {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $result = [PSCustomObject]@{ Success=$false; Restored=0; Verified=0; Errors=@() }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restore exact Advanced Audit Policy prestate')) {
        return $result
    }

    try {
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
            throw "Audit policy backup file not found: $BackupPath"
        }
        if (-not (Get-Command 'Get-AuditPolicyState' -ErrorAction SilentlyContinue)) {
            $nativeHelper = Join-Path $PSScriptRoot 'Get-AuditPolicyState.ps1'
            if (-not (Test-Path -LiteralPath $nativeHelper -PathType Leaf)) {
                throw "Audit policy native helper is missing: $nativeHelper"
            }
            . $nativeHelper
        }
        if (-not (Get-Command 'Get-AuditPolicyState' -ErrorAction SilentlyContinue)) {
            throw 'Get-AuditPolicyState is unavailable for exact audit restore'
        }
        $snapshot = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $policies = @($snapshot.Policies)
        if ([int]$snapshot.SchemaVersion -ne 2 -or
            [string]$snapshot.Target -cne 'SecurityBaselineAuditPolicies' -or
            [int]$snapshot.PolicyCount -ne $policies.Count -or
            $policies.Count -eq 0) {
            throw 'Audit policy backup has an invalid schema, target or count'
        }

        $validated = [System.Collections.Generic.List[object]]::new()
        $seen = [System.Collections.Generic.HashSet[Guid]]::new()
        foreach ($policy in $policies) {
            if (-not $policy.PSObject.Properties['SubcategoryGuid'] -or
                -not $policy.PSObject.Properties['AuditingInformation']) {
                throw 'Audit policy backup entry is incomplete'
            }
            $parsedGuid = [Guid]::Empty
            $flags = [uint32]$policy.AuditingInformation
            if (-not [Guid]::TryParseExact([string]$policy.SubcategoryGuid, 'D', [ref]$parsedGuid) -or
                [string]$policy.SubcategoryGuid -cne $parsedGuid.ToString('D').ToLowerInvariant() -or
                -not $seen.Add($parsedGuid) -or
                $flags -notin [uint32[]]@(1, 2, 3, 4)) {
                throw "Audit policy backup contains an invalid/duplicate entry: $($policy.SubcategoryGuid)"
            }
            $validated.Add([PSCustomObject]@{ Guid=$parsedGuid; Flags=$flags })
        }

        $operationId = [Guid]::NewGuid().ToString('N')
        $stdoutPath = Join-Path $env:TEMP "NoID_AuditRestore_$operationId.out"
        $stderrPath = Join-Path $env:TEMP "NoID_AuditRestore_$operationId.err"
        try {
            foreach ($policy in $validated) {
                $success = if (($policy.Flags -band 1) -ne 0) { 'enable' } else { 'disable' }
                $failure = if (($policy.Flags -band 2) -ne 0) { 'enable' } else { 'disable' }
                $arguments = @(
                    '/set'
                    "/subcategory:{$($policy.Guid.ToString('D'))}"
                    "/success:$success"
                    "/failure:$failure"
                )
                $process = Start-Process -FilePath 'auditpol.exe' -ArgumentList $arguments `
                    -Wait -NoNewWindow -PassThru -RedirectStandardOutput $stdoutPath `
                    -RedirectStandardError $stderrPath -ErrorAction Stop
                if ($process.ExitCode -ne 0) {
                    $detail = @(
                        if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw }
                        if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw }
                    ) -join ' '
                    throw "auditpol restore failed for $($policy.Guid) with exit code $($process.ExitCode): $($detail.Trim())"
                }
                $actual = [uint32](Get-AuditPolicyState -SubcategoryGuid $policy.Guid)
                if ($actual -ne [uint32]$policy.Flags) {
                    throw "Audit policy restore/readback failed for $($policy.Guid): expected $($policy.Flags), got $actual"
                }
                $result.Restored++
            }
        }
        finally {
            foreach ($tempPath in @($stdoutPath, $stderrPath)) {
                if (Test-Path -LiteralPath $tempPath) {
                    try {
                        Remove-Item -LiteralPath $tempPath -Force -ErrorAction Stop
                    }
                    catch {
                        Write-Log -Level WARNING -Message "Could not remove audit restore temp file '$tempPath': $($_.Exception.Message)" -Module 'SecurityBaseline'
                    }
                }
            }
        }
        foreach ($policy in $validated) {
            $actual = [uint32](Get-AuditPolicyState -SubcategoryGuid $policy.Guid)
            if ($actual -ne [uint32]$policy.Flags) {
                throw "Audit policy final verification failed for $($policy.Guid): expected $($policy.Flags), got $actual"
            }
            $result.Verified++
        }
        if ($result.Restored -ne $policies.Count -or $result.Verified -ne $policies.Count) {
            throw 'Audit policy restore count reconciliation failed'
        }
        $result.Success = $true
        Write-Log -Level SUCCESS -Message "Audit policies restored and verified exactly: $($result.Verified)" -Module 'SecurityBaseline'
    }
    catch {
        $result.Errors += "Audit policies restore failed: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message $result.Errors[-1] -Module 'SecurityBaseline'
    }
    return $result
}
