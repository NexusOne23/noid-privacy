<#
.SYNOPSIS
    Back up the exact module-owned Advanced Audit Policy subcategories.

.DESCRIPTION
    Queries only the GUIDs declared in AuditPolicies.json through the native
    AuditQuerySystemPolicy API. Unrelated audit subcategories are not captured
    or replayed, so Restore cannot overwrite policy changed after Apply.
#>

function Backup-AuditPolicies {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [Parameter(Mandatory = $true)]
        [string]$AuditPoliciesPath
    )

    $result = [PSCustomObject]@{ Success=$false; BackupPath=$BackupPath; Count=0; Errors=@() }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Back up exact Advanced Audit Policy prestate')) {
        return $result
    }

    try {
        if (-not (Test-Path -LiteralPath $AuditPoliciesPath -PathType Leaf)) {
            throw "Audit policy target file not found: $AuditPoliciesPath"
        }
        if (-not (Get-Command 'Get-AuditPolicyState' -ErrorAction SilentlyContinue)) {
            $nativeHelper = Join-Path $PSScriptRoot 'Get-AuditPolicyState.ps1'
            if (-not (Test-Path -LiteralPath $nativeHelper -PathType Leaf)) {
                throw "Audit policy native helper is missing: $nativeHelper"
            }
            . $nativeHelper
        }
        $definitions = Get-Content -LiteralPath $AuditPoliciesPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ($definitions.Count -eq 0) { throw 'Audit policy target set is empty' }

        $seen = [System.Collections.Generic.HashSet[Guid]]::new()
        $states = [System.Collections.Generic.List[object]]::new()
        foreach ($definition in $definitions) {
            $parsedGuid = [Guid]::Empty
            if (-not [Guid]::TryParse([string]$definition.SubcategoryGUID, [ref]$parsedGuid) -or
                -not $seen.Add($parsedGuid)) {
                throw "Audit policy target contains an invalid or duplicate GUID: $($definition.SubcategoryGUID)"
            }
            $flags = [uint32](Get-AuditPolicyState -SubcategoryGuid $parsedGuid)
            if ($flags -notin [uint32[]]@(1, 2, 3, 4)) {
                throw "Audit policy $parsedGuid returned unsupported flags 0x$($flags.ToString('X8'))"
            }
            $states.Add([PSCustomObject]@{
                    SubcategoryGuid = $parsedGuid.ToString('D').ToLowerInvariant()
                    AuditingInformation = $flags
                })
        }

        $snapshot = [PSCustomObject]@{
            SchemaVersion = 2
            Target = 'SecurityBaselineAuditPolicies'
            CapturedAt = (Get-Date).ToUniversalTime().ToString('o')
            PolicyCount = $states.Count
            Policies = @($states)
        }
        $json = $snapshot | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($BackupPath, $json, [System.Text.UTF8Encoding]::new($false))

        $roundTrip = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ([int]$roundTrip.SchemaVersion -ne 2 -or
            [string]$roundTrip.Target -cne 'SecurityBaselineAuditPolicies' -or
            [int]$roundTrip.PolicyCount -ne $states.Count -or
            @($roundTrip.Policies).Count -ne $states.Count) {
            throw 'Audit-policy backup failed round-trip schema/count validation'
        }
        $roundTripJson = @($roundTrip.Policies) | ConvertTo-Json -Compress -Depth 10
        $stateJson = @($states) | ConvertTo-Json -Compress -Depth 10
        if ($roundTripJson -cne $stateJson) {
            throw 'Audit-policy backup failed round-trip content validation'
        }

        $result.Success = $true
        $result.Count = $states.Count
        Write-Log -Level DEBUG -Message "Exact audit-policy prestate saved: $($states.Count) subcategories" -Module 'SecurityBaseline'
    }
    catch {
        $result.Errors += "Audit policies backup failed: $($_.Exception.Message)"
        Write-Log -Level ERROR -Message $result.Errors[-1] -Module 'SecurityBaseline'
    }
    return $result
}
