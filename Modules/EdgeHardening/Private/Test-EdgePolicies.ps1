#Requires -Version 5.1

function Test-EdgePolicies {
    <#
    .SYNOPSIS
        Verify exact registry type and data for every selected Edge target.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$EdgePoliciesPath,

        [Parameter(Mandatory = $false)]
        [switch]$AllowExtensions,

        # The public intent-free wrapper measures this one optional target as
        # live state rather than asserting that block-all was selected.
        [Parameter(Mandatory = $false)]
        [switch]$ObserveExtensionWithoutIntent,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$RuntimeApplicability,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$EdgeInstallationStatus,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Snapshot
    )

    $details = [System.Collections.Generic.List[object]]::new()
    try {
        if ($Snapshot) {
            $null = Assert-EdgePolicySnapshot -Snapshot $Snapshot
            if ([int]$Snapshot.SchemaVersion -ne 6) {
                throw 'Edge verification requires a schema-6 sealed plan'
            }
            $declaredCount = [int]$Snapshot.DeclaredTargetCount
            $notApplicableCount = [int]$Snapshot.NotApplicableCount
            $targets = @($Snapshot.Entries | ForEach-Object {
                    [PSCustomObject]@{
                        Path = [string]$_.Path
                        Name = [string]$_.Name
                        Type = [string]$_.ApplyType
                        Value = $_.ApplyValue
                        Origin = 'SealedPlan'
                        MinimumEdgeMajor = $null
                    }
                })
            foreach ($item in @($Snapshot.NotApplicable)) {
                $details.Add([PSCustomObject]@{
                        Policy = [string]$item.Name; Path = [string]$item.Path
                        Origin = 'SealedPlan'; MinimumVersion = $null
                        ExpectedType = $null; Expected = $null
                        ActualType = $null; Actual = $null
                        Status = 'NotApplicable'; Error = [string]$item.Reason
                        Compliant = $false; Optional = $false
                    })
            }
        }
        else {
            if (-not $RuntimeApplicability) { $RuntimeApplicability = Get-EdgeRuntimeApplicability }
            if (-not $EdgeInstallationStatus) { $EdgeInstallationStatus = Get-EdgeInstallationStatus }
            $targetPlan = @(Get-EdgePolicyTargets -EdgePoliciesPath $EdgePoliciesPath `
                    -AllowExtensions:$AllowExtensions -RuntimeApplicability $RuntimeApplicability `
                    -EdgeInstallationStatus $EdgeInstallationStatus)
            $declaredCount = $targetPlan.Count
            $notApplicable = @($targetPlan | Where-Object { -not [bool]$_.Applicable })
            $notApplicableCount = $notApplicable.Count
            $targets = @($targetPlan | Where-Object { [bool]$_.Applicable })
            foreach ($item in $notApplicable) {
                $details.Add([PSCustomObject]@{
                        Policy = [string]$item.Name; Path = [string]$item.Path
                        Origin = [string]$item.Origin; MinimumVersion = [int]$item.MinimumEdgeMajor
                        ExpectedType = $null; Expected = $null
                        ActualType = $null; Actual = $null
                        Status = 'NotApplicable'; Error = [string]$item.NotApplicableReason
                        Compliant = $false; Optional = $false
                    })
            }
        }
        if ($targets.Count -eq 0) { throw 'Canonical Edge target inventory is empty' }

        foreach ($target in $targets) {
            $actualValue = $null
            $actualType = $null
            $status = 'Missing'
            $compliant = $false
            $errorText = $null
            try {
                if (-not (Test-Path -LiteralPath $target.Path -PathType Container -ErrorAction Stop)) {
                    throw 'Registry key does not exist'
                }
                $key = Get-Item -LiteralPath $target.Path -ErrorAction Stop
                if ($key.GetValueNames() -notcontains [string]$target.Name) {
                    throw 'Registry value does not exist'
                }
                $actualType = $key.GetValueKind([string]$target.Name).ToString()
                $actualValue = $key.GetValue(
                    [string]$target.Name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                $expectedJson = ConvertTo-Json -InputObject @($target.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
                $compliant = ($actualType -ceq [string]$target.Type -and $actualJson -ceq $expectedJson)
                $status = if ($compliant) { 'Compliant' } else { 'WrongTypeOrValue' }
            }
            catch {
                $errorText = $_.Exception.Message
                $status = 'ReadFailedOrMissing'
            }

            $optionalObservation = $ObserveExtensionWithoutIntent -and
                [string]$target.Path -ieq 'HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist' -and
                [string]$target.Name -eq '1'
            if (-not $compliant -and -not $optionalObservation) {
                Write-Log -Level WARNING -Message "Edge check failed: $($target.Path)::$($target.Name) ($status; $errorText)" -Module 'EdgeHardening'
            }
            elseif ($optionalObservation) {
                Write-Log -Level DEBUG -Message "Observed Edge extension block-all live state without a profile intent: $status" -Module 'EdgeHardening'
            }
            $details.Add([PSCustomObject]@{
                    Policy         = [string]$target.Name
                    Path           = [string]$target.Path
                    Origin         = [string]$target.Origin
                    MinimumVersion = [int]$target.MinimumEdgeMajor
                    ExpectedType   = [string]$target.Type
                    Expected       = $target.Value
                    ActualType     = $actualType
                    Actual         = $actualValue
                    Status         = $status
                    Error          = $errorText
                    Compliant      = $compliant
                    Optional       = $optionalObservation
                })
        }

        $compliantCount = @($details | Where-Object { $_.Status -eq 'Compliant' }).Count
        $failedCount = @($details | Where-Object { $_.Status -notin @('Compliant', 'NotApplicable') }).Count
        $percentage = [math]::Round(($compliantCount / $targets.Count) * 100, 1)
        return [PSCustomObject]@{
            Compliant             = ($failedCount -eq 0 -and $compliantCount -eq $targets.Count -and
                $compliantCount + $notApplicableCount -eq $declaredCount)
            Message               = "Edge owned state: $compliantCount/$($targets.Count) applicable selected values exact; NotApplicable=$notApplicableCount ($percentage%)"
            SelectedCount         = $declaredCount
            ApplicableCount       = $targets.Count
            NotApplicableCount    = $notApplicableCount
            CompliantCount        = $compliantCount
            NonCompliantCount     = $failedCount
            SkippedCount          = 0
            CompliancePercentage  = $percentage
            RuntimePolicyVerified = $null
            Details               = @($details)
        }
    }
    catch {
        return [PSCustomObject]@{
            Compliant             = $false
            Message               = "Edge policy verification failed: $($_.Exception.Message)"
            SelectedCount         = 0
            ApplicableCount       = 0
            NotApplicableCount    = 0
            CompliantCount        = 0
            NonCompliantCount     = 1
            SkippedCount          = 0
            CompliancePercentage  = 0
            RuntimePolicyVerified = $null
            Details               = @($details)
        }
    }
}
