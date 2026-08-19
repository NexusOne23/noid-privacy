#Requires -Version 5.1

function Set-EdgePolicies {
    <#
    .SYNOPSIS
        Apply and immediately read back the selected Edge policy profile.

    .DESCRIPTION
        Uses the same canonical target inventory as Backup and Verify. GPO
        metadata is never counted as a policy, and the optional extension
        block is absent from the selected inventory when extensions are allowed.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$EdgePoliciesPath,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun,

        [Parameter(Mandatory = $false)]
        [switch]$AllowExtensions,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$RuntimeApplicability,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$EdgeInstallationStatus,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Snapshot
    )

    $result = [PSCustomObject]@{
        Success  = $false
        Selected = 0
        Applied  = 0
        Previewed = 0
        Skipped  = 0
        NotApplicable = 0
        Errors   = [System.Collections.Generic.List[string]]::new()
    }

    try {
        if ($Snapshot) {
            $null = Assert-EdgePolicySnapshot -Snapshot $Snapshot
            if ([int]$Snapshot.SchemaVersion -ne 6) {
                throw 'Edge Apply requires a schema-6 sealed plan'
            }
            $targets = @($Snapshot.Entries | ForEach-Object {
                    [PSCustomObject]@{
                        Path = [string]$_.Path
                        Name = [string]$_.Name
                        Type = [string]$_.ApplyType
                        Value = $_.ApplyValue
                    }
                })
            $result.NotApplicable = [int]$Snapshot.NotApplicableCount
        }
        else {
            if (-not $RuntimeApplicability) {
                throw 'Edge DryRun planning requires explicit runtime applicability'
            }
            if (-not $EdgeInstallationStatus) {
                throw 'Edge DryRun planning requires explicit installation status'
            }
            $targetPlan = @(Get-EdgePolicyTargets -EdgePoliciesPath $EdgePoliciesPath `
                    -AllowExtensions:$AllowExtensions -RuntimeApplicability $RuntimeApplicability `
                    -EdgeInstallationStatus $EdgeInstallationStatus)
            $result.NotApplicable = @($targetPlan | Where-Object { -not [bool]$_.Applicable }).Count
            $targets = @($targetPlan | Where-Object { [bool]$_.Applicable })
        }
        $result.Selected = $targets.Count
        if ($targets.Count -eq 0) { throw 'Canonical Edge target inventory is empty' }

        Write-Host "    Applying $($targets.Count) selected Edge policy values..." -ForegroundColor Cyan
        if ($AllowExtensions) {
            Write-Host '    Profile: extension blocklist is not selected; existing administrator policy is preserved' -ForegroundColor Yellow
        }

        foreach ($target in $targets) {
            $identity = "$($target.Path)::$($target.Name)"
            if ($DryRun) {
                Write-Log -Level DEBUG -Message "[DRYRUN] Would set $identity = $($target.Value) ($($target.Type))" -Module 'EdgeHardening'
                $result.Previewed++
                continue
            }
            if (-not $PSCmdlet.ShouldProcess($identity, 'Set and verify Edge policy value')) {
                $result.Skipped++
                continue
            }

            try {
                if (-not (Test-Path -LiteralPath $target.Path -PathType Container -ErrorAction Stop)) {
                    New-Item -Path $target.Path -Force -ErrorAction Stop | Out-Null
                }
                New-ItemProperty -LiteralPath $target.Path -Name ([string]$target.Name) `
                    -PropertyType ([string]$target.Type) -Value $target.Value `
                    -Force -ErrorAction Stop | Out-Null

                $registryKey = Get-Item -LiteralPath $target.Path -ErrorAction Stop
                $actualType = $registryKey.GetValueKind([string]$target.Name).ToString()
                $actualValue = $registryKey.GetValue(
                    [string]$target.Name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
                $expectedJson = ConvertTo-Json -InputObject @($target.Value) -Compress -Depth 20
                $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
                if ($actualType -cne [string]$target.Type -or $actualJson -cne $expectedJson) {
                    throw "post-write mismatch (expected $($target.Type)/$expectedJson, got $actualType/$actualJson)"
                }
                $result.Applied++
            }
            catch {
                $message = "Failed to apply ${identity}: $($_.Exception.Message)"
                $result.Errors.Add($message)
                Write-Log -Level ERROR -Message $message -Module 'EdgeHardening'
            }
        }

        $completedCount = if ($DryRun) { $result.Previewed } else { $result.Applied }
        $result.Success = ($result.Errors.Count -eq 0 -and $result.Skipped -eq 0 -and
            $completedCount -eq $result.Selected)
        if ($result.Success) {
            Write-Log -Level $(if ($DryRun) { 'INFO' } else { 'SUCCESS' }) -Message $(if ($DryRun) {
                    "Previewed all $($result.Previewed) selected Edge values"
                }
                else {
                    "Applied and read back all $($result.Applied) selected Edge values"
                }) -Module 'EdgeHardening'
        }
    }
    catch {
        $result.Errors.Add("Edge policy application failed: $($_.Exception.Message)")
        Write-Log -Level ERROR -Message $result.Errors[$result.Errors.Count - 1] -Module 'EdgeHardening'
    }

    return $result
}
