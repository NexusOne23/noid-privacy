#Requires -Version 5.1

function Get-PrivacyTargetPlan {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Applicability = (Get-PrivacyApplicability)
    )

    $declaredTargets = @(Get-PrivacyRegistryTargets -Config $Config)
    $applicableTargets = [System.Collections.Generic.List[object]]::new()
    $notCheckedTargets = [System.Collections.Generic.List[object]]::new()
    $notApplicableTargets = [System.Collections.Generic.List[object]]::new()
    foreach ($target in $declaredTargets) {
        $classification = Get-PrivacyTargetApplicability `
            -Path ([string]$target.Path) `
            -Name ([string]$target.Name) `
            -Applicability $Applicability
        if (-not $classification.Applicable) {
            $notApplicableTargets.Add([PSCustomObject]@{
                    Path = [string]$target.Path; Name = [string]$target.Name
                    ApplyType = [string]$target.Type; ApplyValue = $target.Value
                    Reason = [string]$classification.Reason
                })
        }
        elseif ($target.PSObject.Properties['Selected'] -and -not [bool]$target.Selected) {
            $notCheckedTargets.Add([PSCustomObject]@{
                    Path = [string]$target.Path; Name = [string]$target.Name
                    ApplyType = [string]$target.Type; ApplyValue = $target.Value
                    Reason = 'Tier 1 policy-based app removal was not selected'
                })
        }
        else {
            $applicableTargets.Add($target)
        }
    }
    if (($applicableTargets.Count + $notCheckedTargets.Count + $notApplicableTargets.Count) -ne $declaredTargets.Count) {
        throw 'Privacy target-plan reconciliation failed'
    }
    return [PSCustomObject]@{
        Applicability = $Applicability
        DeclaredCount = $declaredTargets.Count
        ApplicableTargets = @($applicableTargets)
        NotCheckedTargets = @($notCheckedTargets)
        NotApplicableTargets = @($notApplicableTargets)
    }
}
