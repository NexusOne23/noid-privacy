#Requires -Version 5.1

function Get-PrivacyRuntimeTargetPlan {
    <#
    .SYNOPSIS
        Classifies the complete registry, service, and scheduled-task scope for
        one Privacy decision before backup, preview, or mutation.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config
    )

    if ([string]$Config.Mode -notin @('MSRecommended', 'Strict', 'Paranoid')) {
        throw "Privacy configuration has an invalid mode: '$($Config.Mode)'"
    }

    $registryPlan = Get-PrivacyTargetPlan -Config $Config
    $declaredServiceNames = @($Config.Services | ForEach-Object { [string]$_.Name })
    if (@($declaredServiceNames | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0 -or
        @($declaredServiceNames | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        throw 'Privacy configuration contains an empty or duplicate service identity'
    }

    $applicableServiceNames = [System.Collections.Generic.List[string]]::new()
    $installedServices = if ($declaredServiceNames.Count -gt 0) { @(Get-Service -ErrorAction Stop) } else { @() }
    foreach ($serviceName in $declaredServiceNames) {
        $serviceMatches = @($installedServices | Where-Object { [string]$_.Name -eq $serviceName })
        if ($serviceMatches.Count -gt 1) { throw "Privacy service identity is ambiguous: $serviceName" }
        if ($serviceMatches.Count -eq 1) { $applicableServiceNames.Add($serviceName) }
    }

    $declaredTaskPaths = @($Config.ScheduledTasks | ForEach-Object { [string]$_ })
    if (@($declaredTaskPaths | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -notmatch '^\\[^\\].+' }).Count -gt 0 -or
        @($declaredTaskPaths | Group-Object | Where-Object Count -gt 1).Count -gt 0) {
        throw 'Privacy configuration contains an invalid or duplicate scheduled-task identity'
    }

    $applicableTaskPaths = [System.Collections.Generic.List[string]]::new()
    $installedTasks = if ($declaredTaskPaths.Count -gt 0) { @(Get-ScheduledTask -ErrorAction Stop) } else { @() }
    foreach ($declaredTaskPath in $declaredTaskPaths) {
        $lastSeparator = $declaredTaskPath.LastIndexOf([char]'\')
        if ($lastSeparator -lt 1 -or $lastSeparator -eq ($declaredTaskPath.Length - 1)) {
            throw "Privacy scheduled-task identity cannot be split into folder and name: $declaredTaskPath"
        }
        $taskName = $declaredTaskPath.Substring($lastSeparator + 1)
        $taskFolder = $declaredTaskPath.Substring(0, $lastSeparator + 1)
        $canonicalTaskPath = "$taskFolder$taskName"
        $taskMatches = @($installedTasks | Where-Object {
                [string]$_.TaskPath -eq $taskFolder -and [string]$_.TaskName -eq $taskName
            })
        if ($taskMatches.Count -gt 1) { throw "Privacy scheduled-task identity is ambiguous: $canonicalTaskPath" }
        if ($taskMatches.Count -eq 1) { $applicableTaskPaths.Add($canonicalTaskPath) }
    }

    $declaredChecks = [int]$registryPlan.DeclaredCount + $declaredServiceNames.Count + $declaredTaskPaths.Count
    $applicableChecks = @($registryPlan.ApplicableTargets).Count + $applicableServiceNames.Count + $applicableTaskPaths.Count
    $notApplicableChecks = @($registryPlan.NotApplicableTargets).Count +
        ($declaredServiceNames.Count - $applicableServiceNames.Count) +
        ($declaredTaskPaths.Count - $applicableTaskPaths.Count)
    $notCheckedChecks = @($registryPlan.NotCheckedTargets).Count
    if ($declaredChecks -lt 1 -or ($applicableChecks + $notCheckedChecks + $notApplicableChecks) -ne $declaredChecks) {
        throw 'Privacy runtime target-plan accounting failed'
    }

    return [PSCustomObject]@{
        RegistryPlan = $registryPlan
        DeclaredServiceNames = $declaredServiceNames
        ApplicableServiceNames = @($applicableServiceNames)
        DeclaredScheduledTaskPaths = $declaredTaskPaths
        ApplicableScheduledTaskPaths = @($applicableTaskPaths)
        DeclaredChecks = $declaredChecks
        ApplicableChecks = $applicableChecks
        NotCheckedChecks = $notCheckedChecks
        NotApplicableChecks = $notApplicableChecks
    }
}
