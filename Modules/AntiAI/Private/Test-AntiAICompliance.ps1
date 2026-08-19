#Requires -Version 5.1
#Requires -RunAsAdministrator

function Test-AntiAIRegistryTarget {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        $Target
    )

    $check = [PSCustomObject]@{
        Category    = [string]$Target.Feature
        Description = [string]$Target.Description
        Path        = [string]$Target.Path
        Name        = [string]$Target.Name
        Expected    = $Target.Value
        ExpectedType = [string]$Target.Type
        Actual      = $null
        ActualType  = $null
        Status      = 'FAIL'
        Error       = $null
    }
    try {
        if (-not (Test-Path -LiteralPath $Target.Path -PathType Container -ErrorAction Stop)) {
            throw 'registry key is missing'
        }
        $key = Get-Item -LiteralPath $Target.Path -ErrorAction Stop
        if ($key.GetValueNames() -notcontains [string]$Target.Name) {
            throw 'registry value is missing'
        }
        $check.ActualType = $key.GetValueKind([string]$Target.Name).ToString()
        $check.Actual = $key.GetValue(
            [string]$Target.Name,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        $expectedJson = [PSCustomObject]@{ Value = $Target.Value } | ConvertTo-Json -Compress -Depth 10
        $actualJson = [PSCustomObject]@{ Value = $check.Actual } | ConvertTo-Json -Compress -Depth 10
        if ($check.ActualType -ne [string]$Target.Type -or $actualJson -cne $expectedJson) {
            throw "expected $($Target.Type)/$expectedJson; actual $($check.ActualType)/$actualJson"
        }
        $check.Status = 'PASS'
    }
    catch {
        $check.Error = $_.Exception.Message
    }
    return $check
}

function Test-AntiAICompliance {
    <#
    .SYNOPSIS
        Verifies the complete config-derived AntiAI registry and URI target set.

    .DESCRIPTION
        This is an exact registry/source-hive verification. PASS means every
        declared value exists with the requested registry kind and data, and
        both Copilot URI handlers are absent from the machine and interactive
        user's real Classes hives. It does not claim runtime effectiveness for
        policies outside their documented edition/build/product applicability.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$ApplicableTargets,

        [Parameter(Mandatory = $false)]
        [object[]]$NotApplicableTargets
    )

    if (-not $PSBoundParameters.ContainsKey('ApplicableTargets') -or
        -not $PSBoundParameters.ContainsKey('NotApplicableTargets')) {
        throw 'AntiAI compliance requires an explicit sealed or durable target plan; live applicability is not Apply intent'
    }

    $started = Get-Date
    function Write-AntiAIVerificationLog {
        param([string]$Level, [string]$Message)
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level $Level -Message $Message -Module 'AntiAI'
        }
        else {
            Write-Verbose "[$Level] $Message"
        }
    }
    try {
        $details = [System.Collections.Generic.List[object]]::new()
        $targets = @($ApplicableTargets)
        $notApplicable = @($NotApplicableTargets)
        if ($targets.Count + $notApplicable.Count -ne 43) {
            throw "Canonical AntiAI verification scope must reconcile to 43 targets; got applicable=$($targets.Count), notApplicable=$($notApplicable.Count)"
        }
        if ($targets.Count -eq 0) {
            # A plan that declares every one of the 43 targets inapplicable
            # verifies nothing but the four URI absences, and 43 of them are
            # HKLM policies that apply to every supported edition. Such a plan
            # is corrupt input, and letting it produce OverallStatus=PASS would
            # green-light a machine on which nothing was checked.
            throw 'AntiAI verification plan declares zero applicable targets; refusing to attest an empty scope'
        }
        foreach ($target in $targets) {
            $details.Add((Test-AntiAIRegistryTarget -Target $target))
        }
        foreach ($target in $notApplicable) {
            $details.Add([PSCustomObject]@{
                    Category     = [string]$target.Feature
                    Description  = 'Declared policy target is not applicable on this host'
                    Path         = [string]$target.Path
                    Name         = [string]$target.Name
                    Expected     = 'Not mutated'
                    ExpectedType = $null
                    Actual       = [string]$target.Reason
                    ActualType   = $null
                    Status       = 'NotApplicable'
                    Error        = $null
                })
        }

    $userRoot = (Get-AntiAIUserContext).Root
    foreach ($uriTarget in @(
            'HKLM:\SOFTWARE\Classes\ms-copilot',
            'HKLM:\SOFTWARE\Classes\ms-edge-copilot',
            "$userRoot\Software\Classes\ms-copilot",
            "$userRoot\Software\Classes\ms-edge-copilot"
        )) {
        $present = Test-Path -LiteralPath $uriTarget -ErrorAction Stop
        $details.Add([PSCustomObject]@{
                Category     = 'URIHandlers'
                Description  = 'Copilot URI source hive must be absent'
                Path         = $uriTarget
                Name         = $null
                Expected     = 'Absent'
                ExpectedType = $null
                Actual       = if ($present) { 'Present' } else { 'Absent' }
                ActualType   = $null
                Status       = if ($present) { 'FAIL' } else { 'PASS' }
                Error        = if ($present) { 'URI handler source still exists' } else { $null }
            })
    }

    if ($details.Count -ne 47) {
        throw "AntiAI verification produced $($details.Count) checks; expected 47"
    }
    $passed = @($details | Where-Object { $_.Status -eq 'PASS' }).Count
    $failed = @($details | Where-Object { $_.Status -eq 'FAIL' }).Count
    $notApplicableCount = @($details | Where-Object { $_.Status -eq 'NotApplicable' }).Count
    foreach ($check in $details) {
        $level = switch ($check.Status) { 'PASS' { 'DEBUG' }; 'NotApplicable' { 'INFO' }; default { 'ERROR' } }
        $message = switch ($check.Status) {
            'PASS' { "PASS $($check.Path)::$($check.Name)" }
            'NotApplicable' { "NOT_APPLICABLE $($check.Path)::$($check.Name) - $($check.Actual)" }
            default { "FAIL $($check.Path)::$($check.Name) - $($check.Error)" }
        }
        # Display-only SID redaction (same pattern as the HTML report); the
        # check-detail objects keep the exact paths for contracts and restore.
        Write-AntiAIVerificationLog -Level $level -Message ([regex]::Replace($message, '(?i)\bS-1-(?:5-21|12-1)-[0-9-]+\b', '[USER-SID]'))
    }

    $result = [PSCustomObject]@{
        OverallStatus  = if ($failed -eq 0 -and ($passed + $notApplicableCount) -eq $details.Count) { 'PASS' } else { 'FAIL' }
        Passed         = $passed
        Failed         = $failed
        NotApplicable  = $notApplicableCount
        FailedChecks   = $failed
        TotalPolicies  = 43
        ApplicablePolicies = $targets.Count
        UriChecks      = 4
        TotalChecks    = $details.Count
        Warnings       = 0
        Details        = @($details)
        MSConflicts    = 0
        MSAligned      = 0
        ExitCode       = if ($failed -eq 0) { 0 } else { 1 }
        DurationSeconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
        VerificationScope = 'Exact registry values/types plus real URI source-hive absence; runtime feature effectiveness not asserted'
    }

    Write-Host "AntiAI registry/source verification: $passed passed, $notApplicableCount not applicable, $failed failed, $($details.Count) declared" `
        -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })
        return $result
    }
    catch {
        Write-AntiAIVerificationLog -Level ERROR -Message "AntiAI verification could not establish its target scope: $($_.Exception.Message)"
        return [PSCustomObject]@{
            OverallStatus    = 'FAIL'
            Passed           = 0
            Failed           = 1
            NotApplicable    = 0
            FailedChecks     = 1
            TotalPolicies    = 0
            ApplicablePolicies = 0
            UriChecks        = 0
            TotalChecks      = 1
            Warnings         = 0
            Details          = @([PSCustomObject]@{ Status = 'FAIL'; Error = $_.Exception.Message })
            MSConflicts      = 0
            MSAligned        = 0
            ExitCode         = 1
            DurationSeconds  = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
            VerificationScope = 'Target scope could not be established'
        }
    }
}
